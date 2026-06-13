"""

资源优化器

- 内存使用监控和限制

- CPU 使用率监控

- 自动 GC 触发

- 缓存动态调整

- 连接池管理

"""


import gc

import os

import asyncio

import logging
import time

from typing import Optional

import ctypes
import ctypes.wintypes


from config import Config

from cache import DNSCache

from resolver_manager import ResolverManager

from logger import RequestLogger


logger = logging.getLogger("dns-proxy.optimizer")


try:

    import psutil


    HAS_PSUTIL = True

except ImportError:

    HAS_PSUTIL = False


# ============================================================
# CRT 堆压缩 (Windows HeapCompact / Linux malloc_trim)
# ============================================================

if os.name == 'nt':
    _kernel32 = ctypes.windll.kernel32
    _kernel32.GetProcessHeap.restype = ctypes.wintypes.HANDLE
    _kernel32.HeapCompact.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
    _kernel32.HeapCompact.restype = ctypes.c_size_t

    def compact_crt_heap() -> int:
        """压缩 Windows CRT 默认堆，合并相邻空闲碎片。"""
        try:
            heap = _kernel32.GetProcessHeap()
            result = _kernel32.HeapCompact(heap, 0)
            return result
        except Exception:
            return 0
else:
    def compact_crt_heap() -> int:
        """Linux: malloc_trim 释放堆顶部空闲内存"""
        try:
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            libc.malloc_trim(0)
            return 1
        except Exception:
            return 0


# ============================================================
# Arena 碎片压力估算
# ============================================================
# 估算 pymalloc arena 的碎片压力，使用 Level 2 回退策略：
# 通过 RSS / 总对象数 估算每对象的平均内存消耗，
# 如果显著高于正常值 (~300 bytes/obj)，说明大量 arena 处于
# 半满状态（碎片化），需要触发提前重建。




def _estimate_arena_pressure(cache_size: int, rss_mb: float) -> float:
    """估算 pymalloc arena 碎片压力 (0.0 ~ 1.0)

    算法：RSS / cache_size 比值趋势分析
      - 正常：~200-500 bytes/条目 (wire + overhead)
      - 碎片严重：>800 bytes/条目 (大量半空 arena)
      - 压力 = 非线性变换使 0-1 范围更敏感

    Args:
        cache_size: 当前缓存条目数
        rss_mb: 当前 RSS MB
    Returns:
        0.0 - 1.0 的碎片压力值
    """
    if cache_size < 10 or rss_mb <= 0:
        return 0.0
    bytes_per_entry = (rss_mb * 1024 * 1024) / cache_size
    # 正常 ~300 bytes/entry, 压力阈值 600 bytes/entry
    if bytes_per_entry <= 300:
        return 0.0
    elif bytes_per_entry >= 1200:
        return 1.0
    else:
        # 300-1200 线性映射到 0.0-1.0
        return (bytes_per_entry - 300) / 900.0


class ResourceOptimizer:

    """资源优化器"""


    def __init__(

        self,

        config: Config,

        cache: DNSCache,

        resolver_manager: ResolverManager,

        request_logger: RequestLogger,

        filter_engine=None,

    ):

        self.config = config

        self.cache = cache

        self.resolver_manager = resolver_manager

        self.request_logger = request_logger

        self._filter_engine = filter_engine

        self._monitor_task: Optional[asyncio.Task] = None

        self._gc_task: Optional[asyncio.Task] = None

        self._defrag_task: Optional[asyncio.Task] = None

        self._running = False


        # 进程对象

        self._process = None

        if HAS_PSUTIL:

            try:

                self._process = psutil.Process()

            except Exception as e:

                logger.debug("优化器初始化 psutil 异常: %s", e)

        # ===== Arena 压力追踪 =====

        self._arena_pressure_history: list[float] = []  # 最近 8 次采样

        self._last_rebuild_time: float = 0.0

        self._rebuild_cooldown: float = 180.0  # 最小间隔 3 分钟

        self._last_critical_reduce: float = 0.0  # 上次激进回收时间（防同一周期双重触发）

        self._arena_pressure_enabled: bool = HAS_PSUTIL  # 需要 psutil 才启用

        self._defrag_enabled: bool = True  # defrag 纯操作 OrderedDict，不依赖 psutil

        # ===== 低负载内存归还 OS =====
        self._last_return_to_os: float = 0.0          # 上次 _return_unused_memory_to_os 调用时间
        self._return_to_os_cooldown: float = 300.0     # 最小间隔 5 分钟
        self._high_water_ratio: float = 0.70           # 高水位阈值（memory_limit 的 70%）
        self._gc_last_total_logged: int = 0
        self._gc_last_loop_time: float = 0.0
        self._defrag_last_total_logged: int = 0
        self._defrag_last_loop_time: float = 0.0


    async def start(self):

        """启动资源监控和优化任务"""

        self._running = True

        self._monitor_task = asyncio.create_task(self._monitor_loop())

        if self.config.aggressive_gc and HAS_PSUTIL:

            self._gc_task = asyncio.create_task(self._gc_loop())

        if self._defrag_enabled and self.config.cache_enabled:

            self._defrag_task = asyncio.create_task(self._defrag_loop())

        logger.info("资源优化器已启动")


    async def stop(self):

        """停止优化任务"""

        self._running = False

        if self._monitor_task:

            self._monitor_task.cancel()

            try:

                await self._monitor_task

            except asyncio.CancelledError:

                pass

        if self._gc_task:

            self._gc_task.cancel()

            try:

                await self._gc_task

            except asyncio.CancelledError:

                pass

        if self._defrag_task:

            self._defrag_task.cancel()

            try:

                await self._defrag_task

            except asyncio.CancelledError:

                pass

        logger.info("资源优化器已停止")


    async def _monitor_loop(self):

        """资源监控主循环"""

        prev_memory_mb = 0.0

        no_decrease_count = 0

        while self._running:

            try:

                memory_mb = await self._check_resources()

                if memory_mb is not None and memory_mb > 0:

                    # 内存趋势检测

                    if prev_memory_mb > 0 and memory_mb >= prev_memory_mb * 0.98:

                        no_decrease_count += 1

                    else:

                        no_decrease_count = 0
                    prev_memory_mb = memory_mb


                    # 连续 3 个周期内存未下降且超过 85%，升级激进回收

                    if no_decrease_count >= 3:

                        mem_limit = self.config.memory_limit_mb

                        if memory_mb > mem_limit * 0.85:

                            logger.warning("内存 %.0fMB 连续 %d 次未下降，触发强制内存回收", memory_mb, no_decrease_count)

                            await self._reduce_memory()

                            self._log_gc_stats()

                            no_decrease_count = 0


                        else:

                            no_decrease_count = 0
                # ===== Arena 碎片压力检测 =====

                if (self._arena_pressure_enabled

                    and memory_mb is not None

                    and memory_mb > self.config.memory_limit_mb * 0.70

                    and hasattr(self.cache, '_current_epoch')):

                    arena_pressure = _estimate_arena_pressure(

                        self.cache.current_size, memory_mb

                    )

                    self._arena_pressure_history.append(arena_pressure)

                    if len(self._arena_pressure_history) > 8:

                        self._arena_pressure_history.pop(0)

                    avg_pressure = (sum(self._arena_pressure_history)

                                    / max(1, len(self._arena_pressure_history)))

                    now = time.monotonic()

                    if (avg_pressure > 0.60

                        and now - self._last_rebuild_time > self._rebuild_cooldown

                        and memory_mb > self.config.memory_limit_mb * 0.85

                        and now - self._last_critical_reduce > self._rebuild_cooldown):

                        logger.warning("Arena 碎片压力 %.0f%%，提前触发撤离重建",

                                       avg_pressure * 100)

                        await self.cache.rebuild()

                        self._last_rebuild_time = now

                        self._arena_pressure_history.clear()

                        # 重建后也清理模板缓存

                        from cache import evict_cold_query_templates

                        evict_cold_query_templates()

                await asyncio.sleep(self.config.monitor_interval)

            except asyncio.CancelledError:

                break

            except Exception as e:

                logger.error("资源监控异常: %s", e, exc_info=True)

                await asyncio.sleep(10)

    async def _check_resources(self) -> Optional[float]:
        """检查并优化资源使用，返回当前 RSS MB"""
        if not HAS_PSUTIL or self._process is None:
            return None

        memory_mb = None
        try:
            # 内存检查
            memory_mb = self._process.memory_info().rss / (1024 * 1024)
            memory_limit = self.config.memory_limit_mb

            if memory_mb > memory_limit * 0.97:
                logger.warning(
                    "内存使用 %.0fMB，超过限制 %dMB 的 97%%，触发激进优化",
                    memory_mb,
                    memory_limit,
                )
                self._last_critical_reduce = time.monotonic()
                await self._critical_reduce_memory()
                self._log_gc_stats()

            elif memory_mb > memory_limit * 0.93:
                logger.warning(
                    "内存使用 %.0fMB，超过限制 %dMB 的 93%%，触发优化",
                    memory_mb,
                    memory_limit,
                )
                await self._reduce_memory()

            elif memory_mb > memory_limit * 0.85:
                logger.info(
                    "内存使用 %.0fMB / %dMB，触发轻度优化", memory_mb, memory_limit
                )
                await self._light_optimize()

            # CPU 检查（cpu_percent 是多核总和，例如 4 核满 = 400%）
            cpu_percent = self._process.cpu_percent(interval=0)
            cpu_count = os.cpu_count() or 1
            core_limit = self.config.cpu_core_limit
            if core_limit <= 0:
                core_limit = max(1, cpu_count - 1)
            cpu_cores_used = cpu_percent / 100.0
            if cpu_cores_used > core_limit:
                logger.warning(
                    "CPU 使用 %.1f 核 (%.0f%%)，超过限制 %d 核，降低并发",
                    cpu_cores_used, cpu_percent, core_limit,
                )
                # 实际限流：降低连接池上限
                if not hasattr(self, '_cpu_throttle'):
                    self._cpu_throttle = self.config.max_concurrent
                curr = self._cpu_throttle
                if curr and curr > 200:
                    self._cpu_throttle = max(200, int(curr * 0.8))
                    logger.info("CPU 超限，并发上限从 %d 降至 %d", curr, self._cpu_throttle)
                # 传递限流值给调用方检查
                if hasattr(self.resolver_manager, "_concurrent_throttle"):
                    try:
                        self.resolver_manager._concurrent_throttle = self._cpu_throttle
                    except AttributeError:
                        pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return memory_mb


    async def _reduce_memory(self):



        """主动降低内存使用 — 堆碎片整理 medium 级别"""



        # 1. 清理 DNS 缓存

        if self.config.cache_enabled:

            await self.cache.cleanup_expired()

            # 1a. 丢弃 LRU 尾部 40% 的 Message 对象（释放复杂对象图）

            await self.cache.drop_messages_lru(ratio=0.4)

            # 1b. 按字节大小淘汰 10% 最大的（保守策略，配合 rebuild 排序整理）

            await self.cache.evict_largest(ratio=0.1)



        # 2. 过滤缓存撤离重建（释放旧 arena）
        try:
            fe = self._filter_engine
            if fe is None:
                import sys as _sys
                app = getattr(_sys.modules.get("__main__"), "app", None)
                fe = app.filter_engine if app and hasattr(app, "filter_engine") else None
            if fe and hasattr(fe, "_filter_cache") and len(fe._filter_cache) > 0 and hasattr(fe, "rebuild_filter_cache"):
                fe.rebuild_filter_cache()
        except Exception:
            pass
        try:
            from cache import evict_cold_query_templates
            evict_cold_query_templates()
        except Exception:
            pass


        # 3. 强制刷新日志缓冲区

        await self.request_logger.flush()



        # 4. 释放 bootstrap 缓存中较大的条目

        bs_cache = getattr(self.resolver_manager, '_bootstrap_cache', None)

        if bs_cache and len(bs_cache) > 20:

            sorted_items = sorted(bs_cache.items(), key=lambda x: len(x[1]), reverse=True)

            kept = 0

            for hostname, _ in sorted_items:

                if kept < 10:

                    kept += 1

                    continue

                del bs_cache[hostname]

            logger.debug("释放了 %d 个 bootstrap 缓存条目", len(sorted_items) - kept)



        # 5. 释放空闲连接池

        try:

            await self.resolver_manager.close_idle_connections()

        except Exception:

            pass



        # 6. GC + 平台级内存回收

        if self.config.aggressive_gc:

            gc.collect(generation=2)

            self._return_unused_memory_to_os()



        logger.info("内存降低操作完成")

    async def _critical_reduce_memory(self):



        """超过 97% 阈值时的激进内存压缩 — 含全量撤离+重建"""



        # 1. 临时缩小缓存 50%

        if self.config.cache_enabled:

            original_max = self.cache.max_size

            reduced = max(100, original_max // 2)

            self.cache.max_size = reduced

            await self.cache.cleanup_expired()

            await self.cache.evict_largest(ratio=0.3)

            try:

                logger.info("临时缩小缓存到 %d", reduced)

                # 1a. ★ 全量撤离+重建（核心动作：释放旧 pymalloc arena）

                await self.cache.rebuild()

            finally:

                self.cache.max_size = original_max

                logger.info("缓存大小已恢复至 %d", original_max)



        # 2. 关闭所有持久连接

        try:

            await self.resolver_manager.reset_all_connections()

        except Exception:

            pass



        # 3. 全量重建过滤缓存（释放旧 arena）
        try:
            fe = self._filter_engine
            if fe is None:
                import sys as _sys
                app = getattr(_sys.modules.get("__main__"), "app", None)
                fe = app.filter_engine if app and hasattr(app, "filter_engine") else None
            if fe and hasattr(fe, "_filter_cache") and hasattr(fe, "rebuild_filter_cache"):
                fe.rebuild_filter_cache()
        except Exception:
            pass


        # 4. 多次 GC + CRT 堆压缩

        for _ in range(3):

            gc.collect(generation=2)

        self._return_unused_memory_to_os()



        logger.warning("激进内存压缩已完成")

    async def _light_optimize(self):



        """轻度优化 — 含 LRU Message 丢弃"""



        await self.cache.cleanup_expired()

        await self.cache.drop_messages_lru(ratio=0.15)

        if self.config.aggressive_gc:

            gc.collect()

    @staticmethod

    def _return_unused_memory_to_os():



        "将空闲内存归还 OS — CRT 堆压缩（HeapCompact / malloc_trim）合并空闲碎片"

        # CRT 堆压缩（安全，无副作用）

        try:

            compact_crt_heap()

        except Exception:

            pass

    async def _defrag_loop(self):
        while self._running:
            try:
                await asyncio.sleep(600)
                if not self._running:
                    break
                # ===== 低负载时归还内存给 OS =====
                if HAS_PSUTIL and self._process is not None:
                    try:
                        _now = time.monotonic()
                        _mem_mb = self._process.memory_info().rss / (1024 * 1024)
                        _mem_limit = self.config.memory_limit_mb
                        _total = getattr(self.request_logger, "_total_logged", 0)
                        _dt = _now - self._defrag_last_loop_time
                        if _dt > 0 and self._defrag_last_loop_time > 0:
                            _req_ps = (_total - self._defrag_last_total_logged) / _dt
                        else:
                            _req_ps = 0.0
                        self._defrag_last_total_logged = _total
                        self._defrag_last_loop_time = _now
                        if (_req_ps < 10.0
                            and _mem_mb > _mem_limit * self._high_water_ratio
                            and _now - self._last_return_to_os > self._return_to_os_cooldown):
                            self._return_unused_memory_to_os()
                            self._last_return_to_os = _now
                            logger.debug("低负载下已归还内存给 OS (%.0fMB > %dMB * %.0f%%, %.1f req/s)",
                                         _mem_mb, _mem_limit, self._high_water_ratio * 100, _req_ps)
                    except Exception:
                        pass
                if self.cache.current_size > 500:
                    await self.cache.defrag()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _gc_loop(self):

        """主动 GC 循环 - 在低负载时触发"""

        while self._running:

            try:

                await asyncio.sleep(self.config.gc_interval)

                if not self._running:

                    break


                # 根据当前内存压力动态调整 GC 策略

                if HAS_PSUTIL and self._process is not None:

                    try:

                        memory_mb = self._process.memory_info().rss / (1024 * 1024)

                        memory_limit = self.config.memory_limit_mb

                        pressure = memory_mb / memory_limit


                        if pressure > 0.85:

                            # 高内存压力: 每轮都做全量 GC

                            gc.collect(generation=2)

                            if pressure > 0.93:

                                gc.collect(generation=2)

                            continue

                    except Exception:

                        pass


                # 低内存压力: 轻量 GC

                gc.collect(generation=1)

                # ===== 低负载时归还内存给 OS =====
                if HAS_PSUTIL and self._process is not None:
                    try:
                        _now = time.monotonic()
                        _mem_mb = self._process.memory_info().rss / (1024 * 1024)
                        _mem_limit = self.config.memory_limit_mb
                        _total = getattr(self.request_logger, "_total_logged", 0)
                        _dt = _now - self._gc_last_loop_time
                        if _dt > 0 and self._gc_last_loop_time > 0:
                            _req_ps = (_total - self._gc_last_total_logged) / _dt
                        else:
                            _req_ps = 0.0
                        self._gc_last_total_logged = _total
                        self._gc_last_loop_time = _now
                        if (_req_ps < 10.0
                            and _mem_mb > _mem_limit * self._high_water_ratio
                            and _now - self._last_return_to_os > self._return_to_os_cooldown):
                            self._return_unused_memory_to_os()
                            self._last_return_to_os = _now
                            logger.debug("低负载下已归还内存给 OS (%.0fMB > %dMB * %.0f%%, %.1f req/s)",
                                         _mem_mb, _mem_limit, self._high_water_ratio * 100, _req_ps)
                    except Exception:
                        pass

                if hasattr(self, "_gc_count"):

                    self._gc_count += 1

                else:

                    self._gc_count = 1

                if self._gc_count % 3 == 0:

                    gc.collect(generation=2)


            except asyncio.CancelledError:

                break

            except Exception as e:

                logger.debug("优化器 GC 循环异常: %s", e)


    async def get_memory_usage(self) -> dict:

        """获取内存使用信息"""

        result = {

            "cache_size": self.cache.current_size,

            "log_buffer": self.request_logger.stats["buffer_size"],

        }

        # 尝试获取过滤缓存大小
        try:
            fe = self._filter_engine
            if fe is None:
                import sys as _sys
                app = getattr(_sys.modules.get('__main__'), 'app', None)
                fe = app.filter_engine if app and hasattr(app, 'filter_engine') else None
            if fe and hasattr(fe, '_filter_cache'):
                result["filter_cache_size"] = len(fe._filter_cache)
        except Exception:
            pass

        if HAS_PSUTIL and self._process is not None:

            try:

                mem = self._process.memory_info()

                result["rss_mb"] = round(mem.rss / (1024 * 1024), 1)

                result["vms_mb"] = round(mem.vms / (1024 * 1024), 1)

                result["cpu_percent"] = self._process.cpu_percent(interval=0)

            except Exception as e:

                logger.debug("优化器获取内存异常: %s", e)

        return result

    def _log_gc_stats(self):

        """轻量版 GC 统计，使用 get_count 避免遍历所有对象"""

        if not HAS_PSUTIL:

            return

        try:

            g0, g1, g2 = gc.get_count()

            stats = gc.get_stats()

            collected = [s.get("collected", 0) for s in stats]

            logger.info("GC 统计: gen0=%d gen1=%d gen2=%d | 累计回收: %s", g0, g1, g2, collected)

        except Exception:

            pass

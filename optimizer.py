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




def _estimate_arena_pressure(cache_size: int, rss_mb: float) -> float:
    """估算 pymalloc arena 碎片压力 (0.0 ~ 1.0)"""
    if cache_size < 10 or rss_mb <= 0:
        return 0.0
    bytes_per_entry = (rss_mb * 1024 * 1024) / cache_size
    if bytes_per_entry <= 300:
        return 0.0
    elif bytes_per_entry >= 1200:
        return 1.0
    else:
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

        self._return_to_os_task: Optional[asyncio.Task] = None

        self._running = False


        self._process = None

        if HAS_PSUTIL:

            try:

                self._process = psutil.Process()

            except Exception as e:

                logger.debug("优化器初始化 psutil 异常: %s", e)

        self._arena_pressure_history: list[float] = []

        self._last_rebuild_time: float = 0.0

        self._rebuild_cooldown: float = 180.0

        self._last_critical_reduce: float = 0.0

        self._arena_pressure_enabled: bool = HAS_PSUTIL

        self._defrag_enabled: bool = True

        # ===== 低负载内存归还 OS =====
        self._last_return_to_os: float = 0.0
        self._return_to_os_cooldown: float = 60.0      # ★ 从 300 改为 60 秒
        self._high_water_ratio: float = 0.70

        self._base_rss_mb: float = 0.0


    async def start(self):

        """启动资源监控和优化任务"""

        self._running = True

        if HAS_PSUTIL and self._process is not None:
            samples = []
            for _ in range(3):
                try:
                    samples.append(self._process.memory_info().rss / (1024 * 1024))
                except Exception:
                    pass
                await asyncio.sleep(0.5)
            if samples:
                self._base_rss_mb = min(samples)
                logger.debug("基线 RSS 采样完成: min=%.1fMB", self._base_rss_mb)

        self._monitor_task = asyncio.create_task(self._monitor_loop())

        if self.config.aggressive_gc and HAS_PSUTIL:

            self._gc_task = asyncio.create_task(self._gc_loop())

        if self._defrag_enabled and self.config.cache_enabled:

            self._defrag_task = asyncio.create_task(self._defrag_loop())

        self._return_to_os_task = asyncio.create_task(self._return_to_os_loop())

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

        if self._return_to_os_task:
            self._return_to_os_task.cancel()
            try:
                await self._return_to_os_task
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

                    if prev_memory_mb > 0 and memory_mb >= prev_memory_mb * 0.98:

                        no_decrease_count += 1

                    else:

                        no_decrease_count = 0
                    prev_memory_mb = memory_mb


                    if no_decrease_count >= 3:

                        mem_limit = self.config.memory_limit_mb

                        if memory_mb > mem_limit * 0.85:

                            logger.warning("内存 %.0fMB 连续 %d 次未下降，触发强制内存回收", memory_mb, no_decrease_count)

                            await self._reduce_memory()

                            self._log_gc_stats()

                            no_decrease_count = 0


                        else:

                            no_decrease_count = 0

                if (self._arena_pressure_enabled

                    and memory_mb is not None

                    and memory_mb > self.config.memory_limit_mb * 0.70

                    and hasattr(self.cache, '_current_epoch')):

                    adjusted_rss = memory_mb - self._base_rss_mb
                    arena_pressure = _estimate_arena_pressure(

                        self.cache.current_size, max(1.0, adjusted_rss)

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
            memory_mb = self._process.memory_info().rss / (1024 * 1024)
            memory_limit = self.config.memory_limit_mb

            if memory_mb > memory_limit * 0.97:
                logger.warning(
                    "内存使用 %.0fMB，超过限制 %dMB 的 97%%，触发激进优化",
                    memory_mb, memory_limit,
                )
                self._last_critical_reduce = time.monotonic()
                await self._critical_reduce_memory()
                self._log_gc_stats()

            elif memory_mb > memory_limit * 0.93:
                logger.warning(
                    "内存使用 %.0fMB，超过限制 %dMB 的 93%%，触发优化",
                    memory_mb, memory_limit,
                )
                await self._reduce_memory()

            elif memory_mb > memory_limit * 0.75:  # ★ 从 0.85 改为 0.75
                logger.info(
                    "内存使用 %.0fMB / %dMB，触发轻度优化", memory_mb, memory_limit
                )
                await self._light_optimize()

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
                if not hasattr(self, '_cpu_throttle'):
                    self._cpu_throttle = self.config.max_concurrent
                curr = self._cpu_throttle
                if curr and curr > 200:
                    self._cpu_throttle = max(200, int(curr * 0.8))
                    logger.info("CPU 超限，并发上限从 %d 降至 %d", curr, self._cpu_throttle)
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



        if self.config.cache_enabled:

            await self.cache.cleanup_expired()

            await self.cache.compact_messages(ratio=0.4)  # ★ 按命中率丢弃 Message，比LRU更智能

            await self.cache.evict_largest(ratio=0.1)



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


        await self.request_logger.flush()



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



        try:

            await self.resolver_manager.close_idle_connections()

        except Exception:

            pass



        if self.config.aggressive_gc:

            gc.collect(generation=2)

            self._return_unused_memory_to_os()



        logger.info("内存降低操作完成")

    async def _critical_reduce_memory(self):



        """超过 97% 阈值时的激进内存压缩 — 含全量撤离+重建"""



        if self.config.cache_enabled:

            original_max = self.cache.max_size

            reduced = max(100, original_max // 2)

            self.cache.max_size = reduced

            await self.cache.cleanup_expired()

            await self.cache.evict_largest(ratio=0.3)

            try:

                logger.info("临时缩小缓存到 %d", reduced)

                await self.cache.rebuild()

            finally:

                self.cache.max_size = original_max

                logger.info("缓存大小已恢复至 %d", original_max)



        try:

            await self.resolver_manager.reset_all_connections()

        except Exception:

            pass



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


        for _ in range(3):

            gc.collect(generation=2)

        self._return_unused_memory_to_os()



        logger.warning("激进内存压缩已完成")

    async def _light_optimize(self):



        """轻度优化 — 含 LRU Message 丢弃 + EmptyWorkingSet"""



        await self.cache.cleanup_expired()

        await self.cache.drop_messages_lru(ratio=0.15)

        if self.config.aggressive_gc:

            gc.collect()

        self._return_unused_memory_to_os()  # ★ 新增：轻度优化后也把冷页换出

    @staticmethod

    def _return_unused_memory_to_os():



        "将空闲内存归还 OS — 堆压缩 + 工作集修剪"

        try:
            compact_crt_heap()
        except Exception:
            pass

        try:
            if os.name == 'nt':
                _kernel32 = ctypes.windll.kernel32
                _PROCESS_HANDLE = _kernel32.GetCurrentProcess()
                _kernel32.SetProcessWorkingSetSize(
                    _PROCESS_HANDLE,
                    ctypes.c_size_t(-1),
                    ctypes.c_size_t(-1)
                )
            else:
                try:
                    with open("/proc/self/clear_refs", "w") as f:
                        f.write("1")
                except (IOError, PermissionError):
                    pass
        except Exception:
            pass

    async def _defrag_loop(self):
        loop_interval = 30.0
        defrag_cooldown = 30.0
        fallback_interval = 600.0
        last_defrag_time = 0.0

        while self._running:
            try:
                await asyncio.sleep(loop_interval)
                if not self._running:
                    break

                now = time.monotonic()
                cache_size = self.cache.current_size

                insert_count = self.cache.get_and_reset_insert_count()
                threshold = max(100, self.config.cache_max_size // 20)
                if (insert_count >= threshold
                    and cache_size > 500
                    and now - last_defrag_time > defrag_cooldown):
                    await self.cache.defrag()
                    last_defrag_time = now
                    logger.debug("★ 插入计数 %d >= 阈值 %d (max_size=%d), 触发碎片整理",
                                 insert_count, threshold, self.config.cache_max_size)
                    continue

                # ★ 检查 arena 碎片压力：当 monitor 检测到高碎片压力时提前 defrag
                if (hasattr(self, '_arena_pressure_history')
                    and len(self._arena_pressure_history) >= 3
                    and cache_size > 500
                    and now - last_defrag_time > defrag_cooldown):
                    avg_pressure = sum(self._arena_pressure_history[-3:]) / 3.0
                    if avg_pressure > 0.65:
                        await self.cache.defrag()
                        last_defrag_time = now
                        self._arena_pressure_history.clear()
                        logger.debug("★ Arena碎片压力 %.0f%% 触发碎片整理 (%d 条目)",
                                     avg_pressure * 100, cache_size)
                        continue

                if (cache_size > 500
                    and now - last_defrag_time > fallback_interval):
                    await self.cache.defrag()
                    last_defrag_time = now
                    logger.debug("★ 定时兜底触发碎片整理 (%d 条目)", cache_size)

            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _return_to_os_loop(self):
        while self._running:
            try:
                await asyncio.sleep(60)  # ★ 每 1 分钟检查（原来 300 秒）
                if not self._running:
                    break

                if not (HAS_PSUTIL and self._process is not None):
                    continue

                _now = time.monotonic()
                _mem_mb = self._process.memory_info().rss / (1024 * 1024)
                _mem_limit = self.config.memory_limit_mb
                _total = getattr(self.request_logger, "_total_logged", 0)
                _dt = _now - getattr(self, "_last_rtos_time", _now)
                if _dt > 0:
                    _req_ps = (_total - getattr(self, "_last_rtos_req_total", _total)) / _dt
                else:
                    _req_ps = 0.0
                self._last_rtos_req_total = _total
                self._last_rtos_time = _now

                if (_req_ps < 100
                    and _mem_mb > _mem_limit * self._high_water_ratio
                    and _now - self._last_return_to_os > self._return_to_os_cooldown):
                    self._return_unused_memory_to_os()
                    self._last_return_to_os = _now
                    logger.debug("★ 低负载下已归还内存给 OS (%.0fMB > %dMB * %.0f%%, %.1f req/s)",
                                 _mem_mb, _mem_limit, self._high_water_ratio * 100, _req_ps)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _gc_loop(self):

        while self._running:

            try:

                await asyncio.sleep(self.config.gc_interval)

                if not self._running:

                    break

                if HAS_PSUTIL and self._process is not None:

                    try:

                        memory_mb = self._process.memory_info().rss / (1024 * 1024)

                        memory_limit = self.config.memory_limit_mb

                        pressure = memory_mb / memory_limit

                        if pressure > 0.85:

                            gc.collect(generation=2)

                            if pressure > 0.93:

                                gc.collect(generation=2)

                            continue

                    except Exception:

                        pass

                gc.collect(generation=1)

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

        result = {

            "cache_size": self.cache.current_size,

            "log_buffer": self.request_logger.stats["buffer_size"],

        }

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

        if not HAS_PSUTIL:

            return

        try:

            g0, g1, g2 = gc.get_count()

            stats = gc.get_stats()

            collected = [s.get("collected", 0) for s in stats]

            logger.info("GC 统计: gen0=%d gen1=%d gen2=%d | 累计回收: %s", g0, g1, g2, collected)

        except Exception:

            pass

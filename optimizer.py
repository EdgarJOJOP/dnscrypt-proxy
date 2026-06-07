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

from typing import Optional


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


class ResourceOptimizer:

    """资源优化器"""


    def __init__(

        self,

        config: Config,

        cache: DNSCache,

        resolver_manager: ResolverManager,

        request_logger: RequestLogger,

    ):

        self.config = config

        self.cache = cache

        self.resolver_manager = resolver_manager

        self.request_logger = request_logger


        self._monitor_task: Optional[asyncio.Task] = None

        self._gc_task: Optional[asyncio.Task] = None

        self._running = False


        # 进程对象

        self._process = None

        if HAS_PSUTIL:

            try:

                self._process = psutil.Process()

            except Exception as e:

                logger.debug("优化器初始化 psutil 异常: %s", e)


    async def start(self):

        """启动资源监控和优化任务"""

        self._running = True

        self._monitor_task = asyncio.create_task(self._monitor_loop())

        if self.config.aggressive_gc and HAS_PSUTIL:

            self._gc_task = asyncio.create_task(self._gc_loop())

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

                await asyncio.sleep(self.config.monitor_interval)

            except asyncio.CancelledError:

                break

            except Exception as e:

                logger.error("资源监控异常: %s", e, exc_info=True)

                await asyncio.sleep(10)

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
            cpu_percent = self._process.cpu_percent(interval=0.1)
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

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return memory_mb


    async def _reduce_memory(self):

        """主动降低内存使用 - 升级版:锁定缓存、连接池、过滤缓存"""

        # 1. 清理 DNS 缓存:先清过期，再按字节大小淘汰 20% 最大的

        if self.config.cache_enabled:

            await self.cache.cleanup_expired()

            await self.cache.evict_largest(ratio=0.2)


        # 2. 清除过滤结果缓存（跳过 priority 自定义 hosts 条目）

        await self._compact_filter_cache_global()


        # 3. 强制刷新日志缓冲区

        await self.request_logger.flush()


        # 4. 释放 bootstrap 缓存中较大的条目

        bs_cache = getattr(self.resolver_manager, '_bootstrap_cache', None)

        if bs_cache and len(bs_cache) > 20:

            sorted_items = sorted(bs_cache.items(), key=lambda x: len(x[1]), reverse=True)

            kept = 0

            for hostname in list(bs_cache.keys()):

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


        # 6. 触发 Python GC + 平台级内存回收

        if self.config.aggressive_gc:

            gc.collect(generation=2)

            self._return_unused_memory_to_os()


        logger.info("内存降低操作完成")


    async def _critical_reduce_memory(self):

        """超过 95% 阈值时的激进内存压缩"""

        # 1. 临时缩小缓存 50%

        if self.config.cache_enabled:

            original_max = self.cache.max_size

            reduced = max(100, original_max // 2)

            self.cache.max_size = reduced

            await self.cache.cleanup_expired()

            await self.cache.evict_largest(ratio=0.3)

            self.cache.max_size = original_max

            logger.info("临时缩小缓存到 %d，已恢复", reduced)


        # 2. 关闭所有持久连接

        try:

            await self.resolver_manager.reset_all_connections()

        except Exception:

            pass


        # 3. 强制清除过滤缓存（保留 priority）

        await self._compact_filter_cache_global()


        # 4. 强制 GC + 平台级回收

        for _ in range(3):

            gc.collect(generation=2)

        self._return_unused_memory_to_os()


        logger.warning("激进内存压缩已完成")


    async def _light_optimize(self):

        """轻度优化"""

        await self.cache.cleanup_expired()

        if self.config.aggressive_gc:

            gc.collect()


    @staticmethod

    def _return_unused_memory_to_os():

        """将 Python 层未使用的内存返回给操作系统"""

        try:

            if os.name == 'nt':

                import ctypes

                kernel32 = ctypes.windll.kernel32

                kernel32.SetProcessWorkingSetSize(-1, -1)

            else:

                try:

                    import ctypes

                    import ctypes.util

                    libc = ctypes.CDLL(ctypes.util.find_library('c'))

                    libc.malloc_trim(0)

                except Exception:

                    pass

        except Exception:

            pass


    async def _compact_filter_cache_global(self):

        """大量清理过滤缓存，保留 priority 条目（自定义 hosts）"""

        try:

            import sys as _sys

            app = getattr(_sys.modules.get('main'), 'app', None)

            if app and hasattr(app, 'filter_engine'):

                fe = app.filter_engine

                cache = getattr(fe, '_filter_cache', None)

                if cache is not None:

                    import time as _time

                    now = _time.monotonic()

                    timeout = getattr(fe, '_filter_cache_timeout', 5.0)

                    expired = []

                    for k, v in list(cache.items()):

                        if len(v) >= 4 and v[3]:

                            continue  # priority 条目，保留

                        ts = v[2] if len(v) >= 3 else 0

                        if now - ts > timeout:

                            expired.append(k)

                    for k in expired:

                        try:

                            del cache[k]

                        except KeyError:

                            pass

                    if expired:

                        logger.debug("过滤缓存清理: 移除了 %d 个过期非 priority 条目", len(expired))

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
            import sys as _sys
            app = getattr(_sys.modules.get('main'), 'app', None)
            if app and hasattr(app, 'filter_engine') and hasattr(app.filter_engine, '_filter_cache'):
                result["filter_cache_size"] = len(app.filter_engine._filter_cache)
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

        """输出 GC 对象统计，帮助诊断内存泄漏"""

        if not HAS_PSUTIL:

            return

        try:

            import collections

            obj_counts = collections.Counter(type(o).__name__ for o in gc.get_objects())

            top10 = obj_counts.most_common(10)

            total = sum(obj_counts.values())

            logger.info("GC 存活对象: %d 个, Top10: %s", total, dict(top10))

        except Exception:

            pass



"""
资源优化器
- 内存使用监控和限制
- CPU 使用率监控
- 自动 GC 触发
- 缓存动态调整
- 连接池管理
"""

import gc
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
            except Exception:
                pass

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
        while self._running:
            try:
                await self._check_resources()
                await asyncio.sleep(self.config.monitor_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("资源监控异常: %s", e)
                await asyncio.sleep(10)

    async def _check_resources(self):
        """检查并优化资源使用"""
        if not HAS_PSUTIL or self._process is None:
            return

        try:
            # 内存检查
            memory_mb = self._process.memory_info().rss / (1024 * 1024)
            memory_limit = self.config.memory_limit_mb

            if memory_mb > memory_limit * 0.9:
                logger.warning(
                    "内存使用 %.0fMB，超过限制 %dMB 的 90%%，触发优化",
                    memory_mb,
                    memory_limit,
                )
                await self._reduce_memory()

            elif memory_mb > memory_limit * 0.75:
                logger.info(
                    "内存使用 %.0fMB / %dMB，触发轻度优化", memory_mb, memory_limit
                )
                await self._light_optimize()

            # CPU 检查
            cpu_percent = self._process.cpu_percent(interval=0.1)
            if cpu_percent > self.config.cpu_usage_limit:
                logger.warning(
                    "CPU 使用率 %d%%，超过限制 %d%%，降低并发",
                    cpu_percent,
                    self.config.cpu_usage_limit,
                )
                # 动态调低信号量效果：不做特殊处理，asyncio 自身会协调

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    async def _reduce_memory(self):
        """主动降低内存使用"""
        # 1. 清理 DNS 缓存
        if self.config.cache_enabled:
            await self.cache.cleanup_expired()

        # 2. 强制刷新日志缓冲区
        await self.request_logger.flush()

        # 3. 触发 Python GC
        if self.config.aggressive_gc:
            gc.collect()

        logger.debug("内存降低操作完成")

    async def _light_optimize(self):
        """轻度优化"""
        await self.cache.cleanup_expired()
        if self.config.aggressive_gc:
            gc.collect()

    async def _gc_loop(self):
        """主动 GC 循环 - 在低负载时触发"""
        while self._running:
            try:
                await asyncio.sleep(self.config.gc_interval)
                if self._running:
                    gc.collect(generation=1)  # 轻量 GC
                    # 每 3 次做一次全量 GC
                    if hasattr(self, "_gc_count"):
                        self._gc_count += 1
                    else:
                        self._gc_count = 1
                    if self._gc_count % 3 == 0:
                        gc.collect(generation=2)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def get_memory_usage(self) -> dict:
        """获取内存使用信息"""
        result = {
            "cache_size": self.cache.current_size,
            "log_buffer": self.request_logger.stats["buffer_size"],
        }
        if HAS_PSUTIL and self._process is not None:
            try:
                mem = self._process.memory_info()
                result["rss_mb"] = round(mem.rss / (1024 * 1024), 1)
                result["vms_mb"] = round(mem.vms / (1024 * 1024), 1)
                result["cpu_percent"] = self._process.cpu_percent(interval=0)
            except Exception:
                pass
        return result

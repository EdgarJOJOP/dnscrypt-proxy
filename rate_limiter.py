"""
per-IP 速率限制器（共享单例）
所有服务器（DoH/DoT/DoQ/PlainDNS）共享同一份 IP→Semaphore 映射，
避免每个服务器各自维护独立字典导致的内存浪费。
"""

import time
import asyncio
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger("dns-proxy.ratelimit")


class PerIPRateLimiter:
    """
    按客户端 IP 限速的共享单例。
    所有本地 DNS 服务器（DoH/DoT/DoQ/Plain）引用同一实例，
    避免每个服务器各自维护一份 IP→Semaphore 映射的重复内存开销。
    """

    def __init__(self, per_ip_limit: int = 50,
                 cleanup_interval: int = 300,
                 idle_timeout: int = 600):
        self._per_ip_limit = per_ip_limit
        self._cleanup_interval = cleanup_interval
        self._idle_timeout = idle_timeout
        self._semaphores: Dict[str, Tuple[asyncio.Semaphore, float]] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    def start(self):
        """启动过期条目清理任务"""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """停止清理任务"""
        self._running = False
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def acquire(self, client_ip: str) -> asyncio.Semaphore:
        """获取或创建指定客户端 IP 的信号量，并更新时间戳"""
        now = time.time()
        async with self._lock:
            if client_ip in self._semaphores:
                sem, _ = self._semaphores[client_ip]
                self._semaphores[client_ip] = (sem, now)
                return sem
            sem = asyncio.Semaphore(self._per_ip_limit)
            self._semaphores[client_ip] = (sem, now)
            return sem

    async def _cleanup_loop(self):
        """定期清理过期 IP 条目"""
        while self._running:
            await asyncio.sleep(self._cleanup_interval)
            try:
                await self._cleanup_stale()
            except Exception:
                pass

    async def _cleanup_stale(self):
        """移除超过空闲超时的条目"""
        now = time.time()
        async with self._lock:
            stale = [
                ip for ip, (_, ts) in self._semaphores.items()
                if now - ts > self._idle_timeout
            ]
            for ip in stale:
                del self._semaphores[ip]
        if stale:
            logger.debug("PerIPRateLimiter: 清理了 %d 个过期 IP 条目", len(stale))

    @property
    def count(self) -> int:
        return len(self._semaphores)

    async def clear(self):
        """清空所有条目"""
        async with self._lock:
            self._semaphores.clear()


# ======================== 模块级单例 ========================
# 所有服务器引用同一个实例，消除重复的 per-IP dict 内存

_per_ip_limiter_instance: Optional[PerIPRateLimiter] = None


def get_per_ip_limiter(per_ip_limit: int = 50,
                       cleanup_interval: int = 300,
                       idle_timeout: int = 600) -> PerIPRateLimiter:
    """获取共享的 PerIPRateLimiter 单例"""
    global _per_ip_limiter_instance
    if _per_ip_limiter_instance is None:
        _per_ip_limiter_instance = PerIPRateLimiter(
            per_ip_limit=per_ip_limit,
            cleanup_interval=cleanup_interval,
            idle_timeout=idle_timeout,
        )
    return _per_ip_limiter_instance

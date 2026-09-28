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
                 idle_timeout: int = 600,
                 max_entries: int = 10000):
        self._per_ip_limit = per_ip_limit
        self._cleanup_interval = cleanup_interval
        self._idle_timeout = idle_timeout
        # 容量上限：UDP 源 IP 可伪造，无上限会让字典被海量不同源 IP 撑爆
        self._max_entries = max_entries
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
            if len(self._semaphores) >= self._max_entries:
                self._evict_locked(now)
            sem = asyncio.Semaphore(self._per_ip_limit)
            self._semaphores[client_ip] = (sem, now)
            return sem

    def _evict_locked(self, now: float) -> None:
        """容量达上限时的淘汰：先清空闲超时条目，仍超限则淘汰最旧的一批

        调用方必须已持有 self._lock。
        """
        stale = [
            ip for ip, (_, ts) in self._semaphores.items()
            if now - ts > self._idle_timeout
        ]
        for ip in stale:
            self._semaphores.pop(ip, None)
        overflow = len(self._semaphores) - int(self._max_entries * 0.9)
        if overflow <= 0:
            return
        oldest = sorted(self._semaphores.items(), key=lambda kv: kv[1][1])[:overflow]
        for ip, _ in oldest:
            self._semaphores.pop(ip, None)
        logger.warning(
            "PerIPRateLimiter: 条目数达上限 %d，已淘汰 %d 个最旧条目",
            self._max_entries, len(oldest),
        )

    def set_per_ip_limit(self, limit: int) -> None:
        """更新每 IP 并发上限（供单例构造方同步配置）

        已存在的信号量按旧限额创建，因此清空重建，使新限额对所有 IP 生效。
        """
        if not limit or limit == self._per_ip_limit:
            return
        self._per_ip_limit = limit
        self._semaphores.clear()
        logger.info("PerIPRateLimiter: 每 IP 并发上限更新为 %d", limit)

    @property
    def per_ip_limit(self) -> int:
        return self._per_ip_limit

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
                       idle_timeout: int = 600,
                       max_entries: int = 10000) -> PerIPRateLimiter:
    """获取共享的 PerIPRateLimiter 单例

    单例首次创建后，后续调用若传入不同的 per_ip_limit，会同步更新限额
    （此前参数被静默忽略，谁先初始化就定终身，与各服务端配置不符）。
    """
    global _per_ip_limiter_instance
    if _per_ip_limiter_instance is None:
        _per_ip_limiter_instance = PerIPRateLimiter(
            per_ip_limit=per_ip_limit,
            cleanup_interval=cleanup_interval,
            idle_timeout=idle_timeout,
            max_entries=max_entries,
        )
    elif per_ip_limit is not None:
        _per_ip_limiter_instance.set_per_ip_limit(per_ip_limit)
    return _per_ip_limiter_instance

"""
QPS 限速器（滑动窗口）
- 限制每秒最大请求数
- 超过限制时自动等待（不拒绝请求，只是排队）
"""

import time
import asyncio
import logging
from collections import deque

logger = logging.getLogger("dns-proxy.qps")


class QPSCounter:
    """滑动窗口 QPS 限速器"""

    def __init__(self, max_qps: int, name: str = ""):
        self._max_qps = max_qps
        self._name = name
        self._timestamps: deque = deque()
        self._lock = asyncio.Lock()

    @property
    def max_qps(self) -> int:
        return self._max_qps

    def set_max_qps(self, qps: int):
        """运行时更新 QPS 上限"""
        self._max_qps = max(0, qps)

    async def acquire(self):
        """等待直到可以放行一个请求（超限时 sleep 等待）"""
        if self._max_qps <= 0:
            return  # 0 或负数表示无限制

        async with self._lock:
            now = time.monotonic()
            cutoff = now - 1.0

            # 清理超过 1 秒的旧时间戳
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._max_qps:
                # 超过 QPS 上限，等待最旧的请求过期
                wait = self._timestamps[0] + 1.0 - now
                if wait > 0:
                    if self._name:
                        logger.debug("QPS[%s] 限速中，等待 %.1fms", self._name, wait * 1000)
                    await asyncio.sleep(wait)
                # 等待后重新清理
                now = time.monotonic()
                cutoff = now - 1.0
                while self._timestamps and self._timestamps[0] <= cutoff:
                    self._timestamps.popleft()

            self._timestamps.append(now)

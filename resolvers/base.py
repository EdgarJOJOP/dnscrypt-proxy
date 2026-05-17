"""
DNS 解析器基类 - 定义所有上游解析器的统一接口
"""

import abc
import asyncio
from typing import Optional, Tuple, Dict, Any
import time


class BaseResolver(abc.ABC):
    """解析器基类"""

    def __init__(self, address: str, timeout: float = 5.0, weight: int = 1):
        self.address = address
        self.timeout = timeout
        self.weight = weight
        self._semaphore = asyncio.Semaphore(10)
        self._stats: Dict[str, Any] = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_time": 0.0,
            "avg_response_time": 0.0,
        }
        self._name = self._extract_name(address)

    def _extract_name(self, address: str) -> str:
        """从地址中提取可读名称"""
        addr = address.replace("https://", "").replace("quic://", "")
        return addr.split("/")[0].split(":")[0]

    @property
    def name(self) -> str:
        return self._name

    @abc.abstractmethod
    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """
        执行 DNS 查询
        Args:
            query_bytes: DNS 查询的原始字节
        Returns:
            DNS 响应的原始字节，失败返回 None
        """
        ...

    async def resolve_with_stats(self, query_bytes: bytes) -> Tuple[Optional[bytes], float]:
        """带统计的查询"""
        start = time.monotonic()
        result = await self.resolve(query_bytes)
        elapsed = time.monotonic() - start

        self._stats["total_queries"] += 1
        if result is not None:
            self._stats["successful_queries"] += 1
        else:
            self._stats["failed_queries"] += 1
        self._stats["total_time"] += elapsed
        total_ok = self._stats["successful_queries"]
        self._stats["avg_response_time"] = (
            self._stats["total_time"] / total_ok if total_ok > 0 else 0
        )

        return result, elapsed

    @abc.abstractmethod
    async def close(self):
        """关闭释放资源"""
        ...

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.address})"

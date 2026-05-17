"""
DNS 缓存模块
- LRU 淘汰策略
- 可配置 TTL
- 过期条目自动清理
- 线程安全（asyncio.Lock）
"""

import time
import asyncio
import logging
from typing import Optional, Tuple, Dict, Any
from collections import OrderedDict

import dns.message

logger = logging.getLogger("dns-proxy.cache")


class DNSCache:
    """DNS 缓存 - LRU + TTL"""

    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int = 300,
        min_ttl: int = 30,
        max_ttl: int = 86400,
        negative_ttl: int = 60,
        cleanup_interval: int = 60,
    ):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self.cleanup_interval = cleanup_interval

        # LRU 缓存: {cache_key: CacheEntry}
        self._cache: OrderedDict[Tuple, "CacheEntry"] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats: Dict[str, Any] = {
            "hits": 0,
            "misses": 0,
            "size": 0,
            "evictions": 0,
        }

    async def get(self, key: Tuple) -> Optional[dns.message.Message]:
        """
        获取缓存条目。
        key: (qname, qtype, qclass)
        返回解析后的 DNS 消息（已调整 TTL）
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._stats["misses"] += 1
                return None

            if entry.is_expired():
                del self._cache[key]
                self._stats["misses"] += 1
                return None

            # LRU: 移动到末尾（最近使用）
            self._cache.move_to_end(key)
            self._stats["hits"] += 1
            return entry.get_adjusted_response()

    async def set(
        self, key: Tuple, response: dns.message.Message, is_negative: bool = False
    ):
        """
        设置缓存条目
        key: (qname, qtype, qclass)
        """
        async with self._lock:
            # 如果已存在，先删除
            if key in self._cache:
                del self._cache[key]

            # 计算 TTL
            ttl = self._calculate_ttl(response) if not is_negative else self.negative_ttl

            # 创建缓存条目
            entry = CacheEntry(response, ttl)

            # LRU 淘汰
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)  # 移除最久未使用的
                self._stats["evictions"] += 1

            self._cache[key] = entry
            self._stats["size"] = len(self._cache)

    def _calculate_ttl(self, response: dns.message.Message) -> int:
        """从 DNS 响应中计算合适 TTL"""
        min_ttl = self.default_ttl
        for rrset in response.answer:
            for rd in rrset:
                if hasattr(rd, "ttl") and rd.ttl < min_ttl:
                    min_ttl = rd.ttl
        # 约束到配置范围
        return max(self.min_ttl, min(min_ttl, self.max_ttl))

    async def cleanup_expired(self):
        """清理过期条目"""
        async with self._lock:
            now = time.time()
            expired_keys = [
                k for k, v in self._cache.items() if v.is_expired(now)
            ]
            for k in expired_keys:
                del self._cache[k]
            self._stats["size"] = len(self._cache)
            if expired_keys:
                logger.debug("清理了 %d 个过期缓存条目", len(expired_keys))

    async def clear(self):
        """清空缓存"""
        async with self._lock:
            self._cache.clear()
            self._stats["size"] = 0
            self._stats["evictions"] = 0

    async def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        async with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            hit_rate = (self._stats["hits"] / total * 100) if total > 0 else 0
            return {
                **self._stats,
                "hit_rate": round(hit_rate, 2),
            }

    @property
    def current_size(self) -> int:
        return len(self._cache)


class CacheEntry:
    """缓存条目"""

    __slots__ = ("response_wire", "ttl", "created_at", "is_negative")

    def __init__(self, response: dns.message.Message, ttl: int):
        # 缓存序列化后的字节数据以减少内存
        self.response_wire: bytes = response.to_wire()
        self.ttl: int = ttl
        self.created_at: float = time.time()

    def is_expired(self, now: Optional[float] = None) -> bool:
        """判断是否过期"""
        if now is None:
            now = time.time()
        return (now - self.created_at) >= self.ttl

    def get_adjusted_response(self) -> dns.message.Message:
        """获取已调整 TTL 的响应"""
        response = dns.message.from_wire(self.response_wire)
        elapsed = time.time() - self.created_at
        remaining = max(1, int(self.ttl - elapsed))

        for rrset in response.answer:
            for rd in rrset:
                if hasattr(rd, "ttl"):
                    rd.ttl = remaining
        return response

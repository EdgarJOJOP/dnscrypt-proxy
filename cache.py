"""
DNS 缓存模块
- LRU 淘汰策略
- 可配置 TTL
- 过期条目自动清理
- 线程安全（asyncio.Lock）
- 缓存反序列化后的 DNS 消息，减少 from_wire() 开销
- 预构建常见查询模板，避免重复 make_query()
"""

import time
import asyncio
import copy
import logging
from typing import Optional, Tuple, Dict, Any
from collections import OrderedDict
from functools import lru_cache

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.name
import dns.rdatatype

logger = logging.getLogger("dns-proxy.cache")


MAX_CACHED_WIRE_SIZE = 8 * 1024



# ======================== 查询模板缓存 ========================
# 预构建常见 DNS 查询的 wire_bytes，避免每次 make_query() 重建对象

_query_template_cache: Dict[Tuple[str, int, bool], bytes] = {}


def get_query_wire(qname: str, rdtype: int, rdclass: int = 1,
                   want_dnssec: bool = False) -> bytes:
    """
    获取预构建的 DNS 查询 wire bytes。
    缓存常见查询（A/AAAA/TXT/HTTPS 等类型），避免反复 make_query() + to_wire()。
    抛出 UnicodeError 时返回空 bytes，由调用者处理。
    """
    key = (qname.lower(), rdtype, want_dnssec)
    cached = _query_template_cache.get(key)
    if cached is not None:
        return cached

    try:
        name = dns.name.from_text(qname)
        msg = dns.message.make_query(name, rdtype, rdclass, want_dnssec=want_dnssec)
        wire = msg.to_wire()
    except (UnicodeError, ValueError) as e:
        logger.warning("get_query_wire: 跳过非法域名 '%s' (%s)", qname, e)
        return b""
    # 仅缓存有限数量（常见域名查询可复用，极端域名不计）
    if len(_query_template_cache) < 512:
        _query_template_cache[key] = wire
    return wire


def clear_query_cache():
    """清空查询模板缓存（配置变更时调用）"""
    _query_template_cache.clear()


class CacheEntry:
    """缓存条目 — 仅缓存反序列化后的 Message，不保存 wire 以节省内存"""

    __slots__ = ("response_msg", "ttl",
                 "created_at", "_estimated_bytes")

    def __init__(self, response: dns.message.Message, ttl: int):
        # 缓存反序列化后的 Message 对象，避免每次 get 都 from_wire()
        # 注意：传出时通过 copy 避免修改缓存内容
        self.response_msg: dns.message.Message = response
        self.ttl: int = ttl
        self.created_at: float = time.time()
        # 存储 wire 字节数，供优化器按大小淘汰
        self._estimated_bytes: int = len(response.to_wire())

    @property
    def estimated_bytes(self) -> int:
        """返回该缓存条目的估算字节数（用于内存优化器按大小淘汰）"""
        return self._estimated_bytes

    def is_expired(self, now: Optional[float] = None) -> bool:
        """判断是否过期"""
        if now is None:
            now = time.time()
        return (now - self.created_at) >= self.ttl

    def get_adjusted_response(self) -> dns.message.Message:
        """
        获取已调整 TTL 的响应（浅拷贝 + TTL 覆写，避免 from_wire 全量反序列化）。
        """
        elapsed = time.time() - self.created_at
        remaining = max(1, int(self.ttl - elapsed))

        # 从缓存的 Message 浅拷贝，避免 from_wire() 全量解析
        response = copy.copy(self.response_msg)
        # 浅拷贝 answer 列表，但复用底层的 rrset 和 rdata 对象
        # 然后逐个覆写 TTL（不影响缓存中的原始值）
        response.answer = list(self.response_msg.answer)
        # 为每个 RRset 创建新实例以安全修改 TTL
        new_answer = []
        for rrset in response.answer:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                if hasattr(new_rd, "ttl"):
                    new_rd.ttl = remaining
                new_rrset.add(new_rd)
            new_answer.append(new_rrset)
        response.answer = new_answer

        # 同样处理 authority 和 additional 段
        response.authority = list(self.response_msg.authority)
        new_auth = []
        for rrset in response.authority:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                if hasattr(new_rd, "ttl"):
                    new_rd.ttl = remaining
                new_rrset.add(new_rd)
            new_auth.append(new_rrset)
        response.authority = new_auth

        response.additional = list(self.response_msg.additional)
        new_add = []
        for rrset in response.additional:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                if hasattr(new_rd, "ttl"):
                    new_rd.ttl = remaining
                new_rrset.add(new_rd)
            new_add.append(new_rrset)
        response.additional = new_add

        return response


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
        超过 MAX_CACHED_WIRE_SIZE 的响应不被缓存，避免单个大条目撑破内存
        """
        async with self._lock:
            # 如果已存在，先删除
            if key in self._cache:
                del self._cache[key]

            # 计算 TTL
            ttl = self._calculate_ttl(response) if not is_negative else self.negative_ttl

            # 检查单条目最大尺寸，超过则不缓存
            wire_len = len(response.to_wire())
            if wire_len > MAX_CACHED_WIRE_SIZE:
                logger.debug("跳过缓存超大 DNS 响应: %d bytes (限制 %d)，key=%s",
                             wire_len, MAX_CACHED_WIRE_SIZE, key)
                self._stats["misses"] += 1
                return

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

    async def evict_largest(self, ratio: float = 0.2) -> int:
        """按估算字节大小淘汰最大的 N% 条目（用于内存紧张时主动压缩）。
        跳过已过期条目（它们应由 cleanup_expired 处理）。
        Args:
            ratio: 淘汰比例（0.2 = 淘汰最大的 20%）
        Returns:
            实际淘汰的条目数
        """
        async with self._lock:
            if not self._cache:
                return 0
            target = max(1, int(len(self._cache) * ratio))
            # 按估算字节数排序，淘汰最大的
            sorted_by_size = sorted(
                self._cache.items(),
                key=lambda item: item[1].estimated_bytes,
                reverse=True,
            )
            evicted = 0
            for k, _ in sorted_by_size[:target]:
                if k in self._cache:
                    del self._cache[k]
                    evicted += 1
            self._stats["size"] = len(self._cache)
            self._stats["evictions"] += evicted
            if evicted:
                logger.info("按字节大小淘汰了 %d 个最大缓存条目 (目标 %d)，剩余 %d",
                            evicted, target, len(self._cache))
            return evicted

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

    async def get_all_keys(self) -> list:
        """获取所有缓存的 key 列表（用于缓存扫描）"""
        async with self._lock:
            return list(self._cache.keys())

    async def peek(self, key: Tuple) -> Optional[dns.message.Message]:
        """
        查看缓存条目但不更新 LRU 位置（用于缓存扫描）
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.is_expired():
                del self._cache[key]
                return None
            return entry.get_adjusted_response()

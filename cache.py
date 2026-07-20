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
import gc
import logging
from typing import Optional, Tuple, Dict, Any
from collections import OrderedDict
from functools import lru_cache

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset

logger = logging.getLogger("dns-proxy.cache")


MAX_CACHED_WIRE_SIZE = 8 * 1024



# ======================== 查询模板缓存 ========================
# 预构建常见 DNS 查询的 wire_bytes，避免每次 make_query() 重建对象
# 使用 functools.lru_cache 实现有界缓存 + LRU 淘汰：
#   - 内存始终 <= 512 条目 -> 攻击下内存有界
#   - 使用原始 (str, int, bool) 作为键 -> 无 hash 碰撞风险
#   - LRU 自动淘汰冷条目 -> 热域名长期保留，冷域名释放


@lru_cache(maxsize=512)
def _cached_get_query_wire(qname: str, rdtype: int, want_dnssec: bool) -> bytes:
    """带 LRU 缓存的查询 wire bytes 构建（内部函数）。

    使用 functools.lru_cache 而非手写 Dict，原因：
    - 自动 LRU 淘汰：攻击场景下旧条目自动释放，内存有界
    - 正确的键语义：不存在 hash 碰撞风险
    - 冷域名字符串随 LRU 淘汰自动 GC

    Args:
        qname: 已 lower() 的域名
        rdtype: DNS 记录类型
        want_dnssec: 是否请求 DNSSEC
    Returns:
        wire bytes 或空 bytes（异常时）
    """
    try:
        name = dns.name.from_text(qname)
        msg = dns.message.make_query(name, rdtype, 1, want_dnssec=want_dnssec)
        wire = msg.to_wire()
        return wire
    except (UnicodeError, ValueError) as e:
        logger.warning("get_query_wire: 跳过非法域名 '%s' (%s)", qname, e)
        return b""


def get_query_wire(qname: str, rdtype: int, rdclass: int = 1,
                   want_dnssec: bool = False) -> bytes:
    """
    获取预构建的 DNS 查询 wire bytes。
    缓存常见查询（A/AAAA/TXT/HTTPS 等类型），避免反复 make_query() + to_wire()。

    缓存策略：
    - lru_cache(maxsize=512)：内存始终有界
    - LRU 淘汰：热域名命中率高，冷域名自动释放

    抛出 UnicodeError 时返回空 bytes，由调用者处理。
    """
    return _cached_get_query_wire(qname.lower(), rdtype, want_dnssec)


def clear_query_cache():
    """清空查询模板缓存（配置变更时调用）"""
    _cached_get_query_wire.cache_clear()


def evict_cold_query_templates():
    """清理冷查询模板缓存。

    lru_cache 已自动处理 LRU 淘汰，此函数保留以兼容 optimizer.py 调用。
    全量清空后在下次 rebuild 后给缓存一个干净起点。
    """
    _cached_get_query_wire.cache_clear()
    logger.debug("查询模板缓存已全量清空 (lru_cache maxsize=512)")


class CacheEntry:
    """缓存条目 — Wire-First 双轨存储

    主存储是紧凑的 wire bytes（单个连续内存块），`dns.message.Message` 降级为
    可丢弃的加速缓存。在内存压力下可丢弃 Message 对象，仅保留 wire bytes，
    下次访问时通过 from_wire() 惰性水合。
    """

    __slots__ = ("_wire", "_response_msg", "ttl", "created_at", "epoch", "_hit_count")

    def __init__(self, response: dns.message.Message, ttl: int, epoch: int = 0):
        # 主存储：序列化为紧凑的 wire bytes
        self._wire: bytes = response.to_wire()
        # 加速缓存：保留反序列化后的 Message 对象（可被 drop）
        self._response_msg: Optional[dns.message.Message] = response
        self.ttl: int = ttl
        self.created_at: float = time.time()
        self.epoch: int = epoch  # 分配世代（用于 arena 生命周期追踪）
        self._hit_count: int = 0  # 命中次数（用于智能 Message 丢弃）

    @property
    def response_msg(self) -> dns.message.Message:
        """惰性水合：按需从 wire bytes 重建 Message 对象"""
        if self._response_msg is None:
            self._response_msg = dns.message.from_wire(self._wire)
        return self._response_msg

    @response_msg.setter
    def response_msg(self, value: dns.message.Message):
        self._response_msg = value

    def has_message(self) -> bool:
        """检查 Message 对象是否仍在内存中（无需水合）"""
        return self._response_msg is not None

    def drop_message(self):
        """丢弃 Message 对象，仅保留 wire bytes（节省内存）"""
        self._response_msg = None

    @property
    def estimated_bytes(self) -> int:
        """返回该缓存条目的估算字节数（wire 长度，紧凑且准确）"""
        return len(self._wire)

    def is_expired(self, now: Optional[float] = None) -> bool:
        """判断是否过期"""
        if now is None:
            now = time.time()
        return (now - self.created_at) >= self.ttl

    def get_adjusted_response(self) -> dns.message.Message:
        """
        获取已调整 TTL 的响应（浅拷贝 + TTL 覆写，避免 from_wire 全量反序列化）。
        通过 self.response_msg property 获取 Message（必要时从 wire 惰性水合）。

        ★ 修复 P3: 剩余 TTL >= 95% 原始 TTL 时走轻量路径，跳过逐段深拷贝
        """
        elapsed = time.time() - self.created_at
        remaining = max(1, int(self.ttl - elapsed))

        # 通过 property 获取 Message（惰性水合），然后浅拷贝
        msg = self.response_msg

        # ★ P3: 剩余 TTL >= 95% 时走轻量路径（仍修改所有 answer，仅跳过 authority/additional 深拷贝）
        if remaining >= self.ttl * 0.95:
            response = copy.copy(msg)
            response.answer = list(msg.answer)
            # 修改所有 answer 的 TTL（不依赖 rrset 顺序）
            new_answer = []
            for rrset in response.answer:
                new_rrset = dns.rrset.RRset(
                    rrset.name, rrset.rdclass, rrset.rdtype,
                    rrset.covers,
                )
                for rd in rrset:
                    new_rd = copy.copy(rd)
                    new_rrset.add(new_rd, ttl=remaining)
                new_answer.append(new_rrset)
            response.answer = new_answer
            # authority 和 additional 直接用原引用（它们的 TTL 不影响答案）
            response.authority = list(msg.authority)
            response.additional = list(msg.additional)
            return response

        # ===== 完整深拷贝路径（TTL 偏差 > 5%） =====
        response = copy.copy(msg)
        response.answer = list(msg.answer)
        # 为每个 RRset 创建新实例以安全修改 TTL
        new_answer = []
        for rrset in response.answer:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                new_rrset.add(new_rd, ttl=remaining)
            new_answer.append(new_rrset)
        response.answer = new_answer

        # 同样处理 authority 和 additional 段
        response.authority = list(msg.authority)
        new_auth = []
        for rrset in response.authority:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                new_rrset.add(new_rd, ttl=remaining)
            new_auth.append(new_rrset)
        response.authority = new_auth

        response.additional = list(msg.additional)
        new_add = []
        for rrset in response.additional:
            new_rrset = dns.rrset.RRset(
                rrset.name, rrset.rdclass, rrset.rdtype,
                rrset.covers,
            )
            for rd in rrset:
                new_rd = copy.copy(rd)
                new_rrset.add(new_rd, ttl=remaining)
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

        # ===== Arena 世代追踪 =====
        self._current_epoch: int = 0          # 当前活跃世代编号
        self._epoch_stats: Dict[int, int] = {}  # epoch -> 存活条目数

        # ===== ★ 修复 P1: 插入计数器（用于 defrag 触发） =====
        self._insert_count: int = 0            # 自上次 defrag/重置以来的插入次数

    def _bump_epoch(self):
        """递增世代编号（在 rebuild 时调用），标记 arena 代际边界"""
        self._current_epoch += 1
        self._epoch_stats = {self._current_epoch: 0}
        logger.debug("升级到世代 %d", self._current_epoch)

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
            entry._hit_count += 1
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

            # 一次性序列化 wire，避免重复 to_wire() 调用
            wire = response.to_wire()
            if len(wire) > MAX_CACHED_WIRE_SIZE:
                logger.debug("跳过缓存超大 DNS 响应: %d bytes (限制 %d)，key=%s",
                             len(wire), MAX_CACHED_WIRE_SIZE, key)
                self._stats["misses"] += 1
                return

            # 计算 TTL
            ttl = self._calculate_ttl(response) if not is_negative else self.negative_ttl

            # 创建缓存条目（传入预序列化的 wire）
            entry = CacheEntry.__new__(CacheEntry)
            entry._wire = wire
            entry._response_msg = response
            entry.ttl = ttl
            entry.created_at = time.time()
            entry.epoch = self._current_epoch
            entry._hit_count = 0

            # LRU 淘汰
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)  # 移除最久未使用的
                self._stats["evictions"] += 1

            self._cache[key] = entry
            self._stats["size"] = len(self._cache)
            # ★ P1: 记录一次插入（用于 defrag 触发计数）
            self._insert_count += 1

    def _calculate_ttl(self, response: dns.message.Message) -> int:
        """从 DNS 响应中计算合适 TTL"""
        min_ttl = self.default_ttl
        for rrset in response.answer:
            if hasattr(rrset, 'ttl') and rrset.ttl is not None and rrset.ttl < min_ttl:
                min_ttl = rrset.ttl
        # 约束到配置范围
        return max(self.min_ttl, min(min_ttl, self.max_ttl))

    async def evict_largest(self, ratio: float = 0.2) -> int:
        """按估算字节大小淘汰最大的 N% 条目（跳过已过期条目）。
        Args:
            ratio: 淘汰比例（0.2 = 淘汰最大的 20%）
        Returns:
            实际淘汰的条目数
        """
        async with self._lock:
            if not self._cache:
                return 0
            now = time.time()
            candidates = [(k, v) for k, v in self._cache.items() if not v.is_expired(now)]
            if not candidates:
                return 0
            target = max(1, int(len(candidates) * ratio))
            # 按估算字节数排序，淘汰最大的
            sorted_by_size = sorted(
                candidates,
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

    async def drop_messages_lru(self, ratio: float = 0.3) -> int:
        """丢弃 LRU 尾部 N% 条目的 Message 对象，仅保留 wire bytes。

        从 OrderedDict 头部（最久未使用）开始遍历，丢弃 Message 加速缓存。
        这样在下次访问这些条目时会触发惰性水合（from_wire），
        但释放了复杂对象图占用的 pymalloc arena 空间。

        Args:
            ratio: 丢弃比例（0.3 = 丢弃 LRU 尾部 30% 的 Message 对象）
        Returns:
            实际丢弃的条目数
        """
        async with self._lock:
            if not self._cache:
                return 0
            target = max(1, int(len(self._cache) * ratio))
            dropped = 0
            # OrderedDict 头部是最久未使用的
            for i, key in enumerate(self._cache):
                if i >= target:
                    break
                entry = self._cache[key]
                if entry.has_message():
                    entry.drop_message()
                    dropped += 1
            if dropped:
                logger.debug("丢弃了 %d 个条目的 Message 对象 (LRU 尾部 %.0f%%)",
                             dropped, ratio * 100)
            return dropped

    async def compact_messages(self, ratio: float = 0.3) -> int:
        """★ 修复 P2: 智能丢弃最低命中率条目的 Message 对象。

        利用 _hit_count 追踪，丢弃缓存中命中率最低的 N% 条目的
        Message 加速缓存（保留 wire bytes）。
        """
        async with self._lock:
            if not self._cache:
                return 0
            target = max(1, int(len(self._cache) * ratio))
            # 按命中次数升序排序（最低命中的在前）
            sorted_by_hits = sorted(
                self._cache.items(),
                key=lambda item: item[1]._hit_count,
            )
            dropped = 0
            for key, entry in sorted_by_hits[:target]:
                if entry.has_message():
                    entry.drop_message()
                    dropped += 1
            if dropped:
                logger.debug("★ 智能丢弃 %d 个低命中率条目的 Message 对象 (按 _hit_count)", dropped)
            return dropped

    # ★ P1: 插入计数器读取/重置方法
    def get_and_reset_insert_count(self) -> int:
        """读取并重置插入计数器（asyncio 单线程下 int 赋值原子）。"""
        count = self._insert_count
        self._insert_count = 0
        return count

    async def rebuild(self) -> int:
        """全量撤离+重建 — TLB 友好分配版本

        TLB (Thread-Local Buffer) 分配策略：
        所有新 CacheEntry 在 GC 后的紧循环中连续分配，
        保证它们落入同一批新 pymalloc arena，arena 利用率最大化。

        流程：
        1. 持有锁：收集存活条目 (key, wire_bytes, ttl, created_at)
        2. 持有锁：清空缓存 + 提升世代
        3. 释放锁：4 轮全量 GC → 让旧 arena 变成 fully-free → munmap
        4. 重新持有锁：TLB 批量分配所有新 CacheEntry（无 Message 对象）
        5. 新条目标记为新世代，初始 _hit_count = 0
           ★ 不覆盖 GC 期间其他协程写入的新数据
        Returns:
            幸存条目数
        """
        # 第一阶段：在锁内收集存活数据并清空缓存
        async with self._lock:
            if not self._cache:
                return 0
            now = time.time()
            # 收集（跳过过期），使用 list() 快照避免迭代时修改
            items = [(key, entry._wire, entry.ttl, entry.created_at)
                     for key, entry in list(self._cache.items())
                     if not entry.is_expired(now)]
            old_count = len(self._cache)
            self._cache.clear()
            # 提升世代，标记 arena 代际边界
            new_epoch = self._current_epoch + 1
            self._current_epoch = new_epoch
            self._epoch_stats = {new_epoch: len(items)}

        # 第二阶段：释放锁后执行 4 轮全量 GC
        # pymalloc 在 GC 时会扫描所有 arena，将完全空闲的 pool 合并后 munmap
        # 4 轮确保所有链式引用被彻底遍历
        for _ in range(4):
            gc.collect(generation=2)

        # 第三阶段：TLB 批量分配 — 重新持有锁，从 wire bytes 紧凑重建
        async with self._lock:
            survived = 0
            # 按 wire 大小升序回填：同大小 wire 连续分配，减少堆碎片
            items.sort(key=lambda x: len(x[1]))
            for key, wire, ttl, created_at in items:
                # ★ 修复 P0: 不覆盖锁外 GC 期间其他协程写入的新数据
                if key in self._cache:
                    continue
                # 通过 __new__ + 手动赋值（TLB 友好：无额外对象分配）
                entry = CacheEntry.__new__(CacheEntry)
                entry._wire = wire
                entry._response_msg = None  # 惰性水合，首次访问时 from_wire
                entry.ttl = ttl
                entry.created_at = created_at
                entry.epoch = new_epoch       # 标记新世代
                entry._hit_count = 0          # 重置命中计数
                self._cache[key] = entry
                survived += 1

            self._stats["size"] = len(self._cache)
            self._stats["evictions"] += old_count - survived

        logger.info("缓存重建完成: 旧条目 %d -> 新世代 %d 幸存 %d (淘汰 %d 过期, 跳过 %d 新写入)",
                    old_count, new_epoch, survived, old_count - survived,
                    len(items) - survived)
        return survived

    async def defrag(self) -> int:
        """碎片整理：重排条目 + 全代 GC

        重排条目顺序使其在 pymalloc arena 中紧凑排列，
        self._cache.clear() 触发引用计数释放老 CacheEntry，
        其 pymalloc pool 变为 fully-free 后被 munmap。
        然后执行 gc.collect(2) 作为安全网，确保循环引用也被清理。
        """
        async with self._lock:
            if not self._cache:
                return 0
            now = time.time()
            items = [(key, entry._wire, entry.ttl, entry.created_at, entry._hit_count)
                     for key, entry in self._cache.items()
                     if not entry.is_expired(now)]
            self._cache.clear()
            items.sort(key=lambda x: len(x[1]))
            for key, wire, ttl, created_at, hit_count in items:
                entry = CacheEntry.__new__(CacheEntry)
                entry._wire = wire
                entry._response_msg = None
                entry.ttl = ttl
                entry.created_at = created_at
                entry.epoch = self._current_epoch
                entry._hit_count = hit_count
                self._cache[key] = entry
            self._stats["size"] = len(self._cache)

        # ★ P2: 锁外执行 3 轮全代 GC — 确保所有旧 arena 变为 fully-free → munmap
        #     多轮 GC 确保所有链式引用被彻底遍历（与 rebuild() 逻辑一致）
        for _ in range(3):
            gc.collect(generation=2)

        # ★ P2: defrag 后重置插入计数器，下次 defrag 从干净起点开始计数
        self._insert_count = 0

        logger.debug("★ 缓存碎片整理完成，条目数: %d (3轮全代GC, 重置insert_count)", len(self._cache))
        return len(self._cache)

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

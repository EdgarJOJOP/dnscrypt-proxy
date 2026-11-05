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
import heapq
import logging
from typing import Optional, Tuple, Dict, Any, List
from collections import OrderedDict
from functools import lru_cache

import dns.message
import dns.name
import dns.rcode
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


def _is_zero_answer(response: dns.message.Message) -> bool:
    """应答是否为「零地址映射」（A=0.0.0.0 / AAAA=::）

    这类条目来自 **hosts 自定义 IP 映射**（用户故意指向 0.0.0.0 屏蔽某个
    域名）。它们**不能进预刷新堆**：预刷新会重新走上游解析该域名、拿到真实
    IP 后覆写缓存，用户的自定义映射就悄悄失效了。
    （拦截应答统一是 NXDOMAIN、answer 为空，本来就不会入堆。）
    """
    try:
        for rrset in response.answer:
            for rd in rrset:
                if rd.rdtype == dns.rdatatype.A and str(rd.address) == "0.0.0.0":
                    return True
                if rd.rdtype == dns.rdatatype.AAAA and str(rd.address) == "::":
                    return True
    except Exception:
        pass
    return False


def _clamp_response_ttl(response: dns.message.Message, cap: int) -> None:
    """把响应各段 RRset 的 TTL 截断到不高于 ``cap``（就地修改）

    目的：让**返回给客户端的 TTL** 与本地缓存寿命一致。上游常给 86400 这类
    长 TTL，若原样透传给客户端，客户端会缓存一整天，而本地缓存只保留
    ``max_ttl``（默认 3600 秒）——上游更换 IP 后客户端仍用旧记录，表现为
    「首次访问 TTL 特大、刷新后才正常、个别站点打不开」。
    """
    if cap is None or cap <= 0:
        return
    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            try:
                if rrset.ttl > cap:
                    rrset.ttl = cap
            except Exception:
                continue


class CacheEntry:
    """缓存条目 — Wire-First 双轨存储

    主存储是紧凑的 wire bytes（单个连续内存块），`dns.message.Message` 降级为
    可丢弃的加速缓存。在内存压力下可丢弃 Message 对象，仅保留 wire bytes，
    下次访问时通过 from_wire() 惰性水合。
    """

    __slots__ = ("_wire", "_response_msg", "ttl", "created_at", "epoch",
                 "_hit_count", "_seq", "blocked")

    def __init__(self, response: dns.message.Message, ttl: int, epoch: int = 0,
                 blocked: bool = False):
        # 主存储：序列化为紧凑的 wire bytes
        self._wire: bytes = response.to_wire()
        # 加速缓存：保留反序列化后的 Message 对象（可被 drop）
        self._response_msg: Optional[dns.message.Message] = response
        self.ttl: int = ttl
        self.created_at: float = time.time()
        self.epoch: int = epoch  # 分配世代（用于 arena 生命周期追踪）
        self._hit_count: int = 0  # 命中次数（用于智能 Message 丢弃）
        self._seq: int = 0        # 预刷新调度序号（0 = 未调度）
        # 是否为过滤引擎写入的**拦截占位应答**（A=0.0.0.0 / AAAA=:: / NXDOMAIN）。
        # 规则放宽（删规则 / 加 @@ 例外 / hosts 白名单）后，规则重载的 sweep
        # 依据该标记精确删除旧拦截条目，而不是靠猜应答内容（真实 NXDOMAIN、
        # 以及用户自定义 hosts 映射到 0.0.0.0 的条目长得完全一样）。
        self.blocked: bool = bool(blocked)

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

        # ⚠ dnspython 的 Message 把四个 section 存在 `msg.sections` 里，
        # answer / authority / additional 都是映射到 sections 的 property；
        # copy.copy() 只做浅拷贝 → sections 与外层列表都和源对象共享。
        # 一旦下面写 `response.answer = ...` / `response.authority = []`，
        # 改动会**穿透到缓存条目本身**（实测：条目 authority 在第一次 get
        # 之后永久变空，多协程并发 get 还会互相踩 TTL/顺序）。
        # 这里必须把 sections 复制成独立列表。
        response = copy.copy(msg)
        response.sections = [list(section) for section in msg.sections]

        # ★ P3: 剩余 TTL >= 95% 时走轻量路径（仍修改所有 answer，仅跳过 authority/additional 深拷贝）
        if remaining >= self.ttl * 0.95:
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
            response.authority = []
            for rrset in msg.authority:
                new_rrset = copy.copy(rrset)
                new_rrset.ttl = remaining
                response.authority.append(new_rrset)
            response.additional = []
            for rrset in msg.additional:
                new_rrset = copy.copy(rrset)
                new_rrset.ttl = remaining
                response.additional.append(new_rrset)
            return response

        # ===== 完整深拷贝路径（TTL 偏差 > 5%） =====
        # response 已在函数开头复制（含独立的 sections），这里直接复用
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
        prefetch_enabled: bool = True,
        prefetch_advance_ratio: float = 0.5,
        ttl_floor_threshold: int = 5,
    ):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self.cleanup_interval = cleanup_interval
        # 「min_ttl 下限豁免」阈值（秒，0 = 关闭整个抬升）。
        # 语义：**只有上游 TTL > 该阈值**的记录才把不足 min_ttl 的寿命抬到
        #   min_ttl；TTL <= 阈值（默认 5 秒）的极短记录完全尊重权威原值
        #   （这类记录通常是 DDNS/健康检查/动态调度，变化极快）。
        # ⚠ 抬升本身是非标准扩展，违反 RFC 2181 §5.1（"TTL 不得增加"）。
        #   设 0 即恢复纯 RFC 行为。见 _calculate_ttl 的完整说明。
        try:
            self._ttl_floor_threshold = max(0, min(60, int(ttl_floor_threshold)))
        except (TypeError, ValueError):
            self._ttl_floor_threshold = 5
        # ===== 主动预刷新（最小堆动态调度）=====
        # 开启后：正应答条目在 set() 时按「最终 TTL（权威 TTL 经 max_ttl 向下
        # 钳制，必要时按 min_ttl 抬升）推导出的刷新时刻」入堆；
        # 后台循环休眠到堆顶时刻再成批刷新——因此不存在固定扫描周期，
        # 刷新节奏由 TTL 参数与 advance_ratio 共同决定。
        self.prefetch_enabled = bool(prefetch_enabled)
        self._prefetch_ratio = max(0.0, min(1.0, float(prefetch_advance_ratio)))

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

        # ===== 主动预刷新堆：[(next_refresh_at, seq, key)] =====
        # 队列无长度上限、可随时插入；seq 用于惰性作废
        # （同 key 被覆盖/淘汰后，堆中旧元素自动失效）。
        self._prefetch_heap: List[Tuple[float, int, Tuple]] = []
        self._seq_counter: int = 0

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
        self, key: Tuple, response: dns.message.Message, is_negative: bool = False,
        blocked: bool = False,
    ):
        """
        设置缓存条目
        key: (qname, qtype, qclass)
        超过 MAX_CACHED_WIRE_SIZE 的响应不被缓存，避免单个大条目撑破内存

        blocked: 该条目是**过滤引擎生成的拦截占位应答**（A=0.0.0.0 /
        AAAA=:: / 其它类型的 NXDOMAIN）。标记随条目保存，规则重载的
        `_sweep_cache_after_filter_load` 据此在规则放宽后精确删除旧拦截
        条目（见 is_blocked_entry / discard），否则客户端会一直被旧缓存
        挡到 TTL 到期（最长 max_ttl）。
        """
        async with self._lock:
            # RFC 2308 §7：只有 NOERROR（含 NODATA）与 NXDOMAIN 可以缓存。
            # REFUSED / SERVFAIL / FORMERR / NOTIMP 等**错误应答不入缓存**：
            # 早期实现把 REFUSED 当负应答缓存 negative_ttl 秒，于是单台上游的
            # 一次临时 REFUSED 就能让该域名在本机整个 TTL 内持续失败（服务
            # 降级，且客户端拿到的是"权威拒绝"这种误导性结论）。
            try:
                if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                    return
            except Exception:
                pass

            # 如果已存在，先删除
            if key in self._cache:
                del self._cache[key]

            # 计算 TTL（正应答基于上游原始 TTL；负应答按 RFC 2308 §5 取
            # min(SOA.TTL, SOA.MINIMUM)，拿不到 SOA 才退回配置的 negative_ttl）
            if is_negative:
                ttl = self._negative_ttl_from_soa(response)
            else:
                ttl = self._calculate_ttl(response)

            # RFC 2181 §5.1：TTL=0 的记录只能用于当前事务，不得缓存。
            # 早期实现会照常插入并**先淘汰一条健康条目**，结果是每次 get 都 miss
            # 却反复挤掉有效缓存，与 _calculate_ttl 里"TTL<=0 视为不可缓存"的
            # 注释正好相反。
            if ttl <= 0:
                return

            # 把响应各段 RRset 的 TTL 截断到不高于缓存 TTL，再返回给客户端。
            # 否则首次应答会携带上游原始 TTL（常见 86400），客户端（浏览器/系统
            # 解析器）会把这条记录缓存一整天，而本地缓存只保留 max_ttl（默认
            # 3600 秒）——上游换 IP 后客户端仍用旧记录，表现为「首次访问 TTL
            # 特别大、刷新后才正常、某些站点打不开」。
            _clamp_response_ttl(response, ttl)

            # 一次性序列化 wire，避免重复 to_wire() 调用
            wire = response.to_wire()
            if len(wire) > MAX_CACHED_WIRE_SIZE:
                logger.debug("跳过缓存超大 DNS 响应: %d bytes (限制 %d)，key=%s",
                             len(wire), MAX_CACHED_WIRE_SIZE, key)
                self._stats["misses"] += 1
                return

            # 创建缓存条目（传入预序列化的 wire）
            entry = CacheEntry.__new__(CacheEntry)
            entry._wire = wire
            entry._response_msg = response
            entry.ttl = ttl
            entry.created_at = time.time()
            entry.epoch = self._current_epoch
            entry._hit_count = 0
            # 必须显式初始化调度序号：__slots__ 已声明 _seq，未赋值时任何读取
            # （pop_due_prefetch / 调试 / 未来的清理逻辑）都会抛 AttributeError。
            # 与 rebuild()/defrag() 保持一致（0 = 未调度）。
            entry._seq = 0
            entry.blocked = bool(blocked)

            # LRU 淘汰
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)  # 移除最久未使用的
                self._stats["evictions"] += 1

            self._cache[key] = entry
            self._stats["size"] = len(self._cache)
            # ★ P1: 记录一次插入（用于 defrag 触发计数）
            self._insert_count += 1
            # 主动预刷新：仅正应答入堆。拦截应答是 NXDOMAIN（answer 为空），
            # 天然不入堆；hosts 的零地址映射（0.0.0.0 / ::）**必须显式排除**，
            # 否则预刷新会重新走上游、把用户的映射覆盖成真实 IP。
            if (self.prefetch_enabled and ttl > 0 and response.answer
                    and not _is_zero_answer(response)):
                self._schedule_prefetch(key, entry)

    async def discard(self, key: Tuple) -> bool:
        """按缓存键删除单条条目，返回是否真的删除了条目。

        用途：过滤规则**放宽**（删除规则 / 新增 ``@@`` 例外 / hosts 白名单）后，
        把缓存里仍是拦截占位的旧条目删掉，让下一次查询重新走上游。

        预刷新堆无需同步清理：堆元素带 seq，`pop_due_prefetch` 会按
        「条目仍存在 + seq 一致」惰性校验，条目被删除后这些元素（幽灵元素）
        自然被跳过。
        """
        async with self._lock:
            entry = self._cache.pop(key, None)
            if entry is None:
                return False
            self._stats["size"] = len(self._cache)
            return True

    async def is_blocked_entry(self, key: Tuple) -> bool:
        """该缓存条目是否为过滤引擎写入的拦截占位。

        标记由拦截分支 `set(..., blocked=True)` 写入；历史条目（升级前写入、
        没有标记）返回 False，调用方可用应答内容（0.0.0.0 / :: / NXDOMAIN）
        做兜底判断。
        """
        async with self._lock:
            entry = self._cache.get(key)
            return bool(entry is not None and getattr(entry, "blocked", False))

    def _negative_ttl_from_soa(self, response: dns.message.Message) -> int:
        """负应答缓存时长（RFC 2308 §5：min(SOA.TTL, SOA.MINIMUM)）

        `negative_ttl` 作为**上限**（用户希望负应答不要缓存太久）：
          - SOA 允许 900s、negative_ttl=60 → 60（尊重配置上限）
          - SOA 只允许 5s、negative_ttl=60  → 5（不得超过权威授权时长）
        拿不到 authority SOA（本地生成的拦截 NXDOMAIN、上游未回 SOA）时
        退回 negative_ttl。
        """
        try:
            cap = max(1, int(self.negative_ttl))
            max_ttl = max(1, int(self.max_ttl))
            for rrset in response.authority:
                if rrset.rdtype != dns.rdatatype.SOA:
                    continue
                for rdata in rrset:
                    minimum = int(getattr(rdata, "minimum", 0) or 0)
                    soa_ttl = int(getattr(rrset, "ttl", 0) or 0)
                    if minimum > 0 and soa_ttl > 0:
                        allowed = min(soa_ttl, minimum)
                    elif minimum > 0:
                        allowed = minimum
                    elif soa_ttl > 0:
                        allowed = soa_ttl
                    else:
                        break
                    return max(1, min(allowed, cap, max_ttl))
                break
        except Exception:
            pass
        return max(1, min(int(self.negative_ttl), int(self.max_ttl)))

    def _calculate_ttl(self, response: dns.message.Message) -> int:
        """从 DNS 响应中计算缓存 TTL（RFC 2181 §5.1 + 一处显式标注的非标准扩展）

        语义：
          - 取响应 answer 段中最小的有效 TTL 作为基线（权威授权时长）；
          - `max_ttl` 是向下的上限钳制（保护本机内存与"最长缓存"意图）；
          - `min_ttl` 是**缓存 TTL 下限**，但**豁免极短 TTL**：
              * 上游 TTL > ttl_floor_threshold（默认 5s）→ 不足 min_ttl 的抬到
                min_ttl（常规 min-cache-ttl 下限保护）；
              * 上游 TTL <= ttl_floor_threshold → **完全尊重权威原值**，不抬升。
                这类 1-5 秒的记录通常是 DDNS / 健康检查 / 动态调度，变化极快，
                强行缓存在原地会让客户端拿到过期数据；
              * 完全没有 TTL 信息 → 用 max(default_ttl, min_ttl) 兜底；
          - ⚠ "TTL > 阈值时抬到 min_ttl"这一步是**非标准扩展**，违反 RFC 2181
            §5.1（"TTL 不得增加"；BIND 的 min-cache-ttl 同样被官方标注为非标准）。
            把 `cache.ttl_floor_threshold` 设为 0 即完全关闭，回到纯 RFC 行为：
            此时一律 `min(上游 TTL, max_ttl)`；
          - TTL <= 0 视为不可缓存（返回 0）。

        该函数同时服务**加密上游（DoH/DoT/DoQ）与纯迭代**两条路径：四个前端
        （plain/DoH/DoT/DoQ）与 resolver_manager 都经由 `cache.set()` 落盘，
        因此 upstream: enabled 时走的是同一套规则（含同一处抬升豁免逻辑），
        不会因为"上游是加密的"而不同。
        """
        resp_ttl: Optional[int] = None
        for rrset in response.answer:
            t = getattr(rrset, 'ttl', None)
            if t is None:
                continue
            if resp_ttl is None or t < resp_ttl:
                resp_ttl = t
        if resp_ttl is None:
            # 完全没有 TTL 信息来源（空 answer / 无 rrset）→ 兜底基线。
            # min_ttl 的**唯一**作用点：保证这类条目至少缓存 min_ttl 秒。
            resp_ttl = max(self.default_ttl, self.min_ttl)
        if resp_ttl <= 0:
            return 0
        # RFC 2181 §5.1：只允许向下钳制（max_ttl 封顶），绝不向上抬升。
        capped = min(resp_ttl, self.max_ttl)
        # ---- 非标准扩展：min_ttl 下限（豁免极短 TTL）----
        # 规则：**只有上游 TTL > ttl_floor_threshold（默认 5s）的记录**才把不足
        #       min_ttl 的缓存寿命抬到 min_ttl；TTL <= 阈值的极短记录**完全尊重
        #       权威原值**（1-5 秒通常是 DDNS / 健康检查 / 动态调度，变化极快，
        #       强行原地缓存会让客户端拿到过期数据）。
        # ⚠ 抬升这一步明确违反 RFC 2181 §5.1（"TTL 不得增加"；BIND 的
        #   min-cache-ttl 同样被官方标注为非标准扩展）。设
        #   cache.ttl_floor_threshold: 0 → 关闭，回到纯 RFC 行为（一律只向下钳制）。
        #   副作用：抬升后缓存寿命变长，get_adjusted_response() 返回给客户端的
        #   TTL（= 缓存剩余寿命）也随之变大，客户端会被动延长缓存——这正是
        #   "常规下限保护"想要的效果，但它同时也是同一处 RFC 偏离。
        threshold = getattr(self, "_ttl_floor_threshold", 0)
        if (threshold > 0
                and resp_ttl > threshold
                and self.min_ttl > capped):
            capped = min(self.min_ttl, self.max_ttl)
        return max(1, capped)

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

    # ==================== 主动预刷新（最小堆动态调度） ====================

    def _schedule_prefetch(self, key: Tuple, entry: "CacheEntry"):
        """把一条正应答条目排入预刷新堆（须在持锁状态下调用）。

        刷新时刻 = created_at + 最终 TTL - 提前量，其中
          提前量 = min(最终 TTL * advance_ratio,
                       最终 TTL - max(1 秒, 最终 TTL * advance_ratio))
        —— 保底至少留 max(1 秒, advance_ratio*最终 TTL) 的等待，避免刚插入
        就到期而空转。若上式右侧为负（TTL 极小、advance_ratio 很大时），
        提前量取 0（即不提前，等条目自然到期），不会出现负提前量。

        注意：min_ttl 是「无 TTL 信息时的兜底下限」，**不是**「缓存 TTL 下限」，
        也不参与真实 TTL 的钳制（RFC 2181 §5.1 禁止抬升上游 TTL）。旧实现用
        max(min_ttl, TTL*advance_ratio) 作为提前量，会让所有最终 TTL <= min_ttl
        的条目（旧 _calculate_ttl 会把上游 TTL < min_ttl 的响应钳到 min_ttl）
        提前量被夹到 TTL-1 → 刷新时刻 = 插入后 1 秒，形成「每秒重新查询
        上游一次」的死循环（实测稳态每秒上百次上游查询）。
        """
        ttl = entry.ttl
        if ttl <= 0:
            return
        advance = ttl * self._prefetch_ratio
        # 保底等待：至少 1 秒，且不少于 advance_ratio*TTL（advance_ratio>=1 时
        # 提前量收敛为 0，即不提前刷新，而非插入即到期）
        min_wait = max(1.0, ttl * self._prefetch_ratio)
        advance = min(advance, ttl - min_wait)
        if advance < 0.0:
            advance = 0.0
        self._seq_counter += 1
        entry._seq = self._seq_counter
        heapq.heappush(self._prefetch_heap,
                       (entry.created_at + ttl - advance, self._seq_counter, key))

    async def pop_due_prefetch(self, limit: int = 1000) -> list:
        """取出已到预刷新时刻的有效条目键（最多 limit 个）。

        堆中可能存在幽灵元素（同 key 被覆盖/淘汰）——用 (存在性、seq、
        未过期) 惰性校验后丢弃，无需主动删除。堆本身无长度上限。
        """
        now = time.time()
        out: list = []
        async with self._lock:
            heap = self._prefetch_heap
            while heap and len(out) < limit:
                next_at, seq, key = heap[0]
                if next_at > now:
                    break
                heapq.heappop(heap)
                entry = self._cache.get(key)
                if entry is None or entry._seq != seq:
                    continue          # 已被 LRU 淘汰或被新的 set() 覆盖
                if entry.ttl <= 0 or entry.is_expired(now):
                    continue          # 已过期：交由 get() 的 miss 路径处理
                out.append(key)
        return out

    async def peek_next_prefetch_at(self) -> Optional[float]:
        """堆顶的下一预刷新时刻（供后台循环动态 sleep）；堆空返回 None。"""
        async with self._lock:
            return self._prefetch_heap[0][0] if self._prefetch_heap else None

    @property
    def prefetch_backlog(self) -> int:
        """当前堆中待调度条目数（监控用）"""
        return len(self._prefetch_heap)

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
            # blocked 标记必须随条目一起迁移：否则 rebuild 之后拦截占位会
            # 退化成"按 0.0.0.0/:: 识别"，NXDOMAIN 类型的拦截占位就再也
            # 无法被规则放宽时的反向清理识别。
            items = [(key, entry._wire, entry.ttl, entry.created_at,
                      getattr(entry, "blocked", False))
                     for key, entry in list(self._cache.items())
                     if not entry.is_expired(now)]
            old_count = len(self._cache)
            # 预刷新堆重建：记录旧堆中已调度的 key（缓存被整体重建后
            # 原堆元素全部失效，需按新条目重新排入以保留调度）
            old_scheduled = {k for _, _, k in self._prefetch_heap}
            self._prefetch_heap = []
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
            for key, wire, ttl, created_at, blocked in items:
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
                entry._seq = 0                # 调度序号由 _schedule_prefetch 重分配
                entry.blocked = blocked       # 保留拦截占位标记
                self._cache[key] = entry
                # 保留原预刷新调度（刷新时刻基于 created_at，不受 rebuild 影响）
                if key in old_scheduled and ttl > 0:
                    self._schedule_prefetch(key, entry)
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
            items = [(key, entry._wire, entry.ttl, entry.created_at, entry._hit_count,
                      getattr(entry, "blocked", False))
                     for key, entry in self._cache.items()
                     if not entry.is_expired(now)]
            old_scheduled = {k for _, _, k in self._prefetch_heap}
            self._prefetch_heap = []
            self._cache.clear()
            items.sort(key=lambda x: len(x[1]))
            for key, wire, ttl, created_at, hit_count, blocked in items:
                entry = CacheEntry.__new__(CacheEntry)
                entry._wire = wire
                entry._response_msg = None
                entry.ttl = ttl
                entry.created_at = created_at
                entry.epoch = self._current_epoch
                entry._hit_count = hit_count
                entry._seq = 0
                entry.blocked = blocked   # 保留拦截占位标记
                self._cache[key] = entry
                if key in old_scheduled and ttl > 0:
                    self._schedule_prefetch(key, entry)
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
            self._prefetch_heap.clear()
            self._seq_counter = 0
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

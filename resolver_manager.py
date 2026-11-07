"""
并行解析管理器
- 并行查询所有上游服务器
- 取最快成功响应返回
- 支持普通 DNS、DoH、DoT、DoQ
- Bootstrap 解析上游服务器域名
"""

import asyncio
import collections
import ipaddress
import logging
import os
import time
import tempfile
import atexit
from typing import List, Optional, Dict, Any, Tuple

import dns.message
import dns.name
import dns.rdatatype
import dns.asyncquery
import dns.flags

import aiohttp

from config import Config
from consistency_verifier import ResponseConsistencyVerifier, ResponseRecord, ConsistencyVerdict
from anomaly_detector import AnomalyDetector
from crypto.ech_fetcher import ECHConfigFetcher
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from resolvers.base import BaseResolver
from resolvers.doh import DoHResolver, _MultiHostResolver
from resolvers.dot import DoTResolver
from cache import get_query_wire, clear_query_cache
from resolvers.doq import DoQResolver
from resolvers.plain import PlainDNSResolver

# OpenSSL 4.0 ECH（可选：ctypes 加载 DLL，失败不影响现有功能）
try:
    from crypto.openssl_ctypes import OpenSSL4Wrapper as _OpenSSL4Wrapper
    _HAS_OPENSSL4 = True
except ImportError:
    _HAS_OPENSSL4 = False

if _HAS_OPENSSL4:
    # ECHDoHResolver（resolvers/ech_doh.py）只能走 HTTP/1.1，与「上游 DoH 仅 h3/h2」
    # 策略冲突，已停用：ECH 的 DoH 上游改由 DoHResolver + Python ssl(ECH) 承担。
    from resolvers.ech_dot import ECHDoTResolver

logger = logging.getLogger("dns-proxy.resolver")


class UpstreamServer:
    """上游服务器封装"""

    # 健康评分权重
    _SCORE_WEIGHT_FAILURES = 100   # 每次失败扣分
    _SCORE_WEIGHT_LATENCY = 10     # 每100ms延迟扣分
    _SCORE_BONUS_DOH = 20          # DoH 偏好（综合性能好）
    _SCORE_BONUS_DOQ = 15          # DoQ 偏好
    _SCORE_BONUS_DOT = 0           # DoT 基线
    _MAX_RESPONSE_TIMES = 10       # 滑动窗口大小

    def __init__(self, resolver: BaseResolver, server_type: str):
        self.resolver = resolver
        self.server_type = server_type  # "doh", "dot", "doq", "plain"
        self.failures = 0
        self.consecutive_failures = 0
        self.enabled = True
        # 响应时间滑动窗口（最近 _MAX_RESPONSE_TIMES 次）
        self._response_times = collections.deque(maxlen=self._MAX_RESPONSE_TIMES)

    @property
    def name(self) -> str:
        return self.resolver.name

    @property
    def avg_response_time(self) -> float:
        """平均响应时间（秒），无数据返回 999"""
        if not self._response_times:
            return 999.0
        return sum(self._response_times) / len(self._response_times)

    @property
    def health_score(self) -> float:
        """
        健康评分（越高越好）。
        综合：延迟、失败次数、协议类型。
        """
        if not self.enabled:
            return -9999
        score = 1000.0
        # 协议偏好
        proto_bonus = {
            "doh": self._SCORE_BONUS_DOH,
            "doq": self._SCORE_BONUS_DOQ,
            "dot": self._SCORE_BONUS_DOT,
            "iterative": self._SCORE_BONUS_DOH,  # 迭代解析同 DoH 偏好（独立 DNSSEC 严格验证）
        }.get(self.server_type, 0)
        score += proto_bonus
        # 失败扣分
        score -= self.failures * self._SCORE_WEIGHT_FAILURES
        score -= self.consecutive_failures * self._SCORE_WEIGHT_FAILURES * 3
        # 延迟扣分：每100ms扣分，平滑处理。无历史数据（avg=999 默认值）时不扣分
        #——否则迭代解析（首次参与、无延迟样本）会被初始 999 排除出首波优选
        if self.avg_response_time < 999.0:
            score -= int(self.avg_response_time / 0.1) * self._SCORE_WEIGHT_LATENCY
        return score

    def record_success(self, response_time: Optional[float] = None):
        # 指数衰减：不硬清零，保留部分历史失败记录
        # 防止刚恢复的服务器因一次成功就获得过高权重
        self.consecutive_failures = 0
        if self.failures > 0:
            self.failures = max(0, self.failures - 2)  # 每次成功衰减2
        if response_time is not None:
            self._response_times.append(response_time)

    def record_failure(self, allow_disable: bool = True):
        """记一次失败（连续失败 5 次时暂时禁用该上游）

        ``allow_disable=False``：只累计计数、不禁用。用于「唯一上游」场景——
        纯迭代模式只有 iterative 一个上游，把它禁用会让整机解析直接瘫痪，
        随后被 _auto_recover 重新启用，形成 禁用↔恢复 的抖动（日志表现为
        「没有可用的上游服务器，触发自动恢复...」反复出现）。
        """
        self.consecutive_failures += 1
        self.failures += 1
        # 连续失败 5 次，暂时禁用
        if allow_disable and self.consecutive_failures >= 5:
            self.enabled = False
            logger.debug("上游 %s 连续失败 %d 次，已暂时禁用", self.name, self.consecutive_failures)

    def reenable(self):
        if not self.enabled:
            self.enabled = True
            self.consecutive_failures = 0
            logger.info("上游 %s 已重新启用", self.name)


class ResolverManager:
    """并行解析管理器"""

    def __init__(self, config: Config, dnssec_wrapper: Optional[DNSSECQueryWrapper] = None,
                 consistency_verifier: Optional[ResponseConsistencyVerifier] = None,
                 anomaly_detector: Optional[AnomalyDetector] = None,
                 iterative_resolver: Optional["IterativeResolver"] = None):
        self.config = config
        self._iterative_resolver = iterative_resolver  # 迭代解析上游（根→TLD→权威）
        self._upstream_servers: List[UpstreamServer] = []
        self._bootstrap_resolvers: List[UpstreamServer] = []
        self._bootstrap_cache: Dict[str, List[str]] = {}  # hostname -> [ips]
        self._bootstrap_lock = asyncio.Lock()
        self._concurrent_semaphore: Optional[asyncio.Semaphore] = None
        self._bootstrap_ready = asyncio.Event()
        self._dnssec = dnssec_wrapper  # DNSSEC 查询包装器（可选）
        self._recovery_task: Optional[asyncio.Task] = None  # 自动重连任务
        self._recovery_mode = False  # 恢复模式：刚恢复网络时不因瞬时失败禁用上游
        # 集群故障冷却：上次所有上游全部失败的时间戳
        self._last_all_failed_time = 0.0
        # 冷却期：距上次全部失败不足此时长时，新查询等待剩余时间再发起
        self._all_failed_cooldown = 1.0
        # 启动缓冲：程序启动后前 3 秒内上游失败时等待再试，不触发重试风暴
        self._start_time = 0.0
        self._startup_buffer = 3.0
        # 波次查询失败统计（供 _parallel_resolve_once 汇总日志使用）
        self._failure_stats = {}
        # 重试互斥锁：只有一个并发请求执行重试，其余直接返回 SERVFAIL
        self._retry_lock = asyncio.Lock()
        self._retry_version = 0  # 每次重试递增，避免锁排队请求重复重试
        # 网络断开标志：网络不可达时不查询上游、不打日志，直接返回 SERVFAIL
        self._network_down = False
        self._network_down_reported = False  # 避免重复日志
        # 连续全部失败计数器与静默模式（阶段1：智能退避 + 日志压制）
        self._consecutive_all_failed_counter: int = 0       # 连续全部失败轮数
        self._all_failed_start_time: float = 0.0            # 首次全部失败时间戳
        self._silent_mode: bool = False                     # 静默模式：抑制所有日志
        self._last_silent_probe_time: float = 0.0           # 末次探活时间
        self._silent_probe_interval: float = 60.0           # 探活间隔（秒）
        self._all_failed_silent_rounds: int = getattr(config, 'all_failed_silent_rounds', 5)  # 进入静默的阈值
        # 单查询总预算（硬上限）：所有前端（DoH/DoT/DoQ/plain）都只是 await
        # resolve()，它们自己没有解析超时——纯迭代模式下单查询可能跑到
        # IterativeResolver.total_timeout。前端 6s 已经给客户端回了 504，
        # 底层 handler 却继续空跑 → 事件循环饱和（所以必须硬取消）。
        #
        # 基准取 parallel_timeout×5 = 10s：**故意比前端 forward_timeout(6s) 长**。
        # 这样「长 CNAME 链、8-10s 才解析完」的域名（如 s1.hdslb.com 这类
        # bilibili 图床：CNAME 4-6 级 + 无 glue 的 NS 名还要单独迭代）仍能完成
        # 并写入缓存；浏览器重试/后续访问直接命中缓存，不会每次重跑一遍又失败。
        #
        # 注意：这个 10s 只跟 performance.parallel_timeout 有关，**与
        # iterative.timeout_ms（单跳超时，默认 5000ms）无关**——见
        # _effective_query_budget()：纯迭代模式下它还要与迭代器自身预算对齐。
        self._base_query_budget: float = max(
            3.0,
            min(15.0, float(getattr(config, "parallel_timeout", 2.0) or 2.0) * 5.0),
        )
        # 跨层回调：ResolverManager → NetworkMonitor（全部失败时通知）
        self._on_all_upstreams_failed: Optional[callable] = None
        self._ech_fetchers: Dict[str, ECHConfigFetcher] = {}  # hostname -> ECHConfigFetcher
        self._ech_warmup_failed: set = set()  # hostnames whose ECH warmup all failed
        self._openssl4_wrapper = None  # OpenSSL 4.0 wrapper（ECH；如不可用则为 None）
        # 全局共享的 aiohttp.ClientSession（所有 DoH 上游共用，消除多个连接池）
        self._shared_doh_session: Optional[aiohttp.ClientSession] = None
        self._shared_doh_resolver: Optional[_MultiHostResolver] = None
        # DNS 响应一致性验证器（多上游交叉验证，可选）
        self._consistency_verifier = consistency_verifier
        # DNS 响应异常检测器（RTT/大小/TTL 基线，可选）
        self._anomaly_detector = anomaly_detector
        # 最近一次成功解析的最快上游名称（用于后台一致性验证）
        self._last_fast_server: Optional[str] = None
        self._last_fast_server_obj: Optional[UpstreamServer] = None
        # 进行中的查询（并发合并）：key=(qname, qtype, class, DO, CD) -> Future
        # 客户端超时重发的同一查询会共享这次解析，不再重复跑迭代。
        self._inflight_queries: Dict[Tuple, asyncio.Future] = {}
        # 后台一致性验证节流
        self._consistency_check_count = 0  # 1/10 采样计数器

    async def initialize(self):
        """初始化所有解析器（先 bootstrap 再剩余部分，兼容旧接口）"""
        await self._init_bootstrap()
        await self._init_remaining()

    async def _init_bootstrap(self):
        """
        第一阶段初始化：创建 bootstrap 解析器并解析上游服务器域名。
        纯网络 IO，不依赖过滤规则或 NTP，可与其他启动任务并行执行。
        """
        self._start_time = asyncio.get_event_loop().time()
        self._concurrent_semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # 1. 创建 bootstrap 解析器（普通 DNS）
        if not self.config.bootstrap_resolvers:
            logger.warning("未配置 bootstrap 解析器！系统 DNS 自引用（127.0.0.1）可能导致死锁")
        for addr in self.config.bootstrap_resolvers:
            # 防御：Config 层已把 PyYAML 误解析的 dict 还原成字符串；这里仍
            # 逐条容错——单条坏配置只跳过该条，绝不让整个 bootstrap 初始化
            # 任务异常（否则上游域名解析不到 IP，所有加密上游一起不可用）。
            if not isinstance(addr, str):
                logger.warning("跳过非法 bootstrap 解析器配置项: %r", addr)
                continue
            addr = addr.strip()
            if not addr:
                continue
            try:
                resolver = PlainDNSResolver(addr, timeout=5.0, concurrency=self.config.connection_pool_size)
            except Exception as e:
                logger.warning("创建 bootstrap 解析器 %r 失败，已跳过: %s", addr, e)
                continue
            self._bootstrap_resolvers.append(UpstreamServer(resolver, "plain"))

        # 检查是否有任何上游服务器（加密上游 + 迭代解析上游）
        total_upstreams = (len(self.config.doh_servers) + len(self.config.dot_servers)
                           + len(self.config.doq_servers))
        has_iterative = self._iterative_resolver is not None
        if total_upstreams == 0 and not has_iterative:
            logger.warning("未配置任何上游服务器（doh/dot/doq 均为空且 iterative 未启用），"
                           "所有查询将返回 SERVFAIL")
            self._bootstrap_ready.set()
            return
        if total_upstreams == 0:
            # 纯迭代模式（upstream.enabled=false 或 doh/dot/doq 全空）：
            # 迭代解析用 IP 根列表，不需要 bootstrap 解析上游域名（bootstrap 解析器
            # 对象已在上面创建，但整个模式不会向它发起查询）；
            # 上游注册在 main 调用的 _init_remaining() 中完成（此处只置就绪标志）
            logger.info("未配置/未启用加密上游，仅使用迭代解析上游（根→TLD→权威）")
            self._bootstrap_ready.set()
            return

        # 2. 解析上游服务器域名 -> IP
        logger.info("正在通过 bootstrap DNS 解析上游服务器地址...")
        await self._resolve_upstream_hostnames()

    async def _init_remaining(self):
        """
        第二阶段初始化：ECH fetchers、共享 DoH session、上游解析器等。
        必须在 _init_bootstrap() 完成后调用（依赖 bootstrap 解析结果）。
        """
        total_upstreams = (len(self.config.doh_servers) + len(self.config.dot_servers)
                           + len(self.config.doq_servers))
        if total_upstreams == 0 and self._iterative_resolver is None:
            return
        if total_upstreams == 0:
            # 纯迭代模式（upstream.enabled=false 或 doh/dot/doq 全空）：
            # 跳过加密上游专用初始化（ECH fetchers、共享 DoH session、DoQ 全局
            # 并发上限），只注册迭代解析上游。
            await self._create_upstream_resolvers()
            self._bootstrap_ready.set()
            enabled_count = sum(1 for s in self._upstream_servers if s.enabled)
            logger.info("解析器初始化完成（纯迭代模式）: %d 个上游可用 / %d 个总数",
                        enabled_count, len(self._upstream_servers))
            for s in self._upstream_servers:
                logger.info("  上游: [%s] %s (启用=%s)", s.server_type, s.name, s.enabled)
            return

        # 3. 创建 ECH fetchers（每台上游一个，支持 TTL 缓存 + 后台刷新）
        if self.config.ech_enabled:
            logger.info("正在创建 ECH 配置获取器...")
            await self._init_ech_fetchers()

            # 3b. 尝试加载 OpenSSL 4.0（为真正的 ECH 做准备）
            has_enabled_fetcher = any(f.enabled for f in self._ech_fetchers.values())
            if _HAS_OPENSSL4 and has_enabled_fetcher:
                dll_dir = self.config.openssl4_dll_path
                self._openssl4_wrapper = _OpenSSL4Wrapper(dll_dir)
                if self._openssl4_wrapper.available:
                    logger.info("OpenSSL 4.0 已加载，将对上游启用真正的 ECH")
                else:
                    logger.warning("OpenSSL 4.0 DLL 不可用，ECH 将降级为传统 TLS")
            else:
                logger.info("无 ECH 配置或 OpenSSL 4.0 不可用，跳过")

        # 3b. 创建全局共享的 aiohttp.ClientSession（所有 DoH 上游共用）
        #     显著减少独立连接池的内存开销
        await self._init_shared_doh_session()

        # 4. 创建加密上游解析器
        await self._create_upstream_resolvers()

        # 5. 将 connection_pool_size 注入 DoQ 全局并发限制
        from resolvers.doq import set_doq_global_concurrency
        set_doq_global_concurrency(self.config.connection_pool_size)

        self._bootstrap_ready.set()
        enabled_count = sum(1 for s in self._upstream_servers if s.enabled)
        logger.info("解析器初始化完成: %d 个上游可用 / %d 个总数, %d 个 bootstrap",
                     enabled_count, len(self._upstream_servers), len(self._bootstrap_resolvers))
        for s in self._upstream_servers:
            logger.info("  上游: [%s] %s (启用=%s)", s.server_type, s.name, s.enabled)
        for s in self._bootstrap_resolvers:
            logger.info("  Bootstrap: %s", s.name)

    async def _resolve_upstream_hostnames(self):
        """解析上游 DoH/DoT/DoQ 服务器域名到 IP"""
        all_hostnames = set()
        for url in self.config.doh_servers:
            host = url.replace("https://", "").split("/")[0].split(":")[0]
            all_hostnames.add(host)
        for host in self.config.dot_servers:
            h = host.split(":")[0]
            all_hostnames.add(h)
        for addr in self.config.doq_servers:
            host = addr.replace("quic://", "").split(":")[0]
            all_hostnames.add(host)

        if not all_hostnames:
            logger.debug("无上游域名需要解析（所有主机名已为空）")
            return

        # 固定顺序（set 的迭代顺序在同一对象被修改后会变化，避免
        # 「协程创建顺序」与「结果配对顺序」不一致导致 IP 串域名）
        hostnames = sorted(all_hostnames)
        results = await asyncio.gather(
            *[self._bootstrap_resolve(hostname) for hostname in hostnames],
            return_exceptions=True,
        )

        for hostname, result in zip(hostnames, results):
            if isinstance(result, list) and result:
                # 去重并保留顺序
                seen = set()
                deduped = []
                for ip in result:
                    if ip not in seen:
                        seen.add(ip)
                        deduped.append(ip)
                self._bootstrap_cache[hostname] = deduped
                v4 = [ip for ip in result if ":" not in ip]
                v6 = [ip for ip in result if ":" in ip]
                parts = []
                if v4:
                    parts.append(f"v4={','.join(v4[:2])}")
                if v6:
                    parts.append(f"v6={','.join(v6[:2])}")
                logger.info("  %s -> %s", hostname, " ".join(parts))
            else:
                logger.warning("  无法解析 %s", hostname)

    @staticmethod
    def _is_suspicious_bootstrap_ip(ip: str) -> bool:
        """过滤明显可疑的 bootstrap 应答 IP（DNS 劫持/污染特征）：
        - 回环 127.0.0.0/8、::1（劫持者常把未知域名解析到本地）
        - 未指定 0.0.0.0/::、私网 10/8、172.16/12、192.168/16、fc00::/7
        - 链路本地 169.254/16、fe80::/10、组播 224/4、ff00::/8、保留地址
        """
        try:
            ip_obj = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return True
        return (ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_private
                or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)

    async def _bootstrap_resolve(self, hostname: str) -> List[str]:
        """
        通过 bootstrap DNS 解析域名（A + AAAA 双栈独立查询）
        单栈环境下（IPv4-only / IPv6-only），一种查询失败不影响另一种
        """
        queries = {}
        for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            wire = get_query_wire(hostname, qtype)
            if wire:
                queries[qtype] = wire

        async def try_resolver(qbytes: bytes, bs: UpstreamServer, addr_family: str) -> Optional[bytes]:
            try:
                return await bs.resolver.resolve(qbytes, prefer_family=addr_family)
            except Exception:
                return None
        deadline = asyncio.get_event_loop().time() + 10.0  # 总超时 10 秒

        for attempt in range(3):  # 重试最多 3 次
            if asyncio.get_event_loop().time() > deadline:
                logger.debug("bootstrap 解析 %s 总超时 10s，终止重试", hostname)
                break
            ips = []
            # A 和 AAAA 独立查询，一个失败不影响另一个
            for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                qbytes = queries.get(qtype)
                if qbytes is None:
                    continue  # 跳过非法域名的查询类型
                addr_family = "v4" if qtype == dns.rdatatype.A else "v6"
                # 只选择与查询类型匹配的 bootstrap 解析器地址族
                suitable_bs = []
                for bs in self._bootstrap_resolvers:
                    bs_addr = bs.name
                    is_v6 = ":" in bs_addr
                    if (addr_family == "v4" and not is_v6) or (addr_family == "v6" and is_v6):
                        suitable_bs.append(bs)
                # 如果没有匹配地址族的 bootstrap，尝试所有
                if not suitable_bs:
                    suitable_bs = self._bootstrap_resolvers
                results = await asyncio.gather(
                    *[try_resolver(qbytes, bs, addr_family) for bs in suitable_bs],
                    return_exceptions=True,
                )
                # 审计修复：多 bootstrap 交叉验证 + 可疑 IP 过滤。日志实证污染特征——
                # 劫持源把不同上游域名解析到同一批『公共 DNS』IP（94.140.14.14 等）或
                # 127.0.0.1，导致 DoH 证书验证失败、DoT/DoQ 连错服务器。
                _ok_sources = sum(1 for r in results if isinstance(r, bytes))
                _ip_counts = {}
                for result in results:
                    if isinstance(result, bytes):
                        try:
                            response = dns.message.from_wire(result)
                            for rrset in response.answer:
                                for rd in rrset:
                                    if rd.rdtype == qtype:
                                        _ip = str(rd.address)
                                        # 过滤可疑/保留 IP（127.0.0.1、私网、组播等污染特征）
                                        if self._is_suspicious_bootstrap_ip(_ip):
                                            logger.debug("bootstrap 解析 %s 过滤可疑 IP: %s", hostname, _ip)
                                            continue
                                        _ip_counts[_ip] = _ip_counts.get(_ip, 0) + 1
                        except (UnicodeError, ValueError) as e:
                            logger.debug("解析管理器 DNS 响应包含非法字符: %s", e)
                            continue
                        except Exception as e:
                            logger.debug("解析管理器 DNS 响应解析异常: %s", e)
                            continue
                if _ip_counts:
                    if _ok_sources >= 2:
                        # 多源交叉验证：只采用至少 2 个 bootstrap 一致的 IP（劫持源通常
                        # 返回不一致的伪造 IP，多源一致的真实 IP 才可信）
                        _agreed = [ip for ip, c in _ip_counts.items() if c >= 2]
                        if _agreed:
                            ips.extend(_agreed)
                            logger.debug("bootstrap 解析 %s 交叉验证通过 %d 个 IP: %s",
                                         hostname, len(_agreed), ",".join(_agreed))
                        else:
                            # 多源均不一致：不可信，放弃本轮（触发外层重试）
                            logger.debug("bootstrap 解析 %s 多源结果不一致(%s)，放弃本轮",
                                         hostname, ",".join(_ip_counts.keys()))
                    else:
                        # 仅 1 个 bootstrap 应答：保留其合法 IP（避免单源/部分超时环境丢结果）
                        ips.extend(_ip_counts.keys())

            if ips:
                return ips
            # 快速重试，间隔递增
            await asyncio.sleep(0.2 * (attempt + 1))

        return []

    async def _init_ech_fetchers(self):
        """
        为所有上游主机创建 ECHConfigFetcher。
        - 如果用户明确配置了某上游的 ech 配置，优先使用
        - 否则创建一个自动查询式的 fetcher（通过公共 DoH 查询上游自身 HTTPS 记录）
        - fetcher 内部缓存结果并定期刷新（TTL 控制）
        """
        user_configs = self.config.ech_configs  # hostname -> config_string
        all_hostnames = set()
        for url in self.config.doh_servers:
            host = url.replace("https://", "").split("/")[0].split(":")[0]
            all_hostnames.add(host)
        for host in self.config.dot_servers:
            h = host.split(":")[0]
            all_hostnames.add(h)

        if not all_hostnames:
            return

        has_user_config = bool(user_configs)
        for hostname in all_hostnames:
            if hostname in user_configs:
                # 用户明确配置了 ECH
                config_str = user_configs[hostname]
                logger.info("  %s: 使用用户配置的 ECH: %s", hostname,
                            config_str[:64] if "://" not in config_str else config_str.split("+")[0] + "+...")
            elif has_user_config:
                # 用户配置了 ECH 但不包含此主机 → 跳过
                logger.debug("  %s: 未配置 ECH，跳过", hostname)
                continue
            else:
                # 用户无配置：自动发现（通过公共 DoH 查询此主机自身 HTTPS 记录）
                config_str = f"https://1.1.1.1/dns-query"
                logger.info("  %s: 自动 ECH（通过 %s 查询 HTTPS 记录）",
                            hostname, config_str)

            fetcher = ECHConfigFetcher(
                config_str=config_str,
                upstream_hostname=hostname,
                bootstrap_resolve_fn=self._bootstrap_resolve,
                fallback_udp_servers=self.config.bootstrap_resolvers,
            )
            self._ech_fetchers[hostname] = fetcher

            # 立即尝试获取一次（预热缓存）
            if fetcher.enabled:
                warmed_up = False
                for attempt in range(3):  # 最多 3 次（首次 + 2 次重试）
                    try:
                        config = await asyncio.wait_for(fetcher.get_config(), timeout=8.0)
                        if config:
                            if attempt > 0:
                                logger.info("  %s: ECH 预热成功 (%d bytes, 第%d次重试)",
                                             hostname, len(config), attempt + 1)
                            else:
                                logger.info("  %s: ECH 预热成功 (%d bytes)", hostname, len(config))
                            warmed_up = True
                            break
                        else:
                            logger.debug("  %s: ECH 预热返回空 (第%d次)", hostname, attempt + 1)
                    except asyncio.TimeoutError:
                        logger.debug("  %s: ECH 预热超时 (第%d次，%s)", hostname, attempt + 1,
                                     "继续重试" if attempt < 2 else "放弃")
                    except Exception as e:
                        logger.debug("  %s: ECH 预热异常: %s (第%d次，%s)", hostname, e, attempt + 1,
                                     "继续重试" if attempt < 2 else "放弃")
                    if not warmed_up and attempt < 2:
                        await asyncio.sleep(1.0)  # 重试间隔
                if not warmed_up:
                    self._ech_warmup_failed.add(hostname)
                    last_err = fetcher._last_error or "未知"
                    logger.warning("  %s: ECH 预热失败（%s），将使用普通 TLS 连接此上游",
                                   hostname, last_err)

        enabled_count = sum(1 for f in self._ech_fetchers.values() if f.enabled)
        valid_count = sum(1 for f in self._ech_fetchers.values() if f.has_valid_config)
        failed_count = len(self._ech_warmup_failed)
        logger.info("ECH 获取器初始化完成: %d/%d 个上游启用, %d 有效, %d 预热失败",
                     enabled_count, len(self._ech_fetchers), valid_count, failed_count)

    async def _init_shared_doh_session(self):
        """
        创建全局共享的 aiohttp.ClientSession + _MultiHostResolver。
        所有 DoH 上游共用一个连接池，显著减少内存占用。
        """
        if not self.config.doh_servers:
            return

        # 收集所有 DoH 主机名 → bootstrap IP 映射
        self._shared_doh_resolver = _MultiHostResolver()
        for url in self.config.doh_servers:
            hostname = url.replace("https://", "").split("/")[0].split(":")[0]
            cached_ips = self._bootstrap_cache.get(hostname, [])
            if cached_ips:
                self._shared_doh_resolver.add_host(hostname, cached_ips)

        pool_size = max(1, self.config.connection_pool_size)
        n_doh = max(1, len(self.config.doh_servers))
        connector = aiohttp.TCPConnector(
            limit=pool_size,
            limit_per_host=max(1, pool_size // n_doh),
            ttl_dns_cache=300,
            force_close=False,
            resolver=self._shared_doh_resolver if any(self._bootstrap_cache.values()) else None,
            # 不在这里设 ssl，由 doh.py 的 resolve() 在每个请求中传入 ssl=self._ssl_context
        )
        self._shared_doh_session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.config.parallel_timeout),
        )
        logger.info(
            "全局共享 DoH session 已创建 (pool_size=%d, upstreams=%d)",
            pool_size, n_doh,
        )

    async def _create_upstream_resolvers(self):
        """创建加密上游解析器"""
        timeout = self.config.parallel_timeout

        ech_enabled = self.config.ech_enabled
        # 真正的 ECH 可用条件：OpenSSL 4.0 DLL 加载成功
        openssl4_available = (
            _HAS_OPENSSL4
            and self._openssl4_wrapper is not None
            and self._openssl4_wrapper.available
            and self._openssl4_wrapper.ech_supported
        )
        # CA 证书路径：配置 > certifi > None（用于所有 DoH/DoT/DoQ 解析器的证书验证）
        ca_path = self.config.openssl4_ca_path or None
        custom_ca = bool(self.config.openssl4_ca_path)  # 用户显式配置了 ca_path
        if ca_path is None:
            try:
                import certifi
                ca_path = certifi.where()
            except ImportError:
                pass

        # 自定义 CA 模式时，自动将本地服务器证书加入信任链
        # 这样自签名的本地 DoH/DoT/DoQ 证书也能被代理信任
        if custom_ca:
            merged = self._merge_local_server_certs(ca_path)
            if merged:
                ca_path = merged

        # DoH
        # 上游 DoH 协议策略：h3 优先 → h2；HTTP/1.1 永久禁用（upstream.doh_protocols）
        doh_protocols = self.config.upstream_doh_protocols
        for url in self.config.doh_servers:
            hostname = url.replace("https://", "").split("/")[0].split(":")[0]
            cached_ips = self._bootstrap_cache.get(hostname, [])
            ech_fetcher = self._ech_fetchers.get(hostname) if ech_enabled else None
            # 真正的 ECH 需要：fetcher 存在且有过成功的预热（has_valid_config）且未标记失败
            has_ech = (
                openssl4_available
                and ech_fetcher is not None
                and ech_fetcher.has_valid_config
                and hostname not in self._ech_warmup_failed
            )

            if has_ech:
                # 上游 DoH **只允许 h3/h2**（HTTP/1.1 永久禁用）：ECHDoHResolver 是
                # OpenSSL(ctypes) 手写的 ECH 实现，只能走 HTTP/1.1，与策略冲突，
                # 因此不再使用。这里改用 DoHResolver：ECH 由 Python ssl 的
                # ECHClientConfig 承担（h3 因 aioquic 不支持 ECH 自动让位给 h2），
                # 协议仍严格限制在 h3/h2，不会退回明文 HTTP/1.1。
                ech_config = b""
                try:
                    ech_config = await asyncio.wait_for(
                        ech_fetcher.get_config(), timeout=2.0
                    ) or b""
                except Exception as e:
                    logger.debug("DoH %s: 获取 ECHConfigList 失败: %s", url, e)
                if not ech_config:
                    logger.warning(
                        "DoH %s: ECH 已启用但拿不到 ECHConfigList，"
                        "本次按普通 h3/h2 加密上游运行（不做 ECH 封装）", url,
                    )
                resolver = DoHResolver(url, timeout=timeout,
                                       connection_pool_size=self.config.connection_pool_size,
                                       connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size,
                                       ca_path=ca_path or "",
                                       shared_session=self._shared_doh_session,
                                       shared_resolver=self._shared_doh_resolver,
                                       protocols=doh_protocols,
                                       ech_enabled=bool(ech_config),
                                       ech_config=ech_config)
            else:
                resolver = DoHResolver(url, timeout=timeout,
                                       connection_pool_size=self.config.connection_pool_size,
                                       connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size,
                                       ca_path=ca_path or "",
                                       shared_session=self._shared_doh_session,
                                       shared_resolver=self._shared_doh_resolver,
                                       protocols=doh_protocols)
            self._upstream_servers.append(UpstreamServer(resolver, "doh"))

        # DoT
        for host in self.config.dot_servers:
            parts = host.split(":")
            h = parts[0]
            p = int(parts[1]) if len(parts) > 1 else 853
            cached_ips = self._bootstrap_cache.get(h, [])
            ech_fetcher = self._ech_fetchers.get(h) if ech_enabled else None
            # 真正的 ECH 需要：fetcher 存在且有过成功的预热（has_valid_config）且未标记失败
            has_ech = (
                openssl4_available
                and ech_fetcher is not None
                and ech_fetcher.has_valid_config
                and h not in self._ech_warmup_failed
            )

            if has_ech:
                resolver = ECHDoTResolver(
                    h, port=p, timeout=timeout,
                    ech_fetcher=ech_fetcher,
                    openssl_wrapper=self._openssl4_wrapper,
                    ca_path=ca_path,
                    ciphers=self.config.tls_ciphers,
                    connect_ips=cached_ips,
                    concurrency=self.config.connection_pool_size,
                )
                if not resolver.available:
                    resolver = DoTResolver(h, port=p, timeout=timeout, connect_ips=cached_ips,
                                           concurrency=self.config.connection_pool_size,
                                           ca_path=ca_path or "",
                                           connection_pool_size=self.config.connection_pool_size)
            else:
                resolver = DoTResolver(h, port=p, timeout=timeout, connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size,
                                       ca_path=ca_path or "",
                                       connection_pool_size=self.config.connection_pool_size)
            self._upstream_servers.append(UpstreamServer(resolver, "dot"))

        # DoQ
        for addr in self.config.doq_servers:
            hostname = addr.replace("quic://", "").split(":")[0]
            cached_ips = self._bootstrap_cache.get(hostname, [])
            resolver = DoQResolver(addr, timeout=timeout, connect_ips=cached_ips,
                                   concurrency=self.config.connection_pool_size,
                                   ca_path=ca_path or "")
            self._upstream_servers.append(UpstreamServer(resolver, "doq"))

        # 迭代解析上游（根→TLD→权威）：与加密上游一起注册，参与并行优选，
        # 供全部本地加密 DNS 服务（DoH/DoT/DoQ/plain）使用。
        # DNSSEC 严格验证在迭代器内部完成（内置 IANA 根信任锚全链验证）。
        if self._iterative_resolver is not None:
            self._upstream_servers.append(
                UpstreamServer(self._iterative_resolver, "iterative")
            )
            logger.info("迭代解析上游已注册（根→TLD→权威 + DNSSEC 严格验证，"
                        "与 %d 个加密上游一起参与优选）",
                        len(self.config.doh_servers) + len(self.config.dot_servers)
                        + len(self.config.doq_servers))

    def _merge_local_server_certs(self, base_ca_path: str) -> Optional[str]:
        """
        将本地 DoH/DoT/DoQ 服务器的自签名证书合并到 CA 信任链。

        当用户配置了 tls.ca_path（自定义 CA 模式）时调用。
        读取本地服务器 cert_path 文件中的 PEM 证书，
        与 base_ca_path 合并写入临时文件，返回临时文件路径。

        Returns:
            合并后的临时 PEM 文件路径，失败返回 None
        """
        extra_certs = []

        # DoH 默认启用，只要证书文件存在就加入
        doh = self.config.doh_cert_path
        if doh and os.path.isfile(doh):
            extra_certs.append(doh)

        # DoT 启用且证书存在
        if self.config.local_dot_enabled:
            dot = self.config.local_dot_cert_path
            if dot and os.path.isfile(dot):
                extra_certs.append(dot)

        # DoQ 启用且证书存在
        if self.config.local_doq_enabled:
            doq = self.config.local_doq_cert_path
            if doq and os.path.isfile(doq):
                extra_certs.append(doq)

        if not extra_certs:
            return None

        try:
            with open(base_ca_path, 'r') as f:
                base_content = f.read()
        except (OSError, IOError) as e:
            logger.warning("合并 CA: 读取基础 CA 文件失败: %s", e)
            return None

        fd, tmp_path = tempfile.mkstemp(suffix='.pem', prefix='dnscrypt_ca_')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(base_content.rstrip('\n') + '\n\n')
                for cp in extra_certs:
                    with open(cp, 'r') as cf:
                        f.write(cf.read().rstrip('\n') + '\n\n')
        except Exception as e:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            logger.warning("合并 CA: 写入合并文件失败: %s", e)
            return None

        atexit.register(lambda p=tmp_path: os.unlink(p) if os.path.exists(p) else None)
        logger.info("已合并 %d 个本地服务器证书到 CA 信任链", len(extra_certs))
        return tmp_path

    def _effective_query_budget(self) -> float:
        """当前生效的单查询硬上限（秒）

        三层预算必须自洽，否则会互相打架（实测日志里同时出现 152s/304s 的
        迭代 total_timeout 与 10.0s 的硬取消）：

          1. ``iterative.timeout_ms`` —— **单跳**（对一台权威的一次查询）超时；
          2. ``IterativeResolver.total_timeout`` —— 整条迭代链（根→TLD→权威 +
             CNAME 链 + DNSSEC 链验证）的预算，由 1 与 max_depth 推导，上限 30s；
          3. 本方法 —— resolver 层硬取消上限。

        纯迭代模式（没有启用的 DoH/DoT/DoQ）下迭代是**唯一**路径，硬上限必须
        容得下迭代器自己的预算，否则「迭代器还想继续（total_timeout），外层已
        经砍掉（10s）」——长 CNAME 链（Akamai/CDN 调度域名，实测 10-15s）会
        被整条取消、连缓存都写不进去，下一次访问又重跑一遍。
        有加密上游可回退时仍用基准值（10s）：前端 6s 已回 504，留 4s 给缓存写入。
        """
        budget = self._base_query_budget
        try:
            if self._is_pure_iterative_mode():
                iter_total = float(
                    getattr(self._iterative_resolver, "total_timeout", 0.0) or 0.0
                )
                if iter_total > 0:
                    # 20s 上限：够长链（10-15s）跑完并写缓存，又不至于让
                    # 前端早已放弃的查询在后台空跑太久。
                    budget = max(budget, min(iter_total, 20.0))
        except Exception:
            pass
        return budget

    async def _resolve_impl_with_budget(self, query_bytes: bytes) -> Optional[bytes]:
        """带总预算的解析（到点取消，且**不等待取消完成**）

        为什么不用 ``asyncio.wait_for``：wait_for 在超时后会**等待被取消的协程
        真正结束**，而解析链的 finally 里还要关 socket/收尾，于是 6s 预算实测
        会拖到 9s、10s 预算拖到 18s（日志里能直接看到）。这里用
        ``asyncio.wait`` + ``task.cancel()`` 不等待：预算严格生效，
        被取消的任务在后台自行清理（各处 finally 都限时 0.5s，不会泄漏）。
        """
        budget = self._effective_query_budget()
        task = asyncio.ensure_future(self._resolve_impl(query_bytes))
        # 任务被取消后可能仍带异常完成（socket 收尾等）：挂一个回调消费掉，
        # 否则 asyncio 会打 "Future exception was never retrieved" 的 ERROR。
        def _consume_exc(t):
            if t.cancelled():
                return
            try:
                t.exception()
            except (asyncio.CancelledError, Exception):
                pass

        task.add_done_callback(_consume_exc)
        try:
            done, _ = await asyncio.wait({task}, timeout=budget)
        except asyncio.CancelledError:
            task.cancel()
            raise
        if task in done:
            try:
                return task.result()
            except asyncio.CancelledError:
                return None
            except Exception as e:
                logger.debug("解析任务异常: %s [%s]", e, type(e).__name__)
                return None
        task.cancel()
        self._failure_stats["解析总超时"] = (
            self._failure_stats.get("解析总超时", 0) + 1
        )
        logger.warning(
            "单次解析超过 %.1fs 总预算，已取消整条解析链"
            "（前端超时后不再让后台继续空跑）",
            budget,
        )
        return None

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """解析入口：对相同查询做「并发合并」，再交给 _resolve_impl

        为什么要合并：DNS 协议没有"请稍等"的语义——服务端无法告诉客户端
        "我还在解析，请再等几秒"。客户端超时后只会**重发同一个查询**
        （Windows Dnscache 约 1s/2s/4s 递增，浏览器自带重试）。如果不去重，
        每次重试都会重新跑一遍完整迭代（1.5-6s），既浪费线程和带宽，
        又让整批查询更慢。这里把同一 (qname, qtype, class, DO, CD) 的
        并发查询合并成一个，其余等待者共享结果。

        响应 ID 由各前端负责回填（DoH / plain / DoT / DoQ 都有
        ``resp.id = query.id``），所以共享同一份 wire 是安全的。
        """
        key = None
        try:
            msg = dns.message.from_wire(query_bytes)
            if msg.question:
                question = msg.question[0]
                do_bit = bool(msg.edns >= 0 and (msg.ednsflags & dns.flags.DO))
                cd_bit = bool(msg.flags & dns.flags.CD)
                key = (question.name, question.rdtype, question.rdclass, do_bit, cd_bit)
        except Exception:
            key = None

        if key is None:
            return await self._resolve_impl_with_budget(query_bytes)

        existing = self._inflight_queries.get(key)
        if existing is not None:
            # 已有相同查询在跑：等它的结果。用 shield 避免等待者被取消时
            # 误取消发起方的任务（发起方还要给其它等待者供结果）。
            try:
                return await asyncio.shield(existing)
            except asyncio.CancelledError:
                raise
            except Exception:
                return None

        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight_queries[key] = fut
        try:
            result = await self._resolve_impl_with_budget(query_bytes)
            if not fut.done():
                fut.set_result(result)
            return result
        except asyncio.CancelledError:
            if not fut.done():
                fut.set_result(None)
            raise
        except Exception:
            # 发起方仍按原语义抛异常；等待者视为解析失败（与"上游全失败"一致）
            if not fut.done():
                fut.set_result(None)
            raise
        finally:
            self._inflight_queries.pop(key, None)

    async def _resolve_impl(self, query_bytes: bytes) -> Optional[bytes]:
        """
        并行查询所有上游，返回最快响应。
        如果启用了 DNSSEC，自动添加 DO 位。
        返回后对可疑响应（异常检测标记）启动多上游一致性验证。
        """
        async with self._concurrent_semaphore:
            # DNSSEC: 包装查询添加 DO 位
            dnssec_query = query_bytes
            if self._dnssec is not None:
                dnssec_query = self._dnssec.wrap_query(query_bytes)

            result = await self._parallel_resolve(dnssec_query)

        # DNSSEC 验证（在 resolver 层统一执行，所有 server 类型自动受益）
        #
        # **迭代上游例外**（2026-10-30）：IterativeResolver 在
        # `iterative.strict_dnssec=true` 时已经用内置 IANA 根锚做过一遍完整链验证
        # （根→TLD→父区 DS→DNSKEY→answer RRSIG），verdict 完全决定返回内容：
        #   secure   → 响应带 RRSIG 且已验签通过（并被标记 AD=1）
        #   insecure → 合法未签名区，放行
        #   bogus    → 迭代器内部已丢弃（返回 None，走不到这里）
        # 此时再跑 resolver 层 `DNSSECValidator(mode=strict)` 是**纯重复劳动**，
        # 而且它查 DNSKEY 时走 `resolve_dnskey → 迭代上游 → 迭代器内部又验证一次`，
        # 形成嵌套：冷启动实测单查询 0.13s 被拖到 1.4s 中位、11.5s 峰值
        # （日志里 ipv4only.arpa 4920ms / app.termly.io 9227ms 即此）。
        #
        # 判定只用「纯迭代模式 + 迭代器严格验证已开启」——纯迭代模式下
        # `_upstream_servers` 里只有 iterative 一个上游，结果必然来自它，不存在
        # 「被并发查询的其它上游覆盖」的竞态（不能用 `_last_fast_server_obj`：
        # 那是共享状态，多上游并发时会串味，可能让 DoH 响应误跳过验证）。
        # 混合模式（iterative + 加密上游）保持原有逐响应验证，宁可慢也不放松。
        _iter_already_verified = self.iterative_already_verified()
        if (result is not None and self._dnssec is not None
                and self._dnssec.enabled and not _iter_already_verified):
            try:
                dnssec_ok, dnssec_status = await self._dnssec.validate_response(
                    dnssec_query, result
                )
                if not dnssec_ok and self.config.dnssec_drop_bogus:
                    logger.warning("DNSSEC bogus (resolver层): %s，丢弃响应", dnssec_status)
                    return None
            except Exception as e:
                logger.debug("resolver层 DNSSEC 验证异常: %s", e)

        # 异常检测 + 可疑域名触发交叉验证（不阻塞响应返回）
        should_verify = False
        if result is not None:
            fast_srv = self._last_fast_server_obj
            # 先送入异常检测器，获取异常评分
            if self._anomaly_detector is not None and fast_srv is not None:
                try:
                    avg_rtt = fast_srv.avg_response_time
                    anomaly_score = self._anomaly_detector.record_response(
                        fast_srv.name, avg_rtt, result
                    )
                    # 只有异常评分 > 0（z-score > 阈值）才触发交叉验证
                    if anomaly_score > 0 and self._consistency_verifier is not None:
                        should_verify = True
                except Exception as e:
                    logger.debug("resolve 异常检测失败: %s", e)

            # 无异常检测器时：1/10 采样触发交叉验证
            if not should_verify and self._consistency_verifier is not None:
                self._consistency_check_count += 1
                if self._consistency_check_count % 10 == 0:
                    should_verify = True

        # 后台一致性验证：优选上游可配置，随机抽样排除优选
        if should_verify and result is not None:
            preferred_count = self.config.preferred_server_count
            preferred = self._select_preferred_servers(count=preferred_count)
            bg_count = self.config.response_verification_max_background_servers
            if bg_count > 0 and preferred:
                exclude_names = set(s.name for s in preferred)
                # 后台一致性验证排除 iterative（security_review MEDIUM：避免
                # 慢速迭代拖住后台对照；iterative 本身已有独立 DNSSEC 严格验证）
                all_enabled = [
                    s for s in self._upstream_servers if s.enabled
                    and s.server_type in ("doh", "dot", "doq")
                    and s.name not in exclude_names
                ]
                import random
                selected = random.sample(all_enabled, min(bg_count, len(all_enabled))) if all_enabled else []
            else:
                selected = [s for s in self._select_encrypted_upstreams(count=max(bg_count, 3))
                           if s.server_type != "iterative"]
            if selected:
                asyncio.create_task(
                    self._background_consistency_check(
                        dnssec_query, result, selected,
                        exclude_servers=set(s.name for s in preferred) if preferred else None,
                    )
                )
            else:
                # 一致性验证已开启但没有可用的后台对照上游：典型情况是
                # preferred_count >= 加密上游总数（优选把全部加密上游都排除了）。
                # 功能静默不生效，这里留一条可诊断日志。
                logger.debug("一致性验证: 无可用的后台对照上游"
                             "（preferred_count=%s 已排除全部加密上游，共 %d 个）",
                             preferred_count,
                             sum(1 for s in self._upstream_servers if s.enabled))

        # RFC 1035 §4.1.1：作为**递归服务端**统一修正响应 header 位。
        # 上游可能是权威服务器（迭代：AA=1、RD=0）或 DoH（RA 视上游而定），
        # 原样透传会出现：
        #   * RA=0 → 客户端（glibc res_send、部分游戏/浏览器自带解析器）
        #     据此认为"这台 DNS 不提供递归"，可能弃用/重试到其它服务器；
        #   * AA=1 → 迭代拿到的是权威应答，透传会让客户端误认为本机是权威；
        #   * RD=0 → 没有回显查询的 RD 位，属于非法响应形态。
        # 统一置 RA=1、回显 RD、清 AA（AD/TC/rcode 等保持不变）。
        if result is not None:
            result = self._normalize_response_flags(query_bytes, result)
        return result

    @staticmethod
    def _normalize_response_flags(query_bytes: bytes, resp_bytes: bytes) -> bytes:
        """把上游响应改写为符合递归服务端语义的 header（RFC 1035 §4.1.1）

        见调用点注释。解析/序列化失败时原样返回，不影响可用性。
        """
        try:
            q = dns.message.from_wire(query_bytes)
            r = dns.message.from_wire(resp_bytes)
            if q.flags & dns.flags.RD:
                r.flags |= dns.flags.RD
            else:
                r.flags &= ~dns.flags.RD
            r.flags |= dns.flags.RA          # 本服务器提供递归
            r.flags &= ~dns.flags.AA         # 我们不是权威
            return r.to_wire()
        except Exception:
            return resp_bytes

    async def _auto_recover(self):
        """
        自动恢复：当检测到无可用上游服务器时调用。
        1. 重置所有持久连接（关闭失效的 aiohttp 会话等）
        2. 重新启用所有上游服务器
        3. 进入恢复模式（首次失败不计入连续失败）
        4. 异步刷新 bootstrap IP 缓存（失败不影响恢复）
        """
        logger.info("触发上游服务器自动恢复...")
        # 重置所有持久连接（迭代解析器无连接可重置，hasattr 跳过）
        for server in self._upstream_servers:
            try:
                if hasattr(server.resolver, "reset_connections"):
                    await server.resolver.reset_connections()
            except Exception as e:
                logger.debug("解析管理器重置上游连接异常: %s", e)
        for server in self._bootstrap_resolvers:
            try:
                if hasattr(server.resolver, "reset_connections"):
                    await server.resolver.reset_connections()
            except Exception as e:
                logger.debug("解析管理器重置 bootstrap 连接异常: %s", e)
        # 保存旧缓存作为后备，然后清除（刷新成功后会重新填充）
        _old_cache = dict(self._bootstrap_cache)
        self._bootstrap_cache.clear()
        # 重新启用 + 恢复模式
        self.reenable_all()
        self.enter_recovery_mode()
        # 异步刷新 bootstrap IP（非阻塞，失败则恢复旧缓存）
        asyncio.create_task(self._async_refresh_bootstrap(_old_cache))
        enabled = sum(1 for s in self._upstream_servers if s.enabled)
        logger.info("自动恢复完成: %d 个上游已启用", enabled)

    async def _async_refresh_bootstrap(self, old_cache=None):
        """异步刷新所有上游域名的 bootstrap IP（自动恢复时调用）
        Args:
            old_cache: 旧缓存快照，刷新失败时恢复为后备
        """
        try:
            await asyncio.sleep(0.5)  # 稍等片刻再刷新
            await self.refresh_all_upstream_ips()
        except Exception as e:
            logger.debug("自动恢复后刷新 bootstrap IP 失败: %s", e)
            if old_cache:
                # 刷新失败，恢复旧缓存避免无缓存可用
                for hostname, ips in old_cache.items():
                    if hostname not in self._bootstrap_cache:
                        self._bootstrap_cache[hostname] = ips

    def set_network_down(self, down: bool = True, detail: str = ""):
        """设置网络断开标志。网络断开时上游查询直接跳过，不打印任何警告。"""
        if down and not self._network_down_reported:
            self._network_down = True
            self._network_down_reported = True
            logger.warning("网络已断开，暂停上游加密 DNS 查询" + (" [" + detail + "]" if detail else ""))
        elif not down:
            if self._network_down:
                logger.info("网络已恢复，恢复上游加密 DNS 查询" + (" [" + detail + "]" if detail else ""))
            self._network_down = False
            self._network_down_reported = False

    async def _parallel_resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """
        并行查询核心逻辑（带启动缓冲 + 集群故障冷却 + 互斥渐进退避重试）。

        启动缓冲期（前 3 秒）：上游全部失败时不执行重试，等待缓冲期结束再试一次。
          解决刚启动时所有上游尚未建立连接导致的"全部失败"日志洪流。

        集群故障冷却：上次全部失败距今不足 1 秒时，新查询等待剩余时间再发起。
          避免客户端重试风暴。

        互斥重试锁：同时只有一个并发请求执行重试循环（0.2s/0.5s/1.0s 三次退避），
          其余并发请求直接返回 SERVFAIL。消除同一时刻多个请求各自重试的重复日志。
        """
        now = asyncio.get_event_loop().time()

        # === 网络断开检查 ===
        # 网络不可达时不查询上游、不打任何警告日志，直接返回 SERVFAIL
        if self._network_down:
            return None

        # === 静默模式：**只降噪，不拒绝服务** ===
        # 历史实现：进入静默后 60 秒内直接返回 SERVFAIL（"每分钟仅探活一次"）。
        # 但「全部上游失败」往往只是**某个域名**超时——纯迭代模式只有一个上游，
        # 任何一次单域名超时都等于"全部 1 个上游失败"，于是连续几轮后整机解析
        # 被锁死 60 秒（用户实测：一个域名超时 → 全站打不开）。
        # 现在静默模式只压制日志与退避重试，查询照常执行；成功即退出静默。
        if self._silent_mode:
            self._last_silent_probe_time = now

        # === 启动缓冲期 ===
        # 程序刚启动时，上游 DNS 连接尚未建立，给它们 3 秒时间
        startup_elapsed = now - self._start_time
        if startup_elapsed < self._startup_buffer:
            result = await self._parallel_resolve_once(query_bytes)
            if result is not None:
                if self._last_all_failed_time > 0:
                    # 纯迭代模式：上一次只是**某个域名**失败，不是集群故障
                    if self._is_pure_iterative_mode():
                        logger.debug("并行查询: 单域名失败后已恢复（纯迭代模式，非集群故障）")
                    else:
                        logger.info("并行查询: 上游服务器已恢复域名解析")
                    self._last_all_failed_time = 0.0
                return result
            # 全部失败：等待到缓冲期结束再试
            self._last_all_failed_time = asyncio.get_event_loop().time()
            wait = self._startup_buffer - (asyncio.get_event_loop().time() - self._start_time)
            if wait > 0:
                logger.debug("并行查询: 启动缓冲期 %.1fs，等待上游连接...", wait)
                await asyncio.sleep(wait)
            result = await self._parallel_resolve_once(query_bytes)
            if result is not None:
                if self._last_all_failed_time > 0:
                    if self._is_pure_iterative_mode():
                        logger.debug("并行查询: 单域名失败后已恢复（纯迭代模式，启动缓冲后）")
                    else:
                        logger.info("并行查询: 上游服务器已恢复域名解析 (启动缓冲后)")
                    self._last_all_failed_time = 0.0
                return result

        # === 集群故障冷却 ===
        # 更新时间戳，因为启动缓冲可能已经睡了几秒
        # 纯迭代模式**跳过冷却**（2026-10-31）：只有一个上游时，「单个域名超时」
        # 与「集群全部失败」无法区分，若照常冷却，一个慢域名就会让**后续所有
        # 查询**多等最多 `_all_failed_cooldown`(1s)，浏览器并发时表现为
        # 「失败 → 等 1 秒 → 成功 → 再失败」的循环（日志里那条
        # 「上游服务器已恢复域名解析」就是这么刷出来的）。
        # 多上游集群场景保留冷却（避免重试风暴）。
        now = asyncio.get_event_loop().time()
        if self._last_all_failed_time > 0 and not self._is_pure_iterative_mode():
            elapsed = now - self._last_all_failed_time
            if elapsed < self._all_failed_cooldown:
                wait = self._all_failed_cooldown - elapsed
                logger.debug("并行查询: 集群故障冷却 %.1fs (距上次全部失败 %.1fs)", wait, elapsed)
                await asyncio.sleep(wait)

        result = await self._parallel_resolve_once(query_bytes)
        if result is not None:
            if self._last_all_failed_time > 0:
                if self._is_pure_iterative_mode():
                    logger.debug("并行查询: 单域名失败后已恢复（纯迭代模式，非集群故障）")
                else:
                    logger.info("并行查询: 上游服务器已恢复域名解析")
                self._last_all_failed_time = 0.0
            # 恢复成功：重置连续失败计数器、退出静默模式
            if self._consecutive_all_failed_counter > 0 or self._silent_mode:
                self._consecutive_all_failed_counter = 0
                self._all_failed_start_time = 0.0
                self._silent_mode = False
            return result

        # === 全部失败 → 静默模式下直接返回，不更新计数器、不触发回调 ===
        if self._silent_mode:
            return None

        self._last_all_failed_time = asyncio.get_event_loop().time()
        self._consecutive_all_failed_counter += 1
        if self._consecutive_all_failed_counter == 1:
            self._all_failed_start_time = self._last_all_failed_time
            self._silent_mode = False  # 首次失败时确保退出静默模式

        # 触发跨层回调，通知 NetworkMonitor 进行深度检测。
        # 必须在**后台**执行：诊断会跑 ARP/NDP 检查（子进程）+ plain DNS 探活，
        # 在查询路径上同步 await 会把触发它的客户端查询一起拖住（并发时叠加成
        # 事件循环卡死）。NetworkMonitor 侧另有「单飞 + 限频」去重。
        if self._on_all_upstreams_failed is not None:
            elapsed = max(0.0, self._last_all_failed_time - (
                self._all_failed_start_time if self._all_failed_start_time > 0
                else self._last_all_failed_time))
            try:
                _task = asyncio.ensure_future(
                    self._on_all_upstreams_failed(
                        self._consecutive_all_failed_counter, elapsed
                    )
                )

                def _consume_exc(t):
                    try:
                        t.exception()
                    except Exception:
                        pass

                _task.add_done_callback(_consume_exc)
            except Exception:
                pass

        if self._retry_lock.locked():
            # 已有其他请求在重试，这个请求直接返回（避免重复日志）
            return None

        _failure_start = self._last_all_failed_time
        alive = sum(1 for s in self._upstream_servers if s.enabled)
        _version = self._retry_version
        # 纯迭代模式（没有 DoH/DoT/DoQ 可回退）：失败往往只是**这一个域名**
        # 慢（境外权威/冷启动 DNSSEC 链），退避重试 3 次共 1.7-14s 只会把
        # 客户端拖死，也不会让下一次尝试更容易成功——直接返回，让上层/客户端
        # 自行重试；同时把日志降为 DEBUG，避免每个域名超时都刷一条 WARNING。
        pure_iterative = self._is_pure_iterative_mode()

        async with self._retry_lock:
            # 检查版本号：如果已在之前的重试中被递增，说明已有其他请求执行过重试
            if _version != self._retry_version:
                return None

            # 根据连续失败轮数选择退避延迟
            if (self._consecutive_all_failed_counter >= self._all_failed_silent_rounds
                    and not pure_iterative):
                # 连续全部失败达到阈值 → 进入静默模式（仅日志/退避降噪，
                # 不再拒绝服务；查询仍会照常执行，见 _parallel_resolve 开头）
                self._silent_mode = True
                logger.warning("并行查询: 全部 %d 个上游持续失败 %d 轮 (历时 %.0fs)，"
                               "进入静默模式（只压制日志与退避，查询不中断）",
                               alive, self._consecutive_all_failed_counter,
                               max(0.0, self._last_all_failed_time - self._all_failed_start_time))
                # 重置时间戳以便探活检测使用
                self._last_silent_probe_time = self._last_all_failed_time
                self._last_all_failed_time = 0.0
                self._retry_version += 1
                return None
            if pure_iterative:
                retry_delays = []            # 纯迭代模式不重试，快速失败
                log_level = "DEBUG"
            elif self._consecutive_all_failed_counter >= 2:
                retry_delays = [1.0, 3.0, 10.0]  # 升级退避
                log_level = "DEBUG"  # 降级日志级别
            else:
                retry_delays = [0.2, 0.5, 1.0]   # 正常退避
                log_level = "WARNING"

            for retry, delay in enumerate(retry_delays, start=1):
                if log_level == "WARNING":
                    logger.warning("并行查询: 全部 %d 个上游均失败，%.1fs 后第 %d 次重试...",
                                   alive, delay, retry)
                else:
                    logger.debug("并行查询: 全部 %d 个上游均失败，%.1fs 后第 %d 次重试 (连续%d轮)",
                                 alive, delay, retry, self._consecutive_all_failed_counter)
                await asyncio.sleep(delay)
                result = await self._parallel_resolve_once(query_bytes)
                if result is not None:
                    logger.info("并行查询: 上游服务器已恢复域名解析 (第 %d 次重试成功, 耗时 %.1fs)",
                                retry,
                                asyncio.get_event_loop().time() - _failure_start)
                    self._last_all_failed_time = 0.0
                    self._consecutive_all_failed_counter = 0
                    self._all_failed_start_time = 0.0
                    self._silent_mode = False
                    self._retry_version += 1
                    return result
                self._last_all_failed_time = asyncio.get_event_loop().time()

            self._retry_version += 1
            if pure_iterative:
                logger.debug("并行查询: 迭代解析本次失败（纯迭代模式不重试, 连续%d轮）",
                             self._consecutive_all_failed_counter)
            else:
                logger.warning("并行查询: 全部 %d 个上游均失败 (%d 次重试后放弃, 连续%d轮)",
                               alive, 3, self._consecutive_all_failed_counter)
            return None

    def _is_pure_iterative_mode(self) -> bool:
        """当前是否「纯迭代」模式（没有启用的 DoH/DoT/DoQ 加密上游）

        纯迭代模式下只有一个上游，任何**单个域名**超时都表现为「全部 1 个上游
        失败」。这种失败不指向"上游集群故障"，因此：
          - 不做退避重试（只会把客户端拖 1.7-14s）；
          - 不进入静默模式（否则 60s 内整机解析被锁死）；
          - 日志降为 DEBUG（避免每个域名超时刷一条 WARNING）。
        """
        try:
            return not any(
                getattr(s, "server_type", "") in ("doh", "dot", "doq")
                for s in self._upstream_servers
                if getattr(s, "enabled", True)
            )
        except Exception:
            return False

    def iterative_already_verified(self) -> bool:
        """本次响应是否已由迭代器内部完成 DNSSEC 验证

        纯迭代模式（没有启用的加密上游）+ 迭代器 strict_dnssec=True 时，
        `IterativeResolver` 已在**内部**完成严格链验证（bogus 在内部就被丢弃，
        不会返回到这里）。此时各前端**不应再验一遍**，原因有二：

          1. 重复开销：每域名多若干次 DNSKEY/DS 往返；
          2. **正确性**：`DNSSECValidator`（wrapper）对负应答（NXDOMAIN /
             NODATA 的 NSEC/NSEC3 语义）的判定与迭代器不一致——实测同一个
             `does-not-exist-xyz-123.invalidtld` 的 NXDOMAIN 应答，迭代器判
             secure，wrapper 却判 `bogus`。叠加 `dnssec.drop_bogus: true` 就会
             把**合法的 NXDOMAIN 全部变成 SERVFAIL**（不存在的域名一律解析
             失败）。

        该判定与 `_resolve_impl` 里的 `_iter_already_verified` 完全一致，
        各 DNS 前端（plain/DoH/DoT/DoQ）直接复用，避免各写一套漂移。
        """
        try:
            return (
                self._is_pure_iterative_mode()
                and bool(getattr(self._iterative_resolver, "strict_dnssec", False))
            )
        except Exception:
            return False


    @staticmethod
    def _get_suffix(hostname: str) -> str:
        """提取域名的注册后缀（如 alidns.com、cloudflare.com）。

        前提：传入的必须是 BaseResolver._extract_name 规范化后的**纯主机名**
        （已去掉 scheme/路径/端口）——_get_suffix 只做"取最后两段"的粗粒度
        判断，若直接传入 "https://x.example.com/dns-query" 会得到
        "example.com/dns-query" 这种错误后缀，导致 suffix_dedup 失效。
        （iterative 上游的名字是 "iterative"，单段 → 原样返回，不会与其他
          上游的后缀冲突。）
        """
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    def _select_preferred_servers(self, count: int) -> List[UpstreamServer]:
        """
        全类型混排（DoH/DoT/DoQ 统一排序），按最低延迟排序，
        延迟数据已从历史查询中收集（avg_response_time），
        然后遍历确保后缀域名不同。
        返回优选上游列表（数量 <= count）。
        """
        if count <= 0:
            return []
        encrypted = [
            s for s in self._upstream_servers
            if s.enabled and s.server_type in ("doh", "dot", "doq", "iterative")
        ]
        # 全类型按平均延迟升序排序（延迟数据已存在，无需额外测量）
        encrypted.sort(key=lambda s: s.avg_response_time)
        preferred = []
        used_suffixes = set()
        for s in encrypted:
            if len(preferred) >= count:
                break
            suffix = self._get_suffix(s.name)
            if self.config.suffix_dedup_enabled and suffix in used_suffixes:
                continue
            preferred.append(s)
            used_suffixes.add(suffix)
        return preferred

    def _select_encrypted_upstreams(self, count: int = 3) -> List[UpstreamServer]:
        """
        按健康评分选择最优的 N 个加密上游（DoH/DoT/DoQ）。
        不包含 plain（普通 DNS 只做 bootstrap 解析）。

        排序键（依次）：
          1. 未连续失败；
          2. **已有成功样本**（avg_response_time < 999）——实测可用的上游必须
             排在"零样本"前面。否则零样本的境外 DoH（配置里靠前）会一直霸占
             优选名额：冷启动高并发时它们全部超时，而真正可用的境内上游要等到
             第三波才有机会，最终表现为「全部上游失败 / 大面积 504」；
          3. 平均延迟越低越前；
          4. 健康评分。
        """
        encrypted = [
            s for s in self._upstream_servers
            if s.enabled and s.server_type in ("doh", "dot", "doq", "iterative")
        ]
        encrypted.sort(
            key=lambda s: (
                s.consecutive_failures == 0,
                s.avg_response_time < 999.0,
                -s.avg_response_time,
                s.health_score,
            ),
            reverse=True,
        )
        return encrypted[:count]

    async def _try_upstream_wave(
        self, servers: List[UpstreamServer], query_bytes: bytes,
        remaining_timeout: float, cap_iterative_budget: bool = False,
    ) -> Optional[tuple]:
        """
        向一组上游并行查询，返回最快成功响应 (result, elapsed, server)。
        若全部失败或超时返回 None。

        ``cap_iterative_budget=True``：即使波次含 iterative 也**不**把
        deadline 放大到迭代的 total_timeout——用于「迭代优先」的首波，
        让它按 6s 预算失败后尽快转加密上游兜底。
        """
        if not servers:
            return None

        async def query_one(server: UpstreamServer) -> Optional[tuple]:
            # 纯迭代模式下 iterative 是唯一上游：不能因连续失败禁用它
            # （禁用 = 整机解析瘫痪，随后 auto_recover 再启用 → 抖动）
            _allow_disable = not (
                server.server_type == "iterative" and self._is_pure_iterative_mode()
            )
            try:
                result, elapsed = await server.resolver.resolve_with_stats(
                    query_bytes
                )
                if result is not None:
                    server.record_success(response_time=elapsed)
                    return (result, elapsed, server)
                if not self._recovery_mode:
                    server.record_failure(allow_disable=_allow_disable)
                    self._failure_stats["返回空"] = self._failure_stats.get("返回空", 0) + 1
                else:
                    logger.debug("上游 %s 返回空（恢复模式，不计失败）", server.name)
                return None
            except asyncio.CancelledError:
                return None
            except Exception as e:
                if not self._recovery_mode:
                    server.record_failure(allow_disable=_allow_disable)
                    logger.warning("上游 %s 查询失败: %s [%s]",
                                   server.name, e, type(e).__name__)
                    err_type = type(e).__name__
                    self._failure_stats[err_type] = self._failure_stats.get(err_type, 0) + 1
                else:
                    logger.debug("上游 %s 异常（恢复模式）: %s", server.name, e)
                return None

        tasks = [asyncio.create_task(query_one(s)) for s in servers]
        remaining = set(tasks)
        # SF-1 修复：迭代解析（根→TLD→权威 + DNSSEC 链验证）单次查询需 15-52s，
        # 远超 parallel_timeout（2s）——若波次含 iterative 上游，deadline 按其
        # total_timeout 预算放大（加密上游成功仍由 FIRST_COMPLETED 提前返回，
        # 不影响快速路径；加密上游全失败时 iterative 可完成迭代兜底，而非被 2s 截断）
        _iter_budget = 0.0
        if (not cap_iterative_budget
                and any(getattr(s, "server_type", "") == "iterative" for s in servers)):
            _iter_budget = float(getattr(
                getattr(self, "_iterative_resolver", None), "total_timeout", 30.0,
            ))
        deadline = asyncio.get_event_loop().time() + max(remaining_timeout, _iter_budget)
        successful = []

        try:
            while remaining and not successful:
                now = asyncio.get_event_loop().time()
                if now >= deadline:
                    break
                done, remaining = await asyncio.wait(
                    remaining,
                    timeout=deadline - now,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    try:
                        r = task.result()
                        if r is not None:
                            successful.append(r)
                    except Exception as e:
                        logger.debug("解析管理器并行查询任务异常: %s", e)
        finally:
            # **必须放在 finally**：本函数会被外层「单查询总预算」取消，
            # 原来把 cancel/await 写在 while 之后，取消时直接跳过清理，
            # 在飞的 query_one（及其内部迭代协程、UDP socket、DNSSEC 链）
            # 会继续跑完整条链 → 协程/Task 泄漏（实测 25s 内 coroutine
            # 2.1万→4.9万、Task 6340→20209，RSS 涨到 2GB）。
            pending = [t for t in remaining if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                try:
                    # 清理也限时：取消时若子任务还在收尾，wait_for 会等到它们结束，
                    # 单查询就会从"6s 预算"变成实际 9s+（日志里能看到）。0.5s 足够
                    # 关 socket/取消 future；超时后 task 已收到 cancel，事件循环会收尾。
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=0.5,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                except Exception:
                    pass

        if successful:
            successful.sort(key=lambda x: x[1])
            self.exit_recovery_mode()
            return successful[0]
        return None

    async def _parallel_resolve_once(self, query_bytes: bytes) -> Optional[bytes]:
        """执行一轮并行查询（分波次：最优上游 → 剩余上游）"""
        enabled = [s for s in self._upstream_servers if s.enabled]
        if not enabled:
            logger.warning("没有可用的上游服务器，触发自动恢复...")
            await self._auto_recover()
            enabled = [s for s in self._upstream_servers if s.enabled]
            if not enabled:
                logger.error("自动恢复后仍无可用上游服务器")
                return None

        timeout = self.config.parallel_timeout

        # 首波选择：
        #   iterative.prefer=true（默认）→ 首波直接用根服务器迭代，不依赖第三方 DoH；
        #   iterative.prefer=false → 加密上游首波优先（25-100ms），
        #     iterative 只进备用波作兜底（纯迭代模式下首波即 iterative）。
        #
        # 首波**迭代**预算要分两种情况（这里踩过坑）：
        #   - 有加密上游可回退 → 给短预算（1.8s），超时立刻换 DoH/DoT/DoQ，
        #     避免客户端干等（实测 bilibili 的 live/upos 域名 3.5s 预算 → 3.6s 才答）；
        #   - **纯迭代模式**（upstream.enabled=false 或加密上游全空）→ 没有任何
        #     回退路径，必须给足迭代预算（total_timeout），否则稍慢的境外权威
        #     会被直接判失败，表现为「全部 1 个上游均失败」、整机解析瘫痪。
        prefer_iterative = bool(
            getattr(self.config, "plain_dns_iterative_prefer", True)
        )
        iterative_servers = [
            s for s in enabled if s.server_type == "iterative"
        ]
        encrypted_candidates = [
            s for s in enabled if s.server_type in ("doh", "dot", "doq")
        ]
        first_budget = timeout
        cap_iterative_budget = False
        if prefer_iterative and iterative_servers:
            first_wave = iterative_servers
            if encrypted_candidates:
                # 有加密上游兜底 → 迭代只给短预算，超时立即回退
                first_budget = max(1.8, timeout * 0.9)
                cap_iterative_budget = True
            else:
                # 纯迭代模式：唯一路径，给足预算（IterativeResolver 自己还有
                # total_timeout 兜底，不会无限等）
                first_budget = float(getattr(
                    iterative_servers[0].resolver, "total_timeout", 30.0,
                ))
                cap_iterative_budget = False
                logger.debug(
                    "纯迭代模式（无加密上游可回退）：首波预算放大到 %.1fs",
                    first_budget,
                )
        else:
            wave_candidates = self._select_encrypted_upstreams(count=3)
            first_wave = [
                s for s in wave_candidates if s.server_type != "iterative"
            ]
            if not first_wave:
                first_wave = wave_candidates

        if first_wave:
            if prefer_iterative and iterative_servers:
                _wave_label = (
                    # 纯迭代模式（无加密上游可回退）：预算放大的目的是让唯一
                    # 路径跑完，不是"迭代优先但有 DoH 兜底"——原实现复用
                    # cap_iterative_budget 判断，日志里会误报"加密上游优先"。
                    "纯迭代（无回退）" if not encrypted_candidates else "迭代优先"
                )
            else:
                _wave_label = "加密上游优先"
            logger.debug(
                "首波查询: %d 个上游（%s，预算 %.1fs）",
                len(first_wave),
                _wave_label,
                first_budget,
            )
            result = await self._try_upstream_wave(
                first_wave, query_bytes, first_budget,
                cap_iterative_budget=cap_iterative_budget,
            )
            if result is not None:
                self._last_fast_server = result[2].name
                self._last_fast_server_obj = result[2]
                return result[0]

        # ---- 第二波：回退到优选加密上游（迭代优先模式下就是"迭代整体失败"的出口）----
        # 首波是 iterative 时，说明「根 → TLD → 权威」整条链已失败（每跳失败
        # 过半即放弃 → 迭代整体失败）或超预算：这里回退到**按健康评分排序**的
        # 优选加密上游（DoH/DoT/DoQ，取 preferred_count 个），不再按配置顺序、
        # 也不再带 iterative（同一轮里重复死磕同一条迭代链只会继续拖时间）。
        # 优选波也失败 → 第三波用剩余全部上游做最终兜底（加密优先模式下这一波
        # 还包含 iterative，与旧行为一致）。每波超时都用完整 parallel_timeout。
        ordered_encrypted = [
            s for s in self._select_encrypted_upstreams(count=len(enabled))
            if s.server_type in ("doh", "dot", "doq") and s not in first_wave
        ]
        preferred_n = max(
            3, int(getattr(self.config, "preferred_server_count", 5) or 5)
        )
        preferred = ordered_encrypted[:preferred_n]
        rest = ordered_encrypted[preferred_n:]
        if not cap_iterative_budget:
            # 加密上游优先：iterative 作为最后的兜底波（与旧行为一致）。
            # **纯迭代模式例外**：第一波就是 iterative 且已给足 total_timeout，
            # 这里再兜一次等于把同一轮迭代（含 bootstrap 兜底）跑两遍，
            # 实测单查询耗时 3.7s → 7.4s，故跳过。
            if not self._is_pure_iterative_mode():
                rest.extend(
                    s for s in enabled
                    if s not in first_wave and s.server_type == "iterative"
                )
        waves = [
            (
                preferred,
                "迭代整体失败→回退优选加密上游（按健康评分）"
                if cap_iterative_budget else "加密上游优选",
            ),
            (rest, "其余上游最终兜底"),
        ]
        for wave_no, (wave_servers, label) in enumerate(waves, start=2):
            if not wave_servers:
                continue
            logger.debug(
                "备用查询[第%d波]: 尝试 %d 个上游（%s）",
                wave_no, len(wave_servers), label,
            )
            result = await self._try_upstream_wave(
                wave_servers, query_bytes, timeout,
            )
            if result is not None:
                self._last_fast_server = result[2].name
                self._last_fast_server_obj = result[2]
                return result[0]

        if self._failure_stats:
            summary = ", ".join(f"{k}×{v}" for k, v in sorted(self._failure_stats.items()))
            if self._is_pure_iterative_mode():
                # 纯迭代模式：单域名超时也会表现为「全部 1 个上游失败」，降噪
                logger.debug("并行查询: 迭代解析失败 — %s", summary)
            else:
                logger.warning("并行查询: 全部 %d 个上游均失败 — %s", len(enabled), summary)
            self._failure_stats.clear()
        else:
            if self._is_pure_iterative_mode():
                logger.debug("并行查询: 迭代解析失败（纯迭代模式）")
            else:
                logger.warning("并行查询: 全部 %d 个上游均失败", len(enabled))
        return None

    async def _background_consistency_check(
        self,
        query_bytes: bytes,
        fast_response: bytes,
        enabled_servers: List,
        exclude_servers: set = None,
    ):
        """
        后台一致性验证任务（不阻塞主响应返回）。
        收集其余上游的响应，执行多源交叉验证和异常检测。
        调用方（resolve）传入的 enabled_servers 是「已排除优选上游后的随机抽样」，
        本方法用其中第一个作为参考响应（fast_server），其余逐个查询对照。
        """
        if not self._consistency_verifier:
            return

        # 可诊断性：collect_and_verify 在 len(all_servers) < min_responses 时会直接
        # 返回且不计数（静默不验证）。常见成因是 max_background_servers 太小
        # （对照上游数不足以构成 2 个以上指纹）——这里留一条 debug 便于排查。
        if len(enabled_servers) < self._consistency_verifier.min_responses:
            logger.debug("一致性验证: 后台对照上游不足（%d 个 < min_responses=%d），本轮跳过"
                         "（可调大 response_verification.consistency.max_background_servers，"
                         "并确保加密上游总数 > upstream.preferred_count）",
                         len(enabled_servers), self._consistency_verifier.min_responses)
            return

        # 用抽样列表里的第一个作为参考响应（fast_server）——调用方 resolve()
        # 传入的 selected 是「已排除优选上游后的随机抽样」，不是"最快的上游"；
        # 其响应作为多数派基线，其余上游逐个查询比对指纹。
        fast_srv = enabled_servers[0] if enabled_servers else None
        if fast_srv is None:
            return

        # 从一致性验证器获取等待窗口
        window = self._consistency_verifier.consistency_window_ms / 1000.0
        if window <= 0:
            window = 0.8  # 默认 800ms

        # 收集其他上游响应并做一致性验证
        try:
            await self._consistency_verifier.collect_and_verify(
                fast_result=(fast_response, 0.0, None),
                fast_server=fast_srv.name,
                all_servers=enabled_servers,
                query_bytes=query_bytes,
                timeout=window,
                exclude_servers=exclude_servers,
            )
        except Exception as e:
            logger.debug("后台一致性验证异常: %s", e)

    async def refresh_upstream_ips(self, hostname: str):
        """刷新特定上游服务器的 IP 地址"""
        ips = await self._bootstrap_resolve(hostname)
        if ips:
            self._bootstrap_cache[hostname] = ips
            logger.info("刷新 %s -> %s", hostname, ips)
        return ips

    async def resolve_domain(self, hostname: str) -> List[str]:
        """
        通过优选上游解析域名（A + AAAA 双栈），返回 IP 地址列表。
        优先读取 _bootstrap_cache 缓存，未命中时解析并写入缓存（带锁保护）。
        """
        # 先读缓存（锁外快速路径）
        cached = self._bootstrap_cache.get(hostname)
        if cached:
            logger.debug("域名 %s 命中 bootstrap 缓存: %s", hostname, cached)
            return list(cached)
        # 未命中，加锁后双检，避免并发穿透
        async with self._bootstrap_lock:
            cached = self._bootstrap_cache.get(hostname)
            if cached:
                return list(cached)
            ips = await self._bootstrap_resolve(hostname)
            if ips:
                self._bootstrap_cache[hostname] = ips
                logger.debug("域名 %s 解析并缓存: %s", hostname, ips)
            return ips

    async def refresh_all_upstream_ips(self) -> int:
        """刷新所有上游域名的 bootstrap IP 缓存"""
        all_hostnames = set()
        for url in self.config.doh_servers:
            host = url.replace("https://", "").split("/")[0].split(":")[0]
            all_hostnames.add(host)
        for host in self.config.dot_servers:
            h = host.split(":")[0]
            all_hostnames.add(h)
        for addr in self.config.doq_servers:
            host = addr.replace("quic://", "").split(":")[0]
            all_hostnames.add(host)

        results = await asyncio.gather(
            *[self.refresh_upstream_ips(h) for h in all_hostnames],
            return_exceptions=True,
        )
        success_count = sum(1 for r in results if isinstance(r, list) and r)
        logger.info("批量刷新 bootstrap IP: %d/%d 成功", success_count, len(all_hostnames))

        # 重新尝试 ECH 预热（清理 _ech_warmup_failed 中可能已恢复的主机）
        if self._ech_warmup_failed:
            retried = set(self._ech_warmup_failed)
            for hostname in retried:
                fetcher = self._ech_fetchers.get(hostname)
                if fetcher and fetcher.enabled and not fetcher.has_valid_config:
                    try:
                        config = await asyncio.wait_for(fetcher.force_refresh(), timeout=8.0)
                        if config:
                            self._ech_warmup_failed.discard(hostname)
                            logger.info("  %s: ECH 刷新成功，已从预热失败列表中移除", hostname)
                        else:
                            logger.debug("  %s: ECH 刷新仍无配置，保留在预热失败列表", hostname)
                    except asyncio.TimeoutError:
                        logger.debug("  %s: ECH 刷新超时，保留在预热失败列表", hostname)
                    except Exception as e:
                        logger.debug("  %s: ECH 刷新异常: %s", hostname, e)

        return success_count

    def get_bootstrap_addresses(self) -> List[str]:
        """获取所有 bootstrap 解析器地址"""
        return [bs.name for bs in self._bootstrap_resolvers]

    async def reset_all_connections(self):
        """
        重置所有上游和 bootstrap 解析器的持久连接。
        网络恢复（如网卡禁用/重新启用）后调用，强制所有解析器在下次查询时
        创建全新的连接，避免使用失效的会话/连接池。
        """
        logger.info("正在重置所有解析器的持久连接...")
        for server in self._upstream_servers:
            try:
                await server.resolver.reset_connections()
            except Exception as e:
                logger.debug("重置 %s 连接失败: %s", server.name, e)
        for server in self._bootstrap_resolvers:
            try:
                await server.resolver.reset_connections()
            except Exception as e:
                logger.debug("重置 bootstrap %s 连接失败: %s", server.name, e)
        # 清除 bootstrap DNS 缓存，强制重新解析
        self._bootstrap_cache.clear()
        logger.info("所有解析器持久连接已重置，bootstrap 缓存已清空")

    def reenable_all(self):
        """重新启用所有上游服务器"""
        for s in self._upstream_servers:
            s.reenable()
        for s in self._bootstrap_resolvers:
            s.reenable()

    def enter_recovery_mode(self):
        """
        进入恢复模式：网络刚刚恢复，上游首次查询可能因连接重建而短暂失败。
        恢复模式下，服务器失败不计入连续失败计数，不会被禁用。
        首次成功查询后自动退出恢复模式。
        """
        self._recovery_mode = True
        logger.info("进入恢复模式：瞬时失败不会禁用上游服务器")

    def exit_recovery_mode(self):
        """退出恢复模式"""
        if self._recovery_mode:
            self._recovery_mode = False
            logger.info("退出恢复模式：上游服务器正常工作")

    async def close_all(self):
        """关闭所有解析器"""
        # 停止自动重连任务
        if self._recovery_task:
            self._recovery_task.cancel()
            try:
                await self._recovery_task
            except asyncio.CancelledError:
                pass
            self._recovery_task = None

        for server in self._upstream_servers:
            try:
                await server.resolver.close()
            except Exception as e:
                logger.debug("解析管理器关闭上游解析器异常: %s", e)
        for server in self._bootstrap_resolvers:
            try:
                await server.resolver.close()
            except Exception as e:
                logger.debug("解析管理器关闭 bootstrap 解析器异常: %s", e)

        # 关闭 ECH fetchers（取消后台刷新任务）
        for hostname, fetcher in self._ech_fetchers.items():
            try:
                fetcher.close()
            except Exception as e:
                logger.debug("解析管理器关闭 ECH fetcher 异常: %s", e)

        # 关闭全局共享 DoH session
        if self._shared_doh_session and not self._shared_doh_session.closed:
            try:
                await self._shared_doh_session.close()
            except Exception as e:
                logger.debug("解析管理器关闭共享 DoH session 异常: %s", e)
            self._shared_doh_session = None

    async def resolve_dnskey(self, query_bytes: bytes) -> Optional[bytes]:
        """
        DNSKEY 专用查询（跳过 DNSSEC 验证防止递归）。
        由 DNSSECValidator 在链验证时调用。
        """
        async with self._concurrent_semaphore:
            return await self._parallel_resolve(query_bytes)

    @property
    def stats(self) -> Dict[str, Any]:
        """获取所有上游服务器的统计信息"""
        upstream_stats = []
        for s in self._upstream_servers:
            upstream_stats.append(
                {
                    "name": s.name,
                    "type": s.server_type,
                    "enabled": s.enabled,
                    "failures": s.failures,
                    "stats": s.resolver.stats,
                }
            )
        return {"upstream_servers": upstream_stats}

    @property
    def upstream_count(self) -> int:
        return len(self._upstream_servers)

    @property
    def last_fast_server(self) -> Optional[str]:
        """最后成功响应的最快上游服务器名称"""
        return self._last_fast_server

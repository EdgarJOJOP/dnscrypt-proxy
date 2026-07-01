"""
并行解析管理器
- 并行查询所有上游服务器
- 取最快成功响应返回
- 支持普通 DNS、DoH、DoT、DoQ
- Bootstrap 解析上游服务器域名
"""

import asyncio
import collections
import logging
import os
import time
import tempfile
import atexit
from typing import List, Optional, Dict, Any

import dns.message
import dns.name
import dns.rdatatype
import dns.asyncquery

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
    from resolvers.ech_doh import ECHDoHResolver
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
        }.get(self.server_type, 0)
        score += proto_bonus
        # 失败扣分
        score -= self.failures * self._SCORE_WEIGHT_FAILURES
        score -= self.consecutive_failures * self._SCORE_WEIGHT_FAILURES * 3
        # 延迟扣分：每100ms扣分，平滑处理
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

    def record_failure(self):
        self.consecutive_failures += 1
        self.failures += 1
        # 连续失败 5 次，暂时禁用
        if self.consecutive_failures >= 5:
            self.enabled = False
            logger.warning("上游 %s 连续失败 %d 次，已暂时禁用", self.name, self.consecutive_failures)

    def reenable(self):
        if not self.enabled:
            self.enabled = True
            self.consecutive_failures = 0
            logger.info("上游 %s 已重新启用", self.name)


class ResolverManager:
    """并行解析管理器"""

    def __init__(self, config: Config, dnssec_wrapper: Optional[DNSSECQueryWrapper] = None,
                 consistency_verifier: Optional[ResponseConsistencyVerifier] = None,
                 anomaly_detector: Optional[AnomalyDetector] = None):
        self.config = config
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
        # 后台一致性验证节流
        self._consistency_check_count = 0  # 1/10 采样计数器
        # 定期清理空闲连接的任务
        self._cleanup_idle_task: Optional[asyncio.Task] = None

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
            resolver = PlainDNSResolver(addr, timeout=5.0, concurrency=self.config.connection_pool_size)
            self._bootstrap_resolvers.append(UpstreamServer(resolver, "plain"))

        # 检查是否有任何上游服务器
        total_upstreams = (len(self.config.doh_servers) + len(self.config.dot_servers)
                           + len(self.config.doq_servers))
        if total_upstreams == 0:
            logger.warning("未配置任何上游服务器（doh/dot/doq 均为空），所有查询将返回 SERVFAIL")
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
        if total_upstreams == 0:
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
        # 5b. 启动定期空闲连接清理（每 120 秒）
        self._cleanup_idle_task = asyncio.create_task(self._periodic_idle_cleanup())

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

        results = await asyncio.gather(
            *[self._bootstrap_resolve(hostname) for hostname in all_hostnames],
            return_exceptions=True,
        )

        for hostname, result in zip(all_hostnames, results):
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

        for attempt in range(3):  # 重试最多 3 次
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
                for result in results:
                    if isinstance(result, bytes):
                        try:
                            response = dns.message.from_wire(result)
                            for rrset in response.answer:
                                for rd in rrset:
                                    if rd.rdtype == qtype:
                                        ips.append(str(rd.address))
                        except (UnicodeError, ValueError) as e:
                            logger.debug("解析管理器 DNS 响应包含非法字符: %s", e)
                            continue
                        except Exception as e:
                            logger.debug("解析管理器 DNS 响应解析异常: %s", e)
                            continue

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
                resolver = ECHDoHResolver(
                    url, timeout=timeout,
                    ech_fetcher=ech_fetcher,
                    openssl_wrapper=self._openssl4_wrapper,
                    ca_path=ca_path,
                    ciphers=self.config.tls_ciphers,
                    connect_ips=cached_ips,
                    concurrency=self.config.connection_pool_size,
                )
                if not resolver.available:
                    resolver = DoHResolver(url, timeout=timeout,
                                           connection_pool_size=self.config.connection_pool_size,
                                           connect_ips=cached_ips,
                                           concurrency=self.config.connection_pool_size,
                                           ca_path=ca_path or "",
                                           shared_session=self._shared_doh_session,
                                           shared_resolver=self._shared_doh_resolver)
            else:
                resolver = DoHResolver(url, timeout=timeout,
                                       connection_pool_size=self.config.connection_pool_size,
                                       connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size,
                                       ca_path=ca_path or "",
                                       shared_session=self._shared_doh_session,
                                       shared_resolver=self._shared_doh_resolver)
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

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
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

        # 后台一致性验证（复用健康评分，只选最优 5 个加密上游）
        if should_verify and result is not None:
            selected = self._select_encrypted_upstreams(count=5)
            if selected:
                asyncio.create_task(
                    self._background_consistency_check(
                        dnssec_query, result, selected
                    )
                )

        return result

    async def _auto_recover(self):
        """
        自动恢复：当检测到无可用上游服务器时调用。
        1. 重置所有持久连接（关闭失效的 aiohttp 会话等）
        2. 重新启用所有上游服务器
        3. 进入恢复模式（首次失败不计入连续失败）
        4. 异步刷新 bootstrap IP 缓存（失败不影响恢复）
        """
        logger.info("触发上游服务器自动恢复...")
        # 重置所有持久连接
        for server in self._upstream_servers:
            try:
                await server.resolver.reset_connections()
            except Exception as e:
                logger.debug("解析管理器重置上游连接异常: %s", e)
        for server in self._bootstrap_resolvers:
            try:
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

        # === 启动缓冲期 ===
        # 程序刚启动时，上游 DNS 连接尚未建立，给它们 3 秒时间
        startup_elapsed = now - self._start_time
        if startup_elapsed < self._startup_buffer:
            result = await self._parallel_resolve_once(query_bytes)
            if result is not None:
                if self._last_all_failed_time > 0:
                    logger.info("并行查询: 上游服务器已恢复域名解析")
                    self._last_all_failed_time = 0.0
                return result
            # 全部失败：等待到缓冲期结束再试
            wait = self._startup_buffer - (asyncio.get_event_loop().time() - self._start_time)
            if wait > 0:
                logger.debug("并行查询: 启动缓冲期 %.1fs，等待上游连接...", wait)
                await asyncio.sleep(wait)
            result = await self._parallel_resolve_once(query_bytes)
            if result is not None:
                if self._last_all_failed_time > 0:
                    logger.info("并行查询: 上游服务器已恢复域名解析 (启动缓冲后)")
                    self._last_all_failed_time = 0.0
                return result

        # === 集群故障冷却 ===
        # 更新时间戳，因为启动缓冲可能已经睡了几秒
        now = asyncio.get_event_loop().time()
        if self._last_all_failed_time > 0:
            elapsed = now - self._last_all_failed_time
            if elapsed < self._all_failed_cooldown:
                wait = self._all_failed_cooldown - elapsed
                logger.debug("并行查询: 集群故障冷却 %.1fs (距上次全部失败 %.1fs)", wait, elapsed)
                await asyncio.sleep(wait)

        result = await self._parallel_resolve_once(query_bytes)
        if result is not None:
            if self._last_all_failed_time > 0:
                logger.info("并行查询: 上游服务器已恢复域名解析")
                self._last_all_failed_time = 0.0
            return result

        # === 全部失败 → 仅一个请求执行重试 ===
        self._last_all_failed_time = asyncio.get_event_loop().time()

        if self._retry_lock.locked():
            # 已有其他请求在重试，这个请求直接返回（避免重复日志）
            return None

        _failure_start = self._last_all_failed_time
        alive = sum(1 for s in self._upstream_servers if s.enabled)
        _version = self._retry_version

        async with self._retry_lock:
            # 检查版本号：如果已在之前的重试中被递增，说明已有其他请求执行过重试
            if _version != self._retry_version:
                return None

            for retry, delay in enumerate([0.2, 0.5, 1.0], start=1):
                logger.warning("并行查询: 全部 %d 个上游均失败，%.1fs 后第 %d 次重试...",
                               alive, delay, retry)
                await asyncio.sleep(delay)
                result = await self._parallel_resolve_once(query_bytes)
                if result is not None:
                    logger.info("并行查询: 上游服务器已恢复域名解析 (第 %d 次重试成功, 耗时 %.1fs)",
                                retry,
                                asyncio.get_event_loop().time() - _failure_start)
                    self._last_all_failed_time = 0.0
                    self._retry_version += 1
                    return result
                self._last_all_failed_time = asyncio.get_event_loop().time()

            self._retry_version += 1
            logger.warning("并行查询: 全部 %d 个上游均失败 (%d 次重试后放弃)", alive, 3)
            return None

    def _select_encrypted_upstreams(self, count: int = 3) -> List[UpstreamServer]:
        """
        按健康评分选择最优的 N 个加密上游（DoH/DoT/DoQ）。
        不包含 plain（普通 DNS 只做 bootstrap 解析）。
        """
        encrypted = [
            s for s in self._upstream_servers
            if s.enabled and s.server_type in ("doh", "dot", "doq")
        ]
        # 按健康评分从高到低排序
        encrypted.sort(key=lambda s: s.health_score, reverse=True)
        return encrypted[:count]

    async def _try_upstream_wave(
        self, servers: List[UpstreamServer], query_bytes: bytes,
        remaining_timeout: float,
    ) -> Optional[tuple]:
        """
        向一组上游并行查询，返回最快成功响应 (result, elapsed, server)。
        若全部失败或超时返回 None。
        """
        if not servers:
            return None

        async def query_one(server: UpstreamServer) -> Optional[tuple]:
            try:
                result, elapsed = await server.resolver.resolve_with_stats(
                    query_bytes
                )
                if result is not None:
                    self.exit_recovery_mode()
                    server.record_success(response_time=elapsed)
                    return (result, elapsed, server)
                if not self._recovery_mode:
                    server.record_failure()
                    self._failure_stats["返回空"] = self._failure_stats.get("返回空", 0) + 1
                else:
                    logger.debug("上游 %s 返回空（恢复模式，不计失败）", server.name)
                return None
            except asyncio.CancelledError:
                return None
            except Exception as e:
                if not self._recovery_mode:
                    server.record_failure()
                    logger.warning("上游 %s 查询失败: %s [%s]",
                                   server.name, e, type(e).__name__)
                    err_type = type(e).__name__
                    self._failure_stats[err_type] = self._failure_stats.get(err_type, 0) + 1
                else:
                    logger.debug("上游 %s 异常（恢复模式）: %s", server.name, e)
                return None

        tasks = [asyncio.create_task(query_one(s)) for s in servers]
        remaining = set(tasks)
        deadline = asyncio.get_event_loop().time() + remaining_timeout
        successful = []

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

        for task in remaining:
            task.cancel()
        # 取消未完成的任务；CancelledError 在 query_one 中被捕获返回 None，
        # 不会传播到 DoQ 内部。连接清理由各 resolver 的 close/reset 负责。
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)

        if successful:
            successful.sort(key=lambda x: x[1])
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

        # 第一波：按健康评分选最优的 3 个加密上游（DoH/DoT/DoQ）
        first_wave = self._select_encrypted_upstreams(count=3)
        if first_wave:
            logger.debug("首波查询: %d 个最优上游", len(first_wave))
            result = await self._try_upstream_wave(
                first_wave, query_bytes, timeout,
            )
            if result is not None:
                self._last_fast_server = result[2].name
                self._last_fast_server_obj = result[2]
                return result[0]

        # 第二波：剩余加密上游
        remaining = [
            s for s in enabled
            if s not in first_wave
            and s.server_type in ("doh", "dot", "doq")
        ]
        if remaining:
            logger.debug("备用查询: 尝试剩余 %d 个加密上游", len(remaining))
            result = await self._try_upstream_wave(
                remaining, query_bytes, timeout * 0.5,
            )
            if result is not None:
                self._last_fast_server = result[2].name
                self._last_fast_server_obj = result[2]
                return result[0]

        if self._failure_stats:
            summary = ", ".join(f"{k}×{v}" for k, v in sorted(self._failure_stats.items()))
            logger.warning("并行查询: 全部 %d 个上游均失败 — %s", len(enabled), summary)
            self._failure_stats.clear()
        else:
            logger.warning("并行查询: 全部 %d 个上游均失败", len(enabled))
        return None

    async def _background_consistency_check(
        self,
        query_bytes: bytes,
        fast_response: bytes,
        enabled_servers: List,
    ):
        """
        后台一致性验证任务（不阻塞主响应返回）。
        收集其余上游的响应，执行多源交叉验证和异常检测。
        """
        if not self._consistency_verifier:
            return

        # 用第一个 server 作为"最快"标识（调用方已通过健康评分预选）
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
            )
        except Exception as e:
            logger.debug("后台一致性验证异常: %s", e)
        finally:
            # 验证完成后释放临时连接
            try:
                await self.close_idle_connections()
            except Exception:
                pass

    async def _periodic_idle_cleanup(self):
        """定期清理空闲连接（每 120 秒），防止 UDP/TCP 连接积压。"""
        while True:
            try:
                await asyncio.sleep(120)
                logger.debug("定期清理：执行空闲连接关闭...")
                await self.close_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("定期清理异常: %s", e)

    async def refresh_upstream_ips(self, hostname: str):
        """刷新特定上游服务器的 IP 地址"""
        ips = await self._bootstrap_resolve(hostname)
        if ips:
            self._bootstrap_cache[hostname] = ips
            logger.info("刷新 %s -> %s", hostname, ips)
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
        # 停止定期清理任务
        if self._cleanup_idle_task:
            self._cleanup_idle_task.cancel()
            self._cleanup_idle_task = None
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

    async def close_idle_connections(self):
        """关闭所有空闲持久连接（在内存紧张时调用），保留活跃连接不受影响
        
        区别于 reset_all_connections() 的暴力重置，此方法仅关闭可安全释放的空闲连接：
        - DoT 连接池: 关闭空闲 TLS 连接
        - DoQ 连接池: 关闭空闲 QUIC 连接
        - bootstrap 解析器: 释放空闲 UDP 套接字
        """
        closed = 0
        for server in self._upstream_servers:
            try:
                if hasattr(server.resolver, 'close_idle'):
                    await server.resolver.close_idle()
                    closed += 1
                elif hasattr(server.resolver, 'reset_connections'):
                    await server.resolver.reset_connections()
                    closed += 1
            except Exception as e:
                logger.debug("关闭 %s 空闲连接失败: %s", server.name, e)
        for server in self._bootstrap_resolvers:
            try:
                if hasattr(server.resolver, 'close_idle'):
                    await server.resolver.close_idle()
                    closed += 1
                elif hasattr(server.resolver, 'reset_connections'):
                    await server.resolver.reset_connections()
                    closed += 1
            except Exception as e:
                logger.debug("关闭 bootstrap %s 空闲连接失败: %s", server.name, e)
        if closed:
            logger.debug("关闭了 %d 个解析器的空闲连接", closed)

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

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
import time
from typing import List, Optional, Dict, Any

import dns.message
import dns.name
import dns.rdatatype
import dns.asyncquery

from config import Config
from crypto.ech_fetcher import ECHConfigFetcher
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from resolvers.base import BaseResolver
from resolvers.doh import DoHResolver
from resolvers.dot import DoTResolver
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
        self.consecutive_failures = 0
        self.failures = 0
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

    def __init__(self, config: Config, dnssec_wrapper: Optional[DNSSECQueryWrapper] = None):
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
        # 重试互斥锁：只有一个并发请求执行重试，其余直接返回 SERVFAIL
        self._retry_lock = asyncio.Lock()
        self._retry_version = 0  # 每次重试递增，避免锁排队请求重复重试
        self._ech_fetchers: Dict[str, ECHConfigFetcher] = {}  # hostname -> ECHConfigFetcher
        self._openssl4_wrapper = None  # OpenSSL 4.0 wrapper（ECH；如不可用则为 None）

    async def initialize(self):
        """初始化所有解析器"""
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
            q = dns.message.make_query(hostname, qtype)
            queries[qtype] = q.to_wire()

        async def try_resolver(qbytes: bytes, bs: UpstreamServer, addr_family: str) -> Optional[bytes]:
            try:
                return await bs.resolver.resolve(qbytes, prefer_family=addr_family)
            except Exception:
                return None

        for attempt in range(3):  # 重试最多 3 次
            ips = []
            # A 和 AAAA 独立查询，一个失败不影响另一个
            for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                qbytes = queries[qtype]
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
                        except Exception:
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
                try:
                    config = await asyncio.wait_for(fetcher.get_config(), timeout=8.0)
                    if config:
                        logger.info("  %s: ECH 预热成功 (%d bytes)", hostname, len(config))
                    else:
                        logger.debug("  %s: ECH 预热返回空", hostname)
                except asyncio.TimeoutError:
                    logger.debug("  %s: ECH 预热超时（后台继续重试）", hostname)
                except Exception as e:
                    logger.debug("  %s: ECH 预热异常: %s（后台继续重试）", hostname, e)

        enabled_count = sum(1 for f in self._ech_fetchers.values() if f.enabled)
        logger.info("ECH 获取器初始化完成: %d/%d 个上游", enabled_count, len(self._ech_fetchers))

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
        # CA 证书路径：配置 > certifi > None
        ca_path = self.config.openssl4_ca_path or None
        if ca_path is None:
            try:
                import certifi
                ca_path = certifi.where()
            except ImportError:
                pass

        # DoH
        for url in self.config.doh_servers:
            hostname = url.replace("https://", "").split("/")[0].split(":")[0]
            cached_ips = self._bootstrap_cache.get(hostname, [])
            ech_fetcher = self._ech_fetchers.get(hostname) if ech_enabled else None
            has_ech = openssl4_available and ech_fetcher is not None and ech_fetcher.enabled

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
                                           concurrency=self.config.connection_pool_size)
            else:
                resolver = DoHResolver(url, timeout=timeout,
                                       connection_pool_size=self.config.connection_pool_size,
                                       connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size)
            self._upstream_servers.append(UpstreamServer(resolver, "doh"))

        # DoT
        for host in self.config.dot_servers:
            parts = host.split(":")
            h = parts[0]
            p = int(parts[1]) if len(parts) > 1 else 853
            cached_ips = self._bootstrap_cache.get(h, [])
            ech_fetcher = self._ech_fetchers.get(h) if ech_enabled else None
            has_ech = openssl4_available and ech_fetcher is not None and ech_fetcher.enabled

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
                                           concurrency=self.config.connection_pool_size)
            else:
                resolver = DoTResolver(h, port=p, timeout=timeout, connect_ips=cached_ips,
                                       concurrency=self.config.connection_pool_size)
            self._upstream_servers.append(UpstreamServer(resolver, "dot"))

        # DoQ
        for addr in self.config.doq_servers:
            hostname = addr.replace("quic://", "").split(":")[0]
            cached_ips = self._bootstrap_cache.get(hostname, [])
            resolver = DoQResolver(addr, timeout=timeout, connect_ips=cached_ips,
                                   concurrency=self.config.connection_pool_size)
            self._upstream_servers.append(UpstreamServer(resolver, "doq"))

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """
        并行查询所有上游，返回最快响应。
        如果启用了 DNSSEC，自动添加 DO 位。
        """
        async with self._concurrent_semaphore:
            # DNSSEC: 包装查询添加 DO 位
            dnssec_query = query_bytes
            if self._dnssec is not None:
                dnssec_query = self._dnssec.wrap_query(query_bytes)

            result = await self._parallel_resolve(dnssec_query)
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
            except Exception:
                pass
        for server in self._bootstrap_resolvers:
            try:
                await server.resolver.reset_connections()
            except Exception:
                pass
        # 清除 bootstrap 缓存
        self._bootstrap_cache.clear()
        # 重新启用 + 恢复模式
        self.reenable_all()
        self.enter_recovery_mode()
        # 异步刷新 bootstrap IP（非阻塞，失败不影响恢复）
        asyncio.create_task(self._async_refresh_bootstrap())
        enabled = sum(1 for s in self._upstream_servers if s.enabled)
        logger.info("自动恢复完成: %d 个上游已启用", enabled)

    async def _async_refresh_bootstrap(self):
        """异步刷新所有上游域名的 bootstrap IP（自动恢复时调用）"""
        try:
            await asyncio.sleep(0.5)  # 稍等片刻再刷新
            await self.refresh_all_upstream_ips()
        except Exception as e:
            logger.debug("自动恢复后刷新 bootstrap IP 失败: %s", e)

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
            t0 = asyncio.get_event_loop().time()
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
                else:
                    logger.debug("上游 %s 返回空（恢复模式，不计失败）", server.name)
                return None
            except asyncio.CancelledError:
                return None
            except Exception as e:
                if not self._recovery_mode:
                    server.record_failure()
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
                except Exception:
                    pass

        for task in remaining:
            task.cancel()

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
                return result[0]

        logger.warning("并行查询: 全部 %d 个上游均失败", len(enabled))
        return None

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
            except Exception:
                pass
        for server in self._bootstrap_resolvers:
            try:
                await server.resolver.close()
            except Exception:
                pass

        # 关闭 ECH fetchers（取消后台刷新任务）
        for hostname, fetcher in self._ech_fetchers.items():
            try:
                fetcher.close()
            except Exception:
                pass

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

"""
并行解析管理器
- 并行查询所有上游服务器
- 取最快成功响应返回
- 支持普通 DNS、DoH、DoT、DoQ
- Bootstrap 解析上游服务器域名
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any

import dns.message
import dns.name
import dns.rdatatype
import dns.asyncquery

from config import Config
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from resolvers.base import BaseResolver
from resolvers.doh import DoHResolver
from resolvers.dot import DoTResolver
from resolvers.doq import DoQResolver
from resolvers.plain import PlainDNSResolver

logger = logging.getLogger("dns-proxy.resolver")


class UpstreamServer:
    """上游服务器封装"""

    def __init__(self, resolver: BaseResolver, server_type: str):
        self.resolver = resolver
        self.server_type = server_type  # "doh", "dot", "doq", "plain"
        self.failures = 0
        self.consecutive_failures = 0
        self.enabled = True

    @property
    def name(self) -> str:
        return self.resolver.name

    def record_success(self):
        self.consecutive_failures = 0
        self.failures = 0

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

    async def initialize(self):
        """初始化所有解析器"""
        self._concurrent_semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # 1. 创建 bootstrap 解析器（普通 DNS）
        for addr in self.config.bootstrap_resolvers:
            resolver = PlainDNSResolver(addr, timeout=5.0)
            self._bootstrap_resolvers.append(UpstreamServer(resolver, "plain"))

        # 2. 解析上游服务器域名 -> IP
        logger.info("正在通过 bootstrap DNS 解析上游服务器地址...")
        await self._resolve_upstream_hostnames()

        # 3. 创建加密上游解析器
        await self._create_upstream_resolvers()

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

    async def _create_upstream_resolvers(self):
        """创建加密上游解析器"""
        timeout = self.config.parallel_timeout

        ech_enabled = self.config.ech_enabled

        # DoH
        for url in self.config.doh_servers:
            resolver = DoHResolver(url, timeout=timeout, ech_enabled=ech_enabled)
            self._upstream_servers.append(UpstreamServer(resolver, "doh"))

        # DoT — 先尝试 hostname 直连（系统 DNS），再 fallback bootstrap IP
        for host in self.config.dot_servers:
            parts = host.split(":")
            h = parts[0]
            p = int(parts[1]) if len(parts) > 1 else 853
            cached_ips = self._bootstrap_cache.get(h, [])
            resolver = DoTResolver(h, port=p, timeout=timeout, connect_ips=cached_ips, ech_enabled=ech_enabled)
            self._upstream_servers.append(UpstreamServer(resolver, "dot"))

        # DoQ
        for addr in self.config.doq_servers:
            resolver = DoQResolver(addr, timeout=timeout)
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

    async def _parallel_resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """并行查询核心逻辑"""
        servers = [s for s in self._upstream_servers if s.enabled]
        if not servers:
            logger.warning("没有可用的上游服务器")
            return None

        async def query_with_timeout(
            server: UpstreamServer,
        ) -> Optional[tuple]:
            t0 = asyncio.get_event_loop().time()
            try:
                result, elapsed = await server.resolver.resolve_with_stats(query_bytes)
                if result is not None:
                    server.record_success()
                    logger.debug("上游 %s 成功响应 (%.1fms)", server.name, elapsed * 1000)
                    return (result, elapsed, server)
                server.record_failure()
                elapsed_ms = (asyncio.get_event_loop().time() - t0) * 1000
                logger.warning("上游 %s 返回空结果 (%.1fms)", server.name, elapsed_ms)
                return None
            except asyncio.CancelledError:
                # 被 parallel_resolve 取消，不记录日志
                return None
            except Exception as e:
                server.record_failure()
                elapsed_ms = (asyncio.get_event_loop().time() - t0) * 1000
                logger.warning("上游 %s 异常: %s (%.1fms)", server.name, e, elapsed_ms)
                return None

        logger.debug("并行查询: %d 个上游可用, timeout=%.1fs", len(servers), self.config.parallel_timeout)

        # 使用 FIRST_COMPLETED 循环策略:
        # 如果首批完成的任务全部失败（如 DoH 缺依赖瞬时失败），
        # 继续等待剩余任务（如 DoT），而不是直接放弃
        tasks = [asyncio.create_task(query_with_timeout(s)) for s in servers]
        remaining = set(tasks)
        successful = []
        deadline = asyncio.get_event_loop().time() + self.config.parallel_timeout

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
                    result = task.result()
                    if result is not None:
                        successful.append(result)
                except (asyncio.CancelledError, Exception):
                    pass

        # 取消未完成的任务
        for task in remaining:
            task.cancel()

        if not successful:
            logger.debug("并行查询: 所有 %d 个上游均失败", len(servers))
            return None

        # 按响应时间排序，返回最快的
        successful.sort(key=lambda x: x[1])
        fastest = successful[0]
        return fastest[0]

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

    def reenable_all(self):
        """重新启用所有上游服务器"""
        for s in self._upstream_servers:
            s.reenable()
        for s in self._bootstrap_resolvers:
            s.reenable()

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

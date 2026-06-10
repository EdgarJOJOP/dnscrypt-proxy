"""
本地纯 DNS 服务器（UDP 53 端口）
- 不加密的 DNS 协议，用于局域网客户端
- 支持 IPv4 + IPv6 双栈
- 默认关闭，需在配置中手动开启
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Tuple

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset

from config import Config
from resolver_manager import ResolverManager
from cache import DNSCache
from filter_engine import FilterEngine
from logger import RequestLogger
from dnssec import DNSSECQueryWrapper
from rate_limiter import get_per_ip_limiter

logger = logging.getLogger("dns-proxy.plain-dns")

# DNS 最大 UDP 数据报大小（DNSSEC 建议 1232，传统 512）
MAX_UDP_SIZE = 1232


class PlainDNSServer:
    """纯 DNS 服务器（UDP 53 端口，默认关闭）"""

    def __init__(
        self,
        config: Config,
        resolver_manager: ResolverManager,
        cache: DNSCache,
        filter_engine: FilterEngine,
        request_logger: RequestLogger,
        dnssec_wrapper: Optional[DNSSECQueryWrapper] = None,
    ):
        self.config = config
        self.resolver_manager = resolver_manager
        self.cache = cache
        self.filter_engine = filter_engine
        self.request_logger = request_logger
        self._dnssec_wrapper = dnssec_wrapper

        self.enabled = config.plain_dns_enabled
        self.host = config.plain_dns_host
        self.port = config.plain_dns_port
        self.ipv6_enabled = config.plain_dns_ipv6_enabled
        self.ipv6_host = config.plain_dns_ipv6_host

        self._transport_v4: Optional[asyncio.DatagramTransport] = None
        self._transport_v6: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)

        # 单 IP 限速（共享 PerIPRateLimiter 单例）
        self._per_ip_limiter = get_per_ip_limiter(
            per_ip_limit=config.max_concurrent_per_ip,
        )
        self._per_ip_limit = config.max_concurrent_per_ip
        self._ip_semaphore_task: Optional[asyncio.Task] = None

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        return await self._per_ip_limiter.acquire(client_ip)

    async def _cleanup_stale_per_ip_semaphores(self):
        # 由共享 PerIPRateLimiter 后台管理
        await asyncio.Event().wait()

    # ======================== UDP 协议 ========================

    class _DnsProtocol(asyncio.DatagramProtocol):
        """UDP DNS 协议处理器"""

        def __init__(self, server: "PlainDNSServer"):
            self.server = server
            self.transport = None

        def connection_made(self, transport: asyncio.DatagramTransport):
            self.transport = transport

        def datagram_received(self, data: bytes, addr: tuple):
            """收到 DNS 查询 UDP 数据报"""
            self.server._handle_query(data, addr, self.transport)

        def error_received(self, exc):
            logger.warning("UDP 错误: %s", exc)

    def _handle_query(self, data: bytes, addr: tuple, transport: asyncio.DatagramTransport):
        """处理 DNS 查询（异步执行，避免阻塞 UDP 接收）"""
        asyncio.ensure_future(self._process_query(data, addr, transport))

    async def _process_query(self, data: bytes, addr: tuple,
                              transport: Optional[asyncio.DatagramTransport] = None):
        """异步处理 DNS 查询（并发控制 + 单 IP 限速）"""
        client_ip = addr[0]
        # 单 IP 限速 (非 localhost)
        if not self._is_localhost(client_ip):
            sem = await self._get_per_ip_semaphore(client_ip)
            async with sem:
                async with self._concurrency_semaphore:
                    return await self._do_process_query(data, addr, transport, client_ip)
        async with self._concurrency_semaphore:
            return await self._do_process_query(data, addr, transport, client_ip)

    async def _do_process_query(self, data: bytes, addr: tuple,
                                 transport: Optional[asyncio.DatagramTransport],
                                 client_ip: str):
        """DNS 查询处理核心逻辑"""
        qname = ""
        qtype_str = ""
        status = "ok"
        block_reason = ""
        start_time = asyncio.get_event_loop().time()

        try:
            # 解析 DNS 查询
            query = dns.message.from_wire(data)
            if not query.question:
                self._send_raw_response(b"", addr, transport)
                return

            question = query.question[0]
            qname = str(question.name).rstrip(".")
            qtype_str = dns.rdatatype.to_text(question.rdtype)
            cache_key = (question.name, question.rdtype, question.rdclass)

            # 0. 检查自定义 hosts 映射（最高优先级）
            custom_ips = self.filter_engine.get_custom_hosts_ips(qname)
            if custom_ips:
                response = dns.message.make_response(query)
                rdtype = question.rdtype
                matched = False
                for ip, ip_rdtype in custom_ips:
                    if rdtype == dns.rdatatype.A and ip_rdtype == dns.rdatatype.AAAA:
                        continue
                    if rdtype == dns.rdatatype.AAAA and ip_rdtype == dns.rdatatype.A:
                        continue
                    if rdtype == dns.rdatatype.A and ip_rdtype == dns.rdatatype.A:
                        if not response.answer or response.answer[0].rdtype != dns.rdatatype.A:
                            response.answer.append(
                                dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.A)
                            )
                        response.answer[-1].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, ip), ttl=3600)
                        matched = True
                    elif rdtype == dns.rdatatype.AAAA and ip_rdtype == dns.rdatatype.AAAA:
                        if not response.answer or response.answer[0].rdtype != dns.rdatatype.AAAA:
                            response.answer.append(
                                dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                            )
                        response.answer[-1].add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, ip), ttl=3600)
                        matched = True
                if matched:
                    response.set_rcode(dns.rcode.NOERROR)
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    self._send_raw_response(response.to_wire(), addr, transport)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, "custom_hosts", "")
                    return

            # 1. 检查域名过滤
            if self.config.filter_enabled:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    block_reason = reason
                    status = "blocked"
                    # 像 AdGuard 一样重写 IP：A → 0.0.0.0，AAAA → ::，其他类型 → NXDOMAIN
                    response = dns.message.make_response(query)
                    if question.rdtype == dns.rdatatype.A:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.A)
                        )
                        response.answer[0].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0"), ttl=3600)  # nosec B104 - blocked A record, not binding
                        response.set_rcode(dns.rcode.NOERROR)
                    elif question.rdtype == dns.rdatatype.AAAA:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                        )
                        response.answer[0].add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, "::"), ttl=3600)
                        response.set_rcode(dns.rcode.NOERROR)
                    else:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    # 缓存拦截结果
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    self._send_raw_response(response.to_wire(), addr, transport)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)
                    return

            # 2. 检查缓存
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    self._send_raw_response(cached.to_wire(), addr, transport)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, qtype_str, elapsed, "cached", ""
                    )
                    return

            # 3. 上游并行查询
            result_wire = await self.resolver_manager.resolve(data)

            if result_wire is None:
                # 所有上游失败
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                self._send_raw_response(response.to_wire(), addr, transport)
                status = "error"
            else:
                # DNSSEC 验证
                if self._dnssec_wrapper is not None and self.config.dnssec_enabled:
                    dnssec_ok, _ = await self._dnssec_wrapper.validate_response(
                        data, result_wire
                    )
                    if not dnssec_ok and self.config.dnssec_drop_bogus:
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.SERVFAIL)
                        self._send_raw_response(response.to_wire(), addr, transport)
                        status = "dnssec_bogus"
                    else:
                        self._send_raw_response(result_wire, addr, transport)
                        status = "resolved"
                else:
                    self._send_raw_response(result_wire, addr, transport)
                    status = "resolved"

                # 缓存结果
                if self.config.cache_enabled and status == "resolved":
                    try:
                        response_msg = dns.message.from_wire(result_wire)
                        is_negative = response_msg.rcode() in (
                            dns.rcode.NXDOMAIN,
                            dns.rcode.REFUSED,
                        )
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception as e:
                        logger.debug("Plain DNS 缓存写入异常: %s", e)

            elapsed = asyncio.get_event_loop().time() - start_time
            await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)

        except dns.exception.DNSException as e:
            logger.debug("DNS 解析错误: %s", e)
        except Exception as e:
            logger.error("处理 DNS 查询异常: %s", e)

    def _send_raw_response(self, data: bytes, addr: tuple,
                            transport: Optional[asyncio.DatagramTransport] = None):
        """发送 DNS 响应"""
        t = transport or self._transport_v4 or self._transport_v6
        if t is None or t.is_closing():
            return
        try:
            t.sendto(data, addr)
        except Exception as e:
            logger.warning("发送 UDP 响应失败: %s", e)

    async def _log_query(self, client_ip, domain, qtype, elapsed, status, block_reason):
        """记录查询日志"""
        try:
            await self.request_logger.log(
                client_ip=client_ip,
                domain=domain,
                qtype=qtype,
                response_time=elapsed,
                status=status,
                upstream="",
                block_reason=block_reason,
            )
        except Exception as e:
            logger.debug("Plain DNS 查询日志记录异常: %s", e)

    # ======================== 启动 / 停止 ========================

    async def start(self):
        """启动 DNS 服务器（UDP 53，默认关闭）"""
        if not self.enabled:
            logger.info("普通 DNS 服务器 (UDP 53) 已关闭（可在配置中启用）")
            return

        loop = asyncio.get_running_loop()

        try:
            transport_v4, protocol_v4 = await loop.create_datagram_endpoint(
                lambda: self._DnsProtocol(self),
                local_addr=(self.host, self.port),
            )
            self._transport_v4 = transport_v4
            logger.info("普通 DNS [IPv4] udp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [IPv4] 启动失败: %s", e)

        # IPv6
        if self.ipv6_enabled:
            try:
                transport_v6, protocol_v6 = await loop.create_datagram_endpoint(
                    lambda: self._DnsProtocol(self),
                    local_addr=(self.ipv6_host, self.port),
                )
                self._transport_v6 = transport_v6
                logger.info("普通 DNS [IPv6] udp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [IPv6] 启动失败: %s", e)

        self._running = True

        # 启动单 IP 限速清理任务
        self._ip_semaphore_task = asyncio.create_task(self._cleanup_stale_per_ip_semaphores())

    async def stop(self):
        """停止 DNS 服务器"""
        self._running = False
        if self._ip_semaphore_task:
            self._ip_semaphore_task.cancel()
            try:
                await self._ip_semaphore_task
            except asyncio.CancelledError:
                pass
            self._ip_semaphore_task = None
        for transport in [self._transport_v4, self._transport_v6]:
            if transport and not transport.is_closing():
                try:
                    transport.close()
                except Exception as e:
                    logger.debug("Plain DNS 传输关闭异常: %s", e)
        self._transport_v4 = None
        self._transport_v6 = None
        logger.info("普通 DNS 服务器已停止")

    async def restart(self):
        """重启普通 DNS 服务器（IP 切换后恢复监听）"""
        await self.stop()
        await self.start()

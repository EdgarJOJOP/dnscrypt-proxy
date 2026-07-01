"""
本地纯 DNS 服务器（UDP 53 端口 + TCP 53 端口）
- 不加密的 DNS 协议，用于局域网客户端
- 支持 IPv4 + IPv6 双栈
- 默认关闭，需在配置中手动开启
- TCP 支持用于 nginx stream DoT 反代转发
"""

import asyncio
import logging
import time
import struct
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
    """纯 DNS 服务器（UDP 53 + TCP 53 端口，默认关闭）"""

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

        # UDP transport
        self._transport_v4: Optional[asyncio.DatagramTransport] = None
        self._transport_v6: Optional[asyncio.DatagramTransport] = None
        # TCP server
        self._tcp_server_v4: Optional[asyncio.AbstractServer] = None
        self._tcp_server_v6: Optional[asyncio.AbstractServer] = None
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
        """DNS 查询处理核心逻辑（UDP 版：发送响应后返回 None）"""
        result = await self._resolve_and_respond(data, addr, client_ip)
        if result is not None:
            self._send_raw_response(result, addr, transport)

    # ======================== TCP 协议 ========================

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理 TCP DNS 查询（RFC 1035 §4.2.2：2 字节长度前缀 + DNS 消息）"""
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "unknown"
        try:
            while True:
                # 读取 2 字节长度前缀（带 30s 超时防慢速 Loris 攻击）
                length_bytes = await asyncio.wait_for(
                    reader.readexactly(2), timeout=30.0
                )
                length = struct.unpack('!H', length_bytes)[0]
                if length == 0:
                    break
                if length < 12:
                    logger.warning("TCP DNS 消息长度 %d 过短（最小 12）", length)
                    break
                data = await asyncio.wait_for(
                    reader.readexactly(length), timeout=30.0
                )

                # 并发控制 + 限速（复用 UDP 的 _process_query 逻辑，但改为 TCP 发送）
                if not self._is_localhost(client_ip):
                    sem = await self._get_per_ip_semaphore(client_ip)
                    async with sem:
                        async with self._concurrency_semaphore:
                            result_wire = await self._resolve_and_respond(data, peer, client_ip)
                else:
                    async with self._concurrency_semaphore:
                        result_wire = await self._resolve_and_respond(data, peer, client_ip)

                if result_wire:
                    # TCP DNS 响应：2 字节长度前缀 + DNS 消息
                    writer.write(struct.pack('!H', len(result_wire)) + result_wire)
                    await writer.drain()
        except asyncio.TimeoutError:
            logger.debug("TCP DNS 读取超时，关闭连接")
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("TCP DNS 连接异常: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ======================== 核心解析逻辑（UDP/TCP 共用） ========================

    async def _resolve_and_respond(self, data: bytes, addr: tuple,
                                    client_ip: str) -> Optional[bytes]:
        """
        DNS 查询解析核心逻辑。
        返回响应 wire bytes（发送由调用方决定）。
        返回 None 表示不需要发送响应（例如空查询）。
        """
        qname = ""
        qtype_str = ""
        status = "ok"
        block_reason = ""
        result_wire: Optional[bytes] = None
        start_time = asyncio.get_event_loop().time()

        try:
            # 解析 DNS 查询
            query = dns.message.from_wire(data)
            if not query.question:
                return b""

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
                    result_wire = response.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, "custom_hosts", "")
                    return result_wire

            # 1. 检查域名过滤
            if self.config.filter_enabled:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    block_reason = reason
                    status = "blocked"
                    response = dns.message.make_response(query)
                    if question.rdtype == dns.rdatatype.A:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.A)
                        )
                        response.answer[0].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0"), ttl=3600)  # nosec B104
                        response.set_rcode(dns.rcode.NOERROR)
                    elif question.rdtype == dns.rdatatype.AAAA:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                        )
                        response.answer[0].add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, "::"), ttl=3600)
                        response.set_rcode(dns.rcode.NOERROR)
                    else:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    result_wire = response.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)
                    return result_wire

            # 2. 检查缓存
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    cached.id = query.id  # 修复DNS ID不匹配
                    result_wire = cached.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, qtype_str, elapsed, "cached", ""
                    )
                    return result_wire

            # 3. 上游并行查询
            result_wire = await self.resolver_manager.resolve(data)

            if result_wire is None:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                result_wire = response.to_wire()
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
                        result_wire = response.to_wire()
                        status = "dnssec_bogus"
                    else:
                        status = "resolved"
                else:
                    status = "resolved"

                # 缓存结果
                if self.config.cache_enabled and status == "resolved" and result_wire is not None:
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
            return result_wire

        except dns.exception.DNSException as e:
            logger.debug("DNS 解析错误: %s", e)
            return None
        except Exception as e:
            logger.error("处理 DNS 查询异常: %s", e)
            return None

    def _send_raw_response(self, data: bytes, addr: tuple,
                            transport: Optional[asyncio.DatagramTransport] = None):
        """发送 UDP DNS 响应"""
        if not data:
            return
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
        """启动 DNS 服务器（UDP 53 + TCP 53，默认关闭）"""
        if not self.enabled:
            logger.info("普通 DNS 服务器 (UDP/TCP 53) 已关闭（可在配置中启用）")
            return

        loop = asyncio.get_running_loop()

        # ---------- UDP ----------
        try:
            transport_v4, protocol_v4 = await loop.create_datagram_endpoint(
                lambda: self._DnsProtocol(self),
                local_addr=(self.host, self.port),
            )
            self._transport_v4 = transport_v4
            logger.info("普通 DNS [UDP IPv4] udp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [UDP IPv4] 启动失败: %s", e)

        if self.ipv6_enabled:
            try:
                transport_v6, protocol_v6 = await loop.create_datagram_endpoint(
                    lambda: self._DnsProtocol(self),
                    local_addr=(self.ipv6_host, self.port),
                )
                self._transport_v6 = transport_v6
                logger.info("普通 DNS [UDP IPv6] udp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [UDP IPv6] 启动失败: %s", e)

        # ---------- TCP ----------
        try:
            self._tcp_server_v4 = await asyncio.start_server(
                self._handle_tcp_connection, self.host, self.port
            )
            logger.info("普通 DNS [TCP IPv4] tcp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [TCP IPv4] 启动失败: %s", e)

        if self.ipv6_enabled:
            try:
                self._tcp_server_v6 = await asyncio.start_server(
                    self._handle_tcp_connection, self.ipv6_host, self.port
                )
                logger.info("普通 DNS [TCP IPv6] tcp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [TCP IPv6] 启动失败: %s", e)

        self._running = True

        # 启动单 IP 限速清理任务
        self._ip_semaphore_task = asyncio.create_task(self._cleanup_stale_per_ip_semaphores())

    async def stop(self):
        """停止 DNS 服务器（UDP + TCP）"""
        self._running = False
        if self._ip_semaphore_task:
            self._ip_semaphore_task.cancel()
            try:
                await self._ip_semaphore_task
            except asyncio.CancelledError:
                pass
            self._ip_semaphore_task = None

        # 关闭 UDP transport
        for transport in [self._transport_v4, self._transport_v6]:
            if transport and not transport.is_closing():
                try:
                    transport.close()
                except Exception as e:
                    logger.debug("Plain DNS 传输关闭异常: %s", e)
        self._transport_v4 = None
        self._transport_v6 = None

        # 关闭 TCP server
        for tcp_server in [self._tcp_server_v4, self._tcp_server_v6]:
            if tcp_server:
                try:
                    tcp_server.close()
                    await tcp_server.wait_closed()
                except Exception as e:
                    logger.debug("Plain DNS TCP server 关闭异常: %s", e)
        self._tcp_server_v4 = None
        self._tcp_server_v6 = None

        logger.info("普通 DNS 服务器已停止")

    async def restart(self):
        """重启普通 DNS 服务器（IP 切换后恢复监听）"""
        await self.stop()
        await self.start()

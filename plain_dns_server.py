"""
本地纯 DNS 服务器（UDP 53 端口 + TCP 53 端口）
- 不加密的 DNS 协议，用于局域网客户端
- 支持 IPv4 + IPv6 双栈
- 默认关闭，需在配置中手动开启
- TCP 支持用于 nginx stream DoT 反代转发
"""

import asyncio
import logging
import socket
import struct
import sys
import time
from typing import Optional, Dict, Tuple, Any, List

import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset
from dns_utils import reorder_answer_aaaa_first, sort_dns_response_wire

from config import Config, DEFAULT_ROOT_SERVERS
from resolver_manager import ResolverManager
from cache import DNSCache
from filter_engine import FilterEngine
from logger import RequestLogger
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from rate_limiter import get_per_ip_limiter

logger = logging.getLogger("dns-proxy.plain-dns")

# DNS 最大 UDP 数据报大小（DNSSEC 建议 1232，传统 512）
MAX_UDP_SIZE = 1232


def _safe_qname(qname: str) -> str:
    """过滤 qname 中非可见 ASCII 字符（security_review MEDIUM-1：
    LAN 客户端可经 qname 注入控制序列/伪造日志行——info 级日志进
    控制台与 proxy.log，须清洗后再记录）"""
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in str(qname))

# 迭代解析起点：IANA 根服务器（复用 config 内置常量，避免重复定义）
ROOT_SERVERS = DEFAULT_ROOT_SERVERS


def answer_set_fingerprint(wire_bytes: bytes) -> str:
    """归一化答案集指纹：仅提取 answer 段 (name, rdtype, rdata) 集合的 SHA-256。

    用于交叉验证的全局确认。与 consistency_verifier 的逐字节指纹不同，
    此处显式忽略 RRSIG、AD 位、TTL 与 rdata 顺序差异——这些是合法可变字段
    （多 IP 顺序、签名轮换窗口、DO 位请求差异），不应导致误报 SERVFAIL。
    rdata 用 to_digestable()（RFC 4034 canonical form），避免 name 类
    rdata（CNAME/MX/NS 等）的大小写差异导致误判不一致。
    """
    import hashlib
    try:
        msg = dns.message.from_wire(wire_bytes)
        items = set()
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            for rd in rrset:
                try:
                    rd_bytes = rd.to_digestable()
                except Exception:
                    rd_bytes = rd.to_text().encode("utf-8", errors="replace")
                items.add((str(rrset.name).lower(), rrset.rdtype, rd_bytes))
        h = hashlib.sha256()
        for item in sorted(items, key=lambda x: (x[0], x[1], x[2])):
            h.update(item[0].encode("utf-8", errors="replace"))
            h.update(b"\x00")
            h.update(str(item[1]).encode())
            h.update(b"\x00")
            h.update(item[2])
            h.update(b"\x00")
        return h.hexdigest()[:16]
    except Exception:
        return "error"


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
        iterative_resolver: Optional["IterativeResolver"] = None,
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

        # 迭代解析器（根→TLD→权威，可选模式）：由 main 层创建并注入，
        # 注册为 ResolverManager 的独立上游（server_type="iterative"），
        # 与 DoH/DoT/DoQ 一起参与并行优选，供全部本地加密 DNS 服务使用。
        # plain DNS 自身统一走 resolver_manager.resolve()，不再单独迭代。
        self.iterative_enabled = config.plain_dns_iterative_enabled
        self.iterative_resolver = iterative_resolver  # Optional[IterativeResolver]
        if self.iterative_resolver is not None:
            logger.info("普通 DNS 迭代解析上游已注入（根→TLD→权威 + DNSSEC 严格验证）")

        # UDP transport
        self._transport_v4: Optional[asyncio.DatagramTransport] = None
        self._transport_v6: Optional[asyncio.DatagramTransport] = None
        # TCP server
        self._tcp_server_v4: Optional[asyncio.AbstractServer] = None
        self._tcp_server_v6: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)
        self._tcp_backlog = config.connection_pool_size  # 从 connection_pool_size 取值（默认 100）

        # 单 IP 限速（共享 PerIPRateLimiter 单例）
        self._per_ip_limiter = get_per_ip_limiter(
            per_ip_limit=config.max_concurrent_per_ip,
        )
        self._per_ip_limit = config.max_concurrent_per_ip
        self._recovering_v4 = False
        self._recovering_v6 = False

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    @staticmethod
    def _create_udp_socket(host: str, port: int, family: int) -> socket.socket:
        """Create UDP socket with SIO_UDP_CONNRESET disabled on Windows."""
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            if sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except (AttributeError, OSError, ValueError):
                    try:
                        sock.ioctl(0x58000001, False)
                    except (AttributeError, OSError, ValueError):
                        pass
            return sock
        except Exception:
            sock.close()
            raise

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        return await self._per_ip_limiter.acquire(client_ip)



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
            """UDP socket error callback - auto-recover on WSAECONNRESET."""
            logger.warning("UDP 错误: %s", exc)
            if sys.platform == "win32" and getattr(exc, 'winerror', None) == 10054:
                asyncio.ensure_future(self.server._recover_udp_transport(self.transport))

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
                    reorder_answer_aaaa_first(response)
                    result_wire = response.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, "custom_hosts", "")
                    return result_wire

            # 0b. 检查自定义 hosts 白名单（纯域名绕过，无自定义IP）
            is_hosts_bypass = self.filter_engine.is_custom_hosts_bypass(qname)

            # 1. 检查域名过滤
            if self.config.filter_enabled and not is_hosts_bypass:
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
                    reorder_answer_aaaa_first(response)
                    result_wire = response.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)
                    return result_wire

            # 2. 检查缓存
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    import copy
                    cached = copy.copy(cached)
                    reorder_answer_aaaa_first(cached)
                    cached.id = query.id  # 修复DNS ID不匹配
                    result_wire = cached.to_wire()
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, qtype_str, elapsed, "cached", ""
                    )
                    return result_wire

            # 3. 上游解析：统一走 resolver_manager——迭代解析（根→TLD→权威）
            #    已由 main 层注册为独立上游（server_type="iterative"），与
            #    DoH/DoT/DoQ 一起并行查询、按延迟优选，最快响应胜出。
            #    （用户要求的"根服务器查询作为上游供全部本地加密 DNS 服务使用"；
            #    DNSSEC 严格验证在迭代器内部完成，加密上游路径由 dnssec_wrapper 验证）
            result_wire = await self.resolver_manager.resolve(data)
            if result_wire is not None:
                status = "resolved"

            if result_wire is None:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                result_wire = response.to_wire()
                status = "error"
            else:
                # DNSSEC 验证（仅加密上游路径需要；迭代路径已在上游内部严格验证。
                # 原 `status != "iterative"` 条件在新架构下恒真——迭代不再由
                # plain_dns 独立执行，保留为直接执行）
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
                if self.config.cache_enabled and status in ("resolved", "iterative") and result_wire is not None:
                    try:
                        response_msg = dns.message.from_wire(result_wire)
                        reorder_answer_aaaa_first(response_msg)
                        is_negative = response_msg.rcode() in (
                            dns.rcode.NXDOMAIN,
                            dns.rcode.REFUSED,
                        )
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception as e:
                        logger.debug("Plain DNS 缓存写入异常: %s", e)

            elapsed = asyncio.get_event_loop().time() - start_time
            await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)
            result_wire = sort_dns_response_wire(result_wire)
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
        if transport is not None and not transport.is_closing():
            t = transport
        else:
            if addr and len(addr) > 0 and ":" in str(addr[0]):
                t = self._transport_v6
            else:
                t = self._transport_v4
        if t is None or t.is_closing():
            return
        try:
            t.sendto(data, addr)
        except Exception as e:
            logger.warning("发送 UDP 响应失败: %s", e)

    async def _recover_udp_transport(self, broken_transport: Optional[asyncio.DatagramTransport]):
        """Recover UDP transport broken by WSAECONNRESET.
        M1: create new before closing old.
        M2: concurrent guard.
        M3: check _running.
        """
        if broken_transport is None or broken_transport.is_closing():
            return
        if not self._running:
            logger.debug("skip recovery: server stopped")
            return
        sock = broken_transport.get_extra_info("socket")
        if sock is None:
            return
        is_v6 = (sock.family == socket.AF_INET6)
        flag = "_recovering_v6" if is_v6 else "_recovering_v4"
        if getattr(self, flag):
            logger.debug("recovery already in progress, skip")
            return
        setattr(self, flag, True)
        try:
            host = self.ipv6_host if is_v6 else self.host
            family = socket.AF_INET6 if is_v6 else socket.AF_INET
            loop = asyncio.get_running_loop()
            new_sock = self._create_udp_socket(host, self.port, family)
            new_transport, _ = await loop.create_datagram_endpoint(
                lambda: self._DnsProtocol(self), sock=new_sock,
            )
            if not self._running:
                new_transport.close()
                logger.debug("recovery cancelled: server stopped")
                return
            if not broken_transport.is_closing():
                try:
                    broken_transport.close()
                except Exception:
                    pass
            if is_v6:
                self._transport_v6 = new_transport
                logger.info("plain DNS [UDP IPv6] transport recovered udp://[%s]:%d", host, self.port)
            else:
                self._transport_v4 = new_transport
                logger.info("plain DNS [UDP IPv4] transport recovered udp://%s:%d", host, self.port)
        except Exception as e:
            logger.warning("plain DNS UDP transport recovery failed: %s", e)
        finally:
            setattr(self, flag, False)

    async def _log_query(self, client_ip, domain, qtype, elapsed, status, block_reason):
        """记录查询日志"""
        try:
            # upstream 记录实际胜出上游（如 iterative/DoH 域名），
            # 供 dns_queries.log 区分迭代解析与加密上游
            _upstream = ""
            try:
                _upstream = self.resolver_manager.last_fast_server or ""
            except Exception:
                pass
            await self.request_logger.log(
                client_ip=client_ip,
                domain=domain,
                qtype=qtype,
                response_time=elapsed,
                status=status,
                upstream=_upstream,
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
            sock_v4 = self._create_udp_socket(self.host, self.port, socket.AF_INET)
            transport_v4, protocol_v4 = await loop.create_datagram_endpoint(
                lambda: self._DnsProtocol(self),
                sock=sock_v4,
            )
            self._transport_v4 = transport_v4
            logger.info("普通 DNS [UDP IPv4] udp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [UDP IPv4] 启动失败: %s", e)

        if self.ipv6_enabled:
            try:
                sock_v6 = self._create_udp_socket(self.ipv6_host, self.port, socket.AF_INET6)
                transport_v6, protocol_v6 = await loop.create_datagram_endpoint(
                    lambda: self._DnsProtocol(self),
                    sock=sock_v6,
                )
                self._transport_v6 = transport_v6
                logger.info("普通 DNS [UDP IPv6] udp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [UDP IPv6] 启动失败: %s", e)

        # ---------- TCP ----------
        try:
            self._tcp_server_v4 = await asyncio.start_server(
                self._handle_tcp_connection, self.host, self.port,
                backlog=self._tcp_backlog,
            )
            logger.info("普通 DNS [TCP IPv4] tcp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [TCP IPv4] 启动失败: %s", e)

        if self.ipv6_enabled:
            try:
                self._tcp_server_v6 = await asyncio.start_server(
                    self._handle_tcp_connection, self.ipv6_host, self.port,
                    backlog=self._tcp_backlog,
                )
                logger.info("普通 DNS [TCP IPv6] tcp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [TCP IPv6] 启动失败: %s", e)

        self._running = True



    async def stop(self):
        """停止 DNS 服务器（UDP + TCP）"""
        self._running = False

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


# ======================== 迭代解析器（根→TLD→权威） ========================

class IterativeResolver:
    """
    本地迭代解析器：不依赖递归服务器，自行执行 根→TLD→权威 查询链。

    数学信任模型：
      1. 起点 = 内置 IANA 根服务器 IP（硬编码信任锚，不经 DNS 解析）
      2. 每跳非递归查询（RD=0）并请求 DNSSEC（DO=1）
      3. 每跳响应收集 RRSIG/DNSKEY/DS，最终调用 DNSSECValidator 严格链验证
         （内置根信任锚 KSK 20326/38696 → 逐级 DNSKEY → 最终答案签名）
      4. 严格模式：验证失败（bogus）→ 丢弃（由上层返回 SERVFAIL）
      5. 交叉验证：与加密上游结果指纹比对（由上层调用）
    即使中间人篡改任一跳响应，RSA/ECDSA 签名验证必然失败 → 可检测。
    """

    def __init__(self, config: Config, dnssec_validator: Optional[DNSSECValidator] = None):
        self.config = config
        self.timeout = float(config.plain_dns_iterative_timeout_ms) / 1000.0
        self.max_depth = int(config.plain_dns_iterative_max_depth)
        self.strict_dnssec = bool(config.plain_dns_iterative_strict_dnssec)
        if not self.strict_dnssec:
            # security_review MEDIUM：strict_dnssec=False 时迭代响应未做 DNSSEC
            # 严格验证即返回（无第二信任源指纹兜底——cross_verify 已随新架构
            # 静默失效），向客户端/缓存放行未验证响应，须显式告警
            logger.warning(
                "迭代解析 strict_dnssec=False：未验证的迭代响应将被放行"
                "（DNSSEC 剥离/投毒检测失效，建议开启 strict_dnssec）",
            )
        # cross_verify：原“迭代 vs 加密上游交叉验证”语义——新架构下迭代解析
        # 作为独立上游与加密上游并行竞争（最快响应胜出），不再需要独立交叉验证；
        # 保留属性与配置读取以兼容（deprecated，无实际调用方）
        self.cross_verify = bool(config.plain_dns_iterative_cross_verify)
        root = config.plain_dns_iterative_root_servers
        self.root_servers = [str(x) for x in root] if root else list(ROOT_SERVERS)
        # A3 修复（IPv6 优先）：探测本机 IPv6 公网连通性（UDP connect 公共 IPv6 根，
        # 仅验证路由可达，不发包），连通时 IPv6 根服务器排前、否则 IPv4 排前——
        # 满足"main.py 运行的机子有 IPv6 且正常联通公网则优先使用 IPv6"要求
        self._has_ipv6 = False
        try:
            _probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                _probe.settimeout(0.5)
                _probe.connect(("2001:7fd::1", 53))  # k.root-servers.net IPv6
                self._has_ipv6 = True
            finally:
                _probe.close()
        except Exception:
            self._has_ipv6 = False
        self.root_servers = sorted(
            self.root_servers,
            key=lambda ip: (0 if ((":" in ip) == self._has_ipv6) else 1, ip),
        )
        logger.info(
            "迭代解析已启用：IPv6优先=%s 根服务器 %d 台 = %s",
            self._has_ipv6, len(self.root_servers), ", ".join(self.root_servers),
        )
        # 总超时预算：整个迭代解析（含各跳重试）不得超过此上限，
        # 防止根服务器部分不可达时串行重试（最多 13 台 × 单跳超时）拖垮单查询。
        # M5 修复：原 timeout*max_depth*2 低估实际耗时——每跳会串行尝试服务器列表
        # （每台 wait_for(timeout+1.0)≈3s，UDP 超时后还 TCP 重试再 timeout），
        # 正常 3 级查询 + DNSSEC 链验证（DNSKEY/DS 多跳）实际可达 20-40s；
        # 预算改为按「每跳最多尝试 3 台」估算：timeout*max_depth + 3*(timeout+1)*max_depth/2
        # （折中：默认 2s*8 + 1.5*3s*8 = 52s，成功路径不再被提前截断，
        #  失败路径仍由 wait_for 兜底避免无限拖垮）
        _per_hop_max = min(3.0, max(1.0, len(self.root_servers) * 0.25))
        self.total_timeout = max(
            15.0,
            self.timeout * self.max_depth
            + (self.timeout + 1.0) * _per_hop_max * self.max_depth * 0.5,
        )
        # 独立 DNSSEC 验证器（内置根信任锚），回调指向迭代解析自身 → 全链自举
        self._dnssec = dnssec_validator or DNSSECValidator(enabled=True, mode="strict")
        try:
            self._dnssec.set_dns_query_callback(self._dnssec_query_callback)
        except Exception:
            pass
        self._stats = {
            "queries": 0, "success": 0, "fail": 0,
            "bogus": 0, "insecure": 0, "secure": 0, "depth_exceeded": 0,
        }
        self._ns_ip_cache: Dict[str, List[str]] = {}
        # 已验证 zone 的 DNSKEY 缓存（避免每域名重复全链迭代流量）
        # 值: (rrset, 失效时间戳)，按缓存条目 TTL 失效，避免 DNSKEY 轮换后旧缓存致 bogus
        self._verified_zone_cache: Dict[str, tuple] = {}

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    # ---------- 单跳查询（同步，to_thread 包装） ----------

    def _query_one(self, server_ip: str, qname: str, qtype: int,
                   rdclass: int = 1) -> Optional[dns.message.Message]:
        """向指定服务器发送非递归查询（RD=0, DO=1），TC 时回退 TCP。"""
        q = dns.message.make_query(qname, qtype, rdclass=rdclass, want_dnssec=True)
        q.flags &= ~dns.flags.RD
        try:
            r = dns.query.udp(q, server_ip, timeout=self.timeout, ignore_unexpected=True)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(q, server_ip, timeout=self.timeout)
            return r
        except Exception:
            return None

    async def _query_servers(self, servers: List[str], qname: str, qtype: int,
                             rdclass: int = 1) -> Optional[dns.message.Message]:
        """串行尝试服务器列表，返回第一个成功响应。"""
        for ip in servers:
            # A2（已降级 debug）：迭代过程日志——需查看时设 DEBUG 级
            logger.debug("迭代查询: 向 %s 查询 %s type=%s",
                         ip, _safe_qname(qname), dns.rdatatype.to_text(qtype))
            try:
                resp = await asyncio.wait_for(
                    asyncio.to_thread(self._query_one, ip, qname, qtype, rdclass),
                    timeout=self.timeout + 1.0,
                )
                if resp is not None:
                    logger.debug(
                        "迭代查询: %s 响应 %s (rcode=%s, answer=%d, authority=%d)",
                        ip, _safe_qname(qname), dns.rcode.to_text(resp.rcode()),
                        len(resp.answer), len(resp.authority),
                    )
                    return resp
            except Exception:
                logger.debug("迭代查询: %s 查询 %s 超时/失败，尝试下一台", ip, _safe_qname(qname))
                continue
        return None

    # ---------- 下一跳服务器提取 ----------

    async def _extract_next_servers(self, response) -> List[str]:
        """从 authority NS + additional glue 提取下一级服务器 IP。
        无 glue 的 NS 名称在 _resolve_ns_ip 中迭代解析。"""
        ns_names = []
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rdata in rrset:
                    ns_names.append(str(rdata.target))
        glue: Dict[str, List[str]] = {}
        for rrset in response.additional:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                for rdata in rrset:
                    glue.setdefault(str(rrset.name).lower(), []).append(rdata.address)
        servers: List[str] = []
        for ns in ns_names:
            ips = glue.get(ns.lower())
            if not ips:
                # M3 修复：读取带 TTL 的 NS IP 缓存（值 = (ips, expire_at)）
                _cached = self._ns_ip_cache.get(ns.lower())
                if _cached:
                    _cached_ips, _expire_at = _cached
                    if time.time() < _expire_at:
                        ips = _cached_ips
            if not ips:
                ips = await self._resolve_ns_ip(ns)
            servers.extend(ips)
        # 去重保序
        seen = set()
        uniq = []
        for ip in servers:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        return uniq

    async def _resolve_ns_ip(self, ns_name: str, depth: int = 0) -> List[str]:
        """对无 glue 的 NS 名称迭代解析其 A/AAAA（子问题，从根开始）。"""
        if depth >= self.max_depth:
            return []
        # M3 修复：NS IP 缓存带 TTL（默认 300s），避免 NS 换 IP（CDN/云权威常见）
        # 后长期使用旧地址——与 _verified_zone_cache 按 TTL 失效的设计对齐
        cached = self._ns_ip_cache.get(ns_name.lower())
        if cached:
            ips_cached, expire_at = cached
            if time.time() < expire_at:
                return list(ips_cached)
            self._ns_ip_cache.pop(ns_name.lower(), None)
        ips: List[str] = []
        resp = await self._iterate(ns_name, dns.rdatatype.A, depth + 1)
        if resp is not None:
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    for rdata in rrset:
                        ips.append(rdata.address)
        # 缓存 TTL：取 A rrset 的 TTL（若响应含），至少 60s，最长 86400s；
        # 空结果也缓存短 TTL（60s），避免失败路径每查询重复全链迭代
        ttl = 300.0
        try:
            if resp is not None:
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.A and rrset.ttl:
                        ttl = max(60.0, min(float(rrset.ttl), 86400.0))
                        break
        except Exception:
            ttl = 60.0 if not ips else 300.0
        if not ips:
            ttl = 60.0
        self._ns_ip_cache[ns_name.lower()] = (ips, time.time() + ttl)
        if len(self._ns_ip_cache) > 1024:
            self._ns_ip_cache.clear()
        return ips

    def _extract_cname(self, response, expected_owner: Optional[str] = None) -> Optional[str]:
        """提取 answer 段 CNAME 目标（若有）。

        安全约束：CNAME 记录的 owner 必须等于被查询名（expected_owner）。
        MITM 注入任意真实签名 CNAME（owner 不匹配）诱导跟随会被忽略——
        防止攻击者把查询 X 重定向到攻击者选择的目标 T 的 IP。
        """
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.CNAME:
                continue
            # owner 校验：CNAME 必须属于被查询名
            if expected_owner is not None:
                try:
                    if str(rrset.name).rstrip(".").lower() != expected_owner.rstrip(".").lower():
                        continue  # 注入的 CNAME（owner 不匹配）→ 忽略
                except Exception:
                    continue
            for rdata in rrset:
                return str(rdata.target)
        return None

    # ---------- 主迭代循环 ----------

    async def _iterate(self, qname: str, qtype: int, depth: int = 0,
                       rdclass: int = 1) -> Optional[dns.message.Message]:
        """迭代解析主循环：根→TLD→权威，返回最终响应。"""
        if depth >= self.max_depth:
            self._stats["depth_exceeded"] += 1
            return None
        original_qname = qname  # CNAME 跟随会改变 qname，需在返回时复原 question
        servers: List[str] = list(self.root_servers)
        cname_targets: List[str] = []
        cname_chain: List[bytes] = []  # 中间跳 CNAME 响应 wire（供上层验签，防 target 篡改）
        for _hop in range(self.max_depth - depth):
            # A2（已降级 debug）：每跳过程日志——需查看时设 DEBUG 级
            logger.debug("迭代解析 [跳%d/%d]: %s %s 候选服务器 %d 台",
                         _hop + 1, self.max_depth, _safe_qname(qname),
                         dns.rdatatype.to_text(qtype), len(servers))
            response = await self._query_servers(servers, qname, qtype, rdclass)
            if response is None:
                return None
            # 1. answer 段含目标类型 → 完成（返回前复原 question 为原始 qname）
            if any(rrset.rdtype == qtype for rrset in response.answer):
                try:
                    if response.question and \
                       str(response.question[0].name).rstrip(".") != original_qname.rstrip("."):
                        response.question = [dns.rrset.RRset(
                            dns.name.from_text(original_qname),
                            response.question[0].rdclass, response.question[0].rdtype,
                        )]
                    # 保存 CNAME 链所有目标与中间跳响应，供上层 owner 校验与验签
                    response._cname_targets = list(cname_targets)
                    response._cname_chain = list(cname_chain)
                except Exception:
                    pass
                return response
            # 2. NXDOMAIN / 其他错误码 → 返回（负应答）
            if response.rcode() == dns.rcode.NXDOMAIN:
                return response
            # 2b. 权威负应答（NODATA）：authority 段有 SOA（zone 权威的否定应答），
            #     无 NS referral → 直接返回，避免 _extract_next_servers 死循环
            #     注意：answer 可能含 CNAME + authority NSEC（RFC 4035 §5.2 同响应
            #     CNAME→NODATA）——早退前需填充 _cname_targets 供上层验证
            has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)
            has_ns_ref = any(rrset.rdtype == dns.rdatatype.NS for rrset in response.authority)
            if has_soa and not has_ns_ref:
                # 若 answer 含 CNAME（目标类型缺失的 NODATA），记录 target
                cname_local = self._extract_cname(response, expected_owner=qname)
                if cname_local is not None and cname_local not in cname_targets:
                    cname_targets.append(cname_local)
                    try:
                        cname_chain.append(response.to_wire())
                    except Exception:
                        pass
                try:
                    response._cname_targets = list(cname_targets)
                    response._cname_chain = list(cname_chain)
                except Exception:
                    pass
                return response
            # 3. CNAME 链（最多跟随 8 跳）——owner 必须等于当前 qname（防注入）
            cname = self._extract_cname(response, expected_owner=qname)
            if cname is not None:
                cname_targets.append(cname)
                try:
                    cname_chain.append(response.to_wire())  # 保存供上层验签
                except Exception:
                    pass
                if len(cname_targets) > 8:
                    return None
                qname = str(cname)
                servers = list(self.root_servers)
                continue
            # 4. referral：authority NS → 下一级
            next_servers = await self._extract_next_servers(response)
            if not next_servers:
                return None
            servers = next_servers
        return None

    # ---------- DNSSEC 验证回调（全链自举） ----------

    @staticmethod
    def _extract_dnskey_rrset(msg) -> Optional[dns.rrset.RRset]:
        """提取响应 answer 段中的 DNSKEY RRset（若存在多个取第一个）。"""
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                return rrset
        return None

    @staticmethod
    def _ds_matches_key(ds_rdata, zone_name: dns.name.Name, dnskey_rdata) -> bool:
        """RFC 4034 §5.1.4：计算 DNSKEY 的 DS digest 并与 DS 记录比对。
        digest = hash( canonical_owner_wire || DNSKEY_rdata_wire )"""
        try:
            import hashlib
            owner_wire = zone_name.to_wire(canonicalize=True)
            key_wire = dnskey_rdata.to_wire()
            if ds_rdata.digest_type == 1:      # SHA-1
                digest = hashlib.sha1(owner_wire + key_wire).digest()
            elif ds_rdata.digest_type == 2:    # SHA-256
                digest = hashlib.sha256(owner_wire + key_wire).digest()
            elif ds_rdata.digest_type == 4:    # SHA-384
                digest = hashlib.sha384(owner_wire + key_wire).digest()
            else:
                return False
            return digest == ds_rdata.digest
        except Exception:
            return False

    @staticmethod
    def _find_rrsig_for(msg, rrset) -> Optional[dns.rrset.RRset]:
        """按 covers 查找 rrset 对应的 RRSIG（dnspython 2.x 要求），
        同时搜索 answer 与 authority 段。"""
        for section in (msg.answer, msg.authority):
            try:
                return msg.find_rrset(
                    section, rrset.name, rrset.rdclass,
                    dns.rdatatype.RRSIG, covers=rrset.rdtype, create=False,
                )
            except KeyError:
                continue
        return None

    async def _get_trusted_dnskey(self, zone_name: dns.name.Name) -> Optional[dns.rrset.RRset]:
        """从内置 IANA 根信任锚出发，沿 DS→DNSKEY 链逐级数学验证，
        返回 zone 的已信任 DNSKEY RRset；任一级验证失败返回 None。

        信任链（RFC 4035）：
          根锚 KSK → 验证根区 DNSKEY（含 ZSK）→ ZSK 验证 TLD 的 DS 签名
          → DS digest 匹配 TLD DNSKEY → TLD ZSK 验证子域 DS → ... → zone DNSKEY
        中间人即使伪造 DNSKEY/DS 响应，没有父区私钥就无法通过签名验证。
        """
        if zone_name == dns.name.root:
            return None  # 根区 DNSKEY 由内置信任锚提供，不走此链
        # 缓存命中：已验证过的 zone 直接返回（TTL 未过期），避免重复全链迭代流量
        cached = self._verified_zone_cache.get(str(zone_name).lower())
        if cached is not None:
            rrset, expire_at = cached
            if time.time() < expire_at:
                return rrset
            self._verified_zone_cache.pop(str(zone_name).lower(), None)
        # 1. 根锚 KSK → RRset 格式（dnspython dns.dnssec 要求）
        trusted: Dict = {}
        for root_name, alg_map in self._dnssec._root_keys.items():
            root_rrset = dns.rrset.RRset(root_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            if isinstance(alg_map, dict):
                for rdata_list in alg_map.values():
                    for rd in rdata_list:
                        root_rrset.add(rd)
            else:
                for rd in alg_map:
                    root_rrset.add(rd)
            trusted[root_name] = root_rrset

        # 2. 查询根区 DNSKEY（含 KSK+ZSK），用根锚 KSK 验证其 RRSIG → 得到完整根密钥
        root_dnskey_resp = await self._iterate(".", dns.rdatatype.DNSKEY, 0)
        if root_dnskey_resp is None:
            return None
        root_dnskey_rrset = self._extract_dnskey_rrset(root_dnskey_resp)
        if root_dnskey_rrset is None:
            return None
        root_rrsig = self._find_rrsig_for(root_dnskey_resp, root_dnskey_rrset)
        if root_rrsig is None:
            return None
        try:
            dns.dnssec.validate(root_dnskey_rrset, root_rrsig, trusted)
        except (dns.dnssec.ValidationFailure, KeyError) as e:
            logger.warning("DNSSEC 根区 DNSKEY 验证失败: %s", e)
            return None
        trusted[dns.name.root] = root_dnskey_rrset  # 含 ZSK，供后续验证子区 DS

        # 3. 逐级向下的祖先路径：TLD → ... → zone
        path = []
        n = zone_name
        while n != dns.name.root:
            path.append(n)
            n = n.parent()
        path.reverse()

        for cur_zone in path:
            # 3a. 查询 cur_zone 的 DS（由父区权威持有，父区 ZSK 签名）
            ds_resp = await self._iterate(str(cur_zone), dns.rdatatype.DS, 0)
            if ds_resp is None:
                return None
            ds_rrset = None
            for rrset in ds_resp.answer:
                if rrset.rdtype == dns.rdatatype.DS:
                    ds_rrset = rrset
                    break
            if ds_rrset is None:
                return None  # 无 DS（insecure 委托）→ 严格模式拒绝
            rrsig_set = self._find_rrsig_for(ds_resp, ds_rrset)
            if rrsig_set is None:
                return None
            try:
                dns.dnssec.validate(ds_rrset, rrsig_set, trusted)
            except (dns.dnssec.ValidationFailure, KeyError) as e:
                logger.warning("DNSSEC DS 验证失败 %s: %s", cur_zone, e)
                return None
            # 3b. 查询 cur_zone 的 DNSKEY
            dnskey_resp = await self._iterate(str(cur_zone), dns.rdatatype.DNSKEY, 0)
            if dnskey_resp is None:
                return None
            dnskey_rrset = self._extract_dnskey_rrset(dnskey_resp)
            if dnskey_rrset is None:
                return None
            # 3c. 用已验证 DS 的 digest 匹配 DNSKEY，找到父区授权的 KSK
            auth_ksk = None
            for ds in ds_rrset:
                for key_rdata in dnskey_rrset:
                    if self._ds_matches_key(ds, cur_zone, key_rdata):
                        auth_ksk = key_rdata
                        break
                if auth_ksk is not None:
                    break
            if auth_ksk is None:
                logger.warning("DNSSEC DS/DNSKEY digest 不匹配: %s（伪造 DNSKEY 被拦截）", cur_zone)
                return None
            # 3d. 用父区授权的 KSK 验证 DNSKEY rrset 自身的 RRSIG（signer=cur_zone，
            #     ZSK 与 KSK 一起签名）→ 证明该 DNSKEY 集合完整可信（含 ZSK）
            dnskey_rrsig = self._find_rrsig_for(dnskey_resp, dnskey_rrset)
            if dnskey_rrsig is None:
                return None
            ksk_rrset = dns.rrset.RRset(cur_zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            ksk_rrset.add(auth_ksk)
            try:
                dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {cur_zone: ksk_rrset})
            except (dns.dnssec.ValidationFailure, KeyError) as e:
                logger.warning("DNSSEC DNSKEY 自签验证失败 %s: %s", cur_zone, e)
                return None
            # 3e. 该级验证通过 → 信任整个 DNSKEY rrset（含 ZSK），作为下一级的信任来源
            trusted[cur_zone] = dnskey_rrset

        # 缓存已验证 zone 的 DNSKEY（有界：超 512 条清空，避免内存膨胀；
        # 失效时间 = 当前时间 + DNSKEY rrset TTL，DNSKEY 轮换后自动重新验证）
        if len(self._verified_zone_cache) > 512:
            self._verified_zone_cache.clear()
        ttl = getattr(dnskey_rrset, "ttl", 3600) or 3600
        self._verified_zone_cache[str(zone_name).lower()] = (dnskey_rrset, time.time() + ttl)
        return dnskey_rrset

    async def _dnssec_query_callback(self, query_bytes: bytes) -> Optional[bytes]:
        """DNSSECValidator 的 DNSKEY 查询回调：迭代查询 DNSKEY 并做 DS 链验证。
        仅返回经过数学信任链验证的 DNSKEY 响应（防止伪造 DNSKEY + 重签名绕过）。"""
        try:
            msg = dns.message.from_wire(query_bytes)
            if not msg.question:
                return None
            q = msg.question[0]
            zone = q.name
            # 链验证获取可信 DNSKEY（若已缓存直接命中）
            verified_rrset = await self._get_trusted_dnskey(zone)
            if verified_rrset is None:
                logger.warning("DNSSEC 链验证失败，拒绝信任 %s 的 DNSKEY", zone)
                return None
            # 构造仅含已验证 DNSKEY 的响应返回
            resp = dns.message.make_response(msg)
            resp.flags |= dns.flags.AD
            resp.answer.append(verified_rrset)
            return resp.to_wire()
        except Exception:
            return None

    # ---------- 公开入口 ----------

    @staticmethod
    def _nsec_has_type(nsec_rdata, rdtype: int) -> bool:
        """检查 NSEC/NSEC3 rdata 的类型位图是否包含指定类型。

        NSEC（RFC 4034 §4.1.2）：windows 属性是标准 (window, bitmap) 位图。
        NSEC3（RFC 5155 §3.2）：windows 属性格式不同，改用 to_text 解析
        类型列表（to_text 输出的尾部是类型助记符，权威可靠）。
        """
        try:
            from dns.rdtypes.ANY.NSEC3 import NSEC3 as NSEC3Cls
            if isinstance(nsec_rdata, NSEC3Cls):
                txt = nsec_rdata.to_text()
                parts = txt.split()
                # NSEC3 to_text 格式: algorithm iterations flags salt next [types]
                # 前 5 个字段（algorithm/iterations/flags/salt/next-hash）是数字或
                # hash 文本，可能被 from_text 误解析为类型码（algorithm=1→A）。
                # 跳过前 5 个字段，仅从第 6 个起解析类型助记符。
                parsed_any = False
                for p in parts[5:]:
                    try:
                        parsed_any = True
                        if dns.rdatatype.from_text(p) == rdtype:
                            return True
                    except Exception:
                        continue
                # 类型列表非空且不含目标类型 → 位图明确无该类型，返回 False。
                # 仅类型列表为空（NSEC3 最小记录，无类型字段）才隐含 NS+NSEC3。
                if parsed_any:
                    return False
                # NSEC3 最小记录（RFC 5155 §3.2.1）：默认类型 = NS + RRSIG + NSEC3
                return rdtype in (dns.rdatatype.NS, dns.rdatatype.RRSIG,
                                  dns.rdatatype.NSEC3)
            # NSEC：标准位图
            for window, bitmap in nsec_rdata.windows:
                if rdtype // 256 == window:
                    byte = rdtype % 256 // 8
                    bit = 0x80 >> (rdtype % 8)
                    return bool(bitmap[byte] & bit) if byte < len(bitmap) else False
        except Exception:
            return False
        return False

    @staticmethod
    def _nsec3_hash(name: dns.name.Name, salt: bytes, iterations: int,
                    algorithm: int) -> bytes:
        """RFC 5155 §5 NSEC3 hash 计算：SHA-1 迭代（algorithm=1）。
        owner name 用 canonical wire（RFC 4034 §6.2 小写形式）——
        大小写混合 qname 的 hash 才能与权威一致。"""
        import hashlib
        if algorithm != 1:
            return b""
        h = name.to_wire(canonicalize=True)
        try:
            for _ in range(iterations + 1):
                h = hashlib.sha1(h + salt).digest()
            return h
        except Exception:
            return b""

    @staticmethod
    def _nsec3_owner_hash(nsec3_owner: dns.name.Name) -> bytes:
        """NSEC3 owner name 的 hash bytes：owner 是 base32hex（RFC 4648）编码的
        单 label（可能带 .zone 后缀），取第一个 label 解码。"""
        import base64
        try:
            label = str(nsec3_owner).split(".")[0].upper()
            # base32hex: 0-9A-V，标准 base32 是 A-Z2-7 → 转换
            table = str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV",
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            b32 = label.translate(table)
            pad = "=" * ((8 - len(b32) % 8) % 8)
            return base64.b32decode(b32 + pad)
        except Exception:
            return b""

    @staticmethod
    def _nsec_proves_no_type(nsec_rdata, nsec_owner: dns.name.Name,
                             target: dns.name.Name, rdtype: int) -> bool:
        """NSEC 是否证明 target 无指定类型 rdtype（NODATA 否定语义，RFC 4034 §4.1.1）：
        - NSEC owner 必须等于被查名 target（NODATA 场景）
        - 类型位图必须不含 rdtype（查询类型——防攻击者用位图含 A 的 NSEC
          重放为 NODATA 吞掉真实 A 记录）
        防止重放父区公开有效 NSEC（签名有效但语义不符）伪造 insecure/NODATA。
        """
        try:
            if nsec_owner != target:
                return False
            return not IterativeResolver._nsec_has_type(nsec_rdata, rdtype)
        except Exception:
            return False

    @staticmethod
    def _nsec_proves_no_ds(nsec_rdata, nsec_owner: dns.name.Name,
                           target: dns.name.Name) -> bool:
        """NSEC 是否证明 target 无 DS（委托无 DS 语义）——_nsec_proves_no_type 的特例。"""
        return IterativeResolver._nsec_proves_no_type(
            nsec_rdata, nsec_owner, target, dns.rdatatype.DS)

    @staticmethod
    def _nsec_covers(nsec_rdata, nsec_owner: dns.name.Name,
                     target: dns.name.Name) -> bool:
        """NSEC 是否覆盖 target（NXDOMAIN 纯区间语义，RFC 4034 §4.1.1）：
        owner < target < next（canonical 序）。注意：owner==target 时 NSEC 存在
        本身证明 target 存在（NODATA 语义），不属于 NXDOMAIN 覆盖——必须为 False，
        否则重放 owner==qname 的真实 NSEC 可让真实存在的域名被判 NXDOMAIN。
        """
        try:
            nxt = nsec_rdata.next
            if nsec_owner == target:
                return False  # NSEC 存在 → target 存在，非 NXDOMAIN 证明
            if target == nxt:
                return False  # next 是链首存在名 → target 存在，非 NXDOMAIN 证明
            if nsec_owner < target < nxt:
                return True
            # 回绕（owner 是排序末尾，next 是排序开头）
            if nxt <= nsec_owner:
                if nxt == nsec_owner:
                    return False  # 自指记录（单名 zone）不覆盖任何名字
                return target > nsec_owner or target < nxt
            return False
        except Exception:
            return False

    @staticmethod
    def _nsec3_proves_no_ds(nsec3_rdata, owner_hash: bytes, target: dns.name.Name) -> bool:
        """NSEC3 是否证明 target 无 DS（RFC 5155 §8.4 语义）：
        - 计算 target 的 NSEC3 hash
        - hash 必须落在 [owner_hash, next_hash) 区间（或回绕）
        - 类型位图不含 DS（43）
        防止重放父区公开有效 NSEC3 伪造 insecure。
        """
        return IterativeResolver._nsec3_proves_no_type(
            nsec3_rdata, owner_hash, target, dns.rdatatype.DS)

    @staticmethod
    def _nsec3_interval_check(target_hash: bytes, owner_hash: bytes,
                              next_hash: bytes) -> bool:
        """NSEC3 区间覆盖检查（RFC 5155 §8.4）：
        target_hash 落在 (owner_hash, next_hash) 开区间（或回绕）为覆盖。

        边界语义（安全关键）：
        - target_hash == owner_hash：不覆盖（owner 存在，是链中真实名字）
        - target_hash == next_hash：不覆盖！next_hash 恰是下一条 NSEC3 记录的
          owner → target 真实存在，不能证明其不存在（闭区间可重放前驱 NSEC3
          让真实存在域名判 NXDOMAIN、并让 secure 委托判 insecure 绕过 DNSSEC）
        与 NSEC 分支 _nsec_covers（owner < target < next）保持一致。
        """
        try:
            if target_hash == owner_hash:
                return False
            if target_hash == next_hash:
                return False  # next 是下一条记录的 owner → 存在
            if owner_hash < next_hash:
                return owner_hash < target_hash < next_hash
            # 回绕：target 落在 (owner, 末尾) 或 (开头, next)
            if next_hash == owner_hash:
                return False  # 自指记录（单名 zone）不覆盖任何 hash
            return target_hash > owner_hash or target_hash < next_hash
        except Exception:
            return False

    @staticmethod
    def _nsec3_optout(nsec3_rdata) -> bool:
        """NSEC3 opt-out 位检查（RFC 5155 §3.1.2.1：flags 第二位）。
        opt-out 设置的 NSEC3 区间覆盖证明不可靠（opt-out 子区无 NSEC3 记录、
        位图无 NS/DS 标记）——RFC 5155 §8.4-§8.8 要求拒绝其覆盖证明。"""
        try:
            return bool(getattr(nsec3_rdata, "flags", 0) & 0x01)
        except Exception:
            return False

    @staticmethod
    def _nsec3_proves_no_type(nsec3_rdata, owner_hash: bytes,
                              target: dns.name.Name, rdtype: int) -> bool:
        """NSEC3 是否证明 target 无指定类型 rdtype（RFC 5155 §8.4 NODATA 语义）：
        - hash 落在 (owner_hash, next_hash] 区间（或回绕）——注意 owner 本身
          存在（其 hash 对应真实名字），target_hash == owner_hash 必须 False，
          与 NSEC 的 owner==target 同理；next_hash 是闭边界
        - 类型位图不含 rdtype（查询类型——防位图含 A 的 NSEC3 重放吞真实 A）
        """
        try:
            target_hash = IterativeResolver._nsec3_hash(
                target, nsec3_rdata.salt, nsec3_rdata.iterations,
                nsec3_rdata.algorithm,
            )
            if not target_hash:
                return False
            next_hash = nsec3_rdata.next  # 原始 bytes
            # NODATA 语义（RFC 5155 §8.5）：target == owner → 该名字存在，
            # 位图不含 rdtype 即证明 NODATA；target 落在开区间 → 不存在（NXDOMAIN）
            if target_hash == owner_hash:
                return not IterativeResolver._nsec_has_type(nsec3_rdata, rdtype)
            # RFC 5155 §8.4-8.8：opt-out 位（flags & 0x01）设置的 NSEC3 区间覆盖
            # 证明不可靠（opt-out 子区无 NSEC3 记录）——保守拒绝
            if getattr(nsec3_rdata, "flags", 0) & 0x01:
                return False
            covered = IterativeResolver._nsec3_interval_check(
                target_hash, owner_hash, next_hash)
            return covered and not IterativeResolver._nsec_has_type(
                nsec3_rdata, rdtype)
        except Exception:
            return False

    async def _zone_signed_status(self, zone_name: dns.name.Name) -> str:
        """判定 qname 所在区域的 DNSSEC 签名状态（防 downgrade 剥离攻击）。
        沿父区链逐级查询祖先委托点的 DS（DS 由父区权威回答）：
        - 'secure'   : 某祖先委托点有 DS（父区签名）→ qname 位于签名区
        - 'insecure' : 某祖先委托点无 DS，且父区用 NSEC/NSEC3 否定记录
                       数学验证证明该委托无 DS → 未签名委托，qname 位于未签名区
        - 'unknown'  : 全程无法证明 → 剥离风险，严格模式应丢弃
        """
        # 从 qname 自身开始，逐级向根检查每个名字的 DS。
        # 注意：qname 自身若是 zone apex 也有 DS（如 example.net），
        # 从 parent 起跳会漏查导致未签名 apex 被误判 secure 丢弃。
        n = zone_name if zone_name != dns.name.root else None
        visited: set = set()
        while n is not None and n != dns.name.root and n not in visited:
            visited.add(n)
            ds_resp = await self._iterate(str(n), dns.rdatatype.DS, 0)
            if ds_resp is None:
                return "unknown"
            # DS 存在 → 签名委托
            if any(rrset.rdtype == dns.rdatatype.DS for rrset in ds_resp.answer):
                return "secure"
            # NXDOMAIN：该名字不存在（区间证明），不是"委托无 DS" → 升父级
            if ds_resp.rcode() == dns.rcode.NXDOMAIN:
                n = n.parent()
                continue
            # 无 DS：仅当该名字是 zone apex（响应 SOA owner == 查询名）且父区用
            # NSEC/NSEC3 否定记录 + 有效签名证明"该 apex 委托无 DS" 才判 insecure。
            # 非 apex 名（如 www.example.com）的 DS 查询返回 NODATA 是其所在区
            # 的否定，不代表该名未签名——须升父级继续。
            # 判断 n 是否是 zone apex（父区的委托点）：DS 记录只存在父区，
            # DS 查询恒由父区权威回答（authority SOA owner 是父区，非 n）。
            # 正确判据：响应的 NSEC/NSEC3 RRSIG signer == n.parent()（父区签名
            # 否定该名无 DS）→ n 是父区的委托点/apex。若响应无 NSEC（纯 NODATA
            # SOA，signer 是父区），n 是父区内普通名 → 升父级。
            is_apex = False
            has_nsec = any(
                rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                for section in (ds_resp.answer, ds_resp.authority)
                for rrset in section
            )
            if has_nsec:
                # 检查 NSEC/NSEC3 的 signer 是否为 n.parent() 且 owner 是 n
                # （父区对委托点 n 的"无 DS"否定）。owner 位图需含 NS（委托点
                # 特征）或 n 是父区直接子域——区分"apex 委托无 DS"与
                # "zone 内普通名无 DS 记录"（如 www.example.com 在 example.com 内）。
                # 安全：先验证 NSEC/NSEC3 的 RRSIG 签名有效（防攻击者伪造
                # 无签名 NSEC 冒充父区委托否定——签名验证用父区已信任 DNSKEY）。
                for rrset in ds_resp.answer + ds_resp.authority:
                    if rrset.rdtype not in (
                            dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                        continue
                    rrsig_set = self._find_rrsig_for(ds_resp, rrset)
                    if rrsig_set is None:
                        continue  # 无签名 NSEC → 不认作父区委托否定
                    try:
                        parent_keys_ap = await self._get_trusted_dnskey(n.parent())
                        if parent_keys_ap is None:
                            continue
                        dns.dnssec.validate(
                            rrset, rrsig_set, {n.parent(): parent_keys_ap})
                    except (dns.dnssec.ValidationFailure, KeyError, Exception):
                        continue  # 签名无效 → 不认作父区委托否定
                    # signer == n.parent() 且 owner == n
                    signer_ok = False
                    for rrsig in rrsig_set:
                        try:
                            if str(rrsig.signer).rstrip(".").lower() == \
                               str(n.parent()).rstrip(".").lower():
                                signer_ok = True
                                break
                        except Exception:
                            continue
                    if not signer_ok:
                        continue
                    # NSEC：owner == n 且位图含 NS（委托点）→ apex
                    if rrset.rdtype == dns.rdatatype.NSEC and rrset.name == n:
                        for rdata in rrset:
                            if self._nsec_has_type(rdata, dns.rdatatype.NS):
                                is_apex = True
                                break
                    # NSEC3：owner hash == n 的 hash 且位图含 NS → apex
                    elif rrset.rdtype == dns.rdatatype.NSEC3:
                        oh3 = self._nsec3_owner_hash(rrset.name)
                        th3 = None
                        for rdata in rrset:
                            th3 = self._nsec3_hash(
                                n, rdata.salt, rdata.iterations, rdata.algorithm)
                            if oh3 and th3 and oh3 == th3 and \
                               self._nsec_has_type(rdata, dns.rdatatype.NS):
                                is_apex = True
                                break
                    if is_apex:
                        break
            if not is_apex:
                # 未匹配 owner==n 的 NSEC，但 NSEC/NSEC3 可能区间覆盖 n 且位图
                # 含 NS（n 是父区的 opt-out 委托点）——检查区间覆盖的 NSEC
                # 是否证明 n 是委托点且无 DS（insecure 委托）。
                nsec_valid = False
                try:
                    parent_keys = await self._get_trusted_dnskey(n.parent())
                    if parent_keys is not None:
                        for rrset in ds_resp.answer + ds_resp.authority:
                            if rrset.rdtype not in (
                                    dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                                continue
                            rrsig_set = self._find_rrsig_for(ds_resp, rrset)
                            if rrsig_set is None:
                                continue
                            dns.dnssec.validate(rrset, rrsig_set,
                                                {n.parent(): parent_keys})
                            for rdata in rrset:
                                if rrset.rdtype == dns.rdatatype.NSEC:
                                    # 区间覆盖 n 且位图含 NS（委托点）
                                    if self._nsec_covers(rdata, rrset.name, n) and \
                                       self._nsec_has_type(rdata, dns.rdatatype.NS) and \
                                       not self._nsec_has_type(
                                           rdata, dns.rdatatype.DS):
                                        nsec_valid = True
                                elif rrset.rdtype == dns.rdatatype.NSEC3:
                                    oh3 = self._nsec3_owner_hash(rrset.name)
                                    th3 = self._nsec3_hash(
                                        n, rdata.salt, rdata.iterations,
                                        rdata.algorithm)
                                    if oh3 and th3 and \
                                       not self._nsec3_optout(rdata) and \
                                       self._nsec3_interval_check(
                                           th3, oh3, rdata.next) and \
                                       self._nsec_has_type(
                                           rdata, dns.rdatatype.NS) and \
                                       not self._nsec_has_type(
                                           rdata, dns.rdatatype.DS):
                                        nsec_valid = True
                except Exception:
                    nsec_valid = False
                if nsec_valid:
                    return "insecure"  # opt-out 委托点无 DS → 未签名区
                n = n.parent()
                continue
            if has_nsec:
                # 验证 NSEC/NSEC3 的 RRSIG（父区 DNSKEY 签名）且语义正确：
                # NSEC owner 必须等于被查名 target 且类型位图不含 DS
                # （防重放父区公开有效 NSEC——签名有效但区间不覆盖——伪造 insecure）
                nsec_valid = False
                try:
                    parent_keys = await self._get_trusted_dnskey(n.parent())
                    if parent_keys is not None:
                        for rrset in ds_resp.answer + ds_resp.authority:
                            if rrset.rdtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                                continue
                            rrsig_set = self._find_rrsig_for(ds_resp, rrset)
                            if rrsig_set is None:
                                continue
                            dns.dnssec.validate(rrset, rrsig_set,
                                                {n.parent(): parent_keys})
                            # 语义校验：NSEC owner == 被查名 && 位图不含 DS
                            for rdata in rrset:
                                if rrset.rdtype == dns.rdatatype.NSEC and \
                                   self._nsec_proves_no_ds(rdata, rrset.name, n):
                                    nsec_valid = True
                                elif rrset.rdtype == dns.rdatatype.NSEC3:
                                    # NSEC3：计算被查名 hash，验证落在
                                    # [owner, next) 区间且位图不含 DS（RFC 5155）
                                    owner_hash = self._nsec3_owner_hash(rrset.name)
                                    if owner_hash and self._nsec3_proves_no_ds(
                                            rdata, owner_hash, n):
                                        nsec_valid = True
                except (dns.dnssec.ValidationFailure, KeyError, Exception):
                    nsec_valid = False
                if nsec_valid:
                    return "insecure"  # 父区签名证明该委托无 DS → 未签名区
                # NSEC 签名验证失败或语义不符 → 无法证明（剥离/重放风险）
                return "unknown"
            # 无证明（NODATA 或 referral 无签名）→ 向父级继续
            n = n.parent()
        return "unknown"

    @property
    def name(self) -> str:
        """上游名称（供 ResolverManager 作为 UpstreamServer 注册使用）"""
        return "iterative"

    async def resolve_with_stats(self, query_bytes: bytes) -> tuple:
        """上游统一接口（供 ResolverManager._try_upstream_wave 调用）。

        接收 DNS 查询 wire bytes，执行 根→TLD→权威 迭代解析（含 DNSSEC
        严格验证），返回 (响应 wire bytes, 耗时秒)；失败/超时返回 (None, 耗时)。
        响应 ID 对齐客户端查询（迭代器内部每跳 make_query 生成随机 ID）。
        """
        t0 = time.monotonic()
        try:
            msg = dns.message.from_wire(query_bytes)
            if not msg.question:
                return (None, time.monotonic() - t0)
            q = msg.question[0]
            resp = await self.resolve(
                str(q.name).rstrip("."), q.rdtype, q.rdclass,
            )
            if resp is None:
                return (None, time.monotonic() - t0)
            resp.id = msg.id
            return (resp.to_wire(), time.monotonic() - t0)
        except Exception:
            return (None, time.monotonic() - t0)

    async def resolve(self, qname: str, qtype: int, rdclass: int = 1) -> Optional[dns.message.Message]:
        """迭代解析入口。返回最终响应 Message（含 RRSIG），失败返回 None。

        DNSSEC 严格验证（数学信任模型）：
          响应含 RRSIG（签名区域）→ 对每个 signer 做 DS→DNSKEY 全链验证
          （从内置 IANA 根锚出发），再验证 answer RRSIG；任一失败 → bogus → None
          响应无 RRSIG → 先查 zone 的 DS 状态：
            secure（签名区被剥离 RRSIG）→ 视为 downgrade 攻击 → bogus → None
            insecure（父区 NSEC 签名证明无 DS）→ 放行
            unknown（无法证明）→ 保守丢弃（上层回退加密上游）
        整个流程（迭代 + 链验证）受 total_timeout 总预算约束。
        """
        self._stats["queries"] += 1
        try:
            return await asyncio.wait_for(
                self._resolve_verified(qname, qtype, rdclass),
                timeout=self.total_timeout,
            )
        except asyncio.TimeoutError:
            logger.debug("迭代解析总超时: %s", qname)
            self._stats["fail"] += 1
            return None
        except Exception as e:
            logger.debug("迭代解析异常: %s", e)
            self._stats["fail"] += 1
            return None

    async def _resolve_verified(self, qname: str, qtype: int, rdclass: int) -> Optional[dns.message.Message]:
        """resolve 的内部实现：迭代 + DNSSEC 严格验证（受外层 total_timeout 约束）。"""
        try:
            resp = await self._iterate(qname, qtype, 0, rdclass)
            if resp is None:
                self._stats["fail"] += 1
                return None
            if not self.strict_dnssec:
                self._stats["success"] += 1
                return resp

            # 收集所有 RRSIG 的 signer（签名者区）——含最终响应与 CNAME 中间跳
            signers: set = set()
            for section in (resp.answer, resp.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        for rrsig in rrset:
                            signers.add(rrsig.signer)
            cname_chain_msgs: List = []
            for wire in getattr(resp, "_cname_chain", []) or []:
                try:
                    cm = dns.message.from_wire(wire)
                    cname_chain_msgs.append(cm)
                    for section in (cm.answer, cm.authority):
                        for rrset in section:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                for rrsig in rrset:
                                    signers.add(rrsig.signer)
                except Exception:
                    pass

            if not signers:
                # 无 RRSIG：防剥离攻击——先查 qname zone 的 DS 状态再决定
                try:
                    zone = dns.name.from_text(qname)
                except Exception:
                    zone = None
                zone_status = await self._zone_signed_status(zone) if zone is not None else "unknown"
                if zone_status == "secure":
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 剥离攻击: %s 属签名区却无 RRSIG — 丢弃", qname
                    )
                    return None
                if zone_status == "insecure":
                    self._stats["insecure"] += 1
                    self._stats["success"] += 1
                    return resp
                # unknown：无法证明未签名，严格模式保守丢弃
                self._stats["bogus"] += 1
                logger.warning(
                    "DNSSEC 无法证明 %s 未签名（无 RRSIG 且无 NSEC 证明）— 严格模式丢弃", qname
                )
                return None

            # 对每个 signer 做链验证，收集可信 keys（{signer: DNSKEY RRset}）
            trusted_keys: Dict = {}
            for signer in signers:
                if signer == dns.name.root:
                    continue  # 根锚内置
                dnskey_rrset = await self._get_trusted_dnskey(signer)
                if dnskey_rrset is None:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC 链验证失败，拒绝 %s 的签名响应", signer)
                    return None
                trusted_keys[signer] = dnskey_rrset

            # 关键安全约束 0：CNAME 链中间跳的 CNAME RRset 必须签名有效（若所在
            # zone 是签名区）。中间跳响应在 _iterate 中被丢弃，MITM 可篡改 CNAME
            # target（owner 不变）静默重定向——这里对链上每跳的 CNAME RRset 独立验签。
            for cm in cname_chain_msgs:
                for rrset in cm.answer:
                    if rrset.rdtype != dns.rdatatype.CNAME:
                        continue
                    rrsig_set = self._find_rrsig_for(cm, rrset)
                    if rrsig_set is None:
                        # 无签名：仅未签名区（insecure）合法；签名区（secure）或
                        # 无法证明（unknown）一律拒绝——与主流程 unknown 丢弃一致，
                        # 防 MITM 注入"无 DS"响应把签名区误导为 unknown 后剥离签名
                        try:
                            zs = await self._zone_signed_status(rrset.name)
                        except Exception:
                            zs = "unknown"
                        if zs != "insecure":
                            self._stats["bogus"] += 1
                            logger.warning(
                                "DNSSEC CNAME 链中间跳无签名（%s）: %s", zs, rrset.name)
                            return None
                        continue  # 未签名区 CNAME 无签名是合法的
                    try:
                        dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                    except (dns.dnssec.ValidationFailure, KeyError) as e:
                        self._stats["bogus"] += 1
                        logger.warning("DNSSEC CNAME 链中间跳签名验证失败 %s: %s",
                                       rrset.name, e)
                        return None
                    # wildcard 检测（RFC 4035 §5.3.3）：该跳 CNAME RRset 的
                    # RRSIG labels < owner labels → wildcard 展开——需该跳响应
                    # 有 owner 无精确记录的 NSEC/NSEC3 否定证明（防 MITM 用
                    # 真实签名 wildcard CNAME 替代精确 CNAME 重定向）。
                    rr_labels = len(rrset.name.labels) - 1
                    for rrsig in rrsig_set:
                        if rrsig.labels >= rr_labels:
                            continue
                        # wildcard 展开：检查该跳响应 authority 的 NSEC/NSEC3
                        # 是否证明 rrset.name 无精确 CNAME 记录，且 NSEC signer
                        # == 该跳 CNAME RRSIG signer（signer 归属，防父区 NSEC
                        # 冒充子区否定证明——与主应答分支 wc_signer_zone 对称）
                        wc_hop_signer = str(rrsig.signer).rstrip(".").lower()
                        wc_hop_ok = False
                        for h_rr in cm.authority:
                            if h_rr.rdtype not in (
                                    dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                                continue
                            h_rrsig = self._find_rrsig_for(cm, h_rr)
                            if h_rrsig is None:
                                continue
                            try:
                                dns.dnssec.validate(h_rr, h_rrsig, trusted_keys)
                            except (dns.dnssec.ValidationFailure, KeyError):
                                continue
                            # signer 归属：NSEC signer == 该跳 CNAME RRSIG signer
                            h_sig_ok = False
                            for hs in h_rrsig:
                                if str(hs.signer).rstrip(".").lower() == wc_hop_signer:
                                    h_sig_ok = True
                                    break
                            if not h_sig_ok:
                                continue
                            for hd in h_rr:
                                if h_rr.rdtype == dns.rdatatype.NSEC:
                                    # 仅区间覆盖证明 next closer 不存在（RFC 5155
                                    # §8.6）；NODATA（owner==rrset.name 位图无 CNAME）
                                    # 不适用——真实存在名字+真实签名 wildcard CNAME
                                    # 组合会被误判（重定向注入）。
                                    if self._nsec_covers(hd, h_rr.name, rrset.name):
                                        # 委托点检查（与主 wildcard/NXDOMAIN 分支
                                        # 对称）：区间覆盖 NSEC owner 为委托点则
                                        # 不能作为"无精确记录"证明
                                        h_deleg2 = (
                                            self._nsec_has_type(
                                                hd, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                hd, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            hd, dns.rdatatype.DS)
                                        if not h_deleg2:
                                            # RFC 5155 §8.8：中间跳 wildcard 正向
                                            # 应答只需 next-closer 区间覆盖；owner
                                            # 可为同 zone 兄弟名（跨区重放已由
                                            # signer==wc_hop_signer 归属封死）
                                            wc_hop_ok = True
                                else:
                                    h_oh = self._nsec3_owner_hash(h_rr.name)
                                    h_th = self._nsec3_hash(
                                        rrset.name, hd.salt, hd.iterations,
                                        hd.algorithm)
                                    if h_oh and h_th and \
                                       not self._nsec3_optout(hd) and (
                                            self._nsec3_interval_check(
                                                h_th, h_oh, hd.next)):
                                        # opt-out 委托检查（与 NSEC 分支对称）
                                        h_deleg = (
                                            self._nsec_has_type(
                                                hd, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                hd, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            hd, dns.rdatatype.DS)
                                        if not h_deleg:
                                            # RFC 5155 §8.8：中间跳 wildcard 正向应答
                                            # 只需 next-closer 区间覆盖；CE exact-match
                                            # 与 *.CE 否定属 NXDOMAIN 语义不适用
                                            #（*.CE 真实存在不可被区间否定）
                                            wc_hop_ok = True
                                            break
                        if not wc_hop_ok:
                            self._stats["bogus"] += 1
                            logger.warning(
                                "DNSSEC CNAME 链中间跳 wildcard 展开缺 NSEC 否定"
                                "证明: %s", rrset.name,
                            )
                            return None

            # 验证所有非 RRSIG RRset 的签名（answer + authority）
            # 关键安全约束 1：answer 段每个 RRset 必须单独有有效 RRSIG，
            # 缺失即拒绝（防止攻击者剥离 answer RRSIG 后由 authority 段
            # 真实重放的签名兜底绕过——部分剥离攻击）。
            # 关键安全约束 2：RRset owner 必须与 qname 或 CNAME 链目标匹配
            # （防止攻击者重放任意已签名 RRset 充当任意查询的答案，RFC 4035 §5.3）。
            # 合法 owner 集合：原始 qname + 响应中 CNAME 链的所有目标（含跨区多跳
            # 跟随累积的 target，来自 _iterate 保存的 _cname_targets）
            legal_owners = {dns.name.from_text(qname)}
            try:
                for rrset in resp.answer:
                    if rrset.rdtype != dns.rdatatype.CNAME:
                        continue
                    for rd in rrset:
                        legal_owners.add(rd.target)
                for t in getattr(resp, "_cname_targets", []) or []:
                    legal_owners.add(dns.name.from_text(str(t)))
                # L13 修复：不再向 legal_owners 加入 *.zone wildcard 名——
                # wire 级 wildcard 合成应答的 owner 是展开后的查询名（RFC 4035 §3.1.3），
                # 权威不会返回字面 *.zone 记录；下方对 owner 含 '*' 的 RRset 显式拒绝，
                # 原 wildcard 加入逻辑为不可达死代码（审计 L13）。
            except Exception:
                pass
            answer_unsigned: List[dns.rrset.RRset] = []
            answer_validated = False
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                # owner 校验：answer RRset 的 owner 必须属于合法集合。
                # 显式拒绝 owner 含 '*' 字面的 RRset：wire 级 wildcard 合成应答
                # 的 owner 是展开后的查询名（RFC 4035 §3.1.3），owner 含 '*' 的
                # RRset 是伪造（权威不会返回字面 *.zone 记录）。
                if "*" in str(rrset.name):
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC answer owner 含字面 *（伪造 wildcard 记录）: %s",
                        rrset.name,
                    )
                    return None
                if rrset.name not in legal_owners:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC answer owner 不匹配（重放攻击）: %s 不属于 %s 的合法链",
                        rrset.name, qname,
                    )
                    return None
                rrsig_set = self._find_rrsig_for(resp, rrset)
                if rrsig_set is None:
                    answer_unsigned.append(rrset)
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                    answer_validated = True
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC answer 签名验证失败 %s (%s): %s",
                                   rrset.name, rrset.rdtype, e)
                    return None

            if answer_unsigned:
                # answer 段存在任一无签名 RRset → 拒绝（部分剥离攻击：
                # 攻击者保留 CNAME 等任一合法签名、剥离并篡改其余 RRset）
                self._stats["bogus"] += 1
                logger.warning(
                    "DNSSEC answer 段存在无签名 RRset（剥离攻击）: %s %s",
                    qname, [str(r.name) for r in answer_unsigned][:3],
                )
                return None

            if answer_validated:
                # answer 段全部签名验证通过 → secure
                # wildcard inexact-match 校验（RFC 4035 §5.3.3）：wildcard 合成应答
                # 的 owner 是展开后的查询名（wire 无 *.zone，RFC 4035 §3.1.3），
                # 检测须用 RRSIG labels 字段：rrsig.labels < qname 的 label 数
                # 表示签名覆盖通配名（如 *.example.com 签 www.example.com 时
                # labels=2 < qname labels=3）。命中后需 authority 有 qname 的
                # NSEC/NSEC3 否定证明（qname 自身无精确记录）——否则真实签名
                # wildcard 记录可被重放替代精确应答。
                wildcard_used = False
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    rrsig_w = self._find_rrsig_for(resp, rrset)
                    if rrsig_w is None:
                        continue
                    # RFC 4035 §5.3.3：比较每个 RRset 自身 owner 的 labels
                    # （CNAME 链目标与 qname 不同——按 owner 逐个比较防漏检/误报）
                    rr_labels = len(rrset.name.labels) - 1
                    for rrsig in rrsig_w:
                        if rrsig.labels < rr_labels:
                            wildcard_used = True
                            break
                    if wildcard_used:
                        break
                if wildcard_used:
                    # wildcard 记录的签名 zone = rrsig signer（用于 signer 归属）
                    wc_signer_zone = None
                    for rrset in resp.answer:
                        if rrset.rdtype == dns.rdatatype.RRSIG:
                            continue
                        rrsig_w = self._find_rrsig_for(resp, rrset)
                        if rrsig_w is None:
                            continue
                        rr_labels = len(rrset.name.labels) - 1
                        for rrsig in rrsig_w:
                            if rrsig.labels < rr_labels:
                                wc_signer_zone = str(rrsig.signer).rstrip(".").lower()
                                break
                        if wc_signer_zone:
                            break
                    # RFC 4035 §5.3.3：否定证明对象是**触发 wildcard 的 RRset 自身
                    # owner**（CNAME 目标场景中非 qname）——对每个 wildcard 展开
                    # RRset 用其 owner 做"无精确记录"否定证明，任一失败即拒绝。
                    wc_rrsets = []
                    for rrset in resp.answer:
                        if rrset.rdtype == dns.rdatatype.RRSIG:
                            continue
                        rrsig_w = self._find_rrsig_for(resp, rrset)
                        if rrsig_w is None:
                            continue
                        rr_labels = len(rrset.name.labels) - 1
                        if any(rrsig.labels < rr_labels for rrsig in rrsig_w):
                            wc_rrsets.append(rrset)
                    for wc_rr in wc_rrsets:
                        wc_target = wc_rr.name  # 该 RRset 自身 owner（非 qname）
                        # signer 归属：按该 RRset 自身 RRSIG signer 计算
                        #（跨区双 wildcard CNAME 链时后续 RRset 不再误拒）
                        wc_signer_zone = None
                        rrsig_w2 = self._find_rrsig_for(resp, wc_rr)
                        if rrsig_w2 is not None:
                            rr_labels2 = len(wc_rr.name.labels) - 1
                            for rrsig2 in rrsig_w2:
                                if rrsig2.labels < rr_labels2:
                                    wc_signer_zone = str(rrsig2.signer).rstrip(
                                        ".").lower()
                                    break
                        wildcard_proven = False
                        for a_rr in resp.authority:
                            if a_rr.rdtype not in (
                                    dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                                continue
                            a_rrsig = self._find_rrsig_for(resp, a_rr)
                            if a_rrsig is None:
                                continue
                            try:
                                dns.dnssec.validate(a_rr, a_rrsig, trusted_keys)
                            except (dns.dnssec.ValidationFailure, KeyError):
                                continue
                            # signer 归属：NSEC/NSEC3 signer 必须等于 wildcard answer
                            # RRset 的 RRSIG signer（wildcard 记录的签名 zone）——
                            # 防跨区重放任意签名区的 NSEC 证明无精确记录。
                            if wc_signer_zone:
                                sig_ok = False
                                for rrsig in a_rrsig:
                                    if str(rrsig.signer).rstrip(".").lower() == \
                                       wc_signer_zone:
                                        sig_ok = True
                                        break
                                if not sig_ok:
                                    continue  # 跨区 NSEC → 不认作本 zone 证明
                            for ad in a_rr:
                                if a_rr.rdtype == dns.rdatatype.NSEC:
                                    # wc_target 无精确记录：仅区间覆盖证明 next closer
                                    # 不存在（RFC 5155 §8.6）——NODATA 语义
                                    # （owner==wc_target 位图无类型）不适用：真实存在的
                                    # 名字 + 真实签名 wildcard 组合会被误判为合法
                                    # wildcard 展开（数据注入）。
                                    if self._nsec_covers(ad, a_rr.name, wc_target):
                                        nsec_owner_deleg = (
                                            self._nsec_has_type(
                                                ad, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                ad, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            ad, dns.rdatatype.DS)
                                        if not nsec_owner_deleg:
                                            # RFC 5155 §8.8：wildcard 正向应答只需
                                            # next-closer 区间覆盖；owner 可为同 zone
                                            # 兄弟名（跨区重放已由 signer==wc_signer_zone
                                            # 归属封死）
                                            wildcard_proven = True
                                            break
                                else:
                                    oh = self._nsec3_owner_hash(a_rr.name)
                                    th = self._nsec3_hash(
                                        wc_target, ad.salt, ad.iterations, ad.algorithm)
                                    if oh and th and \
                                       not self._nsec3_optout(ad) and (
                                            self._nsec3_interval_check(
                                                th, oh, ad.next)):
                                        # opt-out 委托检查（与 NSEC 分支对称）：
                                        # 位图含 NS 且不含 SOA，或含 DS → 委托点，
                                        # NSEC3 区间覆盖不能作为"无精确记录"证明
                                        nsec3_deleg = (
                                            self._nsec_has_type(
                                                ad, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                ad, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            ad, dns.rdatatype.DS)
                                        if not nsec3_deleg:
                                            # RFC 5155 §8.8 / RFC 4035 §5.3.4：wildcard
                                            # 正向应答只需 next-closer 区间覆盖证明
                                            #（*.CE 真实存在，其 hash 是链上 owner，
                                            # 无需也不能被区间否定；CE exact-match
                                            # 属 NXDOMAIN 负应答语义，不适用于此）
                                            wildcard_proven = True
                                            break
                    if not wildcard_proven:
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC wildcard 响应缺 %s 无精确记录证明"
                            "（重放替代精确应答）: %s", wc_target, qname,
                        )
                        return None
                # 关键安全约束：answer 含 CNAME 但无目标类型（A/AAAA）RRset 时，
                # 目标 RRset 可能被整体删除（非"无签名"）——须有 NSEC/NSEC3
                # 证明目标 NODATA 才放行，否则拒绝（防吞真实 A/AAAA）。
                has_target_type = any(
                    rrset.rdtype == qtype for rrset in resp.answer)
                has_cname = any(
                    rrset.rdtype == dns.rdatatype.CNAME for rrset in resp.answer)
                if has_cname and not has_target_type:
                    # 可能合法：CNAME 目标同 zone 且真实无目标类型——权威返回
                    # CNAME(签名) + SOA + NSEC(owner=目标, 位图无 qtype)（RFC 4035
                    # §5.2）。检查 authority 是否有目标的 NSEC NODATA 证明。
                    target_nsec_nodata = False
                    # 目标提取：优先 _cname_targets，否则从 answer CNAME RRset 提取
                    tgt = None
                    if hasattr(resp, "_cname_targets") and resp._cname_targets:
                        tgt = resp._cname_targets[-1]
                    if tgt is None:
                        for rrset in resp.answer:
                            if rrset.rdtype != dns.rdatatype.CNAME:
                                continue
                            for rd in rrset:
                                tgt = str(rd.target)
                                break
                            if tgt:
                                break
                    if tgt is not None:
                        try:
                            tgt_name = dns.name.from_text(str(tgt))
                            # signer 归属：NSEC signer 须 == SOA owner zone
                            # （与负应答分支对称，防跨区重放）
                            cname_soa_zone: Optional[dns.name.Name] = None
                            for s_rr in resp.authority:
                                if s_rr.rdtype == dns.rdatatype.SOA:
                                    cname_soa_zone = s_rr.name
                                    break
                            for a_rr in resp.authority:
                                # 支持 NSEC 与 NSEC3 的 NODATA 证明
                                if a_rr.rdtype not in (
                                        dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                                    continue
                                # 关键：NSEC/NSEC3 必须签名有效（防剥离 A 后塞无签名
                                # NSEC 绕过）——与负应答分支同等要求
                                a_rrsig = self._find_rrsig_for(resp, a_rr)
                                if a_rrsig is None:
                                    continue
                                try:
                                    dns.dnssec.validate(a_rr, a_rrsig, trusted_keys)
                                except (dns.dnssec.ValidationFailure, KeyError):
                                    continue
                                # signer==SOA owner zone 归属校验
                                if cname_soa_zone is not None:
                                    sig_ok = False
                                    for rrsig in a_rrsig:
                                        if str(rrsig.signer).rstrip(".").lower() == \
                                           str(cname_soa_zone).rstrip(".").lower():
                                            sig_ok = True
                                            break
                                    if not sig_ok:
                                        continue
                                for ad in a_rr:
                                    if a_rr.rdtype == dns.rdatatype.NSEC:
                                        # 委托点检查（与主分支对称）：位图含 NS
                                        # 且不含 SOA，或含 DS → 委托点 NSEC 不能
                                        # 作为目标"无类型/NXDOMAIN"证明
                                        tgt_ns_deleg = (
                                            self._nsec_has_type(
                                                ad, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                ad, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            ad, dns.rdatatype.DS)
                                        if tgt_ns_deleg:
                                            continue
                                        # NODATA（owner==目标 位图无 qtype）或
                                        # NXDOMAIN（区间覆盖目标）均合法
                                        if self._nsec_proves_no_type(
                                                ad, a_rr.name, tgt_name, qtype):
                                            target_nsec_nodata = True
                                            break
                                        if self._nsec_covers(
                                                ad, a_rr.name, tgt_name):
                                            # RFC 8020 语义：owner 与目标同 zone
                                            #（跨区重放已由 signer==cname_soa_zone
                                            # 归属封死；真实 NSEC owner 可为兄弟名）
                                            if cname_soa_zone is None or \
                                               a_rr.name.is_subdomain(cname_soa_zone):
                                                # M4 修复：RFC 8020 —— 权威签名 NSEC
                                                # 区间覆盖 CNAME 目标即目标 NXDOMAIN 的
                                                # 合法证明（signer==SOA zone 已在上方校验），
                                                # 直接认可；原代码错误套用 RFC 4035 §5.3.3
                                                # 正向 wildcard 应答的 CE+*.CE 双证明，
                                                # 误拒仅返回单 NSEC 覆盖的标准负应答。
                                                target_nsec_nodata = True
                                                break
                                    else:
                                        oh = self._nsec3_owner_hash(a_rr.name)
                                        th = self._nsec3_hash(
                                            tgt_name, ad.salt, ad.iterations,
                                            ad.algorithm)
                                        # NSEC3 opt-out 委托检查（与主分支对称）
                                        tgt_n3_deleg = (
                                            self._nsec_has_type(
                                                ad, dns.rdatatype.NS)
                                            and not self._nsec_has_type(
                                                ad, dns.rdatatype.SOA)
                                        ) or self._nsec_has_type(
                                            ad, dns.rdatatype.DS)
                                        if tgt_n3_deleg:
                                            continue
                                        if oh and th and th == oh and \
                                           not self._nsec_has_type(ad, qtype):
                                            target_nsec_nodata = True
                                            break
                                        # NSEC3 区间覆盖（NXDOMAIN 语义，与 NSEC
                                        # 分支对称）：目标不存在。M4 修复后直接认可
                                        #（签名 + opt-out 排除 + signer 归属已校验）。
                                        if oh and th and \
                                           not self._nsec3_optout(ad) and \
                                           self._nsec3_interval_check(
                                               th, oh, ad.next):
                                            # M4 修复：NSEC3 区间覆盖目标即目标
                                            # NXDOMAIN 的合法签名证明（RFC 5155 §8.4，
                                            # opt-out 已排除；同 zone signer 已校验），
                                            # 直接认可；原 CE+*.CE 双证明对负应答过严，
                                            # 误拒标准 NSEC3 覆盖证明。
                                            target_nsec_nodata = True
                                            break
                        except Exception:
                            pass
                    if not target_nsec_nodata:
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC answer 含 CNAME 但目标类型 %s 缺失且无签名 "
                            "NSEC NODATA 证明（删除攻击）: %s", qtype, qname,
                        )
                        return None
                self._stats["secure"] += 1
                self._stats["success"] += 1
                # 本地链验证通过 → 置 AD 位，客户端可区分 secure/insecure
                resp.flags |= dns.flags.AD
                return resp

            # 负应答（NXDOMAIN/NODATA）场景：answer 空，验证 authority 段签名
            # （SOA/NSEC 由权威签名，数学验证其真实性；任一无签名即拒绝，
            #  防止攻击者剥离 NSEC/NSEC3 的 RRSIG 放行伪造否定应答）
            # 关键安全约束：NSEC/NSEC3 必须做区间语义校验（与 _zone_signed_status
            # 一致），签名只能证明"NSEC 是某区真实签署的"，不能证明区间覆盖本次
            # qname——防止攻击者重放任意区的有效签名 NSEC 伪造 NXDOMAIN/NODATA。
            auth_unsigned: List[dns.rrset.RRset] = []
            nsec_semantic_ok = False
            has_nsec = False
            # SOA owner 必须是 qname 的权威 zone（qname 或祖先 apex）——
            # 防重放任意签名区真实 SOA+RRSIG 伪造任意域名 NODATA 空应答
            soa_owner_valid = False
            soa_owner_zone: Optional[dns.name.Name] = None
            qn = dns.name.from_text(qname)
            # RFC 6604 CNAME+NXDOMAIN：负应答 answer 段可能含 CNAME（指向不存在
            # 目标的链）——与正应答对称：answer 段 CNAME 有签名必验、无签名按
            # zone 状态拒绝（防攻击者在签名区负应答注入未签名 CNAME）。
            for rrset in resp.answer:
                if rrset.rdtype != dns.rdatatype.CNAME:
                    continue
                rrset_sig = self._find_rrsig_for(resp, rrset)
                if rrset_sig is None:
                    # 无签名：仅未签名区（insecure）合法；secure/unknown 一律拒绝
                    try:
                        zs_neg = await self._zone_signed_status(rrset.name)
                    except Exception:
                        zs_neg = "unknown"
                    if zs_neg != "insecure":
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC 负应答 answer CNAME 无签名（%s）: %s",
                            zs_neg, rrset.name,
                        )
                        return None
                    continue
                try:
                    dns.dnssec.validate(rrset, rrset_sig, trusted_keys)
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC 负应答 answer CNAME 签名验证失败 %s: %s",
                                   rrset.name, e)
                    return None
            for rrset in resp.authority:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                if rrset.rdtype == dns.rdatatype.SOA:
                    # qname 或祖先 == SOA owner
                    anc = qn
                    while anc is not None and anc != dns.name.root:
                        if anc == rrset.name:
                            soa_owner_valid = True
                            soa_owner_zone = rrset.name
                            break
                        anc = anc.parent()
                rrsig_set = self._find_rrsig_for(resp, rrset)
                if rrsig_set is None:
                    auth_unsigned.append(rrset)
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC authority 签名验证失败 %s (%s): %s",
                                   rrset.name, rrset.rdtype, e)
                    return None
                # NSEC/NSEC3 区间语义校验：证明的必须是被查名 qname
                # NXDOMAIN → 区间覆盖（owner < qname < next）
                # NODATA  → owner == qname（NSEC 存在但无目标类型）
                # 权威 zone 归属校验（RFC 4035 §5.4）：NSEC/NSEC3 的 RRSIG
                # signer 必须属于 SOA owner 表明的权威 zone——防重放跨区 NSEC
                # （如 com 区 NSEC 冒充 example.com 的 NODATA 证明吞真实 A）
                if rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                    has_nsec = True
                    is_nxdomain = (resp.rcode() == dns.rcode.NXDOMAIN)
                    # 归属校验：rrsig signer 必须 == SOA owner zone（RFC 4035 §5.4）。
                    # 权威负应答必须含 SOA（SOA owner 即权威 zone）——无 SOA 的
                    # NSEC 无法绑定 zone 归属，一律拒绝（防跨区重放）。
                    nsec_zone_ok = False
                    if soa_owner_zone is not None:
                        for rrsig in rrsig_set:
                            if str(rrsig.signer).rstrip(".").lower() == \
                               str(soa_owner_zone).rstrip(".").lower():
                                nsec_zone_ok = True
                                break
                    if not nsec_zone_ok:
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC 负应答 NSEC signer 非 %s 权威 zone（跨区重放）— 拒绝",
                            soa_owner_zone if soa_owner_zone is not None else "(无SOA)",
                        )
                        return None
                    for rdata in rrset:
                        if rrset.rdtype == dns.rdatatype.NSEC:
                            if is_nxdomain:
                                # closest-encloser 校验（RFC 4035 §5.4 / RFC 8020）：
                                # NSEC 区间覆盖的 owner 若含 NS/DS（委托点），说明
                                # qname 可能属于更深委托区，仅凭父区 NSEC 区间覆盖
                                # 不能证明 NXDOMAIN——需更深 zone 的 NSEC 证明。
                                # 例：com.ua 区 NSEC(owner=example.com.ua 委托点,
                                # next=zzz.com.ua) 区间覆盖 foo.example.com.ua——
                                # 若 example.com.ua 是真实委托，foo 属其子区，
                                # 此 NSEC 不能证明 foo 不存在。
                                if self._nsec_covers(rdata, rrset.name, qn):
                                    # RFC 8020 语义：owner 与被查名同 zone（且非
                                    # 委托点，见下）即可——真实权威的 next-closer
                                    # NSEC owner 常为同 zone 前驱兄弟名（如
                                    # NSEC(bar.example.com→www) 覆盖 foo），非祖先。
                                    # 跨 zone 重放已由 signer==SOA owner 归属封死。
                                    if soa_owner_zone is not None and \
                                       not rrset.name.is_subdomain(soa_owner_zone):
                                        logger.debug(
                                            "DNSSEC NXDOMAIN NSEC owner %s 非 %s "
                                            "同 zone（跨区）— 拒绝",
                                            rrset.name, soa_owner_zone,
                                        )
                                        continue
                                    owner_is_delegation = (
                                        self._nsec_has_type(rdata, dns.rdatatype.NS)
                                        and not self._nsec_has_type(
                                            rdata, dns.rdatatype.SOA)
                                    ) or self._nsec_has_type(rdata, dns.rdatatype.DS)
                                    if not owner_is_delegation:
                                        # wildcard 否定检查（RFC 7129 §5.3.3）：
                                        # 需证明 *.CE（CE=覆盖 NSEC owner）也不存在。
                                        # 完整证明需两个 NSEC：qname 区间覆盖 +
                                        # *.CE 区间覆盖（wildcard 否定）。检查响应
                                        # authority 中是否有 NSEC 覆盖 *.owner。
                                        owner_txt = str(rrset.name).lower()
                                        next_txt = str(rdata.next).lower()
                                        if "*" in owner_txt or "*" in next_txt:
                                            logger.debug(
                                                "DNSSEC NXDOMAIN NSEC 含 wildcard"
                                                "（%s）— 保守拒绝", rrset.name,
                                            )
                                            continue
                                        # *.CE wildcard 否定：CE 是 qname 沿祖先链的
                                        # 最深存在祖先（authority 中某 NSEC owner
                                        # exact-match），而非覆盖 NSEC 的 owner——
                                        # 后者构造的 *.owner 因 '*' 是 label 首字符
                                        # 最小值而恒被同一 NSEC 覆盖（owner < *.owner
                                        # < next），检查形同虚设。先求 CE 再否定 *.CE。
                                        ce_nx = None
                                        anc_nx = qn.parent()
                                        while anc_nx is not None and \
                                              anc_nx != dns.name.root:
                                            # 到达 SOA owner zone 边界即停（显式
                                            # 分支，避免三元优先级陷阱）
                                            if soa_owner_zone is not None and \
                                               not anc_nx.is_subdomain(soa_owner_zone):
                                                break
                                            for c_rr in resp.authority:
                                                if c_rr.rdtype != dns.rdatatype.NSEC:
                                                    continue
                                                if c_rr.name == anc_nx:
                                                    ce_nx = anc_nx
                                                    break
                                            if ce_nx is not None:
                                                break
                                            anc_nx = anc_nx.parent()
                                        if ce_nx is None:
                                            # 无 CE exact-match → 无法证明 wildcard
                                            # 否定，保守拒绝
                                            logger.debug(
                                                "DNSSEC NXDOMAIN 缺 CE exact-match"
                                                "（%s）— 保守拒绝", qname,
                                            )
                                            continue
                                        try:
                                            wc_name = dns.name.from_text(
                                                "*." + str(ce_nx))
                                            wc_covered = False
                                            for w_rr in resp.authority:
                                                if w_rr.rdtype != dns.rdatatype.NSEC:
                                                    continue
                                                w_rrsig = self._find_rrsig_for(
                                                    resp, w_rr)
                                                if w_rrsig is None:
                                                    continue
                                                # 辅助记录 signer==SOA owner zone
                                                #（纵深对齐，验签由外层循环兜底）
                                                if soa_owner_zone is not None:
                                                    w_sig_ok = False
                                                    for w_rs in w_rrsig:
                                                        if str(w_rs.signer).rstrip(
                                                                ".").lower() == \
                                                           str(soa_owner_zone).rstrip(
                                                               ".").lower():
                                                            w_sig_ok = True
                                                            break
                                                    if not w_sig_ok:
                                                        continue
                                                for wd in w_rr:
                                                    if self._nsec_covers(
                                                            wd, w_rr.name, wc_name):
                                                        wc_covered = True
                                                        break
                                                if wc_covered:
                                                    break
                                        except Exception:
                                            wc_covered = False
                                        if wc_covered:
                                            nsec_semantic_ok = True
                                        else:
                                            logger.debug(
                                                "DNSSEC NXDOMAIN 缺 *.CE wildcard "
                                                "否定证明（%s）— 保守拒绝",
                                                ce_nx,
                                            )
                                    else:
                                        # owner 是委托点：需检查 qname 与 owner 之间
                                        # 是否有更深 zone 存在——无法证明，保守拒绝
                                        logger.debug(
                                            "DNSSEC NXDOMAIN NSEC owner %s 是委托点，"
                                            "qname %s 需更深 zone 证明 — 保守拒绝",
                                            rrset.name, qname,
                                        )
                            else:
                                # NODATA：owner==qname 且位图不含查询类型 qtype
                                if self._nsec_proves_no_type(
                                        rdata, rrset.name, qn, qtype):
                                    nsec_semantic_ok = True
                        else:
                            # NSEC3：与 NSEC 分支对称，按 is_nxdomain 分流
                            # NXDOMAIN → 仅区间覆盖（hash 落在 (owner,next) 开区间）
                            # NODATA  → 仅 hash==owner 匹配且位图不含 qtype
                            owner_hash = self._nsec3_owner_hash(rrset.name)
                            if not owner_hash:
                                continue
                            target_hash = self._nsec3_hash(
                                qn, rdata.salt, rdata.iterations, rdata.algorithm)
                            if not target_hash:
                                continue
                            if is_nxdomain:
                                # NSEC3 NXDOMAIN：区间覆盖 + closest-encloser
                                # （RFC 5155 §8.9）：位图含 NS/DS（opt-out 委托）
                                # 的 NSEC3 不能用于 NXDOMAIN 证明——qname 可能
                                # 属更深委托区，与 NSEC 分支的委托点拒绝对称。
                                if not self._nsec3_optout(rdata) and \
                                   self._nsec3_interval_check(
                                        target_hash, owner_hash, rdata.next):
                                    owner_is_deleg = (
                                        self._nsec_has_type(rdata, dns.rdatatype.NS)
                                        and not self._nsec_has_type(
                                            rdata, dns.rdatatype.SOA)
                                    ) or self._nsec_has_type(rdata, dns.rdatatype.DS)
                                    if not owner_is_deleg:
                                        # RFC 5155 §8.9：NXDOMAIN 需 closest-encloser
                                        # 存在性证明——qname 覆盖 NSEC3 的 owner hash
                                        # 应对应 qname 的某祖先（closest-encloser 的
                                        # hash 由另一 NSEC3 记录的存在性证明）。当前
                                        # 无法验证 CE 存在性与 wildcard 否定时，
                                        # 保守要求：区间覆盖的 owner hash 需是 qname
                                        # 祖先的 hash（若 NSEC3 位图含 NS/DS 已拒）。
                                        # 此处额外检查：响应中须有覆盖 qname 各级
                                        # 祖先 hash 的 NSEC3（CE 存在性近似证明）。
                                        # CE 存在性：真实 CE 的 hash 恰是链中某 NSEC3
                                        # 的 owner（exact-match）或落在某 NSEC3 区间
                                        # 内——遍历 qname 全部祖先（至 SOA owner zone
                                        # 含）并检查 authority 所有 NSEC3 记录。
                                        ce_covered = False
                                        ce_found_name: Optional[dns.name.Name] = None
                                        anc_ce = qn.parent()
                                        while anc_ce is not None and \
                                              anc_ce != dns.name.root:
                                            ce_hash = self._nsec3_hash(
                                                anc_ce, rdata.salt,
                                                rdata.iterations, rdata.algorithm)
                                            if ce_hash:
                                                if ce_hash == owner_hash:
                                                    ce_covered = True
                                                    ce_found_name = anc_ce
                                                    break
                                                # 仅 exact-match 证明 CE 存在；
                                                # 区间覆盖 = 该祖先不存在，不是
                                                # CE 存在性证明（RFC 5155 §8.9）
                                                for o_rr in resp.authority:
                                                    if o_rr.rdtype != dns.rdatatype.NSEC3:
                                                        continue
                                                    # 辅助记录 signer==SOA owner zone
                                                    o_rrsig = self._find_rrsig_for(
                                                        resp, o_rr)
                                                    if o_rrsig is None:
                                                        continue
                                                    if soa_owner_zone is not None:
                                                        o_sig_ok = False
                                                        for o_rs in o_rrsig:
                                                            if str(o_rs.signer).rstrip(
                                                                    ".").lower() == \
                                                               str(soa_owner_zone).rstrip(
                                                                   ".").lower():
                                                                o_sig_ok = True
                                                                break
                                                        if not o_sig_ok:
                                                            continue
                                                    o_oh = self._nsec3_owner_hash(o_rr.name)
                                                    if o_oh and ce_hash == o_oh:
                                                        ce_covered = True
                                                        ce_found_name = anc_ce
                                                        break
                                                if ce_covered:
                                                    break
                                            # 到达 SOA owner zone 即停
                                            if soa_owner_zone is not None and \
                                               anc_ce == soa_owner_zone:
                                                break
                                            anc_ce = anc_ce.parent()
                                        if ce_covered:
                                            # RFC 5155 §8.9 第三证明项：*.CE wildcard
                                            # 否定——需有 NSEC3 覆盖 hash(*.CE)（证明
                                            # wildcard 也不存在），与 NSEC 分支的
                                            # *.CE 双 NSEC 对称。缺则保守拒绝。
                                            wc_ce_name = None
                                            # 用第二项证明找到的 CE（ce_found_name）
                                            # 构造 *.CE，保持一致性
                                            if ce_found_name is not None:
                                                try:
                                                    wc_ce_name = dns.name.from_text(
                                                        "*." + str(ce_found_name))
                                                except Exception:
                                                    wc_ce_name = None
                                            if wc_ce_name is None:
                                                for ce_anc2 in (qn.parent(),
                                                                qn.parent().parent()):
                                                    if ce_anc2 is None or \
                                                       ce_anc2 == dns.name.root:
                                                        continue
                                                    try:
                                                        wc_ce_name = dns.name.from_text(
                                                            "*." + str(ce_anc2))
                                                        break
                                                    except Exception:
                                                        continue
                                            wc_ce_negated = False
                                            if wc_ce_name is not None:
                                                wc_ce_hash = self._nsec3_hash(
                                                    wc_ce_name, rdata.salt,
                                                    rdata.iterations,
                                                    rdata.algorithm)
                                                if wc_ce_hash:
                                                    for w_rr in resp.authority:
                                                        if w_rr.rdtype != \
                                                           dns.rdatatype.NSEC3:
                                                            continue
                                                        # 辅助记录 signer==SOA owner zone
                                                        w_rr_sig = self._find_rrsig_for(
                                                            resp, w_rr)
                                                        if w_rr_sig is None:
                                                            continue
                                                        if soa_owner_zone is not None:
                                                            w2_sig_ok = False
                                                            for w2_rs in w_rr_sig:
                                                                if str(w2_rs.signer).rstrip(
                                                                        ".").lower() == \
                                                                   str(soa_owner_zone).rstrip(
                                                                       ".").lower():
                                                                    w2_sig_ok = True
                                                                    break
                                                            if not w2_sig_ok:
                                                                continue
                                                        w_oh = self._nsec3_owner_hash(
                                                            w_rr.name)
                                                        if not w_oh:
                                                            continue
                                                        for w_rd in w_rr:
                                                            if not self._nsec3_optout(w_rd) and \
                                                               self._nsec3_interval_check(
                                                                    wc_ce_hash,
                                                                    w_oh,
                                                                    w_rd.next):
                                                                wc_ce_negated = True
                                                                break
                                                        if wc_ce_negated:
                                                            break
                                            if wc_ce_negated:
                                                nsec_semantic_ok = True
                                            else:
                                                logger.debug(
                                                    "DNSSEC NXDOMAIN NSEC3 缺 *.CE "
                                                    "wildcard 否定证明 — 保守拒绝",
                                                )
                                        else:
                                            logger.debug(
                                                "DNSSEC NXDOMAIN NSEC3 缺 closest-"
                                                "encloser 存在性证明 — 保守拒绝",
                                            )
                                    else:
                                        logger.debug(
                                            "DNSSEC NXDOMAIN NSEC3 owner %s 是委托点"
                                            "（opt-out），qname %s 需更深 zone 证明 "
                                            "— 保守拒绝", rrset.name, qname,
                                        )
                            else:
                                # NODATA（RFC 5155 §8.5）：exact-match（hash==owner
                                # 且位图不含 qtype）或 empty non-terminal 区间证明
                                # （target hash 落在区间内，需 CE 存在性防降级）。
                                if target_hash == owner_hash and \
                                   not self._nsec_has_type(rdata, qtype):
                                    nsec_semantic_ok = True
                                elif not self._nsec3_optout(rdata) and \
                                     self._nsec3_interval_check(
                                        target_hash, owner_hash, rdata.next) and \
                                     not self._nsec_has_type(rdata, qtype):
                                    # opt-out 委托检查（RFC 5155 §8.6，与 NSEC 分支
                                    # 对称）：区间覆盖 NSEC3 位图含 NS 且不含 SOA，
                                    # 或含 DS → opt-out 委托点，不能证明 NODATA
                                    # （qname 可能真实存在于 opt-out 子区）
                                    n3_nt_deleg = (
                                        self._nsec_has_type(
                                            rdata, dns.rdatatype.NS)
                                        and not self._nsec_has_type(
                                            rdata, dns.rdatatype.SOA)
                                    ) or self._nsec_has_type(
                                        rdata, dns.rdatatype.DS)
                                    if n3_nt_deleg:
                                        continue
                                    # empty non-terminal：target 非 owner 但落在区间
                                    # 内——该 NSEC3 证明 target 处无直接记录。仅当
                                    # qname 是某祖先的 non-terminal 才合法；保守
                                    # 要求 CE（qn 祖先）存在性成立。
                                    ce_nt = qn.parent()
                                    while ce_nt is not None and ce_nt != dns.name.root:
                                        ce_nt_hash = self._nsec3_hash(
                                            ce_nt, rdata.salt, rdata.iterations,
                                            rdata.algorithm)
                                        # 仅 exact-match（CE hash == 某 NSEC3 owner）
                                        # 证明 CE 存在；区间覆盖 = 祖先不存在（语义
                                        # 错）——遍历 authority 全部 NSEC3（RFC 5155
                                        # §8.9，与主 NXDOMAIN 分支对称）
                                        if ce_nt_hash:
                                            if ce_nt_hash == owner_hash:
                                                nsec_semantic_ok = True
                                                break
                                            for o_nt_rr in resp.authority:
                                                if o_nt_rr.rdtype != \
                                                   dns.rdatatype.NSEC3:
                                                    continue
                                                o_nt_oh = self._nsec3_owner_hash(
                                                    o_nt_rr.name)
                                                if o_nt_oh and \
                                                   ce_nt_hash == o_nt_oh:
                                                    nsec_semantic_ok = True
                                                    break
                                            if nsec_semantic_ok:
                                                break
                                        ce_nt = ce_nt.parent()

            if auth_unsigned:
                # authority 段存在任一无签名 RRset（如被剥离 RRSIG 的 NSEC）→ 拒绝
                self._stats["bogus"] += 1
                logger.warning(
                    "DNSSEC authority 段存在无签名 RRset（否定应答伪造）: %s %s",
                    qname, [str(r.name) for r in auth_unsigned][:3],
                )
                return None

            if has_nsec and not nsec_semantic_ok:
                # 有 NSEC/NSEC3 但区间语义不覆盖本次 qname → 重放攻击 → 拒绝
                self._stats["bogus"] += 1
                logger.warning(
                    "DNSSEC 负应答 NSEC/NSEC3 区间不覆盖 %s（重放攻击）— 拒绝", qname,
                )
                return None

            # SOA owner 校验：负应答（NODATA/NXDOMAIN）authority 含 SOA 时，
            # SOA owner 必须属于 qname 的权威 zone——防重放任意签名区 SOA。
            # NXDOMAIN 也必须校验（无 NSEC 时仅 SOA+RRSIG 也可被重放伪造）。
            # 关键：签名区（SOA owner 有效）负应答必须由 NSEC/NSEC3 证明否定性
            # （RFC 4035 §5.4 / RFC 6840 §4.3）——否则可重放祖先签名区（如
            # paypal.com）公开的真实 SOA+RRSIG 对任意子域名伪造 NODATA/NXDOMAIN。
            has_soa = any(
                rrset.rdtype == dns.rdatatype.SOA for rrset in resp.authority)
            if soa_owner_valid:
                # 签名区负应答：必须有 NSEC/NSEC3 且语义校验通过
                if not (has_nsec and nsec_semantic_ok):
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 签名区负应答缺 NSEC 证明（SOA-only 重放伪造）— 拒绝: %s",
                        qname,
                    )
                    return None
            else:
                if has_soa:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 负应答 SOA owner 不属于 %s 权威 zone（重放伪造）— 拒绝",
                        qname,
                    )
                    return None
                # 无 SOA 的负应答（仅 NSEC 证明）：NSEC 语义已校验，允许
                if not has_nsec:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 负应答无 SOA 且无 NSEC 证明（伪造）— 拒绝: %s", qname,
                    )
                    return None

            if resp.authority:
                # authority 段全部签名验证通过（或为空）→ 负应答 secure
                self._stats["secure"] += 1
                self._stats["success"] += 1
                resp.flags |= dns.flags.AD
                return resp

            # 有 RRSIG 但 answer/authority 均无有效验证 → bogus
            self._stats["bogus"] += 1
            logger.warning("DNSSEC 响应有 RRSIG 但无 RRset 验证通过: %s", qname)
            return None
        except Exception as e:
            logger.debug("迭代解析异常: %s", e)
            self._stats["fail"] += 1
            return None

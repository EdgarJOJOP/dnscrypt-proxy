"""
本地 DoQ 服务器（DNS over QUIC，RFC 9250）
- QUIC 加密传输（基于 UDP）
- 2 字节长度前缀的 DNS 消息格式
- 支持 IPv4/IPv6 双栈
- 可配置域名（SNI）和证书
- 集成 DNS 缓存 + 域名过滤 + DNSSEC
- 基于 aioquic 底层 API
"""

import os
import ssl
import asyncio
import struct
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
from cache import DNSCache
from resolver_manager import ResolverManager
from filter_engine import FilterEngine
from logger import RequestLogger
from dnssec import DNSSECQueryWrapper
from qps_limiter import QPSCounter

logger = logging.getLogger("dns-proxy.local-doq")

# aioquic 为可选依赖
try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import (
        QuicEvent,
        StreamDataReceived,
        HandshakeCompleted,
        ConnectionTerminated,
    )
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False
    logger.warning("aioquic 未安装，本地 DoQ 服务器不可用")

QTYPE_NAMES = {v: k for k, v in dns.rdatatype.__dict__.items() if isinstance(v, int)}


class _DoQConnection:
    """管理单个 QUIC 连接的状态和事件处理"""

    def __init__(
        self,
        server: "LocalDoQServer",
        quic_config: QuicConfiguration,
        transport: asyncio.DatagramTransport,
        addr: tuple,
    ):
        self._server = server
        self._transport = transport
        self._addr = addr
        self._quic = QuicConnection(configuration=quic_config)
        self._stream_queries: dict = {}  # stream_id -> DNS query wire_data

    def receive_datagram(self, data: bytes):
        """接收 UDP 数据报并处理 QUIC 事件"""
        now = asyncio.get_event_loop().time()
        try:
            self._quic.receive_datagram(data, self._addr, now=now)
            self._process_events(now)
        except Exception as e:
            logger.debug("DoQ 处理数据报异常: %s", e)

    def _process_events(self, now: float):
        """处理所有待处理的 QUIC 事件"""
        for event in self._quic.next_send_events(now=now):
            if isinstance(event, StreamDataReceived):
                self._handle_stream_data(event)
            elif isinstance(event, ConnectionTerminated):
                logger.debug("DoQ 客户端 %s 断开连接", self._addr[0])

        # 发送 QUIC 流控数据包
        for data, addr in self._quic.send_flow_control_offered(now=now):
            try:
                self._transport.sendto(data, addr)
            except Exception:
                pass

        # 发送 QUIC 数据报
        while True:
            data = self._quic.send_datagram(now=now)
            if data is None:
                break
            try:
                self._transport.sendto(data, self._addr)
            except Exception:
                pass

    def _handle_stream_data(self, event: StreamDataReceived):
        """处理 QUIC 流上的 DNS 查询"""
        payload = event.data
        if len(payload) < 2:
            return

        msg_len = struct.unpack("!H", payload[:2])[0]
        dns_data = payload[2 : 2 + msg_len]
        if len(dns_data) < 12:
            return

        # 异步处理 DNS 查询
        asyncio.create_task(self._respond(event.stream_id, dns_data))

    async def _respond(self, stream_id: int, dns_data: bytes):
        """执行 DNS 查询并通过 QUIC 流发送响应"""
        client_ip = self._addr[0]
        response = await self._server._process_query(dns_data, client_ip)
        if response is not None:
            response_frame = struct.pack("!H", len(response)) + response
            now = asyncio.get_event_loop().time()
            self._quic.send_stream_data(stream_id, response_frame, end_stream=True)
            # 触发发送
            self._flush()

    def _flush(self):
        """刷新发送缓冲区"""
        now = asyncio.get_event_loop().time()
        for data, addr in self._quic.send_flow_control_offered(now=now):
            try:
                self._transport.sendto(data, addr)
            except Exception:
                pass

    def get_timer(self) -> Optional[float]:
        """获取下一个定时器到期时间"""
        now = asyncio.get_event_loop().time()
        timer = self._quic.get_timer(now=now)
        if timer is not None:
            return max(0, timer - now)
        return None

    def is_closed(self) -> bool:
        return self._quic.is_closed()

    def close(self):
        """关闭 QUIC 连接"""
        try:
            self._quic.close()
            self._flush()
        except Exception:
            pass


class _DoQUdpProtocol(asyncio.DatagramProtocol):
    """UDP 协议处理器，将数据报路由到对应的 QUIC 连接"""

    def __init__(self, server: "LocalDoQServer", quic_config: QuicConfiguration, max_connections: int = 100):
        self._server = server
        self._quic_config = quic_config
        self._max_connections = max_connections
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._connections: dict = {}  # addr -> _DoQConnection
        self._closed = False

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.debug("DoQ UDP 监听已建立")

    def datagram_received(self, data: bytes, addr: tuple):
        if self._closed:
            return
        conn = self._connections.get(addr)
        if conn is None:
            # 最大 QUIC 连接数限制
            if len(self._connections) >= self._max_connections:
                logger.warning("DoQ 超出最大连接数 %d，丢弃 %s 的数据报", self._max_connections, addr[0])
                return
            conn = _DoQConnection(self._server, self._quic_config, self.transport, addr)
            self._connections[addr] = conn
        conn.receive_datagram(data)

    def error_received(self, exc):
        logger.debug("DoQ UDP 错误: %s", exc)

    def connection_lost(self, exc):
        self._closed = True
        self._connections.clear()

    def cleanup_stale_connections(self):
        """清理已关闭的连接"""
        stale = [addr for addr, conn in self._connections.items() if conn.is_closed()]
        for addr in stale:
            self._connections.pop(addr, None)
        return len(stale)


class LocalDoQServer:
    """本地 DNS over QUIC 服务器"""

    def __init__(
        self,
        config: Config,
        resolver_manager: ResolverManager,
        cache: DNSCache,
        filter_engine: FilterEngine,
        request_logger: RequestLogger,
        dnssec_wrapper: Optional[DNSSECQueryWrapper] = None,
    ):
        if not HAS_AIOQUIC:
            logger.error("aioquic 未安装，DoQ 服务器无法启动")
            self.enabled = False
            return

        self.config = config
        self.resolver_manager = resolver_manager
        self.cache = cache
        self.filter_engine = filter_engine
        self.request_logger = request_logger
        self._dnssec_wrapper = dnssec_wrapper

        self.enabled = config.local_doq_enabled
        self.host = config.local_doq_host
        self.port = config.local_doq_port
        self.domain = config.local_doq_domain
        self.cert_path = config.local_doq_cert_path
        self.key_path = config.local_doq_key_path
        self.ipv6_enabled = config.local_doq_ipv6_enabled
        self.ipv6_host = config.local_doq_ipv6_host
        self.ipv6_port = config.local_doq_ipv6_port

        self._transport_v4: Optional[asyncio.DatagramTransport] = None
        self._transport_v6: Optional[asyncio.DatagramTransport] = None
        self._protocol_v4: Optional[_DoQUdpProtocol] = None
        self._protocol_v6: Optional[_DoQUdpProtocol] = None
        self._quic_config: Optional[QuicConfiguration] = None
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)
        self._cleanup_task: Optional[asyncio.Task] = None

        # 单 IP 限速
        self._per_ip_semaphores: Dict[str, Tuple[asyncio.Semaphore, float]] = {}
        self._per_ip_limit = config.max_concurrent_per_ip
        self._per_ip_cleanup_interval = 300
        self._per_ip_idle_timeout = 600

        # 最大 QUIC 连接数限制
        self._max_doq_connections = config.doq_max_connections

        # QPS 限速（所有客户端包括 localhost）
        self._qps_limiter = QPSCounter(config.doq_qps_limit, "DoQ")

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        now = time.time()
        if client_ip in self._per_ip_semaphores:
            sem, _ = self._per_ip_semaphores[client_ip]
            self._per_ip_semaphores[client_ip] = (sem, now)
            return sem
        sem = asyncio.Semaphore(self._per_ip_limit)
        self._per_ip_semaphores[client_ip] = (sem, now)
        return sem

    async def _cleanup_stale_per_ip_semaphores(self):
        while True:
            await asyncio.sleep(self._per_ip_cleanup_interval)
            now = time.time()
            stale = [
                ip for ip, (_, ts) in self._per_ip_semaphores.items()
                if now - ts > self._per_ip_idle_timeout
            ]
            for ip in stale:
                del self._per_ip_semaphores[ip]
            if stale:
                logger.debug("DoQ: 清理了 %d 个过期 IP 限速条目", len(stale))

    def _create_quic_config(self) -> Optional[QuicConfiguration]:
        """创建 QUIC 服务器配置（加载证书）"""
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            logger.warning("DoQ 证书不存在: %s, %s", self.cert_path, self.key_path)
            return None
        config = QuicConfiguration(
            alpn_protocols=["doq"],
            is_client=False,
            max_data=10000000,
            max_stream_data=1000000,
            idle_timeout=60.0,
        )
        config.load_cert_chain(self.cert_path, self.key_path)
        if self.domain:
            logger.info("DoQ 服务器域名: %s, 使用证书: %s", self.domain, self.cert_path)
        return config

    async def start(self):
        """启动 DoQ 服务器（IPv4 UDP + 可选 IPv6 UDP）"""
        if not HAS_AIOQUIC:
            logger.error("aioquic 未安装，本地 DoQ 服务器不可用")
            return
        if not self.enabled:
            logger.info("本地 DoQ 服务器已禁用")
            return

        self._quic_config = self._create_quic_config()
        if self._quic_config is None:
            logger.error("DoQ 服务器启动失败: QUIC 证书无效")
            return

        loop = asyncio.get_running_loop()

        # IPv4 UDP 监听
        try:
            self._protocol_v4 = _DoQUdpProtocol(self, self._quic_config, self._max_doq_connections)
            self._transport_v4, _ = await loop.create_datagram_endpoint(
                lambda: self._protocol_v4,
                local_addr=(self.host, self.port),
                family=asyncio.AddressFamily.AF_INET,
            )
            logger.info(
                "本地 DoQ [IPv4] quic://%s:%d (域名: %s)",
                self.host if self.host != "0.0.0.0" else "127.0.0.1",
                self.port,
                self.domain or "未设置",
            )
        except OSError as e:
            logger.error("DoQ [IPv4] 启动失败: %s", e)

        # IPv6 UDP 监听（可选）
        if self.ipv6_enabled:
            try:
                self._protocol_v6 = _DoQUdpProtocol(self, self._quic_config, self._max_doq_connections)
                self._transport_v6, _ = await loop.create_datagram_endpoint(
                    lambda: self._protocol_v6,
                    local_addr=(self.ipv6_host, self.ipv6_port),
                    family=asyncio.AddressFamily.AF_INET6,
                )
                logger.info(
                    "本地 DoQ [IPv6] quic://[%s]:%d (域名: %s)",
                    self.ipv6_host, self.ipv6_port, self.domain or "未设置",
                )
            except OSError as e:
                logger.warning("DoQ [IPv6] 启动失败（跳过）: %s", e)

        # 启动连接清理任务
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """停止 DoQ 服务器"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        for transport in (self._transport_v4, self._transport_v6):
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
        self._transport_v4 = None
        self._transport_v6 = None
        self._protocol_v4 = None
        self._protocol_v6 = None
        self._quic_config = None
        logger.info("本地 DoQ 服务器已停止")

    async def _cleanup_loop(self):
        """定期清理已关闭的 QUIC 连接 + 过期 IP 限速条目"""
        while True:
            try:
                await asyncio.sleep(30)
                if self._protocol_v4:
                    self._protocol_v4.cleanup_stale_connections()
                if self._protocol_v6:
                    self._protocol_v6.cleanup_stale_connections()
                # 清理过期 IP 限速条目
                now = time.time()
                stale = [
                    ip for ip, (_, ts) in self._per_ip_semaphores.items()
                    if now - ts > self._per_ip_idle_timeout
                ]
                for ip in stale:
                    del self._per_ip_semaphores[ip]
                if stale:
                    logger.debug("DoQ: 清理了 %d 个过期 IP 限速条目", len(stale))
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _process_query(self, wire_data: bytes, client_ip: str) -> Optional[bytes]:
        """处理 DNS 查询（并发控制 + 单 IP 限速 + QPS 限速）"""
        await self._qps_limiter.acquire()  # QPS 限速（所有客户端）
        if not self._is_localhost(client_ip):
            sem = await self._get_per_ip_semaphore(client_ip)
            async with sem:
                async with self._concurrency_semaphore:
                    return await self._do_process_query(wire_data, client_ip)
        async with self._concurrency_semaphore:
            return await self._do_process_query(wire_data, client_ip)

    async def _do_process_query(self, wire_data: bytes, client_ip: str) -> Optional[bytes]:
        """DNS 查询处理核心逻辑"""
        response_wire: Optional[bytes] = None
        block_reason = ""
        status = "ok"

        try:
            query = dns.message.from_wire(wire_data)
            if not query.question:
                return None

            question = query.question[0]
            qname = str(question.name).rstrip(".")
            qtype_name = QTYPE_NAMES.get(question.rdtype, str(question.rdtype))
            cache_key = (question.name, question.rdtype, question.rdclass)

            # 0. 自定义 hosts 映射
            custom_ips = self.filter_engine.get_custom_hosts_ips(qname)
            if custom_ips:
                response = dns.message.make_response(query)
                matched = False
                rdtype = question.rdtype
                for ip, ip_rdtype in custom_ips:
                    if rdtype == dns.rdatatype.A and ip_rdtype == dns.rdatatype.AAAA:
                        continue
                    if rdtype == dns.rdatatype.AAAA and ip_rdtype == dns.rdatatype.A:
                        continue
                    if rdtype == dns.rdatatype.A:
                        if not response.answer or response.answer[0].rdtype != dns.rdatatype.A:
                            response.answer.append(
                                dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.A)
                            )
                        response.answer[-1].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, ip), ttl=3600)
                        matched = True
                    elif rdtype == dns.rdatatype.AAAA:
                        if not response.answer or response.answer[0].rdtype != dns.rdatatype.AAAA:
                            response.answer.append(
                                dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                            )
                        response.answer[-1].add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, ip), ttl=3600)
                        matched = True
                if matched:
                    response.set_rcode(dns.rcode.NOERROR)
                    response_wire = response.to_wire()
                    status = "custom_hosts"
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    await self._log_query(client_ip, qname, qtype_name, status, block_reason)
                    return response_wire

            # 1. 域名过滤
            if self.config.filter_enabled:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    block_reason = reason
                    status = "blocked"
                    response = dns.message.make_response(query)
                    rdtype = question.rdtype
                    if rdtype == dns.rdatatype.A:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.A)
                        )
                        response.answer[0].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0"), ttl=3600)
                        response.set_rcode(dns.rcode.NOERROR)
                    elif rdtype == dns.rdatatype.AAAA:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                        )
                        response.answer[0].add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, "::"), ttl=3600)
                        response.set_rcode(dns.rcode.NOERROR)
                    else:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    response_wire = response.to_wire()
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    await self._log_query(client_ip, qname, qtype_name, status, block_reason)
                    return response_wire

            # 2. 缓存
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    response_wire = cached.to_wire()
                    status = "cached"
                    await self._log_query(client_ip, qname, qtype_name, status, "")
                    return response_wire

            # 3. 上游解析
            result_wire = await self.resolver_manager.resolve(wire_data)
            if result_wire is None:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                response_wire = response.to_wire()
                status = "error"
            else:
                dnssec_ok = True
                if self._dnssec_wrapper is not None and self.config.dnssec_enabled:
                    dnssec_ok, _ = await self._dnssec_wrapper.validate_response(wire_data, result_wire)
                    if not dnssec_ok and self.config.dnssec_drop_bogus:
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.SERVFAIL)
                        response_wire = response.to_wire()
                        status = "dnssec_bogus"
                    else:
                        response_wire = result_wire
                        status = "resolved"
                else:
                    response_wire = result_wire
                    status = "resolved"
                if self.config.cache_enabled and status == "resolved":
                    try:
                        response_msg = dns.message.from_wire(result_wire)
                        is_negative = response_msg.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.REFUSED)
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception:
                        pass

            await self._log_query(client_ip, qname, qtype_name, status, block_reason)
            return response_wire

        except dns.exception.DNSException:
            return None
        except Exception as e:
            logger.error("DoQ 查询异常: %s", e)
            return None

    async def _log_query(self, client_ip, domain, qtype, status, block_reason):
        """记录查询日志"""
        try:
            await self.request_logger.log(
                client_ip=client_ip,
                domain=domain,
                qtype=qtype,
                response_time=0,
                status=status,
                upstream="",
                block_reason=block_reason,
            )
        except Exception:
            pass

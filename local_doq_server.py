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
import socket
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
from rate_limiter import get_per_ip_limiter

# DNS 响应 Answer section 排序：AAAA (IPv6) 优先于 A (IPv4)
from dns_utils import reorder_answer_aaaa_first, sort_dns_response_wire

logger = logging.getLogger("dns-proxy.local-doq")

# aioquic 为可选依赖
try:
    from aioquic.buffer import Buffer
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.packet import pull_quic_header
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
        original_destination_connection_id: Optional[bytes] = None,
    ):
        self._server = server
        self._transport = transport
        self._addr = addr
        # aioquic 1.x：服务端连接必须携带客户端选定的原始 DCID，否则构造即断言失败
        try:
            self._quic = QuicConnection(
                configuration=quic_config,
                original_destination_connection_id=original_destination_connection_id,
            )
        except TypeError:
            # 兼容不支持该参数的旧版 aioquic
            self._quic = QuicConnection(configuration=quic_config)
        self._stream_queries: dict = {}  # stream_id -> DNS query wire_data

    def receive_datagram(self, data: bytes):
        """接收 UDP 数据报并处理 QUIC 事件"""
        now = asyncio.get_running_loop().time()
        try:
            self._quic.receive_datagram(data, self._addr, now=now)
        except Exception as e:
            logger.debug("DoQ 接收数据报异常: %s", e)
            return
        self._process_events(now)

    def _process_events(self, now: float):
        """处理所有待处理的 QUIC 事件，然后冲刷待发数据报

        aioquic 1.x 的取事件 API 是 next_event()（next_send_events 不存在），
        发送 API 是 datagrams_to_send(now)（send_datagram/send_flow_control_offered
        不存在）；用错会导致 QUIC 完全发不出包，客户端握手/响应全部超时。
        """
        try:
            event = self._quic.next_event()
            while event is not None:
                if isinstance(event, StreamDataReceived):
                    self._handle_stream_data(event)
                elif isinstance(event, ConnectionTerminated):
                    logger.debug("DoQ 客户端 %s 断开连接", self._addr[0])
                event = self._quic.next_event()
        except Exception as e:
            logger.debug("DoQ 事件处理异常: %s", e)
        self._flush(now)

    def _handle_stream_data(self, event: StreamDataReceived):
        """处理 QUIC 流上的 DNS 查询（RFC 9250：2 字节长度前缀 + DNS 消息）"""
        payload = event.data
        if len(payload) < 2:
            return

        msg_len = struct.unpack("!H", payload[:2])[0]
        if len(payload) < 2 + msg_len:
            logger.warning("DoQ truncation: need %d, got %d", 2 + msg_len, len(payload))
            return
        dns_data = payload[2 : 2 + msg_len]
        if len(dns_data) < 12:
            return

        # 异步处理 DNS 查询
        self._server._track_task(
            asyncio.ensure_future(self._respond(event.stream_id, dns_data))
        )

    async def _respond(self, stream_id: int, dns_data: bytes):
        """执行 DNS 查询并通过 QUIC 流发送响应"""
        client_ip = self._addr[0]
        try:
            response = await self._server._process_query(dns_data, client_ip)
        except Exception as e:
            logger.debug("DoQ 查询处理异常: %s", e)
            response = None
        if response is None:
            # 处理失败/被丢弃时回 SERVFAIL，避免 stream 悬空导致客户端挂起
            response = self._server._make_servfail_wire(dns_data)
            if response is None:
                return
        response_frame = struct.pack("!H", len(response)) + response
        try:
            self._quic.send_stream_data(stream_id, response_frame, end_stream=True)
        except Exception as e:
            logger.debug("DoQ 流写入异常: %s", e)
            return
        # 触发发送
        self._flush()

    def _flush(self, now: Optional[float] = None):
        """把所有待发的 QUIC 数据报写回 UDP"""
        if now is None:
            now = asyncio.get_running_loop().time()
        try:
            for data, addr in self._quic.datagrams_to_send(now=now):
                try:
                    self._transport.sendto(data, addr)
                except Exception as e:
                    logger.debug("DoQ 数据报发送异常: %s", e)
        except Exception as e:
            logger.debug("DoQ 刷新发送异常: %s", e)

    def handle_timer(self, now: Optional[float] = None):
        """推进 QUIC 定时器（PTO 重传 / idle timeout / draining），然后冲刷

        原先只定义了 get_timer 却从未调用 handle_timer，导致握手重传与
        idle timeout 都不推进：半开连接不会被回收、连接槽位泄漏。
        """
        if now is None:
            now = asyncio.get_running_loop().time()
        try:
            self._quic.handle_timer(now=now)
        except Exception as e:
            logger.debug("DoQ 定时器处理异常: %s", e)
            return
        self._flush(now)

    def get_timer(self) -> Optional[float]:
        """获取下一个 QUIC 定时器到期时间（绝对时间戳，aioquic get_timer() 无参数）"""
        try:
            return self._quic.get_timer()
        except Exception:
            return None

    def is_closed(self) -> bool:
        """aioquic 1.x 的 QuicConnection 没有 is_closed()，改看内部状态机"""
        state = getattr(self._quic, "_state", None)
        if state is None:
            return False
        return getattr(state, "name", "") in ("CLOSING", "DRAINING", "TERMINATED")

    def close(self):
        """关闭 QUIC 连接"""
        try:
            self._quic.close()
            self._flush()
        except Exception as e:
            logger.debug("DoQ 连接关闭异常: %s", e)


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
        self._loop = asyncio.get_running_loop()
        self._timer_task = self._loop.create_task(self._timer_loop())
        logger.debug("DoQ UDP 监听已建立")

    async def _timer_loop(self):
        """周期推进各 QUIC 连接的定时器（PTO 重传 / idle timeout）"""
        while not self._closed:
            await asyncio.sleep(0.25)
            now = asyncio.get_running_loop().time()
            for conn in list(self._connections.values()):
                timer = conn.get_timer()
                if timer is not None and timer <= now:
                    conn.handle_timer(now)

    def datagram_received(self, data: bytes, addr: tuple):
        if self._closed:
            return
        # 先解析 QUIC 头拿到 DCID：服务端必须用它初始化/查找连接（aioquic 1.x 要求）
        try:
            header = pull_quic_header(
                Buffer(data=data),
                host_cid_length=self._quic_config.connection_id_length,
            )
        except Exception as e:
            logger.debug("DoQ 无法解析 QUIC 头，丢弃 %s 的数据报: %s", addr[0], e)
            return
        dcid = header.destination_cid
        conn = self._connections.get(dcid)
        if conn is None:
            # QUIC 连接迁移：源端口变化时按对端地址（host）回退查找
            for c in list(self._connections.values()):
                if getattr(c, "_addr", None) and c._addr[0] == addr[0]:
                    conn = c
                    break
        if conn is None:
            # 最大 QUIC 连接数限制
            if len(self._connections) >= self._max_connections:
                logger.warning("DoQ 超出最大连接数 %d，丢弃 %s 的数据报", self._max_connections, addr[0])
                return
            conn = _DoQConnection(
                self._server, self._quic_config, self.transport, addr,
                original_destination_connection_id=dcid,
            )
            self._connections[dcid] = conn
        conn.receive_datagram(data)

    def error_received(self, exc):
        logger.debug("DoQ UDP 错误: %s", exc)

    def connection_lost(self, exc):
        self._closed = True
        self._connections.clear()
        task = getattr(self, "_timer_task", None)
        if task is not None and not task.done():
            task.cancel()

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
            self.config = None
            self.resolver_manager = None
            self.cache = None
            self.filter_engine = None
            self.request_logger = None
            self._dnssec_wrapper = None
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

        # 单 IP 限速（共享 PerIPRateLimiter 单例）
        self._per_ip_limiter = get_per_ip_limiter(
            per_ip_limit=config.max_concurrent_per_ip,
        )
        self._per_ip_limit = config.max_concurrent_per_ip

        # 最大 QUIC 连接数限制
        self._max_doq_connections = config.doq_max_connections

        # QPS 限速（所有客户端包括 localhost）
        self._qps_limiter = QPSCounter(config.doq_qps_limit, "DoQ")

        # 查询任务引用（防止 create_task 的异常无人回收）
        self._tasks: set = set()

    def _track_task(self, task: asyncio.Task):
        """保存后台任务引用并在完成后清理，避免异常无人回收"""
        self._tasks.add(task)

        def _done(t: asyncio.Task):
            self._tasks.discard(t)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    logger.debug("DoQ 后台任务异常: %s", exc)

        task.add_done_callback(_done)

    @staticmethod
    def _make_servfail_wire(wire_data: bytes) -> Optional[bytes]:
        """构造带查询 ID 的 SERVFAIL 响应；无法解析时返回 None"""
        try:
            query = dns.message.from_wire(wire_data)
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            response.id = query.id
            return response.to_wire()
        except Exception:
            return None

    @staticmethod
    def _make_cache_key(question, query) -> tuple:
        """缓存键 = (name, rdtype, rdclass, DO 位, CD 位)

        RFC 6891/4035：带 DO 的查询可能需要 RRSIG，CD=1 表示跳过校验，
        响应形态不同；只用 (name,type,class) 会让它们互相命中。
        """
        try:
            do_bit = bool(query.edns >= 0 and (query.ednsflags & dns.flags.DO))
        except Exception:
            do_bit = False
        try:
            cd_bit = bool(query.flags & dns.flags.CD)
        except Exception:
            cd_bit = False
        return (question.name, question.rdtype, question.rdclass, do_bit, cd_bit)

    @staticmethod
    def _is_negative_response(msg) -> bool:
        """RFC 2308：NXDOMAIN 或 NODATA（NOERROR 且无 answer）为负应答

        原实现漏判 NODATA，使其按 default_ttl(300s) 缓存（配置 negative_ttl=60s）。
        """
        try:
            rcode = msg.rcode()
        except Exception:
            return False
        if rcode in (dns.rcode.NXDOMAIN, dns.rcode.REFUSED):
            return True
        return rcode == dns.rcode.NOERROR and not msg.answer

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        return await self._per_ip_limiter.acquire(client_ip)

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
                family=socket.AF_INET,
            )
            logger.info(
                "本地 DoQ [IPv4] quic://%s:%d (域名: %s)",
                self.host if self.host != "0.0.0.0" else "127.0.0.1",  # nosec B104 - display formatting, not binding
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
                    family=socket.AF_INET6,
                )
                logger.info(
                    "本地 DoQ [IPv6] quic://[%s]:%d (域名: %s)",
                    self.ipv6_host, self.ipv6_port, self.domain or "未设置",
                )
            except OSError as e:
                logger.warning("DoQ [IPv6] 启动失败（跳过）: %s", e)

        # 启动连接清理任务
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        if self._transport_v4 is None and self._transport_v6 is None:
            logger.error("本地 DoQ 未能监听任何地址（IPv4/IPv6 全部失败），服务不可用")

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
                except Exception as e:
                    logger.debug("DoQ 传输关闭异常: %s", e)
        self._transport_v4 = None
        self._transport_v6 = None
        self._protocol_v4 = None
        self._protocol_v6 = None
        self._quic_config = None
        logger.info("本地 DoQ 服务器已停止")

    async def _cleanup_loop(self):
        """定期清理已关闭的 QUIC 连接（IP 限速条目由 PerIPRateLimiter 管理）"""
        while True:
            try:
                await asyncio.sleep(30)
                if self._protocol_v4:
                    self._protocol_v4.cleanup_stale_connections()
                if self._protocol_v6:
                    self._protocol_v6.cleanup_stale_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("DoQ 清理循环异常: %s", e)

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
            # 缓存键含 DO/CD 维度：不同 DNSSEC 需求的查询不应互相命中
            cache_key = self._make_cache_key(question, query)

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
                    # AAAA 优先于 A 排序
                    reorder_answer_aaaa_first(response)
                    response_wire = response.to_wire()
                    status = "custom_hosts"
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    await self._log_query(client_ip, qname, qtype_name, status, block_reason)
                    return response_wire

            # 0b. 检查自定义 hosts 白名单（纯域名绕过，无自定义IP）
            is_hosts_bypass = self.filter_engine.is_custom_hosts_bypass(qname)

            # 1. 域名过滤
            if self.config.filter_enabled and not is_hosts_bypass:
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
                        response.answer[0].add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0"), ttl=3600)  # nosec B104 - blocked A record, not binding
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
                        await self.cache.set(
                            cache_key, response,
                            response.rcode() == dns.rcode.NXDOMAIN,
                        )
                    await self._log_query(client_ip, qname, qtype_name, status, block_reason)
                    return response_wire

            # 2. 缓存
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    import copy
                    cached = copy.copy(cached)
                    cached.id = query.id
                    # AAAA 优先于 A 排序
                    reorder_answer_aaaa_first(cached)
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
                        # AAAA 优先于 A 排序（确保缓存中数据顺序一致）
                        reorder_answer_aaaa_first(response_msg)
                        is_negative = self._is_negative_response(response_msg)
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception as e:
                        logger.debug("DoQ 缓存写入异常: %s", e)

            await self._log_query(client_ip, qname, qtype_name, status, block_reason)

            # AAAA 优先于 A 排序（仅对成功解析的上游响应）
            if response_wire is not None and status == "resolved":
                response_wire = sort_dns_response_wire(response_wire)

            # 上游直连路径的响应 ID 可能与查询不一致：DoH（RFC 8484）与 DoQ
            # （RFC 9250）上游按协议要求用 ID=0 发起查询，其响应 ID 会被原样
            # 透传给客户端。DoQ 客户端校验 ID，收到不一致的 ID 会丢弃响应并
            # 等待超时（表现为查询卡顿），故在返回前统一重写为查询 ID。
            # 对 make_response(query) 生成的响应（ID 本已正确）是幂等的。
            if response_wire:
                try:
                    _resp = dns.message.from_wire(response_wire)
                    if _resp.id != query.id:
                        _resp.id = query.id
                        response_wire = _resp.to_wire()
                except Exception as e:
                    logger.debug("DoQ 响应 ID 重写异常: %s", e)

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
        except Exception as e:
            logger.debug("DoQ 查询日志记录异常: %s", e)

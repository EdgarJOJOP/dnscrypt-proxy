"""
DNS over QUIC (DoQ) 解析器
- 强制 Transaction ID = 0（RFC 9250）
- 标准 ALPN "doq"（不尝试 doq-i11/dq 等旧版本）
- 2 字节长度前缀（RFC 9250 标准）
- **持久连接池**：复用 QUIC 连接，避免每查询新建 UDP 套接字
"""
import asyncio
import logging
import ssl
import struct
import time
from typing import List, Optional, Dict, Tuple

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.doq")

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import (
        QuicEvent,
        StreamDataReceived,
        HandshakeCompleted,
        ConnectionTerminated,
    )
    from aioquic.tls import SessionTicket
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False
    QuicConnection = None
    SessionTicket = None

# 只使用标准ALPN "doq"（RFC 9250），不尝试旧版本
DEFAULT_ALPN_VERSIONS = ["doq"]

# 全局 DoQ 并发限制（限制同时进行的 QUIC 连接数）
# 由 set_doq_global_concurrency() 初始化（读取 connection_pool_size 配置）
_DOQ_GLOBAL_SEMAPHORE = None
_DOQ_GLOBAL_CONCURRENCY = 100  # 默认值，set_doq_global_concurrency 会覆盖


def set_doq_global_concurrency(size: int):
    """从配置中设置全局 DoQ 并发限制"""
    global _DOQ_GLOBAL_SEMAPHORE, _DOQ_GLOBAL_CONCURRENCY
    _DOQ_GLOBAL_CONCURRENCY = max(1, size)
    _DOQ_GLOBAL_SEMAPHORE = asyncio.Semaphore(_DOQ_GLOBAL_CONCURRENCY)
    logger.debug("DoQ 全局并发限制设为 %d", _DOQ_GLOBAL_CONCURRENCY)


def force_dns_id_zero(query: bytes) -> bytes:
    """RFC 9250: DoQ消息的Transaction ID必须为0"""
    if len(query) >= 2:
        return b'\x00\x00' + query[2:]
    return query


# 每次连接尝试的超时（单个 IP + 单个模式的尝试，非总超时）
_ATTEMPT_TIMEOUT = 5.0

# 空闲连接保活时间（秒）
_IDLE_KEEPALIVE = 30.0

# 连接健康检查间隔
_HEALTH_CHECK_INTERVAL = 10.0


if HAS_AIOQUIC:

    class _PooledQuicProtocol(asyncio.DatagramProtocol):
        """
        支持多流复用的 QUIC 协议处理器。
        一个 QUIC 连接可承载多个并发的 DNS 查询（不同 stream_id），
        每个查询的结果通过对应的 Future 返回。
        """

        def __init__(self, quic: QuicConnection):
            self._quic = quic
            self._transport: Optional[asyncio.DatagramTransport] = None
            self._stream_futures: Dict[int, asyncio.Future] = {}
            self._recv_buffers: Dict[int, bytearray] = {}
            self._closed = False
            self._connected = False
            self._connected_future: Optional[asyncio.Future] = None
            self._close_reason = ""

        def set_connected_future(self, future: asyncio.Future):
            """设置握手完成的 Future（由连接管理器使用）"""
            self._connected_future = future

        def connection_made(self, transport: asyncio.DatagramTransport):
            self._transport = transport

        def connection_lost(self, exc: Optional[Exception]):
            self._closed = True
            self._connected = False
            # 唤醒所有等待的 Future，避免泄漏
            err = ConnectionError(f"QUIC 连接断开: {exc or self._close_reason or 'unknown'}")
            for stream_id, fut in list(self._stream_futures.items()):
                if not fut.done():
                    fut.set_exception(err)
            self._stream_futures.clear()
            self._recv_buffers.clear()
            if self._connected_future and not self._connected_future.done():
                self._connected_future.set_exception(err)

        def error_received(self, exc: Exception):
            logger.debug("DoQ UDP 错误: %s", exc)

        def datagram_received(self, data: bytes, addr: Tuple):
            if self._closed:
                return
            try:
                now = time.time()
                self._quic.receive_datagram(data, addr, now=now)
                self._process_quic_events(now)
                self._flush_send(now)
            except Exception as e:
                logger.debug("DoQ 处理数据报异常: %s", e)

        def _process_quic_events(self, now: float):
            """处理 QUIC 事件并分发给对应 stream 的 Future"""
            for event in self._quic.next_send_events(now=now):
                try:
                    if isinstance(event, HandshakeCompleted):
                        self._connected = True
                        if self._connected_future and not self._connected_future.done():
                            self._connected_future.set_result(True)
                        logger.debug("DoQ 握手完成 (early_data_accepted=%s)",
                                     event.early_data_accepted)

                    elif isinstance(event, StreamDataReceived):
                        buf = self._recv_buffers.get(event.stream_id)
                        if buf is None:
                            buf = bytearray()
                            self._recv_buffers[event.stream_id] = buf
                        buf.extend(event.data)

                        if event.end_stream:
                            future = self._stream_futures.pop(event.stream_id, None)
                            self._recv_buffers.pop(event.stream_id, None)
                            if future and not future.done():
                                if len(buf) >= 2:
                                    length = struct.unpack("!H", buf[:2])[0]
                                    dns_data = bytes(buf[2:2 + length])
                                    if dns_data:
                                        future.set_result(dns_data)
                                        continue
                                future.set_exception(
                                    ConnectionError("无效的 DoQ 响应")
                                )

                    elif isinstance(event, ConnectionTerminated):
                        self._closed = True
                        self._connected = False
                        self._close_reason = event.reason_phrase or ""
                        # 通知所有等待的 Future
                        err = ConnectionError(
                            f"DoQ 连接关闭: code={event.error_code}, "
                            f"reason={self._close_reason}"
                        )
                        for sid, fut in list(self._stream_futures.items()):
                            if not fut.done():
                                fut.set_exception(err)
                        self._stream_futures.clear()
                        self._recv_buffers.clear()
                        if self._connected_future and not self._connected_future.done():
                            self._connected_future.set_exception(err)
                        # 修复：QUIC 连接断开后必须关闭 UDP transport，
                        # 否则 create_datagram_endpoint 创建的 UDP 套接字泄漏
                        self._close_transport()

                except Exception as e:
                    logger.debug("DoQ 解析器连接异常: %s", e)

        def _close_transport(self):
            """安全关闭 UDP transport（释放端口，避免泄漏）"""
            if self._transport and not self._transport.is_closing():
                try:
                    self._transport.close()
                except Exception as e:
                    logger.debug("DoQ 解析器关闭传输异常: %s", e)

        def _flush_send(self, now: float):
            """发送 QUIC 缓冲的数据报"""
            if self._transport and not self._transport.is_closing():
                for data, addr in self._quic.send_flow_control_offered(now=now):
                    try:
                        self._transport.sendto(data, addr)
                    except Exception as e:
                        logger.debug("DoQ 解析器发送异常: %s", e)

        async def send_query(self, query_bytes: bytes,
                             enforce_id_zero: bool = True) -> Optional[bytes]:
            """
            在持久连接上发送 DNS 查询，返回响应。
            使用新的 QUIC stream，不会阻塞同一连接上的其他查询。
            """
            if self._closed or (self._transport and self._transport.is_closing()):
                raise ConnectionError("QUIC 连接已关闭")

            fixed = force_dns_id_zero(query_bytes) if enforce_id_zero else query_bytes
            frame = struct.pack("!H", len(fixed)) + fixed

            stream_id = self._quic.get_next_available_stream_id()
            future = asyncio.get_event_loop().create_future()
            self._stream_futures[stream_id] = future

            self._quic.send_stream_data(stream_id, frame, end_stream=True)
            self._flush_send(time.time())

            try:
                return await asyncio.wait_for(future, timeout=10.0)
            except asyncio.TimeoutError:
                self._stream_futures.pop(stream_id, None)
                self._recv_buffers.pop(stream_id, None)
                raise

        def close(self):
            """关闭 QUIC 连接"""
            self._closed = True
            try:
                self._quic.close()
                self._flush_send(time.time())
            except Exception as e:
                logger.debug("DoQ 解析器关闭异常: %s", e)
            self._close_transport()

        @property
        def is_closed(self) -> bool:
            return self._closed or self._quic.is_closed()

    class _QuicConnectionHandle:
        """
        持久 QUIC 连接句柄。
        在后台保持连接活跃，管理多个并发的 DNS 查询。
        """

        def __init__(self, target: str, port: int,
                     config_factory, timeout: float = 15.0,
                     session_ticket_callback=None):
            self._target = target
            self._port = port
            self._config_factory = config_factory
            self._timeout = timeout
            self._session_ticket_callback = session_ticket_callback
            self._protocol: Optional[_PooledQuicProtocol] = None
            self._lock = asyncio.Lock()
            self._last_used = 0.0
            self._cleanup_task: Optional[asyncio.Task] = None
            self._closed = False

        async def connect(self):
            """建立 QUIC 连接（等待握手完成或超时）"""
            config = self._config_factory()
            quic = QuicConnection(
                configuration=config,
                session_ticket_handler=self._session_ticket_callback,
            )
            protocol = _PooledQuicProtocol(quic)

            connected_future = asyncio.get_event_loop().create_future()
            protocol.set_connected_future(connected_future)

            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(self._target, self._port),
            )

            self._protocol = protocol
            self._last_used = time.time()

            # 等待握手完成（超时则关闭连接）
            try:
                await asyncio.wait_for(connected_future, timeout=self._timeout)
            except asyncio.TimeoutError:
                logger.debug("DoQ %s:%d 握手超时", self._target, self._port)
                protocol.close()
                self._protocol = None
                raise

            # 启动后台保活/健康检查任务
            self._cleanup_task = asyncio.create_task(self._keepalive_loop())

        async def _keepalive_loop(self):
            """后台保活循环：定期刷新数据、检查连接健康"""
            while not self._closed:
                await asyncio.sleep(_HEALTH_CHECK_INTERVAL)
                try:
                    if self._protocol is None or self._protocol.is_closed:
                        break
                    now = time.time()
                    # 处理 QUIC 事件（如空闲超时 → ConnectionTerminated）
                    self._protocol._process_quic_events(now)
                    # 发送保活/ACK
                    self._protocol._flush_send(now)
                    # 如果空闲太久，关闭连接
                    if now - self._last_used > _IDLE_KEEPALIVE:
                        logger.debug("DoQ %s:%d 空闲超时，关闭连接",
                                     self._target, self._port)
                        self._protocol.close()
                        break
                except Exception:
                    break

        async def execute(self, query_bytes: bytes) -> Optional[bytes]:
            """在持久连接上执行 DNS 查询（QUIC 多路复用，无需串行化锁）"""
            if self._protocol is None or self._protocol.is_closed:
                raise ConnectionError("连接不可用")

            # QUIC 原生支持多流复用，多个 send_query 可并发
            self._last_used = time.time()
            try:
                return await self._protocol.send_query(query_bytes)
            except ConnectionError:
                self._protocol.close()
                raise

        async def close(self):
            """关闭连接"""
            self._closed = True
            if self._cleanup_task and not self._cleanup_task.done():
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
            if self._protocol:
                self._protocol.close()
            self._protocol = None

    class _QuicConnectionPool:
        """
        DoQ 连接池：按目标 IP 管理持久 QUIC 连接。
        - 每个目标 IP 最多一个持久连接
        - 空闲超过 _IDLE_KEEPALIVE 自动关闭
        - 连接断开后自动重建
        """

        def __init__(self, host: str, port: int, config_factory,
                     timeout: float, connect_ips: List[str],
                     session_ticket_callback=None):
            self._host = host
            self._port = port
            self._config_factory = config_factory
            self._timeout = timeout
            self._connect_ips = connect_ips
            self._session_ticket_callback = session_ticket_callback
            self._handles: Dict[str, _QuicConnectionHandle] = {}
            self._lock = asyncio.Lock()
            self._target_locks: Dict[str, asyncio.Lock] = {}
            self._closed = False

        def _get_targets(self) -> List[str]:
            """返回连接目标列表（hostname + bootstrap IPs）"""
            targets = [self._host]
            for ip in self._connect_ips:
                if ip not in targets:
                    targets.append(ip)
            return targets

        def _get_target_lock(self, target: str) -> asyncio.Lock:
            """获取 per-target 连接锁（asyncio 单线程，无需额外保护）"""
            if target not in self._target_locks:
                self._target_locks[target] = asyncio.Lock()
            return self._target_locks[target]

        async def _get_or_create_handle(
            self, target: str
        ) -> Optional[_QuicConnectionHandle]:
            """
            线程安全地获取或创建目标连接。
            使用 per-target 锁 + double-check 模式：
            - 只在首次需要连接时加锁等待
            - 连接建立后，后续并发协程直接复用
            """
            # 快速路径：已有可用连接
            handle = self._handles.get(target)
            if handle and handle._protocol and not handle._protocol.is_closed:
                return handle

            # Per-target 锁：同时只有一个协程创建此目标的连接
            async with self._get_target_lock(target):
                # Double-check：等锁期间可能有其他协程已建好连接
                handle = self._handles.get(target)
                if handle and handle._protocol and not handle._protocol.is_closed:
                    return handle

                # 创建新连接
                try:
                    handle = _QuicConnectionHandle(
                        target, self._port, self._config_factory, self._timeout,
                        session_ticket_callback=self._session_ticket_callback,
                    )
                    await asyncio.wait_for(
                        handle.connect(), timeout=_ATTEMPT_TIMEOUT
                    )
                    async with self._lock:
                        old = self._handles.get(target)
                        if old:
                            await old.close()
                        self._handles[target] = handle
                    return handle
                except (ConnectionError, asyncio.TimeoutError, OSError) as e:
                    if handle:
                        await handle.close()
                    raise

        async def execute(self, query_bytes: bytes) -> Optional[bytes]:
            """
            在持久连接上执行 DNS 查询。
            依次尝试每个目标 IP，每个目标 IP 最多维持一个连接。
            """
            last_error = None
            targets = self._get_targets()

            for target in targets:
                try:
                    handle = await self._get_or_create_handle(target)
                    return await handle.execute(query_bytes)
                except (ConnectionError, asyncio.TimeoutError) as e:
                    last_error = e
                    # 连接失效，从缓存中移除
                    async with self._lock:
                        self._handles.pop(target, None)
                    cert_err = str(e).lower()
                    if "certificate" in cert_err or "hostname" in cert_err:
                        logger.warning(
                            "%s 证书验证失败，跳过", target
                        )
                        break
                    continue

            if last_error:
                logger.debug(
                    "DoQ %s 所有目标均失败: %s", self._host, last_error
                )
            return None

        async def close_all(self):
            """关闭所有连接"""
            self._closed = True
            async with self._lock:
                for target, handle in list(self._handles.items()):
                    await handle.close()
                self._handles.clear()

        async def reset(self):
            """重置所有连接（网络恢复时调用）"""
            await self.close_all()


    class DoQResolver(BaseResolver):
        """符合RFC 9250的DoQ解析器（支持持久连接池）"""

        def __init__(self, address: str, timeout: float = 15.0,
                     connect_ips: Optional[list] = None, concurrency: int = 100,
                     verify_cert: bool = True,
                     alpn_versions: Optional[List[str]] = None,
                     ca_path: str = ""):
            super().__init__(address, timeout, concurrency=concurrency)
            raw = address.replace("quic://", "")
            if ":" in raw:
                self.host, port_str = raw.split(":")
                self.port = int(port_str)
            else:
                self.host = raw
                self.port = 853
            self._verify_cert = verify_cert
            self._connect_ips = connect_ips or []
            self._ca_path = ca_path
            self._alpn_versions = alpn_versions or DEFAULT_ALPN_VERSIONS
            self._session_ticket: Optional["SessionTicket"] = None

            if not HAS_AIOQUIC:
                logger.warning("aioquic未安装，DoQ %s不可用", self.host)

            self._config_cache: Dict = {}
            # 连接池
            self._pool: Optional[_QuicConnectionPool] = None
            self._pool_closed = False

        def _get_config(self, alpn: str) -> Optional["QuicConfiguration"]:
            if not HAS_AIOQUIC:
                return None

            cache_key = (self.host, alpn, self._verify_cert, self._ca_path)
            if cache_key in self._config_cache:
                return self._config_cache[cache_key]

            verify = ssl.CERT_REQUIRED if self._verify_cert else ssl.CERT_NONE
            config = QuicConfiguration(
                alpn_protocols=[alpn],
                is_client=True,
                verify_mode=verify,
                server_name=self.host,
            )
            # 自定义 CA 证书包（只信任自定义 CA，不加载系统默认 CA）
            if self._verify_cert and self._ca_path:
                try:
                    config.load_verify_locations(cafile=self._ca_path)
                    logger.info("DoQ %s: 使用自定义 CA 证书（系统默认 CA 已禁用）", self.host)
                except Exception as e:
                    logger.critical(
                        "DoQ %s: 加载自定义 CA 证书失败: %s，系统 CA 不可信，程序退出",
                        self.host, e,
                    )
                    raise SystemExit(1)
            config.max_data = 10_000_000
            config.max_stream_data = 1_000_000
            # 空闲超时设为 60 秒（避免因 _ATTEMPT_TIMEOUT 过短导致连接频繁断开）
            # 实际空闲清理由 _QuicConnectionHandle._keepalive_loop 的 _IDLE_KEEPALIVE(30s) 控制
            config.idle_timeout = 60.0
            # 0-RTT 会话恢复：复用上次的 session ticket
            if self._session_ticket is not None:
                config.session_ticket = self._session_ticket

            self._config_cache[cache_key] = config
            return config

        def _config_factory(self):
            """创建 QUIC 配置（供连接池使用）"""
            return self._get_config(self._alpn_versions[0])

        def _save_session_ticket(self, ticket):
            """保存 session ticket 供后续 0-RTT 复用"""
            self._session_ticket = ticket

        async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
            if not HAS_AIOQUIC:
                return None

            # 延迟初始化连接池
            if self._pool is None or self._pool_closed:
                self._pool = _QuicConnectionPool(
                    self.host, self.port, self._config_factory,
                    self.timeout, self._connect_ips,
                    session_ticket_callback=self._save_session_ticket,
                )
                self._pool_closed = False

            async with self._semaphore:
                # 全局 DoQ 并发限制（懒初始化，从 connection_pool_size 读取）
                global _DOQ_GLOBAL_SEMAPHORE
                sem = _DOQ_GLOBAL_SEMAPHORE
                if sem is None:
                    sem = asyncio.Semaphore(_DOQ_GLOBAL_CONCURRENCY)
                    _DOQ_GLOBAL_SEMAPHORE = sem
                async with sem:
                    return await self._pool.execute(query_bytes)

        async def close(self):
            """关闭所有连接和缓存配置"""
            self._pool_closed = True
            if self._pool:
                await self._pool.close_all()
                self._pool = None
            self._config_cache.clear()
            logger.debug("DoQ解析器 %s 已关闭", self.host)

        async def reset_connections(self):
            """重置连接状态（网络恢复时调用）"""
            self._pool_closed = True
            if self._pool:
                await self._pool.close_all()
                self._pool = None
            self._config_cache.clear()
            logger.debug("DoQ解析器 %s 连接已重置", self.host)


else:
    # aioquic 不可用时的桩实现
    class DoQResolver(BaseResolver):
        def __init__(self, address: str, timeout: float = 15.0,
                     connect_ips: Optional[list] = None, concurrency: int = 100,
                     verify_cert: bool = True,
                     alpn_versions: Optional[List[str]] = None,
                     ca_path: str = ""):
            super().__init__(address, timeout, concurrency=concurrency)
            self.host = address
            self.port = 853
            logger.warning("aioquic未安装，DoQ %s不可用", self.host)

        async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
            return None

        async def close(self):
            pass

        async def reset_connections(self):
            pass

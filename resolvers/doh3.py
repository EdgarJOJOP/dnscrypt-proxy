"""
DNS over HTTPS over HTTP/3（DoH3：RFC 9114 + RFC 8484）

为什么单独实现：httpx 0.28.x 移除了实验性的 ``http3`` 参数（``httpx[http3]``
extra 在 0.28 起不再提供），而本项目的策略要求**上游加密 DNS 优先 HTTP/3**。
项目已因 DoQ 依赖 aioquic，这里直接复用 aioquic 的 QUIC + HTTP/3 栈实现
DoH3 客户端，不引入任何新依赖。

特性：
  - 一条 QUIC 连接多流复用（每次查询一个双向流，RFC 9114 §6）；
  - bootstrap IP 直连（IP pinning）+ ``server_name`` = 域名——证书仍按域名校验，
    不会因为连的是 IP 而放宽验证；
  - 自定义 CA（tls.ca_path）与严格的证书链校验（CERT_REQUIRED）；
  - 服务器不支持 h3（例如只监听 TCP/443）时快速失败，由上层 DoHResolver
    记负缓存并降级到 HTTP/2。

安全说明：aioquic 目前不实现 ECH，因此启用 ECH 的上游不走本模块（否则 SNI
会明文泄漏，反而削弱隐私），由 DoHResolver 强制走 HTTP/2 + Python ssl(ECH)。
"""

import asyncio
import logging
import ssl
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("dns-proxy.resolver.doh3")

try:
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

    HAS_AIOQUIC = True
except ImportError:  # pragma: no cover - 缺少 aioquic 时自动禁用 HTTP/3
    HAS_AIOQUIC = False
    QuicConnectionProtocol = object
    H3_ALPN = ["h3"]
    H3Connection = None

# HTTP/3 响应体上限（DNS 报文最大 65535 字节，留余量；防内存滥用）
MAX_DOH3_BODY = 131072

# H3_EXCESSIVE_LOAD（RFC 9114 §8.1）：用于重置超限/异常的流
_H3_EXCESSIVE_LOAD = 0x0107


def ordered_endpoints(ips, prefer_v6: bool = True, limit: int = 2):
    """按「首选地址族优先 + 另一族兜底」排序 IP 列表（去重 + 截断）

    先放首选族第 1 个、再放另一族第 1 个，然后按首族顺序补齐。
    这样「IPv6 优先」不会因为某个 v6 地址被阻断/黑洞而完全没有 v4 机会
    （上游常同时有 A/AAAA，只认一族会让整条 h3/h2 路径白白失败）。
    """
    ips = [str(ip) for ip in (ips or [])]
    v6 = [ip for ip in ips if ":" in ip]
    v4 = [ip for ip in ips if ":" not in ip]
    primary, secondary = (v6, v4) if prefer_v6 else (v4, v6)
    merged = []
    for group in (primary[:1], secondary[:1], primary[1:], secondary[1:]):
        for ip in group:
            if ip not in merged:
                merged.append(ip)
    return merged[:limit] if limit > 0 else merged



if HAS_AIOQUIC:

    class _DoH3Protocol(QuicConnectionProtocol):
        """一条 QUIC 连接上的 HTTP/3 客户端协议（多流复用，请求按 stream_id 分发）"""

        def __init__(self, quic):
            super().__init__(quic)
            self._h3 = H3Connection(quic)
            # stream_id -> {"future": Future, "body": bytearray, "status": int}
            self._streams: Dict[int, dict] = {}
            self.terminated = False
            self.handshake_done = asyncio.get_running_loop().create_future()

        @property
        def alive(self) -> bool:
            """连接是否仍可用于新查询"""
            try:
                closed = self._closed.is_set()
            except Exception:
                closed = True
            return (not self.terminated) and (not closed)

        # ---------- 内部状态 ----------

        def _mark_handshake(self, exc: Optional[BaseException] = None) -> None:
            fut = self.handshake_done
            if fut.done():
                return
            if exc is None:
                fut.set_result(True)
            else:
                fut.set_exception(exc)

        def _fail_stream(self, stream_id: int, exc: BaseException) -> None:
            """让某个流的等待者收到异常，并重置该流（避免对端继续发送）"""
            stream = self._streams.pop(stream_id, None)
            if stream is None:
                return
            fut = stream["future"]
            if not fut.done():
                fut.set_exception(exc)
            try:
                self._quic.reset_stream(stream_id, error_code=_H3_EXCESSIVE_LOAD)
                self.transmit()
            except Exception:
                pass

        def _fail_all(self, exc: BaseException) -> None:
            for stream_id in list(self._streams):
                self._fail_stream(stream_id, exc)

        def _finish_stream(self, stream_id: int) -> None:
            stream = self._streams.pop(stream_id, None)
            if stream is None:
                return
            fut = stream["future"]
            if not fut.done():
                fut.set_result((stream["status"], bytes(stream["body"])))

        # ---------- QUIC 事件 ----------

        def quic_event_received(self, event) -> None:
            if isinstance(event, HandshakeCompleted):
                logger.debug("DoH3: QUIC 握手完成（ALPN=%s）", event.alpn_protocol)
                self._mark_handshake()
                return
            if isinstance(event, ConnectionTerminated):
                self.terminated = True
                reason = (
                    "HTTP/3 连接终止（error_code=0x{:x}, reason={!r}）".format(
                        event.error_code, event.reason_phrase
                    )
                )
                logger.debug("DoH3: %s", reason)
                self._mark_handshake(ConnectionError(reason))
                self._fail_all(ConnectionError(reason))
                return
            try:
                h3_events = self._h3.handle_event(event)
            except Exception as e:  # aioquic 内部异常不应影响其它在飞查询
                logger.debug("DoH3: H3 事件处理异常: %s", e)
                return
            for h3_event in h3_events:
                stream = self._streams.get(h3_event.stream_id)
                if stream is None:
                    continue
                if isinstance(h3_event, HeadersReceived):
                    for name, value in h3_event.headers:
                        if name == b":status":
                            try:
                                stream["status"] = int(value)
                            except (TypeError, ValueError):
                                pass
                    if h3_event.stream_ended:
                        self._finish_stream(h3_event.stream_id)
                elif isinstance(h3_event, DataReceived):
                    if len(stream["body"]) + len(h3_event.data) > MAX_DOH3_BODY:
                        logger.debug(
                            "DoH3: 响应体超限（stream=%d），重置该流",
                            h3_event.stream_id,
                        )
                        self._fail_stream(
                            h3_event.stream_id,
                            ValueError("HTTP/3 响应体过大"),
                        )
                        continue
                    stream["body"].extend(h3_event.data)
                    if h3_event.stream_ended:
                        self._finish_stream(h3_event.stream_id)

        # ---------- 请求 ----------

        async def post(
            self, authority: str, path: str, body: bytes
        ) -> Tuple[int, bytes]:
            """在一条新流上发送 DoH POST，返回 (status, body)"""
            if self.terminated:
                raise ConnectionError("HTTP/3 连接已终止")
            stream_id = self._quic.get_next_available_stream_id()
            fut = asyncio.get_running_loop().create_future()
            self._streams[stream_id] = {
                "future": fut,
                "body": bytearray(),
                "status": 0,
            }
            headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", authority.encode("ascii")),
                (b":path", path.encode("ascii")),
                (b"content-type", b"application/dns-message"),
                (b"accept", b"application/dns-message"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"user-agent", b"dnscrypt-proxy-doh3"),
            ]
            try:
                self._h3.send_headers(stream_id, headers, end_stream=False)
                self._h3.send_data(stream_id, body, end_stream=True)
                self.transmit()
            except Exception:
                self._streams.pop(stream_id, None)
                raise
            try:
                return await fut
            except asyncio.CancelledError:
                # 调用方超时/取消：清理流状态，避免 future 永远挂起
                self._streams.pop(stream_id, None)
                if not fut.done():
                    fut.cancel()
                try:
                    self._quic.reset_stream(stream_id, error_code=_H3_EXCESSIVE_LOAD)
                    self.transmit()
                except Exception:
                    pass
                raise


class DoH3Client:
    """DoH over HTTP/3 客户端（每个上游 DoH URL 一个实例，惰性建连 + 断线重连）"""

    def __init__(
        self,
        hostname: str,
        port: int = 443,
        path: str = "/dns-query",
        connect_ips: Optional[List[str]] = None,
        ca_path: str = "",
        timeout: float = 5.0,
        connect_timeout: float = 1.5,
        idle_timeout: float = 90.0,
    ):
        self.hostname = hostname
        self.port = int(port or 443)
        self.path = path if path.startswith("/") else "/" + str(path or "dns-query")
        self.connect_ips = list(connect_ips or [])
        self.ca_path = ca_path or ""
        self.timeout = float(timeout)
        # 握手超时必须短：服务器不支持 h3 时尽快失败并降级到 h2
        self.connect_timeout = float(connect_timeout)
        self.idle_timeout = float(idle_timeout)
        self._lock = asyncio.Lock()
        self._proto = None
        self._transport = None
        self.last_target = ""

    @staticmethod
    def available() -> bool:
        """当前环境是否具备 HTTP/3 能力（aioquic 可用）"""
        return HAS_AIOQUIC

    # ---------- 内部 ----------

    def _targets(self) -> List[str]:
        """候选连接目标：优先 bootstrap IP 直连（避免系统 DNS 自引用/污染）。

        **IPv6 优先 + 跨族兜底**（ordered_endpoints）：先 v6，再 v4；两个目标
        各分一半握手预算，v6 被阻断时仍能落到 v4，不会整条 h3 路径直接失败。
        """
        ips = [str(ip) for ip in self.connect_ips] or [self.hostname]
        return ordered_endpoints(ips, prefer_v6=True, limit=2)

    def _build_configuration(self) -> "QuicConfiguration":
        cfg = QuicConfiguration(
            is_client=True,
            alpn_protocols=list(H3_ALPN),
            # 证书始终按域名校验（即使连的是 bootstrap IP）
            server_name=self.hostname,
            verify_mode=ssl.CERT_REQUIRED,
            idle_timeout=self.idle_timeout,
        )
        if self.ca_path:
            cfg.load_verify_locations(cafile=self.ca_path)
        # ca_path 为空时 aioquic 自动使用 certifi 根证书库
        return cfg

    @staticmethod
    def _shutdown(proto, transport) -> None:
        if proto is not None:
            # 先唤醒所有在飞请求（否则它们要等到 timeout 才失败）
            try:
                proto._fail_all(ConnectionError("HTTP/3 连接已关闭"))
            except Exception:
                pass
            try:
                proto.close()
            except Exception:
                pass
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass

    async def _connect_one(self, target: str, timeout: float) -> None:
        quic = QuicConnection(configuration=self._build_configuration())
        loop = asyncio.get_running_loop()
        transport = None
        proto = None
        try:
            transport, proto = await loop.create_datagram_endpoint(
                lambda: _DoH3Protocol(quic),
                remote_addr=(target, self.port),
            )
            proto.connect((target, self.port), transmit=True)
            await asyncio.wait_for(
                asyncio.shield(proto.handshake_done), timeout
            )
        except asyncio.TimeoutError:
            if proto is not None and not proto.handshake_done.done():
                proto.handshake_done.cancel()
            self._shutdown(proto, transport)
            raise asyncio.TimeoutError(
                "HTTP/3 握手超时（{:.1f}s）".format(timeout)
            )
        except Exception:
            if proto is not None and not proto.handshake_done.done():
                proto.handshake_done.cancel()
            self._shutdown(proto, transport)
            raise
        self._proto = proto
        self._transport = transport
        self.last_target = target
        logger.debug(
            "DoH3 %s: QUIC + HTTP/3 连接已建立（目标 %s:%d）",
            self.hostname, target, self.port,
        )

    async def _connect_locked(self) -> None:
        """依次尝试候选目标建连（最多 2 个，跨地址族），全部失败才抛异常

        握手预算在候选间**均分**：v6 被阻断（超时）时仍留一半预算给 v4，
        既保持「IPv6 优先」，又不会让 v6 黑洞吞掉整段预算导致 h3 完全不可用。
        """
        targets = self._targets()
        per_timeout = max(0.3, self.connect_timeout / max(1, len(targets)))
        last_exc: Optional[BaseException] = None
        for target in targets:
            try:
                await self._connect_one(target, per_timeout)
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last_exc = e
                logger.debug("DoH3 %s: 连接 %s:%d 失败: %s [%s]",
                             self.hostname, target, self.port, e, type(e).__name__)
                continue
        if last_exc is not None:
            raise last_exc
        raise ConnectionError("HTTP/3 没有可用的连接目标")

    async def _ensure_connected(self):
        proto = self._proto
        if proto is not None and proto.alive:
            return proto
        async with self._lock:
            proto = self._proto
            if proto is not None and proto.alive:
                return proto
            await self.close()
            await self._connect_locked()
            return self._proto

    @property
    def connected(self) -> bool:
        """是否已有一条可用的 HTTP/3 连接（用于上层 single-flight 探测）"""
        return self._proto is not None and self._proto.alive

    async def ensure_connected(self) -> bool:
        """确保连接可用（供上层 single-flight 探测调用），失败返回 False"""
        if not HAS_AIOQUIC:
            return False
        try:
            await self._ensure_connected()
            return True
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("DoH3 %s: 建连失败: %s [%s]",
                         self.hostname, e, type(e).__name__)
            return False

    # ---------- 对外接口 ----------

    async def post(self, body: bytes) -> Optional[bytes]:
        """发送一次 DoH POST 查询；成功返回 DNS 响应 wire，失败返回 None"""
        if not HAS_AIOQUIC:
            return None
        try:
            proto = await self._ensure_connected()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("DoH3 %s: 建连失败: %s [%s]",
                         self.hostname, e, type(e).__name__)
            return None
        try:
            status, payload = await asyncio.wait_for(
                proto.post(self.hostname, self.path, body), self.timeout
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("DoH3 %s: 查询失败: %s [%s]",
                         self.hostname, e, type(e).__name__)
            # 只有连接本身已经不可用（对端关闭/网络切换）才丢弃整条连接；
            # 单次查询超时/流被重置不影响同一条 QUIC 连接上的其它在飞查询
            #（多流复用），否则并发场景下一个慢查询会把其它查询一起打断。
            if not proto.alive:
                await self.close()
            return None
        if status != 200:
            logger.debug("DoH3 %s: HTTP %d", self.hostname, status)
            return None
        if not payload:
            logger.debug("DoH3 %s: 空响应体", self.hostname)
            return None
        if len(payload) > 65535:
            logger.debug("DoH3 %s: 响应过大 %d 字节，丢弃", self.hostname, len(payload))
            return None
        return payload

    async def close(self) -> None:
        """关闭 QUIC 连接（不抛异常；可重复调用）"""
        proto, transport = self._proto, self._transport
        self._proto = None
        self._transport = None
        self._shutdown(proto, transport)

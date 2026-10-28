"""
本地 DoH 服务器
- 使用 SSL 证书提供 HTTPS 加密 DNS 服务
- 支持 GET (base64url) 和 POST (binary) 查询（RFC 8484）
- 集成 DNS 缓存
- 集成域名过滤
- 非 53 端口，安全提供 DNS 服务
"""

import os
import hmac
import secrets
import ssl
import base64
import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from aiohttp import web

import h11
import httpx
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived as H2DataReceived,
    RequestReceived,
    StreamReset,
    WindowUpdated,
)
from h2.exceptions import H2Error

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
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from qps_limiter import QPSCounter
from rate_limiter import get_per_ip_limiter

# DNS 响应 Answer section 排序：AAAA (IPv6) 优先于 A (IPv4)
from dns_utils import reorder_answer_aaaa_first, sort_dns_response_wire

logger = logging.getLogger("dns-proxy.doh-server")

# ============================================================
# 本地 DoH 协议前端（HTTP/1.1 + HTTP/2 + HTTP/3）
#
# 为什么需要它：
#   Windows 11 的原生 DoH 客户端（Dnscache 服务）只实现 HTTP/2 over TLS
#   （ALPN = "h2"）这一种 DoH 传输；HTTP/1.1-only 的端点会被直接判为不可用
#   （设置页仍可能显示"已加密"，但应用解析全部失败）。而 aiohttp 只提供
#   HTTP/1.1，且不协商 ALPN（实测 ssl_object.selected_alpn_protocol() 返回
#   None），所以纯 aiohttp 的本地 DoH 永远无法被 Win11 原生客户端采纳。
#
# 架构：
#   客户端 ──TLS/TCP──> [ALPN 分流: h2 | http/1.1] ─┐
#                                                   ├─ HTTP/1.1 明文 ─> aiohttp
#   客户端 ──QUIC/UDP─> [HTTP/3] ──────────────────┘   （现有查询/缓存/过滤/DNSSEC 逻辑）
#
#   - 内部 aiohttp 站点只监听 127.0.0.1 的随机端口，不对外暴露；
#   - 三种入口都用 httpx 把请求转发给内部站点（带 X-Forwarded-For，
#     使单 IP 限速与查询日志仍能取到真实客户端地址）；
#   - 可用协议集合由 server.doh.protocols 决定，降级链 h3 → h2 → h1.1
#     （三者全关时回落 HTTP/1.1）。
# ============================================================

# aioquic 为可选依赖（HTTP/3）；缺少时自动降级到 h2/h1.1
try:
    from aioquic.asyncio import QuicConnectionProtocol, serve as quic_serve
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        DataReceived as H3DataReceived,
        HeadersReceived as H3HeadersReceived,
    )
    from aioquic.quic.configuration import QuicConfiguration

    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False
    H3_ALPN = ["h3"]

# 单次读缓冲（DNS 报文很小，64 KiB 足够；过大会增加并发连接内存占用）
FRONTEND_READ_CHUNK = 65536

# 单个 HTTP 请求体的硬上限（DNS 报文最大 64 KiB，与内部 aiohttp 的
# client_max_size 一致）。前端是自研解析层，必须自己封顶：aiohttp 的
# client_max_size 只保护内部站点，管不到前端的读循环。
FRONTEND_MAX_BODY = 65536

# 内部站点鉴权头：启动时随机生成、前端固定注入、handler 常量时间校验。
# 否则本机任意进程都能直连「仅 127.0.0.1 的明文内部端口」并伪造
# X-Forwarded-For，从而绕过单 IP 限速、污染查询日志。
INTERNAL_TOKEN_HEADER = "x-internal-token"

# HTTP/3 错误码（RFC 9114 §8.1）：请求体超限时用于重置流。
# aioquic 的 H3Connection 没有 send_reset_stream，需要走底层 QuicConnection。
H3_EXCESSIVE_LOAD = 0x0107

# 透传给内部站点的请求头白名单（其余 hop-by-hop 头一律丢弃）
FORWARD_REQUEST_HEADERS = ("accept", "content-type", "user-agent", "cache-control")

# 回传给客户端的响应头白名单。
# content-length 由前端按实际 body 长度重算，content-encoding 不透传
# （内部站点返回的是已解码内容，透传压缩头会导致长度/编码不一致）。
FORWARD_RESPONSE_HEADERS = ("content-type", "cache-control")


class DoHProtocols:
    """本地 DoH 协议开关（降级链 h3 → h2 → h1.1）"""

    __slots__ = ("http1_1", "http2", "http3")

    def __init__(self, http1_1: bool = True, http2: bool = True, http3: bool = True):
        self.http1_1 = bool(http1_1)
        self.http2 = bool(http2)
        self.http3 = bool(http3)
        if not (self.http1_1 or self.http2 or self.http3):
            # 三者全关 = 未表达任何偏好：回落 HTTP/1.1（与旧行为一致）
            self.http1_1 = True

    @classmethod
    def from_config(cls, config) -> "DoHProtocols":
        """从 Config 读取 server.doh.protocols（缺失时全开）"""
        try:
            protos = config.doh_protocols or {}
        except Exception:
            protos = {}
        return cls(
            http1_1=protos.get("http1_1", True),
            http2=protos.get("http2", True),
            http3=protos.get("http3", True),
        )

    @property
    def tcp_alpn(self) -> List[str]:
        """TCP(TLS) 上要广告的 ALPN 列表，按偏好从高到低"""
        alpn: List[str] = []
        if self.http2:
            alpn.append("h2")
        if self.http1_1:
            alpn.append("http/1.1")
        return alpn

    def describe(self) -> str:
        names = []
        if self.http3:
            names.append("h3")
        if self.http2:
            names.append("h2")
        if self.http1_1:
            names.append("h1.1")
        return "+".join(names)


class DoHFrontend:
    """DoH 协议前端：对外提供 TLS(ALPN) 与 QUIC，对内转发给本地明文 aiohttp"""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        ipv6_enabled: bool,
        ipv6_host: str,
        ipv6_port: int,
        cert_path: str,
        key_path: str,
        doh_path: str,
        internal_host: str,
        internal_port: int,
        protocols: DoHProtocols,
        internal_token: str = "",
        forward_timeout: float = 30.0,
        max_connections: int = 200,
    ):
        self.host = host
        self.port = port
        self.ipv6_enabled = ipv6_enabled
        self.ipv6_host = ipv6_host
        self.ipv6_port = ipv6_port
        self.cert_path = cert_path
        self.key_path = key_path
        self.doh_path = doh_path
        self.internal_host = internal_host
        self.internal_port = internal_port
        self.protocols = protocols
        # 内部站点鉴权令牌（由 DoHServer 生成），随每个转发请求注入，
        # 使内部明文端口只接受来自本前端、而不是任意本机进程的请求。
        self.internal_token = internal_token
        self.forward_timeout = forward_timeout
        # 连接上限以配置为准（performance.doh_max_connections），
        # 仅在配置非法（<=0）时才回退默认值，不擅自抬高下限
        try:
            requested = int(max_connections)
        except (TypeError, ValueError):
            requested = 0
        self.max_connections = requested if requested > 0 else 200
        self._conn_sem = asyncio.Semaphore(self.max_connections)

        self._servers: List[asyncio.AbstractServer] = []
        self._quic_servers: List[object] = []
        self._client: Optional[httpx.AsyncClient] = None

    # ==================== 生命周期 ====================

    async def start(self):
        """启动 TLS 前端（IPv4 必需，IPv6 可选）与 HTTP/3（可选）"""
        ssl_context = self._make_ssl_context()

        self._client = httpx.AsyncClient(
            base_url=f"http://{self.internal_host}:{self.internal_port}",
            timeout=httpx.Timeout(self.forward_timeout, connect=5.0),
            limits=httpx.Limits(max_connections=256, max_keepalive_connections=64),
            # 不读系统代理：内部转发必须直连 127.0.0.1
            trust_env=False,
            follow_redirects=False,
        )

        targets: List[Tuple[str, int, str]] = [(self.host, self.port, "IPv4")]
        if self.ipv6_enabled:
            targets.append((self.ipv6_host, self.ipv6_port, "IPv6"))

        for host, port, label in targets:
            try:
                server = await asyncio.start_server(
                    self._handle_client,
                    host,
                    port,
                    ssl=ssl_context,
                    ssl_handshake_timeout=10.0,
                    backlog=256,
                )
            except OSError as e:
                if label == "IPv4":
                    await self.stop()
                    raise
                logger.warning("DoH 前端 %s 监听失败（跳过）: %s", label, e)
                continue
            self._servers.append(server)
            logger.info(
                "DoH [%s] https://%s:%d%s （ALPN: %s）",
                label,
                self._display_host(host, label),
                port,
                self.doh_path,
                "/".join(self.protocols.tcp_alpn) or "(无)",
            )

        if self.protocols.http3:
            await self._start_h3(targets)

    @staticmethod
    def _display_host(host: str, label: str) -> str:
        """日志里显示用的主机名：通配地址还原为回环，IPv6 补方括号"""
        display = host
        if host in ("0.0.0.0", "::"):
            display = "127.0.0.1" if label == "IPv4" else "::1"
        return f"[{display}]" if ":" in display else display

    async def stop(self):
        """停止所有监听并释放内部转发连接池"""
        for server in self._servers:
            try:
                server.close()
            except Exception:
                pass
        for server in self._servers:
            try:
                await server.wait_closed()
            except Exception:
                pass
        self._servers.clear()

        for quic_server in self._quic_servers:
            try:
                quic_server.close()
            except Exception:
                pass
        self._quic_servers.clear()

        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    # ==================== TLS / QUIC 配置 ====================

    def _make_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert_path, self.key_path)
        alpn = self.protocols.tcp_alpn
        if alpn:
            # 关键：广告 h2，Win11 原生 DoH 客户端只接受 ALPN=h2
            ctx.set_alpn_protocols(alpn)
        try:
            ctx.set_ciphers(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            )
        except ssl.SSLError:
            # TLS1.3 套件不受 set_ciphers 影响；失败不致命
            pass
        return ctx

    async def _start_h3(self, targets: List[Tuple[str, int, str]]):
        """启动 HTTP/3（QUIC/UDP）监听；任何失败都只降级不抛出"""
        if not HAS_AIOQUIC:
            logger.warning("HTTP/3 已启用但 aioquic 不可用，自动降级到 h2/h1.1")
            return

        # 注意：不启用 QUIC DATAGRAM 扩展（max_datagram_frame_size）——
        # DoH 只用双向流，开着它只会放大单包处理开销。
        quic_config = QuicConfiguration(
            is_client=False,
            alpn_protocols=H3_ALPN,
            idle_timeout=60.0,
        )
        try:
            quic_config.load_cert_chain(self.cert_path, self.key_path)
        except Exception as e:
            logger.warning("HTTP/3 证书加载失败，自动降级到 h2/h1.1: %s", e)
            return

        for host, port, label in targets:
            # 地址验证（Retry）：监听非回环地址时强制开启，阻断伪造源 IP 的
            # UDP 反射放大（未验证地址的客户端只会收到一个 Retry 包，
            # 拿不到证书链，也就无法用本服务放大流量）。
            need_retry = self._needs_quic_retry(host)
            try:
                server = await quic_serve(
                    host,
                    port,
                    configuration=quic_config,
                    create_protocol=self._create_h3_protocol,
                    retry=need_retry,
                )
            except OSError as e:
                logger.warning(
                    "DoH HTTP/3 %s 监听失败（UDP %s:%d，跳过）: %s",
                    label, host, port, e,
                )
                continue
            except Exception as e:  # aioquic 内部异常不应影响 h2/h1.1 服务
                logger.warning("DoH HTTP/3 %s 启动异常（跳过）: %s", label, e)
                continue
            self._quic_servers.append(server)
            logger.info(
                "DoH [%s] https://%s:%d%s （HTTP/3 / QUIC UDP %d，地址验证=%s）",
                label,
                self._display_host(host, label),
                port,
                self.doh_path,
                port,
                "Retry（已开启）" if need_retry else "无需（回环地址）",
            )

    @staticmethod
    def _needs_quic_retry(host: str) -> bool:
        """非回环监听地址需要 QUIC 地址验证（Retry）

        回环地址不可能被伪造源地址用于反射放大，关掉 Retry 可省一个 RTT；
        通配地址（0.0.0.0 / ::）与任何具体网卡地址都视为对外暴露。
        """
        if host in ("localhost", "::1"):
            return False
        if host.startswith("127."):
            return False
        return True

    def _create_h3_protocol(self, quic, stream_handler=None):
        return _H3Protocol(quic, frontend=self, stream_handler=stream_handler)

    # ==================== 连接入口 ====================

    def _pick_protocol(self, alpn: Optional[str]) -> str:
        """按 ALPN 结果选协议，沿降级链 h3 → h2 → h1.1 回落

        h3 走独立的 QUIC/UDP 通道，不参与 TCP ALPN 选择；此处只需在
        h2 与 h1.1 之间抉择（客户端未发 ALPN 时按最低可用协议处理）。
        """
        if alpn == "h2" and self.protocols.http2:
            return "h2"
        if alpn == "http/1.1" and self.protocols.http1_1:
            return "h11"
        if self.protocols.http1_1:
            return "h11"
        if self.protocols.http2:
            return "h2"
        return "h11"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # 连接数上限：达到上限时直接拒绝新连接（而不是排队），
        # 避免异常客户端/本机进程耗尽文件句柄拖垮同进程的 53/853 服务。
        if self._conn_sem.locked():
            logger.debug("DoH 前端连接数已达上限（%d），拒绝新连接", self.max_connections)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        async with self._conn_sem:
            await self._serve_client(reader, writer)

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if peer else "unknown"
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
            if self._pick_protocol(alpn) == "h2":
                await self._serve_h2(reader, writer, peer_ip)
            else:
                await self._serve_h11(reader, writer, peer_ip)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass
        except asyncio.IncompleteReadError:
            pass
        except ssl.SSLError as e:
            logger.debug("DoH 前端 TLS 异常（%s）: %s", peer_ip, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("DoH 前端连接异常（%s）: %s", peer_ip, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ==================== HTTP/1.1 ====================

    async def _serve_h11(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_ip: str,
    ):
        conn = h11.Connection(h11.SERVER)
        while True:
            event = await self._next_h11_event(conn, reader)
            if event is None or isinstance(event, (h11.ConnectionClosed, h11.PAUSED)):
                return
            if not isinstance(event, h11.Request):
                # InformationalResponse 等非预期事件：忽略后继续
                continue

            request = event

            # Content-Length 预检：声明就超限的请求不读 body，直接 413
            declared_length = 0
            for key, value in request.headers:
                if key.lower() == b"content-length":
                    try:
                        declared_length = int(value)
                    except ValueError:
                        declared_length = 0
                    break
            if declared_length > FRONTEND_MAX_BODY:
                await self._h11_reject(conn, writer, 413, "request body too large")
                return

            body = bytearray()
            while True:
                ev = await self._next_h11_event(conn, reader)
                if ev is None or isinstance(ev, (h11.ConnectionClosed, h11.PAUSED)):
                    return
                if isinstance(ev, h11.Data):
                    body.extend(ev.data)
                    if len(body) > FRONTEND_MAX_BODY:
                        # 未声明长度（chunked）的请求同样要拦
                        await self._h11_reject(conn, writer, 413, "request body too large")
                        return
                elif isinstance(ev, h11.EndOfMessage):
                    break

            status, headers, resp_body = await self.forward(
                method=request.method.decode("ascii", "replace"),
                path=request.target.decode("latin-1"),
                headers=[
                    (k.decode("latin-1"), v.decode("latin-1"))
                    for k, v in request.headers
                ],
                body=bytes(body),
                peer_ip=peer_ip,
            )

            message = "OK" if 200 <= status < 300 else "error"
            payload = resp_body or message.encode("utf-8")
            # content-length 由前端按实际 body 重算（不透传内部站点的头）
            response_headers = [
                (k.encode("latin-1"), v.encode("latin-1")) for k, v in headers
            ]
            if not any(k.lower() == b"content-length" for k, _ in response_headers):
                response_headers.append(
                    (b"content-length", str(len(payload)).encode("ascii"))
                )

            try:
                writer.write(
                    conn.send(
                        h11.Response(status_code=status, headers=response_headers)
                    )
                )
                if payload:
                    writer.write(conn.send(h11.Data(data=payload)))
                writer.write(conn.send(h11.EndOfMessage()))
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, h11.LocalProtocolError):
                return

            if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return

    @staticmethod
    async def _h11_reject(conn: h11.Connection, writer: asyncio.StreamWriter,
                          status: int, message: str):
        """在 h11 连接上回一个简单错误响应（随后连接因 body 未读完而关闭）"""
        payload = message.encode("utf-8")
        try:
            writer.write(conn.send(h11.Response(
                status_code=status,
                headers=[
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                ],
            )))
            writer.write(conn.send(h11.Data(data=payload)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, h11.LocalProtocolError):
            pass

    @staticmethod
    async def _next_h11_event(conn: h11.Connection, reader: asyncio.StreamReader):
        """取下一条 h11 事件；NEED_DATA 时继续读（EOF 返回 ConnectionClosed）"""
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(FRONTEND_READ_CHUNK)
                # EOF 只喂一次（重复喂 b"" 无意义），随后 next_event 会给出
                # ConnectionClosed / PAUSED，由调用方结束连接
                conn.receive_data(data)
                continue
            return event

    # ==================== HTTP/2 ====================

    async def _serve_h2(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_ip: str,
    ):
        conn = H2Connection(
            config=H2Configuration(client_side=False, header_encoding="utf-8")
        )
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        lock = asyncio.Lock()                    # 串行化对 H2Connection 的写操作
        waiters: Dict[int, asyncio.Event] = {}   # stream_id -> 流控窗口事件
        tasks: set = set()
        streams: Dict[int, dict] = {}

        try:
            while True:
                data = await reader.read(FRONTEND_READ_CHUNK)
                if not data:
                    break
                try:
                    events = conn.receive_data(data)
                except H2Error as e:
                    logger.debug("h2 协议错误（%s）: %s", peer_ip, e)
                    break

                completed: List[int] = []
                for event in events:
                    if isinstance(event, RequestReceived):
                        streams[event.stream_id] = {
                            "headers": list(event.headers),
                            "body": bytearray(),
                        }
                        if event.stream_ended:
                            completed.append(event.stream_id)
                    elif isinstance(event, H2DataReceived):
                        stream = streams.get(event.stream_id)
                        if stream is not None:
                            stream["body"].extend(event.data)
                            # 及时归还接收窗口：否则窗口停在初始 65535，
                            # 客户端发满即停、服务端等更多数据 → 双方互等到超时
                            async with lock:
                                try:
                                    conn.acknowledge_received_data(
                                        len(event.data), event.stream_id
                                    )
                                except H2Error:
                                    pass
                                window_update = conn.data_to_send()
                                if window_update:
                                    writer.write(window_update)
                            if len(stream["body"]) > FRONTEND_MAX_BODY:
                                # 前端显式封顶：回 413 并结束该流（比 RST 更明确，
                                # 客户端不会因为等不到响应而卡到超时）
                                logger.debug(
                                    "h2 请求体超限（%s stream=%d），拒绝该流",
                                    peer_ip, event.stream_id,
                                )
                                streams.pop(event.stream_id, None)
                                await self._reject_h2(
                                    conn, writer, lock, event.stream_id,
                                    413, "request body too large",
                                )
                                continue
                            if event.stream_ended:
                                completed.append(event.stream_id)
                    elif isinstance(event, StreamReset):
                        streams.pop(event.stream_id, None)
                    elif isinstance(event, WindowUpdated):
                        if event.stream_id == 0:
                            # 连接级窗口更新会解锁所有等待中的流
                            for waiter in waiters.values():
                                waiter.set()
                        else:
                            waiter = waiters.get(event.stream_id)
                            if waiter is not None:
                                waiter.set()
                    elif isinstance(event, ConnectionTerminated):
                        return

                for stream_id in completed:
                    stream = streams.pop(stream_id, None)
                    if stream is None:
                        continue
                    task = asyncio.ensure_future(
                        self._respond_h2(
                            conn, writer, lock, waiters, stream_id, stream, peer_ip
                        )
                    )
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)

                async with lock:
                    pending = conn.data_to_send()
                    if pending:
                        writer.write(pending)
                if pending:
                    await writer.drain()
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _reject_h2(
        self,
        conn: H2Connection,
        writer: asyncio.StreamWriter,
        lock: asyncio.Lock,
        stream_id: int,
        status: int,
        message: str,
    ):
        """在 h2 流上回一个简单错误响应并结束该流"""
        payload = message.encode("utf-8")
        headers = [
            (":status", str(status)),
            ("content-type", "text/plain; charset=utf-8"),
            ("content-length", str(len(payload))),
        ]
        try:
            async with lock:
                conn.send_headers(stream_id, headers, end_stream=False)
                conn.send_data(stream_id, payload, end_stream=True)
                pending = conn.data_to_send()
                if pending:
                    writer.write(pending)
            await writer.drain()
        except (H2Error, ConnectionResetError, BrokenPipeError):
            pass

    async def _respond_h2(
        self,
        conn: H2Connection,
        writer: asyncio.StreamWriter,
        lock: asyncio.Lock,
        waiters: Dict[int, asyncio.Event],
        stream_id: int,
        stream: dict,
        peer_ip: str,
    ):
        method = ""
        path = ""
        for key, value in stream["headers"]:
            if key == ":method":
                method = value
            elif key == ":path":
                path = value

        status, headers, body = await self.forward(
            method=method or "POST",
            path=path or self.doh_path,
            headers=[(k, v) for k, v in stream["headers"] if not k.startswith(":")],
            body=bytes(stream["body"]),
            peer_ip=peer_ip,
        )

        try:
            response_headers = list(headers)
            if not any(k.lower() == "content-length" for k, _ in response_headers):
                response_headers.append(("content-length", str(len(body))))
            async with lock:
                conn.send_headers(
                    stream_id,
                    [(":status", str(status))] + response_headers,
                    end_stream=not body,
                )
                pending = conn.data_to_send()
                if pending:
                    writer.write(pending)
            if pending:
                await writer.drain()
            if body:
                await self._h2_send_body(conn, writer, lock, waiters, stream_id, body)
        except (H2Error, ConnectionResetError, BrokenPipeError) as e:
            logger.debug("h2 响应发送失败（%s stream=%d）: %s", peer_ip, stream_id, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("h2 响应异常（%s stream=%d）: %s", peer_ip, stream_id, e)
        finally:
            waiters.pop(stream_id, None)

    async def _h2_send_body(
        self,
        conn: H2Connection,
        writer: asyncio.StreamWriter,
        lock: asyncio.Lock,
        waiters: Dict[int, asyncio.Event],
        stream_id: int,
        body: bytes,
    ):
        """按对端流控窗口分片发送响应体（DNS 响应通常 <4 KiB，分片一般只有 1 次）"""
        total = len(body)
        sent = 0
        while sent < total:
            async with lock:
                try:
                    window = conn.local_flow_control_window(stream_id)
                except H2Error:
                    return
                chunk = body[sent:sent + window] if window > 0 else b""
                if chunk:
                    conn.send_data(
                        stream_id, chunk, end_stream=(sent + len(chunk) >= total)
                    )
                    sent += len(chunk)
                pending = conn.data_to_send()
                if pending:
                    writer.write(pending)
            if pending:
                await writer.drain()
            if sent >= total:
                return

            waiter = waiters.get(stream_id)
            if waiter is None:
                waiter = asyncio.Event()
                waiters[stream_id] = waiter
            else:
                waiter.clear()
            try:
                await asyncio.wait_for(waiter.wait(), timeout=self.forward_timeout)
            except asyncio.TimeoutError:
                logger.debug(
                    "h2 流控等待超时（stream=%d），放弃剩余 %d 字节",
                    stream_id, total - sent,
                )
                return

    # ==================== 统一转发 ====================

    async def forward(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        body: bytes,
        peer_ip: str,
    ) -> Tuple[int, List[Tuple[str, str]], bytes]:
        """把 DoH 请求转发给内部明文 aiohttp，返回 (状态码, 响应头, 响应体)"""
        normalized_path = path or self.doh_path
        # 只接受本服务配置的 DoH 路径（防止把目标拼成绝对 URL 或塞入控制字符）
        if (
            not normalized_path.startswith(self.doh_path)
            or any(ch in normalized_path for ch in ("\r", "\n", "\0"))
        ):
            return 400, [("content-type", "text/plain; charset=utf-8")], b"invalid request target"

        # 前端自研解析层必须自己封顶（aiohttp 的 client_max_size 只保护内部站点）
        if len(body) > FRONTEND_MAX_BODY:
            return 413, [("content-type", "text/plain; charset=utf-8")], b"request body too large"

        forward_headers: Dict[str, str] = {}
        for key, value in headers:
            lowered = key.lower()
            if lowered in FORWARD_REQUEST_HEADERS:
                forward_headers[lowered] = value
        # 内部站点看到的是 127.0.0.1，用 XFF 还原真实来源（限速/日志依赖它）
        forward_headers["x-forwarded-for"] = peer_ip
        if self.internal_token:
            forward_headers[INTERNAL_TOKEN_HEADER] = self.internal_token

        if self._client is None:
            return 503, [("content-type", "text/plain; charset=utf-8")], b"frontend not started"

        try:
            response = await self._client.request(
                method or "POST",
                normalized_path,
                headers=forward_headers,
                content=body,
            )
        except httpx.TimeoutException:
            logger.debug("内部 DoH 转发超时（%s）", peer_ip)
            return 504, [("content-type", "text/plain; charset=utf-8")], b"gateway timeout"
        except httpx.HTTPError as e:
            logger.debug("内部 DoH 转发失败（%s）: %s", peer_ip, e)
            return 502, [("content-type", "text/plain; charset=utf-8")], b"bad gateway"

        response_headers = [
            (key.lower(), value)
            for key, value in response.headers.items()
            if key.lower() in FORWARD_RESPONSE_HEADERS
        ]
        return response.status_code, response_headers, response.content


class _H3Protocol(QuicConnectionProtocol if HAS_AIOQUIC else object):
    """HTTP/3 连接：解析 H3 请求并转发给内部明文站点"""

    def __init__(self, quic=None, *, frontend: DoHFrontend, stream_handler=None):
        if HAS_AIOQUIC:
            super().__init__(quic, stream_handler=stream_handler)
        self._frontend = frontend
        self._quic = quic
        # 对端地址由 datagram_received 记录（见下），不依赖 QuicConnection 私有属性
        self._peer_addr: Optional[tuple] = None
        self._http = H3Connection(quic) if HAS_AIOQUIC else None
        self._requests: Dict[int, dict] = {}
        self._tasks: set = set()

    def datagram_received(self, data, addr):
        """记录 QUIC 数据报的真实来源地址

        aioquic 的 QuicServer 以 (data, addr) 调用本方法。之前用
        QuicConnection 的私有属性 _network_paths 取客户端 IP——那是内部实现，
        版本升级后可能变更/消失。这里改用协议层直接收到的地址。
        """
        self._peer_addr = addr
        if HAS_AIOQUIC:
            super().datagram_received(data, addr)

    def _client_ip(self) -> str:
        addr = self._peer_addr
        if not addr:
            return "unknown"
        try:
            return str(addr[0])
        except Exception:
            return "unknown"

    def quic_event_received(self, event):
        if not HAS_AIOQUIC:
            return
        try:
            h3_events = self._http.handle_event(event)
        except Exception as e:
            logger.debug("HTTP/3 事件处理异常: %s", e)
            return

        for h3_event in h3_events:
            if isinstance(h3_event, H3HeadersReceived):
                method = ""
                path = ""
                headers: List[Tuple[str, str]] = []
                for key, value in h3_event.headers:
                    decoded_key = key.decode("latin-1").lower()
                    decoded_value = value.decode("latin-1")
                    if decoded_key == ":method":
                        method = decoded_value
                    elif decoded_key == ":path":
                        path = decoded_value
                    elif not decoded_key.startswith(":"):
                        headers.append((decoded_key, decoded_value))
                self._requests[h3_event.stream_id] = {
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": bytearray(),
                }
                if h3_event.stream_ended:
                    self._start_response(h3_event.stream_id)
            elif isinstance(h3_event, H3DataReceived):
                request = self._requests.get(h3_event.stream_id)
                if request is not None:
                    request["body"].extend(h3_event.data)
                    if len(request["body"]) > FRONTEND_MAX_BODY:
                        # 前端显式封顶，不依赖 QUIC 流控的默认窗口
                        logger.debug(
                            "HTTP/3 请求体超限（stream=%d），取消该流",
                            h3_event.stream_id,
                        )
                        self._requests.pop(h3_event.stream_id, None)
                        try:
                            self._quic.reset_stream(
                                h3_event.stream_id, error_code=H3_EXCESSIVE_LOAD
                            )
                            self.transmit()
                        except Exception as e:
                            logger.debug("HTTP/3 重置流失败: %s", e)
                        continue
                    if h3_event.stream_ended:
                        self._start_response(h3_event.stream_id)

    def _start_response(self, stream_id: int):
        request = self._requests.pop(stream_id, None)
        if request is None:
            return
        task = asyncio.ensure_future(self._respond(stream_id, request))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _respond(self, stream_id: int, request: dict):
        status, headers, body = await self._frontend.forward(
            method=request["method"] or "POST",
            path=request["path"] or self._frontend.doh_path,
            headers=request["headers"],
            body=bytes(request["body"]),
            peer_ip=self._client_ip(),
        )
        encoded = [(b":status", str(status).encode("ascii"))] + [
            (key.encode("latin-1"), value.encode("latin-1"))
            for key, value in headers
        ]
        if not any(key == b"content-length" for key, _ in encoded):
            encoded.append((b"content-length", str(len(body)).encode("ascii")))
        try:
            self._http.send_headers(stream_id, encoded)
            self._http.send_data(stream_id, body, end_stream=True)
            self.transmit()
        except Exception as e:
            logger.debug("HTTP/3 响应发送失败（stream=%d）: %s", stream_id, e)


# DNS 记录类型名称映射
QTYPE_NAMES = {v: k for k, v in dns.rdatatype.__dict__.items() if isinstance(v, int)}


class DoHServer:
    """本地 DNS over HTTPS 服务器（支持 IPv4/IPv6 双栈）"""

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

        self.host = config.doh_host
        self.port = config.doh_port
        self.doh_path = config.doh_path
        self.cert_path = config.doh_cert_path
        self.key_path = config.doh_key_path

        # IPv6 配置
        self.ipv6_enabled = config.doh_ipv6_enabled
        self.ipv6_host = config.doh_ipv6_host
        self.ipv6_port = config.doh_ipv6_port

        self.app = web.Application(client_max_size=65536)
        self._setup_routes()
        self._runner: Optional[web.AppRunner] = None
        self._sites: List[web.TCPSite] = []
        self._cleanup_task: Optional[asyncio.Task] = None

        # 内部站点鉴权令牌：每次启动随机生成，只下发给本进程的协议前端。
        # 内部站点只监听 127.0.0.1，但本机任意进程都能连 127.0.0.1，
        # 没有它就能伪造 X-Forwarded-For 绕过限速、污染查询日志。
        self._internal_token = secrets.token_hex(32)

        # 对外协议前端（TLS ALPN h2/http1.1 + QUIC h3）
        self._frontend: Optional[DoHFrontend] = None
        # 内部明文 aiohttp 站点：只监听本机，端口由系统分配（0）
        self.internal_host = "127.0.0.1"
        self.internal_port = 0

        # 并发控制
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)

        # 单 IP 限速（共享 PerIPRateLimiter 单例，消除各服务器独立 dict 的内存浪费）
        self._per_ip_limiter = get_per_ip_limiter(
            per_ip_limit=config.max_concurrent_per_ip,
        )
        self._per_ip_limit = config.max_concurrent_per_ip

        # QPS 限速（所有客户端包括 localhost）
        self._qps_limiter = QPSCounter(config.doh_qps_limit, "DoH")

    @staticmethod
    def _make_cache_key(question, query, source=None) -> tuple:
        """缓存键 = (name, rdtype, rdclass, DO 位, CD 位[, source])

        RFC 6891/4035：带 DO 的查询可能需要 RRSIG，CD=1 表示跳过校验；
        source 用于隔离同一域名的不同入口（wire / json）——两者对被拦截
        域名的应答形态不同（wire 给 0.0.0.0/::，json 给 NXDOMAIN），
        共用同一键会互相覆盖。
        """
        try:
            do_bit = bool(query.edns >= 0 and (query.ednsflags & dns.flags.DO))
        except Exception:
            do_bit = False
        try:
            cd_bit = bool(query.flags & dns.flags.CD)
        except Exception:
            cd_bit = False
        key = (question.name, question.rdtype, question.rdclass, do_bit, cd_bit)
        return key + (source,) if source else key

    @staticmethod
    def _client_ip(request) -> str:
        """取客户端 IP：直连来源是本机（反向代理）时才信任 X-Forwarded-For

        否则反代场景下 request.remote 恒为 127.0.0.1，会命中 localhost 例外
        使 per-IP 限速完全失效；而对外部来源不信任该头可避免伪造绕过。
        """
        remote = request.remote or "unknown"
        if remote in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            try:
                xff = request.headers.get("X-Forwarded-For", "")
            except Exception:
                xff = ""
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
        return remote

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
        """判断是否是本地地址（不限速）"""
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        """获取或创建单 IP 信号量（使用共享 PerIPRateLimiter）"""
        return await self._per_ip_limiter.acquire(client_ip)

    async def _cleanup_stale_per_ip_semaphores(self):
        """已废弃：过期条目由共享 PerIPRateLimiter 的后台循环统一清理

        保留空方法仅为兼容旧调用点；不再阻塞等待（原 asyncio.Event().wait()
        永不返回，会让该后台任务永久挂起）。
        """
        return

    def _setup_routes(self):
        """注册路由"""
        self.app.router.add_route("GET", self.doh_path, self.handle_get)
        self.app.router.add_route("POST", self.doh_path, self.handle_post)

    def _check_internal_token(self, request: web.Request) -> Optional[web.Response]:
        """校验请求确实来自本进程的协议前端

        内部站点只监听 127.0.0.1 的随机端口，但本机任意进程都能连 127.0.0.1：
        没有这层校验，任何本机程序都能绕开 TLS 前端直连内部端口，并自带
        X-Forwarded-For 伪造来源（绕过单 IP 限速、污染查询日志）。
        """
        token = request.headers.get(INTERNAL_TOKEN_HEADER, "")
        if not token or not hmac.compare_digest(token, self._internal_token):
            logger.debug(
                "拒绝非前端的内部端口请求: remote=%s", request.remote
            )
            return web.Response(status=403, text="forbidden")
        return None

    # ======================== GET 处理（双格式自适应） ========================

    async def handle_get(self, request: web.Request) -> web.Response:
        """
        GET 请求 — 自动适配两种 DoH 格式:

        1. Wire Format (RFC 8484):
           ?dns=<base64url 编码的 DNS 查询>

        2. JSON API (Google DNS over HTTPS):
           ?name=example.com&type=A&cd=0
        """
        rejected = self._check_internal_token(request)
        if rejected is not None:
            return rejected

        dns_param = request.query.get("dns")
        name_param = request.query.get("name")

        # 格式1: Wire Format — ?dns=base64url
        if dns_param:
            try:
                padding = 4 - (len(dns_param) % 4)
                if padding != 4:
                    dns_param += "=" * padding
                wire_data = base64.urlsafe_b64decode(dns_param)
            except Exception:
                return web.Response(status=400, text="无效的 base64url 编码")
            if not wire_data or len(wire_data) < 12:
                return web.Response(status=400, text="DNS 消息长度不足")
            return await self._handle_dns_query(wire_data, request, "wire")

        # 格式2: JSON API — ?name=example.com&type=A
        if name_param:
            return await self._handle_json_query(request, name_param)

        # 无法识别 → 根据 Accept 返回合适格式的帮助信息
        accept = request.headers.get("Accept", "")
        if "application/dns-message" in accept:
            return web.Response(status=400, text="缺少 dns 参数")
        return web.Response(
            status=400,
            content_type="application/json",
            text='{"error":"缺少参数","usage":{"wire_format":"?dns=<base64url>","json_api":"?name=<domain>&type=<record_type>"}}',
        )

    # ======================== POST 处理（Wire Format 专有） ========================

    async def handle_post(self, request: web.Request) -> web.Response:
        """
        POST 请求 — Wire Format (RFC 8484):
        body = application/dns-message
        """
        rejected = self._check_internal_token(request)
        if rejected is not None:
            return rejected

        content_type = request.content_type or ""
        if content_type not in (
            "application/dns-message",
            "application/octet-stream",
        ):
            # 如果 Accept 是 JSON，返回 JSON 错误
            accept = request.headers.get("Accept", "")
            if "application/dns-message" not in accept:
                return web.json_response(
                    {"error": "不支持的 Content-Type", "supported": "application/dns-message"},
                    status=415,
                )
            return web.Response(status=415, text="需要 Content-Type: application/dns-message")

        wire_data = await request.read()
        if not wire_data or len(wire_data) < 12:
            return web.Response(status=400, text="空请求体或无效长度")
        return await self._handle_dns_query(wire_data, request, "wire")

    # ======================== JSON API 查询 ========================

    async def _handle_json_query(
        self, request: web.Request, name: str
    ) -> web.Response:
        """处理 JSON API 格式的 DNS 查询"""
        qtype_str = request.query.get("type", "A")
        cd_flag = request.query.get("cd", "0") == "1"

        try:
            qtype = dns.rdatatype.from_text(qtype_str)
        except Exception:
            return web.json_response(
                {"Status": 2, "Comment": f"无效的记录类型: {qtype_str}"}
            )

        # 构建 DNS 查询
        try:
            query = dns.message.make_query(name, qtype, want_dnssec=self.config.dnssec_enabled)
            if cd_flag:
                query.flags |= dns.flags.CD
            wire_data = query.to_wire()
        except Exception:
            return web.json_response(
                {"Status": 2, "Comment": f"无效的域名: {name}"}
            )

        client_ip = self._client_ip(request)
        await self._qps_limiter.acquire()  # QPS 限速（所有客户端）
        if not self._is_localhost(client_ip):
            sem = await self._get_per_ip_semaphore(client_ip)
            async with sem:
                async with self._concurrency_semaphore:
                    json_result = await self._process_json_query(wire_data, request)
        else:
            async with self._concurrency_semaphore:
                json_result = await self._process_json_query(wire_data, request)

        return web.json_response(json_result)

    async def _process_json_query(
        self, wire_data: bytes, request: web.Request
    ) -> dict:
        """处理 DNS 查询并返回 JSON 格式结果"""
        result = {
            "Status": 2,
            "TC": False,
            "RD": True,
            "RA": True,
            "AD": False,
            "CD": False,
            "Question": [],
            "Answer": [],
            "Authority": [],
            "Comment": "查询失败",
        }

        try:
            query = dns.message.from_wire(wire_data)
            if not query.question:
                return {**result, "Comment": "无效的 DNS 查询"}

            question = query.question[0]
            qname = str(question.name).rstrip(".")
            qtype = QTYPE_NAMES.get(question.rdtype, str(question.rdtype))

            result["Question"] = [{"name": qname, "type": qtype}]
            result["CD"] = bool(query.flags & dns.flags.CD)

            # 0. 检查自定义 hosts 映射（JSON API）
            custom_ips = self.filter_engine.get_custom_hosts_ips(qname)
            if custom_ips:
                qrdtype = question.rdtype
                answer_entries = []
                for ip, ip_rdtype in custom_ips:
                    if qrdtype == dns.rdatatype.A and ip_rdtype == dns.rdatatype.AAAA:
                        continue
                    if qrdtype == dns.rdatatype.AAAA and ip_rdtype == dns.rdatatype.A:
                        continue
                    answer_entries.append({
                        "name": qname,
                        "type": QTYPE_NAMES.get(ip_rdtype, str(ip_rdtype)),
                        "TTL": 3600,
                        "data": ip,
                    })
                if answer_entries:
                    result["Status"] = 0  # NOERROR
                    result["Answer"] = answer_entries
                    result["Comment"] = "自定义 hosts 映射"
                    return result

            # 0b. 检查自定义 hosts 白名单（纯域名绕过，无自定义IP）
            is_hosts_bypass = self.filter_engine.is_custom_hosts_bypass(qname)

            # 1. 检查域名过滤
            # 缓存键含 DO/CD 维度，并以 source="json" 与 wire 入口隔离
            #（两者对被拦截域名的应答形态不同，共用键会互相污染）
            cache_key = self._make_cache_key(question, query, source="json")
            if self.config.filter_enabled and not is_hosts_bypass:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    result["Status"] = 3  # NXDOMAIN
                    result["Comment"] = f"被过滤规则拦截: {reason}"
                    # 缓存拦截结果到 DNS 响应缓存，防止上游正向应答重复生效
                    if self.config.cache_enabled:
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.NXDOMAIN)
                        await self.cache.set(cache_key, response, True)
                    return result

            # 2. 缓存检查
            if self.config.cache_enabled:
                cached = await self.cache.get(cache_key)
                if cached is not None:
                    return self._dns_response_to_json(cached, query)

            # 3. 上游解析
            result_wire = await self.resolver_manager.resolve(wire_data)

            if result_wire is None:
                result["Status"] = 2  # SERVFAIL
                result["Comment"] = "所有上游服务器均失败"
                return result

            response = dns.message.from_wire(result_wire)

            # 4. 缓存
            if self.config.cache_enabled:
                is_negative = self._is_negative_response(response)
                await self.cache.set(cache_key, response, is_negative)

            return self._dns_response_to_json(response, query)

        except Exception as e:
            logger.error("JSON 查询异常: %s", e)
            result["Comment"] = "内部错误"
            return result

    @staticmethod
    def _dns_response_to_json(
        response: dns.message.Message, query: dns.message.Message
    ) -> dict:
        """将 DNS 响应转换为 JSON API 格式"""
        rcode = response.rcode()
        status_map = {
            dns.rcode.NOERROR: 0,
            dns.rcode.FORMERR: 1,
            dns.rcode.SERVFAIL: 2,
            dns.rcode.NXDOMAIN: 3,
            dns.rcode.NOTIMP: 4,
            dns.rcode.REFUSED: 5,
        }
        question = query.question[0] if query.question else None

        result = {
            "Status": status_map.get(rcode, 2),
            "TC": bool(response.flags & dns.flags.TC),
            "RD": bool(response.flags & dns.flags.RD),
            "RA": bool(response.flags & dns.flags.RA),
            "AD": bool(response.flags & dns.flags.AD),
            "CD": bool(response.flags & dns.flags.CD),
            "Question": [],
            "Answer": [],
            "Authority": [],
        }

        if question:
            result["Question"].append({
                "name": str(question.name).rstrip("."),
                "type": QTYPE_NAMES.get(question.rdtype, str(question.rdtype)),
            })

        # Answer 部分
        for rrset in response.answer:
            # dnspython v2.x: TTL 存储在 RRset 上，rdata 对象可能没有 ttl 属性
            ttl = max(0, rrset.ttl) if hasattr(rrset, 'ttl') and rrset.ttl is not None else 3600
            for rd in rrset:
                entry = {
                    "name": str(rrset.name).rstrip("."),
                    "type": QTYPE_NAMES.get(rd.rdtype, str(rd.rdtype)),
                    "TTL": ttl,
                }
                if rd.rdtype == dns.rdatatype.A:
                    entry["data"] = str(rd.address)
                elif rd.rdtype == dns.rdatatype.AAAA:
                    entry["data"] = str(rd.address)
                elif rd.rdtype == dns.rdatatype.CNAME:
                    entry["data"] = str(rd.target).rstrip(".")
                elif rd.rdtype == dns.rdatatype.MX:
                    entry["data"] = f"{rd.preference} {str(rd.exchange).rstrip('.')}"
                elif rd.rdtype == dns.rdatatype.TXT:
                    entry["data"] = " ".join(
                        t.decode() if isinstance(t, bytes) else str(t)
                        for t in rd.strings
                    )
                elif rd.rdtype == dns.rdatatype.NS:
                    entry["data"] = str(rd.target).rstrip(".")
                elif rd.rdtype == dns.rdatatype.SOA:
                    entry["data"] = f"{str(rd.mname).rstrip('.')} {str(rd.rname).rstrip('.')} {rd.serial} {rd.refresh} {rd.retry} {rd.expire} {rd.minimum}"
                elif rd.rdtype == dns.rdatatype.CAA:
                    entry["data"] = f"{rd.flags} {rd.tag} \"{rd.value}\""
                elif rd.rdtype == dns.rdatatype.SRV:
                    entry["data"] = f"{rd.priority} {rd.weight} {rd.port} {str(rd.target).rstrip('.')}"
                elif rd.rdtype == dns.rdatatype.HTTPS:
                    entry["data"] = str(rd)
                else:
                    entry["data"] = str(rd)
                result["Answer"].append(entry)

        # Authority 部分
        for rrset in response.authority:
            ttl = max(0, rrset.ttl) if hasattr(rrset, 'ttl') and rrset.ttl is not None else 3600
            for rd in rrset:
                result["Authority"].append({
                    "name": str(rrset.name).rstrip("."),
                    "type": QTYPE_NAMES.get(rd.rdtype, str(rd.rdtype)),
                    "TTL": ttl,
                    "data": str(rd),
                })

        return result

    # ======================== Wire Format 查询 ========================

    async def _handle_dns_query(
        self, wire_data: bytes, request: web.Request, response_format: str = "wire"
    ) -> web.Response:
        """处理 DNS 查询（Wire Format）- 按 response_format 返回"""
        client_ip = self._client_ip(request)
        await self._qps_limiter.acquire()  # QPS 限速（所有客户端）
        if not self._is_localhost(client_ip):
            sem = await self._get_per_ip_semaphore(client_ip)
            async with sem:
                async with self._concurrency_semaphore:
                    return await self._process_query(wire_data, request, response_format)
        async with self._concurrency_semaphore:
            return await self._process_query(wire_data, request, response_format)

    def _make_response(self, data: bytes, fmt: str = "wire",
                    query: Optional[dns.message.Message] = None) -> web.Response:
        """创建 wire 格式的 DoH 响应

        注：JSON 响应由 _dns_response_to_json() 单独生成（_process_json_query
        走的是那条路径），原本永远不会被触发的 fmt=="json" 分支已删除。
        参数 fmt/query 保留以保持调用点兼容。
        """
        return web.Response(body=data, content_type="application/dns-message")

    async def _process_query(
        self, wire_data: bytes, request: web.Request, response_format: str = "wire"
    ) -> web.Response:
        """DNS 查询处理（含缓存、过滤、DNSSEC 验证、自定义 hosts）"""
        client_ip = self._client_ip(request)
        response_wire: Optional[bytes] = None
        upstream = ""
        block_reason = ""
        dnssec_status = ""
        status = "ok"
        start_time = asyncio.get_event_loop().time()

        try:
            # 解析 DNS 查询
            query = dns.message.from_wire(wire_data)
            if not query.question:
                return web.Response(status=400, text="无效的 DNS 查询")

            question = query.question[0]
            qname = str(question.name).rstrip(".")
            qtype = QTYPE_NAMES.get(question.rdtype, str(question.rdtype))
            # 缓存键含 DO/CD 维度：不同 DNSSEC 需求的查询不应互相命中
            cache_key = self._make_cache_key(question, query)

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
                    # AAAA 优先于 A 排序
                    reorder_answer_aaaa_first(response)
                    response_wire = response.to_wire()
                    status = "custom_hosts"
                    block_reason = f"自定义 hosts 映射"
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, qtype, elapsed, status, "", block_reason
                    )
                    return self._make_response(response_wire, response_format, query=query)

            # 0b. 检查自定义 hosts 白名单（纯域名绕过，无自定义IP）
            is_hosts_bypass = self.filter_engine.is_custom_hosts_bypass(qname)

            # 1. 检查域名过滤
            if self.config.filter_enabled and not is_hosts_bypass:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    block_reason = reason
                    status = "blocked"
                    # 像 AdGuard 一样重写 IP：A → 0.0.0.0，AAAA → ::，其他类型 → NXDOMAIN
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
                    # 缓存拦截结果
                    if self.config.cache_enabled:
                        await self.cache.set(
                            cache_key, response,
                            response.rcode() == dns.rcode.NXDOMAIN,
                        )
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, QTYPE_NAMES.get(question.rdtype, str(question.rdtype)),
                        elapsed, status, upstream, block_reason
                    )
                    return self._make_response(response_wire, response_format, query=query)

            # 2. 检查缓存
            cached_response = None
            if self.config.cache_enabled:
                cached_response = await self.cache.get(cache_key)

            if cached_response is not None:
                cached_response.id = query.id  # 修复DNS ID不匹配
                # AAAA 优先于 A 排序
                reorder_answer_aaaa_first(cached_response)
                response_wire = cached_response.to_wire()
                status = "cached"
                elapsed = asyncio.get_event_loop().time() - start_time
                await self._log_query(
                    client_ip, qname, qtype, elapsed, status, "", ""
                )
                return self._make_response(response_wire, response_format, query=query)

            # 3. 通过上游解析器并行查询（自动添加 DNSSEC DO 位）
            result_wire = await self.resolver_manager.resolve(wire_data)

            if result_wire is None:
                # 所有上游都失败
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                response_wire = response.to_wire()
                status = "error"
            else:
                upstream = self.resolver_manager.last_fast_server or ""
                # 4. DNSSEC 验证（如果启用）
                dnssec_ok = True
                if self._dnssec_wrapper is not None and self.config.dnssec_enabled:
                    dnssec_ok, dnssec_status = await self._dnssec_wrapper.validate_response(
                        wire_data, result_wire
                    )
                    if not dnssec_ok and self.config.dnssec_drop_bogus:
                        # DNSSEC 验证失败且配置为丢弃
                        logger.warning("DNSSEC bogus，丢弃 %s 的响应", qname)
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.SERVFAIL)
                        response_wire = response.to_wire()
                        status = "dnssec_bogus"
                    else:
                        response_wire = result_wire
                        status = "resolved"
                        # 缓存结果
                        if self.config.cache_enabled:
                            try:
                                response_msg = dns.message.from_wire(result_wire)
                                # AAAA 优先于 A 排序（确保缓存中数据顺序一致）
                                reorder_answer_aaaa_first(response_msg)
                                is_negative = self._is_negative_response(response_msg)
                                await self.cache.set(cache_key, response_msg, is_negative)
                            except Exception as e:
                                logger.debug("DoH 缓存写入异常: %s", e)
                else:
                    response_wire = result_wire
                    status = "resolved"
                    # 缓存结果
                    if self.config.cache_enabled:
                        try:
                            response_msg = dns.message.from_wire(result_wire)
                            # AAAA 优先于 A 排序（确保缓存中数据顺序一致）
                            reorder_answer_aaaa_first(response_msg)
                            is_negative = self._is_negative_response(response_msg)
                            await self.cache.set(cache_key, response_msg, is_negative)
                        except Exception as e:
                            logger.debug("DoH 缓存写入异常: %s", e)

            elapsed = asyncio.get_event_loop().time() - start_time
            await self._log_query(
                client_ip, qname, qtype, elapsed, status, upstream, block_reason
            )

            # AAAA 优先于 A 排序（仅对成功解析的上游响应）
            if response_wire is not None and status == "resolved":
                response_wire = sort_dns_response_wire(response_wire)

            # 上游直连路径的响应 ID 可能与查询不一致：DoH（RFC 8484）与 DoQ
            # （RFC 9250）上游按协议要求用 ID=0 发起查询，其响应 ID 会被原样
            # 透传给客户端，故在返回前统一重写为查询 ID。对 make_response(query)
            # 生成的响应（ID 本已正确）是幂等的。
            if response_wire:
                try:
                    _resp = dns.message.from_wire(response_wire)
                    if _resp.id != query.id:
                        _resp.id = query.id
                        response_wire = _resp.to_wire()
                except Exception as e:
                    logger.debug("DoH 响应 ID 重写异常: %s", e)

            return self._make_response(response_wire, response_format, query=query)

        except dns.exception.DNSException as e:
            logger.warning("DNS 解析错误: %s", e)
            # 不回显内部异常文本（避免信息泄露）
            return web.Response(status=400, text="DNS 解析错误")
        except Exception as e:
            logger.error("处理 DNS 查询异常: %s", e)
            return web.Response(status=500, text="内部错误")

    async def _log_query(
        self,
        client_ip: str,
        domain: str,
        qtype: str,
        elapsed: float,
        status: str,
        upstream: str,
        block_reason: str,
    ):
        """异步记录查询日志"""
        try:
            await self.request_logger.log(
                client_ip=client_ip,
                domain=domain,
                qtype=qtype,
                response_time=elapsed,
                status=status,
                upstream=upstream,
                block_reason=block_reason,
            )
        except Exception as e:
            logger.debug("DoH 查询日志记录异常: %s", e)

    async def start(self):
        """启动 DoH 服务

        与旧实现的关键区别：对外监听不再由 aiohttp 直接提供。aiohttp 只支持
        HTTP/1.1，且不协商 ALPN（实测 ``selected_alpn_protocol()`` 为 None），
        而 Windows 11 原生 DoH 客户端（Dnscache）只接受 ALPN=h2 的 HTTP/2，
        因此旧实现在 Win11 里必然"设置显示已加密、实际完全不通"。

        现在分成两层：

            [DoHFrontend]  TLS（ALPN: h2 / http/1.1）+ QUIC（h3）
                                 ↓ HTTP/1.1 明文，仅 127.0.0.1
            [内部 aiohttp 站点]  现有查询/缓存/过滤/DNSSEC 逻辑（零改动）

        协议可用集合由 ``server.doh.protocols`` 决定（降级链 h3 → h2 → h1.1）。
        """
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            # 安全：证书缺失时绝不静默降级为明文 HTTP，否则 DNS 查询明文外泄/可篡改
            logger.error(
                "SSL 证书不存在，DoH 拒绝启动（不再降级为明文）。请生成证书:\n"
                "  cd %s\n"
                "  openssl req -x509 -nodes -days 365 -newkey rsa:4096 "
                "-keyout certs/localhost.key -out certs/localhost.crt "
                "-config openssl.conf -extensions v3_req",
                os.path.dirname(os.path.dirname(os.path.abspath(self.cert_path))),
            )
            return

        protocols = DoHProtocols.from_config(self.config)

        # ---------- 1) 内部 aiohttp 站点（明文，仅本机） ----------
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()

        # 启动共享 PerIPRateLimiter（全局单例，含自身后台清理循环）
        self._per_ip_limiter.start()

        internal_site = web.TCPSite(self._runner, self.internal_host, 0)
        try:
            await internal_site.start()
        except OSError as e:
            logger.error(
                "DoH 内部站点启动失败（%s:随机端口）: %s", self.internal_host, e
            )
            raise
        self._sites.append(internal_site)

        internal_port = self._detect_internal_port(internal_site)
        if not internal_port:
            logger.error("DoH 内部站点端口探测失败，无法启动协议前端")
            await self.stop()
            return
        self.internal_port = internal_port
        logger.debug(
            "DoH 内部站点 127.0.0.1:%d（仅本机、明文，供协议前端转发）",
            internal_port,
        )

        # ---------- 2) 对外协议前端（TLS ALPN + QUIC） ----------
        self._frontend = DoHFrontend(
            host=self.host,
            port=self.port,
            ipv6_enabled=self.ipv6_enabled,
            ipv6_host=self.ipv6_host,
            ipv6_port=self.ipv6_port,
            cert_path=self.cert_path,
            key_path=self.key_path,
            doh_path=self.doh_path,
            internal_host=self.internal_host,
            internal_port=internal_port,
            protocols=protocols,
            internal_token=self._internal_token,
            forward_timeout=float(
                getattr(self.config, "parallel_timeout", 30.0) or 30.0
            ),
            # 连接数上限取自 performance.doh_max_connections（默认 200），
            # 与 dot_max_connections / doq_max_connections 同一段配置
            max_connections=int(
                getattr(self.config, "doh_max_connections", 200) or 200
            ),
        )
        try:
            await self._frontend.start()
        except (OSError, ssl.SSLError) as e:
            logger.error(
                "DoH 协议前端启动失败（%s:%s）: %s", self.host, self.port, e
            )
            self._frontend = None
            await self.stop()
            raise

        # 监听在非回环地址时给出明确提示：HTTP/3 已自动强制 Retry 地址验证，
        # 但仍建议确认是否真的需要对外暴露（内部明文站点只绑 127.0.0.1）。
        bindings = [(self.host, "IPv4")]
        if self.ipv6_enabled:
            bindings.append((self.ipv6_host, "IPv6"))
        for _host, _label in bindings:
            if _host in ("127.0.0.1", "::1", "localhost") or _host.startswith("127."):
                continue
            logger.warning(
                "DoH %s 监听在非回环地址 %s：HTTP/3(QUIC) 已强制启用地址验证(Retry) "
                "以防 UDP 反射放大；如无对外提供服务需求，建议改回 127.0.0.1/::1",
                _label, _host,
            )

        logger.info(
            "DoH 协议支持: %s（降级链 h3 → h2 → h1.1）",
            protocols.describe(),
        )
        if not protocols.http2:
            logger.warning(
                "HTTP/2 已在配置中关闭：Windows 11 原生加密 DNS 客户端只支持 "
                "HTTP/2，关闭后系统级 DoH 将无法工作（浏览器等自建 DoH 客户端不受影响）"
            )

    def _detect_internal_port(self, site) -> Optional[int]:
        """取 aiohttp TCPSite 实际绑定的端口（port=0 时由系统分配）"""
        try:
            sockets = getattr(site._server, "sockets", None)
            if sockets:
                return int(sockets[0].getsockname()[1])
        except Exception:
            pass
        try:
            addresses = self._runner.addresses if self._runner else None
            if addresses:
                return int(addresses[0][1])
        except Exception:
            pass
        return None

    async def stop(self):
        """停止 DoH 服务器（协议前端 + 内部站点）"""
        # 先停对外入口，避免停止过程中仍有新请求进来
        if self._frontend is not None:
            try:
                await self._frontend.stop()
            except Exception as e:
                logger.debug("DoH 协议前端停止异常: %s", e)
            self._frontend = None

        # 取消清理任务
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        for site in self._sites:
            try:
                await site.stop()
            except Exception as e:
                logger.debug("DoH 站点停止异常: %s", e)
        self._sites.clear()
        if self._runner:
            try:
                await self._runner.cleanup()
            except Exception as e:
                logger.warning("DoH 服务器 cleanup 异常: %s", e)
            self._runner = None
            logger.info("DoH 服务器已停止")

    async def restart(self):
        """重启 DoH 服务器（IP 切换后恢复监听）

        即使 stop() 部分失败也强制尝试 start()，
        防止服务器在重启过程中永久挂掉。
        """
        await self.stop()
        # 确保 _runner 被重置，避免 start() 使用已清理的旧 runner
        self._runner = None
        await self.start()

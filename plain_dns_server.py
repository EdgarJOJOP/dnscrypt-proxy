"""
本地纯 DNS 服务器（UDP 53 端口 + TCP 53 端口）
- 不加密的 DNS 协议，用于局域网客户端
- 支持 IPv4 + IPv6 双栈
- 默认关闭，需在配置中手动开启
- TCP 支持用于 nginx stream DoT 反代转发
"""

import asyncio
import contextvars
import ipaddress
import logging
import os
import random
import socket
import struct
import sys
import time
from typing import Optional, Dict, Tuple, Any, List

import dns.message
import dns.exception
import dns.query
import dns.asyncquery
import dns.flags
import dns.rcode
import dns.edns
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset
from dns_utils import (
    reorder_answer_aaaa_first,
    sort_dns_response_wire,
    has_global_ipv6,
    probe_ipv6_path,
    make_block_response,
)

from config import Config, DEFAULT_ROOT_SERVERS
from resolver_manager import ResolverManager
from cache import DNSCache
from filter_engine import FilterEngine
from logger import RequestLogger
from dnssec import DNSSECQueryWrapper, DNSSECValidator
from rate_limiter import get_per_ip_limiter

logger = logging.getLogger("dns-proxy.plain-dns")


_V6_DISABLED_CTX: contextvars.ContextVar = contextvars.ContextVar(
    "iterative_v6_disabled", default=False
)
"""本域名本次解析是否已禁用 IPv6（**per-query**，用 ContextVar 隔离）

语义：某一跳的权威服务器里没有可用 IPv6 时，只在**这个域名**的后续跳里
禁用 IPv6（改用 IPv4），其它域名照常按各自的权威集合跨族交错。
asyncio 每个 Task 有独立 context，所以不同域名的并发解析互不影响。
"""


_FAMILY_ONLY_CTX: contextvars.ContextVar = contextvars.ContextVar(
    "iterative_family_only", default=""
)
"""本域名本次解析**优先使用**的地址族："4" / "6" / ""（不限定）

为什么需要：实测有的网络里 IPv4/53 被路由器/运营商/安全软件接管——连
`192.0.2.1`（RFC 5737 TEST-NET 死地址）都能拿到应答，而 IPv6/53 直接到达
真实根服务器（`AA=1`、`OPT` 有、`DO` 回声、`answer` 带 DNSKEY+RRSIG）。
这种链路上 IPv4 应答全是伪造的、且不含任何 DNSSEC 记录；若两族混用，
IPv4 那台"本地设备"的应答总是先到（微秒级），真实 IPv6 应答被丢弃，
DNSSEC 永远判不出来。

处置：启动/预热时判定各族是否真的到达权威（见 `_probe_family_integrity`），
若只有一族是真的，就用本 ContextVar 让该域名的**每一跳**优先走那一族
（该跳没有可用地址时自动回退全族，保证可用性不降级）。
asyncio 每个 Task 独立 context，域名之间互不影响。
"""


_CHAIN_ONLY_CTX: contextvars.ContextVar = contextvars.ContextVar(
    "iterative_chain_only", default=False
)
"""DNSSEC 链查询（DS/DNSKEY/NS）是否强制只用真族。

`iterative.ipv4_verify=corroborate` 只对“解析答案”做真族交叉印证；如果
链验证的 DS/DNSKEY 查询在真族超时/无地址时回退到 IPv4 镜像，就会拿镜像
数据去验签——镜像可能剥离 DNSSEC，等于让被代答的族参与验证。
本标记为 True 时 `_iterate` 的族回退被禁用：真族不可用 → 链查询失败
（dnssec.py 判 indeterminate/bogus），绝不用镜像族的应答。
"""


def _consume_future_exc(fut: asyncio.Future) -> None:
    """消费 future 的异常（不取 result，只取 exception 消除告警）

    UDP transport 的 ``connection_lost`` 是异步回调：调用方已经放弃等待后它才给
    future 设 ``ConnectionError('datagram closed')``，不消费就会触发 asyncio 的
    ``Future exception was never retrieved`` ERROR 刷屏。
    """
    if fut.cancelled():
        return
    try:
        fut.exception()
    except Exception:
        pass


class _UdpQueryProtocol(asyncio.DatagramProtocol):
    """单次 DNS UDP 查询的协议：收到首个数据报即完成 future

    配合 ``IterativeResolver._query_one_async`` 使用——原生 asyncio 收发，
    等待权威应答期间不占工作线程、也不占 CPU（对比 run_in_executor 的
    「线程被阻塞独占」）。transport 用 remote_addr 连接，来源地址由内核过滤；
    上层还会校验响应 ID，双保险防串包/伪造。
    """

    __slots__ = ("future", "transport")

    def __init__(self):
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()
        # transport.close() → connection_lost 是**异步回调**，可能在调用方
        # 已经放弃等待之后才给 future 设异常（ConnectionError('datagram closed')），
        # 于是 asyncio 打 "Future exception was never retrieved" 的 ERROR 刷屏。
        # 挂一个消费回调即可根治（正常路径取 result 不受影响）。
        self.future.add_done_callback(_consume_future_exc)
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        # Windows 上 ICMP 端口不可达会以 ConnectionRefusedError 形式到这里
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_exception(exc or ConnectionError("datagram closed"))

# DNS 最大 UDP 数据报大小（DNSSEC 建议 1232，传统 512）
MAX_UDP_SIZE = 1232

# 无 glue 的 NS 名解析的递归深度上限（远小于 iterative.max_depth）：
# 权威 NS 名通常 1-2 跳解析出来即可，若跟主链一样允许 16 层，一次 referral
# 的 26 个 NS 就会逐层展开成指数级协程/Task（实测 4.4 万协程、1.5GB）。
_NS_RESOLVE_MAX_DEPTH = 3

# Windows WSAIoctl：关闭 UDP socket 的 ICMP「端口不可达」通知
#   SIO_UDP_CONNRESET = _WSAIOW(IOC_VENDOR, 12) = 0x9800000C
# 注意（实测）：Python 的 socket 模块没有 SIO_UDP_CONNRESET 常量，而且
# socket.ioctl() 只接受 SIO_RCVALL / SIO_KEEPALIVE_VALS / SIO_LOOPBACK_FAST_PATH
# 等少数命令，传入其它命令会抛 ValueError("invalid ioctl command")。
# 旧实现走的是 sock.ioctl(socket.SIO_UDP_CONNRESET, False) →
# AttributeError → sock.ioctl(0x58000001, False)（常量为错值）→
# ValueError 被 except 吞掉，抑制从未生效：UDP 53 每收到一次 ICMP Port
# Unreachable 就触发 WSAECONNRESET(10054)，进而重建 transport，
# 重建窗口内的查询被直接丢弃（日志里 10054 与 transport recovered 成对刷屏）。
_SIO_UDP_CONNRESET = 0x9800000C


def _disable_udp_connreset(sock: socket.socket) -> bool:
    """Windows：让 UDP socket 忽略 ICMP 端口不可达（不再报 WSAECONNRESET）。

    必须用 ctypes 调 WSAIoctl —— socket.ioctl() 不支持该命令。
    成功返回 True；非 Windows 或失败返回 False。
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)
        value = wintypes.DWORD(0)   # FALSE = 关闭该通知
        returned = wintypes.DWORD(0)
        rc = ws2_32.WSAIoctl(
            ctypes.c_void_p(sock.fileno()),
            _SIO_UDP_CONNRESET,
            ctypes.byref(value), ctypes.sizeof(value),
            None, 0,
            ctypes.byref(returned), None, None,
        )
        return rc == 0
    except Exception:
        return False


def _safe_qname(qname: str) -> str:
    """过滤 qname 中非可见 ASCII 字符（security_review MEDIUM-1：
    LAN 客户端可经 qname 注入控制序列/伪造日志行——info 级日志进
    控制台与 proxy.log，须清洗后再记录）"""
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in str(qname))


# 迭代解析起点：IANA 根服务器（复用 config 内置常量，避免重复定义）
ROOT_SERVERS = DEFAULT_ROOT_SERVERS


def answer_set_fingerprint(wire_bytes: bytes) -> str:
    """响应答案集指纹（原用于 cross_verify 交叉验证）

    注意：cross_verify 已随新架构废弃，当前全仓无调用方；保留实现以备需要。
    """
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
        # 后台预热根区 DNSKEY 的任务句柄（stop 时取消，避免悬挂任务）
        self._dnssec_warmup_task = None
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

        # ---------- UDP 有界 worker 池 ----------
        # 原实现每个 UDP 请求 `asyncio.ensure_future` 建一个 task，高并发下
        # task 创建/销毁 + 调度 + GC 开销叠加，表现为 p99 长尾（实测 30 并发
        # p50 19.9ms 但 p99 1142ms；同负载 TCP 因「每连接一个常驻协程循环」
        # 只有 25.5ms）。这里改为 N 个常驻 worker 消费有界队列。
        # 数量与队列上限都做范围钳制（与 doh_max_connections 同一风格）。
        self._udp_workers = max(1, int(config.plain_dns_udp_workers))
        # 队列上限必须与 worker 数**解耦**：一开始用 workers*4，worker 少时
        # （如 cpu_core_limit=2 → 2 个 worker，上限只有 8）30 并发瞬间灌满，
        # 大量查询被丢弃 → 客户端全部超时。这里给一个与并发规模匹配的下限。
        self._udp_queue_max = max(1024, self._udp_workers * 32)
        self._udp_queue: Optional[asyncio.Queue] = None
        self._udp_worker_tasks: List[asyncio.Task] = []
        self._udp_dropped = 0
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
            if sys.platform == "win32" and not _disable_udp_connreset(sock):
                logger.debug(
                    "SIO_UDP_CONNRESET 抑制失败（%s:%d）：ICMP 端口不可达仍会"
                    "触发 WSAECONNRESET，但已不再重建 transport", host, port,
                )
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
            """UDP socket 错误回调。

            WSAECONNRESET(10054) 只是「此前某次 sendto 收到 ICMP 端口不可达」
            的回执通知，socket 本身仍可继续收发。旧实现在这里重建 transport，
            重建窗口内到达的查询会被直接丢弃（日志里 10054 与
            "transport recovered" 成对刷屏）。socket 层现已用
            SIO_UDP_CONNRESET 抑制该通知；即便仍出现，也只降级为 debug 日志，
            不再重建（重建只对真正损坏的 socket 有意义）。
            """
            if getattr(exc, "winerror", None) == 10054:
                logger.debug("UDP ICMP 端口不可达（WSAECONNRESET），忽略: %s", exc)
                return
            logger.warning("UDP 错误: %s", exc)

    def _handle_query(self, data: bytes, addr: tuple, transport: asyncio.DatagramTransport):
        """收到 DNS 查询 UDP 数据报：投递到有界 worker 队列

        原实现：`asyncio.ensure_future(self._process_query(...))` —— 每个请求
        建一个 task。高并发下 task 创建/调度/GC 与协程切换叠加，p99 长尾明显。

        现在：N 个常驻 worker 从有界队列取任务；队列满时**丢弃**（UDP 语义
        允许丢包，客户端超时会重传），并周期性告警提示调大 worker 数。
        """
        q = self._udp_queue
        if q is None:
            return
        try:
            q.put_nowait((data, addr, transport))
        except asyncio.QueueFull:
            self._udp_dropped += 1
            # 每 1000 次告警一条，避免刷屏
            if self._udp_dropped % 1000 == 1:
                logger.warning(
                    "普通 DNS [UDP] 队列已满（上限 %d），累计丢弃 %d 个查询；"
                    "可调大 server.plain_dns.udp_workers 缓解",
                    self._udp_queue_max, self._udp_dropped)

    async def _udp_worker_loop(self):
        """常驻 UDP worker：从队列取查询并处理，异常不退出循环"""
        q = self._udp_queue
        while True:
            try:
                data, addr, transport = await q.get()
            except asyncio.CancelledError:
                raise
            try:
                await self._process_query(data, addr, transport)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("普通 DNS [UDP] worker 处理异常: %s", e)
            finally:
                q.task_done()

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
        if result:
            # RFC 1035 §4.2.1 / RFC 6891：按客户端缓冲截断并置 TC，避免靠 IP 分片
            result = self._fit_udp_response(data, result)
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
                    # 消费该帧并回 FORMERR，然后继续服务同一连接上的后续查询
                    # （RFC 7766 允许连接复用，不应因单个坏帧丢弃后续查询）
                    try:
                        short_data = await asyncio.wait_for(
                            reader.readexactly(length), timeout=30.0
                        )
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                        break
                    err = self._make_error_wire(short_data, dns.rcode.FORMERR)
                    if err:
                        writer.write(struct.pack('!H', len(err)) + err)
                        await writer.drain()
                    continue
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
                else:
                    # 无响应（None/空）：回 FORMERR，避免客户端在已建立连接上挂起
                    err = self._make_error_wire(data, dns.rcode.FORMERR)
                    if err:
                        writer.write(struct.pack('!H', len(err)) + err)
                        await writer.drain()
                    else:
                        break
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
                # RFC 1035：QDCOUNT=0 的查询应回 FORMERR，而非静默丢弃
                #（静默丢弃会让 TCP 客户端在已建立连接上一直等）
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.FORMERR)
                return response.to_wire()

            question = query.question[0]
            qname = str(question.name).rstrip(".")
            qtype_str = dns.rdatatype.to_text(question.rdtype)
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
                    # **拦截条目的缓存键不含 DO/CD 位**（2026-10-30）：
                    # 拦截响应固定是 NXDOMAIN + 合成 SOA，与 DNSSEC 需求无关；
                    # 而浏览器/系统解析器会**交替用 DO=0 / DO=1** 查同一域名。
                    # 若沿用含 DO 的 `cache_key`，每种组合都要"首次 blocked 一次"
                    # （实测同一 client_ip 同一 qtype 一秒内出现两条 blocked，
                    # 看起来像缓存完全没生效）。这里改用 (name, type, class)，
                    # 让 DO/CD 不同的查询共享同一条拦截缓存。
                    # 规则放宽后由 _sweep_cache_after_filter_load 按 blocked 标记清理。
                    _block_key = (question.name, question.rdtype, question.rdclass)
                    # **先查缓存**（2026-10-30，关键修复）：
                    # 拦截结果原本会写进缓存，但 `cache.get` 在过滤分支**之后**，
                    # 被拦域名在这个分支就 return 了 —— 缓存永远读不到。
                    # 后果：每来一次查询都重新 make_response + cache.set + to_wire
                    # + 落日志（实测 data.bilibili.com 一次会话被拦 1.8 万次，
                    # 日志里状态全是 "blocked" 而非 "cached"），这些重复工作在
                    # 浏览器并发时与纯迭代查询抢事件循环。
                    # 现在命中缓存的拦截条目直接秒回（与 AdGuard Home 同款行为）。
                    if self.config.cache_enabled:
                        _hit = await self.cache.get(_block_key)
                        if _hit is not None:
                            import copy as _copy
                            _hit = _copy.copy(_hit)
                            reorder_answer_aaaa_first(_hit)
                            _hit.id = query.id
                            elapsed = asyncio.get_event_loop().time() - start_time
                            await self._log_query(
                                client_ip, qname, qtype_str, elapsed,
                                "cached", block_reason,
                            )
                            return _hit.to_wire()
                    # 拦截统一返回 NXDOMAIN + 合成 SOA（2026-10-30）：
                    # 原先 A/AAAA 被重写成 0.0.0.0 / ::（block_ip 机制），客户端会去连
                    # 这个假地址、连不上就无限重试——实测 data.bilibili.com 一次会话
                    # 被拦 1.8 万次、单分钟 299 次，重试挤占前端与事件循环，叠加
                    # 缓存预刷新把纯迭代上游打满（日志出现「迭代解析连续全部失败」），
                    # 连带其它客户端（游戏/加速器）解析超时。
                    # NXDOMAIN 让客户端按"域名不存在"处理，不再重连重试。
                    # block_ip / block_nxdomain 两个配置项随之废弃。
                    # 报文构造集中在 dns_utils.make_block_response，
                    # plain/DoH/DoT/DoQ 与 main 的缓存清扫必须完全一致。
                    response = make_block_response(query, self.config)
                    if self.config.cache_enabled:
                        await self.cache.set(
                            _block_key, response,
                            response.rcode() == dns.rcode.NXDOMAIN,
                            blocked=True,
                        )
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
                #
                # 纯迭代 + strict_dnssec：迭代器内部已完成严格链验证（resolver
                # 层同样跳过），此处必须一起跳过——否则 wrapper 对 NXDOMAIN/
                # NSEC 的判定与迭代器不一致，会把合法负应答误判 bogus，在
                # drop_bogus=true 时变成 SERVFAIL（不存在的域名全部解析失败）。
                if (self._dnssec_wrapper is not None and self.config.dnssec_enabled
                        and not self.resolver_manager.iterative_already_verified()):
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

                # 缓存结果（status 已不再包含旧架构的 "iterative" 值）
                if self.config.cache_enabled and status == "resolved" and result_wire is not None:
                    try:
                        response_msg = dns.message.from_wire(result_wire)
                        reorder_answer_aaaa_first(response_msg)
                        is_negative = self._is_negative_response(response_msg)
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception as e:
                        logger.debug("Plain DNS 缓存写入异常: %s", e)

            elapsed = asyncio.get_event_loop().time() - start_time
            await self._log_query(client_ip, qname, qtype_str, elapsed, status, block_reason)
            result_wire = sort_dns_response_wire(result_wire)
            # 上游直连路径的响应 ID 可能与查询不一致：DoH（RFC 8484）与 DoQ
            # （RFC 9250）上游按协议要求用 ID=0 发起查询，其响应 ID 会被原样
            # 透传给客户端。若客户端校验 ID（dig、DoT/DoQ 前端），会丢弃该响应
            # 并等待超时，表现为查询卡顿，故在返回前统一重写为查询 ID。
            # 对 make_response(query) 生成的响应（ID 本已正确）是幂等的。
            if result_wire:
                try:
                    _resp = dns.message.from_wire(result_wire)
                    if _resp.id != query.id:
                        _resp.id = query.id
                        result_wire = _resp.to_wire()
                except Exception as e:
                    logger.debug("Plain DNS 响应 ID 重写异常: %s", e)
            return result_wire

        except dns.exception.DNSException as e:
            logger.debug("DNS 解析错误: %s", e)
            return self._make_error_wire(data, dns.rcode.FORMERR)
        except Exception as e:
            logger.error("处理 DNS 查询异常: %s", e)
            return self._make_error_wire(data, dns.rcode.SERVFAIL)

    @staticmethod
    def _make_error_wire(data: bytes, rcode: int) -> Optional[bytes]:
        """从原始查询报文尽力构造错误响应（保留 ID / RD / CD），失败返回 None

        用于报文解析失败或无正常响应时，避免客户端（尤其 TCP）无限等待。
        """
        try:
            if len(data) < 2:
                return None
            qid = int.from_bytes(data[:2], "big")
            flags_in = int.from_bytes(data[2:4], "big") if len(data) >= 4 else 0
            # QR=1；回显 RD(0x0100) / CD(0x0010)；rcode 放低 4 位
            flags = 0x8000 | (flags_in & 0x0110) | (int(rcode) & 0x000F)
            return struct.pack("!HHHHHH", qid, flags, 0, 0, 0, 0)
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
        # RFC 2308 §7：只允许缓存 NXDOMAIN 与 NODATA。REFUSED / SERVFAIL 属于
        # 错误应答，不是"名字不存在"，不能当负应答（缓存层 cache.set 亦已直接
        # 拒绝非 NOERROR/NXDOMAIN 的响应，这里同步去掉避免语义混淆）。
        if rcode == dns.rcode.NXDOMAIN:
            return True
        return rcode == dns.rcode.NOERROR and not msg.answer

    @staticmethod
    def _udp_max_payload(query_wire: bytes) -> int:
        """客户端可接受的最大 UDP 响应长度（RFC 1035 §4.2.1 / RFC 6891 §6.2.5）

        无 EDNS0 的客户端一律 512 字节；有 EDNS0 时取声明值的下界 512、
        上界 MAX_UDP_SIZE（1232，避免路径 MTU 分片）。
        """
        try:
            query = dns.message.from_wire(query_wire)
        except Exception:
            return 512
        if query.edns >= 0:
            size = query.payload
            if not size or size < 512:
                size = 512
            return min(size, MAX_UDP_SIZE)
        return 512

    def _fit_udp_response(self, query_wire: bytes, response_wire: bytes) -> bytes:
        """UDP 响应超过客户端缓冲时截断并置 TC 位

        未截断时超长响应只能依赖 IP 分片，NAT/防火墙常丢非首片 → 客户端超时；
        截断后客户端会改用 TCP 重试（RFC 1035 §4.2.1）。
        """
        if not response_wire:
            return response_wire
        max_len = self._udp_max_payload(query_wire)
        if len(response_wire) <= max_len:
            return response_wire
        try:
            msg = dns.message.from_wire(response_wire)
            msg.flags |= dns.flags.TC
            for section in (msg.additional, msg.authority, msg.answer):
                while section and len(msg.to_wire()) > max_len:
                    section.pop()
            wire = msg.to_wire()
            if len(wire) <= max_len:
                return wire
        except Exception as e:
            logger.debug("UDP 响应截断处理异常: %s", e)
        try:
            minimal = dns.message.make_response(dns.message.from_wire(query_wire))
            minimal.flags |= dns.flags.TC
            return minimal.to_wire()
        except Exception:
            return response_wire

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

        started = False

        # 启动 UDP 有界 worker 池（先起 worker 再挂 transport，避免首批包无人消费）
        self._udp_queue = asyncio.Queue(maxsize=self._udp_queue_max)
        self._udp_worker_tasks = [
            asyncio.create_task(self._udp_worker_loop())
            for _ in range(self._udp_workers)
        ]
        logger.info("普通 DNS [UDP] 有界 worker 池: %d 个 worker，队列上限 %d",
                    self._udp_workers, self._udp_queue_max)

        # ---------- UDP ----------
        try:
            sock_v4 = self._create_udp_socket(self.host, self.port, socket.AF_INET)
            transport_v4, protocol_v4 = await loop.create_datagram_endpoint(
                lambda: self._DnsProtocol(self),
                sock=sock_v4,
            )
            self._transport_v4 = transport_v4
            started = True
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
                started = True
                logger.info("普通 DNS [UDP IPv6] udp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [UDP IPv6] 启动失败: %s", e)

        # ---------- TCP ----------
        try:
            self._tcp_server_v4 = await asyncio.start_server(
                self._handle_tcp_connection, self.host, self.port,
                backlog=self._tcp_backlog,
            )
            started = True
            logger.info("普通 DNS [TCP IPv4] tcp://%s:%d", self.host, self.port)
        except OSError as e:
            logger.warning("普通 DNS [TCP IPv4] 启动失败: %s", e)

        if self.ipv6_enabled:
            try:
                # 显式设置 IPV6_V6ONLY（与 UDP 侧 _create_udp_socket 一致）：
                # Linux 默认 v6only=0 时，绑定 "::" 会与已绑定的 IPv4 0.0.0.0:53
                # 冲突 → TCP IPv6 静默不可用。
                sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                try:
                    sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock6.bind((self.ipv6_host, self.port))
                    sock6.listen(self._tcp_backlog)
                except OSError:
                    sock6.close()
                    raise
                self._tcp_server_v6 = await asyncio.start_server(
                    self._handle_tcp_connection, sock=sock6,
                )
                started = True
                logger.info("普通 DNS [TCP IPv6] tcp://[%s]:%d", self.ipv6_host, self.port)
            except OSError as e:
                logger.warning("普通 DNS [TCP IPv6] 启动失败: %s", e)

        if not started:
            logger.error("普通 DNS 未能监听任何地址（UDP/TCP 全部失败），服务未启动")
        self._running = started

        # 后台预热根区 DNSKEY：不阻塞监听启动，只在该进程启用迭代解析时做。
        # 冷启动首个查询最容易在“根 DNSKEY 还没验证并缓存”时超时，预热
        # 可以把这一级的失败率降到最低；失败也不影响服务（查询路径会重试）。
        if started and self.iterative_enabled and self.iterative_resolver is not None:
            try:
                self._dnssec_warmup_task = asyncio.create_task(
                    self.iterative_resolver.warmup_dnssec_chain())
            except Exception as e:
                self._dnssec_warmup_task = None
                logger.debug("DNSSEC 根区预热任务创建失败: %s", e)



    async def stop(self):
        """停止 DNS 服务器（UDP + TCP）"""
        self._running = False

        # 取消后台根区 DNSKEY 预热任务（避免 stop 后还挂着网络任务）
        warmup_task = getattr(self, "_dnssec_warmup_task", None)
        if warmup_task is not None and not warmup_task.done():
            warmup_task.cancel()
        self._dnssec_warmup_task = None

        # 停止 UDP worker 池（先停生产侧 transport，再取消 worker）
        for transport in [self._transport_v4, self._transport_v6]:
            if transport and not transport.is_closing():
                try:
                    transport.close()
                except Exception as e:
                    logger.debug("Plain DNS 传输关闭异常: %s", e)
        self._transport_v4 = None
        self._transport_v6 = None
        for task in self._udp_worker_tasks:
            task.cancel()
        if self._udp_worker_tasks:
            await asyncio.gather(*self._udp_worker_tasks, return_exceptions=True)
        self._udp_worker_tasks = []
        self._udp_queue = None

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
        # 每跳并行协程数（iterative.hop_parallel，默认 2）：同一跳同时向 2 台
        # 候选服务器发非递归查询，先回者胜（见 _query_servers）。钳制 1-4。
        self.hop_parallel = max(
            1, min(4, int(config.plain_dns_iterative_hop_parallel))
        )
        # QNAME 最小化（RFC 9156，iterative.qname_minimization，默认 true）：
        # 向根/TLD 只发「下一级名字」，完整查询名只发给最终权威。
        try:
            self.qname_minimization = bool(config.plain_dns_iterative_qname_minimization)
        except Exception:
            self.qname_minimization = True
        if not self.strict_dnssec:
            # security_review MEDIUM：strict_dnssec=False 时迭代响应未做 DNSSEC
            # 严格验证即返回（无第二信任源指纹兜底——cross_verify 已随新架构
            # 静默失效），向客户端/缓存放行未验证响应，须显式告警
            logger.warning(
                "迭代解析 strict_dnssec=False：未验证的迭代响应将被放行"
                "（DNSSEC 剥离/投毒检测失效，建议开启 strict_dnssec）",
            )
        # cross_verify：原“迭代 vs 加密上游交叉验证”语义已废弃——新架构下迭代解析
        # 作为独立上游与加密上游并行竞争（最快响应胜出），无需独立交叉验证。
        # 此前在此赋值 self.cross_verify 但全仓无任何读取方（config 项
        # plain_dns_iterative_cross_verify 因此失效），已删除该死代码。
        root = config.plain_dns_iterative_root_servers
        self.root_servers = [str(x) for x in root] if root else list(ROOT_SERVERS)
        # IPv6 可用性：**地址探测 + 跨族连通性探测**
        #   1) 网卡上必须存在全局 IPv6 地址（否则直接只用 IPv4）；
        #   2) 再**同时**向一个 IPv6 根和一个 IPv4 根发真实 DNS 查询：
        #      v6 根有应答 → IPv6 真的能出网；v4 根有应答作为对照，
        #      用来区分「IPv6 不通」和「整体断网」（两者日志/处置不同）。
        # 任一条件不满足 → 本次运行**提前禁用 IPv6**，迭代只用 IPv4。
        self._has_ipv6 = has_global_ipv6()
        if self._has_ipv6:
            _v6_ok, _v4_ok = probe_ipv6_path()
            self._has_ipv6 = _v6_ok
            if not _v6_ok:
                if _v4_ok:
                    logger.warning(
                        "IPv6 探测：v6 根无应答、v4 根正常 → 确认 IPv6 不通，"
                        "本次运行迭代解析只用 IPv4"
                    )
                else:
                    logger.warning(
                        "IPv6 探测：v6 根与 v4 根均无应答 → 出网异常，"
                        "本次运行迭代解析只用 IPv4"
                    )
        else:
            logger.info("IPv6 探测：本机无全局 IPv6 地址 → 迭代解析只用 IPv4")
        # 运行时降级是**按跳/按域名**的（见 `_query_servers` 的 `_hop_v6_fail`）：
        # 某一跳的 v6 权威不可用只影响该跳，不会全局禁用 v6、也不影响其它域名。
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
        #
        # 上限 30s（2026-10-30）：原公式随 max_depth 线性放大，timeout_ms=5000 +
        # max_depth=32 时算出 304s，而前端 DoH 6s 就给客户端回了 504、系统 UDP
        # 客户端更早重试——304s 的"预算"实际等于取消永不生效，与 resolver 层
        # 硬上限、前端 forward_timeout 三层互相矛盾（日志里 152s/304s 与 10s 并存）。
        # 收敛到 30s 后：正常查询（0.3-4s）与长 CNAME 链（10-15s）都能完成并写
        # 缓存，真正卡死的查询也不会无限空跑。
        _per_hop_max = min(3.0, max(1.0, len(self.root_servers) * 0.25))
        self.total_timeout = min(
            30.0,
            max(
                15.0,
                self.timeout * self.max_depth
                + (self.timeout + 1.0) * _per_hop_max * self.max_depth * 0.5,
            ),
        )
        # 独立 DNSSEC 验证器（内置根信任锚），回调指向迭代解析自身 → 全链自举。
        # 必须按 upstream.dnssec.* 构造：config.yaml 明确说明该段“对全部上游
        # 完整生效——包括 iterative:”。旧实现硬编码 enabled=True/mode="strict"，
        # 用户把 dnssec 关掉或改成 ad_check / require_rrsig=true 时迭代链路
        # 仍按 strict 跑，配置与行为不一致。
        self._dnssec = dnssec_validator or DNSSECValidator(
            enabled=bool(getattr(config, "dnssec_enabled", True)),
            mode=str(getattr(config, "dnssec_mode", "strict")),
            require_rrsig=bool(getattr(config, "dnssec_require_rrsig", False)),
        )
        # DNSSEC 数学验签后端（dnspython 依赖 cryptography）。
        # 缺失时 dns.dnssec.validate() 抛 ImportError；链验证全部在 dnssec.py，
        # 它会显式检测并把结果判为 indeterminate（而不是误判 secure/bogus）。
        # 这里只记录本机能力，供上层按 require_rrsig 决定放行/丢弃。
        self._dnssec_crypto_ok = True
        try:
            import cryptography  # noqa: F401
        except Exception as _crypto_err:
            self._dnssec_crypto_ok = False
            logger.error(
                "DNSSEC 验签后端不可用（缺少 cryptography：%s）。严格模式无法验证 "
                "RRSIG/DS 链，所有无签名应答将按「无法证明」处理；"
                "请执行 pip install cryptography", _crypto_err,
            )
        # ============================================================
        # 「本链路到底能不能做 DNSSEC 验证」的能力证据
        # ------------------------------------------------------------
        # 纯迭代模式没有加密上游可回退，所以 strict_dnssec 一旦建立不起信任链，
        # 整机解析就会全盘 SERVFAIL（日志表现为：所有域名都报「应答没有签名
        # (RRSIG)，也没有能证明该域名本就未签名的 NSEC/NSEC3」，紧接着
        # 「纯迭代模式：迭代解析连续 N 轮全部失败」）。实测这类环境的共同点
        # 是**链路根本不提供 DNSSEC 材料**：根区 `. DNSKEY` 被中间盒回成
        # NXDOMAIN / 应答里没有任何 RRSIG / DS 的 NODATA 只有 SOA 没有 NSEC3。
        #
        # 此时 strict 验证在数学上不可能成功（连根信任锚都验证不了），继续
        # 逐域名判「无法证明」既救不了安全，又让服务完全不可用。
        # 处置与 resolver 层 dnssec.py 的既有语义保持一致：
        #   * require_rrsig=false（默认）：按「未验证放行」处理 + 节流告警；
        #   * require_rrsig=true（安全优先）：仍然 fail-closed 丢弃。
        # `_dnssec_evidence` 记录最近一次统一验证链的结论（ok/absent/
        # bogus_root/unavailable）；链本身的缓存与 TTL 全部由 dnssec.py 维护
        # （_root_avail / _verified_zone_cache），"网络被修好"能自动恢复。
        try:
            self._require_rrsig = bool(self.config.dnssec_require_rrsig)
        except Exception:
            self._require_rrsig = False
        self._dnssec_evidence = "unknown"
        self._dnssec_evidence_detail = ""
        # 地址族完整性：{"4"/"6": "genuine"/"hijacked"/"unreachable"}。
        # 用来识别「某一族 53 端口被中间设备代答」——实测 IPv4 被接管、
        # IPv6 直达权威的网络，只有换到真族才能拿到 DNSSEC 记录。
        self._family_verdicts: Dict[str, str] = {}
        self._family_probe_at = 0.0
        # 上一次族探测是否两族都给出确定结论（决定把结论缓存 600s 还是 60s，
        # 见 `_ensure_family_preference`：unreachable 只是探测失败，不是结论）
        self._family_probe_reliable = False
        # 地址族策略（iterative.family：auto/ipv4/ipv6）与「无 DNSSEC 能力的
        # 地址族」的验证策略（iterative.ipv4_verify：strict/corroborate/none）
        try:
            self._family_policy = str(
                config.plain_dns_iterative_family or "auto").lower()
        except Exception:
            self._family_policy = "auto"
        if self._family_policy not in ("auto", "ipv4", "ipv6"):
            self._family_policy = "auto"
        try:
            self._ipv4_verify = str(
                config.plain_dns_iterative_ipv4_verify or "strict").lower()
        except Exception:
            self._ipv4_verify = "strict"
        if self._ipv4_verify not in ("strict", "corroborate", "none"):
            self._ipv4_verify = "strict"
        # 强制族优先：policy=ipv4/ipv6 时直接锁定，不做自动判定
        self._preferred_family = {
            "ipv4": "4", "ipv6": "6",
        }.get(self._family_policy, "")
        if self._family_policy != "auto":
            logger.warning(
                "迭代地址族策略: iterative.family=%s → 强制只用 IPv%s"
                "（自动族判定不再改变该选择；IPv4 镜像链路上 DNSSEC 通常不可"
                "验证，可用 iterative.ipv4_verify=corroborate 做交叉印证）",
                self._family_policy, self._preferred_family)
        if self._ipv4_verify != "strict":
            logger.warning(
                "迭代 IPv4 验证策略: iterative.ipv4_verify=%s → 对「不是真权威"
                "的地址族」的应答%s", self._ipv4_verify,
                "改用真族交叉印证（不一致即丢弃）"
                if self._ipv4_verify == "corroborate" else "不做额外校验")
        # 「该应答走了被代答的地址族 → 未验证放行」告警的节流状态
        self._hijack_warn_last = 0.0
        self._hijack_warn_merged = 0
        try:
            self._dnssec.set_dns_query_callback(self._dnssec_query_callback)
        except Exception:
            pass
        self._stats = {
            "queries": 0, "success": 0, "fail": 0,
            "bogus": 0, "insecure": 0, "secure": 0, "depth_exceeded": 0,
            # 因「本链路不提供任何 DNSSEC 材料」而降级放行的次数
            # （require_rrsig=false 时，由统一验证链判为 insecure 后降级）
            "dnssec_absent": 0,
            # 因「该应答走了已被判定为代答的地址族」而降级放行的次数
            # （见 _probe_family_integrity / _report_hijacked_path）
            "hijacked_path": 0,
            # 交叉印证（iterative.ipv4_verify=corroborate）：
            #   corroborated = 用真族成功交叉印证（不一致时也计入，另加 mismatch）
            #   mismatch     = 镜像族答案与真族不一致（疑似中间人，已改用真族答案）
            "corroborated": 0,
            "mismatch": 0,
        }
        self._ns_ip_cache: Dict[str, List[str]] = {}
        # 权威服务器健康度：ip -> (EWMA 往返耗时秒, 连续失败次数)
        # 目的：每跳默认只并行 2 台候选，而根/TLD 权威常有 20+ 台、其中部分是
        # 跨境或异常节点（实测同一跳里的 192.31.80.30 等会反复被选中，每次都
        # 先把 200-400ms 的 RTT 付出去）。有了这张表，`_query_servers` 的跨族
        # 交错里会优先排「历史上回得快」的 IP，把「踩到慢权威」的代价从每跳
        # 一次 RTT 降为偶发。
        self._server_health: Dict[str, tuple] = {}
        # DNS Cookie（RFC 7873）：降低 off-path 伪造响应被接受的概率。
        #   _cookie_secret : 进程级随机 secret（重启即变），用于派生 client cookie
        #   _server_cookies: ip -> 服务端返回的 server cookie（8-32 字节）
        #   _cookie_disabled: 明确不支持 COOKIE 的权威 IP（收到 FORMERR/BADVERS 时
        #                     记入，之后对该 IP 不再发送 COOKIE，避免反复失败）
        self._cookie_secret: bytes = os.urandom(16)
        self._server_cookies: Dict[str, bytes] = {}
        self._cookie_disabled: set = set()
        # 区域权威服务器缓存：zone 名 -> (权威 IP 列表, 失效时间戳)
        # 作用：CNAME 目标/同一 TLD 的后续查询不必再从根逐跳（实测一次
        # www.baidu.com 会为 CNAME 目标重复走 root→com.→baidu.com）。
        # 只缓存 referral 给出的 NS+glue（与解析器自身的 NS 缓存同源），TTL 取 NS TTL。
        self._zone_ns_cache: Dict[str, tuple] = {}
        # DS 响应缓存：zone 名 -> (响应, 失效时间戳)。
        # DNSSECValidator 的 DS 查询回调经过 `_iterate_ds_cached`，同一 zone
        # 的并发查询合并为一次（single-flight），失败短负缓存 5s。
        self._ds_cache: Dict[str, tuple] = {}
        self._ds_inflight: Dict[str, asyncio.Future] = {}
        # 最近一次 _resolve_verified 的放行原因（"chain_unavailable" / "bootstrap" /
        # "insecure" / "secure" / ""）。resolve() 的重试据此判断"第二次放行"是否
        # 只是查询失败/兜底造成的降级，避免把首次已判 bogus 的结论放过去。
        self._last_release = ""
        # DNSSEC 统一验证丢弃告警的 60s 合并状态（防客户端重试刷屏）
        self._dnssec_drop_warn_last = 0.0
        self._dnssec_drop_warn_merged = 0
        # bootstrap 递归兜底的并发闸门（只用于 CDN 调度域名 NODATA 场景）
        self._bootstrap_sem = asyncio.Semaphore(4)
        # 启动期 bootstrap 能力探测：哪些递归上游能返回 NSEC3/RRSIG/DS
        # 证明、哪些只能普通解析、哪些完全不可达。None = 尚未探测；
        # 探到空列表时不要在每次链查询里反复重试全部 bootstrap。
        self._bootstrap_probe_at = 0.0
        self._bootstrap_probe_expire = 0.0
        self._bootstrap_dnssec_resolvers: Optional[List[str]] = None
        self._bootstrap_alive: Optional[List[str]] = None
        self._bootstrap_probe_detail: Dict[str, str] = {}
        self._bootstrap_probe_task: Optional[asyncio.Task] = None
        # **迭代 UDP 并发闸门**（2026-10-30）：`_query_one_async` 走原生 asyncio
        # 数据报端点，**不经过 task_pool 的 PriorityGate**，所以原来没有任何上限。
        # 浏览器一次开几个标签就能并发几十个域名，每跳又并行 hop_parallel(2) 台
        # → 200+ 个 UDP 同时在飞；根/TLD 权威有 RRL 限速，于是大面积失败、
        # 「迭代解析连续全部失败」反复出现，把游戏等其它客户端的解析一起拖垮。
        # 上限由 `performance.iterative_max_inflight` 控制（默认 128，钳制 16-1024）：
        # 超出的查询排队等待，宁可慢一点，也不要让上游被打爆后全军覆没。
        try:
            _inflight_limit = int(getattr(config, "iterative_max_inflight", 128))
        except Exception:
            _inflight_limit = 128
        _effective_limit = max(16, min(1024, _inflight_limit))
        self._inflight_sem = asyncio.Semaphore(_effective_limit)
        logger.info("迭代上游并发闸门: 最多 %d 个单台查询同时在飞"
                    "（performance.iterative_max_inflight）", _effective_limit)
        # 迭代查询是阻塞 socket 调用，统一交给 task_pool 的共享池 + 优先级闸门
        # （等级 DNS > NDP > ARP），NTP/日志另有专属通道，互不排队。
        # 注意：`_query_one_async` 已改为原生 asyncio，不占线程池；
        # 真正约束它并发的是上面的 `_inflight_sem`。

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def _report_hijacked_path(self, qname: str, answer_ip: str):
        """该应答来自已被判定为「中间设备代答」的地址族 → 未验证放行

        **只在 `iterative.ipv4_verify=strict` 时告警**：
          * corroborate：镜像族的每一条应答都已经用真族重解析同一问题印证过
            （不一致会由 `_report_dnssec_mismatch` 单独打「疑似中间人」告警），
            单独再为"这条没验证"刷一条 WARNING 纯属噪音；
          * none：本来就是"只保可用性、不做额外校验"，逐条告警更没有意义；
          * strict：用户主动选择了"维持严格判定"，此时必须让他看到
            "这条数据没验证过、原因是代答族"。
        统计计数（`hijacked_path`）在调用方无条件累加，因此静默不影响可观测性。
        节流：strict 下 60 秒一条 WARNING，其余降为 DEBUG 并合并计数。
        """
        _mode = getattr(self, "_ipv4_verify", "strict")
        if _mode != "strict":
            logger.debug(
                "DNSSEC 未验证放行（代答族，ipv4_verify=%s 不告警）: %s ← %s",
                _mode, _safe_qname(qname), answer_ip)
            return
        now = time.monotonic()
        last = getattr(self, "_hijack_warn_last", 0.0)
        if now - last >= 60.0:
            merged = getattr(self, "_hijack_warn_merged", 0)
            self._hijack_warn_last = now
            self._hijack_warn_merged = 0
            suffix = f"（最近 60 秒同类共 {merged + 1} 次）" if merged else ""
            logger.warning(
                "DNSSEC 无法验证，降级放行 %s%s：应答来自已被判定为「中间设备"
                "代答」的地址族（来源 %s，AA/OPT 均不符合真权威形态），该族"
                "不可能下发 DNSSEC 记录。已按 require_rrsig=false 的语义放行"
                "（未经验签）；如需 fail-closed，请把 upstream.dnssec."
                "require_rrsig 设为 true",
                _safe_qname(qname), suffix, answer_ip,
            )
        else:
            self._hijack_warn_merged += 1
            logger.debug("DNSSEC 无法验证，降级放行（代答族，已合并计数）: %s",
                         _safe_qname(qname))

    async def _resolve_over_genuine(self, qname: str, qtype: int,
                                    rdclass: int) -> Optional[dns.message.Message]:
        """在与当前不同的**真族**上重解析同一问题（用于交叉印证镜像答案）

        背景：境内 IPv4 根服务器 IP 由镜像应答、镜像不下发 DNSSEC；IPv6 方向
        通常直达真实权威。`iterative.ipv4_verify=corroborate` 时，凡是走过
        非真族（`_hijacked_path`）的应答，都要在这里用真族重解析一次：
          * 真族答案随后走完整 DNSSEC 验签（这是"最大有效能"的验证强度）；
          * 两者内容不一致 → 说明镜像在说谎 → 调用方丢弃并告警；
          * 真族拿不到（该名字的权威只有 IPv4）→ 返回 None，由调用方按
            `require_rrsig` 降级放行并标注未验证。

        返回 None 表示"无法交叉印证"。只读操作，不修改缓存/统计。
        """
        _policy = getattr(self, "_family_policy", "auto")
        cur = (_FAMILY_ONLY_CTX.get("")
               or getattr(self, "_preferred_family", "") or "")
        # 选「与当前不同、且判定为 genuine」的那一族做印证源
        # （这样 family=ipv4 强制走镜像时，仍能用 IPv6 真族去印证）
        _verdicts = getattr(self, "_family_verdicts", None) or {}
        alt = ""
        for fam in ("6", "4"):
            if fam != cur and _verdicts.get(fam) == "genuine":
                alt = fam
                break
        if not alt:
            return None
        if not any(self._family_of(ip) == alt for ip in self.root_servers):
            return None
        # 交叉印证的**耗时上限**与失败负缓存：
        # 对「权威只有 IPv4」（境内大量站点）的域名，真族根本走不到最后，
        # 每次都为它跑一遍完整 v6 链会白付几秒延迟。这里给单次尝试设上限
        # （≤2s），失败按 域名+类型 缓存 60 秒，避免同一域名反复空跑。
        _ck = "%s|%d" % (str(qname).rstrip(".").lower(), int(qtype))
        _now = time.time()
        _fail = getattr(self, "_corrob_fail", None)
        if _fail is None:
            _fail = {}
            self._corrob_fail = _fail
        if _fail.get(_ck, 0.0) > _now:
            return None
        _budget = max(0.8, min(2.0, float(getattr(self, "timeout", 2.0))))
        token = _FAMILY_ONLY_CTX.set(alt)
        try:
            alt_resp = await asyncio.wait_for(
                self._iterate(qname, qtype, 0, rdclass), timeout=_budget)
        except Exception:
            alt_resp = None
        finally:
            _FAMILY_ONLY_CTX.reset(token)
        if alt_resp is None or getattr(alt_resp, "_hijacked_path", False):
            if len(_fail) > 2048:
                _fail.clear()
            _fail[_ck] = _now + 60.0
            return None
        return alt_resp

    def _report_dnssec_mismatch(self, qname: str, answer_ip: str):
        """镜像族答案与真族答案不一致 → 疑似中间人（已改用真族答案）

        这是 `iterative.ipv4_verify=corroborate` 的核心告警：境内 IPv4 镜像
        即使伪造得很像真权威（AA/OPT/DO 齐全），只要它与 IPv6 真族的答案
        不一致，就说明它在说谎。此时我们**不采信镜像**，直接把真族答案交给
        后续 DNSSEC 验签，因此数据仍然是正确的——告警的意义是提示这条链路上
        确实存在篡改行为，值得排查（路由/代理/运营商）。
        """
        logger.warning(
            "⚠️ 疑似中间人: %s 的 IPv4 镜像答案与 IPv6 真族不一致（来源 %s）"
            " → 已丢弃镜像答案，改用真族答案（随后按 DNSSEC 验签）",
            _safe_qname(qname), answer_ip)

    def _warn_dnssec_drop(self, qname: str, status: str, detail: str = "",
                          cname_hop: bool = False):
        """DNSSEC 统一验证丢弃告警：60 秒合并，避免客户端重试刷屏

        客户端（浏览器/系统解析器）对 SERVFAIL 会以亚秒级重试；一次真实
        丢弃会在几秒内产生几十条完全相同的 WARNING。旧实现每条都打
        WARNING（且 resolve 内部还会重试一次），日志被单一域名淹没。这里
        全局 60 秒最多一条 WARNING，其余降 DEBUG 并累计次数。
        """
        now = time.monotonic()
        last = getattr(self, "_dnssec_drop_warn_last", 0.0)
        merged = getattr(self, "_dnssec_drop_warn_merged", 0)
        if now - last >= 60.0:
            self._dnssec_drop_warn_last = now
            self._dnssec_drop_warn_merged = 0
            suffix = f"（最近 60 秒同类共 {merged + 1} 次）" if merged else ""
            logger.warning(
                "DNSSEC 统一验证丢弃 %s%s%s：%s（%s）",
                _safe_qname(qname),
                "（CNAME 中间跳）" if cname_hop else "",
                suffix, status, detail,
            )
        else:
            self._dnssec_drop_warn_merged = merged + 1
            logger.debug(
                "DNSSEC 统一验证丢弃（已合并计数）: %s%s status=%s detail=%s",
                _safe_qname(qname),
                "（CNAME 中间跳）" if cname_hop else "", status, detail,
            )

    # ---------- 主根 / 镜像根鉴别 ----------

    async def _probe_one_root(self, ip: str) -> bool:
        """判断某个根 IP 是否能提供**可验证的根区否定证明**

        镜像根可以转发 `. DNSKEY`（甚至带回真实 RRSIG），但它无法为随机
        名字现场生成根区签名的 NSEC；用随机不存在 TLD 的 NXDOMAIN 查询，
        要求 NSEC 的 RRSIG 能被根 DNSKEY 验签且区间覆盖该随机名，即可把
        “真根/可提供完整链的转发根”与“只回缓存/伪造数据的镜像根”分开。
        """
        import secrets
        v = self._dnssec
        anchor = v._root_anchor_rrset()
        if anchor is None:
            return False
        try:
            q = dns.message.make_query(".", dns.rdatatype.DNSKEY,
                                       want_dnssec=True)
            q.flags &= ~dns.flags.RD
            r = await asyncio.wait_for(
                dns.asyncquery.udp(q, ip, timeout=2.0), timeout=3.0)
            dk = next((rr for rr in r.answer
                       if rr.rdtype == dns.rdatatype.DNSKEY), None)
            sig = next((rr for rr in r.answer
                        if rr.rdtype == dns.rdatatype.RRSIG
                        and rr.covers == dns.rdatatype.DNSKEY), None)
            if dk is None or sig is None:
                return False
            dns.dnssec.validate(dk, sig, {dns.name.root: anchor})
            # 随机名查询可能被镜像“碰巧转发成功”，也可能瞬时抖动；
            # 连续两次都拿不到可验证的根 NSEC 才判镜像。
            return (await self._probe_root_nsec(ip, dk)
                    or await self._probe_root_nsec(ip, dk))
        except Exception:
            return False

    async def _probe_root_nsec(self, ip: str, dk) -> bool:
        """随机不存在 TLD：NXDOMAIN + 根签名 NSEC 且覆盖该名字"""
        import secrets
        try:
            label = "nx-" + secrets.token_hex(6) + "."
            qn = dns.name.from_text(label)
            q = dns.message.make_query(qn, dns.rdatatype.A,
                                       want_dnssec=True)
            q.flags &= ~dns.flags.RD
            r = await asyncio.wait_for(
                dns.asyncquery.udp(q, ip, timeout=2.0), timeout=3.0)
            if r.rcode() != dns.rcode.NXDOMAIN:
                return False
            nsec = next((rr for rr in r.authority
                         if rr.rdtype == dns.rdatatype.NSEC), None)
            nsig = next((rr for rr in r.authority
                         if rr.rdtype == dns.rdatatype.RRSIG
                         and rr.covers == dns.rdatatype.NSEC), None)
            if nsec is None or nsig is None:
                return False
            dns.dnssec.validate(nsec, nsig, {dns.name.root: dk})

            def _covers(rd) -> bool:
                try:
                    owner = nsec.name
                    nxt = rd.next
                    if owner == qn or qn == nxt:
                        return False
                    if owner < nxt:
                        return owner < qn < nxt
                    if nxt < owner:
                        return qn > owner or qn < nxt
                    return False
                except Exception:
                    return False

            return any(_covers(rd) for rd in nsec)
        except Exception:
            return False

    async def probe_root_authenticity(self) -> set:
        """探测全部根 IP，记录真正能提供根区证明的集合（缓存 600s）"""
        now = time.time()
        if (getattr(self, "_genuine_roots", None) is not None
                and now < getattr(self, "_root_probe_expire", 0.0)):
            return set(self._genuine_roots)
        roots = list(self.root_servers)
        results = await asyncio.gather(
            *[self._probe_one_root(ip) for ip in roots],
            return_exceptions=True)
        genuine = {ip for ip, ok in zip(roots, results) if ok is True}
        self._genuine_roots = genuine
        self._mirror_roots = set(roots) - genuine
        self._root_probe_expire = now + (600.0 if genuine else 60.0)
        if genuine:
            logger.info("根服务器鉴别: 真根 %d 台 %s；镜像 %d 台 %s",
                        len(genuine), ", ".join(sorted(genuine)),
                        len(self._mirror_roots),
                        ", ".join(sorted(self._mirror_roots)))
        else:
            logger.warning("根服务器鉴别: 没有可提供根区签名证明的根 "
                           "（全部为镜像/被代答）→ DNSSEC 链不可用")
        return genuine

    # ---------- bootstrap 递归上游能力探测 ----------

    async def _probe_bootstrap_one(self, ip: str) -> tuple:
        """探测单台 bootstrap：是否可达、能否给出 RRSIG、DS 否定证明"""
        async def _ask(qname: str, qtype: int):
            try:
                q = dns.message.make_query(qname, qtype, want_dnssec=True)
                q.flags |= dns.flags.RD | dns.flags.CD
                return await asyncio.wait_for(
                    dns.asyncquery.udp(q, ip, timeout=2.0), timeout=2.5)
            except Exception:
                return None

        signed, proof = await asyncio.gather(
            _ask("www.cloudflare.com.", dns.rdatatype.A),
            _ask("deepseek.com.", dns.rdatatype.DS),
        )
        alive = signed is not None or proof is not None
        has_sig = (signed is not None
                   and self._has_dnssec_material(signed, dns.rdatatype.A))
        has_proof = (proof is not None
                     and self._has_dnssec_material(proof, dns.rdatatype.DS))
        return ip, alive, has_sig, has_proof

    async def probe_bootstrap_capabilities(self) -> List[str]:
        """启动时筛选 bootstrap 递归上游，避免每次缺证明都重试全部服务器

        判定：
          * has_sig   ：对签名域名返回 RRSIG（说明不会剥离签名）；
          * has_proof ：对未签名区的 DS 查询返回 NSEC3/NSEC + RRSIG
                        （能提供“无 DS”的否定证明）。
        只有 has_proof 的服务器进入 `_bootstrap_dnssec_resolvers`，供
        `_bootstrap_dnssec_query()` 专用；可达服务器进入 `_bootstrap_alive`，
        供普通递归兜底优先使用。
        """
        resolvers = [str(s) for s in getattr(
            getattr(self, "config", None), "bootstrap_resolvers", []) or []]
        if not resolvers:
            self._bootstrap_dnssec_resolvers = []
            self._bootstrap_alive = []
            return []
        results = await asyncio.gather(
            *[self._probe_bootstrap_one(ip) for ip in resolvers],
            return_exceptions=True)
        proof: List[str] = []
        alive: List[str] = []
        detail: Dict[str, str] = {}
        for ip, res in zip(resolvers, results):
            if isinstance(res, tuple) and len(res) == 4:
                _, ok, sig, prf = res
                if prf:
                    proof.append(ip)
                    detail[ip] = "DNSSEC证明"
                elif sig:
                    detail[ip] = "仅签名"
                elif ok:
                    detail[ip] = "普通解析"
                else:
                    detail[ip] = "不可达"
                if ok:
                    alive.append(ip)
            else:
                detail[ip] = "探测异常"
        self._bootstrap_dnssec_resolvers = proof
        self._bootstrap_alive = alive
        self._bootstrap_probe_detail = detail
        self._bootstrap_probe_at = time.time()
        self._bootstrap_probe_expire = self._bootstrap_probe_at + 600.0
        if proof:
            logger.info("bootstrap 能力探测: 可提供 DNSSEC 证明 %d 台 %s；"
                        "普通可达 %d 台；不可用 %d 台",
                        len(proof), ", ".join(proof),
                        len(alive), len(resolvers) - len(alive))
        else:
            logger.warning(
                "bootstrap 能力探测: 没有上游能返回 NSEC3/RRSIG/DS 证明 "
                "（可用 %d/%d 台）；链查询将只依赖迭代真根，不再反复重试 "
                "无证明的 bootstrap", len(alive), len(resolvers))
        return proof

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

    def _server_score(self, ip: str) -> float:
        """权威服务器健康度得分（越小越优先）

        - 未知 IP：给一个中性值 0.20s（既不会把没见过的 IP 排到已测快 IP 前面，
          也不会让它们永远沉底——首跳仍需覆盖多台权威）；
        - 已知 IP：EWMA 往返耗时 + 失败惩罚（每连续失败 +0.05s，封顶 0.5s）。
        """
        st = self._server_health.get(str(ip))
        if st is None:
            return 0.20
        rtt, fails = st
        return rtt + 0.05 * min(10, fails)

    def _record_server_health(self, ip: str, rtt: Optional[float]) -> None:
        """记录一次权威查询结果（rtt=None 表示失败）"""
        try:
            key = str(ip)
            prev_rtt, prev_fails = self._server_health.get(key, (0.20, 0))
            if rtt is None:
                # 失败：把该 IP 的估算 RTT 抬高（下次排到后面），失败计数 +1
                self._server_health[key] = (min(2.0, prev_rtt * 1.5 + 0.05), prev_fails + 1)
            else:
                self._server_health[key] = (
                    0.7 * prev_rtt + 0.3 * max(0.001, float(rtt)),
                    max(0, prev_fails - 1),
                )
            if len(self._server_health) > 4096:
                # 防无界增长（多 IP/多进程切换场景）：直接清空重学，
                # 排序只影响「先试哪台」，清空不影响正确性。
                self._server_health.clear()
        except Exception:
            pass

    async def _query_servers(self, servers: List[str], qname: str, qtype: int,
                             rdclass: int = 1) -> Optional[dns.message.Message]:
        """单跳查询：**每跳固定并行 2 个协程**，谁先回用谁（先回者胜）

        策略（用户指定）：
          - 一跳内**同时启动 2 个协程**（同一跳的两个候选服务器 IP），
            不再"先发 1 台、等 250ms 无响应再补发"；
          - 任一台成功 → 立即取消另一个，返回先回的那个；
          - 任一台失败 → 立即补发下一台，把「在飞」数量补回 2；
          - 候选不足 2 台时按实际数量并行（1 台即单发）；
          - **失败过半即放弃**：已失败的服务器一旦超过本跳候选总数的一半
            （failed*2 > total），说明这一跳的权威大面积不可达，再试下去
            只会让客户端一直等——直接返回 None（上层按 SERVFAIL 处理），
            让客户端尽快重试，不再死磕剩下的服务器。

        为什么固定并行 2 台：同一跳的多个根/权威 IP 里常有一台跨境 RTT 很高
        或已下线，先回者胜把「踩到坏服务器」的代价从一整个超时（1.5-2s）压到
        另一台的正常 RTT（30-250ms）；代价是首包查询量翻倍（DNS 查询仅几十
        字节，可接受）。并行度由 iterative.hop_parallel 配置（默认 2，钳制
        1-4）；每个协程是纯 asyncio 收发，不占 task_pool 线程。
        """
        if not servers:
            return None
        # 地址族排序：**跨族交错**（优先族第 1 台、另一族第 1 台、优先族第 2 台…）
        # 而不是"优先族全部排前面"。原因：每跳默认只并行 2 台，若这 2 台都是
        # IPv6 而该权威的 v6 路径不通/丢包，就要等满一次超时才补发，长 CNAME 链
        # （s1.hdslb.com 之类）很容易因此整条超时；交错后同一批里必有一台 v4，
        # v6 不通时 v4 仍能在本跳内返回。
        # 地址族策略（**按域名 + 按跳**判定）：
        #   - 本机没有可用 IPv6（无全局地址或连通性探测失败）→ 只用 IPv4；
        #   - 本域名本次解析已被判定「权威没有可用 IPv6」（`_V6_DISABLED_CTX`）
        #     → 该域名后续跳都用 IPv4，**其它域名不受影响**；
        #   - 本跳候选里没有 v6 地址 → 本跳只用 IPv4；
        #   - 否则跨族交错（v6 第 1 台 + v4 第 1 台 …）。
        _v6_off_here = bool(_V6_DISABLED_CTX.get())
        _prefer_v6 = bool(getattr(self, "_has_ipv6", False)) and not _v6_off_here
        # 每个地址族内部按健康度排序（快的在前），再跨族交错——既保留
        # 「同批必有一台 v4」的抗 v6 不通能力，又避免每跳先踩到慢权威。
        _v6 = sorted((ip for ip in servers if ":" in str(ip)), key=self._server_score)
        _v4 = sorted((ip for ip in servers if ":" not in str(ip)), key=self._server_score)
        if not _prefer_v6:
            servers = _v4 or servers
        elif not _v6:
            # 本跳权威服务器**没有 IPv6 地址** → 本域名后续跳也禁用 IPv6
            # （per-domain：其它域名仍按各自权威集合跨族交错）
            _V6_DISABLED_CTX.set(True)
            logger.debug(
                "迭代查询: %s 本跳权威无 IPv6 地址 → 本域名后续只用 IPv4",
                _safe_qname(qname),
            )
        else:
            _ordered: List[str] = []
            for _i in range(max(len(_v6), len(_v4))):
                if _i < len(_v6):
                    _ordered.append(_v6[_i])
                if _i < len(_v4):
                    _ordered.append(_v4[_i])
            servers = _ordered
        total = len(servers)
        # 每跳并行协程数（默认 2：两路竞速、先回者胜）
        max_parallel = max(1, min(4, int(getattr(self, "hop_parallel", 2) or 2)))
        # 本跳总预算：候选多/权威全灭时，最多花「2 倍单跳超时」就放弃本跳，
        # 避免单跳把整个迭代预算（以及上层波次预算）吃掉。
        hop_deadline = time.monotonic() + max(1.0, min(4.0, self.timeout * 2))
        tasks: Dict[asyncio.Task, str] = {}
        started: Dict[asyncio.Task, float] = {}
        idx = 0
        failed = 0
        # 本跳 v6 失败计数：达到阈值后只在本跳跳过剩余 v6 候选
        # （按跳/按域名降级，不影响其它域名）
        _hop_v6_fail = 0

        def _launch() -> None:
            """把「在飞」协程补满 max_parallel（首次即同时发出 2 个）"""
            nonlocal idx
            while len(tasks) < max_parallel and idx < total:
                ip = servers[idx]
                idx += 1
                if _hop_v6_fail >= 2 and ":" in str(ip):
                    logger.debug(
                        "迭代查询: %s 本跳 IPv6 已判定不可用，跳过 %s",
                        _safe_qname(qname), ip,
                    )
                    continue
                task = asyncio.ensure_future(
                    self._query_one_async(ip, qname, qtype, rdclass)
                )
                tasks[task] = ip
                started[task] = time.monotonic()
                logger.debug("迭代查询: %s 并发发出 %s（在飞 %d/%d）",
                             _safe_qname(qname), ip, len(tasks), max_parallel)

        try:
            _launch()
            while tasks:
                remaining = hop_deadline - time.monotonic()
                if remaining <= 0.01:
                    logger.debug("迭代查询: %s 本跳预算耗尽，放弃本跳", _safe_qname(qname))
                    return None
                done, _ = await asyncio.wait(
                    tasks.keys(), timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    logger.debug("迭代查询: %s 本跳超时（%.1fs 预算用尽），放弃本跳",
                                 _safe_qname(qname),
                                 max(1.0, min(4.0, self.timeout * 2)))
                    return None
                for task in done:
                    ip = tasks.pop(task)
                    _elapsed = time.monotonic() - started.pop(task, time.monotonic())
                    try:
                        resp = task.result()
                    except Exception:
                        resp = None
                    if resp is not None and not self._response_is_plausible(
                            resp, qname, qtype):
                        # 答非所问（典型：DS 查询回 A、空 NOERROR、SERVFAIL）：
                        # 不能“先回者胜”，否则会覆盖另一台真权威的 referral，
                        # 让上游链验证永远拿不到否定证明。按失败处理并换下一台。
                        logger.debug(
                            "迭代查询: %s 的应答与查询语义不符（qname=%s "
                            "qtype=%s, rcode=%s, answer=%s），丢弃并换服务器: %s",
                            ip, _safe_qname(qname),
                            dns.rdatatype.to_text(qtype),
                            dns.rcode.to_text(resp.rcode()),
                            [(str(r.name), dns.rdatatype.to_text(r.rdtype))
                             for r in resp.answer][:3], ip)
                        resp = None
                    if resp is not None:
                        self._record_server_health(ip, _elapsed)
                        # 「是谁回的这个响应」——供 DNSSEC 证据诊断使用。
                        # 真实权威：AA=1、RA=0、RD 不回显；
                        # 递归代答/中间盒：AA=0、RA=1，甚至完全没有 OPT。
                        # 这些只是**诊断元数据**，不参与任何安全判定。
                        try:
                            resp._answer_ip = str(ip)
                            resp._answer_aa = bool(resp.flags & dns.flags.AA)
                            resp._answer_ra = bool(resp.flags & dns.flags.RA)
                            resp._answer_rd_echo = bool(
                                resp.flags & dns.flags.RD)
                            # 已知该地址族被中间设备代答 → 标到应答上：
                            # 这类应答不可能带 DNSSEC 证明（代答设备不发），
                            # 由 `_resolve_verified` 按可用性策略处理。
                            resp._answer_family = self._family_of(ip)
                            _fv = getattr(self, "_family_verdicts", None) or {}
                            _fam_bad = _fv.get(resp._answer_family) == "hijacked"
                            if getattr(self, "_ipv4_verify", "strict") == "corroborate":
                                # corroborate：整个"非真族"都要用真族交叉印证；
                                # 另外，即使族探测判为 genuine，**单条应答**若
                                # 形态不是真权威（无 AA / 无 OPT 回声 / 递归式
                                # RA+RD），也必须按未验证路径处理——实测部分
                                # 网络会只劫持特定域名（如 google.com.hk），
                                # 根 DNSKEY 探测仍显示 v6 genuine，但该域名的
                                # 权威应答其实是递归镜像（AA=0/RA=1），继续
                                # 当“可信数据”验签只会得到 bogus 并刷屏。
                                resp._hijacked_path = bool(
                                    _fam_bad or self._looks_fake(resp))
                            else:
                                # strict/none：只有「该族被判代答」**且**这条应答
                                # 形态也不像真权威（没回声 OPT/DO，或权威应答
                                # 却没有 AA）才标记。两个条件同时成立才标记，
                                # 是为了不误伤：有些网络只有**境外** IPv4/53 被
                                # 劫持、境内权威仍可正常访问，那种真权威应答会带
                                # AA+OPT+DO，不应被当成伪造而放弃验证。
                                resp._hijacked_path = (
                                    _fam_bad and self._looks_fake(resp))
                        except Exception:
                            pass
                        logger.debug(
                            "迭代查询: %s 响应 %s (rcode=%s, answer=%d, authority=%d)",
                            ip, _safe_qname(qname), dns.rcode.to_text(resp.rcode()),
                            len(resp.answer), len(resp.authority),
                        )
                        return resp
                    self._record_server_health(ip, None)
                    logger.debug("迭代查询: %s 查询 %s 超时/失败，补发下一台",
                                 ip, _safe_qname(qname))
                    # 本域名禁用 IPv6：同一跳里 2 台 v6 权威都失败 →
                    # 该域名后续所有跳都改用 IPv4（ContextVar 隔离，
                    # 其它域名照常跨族交错）
                    if ":" in str(ip):
                        _hop_v6_fail += 1
                        if _hop_v6_fail == 2:
                            _V6_DISABLED_CTX.set(True)
                            logger.debug(
                                "迭代查询: %s 本跳 v6 权威连续失败 → "
                                "本域名后续只用 IPv4",
                                _safe_qname(qname),
                            )
                    failed += 1
                    # 失败过半（>50% 的候选权威都不可用）→ 放弃本跳，
                    # 让上层尽快返回 SERVFAIL，而不是把全部服务器都试一遍
                    if failed * 2 > total:
                        logger.debug(
                            "迭代查询: %s 已有 %d/%d 台服务器失败（超过半数），放弃本跳",
                            _safe_qname(qname), failed, total,
                        )
                        return None
                # 有协程结束（成功已返回/失败已计数）→ 立即补满并行槽位
                _launch()
            return None
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                # 清理限时：取消时若子查询还在收尾，无限等会把本跳拖长
                #（单查询预算被拉长到 9s+ 的原因之一）。0.5s 足够关 socket。
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=0.5,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

    @staticmethod
    def _response_matches_query(resp, q) -> bool:
        """响应的 question 段是否与查询一致（RFC 5452 §9.1 纵深防御）

        - 查询或响应缺少 question 时不因此拒绝（少数权威/精简实现会省略
          question 段，一律拒绝会造成解析失败）；
        - 名字比较大小写不敏感（RFC 4343）。
        """
        try:
            if not getattr(q, "question", None):
                return True
            if not getattr(resp, "question", None):
                return True
            qq = q.question[0]
            rq = resp.question[0]
            return (str(qq.name).lower() == str(rq.name).lower()
                    and qq.rdtype == rq.rdtype
                    and qq.rdclass == rq.rdclass)
        except Exception:
            return True

    @staticmethod
    def _response_is_plausible(resp, qname: str, qtype: int) -> bool:
        """应答是否**语义上**回答了本次查询（防止采纳伪造/错配应答）

        仅校验 question 段（`_response_matches_query`）不够：实测部分根/TLD
        IP 被中间设备接管后，会对 `google.com.hk DS` 返回一条
        `google.com.hk A`（AA=1、question 也回显 DS），question 校验完全
        通过，但它是**答非所问**。`_iterate` 随后既找不到 DS、也找不到
        referral，只能返回 None → 父区否定证明永远取不到 → 合法未签名域名
        被误判 bogus。

        判定（任一成立即视为有效）：
          * answer 含 owner==qname 的 qtype 记录（正向答案）；
          * answer 含 owner==qname 的 CNAME（CNAME 链的一跳）；
          * authority 含 SOA 且其 owner 是 qname 祖先（NODATA/NXDOMAIN）；
          * authority 含 NS 且其 owner 是 qname 祖先（referral）。
        其它形态（如 DS 查询回 A、空 NOERROR、SERVFAIL）一律丢弃并换服务器。
        """
        try:
            rcode = resp.rcode()
            if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return False
            try:
                qn = dns.name.from_text(qname)
            except Exception:
                return False
            for rrset in resp.answer:
                try:
                    if rrset.name != qn:
                        continue
                    # ANY（255）本来就要返回 qname 的任意类型记录；
                    # 只按 qtype==255 匹配会把合法 ANY 应答全部丢掉。
                    if (qtype == dns.rdatatype.ANY
                            or rrset.rdtype in (qtype, dns.rdatatype.CNAME)):
                        return True
                except Exception:
                    continue
            for rrset in resp.authority:
                try:
                    if rrset.rdtype not in (dns.rdatatype.SOA,
                                            dns.rdatatype.NS):
                        continue
                    if qn == rrset.name or qn.is_subdomain(rrset.name):
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    # ---------- DNS Cookie（RFC 7873） ----------

    def _client_cookie(self, ip: str) -> bytes:
        """8 字节 client cookie（RFC 7873 §5.1：本地 secret 与服务端 IP 派生）"""
        import hashlib
        return hashlib.sha256(self._cookie_secret + str(ip).encode()).digest()[:8]

    def _apply_cookie(self, q, ip: str) -> bool:
        """给查询加 COOKIE EDNS option（RFC 7873）。返回是否真的加上了。"""
        key = str(ip)
        if key in self._cookie_disabled:
            return False
        try:
            opt = dns.edns.CookieOption(
                self._client_cookie(key), self._server_cookies.get(key, b""))
            q.use_edns(0, q.ednsflags, payload=1232, options=[opt])
            return True
        except Exception:
            return False

    def _learn_cookie(self, ip: str, resp) -> None:
        """从响应里学习 server cookie（8-32 字节）"""
        try:
            for opt in (getattr(resp, "options", None) or []):
                if getattr(opt, "otype", None) == dns.edns.COOKIE:
                    srv = bytes(getattr(opt, "server", b"") or b"")
                    if len(srv) >= 8:
                        self._server_cookies[str(ip)] = srv[:32]
                    return
        except Exception:
            pass

    def _cookie_unsupported(self, ip: str, rcode: int) -> None:
        """权威不支持 COOKIE（FORMERR/BADVERS/NOTIMP）：禁用该 IP 的 cookie"""
        key = str(ip)
        if key not in self._cookie_disabled:
            logger.debug("权威 %s 不支持 DNS COOKIE（%s），已禁用该 IP 的 cookie",
                         key, dns.rcode.to_text(rcode))
        self._cookie_disabled.add(key)
        self._server_cookies.pop(key, None)

    async def _query_one_async(self, ip: str, qname: str, qtype: int, rdclass: int):
        """单台查询入口：先过并发闸门，再走原生 asyncio 收发

        `_inflight_sem` 限制「同时在飞的单台查询」数量：超出部分排队等待，
        避免浏览器/预刷新把上游并发推到几百、触发权威 RRL 限速后整体失败。
        """
        async with self._inflight_sem:
            return await self._query_one_async_inner(ip, qname, qtype, rdclass)

    async def _query_one_async_inner(self, ip: str, qname: str, qtype: int, rdclass: int):
        """单台查询：**原生 asyncio**（纯协程，不再借线程）

        旧实现把 dns.query.udp（同步阻塞 API）丢进 run_in_executor：
        等待权威应答期间协程确实能让出 CPU 去调度其它域名的查询，
        但**那个工作线程被独占**直到应答/超时，所以并发域名数实际被
        「共享池线程数 = cpu_core_limit×2」卡住（实测 30 个域名瞬时并发时
        排队把 p95 拖到 6 秒）。

        现在用 asyncio 数据报端点直接收发：等待时既不占线程也不占 CPU，
        迭代并发只受 max_concurrent / 句柄数约束；取消任务时会真正关闭
        socket（不再出现"取消后线程还在阻塞 1.5 秒"）。
        """
        q = dns.message.make_query(qname, qtype, rdclass=rdclass, want_dnssec=True)
        q.flags &= ~dns.flags.RD
        # DNS Cookie（RFC 7873）：首次带 client cookie，权威回 server cookie 后
        # 后续查询带完整 cookie，降低 off-path 伪造响应被接受的概率。
        _cookie_used = self._apply_cookie(q, ip)
        resp = await self._udp_exchange(ip, q)
        # 权威不支持 COOKIE → FORMERR/BADVERS/NOTIMP：禁用该 IP 的 cookie，
        # 并**在同一次查询内无 cookie 重发一次**（不把兼容性问题变成解析失败）。
        if (resp is not None and _cookie_used
                and resp.rcode() in (dns.rcode.FORMERR, dns.rcode.BADVERS,
                                     dns.rcode.NOTIMP)):
            self._cookie_unsupported(ip, resp.rcode())
            q = dns.message.make_query(qname, qtype, rdclass=rdclass,
                                       want_dnssec=True)
            q.flags &= ~dns.flags.RD
            resp = await self._udp_exchange(ip, q)
        if resp is None:
            return None
        if resp.flags & dns.flags.TC:
            # 截断 → TCP 重查（RFC 1035 §4.2.2）；q 仍带 cookie（TCP 同样支持）
            return await self._query_one_tcp(ip, q)
        return resp

    async def _udp_exchange(self, ip: str, q):
        """发一次 UDP 查询并校验响应（ID + 问题段），顺手学习 server cookie

        失败/不匹配返回 None。socket 生命周期严格限定在本函数内——取消/异常
        路径都不会留下未关闭的 transport。
        """
        wire = q.to_wire()
        loop = asyncio.get_running_loop()
        transport = None
        protocol = None
        try:
            # remote_addr 已由内核过滤来源地址；后面仍校验 ID 与问题段
            transport, protocol = await loop.create_datagram_endpoint(
                _UdpQueryProtocol,
                remote_addr=(str(ip), 53),
            )
            transport.sendto(wire)
            data = await asyncio.wait_for(protocol.future, timeout=self.timeout)
            resp = dns.message.from_wire(data)
            if resp.id != q.id:
                logger.debug("迭代查询: %s 响应 ID 不匹配，丢弃", ip)
                return None
            # 纵深防御（RFC 5452 §9.1）：问题段必须与查询一致。内核已按
            # remote_addr 过滤来源 IP/端口，但仍要防"问题段不同的响应"被
            # 当成答案（例如把 A 的应答套用到 AAAA 查询上）。
            if not self._response_matches_query(resp, q):
                logger.debug("迭代查询: %s 响应问题段不匹配，丢弃", ip)
                return None
            self._learn_cookie(ip, resp)
            return resp
        except (asyncio.TimeoutError, OSError, dns.exception.DNSException):
            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        finally:
            if protocol is not None:
                fut = protocol.future
                if not fut.done():
                    # 取消/异常路径：避免 "Future exception was never retrieved"
                    fut.cancel()
                elif not fut.cancelled():
                    # 已完成但仍带异常（如 transport 关闭时的 ConnectionError）：
                    # 必须消费掉，否则 asyncio 会打 "Future exception was never
                    # retrieved" 的 ERROR 刷屏。
                    try:
                        fut.exception()
                    except Exception:
                        pass
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    async def _query_one_tcp(self, ip: str, q: "dns.message.Message"):
        """TCP 重查（纯协程，2 字节长度前缀）——用于 UDP 截断（TC=1）的场景"""
        wire = q.to_wire()
        writer = None
        try:
            reader, writer = await asyncio.open_connection(str(ip), 53)
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            length = struct.unpack(
                "!H", await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
            )[0]
            data = await asyncio.wait_for(
                reader.readexactly(length), timeout=self.timeout
            )
            resp = dns.message.from_wire(data)
            if resp.id != q.id or not self._response_matches_query(resp, q):
                return None
            # 必须显式返回：本函数原先在这里直接落到 finally 之后，函数末尾
            # 没有 return，于是 **TCP 成功读到的响应也被当成失败返回 None**，
            # 导致所有 UDP 截断（TC=1）的查询全部失败——典型受害者是
            # DNSKEY（.org 的响应 1319 字节 > EDNS 1232）→ DNSSEC 信任链
            # 在 TLD 层断裂 → 签名域名全部 bogus。finally 仍会关闭连接。
            return resp
        except (asyncio.TimeoutError, OSError, dns.exception.DNSException):
            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    # ---------- 下一跳服务器提取 ----------

    async def _extract_next_servers(self, response, depth: int = 0) -> List[str]:
        """从 authority NS + additional glue 提取下一级服务器 IP。

        无 glue 的 NS 名称交给 `_resolve_ns_ip` 迭代解析。

        **必须传入当前迭代深度**：早期版本在这里调用 ``_resolve_ns_ip(ns_name)``
        用默认 depth=0，于是"每一层 referral 的无 glue NS"都能重新递归满 16 层；
        一次 referral 常带 26 个 NS，逐层展开就是指数级协程/Task 爆炸
        （实测协程 4.4 万、RSS 1.5GB，来源 Top 全是 _lookup）。
        """
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
        # 第一遍：有 glue / 有缓存的直接收集，缺 glue 的 NS 名单独列出
        resolved: Dict[str, List[str]] = {}
        missing: List[str] = []
        for ns in ns_names:
            lower = ns.lower()
            ips = glue.get(lower)
            if not ips:
                # M3 修复：读取带 TTL 的 NS IP 缓存（值 = (ips, expire_at)）
                _cached = self._ns_ip_cache.get(lower)
                if _cached:
                    _cached_ips, _expire_at = _cached
                    if time.time() < _expire_at:
                        ips = _cached_ips
            if ips:
                resolved[lower] = list(ips)
            elif lower not in resolved and lower not in missing:
                missing.append(lower)

        # 第二遍：缺 glue 的 NS 并行解析（串行时每个 NS 都要独立跑一轮迭代，
        # 实测 ns-open1/2/3.qq.com 各 ~350ms、合计 1s+；限并发避免查询风暴）
        if missing:
            _sem = asyncio.Semaphore(4)

            async def _lookup(ns_name: str) -> tuple:
                async with _sem:
                    try:
                        # 关键：带上当前深度（否则每层都能重新递归满 max_depth）
                        return ns_name, await self._resolve_ns_ip(ns_name, depth + 1)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        return ns_name, []

            for ns_name, ips in await asyncio.gather(*[_lookup(n) for n in missing]):
                resolved[ns_name] = list(ips or [])

        # 第三遍：按 ns_names 原始顺序组装（保持结果确定性）
        for ns in ns_names:
            servers.extend(resolved.get(ns.lower(), []))
        # 去重保序
        seen = set()
        uniq = []
        for ip in servers:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        return uniq

    async def _resolve_ns_ip(self, ns_name: str, depth: int = 0) -> List[str]:
        """对无 glue 的 NS 名称迭代解析其 A/AAAA（子问题，从根开始）。

        递归上限比 max_depth 小得多（`_NS_RESOLVE_MAX_DEPTH`）：解析"权威的
        NS 名"通常 1-2 跳就够，没必要跟着主链跑满 16 层——否则一次 referral
        的 26 个 NS 会逐层展开成指数级协程。
        """
        if depth >= min(self.max_depth, _NS_RESOLVE_MAX_DEPTH):
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

    @staticmethod
    def _restore_question(response, original_qname: str, original_qtype: int) -> None:
        """把响应的 question 段复原为客户端的**原始查询名与类型**

        QNAME 最小化会把发往根/TLD 的查询改成「下一级名字 + NS 类型」（例如
        查 nx-plain.invalidtld A 时向根发 invalidtld. NS），权威返回的
        NXDOMAIN/NODATA 里 question 就是那个中间名 + NS。

        客户端（dnspython 的 dns.query.*、dig、系统解析器）会同时校验名字与
        QTYPE，任一不符就丢弃响应（BadResponse: response does not respond to
        the question asked）。所以这里**两者都要复原**——只改名字不改类型同样
        会被丢弃（实测 question 变成 `nx-plain.invalidtld. IN NS` 仍被拒）。
        """
        try:
            if not response.question:
                return
            cur_name = str(response.question[0].name).rstrip(".").lower()
            cur_type = response.question[0].rdtype
            if cur_name == original_qname.rstrip(".").lower() and cur_type == original_qtype:
                return
            response.question = [dns.rrset.RRset(
                dns.name.from_text(original_qname),
                response.question[0].rdclass,
                original_qtype,
            )]
        except Exception:
            pass

    @staticmethod
    def _next_closer_name(qname: dns.name.Name, zone: dns.name.Name) -> dns.name.Name:
        """qname 相对 zone 的「下一级名字」（RFC 9156 §2.1 next closer name）

        例：qname=www.example.com.
              zone=.             → com.
              zone=com.          → example.com.
              zone=example.com.  → www.example.com.（= qname，说明已到最终名）
        """
        try:
            q_labels = qname.labels            # 末尾是 b'' 空标签
            z_labels = zone.labels
            n_zone = max(0, len(z_labels) - 1)  # 根的名字标签数为 0
            n_q = max(0, len(q_labels) - 1)
            if n_q <= n_zone:
                return qname
            # 取 qname 末尾 (n_zone + 1) 个有效标签 + 末尾空标签 = 共 n_zone+2 个
            # （zone 为空根时取 com.；zone=com. 时取 example.com.）
            return dns.name.Name(q_labels[-(n_zone + 2):])
        except Exception:
            return qname

    @staticmethod
    def _referral_zone(response) -> Optional[dns.name.Name]:
        """referral 的区名（authority 段里最长的 NS owner）"""
        best: Optional[dns.name.Name] = None
        try:
            for rrset in response.authority:
                if rrset.rdtype != dns.rdatatype.NS:
                    continue
                if best is None or len(rrset.name.labels) > len(best.labels):
                    best = rrset.name
        except Exception:
            return None
        return best

    async def _iterate(self, qname: str, qtype: int, depth: int = 0,
                       rdclass: int = 1) -> Optional[dns.message.Message]:
        """迭代解析主循环：根→TLD→权威，返回最终响应。"""
        if depth >= self.max_depth:
            self._stats["depth_exceeded"] += 1
            return None
        original_qname = qname  # CNAME 跟随会改变 qname，需在返回时复原 question
        servers: List[str] = list(self.root_servers)
        # 根起跳只使用“能提供根区签名证明”的 IP（真根/可完整转发的根）；
        # 镜像根虽然能回 DNSKEY 形态，但随机 NSEC 验不过，拿它做迭代起点
        # 会把伪造 A/referral 带进整条链。没有可用真根时才退回全量。
        if _CHAIN_ONLY_CTX.get():
            _genuine = getattr(self, "_genuine_roots", None)
            if _genuine:
                servers = [ip for ip in servers if ip in _genuine] or list(_genuine)
        else:
            _genuine = getattr(self, "_genuine_roots", None)
            if _genuine:
                _sel = [ip for ip in servers if ip in _genuine]
                if _sel:
                    servers = _sel
        # 优先从「最近已知区的权威」起跳：同一 TLD / CNAME 目标可省掉
        # root→TLD 两跳（实测每次约 100-500ms）。DS 查询必须从父区起跳
        # （DS 由父区权威持有），因此 _closest_zone_servers 对 DS 强制上移一级。
        started_from_cache = False
        _cached_start = self._closest_zone_servers(qname, qtype)
        if _cached_start is not None:
            servers, started_from_cache = _cached_start
        cname_targets: List[str] = []
        cname_chain: List[bytes] = []  # 中间跳 CNAME 响应 wire（供上层验签，防 target 篡改）
        # 本次迭代链里是否有**任何一跳**用了「已被判定为中间设备代答」的地址族。
        # 只要有一跳是代答族的应答，整条链的数据都不可信（代答设备不下发
        # DNSSEC），上层据此按 require_rrsig 决定放行/丢弃，而不是误判成
        # "签名被剥离"后把本可解析的域名打成 SERVFAIL。
        _chain_hijacked = [False]

        def _ret(msg):
            try:
                if msg is not None and (_chain_hijacked[0]
                                        or getattr(msg, "_hijacked_path", False)):
                    msg._hijacked_path = True
            except Exception:
                pass
            return msg
        # QNAME 最小化（RFC 9156）：向当前区只问「下一级名字」，中间级用 NS 查询，
        # 到最终名才用原 qtype——根/TLD 看不到完整查询名（隐私），也少发无用查询。
        # ★ DS 查询**不做最小化**：DS 记录在父区，最小化会把「arpa. NS」问成
        #   权威答案（部分递归型根/镜像会这样回），迭代器拿不到 referral，
        #   最终 DS 查询返回 None，导致 ipv4only.arpa 这类合法未签名委托被
        #   判成 bogus。DS 必须直接把完整名字发给父区权威。
        # 缓存起跳时当前区未知，跳过最小化；一旦发现区名没推进，也自动回退全名，
        # 避免把"实现不规范的权威"变成解析失败。
        _minimize = (bool(getattr(self, "qname_minimization", True))
                     and not started_from_cache
                     and qtype != dns.rdatatype.DS)
        current_zone = dns.name.root
        for _hop in range(self.max_depth - depth):
            # A2（已降级 debug）：每跳过程日志——需查看时设 DEBUG 级
            logger.debug("迭代解析 [跳%d/%d]: %s %s 候选服务器 %d 台%s",
                         _hop + 1, self.max_depth, _safe_qname(qname),
                         dns.rdatatype.to_text(qtype), len(servers),
                         "（缓存区权威）" if started_from_cache else "")
            # 本跳实际查询的名字/类型：最小化时向当前区只问「下一级名字」，
            # 且中间级用 NS 查询（到最终名才用原 qtype）。
            _q_name, _q_type = qname, qtype
            if _minimize:
                try:
                    _nc = self._next_closer_name(dns.name.from_text(qname), current_zone)
                    if str(_nc).rstrip(".").lower() != qname.rstrip(".").lower():
                        _q_name = str(_nc).rstrip(".")
                        _q_type = dns.rdatatype.NS
                except Exception:
                    _minimize = False
                    _q_name, _q_type = qname, qtype
            # 族优先（见 `_FAMILY_ONLY_CTX`）：若已判定某一族被中间设备代答、
            # 另一族才是真权威，本跳**先只用真族**——因为代答设备是本地设备、
            # 应答在微秒级，两族混发时它永远先到，真实权威的 DNSSEC 记录会被丢。
            # 真族在本跳没有可用地址（或全部失败）时立刻回退全族：
            # 宁可这一次拿不到 DNSSEC，也不能把域名解析变成失败。
            # 本机没有全局 IPv6：本跳直接剔除 v6 地址，避免每跳先等 v6 超时。
            # （族偏好 _pref 为空时也必须剔除，否则 v4-only 主机仍会发 v6。）
            if not getattr(self, "_has_ipv6", False):
                _v4only = [ip for ip in servers if self._family_of(ip) == "4"]
                if _v4only:
                    servers = _v4only
            _pref = (_FAMILY_ONLY_CTX.get("")
                     or getattr(self, "_preferred_family", "") or "")
            _pref_servers: List[str] = []
            if _pref:
                _cand = [ip for ip in servers if self._family_of(ip) == _pref]
                if _cand:
                    # 只要是“优先族”的地址就用它——即使本跳全部服务器都是
                    # 该族也必须用。旧条件 `0 < len(_cand) < len(servers)`
                    # 在全为 v6 的权威上会得到空列表，链验证随后以为
                    # “本跳没有真族权威”直接失败，导致 arpa. 等 v6-only
                    # 链的 DS/DNSKEY 永远取不到，合法未签名域名被判 bogus。
                    _pref_servers = _cand
            response = None
            _chain_only = bool(_CHAIN_ONLY_CTX.get())
            if _pref_servers:
                response = await self._query_servers(
                    _pref_servers, _q_name, _q_type, rdclass)
                if response is None:
                    if _chain_only:
                        # 链验证强制真族：真族本跳无应答时**不得**回退镜像族，
                        # 否则会拿被代答族的数据去验签（等于没验证）。
                        logger.debug(
                            "DNSSEC 链验证: %s 真族 IPv%s 本跳无应答 → "
                            "不回退镜像族", _safe_qname(qname), _pref)
                        return None
                    logger.debug(
                        "迭代解析: %s 优先族 IPv%s 本跳全部失败，回退全族",
                        _safe_qname(qname), _pref)
            elif _chain_only and _pref:
                logger.debug(
                    "DNSSEC 链验证: %s 本跳无真族 IPv%s 权威 → 不使用镜像族",
                    _safe_qname(qname), _pref)
                return None
            if response is None:
                response = await self._query_servers(
                    servers, _q_name, _q_type, rdclass)
            if response is None and started_from_cache:
                if _chain_only:
                    # 链验证不走“缓存失效→回退根”的可用性降级：
                    # 回退后仍可能落到镜像族，必须让验证失败而不是伪造成功。
                    return None
                # 缓存里的权威已失效/换 IP：回退到根重新走完整链路，功能不降级
                logger.debug("缓存区权威不可达，回退根服务器重试: %s", _safe_qname(qname))
                self._zone_ns_cache.clear()
                servers = list(self.root_servers)
                started_from_cache = False
                response = await self._query_servers(servers, qname, qtype, rdclass)
            if response is None:
                return None
            try:
                if getattr(response, "_hijacked_path", False):
                    _chain_hijacked[0] = True
            except Exception:
                pass
            # 1. answer 段含**目标 owner** 的目标类型 → 完成（返回前复原 question）
            #
            # 不能只看 rdtype：QNAME 最小化/权威异常时，answer 里可能出现
            # 祖先区的 NS（实测查询 sso.sina.com.cn NS 时，权威/最小化路径
            # 返回了 com.cn. NS）。旧实现只看 rdtype，直接把它当最终答案返回，
            # 上层 _resolve_verified 再按 owner 校验判成“重放攻击”丢弃
            # （日志每 60 秒两条 WARNING，NS 查询永远失败）。
            # 只有 owner == 当前 qname（CNAME 跟随后的目标）才算完成；
            # 祖先 NS 属于 referral 信息，应继续走下钻/NODATA 分支。
            _answer_owner = dns.name.from_text(qname)
            if any(rrset.rdtype == qtype and rrset.name == _answer_owner
                   for rrset in response.answer):
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
                return _ret(response)
            # 2. NXDOMAIN → 返回（负应答）
            has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)
            has_ns_ref = any(rrset.rdtype == dns.rdatatype.NS for rrset in response.authority)
            # 最小化的**中间级**（_q_name != qname，用 NS 查询）：
            #   有 referral → 继续下钻（第 4 步）；
            #   负应答（NXDOMAIN / NODATA）→ 该中间级不存在 → 直接作为最终答案
            #   返回（RFC 8020 剪枝：连该 TLD/区都不存在，更深的名字必然不存在）。
            #   question 改回原始名，客户端看到的仍是它问的名字。
            if _minimize and _q_type == dns.rdatatype.NS and _q_name != qname:
                if response.rcode() == dns.rcode.NXDOMAIN or (has_soa and not has_ns_ref):
                    try:
                        response._cname_targets = list(cname_targets)
                        response._cname_chain = list(cname_chain)
                    except Exception:
                        pass
                    # 名字与 QTYPE 都要复原成客户端原始查询（中间名+NS 会被
                    # 客户端判为 question 不匹配而丢弃）
                    self._restore_question(response, original_qname, qtype)
                    return _ret(response)
            # 2. NXDOMAIN → 返回（负应答）
            #
            # ⚠ 必须复原 question：QNAME 最小化下，向权威发送的是 qname 的
            #   「下一级名字」（如把 nx-plain.invalidtld 的最小化查询发成
            #   invalidtld. NS），权威回的 NXDOMAIN 里 question 就是那个中间名。
            #   若原样返回，客户端会因 question 与查询不符而丢弃响应
            #   （dnspython 报 BadResponse: response does not respond to the
            #   question asked；dig/nslookup 也会判 mismatch）。
            #   之前只有「中间级剪枝」分支（_q_name != qname）复原了，最终级
            #   NXDOMAIN / NODATA 两条 return 漏掉，是本次端到端测试发现的。
            if response.rcode() == dns.rcode.NXDOMAIN:
                self._restore_question(response, original_qname, qtype)
                return _ret(response)
            # 2b. 权威负应答（NODATA）：authority 段有 SOA（zone 权威的否定应答），
            #     无 NS referral → 直接返回，避免 _extract_next_servers 死循环
            #     注意：answer 可能含 CNAME + authority NSEC（RFC 4035 §5.2 同响应
            #     CNAME→NODATA）——早退前需填充 _cname_targets 供上层验证
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
                self._restore_question(response, original_qname, qtype)
                return _ret(response)
            # 3. CNAME 链（最多跟随 8 跳）——owner 必须等于当前 qname（防注入）
            cname = self._extract_cname(response, expected_owner=qname)
            if cname is not None:
                if qtype == dns.rdatatype.DS:
                    # DS 查询**不跟随 CNAME**（RFC 4035 §2.4：DS 与 CNAME 不能
                    # 共存；CNAME owner 处没有 DS）。若继续跟到目标区，会把
                    # 目标区的 NSEC3/SOA 当成该名字的否定证明，父区 key 与
                    # owner 错配，dnssec.py 的链状态只能判 unknown。
                    # 典型：cdn.jsdelivr.net（CNAME 到 fastly/cloudflare）被
                    # 误判 unknown → CNAME 链中间跳被丢弃。
                    # 直接返回 CNAME 响应：上层看到“无 DS、无匹配否定证明”，
                    # 会按“普通名”继续升到 jsdelivr.net 判断（未签名 → 放行）。
                    self._restore_question(response, original_qname, qtype)
                    return _ret(response)
                cname_targets.append(cname)
                try:
                    cname_chain.append(response.to_wire())  # 保存供上层验签
                except Exception:
                    pass
                if len(cname_targets) > 8:
                    return None
                qname = str(cname)
                # CNAME 目标可能在别的 TLD：重新按目标名挑最近的已知区（可能没有）
                started_from_cache = False
                # 目标名是"新查询"：当前区回到根；若命中缓存起跳则关闭最小化
                current_zone = dns.name.root
                _cached = self._closest_zone_servers(qname, qtype)
                if _cached is not None:
                    servers, started_from_cache = _cached
                    _minimize = False
                else:
                    servers = list(self.root_servers)
                    _minimize = bool(getattr(self, "qname_minimization", True))
                continue
            # 4. referral：authority NS → 下一级
            next_servers = await self._extract_next_servers(response, depth + _hop)
            if not next_servers:
                return None
            # 最小化：记录本跳 referral 的区名，下一跳按「下一级名字」继续下钻。
            # 若区名没有推进（权威实现不规范，仍返回同一级的 referral），
            # 立即回退全名查询，避免在同一条链上死循环。
            _zone = self._referral_zone(response)
            if _zone is not None:
                # RFC 5452 §9.2 / bailiwick：referral 的 NS owner 必须是
                # 当前 qname 的祖先（或 qname 自身）。否则一条伪造 referral
                # 可以把解析器引到无关区（缓存投毒/解析劫持）。旧实现只对
                # “写入缓存”做了校验，但仍然会直接使用这些服务器。
                try:
                    if not dns.name.from_text(qname).is_subdomain(_zone):
                        logger.debug(
                            "拒绝越界 referral: zone=%s qname=%s",
                            _safe_qname(str(_zone)), _safe_qname(qname))
                        return None
                except Exception:
                    return None
                try:
                    if _minimize and len(_zone.labels) <= len(current_zone.labels):
                        logger.debug("QNAME 最小化: 区名未推进（%s），回退全名查询",
                                     _safe_qname(str(_zone)))
                        _minimize = False
                    else:
                        current_zone = _zone
                except Exception:
                    _minimize = False
            # 缓存「子区 → 权威 IP」：同 TLD 的后续查询 / DS 查询可少走 1-2 跳。
            # 只缓存「从根起跳」链路上的 referral——缓存起跳之后的更深 referral
            # 未经完整链路，可信度更低，不写缓存。
            if not started_from_cache:
                self._cache_zone_servers(response, next_servers, qname)
            servers = next_servers
            started_from_cache = False
        return None

    def _closest_zone_servers(
        self, qname: str, qtype: int,
    ) -> Optional[tuple]:
        """找 qname 最近已知区的权威服务器（用于跳过根/TLD 两跳）

        安全约束：
          - DS 查询必须由**父区**权威回答，因此从 qname.parent() 起找，
            绝不能命中 qname 自身的区（否则会拿到 NODATA 而被误判 bogus）；
          - 只使用 referral 缓存（带 TTL），过期即丢弃；命中后若该权威
            不可达，_iterate 会清空缓存并回退到根，功能不降级。
        """
        try:
            name = dns.name.from_text(qname)
        except Exception:
            return None
        if qtype == dns.rdatatype.DS:
            if name == dns.name.root:
                return None
            # RFC 4035 §3.1.4.1：DS RRset 由**直接父区**的权威回答。
            # 因此只允许命中 qname.parent() 自身缓存的权威，绝不能向上
            # 找到祖父区——例如 update.googleapis.com 的 DS 不能由 .com
            # 的权威回答：.com 对孙域只会返回 referral，而某些上游/镜像会把
            # referral 精简成「SOA-only NODATA」，dnssec.py 会把它
            # 当成“无法证明” → 严格模式丢弃合法应答。
            parent = name.parent()
            entry = self._zone_ns_cache.get(str(parent).lower())
            if entry is not None:
                servers, expire_at = entry
                if time.time() < expire_at and servers:
                    return list(servers), True
                self._zone_ns_cache.pop(str(parent).lower(), None)
            # 父区权威没有缓存 → 返回 None，让 _iterate 从根开始按
            # 根→TLD→父区 的完整链路走（QNAME 最小化会自然收敛到父区）。
            return None
        now = time.time()
        while name != dns.name.root:
            entry = self._zone_ns_cache.get(str(name).lower())
            if entry is not None:
                servers, expire_at = entry
                if now < expire_at and servers:
                    return list(servers), True
                self._zone_ns_cache.pop(str(name).lower(), None)
            name = name.parent()
        return None

    def _cache_zone_servers(self, response, servers: List[str], qname: str):
        """把 referral 的「子区 → 权威 IP」写入缓存（TTL 取 NS rrset 的 TTL）

        安全约束（防缓存投毒 —— 一条恶意 referral 不能污染无关区的缓存）：
          1) 只接受 qname 的**祖先区**：否则查询 a.com 时伪造 bank.com 的
             NS 就能把 bank.com 后续解析全部导向攻击者 IP（持续到 TTL 到期）；
          2) TTL 上限 600s（缩短投毒窗口），下限 60s（避免频繁回根）；
          3) 只缓存合法 IP（glue 可能含垃圾/畸形数据）。
        """
        try:
            zone_name = None
            best_ttl = 300.0
            for rrset in response.authority:
                if rrset.rdtype != dns.rdatatype.NS:
                    continue
                # referral 里可能有多个 NS owner，取最长的作为被委派的子区名
                if zone_name is None or len(rrset.name) > len(zone_name):
                    zone_name = rrset.name
                    best_ttl = float(getattr(rrset, "ttl", 300) or 300)
            if zone_name is None or zone_name == dns.name.root:
                return
            try:
                if not dns.name.from_text(qname).is_subdomain(zone_name):
                    logger.debug(
                        "拒绝缓存非 qname 祖先区的 referral: %s（查询 %s）",
                        _safe_qname(str(zone_name)), _safe_qname(qname),
                    )
                    return
            except Exception:
                return
            clean_servers: List[str] = []
            for ip in servers:
                try:
                    ipaddress.ip_address(str(ip).split("%")[0])
                except ValueError:
                    continue
                clean_servers.append(str(ip))
            if not clean_servers:
                return
            ttl = max(60.0, min(best_ttl, 600.0))
            if len(self._zone_ns_cache) > 512:
                self._zone_ns_cache.clear()
            self._zone_ns_cache[str(zone_name).lower()] = (
                clean_servers, time.time() + ttl,
            )
        except Exception:
            pass

    async def _iterate_ds_cached(self, zone_name) -> Optional[dns.message.Message]:
        """DS 查询（带 zone 级缓存 + single-flight）

        供 DNSSECValidator 的查询回调使用：同一 zone 的并发 DS 查询合并为
        一次；TTL 取响应里最小的 rrset TTL（60s-1h），失败短负缓存 5s，
        避免对同一失败目标反复重试。
        """
        key = str(zone_name).lower()
        entry = self._ds_cache.get(key)
        if entry is not None:
            resp, expire_at = entry
            if time.time() < expire_at:
                return resp
            self._ds_cache.pop(key, None)
        # single-flight：同一 zone 的并发 DS 查询合并成一次
        inflight = self._ds_inflight.get(key)
        if inflight is not None:
            try:
                return await asyncio.shield(inflight)
            except asyncio.CancelledError:
                raise
            except Exception:
                return None
        fut = asyncio.get_running_loop().create_future()
        self._ds_inflight[key] = fut
        try:
            resp = await self._iterate(str(zone_name), dns.rdatatype.DS, 0)
            # 迭代链被镜像代答时常常没有 NSEC/NSEC3/RRSIG；改从递归
            # bootstrap 取带 DNSSEC 材料的原始报文，仍由 dnssec.py 本地验签。
            if resp is None or not self._has_dnssec_material(
                    resp, dns.rdatatype.DS):
                try:
                    _fb = await self._bootstrap_dnssec_query(
                        str(zone_name), dns.rdatatype.DS)
                except Exception:
                    _fb = None
                if _fb is not None:
                    resp = _fb
        except asyncio.CancelledError:
            if not fut.done():
                fut.set_result(None)
            self._ds_inflight.pop(key, None)
            raise
        except Exception:
            if not fut.done():
                fut.set_result(None)
            self._ds_inflight.pop(key, None)
            return None
        ttl = 300.0
        if resp is None:
            # 失败负缓存只留 5 秒：DS 查询失败通常是瞬时抖动/权威不可达，
            # 缓存 60 秒会把一次抖动放大成整分钟的「链验证失败 → bogus」。
            ttl = 5.0
        else:
            try:
                for rrset in list(resp.answer) + list(resp.authority):
                    rttl = getattr(rrset, "ttl", None)
                    if rttl:
                        ttl = min(ttl, float(rttl))
            except Exception:
                pass
            ttl = max(60.0, min(ttl, 3600.0))
        if len(self._ds_cache) > 512:
            self._ds_cache.clear()
        self._ds_cache[key] = (resp, time.time() + ttl)
        if not fut.done():
            fut.set_result(resp)
        self._ds_inflight.pop(key, None)
        return resp

    def _invalidate_zone_cache(self, qname: str):
        """丢弃 qname 各级后缀的区域权威/DS/已验证 DNSKEY 缓存

        判定 bogus 时调用：这条链路上拿到的 referral 与 DS 可能已被中间人
        操纵，不应再作为后续查询的起跳点（否则错误会被缓存放大到 TTL 到期）。
        DNSSEC 链验证的唯一缓存现在在 dnssec.py，因此这里一并作废。
        """
        try:
            name = dns.name.from_text(qname)
        except Exception:
            return
        try:
            self._dnssec.clear_zone_cache()
            self._dnssec._root_avail_expire = 0.0
        except Exception:
            pass
        while name != dns.name.root:
            key = str(name).lower()
            self._zone_ns_cache.pop(key, None)
            self._ds_cache.pop(key, None)
            name = name.parent()

    # ---------- DNSSEC 验证回调（全链自举） ----------

    @staticmethod
    def _extract_dnskey_rrset(msg) -> Optional[dns.rrset.RRset]:
        """提取响应 answer 段中的 DNSKEY RRset（若存在多个取第一个）。"""
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                return rrset
        return None

    @staticmethod
    def _describe_resp(msg) -> str:
        """一句话描述响应形态——用于证明「链路到底回了什么、是谁回的」

        为什么需要：`absent`（链路不提供 DNSSEC）与「我们自己的查询没带 DO」
        必须能被区分开，否则只能靠外部抓包。这里把关键字段打出来：
          * rcode / 各段 rrset 数 / 是否带 OPT / 是否回声 DO / payload；
          * 若是本进程收到的真实响应（`_query_servers` 会打标）：来源 IP、
            AA/RA 位、RD 是否回显 —— 真权威是 AA=1/RA=0，递归代答或中间盒
            是 AA=0/RA=1；
          * authority 段前几个 rrset 的 owner/type（例如只有 `com. SOA`
            就说明"否定证明"缺失）。

        典型对照：
          * 真权威对 DO=1 的 `. DNSKEY`：rcode=NOERROR / answer≥1 /
            OPT=有 / DO回声=True / AA=1 / RA=0；
          * 被中间盒接管：rcode=NXDOMAIN 或只有 SOA / OPT=无 / DO回声=False /
            AA=0 / RA=1。
        本函数只做描述，不参与任何判定。
        """
        try:
            opt = msg.opt
            do_echo = bool(msg.ednsflags & dns.flags.DO)
            parts = []
            ip = getattr(msg, "_answer_ip", None)
            if ip:
                parts.append("来自=%s" % ip)
            aa = getattr(msg, "_answer_aa", None)
            ra = getattr(msg, "_answer_ra", None)
            rd_e = getattr(msg, "_answer_rd_echo", None)
            if aa is not None:
                parts.append("AA=%d RA=%d RD回声=%d"
                             % (1 if aa else 0, 1 if ra else 0,
                                1 if rd_e else 0))
            parts.append("rcode=%s" % dns.rcode.to_text(msg.rcode()))
            parts.append("answer=%d authority=%d additional=%d"
                         % (len(msg.answer), len(msg.authority),
                            len(msg.additional)))
            parts.append("OPT=%s DO回声=%s payload=%s"
                         % ("有" if opt is not None else "无", do_echo,
                            msg.payload if opt is not None else "-"))
            if msg.authority:
                parts.append("authority=[%s]" % ", ".join(
                    "%s %s" % (str(x.name), dns.rdatatype.to_text(x.rdtype))
                    for x in msg.authority[:3]))
            return " | ".join(parts)
        except Exception as e:      # pragma: no cover
            return "（无法描述响应: %r）" % (e,)

    # ---------- 地址族完整性（识别「某一族被中间设备代答」） ----------

    @staticmethod
    def _family_of(ip) -> str:
        """地址族："6" = IPv6，"4" = IPv4"""
        return "6" if ":" in str(ip) else "4"

    @staticmethod
    def _looks_fake(resp) -> bool:
        """应答形态是否**明显不是**真权威发出来的（用于标记"该跳不可信"）

        判据（都是真权威必须满足的硬性形态，RFC 1035 / 6891 / 4035）：
          * 我们查询带了 EDNS+DO，真权威应答必然带 OPT 并回声 DO；
            没有 OPT、或 OPT 里 DO=0 → 不是真权威（或它根本不懂 DNSSEC）；
          * 有 answer 或 SOA（=权威应答）却没有 AA 位 → 不是权威应答
            （referral 本来就没有 AA，不算）。
        只用于**降低误判**：调用方要求「该族已被判定为代答」且本函数为真，
        才会把应答标成走了代答族。宁可漏标（走正常验证），不可错标。
        """
        try:
            if resp.opt is None:
                return True
            if not (resp.ednsflags & dns.flags.DO):
                return True
            has_data = bool(resp.answer) or any(
                x.rdtype == dns.rdatatype.SOA for x in resp.authority)
            is_referral = (not resp.answer) and any(
                x.rdtype == dns.rdatatype.NS for x in resp.authority)
            if has_data and not is_referral and not (resp.flags & dns.flags.AA):
                return True
            return False
        except Exception:
            return False

    async def _probe_family_integrity(self, family: str) -> str:
        """判定某一地址族的 53 端口是否**真的到达权威服务器**

        判据（对根区 `. DNSKEY`，DO=1，取该族前 2 台根做样本）：
          * "genuine"     : AA=1 **且** 应答带 OPT+DO 回声 **且** answer 含 DNSKEY
                            （真权威对根 DNSKEY 的必然形态，RFC 4035 §2.2）；
          * "hijacked"    : 有应答但不满足上面任一条
                            （典型：NXDOMAIN、AA=0、没有 OPT、无 DNSKEY）；
          * "unreachable" : 该族没有根 IP，或样本全部无应答。

        只做诊断，不修改任何状态；调用方据此决定是否换族。
        """
        ips = [ip for ip in self.root_servers
               if self._family_of(ip) == family][:3]
        if not ips:
            return "unreachable"
        # 本机没有全局 IPv6 时，v6 根根本不可达：直接判 unreachable，
        # 不做无意义的 UDP 查询（旧实现会每轮等 socket/超时）。
        if family == "6" and not getattr(self, "_has_ipv6", False):
            return "unreachable"
        saw_any = False
        genuine_any = False
        _known = getattr(self, "_genuine_roots", None)
        for ip in ips:
            try:
                resp = await self._query_one_async(
                    ip, ".", dns.rdatatype.DNSKEY, 1)
            except Exception:
                resp = None
            if resp is None:
                continue
            saw_any = True
            # 已有根鉴别结果时直接复用，**不要**在请求路径里为每台根再跑
            # 两次随机 NSEC（否则首次查询可能多等十几秒）。只有尚未鉴别
            # （_known is None）才现场探测。
            try:
                if _known is not None:
                    if ip in _known:
                        genuine_any = True
                        continue
                elif getattr(self, "_root_probe_enabled", True):
                    if await self._probe_one_root(ip):
                        genuine_any = True
                        logger.debug("地址族 IPv%s 完整性探测: %s 提供可验证"
                                     "根区否定证明 → genuine", family, ip)
                        continue
                else:
                    has_dnskey = any(
                        x.rdtype == dns.rdatatype.DNSKEY for x in resp.answer)
                    opt_ok = (resp.opt is not None
                              and bool(resp.ednsflags & dns.flags.DO))
                    if (resp.flags & dns.flags.AA) and opt_ok and has_dnskey:
                        genuine_any = True
                        continue
            except Exception:
                pass
            try:
                has_dnskey = any(
                    x.rdtype == dns.rdatatype.DNSKEY for x in resp.answer)
                opt_ok = (resp.opt is not None
                          and bool(resp.ednsflags & dns.flags.DO))
                aa = bool(resp.flags & dns.flags.AA)
                if aa and opt_ok and has_dnskey:
                    logger.debug("地址族 IPv%s 完整性探测: %s 的 DNSKEY 形态"
                                 "像真权威，但根区 NSEC 验证失败 → 镜像",
                                 family, ip)
                else:
                    logger.debug(
                        "地址族 IPv%s 完整性探测: %s 的应答不是真权威"
                        "（%s）→ 有设备代答", family, ip,
                        self._describe_resp(resp))
            except Exception:
                continue
        if genuine_any:
            return "genuine"
        return "hijacked" if saw_any else "unreachable"

    async def _ensure_family_preference(self) -> str:
        """在「DNSSEC 证据=absent」时检查是否只是某一族被代答，并选出真族

        返回优先族（"4"/"6"），"" 表示不限定（两族都不能用，或两族都正常）。
        探测结果缓存 600 秒，避免每次失败都重新探测；选中族发生变化时清掉
        DNSSEC 链的负缓存，让下一次根 DNSKEY 查询立刻走新族重试。
        """
        now = time.time()
        # 探测结论的“可信度”决定缓存时长：两族都给出确定结论
        # （genuine/hijacked）→ 缓存 10 分钟；任一族 unreachable（探测本身
        # 失败：启动预热未完成、偶发丢包、探测超时）→ 只缓存 60 秒后重探。
        #
        # 旧实现一律缓存 600 秒。启动时一次探测超时就把「族选择为空」固化
        # 10 分钟：期间每一跳两族混发，被中间设备代答的 IPv4 微秒级先回且
        # 不带任何 DNSSEC 记录，strict 判定只能一路 unknown → 整片域名被
        # 丢弃（日志里「严格模式丢弃 + 迭代解析连续 N 轮全部失败」）。
        _probe_ttl = 600.0 if getattr(self, "_family_probe_reliable", False) else 60.0
        if now - getattr(self, "_family_probe_at", 0.0) < _probe_ttl:
            return getattr(self, "_preferred_family", "") or ""
        self._family_probe_at = now
        verdicts: Dict[str, str] = {}
        _known_roots = getattr(self, "_genuine_roots", None)
        if getattr(self, "_root_probe_enabled", True) and _known_roots is not None:
            # 已有逐 IP 根鉴别结果：直接按真根集合判定族，**不再**为每台根
            # 发 DNSKEY 探测。否则首个客户端查询要串行等 2~6 台根 × 超时。
            def _family_status(fam: str) -> str:
                ips = [ip for ip in self.root_servers
                       if self._family_of(ip) == fam]
                if not ips:
                    return "unreachable"
                if fam == "6" and not getattr(self, "_has_ipv6", False):
                    return "unreachable"
                return ("genuine" if any(ip in _known_roots for ip in ips)
                        else "hijacked")

            verdicts = {"4": _family_status("4"),
                        "6": _family_status("6")}
        else:
            _fam_res = await asyncio.gather(
                self._probe_family_integrity("4"),
                self._probe_family_integrity("6"),
                return_exceptions=True,
            )
            for fam, res in zip(("4", "6"), _fam_res):
                verdicts[fam] = res if isinstance(res, str) else "unreachable"
        self._family_verdicts = verdicts
        # 根级真实性：只有能提供“随机 NXDOMAIN + 根签名 NSEC”的 IP 才可用于
        # 根起跳/链验证。族级 DNSKEY 形态可能被镜像转发伪造，不能作为唯一判据。
        try:
            _genuine = getattr(self, "_genuine_roots", None)
            if _genuine is None:
                if getattr(self, "_root_probe_enabled", True):
                    _genuine = await self.probe_root_authenticity()
                else:
                    _genuine = set()
            elif (getattr(self, "_root_probe_enabled", True)
                  and time.time() >= getattr(self, "_root_probe_expire", 0.0)):
                # 已过期：后台重探，绝不在客户端查询的关键路径上同步等
                # 多台根 × 两次随机 NSEC（首查可能被拖 10s+）。
                _t = getattr(self, "_root_probe_task", None)
                if _t is None or _t.done():
                    self._root_probe_task = asyncio.create_task(
                        self.probe_root_authenticity())
        except Exception:
            _genuine = set()
        v4g = any(":" not in ip for ip in _genuine)
        v6g = any(":" in ip for ip in _genuine)
        # 「两族都给出了确定结论」才算可靠探测；unreachable 是**探测失败**，
        # 不是“该族没有真权威”，不能当成结论固化。
        self._family_probe_reliable = all(
            verdicts.get(f) in ("genuine", "hijacked") for f in ("4", "6"))
        v4, v6 = verdicts.get("4"), verdicts.get("6")
        # 强制族策略优先于自动判定：用户显式指定 family=ipv4/ipv6 时尊重它
        # （探测结果仍保留在 _family_verdicts 里，供「哪些应答不是真权威」
        #  的标记与交叉印证使用）。
        _policy = getattr(self, "_family_policy", "auto")
        if _policy == "ipv4":
            pref = "4"
        elif _policy == "ipv6":
            pref = "6"
        elif v6g and not v4g:
            pref = "6"
        elif v4g and not v6g:
            pref = "4"
        elif v4 == "genuine" and v6 != "genuine":
            pref = "4"
        elif v6 == "genuine" and v4 != "genuine":
            pref = "6"
        else:
            pref = ""
        changed = (pref != (getattr(self, "_preferred_family", "") or ""))
        self._preferred_family = pref
        if pref and _policy == "auto":
            _bad = "6" if pref == "4" else "4"
            _msg = ("地址族完整性: IPv%s 的应答不是来自真权威（%s）→ 判定被中间"
                    "设备代答；IPv%s 直达权威 → 迭代解析每一跳改走 IPv%s，"
                    "以恢复 DNSSEC 验证")
            _args = (_bad, self._family_verdicts.get(_bad, "?"), pref, pref)
            if changed:
                logger.warning(_msg, *_args)      # 只在结论变化时告警，避免刷屏
            else:
                logger.debug(_msg, *_args)
        elif v4 or v6:
            if all(x == "hijacked" for x in (v4, v6) if x):
                logger.warning(
                    "地址族完整性: IPv4 与 IPv6 的 53 端口都被中间设备代答"
                    "（AA=0/无 OPT/无 DNSSEC）→ 本机无法获得任何 DNSSEC 记录")
            elif "genuine" in (v4, v6):
                logger.debug("地址族完整性: 两族都能到真权威 → 不限定族")
            elif v4 == "hijacked" and v6 == "unreachable":
                logger.warning(
                    "地址族完整性: IPv4 被中间设备代答、IPv6 不可达/未启用 "
                    "→ 没有可用的真族；纯 IPv4 环境无法建立 DNSSEC 链，"
                    "将按 upstream.dnssec.require_rrsig 策略处理"
                    "（false=未验证放行，true=fail-closed）")
        if changed:
            # 换族后必须让根 DNSKEY 立刻重试，而不是等负缓存过期。
            # DNSSEC 链缓存现在只在 dnssec.py，清它的根可用性缓存即可。
            try:
                self._dnssec._verified_zone_cache.pop(dns.name.root, None)
                self._dnssec._root_avail = False
                self._dnssec._root_avail_expire = 0.0
            except Exception:
                pass
        return pref

    async def warmup_dnssec_chain(self) -> None:
        """启动后台预热根区 DNSKEY（统一验证链：由 dnssec.py 完成全链验证）。

        plain_dns_server 不再自己验证 DNSKEY；这里只触发一次
        dnssec.DNSSECValidator._get_verified_zone_keys(root)，让根锚/根
        DNSKEY 进入 dnssec.py 的缓存，并输出链路能力诊断。
        """
        try:
            status, _keys = await self._dnssec._get_verified_zone_keys(
                dns.name.root)
        except Exception as e:
            logger.debug("DNSSEC 根区预热失败（不影响服务）: %s", e)
            return
        if status == "secure":
            logger.info(
                "DNSSEC 预热通过：根区 DNSKEY 已由 dnssec.py 全链验证，"
                "strict 模式可做完整链验证")
        elif status == "bogus":
            logger.error(
                "DNSSEC 预热失败：根区 DNSKEY 验签失败（伪造/时钟错/算法不支持）")
        else:
            logger.warning(
                "DNSSEC 预热：根区 DNSKEY 暂时不可用（%s）→ 相关应答按链不可用"
                "处理；恢复后自动回到完整验证", status)

    @staticmethod
    def _has_dnssec_material(msg, qtype: int) -> bool:
        """响应是否含可供本地验签的 DNSSEC 材料（RRSIG/NSEC/NSEC3/DNSKEY）"""
        try:
            if qtype == dns.rdatatype.NS:
                return any(rr.rdtype == dns.rdatatype.NS
                           for section in (msg.answer, msg.authority)
                           for rr in section)
            # 只认与本次查询/否定证明相关的 RRSIG；一条无关的
            # CNAME/RRSIG 不能当作“链材料”。
            if qtype == dns.rdatatype.DS:
                wanted = {dns.rdatatype.DS, dns.rdatatype.NSEC,
                          dns.rdatatype.NSEC3}
            else:
                wanted = {qtype}
            return any(rr.rdtype == dns.rdatatype.RRSIG
                       and rr.covers in wanted
                       for section in (msg.answer, msg.authority)
                       for rr in section)
        except Exception:
            return False

    def _schedule_bootstrap_reprobe(self) -> None:
        """后台重探 bootstrap 能力，不在请求路径等待"""
        if time.time() < getattr(self, "_bootstrap_probe_expire", 0.0):
            return
        task = getattr(self, "_bootstrap_probe_task", None)
        if task is None or task.done():
            try:
                self._bootstrap_probe_task = asyncio.create_task(
                    self.probe_bootstrap_capabilities())
            except RuntimeError:
                # 无运行中的事件循环（测试/同步上下文）
                pass

    async def _bootstrap_dnssec_query(
            self, qname: str, qtype: int) -> Optional[dns.message.Message]:
        """从递归 bootstrap 上游取**带 DNSSEC 材料**的应答

        中国网络里 IPv4 迭代链常被镜像代答，拿不到父区 NSEC/NSEC3 否定证明
        或 DNSKEY/RRSIG；但配置里的递归上游（如 52.80.66.66）可能返回完整的
        NSEC3+RRSIG。这里只负责取回原始报文，是否可信仍由 dnssec.py 用
        DNSKEY 逐级验签决定；没有签名材料的应答不会作为链证据。
        """
        _probed = getattr(self, "_bootstrap_dnssec_resolvers", None)
        if _probed is not None:
            self._schedule_bootstrap_reprobe()
        if _probed is None:
            # 尚未做启动探测（测试/旧调用路径）：退回配置全量
            resolvers = [str(s) for s in getattr(
                getattr(self, "config", None), "bootstrap_resolvers", []) or []]
        elif _probed:
            resolvers = list(_probed)
        else:
            # 探测已确认没有上游能提供证明：不再每次链查询重试全部 bootstrap
            self._schedule_bootstrap_reprobe()
            return None
        if not resolvers:
            return None

        async def _one(ip: str):
            try:
                q = dns.message.make_query(qname, qtype, want_dnssec=True)
                q.flags |= dns.flags.RD | dns.flags.CD
                r = await asyncio.wait_for(
                    dns.asyncquery.udp(q, ip, timeout=2.0), timeout=2.5)
                return r if self._has_dnssec_material(r, qtype) else None
            except Exception:
                return None

        results = await asyncio.gather(
            *[_one(ip) for ip in resolvers], return_exceptions=True)
        for r in results:
            if isinstance(r, dns.message.Message):
                return r
        return None

    async def _dnssec_query_callback(self, query_bytes: bytes) -> Optional[bytes]:
        """DNSSECValidator 的 DNSKEY 查询回调：迭代查询 DNSKEY 并做 DS 链验证。
        仅返回经过数学信任链验证的 DNSKEY 响应（防止伪造 DNSKEY + 重签名绕过）。"""
        # 链验证查询强制走真族（ipv4_verify=corroborate 的完整覆盖）：
        # 真族不可用时 chain-only 让 _iterate 直接失败，不回退镜像族。
        _chain_tok = _CHAIN_ONLY_CTX.set(True)
        try:
            if not getattr(self, "_preferred_family", ""):
                try:
                    await self._ensure_family_preference()
                except Exception:
                    pass
            msg = dns.message.from_wire(query_bytes)
            if not msg.question:
                return None
            q = msg.question[0]
            zone = q.name
            if q.rdtype == dns.rdatatype.DS:
                # DNSSECValidator 的 DS 判定路径（require_rrsig=true）需要原始
                # DS 响应里的 NSEC/NSEC3 否定证明；旧实现把它也塞进 DNSKEY
                # 构造分支，导致 _zone_has_ds_uncached() 永远看不到 DS/NSEC，
                # 只能返回 None（开启 require_rrsig 后所有无 RRSIG 应答被误杀）。
                # 这里返回原始迭代响应；验签由 dnssec.py 的
                # _zone_has_ds_uncached() 用父区 DNSKEY 完成。
                ds_resp = await self._iterate_ds_cached(zone)
                if ds_resp is None:
                    return None
                ds_resp.id = msg.id
                return ds_resp.to_wire()
            if q.rdtype == dns.rdatatype.NS:
                # DNSSECValidator._name_is_delegation() 需要看 NS owner，而不是
                # DNSKEY。这里返回原始迭代响应（未验签）：调用方只用它判断
                # “父区是否存在 owner==name 的 NS”，不作为安全证据；真正的
                # 安全判定仍由 DS/NSEC 验签完成。
                ns_resp = await self._iterate(str(zone), dns.rdatatype.NS, 0)
                if ns_resp is None:
                    ns_resp = await self._bootstrap_dnssec_query(
                        str(zone), dns.rdatatype.NS)
                if ns_resp is None:
                    return None
                ns_resp.id = msg.id
                return ns_resp.to_wire()
            # DNSKEY：直接返回**原始迭代响应（含 RRSIG）**，验签由
            # dnssec.py 的 _get_verified_zone_keys() 完成——plain_dns 不再
            # 参与任何 DNSSEC 验证（统一验证链，2026-11-14）。
            raw = await self._iterate(str(zone), dns.rdatatype.DNSKEY, 0)
            if (raw is None
                    or not self._has_dnssec_material(
                        raw, dns.rdatatype.DNSKEY)
                    or self._extract_dnskey_rrset(raw) is None):
                _fb = await self._bootstrap_dnssec_query(
                    str(zone), dns.rdatatype.DNSKEY)
                if _fb is not None:
                    raw = _fb
            if raw is None:
                return None
            if self._extract_dnskey_rrset(raw) is None:
                return None
            raw.id = msg.id
            return raw.to_wire()
        except Exception:
            return None
        finally:
            _CHAIN_ONLY_CTX.reset(_chain_tok)

    # ---------- 公开入口 ----------

    # NSEC/NSEC3 类型位图解析复用 dnssec.py 的唯一实现。
    _nsec_has_type = staticmethod(DNSSECValidator._nsec_has_type)

    # NSEC3 原语统一使用 dnssec.DNSSECValidator 的实现（iterations 上限 150
    # 也在那里），避免 plain_dns_server 与 dnssec.py 各写一份、行为不一致。
    _nsec3_hash = staticmethod(DNSSECValidator._nsec3_hash)

    # NSEC3 owner-hash 解码同样复用 dnssec.py 的唯一实现。
    _nsec3_owner_hash = staticmethod(DNSSECValidator._nsec3_owner_hash)

    # 区间覆盖语义与 dnssec.py 的 _hash_in_interval 完全一致（含自指保护）；
    # 不再在 plain_dns_server 里复制一份边界判断。
    _nsec3_interval_check = staticmethod(DNSSECValidator._hash_in_interval)

    # Opt-Out 位解析复用 dnssec.py 的实现。
    _nsec3_optout = staticmethod(DNSSECValidator._nsec3_optout)

    @property
    def name(self) -> str:
        """上游名称（供 ResolverManager 作为 UpstreamServer 注册使用）"""
        return "iterative"

    async def close(self):
        """关闭迭代解析器（无外部连接/会话资源，占位保持与其它解析器接口一致，
        避免 resolver_manager 关闭上游时抛 AttributeError）"""
        pass

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

    async def warmup(self):
        """启动预热：预取根 DNSKEY 与常用 TLD 的 DS/DNSKEY

        首次解析任何域名都要现查 `. DNSKEY` + `<tld>. DS` + `<tld>. DNSKEY`；
        TLD 权威多在境外（RTT 200-300ms），合计 400-600ms。
        启动后在后台跑本方法，用户第一次访问时这些已在缓存里。
        验证全部交给 dnssec.DNSSECValidator；这里只触发它的链缓存。
        逐级串行执行（避免启动瞬间打出查询风暴）；失败只记 debug，不影响功能。
        """
        zones = [dns.name.root]
        for tld in ("com.", "net.", "org.", "cn.", "io.", "co."):
            try:
                zones.append(dns.name.from_text(tld))
            except Exception:
                continue
        for zone in zones:
            try:
                await self._dnssec._get_verified_zone_keys(zone)
            except Exception as e:
                logger.debug("迭代预热 %s 失败: %s", zone, e)
        logger.info(
            "迭代解析预热完成: 已验证 zone %d 个（dnssec.py DNSKEY/DS 已缓存）",
            len(getattr(self._dnssec, "_verified_zone_cache", {})),
        )

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

        bogus 重试（2026-10-30）：严格模式在**冷启动/高并发**下会误判——实测
        one.one.one.one 首次必被当作"签名区无 RRSIG"丢弃、www.ripe.net 的 Akamai
        CNAME 中间跳被判"剥离攻击"（真实日志中的 c0.pki.goog 同理），第二次即
        正常。纯迭代模式没有加密上游可回退，这类一次性误判会直接变成客户端
        SERVFAIL。处理：判定为 bogus 时**清掉该链区域/DS 缓存，在剩余预算内
        重跑一次**；判定标准完全不变（第二次仍 bogus 就丢弃），因此攻击者
        无法借重试绕过验签，只多付一次查询成本。
        """
        self._stats["queries"] += 1
        deadline = time.monotonic() + self.total_timeout
        first_was_bogus = False
        for attempt in range(2):
            _bogus_before = self._stats["bogus"]
            try:
                resp = await asyncio.wait_for(
                    self._resolve_verified(qname, qtype, rdclass),
                    timeout=max(0.5, deadline - time.monotonic()),
                )
            except asyncio.TimeoutError:
                logger.debug("迭代解析总超时: %s", _safe_qname(qname))
                self._stats["fail"] += 1
                return None
            except Exception as e:
                logger.debug("迭代解析异常: %s", e)
                self._stats["fail"] += 1
                return None
            if resp is not None:
                # ★ 重试降级防护：第一次已经**明确判 bogus**（伪造/剥签名），
                #   重试后却因「链查询失败（chain_unavailable）」或「bootstrap
                #   兜底」而放行 —— 没有新证据，结论必须维持 bogus。否则攻击者
                #   只要让 DS/DNSKEY 查询失败一次，就能把伪造数据送进客户端
                #   （实测 dnssec-failed.org 在批量查询时会被这样放行）。
                if (attempt == 1 and first_was_bogus
                        and self._last_release in ("chain_unavailable", "bootstrap")):
                    self._stats["bogus"] += 1
                    logger.debug(
                        "DNSSEC: %s 首次判定 bogus，重试仅因 %s 才放行 → 维持 bogus",
                        _safe_qname(qname), self._last_release)
                    return None
                return resp
            if attempt == 0 and self._stats["bogus"] > _bogus_before:
                first_was_bogus = True
                self._invalidate_zone_cache(qname)
                logger.debug(
                    "DNSSEC 严格模式丢弃 %s（可能为冷启动链缓存未就绪），"
                    "清缓存后用剩余 %.1fs 重试一次",
                    _safe_qname(qname), max(0.0, deadline - time.monotonic()),
                )
                continue
            return None
        return None

    @staticmethod
    def _needs_bootstrap_fallback(resp, qtype: int) -> bool:
        """是否需要走 bootstrap 递归兜底

        只在「迭代没拿到最终答案」时兜底：
          - resp is None（迭代整体失败）；
          - rcode=NOERROR 但 answer 里没有 qtype 记录（NODATA，CDN 调度域名常见）。
        NXDOMAIN / SERVFAIL 是明确语义，**不**兜底（避免把"域名不存在"变成"能解析"）。
        """
        if resp is None:
            return True
        try:
            if resp.rcode() != dns.rcode.NOERROR:
                return False
            return not any(rrset.rdtype == qtype for rrset in resp.answer)
        except Exception:
            return False

    async def _bootstrap_recursive(
        self, qname: str, qtype: int, rdclass: int = 1
    ) -> Optional[dns.message.Message]:
        """用配置里的 bootstrap DNS 做一次**递归**查询（RD=1）作为可用性兜底

        只在 `_needs_bootstrap_fallback` 为真时调用（CDN 调度域名 NODATA /
        迭代整体失败），其余查询仍完全走本地迭代。限并发 4，避免 NODATA
        风暴时把 bootstrap DNS 打爆。
        """
        servers = [str(s) for s in (self.config.bootstrap_resolvers or [])]
        # 启动探测到的可达集合优先；空/未探测才回退配置全量
        _alive = getattr(self, "_bootstrap_alive", None)
        if _alive:
            servers = [s for s in servers if s in _alive] or list(_alive)
        if not servers:
            return None
        q = dns.message.make_query(qname, qtype, rdclass=rdclass, want_dnssec=True)
        # RD=1：make_query 默认带 RD，这里显式确保
        try:
            q.flags |= dns.flags.RD
        except Exception:
            pass
        # 兜底是"可用性"性质的，给 0.5-1s 即可：给太多会把预算吃满，
        # 让本来只是缺少最终答案的查询变成整体超时。
        timeout = min(1.0, max(0.5, self.timeout))
        async with self._bootstrap_sem:
            # **并行**问前 3 台：串行试 4 台最坏要 4×2s=8s，会把整个查询预算
            # （10s）吃光，让本来能成功的查询变成超时。
            targets = servers[:3]
            tasks: Dict[asyncio.Future, str] = {}
            for _s in targets:
                try:
                    tasks[asyncio.ensure_future(
                        dns.asyncquery.udp(
                            q, _s, timeout=timeout, ignore_unexpected=True,
                        )
                    )] = _s
                except Exception:
                    continue
            if not tasks:
                return None
            try:
                pending = set(tasks)
                deadline = asyncio.get_running_loop().time() + timeout + 0.5
                while pending:
                    left = deadline - asyncio.get_running_loop().time()
                    if left <= 0:
                        break
                    done, pending = await asyncio.wait(
                        pending, timeout=left,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in done:
                        try:
                            r = t.result()
                        except Exception:
                            continue
                        if r is not None and r.answer:
                            logger.debug(
                                "迭代兜底：%s %s 经 bootstrap %s 递归取到 %d 条答案",
                                _safe_qname(qname),
                                dns.rdatatype.to_text(qtype),
                                tasks.get(t, "?"), len(r.answer),
                            )
                            return r
                return None
            finally:
                # 取消未完成的任务并消费其异常（避免 "Future exception was never retrieved"）
                for t in tasks:
                    if not t.done():
                        t.cancel()
                    t.add_done_callback(_consume_future_exc)

    async def _resolve_verified_unified(self, qname: str, qtype: int,
                                        rdclass: int) -> Optional[dns.message.Message]:
        """统一验证入口：迭代只负责解析，DNSSEC 验证全部交给 dnssec.py。

        2026-11-14：plain_dns_server 不再实现任何链验证（DS→DNSKEY→RRSIG、
        负应答 NSEC/NSEC3 语义、SOA 归属、opt-out 等）。唯一实现是
        dnssec.DNSSECValidator.validate_response()；迭代器只把原始响应
        （含 RRSIG/NSEC/NSEC3）交给它。
        """
        _V6_DISABLED_CTX.set(False)
        self._last_release = ""
        try:
            await self._ensure_family_preference()
        except Exception:
            pass
        _FAMILY_ONLY_CTX.set(getattr(self, "_preferred_family", "") or "")
        resp = await self._iterate(qname, qtype, 0, rdclass)
        if self._needs_bootstrap_fallback(resp, qtype):
            fb = await self._bootstrap_recursive(qname, qtype, rdclass)
            if fb is not None and fb.answer:
                fb._bootstrap_fallback = True
                try:
                    fb._hijacked_path = bool(
                        getattr(resp, "_hijacked_path", False))
                except Exception:
                    pass
                resp = fb
        if resp is None:
            self._stats["fail"] += 1
            return None
        if not self.strict_dnssec:
            self._stats["success"] += 1
            return resp
        # upstream.dnssec.enabled=false：全局关闭 DNSSEC 验证。
        # 必须在这里就返回，不能继续走下面的根链预检：根 DNSKEY 验签失败
        # （bogus_root）会让“已经关闭验证”的响应仍被丢弃，且每次查询都白跑
        # 一遍 DNSKEY/DS。配置注释明确这是全局开关。
        if not getattr(self._dnssec, "enabled", True):
            self._stats["success"] += 1
            self._last_release = "dnssec_disabled"
            return resp
        # bootstrap 递归兜底是**明文、无 DNSSEC**的可用性路径：仅在迭代
        # 整体失败/NODATA 时启用。它返回的无签名应答不能当“签名被剥离”
        # 判 bogus（否则迭代被劫持时所有域名都会 SERVFAIL，等于兜底失效）。
        # require_rrsig=false 时按未验证放行；true 时继续走严格验签。
        if (not getattr(self, "_require_rrsig", False)
                and getattr(resp, "_bootstrap_fallback", False)):
            try:
                _sig = any(
                    rr.rdtype == dns.rdatatype.RRSIG
                    for sec in (resp.answer, resp.authority)
                    for rr in sec)
            except Exception:
                _sig = False
            if not _sig:
                # 但若父区已明确有 DS（该名字本应签名），不能拿明文兜底
                # 数据绕过 DNSSEC（dnssec-failed.org 这类必须仍被丢弃）。
                try:
                    _has_ds = await self._dnssec._zone_has_ds(
                        dns.name.from_text(qname))
                except Exception:
                    _has_ds = None
                if _has_ds is not True:
                    self._stats["insecure"] += 1
                    self._stats["success"] += 1
                    self._last_release = "bootstrap"
                    return resp
        # ---- 代答族/链路降级策略（与验证算法无关，保持原有可观测性）----
        # 1) corroborate：镜像族答案用真族重解析印证（不一致即改用真族）
        _was_hijacked = bool(getattr(resp, "_hijacked_path", False))
        if (getattr(self, "_ipv4_verify", "strict") == "corroborate"
                and _was_hijacked):
            _was_hijacked = True
            _alt = await self._resolve_over_genuine(qname, qtype, rdclass)
            if _alt is not None:
                try:
                    _same = (
                        answer_set_fingerprint(
                            resp.to_wire(origin=dns.name.root))
                        == answer_set_fingerprint(
                            _alt.to_wire(origin=dns.name.root)))
                except Exception:
                    _same = False
                self._stats["corroborated"] = (
                    self._stats.get("corroborated", 0) + 1)
                if _same:
                    logger.debug(
                        "交叉印证通过: %s（改用真族答案）", _safe_qname(qname))
                else:
                    self._stats["mismatch"] = (
                        self._stats.get("mismatch", 0) + 1)
                    try:
                        self._report_dnssec_mismatch(
                            qname, getattr(resp, "_answer_ip", "?"))
                    except Exception:
                        pass
                resp = _alt
            else:
                logger.debug(
                    "交叉印证不可用: %s（按未验证放行）", _safe_qname(qname))
        # 1b) ipv4_verify=none：配置明确“只保可用性、不做额外校验”，
        # 镜像族应答直接未验证放行（I4 的镜像形态伪装得很好，无法区分）。
        if (getattr(self, "_ipv4_verify", "strict") == "none"
                and getattr(resp, "_answer_family", "") == "4"
                and (getattr(self, "_family_verdicts", {}) or {}).get("4")
                == "hijacked"):
            self._stats["hijacked_path"] = (
                self._stats.get("hijacked_path", 0) + 1)
            self._stats["insecure"] += 1
            self._stats["success"] += 1
            self._last_release = "hijacked_path"
            try:
                self._report_hijacked_path(
                    qname, getattr(resp, "_answer_ip", "?"))
            except Exception:
                pass
            return resp
        # 2) 根信任源三态：secure→继续；bogus→真攻击，绝不降级放行；
        #    insecure/indeterminate→链路不提供 DNSSEC 材料（absent），
        #    按 require_rrsig 决定放行/丢弃。
        #    不能只用 `_root_chain_available()` 的 bool：它把“根 DNSKEY
        #    验签失败（bogus）”和“暂时取不到（absent）”合并成 False，
        #    会让伪造的根 DNSKEY 在 require_rrsig=false 下被当成可用性
        #    降级放行（安全回归）。
        try:
            _root_status, _root_keys = await self._dnssec._get_verified_zone_keys(
                dns.name.root)
        except Exception:
            _root_status = "indeterminate"
        if _root_status == "bogus":
            self._stats["bogus"] += 1
            self._last_release = "bogus"
            self._dnssec_evidence = "bogus_root"
            self._warn_dnssec_drop(
                qname, "bogus_root", "根区 DNSKEY 验签失败（伪造/配置错误）")
            return None
        if _root_status != "secure":
            if getattr(self, "_require_rrsig", False):
                self._stats["bogus"] += 1
                self._last_release = "bogus"
                return None
            self._stats["dnssec_absent"] = (
                self._stats.get("dnssec_absent", 0) + 1)
            self._stats["insecure"] += 1
            self._stats["success"] += 1
            self._dnssec_evidence = "absent"
            self._last_release = "dnssec_absent"
            return resp
        # 3) 代答族降级（require_rrsig=false）：按配置未验证放行
        if (not getattr(self, "_require_rrsig", False)
                and getattr(resp, "_hijacked_path", False)):
            self._stats["hijacked_path"] = (
                self._stats.get("hijacked_path", 0) + 1)
            self._stats["insecure"] += 1
            self._stats["success"] += 1
            self._last_release = "hijacked_path"
            try:
                self._report_hijacked_path(
                    qname, getattr(resp, "_answer_ip", "?"))
            except Exception:
                pass
            return resp
        try:
            q = dns.message.make_query(qname, qtype, want_dnssec=True)
            ok, status, info = await self._dnssec.validate_response(
                q.to_wire(), resp.to_wire(origin=dns.name.root))
        except Exception as e:
            logger.debug("DNSSEC 统一验证异常: %s", e)
            self._stats["fail"] += 1
            return None
        if not ok:
            # corroborate 用真族重解析后仍是**完全无 RRSIG**的应答：
            # 说明这条链路对该名字不提供 DNSSEC 材料（实测 google.com.hk：
            # 镜像与真族都回无签名 A），不是“签名被剥离”。按
            # require_rrsig=false 的可用性语义放行并标记未验证，避免
            # 永久 SERVFAIL + 客户端重试刷屏；require_rrsig=true 不覆盖。
            try:
                _no_sig = not any(
                    rr.rdtype == dns.rdatatype.RRSIG
                    for sec in (resp.answer, resp.authority)
                    for rr in sec)
            except Exception:
                _no_sig = False
            if (not getattr(self, "_require_rrsig", False)
                    and _was_hijacked and _no_sig):
                self._stats["hijacked_path"] = (
                    self._stats.get("hijacked_path", 0) + 1)
                self._stats["insecure"] += 1
                self._stats["success"] += 1
                self._last_release = "hijacked_path"
                return resp
            self._stats["bogus"] += 1
            self._last_release = status
            self._warn_dnssec_drop(qname, status, info.get("detail", ""))
            return None
        # CNAME 中间跳：迭代器把每一跳的原始响应保存在 _cname_chain；
        # 逐跳交给同一个 dnssec.py 验证（同一实现，不另写一套）。
        for wire in getattr(resp, "_cname_chain", []) or []:
            try:
                cm = dns.message.from_wire(wire)
                if not cm.question:
                    continue
                qq = dns.message.make_query(
                    str(cm.question[0].name), cm.question[0].rdtype,
                    want_dnssec=True)
                ok2, st2, info2 = await self._dnssec.validate_response(
                    qq.to_wire(), wire, cname_hop=True)
            except Exception:
                continue
            if not ok2:
                self._stats["bogus"] += 1
                self._last_release = st2
                self._warn_dnssec_drop(
                    qname, st2, info2.get("detail", ""), cname_hop=True)
                return None
        if status == "secure":
            try:
                resp.flags |= dns.flags.AD
            except Exception:
                pass
            self._stats["secure"] += 1
            self._dnssec_evidence = "ok"
        else:
            self._stats["insecure"] += 1
        _detail = str(info.get("detail", "")) if isinstance(info, dict) else ""
        if status == "insecure" and "链路不提供" in _detail:
            self._stats["dnssec_absent"] = (
                self._stats.get("dnssec_absent", 0) + 1)
            self._dnssec_evidence = "absent"
            self._last_release = "dnssec_absent"
        elif status == "indeterminate" and not getattr(
                self._dnssec, "_crypto_ok", True):
            # 验签后端缺失（本机无法验证任何签名）与“链路不提供材料”
            # 同一处置：require_rrsig=false 时按 absent 放行。
            self._stats["dnssec_absent"] = (
                self._stats.get("dnssec_absent", 0) + 1)
            self._dnssec_evidence = "absent"
            self._last_release = "dnssec_absent"
        else:
            self._last_release = status
        self._stats["success"] += 1
        return resp

    async def _resolve_verified(self, qname: str, qtype: int,
                                rdclass: int) -> Optional[dns.message.Message]:
        """`_resolve_verified_inner` 的**上下文隔离包装**

        `_FAMILY_ONLY_CTX` 是 per-query 的优先族标记，用 ContextVar 传递到
        `_iterate` 的每一跳。如果只在内部 set 而不还原，同一个 asyncio Task
        里后续的调用（以及直接调 dnssec.py 链查询 `_get_verified_zone_keys()`
        的预热、测试）会**继承上一条查询的族选择**，表现为"明明已经改走 IPv6，
        下一次又去问 IPv4 镜像"。这里统一 save/restore，保证不串味。
        """
        _tok = _FAMILY_ONLY_CTX.set(
            getattr(self, "_preferred_family", "") or "")
        try:
            return await self._resolve_verified_inner(qname, qtype, rdclass)
        finally:
            _FAMILY_ONLY_CTX.reset(_tok)

    async def _resolve_verified_inner(self, qname: str, qtype: int,
                                      rdclass: int) -> Optional[dns.message.Message]:
        """resolve 的内部实现：迭代 + DNSSEC 严格验证（受外层 total_timeout 约束）。

        注：曾尝试"主链与 DNSSEC 链并行预取"（预取根/TLD/父区的 DS+DNSKEY），
        实测反而更慢：baidu 1319→1498ms、qq 1852→2145ms。原因是预取与主链
        访问同一批境外权威、共享同一个阻塞线程池，竞争成本大于重叠收益；
        且 baidu.com/qq.com 这类未签名区预取是纯浪费。故保留串行（配合
        DS/DNSKEY 并行 + DS 缓存 + 启动 warmup 已足够）。
        """
        try:
            # 统一验证链：解析与验证分离（DNSSEC 验证全部在 dnssec.py）。
            return await self._resolve_verified_unified(qname, qtype, rdclass)
        except Exception as e:
            logger.debug("迭代解析异常: %s", e)
            self._stats["fail"] += 1
            return None


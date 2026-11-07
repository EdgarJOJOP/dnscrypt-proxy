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


class _ChainUnavailable(Exception):
    """DNSSEC 链上某一跳**查询失败 / 响应不完整** —— 无法判定真伪，不等于 bogus

    为什么要把这种情形与"验证失败"分开（RFC 4035 §5.2 的安全判定必须是
    二元的：要么验证通过，要么判 bogus；但"没拿到数据"不属于任何一方）：

      * 验证失败（DS digest 不匹配、签名不通过、DNSKEY 自签失败）→ 真 bogus，
        必须拒绝并告警。
      * 查询失败（超时、权威不可达、响应缺 DNSKEY/含 referral）→ 只是这次
        没取到证据。旧实现把它和 bogus 混在一起 `return None`，调用方一律判
        bogus 并打 WARNING —— 实测一次 DNS 抖动就让 verisign.com / nic.se
        这类正常签名域名随机 SERVFAIL 并刷警告。
      * `_iterate_ds_cached` 还会把失败负缓存 60 秒，把一次抖动放大成整分钟
        的持续失败。

    现在这类情形单独抛出：`_get_trusted_dnskey` 会先清负缓存重试一次，
    仍失败才标记为"暂时不可用"，由调用方按 error 语义处理（放行 + debug，
    与 `_zone_signed_status` 返回 "error" 时的策略一致）。
    """


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
        # 独立 DNSSEC 验证器（内置根信任锚），回调指向迭代解析自身 → 全链自举
        self._dnssec = dnssec_validator or DNSSECValidator(enabled=True, mode="strict")
        # DNSSEC 数学验签后端（dnspython 依赖 cryptography）。
        # 缺失时 dns.dnssec.validate() 抛 ImportError，旧代码把它当普通异常吞掉，
        # 导致 _get_trusted_dnskey() 全部返回 None；随后 _zone_signed_status()
        # 无法验证父区 NSEC3 否定证明，会一路升到祖先区、把祖先的 DS 误当成
        # “本区已签名”，最终输出“签名被剥离”的假告警并丢弃合法应答。
        # 这里启动时显式检测并告警；_get_trusted_dnskey() 也会快速返回 None，
        # 让上层按 unknown（无法证明）处理，而不是误判 secure。
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
        try:
            self._dnssec.set_dns_query_callback(self._dnssec_query_callback)
        except Exception:
            pass
        self._stats = {
            "queries": 0, "success": 0, "fail": 0,
            "bogus": 0, "insecure": 0, "secure": 0, "depth_exceeded": 0,
        }
        # 「应答无签名且无法证明该域名未签名」告警的节流状态：
        # 严格模式下这类丢弃可能每秒几十条，必须合并输出，否则日志被刷爆。
        self._unknown_warn_last = 0.0
        self._unknown_warn_merged = 0
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
        # 已验证 zone 的 DNSKEY 缓存（避免每域名重复全链迭代流量）
        # 值: (rrset, 失效时间戳)，按缓存条目 TTL 失效，避免 DNSKEY 轮换后旧缓存致 bogus
        self._verified_zone_cache: Dict[str, tuple] = {}
        # 区域权威服务器缓存：zone 名 -> (权威 IP 列表, 失效时间戳)
        # 作用：CNAME 目标/同一 TLD 的后续查询不必再从根逐跳（实测一次
        # www.baidu.com 会为 CNAME 目标重复走 root→com.→baidu.com）。
        # 只缓存 referral 给出的 NS+glue（与解析器自身的 NS 缓存同源），TTL 取 NS TTL。
        self._zone_ns_cache: Dict[str, tuple] = {}
        # 「name 是否为父区的委托点（有 NS 记录）」缓存：name -> (bool, 失效时间)
        # 用途：DS 查询返回 NODATA 且没有 NSEC/NSEC3 否定证明时，必须区分
        #   - n 是委托点 apex：不能继续升父级（否则会把父区自己的 DS 当成
        #     n 所在区已签名，制造“签名被剥离”假告警）；
        #   - n 只是当前区内的普通名：必须继续升到所在区 apex 才能判断。
        # 正/负结果都缓存，避免未签名区的每个子名都多一次 NS 查询。
        self._delegation_cache: Dict[str, tuple] = {}
        # DS 响应缓存：zone 名 -> (响应, 失效时间戳)
        # `_get_trusted_dnskey` 与 `_zone_signed_status` 会各查一次同一 zone 的 DS；
        # 实测 www.baidu.com 的 DS(baidu.com) 被查了 3 次、每次 200ms+。
        self._ds_cache: Dict[str, tuple] = {}
        # DNSSEC 链查询的 single-flight 表：zone 名 -> Future
        # 冷启动高并发时（如浏览器一次打开 30 个站点），每个域名都要验证
        # 根/TLD 的 DNSKEY 与 DS，若不合并，同一 zone 会被并发查几十次——
        # 根/TLD 权威会因 RRL 限速而大面积超时（表现为「解析卡 3s+ 后失败」）。
        self._dnskey_inflight: Dict[str, asyncio.Future] = {}
        self._ds_inflight: Dict[str, asyncio.Future] = {}
        # DNSSEC 链构建的并发闸门：single-flight 只合并同一 zone；冷启动时
        # root/cn/com/... 等不同 zone 的链构建仍会并发访问权威，同一源 IP
        # 的突发查询容易被 RRL 限速。这里把同时进行的链构建限制在 4 个，
        # 其余在 semaphore 上排队（惰性创建，避免绑定错误的 event loop）。
        self._dnskey_semaphore: Optional[asyncio.Semaphore] = None
        # 链构建失败后的短负缓存：zone -> 可再次尝试的时间戳。
        # 一次限速/超时后若每个新查询都立刻重试同一权威，只会把限速窗口
        # 无限拉长；15s 内直接复用“暂时不可用”结论（按 error 放行），
        # 到期后自动重新尝试，避免既误杀又持续打爆权威。
        self._dnskey_retry_after: Dict[str, float] = {}
        # 失败重试退避（秒）：初始 + 3 次重试，覆盖权威瞬时超时/RRL。
        # 每次附加 0~50ms 抖动，避免多个并发链同步重试再次撞限速。
        self._dnskey_retry_delays = (0.15, 0.4, 0.9)
        # DNSSEC 告警去重：{(tag, zone)} 已告警过。
        # 同一 zone 的链验证失败是**持续状态**（KSK 轮换、上游剥离 RRSIG、
        # 权威配置错误…），每次查询都打一条 WARNING 只会刷屏把真问题淹掉
        # （实测 sc./io. 每秒数条）。首个 WARNING 保留，后续降为 DEBUG。
        self._dnssec_warned = set()
        # 因「查询失败」导致链暂时不可用的 zone（不等于 bogus）。调用方据此
        # 按 error 语义放行而不是判伪造（见 _ChainUnavailable 的说明）。
        self._chain_unavailable = set()
        # 最近一次 _resolve_verified 的放行原因（"chain_unavailable" / "bootstrap" /
        # "insecure" / "secure" / ""）。resolve() 的重试据此判断"第二次放行"是否
        # 只是查询失败/兜底造成的降级，避免把首次已判 bogus 的结论放过去。
        self._last_release = ""
        # bootstrap 递归兜底的并发闸门（只用于 CDN 调度域名 NODATA 场景）
        self._bootstrap_sem = asyncio.Semaphore(4)
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

    def _report_dnssec_drop(self, qname: str, reason: str, hint: str):
        """节流输出「严格模式丢弃应答」告警

        严格模式下这类丢弃可能每秒几十条：60 秒内只输出一条 warning，
        其余同类事件降级为 debug；恢复输出时附带被合并的条数，避免刷爆日志。
        """
        now = time.monotonic()
        if now - self._unknown_warn_last >= 60.0:
            merged = self._unknown_warn_merged
            self._unknown_warn_last = now
            self._unknown_warn_merged = 0
            suffix = f"（最近 60 秒同类共 {merged + 1} 次）" if merged else ""
            logger.warning(
                "DNSSEC 严格模式丢弃 %s%s：%s%s",
                _safe_qname(qname), suffix, reason, hint,
            )
        else:
            self._unknown_warn_merged += 1
            logger.debug(
                "DNSSEC 严格模式丢弃（已合并计数）: %s — %s",
                _safe_qname(qname), reason,
            )

    def _report_unsigned_unknown(self, qname: str):
        """应答既无签名、也无法证明「该域名本就未签名」→ 严格模式丢弃

        用大白话说清楚：上游返回的应答既没有数字签名（RRSIG），也没有能证明
        「这个域名本来就不在 DNSSEC 保护范围内」的否定证明（NSEC/NSEC3）。
        既无法验证、也无法证明无需验证，严格模式就当作「可能被篡改」丢弃。
        """
        self._report_dnssec_drop(
            qname,
            reason=(
                "应答没有签名(RRSIG)，也没有能证明「该域名本就未签名」的 "
                "NSEC/NSEC3 记录，无法确认应答未被篡改。"
            ),
            hint="常见原因是所用上游不返回 DNSSEC 记录，可换用会下发 DNSSEC 记录的上游。",
        )

    def _report_dnssec_stripped(self, qname: str):
        """该域名所在区已启用 DNSSEC，但应答完全没有签名 → 疑似签名被剥离"""
        self._report_dnssec_drop(
            qname,
            reason=(
                "该域名所在区域已启用 DNSSEC，但应答里完全没有数字签名(RRSIG)，"
                "说明签名可能在传输途中被剥离，无法确认应答未被篡改。"
            ),
            hint="请检查链路是否存在 DNS 劫持/代理，或换用会下发 DNSSEC 记录的上游。",
        )

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
                    if resp is not None:
                        self._record_server_health(ip, _elapsed)
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
        # 优先从「最近已知区的权威」起跳：同一 TLD / CNAME 目标可省掉
        # root→TLD 两跳（实测每次约 100-500ms）。DS 查询必须从父区起跳
        # （DS 由父区权威持有），因此 _closest_zone_servers 对 DS 强制上移一级。
        started_from_cache = False
        _cached_start = self._closest_zone_servers(qname, qtype)
        if _cached_start is not None:
            servers, started_from_cache = _cached_start
        cname_targets: List[str] = []
        cname_chain: List[bytes] = []  # 中间跳 CNAME 响应 wire（供上层验签，防 target 篡改）
        # QNAME 最小化（RFC 9156）：向当前区只问「下一级名字」，中间级用 NS 查询，
        # 到最终名才用原 qtype——根/TLD 看不到完整查询名（隐私），也少发无用查询。
        # 缓存起跳时当前区未知，跳过最小化；一旦发现区名没推进，也自动回退全名，
        # 避免把"实现不规范的权威"变成解析失败。
        _minimize = bool(getattr(self, "qname_minimization", True)) and not started_from_cache
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
            response = await self._query_servers(servers, _q_name, _q_type, rdclass)
            if response is None and started_from_cache:
                # 缓存里的权威已失效/换 IP：回退到根重新走完整链路，功能不降级
                logger.debug("缓存区权威不可达，回退根服务器重试: %s", _safe_qname(qname))
                self._zone_ns_cache.clear()
                servers = list(self.root_servers)
                started_from_cache = False
                response = await self._query_servers(servers, qname, qtype, rdclass)
            if response is None:
                return None
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
                return response
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
                    return response
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
                return response
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
                return response
            # 3. CNAME 链（最多跟随 8 跳）——owner 必须等于当前 qname（防注入）
            cname = self._extract_cname(response, expected_owner=qname)
            if cname is not None:
                if qtype == dns.rdatatype.DS:
                    # DS 查询**不跟随 CNAME**（RFC 4035 §2.4：DS 与 CNAME 不能
                    # 共存；CNAME owner 处没有 DS）。若继续跟到目标区，会把
                    # 目标区的 NSEC3/SOA 当成该名字的否定证明，父区 key 与
                    # owner 错配，_zone_signed_status() 只能判 unknown。
                    # 典型：cdn.jsdelivr.net（CNAME 到 fastly/cloudflare）被
                    # 误判 unknown → CNAME 链中间跳被丢弃。
                    # 直接返回 CNAME 响应：上层看到“无 DS、无匹配否定证明”，
                    # 会按“普通名”继续升到 jsdelivr.net 判断（未签名 → 放行）。
                    self._restore_question(response, original_qname, qtype)
                    return response
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
            name = name.parent()
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
        """DS 查询（带 zone 级缓存）

        `_get_trusted_dnskey` 与 `_zone_signed_status` 会对同一 zone 各查一次
        DS（实测 www.baidu.com 的 DS(baidu.com) 被查 3 次、每次 200ms+）。
        这里按 zone 缓存响应：TTL 取响应里最小的 rrset TTL（60s-1h）；
        失败也缓存 60s，避免对同一失败目标反复重试。
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

    def _warn_dnssec_once(self, tag: str, zone_name, msg: str, *args) -> bool:
        """DNSSEC 告警去重：同一 (tag, zone) 只打一次 WARNING，其余降 DEBUG

        返回 True 表示这次真的打了 WARNING（调用方一般不关心）。
        DNSSEC 链验证失败对同一 zone 是**持续状态**：KSK 轮换窗口、权威配置
        错误、上游剥离 RRSIG……每次查询都重复告警没有新信息，反而把日志淹掉
        （实测 sc./io. 每秒数条、全是同一句）。这里首个 WARNING 保留完整明细，
        后续同 zone 的重复事件进 DEBUG，便于需要时用 DEBUG 级查看频率。
        """
        key = f"{tag}|{zone_name}"
        if key in self._dnssec_warned:
            logger.debug(msg, *args)
            return False
        if len(self._dnssec_warned) > 512:
            # 有界：zone 名来自查询（半可控），超限清空重建，不无限增长
            self._dnssec_warned.clear()
        self._dnssec_warned.add(key)
        logger.warning(msg, *args)
        return True

    def _invalidate_zone_cache(self, qname: str):
        """丢弃 qname 各级后缀的区域权威/DS 缓存

        DNSSEC 判定异常（签名区无签名 / 无法证明未签名 / 链验证失败）时调用：
        这条链路上拿到的 referral 与 DS 可能已被中间人操纵，不应再作为后续
        查询的起跳点（否则错误会被缓存放大到 TTL 到期）。
        """
        try:
            name = dns.name.from_text(qname)
        except Exception:
            return
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
        同时搜索 answer 与 authority 段。

        ★ 报文若带 `_insecure_signers` 标记（该响应含「父区无 DS」的区签出的
        RRSIG），这里自动把那些 signer 的 RRSIG 过滤掉：insecure 委托的签名
        无法沿 DS 链验证，RFC 4035 §5.2 要求按未签名处理，留着只会让
        `dns.dnssec.validate()` 抛 KeyError 把合法应答判成 bogus。
        过滤后一条不剩 → 返回 None，等价于「该 RRset 没有签名」，后续代码
        会走既有的「按所在区 DS 状态判定」逻辑。集中在这里做，可同时覆盖
        answer / authority / CNAME 中间跳 / 否定证明的全部验签点。
        """
        insecure = getattr(msg, "_insecure_signers", None)
        for section in (msg.answer, msg.authority):
            try:
                sigs = msg.find_rrset(
                    section, rrset.name, rrset.rdclass,
                    dns.rdatatype.RRSIG, covers=rrset.rdtype, create=False,
                )
            except KeyError:
                continue
            if not insecure:
                return sigs
            kept = [s for s in sigs if s.signer not in insecure]
            if not kept:
                return None
            if len(kept) == len(sigs):
                return sigs
            out = dns.rrset.RRset(sigs.name, sigs.rdclass,
                                  dns.rdatatype.RRSIG, covers=sigs.covers)
            for s in kept:
                out.add(s)
            return out
        return None

    def _clear_ds_cache_for_chain(self, zone_name: dns.name.Name) -> None:
        """只清理 zone 及其父级链的 DS 缓存，保留其它 zone 的有效缓存。

        旧实现失败时 `_ds_cache.clear()` 会把其它 zone 刚建立的有效缓存
        一起扔掉，下一批查询又全部重查，反而放大权威限速。
        """
        n = zone_name
        while n != dns.name.root:
            k = str(n).lower()
            self._ds_cache.pop(k, None)
            self._ds_inflight.pop(k, None)
            n = n.parent()

    async def _get_trusted_dnskey(self, zone_name: dns.name.Name) -> Optional[dns.rrset.RRset]:
        """DNSSEC 链验证入口（缓存 + single-flight + 失败重试/负缓存）

        冷启动并发时（浏览器一次打开几十个站点），每个域名都要验证根/TLD 的
        DNSKEY；若各查一遍，同一 zone 会被并发查几十次，根/TLD 权威因 RRL
        限速而大面积超时。这里把同一 zone 的并发请求合并成一次；不同 zone
        再通过 semaphore 限制同时进行的链构建数，避免同一源 IP 的突发查询
        触发 RRL。

        失败处理（2026-11-06）：一次 DNSKEY/DS 超时或 RRL 不代表签名被剥离，
        所以按 0.15/0.4/0.9s 退避重试；仍失败才记 15s 负缓存并按 error
        （链不可用）放行，15s 后自动重新尝试。负缓存只避免“每个新查询都
        立刻重打同一权威”，不会把暂时故障永久固化为放行。
        """
        key = str(zone_name).lower()
        if not self._dnssec_crypto_ok:
            # 验签后端缺失：任何 DNSKEY 都无法被数学验证，直接返回 None。
            # 调用方必须按 unknown（无法证明）处理，绝不能据此判 secure/bogus。
            return None
        cached = self._verified_zone_cache.get(key)
        if cached is not None and time.time() < cached[1]:
            return cached[0]
        retry_after = getattr(self, "_dnskey_retry_after", None)
        if retry_after is None:
            retry_after = {}
            self._dnskey_retry_after = retry_after
        if time.time() < retry_after.get(key, 0.0):
            # 负缓存期内：不再打同一 zone 的权威，调用方按 error 放行；
            # 到期后这里会自动重新走完整重试。
            self._stats["chain_unavailable"] = (
                self._stats.get("chain_unavailable", 0) + 1)
            return None
        inflight = self._dnskey_inflight.get(key)
        if inflight is not None:
            try:
                return await asyncio.shield(inflight)
            except asyncio.CancelledError:
                raise
            except Exception:
                return None
        fut = asyncio.get_running_loop().create_future()
        self._dnskey_inflight[key] = fut
        sem = getattr(self, "_dnskey_semaphore", None)
        if sem is None:
            sem = asyncio.Semaphore(4)
            self._dnskey_semaphore = sem
        result = None
        try:
            async with sem:
                delays = tuple(getattr(
                    self, "_dnskey_retry_delays", (0.15, 0.4, 0.9)))
                last_error = None
                for attempt, delay in enumerate((0.0,) + delays):
                    if delay:
                        # 抖动：多个并发链/实例不会在同一毫秒重试而再次撞 RRL。
                        await asyncio.sleep(delay + random.uniform(0.0, 0.05))
                    try:
                        result = await self._get_trusted_dnskey_uncached(zone_name)
                        last_error = None
                        break
                    except _ChainUnavailable as e:
                        last_error = e
                        self._clear_ds_cache_for_chain(zone_name)
                        logger.debug(
                            "DNSSEC 链暂时不可用（attempt=%d/%d），退避后重试: "
                            "%s: %s", attempt + 1, len(delays) + 1,
                            _safe_qname(zone_name), e,
                        )
                if last_error is not None:
                    if len(retry_after) > 512:
                        retry_after.clear()
                    retry_after[key] = time.time() + 15.0
                    if len(self._chain_unavailable) > 512:
                        self._chain_unavailable.clear()
                    self._chain_unavailable.add(key)
                    self._stats["chain_unavailable"] = (
                        self._stats.get("chain_unavailable", 0) + 1)
                    logger.debug(
                        "DNSSEC 链暂时不可用（15s 负缓存，非 bogus）: %s: %s",
                        _safe_qname(zone_name), last_error,
                    )
                    result = None
                else:
                    # 成功（或确定性地 insecure / 验证失败）→ 清掉失败标记
                    retry_after.pop(key, None)
                    self._chain_unavailable.discard(key)
        except asyncio.CancelledError:
            if not fut.done():
                fut.set_result(None)
            self._dnskey_inflight.pop(key, None)
            raise
        except Exception:
            if not fut.done():
                fut.set_result(None)
            self._dnskey_inflight.pop(key, None)
            return None
        if not fut.done():
            fut.set_result(result)
        self._dnskey_inflight.pop(key, None)
        return result

    async def warmup_dnssec_chain(self) -> None:
        """启动后台预热根区 DNSKEY，降低冷启动首个查询的链构建失败率。

        只预热根区：根 DNSKEY 是整条链的第一级，验证并缓存后，后续 TLD
        只需查自己的 DS/DNSKEY。预热失败不抛出、不影响服务（下一次查询
        仍会按重试/负缓存逻辑再试）。
        """
        try:
            await self._get_trusted_dnskey(dns.name.root)
        except Exception as e:
            logger.debug("DNSSEC 根区预热失败（不影响服务）: %s", e)

    async def _get_trusted_dnskey_uncached(
        self, zone_name: dns.name.Name
    ) -> Optional[dns.rrset.RRset]:
        """从内置 IANA 根信任锚出发，沿 DS→DNSKEY 链逐级数学验证，
        返回 zone 的已信任 DNSKEY RRset；任一级验证失败返回 None。

        信任链（RFC 4035）：
          根锚 KSK → 验证根区 DNSKEY（含 ZSK）→ ZSK 验证 TLD 的 DS 签名
          → DS digest 匹配 TLD DNSKEY → TLD ZSK 验证子域 DS → ... → zone DNSKEY
        中间人即使伪造 DNSKEY/DS 响应，没有父区私钥就无法通过签名验证。
        """
        # 根区没有父区（DS 链为空），但仍需"用内置根锚验证根 DNSKEY"再返回，
        # 因此不再提前返回 None；否则调用方拿不到根密钥，root 签名的 NSEC/
        # RRset 无法验证 → 合法响应被误判 bogus。
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
            raise _ChainUnavailable("根区 DNSKEY 查询失败")
        root_dnskey_rrset = self._extract_dnskey_rrset(root_dnskey_resp)
        if root_dnskey_rrset is None:
            raise _ChainUnavailable("根区 DNSKEY 响应不含 DNSKEY（上游返回不完整）")
        root_rrsig = self._find_rrsig_for(root_dnskey_resp, root_dnskey_rrset)
        if root_rrsig is None:
            return None
        try:
            dns.dnssec.validate(root_dnskey_rrset, root_rrsig, trusted)
        except ImportError as e:
            # 验签后端缺失不是“验证失败/bogus”：标记链不可用，让上层按
            # unknown 处理（不得据此判 secure，也不得丢弃为伪造）。
            logger.error("DNSSEC 根区 DNSKEY 无法验签：%s", e)
            raise _ChainUnavailable(
                "DNSSEC 验签后端不可用（请安装 cryptography）") from e
        except (dns.dnssec.ValidationFailure, KeyError) as e:
            self._warn_dnssec_once("root_dnskey", ".", "DNSSEC 根区 DNSKEY 验证失败: %s", e)
            return None
        trusted[dns.name.root] = root_dnskey_rrset  # 含 ZSK，供后续验证子区 DS
        # 根 DNSKEY 已验证：立即入缓存，避免每个新域名都重查一次 ". DNSKEY"
        try:
            if len(self._verified_zone_cache) > 512:
                self._verified_zone_cache.clear()
            self._verified_zone_cache["."] = (
                root_dnskey_rrset,
                time.time() + float(getattr(root_dnskey_rrset, "ttl", 3600) or 3600),
            )
        except Exception:
            pass

        # 3. 逐级向下的祖先路径：TLD → ... → zone
        path = []
        n = zone_name
        while n != dns.name.root:
            path.append(n)
            n = n.parent()
        path.reverse()

        for cur_zone in path:
            # 3a+3b 并行：DS 由父区权威持有、DNSKEY 由本区权威持有，两者互不依赖
            # （3c 才用 DS 校验 DNSKEY），并发可以把这一级的两个 RTT 合成一个。
            # 境内外 TLD 权威 RTT 常 200-300ms，这一项对首次解析很显著。
            ds_resp, dnskey_resp = await asyncio.gather(
                self._iterate_ds_cached(cur_zone),
                self._iterate(str(cur_zone), dns.rdatatype.DNSKEY, 0),
            )
            if ds_resp is None:
                # 查询失败 ≠ 无 DS（insecure）：不能据此判 bogus，也不能当作
                # insecure（那是反向伪造面）→ 抛「暂时不可用」交给上层重试/降级
                raise _ChainUnavailable(f"{_safe_qname(cur_zone)} 的 DS 查询失败")
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
                self._warn_dnssec_once("ds_sig", cur_zone,
                                       "DNSSEC DS 验证失败 %s: %s",
                                       _safe_qname(cur_zone), e)
                return None
            # 3b. cur_zone 的 DNSKEY（已在上面的 gather 中并发取回）
            if dnskey_resp is None:
                raise _ChainUnavailable(f"{_safe_qname(cur_zone)} 的 DNSKEY 查询失败")
            dnskey_rrset = self._extract_dnskey_rrset(dnskey_resp)
            if dnskey_rrset is None:
                raise _ChainUnavailable(
                    f"{_safe_qname(cur_zone)} 的 DNSKEY 响应不含 DNSKEY（上游返回不完整）")
            # 3c. 用已验证 DS 的 digest 匹配 DNSKEY —— **收集全部**匹配的 key。
            #     父子区在 KSK 轮换窗口内会同时发布两条 DS（旧 KSK + 新 KSK），
            #     而 DNSKEY RRset 的自签 RRSIG 只由其中一把签发；更麻烦的是
            #     权威返回的 DS 顺序**不固定**（同一 zone 连续两次查询可能顺序
            #     相反）。只取"第一个匹配到的 key"就会在约一半情况下拿到没签
            #     自签的那把 → dns.dnssec 抛 "no RRSIGs validated" → 误判 bogus
            #     + 每次查询一条告警刷屏。
            #     实测 sc.：DS={2539, 35612}，RRSIG(DNSKEY) 由 35612 签发，
            #     DS 顺序为 [2539,35612] 时旧逻辑必然失败、[35612,2539] 时才成功。
            #     安全性不变：能进入 trusted 的 key 必须匹配**已验签**的 DS，
            #     攻击者自造的 key 拿不到 DS digest，仍被拒绝。
            auth_keys = []
            for key_rdata in dnskey_rrset:
                for ds in ds_rrset:
                    if self._ds_matches_key(ds, cur_zone, key_rdata):
                        auth_keys.append(key_rdata)
                        break
            if not auth_keys:
                self._warn_dnssec_once(
                    "ds_mismatch", cur_zone,
                    "DNSSEC DS/DNSKEY digest 不匹配: %s（伪造 DNSKEY 被拦截）",
                    _safe_qname(cur_zone))
                return None
            # 3d. 用 DS 授权的 key 验证 DNSKEY rrset 自身的 RRSIG（signer=cur_zone，
            #     KSK 与 ZSK 可同时签名）→ 证明该 DNSKEY 集合完整可信（含 ZSK）
            dnskey_rrsig = self._find_rrsig_for(dnskey_resp, dnskey_rrset)
            if dnskey_rrsig is None:
                return None
            ksk_rrset = dns.rrset.RRset(cur_zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            for key_rdata in auth_keys:
                ksk_rrset.add(key_rdata)
            try:
                dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {cur_zone: ksk_rrset})
            except (dns.dnssec.ValidationFailure, KeyError) as e:
                self._warn_dnssec_once(
                    "dnskey_selfsig", cur_zone,
                    "DNSSEC DNSKEY 自签验证失败 %s: %s", _safe_qname(cur_zone), e)
                return None
            # 3e. 该级验证通过 → 信任整个 DNSKEY rrset（含 ZSK），作为下一级的信任来源
            trusted[cur_zone] = dnskey_rrset
            # 同时缓存这一级：同一次查询里多个 signer（如 com. 与 baidu.com.）
            # 会各自重做完整链条，逐级缓存后第二次直接命中（实测省 300-600ms）
            try:
                if len(self._verified_zone_cache) > 512:
                    self._verified_zone_cache.clear()
                self._verified_zone_cache[str(cur_zone).lower()] = (
                    dnskey_rrset,
                    time.time() + float(getattr(dnskey_rrset, "ttl", 3600) or 3600),
                )
            except Exception:
                pass

        # 结果：zone 自身的 DNSKEY rrset（zone==root 时即第 2 步用根锚验证过的根密钥）
        result_rrset = trusted.get(zone_name) or root_dnskey_rrset        # 缓存已验证 zone 的 DNSKEY（有界：超 512 条清空，避免内存膨胀；
        # 失效时间 = 当前时间 + DNSKEY rrset TTL，DNSKEY 轮换后自动重新验证）
        if len(self._verified_zone_cache) > 512:
            self._verified_zone_cache.clear()
        ttl = getattr(result_rrset, "ttl", 3600) or 3600
        self._verified_zone_cache[str(zone_name).lower()] = (result_rrset, time.time() + ttl)
        return result_rrset

    async def _dnssec_query_callback(self, query_bytes: bytes) -> Optional[bytes]:
        """DNSSECValidator 的 DNSKEY 查询回调：迭代查询 DNSKEY 并做 DS 链验证。
        仅返回经过数学信任链验证的 DNSKEY 响应（防止伪造 DNSKEY + 重签名绕过）。"""
        try:
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
                    return None
                ns_resp.id = msg.id
                return ns_resp.to_wire()
            # 链验证获取可信 DNSKEY（若已缓存直接命中）
            verified_rrset = await self._get_trusted_dnskey(zone)
            if verified_rrset is None:
                self._warn_dnssec_once(
                    "chain", zone,
                    "DNSSEC 链验证失败，拒绝信任 %s 的 DNSKEY", _safe_qname(zone))
                return None
            # 必须返回**原始 DNSKEY 响应（含 RRSIG）**，不能只构造一个
            # 仅含 DNSKEY rrset 的响应：调用方 DNSSECValidator._query_rrset_ex()
            # 需要按 covers=DNSKEY 找 RRSIG 才能继续验签；旧实现丢掉 RRSIG，
            # 导致 _get_verified_zone_keys() 永远 indeterminate（require_rrsig
            # 路径因此完全失效）。
            raw = await self._iterate(str(zone), dns.rdatatype.DNSKEY, 0)
            if raw is None:
                return None
            raw_rrset = self._extract_dnskey_rrset(raw)
            if raw_rrset is None:
                return None
            if ({str(rd) for rd in raw_rrset}
                    != {str(rd) for rd in verified_rrset}):
                # 原始响应的 DNSKEY 与已验签集合不一致 → 拒绝（防掉包）
                return None
            raw.id = msg.id
            return raw.to_wire()
        except Exception:
            return None

    # ---------- 公开入口 ----------

    # NSEC/NSEC3 类型位图解析复用 dnssec.py 的唯一实现。
    _nsec_has_type = staticmethod(DNSSECValidator._nsec_has_type)

    # NSEC3 原语统一使用 dnssec.DNSSECValidator 的实现（iterations 上限 150
    # 也在那里），避免 plain_dns_server 与 dnssec.py 各写一份、行为不一致。
    _nsec3_hash = staticmethod(DNSSECValidator._nsec3_hash)

    # NSEC3 owner-hash 解码同样复用 dnssec.py 的唯一实现。
    _nsec3_owner_hash = staticmethod(DNSSECValidator._nsec3_owner_hash)

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

    # 区间覆盖语义与 dnssec.py 的 _hash_in_interval 完全一致（含自指保护）；
    # 不再在 plain_dns_server 里复制一份边界判断。
    _nsec3_interval_check = staticmethod(DNSSECValidator._hash_in_interval)

    # Opt-Out 位解析复用 dnssec.py 的实现。
    _nsec3_optout = staticmethod(DNSSECValidator._nsec3_optout)

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

    async def _parent_is_insecure(self, name: dns.name.Name) -> bool:
        """父区是否已被证明为未签名（insecure）。

        DNSSEC 是逐区 opt-in：父区未签名时，子区/委托点不可能通过 DS 链
        获得签名信任（没有父区 DS）。此时子区 NSEC/NSEC3 否定证明本来
        就不存在，不能因为“没有证明”判 unknown 丢弃——应直接判 insecure。
        典型：services.mozilla.com（父区 mozilla.com 未签名）、
        opencdn*.jomodns.com（父区 jomodns.com 未签名）。
        """
        try:
            if name == dns.name.root:
                return False
            return await self._zone_signed_status(name.parent()) == "insecure"
        except Exception:
            return False

    async def _is_delegation(self, name: dns.name.Name) -> Optional[bool]:
        """name 是否是父区的委托点（父区存在 owner==name 的 NS 记录）

        为什么需要它：DS 查询返回 NODATA 时，响应里的 SOA owner 只说明
        “哪个区回答了这次查询”，无法区分 name 是「该区的委托子区」还是
        「该区内的普通名」（两者的 SOA owner 都等于 name.parent()）。
        而这两者的后续处理完全相反：
          - 委托子区：DS 由父区持有；父区无 DS 且无否定证明 = 无法证明，
            必须停在 name，绝不能升到父区把父区自己的 DS 当成 name 已签名；
          - 区内普通名：DS 本来就不存在，必须继续升到所在区 apex 再判断。

        判定方式：向 name 查 NS。委托点的 NS 由父区 referral/子区 apex 返回，
        owner 等于 name；普通名返回 NODATA（没有 owner==name 的 NS）。
        优先复用 `_zone_ns_cache`（解析过程中已缓存的 referral），避免额外 RTT。
        返回 True/False/None（查询失败，无法判定）。
        """
        key = str(name).lower()
        cached = self._delegation_cache.get(key)
        if cached is not None and time.time() < cached[1]:
            return cached[0]
        # 解析过程中已缓存过该区的权威 → 它一定是被委派的区
        ent = self._zone_ns_cache.get(key)
        if ent is not None and time.time() < ent[1] and ent[0]:
            self._delegation_cache[key] = (True, time.time() + 300)
            return True
        try:
            resp = await self._iterate(str(name), dns.rdatatype.NS, 0)
        except Exception:
            resp = None
        if resp is None:
            return None
        result = False
        try:
            for section in (resp.answer, resp.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.NS and rrset.name == name:
                        result = True
                        break
                if result:
                    break
        except Exception:
            return None
        if len(self._delegation_cache) > 2048:
            self._delegation_cache.clear()
        self._delegation_cache[key] = (result, time.time() + 300)
        return result

    async def _retry_ds_once(self, name: dns.name.Name) -> Optional[dns.message.Message]:
        """清掉 name 的 DS 缓存并重查一次（争取拿到父区的 NSEC/NSEC3 否定证明）

        某些权威在限速/精简响应时会返回不带 DNSSEC 记录的 NODATA（只有 SOA），
        这不是“该名字没有 DS”的数学证明。重查一次通常能拿到完整否定证明；
        仍拿不到时由调用方按 unknown 处理，不得升父级或判 secure。
        """
        key = str(name).lower()
        self._ds_cache.pop(key, None)
        self._ds_inflight.pop(key, None)
        try:
            return await self._iterate_ds_cached(name)
        except Exception:
            return None

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
            ds_resp = await self._iterate_ds_cached(n)
            if ds_resp is None:
                # 查询失败 ≠ 无法证明：DS 查询超时/失败时不能据此判定
                # 「无法确认应答未被篡改」，否则冷启动（DNSSEC 链缓存尚未建立）
                # 会把本可解析的域名整片丢弃（纯迭代模式没有加密上游兜底，
                # 表现为「部分站点完全打不开」）。交由上层按 insecure 放行并记日志。
                # 但若父区已被证明未签名，则本名字一定在未签名树下：
                # 直接判 insecure，避免 CNAME 链/owner 检查把 error 当丢弃。
                if await self._parent_is_insecure(n):
                    return "insecure"
                return "error"
            # DS 存在 → 签名委托
            if any(rrset.rdtype == dns.rdatatype.DS for rrset in ds_resp.answer):
                return "secure"
            # NXDOMAIN：该名字不存在（区间证明）。不能无条件升父级——父区
            # 自己的 DS 只能证明父区签名，不能证明这个名字所在区签名；升上去
            # 会把“名字不存在”误判成 secure，进而输出“签名被剥离”的假告警。
            # 但也不能一律 unknown：DS 查询不跟随 CNAME，像 p.ssl.qhimg.com
            # 这类 CNAME 名的 DS 查询会返回 NXDOMAIN，而它实际位于未签名区
            # qhimg.com，必须继续升到所在区才能正确放行。因此仍按“是否委托点”
            # 区分：普通名 → 升父级；委托点/无法判定 → unknown（停）。
            if ds_resp.rcode() == dns.rcode.NXDOMAIN:
                is_del = await self._is_delegation(n)
                if is_del is False:
                    n = n.parent()
                    continue
                # 即使 n 看起来是委托点，只要父区已被证明未签名，n 一定
                # 在未签名树下（未签名区不发布 DS/NSEC3）。不能因为
                # “n 不存在且像委托点”就把 CDN 随机子域整片丢弃。
                # 实测 v9e169o.edge.mountaintoys.cn：_is_delegation 因
                # _zone_ns_cache 命中返回 True，父区 mountaintoys.cn 已
                # insecure，旧代码在这里直接 unknown → 严格模式丢弃；
                # 父区未签名时 DS NXDOMAIN 是合法的（该名字本就不存在）。
                if await self._parent_is_insecure(n):
                    return "insecure"
                return "unknown"
            # 无 DS：仅当该名字是 zone apex（响应 SOA owner == 查询名）且父区用
            # NSEC/NSEC3 否定记录 + 有效签名证明"该 apex 委托无 DS" 才判 insecure。
            # 非 apex 名（如 www.example.com）的 DS 查询返回 NODATA 是其所在区
            # 的否定，不代表该名未签名——须升父级继续。
            # 判断 n 是否是 zone apex（父区的委托点）：DS 记录只存在父区，
            # DS 查询恒由父区权威回答（authority SOA owner 是父区，非 n）。
            # 正确判据：响应的 NSEC/NSEC3 RRSIG signer == n.parent()（父区签名
            # 否定该名无 DS）→ n 是父区的委托点/apex。若响应无 NSEC（纯 NODATA
            # SOA，signer 是父区），n 是父区内普通名 → 升父级。
            has_nsec = any(
                rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                for section in (ds_resp.answer, ds_resp.authority)
                for rrset in section
            )
            if not has_nsec:
                # 无 NSEC/NSEC3 否定证明：这是本次误报的关键分支。
                #
                # 旧逻辑在这里直接 n=n.parent()，于是 OpenCDN/360 这类
                # “父区（.com/.cn）有 DS、子区本来未签名”的域名会一路升到
                # 父区，把父区自己的 DS 当成“子区已签名”，最终输出
                # “该域名所在区域已启用 DNSSEC 但应答无 RRSIG → 签名被剥离”。
                # 实际上子区根本没有 DS，应答合法。
                #
                # 正确语义：先判断 n 是「父区的委托点」还是「当前区内的普通名」。
                #   - 委托点：父区无 DS 且没有否定证明 = 无法证明，返回 unknown，
                #     绝不能升父级（父区 DS 与它无关）；
                #   - 普通名：DS 本来就不存在，必须升到所在区 apex 再判断。
                # 某些权威限速/精简响应时会把带 DO 的 NODATA 退化成“只有 SOA”，
                # 这时先重查一次，争取拿到完整否定证明（通常换一台权威即可）。
                is_del = await self._is_delegation(n)
                if is_del is True:
                    retry_resp = await self._retry_ds_once(n)
                    if retry_resp is not None:
                        ds_resp = retry_resp
                        has_nsec = any(
                            rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                            for section in (ds_resp.answer, ds_resp.authority)
                            for rrset in section
                        )
                    if not has_nsec:
                        # 委托点没有父区否定证明：如果父区本身已被证明
                        # 未签名，那么本区一定也在未签名树下（不可能有 DS），
                        # 直接判 insecure；只有父区签名时才真的“无法证明”。
                        if await self._parent_is_insecure(n):
                            return "insecure"
                        return "unknown"
                elif is_del is False:
                    n = n.parent()
                    continue
                else:
                    # 连“是否委托点”都无法判定：先看父区是否未签名
                    if await self._parent_is_insecure(n):
                        return "insecure"
                    return "unknown"
            is_apex = False
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
                parent_keys = None
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
                                       self._nsec3_interval_check(
                                           th3, oh3, rdata.next):
                                        # RFC 5155 §8.6：opt-out 区间覆盖证明
                                        # “区间内可能存在被省略的未签名委托”，
                                        # **不要求**覆盖记录位图含 NS（位图描述
                                        # 的是 owner 名，不是被覆盖的委托名）。
                                        # 非 opt-out 的区间覆盖才是 NXDOMAIN
                                        # 证明，不能拿来推断 DS NODATA。
                                        if self._nsec3_optout(rdata):
                                            nsec_valid = True
                                        elif self._nsec_has_type(
                                                rdata, dns.rdatatype.NS) and \
                                             not self._nsec_has_type(
                                                rdata, dns.rdatatype.DS):
                                            nsec_valid = True
                except Exception:
                    nsec_valid = False
                if nsec_valid:
                    return "insecure"  # opt-out 委托点无 DS → 未签名区
                if parent_keys is None:
                    # 父区 DNSKEY 取不到（验签后端缺失 / 链查询失败）：
                    # 无法验证否定证明。若父区已证明未签名，则本名字一定
                    # 在未签名树下；否则绝不能升父级把父区 DS 当 secure。
                    #
                    # 返回 "error" 而不是 "unknown"：这是**本机取不到父区
                    # DNSKEY**（链暂时不可用），不是“应答缺少否定证明”。
                    # 两者必须区分：unknown 会被调用方判为可丢弃，冷启动
                    # （根/TLD DNSKEY 查询限速/超时）会把合法未签名域名整片
                    # 丢弃（实测 mountaintoys.cn 的 CDN 子域 60 秒被丢 86 次）；
                    # error 与 `_iterate_ds_cached` 查询失败同级，按可用性放行。
                    if await self._parent_is_insecure(n):
                        return "insecure"
                    return "error"
                is_del = await self._is_delegation(n)
                if is_del is False:
                    # n 只是当前区内的普通名：DS 本来就不存在，升到所在区 apex
                    n = n.parent()
                    continue
                # n 是委托点（或无法判定）：有 NSEC 但语义不成立 → 无法证明
                if await self._parent_is_insecure(n):
                    return "insecure"
                return "unknown"
            if has_nsec:
                # 验证 NSEC/NSEC3 的 RRSIG（父区 DNSKEY 签名）且语义正确：
                # NSEC owner 必须等于被查名 target 且类型位图不含 DS
                # （防重放父区公开有效 NSEC——签名有效但区间不覆盖——伪造 insecure）
                nsec_valid = False
                parent_keys = None
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
                if parent_keys is None:
                    # 父区 DNSKEY 取不到（链暂时不可用）：与上面的 3122 分支
                    # 同一语义，返回 error 而不是 unknown——否则冷启动时会把
                    # 合法未签名域名当成“可能被篡改”丢弃。
                    if await self._parent_is_insecure(n):
                        return "insecure"
                    return "error"
                # NSEC 签名验证失败或语义不符 → 无法证明（剥离/重放风险）
                return "unknown"
            # 理论上不可达（无证明已在上面处理）；保守返回 unknown，
            # 不再盲目升父级（父区 DS 不能证明本名字所在区签名）。
            return "unknown"
        return "unknown"

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
                await self._get_trusted_dnskey(zone)
            except Exception as e:
                logger.debug("迭代预热 %s 失败: %s", zone, e)
        logger.info(
            "迭代解析预热完成: 已验证 zone %d 个（DNSKEY/DS 已缓存）",
            len(self._verified_zone_cache),
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

    async def _resolve_verified(self, qname: str, qtype: int, rdclass: int) -> Optional[dns.message.Message]:
        """resolve 的内部实现：迭代 + DNSSEC 严格验证（受外层 total_timeout 约束）。

        注：曾尝试"主链与 DNSSEC 链并行预取"（预取根/TLD/父区的 DS+DNSKEY），
        实测反而更慢：baidu 1319→1498ms、qq 1852→2145ms。原因是预取与主链
        访问同一批境外权威、共享同一个阻塞线程池，竞争成本大于重叠收益；
        且 baidu.com/qq.com 这类未签名区预取是纯浪费。故保留串行（配合
        DS/DNSKEY 并行 + DS 缓存 + 启动 warmup 已足够）。
        """
        try:
            # 每个域名解析入口重置"本次解析禁用 IPv6"标记（per-query 语义）
            _V6_DISABLED_CTX.set(False)
            self._last_release = ""
            resp = await self._iterate(qname, qtype, 0, rdclass)
            # CDN 调度域名兜底：迭代拿不到最终答案时，用 bootstrap DNS 递归一次。
            # 典型场景：bilibili 的 i1/s2/s3/static.hdslb.com → CNAME 到腾讯
            # 调度域名（*.tdnsv5.com），其权威对迭代查询直接返回 NODATA
            # （实测 1.12.0.17 等：NOERROR/answer=0），只有递归服务器能拿到 A。
            # 纯迭代模式下这类域名必然解析失败（图床/静态资源全挂），
            # 因此仅在「没有 qtype 记录且非 NXDOMAIN」时兜底一次。
            if self._needs_bootstrap_fallback(resp, qtype):
                fb = await self._bootstrap_recursive(qname, qtype, rdclass)
                if fb is not None and fb.answer:
                    fb._bootstrap_fallback = True
                    # 兜底响应**不再直接返回**：与迭代响应走同一套 DNSSEC 校验。
                    # 兜底用的是明文 bootstrap DNS（UDP，无加密、无认证），若原样
                    # 放行，攻击者只需污染 bootstrap 应答即可向签名区注入伪造记录、
                    # 绕过整条 strict_dnssec 信任链（真实的降级攻击面）。
                    # 因此：带 RRSIG → 正常链验签；无 RRSIG → 按区域 DNSSEC 状态
                    # 判定（签名区拒绝，未签名/无法证明时按可用性兜底放行）。
                    resp = fb
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
                # 无 RRSIG：防剥离攻击。
                #
                # ★ 判定必须按**应答里每个 RRset 自己的 owner** 所在区的 DS 状态，
                #   不能只看 qname（实测误判：c.pki.goog 的 qname 所在 pki.goog
                #   有 DS = secure，但它是 CNAME 到 pki-goog.l.google.com
                #   （l.google.com 无 DS = insecure），最终 A 记录没有 RRSIG
                #   完全合法 —— 旧逻辑只看 qname 就判"签名被剥离"并丢弃，
                #   日志里出现"该域名所在区域已启用 DNSSEC，但应答里完全没有
                #   数字签名"这种与实际不符的描述）。
                #
                #   逐 owner 判定同时保住安全性：攻击者若剥掉签名并伪造
                #   「qname CNAME 到未签名区」，CNAME 的 owner 仍是 qname、
                #   仍在 secure 区 → 依旧判剥离拒绝（见下方 _stripped_owners）。
                _owner_status = []
                try:
                    _targets = [rr.name for rr in resp.answer
                                if rr.rdtype != dns.rdatatype.RRSIG]
                except Exception:
                    _targets = []
                if not _targets:
                    # 空应答（NODATA/NXDOMAIN）：退回按 qname 判定，
                    # 与"否定证明必须被签名"的既有语义一致
                    try:
                        _targets = [dns.name.from_text(qname)]
                    except Exception:
                        _targets = []
                _seen = set()
                for _nm in _targets:
                    _k = str(_nm).lower()
                    if _k in _seen:
                        continue
                    _seen.add(_k)
                    try:
                        _zs = await self._zone_signed_status(_nm)
                    except Exception:
                        _zs = "unknown"
                    _owner_status.append((_nm, _zs))

                _stripped_owners = [(n, s) for n, s in _owner_status if s == "secure"]
                _unknown_owners = [(n, s) for n, s in _owner_status if s == "unknown"]
                _insecure_owners = [(n, s) for n, s in _owner_status if s in ("insecure", "error")]

                if _stripped_owners:
                    # 有 RRset 的 owner 明确位于签名区却没有签名 → 剥离攻击
                    #
                    # ★ 例外：bootstrap 递归兜底响应。迭代失败时（冷启动/权威不可达）
                    #   会用明文 bootstrap 递归兜底，那份应答本来就不带 RRSIG，
                    #   不能按"签名被剥离"丢弃 —— 否则第一次 attempt 必然 bogus
                    #   （实测 c.pki.goog 冷启动：_iterate 返回 None → 兜底拿到
                    #   含 CNAME 的未签名应答 → owner 在 pki.goog(secure) → 误判
                    #   剥离 + 打 WARNING，靠后面的重试才成功）。与下方 unknown
                    #   分支对兜底响应的处理保持一致。
                    if getattr(resp, "_bootstrap_fallback", False):
                        self._stats["insecure"] += 1
                        self._stats["success"] += 1
                        logger.debug(
                            "DNSSEC: bootstrap 兜底响应无签名（迭代失败后的可用性兜底）"
                            ": %s，按可用性放行（未经验签）", _safe_qname(qname))
                        self._last_release = "bootstrap"
                        return resp
                    self._stats["bogus"] += 1
                    self._report_dnssec_stripped(qname)
                    self._invalidate_zone_cache(qname)
                    return None
                if _insecure_owners and not _unknown_owners:
                    self._stats["insecure"] += 1
                    self._stats["success"] += 1
                    return resp
                if _unknown_owners and not _insecure_owners:
                    # unknown：既没有签名、也没有"该域名本就未签名"的证明。
                    # 例外：bootstrap 递归兜底响应。兜底本身是可用性措施（迭代对
                    # 某些 CDN 调度域名只回 NODATA），若把它一并丢弃，这类域名在
                    # 纯迭代模式下就永远 SERVFAIL；而能走到这里说明区域状态
                    # **无法证明**（secure 已在上面拒绝），因此放行并留 debug。
                    if getattr(resp, "_bootstrap_fallback", False):
                        self._stats["insecure"] += 1
                        self._stats["success"] += 1
                        logger.debug(
                            "DNSSEC: bootstrap 兜底响应无签名、区域状态无法证明: %s，"
                            "按可用性放行（未经验签）", _safe_qname(qname))
                        self._last_release = "bootstrap"
                        return resp
                    self._stats["bogus"] += 1
                    self._report_unsigned_unknown(qname)
                    self._invalidate_zone_cache(qname)
                    return None

                # 混合：部分 owner 已证明未签名（insecure/error），其余无法证明
                # （unknown）。没有 secure owner → 不是剥离攻击；按可用性放行
                # 并留 debug（与 `answer_unsigned` 分支对 insecure/error 的放行
                # 策略一致，不新增攻击面：攻击者同样只能靠阻断 DS 查询触发）。
                self._stats["insecure"] += 1
                self._stats["success"] += 1
                logger.debug(
                    "DNSSEC: %s 无 RRSIG，各 owner 状态混合"
                    "（已证明未签名 %d 个 / 无法证明 %d 个）→ 按可用性放行",
                    _safe_qname(qname), len(_insecure_owners), len(_unknown_owners))
                return resp

            # 对每个 signer 做链验证，收集可信 keys（{signer: DNSKEY RRset}）
            #
            # **并行**（2026-10-30）：CNAME 链常跨 2-3 个签名区（例：
            # rockstargames.com → edgekey.net → akamaiedge.net，或
            # bilibili → bilivideo），原实现挨个 await，每级 DNSKEY/DS 各一次
            # 迭代（30-300ms），串行累加就是主要的冷解析延迟。
            # `_get_trusted_dnskey` 自带缓存 + single-flight，并发调用安全：
            # 同一 zone 的多个 signer 只会真的查一次。
            trusted_keys: Dict = {}
            # 父区无 DS（insecure 委托）的签名者：其 RRSIG 无法也无需验证
            insecure_signers: set = set()
            # 链「暂时不可用」（查询失败，重试也没成功）的签名者：不判 bogus
            chain_unavailable_signers: set = set()
            _signer_list = list(signers)
            _keys_results = await asyncio.gather(
                *[self._get_trusted_dnskey(s) for s in _signer_list],
                return_exceptions=True,
            )
            for signer, _rrset in zip(_signer_list, _keys_results):
                if isinstance(_rrset, BaseException):
                    _rrset = None
                if signer == dns.name.root:
                    # 根区密钥来自内置信任锚（RFC 4033 §6）：用根锚验证根 DNSKEY 后
                    # 才能验签 root 签名的 RRset。之前直接 continue 会让 trusted_keys
                    # 缺 root → 验签 KeyError → 合法响应被误判 bogus（可用性缺陷）。
                    if _rrset is None:
                        self._stats["bogus"] += 1
                        self._warn_dnssec_once(
                            "root_signer", ".",
                            "DNSSEC 根区 DNSKEY 验证失败，拒绝签名响应")
                        return None
                    trusted_keys[signer] = _rrset
                    continue
                if _rrset is None:
                    if str(signer).lower() in getattr(self, "_chain_unavailable", ()):
                        # 链暂时不可用（DS/DNSKEY 查询失败且重试失败）= 这次没取到
                        # 证据，不是伪造。按可用性放行，不判 bogus、不告警
                        # （与 _zone_signed_status 返回 "error" 时的策略一致）。
                        chain_unavailable_signers.add(signer)
                        continue
                    # 链上取不到 key 要先分清原因：
                    #   * 父区**没有 DS**（insecure 委托）→ 该区本来就不在 DNSSEC
                    #     信任链上，RFC 4035 §5.2 要求把它当「未签名」处理。
                    #     Cloudflare 等托管商默认给区签名、但域名没在注册商提交
                    #     DS 时就是这种 island of security（实测 netsarang.net.：
                    #     Cloudflare 签、net. 用 NSEC3 证明无 DS）。旧实现一律判
                    #     bogus 并拒绝 → 这类域名全部失效 + 每查询一条警告。
                    #   * 父区**有 DS** 但链验证失败 → 真 bogus（伪造/过期），拒绝。
                    try:
                        zs = await self._zone_signed_status(signer)
                    except Exception:
                        zs = "unknown"
                    if zs in ("insecure", "error"):
                        # insecure：父区无 DS（数学证明）；error：DS 查询失败。
                        # 两者都无权要求验签，按未签名处理（与下方"无 RRSIG"分支
                        # 对 insecure/error 的放行策略保持一致，不新增攻击面：
                        # 攻击者同样可以让 DS 查询失败来触发这条放行）。
                        insecure_signers.add(signer)
                        logger.debug(
                            "DNSSEC: %s 的父区无 DS（%s）→ 其签名按未签名处理"
                            "（RFC 4035 §5.2），不判 bogus", _safe_qname(signer), zs)
                        continue
                    self._stats["bogus"] += 1
                    self._warn_dnssec_once(
                        "signer_chain", signer,
                        "DNSSEC 链验证失败，拒绝 %s 的签名响应", _safe_qname(signer))
                    self._invalidate_zone_cache(qname)
                    return None
                trusted_keys[signer] = _rrset

            if chain_unavailable_signers:
                # 有签名者的链因查询失败而暂时无法验证：整条响应按可用性放行
                # （不设 AD 位），与 `_zone_signed_status == "error"` 同策略。
                # 注意：这里**不**判 bogus、不打 WARNING —— 不能把"没取到证据"
                # 说成"检测到伪造"。
                self._stats["insecure"] += 1
                self._stats["success"] += 1
                logger.debug(
                    "DNSSEC: %s 的签名者链暂时不可用（查询失败，非伪造）→ 放行: %s",
                    _safe_qname(qname),
                    ",".join(sorted(_safe_qname(s) for s in chain_unavailable_signers)),
                )
                self._last_release = "chain_unavailable"
                return resp

            if insecure_signers:
                # 标记报文：`_find_rrsig_for` 会据此忽略这些未签名区的签名，
                # 后续所有验签 / 否定证明 / CNAME 中间跳分支统一按「该 RRset
                # 没有签名」处理，走既有的 DS 状态判定（insecure 放行）。
                # 不需要改写报文本身（dnspython 2.8 的 Message 没有 delete_rrset），
                # 客户端仍能拿到原始 RRSIG。
                resp._insecure_signers = insecure_signers
                for cm in cname_chain_msgs:
                    cm._insecure_signers = insecure_signers
                logger.debug(
                    "DNSSEC: %s 的签名者位于未签名区（%s，父区无 DS）"
                    "→ 按 RFC 4035 §5.2 视作未签名处理",
                    _safe_qname(qname),
                    ",".join(sorted(_safe_qname(s) for s in insecure_signers)),
                )

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
                                "DNSSEC CNAME 链中间跳无签名（%s）: %s", zs, _safe_qname(rrset.name))
                            self._invalidate_zone_cache(qname)
                            return None
                        continue  # 未签名区 CNAME 无签名是合法的
                    try:
                        dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                    except (dns.dnssec.ValidationFailure, KeyError) as e:
                        self._stats["bogus"] += 1
                        logger.warning("DNSSEC CNAME 链中间跳签名验证失败 %s: %s",
                                       _safe_qname(rrset.name), e)
                        self._invalidate_zone_cache(qname)
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
                                "证明: %s", _safe_qname(rrset.name),
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
                        _safe_qname(rrset.name),
                    )
                    return None
                if rrset.name not in legal_owners:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC answer owner 不匹配（重放攻击）: %s 不属于 %s 的合法链",
                        _safe_qname(rrset.name), _safe_qname(qname),
                    )
                    return None
                rrsig_set = self._find_rrsig_for(resp, rrset)
                if rrsig_set is None:
                    answer_unsigned.append(rrset)
                    continue
                # RFC 4035 §5.3.1：RRSIG.signer 必须是包含 RRset owner 的
                # zone apex；仅凭 signer 的 DNSKEY 验签不足以证明归属。
                try:
                    if not rrset.name.is_subdomain(rrsig_set[0].signer):
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC answer RRSIG signer 不覆盖 owner: %s signer=%s",
                            _safe_qname(rrset.name), rrsig_set[0].signer)
                        return None
                except Exception:
                    self._stats["bogus"] += 1
                    return None
                try:
                    dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                    answer_validated = True
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC answer 签名验证失败 %s (%s): %s",
                                   _safe_qname(rrset.name), rrset.rdtype, e)
                    return None

            if answer_unsigned:
                # answer 段某个 RRset 无 RRSIG：**不能一律判剥离攻击**——
                # CNAME 链常跨到未签名区（实测 www.ripe.net →
                # e337066.dscb.akamaiedge.net、c0.pki.goog →
                # www3.l.google.com：akamaiedge.net / l.google.com 本身无 DS =
                # insecure，无签名完全合法）。原实现把所有这类应答判成
                # "部分剥离攻击"直接丢弃，纯迭代模式无加密上游可回退 → 这些
                # 域名必 SERVFAIL（真实日志里的 c0.pki.goog 即此）。
                # 改为逐个按 owner 所在 zone 的 DS 状态判定（与"整个响应无
                # RRSIG"分支同一套判据，安全性不降级）：
                #   insecure → 合法未签名，放行该 RRset
                #   error    → DS 链查询失败（冷启动/权威不可达），按可用性放行
                #   secure   → 签名区被剥离 RRSIG，真实的降级攻击 → 拒绝
                #   unknown  → 无法证明，保守拒绝
                _stripped = []
                for rr in answer_unsigned:
                    try:
                        zs = await self._zone_signed_status(rr.name)
                    except Exception:
                        zs = "unknown"
                    if zs in ("insecure", "error"):
                        logger.debug(
                            "DNSSEC: %s 无 RRSIG，但所在区域判定为 %s → 按未签名放行",
                            _safe_qname(str(rr.name)), zs,
                        )
                        continue
                    _stripped.append(rr)
                if _stripped:
                    # 例外：bootstrap 兜底响应（明文递归、本来不带 RRSIG），
                    # 不能按剥离攻击丢弃 —— 与「完全无 RRSIG」分支同一策略
                    if getattr(resp, "_bootstrap_fallback", False):
                        self._stats["insecure"] += 1
                        self._stats["success"] += 1
                        logger.debug(
                            "DNSSEC: bootstrap 兜底响应部分 RRset 无签名: %s，"
                            "按可用性放行（未经验签）", _safe_qname(qname))
                        self._last_release = "bootstrap"
                        _stripped = []
                    else:
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC answer 段存在无签名 RRset（剥离攻击）: %s %s",
                            _safe_qname(qname), [str(r.name) for r in _stripped][:3],
                        )
                        return None

            if answer_unsigned and not answer_validated:
                # answer 段有数据但**全部**未签名，且上面已逐个确认它们所在区域
                # 是 insecure（或 DS 链查询失败按可用性放行）→ 这是「未签名区的
                # 正应答」，合法。典型：www.ripe.net → e337066.dscb.akamaiedge.net
                # （签名区 CNAME 到未签名 Akamai 区）、c0.pki.goog →
                # www3.l.google.com。**不能**再按负应答要求 SOA/NSEC 否定证明——
                # 正应答本来就没有，原逻辑会把它当"伪造负应答"丢弃。
                self._stats["insecure"] += 1
                self._stats["success"] += 1
                logger.debug(
                    "DNSSEC: %s 的正应答全部落在未签名区（%d 个 RRset），按 insecure 放行",
                    _safe_qname(qname), len(answer_unsigned),
                )
                return resp

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
                        # 关键：逐个 wildcard RRset 校验（循环内判定）——任一未证明即拒绝，
                        # 否则含多个 wildcard RRset 时只有最后一个被校验（重放绕过）。
                        if not wildcard_proven:
                            self._stats["bogus"] += 1
                            logger.warning(
                                "DNSSEC wildcard 响应缺 %s 无精确记录证明"
                                "（重放替代精确应答）: %s", _safe_qname(wc_target), _safe_qname(qname),
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
                        # CNAME 目标区**未签名**时，NODATA 本来就不会有
                        # NSEC/NSEC3（未签名区不发布否定证明）。此时缺 NSEC
                        # 是合法的，不能按“删除攻击”拒绝——实测
                        # ocsp.pki.goog AAAA → pki-goog.l.google.com
                        # （pki.goog 签名区 CNAME 到 google.com 未签名区），
                        # 8.8.8.8 返回 CNAME+RRSIG+SOA、无 NSEC，被误判。
                        # 目标区 secure / unknown 时仍保持拒绝（真正的删除
                        # 攻击或无法证明，不能放）。
                        tgt_status = await self._zone_signed_status(tgt_name)
                        if tgt_status in ("insecure", "error"):
                            self._stats["insecure"] += 1
                            self._stats["success"] += 1
                            logger.debug(
                                "DNSSEC CNAME 目标区未签名（%s），NODATA 无 NSEC "
                                "合法，放行: %s", tgt_status, _safe_qname(tgt_name),
                            )
                            return resp
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC answer 含 CNAME 但目标类型 %s 缺失且无签名 "
                            "NSEC NODATA 证明（删除攻击）: %s", qtype, _safe_qname(qname),
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
            # 是否有**任一** NSEC/NSEC3 的区间覆盖了被查名（根区例外判定用）
            nsec_covers_any = False
            has_nsec = False
            # SOA owner 必须是 qname 的权威 zone（qname 或祖先 apex）——
            # 防重放任意签名区真实 SOA+RRSIG 伪造任意域名 NODATA 空应答
            soa_owner_valid = False
            soa_owner_zone: Optional[dns.name.Name] = None
            qn = dns.name.from_text(qname)
            # **最终查询名**（2026-10-31）：负应答的 authority 段由**最后一级权威**
            # 产生。CNAME 跨区时（例：www.foo.com → edge.cdn.net，cdn.net 返回
            # NXDOMAIN），SOA owner 是 cdn.net，而 `qn` 仍是原始 www.foo.com——
            # 用 `qn` 找祖先会得到 None，于是后面所有 NSEC 都被判
            # 「NSEC signer 非 (无SOA) 权威 zone（跨区重放）」而整条拒绝
            # （实测同一秒刷 14 条 WARNING，对应某个跨区域名的 A/AAAA 反复重试）。
            # 这里改用 CNAME 链终点做祖先判定；**无 CNAME 时 qn_final == qn，
            # 与原有行为完全一致**，"重放任意区 SOA" 的防护仍然成立
            # （SOA owner 必须是 qn_final 的祖先）。
            qn_final = qn
            try:
                _targets = getattr(resp, "_cname_targets", None) or []
                if _targets:
                    qn_final = dns.name.from_text(str(_targets[-1]))
            except Exception:
                qn_final = qn
            # 后续所有 NSEC/NSEC3 否定证明与 closest-encloser 计算都针对
            # **最终查询名**（CNAME 链终点）——权威证明的是"终点不存在"，
            # 而不是原始查询名。无 CNAME 时两者相同，行为不变。
            qn = qn_final
            # RFC 6604 CNAME+NXDOMAIN：负应答 answer 段可能含 CNAME（指向不存在
            # 目标的链）——与正应答对称：answer 段 CNAME 有签名必验、无签名按
            # zone 状态拒绝（防攻击者在签名区负应答注入未签名 CNAME）。
            for rrset in resp.answer:
                if rrset.rdtype != dns.rdatatype.CNAME:
                    continue
                rrset_sig = self._find_rrsig_for(resp, rrset)
                if rrset_sig is None:
                    # 无签名：仅未签名区合法；secure/unknown 一律拒绝。
                    #
                    # ★ 这里把 "error"（DS 链查询超时/权威不可达）与正应答分支
                    #   （`answer_unsigned` 里的 `zs in ("insecure","error")`）
                    #   对齐：两者同一语义，冷启动第一次 DS 查询失败时若按 bogus
                    #   拒绝，负应答会被误判成"签名被剥离"（实测 c.pki.goog 这类
                    #   CNAME 到未签名区的名字，冷启动必然踩到）。
                    try:
                        zs_neg = await self._zone_signed_status(rrset.name)
                    except Exception:
                        zs_neg = "unknown"
                    if zs_neg not in ("insecure", "error"):
                        self._stats["bogus"] += 1
                        logger.warning(
                            "DNSSEC 负应答 answer CNAME 无签名（%s）: %s",
                            zs_neg, _safe_qname(rrset.name),
                        )
                        return None
                    continue
                try:
                    dns.dnssec.validate(rrset, rrset_sig, trusted_keys)
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC 负应答 answer CNAME 签名验证失败 %s: %s",
                                   _safe_qname(rrset.name), e)
                    return None
            for rrset in resp.authority:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                if rrset.rdtype == dns.rdatatype.SOA:
                    # SOA owner 必须是 qn_final（CNAME 链终点）的祖先**或等于**它。
                    # 用 is_subdomain 而不是手写 parent() 循环：**必须包含根区**——
                    # 根区负应答（不存在的 TLD，例如 Firefox 的
                    # smartblock.firefox.etp / .local / .invalid）的 SOA owner 就是
                    # 根 "."，原来 `while anc != dns.name.root` 把 root 排除在外，
                    # 导致 soa_owner_zone 恒为 None → 后面所有 NSEC 都被判
                    # 「NSEC signer 非 (无SOA) 权威 zone（跨区重放）」整条拒绝
                    # （实测同一秒刷 14 条 WARNING，对应 .etp 的 A/AAAA/HTTPS 反复重试）。
                    try:
                        if qn_final == rrset.name or qn_final.is_subdomain(rrset.name):
                            soa_owner_valid = True
                            soa_owner_zone = rrset.name
                    except Exception:
                        pass
                rrsig_set = self._find_rrsig_for(resp, rrset)
                if rrsig_set is None:
                    auth_unsigned.append(rrset)
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, trusted_keys)
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    self._stats["bogus"] += 1
                    logger.warning("DNSSEC authority 签名验证失败 %s (%s): %s",
                                   _safe_qname(rrset.name), rrset.rdtype, e)
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
                            "DNSSEC 负应答 NSEC signer 非 %s 权威 zone（跨区重放）— 拒绝: %s"
                            "（CNAME 终点 %s）",
                            soa_owner_zone if soa_owner_zone is not None else "(无SOA)",
                            _safe_qname(qname),
                            _safe_qname(str(qn_final)),
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
                                    nsec_covers_any = True
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
                                            _safe_qname(rrset.name), _safe_qname(soa_owner_zone),
                                        )
                                        continue
                                    owner_is_delegation = (
                                        self._nsec_has_type(rdata, dns.rdatatype.NS)
                                        and not self._nsec_has_type(
                                            rdata, dns.rdatatype.SOA)
                                    ) or self._nsec_has_type(rdata, dns.rdatatype.DS)
                                    # **qname 不在该委托点之下时，「委托」标记不适用**
                                    #（2026-10-31）：NSEC(owner=et., next=eu.) 覆盖
                                    # smartblock.firefox.etp，证明的是"etp. 这个 TLD
                                    # 不存在"——etp 与 et **同级**，不是 et 的子区。
                                    # 原实现只要 owner 含 DS/NS 就保守拒绝，导致所有
                                    # 不存在的 TLD（.etp / .local / .invalid）都被判
                                    # 「NSEC/NSEC3 区间不覆盖（重放攻击）」整条拒绝
                                    # （实测 Firefox 的 smartblock.firefox.etp 每秒
                                    # 刷十几条 WARNING）。仅当被查名**落在委托之下**
                                    # （可能属于更深 zone）时才需要更深层的证明。
                                    if owner_is_delegation:
                                        try:
                                            if not qn.is_subdomain(rrset.name):
                                                owner_is_delegation = False
                                        except Exception:
                                            pass
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
                                                "（%s）— 保守拒绝", _safe_qname(rrset.name),
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
                                                "（%s）— 保守拒绝", _safe_qname(qname),
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
                                                _safe_qname(ce_nx),
                                            )
                                    else:
                                        # owner 是委托点：需检查 qname 与 owner 之间
                                        # 是否有更深 zone 存在——无法证明，保守拒绝
                                        logger.debug(
                                            "DNSSEC NXDOMAIN NSEC owner %s 是委托点，"
                                            "qname %s 需更深 zone 证明 — 保守拒绝",
                                            _safe_qname(rrset.name), _safe_qname(qname),
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
                                # （RFC 5155 §8.9）。
                                #
                                # ★ Opt-Out 不能被排除（RFC 5155 §8.6）：.com / .net
                                #   这类大区用 opt-out 省略未签名委托的 NSEC3，
                                #   其区间覆盖正是**标准**的 NXDOMAIN 证明。
                                #   旧实现用 `not optout` 直接跳过所有 opt-out
                                #   NSEC3 → `.com` 下任何不存在的域名都判"区间
                                #   不覆盖"并拒绝（差分测试实测 nonexistent-*.com）。
                                #   安全性：opt-out 覆盖意味着"该名字不存在**或**是
                                #   未签名委托"，后者在 DNS 层同样没有该名字的记录，
                                #   返回 NXDOMAIN 与权威一致（RFC 5155 §9.2）。
                                if self._nsec3_interval_check(
                                        target_hash, owner_hash, rdata.next):
                                    owner_is_deleg = (
                                        self._nsec_has_type(rdata, dns.rdatatype.NS)
                                        and not self._nsec_has_type(
                                            rdata, dns.rdatatype.SOA)
                                    ) or self._nsec_has_type(rdata, dns.rdatatype.DS)
                                    if (not owner_is_deleg) or self._nsec3_optout(rdata):
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
                                                            # ★ Opt-Out 覆盖同样可用于
                                                            # wildcard 否定（RFC 5155
                                                            # §8.6）：opt-out 区间被省略
                                                            # 的是**未签名委托**，不影响
                                                            # "*.CE 不存在"的判定。旧实现
                                                            # 排除 opt-out → .com 下的
                                                            # NXDOMAIN 全部缺"*.CE 证明"
                                                            # 被判保守拒绝。
                                                            if self._nsec3_interval_check(
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
                                            "— 保守拒绝", _safe_qname(rrset.name), _safe_qname(qname),
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
                    _safe_qname(qname), [str(r.name) for r in auth_unsigned][:3],
                )
                return None

            if has_nsec and not nsec_semantic_ok:
                # **根区负应答例外**（2026-10-31）：根区的 NSEC 链完整、
                # **没有任何通配符记录**，也不存在"更深委托区可能掩盖 qname"
                # 的问题（TLD 的存否由根区唯一决定）。RFC 4035 §5.4 要求补
                # wildcard 否定证明是为了防"区内通配符合成应答"，对根区不适用。
                # 因此「NSEC 已验签（上面的循环）+ 区间覆盖被查名」即为完整证明。
                # 否则所有**不存在的 TLD**（.etp / .local / .invalid …）都会被判
                # 「区间不覆盖」整条拒绝（实测 Firefox 的
                # smartblock.firefox.etp 每秒刷十几条 WARNING）。
                if soa_owner_zone == dns.name.root and nsec_covers_any:
                    nsec_semantic_ok = True
                else:
                    # 有 NSEC/NSEC3 但区间语义不覆盖本次 qname → 重放攻击 → 拒绝
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 负应答 NSEC/NSEC3 区间不覆盖 %s（重放攻击）— 拒绝", _safe_qname(qname),
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
                        _safe_qname(qname),
                    )
                    return None
            else:
                if has_soa:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 负应答 SOA owner 不属于 %s 权威 zone（重放伪造）— 拒绝",
                        _safe_qname(qname),
                    )
                    return None
                # 无 SOA 的负应答（仅 NSEC 证明）：NSEC 语义已校验，允许
                if not has_nsec:
                    self._stats["bogus"] += 1
                    logger.warning(
                        "DNSSEC 负应答无 SOA 且无 NSEC 证明（伪造）— 拒绝: %s", _safe_qname(qname),
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
            logger.warning("DNSSEC 响应有 RRSIG 但无 RRset 验证通过: %s", _safe_qname(qname))
            return None
        except Exception as e:
            logger.debug("迭代解析异常: %s", e)
            self._stats["fail"] += 1
            return None


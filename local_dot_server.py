"""
本地 DoT 服务器（DNS over TLS，RFC 7858）
- TLS 加密的 TCP 连接
- 2 字节长度前缀的 DNS 消息格式
- 支持 IPv4/IPv6 双栈
- 可配置域名（SNI）和证书
- 集成 DNS 缓存 + 域名过滤 + DNSSEC
"""

import os
import ssl
import socket
import struct
import asyncio
import logging
import time
from typing import Optional, List, Dict, Tuple

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

logger = logging.getLogger("dns-proxy.local-dot")

QTYPE_NAMES = {v: k for k, v in dns.rdatatype.__dict__.items() if isinstance(v, int)}


class LocalDoTServer:
    """本地 DNS over TLS 服务器（支持 IPv4/IPv6 双栈）"""

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

        self.enabled = config.local_dot_enabled
        self.host = config.local_dot_host
        self.port = config.local_dot_port
        self.domain = config.local_dot_domain
        self.cert_path = config.local_dot_cert_path
        self.key_path = config.local_dot_key_path
        self.ipv6_enabled = config.local_dot_ipv6_enabled
        self.ipv6_host = config.local_dot_ipv6_host
        self.ipv6_port = config.local_dot_ipv6_port

        self._server_v4: Optional[asyncio.AbstractServer] = None
        self._server_v6: Optional[asyncio.AbstractServer] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)

        # 单 IP 限速（共享 PerIPRateLimiter 单例）
        self._per_ip_limiter = get_per_ip_limiter(
            per_ip_limit=config.max_concurrent_per_ip,
        )
        self._per_ip_limit = config.max_concurrent_per_ip
        self._ip_semaphore_task: Optional[asyncio.Task] = None

        # QPS 限速（所有客户端包括 localhost）
        self._qps_limiter = QPSCounter(config.dot_qps_limit, "DoT")

        # 最大并发 TCP 连接数限制
        self._max_tcp_connections = config.dot_max_connections
        self._active_connections = 0

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

    async def _cleanup_stale_per_ip_semaphores(self):
        # 已废弃：过期条目由共享 PerIPRateLimiter 的后台循环统一清理。
        # 保留空方法仅为兼容旧调用点；不再阻塞等待（原 asyncio.Event().wait() 永不返回）。
        return

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """创建 TLS 服务器端 SSL 上下文"""
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            logger.warning("DoT 证书不存在: %s, %s", self.cert_path, self.key_path)
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(self.cert_path, self.key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
        )
        # 如果配置了服务器域名，记录日志（当前未设置 SNI 回调，
        # 证书由 _create_ssl_context 统一加载；如需按域名分发证书，
        # 需在此调用 ssl_context.set_servername_callback）
        if self.domain:
            logger.info("DoT 服务器域名: %s, 使用证书: %s", self.domain, self.cert_path)
        return ctx

    async def start(self):
        """启动 DoT 服务器（IPv4 + 可选 IPv6）"""
        if not self.enabled:
            logger.info("本地 DoT 服务器已禁用")
            return

        self._ssl_context = self._create_ssl_context()
        if self._ssl_context is None:
            logger.error("DoT 服务器启动失败: SSL 证书无效")
            return

        loop = asyncio.get_running_loop()

        # IPv4 监听
        try:
            self._server_v4 = await asyncio.start_server(
                self._handle_client,
                host=self.host,
                port=self.port,
                ssl=self._ssl_context,
                family=socket.AF_INET,
                reuse_address=True,
                backlog=128,
            )
            logger.info(
                "本地 DoT [IPv4] tls://%s:%d (域名: %s)",
                self.host if self.host != "0.0.0.0" else "127.0.0.1",  # nosec B104 - display formatting, not binding
                self.port,
                self.domain or "未设置",
            )
        except OSError as e:
            logger.error("DoT [IPv4] 启动失败: %s", e)

        # IPv6 监听（可选）
        if self.ipv6_enabled:
            try:
                self._server_v6 = await asyncio.start_server(
                    self._handle_client,
                    host=self.ipv6_host,
                    port=self.ipv6_port,
                    ssl=self._ssl_context,
                    family=socket.AF_INET6,
                    reuse_address=True,
                    backlog=128,
                )
                logger.info(
                    "本地 DoT [IPv6] tls://[%s]:%d (域名: %s)",
                    self.ipv6_host, self.ipv6_port, self.domain or "未设置",
                )
            except OSError as e:
                logger.warning("DoT [IPv6] 启动失败（跳过）: %s", e)

        # 启动单 IP 限速清理任务（空任务，仅保持接口兼容）
        self._ip_semaphore_task = asyncio.create_task(self._cleanup_stale_per_ip_semaphores())
        if self._server_v4 is None and self._server_v6 is None:
            logger.error("本地 DoT 未能监听任何地址（IPv4/IPv6 全部失败），服务不可用")

    async def stop(self):
        """停止 DoT 服务器"""
        if self._ip_semaphore_task:
            self._ip_semaphore_task.cancel()
            try:
                await self._ip_semaphore_task
            except asyncio.CancelledError:
                pass
            self._ip_semaphore_task = None

        for server in (self._server_v4, self._server_v6):
            if server:
                server.close()
                try:
                    await server.wait_closed()
                except Exception as e:
                    logger.debug("DoT 服务器等待关闭异常: %s", e)
        self._server_v4 = None
        self._server_v6 = None
        logger.info("本地 DoT 服务器已停止")

    async def restart(self):
        """重启 DoT 服务器（IP 切换后恢复监听）

        即使 stop() 部分失败也强制尝试 start()，
        防止重启钩子执行期间服务器永久挂掉。
        """
        await self.stop()
        await self.start()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """处理单个 DoT 客户端连接（RFC 7858：2 字节长度前缀）"""
        client_ip = writer.get_extra_info("peername", ("unknown", 0))[0]

        # 最大 TCP 连接数限制
        if self._active_connections >= self._max_tcp_connections:
            logger.warning("DoT 超出最大连接数 %d，拒绝 %s", self._max_tcp_connections, client_ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug("DoT 拒绝连接时关闭异常: %s", e)
            return

        self._active_connections += 1
        try:
            while True:
                # 读取 2 字节长度前缀
                raw_len = await asyncio.wait_for(
                    reader.readexactly(2), timeout=30.0
                )
                if not raw_len or len(raw_len) < 2:
                    break
                msg_len = int.from_bytes(raw_len, "big")
                if msg_len < 12:
                    logger.warning("DoT 客户端 %s 无效消息长度: %d", client_ip, msg_len)
                    # 消费该帧并回 FORMERR，然后继续服务同一连接上的后续查询
                    # （RFC 7766 连接复用：不应因单个坏帧断掉整条连接）
                    try:
                        short_data = await asyncio.wait_for(
                            reader.readexactly(msg_len), timeout=30.0
                        )
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                        break
                    err = self._make_error_wire(short_data, dns.rcode.FORMERR)
                    if err:
                        writer.write(len(err).to_bytes(2, "big") + err)
                        await asyncio.wait_for(writer.drain(), timeout=10.0)
                    continue

                # 读取 DNS 查询消息
                wire_data = await asyncio.wait_for(
                    reader.readexactly(msg_len), timeout=30.0
                )

                # 处理 DNS 查询
                response_data = await self._process_query(wire_data, client_ip)
                if response_data is None:
                    # 无响应时回 FORMERR，避免客户端在长连接上挂起
                    response_data = self._make_error_wire(wire_data, dns.rcode.FORMERR)
                    if response_data is None:
                        break

                # 发送 2 字节长度前缀 + 响应
                writer.write(len(response_data).to_bytes(2, "big") + response_data)
                await asyncio.wait_for(writer.drain(), timeout=10.0)

        except asyncio.IncompleteReadError:
            # 客户端正常断开
            pass
        except asyncio.TimeoutError:
            logger.debug("DoT 客户端 %s 超时断开", client_ip)
        except ConnectionResetError:
            pass
        except Exception as e:
            logger.debug("DoT 客户端 %s 处理异常: %s", client_ip, e)
        finally:
            self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug("DoT 客户端关闭异常: %s", e)

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
        start_time = asyncio.get_event_loop().time()

        try:
            query = dns.message.from_wire(wire_data)
            if not query.question:
                # RFC 1035：QDCOUNT=0 回 FORMERR，而不是断连
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.FORMERR)
                return response.to_wire()

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
                # DNSSEC 验证
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
                # 缓存结果
                if self.config.cache_enabled and status == "resolved":
                    try:
                        response_msg = dns.message.from_wire(result_wire)
                        # AAAA 优先于 A 排序（确保缓存中数据顺序一致）
                        reorder_answer_aaaa_first(response_msg)
                        is_negative = self._is_negative_response(response_msg)
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception as e:
                        logger.debug("DoT 缓存写入异常: %s", e)

            await self._log_query(client_ip, qname, qtype_name, status, block_reason)

            # AAAA 优先于 A 排序（仅对成功解析的上游响应）
            if response_wire is not None and status == "resolved":
                response_wire = sort_dns_response_wire(response_wire)

            # 上游直连路径的响应 ID 可能与查询不一致：DoH（RFC 8484）与 DoQ
            # （RFC 9250）上游按协议要求用 ID=0 发起查询，其响应 ID 会被原样
            # 透传给客户端。DoT 客户端校验 ID，收到不一致的 ID 会丢弃响应并
            # 等待超时（表现为查询卡顿），故在返回前统一重写为查询 ID。
            # 对 make_response(query) 生成的响应（ID 本已正确）是幂等的。
            if response_wire:
                try:
                    _resp = dns.message.from_wire(response_wire)
                    if _resp.id != query.id:
                        _resp.id = query.id
                        response_wire = _resp.to_wire()
                except Exception as e:
                    logger.debug("DoT 响应 ID 重写异常: %s", e)

            return response_wire

        except dns.exception.DNSException:
            return self._make_error_wire(wire_data, dns.rcode.FORMERR)
        except Exception as e:
            logger.error("DoT 查询异常: %s", e)
            return self._make_error_wire(wire_data, dns.rcode.SERVFAIL)

    @staticmethod
    def _make_error_wire(data: bytes, rcode: int) -> Optional[bytes]:
        """从原始查询报文尽力构造错误响应（保留 ID / RD / CD），失败返回 None"""
        try:
            if len(data) < 2:
                return None
            qid = int.from_bytes(data[:2], "big")
            flags_in = int.from_bytes(data[2:4], "big") if len(data) >= 4 else 0
            flags = 0x8000 | (flags_in & 0x0110) | (int(rcode) & 0x000F)
            return struct.pack("!HHHHHH", qid, flags, 0, 0, 0, 0)
        except Exception:
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
            logger.debug("DoT 查询日志记录异常: %s", e)

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
import asyncio
import logging
from typing import Optional, List

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
        # 如果配置了服务器域名，设置 SNI 回调，可针对不同域名返回不同证书
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
                family=asyncio.AddressFamily.AF_INET,
                reuse_address=True,
                backlog=128,
            )
            logger.info(
                "本地 DoT [IPv4] tls://%s:%d (域名: %s)",
                self.host if self.host != "0.0.0.0" else "127.0.0.1",
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
                    family=asyncio.AddressFamily.AF_INET6,
                    reuse_address=True,
                    backlog=128,
                )
                logger.info(
                    "本地 DoT [IPv6] tls://[%s]:%d (域名: %s)",
                    self.ipv6_host, self.ipv6_port, self.domain or "未设置",
                )
            except OSError as e:
                logger.warning("DoT [IPv6] 启动失败（跳过）: %s", e)

    async def stop(self):
        """停止 DoT 服务器"""
        for server in (self._server_v4, self._server_v6):
            if server:
                server.close()
                try:
                    await server.wait_closed()
                except Exception:
                    pass
        self._server_v4 = None
        self._server_v6 = None
        logger.info("本地 DoT 服务器已停止")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """处理单个 DoT 客户端连接（RFC 7858：2 字节长度前缀）"""
        client_ip = writer.get_extra_info("peername", ("unknown", 0))[0]
        try:
            while True:
                # 读取 2 字节长度前缀
                raw_len = await asyncio.wait_for(
                    reader.readexactly(2), timeout=30.0
                )
                if not raw_len or len(raw_len) < 2:
                    break
                msg_len = int.from_bytes(raw_len, "big")
                if msg_len < 12 or msg_len > 65535:
                    logger.debug("DoT 客户端 %s 无效消息长度: %d", client_ip, msg_len)
                    break

                # 读取 DNS 查询消息
                wire_data = await asyncio.wait_for(
                    reader.readexactly(msg_len), timeout=30.0
                )

                # 处理 DNS 查询
                response_data = await self._process_query(wire_data, client_ip)
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
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_query(self, wire_data: bytes, client_ip: str) -> Optional[bytes]:
        """处理 DNS 查询（过滤 → 缓存 → 上游）"""
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
                        is_negative = response_msg.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.REFUSED)
                        await self.cache.set(cache_key, response_msg, is_negative)
                    except Exception:
                        pass

            await self._log_query(client_ip, qname, qtype_name, status, block_reason)
            return response_wire

        except dns.exception.DNSException:
            return None
        except Exception as e:
            logger.error("DoT 查询异常: %s", e)
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

"""
本地 DoH 服务器
- 使用 SSL 证书提供 HTTPS 加密 DNS 服务
- 支持 GET (base64url) 和 POST (binary) 查询（RFC 8484）
- 集成 DNS 缓存
- 集成域名过滤
- 非 53 端口，安全提供 DNS 服务
"""

import os
import ssl
import base64
import asyncio
import logging
from typing import Optional, List

from aiohttp import web

import dns.message
import dns.rdatatype
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset

from config import Config
from cache import DNSCache
from resolver_manager import ResolverManager
from filter_engine import FilterEngine
from logger import RequestLogger
from dnssec import DNSSECQueryWrapper, DNSSECValidator

logger = logging.getLogger("dns-proxy.doh-server")

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

        # 并发控制
        self._concurrency_semaphore = asyncio.Semaphore(config.max_concurrent)

    def _setup_routes(self):
        """注册路由"""
        self.app.router.add_route("GET", self.doh_path, self.handle_get)
        self.app.router.add_route("POST", self.doh_path, self.handle_post)

    # ======================== GET 处理（双格式自适应） ========================

    async def handle_get(self, request: web.Request) -> web.Response:
        """
        GET 请求 — 自动适配两种 DoH 格式:

        1. Wire Format (RFC 8484):
           ?dns=<base64url 编码的 DNS 查询>

        2. JSON API (Google DNS over HTTPS):
           ?name=example.com&type=A&cd=0
        """
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
        query = dns.message.make_query(name, qtype, want_dnssec=self.config.dnssec_enabled)
        if cd_flag:
            query.flags |= dns.flags.CD
        wire_data = query.to_wire()

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

            # 1. 检查域名过滤
            if self.config.filter_enabled:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    result["Status"] = 3  # NXDOMAIN
                    result["Comment"] = f"被过滤规则拦截: {reason}"
                    return result

            # 2. 缓存检查
            cache_key = (question.name, question.rdtype, question.rdclass)
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
                is_negative = response.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.REFUSED)
                await self.cache.set(cache_key, response, is_negative)

            return self._dns_response_to_json(response, query)

        except Exception as e:
            logger.error("JSON 查询异常: %s", e)
            result["Comment"] = f"内部错误: {str(e)[:100]}"
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
            for rd in rrset:
                entry = {
                    "name": str(rrset.name).rstrip("."),
                    "type": QTYPE_NAMES.get(rd.rdtype, str(rd.rdtype)),
                    "TTL": max(0, rd.ttl),
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
            for rd in rrset:
                result["Authority"].append({
                    "name": str(rrset.name).rstrip("."),
                    "type": QTYPE_NAMES.get(rd.rdtype, str(rd.rdtype)),
                    "TTL": max(0, rd.ttl),
                    "data": str(rd),
                })

        return result

    # ======================== Wire Format 查询 ========================

    async def _handle_dns_query(
        self, wire_data: bytes, request: web.Request, response_format: str = "wire"
    ) -> web.Response:
        """处理 DNS 查询（Wire Format）- 按 response_format 返回"""
        async with self._concurrency_semaphore:
            return await self._process_query(wire_data, request, response_format)

    def _make_response(self, data: bytes, fmt: str = "wire") -> web.Response:
        """根据格式创建响应"""
        if fmt == "json":
            try:
                resp = dns.message.from_wire(data)
                json_data = self._dns_response_to_json(resp, resp)
                return web.json_response(json_data)
            except Exception:
                return web.json_response(
                    {"Status": 2, "Comment": "DNS 响应解析失败"}
                )
        return web.Response(body=data, content_type="application/dns-message")

    async def _process_query(
        self, wire_data: bytes, request: web.Request, response_format: str = "wire"
    ) -> web.Response:
        """DNS 查询处理（含缓存、过滤、DNSSEC 验证）"""
        client_ip = request.remote or "unknown"
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
            cache_key = (question.name, question.rdtype, question.rdclass)

            # 1. 检查域名过滤
            if self.config.filter_enabled:
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
                        response.answer[0].add(dns.rdtypes.IN.A.A(question.name, 3600, "0.0.0.0"))
                        response.set_rcode(dns.rcode.NOERROR)
                    elif rdtype == dns.rdatatype.AAAA:
                        response.answer.append(
                            dns.rrset.RRset(question.name, question.rdclass, dns.rdatatype.AAAA)
                        )
                        response.answer[0].add(dns.rdtypes.IN.AAAA.AAAA(question.name, 3600, "::"))
                        response.set_rcode(dns.rcode.NOERROR)
                    else:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    response_wire = response.to_wire()
                    # 缓存拦截结果
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, QTYPE_NAMES.get(question.rdtype, str(question.rdtype)),
                        elapsed, status, upstream, block_reason
                    )
                    return self._make_response(response_wire, response_format)

            # 2. 检查缓存
            cached_response = None
            if self.config.cache_enabled:
                cached_response = await self.cache.get(cache_key)

            if cached_response is not None:
                response_wire = cached_response.to_wire()
                status = "cached"
                elapsed = asyncio.get_event_loop().time() - start_time
                await self._log_query(
                    client_ip, qname, qtype, elapsed, status, "", ""
                )
                return self._make_response(response_wire, response_format)

            # 3. 通过上游解析器并行查询（自动添加 DNSSEC DO 位）
            result_wire = await self.resolver_manager.resolve(wire_data)

            if result_wire is None:
                # 所有上游都失败
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                response_wire = response.to_wire()
                status = "error"
            else:
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
                                is_negative = response_msg.rcode() in (
                                    dns.rcode.NXDOMAIN,
                                    dns.rcode.REFUSED,
                                )
                                await self.cache.set(cache_key, response_msg, is_negative)
                            except Exception:
                                pass
                else:
                    response_wire = result_wire
                    status = "resolved"
                    # 缓存结果
                    if self.config.cache_enabled:
                        try:
                            response_msg = dns.message.from_wire(result_wire)
                            is_negative = response_msg.rcode() in (
                                dns.rcode.NXDOMAIN,
                                dns.rcode.REFUSED,
                            )
                            await self.cache.set(cache_key, response_msg, is_negative)
                        except Exception:
                            pass

            elapsed = asyncio.get_event_loop().time() - start_time
            await self._log_query(
                client_ip, qname, qtype, elapsed, status, upstream, block_reason
            )

            return self._make_response(response_wire, response_format)

        except dns.exception.DNSException as e:
            logger.warning("DNS 解析错误: %s", e)
            return web.Response(status=400, text=f"DNS 解析错误: {e}")
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
        except Exception:
            pass

    async def start(self):
        """启动 DoH 服务器（IPv4 + 可选 IPv6）"""
        use_ssl = os.path.exists(self.cert_path) and os.path.exists(self.key_path)
        ssl_context = None

        if use_ssl:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.cert_path, self.key_path)
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_context.set_ciphers(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            )
        else:
            logger.warning(
                "SSL 证书不存在，请运行:\n"
                "  cd %s\n"
                "  openssl req -x509 -nodes -days 365 -newkey rsa:4096 "
                "-keyout certs/localhost.key -out certs/localhost.crt "
                "-config openssl.conf -extensions v3_req",
                os.path.dirname(os.path.dirname(os.path.abspath(self.cert_path))),
            )
            logger.warning("将在无 SSL 下启动（仅测试用）")

        self._runner = web.AppRunner(self.app)
        await self._runner.setup()

        # IPv4 监听
        site_v4 = web.TCPSite(
            self._runner, self.host, self.port, ssl_context=ssl_context,
        )
        await site_v4.start()
        self._sites.append(site_v4)
        logger.info(
            "DoH [IPv4] https://%s:%s%s",
            self.host if self.host != "0.0.0.0" else "127.0.0.1",
            self.port,
            self.doh_path,
        )

        # IPv6 监听（可选）
        if self.ipv6_enabled:
            try:
                site_v6 = web.TCPSite(
                    self._runner, self.ipv6_host, self.ipv6_port,
                    ssl_context=ssl_context,
                )
                await site_v6.start()
                self._sites.append(site_v6)
                logger.info(
                    "DoH [IPv6] https://[%s]:%d%s",
                    self.ipv6_host, self.ipv6_port, self.doh_path,
                )
            except OSError as e:
                logger.warning("IPv6 监听启动失败（跳过）: %s", e)

    async def stop(self):
        """停止 DoH 服务器（IPv4 + IPv6）"""
        for site in self._sites:
            try:
                await site.stop()
            except Exception:
                pass
        self._sites.clear()
        if self._runner:
            await self._runner.cleanup()
            logger.info("DoH 服务器已停止")

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
import time
from typing import Optional, List, Dict, Tuple

from aiohttp import web

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
        self._cleanup_task: Optional[asyncio.Task] = None

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
    def _is_localhost(ip: str) -> bool:
        """判断是否是本地地址（不限速）"""
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost")

    async def _get_per_ip_semaphore(self, client_ip: str) -> asyncio.Semaphore:
        """获取或创建单 IP 信号量（使用共享 PerIPRateLimiter）"""
        return await self._per_ip_limiter.acquire(client_ip)

    async def _cleanup_stale_per_ip_semaphores(self):
        """定期清理过期 IP 条目（由共享 PerIPRateLimiter 管理）"""
        # PerIPRateLimiter 有自身后台清理任务，此方法保持空占位
        # 兼容 start() 中创建的循环
        await asyncio.Event().wait()

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

        client_ip = request.remote or "unknown"
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
            cache_key = (question.name, question.rdtype, question.rdclass)
            if self.config.filter_enabled and not is_hosts_bypass:
                blocked, reason = self.filter_engine.check_domain(qname)
                if blocked:
                    result["Status"] = 3  # NXDOMAIN
                    result["Comment"] = f"被过滤规则拦截: {reason}"
                    # 缓存拦截结果到 DNS 响应缓存，防止上游正向应答重复生效
                    if self.config.cache_enabled:
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.NXDOMAIN)
                        await self.cache.set(cache_key, response)
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
        client_ip = request.remote or "unknown"
        await self._qps_limiter.acquire()  # QPS 限速（所有客户端）
        if not self._is_localhost(client_ip):
            sem = await self._get_per_ip_semaphore(client_ip)
            async with sem:
                async with self._concurrency_semaphore:
                    return await self._process_query(wire_data, request, response_format)
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
        """DNS 查询处理（含缓存、过滤、DNSSEC 验证、自定义 hosts）"""
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
                    response_wire = response.to_wire()
                    status = "custom_hosts"
                    block_reason = f"自定义 hosts 映射"
                    if self.config.cache_enabled:
                        await self.cache.set(cache_key, response)
                    elapsed = asyncio.get_event_loop().time() - start_time
                    await self._log_query(
                        client_ip, qname, qtype, elapsed, status, "", block_reason
                    )
                    return self._make_response(response_wire, response_format)

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
                import copy
                cached_response = copy.copy(cached_response)
                cached_response.id = query.id  # 修复DNS ID不匹配
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
                            except Exception as e:
                                logger.debug("DoH 缓存写入异常: %s", e)
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
                        except Exception as e:
                            logger.debug("DoH 缓存写入异常: %s", e)

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
        except Exception as e:
            logger.debug("DoH 查询日志记录异常: %s", e)

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

        # 启动共享 PerIPRateLimiter（全局单例，清理过期 IP 条目）
        self._per_ip_limiter.start()
        # 保持兼容性：占位清理任务
        self._cleanup_task = asyncio.create_task(self._cleanup_stale_per_ip_semaphores())

        # IPv4 监听
        site_v4 = web.TCPSite(
            self._runner, self.host, self.port, ssl_context=ssl_context,
        )
        await site_v4.start()
        self._sites.append(site_v4)
        logger.info(
            "DoH [IPv4] https://%s:%s%s",
            self.host if self.host != "0.0.0.0" else "127.0.0.1",  # nosec B104 - display formatting, not binding
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

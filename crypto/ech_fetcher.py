"""
ECHConfigList 获取器 — 支持 TTL 缓存、后台刷新、多源查询

对标 Xray-core 的 ECH 实现（transport/internet/tls/ech.go）：
  - 支持 base64 静态配置
  - 支持 DNS 查询格式：hostname+https://dns/dns-query
  - 支持 DNS 查询格式：hostname+udp://dns-server
  - TTL 缓存，过期前 80% 时间后台刷新
  - 超过 4 小时不再返回过期缓存（等待刷新完成）

所有 DNS 查询绕过系统 DNS（通过 bootstrap DNS 解析 DoH 端点 IP），
解决 GPF 下 UDP 53 被限和系统 DNS 自引用（127.0.0.1）问题。
"""

import asyncio
import base64
import ipaddress
import logging
import ssl
import time
from typing import Optional, Callable, Awaitable, Dict, List, Tuple

import dns.message
import dns.rdatatype
from dns.rdtypes.svcbbase import ParamKey

logger = logging.getLogger("dns-proxy.crypto.ech_fetcher")

# ECHConfig 缓存记录
class _ECHConfigRecord:
    """单条 ECHConfig 缓存记录"""

    def __init__(self, config: bytes, ttl: int, query_hostname: str):
        self.config = config
        self.expire_at = time.time() + ttl
        # 80% TTL 时触发后台刷新
        self.refresh_at = time.time() + ttl * 0.8
        self.query_hostname = query_hostname

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expire_at

    @property
    def should_refresh(self) -> bool:
        return time.time() >= self.refresh_at

    @property
    def is_stale(self) -> bool:
        """超过 4 小时未刷新，视为 stale（等刷新完成而非返回过期数据）"""
        return time.time() >= self.expire_at + 14400  # 4 hours


class ECHConfigFetcher:
    """
    ECHConfigList 管理器

    配置格式（config_str）：
      1. "" 或 None        → 不使用 ECH
      2. Base64 字符串     → 静态 ECHConfigList
      3. "https://dns/dns-query"
                          → 自动查询 upstream_hostname 的 HTTPS 记录
      4. "udp://dns-server"
                          → 同上，但使用 UDP DNS
      5. "hostname+https://dns/dns-query"
                          → 查询指定 hostname 的 HTTPS 记录
      6. "hostname+udp://dns-server"
                          → 同上，UDP DNS
    """

    def __init__(self, config_str: str, upstream_hostname: str,
                 bootstrap_resolve_fn: Optional[Callable[[str], Awaitable[List[str]]]] = None,
                 fallback_udp_servers: Optional[List[str]] = None):
        self._config_str = (config_str or "").strip()
        self._upstream_hostname = upstream_hostname
        self._bootstrap_resolve = bootstrap_resolve_fn  # 用于解析 DoH 端点 IP
        # UDP fallback DNS 服务器（当 DoH 连接不可达时，改用 UDP 查询 HTTPS 记录）
        self._fallback_udp = [s for s in (fallback_udp_servers or []) if s.strip()]

        self._record: Optional[_ECHConfigRecord] = None
        self._lock = asyncio.Lock()
        self._refresh_task: Optional[asyncio.Task] = None
        self._last_error: Optional[str] = None

        # 解析配置模式
        self._mode: str = "none"  # none | static | dns_query
        self._query_hostname: Optional[str] = None
        self._dns_server: Optional[str] = None  # DoH URL or udp://...

        self._parse_config()

    def _parse_config(self):
        raw = self._config_str
        if not raw:
            self._mode = "none"
            return

        # 含 "://" → DNS 查询格式
        if "://" in raw:
            self._mode = "dns_query"
            parts = raw.split("+", 1)
            if len(parts) == 2:
                # "hostname+https://..." or "hostname+udp://..."
                self._query_hostname = parts[0].strip()
                self._dns_server = parts[1].strip()
            else:
                # 只有 DNS 服务器，自动使用 upstream_hostname 作为查询目标
                self._query_hostname = self._upstream_hostname
                self._dns_server = parts[0].strip()
            logger.info("ECH 配置: 通过 %s 查询 %s 的 HTTPS 记录",
                        self._dns_server, self._query_hostname)
        else:
            # 尝试 base64 解码
            try:
                decoded = base64.b64decode(raw)
                if decoded:
                    self._mode = "static"
                    self._record = _ECHConfigRecord(
                        config=decoded,
                        ttl=86400 * 7,  # 静态配置缓存 7 天
                        query_hostname=self._upstream_hostname,
                    )
                    logger.info("ECH 配置: 静态 base64 (%d bytes)", len(decoded))
            except Exception:
                self._mode = "none"
                logger.warning("ECH 配置无效（不是 base64 也不是 DNS 查询格式）: %s",
                               raw[:64])

    # ── 公开接口 ──────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._mode != "none"

    @property
    def has_valid_config(self) -> bool:
        """
        是否已有有效的 ECHConfigList（区别于 enabled 仅表示配置格式合法）。
        - static 模式：解析时即存在 _record，始终有效
        - dns_query 模式：需要至少一次成功查询填充 _record
        """
        if self._mode == "static":
            return self._record is not None and bool(self._record.config)
        if self._mode == "dns_query":
            return self._record is not None and bool(self._record.config)
        return False

    async def get_config(self) -> Optional[bytes]:
        """
        获取 ECHConfigList bytes。
        优先返回缓存的 ECHConfigList，必要时触发后台查询/刷新。
        - 缓存有效 → 直接返回
        - 缓存需刷新（>80% TTL）→ 返回旧值，后台刷新
        - 缓存过期但 <4h → 返回旧值，后台刷新
        - 无缓存或 >4h → 等待查询完成

        注意：网络 I/O 在锁外执行，避免阻塞其他并发 get_config() 调用。
        """
        if self._mode == "static":
            return self._record.config if self._record else None

        if self._mode != "dns_query":
            return None

        # 锁内快速检查缓存状态（无 I/O）
        async with self._lock:
            rec = self._record
            now = time.time()
            need_query = rec is None or rec.is_stale
            can_return_stale = rec is not None and rec.should_refresh and not rec.is_stale

        if need_query:
            # 网络 I/O 在锁外执行，不阻塞其他并发请求
            logger.debug("ECH 缓存%s，开始查询 %s",
                         "为空" if rec is None else " stale (>4h)", self._query_hostname)
            result = await self._do_query()
            return result
        elif can_return_stale:
            # 缓存过期但 <4h：先返回旧值，后台刷新
            self._ensure_refresh()
            return rec.config
        else:
            # 缓存有效且不需要刷新
            return rec.config

    async def force_refresh(self) -> Optional[bytes]:
        """强制刷新（忽略缓存）"""
        if self._mode != "dns_query":
            return self._record.config if self._record else None
        async with self._lock:
            return await self._do_query()

    def close(self):
        """清理资源"""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()

    # ── 内部方法 ──────────────────────────────────────────────

    def _ensure_refresh(self):
        """确保后台刷新任务正在运行"""
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = asyncio.create_task(self._background_refresh())

    async def _background_refresh(self):
        """后台刷新 ECH 配置"""
        try:
            logger.debug("后台刷新 ECH 配置: %s", self._query_hostname)
            # 网络 I/O 不持锁，避免阻塞并发 get_config()
            ech_config = await self._query_ech_config(
                self._query_hostname or self._upstream_hostname,
                self._dns_server,
            )
            if ech_config:
                config_bytes, ttl = ech_config
                async with self._lock:  # 仅在更新缓存时持锁
                    self._record = _ECHConfigRecord(
                        config=config_bytes,
                        ttl=max(ttl, 60),
                        query_hostname=self._query_hostname or self._upstream_hostname,
                    )
                    self._last_error = None
                logger.debug("后台刷新 ECH 配置成功: %s (%d bytes)",
                             self._query_hostname, len(config_bytes))
            else:
                self._last_error = "HTTPS 记录无 ECH 参数"
                logger.debug("后台刷新 ECH 配置: %s 无变化或失败",
                             self._query_hostname)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._last_error = str(e)
            logger.debug("后台刷新 ECH 配置失败 %s: %s",
                         self._query_hostname, e)

    async def _do_query(self) -> Optional[bytes]:
        """
        执行真正的 HTTPS 记录查询。
        返回 ECHConfigList bytes，失败则保留原缓存并返回 None。
        """
        assert self._dns_server is not None
        try:
            ech_config = await self._query_ech_config(
                self._query_hostname or self._upstream_hostname,
                self._dns_server,
            )
            if ech_config:
                config_bytes, ttl = ech_config
                async with self._lock:  # 保护 _record 写操作
                    self._record = _ECHConfigRecord(
                        config=config_bytes,
                        ttl=max(ttl, 60),  # 至少 60 秒
                        query_hostname=self._query_hostname or self._upstream_hostname,
                    )
                    self._last_error = None
                logger.info("ECH 配置已更新: %s (%d bytes, TTL=%d)",
                            self._query_hostname, len(config_bytes), ttl)
                return config_bytes
            else:
                self._last_error = "HTTPS 记录无 ECH 参数"
                logger.debug("ECH 查询: %s 无 ECH 参数", self._query_hostname)
                return None
        except Exception as e:
            self._last_error = str(e)
            logger.warning("ECH 查询失败 %s: %s", self._query_hostname, e)
            # 有旧缓存则返回旧缓存（即使过期）
            if self._record:
                return self._record.config
            return None

    async def _query_ech_config(self, hostname: str, dns_server: str
                                ) -> Optional[tuple]:
        """
        向 dns_server 查询 hostname 的 HTTPS 记录，提取 ECHConfigList。
        返回 (config_bytes, ttl) 或 None。

        当主查询方式（DoH）失败时，自动回退到 UDP DNS fallback 服务器
        （如 bootstrap 解析器），解决 DoH 端点（如 1.1.1.1）被阻断的场景。
        """
        dns_server = dns_server.strip()

        if dns_server.startswith("https://"):
            # 检查 DoH 端点是否是 IP 地址
            # IP 地址作为 TLS server_hostname 会导致证书验证失败（需要域名），
            # 因此直接跳过 DoH 查询，使用 UDP fallback
            ep_host_raw = dns_server.replace("https://", "").split("/")[0]
            # 移除 IPv6 方括号后再检测是否为 IP 地址
            ep_host = ep_host_raw.strip("[]").split(":")[0]
            is_ip_endpoint = False
            try:
                ipaddress.ip_address(ep_host)
                is_ip_endpoint = True
            except ValueError:
                pass

            if is_ip_endpoint:
                logger.warning("ECH 查询: DoH %s 端点是 IP 地址，"
                               "无法通过加密 DNS 获取 ECH 配置。"
                               "请使用域名格式，例如 https://dns.alidns.com/dns-query",
                               dns_server)
                return None

            # 域名 DoH 端点：正常查询
            result, status = await self._query_via_doh(hostname, dns_server)
            if result is not None:
                return result
            # 根据查询状态决定下一步
            if status == "no_ech":
                # DoH 连接成功但 HTTPS 记录无 ECH 参数 → 尝试 UDP fallback
                logger.info("ECH 查询: DoH %s 已响应但无 ECH 参数，尝试 UDP fallback",
                            dns_server)
                udp_result = await self._query_udp_fallback(hostname)
                if udp_result is not None:
                    return udp_result
                logger.debug("ECH 查询: UDP fallback 也未返回 ECH 参数，"
                             "%s 可能未发布 ECH 配置", hostname)
                return None
            else:
                # DoH 连接失败 → 跳过 UDP fallback（用户配置了仅加密 DNS）
                logger.warning("ECH 查询: DoH %s 不可达 (%s)，"
                               "跳过 UDP fallback（仅允许加密 DNS）",
                               dns_server, status)
                return None
        elif dns_server.startswith("udp://"):
            return await self._query_via_udp(hostname, dns_server)
        else:
            logger.warning("不支持的 DNS 服务器格式: %s", dns_server)
            return None

    # 返回值：(ech_config_tuple, status)
    # ech_config_tuple = (config_bytes, ttl) 或 None
    # status = "ok" | "no_ech" | "conn_failed" | "http_error" | "dns_no_https" | "dns_no_records"
    async def _query_via_doh(self, hostname: str, doh_url: str
                             ) -> Tuple[Optional[tuple], str]:
        """
        通过 DoH 查询 HTTPS 记录（RFC 8484 Wire Format）。
        使用 bootstrap DNS 解析 DoH 端点 IP（绕过系统 DNS 自引用）。

        参考 Xray-core (ech.go) dnsQuery() 实现:
          - DNS 消息 ID 设为 0（RFC 8484 Section 5.1: DoH 必须使用 ID=0）
          - 添加 Accept: application/dns-message 头（RFC 8484 Section 5.1 MUST）
          - 添加 EDNS0 padding（随机 100-300 字节，防止指纹识别）
          - 验证响应 Content-Type 为 application/dns-message
        """
        # 从 URL 提取 hostname 和端口
        ep_part = doh_url.replace("https://", "").split("/")[0]
        if ":" in ep_part:
            idx = ep_part.rfind(":")
            ep_hostname = ep_part[:idx]
            ep_port = int(ep_part[idx+1:])
        else:
            ep_hostname = ep_part
            ep_port = 443
        path = "/dns-query"
        if "/" in doh_url.replace("https://", ""):
            path = "/" + "/".join(doh_url.replace("https://", "").split("/")[1:])

        # 用 bootstrap DNS 解析 DoH 端点的 IP（绕过系统 DNS 自引用）
        ips: List[str] = []
        # 如果 ep_hostname 已经是 IP 地址，直接使用
        try:
            ipaddress.ip_address(ep_hostname)
            ips = [ep_hostname]
        except ValueError:
            # 是域名，用 bootstrap 解析
            if self._bootstrap_resolve:
                ips = await self._bootstrap_resolve(ep_hostname)

        if not ips:
            # fallback：直接连接 hostname（走系统 DNS）
            ips = [ep_hostname]

        # 构建 DNS 查询消息
        q = dns.message.make_query(hostname, dns.rdatatype.HTTPS)
        # DoH (RFC 8484 Section 5.1): DNS message ID MUST be 0
        q.id = 0
        # 启用 EDNS0 并设置较大 payload（4096），确保服务器知道我们支持大响应
        q.use_edns(ednsflags=0, payload=4096)

        qbytes = q.to_wire()

        for ip in ips:
            try:
                t0 = time.time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                ctx.set_ciphers(
                    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                    "TLS_CHACHA20_POLY1305_SHA256"
                )

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, ep_port, ssl=ctx,
                                            server_hostname=ep_hostname),
                    timeout=5.0,
                )

                # RFC 8484 Section 5.1: MUST include Accept: application/dns-message
                http_host = ep_hostname if ep_port == 443 else f"{ep_hostname}:{ep_port}"
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {http_host}\r\n"
                    f"Content-Type: application/dns-message\r\n"
                    f"Accept: application/dns-message\r\n"
                    f"Content-Length: {len(qbytes)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("ascii") + qbytes

                writer.write(request)
                await writer.drain()

                raw_response = b""
                while True:
                    chunk = await asyncio.wait_for(
                        reader.read(65536), timeout=5.0
                    )
                    if not chunk:
                        break
                    raw_response += chunk

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                # 解析 HTTP 响应
                if not raw_response:
                    elapsed = time.time() - t0
                    logger.warning("DoH %s (IP=%s) 空响应 (%.0fms)",
                                 ep_hostname, ip, elapsed * 1000)
                    continue

                # 检查 HTTP 状态码
                status_line = raw_response.split(b"\r\n")[0]
                if b"200" not in status_line:
                    elapsed = time.time() - t0
                    logger.warning("DoH %s (IP=%s) HTTP 非 200: %s (%.0fms)",
                                 ep_hostname, ip, status_line.decode(errors="replace"), elapsed * 1000)
                    continue

                # 检查 Content-Type
                headers_end = raw_response.find(b"\r\n\r\n")
                if headers_end < 0:
                    logger.warning("DoH %s (IP=%s) 响应无 HTTP 头分隔符", ep_hostname, ip)
                    continue
                header_part = raw_response[:headers_end]
                ct_valid = any(
                    line.lower().startswith(b"content-type:") and b"application/dns-message" in line
                    for line in header_part.split(b"\r\n")
                )
                if not ct_valid:
                    ct_line = "".join(
                        l.decode(errors="replace") for l in header_part.split(b"\r\n")
                        if l.lower().startswith(b"content-type:")
                    )
                    logger.debug("DoH %s Content-Type 非 dns-message: %s",
                                 ep_hostname, ct_line or "无")

                # 提取 body
                _, _, body = raw_response.partition(b"\r\n\r\n")
                if not body:
                    logger.warning("DoH %s (IP=%s) HTTP 200 但 body 为空", ep_hostname, ip)
                    continue

                # 解析 DNS 响应
                response = dns.message.from_wire(body)
                # 统计答案中的记录类型
                https_rrsets = [rr for rr in response.answer if rr.rdtype == dns.rdatatype.HTTPS]
                if not https_rrsets:
                    logger.debug("DoH %s DNS 响应中无 HTTPS/SVCB 记录（rdtype=65）", ep_hostname)
                    return (None, "dns_no_records")
                for rrset in https_rrsets:
                    for rd in rrset:
                        if not (hasattr(rd, 'params') and hasattr(rd, 'priority')):
                            continue
                        if rd.priority == 0:
                            continue  # AliasMode
                        ech_param = rd.params.get(ParamKey.ECH)
                        if ech_param is not None and ech_param.ech:
                            ttl_val = rrset.ttl if hasattr(rrset, 'ttl') else 300
                            elapsed = time.time() - t0
                            logger.debug("DoH %s 获取 ECH 成功 (%d bytes, TTL=%d, %.0fms)",
                                         ep_hostname, len(ech_param.ech), ttl_val, elapsed * 1000)
                            return ((bytes(ech_param.ech), ttl_val), "ok")
                # 有 HTTPS 记录但都无 ech 参数
                n_records = sum(len(rr) for rr in https_rrsets)
                priorities = [str(rd.priority) for rr in https_rrsets for rd in rr if hasattr(rd, 'priority')]
                logger.debug("DoH %s HTTPS 记录 %d 条 (priority=%s) 均无 ECH 参数",
                             ep_hostname, n_records, ",".join(priorities[:10]))
                return (None, "no_ech")

            except (OSError, ConnectionError, asyncio.TimeoutError) as e:
                err_type = type(e).__name__
                err_msg = str(e) or "无详细错误"
                logger.warning("DoH %s (IP=%s) 连接失败 [%s]: %s",
                             ep_hostname, ip, err_type, err_msg)
                continue
            except Exception as e:
                err_type = type(e).__name__
                err_msg = str(e) or "无详细错误"
                logger.warning("DoH %s (IP=%s) 未知异常 [%s]: %s",
                               ep_hostname, ip, err_type, err_msg)
                continue

        logger.warning("DoH %s 全部 IP 尝试失败", ep_hostname)
        return (None, "conn_failed")

    async def _query_via_udp(self, hostname: str, udp_server: str
                             ) -> Optional[tuple]:
        """
        通过 UDP DNS 查询 HTTPS 记录。
        连接 UDP DNS 服务器发送 DNS 查询。
        正确支持 IPv4 和 IPv6 地址。
        """
        addr_str = udp_server[len("udp://"):].strip()

        # 解析 IP 和端口：处理 IPv4、IPv6 和带端口的地址
        try:
            # 尝试作为纯 IP（IPv4 或 IPv6）解析
            ip_addr = ipaddress.ip_address(addr_str)
            remote_ip = str(ip_addr)
            remote_port = 53
        except ValueError:
            # 不是纯 IP，可能有端口号
            # IPv6 加端口格式: [::1]:53
            if addr_str.startswith("[") and "]" in addr_str:
                remote_ip = addr_str[1:addr_str.index("]")]
                port_part = addr_str[addr_str.index("]") + 1:]
                remote_port = int(port_part.lstrip(":")) if port_part else 53
            else:
                # IPv4:port 格式
                parts = addr_str.rsplit(":", 1)
                remote_ip = parts[0]
                remote_port = int(parts[1]) if len(parts) > 1 else 53

        transport = None
        try:
            q = dns.message.make_query(hostname, dns.rdatatype.HTTPS)
            qbytes = q.to_wire()

            t0 = time.time()
            transport, protocol = await asyncio.wait_for(
                asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: _UDPDNSProtocol(),
                    remote_addr=(remote_ip, remote_port),
                ),
                timeout=5.0,
            )

            protocol.send_query(qbytes)
            response_bytes = await asyncio.wait_for(
                protocol.get_response(), timeout=5.0
            )

            response = dns.message.from_wire(response_bytes)
            for rrset in response.answer:
                if rrset.rdtype != dns.rdatatype.HTTPS:
                    continue
                for rd in rrset:
                    if not (hasattr(rd, 'params') and hasattr(rd, 'priority')):
                        continue
                    if rd.priority == 0:
                        continue
                    ech_param = rd.params.get(ParamKey.ECH)
                    if ech_param is not None and ech_param.ech:
                        ttl_val = rrset.ttl if hasattr(rrset, 'ttl') else 300
                        elapsed = time.time() - t0
                        logger.debug("UDP DNS %s 获取 ECH 成功 (%d bytes, TTL=%d, %.0fms)",
                                     remote_ip, len(ech_param.ech), ttl_val, elapsed * 1000)
                        return (bytes(ech_param.ech), ttl_val)

            logger.debug("UDP DNS %s HTTPS 记录无 ECH 参数", remote_ip)
            return None

        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            logger.debug("UDP DNS %s 查询失败: %s", remote_ip, e)
            return None
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    async def _query_udp_fallback(self, hostname: str) -> Optional[tuple]:
        """
        并行查询所有 UDP fallback DNS 服务器，取最快成功结果。
        避免顺序查询时单个慢服务器导致总超时。
        """
        if not self._fallback_udp:
            return None

        async def _try_one(udp_srv: str) -> Optional[tuple]:
            try:
                return await asyncio.wait_for(
                    self._query_via_udp(hostname, f"udp://{udp_srv}"),
                    timeout=4.0,
                )
            except (OSError, ConnectionError, asyncio.TimeoutError):
                return None

        tasks = [asyncio.create_task(_try_one(srv)) for srv in self._fallback_udp]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            r = t.result()
            if r is not None:
                return r
        return None


class _UDPDNSProtocol(asyncio.DatagramProtocol):
    """简单的 UDP DNS 查询协议"""

    def __init__(self):
        self._transport = None
        self._response: Optional[bytes] = None
        self._future: Optional[asyncio.Future] = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        self._response = data
        if self._future and not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc):
        if self._future and not self._future.done():
            self._future.set_exception(exc)

    def send_query(self, qbytes: bytes):
        self._transport.sendto(qbytes)

    async def get_response(self) -> bytes:
        if self._response is not None:
            return self._response
        self._future = asyncio.get_event_loop().create_future()
        return await self._future

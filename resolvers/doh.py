"""
DNS over HTTPS (DoH) 解析器
使用 aiohttp 进行加密 DNS 查询，RFC 8484
支持全局共享 aiohttp.ClientSession，避免每个上游独立连接池的内存浪费

上游协议策略（用户指定）：
  **HTTP/1.1 全部禁用**，只允许 HTTP/3 与 HTTP/2——
  HTTP/3（aioquic）优先，h3 不可用时用 HTTP/2（httpx，ALPN=h2）；
  ALPN 未协商到 h2/h3（服务器只支持 h1.1）时该上游按失败处理，
  绝不静默降级到明文 HTTP/1.1。
"""

import asyncio
import logging
import socket
import ssl
import time
from typing import List, Optional, Tuple, Dict

import aiohttp

from .base import BaseResolver
from .doh3 import DoH3Client, ordered_endpoints

logger = logging.getLogger("dns-proxy.resolver.doh")


class _MultiHostResolver:
    """
    多主机自定义 aiohttp DNS 解析器。
    将多个主机名映射到预解析的 bootstrap IP 列表。
    用于绕过系统 DNS 自引用（127.0.0.1）死锁。
    支持 DoH 多上游共享同一 session 时各自的路由需求。
    """

    def __init__(self):
        self._hostname_ips: Dict[str, List[str]] = {}
        self._lock = asyncio.Lock()

    def add_host(self, hostname: str, ips: List[str]):
        """注册一个主机名及其 bootstrap IP 列表"""
        if ips:
            self._hostname_ips[hostname] = ips

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        ips = self._hostname_ips.get(host)
        if ips:
            results = []
            for ip in ips:
                try:
                    family_actual = socket.AF_INET6 if ":" in ip else socket.AF_INET
                    results.append({
                        "hostname": host,
                        "host": ip,
                        "port": port,
                        "family": family_actual,
                        "proto": socket.IPPROTO_TCP,
                        "flags": socket.AI_NUMERICHOST,
                    })
                except Exception as e:
                    logger.debug("MultiHostResolver 获取结果异常: %s", e)
                    continue
            return results
        # 未知主机：返回空列表阻止回退系统 DNS（避免死锁）
        logger.error("_MultiHostResolver: 未知主机 %s，拒绝回退系统 DNS", host)
        return []

    async def close(self):
        pass


class _StaticHostResolver:
    """Static DNS resolver for a single hostname -> pre-resolved IPs."""
    def __init__(self, hostname: str, ips: list):
        self._hostname = hostname
        self._ips = ips

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        if host != self._hostname and host != host.split(':')[0]:
            return []
        results = []
        for ip in self._ips:
            try:
                family_actual = socket.AF_INET6 if ":" in ip else socket.AF_INET
                results.append({
                    "hostname": host,
                    "host": ip,
                    "port": port,
                    "family": family_actual,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                })
            except Exception:
                continue
        return results


class DoHResolver(BaseResolver):
    """DoH 上游解析器（RFC 8484 Wire Format POST）"""

    # 检测当前 Python/OpenSSL 是否支持 ECHClientConfig API
    _HAS_ECH = hasattr(ssl, 'ECHClientConfig')

    def __init__(self, url: str, timeout: float = 5.0, ech_enabled: bool = False,
                 connection_pool_size: int = 100, ech_config: bytes = b"",
                 connect_ips: Optional[List[str]] = None, concurrency: int = 100,
                 ca_path: str = "",
                 shared_session: Optional[aiohttp.ClientSession] = None,
                 shared_resolver: Optional[_MultiHostResolver] = None,
                 protocols: Optional[Dict[str, bool]] = None,
                 ciphers: str = ""):
        super().__init__(url, timeout, concurrency=concurrency)
        self.url = url
        self._ech_enabled = ech_enabled
        self._connection_pool_size = connection_pool_size
        self._ech_config = ech_config
        # tls.ciphers：所有上游 TLS（DoH/DoT）共用同一份配置；SM2 上游
        # 例外（必须追加国密套件，否则握手失败）。
        self._ciphers = str(ciphers or "")
        self._connect_ips = connect_ips or []
        # 地址族顺序：**IPv6 优先**（与迭代解析根服务器、DoH3 目标选择一致）。
        # 不可用的上游（如境外被阻的 DoH）会因连续失败被健康评分排到波次末尾，
        # 不再参与竞争，所以这里无需按"可达性"预设，保持统一的 v6 优先语义。
        self._connect_ips = sorted(
            self._connect_ips, key=lambda ip: 0 if ":" in str(ip) else 1
        )
        self._ca_path = ca_path
        self._ssl_context = self._create_ssl_context()
        # 共享 session（若提供则使用共享，否则自建）
        self._shared_session = shared_session
        self._shared_resolver = shared_resolver
        self._own_session: Optional[aiohttp.ClientSession] = None
        # httpx 客户端（HTTP/2；HTTP/3 由 doh3.DoH3Client 提供）
        self._http_client = None
        # ---------- 上游协议策略（HTTP/1.1 永久禁用）----------
        raw_protocols = protocols if isinstance(protocols, dict) else {}
        self._use_h2 = bool(raw_protocols.get("http2", True))
        self._use_h3 = bool(raw_protocols.get("http3", True))
        if not (self._use_h2 or self._use_h3):
            self._use_h2 = True  # 两者都关 → 至少保留 h2，否则 DoH 上游无法工作
        # HTTP/3 客户端与「h3 不可用」负缓存：某些上游只监听 TCP/443（不支持
        # h3），握手会一直等到超时；记住失败，一段时间内直接走 h2。
        self._h3_client: Optional[DoH3Client] = None
        self._h3_probe: Optional[asyncio.Future] = None
        # h3 失败一次后本次运行期间永久禁用该上游的 h3（只用 h2）
        self._h3_disabled = False
        self._h3_cooldown_until = 0.0
        self._h3_fail_count = 0
        if not DoH3Client.available():
            self._use_h3 = False
        if ech_enabled and self._use_h3:
            # aioquic 不支持 ECH：走 h3 会让 SNI 明文泄漏，反而削弱 ECH 的意义
            self._use_h3 = False
            logger.debug("DoH %s: ECH 已启用，HTTP/3 关闭（aioquic 不支持 ECH），改走 HTTP/2",
                         url)

        if self._connect_ips:
            logger.info("DoH %s 使用 bootstrap IP: %s", url, ", ".join(self._connect_ips[:4]))

        if ech_enabled and self._HAS_ECH:
            if ech_config:
                logger.info("DoH %s ECH 已启用 (ECHConfigList %d bytes)", url, len(ech_config))
            else:
                logger.info("DoH %s ECH 已启用，但未获取到 ECHConfigList", url)
        elif ech_enabled and not self._HAS_ECH:
            logger.warning("DoH %s ECH 已请求但当前 Python/OpenSSL 不支持", url)

    def _create_ssl_context(self) -> ssl.SSLContext:
        """为 DoH 连接创建 SSL 上下文（CA 证书验证 + ECH 配置）

        安全策略：
        - 如果配置了 ca_path: 创建空 SSL 上下文，**只信任自定义 CA**，完全排除系统默认 CA
          防御系统 CA 已被入侵的 MITM 场景
        - 如果未配置 ca_path: 使用系统默认 CA
        """
        # 检测是否为国密SM2服务器：添加SM2密码套件支持
        is_sm2 = "sm2." in self.url.lower()
        if is_sm2:
            ciphers = ("HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4:"
                       "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-SM4-CBC-SM3:"
                       "ECC-SM2-SM4-GCM-SM3:ECDHE-SM2-SM4-GCM-SM3")
            logger.info("DoH %s: 国密SM2密码套件已启用", self.url)
        else:
            ciphers = (self._ciphers
                       or "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
        if self._ca_path:
            # 自定义 CA 模式：创建空上下文，只加载自定义 CA
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.set_ciphers(ciphers)
            try:
                ctx.load_verify_locations(self._ca_path)
                logger.info("DoH %s: 使用自定义 CA 证书（系统默认 CA 已禁用）", self.url)
            except Exception as e:
                logger.critical(
                    "DoH %s: 加载自定义 CA 证书失败: %s，系统 CA 不可信，程序退出",
                    self.url, e,
                )
                raise SystemExit(1)
        else:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.set_ciphers(ciphers)

        if self._ech_enabled and self._ech_config and self._HAS_ECH:
            try:
                ech_obj = ssl.ECHClientConfig(self._ech_config)
                ctx.set_ech_config(ech_obj)
                logger.debug("DoH %s: ECHConfigList 已配置到 SSL 上下文 (%d bytes)",
                             self.url, len(self._ech_config))
            except Exception as e:
                logger.warning("DoH %s: ECH 配置失败: %s", self.url, e)

        # 当 ECH 启用时，强制 TLS 1.3 only（RFC 8446 标准套件）
        if self._ech_enabled:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphers(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
            )

        return ctx

    def _get_hostname(self) -> str:
        """从 URL 提取主机名（正确支持 IPv6）"""
        addr = self.url.replace("https://", "").split("/")[0]
        # IPv6 地址含多个冒号，直接返回
        if addr.count(":") > 1:
            return addr
        return addr.split(":")[0]

    def _get_session(self) -> aiohttp.ClientSession:
        """
        获取 HTTP 会话。
        优先使用共享 session（如果有），否则创建独立的 session。

        NOTE：上游 DoH 的 HTTP/1.1 路径已按策略禁用（见模块 docstring），
        本方法不再参与查询；保留它是为了共享 session 架构与 close/reset
        流程保持可用（也为将来若需回退 h1.1 留出实现）。
        """
        # 共享 session 模式
        if self._shared_session is not None:
            return self._shared_session

        # 独立 session 模式（向后兼容）
        if self._own_session is None or self._own_session.closed:
            pool_size = max(1, self._connection_pool_size)
            resolver = None
            if self._connect_ips and self._shared_resolver:
                resolver = self._shared_resolver
            elif self._connect_ips:
                from .doh import _StaticHostResolver
                resolver = _StaticHostResolver(self._get_hostname(), self._connect_ips)
            connector = aiohttp.TCPConnector(
                limit=pool_size,
                limit_per_host=max(1, pool_size // 2),
                ttl_dns_cache=300,
                force_close=False,
                ssl=self._ssl_context,
                resolver=resolver,
            )
            self._own_session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
        return self._own_session

    def _get_http_client(self):
        """返回缓存的 httpx AsyncClient（**仅 HTTP/2**）

        HTTP/3 由 ``doh3.DoH3Client``（aioquic）实现，不再依赖 httpx 的实验性
        ``http3`` 参数（httpx 0.28 起已移除）。httpx 在这里只承担 HTTP/2：
        ALPN 协商不到 h2 时它本会降级到 HTTP/1.1，因此 ``_resolve_http2``
        会对响应版本做**强制校验**，h1.1 响应一律丢弃。
        """
        if self._http_client is not None and not self._http_client.is_closed:
            return self._http_client
        import httpx
        verify = self._ssl_context if self._ssl_context is not None else True
        self._http_client = httpx.AsyncClient(
            http2=True, verify=verify, timeout=self.timeout,
        )
        logger.debug("DoH %s: HTTP/2 客户端已创建（HTTP/1.1 已禁用）", self.url)
        return self._http_client

    def _pin_bootstrap_url(self, ip: Optional[str] = None) -> tuple:
        """bootstrap IP 直连 + sni_hostname extension（保留证书校验）。

        避免 h2 路径退回系统 DNS（自引用 127.0.0.1 时递归环 / DNS 污染时绕过
        pinning）。无 bootstrap IP 时返回原 URL。

        ``ip`` 显式指定要直连的 bootstrap IP；为 None 时用列表里第一个可替换的
        （调用方在首选 IP 不可达时会换下一个 IP 重试）。
        """
        if not self._connect_ips:
            return self.url, {}
        hostname = self._get_hostname()
        targets = [ip] if ip else list(self._connect_ips)
        for cand in targets:
            if not cand:
                continue
            ip_txt = cand
            if ":" in ip_txt and not ip_txt.startswith("["):
                ip_txt = f"[{ip_txt}]"
            url = self.url.replace(f"https://{hostname}", f"https://{ip_txt}", 1)
            if url != self.url:
                return url, {"sni_hostname": hostname}
        return self.url, {}

    def _split_url(self) -> tuple:
        """从 DoH URL 拆出 (hostname, port, path)，供 HTTP/3 直连使用

        正确支持 IPv6 字面量（``https://[2001:db8::1]:443/dns-query``）：
        ``_get_hostname()`` 对带端口的 IPv6 会返回 "[ip]:port"，不能直接当 SNI。
        """
        rest = self.url.split("://", 1)[-1]
        hostport, _, tail = rest.partition("/")
        path = "/" + tail if tail else "/dns-query"
        port = 443
        hostname = hostport
        if hostport.startswith("["):
            # [IPv6] 或 [IPv6]:port
            hostname = hostport[1:].split("]", 1)[0]
            after = hostport[hostport.find("]") + 1:]
            if after.startswith(":"):
                try:
                    port = int(after[1:])
                except ValueError:
                    port = 443
        elif hostport.count(":") == 1:
            host, port_s = hostport.split(":", 1)
            hostname = host
            try:
                port = int(port_s)
            except ValueError:
                port = 443
        return hostname, port, path

    def _mark_h3_unavailable(self) -> None:
        """HTTP/3 探测失败 → 该上游**本次运行期间永久**改走 HTTP/2

        依据：服务器是否支持 QUIC/HTTP/3 是静态能力（不像链路抖动）。第一次
        握手失败基本可确定「该域名不监听 UDP/443，或 UDP 被网络屏蔽」，继续定期
        重试只会让每次重试都白等一次握手超时（用户要求：失败一次后该域名不再用
        h3）。进程重启后会重新尝试一次。
        """
        was_disabled = self._h3_disabled
        self._h3_disabled = True
        self._h3_fail_count += 1
        if not was_disabled:
            logger.info(
                "DoH %s: HTTP/3 不可用（首次失败），本次运行期间固定使用 HTTP/2",
                self.url,
            )

    async def _resolve_http3_first(self, query_bytes: bytes,
                                   deadline: float) -> Optional[bytes]:
        """HTTP/3 优先查询（aioquic，QUIC 多流复用）

        失败（含"服务器不支持 h3"的握手超时）→ 永久标记该上游只用 h2（见
        ``_mark_h3_unavailable``），避免每条查询都白等一次握手。

        **single-flight 建连探测**：同一上游可能同时有几十条查询，若每条都各自
        做一次 QUIC 握手，整段波次预算会被重复握手吃光（实测表现为「全部上游
        均失败」）——并发查询共享同一次探测，成功后才各自开流。
        """
        if not self._use_h3 or self._h3_disabled:
            return None
        if deadline - time.monotonic() <= 0.15:
            return None  # 波次预算不足，直接走 h2
        if self._h3_client is None:
            hostname, port, path = self._split_url()
            self._h3_client = DoH3Client(
                hostname=hostname,
                port=port,
                path=path,
                connect_ips=self._connect_ips,
                ca_path=self._ca_path,
                timeout=self.timeout,
            )
        client = self._h3_client
        if not client.connected:
            probe = self._h3_probe
            if probe is None or probe.done():
                probe = asyncio.ensure_future(client.ensure_connected())
                self._h3_probe = probe
            try:
                ok = await asyncio.shield(probe)
            except asyncio.CancelledError:
                raise
            except Exception:
                ok = False
            if not ok:
                self._mark_h3_unavailable()
                return None
        ans = await client.post(query_bytes)
        if ans is not None:
            return ans
        self._mark_h3_unavailable()
        return None

    async def _resolve_http2(self, query_bytes: bytes,
                             deadline: float) -> Optional[bytes]:
        """HTTP/2 查询（httpx，ALPN=h2）

        **强制只接受 HTTP/2**：httpx 在 ALPN 未协商到 h2 时会自动降级 HTTP/1.1，
        而策略要求上游加密 DNS 禁用 HTTP/1.1，因此这里校验响应的
        ``http_version``，非 HTTP/2 一律丢弃（该上游本次按失败处理）。

        候选 IP 用「IPv6 优先 + 跨族兜底」排序（最多 3 个），每个候选只拿
        「剩余预算 / 剩余候选数」——某个地址族的 IP 被阻断时不会叠加成
        N×timeout（实测境外不可达上游会拖到 10-18s），也保证另一族一定有机会。
        """
        try:
            client = self._get_http_client()
        except Exception as e:
            logger.debug("DoH %s HTTP/2 客户端创建失败: %s [%s]",
                         self.url, e, type(e).__name__)
            return None
        import httpx

        if self._connect_ips:
            candidates = ordered_endpoints(self._connect_ips, prefer_v6=True, limit=3)
        else:
            candidates = [None]
        for idx, cand in enumerate(candidates):
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                logger.debug("DoH %s HTTP/2 预算用尽，放弃本次查询", self.url)
                return None
            share = remaining / max(1, len(candidates) - idx)
            url, ext = self._pin_bootstrap_url(cand)
            try:
                resp = await asyncio.wait_for(
                    client.post(
                        url, content=query_bytes,
                        headers={"Content-Type": "application/dns-message"},
                        extensions=ext,
                    ),
                    timeout=share,
                )
            except asyncio.TimeoutError:
                logger.debug("DoH %s HTTP/2 %s 超时（%.2fs），尝试下一个 IP",
                             self.url, cand, share)
                continue
            except httpx.ConnectError as e:
                logger.debug("DoH %s HTTP/2 连接失败（%s）: %s，尝试下一个 IP",
                             self.url, cand, e)
                continue
            except httpx.HTTPError as e:
                logger.debug("DoH %s HTTP/2 请求失败（%s）: %s [%s]",
                             self.url, cand, e, type(e).__name__)
                return None
            except Exception as e:
                logger.debug("DoH %s HTTP/2 路径失败: %s [%s]",
                             self.url, e, type(e).__name__)
                return None
            http_version = getattr(resp, "http_version", "") or ""
            if http_version != "HTTP/2":
                logger.debug(
                    "DoH %s: 协商到的协议为 %s（只允许 HTTP/2、HTTP/3），丢弃该响应",
                    self.url, http_version or "unknown",
                )
                return None
            if resp.status_code != 200:
                logger.debug("DoH %s HTTP/2 HTTP %d", self.url, resp.status_code)
                return None
            if len(resp.content) > 65536:
                logger.debug("DoH %s HTTP/2 响应过大 %d 字节，丢弃", self.url, len(resp.content))
                return None
            return resp.content
        return None

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoH (RFC 8484 Wire Format POST) 查询。

        协议策略（用户指定）：**HTTP/1.1 完全禁用**，优先 HTTP/3 → 其次 HTTP/2。
        两条路径都失败（或服务器只支持 h1.1）→ 返回 None，由上层按失败处理
        （换下一个上游 / 回退其它传输），绝不会静默降级到明文 HTTP/1.1。

        整个 resolve 共用一个总预算（``self.timeout``）：h3 探测 + h2 兜底都在
        预算内完成，避免"h3 探测吃掉全部预算 → 上层波次把 h2 取消 → 全体失败"。
        """
        async with self._semaphore:
            deadline = time.monotonic() + self.timeout
            if self._use_h3:
                ans = await self._resolve_http3_first(query_bytes, deadline)
                if ans is not None:
                    return ans
            if not self._use_h2:
                return None
            return await self._resolve_http2(query_bytes, deadline)

    async def close(self):
        """关闭 HTTP 会话（仅关闭自有 session，不关闭共享 session）"""
        if self._own_session and not self._own_session.closed:
            try:
                await self._own_session.close()
            except Exception as e:
                logger.debug("DoH 解析器关闭会话异常: %s", e)
            self._own_session = None
        # 关闭 httpx 客户端（HTTP/2 路径）
        if self._http_client is not None and not self._http_client.is_closed:
            try:
                await self._http_client.aclose()
            except Exception as e:
                logger.debug("DoH 解析器关闭 httpx 客户端异常: %s", e)
            self._http_client = None
        # 关闭 HTTP/3（QUIC）连接
        if self._h3_client is not None:
            try:
                await self._h3_client.close()
            except Exception as e:
                logger.debug("DoH 解析器关闭 HTTP/3 连接异常: %s", e)
            self._h3_client = None

    async def reset_connections(self):
        """
        重置 DoH 连接。
        网络恢复后强制后续查询创建新连接。
        """
        await self.close()
        logger.debug("DoH %s: 持久连接已重置", self.url)

    async def close_idle(self):
        """关闭自有 session（aiohttp 无"仅关空闲"API，等价于全量重置）。
        共享 session 模式不受影响，由全局 session 管理连接生命周期。"""
        if self._own_session and not self._own_session.closed:
            await self.close()

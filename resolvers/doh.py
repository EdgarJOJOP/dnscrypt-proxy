"""
DNS over HTTPS (DoH) 解析器
使用 aiohttp 进行加密 DNS 查询，RFC 8484
支持全局共享 aiohttp.ClientSession，避免每个上游独立连接池的内存浪费
"""

import asyncio
import logging
import socket
import ssl
from typing import List, Optional, Tuple, Dict

import aiohttp

from .base import BaseResolver

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
                 shared_resolver: Optional[_MultiHostResolver] = None):
        super().__init__(url, timeout, concurrency=concurrency)
        self.url = url
        self._ech_enabled = ech_enabled
        self._connection_pool_size = connection_pool_size
        self._ech_config = ech_config
        self._connect_ips = connect_ips or []
        self._ca_path = ca_path
        self._ssl_context = self._create_ssl_context()
        # 共享 session（若提供则使用共享，否则自建）
        self._shared_session = shared_session
        self._shared_resolver = shared_resolver
        self._own_session: Optional[aiohttp.ClientSession] = None
        # httpx 客户端（HTTP/2 优先；HTTP/3 条件启用），惰性创建并缓存
        self._http_client = None

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
            ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"
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
        """返回缓存的 httpx AsyncClient（HTTP/2 强制；HTTP/3 条件启用）。

        HTTP/3 仅在 httpx 支持 http3 参数（需 httpx[http3] extra + h3 库）时自动启用，
        否则降级为 HTTP/2-only（当前环境即此情况）。

        NOTE（实验性说明）：httpx 的 HTTP/3 支持目前为实验性——0.27.x 曾引入
        `http3` 参数（需 `pip install httpx[http3]` + h3 库），0.28.0 已移除该参数
        （`httpx 0.28.1 does not provide the extra 'http3'`），HTTP/3 预计在
        httpx 1.0 正式应用。此处 try/except 的"条件启用"写法在未来 httpx 1.0
        重新提供 http3 参数（或降级安装 httpx<0.28 + h3）时自动生效，无需改代码。
        """
        if self._http_client is not None and not self._http_client.is_closed:
            return self._http_client
        import httpx
        verify = self._ssl_context if self._ssl_context is not None else True
        try:
            # HTTP/3 条件启用（实验性）：httpx[http3] extra + h3 库存在且 httpx
            # 版本支持 http3 参数（0.27.x）时启用；httpx 0.28+ 移除该参数 →
            # 抛 TypeError 落入 except 降级 HTTP/2；httpx 1.0 正式支持后此处自动启用
            self._http_client = httpx.AsyncClient(
                http2=True, http3=True, verify=verify, timeout=self.timeout,
            )
            logger.debug("DoH %s: HTTP/2+HTTP/3 客户端已创建", self.url)
        except (TypeError, ImportError, ValueError):
            self._http_client = httpx.AsyncClient(
                http2=True, verify=verify, timeout=self.timeout,
            )
            logger.debug("DoH %s: HTTP/3 不可用（httpx 无 http3 支持），HTTP/2 客户端已创建", self.url)
        return self._http_client

    def _pin_bootstrap_url(self) -> tuple:
        """bootstrap IP 直连 + sni_hostname extension（保留证书校验）。

        与 aiohttp 主路径的 _MultiHostResolver IP pinning 语义对齐：避免回退路径走
        系统 DNS（自引用 127.0.0.1 时递归环 / DNS 污染时绕过 pinning）。
        无 bootstrap IP 时返回原 URL。
        """
        if not self._connect_ips:
            return self.url, {}
        hostname = self._get_hostname()
        for ip in self._connect_ips:
            if ":" in ip and not ip.startswith("["):
                ip = f"[{ip}]"
            url = self.url.replace(f"https://{hostname}", f"https://{ip}", 1)
            if url != self.url:
                return url, {"sni_hostname": hostname}
        return self.url, {}

    async def _resolve_http2_first(self, query_bytes: bytes) -> Optional[bytes]:
        """HTTP/2 优先查询（httpx；HTTP/3 由 _get_http_client 条件启用）。

        部分 DoH 服务器（如 doh.onedns.net）只支持 HTTP/2，aiohttp(HTTP/1.1) 会收到
        空响应报 "Bad status line: Expected HTTP/, RTSP/ or ICE/: b''"。httpx http2=True
        亦兼容 HTTP/1.1 服务器（ALPN 不协商 h2 时自动降级）。失败返回 None 走 HTTP/1.1 兜底。
        """
        try:
            client = self._get_http_client()
            url, ext = self._pin_bootstrap_url()
            resp = await client.post(
                url, content=query_bytes,
                headers={"Content-Type": "application/dns-message"},
                extensions=ext,
            )
            if resp.status_code != 200:
                logger.debug("DoH %s HTTP/2 HTTP %d", self.url, resp.status_code)
                return None
            if len(resp.content) > 65536:
                logger.debug("DoH %s HTTP/2 响应过大 %d 字节，丢弃", self.url, len(resp.content))
                return None
            return resp.content
        except asyncio.TimeoutError:
            logger.debug("DoH %s HTTP/2 超时 (timeout=%s)", self.url, self.timeout)
            return None
        except Exception as e:
            logger.debug("DoH %s HTTP/2 优先路径失败: %s [%s]", self.url, e, type(e).__name__)
            return None

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoH (RFC 8484 Wire Format POST) 查询。

        策略（用户指定）：HTTP/2 优先（httpx）→ HTTP/3 条件启用 → HTTP/1.1 兜底（aiohttp）。
        """
        async with self._semaphore:
            # 1) HTTP/2 优先（HTTP/3 条件启用由 _get_http_client 处理）
            ans = await self._resolve_http2_first(query_bytes)
            if ans is not None:
                return ans
            # 2) HTTP/1.1 兜底：aiohttp 共享 session（保留连接池/ECH 架构）
            try:
                session = self._get_session()
                headers = {"Content-Type": "application/dns-message"}
                # 共享 session 模式下，per-request 传入 SSL context；自有 session connector 已自带
                ssl_ctx = self._ssl_context if self._shared_session else None
                async with session.post(
                    self.url, data=query_bytes, headers=headers,
                    ssl=ssl_ctx,
                ) as response:
                    if response.status != 200:
                        logger.debug(
                            "DoH %s HTTP/1.1 HTTP %d", self.url, response.status
                        )
                        return None
                    return await response.read()

            except asyncio.TimeoutError:
                logger.debug("DoH %s HTTP/1.1 超时 (timeout=%s)", self.url, self.timeout)
                return None
            except Exception as e:
                logger.debug(
                    "DoH %s HTTP/1.1 请求失败: %s [%s]",
                    self.url, e, type(e).__name__,
                )
                return None

    async def close(self):
        """关闭 HTTP 会话（仅关闭自有 session，不关闭共享 session）"""
        if self._own_session and not self._own_session.closed:
            try:
                await self._own_session.close()
            except Exception as e:
                logger.debug("DoH 解析器关闭会话异常: %s", e)
            self._own_session = None
        # 关闭 httpx 客户端（HTTP/2/3 路径）
        if self._http_client is not None and not self._http_client.is_closed:
            try:
                await self._http_client.aclose()
            except Exception as e:
                logger.debug("DoH 解析器关闭 httpx 客户端异常: %s", e)
            self._http_client = None

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

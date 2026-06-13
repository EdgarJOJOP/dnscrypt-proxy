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

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoH (RFC 8484 Wire Format POST) 查询"""
        async with self._semaphore:
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
                            "DoH %s HTTP %d", self.url, response.status
                        )
                        return None
                    return await response.read()

            except asyncio.TimeoutError:
                logger.debug("DoH %s 超时 (timeout=%s)", self.url, self.timeout)
                return None
            except Exception as e:
                logger.debug(
                    "DoH %s 请求失败: %s [%s]",
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

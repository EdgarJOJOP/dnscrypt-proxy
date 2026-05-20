"""
DNS over HTTPS (DoH) 解析器
使用 aiohttp 进行加密 DNS 查询，RFC 8484
"""

import asyncio
import logging
import socket
import ssl
from typing import List, Optional, Tuple

import aiohttp

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.doh")


class _StaticHostResolver:
    """
    自定义 aiohttp DNS 解析器，将指定主机名映射到预解析 IP。
    用于绕过系统 DNS 自引用（127.0.0.1）死锁。
    """

    def __init__(self, hostname: str, ips: List[str]):
        self._hostname = hostname
        self._ips = ips

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        if host == self._hostname:
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
        # 非目标主机：返回空列表让 aiohttp 触发连接错误
        # 不要回退系统 DNS（127.0.0.1 死锁）
        logger.error("_StaticHostResolver: 未知主机 %s（目标=%s），拒绝回退系统 DNS", host, self._hostname)
        return []

    async def close(self):
        pass


class DoHResolver(BaseResolver):
    """DoH 上游解析器（RFC 8484 Wire Format POST）"""

    # 检测当前 Python/OpenSSL 是否支持 ECHClientConfig API
    _HAS_ECH = hasattr(ssl, 'ECHClientConfig')

    def __init__(self, url: str, timeout: float = 5.0, ech_enabled: bool = False,
                 connection_pool_size: int = 100, ech_config: bytes = b"",
                 connect_ips: Optional[List[str]] = None):
        super().__init__(url, timeout)
        self.url = url
        self._ech_enabled = ech_enabled
        self._connection_pool_size = connection_pool_size
        self._ech_config = ech_config
        self._connect_ips = connect_ips or []
        self._session: Optional[aiohttp.ClientSession] = None

        if self._connect_ips:
            logger.info("DoH %s 使用 bootstrap IP: %s", url, ", ".join(self._connect_ips[:4]))

        if ech_enabled and self._HAS_ECH:
            if ech_config:
                logger.info("DoH %s ECH 已启用 (ECHConfigList %d bytes)", url, len(ech_config))
            else:
                logger.info("DoH %s ECH 已启用，但未获取到 ECHConfigList", url)
        elif ech_enabled and not self._HAS_ECH:
            logger.warning("DoH %s ECH 已请求但当前 Python/OpenSSL 不支持", url)

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """为 DoH 连接创建 SSL 上下文（应用 ECH 配置）"""
        if not (self._ech_enabled and self._ech_config):
            return None  # 使用 aiohttp 默认 SSL 上下文
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self._HAS_ECH:
            try:
                ech_obj = ssl.ECHClientConfig(self._ech_config)
                ctx.set_ech_config(ech_obj)
                logger.debug("DoH %s: ECHConfigList 已配置到 SSL 上下文 (%d bytes)",
                             self.url, len(self._ech_config))
            except Exception as e:
                logger.warning("DoH %s: ECH 配置失败: %s", self.url, e)
        return ctx

    def _get_hostname(self) -> str:
        """从 URL 提取主机名"""
        return self.url.replace("https://", "").split("/")[0].split(":")[0]

    def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建 HTTP 会话（支持 bootstrap IP 直连）"""
        if self._session is None or self._session.closed:
            ssl_ctx = self._create_ssl_context()
            pool_size = max(1, self._connection_pool_size)
            resolver = None
            if self._connect_ips:
                resolver = _StaticHostResolver(self._get_hostname(), self._connect_ips)
            connector = aiohttp.TCPConnector(
                limit=pool_size,
                limit_per_host=max(1, pool_size // 2),
                ttl_dns_cache=300,
                force_close=False,
                ssl=ssl_ctx,
                resolver=resolver,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
        return self._session

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoH (RFC 8484 Wire Format POST) 查询"""
        async with self._semaphore:
            try:
                session = self._get_session()
                headers = {"Content-Type": "application/dns-message"}
                async with session.post(
                    self.url, data=query_bytes, headers=headers
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
        """关闭 HTTP 会话"""
        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    async def reset_connections(self):
        """
        重置 DoH 连接：关闭当前 aiohttp 会话。
        网络恢复后（如网卡禁用/启用），强制后续查询创建全新会话，
        避免在失效连接池上反复重试。
        """
        await self.close()
        logger.debug("DoH %s: 持久连接已重置，下次查询将创建新会话", self.url)

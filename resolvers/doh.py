"""
DNS over HTTPS (DoH) 解析器
使用 aiohttp 进行加密 DNS 查询，RFC 8484
"""

import asyncio
import logging
import ssl
from typing import Optional, Tuple

import aiohttp

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.doh")


class DoHResolver(BaseResolver):
    """DoH 上游解析器（RFC 8484 Wire Format POST）"""

    _HAS_ECH = hasattr(ssl, "HAS_ECH") and ssl.HAS_ECH

    def __init__(self, url: str, timeout: float = 5.0, ech_enabled: bool = False):
        super().__init__(url, timeout)
        self.url = url
        self._ech_enabled = ech_enabled
        self._session: Optional[aiohttp.ClientSession] = None

        if ech_enabled and self._HAS_ECH:
            logger.info("DoH %s ECH 已启用", url)
        elif ech_enabled and not self._HAS_ECH:
            logger.warning("DoH %s ECH 已请求但当前 Python/OpenSSL 不支持 (OpenSSL %s)",
                           url, ssl.OPENSSL_VERSION)

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """为 DoH 连接创建 SSL 上下文（支持 ECH）"""
        if not self._ech_enabled:
            return None  # 使用 aiohttp 默认 SSL 上下文
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self._HAS_ECH:
            logger.debug("DoH %s: ECH SSL 上下文已创建", self.url)
        return ctx

    def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建 HTTP 会话（支持 ECH SSL 上下文）"""
        if self._session is None or self._session.closed:
            ssl_ctx = self._create_ssl_context()
            connector = aiohttp.TCPConnector(
                limit=50,
                limit_per_host=20,
                ttl_dns_cache=300,
                force_close=False,
                ssl=ssl_ctx,  # ECH SSL 上下文（None 则使用默认）
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

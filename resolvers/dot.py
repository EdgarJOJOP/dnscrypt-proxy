"""
DNS over TLS (DoT) 解析器
使用 TLS/SSL 加密的 TCP 连接，RFC 7858
"""

import asyncio
import logging
import ssl
from typing import Optional

import dns.message

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.dot")


class DoTResolver(BaseResolver):
    """DoT 上游解析器（支持 bootstrap IP 直连和双栈）"""

    def __init__(self, host: str, port: int = 853, timeout: float = 5.0, connect_ips: Optional[list] = None):
        super().__init__(host, timeout)
        self.host = host
        self.port = port
        self._connect_ips = connect_ips or []  # bootstrap 缓存的 IP 列表 (v4+v6)
        self._ssl_context = self._create_ssl_context()
        if self._connect_ips:
            logger.info("DoT %s 使用 bootstrap IP: %s", host, ", ".join(self._connect_ips[:4]))

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建 SSL 上下文"""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_ciphers("HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
        return ctx

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 TLS 加密连接解析 DNS（先 hostname 直连，再 fallback bootstrap IP）"""
        # 连接目标：hostname 优先（系统 DNS），bootstrap IP 作为 fallback
        connect_targets = [self.host]
        if self._connect_ips:
            for ip in self._connect_ips:
                if ip != self.host:  # 避免 hostname 同时也是 IP 时重复
                    connect_targets.append(ip)

        async with self._semaphore:
            last_error = None
            is_ip_connect = bool(self._connect_ips)

            for target in connect_targets:
                reader: Optional[asyncio.StreamReader] = None
                writer: Optional[asyncio.StreamWriter] = None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            target,
                            self.port,
                            ssl=self._ssl_context,
                            server_hostname=self.host if is_ip_connect else None,
                        ),
                        timeout=self.timeout,
                    )

                    # DoT 使用 2 字节长度前缀
                    msg_len = len(query_bytes)
                    writer.write(msg_len.to_bytes(2, "big") + query_bytes)
                    await asyncio.wait_for(writer.drain(), timeout=self.timeout)

                    # 读取响应长度
                    raw_len = await asyncio.wait_for(
                        reader.readexactly(2), timeout=self.timeout
                    )
                    resp_len = int.from_bytes(raw_len, "big")

                    # 读取响应内容
                    response_data = await asyncio.wait_for(
                        reader.readexactly(resp_len), timeout=self.timeout
                    )

                    return response_data

                except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError, asyncio.IncompleteReadError) as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("DoT %s (%s) 尝试失败: %s，切换到下一地址", self.host, target, e)
                    continue
                except Exception as e:
                    last_error = e
                    logger.debug("DoT %s (%s) 未知错误: %s", self.host, target, e)
                    continue
                finally:
                    if writer:
                        try:
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                        except (Exception, asyncio.TimeoutError):
                            pass

            # 所有地址都失败
            if isinstance(last_error, asyncio.TimeoutError):
                logger.debug("DoT %s:%d 超时 (timeout=%s)", self.host, self.port, self.timeout)
            elif isinstance(last_error, ConnectionError):
                logger.debug("DoT %s:%d 连接错误: %s", self.host, self.port, last_error)
            elif isinstance(last_error, ssl.SSLError):
                logger.debug("DoT %s:%d SSL错误: %s", self.host, self.port, last_error)
            elif last_error:
                logger.debug("DoT %s:%d 失败: %s [%s]", self.host, self.port, last_error, type(last_error).__name__)
            return None

    async def close(self):
        """DoT 解析器无需持久连接，无需额外清理"""
        pass

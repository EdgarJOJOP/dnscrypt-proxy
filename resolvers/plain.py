"""
普通 DNS 解析器（UDP/TCP）- 支持 UDP 套接字复用
仅在 bootstrap 阶段用于解析 DoH/DoT/DoQ 服务器的 IP 地址
支持地址族偏好（单栈环境下 IPv4-only / IPv6-only 兼容）
"""

import asyncio
import socket
import logging
from typing import Optional

import dns.message
import dns.rdatatype
import dns.asyncquery

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.plain")


class PlainDNSResolver(BaseResolver):
    """普通 DNS 解析器 - 仅用于 bootstrap 解析（UDP 套接字复用）"""

    def __init__(self, address: str, timeout: float = 5.0, concurrency: int = 100):
        super().__init__(address, timeout, concurrency=concurrency)
        self.address = address
        self._is_v6 = ":" in address
        # UDP 套接字复用：一个 socket 持续使用，不每查询创建
        self._sock: Optional[socket.socket] = None
        self._sock_lock = asyncio.Lock()

    def _get_socket(self) -> socket.socket:
        """获取或创建复用的 UDP 套接字（懒惰初始化）。"""
        if self._sock is None:
            family = socket.AF_INET6 if self._is_v6 else socket.AF_INET
            self._sock = socket.socket(family, socket.SOCK_DGRAM)
            self._sock.setblocking(False)
        return self._sock

    async def resolve(self, query_bytes: bytes, prefer_family: str = "") -> Optional[bytes]:
        """
        通过复用 UDP 套接字解析 DNS（失败后 TCP 回退）。

        Args:
            query_bytes: DNS 查询字节
            prefer_family: 地址族偏好，"v4" 或 "v6"，空字符串表示自动
        """
        async with self._semaphore:
            if prefer_family:
                is_v6_target = ":" in self.address
                if prefer_family == "v4" and is_v6_target:
                    await asyncio.sleep(0)
                    return None
                if prefer_family == "v6" and not is_v6_target:
                    await asyncio.sleep(0)
                    return None

            # UDP 查询（套接字复用）
            result = await self._resolve_udp(query_bytes)
            if result is not None:
                return result

            # TCP 回退（仅降级，不保持）
            try:
                query = dns.message.from_wire(query_bytes)
                response = await dns.asyncquery.tcp(
                    query, self.address, timeout=self.timeout
                )
                return response.to_wire()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                return None
            except Exception:
                return None

    async def _resolve_udp(self, query_bytes: bytes) -> Optional[bytes]:
        """通过复用 UDP 套接字发送并接收 DNS 查询。"""
        try:
            async with self._sock_lock:
                sock = self._get_socket()
                loop = asyncio.get_running_loop()
                # 发送
                addr = (self.address, 53, 0, 0) if self._is_v6 else (self.address, 53)
                await loop.sock_sendto(sock, query_bytes, addr)
                # 接收（带超时）
                try:
                    data, _ = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 65535),
                        timeout=self.timeout,
                    )
                    return data
                except asyncio.TimeoutError:
                    logger.debug("PlainDNS %s UDP 查询超时", self.address)
                    # 超时后 drain socket：清空 OS 缓冲区中的过期响应
                    sock.setblocking(False)
                    try:
                        while True:
                            sock.recvfrom(65535)
                    except BlockingIOError:
                        pass
                    finally:
                        sock.setblocking(False)
                    return None
        except OSError as e:
            logger.debug("PlainDNS %s UDP 错误: %s", self.address, e)
            return None
        except Exception:
            return None

    async def close(self):
        """关闭复用的 UDP 套接字。"""
        sock = self._sock
        if sock is not None:
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass

    async def close_idle(self):
        """健康检查：关闭并重建 socket（下次查询自动重建）。"""
        await self.close()

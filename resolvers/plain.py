"""
普通 DNS 解析器（UDP/TCP）
仅在 bootstrap 阶段用于解析 DoH/DoT/DoQ 服务器的 IP 地址
支持地址族偏好（单栈环境下 IPv4-only / IPv6-only 兼容）
"""

import asyncio
import socket
from typing import Optional

import dns.asyncquery
import dns.message
import dns.rdatatype

from .base import BaseResolver


class PlainDNSResolver(BaseResolver):
    """普通 DNS 解析器 - 仅用于 bootstrap 解析"""

    def __init__(self, address: str, timeout: float = 5.0, concurrency: int = 100):
        super().__init__(address, timeout, concurrency=concurrency)
        self.address = address
        # 检测地址族
        self._is_v6 = ":" in address

    async def resolve(self, query_bytes: bytes, prefer_family: str = "") -> Optional[bytes]:
        """
        通过 UDP（失败后 TCP 回退）解析 DNS

        Args:
            query_bytes: DNS 查询字节
            prefer_family: 地址族偏好，"v4" 或 "v6"，空字符串表示自动
        """
        async with self._semaphore:
            # 如果网络环境不支持该 bootstrap 地址的协议族，跳过
            if prefer_family:
                is_v6_target = ":" in self.address
                if prefer_family == "v4" and is_v6_target:
                    await asyncio.sleep(0)  # 让出控制权
                    return None
                if prefer_family == "v6" and not is_v6_target:
                    await asyncio.sleep(0)
                    return None

            try:
                query = dns.message.from_wire(query_bytes)
                # UDP 查询
                response = await dns.asyncquery.udp(
                    query, self.address, timeout=self.timeout
                )
                return response.to_wire()
            except (OSError, ConnectionError, asyncio.TimeoutError):
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
            except Exception:
                return None

    async def close(self):
        pass

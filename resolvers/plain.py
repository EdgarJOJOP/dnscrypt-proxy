"""
普通 DNS 解析器（UDP/TCP）
仅在 bootstrap 阶段用于解析 DoH/DoT/DoQ 服务器的 IP 地址
"""

from typing import Optional

import dns.asyncquery
import dns.message
import dns.rdatatype

from .base import BaseResolver


class PlainDNSResolver(BaseResolver):
    """普通 DNS 解析器 - 仅用于 bootstrap 解析"""

    def __init__(self, address: str, timeout: float = 5.0):
        super().__init__(address, timeout)
        self.address = address

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """
        通过 UDP（失败后 TCP 回退）解析 DNS
        """
        async with self._semaphore:
            try:
                query = dns.message.from_wire(query_bytes)
                # 优先使用 UDP
                response = await dns.asyncquery.udp(
                    query, self.address, timeout=self.timeout
                )
                return response.to_wire()
            except Exception:
                try:
                    query = dns.message.from_wire(query_bytes)
                    response = await dns.asyncquery.tcp(
                        query, self.address, timeout=self.timeout
                    )
                    return response.to_wire()
                except Exception:
                    return None

    async def close(self):
        pass

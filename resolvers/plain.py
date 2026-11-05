"""
普通 DNS 解析器（UDP/TCP）- 用于 bootstrap 阶段解析 DoH/DoT/DoQ 服务器的 IP
支持地址族偏好（单栈环境下 IPv4-only / IPv6-only 兼容）

**每次查询独立 UDP 套接字 + 响应 ID 校验**：
bootstrap 会并发解析十几台上游域名（A+AAAA 各一条），若复用同一个 UDP
socket，多个并发 recvfrom 会共享同一个接收队列——谁先被调度谁就拿到"最新
一个数据报"，应答与查询不匹配，于是 A 域名的 IP 被写进 B 域名（实测：
doh.pub 拿到 Cloudflare 的 IP），后续 TLS 证书 Hostname mismatch，全部
加密上游一起失败。改为每次查询一个 connected UDP socket（内核按
remote_addr 过滤来源）并校验响应 ID。
"""

import asyncio
import logging
from typing import Optional

import dns.message
import dns.rdatatype
import dns.asyncquery

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.plain")


def _consume_future_exc(fut: asyncio.Future) -> None:
    """消费 future 的异常（消除 asyncio 的 "never retrieved" ERROR 刷屏）

    UDP transport 的 ``connection_lost`` 是异步回调，可能在调用方已经放弃等待
    之后才给 future 设 ``ConnectionError('datagram closed')``。
    """
    if fut.cancelled():
        return
    try:
        fut.exception()
    except Exception:
        pass


class _BootstrapUdpProtocol(asyncio.DatagramProtocol):
    """单次 bootstrap UDP 查询：收到首个数据报即完成 future

    transport 用 remote_addr 连接，来源地址由内核过滤；上层仍校验响应 ID，
    双保险防串包/伪造。取消时由调用方关闭 transport。
    """

    __slots__ = ("future", "transport")

    def __init__(self):
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()
        # 同 _UdpQueryProtocol：异步 connection_lost 可能在被放弃后才设异常
        self.future.add_done_callback(_consume_future_exc)
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        # Windows 上 ICMP 端口不可达会以 ConnectionRefusedError 形式到这里
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_exception(exc or ConnectionError("datagram closed"))


class PlainDNSResolver(BaseResolver):
    """普通 DNS 解析器 - 仅用于 bootstrap 解析（每查询独立 UDP 套接字）"""

    def __init__(self, address: str, timeout: float = 5.0, concurrency: int = 100):
        super().__init__(address, timeout, concurrency=concurrency)
        self.address = address
        self._is_v6 = ":" in address

    async def resolve(self, query_bytes: bytes, prefer_family: str = "") -> Optional[bytes]:
        """
        通过 UDP 解析 DNS（失败后 TCP 回退）。

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

            # UDP 查询（每次独立套接字）
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
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("PlainDNS %s error: %s", self.address, e)
                return None

    async def _resolve_udp(self, query_bytes: bytes) -> Optional[bytes]:
        """单次 UDP 查询：独立 connected socket + 响应 ID 校验（防并发串包）"""
        try:
            expect_id = int.from_bytes(query_bytes[:2], "big")
        except Exception:
            expect_id = None
        loop = asyncio.get_running_loop()
        transport = None
        protocol = None
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                _BootstrapUdpProtocol,
                remote_addr=(self.address, 53),
            )
            transport.sendto(query_bytes)
            data = await asyncio.wait_for(protocol.future, timeout=self.timeout)
            if expect_id is not None and len(data) >= 2:
                if int.from_bytes(data[:2], "big") != expect_id:
                    logger.debug("PlainDNS %s 响应 ID 不匹配，丢弃", self.address)
                    return None
            return data
        except (asyncio.TimeoutError, OSError):
            logger.debug("PlainDNS %s UDP 查询超时/失败", self.address)
            return None
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        finally:
            if protocol is not None:
                fut = protocol.future
                if not fut.done():
                    # 取消/异常路径：避免 "Future exception was never retrieved"
                    fut.cancel()
                elif not fut.cancelled():
                    # 已完成仍带异常时消费掉，否则 asyncio 会打 ERROR 刷屏
                    try:
                        fut.exception()
                    except Exception:
                        pass
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    async def close(self):
        """无持久连接（每查询独立套接字），占位保持接口一致"""
        pass

    async def close_idle(self):
        """无持久连接，占位保持接口一致"""
        pass

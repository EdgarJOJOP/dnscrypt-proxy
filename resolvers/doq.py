"""
DNS over QUIC (DoQ) 解析器
基于 QUIC 协议的加密 DNS，RFC 9250
使用 aioquic.asyncio.connect() 高层 API
"""

import asyncio
import logging
import struct
from typing import Optional

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.doq")

# aioquic 为可选依赖
try:
    from aioquic.asyncio import connect as aioquic_connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent, StreamDataReceived, HandshakeCompleted, ConnectionTerminated
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False

# 仅在 aioquic 可用时定义 DnsClientProtocol，防止模块级 NameError
if HAS_AIOQUIC:

    class DnsClientProtocol(QuicConnectionProtocol):
        """DoQ 客户端协议（基于 aioquic 的 QuicConnectionProtocol）"""

        def __init__(self, quic, query_bytes, response_future, stream_handler=None):
            super().__init__(quic, stream_handler=stream_handler)
            self._query_bytes = query_bytes
            self._response_future = response_future
            self._response_data = bytearray()
            self._query_sent = False

        def quic_event_received(self, event: QuicEvent):
            """处理 QUIC 事件（由 QuicConnectionProtocol 自动调用）"""
            if isinstance(event, HandshakeCompleted) and not self._query_sent:
                self._query_sent = True
                stream_id = self._quic.get_next_available_stream_id()
                # DoQ (RFC 9250) 要求 DNS 消息前加 2 字节长度前缀
                query_frame = struct.pack("!H", len(self._query_bytes)) + self._query_bytes
                self._quic.send_stream_data(
                    stream_id, query_frame, end_stream=True
                )
                logger.debug("DoQ 握手完成，发送 DNS 查询 (stream %d, %d bytes)",
                             stream_id, len(self._query_bytes))

            elif isinstance(event, StreamDataReceived):
                # DoQ (RFC 9250) 响应前 2 字节是长度前缀，之后是 DNS 消息
                payload = event.data
                if len(payload) >= 2:
                    msg_len = struct.unpack("!H", payload[:2])[0]
                    dns_data = payload[2:2 + msg_len]
                    self._response_data.extend(dns_data)
                if event.end_stream:
                    if not self._response_future.done():
                        self._response_future.set_result(bytes(self._response_data))
                    logger.debug("DoQ 收到 DNS 响应 (%d bytes)", len(self._response_data))

            elif isinstance(event, ConnectionTerminated):
                reason = event.reason_phrase or "unknown"
                logger.debug("DoQ 连接终止: %s (code %d)", reason, event.error_code)
                if not self._response_future.done():
                    self._response_future.set_result(None)


class DoQResolver(BaseResolver):
    """DoQ 上游解析器（基于 aioquic.asyncio.connect）"""

    def __init__(self, address: str, timeout: float = 15.0,
                 connect_ips: Optional[list] = None):
        super().__init__(address, timeout)
        # 解析 quic://host:port 格式
        raw = address.replace("quic://", "")
        if ":" in raw:
            self.host, port_str = raw.split(":")
            self.port = int(port_str)
        else:
            self.host = raw
            self.port = 853
        self._connect_ips = connect_ips or []
        self._configs: dict = {}  # target -> QuicConfiguration
        if not HAS_AIOQUIC:
            logger.warning("DoQ %s: aioquic 未安装，此上游不可用", self.host)
        elif self._connect_ips:
            logger.info("DoQ %s 使用 bootstrap IP: %s", self.host, ", ".join(self._connect_ips[:4]))

    def _get_config(self, server_name: str) -> Optional["QuicConfiguration"]:
        """创建 QUIC 配置（每个连接目标一个实例）"""
        if not HAS_AIOQUIC:
            return None
        if server_name not in self._configs or self._configs[server_name] is None:
            config = QuicConfiguration(
                alpn_protocols=["doq"],
                is_client=True,
                verify_mode=True,
                server_name=self.host,  # SNI 始终用原主机名
            )
            config.max_data = 10000000
            config.max_stream_data = 1000000
            config.idle_timeout = self.timeout
            self._configs[server_name] = config
        return self._configs[server_name]

    async def _do_quic_query(self, target: str, query_bytes: bytes,
                              response_future: asyncio.Future) -> Optional[bytes]:
        """向指定 target (hostname/IP) 发起 QUIC 查询"""
        config = self._get_config(target)
        if config is None:
            return None

        async with aioquic_connect(
            host=target,
            port=self.port,
            configuration=config,
            create_protocol=lambda quic, **kwargs: DnsClientProtocol(
                quic, query_bytes, response_future
            ),
            wait_connected=True,
        ):
            result = await asyncio.wait_for(
                response_future, timeout=self.timeout
            )
            return result

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 QUIC 连接解析 DNS（支持 bootstrap IP fallback）"""
        if not HAS_AIOQUIC:
            return None

        # 构建连接目标列表：hostname 优先，bootstrap IP 作为 fallback
        connect_targets = [self.host]
        if self._connect_ips:
            for ip in self._connect_ips:
                if ip != self.host:
                    connect_targets.append(ip)

        async with self._semaphore:
            last_error = None
            for target in connect_targets:
                loop = asyncio.get_running_loop()
                response_future: asyncio.Future[Optional[bytes]] = loop.create_future()
                try:
                    return await self._do_quic_query(target, query_bytes, response_future)
                except asyncio.TimeoutError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("DoQ %s (%s) 超时，切换到下一地址", self.host, target)
                    continue
                except ConnectionError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("DoQ %s (%s) 连接失败，切换到下一地址", self.host, target)
                    continue
                except OSError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("DoQ %s (%s) 系统错误，切换到下一地址", self.host, target)
                    continue
                except Exception as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("DoQ %s (%s) 未知错误，切换到下一地址", self.host, target)
                    continue
                finally:
                    if not response_future.done():
                        response_future.cancel()
                    else:
                        try:
                            exc = response_future.exception()
                            if exc is not None:
                                logger.debug("DoQ response_future 异常已消费: %s", exc)
                        except (asyncio.CancelledError, Exception):
                            pass

            # 所有地址都失败
            if isinstance(last_error, asyncio.TimeoutError):
                logger.warning("DoQ %s:%d 超时 (timeout=%s)", self.host, self.port, self.timeout)
            elif isinstance(last_error, ConnectionError):
                logger.warning("DoQ %s:%d 连接失败: %s", self.host, self.port, last_error)
            elif isinstance(last_error, OSError):
                logger.warning("DoQ %s:%d 系统错误: %s", self.host, self.port, last_error)
            elif last_error:
                logger.warning("DoQ %s:%d 未知错误: %s [%s]", self.host, self.port, last_error, type(last_error).__name__)
            return None

    async def close(self):
        """清理所有 QUIC 配置"""
        self._configs.clear()

    async def reset_connections(self):
        """重置 DoQ：清除 QUIC 配置，下次查询重建"""
        self._configs.clear()
        logger.debug("DoQ %s:%d: QUIC 配置已重置", self.host, self.port)

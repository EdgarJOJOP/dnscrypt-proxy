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

    def __init__(self, address: str, timeout: float = 15.0):
        super().__init__(address, timeout)
        # 解析 quic://host:port 格式
        raw = address.replace("quic://", "")
        if ":" in raw:
            self.host, port_str = raw.split(":")
            self.port = int(port_str)
        else:
            self.host = raw
            self.port = 853
        self._config: Optional[QuicConfiguration] = None

    def _get_config(self) -> Optional[QuicConfiguration]:
        """创建 QUIC 配置"""
        if not HAS_AIOQUIC:
            return None
        if self._config is None:
            self._config = QuicConfiguration(
                alpn_protocols=["doq"],
                is_client=True,
                verify_mode=True,
                server_name=self.host,
            )
            self._config.max_data = 10000000
            self._config.max_stream_data = 1000000
            self._config.idle_timeout = self.timeout
        return self._config

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 QUIC 连接解析 DNS"""
        if not HAS_AIOQUIC:
            return None

        config = self._get_config()
        if config is None:
            return None

        async with self._semaphore:
            loop = asyncio.get_running_loop()
            response_future: asyncio.Future[Optional[bytes]] = loop.create_future()

            try:
                # 使用 aioquic 的 asyncio.connect 高层 API
                async with aioquic_connect(
                    host=self.host,
                    port=self.port,
                    configuration=config,
                    create_protocol=lambda quic, **kwargs: DnsClientProtocol(
                        quic, query_bytes, response_future
                    ),
                    wait_connected=True,
                ) as client:
                    result = await asyncio.wait_for(
                        response_future, timeout=self.timeout
                    )
                    return result

            except asyncio.TimeoutError:
                logger.warning(
                    "DoQ %s:%d 超时 (timeout=%s)", self.host, self.port, self.timeout
                )
                return None
            except ConnectionError as e:
                logger.warning(
                    "DoQ %s:%d 连接失败: %s", self.host, self.port, e
                )
                return None
            except OSError as e:
                logger.warning(
                    "DoQ %s:%d 系统错误 (UDP 端口可能被拦截): %s",
                    self.host, self.port, e,
                )
                return None
            except Exception as e:
                logger.warning(
                    "DoQ %s:%d 未知错误: %s [%s]",
                    self.host, self.port, e, type(e).__name__,
                )
                return None
            finally:
                # 消费 response_future 的异常，避免 "Future exception was never retrieved"
                if not response_future.done():
                    response_future.cancel()
                else:
                    try:
                        exc = response_future.exception()
                        if exc is not None:
                            logger.debug("DoQ response_future 异常已消费: %s", exc)
                    except (asyncio.CancelledError, Exception):
                        pass

    async def close(self):
        """清理 QUIC 配置"""
        self._config = None

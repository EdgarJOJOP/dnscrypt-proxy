"""
DNS over QUIC (DoQ) 解析器
- 强制 Transaction ID = 0（RFC 9250）
- 标准 ALPN "doq"（不尝试 doq-i11/dq 等旧版本）
- 2 字节长度前缀（RFC 9250 标准）
- 支持 0-RTT 快速重连
"""
import asyncio
import logging
import ssl
import struct
import time
from typing import List, Optional

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.doq")

try:
    from aioquic.asyncio import connect as aioquic_connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import (
        QuicEvent,
        StreamDataReceived,
        HandshakeCompleted,
        ConnectionTerminated,
    )
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False

# 只使用标准ALPN "doq"（RFC 9250），不尝试旧版本
DEFAULT_ALPN_VERSIONS = ["doq"]


def force_dns_id_zero(query: bytes) -> bytes:
    """RFC 9250: DoQ消息的Transaction ID必须为0"""
    if len(query) >= 2:
        return b'\x00\x00' + query[2:]
    return query


# 每次连接尝试的超时（单个 IP + 单个模式的尝试，非总超时）
_ATTEMPT_TIMEOUT = 5.0


if HAS_AIOQUIC:

    class DnsClientProtocol(QuicConnectionProtocol):
        """DoQ客户端协议，支持0-RTT和normal模式"""

        def __init__(self, quic, query_bytes, response_future,
                     use_length_prefix: bool = True,
                     try_early: bool = False):
            super().__init__(quic)
            self._query_bytes = query_bytes
            self._response_future = response_future
            self._recv_buffer = bytearray()
            self._use_length_prefix = use_length_prefix
            self._response_received = False
            self._try_early = try_early

            if try_early:
                logger.debug("0-RTT模式：立即尝试发送查询（握手完成前）")
                self._try_send_query()
            else:
                logger.debug("等待握手完成后再发送查询")

        def _try_send_query(self):
            try:
                stream_id = self._quic.get_next_available_stream_id()
            except Exception:
                logger.warning("无法获取QUIC流ID，跳过发送")
                return

            if self._use_length_prefix:
                frame = struct.pack("!H", len(self._query_bytes)) + self._query_bytes
            else:
                frame = self._query_bytes

            logger.debug("发送DNS查询 (stream %d, %d bytes, 前缀=%s, 模式=%s)",
                         stream_id, len(frame),
                         "带前缀" if self._use_length_prefix else "无前缀",
                         "0-RTT" if self._try_early else "normal")

            self._quic.send_stream_data(stream_id, frame, end_stream=True)

        def quic_event_received(self, event: QuicEvent):
            try:
                if isinstance(event, HandshakeCompleted):
                    logger.debug("握手完成 (early_data_accepted=%s)", event.early_data_accepted)
                    if not self._try_early:
                        self._try_send_query()

                elif isinstance(event, StreamDataReceived):
                    self._recv_buffer.extend(event.data)
                    if event.end_stream:
                        if self._use_length_prefix and len(self._recv_buffer) >= 2:
                            length = struct.unpack("!H", self._recv_buffer[:2])[0]
                            dns_data = bytes(self._recv_buffer[2:2 + length])
                        else:
                            dns_data = bytes(self._recv_buffer)

                        if dns_data:
                            self._response_received = True
                            if not self._response_future.done():
                                self._response_future.set_result(dns_data)
                        else:
                            if not self._response_future.done():
                                self._response_future.set_exception(
                                    ConnectionError("无效的DoQ响应")
                                )

                elif isinstance(event, ConnectionTerminated):
                    if self._response_received:
                        return
                    reason = event.reason_phrase or "unknown"
                    logger.debug("连接终止: code=%d reason=%s", event.error_code, reason)
                    if not self._response_future.done():
                        self._response_future.set_exception(
                            ConnectionError(f"DoQ连接关闭: code={event.error_code}, reason={reason}")
                        )
            except Exception:
                pass


class DoQResolver(BaseResolver):
    """符合RFC 9250的DoQ解析器（支持0-RTT）"""

    def __init__(self, address: str, timeout: float = 15.0,
                 connect_ips: Optional[list] = None, concurrency: int = 100,
                 verify_cert: bool = True,
                 alpn_versions: Optional[List[str]] = None):
        super().__init__(address, timeout, concurrency=concurrency)
        raw = address.replace("quic://", "")
        if ":" in raw:
            self.host, port_str = raw.split(":")
            self.port = int(port_str)
        else:
            self.host = raw
            self.port = 853
        self._verify_cert = verify_cert
        self._connect_ips = connect_ips or []
        self._alpn_versions = alpn_versions or DEFAULT_ALPN_VERSIONS

        if not HAS_AIOQUIC:
            logger.warning("aioquic未安装，DoQ %s不可用", self.host)

        self._config_cache = {}  # 缓存QUIC配置

    def _get_config(self, alpn: str) -> Optional["QuicConfiguration"]:
        if not HAS_AIOQUIC:
            return None

        # 缓存避免重复创建
        cache_key = (self.host, alpn, self._verify_cert)
        if cache_key in self._config_cache:
            return self._config_cache[cache_key]

        verify = ssl.CERT_REQUIRED if self._verify_cert else ssl.CERT_NONE
        config = QuicConfiguration(
            alpn_protocols=[alpn],
            is_client=True,
            verify_mode=verify,
            server_name=self.host,
        )
        # 启用0-RTT：设置最大早期数据大小（非零值）
        config.max_early_data = 0xffffffff  # 允许发送任意大小的early data
        config.max_data = 10_000_000
        config.max_stream_data = 1_000_000
        config.idle_timeout = self.timeout
        config.cache = None  # 禁用会话缓存，避免重复使用旧session ticket

        self._config_cache[cache_key] = config
        return config

    async def _do_quic_query(self, target: str, query_bytes: bytes,
                             response_future: asyncio.Future,
                             alpn: str,
                             use_length_prefix: bool = True,
                             try_early: bool = False) -> Optional[bytes]:
        config = self._get_config(alpn)
        if config is None:
            return None

        try:
            async with aioquic_connect(
                host=target,
                port=self.port,
                configuration=config,
                create_protocol=lambda quic, **kwargs: DnsClientProtocol(
                    quic, query_bytes, response_future,
                    use_length_prefix=use_length_prefix,
                    try_early=try_early
                ),
                wait_connected=True,
            ):
                result = await asyncio.wait_for(response_future, timeout=self.timeout)
                return result
        except ConnectionError as e:
            raise

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        if not HAS_AIOQUIC:
            return None

        # RFC 9250: Transaction ID 必须为 0
        fixed_query = force_dns_id_zero(query_bytes)

        targets = [self.host]
        for ip in self._connect_ips:
            if ip not in targets:
                targets.append(ip)

        # 标准 DoQ：只试 2 种发送模式，都用 2 字节长度前缀（RFC 9250 标准）
        # 先试正常模式（握手后发），再试 0-RTT（握手前发）
        # 不做无前缀尝试（所有主流服务器都支持前缀）
        modes = [("握手后", False), ("0-RTT", True)]

        async with self._semaphore:
            last_error = None
            for target in targets:
                for mode_name, try_early in modes:
                    loop = asyncio.get_running_loop()
                    future = loop.create_future()
                    t0 = time.monotonic()
                    try:
                        logger.debug("尝试 %s:%s  模式=%s", target, self.port, mode_name)
                        result = await asyncio.wait_for(
                            self._do_quic_query(
                                target, fixed_query, future,
                                alpn=self._alpn_versions[0],
                                use_length_prefix=True,
                                try_early=try_early,
                            ),
                            timeout=_ATTEMPT_TIMEOUT,
                        )
                        if result:
                            elapsed = (time.monotonic() - t0) * 1000
                            logger.info("DoQ %s 成功 [%.0fms] 模式=%s", self.host, elapsed, mode_name)
                            return result
                    except asyncio.TimeoutError:
                        elapsed = (time.monotonic() - t0) * 1000
                        last_error = asyncio.TimeoutError(f"超时 {elapsed:.0f}ms")
                        logger.debug("DoQ %s 超时 [%.0fms] 模式=%s", target, elapsed, mode_name)
                    except ConnectionError as e:
                        last_error = e
                        logger.debug("DoQ %s 连接失败 [模式=%s]: %s", target, mode_name, e)
                        # 证书错误直接跳过该目标
                        err_lower = str(e).lower()
                        if "certificate" in err_lower or "hostname" in err_lower:
                            logger.warning("%s 证书验证失败，跳过", target)
                            break
                    except Exception as e:
                        last_error = e
                        logger.debug("DoQ %s 未知错误 [模式=%s]: %s", target, mode_name, e)
                    finally:
                        if not future.done():
                            future.cancel()
                        else:
                            # 抑制 "Future exception was never retrieved" 警告
                            # 超时取消时，QUIC 断开事件的 set_exception 可能已兑现 future
                            try:
                                future.exception()
                            except Exception:
                                pass

                # 证书错误跳过后续目标
                if last_error and "hostname" in str(last_error).lower():
                    break

            if last_error:
                logger.warning("DoQ %s 所有尝试均失败: %s", self.host, last_error)
            return None

    async def close(self):
        """关闭所有缓存配置和连接"""
        self._config_cache.clear()
        logger.debug("DoQ解析器 %s 已关闭", self.host)

    async def reset_connections(self):
        """重置连接状态，清空配置缓存使下次建立新连接"""
        self._config_cache.clear()
        logger.debug("DoQ解析器 %s 连接已重置", self.host)
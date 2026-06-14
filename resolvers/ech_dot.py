"""
ECH-enabled DoT 解析器
使用 OpenSSL 4.0 + ctypes 实现真正的 ECH (Encrypted Client Hello) 支持。

原理：
  - 通过 ctypes 直接加载 OpenSSL 4.0 DLL（libssl-4-x64.dll）
  - 使用 SSL_set1_ech_config_list() 设置 ECHConfigList
  - 使用内存 BIO + asyncio 实现非阻塞 TLS
  - 2 字节长度前缀 + DNS 消息（RFC 7858）

当 OpenSSL 4.0 DLL 不可用时，创建此解析器会记录警告并标记不可用。
"""

import asyncio
import logging
import ssl as py_ssl
from typing import Optional

from resolvers.base import BaseResolver
from crypto.ech_fetcher import ECHConfigFetcher
from crypto.openssl_ctypes import OpenSSL4Wrapper

logger = logging.getLogger("dns-proxy.resolver.ech_dot")


class ECHDoTResolver(BaseResolver):
    """DoT 解析器（通过 OpenSSL 4.0 ctypes 实现 ECH）

    每次建立连接前通过 ECHConfigFetcher 获取最新的 ECHConfigList。
    """

    def __init__(self, host: str, port: int = 853, timeout: float = 5.0,
                 ech_fetcher: Optional[ECHConfigFetcher] = None,
                 openssl_wrapper: Optional[OpenSSL4Wrapper] = None,
                 ca_path: Optional[str] = None,
                 ciphers: Optional[str] = None,
                 connect_ips: Optional[list] = None, concurrency: int = 100):
        super().__init__(host, timeout, concurrency=concurrency)
        self.host = host
        self.port = port
        self._ech_fetcher = ech_fetcher
        self._openssl = openssl_wrapper
        self._ca_path = ca_path
        self._ciphers = ciphers
        self._connect_ips = connect_ips or []

        if self._connect_ips:
            logger.info("ECHDoT %s 使用 bootstrap IP: %s", host, ", ".join(self._connect_ips[:4]))

        # 检查是否可用
        if self._openssl is None or not self._openssl.available:
            self._available = False
            logger.warning("ECHDoT %s: OpenSSL 4.0 不可用，ECH DoT 解析器禁用", host)
        elif self._ech_fetcher is None or not self._ech_fetcher.enabled:
            self._available = False
            logger.warning("ECHDoT %s: 未配置 ECHConfigFetcher，ECH DoT 解析器禁用", host)
        else:
            self._available = True
            logger.info("ECHDoT %s:%d: ECH DoT 解析器就绪 (fetcher)",
                        host, port)

    @property
    def available(self) -> bool:
        return self._available

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoT (ECH TLS) 执行 DNS 查询

        通过 bootstrap IP 直连上游（绕过系统 DNS 自引用 127.0.0.1）。
        """
        if not self._available:
            return None

        reader = None
        writer = None
        ssl_ptr = None
        ctx_ptr = None
        bio_in = None
        bio_out = None

        # 构建连接目标列表：hostname 优先，bootstrap IP 作为 fallback
        connect_targets = [self.host]
        if self._connect_ips:
            for ip in self._connect_ips:
                if ip != self.host:
                    connect_targets.append(ip)

        async with self._semaphore:
            last_error = None
            for target in connect_targets:
                try:
                    # 0. 获取最新的 ECHConfigList（每次连接刷新，fetcher 内部有缓存）
                    ech_config = await self._ech_fetcher.get_config()
                    if not ech_config:
                        logger.debug("ECHDoT %s: ECH 配置不可用（fetcher 返回空），跳过", self.host)
                        return None

                    # 1. 建立 ECH TLS 连接（使用 target 直连，绕过系统 DNS）
                    try:
                        reader, writer, ssl_ptr, ctx_ptr, bio_in, bio_out = \
                            await self._openssl.connect_ech(
                                host=self.host,
                                port=self.port,
                                server_hostname=self.host,
                                ech_config=ech_config,
                                ca_path=self._ca_path,
                                ciphers=self._ciphers,
                                timeout=self.timeout,
                                connect_ip=target if target != self.host else None,
                            )
                    except ConnectionError as e:
                        err_msg = str(e)
                        if "illegal parameter" in err_msg or "ECH" in err_msg:
                            logger.warning("ECHDoT %s: ECH \u88ab\u670d\u52a1\u5668\u62d2\u7edd\uff0c"
                                           "\u56de\u9000\u5230 Python SSL\uff08\u65e0 ECH\uff09", self.host)
                            if self._ca_path:
                                py_ctx = py_ssl.SSLContext(py_ssl.PROTOCOL_TLS_CLIENT)
                                py_ctx.check_hostname = True
                                py_ctx.verify_mode = py_ssl.CERT_REQUIRED
                                try:
                                    py_ctx.load_verify_locations(self._ca_path)
                                except Exception as ca_e:
                                    logger.warning("ECHDoT %s: \u52a0\u8f7d\u81ea\u5b9a\u4e49 CA \u5931\u8d25: %s\uff0c"
                                                   "\u4f7f\u7528\u7cfb\u7edf\u9ed8\u8ba4 CA", self.host, ca_e)
                                    py_ctx = py_ssl.create_default_context()
                            else:
                                py_ctx = py_ssl.create_default_context()
                            py_ctx.minimum_version = py_ssl.TLSVersion.TLSv1_3
                            py_ctx.maximum_version = py_ssl.TLSVersion.TLSv1_3
                            py_ctx.set_ciphers(
                                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                "TLS_CHACHA20_POLY1305_SHA256"
                            )
                            target_ip = target if target != self.host else None
                            fallback_ip = target_ip or self.host
                            try:
                                reader, writer = await asyncio.wait_for(
                                    asyncio.open_connection(
                                        fallback_ip, self.port,
                                        ssl=py_ctx,
                                        server_hostname=self.host,
                                    ),
                                    timeout=self.timeout,
                                )
                            except OSError as conn_e:
                                logger.debug("ECHDoT %s: Python SSL \u8fde\u63a5\u5931\u8d25: %s",
                                             self.host, conn_e)
                                raise ConnectionError(str(conn_e))
                            msg_len = len(query_bytes)
                            query_frame = msg_len.to_bytes(2, "big") + query_bytes
                            writer.write(query_frame)
                            await writer.drain()
                            try:
                                raw_len = await asyncio.wait_for(
                                    reader.readexactly(2), timeout=self.timeout
                                )
                            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as re_e:
                                logger.debug("ECHDoT %s: Python SSL \u8bfb\u53d6\u957f\u5ea6\u524d\u7f00\u5931\u8d25: %s",
                                             self.host, re_e)
                                raise ConnectionError(str(re_e))
                            resp_len = int.from_bytes(raw_len, "big")
                            if resp_len <= 0 or resp_len > 65535:
                                logger.debug("ECHDoT %s: Python SSL \u65e0\u6548\u54cd\u5e94\u957f\u5ea6 %d",
                                             self.host, resp_len)
                                raise ConnectionError(f"\u65e0\u6548\u54cd\u5e94\u957f\u5ea6: {resp_len}")
                            try:
                                response_data = await asyncio.wait_for(
                                    reader.readexactly(resp_len), timeout=self.timeout
                                )
                            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as re_e:
                                logger.debug("ECHDoT %s: Python SSL \u8bfb\u53d6 DNS \u54cd\u5e94\u5931\u8d25: %s",
                                             self.host, re_e)
                                raise ConnectionError(str(re_e))
                            logger.info("ECHDoT %s:%d \u67e5\u8be2\u6210\u529f (Python SSL)", self.host, self.port)
                            return response_data[:resp_len]
                        else:
                            raise


                except asyncio.TimeoutError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoT %s (%s) 超时，切换到下一地址", self.host, target)
                    continue
                except ConnectionError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoT %s (%s) 连接错误，切换到下一地址", self.host, target)
                    continue
                except Exception as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoT %s (%s) 失败: %s，切换到下一地址", self.host, target, e)
                    continue
                finally:
                    if ssl_ptr and self._openssl:
                        self._openssl.destroy(ssl_ptr, ctx_ptr, writer)
                    elif writer:
                        try:
                            writer.close()
                        except Exception as e:
                            logger.debug("ECH DoT writer 关闭异常: %s", e)
                    # 重置变量防止在下一轮循环中被错误使用
                    ssl_ptr = None
                    ctx_ptr = None
                    bio_in = None
                    bio_out = None
                    reader = None
                    writer = None

        # 所有地址都失败（for 循环结束但未 return）
        if isinstance(last_error, asyncio.TimeoutError):
            logger.debug("ECHDoT %s:%d 全部超时 (timeout=%s)", self.host, self.port, self.timeout)
        elif isinstance(last_error, ConnectionError):
            logger.debug("ECHDoT %s:%d 全部连接失败: %s", self.host, self.port, last_error)
        elif last_error:
            logger.debug("ECHDoT %s:%d 全部失败: %s [%s]", self.host, self.port, last_error, type(last_error).__name__)
        return None

    async def _read_exactly(self, ssl: int, bio_in: int, bio_out: int,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            n: int) -> Optional[bytes]:
        """从 ECH TLS 连接中精确读取 n 字节"""
        buf = bytearray()
        while len(buf) < n:
            chunk = await self._openssl.ech_read(
                ssl, bio_in, bio_out, reader, writer, self.timeout
            )
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf) if buf else None

    async def close(self):
        """ECHDoT 解析器无需额外清理"""
        pass

    async def reset_connections(self):
        """重置连接（下次查询自动新建）"""
        logger.debug("ECHDoT %s:%d: 连接已重置", self.host, self.port)

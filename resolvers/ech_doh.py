"""
ECH-enabled DoH 解析器
使用 OpenSSL 4.0 + ctypes 实现真正的 ECH (Encrypted Client Hello) 支持。

原理：
  - 通过 ctypes 直接加载 OpenSSL 4.0 DLL（libssl-4-x64.dll）
  - 使用 SSL_set1_ech_config_list() 设置 ECHConfigList
  - 使用内存 BIO + asyncio 实现非阻塞 TLS
  - HTTP/1.1 POST (application/dns-message) 做 DoH 查询

当 OpenSSL 4.0 DLL 不可用时，创建此解析器会记录警告并标记不可用，
不会影响已有 DoH 解析器的正常运行。
"""

import asyncio
import logging
import ssl as py_ssl
from typing import Optional

from resolvers.base import BaseResolver
from crypto.ech_fetcher import ECHConfigFetcher
from crypto.openssl_ctypes import OpenSSL4Wrapper

logger = logging.getLogger("dns-proxy.resolver.ech_doh")


class ECHDoHResolver(BaseResolver):
    """DoH 解析器（通过 OpenSSL 4.0 ctypes 实现 ECH）

    每次建立连接前通过 ECHConfigFetcher 获取最新的 ECHConfigList，
    支持 Cloudflare 等动态刷新 ECH 公钥的服务器。
    """

    def __init__(self, url: str, timeout: float = 5.0,
                 ech_fetcher: Optional[ECHConfigFetcher] = None,
                 openssl_wrapper: Optional[OpenSSL4Wrapper] = None,
                 ca_path: Optional[str] = None,
                 ciphers: Optional[str] = None,
                 connect_ips: Optional[list] = None):
        super().__init__(url, timeout)
        self.url = url
        self._ech_fetcher = ech_fetcher
        self._openssl = openssl_wrapper
        self._ca_path = ca_path
        self._ciphers = ciphers
        self._connect_ips = connect_ips or []

        # 解析 URL
        rest = url.replace("https://", "")
        self._hostname = rest.split("/")[0].split(":")[0]
        self._port = 443
        if ":" in rest.split("/")[0]:
            self._port = int(rest.split("/")[0].split(":")[1])
        self._path = "/" + "/".join(rest.split("/")[1:]) if "/" in rest else "/dns-query"

        if self._connect_ips:
            logger.info("ECHDoH %s 使用 bootstrap IP: %s", url, ", ".join(self._connect_ips[:4]))

        # 检查是否可用
        if self._openssl is None or not self._openssl.available:
            self._available = False
            logger.warning("ECHDoH %s: OpenSSL 4.0 不可用，ECH DoH 解析器禁用", url)
        elif self._ech_fetcher is None or not self._ech_fetcher.enabled:
            self._available = False
            logger.warning("ECHDoH %s: 未配置 ECHConfigFetcher，ECH DoH 解析器禁用", url)
        else:
            self._available = True
            logger.info("ECHDoH %s: ECH DoH 解析器就绪 (fetcher=%s)",
                        url, self._ech_fetcher._config_str[:48] if hasattr(self._ech_fetcher, '_config_str') else "yes")

    @property
    def available(self) -> bool:
        return self._available

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """通过 DoH (ECH TLS) 执行 DNS 查询

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
        connect_targets = [self._hostname]
        if self._connect_ips:
            for ip in self._connect_ips:
                if ip != self._hostname:
                    connect_targets.append(ip)

        async with self._semaphore:
            last_error = None
            for target in connect_targets:
                try:
                    # 0. 获取最新的 ECHConfigList（每次连接刷新，fetcher 内部有缓存）
                    ech_config = await self._ech_fetcher.get_config()
                    if not ech_config:
                        logger.debug("ECHDoH %s: ECH 配置不可用（fetcher 返回空），跳过", self.url)
                        return None
                    # 诊断: ECHConfigList 格式 = [2byte总长][2byte版本][2byte内容长]...
                    if len(ech_config) >= 6:
                        _ver = int.from_bytes(ech_config[2:4], 'big')
                        logger.debug("ECHDoH %s: ECHConfig version=0x%04x len=%d",
                                     self.url, _ver, len(ech_config))
                    else:
                        logger.warning("ECHDoH %s: ECHConfig 过短 (%d bytes)", self.url, len(ech_config))

                    # 1. 建立 ECH TLS 连接（使用 target 直连，绕过系统 DNS）
                    try:
                        reader, writer, ssl_ptr, ctx_ptr, bio_in, bio_out = \
                            await self._openssl.connect_ech(
                                host=self._hostname,
                                port=self._port,
                                server_hostname=self._hostname,
                                ech_config=ech_config,
                                ca_path=self._ca_path,
                                ciphers=self._ciphers,
                                timeout=self.timeout,
                                connect_ip=target if target != self._hostname else None,
                            )
                    except ConnectionError as e:
                        err_msg = str(e)
                        if "illegal parameter" in err_msg:
                            logger.warning("ECHDoH %s: ECH 被服务器拒绝，"
                                           "回退到 Python SSL（无 ECH）", self.url)
                            # Python 内置 ssl 模块在 Windows 上使用系统证书存储，
                            # 不需要手动指定 CA 路径
                            py_ctx = py_ssl.create_default_context()
                            connect_addr = connect_ip or self._hostname \
                                if target != self._hostname else self._hostname
                            target_ip = target if target != self._hostname else None
                            fallback_ip = target_ip or self._hostname
                            try:
                                reader, writer = await asyncio.wait_for(
                                    asyncio.open_connection(
                                        fallback_ip, self._port,
                                        ssl=py_ctx,
                                        server_hostname=self._hostname,
                                    ),
                                    timeout=self.timeout,
                                )
                            except OSError as conn_e:
                                logger.debug("ECHDoH %s: Python SSL 连接失败: %s",
                                             self.url, conn_e)
                                raise ConnectionError(str(conn_e))

                            # Python ssl 连接成功，直接发送 HTTP POST
                            request_bytes = (
                                f"POST {self._path} HTTP/1.1\r\n"
                                f"Host: {self._hostname}\r\n"
                                f"Content-Type: application/dns-message\r\n"
                                f"Content-Length: {len(query_bytes)}\r\n"
                                f"Connection: close\r\n"
                                f"\r\n"
                            ).encode("ascii") + query_bytes

                            writer.write(request_bytes)
                            await writer.drain()

                            # 读取响应
                            raw_response = b""
                            while True:
                                chunk = await asyncio.wait_for(
                                    reader.read(65536), timeout=self.timeout
                                )
                                if not chunk:
                                    break
                                raw_response += chunk

                            if not raw_response:
                                logger.debug("ECHDoH %s: Python SSL 空响应", self.url)
                                continue

                            # 检查 HTTP 状态码
                            if b"200" not in raw_response.split(b"\r\n")[0]:
                                logger.debug("ECHDoH %s: Python SSL HTTP 非 200", self.url)
                                continue

                            # 提取 DNS 响应
                            _, _, body = raw_response.partition(b"\r\n\r\n")
                            if body:
                                logger.info("ECHDoH %s 查询成功 (Python SSL)", self.url)
                            return body if body else None
                        else:
                            raise

                    # 2. 构造 HTTP POST 请求
                    request_line = (
                        f"POST {self._path} HTTP/1.1\r\n"
                        f"Host: {self._hostname}\r\n"
                        f"Content-Type: application/dns-message\r\n"
                        f"Content-Length: {len(query_bytes)}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode("ascii") + query_bytes

                    # 3. 发送请求
                    await self._openssl.ech_write(
                        ssl_ptr, bio_out, writer, request_line
                    )

                    # 4. 读取 HTTP 响应
                    response_data = await self._read_http_response(
                        ssl_ptr, bio_in, bio_out, reader, writer
                    )

                    if response_data is None:
                        logger.debug("ECHDoH %s (%s) HTTP 响应为空，切换到下一地址", self.url, target)
                        continue

                    # 5. 从 HTTP 响应中提取 DNS 消息
                    dns_response = self._extract_dns_response(response_data)
                    if dns_response:
                        logger.info("ECHDoH %s 查询成功 (ECH)", self.url)
                    return dns_response

                except asyncio.TimeoutError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoH %s (%s) 超时，切换到下一地址", self.url, target)
                    continue
                except ConnectionError as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoH %s (%s) 连接错误，切换到下一地址", self.url, target)
                    continue
                except Exception as e:
                    last_error = e
                    if len(connect_targets) > 1:
                        logger.debug("ECHDoH %s (%s) 失败: %s，切换到下一地址", self.url, target, e)
                    continue
                finally:
                    if ssl_ptr and self._openssl:
                        self._openssl.destroy(ssl_ptr, ctx_ptr, writer)
                    elif writer:
                        try:
                            writer.close()
                        except Exception:
                            pass
                    # 重置变量防止在下一轮循环中被错误使用
                    ssl_ptr = None
                    ctx_ptr = None
                    bio_in = None
                    bio_out = None
                    reader = None
                    writer = None

        # 所有地址都失败（for 循环结束但未 return）
        if isinstance(last_error, asyncio.TimeoutError):
            logger.debug("ECHDoH %s:%d 全部超时 (timeout=%s)", self._hostname, self._port, self.timeout)
        elif isinstance(last_error, ConnectionError):
            logger.debug("ECHDoH %s:%d 全部连接失败: %s", self._hostname, self._port, last_error)
        elif last_error:
            logger.debug("ECHDoH %s:%d 全部失败: %s [%s]", self._hostname, self._port, last_error, type(last_error).__name__)
        return None

    async def _read_http_response(self, ssl: int, bio_in: int, bio_out: int,
                                   reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> Optional[bytes]:
        """读取完整的 HTTP 响应"""
        response = b""
        content_length = None

        while True:
            chunk = await self._openssl.ech_read(
                ssl, bio_in, bio_out, reader, writer, self.timeout
            )
            if not chunk:
                break
            response += chunk

            # 尝试解析 HTTP 头
            if content_length is None and b"\r\n\r\n" in response:
                header_part, _, body_part = response.partition(b"\r\n\r\n")
                # 解析 Content-Length
                for line in header_part.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            content_length = int(line.split(b":")[1].strip())
                        except (ValueError, IndexError):
                            pass
                    # 检查状态码
                    if line.startswith(b"HTTP/"):
                        if b"200" not in line:
                            logger.debug("ECHDoH %s HTTP 状态异常: %s",
                                         self.url, line.decode(errors="replace"))
                            return None

                # 如果 content-length 已知，等够数据
                if content_length is not None:
                    if len(body_part) >= content_length:
                        return response

            # 如果 content-length 未知，等到连接关闭
            if content_length is None and response.endswith(b"\r\n\r\n"):
                # 没有 Content-Length，继续读直到连接关闭
                pass

        return response if response else None

    def _extract_dns_response(self, http_response: bytes) -> Optional[bytes]:
        """从 HTTP 响应中提取 DNS 消息体"""
        if b"\r\n\r\n" not in http_response:
            return None
        _, _, body = http_response.partition(b"\r\n\r\n")
        return body if body else None

    async def close(self):
        """ECHDoH 解析器无需额外清理"""
        pass

    async def reset_connections(self):
        """重置连接（下次查询会自动新建）"""
        logger.debug("ECHDoH %s: 连接已重置", self.url)

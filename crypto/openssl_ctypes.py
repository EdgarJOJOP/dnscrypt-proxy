"""
OpenSSL 4.0 ctypes 封装层
提供对 OpenSSL 4.0 DLL 的直接 ctypes 调用，支持 ECH (Encrypted Client Hello)。
仅用于加密 DNS 解析器的 TLS 连接（不需要 Python ssl 模块的 ECH 支持）。

设计：
  - 使用 ctypes 加载 libssl-4 / libcrypto-4 DLL
  - 使用 OpenSSL 内存 BIO 实现非阻塞 TLS
  - 与 asyncio 集成（StreamReader/StreamWriter）
  - 通过 SSL_set1_ech_config_list() 设置 ECHConfigList
"""

import asyncio
import ctypes
import ctypes.util
import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger("dns-proxy.crypto.openssl4")


# OpenSSL 函数返回/错误常量
SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6

SSL_VERIFY_PEER = 1
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
SSL_VERIFY_CLIENT_ONCE = 4


class OpenSSL4Wrapper:
    """
    OpenSSL 4.0 ctypes 封装器

    延迟加载 DLL，提供 SSL 连接所需的底层函数。
    通过 hasattr(ssl4, 'available') 检查是否加载成功。
    """

    def __init__(self, dll_dir: Optional[str] = None):
        self._libssl = None
        self._libcrypto = None
        self._available = False
        self._load(dll_dir)

    @property
    def available(self) -> bool:
        return self._available

    @property
    def ech_supported(self) -> bool:
        """OpenSSL 4.0 是否支持 ECH"""
        return self._available and self._has_ech

    # ── DLL 加载 ──────────────────────────────────────────────────

    def _load(self, dll_dir: Optional[str] = None):
        """尝试加载 OpenSSL 4.0 DLL"""
        # 搜索路径优先级：指定目录 → PATH → 默认名
        ssl_names = ["libssl-4-x64.dll", "libssl-4.dll"]
        crypto_names = ["libcrypto-4-x64.dll", "libcrypto-4.dll"]

        ssl_paths = []
        if dll_dir:
            for name in ssl_names:
                ssl_paths.append(os.path.join(dll_dir, name))
        ssl_paths.extend(ssl_names)

        crypto_paths = []
        if dll_dir:
            for name in crypto_names:
                crypto_paths.append(os.path.join(dll_dir, name))
        crypto_paths.extend(crypto_names)

        # 加载 libssl
        for sp in ssl_paths:
            try:
                self._libssl = ctypes.cdll.LoadLibrary(sp)
                logger.info("OpenSSL 4.0 libssl 已加载: %s", sp)
                break
            except OSError:
                continue
        else:
            logger.warning("无法加载 OpenSSL 4.0 libssl DLL（libssl-4-x64.dll）")
            return

        # 加载 libcrypto
        for cp in crypto_paths:
            try:
                self._libcrypto = ctypes.cdll.LoadLibrary(cp)
                logger.info("OpenSSL 4.0 libcrypto 已加载: %s", cp)
                break
            except OSError:
                continue
        else:
            logger.warning("无法加载 OpenSSL 4.0 libcrypto DLL（libcrypto-4-x64.dll）")
            self._libssl = None
            return

        # 定义所有函数签名
        self._define_functions()
        # 检查初始化是否成功（OPENSSL_init_ssl / SSL_library_init 必须可用）
        if not getattr(self, '_has_init', False):
            logger.error("OpenSSL 4.0 初始化失败，标记为不可用")
            self._libssl = None
            self._libcrypto = None
            return
        self._available = True

    # ── 函数签名定义 ──────────────────────────────────────────────

    def _define_functions(self):
        S = self._libssl
        C = self._libcrypto

        # ── SSL 库初始化 ──
        # OpenSSL 4.0: int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
        # SSL_library_init 在 4.0 中已移除，用 OPENSSL_init_ssl 替代
        if hasattr(S, "OPENSSL_init_ssl"):
            S.OPENSSL_init_ssl.restype = ctypes.c_int
            S.OPENSSL_init_ssl.argtypes = [ctypes.c_uint64, ctypes.c_void_p]
            self._has_init = True
        elif hasattr(S, "SSL_library_init"):
            S.SSL_library_init.restype = ctypes.c_int
            S.SSL_library_init.argtypes = []
            self._has_init = True
        else:
            self._has_init = False
            logger.error("OpenSSL 4.0 DLL 中找不到 SSL_init 函数")
            return

        # void SSL_load_error_strings(void) - 4.0 中可能已移除
        if hasattr(S, "SSL_load_error_strings"):
            S.SSL_load_error_strings.restype = None
            S.SSL_load_error_strings.argtypes = []

        # void OpenSSL_add_all_algorithms(void) - 4.0 中可能已移除
        if hasattr(C, "OpenSSL_add_all_algorithms"):
            C.OpenSSL_add_all_algorithms.restype = None
            C.OpenSSL_add_all_algorithms.argtypes = []

        # ── SSL_CTX ──
        # SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
        S.SSL_CTX_new.restype = ctypes.c_void_p
        S.SSL_CTX_new.argtypes = [ctypes.c_void_p]

        # void SSL_CTX_free(SSL_CTX *ctx)
        S.SSL_CTX_free.restype = None
        S.SSL_CTX_free.argtypes = [ctypes.c_void_p]

        # const SSL_METHOD *TLS_client_method(void)
        S.TLS_client_method.restype = ctypes.c_void_p
        S.TLS_client_method.argtypes = []

        # int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)
        S.SSL_CTX_load_verify_locations.restype = ctypes.c_int
        S.SSL_CTX_load_verify_locations.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        # void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *callback)
        S.SSL_CTX_set_verify.restype = None
        S.SSL_CTX_set_verify.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

        # int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str)
        S.SSL_CTX_set_ciphersuites.restype = ctypes.c_int
        S.SSL_CTX_set_ciphersuites.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        # int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
        S.SSL_CTX_set_cipher_list.restype = ctypes.c_int
        S.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        # ── SSL ──
        # SSL *SSL_new(SSL_CTX *ctx)
        S.SSL_new.restype = ctypes.c_void_p
        S.SSL_new.argtypes = [ctypes.c_void_p]

        # void SSL_free(SSL *ssl)
        S.SSL_free.restype = None
        S.SSL_free.argtypes = [ctypes.c_void_p]

        # int SSL_set_fd(SSL *ssl, int fd)
        S.SSL_set_fd.restype = ctypes.c_int
        S.SSL_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]

        # void SSL_set_connect_state(SSL *ssl)
        S.SSL_set_connect_state.restype = None
        S.SSL_set_connect_state.argtypes = [ctypes.c_void_p]

        # void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
        S.SSL_set_bio.restype = None
        S.SSL_set_bio.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        # int SSL_do_handshake(SSL *ssl)
        S.SSL_do_handshake.restype = ctypes.c_int
        S.SSL_do_handshake.argtypes = [ctypes.c_void_p]

        # int SSL_get_error(SSL *ssl, int ret)
        S.SSL_get_error.restype = ctypes.c_int
        S.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]

        # int SSL_write(SSL *ssl, const void *buf, int num)
        S.SSL_write.restype = ctypes.c_int
        S.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

        # int SSL_read(SSL *ssl, void *buf, int num)
        S.SSL_read.restype = ctypes.c_int
        S.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

        # int SSL_shutdown(SSL *ssl)
        S.SSL_shutdown.restype = ctypes.c_int
        S.SSL_shutdown.argtypes = [ctypes.c_void_p]

        # int SSL_set_tlsext_host_name(SSL *ssl, const char *name) - SNI
        # OpenSSL 4.0 中此函数已移除；ECH 配置中的 public_name 会自动设置 SNI
        self._has_sni_func = hasattr(S, "SSL_set_tlsext_host_name")
        if self._has_sni_func:
            S.SSL_set_tlsext_host_name.restype = ctypes.c_int
            S.SSL_set_tlsext_host_name.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        # ── ECH ──
        self._has_ech = False
        # int SSL_set1_ech_config_list(SSL *ssl, const uint8_t *ecl, size_t ecl_len)
        if hasattr(S, "SSL_set1_ech_config_list"):
            S.SSL_set1_ech_config_list.restype = ctypes.c_int
            S.SSL_set1_ech_config_list.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
            self._has_ech = True
            logger.info("OpenSSL 4.0 ECH API 可用（SSL_set1_ech_config_list）")
        else:
            logger.warning("OpenSSL 4.0 无 ECH API（SSL_set1_ech_config_list）")

        # int SSL_get_ech_status(const SSL *ssl, int *status)
        # 注意：这个函数可能不存在了或签名不同，先尝试
        try:
            S.SSL_get_ech_status.restype = ctypes.c_int
            S.SSL_get_ech_status.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            self._has_ech_status = True
        except AttributeError:
            self._has_ech_status = False

        # ── BIO ──
        # BIO *BIO_new(const BIO_METHOD *type)
        C.BIO_new.restype = ctypes.c_void_p
        C.BIO_new.argtypes = [ctypes.c_void_p]

        # BIO_METHOD *BIO_s_mem(void)
        C.BIO_s_mem.restype = ctypes.c_void_p
        C.BIO_s_mem.argtypes = []

        # int BIO_free(BIO *a)
        C.BIO_free.restype = ctypes.c_int
        C.BIO_free.argtypes = [ctypes.c_void_p]

        # int BIO_read(BIO *b, void *buf, int len)
        C.BIO_read.restype = ctypes.c_int
        C.BIO_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

        # int BIO_write(BIO *b, const void *buf, int len)
        C.BIO_write.restype = ctypes.c_int
        C.BIO_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

        # size_t BIO_ctrl_pending(BIO *b)
        C.BIO_ctrl_pending.restype = ctypes.c_size_t
        C.BIO_ctrl_pending.argtypes = [ctypes.c_void_p]

        # int BIO_flush(BIO *b) - for BIO_s_mem this is a no-op
        try:
            C.BIO_flush.restype = ctypes.c_int
            C.BIO_flush.argtypes = [ctypes.c_void_p]
        except AttributeError:
            pass

        # ── 错误处理 ──
        # unsigned long ERR_get_error(void)
        if hasattr(C, "ERR_get_error"):
            C.ERR_get_error.restype = ctypes.c_ulong
            C.ERR_get_error.argtypes = []
        else:
            logger.warning("OpenSSL 4.0 中找不到 ERR_get_error")

        # char *ERR_error_string(unsigned long e, char *buf)
        if hasattr(C, "ERR_error_string"):
            C.ERR_error_string.restype = ctypes.c_char_p
            C.ERR_error_string.argtypes = [ctypes.c_ulong, ctypes.c_void_p]
        else:
            logger.warning("OpenSSL 4.0 中找不到 ERR_error_string")

        # ── X509 验证 ──
        # X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)
        S.SSL_CTX_get0_param.restype = ctypes.c_void_p
        S.SSL_CTX_get0_param.argtypes = [ctypes.c_void_p]

        # int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen)
        C.X509_VERIFY_PARAM_set1_host.restype = ctypes.c_int
        C.X509_VERIFY_PARAM_set1_host.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

        # ── 初始化 ──
        # OpenSSL 4.0: OPENSSL_init_ssl(0, NULL)，替代已移除的 SSL_library_init
        if hasattr(S, "OPENSSL_init_ssl"):
            S.OPENSSL_init_ssl(0, None)
        elif hasattr(S, "SSL_library_init"):
            S.SSL_library_init()
        else:
            logger.error("无法初始化 OpenSSL（无初始化函数）")
            return

        if hasattr(S, "SSL_load_error_strings"):
            S.SSL_load_error_strings()
        if hasattr(C, "OpenSSL_add_all_algorithms"):
            C.OpenSSL_add_all_algorithms()

    def _get_ssl_error_string(self) -> str:
        """获取 OpenSSL 错误队列中的最新错误（字符串形式）"""
        if not hasattr(self._libcrypto, 'ERR_get_error'):
            return "ERR_get_error 不可用"
        err_code = self._libcrypto.ERR_get_error()
        if err_code == 0:
            return "无 OpenSSL 错误"
        if hasattr(self._libcrypto, 'ERR_error_string'):
            err_str = self._libcrypto.ERR_error_string(err_code, None)
            return f"{err_str} (code={err_code})" if err_str else f"code={err_code}"
        return f"code={err_code}"

    # ── 高层 SSL 连接管理 ──────────────────────────────────────────

    def _bio_new(self) -> int:
        """创建内存 BIO，返回指针"""
        method = self._libcrypto.BIO_s_mem()
        bio = self._libcrypto.BIO_new(method)
        if not bio:
            raise MemoryError("BIO_new 失败")
        return bio

    def _bio_write(self, bio: int, data: bytes):
        """向 BIO 写入数据（从网络接收的数据进入 read BIO）"""
        n = self._libcrypto.BIO_write(bio, data, len(data))
        if n <= 0:
            # 对于内存 BIO，只可能在 OOM 时失败
            logger.warning("BIO_write 返回 %d", n)

    def _bio_read_all(self, bio: int) -> bytes:
        """读取 BIO 中所有待处理数据"""
        pending = self._libcrypto.BIO_ctrl_pending(bio)
        if pending <= 0:
            return b""
        buf = ctypes.create_string_buffer(pending)
        n = self._libcrypto.BIO_read(bio, buf, pending)
        if n > 0:
            return buf.raw[:n]
        return b""

    def _create_ssl_ctx(self, ca_path: Optional[str] = None,
                        ciphers: Optional[str] = None) -> int:
        """创建 SSL_CTX 并配置验证"""
        method = self._libssl.TLS_client_method()
        ctx = self._libssl.SSL_CTX_new(method)
        if not ctx:
            raise MemoryError("SSL_CTX_new 失败")

        # 设置验证模式
        self._libssl.SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, None)

        # 加载 CA 证书
        if ca_path:
            ca_bytes = ca_path.encode("utf-8")
            ca_buf = ctypes.create_string_buffer(ca_bytes)
            ret = self._libssl.SSL_CTX_load_verify_locations(ctx, ca_buf, None)
            if ret != 1:
                logger.warning("SSL_CTX_load_verify_locations 失败 (CA: %s)", ca_path)
        else:
            # 尝试加载默认路径
            # 在 Windows 上没有默认 CA 路径，需要 certifi
            logger.warning("未指定 CA 文件，证书验证可能失败")

        # 设置密码套件
        if ciphers:
            ciphers_bytes = ciphers.encode("utf-8")
            ciphers_buf = ctypes.create_string_buffer(ciphers_bytes)
            ret = self._libssl.SSL_CTX_set_cipher_list(ctx, ciphers_buf)
            if ret != 1:
                logger.debug("SSL_CTX_set_cipher_list 失败")

        return ctx

    def _new_ssl(self, ctx: int, server_hostname: str) -> int:
        """创建 SSL 对象并设置 SNI"""
        ssl = self._libssl.SSL_new(ctx)
        if not ssl:
            raise MemoryError("SSL_new 失败")

        # 设置 SNI（OpenSSL 4.0 可能已移除，由 ECH 自动处理）
        if self._has_sni_func:
            name_bytes = server_hostname.encode("utf-8")
            name_buf = ctypes.create_string_buffer(name_bytes)
            self._libssl.SSL_set_tlsext_host_name(ssl, name_buf)

        return ssl

    def _ssl_write_all(self, ssl: int, data: bytes):
        """SSL_write 全部数据"""
        offset = 0
        while offset < len(data):
            n = self._libssl.SSL_write(
                ssl,
                ctypes.c_char_p(data[offset:]),
                len(data) - offset,
            )
            if n <= 0:
                err = self._libssl.SSL_get_error(ssl, n)
                if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE:
                    break  # 需要刷新 BIO
                raise ConnectionError(f"SSL_write 失败 (err={err})")
            offset += n

    async def _flush_bio(self, bio_out: int, writer: asyncio.StreamWriter):
        """将 BIO 输出缓存中的数据通过 writer 发送出去"""
        data = self._bio_read_all(bio_out)
        if data:
            writer.write(data)
            await writer.drain()

    async def _handshake(self, ssl: int, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter,
                         bio_in: int, bio_out: int,
                         timeout: float):
        """异步 TLS 握手循环（内存 BIO + asyncio）"""
        while True:
            ret = self._libssl.SSL_do_handshake(ssl)
            if ret == 1:
                # 握手成功，刷新最后的输出
                await self._flush_bio(bio_out, writer)
                return

            err = self._libssl.SSL_get_error(ssl, ret)

            if err == SSL_ERROR_WANT_READ:
                # 1) 刷出待发送的数据
                await self._flush_bio(bio_out, writer)
                # 2) 从网络读取数据
                try:
                    data = await asyncio.wait_for(
                        reader.read(65536), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    raise ConnectionError("TLS 握手超时")
                if not data:
                    raise ConnectionError("TLS 握手时连接关闭")
                # 3) 喂给 read BIO
                self._bio_write(bio_in, data)

            elif err == SSL_ERROR_WANT_WRITE:
                # 刷出待发送数据
                await self._flush_bio(bio_out, writer)

            else:
                err_str = self._get_ssl_error_string()
                logger.debug("TLS 握手错误 (err=%d): %s", err, err_str)
                raise ConnectionError(f"TLS 握手失败 (err={err}: {err_str})")

    # ── 公开接口：建立 ECH TLS 连接 ────────────────────────────────

    async def connect_ech(
        self,
        host: str,
        port: int,
        server_hostname: str,
        ech_config: bytes,
        *,
        ca_path: Optional[str] = None,
        ciphers: Optional[str] = None,
        timeout: float = 10.0,
        connect_ip: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, int, int, int, int]:
        """
        建立带有 ECH 的 TLS 连接。

        参数:
            host: 原始域名（仅用于日志/SNI，当 connect_ip 为 None 时也用于 TCP 连接）
            port: 端口
            server_hostname: TLS SNI 主机名
            ech_config: ECHConfigList 字节数据
            connect_ip: 用于 TCP 连接的 IP 地址（绕过系统 DNS 自引用）
                       为 None 时使用 host 参数进行系统 DNS 解析

        返回:
            (reader, writer, ssl, ctx, bio_in, bio_out)
            使用完毕后调用 destroy() 释放。
        """
        if not self._available:
            raise RuntimeError("OpenSSL 4.0 不可用")

        # 1. TCP 连接（使用 connect_ip 绕过系统 DNS 自引用）
        connect_addr = connect_ip or host
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_addr, port),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionError(f"TCP 连接超时: {connect_addr}:{port}")
        except OSError as e:
            raise ConnectionError(f"TCP 连接失败: {connect_addr}:{port} - {e}")

        # 2. 创建 SSL_CTX
        try:
            ctx = self._create_ssl_ctx(ca_path=ca_path, ciphers=ciphers)
        except Exception as e:
            writer.close()
            raise

        # 3. 创建 SSL 对象（配置 SNI）
        try:
            ssl = self._new_ssl(ctx, server_hostname)
        except Exception as e:
            self._libssl.SSL_CTX_free(ctx)
            writer.close()
            raise

        # 4. 设置内存 BIO
        bio_in = self._bio_new()   # 网络→SSL 方向
        bio_out = self._bio_new()  # SSL→网络方向
        self._libssl.SSL_set_bio(ssl, bio_in, bio_out)
        # 显式设置为 client/connect 模式（使用内存 BIO 时需要）
        self._libssl.SSL_set_connect_state(ssl)

        # 5. 设置 ECH 配置（必须在 SSL_set_connect_state 之后设置）
        if ech_config and self._has_ech:
            ret = self._libssl.SSL_set1_ech_config_list(
                ssl, ech_config, len(ech_config)
            )
            if ret != 1:
                logger.warning("SSL_set1_ech_config_list 失败 (%s, %d bytes)",
                               server_hostname, len(ech_config))
            else:
                logger.debug("ECH 配置已设置: %s (%d bytes)",
                             server_hostname, len(ech_config))

        # 6. TLS 握手
        try:
            await self._handshake(ssl, reader, writer, bio_in, bio_out, timeout)
        except Exception as e:
            self._libssl.SSL_free(ssl)
            self._libssl.SSL_CTX_free(ctx)
            writer.close()
            raise

        # SSL 对象拥有 BIO 的所有权（SSL_free 会自动释放 BIO）
        # 但我们需要释放 SSL_CTX
        # 注意：SSL_free 不会释放 SSL_CTX
        # SSL_CTX 可以在 SSL 对象释放后释放
        # 但我们把 ctx 返回给调用方，让调用方在销毁 SSL 时一并销毁

        return reader, writer, ssl, ctx, bio_in, bio_out

    async def connect_tls(
        self,
        host: str,
        port: int,
        server_hostname: str,
        *,
        ca_path: Optional[str] = None,
        ciphers: Optional[str] = None,
        timeout: float = 10.0,
        connect_ip: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, int, int, int, int]:
        """
        建立普通 TLS 连接（无 ECH），用于诊断对比。
        """
        connect_addr = connect_ip or host
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_addr, port),
                timeout=timeout,
            )
        except Exception as e:
            raise ConnectionError(f"TCP 连接失败: {e}")

        ctx = self._create_ssl_ctx(ca_path=ca_path, ciphers=ciphers)
        ssl = self._new_ssl(ctx, server_hostname)
        bio_in = self._bio_new()
        bio_out = self._bio_new()
        self._libssl.SSL_set_bio(ssl, bio_in, bio_out)
        self._libssl.SSL_set_connect_state(ssl)
        try:
            await self._handshake(ssl, reader, writer, bio_in, bio_out, timeout)
        except Exception as e:
            self._libssl.SSL_free(ssl)
            self._libssl.SSL_CTX_free(ctx)
            writer.close()
            raise
        return reader, writer, ssl, ctx, bio_in, bio_out

    async def ech_read(self, ssl: int, bio_in: int, bio_out: int,
                       reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter,
                       timeout: float) -> bytes:
        """从 ECH TLS 连接读取解密后的数据"""
        buf = ctypes.create_string_buffer(65536)
        n = self._libssl.SSL_read(ssl, buf, 65536)
        if n > 0:
            return buf.raw[:n]
        if n == 0:
            return b""

        err = self._libssl.SSL_get_error(ssl, n)
        if err == SSL_ERROR_WANT_READ:
            # 需要更多网络数据
            await self._flush_bio(bio_out, writer)
            try:
                data = await asyncio.wait_for(
                    reader.read(65536), timeout=timeout
                )
            except asyncio.TimeoutError:
                raise ConnectionError("SSL_read 超时")
            if not data:
                return b""
            self._bio_write(bio_in, data)
            # 重试
            return await self.ech_read(ssl, bio_in, bio_out, reader, writer, timeout)
        elif err == SSL_ERROR_WANT_WRITE:
            await self._flush_bio(bio_out, writer)
            return await self.ech_read(ssl, bio_in, bio_out, reader, writer, timeout)
        elif err == SSL_ERROR_ZERO_RETURN:
            return b""
        else:
            raise ConnectionError(f"SSL_read 失败 (err={err})")

    async def ech_write(self, ssl: int, bio_out: int,
                        writer: asyncio.StreamWriter,
                        data: bytes):
        """向 ECH TLS 连接写入加密数据"""
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 16384]
            n = self._libssl.SSL_write(ssl, chunk, len(chunk))
            if n <= 0:
                err = self._libssl.SSL_get_error(ssl, n)
                if err == SSL_ERROR_WANT_WRITE:
                    await self._flush_bio(bio_out, writer)
                    continue
                elif err == SSL_ERROR_WANT_READ:
                    await self._flush_bio(bio_out, writer)
                    continue
                raise ConnectionError(f"SSL_write 失败 (err={err})")
            offset += n
        # 刷出剩余数据
        await self._flush_bio(bio_out, writer)

    def destroy(self, ssl: int, ctx: int, writer: asyncio.StreamWriter):
        """释放 ECH SSL 连接资源"""
        try:
            if ssl:
                self._libssl.SSL_shutdown(ssl)
        except Exception:
            pass
        try:
            if ssl:
                self._libssl.SSL_free(ssl)
        except Exception:
            pass
        try:
            if ctx:
                self._libssl.SSL_CTX_free(ctx)
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass

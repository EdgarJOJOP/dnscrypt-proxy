"""
加密模块
- OpenSSL 4.0 ctypes 封装（支持 ECH）
"""
from .openssl_ctypes import OpenSSL4Wrapper

__all__ = ["OpenSSL4Wrapper"]

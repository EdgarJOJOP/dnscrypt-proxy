"""
DNS over TLS (DoT) 解析器
使用 TLS/SSL 加密的 TCP 连接，RFC 7858
带 TLS 连接池：复用空闲连接，避免每查询新建/销毁 TLS 连接
"""

import asyncio
import logging
import ssl
import sys
import time
from typing import Optional, Tuple, Dict
from collections import OrderedDict

import dns.message

from .base import BaseResolver

logger = logging.getLogger("dns-proxy.resolver.dot")

# 空闲连接保活探测间隔（秒）
_IDLE_PROBE_INTERVAL = 20.0
# 空闲连接最大空闲时间（秒），超时后关闭
_IDLE_TIMEOUT = 60.0


class _TlsConnection:
    """一条 TLS 连接 (reader, writer) 及元数据"""

    __slots__ = ("reader", "writer", "last_used", "target", "closed")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 target: str):
        self.reader = reader
        self.writer = writer
        self.last_used = time.monotonic()
        self.target = target
        self.closed = False

    async def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


class _TlsConnectionPool:
    """
    TLS 连接池 — 对每个目标地址维持一组空闲 TLS 连接。
    查询时从池中借用，用完后归还；空闲超时自动关闭。
    按 connection_pool_size 控制池上限。
    """

    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext,
                 server_hostname: str, max_pool_size: int,
                 connect_timeout: float):
        self._host = host
        self._port = port
        self._ssl_context = ssl_context
        self._server_hostname = server_hostname
        self._max_pool_size = max_pool_size
        self._connect_timeout = connect_timeout

        # 按目标地址分组的空闲连接池：{target: OrderedDict[id, _TlsConnection]}
        self._idle_pool: Dict[str, OrderedDict[int, _TlsConnection]] = {}
        self._total_conns = 0  # 所有池的连接总数
        self._lock = asyncio.Lock()
        self._closed = False

        # 后台保活任务
        self._keepalive_task: Optional[asyncio.Task] = None

    def start_keepalive(self):
        """启动后台空闲连接保活检测"""
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def _keepalive_loop(self):
        """定期检测空闲连接：关闭超时的，释放资源"""
        while not self._closed:
            await asyncio.sleep(_IDLE_PROBE_INTERVAL)
            try:
                await self._evict_stale()
            except Exception:
                pass

    async def _evict_stale(self):
        """关闭并移除超时空闲连接"""
        async with self._lock:
            now = time.monotonic()
            to_close = []
            for target, pool in list(self._idle_pool.items()):
                stale_ids = []
                for cid, conn in pool.items():
                    if now - conn.last_used > _IDLE_TIMEOUT:
                        stale_ids.append(cid)
                for cid in stale_ids:
                    conn = pool.pop(cid, None)
                    if conn:
                        to_close.append(conn)
                        self._total_conns -= 1
                if not pool:
                    self._idle_pool.pop(target, None)

        # 在锁外执行 close（避免阻塞）
        for conn in to_close:
            await conn.close()

    async def close_idle(self):
        """Close only idle connections, keep active ones."""
        await self._evict_stale()


    def _get_pool(self, target: str) -> OrderedDict:
        """获取或创建某个目标的空闲连接池"""
        if target not in self._idle_pool:
            self._idle_pool[target] = OrderedDict()
        return self._idle_pool[target]

    async def acquire(self, target: str) -> _TlsConnection:
        """
        从池中借出一条 TLS 连接。
        优先返回空闲连接，无空闲则创建新连接（不超过 max_pool_size）。
        """
        dead_conn = None
        evict_conn = None
        async with self._lock:
            pool = self._get_pool(target)
            if pool:
                # LRU: 弹出最久未用的
                cid, conn = pool.popitem(last=False)
                if not pool:
                    self._idle_pool.pop(target, None)
                # 检查连接是否还存活
                if not conn.closed and not conn.writer.is_closing():
                    return conn
                else:
                    # 死连接，丢弃（在锁内递减计数，避免计数漂移）
                    self._total_conns -= 1
                    dead_conn = conn
                    # close 在锁外执行；继续往下创建新连接

            # 检查是否已达上限
            if self._total_conns >= self._max_pool_size:
                # 超限：从任意池中驱逐最久未用的空闲连接
                if self._idle_pool:
                    target_evict = next(iter(self._idle_pool))
                    evict_pool = self._idle_pool[target_evict]
                    _, evict_conn = evict_pool.popitem(last=False)
                    self._total_conns -= 1
                    if not evict_pool:
                        self._idle_pool.pop(target_evict)

        # 在锁外执行 close（避免阻塞）
        if evict_conn is not None:
            await evict_conn.close()
        if dead_conn is not None:
            await dead_conn.close()

        # 创建新连接（锁外）
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target, self._port,
                ssl=self._ssl_context,
                server_hostname=self._server_hostname,
            ),
            timeout=self._connect_timeout,
        )
        conn = _TlsConnection(reader, writer, target)
        async with self._lock:
            self._total_conns += 1
        return conn

    async def release(self, conn: _TlsConnection):
        """将连接归还到池中（供后续复用）"""
        if conn.closed or conn.writer.is_closing():
            await conn.close()
            async with self._lock:
                self._total_conns = max(0, self._total_conns - 1)
            return

        conn.last_used = time.monotonic()
        async with self._lock:
            pool = self._get_pool(conn.target)
            # 用单调递增 id 作为 key
            cid = id(conn)
            pool[cid] = conn

    

    async def discard(self, conn: _TlsConnection):
        """丢弃一条失效连接（不归还池）"""
        await conn.close()
        async with self._lock:
            self._total_conns = max(0, self._total_conns - 1)

    async def close_all(self):
        """关闭所有连接"""
        self._closed = True
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

        async with self._lock:
            all_conns = []
            for pool in self._idle_pool.values():
                for conn in pool.values():
                    all_conns.append(conn)
            self._idle_pool.clear()
            self._total_conns = 0

        for conn in all_conns:
            await conn.close()


class DoTResolver(BaseResolver):
    """DoT 上游解析器（支持连接池复用 + bootstrap IP 直连 + 双栈）"""

    _HAS_ECH = hasattr(ssl, 'ECHClientConfig')

    def __init__(self, host: str, port: int = 853, timeout: float = 5.0,
                 connect_ips: Optional[list] = None,
                 ech_enabled: bool = False, ech_config: bytes = b"",
                 concurrency: int = 100, ca_path: str = "",
                 connection_pool_size: int = 100):
        super().__init__(host, timeout, concurrency=concurrency)
        self.host = host
        self.port = port
        self._connect_ips = connect_ips or []
        self._ech_enabled = ech_enabled
        self._ech_config = ech_config
        self._ca_path = ca_path
        self._connection_pool_size = max(1, connection_pool_size)
        self._ssl_context = self._create_ssl_context()
        self._pool: Optional[_TlsConnectionPool] = None
        self._pool_created = False

        if self._connect_ips:
            logger.info("DoT %s 使用 bootstrap IP: %s", host, ", ".join(self._connect_ips[:4]))
        if ech_enabled and self._HAS_ECH:
            if ech_config:
                logger.info("DoT %s ECH 已启用 (ECHConfigList %d bytes)", host, len(ech_config))
            else:
                logger.info("DoT %s ECH 已启用，但未获取到 ECHConfigList", host)
        elif ech_enabled and not self._HAS_ECH:
            logger.warning("DoT %s ECH 已请求但当前 Python/OpenSSL 不支持", host)

    def _get_pool(self) -> _TlsConnectionPool:
        """懒惰初始化连接池（首次查询时创建）"""
        if not self._pool_created:
            self._pool = _TlsConnectionPool(
                self.host, self.port, self._ssl_context,
                self.host, self._connection_pool_size, self.timeout,
            )
            self._pool.start_keepalive()
            self._pool_created = True
        return self._pool

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建 SSL 上下文（CA 证书验证 + 自定义 CA + ECH 配置）"""
        ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

        if self._ca_path:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.set_ciphers(ciphers)
            try:
                ctx.load_verify_locations(self._ca_path)
                logger.info("DoT %s: 使用自定义 CA 证书（系统默认 CA 已禁用）", self.host)
            except Exception as e:
                logger.critical(
                    "DoT %s: 加载自定义 CA 证书失败: %s，系统 CA 不可信，程序退出",
                    self.host, e,
                )
                raise SystemExit(1)
        else:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.set_ciphers(ciphers)

        if self._ech_enabled and self._HAS_ECH and self._ech_config:
            try:
                ech_obj = ssl.ECHClientConfig(self._ech_config)
                ctx.set_ech_config(ech_obj)
                logger.debug("DoT %s: ECHConfigList 已配置到 SSL 上下文 (%d bytes)",
                             self.host, len(self._ech_config))
            except Exception as e:
                logger.warning("DoT %s: ECH 配置失败: %s", self.host, e)

        # 当 ECH 启用时，强制 TLS 1.3 only（RFC 8446 标准套件）
        if self._ech_enabled:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphers(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
            )

        return ctx

    async def resolve(self, query_bytes: bytes) -> Optional[bytes]:
        """
        通过 TLS 加密连接解析 DNS（先 hostname 直连，再 fallback bootstrap IP）。
        使用连接池复用 TLS 连接，避免每查询新建/销毁 TLS 连接。
        """
        connect_targets = [self.host]
        if self._connect_ips:
            for ip in self._connect_ips:
                if ip != self.host:
                    connect_targets.append(ip)

        pool = self._get_pool()

        async with self._semaphore:
            last_error = None
            conn: Optional[_TlsConnection] = None
            for target in connect_targets:
                try:
                    conn = await pool.acquire(target)
                    msg_len = len(query_bytes)
                    conn.writer.write(msg_len.to_bytes(2, "big") + query_bytes)
                    await asyncio.wait_for(conn.writer.drain(), timeout=self.timeout)

                    raw_len = await asyncio.wait_for(
                        conn.reader.readexactly(2), timeout=self.timeout
                    )
                    resp_len = int.from_bytes(raw_len, "big")
                    if resp_len < 12 or resp_len > 65535:
                        logger.debug("DoT %s: 响应长度 %d 超出范围", self.host, resp_len)
                        await pool.discard(conn)
                        conn = None
                        raise ConnectionError(f"无效的响应长度: {resp_len}")

                    response_data = await asyncio.wait_for(
                        conn.reader.readexactly(resp_len), timeout=self.timeout
                    )

                    await pool.release(conn)
                    conn = None
                    return response_data

                except (asyncio.TimeoutError, ConnectionError, OSError,
                        ssl.SSLError, asyncio.IncompleteReadError) as e:
                    last_error = e
                    if conn is not None:
                        await pool.discard(conn)
                        conn = None
                    if len(connect_targets) > 1:
                        logger.debug("DoT %s (%s) 尝试失败: %s，切换到下一地址",
                                     self.host, target, e)
                    continue
                except Exception as e:
                    last_error = e
                    if conn is not None:
                        await pool.discard(conn)
                        conn = None
                    logger.debug("DoT %s (%s) 未知错误: %s", self.host, target, e)
                    continue
                finally:
                    if conn is not None:
                        await pool.discard(conn)
                        conn = None

            if isinstance(last_error, asyncio.TimeoutError):
                logger.debug("DoT %s:%d 超时 (timeout=%s)", self.host, self.port, self.timeout)
            elif isinstance(last_error, ConnectionError):
                logger.debug("DoT %s:%d 连接错误: %s", self.host, self.port, last_error)
            elif isinstance(last_error, ssl.SSLError):
                logger.debug("DoT %s:%d SSL错误: %s", self.host, self.port, last_error)
            elif last_error:
                logger.debug("DoT %s:%d 失败: %s [%s]",
                             self.host, self.port, last_error, type(last_error).__name__)
            return None

    async def close(self):
        """关闭连接池，释放所有 TLS 连接"""
        if self._pool:
            await self._pool.close_all()
            self._pool = None
            self._pool_created = False

    async def reset_connections(self):
        """
        重置连接池：关闭所有连接，下次查询重新创建。
        网络恢复后调用（如网卡禁用/重新启用），确保不使用失效连接。
        """
        await self.close()
        logger.debug("DoT %s: TLS 连接池已重置", self.host)

    async def close_idle(self):
        """Close only idle connections, keep active ones."""
        if self._pool:
            await self._pool.close_idle()
            logger.debug("DoT %s: 空闲 TLS 连接已关闭", self.host)

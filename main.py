#!/usr/bin/env python3
"""
SecureDNS Proxy - 安全 DNS 加密代理
====================================
功能:
  - 本地 DoH 服务（HTTPS 加密 DNS）
  - 上游 DoH/DoT/DoQ 加密 DNS 支持
  - 并行查询 + 最快响应选择
  - DNS 缓存（LRU + TTL）
  - AdGuard Home 规则过滤
  - 异步请求日志（内存缓冲 → 文件）
  - 运行时控制 API
  - 资源优化（内存/CPU 监控）

架构:
  客户端 → [本地 DoH (HTTPS)] → [并行解析管理器] → [上游 DoH/DoT/DoQ]
                              → [DNS 缓存]
                              → [域名过滤引擎]
                              → [异步日志记录]
"""

import os
import sys
import asyncio
import signal
import logging
from pathlib import Path
from typing import Optional

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import Config
from cache import DNSCache
from logger import RequestLogger
from filter_engine import FilterEngine
from resolver_manager import ResolverManager
from doh_server import DoHServer
from plain_dns_server import PlainDNSServer
from optimizer import ResourceOptimizer
from dnssec import DNSSECValidator, DNSSECQueryWrapper

# ======================== 日志配置 ========================
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_dir: str = "logs"):
    """配置日志系统"""
    log_path = Path(PROJECT_ROOT) / log_dir
    log_path.mkdir(parents=True, exist_ok=True)

    # 文件日志
    file_handler = logging.FileHandler(
        log_path / "proxy.log", encoding="utf-8", mode="a"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # 降低第三方库的日志级别
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("quic").setLevel(logging.WARNING)  # 抑制 aioquic 大量连接日志

    return root_logger


# ======================== 主应用 ========================


class DNSProxyApp:
    """DNS 代理应用"""

    def __init__(self, config_path: Optional[str] = None):
        self.config = Config(config_path)
        self.cache: Optional[DNSCache] = None
        self.request_logger: Optional[RequestLogger] = None
        self.filter_engine: Optional[FilterEngine] = None
        self.resolver_manager: Optional[ResolverManager] = None
        self.resource_optimizer: Optional[ResourceOptimizer] = None
        self.doh_server: Optional[DoHServer] = None
        self.plain_dns_server: Optional[PlainDNSServer] = None
        # DNSSEC
        self._dnssec_validator: Optional[DNSSECValidator] = None
        self._dnssec_wrapper: Optional[DNSSECQueryWrapper] = None

        self._config_reload_task: Optional[asyncio.Task] = None
        self._cache_cleanup_task: Optional[asyncio.Task] = None
        self._filter_update_task: Optional[asyncio.Task] = None
        self._running = False

    async def initialize(self):
        """初始化所有组件"""
        logger = logging.getLogger("dns-proxy.app")
        logger.info("=" * 60)
        logger.info("SecureDNS Proxy 正在初始化...")
        logger.info("=" * 60)

        # 设置自定义事件循环异常处理器，抑制 aioquic 内部 Future 异常日志
        loop = asyncio.get_running_loop()
        original_exc_handler = loop.get_exception_handler()

        def _exc_handler(loop, context):
            exc = context.get("exception")
            msg = context.get("message", "")
            if isinstance(exc, ConnectionError) and "Future exception" in msg:
                return  # 忽略 aioquic 内部 Future 的 ConnectionError
            if original_exc_handler:
                original_exc_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(_exc_handler)

        # 1. 缓存
        logger.info("[1/8] 初始化 DNS 缓存...")
        self.cache = DNSCache(
            max_size=self.config.cache_max_size,
            default_ttl=self.config.cache_default_ttl,
            min_ttl=self.config.cache_min_ttl,
            max_ttl=self.config.cache_max_ttl,
            negative_ttl=self.config.cache_negative_ttl,
            cleanup_interval=self.config.cache_cleanup_interval,
        )

        # 2. DNSSEC 验证器
        logger.info("[2/8] 初始化 DNSSEC 验证器...")
        self._dnssec_validator = DNSSECValidator(enabled=self.config.dnssec_enabled)
        self._dnssec_wrapper = DNSSECQueryWrapper(
            self._dnssec_validator, enabled=self.config.dnssec_enabled
        )
        logger.info("  DNSSEC: %s, mode=%s",
                     "启用" if self.config.dnssec_enabled else "禁用",
                     self.config.dnssec_mode)

        # 3. 过滤器
        logger.info("[3/8] 初始化域名过滤引擎...")
        self.filter_engine = FilterEngine()
        if self.config.filter_enabled:
            rule_files = self.config.filter_rules_files
            full_paths = [str(PROJECT_ROOT / f) for f in rule_files]
            rule_urls = self.config.filter_rules_urls
            await self.filter_engine.async_reload(full_paths, urls=rule_urls)

        # 4. 日志记录器
        logger.info("[4/8] 初始化异步日志记录器...")
        self.request_logger = RequestLogger(
            log_dir=str(PROJECT_ROOT / self.config.logging_dir),
            log_file=self.config.logging_file,
            buffer_size=self.config.logging_buffer_size,
            flush_interval=self.config.logging_flush_interval,
            enabled=self.config.logging_enabled,
            detailed=self.config.logging_detailed,
        )
        await self.request_logger.start()

        # 5. 并行解析管理器（带 DNSSEC）
        logger.info("[5/8] 初始化并行解析管理器...")
        self.resolver_manager = ResolverManager(self.config, dnssec_wrapper=self._dnssec_wrapper)
        await self.resolver_manager.initialize()

        # 6. 资源优化器
        logger.info("[6/8] 初始化资源优化器...")
        self.resource_optimizer = ResourceOptimizer(
            self.config, self.cache, self.resolver_manager, self.request_logger
        )
        await self.resource_optimizer.start()

        # 7. 本地 DoH 服务器（带 IPv6 + DNSSEC）
        logger.info("[7/8] 初始化本地 DoH 服务器...")
        self.doh_server = DoHServer(
            self.config,
            self.resolver_manager,
            self.cache,
            self.filter_engine,
            self.request_logger,
            dnssec_wrapper=self._dnssec_wrapper,
        )

        # 8. 普通 DNS 服务器（UDP 53，默认关闭）
        logger.info("[8/8] 初始化普通 DNS 服务器...")
        self.plain_dns_server = PlainDNSServer(
            self.config,
            self.resolver_manager,
            self.cache,
            self.filter_engine,
            self.request_logger,
            dnssec_wrapper=self._dnssec_wrapper,
        )
        if self.config.plain_dns_enabled:
            logger.info("  普通 DNS 服务器已启用（UDP 53）")
        else:
            logger.info("  普通 DNS 服务器已禁用（可在配置中启用）")

        # 注册配置热加载回调
        self.config.on_reload(self._on_config_reload)

        logger.info("=" * 60)
        logger.info("初始化完成！")
        logger.info("=" * 60)

    async def _on_config_reload(self, new_config: dict):
        """配置热加载回调"""
        logger = logging.getLogger("dns-proxy.app")
        logger.info("配置已热加载，应用新配置...")

    async def _config_reload_loop(self):
        """定期检查配置文件变更"""
        while self._running:
            try:
                await asyncio.sleep(5)
                changed = await self.config.check_reload()
                if changed:
                    logging.getLogger("dns-proxy.app").info("配置文件已变更，已热加载")
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _cache_cleanup_loop(self):
        """定期清理过期缓存"""
        while self._running:
            try:
                await asyncio.sleep(self.config.cache_cleanup_interval)
                if self.cache:
                    await self.cache.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def start(self):
        """启动所有服务"""
        logger = logging.getLogger("dns-proxy.app")
        self._running = True

        # 启动 DoH 服务器（IPv4 + IPv6）
        await self.doh_server.start()

        # 启动普通 DNS 服务器（UDP 53，默认关闭）
        if self.config.plain_dns_enabled:
            await self.plain_dns_server.start()

        # 启动后台任务
        self._config_reload_task = asyncio.create_task(self._config_reload_loop())
        self._cache_cleanup_task = asyncio.create_task(self._cache_cleanup_loop())

        # 启动过滤规则定时更新（如果配置了远程 URL）
        if self.config.filter_update_interval > 0 and self.config.filter_rules_urls:
            await self.filter_engine.start_auto_update(
                interval_hours=self.config.filter_update_interval,
                urls=self.config.filter_rules_urls,
            )
            logger.info("  - 规则自动更新: 每 %d 小时", self.config.filter_update_interval)

        logger.info("所有服务已启动！")
        logger.info("  - DoH 服务器: https://%s:%s%s (IPv4)",
                    self.config.doh_host if self.config.doh_host != "0.0.0.0" else "127.0.0.1",
                    self.config.doh_port,
                    self.config.doh_path)
        if self.config.doh_ipv6_enabled:
            logger.info("  - DoH 服务器: https://[%s]:%d%s (IPv6)",
                        self.config.doh_ipv6_host, self.config.doh_ipv6_port, self.config.doh_path)
        logger.info("  - 上游服务器: DoH x%d + DoT x%d + DoQ x%d",
                    len(self.config.doh_servers),
                    len(self.config.dot_servers),
                    len(self.config.doq_servers))
        logger.info("  - DNSSEC:     %s (mode=%s)",
                     "启用" if self.config.dnssec_enabled else "禁用",
                     self.config.dnssec_mode)
        logger.info("  - 过滤规则:   %d 条", self.filter_engine.stats["total_rules"] if self.config.filter_enabled else 0)
        logger.info("=" * 60)

    async def stop(self):
        """优雅关闭所有服务"""
        logger = logging.getLogger("dns-proxy.app")
        logger.info("正在关闭服务...")

        self._running = False

        # 取消后台任务
        for task in [self._config_reload_task, self._cache_cleanup_task, self._filter_update_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        # 停止过滤规则自动更新
        if self.filter_engine:
            await self.filter_engine.stop_auto_update()

        # 停止服务器
        if self.doh_server:
            await self.doh_server.stop()
        if self.plain_dns_server:
            await self.plain_dns_server.stop()

        # 关闭解析器
        if self.resolver_manager:
            await self.resolver_manager.close_all()

        # 停止资源优化器
        if self.resource_optimizer:
            await self.resource_optimizer.stop()

        # 刷新日志
        if self.request_logger:
            await self.request_logger.stop()

        logger.info("所有服务已停止")


# ======================== 入口 ========================


async def main_async(config_path: Optional[str] = None):
    """异步主入口"""
    # 设置日志（在应用初始化前）
    logger = setup_logging()

    app = DNSProxyApp(config_path)

    try:
        await app.initialize()
        await app.start()

        # 保持运行直到收到停止信号
        stop_event = asyncio.Event()

        def signal_handler():
            logger.info("收到停止信号，正在退出...")
            stop_event.set()

        # 注册信号处理（Windows 上有限支持）
        try:
            loop = asyncio.get_running_loop()
            if sys.platform != "win32":
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, signal_handler)
            else:
                # Windows 上使用 asyncio 的事件处理
                def win_signal_handler():
                    signal_handler()
                loop.add_signal_handler(signal.SIGINT, win_signal_handler)
                loop.add_signal_handler(signal.SIGTERM, win_signal_handler)
        except NotImplementedError:
            pass

        await stop_event.wait()

    except KeyboardInterrupt:
        logger.info("收到中断信号")
    except Exception as e:
        logger.exception("启动失败: %s", e)
    finally:
        await app.stop()


def main():
    """主入口"""
    config_path = os.environ.get("DNS_PROXY_CONFIG")
    if not config_path:
        config_path = str(PROJECT_ROOT / "config.yaml")

    try:
        asyncio.run(main_async(config_path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

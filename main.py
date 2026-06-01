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
import gc
import asyncio
import signal
import logging
from pathlib import Path
from typing import Optional, List

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset
import dns.rcode

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import Config
from cache import DNSCache
from logger import RequestLogger, TrimFileHandler
from filter_engine import FilterEngine
from resolver_manager import ResolverManager
from doh_server import DoHServer
from local_dot_server import LocalDoTServer
from local_doq_server import LocalDoQServer
from plain_dns_server import PlainDNSServer
from optimizer import ResourceOptimizer
from network_monitor import NetworkMonitor
from dnssec import DNSSECValidator, DNSSECQueryWrapper

# ======================== 日志配置 ========================
LOG_FORMAT = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_dir: str = "logs", max_log_size_mb: int = 100):
    """配置日志系统（所有文件日志均带自动裁剪功能）"""
    log_path = Path(PROJECT_ROOT) / log_dir
    log_path.mkdir(parents=True, exist_ok=True)

    # 文件日志（自动裁剪）
    file_handler = TrimFileHandler(
        log_path / "proxy.log", max_log_size_mb=max_log_size_mb,
        encoding="utf-8", mode="a",
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
        self.local_dot_server: Optional[LocalDoTServer] = None
        self.local_doq_server: Optional[LocalDoQServer] = None
        self.plain_dns_server: Optional[PlainDNSServer] = None
        # DNSSEC
        self._dnssec_validator: Optional[DNSSECValidator] = None
        self._dnssec_wrapper: Optional[DNSSECQueryWrapper] = None

        self._config_reload_task: Optional[asyncio.Task] = None
        self._cache_cleanup_task: Optional[asyncio.Task] = None
        self._filter_update_task: Optional[asyncio.Task] = None
        self._filter_reload_task: Optional[asyncio.Task] = None  # 跟踪后台过滤规则重载
        self._filter_reload_gen = 0  # 递增 generation，防止过期重载覆盖
        self._running = False
        self.network_monitor: Optional[NetworkMonitor] = None  # 网络连通性监控

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
            if isinstance(exc, ConnectionResetError) and "_ProactorBasePipeTransport" in msg:
                return  # 忽略 Windows asyncio proactor 连接重置错误
            if isinstance(exc, OSError) and ("Accept failed" in msg or "accept" in str(context.get("socket", "")).lower()):
                return  # 忽略 Windows accept 客户端提前断开错误
            if original_exc_handler:
                original_exc_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(_exc_handler)

        # 1. 缓存
        logger.info("[1/11] 初始化 DNS 缓存...")
        self.cache = DNSCache(
            max_size=self.config.cache_max_size,
            default_ttl=self.config.cache_default_ttl,
            min_ttl=self.config.cache_min_ttl,
            max_ttl=self.config.cache_max_ttl,
            negative_ttl=self.config.cache_negative_ttl,
            cleanup_interval=self.config.cache_cleanup_interval,
        )

        # 2. DNSSEC 验证器
        logger.info("[2/11] 初始化 DNSSEC 验证器...")
        self._dnssec_validator = DNSSECValidator(enabled=self.config.dnssec_enabled)
        self._dnssec_wrapper = DNSSECQueryWrapper(
            self._dnssec_validator, enabled=self.config.dnssec_enabled
        )
        logger.info("  DNSSEC: %s, mode=%s",
                     "启用" if self.config.dnssec_enabled else "禁用",
                     self.config.dnssec_mode)

        # 3. 过滤器
        logger.info("[3/11] 初始化域名过滤引擎...")
        self.filter_engine = FilterEngine()
        # 加载自定义 hosts 映射
        self.filter_engine.load_custom_hosts(self.config.hosts_config)
        if self.config.filter_enabled:
            rule_files = self.config.filter_rules_files
            full_paths = [str(PROJECT_ROOT / f) for f in rule_files]
            rule_urls = self.config.filter_rules_urls
            # 先加载本地规则（快速，不阻塞启动）
            for fp in full_paths:
                self.filter_engine.load_rules_from_file(fp)
            # 远程 URL 规则后台原子加载（内部使用 async_reload 清除旧规则+重载全部）
            if rule_urls:
                self._filter_reload_task = asyncio.create_task(
                    self._filter_reload_safe(full_paths, rule_urls)
                )
        else:
            # 即使过滤规则关闭，也需要标记远程加载已完成（避免阻塞后续逻辑）
            logger.info("  过滤规则已禁用")

        # 4. 日志记录器
        logger.info("[4/11] 初始化异步日志记录器...")
        self.request_logger = RequestLogger(
            log_dir=str(PROJECT_ROOT / self.config.logging_dir),
            log_file=self.config.logging_file,
            buffer_size=self.config.logging_buffer_size,
            flush_interval=self.config.logging_flush_interval,
            enabled=self.config.logging_enabled,
            detailed=self.config.logging_detailed,
            max_log_size_mb=self.config.logging_max_log_size_mb,
        )
        await self.request_logger.start()

        # 5. 并行解析管理器（带 DNSSEC）
        logger.info("[5/11] 初始化并行解析管理器...")
        self.resolver_manager = ResolverManager(self.config, dnssec_wrapper=self._dnssec_wrapper)
        await self.resolver_manager.initialize()

        # 6. 资源优化器
        logger.info("[6/11] 初始化资源优化器...")
        self.resource_optimizer = ResourceOptimizer(
            self.config, self.cache, self.resolver_manager, self.request_logger
        )
        await self.resource_optimizer.start()

        # 7. 网络连通性监控
        logger.info("[7/11] 初始化网络连通性监控器...")
        self.network_monitor = NetworkMonitor(self.config, self.resolver_manager,
                                                 filter_engine=self.filter_engine)
        await self.network_monitor.start()

        # 8. 本地 DoH 服务器（带 IPv6 + DNSSEC）
        logger.info("[8/11] 初始化本地 DoH 服务器...")
        self.doh_server = DoHServer(
            self.config,
            self.resolver_manager,
            self.cache,
            self.filter_engine,
            self.request_logger,
            dnssec_wrapper=self._dnssec_wrapper,
        )

        # 9. 本地 DoT 服务器
        logger.info("[9/11] 初始化本地 DoT 服务器...")
        self.local_dot_server = LocalDoTServer(
            self.config,
            self.resolver_manager,
            self.cache,
            self.filter_engine,
            self.request_logger,
            dnssec_wrapper=self._dnssec_wrapper,
        )
        if self.config.local_dot_enabled:
            logger.info("  本地 DoT 服务器已启用（tls://%s:%d）",
                        self.config.local_dot_host, self.config.local_dot_port)
        else:
            logger.info("  本地 DoT 服务器已禁用（可在配置中启用）")

        # 10. 本地 DoQ 服务器
        logger.info("[10/11] 初始化本地 DoQ 服务器...")
        self.local_doq_server = LocalDoQServer(
            self.config,
            self.resolver_manager,
            self.cache,
            self.filter_engine,
            self.request_logger,
            dnssec_wrapper=self._dnssec_wrapper,
        )
        if self.config.local_doq_enabled:
            logger.info("  本地 DoQ 服务器已启用（quic://%s:%d）",
                        self.config.local_doq_host, self.config.local_doq_port)
        else:
            logger.info("  本地 DoQ 服务器已禁用（可在配置中启用）")

        # 11. 普通 DNS 服务器（UDP 53，默认关闭）
        logger.info("[11/11] 初始化普通 DNS 服务器...")
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

        # ========== 内存优化：启动后立即 GC ==========
        # 1. 手动 GC 回收导入模块和初始化过程中产生的临时对象
        gc.collect()
        # 2. freeze() 告知 GC 启动后所有存活对象都是永久性的，
        #    不再扫描它们，显著降低后续 GC 的 CPU 和内存开销
        gc.freeze()
        logger.info("  内存优化: gc.freeze() 已执行, 当前内存 %.0f MB",
                     self._get_memory_mb())

        logger.info("=" * 60)
        logger.info("初始化完成！")
        logger.info("=" * 60)

    async def _filter_reload_safe(self, files: List[str], urls: List[str]):
        """
        安全地原子重载全部过滤规则（本地+远程）。
        - 先清空旧规则再加载新规则，不会重复叠加
        - 适用于启动后台加载和热加载
        - 使用 generation 计数器防止过期加载覆盖
        - 加载完毕后自动扫描 DNS 缓存，覆写已缓存拦截域名的 IP
        """
        gen = self._filter_reload_gen + 1
        self._filter_reload_gen = gen
        logger = logging.getLogger("dns-proxy.app")
        logger.info("后台加载过滤规则 #%d (本地:%d 远程:%d)...",
                     gen, len(files), len(urls))
        try:
            await self.filter_engine.async_reload(files, urls=urls if urls else None)
            # generation 不匹配说明有更新的重载任务已开始，丢弃本次结果
            if self._filter_reload_gen != gen:
                logger.info("过滤规则 #%d 已过期（新重载 #%d 已开始），丢弃", gen, self._filter_reload_gen)
                return
            logger.info("过滤规则加载完成 #%d，共 %d 条规则",
                         gen, self.filter_engine.stats["total_rules"])
            logger.info("  拦截索引域名: %d, 白名单域名: %d",
                         self.filter_engine.stats["block_index_domains"],
                         self.filter_engine.stats["allow_index_domains"])

            # ========== 规则加载完毕后：扫描 DNS 缓存，覆写已缓存拦截域名的 IP ==========
            await self._sweep_cache_after_filter_load()

        except asyncio.CancelledError:
            logger.info("过滤规则加载 #%d 被取消", gen)
            self.filter_engine._filter_cache.clear()
            raise
        except Exception as e:
            logger.error("过滤规则加载 #%d 失败: %s", gen, e)

    async def _sweep_cache_after_filter_load(self):
        """
        过滤规则加载完毕后，扫描 DNS 缓存中的域名。
        如果有域名匹配新的拦截规则，将其 IP 覆写为 0.0.0.0（A记录）或 ::（AAAA记录）。
        这解决了"启动时规则未加载完 → 域名已被解析并缓存 → 规则加载后旧 IP 仍有效"的问题。
        """
        if not self.cache or not self.config.cache_enabled or not self.config.filter_enabled:
            return

        logger = logging.getLogger("dns-proxy.app")
        logger.info("开始扫描 DNS 缓存，检查是否有域名应被新规则拦截...")

        # 获取当前缓存的所有 key
        cache_keys = await self.cache.get_all_keys()
        swept_count = 0
        changed_count = 0

        for cache_key in cache_keys:
            qname, qtype, qclass = cache_key
            domain = str(qname).rstrip(".")
            # 检查是否匹配过滤规则
            blocked, _ = self.filter_engine.check_domain(domain)
            if blocked:
                # 获取当前缓存的响应
                cached_response = await self.cache.peek(cache_key)
                if cached_response is None:
                    continue
                # 检查当前缓存的 IP 是否已经是 0.0.0.0 或 ::
                already_blocked = False
                for rrset in cached_response.answer:
                    for rd in rrset:
                        if rd.rdtype == dns.rdatatype.A:
                            if str(rd.address) == "0.0.0.0":
                                already_blocked = True
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            if str(rd.address) == "::":
                                already_blocked = True
                if already_blocked:
                    continue
                # 覆写为拦截 IP
                # 注意：make_response() 需要 query 报文，cache 中存的是 response，需构造 query
                q_msg = dns.message.make_query(qname, qtype, qclass)
                new_response = dns.message.make_response(q_msg)
                new_response.answer.clear()
                if qtype == dns.rdatatype.A:
                    new_response.answer.append(
                        dns.rrset.RRset(qname, qclass, dns.rdatatype.A)
                    )
                    new_response.answer[0].add(
                        dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0"), ttl=3600
                    )
                    new_response.set_rcode(dns.rcode.NOERROR)
                elif qtype == dns.rdatatype.AAAA:
                    new_response.answer.append(
                        dns.rrset.RRset(qname, qclass, dns.rdatatype.AAAA)
                    )
                    new_response.answer[0].add(
                        dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, "::"), ttl=3600
                    )
                    new_response.set_rcode(dns.rcode.NOERROR)
                else:
                    new_response.set_rcode(dns.rcode.NXDOMAIN)
                await self.cache.set(cache_key, new_response)
                changed_count += 1
            swept_count += 1

        logger.info("缓存扫描完成: 检查 %d 条, 覆写 %d 条为拦截 IP", swept_count, changed_count)

    @staticmethod
    def _get_memory_mb() -> float:
        """获取当前进程内存占用（MB）"""
        try:
            import psutil
            proc = psutil.Process()
            return proc.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    async def _on_config_reload(self, new_config: dict, changed_sections: set = None):
        """
        配置热加载回调 — 只当 DNS 缓存配置或域名过滤规则（AdGuard Home 语法）
        变更时才重新加载拦截规则和替换缓存中匹配的拦截域名。
        其他配置段（upstream/performance/logging/network_monitor等）变更不会触发任何过滤相关操作。

        Args:
            new_config: 新的完整配置字典
            changed_sections: 发生变更的配置段名称集合
        """
        logger = logging.getLogger("dns-proxy.app")
        if changed_sections is None:
            changed_sections = set()

        if not self.filter_engine:
            return

        # ===== 检测是否涉及过滤相关的配置段 =====
        filter_cache_changed = "cache" in changed_sections or "filter" in changed_sections or "hosts" in changed_sections

        # 0. 始终重新加载自定义 hosts 映射（但只在 hosts 段变化时）
        if "hosts" in changed_sections and "hosts" in new_config:
            self.filter_engine.load_custom_hosts(new_config.get("hosts", {}))
            logger.info("自定义 hosts 映射已重新加载")

        # 如果完全不涉及 filter/cache/hosts 的变化，直接跳过所有过滤相关操作
        if not filter_cache_changed:
            logger.debug("配置变更段 %s 与过滤/缓存无关，跳过过滤规则重载", changed_sections)
            return

        # 只有 cache/filter/hosts 段变更时才清除过滤结果缓存
        self.filter_engine.clear_filter_cache()
        logger.debug("过滤结果缓存已清除（由 %s 变更触发）", ",".join(sorted(changed_sections & {"cache", "filter", "hosts"})))

        if not self.config.filter_enabled:
            logger.info("过滤规则已禁用，跳过规则重载")
            return

        # ===== 检测 filter 段是否有实质性的规则变更 =====
        if "filter" not in changed_sections:
            logger.debug("域名过滤规则配置未变更，跳过规则重载")
            return

        # 判断 rules_files 或 rules_urls 是否真正变更
        new_urls = new_config.get("filter", {}).get("rules_urls", [])
        if not isinstance(new_urls, list):
            new_urls = []

        # 比较新旧 URL 列表（转为规范化集合比较）
        old_urls = set(self.filter_engine._loaded_urls)
        new_urls_set = set(new_urls)

        # 比较 rules_files
        new_files = new_config.get("filter", {}).get("rules_files", [])
        if not isinstance(new_files, list):
            new_files = []
        old_files = set(self.filter_engine._loaded_files)
        new_files_full = {str(PROJECT_ROOT / f) for f in new_files}

        # 如果 rules_files 和 rules_urls 都没变，跳过重载
        if old_files == new_files_full and old_urls == new_urls_set:
            logger.debug("过滤规则文件/URL 均未变更，跳过规则重载")
            return

        logger.info("过滤规则配置已变更（文件: %s, URL: %s），开始重载...",
                     "变更" if old_files != new_files_full else "未变",
                     "变更" if old_urls != new_urls_set else "未变")

        full_paths = list(new_files_full) if new_files_full else [str(PROJECT_ROOT / f) for f in self.config.filter_rules_files]
        # generation 机制确保先完成的重载不会覆盖后完成的
        self._filter_reload_task = asyncio.create_task(
            self._filter_reload_safe(full_paths, list(new_urls_set))
        )

    async def _config_reload_loop(self):
        """定期检查配置文件变更"""
        while self._running:
            try:
                await asyncio.sleep(5)
                changed = await self.config.check_reload()
                if changed:
                    logging.getLogger("dns-proxy.app").info(
                        "配置文件已变更（变更段: %s），已热加载", ",".join(sorted(changed))
                    )
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

        # 启动本地 DoT 服务器
        if self.config.local_dot_enabled:
            await self.local_dot_server.start()

        # 启动本地 DoQ 服务器
        if self.config.local_doq_enabled:
            await self.local_doq_server.start()

        # 启动普通 DNS 服务器（UDP 53，默认关闭）
        if self.config.plain_dns_enabled:
            await self.plain_dns_server.start()

        # 注册 ARP IP 切换后的 TCP 监听器重启钩子
        # netsh 切换 IP 后 Windows IOCP 会取消所有排队的 AcceptEx 操作，
        # 导致 TCP 监听 socket 失效（WinError 64），需要显式重启服务器。
        if self.network_monitor and hasattr(self.network_monitor, '_arp_protection'):
            ap = self.network_monitor._arp_protection
            if ap.enabled:
                ap.register_restart_hook(self.doh_server.restart)
                if self.config.local_dot_enabled:
                    ap.register_restart_hook(self.local_dot_server.restart)
                if self.config.local_doq_enabled:
                    ap.register_restart_hook(self.local_doq_server.restart)
                logger.info("  - ARP 防护: 已注册 %d 个 TCP 监听器重启钩子",
                             len(ap._restart_hooks))

        # 启动后台任务
        self._config_reload_task = asyncio.create_task(self._config_reload_loop())
        self._cache_cleanup_task = asyncio.create_task(self._cache_cleanup_loop())

        # 启动过滤规则定时更新（如果配置了远程 URL）
        if self.config.filter_update_interval > 0 and self.config.filter_rules_urls:
            rule_files = self.config.filter_rules_files
            full_paths = [str(PROJECT_ROOT / f) for f in rule_files]
            await self.filter_engine.start_auto_update(
                interval_hours=self.config.filter_update_interval,
                urls=self.config.filter_rules_urls,
                files=full_paths,
            )
            logger.info("  - 规则自动更新: 每 %d 小时（完整替换模式）", self.config.filter_update_interval)

        logger.info("所有服务已启动！")
        # 启动后再次 GC
        gc.collect()
        logger.info("  - 启动后内存: %.0f MB", self._get_memory_mb())
        logger.info("  - DoH 服务器: https://%s:%s%s (IPv4)",
                    self.config.doh_host if self.config.doh_host != "0.0.0.0" else "127.0.0.1",
                    self.config.doh_port,
                    self.config.doh_path)
        if self.config.doh_ipv6_enabled:
            logger.info("  - DoH 服务器: https://[%s]:%d%s (IPv6)",
                        self.config.doh_ipv6_host, self.config.doh_ipv6_port, self.config.doh_path)
        if self.config.local_dot_enabled:
            logger.info("  - DoT 服务器: tls://%s:%d (域名=%s)",
                        self.config.local_dot_host if self.config.local_dot_host != "0.0.0.0" else "127.0.0.1",
                        self.config.local_dot_port,
                        self.config.local_dot_domain or "未设置")
        if self.config.local_doq_enabled:
            logger.info("  - DoQ 服务器: quic://%s:%d (域名=%s)",
                        self.config.local_doq_host if self.config.local_doq_host != "0.0.0.0" else "127.0.0.1",
                        self.config.local_doq_port,
                        self.config.local_doq_domain or "未设置")
        logger.info("  - 上游服务器: DoH x%d + DoT x%d + DoQ x%d",
                    len(self.config.doh_servers),
                    len(self.config.dot_servers),
                    len(self.config.doq_servers))
        logger.info("  - DNSSEC:     %s (mode=%s)",
                     "启用" if self.config.dnssec_enabled else "禁用",
                     self.config.dnssec_mode)
        nm_cfg = self.config.get_raw().get("network_monitor", {})
        logger.info("  - 网络监控:   %s (网关检测=%gs, 外网检测=%ds)",
                     "启用" if self.config.network_monitor_enabled else "禁用",
                     nm_cfg.get("ping_interval", 0.01),
                     nm_cfg.get("external_interval", 15))
        logger.info("  - 过滤规则:   %d 条", self.filter_engine.stats["total_rules"] if self.config.filter_enabled else 0)
        logger.info("=" * 60)

    async def stop(self):
        """优雅关闭所有服务"""
        logger = logging.getLogger("dns-proxy.app")
        logger.info("正在关闭服务...")

        self._running = False

        # 取消后台任务
        for task in [self._config_reload_task, self._cache_cleanup_task,
                     self._filter_update_task, self._filter_reload_task]:
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
        if self.local_dot_server:
            await self.local_dot_server.stop()
        if self.local_doq_server:
            await self.local_doq_server.stop()
        if self.plain_dns_server:
            await self.plain_dns_server.stop()

        # 关闭解析器
        if self.resolver_manager:
            await self.resolver_manager.close_all()

        # 停止资源优化器
        if self.resource_optimizer:
            await self.resource_optimizer.stop()

        # 停止网络监控
        if self.network_monitor:
            await self.network_monitor.stop()

        # 刷新日志
        if self.request_logger:
            await self.request_logger.stop()

        logger.info("所有服务已停止")


# ======================== 入口 ========================


async def main_async(config_path: Optional[str] = None):
    """异步主入口"""
    # 设置日志（在应用初始化前，使用默认值；随后更新为配置值）
    logger_root = setup_logging(max_log_size_mb=100)
    logger = logger_root  # 给异常处理器等使用

    app = DNSProxyApp(config_path)

    # 用配置文件中的 max_log_size 更新文件日志处理器
    try:
        max_size = app.config.logging_max_log_size_mb
        log_dir = app.config.logging_dir
        log_path = Path(PROJECT_ROOT) / log_dir
        for h in logger_root.handlers:
            if isinstance(h, TrimFileHandler):
                h._max_bytes = max_size * 1024 * 1024
                logger_root.info("日志文件最大大小已设置为 %dMB", max_size)
                break
    except Exception:
        pass

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


def _is_admin() -> bool:
    """检查当前进程是否具有管理员/root 权限"""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return True  # 无法判断时默认放行
    else:
        return os.geteuid() == 0


def _elevate():
    """
    自动提权：非管理员时重新以管理员/root 身份启动。
    - Windows: UAC 弹窗
    - Linux/macOS: sudo 提权
    """
    if _is_admin():
        return

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        except Exception as e:
            print(f"UAC 提权失败: {e}，继续以当前权限运行")
            return
    else:
        import shlex
        import subprocess
        cmd = ["sudo", sys.executable] + sys.argv
        try:
            subprocess.run(cmd, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"sudo 提权失败: {e}，继续以当前权限运行")
            return

    sys.exit()


def main():
    """主入口"""
    # 自动提权：ARP 防护模块需要管理员/root 权限执行 netsh/iptables 等命令
    _elevate()

    config_path = os.environ.get("DNS_PROXY_CONFIG")
    if not config_path:
        config_path = str(PROJECT_ROOT / "config.yaml")

    try:
        asyncio.run(main_async(config_path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

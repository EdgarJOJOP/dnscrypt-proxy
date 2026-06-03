"""
网络连通性监控器
- 定期 ping/探测网络连通性（IPv4 + IPv6 双栈）
- 检测网络中断/恢复，自动重新启用上游服务器
- 支持 ICMP ping 和 DNS 探测两种检测方式
- 集成 ARP 防护：网络检测失败时自动刷新网关 ARP 缓存
"""

import sys
import asyncio
import logging
from typing import List, Optional

import dns.message
import dns.rdatatype
import dns.asyncquery

from arp_protection import ARPProtection

logger = logging.getLogger("dns-proxy.network")


class NetworkMonitor:
    """
    网络连通性监控器

    在网络中断时自动检测，网络恢复后自动：
    1. 重新启用所有被禁用的上游 DNS 服务器
    2. 刷新 bootstrap DNS 缓存（重新解析上游域名 → IP）
    """

    def __init__(self, config, resolver_manager, filter_engine=None):
        self.config = config
        self.resolver_manager = resolver_manager
        self.filter_engine = filter_engine  # 网络恢复时用于清除过滤结果缓存

        # 运行状态
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # 降级状态追踪
        self._degraded = False          # 是否处于降级模式（网络异常）
        self._consecutive_failures = 0  # 连续检测失败次数
        self._last_recovery_time = 0.0  # 上次恢复时间戳

        # ARP 防护锁（防止 10ms 间隔下并发执行 refresh_router_arp）
        self._arp_busy = False
        # 网络断开标记：ARP 防护完整执行失败且外网也不可达时设置，
        # 后续跳过 ARP 防护直到外网检测恢复（避免路由器关机时无限循环）
        self._arp_network_down = False
        # 连通性检测运行中标志（防止断网时 1s 间隔重叠检测）
        self._connectivity_check_busy = False

        # 从配置读取
        nm = config.get_raw().get("network_monitor", {})
        self._enabled = nm.get("enabled", True)
        self._interval = nm.get("ping_interval", 0.01)  # 网关检测间隔（秒，默认 10ms）
        self._external_interval = nm.get("external_interval", 15)  # 外网检测间隔（秒）
        self._next_external_check = 0.0  # 下次外网检测时间戳
        self._ping_timeout = nm.get("ping_timeout", 5)  # ping 超时（秒）
        self._ping_targets_v4 = nm.get("ping_targets_v4", ["223.5.5.5", "114.114.114.114"])
        self._ping_targets_v6 = nm.get("ping_targets_v6", ["2400:3200::1", "2400:da00::6666"])
        self._dns_probe_domains = nm.get("dns_probe_domains", ["www.baidu.com", "www.qq.com"])
        self._failure_threshold = nm.get("failure_threshold", 3)  # 连续多少次失败后进入降级
        self._recovery_check_count = nm.get("recovery_check_count", 2)  # 恢复需要连续成功次数
        self._recovery_successes = 0  # 恢复检测连续成功计数

        # DNS 探测复用解析器缓存（避免每次探测创建新 UDP 套接字）
        self._dns_probe_resolvers: Dict[str, "PlainDNSResolver"] = {}

        # ARP 防护
        self._arp_protection = ARPProtection(config.arp_protection_config)

    @property
    def enabled(self) -> bool:
        """监控器是否启用"""
        return self._enabled

    @property
    def is_degraded(self) -> bool:
        """是否处于降级模式"""
        return self._degraded

    async def start(self):
        """启动监控循环"""
        if not self._enabled:
            logger.info("网络连通性监控已禁用")
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("网络连通性监控已启动 (网关检测=%gs, 外网检测=%ds, ping目标=%s)",
                     self._interval, self._external_interval, self._ping_targets_v4 + self._ping_targets_v6)

        # ARP 防护：自动探测网关（手动配置了 IP+MAC 则跳过）
        if self._arp_protection.enabled and not self._arp_protection.is_manual:
            await self._arp_protection.detect_gateway()

    async def stop(self):
        """停止监控循环"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ======================== 主循环 ========================

    async def _monitor_loop(self):
        """
        监控主循环（双速检测）：
        - 网关 ping：10ms 间隔，快速发现 ARP 投毒
        - 外网 ping + DNS 探测：15s 间隔，判断整体连通性
        """
        while self._running:
            try:
                now = asyncio.get_event_loop().time()

                # ========== 1. 快速网关检测（10ms） ==========
                gw_ok = True
                gw_ip = self._arp_protection.gateway_ip
                if gw_ip:
                    gw_ok = await self._arp_protection._ping_gateway(gw_ip)

                # 网关可达时清除断网标记（网络已恢复）
                if gw_ok:
                    self._arp_network_down = False
                    self.resolver_manager.set_network_down(False)

                # ARP 防护：网关不通时尝试恢复
                if not gw_ok and self._arp_protection.enabled \
                        and not self._arp_protection.is_manual and not self._arp_busy:
                    if self._arp_network_down:
                        # 已确认是网络断开而非 ARP 攻击（之前跑完一轮 ARP 防护 + 外网不可达），
                        # 跳过 ARP 防护，等外网连通性检测恢复后再重新启用
                        pass
                    else:
                        iface_ok, iface_details = await self._arp_protection.check_interface_healthy()
                        if iface_ok:
                            logger.warning("ARP 防护: 网关 ping 失败，本地网卡正常 (%s)，"
                                         "尝试刷新路由器 ARP ...", iface_details)
                        else:
                            logger.warning("ARP 防护: 网关 ping 失败，接口检查异常 (%s)"
                                         "（可能为 ipconfig/route 解析误判），仍尝试 ARP 刷新",
                                         iface_details)
                        self._arp_busy = True
                        try:
                            if await self._arp_protection.refresh_router_arp():
                                if await self._arp_protection._ping_gateway(gw_ip):
                                    logger.info("ARP 防护: 路由器 ARP 刷新后网关已恢复")
                                    gw_ok = True
                            if not gw_ok:
                                # ARP 防护完整执行后网关仍不通 → 快速检查外网
                                # 如果外网也不可达说明是网络断开而非攻击，标记后跳过后续循环
                                ext_ok = await self._check_connectivity()
                                if not ext_ok:
                                    self._arp_network_down = True
                                    self.resolver_manager.set_network_down(True)
                                    logger.warning("ARP 防护: 所有恢复手段失败且外网不可达，"
                                                  "确认网络断开，暂停 ARP 防护等待网络恢复")
                        finally:
                            self._arp_busy = False

                # ========== 2. 外网连通性检测（15s / 断网时 1s） ==========
                if now >= self._next_external_check:
                    # 断网时 1 秒检测一次快速恢复；正常时用配置间隔
                    check_interval = 1.0 if self._arp_network_down else self._external_interval
                    self._next_external_check = now + check_interval
                    ext_ok = False
                    if not self._connectivity_check_busy:
                        self._connectivity_check_busy = True
                        try:
                            ext_ok = await self._check_connectivity()
                        finally:
                            self._connectivity_check_busy = False

                    if ext_ok:
                        self._arp_network_down = False  # 外网恢复，清除断网标记
                        self.resolver_manager.set_network_down(False)
                        self._consecutive_failures = 0
                        if self._degraded:
                            self._recovery_successes += 1
                            if self._recovery_successes >= self._recovery_check_count:
                                logger.info("网络已恢复（连续 %d 次外网检测成功），开始恢复上游...",
                                             self._recovery_successes)
                                await self._recover()
                                self._recovery_successes = 0
                        else:
                            self._recovery_successes = 0
                    else:
                        self._consecutive_failures += 1
                        self._recovery_successes = 0
                        if not self._degraded \
                                and self._consecutive_failures >= self._failure_threshold:
                            self._degraded = True
                            logger.warning("外网连通性异常（连续 %d 次检测失败），进入降级模式",
                                            self._consecutive_failures)

                # 快速间隔
                await asyncio.sleep(self._interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("网络监控异常: %s", e)
                await asyncio.sleep(0.1)

    # ======================== 连通性检测 ========================

    async def _check_connectivity(self) -> bool:
        """
        综合检测网络连通性
        检测方式（任一成功即视为连通）：
        1. ICMP ping 检测（IPv4 + IPv6 双栈）
        2. DNS 探测（向公共 DNS 发送 A/AAAA 查询）
        """
        results = await asyncio.gather(
            self._ping_check_v4(),
            self._ping_check_v6(),
            self._dns_probe_check(),
            return_exceptions=True,
        )

        successes = sum(1 for r in results if r is True)
        if successes > 0:
            logger.debug("网络连通性检测: %d/3 成功 (ping4=%s, ping6=%s, dns=%s)",
                         successes, results[0], results[1], results[2])
            return True
        else:
            logger.debug("网络连通性检测: 全部失败")
            return False

    async def _ping_check_v4(self) -> bool:
        """ICMP ping IPv4 目标"""
        if not self._ping_targets_v4:
            return False
        for target in self._ping_targets_v4:
            if await self._ping(target):
                return True
        return False

    async def _ping_check_v6(self) -> bool:
        """ICMP ping IPv6 目标"""
        if not self._ping_targets_v6:
            return False
        for target in self._ping_targets_v6:
            if await self._ping(target):
                return True
        return False

    async def _ping(self, target: str) -> bool:
        """
        使用系统 ping 命令检测连通性
        跨平台支持 Windows / Linux
        """
        is_ipv6 = ":" in target
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(int(self._ping_timeout * 1000))]
            if is_ipv6:
                cmd.append("-6")
            cmd.append(target)
        else:
            cmd = ["ping", "-c", "1", "-W", str(self._ping_timeout)]
            cmd.append(target)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=self._ping_timeout + 2)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return False

    async def _dns_probe_check(self) -> bool:
        """
        DNS 探测：向 bootstrap 公共 DNS 发送 A/AAAA 查询
        验证 DNS 协议栈是否正常工作
        复用 PlainDNSResolver 实例，避免每次探测创建新 UDP 套接字
        """
        if not self._dns_probe_domains:
            return False
        bootstrap_addrs = self.resolver_manager.get_bootstrap_addresses()
        if not bootstrap_addrs:
            # 回退到配置中的 ping targets
            bootstrap_addrs = self._ping_targets_v4 + self._ping_targets_v6
            if not bootstrap_addrs:
                return False

        for domain in self._dns_probe_domains:
            for addr in bootstrap_addrs:
                try:
                    q = dns.message.make_query(domain, dns.rdatatype.A)
                    qbytes = q.to_wire()
                    is_ipv6 = ":" in addr
                    family = "v6" if is_ipv6 else "v4"
                    from resolvers.plain import PlainDNSResolver

                    # 复用解析器实例，避免每次创建新 UDP 套接字
                    if addr not in self._dns_probe_resolvers:
                        self._dns_probe_resolvers[addr] = PlainDNSResolver(
                            addr, timeout=self._ping_timeout,
                        )
                    resolver = self._dns_probe_resolvers[addr]

                    result = await asyncio.wait_for(
                        resolver.resolve(qbytes, prefer_family=family),
                        timeout=self._ping_timeout,
                    )
                    if result is not None:
                        return True
                except Exception as e:
                    logger.debug("网络监控 ping 异常: %s", e)
                    continue
        return False

    # ======================== 自动恢复 ========================

    async def _recover(self):
        """
        网络恢复后的自动恢复操作：
        1. 等待短暂延迟，让网络栈完全初始化（Windows 网卡重新启用后需要时间）
        2. 重置所有解析器的持久连接（关闭失效的 aiohttp 会话等）
        3. 重新启用所有上游服务器（包括 bootstrap）
        4. 刷新所有上游域名 → IP 的 bootstrap 缓存
        5. 重置降级状态
        """
        logger.info("=" * 50)
        logger.info("网络已恢复，执行自动恢复...")

        # 0. 短暂延迟，让 Windows 网络栈完全初始化
        #    网卡启用后，ICMP ping 可能先于 TCP/UDP 恢复，等待 2 秒确保稳定
        logger.info("  等待网络栈稳定 (2s)...")
        await asyncio.sleep(2.0)

        # 1. 重置所有持久连接（关闭失效的 aiohttp 会话、QUIC 配置等）
        #    这是解决"网卡禁用/启用后上游持续失败"的关键步骤
        logger.info("  正在重置所有解析器的持久连接...")
        await self.resolver_manager.reset_all_connections()
        logger.info("  持久连接已重置")

        # 2. 进入恢复模式：网络刚恢复时，上游首次查询可能因连接重建
        #    而短暂失败，恢复模式下瞬时失败不会禁用上游
        self.resolver_manager.enter_recovery_mode()

        # 3. 重新启用所有上游
        self.resolver_manager.reenable_all()
        logger.info("  已重新启用所有上游服务器")

        # 4. 刷新所有 bootstrap IP 缓存
        refreshed = await self.resolver_manager.refresh_all_upstream_ips()
        logger.info("  已刷新 %d 个上游域名的 bootstrap IP 缓存", refreshed)

        # 5. 清除过滤引擎的过滤结果缓存
        #    断网期间过滤结果可能被误缓存为"放行"状态（FilterCache TTL=5s），
        #    不清除的话恢复后拦截规则中的域名会被错误放行（返回真实 IP 而非 0.0.0.0）
        #    注意：不需要清除 DNS 缓存，因为过滤检查在缓存检查之前执行
        if self.filter_engine:
            self.filter_engine.clear_filter_cache()
            logger.info("  已清除过滤引擎缓存")

        # 6. 标记恢复
        self._degraded = False
        self._consecutive_failures = 0
        self._recovery_successes = 0
        self._last_recovery_time = asyncio.get_event_loop().time()

        # 重新统计可用上游
        enabled = sum(1 for s in self.resolver_manager._upstream_servers if s.enabled)
        total = len(self.resolver_manager._upstream_servers)
        logger.info("自动恢复完成: %d/%d 个上游可用", enabled, total)
        logger.info("=" * 50)

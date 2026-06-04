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
import collections
from typing import List, Optional, Callable

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

        # 滑动窗口：记录最近 N 次 ping 结果
        self._gw_results: collections.deque = collections.deque(maxlen=5)   # 网关 ping 结果窗口 (~4s)
        self._ext_results: collections.deque = collections.deque(maxlen=3)  # 外网 ping 结果窗口 (~2.4s)

        # 网络断开标记：滑动窗口全丢包+外网不通时设置，
        # 跳过 ARP 防护直接抑制 DNS，恢复后重新启用
        self._arp_network_down = False

        # ARP 防护后台任务（主循环不 block，继续以 ping_interval 采样）
        self._arp_task: Optional[asyncio.Task] = None
        self._arp_last_end_time: float = 0.0  # 上次 ARP 防护结束时间，用于防抖

        # 从配置读取
        nm = config.get_raw().get("network_monitor", {})
        self._enabled = nm.get("enabled", True)
        self._interval = nm.get("ping_interval", 0.01)  # 网关检测间隔（秒，默认 10ms）
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
        self._arp_protection = ARPProtection(config.arp_protection_config,
                                              ping_timeout=self._ping_timeout)

        # 外网 ping 轮询索引（轮流 ping 多个 v4 目标，每轮一个）
        self._ext_ping_index = 0

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
        logger.info("网络连通性监控已启动 (网关检测=%gs, ping目标=%s)",
                     self._interval, self._ping_targets_v4 + self._ping_targets_v6)

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
        监控主循环（滑动窗口丢包检测）：
        - 每 ping_interval(0.80s) 采样一次：ping 网关 + ping 一个外网目标
        - 滑动窗口（网关5次/外网3次）计算丢包率
        - 丢包分级驱动 ARP 防护后台任务，主循环继续采样
        """
        while self._running:
            try:
                gw_ip = self._arp_protection.gateway_ip

                # ========== 1. ping 网关 + ping 外网（每轮一次） ==========
                gw_ok = True
                if gw_ip:
                    gw_ok = await self._arp_protection._ping_gateway(gw_ip)
                self._gw_results.append(gw_ok)

                # 每轮顺便 ping 一个外网 IPv4 目标（轮流）
                ext_ok = True
                if self._ping_targets_v4:
                    idx = self._ext_ping_index % len(self._ping_targets_v4)
                    self._ext_ping_index += 1
                    ext_ok = await self._ping(self._ping_targets_v4[idx])
                self._ext_results.append(ext_ok)

                # ========== 2. 从滑动窗口计算丢包分级 ==========
                loss_pct, diagnosis = self._classify_loss()

                # ========== 3. 决策 ==========
                if diagnosis == "recovered":
                    # 窗口内大部分成功 → 网络已正常
                    if self._arp_network_down or self.resolver_manager._network_down:
                        logger.info("网络已恢复 (网关丢包=%d%%, 外网正常)", loss_pct)
                        self._arp_network_down = False
                        self.resolver_manager.set_network_down(False)
                        # 从断网恢复时重建上游连接，避免 DNS 继续失败 19s
                        await self._recover()
                    # 取消还在运行的 ARP 防护任务
                    if self._arp_task and not self._arp_task.done():
                        self._arp_task.cancel()
                        self._arp_task = None

                elif diagnosis == "network_down":
                    # 全丢包 + 外网不通 → 确认断网，抑制 DNS
                    if not self._arp_network_down:
                        logger.warning("网络断开确认 (网关丢包=%d%%, 外网不可达)", loss_pct)
                        self._arp_network_down = True
                        self.resolver_manager.set_network_down(True)
                    # 取消可能还在跑的 ARP 防护任务（断网没必要跑）
                    if self._arp_task and not self._arp_task.done():
                        self._arp_task.cancel()
                        self._arp_task = None

                elif diagnosis == "arp_issue":
                    # 部分丢包 → 需要 ARP 防护（启动后台任务）
                    if not self._arp_network_down and self._arp_protection.enabled \
                            and not self._arp_protection.is_manual:
                        self.resolver_manager.set_network_down(True)
                        if not self._arp_task or self._arp_task.done():
                            logger.warning("ARP 防护: 网关丢包 %d%%，启动后台 ARP 修复", loss_pct)
                            self._arp_task = asyncio.create_task(
                                self._run_arp_defense(gw_ip, lambda: self._is_recovered())
                            )
                        else:
                            # 已有 ARP 防护任务在运行，主循环继续采样
                            pass

                # ========== 4. 外网降级跟踪（全量 check 每 15s 做一次，非每轮） ==========
                # 这里简化：降级状态仅用于触发全量 recover
                if not ext_ok and not self._arp_network_down:
                    self._consecutive_failures += 1
                    self._recovery_successes = 0
                    if not self._degraded \
                            and self._consecutive_failures >= self._failure_threshold:
                        self._degraded = True
                elif ext_ok and self._degraded:
                    self._recovery_successes += 1
                    if self._recovery_successes >= self._recovery_check_count:
                        await self._recover()
                        self._recovery_successes = 0
                elif ext_ok:
                    self._consecutive_failures = 0
                    self._recovery_successes = 0

                # ========== 5. 等待下一个采样周期 ==========
                await asyncio.sleep(self._interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("网络监控异常: %s", e)
                await asyncio.sleep(0.1)

    # ======================== 滑动窗口丢包分级 ========================

    def _classify_loss(self) -> tuple:
        """
        根据滑动窗口计算丢包率并分级。

        Returns:
            (loss_pct, diagnosis)
            diagnosis: "recovered" (丢包 <20%, 外网通)
                       "arp_issue" (丢包 20~89%)
                       "network_down" (丢包 ≥90% 且外网不通)
        """
        gw_len = len(self._gw_results)
        if gw_len < 2:
            # 窗口未填满，不做决策
            return (0, "normal")

        gw_fails = gw_len - sum(self._gw_results)
        gw_loss = int(gw_fails / gw_len * 100)

        ext_len = len(self._ext_results)
        ext_fails = ext_len - sum(self._ext_results) if ext_len > 0 else 0
        ext_loss = int(ext_fails / max(ext_len, 1) * 100) if ext_len > 0 else 100

        if gw_loss < 20 and ext_loss < 100:
            return (gw_loss, "recovered")
        elif gw_loss >= 90 and ext_loss >= 67:
            return (gw_loss, "network_down")
        elif gw_loss >= 20:
            return (gw_loss, "arp_issue")
        return (gw_loss, "normal")

    def _is_recovered(self) -> bool:
        """
        ARP 防护后台任务用：检查主循环的滑动窗口是否显示已恢复。
        被作为 abort_check 回调传给 refresh_router_arp。
        """
        loss_pct, diagnosis = self._classify_loss()
        # 网关恢复率 > 50% 就算恢复（窗口内至少 3/5 成功）
        gw_len = len(self._gw_results)
        if gw_len >= 3:
            gw_ok_count = sum(self._gw_results)
            if gw_ok_count >= max(3, gw_len // 2 + 1):
                return True
        return diagnosis == "recovered"

    async def _run_arp_defense(self, gw_ip: str, abort_check: Callable[[], bool]):
        """
        ARP 防护后台任务：在后台运行 refresh_router_arp，
        主循环继续以 ping_interval 采样。
        每步后检查 abort_check，若网络已恢复则提前退出。
        """
        if not gw_ip or not self._arp_protection.enabled:
            return

        # 防抖：距上次 ARP 结束不足 3s，跳过（波动期避免重复任务）
        now = asyncio.get_event_loop().time()
        if now - self._arp_last_end_time < 3.0:
            return

        try:
            # 并发执行接口检查（仅用于日志，不阻塞 ARP 修复）
            async def _log_iface_check():
                iface_ok, iface_details = await self._arp_protection.check_interface_healthy()
                loss_pct, _ = self._classify_loss()
                if iface_ok:
                    logger.warning("ARP 防护: 网关丢包 %d%%，本地网卡正常 (%s), 启动后台 ARP 修复",
                                   loss_pct, iface_details)
                else:
                    logger.warning("ARP 防护: 网关丢包 %d%%，接口检查异常 (%s)"
                                   "（可能为 ipconfig/route 解析误判），仍尝试 ARP 刷新",
                                   loss_pct, iface_details)

            iface_task = asyncio.create_task(_log_iface_check())

            # 立即启动 ARP 修复（不等待接口检查完成）
            result = await self._arp_protection.refresh_router_arp(abort_check=abort_check)

            # 等待接口检查日志完成（不关键，最多等 3s）
            if not iface_task.done():
                try:
                    await asyncio.wait_for(iface_task, timeout=3.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    iface_task.cancel()

            if result:
                # ARP 防护成功
                if abort_check() or await self._arp_protection._ping_gateway_fast(gw_ip):
                    logger.info("ARP 防护: 后台修复完成，网关已恢复")
                    self._arp_network_down = False
                    self.resolver_manager.set_network_down(False)
                    # 如果是从 network_down 恢复，重建上游连接
                    if self.resolver_manager._network_down:
                        await self._recover()
            else:
                # ARP 防护后网关仍不通 → 检查外网
                ext_ok = abort_check() or (len(self._ext_results) > 0 and
                                            sum(self._ext_results) > 0)
                if not ext_ok:
                    self._arp_network_down = True
                    self.resolver_manager.set_network_down(True)
                    logger.warning("ARP 防护: 后台修复无效且外网不可达，确认网络断开")
                else:
                    logger.warning("ARP 防护: 后台修复无效但外网可达，网关可能自身故障")
        except asyncio.CancelledError:
            logger.info("ARP 防护: 后台任务被取消（网络已恢复）")
        except Exception as e:
            logger.error("ARP 防护: 后台任务异常: %s", e)
        finally:
            self._arp_last_end_time = asyncio.get_event_loop().time()

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

"""
网络连通性监控器
- 定期 ping/探测网络连通性（IPv4 + IPv6 双栈）
- 检测网络中断/恢复，自动重新启用上游服务器
- 支持 ICMP ping 和 DNS 探测两种检测方式
- 集成 ARP 防护：IPv4 网络检测失败时自动刷新网关 ARP 缓存
- 集成 NDP 防护：IPv6 网络检测失败时自动刷新路由器邻居表
"""

import sys
import asyncio
import logging
import collections
from typing import Dict, List, Optional, Callable

import dns.message
import dns.rdatatype

from arp_protection import ARPProtection
from NDP_protection import NDPProtection

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
        self._recovery_in_progress = False  # 恢复互斥锁（防止并发恢复）

        # 滑动窗口：记录最近 N 次 ping 结果
        self._gw_results: collections.deque = collections.deque(maxlen=5)   # 网关 ping 结果窗口 (~4s)
        self._ext_results: collections.deque = collections.deque(maxlen=3)  # 外网 ping 结果窗口 (~2.4s)
        self._ext_results_v6: collections.deque = collections.deque(maxlen=3)

        # 网络断开标记：滑动窗口全丢包+外网不通时设置，
        # 跳过 ARP 防护直接抑制 DNS，恢复后重新启用
        self._arp_network_down = False

        # ARP 防护后台任务（主循环不 block，继续以 ping_interval 采样）
        self._arp_task: Optional[asyncio.Task] = None
        self._arp_last_end_time: float = 0.0  # 上次 ARP 防护结束时间，用于防抖

        # NDP 防护（IPv6 版 ARP 防护）后台任务
        self._ndp_network_down = False
        self._ndp_task: Optional[asyncio.Task] = None
        self._ndp_last_end_time: float = 0.0  # 上次 NDP 防护结束时间，用于防抖
        # IPv6 网关 ping 滑动窗口
        self._ndp_gw_results: collections.deque = collections.deque(maxlen=5)

        # 从配置读取
        nm = config.get_raw().get("network_monitor", {})
        self._enabled = nm.get("enabled", True)
        self._interval = nm.get("ping_interval", 0.01)  # 网关检测间隔（秒，默认 10ms）
        self._ping_timeout = nm.get("ping_timeout", 5)  # ping 超时（秒）
        self._ping_targets_v4 = nm.get("ping_targets_v4", ["223.5.5.5", "114.114.114.114"])
        self._ping_targets_v6 = nm.get("ping_targets_v6", ["2400:3200::1", "2400:da00::6666"])
        self._dns_probe_domains = nm.get("dns_probe_domains", ["www.baidu.com", "www.qq.com"])
        self._failure_threshold = nm.get("failure_threshold", 3)  # 连续多少次失败后进入降级
        self._external_interval = nm.get("external_interval", 15)  # 外网探测间隔（秒）
        self._recovery_check_count = nm.get("recovery_check_count", 2)  # 恢复需要连续成功次数
        self._recovery_successes = 0  # 恢复检测连续成功计数

        # DNS 探测复用解析器缓存（避免每次探测创建新 UDP 套接字）
        self._dns_probe_resolvers: Dict[str, "PlainDNSResolver"] = {}

        # ARP 防护
        self._arp_protection = ARPProtection(config.arp_protection_config,
                                              ping_interval=self._interval,
                                              ping_targets_v4=self._ping_targets_v4)

        # NDP 防护（IPv6）
        self._ndp_protection = NDPProtection(config.ndp_protection_config,
                                              ping_interval=self._interval,
                                              ping_targets_v6=self._ping_targets_v6)

        # 外网 ping 轮询索引（轮流 ping 多个 v4 目标，每轮一个）
        self._ext_ping_index = 0
        self._last_ext_check_time: float = 0.0  # 上次外网探测时间戳
        self._ext_ping_index_v6 = 0
        self._last_ext_check_time_v6: float = 0.0

        # 净化 dns_probe_domains：启动时移除非法域名
        self._dns_probe_domains = [
            d for d in self._dns_probe_domains
            if self._is_valid_domain(d)
        ]
        if len(self._dns_probe_domains) < len(nm.get("dns_probe_domains", [])):
            removed = set(nm.get("dns_probe_domains", [])) - set(self._dns_probe_domains)
            logger.warning("已移除 %d 个非法 DNS 探测域名: %s", len(removed), removed)

        # 常驻恢复 worker（事件触发，用完冻结）
        self._run_recover = asyncio.Event()
        self._recover_task: Optional[asyncio.Task] = None
        self._consecutive_network_down = 0         # 连续 network_down 计数

        # 日志抑制："网络已恢复" 防洪（ARP 攻击期间 GARP 脉冲反复触发）
        self._last_recovery_log_time: float = 0.0

        # ========== Destination Unreachable 快速断网检测（硬编码，始终启用） ==========
        self._wan_unreachable_codes = [0, 1]  # 0=Network Unreachable, 1=Host Unreachable
        # 缓存上次探测结果（避免每轮都重复分析）
        self._last_wan_probe_result: dict = None
        self._last_wan_probe_time: float = 0.0
        self._last_wan_probe_time_v6: float = 0.0  # IPv6 WAN 探测独立限速
        # 外网 ping 的轮换索引（用于 WAN 探测）
        self._wan_probe_index = 0
        self._wan_probe_index_v6 = 0  # IPv6 WAN 探测独立索引
        # WAN 断开确认时间戳（防止首轮误判恢复）
        self._wan_dead_confirmed_at: float = 0.0

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

        # ARP 防护：自动探测网关，然后启动常驻 worker
        if self._arp_protection.enabled:
            if not self._arp_protection.is_manual:
                await self._arp_protection.detect_gateway()
            # 启动常驻 worker（程序启动时创建一次，后续通过事件触发，无需反复 create_task）
            await self._arp_protection._start_workers()

        # NDP 防护：自动探测 IPv6 网关，然后启动 5 个常驻 worker + 30s 主动 NS 探测
        if self._ndp_protection.enabled:
            await self._ndp_protection.start()
            if not self._ndp_protection.enabled:
                logger.info("NDP 防护: 未检测到 IPv6 网关，保持待机")

        # 启动常驻恢复 worker（Worker 5）
        self._recover_task = asyncio.create_task(self._recover_worker_loop())
        logger.debug("网络监控: 常驻恢复 worker 已启动")

    async def stop(self):
        """停止监控循环"""
        self._running = False
        await self._arp_protection._stop_workers()
        await self._ndp_protection.stop()
        # 停止常驻恢复 worker
        if self._recover_task:
            self._run_recover.set()
            self._recover_task.cancel()
            try:
                await self._recover_task
            except asyncio.CancelledError:
                pass
            self._recover_task = None
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

                # IPv6 网关 ping（NDP 防护用）
                ndp_gw = self._ndp_protection.gateway_ipv6
                ndp_gw_ok = True
                if ndp_gw:
                    ndp_gw_ok = await self._ndp_protection._ping_ipv6(ndp_gw)
                    self._ndp_gw_results.append(ndp_gw_ok)

                # 外网探测：按 external_interval 间隔执行，不每轮都 ping
                ext_just_checked = False
                ext_ok = True
                if self._ping_targets_v4:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_ext_check_time >= self._external_interval:
                        self._last_ext_check_time = now
                        idx = self._ext_ping_index % len(self._ping_targets_v4)
                        self._ext_ping_index += 1
                        ext_ok = await self._ping(self._ping_targets_v4[idx])
                        # 只有真实外网 ping 后才更新滑动窗口，避免默认 True 值污染
                        self._ext_results.append(ext_ok)
                        ext_just_checked = True

                # IPv6 external ping (independent from IPv4)
                ext_v6_ok = True
                ext_v6_just_checked = False
                if self._ping_targets_v6:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_ext_check_time_v6 >= self._external_interval:
                        self._last_ext_check_time_v6 = now
                        idx = self._ext_ping_index_v6 % len(self._ping_targets_v6)
                        self._ext_ping_index_v6 += 1
                        ext_v6_ok = await self._ping(self._ping_targets_v6[idx])
                        self._ext_results_v6.append(ext_v6_ok)
                        ext_v6_just_checked = True

                                # ========== WAN 断连快速检测（Dest Unreachable） ==========
                # 当光猫运行但光纤断开时，光猫会对外网 ping 回复 ICMP type=3
                # (Destination Unreachable)。收到来自网关的 Dest Unreachable
                # 立即判定为 WAN 断连，跳过滑动窗口等待。
                if not ext_ok and ext_just_checked and not self._arp_network_down and not ext_v6_ok:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_wan_probe_time >= 1.0:
                        await self._check_wan_unreachable()

                # ========== IPv6 WAN 断开快速检测 ==========
                if not ext_v6_ok and ext_v6_just_checked and not self._ndp_network_down and ndp_gw is not None:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_wan_probe_time_v6 >= 1.0:
                        await self._check_wan_unreachable_v6(ndp_gw)

                # ========== 1.5 ARP 投毒检测（反制已在 _on_arp_attack 中并行执行，不暂停 DNS） ==========
                if self._arp_protection._poison_detected.is_set() and not self._arp_network_down:
                    self._arp_protection._poison_detected.clear()
                    # 如果 scapy 反制系统活跃（常驻 sender 已就绪），全量修复已不需要
                    if self._arp_protection._scapy_sender_ready:
                        logger.debug("ARP 防护: 反制激活中，跳过 monitor 级全量修复")
                    else:
                        logger.info("ARP 防护: 检测到 ARP 投毒（无 scapy），走 fallback 修复")
                        if await self._arp_protection.refresh_router_arp(
                                lambda: self._is_recovered()):
                            if await self._arp_protection._ping_gateway_fast(gw_ip):
                                logger.info("ARP 防护: 投毒修复完成，网关已恢复")
                                self._arp_protection._baseline_mac = (
                                    self._arp_protection.gateway_mac or "").replace("-", ":").upper()
                                self._arp_protection._last_alert_mac = ""

                # ========== 1.6 NDP 投毒检测（IPv6，不暂停 DNS） ==========
                if self._ndp_protection.enabled and self._ndp_protection._poison_detected.is_set() and not self._ndp_network_down:
                    self._ndp_protection._poison_detected.clear()
                    if self._ndp_protection._ndp_sender_ready:
                        logger.debug("NDP 防护: NDP 反制激活中，跳过 monitor 级全量修复")
                    else:
                        logger.info("NDP 防护: 检测到 NDP 投毒（无 scapy），走 fallback 修复")
                        if await self._ndp_protection.refresh_router_ndp(
                                lambda: self._is_recovered()):
                            logger.info("NDP 防护: 投毒修复完成，IPv6 网关已恢复")

                # ========== 2. 从滑动窗口计算丢包分级 ==========
                # 始终调用 _classify_loss 让滑动窗口真实数据判断，不会因 wan_dead 永久卡在 network_down
                loss_pct, diagnosis = self._classify_loss()
                # wan_dead 已经标记断网，但滑动窗口还未恢复时保持 network_down
                # Bug #1: WAN 断开确认后 ping_interval*5 内强制 network_down（给 ext_results 滑动窗口时间填充 False）
                if self._arp_network_down:
                    if diagnosis == "recovered" and self._wan_dead_confirmed_at > 0:
                        elapsed = asyncio.get_event_loop().time() - self._wan_dead_confirmed_at
                        if elapsed < self._interval * 5:
                            diagnosis = "network_down"
                            loss_pct = 100
                    elif diagnosis != "recovered":
                        diagnosis = "network_down"
                        loss_pct = 100
                # ========== 3. 决策 ==========
                if diagnosis == "recovered":
                    # 窗口内大部分成功 → 网络已正常
                    if self._arp_network_down or self.resolver_manager._network_down:
                        now = asyncio.get_event_loop().time()
                        if now - self._last_recovery_log_time >= 3.0:
                            logger.info("网络已恢复 [v4gw=" + str(sum(self._gw_results)) + "/" + str(len(self._gw_results)) + " v6gw=" + str(sum(self._ndp_gw_results)) + "/" + str(len(self._ndp_gw_results)) + " v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + " gw_loss=" + str(loss_pct) + "%]")
                            self._last_recovery_log_time = now
                        # ARP 攻击活跃期间：仅清除标志让 DNS 继续，不触发完整恢复
                        if self._has_active_arp_attacks(seconds=5.0) or self._has_active_ndp_attacks(seconds=5.0):
                            self._arp_network_down = False
                            self._ndp_network_down = False
                            self.resolver_manager.set_network_down(False)
                            self.resolver_manager.enter_recovery_mode()
                            self.resolver_manager.reenable_all()
                        else:
                            # ARP/NDP 安静期：触发完整恢复
                            # 同时直接清除标志作为兜底，防止 recovery worker 异常后主循环卡死
                            self._arp_network_down = False
                            self._ndp_network_down = False
                            self.resolver_manager.set_network_down(False)
                            self._run_recover.set()
                    # 取消还在运行的 ARP 防护任务
                    if self._arp_task and not self._arp_task.done():
                        self._arp_task.cancel()
                        self._arp_task = None
                    if self._ndp_task and not self._ndp_task.done():
                        self._ndp_task.cancel()
                        self._ndp_task = None
                    self._consecutive_network_down = 0

                elif diagnosis == "network_down":
                    # 全丢包 + 外网不通 → 确认断网，抑制 DNS
                    self._consecutive_network_down += 1
                    if self._consecutive_network_down >= 2:
                        if not self._arp_network_down and not self._ndp_network_down:
                            logger.warning("网络断开确认 (连续 " + str(self._consecutive_network_down) + " 轮, 网关丢包=" + str(loss_pct) + "%, 外网不可达" + " [v4gw=" + str(sum(self._gw_results)) + "/" + str(len(self._gw_results)) + " v6gw=" + str(sum(self._ndp_gw_results)) + "/" + str(len(self._ndp_gw_results)) + " v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + "]")
                            self._arp_network_down = True
                            self._ndp_network_down = True
                            self.resolver_manager.set_network_down(True)
                        # 取消可能还在跑的 ARP 防护任务（断网没必要跑）
                        if self._arp_task and not self._arp_task.done():
                            self._arp_task.cancel()
                            self._arp_task = None
                    else:
                        # 第一次检测到 network_down，打印一次日志但不切断 DNS（等下一轮确认）
                        logger.warning("网络连通性严重异常 (网关丢包=%d%%, 外网不可达), 等待下轮确认",
                                       loss_pct)

                elif diagnosis == "arp_issue":
                    # 部分丢包 → 需要 ARP 防护
                    self._consecutive_network_down = 0
                    # Bug #3: 如果 _arp_network_down 已由 WAN 断开检测触发，ARP 修复无效，直接跳过
                    if self._arp_network_down:
                        logger.debug("ARP 防护: WAN 已断开，跳过 ARP 修复")
                    elif self._arp_protection.enabled \
                            and not self._arp_protection.is_manual:
                        v6_has_ext = len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0
                        if not v6_has_ext:
                            self.resolver_manager.set_network_down(True)
                        else:
                            logger.debug("ARP v6 ext ok, skip DNS pause")
                        if not self._arp_task or self._arp_task.done():
                            logger.warning("ARP 防护: IPv4 网关丢包 %d%%，启动后台 ARP 修复", loss_pct)
                            self._arp_task = asyncio.create_task(
                                self._run_arp_defense(gw_ip, lambda: self._is_recovered())
                            )

                    # NDP defense for IPv6 (parallel to IPv4 ARP)
                    if self._ndp_protection.enabled:
                        if not self._ndp_task or self._ndp_task.done():
                            ndp_gw = self._ndp_protection.gateway_ipv6
                            if ndp_gw:
                                logger.warning("NDP 防护: IPv6 网关丢包，启动后台 NDP 修复" + " [v4gw=" + str(sum(self._gw_results)) + "/" + str(len(self._gw_results)) + " v6gw=" + str(sum(self._ndp_gw_results)) + "/" + str(len(self._ndp_gw_results)) + " v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + "]")
                                self._ndp_task = asyncio.create_task(
                                    self._run_ndp_defense(ndp_gw, lambda: self._is_recovered())
                                )
                else:
                    # normal - reset network_down counter
                    self._consecutive_network_down = 0
                # ========== 4. External degradation tracking
                if ext_just_checked and not ext_ok and not self._arp_network_down and not (len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0):
                    self._consecutive_failures += 1
                    self._recovery_successes = 0
                    if not self._degraded and self._consecutive_failures >= self._failure_threshold:
                        self._degraded = True
                        self._arp_network_down = True
                        self._ndp_network_down = True
                        self.resolver_manager.set_network_down(True)
                elif ext_ok and ext_just_checked and self._degraded:
                    self._recovery_successes += 1
                    if self._recovery_successes >= self._recovery_check_count:
                        self._degraded = False
                        self._consecutive_failures = 0
                        self._recovery_successes = 0
                        if not self._recovery_in_progress:
                            self._run_recover.set()
                elif ext_ok and ext_just_checked:
                    self._consecutive_failures = 0
                    self._recovery_successes = 0

                # ========== 5. 等待下一个采样周期 ==========
                await asyncio.sleep(self._interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("网络监控异常: %s", e, exc_info=True)
                await asyncio.sleep(0.1)

    # ======================== WAN 断连快速检测 ========================

    async def _check_wan_unreachable(self):
        """
        WAN 断连快速检测：
        对外网目标发 ICMP，如果收到来自网关的 Destination Unreachable，
        立即判定为 WAN 断连（光纤断开但光猫仍在运行），
        跳过滑动窗口等待，直接设 _arp_network_down=True。
        """
        if not self._ping_targets_v4:
            return
        gw_ip = self._arp_protection.gateway_ip
        if not gw_ip:
            return

        try:
            # Bug #8: 先获取目标，提前增加索引但不保存结果的情况下不浪费索引
            idx = self._wan_probe_index % len(self._ping_targets_v4)
            self._wan_probe_index += 1
            target = self._ping_targets_v4[idx]

            result = await ARPProtection.probe_wan_unreachable(
                target,
                gateway_ip=gw_ip,
                timeout_ms=int(self._ping_timeout * 1000),
            )
        except Exception as e:
            logger.debug("WAN 断连检测异常: %s", e)
            self._last_wan_probe_time = asyncio.get_event_loop().time()
            return

        self._last_wan_probe_result = result
        self._last_wan_probe_time = asyncio.get_event_loop().time()
        if result.get("wan_dead"):
            logger.warning("WAN 断连检测: 网关 %s 对 %s 回复 Destination Unreachable "
                           "(code=%s)，光纤可能已断开，跳过滑动窗口等待",
                           result.get("from_ip", "?"), target,
                           result.get("unreachable_code", "?"))
            # Bug #1: 清空 ext_results 防止首轮误判恢复
            self._ext_results.clear()
            for _ in range(self._ext_results.maxlen):
                self._ext_results.append(False)
            self._wan_dead_confirmed_at = self._last_wan_probe_time
            self._arp_network_down = True
            ext_v6_alive = len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0
            if not ext_v6_alive:
                self._ndp_network_down = True
            self.resolver_manager.set_network_down(True)

            # 取消可能还在跑的 ARP 防护任务
            if self._arp_task and not self._arp_task.done():
                self._arp_task.cancel()
                self._arp_task = None
        elif result.get("timeout"):
            # 超时可能是防火墙丢包，不判定
            pass

    # ======================== WAN 断连快速检测 (IPv6) ========================

    async def _check_wan_unreachable_v6(self, ndp_gw: str):
        """IPv6 WAN 断连快速检测：对外网 IPv6 目标发 ping -6，
        检测是否收到来自 IPv6 网关的 ICMPv6 type=1 Destination Unreachable。
        """
        if not self._ping_targets_v6:
            return

        try:
            idx = self._wan_probe_index_v6 % len(self._ping_targets_v6)
            self._wan_probe_index_v6 += 1
            target = self._ping_targets_v6[idx]

            result = await self._ndp_protection.probe_wan_unreachable_v6(
                target,
                timeout_sec=int(self._ping_timeout),
                gateway_ipv6=ndp_gw,
            )
        except Exception as e:
            logger.debug("WAN 断连检测 (IPv6) 异常: %s", e)
            self._last_wan_probe_time_v6 = asyncio.get_event_loop().time()
            return

        self._last_wan_probe_time_v6 = asyncio.get_event_loop().time()
        if result.get("wan_dead"):
            logger.warning("WAN 断连检测 (IPv6): 网关 %s 对 %s 回复 ICMPv6 "
                           "Destination Unreachable (code=%s)，光纤可能已断开",
                           result.get("from_ip", "?"), target,
                           result.get("unreachable_code", "?"))
            # 清空 ext_results 防止首轮误判
            self._ext_results.clear()
            for _ in range(self._ext_results.maxlen):
                self._ext_results.append(False)
            self._wan_dead_confirmed_at = self._last_wan_probe_time_v6
            self._ndp_network_down = True
            ext_v4_alive = len(self._ext_results) > 0 and sum(self._ext_results) > 0
            if not ext_v4_alive:
                self._arp_network_down = True
            self.resolver_manager.set_network_down(True)

    # ======================== 滑动窗口丢包分级 ========================

    def _classify_loss(self) -> tuple:
        """
        根据滑动窗口计算丢包率并分级。
        优先使用 IPv4 网关窗口；无 IPv4 网关时回退到 IPv6 网关窗口。

        Returns:
            (loss_pct, diagnosis)
            diagnosis: "recovered" (丢包 <20%, 外网通)
                       "arp_issue" (丢包 20~89%)
                       "network_down" (丢包 ≥90% 且外网不通)
        """
        # 优先使用 IPv4 网关窗口；无 IPv4 网关时回退到 IPv6
        gw_results = self._gw_results
        if self._arp_protection.gateway_ip is None and self._ndp_protection.gateway_ipv6:
            gw_results = self._ndp_gw_results

        gw_len = len(gw_results)
        if gw_len < 2:
            # 窗口未填满，不做决策
            return (0, "normal")

        gw_fails = gw_len - sum(gw_results)
        gw_loss = int(gw_fails / gw_len * 100)

        # IPv4 网关高丢包时，回退到 IPv6 网关检测
        if gw_loss >= 50 and self._arp_protection.gateway_ip is not None                 and self._ndp_protection.gateway_ipv6:
            ndp_len = len(self._ndp_gw_results)
            if ndp_len >= 2:
                ndp_fails = ndp_len - sum(self._ndp_gw_results)
                ndp_loss = int(ndp_fails / ndp_len * 100)
                # IPv6 正常说明网关本身可达，问题在 IPv4 层
                if ndp_loss < 50:
                    gw_loss = ndp_loss
                    gw_results = self._ndp_gw_results

        ext_len = len(self._ext_results)
        if ext_len < 2:
            ext_loss = 0
        else:
            ext_fails = ext_len - sum(self._ext_results)
            ext_loss = int(ext_fails / ext_len * 100)

        ext_v6_len = len(self._ext_results_v6)
        if ext_v6_len >= 2:
            ext_v6_fails = ext_v6_len - sum(self._ext_results_v6)
            ext_v6_loss = int(ext_v6_fails / ext_v6_len * 100)
        else:
            ext_v6_loss = 0

        if ext_loss == 100 and ext_v6_loss < 67 and gw_loss < 20:
            return (gw_loss, "recovered")
        if ext_loss == 100 and ext_v6_loss < 67:
            ext_loss = ext_v6_loss

        # Bug #2 fix        # Bug #2 fix: 网关正常但外网全丢——可能是 ONT 静默丢包（不发 Dest Unreachable）
        if gw_loss < 20 and ext_loss == 100:
            return (gw_loss, "network_down")
        if gw_loss < 20 and ext_loss < 100:
            return (gw_loss, "recovered")
        elif gw_loss >= 90 and ext_loss >= 67:
            return (gw_loss, "network_down")
        elif gw_loss >= 20:
            return (gw_loss, "arp_issue")
        return (gw_loss, "normal")

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """
        校验域名是否合法（防止 IDNA 编码异常）。
        尝试 DNS 名称编码，失败说明含非法字符。
        """
        if not domain or not isinstance(domain, str):
            return False
        domain = domain.strip().rstrip(".")
        if not domain or len(domain) > 253:
            return False
        try:
            domain.encode("idna")
            return True
        except (UnicodeError, ValueError):
            return False

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

    def _has_active_arp_attacks(self, seconds: float = 5.0) -> bool:
        """检查过去 seconds 秒内 ARP 防护是否检测到攻击。"""
        return self._arp_protection.has_recent_attacks(seconds)

    def _has_active_ndp_attacks(self, seconds: float = 5.0) -> bool:
        """检查过去 seconds 秒内 NDP 防护是否检测到攻击。"""
        return self._ndp_protection.enabled and self._ndp_protection.has_recent_attacks(seconds)

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
                    logger.warning("ARP 防护: IPv4 网关丢包 %d%%，本地网卡正常 (%s), 启动后台 ARP 修复",
                                   loss_pct, iface_details)
                else:
                    logger.warning("ARP 防护: IPv4 网关丢包 %d%%，接口检查异常 (%s)"
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
                    # 如果是从 network_down 恢复，触发常驻 recover worker
                    if self.resolver_manager._network_down:
                        self._run_recover.set()
                    else:
                        # 未标记断网（波动中快速修复），直接恢复 DNS
                        self._arp_network_down = False
                        self.resolver_manager.set_network_down(False)
            else:
                # ARP 防护后网关仍不通 → 检查外网
                ext_ok = abort_check() or ((len(self._ext_results) > 0 and sum(self._ext_results) > 0) or (len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0))
                if not ext_ok:
                    self._arp_network_down = True
                    # 注意：IPv4 ARP 修复失败时不标记 _ndp_network_down，
                    # IPv6 可能仍可达，由 NDP 防护独立判断
                    self.resolver_manager.set_network_down(True)
                    logger.warning("ARP 防护: 后台修复无效且外网不可达，确认网络断开" + " [v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + " ndp_down=" + str(self._ndp_network_down) + "]")
                else:
                    logger.warning("ARP 防护: 后台修复无效但外网可达，网关可能自身故障")
        except asyncio.CancelledError:
            logger.info("ARP 防护: 后台任务被取消（网络已恢复）")
        except Exception as e:
            logger.error("ARP 防护: 后台任务异常: %s", e)
        finally:
            self._arp_last_end_time = asyncio.get_event_loop().time()

    async def _run_ndp_defense(self, gw_ip: str, abort_check: Callable[[], bool]):
        """NDP 防护后台任务：在后台运行 refresh_router_ndp"""
        if not gw_ip or not self._ndp_protection.enabled:
            return
        now = asyncio.get_event_loop().time()
        if now - self._ndp_last_end_time < 3.0:
            return
        try:
            result = await self._ndp_protection.refresh_router_ndp(abort_check=abort_check)
            if result:
                ndp_gw = self._ndp_protection.gateway_ipv6
                if abort_check() or (ndp_gw and await self._ndp_protection._ping_ipv6(ndp_gw)):
                    logger.info("NDP 防护: 后台修复完成，IPv6 网关已恢复")
                    if self.resolver_manager._network_down and not self._arp_network_down:
                        self.resolver_manager.set_network_down(False)
                    self._ndp_network_down = False
            else:
                ext_ok = abort_check() or ((len(self._ext_results) > 0 and sum(self._ext_results) > 0) or (len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0))
                if not ext_ok:
                    self._ndp_network_down = True
                    self.resolver_manager.set_network_down(True)
                    logger.warning("NDP 防护: 后台修复无效且外网不可达，确认网络断开" + " [v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + " arp_down=" + str(self._arp_network_down) + "]")
                else:
                    logger.warning("NDP 防护: 后台修复无效但外网可达，IPv6 网关可能自身故障")
        except asyncio.CancelledError:
            logger.info("NDP 防护: 后台任务被取消（网络已恢复）")
        except Exception as e:
            logger.error("NDP 防护: 后台任务异常: %s", e)
        finally:
            self._ndp_last_end_time = asyncio.get_event_loop().time()

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
        ICMP 失败时自动尝试 TCP 连接兜底（端口 80/443），
        防止因 Windows 上 scapy 原始套接字拦截 ping.exe 的 ICMP 回复导致的误判。
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
            if proc.returncode == 0:
                return True
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass

        # ICMP 失败时尝试 TCP 连接兜底（端口 443/80）
        # Windows 上 scapy 的 L2pcapListenSocket 可能会拦截 ping.exe 的 ICMP Echo Reply，
        # 导致 ping.exe 超时返回非零退出码。TCP 兜底不受 scapy 原始套接字影响。
        if not is_ipv6:
            for port in (443, 80):
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=min(self._ping_timeout + 2, 5.0),
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    continue
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
            # 校验域名合法性：跳过含非法 Unicode/IDNA 字符的域名
            if not self._is_valid_domain(domain):
                logger.warning("DNS 探测: 跳过非法域名 '%s'", domain)
                continue
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
        try:
            # 0. 短暂延迟，让 Windows 网络栈完全初始化
            #    主循环已经确认了多轮成功 ping，网络已通，0.5s 足够
            logger.info("  等待网络栈稳定 (0.5s)...")
            await asyncio.sleep(0.5)

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
            self._arp_network_down = False
            self._ndp_network_down = False
            self.resolver_manager.set_network_down(False)

            # 重新统计可用上游
            enabled = sum(1 for s in self.resolver_manager._upstream_servers if s.enabled)
            total = len(self.resolver_manager._upstream_servers)
            logger.info("自动恢复完成: %d/%d 个上游可用", enabled, total)
        except Exception as e:
            logger.error("自动恢复异常: %s", e, exc_info=True)
            self._degraded = False
            self._consecutive_failures = 0
            self._recovery_successes = 0
        finally:
            self._recovery_in_progress = False
        logger.info("=" * 50)

    async def _recover_worker_loop(self):
        """
        常驻恢复 worker（Worker 5）：永久等待 _run_recover 事件 → 执行恢复操作 → 冻结。
        由 NetworkMonitor.start() 创建一次，后续通过 _run_recover.set() 触发。
        天然防并发：worker 正在恢复时再次 set() 无效，恢复完回 wait() 后下一次触发才生效。
        """
        while True:
            await self._run_recover.wait()
            if not self._running:
                return
            self._run_recover.clear()

            if self._recovery_in_progress:
                continue
            self._recovery_in_progress = True

            # ARP/NDP 攻击活跃期间跳过连接重置 —— 连接并未失效，是攻击导致的反制波动
            if self._has_active_arp_attacks(seconds=5.0) or self._has_active_ndp_attacks(seconds=5.0):
                logger.info("  [后台恢复] ARP/NDP 攻击仍活跃中，跳过连接重置，仅放行 DNS")
                self._arp_network_down = False
                self._ndp_network_down = False
                self.resolver_manager.set_network_down(False)
                self.resolver_manager.enter_recovery_mode()
                self.resolver_manager.reenable_all()
                self._recovery_in_progress = False
                continue

            # 执行恢复操作（与原来的 _delayed_recover 一致）
            try:
                await asyncio.sleep(0.5)  # 网络栈短暂稳定

                await self.resolver_manager.reset_all_connections()
                logger.info("  [后台恢复] 持久连接已重置")

                self.resolver_manager.enter_recovery_mode()
                self.resolver_manager.reenable_all()
                logger.info("  [后台恢复] 已重新启用所有上游")

                refreshed = await self.resolver_manager.refresh_all_upstream_ips()
                logger.info("  [后台恢复] 已刷新 %d 个上游域名缓存", refreshed)

                if self.filter_engine:
                    self.filter_engine.clear_filter_cache()
                    logger.info("  [后台恢复] 已清除过滤引擎缓存")

                # 重置降级状态
                self._degraded = False
                self._consecutive_failures = 0
                self._recovery_successes = 0
                self._last_recovery_time = asyncio.get_event_loop().time()

                # === 所有恢复操作完成，最后才放行 DNS 查询 ===
                self._arp_network_down = False
                self._ndp_network_down = False
                self.resolver_manager.set_network_down(False)

                enabled = sum(1 for s in self.resolver_manager._upstream_servers if s.enabled)
                total = len(self.resolver_manager._upstream_servers)
                logger.info("  [后台恢复] 完成: %d/%d 个上游可用，DNS 查询已恢复", enabled, total)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("后台恢复异常: %s", e, exc_info=True)
                # 异常时也要放行 DNS，防止主循环卡死
                self._arp_network_down = False
                self._ndp_network_down = False
                self.resolver_manager.set_network_down(False)
            finally:
                self._recovery_in_progress = False

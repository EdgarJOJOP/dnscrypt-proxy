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
        self._gw_results: collections.deque = collections.deque(maxlen=10)   # 网关 ping 结果窗口 (~4s)
        self._ext_results: collections.deque = collections.deque(maxlen=10)  # 外网 ping 结果窗口 (~2.4s)

        self._ext_results_v6: collections.deque = collections.deque(maxlen=10)

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
        self._ndp_gw_results: collections.deque = collections.deque(maxlen=10)

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

        # ========== Destination Unreachable 快速断网检测（可从配置关闭）==========
        self._wan_detect_enabled = nm.get("detect_destination_unreachable", True)
        self._wan_unreachable_codes = nm.get("unreachable_codes", [0, 1])

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

        # ARP 侧 IP 冲突反制联动 NDP：宣告本机 IPv6-MAC + 静态 NDP 绑定
        self._arp_protection._ndp_callback = self._ndp_announce_callback

        # NDP 复用 ARP 常驻 scapy 发送器（scapy/Npcap 发送资源单进程独占：
        # NDP 内部重复 import scapy 直接 sendp 会永久降级系统 fallback）
        self._ndp_protection._arp_sender = self._arp_protection

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

        # 断网/恢复回调：由 DNSProxyApp 连接，断网时停止本地服务，恢复时重启
        self._on_network_down: Optional[callable] = None
        self._on_network_up: Optional[callable] = None

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

        # ScapyBridge：ARP/NDP 共享单一 Npcap 嗅探会话（审计合并，减少驱动会话占用）
        # 配置开关：仅当 ARP 或 NDP 防护 enabled 时才启动桥；两者都关则桥不启动
        try:
            from scapy_bridge import get_scapy_bridge
            _bridge = get_scapy_bridge()
            _bridge.set_loop(asyncio.get_event_loop())
            if (self._arp_protection.enabled or self._ndp_protection.enabled) and _bridge.start_if_ready():
                logger.info("网络监控: ScapyBridge 共享嗅探已启动（ARP/NDP 单一 Npcap 会话）")
        except Exception as e:
            logger.warning("网络监控: ScapyBridge 启动异常: %s", e)

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
        # 停止共享 ScapyBridge（干净退出 sniff 线程，释放 Npcap 会话，防 STOP_PENDING）
        try:
            from scapy_bridge import get_scapy_bridge
            get_scapy_bridge().stop()
        except Exception:
            pass
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
                ndp_gw_ok = True
                if gw_ip and self._ndp_protection.gateway_ipv6:
                    results = await asyncio.gather(
                        self._arp_protection._ping_gateway(gw_ip),
                        self._ndp_protection._ping_ipv6(self._ndp_protection.gateway_ipv6, timeout_ms=50),
                        return_exceptions=True,
                    )
                    gw_ok = results[0] if not isinstance(results[0], Exception) else False
                    ndp_gw_ok = results[1] if not isinstance(results[1], Exception) else False
                elif gw_ip:
                    gw_ok = await self._arp_protection._ping_gateway(gw_ip)
                elif self._ndp_protection.gateway_ipv6:
                    ndp_gw_ok = await self._ndp_protection._ping_ipv6(self._ndp_protection.gateway_ipv6, timeout_ms=50)
                # 无 v4 网关时不向 _gw_results 填充（双栈独立性修复 L13：原恒填 True 稀释丢包率）
                if gw_ip:
                    self._gw_results.append(gw_ok)
                ndp_gw = self._ndp_protection.gateway_ipv6
                if ndp_gw:
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
                # （修复：原条件用每轮局部变量 ext_v6_ok（默认 True 仅 v6 探测轮更新），
                #   使 v4 快速检测几乎永不触发；改用 v6 滑动窗口与 408 行降级判定一致）
                ext_v6_window_alive = len(self._ext_results_v6) > 0 and sum(self._ext_results_v6) > 0
                if not ext_ok and ext_just_checked and not self._arp_network_down and not ext_v6_window_alive:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_wan_probe_time >= 1.0 and self._wan_detect_enabled:
                        await self._check_wan_unreachable()

                # ========== IPv6 WAN 断开快速检测 ==========
                if not ext_v6_ok and ext_v6_just_checked and not self._ndp_network_down and ndp_gw is not None:
                    now = asyncio.get_event_loop().time()
                    if now - self._last_wan_probe_time_v6 >= 1.0 and self._wan_detect_enabled:
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
                                # 注意：不重新赋值 _baseline_mac！基线在 detect_gateway 启动时一次性锁定，
                                # 此处 gateway_mac 可能已被攻击者污染，覆盖基线将导致永久错误。
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
                            # 注意：不重新赋值 _baseline_mac_per_gw！基线在 detect_gateway 启动时一次性锁定，
                            # refresh_router_ndp 只发 NA 不修改基线，此处应保持。

                # ========== 2. 从滑动窗口计算丢包分级 ==========
                # 始终调用 _classify_loss 让滑动窗口真实数据判断，不会因 wan_dead 永久卡在 network_down
                loss_pct, diagnosis = self._classify_loss()
                # wan_dead 已经标记断网，但滑动窗口还未恢复时保持 network_down
                # 修复 M4：保护窗口与外网探测周期匹配（原 _interval*5 仅 0.05~0.25s，远小于 ext 窗口填充时间）
                _protect_window = max(self._external_interval, 5.0)
                if self._arp_network_down or self._ndp_network_down:
                    if diagnosis == "recovered" and self._wan_dead_confirmed_at > 0:
                        elapsed = asyncio.get_event_loop().time() - self._wan_dead_confirmed_at
                        if elapsed < _protect_window:
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
                            # DNS unblock done by recovery worker
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
                            # 触发断网回调：停止所有本地加密 DNS 服务
                            if self._on_network_down is not None:
                                try:
                                    await self._on_network_down()
                                except Exception:
                                    pass
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
                        if len(self._gw_results) >= 5 and not v6_has_ext:
                            self.resolver_manager.set_network_down(True)
                        elif not v6_has_ext:
                            logger.debug("ARP v4 gw window small (%d), skip DNS pause", len(self._gw_results))
                        else:
                            logger.debug("ARP v6 ext ok, skip DNS pause")
                        if not self._arp_task or self._arp_task.done():
                            logger.warning("ARP 防护: IPv4 网关丢包 %d%%，启动后台 ARP 修复" + " [v4gw=" + str(sum(self._gw_results)) + "/" + str(len(self._gw_results)) + " v6gw=" + str(sum(self._ndp_gw_results)) + "/" + str(len(self._ndp_gw_results)) + " v4ext=" + str(sum(self._ext_results)) + "/" + str(len(self._ext_results)) + " v6ext=" + str(sum(self._ext_results_v6)) + "/" + str(len(self._ext_results_v6)) + "]", loss_pct)
                            self._arp_task = asyncio.create_task(
                                self._run_arp_defense(gw_ip, lambda: self._is_recovered())
                            )

                    # NDP defense for IPv6 (仅当 IPv6 网关实际丢包时才触发)
                    if self._ndp_protection.enabled:
                        v6gw_loss = (len(self._ndp_gw_results) > 0 and
                                     sum(self._ndp_gw_results) < len(self._ndp_gw_results) * 0.8)
                        if v6gw_loss:
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
                        # 触发断网回调：停止所有本地加密 DNS 服务
                        if self._on_network_down is not None:
                            try:
                                await self._on_network_down()
                            except Exception:
                                pass
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
                unreachable_codes=self._wan_unreachable_codes,
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
            # 触发断网回调：停止所有本地加密 DNS 服务
            if self._on_network_down is not None:
                try:
                    await self._on_network_down()
                except Exception:
                    pass

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
            # 清空 v6 外网窗口防止首轮误判恢复
            # （原实现误清 v4 窗口 _ext_results 并填 False → ext_v4_alive 恒 False → _arp_network_down 无条件置 True）
            self._ext_results_v6.clear()
            for _ in range(self._ext_results_v6.maxlen):
                self._ext_results_v6.append(False)
            self._wan_dead_confirmed_at = self._last_wan_probe_time_v6
            self._ndp_network_down = True
            ext_v4_alive = len(self._ext_results) > 0 and sum(self._ext_results) > 0
            if not ext_v4_alive:
                self._arp_network_down = True
            self.resolver_manager.set_network_down(True)
            # 触发断网回调：停止所有本地加密 DNS 服务
            if self._on_network_down is not None:
                try:
                    await self._on_network_down()
                except Exception:
                    pass

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

        # 保存 IPv4 网关原始丢包率（ARP 修复触发必须用 v4 原始值——修复 M3：
        # v6 回退只影响整网断/恢复判定，不得掩盖 IPv4 层 ARP 问题）
        gw_loss_v4_raw = gw_loss

        # IPv4 网关高丢包时，回退到 IPv6 网关检测（仅用于 network_down/recovered 判定）
        if gw_loss >= 50 and self._arp_protection.gateway_ip is not None                 and self._ndp_protection.gateway_ipv6:
            ndp_len = len(self._ndp_gw_results)
            if ndp_len >= 2:
                ndp_fails = ndp_len - sum(self._ndp_gw_results)
                ndp_loss = int(ndp_fails / ndp_len * 100)
                # IPv6 正常说明网关本身可达，问题在 IPv4 层（丢包率替换仅用于"是否整网断"判断）
                if ndp_loss < 30:
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
        # v6 健康判定：窗口未满（<2 条）视为"未知"而非健康（双栈独立性——修复 L11：
        # 纯 v4 环境/启动期 v6 空窗口按 0 曾误判 recovered）
        ext_v6_healthy = ext_v6_len >= 2 and ext_v6_loss < 67

        if ext_loss == 100 and ext_v6_healthy and gw_loss < 20:
            return (gw_loss, "recovered")


        # 网关正常但外网全丢——可能是 ONT 静默丢包（不发 Dest Unreachable）
        # v6 窗口未知（<2 条）或 v6 明确差时，以 v4 强信号（外网全丢+网关正常）判 network_down；
        # v6 明确健康时不判（security_review MEDIUM：v6 未知不再推迟断网确认）
        if gw_loss < 20 and ext_loss == 100 and not ext_v6_healthy:
            return (gw_loss, "network_down")
        if gw_loss < 20 and ext_loss < 100 and gw_loss_v4_raw < 20:
            # v4 原始丢包 <20% 才判 recovered（security_review LOW：v6 回退不得让 v4 高丢包截胡 arp_issue）
            return (gw_loss, "recovered")
        elif gw_loss >= 90 and ext_loss >= 67 and ext_v6_loss >= 67:
            return (gw_loss, "network_down")
        elif gw_loss_v4_raw >= 20:
            # v4 网关丢包 ≥20% → arp_issue，独立于 v6 健康（双栈独立性——修复 L10：
            # v4 ARP 投毒在 v6 健康时原永不触发 _run_arp_defense）
            return (gw_loss_v4_raw, "arp_issue")
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
        # 与 _classify_loss 完全对齐的窗口选择（两级回退：无 v4 网关 → v6 窗口；v4 高丢包且 v6 健康 → v6 窗口）
        gw_results = self._gw_results
        ndp_gw = self._ndp_protection.gateway_ipv6
        if self._arp_protection.gateway_ip is None and ndp_gw:
            gw_results = self._ndp_gw_results
        elif ndp_gw and len(self._gw_results) >= 2:
            _v4_fails = len(self._gw_results) - sum(self._gw_results)
            _v4_loss = int(_v4_fails / len(self._gw_results) * 100)
            if _v4_loss >= 50:
                _ndp_len = len(self._ndp_gw_results)
                if _ndp_len >= 2:
                    _ndp_loss = int((_ndp_len - sum(self._ndp_gw_results)) / _ndp_len * 100)
                    if _ndp_loss < 30:
                        gw_results = self._ndp_gw_results
        gw_len = len(gw_results)
        if gw_len >= 3:
            gw_ok_count = sum(gw_results)
            if gw_ok_count >= max(3, gw_len // 2 + 1):
                return True
        return diagnosis == "recovered"

    def _has_active_arp_attacks(self, seconds: float = 5.0) -> bool:
        """检查过去 seconds 秒内 ARP 防护是否检测到攻击。"""
        return self._arp_protection.has_recent_attacks(seconds)

    def _has_active_ndp_attacks(self, seconds: float = 5.0) -> bool:
        """检查过去 seconds 秒内 NDP 防护是否检测到攻击。"""
        return self._ndp_protection.enabled and self._ndp_protection.has_recent_attacks(seconds)

    async def _ndp_announce_callback(self):
        """ARP IP 冲突反制联动：NDP 侧宣告本机 IPv6-MAC + 静态 NDP 绑定"""
        try:
            ndp = self._ndp_protection
            # running 检查：NDP 已停止时不再调用其方法（LOW 修复——原只查 enabled 不查运行时状态）
            if not ndp or not ndp.enabled or not getattr(ndp, "_ndp_running", False):
                return
            # NA 广播宣告本机 IPv6-MAC（纠正网络上被投毒的邻居表）
            await ndp.send_unsolicited_na()
            # 静态 NDP 绑定保护网关条目
            await ndp.protect_ndp_entry()
            logger.info("NDP 联动: 已宣告本机 IPv6-MAC 并刷新静态 NDP 条目")
        except Exception as e:
            logger.debug("NDP 联动宣告失败: %s", e)

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
                # ARP 防护成功 — 使用 ping + tcping 双重验证外网
                async def _dual_verify():
                    ext_ping_ok = any(
                        await asyncio.gather(*[
                            self._ping(t) for t in self._ping_targets_v4[:2]
                        ], return_exceptions=True)
                    ) if self._ping_targets_v4 else False
                    ext_tcp_ok = await self._tcping_check_v4()
                    return ext_ping_ok or ext_tcp_ok

                gw_reachable = abort_check() or await self._arp_protection._ping_gateway_fast(gw_ip)
                if gw_reachable:
                    logger.info("ARP 防护: 后台修复完成，网关已恢复")
                    # 双重验证外网
                    ext_verified = await _dual_verify()
                    if ext_verified:
                        logger.info("ARP 防护: 外网验证通过 (ping+tcping)")
                        if self.resolver_manager._network_down:
                            self._run_recover.set()
                        else:
                            self._arp_network_down = False
                            self.resolver_manager.set_network_down(False)
                    else:
                        # 网关通但外网不通 → 可能是更上层的问题
                        logger.warning("ARP 防护: 网关已恢复但外网不可达 (ping+tcping均失败)")
                        self._arp_network_down = True
                        self.resolver_manager.set_network_down(True)
                else:
                    # GARP 修复后 ping 网关超时：可能是刚广播完的临时波动，
                    # 用 tcping 验证外网作为二次确认
                    ext_verified = await _dual_verify()
                    if ext_verified:
                        logger.info("ARP 防护: 修复完成但 ping 网关超时，tcping 外网可达 (临时波动)")
                        self._arp_network_down = False
                        self.resolver_manager.set_network_down(False)
                    else:
                        logger.warning("ARP 防护: 修复完成且 ping 网关超时，tcping 外网也不可达")
                        self._arp_network_down = True
                        self.resolver_manager.set_network_down(True)
            else:
                # ARP 防护后网关仍不通 → 使用 ping + tcping 双重验证外网
                ext_ping_ok = any(
                    await asyncio.gather(*[
                        self._ping(t) for t in self._ping_targets_v4[:2]
                    ], return_exceptions=True)
                ) if self._ping_targets_v4 else False
                ext_tcp_ok = await self._tcping_check_v4()
                ext_ok = ext_ping_ok or ext_tcp_ok
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
                # NDP 防护成功 — ping + tcping 双重验证外网
                async def _dual_verify_v6():
                    ext_ping_ok = any(
                        await asyncio.gather(*[
                            self._ping(t) for t in self._ping_targets_v6[:2]
                        ], return_exceptions=True)
                    ) if self._ping_targets_v6 else False
                    ext_tcp_ok = await self._tcping_check_v6()
                    return ext_ping_ok or ext_tcp_ok

                ndp_gw = self._ndp_protection.gateway_ipv6
                if abort_check() or (ndp_gw and await self._ndp_protection._ping_ipv6(ndp_gw)):
                    logger.info("NDP 防护: 后台修复完成，IPv6 网关已恢复")
                    ext_verified = await _dual_verify_v6()
                    if ext_verified:
                        logger.info("NDP 防护: IPv6 外网验证通过 (ping+tcping)")
                        if self.resolver_manager._network_down and not self._arp_network_down:
                            self.resolver_manager.set_network_down(False)
                        self._ndp_network_down = False
                    else:
                        logger.warning("NDP 防护: IPv6 网关已恢复但 IPv6 外网不可达")
                        self._ndp_network_down = True
                        self.resolver_manager.set_network_down(True)
                else:
                    ext_verified = await _dual_verify_v6()
                    if ext_verified:
                        logger.info("NDP 防护: 修复完成但 ping IPv6 网关超时，tcping 外网可达 (临时波动)")
                        self._ndp_network_down = False
                        if self.resolver_manager._network_down and not self._arp_network_down:
                            self.resolver_manager.set_network_down(False)
                    else:
                        logger.warning("NDP 防护: 修复完成且 ping IPv6 网关超时，tcping 外网也不可达")
                        self._ndp_network_down = True
                        self.resolver_manager.set_network_down(True)
            else:
                # NDP 修复失败 → ping + tcping 双重验证外网
                ext_ping_ok = any(
                    await asyncio.gather(*[
                        self._ping(t) for t in self._ping_targets_v6[:2]
                    ], return_exceptions=True)
                ) if self._ping_targets_v6 else False
                ext_tcp_ok = await self._tcping_check_v6()
                ext_ok = ext_ping_ok or ext_tcp_ok
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
            await asyncio.wait_for(proc.wait(), timeout=self._ping_timeout + 1)
            if proc.returncode == 0:
                return True
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass

        # ICMP 失败时尝试 TCP 连接兜底（端口 443/80）
        # Windows 上 scapy 的 L2pcapListenSocket 可能会拦截 ping.exe 的 ICMP Echo Reply，
        # 导致 ping.exe 超时返回非零退出码。TCP 兜底不受 scapy 原始套接字影响。
        if await self._tcping(target, port=443):
            return True
        if not is_ipv6:
            if await self._tcping(target, port=80):
                return True
        return False

    async def _tcping(self, target: str, port: int = 443, timeout_sec: float = 3.0) -> bool:
        """
        TCP 连接测试（tcping）：尝试与目标 IP:端口建立 TCP 连接。
        用于验证外网是否正常通信，不受 ICMP 被拦截的影响。

        Args:
            target: 目标 IP（IPv4 或 IPv6）
            port: TCP 端口，默认 443
            timeout_sec: 连接超时秒数

        Returns:
            True 表示 TCP 连接成功（外网可达）
        """
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout_sec,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError, ConnectionError, ValueError):
            return False

    async def _tcping_check_v4(self) -> bool:
        """TCP 连接测试 IPv4 外网目标"""
        if not self._ping_targets_v4:
            return False
        for target in self._ping_targets_v4[:3]:  # 最多测试3个
            if await self._tcping(target, port=443):
                return True
            if await self._tcping(target, port=80):
                return True
        return False

    async def _tcping_check_v6(self) -> bool:
        """TCP 连接测试 IPv6 外网目标"""
        if not self._ping_targets_v6:
            return False
        for target in self._ping_targets_v6[:3]:
            if await self._tcping(target, port=443):
                return True
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

    async def _check_connectivity(self) -> bool:
        """
        [DEPRECATED - 无调用者] 综合检测网络连通性
        检测方式（任一成功即视为连通）：
        1. ICMP ping 检测（IPv4 + IPv6 双栈）
        2. TCP 连接测试（tcping，IPv4 + IPv6）
        3. DNS 探测（向公共 DNS 发送 A/AAAA 查询）
        """
        results = await asyncio.gather(
            self._ping_check_v4(),
            self._ping_check_v6(),
            self._tcping_check_v4(),
            self._tcping_check_v6(),
            self._dns_probe_check(),
            return_exceptions=True,
        )

        successes = sum(1 for r in results if r is True)
        if successes > 0:
            logger.debug("网络连通性检测: %d/5 成功 (ping4=%s, ping6=%s, tcp4=%s, tcp6=%s, dns=%s)",
                         successes, results[0], results[1], results[2], results[3], results[4])
            return True
        else:
            logger.debug("网络连通性检测: 全部失败")
            return False

    # ======================== 自动恢复 ========================

    async def _recover(self):
        """
        [DEPRECATED - 无调用者，实际恢复流程由 _recover_worker_loop 承担] 网络恢复后的自动恢复操作：
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
                # 触发网络恢复回调：重启本地加密 DNS 服务
                if self._on_network_up is not None:
                    try:
                        await self._on_network_up()
                    except Exception:
                        pass

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
                # 修复 M5：清除恢复期间累积的 _run_recover 触发，
                # 否则回到 wait() 时事件仍置位会立即重放一轮完整恢复
                self._run_recover.clear()

    # ======================== Resolver 全部失败回调 ========================

    async def on_all_upstreams_failed(self, consecutive_count: int, elapsed_seconds: float):
        """
        ResolverManager 回调：所有上游 DNS 服务器连续全部失败时调用。
        执行深度检测尝试定位问题根源。

        Args:
            consecutive_count: 连续全部失败的轮数
            elapsed_seconds: 从首次全部失败到现在的持续时间
        """
        if not self._running:
            return

        # 日志：持续全部失败，但 NetworkMonitor 尚未判定断网
        if consecutive_count == 1:
            logger.warning("DNS 上游全部失败 (第1轮) — 但网络连通性检测正常，"
                           "启动深度诊断: ARP/NDP 检查 + plain DNS 探活")
        elif consecutive_count <= 3:
            logger.warning("DNS 上游持续全部失败 (第%d轮, %.0fs) — "
                           "深度诊断中...", consecutive_count, elapsed_seconds)
        else:
            # 超过3轮，降级为 DEBUG 避免日志洪流
            logger.debug("DNS 上游持续全部失败 (第%d轮, %.0fs) — "
                         "深度诊断持续中", consecutive_count, elapsed_seconds)

        # 执行深度诊断
        try:
            await self._force_arp_ndp_check(consecutive_count)
        except Exception as e:
            logger.debug("深度诊断 ARP/NDP 检查异常: %s", e)

        try:
            plain_dns_ok = await self._probe_plain_dns_canary()
        except Exception as e:
            logger.debug("深度诊断 plain DNS 探活异常: %s", e)
            plain_dns_ok = False

        # 根据诊断结果决策
        if plain_dns_ok:
            if consecutive_count <= 3:
                logger.warning("⚠️ 深度诊断: plain DNS 探活成功，但加密 DNS (DoH/DoT/DoQ) 全部失败 — "
                               "可能原因: ① 光猫/路由器对加密 DNS 端口限速或劫持  "
                               "② ISP 临时阻断非标准 DNS 流量  "
                               "③ 上游 DNS 服务器集体故障")
        else:
            if consecutive_count >= 3:
                # plain DNS 也失败，且已持续多轮 → 确认为网络中断
                if not self._arp_network_down and not self._ndp_network_down:
                    logger.warning("⚠️ 深度诊断: plain DNS 探活也失败 — "
                                   "确认网络中断，自动抑制 DNS 查询")
                    # 清空滑动窗口强制进入 network_down 状态
                    self._ext_results.clear()
                    for _ in range(self._ext_results.maxlen):
                        self._ext_results.append(False)
                    self._ext_results_v6.clear()
                    for _ in range(self._ext_results_v6.maxlen):
                        self._ext_results_v6.append(False)
                    self._wan_dead_confirmed_at = asyncio.get_event_loop().time()
                    self._arp_network_down = True
                    self._ndp_network_down = True
                    self.resolver_manager.set_network_down(True, detail="DNS 全失败 + plain DNS 探活也失败")

    async def _force_arp_ndp_check(self, consecutive_count: int = 1):
        """
        强制 ARP/NDP 深度检测与完整反制（不依赖 ping）：
        1. 直接检查本机 ARP/NDP 表是否被投毒
        2. 发现投毒 → 直接触发 GARP/NA 反制（定向随机 MAC 毒化 + 广播爆发 + 静态绑定）
        3. 无投毒时也对比基线 MAC 做预防性检查
        4. 根据 DNS 连续失败轮数映射攻击频率，触发自适应强度

        Args:
            consecutive_count: DNS 连续全部失败轮数，用于映射攻击频率
        """
        # 将 consecutive_count 映射为等效 attack_rate（次/60s），
        # 供 _get_intensity 选择反制强度等级
        if consecutive_count >= 10:
            attack_rate = 250      # MAX 级
        elif consecutive_count >= 5:
            attack_rate = 80       # L2 级
        elif consecutive_count >= 3:
            attack_rate = 40       # L1 级
        else:
            attack_rate = 10       # 默认级

        # === IPv4 ARP 检查（不依赖 ping）===
        # 异常隔离：ARP 检查失败不得阻断 IPv6 NDP 深度检查（协程独立性修复）
        try:
            if self._arp_protection.enabled:
                gw_ip = self._arp_protection.gateway_ip
                if gw_ip:
                    # 1. 直接检查本机 ARP 表是否有投毒条目
                    poisoned = await self._arp_protection._check_arp_poisoning()
                    if poisoned:
                        for gw_ip_p, expected_mac, actual_mac in poisoned:
                            logger.warning("深度诊断 [反制]: 检测到 ARP 投毒！"
                                           "网关 %s 期望 MAC=%s, 当前 MAC=%s — 触发完整反制",
                                           gw_ip_p, expected_mac, actual_mac)
                            burst_size, directed_count, inter, _ = ARPProtection._get_intensity(attack_rate)
                            await self._arp_protection._garp_counterstrike(
                                # attacker_ip 传入网关 IP（投毒者冒充网关），用于 GARP 广播宣告真实网关绑定
                                attacker_ip=gw_ip_p,
                                attacker_mac=actual_mac,
                                burst_size=burst_size,
                                directed_count=directed_count,
                                inter=inter,
                            )
                    else:
                        # 2. 无投毒时，对比基线 MAC 做预防性检查
                        baseline_mac = self._arp_protection._baseline_mac
                        if baseline_mac:
                            try:
                                if sys.platform == "win32":
                                    current_mac = await ARPProtection._arp_get_mac_windows(gw_ip)
                                else:
                                    current_mac = await ARPProtection._arp_get_mac_linux(gw_ip)
                                # 审计（关联）：MAC 格式归一化后比较——current_mac 为横线格式（AA-BB-CC-...）、
                                # baseline_mac 为冒号格式（AA:BB:CC:...），Windows 上直接 upper() 比较恒不等
                                # → 无条件触发反制（向真实网关发送毒化包）
                                if current_mac and ARPProtection._mac_normalize(current_mac) != \
                                        ARPProtection._mac_normalize(baseline_mac):
                                    logger.warning("深度诊断 [反制]: 网关 %s MAC 变更 "
                                                   "(基线=%s, 当前=%s) — 可能 ARP 投毒，触发反制",
                                                   gw_ip, baseline_mac, current_mac)
                                    burst_size, directed_count, inter, _ = ARPProtection._get_intensity(attack_rate)
                                    await self._arp_protection._garp_counterstrike(
                                        attacker_ip=gw_ip,
                                        attacker_mac=current_mac,
                                        burst_size=burst_size,
                                        directed_count=directed_count,
                                        inter=inter,
                                    )
                            except Exception as e:
                                logger.debug("深度诊断 ARP MAC 检查异常: %s", e)
        except Exception as e:
            logger.debug("深度诊断 ARP 检查异常: %s", e)

        # === IPv6 NDP 检查（不依赖 ping）===
        if self._ndp_protection.enabled:
            ndp_gw = self._ndp_protection.gateway_ipv6
            if ndp_gw:
                try:
                    ndp_poisoned = await self._ndp_protection.check_ndp_poisoning()
                    if ndp_poisoned:
                        for entry in ndp_poisoned:
                            # entry = (iface_name, ip, expected_mac, actual_mac)
                            iface_name, ndp_ip, exp_mac, act_mac = entry
                            logger.warning("深度诊断 [反制]: 检测到 NDP 投毒！"
                                           "IPv6 网关 %s 期望 MAC=%s, 当前 MAC=%s — 触发 NDP 反制",
                                           ndp_ip, exp_mac, act_mac)
                            await self._ndp_protection._ndp_counterstrike(
                                attacker_mac=act_mac,
                                attacker_ip=ndp_ip,
                            )
                except Exception as e:
                    logger.debug("深度诊断 NDP 检查异常: %s", e)

    async def _probe_plain_dns_canary(self) -> bool:
        """
        使用 Plain DNS（普通 DNS）发送探活查询。
        用于区分 '网络不通' 和 '加密 DNS 被拦截' 两种场景。

        Returns:
            True 表示 plain DNS 查询成功（网络层正常，问题在加密协议层）
            False 表示 plain DNS 也失败（网络层中断）
        """
        # 获取 bootstrap DNS 地址
        bootstrap_addrs = self.resolver_manager.get_bootstrap_addresses()
        if not bootstrap_addrs:
            bootstrap_addrs = self._ping_targets_v4 + self._ping_targets_v6
        if not bootstrap_addrs:
            return False

        # 取一个探测域名
        probe_domains = self._dns_probe_domains
        if not probe_domains:
            probe_domains = ["www.baidu.com", "www.qq.com"]

        from resolvers.plain import PlainDNSResolver

        for domain in probe_domains:
            if not self._is_valid_domain(domain):
                continue
            for addr in bootstrap_addrs:
                try:
                    import dns.message
                    import dns.rdatatype
                    q = dns.message.make_query(domain, dns.rdatatype.A)
                    qbytes = q.to_wire()

                    is_ipv6 = ":" in addr
                    family = "v6" if is_ipv6 else "v4"

                    # 复用或创建解析器
                    resolver = self._dns_probe_resolvers.get(addr)
                    if resolver is None:
                        resolver = PlainDNSResolver(
                            addr, timeout=self._ping_timeout,
                        )
                        self._dns_probe_resolvers[addr] = resolver

                    result = await asyncio.wait_for(
                        resolver.resolve(qbytes, prefer_family=family),
                        timeout=self._ping_timeout,
                    )
                    if result is not None:
                        logger.debug("深度诊断 plain DNS 探活: %s → %s ✅", addr, domain)
                        return True
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.debug("深度诊断 plain DNS 探活异常 (%s): %s", addr, e)
                    continue
        logger.debug("深度诊断 plain DNS 探活: 全部失败 ❌")
        return False

"""
NDP 防护模块 — IPv6 邻居发现协议 (NDP) 欺骗防护（多接口并行版）
=============================================================
IPv6 没有 ARP，替代者是 NDP（Neighbor Discovery Protocol, RFC 4861）。

本模块对标 arp_protection.py 的架构：
  - 多以太网口检测（从 ipconfig / route 枚举所有接口）
  - 多 IPv6 网关（所有 ::/0 默认路由分配到对应接口）
  - 本机多 IPv6 地址（global + link-local 每接口独立）
  - 所有网关独立投毒检测 + 独立修复
"""

import os
import re
import sys
import time
import struct
import asyncio
import logging
import random
from typing import Optional, List, Tuple, Dict, Callable, Any
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("dns-proxy.ndp")

# ======================== scapy 可选引入 ========================

_HAS_SCAPY = False
try:
    from scapy.all import (
        Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
        ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
        ICMPv6ND_RA, ICMPv6NDOptPrefixInformation,
        ICMPv6ND_RS,
        ICMPv6NDOptRedirectedHdr, ICMPv6Error,
        sniff, sendp,
        conf as scapy_conf,
    )
    _HAS_SCAPY = True
except ImportError:
    pass


@dataclass
class InterfaceInfo:
    """单个网卡的 IPv6 信息"""
    name: str = ""                    # 网卡名称（如"以太网"）
    mac: str = ""                     # 本机 MAC（如 00:11:22:33:44:55）
    ipv6_global: str = ""             # 全局单播 IPv6 地址
    ipv6_ll: str = ""                 # 链路本地地址 (fe80::)
    gateways: List[Tuple[str, str]] = field(default_factory=list)  # [(网关IPv6, 网关MAC)]


class NDPProtection:
    """
    NDP 防护：多接口 + 多网关 + 多地址
    
    架构对标 arp_protection.py:
      - interfaces: List[InterfaceInfo] 管理所有网卡
      - detect_gateway(): 自动探测全部接口、网关、地址
      - check_ndp_poisoning(): 遍历所有网关检测投毒
      - send_unsolicited_na(): 在所有接口上发送 NA
      - protect_ndp_entry(): 为所有网关设静态 NDP
      - refresh_router_ndp(): 全链路修复入口
    """

    def __init__(self, config_ndp: dict = None, ping_interval: float = 0.80,
                 ping_targets_v6: list = None):
        cfg = config_ndp or {}
        self._enabled = cfg.get("enabled", True)
        self._ping_interval = ping_interval
        self._ping_targets_v6 = ping_targets_v6 or ["2400:3200::1", "2400:da00::6666"]
        self._ra_sniff_timeout = cfg.get("ra_sniff_timeout", 5.0)
        self._max_ra_routers = cfg.get("max_ra_routers", 1)
        self._check_interval = cfg.get("check_interval", 30.0)

        # 多接口数据模型
        self.interfaces: List[InterfaceInfo] = []  # 所有检测到的 IPv6 网卡

        # 手动配置网关
        self._manual_gateways: List[Tuple[str, str]] = []  # [(ipv6, mac), ...]
        self._baseline_gateway_mac: str = ""
        gw_field = cfg.get("gateway_ipv6", "") or ""
        if isinstance(gw_field, str) and gw_field:
            pairs = self._parse_gateway_ipv6_field(gw_field)
            if pairs:
                self._manual_gateways = pairs
                for ip, mac in pairs:
                    if not ip and mac:
                        self._baseline_gateway_mac = mac

        self._detected = False
        self._last_refresh_time = 0.0
        self._scapy_available = _HAS_SCAPY

        # 周期性检测任务
        self._running = False
        self._check_task: Optional[asyncio.Task] = None

        # 修复去重
        self._last_fix_time = 0.0
        self._fix_cooldown = 10.0
        self._threat_events: List[Dict] = []

        # ========== 常驻 worker 框架（对标 ARP 5 个 worker） ==========
        self._ndp_running = False
        self._ndp_workers: list = []

        # 恢复监控 worker
        self._recovery_trigger = asyncio.Event()
        self._recovery_detected = asyncio.Event()

        # 检测 + 修复 worker
        self._run_detect = asyncio.Event()     # 信号：触发综合检测
        self._run_na_burst = asyncio.Event()   # 信号：NA 爆发
        self._na_burst_done = asyncio.Event()  # NA 爆发完成通知
        self._detect_done_event = asyncio.Event()  # 检测完成通知
        self._na_burst_ready = False

        # 嗅探投毒检测
        self._poison_detected = asyncio.Event()

        # NDP 基线 MAC 学习
        self._baseline_learned: bool = False
        self._baseline_mac_per_gw: Dict[str, str] = {}   # {网关IP: 已确认的基线 MAC}
        self._baseline_proposed: Dict[str, str] = {}     # {网关IP: 首次候选 MAC}
        self._baseline_proposed_time: Dict[str, float] = {}  # 首次候选时间

    # ======================== 属性 ========================

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def gateway_pairs(self) -> List[Tuple[str, str]]:
        """所有接口的所有网关 (ipv6, mac)"""
        pairs = list(self._manual_gateways)
        for iface in self.interfaces:
            for gw_ip, gw_mac in iface.gateways:
                if not any(ip == gw_ip for ip, _ in pairs):
                    pairs.append((gw_ip, gw_mac))
        return pairs

    @property
    def gateway_ipv6(self) -> Optional[str]:
        """获取第一个可用网关 IPv6（兼容旧代码）"""
        if self._manual_gateways and self._manual_gateways[0][0]:
            return self._manual_gateways[0][0]
        for iface in self.interfaces:
            for gw_ip, _ in iface.gateways:
                if gw_ip:
                    return gw_ip
        return None

    @property
    def gateway_mac(self) -> Optional[str]:
        """获取第一个可用网关 MAC（兼容旧代码）"""
        for ip, mac in self.gateway_pairs:
            if ip == self.gateway_ipv6 and mac:
                return mac
        return None

    @property
    def local_mac(self) -> Optional[str]:
        """获取第一个有 IPv6 的接口 MAC（兼容旧代码）"""
        for iface in self.interfaces:
            if iface.ipv6_global or iface.ipv6_ll:
                return iface.mac
        return None

    @property
    def local_ipv6(self) -> Optional[str]:
        """获取第一个全局 IPv6 地址（兼容旧代码）"""
        for iface in self.interfaces:
            if iface.ipv6_global:
                return iface.ipv6_global
        return None

    @property
    def interface_name(self) -> Optional[str]:
        """获取第一个接口名（兼容旧代码）"""
        for iface in self.interfaces:
            if iface.ipv6_global or iface.ipv6_ll:
                return iface.name
        return None

    @property
    def all_local_ipv6(self) -> List[str]:
        """所有本机 IPv6 地址"""
        addrs = []
        for iface in self.interfaces:
            if iface.ipv6_global:
                addrs.append(iface.ipv6_global)
            if iface.ipv6_ll:
                addrs.append(iface.ipv6_ll)
        return addrs

    # ======================== 网关字段解析 ========================

    @staticmethod
    def _parse_gateway_ipv6_field(gw_field: str) -> list:
        _MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
        _IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')
        parts = [p.strip() for p in gw_field.split(",")]
        pairs = []
        i = 0
        while i < len(parts):
            val = parts[i]
            if not val:
                i += 1
                continue
            is_mac = bool(_MAC_RE.match(val))
            is_ipv6 = not is_mac and bool(_IPV6_RE.match(val)) and ("::" in val or val.count(":") > 1)
            if is_ipv6:
                ip = val
                mac = ""
                if i + 1 < len(parts):
                    nv = parts[i + 1]
                    if not nv or _MAC_RE.match(nv):
                        mac = nv
                        i += 2
                    else:
                        i += 1
                else:
                    i += 1
                pairs.append((ip, mac))
            elif is_mac:
                pairs.append(("", val))
                i += 1
            else:
                i += 1
        return pairs

    # ======================== 生命周期 ========================

    async def start(self):
        if not self._enabled:
            return
        logger.info("NDP 防护: 启动...")
        await self.detect_gateway()
        if not self.interfaces and not self._manual_gateways:
            logger.info("NDP 防护: 未检测到 IPv6 网关，自动关闭")
            self._enabled = False
            return
        self._running = True
        self._check_task = asyncio.create_task(self._periodic_check_loop())
        # 启动常驻 worker（对标 ARP 防护的 4 个 worker + 嗅探）
        await self._start_workers()
        logger.info("NDP 防护: 已启动 (接口=%d, 网关=%d, scapy=%s, workers=%d)",
                    len(self.interfaces), len(self.gateway_pairs), self._scapy_available,
                    len(self._ndp_workers))

    async def stop(self):
        self._running = False
        self._ndp_running = False
        # 唤醒所有 worker 使其退出
        self._recovery_trigger.set()
        self._run_detect.set()
        self._run_na_burst.set()
        self._na_burst_done.set()
        self._detect_done_event.set()
        self._poison_detected.set()
        for w in self._ndp_workers:
            w.cancel()
            try:
                await w
            except (asyncio.CancelledError, Exception):
                pass
        self._ndp_workers = []
        if self._check_task and not self._check_task.done():
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
        logger.debug("NDP 防护: 已停止")

    async def _periodic_check_loop(self):
        while self._running:
            try:
                await asyncio.sleep(self._check_interval)
                if not self._running:
                    break
                results = await self.run_all_checks()
                threat_count = sum(1 for v in results.values() if v)
                if threat_count:
                    logger.info("NDP 防护: 周期性检测发现 %d 类异常", threat_count)
                    now = time.monotonic()
                    if now - self._last_fix_time > self._fix_cooldown:
                        asyncio.create_task(self.refresh_router_ndp())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("NDP 防护: 周期检测异常: %s", e)

    # ======================== 常驻 Worker 框架 ========================

    async def _start_workers(self):
        """启动所有常驻 worker task（对标 ARP 防护的 5 worker 架构）"""
        if self._ndp_workers:
            return
        self._ndp_running = True
        self._ndp_workers = [
            asyncio.create_task(self._recovery_worker_loop()),
            asyncio.create_task(self._na_burst_worker_loop()),
            asyncio.create_task(self._detect_worker_loop()),
            asyncio.create_task(self._ndp_sniffer_worker_loop()),
        ]
        logger.debug("NDP 防护: 4 个常驻 worker 已启动")

    async def _recovery_worker_loop(self):
        """Worker 1: 永久等待 recovery_trigger → ping 网关 → 通则 recovery_detected.set()"""
        while self._ndp_running:
            await self._recovery_trigger.wait()
            if not self._ndp_running:
                return
            self._recovery_trigger.clear()
            self._recovery_detected.clear()
            # 尝试 ping 每个网关
            for gw_ip, _ in self.gateway_pairs[:3]:
                if not gw_ip:
                    continue
                for _ in range(5):
                    if not self._ndp_running:
                        return
                    if await self._ping_ipv6(gw_ip):
                        self._recovery_detected.set()
                        break
                    await asyncio.sleep(self._ping_interval)
                if self._recovery_detected.is_set():
                    break
            if not self._recovery_detected.is_set():
                # 一轮全失败，等下次触发
                pass

    async def _na_burst_worker_loop(self):
        """Worker 2: 等待 run_na_burst → NA 爆发 → 标记完成"""
        while self._ndp_running:
            await self._run_na_burst.wait()
            if not self._ndp_running:
                return
            self._run_na_burst.clear()
            self._na_burst_done.clear()
            self._na_burst_ready = False
            try:
                await self.send_unsolicited_na()
                self._na_burst_ready = True
            except Exception as e:
                logger.debug("NDP 防护: NA 爆发异常: %s", e)
            self._na_burst_done.set()

    async def _detect_worker_loop(self):
        """Worker 3: 等待 run_detect → 执行综合检测 → 标记完成"""
        while self._ndp_running:
            await self._run_detect.wait()
            if not self._ndp_running:
                return
            self._run_detect.clear()
            self._detect_done_event.clear()
            self._detect_done = False
            try:
                await self.run_all_checks()
                self._detect_done = True
            except Exception as e:
                logger.debug("NDP 防护: 检测异常: %s", e)
            self._detect_done_event.set()

    async def _ndp_sniffer_worker_loop(self):
        """
        Worker 4: 常驻 NDP 嗅探（对标 ARP 的 _arp_sniffer_worker_loop）。
        
        持续监听 NA / NS / RA 报文，被动学习每个网关的基线 MAC，
        实时检测投毒。有报文时处理，无报文时冻结在 sniff() 内（零 CPU）。
        
        自动学习基线 MAC:
          - 前 3 次看到同一网关 IP 发来的报文 → 如果 MAC 一致 → 确认为基线
          - 之后该 IP 如果出现不同 MAC → 标记投毒
        """
        if not self._scapy_available:
            await asyncio.Event().wait()  # 永不醒来，相当于冻结
            return

        loop = asyncio.get_event_loop()

        def _ndp_sniff():
            """scapy sniff 持续捕获 NDP 报文，store=False 不保存，prn 回调处理"""
            sniff(
                count=0, timeout=None,
                lfilter=lambda p: (
                    p.haslayer(Ether) and p.haslayer(IPv6) and (
                        p.haslayer(ICMPv6ND_NA) or
                        p.haslayer(ICMPv6ND_NS) or
                        p.haslayer(ICMPv6ND_RA)
                    )
                ),
                prn=self._on_ndp_packet,
                store=False,
                quiet=True,
            )

        try:
            # sniff 是阻塞的，在 executor 中运行
            await loop.run_in_executor(None, _ndp_sniff)
        except Exception as e:
            logger.debug("NDP 防护: 嗅探 worker 退出 (%s)", e)

    def _on_ndp_packet(self, pkt):
        """
        sniff 回调 — 处理每个 NDP 报文（在 executor 线程中运行，非 async）。
        
        功能（对标 ARP 的 _handle_arp_packet）:
          1. 自动学习网关基线 MAC（3 次一致确认）
          2. 检测投毒（基线 MAC 与当前报文的源 MAC 不一致）
          3. 检测 IP 冲突（本机 IPv6 地址出现在他人报文中）
        """
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return
        src_mac = pkt[Ether].src.upper()
        src_ip = str(pkt[IPv6].src)

        # 收集所有已知的网关 IP 和本机 IP
        all_gw_ips = {ip for ip, _ in self.gateway_pairs if ip}
        all_local_ips = set(self.all_local_ipv6)

        # --- 自动学习网关基线 MAC（仅从 RA 和 NS 报文学习） ---
        if pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_NS):
            for gw_ip in all_gw_ips:
                if src_ip == gw_ip or self._ipv6_matches(src_ip, gw_ip):
                    # 候选基线
                    if gw_ip not in self._baseline_proposed:
                        # 首次看到此网关
                        self._baseline_proposed[gw_ip] = src_mac
                        self._baseline_proposed_time[gw_ip] = time.time()
                    elif self._baseline_proposed[gw_ip] == src_mac:
                        # 与首次候选一致 → 检查是否达到确认次数
                        elapsed = time.time() - self._baseline_proposed_time.get(gw_ip, 0)
                        # 超过 3 秒且 MAC 一致 → 确认基线
                        if elapsed > 3.0 and not self._baseline_learned:
                            self._baseline_mac_per_gw[gw_ip] = src_mac
                            self._baseline_learned = True
                            logger.info("NDP 防护: 基线学习完成 [%s] -> MAC=%s", gw_ip, src_mac)
                    else:
                        # MAC 变了 → 重置候选（路由器可能真换了）
                        self._baseline_proposed[gw_ip] = src_mac
                        self._baseline_proposed_time[gw_ip] = time.time()
                    break

        # --- 投毒检测：网关 IP 的源 MAC 与基线不一致 ---
        if pkt.haslayer(ICMPv6ND_NA):
            na = pkt[ICMPv6ND_NA]
            na_target = str(na.target)
            for gw_ip in all_gw_ips:
                baseline = self._baseline_mac_per_gw.get(gw_ip)
                if baseline and (
                    src_ip == gw_ip or na_target == gw_ip
                ) and src_mac != baseline:
                    # 网关的 NA 携带不同的 MAC → 投毒!
                    self._threat_events.append({
                        "type": "na_poison",
                        "time": time.time(),
                        "gateway": gw_ip,
                        "expected_mac": baseline,
                        "actual_mac": src_mac,
                    })
                    logger.warning("NDP 嗅探 [T1]: 检测到 NA 投毒! "
                                   "网关 %s -> 预期 %s != 实际 %s",
                                   gw_ip, baseline, src_mac)
                    # 通过 Event 通知主循环
                    if not self._poison_detected.is_set():
                        self._poison_detected.set()
                        # 创建一个异步任务触发修复（不在 executor 中 await）
                        asyncio.get_event_loop().call_soon_threadsafe(
                            lambda: asyncio.create_task(self._on_poison_detected())
                        )
                    break

        # --- IP 冲突检测：本机 IP 被他人宣告 ---
        for local_ip in all_local_ips:
            if local_ip and (src_ip == local_ip or (
                pkt.haslayer(ICMPv6ND_NA) and str(pkt[ICMPv6ND_NA].target) == local_ip
            )) and src_mac != self.local_mac:
                self._threat_events.append({
                    "type": "ip_conflict",
                    "time": time.time(),
                    "ip": local_ip,
                    "attacker_mac": src_mac,
                })
                logger.warning("NDP 嗅探: IP 冲突! %s 被 %s 宣告", local_ip, src_mac)
                self._poison_detected.set()
                asyncio.get_event_loop().call_soon_threadsafe(
                    lambda: asyncio.create_task(self._on_poison_detected())
                )
                break

        # --- RA 欺骗检测：非网关源发 RA ---
        if pkt.haslayer(ICMPv6ND_RA):
            is_known_gw = any(src_ip == gw for gw in all_gw_ips)
            is_known_mac = any(src_mac == mac.upper() for _, mac in self.gateway_pairs if mac)
            if not is_known_gw and not is_known_mac:
                self._threat_events.append({
                    "type": "rogue_ra",
                    "time": time.time(),
                    "src_mac": src_mac,
                    "src_ip": src_ip,
                })
                logger.warning("NDP 嗅探 [T3]: 未知 RA! %s (%s)", src_ip, src_mac)

    @staticmethod
    def _ipv6_matches(ip1: str, ip2: str) -> bool:
        """比较两个 IPv6 地址是否匹配（考虑链路本地地址的 %zone 后缀）"""
        a = ip1.split("%")[0].strip().lower()
        b = ip2.split("%")[0].strip().lower()
        return a == b

    async def _on_poison_detected(self):
        """嗅探检测到投毒后的处理入口"""
        if not self._enabled:
            return
        now = time.monotonic()
        if now - self._last_fix_time > self._fix_cooldown:
            logger.info("NDP 防护: 嗅探检测到投毒，触发修复")
            await self.refresh_router_ndp()

    # ======================== 多接口多网关探测 ========================

    async def detect_gateway(self):
        """
        自动探测所有 IPv6 接口、网关、地址。
        等同 arp_protection._resolve_interface_windows() 的 IPv6 版。
        
        发现结果存入 self.interfaces: List[InterfaceInfo]：
          - 每个接口的 MAC、IPv6 地址、网关列表
        """
        if self._detected:
            return

        # 手动配置优先
        if self._manual_gateways:
            logger.info("NDP 防护: 使用手动配置 %d 个 IPv6 网关", len(self._manual_gateways))
            # 尝试补全 MAC
            for i, (ip, mac) in enumerate(self._manual_gateways):
                if ip and not mac:
                    resolved = await self._resolve_mac_single(ip)
                    if resolved:
                        self._manual_gateways[i] = (ip, resolved)
            self._detected = True
            return

        if sys.platform == "win32":
            await self._detect_all_windows()
        else:
            await self._detect_all_linux()

        if self.interfaces:
            self._detected = True
            total_gws = sum(len(iface.gateways) for iface in self.interfaces)
            logger.info("NDP 防护: 探测到 %d 个 IPv6 接口, %d 个网关",
                        len(self.interfaces), total_gws)
            for iface in self.interfaces:
                gw_str = ", ".join(f"{g[0]}({g[1] or '?'})" for g in iface.gateways)
                logger.info("  接口 %s [%s] IPv6=%s LL=%s 网关=[%s]",
                            iface.name, iface.mac, iface.ipv6_global or "-",
                            iface.ipv6_ll or "-", gw_str)
        else:
            logger.debug("NDP 防护: 未检测到 IPv6 网络")

    async def _detect_all_windows(self):
        """
        Windows: ipconfig + netsh 枚举全接口。
        等同 arp_protection._resolve_interface_windows() 的 IPv6 版。
        """
        # 1. netsh interface ipv6 show routes → 所有默认路由
        #    路由格式: ::/0   fe80::1   256   11
        default_routes = []  # [(gateway_ipv6, interface_index), ...]
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv6", "show", "route",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                s = line.strip()
                if s.startswith("::/0"):
                    parts = s.replace("::/0", "").strip().split()
                    if len(parts) >= 2:
                        gw = parts[0].strip()
                        try:
                            iface_idx = int(parts[1].strip())
                        except ValueError:
                            iface_idx = 0
                        if ":" in gw and not gw.startswith("ff"):
                            default_routes.append((gw, iface_idx))
        except Exception as e:
            logger.debug("NDP 防护: netsh route 失败: %s", e)

        # 2. ipconfig → 按分段解析每个接口
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("NDP 防护: ipconfig 失败: %s", e)
            return

        raw_sections = re.split(r'\n\s*\n', text)
        for section in raw_sections:
            lines = section.strip().splitlines()
            if not lines:
                continue

            name_line = lines[0].strip()
            current_name = None
            for prefix in ("以太网适配器 ", "Ethernet adapter ",
                           "无线局域网适配器 ", "Wireless LAN adapter ",
                           "WLAN 适配器 ", "WLAN adapter ",
                           "本地连接", "Local Area Connection"):
                if name_line.startswith(prefix):
                    current_name = name_line[len(prefix):].rstrip(":")
                    break
            if not current_name:
                continue

            iface = InterfaceInfo(name=current_name)

            for line in lines:
                s = line.strip()
                if "IPv6 地址" in s or "IPv6 Address" in s:
                    parts = s.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip().split("%")[0].strip()
                        if ":" in ip:
                            if ip.startswith("fe80"):
                                if not iface.ipv6_ll:
                                    iface.ipv6_ll = ip
                            elif not iface.ipv6_global:
                                iface.ipv6_global = ip
                if "物理地址" in s or "Physical Address" in s:
                    parts = s.split(":")
                    if len(parts) >= 2:
                        mac = parts[-1].strip().replace("-", ":").upper()
                        if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                            iface.mac = mac

            # 3. 匹配此接口的默认路由
            if iface.ipv6_ll or iface.ipv6_global:
                self._assign_routes_to_interface(iface, default_routes)

            if (iface.ipv6_ll or iface.ipv6_global):
                self.interfaces.append(iface)

        # 4. 解析每个网关的 MAC（通过 Neighbor Cache）
        await self._resolve_all_gateway_macs()

    async def _detect_all_linux(self):
        """Linux: ip -6 枚举全接口"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "show",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("NDP 防护: Linux 接口检测失败: %s", e)
            return

        current_iface = None
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith(" ") and ":" in s:
                if current_iface and (current_iface.ipv6_ll or current_iface.ipv6_global):
                    self.interfaces.append(current_iface)
                name = s.split(":")[1].strip()
                current_iface = InterfaceInfo(name=name)
                continue
            if current_iface is None:
                continue
            if "inet6" in s:
                for p in s.split():
                    if ":" in p:
                        ip = p.split("/")[0]
                        if ip.startswith("fe80"):
                            current_iface.ipv6_ll = ip
                        elif ":" in ip:
                            current_iface.ipv6_global = ip if not current_iface.ipv6_global else current_iface.ipv6_global
            if "link/ether" in s:
                for p in s.split():
                    if ":" in p and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', p.upper()):
                        current_iface.mac = p.upper()

        if current_iface and (current_iface.ipv6_ll or current_iface.ipv6_global):
            self.interfaces.append(current_iface)

        # Linux 路由
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-6", "route", "show", "default",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                if "default via" in line:
                    parts = line.split()
                    gw = ""
                    iface_name = ""
                    for i, p in enumerate(parts):
                        if p == "via" and i + 1 < len(parts):
                            gw = parts[i + 1]
                        if p == "dev" and i + 1 < len(parts):
                            iface_name = parts[i + 1]
                    if gw and iface_name:
                        for iface in self.interfaces:
                            if iface.name == iface_name:
                                iface.gateways.append((gw, ""))
        except Exception as e:
            logger.debug("NDP 防护: Linux 路由失败: %s", e)

        await self._resolve_all_gateway_macs()

    def _assign_routes_to_interface(self, iface: InterfaceInfo, routes: list):
        """将默认路由分配到接口"""
        for gw, idx in routes:
            # 用接口索引匹配不太可靠，做关键词匹配
            if iface.name and str(idx) in iface.name:
                if not any(g == gw for g, _ in iface.gateways):
                    iface.gateways.append((gw, ""))

    async def _resolve_all_gateway_macs(self):
        """从 Neighbor Cache 解析所有网关的 MAC"""
        for iface in self.interfaces:
            for i, (gw_ip, _) in enumerate(iface.gateways):
                if not gw_ip:
                    continue
                mac = await self._resolve_mac_single(gw_ip)
                if mac:
                    iface.gateways[i] = (gw_ip, mac)

    async def _resolve_mac_single(self, ipv6: str) -> Optional[str]:
        """解析单个 IPv6 地址的 MAC（从 Neighbor Cache）"""
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv6", "show", "neighbors",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    if ipv6.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[1].strip().replace("-", ":").upper()
                            if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                                return mac
            except Exception:
                pass
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    if ipv6.lower() in line.lower() and "lladdr" in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == "lladdr" and i + 1 < len(parts):
                                mac = parts[i + 1].strip().upper()
                                if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                                    return mac
            except Exception:
                pass
        return None

    # ======================== 综合检测 ========================

    async def run_all_checks(self) -> dict:
        """执行全部 NDP 安全检测（并行：非嗅探组 + 嗅探组）"""
        results = {}
        if not self._enabled:
            return results

        logger.debug("NDP 防护: 开始综合检测 (%d 个接口, %d 个网关)...",
                     len(self.interfaces), len(self.gateway_pairs))

        non_sniff_tasks = {
            "t1_na": self.check_ndp_poisoning(),
            "t7_flood": self._ndp_flood_detect(),
        }
        if self._scapy_available:
            non_sniff_tasks["t9_dhcpv6"] = self.detect_dhcpv6_rogue()

        sniff_result = {}
        if self._scapy_available:
            sniff_task = asyncio.create_task(self._sniff_all())
            non_sniff_results, sniff_result = await asyncio.gather(
                self._run_dict(non_sniff_tasks), sniff_task,
                return_exceptions=True,
            )
        else:
            non_sniff_results = await self._run_dict(non_sniff_tasks)
            sniff_result = {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        if isinstance(non_sniff_results, Exception):
            non_sniff_results = {}
        if isinstance(sniff_result, Exception):
            sniff_result = {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        results.update(non_sniff_results)
        results.update(sniff_result)

        threat_count = 0
        for v in results.values():
            if v and isinstance(v, bool):
                threat_count += 1
            elif v and isinstance(v, (list, dict)):
                threat_count += len(v)
        if threat_count:
            logger.warning("NDP 防护: 综合检测发现 %d 项异常", threat_count)

        return results

    @staticmethod
    async def _run_dict(task_dict: dict) -> dict:
        keys = list(task_dict.keys())
        coros = [task_dict[k] for k in keys]
        results = await asyncio.gather(*coros, return_exceptions=True)
        return {k: r if not isinstance(r, Exception) else [] for k, r in zip(keys, results)}

    # ======================== T1: NA 欺骗（全网关检测） ========================

    async def check_ndp_poisoning(self) -> list:
        """
        遍历所有接口的所有网关，检测 NDP 投毒。
        等价于 arp_protection._check_arp_poisoning()。
        
        Returns:
            [(接口名, 网关IP, 预期MAC, 实际MAC), ...]
        """
        poisoned = []

        # 检测手动配置的网关
        for ip, expected in self._manual_gateways:
            if not ip:
                continue
            actual = await self._resolve_mac_single(ip)
            if expected and actual and actual.upper() != expected.upper():
                poisoned.append(("手动", ip, expected, actual))
            if not expected and self._baseline_gateway_mac and actual:
                if actual.upper() != self._baseline_gateway_mac.upper():
                    poisoned.append(("手动-基线", ip, self._baseline_gateway_mac, actual))

        # 检测自动发现的接口网关
        for iface in self.interfaces:
            for gw_ip, expected in iface.gateways:
                if not gw_ip or not expected:
                    continue
                actual = await self._resolve_mac_single(gw_ip)
                if actual and actual.upper() != expected.upper():
                    poisoned.append((iface.name, gw_ip, expected, actual))

        if poisoned:
            for iface_name, gw, exp, act in poisoned:
                logger.warning("NDP 防护 [T1]: %s 网关 %s MAC 变更! %s -> %s",
                               iface_name, gw, exp, act)

        return poisoned

    # ======================== T7: NDP 泛洪 ========================

    async def _ndp_flood_detect(self) -> bool:
        try:
            before = time.monotonic()
            cnt1 = await self._count_neighbors()
            await asyncio.sleep(0.5)
            cnt2 = await self._count_neighbors()
            rate = (cnt2 - cnt1) / (time.monotonic() - before)
            if rate > 50:
                logger.warning("NDP 防护 [T7]: NDP 泛洪! 邻居增长 %.0f 条/秒", rate)
                return True
        except Exception:
            pass
        return False

    async def _count_neighbors(self) -> int:
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv6", "show", "neighbors",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                return len(stdout.decode().splitlines())
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                return len(stdout.decode().splitlines())
        except Exception:
            return 0

    # ======================== sniff 分组分发 ========================

    async def _sniff_all(self) -> dict:
        """单次 sniff 捕获 NDP 报文 → 分发给 all check_xx"""
        if not self._scapy_available:
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        loop = asyncio.get_event_loop()

        def _capture():
            return sniff(
                count=200, timeout=4.0,
                lfilter=lambda p: p.haslayer(Ether) and p.haslayer(IPv6) and (
                    p.haslayer(ICMPv6ND_NA) or p.haslayer(ICMPv6ND_NS) or
                    p.haslayer(ICMPv6ND_RA) or p.haslayer(ICMPv6Error)
                ),
                quiet=True,
            )

        try:
            pkts = await loop.run_in_executor(None, _capture)
        except Exception as e:
            logger.debug("NDP 防护: sniff 失败: %s", e)
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        # 收集已知网关 MAC
        known_gw_macs = {mac.upper() for _, mac in self.gateway_pairs if mac}

        ra_sources = {}          # {mac: (ip, prefix)}
        ns_targets = defaultdict(int)
        dad_targets = defaultdict(int)
        redirect_sources = []    # [(mac, ip)]
        suspicious_ns = []       # [(target, mac)]

        for pkt in pkts:
            src_mac = pkt[Ether].src.upper()
            src_ip = str(pkt[IPv6].src) if pkt.haslayer(IPv6) else "?"

            if pkt.haslayer(ICMPv6ND_RA):
                prefix = ""
                if pkt.haslayer(ICMPv6NDOptPrefixInformation):
                    pi = pkt[ICMPv6NDOptPrefixInformation]
                    prefix = str(pi.prefix) if pi.prefix else ""
                ra_sources[src_mac] = (src_ip, prefix)

            if pkt.haslayer(ICMPv6ND_NS):
                ns = pkt[ICMPv6ND_NS]
                target = str(ns.target)
                ns_targets[target] += 1
                if src_ip == "::":
                    dad_targets[target] += 1
                if known_gw_macs and src_mac not in known_gw_macs:
                    suspicious_ns.append((target, src_mac))

            if pkt.haslayer(ICMPv6Error) and pkt.haslayer(ICMPv6NDOptRedirectedHdr):
                redirect_sources.append((src_mac, src_ip))

        results = {}
        results["t2_ns"] = suspicious_ns
        results["t3_ra"] = [
            (mac, ip, prefix) for mac, (ip, prefix) in ra_sources.items()
            if known_gw_macs and mac not in known_gw_macs
        ]
        results["t4_dad"] = [(t, c) for t, c in dad_targets.items() if c >= 3]
        results["t6_redirect"] = [
            (mac, ip) for mac, ip in redirect_sources
            if known_gw_macs and mac not in known_gw_macs
        ]

        if results["t3_ra"]:
            logger.warning("NDP 防护 [T3]: sniff 发现 %d 个未知 RA 源", len(results["t3_ra"]))
        if results["t4_dad"]:
            logger.warning("NDP 防护 [T4]: sniff 发现 DAD 攻击!")
        return results

    # ======================== T9: Rogue DHCPv6 ========================

    async def detect_dhcpv6_rogue(self) -> list:
        if not self._scapy_available:
            return []
        servers = []
        try:
            from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply
            loop = asyncio.get_event_loop()

            def _capture():
                return sniff(count=10, timeout=2.0,
                             lfilter=lambda p: p.haslayer(DHCP6_Advertise) or p.haslayer(DHCP6_Reply),
                             quiet=True)
            pkts = await loop.run_in_executor(None, _capture)
            seen = set()
            for pkt in pkts:
                mac = pkt[Ether].src if pkt.haslayer(Ether) else "?"
                ip = str(pkt[IPv6].src) if pkt.haslayer(IPv6) else "?"
                if mac not in seen:
                    seen.add(mac)
                    servers.append((ip, mac))
            if len(servers) > 1:
                logger.warning("NDP 防护 [T9]: 发现 %d 个 DHCPv6 服务器!", len(servers))
        except Exception as e:
            logger.debug("NDP 防护 [T9]: 嗅探异常: %s", e)
        return servers

    # ======================== 修复（全接口） ========================

    async def send_unsolicited_na(self, target: str = "ff02::1"):
        """
        在所有有 IPv6 地址的接口上发送 Unsolicited NA（IPv6 版 GARP）。
        等价于 arp_protection 的 GARP 广播。
        """
        if self._scapy_available:
            return await self._send_na_scapy_all(target)
        else:
            return await self._send_na_system_all()

    async def _send_na_scapy_all(self, target: str) -> bool:
        """scapy 在所有接口上发 NA"""
        if not self._scapy_available:
            return False
        loop = asyncio.get_event_loop()
        sent = 0

        def _send_one(iface: InterfaceInfo):
            local_ip = iface.ipv6_global or iface.ipv6_ll
            if not local_ip or not iface.mac:
                return 0
            try:
                eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=iface.mac)
                na = ICMPv6ND_NA(R=0, S=0, O=1, target=local_ip)
                lla = ICMPv6NDOptDstLLAddr(lladdr=iface.mac)
                ipv6 = IPv6(src=local_ip, dst=target, hlim=255)
                pkt = eth / ipv6 / na / lla
                for _ in range(5):
                    sendp(pkt, iface=iface.name, verbose=False)
                    time.sleep(0.02)
                return 5
            except Exception:
                return 0

        try:
            for iface in self.interfaces:
                if iface.ipv6_global or iface.ipv6_ll:
                    sent += await loop.run_in_executor(None, _send_one, iface)
            logger.info("NDP 防护: NA x%d 已在 %d 个接口发送", sent,
                        sum(1 for i in self.interfaces if i.ipv6_global or i.ipv6_ll))
            return sent > 0
        except Exception as e:
            logger.warning("NDP 防护: scapy NA 失败: %s", e)
            return False

    async def _send_na_system_all(self) -> bool:
        """系统命令降级：在所有网关上 ping"""
        if not self.gateway_ipv6:
            return False
        success = False
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-6", "-n", "10", "-w", str(int(self._ping_interval * 1000)),
                self.gateway_ipv6,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=15)
            success = proc.returncode == 0
        except Exception:
            pass
        return success

    async def _send_rs(self):
        """发送 Router Solicitation（触发合法 RA 覆盖恶意 RA）"""
        if not self._scapy_available:
            return
        loop = asyncio.get_event_loop()

        def _send(iface: InterfaceInfo):
            local = iface.ipv6_ll or iface.ipv6_global
            if not local or not iface.mac:
                return
            try:
                eth = Ether(dst="33:33:00:00:00:02", src=iface.mac)
                rs = ICMPv6ND_RS()
                lla = ICMPv6NDOptSrcLLAddr(lladdr=iface.mac)
                ipv6 = IPv6(src=local, dst="ff02::2", hlim=255)
                sendp(eth / ipv6 / rs / lla, iface=iface.name, verbose=False)
            except Exception:
                pass

        try:
            for iface in self.interfaces:
                if iface.ipv6_ll or iface.ipv6_global:
                    await loop.run_in_executor(None, _send, iface)
            logger.debug("NDP 防护: RS 已在 %d 个接口发送",
                         sum(1 for i in self.interfaces if i.ipv6_ll or i.ipv6_global))
        except Exception:
            pass

    async def protect_ndp_entry(self) -> bool:
        """为所有网关设静态 NDP 条目"""
        success = True
        for iface in self.interfaces:
            for gw_ip, gw_mac in iface.gateways:
                if not gw_ip or not gw_mac:
                    continue
                ok = await self._protect_entry(iface.name, gw_ip, gw_mac)
                if not ok:
                    success = False
        for ip, mac in self._manual_gateways:
            if ip and mac:
                ok = await self._protect_entry("", ip, mac)
                if not ok:
                    success = False
        return success

    async def _protect_entry(self, iface: str, gw: str, mac: str) -> bool:
        if sys.platform == "win32":
            try:
                mac_fmt = mac.replace(":", "-").upper()
                iface_name = iface or "以太网"
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv6", "set", "neighbors",
                    f"name={iface_name}", f"address={gw}", f"neighbor={mac_fmt}",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10)
                if proc.returncode == 0:
                    logger.info("NDP 防护: 静态 NDP %s -> %s (%s)", gw, mac, iface)
                    return True
                return False
            except Exception:
                return False
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "replace", gw, "lladdr", mac,
                    "dev", iface, "nud", "permanent",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
                return proc.returncode == 0
            except Exception:
                return False

    # ======================== NDP 修复主入口 ========================

    async def refresh_router_ndp(self, abort_check=None) -> bool:
        if not self.enabled or not self.gateway_pairs:
            return False
        now = time.monotonic()
        if now - self._last_fix_time < self._fix_cooldown:
            logger.debug("NDP 防护: 冷却中，跳过")
            return False
        self._last_fix_time = now

        logger.info("NDP 防护: 修复 NDP (接口=%d, 网关=%d)...",
                    len(self.interfaces), len(self.gateway_pairs))

        # 并行：T1 检测 + sniff
        t1_task = asyncio.create_task(self.check_ndp_poisoning())
        t7_task = asyncio.create_task(self._ndp_flood_detect())
        if self._scapy_available:
            sniff_task = asyncio.create_task(self._sniff_all())
        else:
            sniff_task = None

        # T1 先回来即开始修复
        await asyncio.wait_for(t1_task, timeout=10)
        na_task = asyncio.create_task(self.send_unsolicited_na())
        rs_task = asyncio.create_task(self._send_rs())

        if sniff_task:
            await asyncio.wait_for(sniff_task, timeout=8)
        await t7_task

        await asyncio.gather(na_task, rs_task, return_exceptions=True)
        await asyncio.sleep(0.2)

        if abort_check:
            try:
                if abort_check():
                    return True
            except Exception:
                pass

        # 验证所有网关
        all_ok = True
        for gw_ip, _ in self.gateway_pairs[:3]:  # 最多验证前 3 个
            if gw_ip and not await self._ping_ipv6(gw_ip):
                all_ok = False
                break

        if not all_ok:
            logger.warning("NDP 防护: 修复后网关不可达")
            return False

        await self.protect_ndp_entry()
        logger.info("NDP 防护: 修复完成")

        # 持续 NA 对抗（防攻击者立即重投毒）
        asyncio.create_task(self._na_sustain(duration=3))
        return True

    async def _na_sustain(self, duration: int = 3):
        """
        持续 NA 对抗（对标 ARP 的 _garp_sustain）。
        修复后继续发 NA，防止攻击者立即重投毒。
        每秒 ping 验证，不通才发 NA，通则静默等待。
        """
        if not self._scapy_available:
            return
        logger.debug("NDP 防护: 持续 NA 对抗 %ds...", duration)
        end = time.monotonic() + duration
        while self._ndp_running and time.monotonic() < end:
            # 检查所有网关是否仍可达
            all_ok = True
            for gw_ip, _ in self.gateway_pairs[:3]:
                if gw_ip and not await self._ping_ipv6(gw_ip):
                    all_ok = False
                    break
            if not all_ok:
                logger.warning("NDP 防护: 持续 NA 对抗中发现网关不可达，重发 NA")
                await self.send_unsolicited_na()
            await asyncio.sleep(1.0)
        logger.debug("NDP 防护: 持续 NA 对抗结束")

    async def _ping_ipv6(self, target: str) -> bool:
        if sys.platform == "win32":
            proc = await asyncio.create_subprocess_exec(
                "ping", "-6", "-n", "1", "-w", str(int(self._ping_interval * 1000)),
                target, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                "ping6", "-c", "1", "-W", str(self._ping_interval), target,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
        try:
            await asyncio.wait_for(proc.wait(), timeout=max(self._ping_interval + 2, 5))
            return proc.returncode == 0
        except Exception:
            return False

    # ======================== 统计 ========================

    @property
    def stats(self) -> dict:
        return {
            "enabled": self._enabled,
            "interfaces": len(self.interfaces),
            "total_gateways": len(self.gateway_pairs),
            "ipv6_addresses": self.all_local_ipv6,
            "scapy_available": self._scapy_available,
            "threat_events": len(self._threat_events),
            "last_fix_time": self._last_fix_time,
            "interface_details": [
                {
                    "name": iface.name,
                    "mac": iface.mac,
                    "ipv6_global": iface.ipv6_global,
                    "ipv6_ll": iface.ipv6_ll,
                    "gateways": iface.gateways,
                }
                for iface in self.interfaces
            ],
        }

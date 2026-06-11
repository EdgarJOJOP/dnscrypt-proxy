"""
NDP 防护模块 — IPv6 邻居发现协议 (NDP) 欺骗防护（多接口并行版）
=============================================================
IPv6 没有 ARP，替代者是 NDP（Neighbor Discovery Protocol, RFC 4861）。

攻击面覆盖 (RFC 3756):
  T1  NA 欺骗       — 常驻嗅探实时基线比对 + check_ndp_poisoning()
  T2  NS 欺骗       — _probe_gateway_ns() 主动 NS 探测 + _sniff_all()
  T3  RA 欺骗       — 常驻嗅探非信任 MAC 源发 RA 即告警
  T4  DAD DoS       — _sniff_all() 追踪 ≥3 次 DAD NS
  T5  NUD 失败      — _nud_tracker 80ms 窗口 ≥3 次 NS 重传
  T6  Redirect 欺骗 — _sniff_all() 非信任源 Redirect
  T7  NDP 泛洪      — _ndp_flood_detect() 邻居表增长率 >50条/秒
  T8  Replay 攻击   — 静态 NDP 条目终局防御
  T9  Rogue DHCPv6  — _dhcpv6_worker_loop() Event 驱动嗅探
  4.2.7 参数欺骗    — RA 中 CurHopLimit ≠255 或 M/O 标志异常

5 个常驻 worker (Event 驱动，不用就冻结):
  Worker 1: _recovery_worker_loop
  Worker 2: _na_burst_worker_loop
  Worker 3: _detect_worker_loop
  Worker 4: _ndp_sniffer_worker_loop (常驻嗅探 + 基线学习 + 参数检测)
  Worker 5: _dhcpv6_worker_loop

注：check_interval / ra_sniff_timeout / max_ra_routers 已移除。
    Worker 4 常驻 sniff 实时检测，无需轮询间隔或嗅探超时。
    RA 源自动学习替代 max_ra_routers 硬阈值。
"""

import os
import re
import sys
import time
import struct
import asyncio
import logging
import random
import locale
from typing import Optional, List, Tuple, Dict, Callable, Any
from collections import defaultdict
from dataclasses import dataclass, field

import socket

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
        Dot1Q, sniff, sendp,
    )
    _HAS_SCAPY = True
except ImportError:
    pass


@dataclass
class InterfaceInfo:
    """单个网卡的 IPv6 信息"""
    name: str = ""
    mac: str = ""
    ipv6_globals: List[str] = field(default_factory=list)
    ipv6_ll: str = ""
    gateways: List[Tuple[str, str, str]] = field(default_factory=list)

    @property
    def ipv6_global(self) -> str:
        return self.ipv6_globals[0] if self.ipv6_globals else ""


class NDPProtection:
    """
    NDP 防护：多接口 + 多网关 + 多地址
    5 个 Worker Event 驱动，不用就冻结。
    常驻 sniff 实时检测，无需轮询间隔 / 嗅探超时 / 路由器数量阈值。
    """

    def __init__(self, config_ndp: dict = None, ping_interval: float = 0.80,
                 ping_targets_v6: list = None):
        cfg = config_ndp or {}
        self._enabled = cfg.get("enabled", True)
        self._ping_interval = ping_interval
        self._ping_targets_v6 = ping_targets_v6 or ["2400:3200::1", "2400:da00::6666"]

        # 毫秒级可配置参数
        self._nud_window_ms = int(cfg.get("nud_window_ms", 80))
        self._nud_window = self._nud_window_ms / 1000.0
        self._nud_threshold = cfg.get("nud_threshold", 3)
        self._baseline_learn_ms = int(cfg.get("baseline_learn_ms", 3000))
        self._baseline_learn_time = self._baseline_learn_ms / 1000.0
        self._send_ns_probe = cfg.get("send_ns_probe", True)

        # VLAN/VXLAN 配置
        self._vxlan_enabled = cfg.get("vxlan_enabled", False)

        self.interfaces: List[InterfaceInfo] = []
        self._manual_gateways: List[Tuple[str, str, str]] = []  # [(ip, mac, vlan_id), ...]
        self._baseline_gateway_mac: str = ""
        gw_field = cfg.get("gateway_ipv6", "") or ""
        if isinstance(gw_field, str) and gw_field:
            pairs = self._parse_gateway_ipv6_field(gw_field)
            if pairs:
                self._manual_gateways = pairs
                for gw in pairs:
                    ip = gw[0]
                    mac = gw[1]
                    if not ip and mac:
                        self._baseline_gateway_mac = mac

        # VLAN/VXLAN: 提取第一个手动网关的 VLAN ID
        self._manual_gateway_vlan = self._manual_gateways[0][2] if self._manual_gateways and len(self._manual_gateways[0]) > 2 and self._manual_gateways[0][2] else ""

        self._detected = False
        self._last_refresh_time = 0.0
        self._scapy_available = _HAS_SCAPY
        self._running = False
        self._check_task: Optional[asyncio.Task] = None
        self._last_fix_time = 0.0
        self._threat_events: List[Dict] = []

        # ========== 常驻 Worker 框架 ==========
        self._ndp_running = False
        self._ndp_workers: list = []
        self._recovery_trigger = asyncio.Event()
        self._recovery_detected = asyncio.Event()
        self._run_detect = asyncio.Event()
        self._run_na_burst = asyncio.Event()
        self._na_burst_done = asyncio.Event()
        self._detect_done_event = asyncio.Event()
        self._na_burst_ready = False
        self._poison_detected = asyncio.Event()
        self._run_dhcpv6_check = asyncio.Event()

        # ========== 反击统计 ==========
        self._ndp_attack_stats: dict = {}
        self._ndp_sender_queue: asyncio.Queue = asyncio.Queue()
        self._ndp_sender_ready: bool = False
        self._ndp_counterstrike_cooldown: float = 0.0
        self._ndp_ip_migrated: bool = True              # 全局NDP是否已标记迁移（永久禁用IP迁移，仅用反制）

        # T5 NUD 追踪
        self._nud_tracker: Dict[str, list] = {}

        # 基线学习
        self._baseline_learned: bool = False
        self._baseline_mac_per_gw: Dict[str, str] = {}
        self._baseline_proposed: Dict[str, str] = {}
        self._baseline_proposed_time: Dict[str, float] = {}

        # 4.2.7 参数欺骗基线：记录第一次收到的合法 RA 参数
        self._ra_hoplimit_baseline: Optional[int] = None
        self._ra_m_flag_baseline: Optional[bool] = None
        self._ra_o_flag_baseline: Optional[bool] = None
        self._ra_baseline_learned: bool = False

        # RA 源自动学习（替代 max_ra_routers 硬阈值）
        self._trusted_ra_sources: set = set()  # {MAC, ...} 已确认的合法 RA 源
        self._suspicious_ra_sources: set = set()  # {MAC, ...} 可疑源

    # ======================== 属性 ========================

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def gateway_pairs(self) -> List[Tuple[str, str, str]]:
        pairs = []
        for gw in self._manual_gateways:
            if len(gw) >= 3:
                pairs.append((gw[0], gw[1], gw[2]))
            else:
                pairs.append((gw[0], gw[1], ""))
        for iface in self.interfaces:
            for gw_ip, gw_mac, _ in iface.gateways:
                if not any(ip == gw_ip for ip, _, _ in pairs):
                    pairs.append((gw_ip, gw_mac, ""))
        return pairs

    @property
    def gateway_ipv6(self) -> Optional[str]:
        if self._manual_gateways and self._manual_gateways[0][0]:
            return self._manual_gateways[0][0]
        for iface in self.interfaces:
            for gw_ip, _, _ in iface.gateways:
                if gw_ip:
                    return gw_ip
        return None

    @property
    def gateway_mac(self) -> Optional[str]:
        for ip, mac, _ in self.gateway_pairs:
            if ip == self.gateway_ipv6 and mac:
                return mac
        return None

    @property
    def local_mac(self) -> Optional[str]:
        for iface in self.interfaces:
            if iface.ipv6_global or iface.ipv6_ll:
                return iface.mac
        return None

    @property
    def local_ipv6(self) -> Optional[str]:
        for iface in self.interfaces:
            if iface.ipv6_global:
                return iface.ipv6_global
        return None

    @property
    def interface_name(self) -> Optional[str]:
        for iface in self.interfaces:
            if iface.ipv6_global or iface.ipv6_ll:
                return iface.name
        return None

    @property
    def all_local_ipv6(self) -> List[str]:
        addrs = []
        for iface in self.interfaces:
            addrs.extend(iface.ipv6_globals)
            if iface.ipv6_ll:
                addrs.append(iface.ipv6_ll)
        return addrs

    @staticmethod
    def _parse_gateway_ipv6_field(gw_field: str) -> list:
        """
        解析 gateway_ipv6 逗号格式，仅支持 3 元素交替格式:
        "IPv6,MAC,VLAN_ID,IPv6,MAC,VLAN_ID"

        IPv6 含 :: 或超过 2 个冒号，MAC 为 6 组双位十六进制数，
        VLAN_ID 为纯数字或空。
        vxlan_enabled=true 时 VLAN_ID 解释为 VXLAN VNI。
        """
        parts = [p.strip() for p in gw_field.split(",")]
        n = len(parts)
        if n == 0 or (n == 1 and not parts[0]):
            return []

        # 每 3 个一组：每组为 (IPv6, MAC, VLAN_ID)
        groups = []
        i = 0
        while i + 2 < n:
            groups.append((parts[i], parts[i+1], parts[i+2]))
            i += 3
        if i < n:
            ip = parts[i] if i < n else ""
            mac = parts[i+1] if i + 1 < n else ""
            vlan = parts[i+2] if i + 2 < n else ""
            groups.append((ip, mac, vlan))
        return groups

    @staticmethod
    def _decode_win_output(data: bytes) -> str:
        """Decode Windows cmd output: try system encoding, then utf-8/gbk.
        Never depends on keyword validation — returns cleanly decoded text."""
        seen = set()
        for enc in (locale.getpreferredencoding(False), 'utf-8', 'gbk'):
            if enc in seen:
                continue
            seen.add(enc)
            try:
                return data.decode(enc, errors='replace')
            except LookupError:
                continue
        return data.decode('utf-8', errors='replace')

    # ======================== 生命周期 ========================


    async def _ping_ipv6(self, target: str) -> bool:
        """Ping an IPv6 target using system ping -6."""
        result = await self._ping_ipv6_detailed(target)
        return result["reachable"]

    async def _ping_ipv6_detailed(self, target: str, timeout_sec: int = 3) -> dict:
        """
        IPv6 ICMP 详细探测 — 解析 ping -6 输出提取 ICMPv6 信息。

        IPv6 ICMPv6 Destination Unreachable 是 type=1：
          code=0 (No Route to Destination)
          code=3 (Address Unreachable)

        当光猫仍在运行但光纤断开时，光猫会对 IPv6 外网 ping 回复
        ICMPv6 type=1 (Destination Unreachable)。

        Returns:
            {"reachable": bool, "icmp_type": int|None, "icmp_code": int|None,
             "from_ip": str|None, "saw_reply": bool}
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-6", "-n", "1", "-w", str(int(timeout_sec * 1000)), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_sec + 2)
            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            lines = stdout_text.splitlines()

            reachable = (proc.returncode == 0)
            icmp_type = None
            icmp_code = None
            from_ip = None
            saw_reply = False

            for line in lines:
                # Windows ping -6 output patterns
                # "来自 2001:db8::1 的回复: 无法访问目标主机"
                # "Reply from 2001:db8::1: Destination net unreachable"
                if "unreachable" in line.lower() or "无法访问" in line or "目标不可达" in line:
                    icmp_type = 1  # ICMPv6 Destination Unreachable
                    if "net" in line.lower() or "network" in line.lower() or "路由" in line:
                        icmp_code = 0  # No Route
                    elif "host" in line.lower() or "主机" in line:
                        icmp_code = 3  # Address Unreachable
                    else:
                        icmp_code = 0
                    saw_reply = True
                    # Extract source IP (IPv6)
                    m = re.search(r'([0-9a-fA-F:]+(?::[0-9a-fA-F:]+)*)', line)
                    if m:
                        from_ip = m.group(1)
                elif "Reply from" in line or "来自" in line:
                    saw_reply = True
                    if reachable:
                        icmp_type = 129  # ICMPv6 Echo Reply
                        icmp_code = 0
                    m = re.search(r'([0-9a-fA-F:]+(?::[0-9a-fA-F:]+)*)', line)
                    if m:
                        from_ip = m.group(1)

            return {"reachable": reachable, "icmp_type": icmp_type, "icmp_code": icmp_code,
                    "from_ip": from_ip, "saw_reply": saw_reply}

        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return {"reachable": False, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": False}

    async def probe_wan_unreachable_v6(self, target_ip: str,
                                         timeout_sec: int = 3,
                                         gateway_ipv6: str = None) -> dict:
        """
        IPv6 WAN 断连探测：对外网 IPv6 目标发 ping -6，检测是否收到
        来自网关的 ICMPv6 Destination Unreachable (type=1, code=0/3)。

        当光猫运行但光纤断开时，光猫会对 IPv6 外网目标回复
        ICMPv6 type=1 (Destination Unreachable)。

        Args:
            target_ip: IPv6 外网探测目标
            timeout_sec: 探测超时（秒）
            gateway_ipv6: 本机网关 IPv6，用于判断回复来源

        Returns:
            {"wan_dead": bool, "unreachable_code": int|None,
             "from_ip": str|None, "timeout": bool, "detail": dict}
        """
        result = await self._ping_ipv6_detailed(target_ip, timeout_sec=timeout_sec)

        from_ip = result.get("from_ip")
        icmp_type = result.get("icmp_type")
        icmp_code = result.get("icmp_code") if result.get("icmp_code") is not None else -1

        # ICMPv6 Destination Unreachable is type=1, code=0 (No Route) or code=3 (Address Unreachable)
        is_v6_unreach = (icmp_type == 1 and icmp_code in (0, 3)
                         and from_ip is not None
                         and (gateway_ipv6 is None or from_ip == gateway_ipv6))

        return {
            "wan_dead": is_v6_unreach,
            "unreachable_code": int(icmp_code) if icmp_code is not None else None,
            "from_ip": from_ip,
            "timeout": not result.get("saw_reply", False),
            "detail": result,
        }

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
        await self._start_workers()
        logger.info("NDP 防护: 已启动 (接口=%d, 网关=%d, scapy=%s, workers=%d)",
                    len(self.interfaces), len(self.gateway_pairs), self._scapy_available,
                    len(self._ndp_workers))

    async def stop(self):
        self._running = False
        self._ndp_running = False
        self._recovery_trigger.set()
        self._run_detect.set()
        self._run_na_burst.set()
        self._na_burst_done.set()
        self._detect_done_event.set()
        self._poison_detected.set()
        try:
            self._ndp_sender_queue.put_nowait(None)
        except Exception:
            pass
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
        """每 30 秒执行一次主动探测（T2）+ 检查更新"""
        while self._running:
            try:
                await asyncio.sleep(30)
                if not self._running:
                    break
                self._run_dhcpv6_check.set()
                results = await self.run_all_checks()
                if self._send_ns_probe:
                    for gw_ip, known_mac, _ in self.gateway_pairs[:5]:
                        if not gw_ip:
                            continue
                        actual_mac = await self._probe_gateway_ns(gw_ip, timeout=1.5)
                        if actual_mac and known_mac and actual_mac.upper() != known_mac.upper():
                            logger.warning("NDP 防护 [T2]: NS 探测投毒! %s -> 预期 %s != 实际 %s",
                                           gw_ip, known_mac, actual_mac)
                            results.setdefault("t2_ns", []).append((gw_ip, known_mac, actual_mac))
                threat_count = sum(1 for v in results.values() if v)
                if threat_count:
                    logger.info("NDP 防护: 检测到 %d 类异常，触发修复", threat_count)
                    asyncio.create_task(self.refresh_router_ndp())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("NDP 防护: 周期检测异常: %s", e)

    # ======================== Worker 框架 ========================

    async def _start_workers(self):
        if self._ndp_workers:
            return
        self._ndp_running = True
        self._ndp_workers = [
            asyncio.create_task(self._recovery_worker_loop()),
            asyncio.create_task(self._na_burst_worker_loop()),
            asyncio.create_task(self._detect_worker_loop()),
            asyncio.create_task(self._ndp_sniffer_worker_loop()),
            asyncio.create_task(self._dhcpv6_worker_loop()),
            asyncio.create_task(self._ndp_sender_worker_loop()),
        ]
        logger.debug("NDP 防护: 6 个常驻 worker(含NDP发送器)已启动")

    async def _recovery_worker_loop(self):
        while self._ndp_running:
            await self._recovery_trigger.wait()
            if not self._ndp_running:
                return
            self._recovery_trigger.clear()
            self._recovery_detected.clear()
            for gw_ip, _, _ in self.gateway_pairs[:3]:
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

    async def _na_burst_worker_loop(self):
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
        while self._ndp_running:
            await self._run_detect.wait()
            if not self._ndp_running:
                return
            self._run_detect.clear()
            self._detect_done_event.clear()
            try:
                await self.run_all_checks()
            except Exception as e:
                logger.debug("NDP 防护: 检测异常: %s", e)
            self._detect_done_event.set()

    async def _ndp_sniffer_worker_loop(self):
        """
        Worker 4: 常驻 NDP 嗅探。
        
        持续监听 NA/NS/RA/Redirect 报文，实时检测投毒。
        同时学习合法 RA 源 MAC（替代 max_ra_routers 硬阈值）。
        检测 RA 参数欺骗（4.2.7）：CurHopLimit != 255、M/O 标志异常。
        有报文时处理，无报文时冻结在 sniff() 内（零 CPU）。
        """
        if not self._scapy_available:
            await asyncio.Event().wait()
            return
        loop = asyncio.get_event_loop()

        def _sniff():
            sniff(
                count=0, timeout=None,
                lfilter=lambda p: (
                    p.haslayer(Ether) and p.haslayer(IPv6) and (
                        p.haslayer(ICMPv6ND_NA) or
                        p.haslayer(ICMPv6ND_NS) or
                        p.haslayer(ICMPv6ND_RA) or
                        p.haslayer(ICMPv6Error)
                    )
                ),
                prn=self._on_ndp_packet,
                store=False, quiet=True,
            )

        try:
            await loop.run_in_executor(None, _sniff)
        except Exception as e:
            logger.debug("NDP 防护: 嗅探 worker 退出 (%s)", e)

    def _on_ndp_packet(self, pkt):
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return
        src_mac = pkt[Ether].src.upper()
        src_ip = str(pkt[IPv6].src)
        all_gw_ips = {ip for ip, _, _ in self.gateway_pairs if ip}
        all_local_ips = set(self.all_local_ipv6)

        # ==================== RA 处理 ====================
        if pkt.haslayer(ICMPv6ND_RA):
            ra = pkt[ICMPv6ND_RA]

            # --- 4.2.7 参数欺骗检测 ---
            hop_limit = ra.hlim
            m_flag = bool(ra.M)
            o_flag = bool(ra.O)

            # 学习合法 RA 参数基线（从第一个 RA 学习）
            if not self._ra_baseline_learned:
                self._ra_hoplimit_baseline = hop_limit
                self._ra_m_flag_baseline = m_flag
                self._ra_o_flag_baseline = o_flag
                self._ra_baseline_learned = True
                # 将当前 RA 源加入信任列表
                self._trusted_ra_sources.add(src_mac)
            else:
                # CurHopLimit != 255 一定是伪造 RA
                if self._ra_hoplimit_baseline is not None and hop_limit < 255:
                    logger.warning("NDP 嗅探 [4.2.7]: CurHopLimit=%d (异常) RA 源 %s (%s)",
                                   hop_limit, src_ip, src_mac)
                    self._suspicious_ra_sources.add(src_mac)
                    self._threat_events.append({
                        "type": "ra_param_spoof", "time": time.time(),
                        "src_mac": src_mac, "src_ip": src_ip,
                        "detail": f"CurHopLimit={hop_limit} (expected >=255)",
                    })
                # M/O 标志与基线不一致
                base_m = self._ra_m_flag_baseline
                base_o = self._ra_o_flag_baseline
                if base_m is not None and base_o is not None:
                    if m_flag != base_m or o_flag != base_o:
                        logger.warning("NDP 嗅探 [4.2.7]: M/O 标志异常 RA 源 %s (%s) M=%d O=%d (基线 M=%d O=%d)",
                                       src_ip, src_mac, m_flag, o_flag, base_m, base_o)
                        self._threat_events.append({
                            "type": "ra_param_spoof", "time": time.time(),
                            "src_mac": src_mac, "src_ip": src_ip,
                            "detail": f"M={m_flag} O={o_flag} (baseline M={base_m} O={base_o})",
                        })
                        self._suspicious_ra_sources.add(src_mac)

                # --- RA 源自动学习（替代 max_ra_routers）---
                # 从手动配置的网关 MAC 或已确认的接口网关 MAC 发来的 RA = 信任
                known_gw_macs = {mac.upper() for _, mac, _ in self.gateway_pairs if mac}
                known_baseline_macs = set(self._baseline_mac_per_gw.values())
                all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources

                if src_mac not in all_trusted and src_mac not in self._suspicious_ra_sources:
                    # 新 RA 源但不属于信任/可疑列表 → 检查是否在手动网关列表中
                    is_known = any(
                        src_ip == gw or src_mac == m.upper()
                        for gw, m, _ in self.gateway_pairs if m
                    )
                    if is_known:
                        self._trusted_ra_sources.add(src_mac)
                        logger.info("NDP 嗅探: 自动学习 RA 源 [%s] %s", src_mac, src_ip)
                    else:
                        logger.warning("NDP 嗅探 [T3]: 未知 RA 源! %s (%s)", src_ip, src_mac)
                        self._suspicious_ra_sources.add(src_mac)
                        self._threat_events.append({
                            "type": "rogue_ra", "time": time.time(),
                            "src_mac": src_mac, "src_ip": src_ip,
                        })

        # ==================== T5 NUD 追踪 ====================
        if pkt.haslayer(ICMPv6ND_NS):
            ns = pkt[ICMPv6ND_NS]
            ns_target = str(ns.target)
            now = time.time()
            self._nud_tracker = {
                t: [ts for ts in times if now - ts < self._nud_window]
                for t, times in self._nud_tracker.items()
            }
            if ns_target not in self._nud_tracker:
                self._nud_tracker[ns_target] = []
            self._nud_tracker[ns_target].append(now)
            if len(self._nud_tracker[ns_target]) >= self._nud_threshold:
                logger.warning("NDP 嗅探 [T5]: NUD 失败 %s! %d 次 NS 重传",
                               ns_target, len(self._nud_tracker[ns_target]))
                self._threat_events.append({
                    "type": "nud_failure", "time": now,
                    "target": ns_target, "count": len(self._nud_tracker[ns_target]),
                })
                self._nud_tracker[ns_target] = []

        # ==================== 基线学习 ====================
        if pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_NS):
            for gw_ip in all_gw_ips:
                if src_ip == gw_ip:
                    if gw_ip not in self._baseline_proposed:
                        self._baseline_proposed[gw_ip] = src_mac
                        self._baseline_proposed_time[gw_ip] = time.time()
                    elif self._baseline_proposed[gw_ip] == src_mac:
                        elapsed = time.time() - self._baseline_proposed_time.get(gw_ip, 0)
                        if elapsed > self._baseline_learn_time and not self._baseline_learned:
                            self._baseline_mac_per_gw[gw_ip] = src_mac
                            self._baseline_learned = True
                            logger.info("NDP 防护: 基线学习完成 [%s] -> MAC=%s", gw_ip, src_mac)
                    else:
                        self._baseline_proposed[gw_ip] = src_mac
                        self._baseline_proposed_time[gw_ip] = time.time()
                    break

        # ==================== T1 NA 投毒 ====================
        if pkt.haslayer(ICMPv6ND_NA):
            na = pkt[ICMPv6ND_NA]
            na_target = str(na.target)
            for gw_ip in all_gw_ips:
                baseline = self._baseline_mac_per_gw.get(gw_ip)
                if baseline and (src_ip == gw_ip or na_target == gw_ip) and src_mac != baseline:
                    self._threat_events.append({
                        "type": "na_poison", "time": time.time(),
                        "gateway": gw_ip, "expected_mac": baseline, "actual_mac": src_mac,
                    })
                    logger.warning("NDP 嗅探 [T1]: NA 投毒! %s -> 预期 %s != 实际 %s",
                                   gw_ip, baseline, src_mac)
                    # 自适应防抖：根据攻击频率缩短间隔，同ARP逻辑
                    _now_t1 = time.time()
                    _stats_t1 = self._ndp_attack_stats.get(src_mac, {})
                    _rate_t1 = _stats_t1.get("count", 0)
                    if _rate_t1 > 200:
                        _debounce_t1 = 0.0
                    elif _rate_t1 > 100:
                        _debounce_t1 = 0.1
                    elif _rate_t1 > 50:
                        _debounce_t1 = 0.3
                    elif _rate_t1 > 10:
                        _debounce_t1 = 1.0
                    else:
                        _debounce_t1 = 3.0
                    _last_time = _stats_t1.get("last_attack", 0)
                    if _now_t1 - _last_time < _debounce_t1:
                        break
                    if not self._poison_detected.is_set():
                        self._poison_detected.set()
                        asyncio.get_event_loop().call_soon_threadsafe(
                            lambda: asyncio.create_task(self._on_poison_detected(attacker_mac=src_mac, attacker_ip=src_ip)))
                    break

        # ==================== IP 冲突 ====================
        for local_ip in all_local_ips:
            if local_ip and (src_ip == local_ip or (
                pkt.haslayer(ICMPv6ND_NA) and str(pkt[ICMPv6ND_NA].target) == local_ip
            )) and src_mac != self.local_mac:
                self._threat_events.append({
                    "type": "ip_conflict", "time": time.time(),
                    "ip": local_ip, "attacker_mac": src_mac,
                })
                logger.warning("NDP 嗅探: IP 冲突! %s 被 %s 宣告", local_ip, src_mac)
                _now_ipc = time.time()
                _stats_ipc = self._ndp_attack_stats.get(src_mac, {})
                _rate_ipc = _stats_ipc.get("count", 0)
                if _rate_ipc > 200:
                    _debounce_ipc = 0.0
                elif _rate_ipc > 100:
                    _debounce_ipc = 0.1
                elif _rate_ipc > 50:
                    _debounce_ipc = 0.3
                elif _rate_ipc > 10:
                    _debounce_ipc = 1.0
                else:
                    _debounce_ipc = 3.0
                _last_time_ipc = _stats_ipc.get("last_attack", 0)
                if _now_ipc - _last_time_ipc < _debounce_ipc:
                    break
                self._poison_detected.set()
                asyncio.get_event_loop().call_soon_threadsafe(
                    lambda: asyncio.create_task(self._on_poison_detected(attacker_mac=src_mac, attacker_ip=src_ip)))
                break

    def has_recent_attacks(self, seconds: float = 5.0) -> bool:
        """检查指定秒数内是否有任何 NDP 攻击被检测到。

        Args:
            seconds: 检测时间窗口（秒），默认 5 秒

        Returns:
            True 表示窗口内有攻击事件
        """
        if not self._ndp_attack_stats:
            return False
        now = time.time()
        for mac, stats in self._ndp_attack_stats.items():
            last_attack = stats.get("last_attack", 0)
            if now - last_attack < seconds:
                return True
        return False

    async def _on_poison_detected(self, attacker_mac: str = "", attacker_ip: str = ""):
        if not self._enabled:
            return
        now = time.time()
        # 更新攻击统计（清理超300s + 60s窗口，同ARP逻辑）
        stale_macs = [m for m, s in self._ndp_attack_stats.items() if now - s.get("last_attack", 0) > 300.0]
        for m in stale_macs:
            del self._ndp_attack_stats[m]
        if attacker_mac:
            stats = self._ndp_attack_stats.setdefault(attacker_mac, {"count": 0, "bursts_sent": 0, "last_attack": 0.0, "last_counterstrike": 0.0, "window_start": now, "ip_switched": False})
            if now - stats.get("window_start", now) > 60.0:
                stats["count"] = 0
                stats["bursts_sent"] = 0
                stats["window_start"] = now
            stats["count"] += 1
            stats["last_attack"] = now

        logger.info("NDP 防护: 嗅探检测到投毒，触发修复")
        await self.refresh_router_ndp()
        # 投毒检测后立即触发 NA 反制（异步不阻塞）
        asyncio.create_task(self._ndp_counterstrike(attacker_mac=attacker_mac, attacker_ip=attacker_ip))

    async def refresh_router_ndp(self, abort_check=None) -> bool:
        """刷新路由器 NDP 表（当前无 IPv6 网络时跳过）"""
        if not self._enabled:
            return False
        logger.info("NDP 防护: 刷新路由器 NDP 表...")
        self._run_na_burst.set()  # 触发 NA 爆发 worker
        try:
            await asyncio.wait_for(self._na_burst_done.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            pass
        return True

    # ======================== Worker 5: DHCPv6 ========================

    async def _dhcpv6_worker_loop(self):
        if not self._scapy_available:
            await asyncio.Event().wait()
            return
        loop = asyncio.get_event_loop()
        while self._ndp_running:
            await self._run_dhcpv6_check.wait()
            if not self._ndp_running:
                return
            self._run_dhcpv6_check.clear()
            try:
                from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply

                def _capture():
                    return sniff(count=20, timeout=3.0,
                                 lfilter=lambda p: p.haslayer(DHCP6_Advertise) or p.haslayer(DHCP6_Reply),
                                 quiet=True)
                pkts = await loop.run_in_executor(None, _capture)
                seen = set()
                servers = []
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

    # ======================== T2: 主动 NS 探测 ========================

    async def _probe_gateway_ns(self, gw_ip: str, timeout: float = 2.0) -> Optional[str]:
        if not self._scapy_available:
            return None
        loop = asyncio.get_event_loop()
        result: List[str] = []

        def _send_ns_and_listen():
            try:
                for iface in self.interfaces:
                    local_ll = iface.ipv6_ll
                    if not local_ll or not iface.mac:
                        continue
                    eth = Ether(dst="33:33:ff:00:00:01", src=iface.mac)
                    ns = ICMPv6ND_NS(target=gw_ip)
                    src_lla = ICMPv6NDOptSrcLLAddr(lladdr=iface.mac)
                    ipv6 = IPv6(src=local_ll, dst=gw_ip, hlim=255)
                    sendp(eth / ipv6 / ns / src_lla, iface=iface.name, verbose=False)
                na_pkts = sniff(count=5, timeout=timeout,
                                lfilter=lambda p: p.haslayer(ICMPv6ND_NA) and
                                                  p.haslayer(ICMPv6NDOptDstLLAddr) and
                                                  str(p[ICMPv6ND_NA].target) == gw_ip,
                                quiet=True)
                for pkt in na_pkts:
                    na = pkt[ICMPv6ND_NA]
                    if na.haslayer(ICMPv6NDOptDstLLAddr):
                        mac = na[ICMPv6NDOptDstLLAddr].lladdr.upper()
                        result.append(mac)
            except Exception:
                pass

        try:
            await loop.run_in_executor(None, _send_ns_and_listen)
        except Exception as e:
            logger.debug("NDP 防护 [T2]: NS 探测异常: %s", e)
        return result[0] if result else None

    # ======================== 多接口探测 ========================

    async def detect_gateway(self):
        if self._detected:
            return
        if self._manual_gateways:
            logger.info("NDP 防护: 使用手动配置 %d 个 IPv6 网关", len(self._manual_gateways))
            for i, (ip, mac, vlan) in enumerate(self._manual_gateways):
                if ip and not mac:
                    resolved = await self._resolve_mac_single(ip)
                    if resolved:
                        self._manual_gateways[i] = (ip, resolved, vlan if len(self._manual_gateways[i]) > 2 else "")
            self._detected = True
            await self._detect_local_info()
            # 确保 VLAN 子接口存在
            if self._manual_gateway_vlan and not self._vxlan_enabled:
                for iface in self.interfaces:
                    if iface.name:
                        await self._ensure_vlan_interface(iface.name, self._manual_gateway_vlan)
                        break
            return
        if sys.platform == "win32":
            await self._detect_all_windows()
        else:
            await self._detect_all_linux()
        if self.interfaces:
            self._detected = True
            total_gws = sum(len(iface.gateways) for iface in self.interfaces)
            logger.info("NDP 防护: 探测到 %d 个接口, %d 个网关", len(self.interfaces), total_gws)
            for iface in self.interfaces:
                gw_str = ", ".join(f"{g[0]}({g[1] or '?'})" for g in iface.gateways)
                logger.info("  接口 %s [%s] IPv6=%s LL=%s 网关=[%s]",
                            iface.name, iface.mac, ", ".join(iface.ipv6_globals) or "-",
                            iface.ipv6_ll or "-", gw_str)
        else:
            logger.debug("NDP 防护: 未检测到 IPv6 网络")
        await self._detect_local_info()
        # 确保 VLAN 子接口存在（以第一个接口为准）
        if self._manual_gateway_vlan and not self._vxlan_enabled:
            for iface in self.interfaces:
                if iface.name:
                    await self._ensure_vlan_interface(iface.name, self._manual_gateway_vlan)
                    break


    async def _ensure_vlan_interface(self, iface_name: str, vlan_id: str) -> bool:
        """确保 VLAN 子接口存在（vlan_id 非空且非 VXLAN 时自动创建）"""
        if not vlan_id or self._vxlan_enabled or not iface_name:
            return True
        vlan_iface = f"{iface_name}.{vlan_id}"
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv4", "add", "vlan",
                    f"name={iface_name}", f"vlanid={vlan_id}",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                _, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0:
                    logger.info("NDP 防护: VLAN 子接口 %s 已创建", vlan_iface)
                else:
                    logger.debug("NDP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在）", vlan_iface, proc.returncode)
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("NDP 防护: VLAN 子接口创建失败 %s", e)
                return False
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "link", "add", "link", iface_name,
                    "name", vlan_iface,
                    "type", "vlan", "id", str(vlan_id),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10)
                if proc.returncode == 0:
                    logger.info("NDP 防护: VLAN 子接口 %s 已创建", vlan_iface)
                else:
                    logger.debug("NDP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在）", vlan_iface, proc.returncode)
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("NDP 防护: VLAN 子接口创建失败 %s", e)
                return False

    async def _detect_all_windows(self):
        default_routes = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv6", "show", "route",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in self._decode_win_output(stdout).splitlines():
                s = line.strip()
                if "::/0" in s:
                    # netsh output format: e.g. "No  System  4256  ::/0  14  fe80::1"
                    parts = s.split()
                    try:
                        idx = next(i for i, t in enumerate(parts) if t == "::/0")
                    except StopIteration:
                        continue
                    gw = None
                    zone_id = 0
                    for t in parts[idx+1:]:
                        if ":" in t and not t.startswith("ff"):
                            gw = t
                            break
                        try:
                            zone_id = int(t)
                        except ValueError:
                            pass
                    if gw:
                        if gw.startswith("fe80") and zone_id:
                            gw = f"{gw}%{zone_id}"
                        default_routes.append((gw, zone_id))
        except Exception as e:
            logger.debug("NDP 防护: netsh route 失败: %s", e)
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = self._decode_win_output(stdout)
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
            for prefix in ("以太网适配器 ", "Ethernet adapter ", "无线局域网适配器 ", "Wireless LAN adapter ", "WLAN 适配器 ", "WLAN adapter ", "本地连接", "Local Area Connection"):
                if name_line.startswith(prefix):
                    current_name = name_line[len(prefix):].rstrip(":")
                    break
            if not current_name:
                current_name = name_line.rstrip(":")
            iface = InterfaceInfo(name=current_name)
            for line in lines:
                s = line.strip()
                # IPv6 via regex — no Chinese matching
                m = re.search(r"((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+(?:%\d+)?)", s)
                if m:
                    ip = m.group(1).strip()
                    if ip.startswith("fe80"):
                        if not iface.ipv6_ll:
                            iface.ipv6_ll = ip
                    else:
                        iface.ipv6_globals.append(ip)
                # MAC via regex — no Chinese matching
                m = re.search(r"((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})(?:\s|$)", s)
                if m:
                    mac = m.group(1).replace("-", ":").upper()
                    if not iface.mac:
                        iface.mac = mac
            if iface.ipv6_ll or iface.ipv6_global:
                for gw, idx in default_routes:
                    if not any(g == gw for g, _ in iface.gateways):
                        iface.gateways.append((gw, "", ""))
                self.interfaces.append(iface)
        await self._resolve_all_gateway_macs()

    async def _detect_all_linux(self):
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
                if current_iface and (current_iface.ipv6_ll or current_iface.ipv6_globals):
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
                            current_iface.ipv6_globals.append(ip)
            if "link/ether" in s:
                for p in s.split():
                    if ":" in p and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', p.upper()):
                        current_iface.mac = p.upper()
        if current_iface and (current_iface.ipv6_ll or current_iface.ipv6_globals):
            self.interfaces.append(current_iface)
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
                                iface.gateways.append((gw, "", ""))
        except Exception as e:
            logger.debug("NDP 防护: Linux 路由失败: %s", e)
        await self._resolve_all_gateway_macs()

    async def _resolve_all_gateway_macs(self):
        for iface in self.interfaces:
            for i, (gw_ip, _, _) in enumerate(iface.gateways):
                if not gw_ip:
                    continue
                mac = await self._resolve_mac_single(gw_ip)
                if mac:
                    iface.gateways[i] = (gw_ip, mac, "")

    async def _resolve_mac_single(self, ipv6: str) -> Optional[str]:
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv6", "show", "neighbors",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                for line in self._decode_win_output(stdout).splitlines():
                    if ipv6.split("%")[0].lower() in line.lower():
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

    async def _detect_local_info(self):
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ipconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                text = self._decode_win_output(stdout)
                ipv6_pat = re.compile(r"((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+(?:%\d+)?)")
                mac_pat = re.compile(r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?:\s|$)")
                for line in text.splitlines():
                    s = line.strip()
                    m = ipv6_pat.search(s)
                    if m:
                        ip = m.group(1).strip()
                        if "fe80" in ip.lower():
                            for iface in self.interfaces:
                                if not iface.ipv6_ll:
                                    iface.ipv6_ll = ip
                                    break
                        else:
                            for iface in self.interfaces:
                                if iface.mac:
                                    iface.ipv6_globals.append(ip)
                                    break
                    m = mac_pat.search(s)
                    if m:
                        mac = m.group(1).replace("-", ":").upper()
                        for iface in self.interfaces:
                            if not iface.mac:
                                iface.mac = mac
                                break
            except Exception:
                pass
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "addr", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                text = stdout.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    s = line.strip()
                    if "inet6" in s:
                        for p in s.split():
                            if ":" in p:
                                ip = p.split("/")[0]
                                if "fe80" in ip.lower():
                                    for iface in self.interfaces:
                                        if not iface.ipv6_ll:
                                            iface.ipv6_ll = ip
                                            break
                    if "link/ether" in s:
                        for p in s.split():
                            if ":" in p and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', p.upper()):
                                for iface in self.interfaces:
                                    if not iface.mac:
                                        iface.mac = p.upper()
                                        break
            except Exception:
                pass

    # ======================== 综合检测 ========================

    async def run_all_checks(self) -> dict:
        results = {}
        if not self._enabled:
            return results
        non_sniff_tasks = {
            "t1_na": self.check_ndp_poisoning(),
            "t7_flood": self._ndp_flood_detect(),
        }
        sniff_result = {}
        if self._scapy_available:
            sniff_task = asyncio.create_task(self._sniff_all())
            non_sniff_results, sniff_result = await asyncio.gather(
                self._run_dict(non_sniff_tasks), sniff_task, return_exceptions=True)
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

    # ======================== T1: NA 欺骗 ========================

    async def check_ndp_poisoning(self) -> list:
        poisoned = []
        for gw in self._manual_gateways:
            ip = gw[0]
            expected = gw[1]
            if not ip:
                continue
            actual = await self._resolve_mac_single(ip)
            if expected and actual and actual.upper() != expected.upper():
                poisoned.append(("手动", ip, expected, actual))
            if not expected and self._baseline_gateway_mac and actual:
                if actual.upper() != self._baseline_gateway_mac.upper():
                    poisoned.append(("手动-基线", ip, self._baseline_gateway_mac, actual))
        for iface in self.interfaces:
            for gw_ip, expected, _ in iface.gateways:
                if not gw_ip or not expected:
                    continue
                actual = await self._resolve_mac_single(gw_ip)
                if actual and actual.upper() != expected.upper():
                    poisoned.append((iface.name, gw_ip, expected, actual))
        if poisoned:
            for iface_name, gw, exp, act in poisoned:
                logger.warning("NDP 防护 [T1]: %s 网关 %s MAC 变更! %s -> %s", iface_name, gw, exp, act)
        return poisoned

    # ======================== T7: 泛洪 ========================

    async def _ndp_flood_detect(self) -> bool:
        try:
            before = time.monotonic()
            cnt1 = await self._count_neighbors()
            await asyncio.sleep(0.5)
            cnt2 = await self._count_neighbors()
            rate = (cnt2 - cnt1) / (time.monotonic() - before)
            if rate > 50:
                logger.warning("NDP 防护 [T7]: 泛洪! 邻居增长 %.0f 条/秒", rate)
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
                return len(self._decode_win_output(stdout).splitlines())
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                return len(stdout.decode().splitlines())
        except Exception:
            return 0

    # ======================== sniff 分发 ========================

    async def _sniff_all(self) -> dict:
        if not self._scapy_available:
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}
        loop = asyncio.get_event_loop()

        def _capture():
            return sniff(count=200, timeout=4.0,
                         lfilter=lambda p: p.haslayer(Ether) and p.haslayer(IPv6) and (
                             p.haslayer(ICMPv6ND_NA) or p.haslayer(ICMPv6ND_NS) or
                             p.haslayer(ICMPv6ND_RA) or p.haslayer(ICMPv6Error)),
                         quiet=True)
        try:
            pkts = await loop.run_in_executor(None, _capture)
        except Exception as e:
            logger.debug("NDP 防护: sniff 失败: %s", e)
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        known_gw_macs = {mac.upper() for _, mac, _ in self.gateway_pairs if mac}
        ra_sources = {}
        ns_targets = defaultdict(int)
        dad_targets = defaultdict(int)
        redirect_sources = []
        suspicious_ns = []

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
        results["t3_ra"] = [(m, i, p) for m, (i, p) in ra_sources.items() if known_gw_macs and m not in known_gw_macs]
        results["t4_dad"] = [(t, c) for t, c in dad_targets.items() if c >= 3]
        results["t6_redirect"] = [(m, i) for m, i in redirect_sources if known_gw_macs and m not in known_gw_macs]
        if results["t3_ra"]:
            logger.warning("NDP 防护 [T3]: sniff 发现 %d 个未知 RA 源", len(results["t3_ra"]))
        if results["t4_dad"]:
            logger.warning("NDP 防护 [T4]: DAD 攻击!")
        return results

    # ======================== 修复 ========================

    async def send_unsolicited_na(self, target: str = "ff02::1"):
        if self._scapy_available:
            return await self._send_na_scapy_all(target)
        else:
            return await self._send_na_system_all()

    @staticmethod
    def _get_ndp_intensity(attack_rate: int) -> tuple:
        """根据 attack_rate 返回 (na_rounds, inter, tag)"""
        if attack_rate > 200:
            return (50, 0.00025, "MAX")
        elif attack_rate > 100:
            return (30, 0.0005, "L3")
        elif attack_rate > 50:
            return (20, 0.001, "L2")
        elif attack_rate > 30:
            return (10, 0.0015, "L1")
        elif attack_rate > 10:
            return (10, 0.0015, "L1")
        else:
            return (5, 0.002, "")

    async def _ndp_counterstrike(self, attacker_mac: str = "", attacker_ip: str = ""):
        """NDP 反制：定向 NA 打残攻击者 + 广播 NA 恢复网络"""
        if not self._scapy_available or not self._enabled:
            return
        now = time.time()
        stats = self._ndp_attack_stats.get(attacker_mac, {})
        attack_rate = stats.get("count", 0)

        # 全局唯一一次标记（仅首次攻击触发，后续任何攻击者只用反制）
        if attacker_mac and not self._ndp_ip_migrated:
            self._ndp_ip_migrated = True
            logger.warning("NDP 反制: 全局首次攻击(%s %s)，标记已防御", attacker_mac, attacker_ip)

        # 选择压制等级
        if attack_rate > 200:
            na_rounds = attack_rate + 10
            inter = 0.0
            logger.warning("NDP 反制 [COUNTERSTRIKE-UNLIMITED]: %s %d次/60s -> %d轮NA 无间隔！",
                           attacker_mac or "?", attack_rate, na_rounds)
        else:
            na_rounds, inter, tag = self._get_ndp_intensity(attack_rate)
            log_tag = f"[COUNTERSTRIKE-{tag}]" if tag else "[COUNTERSTRIKE]"
            logger.warning("NDP 反制 %s: %s %d次/60s -> %d轮NA @%.0fms",
                           log_tag, attacker_mac or "?", attack_rate, na_rounds, inter*1000)

        # 定向反制：单播 NA 到攻击者网卡，毒化其邻居缓存
        if attacker_mac and self._ndp_sender_ready:
            # 收集本机 IPv6 和 MAC 信息
            for iface in self.interfaces:
                local_ip = iface.ipv6_global or iface.ipv6_ll
                local_mac_real = iface.mac
                if local_ip and local_mac_real:
                    # 网关 IPv6 -> 00:00:00:00:00:00 毒化包（打残攻击者）
                    null_mac = "00:00:00:00:00:00"
                    vlan_id = self._manual_gateway_vlan
                    self._ndp_sender_queue.put_nowait(
                        (attacker_mac, local_ip, null_mac, attacker_ip or self.gateway_ipv6 or local_ip, na_rounds, inter, vlan_id)
                    )
                    # 正确 NA 广播（固定 1 轮，仅恢复路由器 NDP 表；定向反制保持原量）
                    self._ndp_sender_queue.put_nowait(
                        ("ff:ff:ff:ff:ff:ff", local_ip, local_mac_real, local_ip, 1, inter, vlan_id)
                    )
                    break

        # 回退：如果 sender 就绪就用队列，否则走原广播逻辑
        if not self._ndp_sender_ready:
            for i in range(1):  # 广播只需 1 轮
                try:
                    await self.send_unsolicited_na()
                    if inter > 0:
                        await asyncio.sleep(inter)
                except Exception as e:
                    logger.debug("NDP 反制: NA 发送失败 (%s)", e)
                    break
        logger.info("NDP 反制: %d 轮 NA 完成", na_rounds)

    async def _ndp_sender_worker_loop(self):
        """常驻 NDP 发送器：一次性导入 scapy，从队列取任务发送，进程冻结"""
        if not self._scapy_available:
            self._ndp_sender_ready = False
            await asyncio.Event().wait()
            return
        try:
            from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
        except Exception as e:
            logger.debug("NDP 防护: NDP 发送器初始化失败 (%s)", e)
            self._ndp_sender_ready = False
            await asyncio.Event().wait()
            return
        self._ndp_sender_ready = True
        logger.debug("NDP 防护: NDP 发送器已就绪")
        while self._ndp_running:
            try:
                task = await asyncio.wait_for(self._ndp_sender_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if task is None:
                break
            try:
                dst_mac, local_ip, local_mac, target_ip, count, inter, vlan_id = task
                eth = Ether(dst=dst_mac, src=local_mac)
                na = ICMPv6ND_NA(R=0, S=0, O=1, target=target_ip)
                lla = ICMPv6NDOptDstLLAddr(lladdr=local_mac)
                ipv6 = IPv6(src=local_ip, dst=dst_mac if dst_mac != "ff:ff:ff:ff:ff:ff" else "ff02::1", hlim=255)
                pkt = eth / ipv6 / na / lla
                # VLAN 802.1Q tag when vlan_id is set and not VXLAN
                if vlan_id and not self._vxlan_enabled:
                    try:
                        pkt = Ether(dst=dst_mac, src=local_mac) / Dot1Q(vlan=int(vlan_id)) / ipv6 / na / lla
                    except Exception:
                        pass
                elif vlan_id and self._vxlan_enabled:
                    try:
                        from scapy.all import VXLAN, IP, UDP
                        inner_pkt = eth / ipv6 / na / lla
                        pkt = Ether(dst=dst_mac, src=local_mac) / IP(dst=dst_mac, src=local_ip) / UDP(sport=4789, dport=4789) / VXLAN(vni=int(vlan_id)) / inner_pkt
                    except Exception:
                        pass
                for _ in range(count):
                    sendp(pkt, iface=self.interface_name or "", verbose=False)
                    if inter > 0:
                        await asyncio.sleep(inter)
                log_target = f"定向 {dst_mac}" if dst_mac != "ff:ff:ff:ff:ff:ff" else "广播"
                logger.warning("NDP 反制: 定向 NA %s %s(%s) -> %s x%d", log_target, target_ip, dst_mac, local_mac, count)
            except Exception as e:
                logger.debug("NDP 防护: NDP 发送失败 (%s)", e)

    async def _send_na_scapy_all(self, target: str) -> bool:
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
        success = True
        for iface in self.interfaces:
            for gw_ip, gw_mac, vlan_id in iface.gateways:
                if not gw_ip or not gw_mac:
                    continue
                ok = await self._protect_entry(iface.name, gw_ip, gw_mac, vlan_id)
                if not ok:
                    success = False
        for gw in self._manual_gateways:
            ip = gw[0]
            mac = gw[1]
            vlan_id = gw[2] if len(gw) > 2 else ""
            if ip and mac:
                ok = await self._protect_entry("", ip, mac, vlan_id)
                if not ok:
                    success = False
        return success

    async def _protect_entry(self, iface: str, gw: str, mac: str, vlan_id: str = "") -> bool:
        if sys.platform == "win32":
            try:
                mac_fmt = mac.replace(":", "-").upper()
                # VLAN 子接口：如果 vlan_id 非空且非 vxlan，附加 .{vlan} 到接口名
                iface_name = iface or "以太网"
                if vlan_id and not self._vxlan_enabled:
                    iface_name = f"{iface_name}.{vlan_id}"
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv6", "set", "neighbors",
                    f"name={iface_name}", f"address={gw.split(chr(37))[0]}", f"neighbor={mac_fmt}",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10)
                if proc.returncode == 0:
                    iface_log = iface_name if vlan_id else iface
                    logger.info("NDP 防护: 静态 NDP %s -> %s (%s)", gw, mac, iface_log)
                    return True
                return False
            except Exception:
                return False
        else:
            try:
                dev = iface
                if vlan_id and not self._vxlan_enabled:
                    dev = f"{iface}.{vlan_id}"
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "replace", gw, "lladdr", mac,
                    "dev", dev, "nud", "permanent",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
                return proc.returncode == 0
            except Exception:
                return False
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
            "trusted_ra_sources": len(self._trusted_ra_sources),
            "suspicious_ra_sources": len(self._suspicious_ra_sources),
            "interface_details": [{
                "name": iface.name, "mac": iface.mac,
                "ipv6_globals": iface.ipv6_globals, "ipv6_globals": iface.ipv6_globals, "ipv6_global": iface.ipv6_global, "ipv6_ll": iface.ipv6_ll,
                "gateways": iface.gateways,
            } for iface in self.interfaces],
        }

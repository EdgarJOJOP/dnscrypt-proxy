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

# Suppress Scapy socket BPF filter warnings on Windows
import warnings
warnings.filterwarnings("ignore", category=UserWarning, message=".*Socket.*failed.*")
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
_HAS_SCAPY = False
try:
    import scapy.all as scapy_module
    Ether = scapy_module.Ether
    IPv6 = scapy_module.IPv6
    ICMPv6ND_NA = scapy_module.ICMPv6ND_NA
    ICMPv6NDOptDstLLAddr = scapy_module.ICMPv6NDOptDstLLAddr
    ICMPv6ND_NS = scapy_module.ICMPv6ND_NS
    ICMPv6NDOptSrcLLAddr = scapy_module.ICMPv6NDOptSrcLLAddr
    ICMPv6ND_RA = scapy_module.ICMPv6ND_RA
    ICMPv6ND_RS = scapy_module.ICMPv6ND_RS
    ICMPv6NDOptRedirectedHdr = scapy_module.ICMPv6NDOptRedirectedHdr
    Dot1Q = scapy_module.Dot1Q
    sniff = scapy_module.sniff
    sendp = scapy_module.sendp
    # 兼容不同 scapy 版本的符号名
    ICMPv6NDOptPrefixInformation = getattr(scapy_module, 'ICMPv6NDOptPrefixInformation',
                                         getattr(scapy_module, 'ICMPv6NDOptPrefixInfo', None))
    try:
        from scapy.layers.inet6 import _ICMPv6Error as ICMPv6Error
    except Exception:
        ICMPv6Error = None
    _HAS_SCAPY = True
except Exception:
    pass


@dataclass
class InterfaceInfo:
    """单个网卡的 IPv6 信息"""
    name: str = ""
    idx: int = 0          # 接口索引（Windows: netsh 索引, Linux: if_nametoindex）
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
        # \u7f51\u53e3\u540d\u79f0->\u7d22\u5f15\u7f13\u5b58\uff0c\u7528\u4e8e\u9759\u6001 NDP \u7ed1\u5b9a
        self._iface_name_to_idx: Dict[str, int] = {}
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
        self._max_threat_events: int = 1000
        self._last_ra_cleanup: float = 0.0
        self._ra_cleanup_interval: float = 3600.0

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
        self._ndp_sender_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._ndp_sender_ready: bool = False
        # scapy sendp 运行时可用性（Windows 无 Npcap 时导入成功但发送失败）
        self._scapy_sendp_ok: bool = _HAS_SCAPY
        self._ndp_ip_migrated: bool = True              # 全局NDP是否已标记迁移（永久禁用IP迁移，仅用反制）
        self._local_macs: set = set()              # 本机所有网络接口的 MAC 地址（防自伤反制）
        self._local_macs_loaded: bool = False      # 本地 MAC 是否已加载

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
            logger.warning('NDP 防护: gateway_ipv6 配置尾部 ' + str(n - i) + ' 个多余元素被忽略 (格式应为 IPv6,MAC,VLAN_ID 交替)')
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

    @staticmethod
    async def _fetch_all_local_macs() -> set:
        """
        收集本机所有网络接口的 MAC 地址。
        用于识别攻击者是否冒用本机 MAC 进行 NDP 欺骗，防止反制误伤本地程序。

        Returns:
            所有本地 MAC 的集合（冒号大写格式，如 {'AA:BB:CC:DD:EE:FF', ...}）
        """
        macs: set = set()
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "getmac", "/FO", "CSV", "/NH",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                for line in stdout.decode(locale.getpreferredencoding(False), errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    inner = line.strip('"')
                    parts = inner.split('","')
                    if len(parts) >= 2:
                        mac = parts[1].strip()
                        if mac and len(mac.replace("-", "")) == 12:
                            macs.add(mac.replace("-", ":").upper())
                # getmac 失败时用 wmic 兜底
                if not macs:
                    try:
                        proc2 = await asyncio.create_subprocess_exec(
                            "wmic", "nic", "where", "NetEnabled=True", "get", "MACAddress",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
                        for line2 in out2.decode("utf-8", errors="replace").splitlines():
                            m = re.search(r'((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})', line2)
                            if m:
                                macs.add(m.group(1).replace("-", ":").upper())
                    except Exception:
                        pass
                # wmic 也失败时用 Python uuid.getnode() 兜底
                if not macs:
                    try:
                        import uuid
                        node = uuid.getnode()
                        if node is not None and node != 0 and not (node & 0x010000000000):
                            mac_str = ':'.join(f'{(node >> (5-i)*8) & 0xFF:02x}' for i in range(6)).upper()
                            if len(mac_str.replace(":", "")) == 12:
                                macs.add(mac_str)
                    except Exception:
                        pass
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ls", "/sys/class/net",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                interfaces = stdout.decode("utf-8", errors="replace").split()
                for iface in interfaces:
                    try:
                        proc2 = await asyncio.create_subprocess_exec(
                            "cat", f"/sys/class/net/{iface}/address",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=3)
                        mac = out2.decode("utf-8", errors="replace").strip()
                        if mac and len(mac.replace(":", "")) == 12:
                            macs.add(mac.upper())
                    except Exception:
                        continue
        except Exception as e:
            logger.debug("NDP 防护: 获取所有本地 MAC 失败: %s", e)
        return macs

    @staticmethod
    def _mac_normalize(mac: str) -> str:
        """去掉 MAC 中所有分隔符（:-）后统一大写，用于可靠比较不同来源的 MAC"""
        if not mac:
            return ""
        return re.sub(r'[:-]', '', mac).upper()

    # ======================== 生命周期 ========================



    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        """检查 MAC 地址是否是合法的物理网卡 MAC
        - 拒绝全零 00:00:00:00:00:00
        - 拒绝广播 FF:FF:FF:FF:FF:FF
        - 拒绝组播（第 1 字节 bit0=1，如 01:xx:xx:xx:xx:xx、33:33:xx:xx:xx:xx）
        """
        if not mac:
            return False
        mac = mac.replace("-", ":").upper()
        if mac == "00:00:00:00:00:00":
            return False
        if mac == "FF:FF:FF:FF:FF:FF":
            return False
        try:
            first_byte = int(mac.split(":")[0], 16)
            if first_byte & 0x01:  # 组播 MAC 第 1 字节最低位为 1
                return False
            return True
        except (ValueError, IndexError):
            return False

    async def _ping_ipv6(self, target: str, timeout_ms: int = 3000) -> bool:
        """Ping an IPv6 target using system ping -6."""
        result = await self._ping_ipv6_detailed(target, timeout_sec=max(1, timeout_ms // 1000))
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
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-6", "-n", "1", "-w", str(int(timeout_sec * 1000)), target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-6", "-c", "1", "-W", str(max(1, int(timeout_sec))), target,
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
        self._loop = asyncio.get_event_loop()
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
        self._run_dhcpv6_check.set()
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
                await self._cleanup_ra_sources()
                await asyncio.sleep(30)
                if not self._running:
                    break
                
                # 无 scapy 兜底：每 30 秒检查基线是否已学习
                if not self._scapy_available and not self._baseline_learned:
                    had_macs = any(True for iface in self.interfaces
                                   for _, mac, _ in iface.gateways if mac)
                    if not had_macs:
                        await self._resolve_all_gateway_macs()
                    await self.protect_ndp_entry()
                self._run_dhcpv6_check.set()
                results = await self.run_all_checks()
                if self._send_ns_probe:
                    for gw_ip, known_mac, _ in self.gateway_pairs[:5]:
                        if not gw_ip:
                            continue
                        actual_mac = await self._probe_gateway_ns(gw_ip, timeout=1.5)
                        if actual_mac and known_mac and self._mac_normalize(actual_mac) != self._mac_normalize(known_mac):
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
        Worker 4: 常驻 NDP 嗅探 — 三级兜底。
        
        优先级:
          1. scapy sniff（跨平台，最快）— 带快速 libpcap 预检
          2. AF_PACKET 原始套接字（Linux，无需 libpcap）
          3. 系统 NDP 表轮询（`ip -6 neighbor show`，最终兜底）
        
        持续监听 NA/NS/RA/Redirect 报文，实时检测投毒。
        同时学习合法 RA 源 MAC（替代 max_ra_routers 硬阈值）。
        检测 RA 参数欺骗（4.2.7）：CurHopLimit != 255、M/O 标志异常。
        """
        # 收集本机所有 MAC 地址（用于检测本地 MAC 冒用攻击+防自伤）
        if not self._local_macs_loaded:
            self._local_macs = await NDPProtection._fetch_all_local_macs()
            self._local_macs_loaded = True

        # ==================== 路径 1: scapy 嗅探 ====================
        if self._scapy_available:
            loop = asyncio.get_event_loop()
            # 快速 libpcap 预检
            scapy_ok = True
            try:
                def _probe():
                    sniff(filter="icmp6", count=1, timeout=0.1, store=False, quiet=True)
                await loop.run_in_executor(None, _probe)
            except Exception:
                logger.warning("NDP 防护: scapy 嗅探预检失败 (libpcap 不可用)")
                scapy_ok = False

            if scapy_ok:
                def _sniff():
                    while self._ndp_running:
                        sniff(filter="icmp6",
                            stop_filter=lambda pkt: not self._ndp_running,
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
                    return
                except Exception as e:
                    logger.debug("NDP 防护: scapy sniff 退出 (%s)，尝试 AF_PACKET", e)

        # ==================== 路径 2: AF_PACKET 原始套接字（Linux） ====================
        if sys.platform != "win32":
            logger.info("NDP 防护: AF_PACKET 嗅探已启动")
            await self._ndp_sniff_af_packet()
            return

        # ==================== 路径 3: 系统 NDP 表轮询（最终兜底，Windows 默认路径） ====================
        if sys.platform == "win32":
            logger.info("NDP 防护: scapy 嗅探不可用（Windows 请安装 Npcap），"
                        "回退到系统 NDP 表轮询。"
                        "如需实时抓包，请安装 Npcap (https://npcap.com/)")
        else:
            logger.info("NDP 防护: scapy 和 AF_PACKET 均不可用，回退到 NDP 表轮询")
        await self._poll_ndp_table()

    async def _ndp_sniff_af_packet(self):
        """
        AF_PACKET 原始套接字 NDP 嗅探（Linux 无 libpcap 时兜底）。
        解析原始以太网帧，提取 ICMPv6 NA/NS/RA/Redirect 报文并检测。
        """
        ETH_P_IPV6 = 0x86DD
        ICMPV6_TYPE_NA = 136
        ICMPV6_TYPE_NS = 135
        ICMPV6_TYPE_RA = 134
        ICMPV6_TYPE_REDIRECT = 137

        ndp_sock = None
        try:
            ndp_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                      socket.htons(ETH_P_IPV6))
            ndp_sock.bind((self.interface_name or "", 0))
            ndp_sock.setblocking(True)
        except Exception as e:
            logger.warning("NDP 防护: 无法创建 AF_PACKET IPv6 套接字 (%s)", e)
            return

        loop = asyncio.get_event_loop()
        while self._ndp_running:
            try:
                frame = await loop.sock_recv(ndp_sock, 65535)
            except (asyncio.CancelledError, OSError):
                break
            except Exception:
                continue

            if len(frame) < 54:  # 14(eth) + 40(ipv6) + 4(icmpv6 header minimum)
                continue

            # 提取 src_mac（以太网头字节 6-11）
            raw_src_mac = ':'.join(f'{b:02x}' for b in frame[6:12]).upper()
            # IPv6 next header 在字节 20 的帧偏移 = 14+6=20
            # 实际上 IPv6 header 从字节 14 开始，next header 在偏移 14+6=20
            next_header = frame[20]  # 第 21 字节（0-based）
            if next_header != 58:  # 58 = ICMPv6
                continue

            # ICMPv6 type 在字节 54（14+40）
            icmp6_type = frame[54]

            # IPv6 src IP 在字节 22-37（IPv6 header 内偏移 8-23）
            src_ip = socket.inet_ntop(socket.AF_INET6, frame[22:38])

            # ========== 检测逻辑 ==========
            if icmp6_type == ICMPV6_TYPE_NA:
                # NA: target address 在 ICMPv6 payload 字节 8-23（帧偏移 54+8=62）
                if len(frame) >= 78:
                    na_target = socket.inet_ntop(socket.AF_INET6, frame[62:78])
                    await self._check_ndp_raw_na(raw_src_mac, src_ip, na_target)
            elif icmp6_type == ICMPV6_TYPE_NS:
                if len(frame) >= 78:
                    ns_target = socket.inet_ntop(socket.AF_INET6, frame[62:78])
                    await self._check_ndp_raw_ns(raw_src_mac, src_ip, ns_target)
            elif icmp6_type == ICMPV6_TYPE_RA:
                # RA: CurHopLimit = IPv6 header byte 7 (hop limit)
                hop_limit = frame[21]  # IPv6 header 偏移 7
                await self._check_ndp_raw_ra(raw_src_mac, src_ip, hop_limit)
            elif icmp6_type == ICMPV6_TYPE_REDIRECT:
                await self._check_ndp_raw_redirect(raw_src_mac, src_ip)

        try:
            ndp_sock.close()
        except Exception:
            pass

    async def _check_ndp_raw_na(self, src_mac: str, src_ip: str, na_target: str):
        """AF_PACKET NA 检测：检查网关 MAC 是否被篡改（T1）"""
        if not self._enabled:
            return
        all_gw_ips = {ip for ip, _, _ in self.gateway_pairs if ip}
        if src_ip not in all_gw_ips:
            return
        # 检查从网关 IP 发来的 NA 的 MAC 是否匹配预期
        expected_mac = None
        for ip, mac, _ in self.gateway_pairs:
            if ip == src_ip and mac:
                expected_mac = self._mac_normalize(mac)
                break
        if expected_mac and self._mac_normalize(src_mac) != expected_mac:
            logger.warning("NDP 防护 [T1/AF_PACKET]: NA 投毒! %s 声称 MAC=%s, 预期 %s",
                           src_ip, src_mac, expected_mac)
            self._poison_detected.set()

    async def _check_ndp_raw_ns(self, src_mac: str, src_ip: str, ns_target: str):
        """AF_PACKET NS 检测：DAD 检测（T4）+ NUD 追踪（T5）"""
        if not self._enabled:
            return
        # T4: DAD — src_ip == "::" 表示重复地址检测
        if src_ip == "::":
            addr_key = ns_target
            now = time.time()
            # 清理过期记录
            self._nud_tracker = {
                t: [ts for ts in times if now - ts < self._nud_window]
                for t, times in self._nud_tracker.items()
            }
            if addr_key not in self._nud_tracker:
                self._nud_tracker[addr_key] = []
            self._nud_tracker[addr_key].append(now)
            if len(self._nud_tracker[addr_key]) >= 3:
                logger.warning("NDP 防护 [T4/AF_PACKET]: DAD 攻击! %s 被重复检测 ≥3 次", addr_key)
                self._nud_tracker[addr_key] = []

    async def _check_ndp_raw_ra(self, src_mac: str, src_ip: str, hop_limit: int):
        """AF_PACKET RA 检测：未知 RA 源（T3）+ CurHopLimit 异常"""
        if not self._enabled:
            return
        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        known_baseline_macs = set(self._baseline_mac_per_gw.values())
        all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources

        if src_mac in all_trusted:
            return

        if src_mac in self._suspicious_ra_sources:
            return

        # CurHopLimit 异常检测
        if hop_limit < 255:
            logger.warning("NDP 防护 [4.2.7/AF_PACKET]: CurHopLimit=%d (异常) RA 源 %s (%s)",
                           hop_limit, src_ip, src_mac)
            self._suspicious_ra_sources.add(src_mac)
            self._threat_events.append({
                "type": "ra_param_spoof", "time": time.time(),
                "src_mac": src_mac, "src_ip": src_ip,
                "detail": f"CurHopLimit={hop_limit} (expected >=255)",
            })
            self._trim_threat_events()
            return

        # 未知 RA 源
        logger.warning("NDP 嗅探 [T3/AF_PACKET]: 未知 RA 源! %s (%s)", src_ip, src_mac)
        self._suspicious_ra_sources.add(src_mac)
        self._threat_events.append({
            "type": "rogue_ra", "time": time.time(),
            "src_mac": src_mac, "src_ip": src_ip,
        })
        self._trim_threat_events()

    async def _check_ndp_raw_redirect(self, src_mac: str, src_ip: str):
        """AF_PACKET Redirect 检测（T6）：非信任源 Redirect"""
        if not self._enabled:
            return
        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        if known_gw_macs and src_mac not in known_gw_macs:
            logger.warning("NDP 防护 [T6/AF_PACKET]: 非信任 Redirect! %s (%s)", src_ip, src_mac)
            self._threat_events.append({
                "type": "rogue_redirect", "time": time.time(),
                "src_mac": src_mac, "src_ip": src_ip,
            })
            self._trim_threat_events()

    async def _poll_ndp_table(self):
        """
        系统 NDP 表轮询（最终兜底）：定期执行 `ip -6 neighbor show` 检测网关 MAC 变更。
        """
        logger.info("NDP 防护: NDP 表轮询已启动 (间隔=5s)")
        while self._ndp_running:
            try:
                # T1: 检查所有网关的 NDP 表项
                for gw_ip, expected_mac, _ in self.gateway_pairs:
                    if not gw_ip:
                        continue
                    actual_mac = await self._resolve_mac_single(gw_ip)
                    if expected_mac and actual_mac:
                        if self._mac_normalize(actual_mac) != self._mac_normalize(expected_mac):
                            logger.warning("NDP 防护 [T1/轮询]: 网关 %s MAC 变更! %s -> %s",
                                           gw_ip, expected_mac, actual_mac)
                            self._poison_detected.set()
            except Exception as e:
                logger.debug("NDP 防护: NDP 表轮询异常: %s", e)
            await asyncio.sleep(5)

    def _on_ndp_packet(self, pkt):
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return
        src_mac = self._mac_normalize(pkt[Ether].src)
        src_ip = str(pkt[IPv6].src)
        all_gw_ips = {ip for ip, _, _ in self.gateway_pairs if ip}
        all_local_ips = set(self.all_local_ipv6)

        # ==================== RA 处理 ====================
        if pkt.haslayer(ICMPv6ND_RA):
            ra = pkt[ICMPv6ND_RA]

            # --- 4.2.7 参数欺骗检测 ---
            hop_limit = pkt[IPv6].hlim
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
                    self._trim_threat_events()
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
                        self._trim_threat_events()
                        self._suspicious_ra_sources.add(src_mac)

                # --- RA 源自动学习（替代 max_ra_routers）---
                # 从手动配置的网关 MAC 或已确认的接口网关 MAC 发来的 RA = 信任
                known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
                known_baseline_macs = set(self._baseline_mac_per_gw.values())
                all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources

                if src_mac not in all_trusted and src_mac not in self._suspicious_ra_sources:
                    # 新 RA 源但不属于信任/可疑列表 → 检查是否在手动网关列表中
                    is_known = any(
                        src_ip == gw or self._mac_normalize(src_mac) == self._mac_normalize(m)
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
                        self._trim_threat_events()

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
                self._trim_threat_events()
                self._nud_tracker[ns_target] = []

        # ==================== 基线学习 ====================
        if not self._baseline_learned and (pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_NS)):
            for gw_ip in all_gw_ips:
                if src_ip == gw_ip:
                    if not NDPProtection._is_valid_mac(src_mac):
                        logger.warning("NDP 防护: 基线学习忽略非法 MAC %s（来源 IP %s）", src_mac, src_ip)
                        if gw_ip in self._baseline_proposed:
                            del self._baseline_proposed[gw_ip]
                        break
                    if gw_ip not in self._baseline_proposed:
                        self._baseline_proposed[gw_ip] = src_mac
                        self._baseline_proposed_time[gw_ip] = time.time()
                    elif self._baseline_proposed[gw_ip] == src_mac:
                        elapsed = time.time() - self._baseline_proposed_time.get(gw_ip, 0)
                        if elapsed > self._baseline_learn_time:
                            self._baseline_mac_per_gw[gw_ip] = src_mac
                            self._baseline_learned = True
                            logger.info("NDP 防护: 基线学习完成 [%s] -> MAC=%s", gw_ip, src_mac)
                            # 更新网关 MAC 为基线 MAC，用于 Static NDP 绑定
                            for _iface in self.interfaces:
                                _iface.gateways = [
                                    (_gw, self._baseline_mac_per_gw.get(_gw, _mac), _vlan)
                                    for _gw, _mac, _vlan in _iface.gateways
                                ]
                            asyncio.get_event_loop().create_task(self.protect_ndp_entry())
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
                if baseline and (src_ip == gw_ip or na_target == gw_ip) and self._mac_normalize(src_mac) != self._mac_normalize(baseline):
                    self._threat_events.append({
                        "type": "na_poison", "time": time.time(),
                        "gateway": gw_ip, "expected_mac": baseline, "actual_mac": src_mac,
                    })
                    self._trim_threat_events()
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
                        self._loop.call_soon_threadsafe(
                            lambda: asyncio.create_task(self._on_poison_detected(attacker_mac=src_mac, attacker_ip=src_ip)))
                    break

        # ==================== IP 冲突 ====================
        for local_ip in all_local_ips:
            if local_ip and (src_ip == local_ip or (
                pkt.haslayer(ICMPv6ND_NA) and str(pkt[ICMPv6ND_NA].tgt) == local_ip
            )) and self._mac_normalize(src_mac) != self._mac_normalize(self.local_mac):
                self._threat_events.append({
                    "type": "ip_conflict", "time": time.time(),
                    "ip": local_ip, "attacker_mac": src_mac,
                })
                self._trim_threat_events()
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
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self._on_poison_detected(attacker_mac=src_mac, attacker_ip=src_ip)))
                break

        # ==================== 本地 MAC 冒用攻击 ====================
        if self._local_macs and any(self._mac_normalize(src_mac) == self._mac_normalize(m) for m in self._local_macs)                 and src_ip not in all_local_ips and src_mac != "000000000000":
            self._threat_events.append({
                "type": "local_mac_spoof", "time": time.time(),
                "attacker_mac": src_mac, "src_ip": src_ip,
            })
            self._trim_threat_events()
            logger.warning("NDP 嗅探: 本地 MAC 冒用攻击！攻击者冒用本机 MAC %s 以 %s 身份发送 NDP", src_mac, src_ip)
            _now_lm = time.time()
            _stats_lm = self._ndp_attack_stats.get(src_mac, {})
            _rate_lm = _stats_lm.get("count", 0)
            if _rate_lm > 200:
                _debounce_lm = 0.0
            elif _rate_lm > 100:
                _debounce_lm = 0.1
            elif _rate_lm > 50:
                _debounce_lm = 0.3
            elif _rate_lm > 10:
                _debounce_lm = 1.0
            else:
                _debounce_lm = 3.0
            _last_time_lm = _stats_lm.get("last_attack", 0)
            if _now_lm - _last_time_lm >= _debounce_lm:
                self._poison_detected.set()
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self._on_poison_detected(attacker_mac=src_mac, attacker_ip=src_ip)))

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
        if not self._scapy_available or sys.platform == "win32":
            # 无 scapy 时 DHCPv6 嗅探不可用，仅消费事件信号避免队列积压
            while self._ndp_running:
                try:
                    await asyncio.wait_for(self._run_dhcpv6_check.wait(), timeout=30)
                    self._run_dhcpv6_check.clear()
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
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
                    return sniff(filter="udp and (port 546 or port 547)", count=20, timeout=3.0,
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
        if not self.interfaces:
            return None
        # 尝试 scapy 路径（有 libpcap 时）
        if self._scapy_available:
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
                    na_pkts = sniff(filter="icmp6", count=5, timeout=timeout,
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
                logger.debug("NDP 防护 [T2]: scapy NS 探测异常: %s", e)
            if result:
                return result[0]

        # scapy 不可用或失败：使用 AF_PACKET 原始套接字（Linux）
        if sys.platform != "win32":
            try:
                return await self._probe_gateway_ns_af_packet(gw_ip, timeout)
            except Exception as e:
                logger.debug("NDP 防护 [T2]: AF_PACKET NS 探测异常: %s", e)
        return None

    async def _probe_gateway_ns_af_packet(self, gw_ip: str, timeout: float = 2.0) -> Optional[str]:
        """使用 AF_PACKET 发送 NS 并监听 NA 回复（Linux 无 libpcap 时兜底）"""
        ETH_P_IPV6 = 0x86DD
        ICMPV6_TYPE_NA = 136

        # 找到第一个可用的接口
        iface = None
        for i in self.interfaces:
            if i.ipv6_ll and i.mac:
                iface = i
                break
        if not iface:
            return None

        local_ll = iface.ipv6_ll
        local_mac = iface.mac

        try:
            # 计算 NS 组播目标 MAC: 33:33:ff:xx:xx:xx where xx:xx:xx is last 3 bytes of target
            gw_bytes = socket.inet_pton(socket.AF_INET6, gw_ip)
            ns_dst_mac = bytes([0x33, 0x33, 0xff, gw_bytes[13], gw_bytes[14], gw_bytes[15]])
            s_mac = bytes.fromhex(local_mac.replace("-", "").replace(":", ""))
            d_mac = ns_dst_mac

            # 构造 NS 报文
            # ICMPv6 NS: type=135, code=0
            ns_payload = struct.pack('!BBH', 135, 0, 0)  # type, code, checksum(0)
            ns_payload += struct.pack('!I', 0)            # reserved
            ns_payload += socket.inet_pton(socket.AF_INET6, gw_ip)  # target

            # ICMPv6 Option: Src LLAddr (type=1, len=1, 6 bytes MAC)
            ns_payload += struct.pack('!BB', 1, 1) + s_mac

            # IPv6 头
            ipv6_src = socket.inet_pton(socket.AF_INET6, local_ll.split('%')[0])
            ipv6_dst = socket.inet_pton(socket.AF_INET6, gw_ip)
            payload_len = len(ns_payload)
            ipv6_header = struct.pack('!IHBB', 0x60000000, payload_len, 58, 255)
            ipv6_header += ipv6_src + ipv6_dst

            # 计算 ICMPv6 checksum
            pseudo = ipv6_src + ipv6_dst
            pseudo += struct.pack('!I', payload_len)
            pseudo += b'\x00\x00\x00\x00' + struct.pack('!B', 58)
            cksum_data = pseudo + ns_payload
            if len(cksum_data) % 2:
                cksum_data += b'\x00'
            total = 0
            for i in range(0, len(cksum_data), 2):
                total += (cksum_data[i] << 8) + cksum_data[i+1]
            while total >> 16:
                total = (total & 0xFFFF) + (total >> 16)
            ns_checksum = ~total & 0xFFFF
            # 填入 checksum (在 payload 偏移 2 处)
            ns_payload_list = bytearray(ns_payload)
            struct.pack_into('!H', ns_payload_list, 2, ns_checksum)
            ns_payload = bytes(ns_payload_list)

            # 完整帧
            frame = d_mac + s_mac
            frame += struct.pack('!H', ETH_P_IPV6)
            frame += ipv6_header + ns_payload

            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(ETH_P_IPV6)) as s:
                s.bind((iface.name, 0))
                s.send(frame)

                # 监听 NA 回复（timeout 内）
                s.setblocking(True)
                s.settimeout(timeout)
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        resp = s.recv(65535)
                    except socket.timeout:
                        break
                    except Exception:
                        continue
                    if len(resp) < 54:
                        continue
                    # 检查以太网类型
                    if len(resp) < 14:
                        continue
                    # 检查是否为 ICMPv6 NA (type=136)
                    if resp[20] != 58:  # next header != ICMPv6
                        continue
                    if resp[54] != ICMPV6_TYPE_NA:
                        continue
                    # 提取 src_mac
                    na_src_mac = ':'.join(f'{b:02x}' for b in resp[6:12]).upper()
                    # 提取 NA target 在偏移 62-77
                    if len(resp) >= 78:
                        na_target = socket.inet_ntop(socket.AF_INET6, resp[62:78])
                        if na_target == gw_ip:
                            # 提取 Dst LLAddr option
                            # option 在 ICMPv6 头后: 偏移 54+4+4=62 (type=2, len=1)
                            opt_offset = 54 + 8  # ICMPv6 头 + reserved/target
                            while opt_offset + 2 <= len(resp):
                                opt_type = resp[opt_offset]
                                opt_len = resp[opt_offset + 1]
                                if opt_type == 2 and opt_len == 1 and opt_offset + 8 <= len(resp):
                                    return ':'.join(f'{b:02x}' for b in resp[opt_offset+2:opt_offset+8]).upper()
                                if opt_len == 0:
                                    break
                                opt_offset += opt_len * 8
                            return na_src_mac
        except Exception as e:
            logger.debug("NDP 防护 [T2]: AF_PACKET 探测异常: %s", e)
        return None

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


        # 立即用已探测的 MAC 做静态 NDP 绑定（后续基线学习完成后再覆盖）
        if self.interfaces:
            for iface in self.interfaces:
                for _, gw_mac, _ in iface.gateways:
                    if gw_mac:
                        await self.protect_ndp_entry()
                        break
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
                    logger.warning("NDP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在或命令不被支持）", vlan_iface, proc.returncode)
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
                    logger.warning("NDP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在或命令不被支持）", vlan_iface, proc.returncode)
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
        raw_sections = re.split(
                r'(?=^(?:以太网适配器 |Ethernet adapter |无线局域网适配器 |Wireless LAN adapter |WLAN 适配器 |WLAN adapter |本地连接|Local Area Connection))',
                text, flags=re.MULTILINE
            )
        if raw_sections and not raw_sections[0].strip():
            raw_sections = raw_sections[1:]
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
                # 如果 ipconfig 未解析到 MAC，用 getmac 命令兜底
                if not iface.mac and iface.name:
                    try:
                        proc2 = await asyncio.create_subprocess_exec(
                            "getmac", "/FO", "CSV", "/NH",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        out2, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
                        for line2 in self._decode_win_output(out2).splitlines():
                            line2 = line2.strip().strip('"')
                            parts = line2.split('","')
                            if len(parts) >= 2:
                                mac2 = parts[1].strip()
                                if mac2 and len(mac2.replace("-", "")) == 12:
                                    iface.mac = mac2.replace("-", ":").upper()
                                    break
                    except Exception:
                        pass
            if iface.ipv6_ll or iface.ipv6_global:
                for gw, idx in default_routes:
                    if not any(g == gw for g, _, _ in iface.gateways):
                        iface.gateways.append((gw, "", ""))
                # 解析接口索引，供 sendp 使用数字索引替代中文接口名
                iface.idx = await self._resolve_iface_idx(iface.name)
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
            if expected and actual and self._mac_normalize(actual) != self._mac_normalize(expected):
                poisoned.append(("手动", ip, expected, actual))
            if not expected and self._baseline_gateway_mac and actual:
                if self._mac_normalize(actual) != self._mac_normalize(self._baseline_gateway_mac):
                    poisoned.append(("手动-基线", ip, self._baseline_gateway_mac, actual))
        for iface in self.interfaces:
            for gw_ip, expected, _ in iface.gateways:
                if not gw_ip or not expected:
                    continue
                actual = await self._resolve_mac_single(gw_ip)
                if actual and self._mac_normalize(actual) != self._mac_normalize(expected):
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
            return sniff(filter="icmp6", count=200, timeout=4.0,
                         lfilter=lambda p: p.haslayer(Ether) and p.haslayer(IPv6) and (
                             p.haslayer(ICMPv6ND_NA) or p.haslayer(ICMPv6ND_NS) or
                             p.haslayer(ICMPv6ND_RA) or p.haslayer(ICMPv6Error)),
                         quiet=True)
        try:
            pkts = await loop.run_in_executor(None, _capture)
        except Exception as e:
            logger.debug("NDP 防护: sniff 失败: %s", e)
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        ra_sources = {}
        ns_targets = defaultdict(int)
        dad_targets = defaultdict(int)
        redirect_sources = []
        suspicious_ns = []

        for pkt in pkts:
            src_mac = self._mac_normalize(pkt[Ether].src)
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
            result = await self._send_na_scapy_all(target)
            if result:
                return True
            # scapy NA 失败（如无 libpcap 导致 sendp 不可用），回退系统方法
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

        # 防自伤检测：如果 attacker_mac 属于本机接口的 MAC，跳过定向反制
        # （攻击者冒用本机 MAC 陷害本地程序，定向反制会伤及自身）
        is_local_mac = attacker_mac and self._local_macs and             any(self._mac_normalize(attacker_mac) == self._mac_normalize(m) for m in self._local_macs)
        if is_local_mac:
            logger.warning("NDP 反制: 攻击者冒用本机 MAC %s，跳过定向反制（防自伤），仅用广播 NA 修复", attacker_mac)
            # 广播 NA 按攻击强度等比放大
            for iface in self.interfaces:
                local_ip = iface.ipv6_global or iface.ipv6_ll
                local_mac_real = iface.mac
                if local_ip and local_mac_real:
                    vlan_id = self._manual_gateway_vlan
                    broadcast_rounds = max(na_rounds // 2, 1)
                    try:
                        self._ndp_sender_queue.put_nowait(
                            ("ff:ff:ff:ff:ff:ff", local_ip, local_mac_real, local_ip, broadcast_rounds, inter, vlan_id)
                        )
                    except Exception:
                        pass
                    break
            # 立即尝试静态 NDP 绑定保护网关
            await self.protect_ndp_entry()
            return

        # 全零 MAC 攻击者：定向反制发给不存在的 MAC，完全无效
        if attacker_mac == "00:00:00:00:00:00":
            logger.warning("NDP 反制: 攻击者使用全零 MAC，定向反制无效，改用广播 NA 爆发 + 静态 NDP 绑定")
            # 广播 NA 爆发
            for iface in self.interfaces:
                local_ip = iface.ipv6_global or iface.ipv6_ll
                local_mac_real = iface.mac
                if local_ip and local_mac_real:
                    vlan_id = self._manual_gateway_vlan
                    try:
                        self._ndp_sender_queue.put_nowait(
                            ("ff:ff:ff:ff:ff:ff", local_ip, local_mac_real, local_ip, max(na_rounds * 3, 15), 0.01, vlan_id)
                        )
                    except Exception:
                        pass
                    break
            # 静态 NDP 绑定
            await self.protect_ndp_entry()
            return

        # 定向反制：单播 NA 到攻击者网卡，毒化其邻居缓存
        if attacker_mac and self._ndp_sender_ready:
            # 收集本机 IPv6 和 MAC 信息
            for iface in self.interfaces:
                local_ip = iface.ipv6_global or iface.ipv6_ll
                local_mac_real = iface.mac
                if local_ip and local_mac_real:
                    # 网关 IPv6 -> 随机不可达 MAC 毒化包（打残攻击者）
                    poison_mac = self._generate_poison_mac()
                    vlan_id = self._manual_gateway_vlan
                    try:
                        self._ndp_sender_queue.put_nowait(
                            (attacker_mac, local_ip, poison_mac, attacker_ip or self.gateway_ipv6 or local_ip, na_rounds, inter, vlan_id)
                        )
                    except Exception:
                        pass
                    # 正确 NA 广播按攻击强度等比放大（定向反制保持原量）
                    try:
                        self._ndp_sender_queue.put_nowait(
                            ("ff:ff:ff:ff:ff:ff", local_ip, local_mac_real, local_ip, max(na_rounds // 2, 1), inter, vlan_id)
                        )
                    except Exception:
                        pass

                    # 攻击者冒充网关 IPv6 时，额外宣告真实网关的 IPv6-MAC 绑定
                    # 这样网络上其他设备不会因为 NDP 投毒而错误地学到网关 IPv6 在攻击者 MAC
                    all_gw_ips = {ip for ip, _, _ in self.gateway_pairs if ip}
                    gw_ipv6 = self.gateway_ipv6
                    gw_mac = self.gateway_mac
                    if (attacker_ip in all_gw_ips or (gw_ipv6 and attacker_ip == gw_ipv6)) and gw_mac and gw_ipv6:
                        try:
                            self._ndp_sender_queue.put_nowait(
                                ("ff:ff:ff:ff:ff:ff", gw_ipv6, gw_mac, gw_ipv6, max(na_rounds // 3, 1), inter, vlan_id)
                            )
                        except Exception:
                            pass
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

    async def _send_na_af_packet(self, dst_mac: str, local_ip: str, local_mac: str,
                                  target_ip: str, count: int = 1,
                                  inter: float = 0.0, vlan_id: str = ""):
        """
        使用 AF_PACKET 原始套接字发送 Unsolicited NA 报文（Linux 无 libpcap 时替代 sendp）。
        构造：Ethernet / IPv6 / ICMPv6 NA / ICMPv6OptDstLLAddr
        """
        if sys.platform == "win32":
            return
        try:
            ETH_P_IPV6 = 0x86DD
            d_mac = bytes.fromhex(dst_mac.replace("-", "").replace(":", ""))
            s_mac = bytes.fromhex(local_mac.replace("-", "").replace(":", ""))
            dst_ip = target_ip if dst_mac != "ff:ff:ff:ff:ff:ff" else "ff02::1"

            # IPv6 头
            ipv6_src = socket.inet_pton(socket.AF_INET6, local_ip)
            ipv6_dst = socket.inet_pton(socket.AF_INET6, dst_ip)

            # ICMPv6 NA: type=136, code=0, R=0, S=0, O=1
            # flags: R(bit 7)=0, S(bit 6)=0, O(bit 5)=1 → 0x20
            na_payload = struct.pack('!BBH', 136, 0, 0)  # type, code, checksum(0)
            na_payload += struct.pack('!I', 0x20000000)   # RSO flags + reserved
            na_payload += socket.inet_pton(socket.AF_INET6, target_ip)  # target

            # ICMPv6 Option: Dst LLAddr (type=2, len=1, 6 bytes MAC)
            na_payload += struct.pack('!BB', 2, 1) + s_mac

            # IPv6 头 (40 bytes)
            payload_len = len(na_payload)
            ipv6_header = struct.pack('!IHBB', 0x60000000, payload_len, 58, 255)  # next=58(ICMPv6), hlim=255
            ipv6_header += ipv6_src + ipv6_dst

            frame = d_mac + s_mac
            if vlan_id and not self._vxlan_enabled:
                frame += struct.pack('!HH', 0x8100, int(vlan_id) & 0xFFF)
            frame += struct.pack('!H', ETH_P_IPV6)
            frame += ipv6_header + na_payload

            # 计算 ICMPv6 checksum
            pseudo_header = ipv6_src + ipv6_dst
            pseudo_header += struct.pack('!I', payload_len)
            pseudo_header += b'\x00\x00\x00\x00'  # next header 的零填充
            pseudo_header += struct.pack('!B', 58)  # next header = ICMPv6
            checksum_data = pseudo_header + na_payload
            if len(checksum_data) % 2:
                checksum_data += b'\x00'
            checksum = self._checksum(checksum_data)

            # 更新 checksum 在帧中的位置
            # ICMPv6 checksum 在帧中偏移: 14(eth) + 40(ipv6) + 2(icmpv6 type+code)
            csum_offset = len(frame) - len(na_payload) + 2
            struct.pack_into('!H', frame, csum_offset, checksum)

            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(ETH_P_IPV6)) as s:
                s.bind((self.interface_name or "", 0))
                for _ in range(count):
                    s.send(frame)
                    if inter > 0:
                        await asyncio.sleep(inter)
        except Exception as e:
            logger.debug("NDP 防护: AF_PACKET NA 发送失败 (%s)", e)

    @staticmethod
    def _checksum(data: bytes) -> int:
        """计算 Internet Checksum (RFC 1071)"""
        if len(data) % 2:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i+1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF

    async def _ndp_sender_worker_loop(self):
        """常驻 NDP 发送器：一次性导入 scapy，从队列取任务发送，进程冻结"""
        if not self._scapy_available:
            self._ndp_sender_ready = False
            # 不冻结，允许后续收到信号时检查是否有替代发送方式（AF_PACKET）
            while self._ndp_running:
                try:
                    task = await asyncio.wait_for(self._ndp_sender_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
                if task is None:
                    break
                # scapy 不可用时尝试 AF_PACKET 发送
                if sys.platform != "win32":
                    dst_mac, local_ip, local_mac, target_ip, count, inter, vlan_id = task
                    await self._send_na_af_packet(
                        dst_mac=dst_mac, local_ip=local_ip, local_mac=local_mac,
                        target_ip=target_ip, count=count, inter=inter, vlan_id=vlan_id,
                    )
            return
        try:
            from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
        except Exception as e:
            logger.debug("NDP 防护: NDP 发送器初始化失败 (%s)", e)
            self._ndp_sender_ready = False
            await asyncio.Event().wait()
            return

        # === 快速 sendp 预检 ===
        sendp_ok = True
        if sys.platform != "win32":
            try:
                test_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IPv6(src="::1", dst="ff02::1", hlim=255) / ICMPv6ND_NA()
                sendp(test_pkt, iface=self.interface_name or "lo", verbose=False, count=1, inter=0)
            except Exception:
                logger.debug("NDP 防护: sendp 预检失败 (Linux 无 libpcap)，使用 AF_PACKET 兜底")
                sendp_ok = False

        self._ndp_sender_ready = sendp_ok
        logger.debug("NDP 防护: NDP 发送器已就绪 (sendp=%s)", sendp_ok)
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
                # scapy sendp 尝试
                if sendp_ok:
                    try:
                        eth = Ether(dst=dst_mac, src=local_mac)
                        na = ICMPv6ND_NA(R=1, S=0, O=1, tgt=target_ip)
                        lla = ICMPv6NDOptDstLLAddr(lladdr=local_mac)
                        ipv6 = IPv6(src=local_ip, dst=target_ip if dst_mac != "ff:ff:ff:ff:ff:ff" else "ff02::1", hlim=255)
                        pkt = eth / ipv6 / na / lla
                        if vlan_id and not self._vxlan_enabled:
                            try:
                                pkt = Ether(dst=dst_mac, src=local_mac) / Dot1Q(vlan=int(vlan_id)) / ipv6 / na / lla
                            except Exception:
                                pass
                        elif vlan_id and self._vxlan_enabled:
                            try:
                                inner_pkt = eth / ipv6 / na / lla
                                pkt = (Ether(dst=dst_mac, src=local_mac)
                                       / scapy_module.IPv6(src=local_ip, dst=target_ip, hlim=64)
                                       / scapy_module.UDP(sport=4789, dport=4789)
                                       / scapy_module.VXLAN(vni=int(vlan_id))
                                       / inner_pkt)
                            except Exception:
                                pass
                        for _ in range(count):
                            sendp(pkt, iface=self.interface_name or "", verbose=False)
                            if inter > 0:
                                await asyncio.sleep(inter)
                        log_target = f"定向 {dst_mac}" if dst_mac != "ff:ff:ff:ff:ff:ff" else "广播"
                        logger.warning("NDP 反制: 定向 NA %s %s(%s) -> %s x%d", log_target, target_ip, dst_mac, local_mac, count)
                        continue
                    except Exception:
                        logger.debug("NDP 防护: sendp 运行失败，回退 AF_PACKET 发送")
                # AF_PACKET 兜底（Linux）
                if sys.platform != "win32":
                    await self._send_na_af_packet(
                        dst_mac=dst_mac, local_ip=local_ip, local_mac=local_mac,
                        target_ip=target_ip, count=count, inter=inter, vlan_id=vlan_id,
                    )
                    log_target = f"定向 {dst_mac}" if dst_mac != "ff:ff:ff:ff:ff:ff" else "广播"
                    logger.warning("NDP 反制: 定向 NA (AF_PACKET) %s %s(%s) -> %s x%d",
                                   log_target, target_ip, dst_mac, local_mac, count)
                else:
                    logger.debug("NDP 防护: 当前平台无可用 NDP 发送方式")
            except Exception as e:
                logger.debug("NDP 防护: NDP 发送失败 (%s)", e)

    async def _send_na_scapy_all(self, target: str) -> bool:
        if not self._scapy_available:
            return False

        # 运行时 sendp 预检：Windows 无 Npcap 时 scapy 导入成功但发送失败
        if not self._scapy_sendp_ok and sys.platform == "win32":
            logger.info("NDP 防护: scapy sendp 不可用（需安装 Npcap），走系统 fallback 发送")
            return False

        loop = asyncio.get_event_loop()
        sent = 0

        def _send_one(iface: InterfaceInfo):
            local_ip = iface.ipv6_global or iface.ipv6_ll
            # 清理 IPv6 地址
            if local_ip:
                local_ip = local_ip.strip().split("%")[0]
            # iface.mac 可能为空，用 _local_macs 兜底
            iface_mac = iface.mac
            if not iface_mac and self._local_macs:
                iface_mac = next(iter(self._local_macs), "")
            if not iface_mac:
                try:
                    import uuid
                    node = uuid.getnode()
                    if node is not None and node != 0 and not (node & 0x010000000000):
                        iface_mac = ':'.join(f'{(node >> (5-i)*8) & 0xFF:02x}' for i in range(6)).upper()
                except Exception:
                    pass
            if not local_ip or not iface_mac:
                logger.warning("NDP 防护: 接口 %s 无 MAC (mac=%s, local_macs=%s)，跳过 NA 发送",
                               iface.name, iface.mac, self._local_macs)
                return 0
            try:
                # 预验证 IPv6 地址
                import socket
                socket.inet_pton(socket.AF_INET6, local_ip)
                import scapy.all
                Ether = scapy.all.Ether
                IPv6 = scapy.all.IPv6
                ICMPv6ND_NA = scapy.all.ICMPv6ND_NA
                ICMPv6NDOptDstLLAddr = scapy.all.ICMPv6NDOptDstLLAddr
                sendp = scapy.all.sendp
                dst_ip = "ff02::1" if target == "ff02::1" else target.strip().split("%")[0] if "%" in target else target.strip()
                eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=iface_mac)
                na = ICMPv6ND_NA(R=1, S=0, O=1, tgt=local_ip)
                lla = ICMPv6NDOptDstLLAddr(lladdr=iface_mac)
                ipv6 = IPv6(src=local_ip, dst=dst_ip, hlim=255)
                pkt = eth / ipv6 / na / lla
                iface_arg = iface.idx if iface.idx > 0 else iface.name
                logger.info("NDP 防护: NA 发送中 接口=%s idx=%s IP=%s MAC=%s", iface.name, iface_arg, local_ip, iface_mac)
                for _ in range(5):
                    sendp(pkt, iface=iface_arg, verbose=False)
                    time.sleep(0.02)
                return 5
            except Exception as e:
                self._scapy_sendp_ok = False
                logger.warning("NDP 防护: 接口 %s NA sendp 失败: %s (idx=%s)", iface.name, e, iface.idx)
                return 0

        try:
            for iface in self.interfaces:
                if iface.ipv6_global or iface.ipv6_ll:
                    sent += await loop.run_in_executor(None, _send_one, iface)
            if sent > 0:
                logger.info("NDP 防护: NA x%d 已在 %d 个接口发送", sent,
                            sum(1 for i in self.interfaces if i.ipv6_global or i.ipv6_ll))
            else:
                logger.info("NDP 防护: scapy NA 发送不可用（需安装 Npcap），"
                            "走系统 fallback 发送")
            return sent > 0
        except Exception as e:
            logger.warning("NDP 防护: scapy NA 失败: %s", e)
            return False

    async def _send_na_system_all(self) -> bool:
        if not self.gateway_ipv6:
            return False
        success = False
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-6", "-n", "10", "-w", str(int(self._ping_interval * 1000)),
                    self.gateway_ipv6,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-6", "-c", "10", "-W", str(max(1, int(self._ping_interval))),
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

    async def _resolve_iface_idx(self, iface_name: str) -> int:
        """\u901a\u8fc7 netsh interface ipv6 show interfaces \u83b7\u53d6\u7f51\u53e3\u7d22\u5f15\uff0c\u7f13\u5b58\u81ea _iface_name_to_idx"""
        if iface_name in self._iface_name_to_idx:
            return self._iface_name_to_idx[iface_name]
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv6", "show", "interfaces",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = self._decode_win_output(stdout)
            for line in text.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0].isdigit():
                    idx = int(parts[0])
                    name = " ".join(parts[4:])
                    self._iface_name_to_idx[name] = idx
            return self._iface_name_to_idx.get(iface_name, 0)
        except Exception:
            return 0

    async def _protect_entry(self, iface: str, gw: str, mac: str, vlan_id: str = "") -> bool:
        if sys.platform == "win32":
            try:
                mac_fmt = mac.replace(":", "-").upper()
                # VLAN 子接口：如果 vlan_id 非空且非 vxlan，附加 .{vlan} 到接口名
                iface_name = iface or "以太网"
                if vlan_id and not self._vxlan_enabled:
                    iface_name = f"{iface_name}.{vlan_id}"
                # 尝试用接口索引优先（避免 name= 编码问题）
                iface_idx = await self._resolve_iface_idx(iface_name)
                if iface_idx > 0:
                    proc = await asyncio.create_subprocess_exec(
                        "netsh", "interface", "ipv6", "set", "neighbors",
                        str(iface_idx), gw.split(chr(37))[0], mac_fmt,
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    proc = await asyncio.create_subprocess_exec(
                        "netsh", "interface", "ipv6", "set", "neighbors",
                        f"name={iface_name}", f"address={gw.split(chr(37))[0]}", f"neighbor={mac_fmt}",
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                    )
                try:
                    _, serr = await asyncio.wait_for(proc.communicate(), timeout=10)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    logger.warning("NDP 防护: 静态 NDP 绑定超时 %s -> %s", gw, mac)
                    return False
                if proc.returncode == 0:
                    iface_log = iface_name if vlan_id else iface
                    logger.info("NDP 防护: 静态 NDP %s -> %s (%s)", gw, mac, iface_log)
                    return True
                err_text = serr.decode("utf-8", errors="replace").strip() if serr else ""
                logger.warning("NDP 防护: 静态 NDP 绑定失败 %s -> %s (code=%d, err=%s)",
                              gw, mac, proc.returncode, err_text or "(无错误输出)")
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

    @staticmethod
    def _generate_poison_mac() -> str:
        """生成一个单播、locally administered 的虚假 MAC（不会与真实设备冲突）
        使用 02:xx:xx:xx:xx:xx 范围（locally administered unicast），
        比全零 MAC 更具欺骗性，能更有效毒化攻击者的 NDP 邻居缓存。
        """
        import random
        suffix = random.randint(1, 0xFFFFFF)
        return f"02:00:00:{suffix >> 16:02X}:{(suffix >> 8) & 0xFF:02X}:{suffix & 0xFF:02X}"

    def _trim_threat_events(self):
        if len(self._threat_events) > self._max_threat_events:
            self._threat_events = self._threat_events[-self._max_threat_events:]

    async def _cleanup_ra_sources(self):
        now = time.time()
        if now - self._last_ra_cleanup < self._ra_cleanup_interval:
            return
        self._last_ra_cleanup = now
        if len(self._suspicious_ra_sources) > 100:
            self._suspicious_ra_sources.clear()
            logger.debug("NDP 防护: 清理可疑 RA 源集合 (%d 条)", 100)
        if len(self._trusted_ra_sources) > 200:
            known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
            self._trusted_ra_sources.intersection_update(known_gw_macs)
            logger.debug("NDP 防护: 精简信任 RA 源集合为 %d 条", len(self._trusted_ra_sources))

    def stats(self) -> dict:
        return {
            "enabled": self._enabled,
            "interfaces": len(self.interfaces),
            "total_gateways": len(self.gateway_pairs),
            "ipv6_addresses": self.all_local_ipv6,
            "scapy_available": self._scapy_available,
            "threat_events": len(self._threat_events),
            "local_macs": list(self._local_macs),
            "last_fix_time": self._last_fix_time,
            "trusted_ra_sources": len(self._trusted_ra_sources),
            "suspicious_ra_sources": len(self._suspicious_ra_sources),
            "interface_details": [{
                "name": iface.name, "mac": iface.mac,
                "ipv6_global": iface.ipv6_global, "ipv6_globals": iface.ipv6_globals, "ipv6_ll": iface.ipv6_ll,
                "gateways": iface.gateways,
            } for iface in self.interfaces],
        }

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
    ICMPv6ND_Redirect = scapy_module.ICMPv6ND_Redirect
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
        self._ndp_flood_threshold = cfg.get("ndp_flood_threshold", 50)  # T7 泛洪阈值（条/秒）
        self._ndp_flood_suppress = False  # 泛洪抑制标志（当前仅记录状态，未接入 RA/NA 学习入口——预留）
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
        # 本机全量 IP 白名单（检测层防自伤）：全部网卡（含虚拟网卡）全部 IPv4+IPv6
        # （含运行期轮换的临时 IPv6 地址与链路本地）——本机任一 MAC 宣告本机任一 IP = 正常自包
        self._local_all_ips: set = set()           # {ip, ...}（IPv6 已剥离 %zone）
        self._local_all_ips_ts: float = 0.0        # 全量 IP 最近刷新时间戳
        self._local_ips_refreshing: bool = False   # 全量 IP 异步刷新中（防重入）
        self._local_ips_refresh_attempt: float = 0.0  # 上次刷新尝试时间戳（节流）
        self._local_refresh_interval: float = 30.0    # 刷新最小间隔（失败指数退避，上限 120s）
        # 本机 IPv6↔MAC 权威映射（多接口自包防误伤基线）：{mac_norm: set(ipv6)}
        self._local_ip_mac_map: dict = {}

        # T5 NUD 追踪
        self._nud_tracker: Dict[str, list] = {}
        self._dad_tracker: Dict[str, list] = {}   # DAD 追踪器（与 NUD 分离，防数据污染）
        self._recovery_last_trigger: Dict[str, float] = {}  # NUD 触发恢复 worker 节流（同 target ≥10s）
        self._baseline_verify_pending: bool = False  # 嗅探兜底基线异步验证防重
        self._ra_verify_pending: Dict[str, float] = {}  # RA 源异步信任验证节流（源MAC→上次验证时间，30s 重试）

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
        self._known_prefixes: set = set()           # 已知合法前缀集合（4.2.5/4.2.6 虚假前缀检测）

        # RA 源自动学习（替代 max_ra_routers 硬阈值）
        self._trusted_ra_sources: set = set()  # {MAC, ...} 已确认的合法 RA 源
        self._suspicious_ra_sources: set = set()  # {MAC, ...} 可疑源
        # ========== 可信 MAC 列表（防止误伤正常设备）==========
        self._trusted_sender_macs: set = set()      # 信任的 sender MAC（不触发反制）
        self._suspicious_zero_mac: dict = {}        # {sender_mac: [timestamp, ...]} — 全零 MAC 可疑计数

        # ========== 反制 MAC 追踪（精确防环路，与ARP侧一致）==========
        self._counterstrike_sent_macs: set = set()  # 自身反制已发送过的随机MAC集合

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
    async def _build_local_ip_mac_map() -> dict:
        """
        建立本机 IPv6↔MAC 权威映射：{normalized_mac: set(ipv6)}（多接口各自归属）。
        Windows: ipconfig /all 按适配器段解析（IPv6 地址 + 物理地址）
        Linux: ip -o link（iface→mac）+ ip -o -6 addr（iface→ipv6）对齐
        用于多接口自包防误伤（本机任一接口 MAC 宣告本机任一 IPv6 = 正常）。
        """
        ip_map: dict = {}
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "ipconfig", "/all",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                # staticmethod 内不能用 self（review blocking-3）：直接按系统编码解码
                text = stdout.decode(locale.getpreferredencoding(False), errors="replace")
                raw_sections = re.split(
                    r'(?=^(?:以太网适配器 |Ethernet adapter |无线局域网适配器 |Wireless LAN adapter |WLAN 适配器 |WLAN adapter |本地连接|Local Area Connection))',
                    text, flags=re.MULTILINE)
                if raw_sections and not raw_sections[0].strip():
                    raw_sections = raw_sections[1:]
                cur_mac = None
                for section in raw_sections:
                    lines = section.strip().splitlines()
                    if not lines:
                        continue
                    cur_mac = None
                    for line in lines:
                        s = line.strip()
                        # 仅物理地址行更新 cur_mac（避免其他行 6 组十六进制子串污染——review should-fix）
                        macm = re.search(r'((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})', s)
                        if macm and ("物理地址" in s or "Physical Address" in s or "Physical Address." in s):
                            cand = macm.group(1).replace("-", ":").upper()
                            if cand != "00:00:00:00:00:00" and cand != "FF:FF:FF:FF:FF:FF":
                                cur_mac = cand
                        if cur_mac and ("IPv6 地址" in s or "IPv6 Address" in s or "IPv6 地址." in s):
                            ipm = re.search(r'((?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+(?:%\d+)?)', s)
                            if ipm:
                                ip6 = ipm.group(1).split("%")[0]
                                if not ip6.startswith("fe80") and ":" in ip6:
                                    ip_map.setdefault(cur_mac, set()).add(ip6)
            else:
                # Linux: ip -o link → iface:mac；ip -o -6 addr → iface:ipv6
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-o", "link", "show",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                out_l, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                mac_of = {}
                for line in out_l.decode("utf-8", errors="replace").splitlines():
                    # ip -o link 输出 '2: eth0: <...>'——接口名带尾随冒号，捕获组排除冒号（review blocking-2）
                    m = re.search(r'^\d+:\s+([^:@\s]+).*link/ether\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', line)
                    if m:
                        mac_of[m.group(1)] = m.group(2).upper()
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-o", "-6", "addr", "show",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                out_a, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                for line in out_a.decode("utf-8", errors="replace").splitlines():
                    m = re.search(r'^\d+:\s+(\S+).*inet6\s+([0-9a-fA-F:]+)', line)
                    if m and m.group(1) in mac_of:
                        ip6 = m.group(2).split("%")[0]
                        if not ip6.startswith("fe80"):
                            ip_map.setdefault(mac_of[m.group(1)], set()).add(ip6)
        except Exception as e:
            logger.debug("NDP 防护: 本机 IPv6↔MAC 映射构建失败: %s", e)
        return ip_map

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
                    # 兼容列序：getmac CSV 可能是 "连接名","MAC" 或 "MAC","传输名"（用户机器无连接名列）
                    # 对每个字段做 MAC 格式校验，取第一个合法 MAC（修复 getmac 列序错位漏收集）
                    for _p in parts[:3]:
                        _m = _p.strip()
                        if _m and len(_m.replace("-", "").replace(":", "")) == 12 and \
                                re.match(r'^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$', _m):
                            _m_norm = _m.replace("-", ":").upper()
                            if _m_norm not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                                macs.add(_m_norm)
                            break
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
                # ipconfig /all 兜底：getmac/wmic 可能漏收集（未连接/禁用但配置 TCP/IP 的适配器，含虚拟网卡）
                try:
                    proc3 = await asyncio.create_subprocess_exec(
                        "ipconfig", "/all",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    out3, _ = await asyncio.wait_for(proc3.communicate(), timeout=8)
                    for line3 in NDPProtection._decode_win_output(out3).splitlines():
                        s3 = line3.strip()
                        if ("物理地址" in s3 or "Physical Address" in s3 or "Physical Address." in s3):
                            mm = re.search(r'((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})', s3)
                            if mm:
                                _cand = mm.group(1).replace("-", ":").upper()
                                if _cand not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                                    macs.add(_cand)
                except Exception:
                    pass
                # wmic 也失败时用 Python uuid.getnode() 兜底
                if not macs:
                    try:
                        import uuid
                        node = uuid.getnode()
                        # 拒绝 locally-administered（0x020000000000）与 multicast（0x010000000000）：
                        # uuid 无硬件时返回随机本地管理 MAC，会虚构本机 MAC（A4:5B... 污染根因）
                        if node is not None and node != 0 and not (node & 0x030000000000):
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
    async def _fetch_all_local_ips() -> set:
        """
        收集本机全部网络接口（含虚拟网卡）的全部 IP 地址（IPv4 + IPv6）。
        IPv6 包含全局地址、临时 IPv6 地址（隐私扩展，运行期轮换）、链路本地地址；IPv6 剥离 %zone。
        用于 NDP 检测层"本机全量 IP 白名单"：本机任一网卡 MAC 宣告本机任一 IP = 正常自包，
        避免临时 IPv6 轮换后被误判为"本地 MAC 冒用攻击"（对齐 ARP 侧 _local_ips 机制）。
        Windows: ipconfig /all 按行解析（IPv6 地址/临时 IPv6 地址/本地链接 IPv6 地址/IPv4 地址）
        Linux: ip -o -6 addr show + ip -o -4 addr show

        Returns:
            本机全部 IP 的集合（IPv6 已剥离 %zone；含 fe80 链路本地；含 IPv4）
        """
        ips: set = set()
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "ipconfig", "/all",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                text = NDPProtection._decode_win_output(stdout)
                for line in text.splitlines():
                    s = line.strip()
                    # 仅处理 IP 地址相关行（排除默认网关/租约/DUID 等，避免把网关地址误当本机 IP）
                    if not any(k in s for k in (
                            "IPv6 地址", "IPv6 Address", "IPv4 地址", "IPv4 Address",
                            "IP Address", "IP 地址")):
                        continue
                    m = re.search(r'((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+(?:%\d+)?)', s)
                    if m:
                        ip6 = m.group(1).split("%")[0]
                        if ":" in ip6 and len(ip6) > 1:
                            ips.add(ip6)
                    m4 = re.search(r'(\d+\.\d+\.\d+\.\d+)', s)
                    if m4:
                        ips.add(m4.group(1))
            else:
                for args in (("ip", "-o", "-6", "addr", "show"),
                             ("ip", "-o", "-4", "addr", "show")):
                    proc = await asyncio.create_subprocess_exec(
                        *args,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                    for line in out.decode("utf-8", errors="replace").splitlines():
                        m = re.search(r'inet6?\s+([0-9a-fA-F:.]+)/\d+', line)
                        if m:
                            ip = m.group(1).split("%")[0]
                            if ip:
                                ips.add(ip)
        except Exception as e:
            logger.debug("NDP 防护: 获取本机全量 IP 失败: %s", e)
        return ips

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
        # 启动时自动设置静态 NDP 绑定，防止启动后被投毒
        await self.protect_ndp_entry()
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
        # 本机 IPv6↔MAC 权威映射（多接口自包防误伤基线）+ 补全本机 MAC 集合
        try:
            self._local_ip_mac_map = await NDPProtection._build_local_ip_mac_map()
            # 映射 key 为冒号大写格式，直接加入集合（review blocking-1：原按 12 位切片产生垃圾）
            for mac_colon in self._local_ip_mac_map:
                if mac_colon and mac_colon != "00:00:00:00:00:00":
                    self._local_macs.add(mac_colon)
        except Exception:
            self._local_ip_mac_map = {}
        # 本机全量 IP 白名单（检测层防自伤）：全部网卡全部 IP，含运行期轮换的临时 IPv6 地址
        try:
            self._local_all_ips = await NDPProtection._fetch_all_local_ips()
        except Exception:
            self._local_all_ips = set()
        # 合并权威基线：interfaces 快照 + ipconfig /all 映射（启动时刻的临时地址）
        self._local_all_ips.update(ip.split("%")[0] for ip in self.all_local_ipv6 if ip)
        for _mac_c, _ips in (self._local_ip_mac_map or {}).items():
            self._local_all_ips.update(_ips)
        self._local_all_ips_ts = time.time()
        logger.info("NDP 防护: 嗅探启动 — 本机 IPv6 集合=%s, 本机 MAC=%s, IP↔MAC映射=%s",
                    sorted(self.all_local_ipv6) if self.all_local_ipv6 else "(空!)",
                    (self.local_mac or (",".join(sorted(self._local_macs)) if self._local_macs else "(空!)")),
                    {m: sorted(ips) for m, ips in self._local_ip_mac_map.items()} if self._local_ip_mac_map else "(空!)")
        logger.debug("NDP 防护: 本机全量 IP 白名单=%s",
                    sorted(self._local_all_ips) if self._local_all_ips else "(空!)")

        # ==================== 路径 1: scapy 嗅探（并入 ScapyBridge 单会话） ====================
        if self._scapy_available:
            from scapy_bridge import get_scapy_bridge
            bridge = get_scapy_bridge()
            bridge.set_loop(asyncio.get_event_loop())
            bridge.register_prn(self._on_ndp_packet)
            if bridge.start_if_ready():
                logger.info("NDP 防护: scapy 嗅探已并入 ScapyBridge 单会话（不再自建 Npcap 会话）")
                # 桥嗅探线程独立运行；本 worker 保持存活，桥失效时回退路径 2/3
                while self._ndp_running:
                    await asyncio.sleep(1.0)
                    if not bridge.is_active():
                        logger.warning("NDP 防护: ScapyBridge 嗅探不可用，尝试 AF_PACKET/轮询")
                        break
                else:
                    return
            else:
                logger.info("NDP 防护: ScapyBridge 不可用（Npcap 未接管物理网卡），走 fallback")

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
            ndp_sock.setblocking(False)
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

            # 审计 MEDIUM：802.1Q/802.1ad VLAN 标签（0x8100/0x88a8）时以太头 18 字节，
            # 后续所有偏移需 +4；原实现假设固定 14 字节以太头，VLAN 网络下嗅探完全失效
            vlan_off = 0
            if len(frame) >= 14 and frame[12:14] in (b"\x81\x00", b"\x88\xa8"):
                vlan_off = 4

            # 提取 src_mac（以太网头字节 6-11）
            raw_src_mac = ':'.join(f'{b:02x}' for b in frame[6:12]).upper()
            # IPv6 next header 在字节 20 的帧偏移 = 14+6=20
            # 实际上 IPv6 header 从字节 14 开始，next header 在偏移 14+6=20
            next_header = frame[20 + vlan_off]  # 第 21 字节（0-based）
            if next_header != 58:  # 58 = ICMPv6
                continue

            # ICMPv6 type 在字节 54（14+40）
            icmp6_type = frame[54 + vlan_off]

            # IPv6 src IP 在字节 22-37（IPv6 header 内偏移 8-23）
            src_ip = socket.inet_ntop(socket.AF_INET6, frame[22 + vlan_off:38 + vlan_off])

            # ========== 检测逻辑 ==========
            if icmp6_type == ICMPV6_TYPE_NA:
                # NA: target address 在 ICMPv6 payload 字节 8-23（帧偏移 54+8=62）
                if len(frame) >= 78 + vlan_off:
                    na_target = socket.inet_ntop(socket.AF_INET6, frame[62 + vlan_off:78 + vlan_off])
                    await self._check_ndp_raw_na(raw_src_mac, src_ip, na_target)
            elif icmp6_type == ICMPV6_TYPE_NS:
                if len(frame) >= 78 + vlan_off:
                    ns_target = socket.inet_ntop(socket.AF_INET6, frame[62 + vlan_off:78 + vlan_off])
                    await self._check_ndp_raw_ns(raw_src_mac, src_ip, ns_target)
            elif icmp6_type == ICMPV6_TYPE_RA:
                # RA: CurHopLimit = IPv6 header byte 7 (hop limit)
                hop_limit = frame[21 + vlan_off]  # IPv6 header 偏移 7
                # RA body 偏移: ICMPv6 header (4B) 后, M/O 标志在 byte 1
                ra_body_offset = 54 + 4 + vlan_off  # Ether(14) + IPv6(40) + ICMPv6(4)
                m_flag = (frame[ra_body_offset + 1] >> 7) & 1 if len(frame) > ra_body_offset + 1 else 0
                o_flag = (frame[ra_body_offset + 1] >> 6) & 1 if len(frame) > ra_body_offset + 1 else 0
                await self._check_ndp_raw_ra(raw_src_mac, src_ip, hop_limit, m_flag=m_flag, o_flag=o_flag)
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
            # 清理过期记录（同时删除空 key，防无界增长）
            self._dad_tracker = {
                t: [ts for ts in times if now - ts < self._nud_window]
                for t, times in self._dad_tracker.items()
                if any(now - ts < self._nud_window for ts in times)
            }
            if len(self._dad_tracker) > 200:
                self._dad_tracker.clear()  # 防无界增长（CPU/内存 DoS）
            if addr_key not in self._dad_tracker:
                self._dad_tracker[addr_key] = []
            self._dad_tracker[addr_key].append(now)
            if len(self._dad_tracker[addr_key]) >= 3:
                logger.warning("NDP 防护 [T4/AF_PACKET]: DAD 攻击! %s 被重复检测 ≥3 次", addr_key)
                self._dad_tracker[addr_key] = []

    async def _check_ndp_raw_ra(self, src_mac: str, src_ip: str, hop_limit: int, m_flag: int = 0, o_flag: int = 0):
        """AF_PACKET RA 检测：未知 RA 源（T3）+ CurHopLimit + M/O 标志"""
        if not self._enabled:
            return
        # 统一 MAC 格式（无分隔大写），与 scapy 路径/基线集合一致（MEDIUM-2）
        src_mac_norm = self._mac_normalize(src_mac)
        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        known_baseline_macs = {self._mac_normalize(m) for m in self._baseline_mac_per_gw.values()}
        all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources

        # AF_PACKET 路径也学习 RA 参数基线（与 scapy 路径共享基线条）——审计 MEDIUM：
        # 原信任检查先于基线学习，正常单路由器场景（首个 RA 来自信任源）基线永不学习、
        # M/O 参数欺骗检测成死代码；对齐 scapy 路径先无条件学基线再查信任
        if not self._ra_baseline_learned:
            self._ra_hoplimit_baseline = hop_limit
            self._ra_m_flag_baseline = bool(m_flag)
            self._ra_o_flag_baseline = bool(o_flag)
            self._ra_baseline_learned = True
            # 信任验证：命中已知网关/基线 MAC 或系统 NDP 表交叉验证一致才信任（防首包投毒 HIGH-1）
            if src_mac_norm in known_gw_macs | known_baseline_macs:
                self._trusted_ra_sources.add(src_mac_norm)
                logger.info("NDP 防护 [AF_PACKET]: 学习 RA 基线 HopLimit=%d M=%d O=%d (源 %s，命中网关MAC已信任)",
                            hop_limit, m_flag, o_flag, src_mac)
            else:
                sys_mac = None
                if src_ip and ":" in src_ip:
                    try:
                        sys_mac = await self._resolve_mac_single(src_ip)
                    except Exception:
                        sys_mac = None
                if sys_mac and self._mac_normalize(sys_mac) == src_mac_norm:
                    self._trusted_ra_sources.add(src_mac_norm)
                    logger.info("NDP 防护 [AF_PACKET]: 学习 RA 基线 HopLimit=%d M=%d O=%d (源 %s，系统表验证已信任)",
                                hop_limit, m_flag, o_flag, src_mac)
                else:
                    logger.warning("NDP 防护 [AF_PACKET]: RA 源 %s(%s) 未通过信任验证，仅记录参数基线不信任",
                                   src_ip, src_mac)
            if src_mac_norm in all_trusted:
                return  # 已信任的首 RA：完成基线学习后返回

        if src_mac_norm in all_trusted:
            return

        if src_mac_norm in self._suspicious_ra_sources:
            return

        # CurHopLimit 异常检测
        if hop_limit < 255:
            logger.warning("NDP 防护 [4.2.7/AF_PACKET]: CurHopLimit=%d (异常) RA 源 %s (%s)",
                           hop_limit, src_ip, src_mac)
            self._suspicious_ra_sources.add(src_mac_norm)
            self._threat_events.append({
                "type": "ra_param_spoof", "time": time.time(),
                "src_mac": src_mac, "src_ip": src_ip,
                "detail": f"CurHopLimit={hop_limit} (expected >=255)",
            })
            self._trim_threat_events()
            return

        # M/O 标志异常检测
        if self._ra_baseline_learned:
            if (self._ra_m_flag_baseline is not None and m_flag != self._ra_m_flag_baseline) or \
               (self._ra_o_flag_baseline is not None and o_flag != self._ra_o_flag_baseline):
                logger.warning("NDP 防护 [4.2.7/AF_PACKET]: M/O 标志异常 RA 源 %s (%s) "
                               "M=%d O=%d (基线 M=%s O=%s)",
                               src_ip, src_mac, m_flag, o_flag,
                               self._ra_m_flag_baseline, self._ra_o_flag_baseline)
                self._suspicious_ra_sources.add(src_mac_norm)
                self._threat_events.append({
                    "type": "ra_param_spoof", "time": time.time(),
                    "src_mac": src_mac, "src_ip": src_ip,
                    "detail": f"M={m_flag} O={o_flag} (baseline M={self._ra_m_flag_baseline} O={self._ra_o_flag_baseline})",
                })
                self._trim_threat_events()
                return

        # 未知 RA 源
        logger.warning("NDP 嗅探 [T3/AF_PACKET]: 未知 RA 源! %s (%s)", src_ip, src_mac)
        self._suspicious_ra_sources.add(src_mac_norm)
        self._threat_events.append({
            "type": "rogue_ra", "time": time.time(),
            "src_mac": src_mac, "src_ip": src_ip,
        })
        self._trim_threat_events()

    async def _check_ndp_raw_redirect(self, src_mac: str, src_ip: str):
        """AF_PACKET Redirect 检测（T6）：非信任源 Redirect"""
        if not self._enabled:
            return
        src_mac_norm = self._mac_normalize(src_mac)  # 统一 MAC 格式（MEDIUM-2）
        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        if known_gw_macs and src_mac_norm not in known_gw_macs:
            logger.warning("NDP 防护 [T6/AF_PACKET]: 非信任 Redirect! %s (%s)", src_ip, src_mac)
            self._threat_events.append({
                "type": "rogue_redirect", "time": time.time(),
                "src_mac": src_mac, "src_ip": src_ip,
            })
            self._trim_threat_events()

    async def _poll_ndp_table(self):
        """
        系统 NDP 表轮询（最终兜底）：定期执行系统命令检测网关 MAC 变更。
        无 Npcap 时无法发送原始 NA 帧，改用系统命令主动修复：
        1) ping -6 触发邻居发现刷新路由器 NDP 表
        2) netsh/ip 命令设静态 NDP 条目防篡改
        """
        logger.info("NDP 防护: NDP 表轮询已启动 (间隔=%.1fs)", 5)
        while self._ndp_running:
            try:
                # T1: 检查所有网关的 NDP 表项
                for gw_ip, expected_mac, _ in self.gateway_pairs:
                    if not gw_ip:
                        continue
                    actual_mac = await self._resolve_mac_single(gw_ip)
                    if not actual_mac:
                        continue
                    norm_actual = self._mac_normalize(actual_mac)
                    # 检测：MAC 变更 或 异常 MAC（广播/组播）
                    is_poisoned = False
                    if expected_mac and norm_actual != self._mac_normalize(expected_mac):
                        # 全零 MAC：Windows 上对不完整 NDP 条目的正常行为，不立即反制
                        if norm_actual == "000000000000":
                            logger.debug("NDP 防护 [T1/轮询]: 网关 %s NDP 条目为全零（可能不完整），跳过", gw_ip)
                            continue
                        is_poisoned = True
                    elif norm_actual in ("ffffffffffff",) or norm_actual.startswith("01"):
                        is_poisoned = True
                    if is_poisoned:
                        logger.warning("NDP 防护 [T1/轮询]: 网关 %s MAC 异常! %s -> %s",
                                       gw_ip, expected_mac or "?", actual_mac)
                        # 快速 ping -6 验证：临时 NDP 表波动 vs 真实投毒
                        # 使用 1 秒超时避免多网关场景累积延迟超过轮询间隔
                        ping_ok = await self._ping_ipv6(gw_ip, timeout_ms=1000)
                        if ping_ok:
                            logger.warning("NDP 防护 [T1/轮询]: 网关 %s MAC 异常但 ping 可达，"
                                           "判定为临时波动，跳过投毒标志", gw_ip)
                            # 记录可疑事件（MITM 攻击者可转发 ICMPv6 让 ping 成功）
                            self._threat_events.append({
                                "type": "ndp_table_anomaly_ping_ok", "time": time.time(),
                                "gateway": gw_ip, "expected_mac": expected_mac, "actual_mac": actual_mac,
                            })
                            self._trim_threat_events()
                            continue
                        # 去重：如果嗅探器已就绪（scapy 可用），轮询路径不再设 _poison_detected，
                        # 避免 network_monitor 中嗅探测到的投毒标志和轮询路径形成双重反制
                        if self._ndp_sender_ready:
                            logger.debug("NDP 防护 [T1/轮询]: 嗅探器已就绪，跳过投毒标志（由嗅探路径处理）")
                            # 不设标志，但继续执行修复逻辑（无感补充）
                        else:
                            self._poison_detected.set()
                        # 无 Npcap 时主动修复：ping -6 触发邻居发现刷新路由器 NDP 表
                        if sys.platform == "win32":
                            try:
                                proc = await asyncio.create_subprocess_exec(
                                    "ping", "-6", "-n", "5", gw_ip,
                                    stdout=asyncio.subprocess.DEVNULL,
                                    stderr=asyncio.subprocess.DEVNULL,
                                )
                                await asyncio.wait_for(proc.wait(), timeout=15)
                                await asyncio.sleep(0.1)
                                # 检查学习到的 MAC 是否正确
                                new_mac = await self._resolve_mac_single(gw_ip)
                                if new_mac and expected_mac and \
                                   self._mac_normalize(new_mac) != self._mac_normalize(expected_mac):
                                    logger.warning("NDP 防护: ping -6 后网关 MAC 仍异常 (%s)，"
                                                   "执行静态 NDP 绑定", new_mac)
                                    await self.protect_ndp_entry()
                            except Exception as e:
                                logger.debug("NDP 防护: ping -6 修复异常: %s", e)
                        else:
                            # Linux: 删除 NDP 条目触发重新学习
                            try:
                                proc = await asyncio.create_subprocess_exec(
                                    "ip", "-6", "neigh", "del", gw_ip, "dev",
                                    self.interfaces[0].name if self.interfaces else "",
                                    stdout=asyncio.subprocess.DEVNULL,
                                    stderr=asyncio.subprocess.DEVNULL,
                                )
                                await asyncio.wait_for(proc.wait(), timeout=2)
                            except Exception:
                                pass
                            try:
                                proc = await asyncio.create_subprocess_exec(
                                    "ping", "-6", "-c", "5", gw_ip,
                                    stdout=asyncio.subprocess.DEVNULL,
                                    stderr=asyncio.subprocess.DEVNULL,
                                )
                                await asyncio.wait_for(proc.wait(), timeout=15)
                            except Exception:
                                pass
                            await self.protect_ndp_entry()
            except Exception as e:
                logger.debug("NDP 防护: NDP 表轮询异常: %s", e)
            await asyncio.sleep(5)

    async def _verify_and_trust_ra_source(self, src_ip: str, src_mac: str, norm_src_mac: str):
        """异步交叉验证 RA 源并授予信任（防首包投毒；不在事件循环线程同步阻塞）"""
        try:
            sys_mac = await self._resolve_mac_single(src_ip) if (src_ip and ":" in src_ip) else None
        except Exception:
            sys_mac = None
        if sys_mac and self._mac_normalize(sys_mac) == norm_src_mac:
            self._trusted_ra_sources.add(src_mac)
            logger.info("NDP 嗅探: RA 源 %s(%s) 通过系统NDP表交叉验证，已信任", src_ip, src_mac)
        else:
            logger.warning("NDP 嗅探: RA 源 %s(%s) 未通过信任验证，不授予信任", src_ip, src_mac)

    async def _verify_and_learn_baseline(self, gw_ip: str, src_mac: str):
        """异步交叉验证嗅探兜底基线（防单包投毒；不在事件循环线程同步阻塞）"""
        learned = False
        try:
            try:
                sys_mac = await self._resolve_mac_single(gw_ip)
            except Exception:
                sys_mac = None
            if sys_mac and self._mac_normalize(sys_mac) == self._mac_normalize(src_mac):
                self._baseline_mac_per_gw[gw_ip] = src_mac
                self._baseline_learned = True
                learned = True
                logger.info("NDP 防护: 基线已学习 (嗅探兜底+系统表验证) [%s] -> MAC=%s", gw_ip, src_mac)
                for _iface in self.interfaces:
                    _iface.gateways = [
                        (_gw, self._baseline_mac_per_gw.get(_gw, _mac), _vlan)
                        for _gw, _mac, _vlan in _iface.gateways
                    ]
                try:
                    await self.protect_ndp_entry()
                except Exception:
                    pass
            else:
                logger.warning("NDP 防护: 嗅探到网关NDP包 MAC=%s 但系统NDP表为 %s，不采纳",
                               src_mac, sys_mac or "空")
        finally:
            # 验证未成功时重置 pending，允许后续包再次触发（否则启动初期查表失败会永久禁用基线学习→T1漏报）
            if not learned:
                self._baseline_verify_pending = False

    async def _refresh_local_all_ips_task(self):
        """异步刷新本机全量 IP 白名单（临时 IPv6 地址轮换防误报）."""
        try:
            fresh = await NDPProtection._fetch_all_local_ips()
            if fresh:
                # 合并而非整体替换：单次 ipconfig 漏项（接口瞬断/超时）不收缩白名单（review should-fix）
                self._local_all_ips = fresh | self._local_all_ips
                # 合并权威基线：interfaces 快照 + ipconfig /all 映射，保证启动时地址不丢
                self._local_all_ips.update(ip.split("%")[0] for ip in self.all_local_ipv6 if ip)
                for _mac_c, _ips in (self._local_ip_mac_map or {}).items():
                    self._local_all_ips.update(_ips)
                self._local_all_ips_ts = time.time()
                logger.debug("NDP 防护: 本机全量 IP 白名单已刷新: %d 个", len(self._local_all_ips))
        except Exception as e:
            self._local_refresh_interval = min(self._local_refresh_interval * 2, 120.0)
            logger.debug("NDP 防护: 本机全量 IP 白名单刷新失败(%s)，退避间隔->%.0fs", e, self._local_refresh_interval)
        else:
            self._local_refresh_interval = 30.0
        finally:
            self._local_ips_refreshing = False

    def _on_ndp_packet(self, pkt):
        try:
            self._loop.call_soon_threadsafe(self._on_ndp_packet_sync, pkt)
        except Exception:
            pass

    def _on_ndp_packet_sync(self, pkt):
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return
        # 仅处理 NDP 相关报文：NS/NA/RA/Redirect（Redirect type=137 由 ICMPv6ND_Redirect 表示）
        # 修复：原先仅放行 NS/NA，导致 RA/Redirect 分支（Rogue RA、参数欺骗、前缀、Redirect）成为死代码
        if not (pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA) or
                pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_Redirect)):
            return
        "Execute in event loop (via call_soon_threadsafe)"
        src_mac = self._mac_normalize(pkt[Ether].src)
        # 防环路：精确匹配自身反制已发送 MAC 集合（唯一防环路手段；02:00:00 前缀过滤已移除——
        # 攻击者可伪造本地管理单播 MAC 02:00:00:xx:xx:xx 完全豁免检测，审计 MEDIUM）
        if self._counterstrike_sent_macs and src_mac in self._counterstrike_sent_macs:
            return
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

            # 学习合法 RA 参数基线（从第一个 RA 学习；信任需验证，防首包投毒）
            if not self._ra_baseline_learned:
                self._ra_hoplimit_baseline = hop_limit
                self._ra_m_flag_baseline = m_flag
                self._ra_o_flag_baseline = o_flag
                self._ra_baseline_learned = True
                # 信任验证：仅当源 MAC 命中已知网关/基线 MAC，或与系统 NDP 表交叉验证一致时才加入信任
                # （否则攻击者在 L2 发一个伪造 RA 即可永久豁免 4.2.7/T3/T6 全部 RA 检测）
                known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
                known_baseline_macs = {self._mac_normalize(m) for m in self._baseline_mac_per_gw.values()}
                norm_src_mac = self._mac_normalize(src_mac)
                if norm_src_mac in known_gw_macs | known_baseline_macs:
                    self._trusted_ra_sources.add(src_mac)
                    logger.info("NDP 嗅探: 首个 RA 源 %s(%s) 命中已知网关 MAC，已信任", src_ip, src_mac)
                else:
                    # 异步交叉验证（fire-and-forget：避免事件循环线程内 run_coroutine_threadsafe().result() 阻塞死锁）
                    try:
                        self._loop.create_task(
                            self._verify_and_trust_ra_source(src_ip, src_mac, norm_src_mac))
                    except Exception:
                        pass
            else:
                # 信任集合提前计算：可信源跳过参数欺骗判定（与 AF_PACKET _check_ndp_raw_ra 顺序一致，
                # 避免可信路由器因 CurHopLimit 非 255（部分设备行为）被误报）
                known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
                known_baseline_macs = {self._mac_normalize(m) for m in self._baseline_mac_per_gw.values()}
                all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources

                # 对未知源异步发起信任验证（防重+30s 节流重试）：启动初期系统 NDP 表常为空导致首包验证失败，
                # 合法路由器（非网关）此后可经后续 RA 再次验证成功而获信任，消除永久误报（review should-fix）
                if src_mac not in all_trusted and src_mac not in self._suspicious_ra_sources:
                    _now_v = time.time()
                    if _now_v - self._ra_verify_pending.get(src_mac, 0.0) > 30.0:
                        self._ra_verify_pending[src_mac] = _now_v
                        try:
                            self._loop.create_task(
                                self._verify_and_trust_ra_source(src_ip, src_mac, self._mac_normalize(src_mac)))
                        except Exception:
                            pass
                if len(self._ra_verify_pending) > 200:
                    self._ra_verify_pending.clear()  # 防无界增长

                # CurHopLimit 异常检测（仅对非可信源）
                if src_mac not in all_trusted and self._ra_hoplimit_baseline is not None and hop_limit < 255:
                    logger.warning("NDP 嗅探 [4.2.7]: CurHopLimit=%d (异常) RA 源 %s (%s)",
                                   hop_limit, src_ip, src_mac)
                    self._suspicious_ra_sources.add(src_mac)
                    self._threat_events.append({
                        "type": "ra_param_spoof", "time": time.time(),
                        "src_mac": src_mac, "src_ip": src_ip,
                        "detail": f"CurHopLimit={hop_limit} (expected >=255)",
                    })
                    self._trim_threat_events()
                # M/O 标志与基线不一致（仅对非可信源）
                base_m = self._ra_m_flag_baseline
                base_o = self._ra_o_flag_baseline
                if src_mac not in all_trusted and base_m is not None and base_o is not None:
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

                # --- 4.2.5/4.2.6 虚假前缀检测 ---
                if pkt.haslayer(ICMPv6NDOptPrefixInformation):
                    try:
                        pi = pkt[ICMPv6NDOptPrefixInformation]
                        prefix = str(pi.prefix) if pi.prefix else ""
                        prefix_len = pi.prefixlen if hasattr(pi, 'prefixlen') else 64
                    except Exception:
                        prefix = ""
                        prefix_len = 64
                    if prefix and prefix != "::":
                        # 首次学习前缀
                        if not self._known_prefixes:
                            self._known_prefixes.add(prefix)
                            logger.info("NDP 防护: 学习合法前缀 %s/%d (RA 源 %s)", prefix, prefix_len, src_mac)
                        elif prefix not in self._known_prefixes:
                            # 新前缀与已知前缀不一致 → 可能虚假前缀
                            # 全局单播 IPv6 范围为 2000::/3（首 hex digit 为 2 或 3）
                            first_hex = prefix.split(":")[0].lower() if ":" in prefix else ""
                            is_global_unicast = first_hex and first_hex[0] in "23" and len(first_hex) <= 4
                            if is_global_unicast and prefix_len == 64:
                                self._known_prefixes.add(prefix)
                                logger.info("NDP 防护: 学习新合法前缀 %s/%d (RA 源 %s)", prefix, prefix_len, src_mac)
                            else:
                                logger.warning("NDP 嗅探 [4.2.5/4.2.6]: 可疑前缀 %s/%d (非全局单播/非/64) RA 源 %s (%s)",
                                               prefix, prefix_len, src_ip, src_mac)
                                self._threat_events.append({
                                    "type": "fake_prefix", "time": time.time(),
                                    "src_mac": src_mac, "src_ip": src_ip,
                                    "prefix": prefix, "prefix_len": prefix_len,
                                })
                                self._trim_threat_events()

                # --- RA 源自动学习（替代 max_ra_routers）---
                # 从手动配置的网关 MAC 或已确认的接口网关 MAC 发来的 RA = 信任
                # all_trusted 已在上方提前计算（含网关MAC + 基线MAC + 已确认RA源）

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

        # ==================== T5 NUD 追踪 / T4 DAD 检测 ====================
        if pkt.haslayer(ICMPv6ND_NS):
            ns = pkt[ICMPv6ND_NS]
            try:
                ns_target = str(ns.tgt)
            except (AttributeError, ValueError):
                return
            now = time.time()
            if src_ip == "::":
                # T4: DAD — 源为 :: 表示重复地址检测（与 NUD 分离，防数据污染）
                self._dad_tracker = {
                    t: [ts for ts in times if now - ts < self._nud_window]
                    for t, times in self._dad_tracker.items()
                    if any(now - ts < self._nud_window for ts in times)
                }
                if len(self._dad_tracker) > 200:
                    self._dad_tracker.clear()  # 防无界增长（CPU/内存 DoS）
                if ns_target not in self._dad_tracker:
                    self._dad_tracker[ns_target] = []
                self._dad_tracker[ns_target].append(now)
                if len(self._dad_tracker[ns_target]) >= 3:
                    logger.warning("NDP 嗅探 [T4]: DAD 攻击! %s 被重复检测 ≥3 次", ns_target)
                    self._threat_events.append({
                        "type": "dad_attack", "time": now,
                        "target": ns_target, "count": len(self._dad_tracker[ns_target]),
                    })
                    self._trim_threat_events()
                    self._dad_tracker[ns_target] = []
            else:
                self._nud_tracker = {
                    t: [ts for ts in times if now - ts < self._nud_window]
                    for t, times in self._nud_tracker.items()
                    if any(now - ts < self._nud_window for ts in times)
                }
                if len(self._nud_tracker) > 200:
                    self._nud_tracker.clear()  # 防无界增长（CPU/内存 DoS）
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
                    # 触发恢复 worker 确认网关状态（同 target ≥10s 节流，防伪造 NS 放大 ping 风暴）
                    if len(self._recovery_last_trigger) > 200:
                        self._recovery_last_trigger.clear()  # 防无界增长
                    if now - self._recovery_last_trigger.get(ns_target, 0.0) >= 10.0:
                        self._recovery_last_trigger[ns_target] = now
                        self._recovery_trigger.set()

        # ==================== 基线兜底学习（嗅探器启动早于detect_gateway时，通过系统NDP表验证后学习）====================
        # 手动配置网关时不允许嗅探器覆盖基线（detect_gateway已锁定）
        if not self._baseline_learned and not self._manual_gateways:
            if not self._baseline_verify_pending:
                for gw_ip in all_gw_ips:
                    if src_ip == gw_ip:
                        if NDPProtection._is_valid_mac(src_mac):
                            # 通过系统NDP表验证后再接受，防单包投毒（异步 fire-and-forget，不阻塞事件循环）
                            self._baseline_verify_pending = True
                            try:
                                self._loop.create_task(
                                    self._verify_and_learn_baseline(gw_ip, src_mac))
                            except Exception:
                                self._baseline_verify_pending = False
                        break
            return

        # ==================== 基线与实际MAC完全匹配时直接跳过（正确宣告/防自伤环路）====================
        for gw_ip in all_gw_ips:
            baseline = self._baseline_mac_per_gw.get(gw_ip)
            if baseline and (src_ip == gw_ip) and self._mac_normalize(src_mac) == self._mac_normalize(baseline):
                return

        # ==================== T1 NA 投毒 ====================
        if pkt.haslayer(ICMPv6ND_NA):
            na = pkt[ICMPv6ND_NA]
            try:
                na_target = str(na.tgt)
            except (AttributeError, ValueError):
                return
            for gw_ip in all_gw_ips:
                baseline = self._baseline_mac_per_gw.get(gw_ip)
                # 安全防护：基线为空或全零时不触发检测（防误判）
                if not baseline or self._mac_normalize(baseline) == "000000000000":
                    continue
                if (src_ip == gw_ip or na_target == gw_ip) and self._mac_normalize(src_mac) != self._mac_normalize(baseline):
                    self._threat_events.append({
                        "type": "na_poison", "time": time.time(),
                        "gateway": gw_ip, "expected_mac": baseline, "actual_mac": src_mac,
                    })
                    self._trim_threat_events()
                    logger.warning("NDP 嗅探 [T1]: NA 投毒! %s -> 预期 %s != 实际 %s",
                                   gw_ip, baseline, src_mac)
                    # --- 全零 MAC / 信任列表 处理 ---
                    norm_smac = self._mac_normalize(src_mac) if src_mac else ""
                    if norm_smac in self._trusted_sender_macs:
                        logger.debug("NDP 嗅探: 信任设备 %s 发来可疑 NA，已跳过", src_mac)
                        break
                    if norm_smac == "000000000000":
                        _now_zero = time.time()
                        _rec = self._suspicious_zero_mac.setdefault(norm_smac, [])
                        _rec.append(_now_zero)
                        self._suspicious_zero_mac[norm_smac] = [t for t in _rec if t > _now_zero - 10.0]
                        _cnt_10s = len(self._suspicious_zero_mac[norm_smac])
                        if _cnt_10s >= 3:
                            logger.warning("NDP 嗅探 [T1]: 设备 %s 发送全零 MAC NA 回复 "
                                           "(10s内%d次)，确认为 NDP 投毒", src_mac, _cnt_10s)
                        else:
                            logger.warning("NDP 嗅探: 可疑 NA 包 — %s 发送全零 MAC 回复 "
                                           "(10s内第%d次，≥3次才确认)，暂不反制", src_mac, _cnt_10s)
                            break
                    # --- 全零 MAC 处理结束 ---
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
                        self._loop.call_soon_threadsafe(self._poison_detected.set)
                        self._loop.call_soon_threadsafe(
                            lambda _mac=src_mac, _ip=src_ip: asyncio.create_task(self._on_poison_detected(attacker_mac=_mac, attacker_ip=_ip)))
                    break

        # ==================== IP 冲突 ====================
        # 本机 MAC 集合（检测层防自伤：本机任一接口 MAC 宣告本机 IPv6 = 自发的 NA/GARP，属正常）
        # 修复：原仅对比单值 self.local_mac，本机 MAC 解析为空/不匹配时自包被误判为 IP 冲突
        local_macs_norm = {self._mac_normalize(m) for m in self._local_macs} if self._local_macs else set()
        if self.local_mac:
            local_macs_norm.add(self._mac_normalize(self.local_mac))
        if not local_macs_norm:
            logger.debug("NDP 嗅探: 本机 MAC 集合为空，IP 冲突检测无法排除自包（可能误伤）")
            # 审计 MEDIUM：无法排除自包时跳过 IP 冲突检测（清空循环源），避免本机自包被误报为
            # IP 冲突并触发反制；local_mac_spoof / 自包跳过判定不受影响（使用 local_all_ips_clean 与 _local_macs）
            all_local_ips = []
        # 剥离 IPv6 zone id（%9）：scapy 解析的 src_ip 无 %zone，all_local_ips 可能带 %zone（链路本地自包误判修复）
        src_ip_clean = (src_ip or "").split("%")[0]
        all_local_ips_clean = {ip.split("%")[0] for ip in all_local_ips}
        # 本机全量 IP 白名单（检测层防自伤，对齐 ARP 侧 _local_ips 机制）：
        # 动态全量 = interfaces 快照 ∪ 运行期 ipconfig/ip 采集（含轮换后的临时 IPv6 地址）
        local_all_ips_clean = set(self._local_all_ips) | all_local_ips_clean
        # ==================== 本机自包提前跳过 ====================
        # 本机任一网卡 MAC 宣告本机任一 IP（含运行期轮换的临时 IPv6）= 自发的 NS/NA/DAD，属正常
        if local_macs_norm and src_mac in local_macs_norm and src_ip_clean in local_all_ips_clean:
            if pkt.haslayer(ICMPv6ND_NA):
                # 安全加固（security_review MEDIUM）：NA 自包若携带 TLLA 选项，TLLA 必须等于源 MAC，
                # 防止攻击者伪造本机 MAC+本机 IP 的 NA（TLLA 指向攻击者）劫持邻居缓存
                if pkt.haslayer(ICMPv6NDOptDstLLAddr):
                    _tlla = self._mac_normalize(str(pkt[ICMPv6NDOptDstLLAddr].lladdr))
                    if _tlla and _tlla != self._mac_normalize(src_mac):
                        logger.warning("NDP 嗅探: NA 自包 TLLA(%s)≠源 MAC(%s)，疑似伪造本机 MAC+IP 劫持，已记入威胁事件",
                                       _tlla, src_mac)
                        self._threat_events.append({
                            "type": "na_tlla_mismatch", "time": time.time(),
                            "attacker_mac": src_mac, "src_ip": src_ip,
                        })
                        self._trim_threat_events()
                        return  # 不豁免也不反制（防自伤）
                return  # NA 自包且 TLLA 校验通过（或无 TLLA，不更新邻居缓存）
            return  # NS/RA/Redirect 自包直接放行
        # DAD NS（RFC 4862）：本机接口配置时用 :: 发送重复地址检测，永不进入 IP 白名单，属正常自包
        if src_ip_clean == "::":
            return
        # 运行期临时 IPv6 轮换窗口：本机 MAC + 未知 IP 时先异步刷新一次全量集合再判定
        # （防止刚轮换的新临时地址在下次刷新前被误判为"本地 MAC 冒用攻击"；
        #   刷新中暂缓判定，刷新完成后由后续包正常判定——真攻击者持续发包仍会被检测）
        if local_macs_norm and src_mac in local_macs_norm and src_ip_clean not in local_all_ips_clean:
            if self._local_ips_refreshing:
                return  # 刷新任务运行中：暂缓判定，避免"刷新未完成"窗口误报
            _now_ref = time.time()
            if _now_ref - self._local_all_ips_ts >= 30.0:
                # 白名单可能过期（临时 IPv6 轮换窗口/退避期）：一律暂缓判定，
                # 防退避期（最长 120s）内本机新临时地址被误判 local_mac_spoof（review warn）
                if _now_ref - self._local_ips_refresh_attempt >= self._local_refresh_interval:
                    self._local_ips_refresh_attempt = _now_ref
                    self._local_ips_refreshing = True
                    try:
                        self._loop.create_task(self._refresh_local_all_ips_task())
                    except Exception:
                        self._local_ips_refreshing = False
                else:
                    logger.warning("NDP 嗅探: 本机 MAC + 未知 IP 处于刷新退避期(%.0fs)，检测暂缓防误报(security 权衡)",
                                   self._local_refresh_interval)
                return  # 白名单过期期间暂缓；刷新成功后由后续包正常判定（真攻击者持续发包仍会被检测）
            # 白名单新鲜（<30s）：未知 IP 走正常判定（local_mac_spoof）
        for local_ip in all_local_ips:
            local_ip_clean = local_ip.split("%")[0]
            if local_ip and (src_ip_clean == local_ip_clean or (
                pkt.haslayer(ICMPv6ND_NA) and str(pkt[ICMPv6ND_NA].tgt).split("%")[0] == local_ip_clean
            )) and self._mac_normalize(src_mac) not in local_macs_norm:
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
                    lambda _mac=src_mac, _ip=src_ip: asyncio.create_task(self._on_poison_detected(attacker_mac=_mac, attacker_ip=_ip)))
                break

        # ==================== 本地 MAC 冒用攻击 ====================
        # 本机 MAC 宣告"非本机 IP"才算冒用；IPv6 比较剥离 %zone（链路本地自包误判修复）
        if self._local_macs and any(self._mac_normalize(src_mac) == self._mac_normalize(m) for m in self._local_macs)                 and src_ip_clean not in local_all_ips_clean and src_mac != "000000000000":
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
                    lambda _mac=src_mac, _ip=src_ip: asyncio.create_task(self._on_poison_detected(attacker_mac=_mac, attacker_ip=_ip)))

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
        # 触发恢复 worker 确认网关状态
        self._recovery_trigger.set()
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

        # 可疑全零 MAC 自动学习为信任：超 300 秒无活动说明无害
        stale_suspicious = [m for m, ts_list in self._suspicious_zero_mac.items()
                            if ts_list and now - max(ts_list) > 300.0]
        for m in stale_suspicious:
            self._trusted_sender_macs.add(m)
            del self._suspicious_zero_mac[m]
            logger.info("NDP 防护: 设备 %s 已自动学习为信任（300s无活动）", m)
        # 信任列表防无限增长（最多保留 200 条）
        if len(self._trusted_sender_macs) > 200:
            self._trusted_sender_macs.clear()
            logger.info("NDP 防护: 信任列表已清空（超200条阈值）")

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
                        # 审计 HIGH：原硬编码 33:33:ff:00:00:01（对应 ff02::1:ff00:1）与网关地址不符，
                        # NS 无法送达网关；按网关地址计算 solicited-node 组播（对齐 AF_PACKET 路径）
                        gw_bytes = socket.inet_pton(socket.AF_INET6, gw_ip)
                        ns_dst_mac = bytes([0x33, 0x33, 0xff, gw_bytes[13], gw_bytes[14], gw_bytes[15]])
                        ns_dst_mac_str = ":".join(f"{b:02x}" for b in ns_dst_mac)
                        ns_dst_ipv6 = socket.inet_ntop(socket.AF_INET6,
                            bytes([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff,
                                   gw_bytes[13], gw_bytes[14], gw_bytes[15]]))
                        eth = Ether(dst=ns_dst_mac_str, src=iface.mac)
                        ns = ICMPv6ND_NS(target=gw_ip)
                        src_lla = ICMPv6NDOptSrcLLAddr(lladdr=iface.mac)
                        ipv6 = IPv6(src=local_ll, dst=ns_dst_ipv6, hlim=255)
                        sendp(eth / ipv6 / ns / src_lla, iface=iface.name, verbose=False)
                    na_pkts = sniff(filter="icmp6", count=5, timeout=timeout,
                                    lfilter=lambda p: p.haslayer(ICMPv6ND_NA) and
                                                      p.haslayer(ICMPv6NDOptDstLLAddr) and
                                                      str(p[ICMPv6ND_NA].tgt) == gw_ip,
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
            pseudo += b'\x00\x00\x00' + struct.pack('!B', 58)  # RFC4443: 3 字节零 + next header
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
                s.setblocking(False)
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
            # 注意：不 return，继续执行后续的静态 NDP 绑定和基线锁定
            # 确保手动配置的网关也能进入基线锁定流程
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


        # 立即用已探测的 MAC 做静态 NDP 绑定
        if self.interfaces:
            for iface in self.interfaces:
                for _, gw_mac, _ in iface.gateways:
                    if gw_mac:
                        await self.protect_ndp_entry()
                        break
                break

        # ========== 启动时主动 NDP 基线确认（一次性锁定，嗅探器启动前完成）==========
        locked_count = 0
        for gw_ip, gw_mac, _ in self.gateway_pairs:
            if not gw_ip or not gw_mac:
                continue
            gw_mac_up = gw_mac.replace("-", ":").upper()
            norm = self._mac_normalize(gw_mac_up)
            # 基线有效性检查：拒绝全零/广播/组播MAC
            if norm and NDPProtection._is_valid_mac(gw_mac_up):
                self._baseline_mac_per_gw[gw_ip] = gw_mac_up
                locked_count += 1
                logger.info("NDP 防护: 基线已锁定 [%s] -> MAC=%s (启动时主动确认)", gw_ip, gw_mac_up)
            else:
                # MAC非法，主动触发NDP解析重试
                logger.warning("NDP 防护: 基线 MAC %s 非法（全零/广播/组播），主动触发 NDP 解析重试 [%s]",
                               gw_mac, gw_ip)
                retry_mac = await self._resolve_mac_single(gw_ip)
                if retry_mac and NDPProtection._is_valid_mac(retry_mac):
                    retry_up = retry_mac.replace("-", ":").upper()
                    self._baseline_mac_per_gw[gw_ip] = retry_up
                    locked_count += 1
                    # 更新接口网关MAC
                    for iface in self.interfaces:
                        for i, (ip_, mac_, vlan_) in enumerate(iface.gateways):
                            if ip_ == gw_ip:
                                iface.gateways[i] = (ip_, retry_up, vlan_)
                    logger.info("NDP 防护: 基线已锁定 [%s] -> MAC=%s (重试后确认)", gw_ip, retry_up)
        if locked_count > 0:
            self._baseline_learned = True
            logger.info("NDP 防护: 基线学习完成，已锁定 %d 个网关", locked_count)
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

        # getmac 一次解析所有接口 MAC（原实现在行循环内每行启动子进程——修复 M2）
        getmac_map = {}
        try:
            proc_gm = await asyncio.create_subprocess_exec(
                "getmac", "/FO", "CSV", "/NH",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out_gm, _ = await asyncio.wait_for(proc_gm.communicate(), timeout=5)
            for line_gm in self._decode_win_output(out_gm).splitlines():
                line_gm = line_gm.strip().strip('"')
                parts_gm = line_gm.split('","')
                # 兼容列序（同 _fetch_all_local_macs 修复）：MAC 可能在 0 或 1 列
                _mac_gm = None
                for _p in parts_gm[:3]:
                    _m = _p.strip()
                    if _m and len(_m.replace("-", "").replace(":", "")) == 12 and \
                            re.match(r'^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$', _m):
                        _mac_gm = _m.replace("-", ":").upper()
                        break
                if _mac_gm and parts_gm:
                    # 连接名取 MAC 字段之外的第一个非 MAC 字段（用户列序下为空则跳过映射，不影响 ipconfig 主路径）
                    _conn = next((_p.strip().lower() for _p in parts_gm
                                  if not re.match(r'^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$', _p.strip())), None)
                    if _conn:
                        getmac_map[_conn] = _mac_gm
        except Exception:
            pass

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
                # 审计 MEDIUM：仅处理 IP 地址行（对齐 _fetch_all_local_ips），排除"默认网关/DNS 服务器"
                # 行——否则网关/DNS 地址被当作本机地址，污染 all_local_ipv6（IP 冲突误报 + NA 源地址错误）
                # 修复 review blocking：原条件方向反转（not any → 提取），真正 IP 行被跳过、网关行被收录
                if not any(k in s for k in ("IPv6 地址", "IPv6 Address", "IPv4 地址", "IPv4 Address",
                                            "IP Address", "IP 地址")):
                    continue  # 非 IP 地址行跳过
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
                # 如果 ipconfig 未解析到 MAC，用 getmac 映射兑底（按接口名匹配，修复 M2）
                if not iface.mac and iface.name:
                    mac_gm = getmac_map.get(iface.name.lower())
                    if mac_gm:
                        iface.mac = mac_gm
            if iface.ipv6_ll or iface.ipv6_global:
                # 解析接口索引（供 sendp 使用数字索引替代中文接口名）
                iface.idx = await self._resolve_iface_idx(iface.name)
                # 审计修复：netsh 名称匹配失败（编码差异/多编码均失败）时用默认路由 zone_id 兜底——
                # zone_id 即接口索引（链路本地 %9 中的 9）；仅当接口链路本地带 %zone 时交叉匹配
                # 默认路由（多接口防错配，review should-fix）；无 %zone 信息时不乱兜底（保持 idx=0
                # 回退字符串接口名，避免把绑定/sendp 指向错误接口）
                if iface.idx <= 0:
                    _zone_from_ll = None
                    if iface.ipv6_ll and "%" in iface.ipv6_ll:
                        try:
                            _zone_from_ll = int(iface.ipv6_ll.split("%", 1)[1])
                        except ValueError:
                            _zone_from_ll = None
                    if _zone_from_ll:
                        for _gw, _zid in default_routes:
                            if _zid and _zid > 0 and _zid == _zone_from_ll:
                                iface.idx = _zid
                                break
                    if iface.idx <= 0:
                        logger.warning("NDP 防护: 接口 %s idx 解析失败且无链路本地 zone 交叉匹配，保持 idx=0（回退字符串接口名）",
                                       iface.name)
                # 审计 MEDIUM：仅挂载本接口（zone_id 匹配 iface.idx）的默认路由；
                # 原实现把全部默认路由加给每个接口——多接口场景 gateway_pairs 重复、基线/反制对象错乱
                for gw, idx in default_routes:
                    if idx and iface.idx > 0 and idx != iface.idx:
                        continue
                    if not any(g == gw for g, _, _ in iface.gateways):
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
                    if ipv6.split('%')[0].lower() in line.lower().split():
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
                                    # 去重（修复 M3：同一 IP 可能被多行/多轮重复追加）
                                    if ip not in iface.ipv6_globals:
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
            if expected and actual:
                norm_actual = self._mac_normalize(actual)
                if norm_actual != self._mac_normalize(expected):
                    if norm_actual == "000000000000":
                        continue  # 全零 MAC 降级为可疑，不加入投毒列表
                    poisoned.append(("手动", ip, expected, actual))
            if not expected and self._baseline_gateway_mac and actual:
                if self._mac_normalize(actual) != self._mac_normalize(self._baseline_gateway_mac):
                    if self._mac_normalize(actual) == "000000000000":
                        continue
                    poisoned.append(("手动-基线", ip, self._baseline_gateway_mac, actual))
        for iface in self.interfaces:
            for gw_ip, expected, _ in iface.gateways:
                if not gw_ip or not expected:
                    continue
                actual = await self._resolve_mac_single(gw_ip)
                if actual:
                    norm_actual_iface = self._mac_normalize(actual)
                    if norm_actual_iface != self._mac_normalize(expected):
                        if norm_actual_iface == "000000000000":
                            continue
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
            await asyncio.sleep(2.0)  # 从 0.5s 延长到 2s 采样
            cnt2 = await self._count_neighbors()
            elapsed = time.monotonic() - before
            if elapsed <= 0:
                return False
            rate = (cnt2 - cnt1) / elapsed
            if rate > self._ndp_flood_threshold:
                logger.warning("NDP 防护 [T7]: 泛洪! 邻居增长 %.0f 条/秒 (阈值=%d)", rate, self._ndp_flood_threshold)
                self._ndp_flood_suppress = True
                # 泛洪缓解：清空已学习的可疑条目，抑制进一步学习
                if hasattr(self, '_suspicious_ra_sources'):
                    self._suspicious_ra_sources.clear()
                if hasattr(self, '_ndp_attack_stats'):
                    self._ndp_attack_stats.clear()
                return True
            else:
                # 连续正常则解除抑制
                self._ndp_flood_suppress = False
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
                lines = self._decode_win_output(stdout).splitlines()
                # 跳过表头行（包含 -- 或"接口"开头，或 Internet/物理地址 表头——修复 L4）
                return sum(1 for l in lines if l.strip() and "--" not in l
                           and not l.strip().startswith(("接口", "Internet"))
                           and "物理地址" not in l and "Physical Address" not in l)
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-6", "neigh", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                lines = stdout.decode(errors="replace").splitlines()
                # ip -6 neigh show 输出每行一条邻居条目，跳过空行
                return sum(1 for l in lines if l.strip())
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
                             p.haslayer(ICMPv6ND_RA) or p.haslayer(ICMPv6ND_Redirect) or p.haslayer(ICMPv6Error)),
                         quiet=True)
        try:
            pkts = await loop.run_in_executor(None, _capture)
        except Exception as e:
            logger.debug("NDP 防护: sniff 失败: %s", e)
            return {"t2_ns": [], "t3_ra": [], "t4_dad": [], "t6_redirect": []}

        known_gw_macs = {self._mac_normalize(mac) for _, mac, _ in self.gateway_pairs if mac}
        known_baseline_macs = {self._mac_normalize(m) for m in self._baseline_mac_per_gw.values()}
        # 信任集合与 _check_ndp_raw_ra / _on_ndp_packet_sync 统一：网关MAC + 基线MAC + 已确认RA源
        all_trusted = known_gw_macs | known_baseline_macs | self._trusted_ra_sources
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
                target = str(ns.tgt)
                ns_targets[target] += 1
                if src_ip == "::":
                    dad_targets[target] += 1
                # 审计 MEDIUM：原条件 all_trusted and src_mac not in all_trusted 在信任集合为空时恒 False，
                # 启动初期/网关 MAC 未解析时 NS 可疑源静默漏检（对齐 1458 行常驻路径无此前置）
                if src_mac not in all_trusted:
                    suspicious_ns.append((target, src_mac))
            if pkt.haslayer(ICMPv6ND_Redirect):
                # 修复：原条件 haslayer(ICMPv6Error) 仅匹配 type 1-4 错误类，对 Redirect(type 137) 恒 False
                redirect_sources.append((src_mac, src_ip))

        results = {}
        results["t2_ns"] = suspicious_ns
        results["t3_ra"] = [(m, i, p) for m, (i, p) in ra_sources.items() if m not in all_trusted]
        results["t4_dad"] = [(t, c) for t, c in dad_targets.items() if c >= 3]
        results["t6_redirect"] = [(m, i) for m, i in redirect_sources if m not in all_trusted]
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
        # 审计 HIGH：attacker_mac 经 _mac_normalize 传入（无分隔大写，如 "000000000000"），
        # 原冒号格式比较永不成立（死代码）→ 全零 MAC 攻击者落入无效定向反制
        if self._mac_normalize(attacker_mac) == "000000000000":
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
        # Linux 无 scapy 时 worker 走 AF_PACKET 兜底（修复 M1：原条件使 AF_PACKET 分支死代码）
        _af_packet_capable = sys.platform != "win32"
        if attacker_mac and (self._ndp_sender_ready or _af_packet_capable):
            # 收集本机 IPv6 和 MAC 信息
            for iface in self.interfaces:
                local_ip = iface.ipv6_global or iface.ipv6_ll
                local_mac_real = iface.mac
                if local_ip and local_mac_real:
                    # 网关 IPv6 -> 随机不可达 MAC 毒化包（打残攻击者）
                    poison_mac = self._generate_poison_mac()
                    # 记录反制MAC到追踪集合，用于嗅探器精确防环路
                    self._counterstrike_sent_macs.add(self._mac_normalize(poison_mac))
                    if len(self._counterstrike_sent_macs) > 1000:
                        self._counterstrike_sent_macs.clear()
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

        # 回退：sender 就绪或 Linux AF_PACKET 兜底时用队列；仅 Windows 无 scapy 走系统命令广播
        if not self._ndp_sender_ready and not _af_packet_capable:
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

            frame = bytearray(d_mac + s_mac)  # bytearray：pack_into 写 checksum 需要可写缓冲区
            if vlan_id and not self._vxlan_enabled:
                frame += struct.pack('!HH', 0x8100, int(vlan_id) & 0xFFF)
            frame += struct.pack('!H', ETH_P_IPV6)
            frame += ipv6_header + na_payload

            # 计算 ICMPv6 checksum
            pseudo_header = ipv6_src + ipv6_dst
            pseudo_header += struct.pack('!I', payload_len)
            pseudo_header += b'\x00\x00\x00' + struct.pack('!B', 58)  # RFC4443: 3 字节零 + next header=ICMPv6
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
                # 按 local_ip 匹配出接口（多接口场景防发错物理口——修复 M4）
                send_iface = self.interface_name or ""
                if len(self.interfaces) > 1:
                    for _iface in self.interfaces:
                        _iface_ips = list(_iface.ipv6_globals)
                        if _iface.ipv6_ll:
                            _iface_ips.append(_iface.ipv6_ll)
                        if local_ip in _iface_ips:
                            send_iface = _iface.name
                            break
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
                            # sendp 外包 executor：scapy 构造/发送在事件循环内同步执行会阻塞 ARP 侧协程（对称加固）
                            await asyncio.get_event_loop().run_in_executor(
                                None, lambda p=pkt, i=send_iface: sendp(p, iface=i, verbose=False))
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

        # 审计修复：Npcap 接口可用性探测——get_if_list 仅 loopback（Npcap 驱动未运行/未接管物理网卡）
        # 时给出明确可操作提示（节流：每 300s 最多提示一次）
        if sys.platform == "win32":
            _now_p = time.time()
            if _now_p - getattr(self, "_scapy_npcap_warn_ts", 0.0) >= 300.0:
                try:
                    from scapy.all import get_if_list
                    _ifaces = get_if_list()
                    if _ifaces and all(("Loopback" in i or "loopback" in i) for i in _ifaces):
                        self._scapy_npcap_warn_ts = _now_p
                        logger.warning("NDP 防护: Npcap 未枚举到物理网卡（仅 %s）。NA 反制将尝试 NPF 设备接口"
                                       "或走系统 fallback；请以管理员运行 'sc start npcap' 或检查 Npcap 服务状态",
                                       ", ".join(repr(i) for i in _ifaces))
                except Exception:
                    pass

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
            # iface.mac 可能为空或为本地管理随机 MAC（uuid 兜底污染），
            # 用 IP↔MAC 映射（ipconfig /all 物理地址，权威）校正——修复 NA 发送源 MAC 虚构
            iface_mac = iface.mac
            _is_la = (iface_mac and len(iface_mac.replace(":", "")) == 12
                      and (int(iface_mac.replace(":", "")[:2], 16) & 0x02))
            if not iface_mac or _is_la:
                _map_mac = None
                for _mac_c, _ips in (self._local_ip_mac_map or {}).items():
                    if local_ip in _ips:
                        _map_mac = _mac_c
                        break
                if not _map_mac and self._local_ip_mac_map:
                    _map_mac = next(iter(self._local_ip_mac_map), None)
                if _map_mac:
                    iface_mac = _map_mac
            if not iface_mac and self._local_macs:
                iface_mac = next(iter(self._local_macs), "")
            if not iface_mac:
                try:
                    import uuid
                    node = uuid.getnode()
                    # 拒绝 locally-administered/multicast 随机 MAC（同 _fetch_all_local_macs 修复）
                    if node is not None and node != 0 and not (node & 0x030000000000):
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
                sent = 0
                try:
                    for _ in range(5):
                        sendp(pkt, iface=iface_arg, verbose=False)
                        time.sleep(0.02)
                    sent = 5
                except Exception as e1:
                    # 审计修复：接口名/索引不可用（Npcap 驱动未运行或 get_if_list 枚举不全）时，
                    # 按本机 MAC 匹配 get_windows_if_list 取 \Device\NPF_{GUID} 设备路径重试
                    _npf_iface = None
                    if sys.platform == "win32":
                        try:
                            from scapy.arch.windows import get_windows_if_list
                            _mac_n = str(iface_mac or "").lower().replace("-", ":")
                            _wl = get_windows_if_list()
                        # 优先选择 Npcap Packet Driver 条目（hostcap/WFP 等过滤器的 NPF 设备不可发包）
                            for _w in _wl:
                                _wm = str(_w.get("mac", "") or "").lower().replace("-", ":")
                                if _wm == _mac_n and _wm not in ("", "00:00:00:00:00:00"):
                                    _guid = _w.get("guid", "")
                                    if _guid and "NPCAP" in str(_w.get("name", "") or "").upper():
                                        _npf_iface = f"\\Device\\NPF_{_guid}"
                                        break
                            if not _npf_iface:
                                # 兜底：任一同 MAC 条目
                                for _w in _wl:
                                    _wm = str(_w.get("mac", "") or "").lower().replace("-", ":")
                                    if _wm == _mac_n and _wm not in ("", "00:00:00:00:00:00"):
                                        _guid = _w.get("guid", "")
                                        if _guid:
                                            _npf_iface = f"\\Device\\NPF_{_guid}"
                                            break
                        except Exception:
                            _npf_iface = None
                    if _npf_iface:
                        try:
                            for _ in range(5):
                                sendp(pkt, iface=_npf_iface, verbose=False)
                                time.sleep(0.02)
                            sent = 5
                            logger.info("NDP 防护: NA 改用 NPF 设备接口 %s 发送成功（接口名 %r 不可用）",
                                        _npf_iface, iface_arg)
                        except Exception as e2:
                            self._scapy_sendp_ok = False
                            logger.warning("NDP 防护: 接口 %s NA sendp 失败（接口名与 NPF 设备均不可用，"
                                           "Npcap 驱动可能未运行）: %s / %s (idx=%s)",
                                           iface.name, e1, e2, iface.idx)
                            return 0
                    else:
                        self._scapy_sendp_ok = False
                        if sys.platform == "win32":
                            logger.warning("NDP 防护: 接口 %s NA sendp 失败（scapy 找不到接口 %r 且未能按 MAC 匹配 "
                                           "NPF 设备，Npcap 驱动未运行或未接管该网卡）: %s (idx=%s)。"
                                           "请以管理员运行 sc start npcap 或检查 Npcap 服务状态；将走系统 fallback"
                                           "（ping 网关 + netsh 静态 NDP 绑定）",
                                           iface.name, iface_arg, e1, iface.idx)
                        else:
                            # 非 Windows（Linux AF_PACKET 兑底）：不提示 sc start npcap（review should-fix）
                            logger.warning("NDP 防护: 接口 %s NA sendp 失败: %s (idx=%s)，将走系统 fallback",
                                           iface.name, e1, iface.idx)
                        return 0
                return sent
            except Exception as e_outer:
                # 外层兜底：构造阶段（inet_pton/import/包构造）异常（iface_arg 可能未定义，不引用）
                self._scapy_sendp_ok = False
                logger.warning("NDP 防护: 接口 %s NA 构造/发送异常: %s", iface.name, e_outer)
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
            # 审计修复：netsh 输出编码不固定（本机实测为 UTF-8，但 _decode_win_output 首选
            # cp936 解码 UTF-8 字节产生乱码名称（'浠ュお缃 2'）→ 与 ipconfig 的 '以太网 2' 匹配失败、
            # idx 返回 0。对 locale/utf-8/gbk/utf-16 全部尝试解析，所有名称键均入映射，正确名必命中。
            encodings = []
            pref = locale.getpreferredencoding(False)
            for enc in (pref, 'utf-8', 'gbk', 'utf-16'):
                if enc and enc not in encodings:
                    encodings.append(enc)
            for enc in encodings:
                try:
                    text = stdout.decode(enc, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    continue
                for line in text.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 5 and parts[0].isdigit():
                        idx = int(parts[0])
                        name = " ".join(parts[4:]).strip()
                        if name:
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
                # 尝试用接口索引优先（避免 interface= 编码问题）
                iface_idx = await self._resolve_iface_idx(iface_name)
                # 审计修复：netsh set neighbors 统一用 interface= 语法（原 name= 是无效参数但
                # netsh 报错时 rc 仍为 0 → 假成功）；并捕获 stdout（netsh 错误提示输出到 stdout，
                # 如"请求的操作需要提升"），结合 rc 与输出文本判断真实成功
                if iface_idx > 0:
                    args = ["netsh", "interface", "ipv6", "set", "neighbors",
                            f"interface={iface_idx}",
                            f"address={gw.split(chr(37))[0]}", f"neighbor={mac_fmt}"]
                else:
                    args = ["netsh", "interface", "ipv6", "set", "neighbors",
                            f"interface={iface_name}",
                            f"address={gw.split(chr(37))[0]}", f"neighbor={mac_fmt}"]
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    sout, serr = await asyncio.wait_for(proc.communicate(), timeout=10)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    logger.warning("NDP 防护: 静态 NDP 绑定超时 %s -> %s", gw, mac)
                    return False
                # 审计修复：netsh 错误输出编码不固定（本机实测 UTF-8，_decode_win_output 首选 cp936 会乱码），
                # 判定时拼接 utf-8/gbk 两种解码，任一含失败关键词即判失败（防 rc=0 假成功残留）；
                # 日志显示 _decode_win_output 单版本
                _chk = ""
                for _b in (sout, serr):
                    if not _b:
                        continue
                    for _enc in ('utf-8', 'gbk'):
                        try:
                            _chk += _b.decode(_enc, errors='replace')
                        except Exception:
                            pass
                out_text = NDPProtection._decode_win_output(sout) if sout else ""
                err_text = NDPProtection._decode_win_output(serr) if serr else ""
                combined = _chk
                # netsh 语法错误/权限不足：rc 可能为 0（name= 假成功）或 1，须结合输出文本判断
                # 关键词覆盖：权限提升/语法错误/拒绝访问/找不到接口/参数无效（security_review MEDIUM 补全）
                if proc.returncode == 0 and not any(k in combined for k in
                        ("提升", "elevated", "语法", "有效参数", "不是这个指令",
                         "拒绝", "denied", "找不到", "not found", "Access",
                         "参数不正确", "无效参数", "incorrect", "invalid", "parameter")):
                    iface_log = iface_name if vlan_id else iface
                    logger.info("NDP 防护: 静态 NDP %s -> %s (%s)", gw, mac, iface_log)
                    return True
                logger.warning("NDP 防护: 静态 NDP 绑定失败 %s -> %s (code=%d, out=%s, err=%s)",
                               gw, mac, proc.returncode,
                               out_text.strip()[:100], err_text.strip()[:100])
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

    @staticmethod
    def _generate_poison_mac() -> str:
        """生成一个单播、locally administered 的虚假 MAC（不会与真实设备冲突）
        使用 02:00:00:xx:xx:xx 范围（locally administered unicast，后 3 字节随机，
        与 _on_ndp_packet_sync 的 startswith("020000") 防环路一致），
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
            "trusted_sender_macs": len(self._trusted_sender_macs),
            "suspicious_zero_mac": len(self._suspicious_zero_mac),
            "interface_details": [{
                "name": iface.name, "mac": iface.mac,
                "ipv6_global": iface.ipv6_global, "ipv6_globals": iface.ipv6_globals, "ipv6_ll": iface.ipv6_ll,
                "gateways": iface.gateways,
            } for iface in self.interfaces],
        }

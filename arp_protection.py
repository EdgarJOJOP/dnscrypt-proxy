"""
ARP 防护模块
- 自动探测网关 IPv4 地址和 MAC 地址（支持 Windows / Linux）
- 支持手动配置网关 IP/MAC（配置中指定后跳过自动探测）
- 网络故障时检查本地网卡状态（IPv4/IPv6 地址、子网掩码、网关是否正常存在）
- 本地网卡正常但 ping 不通时，发送流量刷新路由器 ARP 表
"""

import re
import sys
import asyncio
import logging
from typing import Optional, Tuple

logger = logging.getLogger("dns-proxy.arp")


class ARPProtection:
    """ARP 防护：网关侦测 + 路由器 ARP 表刷新"""

    def __init__(self, config_arp: dict):
        """
        Args:
            config_arp: 从配置读取的 arp_protection 字典
        """
        self._enabled = config_arp.get("enabled", True)

        # 解析 gateway 逗号格式（支持多组 "IP1,MAC1,IP2,MAC2" 交替逗号格式）
        self._manual_gateways: list = []  # [(ip, mac), ...] — 手动配置的全部网关
        gw_field = config_arp.get("gateway", "") or ""
        if isinstance(gw_field, str) and gw_field:
            pairs = self._parse_gateway_field(gw_field)
            if pairs:
                self._manual_gateways = pairs
            else:
                # 解析失败，尝试旧字段
                old_ip = config_arp.get("gateway_ip", "") or ""
                old_mac = config_arp.get("gateway_mac", "") or ""
                if old_ip:
                    self._manual_gateways = [(old_ip, old_mac)]
        if not self._manual_gateways:
            old_ip = config_arp.get("gateway_ip", "") or ""
            old_mac = config_arp.get("gateway_mac", "") or ""
            if old_ip:
                self._manual_gateways = [(old_ip, old_mac)]

        self._manual_gateway_ip = self._manual_gateways[0][0] if self._manual_gateways else ""
        self._manual_gateway_mac = self._manual_gateways[0][1] if self._manual_gateways else ""

        # 自动探测结果（手动设置时这些保持 None）
        self._auto_gateway_ip: Optional[str] = None
        self._auto_gateway_mac: Optional[str] = None

        # 探测状态
        self._detected = False          # 是否已完成自动探测
        self._last_refresh_time = 0.0   # 上次 ARP 刷新时间

        # 本机网卡信息（从 ipconfig 解析填充）
        self._local_ipv4: Optional[str] = None
        self._subnet_mask: Optional[str] = None
        self._interface_name: Optional[str] = None  # 网卡名称（用于 netsh）

        # ARP 攻击检测
        self._arp_attack_detected = False  # 是否检测到持续的 ARP 异常
        self._arp_attack_logged = False    # 是否已记录攻击警告（避免重复刷屏）
        self._conflict_resolved = False    # 本周期是否已自动修复 IP 冲突

    @staticmethod
    def _parse_gateway_field(gw_field: str) -> list:
        """
        解析 gateway 逗号格式，支持单组和多组。
        格式: "IP1,MAC1,IP2,MAC2" (交替逗号分隔)

        IP 含 `.`，MAC 含 `-` 或 `:`，根据内容区分。
        MAC 可留空（自动探测），但逗号占位不能省略。
        示例:
          "192.168.1.1,00-11-22-33-44-55"                    → 1 组
          "192.168.1.1,00-11-22-33-44-55,10.0.0.1,aa-bb-cc-dd-ee-ff"  → 2 组
          "192.168.1.1,"                                       → IP 手动，MAC 自动
          "192.168.1.1"                                        → 仅有 IP（无逗号）

        Returns:
            [(ip, mac), ...] 列表，解析失败返回 []
        """
        parts = [p.strip() for p in gw_field.split(",")]
        pairs = []
        i = 0
        while i < len(parts):
            val = parts[i]
            if not val:
                i += 1
                continue
            if "." in val:
                # 这是 IP
                ip = val
                mac = ""
                if i + 1 < len(parts):
                    next_val = parts[i + 1]
                    # 下一个值如果是 MAC（含 - 或 :）或者是空，则是当前 IP 的 MAC
                    if not next_val or "-" in next_val or ":" in next_val:
                        mac = next_val
                        i += 2
                    else:
                        i += 1
                else:
                    i += 1
                pairs.append((ip, mac))
            else:
                # 不是 IP 也不是 MAC → 跳过（格式异常）
                i += 1
        return pairs

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def gateway_ip(self) -> Optional[str]:
        """获取网关 IP：手动 > 自动探测"""
        if self._manual_gateway_ip:
            return self._manual_gateway_ip
        return self._auto_gateway_ip

    @property
    def gateway_mac(self) -> Optional[str]:
        """获取网关 MAC：手动 > 自动探测"""
        if self._manual_gateway_mac:
            return self._manual_gateway_mac
        return self._auto_gateway_mac

    @property
    def gateway_pairs(self) -> list:
        """返回全部网关 (IP, MAC) 列表（手动 + 自动）"""
        pairs = list(self._manual_gateways)
        if self._auto_gateway_ip:
            # 如果自动探测的网关不在手动列表中，追加
            if not any(ip == self._auto_gateway_ip for ip, _ in pairs):
                pairs.append((self._auto_gateway_ip, self._auto_gateway_mac or ""))
        return pairs

    @property
    def is_manual(self) -> bool:
        """全部网关均为手动配置（每组都有 IP+MAC）时跳过自动探测"""
        if not self._manual_gateways:
            return False
        return all(bool(ip) and bool(mac) for ip, mac in self._manual_gateways)

    # ======================== 自动探测 ========================

    async def detect_gateway(self) -> bool:
        """
        自动探测网关 IPv4 地址和 MAC 地址。
        先查默认网关 IP，再查对应 MAC。
        返回 True 表示成功。
        """
        if self._detected:
            return self.gateway_ip is not None

        if sys.platform == "win32":
            ok = await self._detect_windows()
        else:
            ok = await self._detect_linux()
        self._detected = True

        if ok:
            src = "手动配置" if self._manual_gateway_ip else "自动探测"
            if len(self._manual_gateways) > 1:
                pairs_str = "; ".join(f"{ip},{mac or '*'}" for ip, mac in self._manual_gateways)
                logger.info("ARP 防护: 多网关 %s -> %s", src, pairs_str)
            else:
                logger.info("ARP 防护: 网关 %s -> IP=%s, MAC=%s",
                             src, self.gateway_ip, self.gateway_mac or "未知")
        else:
            logger.warning("ARP 防护: 无法自动探测网关地址（防火墙可能阻止了探测）")
        return ok

    async def _detect_windows(self) -> bool:
        """Windows 上探测网关 IP + MAC，通过路由表精确定位网卡"""
        # 1. 如果已有手动 IP 但无 MAC，为所有手动网关查 MAC
        if self._manual_gateway_ip and not self._manual_gateway_mac:
            all_ok = True
            for i, (ip, mac) in enumerate(self._manual_gateways):
                if ip and not mac:
                    detected_mac = await self._arp_get_mac_windows(ip)
                    if detected_mac:
                        self._manual_gateways[i] = (ip, detected_mac)
                    else:
                        all_ok = False
            if all_ok:
                self._manual_gateway_mac = self._manual_gateways[0][1]
                return True
            return False

        # 2. 自动探测：通过路由表精确解析网关 IP 和网卡信息
        if not self._manual_gateway_ip:
            iface_info = await self._resolve_interface_windows()
            if not iface_info:
                return False
            self._auto_gateway_ip = iface_info["gateway_ip"]
            # 同步更新本机网卡信息（供后续 check_interface / IP 冲突使用）
            if not self._local_ipv4:
                self._local_ipv4 = iface_info["local_ipv4"]
            if not self._subnet_mask:
                self._subnet_mask = iface_info["subnet_mask"]
            if not self._interface_name:
                self._interface_name = iface_info["interface_name"]

        # 3. 查网关 MAC
        target_ip = self.gateway_ip
        if target_ip:
            mac = await self._arp_get_mac_windows(target_ip)
            if mac:
                self._auto_gateway_mac = mac
                return True
            logger.debug("ARP 防护: 无法获取网关 %s 的 MAC 地址", target_ip)
            return True
        return False

    async def _detect_linux(self) -> bool:
        """Linux 上探测网关 IP + MAC，通过路由表精确定位网卡"""
        # 1. 如果已有手动 IP 但无 MAC，为所有手动网关查 MAC
        if self._manual_gateway_ip and not self._manual_gateway_mac:
            all_ok = True
            for i, (ip, mac) in enumerate(self._manual_gateways):
                if ip and not mac:
                    detected_mac = await self._arp_get_mac_linux(ip)
                    if detected_mac:
                        self._manual_gateways[i] = (ip, detected_mac)
                    else:
                        all_ok = False
            if all_ok:
                self._manual_gateway_mac = self._manual_gateways[0][1]
                return True
            return False

        # 2. 自动探测
        if not self._manual_gateway_ip:
            iface_info = await self._resolve_interface_linux()
            if not iface_info:
                return False
            self._auto_gateway_ip = iface_info["gateway_ip"]
            if not self._local_ipv4:
                self._local_ipv4 = iface_info["local_ipv4"]
            if not self._subnet_mask:
                self._subnet_mask = iface_info["subnet_mask"]
            if not self._interface_name:
                self._interface_name = iface_info["interface_name"]

        target_ip = self.gateway_ip
        if target_ip:
            mac = await self._arp_get_mac_linux(target_ip)
            if mac:
                self._auto_gateway_mac = mac
            else:
                logger.debug("ARP 防护: 无法获取网关 %s 的 MAC 地址", target_ip)
            return True
        return False

    # ======================== 网卡接口精确定位 ========================
    #
    # 核心策略：先通过路由表找到默认路由的网关 IP 和接口 IP，
    # 再通过接口 IP 交叉匹配 ipconfig / ip addr 找到正确的网卡名称。
    # 不受网卡改名影响，适配多 IP / 多网关场景。

    async def _resolve_interface_windows(self) -> Optional[dict]:
        """
        Windows：通过 route print + ipconfig 精确定位拥有默认路由的网卡。
        支持多默认路由，按 metric 取最优。多网卡多 IP 场景下只选中默认路由的网卡。
        返回 {gateway_ip, local_ipv4, subnet_mask, interface_name, metric, all_gateways} 或 None。
        """
        # 1. route print 0.0.0.0 找到所有默认路由 → 按 metric 排序
        routes = []  # [(gateway_ip, iface_ip, metric), ...]
        try:
            proc = await asyncio.create_subprocess_exec(
                "route", "print", "0.0.0.0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                parts = line.strip().split()
                # 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  25
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2].strip()
                    if gw and gw != "0.0.0.0" and ":" not in gw:
                        if_ip = parts[3].strip() if len(parts) >= 4 else None
                        try:
                            met = int(parts[4].strip())
                        except (ValueError, IndexError):
                            met = 9999
                        routes.append((gw, if_ip, met))
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: route print 失败: %s", e)

        if not routes:
            return None

        # 按 metric 升序排序，取最优
        routes.sort(key=lambda x: x[2])
        gateway_ip, iface_ip, metric = routes[0]
        all_gateways = [{"ip": gw, "iface_ip": ip, "metric": m} for gw, ip, m in routes]

        if len(routes) > 1:
            logger.debug("ARP 防护: 检测到 %d 条默认路由，选用 metric=%d (网关=%s)",
                         len(routes), metric, gateway_ip)

        # 2. ipconfig 按适配器分段解析，找到匹配接口 IP 的网卡
        interface_name = None
        local_ipv4 = None
        subnet_mask = None

        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: ipconfig 失败: %s", e)
            text = ""

        if text:
            # 按空行分段，每段 = 一个适配器信息
            raw_sections = re.split(r'\n\s*\n', text)
            for section in raw_sections:
                lines = section.strip().splitlines()
                if not lines:
                    continue

                # 提取适配器名称行
                # "以太网适配器 以太网:" 或 "Ethernet adapter Ethernet:"
                name_line = lines[0].strip()
                current_name = None
                for prefix in ("以太网适配器 ", "Ethernet adapter ",
                               "无线局域网适配器 ", "Wireless LAN adapter ",
                               "本地连接", "Local Area Connection"):
                    if prefix in name_line:
                        candidate = name_line[name_line.index(prefix) + len(prefix):].rstrip(":")
                        if candidate:
                            current_name = candidate
                        break

                if not current_name:
                    continue

                # 扫描本段中的所有 IPv4 地址
                section_ipv4 = None
                section_mask = None
                for line in lines:
                    s = line.strip()
                    # IPv4 地址
                    for key in ("IPv4", "IP Address", "IPv4 地址"):
                        if key in s and ":" in s:
                            ip = s.split(":", 1)[1].strip()
                            if ip and "." in ip and not ip.startswith("127."):
                                section_ipv4 = ip
                                break
                    # 子网掩码
                    for key in ("子网掩码", "Subnet Mask"):
                        if key in s and ":" in s:
                            mask = s.split(":", 1)[1].strip()
                            if mask and "." in mask and mask != "0.0.0.0":
                                section_mask = mask
                                break

                # 检查 IPv4 是否匹配路由表中的接口 IP
                if section_ipv4 and section_ipv4 == iface_ip:
                    interface_name = current_name
                    local_ipv4 = section_ipv4
                    subnet_mask = section_mask or subnet_mask
                    break

        # 3. 如果 ipconfig 没找到匹配（罕见情况），用 route 的信息兜底
        if not local_ipv4:
            local_ipv4 = iface_ip

        result = {
            "gateway_ip": gateway_ip,
            "local_ipv4": local_ipv4,
            "subnet_mask": subnet_mask,
            "interface_name": interface_name or iface_ip,
            "metric": metric,
            "all_gateways": all_gateways,
        }
        return result

    async def _resolve_interface_linux(self) -> Optional[dict]:
        """
        Linux：通过 ip route + ip addr 精确定位拥有默认路由的网卡。
        返回 {gateway_ip, local_ipv4, subnet_mask, interface_name, metric, all_gateways} 或 None。
        """
        gateway_ip = None
        iface_name = None

        # 1. ip route show default → 获取所有默认路由，按 metric 取最优
        routes = []  # [(gateway_ip, iface_name, metric), ...]
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "route", "show", "default",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                # default via 192.168.1.1 dev eth0  metric 100
                m = re.match(
                    r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)(?:\s+metric\s+(\d+))?',
                    line.strip()
                )
                if m:
                    gw = m.group(1)
                    dev = m.group(2)
                    met = int(m.group(3)) if m.group(3) else 9999
                    routes.append((gw, dev, met))
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: ip route 失败: %s", e)

        if not routes:
            return None

        routes.sort(key=lambda x: x[2])
        gateway_ip, iface_name, metric = routes[0]
        all_gateways = [{"ip": gw, "iface": dev, "metric": m} for gw, dev, m in routes]

        if len(routes) > 1:
            logger.debug("ARP 防护: 检测到 %d 条默认路由，选用 metric=%d (网关=%s, 网卡=%s)",
                         len(routes), metric, gateway_ip, iface_name)

        # 2. ip -4 addr show dev <iface> → 获取 IP 和前缀
        local_ipv4 = None
        subnet_mask = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-4", "addr", "show", "dev", iface_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m and not m.group(1).startswith("127."):
                    local_ipv4 = m.group(1)
                    prefix = int(m.group(2))
                    subnet_mask = ".".join(
                        str((0xFFFFFFFF << (32 - prefix) >> (8 * (3 - i))) & 0xFF)
                        for i in range(4)
                    )
                    break
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: ip addr show %s 失败: %s", iface_name, e)

        if not local_ipv4:
            return None

        return {
            "gateway_ip": gateway_ip,
            "local_ipv4": local_ipv4,
            "subnet_mask": subnet_mask,
            "interface_name": iface_name,
            "metric": metric,
            "all_gateways": all_gateways,
        }

    # ======================== 网关 IP 探测 ========================

    @staticmethod
    async def _find_gateway_ip_windows() -> Optional[str]:
        """Windows: 通过 route print 获取默认网关"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "route", "print", "0.0.0.0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")

            # 解析 route print 输出中的默认网关
            # 匹配: 0.0.0.0          0.0.0.0         192.168.1.1      192.168.1.100    25
            for line in text.splitlines():
                if "0.0.0.0" in line and "0.0.0.0" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        gateway = parts[2].strip()
                        if gateway and gateway != "0.0.0.0" and ":" not in gateway:
                            return gateway
            return None
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: route print 失败: %s", e)
            return None

    @staticmethod
    async def _find_gateway_ip_linux() -> Optional[str]:
        """Linux: 通过 ip route 获取默认网关"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "route",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            # 匹配: default via 192.168.1.1 dev eth0
            for line in text.splitlines():
                m = re.match(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', line.strip())
                if m:
                    return m.group(1)
            return None
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: ip route 失败: %s", e)
            return None

    # ======================== MAC 探测 ========================

    @staticmethod
    async def _arp_get_mac_windows(ip: str) -> Optional[str]:
        """Windows: 通过 arp -a 获取指定 IP 的 MAC 地址"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "arp", "-a", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")

            # 匹配: 192.168.1.1         00-11-22-33-44-55     dynamic
            # MAC 格式: xx-xx-xx-xx-xx-xx
            for line in text.splitlines():
                if ip in line:
                    parts = line.strip().split()
                    for part in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$', part):
                            return part.upper()
            return None
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: arp -a %s 失败: %s", ip, e)
            return None

    @staticmethod
    async def _arp_get_mac_linux(ip: str) -> Optional[str]:
        """Linux: 通过 ip neigh 获取指定 IP 的 MAC 地址"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            # 匹配: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
            m = re.search(r'lladdr\s+(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', text)
            if m:
                return m.group(1).upper()
            return None
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: ip neigh show %s 失败: %s", ip, e)
            return None

    # ======================== 本地网卡状态检查 ========================

    async def check_interface_healthy(self) -> Tuple[bool, str]:
        """
        检查本地网卡接口配置是否正常。
        返回 (healthy, details)：
          healthy=True 表示网卡有 IP 地址、子网掩码、默认网关，配置正常。
          healthy=False 表示网卡本身配置异常（如未获取到 IP），属于断网而非 ARP 问题。
        """
        if sys.platform == "win32":
            return await self._check_interface_windows()
        else:
            return await self._check_interface_linux()

    async def _check_interface_windows(self) -> Tuple[bool, str]:
        """Windows: 通过路由表精确定位默认路由网卡，检查其状态"""
        iface_info = await self._resolve_interface_windows()
        if iface_info:
            # 更新本机网卡信息
            self._local_ipv4 = iface_info["local_ipv4"]
            if iface_info["subnet_mask"]:
                self._subnet_mask = iface_info["subnet_mask"]
            if iface_info["interface_name"]:
                self._interface_name = iface_info["interface_name"]

            has_ipv4 = bool(iface_info["local_ipv4"])
            has_gateway = True  # route print 确认有默认路由
            has_ipv6 = await self._check_ipv6_windows()

            details = f"IPv4={'正常' if has_ipv4 else '无'}, IPv6={'正常' if has_ipv6 else '无'}, 网关=存在"
            return has_ipv4, details

        # 兜底：route print 失败，回退到 ipconfig 扫描
        return await self._check_interface_windows_fallback()

    async def _check_ipv6_windows(self) -> bool:
        """Windows: 检查是否有非环回 IPv6 地址"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                s = line.strip()
                if "IPv6" in s or "IPv6 地址" in s:
                    parts = s.split(":", 1)
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if ip and ip != "::1" and ":" in ip:
                            return True
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass
        return False

    async def _check_interface_windows_fallback(self) -> Tuple[bool, str]:
        """Windows 兜底：传统 ipconfig 全量扫描（当 route print 不可用时）"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            return False, f"ipconfig 执行失败: {e}"

        has_ipv4 = False
        has_ipv6 = False
        has_gateway = False
        current_adapter = ""

        for line in text.splitlines():
            stripped = line.strip()

            for prefix in ("以太网适配器 ", "Ethernet adapter ",
                           "无线局域网适配器 ", "Wireless LAN adapter ",
                           "本地连接", "Local Area Connection"):
                if prefix in stripped:
                    name_part = stripped[stripped.index(prefix) + len(prefix):].rstrip(":")
                    if name_part:
                        current_adapter = name_part
                        if not self._interface_name:
                            self._interface_name = current_adapter
                    break

            if "IPv4" in stripped or "IP Address" in stripped or "IPv4 地址" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and ip != "127.0.0.1" and "." in ip:
                        has_ipv4 = True
                        if not self._local_ipv4:
                            self._local_ipv4 = ip

            if "子网掩码" in stripped or "Subnet Mask" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    mask = parts[1].strip()
                    if mask and mask != "0.0.0.0" and "." in mask:
                        if not self._subnet_mask:
                            self._subnet_mask = mask

            if "IPv6" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    ip = parts[1].strip()
                    if ip and ip != "::1" and ":" in ip:
                        has_ipv6 = True

            if "默认网关" in stripped or "Default Gateway" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    gw = parts[1].strip()
                    if gw and gw != "0.0.0.0" and gw != ":":
                        has_gateway = True

        details = f"IPv4={'正常' if has_ipv4 else '无'}, IPv6={'正常' if has_ipv6 else '无'}, 网关={'存在' if has_gateway else '无'}"
        return has_gateway, details

    async def _check_interface_linux(self) -> Tuple[bool, str]:
        """Linux: 通过路由表精确定位默认路由网卡，检查其状态"""
        iface_info = await self._resolve_interface_linux()
        if iface_info:
            self._local_ipv4 = iface_info["local_ipv4"]
            if iface_info["subnet_mask"]:
                self._subnet_mask = iface_info["subnet_mask"]
            if iface_info["interface_name"]:
                self._interface_name = iface_info["interface_name"]

            has_ipv4 = bool(iface_info["local_ipv4"])
            has_gateway = True
            has_ipv6 = await self._check_ipv6_linux()

            details = f"IPv4={'正常' if has_ipv4 else '无'}, IPv6={'正常' if has_ipv6 else '无'}, 网关=存在"
            return has_ipv4, details

        return False, "无法解析默认路由接口"

    async def _check_ipv6_linux(self) -> bool:
        """Linux: 检查是否有非环回 IPv6 地址"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-6", "addr", "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                m = re.search(r'inet6\s+([0-9a-f:]+)', line.lower())
                if m and m.group(1) != "::1":
                    return True
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass
        return False

    # ======================== 广播地址与 GARP ========================

    def _get_broadcast_address(self) -> Optional[str]:
        """
        根据本机 IPv4 地址和子网掩码计算子网广播地址。
        例如: 192.168.1.100 / 255.255.255.0 → 192.168.1.255
        """
        if not self._local_ipv4 or not self._subnet_mask:
            return None
        try:
            ip_parts = [int(x) for x in self._local_ipv4.split(".")]
            mask_parts = [int(x) for x in self._subnet_mask.split(".")]
            broadcast = ".".join(str(ip_parts[i] | (~mask_parts[i] & 0xFF)) for i in range(4))
            return broadcast
        except (ValueError, IndexError):
            return None

    async def _detect_ip_conflict(self) -> Optional[str]:
        """
        通过 arp -a 检查本机 IP 是否有多个不同 MAC 地址（IP 冲突）。
        返回冲突描述信息，无冲突则返回 None。
        """
        if not self._local_ipv4:
            return None

        try:
            # 先 ping 本机 IP，触发 ARP 解析
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "arp", "-a", self._local_ipv4,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "neigh", "show", self._local_ipv4,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")

            # Windows: arp -a 输出中找本机 IP
            if sys.platform == "win32" and self._local_ipv4 in text:
                for line in text.splitlines():
                    if self._local_ipv4 in line and "dynamic" in line.lower():
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}', line)
                        if mac_match:
                            return f"IP冲突检测: 本机 {self._local_ipv4} 在 ARP 表中存在条目 (MAC={mac_match.group(0)})，可能有另一设备使用相同 IP"
            # Linux: ip neigh 输出中找本机 IP
            elif not sys.platform.startswith("win") and self._local_ipv4 in text:
                m = re.search(r'lladdr\s+(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', text)
                if m:
                    return f"IP冲突检测: 本机 {self._local_ipv4} 在邻居表中存在条目 (MAC={m.group(1)})，可能有另一设备使用相同 IP"
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            pass
        return None

    @staticmethod
    def _increment_ip(ip: str, subnet_mask: Optional[str] = None,
                      offset: int = 1) -> Optional[str]:
        """
        IPv4 地址在主机位范围内 +offset，根据子网掩码判断网络位/主机位边界。
        若 +offset 到达广播地址（主机位全 1）或溢出，则改为尝试 -offset 递减。

        例如 (offset=1):
          192.168.1.100 / 255.255.255.0  →  192.168.1.101
          192.168.1.254 / 255.255.255.0  →  192.168.1.253  (+1 到 255 广播，改递减)
          192.168.1.254 / 255.255.0.0    →  192.168.1.255  (主机位未溢出的有效地址)

        offset=50 时，将 IP 偏移 50 位（用于 GARP 两阶段切换的临时 IP）:
          192.168.1.100 / 24 → 192.168.1.150
          192.168.1.230 / 24 → 192.168.1.180  (+50 越界，改 -50)
        """
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) != 4:
                return None
            ip_int = (parts[0] << 24 | parts[1] << 16 |
                      parts[2] << 8 | parts[3])
        except (ValueError, IndexError):
            return None

        if subnet_mask:
            try:
                mask_parts = [int(x) for x in subnet_mask.split(".")]
                if len(mask_parts) != 4:
                    return None
                mask_int = (mask_parts[0] << 24 | mask_parts[1] << 16 |
                            mask_parts[2] << 8 | mask_parts[3])
            except (ValueError, IndexError):
                mask_int = 0xFFFFFF00  # 默认 /24

            network = ip_int & mask_int           # 网络位不变
            host_max = (~mask_int) & 0xFFFFFFFF    # 主机位最大值
        else:
            network = ip_int & 0xFFFFFF00          # 默认最后 8 位是主机位
            host_max = 0xFF

        host = ip_int & host_max                   # 主机位当前值
        new_host = host + offset

        if new_host >= host_max or new_host <= 0:
            # 正向偏移溢出（如 .254 + 50），改尝试反向偏移
            new_host = host - offset
            if new_host <= 0 or new_host >= host_max:
                return None  # 无法找到安全地址

        new_ip_int = network | new_host
        return ".".join(str((new_ip_int >> (8 * (3 - i))) & 0xFF) for i in range(4))

    async def _resolve_ip_conflict_windows(self) -> bool:
        """
        自动修复 IP 冲突：将本机 IPv4 +1，子网掩码和网关不变。
        使用 netsh interface ipv4 set address 命令（需要管理员权限）。
        """
        if not self._local_ipv4 or not self._subnet_mask or not self._interface_name:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（缺少网卡信息）")
            return False

        new_ip = self._increment_ip(self._local_ipv4, self._subnet_mask)
        if not new_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP %s 无法递增）", self._local_ipv4)
            return False

        gw_ip = self.gateway_ip

        logger.warning("ARP 防护: 自动修复 IP 冲突 %s → %s (掩码=%s, 网关=%s)",
                        self._local_ipv4, new_ip, self._subnet_mask, gw_ip or "无")

        try:
            cmd = ["netsh", "interface", "ipv4", "set", "address",
                   f"name={self._interface_name}",
                   f"source=static",
                   f"address={new_ip}",
                   f"mask={self._subnet_mask}"]
            if gw_ip:
                cmd.append(f"gateway={gw_ip}")
                cmd.append("gwmetric=1")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            if proc.returncode == 0:
                self._local_ipv4 = new_ip
                self._conflict_resolved = True
                logger.warning("ARP 防护: IP 已成功变更为 %s", new_ip)
                return True
            else:
                err_text = stderr.decode("utf-8", errors="replace")[:200]
                logger.warning("ARP 防护: netsh 执行失败 (code=%d): %s",
                               proc.returncode, err_text)
                return False
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: netsh 执行异常: %s", e)
            return False

    @staticmethod
    def _subnet_mask_to_prefix(mask: str) -> Optional[int]:
        """子网掩码转前缀长度，如 255.255.255.0 → 24"""
        try:
            parts = [int(x) for x in mask.split(".")]
            if len(parts) != 4:
                return None
            binary = "".join(format(p, '08b') for p in parts)
            if '01' in binary.rstrip('0'):  # 掩码不是连续的1（非法）
                return None
            return binary.count('1')
        except (ValueError, IndexError):
            return None

    async def _resolve_ip_conflict_linux(self) -> bool:
        """
        自动修复 IP 冲突（Linux）：ip addr del 旧IP → ip addr add 新IP。
        需要 root 权限。
        """
        if not self._local_ipv4 or not self._subnet_mask or not self._interface_name:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（缺少网卡信息）")
            return False

        new_ip = self._increment_ip(self._local_ipv4, self._subnet_mask)
        if not new_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP %s 无法递增）", self._local_ipv4)
            return False

        prefix = self._subnet_mask_to_prefix(self._subnet_mask)
        if prefix is None:
            logger.warning("ARP 防护: 无法解析子网掩码 %s", self._subnet_mask)
            return False

        gw_ip = self.gateway_ip

        logger.warning("ARP 防护: 自动修复 IP 冲突 %s → %s (掩码=%s, 网关=%s)",
                        self._local_ipv4, new_ip, self._subnet_mask, gw_ip or "无")

        try:
            # 先删除旧 IP
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "del", f"{self._local_ipv4}/{prefix}",
                "dev", self._interface_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:200]
                logger.warning("ARP 防护: ip addr del 失败: %s", err)

            # 添加新 IP
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "add", f"{new_ip}/{prefix}",
                "dev", self._interface_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:200]
                logger.warning("ARP 防护: ip addr add 失败: %s", err)
                return False

            # 如果原来有默认网关，重新添加路由
            if gw_ip:
                await asyncio.create_subprocess_exec(
                    "ip", "route", "replace", "default", "via", gw_ip,
                    "dev", self._interface_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )

            self._local_ipv4 = new_ip
            self._conflict_resolved = True
            logger.warning("ARP 防护: IP 已成功变更为 %s", new_ip)
            return True
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: ip addr 执行异常: %s", e)
            return False

    async def _check_arp_poisoning(self) -> list:
        """
        检查本机 ARP 表中所有已知网关的 MAC 是否与预期一致。
        如果网关 MAC 变了（网关不会无故变 MAC），说明本机 ARP 缓存被投毒。

        Returns:
            被投毒的网关列表 [(gateway_ip, 预期MAC, 实际MAC), ...]
        """
        poisoned = []
        for gw_ip, expected_mac in self.gateway_pairs:
            if not gw_ip or not expected_mac:
                continue
            if sys.platform == "win32":
                actual_mac = await self._arp_get_mac_windows(gw_ip)
            else:
                actual_mac = await self._arp_get_mac_linux(gw_ip)
            if actual_mac and actual_mac.upper() != expected_mac.upper():
                poisoned.append((gw_ip, expected_mac, actual_mac))
                self._arp_attack_logged = True
        return poisoned

    # ======================== 刷新路由器 ARP 表 ========================

    async def refresh_router_arp(self) -> bool:
        """
        针对路由器 ARP 表被篡改或 IP 冲突的高级修复策略：

        1. ARP 投毒检测 → 对比本机 ARP 表中网关 MAC 与预期值
        2. 爆发 ping 网关（10 次，10ms 间隔）→ 强制路由器更新本机 IP-MAC
        3. 爆发 GARP 广播（20 次 ping 广播地址）→ 全子网饱和宣告本机 IP-MAC
        4. 检测 IP 冲突 → 如发现冲突，自动 IP +1（子网掩码和网关不变）
        5. 如果以上都失败 → 两阶段 IP 切换抗 ARP 中毒
        """
        gw_ip = self.gateway_ip
        if not gw_ip:
            logger.warning("ARP 防护: 无法刷新路由器 ARP，未知网关 IP")
            return False

        self._arp_attack_logged = False
        logger.info("ARP 防护: 正在修复路由器 ARP 表 (网关=%s)...", gw_ip)

        # 0. ARP 投毒检测：检查本机 ARP 表中各网关 MAC 是否被篡改
        poisoned = await self._check_arp_poisoning()
        if poisoned:
            for gw_ip_poisoned, expected, actual in poisoned:
                logger.warning("ARP 防护: 检测到本机 ARP 表被篡改！"
                               "网关 %s → 预期 %s ≠ 实际 %s（MITM 攻击）",
                               gw_ip_poisoned, expected, actual)
            logger.warning("ARP 防护: 正在执行抗投毒修复...")
        else:
            logger.debug("ARP 防护: 本机 ARP 表正常，未检测到投毒")

        # 1. 爆发 ping 网关（10 次，10ms 间隔）
        #    路由器收到本机 IP 包 → 看到源 MAC → 更新 ARP 表中本机 IP↔MAC
        #    增加次数（3→10）抵抗攻击者的快速重投毒
        logger.debug("ARP 防护: 爆发 ping 网关 %s x10", gw_ip)
        for _ in range(10):
            await self._ping_gateway(gw_ip)
            await asyncio.sleep(0.01)

        # 2. 爆发 GARP 广播（20 次 ping 广播地址）
        #    饱和式宣告本机 IP-MAC，覆盖攻击者的伪造 ARP 条目
        await self._garp_broadcast_burst(count=20)

        # 3. 检测 IP 冲突
        conflict = await self._detect_ip_conflict()
        if conflict:
            logger.warning("ARP 防护: %s", conflict)
            self._arp_attack_logged = True
            if sys.platform == "win32":
                if await self._resolve_ip_conflict_windows():
                    await asyncio.sleep(1.0)
                    return True
            else:
                if await self._resolve_ip_conflict_linux():
                    await asyncio.sleep(1.0)
                    return True

        # 4. 验证 ping
        ping_ok = await self._ping_gateway(gw_ip)
        if ping_ok:
            logger.info("ARP 防护: 网关 %s 可达", gw_ip)
            if self._arp_attack_logged and not self._conflict_resolved:
                logger.warning("ARP 防护: 网络已恢复但检测到 ARP 异常，建议检查局域网设备")
            return True

        # 5. 网关仍不可达 → 可能持续 ARP 中毒 → 尝试两阶段 IP 切换抗毒
        logger.warning("ARP 防护: 网关 %s 仍不可达，尝试两阶段 IP 切换抗 ARP 中毒...", gw_ip)
        if await self._garp_ip_switch_defense():
            logger.info("ARP 防护: 两阶段 GARP 切换后网关 %s 可达", gw_ip)
            return True

        logger.warning("ARP 防护: 网关 %s 仍不可达，可能存在持续 ARP 攻击或 IP 冲突", gw_ip)
        self._arp_attack_detected = True
        return False

    async def _garp_broadcast_burst(self, count: int = 20):
        """
        爆发式 GARP 广播：快速连续 ping 子网广播地址。
        全子网设备（包括路由器）收到 ICMP 包后看到本机源 MAC，
        ARP 表会被刷新为本机 IP ↔ 本机 MAC。

        Args:
            count: 发送次数（默认 20 次，间隔 10ms = 200ms 总耗时）
        """
        broadcast_ip = self._get_broadcast_address()
        if not broadcast_ip:
            return

        logger.debug("ARP 防护: GARP 爆发广播 ping %s x%d", broadcast_ip, count)
        for _ in range(count):
            await self._ping_broadcast(broadcast_ip)
            await asyncio.sleep(0.01)

    async def _switch_ip(self, new_ip: str) -> bool:
        """
        将本机 IPv4 地址切换为 new_ip，子网掩码和网关不变。
        用于两阶段 GARP 抗中毒中的临时 IP 切换。

        Args:
            new_ip: 目标 IP 地址

        Returns:
            True 表示切换成功
        """
        if not self._subnet_mask or not self._interface_name:
            return False

        gw_ip = self.gateway_ip

        if sys.platform == "win32":
            cmd = ["netsh", "interface", "ipv4", "set", "address",
                   f"name={self._interface_name}",
                   "source=static",
                   f"address={new_ip}",
                   f"mask={self._subnet_mask}"]
            if gw_ip:
                cmd.extend([f"gateway={gw_ip}", "gwmetric=1"])
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                if proc.returncode != 0:
                    err = stderr.decode("utf-8", errors="replace")[:200]
                    logger.debug("ARP 防护: netsh 切换 IP 失败: %s", err)
                    return False
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("ARP 防护: netsh 切换 IP 异常: %s", e)
                return False
        else:
            prefix = self._subnet_mask_to_prefix(self._subnet_mask)
            if prefix is None:
                return False
            try:
                # 删除旧 IP（忽略删除失败 — 可能已被其他进程删除）
                proc = await asyncio.create_subprocess_exec(
                    "ip", "addr", "del", f"{self._local_ipv4}/{prefix}",
                    "dev", self._interface_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10)
                # 添加新 IP
                proc = await asyncio.create_subprocess_exec(
                    "ip", "addr", "add", f"{new_ip}/{prefix}",
                    "dev", self._interface_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode != 0:
                    err = stderr.decode("utf-8", errors="replace")[:200]
                    logger.debug("ARP 防护: ip addr 切换 IP 失败: %s", err)
                    return False
                # 网关路由
                if gw_ip:
                    await asyncio.create_subprocess_exec(
                        "ip", "route", "replace", "default", "via", gw_ip,
                        "dev", self._interface_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("ARP 防护: ip addr 切换 IP 异常: %s", e)
                return False

    async def _garp_ip_switch_defense(self) -> bool:
        """
        两阶段 GARP 抗 ARP 中毒（MITM）：

        原理：
          如果攻击者持续向路由器发送伪造 ARP 应答（本机 IP → 攻击者 MAC），
          普通 GARP 广播会被立即覆盖。本方法通过临时 IP 切换打破这种持续投毒。

        阶段 1（解绑）：
          将本机 IP 切换为一个临时 IP → 爆发广播 ping →
          路由器和其他设备看到"本机 MAC 的 IP 已变为临时 IP"，
          原先的 IP-MAC 绑定被解绑。

        阶段 2（重新绑定）：
          切回原始 IP → 爆发广播 ping →
          全网设备重新学习正确的 IP-MAC 绑定。

        攻击者在阶段 1 期间投毒的条目（原始 IP → 攻击者 MAC）
        在阶段 2 开始后会被我们的宣告覆盖。

        Returns:
            True 表示切换后网关可达
        """
        original_ip = self._local_ipv4
        if not original_ip or not self._subnet_mask:
            logger.debug("ARP 防护: 缺少 IP 或子网掩码，无法执行两阶段 GARP")
            return False

        # 计算临时 IP（在当前主机位范围内偏移 50，避免冲突）
        decoy_ip = self._increment_ip(original_ip, self._subnet_mask, offset=50)
        if not decoy_ip or decoy_ip == original_ip:
            logger.debug("ARP 防护: 无法生成临时 IP，跳过两阶段 GARP")
            return False

        gw_ip = self.gateway_ip
        logger.warning("ARP 防护: 两阶段 GARP 抗中毒: %s → %s → %s",
                        original_ip, decoy_ip, original_ip)

        # --- 阶段 1：切换到临时 IP，宣告解绑 ---
        logger.debug("ARP 防护: 阶段 1 — 切换到临时 IP %s", decoy_ip)
        if not await self._switch_ip(decoy_ip):
            logger.warning("ARP 防护: 切换到临时 IP %s 失败", decoy_ip)
            return False

        self._local_ipv4 = decoy_ip
        await self._garp_broadcast_burst(count=10)
        # 短暂等待让 ARP 表传播
        await asyncio.sleep(0.3)

        # --- 阶段 2：切回原始 IP，宣告正确绑定 ---
        logger.debug("ARP 防护: 阶段 2 — 切回原始 IP %s", original_ip)
        if not await self._switch_ip(original_ip):
            logger.warning("ARP 防护: 切回原始 IP %s 失败", original_ip)
            self._local_ipv4 = original_ip
            return False

        self._local_ipv4 = original_ip
        await self._garp_broadcast_burst(count=10)
        await asyncio.sleep(0.3)

        # 确认网关可达
        reachable = await self._ping_gateway(gw_ip)
        return reachable

    @staticmethod
    async def _ping_gateway(gw_ip: str) -> bool:
        """ping 网关"""
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", "3000", gw_ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "3", gw_ip]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return False

    @staticmethod
    async def _ping_broadcast(broadcast_ip: str) -> bool:
        """
        ping 子网广播地址，向全子网发送本机 IP-MAC 宣告。
        相当于 Gratuitous ARP，无需管理员权限。
        """
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", "2000", broadcast_ip]
            else:
                cmd = ["ping", "-b", "-c", "1", "-W", "2", broadcast_ip]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=4)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return False

    # ======================== 信息查询 ========================

    @property
    def info(self) -> dict:
        """返回当前 ARP 防护状态信息"""
        return {
            "enabled": self._enabled,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "local_ipv4": self._local_ipv4,
            "subnet_mask": self._subnet_mask,
            "broadcast": self._get_broadcast_address(),
            "manual_ip": bool(self._manual_gateway_ip),
            "manual_mac": bool(self._manual_gateway_mac),
            "detected": self._detected,
            "arp_attack_detected": self._arp_attack_detected,
        }

"""
ARP 防护模块
- 自动探测网关 IPv4 地址和 MAC 地址（支持 Windows / Linux）
- 支持手动配置网关 IP/MAC（配置中指定后跳过自动探测）
- 网络故障时检查本地网卡状态（IPv4/IPv6 地址、子网掩码、网关是否正常存在）
- 本地网卡正常但 ping 不通时，发送流量刷新路由器 ARP 表
"""

import os
import re
import sys
import struct
import asyncio
import socket
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
        self._local_mac: Optional[str] = None  # 本机 MAC（用于发送真实 GARP 包）
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
            # 网关 MAC 已知时设静态 ARP 防止本机缓存被投毒
            if self.gateway_mac:
                await self._protect_gateway_arp()
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
            if not self._local_mac:
                self._local_mac = iface_info.get("local_mac")
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
            logger.warning("ARP 防护: 无法获取网关 %s 的 MAC 地址", target_ip)
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
            if not self._local_mac:
                self._local_mac = iface_info.get("local_mac")
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
                logger.warning("ARP 防护: 无法获取网关 %s 的 MAC 地址", target_ip)
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
                        # 校验接口 IP 合法性，防止 netsh 切换 IP 后路由表临时输出垃圾值
                        if if_ip and not ARPProtection._is_valid_ip(if_ip):
                            logger.debug("ARP 防护: route print 跳过非法接口 IP '%s'", if_ip)
                            continue
                        try:
                            met = int(parts[4].strip())
                        except (ValueError, IndexError):
                            met = 9999
                        routes.append((gw, if_ip, met))
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: route print 失败: %s", e)

        if not routes:
            return None

        # 按 metric 升序排序，取最优
        routes.sort(key=lambda x: x[2])
        gateway_ip, iface_ip, metric = routes[0]
        all_gateways = [{"ip": gw, "iface_ip": ip, "metric": m} for gw, ip, m in routes]

        if len(routes) > 1:
            logger.info("ARP 防护: 检测到 %d 条默认路由，选用 metric=%d (网关=%s)",
                         len(routes), metric, gateway_ip)

        # 2. ipconfig 按适配器分段解析，找到匹配接口 IP 的网卡
        interface_name = None
        local_ipv4 = None
        subnet_mask = None
        fallback_name = None
        fallback_ipv4 = None
        fallback_mask = None

        try:
            proc = await asyncio.create_subprocess_exec(
                "ipconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: ipconfig 失败: %s", e)
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
                    # 诊断未知名称格式的段
                    if lines and "适配器" in lines[0] or "adapter" in lines[0].lower():
                        logger.info("ARP 防护: ipconfig 未知适配器格式: %s", lines[0].strip()[:80])
                    continue
                else:
                    logger.info("ARP 防护: ipconfig 解析到适配器: '%s'", current_name)

                # 扫描本段中的所有 IPv4 地址
                section_ipv4 = None
                section_mask = None
                for line in lines:
                    s = line.strip()
                    # IPv4 地址（兼容 "IPv4 地址" / "IP 地址" / "IP Address" 等格式）
                    for key in ("IPv4", "IP Address", "IPv4 地址", "IP 地址"):
                        if key in s and ":" in s:
                            ip = s.split(":", 1)[1].strip()
                            if ip and "." in ip and not ip.startswith("127."):
                                section_ipv4 = ARPProtection._clean_ip(ip) or ip
                                break
                    # 子网掩码（兼容新旧格式：子网掩码 / Subnet Mask / 子网前缀 / Subnet Prefix）
                    for key in ("子网掩码", "Subnet Mask", "子网前缀", "Subnet Prefix"):
                        if key in s and ":" in s:
                            mask = s.split(":", 1)[1].strip()
                            # 移除可能的 CIDR 后缀如 "/24"
                            if "/" in mask:
                                mask = mask.split("/")[0]
                            if mask and "." in mask and mask != "0.0.0.0":
                                section_mask = ARPProtection._clean_ip(mask) or mask
                                break

                # 诊断：记录每个段解析到的 IPv4
                if section_ipv4:
                    logger.info("ARP 防护: ipconfig 段 '%s' -> IPv4=%s, mask=%s (目标 iface_ip=%s)",
                                 current_name, section_ipv4, section_mask, iface_ip)

                # 检查 IPv4 是否匹配路由表中的接口 IP
                if section_ipv4 and section_ipv4 == iface_ip:
                    interface_name = current_name
                    local_ipv4 = section_ipv4
                    subnet_mask = section_mask or subnet_mask
                    break
                # 精确匹配失败时，记录第一个有效的非 APIPA 地址作兜底
                if (
                    section_ipv4
                    and ARPProtection._is_valid_ip(section_ipv4)
                    and not interface_name
                ):
                    fallback_name = current_name
                    fallback_ipv4 = section_ipv4
                    fallback_mask = section_mask

        # 3. 精确匹配失败 → 使用兜底（取第一个有效非 APIPA 地址）
        if not local_ipv4 and fallback_ipv4:
            interface_name = fallback_name
            local_ipv4 = fallback_ipv4
            subnet_mask = fallback_mask or subnet_mask
            logger.info("ARP 防护: ipconfig 精确匹配失败 (iface_ip=%s)，"
                         "使用兜底 IPv4=%s, 网卡=%s",
                         iface_ip, local_ipv4, interface_name)

        # 4. 如果 ipconfig 没找到匹配（罕见情况），用 route 的信息兜底
        if not local_ipv4:
            local_ipv4 = iface_ip
            logger.warning("ARP 防护: ipconfig 未找到匹配的网卡段 "
                           "(iface_ip=%s, 共解析 %d 个适配器段)",
                           iface_ip, len(raw_sections) if text else 0)

        # 如果通过 ipconfig 没解析到网卡名，通过 netsh 补充
        if not interface_name:
            logger.info("ARP 防护: 通过 netsh show interfaces 补充网卡名...")
            netsh_info = await self._resolve_interface_netsh()
            if netsh_info:
                interface_name = netsh_info[0]
                logger.info("ARP 防护: netsh 补充网卡名: '%s'", interface_name)

        # 如果 ipconfig 没解析到子网掩码（语言/格式不匹配），通过 netsh 补充
        if not subnet_mask:
            logger.info("ARP 防护: ipconfig 未解析到子网掩码，通过 netsh 补充...")
            subnet_mask = await self._fetch_subnet_mask_netsh(local_ipv4 or iface_ip, interface_name)
            if subnet_mask:
                logger.info("ARP 防护: netsh 补充子网掩码: %s", subnet_mask)

        result = {
            "gateway_ip": gateway_ip,
            "local_ipv4": local_ipv4,
            "subnet_mask": subnet_mask,
            "interface_name": interface_name or iface_ip,
            "metric": metric,
            "all_gateways": all_gateways,
        }
        if not interface_name:
            logger.warning("ARP 防护: 未能获取网卡名，使用 IP %s 作为接口标识",
                           result["interface_name"])

        # 4. 获取本机 MAC 地址（用于发送真实 GARP 包）
        local_mac = await self._fetch_local_mac(result["interface_name"])
        result["local_mac"] = local_mac or ""

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
            logger.warning("ARP 防护: ip route 失败: %s", e)

        if not routes:
            return None

        routes.sort(key=lambda x: x[2])
        gateway_ip, iface_name, metric = routes[0]
        all_gateways = [{"ip": gw, "iface": dev, "metric": m} for gw, dev, m in routes]

        if len(routes) > 1:
            logger.info("ARP 防护: 检测到 %d 条默认路由，选用 metric=%d (网关=%s, 网卡=%s)",
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
                        str(((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF) >> (8 * (3 - i)) & 0xFF)
                        for i in range(4)
                    )
                    break
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: ip addr show %s 失败: %s", iface_name, e)

        if not local_ipv4:
            return None

        # 3. 获取本机 MAC 地址（用于发送真实 GARP 包）
        local_mac = await self._fetch_local_mac(iface_name)

        return {
            "gateway_ip": gateway_ip,
            "local_ipv4": local_ipv4,
            "local_mac": local_mac or "",
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
            logger.warning("ARP 防护: route print 失败: %s", e)
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
            logger.warning("ARP 防护: ip route 失败: %s", e)
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
            logger.warning("ARP 防护: arp -a %s 失败: %s", ip, e)
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
            logger.warning("ARP 防护: ip neigh show %s 失败: %s", ip, e)
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
            if iface_info.get("local_mac"):
                self._local_mac = iface_info["local_mac"]
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

            if "IPv4" in stripped or "IP Address" in stripped or "IPv4 地址" in stripped or "IP 地址" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    ip = ARPProtection._clean_ip(parts[1].strip()) or parts[1].strip()
                    if ip and ip != "127.0.0.1" and "." in ip:
                        has_ipv4 = True
                        if not self._local_ipv4:
                            self._local_ipv4 = ip

            if any(k in stripped for k in ("子网掩码", "Subnet Mask", "子网前缀", "Subnet Prefix")):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    mask = parts[1].strip()
                    if "/" in mask:
                        mask = mask.split("/")[0]
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
            if iface_info.get("local_mac"):
                self._local_mac = iface_info["local_mac"]
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

    async def _detect_packet_loss_pattern(self, gw_ip: str, count: int = 10) -> dict:
        """
        连续 ping 网关多次，通过丢包率判断网络异常类型。

        IP 冲突特征：两个设备抢同一个 IP，路由器在两个 MAC 间摇摆，
                    约 40%-70% 的包能到达本机（另一半去了攻击者）。

        ARP 投毒特征：流量完全被劫持到攻击者 MAC，几乎 100% 丢包。

        网络拥塞特征：低丢包率（<10%），但延迟高。

        Returns:
            {"loss_rate": float, "success": int, "total": int, "diagnosis": str}
            diagnosis: "ip_conflict" | "arp_poisoning" | "network_down" | "normal"
        """
        success = 0
        for _ in range(count):
            if await self._ping_gateway(gw_ip):
                success += 1
            await asyncio.sleep(0.05)

        loss_rate = (count - success) / count
        if loss_rate >= 0.90:
            if success == 0:
                diagnosis = "network_down"
            else:
                diagnosis = "arp_poisoning"
        elif loss_rate >= 0.25:
            diagnosis = "ip_conflict"
        else:
            diagnosis = "normal"

        return {"loss_rate": loss_rate, "success": success, "total": count, "diagnosis": diagnosis}

    @staticmethod
    def _clean_ip(raw_ip: Optional[str]) -> Optional[str]:
        """
        清理 IP 地址字符串，去除尾部垃圾如 (首选)、(preferred)、空格等。
        例如: "192.168.1.100(首选)" → "192.168.1.100"
        """
        if not raw_ip:
            return None
        raw_ip = raw_ip.strip()
        # 提取前 4 段数字+点
        m = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_ip)
        return m.group(1) if m else None

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
                    mask_int = 0xFFFFFF00  # 掩码格式异常，默认 /24
                else:
                    mask_int = (mask_parts[0] << 24 | mask_parts[1] << 16 |
                                mask_parts[2] << 8 | mask_parts[3])
            except (ValueError, IndexError):
                mask_int = 0xFFFFFF00  # 默认 /24

            network = ip_int & mask_int           # 网络位不变
            host_max = (~mask_int) & 0xFFFFFFFF    # 主机位最大值
            if host_max == 0:
                host_max = 0xFF  # 掩码为 /32（255.255.255.255）时兜底 /24
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

        # 清理 IP 中的赃数据（如 "(首选)"）
        cleaned_ip = self._clean_ip(self._local_ipv4)
        if not cleaned_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP 值异常: '%s'）", self._local_ipv4)
            return False
        if cleaned_ip != self._local_ipv4:
            logger.warning("ARP 防护: 清理 IP 地址: '%s' → '%s'", self._local_ipv4, cleaned_ip)
            self._local_ipv4 = cleaned_ip

        # 同样清理子网掩码
        cleaned_mask = self._clean_ip(self._subnet_mask) if self._subnet_mask else None
        if cleaned_mask and cleaned_mask != self._subnet_mask:
            logger.warning("ARP 防护: 清理子网掩码: '%s' → '%s'", self._subnet_mask, cleaned_mask)
            self._subnet_mask = cleaned_mask

        new_ip = self._increment_ip(self._local_ipv4, self._subnet_mask)
        if not new_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP=%s, 掩码=%s, 网卡=%s）",
                           self._local_ipv4, self._subnet_mask, self._interface_name)
            return False
        if not self._is_valid_ip(new_ip):
            logger.warning("ARP 防护: 生成的备用 IP '%s' 非法，跳过冲突修复", new_ip)
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
                if err_text:
                    logger.warning("ARP 防护: netsh 执行失败 (code=%d): %s",
                                   proc.returncode, err_text)
                else:
                    logger.warning("ARP 防护: netsh 执行失败 (code=%d): "
                                   "无错误输出，可能需要管理员权限运行",
                                   proc.returncode)
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

        # 清理 IP 中的赃数据
        cleaned_ip = self._clean_ip(self._local_ipv4)
        if not cleaned_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP 值异常: '%s'）", self._local_ipv4)
            return False
        if cleaned_ip != self._local_ipv4:
            logger.warning("ARP 防护: 清理 IP 地址: '%s' → '%s'", self._local_ipv4, cleaned_ip)
            self._local_ipv4 = cleaned_ip

        cleaned_mask = self._clean_ip(self._subnet_mask) if self._subnet_mask else None
        if cleaned_mask and cleaned_mask != self._subnet_mask:
            logger.warning("ARP 防护: 清理子网掩码: '%s' → '%s'", self._subnet_mask, cleaned_mask)
            self._subnet_mask = cleaned_mask

        new_ip = self._increment_ip(self._local_ipv4, self._subnet_mask)
        if not new_ip:
            logger.warning("ARP 防护: 无法自动修复 IP 冲突（IP=%s, 掩码=%s, 网卡=%s）",
                           self._local_ipv4, self._subnet_mask, self._interface_name)
            return False
        if not self._is_valid_ip(new_ip):
            logger.warning("ARP 防护: 生成的备用 IP '%s' 非法，跳过冲突修复", new_ip)
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

        步骤:
          0. ARP 投毒检测 → 对比本机 ARP 表中网关 MAC 与预期值
          1. 爆发 ping 网关（10 次，10ms 间隔）→ 强制路由器更新本机 IP-MAC
          2. 爆发真实 GARP（20 次，发送真实二层 ARP 包）→ 全网强制更新 ARP
          3. 丢包模式分析 + IP 冲突检测
             - 丢包 ~50% → IP 冲突（攻击者使用相同静态 IP）→ 自动 IP +1
             - 丢包 ~100% → ARP 投毒（流量被劫持）→ 两阶段 IP 切换
          4. 验证 ping → 成功则设静态 ARP + 持续 GARP 对抗
          5. 以上都失败 → 两阶段 IP 切换抗 ARP 中毒
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
            logger.info("ARP 防护: 本机 ARP 表正常，未检测到投毒")

        # 1. 爆发 ping 网关（10 次，10ms 间隔，100ms 超时）
        #    路由器收到本机 IP 包 → 看到源 MAC → 更新 ARP 表中本机 IP↔MAC
        logger.info("ARP 防护: 爆发 ping 网关 %s x10", gw_ip)
        for _ in range(10):
            await self._ping_gateway_fast(gw_ip)
            await asyncio.sleep(0.01)

        # 2. 丢包模式分析：通过连续 ping 判断是 IP 冲突还是 ARP 投毒
        loss_info = await self._detect_packet_loss_pattern(gw_ip, count=10)
        if loss_info["diagnosis"] == "ip_conflict":
            loss_pct = round(loss_info["loss_rate"] * 100)
            logger.warning("ARP 防护: 网关丢包 %d%% (%d/%d), "
                           "诊断=IP冲突(攻击者使用相同静态IP)",
                           loss_pct, loss_info["success"], loss_info["total"])
        elif loss_info["diagnosis"] == "arp_poisoning":
            loss_pct = round(loss_info["loss_rate"] * 100)
            logger.warning("ARP 防护: 网关丢包 %d%% (%d/%d), "
                           "诊断=ARP投毒(流量被劫持到攻击者)",
                           loss_pct, loss_info["success"], loss_info["total"])
        elif loss_info["diagnosis"] == "network_down":
            logger.warning("ARP 防护: 网关完全不可达，诊断=网络断开")

        # 3. 爆发真实 GARP x20（发送真实二层 ARP 包，全网强制更新 ARP 表）
        await self._garp_broadcast_burst(count=20)

        # 4. IP 冲突检测 + 自动修复
        #    丢包 ~50% 说明有设备用相同静态 IP，即使 ARP 表没显示也要处理
        conflict = await self._detect_ip_conflict()
        if loss_info["diagnosis"] == "ip_conflict" or conflict:
            if not conflict:
                logger.warning("ARP 防护: 丢包模式指向 IP 冲突（ARP 表未捕获），"
                               "尝试自动 IP +1")
            else:
                logger.warning("ARP 防护: %s", conflict)
            self._arp_attack_logged = True
            ip_ok = False
            if sys.platform == "win32":
                ip_ok = await self._resolve_ip_conflict_windows()
            else:
                ip_ok = await self._resolve_ip_conflict_linux()
            if ip_ok:
                await asyncio.sleep(1.0)
                return True

        # 5. 验证 ping
        ping_ok = await self._ping_gateway(gw_ip)
        if ping_ok:
            logger.info("ARP 防护: 网关 %s 可达", gw_ip)
            # 设静态 ARP 保护本机缓存（静态度 ARP 后 OS 不再发 ARP 请求，
            # 攻击者无法再投毒本机 ARP 表，无需额外 GARP 对抗）
            if self.gateway_mac:
                if await self._protect_gateway_arp():
                    logger.info("ARP 防护: 静态 ARP 已绑定，跳过持续 GARP 对抗")
                else:
                    # 静态 ARP 绑定失败，简短 GARP 对抗兜底
                    await self._garp_sustain(gw_ip, duration=3, interval=0.5)
            if self._arp_attack_logged and not self._conflict_resolved:
                logger.warning("ARP 防护: 网络已恢复但检测到 ARP 异常，建议检查局域网设备")
            return True

        # 6. 网关仍不可达 → 持续 ARP 中毒 → 两阶段 IP 切换抗毒
        logger.warning("ARP 防护: 网关 %s 仍不可达，尝试两阶段 IP 切换抗 ARP 中毒...", gw_ip)
        if await self._garp_ip_switch_defense():
            logger.info("ARP 防护: 两阶段 GARP 切换后网关 %s 可达", gw_ip)
            return True

        logger.warning("ARP 防护: 网关 %s 仍不可达，可能存在持续 ARP 攻击或 IP 冲突", gw_ip)
        self._arp_attack_detected = True
        return False

    async def _send_single_garp(self) -> bool:
        """
        发送一个真正的 Gratuitous ARP 数据包，向全网宣告本机 IP↔MAC 绑定。

        Linux: 使用 AF_PACKET 原始套接字构造真实的 ARP 请求包（GARP 格式）。
        Windows: 由于没有 Npcap 时无法发送原始二层 ARP 包，改用了
                 "清空网关 ARP 缓存 + ping 网关" 的方式。
                 Ping 前 OS 会发送 ARP 请求（Sender IP/可信 IP, Sender MAC/本机 MAC），
                 路由器收到 ARP 请求后会根据 RFC 826 更新其 ARP 表。
        """
        gw_ip = self.gateway_ip
        if not gw_ip:
            return False

        if sys.platform != "win32":
            # Linux/macOS: 用 AF_PACKET 发送真实 GARP 包
            if not self._local_mac or not self._local_ipv4:
                logger.debug("ARP 防护: 缺少本机 MAC 或 IP，跳过真实 GARP")
                return await self._ping_gateway_fast(gw_ip)  # 兜底：ping 网关
            try:
                mac_bytes = bytes.fromhex(self._local_mac.replace("-", "").replace(":", ""))
                if len(mac_bytes) != 6:
                    return await self._ping_gateway_fast(gw_ip)

                # 以太网帧头
                dest_mac = b'\xff\xff\xff\xff\xff\xff'  # 广播
                eth_type = struct.pack('!H', 0x0806)     # ARP

                # ARP 头部
                htype = struct.pack('!H', 1)             # 以太网
                ptype = struct.pack('!H', 0x0800)        # IPv4
                hlen = struct.pack('B', 6)               # MAC 长度
                plen = struct.pack('B', 4)               # IP 长度
                opcode = struct.pack('!H', 1)            # ARP 请求（GARP 用请求）

                ip_bytes = socket.inet_aton(self._local_ipv4)
                # GARP: Sender IP = Target IP = 本机 IP
                sender_mac = mac_bytes
                sender_ip = ip_bytes
                target_mac = b'\x00\x00\x00\x00\x00\x00'
                target_ip = ip_bytes  # GARP 关键: Target IP = Sender IP

                arp_payload = (htype + ptype + hlen + plen + opcode +
                               sender_mac + sender_ip + target_mac + target_ip)
                frame = dest_mac + mac_bytes + eth_type + arp_payload

                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.htons(0x0806)) as s:
                    s.bind((self._interface_name or "", 0))
                    s.send(frame)
                return True
            except Exception as e:
                logger.debug("ARP 防护: 真实 GARP 发送失败 (%s)，回退到 ping 网关", e)
                return await self._ping_gateway_fast(gw_ip)
        else:
            # Windows: 清空网关 ARP 缓存 + ping → 触发 ARP 请求
            try:
                # 清空本机 ARP 表中网关的缓存，强制 ARP 重新解析
                proc = await asyncio.create_subprocess_exec(
                    "arp", "-d", gw_ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                pass
            # Ping 网关 → OS 发送 ARP 请求（Sender IP=本机IP, Sender MAC=本机MAC）
            # 路由器根据 RFC 826 更新 ARP 表
            return await self._ping_gateway_fast(gw_ip)

    async def _garp_broadcast_burst(self, count: int = 20):
        """
        爆发式 GARP 广播：发送真实 GARP 数据包 + ping 网关。
        真实 GARP 是二层 ARP 包（EtherType 0x0806, Sender IP = Target IP），
        路由器收到后强制更新 ARP 表，不再依赖 ICMP 的"附带学习"。

        Linux: 使用 AF_PACKET 原始套接字发送真实 GARP ARP 包。
        Windows: 通过清空网关 ARP 缓存 + ping 触发 ARP 请求（Sender IP/本机IP,
                 Sender MAC/本机MAC），路由器据此更新 ARP 表。

        Args:
            count: 发送次数（默认 20 次，间隔 10ms）
        """
        gw_ip = self.gateway_ip
        if not gw_ip:
            return

        logger.info("ARP 防护: 爆发真实 GARP x%d (网关=%s)", count, gw_ip)
        for i in range(count):
            # 发送真实 GARP 宣告
            await self._send_single_garp()
            # 每 3 次加一次网关快速 ping（双重确认）
            if i % 3 == 0:
                await self._ping_gateway_fast(gw_ip)
            await asyncio.sleep(0.01)

        # 最后再 ping 一次广播地址（作为辅助，部分交换机可能需要）
        broadcast_ip = self._get_broadcast_address()
        if broadcast_ip:
            for _ in range(min(count // 4, 5)):
                await self._ping_broadcast(broadcast_ip)
                await asyncio.sleep(0.01)

    async def _garp_sustain(self, gw_ip: str, duration: int = 5, interval: float = 0.3):
        """
        持续 GARP 对抗：在恢复后继续发送真实 GARP，防止攻击者立即重投毒。
        每次循环：先 ping 验证，不通才发 GARP（可达时静默等待）。

        检测到攻击者重投毒时自动延长对抗时间（每次 +5s），
        攻击不停就不停，最长不超过 max_duration 秒。

        Args:
            gw_ip: 网关 IP（用于 ping 验证）
            duration: 初始持续秒数
            interval: 每轮间隔（秒）
        """
        start_time = asyncio.get_event_loop().time()
        end_time = start_time + duration
        max_end = start_time + 60  # 绝对上限 60 秒
        rounds = 0
        while asyncio.get_event_loop().time() < end_time:
            rounds += 1
            # 先检查网关是否仍可达，不通才发 GARP
            if not await self._ping_gateway_fast(gw_ip):
                remain = end_time - asyncio.get_event_loop().time()
                logger.warning("ARP 防护: 持续 GARP 对抗中检测到网关再次不可达"
                               "(第 %d 轮, 剩余 %.1fs), 发送 GARP...",
                               rounds, remain)
                await self._garp_broadcast_burst(count=3)
                await self._ping_gateway_fast(gw_ip)
                # 如果还不行，加量
                if not await self._ping_gateway_fast(gw_ip):
                    await self._garp_broadcast_burst(count=10)
                    # 延长 5 秒（但不超过绝对上限）
                    new_end = end_time + 5
                    if new_end <= max_end:
                        end_time = new_end
                        logger.warning("ARP 防护: 对抗已延长至 %.0fs（攻击者持续重投毒）",
                                       end_time - start_time)
            await asyncio.sleep(interval)
        total = asyncio.get_event_loop().time() - start_time
        logger.info("ARP 防护: 持续 GARP 对抗结束（共 %d 轮, 耗时 %.0fs）", rounds, total)

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

        # IP 合法性检查：拒绝空值、APIPA、环回、多播等非法 IP
        if not self._is_valid_ip(new_ip):
            logger.warning("ARP 防护: 拒绝设置非法 IP '%s'", new_ip)
            return False
        if not self._is_valid_ip(self._local_ipv4):
            logger.critical("ARP 防护: 本机 IP '%s' 非法，跳过 IP 切换", self._local_ipv4)
            return False

        # 保存旧 IP 用于失败回滚
        old_ip = self._local_ipv4
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
                    if err:
                        logger.warning("ARP 防护: netsh 切换 IP 失败 (code=%d): %s",
                                       proc.returncode, err)
                    else:
                        logger.warning("ARP 防护: netsh 切换 IP 失败 (code=%d): "
                                       "无错误输出，可能需要管理员权限运行",
                                       proc.returncode)
                    return False
                self._local_ipv4 = new_ip  # 切换成功后更新本机 IP
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.warning("ARP 防护: netsh 切换 IP 异常: %s", e)
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
                    logger.warning("ARP 防护: ip addr 切换 IP 失败: %s", err)
                    return False
                # 网关路由
                if gw_ip:
                    await asyncio.create_subprocess_exec(
                        "ip", "route", "replace", "default", "via", gw_ip,
                        "dev", self._interface_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                self._local_ipv4 = new_ip  # 切换成功后更新本机 IP
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.warning("ARP 防护: ip addr 切换 IP 异常: %s", e)
                return False

    async def _recover_interface_dhcp(self):
        """
        紧急恢复：将接口切换为 DHCP 模式。
        用于两阶段 GARP 切换回原 IP 失败后的兜底恢复。
        """
        iface = self._interface_name
        if not iface:
            return
        logger.critical("ARP 防护: 正在将接口 %s 切换到 DHCP 模式...", iface)
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv4", "set", "address",
                    f"name={iface}", "source=dhcp",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                if proc.returncode == 0:
                    logger.critical("ARP 防护: DHCP 模式已启用，等待 DHCP 服务器分配 IP...")
                    # 等待 DHCP 获取地址
                    await asyncio.sleep(3)
                else:
                    err = stderr.decode("utf-8", errors="replace")[:200]
                    logger.error("ARP 防护: DHCP 切换失败 (code=%d): %s",
                                 proc.returncode, err or "(空)")
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.error("ARP 防护: DHCP 切换异常: %s", e)
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dhclient", "-v", iface,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.wait(), timeout=15)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                pass

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
            logger.warning("ARP 防护: 缺少 IP 或子网掩码，无法执行两阶段 GARP")
            return False

        # 计算临时 IP（在当前主机位范围内偏移 50，避免冲突）
        decoy_ip = self._increment_ip(original_ip, self._subnet_mask, offset=50)
        if not decoy_ip or decoy_ip == original_ip:
            logger.warning("ARP 防护: 无法生成临时 IP，跳过两阶段 GARP")
            return False

        gw_ip = self.gateway_ip
        logger.warning("ARP 防护: 两阶段 GARP 抗中毒: %s → %s → %s",
                        original_ip, decoy_ip, original_ip)

        # --- 阶段 1：切换到临时 IP，宣告解绑 ---
        logger.info("ARP 防护: 阶段 1 — 切换到临时 IP %s", decoy_ip)
        if not await self._switch_ip(decoy_ip):
            logger.warning("ARP 防护: 切换到临时 IP %s 失败", decoy_ip)
            return False

        self._local_ipv4 = decoy_ip
        await self._garp_broadcast_burst(count=10)
        # 短暂等待让 ARP 表传播
        await asyncio.sleep(0.3)

        # --- 阶段 2：切回原始 IP，宣告正确绑定 ---
        logger.info("ARP 防护: 阶段 2 — 切回原始 IP %s", original_ip)
        if not await self._switch_ip(original_ip):
            logger.warning("ARP 防护: 切回原始 IP %s 失败"
                          "（可能是 Windows 内置冲突检测拒绝），"
                          "尝试切换到备用 IP...", original_ip)
            # 放弃原 IP，改用 original+1（避免接口失去 IP 配置被 APIPA 接管）
            fallback_ip = self._increment_ip(original_ip, self._subnet_mask, offset=2)
            if fallback_ip and fallback_ip != original_ip and await self._switch_ip(fallback_ip):
                logger.warning("ARP 防护: 已切换到备用 IP %s（原 IP %s 冲突中）",
                               fallback_ip, original_ip)
                self._local_ipv4 = fallback_ip
                await self._garp_broadcast_burst(count=10)
                await asyncio.sleep(0.3)
                reachable = False
                for attempt in range(5):
                    reachable = await self._ping_gateway(gw_ip)
                    if reachable:
                        break
                    if attempt < 4:
                        await asyncio.sleep(1.0)
                if reachable and self.gateway_mac:
                    await self._protect_gateway_arp()
                return reachable
            # 所有尝试都失败 → 接口可能处于无 IP 状态，尝试 DHCP 恢复
            logger.critical("ARP 防护: 无法设置任何静态 IP，尝试 DHCP 恢复")
            await self._recover_interface_dhcp()
            return False

        self._local_ipv4 = original_ip
        await self._garp_broadcast_burst(count=10)
        await asyncio.sleep(0.3)

        # 确认网关可达：多轮重试，给接口/路由/ARP 足够时间稳定
        # netsh 切换 IP 后 Windows 需时间更新路由表和 ARP 缓存
        reachable = False
        for attempt in range(5):
            reachable = await self._ping_gateway(gw_ip)
            if reachable:
                break
            if attempt < 4:
                await asyncio.sleep(1.0)
        if reachable and self.gateway_mac:
            await self._protect_gateway_arp()
        return reachable

    async def _is_router_changed(self) -> Optional[str]:
        """
        检测是否换了路由器（网关 MAC 变了但能 ping 通）。
        换路由器时：ARP 表中 MAC 不同，但网关 IP 可达。
        ARP 投毒时：ARP 表中 MAC 不同，网关 IP 不可达。

        Returns:
            新的 MAC 地址（换了路由器时），None（未换或不确定）
        """
        gw_ip = self.gateway_ip
        expected_mac = self.gateway_mac
        if not gw_ip or not expected_mac:
            return None

        if sys.platform == "win32":
            current_mac = await self._arp_get_mac_windows(gw_ip)
        else:
            current_mac = await self._arp_get_mac_linux(gw_ip)

        if not current_mac:
            return None

        if current_mac.upper() == expected_mac.upper():
            return None  # MAC 一致，没换路由器

        # MAC 变了，看是否还能 ping 通
        ping_ok = await self._ping_gateway(gw_ip)
        if ping_ok:
            return current_mac.upper()  # 能 ping 通 → 换了路由器
        return None  # ping 不通 → 可能是投毒，不是换路由器

    async def _resolve_interface_netsh(self) -> Optional[Tuple[str, int]]:
        """
        通过 netsh interface ipv4 show interfaces 获取网卡 (名称, 索引)。
        返回 (interface_name, interface_idx) 或 None。
        跳过 Loopback 接口，取第一个 connected 的非回环接口。

        输出格式：
          Idx  Met   MTU   状态         名称
           1   75  1500   connected    以太网
          14   25  1500   connected    Loopback Pseudo-Interface 1  ← 名称含空格
           列序: Idx, Met, MTU, State, Name...
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv4", "show", "interfaces",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
            logger.info("ARP 防护: netsh show interfaces 原始输出:\n%s", text)

            interfaces = []
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("-"):
                    continue
                parts = line.split()
                if len(parts) < 5:  # 最少需要 Idx, Met, MTU, State, Name
                    continue
                try:
                    idx = int(parts[0])
                except ValueError:
                    continue
                # 名称 = 第5列到行尾（可能包含空格）
                iface_name = " ".join(parts[4:])
                status = parts[3]
                interfaces.append((iface_name, idx, status))

            if interfaces:
                logger.info("ARP 防护: netsh 解析到 %d 个接口: %s",
                             len(interfaces),
                             [(n, i, s) for n, i, s in interfaces])
                # 选择第一个 connected 且非 Loopback 的接口
                for name, idx, status in interfaces:
                    if status.lower() == "connected" and "loopback" not in name.lower():
                        logger.info("ARP 防护: 选择网卡 '%s' (idx=%d)", name, idx)
                        return (name, idx)
                # 没有符合条件的，回退到第一个
                logger.warning("ARP 防护: 无 connected 非回环接口，回退到第一个")
                return (interfaces[0][0], interfaces[0][1])
            return None
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning("ARP 防护: netsh show interfaces 异常: %s", e)
            return None

    async def _fetch_subnet_mask_netsh(self, target_ip: str, iface_name: Optional[str] = None) -> Optional[str]:
        """
        通过 netsh 获取子网掩码。优先用 show config name=<iface>（直接输出掩码），
        失败则回退到 show address 提取前缀长度计算。

        Windows 输出格式（中文）:
          DHCP 已启用:                       是
          IP 地址:                          192.168.1.100
          子网掩码:                         255.255.255.0
          默认网关:                         192.168.1.1

        Returns:
            子网掩码字符串如 "255.255.255.0"，失败返回 None
        """
        if not iface_name:
            return None

        # 方法一：show config name=<iface> — 直接输出子网掩码，最可靠
        mask = await self._fetch_mask_via_show_config(iface_name)
        if mask:
            return mask

        # 方法二：回退到 show address 提取前缀长度计算
        mask = await self._fetch_mask_via_show_address(target_ip, iface_name)
        return mask

    async def _fetch_mask_via_show_config(self, iface_name: str) -> Optional[str]:
        """使用 netsh interface ipv4 show config name=<iface> 获取子网掩码"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv4", "show", "config",
                f"name={iface_name}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: netsh show config 失败: %s", e)
            return None

        for line in text.splitlines():
            s = line.strip()
            for key in ("子网掩码", "Subnet Mask"):
                if key in s and ":" in s:
                    mask = s.split(":", 1)[1].strip()
                    if "/" in mask:
                        mask = mask.split("/")[0]
                    if mask and "." in mask:
                        cleaned = ARPProtection._clean_ip(mask)
                        return cleaned or mask
        return None

    async def _fetch_mask_via_show_address(self, target_ip: str, iface_name: str) -> Optional[str]:
        """回退方法：从 netsh interface ipv4 show address 的 Subnet Prefix 计算子网掩码"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "netsh", "interface", "ipv4", "show", "address",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            text = stdout.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: netsh show address 失败: %s", e)
            return None

        sections = re.split(r'\n\s*\n', text)
        for section in sections:
            lines = section.strip().splitlines()
            if len(lines) < 2:
                continue

            # target_ip 不是有效 IP 时不按 IP 匹配，只按接口名匹配
            target_is_valid = target_ip and ARPProtection._is_valid_ip(target_ip)
            section_has_target = target_ip in section if target_is_valid else False
            name_match = False
            if iface_name and not section_has_target:
                for line in lines:
                    s = line.strip().lower()
                    if iface_name.lower() in s and ('"' in s or 'interface' in s or '配置' in s):
                        name_match = True
                        break
                if not name_match:
                    continue

            for line in lines:
                s = line.strip()
                prefix_match = re.search(
                    r'(?:子网前缀|Subnet\s*Prefix)\s*[：:]\s*(?:\d+\.\d+\.\d+\.\d+)/(\d+)',
                    s,
                )
                if prefix_match:
                    prefix_len = int(prefix_match.group(1))
                    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                    mask = ".".join(
                        str((mask_int >> (8 * (3 - i))) & 0xFF)
                        for i in range(4)
                    )
                    return mask
        return None
        return None

        return None

    async def _protect_gateway_arp(self) -> bool:
        """
        为网关添加静态 ARP 条目，防止本机 ARP 缓存被投毒。

        原理：
          Windows: netsh interface ipv4 set neighbors
          Linux: ip neigh replace ... nud permanent

        设静态 ARP 前先检测是否换了路由器：
          - MAC 变了但 ping 通 → 更新 MAC → 设新静态条目
          - MAC 变了但 ping 不通 → 先抗毒，再设静态条目
        """
        gw_ip = self.gateway_ip
        gw_mac = self.gateway_mac
        iface = self._interface_name
        if not gw_ip or not gw_mac or not iface:
            logger.debug("ARP 防护: 缺少网关信息，跳过静态 ARP 保护")
            return False

        # === 换路由器检测 ===
        new_mac = await self._is_router_changed()
        if new_mac:
            logger.warning("ARP 防护: 检测到路由器 MAC 变更 %s → %s，更新静态 ARP",
                            self.gateway_mac, new_mac)
            # 更新手动/自动 MAC
            if self._manual_gateways and self._manual_gateways[0][0] == gw_ip:
                self._manual_gateways[0] = (gw_ip, new_mac)
            self._manual_gateway_mac = new_mac
            self._auto_gateway_mac = new_mac
            gw_mac = new_mac

        # 标准化 MAC 格式
        if sys.platform == "win32":
            mac_fmt = gw_mac.replace(":", "-")
            logger.info("ARP 防护: 准备 netsh — iface='%s', gw_ip=%s, mac=%s",
                         iface, gw_ip, gw_mac)

            # === 主方案：使用 name= address= neighbor= 参数格式 ===
            # 实测 Windows 11 中文版需要命名参数格式才能成功
            named_args = [
                "netsh", "interface", "ipv4", "set", "neighbors",
                f"name={iface}", f"address={gw_ip}", f"neighbor={mac_fmt}",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *named_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0:
                    logger.info("ARP 防护: ✓ 静态 ARP 已绑定 %s (%s → %s)",
                                 gw_ip, iface, gw_mac)
                    return True
                err_text = stderr.decode("utf-8", errors="replace").strip()
                out_text = stdout.decode("utf-8", errors="replace").strip()
                detail = err_text or out_text or "(空 — 可能需要管理员权限)"
                logger.warning("ARP 防护: netsh 命名参数格式失败: %s", detail)

                # === 尝试用接口索引 ===
                logger.info("ARP 防护: 尝试通过 netsh show interfaces 获取接口索引...")
                netsh_info = await self._resolve_interface_netsh()
                if netsh_info:
                    netsh_name, netsh_idx = netsh_info
                    logger.warning("ARP 防护: netsh 返回: name='%s', idx=%d",
                                    netsh_name, netsh_idx)
                    # 用索引 + 命名参数
                    proc2 = await asyncio.create_subprocess_exec(
                        "netsh", "interface", "ipv4", "set", "neighbors",
                        f"name={netsh_idx}", f"address={gw_ip}", f"neighbor={mac_fmt}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    sout2, serr2 = await asyncio.wait_for(proc2.communicate(), timeout=10)
                    if proc2.returncode == 0:
                        logger.info("ARP 防护: ✓ 静态 ARP 已绑定(索引) %s (idx=%d → %s)",
                                     gw_ip, netsh_idx, gw_mac)
                        if netsh_name and netsh_name.upper() != iface.upper():
                            self._interface_name = netsh_name
                        return True
                    err2 = serr2.decode("utf-8", errors="replace").strip() or sout2.decode("utf-8", errors="replace").strip() or "(空)"
                    logger.warning("ARP 防护: netsh 索引也失败: %s", err2)

                    # 用 netsh 的名称重试
                    if netsh_name and netsh_name.upper() != iface.upper():
                        logger.warning("ARP 防护: 尝试用 netsh 名称 '%s' 重试...", netsh_name)
                        self._interface_name = netsh_name
                        return await self._protect_gateway_arp()

                # === 后备方案：传统位置参数 ===
                logger.info("ARP 防护: 尝试传统位置参数格式...")
                proc3 = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv4", "set", "neighbors",
                    self._interface_name, gw_ip, mac_fmt,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                sout3, serr3 = await asyncio.wait_for(proc3.communicate(), timeout=10)
                if proc3.returncode == 0:
                    logger.info("ARP 防护: ✓ 静态 ARP 已绑定(位置参数) %s (%s → %s)",
                                 gw_ip, self._interface_name, gw_mac)
                    return True
                err3 = serr3.decode("utf-8", errors="replace").strip() or sout3.decode("utf-8", errors="replace").strip() or "(空)"
                logger.warning("ARP 防护: netsh 位置参数也失败: %s", err3)
                return False
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.warning("ARP 防护: netsh 异常: %s", e)
                return False
        else:
            mac_fmt = gw_mac.replace("-", ":")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "neigh", "replace", gw_ip,
                    "dev", iface, "lladdr", mac_fmt, "nud", "permanent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0:
                    logger.info("ARP 防护: ✓ 静态 ARP 已绑定 %s (%s → %s)",
                                 gw_ip, iface, gw_mac)
                    return True
                err_text = stderr.decode("utf-8", errors="replace").strip()
                logger.warning("ARP 防护: ip neigh replace 失败: %s",
                                err_text or "(空)")
                return False
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.warning("ARP 防护: ip neigh replace 异常: %s", e)
                return False

    # ======================== 本地 MAC 地址获取 ========================

    @staticmethod
    async def _fetch_local_mac(interface_name: str) -> Optional[str]:
        """
        获取指定网卡的 MAC 地址。
        用于构造真实的 GARP 数据包。
        """
        if not interface_name:
            return None

        try:
            if sys.platform == "win32":
                # Windows: getmac 命令，按接口名称匹配
                proc = await asyncio.create_subprocess_exec(
                    "getmac", "/FO", "CSV", "/NH",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                text = stdout.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # CSV: "连接名","00-11-22-33-44-55","\Device\..."
                    # 去掉外层引号，按 "," 分割
                    inner = line.strip('"')
                    parts = inner.split('","')
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        mac = parts[1].strip()
                        if (mac and len(mac.replace("-", "")) == 12 and
                                interface_name.lower() in name.lower()):
                            return mac
                # 后备：不匹配名称，尝试返回第一个有效 MAC
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    inner = line.strip('"')
                    parts = inner.split('","')
                    if len(parts) >= 2:
                        mac = parts[1].strip()
                        if mac and len(mac.replace("-", "")) == 12:
                            logger.debug("ARP 防护: getmac 未精确匹配接口名，使用首个 MAC %s", mac)
                            return mac
            else:
                # Linux: 读取 sysfs
                path = f"/sys/class/net/{interface_name}/address"
                proc = await asyncio.create_subprocess_exec(
                    "cat", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                mac = stdout.decode("utf-8", errors="replace").strip()
                if mac and len(mac.replace(":", "")) == 12:
                    return mac
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.debug("ARP 防护: 获取本地 MAC 失败: %s", e)
        return None

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """
        检查 IP 地址是否合法且可用于局域网。
        拒绝：APIPA (169.254.x.x), 环回 (127.x.x.x), 多播 (224-239.x.x.x), 0.x.x.x
        """
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) != 4:
                return False
            first = parts[0]
            if first == 0 or first == 127:
                return False
            if first == 169 and parts[1] == 254:
                return False  # APIPA
            if 224 <= first <= 239:
                return False  # 多播
            return all(0 <= p <= 255 for p in parts)
        except (ValueError, IndexError):
            return False

    @staticmethod
    async def _ping_gateway(gw_ip: str) -> bool:
        """ping 网关（标准版：3 秒超时）"""
        return await ARPProtection._ping_icmp(gw_ip, timeout_ms=3000)

    @staticmethod
    async def _ping_gateway_fast(gw_ip: str) -> bool:
        """ping 网关（快速版：200ms 超时，用于 GARP 爆发场景的快速验证，不启用 TCP 兜底）"""
        return await ARPProtection._ping_icmp(gw_ip, timeout_ms=200, use_tcp_fallback=False)

    @staticmethod
    async def _ping_icmp(ip: str, timeout_ms: int,
                         use_tcp_fallback: bool = True) -> bool:
        """
        底层 ICMP Echo 实现。
        ICMP 失败时自动尝试 TCP 连接兜底（端口 80/443），
        防止因防火墙阻止 ping.exe 导致的误判。

        Args:
            ip: 目标 IP
            timeout_ms: ping 内部超时（毫秒）
            use_tcp_fallback: 是否在 ICMP 失败时尝试 TCP 兜底
        """
        if sys.platform == "win32":
            ok = await ARPProtection._ping_icmp_windows(ip, timeout_ms)
        else:
            ok = await ARPProtection._ping_icmp_linux(ip, timeout_ms)
        if ok:
            return True
        if not use_tcp_fallback:
            return False
        # ICMP 失败 → TCP 兜底：尝试连接常见端口
        return await ARPProtection._ping_tcp(ip, timeout_ms=3000)

    @staticmethod
    async def _ping_tcp(ip: str, timeout_ms: int = 3000) -> bool:
        """TCP 连接检测：尝试连接目标 IP 的 80 和 443 端口"""
        for port in (443, 80):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=min(timeout_ms / 1000, 3.0),
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, OSError, ConnectionError):
                continue
        return False

    @staticmethod
    async def _check_external_connectivity() -> bool:
        """
        检查外部连通性（DNS 解析 + TCP 外网）。
        当网关 ping 和接口检查均失败时作为最后兜底。
        """
        # 1. DNS 解析检测
        test_domains = ["dns.alidns.com", "dns.google", "one.one.one.one"]
        for domain in test_domains:
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().getaddrinfo(domain, 443),
                    timeout=3.0,
                )
                return True
            except (asyncio.TimeoutError, OSError):
                continue
        # 2. TCP 外网检测：直接连接知名公共 DNS
        ext_targets = [("223.5.5.5", 53), ("223.6.6.6", 53),
                       ("8.8.8.8", 53), ("114.114.114.114", 53)]
        for ext_ip, ext_port in ext_targets:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ext_ip, ext_port),
                    timeout=3.0,
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, OSError, ConnectionError):
                continue
        return False

    @staticmethod
    async def _ping_icmp_windows(ip: str, timeout_ms: int) -> bool:
        """Windows ICMP Echo：跑 ping.exe，带超时安全包装"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", "1", "-w", str(timeout_ms), ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            # 总超时 = ping 内部超时 + 5s 余量，防止 ping.exe 异常挂起
            await asyncio.wait_for(proc.wait(), timeout=(timeout_ms / 1000) + 5)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError):
            return False

    @staticmethod
    def _icmp_checksum(data: bytes) -> int:
        """ICMP 校验和计算"""
        if len(data) % 2 == 1:
            data += b'\x00'
        s = sum(struct.unpack(f'!{len(data) // 2}H', data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    @staticmethod
    async def _ping_icmp_linux(ip: str, timeout_ms: int) -> bool:
        """Linux：使用 raw ICMP 套接字发送 Echo 请求"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMP)
            sock.settimeout(timeout_ms / 1000.0)
            sock.setblocking(True)

            pid = os.getpid() & 0xFFFF
            data = struct.pack('!d', asyncio.get_event_loop().time()) + b'\x00' * 24

            # 构建 ICMP Echo 请求
            header = struct.pack('!BBHHH', 8, 0, 0, pid, 1)  # type=8(echo), code=0
            pkt = header + data
            chk = ARPProtection._icmp_checksum(pkt)
            header = struct.pack('!BBHHH', 8, 0, chk, pid, 1)
            pkt = header + data

            sock.sendto(pkt, (ip, 0))
            # 等回复
            sock.recvfrom(4096)
            sock.close()
            return True
        except socket.timeout:
            return False
        except PermissionError:
            # 没有 raw socket 权限，回退
            pass
        except Exception:
            return False
        # 回退：使用 timeout 包装的子进程 ping
        try:
            proc = await asyncio.create_subprocess_exec(
                "timeout", str(timeout_ms / 1000), "ping", "-c", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=(timeout_ms / 1000) + 1)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
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
            "local_mac": self._local_mac,
            "subnet_mask": self._subnet_mask,
            "broadcast": self._get_broadcast_address(),
            "manual_ip": bool(self._manual_gateway_ip),
            "manual_mac": bool(self._manual_gateway_mac),
            "detected": self._detected,
            "arp_attack_detected": self._arp_attack_detected,
        }

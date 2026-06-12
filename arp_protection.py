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
import random
from typing import Optional, Tuple

logger = logging.getLogger("dns-proxy.arp")

# ARP 嗅探：scapy 跨平台抓包（可选，需 libpcap/Npcap 驱动支持）
_SCAPY_AVAILABLE = False
try:
    import scapy.all as scapy

    _SCAPY_AVAILABLE = True
except ImportError:
    pass


class ARPProtection:
    """ARP 防护：网关侦测 + 路由器 ARP 表刷新"""

    # Linux ICMP 持久 raw socket（避免每 ping 创建/销毁）
    _icmp_sock: Optional[socket.socket] = None

    def __init__(self, config_arp: dict, ping_interval: float = 0.80,
                 ping_targets_v4: list = None):
        """
        Args:
            config_arp: 从配置读取的 arp_protection 字典
            ping_interval: 网关检测间隔（秒），直接转为 ping 超时（ping_interval × 1000 ms）
            ping_targets_v4: 外网 ping 目标列表，后台监控从中随机选一个
        """
        self._enabled = config_arp.get("enabled", True)
        self._ping_interval = ping_interval
        self._ping_targets_v4 = ping_targets_v4 or ["223.5.5.5"]

        # VLAN/VXLAN 配置
        self._vxlan_enabled = config_arp.get("vxlan_enabled", False)

        # 解析 gateway 逗号格式（支持多组 "IP1,MAC1,IP2,MAC2" 交替逗号格式）
        self._manual_gateways: list = []  # [(ip, mac, vlan_id), ...] — 手动配置的全部网关
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
                    self._manual_gateways = [(old_ip, old_mac, "")]
        if not self._manual_gateways:
            old_ip = config_arp.get("gateway_ip", "") or ""
            old_mac = config_arp.get("gateway_mac", "") or ""
            if old_ip:
                self._manual_gateways = [(old_ip, old_mac, "")]

        self._manual_gateway_ip = self._manual_gateways[0][0] if self._manual_gateways else ""
        self._manual_gateway_mac = self._manual_gateways[0][1] if self._manual_gateways else ""
        self._manual_gateway_vlan = self._manual_gateways[0][2] if self._manual_gateways and len(self._manual_gateways[0]) > 2 and self._manual_gateways[0][2] else ""

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

        # 记录上次有效的非 APIPA IP（用于 APIPA 后恢复正确子网）
        self._last_known_ip: Optional[str] = None

        # IP 切换后的 TCP 监听器重启钩子（避免 netsh 后 socket 失效）
        self._restart_hooks: list = []

        # ========== 常驻 worker 框架 ==========
        self._arp_running = False                 # 运行标志
        self._arp_workers: list = []              # worker task 列表

        # 恢复监控 worker：通过 event 触发/通知
        self._recovery_trigger = asyncio.Event()  # 信号：开始监控恢复
        self._recovery_detected = asyncio.Event() # 信号：恢复已确认

        # 诊断 worker：通过 event 触发
        self._run_loss = asyncio.Event()          # 信号：丢包检测
        self._run_garp = asyncio.Event()          # 信号：GARP 爆发
        self._run_conflict = asyncio.Event()      # 信号：IP 冲突检测
        self._loss_result = None                  # 丢包检测结果
        self._garp_done = False                   # GARP 完成标记
        self._conflict_result = None              # IP 冲突检测结果
        self._garp_done_event = asyncio.Event()   # GARP 完成通知（替代轮询）
        self._loss_done_event = asyncio.Event()   # 丢包检测完成通知

        # ARP 投毒检测（嗅探 worker 检测到变化时设此 event）
        self._baseline_mac = self.gateway_mac or ""  # 首次正确的网关 MAC
        self._poison_detected = asyncio.Event()    # 信号：检测到 ARP 投毒/IP冲突
        self._local_ips: set = set()               # 本机所有 IPv4 地址（嗅探用）
        self._last_alert_mac: str = ""             # 上次告警的攻击者 MAC（同 MAC <3s 不重复触发）
        self._last_alert_time: float = 0.0         # 上次告警时间戳
        self._baseline_learned: bool = False       # 基线 MAC 是否已通过多次确认学习
        self._baseline_proposed_mac: str = ""      # 首次候选基线 MAC（待二次确认）
        self._baseline_proposed_time: float = 0.0

        # ========== 反击统计 ==========
        self._attack_stats: dict = {}
        self._counterstrike_cooldown: float = 0.0
        self._counterstrike_count: int = 0          # 反击轮次计数（用于交替毒化MAC）
        self._ip_migrated: bool = True              # 全局IP是否已迁移（永久禁用IP迁移，仅用反制）

        # ========== 常驻 scapy 发送器 worker（进程冻结，避免重复创建）==========
        self._scapy_sender_queue: asyncio.Queue = asyncio.Queue()
        self._scapy_sender_ready: bool = False      # scapy 发送器是否已就绪

    async def _scapy_sender_worker_loop(self):
        """常驻 scapy 发送器：一次性导入 scapy，从队列取任务发送，进程冻结"""
        if not _SCAPY_AVAILABLE:
            self._scapy_sender_ready = False
            await asyncio.Event().wait()
            return
        try:
            from scapy.all import Ether, ARP, sendp
        except Exception as e:
            logger.debug("ARP 防护: scapy 发送器初始化失败 (%s)", e)
            self._scapy_sender_ready = False
            await asyncio.Event().wait()
            return
        self._scapy_sender_ready = True
        logger.debug("ARP 防护: scapy 发送器已就绪")
        while self._arp_running:
            try:
                task = await asyncio.wait_for(self._scapy_sender_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if task is None:
                break
            try:
                dst_mac, src_mac, src_ip, poison_mac, count, inter, vlan_id = task
                spoof_pkt = Ether(dst=dst_mac) / ARP(
                    op=2, hwsrc=poison_mac, psrc=src_ip,
                    hwdst=dst_mac, pdst=src_ip,
                )
                # VLAN 802.1Q tag when vlan_id is set and not VXLAN
                if vlan_id and not self._vxlan_enabled:
                    try:
                        from scapy.all import Dot1Q
                        spoof_pkt = Ether(dst=dst_mac) / Dot1Q(vlan=int(vlan_id)) / ARP(
                            op=2, hwsrc=poison_mac, psrc=src_ip,
                            hwdst=dst_mac, pdst=src_ip,
                        )
                    except Exception:
                        pass
                elif vlan_id and self._vxlan_enabled:
                    try:
                        from scapy.all import VXLAN, IP, UDP
                        inner_pkt = Ether(dst=dst_mac) / ARP(
                            op=2, hwsrc=poison_mac, psrc=src_ip,
                            hwdst=dst_mac, pdst=src_ip,
                        )
                        spoof_pkt = Ether(dst=dst_mac, src=src_mac) / IP(dst=src_ip) / UDP(sport=4789, dport=4789) / VXLAN(vni=int(vlan_id)) / inner_pkt
                    except Exception:
                        pass
                sendp(spoof_pkt, iface=self._interface_name or "", verbose=False, count=count, inter=inter)
                logger.warning("ARP 反制: 定向反击 %s (%s) -> %s x%d", src_ip, dst_mac, poison_mac, count)
            except Exception as e:
                logger.debug("ARP 反制: 定向发送失败 (%s)", e)

    def register_restart_hook(self, hook):
        """注册 IP 切换后的 TCP 监听器重启回调"""
        if hook not in self._restart_hooks:
            self._restart_hooks.append(hook)

    async def _fire_restart_hooks(self):
        """触发所有已注册的 TCP 监听器重启回调"""
        for hook in self._restart_hooks:
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook()
                else:
                    hook()
            except Exception as e:
                logger.warning("ARP 防护: 重启钩子执行异常: %s", e)

    # ======================== 常驻 worker 框架 ========================

    async def _start_workers(self):
        """启动所有常驻 worker task，程序启动时调用一次，workers 循环等待事件触发"""
        if self._arp_workers:
            return  # 已启动
        self._arp_running = True

        self._arp_workers = [
            asyncio.create_task(self._recovery_worker_loop()),
            asyncio.create_task(self._loss_worker_loop()),
            asyncio.create_task(self._garp_worker_loop()),
            asyncio.create_task(self._conflict_worker_loop()),
            asyncio.create_task(self._arp_sniffer_worker_loop()),
            asyncio.create_task(self._scapy_sender_worker_loop()),
            asyncio.create_task(self._static_arp_monitor_loop()),
        ]
        logger.debug("ARP 防护: 7 个常驻 worker(含嗅探+scapy发送器)已启动")

    async def _stop_workers(self):
        """停止所有常驻 worker"""
        self._arp_running = False
        # 触发所有 event 让 worker 从等待中醒来
        self._recovery_trigger.set()
        self._run_loss.set()
        self._run_garp.set()
        self._run_conflict.set()
        self._garp_done_event.set()
        self._loss_done_event.set()
        self._poison_detected.set()
        # 发送 None 唤醒 scapy 发送器并让其退出
        try:
            self._scapy_sender_queue.put_nowait(None)
        except Exception:
            pass
        # 嗅探 worker 不依赖 event，靠 _arp_running=False 和 socket.close 退出
        for w in self._arp_workers:
            w.cancel()
            try:
                await w
            except (asyncio.CancelledError, Exception):
                pass
        self._arp_workers = []

    @classmethod
    def close_icmp_socket(cls):
        """关闭 Linux 持久 ICMP raw socket（程序退出时调用）"""
        if cls._icmp_sock is not None:
            try:
                cls._icmp_sock.close()
            except Exception:
                pass
            cls._icmp_sock = None

    async def _recovery_worker_loop(self):
        """Worker 1: 永久等待 recovery_trigger → ping gw+ext → 通则 recovery_detected.set()"""
        ext_ip = random.choice(self._ping_targets_v4) if self._ping_targets_v4 else "223.5.5.5"
        ping_ms = int(self._ping_interval * 1000)
        while self._arp_running:
            await self._recovery_trigger.wait()
            if not self._arp_running:
                return
            self._recovery_trigger.clear()
            self._recovery_detected.clear()
            gw_ip = self.gateway_ip
            if not gw_ip:
                continue
            while self._arp_running and not self._recovery_detected.is_set():
                gw_ok = await self._ping_gateway(gw_ip)
                if gw_ok:
                    ext_ok = await ARPProtection._ping_icmp(
                        ext_ip, timeout_ms=ping_ms, use_tcp_fallback=False)
                    if ext_ok:
                        logger.info("ARP 防护: 后台 worker 检测到网关+外网已恢复")
                        self._recovery_detected.set()
                        break
                await asyncio.sleep(self._ping_interval)

    async def _loss_worker_loop(self):
        """Worker 2: 永久等待 run_loss → 丢包检测 → 存结果到 _loss_result → 通知"""
        while self._arp_running:
            await self._run_loss.wait()
            if not self._arp_running:
                return
            self._run_loss.clear()
            self._loss_done_event.clear()
            gw_ip = self.gateway_ip
            if gw_ip:
                try:
                    self._loss_result = await self._detect_packet_loss_pattern(gw_ip, count=10)
                except Exception as e:
                    logger.debug("ARP 防护: 丢包检测 worker 异常: %s", e)
            self._loss_done_event.set()

    async def _garp_worker_loop(self):
        """Worker 3: 永久等待 run_garp → GARP 爆发 → 标记完成 → 通知"""
        while self._arp_running:
            await self._run_garp.wait()
            if not self._arp_running:
                return
            self._run_garp.clear()
            self._garp_done_event.clear()
            gw_ip = self.gateway_ip
            if gw_ip:
                try:
                    await self._garp_broadcast_burst(count=10)
                    self._garp_done = True
                except Exception as e:
                    logger.debug("ARP 防护: GARP worker 异常: %s", e)
            self._garp_done_event.set()

    async def _conflict_worker_loop(self):
        """Worker 4: 永久等待 run_conflict → IP 冲突检测 → 存结果"""
        while self._arp_running:
            await self._run_conflict.wait()
            if not self._arp_running:
                return
            self._run_conflict.clear()
            gw_ip = self.gateway_ip
            if gw_ip:
                try:
                    self._conflict_result = await self._detect_ip_conflict()
                except Exception as e:
                    logger.debug("ARP 防护: 冲突检测 worker 异常: %s", e)

    async def _static_arp_monitor_loop(self):
        """Worker 7: 每 60 秒检测静态 ARP 绑定是否被篡改，若被篡改则重新绑定"""
        while self._arp_running:
            await asyncio.sleep(60)
            if not self._arp_running:
                return
            gw_ip = self.gateway_ip
            gw_mac = self.gateway_mac
            if not gw_ip or not gw_mac:
                continue
            try:
                if sys.platform == "win32":
                    current_mac = await self._arp_get_mac_windows(gw_ip)
                else:
                    current_mac = await self._arp_get_mac_linux(gw_ip)
                if current_mac and self._mac_normalize(current_mac) != self._mac_normalize(gw_mac):
                    logger.warning("ARP 防护: 静态 ARP 绑定被篡改！%s → %s（预期 %s），重新绑定...",
                                   gw_ip, current_mac, gw_mac)
                    await self._protect_gateway_arp()
            except Exception as e:
                logger.debug("ARP 防护: 静态 ARP 监控异常: %s", e)

    async def _check_arp_packet(self, sender_ip: str, sender_mac: str,
                                  target_ip: str, target_mac: str,
                                  opcode: int) -> str:
        """
        统一 ARP 包检测 — 覆盖所有已知 ARP 攻击向量。

        Args:
            sender_ip:    发送者 IP（arp.psrc / frame[14:18]）
            sender_mac:   发送者 MAC（arp.hwsrc，冒号大写）
            target_ip:    目标 IP（arp.pdst / frame[24:28]）
            target_mac:   目标 MAC（arp.hwdst / frame[18:24]，冒号大写）
            opcode:       1=request, 2=reply

        Returns:
            "" (正常) 或 描述字符串 (检测到攻击)
        """
        gw_ip = self.gateway_ip
        gw_ips = set(ip for ip, _, _ in self.gateway_pairs)
        local_mac = (self._local_mac or "").replace("-", ":").upper()
        is_garp = (sender_ip == target_ip)

        # === 防抖：根据攻击频率自适应（频率越高，防抖越短）===
        now = asyncio.get_event_loop().time()
        is_zero_mac = (sender_mac == "00:00:00:00:00:00")
        # 从攻击统计读取当前频率来决定防抖间隔
        existing_stats = self._attack_stats.get(sender_mac, {})
        existing_rate = existing_stats.get("count", 0)
        if is_zero_mac:
            debounce_interval = 0.5
        elif existing_rate > 200:
            debounce_interval = 0.0  # 每个包都检测
        elif existing_rate > 100:
            debounce_interval = 0.1
        elif existing_rate > 50:
            debounce_interval = 0.3
        elif existing_rate > 10:
            debounce_interval = 1.0
        else:
            debounce_interval = 3.0
        if now < self._counterstrike_cooldown and sender_mac == self._last_alert_mac:
            return ""
        if sender_mac == self._last_alert_mac and now - self._last_alert_time < debounce_interval:
            return ""

        # === 安全基线学习（启动时防投毒）===
        if not self._baseline_learned and not self._baseline_mac:
            if sender_ip == gw_ip and sender_mac:
                if not self._baseline_proposed_mac:
                    # 首次收到网关包，记录候选
                    self._baseline_proposed_mac = sender_mac
                    self._baseline_proposed_time = now
                    return ""
                elif sender_mac == self._baseline_proposed_mac and now - self._baseline_proposed_time >= 2.0:
                    # 2 秒内同一 MAC 确认 → 学习为基线
                    self._baseline_mac = sender_mac
                    self._baseline_learned = True
                    logger.info("ARP 防护: 基线 MAC 已学习: %s => %s", gw_ip, sender_mac)
                    return ""
                elif sender_mac != self._baseline_proposed_mac:
                    # 两次 MAC 不一致，可能启动时被攻击，清空候选等下一次
                    self._baseline_proposed_mac = ""
                    return ""
            return ""

        # === 攻击向量检测 ===
        poisoned = False
        reason = ""

        # ① Sender = 网关 IP × MAC 不匹配（ARP 投毒/网关冒充）
        if sender_ip in gw_ips and self._baseline_mac and self._mac_normalize(sender_mac) != self._mac_normalize(self._baseline_mac):
            poisoned = True
            reason = f"ARP 投毒！网关 {sender_ip} → 期望 {self._baseline_mac} ≠ 实际 {sender_mac}"

        # ② Sender = 本机 IP × MAC 不匹配（IP 冲突）
        elif sender_ip in self._local_ips and self._mac_normalize(sender_mac) != self._mac_normalize(local_mac):
            poisoned = True
            reason = f"IP 冲突！本机 {sender_ip} 的 MAC 被篡改为 {sender_mac}"

        # ③ Target = 网关 IP × MAC 不匹配（中间人回复劫持）
        elif target_ip == gw_ip and self._baseline_mac and target_mac and self._mac_normalize(target_mac) != self._mac_normalize(self._baseline_mac):
            poisoned = True
            reason = f"MITM 劫持！回复目标 {target_ip} → 期望 MAC {self._baseline_mac} ≠ 实际 {target_mac}"

        # ④ GARP 宣告伪造（Opcode=2 且 Sender=Target=网关, MAC 不对）
        elif is_garp and opcode == 2 and sender_ip in gw_ips and self._baseline_mac and \
                self._mac_normalize(sender_mac) != self._mac_normalize(self._baseline_mac):
            poisoned = True
            reason = f"GARP 投毒！{sender_ip} 宣告 MAC={sender_mac}，期望 {self._baseline_mac}"

        if poisoned:
            self._last_alert_mac = sender_mac
            self._last_alert_time = now
            self._poison_detected.set()
            self._arp_attack_logged = True
            logger.warning("ARP 嗅探: %s", reason)
            # 清理超 300 秒无活动的攻击源（停火检测）
            stale_macs = [m for m, s in self._attack_stats.items() if now - s.get("last_attack", 0) > 300.0]
            for m in stale_macs:
                del self._attack_stats[m]
            # 更新攻击统计（60 秒窗口计数）
            stats = self._attack_stats.setdefault(sender_mac, {"count": 0, "bursts_sent": 0, "last_attack": 0.0, "last_counterstrike": 0.0, "window_start": now, "ip_switched": False})
            # 如果窗口超过 60 秒，重置计数
            if now - stats.get("window_start", now) > 60.0:
                stats["count"] = 0
                stats["bursts_sent"] = 0
                stats["window_start"] = now
            stats["count"] += 1
            stats["last_attack"] = now
            # 异步触发即时反击
            asyncio.create_task(self._on_arp_attack(sender_ip, sender_mac, reason))
            return reason

        return ""

    async def _arp_sniffer_worker_loop(self):
        """
        Worker 5: ARP 嗅探防护 — 跨平台实时检测 ARP 投毒和 IP 冲突。

        优先级:
          1. scapy 可用 → 跨平台实时抓包（事件驱动，零延迟）
          2. Linux → AF_PACKET 原始套接字
          3. Windows → arp -a 轮询兜底
        """
        gw_ip = self.gateway_ip
        # 收集本机所有 IPv4 地址（避免 _local_ipv4 单值残留旧临时 IP）
        self._local_ips = await ARPProtection._fetch_local_ips(self._interface_name or "")
        # MAC 统一冒号大写格式（scapy 返回冒号格式，arp -a 返回横线格式）
        self._baseline_mac = self._baseline_mac.replace("-", ":").upper() if self._baseline_mac else ""

        # ==================== 路径 1: scapy 嗅探（跨平台，最快） ====================
        if _SCAPY_AVAILABLE:
            from scapy.all import conf, ARP as ScapyARP
            try:
                if self._interface_name:
                    conf.iface = self._interface_name
            except Exception:
                pass

            pkt_queue = asyncio.Queue()
            sniff_failed = False

            def _handle_pkt(pkt):
                """scapy 回调（在 executor 线程中运行），收到 ARP 包就丢进 asyncio 队列"""
                if pkt.haslayer(ScapyARP):
                    try:
                        pkt_queue.put_nowait(pkt)
                    except Exception:
                        pass

            loop = asyncio.get_event_loop()

            sniffer_task = None
            try:
                sniffer_task = loop.run_in_executor(
                    None,
                    lambda: scapy.sniff(
                        prn=_handle_pkt, store=False,
                        filter="arp", timeout=None,
                    ),
                )
                logger.info("ARP 防护: scapy 嗅探已启动")
            except Exception as e:
                logger.warning("ARP 防护: scapy sniff 启动失败 (%s)，使用备用方案", e)
                sniff_failed = True

            if not sniff_failed:
                while self._arp_running:
                    try:
                        pkt = await asyncio.wait_for(pkt_queue.get(), timeout=0.5)
                    except asyncio.TimeoutError:
                        if sniffer_task and sniffer_task.done() and not sniffer_task.cancelled():
                            try:
                                sniffer_task.result()
                            except Exception as e:
                                logger.warning("ARP 防护: scapy sniff 已停止 (%s)，切换到 arp 轮询", e)
                                sniff_failed = True
                                break
                        continue
                    except Exception:
                        break
                    try:
                        arp = pkt[ScapyARP]
                        await self._check_arp_packet(
                            sender_ip=arp.psrc,
                            sender_mac=arp.hwsrc.upper(),
                            target_ip=arp.pdst,
                            target_mac=arp.hwdst.upper() if arp.hwdst else "",
                            opcode=arp.op,
                        )
                    except Exception:
                        continue

            if not sniff_failed:
                return
            logger.info("ARP 防护: scapy 嗅探不可用，回退到 arp 轮询。"
                        "如需实时抓包，Windows 请安装 Npcap (https://npcap.com/)")

        # ==================== 路径 2: AF_PACKET 原始套接字（Linux） ====================
        if sys.platform != "win32":
            ARP_ETH_TYPE = 0x0806
            arp_sock = None
            try:
                arp_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.htons(ARP_ETH_TYPE))
                arp_sock.bind((self._interface_name or "", 0))
                arp_sock.setblocking(True)
                logger.info("ARP 防护: AF_PACKET 嗅探已启动")
            except Exception as e:
                logger.warning("ARP 防护: 无法创建原始套接字 (%s)，回退到 arp 轮询", e)

            if arp_sock:
                while self._arp_running:
                    try:
                        frame = await asyncio.get_event_loop().sock_recv(arp_sock, 65535)
                    except (asyncio.CancelledError, OSError):
                        break
                    except Exception:
                        continue
                    if len(frame) < 42:
                        continue
                    # ARP header: htype(2) ptype(2) hlen(1) plen(1) opcode(2) smac(6) sip(4) tmac(6) tip(4)
                    arp = frame[14:42]
                    htype, ptype = struct.unpack('!HH', arp[:4])
                    if htype != 1 or ptype != ARP_ETH_TYPE:
                        continue
                    opcode = struct.unpack('!H', arp[6:8])[0]
                    try:
                        await self._check_arp_packet(
                            sender_ip=socket.inet_ntoa(arp[14:18]),
                            sender_mac=':'.join(f'{b:02x}' for b in arp[8:14]).upper(),
                            target_ip=socket.inet_ntoa(arp[24:28]),
                            target_mac=':'.join(f'{b:02x}' for b in arp[18:24]).upper(),
                            opcode=opcode,
                        )
                    except Exception:
                        continue
                try:
                    arp_sock.close()
                except Exception:
                    pass
                return

        # ==================== 路径 3: arp -a 轮询（Windows 兜底） ====================
        while self._arp_running:
            poisoned = await self._check_arp_poisoning()
            if poisoned:
                for gw_ip_p, expected, actual in poisoned:
                    logger.warning("ARP 防护: 检测到 ARP 投毒！网关 %s → 预期 %s ≠ 实际 %s",
                                   gw_ip_p, expected, actual)
                self._poison_detected.set()
            await asyncio.sleep(self._ping_interval)

    @staticmethod
    def _parse_gateway_field(gw_field: str) -> list:
        """
        解析 gateway 逗号格式，仅支持 3 元素交替格式:
        "IP1,MAC1,VLAN1,IP2,MAC2,VLAN2"

        IP 含 `.`，MAC 含 `-` 或 `:`，VLAN_ID 为纯数字或空。
        vxlan_enabled=true 时 VLAN_ID 解释为 VXLAN VNI。

        示例:
          "192.168.1.1,00-11-22-33-44-55,12"          → 1组(IP+MAC+VLAN)
          "192.168.1.1,00-11-22-33-44-55,"             → 1组(IP+MAC,无VLAN)
          "192.168.1.1,,"                               → 仅IP
          "192.168.1.1,aa-bb,10,10.0.0.1,cc-dd,20"    → 2组

        Returns:
            [(ip, mac, vlan_id), ...] 列表
        """
        parts = [p.strip() for p in gw_field.split(",")]
        n = len(parts)
        if n == 0 or (n == 1 and not parts[0]):
            return []

        # 每 3 个一组：每组为 (IP, MAC, VLAN_ID)
        groups = []
        i = 0
        while i + 2 < n:
            groups.append((parts[i], parts[i+1], parts[i+2]))
            i += 3
        # 处理尾部不足 3 个的情况
        if i < n:
            ip = parts[i] if i < n else ""
            mac = parts[i+1] if i + 1 < n else ""
            vlan = parts[i+2] if i + 2 < n else ""
            groups.append((ip, mac, vlan))
        return groups

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
    def gateway_vlan(self) -> str:
        """获取网关 VLAN ID / VXLAN VNI（仅手动配置）"""
        return self._manual_gateway_vlan if self._manual_gateway_vlan else ""

    @property
    def gateway_pairs(self) -> list:
        """返回全部网关 (IP, MAC, VLAN_ID) 列表（手动 + 自动）"""
        pairs = []
        for gw in self._manual_gateways:
            if len(gw) >= 3:
                pairs.append((gw[0], gw[1], gw[2]))
            else:
                pairs.append((gw[0], gw[1], ""))
        if self._auto_gateway_ip:
            # 如果自动探测的网关不在手动列表中，追加（自动探测无 VLAN）
            if not any(ip == self._auto_gateway_ip for ip, _, _ in pairs):
                pairs.append((self._auto_gateway_ip, self._auto_gateway_mac or "", ""))
        return pairs

    @property
    def is_manual(self) -> bool:
        """全部网关均为手动配置（每组都有 IP+MAC）时跳过自动探测"""
        if not self._manual_gateways:
            return False
        return all(bool(ip) and bool(mac) for ip, mac, _ in self._manual_gateways)

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
                pairs_str = "; ".join(f"{ip},{mac or '*'},{vlan or '*'}" for ip, mac, vlan in self._manual_gateways)
                logger.info("ARP 防护: 多网关 %s -> %s", src, pairs_str)
            else:
                logger.info("ARP 防护: 网关 %s -> IP=%s, MAC=%s",
                             src, self.gateway_ip, self.gateway_mac or "未知")
            # 确保 VLAN 子接口存在
            await self._ensure_vlan_interface()
            # 网关 MAC 已知时设静态 ARP 防止本机缓存被投毒
            if self.gateway_mac:
                await self._protect_gateway_arp()
        else:
            logger.warning("ARP 防护: 无法自动探测网关地址（防火墙可能阻止了探测）")
        return ok


    async def _ensure_vlan_interface(self) -> bool:
        """确保 VLAN 子接口存在（vlan_id 非空且非 VXLAN 时自动创建）"""
        vlan_id = self._manual_gateway_vlan
        if not vlan_id or self._vxlan_enabled or not self._interface_name:
            return True  # 不需要 VLAN 子接口
        iface = self._interface_name
        vlan_iface = f"{iface}.{vlan_id}"
        if sys.platform == "win32":
            # Windows: netsh interface ipv4 add vlan
            try:
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "interface", "ipv4", "add", "vlan",
                    f"name={iface}", f"vlanid={vlan_id}",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                _, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                if proc.returncode == 0:
                    logger.info("ARP 防护: VLAN 子接口 %s 已创建", vlan_iface)
                    return True
                # 非零返回通常表示子接口已存在，不视为错误
                logger.debug("ARP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在）", vlan_iface, proc.returncode)
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("ARP 防护: VLAN 子接口创建失败 %s", e)
                return False
        else:
            # Linux: ip link add link {iface} name {vlan_iface} type vlan id {vlan_id}
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "link", "add", "link", iface,
                    "name", vlan_iface,
                    "type", "vlan", "id", str(vlan_id),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10)
                if proc.returncode == 0:
                    logger.info("ARP 防护: VLAN 子接口 %s 已创建", vlan_iface)
                    return True
                logger.debug("ARP 防护: VLAN 子接口 %s 创建返回 %d（可能已存在）", vlan_iface, proc.returncode)
                return True
            except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
                logger.debug("ARP 防护: VLAN 子接口创建失败 %s", e)
                return False

    async def _detect_windows(self) -> bool:
        """Windows 上探测网关 IP + MAC，通过路由表精确定位网卡"""
        # 1. 如果已有手动 IP 但无 MAC，为所有手动网关查 MAC
        if self._manual_gateway_ip and not self._manual_gateway_mac:
            all_ok = True
            for i, (ip, mac, vlan) in enumerate(self._manual_gateways):
                if ip and not mac:
                    detected_mac = await self._arp_get_mac_windows(ip)
                    if detected_mac:
                        self._manual_gateways[i] = (ip, detected_mac, self._manual_gateways[i][2] if len(self._manual_gateways[i]) > 2 else "")
                    else:
                        all_ok = False
            if all_ok:
                self._manual_gateway_mac = self._manual_gateways[0][1]
                self._manual_gateway_vlan = self._manual_gateways[0][2] if self._manual_gateways and len(self._manual_gateways[0]) > 2 else ""
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
                if self._local_ipv4 and not self._local_ipv4.startswith("169.254."):
                    self._last_known_ip = self._local_ipv4
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
            for i, (ip, mac, vlan) in enumerate(self._manual_gateways):
                if ip and not mac:
                    detected_mac = await self._arp_get_mac_linux(ip)
                    if detected_mac:
                        self._manual_gateways[i] = (ip, detected_mac, self._manual_gateways[i][2] if len(self._manual_gateways[i]) > 2 else "")
                    else:
                        all_ok = False
            if all_ok:
                self._manual_gateway_mac = self._manual_gateways[0][1]
                self._manual_gateway_vlan = self._manual_gateways[0][2] if self._manual_gateways and len(self._manual_gateways[0]) > 2 else ""
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
                if self._local_ipv4 and not self._local_ipv4.startswith("169.254."):
                    self._last_known_ip = self._local_ipv4
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
                "route", "print", "0.0.0.0",  # nosec B104 - route command argument, not binding
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                parts = line.strip().split()
                # 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  25
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":  # nosec B104 - parsing route table output
                    gw = parts[2].strip()
                    if gw and gw != "0.0.0.0" and ":" not in gw:  # nosec B104 - filtering gateway IP in route output
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                            if mask and "." in mask and mask != "0.0.0.0":  # nosec B104 - comparing subnet mask string
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                "route", "print", "0.0.0.0",  # nosec B104 - route command argument, not binding
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode("utf-8", errors="replace")

            # 解析 route print 输出中的默认网关
            # 匹配: 0.0.0.0          0.0.0.0         192.168.1.1      192.168.1.100    25
            for line in text.splitlines():
                if "0.0.0.0" in line and "0.0.0.0" in line:  # nosec B104 - parsing route table output
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":  # nosec B104 - parsing route table output
                        gateway = parts[2].strip()
                        if gateway and gateway != "0.0.0.0" and ":" not in gateway:  # nosec B104 - filtering gateway IP in route output
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
    def _mac_normalize(mac: str) -> str:
        """去掉 MAC 中所有分隔符（:-. ）后统一大写，用于可靠比较不同来源的 MAC"""
        if not mac:
            return ""
        return re.sub(r'[:-]', '', mac).upper()

    @staticmethod
    async def _arp_get_mac_linux(ip: str) -> Optional[str]:
        """Linux: 通过 ip neigh 获取指定 IP 的 MAC 地址"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            if self._local_ipv4 and not self._local_ipv4.startswith("169.254."):
                self._last_known_ip = self._local_ipv4
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                    if mask and mask != "0.0.0.0" and "." in mask:  # nosec B104 - comparing subnet mask string
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
                    if gw and gw != "0.0.0.0" and gw != ":":  # nosec B104 - filtering gateway IP in ipconfig output
                        has_gateway = True

        details = f"IPv4={'正常' if has_ipv4 else '无'}, IPv6={'正常' if has_ipv6 else '无'}, 网关={'存在' if has_gateway else '无'}"
        return has_gateway, details

    async def _check_interface_linux(self) -> Tuple[bool, str]:
        """Linux: 通过路由表精确定位默认路由网卡，检查其状态"""
        iface_info = await self._resolve_interface_linux()
        if iface_info:
            self._local_ipv4 = iface_info["local_ipv4"]
            if self._local_ipv4 and not self._local_ipv4.startswith("169.254."):
                self._last_known_ip = self._local_ipv4
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            if await self._ping_gateway_fast(gw_ip):
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

        # 检测 APIPA：本机 IP 为 169.254.x.x 时，不递增 APIPA
        # 而是基于上次有效的非 APIPA IP 恢复（避免在链路本地子网内空转）
        is_apipa = self._local_ipv4.startswith("169.254.") if self._local_ipv4 else False
        if is_apipa and self._last_known_ip:
            logger.warning("ARP 防护: 本机 IP %s 为 APIPA 地址，"
                           "基于上次有效 IP %s 生成新 IP",
                           self._local_ipv4, self._last_known_ip)
            base_ip = self._last_known_ip
        else:
            base_ip = self._local_ipv4

        new_ip = self._increment_ip(base_ip, self._subnet_mask)
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

        # VLAN 子接口
        vlan_iface = self._interface_name
        vlan_id = self._manual_gateway_vlan
        if vlan_id and not self._vxlan_enabled:
            vlan_iface = f"{self._interface_name}.{vlan_id}"
        try:
            cmd = ["netsh", "interface", "ipv4", "set", "address",
                   f"name={vlan_iface}",
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
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
            if proc.returncode == 0:
                self._local_ipv4 = new_ip
                if new_ip and not new_ip.startswith("169.254."):
                    self._last_known_ip = new_ip
                self._conflict_resolved = True
                logger.warning("ARP 防护: IP 已成功变更为 %s", new_ip)
                # IP 变更后重启 TCP 监听器（避免 WinError 64）
                await self._fire_restart_hooks()
                # 刷新 DNS 缓存（VPN 切换 / IP 变更后旧 DNS 缓存可能指向错误 IP）
                await self._flush_network_stack()
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

        # 检测 APIPA：本机 IP 为 169.254.x.x 时，不递增 APIPA
        # 而是基于上次有效的非 APIPA IP 恢复（避免在链路本地子网内空转）
        is_apipa = self._local_ipv4.startswith("169.254.") if self._local_ipv4 else False
        if is_apipa and self._last_known_ip:
            logger.warning("ARP 防护: 本机 IP %s 为 APIPA 地址，"
                           "基于上次有效 IP %s 生成新 IP",
                           self._local_ipv4, self._last_known_ip)
            base_ip = self._last_known_ip
        else:
            base_ip = self._local_ipv4

        new_ip = self._increment_ip(base_ip, self._subnet_mask)
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

        # VLAN 子接口
        vlan_iface = self._interface_name
        vlan_id = self._manual_gateway_vlan
        if vlan_id and not self._vxlan_enabled:
            vlan_iface = f"{self._interface_name}.{vlan_id}"
        try:
            # 先删除旧 IP
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "del", f"{self._local_ipv4}/{prefix}",
                "dev", vlan_iface,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:200]
                logger.warning("ARP 防护: ip addr del 失败: %s", err)

            # 添加新 IP
            proc = await asyncio.create_subprocess_exec(
                "ip", "addr", "add", f"{new_ip}/{prefix}",
                "dev", vlan_iface,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:200]
                logger.warning("ARP 防护: ip addr add 失败: %s", err)
                return False

            # 如果原来有默认网关，重新添加路由
            if gw_ip:
                await asyncio.create_subprocess_exec(
                    "ip", "route", "replace", "default", "via", gw_ip,
                    "dev", vlan_iface,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )

            self._local_ipv4 = new_ip
            if new_ip and not new_ip.startswith("169.254."):
                self._last_known_ip = new_ip
            self._conflict_resolved = True
            logger.warning("ARP 防护: IP 已成功变更为 %s", new_ip)
            # IP 变更后重启 TCP 监听器（避免 WinError 64）
            await self._fire_restart_hooks()
            # 刷新 DNS 缓存（VPN 切换 / IP 变更后旧 DNS 缓存可能指向错误 IP）
            await self._flush_network_stack()
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
        for gw_ip, expected_mac, vlan_id in self.gateway_pairs:
            if not gw_ip or not expected_mac:
                continue
            if sys.platform == "win32":
                actual_mac = await self._arp_get_mac_windows(gw_ip)
            else:
                actual_mac = await self._arp_get_mac_linux(gw_ip)
            if actual_mac and self._mac_normalize(actual_mac) != self._mac_normalize(expected_mac):
                poisoned.append((gw_ip, expected_mac, actual_mac))
                self._arp_attack_logged = True
        return poisoned

    async def refresh_router_arp(self, abort_check=None) -> bool:
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

        Args:
            abort_check: 可选回调，每次主要步骤后检查，若返回 True 则提前中止（网络已恢复）
        """
        gw_ip = self.gateway_ip
        if not gw_ip:
            logger.warning("ARP 防护: 无法刷新路由器 ARP，未知网关 IP")
            return False

        self._arp_attack_logged = False
        logger.info("ARP 防护: 正在修复路由器 ARP 表 (网关=%s)...", gw_ip)

        # 触发常驻 recovery worker（后台并行监控网关+外网，一通就设 recovery_detected）
        self._recovery_detected.clear()
        self._recovery_trigger.set()

        # 定义 abort 检查辅助（检查常驻 worker 的恢复信号 + 主循环滑动窗口）
        async def _check_abort():
            if self._recovery_detected.is_set():
                logger.info("ARP 防护: 网络已恢复（后台 worker），提前中止修复")
                return True
            if abort_check:
                try:
                    if abort_check():
                        logger.info("ARP 防护: 网络已恢复，提前中止修复")
                        return True
                except Exception:
                    pass
            return False

        try:
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

            # 1. (跳过爆发 ping — recovery worker 已在后台持续 ping 网关)
            if await _check_abort():
                return True

            # 检查本机是否为 APIPA 地址（169.254.x.x）
            # APIPA 时网关在不同子网，所有 ping 必然失败，无需跑丢包检测
            current_ip = self._local_ipv4 or ""
            is_apipa = current_ip.startswith("169.254.")
            if is_apipa:
                logger.warning("ARP 防护: 本机 IP %s 为 APIPA 地址，"
                               "跳过丢包检测，直接执行 IP 冲突修复", current_ip)
                # 构建一个全丢包的 loss_info，直接导向 ip_conflict 分支
                loss_info = {"loss_rate": 1.0, "success": 0, "total": 10,
                             "diagnosis": "ip_conflict"}
            else:
                # 2-3-4. 触发常驻 workers 并发执行（无需 create_task 开销）
                self._loss_result = None
                self._garp_done = False
                self._conflict_result = None
                self._garp_done_event.clear()
                self._loss_done_event.clear()
                self._run_loss.set()
                self._run_garp.set()
                self._run_conflict.set()

                # 等待 GARP 完成（事件通知，不轮询；最多等 2s）
                loss_info = None
                conflict = None
                try:
                    await asyncio.wait_for(self._garp_done_event.wait(), timeout=2.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

                if await _check_abort():
                    return True

                # GARP 完成后验证网关
                if await self._ping_gateway_fast(gw_ip):
                    logger.info("ARP 防护: GARP 爆发后网关 %s 已恢复可达", gw_ip)
                    if self.gateway_mac:
                        if await self._protect_gateway_arp():
                            logger.info("ARP 防护: 静态 ARP 已绑定")
                        else:
                            await self._garp_sustain(gw_ip, duration=3, interval=0.5)
                    return True

                # 等待丢包检测结果（最多等 1s）
                if self._loss_result is None:
                    try:
                        await asyncio.wait_for(self._loss_done_event.wait(), timeout=1.0)
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        pass
                loss_info = self._loss_result

                # 读取 IP 冲突检测结果（worker 已完成，直接取）
                conflict = self._conflict_result

            # 有丢包分析结果时才打印诊断日志
            if loss_info:
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
            else:
                # 没有丢包分析结果（GARP 跑完但网关不通，loss 被取消），手动检查
                if not await self._ping_gateway_fast(gw_ip):
                    logger.warning("ARP 防护: 网关完全不可达，诊断=网络断开")
                loss_info = loss_info or {"loss_rate": 1.0, "success": 0, "total": 10,
                                           "diagnosis": "network_down"}

            if await _check_abort():
                return True

            # 4. IP 冲突检测 + 自动修复（冲突检测已与 GARP 爆发并发执行）
            #    丢包 ~50% 说明有设备用相同静态 IP，即使 ARP 表没显示也要处理
            if (loss_info and loss_info["diagnosis"] == "ip_conflict") or conflict:
                if not conflict:
                    logger.warning("ARP 防护: 丢包模式指向 IP 冲突（ARP 表未捕获），"
                                   "尝试自动 IP +1")
                else:
                    logger.warning("ARP 防护: %s", conflict)
                self._arp_attack_logged = True
                # [永久禁用 IP 迁移] 不切换本机 IP，用 GARP 反制
                logger.warning("ARP 防护: 检测到疑似 IP 冲突，用 GARP 反制（不切换 IP）")
                await self._garp_broadcast_burst(count=5)
                await self._garp_counterstrike(gw_ip, "", burst_size=3, directed_count=3, inter=0.02)

            # 5. 验证 ping（快速版：此时已确定网络异常，80ms 超时足够判断）
            ping_ok = await self._ping_gateway_fast(gw_ip)
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

            # 6. 网关仍不可达 → 持续 ARP 中毒 → GARP 反制（不切换 IP）
            if await _check_abort():
                return True
            await self._garp_broadcast_burst(count=5)
            await self._garp_counterstrike(gw_ip, "", burst_size=3, directed_count=3, inter=0.02)

            logger.warning("ARP 防护: 网关 %s 仍不可达，已用 GARP 反制（不切换 IP），可能存在持续 ARP 攻击或 IP 冲突", gw_ip)
            self._arp_attack_detected = True
            return False
        finally:
            # 恢复 worker 不再需要监控本轮修复，清除 trigger 使其回等待状态
            # recovery_detected 不清除（如果已经恢复，上层会读取），
            # 但 trigger 需清除让 worker 不再循环
            self._recovery_trigger.clear()

    async def _send_single_garp(self, skip_arp_del: bool = False) -> bool:
        """
        发送一个真正的 Gratuitous ARP 数据包，向全网宣告本机 IP↔MAC 绑定。

        Linux: 使用 AF_PACKET 原始套接字构造真实的 ARP 请求包（GARP 格式）。
        Windows: 由于没有 Npcap 时无法发送原始二层 ARP 包，改用了
                 "清空网关 ARP 缓存 + ping 网关" 的方式。
                 Ping 前 OS 会发送 ARP 请求（Sender IP/可信 IP, Sender MAC/本机 MAC），
                 路由器收到 ARP 请求后会根据 RFC 826 更新其 ARP 表。

        Args:
            skip_arp_del: 如果为 True，跳过 arp -d 步骤（用于爆发模式，
                         由 _garp_broadcast_burst 在循环前一次删除）
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
                # VLAN 802.1Q 标签：vlan_id 非空且非 VXLAN 时在以太网头后插入 4 字节
                vlan_id = self._manual_gateway_vlan
                if vlan_id and not self._vxlan_enabled:
                    vlan_tag = struct.pack('!HH', 0x8100, int(vlan_id) & 0xFFF)
                    frame = dest_mac + mac_bytes + vlan_tag + eth_type + arp_payload
                elif vlan_id and self._vxlan_enabled:
                    # VXLAN 封装
                    try:
                        from vxlan_encap import encap_vxlan
                        inner_arp = dest_mac + mac_bytes + eth_type + arp_payload
                        frame = encap_vxlan(inner_arp, int(vlan_id),
                                             self._local_mac or mac_bytes.hex(), dest_mac.hex(),
                                             self._local_ipv4 or "0.0.0.0", gw_ip)
                    except Exception:
                        logger.debug("ARP 防护: VXLAN 封装失败，回退到无标签")
                        frame = dest_mac + mac_bytes + eth_type + arp_payload
                else:
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
            # Windows: 优先用 scapy 发送真实 GARP（需 Npcap），
            # 不可用时回退到静态 ARP 绑定 + ping
            if _SCAPY_AVAILABLE and self._local_mac and self._local_ipv4:
                try:
                    from scapy.all import Ether, ARP, sendp
                    garp_pkt = (
                        Ether(dst="ff:ff:ff:ff:ff:ff", src=self._local_mac) /
                        ARP(op=1,
                            hwsrc=self._local_mac,
                            psrc=self._local_ipv4,
                            hwdst="00:00:00:00:00:00",
                            pdst=self._local_ipv4)
                    )
                    vlan_id = self._manual_gateway_vlan
                    if vlan_id and not self._vxlan_enabled:
                        try:
                            from scapy.all import Dot1Q
                            garp_pkt = (
                                Ether(dst="ff:ff:ff:ff:ff:ff", src=self._local_mac) /
                                Dot1Q(vlan=int(vlan_id)) /
                                ARP(op=1,
                                    hwsrc=self._local_mac,
                                    psrc=self._local_ipv4,
                                    hwdst="00:00:00:00:00:00",
                                    pdst=self._local_ipv4)
                            )
                        except Exception:
                            pass
                    sendp(garp_pkt, iface=self._interface_name or "",
                          verbose=False, count=1, inter=0)
                    return True
                except Exception as e:
                    logger.debug("ARP 防护: scapy GARP 发送失败 (%s)，回退到静态 ARP", e)

            # 兔底：检测本机 ARP 表中网关 MAC 是否被投毒，若被篡改则设静态 ARP 绑定
            actual_mac = await self._arp_get_mac_windows(gw_ip)
            if actual_mac and self._baseline_mac and self._mac_normalize(actual_mac) != self._mac_normalize(self._baseline_mac):
                logger.warning("ARP 防护: 检测到本机 ARP 表中网关 MAC 被篡改 "
                               "%s → %s（实际），正在设置静态 ARP 绑定...",
                               self._baseline_mac, actual_mac)
                bound = await self._protect_gateway_arp()
                if bound:
                    return await self._ping_gateway_fast(gw_ip)
                # 静态绑定失败，回退到 ping 验证
                logger.warning("ARP 防护: 静态 ARP 绑定失败，回退到 ping 网关")
                return await self._ping_gateway_fast(gw_ip)
            # MAC 一致或无法检测，仅做 ping 验证连通性
            return await self._ping_gateway_fast(gw_ip)

    async def _garp_broadcast_burst(self, count: int = 20, inter: float = 0.01):
        """
        爆发式 GARP 广播：检测本机 ARP 表 + 静态绑定 + ping 验证。
        真实 GARP 是二层 ARP 包（EtherType 0x0806, Sender IP = Target IP），
        路由器收到后强制更新 ARP 表，不再依赖 ICMP 的"附带学习"。

        Linux: 使用 AF_PACKET 原始套接字发送真实 GARP ARP 包。
        Windows: 优先用 scapy 发送真实 GARP（需 Npcap），
                 不可用时回退到静态 ARP 绑定 + ping。

        Args:
            count: 发送次数（默认 20 次）
            inter: 包间间隔（秒），0=无间隔连续发送
        """
        gw_ip = self.gateway_ip
        if not gw_ip:
            return

        logger.info("ARP 防护: 检测 ARP 表并修复 x%d (网关=%s, 间隔=%.4fs)", count, gw_ip, inter)

        for i in range(count):
            # 发送真实 GARP 宣告（skip_arp_del=True，已由循环前统一删除）
            await self._send_single_garp(skip_arp_del=True)
            # 每 3 次加一次网关快速 ping（双重确认），成功则提前结束
            if i % 3 == 0:
                if await self._ping_gateway_fast(gw_ip):
                    logger.info("ARP 防护: ARP 修复中网关已恢复 (第 %d 轮)", i + 1)
                    return
            if inter > 0:
                await asyncio.sleep(inter)

        # 最后再 ping 一次广播地址（作为辅助，部分交换机可能需要）
        if inter > 0:
            broadcast_ip = self._get_broadcast_address()
            if broadcast_ip:
                for _ in range(min(count // 4, 5)):
                    await self._ping_broadcast(broadcast_ip)
                    await asyncio.sleep(inter)

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

    def has_recent_attacks(self, seconds: float = 5.0) -> bool:
        """检查指定秒数内是否有任何 ARP 攻击被检测到。

        Args:
            seconds: 检测时间窗口（秒），默认 5 秒

        Returns:
            True 表示窗口内有攻击事件
        """
        if not self._attack_stats:
            return False
        now = asyncio.get_event_loop().time()
        for mac, stats in self._attack_stats.items():
            last_attack = stats.get("last_attack", 0)
            if now - last_attack < seconds:
                return True
        return False

    @staticmethod
    def _get_intensity(attack_rate: int) -> tuple:
        """根据 attack_rate 返回 (burst_size, directed_count, inter, tag)"""
        if attack_rate > 200:
            return (50, 30, 0.00025, "MAX")
        elif attack_rate > 100:
            return (30, 20, 0.0005, "L3")
        elif attack_rate > 50:
            return (20, 15, 0.001, "L2")
        elif attack_rate > 30:
            return (10, 8, 0.0015, "L1")
        elif attack_rate > 10:
            return (10, 8, 0.0015, "L1")
        else:
            return (5, 5, 0.002, "")

    async def _on_arp_attack(self, sender_ip: str, sender_mac: str, reason: str):
        """检测到 ARP 攻击时即时触发反击（嗅探驱动，来一枪回一枪）"""
        if not self._enabled:
            return
        now = asyncio.get_event_loop().time()
        mac_stats = self._attack_stats.get(sender_mac, {})
        attack_rate = mac_stats.get("count", 0)

        # IP 迁移已永久禁用（_ip_migrated 恒为 True），不切换本机 IP。
        # 首次攻击直接进入渐进式反制。

        # IP已迁移 -> 纯渐进式压制（攻击越猛，反制越狠）
        mac_stats["bursts_sent"] = mac_stats.get("bursts_sent", 0) + 1
        mac_stats["last_counterstrike"] = now
        self._counterstrike_count = self._counterstrike_count + 1

        # >200 次/60s -> 无限制火力全开：不设间隔，包数 = attack_rate+10
        if attack_rate > 200:
            burst_size = attack_rate + 10
            directed_count = attack_rate + 10
            inter = 0.0
            logger.warning("ARP 反制 [COUNTERSTRIKE-UNLIMITED]: %s %d次/60s(%s) -> %d包GARP+%d包定向 无间隔！",
                           sender_mac, attack_rate, reason[:40], burst_size, directed_count)
        else:
            burst_size, directed_count, inter, tag = self._get_intensity(attack_rate)
            log_tag = f"[COUNTERSTRIKE-{tag}]" if tag else "[COUNTERSTRIKE]"
            logger.warning("ARP 反制 %s: %s %d次/60s(%s) -> %d包GARP+%d包定向 @%.0fms",
                           log_tag, sender_mac, attack_rate, reason[:40], burst_size, directed_count, inter*1000)

        await self._garp_counterstrike(sender_ip, sender_mac, burst_size=burst_size, directed_count=directed_count, inter=inter)

        if self._poison_detected.is_set():
            self._poison_detected.clear()

    async def _garp_counterstrike(self, attacker_ip: str, attacker_mac: str, burst_size: int = 5, directed_count: int = 5, inter: float = 0.01):
        """增强 GARP 反制：定向反制（常驻 sender 并行）+ GARP 广播"""
        gw_ip = self.gateway_ip
        if not gw_ip:
            return

        # 定向反制：使用攻击者真实 MAC 单播射它，误导其网络栈中断
        # 不再区分 GARP/ARP 攻击（GARP 攻击 attacker_ip=网关，但 attacker_mac 是攻击者真实的）
        is_local = attacker_ip and self._local_ipv4 and attacker_ip == self._local_ipv4
        if attacker_mac and not is_local:
            poison_mac = "FF:FF:FF:FF:FF:FE" if (self._counterstrike_count % 2 == 0) else "00:00:00:00:00:00"
            if _SCAPY_AVAILABLE and self._scapy_sender_ready:
                # 通过常驻 sender 队列发送（一次性导入 scapy，不重复创建）
                self._scapy_sender_queue.put_nowait(
                    (attacker_mac, None, attacker_ip, poison_mac, directed_count, inter, self._manual_gateway_vlan)
                )
            # Windows fallback 已移除：netsh set neighbors 阻塞事件循环最多 5s。

        # GARP 广播（固定 1 包，仅恢复路由器 ARP 表；定向反制已在队列中并行）
        await self._garp_broadcast_burst(count=1)

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

        gw_ip = self.gateway_ip

        # VLAN 子接口
        vlan_iface = self._interface_name
        vlan_id = self._manual_gateway_vlan
        if vlan_id and not self._vxlan_enabled:
            vlan_iface = f"{self._interface_name}.{vlan_id}"
        if sys.platform == "win32":
            cmd = ["netsh", "interface", "ipv4", "set", "address",
                   f"name={vlan_iface}",
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
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
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
                if new_ip and not new_ip.startswith("169.254."):
                    self._last_known_ip = new_ip
                # 注意：此处不刷新 ARP 缓存（arp -d *），
                # 因为 ARP 攻击进行中时清空网关 ARP 条目会让攻击者立刻重新投毒。
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
                    "dev", vlan_iface,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
                # 添加新 IP
                proc = await asyncio.create_subprocess_exec(
                    "ip", "addr", "add", f"{new_ip}/{prefix}",
                    "dev", vlan_iface,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode != 0:
                    err = stderr.decode("utf-8", errors="replace")[:200]
                    logger.warning("ARP 防护: ip addr 切换 IP 失败: %s", err)
                    return False
                # 网关路由
                if gw_ip:
                    await asyncio.create_subprocess_exec(
                        "ip", "route", "replace", "default", "via", gw_ip,
                        "dev", vlan_iface,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                self._local_ipv4 = new_ip  # 切换成功后更新本机 IP
                if new_ip and not new_ip.startswith("169.254."):
                    self._last_known_ip = new_ip
                # 不在此处刷新 ARP 缓存 — 同上（攻击中清空 ARP 有害）
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
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
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
                await asyncio.wait_for(proc.wait(), timeout=8)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                pass

    async def _flush_network_stack(self):
        """
        IP 变更后刷新 DNS 缓存，防止旧 DNS 条目指向过时的上游 IP。
        注意：不在此处刷新 ARP 缓存（arp -d *），
        因为 ARP 攻击进行中时清空网关 ARP 条目会让攻击者立刻重新投毒。
        """
        if sys.platform == "win32":
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ipconfig", "/flushdns",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                pass
        else:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "resolvectl", "flush-caches",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "systemd-resolve", "--flush-caches",
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except (asyncio.TimeoutError, FileNotFoundError, OSError):
                    pass

    async def _garp_ip_switch_defense(self, abort_check=None) -> bool:
        """
        [DEPRECATED] 两阶段 GARP 抗 ARP 中毒（MITM）—— IP 迁移已永久禁用，不再调用。
        保留以防将来需要恢复此策略。

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

        Args:
            abort_check: 可选回调，操作间检查，若返回 True 则提前中止

        Returns:
            True 表示切换后网关可达
        """
        # 定义 abort 检查辅助
        async def _check_abort():
            if abort_check:
                try:
                    if abort_check():
                        logger.info("ARP 防护: 网络已恢复，提前中止两阶段切换")
                        return True
                except Exception:
                    pass
            return False

        original_ip = self._local_ipv4
        if not original_ip or not self._subnet_mask:
            logger.warning("ARP 防护: 缺少 IP 或子网掩码，无法执行两阶段 GARP")
            return False
        # 保存当前有效 IP 供后续 APIPA 恢复使用
        if original_ip and not original_ip.startswith("169.254."):
            self._last_known_ip = original_ip

        # 计算临时 IP（在当前主机位范围内偏移 50，避免冲突）
        decoy_ip = self._increment_ip(original_ip, self._subnet_mask, offset=50)
        if not decoy_ip or decoy_ip == original_ip:
            logger.warning("ARP 防护: 无法生成临时 IP，跳过两阶段 GARP")
            return False

        gw_ip = self.gateway_ip
        logger.warning("ARP 防护: 两阶段 GARP 抗中毒: %s → %s → %s",
                        original_ip, decoy_ip, original_ip)

        if await _check_abort():
            return True

        # --- 阶段 1：切换到临时 IP，宣告解绑 ---
        logger.info("ARP 防护: 阶段 1 — 切换到临时 IP %s", decoy_ip)
        if not await self._switch_ip(decoy_ip):
            logger.warning("ARP 防护: 切换到临时 IP %s 失败", decoy_ip)
            return False

        self._local_ipv4 = decoy_ip
        await self._garp_broadcast_burst(count=5)
        await asyncio.sleep(0.1)

        if await _check_abort():
            return True

        # --- 阶段 2：永久迁移到邻接 IP（只切一次，不切回原 IP）---
        new_ip = self._increment_ip(original_ip, self._subnet_mask, offset=-1)
        if not new_ip or new_ip == original_ip:
            new_ip = self._increment_ip(original_ip, self._subnet_mask, offset=1)
        if not new_ip or new_ip == original_ip:
            new_ip = self._increment_ip(original_ip, self._subnet_mask, offset=2)
        logger.info("ARP 防护: 阶段 2 — 永久迁移 %s → %s（废弃 %s 让攻击者自娱）", original_ip, new_ip, original_ip)

        # 单次切换（不切回，不双击）
        migrated_ok = False
        if new_ip and new_ip != original_ip and await self._switch_ip(new_ip):
            self._local_ipv4 = new_ip
            migrated_ok = True
        else:
            # 主 IP 失败 -> 尝试备用 IP（original+2）
            fallback_ip = self._increment_ip(original_ip, self._subnet_mask, offset=2)
            if fallback_ip and fallback_ip != original_ip and await self._switch_ip(fallback_ip):
                logger.warning("ARP 防护: 已切换到备用 IP %s（原 IP %s 冲突中）", fallback_ip, original_ip)
                self._local_ipv4 = fallback_ip
                migrated_ok = True

        if migrated_ok:
            # GARP 爆发 + ping 验证 + 静态 ARP
            await self._garp_broadcast_burst(count=5)
            await asyncio.sleep(0.1)
            reachable = False
            for attempt in range(2):
                reachable = await self._ping_gateway_fast(gw_ip)
                if reachable:
                    break
                if attempt < 1:
                    await asyncio.sleep(0.1)
            if reachable and self.gateway_mac:
                await self._protect_gateway_arp()
            # 刷新 DNS 缓存（IP 变更后旧 DNS 缓存可能指向错误 IP）
            # 注意：不重启 DoH 服务器（DoH 绑定 127.0.0.1 不受 LAN IP 变更影响）
            await self._flush_network_stack()
            return reachable

        # 所有尝试都失败 -> DHCP 恢复
        logger.critical("ARP 防护: 无法设置任何静态 IP，尝试 DHCP 恢复")
        await self._recover_interface_dhcp()
        await self._fire_restart_hooks()  # DHCP 可能拿到不同子网 IP，需重启 TCP
        await self._flush_network_stack()
        return False

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

        if self._mac_normalize(current_mac) == self._mac_normalize(expected_mac):
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                old_vlan = self._manual_gateways[0][2] if self._manual_gateways and len(self._manual_gateways[0]) > 2 else ""
                self._manual_gateways[0] = (gw_ip, new_mac, old_vlan)
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
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                dev = iface
                vlan_id = self._manual_gateway_vlan
                if vlan_id and not self._vxlan_enabled:
                    dev = f"{iface}.{vlan_id}"
                proc = await asyncio.create_subprocess_exec(
                    "ip", "neigh", "replace", gw_ip,
                    "dev", dev, "lladdr", mac_fmt, "nud", "permanent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
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
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
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
    async def _fetch_local_ips(interface_name: str) -> set:
        """
        获取指定网卡的所有 IPv4 地址。
        用于嗅探 worker 比对 IP 冲突（本机可能有多 IP）。
        """
        ips: set = set()
        if not interface_name:
            return ips
        try:
            if sys.platform == "win32":
                proc = await asyncio.create_subprocess_exec(
                    "ipconfig",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                text = stdout.decode("utf-8", errors="replace")
                in_adapter = False
                for line in text.splitlines():
                    s = line.strip()
                    # 检测到本网卡段
                    if interface_name.lower() in s.lower() and ("适配器" in s or "adapter" in s):
                        in_adapter = True
                        continue
                    if in_adapter:
                        # 空行 = 网卡段结束
                        if not s:
                            break
                        # 提取 IPv4 地址
                        for key in ("IPv4", "IP Address", "IPv4 地址", "IP 地址"):
                            if key in s and ":" in s:
                                ip = s.split(":", 1)[1].strip()
                                if "." in ip:
                                    m = re.match(r'(\d+\.\d+\.\d+\.\d+)', ip)
                                    if m:
                                        ips.add(m.group(1))
            else:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "-4", "addr", "show", "dev", interface_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ips.add(m.group(1))
        except Exception as e:
            logger.debug("ARP 防护: 获取本机 IP 列表失败: %s", e)
        return ips

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

    async def _ping_gateway(self, gw_ip: str) -> bool:
        """ping 网关（直接使用 ping_interval 转为毫秒，公式 ping_interval×1000 ms）"""
        timeout_ms = int(self._ping_interval * 1000)
        return await ARPProtection._ping_icmp(gw_ip, timeout_ms=timeout_ms)

    async def _ping_gateway_fast(self, gw_ip: str) -> bool:
        """ping 网关（使用 ping_interval 超时，用于 GARP 爆发场景的快速验证，不启用 TCP 兜底）"""
        timeout_ms = int(self._ping_interval * 1000)
        return await ARPProtection._ping_icmp(gw_ip, timeout_ms=timeout_ms, use_tcp_fallback=False)

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
        result = await ARPProtection._ping_icmp_detailed(ip, timeout_ms,
                                                          use_tcp_fallback=use_tcp_fallback)
        return result["reachable"]

    @staticmethod
    async def _ping_icmp_detailed(ip: str, timeout_ms: int,
                                   use_tcp_fallback: bool = True,
                                   gateway_ip: str = None) -> dict:
        """
        底层 ICMP 详细探测 — 返回结构化结果而非仅 bool。

        Args:
            ip: 目标 IP
            timeout_ms: ping 内部超时（毫秒）
            use_tcp_fallback: 是否在 ICMP 失败时尝试 TCP 兜底
            gateway_ip: 本机网关 IP，用于判断 ICMP 回复是否来自网关

        Returns:
            {"reachable": bool, "icmp_type": int|None, "icmp_code": int|None,
             "from_ip": str|None, "saw_reply": bool,
             "gateway_unreachable": bool, "diagnosis": str}
            - reachable: True 仅当收到来自目标的有效 Echo Reply
            - icmp_type / icmp_code / from_ip: 从 ICMP 响应解析
            - saw_reply: 是否收到任何 ICMP 响应（vs. 超时无响应）
            - gateway_unreachable: 是否来自网关的 Destination Unreachable
            - diagnosis: "destination_unreachable" | "timeout" | "echo_reply" | "tcp_ok" | "tcp_fail"
        """
        if sys.platform == "win32":
            result = await ARPProtection._ping_icmp_windows_detailed(ip, timeout_ms)
        else:
            result = await ARPProtection._ping_icmp_linux_detailed(ip, timeout_ms)

        # 分析诊断结果
        if result.get("reachable"):
            result["diagnosis"] = "echo_reply"
            result["gateway_unreachable"] = False
            return result

        # 检查是否为来自网关的 Destination Unreachable
        from_ip = result.get("from_ip")
        icmp_type = result.get("icmp_type")
        icmp_code = result.get("icmp_code") if result.get("icmp_code") is not None else -1
        gw_unreach = (icmp_type == 3 and icmp_code in (0, 1)
                      and from_ip is not None
                      and (gateway_ip is None or from_ip == gateway_ip))

        if gw_unreach:
            result["diagnosis"] = "destination_unreachable"
            result["gateway_unreachable"] = True
            return result

        if result.get("saw_reply"):
            # 收到了 ICMP 响应但不是有效的 Echo Reply
            result["reachable"] = False
            result["diagnosis"] = f"icmp_type_{icmp_type}"
            result["gateway_unreachable"] = False
            return result

        # 超时 — 尝试 TCP 兜底
        result["gateway_unreachable"] = False
        if not use_tcp_fallback:
            result["diagnosis"] = "timeout"
            return result

        tcp_ok = await ARPProtection._ping_tcp(ip, timeout_ms=3000)
        if tcp_ok:
            result["reachable"] = True
            result["diagnosis"] = "tcp_ok"
        else:
            result["diagnosis"] = "tcp_fail"
        # TCP 兜底不改 ICMP 详情
        return result

    @staticmethod
    def _is_destination_unreachable(result: dict, unreachable_codes: list = None) -> bool:
        """
        判断 ICMP 详细探测结果是否为来自网关的 Destination Unreachable。

        Args:
            result: _ping_icmp_detailed 的返回字典
            unreachable_codes: 哪些 code 算断网（默认 [0, 1]）
        Returns:
            True 当 type=3 且 code 在列表中且 from_ip 是网关
        """
        if unreachable_codes is None:
            unreachable_codes = [0, 1]
        icmp_code = result.get("icmp_code")
        return (result.get("icmp_type") == 3
                and icmp_code is not None
                and icmp_code in unreachable_codes
                and result.get("from_ip") is not None
                and result.get("gateway_unreachable", False))

    @staticmethod
    async def probe_wan_unreachable(target_ip: str, gateway_ip: str = None,
                                     timeout_ms: int = 3000) -> dict:
        """
        对外网目标发送 ICMP，检测是否收到来自网关的 Destination Unreachable。

        这是 WAN 断连检测的核心方法：当光猫运行但光纤断开时，
        光猫（网关）会对外网目标回复 ICMP type=3 Destination Unreachable。

        Args:
            target_ip: 外网探测目标 IP
            gateway_ip: 本机网关 IP（用于判断回复来源）
            timeout_ms: 探测超时（毫秒）

        Returns:
            {"wan_dead": bool, "unreachable_code": int|None,
             "from_ip": str|None, "timeout": bool, "detail": dict}
            - wan_dead: True 确认 WAN 断连（收到来自网关的 Dest Unreachable）
            - unreachable_code: ICMP code (0=Network, 1=Host)
            - from_ip: 回复来源 IP
            - timeout: 是否超时（可能被防火墙丢弃，不判定）
        """
        result = await ARPProtection._ping_icmp_detailed(
            target_ip, timeout_ms=timeout_ms,
            use_tcp_fallback=False, gateway_ip=gateway_ip)

        is_unreachable = ARPProtection._is_destination_unreachable(result, [0, 1])
        icmp_code = result.get("icmp_code")
        return {
            "wan_dead": is_unreachable,
            "unreachable_code": int(icmp_code) if icmp_code is not None else None,
            "from_ip": result.get("from_ip"),
            "timeout": result.get("diagnosis") == "timeout",
            "detail": result,
        }

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
        result = await ARPProtection._ping_icmp_windows_detailed(ip, timeout_ms)
        return result["reachable"]

    @staticmethod
    async def _ping_icmp_windows_detailed(ip: str, timeout_ms: int) -> dict:
        """
        Windows ICMP 详细探测 — 解析 ping.exe 输出提取 Dest Unreachable。

        Returns:
            {"reachable": bool, "icmp_type": int|None, "icmp_code": int|None,
             "from_ip": str|None, "saw_reply": bool, "stdout_lines": list}
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", "1", "-w", str(timeout_ms), ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=(timeout_ms / 1000) + 5)
            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            lines = stdout_text.splitlines()

            # ping.exe exit code: 0=success, 1=unreachable/timeout
            reachable = (proc.returncode == 0)

            # 解析 Dest Unreachable 关键词
            from_ip = None
            icmp_type = None
            icmp_code = None
            saw_reply = False

            for line in lines:
                # 匹配 "Reply from X.X.X.X: Destination net unreachable" 等
                # 或者 "来自 X.X.X.X 的回复: 无法访问目标主机"
                if "unreachable" in line.lower() or "无法访问" in line or "目标不可达" in line:
                    icmp_type = 3  # Destination Unreachable
                    if "net" in line.lower() or "network" in line.lower():
                        icmp_code = 0  # Network Unreachable
                    elif "host" in line.lower():
                        icmp_code = 1  # Host Unreachable
                    else:
                        icmp_code = 1  # 默认 Host Unreachable
                    saw_reply = True
                    # 尝试提取来源 IP（模块级已 import re）
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        from_ip = m.group(1)
                elif "Reply from" in line or "来自" in line:
                    saw_reply = True
                    if reachable:
                        icmp_type = 0  # Echo Reply
                        icmp_code = 0
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        from_ip = m.group(1)

            return {"reachable": reachable, "icmp_type": icmp_type, "icmp_code": icmp_code,
                    "from_ip": from_ip, "saw_reply": saw_reply, "stdout_lines": lines}

        except (asyncio.TimeoutError, FileNotFoundError):
            return {"reachable": False, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": False, "stdout_lines": []}

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
        result = await ARPProtection._ping_icmp_linux_detailed(ip, timeout_ms)
        return result["reachable"]

    @staticmethod
    async def _ping_icmp_linux_detailed(ip: str, timeout_ms: int) -> dict:
        """
        Linux ICMP 详细探测 — 解析 ICMP 响应的 type/code/source IP。

        Returns:
            {"reachable": bool, "icmp_type": int|None, "icmp_code": int|None,
             "from_ip": str|None, "saw_reply": bool}
            - reachable: True 仅当收到来自目标 IP 的 Echo Reply (type=0)
            - icmp_type / icmp_code: 收到的 ICMP 响应的 type/code（无论来自谁）
            - from_ip: 发回 ICMP 响应的设备 IP（网关在光纤断开时会回复）
            - saw_reply: 是否收到了任何 ICMP 响应（用于区分超时 vs 被回复）
        """
        cls = ARPProtection
        try:
            if cls._icmp_sock is None:
                cls._icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                               socket.IPPROTO_ICMP)
                cls._icmp_sock.setblocking(False)
            sock = cls._icmp_sock

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
            sock.settimeout(timeout_ms / 1000.0)
            sock.setblocking(True)
            resp, addr = sock.recvfrom(4096)
            # addr = (source_ip, port) — port is 0 for raw sockets

            # 解析 IP 头 + ICMP 载荷
            # IP 头最小 20 字节（ihl * 4）
            ip_ihl = (resp[0] & 0x0F) * 4
            src_ip = socket.inet_ntoa(resp[12:16])  # 源 IP 在偏移 12-15

            if len(resp) < ip_ihl + 8:
                # 包太短，无法解析 ICMP 头
                return {"reachable": False, "icmp_type": None, "icmp_code": None,
                        "from_ip": src_ip, "saw_reply": True}

            # ICMP 头在 IP 头之后
            icmp_type = resp[ip_ihl]
            icmp_code = resp[ip_ihl + 1]

            # type=0 (Echo Reply) 且源 IP == 目标 → 真正的可达
            reachable = (icmp_type == 0 and src_ip == ip)
            return {"reachable": reachable, "icmp_type": icmp_type, "icmp_code": icmp_code,
                    "from_ip": src_ip, "saw_reply": True}

        except socket.timeout:
            return {"reachable": False, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": False}
        except PermissionError:
            # 没有 raw socket 权限，回退
            pass
        except Exception:
            return {"reachable": False, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": False}
        finally:
            # 恢复非阻塞供下次复用
            if cls._icmp_sock is not None:
                try:
                    cls._icmp_sock.setblocking(False)
                except Exception:
                    pass

        # 回退：使用 timeout 包装的子进程 ping
        try:
            proc = await asyncio.create_subprocess_exec(
                "timeout", str(timeout_ms / 1000), "ping", "-c", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=(timeout_ms / 1000) + 1)
            reachable = (proc.returncode == 0)
            return {"reachable": reachable, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": reachable}
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
            return {"reachable": False, "icmp_type": None, "icmp_code": None,
                    "from_ip": None, "saw_reply": False}

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
            "gateway_vlan": self.gateway_vlan or "",
            "vxlan_enabled": self._vxlan_enabled,
            "manual_gateway_count": len(self._manual_gateways),
            "local_ipv4": self._local_ipv4,
            "local_mac": self._local_mac,
            "subnet_mask": self._subnet_mask,
            "broadcast": self._get_broadcast_address(),
            "manual_ip": bool(self._manual_gateway_ip),
            "manual_mac": bool(self._manual_gateway_mac),
            "detected": self._detected,
            "arp_attack_detected": self._arp_attack_detected,
        }

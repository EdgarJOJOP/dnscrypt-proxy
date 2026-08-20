# -*- coding: utf-8 -*-
"""
ScapyBridge — 共享 scapy sniff 基础设施
========================================
将 ARP / NDP 防护的两个独立 scapy sniff（各占一个 Npcap 捕获会话）合并为
单一 sniff 会话（filter="arp or icmp6"），由 dispatcher 回调分发到各模块的
prn 处理器。减少对 Npcap 内核驱动的会话占用，避免多会话场景下驱动异常
（如 STOP_PENDING 卡死）。

- sniff 在独立守护线程运行，模块 prn 回调须自行保证线程安全
  （NDP 用 call_soon_threadsafe、ARP 用 call_soon_threadsafe+queue，均满足）
- is_ready() 探测 Npcap 是否枚举到物理网卡（仅 loopback 视为不可用）
- 按配置开关：仅当 ARP 或 NDP 防护 enabled 时由 network_monitor 调用 start()
- send_packet() 统一 sendp 出口（保留模块内 sendp 逻辑亦可，此处为可选辅助）
"""
import threading
import logging

logger = logging.getLogger("dns-proxy.scapy-bridge")

_bridge_singleton = None
_bridge_lock = threading.Lock()


def get_scapy_bridge():
    """模块级单例"""
    global _bridge_singleton
    with _bridge_lock:
        if _bridge_singleton is None:
            _bridge_singleton = ScapyBridge()
        return _bridge_singleton


class ScapyBridge:
    def __init__(self):
        self._prns = []          # prn 回调列表（sniff 线程调用）
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._loop = None        # asyncio loop（供需要 threadsafe 的 prn）
        self._scapy = None       # 延迟导入
        self._gen = 0            # 代际计数：防旧 sniff 线程 finally 误杀新桥

    # ======================== 生命周期 ========================

    def set_loop(self, loop):
        """绑定 asyncio 事件循环（供 prn 回调内 call_soon_threadsafe 使用）"""
        self._loop = loop

    def register_prn(self, callback):
        """注册嗅探回调（scapy prn 风格：接收一个 pkt 参数）"""
        with self._lock:
            if callback not in self._prns:
                self._prns.append(callback)

    def unregister_prn(self, callback):
        with self._lock:
            if callback in self._prns:
                self._prns.remove(callback)

    def is_ready(self) -> bool:
        """Npcap 驱动可用性：get_if_list 是否含物理网卡（仅 loopback 视为不可用）"""
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            if not ifaces:
                return False
            return not all(("Loopback" in i or "loopback" in i) for i in ifaces)
        except Exception:
            return False

    def is_active(self) -> bool:
        """嗅探线程是否运行中"""
        return self._running and self._thread is not None

    def start_if_ready(self) -> bool:
        """若 Npcap 可用则启动嗅探线程；否则返回 False（模块走 fallback）"""
        if self._running:
            return True
        if not self.is_ready():
            logger.warning("ScapyBridge: Npcap 未枚举到物理网卡（驱动可能未运行），"
                           "共享嗅探不可用，ARP/NDP 走各自 fallback")
            return False
        try:
            import scapy.all as S
            self._scapy = S
        except Exception as e:
            logger.warning("ScapyBridge: scapy 导入失败: %s", e)
            return False
        # 先递增代际再置 running：防 join 超时残留的旧线程在间隙执行 finally 误杀新桥（review should-fix）
        self._gen += 1
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, args=(self._gen,),
                                        name="scapy-bridge-sniff", daemon=True)
        self._thread.start()
        logger.info("ScapyBridge: 共享嗅探已启动（单一 Npcap 会话，filter=arp or icmp6）")
        return True

    def stop(self):
        """停止嗅探线程（确保干净退出，避免驱动句柄残留）"""
        self._running = False
        if self._thread:
            try:
                self._thread.join(timeout=3.0)
            except Exception:
                pass
            self._thread = None

    # ======================== 内部 ========================

    @staticmethod
    def _clean_npcap_error(msg: str) -> str:
        """清洗 Npcap/scapy 异常消息中的 GBK 乱码（SF-12/SF-13）。

        实测（打开 NPF_Loopback）异常结构：
          'Error opening adapter: 系统找不到指定的路径。  (3)\\x00緞銆�  (3)'
        pcap 错误缓冲以 \\x00 结尾，其后为缓冲区残留/重复错误文本（乱码源）。
        清洗：① NUL 截断（主要手段，剥离残留段）；② latin-1 扩展字符占比高
        （GBK 字节被 latin-1 误存）时尝试 latin-1→gbk 还原；均失败原样返回。
        """
        if not msg:
            return msg
        # 1) NUL 截断：\\x00 后为 pcap 缓冲残留/重复错误段（緞銆� 等乱码来源）
        if "\x00" in msg:
            msg = msg.split("\x00", 1)[0]
        # 2) latin-1 误存的 GBK 中文还原（ctypes 逐字节映射场景）
        latin1_chars = [c for c in msg if "\u0080" <= c <= "\u00ff"]
        if latin1_chars and len(latin1_chars) / max(1, len(msg)) >= 0.05:
            try:
                fixed = msg.encode("latin-1").decode("gbk", errors="replace")
                if fixed.count("\ufffd") <= msg.count("\ufffd"):
                    return fixed
            except Exception:
                pass
        return msg

    def _sniff_loop(self, gen):
        """sniff 分段超时循环：静默网段也定期检查 _running/gen，确保 stop() 可干净退出
        （review should-fix：stop_filter 仅在收包时评估，无 timeout 时静默网段 join 会超时残留）。

        SF-14：适配器短暂失效（如迅游加速器创建/修改虚拟网卡时 Npcap 适配器引用失效，
        sniff 抛 "Error opening adapter: 系统找不到指定的路径"）时自动指数退避重试，
        而非一次性退出导致 ARP/NDP 永久回退轮询；连续 5 次失败或 Npcap 无物理网卡才退出。
        """
        fail_count = 0
        import time as _time
        while self._running and gen == self._gen:
            try:
                self._scapy.sniff(
                    filter="arp or icmp6",
                    prn=self._dispatch,
                    store=False, quiet=True,
                    timeout=1.0,
                    stop_filter=lambda _p: not self._running or gen != self._gen,
                )
                fail_count = 0  # 正常返回（含 1s 超时静默）即重置连续失败计数
            except Exception as e:
                clean = self._clean_npcap_error(str(e))
                # SF-14 整改（review should-fix）：区分“确实无物理网卡”（枚举成功但仅 Loopback）
                # 与“枚举瞬时失败”（get_if_list 抛异常 → 走退避重试），避免瞬态失效被误判退出
                try:
                    from scapy.all import get_if_list as _gif
                    _ifaces = _gif()
                    # SF-14 整改（security_review low）：空列表与仅 Loopback 均视为
                    # “无可用物理网卡”→ 退出（与 is_ready 语义一致），避免多退避 15s
                    if not _ifaces or all(("Loopback" in i or "loopback" in i) for i in _ifaces):
                        logger.warning("ScapyBridge: Npcap 无可用物理网卡，sniff 退出: %s", clean)
                        break
                except Exception:
                    pass  # Npcap 枚举瞬时失败 → 计入 fail_count 走退避重试
                fail_count += 1
                if fail_count >= 5:
                    logger.warning("ScapyBridge: sniff 连续失败 %d 次，退出: %s", fail_count, clean)
                    break
                delay = min(2 ** (fail_count - 1), 30.0)  # 实际序列 1,2,4,8s（第 5 次在 sleep 前退出）
                logger.debug("ScapyBridge: sniff 异常(第%d次)，%.0fs 后重试: %s",
                             fail_count, delay, clean)
                _time.sleep(delay)
                # 注：stop() 时若线程恰在退避 sleep，join(3s) 可能超时；线程为 daemon，
                # 醒来即退出，且 start_if_ready 递增 gen 防旧线程误杀新桥，可接受
        # 仅当本线程仍是当前代际时才复位 _running（防旧线程误杀新桥）
        if gen == self._gen:
            self._running = False

    def _dispatch(self, pkt):
        """sniff 线程回调 → 分发到所有注册 prn（模块回调自行保证线程安全）"""
        with self._lock:
            prns = list(self._prns)
        for cb in prns:
            try:
                cb(pkt)
            except Exception:
                pass

    # ======================== 发送（可选统一出口） ========================

    def send_packet(self, pkt, iface, count=1, inter=0.0):
        """统一 sendp 出口（Npcap 不可用时返回 0）"""
        if self._scapy is None:
            return 0
        try:
            return self._scapy.sendp(pkt, iface=iface, verbose=False,
                                     count=count, inter=inter)
        except Exception:
            return 0

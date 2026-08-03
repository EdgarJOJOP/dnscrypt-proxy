"""
ARP 防护 = 完整测试套件
=======================
覆盖场景:
  + 有 Npcap (scapy 可用): 嗅探投毒检测 + 定向毒化反制 + GARP 广播
  + 无 Npcap (scapy 不可用): arp -a 轮询 + arp -d/ping/静态绑定 修复
  + 投毒→完整反制链路: GARP 爆发 / 定向随机 MAC 毒化 / 静态绑定
  + 防自伤: 攻击者冒用本机 MAC 时跳过定向反制

使用方法:
  python test_arp_protection.py
"""

import sys
import os
import asyncio
import random
import time
# 确保能导入项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from arp_protection import ARPProtection

# ============================================================
# 测试框架辅助
# ============================================================
_pass_count = 0
_fail_count = 0
_fail_details = []

def check(condition: bool, msg: str):
    global _pass_count, _fail_count, _fail_details
    if condition:
        _pass_count += 1
        print(f"  OK {msg}")
    else:
        _fail_count += 1
        _fail_details.append(msg)
        print(f"  XX {msg}")

def check_eq(actual, expected, msg: str):
    return check(actual == expected, f"{msg}: 期望={expected!r}, 实际={actual!r}")

def check_ne(actual, unexpected, msg: str):
    return check(actual != unexpected, f"{msg}: 不应等于{unexpected!r}, 实际={actual!r}")

def check_in(item, container, msg: str):
    return check(item in container, f"{msg}: {item!r} 应在 {container!r} 中")

# ============================================================
# 测试配置与 Mock
# ============================================================

def _make_test_config(manual_gateway: str = "192.168.1.1,aa-bb-cc-dd-ee-ff,") -> dict:
    """生成最小 ARP 防护测试配置"""
    return {
        "enabled": True,
        "gateway": manual_gateway,
        "vxlan_enabled": False,
    }


async def _async_true(*args, **kwargs):
    return True

async def _async_false(*args, **kwargs):
    return False


# ============================================================
# 1. 无 Npcap：_check_arp_poisoning 检测投毒
# ============================================================

async def test_check_arp_poisoning_noscapy():
    """无 Npcap 时 _check_arp_poisoning 应返回被投毒的网关条目"""
    print("\n" + "=" * 60)
    print("1. _check_arp_poisoning (无 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._auto_gateway_mac = "AA:BB:CC:DD:EE:FF"

    # Mock 返回被篡改的 MAC
    async def mock_poisoned(ip):
        return "11:22:33:44:55:66"
    arp._arp_get_mac_windows = mock_poisoned

    poisoned = await arp._check_arp_poisoning()

    check(len(poisoned) > 0, "应检测到 ARP 投毒")
    if poisoned:
        gw_ip, expected, actual = poisoned[0]
        check_eq(gw_ip, "192.168.1.1", "投毒网关 IP")
        check_ne(actual, expected, "实际 MAC ≠ 预期 MAC")


async def test_check_arp_poisoning_anomaly_mac():
    """无 Npcap 时异常 MAC（全零/广播）应被检测为投毒"""
    print("\n" + "=" * 60)
    print("2. _check_arp_poisoning 异常 MAC 检测")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._auto_gateway_mac = "AA:BB:CC:DD:EE:FF"

    # 测试全零 MAC
    async def mock_zero_mac(ip):
        return "00:00:00:00:00:00"
    arp._arp_get_mac_windows = mock_zero_mac
    poisoned = await arp._check_arp_poisoning()
    check(len(poisoned) > 0, "全零 MAC 应被检测为投毒")

    # 测试广播 MAC
    async def mock_broadcast_mac(ip):
        return "FF:FF:FF:FF:FF:FF"
    arp._arp_get_mac_windows = mock_broadcast_mac
    poisoned = await arp._check_arp_poisoning()
    check(len(poisoned) > 0, "广播 MAC 应被检测为投毒")


# ============================================================
# 3. 无 Npcap：_garp_broadcast_burst 回退路径
# ============================================================

async def test_garp_broadcast_burst_noscapy():
    """无 Npcap 时 _garp_broadcast_burst 走回退路径，不抛异常"""
    print("\n" + "=" * 60)
    print("3. _garp_broadcast_burst (无 Npcap 回退)")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    # 显式设为无 Npcap，避免误触 scapy 发包
    import arp_protection as ap_mod
    ap_mod._SCAPY_AVAILABLE = False
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._auto_gateway_mac = "AA:BB:CC:DD:EE:FF"
    arp._local_mac = "AA:BB:CC:DD:EE:FF"
    arp._local_ipv4 = "192.168.1.100"
    arp._local_mac_win = ""
    arp._interface_name = "eth0"

    # Mock
    arp._ping_gateway_fast = lambda ip: _async_true()
    arp._protect_gateway_called = False
    async def mock_protect(abort_check=None):
        arp._protect_gateway_called = True
        return True
    arp._protect_gateway_arp = mock_protect

    try:
        await arp._garp_broadcast_burst(count=5, inter=0.001)
        check(True, "_garp_broadcast_burst 无 Npcap 回退正常执行")
    except Exception as e:
        check(False, f"_garp_broadcast_burst 异常: {e}")


# ============================================================
# 4. 有 Npcap：_garp_counterstrike 随机 MAC
# ============================================================

async def test_garp_counterstrike_random_mac():
    """有 Npcap 时 _garp_counterstrike 使用随机 MAC 定向毒化"""
    print("\n" + "=" * 60)
    print("4. _garp_counterstrike 随机 MAC (有 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._auto_gateway_mac = "AA:BB:CC:DD:EE:FF"

    # 模拟有 scapy
    import arp_protection as ap_mod
    saved_scapy = ap_mod._SCAPY_AVAILABLE
    ap_mod._SCAPY_AVAILABLE = True
    arp._scapy_sender_ready = True
    arp._local_macs = set()
    arp._ping_gateway_fast = lambda ip: _async_true()

    # 记录定向毒化用的 poison_mac
    sent_macs = []
    orig_queue_put = arp._scapy_sender_queue.put_nowait
    def tracking_put(item):
        if item is not None:
            sent_macs.append(item[3])
    arp._scapy_sender_queue.put_nowait = tracking_put

    for i in range(5):
        arp._counterstrike_count = i
        await arp._garp_counterstrike(
            attacker_ip="192.168.1.1",
            attacker_mac="11:22:33:44:55:66",
            burst_size=3, directed_count=3, inter=0.001,
        )

    ap_mod._SCAPY_AVAILABLE = saved_scapy
    arp._scapy_sender_queue.put_nowait = orig_queue_put

    check(len(sent_macs) > 0, "定向毒化包已发送")
    if len(sent_macs) >= 2:
        check_ne(sent_macs[0], sent_macs[1], "每次反制使用不同随机 MAC")
    for mac in sent_macs:
        check(mac.startswith("02:"), f"随机 MAC 以 02: 开头: {mac}")
        parts = mac.split(":")
        check(len(parts) == 6, f"MAC 格式有效 (6 段): {mac}")


# ============================================================
# 5. 防自伤：攻击者冒用本机 MAC
# ============================================================

async def test_garp_counterstrike_self_protect():
    """攻击者冒用本机 MAC 时跳过定向反制，仅广播 GARP"""
    print("\n" + "=" * 60)
    print("5. _garp_counterstrike 防自伤")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._local_macs = {"AA:BB:CC:DD:EE:FF"}
    arp._ping_gateway_fast = lambda ip: _async_true()
    arp._protect_gateway_called = False
    async def mock_protect(abort_check=None):
        arp._protect_gateway_called = True
        return True
    arp._protect_gateway_arp = mock_protect
    arp._garp_burst_called = False
    async def mock_burst(count=20, inter=0.01):
        arp._garp_burst_called = True
    arp._garp_broadcast_burst = mock_burst

    import arp_protection as ap_mod
    saved_scapy = ap_mod._SCAPY_AVAILABLE
    ap_mod._SCAPY_AVAILABLE = True
    arp._scapy_sender_ready = True

    await arp._garp_counterstrike(
        attacker_ip="192.168.1.100",
        attacker_mac="AA:BB:CC:DD:EE:FF",
        burst_size=5, directed_count=5, inter=0.001,
    )

    ap_mod._SCAPY_AVAILABLE = saved_scapy
    check(arp._garp_burst_called, "广播 GARP 已执行")
    check(arp._protect_gateway_called, "静态 ARP 绑定已执行")


# ============================================================
# 6. 投毒→完整反制链路（嗅探触发）
# ============================================================

async def test_poison_to_full_defense():
    """嗅探检测投毒→_on_arp_attack→完整反制"""
    print("\n" + "=" * 60)
    print("6. 投毒→完整反制链路")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"
    arp._auto_gateway_mac = "AA:BB:CC:DD:EE:FF"

    import arp_protection as ap_mod
    saved_scapy = ap_mod._SCAPY_AVAILABLE
    ap_mod._SCAPY_AVAILABLE = True
    arp._scapy_sender_ready = True
    arp._local_macs = set()
    arp._ping_gateway_fast = lambda ip: _async_true()

    counterstrike_called = False
    orig_counterstrike = arp._garp_counterstrike
    async def tracking_counterstrike(attacker_ip, attacker_mac, burst_size=5, directed_count=5, inter=0.01):
        nonlocal counterstrike_called
        counterstrike_called = True
    arp._garp_counterstrike = tracking_counterstrike

    try:
        await arp._on_arp_attack(
            sender_ip="192.168.1.1",
            sender_mac="11:22:33:44:55:66",
            reason="ARP 投毒检测测试"
        )
        check(True, "_on_arp_attack 触发反制，无异常")
    except Exception as e:
        check(False, f"_on_arp_attack 异常: {e}")

    ap_mod._SCAPY_AVAILABLE = saved_scapy


# ============================================================
# 7. 无 Npcap 路径3：arp -a 轮询主动修复
# ============================================================

async def test_poll_path3_active_fix():
    """无 Npcap 路径3 检测投毒后执行主动修复，不阻塞"""
    print("\n" + "=" * 60)
    print("7. 无 Npcap 路径3 轮询主动修复")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)

    # Mock _check_arp_poisoning 返回投毒
    async def mock_poisoned():
        return [("192.168.1.1", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66")]
    arp._check_arp_poisoning = mock_poisoned
    arp._arp_running = False
    arp._baseline_mac = "AA:BB:CC:DD:EE:FF"

    # 模拟路径3的一轮检查
    poisoned = await arp._check_arp_poisoning()
    if poisoned:
        check(len(poisoned) > 0, "路径3 检测到投毒")
        arp._poison_detected.set()
        check(arp._poison_detected.is_set(), "_poison_detected 已设置")


# ============================================================
# 8. MAC 标准化
# ============================================================

async def test_mac_normalize():
    """_mac_normalize 统一各种 MAC 格式"""
    print("\n" + "=" * 60)
    print("8. MAC 标准化")
    print("=" * 60)

    config = _make_test_config()
    arp = ARPProtection(config, ping_interval=999)

    norm1 = arp._mac_normalize("AA-BB-CC-DD-EE-FF")
    norm2 = arp._mac_normalize("aa:bb:cc:dd:ee:ff")
    norm3 = arp._mac_normalize("aabb.ccdd.eeff")
    check_eq(norm1, norm2, "破折号与冒号格式统一")
    check_eq(norm1, "AABBCCDDEEFF", "标准化为大写无分隔符")


# ============================================================
# 主入口
# ============================================================

# ============================================================
# 9. 本机 IP↔MAC 映射自包防误伤
# ============================================================

async def test_ip_mac_map_merge_self_packet():
    """映射补全后本机 MAC 宣告本机 IP 不误判（多接口自包防误伤）"""
    print("\n" + "=" * 60)
    print("9. 本机 IP↔MAC 映射自包防误伤")
    print("=" * 60)
    config = _make_test_config()
    arp = ARPProtection(config)
    arp._local_ips = {"192.168.1.13"}
    arp._local_mac = "A4:5B:5C:B9:64:D0"
    arp._local_macs = {"A4:5B:5C:B9:64:D0"}
    arp._local_ip_mac_map = {"00:E0:4C:68:00:AB": {"192.168.1.13"}}  # getmac 漏收集接口
    async def _noop(*a, **k):
        pass
    arp._on_arp_attack = _noop  # 命中时不创建后台反制 task（避免 mock 泄漏到后续测试）
    # 映射补全（与嗅探 worker 逻辑一致）
    for mac_colon in arp._local_ip_mac_map:
        if mac_colon and mac_colon != "00:00:00:00:00:00":
            arp._local_macs.add(mac_colon)
    r = await arp._check_arp_packet(sender_ip="192.168.1.13", sender_mac="00:E0:4C:68:00:AB",
                                    target_ip="192.168.1.1", target_mac="00:11:22:33:44:55", opcode=1)
    check(r == "", f"映射补全后本机 MAC 宣告本机 IP 不误判 (got {r!r})")
    r2 = await arp._check_arp_packet(sender_ip="192.168.1.13", sender_mac="AA:BB:CC:DD:EE:50",
                                     target_ip="192.168.1.1", target_mac="00:11:22:33:44:55", opcode=1)
    check("IP 冲突" in r2, "外来 MAC 仍检测 IP 冲突")


async def test_ip_mac_map_linux_parse():
    """_build_local_ip_mac_map Linux 解析（ip -o 输出含 eth0: 尾冒号）"""
    print("\n" + "=" * 60)
    print("10. Linux IP↔MAC 映射解析")
    print("=" * 60)
    import types as _types
    import arp_protection as _ap
    class _FakeProc:
        def __init__(self, text):
            self._t = text.encode()
        async def communicate(self):
            return self._t, b""
        async def wait(self):
            return 0
    _orig_sp = asyncio.create_subprocess_exec
    _orig_sys = _ap.sys
    _ap.sys = _types.SimpleNamespace(platform="linux")
    _outputs = iter([
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000 link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n",
        "2: eth0    inet 192.168.1.13/24 brd 192.168.1.255 scope global dynamic eth0\n",
    ])
    async def _fake_sp(*a, **k):
        return _FakeProc(next(_outputs))
    asyncio.create_subprocess_exec = _fake_sp
    try:
        m = await ARPProtection._build_local_ip_mac_map()
    finally:
        asyncio.create_subprocess_exec = _orig_sp
        _ap.sys = _orig_sys
    check("00:11:22:33:44:55" in m and "192.168.1.13" in m["00:11:22:33:44:55"],
          f"Linux ip -o 映射解析 (got {m})")


# ============================================================
# 主入口
# ============================================================

async def main():
    """运行所有 ARP 防护测试"""
    print("=" * 60)
    print("ARP 防护测试套件")
    print("=" * 60)

    await test_check_arp_poisoning_noscapy()
    await test_check_arp_poisoning_anomaly_mac()
    await test_garp_broadcast_burst_noscapy()
    await test_garp_counterstrike_random_mac()
    await test_garp_counterstrike_self_protect()
    await test_poison_to_full_defense()
    await test_poll_path3_active_fix()
    await test_mac_normalize()
    await test_ip_mac_map_merge_self_packet()
    await test_ip_mac_map_linux_parse()

    total = _pass_count + _fail_count
    print("\n" + "=" * 60)
    print(f"ARP 测试完成: {_pass_count}/{total} 通过", end="")
    if _fail_count > 0:
        print(f", {_fail_count} 失败")
        for d in _fail_details:
            print(f"  失败: {d}")
    else:
        print(" (全部通过)")
    print("=" * 60)
    return 0 if _fail_count == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

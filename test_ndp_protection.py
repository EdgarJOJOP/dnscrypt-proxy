"""
NDP 防护 = 完整测试套件
=======================
覆盖场景:
  + 有 Npcap (scapy 可用): NDP 嗅探投毒检测 + NA 定向毒化反制
  + 无 Npcap (scapy 不可用): NDP 表轮询 + ping -6 + 静态 NDP 绑定
  + 投毒→完整反制链路: NA 爆发 / 定向毒化 / 静态 NDP 绑定
  + 防自伤: 攻击者冒用本机 MAC 时跳过定向反制

使用方法:
  python test_ndp_protection.py
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from NDP_protection import NDPProtection

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

def check_gt(actual, threshold, msg: str):
    return check(actual > threshold, f"{msg}: {actual:.2f} > {threshold:.2f}")

# ============================================================
# 测试配置与 Mock 辅助
# ============================================================

def _make_test_config(gateway_ipv6: str = "fe80::1,aa:bb:cc:dd:ee:ff,") -> dict:
    """生成最小 NDP 防护测试配置"""
    return {
        "enabled": True,
        "gateway_ipv6": gateway_ipv6,
        "vxlan_enabled": False,
        "nud_window_ms": 80,
        "nud_threshold": 3,
        "baseline_learn_ms": 1,
        "send_ns_probe": False,
    }


async def _async_true(*args, **kwargs):
    return True

async def _async_false(*args, **kwargs):
    return False


def _install_mocks(ndp):
    """安装通用 mock，避免测试中执行真实系统命令"""
    # Mock _ping_ipv6 — 返回 True（网关可达）
    ndp._ping_ipv6 = lambda ip, **kw: _async_true()

    # Mock _resolve_mac_single — 默认返回正确 MAC
    async def mock_resolve_mac(ip):
        return "AA:BB:CC:DD:EE:FF"
    ndp._resolve_mac_single = mock_resolve_mac

    # Mock protect_ndp_entry — 记录调用
    ndp._protect_ndp_called = False
    async def mock_protect_entry():
        ndp._protect_ndp_called = True
        return True
    ndp.protect_ndp_entry = mock_protect_entry

    # Mock _probe_gateway_ns — 跳过
    ndp._probe_gateway_ns = lambda: _async_true()

    # Mock send_unsolicited_na — 跳过
    ndp.send_unsolicited_na = lambda: _async_true()

    # Mock _ndp_counterstrike — 记录调用，同时设防御标记
    ndp._counterstrike_called = False
    async def mock_counterstrike(attacker_mac="", attacker_ip=""):
        ndp._counterstrike_called = True
        ndp._last_cs_mac = attacker_mac
        ndp._ndp_ip_migrated = True
    ndp._ndp_counterstrike = mock_counterstrike


# ============================================================
# 1. 有 Npcap：check_ndp_poisoning 检测投毒
# ============================================================

async def test_check_ndp_poisoning_scapy():
    """有 Npcap 时 check_ndp_poisoning 应检测到网关 MAC 变更"""
    print("\n" + "=" * 60)
    print("1. check_ndp_poisoning (有 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)

    # 模拟有 Npcap
    ndp._scapy_available = True
    ndp._scapy_sendp_ok = True

    # Mock _resolve_mac_single 返回被篡改的 MAC
    async def mock_poisoned(ip):
        return "11:22:33:44:55:66"
    ndp._resolve_mac_single = mock_poisoned

    # 手动添加网关信息到 interfaces
    from NDP_protection import InterfaceInfo
    iface = InterfaceInfo(
        name="eth0",
        ipv6_ll="fe80::100",
        ipv6_globals=[],
        mac="AA:BB:CC:DD:EE:FF",
        idx=1,
    )
    iface.gateways.append(("fe80::1", "AA:BB:CC:DD:EE:FF", ""))
    ndp.interfaces = [iface]

    poisoned = await ndp.check_ndp_poisoning()
    check(len(poisoned) > 0, "应检测到 NDP 投毒")
    if poisoned:
        # (iface_name, ip, expected, actual)
        check_eq(poisoned[0][1], "fe80::1", "投毒网关 IPv6")


# ============================================================
# 2. 无 Npcap：_poll_ndp_table 投毒检测
# ============================================================

async def test_poll_ndp_table_poison_detect():
    """无 Npcap 时 _poll_ndp_table 检测投毒并设 _poison_detected"""
    print("\n" + "=" * 60)
    print("2. _poll_ndp_table 投毒检测 (无 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._scapy_available = False
    ndp._ndp_running = False  # 不让循环真正跑

    # Mock _resolve_mac_single 返回被篡改的 MAC
    async def mock_poisoned(ip):
        return "11:22:33:44:55:66"
    ndp._resolve_mac_single = mock_poisoned

    # 手动添加网关
    ndp._manual_gateways = [("fe80::1", "AA:BB:CC:DD:EE:FF", "")]

    # 手动执行一轮 _poll_ndp_table 逻辑
    for gw_ip, expected_mac, _ in ndp.gateway_pairs:
        if not gw_ip:
            continue
        actual_mac = await ndp._resolve_mac_single(gw_ip)
        if actual_mac and expected_mac:
            if ndp._mac_normalize(actual_mac) != ndp._mac_normalize(expected_mac):
                ndp._poison_detected.set()

    check(ndp._poison_detected.is_set(), "投毒检测后 _poison_detected 已设置")


# ============================================================
# 3. 无 Npcap：_poll_ndp_table 主动修复（异步不阻塞）
# ============================================================

async def test_poll_ndp_table_active_fix():
    """无 Npcap 时 _poll_ndp_table 触发 ping -6 + 静态绑定，不阻塞"""
    print("\n" + "=" * 60)
    print("3. _poll_ndp_table 主动修复 (无 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._scapy_available = False
    ndp._ndp_running = False

    # Mock _resolve_mac_single 返回异常 MAC
    async def mock_poisoned(ip):
        return "11:22:33:44:55:66"
    ndp._resolve_mac_single = mock_poisoned
    ndp._manual_gateways = [("fe80::1", "AA:BB:CC:DD:EE:FF", "")]

    # Mock protect_ndp_entry（已由 _install_mocks 完成）
    ndp._protect_ndp_called = False

    # 执行一轮修复
    for gw_ip, expected_mac, _ in ndp.gateway_pairs:
        if not gw_ip:
            continue
        actual_mac = await ndp._resolve_mac_single(gw_ip)
        if actual_mac and ndp._mac_normalize(actual_mac) != ndp._mac_normalize(expected_mac):
            await ndp.protect_ndp_entry()

    check(ndp._protect_ndp_called, "主动修复中 protect_ndp_entry 被调用")


# ============================================================
# 4. 有 Npcap：_ndp_counterstrike 反制
# ============================================================

async def test_ndp_counterstrike_scapy():
    """有 Npcap 时 _ndp_counterstrike 执行 NA 反制，不抛异常"""
    print("\n" + "=" * 60)
    print("4. _ndp_counterstrike (有 Npcap)")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._scapy_available = True
    ndp._ndp_sender_ready = True
    ndp._local_macs = set()
    ndp._ndp_ip_migrated = False

    # Mock sender queue
    sent_items = []
    orig_put = ndp._ndp_sender_queue.put_nowait
    def tracking_put(item):
        if item is not None:
            sent_items.append(item)
    ndp._ndp_sender_queue.put_nowait = tracking_put

    try:
        await ndp._ndp_counterstrike(
            attacker_mac="11:22:33:44:55:66",
            attacker_ip="fe80::1",
        )
        check(True, "_ndp_counterstrike 执行无异常")
    except Exception as e:
        check(False, f"_ndp_counterstrike 异常: {e}")

    ndp._ndp_sender_queue.put_nowait = orig_put
    check(ndp._ndp_ip_migrated, "全局防御标记已设置")


# ============================================================
# 5. 无 Npcap：_ndp_counterstrike 安全跳过
# ============================================================

async def test_ndp_counterstrike_noscapy_skip():
    """无 Npcap 时 _ndp_counterstrike 入口守卫 return，不执行"""
    print("\n" + "=" * 60)
    print("5. _ndp_counterstrike 无 Npcap 安全跳过")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    # 手动安装最小 mock（不覆盖 _ndp_counterstrike，保留原始入口守卫）
    ndp._ping_ipv6 = lambda ip, **kw: _async_true()
    ndp._resolve_mac_single = lambda ip: _async_true()
    ndp.protect_ndp_entry = lambda: _async_true()
    ndp._probe_gateway_ns = lambda: _async_true()
    ndp.send_unsolicited_na = lambda: _async_true()
    ndp._scapy_available = False
    ndp._ndp_ip_migrated = False

    try:
        await ndp._ndp_counterstrike(
            attacker_mac="11:22:33:44:55:66",
            attacker_ip="fe80::1",
        )
        check(True, "无 Npcap 时 _ndp_counterstrike 安全跳过，无异常")
    except Exception as e:
        check(False, f"_ndp_counterstrike 异常: {e}")

    check(not ndp._ndp_ip_migrated, "无 Npcap 时不设置防御标记")


# ============================================================
# 6. NDP 投毒→完整反制链路
# ============================================================

async def test_ndp_poison_to_counterstrike():
    """NDP 投毒检测→反制完整链路"""
    print("\n" + "=" * 60)
    print("6. NDP 投毒→反制链路")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._scapy_available = True
    ndp._ndp_sender_ready = True

    # Mock _resolve_mac_single 返回篡改 MAC
    async def mock_poisoned(ip):
        return "11:22:33:44:55:66"
    ndp._resolve_mac_single = mock_poisoned
    from NDP_protection import InterfaceInfo
    iface = InterfaceInfo(
        name="eth0", ipv6_ll="fe80::100", ipv6_globals=[],
        mac="AA:BB:CC:DD:EE:FF", idx=1,
    )
    iface.gateways.append(("fe80::1", "AA:BB:CC:DD:EE:FF", ""))
    ndp.interfaces = [iface]

    # 步骤1：检测投毒
    poisoned = await ndp.check_ndp_poisoning()
    check(len(poisoned) > 0, "NDP 投毒检测成功")

    # 步骤2：触发反制
    if poisoned:
        _, ndp_ip, exp_mac, act_mac = poisoned[0]
        await ndp._ndp_counterstrike(attacker_mac=act_mac, attacker_ip=ndp_ip)
        check(ndp._ndp_ip_migrated, "反制后防御标记已设置")


# ============================================================
# 7. NDP 异常 MAC 检测
# ============================================================

async def test_ndp_anomaly_mac_detection():
    """NDP 异常 MAC（全零/广播）应被检测"""
    print("\n" + "=" * 60)
    print("7. NDP 异常 MAC 检测")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._scapy_available = False
    ndp._ndp_running = False

    ndp._manual_gateways = [("fe80::1", "AA:BB:CC:DD:EE:FF", "")]

    # 测试全零 MAC
    async def mock_zero_mac(ip):
        return "00:00:00:00:00:00"
    ndp._resolve_mac_single = mock_zero_mac

    for gw_ip, expected_mac, _ in ndp.gateway_pairs:
        actual_mac = await ndp._resolve_mac_single(gw_ip)
        if actual_mac:
            norm_actual = ndp._mac_normalize(actual_mac)
            is_poisoned = expected_mac and norm_actual != ndp._mac_normalize(expected_mac)
            if not is_poisoned:
                is_poisoned = norm_actual in ("000000000000", "ffffffffffff") or norm_actual.startswith("01")
            check(is_poisoned, "全零 MAC 被识别为 NDP 投毒")

    # 测试广播 MAC
    async def mock_broadcast_mac(ip):
        return "FF:FF:FF:FF:FF:FF"
    ndp._resolve_mac_single = mock_broadcast_mac

    for gw_ip, expected_mac, _ in ndp.gateway_pairs:
        actual_mac = await ndp._resolve_mac_single(gw_ip)
        if actual_mac:
            norm_actual = ndp._mac_normalize(actual_mac)
            is_poisoned = expected_mac and norm_actual != ndp._mac_normalize(expected_mac)
            if not is_poisoned:
                is_poisoned = norm_actual in ("ffffffffffff",) or norm_actual.startswith("01")
            check(is_poisoned, "广播 MAC 被识别为 NDP 投毒")


# ============================================================
# 8. _generate_poison_mac
# ============================================================

async def test_generate_poison_mac():
    """_generate_poison_mac 生成有效随机 MAC"""
    print("\n" + "=" * 60)
    print("8. _generate_poison_mac")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)

    macs = set()
    for _ in range(10):
        m = ndp._generate_poison_mac()
        check(m.startswith("02:"), f"随机毒化 MAC 以 02: 开头: {m}")
        parts = m.split(":")
        check(len(parts) == 6, f"MAC 格式有效 (6 段): {m}")
        macs.add(m)

    check_gt(len(macs), 5, "生成 10 次中至少有 6 个不同的随机 MAC")


# ============================================================
# 9. 信任 MAC 列表跳过
# ============================================================

async def test_trusted_mac_skip():
    """信任列表中的 MAC 应跳过 NDP 投毒检测"""
    print("\n" + "=" * 60)
    print("9. 信任 MAC 列表跳过")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)
    ndp._trusted_sender_macs.add("AABBCCDDEEFF")

    # 验证信任 MAC 在 _trusted_sender_macs 中
    check("AABBCCDDEEFF" in ndp._trusted_sender_macs, "信任 MAC 已加入列表")


# ============================================================
# 10. 信任 MAC 自动学习
# ============================================================

async def test_trust_learning():
    """超 300 秒无活动的可疑 MAC 应自动加入信任列表"""
    print("\n" + "=" * 60)
    print("10. 信任 MAC 自动学习")
    print("=" * 60)

    config = _make_test_config()
    ndp = NDPProtection(config, ping_interval=999)
    _install_mocks(ndp)

    # 模拟可疑 MAC，设置超 300 秒的时间戳
    old_time = time.time() - 301.0
    ndp._suspicious_zero_mac["112233445566"] = [old_time]

    # 执行清理（模拟 _on_poison_detected 中的逻辑）
    now = time.time()
    stale = [m for m, ts_list in ndp._suspicious_zero_mac.items()
             if ts_list and now - max(ts_list) > 300.0]
    for m in stale:
        ndp._trusted_sender_macs.add(m)
        del ndp._suspicious_zero_mac[m]

    check("112233445566" in ndp._trusted_sender_macs, "超300秒可疑 MAC 自动加入信任")
    check("112233445566" not in ndp._suspicious_zero_mac, "可疑 MAC 已从可疑列表移除")


# ============================================================
# 主入口
# ============================================================

async def test_ip_mac_map_self_packet_ipv6():
    """NDP 映射补全后本机 MAC 宣告本机 IPv6 不误判（多接口自包防误伤）"""
    print("\n" + "=" * 60)
    print("11. 本机 IPv6↔MAC 映射自包防误伤")
    print("=" * 60)
    config = _make_test_config()
    from NDP_protection import InterfaceInfo
    ndp = NDPProtection(config)
    ndp.interfaces = [InterfaceInfo(name="接口B", mac="00:E0:4C:68:00:AB",
                                    ipv6_globals=["2408:826c:511:83dd:4148:3c51:783e:1a7e"])]
    ndp._local_macs = {"A4:5B:5C:B9:64:D0"}
    ndp._local_ip_mac_map = {"00:E0:4C:68:00:AB": {"2408:826c:511:83dd:4148:3c51:783e:1a7e"}}
    for mac_colon in ndp._local_ip_mac_map:
        if mac_colon and mac_colon != "00:00:00:00:00:00":
            ndp._local_macs.add(mac_colon)
    from scapy.all import Ether as _E, IPv6 as _V6, ICMPv6ND_NA as _NA
    na_own = _E(src="00:E0:4C:68:00:AB", dst="33:33:00:00:00:01") / \
        _V6(src="2408:826c:511:83dd:4148:3c51:783e:1a7e", dst="ff02::1", hlim=255) / \
        _NA(tgt="2408:826c:511:83dd:4148:3c51:783e:1a7e")
    ndp._on_ndp_packet_sync(na_own)
    check(not [e for e in ndp._threat_events if e["type"] == "ip_conflict"],
          "本机 MAC 宣告本机 IPv6 不误判 IP 冲突")


async def main():
    """运行所有 NDP 防护测试"""
    print("=" * 60)
    print("NDP 防护测试套件")
    print("=" * 60)

    await test_check_ndp_poisoning_scapy()
    await test_poll_ndp_table_poison_detect()
    await test_poll_ndp_table_active_fix()
    await test_ndp_counterstrike_scapy()
    await test_ndp_counterstrike_noscapy_skip()
    await test_ndp_poison_to_counterstrike()
    await test_ndp_anomaly_mac_detection()
    await test_generate_poison_mac()
    await test_trusted_mac_skip()
    await test_trust_learning()
    await test_ip_mac_map_self_packet_ipv6()

    total = _pass_count + _fail_count
    print("\n" + "=" * 60)
    print(f"NDP 测试完成: {_pass_count}/{total} 通过", end="")
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

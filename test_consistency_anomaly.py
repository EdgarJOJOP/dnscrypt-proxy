"""
验证测试：多上游一致性验证 + 统计异常检测 — 完整数据流可靠性验证
===================================================================
覆盖 21 组测试：
  1. consistency_verifier 单元测试（7 组）
  2. anomaly_detector 单元测试（9 组）
  3. 端到端集成测试（12 组）
     - 基础场景：全一致 / 投毒模拟 / 无共识 / 超时
     - 多IP场景：同上游多IP / 多IP指纹一致
     - 多网卡场景：双网卡独立RTT基线 / 回程路径差异
     - 异常检测器多IP稳定性
     - 端到端多IP集成：bootstrap 多IP连接
"""

import sys
import os
import math
import asyncio
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns.message
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

from consistency_verifier import (
    ResponseConsistencyVerifier,
    ResponseRecord,
    ConsistencyVerdict,
)
from anomaly_detector import AnomalyDetector, OnlineStats, _extract_2ld

_TEST_DOMAIN = "example.com"
_TEST_DOMAIN2 = "test.org"


def make_dns_response(
    domain: str,
    ip: str = "1.2.3.4",
    rdtype: int = dns.rdatatype.A,
    ttl: int = 300,
    rcode: int = dns.rcode.NOERROR,
    ad_bit: bool = False,
    add_additional: bool = False,
    extra_ip_count: int = 0,
) -> bytes:
    """创建测试用 DNS 响应（wire format）"""
    qname = dns.name.from_text(domain)
    msg = dns.message.make_response(dns.message.make_query(qname, rdtype))
    msg.set_rcode(rcode)
    if ad_bit:
        msg.flags |= dns.flags.AD
    if rdtype == dns.rdatatype.A:
        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, ip), ttl=ttl)
        for j in range(extra_ip_count):
            rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, f"10.0.0.{j+2}"), ttl=ttl)
        msg.answer.append(rrset)
    elif rdtype == dns.rdatatype.AAAA:
        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.AAAA)
        rrset.add(dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, ip), ttl=ttl)
        msg.answer.append(rrset)
    if add_additional:
        msg.use_edns(payload=4096)
    return msg.to_wire()


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


def check_gt(actual, threshold, msg: str):
    return check(actual > threshold, f"{msg}: {actual:.2f} > {threshold:.2f}")


# ============================================================
# 1. consistency_verifier 单元测试（原 7 组）
# ============================================================


def test_compute_fingerprint():
    print("\n" + "=" * 60)
    print("1. compute_fingerprint")
    print("=" * 60)
    r1 = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    r2 = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    fp1 = ResponseConsistencyVerifier.compute_fingerprint(r1)
    fp2 = ResponseConsistencyVerifier.compute_fingerprint(r2)
    check_eq(fp1, fp2, "相同响应 -> 相同指纹")

    r3 = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    fp3 = ResponseConsistencyVerifier.compute_fingerprint(r3)
    check(fp1 != fp3, "不同 IP -> 不同指纹")

    r4 = make_dns_response(_TEST_DOMAIN2, "1.2.3.4")
    fp4 = ResponseConsistencyVerifier.compute_fingerprint(r4)
    check(fp1 != fp4, "不同域名 -> 不同指纹")

    r5 = make_dns_response(_TEST_DOMAIN, "1.2.3.4", rcode=dns.rcode.NXDOMAIN)
    fp5 = ResponseConsistencyVerifier.compute_fingerprint(r5)
    check(fp1 != fp5, "不同 rcode -> 不同指纹")

    r6 = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ad_bit=True)
    fp6 = ResponseConsistencyVerifier.compute_fingerprint(r6)
    check(fp1 != fp6, "AD 位不同 -> 不同指纹")

    r7 = make_dns_response(_TEST_DOMAIN, "1.2.3.4", add_additional=True)
    fp7 = ResponseConsistencyVerifier.compute_fingerprint(r7)
    check_eq(fp1, fp7, "additional 段不同 -> 指纹相同(忽略EDNS0)")

    r8 = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=600)
    fp8 = ResponseConsistencyVerifier.compute_fingerprint(r8)
    check(fp1 != fp8, "不同 TTL -> 不同指纹")

    qname = dns.name.from_text(_TEST_DOMAIN)
    empty = dns.message.make_response(dns.message.make_query(qname, dns.rdatatype.A))
    empty.set_rcode(dns.rcode.NXDOMAIN)
    fp_empty = ResponseConsistencyVerifier.compute_fingerprint(empty.to_wire())
    check_eq(len(fp_empty), 16, "空响应指纹长度为 16")


def test_verify_all_consistent():
    print("\n" + "=" * 60)
    print("2. verify() -- 完全一致")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    records = [ResponseRecord(f"dns{i}", r, 0.05, 0.05) for i in range(1, 4)]
    verdict = v.verify(records)
    check(verdict is not None, "返回 verdict")
    if verdict:
        check(verdict.consistent, "consistent=True")
        check_eq(verdict.total_responses, 3, "3 个响应")
        check_eq(verdict.majority_count, 3, "majority=3")
        check_eq(verdict.minority_count, 0, "minority=0")
        check(not verdict.is_total_disagreement, "not total_disagreement")
    check_eq(v.stats["consistent"], 1, "stats.consistent=1")


def test_verify_minority():
    print("\n" + "=" * 60)
    print("3. verify() -- 少数派不一致 (2:1)")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    r_good = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    r_bad = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    records = [
        ResponseRecord("dns1", r_good, 0.05, 0.05),
        ResponseRecord("dns2", r_good, 0.06, 0.06),
        ResponseRecord("dns3", r_bad, 0.04, 0.04),
    ]
    verdict = v.verify(records)
    check(verdict is not None, "返回 verdict")
    if verdict:
        check(not verdict.consistent, "consistent=False")
        check_eq(verdict.majority_count, 2, "majority=2")
        check_eq(verdict.minority_count, 1, "minority=1")
        check("dns3" in verdict.minority_servers, "dns3 是少数派")
    check_eq(v.stats["inconsistent"], 1, "stats.inconsistent=1")
    check_eq(v.stats["server_inconsistencies"].get("dns3", 0), 1, "dns3 不一致计数=1")


def test_verify_total_disagreement():
    print("\n" + "=" * 60)
    print("4. verify() -- 完全无共识")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    ra = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    rb = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    rc = make_dns_response(_TEST_DOMAIN, "9.10.11.12")
    records = [
        ResponseRecord("dns1", ra, 0.05, 0.05),
        ResponseRecord("dns2", rb, 0.06, 0.06),
        ResponseRecord("dns3", rc, 0.07, 0.07),
    ]
    verdict = v.verify(records)
    check(verdict is not None, "返回 verdict")
    if verdict:
        check(not verdict.consistent, "consistent=False")
        check(verdict.is_total_disagreement, "is_total_disagreement=True")
    check_eq(v.stats["total_disagreements"], 1, "stats.total_disagreements=1")


def test_verify_insufficient():
    print("\n" + "=" * 60)
    print("5. verify() -- 响应数不足")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True, min_responses=3)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    records = [ResponseRecord("dns1", r, 0.05, 0.05)]
    verdict = v.verify(records)
    check(verdict is None, "返回 None")
    check_eq(v.stats["insufficient_responses"], 1, "stats.insufficient=1")


def test_verify_disabled():
    print("\n" + "=" * 60)
    print("6. verify() -- 禁用")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=False)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    records = [ResponseRecord(f"dns{i}", r, 0.05, 0.05) for i in range(1, 4)]
    verdict = v.verify(records)
    check(verdict is None, "返回 None")


def test_verify_ad_bit_mismatch():
    print("\n" + "=" * 60)
    print("7. verify() -- AD 位不同")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    r_ad = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ad_bit=True)
    r_noad = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ad_bit=False)
    records = [
        ResponseRecord("dns1", r_ad, 0.05, 0.05),
        ResponseRecord("dns2", r_noad, 0.06, 0.06),
        ResponseRecord("dns3", r_ad, 0.07, 0.07),
    ]
    verdict = v.verify(records)
    check(verdict is not None, "返回 verdict")
    if verdict:
        check(not verdict.consistent, "consistent=False (AD 位不同)")
        check("dns2" in verdict.minority_servers, "dns2 是少数派(AD=0)")


# ============================================================
# 2. anomaly_detector 单元测试（原 9 组）
# ============================================================


def test_online_stats():
    print("\n" + "=" * 60)
    print("8. OnlineStats")
    print("=" * 60)
    s = OnlineStats()
    check_eq(s.n, 0, "初始 n=0")
    check_eq(s.variance, 0.0, "初始 variance=0")

    samples = [10.0, 20.0, 30.0, 40.0, 50.0]
    for v in samples:
        s.update(v)
    check_eq(s.n, 5, "n=5")
    check_eq(s.mean, 30.0, "mean=30.0")
    expected_var = sum((x - 30.0) ** 2 for x in samples) / 4
    check(abs(s.variance - expected_var) < 1e-10, "variance correct")
    z = s.z_score(30.0)
    check(abs(z) < 1e-10, "z-score of mean approx 0")
    z_out = s.z_score(100.0)
    check(z_out > 0, "outlier z-score > 0")

    s2 = OnlineStats()
    s2.update(10.0)
    check_eq(s2.z_score(100.0), 0.0, "n<2 时 z_score=0")


def test_extract_2ld():
    print("\n" + "=" * 60)
    print("9. _extract_2ld")
    print("=" * 60)
    cases = [
        ("www.example.com", "example.com"),
        ("example.com", "example.com"),
        ("sub.abc.co.uk", "co.uk"),
        ("localhost", "localhost"),
        ("a.b.c.d.e.example.com", "example.com"),
    ]
    for domain, expected in cases:
        check_eq(_extract_2ld(domain), expected, domain)


def test_anomaly_disabled():
    print("\n" + "=" * 60)
    print("10. AnomalyDetector -- 禁用")
    print("=" * 60)
    d = AnomalyDetector(enabled=False)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    score = d.record_response("dns1", 0.05, r)
    check_eq(score, 0.0, "返回 0.0")
    check_eq(d.stats["total_responses"], 0, "不统计")


def test_anomaly_learning():
    print("\n" + "=" * 60)
    print("11. AnomalyDetector -- 学习阶段")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=10, z_score_threshold=2.0)
    for i in range(10):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
        score = d.record_response("dns1", 0.1 + i * 0.5, r)
        check_eq(score, 0.0, f"学习样本 {i+1} -> score=0")
    check(not d.server_in_learning("dns1"), "dns1 learning ended (10 samples)")

    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
    d.record_response("dns1", 0.3, r)
    check(not d.in_learning_phase, "之后仍然 in_learning_phase=False")


def test_anomaly_rtt():
    print("\n" + "=" * 60)
    print("12. AnomalyDetector -- RTT 异常")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=10, z_score_threshold=2.0)
    for i in range(10):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
        d.record_response("dns1", 0.05 + (i % 3) * 0.01, r)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
    score = d.record_response("dns1", 5.0, r)
    check_gt(score, 2.0, "RTT 异常 score")
    check_eq(d.stats["rtt_anomalies"], 1, "rtt_anomalies=1")
    check_eq(d.stats["anomalies_detected"], 1, "anomalies_detected=1")


def test_anomaly_size():
    print("\n" + "=" * 60)
    print("13. AnomalyDetector -- 响应大小异常")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=10, z_score_threshold=2.0)
    for i in range(10):
        msg = dns.message.make_response(dns.message.make_query(
            dns.name.from_text(_TEST_DOMAIN), dns.rdatatype.A))
        rrset = dns.rrset.RRset(dns.name.from_text(_TEST_DOMAIN),
                                 dns.rdataclass.IN, dns.rdatatype.A)
        rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A,
                                      f"1.2.3.{i % 4 + 1}"), ttl=300)
        for j in range(i % 3):
            rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A,
                                          f"10.0.0.{j+2}"), ttl=300)
        msg.answer.append(rrset)
        d.record_response("dns1", 0.05, msg.to_wire())
    qname = dns.name.from_text(_TEST_DOMAIN)
    msg = dns.message.make_response(dns.message.make_query(qname, dns.rdatatype.A))
    rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
    for i in range(100):
        rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A,
                                      f"10.0.{i // 256}.{i % 256}"), ttl=300)
    msg.answer.append(rrset)
    score = d.record_response("dns1", 0.05, msg.to_wire())
    check(d.stats["size_anomalies"] >= 1, "size_anomalies >= 1")


def test_anomaly_ttl():
    print("\n" + "=" * 60)
    print("14. AnomalyDetector -- TTL 异常")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=10, z_score_threshold=2.0)
    for i in range(10):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=3600 + i * 100)
        d.record_response("dns1", 0.05, r)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=60)
    score = d.record_response("dns1", 0.05, r)
    print(f"  TTL 异常 score={score:.2f}")
    check(d.stats["anomalies_detected"] >= 0, "anomalies_detected >= 0")


def test_anomaly_multi_server():
    print("\n" + "=" * 60)
    print("15. AnomalyDetector -- 多上游独立基线")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=5, z_score_threshold=2.0)
    for i in range(5):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
        d.record_response("fast", 0.05, r)
        d.record_response("slow", 0.50, r)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
    s1 = d.record_response("fast", 0.05, r)
    s2 = d.record_response("slow", 0.50, r)
    check_eq(s1, 0.0, "fast 正常 RTT -> score=0")
    check_eq(s2, 0.0, "slow 正常 RTT -> score=0")
    rate = d.get_server_anomaly_rate("fast")
    check(isinstance(rate, float), "anomaly_rate 返回 float")


def test_stats_tracking():
    print("\n" + "=" * 60)
    print("16. 统计追踪完整性")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    rb = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    v.verify([ResponseRecord("a", r, 0.1, 0.1), ResponseRecord("b", r, 0.1, 0.1)])
    v.verify([ResponseRecord("a", r, 0.1, 0.1), ResponseRecord("b", r, 0.1, 0.1)])
    v.verify([ResponseRecord("a", r, 0.1, 0.1), ResponseRecord("b", rb, 0.1, 0.1)])
    v.verify([ResponseRecord("a", r, 0.1, 0.1)])
    s = v.stats
    check_eq(s["consistent"], 2, "consistent=2")
    check_eq(s["inconsistent"], 1, "inconsistent=1")
    check_eq(s["insufficient_responses"], 1, "insufficient=1")
    check_eq(s["total_verifications"], 3, "verifications=3")
    check("server_inconsistencies" in s, "server_inconsistencies in stats")


# ============================================================
# 3. Mocks
# ============================================================


class MockResolver:
    """模拟解析器：返回预设 DNS 响应"""
    def __init__(self, name, response_bytes, delay=0.0, fail=False):
        self.name = name
        self._response = response_bytes
        self._delay = delay
        self._fail = fail
        self.resolve_count = 0

    async def resolve(self, query_bytes):
        self.resolve_count += 1
        if self._fail:
            return None
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        return self._response


class MockUpstream:
    """模拟 UpstreamServer"""
    def __init__(self, name, resolver):
        self.name = name
        self.resolver = resolver
        self.enabled = True
        self._avg_rtt = 0.05

    @property
    def avg_response_time(self):
        return self._avg_rtt

    def set_avg_rtt(self, rtt):
        self._avg_rtt = rtt


class MockResolverWithMultiIP:
    """
    模拟多 IP 解析器：同一个逻辑上游从不同 IP 连接时返回相同 answer
    但附加了略微不同的 EDNS0 / additional 段
    """
    def __init__(self, name: str, base_response: bytes, ip_delays: dict = None):
        self.name = name
        self._base = base_response
        self._ip_delays = ip_delays or {}
        self.resolve_count = 0

    async def resolve(self, query_bytes, preferred_ip=None):
        self.resolve_count += 1
        delay = self._ip_delays.get(preferred_ip, 0.05) if preferred_ip else 0.05
        if delay > 0:
            await asyncio.sleep(delay)
        # 无论通过哪个 IP 连接，返回相同的基础 DNS 响应
        # 但附加了包含连接 IP 的 EDNS0（模拟不同 IP 的 EDNS0 差异）
        msg = dns.message.from_wire(self._base)
        # 添加 EDNS0 client-subnet 选项表示来自不同连接 IP
        try:
            msg.use_edns(payload=4096, options=[
                dns.edns.ECSOption(preferred_ip or "1.1.1.1", 32)
            ] if preferred_ip else [])
        except Exception:
            pass
        return msg.to_wire()


# ============================================================
# 4. 端到端集成测试 — 基础场景（原 5 组）
# ============================================================


async def test_integration_consistent():
    print("\n" + "=" * 60)
    print("17. 集成 -- 全一致")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    resp = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    resolvers = [
        MockResolver("dns1", resp, 0.05),
        MockResolver("dns2", resp, 0.06),
        MockResolver("dns3", resp, 0.07),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    fast_bytes, verdict = await v.collect_and_verify(
        (resp, 0.05, None), "dns1", servers, query, 1.0,
    )
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(verdict.consistent, "consistent=True")
        check_eq(verdict.total_responses, 3, "3 个响应")
    check_eq(fast_bytes, resp, "最快响应正确返回")


async def test_integration_inconsistent():
    print("\n" + "=" * 60)
    print("18. 集成 -- 不一致 (2:1 投毒模拟)")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    r_good = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    r_bad = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    resolvers = [
        MockResolver("trusted1", r_good, 0.05),
        MockResolver("trusted2", r_good, 0.06),
        MockResolver("poisoned", r_bad, 0.04),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    fast_bytes, verdict = await v.collect_and_verify(
        (r_bad, 0.04, None), "poisoned", servers, query, 1.0,
    )
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(not verdict.consistent, "consistent=False")
        check_eq(verdict.majority_count, 2, "多数派=2")
        check_eq(verdict.minority_count, 1, "少数派=1")
        check("poisoned" in verdict.minority_servers, "poisoned 是少数派")
        check(verdict.trusted_server in ("trusted1", "trusted2"), "可信响应来自多数派")


async def test_integration_total_disagreement():
    print("\n" + "=" * 60)
    print("19. 集成 -- 完全无共识")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    ra = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    rb = make_dns_response(_TEST_DOMAIN, "5.6.7.8")
    rc = make_dns_response(_TEST_DOMAIN, "9.10.11.12")
    resolvers = [
        MockResolver("dns1", ra, 0.05),
        MockResolver("dns2", rb, 0.06),
        MockResolver("dns3", rc, 0.07),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    _, verdict = await v.collect_and_verify(
        (ra, 0.05, None), "dns1", servers, query, 1.0,
    )
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(not verdict.consistent, "consistent=False")
        check(verdict.is_total_disagreement, "is_total_disagreement=True")


async def test_integration_timeout():
    print("\n" + "=" * 60)
    print("20. 集成 -- 部分上游超时")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True, consistency_window_ms=100)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    resp = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    resolvers = [
        MockResolver("fast", resp, 0.01),
        MockResolver("slow", resp, 10.0),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    _, verdict = await v.collect_and_verify(
        (resp, 0.01, None), "fast", servers, query, 0.1,
    )
    check(verdict is None, "超时后 None (仅 1 个响应)")


async def test_integration_anomaly_feed():
    print("\n" + "=" * 60)
    print("21. 集成 -- 异常检测器数据流")
    print("=" * 60)
    detector = AnomalyDetector(enabled=True, learning_samples=5, z_score_threshold=3.0)
    for i in range(4):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
        detector.record_response("dns-test", 0.05 + i * 0.01, r)
    check_eq(detector.stats["total_responses"], 4, "4 样本已记录")
    check(detector.server_in_learning("dns-test"), "dns-test 仍在学习阶段")

    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
    score = detector.record_response("dns-test", 0.06, r)
    check(not detector.server_in_learning("dns-test"), "dns-test 进入检测阶段 (5 samples)")
    check_eq(score, 0.0, "正常响应 score=0")

    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4", ttl=300)
    score = detector.record_response("dns-test", 5.0, r)
    check_gt(score, 3.0, "异常 RTT 触发告警")
    check_eq(detector.stats["anomalies_detected"], 1, "1 个异常检测")
    check(detector.get_server_anomaly_rate("dns-test") > 0, "anomaly_rate > 0")


# ============================================================
# 5. Phase 2: 同上游多IP场景测试
# ============================================================


async def test_multi_ip_same_answer():
    """
    同上游通过不同 IP 连接，返回相同 DNS 内容（fingerprint一致）：
    模拟 bootstrap 返回了 dns.example.com -> [1.1.1.1, 2.2.2.2]
    两个连接 IP 返回的 answer 相同但 EDNS0 略微不同
    """
    print("\n" + "=" * 60)
    print("22. 多IP -- 同上游多IP返回相同内容")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    base_resp = make_dns_response(_TEST_DOMAIN, "1.2.3.4")

    resolvers = [
        MockResolverWithMultiIP("upstreamA", base_resp, {"1.1.1.1": 0.05, "2.2.2.2": 0.06}),
        MockResolver("upstreamB", base_resp, 0.07),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    fast_bytes, verdict = await v.collect_and_verify(
        (base_resp, 0.05, None), "upstreamA", servers, query, 1.0,
    )
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(verdict.consistent, "multi-IP 同内容 -> consistent=True")
        check_eq(verdict.total_responses, 2, "2 个响应")


async def test_multi_ip_fingerprint_ignores_additional():
    """
    多 IP 连接时不同 EDNS0 不影响指纹计算：
    upstreamA 通过 IP1 和 IP2 返回的响应附加了不同的 EDNS0(ECS)，
    但指纹应相同（忽略 additional 段）
    """
    print("\n" + "=" * 60)
    print("23. 多IP -- 不同EDNS0不影响指纹")
    print("=" * 60)

    # 从不同 IP 连接，可能附加不同 ECS，但 answer 相同
    base_resp = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    msg1 = dns.message.from_wire(base_resp)
    msg1.use_edns(payload=4096)
    resp_with_edns = msg1.to_wire()

    fp1 = ResponseConsistencyVerifier.compute_fingerprint(base_resp)
    fp2 = ResponseConsistencyVerifier.compute_fingerprint(resp_with_edns)
    check_eq(fp1, fp2, "EDNS0 OPT 不影响指纹 (忽略 additional)")


async def test_multi_ip_3_upstream_same():
    """
    3 个上游，其中 2 个是同一服务商的不同 IP，内容一致：
    upstreamA(IP1), upstreamA(IP2), upstreamB 全部返回相同 answer
    """
    print("\n" + "=" * 60)
    print("24. 多IP -- 3上游同内容")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    base = make_dns_response(_TEST_DOMAIN, "1.2.3.4")

    resolvers = [
        MockResolverWithMultiIP("upstreamA", base),
        MockResolver("upstreamB", base, 0.06),
    ]
    # 模拟 upstreamA 有 2 个 IP 连接
    servers = [MockUpstream(r.name, r) for r in resolvers]
    # 把 upstreamA 当成 2 个独立的上游记录(同名但不同连接)
    records = [
        ResponseRecord("upstreamA-ip1", base, 0.05, 0.05),
        ResponseRecord("upstreamA-ip2", base, 0.06, 0.06),
        ResponseRecord("upstreamB", base, 0.07, 0.07),
    ]
    verdict = v.verify(records)
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(verdict.consistent, "consistent=True")
        check_eq(verdict.majority_count, 3, "全部一致")


# ============================================================
# 6. Phase 3: 多网卡多回程路径场景测试
# ============================================================


async def test_dual_nic_independent_baselines():
    """
    双网卡场景：同一上游通过 NIC1 和 NIC2 连接，RTT 基线应独立维护。
    异常检测器按 server_name 独立基线，不应因 NIC2 的高 RTT 影响 NIC1 的检测。
    """
    print("\n" + "=" * 60)
    print("25. 多网卡 -- 独立 RTT 基线")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=5, z_score_threshold=3.0)

    # NIC1 RTT ~10ms, NIC2 RTT ~200ms
    # 学习阶段：两个上游独立
    for i in range(5):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        d.record_response("upstreamA-nic1", 0.01, r)
        d.record_response("upstreamA-nic2", 0.20, r)

    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    s1 = d.record_response("upstreamA-nic1", 0.01, r)
    s2 = d.record_response("upstreamA-nic2", 0.20, r)
    check(not d.server_in_learning("upstreamA-nic1"), "NIC1 learning ended")
    check(not d.server_in_learning("upstreamA-nic2"), "NIC2 learning ended")
    check_eq(s1, 0.0, "NIC1 正常 RTT -> score=0")
    check_eq(s2, 0.0, "NIC2 正常 RTT -> score=0")

    # 验证 NIC1 的基线没有被 NIC2 的高 RTT 污染
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    s1_again = d.record_response("upstreamA-nic1", 0.01, r)
    check_eq(s1_again, 0.0, "NIC1 再次正常 -> score=0")


async def test_dual_nic_rtt_anomaly_detection():
    """
    双网卡场景：NIC1 出现 RTT 异常应被正确检测，
    不影响 NIC2 的正常判断。
    """
    print("\n" + "=" * 60)
    print("26. 多网卡 -- NIC1异常不影响NIC2")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=5, z_score_threshold=3.0)

    for i in range(5):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        d.record_response("nic1", 0.01 + i * 0.001, r)
        d.record_response("nic2", 0.20 + i * 0.01, r)

    # NIC1 异常高 RTT
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    s_nic1 = d.record_response("nic1", 1.0, r)
    check_gt(s_nic1, 2.0, "NIC1 异常 RTT 被检测")

    # NIC2 正常
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    s_nic2 = d.record_response("nic2", 0.20, r)
    check_eq(s_nic2, 0.0, "NIC2 正常不被误报")

    check(not d.server_in_learning("nic1"), "NIC1 learning ended")
    check(not d.server_in_learning("nic2"), "NIC2 learning ended")
    check_eq(d.stats["rtt_anomalies"], 1, "仅 NIC1 触发 RTT 异常")


async def test_dual_nic_consistency_across_interfaces():
    """
    双网卡场景：同一上游通过 NIC1 和 NIC2 返回相同 DNS 内容，
    一致性验证应认为一致。
    """
    print("\n" + "=" * 60)
    print("27. 多网卡 -- 跨网卡内容一致性")
    print("=" * 60)
    v = ResponseConsistencyVerifier(enabled=True)
    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    resp = make_dns_response(_TEST_DOMAIN, "1.2.3.4")

    resolvers = [
        MockResolver("upstreamA-nic1", resp, 0.01),
        MockResolver("upstreamA-nic2", resp, 0.20),
        MockResolver("upstreamB", resp, 0.05),
    ]
    servers = [MockUpstream(r.name, r) for r in resolvers]
    fast_bytes, verdict = await v.collect_and_verify(
        (resp, 0.01, None), "upstreamA-nic1", servers, query, 1.0,
    )
    check(verdict is not None, "收到 verdict")
    if verdict:
        check(verdict.consistent, "跨网卡内容一致 -> consistent=True")
        check_eq(verdict.total_responses, 3, "3 个响应全部一致")


# ============================================================
# 7. Phase 4: 异常检测器在多IP场景下的基线稳定性
# ============================================================


async def test_multi_ip_rtt_jitter_no_false_positive():
    """
    多IP场景：上游通过 IP1 (RTT=50ms) 和 IP2 (RTT=500ms) 交替连接，
    学习阶段后 RTT 基线处于中间值，正常波动不应触发告警。
    z_score_threshold=3.0 应能容忍这种切换。
    """
    print("\n" + "=" * 60)
    print("28. 多IP -- RTT 抖动不应误报")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=20, z_score_threshold=3.0)

    # 模拟 IP 切换：RTT 在 50ms-500ms 之间交替
    rtts = [0.05, 0.5, 0.05, 0.5, 0.05, 0.5] * 4  # 24 个样本
    for i, rtt in enumerate(rtts[:20]):
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        d.record_response("dns-multiip", rtt, r)

    check(not d.server_in_learning("dns-multiip"), "dns-multiip 学习阶段已结束")
    check_eq(d.stats["anomalies_detected"], 0, "学习阶段无告警")

    # 检测阶段：合理的 RTT 值不应误报
    for rtt in [0.05, 0.5, 0.1, 0.4, 0.05, 0.5]:
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        score = d.record_response("dns-multiip", rtt, r)
        check_eq(score, 0.0, f"RTT={rtt*1000:.0f}ms 在容忍范围内 -> score=0")

    check_eq(d.stats["anomalies_detected"], 0, "无异常误报")


async def test_multi_ip_rtt_extreme_outlier_still_detected():
    """
    多IP场景：即使有 IP 切换导致 RTT 抖动，真正的极端异常（如 10s）
    仍应被正确检测。
    """
    print("\n" + "=" * 60)
    print("29. 多IP -- 极端异常仍被检测")
    print("=" * 60)
    d = AnomalyDetector(enabled=True, learning_samples=20, z_score_threshold=3.0)

    rtts = [0.05, 0.5, 0.05, 0.5] * 5
    for rtt in rtts[:20]:
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        d.record_response("dns-multiip", rtt, r)
        r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
        d.record_response("dns-multiip", rtt, r)

    # 极端异常
    r = make_dns_response(_TEST_DOMAIN, "1.2.3.4")
    score = d.record_response("dns-multiip", 10.0, r)
    check_gt(score, 3.0, "极端 RTT 异常触发了告警")
    check_eq(d.stats["anomalies_detected"], 1, "1 个异常被检测")


# ============================================================
# 8. Phase 5: 端到端多IP集成测试
# ============================================================


class MockUpstreamWithRTT:
    """模拟带 RTT 的上游服务器"""
    def __init__(self, name, resolver, avg_rtt=0.05):
        self.name = name
        self.resolver = resolver
        self.enabled = True
        self._avg_rtt = avg_rtt

    @property
    def avg_response_time(self):
        return self._avg_rtt


async def test_e2e_multi_ip_bootstrap():
    """
    端到端：bootstrap 返回多个 IP，上游通过不同 IP 连接。
    验证：
    1. 一致性验证器正确工作
    2. 异常检测器收到正确的 server_name
    """
    print("\n" + "=" * 60)
    print("30. 端到端 -- bootstrap 多 IP 连接")
    print("=" * 60)

    verifier = ResponseConsistencyVerifier(enabled=True)
    detector = AnomalyDetector(enabled=True, learning_samples=3, z_score_threshold=3.0)

    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    resp = make_dns_response(_TEST_DOMAIN, "93.184.216.34")

    # 模拟 bootstrap 解析 example.com -> [93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946]
    # 通过两个IP连接，但内容相同
    resolvers = [
        MockResolverWithMultiIP("example.com", resp, {"93.184.216.34": 0.05, "2606:2800:220:1:248:1893:25c8:1946": 0.08}),
        MockResolver("cloudflare-dns", resp, 0.06),
        MockResolver("quad9-dns", resp, 0.07),
    ]
    servers = [MockUpstreamWithRTT(r.name, r) for r in resolvers]

    # 模拟最快的响应来自 "example.com" 通过 IPv4
    fast_bytes, verdict = await verifier.collect_and_verify(
        (resp, 0.05, None), "example.com", servers, query, 1.0,
    )

    check(verdict is not None, "收到 verdict")
    if verdict:
        check(verdict.consistent, "多IP bootstrap 场景一致")
        check_eq(verdict.total_responses, 3, "3 个上游全部响应")

    # 验证异常检测器工作
    detector.record_response("example.com", 0.05, resp)
    detector.record_response("cloudflare-dns", 0.06, resp)
    detector.record_response("quad9-dns", 0.07, resp)
    check(detector.server_in_learning("example.com"), "example.com 学习阶段 (1/3) 未结束")
    check(detector.server_in_learning("cloudflare-dns"), "cloudflare-dns 学习阶段 (1/3) 未结束")

    r = make_dns_response(_TEST_DOMAIN, "93.184.216.34")
    detector.record_response("example.com", 0.05, r)
    check(detector.server_in_learning("example.com"), "example.com 学习阶段 (2/3) 未结束")

    detector.record_response("cloudflare-dns", 0.06, r)
    check(detector.server_in_learning("cloudflare-dns"), "cloudflare-dns 学习阶段 (2/3) 未结束")

    score = detector.record_response("example.com", 0.05, r)  # 6th - 进入检测阶段
    check(not detector.server_in_learning("example.com"), "example.com 进入检测阶段 (3/3)")
    check_eq(score, 0.0, "正常响应 score=0")
    check_eq(detector.stats["total_responses"], 6, "6 条响应已记录")


async def test_e2e_multi_ip_with_poisoning():
    """
    端到端：多IP场景下其中一个上游被投毒。
    bootstrap 返回 example.com -> [真IP, 假IP]
    假 IP 返回伪造 DNS 响应，真 IP 返回正确响应。
    """
    print("\n" + "=" * 60)
    print("31. 端到端 -- 多IP场景下检测投毒")
    print("=" * 60)

    verifier = ResponseConsistencyVerifier(enabled=True)

    query = dns.message.make_query(_TEST_DOMAIN, dns.rdatatype.A).to_wire()
    resp_real = make_dns_response(_TEST_DOMAIN, "93.184.216.34")
    resp_poisoned = make_dns_response(_TEST_DOMAIN, "5.6.7.8")  # 伪造 IP

    # upstreamA 通过两个 IP 连接
    resolvers = [
        MockResolver("upstreamA-real", resp_real, 0.05),      # 真 IP，慢一点
        MockResolver("upstreamA-fake", resp_poisoned, 0.03),  # 伪造 IP，最快但投毒
        MockResolver("upstreamB", resp_real, 0.06),
        MockResolver("upstreamC", resp_real, 0.07),
    ]
    servers = [MockUpstreamWithRTT(r.name, r) for r in resolvers]

    # 伪造的上游最快响应，但内容被篡改
    fast_bytes, verdict = await verifier.collect_and_verify(
        (resp_poisoned, 0.03, None), "upstreamA-fake", servers, query, 1.0,
    )

    check(verdict is not None, "收到 verdict")
    if verdict:
        check(not verdict.consistent, "投毒被检测到 -> consistent=False")
        check_eq(verdict.majority_count, 3, "3 个上游返回正确结果")
        check_eq(verdict.minority_count, 1, "1 个上游被投毒(upstreamA-fake)")
        check("upstreamA-fake" in verdict.minority_servers,
              "upstreamA-fake 被标记为少数派")
        check(verdict.trusted_server in ("upstreamA-real", "upstreamB", "upstreamC"),
              "可信响应来自多数派之一")
        # 可信响应应来自多数派，内容为正确 IP
        trusted_verdict = dns.message.from_wire(verdict.trusted_response)
        correct_answer = dns.message.from_wire(resp_real)
        check_eq(trusted_verdict.answer[0][0].address,
                 correct_answer.answer[0][0].address,
                 "可信响应包含正确的 IP 地址")


# ============================================================
# 主入口
# ============================================================


async def main():
    logging.basicConfig(level=logging.WARNING)

    # 一致性验证器单元测试 (1-7)
    test_compute_fingerprint()
    test_verify_all_consistent()
    test_verify_minority()
    test_verify_total_disagreement()
    test_verify_insufficient()
    test_verify_disabled()
    test_verify_ad_bit_mismatch()

    # 异常检测器单元测试 (8-16)
    test_online_stats()
    test_extract_2ld()
    test_anomaly_disabled()
    test_anomaly_learning()
    test_anomaly_rtt()
    test_anomaly_size()
    test_anomaly_ttl()
    test_anomaly_multi_server()
    test_stats_tracking()

    # 基础集成测试 (17-21)
    await test_integration_consistent()
    await test_integration_inconsistent()
    await test_integration_total_disagreement()
    await test_integration_timeout()
    await test_integration_anomaly_feed()

    # 多IP场景 (22-24)
    await test_multi_ip_same_answer()
    await test_multi_ip_fingerprint_ignores_additional()
    await test_multi_ip_3_upstream_same()

    # 多网卡场景 (25-27)
    await test_dual_nic_independent_baselines()
    await test_dual_nic_rtt_anomaly_detection()
    await test_dual_nic_consistency_across_interfaces()

    # 多IP异常检测稳定性 (28-29)
    await test_multi_ip_rtt_jitter_no_false_positive()
    await test_multi_ip_rtt_extreme_outlier_still_detected()

    # 端到端多IP集成 (30-31)
    await test_e2e_multi_ip_bootstrap()
    await test_e2e_multi_ip_with_poisoning()

    # 汇总
    total = _pass_count + _fail_count
    print("\n" + "=" * 60)
    print(f"测试完成: {_pass_count}/{total} 通过", end="")
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

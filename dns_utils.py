"""
DNS 响应工具函数
- AAAA (IPv6) 优先于 A (IPv4) 排序
- 安全实现：只交换连续 A/AAAA 段内的顺序，不移动 CNAME/SOA/NS 等非地址记录
"""

import dns.message
import dns.rdatatype


def reorder_answer_aaaa_first(msg):
    """
    将 DNS 响应消息的 Answer section 中 AAAA (IPv6) 记录排在 A (IPv4) 前面。

    安全策略：只交换连续 A/AAAA 段内的顺序，
    CNAME、SOA、NS 等非地址记录保持原位不变。
    原地修改 msg.answer 列表。
    """
    if not msg.answer or len(msg.answer) < 2:
        return

    # 找到第一个和最后一个 A/AAAA 记录的位置
    first_aa = -1
    last_aa = -1
    for i, rrset in enumerate(msg.answer):
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if first_aa == -1:
                first_aa = i
            last_aa = i

    # 如果没有 A 和 AAAA，或只有一个 A/AAAA，无需排序
    if first_aa < 0 or first_aa == last_aa:
        return

    # 检查范围内是否同时有 AAAA 和 A
    has_aaaa = any(
        rrset.rdtype == dns.rdatatype.AAAA
        for rrset in msg.answer[first_aa:last_aa + 1]
    )
    has_a = any(
        rrset.rdtype == dns.rdatatype.A
        for rrset in msg.answer[first_aa:last_aa + 1]
    )
    if not has_aaaa or not has_a:
        return

    # 范围内 AAAA 在前，A 在后
    aaaa_in_range = [
        rrset for rrset in msg.answer[first_aa:last_aa + 1]
        if rrset.rdtype == dns.rdatatype.AAAA
    ]
    a_in_range = [
        rrset for rrset in msg.answer[first_aa:last_aa + 1]
        if rrset.rdtype == dns.rdatatype.A
    ]

    # 构建新 answer：范围外的保持原位，范围内 AAAA 在前
    new_answer = (
        list(msg.answer[:first_aa])
        + aaaa_in_range
        + a_in_range
        + list(msg.answer[last_aa + 1:])
    )

    if msg.answer != new_answer:
        msg.answer.clear()
        msg.answer.extend(new_answer)


def sort_dns_response_wire(wire_bytes):
    """
    对 DNS 响应 wire bytes 进行 AAAA 优先排序。
    使用安全策略：只交换连续 A/AAAA 段内的顺序。
    失败时返回原始 bytes（不中断服务）。
    """
    if not wire_bytes:
        return wire_bytes
    try:
        msg = dns.message.from_wire(wire_bytes)
        reorder_answer_aaaa_first(msg)
        return msg.to_wire()
    except Exception:
        return wire_bytes

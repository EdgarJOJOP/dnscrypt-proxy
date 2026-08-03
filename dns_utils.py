"""
DNS 响应工具函数
- AAAA (IPv6) 优先于 A (IPv4) 排序
"""

import dns.message
import dns.rdatatype


def reorder_answer_aaaa_first(msg):
    """
    将 DNS 响应消息的 Answer section 重新排序，
    AAAA (IPv6) 记录排在 A (IPv4) 记录前面，
    其他类型（CNAME、MX 等）记录保持在末尾。
    原地修改 msg.answer 列表。
    """
    if not msg.answer or len(msg.answer) < 2:
        return

    aaaa_sets = []
    a_sets = []
    other_sets = []

    for rrset in msg.answer:
        rdtype = rrset.rdtype
        if rdtype == dns.rdatatype.AAAA:
            aaaa_sets.append(rrset)
        elif rdtype == dns.rdatatype.A:
            a_sets.append(rrset)
        else:
            other_sets.append(rrset)

    if not aaaa_sets and not a_sets:
        return

    new_order = aaaa_sets + a_sets + other_sets

    if msg.answer != new_order:
        msg.answer.clear()
        msg.answer.extend(new_order)


def sort_dns_response_wire(wire_bytes):
    """
    对 DNS 响应 wire bytes 进行 AAAA 优先排序。
    解析 → 排序 → 重新序列化。
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

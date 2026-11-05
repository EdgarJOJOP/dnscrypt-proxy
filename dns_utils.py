"""
DNS 响应工具函数
- AAAA (IPv6) 优先于 A (IPv4) 排序
- 安全实现：只交换连续 A/AAAA 段内的顺序，不移动 CNAME/SOA/NS 等非地址记录
- 本机 IPv6 可用性探测（决定上游/权威是否优先用 IPv6）
"""

import ipaddress
import socket
from typing import Optional

import dns.message
import dns.rdatatype
import dns.flags
import dns.rcode
import dns.rrset

# 本机是否存在全局 IPv6 地址（进程内缓存；网络变化后可 reset_ipv6_probe()）
_HAS_GLOBAL_IPV6: Optional[bool] = None


def has_global_ipv6() -> bool:
    """本机是否存在**全局** IPv6 地址（能出公网），结果进程内缓存

    为什么不用 UDP connect 探测路由：Windows 上「有 IPv6 默认路由但实际不通」
    （运营商未下发前缀 / 防火墙丢弃 v6）非常常见，UDP connect 不会失败，
    于是「IPv6 优先」会退化成「每次先白等一个超时」。这里直接检查接口地址：
    只有存在全局单播地址（非回环 / 非链路本地 / 非 ULA / 非文档地址）才认为
    可用 IPv6；否则调用方应只用 IPv4。
    """
    global _HAS_GLOBAL_IPV6
    if _HAS_GLOBAL_IPV6 is not None:
        return _HAS_GLOBAL_IPV6
    ok = False
    try:
        try:
            import psutil
            ifaces = psutil.net_if_addrs()
        except Exception:
            ifaces = {}
        for _name, addrs in ifaces.items():
            for addr in addrs:
                if addr.family != socket.AF_INET6 or not addr.address:
                    continue
                raw = str(addr.address).split("%", 1)[0]
                try:
                    ip = ipaddress.ip_address(raw)
                except ValueError:
                    continue
                if ip.is_global:
                    ok = True
                    break
            if ok:
                break
    except Exception:
        ok = False
    _HAS_GLOBAL_IPV6 = ok
    return ok


def reset_ipv6_probe() -> None:
    """网络变化（网卡启停 / VPN 切换 / 重新拨号）后重新探测 IPv6 可用性"""
    global _HAS_GLOBAL_IPV6
    _HAS_GLOBAL_IPV6 = None


# 连通性探测目标：**跨族并发**——同时问一个 IPv6 根和一个 IPv4 根。
# v4 根在这里不是"兜底"，而是对照：用来区分「IPv6 不通」与「整体断网」。
_PROBE_V6_TARGET = "2001:7fd::1"     # k.root-servers.net (IPv6)
_PROBE_V4_TARGET = "192.5.5.241"     # f.root-servers.net (IPv4)


def probe_ipv6_path(timeout: float = 0.8) -> tuple:
    """跨族并发探测：同时向一个 IPv6 根和一个 IPv4 根发真实 DNS 查询

    返回 ``(v6_ok, v4_ok)``：
      - ``v6_ok``：IPv6 根有应答 → IPv6 真的能出网，可以用"IPv6 优先"；
      - ``v4_ok``：IPv4 根有应答 → 网络本身正常，仅作为对照。

    为什么要 v4 对照：只看 v6 超时无法区分「IPv6 不通」和「整台机器断网」，
    两者应给出不同的日志与处置（前者降级为纯 IPv4 继续服务，后者说明网络异常）。
    两台并发发出，总耗时最多 ``timeout`` 秒，只在启动/重探时调用一次。
    """
    import concurrent.futures as _futures

    import dns.message
    import dns.query
    import dns.rdatatype

    try:
        q = dns.message.make_query(".", dns.rdatatype.NS)
    except Exception:
        return (False, False)

    def _one(server: str) -> bool:
        try:
            r = dns.query.udp(q, server, timeout=timeout, ignore_unexpected=True)
            return r is not None and len(r.answer) > 0
        except Exception:
            return False

    try:
        with _futures.ThreadPoolExecutor(max_workers=2) as pool:
            f_v6 = pool.submit(_one, _PROBE_V6_TARGET)
            f_v4 = pool.submit(_one, _PROBE_V4_TARGET)
            return (bool(f_v6.result()), bool(f_v4.result()))
    except Exception:
        return (False, False)


def ipv6_dns_reachable(timeout: float = 0.8) -> bool:
    """IPv6 是否真的能出网（等价于 ``probe_ipv6_path()[0]``）"""
    return probe_ipv6_path(timeout)[0]


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

    # 范围内按类型分组重建（见下方 reordered）；这里只判断"两者都有"才值得重排

    # 构建新 answer：范围外的保持原位，范围内**只把 AAAA 块整体前移**，
    # 其余 RRset（A、RRSIG、HTTPS…）保持原相对顺序。
    #
    # 修复：早期版本用 `aaaa_in_range + a_in_range` 重建区间，只保留 A/AAAA，
    # 区间内的其它 RRset 会被**直接丢弃**。带 DO=1 的应答形如
    # [A, RRSIG(A), AAAA, RRSIG(AAAA)]，重排后变成 [AAAA, A]——两个 RRSIG
    # 都被静默剥离，下游（浏览器安全 DNS / 其它校验器）验签必然失败。
    range_items = list(msg.answer[first_aa:last_aa + 1])
    reordered = [rrset for rrset in range_items
                 if rrset.rdtype == dns.rdatatype.AAAA]
    reordered += [rrset for rrset in range_items
                  if rrset.rdtype != dns.rdatatype.AAAA]
    new_answer = (
        list(msg.answer[:first_aa])
        + reordered
        + list(msg.answer[last_aa + 1:])
    )
    # 防御：RRset 数量必须不变，否则说明重排逻辑漏项 → 放弃重排
    if len(new_answer) != len(msg.answer):
        return

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


# ============================================================
# 拦截应答统一构造（NXDOMAIN + SOA）
# ============================================================

# 合成 SOA 使用的域：blocked.invalid. 按 RFC 6761 保留，不会被误解析到真实域。
BLOCK_SOA_MNAME = "blocked.invalid."
BLOCK_SOA_RNAME = "hostmaster.blocked.invalid."
DEFAULT_BLOCK_NEGATIVE_TTL = 60
# SOA 的 refresh / retry / expire 与 AdGuard Home 的负应答字段一致。
BLOCK_SOA_REFRESH = 3600
BLOCK_SOA_RETRY = 600
BLOCK_SOA_EXPIRE = 86400
_MAX_TTL = 0xFFFFFFFF


def normalize_block_negative_ttl(value, default=DEFAULT_BLOCK_NEGATIVE_TTL):
    """把配置里的 cache_negative_ttl 归一化为合法的 SOA TTL/MINIMUM。

    - None / 0 / 负数 / 非整数 / 超出 32 位 → default（60）；
    - 合法值原样返回（字符串数字也接受，兼容 YAML 里写成 "60"）。

    为什么不在调用点各自 `int(... or 60)`：原实现里负数会让
    `dns.rrset.from_text` 抛异常并被静默吞掉，结果是“配置写了负数时
    所有入口都悄悄丢掉 SOA、客户端立刻重试”，而且各入口难以保持一致。
    """
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return default
    if ttl <= 0 or ttl > _MAX_TTL:
        return default
    return ttl


def make_block_response(query, config=None, *, negative_ttl=None):
    """构造“被过滤规则拦截”的统一 DNS 应答：NXDOMAIN + 合成 SOA。

    四个前端（plain / DoH / DoT / DoQ）以及 main 的缓存清扫必须返回完全
    相同的拦截形态；此前这段代码在 5 处各自复制了一份，改一处漏三处会
    直接导致“某个入口返回空 NXDOMAIN、客户端立刻重试”的重试风暴。

    形态与 AdGuard Home 的 ``blocking_mode=nxdomain`` 对齐：

    - ``rcode = NXDOMAIN``；
    - ``RA=1``（本机是递归服务端，RFC 1035 §4.1.1）；
    - authority 附一条 SOA：owner=查询名，MNAME=blocked.invalid.，
      RNAME=hostmaster.blocked.invalid.，``MINIMUM=TTL=cache_negative_ttl``。
      RFC 2308 §5 规定客户端按 ``min(SOA.TTL, SOA.MINIMUM)`` 缓存负应答；
      没有 SOA 时客户端（浏览器 / B 站客户端）会立刻重试。

    与 0.0.0.0/:: 方案的区别：不返回任何地址，客户端按“域名不存在”处理，
    不会去连 0.0.0.0 反复重试（实测 0.0.0.0 会让 data.bilibili.com 一次
    会话被拦 1.8 万次）。

    Args:
        query: 原始查询 ``dns.message.Message``（可以是无 question 的畸形包）。
        config: 可选配置对象；读取 ``cache_negative_ttl``。
        negative_ttl: 显式 TTL，优先于 config（主要供测试 / 调用方覆盖）。

    Returns:
        新的 ``dns.message.Message``；调用方可直接 ``to_wire()`` 或写缓存。
    """
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.flags |= dns.flags.RA

    if negative_ttl is None:
        raw = (getattr(config, "cache_negative_ttl", None)
               if config is not None else None)
        negative_ttl = raw
    ttl = normalize_block_negative_ttl(negative_ttl)

    # 没有 question 的畸形查询（QTYPE 缺失 / 头部损坏）仍返回 NXDOMAIN，
    # 只是不附 SOA——绝不在这里抛异常，否则前端会把它变成 SERVFAIL，
    # 反而让客户端重试。
    try:
        question = query.question[0]
    except (IndexError, AttributeError):
        return response

    try:
        response.authority.append(dns.rrset.from_text(
            question.name, ttl, "IN", "SOA",
            "%s %s 1 %d %d %d %d" % (
                BLOCK_SOA_MNAME, BLOCK_SOA_RNAME,
                BLOCK_SOA_REFRESH, BLOCK_SOA_RETRY,
                BLOCK_SOA_EXPIRE, ttl,
            ),
        ))
    except Exception:
        # 极端情况下（owner 名非法）退化为“只有 NXDOMAIN 无 SOA”，
        # 保证拦截本身不失败。
        pass
    return response

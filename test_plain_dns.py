"""test_plain_dns.py — 明文 DNS(53) UDP/TCP 协议测试 + 迭代解析 DNSSEC 攻击向量穷举

运行方式：
    python test_plain_dns.py                 # 默认在 127.0.0.1:15353 起测试服务
    python test_plain_dns.py --port 53       # 用真实 53 端口（需要权限 / 端口空闲）
    python test_plain_dns.py --skip-net      # 只跑离线 DNSSEC 攻击用例

Part A（明文协议，真实 socket 栈）：
  A1 UDP 正常查询 → 响应 ID 回显、rcode/answer 正确
  A2 UDP 大响应 + 客户端无 EDNS → 置 TC 且长度 <= 512（RFC 1035 §4.2.1）
  A3 UDP 大响应 + 客户端 EDNS 4096 → 不截断
  A4 TCP 正常查询（2 字节长度前缀，RFC 1035 §4.2.2）
  A5 TCP 过短帧（length < 12）→ 回 FORMERR，且同一连接仍可复用
  A6 UDP 畸形报文（< 12 字节）→ 不崩溃（无响应或 FORMERR）
  A7 TCP 空帧（length == 0）→ 关闭连接，不挂起

Part B（迭代解析 DNSSEC 攻击向量，离线动态签名，永不过期）：
  1  重放他人 NXDOMAIN（NSEC 区间不覆盖）
  2  重放他区 SOA 伪造 NODATA
  3  篡改 answer 记录（签名失效）
  4  剥离 answer 的 RRSIG
  5  剥离否定证明（NSEC）的 RRSIG
  6  answer owner 重放（改名）
  7  CNAME 中间跳 target 篡改
  8  向负应答注入无签名 A 记录
  9  跨区重放 NSEC3 否定证明（.com opt-out）
  10 剥离 NSEC3 的 RRSIG
  11 篡改 NSEC3 Opt-Out 位（签名失效）
  12 正向合法响应（回归：必须放行）
  13 NXDOMAIN(NSEC) 合法（回归：必须放行）
  14 NXDOMAIN(NSEC3 opt-out) 合法（回归：必须放行）
  15 独立参考判定差分（同源数据，判定必须一致）
  16 CNAME 中间跳无签名 + 区未签名（cdn.jsdelivr.net 回归：必须放行）
  17 CNAME 中间跳无签名 + 区状态 unknown（必须拒绝）
  18 DS 查询不跟随 CNAME（RFC 4035 §2.4，离线）

Part B2（DNSSEC 链状态/重试逐分支穷举，离线）：
  B2.1  parent_keys 取不到 + 父区 secure → error（链不可用，放行；修复前 unknown）
  B2.2  parent_keys 取不到 + 父区 insecure → insecure
  B2.3  精确 NSEC3 + parent_keys 取不到 → error
  B2.4  NSEC3 验签失败 + keys 可用 → unknown（保守）
  B2.5  NODATA 无 NSEC + 委托点 + 父区 secure → unknown
  B2.6  NODATA 无 NSEC + 委托点 + 父区 insecure → insecure
  B2.7  DS NXDOMAIN + is_del=True → unknown
  B2.8  DS NXDOMAIN + is_del=False 升父级 → insecure
  B2.13 DS NXDOMAIN + is_del=True + 父区 insecure → insecure（CDN 随机子域回归）
  B2.14 NS 查询不把祖先区 NS（com.cn.）当最终答案（sso.sina.com.cn 回归）

Part B3（域名类型矩阵穷举，离线）：
  B3.1  gTLD / ccTLD / 中国二级 / 中文域名 / new gTLD / geoTLD / 其他
        正常查询 owner 与目标类型正确
  B3.2  各类代表域名：answer 混入祖先区 NS 时继续下钻，不误判重放
  B3.3  各类代表域名：CNAME + NODATA 返回 owner 正确的 CNAME
  B3.4  大小写 / 尾点 / IDN（Unicode 与 Punycode）等价 owner 不误判
  B2.9  链查询首次 RRL 失败、退避重试后成功
  B2.10 连续失败 → None + 15s 负缓存（第二次不重查权威）
  B2.11 同 zone 10 并发只构建一次链（single-flight）
  B2.12 不同 zone 并发受 semaphore=4 限制

Part C（真实网络端到端，`--real-dnssec` 开启）：
  cdn.jsdelivr.net / s.360.cn / opencdnkav6.jomodns.com / p.ssl.qhimg.com
  必须判 insecure 且能解析；ietf.org 必须 secure 且带 RRSIG；
  dnssec-failed.org 必须仍被丢弃。

Part D（合成 DNSSEC 权威树：能做验证时的逐分支穷举，离线）：
  D1 签名区正向（RRSIG 有效）放行 / D2 剥离 RRSIG 丢弃 /
  D3 篡改签名丢弃 / D4 未签名区（父区 NSEC 证明）放行 /
  D5 未签名区（NSEC3 opt-out 覆盖证明）放行 / D6 缺否定证明仍丢弃 /
  D7 根 DNSKEY 验签失败（bogus_root）不放行 / D8 证据 ok 时闸门不生效

Part E（链路完全不提供 DNSSEC 材料时的降级闸门，离线）：
  E1 正向放行 / E2 NODATA 放行 / E3 NXDOMAIN 保留语义 /
  E4 require_rrsig=true 仍 fail-closed / E5 根 DNSKEY NODATA /
  E6 确定性缺失只查 1 次 / E7 证据 TTL 缓存 / E8 恢复后自动回 ok /
  E9/E10 验签后端缺失的两种开关 / E11 wire 级 resolve_with_stats /
  E12 stats 计数口径

Part F（出站报文 DO 穷举，抓真实 wire bytes）：
  F1 UDP / F2 COOKIE 重发 / F3 TCP 截断重查 / F4 最小化中间跳 /
  F5 DS+DNSKEY 全链——每一条都必须带 EDNS+DO=1（排除"本地没请求 DNSSEC"）

Part G（纯迭代、无任何加密上游）：真实 ResolverManager + 合成权威树，
  G1 确认是纯迭代 / G2 签名域名解析成功 / G3 判 secure

Part H（某一地址族被中间设备代答）：H1 族完整性判定 / H2 自动换族后证据 ok /
  H3 换族后判 secure / H4 解析全程只问真族 / H5 两族都被代答仍可用 /
  H6 真族不可达时回退全族且标记未验证

Part I（iterative.family / iterative.ipv4_verify）：I1 auto 自动换族 /
  I2 ipv4+corroborate 识破镜像篡改并改用真族答案 / I3 ipv4+strict 无法判 secure /
  I4 ipv4+none 未验证放行 / I5 ipv6 强制 0 次 v4 查询 /
  I6 真族不可达时印证自动放弃 / I7 配置解析与非法值回退

Part J/K（`--real` 开启，需要出网）：J 真实链路 7 个域名端到端；
  K Config → DNSSEC 包装器 → ResolverManager → 迭代上游 全链路

诊断模式（不参与判定）：
  --probe    直接问权威，DO=1 与 DO=0 对照，打印 OPT/回声DO/RRSIG/NSEC3
  --forensic 死 IP / TCP / IPv6 对照，定位「是谁在替权威回答问题」
"""
import argparse
import asyncio
import base64
import collections
import hashlib
import logging
import os
import socket
import struct
import sys
import time
import types

from cryptography.hazmat.primitives.asymmetric import rsa

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.IN.A
import dns.rrset

# Part D..K 直接用到迭代解析器实现；缺依赖时降级为"跳过"而不是让整个测试文件
# 导入失败（Part A/B 不依赖它）。
try:
    import plain_dns_server as pds
except Exception:                       # pragma: no cover
    pds = None


def _pds_ready() -> bool:
    """Part D..K / probe / forensic 的统一前置检查"""
    if pds is None:
        print("  跳过：无法导入 plain_dns_server（缺少依赖？）")
        return False
    return True

# ============================================================
# 历史对照样本（真实权威 wire，base64）
#
# 当前 Part B 已改为用 _make_offline_fixtures() 现场生成签名，
# 不再读取这些常量；保留仅用于人工比对真实报文结构。
# ============================================================
W_FORWARD = base64.b64decode(  # ietf.org A + RRSIG（正向，签名有效）
    "3T+EAAABAAMAAAABBGlldGYDb3JnAAABAAHADAABAAEAAAEsAARoECxjwAwAAQABAAABLAAEaBAtY8AMAC4AAQAA"
    "ASwAXAABDQIAAAEsauz7EmrqO/KGyQRpZXRmA29yZwAx/jXyjSE+rnxKxPNFl/b7l3MGxS6k/6q6J92AKI4cKLXk"
    "iTeBX608PPmWIwkHKL1o6zx77IIUkXFavAowdgUtAAApBNAAAIAAAAA="
)
W_NX_NSEC = base64.b64decode(  # nonexistent-aaa111.ietf.org NXDOMAIN + NSEC
    "7ZyEAAABAAAABAABEm5vbmV4aXN0ZW50LWFhYTExMQRpZXRmA29yZwAAAQABwB8ABgABAAAHCAAyBGppbGwCbnMK"
    "Y2xvdWRmbGFyZQNjb20AA2Ruc8BBkDNcLwAAJxAAAAlgAAk6gAAABwjADAAvAAEAAAcIADIBABJub25leGlzdGVu"
    "dC1hYWExMTEEaWV0ZgNvcmcAABEAAAAAAAMAAAAAAAAAAAAAgMAfAC4AAQAABwgAXAAGDQIAAAcIauz7EmrqO/KG"
    "yQRpZXRmA29yZwD+yYldmjrO5P2hTGyl2N5VG3ocqztPHM0izgPDPhw3fadbCXGVjFE0MbJ0El9NezXjddUt0qEw"
    "HS2DtEc1fUUKwAwALgABAAAHCABcAC8NAwAABwhq7PsSauo78obJBGlldGYDb3JnABFlLiDP7n7/NZVOxkDFP98k"
    "JJ5ruNqn5NWHKsSvRMnXkKpavVTj77R9bJpyXLDXHnYA6XiAWjNv9rFdcev6ub4AACkE0AAAgAAAAA=="
)
W_NX_NSEC3 = base64.b64decode(  # nonexistent-aaa111.com NXDOMAIN + NSEC3(opt-out)
    "ebeEAwABAAAACAABEm5vbmV4aXN0ZW50LWFhYTExMQNjb20AAAEAAcAfAAYAAQAAA4QAPQFhDGd0bGQtc2VydmVy"
    "cwNuZXQABW5zdGxkDHZlcmlzaWduLWdyc8Afauub0gAABwgAAAOEAAk6gAAAA4TAHwAuAAEAAAOEAFcABg0BAAAD"
    "hGr01lJq64tq/0ADY29tAO06U/dCZxVTtbmmnNx9po7Yl494Btt5vGyKhvpE6OFXDYEECcU0tt11LlwepY351LxC"
    "AL/vASMZOKFMZt9E/GQgQ0swUE9KTUc4NzRMSlJFRjdFRk44NDMwUVZJVDhCU03AHwAyAAEAAAOEACMBAQAAABRl"
    "AaGWO+Eic0DMjdaSBIydzcL7NQAHIgAAAAACkMDUAC4AAQAAA4QAVwAyDQIAAAOEavJklWrpGa3/QANjb20ArL8V"
    "BVFzzh+2QfkZ52d+a78doYjcUDp5dK7K+KqBDlO3OkFBvwyuy5KMszHtK1vwP+k0z/FZKM+KcR3xvpY2qCBSNzJJ"
    "MERNR1RVUkIwUDBLSktQNlRMQTM2OUczUUJFRsAfADIAAQAAA4QAIgEBAAAAFNnFIxuwkh64n2kTVcdu7PIB10hu"
    "AAYgAAAAABLBhwAuAAEAAAOEAFcAMg0CAAADhGrybTVq6SJN/0ADY29tAHWjdsmH9SCNm4hODUc7Eqs+eaKpNCXP"
    "oghV09uz23Zbt5EQ3zacIi3PTXUzhmOdDukXbi33OxiOKt1yQcar1gEgM1JMMlE1ODIwNTY4N0M4STlLQzlNVjQ2"
    "REdIQ05TNDXAHwAyAAEAAAOEACIBAQAAABQe6i/u8d9vrIlMWedB0BiHyc6PwwAGIAAAAAASwjkALgABAAADhABX"
    "ADINAgAAA4Rq8RMaaufIMv9AA2NvbQCegw1cLYU16rvyNyoLU5g3Zs4Cbg2v/iPt9wiq3GrK0z2bIahdtKX8nB19"
    "orgxsOD2OEeDiodW2IZSmBThon7qAAApEAAAAIAAAAA="
)
W_CNAME = base64.b64decode(  # c.pki.goog CNAME → pki-goog.l.google.com + A
    "Q96EAAABAAEAAAABAWMDcGtpBGdvb2cAAAEAAQhwa2ktZ29vZwFsBmdvb2dsZQNjb20AAAEAAQAAASwABDr+laIA"
    "ACkCAAAAgAAAAA=="
)
W_KEY_IETF = base64.b64decode(
    "TDCFAAABAAMAAAABBGlldGYDb3JnAAAwAAHADAAwAAEAAA4QAEQBAQMNmdsswUyr3DPW132mOi8V9xESWE8jTo0d"
    "xCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGcAMADAAAQAADhAARAEAAw2gkxERLPkTiBjN"
    "L+rpcOu9TWow9giMJbMlo5q7xc0Rl6oJgoPlqvQhF3wqpdcUmSqZV9G8wY+YzXHx8YBrZeFIwAwALgABAAAOEABc"
    "ADANAgAADhBrMKKAauA3AAlDBGlldGYDb3JnAA4ixp7MmXNTwxAdWbqQLc8t8+X7iNzObnRzkVvh7gJmnHHugAd4"
    "jOpVsJvIgcR/LQPuVm/nkwTZL1/8DlYDOTgAACkE0AAAgAAAAA=="
)
W_KEY_COM = base64.b64decode(
    "DsCFAAABAAMAAAABA2NvbQAAMAABwAwAMAABAAFRgABEAQADDbwSy6u3T/QaBqbLf4wzx0qMtTBxGKF4II8Pu79s"
    "o8y1mYOgmnVXOGiFEhdlTtqNBptHgCAIDrfLHmZ8xThAwXHADAAwAAEAAVGAAEQBAQMNtx8EZRAd2+K/DJRV0S+h"
    "bBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINcAMAC4AAQABUYAAVwAwDQEA"
    "AVGAav2+C2rp9l9NBgNjb20ArE4G5tnBPIxzOBR9YNLaQH3p5B1ha3vupXZhcqEXkcfOMUEIAa/kKbTvBrPyF/k3"
    "vlbgLlNI2PQPfvIgMPEoHwAAKRAAAACAAAAA"
)
W_KEY_ROOT = base64.b64decode(
    "UymFAAABAAQAAAABAAAwAAEAADAAAQACowABCAEAAwgDAQAByis3E1z23S57Vl6c+NUxG6OVDZgsEnSlH/hcyMdv"
    "L2+vTdxHEVIqdanF6Dk8vfzgP1V6p1LVuOsbJOwe2hqDMjc2JcV3yyMcw6dnG7mmn/5QEiDu1qxiBUwx1SIzVi79"
    "z63fR3VDD+/o1gs2c6fLBO7oe5SHtjWxlGr8ZlyvEsQ1cdCjIqk6s6vxHf6p3rArr0goHzRkFm2Rf2t0SoomT7Jh"
    "eMRnNnTOQAW2GY2AKt4ChT09WVTrp3I6xouN/fApSVSb1I04qz60rou5KZFsrr7VP+09pFowFIS6/Ybq9d+cnW7I"
    "xsa+2lGf9gNy9OOunoPMTpfIXjhB3AnegrHh6QAAMAABAAKjAAEIAQEDCAMBAAGveo3rpJ2ZWnkq78gCY+mR79vI"
    "YTipMd6yxl1Wguq107A3OOPf3InZbaZMhsAiTZzgJRTShdowaLGQVOXnh7KWkFjpjhJWbIyAjEDAt2nh2xokob2b"
    "MeMDGEox/Hu1a4W7uoq8As1QQKREo21HaVlphJ4WrYVrtY6PrIhVIkQAMZvasiTYP8Dmaqsy/3S/6vD5HEVOaFCh"
    "KVIHu9TN3o9v+wj6qXVcLjKE76AfmTk+GHhssTLx5m68ZRcxjhzoo7czfrtU0DWrV9lwbs2TUNSvrNgl5DyGaO7O"
    "iYGcr2gXr2LcT72C8OM/Zkeytr2hdfFGB/WfRjVFHmsn3ygu9z2HAAAwAAEAAqMAAQgBAQMIAwEAAaz/tAm8yTn4"
    "Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlN"
    "Vz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb"
    "9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd"
    "RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bUAAC4AAQACowABEwAwCAAA"
    "AqMAawDfAGrlL4CXKABQWQliF7GrlmB+8/6gjPZZQlCAXxuFbyy3cude0gE/R5FxJBetiDv6W7HBBiD7eKJlXb4E"
    "k9w2Z/+kO76409qmWQc8kteH1ZLSgRVkpQ2T/TCTcDRcvlQ5JN09af8ihNZbHIbG6f651Xt5FCpWlG9J2UEVqo9Z"
    "IMgORfRBAh/J7vZMHi2w8GcDaJYPJ7pTXnsRw8F014q/hx+HVwA6V48hrEuzU2g0ci79muoRjnMz4Y0nhnvZNtrT"
    "2NiPPdrIFI9WKcjrg5g45Gpmxi24tdSsF0PpRZ9XwuN/dvQwZ8GzsGhlgAnFXI2vkJAXXcIvD7jGtsyyZBZ1MGrO"
    "nmIS0H1UAAApEAAAAIAAAAA="
)

RESULTS = []


def check(name: str, cond: bool, detail: str = ""):
    RESULTS.append((name, bool(cond)))
    print(("  PASS " if cond else "  FAIL ") + name + (f" | {detail}" if detail else ""))


# ============================================================
# Part A：明文 53 端口 UDP / TCP 协议测试（真实 socket）
# ============================================================
_LEGACY_SLOTS = {"a": 0}


def _big_response(query_wire: bytes) -> bytes:
    """构造一个 > 512 字节的响应（用于测 UDP 截断 / EDNS）"""
    q = dns.message.from_wire(query_wire)
    resp = dns.message.make_response(q)
    rrset = resp.find_rrset(resp.answer, q.question[0].name,
                            dns.rdataclass.IN, dns.rdatatype.A, create=True)
    for i in range(40):   # 40 × (4B rdata + 12B 头) ≈ 640B
        rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A,
                                     f"203.0.113.{i + 1}"))
    rrset.ttl = 60
    return resp.to_wire()


def _udp_query(port: int, wire: bytes, timeout: float = 3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(wire, ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def _tcp_query(port: int, wire: bytes, timeout: float = 3.0, reuse_sock=None):
    """返回 (响应 wire 或 None, socket)；reuse_sock 非空时复用连接"""
    s = reuse_sock
    close_after = False
    if s is None:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        close_after = True
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack("!H", len(wire)) + wire)
        hdr = s.recv(2)
        if len(hdr) < 2:
            return None, s
        ln = struct.unpack("!H", hdr)[0]
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf, s
    except socket.timeout:
        return None, s
    finally:
        if close_after and s is not None and not reuse_sock:
            pass  # 由调用方关闭


class _SrvCfg:
    """PlainDNSServer 需要的最小配置（未列出的字段一律 0/False）"""
    plain_dns_enabled = True
    plain_dns_host = "127.0.0.1"
    plain_dns_port = 15353
    plain_dns_ipv6_enabled = False
    plain_dns_ipv6_host = "::1"
    plain_dns_iterative_enabled = False
    plain_dns_udp_workers = 2
    max_concurrent = 100
    max_concurrent_per_ip = 50
    plain_dns_iterative_timeout_ms = 2000
    plain_dns_iterative_max_depth = 8
    plain_dns_iterative_strict_dnssec = True
    plain_dns_iterative_hop_parallel = 2
    plain_dns_iterative_qname_minimization = True
    plain_dns_iterative_root_servers = None
    bootstrap_resolvers = []

    def __getattr__(self, name):
        return 0


async def run_part_a(port: int) -> bool:
    print("\n[Part A] 明文 DNS 协议（UDP/TCP，127.0.0.1:%d）" % port)
    try:
        from plain_dns_server import PlainDNSServer
    except Exception as e:      # pragma: no cover
        print(f"  跳过：无法导入 PlainDNSServer（{e}）")
        return True

    cfg = _SrvCfg()
    cfg.plain_dns_port = port
    try:
        srv = PlainDNSServer(cfg, None, None, None, None)
    except Exception as e:
        print(f"  跳过：PlainDNSServer 构造失败（{e}）")
        return True

    async def fake_resolve(data, addr, client_ip):
        # 只替换业务逻辑：协议层（截断 / 长度前缀 / FORMERR / ID）走真实实现
        return _big_response(data)

    srv._resolve_and_respond = fake_resolve
    try:
        await srv.start()
    except Exception as e:
        print(f"  跳过：服务启动失败（{e}）")
        return True
    if not getattr(srv, "_transport_v4", None):
        print("  跳过：UDP 端口未绑定（可能被占用/权限不足）")
        try:
            await srv.stop()
        except Exception:
            pass
        return True

    try:
        # 同步 socket 操作必须丢到线程里：直接在事件循环线程里 recv 会阻塞
        # loop，服务端（同一个 loop）根本没机会处理，表现为"无响应"。
        async def a_udp(wire, timeout=3.0):
            return await asyncio.to_thread(_udp_query, port, wire, timeout)

        async def a_tcp(wire, timeout=3.0, reuse_sock=None):
            return await asyncio.to_thread(_tcp_query, port, wire, timeout,
                                           reuse_sock)

        # A1 UDP 正常查询：ID 回显
        q = dns.message.make_query("example.test", dns.rdatatype.A)
        resp = await a_udp(q.to_wire())
        ok_id = False
        if resp:
            try:
                r = dns.message.from_wire(resp)
                ok_id = r.id == q.id
                # 无 EDNS 的客户端会拿到截断响应（TC 置位、answer 可能被清空），
                # 因此判据是"ID 回显 且（有数据 或 已置 TC）"
                has_data = bool(r.answer) or bool(r.flags & dns.flags.TC)
                check("A1 UDP 正常查询（ID 回显）", ok_id and has_data,
                      f"id_match={ok_id} tc={bool(r.flags & dns.flags.TC)} "
                      f"answers={len(r.answer)}")
            except Exception as e:
                check("A1 UDP 正常查询（ID 回显）", False, repr(e))
        else:
            check("A1 UDP 正常查询（ID 回显）", False, "无响应")

        # A2 UDP 大响应 + 无 EDNS → TC 置位且 <= 512
        q2 = dns.message.make_query("example.test", dns.rdatatype.A)
        resp2 = await a_udp(q2.to_wire())
        if resp2:
            r2 = dns.message.from_wire(resp2)
            tc = bool(r2.flags & dns.flags.TC)
            check("A2 UDP 无 EDNS 大响应被截断（TC + ≤512B）",
                  tc and len(resp2) <= 512, f"tc={tc} len={len(resp2)}")
        else:
            check("A2 UDP 无 EDNS 大响应被截断（TC + ≤512B）", False, "无响应")

        # A3 UDP + EDNS 4096 → 不截断
        q3 = dns.message.make_query("example.test", dns.rdatatype.A)
        q3.use_edns(0, payload=4096)
        resp3 = await a_udp(q3.to_wire())
        if resp3:
            r3 = dns.message.from_wire(resp3)
            tc3 = bool(r3.flags & dns.flags.TC)
            check("A3 UDP + EDNS 4096 不截断", (not tc3) and len(resp3) > 512,
                  f"tc={tc3} len={len(resp3)}")
        else:
            check("A3 UDP + EDNS 4096 不截断", False, "无响应")

        # A4 TCP 正常查询（长度前缀）
        q4 = dns.message.make_query("example.test", dns.rdatatype.A)
        r4_wire, sock4 = await a_tcp(q4.to_wire())
        ok4 = False
        if r4_wire:
            try:
                r4 = dns.message.from_wire(r4_wire)
                ok4 = (r4.id == q4.id) and len(r4.answer) > 0
                check("A4 TCP 正常查询（2 字节长度前缀 + ID 回显）", ok4,
                      f"len={len(r4_wire)} id_match={r4.id == q4.id}")
            except Exception as e:
                check("A4 TCP 正常查询（2 字节长度前缀 + ID 回显）", False, repr(e))
        else:
            check("A4 TCP 正常查询（2 字节长度前缀 + ID 回显）", False, "无响应")

        # A5 TCP 过短帧 → FORMERR，且连接可复用
        if sock4 is not None:
            try:
                short = b"\x00" * 6      # length=6 < 12
                await asyncio.to_thread(
                    sock4.sendall, struct.pack("!H", len(short)) + short)
                hdr = await asyncio.to_thread(sock4.recv, 2)
                ln = struct.unpack("!H", hdr)[0] if len(hdr) == 2 else 0
                body = b""
                while len(body) < ln:
                    body += await asyncio.to_thread(sock4.recv, ln - len(body))
                err = dns.message.from_wire(body) if body else None
                ok5 = err is not None and err.rcode() == dns.rcode.FORMERR
                # 复用同一连接再查一次
                q5 = dns.message.make_query("again.test", dns.rdatatype.A)
                r5_wire, _ = await a_tcp(q5.to_wire(), reuse_sock=sock4)
                reuse_ok = False
                if r5_wire:
                    try:
                        reuse_ok = dns.message.from_wire(r5_wire).id == q5.id
                    except Exception:
                        reuse_ok = False
                check("A5 TCP 过短帧回 FORMERR 且连接可复用",
                      ok5 and reuse_ok,
                      f"formerr={ok5} reuse={reuse_ok}")
            except Exception as e:
                check("A5 TCP 过短帧回 FORMERR 且连接可复用", False, repr(e))
            finally:
                try:
                    sock4.close()
                except Exception:
                    pass

        # A6 UDP 畸形报文（< 12 字节）→ 不崩溃
        try:
            await a_udp(b"\x01\x02\x03", timeout=1.0)
        except Exception:
            pass
        alive = False
        q6 = dns.message.make_query("alive.test", dns.rdatatype.A)
        r6 = await a_udp(q6.to_wire())
        if r6:
            try:
                alive = dns.message.from_wire(r6).id == q6.id
            except Exception:
                alive = False
        check("A6 UDP 畸形报文后服务仍存活", alive)

        # A7 TCP 空帧（length=0）→ 关闭连接，不挂起
        try:
            s7 = await asyncio.to_thread(
                socket.create_connection, ("127.0.0.1", port), 3)
            await asyncio.to_thread(s7.sendall, struct.pack("!H", 0))
            s7.settimeout(2.0)
            data = await asyncio.to_thread(s7.recv, 2)
            closed = (data == b"")
            check("A7 TCP 空帧关闭连接（不挂起）", closed,
                  f"recv={data!r}")
            s7.close()
        except socket.timeout:
            check("A7 TCP 空帧关闭连接（不挂起）", False, "超时未关闭")
        except Exception as e:
            check("A7 TCP 空帧关闭连接（不挂起）", False, repr(e))
    finally:
        try:
            await srv.stop()
        except Exception:
            pass
    return all(ok for _, ok in RESULTS)


# ============================================================
# Part B：迭代解析 DNSSEC 攻击向量（动态签名，永不过期）
# ============================================================
def _new_dnssec_key(flags=257):
    """生成一把临时 RSA 密钥（测试用 1024 位足够，生成快）。"""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    key = dns.dnssec.make_dnskey(
        priv.public_key(), algorithm=8, flags=flags, protocol=3)
    return priv, key


def _zone_keyset(zone, key, ttl=300):
    return dns.rrset.from_rdata(dns.name.from_text(zone), ttl, key)


def _sign_rrset(rrset, priv, key, signer, now):
    """以“当前时间 ± 缓冲”签一个 RRset，返回 RRSIG RRset。

    旧测试内嵌真实权威的 base64 wire，签名有效期是固定的（例如到
    2026-11-05 21:54 UTC）；数据一过期，合法用例会被误判为
    ``no RRSIGs validated``，测试就成了时间炸弹。这里每次运行都用
    临时密钥现场签，inception=now-300、expiration=now+86400，
    攻击向量（篡改/剥离/重放）的语义不变，但数据永不过期。
    """
    sig = dns.dnssec.sign(
        rrset, priv, dns.name.from_text(signer), key,
        inception=now - 300, expiration=now + 86400, verify=False)
    return dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)


def _make_offline_fixtures(pds):
    """生成等价于旧静态 wire 的一套动态签名数据。

    返回 (fwd, nx_nsec, nx_nsec3, cname, keys)，结构/owner/签名者与
    旧数据一致，只是签名时间随运行时刻变化。
    """
    now = int(time.time())
    ietf_priv, ietf_key = _new_dnssec_key()
    com_priv, com_key = _new_dnssec_key()
    root_priv, root_key = _new_dnssec_key()
    pki_priv, pki_key = _new_dnssec_key()
    keys = {
        "ietf.org.": _zone_keyset("ietf.org.", ietf_key),
        "com.": _zone_keyset("com.", com_key),
        ".": _zone_keyset(".", root_key),
        "pki.goog.": _zone_keyset("pki.goog.", pki_key),
    }

    # 1) 正向：ietf.org A + RRSIG
    fwd = dns.message.make_response(
        dns.message.make_query("ietf.org", dns.rdatatype.A))
    a = dns.rrset.from_text("ietf.org.", 300, "IN", "A", "192.0.2.1")
    fwd.answer.extend(
        [a, _sign_rrset(a, ietf_priv, ietf_key, "ietf.org.", now)])

    # 2) NXDOMAIN + NSEC（owner=ietf.org，next 覆盖 nonexistent-aaa111）
    nx_nsec = dns.message.make_response(
        dns.message.make_query("nonexistent-aaa111.ietf.org",
                               dns.rdatatype.A))
    nx_nsec.set_rcode(dns.rcode.NXDOMAIN)
    soa = dns.rrset.from_text(
        "ietf.org.", 300, "IN", "SOA",
        "ns.ietf.org. hostmaster.ietf.org. 1 3600 600 86400 300")
    nsec = dns.rrset.from_text(
        "ietf.org.", 300, "IN", "NSEC",
        "nonexistent-zzz999.ietf.org. A RRSIG NSEC")
    for rr in (soa, nsec):
        nx_nsec.authority.extend(
            [rr, _sign_rrset(rr, ietf_priv, ietf_key, "ietf.org.", now)])

    # 3) NXDOMAIN + NSEC3 opt-out（com.；owner=hash(qname)，位图不含 DS）
    nx_nsec3 = dns.message.make_response(
        dns.message.make_query("nonexistent-aaa111.com", dns.rdatatype.A))
    nx_nsec3.set_rcode(dns.rcode.NXDOMAIN)
    com_soa = dns.rrset.from_text(
        "com.", 300, "IN", "SOA",
        "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400")
    salt = b"\xaa"
    qname = dns.name.from_text("nonexistent-aaa111.com.")

    def _nsec3_rr(owner_hash, next_hash, flags, bitmap):
        owner_label = base64.b32hexencode(owner_hash).decode().lower().rstrip("=")
        next_label = base64.b32hexencode(next_hash).decode().lower().rstrip("=")
        return dns.rrset.from_text(
            owner_label + ".com.", 300, "IN", "NSEC3",
            "1 %d 0 %s %s %s" % (flags, salt.hex(), next_label, bitmap))

    # RFC 5155 §8.9 的 NXDOMAIN 需要三项证明，缺一项会被保守拒绝：
    #   1) next-closer 区间覆盖 qname 的 hash；
    #   2) closest-encloser（com.）存在性：某个 NSEC3 owner 恰好等于 hash(com.)；
    #   3) *.CE wildcard 否定：hash(*.com.) 落在某个 NSEC3 区间内。
    hq = pds.IterativeResolver._nsec3_hash(qname, salt, 0, 1)
    hc = pds.IterativeResolver._nsec3_hash(dns.name.from_text("com."), salt, 0, 1)
    hw = pds.IterativeResolver._nsec3_hash(
        dns.name.from_text("*.com."), salt, 0, 1)

    def _shift(h, delta):
        return ((int.from_bytes(h, "big") + delta) % (1 << 160)).to_bytes(20, "big")

    nsec3_q = _nsec3_rr(_shift(hq, -1), _shift(hq, 1), 1, "A RRSIG")
    nsec3_ce = _nsec3_rr(hc, _shift(hc, 1), 0, "SOA RRSIG NSEC3PARAM")
    nsec3_wc = _nsec3_rr(_shift(hw, -1), _shift(hw, 1), 1, "A RRSIG")
    for rr in (com_soa, nsec3_q, nsec3_ce, nsec3_wc):
        nx_nsec3.authority.extend(
            [rr, _sign_rrset(rr, com_priv, com_key, "com.", now)])

    # 4) CNAME（c.pki.goog → pki-goog.l.google.com），中间跳用于篡改用例
    cname = dns.message.make_response(
        dns.message.make_query("c.pki.goog", dns.rdatatype.A))
    c = dns.rrset.from_text(
        "c.pki.goog.", 300, "IN", "CNAME", "pki-goog.l.google.com.")
    cname.answer.extend(
        [c, _sign_rrset(c, pki_priv, pki_key, "pki.goog.", now)])
    cname._cname_chain = [cname.to_wire()]
    cname._cname_targets = ["pki-goog.l.google.com."]
    return fwd, nx_nsec, nx_nsec3, cname, keys


def _clone(msg):
    return dns.message.from_wire(msg.to_wire())


def _drop_sigs(msg, section_name, covers):
    """删除指定段中 covers 匹配的 RRSIG（模拟中间人剥离）"""
    from dns.message import Message
    section = getattr(msg, section_name)
    keep = [r for r in section
            if not (r.rdtype == dns.rdatatype.RRSIG
                    and getattr(r, "covers", None) == covers)]
    out = Message(id=msg.id)
    out.flags = msg.flags
    out.question = list(msg.question)
    for name in ("answer", "authority", "additional"):
        for rrset in getattr(msg, name):
            if rrset not in keep and getattr(msg, name) is section:
                continue
            tgt = out.find_rrset(getattr(out, name), rrset.name, rrset.rdclass,
                                 rrset.rdtype,
                                 covers=getattr(rrset, "covers", None) or 0,
                                 create=True)
            for rd in rrset:
                tgt.add(rd)
            tgt.ttl = rrset.ttl
    return out


def _make_engine(reply, keys, status_map, pds):
    eng = object.__new__(pds.IterativeResolver)
    eng.strict_dnssec = True
    eng._stats = collections.Counter()
    eng._verified_zone_cache = {}
    eng._dnskey_inflight = {}
    eng._ds_cache = {}
    eng._ds_inflight = {}
    eng._dnssec_warned = set()
    eng._chain_unavailable = set()
    eng._last_release = ""
    eng._zone_ns_cache = {}
    eng._delegation_cache = {}
    eng._dnssec_crypto_ok = True
    eng._has_ipv6 = False
    eng._dropped = []

    async def fake_iterate(qname, qtype, depth=0, rdclass=1):
        # 必须保留 _cname_chain / _cname_targets：旧实现 from_wire(reply.to_wire())
        # 会把这两个动态属性丢掉，CNAME 中间跳用例因此**从未真正执行**
        # （测试 7 之前只是命中了“无签名 owner”分支，不是链中间跳校验）。
        out = dns.message.from_wire(reply.to_wire())
        out._cname_chain = list(getattr(reply, "_cname_chain", []) or [])
        out._cname_targets = list(getattr(reply, "_cname_targets", []) or [])
        return out

    async def fake_trusted(zone_name):
        return keys.get(str(zone_name).lower())

    async def fake_status(zone_name):
        return (status_map or {}).get(str(zone_name).lower(), "secure")

    eng._iterate = fake_iterate
    eng._get_trusted_dnskey = fake_trusted
    eng._zone_signed_status = fake_status
    eng._needs_bootstrap_fallback = lambda resp, qtype: False
    eng._report_dnssec_drop = lambda qname, **kw: eng._dropped.append(qname)
    eng._report_dnssec_stripped = lambda qname: eng._dropped.append(("stripped", qname))
    eng._report_unsigned_unknown = lambda qname: eng._dropped.append(("unknown", qname))
    return eng


async def run_part_b() -> bool:
    print("\n[Part B] 迭代解析 DNSSEC 攻击向量（离线）")
    try:
        import plain_dns_server as pds
    except Exception as e:      # pragma: no cover
        print(f"  跳过：无法导入 plain_dns_server（{e}）")
        return True

    fwd, nx_nsec, nx_nsec3, cname, keys = _make_offline_fixtures(pds)
    start_ok = len(RESULTS)

    # 0) 泛化性门槛：所有 RRSIG 都必须覆盖“当前运行时刻”，而不是
    #    依赖某个固定日期。数据由临时密钥现场签，任何一天运行都应成立。
    _now = int(time.time())
    _sig_count = 0
    _sig_ok = True
    for _section in (fwd.answer, nx_nsec.authority, nx_nsec3.authority):
        for _rr in _section:
            if _rr.rdtype != dns.rdatatype.RRSIG:
                continue
            for _sig in _rr:
                _sig_count += 1
                if not (_sig.inception <= _now < _sig.expiration):
                    _sig_ok = False
    check("0  动态签名有效期覆盖当前时间（不依赖固定日期）",
          _sig_count > 0 and _sig_ok,
          f"now={_now} sigs={_sig_count}")

    async def run(eng, qname, qtype=dns.rdatatype.A):
        return await eng._resolve_verified(qname, qtype, 1)

    # 1) 重放他人 NXDOMAIN（NSEC 区间不覆盖）
    eng = _make_engine(_clone(nx_nsec), keys, {}, pds)
    out = await run(eng, "nonexistent-zzz999.ietf.org")
    check("1  重放他人 NXDOMAIN（NSEC 区间不覆盖）被拒绝", out is None,
          f"stats={ {k: v for k, v in dict(eng._stats).items() if v} }")

    # 2) 重放他区 SOA 伪造 NODATA
    eng = _make_engine(_clone(nx_nsec), keys, {"nic.cz.": "secure"}, pds)
    out = await run(eng, "nonexistent-zzz999.nic.cz")
    check("2  重放他区 SOA 伪造 NODATA 被拒绝", out is None)

    # 3) 篡改 answer 记录（签名失效）
    t3 = _clone(fwd)
    a_rr = next(r for r in t3.answer if r.rdtype == dns.rdatatype.A)
    a_rr.clear()
    a_rr.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "203.0.113.66"))
    eng = _make_engine(t3, keys, {}, pds)
    out = await run(eng, "ietf.org")
    check("3  篡改 answer 记录（签名失效）被拒绝", out is None)

    # 4) 剥离 answer 的 RRSIG
    t4 = _drop_sigs(_clone(fwd), "answer", dns.rdatatype.A)
    eng = _make_engine(t4, keys, {}, pds)
    out = await run(eng, "ietf.org")
    check("4  剥离 answer RRSIG 被拒绝", out is None)

    # 5) 剥离否定证明（NSEC）的 RRSIG
    t5 = _drop_sigs(_clone(nx_nsec), "authority", dns.rdatatype.NSEC)
    eng = _make_engine(t5, keys, {}, pds)
    out = await run(eng, "nonexistent-aaa111.ietf.org")
    check("5  剥离 NSEC 的 RRSIG 被拒绝", out is None)

    # 6) answer owner 重放（改名）
    t6 = _clone(fwd)
    new_rr = dns.rrset.RRset(dns.name.from_text("other.example."),
                             dns.rdataclass.IN, dns.rdatatype.A)
    for r in t6.answer:
        if r.rdtype == dns.rdatatype.A:
            for rd in r:
                new_rr.add(rd)
    t6.answer.clear()
    t6.answer.append(new_rr)
    eng = _make_engine(t6, keys, {}, pds)
    out = await run(eng, "ietf.org")
    check("6  answer owner 重放（改名）被拒绝", out is None)

    # 7) CNAME 中间跳 target 篡改
    t7 = _clone(cname)
    chain = list(getattr(t7, "_cname_chain", []) or [])
    if chain:
        mid = dns.message.from_wire(chain[0])
        for rrset in mid.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                rrset.clear()
                rrset.add(dns.rdtypes.ANY.CNAME.CNAME(
                    dns.rdataclass.IN, dns.rdatatype.CNAME,
                    dns.name.from_text("evil.example.")))
        t7._cname_chain = [mid.to_wire()]
    eng = _make_engine(t7, keys, {}, pds)
    out = await run(eng, "c.pki.goog")
    check("7  CNAME 中间跳 target 篡改被拒绝", out is None)

    # 8) 向负应答注入无签名 A 记录
    t8 = _clone(nx_nsec)
    inj = dns.rrset.RRset(dns.name.from_text("ietf.org."), dns.rdataclass.IN,
                          dns.rdatatype.A)
    inj.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, "203.0.113.77"))
    t8.answer.append(inj)
    eng = _make_engine(t8, keys, {}, pds)
    out = await run(eng, "nonexistent-aaa111.ietf.org")
    check("8  向负应答注入 A 记录（无签名）被拒绝", out is None)

    # 9) 跨区重放 NSEC3 否定证明
    eng = _make_engine(_clone(nx_nsec3), keys, {"nic.cz.": "secure"}, pds)
    out = await run(eng, "nonexistent-zzz999.nic.cz")
    check("9  跨区重放 NSEC3 否定证明被拒绝", out is None)

    # 10) 剥离 NSEC3 的 RRSIG
    t10 = _drop_sigs(_clone(nx_nsec3), "authority", dns.rdatatype.NSEC3)
    eng = _make_engine(t10, keys, {}, pds)
    out = await run(eng, "nonexistent-aaa111.com")
    check("10 剥离 NSEC3 的 RRSIG 被拒绝", out is None)

    # 11) 篡改 NSEC3 Opt-Out 位（签名失效）
    t11 = _clone(nx_nsec3)
    for rrset in t11.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        old = list(rrset)
        rrset.clear()
        for rd in old:
            rrset.add(dns.rdtypes.ANY.NSEC3.NSEC3(
                rd.rdclass, rd.rdtype, algorithm=rd.algorithm,
                flags=int(rd.flags) ^ 0x01, iterations=rd.iterations,
                salt=rd.salt, next=rd.next, windows=rd.windows))
    eng = _make_engine(t11, keys, {}, pds)
    out = await run(eng, "nonexistent-aaa111.com")
    check("11 篡改 NSEC3 Opt-Out 位（签名失效）被拒绝", out is None)

    # 12) 正向合法响应（回归）
    eng = _make_engine(_clone(fwd), keys, {}, pds)
    out = await run(eng, "ietf.org")
    check("12 正向合法响应被放行（回归）", out is not None,
          f"stats={ {k: v for k, v in dict(eng._stats).items() if v} }")

    # 13) NXDOMAIN(NSEC) 合法（回归）
    eng = _make_engine(_clone(nx_nsec), keys,
                       {"nonexistent-aaa111.ietf.org": "secure"}, pds)
    out = await run(eng, "nonexistent-aaa111.ietf.org")
    check("13 NXDOMAIN(NSEC) 合法响应被放行（回归）", out is not None,
          f"stats={ {k: v for k, v in dict(eng._stats).items() if v} }")

    # 14) NXDOMAIN(NSEC3 opt-out) 合法（回归）
    eng = _make_engine(_clone(nx_nsec3), keys,
                       {"nonexistent-aaa111.com": "secure"}, pds)
    out = await run(eng, "nonexistent-aaa111.com")
    check("14 NXDOMAIN(NSEC3 opt-out) 合法响应被放行（回归）", out is not None,
          f"stats={ {k: v for k, v in dict(eng._stats).items() if v} }")

    # 16) CNAME 中间跳无签名，但该跳所在区**未签名** → 必须放行
    #     （生产日志：cdn.jsdelivr.net CNAME 中间跳被误判 unknown 后丢弃）
    def _cname_hop(owner: str, target: str):
        m = dns.message.make_response(
            dns.message.make_query(owner, dns.rdatatype.A))
        rr = dns.rrset.RRset(dns.name.from_text(owner),
                             dns.rdataclass.IN, dns.rdatatype.CNAME)
        rr.add(dns.rdtypes.ANY.CNAME.CNAME(
            dns.rdataclass.IN, dns.rdatatype.CNAME,
            dns.name.from_text(target)))
        rr.ttl = 60
        m.answer.append(rr)
        return m

    t16 = _clone(fwd)  # 最终 A + RRSIG（ietf.org，可验证；qname 必须是 owner）
    t16._cname_chain = [_cname_hop("cdn.jsdelivr.net", "ietf.org").to_wire()]
    eng = _make_engine(t16, keys,
                       {"cdn.jsdelivr.net.": "insecure",
                        "ietf.org.": "secure"}, pds)
    out = await run(eng, "ietf.org")
    check("16 CNAME 中间跳无签名但区未签名被放行（cdn.jsdelivr 回归）",
          out is not None,
          f"stats={ {k: v for k, v in dict(eng._stats).items() if v} }")

    # 17) 同一中间跳，若无法证明该区未签名（unknown）→ 仍必须拒绝
    t17 = _clone(fwd)
    t17._cname_chain = [_cname_hop("cdn.jsdelivr.net", "ietf.org").to_wire()]
    eng = _make_engine(t17, keys,
                       {"cdn.jsdelivr.net.": "unknown",
                        "ietf.org.": "secure"}, pds)
    out = await run(eng, "ietf.org")
    check("17 CNAME 中间跳无签名且区状态 unknown 仍被拒绝", out is None)

    # 18) DS 查询不得跟随 CNAME（RFC 4035 §2.4）
    #     cdn.jsdelivr.net 的 DS 查询若跟到 fastly/cloudflare，会把目标区的
    #     NSEC3/SOA 当成自己的否定证明，父区 key 与 owner 错配 → unknown。
    eng18 = object.__new__(pds.IterativeResolver)
    eng18.qname_minimization = False
    eng18.root_servers = ["192.0.2.1"]
    eng18.max_depth = 8
    eng18._zone_ns_cache = {}
    eng18._stats = collections.Counter()
    eng18._closest_zone_servers = lambda qname, qtype: None
    _ds_cname = _cname_hop("cdn.jsdelivr.net",
                           "cdn.jsdelivr.net.cdn.cloudflare.net")

    async def fake_query_servers(servers, qname, qtype, rdclass=1):
        return _ds_cname

    eng18._query_servers = fake_query_servers
    out18 = await eng18._iterate("cdn.jsdelivr.net", dns.rdatatype.DS)
    check("18 DS 查询不跟随 CNAME（直接返回 CNAME 应答）",
          out18 is not None
          and any(rr.rdtype == dns.rdatatype.CNAME for rr in out18.answer),
          f"answers={[(str(r.name), dns.rdatatype.to_text(r.rdtype)) for r in (out18.answer if out18 else [])]}")

    # 19/20) RFC 4035 §5.3：签名区 RRset 缺 RRSIG 必须 bogus；
    #        未签名区（如签名区 CNAME 到未签名 CDN）允许无 RRSIG。
    from dnssec import DNSSECValidator

    async def _local_unsigned_case(zone_signed: bool, owner: str):
        val = DNSSECValidator(enabled=True, mode="strict")

        async def fake_keys(_name):
            return "secure", {
                dns.name.from_text("ietf.org."): keys["ietf.org."],
                dns.name.from_text("."): keys["."],
            }

        async def fake_zone(_name):
            return zone_signed

        val._get_verified_zone_keys = fake_keys
        val._zone_has_ds = fake_zone
        resp = _clone(fwd)
        extra = dns.rrset.RRset(dns.name.from_text(owner),
                                dns.rdataclass.IN, dns.rdatatype.A)
        extra.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A,
                                     "203.0.113.99"))
        resp.answer.append(extra)
        return await val._validate_locally(resp, dns.name.from_text("ietf.org"))

    ok19 = await _local_unsigned_case(True, "unsigned.ietf.org.")
    check("19 签名区 RRset 缺 RRSIG 判 bogus", ok19 is False)
    ok20 = await _local_unsigned_case(False, "unsigned.example.")
    check("20 未签名区 RRset 无 RRSIG 允许", ok20 is True)

    # 23) RFC 5452 §9.2 bailiwick：referral 的 NS owner 必须是 qname 祖先；
    #     旧实现只校验“写缓存”，仍会直接使用越界 referral 的服务器。
    eng23 = object.__new__(pds.IterativeResolver)
    eng23.qname_minimization = False
    eng23.root_servers = ["192.0.2.1"]
    eng23.max_depth = 8
    eng23._zone_ns_cache = {}
    eng23._stats = collections.Counter()
    eng23._closest_zone_servers = lambda qname, qtype: None
    bad_ref = dns.message.make_response(dns.message.make_query(
        "victim.example", dns.rdatatype.A))
    bad_ref.authority.append(dns.rrset.from_text(
        "evil.example.", 300, "IN", "NS", "ns.evil.example."))
    bad_ref.additional.append(dns.rrset.from_text(
        "ns.evil.example.", 300, "IN", "A", "192.0.2.9"))
    calls23 = []

    async def fake_bad_referral(servers, qname, qtype, rdclass=1):
        calls23.append(qname)
        if len(calls23) == 1:
            return bad_ref
        good = dns.message.make_response(dns.message.make_query(
            qname, dns.rdatatype.A))
        good.answer.append(dns.rrset.from_text(
            f"{qname}.", 60, "IN", "A", "203.0.113.5"))
        return good

    eng23._query_servers = fake_bad_referral
    out23 = await eng23._iterate("victim.example", dns.rdatatype.A)
    check("23 越界 referral 被拒绝（bailiwick）",
          out23 is None and len(calls23) == 1,
          f"out={out23 is not None} calls={len(calls23)}")

    # 15) 独立参考判定差分（正向 / 两种负应答 / CNAME）
    def _ref_find_sig(msg, rrset):
        for sec in (msg.answer, msg.authority):
            try:
                return msg.find_rrset(sec, rrset.name, rrset.rdclass,
                                      dns.rdatatype.RRSIG,
                                      covers=rrset.rdtype, create=False)
            except KeyError:
                continue
        return None

    def ref_verdict(resp, status):
        signers = set()
        for sec in (resp.answer, resp.authority):
            for rrset in sec:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    for s in rrset:
                        signers.add(s.signer)
        if not signers:
            return "insecure" if status == "insecure" else "bogus"
        kk = {}
        for z, k in keys.items():
            if k is not None:
                kk[dns.name.from_text(z)] = k
        for sec in (resp.answer, resp.authority):
            for rrset in sec:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                sig = _ref_find_sig(resp, rrset)
                if sig is None:
                    return "bogus"
                try:
                    dns.dnssec.validate(rrset, sig, kk)
                except Exception:
                    return "bogus"
        return "secure"

    diff_ok = True
    for label, msg, qname, status in (
        ("正向 ietf.org", _clone(fwd), "ietf.org", "secure"),
        ("NX(NSEC)", _clone(nx_nsec), "nonexistent-aaa111.ietf.org", "secure"),
        ("NX(NSEC3)", _clone(nx_nsec3), "nonexistent-aaa111.com", "secure"),
    ):
        ref = ref_verdict(_clone(msg), status)
        eng = _make_engine(msg, keys, {qname: status}, pds)
        out = await run(eng, qname)
        proj = "bogus" if out is None else ("secure" if eng._stats.get("secure")
                                           else "insecure")
        same = (ref == "bogus") == (proj == "bogus")
        diff_ok = diff_ok and same
        print(f"    差分 {label:24s} ref={ref:8s} proj={proj:8s} "
              f"{'一致' if same else '分歧'}")
    check("15 独立参考判定差分一致", diff_ok)

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part B2：DNSSEC 链状态逐分支穷举（离线）
#
# 覆盖两类历史问题：
#   1. _zone_signed_status 的“链不可用 ≠ 可丢弃”：父区 DNSKEY 取不到时
#      旧代码返回 unknown（调用方按可丢弃），修复后返回 error（可用性放行）；
#   2. _get_trusted_dnskey 的重试/负缓存/single-flight/并发闸门：冷启动
#      根/TLD DNSKEY 被 RRL 限速时，退避重试后仍失败才放行，且 15s 内
#      不重复打爆同一权威。
# ============================================================

def _chain_resp(name, rcode=dns.rcode.NOERROR, authority=None):
    q = dns.message.make_query(name, dns.rdatatype.DS)
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    for rr in authority or []:
        r.authority.append(rr)
    return r


def _chain_soa(zone="cn."):
    return dns.rrset.from_text(
        zone, 300, "IN", "SOA",
        "a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400")


def _chain_nsec3(owner_label=None, flags=0,
                 bitmap="NS SOA RRSIG DNSKEY NSEC3PARAM"):
    if owner_label is None:
        owner_label = base64.b32hexencode(b"\x01" * 20).decode().lower()
    owner = dns.name.from_text(owner_label + ".cn.")
    nxt = base64.b32hexencode(b"\x02" * 20).decode().lower()
    rd = dns.rdata.from_text(
        "IN", "NSEC3", "1 %d 10 aef123ab %s %s" % (flags, nxt, bitmap))
    return dns.rrset.from_rdata(owner, 300, rd)


def _chain_rrsig_for(rrset, signer="cn."):
    sig = dns.rdata.from_text(
        "IN", "RRSIG",
        "NSEC3 8 3 300 20300101000000 20200101000000 12345 %s AAAA" % signer)
    return dns.rrset.from_rdata(rrset.name, 300, sig)


def _make_chain_resolver(ds_map, del_map, parent_insecure, trusted_keys, pds):
    """构造只跑 _zone_signed_status 的 resolver（全部依赖 mock）。"""
    r = object.__new__(pds.IterativeResolver)
    r._ds_cache = {}
    r._ds_inflight = {}
    r._delegation_cache = {}
    r._zone_ns_cache = {}
    r._verified_zone_cache = {}
    r._dnssec_crypto_ok = True
    r._chain_unavailable = set()

    async def _iterate_ds_cached(name):
        return ds_map.get(str(name).lower())

    async def _is_delegation(name):
        return del_map.get(str(name).lower())

    async def _parent_is_insecure(name):
        return parent_insecure.get(str(name).lower(), False)

    async def _get_trusted_dnskey(name):
        return trusted_keys.get(str(name).lower())

    async def _retry_ds_once(name):
        return ds_map.get(str(name).lower())

    r._iterate_ds_cached = _iterate_ds_cached
    r._is_delegation = _is_delegation
    r._parent_is_insecure = _parent_is_insecure
    r._get_trusted_dnskey = _get_trusted_dnskey
    r._retry_ds_once = _retry_ds_once
    return r


def _build_chain(target, mt_resp, pds, del_map=None,
                 parent_insecure=None, keys=None):
    """target 的 DS 为 NXDOMAIN，edge 为 NODATA 无 NSEC，mountaintoys.cn 为给定响应。"""
    name = dns.name.from_text(target)
    edge = "edge.mountaintoys.cn."
    mt = "mountaintoys.cn."
    ds_map = {
        str(name).lower(): _chain_resp(target, dns.rcode.NXDOMAIN),
        edge: _chain_resp(edge, dns.rcode.NOERROR, [_chain_soa()]),
        mt: mt_resp,
    }
    return _make_chain_resolver(
        ds_map, del_map or {}, parent_insecure or {}, keys or {}, pds)


def _make_trusted_resolver(pds, delays=(0.0, 0.0, 0.0)):
    """构造只跑 _get_trusted_dnskey 的 resolver（retry/负缓存/并发测试）。"""
    r = object.__new__(pds.IterativeResolver)
    r._dnssec_crypto_ok = True
    r._stats = collections.Counter()
    r._verified_zone_cache = {}
    r._dnskey_inflight = {}
    r._ds_cache = {}
    r._ds_inflight = {}
    r._dnskey_retry_after = {}
    r._dnskey_semaphore = None
    r._dnskey_retry_delays = delays
    r._chain_unavailable = set()
    return r


async def run_part_b_chain() -> bool:
    print("\n[Part B2] DNSSEC 链状态/重试逐分支穷举（离线）")
    try:
        import plain_dns_server as pds
    except Exception as e:      # pragma: no cover
        print(f"  跳过：无法导入 plain_dns_server（{e}）")
        return True

    start_ok = len(RESULTS)
    target = "v9e169o.edge.mountaintoys.cn"
    mt = dns.name.from_text("mountaintoys.cn.")
    del_map = {
        "v9e169o.edge.mountaintoys.cn.": False,
        "edge.mountaintoys.cn.": False,
        "mountaintoys.cn.": True,
    }

    # 1) parent_keys 取不到 + 父区未证明未签名 → error（修复前 unknown）
    edge_nsec3 = _chain_nsec3(flags=1)
    resp = _chain_resp("mountaintoys.cn", dns.rcode.NOERROR,
                       [_chain_soa(), edge_nsec3])
    r = _build_chain(target, resp, pds, del_map=del_map)
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.1 parent_keys=None + 父区 secure → error（链不可用，放行）",
          got == "error", f"got={got!r}")

    # 2) parent_keys 取不到 + 父区已证明未签名 → insecure（优先）
    r = _build_chain(target, resp, pds, del_map=del_map,
                     parent_insecure={"mountaintoys.cn.": True})
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.2 parent_keys=None + 父区 insecure → insecure",
          got == "insecure", f"got={got!r}")

    # 3) 精确 NSEC3 owner（is_apex=True）同样走 parent_keys=None → error
    h = pds.IterativeResolver._nsec3_hash(mt, b"\xae\xf1\x23\xab", 10, 1)
    label = base64.b32hexencode(h).decode().lower().rstrip("=")
    exact = _chain_nsec3(owner_label=label, flags=0,
                         bitmap="NS SOA RRSIG DNSKEY NSEC3PARAM")
    resp_exact = _chain_resp("mountaintoys.cn", dns.rcode.NOERROR,
                             [_chain_soa(), exact])
    r = _build_chain(target, resp_exact, pds, del_map=del_map)
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.3 精确 NSEC3 + parent_keys=None → error",
          got == "error", f"got={got!r}")

    # 4) parent_keys 可用但 NSEC3 验签失败 → unknown（保守，可能是伪造）
    fake_key = dns.rrset.RRset(dns.name.from_text("cn."), dns.rdataclass.IN,
                               dns.rdatatype.DNSKEY)
    resp_sig = _chain_resp("mountaintoys.cn", dns.rcode.NOERROR,
                           [_chain_soa(), edge_nsec3,
                            _chain_rrsig_for(edge_nsec3)])
    r = _build_chain(target, resp_sig, pds, del_map=del_map,
                     keys={"cn.": fake_key})
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.4 NSEC3 验签失败 + keys 可用 → unknown（保守）",
          got == "unknown", f"got={got!r}")

    # 5) NODATA 无 NSEC + is_del=True + 父区 secure → unknown（保持）
    resp_nodata = _chain_resp("mountaintoys.cn", dns.rcode.NOERROR,
                              [_chain_soa()])
    r = _build_chain(target, resp_nodata, pds, del_map=del_map)
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.5 NODATA 无 NSEC + 委托点 + 父区 secure → unknown",
          got == "unknown", f"got={got!r}")

    # 6) NODATA 无 NSEC + is_del=True + 父区 insecure → insecure（保持）
    r = _build_chain(target, resp_nodata, pds, del_map=del_map,
                     parent_insecure={"mountaintoys.cn.": True})
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.6 NODATA 无 NSEC + 委托点 + 父区 insecure → insecure",
          got == "insecure", f"got={got!r}")

    # 7) DS NXDOMAIN + is_del=True → unknown（名字不存在且是委托点）
    r = _build_chain(target, resp_nodata, pds, del_map={
        "v9e169o.edge.mountaintoys.cn.": True,
    })
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.7 DS NXDOMAIN + is_del=True → unknown",
          got == "unknown", f"got={got!r}")

    # 8) DS NXDOMAIN + is_del=False → 升父级，最终 insecure
    r = _build_chain(target, resp_nodata, pds, del_map=del_map,
                     parent_insecure={"mountaintoys.cn.": True})
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.8 DS NXDOMAIN + is_del=False 升父级 → insecure",
          got == "insecure", f"got={got!r}")

    # 13) DS NXDOMAIN + is_del=True + 父区已 insecure → insecure
    #     （实测 v9e169o.edge.mountaintoys.cn：_is_delegation 缓存命中为 True，
    #      父区 mountaintoys.cn 已未签名；旧代码在这里直接 unknown → 丢弃）
    r = _build_chain(target, resp_nodata, pds, del_map={
        "v9e169o.edge.mountaintoys.cn.": True,
    }, parent_insecure={"v9e169o.edge.mountaintoys.cn.": True})
    got = await r._zone_signed_status(dns.name.from_text(target))
    check("B2.13 DS NXDOMAIN + is_del=True + 父区 insecure → insecure",
          got == "insecure", f"got={got!r}")

    # 14) NS 查询：answer 里混入祖先区 NS（com.cn.）时，不能把它当最终答案
    #     旧实现只看 rdtype，会把 com.cn. NS 返回给 sso.sina.com.cn NS，
    #     上层 owner 校验再判“重放攻击”丢弃（实测每 60 秒两条 WARNING）。
    eng14 = object.__new__(pds.IterativeResolver)
    eng14.qname_minimization = False
    eng14.root_servers = ["192.0.2.1"]
    eng14.max_depth = 8
    eng14._zone_ns_cache = {}
    eng14._stats = collections.Counter()
    eng14._closest_zone_servers = lambda qname, qtype: None
    calls14 = []

    async def fake_ns(servers, qname, qtype, rdclass=1):
        calls14.append((qname, qtype))
        m = dns.message.make_response(
            dns.message.make_query(qname, qtype, rdclass))
        if len(calls14) == 1:
            # 祖先区 NS + 本名的 referral（模拟权威把 com.cn. NS 塞进 answer）
            m.answer.append(dns.rrset.from_text(
                "com.cn.", 300, "IN", "NS", "a.dns.cn."))
            m.authority.append(dns.rrset.from_text(
                "sso.sina.com.cn.", 300, "IN", "NS",
                "ns1.sso.sina.com.cn."))
            m.additional.append(dns.rrset.from_text(
                "ns1.sso.sina.com.cn.", 300, "IN", "A", "192.0.2.53"))
            return m
        m.answer.append(dns.rrset.from_text(
            f"{qname}.", 300, "IN", "NS", "ns1.sso.sina.com.cn."))
        return m

    eng14._query_servers = fake_ns
    out14 = await eng14._iterate("sso.sina.com.cn", dns.rdatatype.NS)
    owners14 = [str(rr.name).lower() for rr in (out14.answer if out14 else [])]
    check("B2.14 NS 查询不把祖先区 NS 当最终答案",
          out14 is not None
          and "sso.sina.com.cn." in owners14
          and "com.cn." not in owners14,
          f"owners={owners14} calls={len(calls14)}")

    # 15) CNAME 目标区未签名 + 无 NSEC NODATA → 放行（ocsp.pki.goog 回归）
    #     ocsp.pki.goog CNAME → pki-goog.l.google.com；pki.goog 有 DS，
    #     但 l.google.com / google.com 未签名，NODATA 本来就没有 NSEC。
    _f, _n1, _n2, cname_t, keys_t = _make_offline_fixtures(pds)

    async def run_chain(eng, qname, qtype=dns.rdatatype.A):
        return await eng._resolve_verified(qname, qtype, 1)

    eng15 = _make_engine(_clone(cname_t), keys_t,
                         {"pki-goog.l.google.com.": "insecure"}, pds)
    out15 = await run_chain(eng15, "c.pki.goog")
    check("B2.15 CNAME 目标区 insecure + 无 NSEC NODATA → 放行",
          out15 is not None,
          f"stats={ {k: v for k, v in dict(eng15._stats).items() if v} }")

    eng16 = _make_engine(_clone(cname_t), keys_t,
                         {"pki-goog.l.google.com.": "secure"}, pds)
    out16 = await run_chain(eng16, "c.pki.goog")
    check("B2.16 CNAME 目标区 secure + 无 NSEC NODATA → 拒绝", out16 is None,
          f"stats={ {k: v for k, v in dict(eng16._stats).items() if v} }")

    eng17 = _make_engine(_clone(cname_t), keys_t,
                         {"pki-goog.l.google.com.": "unknown"}, pds)
    out17 = await run_chain(eng17, "c.pki.goog")
    check("B2.17 CNAME 目标区 unknown + 无 NSEC NODATA → 拒绝", out17 is None,
          f"stats={ {k: v for k, v in dict(eng17._stats).items() if v} }")

    # 18) NSEC3 原语统一：plain 与 dnssec.py 对同一输入必须给出相同结果
    _name = dns.name.from_text("example.com.")
    _salt = b"\xaa"
    _h_plain = pds.IterativeResolver._nsec3_hash(_name, _salt, 10, 1)
    _h_dnssec = pds.DNSSECValidator._nsec3_hash(_name, _salt, 10, 1)
    check("B2.18 _nsec3_hash 单一实现（plain 与 dnssec 一致）",
          _h_plain == _h_dnssec and len(_h_plain) == 20,
          f"plain={_h_plain.hex()} dnssec={_h_dnssec.hex()}")

    # 19) NSEC3 owner-hash 解码一致
    _label = base64.b32hexencode(_h_dnssec).decode().lower().rstrip("=")
    _owner = dns.name.from_text(_label + ".com.")
    _owner_plain = pds.IterativeResolver._nsec3_owner_hash(_owner)
    _owner_dnssec = pds.DNSSECValidator._nsec3_owner_hash(_owner)
    check("B2.19 _nsec3_owner_hash 单一实现（plain 与 dnssec 一致）",
          _owner_plain == _owner_dnssec == _h_dnssec,
          f"plain={_owner_plain.hex()} dnssec={_owner_dnssec.hex()}")

    # 20) NSEC/NSEC3 类型位图解析一致
    _next = base64.b32hexencode(b"\x00" * 20).decode().lower().rstrip("=")
    _rd = dns.rdata.from_text("IN", "NSEC3",
                              "1 0 10 aa %s A RRSIG" % _next)
    _has_a = pds.IterativeResolver._nsec_has_type(_rd, dns.rdatatype.A)
    _has_ds = pds.IterativeResolver._nsec_has_type(_rd, dns.rdatatype.DS)
    _has_a_d = pds.DNSSECValidator._nsec_has_type(_rd, dns.rdatatype.A)
    check("B2.20 _nsec_has_type 单一实现（位图 A=True DS=False）",
          _has_a is True and _has_ds is False and _has_a == _has_a_d,
          f"A={_has_a} DS={_has_ds} dnssecA={_has_a_d}")

    # 21) NSEC3 区间自指保护：owner == next 不能覆盖任何 target
    _self = b"\x05" * 20
    check("B2.21 NSEC3 区间自指记录不覆盖任何 hash",
          pds.DNSSECValidator._hash_in_interval(
              b"\x06" * 20, _self, _self) is False
          and pds.IterativeResolver._nsec3_interval_check(
              b"\x06" * 20, _self, _self) is False)

    # 9) 链查询首次 RRL 失败、退避后重试成功 → 不应被当成不可用
    r = _make_trusted_resolver(pds)
    calls = {"n": 0}

    async def flaky(zone):
        calls["n"] += 1
        if calls["n"] < 2:
            raise pds._ChainUnavailable("simulated RRL")
        return "TRUSTED"

    r._get_trusted_dnskey_uncached = flaky
    out = await r._get_trusted_dnskey(dns.name.from_text("cn."))
    check("B2.9 链查询首次失败、退避重试后成功",
          out == "TRUSTED" and calls["n"] == 2,
          f"out={out!r} calls={calls['n']}")

    # 10) 连续失败 → None + 15s 负缓存，第二次不再打权威
    r = _make_trusted_resolver(pds)
    calls = {"n": 0}

    async def always_fail(zone):
        calls["n"] += 1
        raise pds._ChainUnavailable("simulated RRL")

    r._get_trusted_dnskey_uncached = always_fail
    out1 = await r._get_trusted_dnskey(dns.name.from_text("cn."))
    first_calls = calls["n"]
    out2 = await r._get_trusted_dnskey(dns.name.from_text("cn."))
    check("B2.10 连续失败 → None + 15s 负缓存（第二次不重查）",
          out1 is None and out2 is None
          and first_calls == 4 and calls["n"] == first_calls,
          f"out1={out1!r} out2={out2!r} calls={calls['n']} first={first_calls}")

    # 11) 同 zone 10 并发只构建一次链（single-flight）
    r = _make_trusted_resolver(pds)
    calls = {"n": 0}

    async def slow(zone):
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return "TRUSTED"

    r._get_trusted_dnskey_uncached = slow
    outs = await asyncio.gather(*[
        r._get_trusted_dnskey(dns.name.from_text("cn.")) for _ in range(10)
    ])
    check("B2.11 同 zone 10 并发只构建一次链（single-flight）",
          calls["n"] == 1 and all(o == "TRUSTED" for o in outs),
          f"calls={calls['n']}")

    # 12) 不同 zone 并发受 semaphore=4 限制（不把根/TLD 一次打爆）
    r = _make_trusted_resolver(pds)
    r._dnskey_semaphore = asyncio.Semaphore(4)
    active = {"now": 0, "peak": 0}

    async def tracked(zone):
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
        await asyncio.sleep(0.02)
        active["now"] -= 1
        return "TRUSTED"

    r._get_trusted_dnskey_uncached = tracked
    await asyncio.gather(*[
        r._get_trusted_dnskey(dns.name.from_text("z%d.example." % i))
        for i in range(12)
    ])
    check("B2.12 不同 zone 并发被 semaphore 限制在 4",
          active["peak"] <= 4, f"peak={active['peak']}")

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part B3：域名类型矩阵穷举（离线）
#
# 目标：用同一套 mock 迭代链，覆盖 gTLD / ccTLD / 中国二级 / 中文域名 /
# new gTLD / geoTLD / 其他（根、单标签、arpa、SRV、通配、大小写、尾点、
# 超长标签），确保：
#   1. 正常查询返回 owner==qname 的目标类型，不被祖先区 NS 干扰；
#   2. answer 混入祖先 NS（com.cn. NS 场景）时继续下钻，不判“重放”；
#   3. CNAME + NODATA（sso.sina.com.cn 场景）返回 owner 正确的 CNAME；
#   4. 大小写/尾点/IDN 按 DNS 语义等价，不误判 owner 不匹配。
# ============================================================

_DOMAIN_TYPE_MATRIX = {
    "gTLD": ["example.com", "example.net", "example.org",
             "example.info", "example.biz"],
    "ccTLD": ["example.cn", "example.uk", "example.de",
              "example.jp", "example.ru"],
    "中国二级": ["example.com.cn", "example.net.cn", "example.org.cn",
                 "example.gov.cn", "example.edu.cn"],
    "中文域名": ["例子.中国", "例子.公司", "例子.网络",
                 "xn--fsqu00a.xn--fiqs8s", "xn--fsqu00a.xn--55qx5d"],
    "new gTLD": ["example.app", "example.dev", "example.xyz",
                 "example.top", "example.shop"],
    "geoTLD": ["example.nyc", "example.london", "example.berlin",
               "example.tokyo", "example.asia"],
    "其他": [".", "localhost", "1.0.0.127.in-addr.arpa",
             "_sip._tcp.example.com", "*.example.com",
             "ExAmPlE.CoM", "example.com.", "a" * 63 + ".com"],
}


def _type_qtype(name):
    if name == ".":
        return dns.rdatatype.NS
    if name.endswith(".in-addr.arpa"):
        return dns.rdatatype.PTR
    if name.startswith("_sip."):
        return dns.rdatatype.SRV
    return dns.rdatatype.A


def _type_answer_value(qtype, qname):
    name = dns.name.from_text(qname)
    if qtype == dns.rdatatype.A:
        return "192.0.2.10"
    if qtype == dns.rdatatype.AAAA:
        return "2001:db8::1"
    if qtype == dns.rdatatype.NS:
        return str(dns.name.from_text("ns1", None) + name)
    if qtype == dns.rdatatype.PTR:
        return "host.example."
    if qtype == dns.rdatatype.SRV:
        return "0 5 5060 sip.example.com."
    return '"v=spf1 -all"'


def _type_referral(msg, zone, glue_ip):
    zone = dns.name.from_text(zone) if isinstance(zone, str) else zone
    ns = dns.name.from_text("ns1", None) + zone
    msg.authority.append(dns.rrset.from_text(
        str(zone), 300, "IN", "NS", str(ns)))
    msg.additional.append(dns.rrset.from_text(
        str(ns), 300, "IN", "A", glue_ip))


def _make_type_engine(pds, mode):
    """构造只跑 _iterate 的 resolver；responder 按当前跳伪造完整迭代链。"""
    eng = object.__new__(pds.IterativeResolver)
    eng.qname_minimization = False
    eng.root_servers = ["192.0.2.1"]
    eng.max_depth = 12
    eng._zone_ns_cache = {}
    eng._ns_ip_cache = {}
    eng._stats = collections.Counter()
    eng._closest_zone_servers = lambda qname, qtype: None

    async def responder(servers, qname, qtype, rdclass=1):
        q = dns.message.make_query(qname, qtype, rdclass)
        msg = dns.message.make_response(q)
        name = dns.name.from_text(qname)
        labels = [l.decode("ascii") for l in name.labels if l]
        ip = servers[0]

        if name == dns.name.root:
            msg.answer.append(dns.rrset.from_text(
                ".", 300, "IN", "NS", "a.root-servers.net."))
            return msg

        if ip == "192.0.2.1":
            if len(labels) <= 1:
                msg.answer.append(dns.rrset.from_text(
                    str(name), 300, "IN", dns.rdatatype.to_text(qtype),
                    _type_answer_value(qtype, qname)))
                return msg
            tld = dns.name.from_text(labels[-1])
            _type_referral(msg, tld, "192.0.2.2")
            if mode == "ancestor_ns":
                msg.answer.append(dns.rrset.from_text(
                    str(tld), 300, "IN", "NS", "ns1." + labels[-1]))
            return msg

        if ip == "192.0.2.2":
            if len(labels) <= 2:
                _type_referral(msg, name, "192.0.2.3")
            else:
                _type_referral(msg, name.parent(), "192.0.2.3")
            return msg

        if ip == "192.0.2.3":
            _type_referral(msg, name, "192.0.2.4")
            if mode == "ancestor_ns":
                tld = dns.name.from_text(labels[-1])
                msg.answer.append(dns.rrset.from_text(
                    str(tld), 300, "IN", "NS", "ns1." + labels[-1]))
            return msg

        if mode == "cname_nodata":
            target = dns.name.from_text("target", None) + name
            msg.answer.append(dns.rrset.from_text(
                str(name), 300, "IN", "CNAME", str(target)))
            parent = name.parent()
            msg.authority.append(dns.rrset.from_text(
                str(parent), 300, "IN", "SOA",
                "ns1.%s hostmaster.%s 1 3600 600 86400 300"
                % (str(parent).rstrip("."), str(parent).rstrip("."))))
            return msg

        msg.answer.append(dns.rrset.from_text(
            str(name), 300, "IN", dns.rdatatype.to_text(qtype),
            _type_answer_value(qtype, qname)))
        return msg

    eng._query_servers = responder
    return eng


async def run_part_b_types() -> bool:
    print("\n[Part B3] 域名类型矩阵穷举"
          "（gTLD/ccTLD/中国二级/中文/new gTLD/geoTLD/其他）")
    try:
        import plain_dns_server as pds
    except Exception as e:      # pragma: no cover
        print(f"  跳过：无法导入 plain_dns_server（{e}）")
        return True

    start_ok = len(RESULTS)

    # 1) 正常查询：每类所有样本都必须返回 owner==qname 的目标类型
    for category, domains in _DOMAIN_TYPE_MATRIX.items():
        bad = []
        for domain in domains:
            qtype = _type_qtype(domain)
            eng = _make_type_engine(pds, "normal")
            out = await eng._iterate(domain, qtype)
            owner = dns.name.from_text(domain)
            if out is None or not any(
                    rr.rdtype == qtype and rr.name == owner
                    for rr in out.answer):
                bad.append(domain)
        check(f"B3.1 {category} 正常查询 owner/类型正确"
              f"（{len(domains)} 个）", not bad, f"bad={bad}")

    # 2) 祖先区 NS 混入 answer：每类代表域名不能把祖先 NS 当最终答案
    for category, domains in _DOMAIN_TYPE_MATRIX.items():
        domain = next((d for d in domains
                       if d not in (".", "localhost")), domains[0])
        qtype = _type_qtype(domain)
        eng = _make_type_engine(pds, "ancestor_ns")
        out = await eng._iterate(domain, qtype)
        owner = dns.name.from_text(domain)
        bad = []
        if out is None:
            bad.append("out=None")
        else:
            if not any(rr.rdtype == qtype and rr.name == owner
                       for rr in out.answer):
                bad.append("missing owner")
            labels = [l.decode("ascii") for l in owner.labels if l]
            if len(labels) >= 2:
                tld = dns.name.from_text(labels[-1])
                if any(rr.rdtype == dns.rdatatype.NS and rr.name == tld
                       for rr in out.answer):
                    bad.append("ancestor NS leaked")
        check(f"B3.2 {category} 祖先区 NS 混入不误判（{domain}）",
              not bad, f"bad={bad}")

    # 3) CNAME + NODATA（sso.sina.com.cn 场景）：每类代表域名返回 CNAME
    for category, domains in _DOMAIN_TYPE_MATRIX.items():
        domain = next((d for d in domains
                       if d not in (".", "localhost")), domains[0])
        eng = _make_type_engine(pds, "cname_nodata")
        out = await eng._iterate(domain, dns.rdatatype.A)
        owner = dns.name.from_text(domain)
        ok = (out is not None
              and any(rr.rdtype == dns.rdatatype.CNAME and rr.name == owner
                      for rr in out.answer))
        types = [dns.rdatatype.to_text(r.rdtype)
                 for r in (out.answer if out else [])]
        check(f"B3.3 {category} CNAME+NODATA 返回 owner 正确的 CNAME"
              f"（{domain}）", ok, f"answer={types}")

    # 4) 大小写/尾点/IDN 等价性：owner 比较必须按 DNS 语义（大小写不敏感）
    equiv = [
        ("ExAmPlE.CoM", "example.com"),
        ("example.com.", "example.com"),
        ("例子.中国", "xn--fsqu00a.xn--fiqs8s"),
        ("XN--FSQU00A.XN--FIQS8S", "例子.中国"),
    ]
    bad = []
    for qname, canonical in equiv:
        eng = _make_type_engine(pds, "normal")
        out = await eng._iterate(qname, dns.rdatatype.A)
        canonical_name = dns.name.from_text(canonical)
        if out is None or not any(
                rr.rdtype == dns.rdatatype.A and rr.name == canonical_name
                for rr in out.answer):
            bad.append(qname)
    check("B3.4 大小写/尾点/IDN 等价 owner 不误判", not bad,
          f"bad={bad}")

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part C：真实网络端到端 DNSSEC 回归（--real-dnssec）
# ============================================================
async def run_part_c() -> bool:
    print("\n[Part C] 真实网络 DNSSEC 回归（日志误报域名 + 签名区 + bogus）")
    try:
        import plain_dns_server as pds
        from config import Config
    except Exception as e:      # pragma: no cover
        print(f"  跳过：无法导入解析器（{e}）")
        return True

    pds.has_global_ipv6 = lambda: False
    pds.probe_ipv6_path = lambda: (False, True)
    cfg = Config(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "config.yaml"))
    eng = pds.IterativeResolver(cfg)

    class _Cap(logging.Handler):
        def __init__(self):
            super().__init__()
            self.msgs = []

        def emit(self, record):
            self.msgs.append(record.getMessage())

    cap = _Cap()
    lg = logging.getLogger("dns-proxy.plain-dns")
    lg.addHandler(cap)
    lg.setLevel(logging.WARNING)
    start_ok = len(RESULTS)

    # 日志中“应通过却被拦截”的未签名域名
    for domain in ("cdn.jsdelivr.net", "s.360.cn",
                   "opencdnkav6.jomodns.com", "p.ssl.qhimg.com"):
        try:
            st = await asyncio.wait_for(
                eng._zone_signed_status(dns.name.from_text(domain)), timeout=30)
        except Exception as e:
            st = f"EXC:{type(e).__name__}"
        check(f"C1 {domain} 区域状态不是 secure", st != "secure",
              f"status={st}")
        cap.msgs.clear()
        try:
            resp = await asyncio.wait_for(
                eng.resolve(domain, dns.rdatatype.A), timeout=40)
        except Exception as e:
            resp = None
            print(f"     resolve 异常: {e!r}")
        check(f"C2 {domain} 能解析（未被误拦）", resp is not None)
        cname_warn = [m for m in cap.msgs
                      if "CNAME 链中间跳无签名" in m]
        check(f"C3 {domain} 无 CNAME 中间跳误报告警", not cname_warn,
              f"warnings={len(cname_warn)}")

    # 真签名区不能被误伤
    cap.msgs.clear()
    eng._last_release = ""
    try:
        st = await asyncio.wait_for(
            eng._zone_signed_status(dns.name.from_text("ietf.org")), timeout=30)
        resp = await asyncio.wait_for(
            eng.resolve("ietf.org", dns.rdatatype.A), timeout=40)
    except Exception as e:
        st, resp = f"EXC:{type(e).__name__}", None
    check("C4 ietf.org 仍为 secure", st == "secure", f"status={st}")
    has_sig = bool(resp is not None and any(
        rr.rdtype == dns.rdatatype.RRSIG for rr in resp.answer))
    boot = bool(getattr(resp, "_bootstrap_fallback", False))
    # 本测试强制 IPv4-only（pds.has_global_ipv6=lambda: False）：在境内镜像
    # 链路上，签名区也可能拿不到任何 DNSSEC 记录——此时程序按
    # require_rrsig=false 的语义「未验证放行」并标注原因（dnssec_absent /
    # hijacked_path）。因此这里接受三种合法结果：带 RRSIG / bootstrap 兜底 /
    # 明确走了降级放行；关键是**不能**在没有任何说明的情况下把它当成已验证。
    release = getattr(eng, "_last_release", "")
    degraded = release in ("dnssec_absent", "hijacked_path", "bootstrap",
                           "chain_unavailable")
    check("C5 ietf.org 应答带 RRSIG（或明确走 bootstrap/降级放行）",
          has_sig or boot or degraded,
          f"rrsig={has_sig} bootstrap={boot} release={release!r}")

    # 真实 bogus 仍必须被拒绝
    try:
        out = await asyncio.wait_for(
            eng._resolve_verified("dnssec-failed.org", dns.rdatatype.A, 1),
            timeout=40)
    except Exception:
        out = None
    check("C6 dnssec-failed.org 仍被严格模式丢弃", out is None)

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part D/E：合成权威树（离线、确定性）——「能做 DNSSEC 验证」与
#            「链路完全不提供 DNSSEC」两类链路的逐分支穷举
#
# 复用上面 Part B 已有的密钥/签名工具（_new_dnssec_key / _zone_keyset /
# _sign_rrset / check），这里只补合成世界本身需要的材料。
# ============================================================
_HERE = os.path.dirname(os.path.abspath(__file__))
_ALG = 8            # RSASHA256（与 _new_dnssec_key 一致）
_TTL = 300

#   .                       根区（签名，NSEC）
#   └── test.               签名，NSEC
#       ├── secure.test.    签名（NSEC）      → www.secure.test. A（有签名）
#       ├── insecure.test.  未签名（无 DS）   → www.insecure.test. A（无签名）
#       └── opt.test.       签名，NSEC3 opt-out
#           ├── secure.opt.test.    签名（NSEC3）→ www.secure.opt.test. A
#           └── unsigned.opt.test.  未签名（opt-out 覆盖证明）
#                                     → www.unsigned.opt.test. A
_ZONES = [
    # zone,                 ip,          signed, nsec3, children
    (".",                   "10.0.0.1",  True,  False, ["test."]),
    ("test.",               "10.0.0.2",  True,  False,
     ["secure.test.", "insecure.test.", "opt.test."]),
    ("secure.test.",        "10.0.0.3",  True,  False, []),
    ("insecure.test.",      "10.0.0.4",  False, False, []),
    ("opt.test.",           "10.0.0.5",  True,  True,
     ["secure.opt.test.", "unsigned.opt.test."]),
    ("secure.opt.test.",    "10.0.0.6",  True,  True, []),
    ("unsigned.opt.test.",  "10.0.0.7",  False, False, []),
]

_ROOT_SOA = "a.root-servers.net. hostmaster.root. 1 3600 600 86400 300"

# 每个 zone 的区内记录：{zone: {name: {rdtype_text: [values]}}}
_RECORDS = {
    "test.": {
        "www.test.": {"A": ["10.0.0.11"]},
    },
    "secure.test.": {
        "www.secure.test.": {"A": ["10.0.0.21"]},
        "txt.secure.test.": {"TXT": ["\"hello\""]},
    },
    "insecure.test.": {
        "www.insecure.test.": {"A": ["10.0.0.31"]},
    },
    "opt.test.": {
        "www.opt.test.": {"A": ["10.0.0.41"]},
    },
    "secure.opt.test.": {
        "www.secure.opt.test.": {"A": ["10.0.0.51"]},
    },
    "unsigned.opt.test.": {
        "www.unsigned.opt.test.": {"A": ["10.0.0.61"]},
    },
}

# 传输/应答形态（模拟不同链路与攻击）
_MODE_FULL = "full"                     # 完整 DNSSEC 记录（能做验证）
_MODE_ABSENT = "absent"                 # 链路完全不提供 DNSSEC：根 DNSKEY → NXDOMAIN
_MODE_ABSENT_NOROOT = "absent_noroot"   # 根 DNSKEY → NODATA（应答里没有 DNSKEY）
_MODE_ROOT_BAD_SIG = "root_bad_sig"     # 根 DNSKEY 的 RRSIG 由野钥匙签（真 bogus）
_MODE_STRIP_ANSWER = "strip_answer"     # 只剥掉最终 A 的 RRSIG（剥离攻击）
_MODE_TAMPER_ANSWER = "tamper_answer"   # A 记录被改写（签名失效）
_MODE_NO_PROOF = "no_proof"             # DS NODATA 缺 NSEC3 否定证明（攻击信号）


def _sign_now(rrset, priv, key, signer: str):
    """用当前时间现签一个 RRset（复用 Part B 的 _sign_rrset，签名永不过期）"""
    return _sign_rrset(rrset, priv, key, signer, int(time.time()))


def _ds_text(zone: str, key) -> str:
    owner_wire = dns.name.from_text(zone).to_wire(canonicalize=True)
    digest = hashlib.sha256(owner_wire + key.to_wire()).hexdigest().upper()
    return "%d %d 2 %s" % (dns.dnssec.key_id(key), _ALG, digest)


def _b32hex(data: bytes) -> str:
    """RFC 4648 §7 base32hex（NSEC3 owner / next 的文本形式）"""
    return base64.b32hexencode(data).decode("ascii").lower()


def _rr(name: str, rdtype: str, *values, ttl: int = _TTL):
    return dns.rrset.from_text(name, ttl, "IN", rdtype, *values)


def _cover_pair(target: dns.name.Name):
    """构造一对 (owner, next) 使 owner < target < next（canonical 序）

    用于 NSEC 的 NXDOMAIN 区间覆盖证明。
    """
    parent = str(target.parent())
    if parent == ".":
        parent = ""
    cands = ["a", "b", "m", "n", "z", "zz", "0", "9"]
    names = [dns.name.from_text(c + "." + parent) for c in cands]
    for lo in names:
        for hi in names:
            if lo == hi:
                continue
            try:
                if lo < target < hi:
                    return lo, hi
            except Exception:
                continue
    return names[0], names[-1]


def _soa_text(zone: str) -> str:
    if zone in (".", ""):
        return _ROOT_SOA
    base = zone.rstrip(".")
    return "ns1.%s hostmaster.%s 1 3600 600 86400 300" % (base, base)


class World:
    """合成权威树 + 可注入的传输/应答形态"""

    def __init__(self, mode: str = _MODE_FULL):
        self.mode = mode
        self.priv = {}
        self.key = {}
        self.signed = set()
        self.nsec3 = set()
        self.ip2zone = {}
        self.children = collections.defaultdict(list)
        self.queries = collections.Counter()
        self._build_keys()
        self.rogue_priv, self.rogue_key = _new_dnssec_key()

    # ---------- 构建 ----------
    def _build_keys(self):
        for zone, ip, signed, nsec3, children in _ZONES:
            self.ip2zone[ip] = zone
            self.children[zone] = list(children)
            if signed:
                self.signed.add(zone)
                self.priv[zone], self.key[zone] = _new_dnssec_key()
            if nsec3:
                self.nsec3.add(zone)

    def build_anchor(self):
        """返回 `_dnssec._root_keys` 结构：{root: {alg: [DNSKEY rdata]}}"""
        return {dns.name.root: {_ALG: [self.key["."]]}}

    def child_containing(self, zone: str, name: dns.name.Name):
        """zone 下、包含 name 的最深直接子区（= 本次查询会命中的 referral 目标）"""
        best = None
        for child in self.children.get(zone, []):
            c = dns.name.from_text(child)
            if name.is_subdomain(c):
                if best is None or len(c.labels) > len(best.labels):
                    best = c
        return None if best is None else str(best)

    # ---------- 基础追加 ----------
    @staticmethod
    def _soa(msg, zone: str):
        if zone == ".":
            msg.authority.append(_rr(".", "SOA", _ROOT_SOA))
            return
        msg.authority.append(_rr(
            zone, "SOA",
            "ns1.%s hostmaster.%s 1 3600 600 86400 300"
            % (zone.rstrip("."), zone.rstrip("."))))

    def _add(self, msg, section: str, rrset, zone: str, signed: bool = True):
        """把 rrset 追加到 section，必要时附上 zone 的 RRSIG"""
        target = getattr(msg, section)
        target.append(rrset)
        if signed and zone in self.signed and rrset.rdtype != dns.rdatatype.RRSIG:
            target.append(_sign_now(
                rrset, self.priv[zone], self.key[zone], zone))

    def _referral(self, msg, zone: str, child: str):
        ns_name = "ns1." + child
        msg.authority.append(_rr(child, "NS", ns_name))
        msg.additional.append(_rr(ns_name, "A", self.ip_of(child)))

    @staticmethod
    def ip_of(zone: str) -> str:
        for z, ip, _s, _n, _c in _ZONES:
            if z == zone:
                return ip
        return "10.0.0.1"

    # ---------- 各类型应答 ----------
    def _answer_dnskey(self, msg, zone: str):
        if zone not in self.signed:
            self._soa(msg, zone)          # 未签名区：NODATA
            return
        ks = _zone_keyset(zone, self.key[zone])
        msg.answer.append(ks)
        signer_key = self.key[zone]
        signer_priv = self.priv[zone]
        if self.mode == _MODE_ROOT_BAD_SIG and zone == ".":
            # 野钥匙签：RRSIG 的 key tag 在 DNSKEY 集合里找不到 → 验签失败
            signer_key = self.rogue_key
            signer_priv = self.rogue_priv
        msg.answer.append(_sign_now(ks, signer_priv, signer_key, zone))

    def _answer_ds(self, msg, parent: str, child: str):
        """父区回答子区 DS：签名子区 → DS + RRSIG；未签名子区 → 否定证明"""
        if child in self.signed:
            d = _rr(child, "DS", _ds_text(child, self.key[child]))
            self._add(msg, "answer", d, parent)
            return
        self._soa(msg, parent)
        if self.mode == _MODE_NO_PROOF and child == "unsigned.opt.test.":
            return                        # 故意不给否定证明（攻击信号）
        if parent in self.nsec3:
            # RFC 5155 §8.6：opt-out 区间覆盖证明（位图描述 owner，不含 DS）
            target = pds.IterativeResolver._nsec3_hash(
                dns.name.from_text(child), b"\xaa\xbb", 0, 1)
            lo = (int.from_bytes(target, "big") - 1).to_bytes(20, "big")
            hi = (int.from_bytes(target, "big") + 1).to_bytes(20, "big")
            n3 = _rr("%s.%s" % (_b32hex(lo), parent.rstrip(".")), "NSEC3",
                     "1 1 0 aabb %s NS RRSIG" % _b32hex(hi))
            self._add(msg, "authority", n3, parent)
        else:
            # NSEC：owner == 子区名，位图含 NS、不含 DS（未签名委托点）
            _lo, hi = _cover_pair(dns.name.from_text(child))
            nsec = _rr(child, "NSEC", "%s NS RRSIG NSEC" % hi)
            self._add(msg, "authority", nsec, parent)

    def _nodata(self, msg, zone: str, name: dns.name.Name, qtype: int):
        self._soa(msg, zone)
        if zone not in self.signed:
            return
        if zone in self.nsec3:
            h = pds.IterativeResolver._nsec3_hash(name, b"\xaa\xbb", 0, 1)
            hi = (int.from_bytes(h, "big") + 1).to_bytes(20, "big")
            n3 = _rr("%s.%s" % (_b32hex(h), zone.rstrip(".")), "NSEC3",
                     "1 0 0 aabb %s RRSIG NSEC3" % _b32hex(hi))
            self._add(msg, "authority", n3, zone)
        else:
            _lo, hi = _cover_pair(name)
            nsec = _rr(str(name), "NSEC", "%s A RRSIG NSEC" % hi)
            self._add(msg, "authority", nsec, zone)

    def _answer_name(self, msg, zone: str, name: dns.name.Name, qtype: int):
        rdtype_txt = dns.rdatatype.to_text(qtype)
        recs = _RECORDS.get(zone, {}).get(str(name), {})
        if rdtype_txt in recs:
            rs = _rr(str(name), rdtype_txt, *recs[rdtype_txt])
            self._add(msg, "answer", rs, zone)
            return
        if "CNAME" in recs:
            rs = _rr(str(name), "CNAME", *recs["CNAME"])
            self._add(msg, "answer", rs, zone)
            return
        if recs:
            # 名字存在但没有该类型 → NODATA（RFC 4035 §5.2 需要 NSEC 证明）
            self._soa(msg, zone)
            if zone in self.signed:
                if zone in self.nsec3:
                    h = pds.IterativeResolver._nsec3_hash(name, b"\xaa\xbb", 0, 1)
                    hi = (int.from_bytes(h, "big") + 1).to_bytes(20, "big")
                    bitmap = " ".join(sorted(recs.keys()) + ["RRSIG"])
                    n3 = _rr("%s.%s" % (_b32hex(h), zone.rstrip(".")), "NSEC3",
                             "1 0 0 aabb %s %s" % (_b32hex(hi), bitmap))
                    self._add(msg, "authority", n3, zone)
                else:
                    _lo, hi = _cover_pair(name)
                    bitmap = " ".join(sorted(recs.keys()) + ["RRSIG", "NSEC"])
                    nsec = _rr(str(name), "NSEC", "%s %s" % (hi, bitmap))
                    self._add(msg, "authority", nsec, zone)
            return
        # 名字不存在 → NXDOMAIN
        msg.set_rcode(dns.rcode.NXDOMAIN)
        self._soa(msg, zone)
        if zone in self.signed and zone not in self.nsec3:
            lo, hi = _cover_pair(name)
            nsec = _rr(str(lo), "NSEC", "%s RRSIG NSEC" % hi)
            self._add(msg, "authority", nsec, zone)

    # ---------- 主入口 ----------
    def answer(self, ip: str, qname: str, qtype: int, rdclass: int = 1):
        self.queries[(qname, dns.rdatatype.to_text(qtype))] += 1
        zone = self.ip2zone.get(ip, ".")
        q = dns.name.from_text(qname)
        msg = dns.message.make_response(
            dns.message.make_query(qname, qtype, rdclass))
        # 真实权威会回声 EDNS/DO（否则"是否真权威"的诊断会把它们误判成代答）
        msg.use_edns(0, dns.flags.DO, payload=1232)
        # 直接 append 到 sections 的 RRset 不会写进 Message.index，而
        # `_find_rrsig_for()` 走的是 `msg.find_rrset()`（优先查 index）。
        # 真实上游应答是 wire 解析出来的，这里把 index 关掉让查找退化为扫描
        # sections，行为与真实报文一致。
        msg.index = None

        # (0) 「链路不提供 DNSSEC」的根 DNSKEY 形态
        if q == dns.name.root and qtype == dns.rdatatype.DNSKEY:
            if self.mode == _MODE_ABSENT:
                msg.set_rcode(dns.rcode.NXDOMAIN)
                self._soa(msg, ".")
                msg.flags |= dns.flags.AA
                return msg
            if self.mode == _MODE_ABSENT_NOROOT:
                self._soa(msg, ".")
                msg.flags |= dns.flags.AA
                return msg

        child = self.child_containing(zone, q)
        if child is not None:
            if qtype == dns.rdatatype.DS and str(q) == child:
                self._answer_ds(msg, zone, child)
            else:
                self._referral(msg, zone, child)     # referral 不带 AA
                return self._finalize(msg, qname, qtype)
            msg.flags |= dns.flags.AA
            return self._finalize(msg, qname, qtype)

        if str(q) == zone:
            if qtype == dns.rdatatype.DNSKEY:
                self._answer_dnskey(msg, zone)
            elif qtype == dns.rdatatype.NS:
                ns_name = "ns1." + ("" if zone == "." else zone)
                self._add(msg, "answer", _rr(zone, "NS", ns_name), zone,
                          signed=False)
            else:
                self._nodata(msg, zone, q, qtype)
            if zone in self.signed:
                msg.flags |= dns.flags.AA
            return self._finalize(msg, qname, qtype)

        if qtype == dns.rdatatype.DS:
            # 区内普通名（非委托点）的 DS：父区语义上就是"无 DS"
            self._nodata(msg, zone, q, qtype)
            if zone in self.signed:
                msg.flags |= dns.flags.AA
            return self._finalize(msg, qname, qtype)

        self._answer_name(msg, zone, q, qtype)
        if zone in self.signed:
            msg.flags |= dns.flags.AA
        return self._finalize(msg, qname, qtype)

    # ---------- 形态后处理 ----------
    def _finalize(self, msg, qname: str, qtype: int):
        if self.mode in (_MODE_ABSENT, _MODE_ABSENT_NOROOT):
            self._strip_dnssec(msg)
            # 连 EDNS 一起退化（实测中间盒形态：没有 OPT、payload=512）
            msg.use_edns(0, 0, payload=512)
            return msg
        if self.mode == _MODE_STRIP_ANSWER:
            # 只剥最终答案（A/TXT）的 RRSIG，其它 DNSSEC 记录保持完好
            self._drop(msg, dns.rdatatype.RRSIG,
                       covers=(dns.rdatatype.A, dns.rdatatype.TXT))
        elif self.mode == _MODE_TAMPER_ANSWER:
            for i, rs in enumerate(msg.answer):
                if rs.rdtype in (dns.rdatatype.A, dns.rdatatype.TXT):
                    if rs.rdtype == dns.rdatatype.A:
                        new = _rr(str(rs.name), "A", "203.0.113.66", ttl=rs.ttl)
                    else:
                        new = _rr(str(rs.name), "TXT", "\"tampered\"", ttl=rs.ttl)
                    msg.answer[i] = new
        return msg

    @staticmethod
    def _strip_dnssec(msg):
        drop = (dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                dns.rdatatype.NSEC3, dns.rdatatype.DNSKEY,
                dns.rdatatype.NSEC3PARAM)
        for attr in ("answer", "authority", "additional"):
            setattr(msg, attr, [rs for rs in getattr(msg, attr)
                                if rs.rdtype not in drop])

    @staticmethod
    def _drop(msg, rdtype: int, covers=()):
        for attr in ("answer", "authority", "additional"):
            kept = []
            for rs in getattr(msg, attr):
                if rs.rdtype == rdtype and (
                        not covers or getattr(rs, "covers", None) in covers):
                    continue
                kept.append(rs)
            setattr(msg, attr, kept)


class AbsentWorld:
    """模拟实测中间盒：任何应答都不携带 DNSSEC 记录（本次真实故障形态）

    与在故障机器上实测到的行为一致：
      * 向**任意**目的 IP 发查询都能拿到"递归式"应答；
      * 应答里没有 RRSIG / NSEC / NSEC3 / DNSKEY；
      * 根区 `. DNSKEY` 直接被回成 NXDOMAIN（或 NODATA，无 DNSKEY）；
      * DS 查询回 NODATA，authority 里只有 SOA，没有任何否定证明；
      * A 查询回真实 A，但没有签名。

    因此它能让「链路完全不提供 DNSSEC」这一分支用**真实域名**跑完整链路。
    """

    def __init__(self, root_dnskey: str = "nxdomain"):
        self.root_dnskey = root_dnskey        # "nxdomain" / "nodata"
        self.queries = collections.Counter()
        self._anchor = _new_dnssec_key()[1]

    def build_anchor(self):
        return {dns.name.root: {_ALG: [self._anchor]}}

    def answer(self, ip: str, qname: str, qtype: int, rdclass: int = 1):
        self.queries[(qname, dns.rdatatype.to_text(qtype))] += 1
        q = dns.name.from_text(qname)
        msg = dns.message.make_response(
            dns.message.make_query(qname, qtype, rdclass))
        msg.index = None
        # 根 DNSKEY：中间盒的确定形态
        if q == dns.name.root and qtype == dns.rdatatype.DNSKEY:
            if self.root_dnskey == "nxdomain":
                msg.set_rcode(dns.rcode.NXDOMAIN)
            msg.authority.append(_rr(".", "SOA", _ROOT_SOA))
            return msg
        if qtype == dns.rdatatype.DNSKEY:
            msg.authority.append(_rr(str(q), "SOA", _soa_text(str(q))))
            return msg
        if qtype == dns.rdatatype.DS:
            # DS 的 NODATA：只有 SOA，没有 NSEC/NSEC3（实测就是这样）
            msg.authority.append(
                _rr(str(q.parent()), "SOA", _soa_text(str(q.parent()))))
            return msg
        if qtype == dns.rdatatype.NS:
            # 让 QNAME 最小化能继续下钻：返回同名 referral + glue
            ns = "ns1." + qname.rstrip(".")
            msg.authority.append(_rr(str(q), "NS", ns))
            msg.additional.append(_rr(ns, "A", "10.9.9.9"))
            return msg
        if qname.startswith("nx-"):
            msg.set_rcode(dns.rcode.NXDOMAIN)
            msg.authority.append(
                _rr(str(q.parent()), "SOA", _soa_text(str(q.parent()))))
            return msg
        if qtype == dns.rdatatype.A:
            msg.answer.append(_rr(str(q), "A", "203.0.113.9"))
            return msg
        # 其它类型（AAAA/TXT...）→ NODATA
        msg.authority.append(
            _rr(str(q.parent()), "SOA", _soa_text(str(q.parent()))))
        return msg


# ---------- 引擎装配（真实代码路径，只替换「网络」与信任锚） ----------
def _world_engine(world, require_rrsig: bool = False, crypto_ok: bool = True):
    eng = object.__new__(pds.IterativeResolver)
    eng.config = types.SimpleNamespace(bootstrap_resolvers=[])
    eng.strict_dnssec = True
    eng.total_timeout = 20.0
    eng.max_depth = 12
    eng.hop_parallel = 1
    eng.qname_minimization = True
    eng.root_servers = ["10.0.0.1"]
    eng.timeout = 1.0
    eng._stats = collections.Counter()
    eng._last_release = ""
    # DNSSEC 判定状态
    eng._require_rrsig = require_rrsig
    eng._dnssec_crypto_ok = crypto_ok
    eng._dnssec_evidence = "unknown"
    eng._dnssec_evidence_detail = ""
    eng._dnssec_avail_cache = ("", 0.0)
    eng._absent_warn_last = 0.0
    eng._absent_warn_merged = 0
    eng._absent_detail_logged = False
    eng._unknown_warn_last = 0.0
    eng._unknown_warn_merged = 0
    # 地址族状态
    eng._family_verdicts = {}
    eng._family_probe_at = 0.0
    eng._preferred_family = ""
    eng._family_policy = "auto"
    eng._ipv4_verify = "strict"
    eng._hijack_warn_last = 0.0
    eng._hijack_warn_merged = 0
    # 缓存/状态容器
    eng._ns_ip_cache = {}
    eng._zone_ns_cache = {}
    eng._delegation_cache = {}
    eng._ds_cache = {}
    eng._verified_zone_cache = {}
    eng._dnskey_inflight = {}
    eng._ds_inflight = {}
    eng._dnskey_retry_after = {}
    eng._dnskey_retry_delays = (0.0,)     # 测试不需要退避等待
    eng._dnskey_semaphore = None
    eng._dnssec_warned = set()
    eng._chain_unavailable = set()
    eng._server_health = {}
    eng._server_cookies = {}
    eng._cookie_disabled = set()
    eng._cookie_secret = b"e2e-test-secret!"
    eng._bootstrap_sem = asyncio.Semaphore(1)
    eng._inflight_sem = asyncio.Semaphore(8)
    # 信任锚：用合成根 KSK 替代内置 IANA 锚
    eng._dnssec = types.SimpleNamespace(_root_keys=world.build_anchor())
    # 网络层：直接命中合成权威（跳过 UDP/TCP/健康度/COOKIE）
    eng._closest_zone_servers = lambda qname, qtype: None

    async def _query_servers(servers, qname, qtype, rdclass=1):
        return world.answer(servers[0], qname, qtype, rdclass)

    eng._query_servers = _query_servers
    return eng


async def _resolve_via(eng, qname: str, qtype: int = dns.rdatatype.A):
    return await asyncio.wait_for(eng.resolve(qname, qtype),
                                  timeout=eng.total_timeout + 5)


# ============================================================
# Part D：合成 DNSSEC 权威树——能做验证时的逐分支穷举（离线）
# ============================================================
async def run_part_d() -> bool:
    print("\n[Part D] 合成 DNSSEC 权威树：能做验证时的逐分支穷举（离线）")
    if not _pds_ready():
        return True
    start_ok = len(RESULTS)

    # D1 签名区正向应答：链验证通过 → 放行
    w = World(_MODE_FULL)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.secure.test.")
    check("D1 签名区正向应答（RRSIG 有效）→ 放行",
          r is not None and any(x.rdtype == dns.rdatatype.A for x in r.answer)
          and eng._stats["secure"] >= 1,
          "stats=%s release=%r" % (dict(eng._stats), eng._last_release))

    # D2 签名区正向应答但剥离 A 的 RRSIG → 判 bogus 丢弃
    w = World(_MODE_STRIP_ANSWER)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.secure.test.")
    check("D2 签名区应答剥离 RRSIG（剥离攻击）→ 丢弃",
          r is None and eng._stats["bogus"] >= 1,
          "stats=%s" % (dict(eng._stats),))

    # D3 签名被篡改（A 记录被改写）→ 验签失败 → 丢弃
    w = World(_MODE_TAMPER_ANSWER)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.secure.test.")
    check("D3 签名区应答被篡改（签名失效）→ 丢弃",
          r is None and eng._stats["bogus"] >= 1,
          "stats=%s" % (dict(eng._stats),))

    # D4 未签名区（父区用 NSEC 证明无 DS）→ 合法放行（insecure）
    w = World(_MODE_FULL)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.insecure.test.")
    check("D4 未签名区（父区 NSEC 证明无 DS）→ 放行",
          r is not None and eng._stats["insecure"] >= 1
          and eng._stats["bogus"] == 0,
          "stats=%s release=%r" % (dict(eng._stats), eng._last_release))

    # D5 未签名区（父区用 NSEC3 opt-out 覆盖证明，=.com 的真实形态）→ 放行
    w = World(_MODE_FULL)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.unsigned.opt.test.")
    check("D5 未签名区（父区 NSEC3 opt-out 覆盖证明）→ 放行",
          r is not None and eng._stats["insecure"] >= 1
          and eng._stats["bogus"] == 0,
          "stats=%s release=%r" % (dict(eng._stats), eng._last_release))

    # D6 【安全回归】未签名区但父区缺否定证明 → 必须仍判 unknown 丢弃
    w = World(_MODE_NO_PROOF)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.unsigned.opt.test.")
    check("D6 缺少父区否定证明（可能是剥离/降级）→ 仍丢弃",
          r is None and eng._stats["bogus"] >= 1,
          "stats=%s" % (dict(eng._stats),))

    # D7 根信任锚验签失败（野钥匙签根 DNSKEY）→ 证据 bogus_root，绝不放行
    w = World(_MODE_ROOT_BAD_SIG)
    eng = _world_engine(w)
    r = await _resolve_via(eng, "www.secure.test.")
    ev = await eng._dnssec_availability()
    check("D7 根 DNSKEY 验签失败 → 证据 bogus_root 且不放行",
          ev == "bogus_root" and r is None,
          "evidence=%s stats=%s" % (ev, dict(eng._stats)))

    # D8 链路正常（证据 ok）时，降级闸门不得生效
    w = World(_MODE_FULL)
    eng = _world_engine(w)
    await eng._dnssec_availability()
    r = await _resolve_via(eng, "www.secure.test.")
    check("D8 链路证据 ok 时降级闸门不生效（仍走严格验签）",
          eng._dnssec_evidence == "ok" and r is not None
          and eng._stats["dnssec_absent"] == 0,
          "evidence=%s stats=%s" % (eng._dnssec_evidence, dict(eng._stats)))

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part E：链路完全不提供 DNSSEC 材料——降级闸门逐分支穷举（离线）
# ============================================================
async def run_part_e() -> bool:
    print("\n[Part E] 链路完全不提供 DNSSEC 材料：降级闸门逐分支穷举（离线）")
    if not _pds_ready():
        return True
    start_ok = len(RESULTS)

    # E1 require_rrsig=false（默认）→ 正向应答放行（用日志里的真实域名）
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    r = await _resolve_via(eng, "datarouter-prod.ak.epicgames.com")
    check("E1 链路无 DNSSEC + require_rrsig=false → 正向应答放行",
          r is not None and eng._last_release == "dnssec_absent"
          and eng._stats["dnssec_absent"] >= 1,
          "release=%r stats=%s" % (eng._last_release, dict(eng._stats)))

    # E2 NODATA（无该类型）→ 同样放行，不能被判「无法证明」
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    r = await _resolve_via(eng, "www.bing.com", dns.rdatatype.AAAA)
    check("E2 链路无 DNSSEC + NODATA → 放行（不再判无法证明）",
          r is not None and r.rcode() == dns.rcode.NOERROR
          and eng._last_release == "dnssec_absent",
          "rcode=%s release=%r"
          % (dns.rcode.to_text(r.rcode()) if r else None, eng._last_release))

    # E3 NXDOMAIN（域名不存在）→ 放行（语义必须保留为 NXDOMAIN）
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    r = await _resolve_via(eng, "nx-nothing.epicgames.com")
    check("E3 链路无 DNSSEC + NXDOMAIN → 放行且 rcode=NXDOMAIN",
          r is not None and r.rcode() == dns.rcode.NXDOMAIN
          and eng._last_release == "dnssec_absent",
          "rcode=%s" % (dns.rcode.to_text(r.rcode()) if r else None))

    # E4 require_rrsig=true（安全优先）→ 必须仍然丢弃（fail-closed）
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=True)
    r = await _resolve_via(eng, "datarouter-prod.ak.epicgames.com")
    check("E4 链路无 DNSSEC + require_rrsig=true → 仍 fail-closed 丢弃",
          r is None and eng._stats["dnssec_absent"] == 0,
          "stats=%s" % (dict(eng._stats),))

    # E5 根 DNSKEY 回 NODATA（没有 DNSKEY）→ 同样是 absent，可放行
    w = AbsentWorld("nodata")
    eng = _world_engine(w, require_rrsig=False)
    r = await _resolve_via(eng, "update.googleapis.com")
    check("E5 根 DNSKEY 应答无 DNSKEY（NODATA）→ 证据 absent 且放行",
          r is not None and eng._dnssec_evidence == "absent"
          and eng._last_release == "dnssec_absent",
          "evidence=%s release=%r"
          % (eng._dnssec_evidence, eng._last_release))

    # E6 「确定性缺失」不再退避重试：一次根 DNSKEY 查询即可（旧实现 4 次）
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    await eng._get_trusted_dnskey(dns.name.root)
    n = w.queries[(".", "DNSKEY")]
    check("E6 根 DNSKEY 确定性缺失只查 1 次（不再退避重试 4 次）",
          n == 1, "root_dnskey_queries=%d" % n)

    # E7 证据 TTL 缓存：absent 期间重复查询不复用根 DNSKEY 往返
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    await _resolve_via(eng, "www.bing.com")
    q1 = w.queries[(".", "DNSKEY")]
    for _ in range(3):
        await _resolve_via(eng, "www.bing.com")
    q2 = w.queries[(".", "DNSKEY")]
    check("E7 absent 证据在 60s TTL 内不重复探测根 DNSKEY",
          q2 == q1, "root_dnskey_queries %d → %d" % (q1, q2))

    # E8 链路恢复后自动回到完整验证（证据过期 → 重新探测 → ok）
    w = World(_MODE_ABSENT)
    eng = _world_engine(w, require_rrsig=False)
    await _resolve_via(eng, "www.secure.test.")
    ev_before = await eng._dnssec_availability()
    w.mode = _MODE_FULL                      # 网络被修好
    eng._dnssec_avail_cache = ("", 0.0)      # 模拟 TTL 到期
    eng._dnskey_retry_after.pop(".", None)
    eng._chain_unavailable.discard(".")
    ev_after = await eng._dnssec_availability()
    check("E8 网络恢复后证据自动回到 ok（无需重启进程）",
          ev_before == "absent" and ev_after == "ok",
          "%s → %s" % (ev_before, ev_after))

    # E9 验签后端缺失（无 cryptography）→ require_rrsig=false 时放行
    w = World(_MODE_FULL)
    eng = _world_engine(w, require_rrsig=False, crypto_ok=False)
    r = await _resolve_via(eng, "www.secure.test.")
    check("E9 验签后端缺失 + require_rrsig=false → 放行（不再是全盘丢弃）",
          r is not None and eng._last_release == "dnssec_absent",
          "release=%r stats=%s" % (eng._last_release, dict(eng._stats)))

    # E10 验签后端缺失 + require_rrsig=true → fail-closed
    w = World(_MODE_FULL)
    eng = _world_engine(w, require_rrsig=True, crypto_ok=False)
    r = await _resolve_via(eng, "www.secure.test.")
    check("E10 验签后端缺失 + require_rrsig=true → fail-closed 丢弃",
          r is None, "stats=%s" % (dict(eng._stats),))

    # E11 wire 级端到端：resolve_with_stats 在降级模式下必须返回可用报文
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    q = dns.message.make_query("prod.cloud.rockstargames.com",
                               dns.rdatatype.A)
    wire, elapsed = await asyncio.wait_for(
        eng.resolve_with_stats(q.to_wire()), timeout=eng.total_timeout + 5)
    ok = False
    detail = "wire=None"
    if wire:
        try:
            resp = dns.message.from_wire(wire)
            ok = (resp.id == q.id and resp.question
                  and str(resp.question[0].name).rstrip(".") ==
                  "prod.cloud.rockstargames.com"
                  and any(x.rdtype == dns.rdatatype.A for x in resp.answer))
            detail = ("id_ok=%s q_ok=%s ans=%d %.2fs"
                      % (resp.id == q.id,
                         str(resp.question[0].name) if resp.question else None,
                         len(resp.answer), elapsed))
        except Exception as e:
            detail = "解析失败: %r" % (e,)
    check("E11 wire 级 resolve_with_stats：ID/question/answer 全部正确",
          ok, detail)

    # E12 统计口径：stats() 暴露 dnssec_absent，且 insecure/success 同步累加
    w = AbsentWorld("nxdomain")
    eng = _world_engine(w, require_rrsig=False)
    await _resolve_via(eng, "www.bing.com")
    s = eng.stats
    check("E12 stats() 暴露 dnssec_absent 且计数一致",
          s.get("dnssec_absent", 0) >= 1 and s.get("insecure", 0) >= 1
          and s.get("success", 0) >= 1 and s.get("bogus", 0) == 0,
          "stats=%s" % (s,))

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part F：出站报文 DO 穷举（证明"自己的查询没缺 DO"）
# ============================================================
def _wire_engine(world, require_rrsig: bool = False):
    """保留**真实**的 `_query_servers → _query_one_async → _udp_exchange`
    查询链，只把最后一步的 UDP 收发换成对合成权威的一次调用。

    与 `_world_engine()` 的区别：后者直接替换 `_query_servers`，会跳过
    `_query_one_async_inner()` 里 `make_query(..., want_dnssec=True)` +
    `_apply_cookie()` + 各分支逻辑，因此无法用来验证 DO 位。
    """
    eng = _world_engine(world, require_rrsig=require_rrsig)
    # 删掉实例属性，让 `_query_servers` 回落到类方法（真实调度逻辑）
    eng.__dict__.pop("_query_servers", None)
    captured: list = []

    async def fake_udp(ip, q):
        captured.append((ip, q.to_wire()))
        qn = str(q.question[0].name)
        qt = int(q.question[0].rdtype)
        resp = world.answer(ip, qn, qt)
        resp.id = q.id
        return resp

    eng._udp_exchange = fake_udp
    return eng, captured


def _parse_wire(wire: bytes):
    m = dns.message.from_wire(wire)
    return {
        "do": bool(m.ednsflags & dns.flags.DO),
        "edns": m.edns,
        "rd": bool(m.flags & dns.flags.RD),
        "payload": int(m.payload),
        "cookie": any(o.otype == dns.edns.COOKIE for o in (m.options or [])),
        "qtype": int(m.question[0].rdtype),
        "qname": str(m.question[0].name),
    }


async def run_part_f() -> bool:
    print("\n[Part F] 出站报文 DO 穷举"
          "（抓真实 wire bytes，排除「本地没请求 DNSSEC」）")
    if not _pds_ready():
        return True
    start_ok = len(RESULTS)

    # F1 普通 UDP 单跳（含 COOKIE）
    w = World(_MODE_FULL)
    eng, cap = _wire_engine(w)
    resp = await eng._query_one_async_inner(
        "10.0.0.1", "test.", dns.rdatatype.DNSKEY, 1)
    info = _parse_wire(cap[-1][1]) if cap else {}
    check("F1 UDP 单跳出站带 EDNS+DO=1（RD=0，payload=1232，带 COOKIE）",
          resp is not None and info.get("do") is True
          and info.get("edns") == 0 and info.get("rd") is False
          and info.get("payload") == 1232 and info.get("cookie") is True,
          "wire=%s" % (info,))

    # F2 权威不支持 COOKIE（FORMERR）→ 无 cookie 重发的那一次仍带 DO=1
    class _FormerrWorld(World):
        def answer(self, ip, qname, qtype, rdclass=1):
            msg = super().answer(ip, qname, qtype, rdclass)
            if getattr(self, "_formerr_once", True):
                self._formerr_once = False
                msg.set_rcode(dns.rcode.FORMERR)
            return msg

    w = _FormerrWorld(_MODE_FULL)
    eng, cap = _wire_engine(w)
    await eng._query_one_async_inner("10.0.0.1", "test.", dns.rdatatype.A, 1)
    dois = [_parse_wire(x[1])["do"] for x in cap]
    check("F2 COOKIE 不被支持后无 cookie 重发，两次都带 DO=1",
          len(cap) >= 2 and all(dois),
          "出站次数=%d DO=%s" % (len(cap), dois))

    # F3 UDP 截断（TC=1）→ TCP 重查**实际写出的字节**仍带 DO=1
    sent = {"raw": b""}

    class _TCWorld(World):
        def answer(self, ip, qname, qtype, rdclass=1):
            msg = super().answer(ip, qname, qtype, rdclass)
            msg.flags |= dns.flags.TC
            return msg

    class _Writer:
        def write(self, data):
            sent["raw"] += data

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_udp_tc(ip, q):
        sent["query"] = q.to_wire()
        r = dns.message.make_response(q)
        r.flags |= dns.flags.TC
        return r

    class _Reader:
        async def readexactly(self, n):
            if n == 2:
                return len(sent["payload"]).to_bytes(2, "big")
            return sent["payload"]

    async def fake_open(host, port, *a, **k):
        q = dns.message.from_wire(sent["query"])
        r = dns.message.make_response(q)
        r.answer.append(_rr(str(q.question[0].name), "A", "192.0.2.7"))
        sent["payload"] = r.to_wire()
        return _Reader(), _Writer()

    eng2, _cap2 = _wire_engine(_TCWorld(_MODE_FULL))
    eng2._udp_exchange = fake_udp_tc
    _orig_open = asyncio.open_connection
    asyncio.open_connection = fake_open
    try:
        await eng2._query_one_async_inner(
            "10.0.0.1", "www.test.", dns.rdatatype.A, 1)
    finally:
        asyncio.open_connection = _orig_open
    tcp_wire = sent["raw"][2:]           # 去掉 2 字节长度前缀
    info = _parse_wire(tcp_wire) if tcp_wire else {}
    check("F3 UDP 截断后 TCP 重查的实际字节仍带 DO=1",
          bool(tcp_wire) and info.get("do") is True and info.get("edns") == 0,
          "tcp_wire=%s" % (info,))

    # F4 QNAME 最小化的中间跳（NS 查询）也带 DO=1
    w = World(_MODE_FULL)
    eng, cap = _wire_engine(w)
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    infos = [_parse_wire(x[1]) for x in cap]
    ns_hops = [i for i in infos if i["qtype"] == dns.rdatatype.NS]
    check("F4 最小化中间跳（NS）与最终查询全部带 DO=1",
          r is not None and bool(ns_hops)
          and all(i["do"] and not i["rd"] for i in infos),
          "hops=%d ns_hops=%d 全部DO=%s"
          % (len(infos), len(ns_hops), all(i["do"] for i in infos)))

    # F5 DS / DNSKEY 全链查询带 DO=1（这是 DNSSEC 验证唯一的数据来源）
    w = World(_MODE_FULL)
    eng, cap = _wire_engine(w)
    k = await eng._get_trusted_dnskey(dns.name.from_text("secure.test."))
    infos = [_parse_wire(x[1]) for x in cap]
    chain = [i for i in infos if i["qtype"] in (
        dns.rdatatype.DS, dns.rdatatype.DNSKEY)]
    check("F5 DS/DNSKEY 全链查询全部带 DO=1 且链验证成功",
          k is not None and len(chain) >= 4
          and all(i["do"] for i in chain),
          "链路查询=%d 全部DO=%s 链长度=%s"
          % (len(chain), all(i["do"] for i in infos),
             None if k is None else len(k)))

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part G：纯迭代（无任何加密上游）也能做完整 DNSSEC
# ============================================================
async def run_part_g() -> bool:
    print("\n[Part G] 纯迭代（不使用任何加密上游）+ 真实 ResolverManager"
          " → 必须判 secure")
    if not _pds_ready():
        return True
    from config import Config
    from dnssec import DNSSECValidator, DNSSECQueryWrapper
    from resolver_manager import ResolverManager

    start_ok = len(RESULTS)
    cfg = Config(os.path.join(_HERE, "config.yaml"))
    if getattr(cfg, "upstream_enabled", True):
        print("  跳过：当前 config.yaml 里 upstream.enabled=true（不是纯迭代模式）")
        return True
    validator = DNSSECValidator(
        enabled=cfg.dnssec_enabled, mode=cfg.dnssec_mode,
        require_rrsig=cfg.dnssec_require_rrsig)
    wrapper = DNSSECQueryWrapper(validator, enabled=cfg.dnssec_enabled)
    # 真实查询路径（含 DO/COOKIE/TCP 回退）+ 合成"能下发 DNSSEC"的权威树
    eng, _cap = _wire_engine(World(_MODE_FULL))
    manager = ResolverManager(
        cfg, dnssec_wrapper=wrapper,
        consistency_verifier=None, anomaly_detector=None,
        iterative_resolver=eng)
    try:
        await asyncio.wait_for(manager.initialize(), timeout=60)
        check("G1 当前配置确实是纯迭代（只有 iterative 一个上游，无 DoH/DoT/DoQ）",
              manager._is_pure_iterative_mode()
              and len(manager._upstream_servers) == 1,
              "上游=%s" % ([u.name for u in manager._upstream_servers],))
        for name in ("www.secure.test.", "www.secure.opt.test."):
            q = dns.message.make_query(name, dns.rdatatype.A)
            wire = await asyncio.wait_for(manager.resolve(q.to_wire()), timeout=30)
            ok = False
            detail = "wire=None"
            if wire:
                m = dns.message.from_wire(wire)
                ok = (m.rcode() == dns.rcode.NOERROR
                      and any(x.rdtype == dns.rdatatype.A for x in m.answer))
                detail = "rcode=%s answer=%s" % (
                    dns.rcode.to_text(m.rcode()),
                    [dns.rdatatype.to_text(x.rdtype) for x in m.answer])
            check("G2 纯迭代解析签名域名 %s（无任何加密上游）" % name, ok, detail)
        check("G3 纯迭代下 DNSSEC 判定为 secure（证据=ok，无降级放行）",
              eng.stats.get("secure", 0) >= 1
              and eng.stats.get("dnssec_absent", 0) == 0
              and eng._dnssec_evidence == "ok",
              "evidence=%s stats=%s"
              % (eng._dnssec_evidence, eng.stats))
    finally:
        try:
            await asyncio.wait_for(manager.close_all(), timeout=15)
        except Exception:
            pass

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part H：某一地址族被中间设备代答时的「换族恢复 DNSSEC」
# ============================================================
class SplitWorld(World):
    """v4/53 被中间盒代答、v6/53 直达权威的合成世界（实测网络形态）

    每个 zone 同时有 v4 与 v6 地址：
      * v4 查询由 `fake_udp` 回 NXDOMAIN（无 OPT、无 DNSSEC）= 被代答；
      * v6 查询走正常权威（NSEC/NSEC3/RRSIG 齐全）。
    referral 同时给 A 与 AAAA glue（真实互联网也是这样），因此换族逻辑
    必须在**每一跳**生效才有效。
    """

    def __init__(self, v6_glue: bool = True):
        super().__init__(_MODE_FULL)
        self.v6_glue = v6_glue
        self.v6_of = {}
        for zone, ip, _s, _n, _c in _ZONES:
            v6 = "fd00::" + ip.rsplit(".", 1)[-1]
            self.v6_of[zone] = v6
            self.ip2zone[v6] = zone

    def _referral(self, msg, zone: str, child: str):
        ns = "ns1." + child
        msg.authority.append(_rr(child, "NS", ns))
        msg.additional.append(_rr(ns, "A", self.ip_of(child)))       # v4（代答）
        if self.v6_glue:
            msg.additional.append(_rr(ns, "AAAA", self.v6_of[child]))  # v6（真）


def _split_engine(world: SplitWorld, hijack_both: bool = False):
    eng, _cap = _wire_engine(world)
    eng.root_servers = ["10.0.0.1", "fd00::1"]
    hits = collections.Counter()

    async def fake_udp(ip, q):
        fam = "6" if ":" in str(ip) else "4"
        qname = str(q.question[0].name)
        qtype = int(q.question[0].rdtype)
        hits[(fam, qname, qtype)] += 1
        if fam == "4" or hijack_both:
            # 代答形态：NXDOMAIN + 只有 SOA，无 OPT、无任何 DNSSEC 记录
            r = dns.message.make_response(dns.message.make_query(qname, qtype))
            r.index = None
            r.set_rcode(dns.rcode.NXDOMAIN)
            r.authority.append(_rr(".", "SOA", _ROOT_SOA))
            r.id = q.id
            return r
        r = world.answer(ip, qname, qtype)
        r.id = q.id
        return r

    eng._udp_exchange = fake_udp
    eng._hits = hits
    return eng, hits


async def run_part_h() -> bool:
    print("\n[Part H] 某一地址族被中间设备代答 → 自动换族恢复 DNSSEC")
    if not _pds_ready():
        return True
    start_ok = len(RESULTS)

    # H1 族完整性判定：v4=hijacked / v6=genuine
    w = SplitWorld()
    eng, _hits = _split_engine(w)
    v4 = await eng._probe_family_integrity("4")
    v6 = await eng._probe_family_integrity("6")
    check("H1 族完整性判定：v4=hijacked / v6=genuine",
          v4 == "hijacked" and v6 == "genuine", "v4=%s v6=%s" % (v4, v6))

    # H2 自动换族后根 DNSKEY 能验证通过（证据从 absent 变 ok）
    w = SplitWorld()
    eng, _hits = _split_engine(w)
    ev_before = await eng._dnssec_availability()
    check("H2 换族后证据变 ok，且选定优先族=IPv6",
          ev_before == "ok" and eng._preferred_family == "6"
          and eng._family_verdicts.get("4") == "hijacked"
          and eng._family_verdicts.get("6") == "genuine",
          "evidence=%s pref=%s verdicts=%s"
          % (ev_before, eng._preferred_family, eng._family_verdicts))

    # H3 换族后签名域名解析成功且判 secure（换族前这是"无法证明"）
    #    先让族探测跑完（探测本身必然要问 v4 一次），再清零计数观察解析路径
    w = SplitWorld()
    eng, hits = _split_engine(w)
    await eng._dnssec_availability()
    hits.clear()
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    check("H3 换族后签名域名判 secure（answer 带 RRSIG）",
          r is not None and eng.stats.get("secure", 0) >= 1
          and eng.stats.get("dnssec_absent", 0) == 0,
          "stats=%s release=%r" % (dict(eng.stats), eng._last_release))

    # H4 每一跳都优先走 v6：解析期间不应再向 v4 权威发查询
    v4_during = sum(c for (fam, _n, _t), c in hits.items() if fam == "4")
    v6_during = sum(c for (fam, _n, _t), c in hits.items() if fam == "6")
    check("H4 解析全程只问 v6 权威（代答的 v4 不再参与）",
          v4_during == 0 and v6_during >= 5,
          "v4=%d v6=%d" % (v4_during, v6_during))

    # H5 两族都被代答 → 保持原有降级（可用性优先，不整机 SERVFAIL）
    w = SplitWorld()
    eng2, _h2 = _split_engine(w, hijack_both=True)
    ev = await eng2._dnssec_availability()
    r2 = await eng2.resolve("www.secure.test.", dns.rdatatype.A)
    check("H5 两族都被代答 → 仍解析成功（dnssec_absent 降级，不 SERVFAIL）",
          ev == "absent" and r2 is not None
          and eng2._last_release == "dnssec_absent",
          "evidence=%s release=%r stats=%s"
          % (ev, eng2._last_release, dict(eng2.stats)))

    # H6 回退保障：某一跳没有 v6 地址时自动回退全族，解析不能失败
    #    （回退拿到的是代答族的数据 → 按 require_rrsig=false 未验证放行，
    #     并且必须让运维在日志/统计里看到"这条没验证过"）
    w = SplitWorld(v6_glue=False)
    eng3, _h3 = _split_engine(w)
    r3 = await eng3.resolve("www.secure.test.", dns.rdatatype.A)
    check("H6 真族在该跳无可用地址 → 回退全族，解析仍成功且标记未验证",
          r3 is not None and eng3._last_release == "hijacked_path"
          and eng3.stats.get("hijacked_path", 0) >= 1,
          "release=%r stats=%s"
          % (eng3._last_release, dict(eng3.stats)))

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part I：iterative.family / iterative.ipv4_verify（境内 IPv4 镜像场景）
# ============================================================
class MirrorWorld(SplitWorld):
    """v4 = 境内镜像：结构像真权威（转发 referral/NSEC），但**篡改 A 记录**

    这正是境内 IPv4 根 IP 的真实威胁模型：镜像能看到全部查询，也能把
    referral 转回来，但它既不下发 DNSSEC，还可以悄悄改答案。
    """

    POISON = "203.0.113.66"


def _mirror_engine(world: MirrorWorld, family_policy: str, ipv4_verify: str):
    eng, _cap = _wire_engine(world)
    eng.root_servers = ["10.0.0.1", "fd00::1"]
    eng._family_policy = family_policy
    eng._ipv4_verify = ipv4_verify
    eng._preferred_family = {"ipv4": "4", "ipv6": "6"}.get(family_policy, "")
    eng._family_verdicts = {}
    eng._family_probe_at = 0.0
    hits = collections.Counter()

    async def fake_udp(ip, q):
        fam = "6" if ":" in str(ip) else "4"
        qname = str(q.question[0].name)
        qtype = int(q.question[0].rdtype)
        hits[(fam, qname, qtype)] += 1
        resp = world.answer(ip, qname, qtype)
        resp.index = None
        resp.id = q.id
        if fam == "4":
            if qname == "." and qtype == dns.rdatatype.DNSKEY:
                # 镜像不下发 DNSSEC：根 DNSKEY 只回 SOA（→ 族判定 hijacked）
                resp.answer = [
                    x for x in resp.answer
                    if x.rdtype != dns.rdatatype.DNSKEY]
                resp.authority = [_rr(".", "SOA", _ROOT_SOA)]
                resp.flags |= dns.flags.AA
                return resp
            if qtype == dns.rdatatype.A:
                # 篡改答案，并剥掉这条 A 的 RRSIG
                resp.answer = [x for x in resp.answer
                               if x.rdtype not in (dns.rdatatype.A,
                                                   dns.rdatatype.RRSIG)]
                resp.answer.append(_rr(qname, "A", MirrorWorld.POISON))
                resp.flags |= dns.flags.AA
        return resp

    eng._udp_exchange = fake_udp
    eng._hits = hits
    return eng, hits


async def run_part_i() -> bool:
    print("\n[Part I] iterative.family / iterative.ipv4_verify"
          "（IPv4 镜像场景）")
    if not _pds_ready():
        return True
    start_ok = len(RESULTS)

    # I1 family=auto + corroborate：自动选真族，无需印证、直接判 secure
    w = MirrorWorld()
    eng, hits = _mirror_engine(w, "auto", "corroborate")
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    a = [x for x in (r.answer if r else []) if x.rdtype == dns.rdatatype.A]
    check("I1 family=auto：自动改用真族（IPv6），判 secure，不产生 mismatch",
          r is not None and eng._preferred_family == "6"
          and eng.stats.get("secure", 0) >= 1
          and eng.stats.get("mismatch", 0) == 0
          and a and a[0][0].address != MirrorWorld.POISON,
          "pref=%s stats=%s" % (eng._preferred_family, dict(eng.stats)))

    # I2 family=ipv4 + corroborate：答案来自镜像，但用真族印证 → 发现篡改，
    #    丢弃镜像答案、改用真族答案（客户端拿到的是真实 A）
    w = MirrorWorld()
    eng, hits = _mirror_engine(w, "ipv4", "corroborate")
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    a = [x for x in (r.answer if r else []) if x.rdtype == dns.rdatatype.A]
    addr = a[0][0].address if a else None
    check("I2 family=ipv4 + corroborate：镜像篡改被识破，改用真族答案",
          r is not None and eng.stats.get("mismatch", 0) >= 1
          and eng.stats.get("corroborated", 0) >= 1
          and addr == "10.0.0.21",
          "answer=%s stats=%s" % (addr, dict(eng.stats)))

    # I3 family=ipv4 + strict：不做印证。镜像链路上拿不到 DNSSEC 证据，
    #    因此答案**不会被判为已验证**（secure=0）——这正是为什么不推荐
    #    在镜像链路上单靠 strict：它只能"未验证放行"或失败，给不出保证。
    w = MirrorWorld()
    eng, hits = _mirror_engine(w, "ipv4", "strict")
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    check("I3 family=ipv4 + strict：镜像答案无法被判为已验证（secure=0）",
          eng.stats.get("secure", 0) == 0
          and eng.stats.get("mismatch", 0) == 0,
          "rcode=%s stats=%s"
          % (dns.rcode.to_text(r.rcode()) if r else None, dict(eng.stats)))

    # I4 family=ipv4 + none：不做印证。镜像**形态伪装得很好**（AA/OPT/DO 齐全），
    #    因此程序无法区分它和真权威，只能放行"未验证"数据——这就是为什么不建议
    #    在镜像链路上用 none（对比 I2：corroborate 能识破同样的篡改）。
    w = MirrorWorld()
    eng, hits = _mirror_engine(w, "ipv4", "none")
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    a = [x for x in (r.answer if r else []) if x.rdtype == dns.rdatatype.A]
    addr = a[0][0].address if a else None
    check("I4 family=ipv4 + none：镜像数据被放行但**未验证**（secure=0）",
          r is not None and eng.stats.get("secure", 0) == 0
          and eng.stats.get("mismatch", 0) == 0,
          "release=%r answer=%s stats=%s"
          % (eng._last_release, addr, dict(eng.stats)))

    # I5 family=ipv6 强制：全程只问 v6（不因镜像存在而动摇）
    w = MirrorWorld()
    eng, hits = _mirror_engine(w, "ipv6", "corroborate")
    # 先让族探测跑完（探测本身必须两族各问一次才能得出判定），再清零观察解析路径
    await eng._ensure_family_preference()
    hits.clear()
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    v4 = sum(c for (fam, _n, _t), c in hits.items() if fam == "4")
    check("I5 family=ipv6 强制生效：解析全程 0 次 v4 查询",
          r is not None and v4 == 0 and eng._preferred_family == "6",
          "v4查询=%d stats=%s" % (v4, dict(eng.stats)))

    # I6 真族拿不到该名字（跳内无 v6 地址）→ 印证不可用 → 按未验证放行
    w = MirrorWorld(v6_glue=False)
    eng, hits = _mirror_engine(w, "ipv4", "corroborate")
    r = await eng.resolve("www.secure.test.", dns.rdatatype.A)
    check("I6 真族不可达时印证自动放弃 → 未验证放行（不 SERVFAIL）",
          r is not None
          and eng._last_release in ("hijacked_path", "dnssec_absent", ""),
          "release=%r stats=%s" % (eng._last_release, dict(eng.stats)))

    # I7 配置解析：合法值生效、非法值安全回退
    import re
    import tempfile
    from config import Config
    base = open(os.path.join(_HERE, "config.yaml"), encoding="utf-8").read()
    ok_all = True
    detail = []
    for fam, ver, exp_fam, exp_ver in (
            ("ipv6", "corroborate", "ipv6", "corroborate"),
            ("ipv4", "none", "ipv4", "none"),
            ("bogus", "bogus", "auto", "strict"),
    ):
        text = re.sub(r"(?m)^  family:\s*\S+", "  family: %s" % fam, base, count=1)
        text = re.sub(r"(?m)^  ipv4_verify:\s*\S+",
                      "  ipv4_verify: %s" % ver, text, count=1)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False,
                                         encoding="utf-8") as f:
            f.write(text)
            path = f.name
        try:
            cfg = Config(path)
            got = (cfg.plain_dns_iterative_family,
                   cfg.plain_dns_iterative_ipv4_verify)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        detail.append("%s/%s→%s" % (fam, ver, got))
        if got != (exp_fam, exp_ver):
            ok_all = False
    check("I7 iterative.family / ipv4_verify 解析与非法值回退",
          ok_all, " ".join(detail))

    # I8 逐域名「代答族降级放行」告警只在 ipv4_verify=strict 时打印：
    #    corroborate 已用真族逐条印证（不一致另有「疑似中间人」告警），
    #    none 本来就不做校验——这两档必须静默，避免日志被刷。
    class _Cap(logging.Handler):
        def __init__(self):
            super().__init__()
            self.msgs = []

        def emit(self, record):
            self.msgs.append(record.getMessage())

    lg = logging.getLogger("dns-proxy.plain-dns")
    cap = _Cap()
    _old_level = lg.level
    lg.addHandler(cap)
    lg.setLevel(logging.WARNING)
    warned = {}
    try:
        for policy in ("strict", "corroborate", "none"):
            # v6 不可达 → 应答只能来自镜像族，必然走 hijacked_path 分支
            eng, _h = _split_engine(SplitWorld(v6_glue=False))
            eng._ipv4_verify = policy
            cap.msgs.clear()
            await eng.resolve("www.secure.test.", dns.rdatatype.A)
            # 只统计**逐域名降级**那条；「地址族完整性 … 判定被中间设备代答」
            # 是首次判定时的一条结论日志，与本次要求无关，不能算进来
            warned[policy] = sum(
                1 for m in cap.msgs
                if m.startswith("DNSSEC 无法验证，降级放行"))
    finally:
        lg.removeHandler(cap)
        lg.setLevel(_old_level)
    check("I8 代答族降级告警只在 ipv4_verify=strict 时打印"
          "（corroborate/none 静默）",
          warned.get("strict", 0) >= 1
          and warned.get("corroborate", 1) == 0
          and warned.get("none", 1) == 0,
          "strict=%d corroborate=%d none=%d"
          % (warned.get("strict", 0), warned.get("corroborate", 0),
             warned.get("none", 0)))

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# Part J/K：真实链路端到端（需要出网）
# ============================================================
_REAL_DOMAINS = [
    # 线上日志里被丢弃的真实域名（未签名区 / CNAME 到未签名 CDN）
    "datarouter-prod.ak.epicgames.com",
    "hw-v2-web-player-tracker.biliapi.net",
    "prod.cloud.rockstargames.com",
    "update.googleapis.com",
    "www.bing.com",
    # 签名域名：能做验证的链路上必须判 secure（换族恢复 DNSSEC 的直接证据）
    "nic.cz",
    "www.ietf.org",
]


async def run_part_j() -> bool:
    """真实链路：纯迭代 + 真实 config.yaml 的端到端解析"""
    print("\n[Part J] 真实链路端到端（纯迭代模式 + 真实 config.yaml）")
    if not _pds_ready():
        return True
    from config import Config

    start_ok = len(RESULTS)
    cfg = Config(os.path.join(_HERE, "config.yaml"))
    eng = pds.IterativeResolver(cfg)

    class _Cap(logging.Handler):
        def __init__(self):
            super().__init__()
            self.msgs = []

        def emit(self, record):
            self.msgs.append(record.getMessage())

    cap = _Cap()
    lg = logging.getLogger("dns-proxy.plain-dns")
    _old_level = lg.level
    lg.addHandler(cap)
    lg.setLevel(logging.WARNING)
    try:
        await eng.warmup_dnssec_chain()
        ev = await eng._dnssec_availability()
        cap.msgs.clear()          # 只统计"逐域名解析期间"的告警
        print("  链路 DNSSEC 证据: %s（require_rrsig=%s, strict_dnssec=%s，"
              "优先族=%r，各族=%s，ipv4_verify=%s）"
              % (ev, eng._require_rrsig, eng.strict_dnssec,
                 eng._preferred_family, eng._family_verdicts,
                 eng._ipv4_verify))

        for d in _REAL_DOMAINS:
            try:
                r = await asyncio.wait_for(eng.resolve(d, dns.rdatatype.A),
                                           timeout=eng.total_timeout + 10)
            except asyncio.TimeoutError:
                r = None
            check("J1 真实链路解析 %s" % d,
                  r is not None and r.answer and r.rcode() == dns.rcode.NOERROR,
                  "rcode=%s answer=%s release=%r"
                  % (dns.rcode.to_text(r.rcode()) if r else None,
                     [dns.rdatatype.to_text(x.rdtype) for x in r.answer] if r else [],
                     eng._last_release))
        per_domain_hijack_warn = sum(
            1 for m in cap.msgs if m.startswith("DNSSEC 无法验证，降级放行"))
    finally:
        lg.removeHandler(cap)
        lg.setLevel(_old_level)

    s = eng.stats
    check("J2 真实链路：不再出现「严格模式丢弃」造成的 bogus",
          s["bogus"] == 0, "stats=%s" % (s,))

    # J4 逐域名「代答族降级放行」告警：只在 ipv4_verify=strict 时允许出现，
    #    corroborate/none 下必须静默（corroborate 的不一致另有"疑似中间人"告警）
    if eng._ipv4_verify == "strict":
        check("J4 ipv4_verify=strict：逐域名降级告警允许出现（跳过校验）",
              True, "warn=%d" % per_domain_hijack_warn)
    else:
        check("J4 逐域名「代答族降级放行」告警已静默"
              "（ipv4_verify=%s）" % eng._ipv4_verify,
              per_domain_hijack_warn == 0,
              "warnings=%d hijacked_path=%s"
              % (per_domain_hijack_warn, s.get("hijacked_path", 0)))

    if ev == "absent":
        check("J3 真实链路（无 DNSSEC 记录）：全部走 dnssec_absent 降级放行",
              s["dnssec_absent"] >= len(_REAL_DOMAINS) * 0.8,
              "dnssec_absent=%s" % (s["dnssec_absent"],))
    else:
        check("J3 真实链路能做 DNSSEC 验证（换族后）："
              "至少一个签名域名判 secure",
              s.get("secure", 0) >= 1,
              "stats=%s 优先族=%r 各族=%s"
              % (s, eng._preferred_family, eng._family_verdicts))

    return all(ok for _, ok in RESULTS[start_ok:])


async def run_part_k() -> bool:
    """全链路：Config → DNSSEC 包装器 → ResolverManager → 迭代上游"""
    print("\n[Part K] 全链路端到端："
          "Config → DNSSEC 包装器 → ResolverManager → 迭代上游")
    if not _pds_ready():
        return True
    from config import Config
    from dnssec import DNSSECValidator, DNSSECQueryWrapper
    from resolver_manager import ResolverManager

    start_ok = len(RESULTS)
    cfg = Config(os.path.join(_HERE, "config.yaml"))
    validator = DNSSECValidator(
        enabled=cfg.dnssec_enabled, mode=cfg.dnssec_mode,
        require_rrsig=cfg.dnssec_require_rrsig)
    wrapper = DNSSECQueryWrapper(validator, enabled=cfg.dnssec_enabled)
    iterative = pds.IterativeResolver(cfg)
    manager = ResolverManager(
        cfg, dnssec_wrapper=wrapper,
        consistency_verifier=None, anomaly_detector=None,
        iterative_resolver=iterative)
    try:
        await asyncio.wait_for(manager.initialize(), timeout=60)
        for d in _REAL_DOMAINS:
            q = dns.message.make_query(d, dns.rdatatype.A)
            try:
                wire = await asyncio.wait_for(
                    manager.resolve(q.to_wire()),
                    timeout=iterative.total_timeout + 15)
            except asyncio.TimeoutError:
                wire = None
            ok = False
            detail = "wire=None"
            if wire:
                try:
                    r = dns.message.from_wire(wire)
                    ans = [dns.rdatatype.to_text(x.rdtype) for x in r.answer]
                    ok = (r.id == q.id and r.rcode() == dns.rcode.NOERROR
                          and any(x.rdtype == dns.rdatatype.A for x in r.answer))
                    detail = ("rcode=%s id_ok=%s answer=%s"
                              % (dns.rcode.to_text(r.rcode()),
                                 r.id == q.id, ans))
                except Exception as e:
                    detail = "解析失败: %r" % (e,)
            check("K1 全链路解析 %s" % d, ok, detail)
        s = iterative.stats
        check("K2 全链路：无 bogus，且每条应答都归于三态之一"
              "（secure / dnssec_absent / hijacked_path）",
              s.get("bogus", 0) == 0
              and (s.get("dnssec_absent", 0) >= 1
                   or s.get("secure", 0) >= 1
                   or s.get("hijacked_path", 0) >= 1),
              "iterative.stats=%s" % (s,))
    finally:
        try:
            await asyncio.wait_for(manager.close_all(), timeout=15)
        except Exception:
            pass

    return all(ok for _, ok in RESULTS[start_ok:])


# ============================================================
# --probe / --forensic：真实链路取证（只做诊断，不参与判定）
# ============================================================
async def run_part_probe():
    """真实链路 DNSSEC 证据探测（DO=1 / DO=0 对照，不用任何加密上游）"""
    print("\n[Probe] 真实链路 DNSSEC 证据探测"
          "（直接问权威，不使用任何加密上游）")
    if not _pds_ready():
        return
    from config import Config
    cfg = Config(os.path.join(_HERE, "config.yaml"))
    eng = pds.IterativeResolver(cfg)

    def _summ(msg, wire_do):
        rrsig = sum(len(x) for sec in (msg.answer, msg.authority)
                    for x in sec if x.rdtype == dns.rdatatype.RRSIG)
        nsec = sum(1 for sec in (msg.answer, msg.authority) for x in sec
                   if x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3))
        dnskey = sum(1 for x in msg.answer if x.rdtype == dns.rdatatype.DNSKEY)
        return ("出站DO=%s | 回: rcode=%-8s OPT=%s 回声DO=%-5s payload=%-5s "
                "RRSIG=%-3d NSEC/NSEC3=%-2d DNSKEY=%d"
                % (wire_do, dns.rcode.to_text(msg.rcode()),
                   "有" if msg.opt is not None else "无",
                   bool(msg.ednsflags & dns.flags.DO),
                   msg.payload if msg.opt is not None else "-",
                   rrsig, nsec, dnskey))

    # 目标：根区和 .com 权威（这两处就能判定链路是否传 DNSSEC）
    targets = [
        ("198.41.0.4", ".", dns.rdatatype.DNSKEY),      # a.root-servers.net
        ("192.5.6.30", "com.", dns.rdatatype.DNSKEY),   # a.gtld-servers.net
        ("192.5.6.30", "ietf.org", dns.rdatatype.DS),   # 签名 TLD 的 DS
        ("192.5.6.30", "rockstargames.com", dns.rdatatype.DS),  # 未签名委托
        ("198.41.0.4", "example.com", dns.rdatatype.A),  # 根不该递归，对照用
    ]
    for ip, name, qtype in targets:
        print("\n  目标 %s:%s %s" % (ip, name, dns.rdatatype.to_text(qtype)))
        # (1) 走真实代码路径（DO=1 + COOKIE），抓出站 wire 确认 DO
        cap = []
        real_udp = eng._udp_exchange

        async def spy(ip_, q, _real=real_udp, _cap=cap):
            _cap.append(q.to_wire())
            return await _real(ip_, q)

        eng._udp_exchange = spy
        try:
            with_do = await eng._query_one_async_inner(ip, name, qtype, 1)
        finally:
            eng._udp_exchange = real_udp
        wire_do = _parse_wire(cap[-1])["do"] if cap else "?"
        if with_do is None:
            print("    DO=1 查询无应答（超时/不可达）")
        else:
            print("    DO=1 " + _summ(with_do, wire_do))
        # (2) 对照组：同一目标、同一问题，DO=0
        q0 = dns.message.make_query(name, qtype, want_dnssec=False)
        q0.flags &= ~dns.flags.RD
        no_do = await eng._udp_exchange(ip, q0)
        if no_do is None:
            print("    DO=0 查询无应答")
        else:
            print("    DO=0 " + _summ(no_do, False))

    print("\n  判读方法：")
    print("    * DO=1 回 RRSIG/NSEC3/DNSKEY，DO=0 不回  → 链路正常，"
          "纯迭代即可完成 DNSSEC 验证（不需要任何加密上游）；")
    print("    * DO=1 与 DO=0 应答完全一样、且 OPT/回声DO 缺失或 payload=512，")
    print("      甚至 answer/authority 只有 SOA → 中间设备在替权威回答问题并剥掉了")
    print("      DNSSEC 记录，任何程序侧选择都换不到 DNSSEC 记录；")
    print("    * 若 DO=1 就只有 NXDOMAIN（例如 `. DNSKEY`）→ 同上。")


_TESTNET_IPS = ("192.0.2.1", "198.51.100.1")   # RFC 5737 TEST-NET，不可能有 DNS 服务
_ROOT_V4 = ("198.41.0.4", "199.7.83.42")       # a.root / l.root
_ROOT_V6 = "2001:503:ba3e::2:30"               # a.root-servers.net AAAA


def _resp_sig(msg) -> str:
    """响应的"内容指纹"（忽略 ID），用于判断两个不同目标是否由同一设备代答"""
    try:
        body = []
        for sec in (msg.answer, msg.authority, msg.additional):
            body.append("|".join(sorted(x.to_text() for x in sec)))
        return "%s/%d/%s" % (dns.rcode.to_text(msg.rcode()), msg.flags,
                             "#".join(body))
    except Exception:
        return repr(msg)


async def run_part_forensic():
    """定位「是谁在替权威回答问题」——只做诊断，不改任何状态"""
    print("\n[Forensic] 定位「是谁在替权威回答问题」——只做诊断，不改任何状态")
    if not _pds_ready():
        return
    from config import Config
    cfg = Config(os.path.join(_HERE, "config.yaml"))
    eng = pds.IterativeResolver(cfg)

    async def ask(ip, name, qtype, want_dnssec=True, tcp=False):
        q = dns.message.make_query(name, qtype, want_dnssec=want_dnssec)
        q.flags &= ~dns.flags.RD
        try:
            if tcp:
                return await eng._query_one_tcp(ip, q), q
            return await eng._udp_exchange(ip, q), q
        except Exception as e:
            print("    %s 查询异常: %r" % (ip, e))
            return None, q

    def line(tag, resp):
        if resp is None:
            print("    %-34s 无应答（超时/被丢弃）" % tag)
            return None
        print("    %-34s %s" % (tag, pds.IterativeResolver._describe_resp(resp)))
        return resp

    # 1) 死 IP 测试：任何合法 DNS 路径都不可能回答 TEST-NET 地址
    print("\n  ① 死 IP 测试（%s，RFC 5737 TEST-NET：不可能有 DNS 服务）"
          % ", ".join(_TESTNET_IPS))
    dead_answered = False
    for ip in _TESTNET_IPS:
        r, _ = await ask(ip, ".", dns.rdatatype.NS)
        if line("%s 查 . NS" % ip, r) is not None:
            dead_answered = True

    # 2) 根服务器：IPv4 / IPv6 / TCP 三条路径
    print("\n  ② 根服务器 . DNSKEY（真权威只可能回 NOERROR+DNSKEY+RRSIG+OPT）")
    v4_resp = None
    for ip in _ROOT_V4:
        r, _ = await ask(ip, ".", dns.rdatatype.DNSKEY)
        if r is not None and v4_resp is None:
            v4_resp = r
        line("%s UDP" % ip, r)
    r6, _ = await ask(_ROOT_V6, ".", dns.rdatatype.DNSKEY)
    line("%s UDP(v6)" % _ROOT_V6, r6)
    rt, _ = await ask(_ROOT_V4[0], ".", dns.rdatatype.DNSKEY, tcp=True)
    line("%s TCP" % _ROOT_V4[0], rt)

    # 3) 同一问题问两台不同根：内容指纹相同 ⇒ 同一设备在代答
    print("\n  ③ 同一问题问两台不同根（内容指纹对比）")
    ra, _ = await ask(_ROOT_V4[0], "example.com", dns.rdatatype.A)
    rb, _ = await ask(_ROOT_V4[1], "example.com", dns.rdatatype.A)
    same = (ra is not None and rb is not None
            and _resp_sig(ra) == _resp_sig(rb))
    line("%s 查 example.com A" % _ROOT_V4[0], ra)
    line("%s 查 example.com A" % _ROOT_V4[1], rb)
    print("    指纹一致=%s" % same)

    # 4) 结论
    print("\n  ④ 结论")
    if dead_answered:
        print("    ✗ 对 TEST-NET 死地址也有应答 → 链路上存在**替任意目标回答**的设备")
        print("      （路由器「DNS 劫持/防劫持」、安全软件、VPN/代理的 DNS 接管、")
        print("       或运营商 UDP/53 重定向）。这不是本程序的问题：无论问哪台权威，")
        print("      应答都来自那台设备，而它不下发 DNSSEC 记录。")
        print("      处置：在路由器/安全软件/代理里关掉 DNS 劫持或「DNS 代理」，")
        print("            或改用 DoH/DoT/DoQ（程序内 upstream.enabled=true）。")
    elif v4_resp is not None and any(
            x.rdtype == dns.rdatatype.RRSIG
            for sec in (v4_resp.answer, v4_resp.authority) for x in sec):
        print("    ✓ 根 DNSKEY 应答里带 RRSIG → 链路正常传 DNSSEC，纯迭代即可验证")
    elif v4_resp is not None and v4_resp.rcode() == dns.rcode.NXDOMAIN:
        print("    ✗ 根服务器对 `. DNSKEY` 回 NXDOMAIN → 应答不是来自真根，")
        print("      是针对 53 端口的定向拦截/改包（死 IP 未答，说明只劫持已知权威）")
    else:
        print("    ? 形态不典型，请把上面每行贴出来再判断")
    if rt is not None and v4_resp is not None and _resp_sig(rt) == _resp_sig(v4_resp):
        print("    · TCP 与 UDP 应答一致 → 拦截同时覆盖 TCP/53（换传输方式无效）")
    if r6 is None and v4_resp is not None:
        print("    · IPv6 路径无应答（本机可能无 IPv6 出网）→ 没有可绕过的第二路径")
    elif r6 is not None:
        print("    · IPv6 有应答，可与 IPv4 结果对比看是否只有 v4 被劫持")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15353,
                    help="明文 DNS 测试端口（默认 15353，53 需要权限）")
    ap.add_argument("--skip-net", action="store_true", help="只跑离线 DNSSEC 用例")
    ap.add_argument("--real-dnssec", action="store_true",
                    help="额外跑真实网络 DNSSEC 回归（Part C，需要出网）")
    ap.add_argument("--real", action="store_true",
                    help="额外跑真实链路端到端（Part C + J + K，需要出网）")
    ap.add_argument("--probe", action="store_true",
                    help="真实链路 DNSSEC 证据探测（DO=1/DO=0 对照）")
    ap.add_argument("--forensic", action="store_true",
                    help="定位「是谁在替权威回答问题」（死 IP / TCP / IPv6 对照）")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="打印 DEBUG 级日志（排障用）")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname).1s %(name)s: %(message)s",
    )
    logging.getLogger("dns-proxy.plain-dns").setLevel(
        logging.DEBUG if args.verbose else logging.WARNING)
    print("=" * 72)
    print("test_plain_dns.py — 明文 DNS 协议 + 迭代解析 DNSSEC 逐分支穷举")
    print("=" * 72)
    t0 = time.time()
    if not args.skip_net:
        asyncio.run(run_part_a(args.port))
    asyncio.run(run_part_b())
    asyncio.run(run_part_b_chain())
    asyncio.run(run_part_b_types())
    asyncio.run(run_part_d())
    asyncio.run(run_part_e())
    asyncio.run(run_part_f())
    asyncio.run(run_part_g())
    asyncio.run(run_part_h())
    asyncio.run(run_part_i())
    if args.real_dnssec or args.real:
        asyncio.run(run_part_c())
    if args.real:
        asyncio.run(run_part_j())
        asyncio.run(run_part_k())
    if args.probe:
        asyncio.run(run_part_probe())
    if args.forensic:
        asyncio.run(run_part_forensic())

    total = len(RESULTS)
    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 72)
    print(f"总计 {total} 项，通过 {total - len(failed)} 项，失败 {len(failed)} 项"
          f"（耗时 {time.time() - t0:.1f}s）")
    if failed:
        for n in failed:
            print(f"  FAILED: {n}")
        print("RESULT: FAILED")
        return 1
    print("RESULT: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

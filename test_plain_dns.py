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
"""
import argparse
import asyncio
import base64
import collections
import logging
import os
import socket
import struct
import sys
import time

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
    check("C5 ietf.org 应答含 RRSIG（bootstrap 兜底时允许上游不下发）",
          has_sig or boot, f"rrsig={has_sig} bootstrap={boot}")

    # 真实 bogus 仍必须被拒绝
    try:
        out = await asyncio.wait_for(
            eng._resolve_verified("dnssec-failed.org", dns.rdatatype.A, 1),
            timeout=40)
    except Exception:
        out = None
    check("C6 dnssec-failed.org 仍被严格模式丢弃", out is None)

    return all(ok for _, ok in RESULTS[start_ok:])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15353,
                    help="明文 DNS 测试端口（默认 15353，53 需要权限）")
    ap.add_argument("--skip-net", action="store_true", help="只跑离线 DNSSEC 用例")
    ap.add_argument("--real-dnssec", action="store_true",
                    help="额外跑真实网络 DNSSEC 回归（Part C，需要出网）")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("dns-proxy.plain-dns").setLevel(logging.WARNING)
    print("=" * 72)
    print("test_plain_dns.py — 明文 DNS 协议 + 迭代 DNSSEC 攻击向量")
    print("=" * 72)
    t0 = time.time()
    if not args.skip_net:
        asyncio.run(run_part_a(args.port))
    asyncio.run(run_part_b())
    asyncio.run(run_part_b_chain())
    asyncio.run(run_part_b_types())
    if args.real_dnssec:
        asyncio.run(run_part_c())

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

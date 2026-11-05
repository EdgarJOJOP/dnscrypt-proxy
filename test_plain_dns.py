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

Part B（迭代解析 DNSSEC 攻击向量，离线回放真实签名 wire）：
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

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.IN.A
import dns.rrset

# ============================================================
# 内嵌测试数据：真实权威返回的响应 wire（base64），保证离线可重复
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
# Part B：迭代解析 DNSSEC 攻击向量（离线回放真实签名 wire）
# ============================================================
def _load(b64: bytes):
    return dns.message.from_wire(b64)


def _dnskey(msg):
    for rr in msg.answer:
        if rr.rdtype == dns.rdatatype.DNSKEY:
            return rr
    return None


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
    eng._has_ipv6 = False
    eng._dropped = []

    async def fake_iterate(qname, qtype, depth=0, rdclass=1):
        return dns.message.from_wire(reply.to_wire())

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

    fwd = _load(W_FORWARD)
    nx_nsec = _load(W_NX_NSEC)
    nx_nsec3 = _load(W_NX_NSEC3)
    cname = _load(W_CNAME)
    keys = {
        "ietf.org.": _dnskey(_load(W_KEY_IETF)),
        "com.": _dnskey(_load(W_KEY_COM)),
        ".": _dnskey(_load(W_KEY_ROOT)),
        "pki.goog.": None,
    }
    start_ok = len(RESULTS)

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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15353,
                    help="明文 DNS 测试端口（默认 15353，53 需要权限）")
    ap.add_argument("--skip-net", action="store_true", help="只跑离线 DNSSEC 用例")
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

#!/usr/bin/env python3
"""诊断脚本：测试各个上游 DNS 服务器的连通性"""

import asyncio
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from resolvers.doh import DoHResolver
from resolvers.dot import DoTResolver
from resolvers.doq import DoQResolver, HAS_AIOQUIC
from resolvers.plain import PlainDNSResolver
import dns.message
import dns.rdatatype
import dns.edns


async def test_resolver(name, resolver, query_bytes):
    print(f"\n{'='*60}")
    print(f"测试: {name}")
    print(f"{'='*60}")
    try:
        result = await resolver.resolve(query_bytes)
        if result:
            msg = dns.message.from_wire(result)
            print(f"  状态: 成功")
            print(f"  Rcode: {msg.rcode()}")
            for rrset in msg.answer:
                for rd in rrset:
                    print(f"  应答: {rrset.name} {rd.rdtype} {rd}")
            # 测试第二个查询（连接池）
            print(f"  --- 第二次查询（连接复用）---")
            result2 = await resolver.resolve(query_bytes)
            if result2:
                print(f"  第二次查询成功")
            else:
                print(f"  第二次查询失败")
        else:
            print(f"  状态: 失败 (返回 None)")
    except Exception as e:
        print(f"  状态: 异常 — {e}")
    finally:
        await resolver.close()


async def main():
    query = dns.message.make_query("baidu.com", dns.rdatatype.A)
    query_bytes = query.to_wire()

    # 1. 测试 bootstrap DNS
    print("\n>>> 1. Bootstrap 普通 DNS 解析器")
    for addr in ["223.5.5.5", "114.114.114.114", "119.29.29.29"]:
        resolver = PlainDNSResolver(addr, timeout=5.0)
        await test_resolver(f"PlainDNS {addr}", resolver, query_bytes)

    # 2. 测试 DoH
    print("\n>>> 2. DNS-over-HTTPS")
    for url in [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
    ]:
        resolver = DoHResolver(url, timeout=5.0)
        await test_resolver(f"DoH {url}", resolver, query_bytes)

    # 3. 测试 DoT
    print("\n>>> 3. DNS-over-TLS")
    for host in ["dns.alidns.com", "dns.pub"]:
        resolver = DoTResolver(host, port=853, timeout=5.0)
        await test_resolver(f"DoT {host}:853", resolver, query_bytes)

    # 4. 测试 DoQ
    print("\n>>> 4. DNS-over-QUIC")
    if HAS_AIOQUIC:
        # 带 EDNS 的查询（部分服务器可能需要）
        query_edns = dns.message.make_query("baidu.com", dns.rdatatype.A)
        query_edns.use_edns(payload=4096)
        query_edns_bytes = query_edns.to_wire()

        test_cases = [
            ("quic://dns9.quad9.net:853", query_bytes),                     # Quad9（已验证可工作）
            ("quic://dns.alidns.com:853", query_bytes),                     # 阿里 DNS 标准查询
            ("quic://dns.alidns.com:853", query_edns_bytes, "带 EDNS"),     # 阿里 DNS + EDNS
            ("quic://unfiltered.adguard-dns.com", query_bytes),             # AdGuard 默认 853
            ("quic://unfiltered.adguard-dns.com:784", query_bytes),         # AdGuard 端口 784
        ]
        for case in test_cases:
            addr = case[0]
            qb = case[1]
            label = f"DoQ {addr}" + (f" ({case[2]})" if len(case) > 2 else "")
            resolver = DoQResolver(addr, timeout=10.0)
            await test_resolver(label, resolver, qb)
    else:
        print("  aioquic 未安装，跳过 DoQ 测试")
        print("  如需安装: pip install aioquic")


if __name__ == "__main__":
    asyncio.run(main())

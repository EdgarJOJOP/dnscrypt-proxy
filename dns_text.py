import asyncio
import aiohttp
import ssl
import dns.message
import dns.rdatatype
import base64
from typing import List


class DoHWireFormatResolver:
    """
    遵循 RFC 8484 的 DNS-over-HTTPS 解析器（wire format）
    一次调用同时获取 A 和 AAAA 记录
    """

    def __init__(self, doh_url: str, ssl_context: ssl.SSLContext | bool | None = None):
        self.doh_url = doh_url.rstrip('/')
        self.ssl_context = ssl_context
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self.ssl_context)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._session

    async def _resolve_single(self, domain: str, rdtype: int) -> List[str]:
        """
        执行单一类型的 DNS 查询（A 或 AAAA）
        """
        query = dns.message.make_query(domain, rdtype)
        wire_data = query.to_wire()

        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        }
        session = await self._get_session()
        async with session.post(self.doh_url, data=wire_data, headers=headers) as resp:
            if resp.status != 200:
                raise RuntimeError(f"DoH {dns.rdatatype.to_text(rdtype)} 查询失败，HTTP {resp.status}")
            response_wire = await resp.read()
            response = dns.message.from_wire(response_wire)

        ips = []
        for answer in response.answer:
            if answer.rdtype == rdtype:
                for rdata in answer:
                    ips.append(str(rdata))
        return ips

    async def resolve(self, domain: str) -> List[str]:
        """
        同时获取 A 和 AAAA 记录，返回合并后的 IP 列表
        """
        # 并行查询 A 和 AAAA
        task_a = asyncio.create_task(self._resolve_single(domain, dns.rdatatype.A))
        task_aaaa = asyncio.create_task(self._resolve_single(domain, dns.rdatatype.AAAA))

        results = await asyncio.gather(task_a, task_aaaa, return_exceptions=True)

        # 合并结果，忽略异常（例如某些域名没有 AAAA 记录）
        ips = []
        for result in results:
            if isinstance(result, Exception):
                # 可以选择打印日志，但对于无记录的常见错误静默处理
                # print(f"查询异常（可能无此记录）: {result}")
                continue
            ips.extend(result)
        return ips

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


async def main():
    # 你的本地 dnscrypt-proxy DoH 地址
    doh_url = "https://127.0.0.1:8443/dns-query"

    # 测试时跳过 SSL 验证（生产环境请配置证书）
    resolver = DoHWireFormatResolver(doh_url, ssl_context=False)

    domains = ["baidu.com", "taobao.com", "qq.com", "google.com"]  # google.com 通常有 AAAA
    for domain in domains:
        try:
            ips = await resolver.resolve(domain)
            print(f"{domain:12} => {', '.join(ips) if ips else '<empty>'}")
        except Exception as e:
            print(f"{domain:12} ❌ {e}")

    await resolver.close()


if __name__ == "__main__":
    asyncio.run(main())
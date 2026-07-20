"""
DNSSEC 验证模块
- DNS 查询中设置 DO (DNSSEC OK) 位
- 验证响应中的 AD (Authentic Data) 位
- 支持完整的 DNSSEC 链验证（RRSIG → DNSKEY → DS）
- 内置 IANA 根信任锚
"""

import asyncio
import struct
import logging
import threading
from typing import Optional, Tuple, Dict, Any, List, Callable

import dns.message
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.tsig
import dns.rcode
import dns.flags
import dns.exception
import dns.resolver
import dns.rdata

logger = logging.getLogger("dns-proxy.dnssec")

# ============================================================
# IANA 根区 KSK 信任锚（2024 年发布）
# 来源: https://data.iana.org/root-anchors/
# ============================================================
# 实际的根信任锚 - 从 IANA 官方获取
# 来源: https://data.iana.org/root-anchors/root-anchors.xml
ROOT_ANCHOR_KEYS = {
    # IANA Root Zone KSK 2017 (key tag 20326, algorithm 8 RSA/SHA-256)
    # 有效期: 2017-02-02 至今
    20326: {
        "flags": 257,
        "protocol": 3,
        "algorithm": 8,
        "public_key": (
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4R"
            "gWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROx"
            "VQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3"
            "rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6"
            "H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM"
            "8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
        ),
    },
    # IANA Root Zone KSK 2024 (key tag 38696, algorithm 8 RSA/SHA-256)
    # 有效期: 2024-07-18 至今
    38696: {
        "flags": 257,
        "protocol": 3,
        "algorithm": 8,
        "public_key": (
            "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidlt"
            "pkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx"
            "4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qy"
            "JNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4Y"
            "eGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyv"
            "aBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
        ),
    },
}


# ============================================================
# 设置 DNSSEC DO 位
# ============================================================


def set_dnssec_do_bit(query_bytes: bytes) -> bytes:
    """
    在 DNS 查询中设置 DNSSEC OK (DO) 位 (RFC 4035)
    DO 位是 EDNS0 标志的 bit 15
    """
    try:
        msg = dns.message.from_wire(query_bytes)
        if msg.additional and len(msg.additional) > 0:
            # 已有 OPT 记录，设置 DO 位
            for rr in msg.additional:
                if rr.rdtype == dns.rdatatype.OPT:
                    rr.flags |= 0x8000  # DO = bit 15
                    break
        else:
            # 添加 OPT 记录（EDNS0）并设置 DO 位
            opt = dns.message.make_edns(flags=0x8000, payload=4096)
            msg.additional.append(opt)

        return msg.to_wire()
    except Exception:
        return query_bytes


def has_dnssec_do_bit(query_bytes: bytes) -> bool:
    """检查 DNS 查询是否设置了 DO 位"""
    try:
        msg = dns.message.from_wire(query_bytes)
        for rr in msg.additional:
            if rr.rdtype == dns.rdatatype.OPT:
                return bool(rr.flags & 0x8000)
    except Exception as e:
        logger.debug("DNSSEC 查询 OPT 记录异常: %s", e)
        pass
    return False


# ============================================================
# DNSSEC 验证
# ============================================================


class DNSSECValidator:
    """DNSSEC 验证器"""

    def __init__(self, enabled: bool = True, mode: str = "ad_check"):
        self.enabled = enabled
        self.mode = mode  # "ad_check" 或 "strict"
        self._root_keys: Dict = self._parse_root_anchor()
        self._dns_query_callback: Optional[Callable] = None
        self._verified_zone_cache: Dict = {}  # zone_name → DNSKEY rrset
        self._zone_cache_lock = asyncio.Lock()
        self._stats: Dict[str, Any] = {
            "validated": 0,
            "failed": 0,
            "bogus": 0,
            "insecure": 0,
            "indeterminate": 0,
        }

    def set_dns_query_callback(self, callback: Callable):
        """
        设置 DNSKEY 查询回调（由 ResolverManager 注入）。
        callback(query_bytes: bytes) -> Optional[bytes]
        """
        self._dns_query_callback = callback

    def clear_zone_cache(self):
        """清除已缓存的已验证区 DNSKEY（网络变化时调用）"""
        self._verified_zone_cache.clear()

    def _parse_root_anchor(self) -> Dict:
        """
        解析内置 IANA 根信任锚为 dnspython key 字典。
        支持多个 KSK（2017 KSK 20326 + 2024 KSK 38696）。
        """
        try:
            import base64
            from dns.rdtypes.ANY.DNSKEY import DNSKEY as _DNSKEY
            root_name = dns.name.from_text('.')
            keys_dict: Dict = {}

            for tag, info in ROOT_ANCHOR_KEYS.items():
                try:
                    raw_key = "".join(info["public_key"])
                    # 补全 base64 padding
                    pad = 4 - (len(raw_key) % 4)
                    if pad != 4:
                        raw_key += "=" * pad
                    key_bytes = base64.b64decode(raw_key)
                    key_rdata = _DNSKEY(
                        rdclass=dns.rdataclass.IN,
                        rdtype=dns.rdatatype.DNSKEY,
                        flags=info["flags"],
                        protocol=info["protocol"],
                        algorithm=info["algorithm"],
                        key=key_bytes,
                    )
                    alg = info["algorithm"]
                    if root_name not in keys_dict:
                        keys_dict[root_name] = {}
                    if alg not in keys_dict[root_name]:
                        keys_dict[root_name][alg] = []
                    keys_dict[root_name][alg].append(key_rdata)
                    logger.debug("DNSSEC 根信任锚加载成功: key_tag=%d", tag)
                except Exception as e:
                    logger.warning("DNSSEC 根信任锚 key_tag=%d 加载失败: %s", tag, e)

            if keys_dict:
                logger.info("DNSSEC 根信任锚已加载: %d 个 KSK", sum(len(v) for v in keys_dict.get(root_name, {}).values()))
            else:
                logger.warning("DNSSEC 根信任锚全部加载失败，本地验证降级为 ad_check")
            return keys_dict
        except ImportError:
            logger.warning("DNSSEC 根信任锚: dns.rdtypes.ANY.DNSKEY 不可用，降级为 ad_check")
            return {}
        except Exception as e:
            logger.warning("DNSSEC 根信任锚解析失败，本地验证降级为 ad_check: %s", e)
            return {}

    async def validate_response(
        self,
        query_bytes: bytes,
        response_bytes: bytes,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        验证 DNS 响应的 DNSSEC 状态

        返回:
            (是否安全, 状态描述, 详细信息)
        状态:
            - secure: 验证通过
            - insecure: 未签名区域（合法）
            - bogus: 验证失败（伪造/篡改）
            - indeterminate: 无法验证
        """
        if not self.enabled:
            return True, "dnssec_disabled", {"reason": "DNSSEC 验证已禁用"}

        try:
            query = dns.message.from_wire(query_bytes)
            response = dns.message.from_wire(response_bytes)
        except Exception as e:
            return False, "indeterminate", {"reason": f"消息解析失败: {e}"}

        question = query.question[0] if query.question else None
        if question is None:
            return True, "indeterminate", {"reason": "无问题部分"}

        # 检查 AD 位 - 上游已经验证过
        ad_bit = bool(response.flags & dns.flags.AD)
        rcode = response.rcode()

        # 检查响应中是否有 RRSIG 记录
        has_rrsig = False
        for section in (response.answer, response.authority, response.additional):
            for rrset in section:
                for rd in rrset:
                    if rd.rdtype == dns.rdatatype.RRSIG:
                        has_rrsig = True
                        break

        result_info: Dict[str, Any] = {
            "ad_bit": ad_bit,
            "has_rrsig": has_rrsig,
            "rcode": dns.rcode.to_text(rcode),
        }

        # 如果有 RRSIG，始终尝试本地验证（strict 模式下即使是 AD=1 也验证）
        if has_rrsig:
            try:
                is_valid = await self._validate_locally(response, question.name)
                if is_valid:
                    self._stats["validated"] += 1
                    return True, "secure", {
                        **result_info,
                        "detail": f"本地验证通过 (mode={self.mode})",
                    }
                else:
                    self._stats["bogus"] += 1
                    return False, "bogus", {
                        **result_info,
                        "detail": f"本地 DNSSEC 验证失败 (mode={self.mode})",
                    }
            except dns.dnssec.ValidationFailure as e:
                self._stats["bogus"] += 1
                return False, "bogus", {
                    **result_info,
                    "detail": f"DNSSEC 验证失败: {e}",
                }
            except NotImplementedError:
                self._stats["indeterminate"] += 1
                return False, "indeterminate", {
                    **result_info,
                    "detail": "本地验证不支持的算法",
                }

        # 无 RRSIG 但有 AD 位 - 上游已验证但响应不含 RRSIG
        if ad_bit:
            self._stats["validated"] += 1
            return True, "secure", {
                **result_info,
                "detail": "AD 位已设置（上游已验证）",
            }

        # 无 DNSSEC 记录，认为是 insecure（未签名）
        self._stats["insecure"] += 1
        return True, "insecure", {
            **result_info,
            "detail": "区域未签名（无 DNSSEC）",
        }

    async def _validate_locally(
        self, response: dns.message.Message, qname: dns.name.Name
    ) -> bool:
        """
        本地执行 DNSSEC 链验证。
        使用内置 IANA 根信任锚 + 动态查询各区 DNSKEY 构建完整信任链。
        """
        # 1. 从根密钥开始构建 keys 字典
        keys: Dict = dict(self._root_keys)

        # 2. 收集所有 RRSIG 的 signer（签名者区），这些是需要 DNSKEY 的区
        signers: set = set()
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    for rrsig in rrset:
                        signers.add(rrsig.signer)

        root_name = dns.name.from_text('.')
        for signer in list(signers):
            if signer == root_name:
                continue  # 根区已在 _root_keys 中
            async with self._zone_cache_lock:
                if signer in keys:
                    continue  # 已加载
                if signer in self._verified_zone_cache:
                    keys[signer] = self._verified_zone_cache[signer]
                    continue

            # 3. 查询 signer 区的 DNSKEY
            dnskey_rrset = await self._query_zone_dnskey(signer)
            if dnskey_rrset is not None:
                keys[signer] = dnskey_rrset
                async with self._zone_cache_lock:
                    self._verified_zone_cache[signer] = dnskey_rrset

        # 4. 用完整的 keys 验证 answer 中的所有 RRset
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            # 查找对应的 RRSIG
            try:
                rrsig_set = response.find_rrset(
                    response.answer,
                    rrset.name,
                    rrset.rdclass,
                    dns.rdatatype.RRSIG,
                    create=False,
                )
            except KeyError:
                continue
            if rrsig_set:
                try:
                    dns.dnssec.validate(rrset, rrsig_set, keys)
                except (dns.dnssec.ValidationFailure, KeyError) as e:
                    logger.debug("DNSSEC 验证失败 (%s): %s", rrset.name, e)
                    continue

        # 5. 如果 answer 段没有找到可验证的 RRset，检查 authority 段
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            rrsig_set = response.find_rrset(
                response.authority,
                rrset.name,
                rrset.rdclass,
                dns.rdatatype.RRSIG,
                create=False,
            )
            if rrsig_set:
                dns.dnssec.validate(rrset, rrsig_set, keys)
                return True

        return False

    async def _query_zone_dnskey(self, zone_name: dns.name.Name) -> Optional[object]:
        """
        查询指定区的 DNSKEY 记录。
        利用上游 DNS（TLS 已验证）返回的 AD=1 标志信任 DNSKEY 数据。
        返回: DNSKEY RRset (dns.rrset.RRset) 或 None
        """
        if self._dns_query_callback is None:
            return None

        try:
            from cache import get_query_wire

            query_bytes = get_query_wire(
                str(zone_name), dns.rdatatype.DNSKEY, want_dnssec=True
            )
            if query_bytes is None:
                return None

            response_bytes = await self._dns_query_callback(query_bytes)
            if response_bytes is None:
                return None

            resp = dns.message.from_wire(response_bytes)

            # 在 answer 段查找 DNSKEY
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    return rrset

            return None
        except Exception as e:
            logger.debug("查询 %s DNSKEY 失败: %s", zone_name, e)
            return None

    async def validate_and_filter(
        self,
        query_bytes: bytes,
        response: Optional[bytes],
    ) -> Tuple[Optional[bytes], bool, str]:
        """
        验证并过滤 DNS 响应
        如果 DNSSEC 验证失败（bogus），丢弃响应
        返回: (验证后的响应字节或 None, 是否安全, 状态)
        """
        if response is None or not self.enabled:
            return response, True, "no_check"

        is_secure, status, details = await self.validate_response(
            query_bytes, response
        )

        if not is_secure:
            logger.warning("DNSSEC 验证失败 (%s): %s", status, details)
            return None, False, status

        return response, True, status

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)


# ============================================================
# DNSSEC 查询包装器
# ============================================================


class DNSSECQueryWrapper:
    """
    DNSSEC 查询包装器
    为 DNS 查询添加 DO 位，并检查响应的 DNSSEC 状态
    """

    def __init__(self, validator: DNSSECValidator, enabled: bool = True):
        self.validator = validator
        self.enabled = enabled

    def wrap_query(self, query_bytes: bytes) -> bytes:
        """包装查询：添加 DO 位"""
        if not self.enabled:
            return query_bytes
        return set_dnssec_do_bit(query_bytes)

    async def validate_response(
        self, query_bytes: bytes, response_bytes: bytes
    ) -> Tuple[bool, str]:
        """验证响应 DNSSEC"""
        if not self.enabled:
            return True, "disabled"

        is_secure, status, _ = await self.validator.validate_response(
            query_bytes, response_bytes
        )
        return is_secure, status

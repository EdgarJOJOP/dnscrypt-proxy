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
import time
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

    修复：原实现用 `dns.message.make_edns(flags=0x8000)`（dnspython 参数名是
    ednsflags，flags= 会抛 TypeError）且对已存在的 OPT RRset 写 `rr.flags`
    （RRset 没有该属性），异常被裸 `except` 吞掉后**静默返回未加 DO 的查询**——
    导致上游从不返回 RRSIG，本地 DNSSEC 验证形同虚设。
    现统一走 dnspython 的 EDNS 接口。
    """
    try:
        msg = dns.message.from_wire(query_bytes)
        if msg.edns < 0:
            # 无 OPT：新增 EDNS0 并置 DO
            msg.use_edns(0, payload=1232, ednsflags=dns.flags.DO)
        else:
            # 已有 OPT：直接置 DO 位（ednsflags 可写）
            msg.ednsflags |= dns.flags.DO
        return msg.to_wire()
    except Exception as e:
        logger.debug("设置 DO 位失败: %s", e)
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

    def __init__(self, enabled: bool = True, mode: str = "ad_check",
                 require_rrsig: bool = False):
        self.enabled = enabled
        self.mode = mode  # "ad_check" 或 "strict"
        # strict 下“无 RRSIG 且父区有 DS”是否直接判 bogus。
        # 默认 False（fail-open）：现实中大量上游（阿里/腾讯 DoH 等）即使
        # 客户端带了 DO 也不返回 RRSIG，若一律判剥离会让所有域名解析失败。
        self.require_rrsig = require_rrsig
        self._root_keys: Dict = self._parse_root_anchor()
        self._dns_query_callback: Optional[Callable] = None
        self._verified_zone_cache: Dict = {}  # zone_name → DNSKEY rrset
        # zone_name → (has_ds, expire_at)：避免重复逐级查 DS
        # （仅在 require_rrsig=True、需要判定“是否被剥离”时才会用到）
        self._zone_ds_cache: Dict[str, Tuple[Optional[bool], float]] = {}
        # 防刷屏：默认 fail-open 下的“上游响应不带 RRSIG”提示全局只打印一次
        self._warned_no_rrsig = False
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

        # mode 语义（与 config.yaml 注释对齐）：
        #   ad_check - 优先信任上游 AD 位（快速）；AD=0 时对 RRSIG 做本地验证
        #   strict   - 始终本地验证 RRSIG 签名链（安全但较慢）
        if has_rrsig and (self.mode == "strict" or not ad_bit):
            try:
                is_valid = await self._validate_locally(response, question.name)
                if is_valid is True:
                    self._stats["validated"] += 1
                    return True, "secure", {
                        **result_info,
                        "detail": f"本地链验证通过 (mode={self.mode})",
                    }
                elif is_valid is False:
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
                return True, "indeterminate", {
                    **result_info,
                    "detail": "本地验证不支持的算法（放行）",
                }
        elif has_rrsig and ad_bit and self.mode == "ad_check":
            # ad_check + 上游已验证（AD=1）→ 直接信任，不做本地链验证
            self._stats["validated"] += 1
            return True, "secure", {
                **result_info,
                "detail": "AD 位已设置（上游已验证，ad_check 模式）",
            }

        # 无 RRSIG 但有 AD 位 - 上游已验证但响应不含 RRSIG
        if ad_bit:
            self._stats["validated"] += 1
            return True, "secure", {
                **result_info,
                "detail": "AD 位已设置（上游已验证）",
            }

        # strict 模式：无 RRSIG 且无 AD 时的处理
        #
        # 实测：阿里/腾讯等国内 DoH 上游即使收到 DO=1 也不返回 RRSIG，
        # 因此“无 RRSIG”并不能证明“签名被剥离”。默认 fail-open（insecure 放行，
        # 仅记日志）；只有显式开启 require_rrsig 时才按 bogus 拒绝。
        if self.mode == "strict" and self.require_rrsig:
            has_ds = await self._zone_has_ds(question.name)
            if has_ds is True:
                self._stats["bogus"] += 1
                return False, "bogus", {
                    **result_info,
                    "detail": "父区有 DS 但响应无 RRSIG（签名被剥离）",
                }
        elif self.mode == "strict" and not self._warned_no_rrsig:
            # 默认 fail-open：该响应无论如何都会按 insecure 放行，因此这里不再
            # 逐级查询 DS（其结果仅用于措辞，却要给每个新域名增加多次 DNS 往返），
            # 并且整条提示全局只打印一次，避免日志刷屏。
            self._warned_no_rrsig = True
            logger.warning(
                "DNSSEC：strict 模式下检测到上游响应不带 RRSIG"
                "（上游可能不支持 DNSSEC 数据传输），已按 insecure 放行；"
                "此提示全局只显示一次（首个示例域名: %s）。"
                "如需拒绝此类响应，请开启 dnssec.require_rrsig",
                question.name,
            )

        # 无 DNSSEC 记录，认为是 insecure（未签名）
        self._stats["insecure"] += 1
        return True, "insecure", {
            **result_info,
            "detail": "区域未签名（无 DNSSEC）",
        }

    async def _zone_has_ds(self, qname: dns.name.Name) -> Optional[bool]:
        """逐级向上查询父区 DS，判断该名字所在区是否应为签名区。

        返回 True（找到 DS，该区应有 RRSIG）/ False（沿链均无 DS，未签名）/
        None（无法判定：无回调、查询失败或超时）。任何不确定一律返回 None，
        调用方据此保持原有的 insecure 行为（fail-open），避免误杀普通域名。
        """
        if self._dns_query_callback is None:
            return None
        cache_key = str(qname).lower()
        cached = self._zone_ds_cache.get(cache_key)
        if cached is not None and time.time() < cached[1]:
            return cached[0]

        async def _lookup() -> Optional[bool]:
            return await self._zone_has_ds_uncached(qname)

        result = await _lookup()
        # 缓存 300s（含无法判定），避免逐级 DS 查询成为热点开销
        self._zone_ds_cache[cache_key] = (result, time.time() + 300)
        if len(self._zone_ds_cache) > 2048:
            self._zone_ds_cache.clear()
        return result

    async def _zone_has_ds_uncached(self, qname: dns.name.Name) -> Optional[bool]:
        """逐级向上查询父区 DS（无缓存路径）"""
        try:
            name = qname.parent()
        except Exception:
            return None
        for _ in range(8):
            if name == dns.name.root:
                return False
            try:
                q = dns.message.make_query(name, dns.rdatatype.DS)
                q.use_edns(0, payload=1232, ednsflags=dns.flags.DO)
                resp_bytes = await asyncio.wait_for(
                    self._dns_query_callback(q.to_wire()), timeout=2.0
                )
                if resp_bytes is None:
                    return None
                resp = dns.message.from_wire(resp_bytes)
            except Exception:
                return None
            if any(rr.rdtype == dns.rdatatype.DS for rr in resp.answer):
                return True
            # 无 DS：只有拿到 NSEC/NSEC3 否定证明才能确认"该区未签名"
            if any(
                rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                for rr in (list(resp.answer) + list(resp.authority))
            ):
                return False
            name = name.parent()
        return None

    # ---------- DNSSEC 信任链（逐级 DS → DNSKEY 验证） ----------

    def _root_anchor_rrset(self) -> Optional[dns.rrset.RRset]:
        """内置 IANA 根信任锚 → dnspython 验签所需的 RRset 形式

        注意：self._root_keys 的结构是 {name: {algorithm: [rdata,...]}}，不能直接
        作为 dns.dnssec.validate(..., keys) 的 keys 参数（它要求 {name: RRset}）；
        原实现直接传 dict 会让所有由根签名的 RRset 验签失败。
        """
        for root_name, alg_map in self._root_keys.items():
            rrset = dns.rrset.RRset(root_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            if isinstance(alg_map, dict):
                for rdata_list in alg_map.values():
                    for rd in rdata_list:
                        rrset.add(rd)
            else:
                for rd in alg_map:
                    rrset.add(rd)
            return rrset
        return None

    @staticmethod
    def _find_rrsig_for(msg, section, rrset):
        """从指定段中找 covers 匹配的 RRSIG 集合（dnspython 2.x 需按 covers 匹配）"""
        try:
            return msg.find_rrset(
                section, rrset.name, rrset.rdclass,
                dns.rdatatype.RRSIG, covers=rrset.rdtype, create=False,
            )
        except Exception:
            return None

    async def _query_rrset(self, zone: dns.name.Name, rdtype: int):
        """查询 zone 的指定 RR 类型，返回 (rrset, rrsig_set)；任一缺失返回 (None, None)"""
        if self._dns_query_callback is None:
            return None, None
        try:
            from cache import get_query_wire

            query_bytes = get_query_wire(str(zone), rdtype, want_dnssec=True)
            if query_bytes is None:
                return None, None
            response_bytes = await self._dns_query_callback(query_bytes)
            if response_bytes is None:
                return None, None
            resp = dns.message.from_wire(response_bytes)
        except Exception as e:
            logger.debug("查询 %s %s 失败: %s", zone, dns.rdatatype.to_text(rdtype), e)
            return None, None

        target = None
        for rrset in resp.answer:
            if rrset.rdtype == rdtype:
                target = rrset
                break
        if target is None:
            return None, None
        return target, self._find_rrsig_for(resp, resp.answer, target)

    @staticmethod
    def _ds_matches_dnskey(ds_rdata, zone_name: dns.name.Name, dnskey_rdata) -> bool:
        """RFC 4034 §5.1.4：DS digest = hash(canonical owner || DNSKEY rdata)"""
        try:
            import hashlib

            owner_wire = zone_name.to_wire(canonicalize=True)
            key_wire = dnskey_rdata.to_wire()
            if ds_rdata.digest_type == 1:
                digest = hashlib.sha1(owner_wire + key_wire).digest()
            elif ds_rdata.digest_type == 2:
                digest = hashlib.sha256(owner_wire + key_wire).digest()
            elif ds_rdata.digest_type == 4:
                digest = hashlib.sha384(owner_wire + key_wire).digest()
            else:
                return False
            return digest == ds_rdata.digest
        except Exception:
            return False

    async def _get_verified_zone_keys(self, zone: dns.name.Name, depth: int = 0):
        """沿 DS→DNSKEY 链逐级数学验证，返回 (status, keys)

        status:
          "secure"        — keys 含该区已验证的 DNSKEY（以及整条父链）
          "insecure"      — 父区确无 DS（该区本可未签名，合法）
          "bogus"         — 链上明确验证失败（伪造/篡改）
          "indeterminate" — 上游无数据/查询失败，无法判定
        """
        if depth > 8:
            return "indeterminate", {}
        root_name = dns.name.from_text(".")
        root_anchor = self._root_anchor_rrset()
        if root_anchor is None:
            return "indeterminate", {}

        if zone == root_name:
            # 根区：用内置根锚验证根 DNSKEY，得到含 ZSK 的完整根密钥集
            dnskey_rrset, sigs = await self._query_rrset(zone, dns.rdatatype.DNSKEY)
            if dnskey_rrset is None or sigs is None:
                return "indeterminate", {root_name: root_anchor}
            try:
                dns.dnssec.validate(dnskey_rrset, sigs, {root_name: root_anchor})
            except dns.dnssec.ValidationFailure:
                return "bogus", {}
            except Exception:
                return "indeterminate", {root_name: root_anchor}
            return "secure", {root_name: dnskey_rrset}

        cached = self._verified_zone_cache.get(zone)
        if cached is not None:
            return "secure", {zone: cached}

        parent_status, parent_keys = await self._get_verified_zone_keys(
            zone.parent(), depth + 1
        )
        if parent_status != "secure":
            return parent_status, {}

        # 父区 DS：查询不到 DS 记录 = insecure 委托（RFC 4035 §5.2 的合法情形）
        ds_rrset, ds_sigs = await self._query_rrset(zone, dns.rdatatype.DS)
        if ds_rrset is None:
            return "insecure", {}
        if ds_sigs is None:
            return "indeterminate", {}
        try:
            dns.dnssec.validate(ds_rrset, ds_sigs, parent_keys)
        except dns.dnssec.ValidationFailure:
            return "bogus", {}
        except Exception:
            return "indeterminate", {}

        dnskey_rrset, sigs = await self._query_rrset(zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None or sigs is None:
            return "indeterminate", {}

        # DS digest 匹配出父区授权的 KSK，再用它验证 DNSKEY 集合的自签
        auth_ksk = None
        for ds in ds_rrset:
            for key in dnskey_rrset:
                if self._ds_matches_dnskey(ds, zone, key):
                    auth_ksk = key
                    break
            if auth_ksk is not None:
                break
        if auth_ksk is None:
            return "bogus", {}
        ksk_rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        ksk_rrset.add(auth_ksk)
        try:
            dns.dnssec.validate(dnskey_rrset, sigs, {zone: ksk_rrset})
        except dns.dnssec.ValidationFailure:
            return "bogus", {}
        except Exception:
            return "indeterminate", {}

        if len(self._verified_zone_cache) > 512:
            self._verified_zone_cache.clear()
        self._verified_zone_cache[zone] = dnskey_rrset
        keys = dict(parent_keys)
        keys[zone] = dnskey_rrset
        return "secure", keys

    async def _validate_locally(
        self, response: dns.message.Message, qname: dns.name.Name
    ) -> Optional[bool]:
        """本地 DNSSEC 链验证（三态）

        返回 True=验证通过；False=链上明确失败或签名无效（bogus）；
        None=无法判定（上游不返回 DS/DNSKEY 等），由调用方按 fail-open 处理。
        """
        root_name = dns.name.from_text(".")
        root_anchor = self._root_anchor_rrset()
        keys: Dict = {root_name: root_anchor} if root_anchor is not None else {}

        # 1. 收集签名者区（需要这些区的 DNSKEY）
        signers: set = set()
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    for rrsig in rrset:
                        signers.add(rrsig.signer)

        # 2. 逐级 DS 验证取回可信 DNSKEY
        indeterminate = False
        for signer in signers:
            if signer in keys:
                continue
            status, zkeys = await self._get_verified_zone_keys(signer)
            if status == "bogus":
                logger.warning("DNSSEC 链验证失败（bogus）: %s", signer)
                return False
            if status == "secure":
                keys.update(zkeys)
            else:
                # insecure / indeterminate：该 signer 无可用可信 key
                indeterminate = True

        # 3. 用可信 keys 验签 answer / authority 中的 RRset
        validated = False
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                rrsig_set = self._find_rrsig_for(response, section, rrset)
                if rrsig_set is None:
                    continue
                signer = rrsig_set[0].signer
                if signer not in keys:
                    indeterminate = True
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, keys)
                    validated = True
                except dns.dnssec.ValidationFailure as e:
                    logger.debug("DNSSEC 验签失败 (%s): %s", rrset.name, e)
                    return False
                except Exception as e:
                    logger.debug("DNSSEC 验证异常 (%s): %s", rrset.name, e)
                    indeterminate = True

        if validated:
            return True
        return None if indeterminate else False

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

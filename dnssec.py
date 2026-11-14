"""
DNSSEC 验证模块
- DNS 查询中设置 DO (DNSSEC OK) 位
- 验证响应中的 AD (Authentic Data) 位
- 支持完整的 DNSSEC 链验证（RRSIG → DNSKEY → DS）
- 内置 IANA 根信任锚
"""

import asyncio
import contextvars
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

# 每次 validate_response 独立的“链查询是否遇到非权威应答”标记。
# 不能用实例属性：DNSSECValidator 被所有并发查询共享，A 查询在 await
# DS 查询期间设置 True，B 查询随后把它重置/读取，会互相污染，导致
# 合法未签名域名被误判 bogus 或攻击应答被误放行。
_LINK_UNTRUSTED: contextvars.ContextVar = contextvars.ContextVar(
    "dnssec_link_untrusted", default=False)
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
        # 链路级信任源可用性（根锚 → 根 DNSKEY 验证）：缓存 30 分钟 / 60 秒
        self._root_avail = False
        self._root_avail_expire = 0.0
        # 「name 是否为父区委托点」缓存：name → (bool, expire_at)。
        # 用于 DS NODATA 无否定证明时区分「委托点 apex」与「区内普通名」，
        # 防止把父区自己的 DS 误当成子区已签名（详见 _zone_has_ds_uncached）。
        self._delegation_cache: Dict[str, Tuple[Optional[bool], float]] = {}
        # dnspython 的 dns.dnssec.validate() 需要 cryptography；缺失时验签会抛
        # ImportError。这里显式检测，避免把“无法验签”静默当成“未签名/放行”。
        self._crypto_ok = True
        try:
            import cryptography  # noqa: F401
        except Exception as _crypto_err:
            self._crypto_ok = False
            logger.error(
                "DNSSEC 验签后端不可用（缺少 cryptography：%s）。"
                "本地 RRSIG/DS 链验证将无法进行，严格模式不会把结果判为 secure；"
                "请执行 pip install cryptography", _crypto_err,
            )
        # 「链查询是否遇到非权威应答」是**每次验证独立**的 ContextVar，
        # 见模块顶部 _LINK_UNTRUSTED；不能放实例属性（并发共享会串味）。
        # 已验证为 signed 的区（signer 名）：用于防“先验通过、后剥离签名”
        # 的降级攻击——同一区后续无 RRSIG 时必须仍判 bogus，不能因为
        # 链路暂时拿不到否定证明就放行。
        self._signed_zones: set = set()
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
        cname_hop: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        验证 DNS 响应的 DNSSEC 状态

        `cname_hop=True`：这是 CNAME 链的**中间跳**（只有 CNAME、没有最终
        答案）。此时只验证 RRset 签名/所在区状态，不做「负应答必须有
        SOA+NSEC/NSEC3」的语义校验——中间跳本来就没有最终答案。
        最终响应仍必须走完整负应答语义（重放防护）。

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

        # 每次验证重新采样“链查询是否遇到非权威应答”
        _LINK_UNTRUSTED.set(False)

        # 检查 AD 位 - 上游已经验证过
        ad_bit = bool(response.flags & dns.flags.AD)
        rcode = response.rcode()

        # 检查响应中是否有 RRSIG 记录（只统计 answer/authority：
        # additional 里的 RRSIG 不参与 RRset 验签，不能据此判定“已签名”）
        has_rrsig = False
        for section in (response.answer, response.authority):
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
                is_valid = await self._validate_locally(
                    response, question.name, question.rdtype,
                    cname_hop=cname_hop)
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
                else:
                    # 验签后端缺失 + require_rrsig=true：安全优先，fail-closed
                    if self.require_rrsig and not getattr(
                            self, "_crypto_ok", True):
                        self._stats["bogus"] += 1
                        return False, "bogus", {
                            **result_info,
                            "detail": "验签后端缺失且 require_rrsig=true（fail-closed）",
                        }
                    # 有 RRSIG 但链上暂时取不到 key（indeterminate）：
                    # 不是伪造，按可用性放行；绝不能落到下面“无 RRSIG”的
                    # 严格分支（那会把冷启动链超时判成签名被剥离）。
                    self._stats["indeterminate"] += 1
                    return True, "indeterminate", {
                        **result_info,
                        "detail": "链暂时不可用（indeterminate，不判 bogus）",
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

        # 无 RRSIG 但有 AD 位：**只有 ad_check 模式**才能信任上游 AD。
        # strict 模式的语义是“始终本地验证 RRSIG 签名链”，不能凭 AD 位
        # 就把无签名应答判 secure——否则攻击者只要设置 AD=1 就能绕过
        # strict/require_rrsig（RFC 4035 §3.2.3：AD 只应由可信验证者设置）。
        if ad_bit and self.mode == "ad_check":
            self._stats["validated"] += 1
            return True, "secure", {
                **result_info,
                "detail": "AD 位已设置（上游已验证）",
            }

        # strict 模式：无 RRSIG 时的统一语义（2026-11-14 统一验证链）
        #
        # 用户确认：**已证明整条链没有签名（insecure）才放行**；
        #   - 父区有 DS（secure）→ 无 RRSIG = 签名被剥离 → bogus；
        #   - 无法证明（unknown，例如链路上的 NSEC3 被剥离）→ fail-closed。
        # 旧实现按 require_rrsig=false 一律 fail-open，会让“重放无签名应答”
        # 通过，与 test_plain_dns D6 的安全回归直接冲突。
        if self.mode == "strict":
            # 链路级降级：根锚/根 DNSKEY 都不可用 → 本链路根本不提供
            # DNSSEC 材料（absent），按 require_rrsig=false 的语义放行。
            # 这与“unknown（有根锚但拿不到否定证明）”必须区分：后者 fail-closed。
            if not await self._root_chain_available():
                if self.require_rrsig:
                    self._stats["bogus"] += 1
                    return False, "bogus", {
                        **result_info,
                        "detail": "链路不提供 DNSSEC 材料且 require_rrsig=true（fail-closed）",
                    }
                self._stats["insecure"] += 1
                return True, "insecure", {
                    **result_info,
                    "detail": "链路不提供 DNSSEC 材料（根锚不可用），降级放行",
                }
            has_ds = await self._zone_has_ds(question.name)
            if has_ds is False:
                self._stats["insecure"] += 1
                return True, "insecure", {
                    **result_info,
                    "detail": "父区已证明无 DS（未签名链，合法放行）",
                }
            # 该名字所在区此前已通过验签：现在无 RRSIG = 剥离/降级攻击。
            # 即使链路暂时拿不到否定证明，也不能按“镜像不可验证”放行。
            # （父区已证明无 DS 的情况已在上面放行，优先级更高。）
            try:
                _nm = question.name
                _known_signed = any(
                    _nm == _z or _nm.is_subdomain(_z)
                    for _z in getattr(self, "_signed_zones", ()))
            except Exception:
                _known_signed = False
            if _known_signed:
                self._stats["bogus"] += 1
                return False, "bogus", {
                    **result_info,
                    "detail": "该区此前已验证签名，本次无 RRSIG（剥离/降级攻击）",
                }
            # 父区 DS 应答是**非权威**的（AA=0：递归镜像/中间盒）：
            # 否定证明不是“被剥离”，而是这条路根本拿不到证明。按配置
            # require_rrsig=false 的可用性语义放行（标记 insecure），
            # 避免合法未签名域名被永久判 bogus；require_rrsig=true 仍 fail-closed。
            if (not self.require_rrsig
                    and _LINK_UNTRUSTED.get()):
                self._stats["insecure"] += 1
                return True, "insecure", {
                    **result_info,
                    "detail": (
                        "父区 DS 应答非权威（链路剥离 DNSSEC 证明），"
                        "require_rrsig=false 按未验证放行"),
                }
            self._stats["bogus"] += 1
            return False, "bogus", {
                **result_info,
                "detail": (
                    "无 RRSIG 且无法证明未签名"
                    "（父区有 DS 或无可验证的否定证明）"),
            }

        # 非 strict（ad_check）：无 DNSSEC 记录按 insecure 放行
        self._stats["insecure"] += 1
        return True, "insecure", {
            **result_info,
            "detail": "区域未签名（无 DNSSEC）",
        }

        # 无 DNSSEC 记录，认为是 insecure（未签名）
        self._stats["insecure"] += 1
        return True, "insecure", {
            **result_info,
            "detail": "区域未签名（无 DNSSEC）",
        }

    async def _root_chain_available(self) -> bool:
        """链路是否具备可用的 DNSSEC 信任源（根锚 → 根 DNSKEY 验证成功）

        用途：strict 模式无 RRSIG 时区分两种语义：
          * 根锚/根 DNSKEY 都不可用（absent）→ 本链路根本不提供 DNSSEC
            材料，按 require_rrsig=false 降级放行（可用性）；
          * 根锚可用、但拿不到该名字的否定证明（unknown）→ fail-closed。
        后者是“可能被剥离”，不能放行（test_plain_dns D6）。
        """
        now = time.time()
        if now < getattr(self, "_root_avail_expire", 0.0):
            return getattr(self, "_root_avail", False)
        ok = False
        try:
            status, _keys = await self._get_verified_zone_keys(dns.name.root)
            ok = (status == "secure")
        except Exception:
            ok = False
        self._root_avail = ok
        self._root_avail_expire = now + (1800.0 if ok else 60.0)
        return ok

    async def _zone_has_ds(self, qname: dns.name.Name) -> Optional[bool]:
        """逐级向上查询父区 DS，判断该名字所在区是否应为签名区。

        返回 True（找到 DS，该区应有 RRSIG）/ False（沿链均无 DS，未签名）/
        None（无法判定：无回调、查询失败或超时）。任何不确定一律返回 None，
        调用方据此保持原有的 insecure 行为（fail-open），避免误杀普通域名。
        """
        if self._dns_query_callback is None:
            return None
        # 父区已被证明未签名 → 本名字一定在未签名树下，无需再为它单独
        # 查 DS/否定证明。否则镜像链路偶尔拿不到 NSEC3 时，同一未签名
        # 域名会时好时坏（coinglass 生产日志即此形态）。
        # 根的直接子区（如 com.）不能套用：根没有 DS，但根是信任锚。
        if qname != dns.name.root and qname.parent() != dns.name.root:
            try:
                if await self._parent_is_insecure(qname):
                    return False
            except Exception:
                pass
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

    # ---- NSEC/NSEC3 否定证明（仅用于「DS NODATA 是否成立」的判定） ----

    @staticmethod
    def _nsec_has_type(nsec_rdata, rdtype: int) -> bool:
        """检查 NSEC/NSEC3 rdata 的类型位图是否包含指定类型

        NSEC（RFC 4034 §4.1.2）：windows 是 (window, bitmap) 的可迭代；
        NSEC3（RFC 5155 §3.2）：windows 布局不同，改用 to_text 解析类型列表。
        与 `plain_dns_server.IterativeResolver._nsec_has_type` 完全一致，
        避免两个模块对同一份数据给出不同结论。
        """
        try:
            from dns.rdtypes.ANY.NSEC3 import NSEC3 as NSEC3Cls
            if isinstance(nsec_rdata, NSEC3Cls):
                parts = nsec_rdata.to_text().split()
                parsed_any = False
                for p in parts[5:]:
                    try:
                        parsed_any = True
                        if dns.rdatatype.from_text(p) == rdtype:
                            return True
                    except Exception:
                        continue
                if parsed_any:
                    return False
                # NSEC3 最小记录（RFC 5155 §3.2.1）：隐含 NS + RRSIG + NSEC3
                return rdtype in (dns.rdatatype.NS, dns.rdatatype.RRSIG,
                                  dns.rdatatype.NSEC3)
            for window, bitmap in nsec_rdata.windows:
                if rdtype // 256 == window:
                    byte = rdtype % 256 // 8
                    bit = 0x80 >> (rdtype % 8)
                    return bool(bitmap[byte] & bit) if byte < len(bitmap) else False
        except Exception:
            return False
        return False

    @staticmethod
    def _nsec3_hash(name: dns.name.Name, salt: bytes, iterations: int,
                    algorithm: int) -> bytes:
        """RFC 5155 §5：NSEC3 hash（SHA-1 迭代，algorithm=1）

        iterations 上限 150（RFC 9276 §3 建议值），防响应驱动的 CPU 放大攻击；
        超限返回 b""（=无法验证），调用方按"无证明"处理。
        """
        import hashlib
        if algorithm != 1:
            return b""
        try:
            if iterations < 0 or iterations > 150:
                return b""
        except Exception:
            return b""
        try:
            h = name.to_wire(canonicalize=True)
            for _ in range(iterations + 1):
                h = hashlib.sha1(h + salt).digest()
            return h
        except Exception:
            return b""

    @staticmethod
    def _nsec3_owner_hash(owner: dns.name.Name) -> bytes:
        """NSEC3 owner 名的 hash bytes（base32hex，RFC 4648 §7）"""
        import base64
        try:
            label = str(owner).split(".")[0].upper()
            table = str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV",
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            b32 = label.translate(table)
            pad = "=" * ((8 - len(b32) % 8) % 8)
            return base64.b32decode(b32 + pad)
        except Exception:
            return b""

    @staticmethod
    def _hash_in_interval(target: bytes, owner: bytes, nxt: bytes) -> bool:
        """NSEC3 hash 是否落在 (owner, next) 区间（含回绕，RFC 5155 §8.4）

        target == owner（该名字本身存在）或 target == next（下一条记录存在）
        都不算"覆盖"，否则会把真实存在的签名委托误判为不存在。
        """
        if not target or not owner or not nxt:
            return False
        if target == owner or target == nxt:
            return False
        if owner == nxt:
            # 自指记录（单名 zone）不覆盖任何 hash。缺这个判断时
            # `target > owner or target < nxt` 在 owner==nxt 时几乎恒真，
            # 会把任意 target 判成“被覆盖”，与
            # IterativeResolver._nsec3_interval_check 的语义不一致。
            return False
        if owner < nxt:
            return owner < target < nxt
        return target > owner or target < nxt

    @staticmethod
    def _nsec3_optout(rdata) -> bool:
        """NSEC3 flags 的 Opt-Out 位（RFC 5155 §3.1.2.1）"""
        try:
            return bool(int(getattr(rdata, "flags", 0)) & 0x01)
        except Exception:
            return False

    @staticmethod
    def _nsec_covers(nsec_rdata, nsec_owner: dns.name.Name,
                     target: dns.name.Name) -> bool:
        """NSEC 是否覆盖 target（NXDOMAIN 纯区间语义，RFC 4034 §4.1.1）

        从 plain_dns_server 迁移：owner < target < next（canonical 序）。
        owner==target 时 NSEC 存在本身证明 target 存在（NODATA 语义），
        不属于 NXDOMAIN 覆盖；next==target 同理（下一条记录存在）。
        自指记录（owner==next，单名 zone）不覆盖任何名字。
        """
        try:
            nxt = nsec_rdata.next
            if nsec_owner == target:
                return False
            if target == nxt:
                return False
            if nsec_owner < target < nxt:
                return True
            if nxt <= nsec_owner:
                if nxt == nsec_owner:
                    return False
                return target > nsec_owner or target < nxt
            return False
        except Exception:
            return False

    def _validate_negative_semantics(self, response, qname: dns.name.Name,
                                     qtype: int,
                                     verified_ids=None) -> Optional[bool]:
        """负应答（NXDOMAIN/NODATA）的 NSEC/NSEC3 区间语义校验

        从 `plain_dns_server` 迁移到 dnssec.py——签名验证只能证明
        「这条 NSEC/SOA 是某区真实签署的」，不能证明「它覆盖/匹配本次
        qname」。缺这一层，攻击者可以重放任意签名区的 NSEC + SOA 伪造
        否定应答（test_plain_dns Part B 用例 1/2/9 就是这类攻击）。

        返回 True=否定证明成立；False=不成立（重放/跨区/缺少 SOA 等）；
        None=响应里没有 NSEC/NSEC3（调用方按“无证明”处理）。

        `verified_ids`：已通过链验签的 rrset id() 集合；传入时只采纳这些，
        防止有效 NSEC 旁混入伪造 NSEC 让本函数采纳。

        SOA 归属按 RFC 2308 §2.1 先完整扫描再判定（**与 RRset 顺序无关**）：
        com 对 `googleapis.com DS` 的真实顺序是 [NSEC3, RRSIG, SOA, RRSIG]，
        顺序依赖的旧实现会误判「(无SOA)」。
        """
        qn_final = qname
        try:
            for rrset in response.answer:
                if rrset.rdtype != dns.rdatatype.CNAME:
                    continue
                for rd in rrset:
                    try:
                        qn_final = rd.target
                    except Exception:
                        pass
        except Exception:
            qn_final = qname
        soa_zone = None
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.SOA:
                continue
            try:
                if qn_final == rrset.name or qn_final.is_subdomain(rrset.name):
                    soa_zone = rrset.name
                    break
            except Exception:
                continue
        # 权威负应答必须含 SOA（RFC 2308 §2.1）；没有 SOA 就无法绑定
        # 权威 zone，NSEC 可以被任意区重放 → 直接失败。
        if soa_zone is None:
            return False
        is_nxdomain = (response.rcode() == dns.rcode.NXDOMAIN)
        has_nsec = False
        semantic_ok = False
        for rrset in response.authority:
            if rrset.rdtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                continue
            if verified_ids is not None and id(rrset) not in verified_ids:
                continue
            has_nsec = True
            try:
                if not rrset.name.is_subdomain(soa_zone):
                    continue
            except Exception:
                continue
            for rd in rrset:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    if is_nxdomain:
                        if self._nsec_covers(rd, rrset.name, qn_final):
                            semantic_ok = True
                    else:
                        # NODATA：owner 必须等于被查名且位图不含 qtype
                        if rrset.name == qn_final and not self._nsec_has_type(rd, qtype):
                            semantic_ok = True
                else:
                    th = self._nsec3_hash(
                        qn_final, rd.salt, rd.iterations, rd.algorithm)
                    oh = self._nsec3_owner_hash(rrset.name)
                    if not th or not oh:
                        continue
                    if is_nxdomain:
                        if self._hash_in_interval(th, oh, rd.next):
                            semantic_ok = True
                    else:
                        if oh == th and not self._nsec_has_type(rd, qtype):
                            semantic_ok = True
                        elif (qtype == dns.rdatatype.DS
                              and self._nsec3_optout(rd)
                              and self._hash_in_interval(th, oh, rd.next)):
                            # RFC 5155 §8.6：opt-out 区间覆盖 + DS 查询
                            # = 该委托没有 DS 的合法 NODATA 证明。
                            semantic_ok = True
        if not has_nsec:
            return None
        return semantic_ok


    def _ds_nodata_proves_insecure(self, resp, name: dns.name.Name,
                                   verified_ids=None) -> bool:
        """DS 查询的 NODATA 响应是否**数学上**证明 name 没有 DS

        RFC 4035 §5.2 要求：只有拿到父区签名的否定证明，才能把该名字判为
        insecure 委托。旧实现只看"响应里有没有 NSEC/NSEC3 记录"就认定未签名，
        任意 NSEC 响应都能把签名区降级。

        `verified_ids`（可选）：已通过父区 DNSKEY 验签的 rrset 的 id() 集合。
        传入时只采纳这些 rrset——攻击者不能在有效 NSEC 旁边混入一条伪造
        NSEC 来让本函数采纳伪造证明。

        认可三种证明（与 `plain_dns_server._zone_signed_status` 语义一致）：
          1. NSEC owner == name 且位图**含 NS 但不含 DS**（未签名委托点）
          2. NSEC3 hash(name) == owner hash 且位图含 NS 不含 DS（未签名委托点）
          3. NSEC3 opt-out 区间覆盖 name（RFC 5155 §8.6：区间内可能存在被
             省略的未签名委托；**不要求**覆盖记录位图含 NS——位图描述的是
             owner 名，不是被覆盖的委托名）

        ★ "含 NS"条件用于 1/2 和非 opt-out 的区间覆盖：普通记录（如
          www.ietf.org 在签名区 ietf.org 内）也有 NSEC3 且位图不含 DS，
          但它不是委托点，DS NODATA 不能据此推断"所在区未签名"。
          opt-out 覆盖是 RFC 5155 §8.6 的例外，只看 Opt-Out 位。
        """
        rd_DS = dns.rdatatype.DS
        rd_NS = dns.rdatatype.NS
        for rrset in list(resp.answer) + list(resp.authority):
            if verified_ids is not None and id(rrset) not in verified_ids:
                continue
            if rrset.rdtype == dns.rdatatype.NSEC:
                if rrset.name != name:
                    continue
                for rd in rrset:
                    if (self._nsec_has_type(rd, rd_NS)
                            and not self._nsec_has_type(rd, rd_DS)):
                        return True
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                owner_hash = self._nsec3_owner_hash(rrset.name)
                if not owner_hash:
                    continue
                for rd in rrset:
                    th = self._nsec3_hash(name, rd.salt, rd.iterations, rd.algorithm)
                    if not th:
                        continue
                    if (owner_hash == th
                            and self._nsec_has_type(rd, rd_NS)
                            and not self._nsec_has_type(rd, rd_DS)):
                        return True
                    # RFC 5155 §8.6：opt-out 区间覆盖证明“区间内可能存在被
                    # 省略的未签名委托”，不要求覆盖记录位图含 NS（位图描述
                    # 的是 owner 名，不是被覆盖的委托名）。旧实现多要求 NS，
                    # 会漏掉合法 opt-out 证明并误判 unknown。
                    if (self._hash_in_interval(th, owner_hash, rd.next)
                            and self._nsec3_optout(rd)):
                        return True
        return False

    async def _zone_has_ds_uncached(self, qname: dns.name.Name) -> Optional[bool]:
        """逐级向上查询 DS，判断该名字所在区是否应为签名区

        ★ 必须从 **qname 自身** 起跳：qname 自己就可能是一个 zone apex
          （DS 由父区持有）。旧实现从 `qname.parent()` 起跳，会直接看到父区
          （如 com.）有 DS 就判"应有签名"——实测 `google.com`（未签名）因此
          被判 True，开启 `require_rrsig` 后合法应答会被当成"签名被剥离"丢弃。
        ★ 无 DS 时必须验证否定证明的语义（见 `_ds_nodata_proves_insecure`），
          不能只看"响应里有没有 NSEC/NSEC3"。
        ★ 无证明时**不能**无条件升父级：对委托点（如 360.cn）来说，父区
          （cn.）自己的 DS 只能证明 cn. 签名，不能证明 360.cn 签名；升上去
          会把未签名的子区误判成 secure（生产日志“签名被剥离”假告警的根因）。
          必须先判断 name 是「父区委托点」还是「区内普通名」：
            - 委托点：无证明 → None（无法证明，停止）；
            - 普通名：DS 本来就不存在 → 升父级找所在区 apex。
        """
        name = qname
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
                    # DS 查询失败 ≠ 这个 CNAME/普通名“无法证明未签名”。
                    # 直接 return None 会让 CNAME 目标（如 api.live.bilibili.com）
                    # 永久被判 bogus。先区分「父区委托点」与「区内普通名」：
                    #   * 普通名/CNAME owner：DS 本来就不存在，必须升父级；
                    #   * 委托点：没有否定证明，只能返回 None（无法证明）。
                    is_del = await self._name_is_delegation(name)
                    if is_del is False:
                        name = name.parent()
                        continue
                    if await self._parent_is_insecure(name):
                        return False
                    return None
                resp = dns.message.from_wire(resp_bytes)
                try:
                    # 真权威对 DS 查询必须置 AA；AA=0 说明这条应答来自
                    # 递归镜像/中间盒（实测 hk/com.hk 方向），其“无 NSEC 的
                    # NODATA”不能当作“签名被剥离”的证据。
                    if not (resp.flags & dns.flags.AA):
                        _LINK_UNTRUSTED.set(True)
                except Exception:
                    pass
            except Exception:
                return None
            # 只采纳通过父区已信任 DNSKEY 验签的 DS/NSEC/NSEC3。
            # 注意：name.parent() 可能是未签名区（如 s.360.cn 的父区
            # 360.cn），此时拿不到 key，不能据此判 secure/bogus，只能按
            # “无证明”继续判断委托点并升父级。
            verified_ids = set()
            try:
                parent_status, parent_keys = await self._get_verified_zone_keys(
                    name.parent())
            except Exception:
                parent_status, parent_keys = "indeterminate", {}
            if parent_status == "secure":
                verified_ids = self._verified_rrset_ids(resp, parent_keys)
            ds_rrset = next((rr for rr in resp.answer
                             if rr.rdtype == dns.rdatatype.DS), None)
            if ds_rrset is not None:
                # 有 DS 但没通过父区验签 → 无法证明（不能返回 True）
                return True if id(ds_rrset) in verified_ids else None
            if verified_ids and self._ds_nodata_proves_insecure(
                    resp, name, verified_ids):
                return False
            # 无有效否定证明：区分委托点（停）与区内普通名（升父级）
            is_del = await self._name_is_delegation(name)
            if is_del is False:
                name = name.parent()
                continue
            # 父区已证明未签名 → 本名字一定在未签名树下，无需 NSEC/NSEC3
            # 证明（未签名区本来就没有这些记录）。
            if await self._parent_is_insecure(name):
                return False
            return None
        return None

    async def _parent_is_insecure(self, name: dns.name.Name) -> bool:
        """父区是否已被证明为未签名（insecure）。

        未签名父区不会发布 DS，也不会发布 NSEC/NSEC3；其子区/委托点因此
        不可能有“父区签名证明无 DS”的记录。不能因为缺证明判 unknown。
        """
        try:
            if name == dns.name.root:
                return False
            return await self._zone_has_ds(name.parent()) is False
        except Exception:
            return False

    async def _name_is_delegation(self, name: dns.name.Name) -> Optional[bool]:
        """name 是否是父区的委托点（父区存在 owner==name 的 NS 记录）

        DS NODATA 响应无法单凭 SOA owner 区分“委托点”与“区内普通名”：
        两者的 SOA owner 都等于 name.parent()。查一次 NS 即可区分：
          - 委托点：NS owner == name（referral 或 apex NS）；
          - 普通名：NODATA（没有 owner==name 的 NS）。
        返回 True/False/None（查询失败/无回调）。
        """
        if self._dns_query_callback is None:
            return None
        key = str(name).lower()
        cached = self._delegation_cache.get(key)
        if cached is not None and time.time() < cached[1]:
            return cached[0]
        try:
            q = dns.message.make_query(name, dns.rdatatype.NS)
            q.use_edns(0, payload=1232, ednsflags=dns.flags.DO)
            resp_bytes = await asyncio.wait_for(
                self._dns_query_callback(q.to_wire()), timeout=2.0
            )
            if resp_bytes is None:
                return None
            resp = dns.message.from_wire(resp_bytes)
        except Exception:
            return None
        result = any(
            rrset.rdtype == dns.rdatatype.NS and rrset.name == name
            for section in (resp.answer, resp.authority)
            for rrset in section
        )
        if len(self._delegation_cache) > 2048:
            self._delegation_cache.clear()
        self._delegation_cache[key] = (result, time.time() + 300)
        return result

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

    def _verified_rrset_ids(self, resp, keys) -> set:
        """返回 resp 中已通过 keys 验签的 DS/NSEC/NSEC3 rrset 的 id() 集合

        安全约束：DS 否定证明（“父区签名证明无 DS”）只能采纳验签通过的
        NSEC/NSEC3。旧实现不验签，攻击者可用一条伪造 NSEC 把签名区降级为
        insecure（进而放行被剥离签名的应答）。
        """
        verified = set()
        for section in (resp.answer, resp.authority):
            for rrset in section:
                if rrset.rdtype not in (dns.rdatatype.DS,
                                        dns.rdatatype.NSEC,
                                        dns.rdatatype.NSEC3):
                    continue
                rrsig_set = self._find_rrsig_for(resp, section, rrset)
                if rrsig_set is None:
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, keys)
                except Exception:
                    continue
                verified.add(id(rrset))
        return verified

    async def _query_rrset_ex(self, zone: dns.name.Name, rdtype: int):
        """查询 zone 的 RR 类型，返回 (rrset, rrsig_set, full_response)

        比 `_query_rrset` 多返回完整报文：判定「DS NODATA 是否成立」必须看
        否定证明（NSEC/NSEC3），只有 rrset 是不够的。
        """
        if self._dns_query_callback is None:
            return None, None, None
        try:
            from cache import get_query_wire

            query_bytes = get_query_wire(str(zone), rdtype, want_dnssec=True)
            if query_bytes is None:
                return None, None, None
            response_bytes = await self._dns_query_callback(query_bytes)
            if response_bytes is None:
                return None, None, None
            resp = dns.message.from_wire(response_bytes)
        except Exception as e:
            logger.debug("查询 %s %s 失败: %s", zone, dns.rdatatype.to_text(rdtype), e)
            return None, None, None

        target = None
        for rrset in resp.answer:
            if rrset.rdtype == rdtype:
                target = rrset
                break
        if target is None:
            return None, None, resp
        return target, self._find_rrsig_for(resp, resp.answer, target), resp

    async def _query_rrset(self, zone: dns.name.Name, rdtype: int):
        """查询 zone 的指定 RR 类型，返回 (rrset, rrsig_set)；任一缺失返回 (None, None)"""
        rrset, sigs, _resp = await self._query_rrset_ex(zone, rdtype)
        return rrset, sigs

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
        #
        # ★ 但"查不到 DS"不等于"没有 DS"：中间人可以让 DS 查询返回 NODATA，
        #   把签名区降级成 insecure（DNSSEC 降级攻击）。RFC 4035 §5.2 要求
        #   必须拿到父区**签名过的否定证明**（NSEC/NSEC3）才能判 insecure；
        #   拿不到证明就只能判 indeterminate（不放行也不判伪造）。
        ds_rrset, ds_sigs, ds_resp = await self._query_rrset_ex(
            zone, dns.rdatatype.DS)
        if ds_rrset is None:
            if ds_resp is not None:
                verified_ids = self._verified_rrset_ids(ds_resp, parent_keys)
                if verified_ids and self._ds_nodata_proves_insecure(
                        ds_resp, zone, verified_ids):
                    return "insecure", {}
            return "indeterminate", {}
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

        # DS digest 匹配出父区授权的 key —— **收集全部**匹配项，再用它们验证
        # DNSKEY 集合的自签。KSK 轮换窗口内父区会同时发布新旧两条 DS，而自签
        # RRSIG 只由其中一把签发；且权威返回的 DS 顺序不固定（同一 zone 两次
        # 查询可能顺序相反）。只取"第一把匹配的 key"会误判 bogus
        # （实测 sc.：DS={2539,35612}，RRSIG(DNSKEY) 由 35612 签）。
        # 安全性不变：能进入 trusted 的 key 必须匹配**已验签**的 DS。
        auth_keys = []
        for key in dnskey_rrset:
            for ds in ds_rrset:
                if self._ds_matches_dnskey(ds, zone, key):
                    auth_keys.append(key)
                    break
        if not auth_keys:
            return "bogus", {}
        ksk_rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for key in auth_keys:
            ksk_rrset.add(key)
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
        self, response: dns.message.Message, qname: dns.name.Name,
        qtype: int = dns.rdatatype.A, cname_hop: bool = False,
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
        root_name = dns.name.from_text(".")
        # 根区密钥是否已从「信任锚（KSK）」升级为完整 DNSKEY RRset（含 ZSK）。
        # 只有 True 时 keys[.] 才能用来验证根区日常记录。
        root_dnskey_ok = False
        for signer in signers:
            # 根签名者必须单独处理：keys[root] 初始只是**信任锚**（通常只有 KSK），
            # 而根区的 SOA / NSEC / DNSKEY 等日常记录由 **ZSK** 签名。早期实现
            # 用 `if signer in keys: continue` 把根跳过了，于是拿信任锚去验 ZSK
            # 签名必然 ValidationFailure → 返回 False → 判 bogus。
            # 后果：**所有以根区为 signer 的应答**（典型是 NXDOMAIN/NODATA 的
            # NSEC 否定证明，如不存在的 TLD）在 strict 模式 + drop_bogus 下
            # 全部被丢弃成 SERVFAIL。
            # 这里先用信任锚验出根 DNSKEY RRset（含 ZSK），拿到完整密钥集再验签。
            if signer in keys and signer != root_name:
                continue
            status, zkeys = await self._get_verified_zone_keys(signer)
            if status == "bogus":
                logger.warning("DNSSEC 链验证失败（bogus）: %s", signer)
                return False
            if status == "secure":
                keys.update(zkeys)
                # 根区密钥已从「信任锚」升级为完整 DNSKEY RRset（含 ZSK），
                # 此时才能用它验证根区日常记录。
                if signer == root_name:
                    root_dnskey_ok = True
            else:
                # insecure / indeterminate：该 signer 无可用可信 key
                indeterminate = True

        # 3. 用可信 keys 验签 answer / authority 中的 RRset
        validated = False
        validated_ids = set()
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                if (section is response.authority
                        and rrset.rdtype == dns.rdatatype.NS):
                    # RFC 4035 §3.1.4.1：delegation 的 NS RRset 由子区签名，
                    # 父区 referral 里的 NS 本来就不带 RRSIG，不能要求。
                    continue
                rrsig_set = self._find_rrsig_for(response, section, rrset)
                if rrsig_set is None:
                    # RFC 4035 §5.3：签名区里的每个 RRset 都必须有 RRSIG。
                    # 只有 owner 所在区被证明为未签名（insecure）时才允许
                    # 无签名 RRset（例如签名区 CNAME 到未签名 CDN）。
                    # 旧实现直接 continue，只要响应里任意一个 RRset 验签成功
                    # 就返回 secure，攻击者可剥离其余 RRset 的签名。
                    zone_signed = await self._zone_has_ds(rrset.name)
                    if zone_signed is False:
                        continue
                    if zone_signed is None:
                        indeterminate = True
                        continue
                    logger.debug(
                        "DNSSEC: 签名区 RRset 缺 RRSIG（owner=%s，section=%s）",
                        rrset.name, "answer" if section is response.answer else "authority")
                    return False
                if len(rrsig_set) == 0:
                    return False
                signer = rrsig_set[0].signer
                # RFC 4035 §5.3.1：RRSIG.signer 必须是包含该 RRset owner 的
                # zone apex。旧实现只按 signer 取 DNSKEY 验签，未检查 owner
                # 是否在 signer 区之内；用祖先/无关区的 key 签别的名字会被
                # 误接受。
                try:
                    if not rrset.name.is_subdomain(signer):
                        logger.debug(
                            "DNSSEC: RRSIG signer 不覆盖 RRset owner: owner=%s signer=%s",
                            rrset.name, signer)
                        return False
                except Exception:
                    return False
                if signer == root_name and not root_dnskey_ok:
                    # 根 DNSKEY 没能取到（无查询回调 / 查询失败）：此时 keys[.] 还
                    # 只是**信任锚（KSK）**，而根区记录由 ZSK 签名——拿它验必然
                    # ValidationFailure。这属于"无法判定"，绝不能据此判 bogus
                    # （否则所有根区签名的负应答都会被丢弃）。
                    indeterminate = True
                    continue
                if signer not in keys:
                    indeterminate = True
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsig_set, keys)
                    validated = True
                    validated_ids.add(id(rrset))
                except dns.dnssec.ValidationFailure as e:
                    logger.debug("DNSSEC 验签失败 (%s): %s", rrset.name, e)
                    return False
                except Exception as e:
                    logger.debug("DNSSEC 验证异常 (%s): %s", rrset.name, e)
                    indeterminate = True

        # 负应答语义校验（从 plain_dns_server 迁移）：
        # 签名只证明 NSEC/SOA 是某区真实签署的，还必须证明它覆盖/匹配
        # 本次 qname（RFC 4035 §5.4）。否则重放任意签名区的 NSEC+SOA
        # 就能伪造否定应答。
        try:
            is_negative = (
                response.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR)
                and not any(rr.rdtype == qtype for rr in response.answer)
            )
        except Exception:
            is_negative = False
        if is_negative and not cname_hop:
            # 先取 CNAME 终点：负应答由**最后一跳权威**产生，SOA/NSEC
            # 绑定的是终点所在区（不是原始查询名）。
            _tgt = qname
            try:
                for _rr in response.answer:
                    if _rr.rdtype == dns.rdatatype.CNAME:
                        _tgt = _rr[0].target
            except Exception:
                _tgt = qname
            if await self._zone_has_ds(_tgt) is False:
                # 目标区已证明未签名：未签名区本来就不发布 NSEC/NSEC3，
                # 负应答没有否定证明是合法的（典型：CNAME 到未签名 CDN）。
                return True
            neg = self._validate_negative_semantics(
                response, qname, qtype, validated_ids)
            if neg is False:
                logger.debug(
                    "DNSSEC 负应答语义校验失败（重放/跨区/缺SOA）: %s", qname)
                return False
            if neg is None and not indeterminate:
                logger.debug("DNSSEC 负应答缺 NSEC/NSEC3 否定证明: %s", qname)
                return False

        if validated:
            try:
                for section in (response.answer, response.authority):
                    for rrset in section:
                        if id(rrset) not in validated_ids:
                            continue
                        sigs = self._find_rrsig_for(response, section, rrset)
                        if sigs:
                            for s in sigs:
                                self._signed_zones.add(s.signer)
                if len(self._signed_zones) > 2048:
                    self._signed_zones.clear()
            except Exception:
                pass
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

"""
多上游交叉一致性验证模块
================================
检测 DNS 响应投毒/篡改的核心模块。

原理：
  对同一 DNS 查询，向多个独立加密上游（DoH/DoT/DoQ）发起查询，
  比较各上游返回的响应内容指纹（SHA-256）。
  若指纹不一致，说明至少有一个上游返回了被篡改的响应。

指纹计算：
  忽略 additional 段的 EDNS0 等可差异字段，仅对以下内容计算 SHA-256：
    - answer 段（实际 DNS 解析结果）
    - authority 段（权威服务器信息）
    - rcode（响应码）
    - AD 位（Authentic Data 标志）

两阶段策略：
  阶段 A（快速路径）：取最快成功响应返回（零延迟增加）
  阶段 B（后台验证）：继续收集其余上游响应，在后台做一致性校验
"""

import asyncio
import hashlib
import io
import logging
import random
import struct
import time
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass

import dns.message
import dns.flags
import dns.rcode

logger = logging.getLogger("dns-proxy.consistency")


# ============================================================
# 数据结构
# ============================================================


@dataclass
class ConsistencyVerdict:
    """一致性验证结论"""
    consistent: bool
    total_responses: int
    majority_count: int
    minority_count: int
    trusted_response: bytes
    trusted_server: str
    majority_servers: List[str]
    minority_servers: List[str]
    fingerprints: Dict[str, str]
    is_total_disagreement: bool = False
    anomaly_boosted: bool = False


@dataclass
class ResponseRecord:
    """单条上游响应记录"""
    server_name: str
    response_bytes: bytes
    elapsed: float
    rtt: float


# ============================================================
# 一致性验证器
# ============================================================


class ResponseConsistencyVerifier:
    """多上游响应一致性验证器。"""

    def __init__(self, enabled: bool = True,
                 min_responses: int = 2,
                 consistency_window_ms: float = 800.0,
                 anomaly_detector=None,
                 max_background_servers: int = 5):
        self.enabled = enabled
        self.min_responses = min_responses
        self.consistency_window_ms = consistency_window_ms
        self._anomaly_detector = anomaly_detector
        self.max_background_servers = max_background_servers  # 后台验证随机抽样的最大上游数

        self._stats: Dict[str, Any] = {
            "total_verifications": 0,
            "consistent": 0,
            "inconsistent": 0,
            "total_disagreements": 0,
            "insufficient_responses": 0,
        }
        self._server_inconsistencies: Dict[str, int] = {}

    @property
    def stats(self) -> Dict[str, Any]:
        stats = dict(self._stats)
        stats["server_inconsistencies"] = dict(self._server_inconsistencies)
        return stats

    @staticmethod
    def compute_fingerprint(response_bytes: bytes) -> str:
        """
        计算 DNS 响应指纹（SHA-256）。
        仅包含 answer + authority + rcode + AD 位，
        忽略 additional 段的 EDNS0 等可差异字段。
        """
        try:
            msg = dns.message.from_wire(response_bytes)
            h = hashlib.sha256()

            for rrset in msg.answer:
                buf = io.BytesIO()
                rrset.to_wire(buf)
                h.update(buf.getvalue())

            for rrset in msg.authority:
                buf = io.BytesIO()
                rrset.to_wire(buf)
                h.update(buf.getvalue())

            h.update(struct.pack("!H", msg.rcode()))

            ad = 1 if msg.flags & dns.flags.AD else 0
            h.update(struct.pack("!B", ad))

            return h.hexdigest()[:16]
        except Exception as e:
            logger.debug("一致性验证: 指纹计算失败: %s", e)
            return "error:" + str(e)[:32]

    def verify(self, records: List[ResponseRecord]) -> Optional[ConsistencyVerdict]:
        """对一组上游响应进行交叉一致性验证。"""
        if not self.enabled:
            return None

        if len(records) < self.min_responses:
            self._stats["insufficient_responses"] += 1
            return None

        self._stats["total_verifications"] += 1

        fingerprints: Dict[str, Tuple[str, ResponseRecord]] = {}
        for rec in records:
            fp = self.compute_fingerprint(rec.response_bytes)
            fingerprints[rec.server_name] = (fp, rec)

        fp_groups: Dict[str, List[str]] = {}
        for sname, (fp, _) in fingerprints.items():
            fp_groups.setdefault(fp, []).append(sname)

        majority_fp = max(fp_groups, key=lambda k: len(fp_groups[k]))
        majority_servers = fp_groups[majority_fp]
        minority_servers = [
            s for s in fingerprints if s not in majority_servers
        ]
        majority_count = len(majority_servers)
        minority_count = len(minority_servers)

        trusted_name = majority_servers[0]
        trusted_bytes = fingerprints[trusted_name][1].response_bytes

        is_total_disagreement = len(fp_groups) == len(records)

        fp_summary = {s: f for s, (f, _) in fingerprints.items()}

        verdict = ConsistencyVerdict(
            consistent=minority_count == 0,
            total_responses=len(records),
            majority_count=majority_count,
            minority_count=minority_count,
            trusted_response=trusted_bytes,
            trusted_server=trusted_name,
            majority_servers=majority_servers,
            minority_servers=minority_servers,
            fingerprints=fp_summary,
            is_total_disagreement=is_total_disagreement,
        )

        if verdict.consistent:
            self._stats["consistent"] += 1
        elif is_total_disagreement:
            self._stats["total_disagreements"] += 1
            self._stats["inconsistent"] += 1
            for s in minority_servers:
                self._server_inconsistencies[s] = self._server_inconsistencies.get(s, 0) + 1
        else:
            self._stats["inconsistent"] += 1
            for s in minority_servers:
                self._server_inconsistencies[s] = self._server_inconsistencies.get(s, 0) + 1

        return verdict

    async def collect_and_verify(
        self,
        fast_result: Tuple[bytes, float, Any],
        fast_server: str,
        all_servers: List[Any],
        query_bytes: bytes,
        timeout: float,
        exclude_servers: set = None,
    ) -> Tuple[bytes, Optional[ConsistencyVerdict]]:
        """两阶段策略主入口。"""
        if not self.enabled or len(all_servers) < self.min_responses:
            return fast_result[0], None

        fast_bytes = fast_result[0]
        records: List[ResponseRecord] = [
            ResponseRecord(
                server_name=fast_server,
                response_bytes=fast_bytes,
                elapsed=fast_result[1],
                rtt=fast_result[1],
            )
        ]

        remaining = [s for s in all_servers if s.name != fast_server and s.enabled]
        if not remaining:
            return fast_bytes, None

        # 排除优选上游（它们不参与后台验证抽样）
        if exclude_servers:
            remaining = [s for s in remaining if s.name not in exclude_servers]

        # 真随机抽样，减少连接数暴涨
        if self.max_background_servers > 0 and len(remaining) > self.max_background_servers:
            remaining = random.sample(remaining, self.max_background_servers)

        collected = await self._collect_responses(
            remaining, query_bytes, timeout
        )
        records.extend(collected)

        verdict = self.verify(records)
        return fast_bytes, verdict

    async def _collect_responses(
        self,
        servers: List[Any],
        query_bytes: bytes,
        timeout: float,
    ) -> List[ResponseRecord]:
        """向指定上游列表并行查询，在超时内收集响应。"""
        records: List[ResponseRecord] = []

        async def query_one(srv) -> Optional[ResponseRecord]:
            try:
                t0 = time.monotonic()
                result = await srv.resolver.resolve(query_bytes)
                elapsed = time.monotonic() - t0
                if result is not None:
                    return ResponseRecord(
                        server_name=srv.name,
                        response_bytes=result,
                        elapsed=elapsed,
                        rtt=elapsed,
                    )
            except Exception:
                pass
            return None

        tasks = [asyncio.create_task(query_one(s)) for s in servers]
        done, _ = await asyncio.wait(tasks, timeout=timeout)

        for task in done:
            try:
                r = task.result()
                if r is not None:
                    records.append(r)
            except Exception:
                pass

        pending_tasks = set(tasks) - done
        for t in pending_tasks:
            t.cancel()
        # await 被取消的 task，让 CancelledError 在内部传播，确保 DoQ 等资源被清理
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        return records

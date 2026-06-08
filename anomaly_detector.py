"""
统计异常检测基线引擎
==============================
对上游 DNS 响应做异常行为检测，基于三个基线维度：

1. RTT 基线（响应延迟）
   - 指数移动平均（EMA）+ 标准差
   - 检测异常的慢响应（可能是投毒链路的额外延迟）
   - 检测异常的快响应（可能是伪造缓存的本地响应）

2. 响应大小基线
   - 每个上游 + 记录类型的 mean/stddev
   - 异常的过大响应可能夹带私货（劫持/投毒）
   - 异常的过小响应可能是伪造的 NXDOMAIN

3. TTL 基线
   - 按 (2LD, record_type) 分组的 TTL 值分布
   - 投毒响应常用极短 TTL（几分钟到几十分钟）

双阶段（每上游独立）：
  - learn 阶段：前 N 个样本仅收集，不告警（每个上游独立计数器）
  - detect 阶段：偏差超过 z_score_threshold 触发异常标记
"""

import logging
import time
import math
from typing import Dict, Optional, List, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

import dns.message
import dns.rdatatype

logger = logging.getLogger("dns-proxy.anomaly")


# ============================================================
# 辅助：指数移动平均 + 标准差（Welford 在线算法）
# ============================================================


class OnlineStats:
    """
    在线统计量（Welford 算法）。
    无需存储所有样本即可计算 mean + variance。
    """

    __slots__ = ("n", "mean", "m2")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value: float):
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def count(self) -> int:
        return self.n

    def z_score(self, value: float) -> float:
        """计算新值相对于基线偏差的标准差倍数。"""
        if self.n < 2 or self.std < 1e-9:
            return 0.0
        return (value - self.mean) / self.std


# ============================================================
# 2LD 提取工具
# ============================================================


def _extract_2ld(domain: str) -> str:
    """
    从完整域名中提取二级域名（2LD）。
    例如：www.example.com -> example.com
          sub.abc.co.uk -> abc.co.uk
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain.rstrip(".")
    # 提取最后二级
    return ".".join(parts[-2:])


# ============================================================
# 异常检测器
# ============================================================


class AnomalyDetector:
    """
    DNS 响应异常检测器。
    每上游独立维护三个基线维度的在线统计。
    """

    def __init__(self, enabled: bool = True,
                 learning_samples: int = 200,
                 z_score_threshold: float = 3.0):
        """
        Args:
            enabled: 总开关
            learning_samples: 基线学习阶段的样本数
            z_score_threshold: z-score 超过此值视为异常
        """
        self.enabled = enabled
        self.learning_samples = learning_samples
        self.z_score_threshold = z_score_threshold

        # 每上游的 RTT 统计
        self._rtt_stats: Dict[str, OnlineStats] = {}

        # 每上游 + 记录类型的响应大小统计
        self._size_stats: Dict[Tuple[str, int], OnlineStats] = {}

        # TTL 分布统计：按 (2LD, record_type) 分组
        self._ttl_stats: Dict[Tuple[str, int], OnlineStats] = {}
        # TTL 观测值暂存（用于 learn 阶段）
        self._ttl_observations: Dict[Tuple[str, int], List[int]] = defaultdict(list)

        # 每上游独立学习计数器（替代全局单一学习阶段）
        self._server_learning_count: Dict[str, int] = {}

        # 统计
        self._stats: Dict[str, Any] = {
            "total_responses": 0,
            "anomalies_detected": 0,
            "rtt_anomalies": 0,
            "size_anomalies": 0,
            "ttl_anomalies": 0,
            "in_learning_phase": True,
        }

        # 记录每上游的异常数
        self._server_anomalies: Dict[str, int] = {}

    @property
    def stats(self) -> Dict[str, Any]:
        s = dict(self._stats)
        s["server_anomalies"] = dict(self._server_anomalies)
        s["server_learning"] = {
            name: count for name, count in self._server_learning_count.items()
        }
        s["in_learning_phase"] = any(
            c < self.learning_samples
            for c in self._server_learning_count.values()
        ) if self._server_learning_count else True
        return s

    def server_in_learning(self, server_name: str) -> bool:
        """指定上游是否仍在学习阶段（每上游独立）。"""
        return self._server_learning_count.get(server_name, 0) < self.learning_samples

    @property
    def in_learning_phase(self) -> bool:
        """是否存在至少一个上游仍在学习阶段。"""
        if not self._server_learning_count:
            return True
        return any(
            c < self.learning_samples
            for c in self._server_learning_count.values()
        )

    # ============================================================
    # 记录单条响应
    # ============================================================

    def record_response(self, server_name: str, rtt: float,
                        response_bytes: bytes) -> Optional[float]:
        """
        记录一条上游响应，返回异常评分（0=正常，越高越异常）。
        如果未启用或仍在学习阶段，返回 0 不告警。

        Args:
            server_name: 上游名称
            rtt: 响应延迟（秒）
            response_bytes: 完整 DNS 响应字节

        Returns:
            异常评分（0.0 ~ 3.0+，超过 z_score_threshold 视为异常）
        """
        if not self.enabled:
            return 0.0

        self._stats["total_responses"] += 1

        # 每上游独立学习计数器
        server_learn_count = self._server_learning_count.get(server_name, 0)
        is_learning = server_learn_count < self.learning_samples
        self._server_learning_count[server_name] = server_learn_count + 1
        self._stats["in_learning_phase"] = any(
            c < self.learning_samples
            for c in self._server_learning_count.values()
        )

        # 解析响应获取记录类型和大小/TTL 信息（在更新统计前解析）
        try:
            msg = dns.message.from_wire(response_bytes)
        except Exception:
            return 0.0

        response_size = len(response_bytes)

        # 学习阶段：仅更新统计，不告警
        if is_learning:
            # 1. 更新 RTT 基线
            if server_name not in self._rtt_stats:
                self._rtt_stats[server_name] = OnlineStats()
            self._rtt_stats[server_name].update(rtt)

            # 2. 更新响应大小基线
            rdtypes_seen = set()
            for rrset in msg.answer:
                rdtype = rrset.rdtype
                rdtypes_seen.add(rdtype)
                key = (server_name, rdtype)
                if key not in self._size_stats:
                    self._size_stats[key] = OnlineStats()
                self._size_stats[key].update(response_size)

                # 3. TTL 统计
                for rd in rrset:
                    ttl = getattr(rrset, 'ttl', None) or 0
                    if ttl > 0:
                        domain = str(rrset.name)
                        ttl_key = (_extract_2ld(domain), rdtype)
                        self._ttl_observations[ttl_key].append(ttl)
                        if ttl_key not in self._ttl_stats:
                            self._ttl_stats[ttl_key] = OnlineStats()
                        self._ttl_stats[ttl_key].update(float(ttl))
            return 0.0

        # ========== 检测阶段：先检查异常，后更新统计 ==========
        rdtypes_seen = set()
        for rrset in msg.answer:
            rdtypes_seen.add(rrset.rdtype)

        max_z = 0.0
        anomaly_types = []

        # RTT 异常检测（在更新基线前检测偏差）
        if server_name in self._rtt_stats:
            rtt_z = abs(self._rtt_stats[server_name].z_score(rtt))
            if rtt_z > self.z_score_threshold:
                max_z = max(max_z, rtt_z)
                anomaly_types.append("rtt")
                self._stats["rtt_anomalies"] += 1

        # 更新 RTT 基线（检测之后才更新）
        if server_name not in self._rtt_stats:
            self._rtt_stats[server_name] = OnlineStats()
        self._rtt_stats[server_name].update(rtt)

        # 响应大小异常检测（基于检测前的基线）
        for rdtype in rdtypes_seen:
            key = (server_name, rdtype)
            if key in self._size_stats:
                size_z = abs(self._size_stats[key].z_score(float(response_size)))
                if size_z > self.z_score_threshold:
                    max_z = max(max_z, size_z)
                    anomaly_types.append("size")
                    self._stats["size_anomalies"] += 1

        # 更新响应大小基线
        for rrset in msg.answer:
            rdtype = rrset.rdtype
            key = (server_name, rdtype)
            if key not in self._size_stats:
                self._size_stats[key] = OnlineStats()
            self._size_stats[key].update(response_size)

        # TTL 异常检测 + 更新 TTL 基线
        for rrset in msg.answer:
            domain = str(rrset.name)
            rdtype = rrset.rdtype
            ttl = getattr(rrset, 'ttl', None) or 0
            if ttl > 0:
                ttl_key = (_extract_2ld(domain), rdtype)
                if ttl_key in self._ttl_stats:
                    ttl_z = abs(self._ttl_stats[ttl_key].z_score(float(ttl)))
                    if ttl_z > self.z_score_threshold:
                        max_z = max(max_z, ttl_z)
                        anomaly_types.append("ttl")
                        self._stats["ttl_anomalies"] += 1

                # 更新 TTL 基线
                self._ttl_observations[ttl_key].append(ttl)
                if ttl_key not in self._ttl_stats:
                    self._ttl_stats[ttl_key] = OnlineStats()
                self._ttl_stats[ttl_key].update(float(ttl))

        if max_z > self.z_score_threshold:
            self._stats["anomalies_detected"] += 1
            self._server_anomalies[server_name] = self._server_anomalies.get(server_name, 0) + 1
            logger.warning(
                "DNS 异常检测 [RTT/大小/TTL]: 上游 %s 响应偏差 %.1fσ "
                "(类型: %s, rtt=%.0fms, 大小=%d bytes)",
                server_name, max_z, "/".join(anomaly_types), rtt * 1000, response_size,
            )

        return max_z

    def get_server_anomaly_rate(self, server_name: str) -> float:
        """获取指定上游的异常率。"""
        total = self._server_learning_count.get(server_name, 0)
        if total == 0:
            return 0.0
        return self._server_anomalies.get(server_name, 0) / total

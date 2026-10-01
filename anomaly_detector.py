"""
统计异常检测基线引擎
==============================
对上游 DNS 响应做异常行为检测，基于三个基线维度：

1. RTT 基线（响应延迟）
   - 指数移动平均（EMA）+ 标准差
   - 检测异常的慢响应（可能是投毒链路的额外延迟）
   - 检测异常的快响应（可能是伪造缓存的本地响应）

2. 响应大小基线
   - 按 (上游, 记录类型) 分组统计「整条响应字节数」的 mean/stddev。
     注：基线值是 len(整个 DNS 响应报文)，不是单个 RRset 的字节数；
     同一响应含多种记录类型时，该响应大小会分别计入各记录类型分组
     （用途：发现“该上游/该类记录返回的响应整体变大或变小”）
   - 异常的过大响应可能夹带私货（劫持/投毒）
   - 异常的过小响应可能是伪造的 NXDOMAIN

3. TTL 基线
   - 按 (2LD, record_type) 分组的 TTL 值分布
   - 投毒响应常用极短 TTL（几分钟到几十分钟）

双阶段（每上游独立）：
  - learn 阶段：前 N 个样本仅收集，不告警（每个上游独立计数器）
  - detect 阶段：偏差超过 z_score_threshold 触发异常标记
    （特殊：基线恒定即 std≈0 时 z-score 恒为 0，会漏报"从恒定值突变到
      另一个固定值"；此类分组改用 OnlineStats.flat_anomaly_score 的
      "绝对差值相对比例"判分，阈值由 flat_diff_ratio 控制）
"""

import logging
import math
from typing import Dict, Optional, Tuple, Any

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
        """计算新值相对于基线偏差的标准差倍数。

        注意：基线恒定（std≈0）时 z-score 数学上不可定义，此处返回 0；
        调用方必须先用 is_flat() 判断并用 flat_anomaly_score() 兜底，
        否则"从恒定值突变为另一个固定值"会漏报（详见 AnomalyDetector）。
        """
        if self.n < 2 or self.std < 1e-9:
            return 0.0
        return (value - self.mean) / self.std

    def is_flat(self, eps: float = 1e-9) -> bool:
        """基线是否恒定（样本足够但标准差≈0）——此时 z_score 恒为 0。"""
        return self.n >= 2 and self.std < eps

    def flat_anomaly_score(self, value: float, ratio: float) -> float:
        """恒定基线（std≈0）下的偏差分值，可直接与 z_score_threshold 比较。

        以"相对偏离比例"折算：|value-mean| / |mean| 达到 ratio 记 1 分,
        达到 z_score_threshold * ratio 时即触发告警（得分 = 相对偏离 / ratio）。
        ratio=0.2 即偏离 20% 记 1σ、60% 达 3σ 告警。
        分母用 max(|mean|, 1e-6) 防 mean≈0 时除零/爆表。
        """
        denom = max(abs(self.mean), 1e-6)
        rel = abs(value - self.mean) / denom
        r = ratio if ratio > 0 else 1e-6
        return rel / r


# ============================================================
# 2LD 提取工具
# ============================================================


def _extract_2ld(domain: str) -> str:
    """
    从完整域名中提取最后两级标签（用作 TTL 分组键）。
    例如：www.example.com -> example.com
          a.b.example.com -> example.com
          sub.abc.co.uk -> co.uk
    注意：本函数不做公共后缀（PSL）识别，多级后缀（co.uk / com.cn 等）
    会归并到同一分组——这是有意的粗粒度聚类，仅用于 TTL 基线相似性分组。
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
                 z_score_threshold: float = 3.0,
                 flat_diff_ratio: float = 0.2,
                 quasi_flat_rel_std: Optional[float] = None,
                 ttl_min_ref: float = 2.0,
                 ttl_default_ref: float = 300.0):
        """
        Args:
            enabled: 总开关
            learning_samples: 基线学习阶段的样本数
            z_score_threshold: z-score 超过此值视为异常
            flat_diff_ratio: 基线恒定时"绝对差值"的相对阈值——相对偏离
                达到该比例记 1 分（等价 1σ），达到 z_score_threshold 倍即告警。
                0.2 = 偏离恒定均值 20% 记 1σ、60% 触发 3σ 告警。
            quasi_flat_rel_std: "准恒定基线"判据 std/|mean| 的阈值。为 None
                （默认）时**不写死**，而由配置的 TTL 粒度实时推导：
                ttl_min_ref / ttl_default_ref（= 系统认为可忽略的 TTL 波动尺度）。
                低于该阈值说明基线噪声太小、z-score 会被放大失真，改用相对
                偏离判分（例：TTL mean=300、std=0.5 时，8% 的偏离会被
                z 算成 50σ）。
            ttl_min_ref: 配置 cache.min_ttl（仅用于推导阈值）。
            ttl_default_ref: 配置 cache.default_ttl（仅用于推导阈值）。
        """
        self.enabled = enabled
        self.learning_samples = learning_samples
        self.z_score_threshold = z_score_threshold
        self.flat_diff_ratio = flat_diff_ratio
        # 准恒定判据阈值：默认由配置 TTL 粒度实时计算，而非预置常量。
        if quasi_flat_rel_std is None:
            denom = float(ttl_default_ref) if ttl_default_ref else 300.0
            quasi_flat_rel_std = (float(ttl_min_ref) / denom) if denom > 0 else 1e-3
        # 夹到合理区间，避免配置极端值使判据失效
        self.quasi_flat_rel_std = max(1e-6, min(0.5, float(quasi_flat_rel_std)))

        # 每上游的 RTT 统计
        self._rtt_stats: Dict[str, OnlineStats] = {}

        # 每上游 + 记录类型的响应大小统计
        # 值 = 整条响应字节数 len(response_bytes)（不是单个 RRset 字节数）
        self._size_stats: Dict[Tuple[str, int], OnlineStats] = {}

        # TTL 分布统计：按 (2LD, record_type) 分组
        # （OnlineStats 已在线维护 mean/variance，无需另存观测值列表；
        #   原先的 _ttl_observations 只写不读，会随运行时间无限增长）
        self._ttl_stats: Dict[Tuple[str, int], OnlineStats] = {}

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

    # TTL 基线分组容量上限：分组键含 2LD（客户端可控域名）。若无上限，
    # LAN 客户端可用随机域名（随机 2LD）无限撑大该表 → 内存耗尽（DoS）。
    _MAX_TTL_BASELINE_KEYS = 4096

    def _get_ttl_stats(self, ttl_key: Tuple[str, int]) -> OnlineStats:
        """取（或创建）TTL 基线分组；超容量上限时按插入顺序 FIFO 淘汰最旧分组。"""
        st = self._ttl_stats.get(ttl_key)
        if st is None:
            if len(self._ttl_stats) >= self._MAX_TTL_BASELINE_KEYS:
                self._ttl_stats.pop(next(iter(self._ttl_stats)), None)
            st = OnlineStats()
            self._ttl_stats[ttl_key] = st
        return st

    def _is_noise_small(self, stats: OnlineStats) -> bool:
        """基线噪声是否小到令 z-score 失真（含"准恒定"情形）。

        判据（阈值随数据/配置实时计算，无预置比例常量）：
          - std 绝对为 0 → 完全恒定；
          - std/|mean| < self.quasi_flat_rel_std（默认 = cache.min_ttl /
            cache.default_ttl）→ 噪声相对均值可忽略。
        """
        if stats.is_flat():
            return True
        m = abs(stats.mean)
        if m <= 0.0:
            return False
        return (stats.std / m) < self.quasi_flat_rel_std

    def _anomaly_score(self, stats: OnlineStats, value: float) -> float:
        """统一的偏差分值（非负）。

        统计 z-score 在基线噪声很小时会失真：std 只差一点点，z = 偏离/std
        就会被放大成几十上百 σ（如 TTL 基线 mean=300、std=0.5 时，300→275
        仅偏离 8% 却算出 50σ）。因此噪声过小时改用"相对偏离比例"判分；
        基线完全恒定（std≈0）时 z 恒为 0 也会漏报，同样走此路径。
        """
        if stats.n < 2:
            return 0.0
        if self._is_noise_small(stats):
            return abs(stats.flat_anomaly_score(value, self.flat_diff_ratio))
        return abs(stats.z_score(value))

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

                # 3. TTL 统计（TTL 是 RRset 级属性：每个 RRset 只计入一次。
                #    原先在 for rd 循环内更新会把同一 TTL 重复喂入 N 次，
                #    使基线样本数虚高、方差被低估 → 检测阶段 z 值偏大而误报）
                ttl = getattr(rrset, 'ttl', None) or 0
                if ttl > 0:
                    ttl_key = (_extract_2ld(str(rrset.name)), rdtype)
                    self._get_ttl_stats(ttl_key).update(float(ttl))
            return 0.0

        # ========== 检测阶段：先检查异常，后更新统计 ==========
        rdtypes_seen = set()
        for rrset in msg.answer:
            rdtypes_seen.add(rrset.rdtype)

        max_z = 0.0
        # 用 set 去重：同一响应可能有多个 RRset / 记录类型同时异常，
        # 此前用 list 会在循环内重复 append（日志因此出现 "ttl/ttl"）
        anomaly_types: set = set()

        # RTT 异常检测（在更新基线前检测偏差）
        if server_name in self._rtt_stats:
            rtt_z = self._anomaly_score(self._rtt_stats[server_name], rtt)
            if rtt_z > self.z_score_threshold:
                max_z = max(max_z, rtt_z)
                anomaly_types.add("rtt")

        # 更新 RTT 基线（检测之后才更新）
        if server_name not in self._rtt_stats:
            self._rtt_stats[server_name] = OnlineStats()
        self._rtt_stats[server_name].update(rtt)

        # 响应大小异常检测（基于检测前的基线）
        for rdtype in rdtypes_seen:
            key = (server_name, rdtype)
            if key in self._size_stats:
                size_z = self._anomaly_score(self._size_stats[key], float(response_size))
                if size_z > self.z_score_threshold:
                    max_z = max(max_z, size_z)
                    anomaly_types.add("size")

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
                    ttl_z = self._anomaly_score(self._ttl_stats[ttl_key], float(ttl))
                    if ttl_z > self.z_score_threshold:
                        max_z = max(max_z, ttl_z)
                        anomaly_types.add("ttl")

                # 更新 TTL 基线（每个 RRset 一次；OnlineStats 自带 mean/variance）
                self._get_ttl_stats(ttl_key).update(float(ttl))

        if max_z > self.z_score_threshold:
            self._stats["anomalies_detected"] += 1
            self._server_anomalies[server_name] = self._server_anomalies.get(server_name, 0) + 1
            # 每响应每个维度最多计一次（与 anomalies_detected 语义对齐，
            # 保证 rtt+size+ttl 三个计数之和不超过 anomalies_detected）
            if "rtt" in anomaly_types:
                self._stats["rtt_anomalies"] += 1
            if "size" in anomaly_types:
                self._stats["size_anomalies"] += 1
            if "ttl" in anomaly_types:
                self._stats["ttl_anomalies"] += 1
            logger.warning(
                "DNS 异常检测: 上游 %s 的 %s 维度偏差 %.1fσ"
                "（本次观测: rtt=%.0fms, 响应=%d bytes；σ 只属于该维度）",
                server_name, "/".join(sorted(anomaly_types)), max_z,
                rtt * 1000, response_size,
            )

        return max_z

    def get_server_anomaly_rate(self, server_name: str) -> float:
        """获取指定上游的异常率。"""
        total = self._server_learning_count.get(server_name, 0)
        if total == 0:
            return 0.0
        return self._server_anomalies.get(server_name, 0) / total

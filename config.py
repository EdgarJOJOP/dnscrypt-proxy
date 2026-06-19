"""
配置管理模块 - 支持 YAML 配置文件热加载

NDP 防护参数说明（位于 config.yaml network_monitor.ndp_protection）:
  enabled              - 默认开启，未检测到 IPv6 时自动关闭
  gateway_ipv6         - 手动指定 IPv6 网关，逗号交替格式 "IPv6,MAC,VLAN_ID,IPv6,MAC,VLAN_ID"
  vxlan_enabled        - false=VLAN(802.1Q), true=VXLAN(VNI)（ARP/NDP 共用）
  nud_window_ms        - NUD 检测窗口（毫秒），内网 <1ms，默认 80
  nud_threshold        - NUD 失败阈值：窗口内 NS 重传超过此数则告警，默认 3
  baseline_learn_ms    - 基线 MAC 学习确认时间（毫秒），默认 1
  send_ns_probe        - 是否启用主动 NS 探测验证网关真实性，默认 true

注：check_interval / ra_sniff_timeout / max_ra_routers 已移除。
    Worker 4 常驻 sniff 实时检测，无需轮询间隔和嗅探超时配置。
    Gateway/gateway_ipv6 现支持 3 元素格式 "(IP, MAC, VLAN_ID)"，
    vxlan_enabled 控制第 3 元素解释为 VLAN ID 或 VXLAN VNI。
"""

import os
import time
import asyncio
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path

import yaml
import logging


# ============================================================
# 完整配置模板（带注释），用于 config.yaml 缺失时的再生
# ============================================================
CONFIG_TEMPLATE = '# ============================================================\n# DNS 加密代理 - 全局配置文件（支持热加载）\n# 修改文件后自动检测变更并应用\n# ============================================================\n\nserver:\n  # 本地 DoH 服务（HTTPS 加密 DNS）\n  doh:\n    enabled: true\n    host: "127.0.0.1"            # IPv4 监听地址\n    port: 8443                  # DoH 端口\n    path: "/dns-query"\n    cert_path: "certs/localhost.crt"\n    key_path: "certs/localhost.key"\n    # IPv6 支持（同时监听 IPv6）\n    ipv6:\n      enabled: true\n      host: "::1"\n      port: 8443\n\n  # 本地 DoT 服务（DNS over TLS，RFC 7858）\n  dot:\n    enabled: false               # 默认关闭，设为 true 开启\n    host: "127.0.0.1"           # IPv4 监听地址\n    port: 853                   # 标准 DoT 端口\n    domain: ""                  # 服务器域名（SNI），留空则使用证书 CN\n    cert_path: "certs/localhost.crt"\n    key_path: "certs/localhost.key"\n    ipv6:\n      enabled: false\n      host: "::1"\n      port: 853\n\n  # 本地 DoQ 服务（DNS over QUIC，RFC 9250）\n  doq:\n    enabled: false               # 默认关闭，设为 true 开启\n    host: "127.0.0.1"           # IPv4 监听地址\n    port: 784                   # 标准 DoQ 端口\n    domain: ""                  # 服务器域名（SNI），留空则使用证书 CN\n    cert_path: "certs/localhost.crt"\n    key_path: "certs/localhost.key"\n    ipv6:\n      enabled: false\n      host: "::1"\n      port: 784\n\n  # 本地纯 DNS 服务器（UDP 53，不加密，默认关闭）\n  plain_dns:\n    enabled: false               # 默认关闭，设为 true 开启\n    host: "127.0.0.1"           # IPv4 监听地址\n    port: 53                    # 标准 DNS 端口（需要管理员权限）\n    ipv6:\n      enabled: false\n      host: "::1"\n\n# ============================================================\n# 上游 DNS 服务器\n# 并行查询所有启用的上游，取最快响应\n# ============================================================\nupstream:\n  # bootstrap DNS：仅用于解析 DoH/DoT/DoQ 服务器的 IP 地址\n  # 包含 IPv4 + IPv6 双栈 DNS 服务器\n  bootstrap_resolvers:\n    - "9.9.9.9"\n    - "223.5.5.5"               # 阿里 DNS (IPv4)\n    - "114.114.114.114"         # 114 DNS (IPv4)\n    - "119.29.29.29"            # 腾讯 DNS (IPv4)\n    - "2400:3200::1"            # 阿里 DNS (IPv6)\n    - "2400:da00::6666"         # 114 DNS (IPv6)\n\n  # DNS over HTTPS\n  doh:\n    - "https://dns.alidns.com/dns-query"\n    - "https://doh.pub/dns-query"\n    - "https://dns.adguard-dns.com/dns-query"\n    - "https://dns.cloudflare.com/dns-query"\n    - "https://dns11.quad9.net/dns-query"\n\n  # DNS over TLS\n  dot:\n    - "dns.alidns.com"\n    - "dns.pub"\n    - "dns.adguard-dns.com"\n    - "one.one.one.one"\n    - "1dot1dot1dot1.cloudflare-dns.com"\n\n  # DNS over QUIC\n  doq:\n    - "quic://dns9.quad9.net:853"         # Quad9 DoQ（已验证可用）\n    - "quic://dns.caliph.dev:853"\n    - "quic://dns.alidns.com:853"         # 阿里 DNS（部分环境可能不支持）\n\n# ============================================================\n# DNS 缓存配置\n# ============================================================\ncache:\n  enabled: true\n  max_size: 10000           # 最大缓存条目数，超限 LRU 淘汰\n  default_ttl: 300          # 默认缓存时间（秒）\n  min_ttl: 30               # 最小缓存时间（秒）\n  max_ttl: 86400            # 最大缓存时间（秒）\n  negative_ttl: 60          # 负面应答缓存时间（秒）\n  cleanup_interval: 60      # 过期清理间隔（秒）\n\n# ============================================================\n# DNSSEC 验证配置\n# ============================================================\ndnssec:\n  enabled: true                     # 全局 DNSSEC 验证开关\n  # 验证模式:\n  #   ad_check       - 仅检查 AD 位（快速，依赖上游验证）\n  #   strict         - 严格本地验证 RRSIG 签名链（安全但较慢）\n  mode: "ad_check"\n  # 是否丢弃验证失败的响应（bogus）\n  drop_bogus: false\n\n# ============================================================\n# 自定义域名 IP 映射（类似 Windows hosts 文件）\n# 格式: "域名 IP1,IP2" (域名和IP用空格分隔,多IP用逗号)\n# 支持 IPv4 和 IPv6\n# ============================================================\nhosts:\n  enabled: false\n  mappings:\n    # - "my.dns 127.0.0.1,192.168.1.1"\n    # - "router.local 192.168.1.1"\n    # - "ipv6test.local ::1"\n\n# ============================================================\n# 域名过滤规则（AdGuard Home 语法）\n# ============================================================\nfilter:\n  enabled: true\n  # 规则文件路径（支持本地文件和远程 URL）\n  rules_files:\n  # 远程规则列表（定时自动更新）\n  rules_urls:\n    - "https://proxy.gitwarp.top/https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/main/rule/all.txt"\n    # AdGuard 官方推荐规则列表（按需启用）\n    # - "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"\n    # - "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Chinese/filter.txt"\n    # - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"\n  # 远程规则更新间隔（小时，0=不自动更新）\n  update_interval: 24\n  # 是否拦截后返回 NXDOMAIN\n  block_nxdomain: true\n  # 自定义拦截页面 IP（NXDOMAIN 模式下无效）\n  block_ip: "0.0.0.0"\n\n# ============================================================\n# 请求日志（异步缓冲写入）\n# ============================================================\nlogging:\n  enabled: true\n  buffer_size: 500          # 内存缓冲条目数，达到后写入文件并清空\n  flush_interval: 10        # 定时刷新间隔（秒）\n  log_dir: "logs"\n  log_file: "dns_queries.log"\n  detailed: true\n  max_log_size_mb: 10      # 日志文件最大大小（MB），超限自动裁剪保留后半部分\n\n# ============================================================\n# TLS/SSL 配置（加密连接参数）\n# ============================================================\ntls:\n  # Encrypted Client Hello（加密客户端问候）\n  # 防止 SNI 明文泄露导致的域名嗅探和干扰\n  # 注意：需要 OpenSSL 4.0+ 才能真正启用 ECH\n  ech_enabled: false\n  # 密码套件（默认安全配置）\n  ciphers: "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"\n  # OpenSSL 4.0 DLL 路径（用于上游 ECH 连接）\n  # 下载: https://github.com/TaurusTLS-Developers/OpenSSL-Distribution/releases/tag/v4.0.0\n  # 解压后将 libssl-4-x64.dll 和 libcrypto-4-x64.dll 所在目录填在这里\n  # 支持正斜杠和反斜杠两种格式:\n  #   Windows: "D:/dns/openssl4" 或 \'D:\\dns\\openssl4\' 或 "D:\\\\dns\\\\openssl4"\n  #   Linux:   "/usr/local/openssl4"\n  openssl4_dll_path: "D:/dns/1/dnscrypt-proxy/openssl-4.0.0-Windows-x64"\n  # 留空则尝试使用 certifi（推荐）: pip install certifi(默认安装了)\n  ca_path: ""\n\n  # ============================================================\n  # ECH 配置（每台上游服务器）\n  # 支持 3 种格式:\n  #   1. Base64 编码的 ECHConfigList（静态配置）\n  #      "dns.alidns.com": "AFj+DQAAAC..."\n  #   2. DNS 查询 URL（自动查询此上游的 HTTPS 记录）\n  #      "dns.cloudflare.com": "https://cloudflare-dns.com/dns-query"\n  #   3. hostname+DNS 查询（查询指定 hostname 的 HTTPS 记录）\n  #      "dns.cloudflare.com": "cloudflare-ech.com+https://cloudflare-dns.com/dns-query"\n  # ============================================================\n  ech:\n    # Cloudflare DNS 的 ECH 配置：查询 cloudflare-ech.com 的 HTTPS 记录\n    "dns.cloudflare.com": "cloudflare-ech.com+https://cloudflare-dns.com/dns-query"\n    "1dot1dot1dot1.cloudflare-dns.com": "cloudflare-ech.com+https://cloudflare-dns.com/dns-query"\n\n# ============================================================\n# 网络连通性监控（自动恢复上游服务器连接）\n# 多IP/多网关场景下，IP/网关变更后自动检测并恢复\n# ============================================================\nnetwork_monitor:\n  enabled: true\n  ping_interval: 0.05       # 网关检测间隔（秒，0.01 = 10ms）\n  external_interval: 15     # 外网 ping/DNS 探测间隔（秒）\n  ping_timeout: 0.085       # ping 超时（秒，与 ping_interval 一致）\n  # ICMP ping 检测目标（IPv4 + IPv6 双栈）\n  ping_targets_v4:\n    - "223.5.5.5"\n    - "114.114.114.114"\n  ping_targets_v6:\n    - "2400:3200::1"\n    - "2400:da00::6666"\n  # DNS 探测域名（向公共 DNS 发送 DNS 查询验证）\n  dns_probe_domains:\n    - "www.baidu.com"\n    - "www.qq.com"\n  # 连续检测失败多少次后进入降级模式\n  failure_threshold: 3\n  # 退出降级需要连续成功检测次数\n  recovery_check_count: 2\n\n  # ============================================================\n  # ARP 防护（检测并修复因 ARP 投毒/IP 冲突导致的网络中断）\n  # 当 ping 检测失败但本地网卡配置正常时:\n  #   1. 检测本机 ARP 表是否被 MITM 篡改（对比网关 MAC 预期值）\n  #   2. 爆发 GARP 广播强制刷新路由器 ARP 表\n  #   3. 检测 IP 冲突并自动修复\n  #   4. 两阶段 IP 切换抗持续 ARP 中毒\n  # 支持多网关/多网卡场景。支持 Windows / Linux。\n  # ============================================================\n  arp_protection:\n    enabled: true                  # ARP 防护总开关\n    # 手动指定网关（自动探测的高优先级替代）\n    # 格式: "网关IP,网关MAC,VLAN_ID" (英文逗号隔开), 留空则自动探测\n    # VLAN_ID 默认为空（无 VLAN/VXLAN）；vxlan_enabled=true 时解释为 VXLAN VNI\n    # 多组: "IP1,MAC1,VLAN1,IP2,MAC2,VLAN2" (交替逗号隔开), 适配多网关场景\n    # 例如: "192.168.1.1,00-11-22-33-44-55,12"    IP+MAC+VLAN 12\n    #       "192.168.1.1,00-11-22-33-44-55,"       IP+MAC, 无 VLAN\n    #       "192.168.1.1,,"                        仅 IP, MAC/VLAN 自动\n    #       多组: "192.168.1.1,aa-bb,10,10.0.0.1,cc-dd,20"\n    # 注意: 只填 IP 不填 MAC, 自动探测 MAC; 都留空则完全自动探测\n    vxlan_enabled: false           # false=VLAN(802.1Q), true=VXLAN(VNI)\n    gateway: ""\n\n  # ============================================================\n  # NDP 防护（IPv6 版 ARP 防护 — 邻居发现协议欺骗防护）\n  # 当 ping 检测失败但本地网卡正常时，检测 IPv6 NDP 缓存是否被投毒，\n  # 发送 Unsolicited NA 刷新路由器邻居表，设静态 NDP 条目防篡改。\n  #\n  # 覆盖攻击面（RFC 3756）:\n  #   T1  NA 欺骗       — 常驻嗅探实时基线比对\n  #   T2  NS 欺骗       — 主动 NS 探测验证网关真实性\n  #   T3  RA 欺骗       — 非信任 MAC 源发 RA 即告警（源 MAC 自动学习）\n  #   T4  DAD DoS       — 追踪 DAD NS 重复地址检测\n  #   T5  NUD 失败      — 窗口内 NS 重传超阈值告警\n  #   T6  Redirect 欺骗 — 非信任源 Redirect 丢弃\n  #   T7  NDP 泛洪      — 邻居表增长率超限检测\n  #   T8  Replay 攻击   — 静态 NDP 条目终局防御\n  #   T9  Rogue DHCPv6  — Event 驱动嗅探检测\n  # 5 个常驻 Worker，Event 驱动，不用就冻结。\n  # 需要安装 Npcap 以使用 scapy 发包（否则降级为 ping 等效方案）。\n  # ============================================================\n  ndp_protection:\n    enabled: true                 # 默认开启，未检测到 IPv6 时自动关闭\n    # 手动指定 IPv6 网关（自动探测的高优先级替代）\n    # 格式: "网关IPv6,网关MAC,VLAN_ID" (英文逗号隔开), 留空则自动探测\n    # VLAN_ID 默认为空（无 VLAN/VXLAN）；vxlan_enabled=true 时解释为 VXLAN VNI\n    # IPv6 与 MAC 的区分: MAC 为 6 组 2 位十六进制数 (xx:xx:xx:xx:xx:xx)\n    #                      IPv6 含 :: 或超过 2 个冒号\n    # 示例:\n    #   "2001:db8::1,00-11-22-33-44-55,100"      指定 IPv6 + MAC + VLAN 100\n    #   "2001:db8::1,00-11-22-33-44-55,"         指定 IPv6 + MAC, 无 VLAN\n    #   "2001:db8::1,,"                           指定 IPv6, MAC/VLAN 自动探测\n    #   "fe80::1,aa-bb,10,2001:db8::1,cc-dd,20"  多组（3 元素交替格式）\n    vxlan_enabled: false           # false=VLAN(802.1Q), true=VXLAN(VNI)\n    gateway_ipv6: ""\n    # NUD 检测窗口（毫秒），内网 <1ms，默认 80\n    # 窗口内追踪对网关的 NS 重传次数，超过 nud_threshold 则触发告警（T5）\n    nud_window_ms: 80\n    # NUD 失败阈值：窗口内 NS 重传超过此数则告警，默认 3\n    nud_threshold: 3\n    # 基线 MAC 学习确认时间（毫秒），默认 1\n    # 首次捕获到网关 NA 后等待此时间确认 MAC 稳定，再写入静态 NDP 条目\n    baseline_learn_ms: 1\n    # 主动 NS 探测：构造 NS 查询验证网关真实性，检测 T2 NS 欺骗攻击\n    # 有 scapy 时必启用\n    send_ns_probe: True\n\n# ============================================================\n# 性能与资源优化\n# ============================================================\nperformance:\n  parallel_timeout: 2.0     # 并行查询超时（秒）\n  max_concurrent: 1000      # 最大并发查询数（受 Windows 句柄数限制，需注册表调整 HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Ancillary Function Driver for Winsock\\Parameters\\MaxUserPort，默认 16384，建议 ≥30000）\n  max_concurrent_per_ip: 50 # 单 IP 最大并发查询数（127.0.0.1 和 ::1 除外）\n  connection_pool_size: 1000 # 连接池大小（同时打开的上游连接数，每个 TCP 连接消耗 2-3 个句柄）\n  memory_limit_mb: 512      # 内存软限制（MB）\n  cpu_core_limit: 0         # CPU 核心限制（0=自动=总核心数-1；手动设置如 4 表示最多用 4 核）\n  monitor_interval: 30      # 资源监控间隔（秒）\n  aggressive_gc: true       # 低负载时主动 GC\n  gc_interval: 60           # GC 触发间隔（秒）\n  # ============================================================\n  # QPS 限速（每秒请求数上限，0=无限制）\n  # 所有客户端（含 localhost）共同遵守\n  # ============================================================\n  doh_qps_limit: 1000       # 本地DoH 每秒最多处理 1000 个请求\n  dot_qps_limit: 500        # 本地DoT 每秒最多处理 500 个请求\n  doq_qps_limit: 500        # 本地DoQ 每秒最多处理 500 个请求\n  # ============================================================\n  # 连接数上限（防止恶意客户端耗尽连接池）\n  # ============================================================\n  dot_max_connections: 200  # 本地DoT 最大并发 TCP 连接数\n  doq_max_connections: 100  # 本地DoQ 最大 QUIC 连接数'


logger = logging.getLogger("dns-proxy.config")

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"



class Config:
    """配置管理"""

    def __init__(self, config_path=None):
        self._path = Path(config_path or DEFAULT_CONFIG_PATH)
        self._data = {}
        self._last_mtime = 0.0
        self._lock = asyncio.Lock()
        self._reload_callbacks = []
        self._section_snapshots = {}
        self._load()

    def _load(self):
        if self._path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}
            self._last_mtime = self._path.stat().st_mtime
        else:
            self._data = self._defaults()
            self._save(use_template=True)
        self._update_section_snapshots()

    def _update_section_snapshots(self):
        self._section_snapshots = {}
        for key in self._data:
            if isinstance(self._data[key], dict):
                self._section_snapshots[key] = dict(self._data[key])
            else:
                self._section_snapshots[key] = self._data[key]

    def get_changed_sections(self) -> set:
        changed = set()
        sections_to_check = {"cache", "filter", "hosts", "server", "upstream",
                             "logging", "dnssec", "performance", "tls", "network_monitor"}
        for section in sections_to_check:
            old = self._section_snapshots.get(section, {})
            new = self._data.get(section, {})
            if old != new:
                changed.add(section)
        return changed

    def _defaults(self) -> Dict:
        return yaml.safe_load(CONFIG_TEMPLATE)

    def _save(self, use_template=False):
        if use_template:
            with open(self._path, "w", encoding="utf-8") as f:
                f.write(CONFIG_TEMPLATE)
        else:
            from ruamel.yaml import YAML
            ryaml = YAML()
            ryaml.indent(mapping=2, sequence=4, offset=2)
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8") as f:
                    ryaml_data = ryaml.load(f)
            else:
                ryaml_data = yaml.safe_load(CONFIG_TEMPLATE)
            def _deep_update(dst, src):
                for k, v in src.items():
                    if isinstance(v, dict) and k in dst and isinstance(dst[k], dict):
                        _deep_update(dst[k], v)
                    else:
                        dst[k] = v
            _deep_update(ryaml_data, self._data)
            with open(self._path, "w", encoding="utf-8") as f:
                ryaml.dump(ryaml_data, f)
        self._last_mtime = self._path.stat().st_mtime

    async def check_reload(self) -> set:
        if not self._path.exists():
            return set()
        mtime = self._path.stat().st_mtime
        if mtime > self._last_mtime:
            async with self._lock:
                old_snapshots = dict(self._section_snapshots)
                self._load()
                sections_to_check = {"cache", "filter", "hosts", "server", "upstream",
                                     "logging", "dnssec", "performance", "tls", "network_monitor"}
                changed = set()
                for section in sections_to_check:
                    old = old_snapshots.get(section, {})
                    new = self._section_snapshots.get(section, {})
                    if old != new:
                        changed.add(section)
                for cb in self._reload_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(cb):
                            await cb(self._data, changed)
                        else:
                            cb(self._data, changed)
                    except Exception as e:
                        logger.warning("配置回调异常: %s", e)
            return changed
        return set()

    def on_reload(self, callback):
        self._reload_callbacks.append(callback)

    # --- Properties ---
    @property
    def doh_host(self) -> str:
        return self._data.get("server", {}).get("doh", {}).get("host", "0.0.0.0")
    @property
    def doh_port(self) -> int:
        return self._data.get("server", {}).get("doh", {}).get("port", 8443)
    @property
    def doh_path(self) -> str:
        return self._data.get("server", {}).get("doh", {}).get("path", "/dns-query")
    @property
    def doh_cert_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("doh", {}).get("cert_path", "certs/localhost.crt"))
    @property
    def doh_key_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("doh", {}).get("key_path", "certs/localhost.key"))
    @property
    def bootstrap_resolvers(self) -> List[str]:
        return self._data.get("upstream", {}).get("bootstrap_resolvers", ["223.5.5.5"]) or []
    @property
    def doh_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("doh", []) or []
    @property
    def dot_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("dot", []) or []
    @property
    def doq_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("doq", []) or []
    @property
    def all_upstream_addresses(self) -> List[str]:
        addrs = []
        for s in self.doh_servers:
            addrs.append(s.replace("https://", "").split("/")[0])
        addrs.extend(self.dot_servers)
        for s in self.doq_servers:
            addrs.append(s.replace("quic://", "").split(":")[0])
        return list(set(addrs))
    @property
    def cache_enabled(self) -> bool:
        return self._data.get("cache", {}).get("enabled", True)
    @property
    def cache_max_size(self) -> int:
        return self._data.get("cache", {}).get("max_size", 10000)
    @property
    def cache_default_ttl(self) -> int:
        return self._data.get("cache", {}).get("default_ttl", 300)
    @property
    def cache_min_ttl(self) -> int:
        return self._data.get("cache", {}).get("min_ttl", 30)
    @property
    def cache_max_ttl(self) -> int:
        return self._data.get("cache", {}).get("max_ttl", 86400)
    @property
    def cache_negative_ttl(self) -> int:
        return self._data.get("cache", {}).get("negative_ttl", 60)
    @property
    def cache_cleanup_interval(self) -> int:
        return self._data.get("cache", {}).get("cleanup_interval", 60)
    @property
    def filter_enabled(self) -> bool:
        return self._data.get("filter", {}).get("enabled", True)
    @property
    def filter_rules_files(self) -> List[str]:
        result = self._data.get("filter", {}).get("rules_files")
        return result if isinstance(result, list) else []
    @property
    def filter_block_nxdomain(self) -> bool:
        return self._data.get("filter", {}).get("block_nxdomain", True)
    @property
    def filter_block_ip(self) -> str:
        return self._data.get("filter", {}).get("block_ip", "0.0.0.0")
    @property
    def logging_enabled(self) -> bool:
        return self._data.get("logging", {}).get("enabled", True)
    @property
    def logging_buffer_size(self) -> int:
        return self._data.get("logging", {}).get("buffer_size", 500)
    @property
    def logging_flush_interval(self) -> int:
        return self._data.get("logging", {}).get("flush_interval", 10)
    @property
    def logging_dir(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("logging", {}).get("log_dir", "logs"))
    @property
    def logging_file(self) -> str:
        return self._data.get("logging", {}).get("log_file", "dns_queries.log")
    @property
    def logging_detailed(self) -> bool:
        return self._data.get("logging", {}).get("detailed", True)
    @property
    def logging_max_log_size_mb(self) -> int:
        return int(self._data.get("logging", {}).get("max_log_size_mb", 100))
    @property
    def parallel_timeout(self) -> float:
        return float(self._data.get("performance", {}).get("parallel_timeout", 3.0))
    @property
    def max_concurrent(self) -> int:
        return self._data.get("performance", {}).get("max_concurrent", 100)
    @property
    def connection_pool_size(self) -> int:
        return self._data.get("performance", {}).get("connection_pool_size", 100)
    @property
    def max_concurrent_per_ip(self) -> int:
        return self._data.get("performance", {}).get("max_concurrent_per_ip", 50)
    @property
    def memory_limit_mb(self) -> int:
        return self._data.get("performance", {}).get("memory_limit_mb", 768)
    @property
    def cpu_core_limit(self) -> int:
        return self._data.get("performance", {}).get("cpu_core_limit", 0)
    @property
    def monitor_interval(self) -> int:
        return self._data.get("performance", {}).get("monitor_interval", 30)
    @property
    def aggressive_gc(self) -> bool:
        return self._data.get("performance", {}).get("aggressive_gc", True)
    @property
    def gc_interval(self) -> int:
        return self._data.get("performance", {}).get("gc_interval", 60)
    @property
    def doh_qps_limit(self) -> int:
        return int(self._data.get("performance", {}).get("doh_qps_limit", 1000))
    @property
    def dot_qps_limit(self) -> int:
        return int(self._data.get("performance", {}).get("dot_qps_limit", 500))
    @property
    def doq_qps_limit(self) -> int:
        return int(self._data.get("performance", {}).get("doq_qps_limit", 500))
    @property
    def dot_max_connections(self) -> int:
        return int(self._data.get("performance", {}).get("dot_max_connections", 200))
    @property
    def doq_max_connections(self) -> int:
        return int(self._data.get("performance", {}).get("doq_max_connections", 100))
    @property
    def dnssec_enabled(self) -> bool:
        return self._data.get("dnssec", {}).get("enabled", True)
    @property
    def dnssec_mode(self) -> str:
        return self._data.get("dnssec", {}).get("mode", "ad_check")
    @property
    def dnssec_drop_bogus(self) -> bool:
        return self._data.get("dnssec", {}).get("drop_bogus", False)
    @property
    def doh_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("enabled", False)
    @property
    def doh_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("host", "::")
    @property
    def doh_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("port", 8443)
    @property
    def local_dot_enabled(self) -> bool:
        return self._data.get("server", {}).get("dot", {}).get("enabled", False)
    @property
    def local_dot_host(self) -> str:
        return self._data.get("server", {}).get("dot", {}).get("host", "127.0.0.1")
    @property
    def local_dot_port(self) -> int:
        return self._data.get("server", {}).get("dot", {}).get("port", 853)
    @property
    def local_dot_domain(self) -> str:
        return self._data.get("server", {}).get("dot", {}).get("domain", "")
    @property
    def local_dot_cert_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("dot", {}).get("cert_path", "certs/localhost.crt"))
    @property
    def local_dot_key_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("dot", {}).get("key_path", "certs/localhost.key"))
    @property
    def local_dot_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("enabled", False)
    @property
    def local_dot_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("host", "::1")
    @property
    def local_dot_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("port", 853)
    @property
    def local_doq_enabled(self) -> bool:
        return self._data.get("server", {}).get("doq", {}).get("enabled", False)
    @property
    def local_doq_host(self) -> str:
        return self._data.get("server", {}).get("doq", {}).get("host", "127.0.0.1")
    @property
    def local_doq_port(self) -> int:
        return self._data.get("server", {}).get("doq", {}).get("port", 784)
    @property
    def local_doq_domain(self) -> str:
        return self._data.get("server", {}).get("doq", {}).get("domain", "")
    @property
    def local_doq_cert_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("doq", {}).get("cert_path", "certs/localhost.crt"))
    @property
    def local_doq_key_path(self) -> str:
        return os.path.join(os.path.dirname(self._path), self._data.get("server", {}).get("doq", {}).get("key_path", "certs/localhost.key"))
    @property
    def local_doq_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("enabled", False)
    @property
    def local_doq_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("host", "::1")
    @property
    def local_doq_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("port", 784)
    @property
    def plain_dns_enabled(self) -> bool:
        return self._data.get("server", {}).get("plain_dns", {}).get("enabled", False)
    @property
    def plain_dns_host(self) -> str:
        return self._data.get("server", {}).get("plain_dns", {}).get("host", "0.0.0.0")
    @property
    def plain_dns_port(self) -> int:
        return self._data.get("server", {}).get("plain_dns", {}).get("port", 53)
    @property
    def plain_dns_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("plain_dns", {}).get("ipv6", {}).get("enabled", False)
    @property
    def plain_dns_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("plain_dns", {}).get("ipv6", {}).get("host", "::")
    @property
    def filter_rules_urls(self) -> List[str]:
        result = self._data.get("filter", {}).get("rules_urls")
        return result if isinstance(result, list) else []
    @property
    def filter_update_interval(self) -> int:
        return self._data.get("filter", {}).get("update_interval", 0)
    @property
    def hosts_config(self) -> dict:
        return self._data.get("hosts", {})
    @property
    def ech_enabled(self) -> bool:
        return self._data.get("tls", {}).get("ech_enabled", False)
    @property
    def tls_ciphers(self) -> str:
        return self._data.get("tls", {}).get("ciphers", "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
    @property
    def openssl4_dll_path(self) -> str:
        raw = self._data.get("tls", {}).get("openssl4_dll_path", "") or ""
        return self._normalize_path(raw)
    @property
    def openssl4_ca_path(self) -> str:
        raw = self._data.get("tls", {}).get("ca_path", "") or ""
        return self._normalize_path(raw)
    @property
    def ech_configs(self) -> dict:
        return dict(self._data.get("tls", {}).get("ech", {}) or {})
    @staticmethod
    def _normalize_path(path: str) -> str:
        if not path:
            return ""
        return os.path.normpath(path)
    @property
    def network_monitor_enabled(self) -> bool:
        return self._data.get("network_monitor", {}).get("enabled", True)
    @property
    def network_monitor_config(self) -> dict:
        return self._data.get("network_monitor", {})
    @property
    def arp_protection_config(self) -> dict:
        raw = dict(self._data.get("network_monitor", {}).get("arp_protection", {}))
        raw.setdefault("gateway_ip", "")
        raw.setdefault("gateway_mac", "")
        raw.setdefault("vxlan_enabled", False)
        return raw
    @property
    def ndp_protection_config(self) -> dict:
        """NDP 防护配置（由 NDPProtection 自行解析）"""
        raw = dict(self._data.get("network_monitor", {}).get("ndp_protection", {}))
        raw.setdefault("gateway_ipv6", "")
        raw.setdefault("vxlan_enabled", False)
        raw.setdefault("nud_window_ms", 80)
        raw.setdefault("nud_threshold", 3)
        raw.setdefault("baseline_learn_ms", 1)
        raw.setdefault("send_ns_probe", True)
        return raw
    @property
    def response_verification_config(self) -> dict:
        """DNS 响应验证配置（多上游一致性 + 异常检测）"""
        return dict(self._data.get("network_monitor", {}).get("response_verification", {}))
    @property
    def response_consistency_enabled(self) -> bool:
        return self._data.get("network_monitor", {}).get("response_verification", {}).get("consistency", {}).get("enabled", True)
    @property
    def response_consistency_min_responses(self) -> int:
        return self._data.get("network_monitor", {}).get("response_verification", {}).get("consistency", {}).get("min_responses", 2)
    @property
    def response_consistency_window_ms(self) -> float:
        return float(self._data.get("network_monitor", {}).get("response_verification", {}).get("consistency", {}).get("consistency_window_ms", 800.0))
    @property
    def anomaly_detection_enabled(self) -> bool:
        return self._data.get("network_monitor", {}).get("response_verification", {}).get("anomaly_detection", {}).get("enabled", True)
    @property
    def anomaly_detection_learning_samples(self) -> int:
        return self._data.get("network_monitor", {}).get("response_verification", {}).get("anomaly_detection", {}).get("learning_samples", 200)
    @property
    def anomaly_detection_z_score_threshold(self) -> float:
        return float(self._data.get("network_monitor", {}).get("response_verification", {}).get("anomaly_detection", {}).get("z_score_threshold", 3.0))
    @property
    def response_verification_max_background_servers(self) -> int:
        """后台验证时最多查询的上游数（随机抽样），减少连接开销。"""
        return int(self._data.get("network_monitor", {}).get("response_verification", {}).get("consistency", {}).get("max_background_servers", 5))
    def get_raw(self) -> Dict[str, Any]:
        return dict(self._data)
    def update_section(self, section: str, data: dict):
        keys = section.split(".")
        current = self._data
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        current[keys[-1]] = data
        self._save()
    def update_upstream(self, upstream_type: str, servers: List[str]):
        valid_types = {"bootstrap_resolvers", "doh", "dot", "doq"}
        if upstream_type not in valid_types:
            raise ValueError(f"类型必须为: {valid_types}")
        self._data.setdefault("upstream", {})[upstream_type] = servers
        self._save()

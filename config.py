"""
配置管理模块 - 支持 YAML 配置文件热加载
"""

import os
import time
import asyncio
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


class Config:
    """配置管理"""

    def __init__(self, config_path: Optional[str] = None):
        self._path = Path(config_path or DEFAULT_CONFIG_PATH)
        self._data: Dict[str, Any] = {}
        self._last_mtime: float = 0
        self._lock = asyncio.Lock()
        self._reload_callbacks: List[Callable] = []
        # 记录上一次各配置段的快照，用于检测哪些段发生了变更
        self._section_snapshots: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """加载配置文件"""
        if self._path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}
            self._last_mtime = self._path.stat().st_mtime
        else:
            self._data = self._defaults()
            self._save()
        self._update_section_snapshots()

    def _update_section_snapshots(self):
        """更新各配置段的快照，用于后续检测变更"""
        self._section_snapshots = {}
        for key in self._data:
            if isinstance(self._data[key], dict):
                self._section_snapshots[key] = dict(self._data[key])
            else:
                self._section_snapshots[key] = self._data[key]

    def get_changed_sections(self) -> set:
        """
        返回自上次快照以来发生变更的配置段名称集合。
        返回示例: {'cache', 'filter', 'hosts', 'upstream'}
        """
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
        """默认配置"""
        return {
            "server": {
                "doh": {
                    "enabled": True,
                    "host": "0.0.0.0",
                    "port": 8443,
                    "path": "/dns-query",
                    "cert_path": "certs/localhost.crt",
                    "key_path": "certs/localhost.key",
                    "ipv6": {
                        "enabled": True,
                        "host": "::",
                        "port": 8443,
                    },
                },
                # 本地 DoT 服务（DNS over TLS）
                "dot": {
                    "enabled": False,
                    "host": "127.0.0.1",
                    "port": 853,
                    "domain": "",
                    "cert_path": "certs/localhost.crt",
                    "key_path": "certs/localhost.key",
                    "ipv6": {
                        "enabled": False,
                        "host": "::1",
                        "port": 853,
                    },
                },
                # 本地 DoQ 服务（DNS over QUIC）
                "doq": {
                    "enabled": False,
                    "host": "127.0.0.1",
                    "port": 784,
                    "domain": "",
                    "cert_path": "certs/localhost.crt",
                    "key_path": "certs/localhost.key",
                    "ipv6": {
                        "enabled": False,
                        "host": "::1",
                        "port": 784,
                    },
                },
            },
            "upstream": {
                "bootstrap_resolvers": ["223.5.5.5", "114.114.114.114", "119.29.29.29"],
                "doh": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
                "dot": ["dns.alidns.com", "dns.pub"],
                "doq": ["quic://dns.alidns.com:853"],
            },
            "cache": {
                "enabled": True,
                "max_size": 10000,
                "default_ttl": 300,
                "min_ttl": 30,
                "max_ttl": 86400,
                "negative_ttl": 60,
                "cleanup_interval": 60,
            },
            "dnssec": {
                "enabled": True,
                "mode": "ad_check",
                "drop_bogus": False,
            },
            "filter": {
                "enabled": True,
                "rules_files": ["rules/filter_rules.txt"],
                "rules_urls": [],
                "update_interval": 24,
                "block_nxdomain": True,
                "block_ip": "0.0.0.0",
            },
            "hosts": {
                "enabled": True,
                "mappings": {},
            },
            "logging": {
                "enabled": True,
                "buffer_size": 500,
                "flush_interval": 10,
                "log_dir": "logs",
                "log_file": "dns_queries.log",
                "detailed": True,
                "max_log_size_mb": 100,
            },
            "performance": {
                "parallel_timeout": 3.0,
                "max_concurrent": 1000,
                "connection_pool_size": 1000,
                "max_concurrent_per_ip": 50,
                "memory_limit_mb": 256,
                "cpu_core_limit": 0,  # 0=自动=总核心数-1
                "cpu_usage_limit": 70,
                "monitor_interval": 30,
                "aggressive_gc": True,
                "gc_interval": 60,
            },
            "network_monitor": {
                "enabled": True,
                "ping_interval": 15,
                "ping_timeout": 5,
                "ping_targets_v4": ["223.5.5.5", "114.114.114.114"],
                "ping_targets_v6": ["2400:3200::1", "2400:da00::6666"],
                "dns_probe_domains": ["www.baidu.com", "www.qq.com"],
                "failure_threshold": 3,
                "recovery_check_count": 2,
            },
            "tls": {
                "ech_enabled": False,
                "ciphers": "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4",
                "openssl4_dll_path": "",
                "ca_path": "",
                "ech": {},  # hostname -> config_string: base64 | "https://dns/dns-query" | "hostname+https://dns/dns-query"
            },
        }

    def _save(self):
        """保存配置到文件"""
        with open(self._path, "w", encoding="utf-8") as f:
            yaml.dump(self._data, f, default_flow_style=False, allow_unicode=True)
        self._last_mtime = self._path.stat().st_mtime

    async def check_reload(self) -> set:
        """
        检查配置文件是否变更，是则热加载。
        返回发生变更的配置段名称集合，无变更返回空集。
        """
        if not self._path.exists():
            return set()
        mtime = self._path.stat().st_mtime
        if mtime > self._last_mtime:
            async with self._lock:
                # 保存旧快照用于计算变更
                old_snapshots = dict(self._section_snapshots)
                self._load()
                # 计算所有段的变化
                sections_to_check = {"cache", "filter", "hosts", "server", "upstream",
                                      "logging", "dnssec", "performance", "tls", "network_monitor"}
                changed = set()
                for section in sections_to_check:
                    old = old_snapshots.get(section, {})
                    new = self._section_snapshots.get(section, {})
                    if old != new:
                        changed.add(section)
                # 通知回调，传入变更的配置段信息
                for cb in self._reload_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(cb):
                            await cb(self._data, changed)
                        else:
                            cb(self._data, changed)
                    except Exception:
                        pass
            return changed
        return set()

    def on_reload(self, callback: Callable):
        """注册配置热加载回调"""
        self._reload_callbacks.append(callback)

    # --- 便捷访问属性 ---
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
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("doh", {}).get("cert_path", "certs/localhost.crt"),
        )

    @property
    def doh_key_path(self) -> str:
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("doh", {}).get("key_path", "certs/localhost.key"),
        )

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
        """获取所有上游服务器地址（用于 bootstrap）"""
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
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("logging", {}).get("log_dir", "logs"),
        )

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
        return self._data.get("performance", {}).get("memory_limit_mb", 256)

    @property
    def cpu_core_limit(self) -> int:
        return self._data.get("performance", {}).get("cpu_core_limit", 0)

    @property
    def cpu_usage_limit(self) -> int:
        return self._data.get("performance", {}).get("cpu_usage_limit", 70)

    @property
    def monitor_interval(self) -> int:
        return self._data.get("performance", {}).get("monitor_interval", 30)

    @property
    def aggressive_gc(self) -> bool:
        return self._data.get("performance", {}).get("aggressive_gc", True)

    @property
    def gc_interval(self) -> int:
        return self._data.get("performance", {}).get("gc_interval", 60)

    # --- DNSSEC ---
    @property
    def dnssec_enabled(self) -> bool:
        return self._data.get("dnssec", {}).get("enabled", True)

    @property
    def dnssec_mode(self) -> str:
        return self._data.get("dnssec", {}).get("mode", "ad_check")

    @property
    def dnssec_drop_bogus(self) -> bool:
        return self._data.get("dnssec", {}).get("drop_bogus", False)

    # --- IPv6 DoH ---
    @property
    def doh_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("enabled", False)

    @property
    def doh_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("host", "::")

    @property
    def doh_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("doh", {}).get("ipv6", {}).get("port", 8443)

    # --- 本地 DoT 服务器 ---
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
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("dot", {}).get("cert_path", "certs/localhost.crt"),
        )

    @property
    def local_dot_key_path(self) -> str:
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("dot", {}).get("key_path", "certs/localhost.key"),
        )

    @property
    def local_dot_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("enabled", False)

    @property
    def local_dot_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("host", "::1")

    @property
    def local_dot_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("dot", {}).get("ipv6", {}).get("port", 853)

    # --- 本地 DoQ 服务器 ---
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
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("doq", {}).get("cert_path", "certs/localhost.crt"),
        )

    @property
    def local_doq_key_path(self) -> str:
        return os.path.join(
            os.path.dirname(self._path),
            self._data.get("server", {}).get("doq", {}).get("key_path", "certs/localhost.key"),
        )

    @property
    def local_doq_ipv6_enabled(self) -> bool:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("enabled", False)

    @property
    def local_doq_ipv6_host(self) -> str:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("host", "::1")

    @property
    def local_doq_ipv6_port(self) -> int:
        return self._data.get("server", {}).get("doq", {}).get("ipv6", {}).get("port", 784)

    # --- 纯 DNS 服务器 (UDP 53) ---
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

    # --- 过滤规则更新 ---
    @property
    def filter_rules_urls(self) -> List[str]:
        result = self._data.get("filter", {}).get("rules_urls")
        return result if isinstance(result, list) else []

    @property
    def filter_update_interval(self) -> int:
        """返回更新间隔（小时），0 表示不自动更新"""
        return self._data.get("filter", {}).get("update_interval", 0)

    # --- 自定义 hosts ---
    @property
    def hosts_config(self) -> dict:
        return self._data.get("hosts", {})

    # --- TLS/ECH ---
    @property
    def ech_enabled(self) -> bool:
        return self._data.get("tls", {}).get("ech_enabled", False)

    @property
    def tls_ciphers(self) -> str:
        return self._data.get("tls", {}).get("ciphers", "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")

    @property
    def openssl4_dll_path(self) -> str:
        """OpenSSL 4.0 DLL 所在目录（留空则在 PATH 中搜索）"""
        raw = self._data.get("tls", {}).get("openssl4_dll_path", "") or ""
        return self._normalize_path(raw)

    @property
    def openssl4_ca_path(self) -> str:
        """CA 证书文件路径（用于 OpenSSL 4.0 证书验证，Windows 需要）"""
        raw = self._data.get("tls", {}).get("ca_path", "") or ""
        return self._normalize_path(raw)

    @property
    def ech_configs(self) -> dict:
        """
        每台上游服务器的 ECH 配置。
        返回 dict: {hostname: config_string}
          config_string 可以是：
            - base64 编码的 ECHConfigList（静态）
            - "https://dns-server/dns-query"（通过 DoH 自动查询此上游的 HTTPS 记录）
            - "hostname+https://dns-server/dns-query"（查询指定 hostname 的 HTTPS 记录）
            - "udp://dns-server" 或 "hostname+udp://dns-server"（UDP DNS 查询）
        """
        return dict(self._data.get("tls", {}).get("ech", {}) or {})

    @staticmethod
    def _normalize_path(path: str) -> str:
        """标准化路径，兼容 Windows 反斜杠和 Linux 正斜杠"""
        if not path:
            return ""
        return os.path.normpath(path)

    # --- 网络监控 ---
    @property
    def network_monitor_enabled(self) -> bool:
        return self._data.get("network_monitor", {}).get("enabled", True)

    @property
    def network_monitor_config(self) -> dict:
        return self._data.get("network_monitor", {})

    def get_raw(self) -> Dict[str, Any]:
        """获取原始配置数据"""
        return dict(self._data)

    def update_section(self, section: str, data: dict):
        """更新指定配置段并保存"""
        keys = section.split(".")
        current = self._data
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        current[keys[-1]] = data
        self._save()

    def update_upstream(self, upstream_type: str, servers: List[str]):
        """更新上游服务器列表"""
        valid_types = {"bootstrap_resolvers", "doh", "dot", "doq"}
        if upstream_type not in valid_types:
            raise ValueError(f"类型必须为: {valid_types}")
        self._data.setdefault("upstream", {})[upstream_type] = servers
        self._save()

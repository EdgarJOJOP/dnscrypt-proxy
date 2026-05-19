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
                "max_concurrent": 100,
                "connection_pool_size": 50,
                "memory_limit_mb": 256,
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
            },
        }

    def _save(self):
        """保存配置到文件"""
        with open(self._path, "w", encoding="utf-8") as f:
            yaml.dump(self._data, f, default_flow_style=False, allow_unicode=True)
        self._last_mtime = self._path.stat().st_mtime

    async def check_reload(self) -> bool:
        """检查配置文件是否变更，是则热加载"""
        if not self._path.exists():
            return False
        mtime = self._path.stat().st_mtime
        if mtime > self._last_mtime:
            async with self._lock:
                self._load()
                for cb in self._reload_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(cb):
                            await cb(self._data)
                        else:
                            cb(self._data)
                    except Exception:
                        pass
            return True
        return False

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
        return self._data.get("upstream", {}).get("bootstrap_resolvers", ["223.5.5.5"])

    @property
    def doh_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("doh", [])

    @property
    def dot_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("dot", [])

    @property
    def doq_servers(self) -> List[str]:
        return self._data.get("upstream", {}).get("doq", [])

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
        return self._data.get("performance", {}).get("connection_pool_size", 50)

    @property
    def memory_limit_mb(self) -> int:
        return self._data.get("performance", {}).get("memory_limit_mb", 256)

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

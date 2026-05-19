"""
域名过滤引擎 - 支持 AdGuard Home 规则语法
拦截匹配规则的域名 DNS 请求

支持的规则语法:
  ||domain.com^         - 拦截 domain.com 及其所有子域名
  @@||domain.com^       - 例外规则（白名单）
  domain.com            - 简单域名拦截
  |domain.com^          - 从根开始匹配
  ||domain.com^$important - 重要规则（覆盖例外）
  |http://domain/path   - URL 前缀规则（提取域名）
  /regex/               - 正则匹配域名
  0.0.0.0 domain.com    - hosts 格式
  ! / #                 - 注释行
"""

import os
import re
import time
import zlib
import asyncio
import logging
from typing import List, Tuple, Optional, Set, Callable, BinaryIO, TextIO
from io import BytesIO, StringIO
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("dns-proxy.filter")

# 规则下载最大大小（50MB）
DEFAULT_MAX_SIZE = 50 * 1024 * 1024

# 默认规则缓冲区大小（类似 Go 的 DefaultRuleBufSize）
DEFAULT_RULE_BUF_SIZE = 65536


class ParseResult:
    """规则解析结果，类似 Go 的 ParseResult"""

    __slots__ = ("title", "rules_count", "checksum", "bytes_written")

    def __init__(self, title: str = "", rules_count: int = 0,
                 checksum: int = 0, bytes_written: int = 0):
        self.title = title
        self.rules_count = rules_count
        self.checksum = checksum
        self.bytes_written = bytes_written


class AdGuardRuleParser:
    """
    AdGuard 规则解析器
    对标 Go: github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist.Parser
    """

    ERR_HTML = "looks like the rules text contains an html, not plain text"

    @staticmethod
    def _looks_like_html(text: str) -> bool:
        """检测内容是否为 HTML（检查前 100 行）"""
        lines = text.splitlines()[:100]
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if (stripped.startswith("<!") or
                stripped.startswith("<html") or
                stripped.startswith("<HTML") or
                stripped.startswith("<head") or
                stripped.startswith("<HEAD") or
                stripped.startswith("<body") or
                stripped.startswith("<BODY")):
                return True
            # 只要遇到非空规则行就停止检查
            if not stripped.startswith("!") and not stripped.startswith("#"):
                break
        return False

    @staticmethod
    def _has_binary_chars(text: str) -> Tuple[bool, int, str]:
        """
        检测二进制字符（仅检测真正的控制字符，不误伤中文等 Unicode）
        返回: (是否检测到, 行号, 描述)
        """
        for i, line in enumerate(text.splitlines(), 1):
            for j, ch in enumerate(line):
                code = ord(ch)
                # 只检测真正的控制字节：0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F
                # 不检测 > 0x7E（中文、日文等 Unicode 字符不是二进制垃圾）
                if (0x00 <= code <= 0x08) or (0x0B <= code <= 0x0C) or \
                   (0x0E <= code <= 0x1F) or code == 0x7F:
                    char_desc = f"'\\x{code:02x}'"
                    return True, i, f"line {i}: character {j}: likely binary character {char_desc}"
        return False, 0, ""

    @staticmethod
    def _extract_title(text: str) -> str:
        """从注释中提取标题 ! Title: xxx"""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("! "):
                # 检查 "! Title:"
                # Go 代码中: ! Title: 后面跟上标题
                # 也处理中文 "! 标题:"
                lower = stripped.lower()
                for prefix in ("! title:", "! 标题:"):
                    if lower.startswith(prefix):
                        title = stripped[len(prefix):].strip()
                        if title:
                            return title
        return ""

    @staticmethod
    def _clean_rule_line(line: str) -> Optional[str]:
        """
        清理单行规则文本
        返回清理后的规则行，或 None 表示跳过
        - 去除首尾空白
        - 跳过空行和注释
        - 跳过 cosmetic 规则
        """
        line = line.strip()
        if not line:
            return None
        # 注释: ! 或 #
        if line.startswith("!") or line.startswith("#"):
            return None
        # cosmetic 规则: ## #@# $$
        if "##" in line or "#@#" in line or "$$" in line:
            return None

        # etc/hosts 格式: 0.0.0.0 domain.com 或 127.0.0.1 domain.com
        # 官方定义：精确匹配域名，不匹配子域名
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0\.0\.0\.0)\s+(\S+)$',
            line
        )
        if hosts_match:
            domain = hosts_match.group(1)
            # 跳过带路径的 hosts 条目
            if "/" not in domain:
                return domain  # 裸域名 → FilterRule 会做精确匹配

        return line

    def parse(self, text: str, buf: Optional[bytearray] = None) -> ParseResult:
        """
        解析规则文本
        类似 Go: parser.Parse(w, r, buf) → ParseResult

        Args:
            text: 原始规则文本
            buf: 可选缓冲区

        Returns:
            ParseResult
        """
        # 1. HTML 检测
        if self._looks_like_html(text):
            raise ValueError(self.ERR_HTML)

        # 2. 二进制字符检测
        has_binary, line_no, desc = self._has_binary_chars(text)
        if has_binary:
            raise ValueError(desc)

        # 3. 提取标题
        title = self._extract_title(text)

        # 4. 解析并写入输出
        output = StringIO()
        rules_count = 0

        for raw_line in text.splitlines():
            cleaned = self._clean_rule_line(raw_line)
            if cleaned is None:
                continue
            output.write(cleaned)
            output.write("\n")
            rules_count += 1

        output_str = output.getvalue()

        # 5. 计算 CRC32 checksum
        checksum = zlib.crc32(output_str.encode("utf-8")) & 0xFFFFFFFF

        return ParseResult(
            title=title,
            rules_count=rules_count,
            checksum=checksum,
            bytes_written=len(output_str),
        )

    def parse_to_text(self, text: str) -> Tuple[str, ParseResult]:
        """
        解析并返回清理后的规则文本
        返回: (cleaned_text, parse_result)
        """
        result = self.parse(text)
        # 重新生成清理后的文本
        lines = []
        for raw_line in text.splitlines():
            cleaned = self._clean_rule_line(raw_line)
            if cleaned is not None:
                lines.append(cleaned)
        cleaned_text = "\n".join(lines)
        return cleaned_text, result


class FilterRule:
    """单条过滤规则（编译后的匹配规则）"""

    __slots__ = ("pattern", "is_exception", "is_important", "is_regex", "raw", "_skip")

    def __init__(self, rule_text: str):
        self.raw = rule_text
        self.is_exception = False
        self.is_important = False
        self.is_regex = False
        self.pattern = rule_text
        self._skip = False

        self._parse()

    # DNS 级别已知的 modifier 集合
    # 不在列表中的 modifier → 整条规则跳过（官方规范）
    _KNOWN_MODIFIERS = {
        # DNS-specific
        'important', 'badfilter', 'client', 'denyallow', 'dnstype',
        'dnsrewrite', 'ctag',
        # Network-level（浏览器级别，但 DNS 列表中常见，安全忽略）
        'third-party', 'script', 'image', 'stylesheet', 'object',
        'xmlhttprequest', 'subdocument', 'font', 'media', 'popup',
        'document', 'match-case', 'generichide', 'specifichide',
        'elemhide', 'extension', 'ping', 'webrtc', 'domain',
        # 常见但不影响 DNS 过滤的
        'popunder', 'empty', 'network',
    }

    @staticmethod
    def _validate_modifiers(modifiers_str: str) -> bool:
        """验证 modifier 是否已知，未知则跳过整条规则"""
        for mod in modifiers_str.split(','):
            mod = mod.strip()
            # 提取 modifier 名（去掉 =value 部分）
            if '=' in mod:
                name = mod.split('=', 1)[0].strip()
            else:
                name = mod
            # ~ 前缀表示排除
            if name.startswith('~'):
                name = name[1:]
            # 允许 s@...@...@ 格式（内容替换，DNS 级别不适用，跳过规则本身）
            if name == 's':
                return False
            if name not in FilterRule._KNOWN_MODIFIERS:
                return False
        return True

    @staticmethod
    def _pattern_to_regex(pattern: str, match_subdomains: bool = False,
                          exact_start: bool = False, exact_end: bool = False) -> Optional[re.Pattern]:
        """
        将 AdGuard 模式转换为正则表达式

        Args:
            pattern: 域名模式（不含 ||、|、@@ 等前缀）
            match_subdomains: 是否匹配子域名（|| 前缀）
            exact_start: 是否限定开头（| 前缀）
            exact_end: 是否限定结尾（后缀 |）
        Returns:
            编译后的 regex 或 None（pattern 无效时）
        """
        if not pattern:
            return None

        # 处理 * 通配符：escape 其他特殊字符，* 转成 [^.]*
        parts = []
        i = 0
        while i < len(pattern):
            ch = pattern[i]
            if ch == '*':
                # 匹配除点号外的任意字符（不跨域名段）
                parts.append('[^.]*')
            elif ch in '.^$+{}[]\\()|':
                parts.append('\\' + ch)
            else:
                parts.append(ch)
            i += 1

        regex_str = ''.join(parts)

        # 构建完整正则
        if match_subdomains:
            # ||domain.com → 匹配 domain.com 和 sub.domain.com，但不匹配 notdomain.com
            full = r'(^|\.)' + regex_str + r'$'
        elif exact_start and exact_end:
            full = r'^' + regex_str + r'$'
        elif exact_start:
            full = r'^' + regex_str
        elif exact_end:
            full = regex_str + r'$'
        else:
            full = regex_str + r'$'

        try:
            return re.compile(full, re.IGNORECASE)
        except re.error:
            return None

    def _parse(self):
        """
        解析 AdGuard 规则语法（官方规范实现）
        参见: https://adguard.com/kb/general/ad-filtering/create-own-filters/
        """
        text = self.raw.strip()

        if not text:
            self._skip = True
            return

        # 1. 例外规则标记
        while text.startswith("@@"):
            self.is_exception = True
            text = text[2:]

        # 2. 跳过 cosmetic 规则
        if "##" in text or "#@#" in text or "$$" in text:
            self._skip = True
            return

        # 3. 分离 $modifiers 并验证
        modifiers_str = None
        if "$" in text:
            parts = text.rsplit("$", 1)
            text = parts[0]
            modifiers_str = parts[1]

        if modifiers_str:
            # 未知 modifier → 跳过整条规则（官方规范）
            if not self._validate_modifiers(modifiers_str):
                self._skip = True
                return
            if modifiers_str == "important" or modifiers_str.startswith("important"):
                self.is_important = True

        if not text:
            self._skip = True
            return

        # 4. URL 前缀规则: |http(s)://domain.com/path
        if text.startswith("|http://") or text.startswith("|https://"):
            url_text = text[1:].rstrip("^")
            if "://*" in url_text:
                self._skip = True
                return
            try:
                parsed = urlparse(url_text)
                domain = parsed.hostname
                if domain:
                    self.pattern = self._pattern_to_regex(domain, match_subdomains=False)
                    if self.pattern:
                        self.is_regex = True
                        return
            except Exception:
                pass
            self._skip = True
            return

        # 5. http(s):// 开头（无 | 前缀）→ 提取域名，精确匹配
        if text.startswith("http://") or text.startswith("https://"):
            try:
                parsed = urlparse(text)
                domain = parsed.hostname
                if domain:
                    self.pattern = self._pattern_to_regex(domain, match_subdomains=False)
                    if self.pattern:
                        self.is_regex = True
                        return
            except Exception:
                pass
            self._skip = True
            return

        # 6. ||domain.com — 匹配域名及所有子域名
        if text.startswith("||"):
            domain_part = text[2:]
            if "/" in domain_part:
                domain_part = domain_part.split("/")[0]
            domain = domain_part.rstrip("^")
            # 去掉前置 *.（||*.example.com → ||example.com）
            if domain.startswith("*."):
                domain = domain[2:]
            if domain and "." in domain:
                self.pattern = self._pattern_to_regex(domain, match_subdomains=True)
                if self.pattern:
                    self.is_regex = True
                    return
            self._skip = True
            return

        # 7. | 指针语法
        has_start_pipe = text.startswith("|")
        has_end_pipe = text.endswith("|")
        has_end_caret = text.endswith("^")

        if has_start_pipe or has_end_pipe:
            if has_start_pipe and has_end_pipe:
                # |exact.domain.com| — 精确匹配
                domain = text[1:-1].rstrip("^")
                self.pattern = self._pattern_to_regex(domain, exact_start=True, exact_end=True)
            elif has_start_pipe and has_end_caret:
                # |domain.com^ — 精确匹配（^ 标记域名结束）
                domain = text[1:-1].rstrip("^")
                self.pattern = self._pattern_to_regex(domain, exact_start=True, exact_end=True)
            elif has_start_pipe:
                # |example — 匹配以 example 开头的域名
                domain = text[1:].rstrip("^")
                self.pattern = self._pattern_to_regex(domain, exact_start=True)
            else:
                # example.com| — 匹配以 example.com 结尾的域名
                domain = text[:-1].rstrip("^")
                self.pattern = self._pattern_to_regex(domain, exact_end=True)

            if self.pattern:
                self.is_regex = True
            else:
                self._skip = True
            return

        # 8. /regex/ 规则
        if text.startswith("/") and text.endswith("/"):
            regex_text = text[1:-1]
            try:
                self.pattern = re.compile(regex_text, re.IGNORECASE)
                self.is_regex = True
            except re.error:
                self._skip = True
            return

        # 9. hosts 格式: 0.0.0.0 domain / 127.0.0.1 domain / ::1 domain
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0\.0\.0\.0)\s+(\S+)$',
            text
        )
        if hosts_match:
            domain = hosts_match.group(1)
            if "/" not in domain and "." in domain:
                text = domain  # 去掉 IP 前缀，用裸域名做精确匹配
                # 继续执行下面的普通域名规则

        # 10. 普通域名规则 — 官方定义：精确匹配，不匹配子域名
        clean = text.rstrip("^")
        if clean:
            # 包含 * 通配符的普通域名
            if "*" in clean:
                self.pattern = self._pattern_to_regex(clean)
            else:
                self.pattern = self._pattern_to_regex(clean, exact_start=True, exact_end=True)
            if self.pattern:
                self.is_regex = True
            else:
                self._skip = True
        else:
            self._skip = True

    def matches(self, domain: str) -> bool:
        """检查域名是否匹配此规则"""
        try:
            return bool(self.pattern.search(domain))
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"FilterRule({'例外' if self.is_exception else '拦截'}: {self.raw})"


class DomainIndex:
    """
    域名索引 — 按域名索引规则，支持父域名链查找。

    类似 Go urlfilter 的 domain-based matching:
    匹配 sub.example.com 时，按 sub.example.com → example.com → com 顺序查找。
    """

    def __init__(self):
        # 域名 -> 规则列表（精确域名索引）
        self._by_domain: Dict[str, List[FilterRule]] = {}
        # 通配/无特定域名的规则（正则、前缀后缀等）
        self._pattern_rules: List[FilterRule] = []
        # 已索引的域名集合（类似于 Go 的快速过滤）
        self._domain_set: Set[str] = set()
        self._count = 0

    def add_rule(self, rule: FilterRule, index_domain: Optional[str]):
        """向索引添加一条规则"""
        if index_domain:
            self._by_domain.setdefault(index_domain, []).append(rule)
            self._domain_set.add(index_domain)
        else:
            self._pattern_rules.append(rule)
        self._count += 1

    def match(self, domain: str) -> Optional[Tuple[FilterRule, str]]:
        """
        匹配域名，返回 (匹配的规则, 匹配方式)。
        按父域名链从精确到宽泛查找。
        """
        # 1. 精确域名
        if domain in self._by_domain:
            for rule in self._by_domain[domain]:
                if rule.matches(domain):
                    return rule, "精确域名匹配"

        # 2. 父域名链 (sub.example.com → example.com → com)
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._by_domain:
                for rule in self._by_domain[parent]:
                    if rule.matches(domain):
                        return rule, f"父域名匹配 ({parent})"

        # 3. 通配/正则规则
        for rule in self._pattern_rules:
            if rule.matches(domain):
                return rule, "模式匹配"

        return None

    def has_domain(self, domain: str) -> bool:
        """域名是否在索引中（快速检查）"""
        if domain in self._domain_set:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in self._domain_set:
                return True
        return False

    def clear(self):
        self._by_domain.clear()
        self._pattern_rules.clear()
        self._domain_set.clear()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def domain_count(self) -> int:
        return len(self._domain_set)


class FilterEngine:
    """
    域名过滤引擎（支持定时从远程更新规则）

    架构类似 Go 的 DNSFilter:
    - 黑名单引擎 (block_index) — 拦截匹配规则的域名
    - 白名单引擎 (allow_index) — 先于黑名单检查，匹配则放行
    - 重要规则 (important_rules) — 不受白名单影响
    - 自定义 hosts 映射 — 类似 Windows hosts 文件，可自定义域名指向 IP
    """

    def __init__(self, cache_dir: Optional[str] = None):
        # 黑名单索引（Go: filteringEngine）
        self._block_index = DomainIndex()
        # 白名单索引（Go: filteringEngineAllow）
        self._allow_index = DomainIndex()
        # 重要规则（Go: 通过 rules.NetworkRule.Important 标志）
        self._important_rules: List[FilterRule] = []

        # 原始规则列表（用于统计和调试）
        self._block_rules: List[FilterRule] = []
        self._exception_rules: List[FilterRule] = []

        self._loaded_files: List[str] = []
        self._loaded_urls: List[str] = []
        self._rule_count = 0
        self._title = ""
        # 过滤结果缓存 {domain: (blocked, reason, timestamp)} — 避免重复匹配，大幅提升效率
        self._filter_cache: Dict[str, Tuple[bool, str, float]] = {}
        self._filter_cache_timeout: float = 5.0
        self._update_callback: Optional[Callable] = None
        # 校验和缓存（类似 Go 的 checksum）
        self._file_checksums: dict = {}
        self._url_checksums: dict = {}
        # 缓存目录
        self._cache_dir = cache_dir
        # 解析器
        self._parser = AdGuardRuleParser()
        # 定时更新相关
        self._update_task: Optional[asyncio.Task] = None
        self._running = False
        self._update_interval_hours = 0

        # ========== 自定义 hosts 映射 ==========
        # 格式: {domain: [(ip, rdtype), ...]}
        # 例如: {"my.dns": [("127.0.0.1", dns.rdatatype.A), ("192.168.1.1", dns.rdatatype.A)]}
        self._custom_hosts: Dict[str, List[Tuple[str, int]]] = {}
        self._custom_hosts_cache: Dict[str, Tuple[bool, str, float]] = {}
        self._custom_hosts_enabled = True

    @property
    def title(self) -> str:
        return self._title

    # 过滤结果缓存 TTL（秒）
    FILTER_CACHE_TTL = 5.0

    @staticmethod
    def _extract_index_domain(rule_text: str) -> Optional[str]:
        """
        从规则文本中提取域名索引键。

        返回域名用于索引，或 None 表示此规则无法通过域名索引查找。

        ||doubleclick.net^  -> doubleclick.net
        example.org          -> example.org
        0.0.0.0 tracker.com  -> tracker.com
        |http://domain/path  -> domain
        |domain.com^         -> domain.com
        |exact.com|          -> exact.com
        ||example.*          -> None  (通配符 TLD)
        |prefix              -> None  (前缀匹配)
        suffix|              -> None  (后缀匹配)
        /regex/              -> None  (正则)
        """
        line = rule_text.strip()
        if not line:
            return None
        if line.startswith("!") or line.startswith("#"):
            return None
        if "##" in line or "#@#" in line or "$$" in line:
            return None

        while line.startswith("@@"):
            line = line[2:]

        if "$" in line:
            line = line.rsplit("$", 1)[0]
        if not line:
            return None

        # hosts 格式
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0\.0\.0\.0)\s+(\S+)$',
            line
        )
        if hosts_match:
            domain = hosts_match.group(1)
            if "." in domain and "*" not in domain and "/" not in domain:
                return domain.lower()
            return None

        # ||domain 格式
        if line.startswith("||"):
            domain = line[2:]
            if "/" in domain:
                domain = domain.split("/")[0]
            domain = domain.rstrip("^")
            if domain.startswith("*."):
                domain = domain[2:]
            if domain and "." in domain and "*" not in domain:
                return domain.lower()
            return None

        # |http://domain/path
        if line.startswith("|http://") or line.startswith("|https://"):
            url_text = line[1:].rstrip("^")
            try:
                parsed = urlparse(url_text)
                if parsed.hostname and "." in parsed.hostname:
                    return parsed.hostname.lower()
            except Exception:
                pass
            return None

        # |domain^ 或 |domain| 精确匹配
        if line.startswith("|") and (line.endswith("^") or line.endswith("|")):
            domain = line[1:].rstrip("^|")
            return domain.lower() if domain else None

        # | 前缀 / 后缀 | → 不能索引
        if line.startswith("|") or line.endswith("|"):
            return None

        # /regex/ → 不能索引
        if line.startswith("/") and line.endswith("/"):
            return None

        # http(s)://domain
        if line.startswith("http://") or line.startswith("https://"):
            try:
                parsed = urlparse(line)
                if parsed.hostname and "." in parsed.hostname:
                    return parsed.hostname.lower()
            except Exception:
                pass
            return None

        # 普通域名
        domain = line.rstrip("^").lower()
        if domain and "." in domain and "*" not in domain:
            return domain
        return None

    def _index_rule(self, rule: FilterRule, rule_text: str):
        """将单条规则加入对应的索引"""
        if rule.is_exception:
            self._exception_rules.append(rule)
            index_domain = self._extract_index_domain(rule_text)
            self._allow_index.add_rule(rule, index_domain)
        elif rule.is_important:
            self._important_rules.append(rule)
            # 重要规则也加入黑名单索引
            index_domain = self._extract_index_domain(rule_text)
            self._block_index.add_rule(rule, index_domain)
            self._block_rules.append(rule)
        else:
            self._block_rules.append(rule)
            index_domain = self._extract_index_domain(rule_text)
            self._block_index.add_rule(rule, index_domain)

    def _compile_rules(self, cleaned_text: str, source: str = "memory"):
        """
        编译清理后的规则文本为 FilterRule 对象并建立索引
        """
        count = 0
        for line in cleaned_text.splitlines():
            line = line.strip()
            if not line:
                continue

            rule = FilterRule(line)
            if rule._skip:
                continue

            self._index_rule(rule, line)
            count += 1

        self._rule_count += count
        logger.info(
            "从 %s 索引了 %d 条规则 (总: %d, 拦截索引: %d 域名, 白名单: %d 域名)",
            source, count,
            self._rule_count,
            self._block_index.domain_count,
            self._allow_index.domain_count,
        )

    def load_rules_from_text(self, text: str, source: str = "memory"):
        """
        从文本加载规则（完整流程：解析 → 编译）
        """
        try:
            cleaned_text, parse_res = self._parser.parse_to_text(text)
            if parse_res.rules_count > 0:
                self._compile_rules(cleaned_text, source=source)
            if parse_res.title and not self._title:
                self._title = parse_res.title
            return parse_res
        except ValueError as e:
            logger.error("解析 %s 失败: %s", source, e)
            return ParseResult()

    def load_rules_from_file(self, filepath: str) -> bool:
        """从文件加载规则"""
        path = Path(filepath)
        if not path.exists():
            logger.warning("规则文件不存在: %s", filepath)
            return False

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            parse_res = self.load_rules_from_text(text, source=filepath)
            self._loaded_files.append(filepath)
            return parse_res.rules_count > 0
        except Exception as e:
            logger.error("读取规则文件 %s 失败: %s", filepath, e)
            return False

    async def _fetch_url_async(self, url: str, max_size: int = DEFAULT_MAX_SIZE,
                               timeout: int = 30) -> Optional[str]:
        """异步获取远程 URL 内容"""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": "SecureDNS-Proxy/1.0"},
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status != 200:
                        logger.error("获取 URL %s 失败: HTTP %d", url, resp.status)
                        return None
                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > max_size:
                        logger.error("URL %s 文件过大: %s bytes (限制 %d)",
                                     url, content_length, max_size)
                        return None
                    raw = await resp.read()
                    if len(raw) > max_size:
                        logger.error("URL %s 实际大小 %d 超过限制 %d",
                                     url, len(raw), max_size)
                        return None
            return raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            logger.error("获取 URL %s 超时 (%ds)", url, timeout)
            return None
        except Exception as e:
            logger.error("从 URL %s 加载规则失败: %s", url, e)
            return None

    async def load_rules_from_url_async(self, url: str) -> bool:
        """
        异步从远程 URL 加载规则（带总超时防止阻塞）
        """
        try:
            content = await asyncio.wait_for(
                self._fetch_url_async(url), timeout=35
            )
            if content is None:
                return False
        except asyncio.TimeoutError:
            logger.error("从 URL %s 加载规则超时 (35s)", url)
            return False

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.load_rules_from_text, content, url)
        self._loaded_urls.append(url)
        return True

    async def async_reload(self, files: List[str], urls: Optional[List[str]] = None):
        """异步重新加载所有规则"""
        self._block_index.clear()
        self._allow_index.clear()
        self._important_rules.clear()
        self._block_rules.clear()
        self._exception_rules.clear()
        self._loaded_files.clear()
        self._loaded_urls.clear()
        self._rule_count = 0
        self._filter_cache.clear()
        self._custom_hosts_cache.clear()

        for filepath in files:
            self.load_rules_from_file(filepath)

        if urls:
            await asyncio.gather(
                *[self.load_rules_from_url_async(url) for url in urls],
                return_exceptions=True,
            )

        logger.info("规则重载完成，共 %d 条规则 (本地: %d, 远程: %d)",
                     self._rule_count, len(files), len(urls or []))

        if self._update_callback:
            try:
                self._update_callback(self._rule_count)
            except Exception:
                pass

    def reload(self, files: List[str], urls: Optional[List[str]] = None):
        """
        重新加载所有规则（同步接口，用于测试）
        """
        self._block_index.clear()
        self._allow_index.clear()
        self._important_rules.clear()
        self._block_rules.clear()
        self._exception_rules.clear()
        self._loaded_files.clear()
        self._loaded_urls.clear()
        self._rule_count = 0
        self._filter_cache.clear()
        self._custom_hosts_cache.clear()

        for filepath in files:
            self.load_rules_from_file(filepath)

        if urls:
            for url in urls:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        logger.warning("规则 URL %s 无法同步加载（事件循环已运行）", url)
                        continue
                    import urllib.request
                    resp = urllib.request.urlopen(url, timeout=120)
                    content = resp.read().decode("utf-8", errors="replace")
                    self.load_rules_from_text(content, source=url)
                    self._loaded_urls.append(url)
                except Exception as e:
                    logger.error("从 %s 加载规则失败: %s", url, e)

        logger.info("规则重载完成，共 %d 条规则 (本地: %d, 远程: %d)",
                     self._rule_count, len(files), len(urls or []))

        if self._update_callback:
            try:
                self._update_callback(self._rule_count)
            except Exception:
                pass

    def check_domain(self, domain: str) -> Tuple[bool, str]:
        """
        检查域名是否被拦截（Go 风格的匹配流程）

        匹配顺序:
        0. 自定义 hosts 映射（最高优先级）
        1. 过滤结果缓存（避免重复匹配，大幅提升效率）
        2. 重要规则 (不受白名单影响)
        3. 白名单索引 (Go: filteringEngineAllow)
        4. 黑名单索引 (Go: filteringEngine)

        返回: (是否拦截, 原因)
        """
        domain = domain.lower().rstrip(".")
        now = time.monotonic()

        # 0. 检查自定义 hosts 映射（最高优先级）
        if self._custom_hosts_enabled and domain in self._custom_hosts:
            self._custom_hosts_cache[domain] = (True, "custom_hosts", now)
            return True, "custom_hosts"

        # 1. 检查过滤结果缓存
        cached = self._filter_cache.get(domain)
        if cached is not None:
            result, reason, ts = cached
            if now - ts < self._filter_cache_timeout:
                return result, reason
            # 缓存过期，删除并重新匹配
            del self._filter_cache[domain]

        # 2. 重要规则优先匹配
        for rule in self._important_rules:
            if rule.matches(domain):
                result = (True, f"重要规则拦截: {rule.raw}")
                self._filter_cache[domain] = (True, result[1], now)
                return result

        # 3. 白名单索引 — 类似 Go 的 filteringEngineAllow.MatchRequest()
        match = self._allow_index.match(domain)
        if match is not None:
            self._filter_cache[domain] = (False, "", now)
            return False, ""

        # 4. 黑名单索引 — 类似 Go 的 filteringEngine.MatchRequest()
        match = self._block_index.match(domain)
        if match is not None:
            rule, method = match
            reason = f"{method}: {rule.raw}"
            self._filter_cache[domain] = (True, reason, now)
            return True, reason

        # 未匹配：缓存并放行
        self._filter_cache[domain] = (False, "", now)
        return False, ""

    # ======================== 自定义 hosts 管理 ========================

    def load_custom_hosts(self, hosts_config: dict):
        """
        从配置加载自定义 hosts 映射。
        配置格式（类似 Windows hosts 文件）:
          hosts:
            enabled: true
            mappings:
              - "my.dns 127.0.0.1,192.168.1.1"
              - "router.local 192.168.1.1"
              - "ipv6test.local ::1,fe80::1"
        """
        self._custom_hosts.clear()
        self._custom_hosts_cache.clear()

        if not hosts_config:
            return

        enabled = hosts_config.get("enabled", True)
        self._custom_hosts_enabled = enabled
        if not enabled:
            return

        mappings = hosts_config.get("mappings", [])
        if not isinstance(mappings, list):
            return

        import dns.rdatatype
        for entry in mappings:
            if not isinstance(entry, str):
                continue
            entry = entry.strip()
            if not entry:
                continue
            # 格式: "domain ip1,ip2,ip3"
            parts = entry.split(None, 1)  # 用空白分割，只切第一段
            if len(parts) != 2:
                continue
            domain, ip_str = parts
            domain = domain.strip().lower()
            if not domain:
                continue
            ips = []
            for ip in ip_str.split(","):
                ip = ip.strip()
                if not ip:
                    continue
                if ":" in ip:
                    ips.append((ip, dns.rdatatype.AAAA))
                else:
                    ips.append((ip, dns.rdatatype.A))
            if ips:
                self._custom_hosts[domain] = ips

        logger.info("自定义 hosts 映射已加载: %d 条", len(self._custom_hosts))

    def get_custom_hosts_ips(self, domain: str) -> Optional[List[Tuple[str, int]]]:
        """获取自定义 hosts 中域名对应的 IP 列表"""
        domain = domain.lower().rstrip(".")
        return self._custom_hosts.get(domain)

    def clear_filter_cache(self):
        """清除过滤结果缓存 - 让所有域名重新匹配规则"""
        self._filter_cache.clear()
        self._custom_hosts_cache.clear()
        logger.debug("过滤缓存已清除 (%d 条)", len(self._filter_cache))

    # ======================== 定时更新 ========================

    def on_update(self, callback: Callable):
        """注册规则更新回调"""
        self._update_callback = callback

    async def start_auto_update(self, interval_hours: int, urls: List[str]):
        """启动定时更新任务"""
        if interval_hours <= 0 or not urls:
            logger.info("远程规则自动更新未启用 (interval=%dh, urls=%d)",
                         interval_hours, len(urls))
            return

        self._update_interval_hours = interval_hours
        self._running = True
        self._update_task = asyncio.create_task(self._update_loop(urls))
        logger.info("远程规则自动更新已启动 (间隔=%d小时, %d个源)",
                     interval_hours, len(urls))

    async def stop_auto_update(self):
        """停止定时更新"""
        self._running = False
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
            self._update_task = None

    async def _update_loop(self, urls: List[str]):
        """定时更新循环"""
        while self._running:
            try:
                await asyncio.sleep(self._update_interval_hours * 3600)
                if not self._running:
                    break

                logger.info("开始远程规则自动更新...")

                results = await asyncio.gather(
                    *[self.load_rules_from_url_async(url) for url in urls],
                    return_exceptions=True,
                )
                success_count = sum(1 for r in results if r is True)

                logger.info("远程规则更新完成: %d/%d 个源成功，当前共 %d 条规则",
                             success_count, len(urls), self._rule_count)

                if self._update_callback:
                    try:
                        self._update_callback(self._rule_count)
                    except Exception:
                        pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("远程规则更新异常（将在 %d 小时后重试）: %s",
                              self._update_interval_hours, e)

    @property
    def stats(self) -> dict:
        return {
            "total_rules": self._rule_count,
            "block_rules": len(self._block_rules),
            "exception_rules": len(self._exception_rules),
            "important_rules": len(self._important_rules),
            "block_index_domains": self._block_index.domain_count,
            "allow_index_domains": self._allow_index.domain_count,
            "filter_cache_size": len(self._filter_cache),
            "loaded_files": self._loaded_files,
            "loaded_urls": self._loaded_urls,
            "title": self._title,
            "update_interval_hours": self._update_interval_hours,
            "auto_update_running": self._running,
            "custom_hosts_count": len(self._custom_hosts),
            "custom_hosts_enabled": self._custom_hosts_enabled,
        }

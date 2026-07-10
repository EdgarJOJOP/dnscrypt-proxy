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
import socket
import concurrent.futures
import gc
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.flags

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


# =============================================================================
# ★ OPTIMIZATION Phase 1: 紧凑域名规则匹配
# ★ 对简单域名规则（||domain^、裸域名、hosts格式）使用字符串匹配而非正则
# =============================================================================

# 紧凑规则类型常量（DomainTrie 用）
_RT_NONE = 0
_RT_BLOCK_EXACT = 1       # 精确域名拦截
_RT_BLOCK_SUBDOMAIN = 2   # ||domain^ 子域名拦截
_RT_ALLOW_EXACT = 3       # 精确白名单
_RT_ALLOW_SUBDOMAIN = 4   # @@||domain^ 子域名白名单
_RT_IMPORTANT_EXACT = 5   # 重要规则精确
_RT_IMPORTANT_SUBDOMAIN = 6  # 重要规则子域名


class _DomainTrieNode:
    """域名 Trie 节点 — 紧凑存储，无正则编译"""
    __slots__ = ('children', 'rule_type', 'dnsrewrite', 'raw_short')

    def __init__(self):
        # ★ 惰性初始化：不预先分配空 dict，叶子节点永远不需要 children
        self.children = None  # type: Optional[Dict[str, '_DomainTrieNode']]
        self.rule_type: int = _RT_NONE
        self.dnsrewrite: Optional[dict] = None
        self.raw_short: str = ""


class _DomainTrie:
    """
    域名 Trie 索引 — 反向标签索引。
    
    为 95% 以上的简单域名规则提供紧凑存储和快速匹配，
    避免创建 FilterRule 对象和编译正则表达式。
    """

    __slots__ = ('_root', '_count', '_domain_count')

    def __init__(self):
        self._root = _DomainTrieNode()
        self._count = 0
        self._domain_count = 0

    def add(self, domain: str, rule_type: int, dnsrewrite: Optional[dict] = None,
            raw_short: str = "") -> bool:
        """添加域名规则到 Trie"""
        labels = domain.lower().rstrip('.').split('.')[::-1]
        node = self._root
        for label in labels:
            if node.children is None:
                node.children = {}
            if label not in node.children:
                node.children[label] = _DomainTrieNode()
            node = node.children[label]

        is_new_domain = (node.rule_type == _RT_NONE)

        # 合并规则类型：同一域名可能有多条规则，保留最高优先级
        if rule_type in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN):
            node.rule_type = rule_type
        elif rule_type in (_RT_BLOCK_EXACT, _RT_BLOCK_SUBDOMAIN):
            if node.rule_type not in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN):
                node.rule_type = rule_type
        elif rule_type in (_RT_ALLOW_EXACT, _RT_ALLOW_SUBDOMAIN):
            if node.rule_type == _RT_NONE:
                node.rule_type = rule_type

        if dnsrewrite:
            node.dnsrewrite = dnsrewrite
        if raw_short and not node.raw_short:
            node.raw_short = raw_short

        self._count += 1
        if is_new_domain:
            self._domain_count += 1
        return is_new_domain

    def match(self, domain: str) -> Optional[Tuple[Optional['_MatchInfo'], str]]:
        """
        匹配域名，返回 (_MatchInfo, 匹配方式)。
        按精确域名 → 父域名链匹配。
        """
        labels = domain.lower().rstrip('.').split('.')[::-1]
        if not labels or not labels[0]:
            return None

        node = self._root
        matched = None

        for i, label in enumerate(labels):
            if node.children is not None and label in node.children:
                node = node.children[label]
                if node.rule_type != _RT_NONE:
                    if i == len(labels) - 1:
                        # 精确到完整域名
                        matched = (node, i + 1)
                    elif node.rule_type in (_RT_BLOCK_SUBDOMAIN, _RT_ALLOW_SUBDOMAIN,
                                            _RT_IMPORTANT_SUBDOMAIN):
                        matched = (node, i + 1)
            else:
                break

        if matched is not None:
            matched_node, depth = matched
            matched_domain = '.'.join(labels[:depth][::-1])
            return (_MatchInfo(matched_node), f"域名匹配 ({matched_domain})")

        return None

    def has_domain(self, domain: str) -> bool:
        """域名是否在索引中（快速检查）"""
        labels = domain.lower().rstrip('.').split('.')[::-1]
        node = self._root
        for label in labels:
            if node.children is not None and label in node.children:
                node = node.children[label]
                if node.rule_type != _RT_NONE:
                    return True
            else:
                return False
        return node.rule_type != _RT_NONE

    def clear(self):
        self._root = _DomainTrieNode()
        self._count = 0
        self._domain_count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def domain_count(self) -> int:
        return self._domain_count


class _MatchInfo:
    """
    匹配结果信息 — 轻量替代 FilterRule。
    由 DomainTrie.match() 返回，兼容 FilterRule 的接口子集。
    """
    __slots__ = ('_node',)

    def __init__(self, node: _DomainTrieNode):
        self._node = node

    @property
    def is_important(self) -> bool:
        return self._node.rule_type in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN)

    @property
    def is_exception(self) -> bool:
        return self._node.rule_type in (_RT_ALLOW_EXACT, _RT_ALLOW_SUBDOMAIN)

    @property
    def dnsrewrite(self) -> Optional[dict]:
        return self._node.dnsrewrite

    @property
    def raw(self) -> str:
        if self._node.raw_short:
            return self._node.raw_short
        rt = self._node.rule_type
        if rt == _RT_BLOCK_EXACT:
            return "compact:block"
        elif rt == _RT_BLOCK_SUBDOMAIN:
            return "compact:block+sub"
        elif rt == _RT_ALLOW_EXACT:
            return "compact:allow"
        elif rt == _RT_ALLOW_SUBDOMAIN:
            return "compact:allow+sub"
        elif rt == _RT_IMPORTANT_EXACT:
            return "compact:important"
        elif rt == _RT_IMPORTANT_SUBDOMAIN:
            return "compact:important+sub"
        return "compact:unknown"


class FilterRule:
    """单条过滤规则（编译后的匹配规则）"""

    __slots__ = ("pattern", "is_exception", "is_important", "is_regex", "raw", "_skip",
                 "is_badfilter", "dnsrewrite",
                 # ★ Phase 1: 紧凑匹配字段
                 "_simple_match", "_simple_domain", "_match_subdomains")

    def __init__(self, rule_text: str):
        self.raw = rule_text
        self.is_exception = False
        self.is_important = False
        self.is_regex = False
        self.pattern = rule_text
        self._skip = False
        self.is_badfilter = False
        self.dnsrewrite = None
        # ★ Phase 1: 紧凑匹配初始化
        self._simple_match = False
        self._simple_domain = ""
        self._match_subdomains = False

        self._parse()

    # AdGuard 官方已知的全部 modifier 集合
    # 参见: https://adguard.com/kb/general/ad-filtering/create-own-filters/
    # 不在列表中的 modifier → 整条规则跳过（官方规范）
    _KNOWN_MODIFIERS = {
        # DNS-specific（完全支持）
        'important', 'badfilter', 'client', 'denyallow', 'dnstype',
        'dnsrewrite', 'ctag',
        # Content-type（浏览器级别，DNS 列表中常见，安全忽略）
        'third-party', 'strict-third-party', 'strict-first-party',
        'script', 'image', 'stylesheet', 'object',
        'xmlhttprequest', 'subdocument', 'font', 'media', 'popup',
        'document', 'websocket', 'other', 'all',
        'ping', 'webrtc', 'popup', 'frame', 'xhr',
        'inline-font', 'inline-script',
        # 条件修饰符（需要请求上下文，DNS 无法评估）
        'domain', 'match-case', 'method', 'to', 'header', 'app',
        # URL/内容修改
        'redirect', 'redirect-rule', 'replace', 'removeparam',
        'queryprune', 'removeheader', 'csp', 'permissions',
        'referrerpolicy', 'urltransform', 'xmlprune', 'empty',
        # 例外相关
        'elemhide', 'generichide', 'specifichide', 'jsinject',
        'urlblock', 'content', 'extension', 'genericblock',
        # 杂项
        'popunder', 'network', 'hls', 'jsonprune', 'cookie',
        # 其他
        'noop', 'reason', 'stealth', 'mp4',
    }

    # 例外规则上 DNS 级别无法评估的修饰符集合
    # 这些修饰符限制了例外规则的适用范围（如仅限特定页面/请求类型），
    # 但 DNS 代理无法区分请求来源和类型，所以带这些修饰符的例外规则应跳过。
    _EXCEPTION_RESTRICTIVE_MODIFIERS = frozenset({
        # 条件修饰符（需要页面域名/请求来源上下文）
        'domain', 'third-party', 'strict-third-party', 'strict-first-party',
        'denyallow', 'app', 'method', 'to', 'header', 'client', 'ctag', 'dnstype',
        # Content-type（需要请求类型信息）
        'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
        'subdocument', 'font', 'media', 'popup', 'document',
        'websocket', 'other', 'all', 'ping', 'webrtc', 'popup',
        'frame', 'xhr', 'inline-font', 'inline-script',
        # match-case（DNS 大小写不敏感）
        'match-case',
        # URL/内容修改（DNS 级别无法修改请求/响应）
        'redirect', 'redirect-rule', 'replace', 'removeparam',
        'queryprune', 'removeheader', 'csp', 'permissions',
        'referrerpolicy', 'urltransform', 'xmlprune', 'empty',
        # 伪装/例外相关（DNS 级别无意义）
        'elemhide', 'generichide', 'specifichide', 'jsinject',
        'urlblock', 'content', 'extension', 'genericblock',
        # 杂项限制修饰符
        'popunder', 'network', 'hls', 'jsonprune', 'cookie', 'stealth',
    })

    # 拦截规则上 DNS 级别无法评估的范围限制修饰符集合
    # 这些修饰符将拦截规则的适用范围限制在特定页面/应用/请求上下文中，
    # 如 $domain=xxx（仅特定页面）、$app=xxx（仅特定应用）。
    # DNS 代理无法评估这些条件，若不跳过会导致全局拦截 → 误拦合法域名。
    # 注意：content-type 修饰符（$script、$image 等）不在其中——
    # 对广告域名进行全类型拦截是可接受的。
    #
    # 此外还包括 HTTP 级别操作修饰符（如 $cookie、$redirect 等），
    # 这些修饰符表示规则的意图是修改 HTTP 请求/响应，而非 DNS 拦截。
    # DNS 代理无法执行这些操作（如修改 Cookie、重定向到本地资源），
    # 若在 DNS 级别应用会导致整个域名被误拦截。
    _BLOCK_RESTRICTIVE_MODIFIERS = frozenset({
        # 范围限制修饰符（需要请求上下文，DNS 无法评估）
        'domain',    # 限制到特定来源页面
        'app',       # 限制到特定应用
        'method',    # 限制到特定 HTTP 方法
        'to',        # 限制到特定请求目标
        'header',    # 限制到特定 HTTP 头
        'client',    # 限制到特定 DHCP 客户端
        'ctag',      # 限制到特定客户端标签
        # ========== HTTP 级别操作修饰符 ==========
        # 以下修饰符表示规则意图是修改 HTTP 请求/响应而非 DNS 拦截。
        # DNS 代理无法执行这些操作，跳过以避免误拦截整个域名。
        'cookie',          # 修改/移除 Cookie（HTTP 响应头/请求头）
        'removeparam',     # 移除 URL 查询参数（HTTP 请求）
        'queryprune',      # $removeparam 的别名
        'removeheader',    # 移除 HTTP 请求/响应头
        'redirect',        # 重定向到本地资源（HTTP 响应）
        'redirect-rule',   # 条件重定向（HTTP 响应）
        'replace',         # 替换响应内容（HTTP 响应）
        'csp',             # 修改 Content-Security-Policy（HTTP 响应头）
        'permissions',     # 修改 Permissions-Policy（HTTP 响应头）
        'referrerpolicy',  # 修改 Referrer-Policy（HTTP 响应头）
        'urltransform',    # 修改请求 URL（HTTP 请求）
        'xmlprune',        # 修剪 XML 响应内容（HTTP 响应）
        'empty',           # 返回空响应（HTTP 响应，已弃用）
        'hls',             # 修改 HLS 流（HTTP 响应）
        'jsonprune',       # 修剪 JSON 响应内容（HTTP 响应）
        'network',         # 防火墙规则（IP/端口级别，非 DNS）
        'mp4',             # 替换为视频占位符（HTTP 响应，已弃用）
    })

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
            elif ch == '^':
                # 分隔符：匹配非字母数字_-.% 的字符，或字符串结尾
                parts.append('(?:[^a-zA-Z0-9_\\-.%]|\\Z)')
            elif ch in '.$+{}[]\\()|':
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

    def _set_simple_match(self, clean_domain: str, match_subdomains: bool):
        """
        ★ Phase 1: 设置为紧凑匹配模式（不编译正则）。
        clean_domain: 清理后的域名（小写，无 ||^ 等前缀）
        match_subdomains: 是否匹配子域名 ||domain^
        """
        self._simple_match = True
        self._simple_domain = clean_domain.lower().rstrip('.')
        self._match_subdomains = match_subdomains
        self.pattern = None  # 不编译正则
        self.is_regex = False

    def _parse(self):
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
            # 检测 important 修饰符（可能在 modifier 列表任意位置）
            for mod in modifiers_str.split(','):
                if mod.strip() == 'important':
                    self.is_important = True
                    break

            # 检测 badfilter 修饰符 — $badfilter 规则禁用其他具有相同 pattern 的规则
            for mod in modifiers_str.split(','):
                if mod.strip() == 'badfilter':
                    self.is_badfilter = True
                    break

            # 检测 dnsrewrite 修饰符
            for mod in modifiers_str.split(','):
                if mod.strip().startswith('dnsrewrite'):
                    self._parse_dnsrewrite(mod.strip())
                    break

            # 例外规则带有限制性修饰符（如 $domain=xxx、$third-party、$script 等）
            # 则跳过该规则。DNS 代理无法评估这些修饰符的条件，
            # 如果无条件应用，会导致本应有限制的例外被无限放行。
            if self.is_exception:
                for mod in modifiers_str.split(','):
                    mod = mod.strip()
                    if '=' in mod:
                        name = mod.split('=', 1)[0].strip()
                    else:
                        name = mod
                    if name.startswith('~'):
                        name = name[1:]
                    # 除了 $important 之外的其他修饰符都是限制性的
                    if name in self._EXCEPTION_RESTRICTIVE_MODIFIERS:
                        self._skip = True
                        return

            # 拦截规则带范围限制修饰符（如 $domain=xxx、$app=xxx 等）
            # 则跳过该规则。这些修饰符将拦截范围限制在特定页面/应用中，
            # DNS 无法评估这些条件，若不跳过会导致全局拦截 → 误拦合法域名。
            if not self.is_exception and not self.is_important:
                for mod in modifiers_str.split(','):
                    mod = mod.strip()
                    if '=' in mod:
                        name = mod.split('=', 1)[0].strip()
                    else:
                        name = mod
                    if name.startswith('~'):
                        name = name[1:]
                    # 跳过非重要拦截规则中携带的限制性修饰符
                    if name in self._BLOCK_RESTRICTIVE_MODIFIERS:
                        logger.debug("跳过 DNS 不适用的规则: %s (修饰符: $%s)",
                                      self.raw[:80], name)
                        self._skip = True
                        return

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
                    # 含路径的 URL 规则（如 |https://github.com/path^）需要 HTTP 级别匹配，
                    # DNS 级别无法评估路径条件，跳过以避免误拦整个域名。
                    if parsed.path and parsed.path not in ("/", ""):
                        self._skip = True
                        return
                    # ★ Phase 1: 简单域名 → 紧凑匹配（无需正则）
                    if '*' not in domain and domain.count('.') >= 1:
                        self._set_simple_match(domain, False)
                        return
                    self.pattern = self._pattern_to_regex(domain, match_subdomains=False)
                    if self.pattern:
                        self.is_regex = True
                        return
            except Exception as e:
                logger.debug("过滤器规则解析异常（域名）: %s", e)
                pass
            self._skip = True
            return

        # 5. http(s):// 开头（无 | 前缀）→ 提取域名，精确匹配
        if text.startswith("http://") or text.startswith("https://"):
            try:
                parsed = urlparse(text)
                domain = parsed.hostname
                if domain:
                    # 含路径的 URL 规则同上，DNS 级别无法评估路径
                    if parsed.path and parsed.path not in ("/", ""):
                        self._skip = True
                        return
                    # ★ Phase 1: 简单域名 → 紧凑匹配（无需正则）
                    if '*' not in domain and domain.count('.') >= 1:
                        self._set_simple_match(domain, False)
                        return
                    self.pattern = self._pattern_to_regex(domain, match_subdomains=False)
                    if self.pattern:
                        self.is_regex = True
                        return
            except Exception as e:
                logger.debug("过滤器规则解析异常（URL）: %s", e)
                pass
            self._skip = True
            return

        # 6. ||domain.com — 匹配域名及所有子域名
        if text.startswith("||"):
            domain_part = text[2:]
            # 含路径的 || 规则（如 ||api.bilibili.com/path^）需要 HTTP 路径匹配，
            # DNS 级别无法评估路径条件，跳过以避免误拦整个域名。
            if "/" in domain_part:
                self._skip = True
                return
            domain = domain_part.rstrip("^")
            # 去掉前置 *.（||*.example.com → ||example.com）
            if domain.startswith("*."):
                domain = domain[2:]
            if domain and "." in domain:
                # ★ Phase 1: 不含通符且含点号 → 紧凑匹配
                if '*' not in domain:
                    self._set_simple_match(domain, True)
                    return
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
                # ★ Phase 1: 不含通配符且含点号 → 紧凑匹配
                if '*' not in domain and '.' in domain:
                    self._set_simple_match(domain, False)
                    return
                self.pattern = self._pattern_to_regex(domain, exact_start=True, exact_end=True)
            elif has_start_pipe and has_end_caret:
                # |domain.com^ — 精确匹配（^ 标记域名结束）
                domain = text[1:-1].rstrip("^")
                # ★ Phase 1: 不含通配符且含点号 → 紧凑匹配
                if '*' not in domain and '.' in domain:
                    self._set_simple_match(domain, False)
                    return
                self.pattern = self._pattern_to_regex(domain, exact_start=True, exact_end=True)
            elif has_start_pipe:
                # |example — 匹配以 example 开头的域名（前缀匹配，不能走紧凑路径）
                domain = text[1:].rstrip("^")
                self.pattern = self._pattern_to_regex(domain, exact_start=True)
            else:
                # example.com| — 匹配以 example.com 结尾的域名（后缀匹配，不能走紧凑路径）
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
            # 纯通配符 * 会匹配所有域名，DNS 级别不应使用
            if clean == '*':
                self._skip = True
                return
            # ★ Phase 1: 不含通配符且含点号 → 紧凑匹配（无需正则）
            if "*" not in clean and "." in clean:
                self._set_simple_match(clean, False)
                return
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

    def _parse_dnsrewrite(self, mod: str):
        """
        解析 $dnsrewrite 修饰符的值

        AdGuard 支持以下格式:
          $dnsrewrite              - 返回 NOERROR（空应答）
          $dnsrewrite=1.2.3.4      - 返回 A 记录
          $dnsrewrite=::1          - 返回 AAAA 记录
          $dnsrewrite=host:name    - 返回 CNAME
          $dnsrewrite=REFUSED      - 自定义 DNS 返回码
          $dnsrewrite=NOERROR;A;1.2.3.4  - 完整自定义应答
        """
        if '=' not in mod:
            # 纯 $dnsrewrite（无值）→ NOERROR 空应答
            self.dnsrewrite = {'action': 'noerror'}
            return

        value = mod.split('=', 1)[1].strip()
        if not value:
            self.dnsrewrite = {'action': 'noerror'}
            return

        # 结构化语法: RC;QT;VAL
        if ';' in value:
            parts = value.split(';', 2)
            rc = parts[0].strip().upper() if parts[0] else 'NOERROR'
            qt = parts[1].strip().upper() if len(parts) > 1 and parts[1] else ''
            val = parts[2].strip() if len(parts) > 2 and parts[2] else ''
            self.dnsrewrite = {
                'action': 'dnsrewrite',
                'rcode': rc,
                'qtype': qt,
                'value': val,
            }
            return

        # host: 前缀 → CNAME 重写
        if value.startswith('host:'):
            self.dnsrewrite = {
                'action': 'dnsrewrite',
                'rcode': 'NOERROR',
                'qtype': 'CNAME',
                'value': value[5:],
            }
            return

        # 简单 IP 地址
        if ':' in value:
            # IPv6
            self.dnsrewrite = {
                'action': 'dnsrewrite',
                'rcode': 'NOERROR',
                'qtype': 'AAAA',
                'value': value,
            }
            return

        # 检查是否为 DNS 返回码（REFUSED, SERVFAIL 等大写单词）
        if value.upper() in ('NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN',
                              'NOTIMP', 'REFUSED'):
            self.dnsrewrite = {
                'action': 'dnsrewrite',
                'rcode': value.upper(),
                'qtype': '',
                'value': '',
            }
            return

        # 默认视为 IPv4 地址
        import re as _re
        ipv4_match = _re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', value)
        if ipv4_match:
            self.dnsrewrite = {
                'action': 'dnsrewrite',
                'rcode': 'NOERROR',
                'qtype': 'A',
                'value': value,
            }
            return

        # 未知格式，记录日志并按 noerror 处理
        logger.debug("无法识别的 $dnsrewrite 值: %s (规则: %s)", value, self.raw[:80])
        self.dnsrewrite = {'action': 'noerror'}

    def matches(self, domain: str) -> bool:
        """检查域名是否匹配此规则"""
        # ★ Phase 1: 紧凑匹配路径（无需正则）
        if self._simple_match:
            if self._match_subdomains:
                # ||domain.com 匹配 domain.com 和 sub.domain.com
                return domain == self._simple_domain or domain.endswith('.' + self._simple_domain)
            else:
                # 精确匹配
                return domain == self._simple_domain
        # 正则匹配路径
        try:
            return bool(self.pattern.search(domain))
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"FilterRule({'例外' if self.is_exception else '拦截'}: {self.raw})"


class DomainIndex:
    """
    域名索引 — 支持紧凑域名 Trie 和传统正则规则。
    
    ★ Phase 1+2: 简单域名规则存入 _trie（紧凑），复杂规则存入 _pattern_rules（正则）。
    ★ Phase 2: 单规则域名直接用对象而非 List 包装。
    """

    __slots__ = ('_trie', '_pattern_rules', '_count')

    def __init__(self):
        # ★ Phase 1: 紧凑 Trie 替代 _by_domain Dict
        self._trie = _DomainTrie()
        # 复杂正则/通配规则（无法用紧凑匹配的）
        self._pattern_rules: List[FilterRule] = []
        self._count = 0

    def add_rule(self, rule: FilterRule, index_domain: Optional[str]):
        """
        向索引添加一条规则。
        
        ★ Phase 1: 简单规则 → Trie；复杂规则 → _pattern_rules
        """
        if index_domain and rule._simple_match:
            # 紧凑规则 → 存入 Trie
            if rule.is_exception:
                rt = _RT_ALLOW_SUBDOMAIN if rule._match_subdomains else _RT_ALLOW_EXACT
            elif rule.is_important:
                rt = _RT_IMPORTANT_SUBDOMAIN if rule._match_subdomains else _RT_IMPORTANT_EXACT
            else:
                rt = _RT_BLOCK_SUBDOMAIN if rule._match_subdomains else _RT_BLOCK_EXACT
            self._trie.add(index_domain, rt, rule.dnsrewrite, rule.raw)
        elif index_domain:
            # 有域名但不能紧凑匹配（如含通配符）→ 需保留 FilterRule
            self._pattern_rules.append(rule)
        else:
            self._pattern_rules.append(rule)
        self._count += 1

    def match(self, domain: str) -> Optional[Tuple[object, str]]:
        """
        匹配域名，返回 (匹配对象, 匹配方式)。
        
        ★ Phase 1: 先查 Trie（紧凑匹配），再查 _pattern_rules（正则）
        """
        domain_lower = domain.lower().rstrip('.')

        # 1. Trie 紧凑匹配（覆盖 95% 以上规则）
        trie_result = self._trie.match(domain_lower)
        if trie_result is not None:
            return trie_result

        # 2. _pattern_rules 正则匹配（复杂规则）
        for rule in self._pattern_rules:
            try:
                if rule.matches(domain_lower):
                    return rule, "模式匹配"
            except Exception:
                continue

        return None

    def has_domain(self, domain: str) -> bool:
        """域名是否在索引中（快速检查）"""
        # 检查 Trie
        if self._trie.has_domain(domain.lower().rstrip('.')):
            return True
        # 检查 _pattern_rules
        for rule in self._pattern_rules:
            if rule._simple_domain and domain.lower().rstrip('.') == rule._simple_domain:
                return True
            if rule._match_subdomains and domain.lower().rstrip('.').endswith('.' + rule._simple_domain):
                return True
        return False

    def clear(self):
        self._trie.clear()
        self._pattern_rules.clear()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def domain_count(self) -> int:
        """返回 Trie 中唯一域名数 + pattern 规则数"""
        return self._trie.domain_count + len(self._pattern_rules)


class _EncryptedDNSResolver:
    """
    aiohttp 自定义 DNS 解析器 — 使用程序中的加密上游（DoH/DoT/DoQ）解析域名。
    实现 aiohttp 的 resolver 接口，用于过滤规则下载时的安全域名解析。
    """

    def __init__(self, resolver_manager):
        self._resolver_manager = resolver_manager

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        """
        aiohttp resolver 接口。
        通过加密上游并行查询 A + AAAA 记录，返回 IP 列表。
        aiohttp 自动使用原始 hostname 做 SNI 和证书验证。
        """
        if not host or not self._resolver_manager:
            return []

        # 根据 family 决定查询哪些记录类型
        # family=0(AF_UNSPEC): 同时查 A + AAAA
        # family=socket.AF_INET:  只查 A
        # family=socket.AF_INET6: 只查 AAAA
        if family == socket.AF_INET6:
            qtypes = [dns.rdatatype.AAAA]
        elif family == socket.AF_INET:
            qtypes = [dns.rdatatype.A]
        else:
            qtypes = [dns.rdatatype.A, dns.rdatatype.AAAA]

        async def _query_one(qtype):
            """查询单个记录类型，返回 IP 列表"""
            try:
                qname = dns.name.from_text(host)
                msg = dns.message.make_query(qname, qtype, dns.rdataclass.IN)
                wire = msg.to_wire()

                resp_wire = await self._resolver_manager.resolve(wire)
                if resp_wire is None:
                    return []

                resp = dns.message.from_wire(resp_wire)
                if resp.rcode() != dns.rcode.NOERROR:
                    return []

                ips = []
                for rrset in resp.answer:
                    if rrset.rdtype != qtype:
                        continue
                    for rd in rrset:
                        ips.append(str(rd.address))
                return ips
            except Exception:
                return []

        # 并行查询（A 和 AAAA 可同时发）
        results_lists = await asyncio.gather(
            *[_query_one(qt) for qt in qtypes],
            return_exceptions=True,
        )

        # 合并结果，去重
        seen = set()
        results = []
        for ips in results_lists:
            if not isinstance(ips, list):
                continue
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    family_actual = socket.AF_INET6 if ":" in ip else socket.AF_INET
                    results.append({
                        "hostname": host,
                        "host": ip,
                        "port": port,
                        "family": family_actual,
                        "proto": socket.IPPROTO_TCP,
                        "flags": socket.AI_NUMERICHOST,
                    })
        return results

    async def close(self):
        pass


class FilterEngine:
    """
    域名过滤引擎（支持定时从远程更新规则）

    架构类似 Go 的 DNSFilter:
    - 黑名单引擎 (block_index) — 拦截匹配规则的域名
    - 白名单引擎 (allow_index) — 先于黑名单检查，匹配则放行
    - 重要规则 (important_rules) — 不受白名单影响
    - 自定义 hosts 映射 — 类似 Windows hosts 文件，可自定义域名指向 IP
    """

    def __init__(self, cache_dir: Optional[str] = None,
                 cache_ttl_blocked: int = 300,
                 cache_ttl_allowed: int = 60,
                 cache_maxsize: int = 100000,
                 resolver_manager=None):
        """
        Args:
            cache_dir: 缓存目录（未使用，保留兼容）
            cache_ttl_blocked: 已拦截域名的过滤缓存 TTL（秒），默认 300
            cache_ttl_allowed: 放行域名的过滤缓存 TTL（秒），默认 60
            cache_maxsize: 过滤缓存最大条目数，默认 100000
        """
        # 黑名单索引（Go: filteringEngine）
        self._resolver_manager = resolver_manager
        # 黑名单索引（Go: filteringEngine）
        self._block_index = DomainIndex()
        # 白名单索引（Go: filteringEngineAllow）
        self._allow_index = DomainIndex()
        # 重要规则不再单独保存列表，直接查索引即可

        # 冗余规则列表已移除：_block_rules / _exception_rules / _important_rules
        # 改为实时从索引计算 stats（见 stats 属性）

        self._loaded_files: List[str] = []
        self._loaded_urls: List[str] = []
        self._rule_count = 0
        self._title = ""
        # 统一过滤结果缓存（合并原 _filter_cache + _custom_hosts_cache）
        # 格式: {domain: (blocked, reason, timestamp, priority)}
        # priority=True 的条目（自定义 hosts）永不淘汰
        self._filter_cache: Dict[str, Tuple[bool, str, float, bool]] = {}
        self._cache_ttl_blocked: int = cache_ttl_blocked
        self._cache_ttl_allowed: int = cache_ttl_allowed
        self._cache_trim_pending: bool = False  # call_soon 防重复
        self._filter_cache_maxsize: int = cache_maxsize
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
        self._update_files: List[str] = []
        self._update_urls: List[str] = []
        self._hourly_traffic = [0]*24
        self._traffic_slot = -1
        self._traffic_lock = asyncio.Lock()
        self._restart_cb = None

        # ========== 自定义 hosts 映射（白名单） ==========
        # 格式: {domain: [(ip, rdtype), ...]}
        # 例如: {"my.dns": [("127.0.0.1", dns.rdatatype.A), ("192.168.1.1", dns.rdatatype.A)]}
        self._custom_hosts: Dict[str, List[Tuple[str, int]]] = {}
        self._custom_hosts_bypass: Set[str] = set()  # 纯域名白名单：无自定义IP，仅绕过过滤规则
        self._custom_hosts_enabled = True
        # 内存压力下暂停过滤缓存写入（由优化器控制）
        self._cache_suspended = False
        # 规则重载进行中标志：重载期间不缓存未拦截的中间结果，防止窗口期漏放
        self._loading = False
        # 纯域名快速查找集合（无通配符/正则的规则）
        self._plain_domains: Set[str] = set()
        # $badfilter 禁用 pattern 集合
        self._badfilter_patterns: Set[str] = set()
        # $dnsrewrite 匹配结果缓存
        self._last_dnsrewrite: Optional[dict] = None
        # ========== Atomic reload: pending state ==========
        # Rule reload writes new rules to pending indices while active indices
        # continue answering DNS queries. Atomically swap on success.
        self._pending_block_index: Optional[DomainIndex] = None
        self._pending_allow_index: Optional[DomainIndex] = None
        self._pending_plain_domains: Optional[Set[str]] = None
        self._pending_rule_count: int = 0
        self._pending_loaded_files: List[str] = []
        self._pending_loaded_urls: List[str] = []

    @property
    def title(self) -> str:
        return self._title

    # 过滤结果缓存 TTL（秒）
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
            # 含路径的 ||domain/path 规则在 _parse 中跳过，这里也不应索引
            if "/" in domain:
                return None
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
                # 含路径的 URL 规则在 _parse 中跳过，这里也不应索引
                if parsed.path and parsed.path not in ("/", ""):
                    return None
                if parsed.hostname and "." in parsed.hostname:
                    return parsed.hostname.lower()
            except Exception as e:
                logger.debug("过滤器域名提取异常（URL）: %s", e)
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
                # 含路径的 URL 规则在 _parse 中跳过，这里也不应索引
                if parsed.path and parsed.path not in ("/", ""):
                    return None
                if parsed.hostname and "." in parsed.hostname:
                    return parsed.hostname.lower()
            except Exception as e:
                logger.debug("过滤器域名提取异常（HTTP）: %s", e)
                pass
            return None

        # 普通域名
        domain = line.rstrip("^").lower()
        if domain and "." in domain and "*" not in domain:
            return domain
        return None

    def _index_rule(self, rule: FilterRule, rule_text: str):
        """将单条规则加入对应的索引（不再维护冗余列表）"""
        # 原子重载期间使用 pending 索引，旧索引保持活跃继续应答 DNS 查询
        if self._pending_block_index is not None:
            block_idx = self._pending_block_index
            allow_idx = self._pending_allow_index
            plain_domains = self._pending_plain_domains
        else:
            block_idx = self._block_index
            allow_idx = self._allow_index
            plain_domains = self._plain_domains

        if rule.is_exception:
            index_domain = self._extract_index_domain(rule_text)
            allow_idx.add_rule(rule, index_domain)
        elif rule.is_important:
            index_domain = self._extract_index_domain(rule_text)
            block_idx.add_rule(rule, index_domain)
        else:
            index_domain = self._extract_index_domain(rule_text)
            block_idx.add_rule(rule, index_domain)

        # ★ Phase 3: 非重要的紧凑规则可以释放 raw（节省内存）
        #     紧凑规则匹配不需要 raw，仅保留用于日志的短版本
        if not rule.is_important and not rule.is_exception and rule._simple_match:
            if len(rule.raw) > 40:
                rule.raw = rule.raw[:40] + "…"

        # 为纯域名拦截规则（无通配符/正则）添加快速 set-lookup
        # 例外规则不加入 _plain_domains：该检查在白名单之后执行，
        # 已由 allowlist 放行的域名不会再被这里拦截；
        # _plain_domains 仅作为拦截快速路径，白名单不需要在此记录。
        if not rule.is_exception and not rule.is_regex and not rule._skip:
            domain = rule_text.strip().lower().rstrip('^')
            # 去除 || 和 *. 前缀，提取实际域名用于快速查找
            if domain.startswith('||'):
                domain = domain[2:]
            if domain.startswith('*.'):
                domain = domain[2:]
            # 仅当规则是普通域名（不含 * ? 等特殊字符）
            if domain and '.' in domain and '*' not in domain and '/' not in domain:
                plain_domains.add(domain)

    @staticmethod
    def _extract_badfilter_target(rule_text: str) -> Optional[str]:
        if '$' not in rule_text:
            return None
        pattern = rule_text.rsplit('$', 1)[0]
        return pattern

    def _is_rule_badfiltered(self, rule_text: str) -> bool:
        if not self._badfilter_patterns:
            return False
        pattern = rule_text.split('$')[0] if '$' in rule_text else rule_text
        return pattern in self._badfilter_patterns

    def _compile_rules(self, cleaned_text: str, source: str = "memory"):
        """
        编译清理后的规则文本为 FilterRule 对象并建立索引

        两阶段加载：先收集 $badfilter 目标，再索引剩余规则。
        """
        count = 0
        skip_count = 0

        # 第一阶段：收集 $badfilter 目标 pattern
        for line in cleaned_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if '$' not in line:
                continue
            rule = FilterRule(line)
            if rule.is_badfilter:
                target = self._extract_badfilter_target(line)
                if target:
                    self._badfilter_patterns.add(target)

        # 第二阶段：索引剩余规则，过滤被禁用的
        for line in cleaned_text.splitlines():
            line = line.strip()
            if not line:
                continue

            rule = FilterRule(line)
            if rule._skip:
                continue

            if rule.is_badfilter:
                skip_count += 1
                continue

            if self._is_rule_badfiltered(line):
                skip_count += 1
                continue

            self._index_rule(rule, line)
            count += 1

        # 原子重载期间使用 pending 计数
        if self._pending_block_index is not None:
            self._pending_rule_count += count
            total = self._pending_rule_count
            block_domains = self._pending_block_index.domain_count
            allow_domains = self._pending_allow_index.domain_count
        else:
            self._rule_count += count
            total = self._rule_count
            block_domains = self._block_index.domain_count
            allow_domains = self._allow_index.domain_count

        if skip_count:
            logger.info(
                "从 %s 索引了 %d 条规则 (%d 条被 badfilter 跳过), 总: %d, "
                "拦截索引: %d 域名, 白名单: %d 域名",
                source, count, skip_count,
                total, block_domains, allow_domains,
            )
        else:
            logger.info(
                "从 %s 索引了 %d 条规则 (总: %d, 拦截索引: %d 域名, 白名单: %d 域名)",
                source, count,
                total, block_domains, allow_domains,
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
        """从文件加载规则（带 mtime+size checksum 缓存）"""
        path = Path(filepath)
        if not path.exists():
            logger.warning("规则文件不存在: %s", filepath)
            return False

        # 检查 checksum 缓存：mtime + size 未变则跳过重解析
        try:
            stat = path.stat()
            file_key = (stat.st_mtime, stat.st_size)
            cached = self._file_checksums.get(filepath)
            if cached == file_key:
                logger.debug("Checksum 命中，跳过未变更文件: %s", filepath)
                return True
        except OSError:
            pass

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            parse_res = self.load_rules_from_text(text, source=filepath)
            if self._pending_block_index is not None:
                self._pending_loaded_files.append(filepath)
            else:
                self._loaded_files.append(filepath)
            # 更新 checksum 缓存
            try:
                stat = path.stat()
                self._file_checksums[filepath] = (stat.st_mtime, stat.st_size)
            except OSError:
                pass
            logger.debug("Checksum 缓存已更新: %s (rules=%d)", filepath, parse_res.rules_count)
            return parse_res.rules_count > 0
        except Exception as e:
            logger.error("读取规则文件 %s 失败: %s", filepath, e)
            return False

    async def _fetch_url_async(self, url: str, max_size: int = DEFAULT_MAX_SIZE,
                               timeout: int = 30) -> Optional[str]:
        """获取远程 URL 内容（全量模式，向下兼容）"""
        try:
            headers = {"User-Agent": "SecureDNS-Proxy/1.0",
                       "Accept-Encoding": "gzip, deflate"}
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=headers,
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

    async def _process_rules_from_text(self, text: str, url: str) -> bool:
        """
        两遍解析全文规则并索引（使用 ThreadPoolExecutor 多线程并行）。
        第 1 遍：收集 $badfilter 目标（确保顺序无关）
        第 2 遍：索引规则，跳过被 badfilter 禁用的
        调用方须确保 text 已通过 HTML/二进制检测。
        """
        lines = text.splitlines()
        if not lines:
            return False

        NUM_WORKERS = 4
        chunk_size = (len(lines) + NUM_WORKERS - 1) // NUM_WORKERS
        loop = asyncio.get_running_loop()

        # ===== 第 1 遍：收集 $badfilter 目标（确保顺序无关）=====
        def collect_badfilters(start: int, end: int):
            """扫描一个分块，收集 $badfilter 目标 pattern"""
            for i in range(start, end):
                raw_line = lines[i]
                # 快速跳过：不含 $ 的行不可能有 badfilter
                if "$" not in raw_line:
                    continue
                stripped = raw_line.rstrip("\r").strip()
                if not stripped:
                    continue
                cleaned = AdGuardRuleParser._clean_rule_line(stripped)
                if cleaned is None:
                    continue
                rule = FilterRule(cleaned)
                if rule.is_badfilter:
                    target = self._extract_badfilter_target(cleaned)
                    if target:
                        self._badfilter_patterns.add(target)

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as pool:
            tasks = []
            for i in range(0, len(lines), chunk_size):
                end = min(i + chunk_size, len(lines))
                tasks.append(
                    loop.run_in_executor(pool, collect_badfilters, i, end)
                )
            await asyncio.gather(*tasks)

        # ===== 第 2 遍：索引规则（_index_rule 自动处理 pending/active）=====
        _index_rule = self._index_rule
        _is_rule_badfiltered = self._is_rule_badfiltered
        FilterRule_ = FilterRule
        total_rules = 0
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                continue
            # 快速跳过 cosmetic 规则（避免 FilterRule._parse 无谓开销）
            if "##" in stripped or "#@#" in stripped or "$$" in stripped:
                continue
            rule = FilterRule_(stripped)
            if rule._skip or rule.is_badfilter:
                continue
            # ★ BUGFIX: 使用 cleaned 行检查 badfilter（与第 1 阶段格式一致）
            cleaned = AdGuardRuleParser._clean_rule_line(stripped)
            if cleaned is not None and _is_rule_badfiltered(cleaned):
                continue
            _index_rule(rule, stripped)
            total_rules += 1

        # 跟踪 URL（与流式路径一致）
        if self._pending_block_index is not None:
            self._pending_rule_count += total_rules
            self._pending_loaded_urls.append(url)
            total = self._pending_rule_count
        else:
            self._rule_count += total_rules
            self._loaded_urls.append(url)
            total = self._rule_count

        logger.info("从 %s 加载了 %d 条规则 (总: %d)", url, total_rules, total)
        return total_rules > 0

    async def _download_url_parallel(self, url: str, num_chunks: int = 8,
                                      timeout: int = 60) -> Optional[bytes]:
        """
        使用 HTTP Range 分片并行下载 URL 内容（类似迅雷多线程下载）。

        先 HEAD 探测是否支持 Accept-Ranges: bytes，支持则将文件分成
        num_chunks 片，并发 GET Range 下载，最后按序拼接。

        Range 请求与 gzip 不兼容（无法解压部分压缩数据），因此原文下载。
        8 路并发足够弥补未压缩的带宽开销。

        Returns:
            完整文件字节内容，不支持 Range 或任何失败返回 None（触发回退）
        """
        try:
            headers = {"User-Agent": "SecureDNS-Proxy/1.0"}
            connector = None
            if self._resolver_manager is not None:
                resolver = _EncryptedDNSResolver(self._resolver_manager)
                connector = aiohttp.TCPConnector(resolver=resolver)

            # 1. HEAD 探测 Range 支持和文件大小
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                headers=headers,
                connector=connector,
            ) as session:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        return None
                    accept_ranges = (resp.headers.get("Accept-Ranges", "")
                                     .lower().strip())
                    content_length = resp.headers.get("Content-Length")
                    if "bytes" not in accept_ranges or not content_length:
                        return None
                    file_size = int(content_length)
                    if file_size <= 0 or file_size > DEFAULT_MAX_SIZE:
                        return None
                    if file_size < 65536:  # 小于 64KB 不值得分片
                        return None

            logger.info("并行下载 %s (%d bytes, %d 片)", url, file_size, num_chunks)

            # 2. 计算分片边界
            chunk_size = (file_size + num_chunks - 1) // num_chunks
            chunks = {}
            lock = asyncio.Lock()

            async def download_chunk(idx: int, start: int, end: int):
                """下载单个分片 [start, end]（闭区间）"""
                range_hdr = f"bytes={start}-{end}"
                chunk_headers = {
                    "User-Agent": "SecureDNS-Proxy/1.0",
                    "Range": range_hdr,
                }
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers=chunk_headers,
                    connector=connector,
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as resp:
                        if resp.status not in (200, 206):
                            raise IOError(
                                f"分片 {idx} HTTP {resp.status}: {range_hdr}"
                            )
                        data = await resp.read()
                        expected = end - start + 1
                        if len(data) != expected:
                            if idx < num_chunks - 1 or len(data) == 0:
                                raise IOError(
                                    f"分片 {idx}: 期望 {expected} bytes, 收到 {len(data)}"
                                )
                        async with lock:
                            chunks[idx] = data
                        logger.debug("  分片 %d/%d: %d bytes [%d-%d]",
                                     idx + 1, num_chunks, len(data), start, end)

            # 3. 并发下载所有分片
            tasks = []
            for i in range(num_chunks):
                start = i * chunk_size
                end = min(start + chunk_size, file_size) - 1
                if start >= file_size:
                    break
                tasks.append(asyncio.create_task(download_chunk(i, start, end)))

            try:
                await asyncio.gather(*tasks)
            except Exception as e:
                logger.warning("URL %s 分片下载异常: %s，回退到流式下载", url, e)
                for t in tasks:
                    t.cancel()
                return None

            # 4. 验证完整性并按序拼接
            if len(chunks) != len(tasks):
                return None

            result = bytearray(file_size)
            offset = 0
            for i in range(len(tasks)):
                data = chunks.get(i)
                if data is None:
                    return None
                result[offset:offset + len(data)] = data
                offset += len(data)

            logger.info("  并行下载完成: %d bytes (%d 片)", offset, len(tasks))
            return bytes(result)

        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug("URL %s 并行下载不可用: %s，回退到流式下载", url, e)
            return None

    async def load_rules_from_url_async(self, url: str) -> bool:
        """
        异步从远程 URL 加载规则（带流式处理，避免全量文本驻留内存）。
        逐行读取并解析，不将整个文件同时加载到内存。
        """
        try:
            # 优先尝试并行分片下载（HTTP Range 8 路并发，类似迅雷）
            parallel_data = await self._download_url_parallel(url)
            if parallel_data is not None:
                # 并行下载成功 → 全量文本解析
                text = parallel_data.decode("utf-8", errors="replace")
                # HTML 检测
                if self._parser._looks_like_html(text):
                    logger.error("URL %s 内容包含 HTML，跳过", url)
                    return False
                # 二进制检测
                has_binary, line_no, desc = self._parser._has_binary_chars(text)
                if has_binary:
                    logger.error("URL %s 包含二进制字符: %s", url, desc)
                    return False
                return await self._process_rules_from_text(text, url)

            # 并行下载不可用 → 回退到全文 gzip 下载（使用 _process_rules_from_text 多进程解析）
            # 显式请求 gzip 压缩（自定义 headers 会覆盖 aiohttp 默认的 Accept-Encoding）
            headers = {"User-Agent": "SecureDNS-Proxy/1.0",
                       "Accept-Encoding": "gzip, deflate"}
            # 当加密上游就绪时，使用自定义 DNS 解析器（走 DoH/DoT/DoQ）
            connector = None
            if self._resolver_manager is not None:
                resolver = _EncryptedDNSResolver(self._resolver_manager)
                connector = aiohttp.TCPConnector(resolver=resolver)

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=80),
                headers=headers,
                connector=connector,
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=80)) as resp:
                    if resp.status != 200:
                        logger.error("获取 URL %s 失败: HTTP %d", url, resp.status)
                        return False

                    content_length = resp.headers.get("Content-Length")
                    if content_length and int(content_length) > DEFAULT_MAX_SIZE:
                        logger.error("URL %s 文件过大: %s bytes (限制 %d)",
                                     url, content_length, DEFAULT_MAX_SIZE)
                        return False

                    raw = await resp.read()
                    if len(raw) > DEFAULT_MAX_SIZE:
                        logger.error("URL %s 实际大小 %d 超过限制 %d",
                                     url, len(raw), DEFAULT_MAX_SIZE)
                        return False

                    text = raw.decode("utf-8", errors="replace")

                    # HTML 检测
                    if self._parser._looks_like_html(text):
                        logger.error("URL %s 内容包含 HTML，跳过", url)
                        return False
                    # 二进制检测
                    has_binary, line_no, desc = self._parser._has_binary_chars(text)
                    if has_binary:
                        logger.error("URL %s 包含二进制字符: %s", url, desc)
                        return False

                    return await self._process_rules_from_text(text, url)

        except asyncio.TimeoutError:
            logger.error("从 URL %s 加载规则超时 (80s)", url)
            return False
        except Exception as e:
            logger.error("从 URL %s 加载规则失败: %s", url, e)
            return False

    async def async_reload(self, files: List[str], urls: Optional[List[str]] = None):
        """
        异步重新加载所有规则（原子加载模式）。

        加载流程：
        1. 保存旧规则状态（旧索引保持活跃应答 DNS 查询）
        2. 创建 pending 索引（不触碰活跃索引）
        3. 将新规则加载到 pending 索引
        4. 加载成功则原子交换 pending → active；失败则丢弃 pending，保留旧状态
        5. 清除 filter_cache（旧缓存基于旧规则集，已失效）
        """
        # 1. 保存旧状态
        saved_state = {
            'block_index': self._block_index,
            'allow_index': self._allow_index,
            'plain_domains': self._plain_domains,
            'loaded_files': list(self._loaded_files),
            'loaded_urls': list(self._loaded_urls),
            'rule_count': self._rule_count,
        }

        # 2. 创建 pending 状态（不触碰活跃索引）
        gc.collect(generation=2)
        self._pending_block_index = DomainIndex()
        self._pending_allow_index = DomainIndex()
        self._pending_plain_domains = set()
        self._pending_rule_count = 0
        self._pending_loaded_files = []
        self._pending_loaded_urls = []
        self._loading = True

        # 3. 加载到 pending 状态
        try:
            for filepath in files:
                self.load_rules_from_file(filepath)

            if urls:
                await asyncio.gather(
                    *[self.load_rules_from_url_async(url) for url in urls],
                    return_exceptions=True,
                )

            # 4. 原子交换或恢复
            if self._pending_rule_count == 0 and saved_state['rule_count'] > 0:
                logger.error("规则加载失败（所有 %d 个远程 URL 均不可用），"
                             "保留上次的 %d 条规则 | 本地上次: %d 个文件",
                             len(urls or []), saved_state['rule_count'],
                             len(saved_state['loaded_files']))
            else:
                # 原子交换：pending → active
                self._block_index = self._pending_block_index
                self._allow_index = self._pending_allow_index
                self._plain_domains = self._pending_plain_domains
                self._loaded_files = self._pending_loaded_files
                self._loaded_urls = self._pending_loaded_urls
                self._rule_count = self._pending_rule_count
                # 清除 filter_cache：旧缓存基于旧规则集，可能不再正确
                self._filter_cache = {}

                logger.info("规则重载完成，共 %d 条规则 (本地: %d, 远程: %d)",
                             self._rule_count, len(files), len(urls or []))

        finally:
            # 5. 清理 pending 状态
            self._pending_block_index = None
            self._pending_allow_index = None
            self._pending_plain_domains = None
            self._pending_loaded_files = []
            self._pending_loaded_urls = []
            self._loading = False

        # ★ 重载后显式释放旧状态 + GC：释放旧 DomainIndex 占用的 pymalloc arena
        del saved_state
        import gc as _gc_after_reload
        for _ in range(3):
            _gc_after_reload.collect(generation=2)

        if self._update_callback:
            try:
                self._update_callback(self._rule_count)
            except Exception as e:
                logger.debug("过滤器异步重载回调异常: %s", e)

    def reload(self, files: List[str], urls: Optional[List[str]] = None):
        """
        重新加载所有规则（同步接口，用于测试）
        使用与 async_reload 相同的原子加载模式。
        """
        # 1. 保存旧状态
        saved_state = {
            'block_index': self._block_index,
            'allow_index': self._allow_index,
            'plain_domains': self._plain_domains,
            'loaded_files': list(self._loaded_files),
            'loaded_urls': list(self._loaded_urls),
            'rule_count': self._rule_count,
        }

        # 2. 创建 pending 状态（不触碰活跃索引）
        gc.collect(generation=2)
        self._pending_block_index = DomainIndex()
        self._pending_allow_index = DomainIndex()
        self._pending_plain_domains = set()
        self._pending_rule_count = 0
        self._pending_loaded_files = []
        self._pending_loaded_urls = []
        self._loading = True

        # 3. 加载到 pending 状态
        try:
            for filepath in files:
                self.load_rules_from_file(filepath)

            if urls:
                for url in urls:
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            logger.warning("规则 URL %s 无法同步加载（事件循环已运行）", url)
                            continue
                        from urllib.parse import urlparse as _urlparse
                        parsed = _urlparse(url)
                        if parsed.scheme not in ("http", "https"):
                            raise ValueError(f"不允许的 URL 协议: {parsed.scheme}")
                        import urllib.request
                        resp = urllib.request.urlopen(url, timeout=120)  # nosec B310 - scheme validated above
                        content = resp.read().decode("utf-8", errors="replace")
                        self.load_rules_from_text(content, source=url)
                        self._pending_loaded_urls.append(url)
                    except Exception as e:
                        logger.error("从 %s 加载规则失败: %s", url, e)

            # 4. 原子交换或恢复
            if self._pending_rule_count == 0 and saved_state['rule_count'] > 0:
                logger.error("同步规则加载失败，保留上次的 %d 条规则",
                             saved_state['rule_count'])
            else:
                # 原子交换：pending → active
                self._block_index = self._pending_block_index
                self._allow_index = self._pending_allow_index
                self._plain_domains = self._pending_plain_domains
                self._loaded_files = self._pending_loaded_files
                self._loaded_urls = self._pending_loaded_urls
                self._rule_count = self._pending_rule_count
                self._filter_cache = {}

                logger.info("规则重载完成，共 %d 条规则 (本地: %d, 远程: %d)",
                             self._rule_count, len(files), len(urls or []))

        finally:
            # 5. 清理 pending 状态
            self._pending_block_index = None
            self._pending_allow_index = None
            self._pending_plain_domains = None
            self._pending_loaded_files = []
            self._pending_loaded_urls = []
            self._loading = False

        if self._update_callback:
            try:
                self._update_callback(self._rule_count)
            except Exception as e:
                logger.debug("过滤器同步重载回调异常: %s", e)

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

        # 0. 检查自定义 hosts 映射（最高优先级白名单）
        #    无论是有自定义IP还是纯域名绕过，都跳过所有过滤规则。
        #    返回 False（不拦截）确保缓存扫描（_sweep_once）不会误覆写。
        if self._custom_hosts_enabled:
            if domain in self._custom_hosts:
                self._filter_cache[domain] = (False, "custom_hosts", now, True)
                return False, "custom_hosts"
            if domain in self._custom_hosts_bypass:
                self._filter_cache[domain] = (False, "custom_hosts_bypass", now, True)
                return False, "custom_hosts_bypass"

        # 1. 检查统一过滤结果缓存
        cached = self._filter_cache.get(domain)
        if cached is not None:
            result, reason, ts, priority = cached
            # blocked 结果永久有效（直到规则重载清空 _filter_cache）；
            # allowed 结果使用 _cache_ttl_allowed 检查；priority 条目永不超时
            if priority or result:
                if result:
                    logger.debug("FilterCache HIT(blocked): %s | %s (永久)", domain, reason[:60])
                else:
                    logger.debug("FilterCache HIT(allow/priority): %s", domain)
                return result, reason
            # allowed 结果检查 TTL
            if now - ts < self._cache_ttl_allowed:
                logger.log(logging.DEBUG-1, "FilterCache HIT(allow): %s (ttl=%ds)", domain, self._cache_ttl_allowed)
                return result, reason
            # allowed 缓存过期，删除并重新匹配
            del self._filter_cache[domain]
            logger.debug("FilterCache EXPIRED(allow): %s (age=%.1fs)", domain, now - ts)

        # 2. 重要规则优先匹配（通过 block_index 中的 is_important 规则）
        #    重要规则与普通规则都在 block_index 中，但通过 FilterRule.is_important 区分
        #    先查 block_index，如果命中重要规则直接拦截；
        #    如果命中普通规则则保存结果，等白名单检查完后决定
        block_match = self._block_index.match(domain)
        block_rule_result = None
        if block_match is not None:
            rule, method = block_match
            if rule.is_important:
                if rule.dnsrewrite:
                    self._last_dnsrewrite = rule.dnsrewrite
                    reason = "dnsrewrite"
                    if not self._cache_suspended:
                        self._filter_cache[domain] = (True, reason, now, False)
                    self._defer_trim()
                    return True, reason
                reason = f"重要规则拦截: {rule.raw}"
                if not self._cache_suspended:
                    self._filter_cache[domain] = (True, reason, now, False)
                self._defer_trim()
                logger.debug("拦截(重要规则): %s | %s", domain, rule.raw[:60])
                return True, reason
            # 保存普通规则匹配结果，避免后续重新查询
            block_rule_result = (rule, method)

        # 3. 白名单索引 — 类似 Go 的 filteringEngineAllow.MatchRequest()
        match = self._allow_index.match(domain)
        if match is not None:
            rule, method = match
            if not self._cache_suspended and not self._loading:
                self._filter_cache[domain] = (False, "", now, False)
            logger.debug("放行(白名单): %s | %s: %s", domain, method, rule.raw[:60])
            return False, ""

        # 3b. 快速纯域名 set 查找（在白名单之后，防止绕过白名单）
        if domain in self._plain_domains:
            reason = "plain_domain_block"
            if not self._cache_suspended:
                self._filter_cache[domain] = (True, reason, now, False)
            self._defer_trim()
            return True, reason

        # 4. 使用步骤 2 保存的 block 匹配结果（如有）
        if block_rule_result is not None:
            rule, method = block_rule_result
            if rule.dnsrewrite:
                self._last_dnsrewrite = rule.dnsrewrite
                reason = "dnsrewrite"
            else:
                reason = f"{method}: {rule.raw}"
            if not self._cache_suspended:
                self._filter_cache[domain] = (True, reason, now, False)
            self._defer_trim()
            logger.debug("拦截: %s | %s (%s)", domain, method, rule.raw[:80])
            return True, reason

        # 未匹配：缓存并放行
        if not self._cache_suspended and not self._loading:
            self._filter_cache[domain] = (False, "", now, False)
        self._defer_trim()
        logger.log(logging.DEBUG-1, "放行(无匹配): %s (共 %d 条拦截规则)", domain, self._rule_count)
        return False, ""

    def get_last_dnsrewrite(self) -> Optional[dict]:
        """获取上一条匹配的 $dnsrewrite 规则数据（读取后清除）"""
        result = self._last_dnsrewrite
        self._last_dnsrewrite = None
        return result

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
        self._custom_hosts_bypass.clear()
        # 统一缓存中 priority 标记的自定义 hosts 条目在下次 check_domain 时会自动覆盖

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
            # 格式1: "domain" — 纯域名白名单，绕过过滤规则，正常解析
            # 格式2: "domain ip1,ip2" — 自定义 IP 映射
            parts = entry.split(None, 1)
            domain = parts[0].strip().lower()
            if not domain:
                continue
            if len(parts) == 1:
                # 纯域名白名单（无自定义IP）
                self._custom_hosts_bypass.add(domain)
            else:
                # 域名 + IP 映射
                ip_str = parts[1]
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

        total = len(self._custom_hosts) + len(self._custom_hosts_bypass)
        logger.info("自定义 hosts 映射已加载: %d 条 (IP映射: %d, 白名单绕过: %d)",
                     total, len(self._custom_hosts), len(self._custom_hosts_bypass))

    def is_custom_hosts_bypass(self, domain: str) -> bool:
        """检查域名是否在纯域名白名单中（无自定义IP，仅跳过过滤规则）"""
        domain = domain.lower().rstrip(".")
        return domain in self._custom_hosts_bypass

    def get_custom_hosts_ips(self, domain: str) -> Optional[List[Tuple[str, int]]]:
        """获取自定义 hosts 中域名对应的 IP 列表"""
        domain = domain.lower().rstrip(".")
        return self._custom_hosts.get(domain)

    def suspend_cache(self, suspended: bool):
        """在内存压力下暂停/恢复过滤缓存写入（priority 条目不受影响）
        
        Args:
            suspended: True=暂停写入新条目, False=恢复写入
        """
        self._cache_suspended = suspended
        if suspended:
            logger.info("过滤缓存写入已暂停（内存压力）")
        else:
            logger.info("过滤缓存写入已恢复")

    def clear_filter_cache(self):
        """清除过滤结果缓存（保留 priority 条目如自定义 hosts）"""
        priority_keys = [k for k, v in self._filter_cache.items()
                         if len(v) >= 4 and v[3]]  # v = (blocked, reason, ts, priority)
        self._filter_cache = {}
        for k in priority_keys:
            if k in self._custom_hosts or k in self._custom_hosts_bypass:
                self._filter_cache[k] = (False, "custom_hosts", time.monotonic(), True)
        logger.debug("过滤缓存已清除（保留 %d 条 priority 条目）", len(priority_keys))

    def _defer_trim(self):
        """延迟执行缓存裁剪，带防重复标志"""
        if self._cache_trim_pending:
            return
        self._cache_trim_pending = True
        asyncio.get_event_loop().call_soon(self._trim_cache_wrapper)

    def _trim_cache_wrapper(self):
        """call_soon 回调：执行裁剪并清除标志"""
        try:
            self._trim_filter_cache()
        finally:
            self._cache_trim_pending = False

    def _trim_filter_cache(self):
        """限制过滤缓存大小，跳过 priority 条目（自定义 hosts）"""
        if len(self._filter_cache) <= self._filter_cache_maxsize:
            return
        # 超出上限时移除最旧的非 priority 条目
        remove_count = len(self._filter_cache) - self._filter_cache_maxsize
        remove_count = max(remove_count, len(self._filter_cache) // 4)
        removed = 0
        for _ in range(remove_count * 2):  # 加倍扫描，因为可能跳过 priority
            if len(self._filter_cache) <= self._filter_cache_maxsize:
                break
            try:
                k, v = next(iter(self._filter_cache.items()))
                # priority 条目永不淘汰
                if len(v) >= 4 and v[3]:
                    # 移到末尾再试下一个
                    val = self._filter_cache.pop(k)
                    self._filter_cache[k] = val
                    continue
                del self._filter_cache[k]
                removed += 1
            except (KeyError, StopIteration):
                break
        if removed:
            logger.debug("过滤缓存已达上限 %d，已裁剪 %d 条",
                         self._filter_cache_maxsize, removed)


    def rebuild_filter_cache(self):
        """撤离重建过滤缓存 — 释放碎片化 pymalloc arena

        过滤缓存最大 100000 条 Dict[str, Tuple[bool, str, float, bool]]，
        大量 tuple + str 散布在 arena 中。重建让所有存活条目
        重新分配进更少、更紧凑的新 arena。
        """
        if not self._filter_cache:
            return
        # 分离 priority 条目（自定义 hosts，永不淘汰）
        priority_items = [
            (k, v) for k, v in self._filter_cache.items()
            if len(v) >= 4 and v[3]
        ]
        # 保留未过期的非 priority 条目 + 所有已拦截条目（永久有效，不淘汰）
        now = time.monotonic()
        timeout = self._cache_ttl_allowed
        active_items = [
            (k, v) for k, v in self._filter_cache.items()
            if not (len(v) >= 4 and v[3])
            and (len(v) >= 3 and (v[0] or now - v[2] < timeout))
        ]
        old_count = len(self._filter_cache)
        # 清空旧 dict
        self._filter_cache = {}
        # 重建：新 dict 条目在连续 arena 中分配
        for k, v in priority_items:
            self._filter_cache[k] = v
        for k, v in active_items:
            self._filter_cache[k] = v
        logger.debug("Filter cache 撤离重建: %d -> %d (priority=%d, active=%d)",
                     old_count, len(self._filter_cache), len(priority_items), len(active_items))

        # ★ GC 释放旧 _filter_cache 占用的 arena 碎片
        #     清空旧 dict 后，大量 str key + tuple value 的引用已释放，
        #     显式 GC 确保这些对象占用的 pymalloc pool 变为 fully-free → munmap
        import gc as _gc
        _gc.collect(generation=2)


    # ======================== 定时更新 ========================

    def on_update(self,cb): self._update_callback = cb
    def on_restart(self,cb): self._restart_cb = cb
    def record_query(self):
        h = time.localtime().tm_hour
        if self._traffic_slot != h: self._traffic_slot = h
        self._hourly_traffic[h] += 1
    def _lowest_hour(self):
        t = self._hourly_traffic
        if sum(t)==0: return (time.localtime().tm_hour+1)%24
        m = min(t); cand = [i for i,v in enumerate(t) if v==m]
        cur = time.localtime().tm_hour
        fut = [h for h in cand if h>cur]
        return min(fut) if fut else min(cand)
    async def start_auto_update(self,interval_hours,urls=None,files=None):
        if interval_hours<=0: return
        self._update_interval_hours = interval_hours
        self._running = True
        self._update_task = asyncio.create_task(self._restart_loop())
    async def stop_auto_update(self):
        self._running = False
        if self._update_task:
            self._update_task.cancel()
            try: await self._update_task
            except asyncio.CancelledError: pass
            self._update_task = None
    async def _restart_loop(self):
        while self._running:
            try:
                await asyncio.sleep(self._update_interval_hours*3600)
                if not self._running: break
                await self._schedule_restart()
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error("restart loop error: %s",e)
    async def _schedule_restart(self):
        if not self._restart_cb: return
        bh = self._lowest_hour()
        ch = time.localtime().tm_hour
        cm = time.localtime().tm_min
        if bh>ch: ws = (bh-ch)*3600-cm*60
        elif bh<ch: ws = (24-ch+bh)*3600-cm*60
        else:
            ws = 3600-cm*60
            if ws<60: ws += 3600
        logger.info("restart in %d min at hour %d",ws//60,bh)
        await asyncio.sleep(ws)
        if self._restart_cb:
            try:
                self._restart_cb(bh)
            except Exception as e: logger.error("restart cb error: %s",e)
    @property
    def stats(self) -> dict:
        # 从索引实时计算，不再维护冗余列表
        block_count = self._block_index.count
        allow_count = self._allow_index.count
        return {
            "total_rules": block_count + allow_count,
            "block_rules": block_count,
            "exception_rules": allow_count,
            "important_rules": 0,  # 不再单独追踪，包含在 block_rules 中
            "block_index_domains": self._block_index.domain_count,
            "allow_index_domains": self._allow_index.domain_count,
            "filter_cache_size": len(self._filter_cache),
            "loaded_files": self._loaded_files,
            "loaded_urls": self._loaded_urls,
            "title": self._title,
            "update_interval_hours": self._update_interval_hours,
            "auto_update_running": self._running,
            "hourly_traffic": list(self._hourly_traffic),
            "lowest_traffic_hour": self._lowest_hour(),
            "custom_hosts_count": len(self._custom_hosts) + len(self._custom_hosts_bypass),
            "custom_hosts_enabled": self._custom_hosts_enabled,
        }

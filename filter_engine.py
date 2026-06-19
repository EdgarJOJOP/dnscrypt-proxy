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

    __slots__ = ("pattern", "is_exception", "is_important", "is_regex", "raw", "_skip",
                 "is_badfilter", "dnsrewrite")

    def __init__(self, rule_text: str):
        self.raw = rule_text
        self.is_exception = False
        self.is_important = False
        self.is_regex = False
        self.pattern = rule_text
        self._skip = False
        self.is_badfilter = False
        self.dnsrewrite = None

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
            # 纯通配符 * 会匹配所有域名，DNS 级别不应使用
            if clean == '*':
                self._skip = True
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

    def __init__(self, cache_dir: Optional[str] = None,
                 cache_ttl_blocked: int = 300,
                 cache_ttl_allowed: int = 60,
                 cache_maxsize: int = 100000):
        """
        Args:
            cache_dir: 缓存目录（未使用，保留兼容）
            cache_ttl_blocked: 已拦截域名的过滤缓存 TTL（秒），默认 300
            cache_ttl_allowed: 放行域名的过滤缓存 TTL（秒），默认 60
            cache_maxsize: 过滤缓存最大条目数，默认 100000
        """
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

        # ========== 自定义 hosts 映射 ==========
        # 格式: {domain: [(ip, rdtype), ...]}
        # 例如: {"my.dns": [("127.0.0.1", dns.rdatatype.A), ("192.168.1.1", dns.rdatatype.A)]}
        self._custom_hosts: Dict[str, List[Tuple[str, int]]] = {}
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
        异步从远程 URL 加载规则（带流式处理，避免全量文本驻留内存）。
        逐行读取并解析，不将整个文件同时加载到内存。
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=80),
                headers={"User-Agent": "SecureDNS-Proxy/1.0"},
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

                    # 流式逐块读取，逐行处理
                    total = 0
                    line_buffer = ""
                    rule_count = 0
                    lines_processed = 0
                    first_chunk = True
                    raw_preview = bytearray()

                    async for chunk, _ in resp.content.iter_chunks():
                        total += len(chunk)
                        if total > DEFAULT_MAX_SIZE:
                            logger.error("URL %s 实际大小超过限制 %d", url, DEFAULT_MAX_SIZE)
                            return False

                        # 收集前 64KB 用于 HTML/二进制检测
                        if first_chunk and len(raw_preview) < 65536:
                            raw_preview.extend(chunk)
                            if len(raw_preview) >= 65536 or len(chunk) == 0:
                                preview_text = raw_preview.decode("utf-8", errors="replace")
                                # HTML 检测
                                if self._parser._looks_like_html(preview_text):
                                    logger.error("URL %s 内容包含 HTML，跳过", url)
                                    return False
                                # 二进制检测
                                has_binary, line_no, desc = self._parser._has_binary_chars(preview_text)
                                if has_binary:
                                    logger.error("URL %s 包含二进制字符: %s", url, desc)
                                    return False
                                first_chunk = False

                        # 解码块并逐行处理
                        decoded = chunk.decode("utf-8", errors="replace")
                        line_buffer += decoded

                        while "\n" in line_buffer:
                            line, line_buffer = line_buffer.split("\n", 1)
                            stripped = line.rstrip("\r").strip()
                            if not stripped:
                                continue

                            cleaned = AdGuardRuleParser._clean_rule_line(stripped)
                            if cleaned is None:
                                continue

                            # 直接编译规则（跳过 parse_to_text 的全量拆分）
                            rule = FilterRule(cleaned)
                            if rule._skip:
                                continue
                            if rule.is_badfilter:
                                target = self._extract_badfilter_target(cleaned)
                                if target:
                                    self._badfilter_patterns.add(target)
                                continue
                            if self._is_rule_badfiltered(cleaned):
                                continue
                            self._index_rule(rule, cleaned)
                            rule_count += 1
                            lines_processed += 1

                    # 处理最后一行（无换行符）
                    if line_buffer.strip():
                        cleaned = AdGuardRuleParser._clean_rule_line(line_buffer.strip())
                        if cleaned:
                            rule = FilterRule(cleaned)
                            if not rule._skip:
                                if rule.is_badfilter:
                                    target = self._extract_badfilter_target(cleaned)
                                    if target:
                                        self._badfilter_patterns.add(target)
                                elif self._is_rule_badfiltered(cleaned):
                                    pass
                                else:
                                    self._index_rule(rule, cleaned)
                                    rule_count += 1
                                    lines_processed += 1

                    if self._pending_block_index is not None:
                        self._pending_rule_count += rule_count
                        self._pending_loaded_urls.append(url)
                        total = self._pending_rule_count
                    else:
                        self._rule_count += rule_count
                        self._loaded_urls.append(url)
                        total = self._rule_count
                    logger.info("从 %s 流式加载了 %d 条规则 (总: %d)", url, rule_count, total)
                    return rule_count > 0

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
                self._filter_cache.clear()

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
                self._filter_cache.clear()

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

        # 0. 检查自定义 hosts 映射（最高优先级，存入统一缓存且标记 priority）
        if self._custom_hosts_enabled and domain in self._custom_hosts:
            self._filter_cache[domain] = (True, "custom_hosts", now, True)
            return True, "custom_hosts"

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
        self._filter_cache.clear()
        for k in priority_keys:
            if k in self._custom_hosts:
                self._filter_cache[k] = (True, "custom_hosts", time.monotonic(), True)
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
        self._filter_cache.clear()
        # 重建：新 dict 条目在连续 arena 中分配
        for k, v in priority_items:
            self._filter_cache[k] = v
        for k, v in active_items:
            self._filter_cache[k] = v
        logger.debug("Filter cache 撤离重建: %d -> %d (priority=%d, active=%d)",
                     old_count, len(self._filter_cache), len(priority_items), len(active_items))



    # ======================== 定时更新 ========================

    def on_update(self, callback: Callable):
        """注册规则更新回调"""
        self._update_callback = callback

    async def start_auto_update(self, interval_hours: int, urls: List[str],
                                 files: Optional[List[str]] = None):
        """
        启动定时更新任务。
        与 `async_reload` 一致：先清除全部旧规则，再重新从文件和 URL 加载。
        避免规则累加导致的重复和内存膨胀。
        """
        if interval_hours <= 0 or not urls:
            logger.info("远程规则自动更新未启用 (interval=%dh, urls=%d)",
                         interval_hours, len(urls))
            return

        self._update_interval_hours = interval_hours
        self._running = True
        self._update_files = files or []
        self._update_urls = urls
        self._update_task = asyncio.create_task(self._update_loop())
        logger.info("远程规则自动更新已启动 (间隔=%d小时, %d个源, 规则替换模式)",
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

    async def _update_loop(self):
        """
        定时更新循环 — 使用 async_reload 完整替换而非追加规则。
        每次更新先清除全部旧规则，再从文件和 URL 重新加载。
        """
        while self._running:
            try:
                await asyncio.sleep(self._update_interval_hours * 3600)
                if not self._running:
                    break

                logger.info("开始远程规则自动更新（完整替换模式）...")

                # 使用 async_reload 完整替换全部规则（清空旧规则 + 从文件+URL重新加载）
                await self.async_reload(self._update_files, urls=self._update_urls if self._update_urls else None)

                logger.info("远程规则更新完成，当前共 %d 条规则", self._rule_count)

                if self._update_callback:
                    try:
                        self._update_callback(self._rule_count)
                    except Exception as e:
                        logger.debug("过滤器更新循环回调异常: %s", e)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("远程规则更新异常（将在 %d 小时后重试）: %s",
                              self._update_interval_hours, e)

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
            "custom_hosts_count": len(self._custom_hosts),
            "custom_hosts_enabled": self._custom_hosts_enabled,
        }

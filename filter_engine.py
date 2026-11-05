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
import sys
import time
import zlib
import codecs
import threading
import asyncio
import logging
from typing import List, Tuple, Optional, Set, Callable, BinaryIO, TextIO, Dict
from bisect import bisect_left
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
import dns.rcode

logger = logging.getLogger("dns-proxy.filter")

# 规则下载最大大小（50MB）
DEFAULT_MAX_SIZE = 50 * 1024 * 1024


def _release_heap_to_os() -> None:
    """把已释放的空闲堆页归还内核（仅 Linux glibc；其它平台 no-op）

    规则加载会在短时间内申请上百 MB 临时内存（整份下载字节、2MB 分块、
    上百万次索引写入）。CPython 释放这些对象后，glibc 的 arena 默认保留
    空闲页，进程 RSS 就停在加载峰值的高水位上——同一份规则集在 Windows 上
    RSS 随 HeapFree 回落，Ubuntu 上却长期高出约 100MB。
    `malloc_trim(0)` 会立即把空闲页 madvise(MADV_DONTNEED) 掉。

    注意：`PYTHONMALLOC=mimalloc` 时分配器不是 glibc，本函数无效；那类
    部署应使用 `MIMALLOC_PURGE_DELAY=0`（mimalloc 会立即 purge 空闲段）。
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except Exception as e:  # 非 glibc（musl / 精简镜像）时静默跳过
        logger.debug("malloc_trim 不可用，跳过堆归还: %s", e)

# /regex/ 自由正则规则的防 ReDoS 限制
MAX_FREE_REGEX_LEN = 256     # 单条自由正则最大长度
MAX_FREE_REGEX_RULES = 500   # 自由正则规则总数上限（防线性遍历放大）


def _is_redos_prone(regex_text: str) -> bool:
    """静态预检：判断自由正则是否存在灾难性回溯（ReDoS）风险。

    规则列表可能来自远程（半可信），而客户端可用构造域名触发匹配 →
    单核 CPU 被灾难性回溯打满（放大 DoS）。这里只做保守的启发式拒绝：
      1. 超长（> MAX_FREE_REGEX_LEN）——正常域名正则极短；
      2. 叠加量词：分组内含无界量词（* / +）且分组本身又被 * / + / {n,m} 重复，
         如 (a+)+、(ab*c)+、(x*)* —— 经典灾难性回溯形态；
      3. 3 个及以上无界通配 .* / .+（重叠通配导致指数级回溯）。
    宁可漏报（放过）也不误伤合法规则。
    """
    if len(regex_text) > MAX_FREE_REGEX_LEN:
        return True
    # 分组内含 * 或 +，且分组后紧跟 * 或 +：( ... [*+] ... )[*+]
    if re.search(r"\([^()]*[*+][^()]*\)\s*[*+]", regex_text):
        return True
    # 分组内含 * 或 +，且分组后跟 {n,} / {n,m}
    if re.search(r"\([^()]*[*+][^()]*\)\s*\{\d+,\d*\}", regex_text):
        return True
    # 重叠无界通配 .* / .+ 出现 3 次及以上
    if len(re.findall(r"\.\*|\.\+", regex_text)) >= 3:
        return True
    return False

# 默认规则缓冲区大小（类似 Go 的 DefaultRuleBufSize）
DEFAULT_RULE_BUF_SIZE = 65536


# ============================================================
# DNS 规则判定（解析入口零分配预过滤）
# ------------------------------------------------------------
# DNS 过滤只能看到「域名 + 查询类型」，看不到页面 DOM/CSS/脚本，因此
# AdGuard 的 HTML 过滤规则（元素隐藏、扩展 CSS、CSS 注入、scriptlet、
# HTML 过滤）在 DNS 层完全没有意义：它们既不可能命中，又会为每条规则
# 构造 FilterRule 对象、编译正则、占用内存。规则列表动辄 50 万行，
# 必须在**建对象之前**按字符串丢掉。
# ============================================================

# 以 # 开头的 HTML 过滤标记（元素隐藏 / 扩展 CSS / CSS 注入 / scriptlet）
_HTML_FILTER_HASH_MARKERS = (
    "##", "#@#",      # 元素隐藏 / 例外
    "#?#", "#@?#",    # 扩展 CSS / 例外
    "#$#", "#@$#",    # CSS 注入 / 例外
    "#%#", "#@%#",    # scriptlet / 例外
)
# 以 $ 开头的 HTML 过滤标记（HTML 过滤 / 例外）
_HTML_FILTER_DOLLAR_MARKERS = ("$$", "$@$")


def is_html_filter_rule(line: str) -> bool:
    """该行是否为 AdGuard 的 HTML 过滤规则（元素隐藏 / scriptlet / HTML 过滤）。

    纯字符串判定、不分配对象（调用方每行都要检查，列表可到 50 万行）。
    以 `#` / `$` 做粗筛：域名规则几乎不含这两个字符，绝大多数行只做 1-2 次
    `in` 判断就返回 False。
    """
    if "#" in line:
        for marker in _HTML_FILTER_HASH_MARKERS:
            if marker in line:
                return True
    if "$" in line:
        for marker in _HTML_FILTER_DOLLAR_MARKERS:
            if marker in line:
                return True
    return False


# AdGuard DNS 过滤规则文档列出的、可能出现在 DNS 规则上的修饰符。
# 文档明确要求：**规则包含未列出的修饰符时，必须忽略整条规则**（避免把
# 面向浏览器/HTTP 的过滤列表套用到 DNS 层产生误报）。因此 third-party /
# script / image / redirect / removeparam / cookie / csp / replace 等
# 浏览器级修饰符不再放行——带这些修饰符的规则整条丢弃，既不匹配也不占内存。
#
# 本程序对其中各修饰符的实际处理：
#   important   —— 支持（优先级高于普通规则/普通例外）
#   badfilter   —— 支持（禁用同 pattern 的其它规则）
#   dnsrewrite  —— **整条跳过**（2026-10-31）：解析器能识别它，但四个 DNS 前端
#                  都没有消费 get_last_dnsrewrite()——带该修饰符的规则只会退化成
#                  "整域 NXDOMAIN"，即把本应返回 1.2.3.4 / REFUSED / 空应答的域名
#                  直接拦死（误拦截）。在真正实现响应重写之前，宁可少拦不误拦。
#   client      —— AdGuard Home/DNS 专用；本程序无客户端身份，无法评估 → 整条跳过
#   ctag        —— 同上（客户端标签）→ 整条跳过
#   respgeo     —— AdGuard DNS 专用（按响应 IP 国家/ASN）→ 无法评估 → 整条跳过
#   denyallow   —— DNS 可评估，但本程序尚未实现 → 整条跳过（宁可少拦，不误拦）
#   dnstype     —— 同上（按查询类型）→ 整条跳过
_DNS_DOC_MODIFIERS = frozenset({
    "important", "badfilter",
    "client", "ctag", "respgeo",
    "denyallow", "dnstype",
})


def _free_regex_parts(line: str):
    """把 `/regex/` 或 `/regex/$modifiers` 拆成 (正则部分, 修饰符部分)

    不是自由正则规则时返回 None。

    必须**在** `$` 修饰符切分之前识别：自由正则里的 `$` 是行尾锚点，
    早期实现直接 `rsplit("$", 1)`，会把 `/^ads\\.example\\.com$/` 切成
    正则 `/^ads\\.example\\.com` + 修饰符 `/`，然后因为 `/` 不是合法修饰符
    而把整条规则丢弃——所有带行尾锚点的正则规则全部静默失效（漏拦截）。
    """
    text = line.strip()
    if len(text) < 3 or not text.startswith("/"):
        return None
    last = text.rfind("/")
    if last <= 0:
        return None
    regex_part = text[:last + 1]
    rest = text[last + 1:]
    if not rest:
        return regex_part, None
    if rest.startswith("$"):
        return regex_part, rest[1:]
    return None


def has_non_dns_modifier(line: str) -> bool:
    """规则是否带有 AdGuard DNS 文档未列出的修饰符（非 DNS 规则）。

    不含 `$` → False（纯域名规则）。修饰符解析规则与 FilterRule._parse 一致：
    取最后一个 `$` 之后的部分、按逗号分隔、`name=value` 只取 name、`~` 前缀
    去掉；纯下划线（noop）按规范忽略。自由正则 `/regex/` 先整体识别，
    其中的 `$` 属于正则语法而非修饰符。
    """
    parts = _free_regex_parts(line)
    if parts is not None:
        line = parts[0]
        if parts[1] is None:
            return False
        # 只校验正则之后的修饰符部分
        line = "$" + parts[1]
    if "$" not in line:
        return False
    modifiers = line.rsplit("$", 1)[1]
    for mod in modifiers.split(","):
        mod = mod.strip()
        if not mod:
            continue
        name = mod.split("=", 1)[0].strip() if "=" in mod else mod
        if name.startswith("~"):
            name = name[1:]
        if not name:
            continue
        # noop 修饰符：纯下划线序列（任意长度），规范定义为"什么也不做"
        if not name.strip("_"):
            continue
        if name not in _DNS_DOC_MODIFIERS:
            return True
    return False


class ParseResult:
    """规则解析结果，类似 Go 的 ParseResult

    skipped_html / skipped_non_dns：解析阶段按 DNS 语法丢弃的规则数
    （HTML 过滤 / 带非 DNS 修饰符）。这些规则不会进入任何索引，用于日志与
    stats 观测"到底省掉了多少条"。
    """

    __slots__ = ("title", "rules_count", "checksum", "bytes_written",
                 "skipped_html", "skipped_non_dns", "text")

    def __init__(self, title: str = "", rules_count: int = 0,
                 checksum: int = 0, bytes_written: int = 0,
                 skipped_html: int = 0, skipped_non_dns: int = 0,
                 text: str = ""):
        self.title = title
        self.rules_count = rules_count
        self.checksum = checksum
        self.bytes_written = bytes_written
        self.skipped_html = skipped_html
        self.skipped_non_dns = skipped_non_dns
        # 清理后的规则文本（只含 DNS 规则）：parse_to_text 直接复用，
        # 避免为 50 万行列表再全量扫描一遍（纯 CPU 浪费）。
        self.text = text


class AdGuardRuleParser:
    """
    AdGuard 规则解析器
    对标 Go: github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist.Parser
    """

    ERR_HTML = "looks like the rules text contains an html, not plain text"

    @staticmethod
    def _looks_like_html(text: str) -> bool:
        """检测内容是否为 HTML（检查前 100 行）"""
        # **只切前 100 行**（2026-10-30）：原实现 `text.splitlines()[:100]` 会先对
        # 整个文件做一次 splitlines——hagezi tif 有 185 万行/37MB，这一刀就是
        # 约 7.8s 的纯 C 操作，持 GIL 不释放，事件循环线程被饿死，
        # 加载期间进程内的 DNS 服务一个查询都处理不了。
        # `str.split(sep, maxsplit)` 有切分数上限，代价只与切出的行数相关。
        lines = text.split("\n", 100)[:100]
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

    # 二进制控制字符（与旧实现的判定范围严格一致）：
    #   0x00-0x08、0x0E-0x1B、0x1F、0x7F。
    # 不含 0x0B/0x0C/0x1C-0x1E —— 它们是 `str.splitlines()` 的行分隔符，
    # 旧实现逐行遍历时**永远看不到**这些字符，这里保持一致，避免把
    # 含分页符的合法规则文件误判成二进制。
    _BINARY_CTRL_RE = re.compile(r"[\x00-\x08\x0e-\x1b\x1f\x7f]")

    @classmethod
    def _has_binary_chars(cls, text: str) -> Tuple[bool, int, str]:
        """
        检测二进制字符（仅检测真正的控制字符，不误伤中文等 Unicode）
        返回: (是否检测到, 行号, 描述)

        **改用 C 层正则**（2026-10-30）：原实现是 `for line in text.splitlines():
        for ch in line:` 的双层 Python 循环——37MB/185 万行要 7.4s，且 splitlines
        本身再来一次全量切分。正则一次扫描是毫秒级，语义完全相同（都返回
        第一个控制字符所在的行号/列号）。
        """
        m = cls._BINARY_CTRL_RE.search(text)
        if m is None:
            return False, 0, ""
        pos = m.start()
        line_no = text.count("\n", 0, pos) + 1
        col = pos - (text.rfind("\n", 0, pos) + 1)
        code = ord(m.group())
        return True, line_no, (
            f"line {line_no}: character {col}: likely binary character '\\x{code:02x}'"
        )

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
        - 跳过所有 HTML 过滤规则（元素隐藏 / 扩展 CSS / CSS 注入 / scriptlet /
          HTML 过滤）——DNS 层不可见、无意义，见 is_html_filter_rule
        """
        line = line.strip()
        if not line:
            return None
        # 注释: ! 或 #
        if line.startswith("!") or line.startswith("#"):
            return None
        # HTML 过滤规则：与 DNS 过滤无关，直接丢弃（不建对象、不入索引）
        if is_html_filter_rule(line):
            return None

        # etc/hosts 格式: 0.0.0.0 domain.com 或 127.0.0.1 domain.com
        # 官方定义：精确匹配域名，不匹配子域名
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+:+[0-9a-fA-F:]*|0\.0\.0\.0)\s+(\S+)$',
            line
        )
        if hosts_match:
            domain = hosts_match.group(1)
            # 跳过带路径的 hosts 条目
            if "/" not in domain:
                return domain  # 裸域名 → FilterRule 会做精确匹配

        # 带 AdGuard DNS 文档未列出的修饰符（$third-party / $script /
        # $redirect / $cookie …）→ 整条丢弃：DNS 层无法评估，加载只会误拦。
        # 文档要求：未列出的修饰符必须忽略整条规则。
        if has_non_dns_modifier(line):
            return None

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
        skipped_html = 0
        skipped_non_dns = 0

        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            # HTML 过滤规则（元素隐藏 / 扩展 CSS / CSS 注入 / scriptlet /
            # HTML 过滤）：DNS 层无意义 → 丢弃并计数（不写进 cleaned_text，
            # 后续 _compile_rules 连见都见不到）
            if is_html_filter_rule(stripped):
                skipped_html += 1
                continue
            # 注释: ! 或 #
            if stripped.startswith("!") or stripped.startswith("#"):
                continue
            # 带 AdGuard DNS 文档未列出的修饰符（$third-party / $script /
            # $redirect / $cookie …）→ 整条丢弃（文档要求：未列出即忽略整条）
            if has_non_dns_modifier(stripped):
                skipped_non_dns += 1
                continue
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
            skipped_html=skipped_html,
            skipped_non_dns=skipped_non_dns,
            text=output_str,
        )

    def parse_to_text(self, text: str) -> Tuple[str, ParseResult]:
        """
        解析并返回清理后的规则文本
        返回: (cleaned_text, parse_result)

        直接复用 parse() 已经拼好的输出（只含 DNS 规则），不再对原始文本做
        第二遍全量扫描——50 万行列表的二次扫描是纯 CPU 浪费。
        """
        result = self.parse(text)
        return result.text, result


# =============================================================================
# ★ OPTIMIZATION Phase 1: 紧凑域名规则匹配
# ★ 对简单域名规则（||domain^、裸域名、hosts格式）使用字符串匹配而非正则
# =============================================================================

# 规则类型常量（DomainTrie 用，1 字节存进 bytearray）
_RT_NONE = 0
_RT_BLOCK_EXACT = 1       # 精确域名拦截
_RT_BLOCK_SUBDOMAIN = 2   # ||domain^ 子域名拦截
_RT_ALLOW_EXACT = 3       # 精确白名单
_RT_ALLOW_SUBDOMAIN = 4   # @@||domain^ 子域名白名单
_RT_IMPORTANT_EXACT = 5   # 重要规则精确
_RT_IMPORTANT_SUBDOMAIN = 6  # 重要规则子域名

# 只有这三种类型在「非完整域名」层级也算命中（与旧 trie 的语义一致）
_SUBDOMAIN_TYPES = frozenset({
    _RT_BLOCK_SUBDOMAIN, _RT_ALLOW_SUBDOMAIN, _RT_IMPORTANT_SUBDOMAIN,
})

# 普通规则不保存原文，日志里用这些可读占位
_RT_RAW_TEXT = {
    _RT_BLOCK_EXACT: "compact:block",
    _RT_BLOCK_SUBDOMAIN: "compact:block+sub",
    _RT_ALLOW_EXACT: "compact:allow",
    _RT_ALLOW_SUBDOMAIN: "compact:allow+sub",
    _RT_IMPORTANT_EXACT: "compact:important",
    _RT_IMPORTANT_SUBDOMAIN: "compact:important+sub",
}


def _merge_rule_type(cur: int, new: int) -> int:
    """合并同一域名的多条规则（逐字复现旧 trie 的 add 优先级）：

    - important 覆盖一切；
    - block 覆盖非 important 的规则（同域名的旧 block 也被后来者替换，
      因此 EXACT/SUB 的粒度以最后一条 block 规则为准）；
    - allow 只在当前没有规则时生效。
    """
    if new in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN):
        return new
    if new in (_RT_BLOCK_EXACT, _RT_BLOCK_SUBDOMAIN):
        if cur in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN):
            return cur
        return new
    if new in (_RT_ALLOW_EXACT, _RT_ALLOW_SUBDOMAIN):
        if cur == _RT_NONE:
            return new
        return cur
    return cur


class _DomainTrie:
    """域名索引 —— 反转标签排序的扁平表（真正的紧凑存储）。

    旧实现（每个标签一个 `_DomainTrieNode` + 每层一个 dict）在 32.9 万条
    真实规则下实测：「紧凑」名不副实 ——

        462,375 个节点对象  28.2MB
        139,840 个 dict      32.3MB
        462,374 个标签字符串 22.0MB
        合计                 82.5MB（每域名 263B，是域名文本本身的 10 倍以上）

    这里把同一棵树压成三组平行结构：

      _keys    list[bytes]  反转标签后的域名键（mediav.com → b"com.mediav"），
                            按字节序排序；父域在排序中恰是子域的前缀
      _types   bytearray    与 _keys 对齐的规则类型（_RT_*，1 字节/条）
      _rewrites/_raws       dict，稀疏旁路：仅 $dnsrewrite 与 important 规则的原文

    内存：每域名 ≈ 一个 bytes（33+len）+ 8B 列表槽 + 1B 类型 ≈ 60B；
    32.9 万条实测 18.9MB（**旧实现的 23%**）。

    匹配：对「本域 + 各级父域」（反转后即前缀）各做一次 bisect——C 实现的
    二分，实测 3.2µs/次（旧 trie 2.3µs/次；QPS 1000 时 <0.1% CPU）。

    增量写入：加载期间先写 `_pending` dict（同域名按优先级合并），加载结束
    （或增量达到 `_FINALIZE_THRESHOLD`）再一次性归并进排序表，避免每条规则
    都重排整个数组。match/has_domain 会同时查 pending 与表，保持旧 trie 的
    「加载中已可见」语义。
    """

    __slots__ = ('_keys', '_types', '_rewrites', '_raws',
                 '_pending', '_pending_rewrites', '_pending_raws',
                 '_count', '_domain_count')

    # 增量区达到该条数时自动归并：限制加载峰值内存，同时避免频繁 O(N) 归并
    _FINALIZE_THRESHOLD = 50000

    def __init__(self):
        self._keys: List[bytes] = []
        self._types = bytearray()
        # 稀疏旁路（绝大多数规则既没有 dnsrewrite，也没有保留原文）
        self._rewrites: Dict[bytes, dict] = {}
        self._raws: Dict[bytes, str] = {}
        # 增量区（尚未归并进 _keys/_types）
        self._pending: Dict[bytes, int] = {}
        self._pending_rewrites: Dict[bytes, dict] = {}
        self._pending_raws: Dict[bytes, str] = {}
        self._count = 0
        self._domain_count = 0

    # ---- 键变换 ----

    @staticmethod
    def _reverse_key(domain: str) -> bytes:
        """域名 → 反转标签键（小写）。父域反转后是子域反转键的前缀。"""
        return ".".join(reversed(domain.lower().rstrip('.').split('.'))).encode()

    def _lookup(self, key: bytes) -> int:
        """在「增量区 + 排序表」里查规则类型，未命中返回 _RT_NONE。"""
        pending = self._pending
        if pending:
            rt = pending.get(key, _RT_NONE)
            if rt != _RT_NONE:
                return rt
        keys = self._keys
        idx = bisect_left(keys, key)
        if idx < len(keys) and keys[idx] == key:
            return self._types[idx]
        return _RT_NONE

    # ---- 写入 ----

    def add(self, domain: str, rule_type: int, dnsrewrite: Optional[dict] = None,
            raw_short: str = "") -> bool:
        """添加域名规则（返回该域名是否首次出现）。"""
        key = self._reverse_key(domain)
        pending = self._pending
        cur = pending.get(key)
        is_new = False
        if cur is None:
            keys = self._keys
            idx = bisect_left(keys, key)
            if idx < len(keys) and keys[idx] == key:
                cur = self._types[idx]
            else:
                cur = _RT_NONE
                is_new = True
        pending[key] = _merge_rule_type(cur, rule_type)
        if dnsrewrite:
            self._pending_rewrites[key] = dnsrewrite
        if raw_short and key not in self._raws and key not in self._pending_raws:
            self._pending_raws[key] = raw_short
        self._count += 1
        if is_new:
            self._domain_count += 1
        if len(pending) >= self._FINALIZE_THRESHOLD:
            self.finalize()
        return is_new

    def finalize(self):
        """把增量区归并进已排序的扁平表，并释放临时 dict。

        表为空时直接排序建表；表非空时归并两个有序序列（O(N)；同键以增量区
        为准——增量区里的类型已经是「表值 + 新规则」合并后的结果）。
        """
        pending = self._pending
        if not pending:
            return
        pk = sorted(pending)
        keys = self._keys
        if not keys:
            self._keys = pk
            self._types = bytearray(pending[k] for k in pk)
        else:
            types = self._types
            out_keys: List[bytes] = []
            out_types = bytearray()
            i = j = 0
            npk = len(pk)
            nk = len(keys)
            while i < npk and j < nk:
                a = pk[i]
                b = keys[j]
                if a < b:
                    out_keys.append(a)
                    out_types.append(pending[a])
                    i += 1
                elif a > b:
                    out_keys.append(b)
                    out_types.append(types[j])
                    j += 1
                else:
                    out_keys.append(a)
                    out_types.append(pending[a])
                    i += 1
                    j += 1
            if i < npk:
                out_keys.extend(pk[i:])
                out_types.extend(pending[k] for k in pk[i:])
            if j < nk:
                out_keys.extend(keys[j:])
                out_types.extend(types[j:])
            self._keys = out_keys
            self._types = out_types
        if self._pending_rewrites:
            self._rewrites.update(self._pending_rewrites)
            self._pending_rewrites = {}
        if self._pending_raws:
            self._raws.update(self._pending_raws)
            self._pending_raws = {}
        self._pending = {}

    # ---- 查询 ----

    def match(self, domain: str) -> Optional[Tuple[Optional['_MatchInfo'], str]]:
        """匹配域名，返回 (_MatchInfo, 匹配方式)。

        语义与旧 trie 完全一致：
          - 完整域名层级：任意规则类型都算命中；
          - 中间层级（父域）：只有子域类型（block+sub / allow+sub /
            important+sub）才算命中；
          - 命中取**最深**（最具体）的那一级。
        """
        d = domain.lower().rstrip('.')
        if not d:
            return None
        labels = d.split('.')
        if not labels or not labels[0]:
            return None
        n = len(labels)
        last = n - 1
        hit_key = b""
        hit_text = ""
        hit_type = _RT_NONE
        # 同时维护两种累积：
        #   key_acc  —— 反转标签键（com → com.ads），用于查表
        #   text_acc —— 原域名文本（com → ads.com），用于日志/命中域名
        key_acc = labels[-1]
        text_acc = labels[-1]
        for i in range(n):
            if i:
                key_acc = key_acc + '.' + labels[n - i - 1]
                text_acc = labels[n - i - 1] + '.' + text_acc
            key = key_acc.encode()
            rt = self._lookup(key)
            if rt != _RT_NONE and (i == last or rt in _SUBDOMAIN_TYPES):
                hit_key = key
                hit_text = text_acc
                hit_type = rt
        if hit_type == _RT_NONE:
            return None
        raw = self._raws.get(hit_key)
        if not raw:
            raw = self._pending_raws.get(hit_key)
        rewrite = self._rewrites.get(hit_key)
        if rewrite is None:
            rewrite = self._pending_rewrites.get(hit_key)
        return (_MatchInfo(hit_type, raw, rewrite), f"域名匹配 ({hit_text})")

    def has_domain(self, domain: str) -> bool:
        """域名（或任一父域）是否有规则（诊断用，宽松判定，与旧实现一致）。"""
        d = domain.lower().rstrip('.')
        if not d:
            return False
        labels = d.split('.')
        if not labels or not labels[0]:
            return False
        n = len(labels)
        key_acc = labels[-1]
        for i in range(n):
            if i:
                key_acc = key_acc + '.' + labels[n - i - 1]
            if self._lookup(key_acc.encode()) != _RT_NONE:
                return True
        return False

    def clear(self):
        self._keys = []
        self._types = bytearray()
        self._rewrites = {}
        self._raws = {}
        self._pending = {}
        self._pending_rewrites = {}
        self._pending_raws = {}
        self._count = 0
        self._domain_count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def domain_count(self) -> int:
        return self._domain_count


class _MatchInfo:
    """匹配结果 — 轻量替代 FilterRule（只保留 check_domain 需要的字段）。

    与旧实现不同：不再持有 trie 节点（节点已不存在），直接存规则类型、
    原文（仅 important 规则保留）/ dnsrewrite（仅 $dnsrewrite 规则）。
    """

    __slots__ = ('rule_type', 'raw', 'dnsrewrite')

    def __init__(self, rule_type: int, raw: str = "",
                 dnsrewrite: Optional[dict] = None):
        self.rule_type = rule_type
        self.raw = raw or _RT_RAW_TEXT.get(rule_type, "compact:unknown")
        self.dnsrewrite = dnsrewrite

    @property
    def is_important(self) -> bool:
        return self.rule_type in (_RT_IMPORTANT_EXACT, _RT_IMPORTANT_SUBDOMAIN)

    @property
    def is_exception(self) -> bool:
        return self.rule_type in (_RT_ALLOW_EXACT, _RT_ALLOW_SUBDOMAIN)


class FilterRule:
    """单条过滤规则（编译后的匹配规则）"""

    __slots__ = ("pattern", "is_exception", "is_important", "is_regex", "is_free_regex",
                 "raw", "_skip",
                 "is_badfilter", "dnsrewrite",
                 # ★ Phase 1: 紧凑匹配字段
                 "_simple_match", "_simple_domain", "_match_subdomains",
                 # 通配符/正则规则的「匹配必要条件」锚点（供 DomainIndex 分组索引）
                 "_anchor_suffix", "_anchor_sld", "_anchor_prefix",
                 "_anchor_contains", "_order")

    def __init__(self, rule_text: str):
        self.raw = rule_text
        self.is_exception = False
        self.is_important = False
        self.is_regex = False
        # /regex/ 自由正则规则（区别于 _pattern_to_regex 生成的受控正则）
        self.is_free_regex = False
        self.pattern = rule_text
        self._skip = False
        self.is_badfilter = False
        self.dnsrewrite = None
        # ★ Phase 1: 紧凑匹配初始化
        self._simple_match = False
        self._simple_domain = ""
        self._match_subdomains = False
        # 锚点（只有 pattern 规则会用到；simple 规则留空）
        self._anchor_suffix = ""
        self._anchor_sld = ""
        self._anchor_prefix = ""
        self._anchor_contains = ""
        self._order = 0

        self._parse()

        # 只有通配符/正则规则（非 simple_match）才需要锚点：simple 规则走 trie，
        # 锚点只用于把 pattern 规则分组，避免未命中时线性跑全部正则。
        if not self._skip and not self._simple_match:
            self._set_anchor()

    # AdGuard **DNS** 过滤规则文档列出的修饰符集合。
    # 参见: https://adguard-dns.io/kb/general/dns-filtering-syntax/
    # 文档明确要求：不在列表中的 modifier → 整条规则忽略（官方规范），
    # 以免把浏览器/HTTP 级过滤列表套用到 DNS 层产生误报。
    #
    # 旧实现把 third-party / script / image / redirect / cookie 等浏览器级
    # 修饰符也放进"已知"集合，导致这些规则的域名被无条件加载进 trie、参与
    # 拦截匹配（DNS 层根本无法评估它们）。现在统一改为：只认下面 8 个 DNS
    # 修饰符，其余整条丢弃（在解析入口 has_non_dns_modifier 就已跳过，
    # 连 FilterRule 对象都不会创建）。
    _KNOWN_MODIFIERS = _DNS_DOC_MODIFIERS

    # 例外规则上无法评估/会改变语义的 DNS 修饰符集合。
    # 带这些修饰符的例外规则不能当作"无条件放行"，否则会放行过多域名。
    #   client / ctag / respgeo —— 本程序没有客户端身份 / 响应地理信息
    #   denyallow / dnstype     —— DNS 可评估但本程序尚未实现
    _EXCEPTION_RESTRICTIVE_MODIFIERS = frozenset({
        'client', 'ctag', 'respgeo',
        'denyallow', 'dnstype',
    })

    # 拦截规则上无法评估（或会改变语义）的 DNS 修饰符集合。
    # 带这些修饰符的拦截规则若当作"全域拦截"会误拦合法域名，因此整条跳过。
    # （$important / $dnsrewrite / $badfilter 不在此列：它们与域名拦截正交。）
    _BLOCK_RESTRICTIVE_MODIFIERS = frozenset({
        'client',     # 仅对特定客户端拦截 → 无法评估
        'ctag',       # 仅对特定客户端标签拦截 → 无法评估
        'respgeo',    # 仅按响应 IP 国家/ASN 拦截 → 无法评估
        'dnstype',    # 仅对特定 DNS 记录类型拦截 → 未实现
        'denyallow',  # 排除指定域名的拦截 → 未实现
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
            # noop 修饰符：纯下划线序列（任意长度），不做任何事
            if re.fullmatch(r'_+', name):
                continue
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

        # 2. 跳过所有 HTML 过滤规则（元素隐藏 / 扩展 CSS / CSS 注入 /
        #    scriptlet / HTML 过滤）。DNS 层看不到 DOM/CSS/脚本，这类规则
        #    永远不可能命中；正常入口（load_rules_from_*）已在解析前用
        #    is_html_filter_rule 预过滤，这里作为直接构造 FilterRule 时的纵深防御。
        if is_html_filter_rule(text):
            self._skip = True
            return

        # 3. 分离 $modifiers 并验证
        #
        # 自由正则 /regex/ 必须先整体识别：正则里的 `$` 是行尾锚点，不是修饰符。
        # 早期实现无条件 rsplit("$", 1)，导致 `/^ads\.example\.com$/` 被切成
        # 正则 `/^ads\.example\.com` + 修饰符 `/` → 判为未知修饰符 → 整条丢弃。
        modifiers_str = None
        _regex_parts = _free_regex_parts(text)
        if _regex_parts is not None:
            text, modifiers_str = _regex_parts
        elif "$" in text:
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

            # dnsrewrite：**当前整条跳过**（不再解析）
            # 解析出来的 rewrite 值没有任何 DNS 前端消费，实际行为会退化成
            # "整域 NXDOMAIN"——把本该返回 1.2.3.4 / REFUSED / 空应答的域名
            # 直接拦死。整条跳过前，先把它记成跳过原因便于排障。
            for mod in modifiers_str.split(','):
                if mod.strip().startswith('dnsrewrite'):
                    self._skip = True
                    return

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
            if not self.is_exception:
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
            # 防 ReDoS：拒绝可能灾难性回溯的自由正则（规则列表可能来自远程，
            # 客户端可用匹配域名触发回溯造成 CPU 放大），见 _is_redos_prone
            if _is_redos_prone(regex_text):
                logger.warning(
                    "过滤规则：拒绝疑似灾难性回溯（ReDoS）的 /regex/ 规则: %s",
                    regex_text[:120],
                )
                self._skip = True
                return
            try:
                self.pattern = re.compile(regex_text, re.IGNORECASE)
                self.is_free_regex = True
                self.is_regex = True
            except re.error:
                self._skip = True
            return

        # 9. hosts 格式: 0.0.0.0 domain / 127.0.0.1 domain / ::1 domain
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+:+[0-9a-fA-F:]*|0\.0\.0\.0)\s+(\S+)$',
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

    def _set_anchor(self):
        """提取该通配符/正则规则的「匹配必要条件」锚点。

        旧实现里 pattern 规则只能在 `DomainIndex.match` 中线性跑正则：hululu
        的 550 条让每次**未命中**多花约 213µs。这里从规则文本提取保守的必要
        条件，交给 DomainIndex 分组索引 + 预筛，使被排除的规则根本不进正则
        引擎。

        提取原则：只提取「匹配的必要条件」——宁可漏提取（退回线性），也不能
        错提（错提会让本该命中的规则漏掉）：
          suffix   —— 匹配的域名必须以它结尾（`||…tail^`、`tail|`）
          sld      —— `||x.*`：域名倒数第二段必须是 x
          prefix   —— `|head`：匹配的域名必须以它开头
          contains —— 通配符两侧剩余的字面量必须作为子串出现在域名里
        """
        raw = self.raw.strip()
        while raw.startswith("@@"):
            raw = raw[2:]
        raw = raw.strip()
        if not raw:
            return
        # 自由正则 /regex/：无法安全提取字面锚点 → 保持线性
        if raw.startswith("/") and raw.endswith("/"):
            return

        body = raw
        double_bar = body.startswith("||")         # 域名边界锚定（可匹配子域）
        anchored_start = body.startswith("|")      # | 或 ||
        end_anchored = body.endswith("|")          # 结尾锚定
        if anchored_start:
            body = body[2:] if double_bar else body[1:]
        if end_anchored:
            body = body[:-1]
        body = body.rstrip("^").strip()
        if not body:
            return

        if "*" not in body:
            # 无通配：||domain（域名边界 + 子域）、|prefix（字符串开头）、
            # suffix|（域名结尾）
            if double_bar:
                # ||domain 匹配 domain 及其子域 → 域名必然以 domain 结尾
                self._anchor_suffix = body.lstrip(".")
            elif end_anchored:
                self._anchor_suffix = body.lstrip(".")
            elif anchored_start:
                self._anchor_prefix = body
            elif "." in body:
                # 理论上不进 pattern（简单域名规则应走 trie），兜底用 contains
                self._anchor_contains = body
            return

        # ||x.* —— SLD 通配（唯一 * 在末尾、x 不含点）
        if body.endswith(".*") and body.count("*") == 1:
            sld = body[:-2]
            if sld and "." not in sld and "*" not in sld:
                self._anchor_sld = sld
                return

        first = body.find("*")
        last = body.rfind("*")
        head = body[:first]        # 第一个 * 之前的字面量
        tail = body[last + 1:]     # 最后一个 * 之后的字面量

        if tail and "*" not in tail and "/" not in tail:
            if tail.startswith("."):
                # `*` 与尾部之间是标签边界（如 ad-*.aliyuncs.com）→ tail 是
                # 合法的「标签边界后缀」，可以作为分组 key
                self._anchor_suffix = tail.lstrip(".")
            elif "." in tail:
                # `*` 直接连着尾部字面量（如 tongji.*kuwo.cn 的 "kuwo.cn"）：
                # 域名以它结尾，但它可能落在某个标签中间（akuwo.cn），
                # 不能当分组 key，只能当 contains 预筛
                self._anchor_contains = tail
        if head and "*" not in head and "/" not in head:
            if "." in head:
                # 含点的字面头部必须作为子串出现在域名里
                self._anchor_contains = self._anchor_contains or head
            elif not double_bar and anchored_start and not self._anchor_suffix:
                # 只有单竖线 |head*（字符串开头锚定）才能用前缀锚点
                self._anchor_prefix = head
            else:
                # ||head*（域名边界语义）不要求域名以 head 开头（可匹配
                # sub.head…），但 head 必然作为子串出现
                self._anchor_contains = self._anchor_contains or head

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

    __slots__ = ('_trie', '_pattern_rules', '_count', '_free_regex_count',
                 '_pat_suffix', '_pat_sld', '_pat_prefix', '_pat_other')

    # 自由正则规则数达到上限时的告警只提示一次（类级共享）
    _warned_free_regex_full = False

    def __init__(self):
        # ★ Phase 1: 紧凑 Trie 替代 _by_domain Dict
        self._trie = _DomainTrie()
        # 全部通配符/正则规则（保持加载顺序；has_domain/domain_count 仍用它）
        self._pattern_rules: List[FilterRule] = []
        self._count = 0
        # /regex/ 自由正则规则计数（用于上限控制，防线性遍历放大）
        self._free_regex_count = 0
        # ★ pattern 规则分组索引：用「匹配必要条件」把线性遍历拆成 O(1) 分组
        #   _pat_suffix: 后缀锚点（域名后缀 → 规则），如 ||a*.b.com^ → "b.com"
        #   _pat_sld   : SLD 锚点（倒数第二段 → 规则），如 ||x.* → "x"
        #   _pat_prefix: 前缀锚点（|head 开头）
        #   _pat_other : 无法锚定（自由正则等），仍线性但数量少
        self._pat_suffix: Dict[str, List[FilterRule]] = {}
        self._pat_sld: Dict[str, List[FilterRule]] = {}
        self._pat_prefix: List[FilterRule] = []
        self._pat_other: List[FilterRule] = []

    def add_rule(self, rule: FilterRule, index_domain: Optional[str]):
        """
        向索引添加一条规则。
        
        ★ Phase 1: 简单规则 → Trie；复杂规则 → _pattern_rules
        """
        # 自由正则（/regex/）规则数量上限：防止海量正则规则放大 match() 的
        # 线性遍历（与静态 ReDoS 预检形成双重防护）
        if rule.is_free_regex:
            if self._free_regex_count >= MAX_FREE_REGEX_RULES:
                if not DomainIndex._warned_free_regex_full:
                    DomainIndex._warned_free_regex_full = True
                    logger.warning(
                        "过滤规则：自由正则规则数已达上限 %d，其余同类规则将被忽略",
                        MAX_FREE_REGEX_RULES,
                    )
                return
            self._free_regex_count += 1

        if index_domain and rule._simple_match:
            # 紧凑规则 → 存入 Trie
            if rule.is_exception:
                rt = _RT_ALLOW_SUBDOMAIN if rule._match_subdomains else _RT_ALLOW_EXACT
            elif rule.is_important:
                rt = _RT_IMPORTANT_SUBDOMAIN if rule._match_subdomains else _RT_IMPORTANT_EXACT
            else:
                rt = _RT_BLOCK_SUBDOMAIN if rule._match_subdomains else _RT_BLOCK_EXACT
            # raw 只给「重要规则」保留（数量少、排查时有用）。普通规则不存原文：
            # 54 万条规则每条多存 40 字符原文 ≈ 40MB，而匹配完全不需要它
            # （_MatchInfo.raw 已有 compact:block 这类可读兜底）。
            self._trie.add(
                index_domain, rt, rule.dnsrewrite,
                rule.raw if rule.is_important else "",
            )
        else:
            # 通配符 / 正则 / 前缀 / 后缀规则：保留 FilterRule，并按「匹配必要
            # 条件」挂到分组索引（后缀 / SLD / 前缀 / 其它），避免未命中时线性
            # 跑全部正则。
            rule._order = self._count
            self._pattern_rules.append(rule)
            if rule._anchor_suffix:
                self._pat_suffix.setdefault(rule._anchor_suffix, []).append(rule)
            elif rule._anchor_sld:
                self._pat_sld.setdefault(rule._anchor_sld, []).append(rule)
            elif rule._anchor_prefix:
                self._pat_prefix.append(rule)
            else:
                self._pat_other.append(rule)
        self._count += 1

    def match(self, domain: str) -> Optional[Tuple[object, str]]:
        """
        匹配域名，返回 (匹配对象, 匹配方式)。

        ★ Phase 1: 先查 Trie（紧凑匹配），未命中再查 pattern 规则（分组索引）
        """
        domain_lower = domain.lower().rstrip('.')

        # 1. Trie 紧凑匹配（覆盖 95% 以上规则）
        trie_result = self._trie.match(domain_lower)
        if trie_result is not None:
            return trie_result

        # 2. pattern 规则：按「匹配必要条件」分组定位，避免线性跑全部正则
        if not self._pattern_rules:
            return None
        rule = self._match_patterns(domain_lower)
        if rule is None:
            return None
        return rule, "模式匹配"

    def _match_patterns(self, domain: str) -> Optional[FilterRule]:
        """在 pattern 规则里找**序号最小**的命中项（等价于旧实现的列表顺序优先）。

        分组后每组内部仍按加载顺序排列，所以组内第一个命中就是该组最优；
        跨组再比较 `_order` 取最小，保证与「线性遍历 + 第一个命中即返回」
        完全等价。组内先用 contains/prefix 锚点做 C 级预筛，只有可能命中的
        规则才进正则引擎。
        """
        best: Optional[FilterRule] = None
        best_order = -1
        labels = domain.split('.')
        n = len(labels)

        # 1. 后缀锚点组：候选后缀（本域 + 各级父域，反转后即前缀）
        pat_suffix = self._pat_suffix
        if pat_suffix and n:
            acc = labels[-1]
            for i in range(n):
                if i:
                    acc = labels[n - i - 1] + '.' + acc
                rules = pat_suffix.get(acc)
                if not rules:
                    continue
                for r in rules:
                    if best is not None and r._order > best_order:
                        break
                    ac = r._anchor_contains
                    if ac and ac not in domain:
                        continue
                    try:
                        if r.matches(domain):
                            best = r
                            best_order = r._order
                            break
                    except Exception:
                        continue

        # 2. SLD 锚点组（||x.*）：域名倒数第二段
        pat_sld = self._pat_sld
        if pat_sld and n >= 2:
            rules = pat_sld.get(labels[-2])
            if rules:
                for r in rules:
                    if best is not None and r._order > best_order:
                        break
                    ac = r._anchor_contains
                    if ac and ac not in domain:
                        continue
                    try:
                        if r.matches(domain):
                            best = r
                            best_order = r._order
                            break
                    except Exception:
                        continue

        # 3. 前缀锚点组（|head）
        for r in self._pat_prefix:
            if best is not None and r._order > best_order:
                break
            if not domain.startswith(r._anchor_prefix):
                continue
            try:
                if r.matches(domain):
                    best = r
                    best_order = r._order
                    break
            except Exception:
                continue

        # 4. 其余（无法锚定：自由正则 / 无点通配等），线性 + contains 预筛
        for r in self._pat_other:
            if best is not None and r._order > best_order:
                break
            ac = r._anchor_contains
            if ac and ac not in domain:
                continue
            try:
                if r.matches(domain):
                    best = r
                    best_order = r._order
                    break
            except Exception:
                continue

        return best

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
        self._pat_suffix.clear()
        self._pat_sld.clear()
        self._pat_prefix.clear()
        self._pat_other.clear()
        self._count = 0
        self._free_regex_count = 0

    def finalize(self):
        """把域名索引的增量区归并进排序扁平表（加载结束后调用）。

        `_DomainTrie` 采用「增量 dict + 排序扁平表」两段式存储：add 只写
        dict（同域名按优先级合并），finalize 一次性归并并释放临时 dict。
        增量超过阈值时 trie 也会自动归并，所以即使漏调也不会无限涨内存。
        """
        self._trie.finalize()

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

    解析路径**跟随当前上游配置**（不额外走 bootstrap 明文）：
      * `iterative.enabled=true` 且没有加密上游（纯迭代模式，`upstream.enabled=false`）
        → 走迭代解析（根→TLD→权威），与用户查询同一条链路；
      * `upstream.enabled=true` → 走 `resolver_manager` 的上游调度
        （优选加密 DoH/DoT/DoQ，迭代按 `iterative.prefer` 参与首波/兜底）。
    规则下载只需要拿到 CDN 的 A/AAAA（响应内容另过 HTML/二进制校验），
    这里不做额外的隐私降级或旁路。
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
        self._filter_cache: Dict[str, Tuple[bool, str, float, bool, Optional[dict]]] = {}
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
        self._badfilter_lock: threading.Lock = threading.Lock()
        self._last_dnsrewrite: Optional[dict] = None
        # ===== 解析入口预过滤统计（不进内存的规则）=====
        # DNS 层只加载「域名拦截 / 放行」规则；HTML 过滤规则（元素隐藏 /
        # 扩展 CSS / CSS 注入 / scriptlet / HTML 过滤）与带 AdGuard DNS 文档
        # 未列出修饰符的规则（$third-party / $script / $redirect / $cookie …）
        # 在解析入口就丢弃，连 FilterRule 对象都不创建。
        # 这两个计数供日志与 /stats 观测"到底有多少规则被省掉了"。
        self._skipped_html_rules = 0
        self._skipped_modifier_rules = 0
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
        # HTML 过滤规则（元素隐藏 / scriptlet / HTML 过滤）不是域名规则
        if is_html_filter_rule(line):
            return None

        while line.startswith("@@"):
            line = line[2:]

        if "$" in line:
            line = line.rsplit("$", 1)[0]
        if not line:
            return None

        # hosts 格式
        hosts_match = re.match(
            r'^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+:+[0-9a-fA-F:]*|0\.0\.0\.0)\s+(\S+)$',
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

        # 说明：早期版本会把"纯域名拦截规则"再存一份到 _plain_domains（Set[str]）
        # 作为 check_domain 的快速路径。实测 54 万条规则时这第二份副本约 38MB，
        # 而 `_DomainTrie` 本身已能精确匹配（且 check_domain 里 trie 结果同样在
        # 白名单之后才生效），因此不再重复存储——过滤语义不变。

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

    def _finalize_indexes(self):
        """把域名索引的增量区归并进排序扁平表（释放加载期临时内存）。

        `_DomainTrie` 加载时先写增量 dict（同域名按优先级合并），加载结束再
        一次性归并成「反转键排序表」。因此每条加载路径结束时都要调用一次；
        原子重载的 pending 索引同样处理。
        """
        for index in (self._block_index, self._allow_index,
                      self._pending_block_index, self._pending_allow_index):
            if index is None:
                continue
            try:
                index.finalize()
            except Exception as e:
                logger.debug("域名索引 finalize 异常: %s", e)

    def _compile_rules(self, cleaned_text: str, source: str = "memory"):
        """
        编译清理后的规则文本为 FilterRule 对象并建立索引

        两阶段加载：先收集 $badfilter 目标，再索引剩余规则。

        ★ 解析入口预过滤（两阶段都生效）：HTML 过滤规则（元素隐藏 / 扩展 CSS /
        CSS 注入 / scriptlet / HTML 过滤）与带 AdGuard DNS 文档未列出修饰符的
        规则（$third-party / $script / $image / $redirect / $cookie / $csp …）
        在这里直接丢弃——**不构造 FilterRule 对象、不进 trie/pattern 索引、
        不参与匹配、不占内存**。DNS 层只能看到域名与查询类型，这些规则既不可
        评估也没有意义（浏览器/HTTP 级过滤）。文档要求：含未列出修饰符的规则
        必须忽略整条，以免把浏览器过滤列表套到 DNS 层产生误报。
        """
        count = 0
        skip_count = 0
        skipped_html = 0
        skipped_modifier = 0

        def _prefilter(line: str) -> int:
            """0 = 可能是 DNS 规则；1 = HTML 过滤规则；2 = 带非 DNS 修饰符"""
            if is_html_filter_rule(line):
                return 1
            if has_non_dns_modifier(line):
                return 2
            return 0

        # 第一阶段：收集 $badfilter 目标 pattern
        for line in cleaned_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if '$' not in line:
                continue
            if _prefilter(line):
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

            kind = _prefilter(line)
            if kind == 1:
                skipped_html += 1
                continue
            if kind == 2:
                skipped_modifier += 1
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

        self._skipped_html_rules += skipped_html
        self._skipped_modifier_rules += skipped_modifier

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
        if skipped_html or skipped_modifier:
            logger.info(
                "  %s: 跳过 %d 条非 DNS 规则（HTML 过滤 %d 条 / 非 DNS 修饰符 %d 条）"
                "——未建对象、未入索引",
                source, skipped_html + skipped_modifier, skipped_html, skipped_modifier,
            )

    def load_rules_from_text(self, text: str, source: str = "memory"):
        """
        从文本加载规则（完整流程：解析 → 编译）

        解析阶段（AdGuardRuleParser.parse）与编译阶段（_compile_rules）都会
        按 DNS 语法预过滤：HTML 过滤规则、带非 DNS 修饰符的规则一律丢弃，
        既不构造 FilterRule 也不进任何索引。这里把解析阶段的丢弃数并入统计，
        使 `stats["skipped_html_rules"] / ["skipped_modifier_rules"]` 反映
        **本地文件 + 内存文本**的完整口径。
        """
        try:
            cleaned_text, parse_res = self._parser.parse_to_text(text)
            self._skipped_html_rules += parse_res.skipped_html
            self._skipped_modifier_rules += parse_res.skipped_non_dns
            if parse_res.rules_count > 0:
                self._compile_rules(cleaned_text, source=source)
            if parse_res.title and not self._title:
                self._title = parse_res.title
            self._finalize_indexes()
            # 与文件/URL 路径一致：内存文本加载完也把空闲堆页还给内核
            _release_heap_to_os()
            if parse_res.skipped_html or parse_res.skipped_non_dns:
                logger.info(
                    "  %s: 解析阶段跳过 %d 条非 DNS 规则（HTML 过滤 %d 条 / "
                    "非 DNS 修饰符 %d 条）——未建对象、未入索引",
                    source,
                    parse_res.skipped_html + parse_res.skipped_non_dns,
                    parse_res.skipped_html, parse_res.skipped_non_dns,
                )
            return parse_res
        except ValueError as e:
            logger.error("解析 %s 失败: %s", source, e)
            return ParseResult()

    def load_rules_from_file(self, filepath: str) -> bool:
        """从文件加载规则（同步接口，仅用于没有事件循环的脚本/测试）

        真正的实现是 `load_rules_from_file_async`（与远程 URL 共用同一套
        字节直通 + 两遍扫描逻辑）。事件循环正在运行时无法同步等待协程，
        这里会给出告警并返回 False —— 那种上下文请改用
        `await engine.load_rules_from_file_async(path)`。
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # 不能直接用 asyncio.run()：它结束时会 set_event_loop(None)，
            # 破坏调用方随后 asyncio.get_event_loop() 的语义（3.12+ 会直接
            # RuntimeError）。这里自建 loop 且不设置 current loop。
            _loop = asyncio.new_event_loop()
            try:
                return _loop.run_until_complete(
                    self.load_rules_from_file_async(filepath))
            finally:
                _loop.close()
        logger.warning(
            "事件循环正在运行，无法同步加载规则文件 %s；"
            "请改用 await load_rules_from_file_async()", filepath)
        return False

    async def load_rules_from_file_async(self, filepath: str) -> bool:
        """从文件加载规则（异步、字节直通、带 mtime+size checksum 缓存）

        与远程 URL **完全同一套**解析/索引逻辑（`_process_rules_from_bytes`
        → 2MB 分块 → 两遍扫描 → 入口预过滤 → trie 索引），因此本地
        `rules_files:` 和 `rules_urls:` 的内存与 CPU 特征一致：

        - 不再 `read_text()` 生成整份 str，也不再经 `parse_to_text` 的
          StringIO 再复制一份（旧路径 38MB 文件峰值可达 2-3 份完整文本）；
        - 大文件按块解析，不会一次性 splitlines 卡住事件循环；
        - 加载完成后把空闲堆页归还内核（`_release_heap_to_os`）。

        返回值语义与旧实现一致：索引到至少 1 条规则才为 True。
        """
        path = Path(filepath)
        if not path.exists():
            logger.warning("规则文件不存在: %s", filepath)
            return False

        # 检查 checksum 缓存：mtime + size 未变则跳过重解析
        try:
            stat = path.stat()
            file_key = (stat.st_mtime, stat.st_size)
            if self._file_checksums.get(filepath) == file_key:
                logger.debug("Checksum 命中，跳过未变更文件: %s", filepath)
                return True
        except OSError:
            pass

        try:
            loop = asyncio.get_running_loop()
            data = await loop.run_in_executor(None, path.read_bytes)
        except Exception as e:
            logger.error("读取规则文件 %s 失败: %s", filepath, e)
            return False

        try:
            if not self._title:
                # 旧路径由 parse() 从 "! Title:" 提取标题，这里只看头部
                # （标题永远在最前面几行），维持原有行为
                self._title = self._parser._extract_title(
                    self._head_text(data, 65_536)
                )
            ok = await self._process_rules_from_bytes(
                data, filepath, kind="file")
        except Exception as e:
            logger.error("解析规则文件 %s 失败: %s", filepath, e)
            return False
        finally:
            del data

        # 更新 checksum 缓存（与旧实现一致：读取成功即缓存，即使 0 条规则，
        # 这样同一份没变的文件不会被反复重解析）
        try:
            stat = path.stat()
            self._file_checksums[filepath] = (stat.st_mtime, stat.st_size)
        except OSError:
            pass
        logger.debug("规则文件加载完成并缓存 checksum: %s (rules=%s)",
                     filepath, ok)
        # 与远程 URL 路径一致：单个来源加载完成即归还空闲堆页
        _release_heap_to_os()
        return ok

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

    async def _decode_utf8_incremental(self, data: bytes, step: int = 2_000_000) -> str:
        """把大块 bytes 增量解码成 str，并按块让出事件循环

        为什么不用 `data.decode("utf-8", errors="replace")` 一次到位：
        规则文件 20-40MB，一次性解码是数秒级的纯 C 操作，持 GIL 不释放，
        事件循环线程被完全饿死 —— 加载期间进程内的 DNS 服务一个查询都处理不了
        （实测下载完成瞬间有 7.5s 停顿）。
        增量解码器（codecs.IncrementalDecoder）能正确处理跨块的多字节字符，
        每块之间 await sleep(0) 让事件循环处理在飞的 DNS 查询/上游响应。
        """
        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        total = len(data)
        parts: List[str] = []
        pos = 0
        while pos < total:
            end = min(pos + step, total)
            parts.append(dec.decode(data[pos:end]))
            pos = end
            await asyncio.sleep(0)
        parts.append(dec.decode(b"", True))
        return "".join(parts)

    @staticmethod
    def _head_text(data, limit: int = 262_144) -> str:
        """只解码头部一小段（HTML 检测用）

        旧实现为了看前 100 行，先把整份文本 decode 成 str——在字节直通路径
        上这一份 38MB 级副本纯属浪费，而且会把 RSS 高水位顶上去。
        """
        head = data[:limit]
        if isinstance(head, (bytes, bytearray, memoryview)):
            return bytes(head).decode("utf-8", "replace")
        return head

    async def _process_rules_from_bytes(self, data, url: str,
                                        kind: str = "url") -> bool:
        """字节直通：直接从原始字节解析并索引，不生成整份 str。

        为什么（2026-11）：远程大列表（hagezi tif 38MB / 185 万行）原先走
        `bytes → 整份 str → 分块 splitlines`，加载期同时驻留「下载字节」+
        「整份 str」+「join 出来的 str」三份完整文本。实测加载峰值比稳态高
        ~93MB，而 Linux 的 glibc / mimalloc 在释放后不归还高水位——同一份
        规则集在 Windows 上看起来正常，Ubuntu 上 RSS 却常年高出约 100MB。
        这里改成按 2MB 块解码 + 索引，峰值只多一个块。

        HTML 检测仍在写入索引之前做（只看头部，足以识别 CDN 错误页）；
        二进制控制字符检测在 `_process_rules_from_text` 第 1 遍的分块里做。
        """
        if not data:
            return False
        if self._parser._looks_like_html(self._head_text(data)):
            logger.error("规则来源 %s 内容包含 HTML，跳过", url)
            return False
        return await self._process_rules_from_text(data, url, kind=kind)

    async def _process_rules_from_text(self, text, url: str,
                                       kind: str = "url") -> bool:
        """
        两遍解析全文规则并索引（使用 ThreadPoolExecutor 多线程并行）。
        第 1 遍：收集 $badfilter 目标（确保顺序无关）
        第 2 遍：索引规则，跳过被 badfilter 禁用的
        调用方须确保内容已通过 HTML 检测；二进制字符检测在下面第 1 遍
        **分块**里做（发现即中止，此时尚未写入索引，中止是安全的）。

        ★ 与 `_compile_rules` 一致：HTML 过滤规则与带非 DNS 修饰符的规则在
        两遍扫描的入口就被丢弃（不构造 FilterRule、不入索引、不参与匹配）。
        远程列表（EasyList 之类）里这类规则占比可能很高，提前丢弃既省内存
        也省掉每行的正则编译成本。

        ★ `text` 允许是 `str`，也允许是 `bytes` / `bytearray`（字节直通）。
        远程列表 38MB 级时，若先整份 `bytes → str` 再分块 `"".join(parts)`
        复制，加载期会同时驻留 2-3 份完整文本，实测 hagezi tif（185 万行）
        峰值比稳态高 ~93MB；而 Linux 的 glibc / mimalloc 在释放后不归还
        高水位，进程 RSS 就永久高出这一截（Windows 堆会归还，所以那边看不出）。
        字节直通只按块解码，峰值只多一个 2MB 块。
        """
        loop = asyncio.get_running_loop()
        # **分块取行**（2026-10-30）：一次性 `text.splitlines()` 对 100-200 万行
        # 是 7-8s 的纯 C 操作（实测 hagezi tif 185 万行 = 7.81s），而 CPython 的
        # C 字符串操作在释放 GIL 前不可中断——即使丢进线程池，事件循环线程也会
        # 被饿死 7.8s，进程内的 DNS 服务一个查询都处理不了（用户看到的
        # 「开了 filter 后游戏加载不出/网络问题」正是这类停顿）。
        # 这里按 ~2MB 文本切块（对齐到换行边界），每块单独 splitlines：
        # 单次占用 GIL 约 0.4s，块与块之间 await sleep(0) 让事件循环处理在飞的
        # DNS 查询。总加载时间略增，但服务不再出现秒级「黑洞」。
        _text = text
        _text_len = len(_text)
        _CHUNK_CHARS = 2_000_000
        # 字节直通：`_text` 可能是 bytes/bytearray，块内再解码
        _is_bytes = isinstance(_text, (bytes, bytearray))
        _NL = b"\n" if _is_bytes else "\n"
        # 已扫描行数（二进制字符报错时换算行号用）
        _lines_seen = 0
        # 本次列表收集到的 $badfilter 目标（校验通过后才合并进全局集合）
        _local_badfilters: Set[str] = set()

        def _take_chunk(pos: int):
            """切出下一块并 splitlines，返回 (lines, chunk_text, next_pos)

            边界处理：优先在块内**最后一个换行符**处切开，保证不把一行规则
            劈成两半。若块内没有换行（某条规则长度超过 _CHUNK_CHARS，理论上
            可能出现在畸形/被拼接的列表里），则**向后找该行的换行符**而不是
            硬切——硬切会让这一行变成两条无效规则（解析失败、规则丢失）。

            `\\n`（0x0A）不会出现在 UTF-8 多字节序列内部，所以按字节切块
            永远劈不开多字节字符。
            """
            end = min(pos + _CHUNK_CHARS, _text_len)
            if end < _text_len:
                nl = _text.rfind(_NL, pos, end)
                if nl > pos:
                    end = nl + 1
                else:
                    # 块内无换行：扩大到下一个换行（找不到就取到文本末尾）
                    nxt = _text.find(_NL, end)
                    end = (_text_len if nxt < 0 else nxt + 1)
            _chunk = _text[pos:end]
            if _is_bytes:
                _chunk = _chunk.decode("utf-8", "replace")
            return _chunk.splitlines(), _chunk, end

        def _check_binary(chunk_text: str, lines_before: int):
            """检测单个分块里的二进制控制字符，返回错误描述或 None

            语义与 `AdGuardRuleParser._has_binary_chars` 完全一致（同一个 C
            正则、同一批控制字符），只是改为**逐块**扫描：全文一次性检测需要
            先有整份 str，而字节直通路径不能为了检测再复制一份完整文本。
            """
            m = AdGuardRuleParser._BINARY_CTRL_RE.search(chunk_text)
            if m is None:
                return None
            pos = m.start()
            line_no = lines_before + chunk_text.count("\n", 0, pos) + 1
            col = pos - (chunk_text.rfind("\n", 0, pos) + 1)
            return (
                f"line {line_no}: character {col}: likely binary character "
                f"'\\x{ord(m.group()):02x}'"
            )

        if _text_len == 0:
            return False

        # ===== 第 1 遍：收集 $badfilter 目标（确保顺序无关）=====
        def collect_badfilters(chunk_lines):
            """扫描一个分块，收集 $badfilter 目标 pattern"""
            for raw_line in chunk_lines:
                # 快速跳过：不含 $ 的行不可能有 badfilter
                if "$" not in raw_line:
                    continue
                stripped = raw_line.rstrip("\r").strip()
                if not stripped:
                    continue
                # 非 DNS 规则不可能贡献 badfilter（HTML 过滤 / 浏览器级修饰符）
                if is_html_filter_rule(stripped) or has_non_dns_modifier(stripped):
                    continue
                cleaned = AdGuardRuleParser._clean_rule_line(stripped)
                if cleaned is None:
                    continue
                rule = FilterRule(cleaned)
                if rule.is_badfilter:
                    target = self._extract_badfilter_target(cleaned)
                    if target:
                        # 先收进本次加载的**局部**集合，整份列表通过校验后才
                        # 合并进全局：否则一个中途被判为二进制垃圾的列表会把
                        # 半截 badfilter 留在全局集合里，误伤随后加载的列表。
                        _local_badfilters.add(target)

        # 单 worker 串行：$badfilter 收集与索引都必须保持"按文件顺序"，且
        # `_index_rule` 写 `_pending_*` 索引，串行写入与原实现语义完全一致。
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            _pos = 0
            while _pos < _text_len:
                try:
                    _chunk_lines, _chunk_text, _pos = await loop.run_in_executor(
                        pool, _take_chunk, _pos
                    )
                    # 二进制字符检测：与旧实现同样覆盖全部内容，只是按块做。
                    # 此时还在第 1 遍、尚未写入任何索引，中止是干净的。
                    _bin_err = await loop.run_in_executor(
                        pool, _check_binary, _chunk_text, _lines_seen
                    )
                    if _bin_err:
                        logger.error("规则来源 %s 包含二进制字符: %s",
                                     url, _bin_err)
                        return False
                    _lines_seen += len(_chunk_lines)
                    await loop.run_in_executor(pool, collect_badfilters, _chunk_lines)
                except (StopIteration, RuntimeError) as e:
                    # PEP 479：worker 内逸出的 StopIteration 会被 asyncio 转成
                    # RuntimeError("coroutine raised StopIteration")。$badfilter
                    # 收集失败只影响 badfilter 生效范围，不应让整次加载失败。
                    logger.warning("规则解析阶段异常（已忽略该块）: %r", e)
                    # 防死循环：异常发生在 _pos 推进之前，不前进会永远卡同一块
                    _pos += _CHUNK_CHARS
                await asyncio.sleep(0)

        # 第 1 遍通过（含二进制检测）→ 本次列表的 $badfilter 才对外生效
        if _local_badfilters:
            with self._badfilter_lock:
                self._badfilter_patterns.update(_local_badfilters)

        # ===== 第 2 遍：索引规则（_index_rule 自动处理 pending/active）=====
        _index_rule = self._index_rule
        _is_rule_badfiltered = self._is_rule_badfiltered
        FilterRule_ = FilterRule

        def _index_chunk(chunk_lines):
            """索引一个分块，返回 (规则数, 跳过HTML, 跳过修饰符)"""
            _total = 0
            _html = 0
            _mod = 0
            for raw_line in chunk_lines:
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                    continue
                # 解析入口预过滤：HTML 过滤规则 / 带非 DNS 修饰符的规则 → 直接丢弃
                if is_html_filter_rule(stripped):
                    _html += 1
                    continue
                if has_non_dns_modifier(stripped):
                    _mod += 1
                    continue
                rule = FilterRule_(stripped)
                if rule._skip or rule.is_badfilter:
                    continue
                # ★ BUGFIX: 使用 cleaned 行检查 badfilter（与第 1 阶段格式一致）
                cleaned = AdGuardRuleParser._clean_rule_line(stripped)
                if cleaned is not None and _is_rule_badfiltered(cleaned):
                    continue
                _index_rule(rule, stripped)
                _total += 1
            return _total, _html, _mod

        total_rules = 0
        skipped_html = 0
        skipped_modifier = 0
        # 单 worker：`_index_rule` 会写 `_pending_*` 索引，串行执行保持与
        # 原实现完全相同的写入顺序与语义（不引入并发写入的竞态）。
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ipool:
            _pos = 0
            while _pos < _text_len:
                _chunk_lines, _chunk_text, _pos = await loop.run_in_executor(
                    ipool, _take_chunk, _pos
                )
                if _chunk_lines:
                    _n, _h, _m = await loop.run_in_executor(
                        ipool, _index_chunk, _chunk_lines
                    )
                    total_rules += _n
                    skipped_html += _h
                    skipped_modifier += _m
                # 让出事件循环：处理此刻在飞的 DNS 查询/上游响应
                await asyncio.sleep(0)

        self._skipped_html_rules += skipped_html
        self._skipped_modifier_rules += skipped_modifier

        # 记录来源：本地文件 → _loaded_files，远程 URL → _loaded_urls
        # （配置热重载靠这两个列表判断 rules_files / rules_urls 是否变更）
        if self._pending_block_index is not None:
            self._pending_rule_count += total_rules
            if kind == "file":
                self._pending_loaded_files.append(url)
            else:
                self._pending_loaded_urls.append(url)
            total = self._pending_rule_count
        else:
            self._rule_count += total_rules
            if kind == "file":
                self._loaded_files.append(url)
            else:
                self._loaded_urls.append(url)
            total = self._rule_count

        logger.info("从 %s 加载了 %d 条规则 (总: %d)", url, total_rules, total)
        if skipped_html or skipped_modifier:
            logger.info(
                "  %s: 跳过 %d 条非 DNS 规则（HTML 过滤 %d 条 / 非 DNS 修饰符 %d 条）"
                "——未建对象、未入索引",
                url, skipped_html + skipped_modifier, skipped_html, skipped_modifier,
            )
        self._finalize_indexes()
        return total_rules > 0

    async def _download_url_parallel(self, url: str, num_chunks: int = 8,
                                      timeout: int = 60) -> Optional[bytearray]:
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
            # Range 分片必须拿到未压缩的原始字节，否则分片边界无意义
            # （aiohttp 默认会带 Accept-Encoding，CDN 可能回 br/gzip 导致
            #   "Can not decode content-encoding" 而整体失败）
            headers = {"User-Agent": "SecureDNS-Proxy/1.0",
                       "Accept-Encoding": "identity"}
            connector = None
            if self._resolver_manager is not None:
                resolver = _EncryptedDNSResolver(self._resolver_manager)
                connector = aiohttp.TCPConnector(resolver=resolver)

            # 修复：HEAD 探测与分片下载必须共用同一个 session/connector。
            # 原实现在 HEAD 的 `async with ClientSession(connector=...)` 退出时连带
            # 关闭了 connector（session 默认拥有传入的 connector），随后分片复用
            # 这个已关闭的 connector → "Session is closed"，分片下载整体失败。
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=headers,
                connector=connector,
            ) as session:
                # 1. HEAD 探测 Range 支持和文件大小
                async with session.head(
                    url, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
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
                    async with session.get(
                        url, headers=chunk_headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
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

                # 边拼接边释放分片：`chunks` 与 `result` 同时驻留会让峰值多出
                # 一整份文件（38MB 级）；最后也不再复制成 bytes —— 调用方按
                # 字节分块解析，bytearray 可以零拷贝切片。
                result = bytearray(file_size)
                offset = 0
                for i in range(len(tasks)):
                    data = chunks.pop(i, None)
                    if data is None:
                        return None
                    result[offset:offset + len(data)] = data
                    offset += len(data)

                logger.info("  并行下载完成: %d bytes (%d 片)", offset, len(tasks))
                return result

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
                # 并行下载成功 → 字节直通解析（不再 decode 整份文本）
                try:
                    return await self._process_rules_from_bytes(parallel_data, url)
                finally:
                    # 尽快丢掉整份字节，别把它留到协程结束
                    del parallel_data

            # 并行下载不可用 → 回退到全文 gzip 下载（同样字节直通解析）
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

                    # 字节直通：不再把整份内容 decode 成 str（见
                    # _process_rules_from_bytes 的内存说明）
                    try:
                        return await self._process_rules_from_bytes(raw, url)
                    finally:
                        del raw

        except asyncio.TimeoutError:
            logger.error("从 URL %s 加载规则超时 (80s)", url)
            return False
        except (RuntimeError, StopIteration) as e:
            # PEP 479：协程内逸出的 StopIteration 会变成 RuntimeError
            # （即日志里的 "coroutine raised StopIteration"）。这类异常多与
            # 自定义加密解析器路径相关，改用系统解析器重试一次，
            # 避免整条规则加载失败。
            logger.warning("从 URL %s 加载异常（%s: %s），改用系统解析器重试",
                           url, type(e).__name__, e)
            return await self._load_url_without_encrypted_resolver(url)
        except Exception as e:
            logger.error("从 URL %s 加载规则失败: %s", url, e)
            return False

    async def _load_url_without_encrypted_resolver(self, url: str) -> bool:
        """无自定义解析器的规则下载回退路径（使用系统 DNS）

        用于加密解析器路径偶发异常（如 coroutine raised StopIteration）时重试。
        """
        headers = {"User-Agent": "SecureDNS-Proxy/1.0",
                   "Accept-Encoding": "gzip, deflate"}
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=80),
                headers=headers,
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=80)
                ) as resp:
                    if resp.status != 200:
                        logger.error("获取 URL %s 失败: HTTP %d", url, resp.status)
                        return False
                    raw = await resp.read()
                    if len(raw) > DEFAULT_MAX_SIZE:
                        logger.error("URL %s 实际大小 %d 超过限制 %d",
                                     url, len(raw), DEFAULT_MAX_SIZE)
                        return False
                    # 字节直通：不再把整份内容 decode 成 str
                    try:
                        return await self._process_rules_from_bytes(raw, url)
                    finally:
                        del raw
        except Exception as e:
            logger.error("从 URL %s 加载规则失败（系统解析器回退）: %s", url, e)
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
        # 重载会**重建**整份索引：此时 checksum 命中跳过解析＝把该文件的规则
        # 直接丢掉（pending 里只剩远程 URL 的规则），因此重载路径必须清空
        # checksum 缓存强制重解析；badfilter 集合同理，否则旧列表的
        # $badfilter 会永久压制新列表里的同名规则。
        self._file_checksums.clear()
        with self._badfilter_lock:
            self._badfilter_patterns.clear()
        self._pending_block_index = DomainIndex()
        self._pending_allow_index = DomainIndex()
        self._pending_plain_domains = set()
        self._pending_rule_count = 0
        self._pending_loaded_files = []
        self._pending_loaded_urls = []
        # 预过滤统计按「本次加载」重新累计（旧值随旧规则集一起作废）
        self._skipped_html_rules = 0
        self._skipped_modifier_rules = 0
        self._loading = True

        # 3. 加载到 pending 状态
        try:
            for filepath in files:
                await self.load_rules_from_file_async(filepath)

            if urls:
                # ★ 串行加载（2026-11）：原实现 `asyncio.gather` 并发加载全部
                # URL，有两个副作用：
                #   1) 内存峰值叠加——每个 URL 都要整份下载字节（tif 38MB 级）
                #      与 2MB 分块同时驻留，Linux 下这笔高水位不回落；
                #   2) 结果不确定——`_badfilter_patterns` 是全局集合，URL A 的
                #      第 2 遍索引会看到 URL B 刚收集的 badfilter（反之亦然），
                #      同一份规则集每次加载的域名数不同（实测
                #      2160769 / 2160844 / 2160861 三次各异）。
                # 逐个加载后两者都消失：每个 URL 结束即释放自己的临时缓冲，
                # 且第 1 遍的 badfilter 收集与第 2 遍索引不再跨 URL 交错。
                # 总耗时不变（并发下载只是让两个大文件互相抢带宽）。
                for url in urls:
                    try:
                        await self.load_rules_from_url_async(url)
                    except Exception as e:
                        # 单个 URL 失败不影响其余列表（与原 gather 的
                        # return_exceptions=True 语义一致）
                        logger.error("从 %s 加载规则失败: %s", url, e)

            # 域名索引：把增量区归并进排序扁平表（释放临时 dict）
            self._finalize_indexes()

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
        # 再把 glibc 手里的空闲页还给内核，避免 RSS 停在加载峰值
        _release_heap_to_os()

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
        # 与 async_reload 一致：重载重建索引，checksum 缓存必须失效强制重解析，
        # 否则本地规则在重载后整体消失；badfilter 集合也随旧规则集作废。
        self._file_checksums.clear()
        with self._badfilter_lock:
            self._badfilter_patterns.clear()
        self._pending_block_index = DomainIndex()
        self._pending_allow_index = DomainIndex()
        self._pending_plain_domains = set()
        self._pending_rule_count = 0
        self._pending_loaded_files = []
        self._pending_loaded_urls = []
        # 预过滤统计按「本次加载」重新累计（旧值随旧规则集一起作废）
        self._skipped_html_rules = 0
        self._skipped_modifier_rules = 0
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

            # 域名索引：把增量区归并进排序扁平表（释放临时 dict）
            self._finalize_indexes()

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

        # 同步路径同样把空闲堆页还给内核（Linux glibc）
        _release_heap_to_os()

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
                self._filter_cache[domain] = (False, "custom_hosts_bypass", now, True, None)
                return False, "custom_hosts_bypass"

        # 1. 检查统一过滤结果缓存
        cached = self._filter_cache.get(domain)
        if cached is not None:
            result, reason, ts, priority, *dnsrewrite_extra = cached
            dnsrewrite_data = dnsrewrite_extra[0] if dnsrewrite_extra else None
            # blocked 结果永久有效（直到规则重载清空 _filter_cache）；
            # allowed 结果使用 _cache_ttl_allowed 检查；priority 条目永不超时
            if priority or result:
                if result:
                    logger.debug("FilterCache HIT(blocked): %s | %s (永久)", domain, reason[:60])
                else:
                    logger.debug("FilterCache HIT(allow/priority): %s", domain)
                # Restore dnsrewrite data for consumer
                if dnsrewrite_data and reason == "dnsrewrite":
                    self._last_dnsrewrite = dnsrewrite_data
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
                        self._filter_cache[domain] = (True, reason, now, False, self._last_dnsrewrite)
                    self._defer_trim()
                    return True, reason
                reason = f"重要规则拦截: {rule.raw}"
                if not self._cache_suspended:
                    self._filter_cache[domain] = (True, reason, now, False, None)
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
                self._filter_cache[domain] = (False, "", now, False, None)
            logger.debug("放行(白名单): %s | %s: %s", domain, method, rule.raw[:60])
            return False, ""

        # 3b.（已移除）早期在这里用 _plain_domains 做"纯域名快速 set 查找"。
        # 该集合是 trie 的第二份域名副本（54 万条 ≈38MB），而步骤 2 的
        # `_block_index.match()` 已通过紧凑 trie 得到同样的结果，且同样在
        # 白名单之后生效（步骤 4），故删除以省内存。过滤语义不变。

        # 4. 使用步骤 2 保存的 block 匹配结果（如有）
        if block_rule_result is not None:
            rule, method = block_rule_result
            if rule.dnsrewrite:
                self._last_dnsrewrite = rule.dnsrewrite
                reason = "dnsrewrite"
            else:
                reason = f"{method}: {rule.raw}"
            if not self._cache_suspended:
                self._filter_cache[domain] = (True, reason, now, False, rule.dnsrewrite if rule.dnsrewrite else None)
            self._defer_trim()
            logger.debug("拦截: %s | %s (%s)", domain, method, rule.raw[:80])
            return True, reason

        # 未匹配：缓存并放行
        if not self._cache_suspended and not self._loading:
            self._filter_cache[domain] = (False, "", now, False, None)
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
                if asyncio.iscoroutinefunction(self._restart_cb):
                    await self._restart_cb(bh)
                else:
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
            # 解析入口按 DNS 语法预过滤掉的规则（未建对象、未入索引、不占内存）
            "skipped_html_rules": self._skipped_html_rules,
            "skipped_modifier_rules": self._skipped_modifier_rules,
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

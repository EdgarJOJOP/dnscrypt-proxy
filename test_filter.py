"""测试过滤引擎 - 规则解析、编译、域名拦截"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from filter_engine import FilterEngine, FilterRule, AdGuardRuleParser, ParseResult

def test_parser():
    """测试 AdGuardRuleParser"""
    print("=" * 60)
    print("1. 测试 Parser")
    print("=" * 60)

    parser = AdGuardRuleParser()

    # 1.1 HTML 检测
    try:
        parser.parse("<html><body>hello</body></html>")
        print("  xx HTML 检测: 应该报错但未报")
    except ValueError as e:
        if "looks like the rules text contains an html" in str(e):
            print("  OK HTML 检测: 正确识别")
        else:
            print(f"  xx HTML 检测: 错误信息不对: {e}")

    # 1.2 二进制检测
    try:
        parser.parse("||example.com^\n\x00binary")
        print("  xx 二进制检测: 应该报错但未报")
    except ValueError as e:
        if "binary" in str(e).lower():
            print("  OK 二进制检测: 正确识别")
        else:
            print(f"  xx 二进制检测: {e}")

    # 1.3 Title 提取
    result = parser.parse("! Title: My Test List\n||doubleclick.net^\n! Comment\n||example.com^")
    if result.title == "My Test List":
        print(f"  OK Title 提取: '{result.title}'")
    else:
        print(f"  xx Title 提取: 得到 '{result.title}'")

    # 1.4 规则计数
    result = parser.parse("! comment\n# another comment\n||doubleclick.net^\n||example.com^")
    assert result.rules_count == 2, f"期望 2 条规则, 得到 {result.rules_count}"
    print(f"  OK 规则计数: {result.rules_count} 条")

    # 1.5 Hosts 格式
    result = parser.parse("0.0.0.0 ad.doubleclick.net\n127.0.0.1 ads.example.com\n1.2.3.4 tracker.com")
    assert result.rules_count == 3, f"期望 3 条 hosts 规则, 得到 {result.rules_count}"
    print(f"  OK Hosts 格式: 正确解析 {result.rules_count} 条")

    # 1.6 Cosmetic 跳过
    result = parser.parse("||doubleclick.net^\nexample.com##.ad-banner\n||ads.com^")
    assert result.rules_count == 2, f"期望 2 条规则 (cosmetic 忽略), 得到 {result.rules_count}"
    print(f"  OK Cosmetic 跳过: {result.rules_count} 条（cosmetic 已忽略）")

    # 1.7 Checksum 一致性
    r1 = parser.parse("||doubleclick.net^\n||example.com^")
    r2 = parser.parse("||doubleclick.net^\n||example.com^")
    assert r1.checksum == r2.checksum, "相同内容的 checksum 应一致"
    print(f"  OK Checksum 一致性: {r1.checksum:#x}")


def test_rule_parsing():
    """测试 FilterRule 解析和匹配"""
    print()
    print("=" * 60)
    print("2. 测试 FilterRule 解析")
    print("=" * 60)

    test_cases = [
        ("||doubleclick.net^", ["doubleclick.net", "ads.doubleclick.net"], ["notdoubleclick.net"]),
        ("||doubleclick.net^$third-party,script", ["doubleclick.net", "ads.doubleclick.net"], ["notdoubleclick.net"]),
        ("@@||example.com^", ["example.com"], []),  # 例外规则也匹配域名
        ("|http://phpad.cqnews.net/static_files/$script", ["phpad.cqnews.net"], ["other.com"]),
        ("||google-analytics.com/analytics.js", ["google-analytics.com", "www.google-analytics.com"], ["other.com"]),
        ("|https://d1.sina.com.cn^", ["d1.sina.com.cn"], ["d2.sina.com.cn"]),
        ("||kawinhome.com/js/mob/$script", ["kawinhome.com", "www.kawinhome.com"], ["other.com"]),
        ("||ndtzx.com", ["ndtzx.com", "www.ndtzx.com"], ["other.com"]),
        ("|http://www.55atv.com/js/count.js", ["www.55atv.com"], ["55atv.com"]),
        ("||adsmogo.net", ["adsmogo.net", "sub.adsmogo.net"], []),
        ("|http://211.149.225.23^", ["211.149.225.23"], ["211.149.225.24"]),
        ("||jeb.xnimg.cn", ["jeb.xnimg.cn", "img.jeb.xnimg.cn"], []),
        ("||souid.com/templets/js/sougg.js", ["souid.com", "www.souid.com"], []),
        ("shandian.biz##[height=\"600\"]", [], ["shandian.biz"]),  # cosmetic
        ("@@@@|https://zhihu-web-analytics.zhihu.com", ["zhihu-web-analytics.zhihu.com"], []),
        ("|http://*/path", [], ["any.com"]),  # 通配符域名
        ("||org/ad$image", [], ["python.org", "example.org"]),  # TLD 级应跳过
        ("||cn/tlgg/", [], ["example.cn", "baidu.cn"]),  # TLD 级应跳过
        # 新功能：| 指针语法
        ("|example", ["example.org", "example.com"], ["notexample.org"]),  # starts with
        ("ample.org|", ["example.org", "testample.org"], ["example.com"]),  # ends with
        ("|exact.com|", ["exact.com"], ["sub.exact.com"]),  # 双 | 精确匹配
        # 新功能：* 通配符
        ("||example.*", ["example.com", "example.org"], ["notexample.com"]),  # 任何 TLD
        ("||*.example.org", ["sub.example.org", "example.org"], ["notexample.org"]),  # *. 前缀
        # 新行为：普通域名不匹配子域名
        ("example.org", ["example.org"], ["sub.example.org"]),
        # 未知 modifier → 跳过
        ("||example.com^$unknownmod", [], ["example.com"]),
        # HTTP 级别修饰符规则 → DNS 应跳过（不拦截域名）
        ("||bing.com^$cookie=ABDEF", [], ["bing.com", "www.bing.com"]),
        ("||example.com^$redirect=noopjs", [], ["example.com"]),
        ("||example.com^$removeparam=p", [], ["example.com"]),
        ("||example.com^$replace=/bad/good/", [], ["example.com"]),
        ("||example.com^$removeheader=refresh", [], ["example.com"]),
        ("||example.com^$csp=frame-src 'none'", [], ["example.com"]),
        ("||example.com^$urltransform=/X/Y/", [], ["example.com"]),
        ("||example.com^$permissions=autoplay=()", [], ["example.com"]),
        ("||example.com^$referrerpolicy=unsafe-url", [], ["example.com"]),
        ("||example.com^$removeparam,important", ["example.com"], []),  # important 覆盖限制
    ]

    for rule_text, should_match, should_not_match in test_cases:
        rule = FilterRule(rule_text)
        if rule._skip:
            print(f"  [跳过] {rule_text[:60]}")
            continue

        label = "例外" if rule.is_exception else ("重要" if rule.is_important else "拦截")
        all_ok = True
        for d in should_match:
            if not rule.matches(d):
                print(f"  xx [{label}] '{rule_text[:50]}' 应匹配 {d} 但未匹配!")
                all_ok = False
        for d in should_not_match:
            if rule.matches(d):
                print(f"  xx [{label}] '{rule_text[:50]}' 不应匹配 {d} 但误匹配了!")
                all_ok = False
        if all_ok:
            print(f"  OK [{label}] {rule_text[:55]}")


def test_filter_engine():
    """用实际规则文件测试过滤引擎"""
    print()
    print("=" * 60)
    print("3. 加载规则文件并测试拦截效果")
    print("=" * 60)

    engine = FilterEngine()
    # 直接使用 D:\迅雷下载\all.txt
    rule_file = r"D:\迅雷下载\all.txt"

    if not os.path.exists(rule_file):
        print(f"  规则文件不存在: {rule_file}")
        return

    import time

    # 第一次加载
    t0 = time.time()
    engine.reload([rule_file])
    t1 = time.time()
    print(f"  首次加载: {t1-t0:.1f}s")
    print(f"  总规则数: {engine.stats['total_rules']}")
    print(f"  拦截规则: {len(engine._block_rules)}")
    print(f"  例外规则: {len(engine._exception_rules)}")
    print(f"  域名索引: {engine.stats['block_index_domains']}")

    # 第二次加载（同一引擎实例，checksum 缓存应生效）
    t0 = time.time()
    engine.reload([rule_file])
    t1 = time.time()
    print(f"  二次加载（checksum 缓存）: {t1-t0:.1f}s")
    if t1 - t0 < 1.0:
        print(f"  OK Checksum 缓存生效!")
    else:
        print(f"  缓存未生效，耗时较长")

    # 测试拦截
    print()
    print("  --- 域名拦截测试 ---")
    test_domains = [
        # 广告域名
        ("doubleclick.net", True),
        ("adsrvr.org", True),
        ("casalemedia.com", True),
        ("outbrain.com", True),
        ("criteo.com", True),
        ("criteo.net", True),
        ("pubmatic.com", True),
        ("appnexus.com", True),
        ("exelator.com", True),
        ("demdex.net", True),
        ("krxd.net", True),
        ("addthis.com", True),
        ("addtoany.com", True),
        # 中文站广告
        ("btrace.qq.com", True),
        ("tajs.qq.com", True),
        ("pingtas.qq.com", True),
        ("utrace.img.qq.com", False),
        ("qlogo.cn", False),
        ("wu.51.la", True),
        # 应放行的
        ("google.com", False),
        ("github.com", False),
        ("baidu.com", False),
        ("microsoft.com", False),
        ("python.org", False),
    ]

    hit = miss = fp = 0
    for domain, should_block in test_domains:
        blocked, reason = engine.check_domain(domain)
        if should_block and blocked:
            hit += 1
            print(f"  OK 拦截 {domain}")
        elif should_block and not blocked:
            miss += 1
            print(f"  xx 漏放 {domain}")
        elif not should_block and blocked:
            fp += 1
            print(f"  ? 误拦 {domain}: {reason[:60]}")

    total = hit + miss
    print(f"\n  结果: 正确拦截 {hit}/{total}  |  漏放 {miss}  |  误拦 {fp}")
    if miss > 0:
        print(f"  !! 漏放域名在规则文件中可能不存在")


def test_parser_in_engine():
    """测试引擎内部的 Parser 集成"""
    print()
    print("=" * 60)
    print("4. 测试引擎内部 Parser 集成")
    print("=" * 60)

    engine = FilterEngine()

    # 模拟规则文本
    text = """! Title: Test Filter
! 规则测试
# comment
||doubleclick.net^$third-party
||google-analytics.com/analytics.js
@@||example.com^
0.0.0.0 tracker.ads.net
127.0.0.1 ad.doubleclick.net
shandian.biz##.ad-banner
"""
    engine.load_rules_from_text(text, source="test")
    assert engine.stats["total_rules"] >= 4, f"规则不足: {engine.stats['total_rules']}"
    print(f"  OK 从文本加载: {engine.stats['total_rules']} 条规则")

    # 测试拦截
    blocked, reason = engine.check_domain("doubleclick.net")
    assert blocked, "doubleclick.net 应被拦截"
    print(f"  OK 拦截 doubleclick.net: {reason[:50]}")

    blocked, reason = engine.check_domain("example.com")
    if blocked:
        print(f"  xx example.com 不应被拦截 (例外规则)")
    else:
        print(f"  OK 例外规则生效: example.com 放行")

    blocked, reason = engine.check_domain("tracker.ads.net")
    assert blocked, "hosts 格式 tracker.ads.net 应被拦截"
    print(f"  OK Hosts 格式拦截: tracker.ads.net")

    print(f"  OK Title: {engine.title}")


if __name__ == "__main__":
    test_parser()
    test_rule_parsing()
    # 加载大文件测试太慢，默认跳过。用 --all 参数启用
    if "--all" in sys.argv:
        test_filter_engine()
    else:
        print()
        print("=" * 60)
        print("3. 跳过 all.txt 文件加载测试（使用 --all 参数启用）")
        print("=" * 60)
    test_parser_in_engine()

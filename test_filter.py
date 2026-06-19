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
    assert result.rules_count == 2, f"期望 2 条规则, 得到 {result.rules_count}"  # nosec B101
    print(f"  OK 规则计数: {result.rules_count} 条")

    # 1.5 Hosts 格式
    result = parser.parse("0.0.0.0 ad.doubleclick.net\n127.0.0.1 ads.example.com\n1.2.3.4 tracker.com")
    assert result.rules_count == 3, f"期望 3 条 hosts 规则, 得到 {result.rules_count}"  # nosec B101
    print(f"  OK Hosts 格式: 正确解析 {result.rules_count} 条")

    # 1.6 Cosmetic 跳过
    result = parser.parse("||doubleclick.net^\nexample.com##.ad-banner\n||ads.com^")
    assert result.rules_count == 2, f"期望 2 条规则 (cosmetic 忽略), 得到 {result.rules_count}"  # nosec B101
    print(f"  OK Cosmetic 跳过: {result.rules_count} 条（cosmetic 已忽略）")

    # 1.7 Checksum 一致性
    r1 = parser.parse("||doubleclick.net^\n||example.com^")
    r2 = parser.parse("||doubleclick.net^\n||example.com^")
    assert r1.checksum == r2.checksum, "相同内容的 checksum 应一致"  # nosec B101
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
        ("||mcdn.bilivideo.cn^", ["mcdn.bilivideo.cn"], ["other.com"]),
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
    print(f"  拦截规则: {engine._block_index.count}")
    print(f"  例外规则: {engine._allow_index.count}")
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
    assert engine.stats["total_rules"] >= 4, f"规则不足: {engine.stats['total_rules']}"  # nosec B101
    print(f"  OK 从文本加载: {engine.stats['total_rules']} 条规则")

    # 测试拦截
    blocked, reason = engine.check_domain("doubleclick.net")
    assert blocked, "doubleclick.net 应被拦截"  # nosec B101
    print(f"  OK 拦截 doubleclick.net: {reason[:50]}")

    blocked, reason = engine.check_domain("example.com")
    if blocked:
        print(f"  xx example.com 不应被拦截 (例外规则)")
    else:
        print(f"  OK 例外规则生效: example.com 放行")

    blocked, reason = engine.check_domain("tracker.ads.net")
    assert blocked, "hosts 格式 tracker.ads.net 应被拦截"  # nosec B101
    print(f"  OK Hosts 格式拦截: tracker.ads.net")

    print(f"  OK Title: {engine.title}")



# ===== Test 5: 规则优先级 =====
def test_rule_priority():
    """测试 AdGuard 规则优先级：$important > 白名单 > 普通拦截"""
    print()
    print("=" * 60)
    print("5. 测试规则优先级")
    print("=" * 60)
    from filter_engine import FilterEngine

    ok = total = 0

    # 5.1 白名单覆盖普通拦截
    e1 = FilterEngine()
    e1.load_rules_from_text("||ads.com^\n@@||ads.com^", source="prio1")
    blocked, _ = e1.check_domain("ads.com")
    total += 1
    if not blocked:
        ok += 1; print("  OK [5.1] 白名单覆盖普通拦截: ads.com 放行")
    else:
        print("  xx [5.1] 白名单应覆盖普通拦截")

    # 5.2 重要规则覆盖白名单
    e2 = FilterEngine()
    e2.load_rules_from_text("||ads.com^$important\n@@||ads.com^", source="prio2")
    blocked, _ = e2.check_domain("ads.com")
    total += 1
    if blocked:
        ok += 1; print("  OK [5.2] 重要规则覆盖白名单: ads.com 被拦截")
    else:
        print("  xx [5.2] 重要规则应覆盖白名单")

    # 5.3 子域名白名单精确匹配
    e3 = FilterEngine()
    e3.load_rules_from_text("||example.com^\n@@||sub.example.com^", source="prio3")
    checks = [("sub.example.com", False), ("example.com", True)]
    for d, expect in checks:
        blocked, _ = e3.check_domain(d)
        total += 1
        if blocked == expect:
            ok += 1
        else:
            print(f"  xx [5.3] {d}: 期望{"拦截" if expect else "放行"}")
    if ok == total - len(checks) + ok:
        print("  OK [5.3] 子域名白名单精确匹配")

    # 5.4 混合多规则
    e4 = FilterEngine()
    e4.load_rules_from_text(
        "||blocked.com^\n"
        "@@||allowed.com^\n"
        "||also-blocked.com^\n"
        "||important.com^$important\n"
        "@@||important.com^",
        source="prio4"
    )
    checks = [("blocked.com", True), ("allowed.com", False),
              ("also-blocked.com", True), ("important.com", True)]
    for d, expect in checks:
        blocked, _ = e4.check_domain(d)
        total += 1
        if blocked == expect:
            ok += 1
        else:
            print(f"  xx [5.4] {d}: 期望{"拦截" if expect else "放行"}")
    if ok == total - 4 + ok:
        print("  OK [5.4] 混合多规则优先级正确")

    print(f"  => 优先级测试: {ok}/{total} 通过")


# ===== Test 6: $badfilter =====
def test_badfilter():
    """测试 $badfilter 修饰符"""
    print()
    print("=" * 60)
    print("6. 测试 $badfilter 修饰符")
    print("=" * 60)
    from filter_engine import FilterEngine

    ok = total = 0

    # 6.1 badfilter 禁用同一文件规则
    e1 = FilterEngine()
    e1.load_rules_from_text("||ads.com^\n||ads.com^$badfilter", source="bf1")
    total += 1
    blocked, _ = e1.check_domain("ads.com")
    if not blocked:
        ok += 1; print("  OK [6.1] badfilter 禁用 ||ads.com^")
    else:
        print("  xx [6.1] badfilter 未生效")

    # 6.2 badfilter 规则自身不被索引
    total += 1
    if e1.stats['total_rules'] == 0:
        ok += 1; print("  OK [6.2] badfilter 规则自身未进入索引")
    else:
        print(f"  xx [6.2] 仍有 {e1.stats['total_rules']} 条规则")

    # 6.3 badfilter 禁用例外规则
    e2 = FilterEngine()
    e2.load_rules_from_text("||ads.com^\n@@||ads.com^$badfilter", source="bf2")
    total += 1
    blocked, _ = e2.check_domain("ads.com")
    if blocked:
        ok += 1; print("  OK [6.3] badfilter 禁用例外: ads.com 被拦截")
    else:
        print("  xx [6.3] badfilter 应禁用例外规则")

    # 6.4 badfilter 精确禁用，不影响其他
    e3 = FilterEngine()
    e3.load_rules_from_text(
        "||blocked.com^\n||ads.com^\n||ads.com^$badfilter\n||also-blocked.com^",
        source="bf3"
    )
    for d, expect in [("blocked.com", True), ("ads.com", False), ("also-blocked.com", True)]:
        total += 1
        blocked, _ = e3.check_domain(d)
        if blocked == expect:
            ok += 1
        else:
            print(f"  xx [6.4] {d}: 期望{"拦截" if expect else "放行"}")

    print(f"  => badfilter 测试: {ok}/{total} 通过")


# ===== Test 7: $dnsrewrite =====
def test_dnsrewrite():
    """测试 $dnsrewrite 修饰符"""
    print()
    print("=" * 60)
    print("7. 测试 $dnsrewrite 修饰符")
    print("=" * 60)
    from filter_engine import FilterRule, FilterEngine

    ok = total = 0

    # 7.1 解析格式
    cases = [
        ("||t.com^$dnsrewrite", "noerror", None),
        ("||t.com^$dnsrewrite=1.2.3.4", "dnsrewrite", "A:1.2.3.4"),
        ("||t.com^$dnsrewrite=::1", "dnsrewrite", "AAAA:::1"),
        ("||t.com^$dnsrewrite=host:my.d", "dnsrewrite", "CNAME:my.d"),
        ("||t.com^$dnsrewrite=REFUSED", "dnsrewrite", "rc:REFUSED"),
        ("||t.com^$dnsrewrite=NOERROR;A;5.6.7.8", "dnsrewrite", "A:5.6.7.8"),
    ]
    for rule_text, exp_action, exp_detail in cases:
        rule = FilterRule(rule_text)
        total += 1
        if rule._skip or rule.dnsrewrite is None:
            print(f"  xx [7.1] 解析失败: {rule_text[:40]}")
        elif rule.dnsrewrite.get('action') == exp_action:
            ok += 1
        else:
            print(f"  xx [7.1] {rule_text[:40]}: action={rule.dnsrewrite.get('action')}, 期望={exp_action}")

    # 7.2 集成: check_domain + get_last_dnsrewrite
    e1 = FilterEngine()
    e1.load_rules_from_text("||rewrite.com^$dnsrewrite=10.0.0.1", source="dr1")
    total += 1
    blocked, reason = e1.check_domain("rewrite.com")
    d = e1.get_last_dnsrewrite()
    if blocked and reason == "dnsrewrite" and d and d.get('value') == '10.0.0.1':
        ok += 1; print("  OK [7.2] dnsrewrite 集成: blocked + reason + data 正确")
    else:
        print(f"  xx [7.2] 集成错误: blocked={blocked}, reason={reason}, data={d}")

    # 7.3 白名单可覆盖 dnsrewrite
    e2 = FilterEngine()
    e2.load_rules_from_text("||r.com^$dnsrewrite=10.0.0.1\n@@||r.com^", source="dr2")
    total += 1
    blocked, _ = e2.check_domain("r.com")
    if not blocked:
        ok += 1; print("  OK [7.3] 白名单覆盖 dnsrewrite")
    else:
        print("  xx [7.3] 白名单应覆盖 dnsrewrite")

    print(f"  => dnsrewrite 测试: {ok}/{total} 通过")


# ===== Test 8: 原子重载 =====
def test_atomic_reload():
    """测试原子重载"""
    print()
    print("=" * 60)
    print("8. 测试原子重载")
    print("=" * 60)
    from filter_engine import FilterEngine
    import tempfile, os

    ok = total = 0

    # 8.1 reload 基本功能
    e1 = FilterEngine()
    e1.load_rules_from_text("||old.com^", source="old")
    f1 = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    f1.write("||new.com^\n")
    f1.close()
    f2 = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    f2.write("! empty\n")
    f2.close()

    try:
        e1.reload([f1.name])
        total += 2
        ok_new = e1.check_domain("new.com")[0]
        ok_old = not e1.check_domain("old.com")[0]
        if ok_new: ok += 1
        if ok_old: ok += 1

        # 8.2 空文件不替换旧规则
        e1.reload([f2.name])
        total += 1
        if e1.check_domain("new.com")[0]:
            ok += 1
    finally:
        os.unlink(f1.name)
        os.unlink(f2.name)

    print(f"  => 原子重载测试: {ok}/{total} 通过")


# ===== Test 9: 边界条件 =====
def test_boundary():
    """测试边界条件：FQDN、大小写、限制修饰符跳过"""
    print()
    print("=" * 60)
    print("9. 测试边界条件")
    print("=" * 60)
    from filter_engine import FilterEngine

    ok = total = 0

    # 9.1 FQDN 尾点
    e1 = FilterEngine()
    e1.load_rules_from_text("||example.net^\n0.0.0.0 tracker.net", source="b1")
    for d, exp in [("example.net", True), ("example.net.", True),
                   ("tracker.net", True), ("tracker.net.", True)]:
        total += 1
        if e1.check_domain(d)[0] == exp:
            ok += 1
        else:
            print(f"  xx [9.1] FQDN: {d}")
    if ok >= total - 4 + 4:
        print("  OK [9.1] FQDN 尾点匹配正确")

    # 9.2 大小写不敏感
    e2 = FilterEngine()
    e2.load_rules_from_text("||Example.COM^", source="b2")
    for d in ["example.com", "EXAMPLE.COM", "Example.Com"]:
        total += 1
        if e2.check_domain(d)[0]:
            ok += 1
        else:
            print(f"  xx [9.2] 大小写: {d}")
    if ok >= total - 3 + 3:
        print("  OK [9.2] 大小写不敏感")

    # 9.3 白名单大小写不敏感
    e3 = FilterEngine()
    e3.load_rules_from_text("||Blocked.COM^\n@@||blocked.com^", source="b3")
    for d in ["BLOCKED.COM", "blocked.com"]:
        total += 1
        if not e3.check_domain(d)[0]:
            ok += 1
        else:
            print(f"  xx [9.3] 白名单大小写: {d}")

    # 9.4 $domain 限制规则应跳过
    e4 = FilterEngine()
    e4.load_rules_from_text("||skip.com^$domain=somewhere.com\n||normal.com^", source="b4")
    total += 2
    if not e4.check_domain("skip.com")[0]: ok += 1
    else: print("  xx [9.4] $domain 限制规则未跳过")
    if e4.check_domain("normal.com")[0]: ok += 1
    else: print("  xx [9.4] 普通规则被误跳过")

    # 9.5 $app / $client 限制规则应跳过
    e5 = FilterEngine()
    e5.load_rules_from_text(
        "||skip-app.com^$app=X\n||skip-client.com^$client=1.2.3.4\n||ok.com^",
        source="b5"
    )
    total += 3
    if not e5.check_domain("skip-app.com")[0]: ok += 1
    else: print("  xx [9.5] $app 限制未跳过")
    if not e5.check_domain("skip-client.com")[0]: ok += 1
    else: print("  xx [9.5] $client 限制未跳过")
    if e5.check_domain("ok.com")[0]: ok += 1
    else: print("  xx [9.5] 普通规则被误跳过")

    print(f"  => 边界条件测试: {ok}/{total} 通过")


# ===== 更新 main 入口 =====

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
    test_rule_priority()
    test_badfilter()
    test_dnsrewrite()
    test_atomic_reload()
    test_boundary()

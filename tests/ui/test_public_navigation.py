"""Public navigation contract tests for web/home and web/compare.

Scope and honesty notes:
  * Python parses the shipped HTML/CSS/JS as text. Nothing here renders a page,
    follows a link, or verifies real browser, assistive-technology, visual or
    performance behaviour (all UNKNOWN). There is no actual Browser.
  * Reset-control logic is executed by the installed Node against the real
    web/compare/app.js controller, but on the hand-written MOCK DOM / canvas /
    Object URL harness from test_image_compare.py. It is a mock, not a browser.
  * Relative route resolution is simulated with posixpath for the repository
    layout (web/home, web/compare) and for S3-style /home/ and /compare/ paths.
  * Standard library only; no network. If Node is missing the Node tests are
    SKIPPED (reported, not hidden).
"""

import posixpath
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import test_image_compare as tic  # noqa: E402  (module only; its TestCases are not re-exported)

REPO_ROOT = HERE.parents[1]
WEB = REPO_ROOT / "web"

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "source", "track", "wbr"}

PAGES = {
    "home": {"dir": WEB / "home", "other": "compare", "href": "../compare/index.html"},
    "compare": {"dir": WEB / "compare", "other": "home", "href": "../home/index.html"},
}
SIX_FILES = {"home/index.html", "home/styles.css", "home/app.js",
             "compare/index.html", "compare/styles.css", "compare/app.js"}

URL_ATTRS = ("href", "src", "action", "formaction", "poster", "data", "srcset",
             "xlink:href", "cite", "ping", "background", "manifest", "longdesc")

HOSTILE_HREFS = [
    "http://example.com/", "https://example.com/compare/index.html",
    "HTTP://EXAMPLE.COM", "javascript:alert(1)", "JaVaScRiPt:alert(1)",
    " javascript:alert(1)", "java\tscript:alert(1)", "java\nscript:alert(1)",
    "data:text/html,x", "file:///C:/x", "mailto:a@example.com", "ftp://example.com/",
    "//example.com/compare/index.html", "///compare/index.html",
    "\\\\example.com\\x", "..\\compare\\index.html", "../compare\\index.html",
    "/", "/compare/index.html", "/home/index.html", "/index.html",
    "../../compare/index.html", "../../../etc/passwd", "../compare/../compare/index.html",
    "../compare/index.html/..", "./../compare/index.html", ".././compare/index.html",
    "../compare/./index.html", "../compare//index.html",
    "../compare/", "../compare", "../compare/index.htm", "../compare/index.html/",
    "../compare/index.html?x=1", "../compare/index.html#main", "../compare/index.html#",
    "../Compare/index.html", "../compare/INDEX.HTML", "../compare/index.html ",
    " ../compare/index.html", "../compare/index.html\n", "../compare/index.html\t",
    "..%2fcompare%2findex.html", "%2e%2e/compare/index.html", "%2E%2E%2Fcompare/index.html",
    "../compare/%69ndex.html", "../compare/index%2ehtml", "..%5Ccompare%5Cindex.html",
    "%2f%2fexample.com", "&#46;&#46;/compare/index.html", "../compare/index.html%00",
    "../compare/index.html%0a", "..;/compare/index.html", "../home/index.html",
    "../compare/app.js", "../compare/styles.css", "app.js", "styles.css", "index.html",
    "#", "#top", "#main ", "# main", "#Main", "", "about:blank", "tel:123",
]


class Doc(HTMLParser):
    """Collect start tags in document order with their attributes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, {k: (v if v is not None else "") for k, v in attrs}))

    handle_startendtag = handle_starttag


def parse(source):
    d = Doc()
    d.feed(source)
    d.close()
    return d


def scan_page(source, page):
    """Return the list of navigation-contract problems found in an HTML source."""
    expected_other = PAGES[page]["href"]
    doc = parse(source)
    problems = []
    anchors = [a for t, a in doc.tags if t == "a"]
    hrefs = [a.get("href") for a in anchors]
    # Entity/escape forms decode to a valid href; the shipped source must be the literal text.
    raw = [m.group(1) for m in re.finditer(r'<a\b[^>]*?\bhref="([^"]*)"', source)]
    if raw != ["#main", expected_other]:
        problems.append("raw anchor hrefs %r" % (raw,))
    if hrefs != ["#main", expected_other]:
        problems.append("anchor hrefs %r != %r" % (hrefs, ["#main", expected_other]))
    first = next((t for t, _ in doc.tags if t in ("a", "button", "input")), None)
    first_attrs = next((a for t, a in doc.tags if t in ("a", "button", "input")), {})
    if first != "a" or first_attrs.get("href") != "#main" or "skip-link" not in first_attrs.get("class", "").split():
        problems.append("skip link is not the first interactive element")
    for t, a in doc.tags:
        if t in ("nav", "aside", "base", "form", "iframe", "frame", "object", "embed", "area"):
            problems.append("forbidden element <%s>" % t)
        for k in a:
            if k.lower().startswith("on"):
                problems.append("inline handler %s" % k)
        if t == "meta" and a.get("http-equiv", "").lower() == "refresh":
            problems.append("meta refresh")
        for attr in URL_ATTRS:
            if attr in a and t != "a":
                v = a[attr]
                if t == "link" and attr == "href" and v == "styles.css" and a.get("rel") == "stylesheet":
                    continue
                if t == "script" and attr == "src" and v == "app.js":
                    continue
                if t == "img" and attr == "src" and v == "":
                    continue
                problems.append("unexpected %s=%r on <%s>" % (attr, v, t))
    return problems


def href_allowed(page, href):
    """Exact-match allowlist: no normalisation, decoding or prefix matching."""
    return href in ("#main", PAGES[page]["href"])


def read(path):
    return Path(path).read_text(encoding="utf-8")


class PageCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = {p: read(PAGES[p]["dir"] / "index.html") for p in PAGES}
        cls.css = {p: read(PAGES[p]["dir"] / "styles.css") for p in PAGES}
        cls.js = {p: read(PAGES[p]["dir"] / "app.js") for p in PAGES}
        cls.doc = {p: parse(cls.src[p]) for p in PAGES}


class ExactNavigationTests(PageCase):
    def test_each_page_has_exactly_skip_then_one_route(self):
        for page, info in PAGES.items():
            with self.subTest(page=page):
                anchors = [a for t, a in self.doc[page].tags if t == "a"]
                self.assertEqual([a.get("href") for a in anchors], ["#main", info["href"]])
                self.assertEqual(sum(1 for a in anchors if a.get("href") == info["href"]), 1)
                self.assertEqual(sum(1 for a in anchors if a.get("href") == "#main"), 1)
                self.assertIn("skip-link", anchors[0].get("class", "").split())
                self.assertEqual(scan_page(self.src[page], page), [])

    def test_skip_link_is_first_interactive_element_and_target_exists(self):
        for page in PAGES:
            with self.subTest(page=page):
                interactive = [(t, a) for t, a in self.doc[page].tags if t in ("a", "button", "input", "select", "textarea")]
                self.assertEqual(interactive[0][0], "a")
                self.assertEqual(interactive[0][1]["href"], "#main")
                self.assertEqual(interactive[1][0], "a")
                ids = [a["id"] for _, a in self.doc[page].tags if "id" in a]
                self.assertEqual(ids.count("main"), 1)
                main = next(a for t, a in self.doc[page].tags if t == "main")
                self.assertEqual(main.get("id"), "main")
                self.assertEqual(main.get("tabindex"), "-1")

    def test_route_text_is_non_empty_native_link_without_script_navigation(self):
        for page, info in PAGES.items():
            with self.subTest(page=page):
                m = re.search(r'<a href="%s">([^<]+)</a>' % re.escape(info["href"]), self.src[page])
                self.assertIsNotNone(m)
                self.assertTrue(m.group(1).strip())
                for attr in ("target", "download", "ping", "rel"):
                    anchors = [a for t, a in self.doc[page].tags if t == "a"]
                    self.assertNotIn(attr, anchors[1])
                # navigation must not be replaced or supplemented by JavaScript
                self.assertNotIn(info["other"] + "/", self.js[page])
                self.assertNotIn("index.html", self.js[page])
                self.assertIsNone(re.search(r"\blocation\b|window\.open|\bhistory\b|\.click\s*\(|\.href\s*=", self.js[page]))
                self.assertNotIn(info["other"] + "/", self.css[page])

    def test_no_sidebar_or_nav_landmark(self):
        for page in PAGES:
            with self.subTest(page=page):
                tags = [t for t, _ in self.doc[page].tags]
                self.assertNotIn("nav", tags)
                self.assertNotIn("aside", tags)
                self.assertEqual(tags.count("header"), 1)
                self.assertEqual(tags.count("main"), 1)
                self.assertEqual(tags.count("footer"), 1)
                self.assertEqual(tags.count("h1"), 1)

    def test_positive_hrefs_pass_allowlist(self):
        self.assertTrue(href_allowed("home", "#main"))
        self.assertTrue(href_allowed("home", "../compare/index.html"))
        self.assertTrue(href_allowed("compare", "#main"))
        self.assertTrue(href_allowed("compare", "../home/index.html"))
        self.assertFalse(href_allowed("home", "../home/index.html"))
        self.assertFalse(href_allowed("compare", "../compare/index.html"))

    def test_hostile_hrefs_rejected_by_allowlist(self):
        for page in PAGES:
            for href in HOSTILE_HREFS:
                if href == PAGES[page]["href"]:
                    continue   # the one approved route for this page (hostile for the other page)
                with self.subTest(page=page, href=href):
                    self.assertFalse(href_allowed(page, href))

    def test_hostile_href_substituted_into_real_page_is_detected(self):
        for page, info in PAGES.items():
            marker = 'href="%s"' % info["href"]
            self.assertEqual(self.src[page].count(marker), 1)
            for href in HOSTILE_HREFS:
                if href == info["href"]:
                    continue
                with self.subTest(page=page, href=href):
                    safe = href.replace('"', "&quot;")
                    mutated = self.src[page].replace(marker, 'href="%s"' % safe)
                    self.assertNotEqual(scan_page(mutated, page), [])

    def test_multiplicity_ordering_and_extra_anchor_mutations_detected(self):
        for page, info in PAGES.items():
            src = self.src[page]
            route = re.search(r'<p class="header-link">.*?</p>', src, re.S).group(0)
            with self.subTest(page=page, mutation="duplicate"):
                self.assertNotEqual(scan_page(src.replace(route, route + route), page), [])
            with self.subTest(page=page, mutation="missing"):
                self.assertNotEqual(scan_page(src.replace(route, ""), page), [])
            with self.subTest(page=page, mutation="extra-anchor"):
                self.assertNotEqual(scan_page(src.replace(route, route + '<a href="#main">x</a>'), page), [])
            with self.subTest(page=page, mutation="route-before-skip"):
                skip = re.search(r'<a class="skip-link"[^>]*>[^<]*</a>', src).group(0)
                self.assertNotEqual(scan_page(src.replace(skip, "").replace("<body>", "<body>" + route + skip), page), [])
            with self.subTest(page=page, mutation="nav"):
                self.assertNotEqual(scan_page(src.replace(route, "<nav>" + route + "</nav>"), page), [])
            with self.subTest(page=page, mutation="base"):
                self.assertNotEqual(scan_page(src.replace("<title>", '<base href="/x/"><title>'), page), [])
            with self.subTest(page=page, mutation="inline-handler"):
                self.assertNotEqual(scan_page(src.replace(route, route.replace("<a ", '<a onclick="x" ')), page), [])
            with self.subTest(page=page, mutation="area-link"):
                self.assertNotEqual(scan_page(src.replace(route, route + '<area href="../x">'), page), [])
            with self.subTest(page=page, mutation="other-page-link"):
                self.assertNotEqual(scan_page(src.replace(route, route.replace(info["href"], PAGES[info["other"]]["href"])), page), [])


class PublicSixFileTests(PageCase):
    def test_web_tree_is_exactly_the_six_public_files(self):
        found = {p.relative_to(WEB).as_posix() for p in WEB.rglob("*") if p.is_file()}
        self.assertEqual(found, SIX_FILES)

    def test_references_are_relative_and_resolve_for_repo_and_s3_layouts(self):
        for page, info in PAGES.items():
            refs = [(t, a[k]) for t, a in self.doc[page].tags for k in ("href", "src") if k in a and t != "meta"]
            self.assertEqual(sorted(r for _, r in refs),
                             sorted(["#main", info["href"], "styles.css", "app.js"]))
            for _, ref in refs:
                if ref == "#main":
                    continue
                self.assertFalse(ref.startswith("/"), ref)
                self.assertNotIn("\\", ref)
                self.assertNotRegex(ref, r"^[A-Za-z][A-Za-z0-9+.-]*:")
                self.assertNotIn("?", ref)
                # S3-style: https://bucket/home/ and https://bucket/compare/
                s3 = posixpath.normpath(posixpath.join("/%s/" % page, ref))
                self.assertIn(s3.lstrip("/"), SIX_FILES, (page, ref, s3))
                # repository layout: web/<page>/<ref>
                repo = (info["dir"] / ref).resolve()
                self.assertTrue(repo.is_file(), repo)
                self.assertIn(repo.relative_to(WEB.resolve()).as_posix(), SIX_FILES)

    def test_stylesheet_and_script_stay_relative_for_root_redirect_candidate(self):
        for page in PAGES:
            links = [(a.get("rel"), a.get("href")) for t, a in self.doc[page].tags if t == "link"]
            self.assertEqual(links, [("stylesheet", "styles.css")])
            scripts = [a.get("src") for t, a in self.doc[page].tags if t == "script"]
            self.assertEqual(scripts, ["app.js"])

    def test_css_and_js_reference_no_urls(self):
        for page in PAGES:
            self.assertNotIn("url(", self.css[page])
            self.assertNotIn("@import", self.css[page])
            self.assertIsNone(re.search(r"https?:|//[a-z]", self.css[page], re.I))

    def test_csp_still_strict_on_both_pages(self):
        for page in PAGES:
            csp = next(a["content"] for t, a in self.doc[page].tags
                       if t == "meta" and a.get("http-equiv", "").lower() == "content-security-policy")
            self.assertIn("default-src 'none'", csp)
            self.assertIn("connect-src 'none'", csp)
            self.assertIn("script-src 'self'", csp)
            self.assertIn("base-uri 'none'", csp)
            self.assertIn("form-action 'none'", csp)
            self.assertNotIn("unsafe", csp)


class SafetyLabelTests(PageCase):
    def test_safety_labels_preserved_and_distinctions_stated(self):
        for page in PAGES:
            for needle in ("LOCAL-ISOLATION NOT VERIFIED",):
                self.assertIn(needle, self.src[page], (page, needle))
        for needle in ("AWS LIVE NO-GO", "UNATTESTED", "UNKNOWN", "NOT_RUN"):
            self.assertIn(needle, self.src["compare"], needle)
        self.assertIn("AWS LIVE NO-GO", self.src["home"])
        # HOME: synthetic DEMO vs user-selected unauthenticated JSON vs real local pixels vs unimplemented
        for needle in ("合成 DEMO", "未認証の JSON", "実ピクセル計算", "実サイトの検査は未実装"):
            self.assertIn(needle, self.src["home"], needle)
        # Compare: real local pixel values vs SAMPLE/DEMO vs unimplemented site checks vs unauthenticated JSON
        for needle in ("実データ", "SAMPLE", "DEMO", "実サイトの検査は未実装", "未認証"):
            self.assertIn(needle, self.src["compare"], needle)

    def test_no_quality_pass_or_trusted_s2_claim_added(self):
        for m in re.finditer(r"PASS", self.src["compare"]):
            self.assertEqual(self.src["compare"][m.start() - 1:m.start() + 10], "（PASS/FAIL）")
        self.assertNotIn("PASS", self.js["compare"])
        for needle in ("承認済み", "合格", "品質PASS", "S2 trusted", "trusted S2"):
            self.assertNotIn(needle, self.src["compare"])
        # the new HOME footer/link text must not claim a verdict or trust
        footer = re.search(r"<footer.*?</footer>", self.src["home"], re.S).group(0)
        header_link = re.search(r'<p class="header-link">.*?</p>', self.src["home"], re.S).group(0)
        for text in (footer, header_link):
            self.assertNotRegex(text, r"合格|承認済み|品質|(?<!un)trusted|S2")
            self.assertNotRegex(text, r"(?<![A-Za-z])PASS(?![A-Za-z])")


class CompareLimitsPreservedTests(PageCase):
    def test_validation_limits_unchanged(self):
        js = self.js["compare"]
        for needle in ("10 * 1024 * 1024", "MAX_DIM = 4096", "4096 * 4096"):
            self.assertIn(needle, js)
        for needle in ("PNG / JPEG / WebP", "10 MiB", "4096 px"):
            self.assertIn(needle, self.src["compare"])
        self.assertNotRegex(js, r"\.(drawImage|putImageData)\([^)]*,[^)]*,[^)]*,[^)]*,")  # no scaling overloads


class StaticResponsiveAndResetControlTests(PageCase):
    def test_viewport_and_breakpoints_cover_360_768_1440(self):
        for page in PAGES:
            vp = [a for t, a in self.doc[page].tags if t == "meta" and a.get("name") == "viewport"]
            self.assertEqual(len(vp), 1)
            self.assertIn("width=device-width", vp[0]["content"])
        compare_css = self.css["compare"]
        self.assertRegex(compare_css, r"@media\s*\(max-width:\s*800px\)")   # <= 768 tablet / phone
        self.assertRegex(compare_css, r"@media\s*\(max-width:\s*560px\)")   # <= 360 phone
        self.assertRegex(self.css["home"], r"@media\s*\(max-width:\s*560px\)")
        self.assertRegex(self.css["home"], r"@media\s*\(max-width:\s*900px\)")
        self.assertRegex(compare_css, r"max-width:\s*1360px")               # 1440 wide: content capped
        self.assertRegex(self.css["home"], r"max-width:\s*1440px")         # realigned HOME: 1440 reference width

    def test_overflow_safety_rules(self):
        for page in PAGES:
            css = self.css[page]
            self.assertIn("box-sizing: border-box", css)
            self.assertRegex(css, r"\.header-link\s*\{[^}]*overflow-wrap:\s*anywhere")
            if page == "home":
                # Realigned HOME header is a grid; the link only takes a full row when stacked.
                self.assertRegex(css, r"\.header-link\s*\{[^}]*min-width:\s*0")
                self.assertRegex(css, r"@media \(max-width: 1340px\)\s*\{[^@]*\.header-link\s*\{[^}]*margin:")
                self.assertRegex(css, r"grid-template-areas:\s*\"left bar\"\s*\"link link\"")
            else:
                self.assertRegex(css, r"\.header-link\s*\{[^}]*flex:\s*1 1 100%")
            self.assertIsNone(re.search(r"(?<![-\w])width:\s*\d{3,}px", css), "fixed pixel width")
            for m in re.finditer(r"min-width:\s*(\d+)px", css):
                self.assertLessEqual(int(m.group(1)), 320)
        css = self.css["compare"]
        self.assertRegex(css, r"\.metrics dd\s*\{[^}]*overflow-wrap:\s*anywhere")
        self.assertRegex(css, r"\.diff-wrap\s*\{[^}]*overflow:\s*auto")
        self.assertRegex(css, r"\.preview-box\s*\{[^}]*overflow:\s*auto")
        self.assertRegex(css, r"\.actions\s*\{[^}]*flex-wrap:\s*wrap")
        mobile = re.search(r"@media \(max-width: 560px\)\s*\{(.*?)\n\}", css, re.S).group(1)
        self.assertIn("grid-template-columns: 1fr", mobile)
        self.assertIn("flex: 1 1 100%", mobile)

    def test_touch_target_and_focus_style_for_links_and_buttons(self):
        for page in PAGES:
            self.assertRegex(self.css[page], r":focus-visible\s*\{[^}]*outline:\s*3px solid")
            self.assertRegex(self.css[page], r"\.site-header :focus-visible[^{]*\{[^}]*outline-color")
            self.assertRegex(self.css[page], r"\.header-link a\s*\{[^}]*padding:\s*8px 0")
        self.assertRegex(self.css["compare"], r"\.btn\s*\{[^}]*min-height:\s*44px")

    def test_reset_controls_are_native_labelled_buttons_in_actions(self):
        tags = self.doc["compare"].tags
        by_id = {a["id"]: (t, a) for t, a in tags if "id" in a}
        for bid in ("compare-button", "clear-result-button", "reset-all-button"):
            t, a = by_id[bid]
            self.assertEqual(t, "button", bid)
            self.assertEqual(a.get("type"), "button", bid)
            self.assertIn("disabled", a, bid)
            for banned in ("role", "tabindex", "aria-hidden", "onclick"):
                self.assertNotIn(banned, a, (bid, banned))
            m = re.search(r'<button[^>]*id="%s"[^>]*>([^<]+)</button>' % bid, self.src["compare"])
            self.assertTrue(m and m.group(1).strip(), bid)
        self.assertIn("結果だけをクリア", self.src["compare"])
        self.assertIn("すべてリセット", self.src["compare"])
        # contiguous in the .actions block, after the compare button
        block = re.search(r'<div class="actions">(.*?)</div>', self.src["compare"], re.S).group(1)
        ids = re.findall(r'id="([^"]+)"', block)
        self.assertEqual(ids, ["compare-button", "clear-result-button", "reset-all-button"])
        self.assertEqual(by_id["status"][1].get("role"), "status")
        self.assertEqual(by_id["alert"][1].get("role"), "alert")
        self.assertEqual(by_id["status"][1].get("aria-live"), "polite")
        for key in ("before", "after"):   # per-slot clear buttons stay native and labelled
            self.assertEqual(by_id[key + "-clear"][0], "button")

    def test_script_wires_reset_controls_without_navigation(self):
        js = self.js["compare"]
        for needle in ("'clear-result-button'", "'reset-all-button'", "function onClearResult", "function onResetAll"):
            self.assertIn(needle, js)
        ids = {a["id"] for _, a in self.doc["compare"].tags if "id" in a}
        for m in re.finditer(r"\$\('([a-z0-9-]+)'\)", js):
            self.assertIn(m.group(1), ids)


# ---------------------------------------------------------------------------
# Real controller (web/compare/app.js) on the MOCK DOM harness from test_image_compare
# ---------------------------------------------------------------------------
NODE_EXTRAS = r"""
// Provide the two new buttons to the existing mock DOM (mirrors the HTML: both start disabled).
const _create = app.createController;
app.createController = env => {
  const extra = {};
  for (const id of ['clear-result-button', 'reset-all-button']) { extra[id] = new El(id); extra[id].disabled = true; }
  const orig = env.document.getElementById;
  env.document.getElementById = id => orig(id) || extra[id];
  env.extra = extra;
  return _create(env);
};
const B = H => ({ clear: H.env.extra['clear-result-button'], reset: H.env.extra['reset-all-button'] });
const snapshot = H => ({ live: H.live().length, status: H.ctrl.slots.before.status + '/' + H.ctrl.slots.after.status });
"""


@unittest.skipUnless(tic.NODE, "node not installed; Node-driven tests SKIPPED")
class MockControllerResetTests(unittest.TestCase):
    def check(self, body):
        proc = tic.run_node(NODE_EXTRAS + "\n" + body)
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
        self.assertIn("NODE-OK", proc.stdout)

    def test_initial_and_selected_button_states(self):
        self.check(r"""
const H = harness(); const { clear, reset } = B(H);
assert.equal(clear.disabled, true); assert.equal(reset.disabled, true);
const px = solid(3, 2, [1, 2, 3, 255]);
await pick(H, 'before', pngFile('a.png', 3, 2), { w: 3, h: 2, px });
assert.equal(reset.disabled, false, 'something selected: reset available');
assert.equal(clear.disabled, true, 'no result yet');
await pick(H, 'after', pngFile('b.png', 3, 2), { w: 3, h: 2, px: px.slice() });
await H.ctrl.onCompare();
assert.equal(clear.disabled, false); assert.equal(reset.disabled, false);
assert.equal(H.els['compare-button'].textContent, '再比較する');
""")

    def test_clear_result_keeps_images_and_allows_recompare(self):
        self.check(r"""
const H = harness(); const { clear, reset } = B(H);
const a = solid(3, 2, [1, 2, 3, 255]); const b = a.slice(); b[0] = 9;
await pickPair(H, 3, 2, a, b);
await H.ctrl.onCompare();
assert.equal(H.els['metric-diff'].textContent, '1'); assert.equal(H.els['metric-size'].textContent, '3×2 px');
const live = H.live().length; assert.equal(live, 2);
clear.fire('click');
assertNoResult(H);
assert.equal(H.ctrl.slots.before.status, 'ready'); assert.equal(H.ctrl.slots.after.status, 'ready');
assert.equal(H.live().length, 2, 'object URLs are kept (images remain selected)');
assert.equal(H.els['before-preview'].hidden, false); assert.equal(H.els['after-preview'].hidden, false);
assert.equal(H.els['compare-button'].disabled, false); assert.equal(H.els['compare-button'].textContent, '比較する');
assert.equal(clear.disabled, true); assert.equal(reset.disabled, false);
assert.match(H.els.status.textContent, /クリア/); assert.equal(H.els.alert.textContent, '');
assert.ok(H.els['compare-button'].focused >= 1, 'focus moves to the compare button, not lost');
assert.equal(H.els['diff-canvas'].attrs['aria-label'], '差分キャンバス（結果なし）');
await H.ctrl.onCompare();   // recompare after clearing reproduces the same native-dimension result
assert.equal(H.els['metric-diff'].textContent, '1'); assert.equal(H.els['metric-total'].textContent, '6');
assert.equal(H.els['metric-ratio'].textContent, '16.6667%'); assert.equal(H.els['diff-canvas'].width, 3);
""")

    def test_reset_all_releases_everything_and_returns_to_initial_state(self):
        self.check(r"""
const H = harness(); const { clear, reset } = B(H);
const a = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, a, a.slice()); await H.ctrl.onCompare();
H.els['before-input'].value = 'C:\\fakepath\\a.png';
const urls = [...H.created];
reset.fire('click');
assertNoResult(H);
for (const k of ['before', 'after']) {
  assert.equal(H.ctrl.slots[k].status, 'empty'); assert.equal(H.ctrl.slots[k].info, null); assert.equal(H.ctrl.slots[k].url, null);
  assert.equal(H.els[k + '-preview'].hidden, true); assert.equal(H.els[k + '-preview-box'].hidden, true);
  assert.equal(H.els[k + '-preview'].attrs.src, undefined); assert.equal(H.els[k + '-input'].value, '');
  assert.equal(H.els[k + '-meta'].textContent, ''); assert.equal(H.els[k + '-msg'].textContent, '');
  assert.equal(H.els[k + '-clear'].disabled, true);
}
assert.equal(H.live().length, 0, 'every object URL revoked'); assert.deepEqual(urls.sort(), [...H.revoked].sort());
assert.equal(H.els['compare-button'].disabled, true); assert.equal(H.els['compare-button'].textContent, '比較する');
assert.equal(clear.disabled, true); assert.equal(reset.disabled, true);
assert.equal(H.els.alert.textContent, ''); assert.match(H.els.status.textContent, /リセット/);
assert.ok(H.els['before-input'].focused >= 1, 'focus returns to the first file input');
assert.ok(H.work.every(c => c.width === 0 && c.height === 0));
// a fresh pick after reset works and still computes nothing until explicitly asked
await pickPair(H, 3, 2, a, a.slice());
assertNoResult(H); assert.equal(H.els['compare-button'].disabled, false);
await H.ctrl.onCompare(); assert.equal(H.els['metric-diff'].textContent, '0');
""")

    def test_reset_all_clears_errors_and_invalid_state(self):
        self.check(r"""
const H = harness(); const { clear, reset } = B(H);
H.els['after-input'].files = [file('x.png', 'image/png', png(5000, 5000))];
await H.ctrl.onFileChange('after');
assert.match(H.els.alert.textContent, /上限/); assert.equal(H.els['after-input'].attrs['aria-invalid'], 'true');
assert.equal(reset.disabled, false, 'error state is resettable');
reset.fire('click');
assert.equal(H.els.alert.textContent, ''); assert.equal(H.els['after-input'].attrs['aria-invalid'], undefined);
assert.equal(H.ctrl.slots.after.status, 'empty'); assert.equal(H.els['after-msg'].textContent, '');
assert.equal(reset.disabled, true);
// oversize still refused after reset (limits unchanged)
H.els['before-input'].files = [{ name: 'big.png', type: 'image/png', size: 10 * MiB + 1, arrayBuffer() { throw new Error('must not read'); } }];
await H.ctrl.onFileChange('before'); assert.match(H.els.alert.textContent, /10 MiB/);
""")

    def test_reset_and_clear_are_ignored_while_comparing(self):
        self.check(r"""
const w = 2000, h = 2000; const H = harness(); const { clear, reset } = B(H); const a = solid(w, h, [3, 3, 3, 255]);
await pickPair(H, w, h, a, a.slice());
const p = H.ctrl.onCompare();
assert.equal(clear.disabled, true); assert.equal(reset.disabled, true, 'busy disables reset');
reset.fire('click'); clear.fire('click');   // a stray click on a disabled control must change nothing
assert.equal(H.ctrl.slots.before.status, 'ready'); assert.equal(H.live().length, 2);
await p;
assert.equal(H.els.result.hidden, false); assert.equal(H.els['metric-total'].textContent, String(w * h));
reset.fire('click'); assertNoResult(H); assert.equal(H.live().length, 0);
""")

    def test_reset_during_pending_read_discards_late_decode(self):
        self.check(r"""
const H = harness(); const { reset } = B(H); const d = defer();
H.els['before-input'].files = [file('a.png', 'image/png', png(3, 2), d)];
const pending = H.ctrl.onFileChange('before');
assert.equal(H.ctrl.slots.before.status, 'checking'); assert.equal(reset.disabled, false);
reset.fire('click');
assert.equal(H.ctrl.slots.before.status, 'empty');
d.resolve(); await pending;
assert.equal(H.ctrl.slots.before.status, 'empty'); assert.equal(H.created.size, 0, 'stale read never creates a URL');
assert.equal(H.els.alert.textContent, '');
""")

    def test_missing_optional_buttons_do_not_break_controller(self):
        # The pre-existing harness (no new buttons) must keep working: controls are optional.
        self.check(r"""
app.createController = _create;
const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, px, px.slice()); await H.ctrl.onCompare();
assert.equal(H.els.result.hidden, false);
H.ctrl.onResetAll(); assertNoResult(H); assert.equal(H.live().length, 0);
""")


if __name__ == "__main__":
    unittest.main()

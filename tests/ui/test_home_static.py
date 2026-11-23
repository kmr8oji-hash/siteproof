"""Static contract tests for the offline HOME UI sample (web/home).

Scope: these tests parse the shipped files as text. They do NOT render the
page, run JavaScript, or verify runtime/visual/accessibility behaviour.
Standard library only; no browser, no network.
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOME_DIR = REPO_ROOT / "web" / "home"

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "source", "track", "wbr"}


class Node:
    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = dict(attrs)
        self.parent = parent
        self.children = []
        self.text = []

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def ancestors(self):
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def full_text(self, skip_hidden=True):
        parts = list(self.text_parts(skip_hidden))
        return re.sub(r"\s+", " ", "".join(parts)).strip()

    def text_parts(self, skip_hidden):
        if skip_hidden and self.attrs.get("aria-hidden") == "true":
            return
        for item in self.text:
            if isinstance(item, str):
                yield item
            else:
                yield from item.text_parts(skip_hidden)


class TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [], None)
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        node = Node(tag, [(k, v if v is not None else "") for k, v in attrs], self.cur)
        self.cur.children.append(node)
        self.cur.text.append(node)
        if tag not in VOID_TAGS:
            self.cur = node

    def handle_startendtag(self, tag, attrs):
        node = Node(tag, [(k, v if v is not None else "") for k, v in attrs], self.cur)
        self.cur.children.append(node)
        self.cur.text.append(node)

    def handle_endtag(self, tag):
        node = self.cur
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.cur = node.parent

    def handle_data(self, data):
        self.cur.text.append(data)


def parse_html(source):
    builder = TreeBuilder()
    builder.feed(source)
    builder.close()
    return builder.root


def strip_js_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$|(?<=[;{}\s])//[^\n'\"]*$", "", src)


def strip_css_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


COLOR_TOKEN = re.compile(
    r"var\((--[\w-]+)\)"
    r"|#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b"
    r"|rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)"
)


def css_rules(css):
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        yield [s.strip() for s in selector.split(",")], body


def css_decl(css, selector, prop):
    """Last declaration of `prop` in rules whose selector list contains `selector`."""
    value = None
    for selectors, body in css_rules(css):
        if selector in selectors:
            found = re.findall(r"(?<![\w-])" + re.escape(prop) + r"\s*:\s*([^;]+)", body)
            if found:
                value = found[-1].strip()
    return value


def css_vars(css):
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", css)}


def parse_colors(value, variables):
    """Colours in order of appearance as (r, g, b, alpha)."""
    out = []
    for m in COLOR_TOKEN.finditer(value):
        if m.group(1):
            out.extend(parse_colors(variables[m.group(1)], variables))
        elif m.group(2):
            h = m.group(2)
            if len(h) == 3:
                h = "".join(ch * 2 for ch in h)
            out.append((int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0))
        else:
            out.append((int(m.group(3)), int(m.group(4)), int(m.group(5)), float(m.group(6))))
    return out


def srgb_channel(value):
    c = value / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(rgb):
    r, g, b = rgb[:3]
    return 0.2126 * srgb_channel(r) + 0.7152 * srgb_channel(g) + 0.0722 * srgb_channel(b)


def contrast_ratio(fg, bg):
    hi, lo = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def composite(fg, bg):
    a = fg[3]
    return tuple(fg[i] * a + bg[i] * (1 - a) for i in range(3))


def gradient_samples(stops, steps=16):
    """Stop colours plus sRGB-interpolated points between neighbouring stops."""
    if len(stops) == 1:
        return [tuple(stops[0][:3])]
    out = []
    for a, b in zip(stops, stops[1:]):
        for i in range(steps + 1):
            t = i / steps
            out.append(tuple(a[k] + (b[k] - a[k]) * t for k in range(3)))
    return out


class HomeTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html_src = (HOME_DIR / "index.html").read_text(encoding="utf-8")
        cls.css_src = (HOME_DIR / "styles.css").read_text(encoding="utf-8")
        cls.js_src = (HOME_DIR / "app.js").read_text(encoding="utf-8")
        cls.js_code = strip_js_comments(cls.js_src)
        cls.css_code = strip_css_comments(cls.css_src)
        cls.root = parse_html(cls.html_src)
        cls.nodes = list(cls.root.walk())

    def find(self, tag=None, **attrs):
        out = []
        for n in self.nodes:
            if tag and n.tag != tag:
                continue
            if all(n.attrs.get(k.replace("_", "-")) == v for k, v in attrs.items()):
                out.append(n)
        return out

    def by_id(self, ident):
        found = [n for n in self.nodes if n.attrs.get("id") == ident]
        self.assertEqual(len(found), 1, f"id {ident!r} must exist exactly once")
        return found[0]

    def page_text(self):
        return self.root.full_text()


class FilesAndDocumentTests(HomeTestBase):
    def test_expected_files_exist(self):
        for name in ("index.html", "styles.css", "app.js"):
            self.assertTrue((HOME_DIR / name).is_file(), name)

    def test_document_basics(self):
        self.assertTrue(self.html_src.lstrip().lower().startswith("<!doctype html>"))
        html = self.find("html")[0]
        self.assertEqual(html.attrs.get("lang"), "ja")
        charset = [m for m in self.find("meta") if m.attrs.get("charset")]
        self.assertEqual(charset[0].attrs["charset"].lower(), "utf-8")
        viewport = [m for m in self.find("meta") if m.attrs.get("name") == "viewport"]
        self.assertEqual(len(viewport), 1)
        self.assertEqual(len(self.find("title")), 1)
        self.assertTrue(self.find("title")[0].full_text())

    def test_semantic_landmarks_and_headings(self):
        for tag in ("header", "main", "footer"):
            self.assertEqual(len(self.find(tag)), 1, tag)
        self.assertEqual(len(self.find("h1")), 1)
        self.assertGreaterEqual(len(self.find("h2")), 4)
        self.assertEqual(self.find("nav"), [], "No sidebar/navigation expected")
        self.assertEqual(self.find("aside"), [], "No sidebar expected")
        for h in self.find("h1") + self.find("h2") + self.find("h3"):
            self.assertTrue(h.full_text(), "empty heading")

    def test_ids_unique_and_references_resolve(self):
        ids = [n.attrs["id"] for n in self.nodes if "id" in n.attrs]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")
        for n in self.nodes:
            for attr in ("aria-labelledby", "aria-describedby", "aria-controls"):
                for ref in (n.attrs.get(attr) or "").split():
                    self.assertIn(ref, ids, f"{attr} -> {ref}")
            target = n.attrs.get("data-sample-target")
            if target:
                self.assertIn(target, ids)

    def test_skip_link_first_and_valid(self):
        links = self.find("a")
        # Approved navigation contract: skip link, then exactly one route to Compare.
        self.assertEqual([l.attrs.get("href") for l in links],
                         ["#main", "../compare/index.html"])
        skip = links[0]
        self.assertIn("skip-link", skip.classes())
        self.assertTrue(skip.attrs["href"].startswith("#"))
        self.by_id(skip.attrs["href"][1:])
        first_interactive = next(n for n in self.nodes if n.tag in ("a", "button"))
        self.assertIs(first_interactive, skip)

    def test_svgs_are_decorative(self):
        svgs = self.find("svg")
        self.assertGreaterEqual(len(svgs), 8)
        for svg in svgs:
            self.assertEqual(svg.attrs.get("aria-hidden"), "true")
            self.assertEqual(svg.attrs.get("focusable"), "false")


class ContentContractTests(HomeTestBase):
    def test_four_status_cards_all_demo(self):
        cards = [n for n in self.nodes if "status-card" in n.classes()]
        self.assertEqual(len(cards), 4)
        for card in cards:
            self.assertIn("DEMO", card.full_text())
        self.assertEqual([c.attrs.get("data-card") for c in cards],
                         ["environment", "targets", "jobs", "attention"])
        titles = [next(c for c in card.children if c.tag == "h3").full_text() for card in cards]
        self.assertEqual(titles, ["実行環境", "監視対象", "検査ジョブ", "要確認"])
        values = [next(c for c in card.children if "card-value" in c.classes()).full_text()
                  for card in cards]
        self.assertEqual(values, ["LOCAL隔離 未検証", "DEMO 128件", "DEMO 未実行", "DEMO 3件"])
        heading = self.by_id("status-heading")
        self.assertIn("現在の状態", heading.full_text())
        self.assertIn("STATUS", heading.full_text())

    def test_log_and_aws_headings(self):
        log = self.by_id("log-heading").full_text()
        self.assertIn("最新ログ", log)
        self.assertIn("LATEST ACTIVITY", log)
        self.assertIn("AWS / クラウド運用", self.by_id("aws-heading").full_text())

    def test_six_launchers_open_sample_dialogs_only(self):
        launchers = [n for n in self.nodes if "launcher" in n.classes()]
        self.assertEqual(len(launchers), 6)
        english = []
        names = []
        for b in launchers:
            self.assertEqual(b.tag, "button")
            self.assertEqual(b.attrs.get("type"), "button")
            self.assertEqual(b.attrs.get("aria-haspopup"), "dialog")
            self.assertNotIn("disabled", b.attrs)
            text = b.full_text()
            self.assertIn("サンプル", text)
            self.assertIn("実行しません", text)
            target = self.by_id(b.attrs["data-sample-target"])
            self.assertIn("data-sample-detail", target.attrs)
            en = next(c for c in b.walk() if "launcher-en" in c.classes()).full_text()
            ja = next(c for c in b.walk() if "launcher-label" in c.classes()).full_text()
            english.append(en)
            names.append(ja)
            # Matching detail title: "<name> / <EN>（サンプル）" in data-title and heading.
            expected = f"{ja} / {en}（サンプル）"
            self.assertEqual(target.attrs.get("data-title"), expected)
            heading = next(c for c in target.children if "detail-heading" in c.classes())
            self.assertEqual(heading.full_text(), expected)
        self.assertEqual(english, ["CHECKS", "REVIEW", "SITES", "EVIDENCE", "ACTIVITY", "REPORTS"])
        self.assertEqual(names, ["検査・監視", "差分レビュー", "サイト管理",
                                 "証拠ライブラリ", "履歴・通知", "レポート"])
        self.assertIn("launcher-primary", launchers[0].classes())
        self.assertIn("launcher-secondary", launchers[1].classes())
        details = [n for n in self.nodes if "data-sample-detail" in n.attrs]
        self.assertEqual(len(details), 6)

    def test_every_button_has_accessible_name(self):
        buttons = self.find("button")
        self.assertGreaterEqual(len(buttons), 10)
        for b in buttons:
            self.assertEqual(b.attrs.get("type"), "button")
            self.assertTrue(b.full_text() or b.attrs.get("aria-label"))

    def test_five_log_rows_one_per_semantic_status(self):
        rows = [n for n in self.nodes if "log-row" in n.classes()]
        self.assertEqual(len(rows), 5)
        statuses = [r.attrs.get("data-log-status") for r in rows]
        self.assertEqual(statuses, ["completed", "pass", "changed", "approved", "unknown"])
        for row in rows:
            text = row.full_text()
            self.assertIn("SAMPLE", [c.full_text() for c in row.walk() if "sample-tag" in c.classes()])
            badge = next(c for c in row.walk() if "status-badge" in c.classes())
            self.assertEqual(badge.full_text(), row.attrs["data-log-status"].upper())
            self.assertRegex(text, r"[ぁ-んァ-ン一-龥]")
        parent_lists = {r.parent.tag for r in rows}
        self.assertEqual(parent_lists, {"ol"})

    def test_status_semantics_are_distinguished(self):
        rows = {r.attrs["data-log-status"]: r.full_text()
                for r in self.nodes if "log-row" in r.classes()}
        self.assertIn("品質の良し悪しではありません", rows["completed"])
        self.assertIn("SAMPLE DATA", rows["pass"])
        self.assertIn("実測ではありません", rows["pass"])
        self.assertIn("不具合とは限りません", rows["changed"])
        self.assertIn("品質を保証するものではありません", rows["approved"])
        self.assertIn("成功とはみなしません", rows["unknown"])

    def test_unknown_is_never_styled_as_success(self):
        row = next(r for r in self.nodes if r.attrs.get("data-log-status") == "unknown")
        blob = " ".join(" ".join(n.classes()) for n in row.walk()).lower()
        for word in ("success", "ok", "green", "pass", "done"):
            self.assertNotIn(word, blob)
        self.assertNotIn("PASS", row.full_text().replace("UNKNOWN", ""))
        # Any CSS rule that targets unknown must not use a green-dominant colour.
        for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css_code):
            if "unknown" not in selector:
                continue
            for hexcode in re.findall(r"#([0-9a-fA-F]{6})\b", body):
                r, g, b = (int(hexcode[i:i + 2], 16) for i in (0, 2, 4))
                self.assertFalse(g > r and g > b, f"green-ish colour #{hexcode} on unknown")
            self.assertNotRegex(body.lower(), r"green|lime")

    def test_mandatory_gate_and_sample_text(self):
        text = self.page_text()
        header = self.find("header")[0].full_text()
        footer = self.find("footer")[0].full_text()
        self.assertIn("LOCAL-ISOLATION NOT VERIFIED", header)
        self.assertIn("UI SAMPLE / DEMO", header)
        self.assertIn("AWS LIVE NO-GO", text)
        self.assertIn("AWS LIVE NO-GO", footer)
        self.assertIn("LOCAL-ISOLATION NOT VERIFIED", footer)
        self.assertIn("DEMO / SAMPLE DATA", footer)
        self.assertIn("UNATTESTED", text)
        self.assertIn("Production Profile Trust Source OPEN", text)

    def test_aws_area_is_separate_and_inert(self):
        aws = self.by_id("aws-sample")
        self.assertEqual(aws.tag, "section")
        self.assertEqual(aws.parent.tag, "main")
        grid = next(n for n in self.nodes if "home-grid" in n.classes())
        self.assertNotIn(grid, list(aws.ancestors()))
        self.assertNotIn(aws, list(grid.walk()))
        self.assertIn("AWS LIVE NO-GO", aws.full_text())
        self.assertTrue(any(c.tag == "h2" for c in aws.walk()))
        buttons = [n for n in aws.walk() if n.tag == "button"]
        self.assertGreaterEqual(len(buttons), 1)
        for b in buttons:
            self.assertIn("disabled", b.attrs)
            self.assertIn("無効", b.full_text())
        self.assertFalse([n for n in aws.walk() if n.tag in ("a", "form")])

    def test_no_javascript_fallback(self):
        noscript = self.find("noscript")
        self.assertEqual(len(noscript), 1)
        text = noscript[0].full_text()
        self.assertIn("JavaScript", text)
        self.assertIn("サンプル", text)
        details = self.by_id("sample-details")
        self.assertEqual(len([n for n in details.walk() if "detail" in n.classes()]), 6)
        # Fallback section is only hidden once JS has marked the document.
        self.assertRegex(self.css_code, r"\.js\s+\.details-section\s*\{[^}]*display\s*:\s*none")

    def test_dialog_markup_is_labelled_and_described(self):
        dialog = self.by_id("sample-dialog")
        self.assertEqual(dialog.tag, "dialog")
        self.assertNotIn("open", dialog.attrs)
        title = self.by_id(dialog.attrs["aria-labelledby"])
        desc = self.by_id(dialog.attrs["aria-describedby"])
        self.assertEqual(title.tag, "h2")
        self.assertTrue(title.full_text() and desc.full_text())
        close = self.by_id("sample-dialog-close")
        self.assertIn(dialog, list(close.ancestors()))
        self.assertIn("閉じる", close.full_text())
        self.assertIn("実行", desc.full_text())

    def test_no_fake_actions_in_text(self):
        text = self.page_text()
        for phrase in ("実行しました", "保存しました", "送信しました", "デプロイしました", "Deployed"):
            self.assertNotIn(phrase, text)


class LocalOnlyTests(HomeTestBase):
    def test_csp_meta_is_strict(self):
        metas = [m for m in self.find("meta")
                 if (m.attrs.get("http-equiv") or "").lower() == "content-security-policy"]
        self.assertEqual(len(metas), 1)
        directives = {}
        for part in metas[0].attrs["content"].split(";"):
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:]
        self.assertEqual(directives, {
            "default-src": ["'none'"],
            "style-src": ["'self'"],
            "script-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "connect-src": ["'none'"],
            "base-uri": ["'none'"],
            "form-action": ["'none'"],
        })
        self.assertNotIn("unsafe", metas[0].attrs["content"])

    def test_only_relative_local_resources(self):
        links = self.find("link")
        self.assertEqual([(l.attrs.get("rel"), l.attrs.get("href")) for l in links],
                         [("stylesheet", "styles.css")])
        scripts = self.find("script")
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0].attrs.get("src"), "app.js")
        self.assertFalse("".join(t for t in scripts[0].text if isinstance(t, str)).strip(),
                         "no inline script")
        for n in self.nodes:
            for attr in ("src", "href", "action", "formaction", "poster", "data", "srcset", "xlink:href"):
                value = n.attrs.get(attr)
                if value is None:
                    continue
                self.assertFalse(re.match(r"^\s*([a-z][a-z0-9+.-]*:|//)", value, re.I),
                                 f"absolute/scheme reference {attr}={value!r}")
                if n.tag == "a":
                    self.assertIn(value, ("#main", "../compare/index.html"),
                                  "anchors: skip link or the one approved Compare route")

    def test_forbidden_elements_and_attributes(self):
        banned = {"form", "iframe", "frame", "object", "embed", "base", "img", "video",
                  "audio", "source", "input", "style", "applet", "meta-refresh"}
        self.assertFalse([n.tag for n in self.nodes if n.tag in banned])
        for n in self.nodes:
            for attr in n.attrs:
                self.assertFalse(attr.lower().startswith("on"), f"inline handler {attr}")
                self.assertNotEqual(attr.lower(), "style", "inline style blocked by CSP")
            self.assertNotEqual(n.attrs.get("http-equiv", "").lower(), "refresh")
            self.assertNotIn("javascript:", " ".join(n.attrs.values()).lower())

    def test_css_has_no_external_loading(self):
        for pattern in (r"@import", r"@font-face", r"url\s*\(", r"https?:", r"//[a-z]"):
            self.assertIsNone(re.search(pattern, self.css_code, re.I), pattern)

    def test_js_has_no_network_storage_or_navigation(self):
        banned = [
            r"\bfetch\b", r"XMLHttpRequest", r"\bWebSocket\b", r"\bEventSource\b",
            r"sendBeacon", r"serviceWorker", r"\bimport\b", r"importScripts",
            r"\bWorker\b", r"SharedWorker", r"localStorage", r"sessionStorage",
            r"indexedDB", r"document\.cookie", r"\bcaches\b", r"\blocation\b",
            r"window\.open", r"\bhistory\b", r"postMessage", r"\beval\b",
            r"new\s+Function", r"\binnerHTML\b", r"\bouterHTML\b",
            r"insertAdjacentHTML", r"document\.write", r"createElement\(\s*['\"]script",
            r"https?:", r"\.href\s*=", r"\.src\s*=", r"\.action\s*=", r"\.submit\s*\(",
            r"\bnavigator\b", r"\bsetAttribute\(\s*['\"](?:href|src|action)",
        ]
        for pattern in banned:
            self.assertIsNone(re.search(pattern, self.js_code), pattern)


class CssContractTests(HomeTestBase):
    def test_visible_focus_style(self):
        self.assertRegex(self.css_code, r":focus-visible\s*\{[^}]*outline\s*:\s*[^;}]*\b[2-9]px")
        self.assertRegex(self.css_code, r"\.skip-link:focus\s*\{[^}]*top\s*:")
        # The only rule allowed to remove an outline is the programmatic-focus
        # target of the skip link (<main tabindex="-1">).
        for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css_code):
            if re.search(r"outline\s*:\s*(none|0)\b", body):
                self.assertEqual(selector.strip(), ".main:focus")

    def test_reduced_motion_respected(self):
        match = re.search(r"@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*?)\n\}", self.css_code, re.S)
        self.assertIsNotNone(match)
        self.assertIn("transition: none", match.group(1))
        self.assertIn("animation: none", match.group(1))

    def test_responsive_breakpoints(self):
        widths = [int(w) for w in re.findall(r"@media\s*\(max-width:\s*(\d+)px\)", self.css_code)]
        self.assertGreaterEqual(len(widths), 2)
        self.assertTrue(any(w <= 600 for w in widths))
        self.assertRegex(self.css_code, r"\.home-grid\s*\{[^}]*grid-template-columns\s*:\s*2fr 1fr")
        self.assertRegex(self.css_code, r"\.launcher-grid\s*\{[^}]*repeat\(2")
        self.assertRegex(self.css_code, r"\.status-cards\s*\{[^}]*repeat\(4")

    def test_dialog_and_disabled_styles_exist(self):
        self.assertIn(".sample-dialog::backdrop", self.css_code)
        self.assertRegex(self.css_code, r"\.aws-actions button\s*\{[^}]*cursor\s*:\s*not-allowed")


class JsContractTests(HomeTestBase):
    """Static text checks only; no JavaScript is executed."""

    def test_uses_modal_dialog_with_fallback(self):
        self.assertIn("showModal", self.js_code)
        self.assertIn("'sample-dialog'", self.js_code)
        self.assertRegex(self.js_code, r"dialog\.close\(")

    def test_escape_cancel_and_close_handled(self):
        self.assertRegex(self.js_code, r"event\.key\s*===\s*'Escape'")
        self.assertRegex(self.js_code, r"addEventListener\(\s*'cancel'")
        self.assertRegex(self.js_code, r"closeBtn\.addEventListener\(\s*'click'")

    def test_focus_trap_and_return_focus(self):
        self.assertRegex(self.js_code, r"event\.key\s*===\s*'Tab'")
        self.assertIn("event.shiftKey", self.js_code)
        self.assertRegex(self.js_code, r"lastTrigger\s*=\s*trigger")
        # closeSample hands the saved trigger to focusElement(), which calls .focus().
        self.assertRegex(self.js_code, r"var trigger = lastTrigger;")
        self.assertRegex(self.js_code, r"focusElement\(trigger\)")
        self.assertRegex(self.js_code, r"el\.focus\(\)")
        self.assertRegex(self.js_code, r"closeBtn\.focus\(\)")

    def test_background_made_inert_while_open(self):
        self.assertIn("'inert'", self.js_code)
        self.assertIn("data-dialog-background", self.js_code)
        marked = [n.tag for n in self.nodes if "data-dialog-background" in n.attrs]
        self.assertEqual(sorted(marked), ["footer", "header", "main"])
        dialog = self.by_id("sample-dialog")
        for n in self.nodes:
            if "data-dialog-background" in n.attrs:
                self.assertNotIn(n, list(dialog.ancestors()))

    def test_no_production_actions_in_js(self):
        for word in ("deploy", "aws", "production", "credential", "token", "secret"):
            self.assertIsNone(re.search(word, self.js_code, re.I), word)

    def test_js_only_listens_on_sample_targets(self):
        self.assertIn("[data-sample-target]", self.js_code)
        self.assertRegex(self.js_code, r"^\(function \(\) \{\n  'use strict';", )


class ContrastTests(HomeTestBase):
    """WCAG contrast computed from the stylesheet's own colours (no rendering).

    Gradients are checked at every stop and at interpolated points. This is a
    static calculation, not a visual/browser verification.
    """

    MIN_RATIO = 4.5

    def test_focus_ring_contrast_on_light_backgrounds(self):
        variables = css_vars(self.css_code)
        focus = parse_colors(variables["--focus"], variables)[0]
        self.assertRegex(self.css_code,
                         r":focus-visible\s*\{[^}]*outline:\s*3px solid var\(--focus\)")
        for name, bg in (("white", (255, 255, 255)),
                         ("ice", parse_colors(variables["--ice"], variables)[0][:3])):
            ratio = contrast_ratio(focus, bg)
            self.assertGreaterEqual(ratio, 3.0, f"--focus vs {name}: {ratio:.2f}")

    # (text selector, background selector, selector whose background shows through alpha)
    PAIRS = [
        (".launcher-primary", ".launcher-primary", None),
        (".launcher-primary .launcher-en", ".launcher-primary", None),
        (".launcher-primary .launcher-note", ".launcher-primary", None),
        (".launcher-secondary", ".launcher-secondary", None),
        (".launcher-secondary .launcher-en", ".launcher-secondary", None),
        (".launcher-secondary .launcher-note", ".launcher-secondary", None),
        (".launcher", ".launcher", None),
        (".launcher-en", ".launcher", None),
        (".launcher-note", ".launcher", None),
        (".site-header", ".site-header", None),
        (".badge-sample", ".badge-sample", ".site-header"),
        (".badge-amber", ".badge-amber", None),
        (".site-footer", ".site-footer", None),
        (".gate", ".site-footer", None),
        (".aws-section", ".aws-section", None),
        (".aws-section h2", ".aws-section", None),
        (".aws-section .h-en", ".aws-section", None),
        (".aws-actions button", ".aws-actions button", ".aws-section"),
        (".status-card h3", ".status-card", None),
        (".card-value", ".status-card", None),
        (".card-meta", ".status-card", None),
        (".panel-note", ".panel", None),
        (".h-en", ".panel", None),
        ("h2", ".panel", None),
        (".log-expl", ".log-row", None),
        (".sample-tag", ".log-row", None),
        (".st-completed", ".st-completed", None),
        (".st-pass", ".st-pass", None),
        (".st-changed", ".st-changed", None),
        (".st-approved", ".st-approved", None),
        (".st-unknown", ".st-unknown", None),
        (".dialog-badge", ".dialog-badge", None),
        (".btn-close", ".btn-close", None),
        (".sample-dialog", ".sample-dialog", None),
        (".skip-link", ".skip-link", None),
        (".noscript-note", ".noscript-note", None),
    ]

    def variables(self):
        return css_vars(self.css_code)

    def foreground(self, selector):
        value = css_decl(self.css_code, selector, "color")
        self.assertIsNotNone(value, f"no colour declared for {selector}")
        colors = parse_colors(value, self.variables())
        self.assertEqual(len(colors), 1, selector)
        return colors[0]

    def background_samples(self, selector, base_selector=None):
        value = css_decl(self.css_code, selector, "background")
        self.assertIsNotNone(value, f"no background declared for {selector}")
        colors = parse_colors(value, self.variables())
        self.assertTrue(colors, selector)
        if any(c[3] < 1 for c in colors):
            self.assertIsNotNone(base_selector, f"{selector} is translucent and needs a base")
            samples = []
            for base in self.background_samples(base_selector):
                samples.extend(gradient_samples([composite(c, base) + (1.0,) for c in colors]))
            return samples
        return gradient_samples(colors)

    def test_contrast_function_is_correct(self):
        self.assertAlmostEqual(contrast_ratio((255, 255, 255), (0, 0, 0)), 21.0, places=6)
        self.assertAlmostEqual(contrast_ratio((10, 20, 30), (10, 20, 30)), 1.0, places=6)
        # The rejected primary endpoint must fail, proving the check can fail.
        self.assertLess(contrast_ratio((255, 255, 255), (0x12, 0xC8, 0xF0)), self.MIN_RATIO)
        self.assertLess(contrast_ratio((255, 255, 255), (0x15, 0x96, 0xE8)), self.MIN_RATIO)
        # Alpha compositing: 50% white over black is mid grey.
        self.assertEqual(composite((255, 255, 255, 0.5), (0, 0, 0)), (127.5, 127.5, 127.5))

    def test_white_text_on_launcher_gradients_meets_aa(self):
        for selector in (".launcher-primary", ".launcher-secondary"):
            fg = self.foreground(selector)
            self.assertEqual(fg[:3], (255, 255, 255))
            value = css_decl(self.css_code, selector, "background")
            self.assertIn("gradient", value)
            stops = parse_colors(value, self.variables())
            self.assertGreaterEqual(len(stops), 2)
            samples = gradient_samples(stops)
            self.assertGreater(len(samples), len(stops))
            worst = min(contrast_ratio(fg, s) for s in samples)
            self.assertGreaterEqual(worst, self.MIN_RATIO, f"{selector} worst {worst:.2f}")

    def test_primary_gradient_has_no_vivid_cyan_behind_text(self):
        value = css_decl(self.css_code, ".launcher-primary", "background")
        stops = {c[:3] for c in parse_colors(value, self.variables())}
        for bright in ((0x12, 0xC8, 0xF0), (0x15, 0x96, 0xE8), (0x8D, 0xEF, 0xFF)):
            self.assertNotIn(bright, stops)
        # Decorative corner triangle (translucent cyan) must not overlay the text.
        self.assertRegex(self.css_code,
                         r"\.launcher-primary::after\s*,\s*\.launcher-secondary::after\s*\{[^}]*display\s*:\s*none")

    def test_all_text_pairs_meet_aa(self):
        failures = []
        for fg_sel, bg_sel, base_sel in self.PAIRS:
            fg = self.foreground(fg_sel)
            worst = min(contrast_ratio(fg, s) for s in self.background_samples(bg_sel, base_sel))
            if worst < self.MIN_RATIO:
                failures.append(f"{fg_sel} on {bg_sel}: {worst:.2f}")
        self.assertEqual(failures, [])

    def test_hover_and_ink_pairs_meet_aa(self):
        v = {k: parse_colors(val, self.variables())[0] for k, val in self.variables().items()
             if COLOR_TOKEN.search(val)}
        self.assertGreaterEqual(contrast_ratio(v["--white"], v["--blue"]), self.MIN_RATIO)  # .btn-close:hover
        for text in ("--ink", "--muted"):
            self.assertGreaterEqual(contrast_ratio(v[text], v["--ice"]), self.MIN_RATIO, text)


class JsRecoveryTests(HomeTestBase):
    """Static checks of the progressive-enhancement failure path; JS is not run."""

    def body(self, name):
        match = re.search(r"function " + name + r"\([^)]*\) \{", self.js_code)
        self.assertIsNotNone(match, name)
        depth, i = 1, match.end()
        while depth:
            ch = self.js_code[i]
            depth += (ch == "{") - (ch == "}")
            i += 1
        return self.js_code[match.end():i - 1]

    def test_open_commits_state_only_after_success(self):
        body = self.body("openSample")
        try_at = body.index("try {")
        show_at = body.index("dialog.showModal()")
        open_attr_at = body.index("dialog.setAttribute('open', '')")
        committed_at = body.index("isOpen = true")
        inert_at = body.index("setBackgroundInert(true)")
        self.assertLess(try_at, show_at)
        self.assertLess(show_at, committed_at)
        self.assertLess(open_attr_at, committed_at)
        self.assertLess(committed_at, inert_at)
        self.assertLess(inert_at, body.index("} catch"))
        self.assertNotRegex(body[:try_at], r"isOpen\s*=\s*true|setBackgroundInert\(true\)")

    def test_open_failure_restores_page_and_keeps_fallback_visible(self):
        body = self.body("openSample")
        catch = body[body.index("} catch"):]
        for needle in ("isOpen = false", "setGuard(false)", "setBackgroundInert(false)",
                       "resetDialogElement()", "showFallback("):
            self.assertIn(needle, catch)
        fallback = self.body("showFallback")
        self.assertIn("root.classList.remove('js')", fallback)
        self.assertIn("dialogBroken = true", fallback)
        self.assertIn("focusElement(detail)", fallback)
        self.assertIn("focusElement(trigger)", fallback)
        # After a failure later clicks go straight to the visible fallback.
        self.assertRegex(self.body("openSample"), r"if \(dialogBroken\) \{\s*showFallback\(")

    def test_background_attributes_restored_to_originals(self):
        body = self.body("setBackgroundInert")
        self.assertIn("getAttribute('inert')", body)
        self.assertIn("getAttribute('aria-hidden')", body)
        self.assertIn("restoreAttribute(", body)
        restore = self.body("restoreAttribute")
        self.assertIn("removeAttribute(name)", restore)
        self.assertIn("setAttribute(name, value)", restore)

    def test_native_close_failure_still_restores_state(self):
        reset = self.body("resetDialogElement")
        self.assertRegex(reset, re.compile(r"try \{.*dialog\.close\(\).*\} catch", re.S))
        self.assertIn("dialog.removeAttribute('open')", reset)
        self.assertIn("dialog.removeAttribute('aria-modal')", reset)
        close = self.body("closeSample")
        self.assertLess(close.index("resetDialogElement()"), close.index("setBackgroundInert(false)"))
        self.assertLess(close.index("setBackgroundInert(false)"), close.index("focusElement(trigger)"))
        self.assertLess(close.index("isOpen = false"), close.index("resetDialogElement()"))

    def test_document_capture_guard_for_attribute_fallback(self):
        self.assertRegex(self.js_code, r"document\.addEventListener\('keydown', guardKeydown, true\)")
        self.assertRegex(self.js_code, r"document\.addEventListener\('focusin', guardFocusIn, true\)")
        self.assertRegex(self.js_code, r"document\.removeEventListener\('keydown', guardKeydown, true\)")
        self.assertRegex(self.js_code, r"document\.removeEventListener\('focusin', guardFocusIn, true\)")
        self.assertIn("setGuard(!native || !('inert' in root))", self.body("openSample"))
        keydown = self.body("guardKeydown")
        self.assertIn("'Escape'", keydown)
        self.assertIn("'Tab'", keydown)
        self.assertIn("stopPropagation()", keydown)
        self.assertIn("closeBtn.focus()", self.body("guardFocusIn"))
        self.assertIn("setGuard(false)", self.body("closeSample"))

    def test_native_close_event_cannot_recurse_or_close_a_newer_open(self):
        self.assertRegex(self.js_code,
                         r"addEventListener\('close', function \(\) \{\s*if \(isOpen && !dialog\.open\) \{ closeSample\(\); \}")
        self.assertRegex(self.body("closeSample"), r"^\s*if \(!isOpen\) \{ return; \}\s*isOpen = false;")

    def test_no_actions_or_network_added(self):
        for pattern in (r"\bfetch\b", r"XMLHttpRequest", r"innerHTML", r"\.click\(\)"):
            self.assertIsNone(re.search(pattern, self.js_code), pattern)
        # Only static, already-present children are cloned.
        self.assertEqual(len(re.findall(r"cloneNode\(", self.js_code)), 1)


if __name__ == "__main__":
    unittest.main()

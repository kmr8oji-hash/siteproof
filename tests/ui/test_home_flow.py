"""Behaviour tests for the synthetic job flow on the offline HOME sample.

Scope and honesty notes:
  * Python parses web/home/index.html and web/home/styles.css as text.
  * The runtime logic in web/home/app.js is executed by the installed Node
    (`vm` + a small hand-written fake DOM). The fake DOM is built from the
    real index.html markup, but it is NOT a browser: nothing here verifies
    rendering, layout, real focus/keyboard behaviour or assistive-technology
    output. No Visual or screen-reader PASS is claimed.
  * Node receives its script on stdin, so no temp files are written. If Node
    is not installed the Node-driven tests are SKIPPED (reported, not hidden).
  * Standard library only; no network, no browser.
"""

import json
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOME_DIR = REPO_ROOT / "web" / "home"
APP_JS = HOME_DIR / "app.js"
NODE = shutil.which("node")

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "source", "track", "wbr"}


# --------------------------------------------------------------------------
# HTML helpers
# --------------------------------------------------------------------------
class Element:
    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = {k: (v if v is not None else "") for k, v in attrs}
        self.parent = parent
        self.children = []
        self.chunks = []  # direct text and child elements, in order

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def ancestors(self):
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def text(self):
        out = []
        for chunk in self.chunks:
            out.append(chunk if isinstance(chunk, str) else chunk.text())
        return re.sub(r"\s+", " ", "".join(out)).strip()

    def own_text(self):
        return re.sub(r"\s+", " ", "".join(c for c in self.chunks if isinstance(c, str))).strip()

    def to_json(self):
        return {"tag": self.tag, "attrs": self.attrs, "text": self.own_text(),
                "children": [c.to_json() for c in self.children]}


class Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Element("#root", [], None)
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        node = Element(tag, attrs, self.cur)
        self.cur.children.append(node)
        self.cur.chunks.append(node)
        if tag not in VOID_TAGS:
            self.cur = node

    def handle_endtag(self, tag):
        node = self.cur
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.cur = node.parent

    def handle_data(self, data):
        self.cur.chunks.append(data)


def parse_html(src):
    builder = Builder()
    builder.feed(src)
    builder.close()
    return builder.root


def strip_js_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$|(?<=[;{}\s])//[^\n'\"]*$", "", src)


def strip_css_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


# --------------------------------------------------------------------------
# Colour helpers (own copy; WCAG relative luminance, static calculation only)
# --------------------------------------------------------------------------
def css_variables(css):
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", css)}


def css_declaration(css, selector, prop):
    """Last `prop` declared by a rule whose selector list contains `selector`."""
    value = None
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if selector in [s.strip() for s in selectors.split(",")]:
            found = re.findall(r"(?<![\w-])" + re.escape(prop) + r"\s*:\s*([^;]+)", body)
            if found:
                value = found[-1].strip()
    return value


def to_rgb(value, variables):
    value = value.strip()
    match = re.fullmatch(r"var\((--[\w-]+)\)", value)
    if match:
        return to_rgb(variables[match.group(1)], variables)
    match = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    if match:
        h = match.group(1)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    raise AssertionError(f"unsupported colour {value!r}")


def luminance(rgb):
    def channel(v):
        c = v / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(fg, bg):
    hi, lo = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# --------------------------------------------------------------------------
# Node harness (JavaScript, executed via stdin). A hand-written fake DOM; see
# the module docstring for what it does and does not prove.
# --------------------------------------------------------------------------
HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const J = (value) => JSON.parse(JSON.stringify(value));
// Errors raised inside the vm realm are not `instanceof` this realm's TypeError.
const TE = (error) => error && error.name === 'TypeError';

class El {
  constructor(doc, tag) {
    this.doc = doc;
    this.tagName = tag.toUpperCase();
    this.attrs = new Map();
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this.ownText = '';
    this.writeLog = null;
    this._value = null;
  }
  getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
  setAttribute(name, value) { this.attrs.set(name, String(value)); }
  removeAttribute(name) { this.attrs.delete(name); }
  hasAttribute(name) { return this.attrs.has(name); }
  get id() { return this.getAttribute('id') || ''; }
  get classList() {
    const self = this;
    const read = () => (self.getAttribute('class') || '').split(/\s+/).filter(Boolean);
    return {
      add(name) { const set = new Set(read()); set.add(name); self.setAttribute('class', Array.from(set).join(' ')); },
      remove(name) { self.setAttribute('class', read().filter((c) => c !== name).join(' ')); },
      contains(name) { return read().includes(name); }
    };
  }
  get textContent() { return this.ownText + this.children.map((c) => c.textContent).join(''); }
  set textContent(value) {
    for (const child of this.children) { child.parent = null; }
    this.children = [];
    this.ownText = String(value);
    if (this.writeLog) { this.writeLog.push(this.ownText); }
  }
  get value() {
    if (this._value !== null) { return this._value; }
    const option = this.children.find((c) => c.tagName === 'OPTION');
    return option ? option.getAttribute('value') : '';
  }
  set value(v) { this._value = String(v); }
  appendChild(child) {
    if (child.parent) { child.parent.children.splice(child.parent.children.indexOf(child), 1); }
    child.parent = this;
    this.children.push(child);
    return child;
  }
  contains(node) {
    for (let n = node; n; n = n.parent) { if (n === this) { return true; } }
    return false;
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  isHiddenOrDisabled() {
    for (let n = this; n; n = n.parent) { if (n.hasAttribute('hidden')) { return true; } }
    return this.hasAttribute('disabled');
  }
  focus() {
    if (this.isHiddenOrDisabled() || !this.doc.body.contains(this)) { return; }
    this.doc._active = this;
  }
  walk(fn) { fn(this); this.children.forEach((c) => c.walk(fn)); }
}

class Doc {
  constructor(tree) {
    this.body = new El(this, 'body');
    this._active = null;
    this.createdTags = [];
    this.requestedIds = [];
    this.body.appendChild(this.build(tree));
  }
  build(node) {
    const el = new El(this, node.tag);
    for (const [k, v] of Object.entries(node.attrs)) { el.setAttribute(k, v); }
    el.ownText = node.text || '';
    node.children.forEach((c) => el.appendChild(this.build(c)));
    return el;
  }
  getElementById(id) {
    this.requestedIds.push(id);
    let found = null;
    this.body.walk((el) => { if (!found && el.getAttribute('id') === id) { found = el; } });
    return found;
  }
  createElement(tag) {
    this.createdTags.push(String(tag).toLowerCase());
    return new El(this, tag);
  }
  get activeElement() {
    return this._active && this.body.contains(this._active) ? this._active : this.body;
  }
}

function withoutId(node, id) {
  return { ...node, children: node.children.filter((c) => c.attrs.id !== id).map((c) => withoutId(c, id)) };
}

function load(options = {}) {
  const doc = new Doc(J(options.tree || TREE));
  const timers = [];
  const sandbox = {
    document: doc,
    module: { exports: {} },
    setTimeout: () => { timers.push('setTimeout'); },
    setInterval: () => { timers.push('setInterval'); },
    requestAnimationFrame: () => { timers.push('requestAnimationFrame'); }
  };
  const initialKeys = Object.keys(sandbox).sort();
  vm.runInNewContext(fs.readFileSync(APP_PATH, 'utf8'), sandbox, { filename: 'app.js' });
  const $ = (id) => doc.getElementById(id);
  const text = (id) => $(id).textContent;
  // Simulates a user activating a button (focus, then click). An element with
  // the `disabled` attribute or a hidden ancestor receives nothing; an
  // aria-disabled button still fires, exactly like a real browser.
  const press = (el) => {
    assert.ok(el, 'press: element exists');
    if (el.isHiddenOrDisabled()) { return false; }
    el.focus();
    for (const fn of (el.listeners.click || []).slice()) {
      fn({ type: 'click', target: el, preventDefault() {}, stopPropagation() {} });
    }
    return true;
  };
  const jobButtons = () => $('flow-list').children.map((li) => li.children[0]);
  const addJob = (scenario) => { if (scenario) { $('flow-scenario').value = scenario; } press($('flow-add')); };
  const model = () => sandbox.module.exports.instance.model;
  return { doc, sandbox, timers, initialKeys, api: sandbox.module.exports, $, text, press, jobButtons, addJob, model };
}

const IDS_IN_HTML = new Set();
(function collect(node) { if (node.attrs.id) { IDS_IN_HTML.add(node.attrs.id); } node.children.forEach(collect); })(TREE);
"""


@unittest.skipIf(NODE is None, "node is not installed; Node-driven tests skipped")
class NodeTestCase(unittest.TestCase):
    """Runs a JavaScript scenario body against the real app.js."""

    @classmethod
    def setUpClass(cls):
        root = parse_html((HOME_DIR / "index.html").read_text(encoding="utf-8"))
        section = next(n for n in root.walk() if n.attrs.get("id") == "flow-demo")
        cls.tree_json = json.dumps(section.to_json())

    def run_js(self, body):
        # The directive must be the very first statement, or it is not strict mode.
        script = ("'use strict';\n"
                  f"const APP_PATH = {json.dumps(str(APP_JS))};\n"
                  f"const TREE = {self.tree_json};\n"
                  f"{HARNESS}\n"
                  "try {\n" + body + "\n} catch (error) {\n"
                  "  console.error(error && error.stack ? error.stack : String(error));\n"
                  "  process.exit(1);\n}\n"
                  "console.log('SCENARIO_OK');\n")
        proc = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                              encoding="utf-8", cwd=str(REPO_ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0, f"node exit {proc.returncode}\n{proc.stderr}")
        self.assertIn("SCENARIO_OK", proc.stdout)


# --------------------------------------------------------------------------
# Static markup / CSS / source checks (no JavaScript executed)
# --------------------------------------------------------------------------
class FlowStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (HOME_DIR / "index.html").read_text(encoding="utf-8")
        cls.css = strip_css_comments((HOME_DIR / "styles.css").read_text(encoding="utf-8"))
        cls.js_src = APP_JS.read_text(encoding="utf-8")
        cls.js = strip_js_comments(cls.js_src)
        cls.root = parse_html(cls.html)
        cls.nodes = list(cls.root.walk())
        cls.flow = next(n for n in cls.nodes if n.attrs.get("id") == "flow-demo")

    def by_id(self, ident):
        found = [n for n in self.nodes if n.attrs.get("id") == ident]
        self.assertEqual(len(found), 1, ident)
        return found[0]

    def test_aws_follows_dashboard_and_flow_panel_is_an_auxiliary_region_after_it(self):
        main = next(n for n in self.nodes if n.tag == "main")
        self.assertIs(self.flow.parent, main)
        order = [c for c in main.children if c.tag == "section" or "home-grid" in c.classes()]
        ids = [c.attrs.get("id") or ("home-grid" if "home-grid" in c.classes() else "other") for c in order]
        # Realigned HOME: AWS sits immediately after the dashboard; the synthetic flow and the
        # local result viewer are auxiliary regions placed after it.
        self.assertEqual(ids.index("aws-sample"), ids.index("home-grid") + 1)
        self.assertLess(ids.index("aws-sample"), ids.index("flow-demo"))
        self.assertLess(ids.index("flow-demo"), ids.index("result-viewer"))
        aws = self.by_id("aws-sample")
        self.assertNotIn(self.flow, list(aws.ancestors()))
        self.assertNotIn(aws, list(self.flow.walk()))
        grid = next(n for n in self.nodes if "home-grid" in n.classes())
        self.assertNotIn(self.flow, list(grid.walk()))
        heading = self.by_id(self.flow.attrs["aria-labelledby"])
        self.assertEqual(heading.tag, "h2")

    def test_original_home_composition_retained(self):
        self.assertEqual(len([n for n in self.nodes if "status-card" in n.classes()]), 4)
        self.assertEqual(len([n for n in self.nodes if "launcher" in n.classes()]), 6)
        self.assertEqual(len([n for n in self.nodes if "log-row" in n.classes()]), 5)
        self.assertEqual(len([n for n in self.nodes if n.tag in ("nav", "aside")]), 0)
        self.assertIn("site-header", [n for n in self.nodes if n.tag == "header"][0].classes())
        aws = self.by_id("aws-sample")
        self.assertTrue(all("disabled" in b.attrs for b in aws.walk() if b.tag == "button"))
        flow_buttons = [b for b in self.flow.walk() if b.tag == "button"]
        for button in flow_buttons:
            self.assertNotIn("launcher", button.classes())
            self.assertNotIn("data-sample-target", button.attrs)

    def test_mandatory_markers_inside_flow_panel(self):
        text = self.flow.text()
        for marker in ("SAMPLE DATA / OFFLINE DEMO", "LOCAL-ISOLATION NOT VERIFIED", "AWS LIVE NO-GO"):
            self.assertIn(marker, text)
        for phrase in ("合成", "再読み込み", "通信も保存もせず", "自動では進まず"):
            self.assertIn(phrase, text)
        for phrase in ("実行しました", "保存しました", "送信しました", "ダウンロードしました"):
            self.assertNotIn(phrase, text)

    def test_no_form_controls_other_than_one_labelled_select(self):
        tags = [n.tag for n in self.flow.walk()]
        for banned in ("form", "input", "textarea", "a", "img", "iframe", "svg", "script", "style"):
            self.assertNotIn(banned, tags)
        selects = [n for n in self.flow.walk() if n.tag == "select"]
        self.assertEqual(len(selects), 1)
        labels = [n for n in self.flow.walk() if n.tag == "label" and n.attrs.get("for") == selects[0].attrs["id"]]
        self.assertEqual(len(labels), 1)
        self.assertTrue(labels[0].text())
        values = [o.attrs["value"] for o in selects[0].children if o.tag == "option"]
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(o.text() for o in selects[0].children))

    def test_static_buttons_are_named_typed_and_not_natively_disabled(self):
        buttons = [n for n in self.flow.walk() if n.tag == "button"]
        self.assertEqual(sorted(b.attrs["id"] for b in buttons),
                         ["flow-add", "flow-complete", "flow-start", "flow-unknown"])
        for b in buttons:
            self.assertEqual(b.attrs.get("type"), "button")
            self.assertTrue(b.text() or b.attrs.get("aria-label"))
            self.assertNotIn("disabled", b.attrs, "aria-disabled keeps the button focusable")
        ids = {n.attrs["id"] for n in self.nodes if "id" in n.attrs}
        for b in buttons:
            for ref in b.attrs.get("aria-describedby", "").split():
                self.assertIn(ref, ids)
        for name in ("flow-start", "flow-complete", "flow-unknown"):
            b = self.by_id(name)
            self.assertEqual(b.attrs.get("aria-disabled"), "true", "no job is selected initially")
            self.assertEqual(b.attrs.get("aria-describedby"), "flow-hint")

    def test_live_regions_declared_and_empty_at_load(self):
        status = self.by_id("flow-status")
        error = self.by_id("flow-error")
        self.assertEqual(status.attrs.get("role"), "status")
        self.assertEqual(status.attrs.get("aria-live"), "polite")
        self.assertEqual(status.attrs.get("aria-atomic"), "true")
        self.assertEqual(error.attrs.get("role"), "alert")
        self.assertEqual(status.text(), "")
        self.assertEqual(error.text(), "")
        self.assertNotIn("hidden", status.attrs)
        self.assertNotIn("hidden", error.attrs)

    def test_interactive_area_hidden_until_script_enables_it(self):
        self.assertIn("hidden", self.by_id("flow-app").attrs)
        self.assertNotIn("hidden", self.by_id("flow-nojs").attrs)
        self.assertIn("利用できません", self.by_id("flow-nojs").text())
        for ident in ("flow-status", "flow-error", "flow-add"):
            self.assertIn(self.by_id("flow-app"), list(self.by_id(ident).ancestors()))

    def test_distinct_dimensions_have_separate_labelled_rows(self):
        labels = [dt.text() for dt in self.flow.walk() if dt.tag == "dt"]
        for needed in ("ジョブ状態", "品質判定", "差分比較", "人の承認", "合成証跡", "実ファイル・実証跡"):
            self.assertTrue(any(needed in label for label in labels), needed)
        real = next(dd for dd in self.flow.walk() if dd.tag == "dd" and "NOT READ" in dd.text())
        self.assertIn("読み取りません", real.text())
        for dd in self.flow.walk():
            if dd.tag == "dd":
                self.assertNotIn("APPROVED", dd.text())

    def test_html_never_ships_real_looking_values(self):
        self.assertFalse(re.search(r"https?:|file:|[A-Za-z]:\\", self.flow.text()))
        self.assertNotIn("demo_data", self.html)
        self.assertEqual(len([n for n in self.nodes if n.tag == "script"]), 1)

    def test_flow_js_has_no_timers_clock_randomness_or_storage(self):
        flow_part = self.js[self.js.index("createFlowModel"):]
        for pattern in (r"setTimeout", r"setInterval", r"requestAnimationFrame", r"queueMicrotask",
                        r"Date\.now", r"new Date\(\s*\)", r"Math\.random", r"Promise", r"async\b",
                        r"await\b", r"localStorage", r"sessionStorage", r"\bfetch\b"):
            self.assertIsNone(re.search(pattern, flow_part), pattern)
        self.assertNotIn("innerHTML", self.js)
        self.assertEqual(len(re.findall(r"cloneNode\(", self.js_src)), 1)

    def test_flow_js_has_no_approval_operation(self):
        self.assertNotRegex(self.js, r"(?i)function\s+\w*approv")
        self.assertNotRegex(self.js, r"approval\s*[:=]\s*'(?!NOT_RECORDED')")
        self.assertNotRegex(self.js, r"'APPROVED'")

    def test_css_defines_every_flow_class_and_state_style(self):
        classes = set()
        for node in self.flow.walk():
            classes.update(node.classes())
        js_classes = set(re.findall(r"'(flow-[\w-]+|st-[\w-]+)", self.js))
        used = {c for c in classes | js_classes if c.startswith(("flow-", "st-"))}
        for name in sorted(used):
            self.assertRegex(self.css, r"\." + re.escape(name) + r"(?![\w-])", name)
        self.assertRegex(self.css, r"\[hidden\]\s*\{[^}]*display\s*:\s*none")
        self.assertRegex(self.css, r"\.flow-btn\[aria-disabled=\"true\"\]")
        self.assertRegex(self.css, r"\.flow-job\[aria-current=\"true\"\]")
        for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", self.css):
            if re.search(r"outline\s*:\s*(none|0)\b", body):
                self.assertEqual(selector.strip(), ".main:focus")
            if "unknown" in selector:
                self.assertNotRegex(body.lower(), r"green|lime")

    def test_new_text_pairs_meet_wcag_aa_by_calculation(self):
        variables = css_variables(self.css)
        pairs = [
            (".flow-flag", ".flow-flag"), (".flow-flag-amber", ".flow-flag-amber"),
            (".flow-nojs", ".flow-nojs"), (".flow-btn", ".flow-btn"),
            (".flow-btn[aria-disabled=\"true\"]", ".flow-btn[aria-disabled=\"true\"]"),
            (".flow-job", ".flow-job"), (".flow-job-mark", ".flow-job[aria-current=\"true\"]"),
            (".flow-job-target", ".flow-job"), (".flow-job-target", ".flow-job[aria-current=\"true\"]"),
            (".st-pending", ".st-pending"), (".st-running", ".st-running"), (".st-none", ".st-none"),
            (".flow-status", ".flow-status"), (".flow-error", ".flow-error"),
            (".flow-row select", ".flow-row select"), (".flow-selected", ".panel"),
            (".flow-help", ".panel"), (".flow-note", ".panel"), (".flow-dl dt", ".panel"),
        ]
        failures = []
        for fg_sel, bg_sel in pairs:
            fg = css_declaration(self.css, fg_sel, "color")
            if fg is None:  # colour inherited from the base class
                fg = css_declaration(self.css, fg_sel.split("[")[0], "color")
            bg = css_declaration(self.css, bg_sel, "background")
            self.assertIsNotNone(fg, fg_sel)
            self.assertIsNotNone(bg, bg_sel)
            ratio = contrast(to_rgb(fg, variables), to_rgb(bg, variables))
            if ratio < 4.5:
                failures.append(f"{fg_sel} on {bg_sel}: {ratio:.2f}")
        self.assertEqual(failures, [])
        # hover state of an enabled action button
        self.assertGreaterEqual(contrast(to_rgb("var(--white)", variables), to_rgb("var(--blue)", variables)), 4.5)
        # the checker can fail: muted text on the navy button would not pass
        self.assertLess(contrast(to_rgb("var(--muted)", variables), to_rgb("var(--navy)", variables)), 4.5)


# --------------------------------------------------------------------------
# Pure model (Node, no DOM involvement)
# --------------------------------------------------------------------------
class FlowModelTests(NodeTestCase):
    def test_model_starts_empty_with_no_selection(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
assert.equal(m.getJobs().length, 0);
assert.equal(m.getSelectedId(), null);
assert.equal(m.getSelectedJob(), null);
assert.equal(m.maxJobs, 8);
assert.deepEqual(J(m.allowedActions('SYN-001')), []);
""")

    def test_add_job_creates_pending_synthetic_job_without_selecting_it(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const r = m.addJob('present-pass-changed');
assert.equal(r.ok, true);
assert.deepEqual(J(r.job), {
  id: 'SYN-001', target: 'SAMPLE-TARGET-001', synthetic: true, scenario: 'present-pass-changed',
  state: 'pending', createdAt: '2000-01-01T00:00:00Z', startedAt: null, finishedAt: null, result: null });
assert.equal(m.getSelectedId(), null, 'adding must not select');
const r2 = m.addJob('evidence-absent');
assert.equal(r2.job.id, 'SYN-002');
assert.equal(r2.job.createdAt, '2000-01-01T00:01:00Z');
assert.deepEqual(J(m.getJobs().map((j) => j.state)), ['pending', 'pending']);
""")

    def test_select_job_and_rejected_selection_keeps_previous(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
m.addJob('present-pass-changed'); m.addJob('evidence-absent');
const ok = m.selectJob('SYN-002');
assert.equal(ok.ok, true);
assert.equal(m.getSelectedId(), 'SYN-002');
assert.equal(m.getSelectedJob().id, 'SYN-002');
for (const bad of ['SYN-999', null, undefined, '', 'constructor', '__proto__', 2, {}]) {
  const r = m.selectJob(bad);
  assert.equal(r.ok, false);
  assert.equal(r.code, 'UNKNOWN_JOB');
  assert.equal(m.getSelectedId(), 'SYN-002', 'selection unchanged after rejected select');
}
""")

    def test_explicit_pending_running_completed_with_ordered_timestamps(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const id = m.addJob('present-pass-changed').job.id;
assert.equal(m.simulate(id, 'start').ok, true);
let j = m.getJobs()[0];
assert.equal(j.state, 'running');
assert.equal(j.startedAt, '2000-01-01T00:01:00Z');
assert.equal(j.finishedAt, null);
assert.equal(j.result, null, 'no result before the job ends');
assert.deepEqual(J(m.allowedActions(id)), ['complete', 'mark-unknown']);
assert.equal(m.simulate(id, 'complete').ok, true);
j = m.getJobs()[0];
assert.equal(j.state, 'completed');
assert.equal(j.finishedAt, '2000-01-01T00:02:00Z');
assert.ok(j.createdAt < j.startedAt && j.startedAt < j.finishedAt);
const r = J(j.result);
assert.equal(r.quality, 'PASS');
assert.equal(r.comparison, 'CHANGED');
assert.equal(r.approval, 'NOT_RECORDED');
assert.deepEqual(r.evidence, { synthetic: 'present', real: 'NOT_READ' });
assert.deepEqual(J(m.allowedActions(id)), []);
""")

    def test_explicit_pending_running_unknown_forces_unknown_verdicts(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const id = m.addJob('present-pass-changed').job.id;   // scenario would otherwise PASS / CHANGED
m.simulate(id, 'start');
const r = m.simulate(id, 'mark-unknown');
assert.equal(r.ok, true);
const j = J(r.job);
assert.equal(j.state, 'unknown');
assert.equal(j.result.quality, 'UNKNOWN');
assert.equal(j.result.comparison, 'UNKNOWN');
assert.deepEqual(j.result.reasons, ['JOB_ENDED_UNKNOWN']);
assert.equal(j.finishedAt, '2000-01-01T00:02:00Z');
""")

    def test_invalid_transitions_rejected_without_changing_state_or_clock(self):
        self.run_js(r"""
const { api } = load();
let calls = 0;
const m = api.createFlowModel({ clock: () => 'T' + (calls++) });
const id = m.addJob('present-pass-changed').job.id;      // clock call 0
const reject = (action, from) => {
  const before = J(m.getJobs()); const used = calls;
  const r = m.simulate(id, action);
  assert.equal(r.ok, false, `${from} -> ${action} must be rejected`);
  assert.equal(r.code, 'INVALID_TRANSITION');
  assert.ok(r.message.includes(id));
  assert.deepEqual(J(m.getJobs()), before);
  assert.equal(calls, used, 'a rejected operation must not consume the clock');
};
reject('complete', 'pending'); reject('mark-unknown', 'pending');
assert.equal(m.simulate(id, 'start').ok, true);
reject('start', 'running');
assert.equal(m.simulate(id, 'complete').ok, true);
for (const a of ['start', 'complete', 'mark-unknown']) { reject(a, 'completed'); }
const id2 = m.addJob('present-pass-changed').job.id;
m.simulate(id2, 'start'); m.simulate(id2, 'mark-unknown');
for (const a of ['start', 'complete', 'mark-unknown']) {
  const r = m.simulate(id2, a);
  assert.equal(r.ok, false); assert.equal(r.code, 'INVALID_TRANSITION');
  assert.ok(r.message.includes('終了状態'));
}
assert.equal(m.getJobs()[1].state, 'unknown');
""")

    def test_unknown_actions_ids_and_missing_selection_are_distinct_errors(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const id = m.addJob('evidence-absent').job.id;
const before = J(m.getJobs());
assert.equal(m.simulate(null, 'start').code, 'NO_SELECTION');
assert.equal(m.simulate(undefined, 'start').code, 'NO_SELECTION');
assert.equal(m.simulate('SYN-404', 'start').code, 'UNKNOWN_JOB');
for (const bad of ['approve', 'APPROVED', 'constructor', '__proto__', 'toString', '', null, undefined, 7, {}, ['start']]) {
  const r = m.simulate(id, bad);
  assert.equal(r.ok, false); assert.equal(r.code, 'UNKNOWN_ACTION');
}
assert.deepEqual(J(m.getJobs()), before);
""")

    def test_results_fail_closed_against_independent_oracle(self):
        self.run_js(r"""
const { api } = load();
// oracle: scenario -> [evidence, quality, comparison] when the job COMPLETES
const oracle = {
  'present-pass-changed': ['present', 'PASS', 'CHANGED'],
  'present-pass-compare-unknown': ['present', 'PASS', 'UNKNOWN'],
  'present-quality-unknown-changed': ['present', 'UNKNOWN', 'CHANGED'],
  'evidence-absent': ['absent', 'UNKNOWN', 'UNKNOWN'],
  'evidence-unknown': ['unknown', 'UNKNOWN', 'UNKNOWN']
};
assert.deepEqual(J(api.scenarios.map((s) => s.key)), Object.keys(oracle));
for (const [key, [evidence, quality, comparison]] of Object.entries(oracle)) {
  const m = api.createFlowModel();
  const a = m.addJob(key).job.id; m.simulate(a, 'start'); const done = m.simulate(a, 'complete').job;
  assert.equal(done.state, 'completed');
  assert.equal(done.result.quality, quality, key);
  assert.equal(done.result.comparison, comparison, key);
  assert.equal(done.result.evidence.synthetic, evidence, key);
  assert.equal(done.result.evidence.real, 'NOT_READ');
  assert.equal(done.result.approval, 'NOT_RECORDED');
  const b = m.addJob(key).job.id; m.simulate(b, 'start'); const ended = m.simulate(b, 'mark-unknown').job;
  assert.equal(ended.state, 'unknown');
  assert.equal(ended.result.quality, 'UNKNOWN', key);
  assert.equal(ended.result.comparison, 'UNKNOWN', key);
  assert.equal(ended.result.evidence.synthetic, evidence, 'evidence is independent of the job end state');
}
""")

    def test_job_state_quality_comparison_approval_are_distinct_facts(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
assert.deepEqual(J(Object.keys(m).filter((k) => /approv|accept|sign/i.test(k))), []);
const seen = [];
for (const s of api.scenarios) {
  for (const end of ['complete', 'mark-unknown']) {
    const fresh = api.createFlowModel();   // the per-model job cap is 8
    const id = fresh.addJob(s.key).job.id;
    fresh.simulate(id, 'start');
    seen.push(fresh.simulate(id, end).job);
  }
}
// a COMPLETED job is not necessarily good, and PASS only ever comes with COMPLETED
assert.ok(seen.some((j) => j.state === 'completed' && j.result.quality === 'UNKNOWN'));
assert.ok(seen.some((j) => j.state === 'completed' && j.result.comparison === 'UNKNOWN'));
assert.ok(seen.some((j) => j.state === 'completed' && j.result.quality === 'PASS'));
for (const j of seen) {
  if (j.result.quality === 'PASS' || j.result.comparison === 'CHANGED') {
    assert.equal(j.state, 'completed');
    assert.equal(j.result.evidence.synthetic, 'present');
  }
  assert.ok(['PASS', 'UNKNOWN'].includes(j.result.quality));
  assert.ok(['CHANGED', 'UNKNOWN'].includes(j.result.comparison));
  assert.equal(j.result.approval, 'NOT_RECORDED');
  assert.equal(j.result.evidence.real, 'NOT_READ');
}
const everything = JSON.stringify(seen);
assert.ok(!/APPROVED/i.test(everything), 'a human approval must never be invented');
""")

    def test_snapshots_are_frozen_and_old_snapshots_never_change(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const added = m.addJob('evidence-absent').job;
assert.ok(Object.isFrozen(added));
assert.throws(() => { added.state = 'completed'; }, TE);
assert.throws(() => { added.extra = 1; }, TE);
const list = m.getJobs();
assert.ok(Object.isFrozen(list));
assert.throws(() => { list.push(added); }, TE);
assert.throws(() => { list[0] = null; }, TE);
m.simulate('SYN-001', 'start');
const done = m.simulate('SYN-001', 'complete').job;
assert.equal(added.state, 'pending', 'earlier snapshot is not mutated by later transitions');
assert.equal(list[0].state, 'pending');
assert.equal(m.getJobs()[0].state, 'completed');
assert.notStrictEqual(m.getJobs(), list);
assert.ok(Object.isFrozen(done.result) && Object.isFrozen(done.result.evidence) && Object.isFrozen(done.result.reasons));
assert.throws(() => { done.result.quality = 'PASS'; }, TE);
assert.throws(() => { done.result.evidence.real = 'READ'; }, TE);
assert.throws(() => { done.result.reasons.push('x'); }, TE);
assert.equal(m.getJobs()[0].result.quality, 'UNKNOWN');
assert.throws(() => { api.scenarios[0].evidence = 'absent'; }, TE);
assert.throws(() => { api.scenarios.push({}); }, TE);
assert.throws(() => { m.simulate = null; }, TE);
""")

    def test_job_limit_and_unknown_scenario_leave_state_untouched(self):
        self.run_js(r"""
const { api } = load();
let calls = 0;
const m = api.createFlowModel({ clock: () => 'T' + (calls++) });
for (let i = 0; i < m.maxJobs; i++) { assert.equal(m.addJob('present-pass-changed').ok, true); }
const full = m.addJob('present-pass-changed');
assert.equal(full.ok, false); assert.equal(full.code, 'LIMIT_REACHED');
assert.ok(full.message.includes('8'));
assert.equal(m.getJobs().length, 8);
assert.equal(calls, 8, 'rejected add does not consume the clock');
assert.deepEqual(J(m.getJobs().map((j) => j.id)),
  ['SYN-001', 'SYN-002', 'SYN-003', 'SYN-004', 'SYN-005', 'SYN-006', 'SYN-007', 'SYN-008']);
const m2 = api.createFlowModel();
for (const bad of ['nope', '', null, undefined, 'constructor', '__proto__', 3]) {
  const r = m2.addJob(bad);
  assert.equal(r.ok, false); assert.equal(r.code, 'UNKNOWN_SCENARIO');
}
assert.equal(m2.getJobs().length, 0);
assert.equal(m2.addJob('evidence-unknown').job.id, 'SYN-001', 'failed adds do not consume ids');
""")

    def test_default_clock_is_deterministic_synthetic_and_models_are_independent(self):
        self.run_js(r"""
const { api } = load();
const clock = api.createSyntheticClock();
const stamps = [clock(), clock(), clock()];
assert.deepEqual(stamps, ['2000-01-01T00:00:00Z', '2000-01-01T00:01:00Z', '2000-01-01T00:02:00Z']);
const a = api.createFlowModel(); const b = api.createFlowModel();
a.addJob('present-pass-changed');
assert.equal(b.getJobs().length, 0);
assert.equal(b.addJob('present-pass-changed').job.createdAt, '2000-01-01T00:00:00Z');
const injected = api.createFlowModel({ clock: () => 'INJECTED' });
assert.equal(injected.addJob('present-pass-changed').job.createdAt, 'INJECTED');
""")

    def test_allowed_actions_follow_the_state_machine(self):
        self.run_js(r"""
const { api } = load();
const m = api.createFlowModel();
const id = m.addJob('present-pass-changed').job.id;
assert.deepEqual(J(m.allowedActions(id)), ['start']);
m.simulate(id, 'start');
assert.deepEqual(J(m.allowedActions(id)), ['complete', 'mark-unknown']);
m.simulate(id, 'complete');
assert.deepEqual(J(m.allowedActions(id)), []);
assert.deepEqual(J(m.allowedActions('SYN-404')), []);
assert.ok(Object.isFrozen(m.allowedActions(id)));
""")


# --------------------------------------------------------------------------
# UI wiring (Node, fake DOM built from the real markup)
# --------------------------------------------------------------------------
class FlowUiTests(NodeTestCase):
    def test_every_id_requested_by_script_exists_in_markup_and_options_match_scenarios(self):
        self.run_js(r"""
const L = load();
const requested = new Set(L.doc.requestedIds.filter((id) => id.startsWith('flow-')));
assert.ok(requested.size >= 25);
for (const id of requested) { assert.ok(IDS_IN_HTML.has(id), `script asks for #${id}, missing in index.html`); }
const options = L.$('flow-scenario').children.map((o) => o.getAttribute('value'));
assert.deepEqual(options, J(L.api.scenarios.map((s) => s.key)));
const labels = L.$('flow-scenario').children.map((o) => o.ownText);
assert.deepEqual(labels, J(L.api.scenarios.map((s) => s.label)));
""")

    def test_initial_ui_state_is_empty_enabled_for_add_only_and_idle(self):
        self.run_js(r"""
const L = load();
assert.ok(L.api.instance, 'UI initialised');
assert.equal(L.$('flow-app').hasAttribute('hidden'), false);
assert.equal(L.$('flow-nojs').hasAttribute('hidden'), true);
assert.equal(L.$('flow-empty').hasAttribute('hidden'), false);
assert.equal(L.$('flow-list').children.length, 0);
for (const id of ['flow-start', 'flow-complete', 'flow-unknown']) {
  assert.equal(L.$(id).getAttribute('aria-disabled'), 'true', id);
}
assert.equal(L.$('flow-add').hasAttribute('aria-disabled'), false);
assert.equal(L.text('flow-selected'), '選択中: なし');
for (const id of ['flow-v-state', 'flow-v-quality', 'flow-v-comparison', 'flow-v-approval']) { assert.equal(L.text(id), '—'); }
assert.equal(L.text('flow-v-evidence'), 'NOT EVALUATED');
assert.equal(L.text('flow-status'), '');
assert.equal(L.text('flow-error'), '');
assert.equal(L.model().getJobs().length, 0);
assert.deepEqual(L.timers, []);
""")

    def test_adding_a_job_shows_pending_selects_it_and_announces(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed');
assert.equal(L.jobButtons().length, 1);
const b = L.jobButtons()[0];
assert.equal(b.tagName, 'BUTTON'); assert.equal(b.getAttribute('type'), 'button');
assert.equal(b.getAttribute('aria-current'), 'true');
for (const piece of ['SYN-001', 'SAMPLE-TARGET-001', 'PENDING', 'SAMPLE', '選択中']) { assert.ok(b.textContent.includes(piece), piece); }
assert.equal(L.model().getJobs()[0].state, 'pending');
assert.equal(L.model().getSelectedId(), 'SYN-001');
assert.equal(L.$('flow-empty').hasAttribute('hidden'), true);
assert.equal(L.text('flow-v-state'), 'PENDING');
assert.equal(L.$('flow-v-state').getAttribute('class'), 'status-badge st-pending');
assert.equal(L.text('flow-v-quality'), '—');
assert.equal(L.text('flow-t-created'), '2000-01-01T00:00:00Z（合成時刻）');
assert.ok(L.text('flow-t-started').includes('未発生'));
assert.ok(L.text('flow-t-finished').includes('未発生'));
assert.ok(L.text('flow-summary').includes('まだ結果はありません'));
assert.equal(L.$('flow-start').hasAttribute('aria-disabled'), false);
assert.equal(L.$('flow-complete').getAttribute('aria-disabled'), 'true');
assert.equal(L.$('flow-unknown').getAttribute('aria-disabled'), 'true');
assert.ok(L.text('flow-hint').includes('開始をシミュレート'));
assert.ok(L.text('flow-status').includes('SYN-001') && L.text('flow-status').includes('PENDING'));
assert.equal(L.text('flow-error'), '');
""")

    def test_nothing_advances_without_an_explicit_press(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed');
L.press(L.$('flow-start'));
assert.equal(L.model().getJobs()[0].state, 'running');
assert.equal(L.text('flow-v-state'), 'RUNNING');
assert.ok(L.text('flow-t-started').startsWith('2000-01-01T00:01:00Z'));
assert.ok(L.text('flow-t-finished').includes('未発生'));
assert.equal(L.text('flow-v-quality'), '—', 'no verdict before the job ends');
// other activity (adding, selecting, re-rendering) never completes a running job
L.addJob('evidence-absent'); L.addJob('evidence-unknown');
L.press(L.jobButtons()[0]);
L.instance = L.api.instance; L.instance.render(); L.instance.render();
assert.deepEqual(J(L.model().getJobs().map((j) => j.state)), ['running', 'pending', 'pending']);
assert.deepEqual(L.timers, [], 'no timer was ever scheduled');
L.press(L.$('flow-complete'));
assert.equal(L.model().getJobs()[0].state, 'completed');
""")

    def test_completed_job_shows_distinct_status_verdicts_evidence_and_timestamps(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed');
L.press(L.$('flow-start')); L.press(L.$('flow-complete'));
assert.equal(L.text('flow-v-state'), 'COMPLETED');
assert.equal(L.$('flow-v-state').getAttribute('class'), 'status-badge st-completed');
assert.equal(L.text('flow-v-quality'), 'PASS');
assert.equal(L.text('flow-v-comparison'), 'CHANGED');
assert.equal(L.text('flow-v-approval'), 'NOT RECORDED');
assert.equal(L.text('flow-v-evidence'), 'PRESENT');
assert.ok(L.text('flow-n-evidence').includes('SYNTHETIC') && L.text('flow-n-evidence').includes('実ファイルではありません'));
assert.ok(L.text('flow-n-state').includes('品質の良し悪しではありません'));
assert.ok(L.text('flow-n-quality').includes('実測ではありません'));
assert.ok(L.text('flow-n-comparison').includes('不具合とは限りません'));
assert.ok(L.text('flow-n-approval').includes('記録されていません'));
assert.deepEqual([L.text('flow-t-created'), L.text('flow-t-started'), L.text('flow-t-finished')].map((s) => s.slice(0, 20)),
  ['2000-01-01T00:00:00Z', '2000-01-01T00:01:00Z', '2000-01-01T00:02:00Z']);
assert.ok(L.text('flow-summary').includes('合成') && L.text('flow-summary').includes('実測ではありません'));
for (const id of ['flow-start', 'flow-complete', 'flow-unknown']) { assert.equal(L.$(id).getAttribute('aria-disabled'), 'true'); }
assert.ok(L.text('flow-hint').includes('終了状態'));
const status = L.text('flow-status');
assert.ok(status.includes('RUNNING → COMPLETED') && status.includes('品質 PASS') && status.includes('人の承認 NOT RECORDED'));
""")

    def test_unknown_end_shows_unknown_never_styled_as_success(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed');
L.press(L.$('flow-start')); L.press(L.$('flow-unknown'));
assert.equal(L.text('flow-v-state'), 'UNKNOWN');
assert.equal(L.text('flow-v-quality'), 'UNKNOWN');
assert.equal(L.text('flow-v-comparison'), 'UNKNOWN');
for (const id of ['flow-v-state', 'flow-v-quality', 'flow-v-comparison']) {
  assert.equal(L.$(id).getAttribute('class'), 'status-badge st-unknown', id);
}
assert.ok(L.text('flow-n-state').includes('成功とはみなしません'));
assert.ok(!/PASS|CHANGED/.test(L.text('flow-v-quality') + L.text('flow-v-comparison')));
assert.ok(L.text('flow-status').includes('RUNNING → UNKNOWN'));
assert.equal(L.text('flow-v-approval'), 'NOT RECORDED');
""")

    def test_invalid_press_on_aria_disabled_button_reports_error_and_keeps_state_and_focus(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed');
const statusBefore = L.text('flow-status');
const complete = L.$('flow-complete');
assert.equal(complete.getAttribute('aria-disabled'), 'true');
assert.equal(L.press(complete), true, 'aria-disabled stays focusable and clickable');
assert.equal(L.model().getJobs()[0].state, 'pending');
assert.equal(L.doc.activeElement, complete, 'focus stays on the pressed button');
const err = L.text('flow-error');
assert.ok(err.startsWith('[エラー 1]'));
assert.ok(err.includes('SYN-001') && err.includes('PENDING') && err.includes('できません') && err.includes('開始をシミュレート'));
assert.equal(L.text('flow-status'), statusBefore, 'a rejected action is not announced as progress');
L.press(L.$('flow-unknown'));
assert.ok(L.text('flow-error').startsWith('[エラー 2]'));
L.press(L.$('flow-start'));
assert.equal(L.text('flow-error'), '', 'a successful action clears the error');
assert.equal(L.model().getJobs()[0].state, 'running');
""")

    def test_actions_without_a_selected_job_report_no_selection(self):
        self.run_js(r"""
const L = load();
L.press(L.$('flow-start'));
assert.ok(L.text('flow-error').includes('ジョブが選択されていません'));
assert.equal(L.model().getJobs().length, 0);
assert.equal(L.text('flow-status'), '');
""")

    def test_selecting_between_jobs_updates_detail_current_marker_and_keeps_focus(self):
        self.run_js(r"""
const L = load();
L.addJob('present-pass-changed'); L.addJob('evidence-absent');
assert.equal(L.model().getSelectedId(), 'SYN-002');
L.press(L.jobButtons()[0]);
assert.equal(L.model().getSelectedId(), 'SYN-001');
let buttons = L.jobButtons();
assert.equal(buttons[0].getAttribute('aria-current'), 'true');
assert.equal(buttons[1].hasAttribute('aria-current'), false);
assert.equal(L.doc.activeElement, buttons[0], 'focus restored to the same job after re-render');
assert.ok(L.doc.body.contains(L.doc.activeElement));
assert.equal(L.doc.activeElement.getAttribute('data-job-id'), 'SYN-001');
assert.ok(L.text('flow-selected').includes('SYN-001'));
L.press(L.$('flow-start'));
assert.equal(L.text('flow-v-state'), 'RUNNING');
L.press(L.jobButtons()[1]);
assert.equal(L.text('flow-v-state'), 'PENDING');
assert.ok(L.text('flow-selected').includes('SYN-002'));
assert.equal(L.doc.activeElement.getAttribute('data-job-id'), 'SYN-002');
// the other job kept its own state
assert.deepEqual(J(L.model().getJobs().map((j) => j.state)), ['running', 'pending']);
assert.ok(L.text('flow-status').includes('SYN-002'));
""")

    def test_ninth_job_is_refused_with_visible_error(self):
        self.run_js(r"""
const L = load();
for (let i = 0; i < 8; i++) { L.addJob('present-pass-changed'); }
assert.equal(L.jobButtons().length, 8);
assert.equal(L.text('flow-error'), '');
L.addJob('present-pass-changed');
assert.equal(L.jobButtons().length, 8);
assert.ok(L.text('flow-error').includes('最大 8 件'));
assert.equal(L.model().getJobs().length, 8);
""")

    def test_synthetic_evidence_present_absent_unknown_vs_real_evidence_not_read(self):
        self.run_js(r"""
const L = load();
const expected = { 'present-pass-changed': 'PRESENT', 'present-pass-compare-unknown': 'PRESENT',
  'present-quality-unknown-changed': 'PRESENT', 'evidence-absent': 'ABSENT', 'evidence-unknown': 'UNKNOWN' };
const realRow = [];
L.$('flow-demo').walk((el) => { if (el.ownText === 'NOT READ') { realRow.push(el); } });
assert.equal(realRow.length, 1, 'a static NOT READ row for real evidence exists');
let n = 0;
for (const [key, label] of Object.entries(expected)) {
  L.addJob(key); n++;
  assert.equal(L.text('flow-v-evidence'), 'NOT EVALUATED', 'not evaluated before the job ends');
  L.press(L.$('flow-start')); L.press(L.$('flow-complete'));
  assert.equal(L.text('flow-v-evidence'), label, key);
  assert.equal(realRow[0].textContent, 'NOT READ');
  if (label !== 'PRESENT') {
    assert.equal(L.text('flow-v-quality'), 'UNKNOWN', key);
    assert.equal(L.text('flow-v-comparison'), 'UNKNOWN', key);
    assert.equal(L.$('flow-v-quality').getAttribute('class'), 'status-badge st-unknown');
    assert.equal(L.text('flow-v-state'), 'COMPLETED', 'COMPLETED does not imply PASS');
  }
  assert.ok(L.text('flow-n-evidence').includes('合成シナリオ'));
  assert.ok(!L.text('flow-n-evidence').includes('実ファイルが'));
}
assert.equal(n, 5);
""")

    def test_approval_is_never_approved_and_no_control_can_record_one(self):
        self.run_js(r"""
const L = load();
for (const s of L.api.scenarios) {
  L.addJob(s.key); L.press(L.$('flow-start')); L.press(L.$('flow-complete'));
  assert.equal(L.text('flow-v-approval'), 'NOT RECORDED');
  assert.notEqual(L.text('flow-v-approval'), 'APPROVED');
}
const all = [];
L.$('flow-demo').walk((el) => { all.push(el); });
const buttons = all.filter((el) => el.tagName === 'BUTTON');
assert.ok(buttons.length >= 4 + 5);
for (const b of buttons) { assert.ok(!/承認|approv/i.test(b.textContent), `button "${b.textContent}" must not offer approval`); }
const approvedMentions = all.map((el) => el.ownText).filter((t) => /APPROVED/.test(t));
assert.deepEqual(approvedMentions, ['人による承認は記録されていません。このデモに承認の操作はなく、APPROVED になることはありません。']);
assert.ok(!all.some((el) => el.getAttribute('class') && /st-approved/.test(el.getAttribute('class'))));
""")

    def test_live_region_writes_clear_before_setting_and_each_step_changes_message(self):
        self.run_js(r"""
const L = load();
const status = L.$('flow-status'); const error = L.$('flow-error');
status.writeLog = []; error.writeLog = [];
L.addJob('present-pass-changed');
L.press(L.$('flow-start')); L.press(L.$('flow-complete'));
assert.deepEqual(status.writeLog.filter((_, i) => i % 2 === 0), ['', '', ''], 'cleared before each announcement');
const messages = status.writeLog.filter((_, i) => i % 2 === 1);
assert.equal(messages.length, 3);
assert.equal(new Set(messages).size, 3, 'each step announces something new');
assert.ok(messages[0].includes('追加'));
assert.ok(messages[1].includes('PENDING → RUNNING'));
assert.ok(messages[2].includes('RUNNING → COMPLETED'));
L.press(L.$('flow-start'));          // rejected: COMPLETED job
L.press(L.$('flow-start'));          // rejected again with identical reason
const errs = error.writeLog.filter((t) => t !== '');
assert.equal(errs.length, 2);
assert.notEqual(errs[0], errs[1], 'repeated identical errors still change the text so they re-announce');
""")

    def test_script_creates_only_li_button_span_and_never_injects_markup(self):
        self.run_js(r"""
const L = load();
for (const s of L.api.scenarios) { L.addJob(s.key); }
L.press(L.$('flow-start'));
const created = new Set(L.doc.createdTags);
assert.deepEqual(Array.from(created).sort(), ['button', 'li', 'span']);
const dynamicButtons = L.jobButtons();
assert.equal(dynamicButtons.length, 5);
for (const b of dynamicButtons) {
  assert.equal(b.getAttribute('type'), 'button');
  assert.ok(b.textContent.trim().length > 0, 'accessible name from text');
  assert.ok(!b.hasAttribute('href') && !b.hasAttribute('src'));
}
""")

    def test_ui_fails_closed_when_markup_is_incomplete(self):
        self.run_js(r"""
const L = load({ tree: withoutId(TREE, 'flow-status') });
assert.equal(L.api.instance, null, 'no UI when an expected element is missing');
assert.equal(L.$('flow-app').hasAttribute('hidden'), true, 'interactive area stays hidden');
assert.equal(L.$('flow-nojs').hasAttribute('hidden'), false, 'unavailable notice stays visible');
assert.equal(L.$('flow-add').listeners.click, undefined, 'no handler attached');
const model = L.api.createFlowModel();
assert.equal(L.api.initFlowUi(L.doc, model), null);
""")

    def test_no_persistence_global_leakage_network_or_timers(self):
        self.run_js(r"""
const L = load();
for (const s of L.api.scenarios) { L.addJob(s.key); L.press(L.$('flow-start')); L.press(L.$('flow-unknown')); }
assert.deepEqual(Object.keys(L.sandbox).sort(), L.initialKeys, 'app.js defined no new globals');
assert.deepEqual(L.timers, []);
for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'localStorage', 'sessionStorage', 'indexedDB', 'navigator', 'location']) {
  assert.equal(L.sandbox[name], undefined, name);
}
// a "reload" (fresh load) starts from nothing
const fresh = load();
assert.equal(fresh.model().getJobs().length, 0);
assert.equal(fresh.model().getSelectedId(), null);
assert.equal(fresh.jobButtons().length, 0);
assert.equal(fresh.text('flow-status'), '');
""")

    def test_flow_does_not_touch_the_existing_sample_dialog_wiring(self):
        self.run_js(r"""
// The fake page has no #sample-dialog, so the original IIFE returns early;
// the flow must still initialise independently of it.
const L = load();
assert.equal(L.doc.getElementById('sample-dialog'), null);
assert.ok(L.api.instance);
L.addJob('present-pass-changed');
assert.equal(L.jobButtons().length, 1);
""")


class FlowLauncherRegressionTests(unittest.TestCase):
    def test_original_dialog_script_is_first_and_unchanged_in_shape(self):
        src = APP_JS.read_text(encoding="utf-8")
        self.assertTrue(src.startswith("(function () {\n  'use strict';"))
        for needle in ("function openSample(", "function closeSample(", "function showFallback(",
                       "dialog.showModal()", "[data-sample-target]"):
            self.assertEqual(src.count(needle), 1, needle)


if __name__ == "__main__":
    unittest.main()

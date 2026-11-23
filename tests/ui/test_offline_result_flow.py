"""Tests for the HOME local result viewer (user-selected siteproof.offline-result.v1 JSON).

Scope and honesty notes:
  * Python parses web/home/index.html as text. The runtime logic of
    web/home/app.js is executed by the installed Node (`vm` + a small
    hand-written fake DOM built from the real markup + a mock FileReader).
    It is NOT a browser: nothing here verifies real file pickers, rendering,
    layout, focus order or assistive-technology output. No Visual PASS.
  * The validator is also cross-checked against an independent Python
    reference written from the agreed contract (differential test).
  * Node receives its script on stdin, so no temp files are written. If Node
    is not installed the Node-driven tests are SKIPPED (reported, not hidden).
  * Standard library only; no network, no browser.
"""

import base64
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

NOTICE = "オフライン結果です。撮影条件の真正性およびUIでの証拠検証は保証しません。"
UNTRUSTED = "ローカルファイルから読み込んだ未認証レポート"


# --------------------------------------------------------------------------
# HTML helpers
# --------------------------------------------------------------------------
class Element:
    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = {k: (v if v is not None else "") for k, v in attrs}
        self.parent = parent
        self.children = []
        self.chunks = []

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

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


# --------------------------------------------------------------------------
# Independent Python reference of the agreed contract (differential oracle)
# --------------------------------------------------------------------------
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
TOP_KEYS = {"schema_version", "record_type", "source", "job_id", "attempt_id", "profile_trust",
            "eligibility", "comparison", "human_approval", "bridge", "evidence",
            "unknown_reasons", "notice"}
FIXED = {"schema_version": "siteproof.offline-result.v1", "record_type": "OFFLINE_RESULT",
         "source": "OFFLINE_PROJECTION", "profile_trust": "UNATTESTED", "eligibility": "UNKNOWN",
         "comparison": "NOT_RUN", "human_approval": "NOT_RECORDED", "notice": NOTICE}


class _Reject(Exception):
    pass


def _pairs(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise _Reject("duplicate")
        seen.add(key)
    return dict(pairs)


def _no(*_args):
    raise _Reject("unsupported value")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _bad_ref(ref, job, attempt, manifest):
    if not isinstance(ref, str) or len(ref) > 4096:
        return True
    if any(ch in "\\:" or ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in ref):
        return True
    parts = ref.split("/")
    if len(parts) != 3 or parts[0] != job or parts[1] != attempt:
        return True
    if any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts):
        return True
    return (parts[2] == "manifest.json") != manifest


def reference_accepts(raw):
    """True iff the contract accepts these bytes. Written independently of app.js."""
    try:
        if not raw or len(raw) > 1048576 or raw.startswith(b"\xef\xbb\xbf"):
            return False
        text = raw.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no,
                         parse_float=_no, parse_int=_no)
        for s in _strings(doc):
            s.encode("utf-8")  # lone surrogates raise UnicodeEncodeError
    except (_Reject, ValueError, RecursionError, UnicodeError):
        return False
    return reference_valid(doc)


def reference_valid(doc):
    if not isinstance(doc, dict) or set(doc) != TOP_KEYS:
        return False
    if any(doc[k] != v for k, v in FIXED.items()):
        return False
    for key in ("job_id", "attempt_id"):
        if doc[key] is not None and not (isinstance(doc[key], str) and ID_RE.fullmatch(doc[key])):
            return False
    bridge, evidence, reasons = doc["bridge"], doc["evidence"], doc["unknown_reasons"]
    if not isinstance(bridge, dict) or set(bridge) != {"status", "reason"}:
        return False
    if not isinstance(evidence, dict) or set(evidence) != {"status", "manifest_ref", "screenshot_ref"}:
        return False
    if bridge["status"] not in ("STRUCTURALLY_CHECKED", "REJECTED", "UNKNOWN"):
        return False
    if evidence["status"] not in ("STRUCTURALLY_CHECKED", "NOT_VERIFIED"):
        return False
    reason = bridge["reason"]
    if reason is not None and not (isinstance(reason, str) and CODE_RE.fullmatch(reason)):
        return False
    if not isinstance(reasons, list) or not 1 <= len(reasons) <= 128:
        return False
    if not all(isinstance(r, str) and CODE_RE.fullmatch(r) for r in reasons):
        return False
    if len(set(reasons)) != len(reasons) or "COMPARISON_NOT_RUN" not in reasons:
        return False
    if reason is not None and reason not in reasons:
        return False
    checked = bridge["status"] == "STRUCTURALLY_CHECKED"
    if checked != (evidence["status"] == "STRUCTURALLY_CHECKED"):
        return False
    if (bridge["status"] == "REJECTED") != (reason is not None):
        return False
    if checked:
        job, attempt = doc["job_id"], doc["attempt_id"]
        if job is None or attempt is None or "PROFILE_UNATTESTED" not in reasons:
            return False
        if _bad_ref(evidence["manifest_ref"], job, attempt, True):
            return False
        if _bad_ref(evidence["screenshot_ref"], job, attempt, False):
            return False
    elif evidence["manifest_ref"] is not None or evidence["screenshot_ref"] is not None:
        return False
    return True


def checked_doc():
    return {
        "schema_version": "siteproof.offline-result.v1", "record_type": "OFFLINE_RESULT",
        "source": "OFFLINE_PROJECTION", "job_id": "job-1", "attempt_id": "att-1",
        "profile_trust": "UNATTESTED", "eligibility": "UNKNOWN", "comparison": "NOT_RUN",
        "human_approval": "NOT_RECORDED",
        "bridge": {"status": "STRUCTURALLY_CHECKED", "reason": None},
        "evidence": {"status": "STRUCTURALLY_CHECKED", "manifest_ref": "job-1/att-1/manifest.json",
                     "screenshot_ref": "job-1/att-1/shot.png"},
        "unknown_reasons": ["COMPARISON_NOT_RUN", "PROFILE_UNATTESTED"], "notice": NOTICE,
    }


def rejected_doc():
    doc = checked_doc()
    doc["bridge"] = {"status": "REJECTED", "reason": "ADAPTER_ODD_REASON_7"}
    doc["evidence"] = {"status": "NOT_VERIFIED", "manifest_ref": None, "screenshot_ref": None}
    doc["unknown_reasons"] = ["COMPARISON_NOT_RUN", "ADAPTER_ODD_REASON_7"]
    return doc


def unknown_doc():
    doc = checked_doc()
    doc["job_id"] = None
    doc["attempt_id"] = None
    doc["bridge"] = {"status": "UNKNOWN", "reason": None}
    doc["evidence"] = {"status": "NOT_VERIFIED", "manifest_ref": None, "screenshot_ref": None}
    doc["unknown_reasons"] = ["COMPARISON_NOT_RUN"]
    return doc


def mutated(base, fn):
    doc = base()
    fn(doc)
    return doc


def differential_cases():
    """(name, bytes) pairs: valid documents, single-fault mutations, hostile raw inputs."""
    cases = []

    def add(name, value):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
        cases.append((name, data))

    add("good-checked", checked_doc())
    add("good-rejected", rejected_doc())
    add("good-unknown", unknown_doc())
    add("good-unknown-with-ids", mutated(unknown_doc, lambda d: d.update(job_id="a", attempt_id="B.c_d-9")))
    add("good-max-id", mutated(unknown_doc, lambda d: d.update(job_id="a" * 64)))
    add("good-128-reasons", mutated(unknown_doc, lambda d: d.update(
        unknown_reasons=["COMPARISON_NOT_RUN"] + ["R%d" % i for i in range(127)])))
    add("good-unicode-screenshot", mutated(checked_doc, lambda d: d["evidence"].update(
        screenshot_ref="job-1/att-1/画面😀.png")))
    add("good-extra-reasons-reordered", mutated(checked_doc, lambda d: d.update(
        unknown_reasons=["X_Y", "PROFILE_UNATTESTED", "COMPARISON_NOT_RUN"])))
    add("good-rejected-with-ids", mutated(rejected_doc, lambda d: d.update(job_id="j", attempt_id="a")))

    for key, value in (("schema_version", "siteproof.offline-result.v2"), ("record_type", "X"),
                       ("source", "TRUSTED_ISSUER"), ("profile_trust", "ATTESTED"),
                       ("eligibility", "ELIGIBLE"), ("comparison", "PASS"),
                       ("comparison", "CHANGED"), ("human_approval", "APPROVED"),
                       ("notice", NOTICE + " "), ("notice", "")):
        add("fixed-%s-%s" % (key, value[:8]), mutated(checked_doc, lambda d, k=key, v=value: d.update({k: v})))
    for key in sorted(TOP_KEYS):
        add("missing-" + key, mutated(checked_doc, lambda d, k=key: d.pop(k)))
    add("extra-key", mutated(checked_doc, lambda d: d.update(extra="x")))
    add("extra-bridge-key", mutated(checked_doc, lambda d: d["bridge"].update(extra=1)))
    add("extra-evidence-key", mutated(checked_doc, lambda d: d["evidence"].update(extra=None)))
    add("missing-bridge-reason", mutated(checked_doc, lambda d: d["bridge"].pop("reason")))
    add("missing-evidence-ref", mutated(checked_doc, lambda d: d["evidence"].pop("manifest_ref")))
    add("top-level-array", [checked_doc()])
    add("top-level-null", None)
    add("top-level-string", "x")

    for name, fn in (
        ("job-empty", lambda d: d.update(job_id="")),
        ("job-leading-dot", lambda d: d.update(job_id=".a")),
        ("job-65", lambda d: d.update(job_id="a" * 65)),
        ("job-int", lambda d: d.update(job_id=7)),
        ("job-space", lambda d: d.update(job_id="a b")),
        ("job-nonascii-digit", lambda d: d.update(job_id="a١")),
        ("attempt-slash", lambda d: d.update(attempt_id="a/b")),
        ("bridge-null", lambda d: d.update(bridge=None)),
        ("bridge-list", lambda d: d.update(bridge=[])),
        ("bridge-bad-status", lambda d: d["bridge"].update(status="OK")),
        ("bridge-lower-status", lambda d: d["bridge"].update(status="structurally_checked")),
        ("bridge-passed", lambda d: d["bridge"].update(status="PASSED")),
        ("evidence-bad-status", lambda d: d["evidence"].update(status="VERIFIED")),
        ("reason-lowercase", lambda d: d["bridge"].update(reason="bad")),
        ("reason-empty", lambda d: d["bridge"].update(reason="")),
        ("reason-129", lambda d: d["bridge"].update(reason="A" * 129)),
        ("checked-with-reason", lambda d: (d["bridge"].update(reason="X"), d["unknown_reasons"].append("X"))),
        ("checked-job-null", lambda d: d.update(job_id=None)),
        ("checked-attempt-null", lambda d: d.update(attempt_id=None)),
        ("checked-manifest-null", lambda d: d["evidence"].update(manifest_ref=None)),
        ("checked-screenshot-null", lambda d: d["evidence"].update(screenshot_ref=None)),
        ("checked-no-profile-reason", lambda d: d.update(unknown_reasons=["COMPARISON_NOT_RUN"])),
        ("checked-bridge-evidence-mismatch", lambda d: d["evidence"].update(
            status="NOT_VERIFIED", manifest_ref=None, screenshot_ref=None)),
        ("ref-wrong-job", lambda d: d["evidence"].update(manifest_ref="other/att-1/manifest.json")),
        ("ref-wrong-attempt", lambda d: d["evidence"].update(screenshot_ref="job-1/other/shot.png")),
        ("ref-two-parts", lambda d: d["evidence"].update(screenshot_ref="job-1/shot.png")),
        ("ref-four-parts", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/x/shot.png")),
        ("ref-dotdot", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/..")),
        ("ref-dot", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/.")),
        ("ref-empty-name", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/")),
        ("ref-backslash", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a\\b.png")),
        ("ref-colon", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a:b.png")),
        ("ref-control", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a\u0001.png")),
        ("ref-c1-control", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a\u0085.png")),
        ("ref-trailing-dot", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a.")),
        ("ref-trailing-space", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/a ")),
        ("ref-same-as-manifest", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/manifest.json")),
        ("ref-manifest-wrong-name", lambda d: d["evidence"].update(manifest_ref="job-1/att-1/other.json")),
        ("ref-too-long", lambda d: d["evidence"].update(screenshot_ref="job-1/att-1/" + "a" * 4090)),
        ("ref-url", lambda d: d["evidence"].update(screenshot_ref="https://example.invalid/x.png")),
        ("ref-int", lambda d: d["evidence"].update(screenshot_ref=1)),
        ("not-verified-with-ref", lambda d: d["evidence"].update(manifest_ref="job-1/att-1/manifest.json")),
        ("reasons-empty", lambda d: d.update(unknown_reasons=[])),
        ("reasons-missing-not-run", lambda d: d.update(unknown_reasons=["PROFILE_UNATTESTED"])),
        ("reasons-duplicate", lambda d: d.update(
            unknown_reasons=["COMPARISON_NOT_RUN", "PROFILE_UNATTESTED", "COMPARISON_NOT_RUN"])),
        ("reasons-lowercase", lambda d: d["unknown_reasons"].append("low")),
        ("reasons-129", lambda d: d.update(
            unknown_reasons=["COMPARISON_NOT_RUN", "PROFILE_UNATTESTED"] + ["R%d" % i for i in range(127)])),
        ("reasons-not-list", lambda d: d.update(unknown_reasons="COMPARISON_NOT_RUN")),
        ("reasons-non-string", lambda d: d["unknown_reasons"].append(5)),
        ("reasons-null-item", lambda d: d["unknown_reasons"].append(None)),
    ):
        add("mut-" + name, mutated(checked_doc, fn))

    for name, fn in (
        ("rejected-reason-null", lambda d: d["bridge"].update(reason=None)),
        ("rejected-reason-not-in-list", lambda d: d.update(unknown_reasons=["COMPARISON_NOT_RUN"])),
        ("rejected-with-refs", lambda d: d["evidence"].update(
            manifest_ref="job-1/att-1/manifest.json", screenshot_ref="job-1/att-1/s.png")),
        ("rejected-evidence-checked", lambda d: d["evidence"].update(status="STRUCTURALLY_CHECKED")),
    ):
        add("rej-" + name, mutated(rejected_doc, fn))
    for name, fn in (
        ("unknown-with-reason", lambda d: (d["bridge"].update(reason="X"), d["unknown_reasons"].append("X"))),
        ("unknown-evidence-checked", lambda d: d["evidence"].update(status="STRUCTURALLY_CHECKED")),
    ):
        add("unk-" + name, mutated(unknown_doc, fn))

    good = json.dumps(checked_doc(), ensure_ascii=False)
    # Raw / hostile inputs.
    add("raw-empty", b"")
    add("raw-whitespace", b"  \n")
    add("raw-bom", b"\xef\xbb\xbf" + good.encode("utf-8"))
    add("raw-invalid-utf8", good.encode("utf-8").replace(b"job-1", b"job\xff1", 1))
    add("raw-overlong-utf8", good.encode("utf-8").replace(b"job-1", b"job\xc0\xaf", 1))
    add("raw-trailing-garbage", (good + " x").encode("utf-8"))
    add("raw-trailing-comma", good.replace("}}", "},}", 1).encode("utf-8"))
    add("raw-two-docs", (good + good).encode("utf-8"))
    add("raw-truncated", good[:-5].encode("utf-8"))
    add("raw-trailing-ws-ok", (good + " \r\n\t").encode("utf-8"))
    add("raw-single-quotes", good.replace('"', "'").encode("utf-8"))
    add("raw-comment", ("/*x*/" + good).encode("utf-8"))
    add("raw-dup-top", good.replace('"job_id": "job-1"', '"job_id": "job-1", "job_id": "job-1"').encode("utf-8"))
    add("raw-dup-escaped", good.replace('"job_id": "job-1"', '"job_id": "job-1", "job\\u005fid": "job-1"').encode("utf-8"))
    add("raw-dup-nested", good.replace('"reason": null', '"reason": null, "reason": null').encode("utf-8"))
    add("raw-dup-surrogate-pair-key", good.replace('"job_id"', '"job_id", "\\ud83d\\ude00": 1, "\\ud83d\\ude00"', 1).encode("utf-8"))
    add("raw-escaped-key-ok", good.replace('"job_id"', '"job\\u005fid"').encode("utf-8"))
    add("raw-escaped-value-ok", good.replace('"job-1"', '"job\\u002d1"', 1).encode("utf-8"))
    add("raw-nan", good.replace('"job_id": "job-1"', '"job_id": NaN').encode("utf-8"))
    add("raw-infinity", good.replace('"job_id": "job-1"', '"job_id": Infinity').encode("utf-8"))
    add("raw-number", good.replace('"job_id": "job-1"', '"job_id": 1').encode("utf-8"))
    add("raw-true", good.replace('"job_id": "job-1"', '"job_id": true').encode("utf-8"))
    add("raw-lone-high", good.replace('"job-1"', '"job\\ud800"', 1).encode("utf-8"))
    add("raw-lone-low-in-ref", good.replace("shot.png", "shot\\udc00.png").encode("utf-8"))
    add("raw-valid-pair-escape", good.replace("shot.png", "s\\ud83d\\ude00.png").encode("utf-8"))
    add("raw-nul-escape-in-ref", good.replace("shot.png", "s\\u0000.png").encode("utf-8"))
    add("raw-raw-tab-in-string", good.replace("shot.png", "s\t.png").encode("utf-8"))
    add("raw-bad-escape", good.replace("shot.png", "s\\x.png").encode("utf-8"))
    add("raw-deep-array", b"[" * 100000)
    add("raw-deep-balanced", b"[" * 50000 + b"]" * 50000)
    add("raw-deep-object", b'{"a":' * 50000 + b"1" + b"}" * 50000)
    add("raw-deep-in-field", good.replace('"reason": null', '"reason": ' + "[" * 5000 + "]" * 5000).encode("utf-8"))
    add("raw-oversize", b" " * (1048576 + 1))
    add("raw-oversize-valid-prefix", good.encode("utf-8") + b" " * (1048576 - len(good.encode("utf-8")) + 1))
    add("raw-exact-limit", good.encode("utf-8") + b" " * (1048576 - len(good.encode("utf-8"))))
    add("raw-huge-string", good.replace("shot.png", "a" * 1000000).encode("utf-8"))
    add("raw-many-keys", ("{" + ",".join('"k%d":null' % i for i in range(5000)) + "}").encode("utf-8"))
    return cases


# --------------------------------------------------------------------------
# Node harness: fake DOM from the real markup, mock FileReader, real app.js
# --------------------------------------------------------------------------
HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const J = (value) => JSON.parse(JSON.stringify(value));

class El {
  constructor(doc, tag) {
    this.doc = doc;
    this.tagName = tag.toUpperCase();
    this.attrs = new Map();
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this.ownText = '';
    this.files = [];
    this.value = '';
  }
  getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
  setAttribute(name, value) { this.attrs.set(name, String(value)); }
  removeAttribute(name) { this.attrs.delete(name); }
  hasAttribute(name) { return this.attrs.has(name); }
  get id() { return this.getAttribute('id') || ''; }
  get textContent() { return this.ownText + this.children.map((c) => c.textContent).join(''); }
  set textContent(value) {
    for (const child of this.children) { child.parent = null; }
    this.children = [];
    this.ownText = String(value);
  }
  set innerHTML(_v) { throw new Error('innerHTML must never be used'); }
  set outerHTML(_v) { throw new Error('outerHTML must never be used'); }
  appendChild(child) {
    if (child.parent) { child.parent.children.splice(child.parent.children.indexOf(child), 1); }
    child.parent = this;
    this.children.push(child);
    return child;
  }
  contains(node) { for (let n = node; n; n = n.parent) { if (n === this) { return true; } } return false; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  isHidden() { for (let n = this; n; n = n.parent) { if (n.hasAttribute('hidden')) { return true; } } return false; }
  focus() { if (!this.isHidden()) { this.doc._active = this; } }
  walk(fn) { fn(this); this.children.forEach((c) => c.walk(fn)); }
}

class Doc {
  constructor(trees) {
    this.body = new El(this, 'body');
    this._active = null;
    this.createdTags = [];
    this.inputs = [];
    this.pickerCalls = 0;
    this.showPicker = true;
    for (const tree of trees) { this.body.appendChild(this.build(tree)); }
  }
  build(node) {
    const el = new El(this, node.tag);
    for (const [k, v] of Object.entries(node.attrs)) { el.setAttribute(k, v); }
    el.ownText = node.text || '';
    node.children.forEach((c) => el.appendChild(this.build(c)));
    return el;
  }
  getElementById(id) {
    let found = null;
    this.body.walk((el) => { if (!found && el.getAttribute('id') === id) { found = el; } });
    return found;
  }
  createElement(tag) {
    const t = String(tag).toLowerCase();
    this.createdTags.push(t);
    const el = new El(this, t);
    if (t === 'input') {
      this.inputs.push(el);
      if (this.showPicker) { el.showPicker = () => { this.pickerCalls++; }; }
    }
    return el;
  }
}

function snapshot(el) {
  return JSON.stringify({ t: el.tagName, a: Array.from(el.attrs.entries()), o: el.ownText, c: el.children.map(snapshot) });
}

const toAB = (buf) => { const b = Buffer.from(buf); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };
const enc = (value) => toAB(Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8'));

const NOTICE = FIXTURE.notice;
const checkedDoc = () => J(FIXTURE.checked);
const rejectedDoc = () => J(FIXTURE.rejected);
const unknownDoc = () => J(FIXTURE.unknown);

function load(options = {}) {
  const trees = options.viewerOnly ? [VIEWER_TREE] : [FLOW_TREE, VIEWER_TREE];
  const doc = new Doc(trees);
  if (options.showPicker === false) { doc.showPicker = false; }
  const readers = [];
  const log = { constructed: 0, networkTouched: [] };
  class MockReader {
    constructor() {
      log.constructed++;
      if (options.readerThrows) { throw new Error('no reader'); }
      this.state = 'idle'; this.result = null; this.aborted = false; this.file = null;
      this.onload = null; this.onerror = null; this.onabort = null;
      readers.push(this);
    }
    readAsArrayBuffer(file) {
      if (options.readThrows) { throw new Error('read failed'); }
      this.state = 'loading'; this.file = file;
    }
    abort() {
      if (this.state === 'loading') { this.state = 'aborted'; this.aborted = true; if (this.onabort) { this.onabort({}); } }
    }
    // Test drivers: deliver a late/arbitrary callback regardless of state (race simulation).
    deliver(value) { this.state = 'done'; this.result = value; if (this.onload) { this.onload({}); } }
    break_() { this.state = 'error'; if (this.onerror) { this.onerror({}); } }
  }
  const sandbox = {
    document: doc,
    module: { exports: {} },
    TextDecoder,
    setTimeout: () => { log.networkTouched.push('setTimeout'); },
    setInterval: () => { log.networkTouched.push('setInterval'); }
  };
  if (!options.noFileReader) { sandbox.FileReader = MockReader; }
  const initialKeys = Object.keys(sandbox).sort();
  vm.runInNewContext(fs.readFileSync(APP_PATH, 'utf8'), sandbox, { filename: 'app.js' });
  const $ = (id) => doc.getElementById(id);
  const press = (el) => {
    assert.ok(el, 'press: element exists');
    if (el.isHidden()) { return false; }
    el.focus();
    for (const fn of (el.listeners.click || []).slice()) { fn({ type: 'click', target: el }); }
    return true;
  };
  const api = () => sandbox.module.exports.offlineResultViewer;
  const select = () => press($('rv-select'));
  const input = () => doc.inputs[0];
  // The user picks `file` (a {name,size} object) in the open picker.
  const pick = (file, list) => {
    const i = input();
    i.files = list || [file];
    for (const fn of (i.listeners.change || []).slice()) { fn({ type: 'change', target: i }); }
  };
  const cancel = () => { for (const fn of (input().listeners.cancel || []).slice()) { fn({ type: 'cancel' }); } };
  const fileFor = (ab, name) => ({ name: name || 'result.json', size: ab.byteLength });
  // Whole user journey: press select, pick a file, let the (only newest) reader finish.
  const open = (value) => {
    const ab = value instanceof ArrayBuffer ? value : enc(value);
    select();
    const before = readers.length;
    pick(fileFor(ab));
    if (readers.length > before) { readers[readers.length - 1].deliver(ab); }
  };
  const shown = () => !$('rv-result').hasAttribute('hidden');
  const dynamicIds = ['v-source','v-job','v-attempt','v-bridge','n-bridge','v-reason','v-profile','v-eligibility',
    'v-comparison','v-approval','v-evidence','n-evidence','v-manifest','v-screenshot','v-unknown','v-notice'];
  const assertNoReport = (why) => {
    assert.equal(shown(), false, 'result hidden: ' + why);
    for (const id of dynamicIds) { assert.equal($('rv-' + id).textContent, '', id + ' empty: ' + why); }
  };
  return { doc, sandbox, readers, log, initialKeys, $, press, api, select, input, pick, cancel, fileFor, open,
           shown, assertNoReport, dynamicIds };
}
"""


@unittest.skipIf(NODE is None, "node is not installed; Node-driven tests skipped")
class NodeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = parse_html((HOME_DIR / "index.html").read_text(encoding="utf-8"))
        by_id = {n.attrs["id"]: n for n in root.walk() if "id" in n.attrs}
        cls.viewer_json = json.dumps(by_id["result-viewer"].to_json())
        cls.flow_json = json.dumps(by_id["flow-demo"].to_json())
        cls.fixture = json.dumps({"notice": NOTICE, "checked": checked_doc(),
                                  "rejected": rejected_doc(), "unknown": unknown_doc()})

    def run_js(self, body, extra=""):
        script = ("'use strict';\n"
                  f"const APP_PATH = {json.dumps(str(APP_JS))};\n"
                  f"const VIEWER_TREE = {self.viewer_json};\n"
                  f"const FLOW_TREE = {self.flow_json};\n"
                  f"const FIXTURE = {self.fixture};\n"
                  f"{extra}\n{HARNESS}\n"
                  "try {\n" + body + "\n} catch (error) {\n"
                  "  console.error(error && error.stack ? error.stack : String(error));\n"
                  "  process.exit(1);\n}\n"
                  "console.log('SCENARIO_OK');\n")
        proc = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                              encoding="utf-8", cwd=str(REPO_ROOT), timeout=120)
        self.assertEqual(proc.returncode, 0, f"node exit {proc.returncode}\n{proc.stderr}")
        self.assertIn("SCENARIO_OK", proc.stdout)
        return proc.stdout


# --------------------------------------------------------------------------
# Static checks of the shipped markup / script text
# --------------------------------------------------------------------------
class ViewerStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (HOME_DIR / "index.html").read_text(encoding="utf-8")
        cls.root = parse_html(cls.html)
        cls.nodes = list(cls.root.walk())
        cls.viewer = next(n for n in cls.nodes if n.attrs.get("id") == "result-viewer")
        cls.js_src = APP_JS.read_text(encoding="utf-8")
        cls.js = strip_js_comments(cls.js_src)

    def by_id(self, ident):
        return next(n for n in self.nodes if n.attrs.get("id") == ident)

    def test_no_input_or_form_in_static_html(self):
        self.assertFalse([n for n in self.nodes if n.tag in ("input", "form", "textarea")])
        self.assertNotIn("<input", self.html.lower())

    def test_select_button_is_a_labelled_native_button_with_help(self):
        button = self.by_id("rv-select")
        self.assertEqual(button.tag, "button")
        self.assertEqual(button.attrs.get("type"), "button")
        self.assertNotIn("disabled", button.attrs)
        self.assertTrue(button.text())
        self.assertIn(self.by_id(button.attrs["aria-describedby"]), list(self.viewer.walk()))

    def test_live_regions_declared_empty_and_app_hidden_until_script(self):
        status, error = self.by_id("rv-status"), self.by_id("rv-error")
        self.assertEqual((status.attrs.get("role"), status.attrs.get("aria-live")), ("status", "polite"))
        self.assertEqual(error.attrs.get("role"), "alert")
        self.assertEqual((status.text(), error.text()), ("", ""))
        self.assertIn("hidden", self.by_id("rv-app").attrs)
        self.assertIn("hidden", self.by_id("rv-result").attrs)
        self.assertNotIn("hidden", self.by_id("rv-nojs").attrs)

    def test_untrusted_and_safety_markers_always_visible_outside_script_controlled_area(self):
        app = self.by_id("rv-app")
        outside = [n for n in self.viewer.walk() if n is not app and app not in list(_ancestors(n))]
        text = " ".join(n.text() for n in outside)
        for needle in (UNTRUSTED, "S1 DB", "manifest", "スクリーンショット", "検証していません",
                       "OFFLINE REPORT / UNTRUSTED FILE", "LOCAL-ISOLATION NOT VERIFIED", "AWS LIVE NO-GO"):
            self.assertIn(needle, text, needle)
        # A user-selected report is not synthetic sample data and must not be labelled as such.
        self.assertNotIn("SAMPLE DATA", text)
        # And again inside the report itself.
        self.assertIn(UNTRUSTED, self.by_id("rv-result").text())

    def test_static_markup_ships_no_report_values(self):
        for ident in ("v-source", "v-job", "v-attempt", "v-bridge", "v-reason", "v-profile", "v-eligibility",
                      "v-comparison", "v-approval", "v-evidence", "v-manifest", "v-screenshot", "v-notice"):
            self.assertEqual(self.by_id("rv-" + ident).text(), "", ident)
        self.assertEqual(self.by_id("rv-v-unknown").children, [])

    def test_dimensions_have_separate_rows(self):
        labels = [n.text() for n in self.viewer.walk() if n.tag == "dt"]
        for needed in ("報告元", "ジョブ", "試行", "ブリッジ結果", "プロファイル信頼", "適格性", "差分比較",
                       "人の承認", "証跡の構造状態", "manifest 参照", "スクリーンショット参照",
                       "不明の理由", "注記", "HOME による検証"):
            self.assertTrue(any(needed in label for label in labels), needed)
        self.assertNotIn("PASS", self.by_id("rv-result").text())
        self.assertNotIn("APPROVED", self.by_id("rv-result").text())

    def test_original_page_structure_untouched(self):
        classes = [c for n in self.nodes for c in (n.attrs.get("class") or "").split()]
        self.assertEqual(classes.count("status-card"), 4)
        self.assertEqual(classes.count("launcher"), 6)
        self.assertEqual(classes.count("log-row"), 5)
        self.assertEqual(self.by_id("aws-sample").tag, "section")
        self.assertIn("flow-demo", [n.attrs.get("id") for n in self.nodes])
        self.assertEqual(len([n for n in self.nodes if n.tag == "script"]), 1)

    def test_script_has_no_network_storage_navigation_or_html_injection(self):
        for pattern in (r"\bfetch\b", r"XMLHttpRequest", r"WebSocket", r"EventSource", r"sendBeacon",
                        r"localStorage", r"sessionStorage", r"indexedDB", r"document\.cookie",
                        r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"\.click\(\)",
                        r"\blocation\b", r"window\.open", r"createObjectURL", r"readAsText",
                        r"readAsDataURL", r"showOpenFilePicker", r"https?:", r"\.href\s*=", r"\.src\s*="):
            self.assertIsNone(re.search(pattern, self.js), pattern)
        viewer_part = self.js[self.js.index("Offline result viewer") if "Offline result viewer" in self.js
                              else self.js.index("var MAX_BYTES"):]
        self.assertEqual(len(re.findall(r"new Reader\(\)", viewer_part)), 1)
        self.assertEqual(len(re.findall(r"readAsArrayBuffer", viewer_part)), 1)
        self.assertEqual(len(re.findall(r"createElement\('input'\)", viewer_part)), 1)

    def test_native_file_apis_only_inside_user_handlers(self):
        viewer_part = self.js[self.js.index("var MAX_BYTES"):]
        # Everything that touches the page-global FileReader / creates the input is nested in
        # functions that only run from the select button or the input's own events.
        for needle in ("typeof FileReader", "doc.createElement('input')"):
            index = viewer_part.index(needle)
            self.assertGreater(index, viewer_part.index("function initViewer"), needle)
        self.assertNotRegex(viewer_part, r"\binitViewer\([^)]*\)\s*;\s*\n\s*var\s+\w+\s*=\s*new FileReader")
        self.assertIn("els.select.addEventListener('click', onSelect)", viewer_part)

    def test_exports_extend_without_replacing_flow_api(self):
        self.assertIn("module.exports.offlineResultViewer = {", self.js)
        self.assertEqual(self.js.count("module.exports = {"), 1)


def _ancestors(node):
    node = node.parent
    while node is not None:
        yield node
        node = node.parent


# --------------------------------------------------------------------------
# Runtime behaviour
# --------------------------------------------------------------------------
class ViewerStartupTests(NodeCase):
    def test_startup_creates_no_input_or_reader_and_shows_nothing(self):
        self.run_js(r"""
const L = load();
assert.equal(L.doc.inputs.length, 0);
assert.equal(L.log.constructed, 0);
assert.ok(!L.doc.createdTags.includes('input'));
assert.equal(L.$('rv-app').hasAttribute('hidden'), false, 'enabled by script');
assert.equal(L.$('rv-nojs').hasAttribute('hidden'), true);
assert.equal(L.$('rv-status').textContent, '');
assert.equal(L.$('rv-error').textContent, '');
L.assertNoReport('startup');
assert.deepEqual(L.log.networkTouched, []);
assert.deepEqual(Object.keys(L.sandbox).sort(), L.initialKeys, 'no new globals');
""")

    def test_viewer_absent_returns_safely_and_flow_api_is_preserved(self):
        self.run_js(r"""
const bare = new Doc([FLOW_TREE]);
const sandbox = { document: bare, module: { exports: {} }, TextDecoder };
vm.runInNewContext(fs.readFileSync(APP_PATH, 'utf8'), sandbox, { filename: 'app.js' });
const api = sandbox.module.exports;
assert.equal(api.offlineResultViewer.instance, null);
assert.equal(bare.createdTags.length, 0);
for (const key of ['createFlowModel', 'createSyntheticClock', 'initFlowUi', 'instance', 'scenarios', 'maxJobs']) {
  assert.ok(key in api, key);
}
assert.ok(api.instance, 'synthetic flow still initialised');
const viewerOnly = load({ viewerOnly: true });
assert.ok(viewerOnly.api().instance, 'viewer initialised alone');
assert.equal(viewerOnly.sandbox.module.exports.instance, null, 'no flow without its markup');
""")

    def test_fails_closed_when_viewer_markup_is_incomplete(self):
        self.run_js(r"""
const without = (node, id) => ({ ...node, children: node.children.filter((c) => c.attrs.id !== id).map((c) => without(c, id)) });
const doc = new Doc([without(VIEWER_TREE, 'rv-error')]);
const sandbox = { document: doc, module: { exports: {} }, TextDecoder };
vm.runInNewContext(fs.readFileSync(APP_PATH, 'utf8'), sandbox, { filename: 'app.js' });
assert.equal(sandbox.module.exports.offlineResultViewer.instance, null);
assert.equal(doc.getElementById('rv-app').hasAttribute('hidden'), true);
assert.equal(doc.getElementById('rv-nojs').hasAttribute('hidden'), false);
assert.equal(doc.getElementById('rv-select').listeners.click, undefined);
""")

    def test_constants_match_contract(self):
        self.run_js(r"""
const L = load();
const v = L.api();
assert.equal(v.maxBytes, 1048576);
assert.equal(v.notice, NOTICE);
assert.deepEqual(J(v.fixed), {
  schema_version: 'siteproof.offline-result.v1', record_type: 'OFFLINE_RESULT', source: 'OFFLINE_PROJECTION',
  profile_trust: 'UNATTESTED', eligibility: 'UNKNOWN', comparison: 'NOT_RUN', human_approval: 'NOT_RECORDED' });
""")


class ViewerDisplayTests(NodeCase):
    def test_press_opens_exactly_one_input_lazily_and_reuses_it(self):
        self.run_js(r"""
const L = load();
L.select();
assert.equal(L.doc.inputs.length, 1);
assert.equal(L.doc.pickerCalls, 1);
const input = L.input();
assert.equal(input.getAttribute('type'), 'file');
assert.ok(input.getAttribute('aria-label'));
assert.equal(input.hasAttribute('multiple'), false);
assert.equal(L.log.constructed, 0, 'no reader before a file is chosen');
L.select(); L.select();
assert.equal(L.doc.inputs.length, 1, 'one input is reused');
assert.equal(L.log.constructed, 0);
assert.ok(L.doc._active === L.$('rv-select'), 'focus stays on the native button');
""")

    def test_fallback_shows_native_control_when_picker_cannot_open(self):
        self.run_js(r"""
const L = load({ showPicker: false });
L.select();
assert.equal(L.doc.inputs.length, 1);
assert.equal(L.$('rv-picker-slot').children.length, 1);
assert.equal(L.$('rv-picker-slot').children[0], L.input());
assert.match(L.$('rv-status').textContent, /ファイル選択欄/);
L.select();
assert.equal(L.$('rv-picker-slot').children.length, 1);
""")

    def test_checked_report_shows_claims_separately_and_as_untrusted(self):
        self.run_js(r"""
const L = load();
L.open(checkedDoc());
assert.ok(L.shown());
const t = (id) => L.$('rv-' + id).textContent;
assert.equal(t('v-source'), 'OFFLINE_PROJECTION');
assert.equal(t('v-job'), 'job-1');
assert.equal(t('v-attempt'), 'att-1');
assert.equal(t('v-bridge'), 'STRUCTURALLY_CHECKED');
assert.equal(t('v-reason'), '（なし）');
assert.equal(t('v-profile'), 'UNATTESTED');
assert.equal(t('v-eligibility'), 'UNKNOWN');
assert.equal(t('v-comparison'), 'NOT_RUN');
assert.equal(t('v-approval'), 'NOT_RECORDED');
assert.equal(t('v-evidence'), 'STRUCTURALLY_CHECKED');
assert.equal(t('v-manifest'), 'job-1/att-1/manifest.json');
assert.equal(t('v-screenshot'), 'job-1/att-1/shot.png');
assert.equal(t('v-notice'), NOTICE);
assert.deepEqual(L.$('rv-v-unknown').children.map((c) => c.textContent), ['COMPARISON_NOT_RUN', 'PROFILE_UNATTESTED']);
assert.notEqual(L.$('rv-v-profile').id, L.$('rv-v-eligibility').id);
assert.match(t('n-bridge'), /主張/);
assert.match(t('n-bridge'), /検証していません/);
assert.match(t('n-evidence'), /主張/);
assert.match(L.$('rv-result').textContent, /ローカルファイルから読み込んだ未認証レポート/);
assert.match(L.$('rv-result').textContent, /NOT VERIFIED/);
assert.match(L.$('rv-status').textContent, /未認証レポート/);
assert.match(L.$('rv-status').textContent, /検証していません/);
assert.equal(L.$('rv-error').textContent, '');
assert.equal(L.$('rv-v-bridge').getAttribute('class').includes('st-pass'), false);
assert.doesNotMatch(L.$('rv-result').textContent, /APPROVED|PASS\b/);
assert.doesNotMatch(L.$('rv-result').textContent.replace(/NOT VERIFIED/g, ''), /VERIFIED/);
assert.deepEqual(Array.from(new Set(L.doc.createdTags)).filter((x) => x !== 'li' && x !== 'button' && x !== 'span').sort(), ['input']);
assert.equal(L.log.constructed, 1);
assert.deepEqual(L.log.networkTouched, []);
""")

    def test_rejected_report_preserves_unmapped_reason_code(self):
        self.run_js(r"""
const L = load();
L.open(rejectedDoc());
assert.ok(L.shown());
assert.equal(L.$('rv-v-bridge').textContent, 'REJECTED');
assert.equal(L.$('rv-v-reason').textContent, 'ADAPTER_ODD_REASON_7');
assert.equal(L.$('rv-v-evidence').textContent, 'NOT_VERIFIED');
assert.equal(L.$('rv-v-manifest').textContent, '（なし）');
assert.equal(L.$('rv-v-screenshot').textContent, '（なし）');
assert.ok(L.$('rv-v-unknown').children.map((c) => c.textContent).includes('ADAPTER_ODD_REASON_7'));
assert.doesNotMatch(L.$('rv-v-bridge').getAttribute('class'), /st-pass|st-completed|st-approved/);
assert.equal(L.$('rv-v-profile').textContent, 'UNATTESTED');
assert.equal(L.$('rv-v-comparison').textContent, 'NOT_RUN');
""")

    def test_unknown_report_with_null_ids(self):
        self.run_js(r"""
const L = load();
L.open(unknownDoc());
assert.ok(L.shown());
assert.equal(L.$('rv-v-bridge').textContent, 'UNKNOWN');
assert.equal(L.$('rv-v-job').textContent, '（なし）');
assert.equal(L.$('rv-v-attempt').textContent, '（なし）');
assert.equal(L.$('rv-v-evidence').textContent, 'NOT_VERIFIED');
assert.match(L.$('rv-n-bridge').textContent, /成功とはみなしません/);
assert.equal(L.$('rv-v-unknown').children.length, 1);
""")

    def test_hostile_text_is_inert_textcontent_only(self):
        self.run_js(r"""
const L = load();
const d = checkedDoc();
d.evidence.screenshot_ref = 'job-1/att-1/<img src=x onerror=alert(1)>&amp;<script>.png';
L.open(d);
assert.ok(L.shown());
assert.equal(L.$('rv-v-screenshot').textContent, 'job-1/att-1/<img src=x onerror=alert(1)>&amp;<script>.png');
assert.equal(L.$('rv-v-screenshot').children.length, 0);
const created = new Set(L.doc.createdTags);
assert.deepEqual(Array.from(created).sort(), ['input', 'li']);
// No anchors/images/iframes/links anywhere in the viewer after rendering.
const bad = [];
L.$('rv-result').walk((el) => { if (['A', 'IMG', 'IFRAME', 'SCRIPT', 'OBJECT', 'EMBED', 'LINK'].includes(el.tagName)) { bad.push(el.tagName); } });
assert.deepEqual(bad, []);
for (const key of ['href', 'src']) {
  L.$('rv-result').walk((el) => assert.equal(el.hasAttribute(key), false));
}
// Hostile reason-like strings cannot get past the code pattern.
const e = checkedDoc(); e.bridge.reason = '<b>X</b>'; e.unknown_reasons.push('<b>X</b>');
const L2 = load(); L2.open(e);
L2.assertNoReport('hostile reason');
""")

    def test_errors_are_fixed_texts_and_never_echo_file_content(self):
        self.run_js(r"""
const L = load();
const d = checkedDoc(); d.human_approval = 'APPROVED_BY_ATTACKER'; d.comparison = 'PASS';
L.open(d);
L.assertNoReport('spoof');
const err = L.$('rv-error').textContent;
assert.ok(err.length > 0);
assert.doesNotMatch(err, /ATTACKER|APPROVED|PASS/);
assert.equal(L.$('rv-error').getAttribute('role'), 'alert');
""")


class ViewerRejectionTests(NodeCase):
    def test_spoofed_trust_comparison_and_approval_are_rejected(self):
        self.run_js(r"""
const spoofs = [
  ['profile_trust', 'ATTESTED'], ['profile_trust', 'VERIFIED'], ['eligibility', 'ELIGIBLE'],
  ['eligibility', 'OK'], ['comparison', 'PASS'], ['comparison', 'CHANGED'], ['comparison', 'UNCHANGED'],
  ['human_approval', 'APPROVED'], ['human_approval', 'REJECTED'], ['source', 'TRUSTED_ISSUER'],
  ['record_type', 'SIGNED_RESULT'], ['schema_version', 'siteproof.offline-result.v2'],
  ['notice', NOTICE + 'verified'],
];
for (const [key, value] of spoofs) {
  const L = load();
  const d = checkedDoc(); d[key] = value;
  L.open(d);
  L.assertNoReport(key + '=' + value);
  assert.notEqual(L.$('rv-error').textContent, '', key);
}
// Nested spoof attempts: bridge/evidence cannot carry extra "verified"/"approved" members.
for (const mut of [(d) => { d.bridge.verified = true; }, (d) => { d.evidence.approved = 'APPROVED'; },
                   (d) => { d.quality = 'PASS'; }, (d) => { d.human_approval_record = {}; }]) {
  const L = load(); const d = checkedDoc(); mut(d); L.open(d); L.assertNoReport('extra member');
}
""")

    def test_malformed_and_hostile_inputs_fail_closed(self):
        self.run_js(r"""
const good = JSON.stringify(checkedDoc());
const bad = {
  empty: '',
  bom: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(good)]),
  invalidUtf8: Buffer.concat([Buffer.from(good.slice(0, good.indexOf('job-1'))), Buffer.from([0xff]),
    Buffer.from(good.slice(good.indexOf('job-1') + 4))]),
  truncated: good.slice(0, -4),
  trailing: good + ' x',
  twoDocs: good + good,
  dupKey: good.replace('"job_id":"job-1"', '"job_id":"job-1","job_id":"job-1"'),
  dupEscaped: good.replace('"job_id":"job-1"', '"job_id":"job-1","job\\u005fid":"job-1"'),
  dupNested: good.replace('"reason":null', '"reason":null,"reason":null'),
  nan: good.replace('"job_id":"job-1"', '"job_id":NaN'),
  infinity: good.replace('"job_id":"job-1"', '"job_id":Infinity'),
  negInfinity: good.replace('"job_id":"job-1"', '"job_id":-Infinity'),
  number: good.replace('"job_id":"job-1"', '"job_id":1'),
  boolean: good.replace('"job_id":"job-1"', '"job_id":false'),
  loneSurrogate: good.replace('job-1', 'job\\ud800'),
  controlChar: good.replace('shot.png', 's\\u0001.png'),
  rawControl: good.replace('shot.png', 's\t.png'),
  array: '[' + good + ']',
  nullTop: 'null',
  deepArray: '['.repeat(200000),
  deepBalanced: '['.repeat(100000) + ']'.repeat(100000),
  deepObject: '{"a":'.repeat(60000) + '1' + '}'.repeat(60000),
  deepInField: good.replace('"reason":null', '"reason":' + '['.repeat(3000) + ']'.repeat(3000)),
  hugeString: good.replace('shot.png', 'a'.repeat(900000)),
  manyKeys: '{' + Array.from({ length: 4000 }, (_, i) => '"k' + i + '":null').join(',') + '}',
  oversizeBytes: Buffer.alloc(1048577, 0x20),
};
for (const [name, value] of Object.entries(bad)) {
  const L = load();
  L.open(enc(value));
  L.assertNoReport(name);
  assert.notEqual(L.$('rv-error').textContent, '', name);
}
""")

    def test_oversize_file_is_refused_before_any_reader_exists(self):
        self.run_js(r"""
const L = load();
L.select();
L.pick({ name: 'big.json', size: 1048577 });
L.assertNoReport('oversize');
assert.equal(L.log.constructed, 0);
assert.match(L.$('rv-error').textContent, /大きすぎます/);
// A file whose bytes grow past the limit after the size check is still refused.
const ab = new ArrayBuffer(1048577);
L.select();
L.pick({ name: 'grew.json', size: 10 });
L.readers[0].deliver(ab);
L.assertNoReport('grown');
assert.match(L.$('rv-error').textContent, /大きすぎます/);
// Exactly 1 MiB of valid JSON plus padding is accepted.
const text = JSON.stringify(checkedDoc());
const padded = text + ' '.repeat(1048576 - Buffer.byteLength(text));
const L2 = load();
L2.open(enc(padded));
assert.ok(L2.shown());
""")

    def test_empty_and_unusable_file_objects(self):
        self.run_js(r"""
for (const file of [{ name: 'e.json', size: 0 }, { name: 'x.json' }, null]) {
  const L = load();
  L.select();
  L.pick(file, [file]);
  L.assertNoReport('unusable');
  assert.equal(L.log.constructed, 0);
  assert.notEqual(L.$('rv-error').textContent, '');
}
const L = load();
L.select();
L.pick(null, []);
L.assertNoReport('no files');
assert.match(L.$('rv-status').textContent, /選択されませんでした/);
const M = load();
M.select();
M.pick(null, [{ name: 'a', size: 5 }, { name: 'b', size: 5 }]);
M.assertNoReport('two files');
assert.equal(M.log.constructed, 0);
""")


class ViewerLifecycleTests(NodeCase):
    def test_reselecting_or_replacing_never_leaves_a_stale_success(self):
        self.run_js(r"""
const L = load();
L.open(checkedDoc());
assert.ok(L.shown());
L.select();                       // user starts choosing a replacement
L.assertNoReport('replacement picker opened');
assert.match(L.$('rv-status').textContent, /表示されません/);
// ...and picks an invalid replacement
const bad = enc('{"nope":1}');
L.pick(L.fileFor(bad));
L.readers[1].deliver(bad);
L.assertNoReport('invalid replacement');
assert.notEqual(L.$('rv-error').textContent, '');
// valid again: error disappears, new report shown
const ab = enc(rejectedDoc());
L.select(); L.pick(L.fileFor(ab)); L.readers[2].deliver(ab);
assert.ok(L.shown());
assert.equal(L.$('rv-error').textContent, '');
assert.equal(L.$('rv-v-bridge').textContent, 'REJECTED');
assert.equal(L.$('rv-v-manifest').textContent, '（なし）', 'no field from the previous report survives');
assert.equal(L.$('rv-v-unknown').children.length, 2);
""")

    def test_cancel_clears_previous_report_and_late_events_do_nothing(self):
        self.run_js(r"""
const L = load();
L.open(checkedDoc());
L.select();
L.cancel();
L.assertNoReport('cancelled');
assert.match(L.$('rv-status').textContent, /キャンセル/);
assert.equal(L.$('rv-error').textContent, '');
// A cancel while a read is in flight aborts it; its late result is ignored.
const ab = enc(checkedDoc());
L.select(); L.pick(L.fileFor(ab));
const reader = L.readers[L.readers.length - 1];
L.cancel();
assert.equal(reader.aborted, true);
reader.deliver(ab);
L.assertNoReport('late result after cancel');
""")

    def test_direct_native_input_activation_clears_old_report_before_chooser(self):
        self.run_js(r"""
const L = load({ showPicker: false });
L.open(checkedDoc());
assert.ok(L.shown());
assert.ok((L.input().listeners.click || []).length >= 1, 'native input click is bound');
// Direct click/keyboard activation of the visible native input, no cancel event follows.
L.press(L.input());
L.assertNoReport('direct native activation');
assert.equal(L.log.constructed, 1, 'no new read started by activation alone');
// Cancelled chooser without a cancel event leaves nothing stale; no files were chosen.
L.assertNoReport('cancelled without cancel event');
// Normal replacement still works: activation, then change.
const ab = enc(rejectedDoc());
L.press(L.input());
L.pick(L.fileFor(ab));
L.readers[L.readers.length - 1].deliver(ab);
assert.ok(L.shown());
assert.equal(L.$('rv-v-bridge').textContent, 'REJECTED');
// Focus alone does not erase a just-loaded result.
L.input().focus();
assert.ok(L.shown());
// Late callback from a read in flight when the native input is activated is ignored.
const ab2 = enc(checkedDoc());
L.pick(L.fileFor(ab2));
const reader = L.readers[L.readers.length - 1];
L.press(L.input());
reader.deliver(ab2);
L.assertNoReport('late result after native activation');
""")

    def test_stale_read_race_second_selection_wins(self):
        self.run_js(r"""
const L = load();
const a = enc(checkedDoc()), b = enc(rejectedDoc());
L.select();
L.pick(L.fileFor(a, 'a.json'));
const ra = L.readers[0];
L.pick(L.fileFor(b, 'b.json'));       // replacement chosen while A still loading
const rb = L.readers[1];
assert.equal(ra.aborted, true);
ra.deliver(a);                         // A completes late: must be ignored
L.assertNoReport('A late while B loading');
rb.deliver(b);
assert.ok(L.shown());
assert.equal(L.$('rv-v-bridge').textContent, 'REJECTED');
ra.deliver(a);                         // A completes again even later
assert.equal(L.$('rv-v-bridge').textContent, 'REJECTED', 'still B');
ra.break_();
assert.ok(L.shown());
assert.equal(L.$('rv-error').textContent, '');
""")

    def test_stale_read_after_reselect_click_is_ignored(self):
        self.run_js(r"""
const L = load();
const a = enc(checkedDoc());
L.select(); L.pick(L.fileFor(a));
const ra = L.readers[0];
L.select();                            // user presses the button again mid-read
assert.equal(ra.aborted, true);
ra.deliver(a);
L.assertNoReport('stale after reselect');
assert.equal(L.$('rv-error').textContent, '');
""")

    def test_late_success_cannot_overwrite_a_newer_failure(self):
        self.run_js(r"""
const L = load();
const a = enc(checkedDoc());
L.select(); L.pick(L.fileFor(a));
const ra = L.readers[0];
L.pick({ name: 'big', size: 2000000 });   // newer selection fails immediately
const err = L.$('rv-error').textContent;
assert.notEqual(err, '');
ra.deliver(a);
L.assertNoReport('late success after newer failure');
assert.equal(L.$('rv-error').textContent, err);
""")

    def test_read_errors_and_aborts_fail_closed(self):
        self.run_js(r"""
let L = load();
L.open(checkedDoc());
L.select();
const ab = enc(checkedDoc());
L.pick(L.fileFor(ab));
L.readers[1].break_();
L.assertNoReport('read error');
assert.match(L.$('rv-error').textContent, /読み取りに失敗/);
// browser-initiated abort of the current read
L = load(); L.select(); L.pick(L.fileFor(ab)); L.readers[0].state = 'loading'; L.readers[0].abort();
L.assertNoReport('abort');
assert.match(L.$('rv-error').textContent, /中断/);
// reader that cannot be created / started
L = load({ readerThrows: true }); L.select(); L.pick(L.fileFor(ab)); L.assertNoReport('ctor throws');
assert.notEqual(L.$('rv-error').textContent, '');
L = load({ readThrows: true }); L.select(); L.pick(L.fileFor(ab)); L.assertNoReport('read throws');
assert.match(L.$('rv-error').textContent, /読み取りに失敗/);
L = load({ noFileReader: true }); L.select(); L.pick(L.fileFor(ab)); L.assertNoReport('no FileReader');
assert.match(L.$('rv-error').textContent, /読み取れません/);
// a non-buffer result is refused
L = load(); L.select(); L.pick(L.fileFor(ab)); L.readers[0].deliver('plain string'); L.assertNoReport('string result');
L = load(); L.select(); L.pick(L.fileFor(ab)); L.readers[0].deliver(null); L.assertNoReport('null result');
""")

    def test_no_automated_reads_or_timers_after_user_flow(self):
        self.run_js(r"""
const L = load();
L.open(checkedDoc());
L.open(rejectedDoc());
assert.equal(L.doc.inputs.length, 1);
assert.equal(L.log.constructed, 2, 'one reader per explicit selection');
assert.deepEqual(L.log.networkTouched, []);
for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'localStorage', 'sessionStorage', 'indexedDB', 'navigator', 'location']) {
  assert.equal(L.sandbox[name], undefined, name);
}
assert.deepEqual(Object.keys(L.sandbox).sort(), L.initialKeys, 'no new globals');
// a fresh load shows nothing: data lived in memory only
const fresh = load();
fresh.assertNoReport('fresh');
assert.equal(fresh.log.constructed, 0);
""")

    def test_strict_decoder_required_and_used(self):
        self.run_js(r"""
let used = null;
class Spy extends TextDecoder { constructor(label, opts) { super(label, opts); used = opts; } }
const v = load().api();
const ok = v.parseReportBytes(enc(checkedDoc()), Spy);
assert.equal(ok.ok, true);
assert.equal(used.fatal, true);
assert.equal(v.parseReportBytes(enc(checkedDoc()), undefined).code, 'NO_DECODER');
assert.equal(v.parseReportBytes(enc(checkedDoc()), Spy).report.job_id, 'job-1');
assert.ok(Object.isFrozen(ok.report) && Object.isFrozen(ok.report.bridge) && Object.isFrozen(ok.report.unknown_reasons));
assert.equal(Object.getPrototypeOf(v.parseStrictJson('{"__proto__":null}')), null, 'no prototype pollution');
assert.equal(({}).polluted, undefined);
""")


class SyntheticFlowUnchangedTests(NodeCase):
    def test_viewer_use_leaves_synthetic_flow_dom_and_behaviour_untouched(self):
        self.run_js(r"""
const L = load();
const before = snapshot(L.$('flow-demo'));
L.open(checkedDoc());
L.open(rejectedDoc());
L.select(); L.cancel();
L.open({ bad: true });
assert.equal(snapshot(L.$('flow-demo')), before, 'flow subtree identical');
// The synthetic flow still works and the viewer is unaffected by it.
const flow = L.sandbox.module.exports.instance;
assert.ok(flow);
L.$('flow-scenario').value = 'present-pass-changed';
L.press(L.$('flow-add'));
assert.equal(flow.model.getJobs().length, 1);
L.open(unknownDoc());
assert.ok(L.shown());
assert.equal(flow.model.getJobs().length, 1, 'viewer never creates synthetic jobs');
assert.equal(L.$('flow-error').textContent, '');
""")

    def test_flow_never_feeds_the_viewer(self):
        self.run_js(r"""
const L = load();
L.press(L.$('flow-add'));
L.press(L.$('flow-start'));
L.press(L.$('flow-complete'));
L.assertNoReport('flow activity');
assert.equal(L.doc.inputs.length, 0);
assert.equal(L.log.constructed, 0);
assert.equal(L.$('rv-status').textContent, '');
""")


# --------------------------------------------------------------------------
# Differential test: app.js validator vs the independent Python reference
# --------------------------------------------------------------------------
class ValidatorDifferentialTests(NodeCase):
    def test_validator_agrees_with_contract_reference_on_every_case(self):
        cases = differential_cases()
        names = [name for name, _ in cases]
        self.assertEqual(len(names), len(set(names)), "case names unique")
        payload = json.dumps([[name, base64.b64encode(data).decode("ascii")] for name, data in cases])
        out = self.run_js(
            r"""
const v = load({ viewerOnly: true }).api();
const results = {};
for (const [name, b64] of CASES) {
  const bytes = Buffer.from(b64, 'base64');
  const r = v.parseReportBytes(toAB(bytes), TextDecoder);
  results[name] = r.ok ? 'ok' : r.code;
}
console.log('RESULTS=' + JSON.stringify(results));
""", extra=f"const CASES = {payload};")
        results = json.loads(re.search(r"RESULTS=(.*)", out).group(1))
        mismatches = []
        accepted = 0
        for name, data in cases:
            expected = reference_accepts(data)
            actual = results[name] == "ok"
            accepted += actual
            if expected != actual:
                mismatches.append((name, "reference accepts" if expected else "reference rejects", results[name]))
        self.assertEqual(mismatches, [])
        # Sanity: the corpus really contains both outcomes, with the valid ones accepted.
        self.assertGreaterEqual(accepted, 10)
        self.assertGreaterEqual(len(cases) - accepted, 100)
        for name in ("good-checked", "good-rejected", "good-unknown", "raw-escaped-key-ok", "raw-exact-limit"):
            self.assertEqual(results[name], "ok", name)
        for name in ("raw-dup-escaped", "raw-lone-high", "raw-oversize", "raw-deep-array", "raw-bom",
                     "raw-invalid-utf8", "raw-nan", "mut-reasons-missing-not-run"):
            self.assertNotEqual(results[name], "ok", name)

    def test_reference_self_check(self):
        self.assertTrue(reference_valid(checked_doc()))
        self.assertTrue(reference_valid(rejected_doc()))
        self.assertTrue(reference_valid(unknown_doc()))
        self.assertFalse(reference_valid(mutated(checked_doc, lambda d: d.update(comparison="PASS"))))


if __name__ == "__main__":
    unittest.main()

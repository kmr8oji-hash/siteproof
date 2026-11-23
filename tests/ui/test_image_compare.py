"""Tests for the standalone local image compare page (web/compare).

Scope and honesty notes:
  * Python parses web/compare/index.html and styles.css/app.js as text for static
    safety contracts.
  * The real pure logic (header parsing, validation, pixel diff) and the real
    controller (web/compare/app.js, loaded with Node `require`) are executed by the
    installed Node against synthetic byte headers and a hand-written MOCK DOM /
    canvas / Image / Object URL environment. This is NOT a browser: actual
    rendering, native image decoding, colour handling, keyboard/focus behaviour and
    assistive-technology output are NOT verified (UNKNOWN).
  * Node receives its script on stdin (no temp files). If Node is missing the
    Node-driven tests are SKIPPED (reported, not hidden).
  * Standard library only; no network, no browser.
"""

import os
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPARE_DIR = REPO_ROOT / "web" / "compare"
INDEX_HTML = COMPARE_DIR / "index.html"
STYLES_CSS = COMPARE_DIR / "styles.css"
APP_JS = COMPARE_DIR / "app.js"
NODE = shutil.which("node")

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "source", "track", "wbr"}


class Doc(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []      # (tag, attrs dict)
        self.text = []
        self.stack = []
        self.labels_for = set()

    def handle_starttag(self, tag, attrs):
        a = {k: (v if v is not None else "") for k, v in attrs}
        self.tags.append((tag, a))
        if tag == "label" and "for" in a:
            self.labels_for.add(a["for"])
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data):
        if not any(t in ("script", "style") for t in self.stack):
            self.text.append(data)

    def find(self, tag):
        return [a for t, a in self.tags if t == tag]

    def ids(self):
        return {a["id"] for _, a in self.tags if "id" in a}


def load_doc():
    d = Doc()
    d.feed(INDEX_HTML.read_text(encoding="utf-8"))
    d.close()
    return d


class StaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = INDEX_HTML.read_text(encoding="utf-8")
        cls.css = STYLES_CSS.read_text(encoding="utf-8")
        cls.js = APP_JS.read_text(encoding="utf-8")
        cls.doc = load_doc()
        cls.visible = "".join(cls.doc.text)

    def test_files_exist_and_lang_ja(self):
        self.assertEqual(self.doc.find("html")[0].get("lang"), "ja")
        self.assertTrue(any(a.get("charset") == "utf-8" for a in self.doc.find("meta")))

    def test_csp_is_strict_and_meta_only_claims_are_honest(self):
        csp = next(a["content"] for a in self.doc.find("meta")
                   if a.get("http-equiv", "").lower() == "content-security-policy")
        directives = {d.strip().split()[0]: d.strip().split()[1:] for d in csp.split(";") if d.strip()}
        self.assertEqual(directives["default-src"], ["'none'"])
        self.assertEqual(directives["script-src"], ["'self'"])
        self.assertEqual(directives["style-src"], ["'self'"])
        self.assertEqual(directives["connect-src"], ["'none'"])
        self.assertEqual(directives["img-src"], ["blob:"])
        self.assertEqual(directives["base-uri"], ["'none'"])
        self.assertEqual(directives["form-action"], ["'none'"])
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("frame-ancestors", csp)  # ignored in <meta>; must not be claimed as enforced
        self.assertIn("frame-ancestors", self.visible)
        self.assertIn("強制されません", self.visible)

    def test_no_external_resources_or_navigation(self):
        for text in (self.html, self.css, self.js):
            self.assertIsNone(re.search(r"https?://|//cdn|wss?://", text, re.I))
        anchors = self.doc.find("a")
        self.assertEqual([a.get("href") for a in anchors], ["#main", "../home/index.html"])
        self.assertNotIn("url(", self.css)
        self.assertNotIn("@import", self.css)
        self.assertNotIn("@font-face", self.css)
        for tag in ("iframe", "object", "embed", "form", "base"):
            self.assertEqual(self.doc.find(tag), [], tag)
        scripts = self.doc.find("script")
        self.assertEqual([s.get("src") for s in scripts], ["app.js"])
        links = self.doc.find("link")
        self.assertEqual([(l.get("rel"), l.get("href")) for l in links], [("stylesheet", "styles.css")])

    def test_no_inline_handlers_or_styles(self):
        for tag, attrs in self.doc.tags:
            for k in attrs:
                self.assertFalse(k.startswith("on"), (tag, k))
            self.assertNotIn("style", attrs)

    def test_script_has_no_network_storage_or_dynamic_code(self):
        banned = [r"\bfetch\s*\(", r"XMLHttpRequest", r"WebSocket", r"EventSource", r"sendBeacon",
                  r"localStorage", r"sessionStorage", r"indexedDB", r"document\.cookie",
                  r"\beval\s*\(", r"new\s+Function", r"innerHTML", r"outerHTML", r"insertAdjacentHTML",
                  r"document\.write", r"window\.open", r"location\s*[.=]", r"importScripts",
                  r"\bimport\s*\(", r"serviceWorker", r"\.href\s*=", r"\.click\s*\("]
        for pat in banned:
            self.assertIsNone(re.search(pat, self.js), pat)

    def test_file_inputs_labelled_and_restricted(self):
        inputs = self.doc.find("input")
        self.assertEqual({i["id"] for i in inputs}, {"before-input", "after-input"})
        for i in inputs:
            self.assertEqual(i["type"], "file")
            self.assertIn(i["id"], self.doc.labels_for)
            accept = i["accept"]
            for ok in (".png", ".jpg", ".jpeg", ".webp", "image/png", "image/jpeg", "image/webp"):
                self.assertIn(ok, accept)
            self.assertNotIn("capture", i)
            self.assertNotIn("multiple", i)
            self.assertNotIn("webkitdirectory", i)

    def test_live_regions_and_result_initially_hidden(self):
        by_id = {a["id"]: (t, a) for t, a in self.doc.tags if "id" in a}
        self.assertEqual(by_id["status"][1].get("role"), "status")
        self.assertEqual(by_id["alert"][1].get("role"), "alert")
        self.assertIn("hidden", by_id["result"][1])
        self.assertIn("disabled", by_id["compare-button"][1])
        self.assertEqual(by_id["result-heading"][1].get("tabindex"), "-1")
        self.assertIn("aria-label", by_id["diff-canvas"][1])
        for k in ("before", "after"):
            self.assertTrue(by_id[k + "-preview"][1].get("alt"))
            self.assertIn("hidden", by_id[k + "-preview"][1])
        for _, a in self.doc.tags:
            if "id" in a and a["id"].startswith("metric-"):
                pass
        for mid in ("metric-diff", "metric-total", "metric-ratio", "metric-size", "result-note"):
            idx = self.html.index('id="%s"' % mid)
            self.assertEqual(self.html[idx:].split(">", 1)[1].split("<", 1)[0], "", mid)

    def test_every_script_id_exists_in_html(self):
        ids = self.doc.ids()
        for m in re.finditer(r"\$\('([a-z0-9-]+)'\)", self.js):
            self.assertIn(m.group(1), ids, m.group(1))
        for k in ("before", "after"):
            for suffix in re.findall(r"\$\(key \+ '(-[a-z-]+)'\)", self.js):
                self.assertIn(k + suffix, ids)
        self.assertGreaterEqual(len(re.findall(r"\$\(key \+ '", self.js)), 6)

    def test_semantic_safety_labels_present(self):
        for needle in ("LOCAL-ISOLATION NOT VERIFIED", "AWS LIVE NO-GO", "UNATTESTED", "UNKNOWN", "NOT_RUN",
                       "LOCAL TOOL / USER DATA", "SAMPLE", "DEMO", "Baseline", "S2",
                       "不具合が確認された", "自動のリサイズ", "しきい値", "attestation",
                       "アニメーション", "EXIF", "frame-ancestors", "未検証"):
            self.assertIn(needle, self.html, needle)
        for needle in ("LOCAL-ISOLATION NOT VERIFIED", "AWS LIVE NO-GO"):
            self.assertIn(needle, self.visible)

    def test_no_pass_claim_anywhere(self):
        for m in re.finditer(r"PASS", self.html):
            self.assertEqual(self.html[m.start() - 1:m.start() + 10], "（PASS/FAIL）", "only as an explicit negation")
        self.assertNotIn("PASS", self.js)
        self.assertNotIn("承認済み", self.html)
        self.assertNotIn("合格", self.html)

    def test_limits_declared_in_script(self):
        self.assertIn("10 * 1024 * 1024", self.js)
        self.assertIn("MAX_DIM = 4096", self.js)
        self.assertIn("4096 * 4096", self.js)

    def test_css_focus_and_no_blanket_outline_removal(self):
        self.assertIn(":focus-visible", self.css)
        self.assertIn("[hidden]", self.css)
        self.assertIn("--navy: #0b1f4a", self.css)
        self.assertIn("--cyan: #12c8f0", self.css)
        self.assertNotIn("outline: none", self.css.replace(".main:focus { outline: none; }", "").replace("h2:focus { outline: none; }", ""))

    def test_no_home_runtime_import_and_home_unmodified_contract(self):
        # Approved navigation contract: the single static HOME anchor is the only
        # reference to the home page; CSS and JS never reference it.
        self.assertNotIn("home/", self.css + self.js)
        self.assertEqual(self.html.count("../home/index.html"), 1)
        self.assertEqual(self.html.count("home/"), 1)

    def test_no_pycache_written_for_compare_tests(self):
        self.assertFalse((REPO_ROOT / "tests" / "ui" / "__pycache__").exists())


# --------------------------------------------------------------------------
# Node harness
# --------------------------------------------------------------------------
PRELUDE = r"""
'use strict';
const assert = require('node:assert/strict');
const app = require(process.env.APP_JS);
const MiB = 1024 * 1024;
const u8 = (...a) => Uint8Array.from(a);
const cat = (...parts) => { let n = 0; for (const p of parts) n += p.length; const o = new Uint8Array(n); let k = 0; for (const p of parts) { o.set(p, k); k += p.length; } return o; };
const str = s => Uint8Array.from(Array.from(s, c => c.charCodeAt(0)));
const be16 = n => u8((n >>> 8) & 255, n & 255);
const be32 = n => u8((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const le16 = n => u8(n & 255, (n >>> 8) & 255);
const le24 = n => u8(n & 255, (n >>> 8) & 255, (n >>> 16) & 255);
const le32 = n => u8(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);

// ---- synthetic images (headers only; NOT decodable pictures) ----
function pchunk(type, data) { return cat(be32(data.length), str(type), data, u8(0, 0, 0, 0)); }
function png(w, h, o = {}) {
  return cat(u8(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
    pchunk('IHDR', cat(be32(w), be32(h), u8(o.depth ?? 8, o.ct ?? 6, 0, 0, 0))),
    ...(o.pre || []),
    ...(o.noIdat ? [] : [pchunk('IDAT', u8(1, 2, 3, 4))]),
    ...(o.noIend ? [] : [pchunk('IEND', u8())]),
    ...(o.post || []));
}
function tiff(orient) {
  return cat(str('II'), u8(42, 0), le32(8), u8(1, 0), u8(0x12, 0x01, 3, 0, 1, 0, 0, 0, orient, 0, 0, 0), le32(0));
}
function tiffBE(orient) {
  return cat(str('MM'), u8(0, 42), be32(8), u8(0, 1), u8(0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orient, 0, 0), be32(0));
}
function seg(m, data) { return cat(u8(0xff, m), be16(data.length + 2), data); }
function jpeg(w, h, o = {}) {
  const sof = seg(0xc0, cat(u8(8), be16(h), be16(w), u8(1, 1, 0x11, 0)));
  const parts = [u8(0xff, 0xd8)];
  if (o.exif) parts.push(seg(0xe1, cat(str('Exif\0\0'), o.exif)));
  if (o.mpf) parts.push(seg(0xe2, cat(str('MPF\0'), u8(1, 2, 3, 4))));
  if (!o.noSof) parts.push(sof);
  if (o.twoSof) parts.push(sof);
  parts.push(seg(0xda, u8(1, 1, 0, 0, 63, 0)), u8(1, 2, 3, 4));
  if (!o.noEoi) parts.push(u8(0xff, 0xd9));
  return cat(...parts);
}
function wck(type, data) { return cat(str(type), le32(data.length), data, (data.length & 1) ? u8(0) : u8()); }
const vp8d = (w, h) => cat(u8(0x10, 0, 0, 0x9d, 0x01, 0x2a), le16(w), le16(h));
const vp8ld = (w, h) => cat(u8(0x2f), le32((w - 1) + (h - 1) * 16384));
const vp8xd = (cw, ch, flags = 0) => cat(u8(flags, 0, 0, 0), le24(cw - 1), le24(ch - 1));
function riff(chunks, delta = 0) {
  const body = cat(str('WEBP'), ...chunks);
  return cat(str('RIFF'), le32(body.length + delta), body);
}
function webp(kind, w, h, o = {}) {
  if (kind === 'vp8') return riff([wck('VP8 ', vp8d(w, h))], o.delta || 0);
  if (kind === 'vp8l') return riff([wck('VP8L', vp8ld(w, h))], o.delta || 0);
  return riff([wck('VP8X', vp8xd(o.cw ?? w, o.ch ?? h, o.flags || 0)), ...(o.extra || []), ...(o.noImg ? [] : [wck('VP8L', vp8ld(w, h))])], o.delta || 0);
}
const meta = (name, type, bytes) => ({ name, type, size: bytes.length });
const inspect = (name, type, bytes) => app.inspectImage(meta(name, type, bytes), bytes);
const okDims = (r, f, w, h) => { assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.format, f); assert.equal(r.width, w); assert.equal(r.height, h); };
const code = (r, c) => { assert.equal(r.ok, false, 'expected refusal ' + c); assert.equal(r.code, c, r.code + ' ' + r.message); assert.ok(r.message.length > 0); };

// ---- mock DOM / canvas / URL environment ----
class El {
  constructor(id) { this.id = id; this.attrs = {}; this.listeners = {}; this.textContent = ''; this.hidden = false; this.disabled = false; this.onload = null; this.onerror = null; this.files = []; this.value = ''; this.focused = 0; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t) { for (const f of (this.listeners[t] || [])) f({ type: t }); }
  focus() { this.focused++; }
}
class Canvas extends El {
  constructor(id, H) { super(id); this._w = 300; this._h = 150; this.px = null; this.H = H; }
  get width() { return this._w; } set width(v) { this._w = v; this.px = null; }
  get height() { return this._h; } set height(v) { this._h = v; this.px = null; }
  ensure() { if (!this.px) this.px = new Uint8ClampedArray(this._w * this._h * 4); }
  getContext() {
    const c = this, f = this.H.faults;
    if (f.noContext) return null;
    return {
      drawImage(img) { if (f.draw) throw new Error('draw fail'); if (!img.pixels) throw new Error('no pixels'); c.ensure(); c.px.set(img.pixels); },
      getImageData(x, y, w, h) { if (f.getImageData) throw new Error('gid fail'); c.ensure(); return { width: w, height: h, data: c.px.slice(y * c._w * 4, (y + h) * c._w * 4) }; },
      createImageData(w, h) { return { width: w, height: h, data: new Uint8ClampedArray(w * h * 4) }; },
      putImageData(d, x, y) { if (f.putImageData) throw new Error('put fail'); c.ensure(); c.px.set(d.data, y * c._w * 4); }
    };
  }
}
function harness(o = {}) {
  const H = { faults: {}, work: [], created: new Set(), revoked: [], els: {}, blobs: {} };
  const mk = (id, C = El) => (H.els[id] = new C(id, H));
  ['status', 'alert', 'compare-button', 'result', 'result-heading', 'metric-diff', 'metric-total', 'metric-ratio', 'metric-size', 'result-note'].forEach(i => mk(i));
  mk('diff-canvas', Canvas);
  for (const k of ['before', 'after']) ['input', 'preview', 'preview-box', 'meta', 'msg', 'clear'].forEach(s => mk(k + '-' + s));
  H.els.result.hidden = true; H.els['compare-button'].disabled = true;
  for (const k of ['before', 'after']) { H.els[k + '-preview'].hidden = true; H.els[k + '-preview-box'].hidden = true; H.els[k + '-clear'].disabled = true; }
  let n = 0;
  H.env = {
    document: { getElementById: id => H.els[id] },
    URL: { createObjectURL(b) { if (H.faults.createUrl) throw new Error('url fail'); const u = 'blob:t' + (++n); H.created.add(u); H.blobs[u] = b; return u; }, revokeObjectURL(u) { H.revoked.push(u); } },
    features: Object.assign({ file: true, url: true, blob: true, canvas: true }, o.features),
    makeBlob: (bytes, type) => ({ bytes, type }),
    createCanvas(w, h) {
      if (H.faults.badAlloc) { const c = new Canvas('work', H); c.width = 0; c.height = 0; H.work.push(c); return c; }
      const c = new Canvas('work', H); c.width = w; c.height = h; H.work.push(c); return c;
    },
    yieldNow: () => new Promise(r => setImmediate(r))
  };
  H.ctrl = app.createController(H.env);
  H.started = H.ctrl.start();
  H.live = () => [...H.created].filter(u => !H.revoked.includes(u));
  return H;
}
function file(name, type, bytes, defer) {
  return { name, type, size: bytes.length, arrayBuffer: () => defer ? defer.promise : Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length)) };
}
const pngFile = (name, w, h) => file(name, 'image/png', png(w, h));
function solid(w, h, rgba) { const a = new Uint8ClampedArray(w * h * 4); for (let i = 0; i < a.length; i += 4) { a[i] = rgba[0]; a[i + 1] = rgba[1]; a[i + 2] = rgba[2]; a[i + 3] = rgba[3]; } return a; }
async function pick(H, key, f, img) {
  H.els[key + '-input'].files = [f];
  await H.ctrl.onFileChange(key);
  if (img) { const el = H.els[key + '-preview']; el.naturalWidth = img.w; el.naturalHeight = img.h; el.pixels = img.px; if (el.onload) el.onload(); }
}
async function pickPair(H, w, h, pxA, pxB) {
  await pick(H, 'before', pngFile('a.png', w, h), { w, h, px: pxA });
  await pick(H, 'after', pngFile('b.png', w, h), { w, h, px: pxB });
}
function assertNoResult(H) {
  assert.equal(H.els.result.hidden, true);
  for (const m of ['metric-diff', 'metric-total', 'metric-ratio', 'metric-size', 'result-note']) assert.equal(H.els[m].textContent, '', m);
  assert.equal(H.els['diff-canvas'].width, 0);
}
function defer() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
"""


def run_node(body):
    env = dict(os.environ)
    env["APP_JS"] = str(APP_JS)
    script = PRELUDE + "\n(async () => {\n" + body + "\n})().then(() => { console.log('NODE-OK'); }, e => { console.error(e && e.stack || e); process.exit(1); });\n"
    proc = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                          encoding="utf-8", env=env, timeout=120, cwd=str(REPO_ROOT))
    return proc


@unittest.skipUnless(NODE, "node not installed; Node-driven tests SKIPPED")
class NodeLogicTests(unittest.TestCase):
    def check(self, body):
        proc = run_node(body)
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
        self.assertIn("NODE-OK", proc.stdout)

    def test_node_syntax_and_no_browser_globals_needed(self):
        self.check("assert.equal(typeof app.createController, 'function'); assert.equal(app.LIMITS.MAX_BYTES, 10 * MiB); assert.equal(app.LIMITS.MAX_DIM, 4096); assert.equal(app.LIMITS.MAX_PIXELS, 4096 * 4096);")

    # ---- pixel metric ----
    def test_identical_pixels_zero_difference(self):
        self.check(r"""
const a = solid(4, 3, [10, 20, 30, 255]); const b = solid(4, 3, [10, 20, 30, 255]); const out = new Uint8ClampedArray(a.length);
assert.equal(app.diffBand(a, b, out), 0);
for (let i = 0; i < out.length; i += 4) assert.equal(out[i + 3], 255);
assert.ok(!Array.from(out).some((v, i) => i % 4 === 0 && v === 255 && out[i + 1] === 0), 'no changed marker colour');
""")

    def test_one_and_multiple_changed_pixels_counted(self):
        self.check(r"""
const a = solid(5, 4, [1, 2, 3, 255]); const b = solid(5, 4, [1, 2, 3, 255]); const out = new Uint8ClampedArray(a.length);
b[7 * 4] = 2;           // one pixel, R
assert.equal(app.diffBand(a, b, out), 1);
assert.deepEqual(Array.from(out.slice(28, 32)), [255, 0, 102, 255]);
b[0 + 1] = 3; b[19 * 4 + 2] = 9;  // two more pixels (G of px0, B of px19)
assert.equal(app.diffBand(a, b, out), 3);
for (let c = 0; c < 4; c++) { const x = solid(1, 1, [5, 5, 5, 5]); const y = solid(1, 1, [5, 5, 5, 5]); y[c] += 1; assert.equal(app.diffBand(x, y, new Uint8ClampedArray(4)), 1, 'channel ' + c); }
""")

    def test_alpha_only_change_counts_and_no_threshold(self):
        self.check(r"""
const a = solid(2, 1, [9, 9, 9, 255]); const b = solid(2, 1, [9, 9, 9, 254]);
assert.equal(app.diffBand(a, b, new Uint8ClampedArray(8)), 2);
const c = solid(1, 1, [0, 0, 0, 255]); const d = solid(1, 1, [0, 0, 1, 255]);
assert.equal(app.diffBand(c, d, new Uint8ClampedArray(4)), 1, 'a difference of 1 level is still a difference');
""")

    def test_diff_is_deterministic_and_validates_lengths(self):
        self.check(r"""
const a = new Uint8ClampedArray(64).map((_, i) => (i * 37) & 255); const b = a.slice(); b[10] ^= 1;
const o1 = new Uint8ClampedArray(64), o2 = new Uint8ClampedArray(64);
assert.equal(app.diffBand(a, b, o1), app.diffBand(a, b, o2)); assert.deepEqual(o1, o2);
assert.throws(() => app.diffBand(new Uint8ClampedArray(8), new Uint8ClampedArray(4), new Uint8ClampedArray(8)), RangeError);
assert.throws(() => app.diffBand(new Uint8ClampedArray(8), new Uint8ClampedArray(8), new Uint8ClampedArray(4)), RangeError);
assert.throws(() => app.diffBand(new Uint8ClampedArray(6), new Uint8ClampedArray(6), new Uint8ClampedArray(6)), RangeError);
""")

    def test_ratio_math_and_formatting(self):
        self.check(r"""
assert.equal(app.formatRatio(0, 6), '0.0000%');
assert.equal(app.formatRatio(1, 6), '16.6667%');
assert.equal(app.formatRatio(6, 6), '100.0000%');
assert.equal(app.formatRatio(1, 4096 * 4096), '<0.0001%');
assert.equal(app.formatRatio(1, 100), '1.0000%');
assert.equal(app.formatRatio(1, 0), '—'); assert.equal(app.formatRatio(7, 6), '—'); assert.equal(app.formatRatio(-1, 6), '—');
assert.equal(app.sameSize({ width: 2, height: 3 }, { width: 2, height: 3 }), true);
assert.equal(app.sameSize({ width: 2, height: 3 }, { width: 3, height: 2 }), false);
assert.equal(app.sameSize(null, { width: 2, height: 3 }), false);
""")

    # ---- validation of file meta ----
    def test_file_meta_empty_size_boundary_extension_and_mime(self):
        self.check(r"""
const v = (name, type, size) => app.validateFileMeta({ name, type, size });
code(v('a.png', 'image/png', 0), 'EMPTY');
assert.equal(v('a.png', 'image/png', 10 * MiB).ok, true);
code(v('a.png', 'image/png', 10 * MiB + 1), 'TOO_LARGE');
code(v('a.gif', 'image/gif', 5), 'BAD_EXTENSION'); code(v('a', 'image/png', 5), 'BAD_EXTENSION'); code(v('a.png.exe', 'image/png', 5), 'BAD_EXTENSION');
code(v('a.png', '', 5), 'BAD_MIME'); code(v('a.png', 'text/html', 5), 'BAD_MIME'); code(v('a.png', 'image/svg+xml', 5), 'BAD_MIME');
code(v('a.png', 'image/jpeg', 5), 'MIME_EXTENSION_MISMATCH'); code(v('a.webp', 'image/png', 5), 'MIME_EXTENSION_MISMATCH');
assert.equal(v('A.JPG', 'image/jpeg', 5).ok, true); assert.equal(v('a.jpeg', 'image/jpeg', 5).ok, true); assert.equal(v('a.WEBP', 'image/webp', 5).ok, true);
code(v('a.png', 'image/png', NaN), 'CORRUPT'); code(app.validateFileMeta(null), 'CORRUPT');
""")

    # ---- headers ----
    def test_valid_headers_all_formats_and_boundaries(self):
        self.check(r"""
okDims(inspect('a.png', 'image/png', png(1, 1)), 'png', 1, 1);
okDims(inspect('a.png', 'image/png', png(4096, 4096)), 'png', 4096, 4096);
okDims(inspect('a.png', 'image/png', png(4096, 1)), 'png', 4096, 1);
okDims(inspect('a.jpg', 'image/jpeg', jpeg(123, 45)), 'jpeg', 123, 45);
okDims(inspect('a.jpeg', 'image/jpeg', jpeg(4096, 4096)), 'jpeg', 4096, 4096);
okDims(inspect('a.webp', 'image/webp', webp('vp8', 17, 9)), 'webp', 17, 9);
okDims(inspect('a.webp', 'image/webp', webp('vp8l', 4096, 4096)), 'webp', 4096, 4096);
okDims(inspect('a.webp', 'image/webp', webp('vp8x', 300, 200)), 'webp', 300, 200);
okDims(inspect('a.webp', 'image/webp', webp('vp8', 4096, 4095)), 'webp', 4096, 4095);
""")

    def test_oversize_and_zero_dimensions_refused_from_header(self):
        self.check(r"""
code(inspect('a.png', 'image/png', png(4097, 1)), 'DIM_TOO_LARGE');
code(inspect('a.png', 'image/png', png(1, 4097)), 'DIM_TOO_LARGE');
code(inspect('a.png', 'image/png', png(0, 10)), 'DIM_ZERO');
code(inspect('a.png', 'image/png', png(10, 0)), 'DIM_ZERO');
code(inspect('a.png', 'image/png', png(2147483647, 2147483647)), 'DIM_TOO_LARGE');
code(inspect('a.png', 'image/png', png(4294967295, 4294967295)), 'DIM_TOO_LARGE');
code(inspect('a.jpg', 'image/jpeg', jpeg(4097, 10)), 'DIM_TOO_LARGE');
code(inspect('a.jpg', 'image/jpeg', jpeg(65535, 65535)), 'DIM_TOO_LARGE');
code(inspect('a.jpg', 'image/jpeg', jpeg(0, 10)), 'DIM_ZERO');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 0)), 'DIM_ZERO');
code(inspect('a.webp', 'image/webp', webp('vp8', 4097, 10)), 'DIM_TOO_LARGE');
code(inspect('a.webp', 'image/webp', webp('vp8l', 16384, 16384)), 'DIM_TOO_LARGE');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { cw: 16777216, ch: 16777216 })), 'DIM_TOO_LARGE');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { cw: 4097, ch: 10 })), 'DIM_TOO_LARGE');
""")

    def test_corrupt_headers_lengths_and_truncation_refused(self):
        self.check(r"""
const pg = png(10, 10);
code(inspect('a.png', 'image/png', pg.slice(0, 20)), 'CORRUPT');
code(inspect('a.png', 'image/png', pg.slice(0, pg.length - 5)), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { noIend: true })), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { noIdat: true })), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { post: [u8(1, 2, 3)] })), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { pre: [cat(be32(0x7fffffff), str('tEXt'), u8(0, 0))] })), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { depth: 7 })), 'CORRUPT');
code(inspect('a.png', 'image/png', png(10, 10, { ct: 5 })), 'CORRUPT');
const badIhdr = pg.slice(); badIhdr[11] = 'X'.charCodeAt(0); code(inspect('a.png', 'image/png', badIhdr), 'CORRUPT');
const shortIhdr = cat(pg.slice(0, 8), pchunk('IHDR', u8(0, 0, 0, 1)), pchunk('IEND', u8())); code(inspect('a.png', 'image/png', shortIhdr), 'CORRUPT');
const jg = jpeg(10, 10);
code(inspect('a.jpg', 'image/jpeg', jg.slice(0, jg.length - 2)), 'CORRUPT');
code(inspect('a.jpg', 'image/jpeg', jg.slice(0, 12)), 'CORRUPT');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { noEoi: true })), 'CORRUPT');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { noSof: true })), 'CORRUPT');
const badLen = jg.slice(); badLen[4] = 0xff; badLen[5] = 0xff; code(inspect('a.jpg', 'image/jpeg', badLen), 'CORRUPT');
const zeroLen = jg.slice(); zeroLen[4] = 0; zeroLen[5] = 1; code(inspect('a.jpg', 'image/jpeg', zeroLen), 'CORRUPT');
const noMarker = jg.slice(); noMarker[2] = 0x12; code(inspect('a.jpg', 'image/jpeg', noMarker), 'BAD_SIGNATURE');
const wg = webp('vp8', 10, 10);
code(inspect('a.webp', 'image/webp', webp('vp8', 10, 10, { delta: 4 })), 'CORRUPT');
code(inspect('a.webp', 'image/webp', webp('vp8', 10, 10, { delta: -4 })), 'CORRUPT');
code(inspect('a.webp', 'image/webp', wg.slice(0, 14)), 'CORRUPT');
const badStart = wg.slice(); badStart[23] = 0; code(inspect('a.webp', 'image/webp', badStart), 'CORRUPT');
const bigChunk = wg.slice(); bigChunk[16] = 0xff; bigChunk[17] = 0xff; code(inspect('a.webp', 'image/webp', bigChunk), 'CORRUPT');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { cw: 11, ch: 10 })), 'CORRUPT');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { noImg: true })), 'CORRUPT');
const badL = webp('vp8l', 10, 10); badL[20] = 0x00; code(inspect('a.webp', 'image/webp', badL), 'CORRUPT');
// loaded byte count must equal declared size
const b = png(10, 10); code(app.inspectImage({ name: 'a.png', type: 'image/png', size: b.length + 1 }, b), 'CORRUPT');
code(app.inspectImage({ name: 'a.png', type: 'image/png', size: 0 }, new Uint8Array(0)), 'EMPTY');
code(app.inspectImage({ name: 'a.png', type: 'image/png', size: 10 * MiB + 1 }, b), 'TOO_LARGE');
""")

    def test_mime_extension_and_content_spoofing_refused(self):
        self.check(r"""
code(inspect('a.jpg', 'image/jpeg', png(10, 10)), 'FORMAT_MISMATCH');
code(inspect('a.png', 'image/png', jpeg(10, 10)), 'FORMAT_MISMATCH');
code(inspect('a.webp', 'image/webp', png(10, 10)), 'FORMAT_MISMATCH');
code(inspect('a.png', 'image/png', webp('vp8', 10, 10)), 'FORMAT_MISMATCH');
code(inspect('a.png', 'image/png', str('<html><script>alert(1)</script></html>')), 'BAD_SIGNATURE');
code(inspect('a.png', 'image/png', str('<svg xmlns="http://www.w3.org/2000/svg"/>')), 'BAD_SIGNATURE');
code(inspect('a.png', 'image/png', str('GIF89a......')), 'BAD_SIGNATURE');
code(inspect('a.png', 'image/jpeg', png(10, 10)), 'MIME_EXTENSION_MISMATCH');
code(inspect('a.png', 'text/plain', png(10, 10)), 'BAD_MIME');
code(inspect('a.png', '', png(10, 10)), 'BAD_MIME');
code(inspect('a.png', 'image/png', u8(0x89, 0x50)), 'BAD_SIGNATURE');
""")

    def test_animated_multiframe_and_orientation_refused(self):
        self.check(r"""
code(inspect('a.png', 'image/png', png(10, 10, { pre: [pchunk('acTL', u8(0, 0, 0, 2, 0, 0, 0, 0))] })), 'ANIMATED');
code(inspect('a.png', 'image/png', png(10, 10, { post: [] , pre: [pchunk('fcTL', new Uint8Array(26))] })), 'ANIMATED');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { flags: 0x02 })), 'ANIMATED');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { extra: [wck('ANIM', u8(0, 0, 0, 0, 0, 0))] })), 'ANIMATED');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { extra: [wck('ANMF', new Uint8Array(16))] })), 'ANIMATED');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { mpf: true })), 'MULTIFRAME');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { twoSof: true })), 'MULTIFRAME');
code(inspect('a.webp', 'image/webp', riff([wck('VP8X', vp8xd(10, 10)), wck('VP8L', vp8ld(10, 10)), wck('VP8L', vp8ld(10, 10))])), 'MULTIFRAME');
// orientation
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: tiff(6) })), 'ORIENTATION');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: tiffBE(3) })), 'ORIENTATION');
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: tiff(0) })), 'ORIENTATION');
code(inspect('a.png', 'image/png', png(10, 10, { pre: [pchunk('eXIf', tiff(8))] })), 'ORIENTATION');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { extra: [wck('EXIF', tiff(5))] })), 'ORIENTATION');
okDims(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: tiff(1) })), 'jpeg', 10, 10);
okDims(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: tiffBE(1) })), 'jpeg', 10, 10);
okDims(inspect('a.png', 'image/png', png(10, 10, { pre: [pchunk('eXIf', tiff(1))] })), 'png', 10, 10);
// unparsable EXIF: conservative refusal
code(inspect('a.jpg', 'image/jpeg', jpeg(10, 10, { exif: str('garbage!!') })), 'CORRUPT');
""")

    # ---- controller flow ----
    def test_initial_state_has_no_result_and_compare_is_disabled(self):
        self.check(r"""
const H = harness(); assert.equal(H.started, true);
assertNoResult(H);
assert.equal(H.els['compare-button'].disabled, true);
assert.equal(H.created.size, 0); assert.equal(H.work.length, 0);
await H.ctrl.onCompare();
assertNoResult(H); assert.match(H.els.alert.textContent, /両方/); assert.equal(H.work.length, 0);
assert.equal(H.els.status.textContent.includes('完了'), false);
""")

    def test_selection_alone_never_computes(self):
        self.check(r"""
const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, px, px);
assert.equal(H.work.length, 0, 'no canvas work before explicit compare');
assertNoResult(H);
assert.equal(H.els['compare-button'].disabled, false);
assert.equal(H.els['before-preview'].hidden, false); assert.equal(H.els['before-preview-box'].hidden, false);
assert.match(H.els['before-meta'].textContent, /PNG.*3×2/);
""")

    def test_identical_compare_reports_zero_without_pass_claim(self):
        self.check(r"""
const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, px, px.slice());
await H.ctrl.onCompare();
assert.equal(H.els.result.hidden, false);
assert.equal(H.els['metric-diff'].textContent, '0'); assert.equal(H.els['metric-total'].textContent, '6');
assert.equal(H.els['metric-ratio'].textContent, '0.0000%'); assert.equal(H.els['metric-size'].textContent, '3×2 px');
assert.equal(H.els['diff-canvas'].width, 3); assert.equal(H.els['diff-canvas'].height, 2);
const all = Object.values(H.els).map(e => e.textContent).join(' ');
assert.equal(/PASS|合格|承認/.test(all), false);
assert.match(H.els['result-note'].textContent, /証明ではありません/);
assert.ok(H.els['result-heading'].focused >= 1);
assert.equal(H.els['compare-button'].textContent, '再比較する');
assert.ok(H.work.length === 2 && H.work.every(c => c.width === 0 && c.height === 0), 'work canvases released');
""")

    def test_changed_pixels_alpha_and_ratio_in_full_flow(self):
        self.check(r"""
const H = harness(); const a = solid(3, 2, [1, 2, 3, 255]); const b = a.slice(); b[3] = 200; // alpha only on px 0
await pickPair(H, 3, 2, a, b);
await H.ctrl.onCompare();
assert.equal(H.els['metric-diff'].textContent, '1'); assert.equal(H.els['metric-ratio'].textContent, '16.6667%');
assert.match(H.els['result-note'].textContent, /不具合が確認された/);
const d = H.els['diff-canvas'].px; assert.deepEqual(Array.from(d.slice(0, 4)), [255, 0, 102, 255]);
assert.notDeepEqual(Array.from(d.slice(4, 8)), [255, 0, 102, 255]);
""")

    def test_multi_band_compare_matches_expected_count(self):
        self.check(r"""
const w = 1500, h = 1500; // 2.25M px > one 1M-px band
const H = harness(); const a = solid(w, h, [7, 7, 7, 255]); const b = a.slice();
const idx = [0, 1499, 700 * 1500 + 3, 1499 * 1500 + 1499]; for (const i of idx) b[i * 4 + 1] ^= 4;
await pickPair(H, w, h, a, b);
await H.ctrl.onCompare();
assert.equal(H.els['metric-diff'].textContent, '4'); assert.equal(H.els['metric-total'].textContent, String(w * h));
""")

    def test_mismatched_sizes_refused_without_resize(self):
        self.check(r"""
const H = harness();
await pick(H, 'before', pngFile('a.png', 3, 2), { w: 3, h: 2, px: solid(3, 2, [0, 0, 0, 255]) });
await pick(H, 'after', pngFile('b.png', 4, 2), { w: 4, h: 2, px: solid(4, 2, [0, 0, 0, 255]) });
assert.equal(H.els['compare-button'].disabled, true);
assert.match(H.els.alert.textContent, /一致しません/); assert.match(H.els.alert.textContent, /3×2/); assert.match(H.els.alert.textContent, /4×2/);
await H.ctrl.onCompare();
assertNoResult(H); assert.equal(H.work.length, 0, 'no canvas created, no resizing');
assert.match(H.els.alert.textContent, /リサイズ/);
""")

    def test_replacement_clears_result_revokes_urls_and_recompare_works(self):
        self.check(r"""
const H = harness(); const a = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, a, a.slice());
await H.ctrl.onCompare(); assert.equal(H.els.result.hidden, false);
const oldUrl = H.els['before-preview'].attrs.src;
const b2 = a.slice(); b2[0] = 9;
await pick(H, 'before', pngFile('c.png', 3, 2), { w: 3, h: 2, px: b2 });
assertNoResult(H); assert.ok(H.revoked.includes(oldUrl), 'old URL revoked');
assert.equal(H.els['compare-button'].textContent, '比較する');
await H.ctrl.onCompare();
assert.equal(H.els['metric-diff'].textContent, '1');
await H.ctrl.onCompare();   // explicit recompare of same files
assert.equal(H.els['metric-diff'].textContent, '1'); assert.equal(H.work.length, 6);
// clear everything: no live URL remains
await H.ctrl.onClear('before'); await H.ctrl.onClear('after');
assertNoResult(H); assert.deepEqual(H.live(), []);
assert.equal(H.els['before-preview'].attrs.src, undefined);
assert.equal(H.els['compare-button'].disabled, true);
""")

    def test_invalid_replacement_clears_stale_result_and_metrics(self):
        self.check(r"""
const H = harness(); const a = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, a, a.slice()); await H.ctrl.onCompare(); assert.equal(H.els.result.hidden, false);
H.els['after-input'].files = [file('x.png', 'image/png', png(5000, 5000))];
await H.ctrl.onFileChange('after');
assertNoResult(H); assert.match(H.els.alert.textContent, /上限/); assert.equal(H.els['compare-button'].disabled, true);
assert.equal(H.els['after-input'].attrs['aria-invalid'], 'true');
assert.equal(H.live().length, 1, 'only the still-valid before image keeps a URL');
H.els['after-input'].files = [file('x.png', 'image/png', new Uint8Array(0))];
await H.ctrl.onFileChange('after'); assert.match(H.els.alert.textContent, /空/);
H.els['after-input'].files = [file('x.png', 'image/jpeg', png(2, 2))];
await H.ctrl.onFileChange('after'); assert.match(H.els.alert.textContent, /一致しません/);
H.els['after-input'].files = [file('x.png', 'image/png', jpeg(2, 2))];
await H.ctrl.onFileChange('after'); assert.match(H.els.alert.textContent, /内容/);
assert.equal(H.live().length, 1);
""")

    def test_oversize_file_refused_before_reading(self):
        self.check(r"""
const H = harness(); let read = 0;
const f = { name: 'big.png', type: 'image/png', size: 10 * MiB + 1, arrayBuffer() { read++; return Promise.resolve(new ArrayBuffer(0)); } };
H.els['before-input'].files = [f]; await H.ctrl.onFileChange('before');
assert.equal(read, 0); assert.equal(H.created.size, 0); assert.match(H.els.alert.textContent, /10 MiB/);
const g = { name: 'e.png', type: 'image/png', size: 0, arrayBuffer() { read++; return Promise.resolve(new ArrayBuffer(0)); } };
H.els['before-input'].files = [g]; await H.ctrl.onFileChange('before'); assert.equal(read, 0);
""")

    def test_late_decode_of_replaced_image_is_ignored(self):
        self.check(r"""
const H = harness(); const el = H.els['before-preview'];
H.els['before-input'].files = [pngFile('a.png', 3, 2)]; await H.ctrl.onFileChange('before');
const staleLoad = el.onload, staleErr = el.onerror, staleUrl = el.attrs.src;
H.els['before-input'].files = [pngFile('b.png', 3, 2)]; await H.ctrl.onFileChange('before');
assert.ok(H.revoked.includes(staleUrl));
el.naturalWidth = 3; el.naturalHeight = 2; el.pixels = solid(3, 2, [0, 0, 0, 255]);
staleLoad(); staleErr();
assert.equal(H.ctrl.slots.before.status, 'checking'); assert.equal(H.els.alert.textContent, ''); assert.equal(H.ctrl.slots.before.info, null);
assert.equal(H.els['compare-button'].disabled, true);
el.onload(); assert.equal(H.ctrl.slots.before.status, 'ready');
// late decode after clear
const lateLoad = el.onload; await H.ctrl.onClear('before'); lateLoad();
assert.equal(H.ctrl.slots.before.status, 'empty'); assert.deepEqual(H.live(), []);
""")

    def test_late_file_read_after_replacement_creates_no_url(self):
        self.check(r"""
const H = harness(); const d = defer(); const bytes = png(3, 2);
H.els['before-input'].files = [file('a.png', 'image/png', bytes, d)];
const p1 = H.ctrl.onFileChange('before');
H.els['before-input'].files = [pngFile('b.png', 3, 2)];
await H.ctrl.onFileChange('before');
d.resolve(bytes.buffer.slice(0)); await p1;
assert.equal(H.created.size, 1, 'late read of replaced file created nothing');
H.els['before-input'].files = []; await H.ctrl.onFileChange('before');
const d2 = defer(); H.els['before-input'].files = [file('c.png', 'image/png', bytes, d2)];
const p2 = H.ctrl.onFileChange('before'); await H.ctrl.onClear('before'); d2.resolve(bytes.buffer.slice(0)); await p2;
assert.equal(H.created.size, 1); assert.deepEqual(H.live(), []);
""")

    def test_decode_failure_dimension_mismatch_and_url_failure_clean_up(self):
        self.check(r"""
let H = harness(); let el = H.els['before-preview'];
H.els['before-input'].files = [pngFile('a.png', 3, 2)]; await H.ctrl.onFileChange('before');
el.onerror(); assert.match(H.els.alert.textContent, /デコード/); assert.deepEqual(H.live(), []); assert.equal(H.ctrl.slots.before.status, 'error');
assert.equal(el.attrs.src, undefined); assert.equal(el.hidden, true);
H = harness(); el = H.els['before-preview'];
H.els['before-input'].files = [pngFile('a.png', 3, 2)]; await H.ctrl.onFileChange('before');
el.naturalWidth = 4000; el.naturalHeight = 4000; el.pixels = solid(1, 1, [0, 0, 0, 0]); el.onload();
assert.match(H.els.alert.textContent, /一致しません/); assert.deepEqual(H.live(), []); assert.equal(H.ctrl.slots.before.status, 'error');
H = harness(); el = H.els['before-preview'];
H.faults.createUrl = true;
H.els['before-input'].files = [pngFile('a.png', 3, 2)]; await H.ctrl.onFileChange('before');
assert.match(H.els.alert.textContent, /準備できません/); assert.equal(H.ctrl.slots.before.status, 'error');
// read rejection
H = harness();
H.els['before-input'].files = [{ name: 'a.png', type: 'image/png', size: 10, arrayBuffer: () => Promise.reject(new Error('io')) }];
await H.ctrl.onFileChange('before'); assert.match(H.els.alert.textContent, /読み込めません/); assert.equal(H.ctrl.slots.before.status, 'error');
// no arrayBuffer support is an error, never success
H = harness(); H.els['before-input'].files = [{ name: 'a.png', type: 'image/png', size: 10 }];
await H.ctrl.onFileChange('before'); assert.equal(H.ctrl.slots.before.status, 'error');
""")

    def test_compare_failures_never_report_success(self):
        self.check(r"""
for (const fault of ['noContext', 'draw', 'getImageData', 'putImageData', 'badAlloc']) {
  const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]);
  await pickPair(H, 3, 2, px, px.slice());
  H.faults[fault] = true;
  await H.ctrl.onCompare();
  assertNoResult(H);
  assert.match(H.els.alert.textContent, /比較に失敗/, fault);
  assert.equal(/完了/.test(H.els.status.textContent), false, fault);
  assert.ok(H.work.every(c => c.width === 0), 'work canvases released after ' + fault);
  assert.equal(H.els['compare-button'].disabled, false, 'user may retry after ' + fault);
  H.faults[fault] = false;
  await H.ctrl.onCompare(); assert.equal(H.els.result.hidden, false, 'retry works after ' + fault); assert.equal(H.els['metric-diff'].textContent, '0');
}
// image whose natural size no longer matches
const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]); await pickPair(H, 3, 2, px, px.slice());
H.els['after-preview'].naturalWidth = 9; await H.ctrl.onCompare(); assertNoResult(H); assert.match(H.els.alert.textContent, /比較に失敗/);
// short pixel data from getImageData
const H2 = harness(); await pickPair(H2, 3, 2, px, px.slice());
const ctxOrig = Canvas.prototype.getContext;
Canvas.prototype.getContext = function () { const c = ctxOrig.call(this); if (!c || this.id !== 'work') return c; c.getImageData = (x, y, w, h) => ({ width: w, height: h, data: new Uint8ClampedArray(4) }); return c; };
await H2.ctrl.onCompare(); Canvas.prototype.getContext = ctxOrig;
assertNoResult(H2); assert.match(H2.els.alert.textContent, /比較に失敗/);
""")

    def test_replacement_during_compare_discards_stale_result_and_releases_canvases(self):
        self.check(r"""
const w = 2000, h = 2000; const H = harness(); const a = solid(w, h, [3, 3, 3, 255]);
await pickPair(H, w, h, a, a.slice());
const p = H.ctrl.onCompare();            // runs synchronously up to first band yield
assert.equal(H.els['compare-button'].disabled, true, 'busy');
H.els['before-input'].files = []; await H.ctrl.onFileChange('before');
await p;
assertNoResult(H);
assert.ok(H.work.every(c => c.width === 0 && c.height === 0));
assert.equal(H.els.alert.textContent, '');
assert.equal(H.els['compare-button'].disabled, true, 'before slot is empty now');
assert.equal(H.ctrl.slots.before.status, 'empty');
// the new compare of a fresh pair works afterwards
await pick(H, 'before', pngFile('n.png', w, h), { w, h, px: a.slice() });
await H.ctrl.onCompare(); assert.equal(H.els['metric-diff'].textContent, '0'); assert.equal(H.els['metric-total'].textContent, String(w * h));
""")

    def test_missing_browser_capabilities_are_not_success(self):
        self.check(r"""
for (const missing of ['file', 'url', 'blob', 'canvas']) {
  const H = harness({ features: { [missing]: false } });
  assert.equal(H.started, false, missing);
  assert.match(H.els.alert.textContent, /利用できない/);
  assert.equal(H.els['before-input'].disabled, true); assert.equal(H.els['after-input'].disabled, true); assert.equal(H.els['compare-button'].disabled, true);
  assert.equal(Object.keys(H.els['before-input'].listeners).length, 0);
  assertNoResult(H);
}
""")

    def test_no_user_data_leaves_through_controller_surface(self):
        self.check(r"""
const H = harness(); const px = solid(3, 2, [1, 2, 3, 255]);
await pickPair(H, 3, 2, px, px.slice()); await H.ctrl.onCompare();
// the only environment surface is DOM, Blob/URL and canvas; blob URLs reference only the validated bytes
for (const u of H.created) { assert.ok(H.blobs[u].bytes instanceof Uint8Array); assert.equal(H.blobs[u].type, 'image/png'); }
""")

    def test_webp_full_container_scan_after_simple_bitstream(self):
        self.check(r"""
const v8 = wck('VP8 ', vp8d(10, 10)), vl = wck('VP8L', vp8ld(10, 10));
// valid forms stay supported
okDims(inspect('a.webp', 'image/webp', riff([v8])), 'webp', 10, 10);
okDims(inspect('a.webp', 'image/webp', riff([vl])), 'webp', 10, 10);
okDims(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10)), 'webp', 10, 10);
okDims(inspect('a.webp', 'image/webp', riff([v8, wck('EXIF', tiff(1))])), 'webp', 10, 10);
okDims(inspect('a.webp', 'image/webp', riff([vl, wck('XMP ', u8(1, 2, 3))])), 'webp', 10, 10);
// trailing features after a simple bitstream are no longer skipped
code(inspect('a.webp', 'image/webp', riff([v8, wck('EXIF', tiff(3))])), 'ORIENTATION');
code(inspect('a.webp', 'image/webp', riff([vl, wck('EXIF', tiff(6))])), 'ORIENTATION');
code(inspect('a.webp', 'image/webp', riff([v8, wck('ANIM', u8(0, 0, 0, 0, 0, 0))])), 'ANIMATED');
code(inspect('a.webp', 'image/webp', riff([vl, wck('ANMF', new Uint8Array(16))])), 'ANIMATED');
code(inspect('a.webp', 'image/webp', riff([v8, wck('VP8L', vp8ld(10, 10))])), 'MULTIFRAME');
code(inspect('a.webp', 'image/webp', riff([vl, wck('VP8 ', vp8d(10, 10))])), 'MULTIFRAME');
code(inspect('a.webp', 'image/webp', riff([vl, vl])), 'MULTIFRAME');
// exact RIFF length: smaller than file (trailing bytes) and larger both refused
code(inspect('a.webp', 'image/webp', cat(riff([v8]), u8(0))), 'CORRUPT');
code(inspect('a.webp', 'image/webp', riff([v8, wck('EXIF', tiff(3))], -26)), 'CORRUPT');
code(inspect('a.webp', 'image/webp', cat(webp('vp8', 10, 10, { delta: -2 }), u8(0, 0))), 'CORRUPT');
code(inspect('a.webp', 'image/webp', webp('vp8x', 10, 10, { delta: -2 })), 'CORRUPT');
// incomplete trailing chunk header / chunk / padding
code(inspect('a.webp', 'image/webp', riff([v8, str('EXIF'), u8(0, 0)])), 'CORRUPT');
code(inspect('a.webp', 'image/webp', riff([v8, str('EXIF'), le32(50), u8(1, 2, 3, 4)])), 'CORRUPT');
code(inspect('a.webp', 'image/webp', riff([v8, str('XMP '), le32(3), u8(1, 2, 3)])), 'CORRUPT');
code(inspect('a.webp', 'image/webp', riff([str('VP8L'), le32(5), vp8ld(10, 10)])), 'CORRUPT');
code(inspect('a.webp', 'image/webp', riff([v8, str('XMP '), le32(3), u8(1, 2, 3, 9)])), 'CORRUPT');
// extended: trailing orientation after the image
code(inspect('a.webp', 'image/webp', riff([wck('VP8X', vp8xd(10, 10)), vl, wck('EXIF', tiff(8))])), 'ORIENTATION');
""")

    def test_picker_activation_cancel_reselect_and_stale_invalidation(self):
        self.check(r"""
const a = solid(3, 2, [1, 2, 3, 255]);
// focus alone never clears a loaded result
let H = harness(); await pickPair(H, 3, 2, a, a.slice()); await H.ctrl.onCompare();
assert.equal(H.els.result.hidden, false);
H.els['before-input'].fire('focus'); H.els['before-input'].fire('blur');
assert.equal(H.els.result.hidden, false); assert.equal(H.ctrl.slots.before.status, 'ready');
// activation (mouse or keyboard-generated click) then cancel: old result and slot are gone
const oldUrl = H.els['before-preview'].attrs.src;
H.els['before-input'].value = 'C:/fakepath/a.png';
H.els['before-input'].fire('click');
assertNoResult(H);
assert.equal(H.ctrl.slots.before.status, 'empty'); assert.equal(H.ctrl.slots.before.info, null);
assert.equal(H.els['before-input'].value, '', 'value reset so the same file can be re-picked');
assert.ok(H.revoked.includes(oldUrl)); assert.equal(H.els['before-preview'].attrs.src, undefined);
assert.equal(H.els['before-preview-box'].hidden, true);
assert.equal(H.els['compare-button'].disabled, true); assert.equal(H.els['compare-button'].textContent, '比較する');
H.els['before-input'].files = [];
H.els['before-input'].fire('cancel');
assertNoResult(H); assert.equal(H.ctrl.slots.before.status, 'empty'); assert.equal(H.els['compare-button'].disabled, true);
assert.match(H.els.status.textContent, /キャンセル/);
await H.ctrl.onCompare(); assertNoResult(H); assert.match(H.els.alert.textContent, /両方/);
// reselecting the SAME file after the click/cancel works end to end
H.els['before-input'].fire('click');
await pick(H, 'before', pngFile('a.png', 3, 2), { w: 3, h: 2, px: a });
assert.equal(H.ctrl.slots.before.status, 'ready');
await H.ctrl.onCompare(); assert.equal(H.els['metric-diff'].textContent, '0');
assert.equal(H.live().length, 2);
assert.equal(H.ctrl.slots.after.status, 'ready');

// pending file read finishing after the picker opened cannot publish
H = harness(); const d = defer(); const bytes = png(3, 2);
H.els['before-input'].files = [file('a.png', 'image/png', bytes, d)];
const p1 = H.ctrl.onFileChange('before');
assert.equal(H.ctrl.slots.before.status, 'checking');
H.els['before-input'].fire('click');
assert.equal(H.ctrl.slots.before.status, 'empty');
d.resolve(bytes.buffer.slice(0)); await p1;
assert.equal(H.created.size, 0, 'stale read created no URL'); assert.equal(H.ctrl.slots.before.status, 'empty');
assert.equal(H.els['before-preview'].onload, null); assert.deepEqual(H.live(), []);
assert.equal(H.els.alert.textContent, '');

// pending decode finishing after the picker opened cannot repopulate
H = harness(); const el = H.els['before-preview'];
H.els['before-input'].files = [pngFile('a.png', 3, 2)]; await H.ctrl.onFileChange('before');
const lateLoad = el.onload, lateErr = el.onerror, url = el.attrs.src;
H.els['before-input'].fire('click');
assert.ok(H.revoked.includes(url)); assert.deepEqual(H.live(), []);
el.naturalWidth = 3; el.naturalHeight = 2; el.pixels = a;
lateLoad(); lateErr();
assert.equal(H.ctrl.slots.before.status, 'empty'); assert.equal(H.ctrl.slots.before.info, null);
assert.equal(el.hidden, true); assert.equal(H.els.alert.textContent, ''); assert.equal(H.els['compare-button'].disabled, true);

// in-flight compare is invalidated when a picker opens: nothing published, canvases released
const w = 2000, h = 2000; H = harness(); const big = solid(w, h, [3, 3, 3, 255]);
await pickPair(H, w, h, big, big.slice());
const pc = H.ctrl.onCompare();
assert.equal(H.els['compare-button'].disabled, true);
H.els['after-input'].fire('click');
await pc;
assertNoResult(H); assert.ok(H.work.every(c => c.width === 0 && c.height === 0));
assert.equal(H.ctrl.slots.after.status, 'empty'); assert.equal(H.ctrl.slots.before.status, 'ready');
assert.equal(H.els['compare-button'].disabled, true); assert.equal(H.els.alert.textContent, '');
""")

    def test_picker_listeners_registered_and_focus_is_not_one(self):
        self.check(r"""
const H = harness();
for (const k of ['before', 'after']) {
  const l = H.els[k + '-input'].listeners;
  assert.equal(l.click.length, 1); assert.equal(l.change.length, 1); assert.equal(l.cancel.length, 1);
  assert.equal(l.focus, undefined);
}
""")


if __name__ == "__main__":
    unittest.main()

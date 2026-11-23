"""Real JS controller -> loopback gateway -> Bearer BFF -> temporary SQLite.

Node uses a MOCK DOM and a constrained HTTP cookie jar, not a real browser.
Native cookie policy, browser rendering/accessibility/UX remain NOT VERIFIED.
The pairing code is passed only on stdin and in the pairing POST body.
"""

import hashlib
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest

from src.baseline.model import BaselineCandidate, BaselineStatus
from src.baseline.sqlite_store import SQLiteBaselineStore
from src.bff.local_ui import LocalBaselineHOME


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
NETWORK_VIOLATIONS = []


def network_boundary(event, args):
    if event == "socket.getaddrinfo":
        NETWORK_VIOLATIONS.append(event)
        raise AssertionError("DNS forbidden in local UI tests")
    if event in ("socket.bind", "socket.connect", "socket.sendto"):
        address = args[1] if event != "socket.sendto" else args[-1]
        if type(address) is not tuple or address[0] != "127.0.0.1":
            NETWORK_VIOLATIONS.append(event)
            raise AssertionError("only numeric loopback fixture traffic allowed")


sys.addaudithook(network_boundary)
IDS = ["pair-form", "pair-code", "pair-button", "connection-status", "reload-list", "list-message",
       "baseline-list", "list-next", "detail-message", "baseline-detail", "history-message",
       "baseline-history", "history-next", "approval-panel", "approval-confirm", "approve-button",
       "approval-message"]

HARNESS = r'''
const assert = require('node:assert/strict');
const http = require('node:http');
const dns = require('node:dns');
dns.lookup = () => { throw Error('DNS forbidden'); };
const app = require(APP_PATH);
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this._text = ''; this.value = '';
    this.disabled = false; this.hidden = false; this.checked = false; this.events = {}; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(' '); }
  set innerHTML(value) { throw Error('HTML injection sink forbidden'); }
  get firstChild() { return this.children[0] || null; }
  appendChild(child) { this.children.push(child); return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(type, fn) { this.events[type] = fn; }
}
const elements = Object.fromEntries(IDS.map(id => [id, new Element(id)]));
const document = { getElementById: id => elements[id], createElement: tag => {
  assert.ok(['tr', 'td', 'button', 'dt', 'dd', 'li'].includes(tag)); return new Element(tag);
}};
let jar = '', savedCookie = '', interceptedStatus = null;
let dropApprovalReply = false, refuseApprovalBeforeSend = false;
const requests = [];
function fetchLocal(path, options) {
  assert.ok(path === '/api/baselines' || path.startsWith('/api/baselines?') ||
    path.startsWith('/api/baselines/') || path === '/local/pair');
  assert.ok(!path.includes(PAIR_CODE));
  assert.equal(options.credentials, 'same-origin');
  assert.equal(options.mode, 'same-origin');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  requests.push({path, method: options.method});
  if (path === '/api/baselines/_approval/approve') {
    assert.match(options.headers['X-SiteProof-CSRF'], /^[A-Za-z0-9_-]{43}$/);
    assert.ok(!path.includes(options.headers['X-SiteProof-CSRF']));
    if (refuseApprovalBeforeSend) { refuseApprovalBeforeSend = false; return Promise.reject(Error('connection lost')); }
  }
  if (interceptedStatus !== null) {
    const status = interceptedStatus; interceptedStatus = null;
    return Promise.resolve({status, json: async () => ({})});
  }
  return new Promise((resolve, reject) => {
    const headers = Object.assign({}, options.headers || {}, {'Host': AUTHORITY,
      'Origin': ORIGIN, 'Sec-Fetch-Site': 'same-origin'});
    assert.ok(!Object.keys(headers).some(k => k.toLowerCase() === 'authorization'));
    if (jar && path.startsWith('/api/baselines')) { headers.Cookie = jar; }
    if (options.body) { headers['Content-Length'] = Buffer.byteLength(options.body); }
    const req = http.request({host: '127.0.0.1', port: PORT, path, method: options.method,
      headers, family: 4, agent: false, lookup: () => reject(Error('DNS forbidden'))}, res => {
      const chunks = []; let size = 0;
      res.on('data', data => { size += data.length; assert.ok(size < 262145); chunks.push(data); });
      res.on('end', () => {
        if (res.headers['set-cookie']) {
          const cookie = res.headers['set-cookie'][0];
          assert.match(cookie, /HttpOnly/); assert.match(cookie, /SameSite=Strict/);
          assert.ok(cookie.includes('Path=/api/baselines'));
          jar = cookie.split(';')[0]; savedCookie = jar;
        }
        const raw = Buffer.concat(chunks).toString('utf8');
        assert.ok(!raw.includes(PAIR_CODE));
        if (dropApprovalReply && path === '/api/baselines/_approval/approve') {
          dropApprovalReply = false; reject(Error('reply lost after commit')); return;
        }
        resolve({status: res.statusCode, json: async () => JSON.parse(raw)});
      });
    });
    req.setTimeout(1500, () => req.destroy(Error('HTTP fixture deadline')));
    req.on('error', reject);
    if (options.body) { req.write(options.body); }
    req.end();
  });
}
const controller = app.createController({document, fetch: fetchLocal});
const $ = id => elements[id];
'''


class LocalBaselineUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-local-baseline-ui-01-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "siteproof.sqlite"
        self.store = SQLiteBaselineStore.create(self.db, self.root)
        self.server = None
        self.addCleanup(self.stop_server)

    def stop_server(self):
        if self.server is not None:
            self.assertTrue(self.server.stop())
            self.assertEqual(self.server._server.socket.fileno(), -1)
            self.assertEqual(self.server.backend._server.socket.fileno(), -1)
        self.assertEqual(NETWORK_VIOLATIONS, [])

    def add(self, cid, *, current=0, approve=False, profile="a" * 64):
        record = self.store.register(BaselineCandidate(cid, "page-1", profile,
            "job/attempt/shot.png", "b" * 64))
        if approve:
            self.store.decide(cid, decision=BaselineStatus.APPROVED, actor="alice",
                expected_revision=0, reviewed_digest=record.registered_digest,
                expected_current_version=current)

    def run_js(self, code, *, missing=False, approval_actor=None, writes=False):
        if NODE is None:
            self.skipTest("installed Node required; no dependency installation")
        path = self.root / "missing.sqlite" if missing else self.db
        self.server = LocalBaselineHOME(path, self.root, approval_actor=approval_actor)
        self.server.start()
        declarations = {
            "APP_PATH": str(ROOT / "src/bff/ui/baseline.js"), "IDS": IDS,
            "PAIR_CODE": self.server.pairing_for_local_user(), "AUTHORITY": self.server.authority,
            "ORIGIN": self.server.origin, "PORT": self.server.address[1],
        }
        script = "\n".join("const " + k + " = " + json.dumps(v) + ";" for k, v in declarations.items())
        script += HARNESS + "\n(async () => {\n" + code + "\n})().catch(() => { process.stderr.write('UI fixture failed'); process.exitCode = 1; });"
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        result = subprocess.run([NODE, "-"], input=script, text=True, capture_output=True,
                                timeout=15, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        if writes:
            self.assertNotEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        else:
            self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)

    def test_A01_A02_A05_explicit_confirmation_double_click_and_history_refresh(self):
        self.add("old", approve=True)
        old = self.store.get("old")
        self.add("pending")
        self.run_js(r'''
await controller.start();
$('pair-code').value = PAIR_CODE; await controller.pair();
await controller.approve();
await controller.select('pending');
assert.equal($('approval-panel').hidden, false);
assert.equal($('approval-confirm').checked, false);
assert.equal($('approve-button').disabled, true);
const details = $('baseline-detail').textContent;
for (const value of ['page-1', 'pending', 'revision 0', 'job/attempt/shot.png', 'BASELINE_PENDING', '現行version 1']) {
  assert.ok(details.includes(value));
}
assert.match(details, /digest [0-9a-f]{64}/);
await controller.approve();
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 0);
$('approval-confirm').checked = true; $('approval-confirm').events.change();
assert.equal($('approve-button').disabled, false);
const operation = controller.approve();
assert.equal($('approve-button').disabled, true);
await controller.approve(); // second click during the in-flight operation is ignored
await operation;
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 1);
assert.equal($('approval-message').textContent, 'Baseline承認済み');
assert.ok($('baseline-detail').textContent.includes('APPROVED'));
assert.ok($('baseline-detail').textContent.includes('revision 1'));
assert.ok($('baseline-detail').textContent.includes('fixture-local-operator'));
assert.ok($('baseline-detail').textContent.includes('現行version 2'));
assert.ok($('baseline-history').textContent.includes('（過去版）'));
assert.ok($('baseline-history').textContent.includes('（現行版）'));
assert.equal($('approval-panel').hidden, true);
assert.equal($('approval-confirm').checked, false);
''', approval_actor="fixture-local-operator", writes=True)
        self.assertEqual(self.store.get("old"), old)
        self.assertEqual(self.store.get("pending").revision, 1)
        self.assertEqual(len(self.store.history("page-1", "a" * 64)), 2)

    def test_A13_reply_lost_after_commit_requeries_without_success_claim_or_retry(self):
        self.add("pending")
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
await controller.select('pending');
$('approval-confirm').checked = true;
dropApprovalReply = true;
await controller.approve();
assert.ok($('approval-message').textContent.includes('承認結果は未確認です'));
assert.ok(!$('approval-message').textContent.includes('Baseline承認済み'));
assert.ok($('baseline-detail').textContent.includes('APPROVED'));
assert.ok($('baseline-history').textContent.includes('（現行版）'));
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 1);
await controller.approve();
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 1);
''', approval_actor="fixture-local-operator", writes=True)
        self.assertEqual(self.store.get("pending").revision, 1)

    def test_A13_connection_lost_before_write_requeries_pending_and_requires_new_confirmation(self):
        self.add("pending")
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
await controller.select('pending'); $('approval-confirm').checked = true;
refuseApprovalBeforeSend = true; await controller.approve();
assert.ok($('approval-message').textContent.includes('承認結果は未確認です'));
assert.ok($('baseline-detail').textContent.includes('BASELINE_PENDING'));
assert.equal($('history-message').textContent, '履歴はありません');
assert.equal($('approval-confirm').checked, false);
assert.equal($('approve-button').disabled, true);
await controller.approve();
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 1);
''', approval_actor="fixture-local-operator")

    def test_A03_A04_A07_A10_errors_never_automatically_approve_or_claim_success(self):
        self.add("pending")
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
for (const [status, expected] of [[409, '再確認'], [422, 'digest'], [403, '承認を拒否'], [503, '未確認']]) {
  await controller.select('pending'); $('approval-confirm').checked = true;
  interceptedStatus = status; await controller.approve();
  assert.ok($('approval-message').textContent.includes(expected));
  assert.ok(!$('approval-message').textContent.includes('Baseline承認済み'));
  assert.equal($('approval-confirm').checked, false);
  assert.equal($('approve-button').disabled, true);
}
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 4);
assert.ok($('baseline-detail').textContent.includes('BASELINE_PENDING'));
''', approval_actor="fixture-local-operator")

    def test_A06_invalid_cookie_on_approval_clears_protected_data(self):
        self.add("pending")
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
await controller.select('pending'); $('approval-confirm').checked = true;
jar = jar.split('=')[0] + '=wrong'; await controller.approve();
assert.equal($('approval-message').textContent, '認証が必要です');
assert.equal($('pair-form').hidden, false);
assert.equal($('approval-panel').hidden, true);
assert.equal($('baseline-list').children.length, 0);
assert.equal($('baseline-detail').children.length, 0);
assert.equal($('baseline-history').children.length, 0);
''', approval_actor="fixture-local-operator")

    def test_A14_approval_payload_and_actor_are_text_only(self):
        malicious = '<img src=x onerror="throw 1">'
        self.add(malicious)
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
await controller.select('<img src=x onerror="throw 1">');
$('approval-confirm').checked = true; await controller.approve();
assert.equal($('approval-message').textContent, 'Baseline承認済み');
assert.ok($('baseline-detail').textContent.includes('<img src=x onerror="throw 1">'));
assert.ok($('baseline-history').textContent.includes('<img src=x onerror="throw 1">'));
''', approval_actor=malicious, writes=True)

    def test_A02_no_configured_local_operator_retains_view_only(self):
        self.add("pending")
        self.run_js(r'''
await controller.start(); $('pair-code').value = PAIR_CODE; await controller.pair();
await controller.select('pending');
assert.equal($('approval-panel').hidden, true);
assert.ok($('approval-message').textContent.includes('操作主体の指定が必要です'));
$('approval-confirm').checked = true; await controller.approve();
assert.equal(requests.filter(r => r.path.endsWith('/approve')).length, 0);
''')

    def test_authenticated_controller_reads_real_sqlite_list_current_detail_history_and_errors(self):
        self.add("old", approve=True)
        self.add("new", approve=True, current=1)
        self.add("pending", profile="c" * 64)
        self.run_js(r'''
await controller.start();
assert.equal($('connection-status').textContent, '認証が必要です');
$('pair-code').value = PAIR_CODE;
const pairing = controller.pair();
assert.equal($('pair-code').value, '');
await pairing;
assert.equal($('baseline-list').children.length, 3);
assert.ok($('baseline-list').textContent.includes('APPROVED'));
assert.ok($('baseline-list').textContent.includes('BASELINE_PENDING'));
assert.ok($('list-message').textContent.includes('Desktop/Mobile区分は保存されていません'));
await controller.select('old');
assert.ok($('baseline-detail').textContent.includes('現行version 2'));
assert.ok($('baseline-detail').textContent.includes('alice'));
assert.ok($('baseline-history').textContent.includes('（過去版）'));
assert.ok($('baseline-history').textContent.includes('（現行版）'));
await controller.select('pending');
assert.ok($('baseline-detail').textContent.includes('revision 0'));
assert.equal($('history-message').textContent, '履歴はありません');
await controller.select('missing');
assert.equal($('detail-message').textContent, 'Baselineが見つかりません');
assert.equal($('baseline-detail').children.length, 0);
await controller.select('new');
jar = jar.split('=')[0] + '=wrong';
await controller.refreshList(0);
assert.equal($('connection-status').textContent, '認証が必要です');
assert.equal($('baseline-list').children.length, 0);
assert.equal($('baseline-detail').children.length, 0);
assert.equal($('baseline-history').children.length, 0);
assert.equal($('pair-form').hidden, false);
assert.ok(requests.every(r => r.method === 'GET' || r.method === 'POST' && r.path === '/local/pair'));
''')

    def test_zero_candidates_is_not_database_failure(self):
        self.run_js(r'''
$('pair-code').value = PAIR_CODE; await controller.pair();
assert.equal($('list-message').textContent, 'Baselineが登録されていません');
assert.equal($('baseline-list').children.length, 0);
''')

    def test_database_failure_is_never_shown_as_zero_or_success(self):
        self.run_js(r'''
$('pair-code').value = PAIR_CODE; await controller.pair();
assert.equal($('list-message').textContent, 'Baselineを取得できません');
assert.equal($('baseline-list').children.length, 0);
assert.ok(!$('connection-status').textContent.includes('接続中'));
''', missing=True)

    def test_html_payload_is_only_text_and_does_not_change_trust(self):
        malicious = '<img src=x onerror="throw 1">'
        self.add(malicious, approve=True)
        self.run_js(r'''
$('pair-code').value = PAIR_CODE; await controller.pair();
assert.ok($('baseline-list').textContent.includes('<img src=x onerror="throw 1">'));
await controller.select('<img src=x onerror="throw 1">');
assert.ok($('baseline-detail').textContent.includes('<img src=x onerror="throw 1">'));
assert.ok($('baseline-history').textContent.includes('<img src=x onerror="throw 1">'));
assert.equal($('baseline-list').children.length, 1);
''')

    def test_static_page_no_write_operations_or_public_auth_integration(self):
        html = (ROOT / "src/bff/ui/index.html").read_text(encoding="utf-8")
        js = (ROOT / "src/bff/ui/baseline.js").read_text(encoding="utf-8")
        public = (ROOT / "web/home/index.html").read_text(encoding="utf-8")
        for term in ("PROFILE_UNATTESTED", "UNKNOWN", "Web品質PASSではありません"):
            self.assertIn(term, html)
        for term in ("innerHTML", "localStorage", "sessionStorage", "document.cookie", "Authorization", "Bearer"):
            self.assertNotIn(term, js)
        self.assertNotIn("/local/pair", public)
        self.assertNotIn("/api/baselines", public)
        self.assertNotIn("web/local", public)
        self.assertIn("connect-src 'none'", public)
        for method in ("PUT", "PATCH", "DELETE"):
            self.assertNotIn("method: '" + method + "'", js)


if __name__ == "__main__":
    unittest.main()

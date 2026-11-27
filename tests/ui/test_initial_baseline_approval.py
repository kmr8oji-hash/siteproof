"""The first Baseline (automatic, version 1) can be formally approved by the USER, as it is: still version 1, nothing else changes.

Offline: the same capture test double as the lifecycle tests (synthetic page image, real comparison and permit code); no Docker, no network,
no real site. What this does NOT show: the panel in a real browser, or a real inspection after the approval.
"""
import hashlib
import json
from pathlib import Path
import socket
import threading
import unittest

from src.noxiworks.app import serve, utc_now
from src.noxiworks.baseline_registry import STANDING_LABELS, baseline_standing, standing, valid_formal
from src.noxiworks.real_capture import RealCaptureRefused
from src.noxiworks.site_workflow import ACTOR
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


@needs_ssh
class InitialApproval(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=12)
        self.real = self.app.site.root / 'real'
        self.site = self.app.site
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))   # v1, made automatically
        self.shown = self.targets()                                              # what the screen offered for v1

    def inspect(self, variant='same'):
        self.h.fake.variant = variant
        return self.h.outcome(self.app)

    def targets(self):
        return json.loads(json.dumps(self.site.baseline_state()['targets']))

    def approve(self, expected=None):
        return self.app.monitor().approve_baseline(self.shown if expected is None else expected, utc_now(), ACTOR)

    def pages(self):
        self.app.rebuild_site()
        self.assertIsNone(self.app.site_error)
        return {n: (self.app.site_ui / n).read_text('utf-8') for n in ('index.html', 'review.html', 'details.html', 'evidence.html')}

    def untouched(self):
        """Everything a formal approval must leave exactly as it is."""
        return {'registry': tree(self.real / 'registry'), 'origin': (self.real / 'registry-origin.json').read_bytes(),
                'runs': tree(self.real / 'runs'), 'ledger': tree(self.app.data / 'trust' / 'permit-ledger'),
                'permit': (self.real / 'permit.json').read_bytes(), 'permit_sig': (self.real / 'permit.json.sig').read_bytes(),
                'monitor': self.app.monitor().load(), 'history': (self.real / 'registry-history').exists()}

    # ---- the three states are three states
    def test_automatic_confirmed_and_formally_approved_are_told_apart(self):
        self.assertEqual(self.site.baseline_state()['state'], 'AUTO')
        self.assertIn('自動作成・未確認', self.pages()['review.html'])
        self.site.confirm_baseline(utc_now())
        self.assertEqual(self.site.baseline_state()['state'], 'CONFIRMED')                  # looked at: not approved
        pages = self.pages()
        self.assertIn('自動作成・USER確認済み', pages['review.html'])
        self.assertNotIn('正式承認済み', pages['review.html'] + pages['index.html'])
        self.approve()
        state = self.site.baseline_state()
        self.assertEqual((state['state'], state['versions']), ('USER', {'Desktop': 1}))
        self.assertEqual(state['formal']['actor'], ACTOR)
        pages = self.pages()
        for name in ('review.html', 'evidence.html'):
            self.assertIn('正式承認済み', pages[name], name)
        self.assertIn('Baseline 正式承認済み', pages['index.html'])
        self.assertIn('正式承認（USER）', pages['details.html'])
        self.assertIn('USERが正式に承認したBaseline', pages['details.html'])
        self.assertNotIn('自動作成・未確認', pages['review.html'])

    # ---- version 1 stays version 1; nothing else is touched
    def test_the_approval_keeps_version_1_and_changes_nothing_but_adds_its_own_record(self):
        before = self.untouched()
        record = self.approve()
        after = self.untouched()
        self.assertEqual(after, before)                                                     # registry, evidence, ledger, permit, monitor, history
        self.assertEqual(self.site.baseline_history(), [])                                  # no second version, no history entry
        self.assertEqual(self.site.baseline_state()['versions'], {'Desktop': 1})
        self.assertEqual(json.loads((self.real / 'baseline-approval.json').read_text('utf-8')), record)
        self.assertEqual(record['not_changed']['baseline_version'], 'same')
        # the record is bound to this registry and these Baselines, and sits beside it, not inside it
        self.assertFalse((self.real / 'registry' / 'baseline-approval.json').exists())
        self.assertEqual(record['registry_export_sha256'], hashlib.sha256((self.real / 'registry' / 'export-sha256.json').read_bytes()).hexdigest())
        # quality and profile trust are what they were: an approval is not a quality verdict
        approval = json.loads((self.real / 'registry' / 'APPROVAL-RECORD.json').read_text('utf-8'))
        self.assertEqual({(b['quality'], b['profile_reason']) for b in approval['baselines']}, {('UNKNOWN', 'PROFILE_UNATTESTED')})
        self.assertNotIn('品質PASS', self.pages()['review.html'])
        # the next inspection still pins version 1; monitoring was not started or stopped by the approval
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))
        last = sorted((self.real / 'runs').iterdir())[-1]
        result = json.loads((last / last.name / 'Desktop-run-result.json').read_text('utf-8'))
        self.assertEqual(result['comparison']['results'][0]['baseline']['version'], 1)

    # ---- refusals
    def refused(self, expected=None, why=RealCaptureRefused):
        before = self.untouched()
        existed = (self.real / 'baseline-approval.json').exists()
        with self.assertRaises(why):
            self.approve(expected)
        self.assertEqual(self.untouched(), before)
        self.assertEqual((self.real / 'baseline-approval.json').exists(), existed)
        self.assertFalse((self.real / 'baseline-approval.json.tmp').exists())

    def test_a_second_approval_is_refused_and_the_first_record_is_kept(self):
        first = self.approve()
        kept = (self.real / 'baseline-approval.json').read_bytes()
        self.refused()
        self.assertEqual((self.real / 'baseline-approval.json').read_bytes(), kept)
        self.assertEqual(json.loads(kept.decode('utf-8')), first)

    def test_what_the_user_saw_must_be_what_is_current(self):
        good = self.shown
        for field, value in (('candidate_id', 'capture-other'), ('version', 2), ('png_sha256', '0' * 64), ('candidate_digest', '1' * 64)):
            wrong = json.loads(json.dumps(good))
            wrong['Desktop'][field] = value
            with self.subTest(field=field):
                self.refused(wrong)
        self.refused({})
        self.refused({'Mobile': good['Desktop']})
        self.refused({'Desktop': good['Desktop'], 'Mobile': good['Desktop']})
        self.assertEqual(self.site.baseline_state()['state'], 'AUTO')

    def test_a_registry_that_differs_from_its_hashes_is_refused(self):
        png = next(p for p in (self.real / 'registry').rglob('*.png'))
        png.write_bytes(png.read_bytes() + b'x')
        before = tree(self.real / 'registry')
        with self.assertRaises(RealCaptureRefused):
            self.approve({'Desktop': {'candidate_id': 'x'}})
        with self.assertRaises(RealCaptureRefused):
            self.approve()
        self.assertEqual(tree(self.real / 'registry'), before)
        self.assertFalse((self.real / 'baseline-approval.json').exists())

    def test_an_approval_does_not_survive_a_changed_registry_or_a_tampered_record(self):
        self.approve()
        record_path = self.real / 'baseline-approval.json'
        good = record_path.read_text('utf-8')
        self.assertEqual(self.site.baseline_state()['state'], 'USER')
        registry = self.site.real_registry()
        record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
        for change in ({'registry_export_sha256': '0' * 64}, {'actor': ''}, {'actor': 'SiteProof自動作成（x）'}, {'schema': 'x'},
                       {'baselines': [{**json.loads(good)['baselines'][0], 'version': 2}]}):
            record_path.write_text(json.dumps({**json.loads(good), **change}), encoding='utf-8')
            self.assertIsNone(valid_formal(registry, record['baselines']), change)
            self.assertIn(self.site.baseline_state()['state'], ('AUTO', 'CONFIRMED'), change)   # never "approved" on a bad record
        record_path.write_text('{not json', encoding='utf-8')
        self.assertIn(self.site.baseline_state()['state'], ('AUTO', 'CONFIRMED'))
        record_path.write_text(good, encoding='utf-8')
        self.assertEqual(self.site.baseline_state()['state'], 'USER')

    def test_an_unfinished_baseline_switch_blocks_the_approval(self):
        (self.real / 'baseline-switch.json').write_text('{}', encoding='utf-8')
        before = self.untouched()
        with self.assertRaises(RealCaptureRefused):
            self.approve()
        self.assertFalse((self.real / 'baseline-approval.json').exists())

    def test_an_inspection_in_progress_blocks_the_approval(self):
        from src.noxiworks.site_monitor import Busy
        monitor = self.app.monitor()
        monitor._lock(utc_now())
        try:
            with self.assertRaises(Busy):
                self.approve()
        finally:
            monitor.lock_path.unlink(missing_ok=True)
        self.assertFalse((self.real / 'baseline-approval.json').exists())

    # ---- and the road on: v1 (formal) -> v2
    def test_after_the_formal_approval_a_change_can_still_become_version_2(self):
        self.approve()
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))
        offer = self.app.monitor().real().baseline_update_state()
        self.assertEqual((offer['state'], offer['versions']), ('AVAILABLE', {'Desktop': 1}))
        v1 = tree(self.real / 'registry')
        approval = (self.real / 'baseline-approval.json').read_bytes()
        state = self.app.monitor().real().baseline_update_state()
        record = self.app.monitor().update_baseline(state['run_id'], state['versions'], utc_now(), ACTOR)
        self.assertEqual(record['baselines'][0]['version'], 2)
        self.assertEqual(self.site.baseline_state()['state'], 'USER')
        self.assertEqual(self.site.baseline_state()['versions'], {'Desktop': 2})
        history = self.site.baseline_history()
        self.assertEqual([h['versions'] for h in history], [{'Desktop': 1}])
        self.assertEqual(tree(self.real / 'registry-history' / history[0]['name']), v1)    # v1 is kept as it was approved
        self.assertEqual((self.real / 'baseline-approval.json').read_bytes(), approval)    # the record of v1 stays; it names v1's registry only
        self.assertIsNone(valid_formal(self.real / 'registry', json.loads((self.real / 'registry' / 'APPROVAL-RECORD.json').read_text('utf-8'))['baselines']))
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))
        # v2 is a USER_UPDATE Baseline: formal already, so there is nothing left to approve; v1's record cannot approve v2
        self.assertNotIn('targets', self.site.baseline_state())
        self.refused()

    def test_the_regular_update_still_needs_a_change(self):
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))
        self.assertEqual(self.app.monitor().real().baseline_update_state()['state'], 'NONE')   # formal approval of v1 is its own action

    # ---- the app's door
    def test_the_route_needs_the_session_token_the_explicit_confirmation_and_the_exact_baseline(self):
        server, served = serve(self.app.data, 0, scheduler=False)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), served.stop()))
        port = server.server_address[1]
        authority = f'127.0.0.1:{port}'

        def call(method, path, body=None):
            # a plain socket to the numeric loopback address: no name lookup (other suites forbid it in the same process)
            payload = json.dumps(body).encode() if body is not None else b''
            crlf = bytes((13, 10))
            lines = [f'{method} {path} HTTP/1.1', f'Host: {authority}', 'X-SiteProof-App: 1', 'Connection: close']
            if body is not None:
                lines += [f'Origin: http://{authority}', 'Content-Type: application/json', f'Content-Length: {len(payload)}']
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(60)
                conn.connect(('127.0.0.1', port))
                conn.sendall(crlf.join(x.encode() for x in lines) + crlf + crlf + payload)
                raw = b''
                while chunk := conn.recv(65536):
                    raw += chunk
            top, _, rest = raw.partition(crlf + crlf)
            return int(top.split(b' ', 2)[1]), json.loads(rest or b'{}')
        status, session = call('GET', '/app/api/session')
        targets = session['site']['baseline']['targets']
        self.assertEqual((status, session['site']['baseline']['state']), (200, 'AUTO'))
        route = '/app/api/site/baseline-approve'
        body = {'token': session['token'], 'expected': targets}
        self.assertEqual(call('POST', route, {**body, 'token': 'wrong', 'confirmed': True})[0], 403)    # no token, no approval
        self.assertEqual(call('POST', route, body)[0], 422)                                          # no explicit confirmation
        self.assertEqual(call('POST', route, {**body, 'confirmed': 'yes'})[0], 422)
        self.assertEqual(call('POST', route, {**body, 'confirmed': True, 'expected': {}})[0], 422)
        wrong = json.loads(json.dumps(targets))
        wrong['Desktop']['png_sha256'] = '0' * 64
        self.assertEqual(call('POST', route, {**body, 'confirmed': True, 'expected': wrong})[0], 422)
        self.assertEqual(self.site.baseline_state()['state'], 'AUTO')                                  # nothing happened so far
        status, answer = call('POST', route, {**body, 'confirmed': True})
        self.assertEqual((status, answer['result']), (200, {'state': 'USER'}))
        self.assertEqual(call('POST', route, {**body, 'confirmed': True})[0], 422)                    # the same approval again
        status, session = call('GET', '/app/api/session')
        self.assertNotIn('targets', session['site']['baseline'])                                       # nothing left to offer

    def test_the_review_panel_asks_for_the_checkbox_and_sends_the_exact_baseline(self):
        js = (ROOT / 'src/noxiworks/app_assets/app.js').read_text('utf-8')
        for text in ("decision('baseline-approve', '初回Baselineを承認する'", 'このBaselineを正式承認', '/app/api/site/baseline-approve', 'confirmed: checked',
                     'expected: targets', "button.setAttribute('disabled', '')", '正式な承認ではありません（確認済みでも同じです）', 'app-bigcheck'):
            self.assertIn(text, js)
        self.assertIn('var targets = s.baseline.targets', js)            # only while the Baseline is automatic
        text = ''.join((ROOT / 'src/noxiworks' / n).read_text('utf-8') for n in ('app.py', 'site_app.py'))
        self.assertEqual(text.count('approve_baseline('), 1)              # one caller: the route, behind the token and the confirmation
        monitor = (ROOT / 'src/noxiworks/site_monitor.py').read_text('utf-8')
        self.assertNotIn('approve_baseline', monitor.split('def run(self', 1)[1])   # never from an inspection or a schedule


class Wording(unittest.TestCase):
    def test_labels_and_the_standing_of_a_formally_approved_registry(self):
        self.assertEqual(STANDING_LABELS['USER'][0], '正式承認済み')
        self.assertEqual(baseline_standing({'baseline_registry': {'standing': 'USER'}}), 'USER')


if __name__ == '__main__':
    unittest.main()

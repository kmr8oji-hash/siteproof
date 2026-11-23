"""S1-A operational visual verdict. Synthetic pixels, temporary SQLite; no browser/network/Docker."""
import unittest
from unittest.mock import patch

from src.comparison import preview
from src.comparison.operational import operational_verdict
from tests.comparison.support import Fixture, observations, synthetic_browser_audit

CHANGED, SAME, UNKNOWN = 'VISUAL_CHANGED', 'NO_VISUAL_CHANGE_DETECTED', 'UNKNOWN'


def audit(allowed=1, blocked=0, failed=0, **extra):
    entries = [{'host': 'h.example', 'port': 443, 'decision': d, 'reason': r, 'count': n}
               for d, r, n in (('ALLOW', 'ALLOW', allowed), ('BLOCK', 'NOT_ALLOWLISTED', blocked),
                               ('FAILED', 'DNS_TIMEOUT', failed)) if n]
    return {'schema': 'siteproof.network-audit.v1', 'source': 'TRUSTED_CONNECT_PROXY',
            'resource_types': 'NOT_OBSERVABLE', 'complete': True, 'allowed': allowed, 'blocked': blocked,
            'failed': failed, 'dropped': 0, 'in_flight': 0, 'entries': entries, **extra}


class OperationalVerdictTests(unittest.TestCase):
    """The real-site configuration: no trusted authority, explicit unattested-preview opt-in."""

    def fixture(self, *, preview=True, **kwargs):
        f = Fixture(**{'trusted': False, **kwargs}); self.addCleanup(f.close)
        f.comparison.allow_unattested_preview = preview
        return f

    def approved(self, f):
        for job in f.run()['jobs']: f.approve(job['candidate'])

    def newest(self, f, **run):
        results = f.run(**run)['results'][:2]
        self.assertEqual(len(results), 2)
        return results

    def verdicts(self, results):
        return {r['operational']['verdict'] for r in results}

    def assert_strict_unattested(self, results):
        # The strict judgement is untouched: never PASS/CHANGED, attestation gap still reported.
        for r in results:
            self.assertEqual(r['quality'], 'UNKNOWN')
            self.assertEqual(r['profile_trust'], 'UNATTESTED')
            self.assertIn('PROFILE_UNATTESTED', r['reasons'])
            self.assertTrue(r['preview_only'])
            self.assertEqual(r['operational']['assurance'], 'NONE')
            self.assertEqual(r['operational']['renderer_authenticity'], 'NOT_ASSERTED')

    def assert_unknown(self, results, reason=None):
        self.assertEqual(self.verdicts(results), {UNKNOWN})
        for r in results:
            self.assertNotIn(r['quality'], ('PASS', 'CHANGED'))
            self.assertTrue(r['operational']['reasons'])
            self.assertIsNone(r['operational']['changed_pixels'])
            if reason: self.assertIn(reason, r['operational']['reasons'])

    def test_same_changed_and_restored_images(self):
        f = self.fixture(); self.approved(f)
        same = self.newest(f)
        self.assertEqual(self.verdicts(same), {SAME})
        self.assert_strict_unattested(same)
        for r in same:
            self.assertEqual(r['operational']['changed_pixels'], 0)
            # Equal hashes are byte equality only; they never lift the profile to trusted.
            self.assertEqual(r['current_sha256'], r['baseline_sha256'])
            self.assertEqual(r['profile_trust'], 'UNATTESTED')
            self.assertEqual(r['operational']['notes'], ['PROFILE_UNATTESTED'])
        changed = self.newest(f, changed=True)
        self.assertEqual(self.verdicts(changed), {CHANGED})
        self.assert_strict_unattested(changed)
        for r in changed:
            self.assertEqual(r['operational']['changed_pixels'], 1)
            self.assertNotEqual(r['current_sha256'], r['baseline_sha256'])
            self.assertIsNotNone(r['diff_sha256'])
        restored = self.newest(f)
        self.assertEqual(self.verdicts(restored), {SAME})
        self.assert_strict_unattested(restored)

    def test_strict_trusted_judgement_is_unchanged_and_consistent(self):
        f = Fixture(); self.addCleanup(f.close)
        for job in f.run()['jobs']: f.approve(job['candidate'])
        same = f.run()['results'][:2]
        self.assertEqual({r['quality'] for r in same}, {'PASS'})
        self.assertEqual({r['operational']['verdict'] for r in same}, {SAME})
        changed = f.run(changed=True)['results'][:2]
        self.assertEqual({r['quality'] for r in changed}, {'CHANGED'})
        self.assertEqual({r['operational']['verdict'] for r in changed}, {CHANGED})
        for r in same + changed:
            self.assertEqual(r['profile_trust'], 'TRUSTED_TEST')
            self.assertEqual(r['operational']['notes'], [])
            self.assertEqual(r['operational']['assurance'], 'NONE')

    def test_unattested_without_explicit_opt_in_is_unknown(self):
        f = self.fixture(preview=False); self.approved(f)
        results = self.newest(f)
        self.assert_unknown(results, 'COMPARISON_NOT_RUN')
        self.assertTrue(all(r['metrics'] is None and not r['preview_only'] for r in results))

    def test_capture_profile_mismatch_is_unknown(self):
        f = self.fixture(); self.approved(f)
        f.workspace.save_profile({'page_id': 'p', 'kind': 'Desktop', 'width': 9, 'height': 8, 'expected_revision': 2})
        results = self.newest(f)
        desktop = next(r for r in results if r['kind'] == 'Desktop')
        self.assertEqual(desktop['operational']['verdict'], UNKNOWN)
        self.assertIn('PROFILE_MISMATCH', desktop['operational']['reasons'])
        self.assertNotIn(desktop['quality'], ('PASS', 'CHANGED'))
        mobile = next(r for r in results if r['kind'] == 'Mobile')
        self.assertEqual(mobile['operational']['verdict'], SAME)

    def test_baseline_pending_or_unset_is_unknown(self):
        f = self.fixture()
        first = self.newest(f)  # No Baseline exists yet.
        self.assert_unknown(first, 'BASELINE_UNSET')
        second = self.newest(f)  # A candidate exists but was never approved.
        self.assert_unknown(second, 'BASELINE_UNSET')
        self.assertTrue(all('BASELINE_PENDING' in r['reasons'] and r['metrics'] is None for r in second))

    def test_corrupt_or_missing_baseline_and_current_evidence_is_unknown(self):
        for target in ('screenshot', 'manifest'):
            for mutation in ('corrupt', 'missing'):
                with self.subTest(target=target, mutation=mutation):
                    f = self.fixture(); state = f.run()
                    for job in state['jobs']: f.approve(job['candidate'])
                    binding = f.comparison.store.body('candidates', state['jobs'][0]['candidate']['candidate_id'])
                    path = f.root / binding['evidence'][target]['artifact_ref']
                    if mutation == 'corrupt': path.write_bytes(b'invalid synthetic corruption')
                    else: path.unlink()
                    results = self.newest(f)
                    broken = next(r for r in results if r['kind'] == state['jobs'][0]['kind'])
                    self.assertEqual(broken['operational']['verdict'], UNKNOWN)
                    self.assertIsNone(broken['metrics'])
                    # The current capture's own evidence is re-observed on every comparison too.
                    current = f.comparison.store.body('candidates', 'capture-' + broken['job_id'])
                    (f.root / current['evidence'][target]['artifact_ref']).write_bytes(b'fixture corruption')
                    again = f.comparison.compare(broken['job_id'])
                    self.assertEqual(again['operational']['verdict'], UNKNOWN)
                    self.assertIsNone(again['metrics'])

    def test_capture_failure_incomplete_render_and_cleanup_loss_are_unknown(self):
        for kwargs in ({'status': 404}, {'bad': True}, {'clean': False}, {'proxy_clean': False}):
            with self.subTest(kwargs=kwargs):
                f = self.fixture(); self.approved(f)
                results = self.newest(f, **kwargs)
                self.assert_unknown(results)
                if 'proxy_clean' in kwargs:
                    # Strict code skips the cleanup check without an authority; the verdict does not.
                    self.assertTrue(all(r['metrics'] is not None for r in results))
                    self.assert_unknown(results, 'CLEANUP_UNCONFIRMED')

    def test_wrong_dimensions_are_unknown(self):
        f = self.fixture(); self.approved(f)
        wrong = preview.png(7, 8, b'\0\0\0\xff' * (7 * 8))
        with patch('tests.comparison.support.Driver.capture', return_value=wrong):
            results = self.newest(f)
        self.assert_unknown(results, 'CAPTURE_DIMENSIONS_MISMATCH')

    def test_unstable_capture_is_unknown_even_though_strict_preview_tolerates_it(self):
        def unstable(profile, phase, jid):
            data = observations(profile, phase, jid)
            data['stability_result']['value'] = 'UNSTABLE'
            return data
        f = Fixture(observer=unstable); self.addCleanup(f.close)
        f.comparison.allow_unattested_preview = True
        for job in f.run()['jobs']: f.approve(job['candidate'])
        results = f.run(changed=True)['results'][:2]
        self.assertTrue(all(r['preview_only'] and r['preview_changed'] for r in results))
        self.assert_unknown(results, 'CAPTURE_UNSTABLE')

    def test_baseline_from_a_different_source_is_unknown(self):
        f = self.fixture()
        for job in f.run(batch=f.runtime.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED'))['jobs']:
            f.approve(job['candidate'])
        results = self.newest(f)
        self.assertEqual({r['source'] for r in results}, {'OFFLINE_FIXTURE_UNATTESTED'})
        self.assert_unknown(results, 'BASELINE_SOURCE_MISMATCH')

    def test_pure_function_fails_closed(self):
        base = dict(reasons=['PROFILE_UNATTESTED'], metrics={'changed_pixels': 3},
                    policy={'maximum_changed_pixels': 3}, baseline={'candidate_id': 'c'}, source='S',
                    baseline_source='S', execution='COMPLETED', cleanup_confirmed=True,
                    profile_trust='UNATTESTED', network_audit=audit(), baseline_network_audit=audit(),
                    browser_audit=synthetic_browser_audit('ok'), baseline_browser_audit=synthetic_browser_audit('ok'))
        verdict = lambda **kw: operational_verdict(**{**base, **kw})['verdict']
        self.assertEqual(verdict(), SAME)  # threshold is inclusive: only strictly more changes.
        self.assertEqual(verdict(metrics={'changed_pixels': 4}), CHANGED)
        for override in ({'reasons': ['PROFILE_UNATTESTED', 'CAPTURE_UNSTABLE']}, {'reasons': ['CHECK_FAILED']},
                         {'metrics': None}, {'metrics': {'changed_pixels': True}}, {'metrics': {}},
                         {'policy': None}, {'policy': {'maximum_changed_pixels': 3.0}}, {'baseline': None},
                         {'baseline_source': 'T'}, {'execution': 'FAILED_EXECUTION'},
                         {'cleanup_confirmed': False}, {'cleanup_confirmed': None},
                         {'source': None, 'baseline_source': None}, {'source': '', 'baseline_source': ''},
                         {'browser_audit': None}, {'baseline_browser_audit': None}, {'browser_audit': synthetic_browser_audit('tls')},
                         {'baseline_browser_audit': synthetic_browser_audit('http404')}, {'browser_audit': synthetic_browser_audit('pending')},
                         {'browser_audit': {'schema': 'x'}},
                         {'network_audit': None}, {'baseline_network_audit': None},
                         {'network_audit': audit(complete=False)}, {'network_audit': audit(allowed=0)},
                         {'network_audit': audit(blocked=1)}, {'network_audit': audit(failed=1)},
                         {'baseline_network_audit': audit(blocked=1)}, {'baseline_network_audit': audit(failed=1)},
                         {'network_audit': {**audit(), 'allowed': 0}}, {'network_audit': {**audit(), 'complete': None}},
                         {'network_audit': {**audit(), 'source': 'BROWSER_REPORT'}},
                         {'network_audit': {**audit(), 'entries': 'none'}}, {'network_audit': 'clean'},
                         {'network_audit': {'schema': 'siteproof.network-audit.v1', 'source': 'UNAVAILABLE',
                                            'complete': False, 'entries': []}}):
            with self.subTest(override=override):
                self.assertEqual(verdict(**override), UNKNOWN)

    def test_browser_startup_traffic_before_the_document_is_kept_but_not_blocking(self):
        f = self.fixture(); self.approved(f)
        for r in self.newest(f, net='prelude'):
            a = r['network_audit']
            self.assertEqual(r['operational']['verdict'], SAME)
            self.assertEqual((a['prelude']['blocked'], a['prelude']['idle'], a['blocked'], a['failed']), (1, 1, 0, 0))
            self.assertTrue(a['anchor']['seen'] and a['complete'])
            self.assertTrue(any(t[2] == 'www.google.com' for t in a['timeline']))  # Retained, with its order.
        # An ALLOWed connection before the document cannot be explained away.
        self.assert_unknown(self.newest(f, net='prelude_allowed'), 'PRELUDE_CONNECTION_ALLOWED')

    def test_v2_audit_without_the_anchor_connection_is_unknown(self):
        v2 = {**audit(), 'schema': 'siteproof.network-audit.v2', 'idle': 0,
              'anchor': {'host': 'h.example', 'port': 443, 'seen': False},
              'prelude': {'allowed': 0, 'blocked': 0, 'failed': 0, 'idle': 0, 'entries': []}}
        def verdict(a):
            return operational_verdict(reasons=['PROFILE_UNATTESTED'], metrics={'changed_pixels': 0},
                policy={'maximum_changed_pixels': 0}, baseline={'candidate_id': 'c'}, source='S', baseline_source='S',
                execution='COMPLETED', cleanup_confirmed=True, profile_trust='UNATTESTED',
                network_audit=a, baseline_network_audit=audit(),
                browser_audit=synthetic_browser_audit('ok'), baseline_browser_audit=synthetic_browser_audit('ok'))
        self.assertIn('NETWORK_AUDIT_ANCHOR_MISSING', verdict(v2)['reasons'])
        good = {**v2, 'anchor': {**v2['anchor'], 'seen': True}}
        self.assertEqual(verdict(good)['verdict'], SAME)
        # Prelude refusals are fine; a prelude ALLOW or inconsistent prelude counts are not.
        refused = {**good, 'prelude': {**good['prelude'], 'blocked': 2, 'entries': [
            {'host': None, 'port': None, 'decision': 'BLOCK', 'reason': 'X', 'count': 2}]}}
        self.assertEqual(verdict(refused)['verdict'], SAME)
        allowed = {**good, 'prelude': {**good['prelude'], 'allowed': 1, 'entries': [
            {'host': 'o.example', 'port': 443, 'decision': 'ALLOW', 'reason': 'ALLOW', 'count': 1}]}}
        self.assertIn('PRELUDE_CONNECTION_ALLOWED', verdict(allowed)['reasons'])
        self.assertIn('NETWORK_AUDIT_INVALID', verdict({**good, 'prelude': {**good['prelude'], 'blocked': 3}})['reasons'])

    # --- S2-A-FIX: the page context's own request audit ---------------------------------------

    def test_browser_audit_failures_make_the_verdict_unknown_with_a_specific_reason(self):
        for browser, reason in (('tls', 'TLS_VALIDATION_FAILED'), ('load', 'RESOURCE_LOAD_FAILED'), ('http404', 'RESOURCE_LOAD_FAILED'),
                                ('none', 'BROWSER_AUDIT_UNAVAILABLE'), ('unavailable', 'BROWSER_AUDIT_UNAVAILABLE'),
                                ('invalid', 'BROWSER_AUDIT_INVALID'), ('pending', 'BROWSER_AUDIT_INCOMPLETE'),
                                ('unfinalized', 'BROWSER_AUDIT_INCOMPLETE'), ('attach_failed', 'BROWSER_AUDIT_INCOMPLETE'),
                                ('handler_error', 'BROWSER_AUDIT_INCOMPLETE')):
            with self.subTest(browser=browser):
                f = self.fixture(); self.approved(f)
                results = self.newest(f, browser=browser)
                self.assert_unknown(results, reason)
                # The proxy saw nothing wrong: only the browser's report (or its absence) made this UNKNOWN.
                self.assertTrue(all(r['network_audit']['blocked'] == 0 and r['network_audit']['failed'] == 0 for r in results))
                self.assertTrue(all(r['metrics'] is not None for r in results))  # The pixel preview is untouched.

    def test_clean_browser_audit_never_promotes_and_never_hides_a_connect_problem(self):
        f = self.fixture(); self.approved(f)
        self.assertEqual(self.verdicts(self.newest(f, browser='ok')), {SAME})
        for r in self.newest(f, browser='ok', net='blocked'):
            self.assertEqual(r['operational']['verdict'], UNKNOWN)
            self.assertIn('RESOURCE_BLOCKED', r['operational']['reasons'])
            self.assertEqual(r['browser_audit']['failed'], 0)

    def test_baseline_captured_with_a_browser_failure_is_unknown_with_a_baseline_reason(self):
        f = self.fixture()
        for job in f.run(browser='tls')['jobs']: f.approve(job['candidate'])
        self.assert_unknown(self.newest(f), 'BASELINE_TLS_VALIDATION_FAILED')

    def test_stored_results_without_a_browser_audit_are_downgraded_for_display_and_never_invented(self):
        from src.comparison.operational import present
        f = self.fixture(); self.approved(f)
        result = self.newest(f)[0]
        self.assertEqual(present(result, 'UNCHANGED')['verdict'], SAME)
        old = {k: v for k, v in result.items() if k != 'browser_audit'}  # Saved by S2-A: verdict, but no browser audit.
        shown = present(old, 'UNCHANGED')
        self.assertEqual(shown['verdict'], UNKNOWN)
        self.assertIn('BROWSER_AUDIT_UNAVAILABLE', shown['reasons'])
        self.assertEqual(shown['browser']['state'], 'UNAVAILABLE')
        forged = {**result, 'browser_audit': {**result['browser_audit'], 'complete': True, 'failed': 0}}
        forged['browser_audit']['failures'] = [{'resource_type': 'stylesheet', 'scheme': 'https', 'host': 'x.invalid', 'port': 443,
                                                'error': 'ERR_CERT_DATE_INVALID', 'class': 'RESOURCE_LOAD_FAILED',
                                                'navigation': False, 'count': 1}]
        self.assertIn('TLS_VALIDATION_FAILED', present(forged, 'UNCHANGED')['reasons'])  # class recomputed, claim ignored

    def test_audit_can_only_run_for_the_running_job(self):
        f = self.fixture(); f.run()
        job = f.comparison.state()['jobs'][0]['job_id']
        with self.assertRaises(ValueError): f.runtime.record_browser_audit(job, {})

    # --- S1-B: trusted-proxy connection audit -------------------------------------------

    def test_clean_audit_is_recorded_and_allows_the_comparison(self):
        f = self.fixture(); self.approved(f)
        for r in self.newest(f):
            self.assertEqual(r['operational']['verdict'], SAME)
            a = r['network_audit']
            self.assertEqual((a['complete'], a['allowed'], a['blocked'], a['failed']), (True, 1, 0, 0))
            self.assertEqual(a['source'], 'TRUSTED_CONNECT_PROXY')
            self.assertEqual(a['resource_types'], 'NOT_OBSERVABLE')

    def test_blocked_or_failed_resource_is_unknown_but_preview_remains(self):
        for net, reason in (('blocked', 'RESOURCE_BLOCKED'), ('failed', 'RESOURCE_FAILED')):
            with self.subTest(net=net):
                f = self.fixture(); self.approved(f)
                results = self.newest(f, changed=True, net=net)
                self.assert_unknown(results, reason)
                # The pixel preview is kept; only the operational verdict refuses to speak.
                self.assertTrue(all(r['preview_only'] and r['preview_changed'] and r['metrics'] for r in results))
                self.assertEqual({r['quality'] for r in results}, {'UNKNOWN'})
                self.assertTrue(all(r['network_audit']['complete'] for r in results))

    def test_missing_incomplete_or_empty_audit_is_never_zero_blocked(self):
        for kwargs, reason in (({'ledger': False}, 'NETWORK_AUDIT_UNAVAILABLE'),
                               ({'net': 'pending'}, 'NETWORK_AUDIT_INCOMPLETE'),
                               ({'net': 'overflow'}, 'NETWORK_AUDIT_INCOMPLETE'),
                               ({'net': 'silent'}, 'NETWORK_AUDIT_EMPTY')):
            with self.subTest(kwargs=kwargs):
                f = self.fixture(); self.approved(f)
                results = self.newest(f, **kwargs)
                self.assert_unknown(results, reason)
                self.assertTrue(all(r['metrics'] is not None for r in results))

    def test_baseline_captured_with_blocks_or_without_audit_is_unknown(self):
        for kwargs, reason in (({'net': 'blocked'}, 'BASELINE_RESOURCE_BLOCKED'),
                               ({'ledger': False}, 'BASELINE_NETWORK_AUDIT_UNAVAILABLE')):
            with self.subTest(kwargs=kwargs):
                f = self.fixture()
                for job in f.run(**kwargs)['jobs']: f.approve(job['candidate'])
                self.assert_unknown(self.newest(f), reason)

    def test_audit_window_belongs_to_one_job_only(self):
        f = self.fixture(); self.approved(f)
        first = self.newest(f, net='blocked')
        second = self.newest(f)  # A block in the previous run must not leak into this one.
        self.assert_unknown(first, 'RESOURCE_BLOCKED')
        self.assertEqual(self.verdicts(second), {SAME})
        self.assertTrue(all(r['network_audit']['blocked'] == 0 for r in second))

    def test_strict_quality_is_not_changed_by_the_audit(self):
        f = Fixture(); self.addCleanup(f.close)
        for job in f.run()['jobs']: f.approve(job['candidate'])
        for r in f.run(net='blocked')['results'][:2]:
            self.assertEqual(r['operational']['verdict'], UNKNOWN)
            self.assertEqual(r['quality'], 'PASS')  # Strict logic is untouched; see report.
        g = self.fixture()  # Unattested never reaches PASS/CHANGED whatever the audit says.
        self.approved(g)
        for net in ('ok', 'blocked'):
            self.assertEqual({r['quality'] for r in self.newest(g, net=net)}, {'UNKNOWN'})

    def test_audit_holds_no_url_query_credential_or_cookie_material(self):
        import json as _json
        from src.isolation.ledger import ConnectLedger
        ledger = ConnectLedger(); mark = ledger.mark()
        for host in ('user:secret@a.example', 'a.example?token=1', 'A.example/path', 'ok.example', None):
            ledger.begin(); ledger.record(host, 443, 'BLOCK', 'NOT_ALLOWLISTED')
        ledger.begin(); ledger.record('ok.example', 443, 'BLOCK', 'secret=1 & cookie')
        text = _json.dumps(ledger.window(mark))
        for leak in ('secret', 'token', 'cookie', '@', '?', '/path', 'A.example'):
            self.assertNotIn(leak, text)
        self.assertIn('ok.example', text)
        f = self.fixture(); self.approved(f)
        text = _json.dumps(self.newest(f, net='blocked'))
        self.assertNotIn('Cookie', text)
        self.assertNotIn('Authorization', text)


if __name__ == '__main__': unittest.main()

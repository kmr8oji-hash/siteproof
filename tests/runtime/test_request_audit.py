"""S2-A-FIX: browser-side request audit. Offline: a fake Playwright context, no browser, no network."""
import json
import unittest

from src.runtime.request_audit import (MAX_ENTRIES, RequestAuditCollector, audit_problems, check_browser_audit,
                                       classify, error_token)
from tests.comparison.support import _Context, _Request, _Response, synthetic_browser_audit


def collect(*steps, final=True):
    collector, context = RequestAuditCollector(), _Context()
    collector.attach(context)
    for name, item in steps:
        context.handlers[name](item)
    return collector.summary(final=final)


def load(url, kind='stylesheet', failure=None, navigation=False):
    return _Request(url, kind, failure, navigation)


class RequestAuditTests(unittest.TestCase):
    def test_clean_page_is_complete_and_proves_nothing_more(self):
        page = load('https://p.invalid/', 'document', navigation=True)
        report = collect(('request', page), ('requestfinished', page))
        self.assertTrue(report['complete'])
        self.assertEqual((report['failed'], report['http_errors'], report['pending']), (0, 0, 0))
        self.assertEqual(audit_problems(report), [])

    def test_tls_errors_are_their_own_class_other_failures_and_http_errors_are_load_failures(self):
        for error in ('net::ERR_CERT_AUTHORITY_INVALID', 'net::ERR_CERT_COMMON_NAME_INVALID', 'net::ERR_CERT_DATE_INVALID',
                      'net::ERR_SSL_PROTOCOL_ERROR', 'net::ERR_CERT_REVOKED'):
            self.assertEqual(classify(error_token(error)), 'TLS_VALIDATION_FAILED', error)
        for error in ('net::ERR_CONNECTION_RESET', 'net::ERR_TUNNEL_CONNECTION_FAILED', 'net::ERR_ABORTED', 'net::ERR_NAME_NOT_RESOLVED',
                      'net::ERR_BLOCKED_BY_CLIENT', None, 'garbage'):
            self.assertEqual(classify(error_token(error)), 'RESOURCE_LOAD_FAILED', error)
        bad = load('https://t.invalid/a.css', failure='net::ERR_CERT_COMMON_NAME_INVALID')
        self.assertEqual(audit_problems(collect(('request', bad), ('requestfailed', bad))), ['TLS_VALIDATION_FAILED'])
        reset = load('https://t.invalid/a.js', 'script', 'net::ERR_CONNECTION_RESET')
        self.assertEqual(audit_problems(collect(('request', reset), ('requestfailed', reset))), ['RESOURCE_LOAD_FAILED'])
        missing = load('https://t.invalid/a.png', 'image')
        report = collect(('request', missing), ('response', _Response(missing, 404)), ('requestfinished', missing))
        self.assertEqual(audit_problems(report), ['RESOURCE_LOAD_FAILED'])
        ok = load('https://t.invalid/b.png', 'image')
        self.assertEqual(collect(('request', ok), ('response', _Response(ok, 200)), ('requestfinished', ok))['http_errors'], 0)

    def test_only_scheme_host_port_type_and_error_are_kept(self):
        secret = load('https://user:pw@s.invalid:8443/p/a.css?token=SECRET&k=v#frag', 'stylesheet', 'net::ERR_CERT_DATE_INVALID')
        report = collect(('request', secret), ('requestfailed', secret))
        text = json.dumps(report)
        for leak in ('user', 'pw', 'SECRET', 'token', '/p/', 'a.css', 'frag', 'k=v'):
            self.assertNotIn(leak, text)
        failure = report['failures'][0]
        self.assertEqual((failure['host'], failure['port'], failure['scheme'], failure['resource_type']), ('s.invalid', 8443, 'https', 'stylesheet'))

    def test_unfinished_unfinalized_unattached_and_failing_handlers_are_incomplete(self):
        pending = load('https://p.invalid/slow', 'fetch')
        self.assertEqual(audit_problems(collect(('request', pending))), ['BROWSER_AUDIT_INCOMPLETE'])
        done = load('https://p.invalid/', 'document', navigation=True)
        self.assertEqual(audit_problems(collect(('request', done), ('requestfinished', done), final=False)), ['BROWSER_AUDIT_INCOMPLETE'])
        self.assertEqual(audit_problems(RequestAuditCollector().summary(final=True)), ['BROWSER_AUDIT_INCOMPLETE'])  # never attached
        broken = RequestAuditCollector()
        self.assertFalse(broken.attach(object()))  # No .on(): monitoring never started.
        self.assertEqual(broken.monitor, 'FAILED')
        self.assertEqual(audit_problems(broken.summary(final=True)), ['BROWSER_AUDIT_INCOMPLETE'])
        self.assertEqual(audit_problems(synthetic_browser_audit('handler_error')), ['BROWSER_AUDIT_INCOMPLETE'])

    def test_missing_unavailable_and_malformed_reports_are_reasons_not_passes(self):
        self.assertEqual(audit_problems(None), ['BROWSER_AUDIT_UNAVAILABLE'])
        self.assertEqual(audit_problems({'schema': 'siteproof.browser-audit.v1', 'source': 'UNAVAILABLE'}), ['BROWSER_AUDIT_UNAVAILABLE'])
        self.assertEqual(audit_problems({'schema': 'siteproof.browser-audit.v1', 'source': 'INVALID'}), ['BROWSER_AUDIT_INVALID'])
        self.assertEqual(audit_problems(None, 'BASELINE_'), ['BASELINE_BROWSER_AUDIT_UNAVAILABLE'])
        good = synthetic_browser_audit('ok')
        for broken in ({**good, 'requests': -1}, {**good, 'requests': True}, {**good, 'schema': 'x'}, {**good, 'source': 'TRUSTED_CONNECT_PROXY'},
                       {**good, 'failures': 'none'}, {**good, 'monitor': 'MAYBE'}, {**good, 'finalized': 'yes'}, 'clean', 5, []):
            with self.subTest(broken=str(broken)[:40]):
                self.assertIsNone(check_browser_audit(broken))
                self.assertEqual(audit_problems(broken), ['BROWSER_AUDIT_INVALID'])

    def test_trusted_side_recomputes_class_counts_and_completeness(self):
        report = synthetic_browser_audit('tls')
        forged = json.loads(json.dumps(report))
        forged.update(complete=True, failed=0, http_errors=0)
        forged['failures'][0]['class'] = 'RESOURCE_LOAD_FAILED'
        forged['failures'][0]['evil'] = 'extra field'
        clean = check_browser_audit(forged)
        self.assertEqual(clean['failed'], 1)
        self.assertEqual(clean['failures'][0]['class'], 'TLS_VALIDATION_FAILED')
        self.assertNotIn('evil', clean['failures'][0])
        self.assertEqual(audit_problems(forged), ['TLS_VALIDATION_FAILED'])
        incomplete = json.loads(json.dumps(synthetic_browser_audit('pending')))
        incomplete['complete'] = True
        self.assertFalse(check_browser_audit(incomplete)['complete'])
        for bad_host in ('A.INVALID', 'x/y', 'h:1', ''):
            tampered = json.loads(json.dumps(report))
            tampered['failures'][0]['host'] = bad_host
            self.assertIsNone(check_browser_audit(tampered), bad_host)

    def test_entries_are_bounded_and_overflow_makes_the_audit_incomplete(self):
        steps = []
        for n in range(MAX_ENTRIES + 3):
            r = load(f'https://h{n}.invalid/a.css', failure='net::ERR_CONNECTION_RESET')
            steps += [('request', r), ('requestfailed', r)]
        page = load('https://p.invalid/', 'document', navigation=True)
        report = collect(('request', page), ('requestfinished', page), *steps)
        self.assertEqual(len(report['failures']), MAX_ENTRIES)
        self.assertEqual(report['dropped'], 3)
        self.assertIn('BROWSER_AUDIT_INCOMPLETE', audit_problems(report))

    def test_page_script_errors_are_counted_by_class_only_and_old_audits_read_as_not_recorded(self):
        class _Err:
            def __init__(self, name, message):
                self.name, self.message = name, message
        class _WebError:
            def __init__(self, name):
                self.error = _Err(name, 'secret token=SECRET at https://p.invalid/app.js')
        page = load('https://p.invalid/', 'document', navigation=True)
        report = collect(('request', page), ('requestfinished', page), ('weberror', _WebError('TypeError')),
                         ('weberror', _WebError('TypeError')), ('weberror', _WebError('<script>')))
        self.assertEqual(report['script_errors'], 3)
        self.assertEqual(report['script_error_entries'], [{'name': 'Error', 'count': 1}, {'name': 'TypeError', 'count': 2}])
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertTrue(report['complete'])  # a script error is a finding, not a broken monitor
        self.assertEqual(audit_problems(report), ['PAGE_SCRIPT_ERROR'])
        clean = collect(('request', page), ('requestfinished', page))
        self.assertEqual((clean['script_errors'], audit_problems(clean)), (0, []))
        legacy = {k: v for k, v in clean.items() if not k.startswith('script_error')}  # recorded before the field existed
        self.assertNotIn('script_errors', check_browser_audit(legacy))
        self.assertEqual(audit_problems(legacy), [])
        forged = json.loads(json.dumps(report))
        forged['script_errors'] = 0  # the trusted side recomputes the count
        self.assertEqual(check_browser_audit(forged)['script_errors'], 3)
        for bad in ({**report, 'script_error_entries': 'none'}, {**report, 'script_error_entries': [{'name': 'a b', 'count': 1}]}):
            self.assertEqual(audit_problems(bad), ['BROWSER_AUDIT_INVALID'])


if __name__ == '__main__':
    unittest.main()

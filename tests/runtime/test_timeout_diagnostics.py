"""HTTP_TIMEOUT of a real comparison capture: what the code can and cannot say about it, offline.

Facts these tests pin down (no real site, no Docker, no network beyond a loopback socket that is never opened for real):
  * the worker names a timeout after the STAGE it was in, so a timed-out local-proxy liveness probe (1 s) that happens while the
    HTTP stage is starting is reported as HTTP_TIMEOUT, exactly like a navigation that really ran out of time;
  * the new evidence-only diagnostics tell the two apart (probe record vs. the Playwright operation and its limit);
  * a real failure is still a failure (never COMPLETE), the cause text only repeats what the harness recorded, and nothing here
    changes a limit, a deadline, a run count or a destination rule.

What this does NOT show: which of the two really happened in the permit #3 comparison run. That is UNKNOWN until a run records it.
"""
import json
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock

try:
    import playwright.sync_api  # noqa: F401
except ImportError:  # Playwright lives only in the sandbox image; the probe code under test never calls it.
    _pw = types.ModuleType('playwright')
    _api = types.ModuleType('playwright.sync_api')
    _api.sync_playwright = None
    _pw.sync_api = _api
    sys.modules.update({'playwright': _pw, 'playwright.sync_api': _api})

from src.core.offline import profile
from src.noxiworks import real_capture
from src.runtime.browser import PlaywrightDriver, ResourceLimits
from src.worker.capture import capture, CaptureRequest
from tests.runtime.s2b_browser import RealProxyBinding

ROOT = Path(__file__).resolve().parents[2]
HOST = 'site.example.invalid'
LIMITS = ResourceLimits(90, 20, 1024 * 1024, 128 * 1024 * 1024, 16, 64, 10, 1024 * 1024)
PNG = b'\x89PNG\r\n\x1a\n' + b'0' * 32


class Driver:
    def __init__(self, fail=None):
        self.fail, self.calls = fail, []

    def start(self, p):
        self.calls.append('start')

    def http(self, u, t):
        self.calls.append('http')
        if self.fail == 'http-timeout':
            raise TimeoutError()
        if self.fail == 'http-crash':
            raise RuntimeError('sensitive text must not escape')
        return 200

    def load(self, t):
        self.calls.append('load')

    def capture(self, p, t):
        self.calls.append('capture')
        return PNG

    def close(self):
        return True


class Lease:
    """What the worker's `check()` calls; here the REAL probe of RealProxyBinding with the socket under test control."""
    def __init__(self):
        self.binding = RealProxyBinding(3128, HOST)

    def check(self, url=None):
        return self.binding.check(url)


def run(driver, lease):
    return capture(CaptureRequest('p', profile('Desktop'), f'https://{HOST}/'), driver, lease, LIMITS)


class WorkerNamesTheStage(unittest.TestCase):
    def probe_socket(self, connect):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.connect.side_effect = connect
        return mock.patch('tests.runtime.s2b_browser.socket.socket', return_value=sock)

    def test_the_probe_record_says_which_call_failed_and_how_long_it_took(self):
        lease, calls = Lease(), []

        def connect(address):
            calls.append(address)
            if len(calls) > 1:
                raise socket.timeout('timed out')

        driver = Driver()
        with self.probe_socket(connect):
            out = run(driver, lease)
        self.assertEqual(out.reason, 'HTTP_TIMEOUT')        # indistinguishable from a navigation timeout by the reason alone
        self.assertEqual(driver.calls, ['start'])           # ...but no navigation was ever attempted
        errors = [p['error'] for p in lease.binding.probes]
        self.assertEqual(errors, [None, 'TimeoutError'])
        self.assertTrue(all(isinstance(p['ms'], int) and p['ms'] >= 0 for p in lease.binding.probes))
        self.assertEqual(calls, [('127.0.0.1', 3128)] * 2)        # only the owned loopback proxy is ever probed

    def test_the_probe_still_fails_closed_and_never_swallows_the_error(self):
        lease = Lease()
        with self.probe_socket(ConnectionRefusedError()):
            with self.assertRaises(ConnectionRefusedError):
                lease.binding.check(f'https://{HOST}/')
        self.assertEqual(lease.binding.probes[-1]['error'], 'ConnectionRefusedError')

    def test_the_probe_list_is_bounded(self):
        lease = Lease()
        with self.probe_socket(lambda address: None):
            for _ in range(200):
                lease.binding.check(f'https://{HOST}/')
        self.assertEqual(len(lease.binding.probes), 64)

    def test_destination_rules_are_unchanged(self):
        lease = Lease()
        for url in ('https://other.example.invalid/', f'http://{HOST}/', f'https://{HOST}:8443/', f'https://user@{HOST}/'):
            with self.subTest(url=url), self.probe_socket(lambda address: None):
                with self.assertRaises(Exception):
                    lease.binding.check(url)
        self.assertEqual(lease.binding.probes, [])                 # refused before any probe

    def test_a_real_navigation_timeout_is_also_http_timeout_but_leaves_a_different_record(self):
        lease, driver = Lease(), Driver(fail='http-timeout')
        with self.probe_socket(lambda address: None):
            out = run(driver, lease)
        self.assertEqual(out.reason, 'HTTP_TIMEOUT')
        self.assertIn('http', driver.calls)                        # navigation was attempted
        self.assertTrue(all(p['error'] is None for p in lease.binding.probes))

    def test_normal_completion_is_unchanged(self):
        lease, driver = Lease(), Driver()
        with self.probe_socket(lambda address: None):
            out = run(driver, lease)
        self.assertEqual(out.reason, 'CAPTURE_COMPLETE')
        self.assertEqual(driver.calls, ['start', 'http', 'load', 'capture'])
        self.assertTrue(out.cleanup_confirmed)
        self.assertTrue(all(p['error'] is None for p in lease.binding.probes))

    def test_a_real_failure_is_never_reported_as_success(self):
        lease, driver = Lease(), Driver(fail='http-crash')
        with self.probe_socket(lambda address: None):
            out = run(driver, lease)
        self.assertEqual(out.reason, 'HTTP_FAILED')
        self.assertNotEqual(out.reason, 'CAPTURE_COMPLETE')
        self.assertNotIn(b'sensitive', out.wire)


class PlaywrightTimeoutIsRecorded(unittest.TestCase):
    def setUp(self):
        PlaywrightDriver.last_timeout = None
        self.addCleanup(setattr, PlaywrightDriver, 'last_timeout', None)

    def test_a_playwright_timeout_records_operation_limit_and_elapsed_and_still_raises_the_same_error(self):
        playwright_timeout = type('TimeoutError', (Exception,), {'__module__': 'playwright.sync_api'})

        def goto(url, **kwargs):
            raise playwright_timeout('Timeout 20000ms exceeded')

        with self.assertRaises(TimeoutError) as caught:
            PlaywrightDriver._call(goto, 'https://x/', timeout=20000)
        self.assertEqual(str(caught.exception), '')                # no raw text escapes
        record = PlaywrightDriver.last_timeout
        self.assertEqual((record['operation'], record['limit_ms']), ('goto', 20000))
        self.assertIsInstance(record['elapsed_ms'], int)

    def test_other_errors_leave_no_timeout_record_and_propagate_unchanged(self):
        def boom(**kwargs):
            raise ValueError('x')

        with self.assertRaises(ValueError):
            PlaywrightDriver._call(boom, timeout=1)
        self.assertIsNone(PlaywrightDriver.last_timeout)


class CauseText(unittest.TestCase):
    def cause(self, report=None, write=True):
        with tempfile.TemporaryDirectory() as tmp:
            if write:
                (Path(tmp) / 'validation-result.json').write_text(report if isinstance(report, str) else json.dumps(report), encoding='utf-8')
            return real_capture.failure_cause(tmp)

    def test_a_timeout_names_the_recorded_reason_and_says_the_permit_run_is_used(self):
        text = self.cause({'captures': {'Desktop': {'execution': 'TIMED_OUT', 'reason': 'HTTP_TIMEOUT'}}})
        self.assertIn('Desktopの撮影が完了しませんでした', text)
        self.assertIn('HTTP_TIMEOUT', text)
        self.assertIn('許可の回数は1回使用済み', text)
        self.assertNotIn('自動', text)                              # nothing is promised about a rerun

    def test_an_unknown_reason_is_shown_as_recorded_not_invented(self):
        text = self.cause({'captures': {'Desktop': {'execution': 'FAILED', 'reason': 'SOMETHING_NEW'}}})
        self.assertIn('SOMETHING_NEW', text)
        self.assertIn('撮影が完了しませんでした', text)

    def test_gate_error_and_failed_checks_are_reported_as_recorded(self):
        self.assertIn('安全確認で停止しました（DOCKER）', self.cause({'gate_failed': 'DOCKER'}))
        self.assertIn('RuntimeError', self.cause({'error_type': 'RuntimeError'}))
        self.assertIn('確認項目が成立しませんでした（a、b）', self.cause({'checks': {'a': False, 'b': 'x', 'c': True}}))

    def test_no_record_means_no_cause_is_claimed(self):
        self.assertIsNone(self.cause(write=False))
        self.assertIsNone(self.cause('not json'))
        self.assertIsNone(self.cause([]))
        self.assertIsNone(self.cause({'captures': {'Desktop': {'execution': 'COMPLETED'}}, 'checks': {'a': True}}))


class DiagnosticsWiring(unittest.TestCase):
    def source(self, name):
        return (ROOT / name).read_text('utf-8')

    def test_diagnostics_are_emitted_and_kept_but_never_a_decision_input(self):
        s3 = self.source('tests/runtime/s3_browser.py')
        for key in ("'diagnostics'", "'lease_probes'", "'last_playwright_timeout'", "'elapsed_ms'"):
            self.assertIn(key, s3)
        self.assertIn("'diagnostics': meta.get('diagnostics')", self.source('tests/runtime/validate_s3t.py'))

    def test_no_limit_or_deadline_was_changed(self):
        self.assertIn('RESOURCES=ResourceLimits(90,20,64*1024*1024,768*1024*1024,256,256,60,256*1024*1024)',
                      self.source('tests/runtime/linux_worker.py'))
        self.assertIn('s.settimeout(1)', self.source('tests/runtime/s2b_browser.py'))
        self.assertIn("self._call(self.page.goto,url,wait_until='commit',timeout=seconds * 1000)", self.source('src/runtime/browser.py'))


if __name__ == '__main__':
    unittest.main()

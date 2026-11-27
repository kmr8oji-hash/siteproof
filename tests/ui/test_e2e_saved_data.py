"""Offline checks on a COPY of the saved HMS real-site E2E data (2026-11-21, .local/real-e2e-hms-data-01): the automatic Baseline from
the stable real capture, the Baseline staying fixed, the real comparison run, and how the result is shown (image comparison apart from
inspection quality) on HOME / REVIEW / ACTIVITY. The saved evidence itself is never written. Skipped where that data is not present.
Also: the first-time setup buttons delegate to the existing tools (no key, no answer, no signing in the app)."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from src.comparison.operational import image_comparison, inspection_quality, present
from src.noxiworks.app import App, utc_now

ROOT = Path(__file__).resolve().parents[2]
SAVED = ROOT / '.local' / 'real-e2e-hms-data-01'
SITE = 'site-5c09908c'
RUN_BASELINE, RUN_COMPARE = '20261121T010511Z-02-real', '20261121T010823Z-03-real'
saved_data = unittest.skipUnless((SAVED / 'sites' / SITE / 'real' / 'runs' / RUN_COMPARE).is_dir(), 'saved E2E data not present')


def tree(folder):
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(folder).rglob('*')) if p.is_file()}


class ImageApartFromQuality(unittest.TestCase):
    def test_the_two_are_separate_facts(self):
        base = {'baseline': {'candidate_id': 'c', 'version': 1}, 'policy': {'maximum_changed_pixels': 0}}
        self.assertEqual(image_comparison({**base, 'metrics': {'changed_pixels': 0}})['label'], '画像比較：変更なし（0px）')
        self.assertEqual(image_comparison({**base, 'metrics': {'changed_pixels': 1234}})['label'], '画像比較：変更あり（1,234px）')
        for missing in ({}, {**base, 'metrics': None}, {**base, 'baseline': None, 'metrics': {'changed_pixels': 0}}, {**base, 'metrics': {'changed_pixels': '0'}}):
            self.assertEqual(image_comparison(missing)['state'], 'NOT_COMPARED')  # never a guessed "no change"
        q = inspection_quality('UNKNOWN', ['RESOURCE_BLOCKED'])
        self.assertEqual((q['state'], q['label']), ('UNKNOWN', '検査品質：判定不能（撮影に必要な通信が遮断されました）'))
        self.assertEqual(inspection_quality('NO_VISUAL_CHANGE_DETECTED', [])['label'], '検査品質：問題なし')
        self.assertIn('image', present({}, None))


@saved_data
class SavedRealE2E(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-e2e-copy-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.before = tree(SAVED)
        self.addCleanup(lambda: self.assertEqual(tree(SAVED), self.before, 'the saved E2E data must never change'))
        self.data = Path(tmp.name) / 'data'
        shutil.copytree(SAVED, self.data, ignore=shutil.ignore_patterns('ui', 'monitor.lock'))
        self.site = self.data / 'sites' / SITE
        (self.site / 'ui').mkdir()  # the pages are rebuilt from the saved runs

    def app(self):
        app = App(self.data)
        app.setup()  # rebuilds HOME / REVIEW / ACTIVITY from the saved real runs (no capture, no network, no Docker)
        app.docker_found = True
        return app

    def test_the_saved_comparison_is_shown_consistently_on_every_page(self):
        app = self.app()
        registry = tree(self.site / 'real' / 'registry')
        summary = app.site.summary(self.site / 'real' / 'runs' / RUN_COMPARE / RUN_COMPARE)
        for kind in ('Desktop', 'Mobile'):
            p = summary['profiles'][kind]
            self.assertEqual((p['verdict'], p['changed_pixels'], p['stability'], p['compared']), ('UNKNOWN', 0, 'STABLE', True))
            self.assertEqual(p['image_label'], '画像比較：変更なし（0px）')
            self.assertTrue(p['quality_label'].startswith('検査品質：判定不能（撮影に必要な通信が遮断されました'))
        ui = sorted((app.site.root / 'ui').iterdir(), key=lambda d: int(d.name) if d.name.isdigit() else -1)[-1]
        for page in ('index.html', 'review.html', 'activity.html'):
            text = (ui / page).read_text('utf-8')
            with self.subTest(page):
                self.assertIn('画像比較：変更なし（0px）', text)
                self.assertIn('検査品質：判定不能', text)
                self.assertNotIn('画像比較：変更あり', text)
                self.assertNotIn('検査品質：問題なし', text)  # the verdict stays UNKNOWN everywhere: no page contradicts another
        view = json.loads((ui / 'view.json').read_text('utf-8'))
        compared = [h for h in view['monitoring']['history'] if h['baseline']]
        self.assertEqual({(h['class'], h['image_label']) for h in compared}, {('UNKNOWN', '画像比較：変更なし（0px）')})
        self.assertEqual(tree(self.site / 'real' / 'registry'), registry)  # showing results never touches the Baseline

    def test_the_automatic_baseline_comes_from_the_stable_real_capture_and_stays_fixed(self):
        from src.noxiworks.real_capture import RealCaptureRefused
        from src.noxiworks.site_monitor import AUTO_ACTOR
        real = self.site / 'real'
        original = json.loads((real / 'registry-origin.json').read_text('utf-8'))
        shutil.rmtree(real / 'registry')
        (real / 'registry-origin.json').unlink()
        for name in ('permit.json', 'permit.json.sig'):  # the copy only: the signed (now expired) E2E permit, for its baseline policy
            (real / (name + '.disabled')).rename(real / name)
        from src.noxiworks.site_monitor import Monitor
        from src.noxiworks.site_workflow import Site
        site = Site(self.site)  # no page rebuild here: a compared run is shown only together with its Baseline registry
        capture = Monitor(site, docker_found=True).real()
        summary = site.summary(real / 'runs' / RUN_BASELINE / RUN_BASELINE)
        self.assertIsNone(Site.approvable(summary))
        capture.create_baseline(summary, utc_now(), AUTO_ACTOR)
        record = json.loads((real / 'registry' / 'APPROVAL-RECORD.json').read_text('utf-8'))
        self.assertEqual(sorted(b['candidate_id'] for b in record['baselines']),
                         sorted(p['candidate'] for p in summary['profiles'].values()))  # exactly run 02's stable captures
        self.assertEqual(json.loads((real / 'registry-origin.json').read_text('utf-8'))['permit_id'], original['permit_id'])
        fixed = tree(real / 'registry')
        with self.assertRaises(RealCaptureRefused):
            capture.create_baseline(summary, utc_now(), AUTO_ACTOR)  # a second Baseline is never made over the first
        self.assertEqual(tree(real / 'registry'), fixed)

    def test_the_saved_real_record_is_not_rewritten_as_a_clean_success(self):
        log = [json.loads(l) for l in (SAVED / 'sites' / SITE / 'monitor-log.jsonl').read_text('utf-8').splitlines() if l.strip()]
        self.assertEqual([e['outcome'] for e in log][-4:], ['FAILED', 'FAILED', 'FAILED', 'UNKNOWN'])
        self.assertIn('Baselineを作成できませんでした', log[-2]['error'])  # run 02: made offline afterwards, recorded as such


class SetupButtons(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-gui-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def app(self, url):
        app = App(self.root / url.split('/')[2])
        app.setup()
        app.launcher = mock.MagicMock()
        app.site_action('register', {'name': 'S', 'url': url, 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})
        return app

    def test_setup_opens_the_users_own_window_with_the_existing_tool(self):
        app = self.app('https://my-worker.my-sub.workers.dev/')
        out = app.site_action('setup', {'step': 'setup'})
        args, kwargs = app.launcher.call_args
        cmd = args[0]
        self.assertEqual((out['ownership'], kwargs), ('cloudflare', {'console': True}))
        self.assertEqual(cmd[2:4], ['tools/setup_monitoring.py', '--data'])
        self.assertIn('--pause', cmd)
        for never in ('--yes', '--no-passphrase', '--key', '-Y', 'sign'):  # the USER confirms and signs in that window
            self.assertNotIn(never, cmd)

    def test_other_sites_have_no_supported_ownership_method_yet(self):
        app = self.app('https://my-site.com/')
        with self.assertRaises(ValueError):
            app.site_action('setup', {'step': 'setup', 'ownership': 'cloudflare'})  # not a workers.dev host
        with self.assertRaises(ValueError) as nothing:
            app.site_action('setup', {'step': 'setup'})  # no method at all
        self.assertIn('まだありません', str(nothing.exception))
        for method in ('well-known-file', 'dns-txt'):
            for body in ({'ownership': method}, {'ownership': method, 'confirmed': True}):
                with self.subTest(body):
                    with self.assertRaises(ValueError) as refused:
                        app.site_action('setup', {'step': 'setup', **body})
                    self.assertIn('現在対応していません', str(refused.exception))
        app.launcher.assert_not_called()  # no setup window, no status file
        self.assertFalse((app.site.root / 'setup-status.json').exists())

    def test_docker_and_background_buttons(self):
        app = self.app('https://my-site.com/')
        app.site_action('setup', {'step': 'docker'})
        self.assertEqual(app.launcher.call_args[0][0], ['docker', 'desktop', 'start'])
        app.site_action('setup', {'step': 'background'})
        self.assertEqual(app.launcher.call_args[0][0][2:4], ['tools/background_monitor.py', 'install'])
        with self.assertRaises(ValueError):
            app.site_action('setup', {'step': 'sign'})


if __name__ == '__main__':
    unittest.main()


class SetupProgressAndRenewal(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-gui2-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.app = App(Path(tmp.name) / 'data')
        self.app.setup()
        self.app.launcher = mock.MagicMock()
        self.app.site_action('register', {'name': 'S', 'url': 'https://my-worker.my-sub.workers.dev/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})

    def test_the_button_shows_launched_and_a_launch_failure_shows_failed(self):
        self.app.site_action('setup', {'step': 'setup'})
        self.assertEqual(self.app.site_status()['setup']['state'], 'LAUNCHED')
        self.app.launcher.side_effect = OSError('no console')
        with self.assertRaises(ValueError):
            self.app.site_action('setup', {'step': 'setup'})
        self.assertEqual(self.app.site_status()['setup']['state'], 'FAILED')

    def test_the_tool_reports_its_progress_to_the_screen(self):
        from tools import setup_monitoring
        setup_monitoring.write_status(self.app.site.root, 'RUNNING', 'x')
        self.assertEqual(self.app.site_status()['setup']['state'], 'RUNNING')
        setup_monitoring.write_status(self.app.site.root, 'DONE', '準備ができました')
        self.assertEqual(self.app.site_status()['setup'], {'state': 'DONE', 'message': '準備ができました', 'at': self.app.site_status()['setup']['at']})

    def test_renewal_reuses_the_ownership_evidence_only_when_there_is_one(self):
        with self.assertRaises(ValueError):
            self.app.site_action('setup', {'step': 'setup', 'ownership': 'reuse'})
        real = self.app.site.root / 'real'
        real.mkdir(exist_ok=True)
        (real / 'ownership-evidence.json').write_text('{}', encoding='utf-8')
        self.app.site_action('setup', {'step': 'setup', 'ownership': 'reuse'})
        cmd = self.app.launcher.call_args[0][0]
        self.assertNotIn('--ownership', cmd)  # the tool re-checks the evidence that is there
        self.assertTrue(self.app.site_status()['ownership_evidence'])

    def test_the_permit_warning(self):
        from datetime import timedelta
        from src.aws_b.model import format_utc
        now = utc_now()

        class Real:
            def __init__(self, until, max_runs, used):
                self.p, self.u = {'permit_id': 'p', 'valid_until': format_utc(now + until), 'max_runs': max_runs}, used

            def permit(self):
                return self.p, None

            def used(self, permit):
                return self.u
        info = lambda *a: self.app.permit_info(Real(*a), now)
        self.assertEqual((info(timedelta(days=30), 100, 0)['warning'], info(timedelta(days=30), 100, 0)['expired']), (False, False))
        self.assertTrue(info(timedelta(days=5), 100, 0)['warning'])      # 7 days or less
        self.assertTrue(info(timedelta(days=30), 100, 96)['warning'])    # 5 runs or less
        self.assertTrue(info(timedelta(days=30), 100, 100)['expired'])
        self.assertTrue(info(timedelta(seconds=-1), 100, 0)['expired'])
        self.assertIsNone(self.app.permit_info(type('N', (), {'permit': lambda s: (None, 'x')})(), now))


class DisplayStatesAndBackground(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-gui3-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.app = App(Path(tmp.name) / 'data')
        self.app.setup()
        self.app.launcher = mock.MagicMock()
        self.app.background_query = mock.MagicMock(return_value=False)  # no schtasks in tests
        self.app.site_action('register', {'name': 'S', 'url': 'https://my-worker.my-sub.workers.dev/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})

    def test_the_headline_tells_setup_needed_running_and_expired_apart(self):
        self.assertEqual(self.app.site_status()['display'], 'SETUP_NEEDED')
        self.app.site_action('setup', {'step': 'setup'})
        self.assertEqual(self.app.site_status()['display'], 'SETUP_RUNNING')
        from tools import setup_monitoring
        setup_monitoring.write_status(self.app.site.root, 'FAILED', 'x')
        self.assertEqual(self.app.site_status()['display'], 'SETUP_NEEDED')  # a failed setup leaves it to be done
        with mock.patch.object(self.app.first, 'permit_info', return_value={'expired': True, 'warning': True, 'permit_id': 'p', 'valid_until': 'x',
                                                                      'remaining_runs': 0, 'days_left': -1}):
            self.assertEqual(self.app.site_status()['display'], 'EXPIRED')
        self.app.site_action('monitor', {'enabled': False})
        self.assertEqual(self.app.site_status()['display'], 'PAUSED')

    def test_background_state_and_removal(self):
        self.assertIs(self.app.site_status()['background'], False)
        self.app.site_status()
        self.assertEqual([c.args[2] for c in self.app.background_query.call_args_list], ['image', 'http'])  # each channel asked once a minute at most
        self.app.site_action('setup', {'step': 'background-remove'})
        self.assertEqual(self.app.launcher.call_args[0][0][2:4], ['tools/background_monitor.py', 'remove'])
        self.app.background_query.return_value = True
        self.assertIs(self.app.site_status()['background'], True)  # asked again after the button

    def test_a_second_launch_opens_the_running_app(self):
        from src.noxiworks import app as app_module
        with mock.patch.object(app_module, 'already_running', return_value=True), mock.patch.object(app_module.webbrowser, 'open') as browser, \
                mock.patch.object(app_module, 'serve', side_effect=AssertionError('no second server')):
            self.assertEqual(app_module.main(['--data', str(self.app.data), '--port', '8765']), 0)
        browser.assert_called_once_with('http://127.0.0.1:8765/')

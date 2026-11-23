"""The USER-run setup tools, offline: tools/setup_monitoring.py (register -> key -> trust -> ownership -> signed permit -> readiness),
renewal with the Baseline carried over, tools/cf_ownership.py against a fake Cloudflare API (GET only), and tools/background_monitor.py
`tick` / `install --dry-run`. Keys are SYNTHETIC (temp folder, no passphrase); nothing touches the network, Docker or the OS scheduler."""
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import permit as permits
from src.noxiworks.app import App, utc_now
from tests.ui.test_real_capture import CF_HOST, CF_SUB, CF_URL, CF_WORKER, FakeHarness, needs_ssh
from tools import background_monitor, cf_ownership, setup_monitoring

ACCOUNT = '0123456789abcdef0123456789abcdef'
real_readiness = setup_monitoring.readiness


def setUpModule():
    # Any real network connection from these tests is a bug: fail it before it leaves the process.
    patcher = mock.patch('socket.socket.connect', side_effect=AssertionError('network access in an offline test'))
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


class FakeCloudflare:
    """Answers the READ-ONLY API like Cloudflare would for one account owning CF_WORKER on CF_SUB; records every request."""

    def __init__(self, enabled=True, sub=CF_SUB, scripts=(CF_WORKER,)):
        self.enabled, self.sub, self.scripts, self.requests = enabled, sub, scripts, []

    def __call__(self, req, timeout=None):
        self.requests.append((req.get_method(), req.full_url))
        path = req.full_url.split('/client/v4', 1)[1].split('?')[0]
        other = 'f' * 32
        body = {'/accounts': {'result': [{'id': other}, {'id': ACCOUNT}]},
                f'/accounts/{other}/workers/subdomain': {'result': {'subdomain': 'someone-else'}},
                f'/accounts/{ACCOUNT}/workers/subdomain': {'result': {'subdomain': self.sub}},
                f'/accounts/{ACCOUNT}/workers/scripts': {'result': [{'id': s} for s in self.scripts]},
                f'/accounts/{ACCOUNT}/workers/scripts/{CF_WORKER}/subdomain': {'result': {'enabled': self.enabled, 'previews_enabled': True}},
                f'/accounts/{ACCOUNT}/workers/domains': {'result': []}}[path]
        answer = mock.MagicMock()
        answer.status = 200
        answer.read.return_value = json.dumps(body).encode()
        answer.__enter__.return_value = answer
        return answer


class CloudflareOwnership(unittest.TestCase):
    def test_the_check_finds_the_account_from_the_host_and_only_reads(self):
        api = cf_ownership.ReadOnlyApi('synthetic-token', CF_WORKER, opener=FakeCloudflare())
        evidence, raw = cf_ownership.check(api, CF_HOST)
        self.assertEqual((evidence['worker'], evidence['workers_dev_subdomain'], evidence['host']), (CF_WORKER, CF_SUB, CF_HOST))
        self.assertEqual(evidence['account_id_sha256'], hashlib.sha256(ACCOUNT.encode()).hexdigest())
        self.assertEqual({m for m, _ in api.opener.requests}, {'GET'})
        self.assertTrue(all(u.startswith('https://api.cloudflare.com/client/v4/') for _, u in api.opener.requests))
        self.assertNotIn(ACCOUNT, json.dumps(evidence))  # the full ID stays in the raw answers only
        self.assertNotIn('synthetic-token', json.dumps([evidence, raw, api.log]))

    def test_nothing_is_guessed(self):
        for name, fake, host in [('workers.dev disabled', FakeCloudflare(enabled=False), CF_HOST),
                                 ('no account with that subdomain', FakeCloudflare(sub='other'), CF_HOST),
                                 ('worker not in the account', FakeCloudflare(scripts=('other-worker',)), CF_HOST),
                                 ('custom domain', FakeCloudflare(), 'my-site.com')]:
            with self.subTest(name), self.assertRaises(cf_ownership.OwnershipCheckFailed):
                cf_ownership.check(cf_ownership.ReadOnlyApi('t', CF_WORKER, opener=fake), host)

    def test_only_allowlisted_get_paths(self):
        api = cf_ownership.ReadOnlyApi('t', CF_WORKER, opener=FakeCloudflare())
        with self.assertRaises(cf_ownership.OwnershipCheckFailed):
            api.get(f'/accounts/{ACCOUNT}/workers/scripts/{CF_WORKER}')  # would download the Worker's code


@needs_ssh
class SetupTool(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-setup-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.key = self.root / 'keys' / 'synthetic'

    def run_setup(self, *extra, key=None):
        argv = ['--data', str(self.root / 'data'), '--key', str(key or self.key), '--no-passphrase', '--yes', *extra]
        docker_present = lambda root, now: real_readiness(root, now, docker_found=True)  # this PC's Docker plays no part
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out, mock.patch.object(setup_monitoring, 'readiness', docker_present):
            code = setup_monitoring.main(argv)
        return code, out.getvalue()

    def app(self):
        app = App(self.root / 'data')
        app.setup()
        app.docker_found, app.real_runner = True, self.fake
        return app

    def test_one_command_sets_up_real_monitoring_and_a_renewal_keeps_the_baseline(self):
        self.fake = FakeHarness()
        with mock.patch('tools.cf_ownership.wrangler_token', return_value='synthetic-token'), \
                mock.patch('tools.cf_ownership.find_wrangler', return_value=['wrangler']), \
                mock.patch('urllib.request.urlopen', FakeCloudflare()):
            code, out = self.run_setup('--url', CF_URL, '--name', 'My worker', '--ownership', 'cloudflare', '--days', '30')
        self.assertIn('Cloudflareで所有権を確認しました', out)
        app = self.app()
        real = app.site.root / 'real'
        permit = json.loads((real / 'permit.json').read_text('utf-8'))
        self.assertEqual((permit['max_runs'], permit['ownership']['method']), (30 + 7, 'CLOUDFLARE_ACCOUNT_CONTROL'))
        self.assertTrue(all(c['ok'] for c in app.monitor().real().readiness(utc_now())), out)
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'BASELINE_CREATED')
        source_run = app.site.baseline_state()['source_run']
        # renewal: the same command again (evidence reused), the old permit kept, the Baseline carried over under the USER's signature
        code, out = self.run_setup('--days', '30')
        self.assertEqual(code, 0, out)
        renewed = json.loads((real / 'permit.json').read_text('utf-8'))
        self.assertNotEqual(renewed['permit_id'], permit['permit_id'])
        self.assertEqual(renewed['baseline_carryover']['permit_id'], permit['permit_id'])
        self.assertTrue((real / 'permit-history' / permit['permit_id'] / 'permit.json.sig').is_file())
        self.assertEqual(app.monitor().run(utc_now(), 'MANUAL')['outcome'], 'UNCHANGED')
        self.assertEqual(app.site.baseline_state()['source_run'], source_run)

    def test_a_tampered_carryover_or_another_trusted_key_is_refused(self):
        self.fake = FakeHarness()
        code, out = self.run_setup('--url', 'https://my-site.com/', '--ownership', 'well-known-file', '--verified-at', format_utc(utc_now()), '--days', '3')
        self.assertEqual(code, 0, out)
        app = self.app()
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'BASELINE_CREATED')
        origin = app.site.root / 'real' / 'registry-origin.json'
        o = json.loads(origin.read_text('utf-8'))
        origin.write_text(json.dumps({**o, 'registry_export_sha256': '0' * 64}), encoding='utf-8')  # carried-over name, other content
        code, out = self.run_setup('--ownership', 'well-known-file', '--verified-at', format_utc(utc_now()))
        self.assertEqual(code, 2, out)
        self.assertIn('NG', out)
        code, out = self.run_setup('--ownership', 'dns-txt', '--verified-at', format_utc(utc_now()), key=self.root / 'keys' / 'other')
        self.assertEqual(code, 1)
        self.assertIn('別の鍵', out)

    def test_an_unconfirmed_ownership_signs_nothing(self):
        code, out = self.run_setup('--url', 'https://my-site.com/', '--ownership', 'well-known-file')
        self.assertEqual(code, 1)
        self.assertFalse((self.root / 'data' / 'sites').is_dir() and any((self.root / 'data' / 'sites').glob('site-*/real/permit.json')))


class BackgroundTick(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-bg-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name) / 'data'
        app = App(self.data)
        app.setup()
        app.site_action('register', {'name': 'S', 'url': 'https://my-site.com/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})
        self.site = app.site.root

    def test_nothing_runs_unless_due_and_docker_is_started_only_for_a_real_site(self):
        docker = mock.MagicMock(return_value=True)
        with mock.patch('src.noxiworks.site_monitor.main', return_value=0) as run:
            m = json.loads((self.site / 'monitor.json').read_text('utf-8'))
            (self.site / 'monitor.json').write_text(json.dumps({**m, 'next_due_at': format_utc(utc_now() + timedelta(hours=1))}), encoding='utf-8')
            self.assertEqual(background_monitor.tick(self.data, docker=docker), 0)
            run.assert_not_called()
            (self.site / 'monitor.json').write_text(json.dumps({**m, 'next_due_at': format_utc(utc_now() - timedelta(seconds=1))}), encoding='utf-8')
            background_monitor.tick(self.data, docker=docker)
            run.assert_called_once()
            docker.assert_not_called()  # no permit: Docker is not started
            (self.site / 'real').mkdir(exist_ok=True)
            (self.site / 'real' / 'permit.json').write_text('{}', encoding='utf-8')
            background_monitor.tick(self.data, docker=docker)
            docker.assert_called_once()

    def test_docker_is_started_when_it_does_not_answer(self):
        answers = iter([False, False, True])
        start = mock.MagicMock()
        self.assertTrue(background_monitor.ensure_docker(lambda: next(answers), start, wait=60, sleep=lambda s: None))
        start.assert_called_once()
        self.assertFalse(background_monitor.ensure_docker(lambda: False, start, wait=0, sleep=lambda s: None))

    def test_install_is_per_site_and_dry_run_registers_nothing(self):
        with mock.patch('tools.background_monitor.schtasks') as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(background_monitor.install(self.data, 15, dry_run=True), 0)
        schtasks.assert_not_called()
        self.assertIn('/TN SiteProof-Monitor-' + self.site.name, out.getvalue())
        self.assertIn('tick --data', (self.data / 'background' / 'tick.cmd').read_text('ascii'))


if __name__ == '__main__':
    unittest.main()


class FoundInTheRealE2E(unittest.TestCase):
    """Defects the HMS real-site E2E (2026-11-21) found, which the harness test double could not."""

    def test_the_app_starts_the_harness_as_a_module(self):
        import subprocess
        import sys
        from src.noxiworks import real_capture
        p = subprocess.run([sys.executable, '-B', '-m', real_capture.HARNESS_MODULE, '--help'], cwd=real_capture.ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])  # as a script (`python tests/runtime/validate_s3t.py`) `src` is not importable

    def test_a_baseline_needs_only_the_settled_shots_to_match(self):
        from tools import register_baseline as rb
        final, early = 'a' * 64, 'b' * 64
        shot = lambda sha: {'t_ms': 1, 'sha256': sha}
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        run = Path(tmp.name)
        job = {'job_id': 'j1', 'kind': 'Desktop', 'execution': 'COMPLETED', 'page_id': 'p1',
               'profile': {'attributes': {'viewport_width': 1440, 'viewport_height': 900, 'full_page': True}}}
        (run / 'Desktop-run-result.json').write_text(json.dumps({'state': {'jobs': [job]}}), encoding='utf-8')
        planned = {'page_id': 'p1', 'width': 1440, 'height': 900, 'full_page': True}

        def report(shots):
            return {'captures': {'Desktop': {'job_id': 'j1', 'stability': {'value': 'STABLE', 'reason': None, 'shots': shots,
                                                                           'policy': {'required_identical': 3}}}}}
        try:  # a still-loading first shot differs: the last three are the settled run
            rb.check_candidate(run, report([shot(early), shot(final), shot(final), shot(final)]), 'Desktop', 'capture-j1', final, planned)
        except rb.Stop as exc:
            if 'stability' in str(exc):
                self.fail(exc)
        for shots in ([shot(early), shot(final), shot(final)], [shot(final), shot(final), shot(early)], []):
            with self.subTest(shots=len(shots)), self.assertRaises(rb.Stop):
                rb.check_candidate(run, report(shots), 'Desktop', 'capture-j1', final, planned)

    def test_a_site_not_ready_is_looked_at_again_within_the_hour(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-nr-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        app = App(Path(tmp.name) / 'data')
        app.setup()
        app.site_action('register', {'name': 'S', 'url': 'https://my-site.com/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True,
                                     'interval_seconds': 86400})
        entry = app.monitor().run(utc_now(), 'SCHEDULE')
        self.assertEqual(entry['outcome'], 'REAL_NOT_READY')
        due = json.loads((app.site.root / 'monitor.json').read_text('utf-8'))['next_due_at']
        from src.aws_b.model import parse_utc
        self.assertLessEqual(parse_utc(due) - parse_utc(entry['finished_at']), timedelta(hours=1))

    def test_docker_must_answer_not_just_be_installed(self):
        from src.noxiworks import real_capture
        from src.noxiworks.site_workflow import Site
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-dk-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        app = App(Path(tmp.name) / 'data')
        app.setup()
        app.site_action('register', {'name': 'S', 'url': 'https://my-site.com/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})
        with mock.patch.object(real_capture.shutil, 'which', return_value='docker'), \
                mock.patch.object(real_capture, 'docker_engine_answers', return_value=False) as engine:
            capture = real_capture.RealCapture(Site(app.site.root))
            # the engine is asked only once every other gate holds (never merely because a site is registered) ...
            env = next(c for c in capture.readiness(utc_now()) if c['key'] == 'environment')
            engine.assert_not_called()
            self.assertFalse(env['ok'])
            self.assertIn('確認していません', env['state'])
            # ... and then it must ANSWER, not just be installed
            self.assertIs(capture._engine(True), False)
        with mock.patch.object(real_capture.RealCapture, '_engine', return_value=False):
            env = next(c for c in real_capture.RealCapture(Site(app.site.root)).readiness(utc_now()) if c['key'] == 'environment')
        self.assertFalse(env['ok'])
        self.assertIn('Docker Desktopが起動していません', env['state'])

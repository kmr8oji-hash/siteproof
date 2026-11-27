"""The USER-run setup tools, offline: tools/setup_monitoring.py (register -> key -> trust -> ownership -> signed permit -> readiness),
renewal with the Baseline carried over, tools/cf_ownership.py against a fake Cloudflare API (GET only), and tools/background_monitor.py
`tick` / `install --dry-run`. Keys are SYNTHETIC (temp folder, no passphrase); nothing touches the network, Docker or the OS scheduler."""
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import shutil
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
        with mock.patch('tools.cf_ownership.wrangler_token', return_value='synthetic-token'), \
                mock.patch('tools.cf_ownership.find_wrangler', return_value=['wrangler']), \
                mock.patch('urllib.request.urlopen', FakeCloudflare()):
            code, out = self.run_setup('--url', CF_URL, '--ownership', 'cloudflare', '--days', '3')
        self.assertEqual(code, 0, out)
        app = self.app()
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'BASELINE_CREATED')
        origin = app.site.root / 'real' / 'registry-origin.json'
        o = json.loads(origin.read_text('utf-8'))
        origin.write_text(json.dumps({**o, 'registry_export_sha256': '0' * 64}), encoding='utf-8')  # carried-over name, other content
        code, out = self.run_setup()
        self.assertEqual(code, 2, out)
        self.assertIn('NG', out)
        code, out = self.run_setup(key=self.root / 'keys' / 'other')
        self.assertEqual(code, 1)
        self.assertIn('別の鍵', out)

    def tree(self):
        """Every file under the data folder with its hash: what a refused setup must leave exactly as it was."""
        data = self.root / 'data'
        return {p.relative_to(data).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(data.rglob('*')) if p.is_file()} if data.is_dir() else {}

    def test_unsupported_ownership_methods_are_refused_before_anything_is_created(self):
        for method in ('well-known-file', 'dns-txt'):
            with self.subTest(method):
                code, out = self.run_setup('--url', 'https://my-site.com/', '--ownership', method, '--days', '3')
                self.assertEqual(code, 1, out)
                self.assertIn('現在対応していません', out)
                self.assertIn('何も変更していません', out)
                self.assertFalse((self.root / 'data').exists(), 'no site, trust file, status or permit may be created')
                self.assertFalse(self.key.exists() or self.key.with_name(self.key.name + '.pub').exists(), 'no key may be created')

    def test_an_unsupported_method_never_replaces_or_archives_a_working_permit(self):
        self.fake = FakeHarness()
        with mock.patch('tools.cf_ownership.wrangler_token', return_value='synthetic-token'),                 mock.patch('tools.cf_ownership.find_wrangler', return_value=['wrangler']),                 mock.patch('urllib.request.urlopen', FakeCloudflare()):
            code, out = self.run_setup('--url', CF_URL, '--ownership', 'cloudflare', '--days', '3')
        self.assertEqual(code, 0, out)
        before = self.tree()
        self.assertTrue(any(k.endswith('/real/permit.json') for k in before))
        for method in ('well-known-file', 'dns-txt'):
            with self.subTest(method):
                code, out = self.run_setup('--ownership', method, '--days', '30')
                self.assertEqual(code, 1, out)
                self.assertIn('現在対応していません', out)
                self.assertEqual(self.tree(), before, 'permit, signature, permit-history, trust and status must be untouched')
        self.assertFalse(list((self.root / 'data').glob('sites/*/real/permit-history')))
        self.assertTrue(all(c['ok'] for c in self.app().monitor().real().readiness(utc_now())))  # the working permit still works

    def cloudflare_setup(self, *extra):
        with mock.patch('tools.cf_ownership.wrangler_token', return_value='synthetic-token'), \
                mock.patch('tools.cf_ownership.find_wrangler', return_value=['wrangler']), \
                mock.patch('urllib.request.urlopen', FakeCloudflare()):
            return self.run_setup('--url', CF_URL, '--ownership', 'cloudflare', *extra)

    def monitor_json(self):
        return json.loads(next((self.root / 'data').glob('sites/*/monitor.json')).read_text('utf-8'))

    def test_max_runs_sets_the_signed_limit_and_the_default_is_kept(self):
        self.fake = FakeHarness()
        code, out = self.cloudflare_setup('--max-runs', '1', '--days', '3')
        self.assertEqual(code, 0, out)
        self.assertIn('最大 1 回（指定）', out)
        real = self.app().site.root / 'real'
        permit = json.loads((real / 'permit.json').read_text('utf-8'))
        self.assertEqual(permit['max_runs'], 1)
        permits.verify_signature(real / 'permit.json', self.root / 'data' / 'trust' / 'allowed_signers')  # the limit is inside the signature
        code, out = self.run_setup('--days', '30')  # renewal without --max-runs: the computed value (30 days, 24 h interval) as before
        self.assertEqual(code, 0, out)
        self.assertIn('自動計算', out)
        self.assertEqual(json.loads((real / 'permit.json').read_text('utf-8'))['max_runs'], 30 + 7)

    def test_a_bad_max_runs_is_refused_before_anything_is_touched(self):
        for bad in ('0', '-1', 'abc', '1.5', '', '01', '1e3'):
            with self.subTest(bad), mock.patch('sys.stderr', new_callable=io.StringIO) as err:
                with self.assertRaises(SystemExit) as stop:
                    setup_monitoring.main(['--data', str(self.root / 'data'), '--key', str(self.key), '--no-passphrase', '--yes', '--url', CF_URL,
                                           '--ownership', 'cloudflare', '--max-runs', bad])
                self.assertEqual(stop.exception.code, 2)
                self.assertIn('1以上の整数', err.getvalue())
                self.assertFalse((self.root / 'data').exists() or self.key.exists(), 'no site, trust file, key or permit may be created')

    def test_a_bad_max_runs_leaves_a_working_permit_untouched(self):
        self.fake = FakeHarness()
        code, out = self.cloudflare_setup('--days', '3')
        self.assertEqual(code, 0, out)
        before = self.tree()
        for bad in ('0', '-5', 'x'):
            with self.subTest(bad), mock.patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit):
                    setup_monitoring.main(['--data', str(self.root / 'data'), '--key', str(self.key), '--no-passphrase', '--yes', '--max-runs', bad])
                self.assertEqual(self.tree(), before)

    def test_manual_only_leaves_nothing_that_runs_by_itself(self):
        self.fake = FakeHarness()
        seen = []
        real_run = setup_monitoring.subprocess.run

        def watching(args, *a, **kw):
            if '-Y' in args and 'sign' in args:  # at the moment the permit is signed, automatic monitoring is already off
                seen.append(self.monitor_json()['enabled'])
            return real_run(args, *a, **kw)
        with mock.patch.object(setup_monitoring.subprocess, 'run', watching):
            code, out = self.cloudflare_setup('--manual-only', '--max-runs', '1', '--days', '1')
        self.assertEqual(code, 0, out)
        self.assertEqual(seen, [False])
        self.assertIn('手動撮影のみ', out)
        self.assertIs(self.monitor_json()['enabled'], False)
        app = self.app()
        self.assertEqual(json.loads((app.site.root / 'real' / 'permit.json').read_text('utf-8'))['max_runs'], 1)
        self.assertTrue(all(c['ok'] for c in app.monitor().real().readiness(utc_now())), out)  # the permit itself is fully valid
        self.assertIsNone(app.monitor().run_if_due(utc_now() + timedelta(days=1)))  # a scheduler / the app tick finds nothing due
        self.assertIsNone(app.tick())
        done = app.site_action('inspect', {})  # the GUI's 今すぐ再検査 still works, and it is the only way to capture
        self.assertEqual(done['outcome'], 'BASELINE_CREATED')
        self.assertIs(self.monitor_json()['enabled'], False)

    def test_manual_only_renewal_keeps_the_baseline_and_the_schedule_fields(self):
        self.fake = FakeHarness()
        code, out = self.cloudflare_setup('--days', '30')
        self.assertEqual(code, 0, out)
        self.assertIs(self.monitor_json()['enabled'], True)  # without the option the behaviour is unchanged: on, due now
        app = self.app()
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'BASELINE_CREATED')
        real = app.site.root / 'real'
        old = json.loads((real / 'permit.json').read_text('utf-8'))
        source_run = app.site.baseline_state()['source_run']
        due = self.monitor_json()['next_due_at']
        code, out = self.run_setup('--manual-only', '--max-runs', '1', '--days', '1')
        self.assertEqual(code, 0, out)
        renewed = json.loads((real / 'permit.json').read_text('utf-8'))
        self.assertEqual((renewed['max_runs'], renewed['baseline_carryover']['permit_id']), (1, old['permit_id']))
        settings = self.monitor_json()
        self.assertEqual((settings['enabled'], settings['next_due_at']), (False, due))  # only `enabled` changed
        self.assertIsNone(app.monitor().run_if_due(utc_now() + timedelta(days=2)))
        self.assertEqual(app.monitor().run(utc_now(), 'MANUAL')['outcome'], 'UNCHANGED')  # compared with the carried-over Baseline
        self.assertEqual(app.site.baseline_state()['source_run'], source_run)

    def test_manual_only_is_refused_while_an_inspection_is_running(self):
        self.fake = FakeHarness()
        code, out = self.cloudflare_setup('--days', '3')
        self.assertEqual(code, 0, out)
        (self.app().site.root / 'monitor.lock').write_text('{}', encoding='utf-8')  # an inspection holds the lock
        before = self.tree()
        code, out = self.run_setup('--manual-only', '--max-runs', '1')
        self.assertEqual(code, 1, out)
        self.assertIn('monitor.lock', out)
        self.assertIn('監視設定は何も変更していません', out)
        status = lambda t: {k: v for k, v in t.items() if not k.endswith('setup-status.json')}  # only the screen's status line may change
        self.assertEqual(status(self.tree()), status(before))

    def test_no_ownership_method_and_no_evidence_signs_nothing(self):
        code, out = self.run_setup('--url', 'https://my-site.com/')
        self.assertEqual(code, 1)
        self.assertIn('--ownership cloudflare', out)
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
            run.assert_called_once_with(['--data', str(self.data), '--site', self.site.name])  # one pass for this site only
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
        self.assertIn('/TN ' + background_monitor.task_name(self.data, self.site.name, 'image'), out.getvalue())
        self.assertRegex(background_monitor.task_name(self.data, self.site.name, 'image'), r'^SiteProof-Image-' + self.site.name + r'-[0-9a-f]{8}$')
        self.assertIn('tick --data', self.cmd_path().read_text('ascii'))
        self.assertFalse((self.data / 'background' / 'tick.cmd').exists())  # the old launcher name is not written any more

    # ---- which Python the task runs (tick.cmd)
    def fake_python(self, parent, *names):
        folder = Path(parent)
        folder.mkdir(parents=True, exist_ok=True)
        for name in names:
            (folder / name).write_bytes(b'')
        return folder / 'python.exe'

    def cmd_path(self, channel='image'):
        return self.data / 'background' / f'{self.site.name}-{channel}.cmd'

    def tick_line(self):
        lines = self.cmd_path().read_text('ascii').splitlines()
        return next(l for l in lines if 'background_monitor.py' in l)

    def test_the_task_runs_the_python_that_runs_the_tool_not_a_fixed_version(self):
        env = Path(tempfile.mkdtemp(prefix='siteproof-py-'))
        self.addCleanup(shutil.rmtree, env, True)
        python = self.fake_python(env / 'venv' / 'Scripts', 'python.exe', 'pythonw.exe')
        with mock.patch.object(background_monitor.sys, 'executable', str(python)):
            cmd = background_monitor.launcher(self.data)
        text = cmd.read_text('ascii')
        line = self.tick_line()
        self.assertTrue(line.startswith('"' + str((env / 'venv' / 'Scripts' / 'pythonw.exe').resolve()) + '" -B tools\\background_monitor.py tick --data "'))
        self.assertNotIn('3.15', text)  # no version is fixed, and no `pyw -3.x` launcher switch
        self.assertNotIn('pyw', text)
        self.assertIn(f'cd /d "{background_monitor.ROOT}"', text)  # the working directory is kept
        self.assertIn(f'--data "{self.data.resolve()}"', line)  # the data folder is kept
        self.assertIn(f' --site {self.site.name} >> ', line)
        self.assertTrue(line.endswith(f'>> "{self.data.resolve() / "background" / (self.site.name + "-image.log")}" 2>&1'))  # the log is kept

    def test_without_pythonw_the_interpreter_itself_is_used(self):
        env = Path(tempfile.mkdtemp(prefix='siteproof-py-'))
        self.addCleanup(shutil.rmtree, env, True)
        python = self.fake_python(env, 'python.exe')
        with mock.patch.object(background_monitor.sys, 'executable', str(python)):
            background_monitor.launcher(self.data)
        self.assertTrue(self.tick_line().startswith('"' + str((env / 'python.exe').resolve()) + '" -B '))
        pythonw = self.fake_python(env / 'w', 'pythonw.exe')  # already windowless: used as it is
        with mock.patch.object(background_monitor.sys, 'executable', str(pythonw.with_name('pythonw.exe'))):
            background_monitor.launcher(self.data)
        self.assertTrue(self.tick_line().startswith('"' + str((env / 'w' / 'pythonw.exe').resolve()) + '" -B '))

    def test_paths_with_spaces_are_quoted(self):
        env = Path(tempfile.mkdtemp(prefix='siteproof-py-'))
        self.addCleanup(shutil.rmtree, env, True)
        python = self.fake_python(env / 'My Python 3.13' / 'Scripts', 'python.exe', 'pythonw.exe')
        with mock.patch.object(background_monitor.sys, 'executable', str(python)):
            background_monitor.launcher(self.data)
        self.assertTrue(self.tick_line().startswith('"' + str((env / 'My Python 3.13' / 'Scripts' / 'pythonw.exe').resolve()) + '" '))

    def test_a_percent_sign_in_a_path_is_not_expanded_by_cmd(self):
        self.assertEqual(background_monitor.batch_text(r'C:\a%PATH%b'), r'C:\a%%PATH%%b')

    def test_no_usable_python_registers_no_task_and_writes_no_launcher(self):
        env = Path(tempfile.mkdtemp(prefix='siteproof-py-'))
        self.addCleanup(shutil.rmtree, env, True)
        missing = env / 'nowhere' / 'python.exe'
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run), mock.patch.object(background_monitor.sys, 'executable', str(missing)), \
                    mock.patch('tools.background_monitor.schtasks') as schtasks:
                with self.assertRaises(SystemExit) as stop:
                    background_monitor.install(self.data, 15, dry_run=dry_run)
                self.assertIn('Pythonの実行ファイルが見つかりません', str(stop.exception))
                schtasks.assert_not_called()
                self.assertFalse(self.cmd_path().exists())

    def test_install_registers_the_task_with_that_launcher_only_through_schtasks(self):
        env = Path(tempfile.mkdtemp(prefix='siteproof-py-'))
        self.addCleanup(shutil.rmtree, env, True)
        python = self.fake_python(env, 'python.exe', 'pythonw.exe')
        done = mock.MagicMock(returncode=0, stdout='ok', stderr='')
        with mock.patch.object(background_monitor.sys, 'executable', str(python)), mock.patch('tools.background_monitor.schtasks', return_value=done) as schtasks, \
                mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(background_monitor.install(self.data, 15, dry_run=False), 0)
        args = schtasks.call_args[0]
        self.assertEqual(args[:2], ('/Create', '/F'))  # the existing registration call, unchanged
        self.assertEqual(args[args.index('/TN') + 1], background_monitor.task_name(self.data, self.site.name, 'image'))
        self.assertEqual(args[args.index('/MO') + 1], '15')
        self.assertEqual(args[args.index('/TR') + 1], '"' + str(self.cmd_path().resolve()) + '"')

    def test_a_disabled_monitor_never_starts_an_inspection_or_docker(self):
        docker = mock.MagicMock(return_value=True)
        m = json.loads((self.site / 'monitor.json').read_text('utf-8'))
        (self.site / 'monitor.json').write_text(json.dumps({**m, 'enabled': False, 'next_due_at': format_utc(utc_now() - timedelta(days=1))}), encoding='utf-8')
        (self.site / 'real').mkdir(exist_ok=True)
        (self.site / 'real' / 'permit.json').write_text('{}', encoding='utf-8')  # a real-capture site: Docker would be asked if it were due
        with mock.patch('src.noxiworks.site_monitor.main', return_value=0) as run:
            self.assertEqual(background_monitor.tick(self.data, docker=docker), 0)
        run.assert_not_called()
        docker.assert_not_called()  # --manual-only (enabled false) keeps the OS task idle


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

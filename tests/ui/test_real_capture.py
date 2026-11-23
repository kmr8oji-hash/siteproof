"""Signed monitoring permits (src/noxiworks/permit.py), the real-capture adapter (real_capture.py) and automatic continuation
(site_monitor.py), offline. Keys are SYNTHETIC Ed25519 keys made per test in a temp folder; the USER's signing is played by the
test with `ssh-keygen -Y sign`. The harness is replaced by FakeHarness, a TEST DOUBLE that re-verifies the permit like the harness's
permit mode (same shared code) and writes the S3-1T export from the offline image producer -- no Docker, browser or network.
Nothing here is a real-site E2E."""
from datetime import timedelta
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from src.aws_b.model import format_utc
from src.noxiworks import permit as permits
from src.noxiworks.app import App, utc_now

ROOT = Path(__file__).resolve().parents[2]
SITE_URL = 'https://my-site.com/'
# = tests/runtime/validate_s3t.IDENTITY_FILES (the harness requires --expect to pin exactly these)
IDENTITY_FILES = ('tests/runtime/netpolicy_hardened.py', 'tests/runtime/egress_broker.py', 'tests/runtime/egress_reaper.py',
                  'tests/runtime/s3_worker.py', 'tests/runtime/s3t_worker.py', 'tests/runtime/validate_s3t.py',
                  'src/noxiworks/capture_plan.json', 'src/noxiworks/targets.json', 'src/noxiworks/capture.py', 'src/isolation/site_policy.py',
                  'src/runtime/stability.py', 'src/runtime/service.py', 'src/comparison/service.py', 'src/noxiworks/baseline_runtime.py',
                  'src/noxiworks/permit.py', 'src/noxiworks/product.py')
# synthetic Cloudflare record for CLOUDFLARE_ACCOUNT_CONTROL (not a real account, Worker or subdomain)
CF_ACCOUNT, CF_WORKER, CF_SUB = 'a' * 64, 'my-worker', 'my-sub'
CF_HOST = f'{CF_WORKER}.{CF_SUB}.workers.dev'
CF_URL = f'https://{CF_HOST}/'
needs_ssh = unittest.skipUnless(permits.ssh_keygen(), 'OpenSSH ssh-keygen not available')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def keypair(folder, name):
    subprocess.run([permits.ssh_keygen(), '-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-test-key', '-f', str(folder / name)], check=True)
    return folder / name


class FakeHarness:
    """Stands in for validate_s3t.py in permit mode (offline test double): verifies like the harness, captures the pinned target."""

    def __init__(self):
        self.calls, self.variant, self.mark_synthetic = [], 'same', False

    def __call__(self, args, env):
        from src.noxiworks.baseline_runtime import comparison_export, expected_baseline, open_runtime, prepare_job, read_registry, stage, tree
        from src.noxiworks.capture import create_runtime
        from src.noxiworks.site_workflow import IMAGE_HEIGHTS, STABILITY, page_image
        from src.runtime.stability import policy
        from src.worker.capture import capture, MemoryChannel
        from tests.comparison.support import synthetic_browser_audit
        from tools.offline_baseline_demo import RESOURCES, DemoLease, StoredImageDriver, changed_image, stability_record
        self.calls.append((list(args), dict(env)))
        arg = lambda k: Path(args[args.index(k) + 1]) if k in args else None
        evidence, registry, target_dir = arg('--evidence'), arg('--baseline-registry'), arg('--target-dir')
        # what the harness's permit mode checks before any container (shared code)
        permit = permits.verify_signature(arg('--permit'), arg('--trust'))
        pins = {**expected_baseline(read_registry(registry)), 'registry_export_sha256': sha(registry / 'export-sha256.json')} if registry else None
        expect = json.loads(arg('--expect').read_text('utf-8'))
        assert permits.check_expect(permit, expect, pins), 'expect is not the permit identity'
        assert all(permit['target_files'][n] == sha(target_dir / n) for n in permits.TARGET_FILES), 'target files differ'
        targets = json.loads((target_dir / 'targets.json').read_text('utf-8'))
        page = next(p for p in targets['pages'] if p['target_id'] == permit['target']['target_id'])
        assert page['url'] == permit['target']['url']
        plan = json.loads((target_dir / 'capture_plan.json').read_text('utf-8'))
        profiles = next(pg for s in plan['sites'] for pg in s['pages'] if pg['page_id'] == page['target_id'])['profiles']
        try:  # the harness counts the run in the permit ledger before any container (validate_s3t permit mode)
            permits.reserve_run(arg('--trust'), permit, evidence.name, format_utc(utc_now()))
        except permits.PermitRefused:
            return 2  # GateFailed: no container, no evidence
        evidence.mkdir(parents=True, exist_ok=False)
        ws = evidence.parent / 'fake-worker-ws'
        if registry is not None:
            stage(registry, ws)
            runtime = open_runtime(ws)
        else:
            runtime = create_runtime(ws, {'pages': [{'target_id': page['target_id'], 'label': page['label'], 'url': page['url'],
                                                     'site_name': targets['sites'][0]['name'], 'profiles': profiles}]})
        files, windows, captures, exports, compared = {}, {}, {}, {}, set()
        now = utc_now()
        for n, p in enumerate(profiles):
            kind = p['kind']
            base = page_image(p['width'], IMAGE_HEIGHTS[kind], (40, 60, 90, 255))
            image = changed_image(base) if self.variant == 'changed' else base
            stability = stability_record(image, None, policy(STABILITY))
            batch, job_id, bound = prepare_job(runtime, page['target_id'], kind)
            lease = DemoLease(runtime.repo.get_job(job_id).snapshot.intent.target_url)

            def factory(request, remaining, image=image, job_id=job_id, lease=lease, stability=stability):
                out = capture(request, StoredImageDriver(image, lease.ledger), lease, RESOURCES)
                runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))
                runtime.record_capture_stability(job_id, stability)
                return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed
            runtime.run(batch, factory, lease, RESOURCES)
            compared.add(bound['baseline'] is not None)
            comp = runtime.comparison.result(runtime.comparison.store.rows('results', job_id=job_id, limit=1)[0]['result_id'])
            files[f'{kind}-run-result.json'] = {'type': 'result', 'state': runtime.state(batch), 'comparison': runtime.comparison.state(),
                                                'baselines': runtime.workspace.state()['baselines'], 'capture_info': {job_id: {'repeat_identical': True}}}
            files[f'{kind}-head.json'] = {'http_status': 'HTTP/1.1 200 OK', 'tls': {'result': 'OK'}, 'http_headers': {}, 'redirect': None}
            files[f'{kind}-capture-meta.json'] = [{'sandbox': {'browser_version': 'fake-harness'}, 'runtime': {}}]
            exports.update(comparison_export(runtime, job_id))
            at = now - timedelta(seconds=30 - 10 * n)  # windows just passed, as a real harness records them (never in the future)
            windows['CAPTURE-' + kind] = {'opened_at': format_utc(at), 'closed_at': format_utc(at + timedelta(seconds=5))}
            captures[kind] = {'job_id': job_id, 'stability': stability, 'quality': comp['quality'], 'comparison_reasons': comp['reasons']}
        report = {'task': 'FAKE-HARNESS-TEST-DOUBLE', 'passed': True, 'baseline_approved': False, 'baseline_compared': compared.pop(),
                  'aws_touched': False, 'site_modified': False, 'monitoring_started': False, 'navigated_to_real_site': False,
                  'windows': windows, 'captures': captures, 'fake_harness': True, **({'synthetic': True} if self.mark_synthetic else {})}
        files['validation-result.json'] = report
        files['workspace-created.json'] = {'site': targets['sites'][0]['name'], 'origin': targets['sites'][0]['origin'], 'url': page['url'],
                                           'page_id': page['target_id']}
        for name, body in files.items():
            (evidence / name).write_text(json.dumps(body, ensure_ascii=False), encoding='utf-8')
        for name, raw in exports.items():
            (evidence / name).write_bytes(raw)
        shutil.copytree(ws, evidence / 'workspace')
        shutil.rmtree(ws, ignore_errors=True)
        (evidence / 'export-sha256.json').write_text(json.dumps(tree(evidence)), encoding='utf-8')
        return 0


@needs_ssh
class SignedPermit(unittest.TestCase):
    def setUp(self):
        # ignore_cleanup_errors: Windows may still hold a SQLite handle briefly after a test
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-permit-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.keys = self.root / 'keys'
        self.keys.mkdir()
        self.user_key = keypair(self.keys, 'user')        # stands in for the USER's own key (synthetic)
        self.other_key = keypair(self.keys, 'stranger')   # a key nobody trusts
        self.fake = FakeHarness()
        self.n = 0

    def app(self, name='data', url=SITE_URL, fixture_capture=False, kinds=('Desktop', 'Mobile')):
        app = App(self.root / name)
        app.fixture_capture = fixture_capture
        app.setup()
        app.docker_found, app.real_runner = True, self.fake
        app.site_action('register', {'name': 'S', 'url': url, 'kinds': list(kinds), 'owner_confirmed': True})
        trust = app.data / 'trust'
        trust.mkdir(exist_ok=True)
        pub = (self.keys / 'user.pub').read_text('utf-8').split()
        (trust / 'allowed_signers').write_text(f'site-owner namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='utf-8')
        return app

    def permit(self, app, key=None, *, sign=True, **over):
        site, now = app.site, utc_now()
        self.n += 1
        body = {'schema': permits.SCHEMA, 'permit_id': 'permit-%d' % self.n, 'issued_by': 'site-owner', 'issued_at': format_utc(now),
                'site': {'site_id': site.info['site_id'], 'origin': site.info['origin'], 'host': site.info['url'].split('/')[2]},
                'target': {'target_id': site.page_id, 'url': site.info['url']},
                'target_files': {n: sha(site.root / n) for n in permits.TARGET_FILES},
                'valid_from': format_utc(now - timedelta(hours=1)), 'valid_until': format_utc(now + timedelta(days=1)), 'max_runs': 5,
                'ownership': {'method': 'well-known-file', 'verified_at': format_utc(now)},
                'identity': {'files': {rel: sha(ROOT / rel) for rel in IDENTITY_FILES}, 'image_id': 'sha256:' + '0' * 64,
                             'bundle_manifest_sha256': '1' * 64},
                'baseline_policy': 'AUTO_INITIAL_THEN_COMPARE'}
        body.update(over)
        real = site.root / 'real'
        real.mkdir(exist_ok=True)
        f = real / 'permit.json'
        f.write_text(json.dumps(body, ensure_ascii=False), encoding='utf-8')
        sig = f.with_name('permit.json.sig')
        sig.unlink(missing_ok=True)
        if sign:
            subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(key or self.user_key), str(f)],
                           check=True, capture_output=True)
        return body

    def outcome(self, app):
        entry = app.monitor().run(utc_now(), 'SCHEDULE')
        return entry['mode'], entry['outcome']

    def test_refusals_never_reach_the_harness(self):
        app = self.app()
        cases = [('no permit', lambda: None), ('unsigned', lambda: self.permit(app, sign=False)),
                 ('untrusted key', lambda: self.permit(app, self.other_key)),
                 ('other host', lambda: self.permit(app, site={'site_id': app.site.info['site_id'], 'origin': 'https://evil.example', 'host': 'evil.example'})),
                 ('expired', lambda: self.permit(app, valid_until=format_utc(utc_now() - timedelta(seconds=1)))),
                 ('no runs', lambda: self.permit(app, max_runs=0)),
                 ('no ownership check', lambda: self.permit(app, ownership={})),
                 ('identity pins other file contents', lambda: self.permit(app, identity={'files': {rel: '0' * 64 for rel in IDENTITY_FILES}, 'image_id': 'sha256:' + '0' * 64}))]
        for name, make in cases:
            with self.subTest(name):
                make()
                self.assertFalse(app.monitor().real().ready(utc_now()))
                self.assertEqual(self.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))
        # a valid permit, then the permit or the settings file is edited without a new signature
        self.permit(app)
        self.assertTrue(app.monitor().real().ready(utc_now()))
        f = app.site.root / 'real' / 'permit.json'
        f.write_text(f.read_text('utf-8').replace('"max_runs": 5', '"max_runs": 500'), encoding='utf-8')
        self.assertIn('署名が正しくありません', app.monitor().real().permit()[1])
        self.permit(app)
        targets = app.site.root / 'targets.json'
        original = targets.read_bytes()
        targets.write_bytes(original.replace(b'https://my-site.com/', b'https://other-site.com/'))  # "just change the URL in the settings"
        self.assertFalse(app.monitor().real().ready(utc_now()))
        self.assertEqual(self.outcome(app)[1], 'REAL_NOT_READY')
        targets.write_bytes(original)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual((app.site.runs(), app.site.real_runs()), ([], []))

    def test_signed_permit_runs_baseline_then_compares_without_new_approval(self):
        app = self.app()
        self.assertEqual(self.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))  # registered, nothing captured or generated
        permit = self.permit(app, max_runs=4)
        self.assertEqual(self.outcome(app), ('REAL', 'BASELINE_CREATED'))
        args = self.fake.calls[-1][0]
        self.assertTrue({'--permit', '--trust', '--target-dir', '--expect'} <= set(args))
        self.assertNotIn('--baseline-registry', args)
        registry = app.site.real_registry()
        record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
        self.assertEqual(record['page_id'], app.site.page_id)
        self.assertEqual(json.loads((app.site.root / 'real' / 'registry-origin.json').read_text('utf-8'))['permit_id'], permit['permit_id'])
        registry_tree = {p.relative_to(registry).as_posix(): sha(p) for p in registry.rglob('*') if p.is_file()}
        # no new approval: the next runs derive the compare-mode --expect from the same signed permit
        self.assertEqual(self.outcome(app), ('REAL', 'UNCHANGED'))
        self.fake.variant = 'changed'
        self.assertEqual(self.outcome(app), ('REAL', 'CHANGED'))
        self.assertIn('--baseline-registry', self.fake.calls[-1][0])
        self.assertEqual({p.relative_to(registry).as_posix(): sha(p) for p in registry.rglob('*') if p.is_file()}, registry_tree)  # untouched
        self.assertEqual(app.site.baseline_state()['source_run'], record['source_run']['run_id'])
        self.assertEqual(app.site_status()['display'], 'REAL_MONITORING')
        # 4 of 4 runs used: the next one stops -- also after a restart (count and Baseline pin are on disk)
        self.assertEqual(self.outcome(app), ('REAL', 'CHANGED'))
        again = App(app.data)
        again.setup()
        again.docker_found, again.real_runner = True, self.fake
        calls = len(self.fake.calls)
        self.assertEqual(again.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'REAL_NOT_READY')
        self.assertEqual(len(self.fake.calls), calls)
        self.assertEqual(again.site.baseline_state()['source_run'], record['source_run']['run_id'])
        self.assertEqual(again.site_status()['display'], 'EXPIRED')  # all runs used: the headline asks for "監視設定を更新"
        # real only on the pages: no synthetic run was ever made for this site
        again.rebuild_site()
        view = json.loads((again.site_ui / 'view.json').read_text('utf-8'))
        self.assertNotEqual(view['source'], 'FIXTURE')
        self.assertEqual(sorted(h['class'] for h in view['monitoring']['history']),
                         ['CHANGED', 'CHANGED', 'CHANGED', 'CHANGED', 'NOT_COMPARED', 'NOT_COMPARED', 'UNCHANGED', 'UNCHANGED'])
        self.assertEqual(again.site.runs(), [])
        # a new permit (renewal) does not silently take over the old Baseline
        self.permit(again, max_runs=10)
        problems = [c['state'] for c in again.monitor().real().readiness(utc_now()) if not c['ok']]
        self.assertTrue(any('別の監視許可' in p for p in problems), problems)

    def test_run_limit_holds_for_direct_harness_runs_failures_and_restarts(self):
        app = self.app()
        permit = self.permit(app, max_runs=2)
        trust = app.data / 'trust' / 'allowed_signers'
        self.fake.mark_synthetic = True
        self.assertEqual(self.outcome(app), ('REAL', 'FAILED'))  # a failed run stays counted (fail-closed)
        self.assertEqual(permits.used_runs(trust, permit['permit_id']), 1)
        # someone runs the harness directly, bypassing the app: it still counts, then refuses at the limit
        real = app.site.root / 'real'
        direct = lambda name: self.fake([os.sys.executable, '-B', 'tests/runtime/validate_s3t.py', '--evidence', str(self.root / name / 'ev'),
                                         '--expect', str(self.write_expect(permit)), '--permit', str(real / 'permit.json'),
                                         '--trust', str(trust), '--target-dir', str(app.site.root)], {})
        self.fake.mark_synthetic = False
        self.assertEqual(direct('d1'), 0)
        self.assertEqual(direct('d2'), 2)  # max_runs reached: refused before any container
        self.assertFalse((self.root / 'd2' / 'ev').exists())
        # the app sees the same count, also as a fresh process ("restart")
        again = App(app.data)
        again.setup()
        again.docker_found, again.real_runner = True, self.fake
        self.assertEqual(again.monitor().real().used(permit), 2)
        self.assertFalse(again.monitor().real().ready(utc_now()))
        self.assertEqual(again.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'REAL_NOT_READY')

    def write_expect(self, permit):
        f = self.root / ('expect-%d.json' % len(self.fake.calls))
        f.write_text(json.dumps(permits.derive_expect(permit)), encoding='utf-8')
        return f

    def test_a_permit_without_baseline_policy_never_creates_one(self):
        app = self.app()
        self.permit(app, baseline_policy='NONE')
        self.assertEqual(self.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))
        self.assertIsNone(app.site.real_registry())

    def test_synthetic_harness_output_is_refused_and_kept_apart(self):
        app = self.app()
        self.permit(app)
        self.fake.mark_synthetic = True
        self.assertEqual(self.outcome(app), ('REAL', 'FAILED'))
        self.assertEqual(app.site.real_runs(), [])
        self.assertTrue(any(p.name.endswith('-failed') for p in (app.site.root / 'real' / 'runs').iterdir()))

    # ---- CLOUDFLARE_ACCOUNT_CONTROL (synthetic account, Worker and subdomain; nothing here contacts Cloudflare)
    def cf_permit(self, app, *, worker=CF_WORKER, sub=CF_SUB, evidence=None, cloudflare=None, pin=None, write=True, **over):
        """The USER's record: the evidence file in real/, then a signed permit that pins it. Keyword overrides model a wrong record."""
        now = format_utc(utc_now())
        ev = {'schema': permits.CF_EVIDENCE_SCHEMA, 'evidence_id': 'cf-check-1', 'method': 'CLOUDFLARE_ACCOUNT_CONTROL', 'checked_at': now,
              'account_id_sha256': CF_ACCOUNT, 'worker': CF_WORKER, 'workers_dev_subdomain': CF_SUB, 'host': CF_HOST,
              'checks': {'worker_in_account': True, 'account_workers_dev_subdomain': CF_SUB}, 'sources': ['synthetic test record'],
              **(evidence or {})}
        real = app.site.root / 'real'
        real.mkdir(exist_ok=True)
        f = real / permits.OWNERSHIP_EVIDENCE
        f.unlink(missing_ok=True)
        raw = json.dumps(ev, ensure_ascii=False).encode('utf-8')
        if write:
            f.write_bytes(raw)
        own = {'method': 'CLOUDFLARE_ACCOUNT_CONTROL', 'verified_at': now,
               'cloudflare': cloudflare if cloudflare is not None else {'account_id_sha256': CF_ACCOUNT, 'worker': worker, 'workers_dev_subdomain': sub},
               'evidence': pin if pin is not None else {'evidence_id': 'cf-check-1', 'sha256': hashlib.sha256(raw).hexdigest()}}
        return self.permit(app, ownership={**own, **over})

    def owner_problems(self, app):
        checks = app.monitor().real().readiness(utc_now())
        return [c['key'] for c in checks if not c['ok']], next(c for c in checks if c['key'] == 'owner')['state']

    def test_cloudflare_account_control_accepts_only_the_matching_workers_dev_host(self):
        app = self.app(url=CF_URL)
        self.cf_permit(app)
        failing, state = self.owner_problems(app)
        self.assertEqual(failing, [], state)
        self.assertIn('CLOUDFLARE_ACCOUNT_CONTROL', state)
        f = app.site.root / 'real' / permits.OWNERSHIP_EVIDENCE
        cases = [
            ('other Worker', lambda: self.cf_permit(app, worker='other-worker')),
            ('other subdomain', lambda: self.cf_permit(app, sub='other-sub')),
            ('account hash only', lambda: self.cf_permit(app, cloudflare={'account_id_sha256': CF_ACCOUNT})),
            ('no account hash', lambda: self.cf_permit(app, cloudflare={'worker': CF_WORKER, 'workers_dev_subdomain': CF_SUB})),
            ('host spelled with a suffix', lambda: self.cf_permit(app, worker=CF_WORKER + '.' + CF_SUB, sub='workers')),
            ('no evidence pin', lambda: self.cf_permit(app, pin={})),
            ('no evidence file', lambda: self.cf_permit(app, write=False)),
            ('evidence of another account', lambda: self.cf_permit(app, evidence={'account_id_sha256': 'b' * 64})),
            ('evidence of another host', lambda: self.cf_permit(app, evidence={'host': 'other-worker.' + CF_SUB + '.workers.dev'})),
            ('evidence says the Worker is not in the account', lambda: self.cf_permit(app, evidence={'checks': {'worker_in_account': False, 'account_workers_dev_subdomain': CF_SUB}})),
            ('evidence of another check time', lambda: self.cf_permit(app, evidence={'checked_at': '2026-01-01T00:00:00Z'})),
            ('evidence with another id', lambda: self.cf_permit(app, evidence={'evidence_id': 'cf-check-2'})),
            ('check time in the future', lambda: self.cf_permit(app, verified_at=format_utc(utc_now() + timedelta(days=1)))),
            ('evidence edited after signing', lambda: (self.cf_permit(app), f.write_text(f.read_text('utf-8').replace(CF_SUB, 'other-sub'), encoding='utf-8'))),
        ]
        for name, make in cases:
            with self.subTest(name):
                make()
                failing, state = self.owner_problems(app)
                self.assertEqual(failing, ['owner'], state)  # only the ownership check fails: signature / scope / identity stay valid
                self.assertEqual(self.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))
        # the permit edited after signing (pointing it at another Worker): the signature no longer verifies
        self.cf_permit(app)
        p = app.site.root / 'real' / 'permit.json'
        p.write_text(p.read_text('utf-8').replace(f'"worker": "{CF_WORKER}"', '"worker": "other-worker"'), encoding='utf-8')
        self.assertIn('署名が正しくありません', app.monitor().real().permit()[1])
        # signed by a key nobody trusts
        self.cf_permit(app)
        self.permit(app, self.other_key, ownership=json.loads(p.read_text('utf-8'))['ownership'])
        self.assertIsNone(app.monitor().real().permit()[0])
        self.assertEqual(self.fake.calls, [])
        # the matching record reaches the harness and runs exactly as the other methods do
        self.cf_permit(app)
        self.assertEqual(self.outcome(app), ('REAL', 'BASELINE_CREATED'))

    def test_cloudflare_account_control_never_covers_a_custom_domain(self):
        for url in (SITE_URL, 'https://www.' + CF_HOST + '/', 'https://' + CF_WORKER + '.' + CF_SUB + '.workers.dev.example.com/'):
            with self.subTest(url):
                app = self.app(name='data-' + hashlib.sha256(url.encode()).hexdigest()[:8], url=url)
                host = url.split('/')[2]
                self.cf_permit(app, evidence={'host': host})
                self.assertEqual(self.owner_problems(app)[0], ['owner'])
                self.assertEqual(self.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))
        self.assertEqual(self.fake.calls, [])

    def test_the_harness_refuses_bad_ownership_evidence_before_any_docker_call(self):
        """The REAL validate_s3t.main() in permit mode; the Docker launcher is replaced by a stub that only records that it was reached."""
        from unittest import mock
        import tests.runtime.validate_s3t as harness

        class DockerReached(Exception):
            pass

        app = self.app(url=CF_URL)
        real, trust = app.site.root / 'real', app.data / 'trust' / 'allowed_signers'
        f = real / permits.OWNERSHIP_EVIDENCE

        def run(name):
            permit = json.loads((real / 'permit.json').read_text('utf-8'))
            expect = self.root / (name + '-expect.json')
            expect.write_text(json.dumps(permits.derive_expect(permit)), encoding='utf-8')
            evidence = self.root / 'harness' / name
            argv = ['validate_s3t.py', '--evidence', str(evidence), '--expect', str(expect), '--permit', str(real / 'permit.json'),
                    '--trust', str(trust), '--target-dir', str(app.site.root)]
            with mock.patch.object(harness, 'S2BLauncher', side_effect=DockerReached), mock.patch('sys.argv', argv):
                try:
                    harness.main()
                except DockerReached:
                    return 'DOCKER', json.loads((evidence / 'permit-preflight.json').read_text('utf-8'))['refused']
                except SystemExit as exc:
                    return exc.code, json.loads((evidence / 'permit-preflight.json').read_text('utf-8'))['refused']
            self.fail('the harness neither refused nor reached Docker')

        self.cf_permit(app)
        self.assertEqual(run('valid'), ('DOCKER', []))  # a matching record passes the preflight (and only then reaches the launcher)
        cases = [('evidence edited after signing', lambda: (self.cf_permit(app), f.write_text(f.read_text('utf-8').replace(CF_SUB, 'x-sub'), encoding='utf-8'))),
                 ('no evidence file', lambda: self.cf_permit(app, write=False)),
                 ('other Worker', lambda: self.cf_permit(app, worker='other-worker')),
                 ('account hash only', lambda: self.cf_permit(app, cloudflare={'account_id_sha256': CF_ACCOUNT})),
                 ('evidence of another account', lambda: self.cf_permit(app, evidence={'account_id_sha256': 'b' * 64})),
                 ('unsigned permit', lambda: (self.cf_permit(app), (real / 'permit.json.sig').unlink())),
                 ('untrusted key', lambda: self.permit(app, self.other_key, ownership=json.loads((real / 'permit.json').read_text('utf-8'))['ownership']))]
        for i, (name, make) in enumerate(cases):
            with self.subTest(name):
                make()
                code, refused = run(f'bad-{i}')
                self.assertEqual(code, 2)
                self.assertTrue(refused, name)
        for method in ('well-known-file', 'dns-txt'):  # the existing methods pass the preflight unchanged
            self.permit(app, ownership={'method': method, 'verified_at': format_utc(utc_now())})
            self.assertEqual(run(method), ('DOCKER', []))
        self.assertEqual(list((app.data / 'trust').glob('permit-ledger/*.jsonl')), [])  # nothing was counted: refused before the ledger

    def test_existing_ownership_methods_are_unchanged(self):
        for method in ('well-known-file', 'dns-txt'):
            for url in (SITE_URL, CF_URL):  # no evidence file and no Cloudflare record needed, on any host
                with self.subTest(method=method, url=url):
                    app = self.app(name=f'd-{method[:4]}-{"cf" if url == CF_URL else "site"}', url=url)  # short: the data folder must stay under the bundle path limit
                    self.permit(app, ownership={'method': method, 'verified_at': format_utc(utc_now())})
                    self.assertEqual(self.owner_problems(app)[0], [])
                    self.permit(app, ownership={'method': method})
                    self.assertEqual(self.owner_problems(app)[0], ['owner'])
        app = self.app(name='data-unknown')
        self.permit(app, ownership={'method': 'cloudflare-account-control', 'verified_at': format_utc(utc_now())})  # not an accepted spelling
        self.assertEqual(self.owner_problems(app)[0], ['owner'])

    def test_the_app_cannot_issue_a_permit(self):
        """No code under src/ signs, and no app route writes a permit or the trust file."""
        for f in (ROOT / 'src').rglob('*.py'):
            text = f.read_text('utf-8')
            self.assertNotIn("'-Y', 'sign'", text, f)
            self.assertNotIn('"-Y", "sign"', text, f)
        from src.noxiworks.app import SITE_ROUTES
        self.assertFalse([r for r in SITE_ROUTES if 'permit' in r or 'trust' in r])


class RunLedger(unittest.TestCase):
    """permit.reserve_run: atomic, persistent, refuses at max_runs, survives a crashed lock holder, never over-counts in parallel."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-ledger-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.trust = Path(tmp.name) / 'trust' / 'allowed_signers'
        self.permit = {'permit_id': 'p-ledger', 'max_runs': 3}

    def test_limit_and_persistence(self):
        for n in (1, 2, 3):
            self.assertEqual(permits.reserve_run(self.trust, self.permit, f'r{n}', 'now'), n)
        with self.assertRaises(permits.PermitRefused):
            permits.reserve_run(self.trust, self.permit, 'r4', 'now')
        self.assertEqual(permits.used_runs(self.trust, 'p-ledger'), 3)  # read back from disk, as after a restart

    def test_parallel_reservations_never_exceed_the_limit(self):
        import threading
        results = []

        def go(i):
            try:
                results.append(permits.reserve_run(self.trust, self.permit, f't{i}', 'now'))
            except permits.PermitRefused:
                results.append(None)
        threads = [threading.Thread(target=go, args=(i,)) for i in range(10)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(r for r in results if r), [1, 2, 3])
        self.assertEqual(permits.used_runs(self.trust, 'p-ledger'), 3)

    def test_a_held_lock_blocks_and_a_stale_one_is_taken_over(self):
        lock = permits.ledger_file(self.trust, 'p-ledger').with_suffix('.lock')
        lock.parent.mkdir(parents=True)
        lock.write_text('9999', encoding='utf-8')
        saved = permits.LOCK_WAIT_SECONDS
        permits.LOCK_WAIT_SECONDS = 0.3
        try:
            with self.assertRaises(permits.PermitRefused):
                permits.reserve_run(self.trust, self.permit, 'busy', 'now')
            old = lock.stat().st_mtime - permits.LOCK_STALE_SECONDS - 5
            os.utime(lock, (old, old))
            self.assertEqual(permits.reserve_run(self.trust, self.permit, 'after-crash', 'now'), 1)
        finally:
            permits.LOCK_WAIT_SECONDS = saved

    def test_an_unsafe_permit_id_is_refused(self):
        with self.assertRaises(permits.PermitRefused):
            permits.reserve_run(self.trust, {'permit_id': '../escape', 'max_runs': 9}, 'x', 'now')


class EngineOnly(unittest.TestCase):
    """Storage and disk limit of the monitoring engine itself (synthetic captures switched on explicitly)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-engine-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def app(self, name):
        app = App(self.root / name)
        app.fixture_capture = True
        app.setup()
        app.site_action('register', {'name': 'S', 'url': SITE_URL, 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True})
        return app

    def test_disk_limit_pauses_monitoring_and_deletes_nothing(self):
        app = self.app('disk')
        monitor = app.monitor()
        monitor.run(utc_now(), 'MANUAL')
        keep = lambda: sorted(p for p in app.site.root.rglob('*') if p.is_file() and p.name not in ('monitor.json', 'monitor-log.jsonl'))
        files = keep()
        settings = monitor.load()
        settings['disk_limit_bytes'] = 1
        monitor.save(settings)
        self.assertEqual(monitor.run(utc_now(), 'SCHEDULE')['outcome'], 'DISK_FULL')
        self.assertEqual((monitor.load()['enabled'], monitor.load()['paused_reason']), (False, 'DISK_FULL'))
        self.assertEqual(keep(), files)

    def test_offline_runs_keep_only_their_own_evidence(self):
        app = self.app('size')
        monitor = app.monitor()
        sizes = []
        for _ in range(4):
            run = app.site.root / 'runs' / monitor.run(utc_now(), 'MANUAL')['run_id']
            sizes.append(sum(f.stat().st_size for f in run.rglob('*') if f.is_file()))
        self.assertLess(max(sizes[1:]) - min(sizes[1:]), 2048, sizes)


class WorkerPermitMode(unittest.TestCase):
    """tests/runtime/s3t_worker in permit mode (the env the harness sets): only the pinned files of a top-page plan are accepted."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='siteproof-worker-', ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.saved = {k: os.environ.get(k) for k in ('SITEPROOF_TARGETS', 'SITEPROOF_CAPTURE_PLAN', 'SITEPROOF_TARGET_ID',
                                                       'SITEPROOF_TARGET_SHA256', 'SITEPROOF_PLAN_SHA256')}
        self.addCleanup(self.restore)

    def restore(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import tests.runtime.s3t_worker as w
        importlib.reload(w)

    def worker(self, path='/', tamper=False):
        from src.noxiworks.site_workflow import Site
        site = Site.register(self.root, 'S', 'https://my-site.com' + path, ['Desktop', 'Mobile'], True, utc_now())
        targets, plan = site.root / 'targets.json', site.root / 'capture_plan.json'
        os.environ.update(SITEPROOF_TARGETS=str(targets), SITEPROOF_CAPTURE_PLAN=str(plan), SITEPROOF_TARGET_ID=site.page_id,
                          SITEPROOF_TARGET_SHA256=sha(targets), SITEPROOF_PLAN_SHA256=sha(plan))
        if tamper:
            targets.write_bytes(targets.read_bytes().replace(b'my-site.com', b'other-site.com'))
        import tests.runtime.s3t_worker as w
        return importlib.reload(w), site

    def test_pinned_top_page_plan_accepted(self):
        w, site = self.worker()
        entry = w.checked_plan()
        self.assertEqual((w.TARGET_ID, entry['url']), (site.page_id, SITE_URL))

    def test_changed_target_file_refused(self):
        w, _ = self.worker(tamper=True)
        with self.assertRaises(w.PlanRefused):
            w.checked_plan()

    def test_not_a_top_page_refused(self):
        w, _ = self.worker(path='/shop')
        with self.assertRaises(w.PlanRefused):
            w.checked_plan()


if __name__ == '__main__':
    unittest.main()

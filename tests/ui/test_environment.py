"""導入環境の確認 (src/noxiworks/environment.py, tools/doctor.py, App.environment, GET /app/api/environment). Offline: every probe is a fake, so no Docker command,
no Windows task query, no network and no key is touched; the report writes nothing."""
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import backup, environment
from src.noxiworks.app import App, serve
from src.noxiworks.site_workflow import Site
from tools import doctor

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
PINNED = 'sha256:' + 'ab' * 32


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


def fakes(**over):
    base = {'python': lambda: ((3, 15, 1), 'C:\\py\\python.exe'), 'ssh_keygen': lambda: 'C:\\ssh\\ssh-keygen.exe', 'docker_cli': lambda: 'C:\\d\\docker.exe',
            'docker_engine': lambda: True, 'pinned_image': lambda: PINNED, 'docker_image': lambda pinned: pinned, 'background': lambda data, site, channel: True,
            'path_problem': lambda data: None, 'free_bytes': lambda path: 50 << 30, 'writable': lambda path: True, 'now': lambda: NOW,
            'switches': lambda: {'http': False, 'mail': False, 'dns': False}}
    return {**base, **over}


def forbidden(name):
    def call(*args):
        raise AssertionError(name + ' must not be asked')
    return call


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-env-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'trust').mkdir(parents=True)
        (self.data / 'trust' / 'allowed_signers').write_text('site-owner ssh-ed25519 AAAA', encoding='utf-8')
        self.a = Site.register(self.data / 'sites', 'A', 'https://my-site.com/', ['Desktop'], True, NOW)

    def report(self, docker=True, data=None, **over):
        result = environment.report(data or self.data, fakes(**over), docker=docker)
        return result, {i['key']: i for i in result['items']}


class Items(Base):
    def test_a_complete_pc_is_all_ok_and_nothing_is_written(self):
        before = tree(self.data)
        backups = self.tmp / 'data-backups'
        backups.mkdir()
        (backups / 'siteproof-backup-20261124T120000Z').mkdir()
        (backups / 'siteproof-backup-20261124T120000Z' / 'MANIFEST.json').write_text(json.dumps({'created_at': '2026-11-24T12:00:00Z'}), encoding='utf-8')
        dirs, inside = sorted(p.name for p in self.tmp.iterdir()), tree(backups)
        result, items = self.report()
        self.assertEqual(result['schema'], 'siteproof.environment.v1')
        self.assertEqual(result['checked_at'], '2026-11-25T12:00:00Z')
        self.assertEqual({i['status'] for i in result['items']}, {'OK'})
        for key in ('python', 'ssh_keygen', 'docker_cli', 'docker_engine', 'docker_image', 'data_folder', 'data_space', 'data_path_length', 'data_path_ascii', 'trust', 'sites', 'backup',
                    'switch_http', 'switch_mail', 'switch_dns', f'background:{self.a.root.name}:image', f'background:{self.a.root.name}:http'):
            self.assertIn(key, items)
        self.assertEqual(result['counts'], {'OK': len(result['items']), 'MISSING': 0, 'WARN': 0, 'UNKNOWN': 0})
        self.assertIn('1日前', items['backup']['detail'])
        self.assertEqual(tree(self.data), before)
        self.assertEqual((sorted(p.name for p in self.tmp.iterdir()), tree(backups)), (dirs, inside))  # no folder was made, nothing was written

    def test_every_missing_or_warning_item_says_what_to_do_and_an_ok_one_does_not(self):
        shutil.rmtree(self.data / 'trust')
        result, _ = self.report(python=lambda: ((3, 11, 0), 'x'), ssh_keygen=lambda: None, docker_cli=lambda: None, free_bytes=lambda p: 1 << 20, writable=lambda p: False,
                                path_problem=lambda d: '長すぎます', background=lambda d, s, c: False)
        bad = [i for i in result['items'] if i['status'] in ('MISSING', 'WARN')]
        self.assertGreaterEqual(len(bad), 8)
        for i in bad:
            self.assertTrue(i['next'].strip(), i['key'])
        for i in result['items']:
            if i['status'] in ('OK', 'UNKNOWN'):
                self.assertEqual(i['next'], '', i['key'])

    def test_python_and_openssh(self):
        _, items = self.report(python=lambda: ((3, 11, 9), 'C:\\old\\python.exe'))
        self.assertEqual(items['python']['status'], 'MISSING')
        self.assertIn('C:\\old\\python.exe', items['python']['detail'])
        _, items = self.report(python=forbidden_python)
        self.assertEqual(items['python']['status'], 'UNKNOWN')
        _, items = self.report(ssh_keygen=lambda: None)
        self.assertEqual(items['ssh_keygen']['status'], 'MISSING')
        _, items = self.report(ssh_keygen=forbidden('ssh'))
        self.assertEqual(items['ssh_keygen']['status'], 'UNKNOWN')

    def test_docker_in_its_four_states(self):
        _, items = self.report(docker_cli=lambda: None, docker_engine=forbidden('engine'), docker_image=forbidden('image'))
        self.assertEqual([items[k]['status'] for k in ('docker_cli', 'docker_engine', 'docker_image')], ['MISSING', 'UNKNOWN', 'UNKNOWN'])
        _, items = self.report(docker_engine=lambda: False, docker_image=forbidden('image'))
        self.assertEqual([items[k]['status'] for k in ('docker_engine', 'docker_image')], ['MISSING', 'UNKNOWN'])
        self.assertIn('起動', items['docker_engine']['next'])
        _, items = self.report(docker_image=lambda pinned: '')
        self.assertEqual(items['docker_image']['status'], 'MISSING')
        self.assertIn('INSTALL.md', items['docker_image']['next'])
        self.assertIn('取得・ビルドをしません', items['docker_image']['next'])
        _, items = self.report(docker_image=lambda pinned: 'sha256:' + 'cd' * 32)
        self.assertEqual(items['docker_image']['status'], 'WARN')
        self.assertIn('使いません', items['docker_image']['detail'])
        _, items = self.report(docker_image=lambda pinned: None)
        self.assertEqual(items['docker_image']['status'], 'UNKNOWN')
        asked = []
        _, items = self.report(docker_image=lambda pinned: asked.append(pinned) or pinned)
        self.assertEqual((items['docker_image']['status'], asked), ('OK', [PINNED]))  # exactly the pinned ID is asked for

    def test_no_docker_asks_none_of_the_docker_probes(self):
        _, items = self.report(docker=False, docker_cli=forbidden('cli'), docker_engine=forbidden('engine'), pinned_image=forbidden('pinned'), docker_image=forbidden('image'))
        self.assertEqual([items[k]['status'] for k in ('docker_cli', 'docker_engine', 'docker_image')], ['UNKNOWN'] * 3)
        self.assertIn('--no-docker', items['docker_engine']['detail'])

    def test_the_data_folder(self):
        _, items = self.report(data=self.tmp / 'new-place')
        self.assertEqual((items['data_folder']['status'], items['sites']['status'], items['trust']['status']), ('MISSING', 'MISSING', 'MISSING'))
        self.assertFalse((self.tmp / 'new-place').exists())  # asking never creates it
        _, items = self.report(writable=lambda p: False)
        self.assertEqual(items['data_folder']['status'], 'WARN')
        _, items = self.report(free_bytes=lambda p: 500 << 20)
        self.assertEqual(items['data_space']['status'], 'WARN')
        self.assertIn('0.5 GB', items['data_space']['detail'])
        _, items = self.report(free_bytes=forbidden('free'))
        self.assertEqual(items['data_space']['status'], 'UNKNOWN')
        _, items = self.report(path_problem=lambda d: '証拠の保存先のパスが長すぎます（最長のファイルで271文字、上限240文字）')
        self.assertEqual(items['data_path_length']['status'], 'WARN')
        self.assertIn('240', items['data_path_length']['detail'])
        self.assertIn('C:\\spe', items['data_path_length']['next'])
        _, items = self.report(path_problem=forbidden('length'))
        self.assertEqual(items['data_path_length']['status'], 'UNKNOWN')

    def test_the_real_path_length_arithmetic_is_used_without_docker(self):
        deep = self.tmp / ('d' * 120) / ('e' * 100)
        result = environment.default_probes()['path_problem'](deep)
        self.assertIn('長すぎます', result or '')
        self.assertIsNone(environment.default_probes()['path_problem'](Path('C:/spe') if Path('C:/').exists() else self.tmp))

    def test_a_japanese_path_is_a_warning_with_the_truth_about_what_is_not_measured(self):
        jp = self.tmp / 'データ フォルダ'
        jp.mkdir()
        _, items = self.report(data=jp)
        self.assertEqual(items['data_path_ascii']['status'], 'WARN')
        self.assertIn('未検証', items['data_path_ascii']['detail'])
        self.assertIn('英数字', items['data_path_ascii']['next'])
        self.assertEqual(self.report()[1]['data_path_ascii']['status'], 'OK')

    def test_sites_folders_that_are_not_used_and_the_background_tasks(self):
        broken = self.data / 'sites' / 'site-deadbeef'
        broken.mkdir()
        (broken / 'site.json').write_text(json.dumps({'site_id': 'site-00000000'}), encoding='utf-8')
        asked = []

        def background(data, site, channel):
            asked.append((Path(data), site, channel))
            return {'image': True, 'http': False}[channel]
        result, items = self.report(background=background)
        self.assertEqual(items['sites']['status'], 'OK')
        self.assertEqual(items['site_folders']['status'], 'WARN')
        self.assertIn('site-deadbeef', items['site_folders']['detail'])
        site = self.a.root.name
        self.assertEqual((items[f'background:{site}:image']['status'], items[f'background:{site}:http']['status']), ('OK', 'MISSING'))
        self.assertIn('アプリを閉じても', items[f'background:{site}:http']['next'])
        self.assertEqual(sorted(asked), [(self.data, site, 'http'), (self.data, site, 'image')])  # per site and channel, only the registered sites
        _, items = self.report(background=lambda d, s, c: None)
        self.assertEqual(items[f'background:{site}:image']['status'], 'UNKNOWN')
        _, items = self.report(background=forbidden('schtasks'))
        self.assertEqual(items[f'background:{site}:image']['status'], 'UNKNOWN')

    def test_two_sites_each_with_both_channels(self):
        Site.register(self.data / 'sites', 'B', 'https://other-site.com/', ['Desktop'], True, NOW + timedelta(seconds=1))
        result, items = self.report()
        self.assertEqual(len([k for k in items if k.startswith('background:')]), 4)
        self.assertIn('2サイト', items['sites']['detail'])

    def test_the_last_backup_and_its_age(self):
        kept = self.tmp / 'data-backups'
        _, items = self.report()
        self.assertEqual(items['backup']['status'], 'MISSING')
        self.assertIn('バックアップ', items['backup']['next'])
        kept.mkdir()
        old = backup.create(self.data, kept, NOW - timedelta(days=30))
        _, items = self.report()
        self.assertEqual(items['backup']['status'], 'WARN')
        self.assertIn('30日前', items['backup']['detail'])
        self.assertIn('siteproof-backup-20261026T120000Z', items['backup']['detail'])
        fresh = backup.create(self.data, kept, NOW - timedelta(hours=5))
        _, items = self.report()
        self.assertEqual(items['backup']['status'], 'OK')
        self.assertIn('siteproof-backup-20261125T070000Z', items['backup']['detail'])
        self.assertIn('照合はここでは行いません', items['backup']['detail'])

    def test_the_external_switches_are_facts_not_errors(self):
        _, items = self.report()
        for key in ('switch_http', 'switch_mail', 'switch_dns'):
            self.assertEqual(items[key]['status'], 'OK')
            self.assertTrue(items[key]['detail'].startswith('無効'), items[key]['detail'])
        _, items = self.report(switches=lambda: {'http': True, 'mail': False, 'dns': True})
        self.assertTrue(items['switch_http']['detail'].startswith('有効'))
        self.assertTrue(items['switch_mail']['detail'].startswith('無効'))
        self.assertTrue(items['switch_dns']['detail'].startswith('有効'))
        self.assertEqual({items[k]['status'] for k in ('switch_http', 'switch_mail', 'switch_dns')}, {'OK'})
        _, items = self.report(switches=forbidden('switches'))
        self.assertEqual(items['switch_http']['status'], 'UNKNOWN')

    def test_the_real_switches_read_the_source_values(self):
        from src.noxiworks import http_monitor, smtp_notify
        from tools import dns_ownership
        self.assertEqual(environment.switches(), {'http': http_monitor.HTTP_EXTERNAL_ENABLED is True, 'mail': smtp_notify.NOTIFY_EXTERNAL_ENABLED is True,
                                                  'dns': dns_ownership.OWNERSHIP_DNS_ENABLED is True})
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True):
            self.assertTrue(environment.switches()['http'])

    def test_the_real_default_probes_exist_for_every_key_the_report_asks_for(self):
        real = environment.default_probes()
        self.assertEqual(set(real), set(fakes()))


def forbidden_python():
    raise RuntimeError('no')


class Doctor(Base):
    def test_text_output_lists_every_item_with_its_next_step_and_summarises(self):
        out = []
        self.assertEqual(doctor.main(['--data', str(self.data), '--no-docker'], probes=fakes(), out=out.append), 0)
        text = '\n'.join(out)
        self.assertIn('読み取りだけ', text)
        self.assertIn('[OK     ] Python', text)
        self.assertIn('[不明   ] Docker CLI', text)
        self.assertIn('まとめ：OK', text)
        self.assertEqual(out[-1].split('：')[0], 'まとめ')

    def test_json_output_and_a_missing_item_with_its_next_step(self):
        shutil.rmtree(self.data / 'trust')
        out = []
        self.assertEqual(doctor.main(['--data', str(self.data), '--json'], probes=fakes(), out=out.append), 0)
        parsed = json.loads('\n'.join(out))
        self.assertEqual(parsed['counts']['MISSING'], 2)  # the trust file and the backup
        trust = next(i for i in parsed['items'] if i['key'] == 'trust')
        self.assertEqual(trust['status'], 'MISSING')
        self.assertIn('allowed_signers', trust['next'])
        out = []
        doctor.main(['--data', str(self.data)], probes=fakes(), out=out.append)
        self.assertTrue(any('次にすること' in line for line in out))

    def test_it_runs_as_a_program_without_docker(self):
        import subprocess
        import sys
        p = subprocess.run([sys.executable, '-B', str(Path(doctor.__file__)), '--data', str(self.tmp / 'nothing-here'), '--no-docker', '--json'], capture_output=True, timeout=120,
                           env={**__import__('os').environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'})
        self.assertEqual(p.returncode, 0, p.stderr[-400:])
        parsed = json.loads(p.stdout.decode('utf-8'))
        self.assertEqual(next(i for i in parsed['items'] if i['key'] == 'docker_engine')['status'], 'UNKNOWN')
        self.assertFalse((self.tmp / 'nothing-here').exists())


class InTheApp(Base):
    def make(self):
        app = App(self.data)
        app.docker_found = False
        app.background_query = mock.MagicMock(return_value=False)
        return app

    def test_the_app_asks_the_injected_fakes_only_and_caches_for_a_minute(self):
        app = self.make()
        first = app.environment()
        self.assertEqual(app.environment(), first)
        self.assertIs(app.environment(), first)
        items = {i['key']: i for i in first['items']}
        self.assertEqual(items['docker_engine']['status'], 'MISSING')  # injected: Docker does not answer
        self.assertEqual(items['docker_image']['status'], 'UNKNOWN')
        self.assertEqual(items[f'background:{self.a.root.name}:image']['status'], 'MISSING')
        self.assertEqual(app.background_query.call_count, 2)  # not asked again while cached
        with mock.patch('time.monotonic', return_value=__import__('time').monotonic() + 61):
            self.assertIsNot(app.environment(), first)
        app.docker_found = True
        app._environment = None
        items = {i['key']: i for i in app.environment()['items']}
        self.assertEqual((items['docker_cli']['status'], items['docker_engine']['status'], items['docker_image']['status']), ('OK', 'OK', 'OK'))

    def test_the_route_has_the_same_guards_as_the_session(self):
        server, app = serve(self.tmp / 'served', 0, scheduler=False)
        app.docker_found = False
        app.background_query = lambda data, site, channel: False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(app.stop)
        port = server.server_address[1]

        def call(path='/app/api/environment', headers=None, host=None):
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=120)
            c.request('GET', path, headers={'Host': host or f'127.0.0.1:{port}', **(headers or {})})
            r = c.getresponse()
            return r.status, r.read()
        self.assertEqual(call()[0], 403)  # no app header
        self.assertEqual(call(headers={'X-SiteProof-App': '1', 'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(call(headers={'X-SiteProof-App': '1'}, host='evil.invalid')[0], 421)
        status, raw = call(headers={'X-SiteProof-App': '1'})
        self.assertEqual(status, 200)
        parsed = json.loads(raw)
        self.assertEqual(parsed['schema'], 'siteproof.environment.v1')
        self.assertIn('python', {i['key'] for i in parsed['items']})
        self.assertNotIn('token', parsed)


if __name__ == '__main__':
    unittest.main()

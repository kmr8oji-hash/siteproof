"""Who may be checked over HTTP, offline: signed grant v2 (SYNTHETIC keys), ownership evidence, the request ledger, pages. The isolated run itself:
tests/ui/test_http_isolation.py. No network, no Docker.
"""
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import filelock, http_authority, http_monitor, sites
from src.noxiworks import permit as permits
from src.noxiworks.http_monitor import HttpMonitor
from src.noxiworks.site_workflow import Site
from tests.ui.test_real_capture import CF_ACCOUNT, CF_HOST, CF_SUB, CF_URL, CF_WORKER, keypair, needs_ssh
from tools import http_grant

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return NOW + timedelta(seconds=seconds)


def evidence(site_root, checked_at, host=CF_HOST, worker=CF_WORKER, sub=CF_SUB):
    f = Path(site_root) / 'real' / permits.OWNERSHIP_EVIDENCE
    f.parent.mkdir(exist_ok=True)
    f.write_text(json.dumps({'schema': permits.CF_EVIDENCE_SCHEMA, 'evidence_id': 'ev-1', 'method': 'CLOUDFLARE_ACCOUNT_CONTROL', 'account_id_sha256': CF_ACCOUNT,
                             'worker': worker, 'workers_dev_subdomain': sub, 'host': host, 'checked_at': checked_at,
                             'checks': {'worker_in_account': True, 'account_workers_dev_subdomain': sub}}), encoding='utf-8')
    return f


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-boundary-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.site = Site.register(self.data / 'sites', 'S', CF_URL, ['Desktop'], True, NOW)
        http_monitor._GRANT_CACHE.clear()

    def keys(self):
        folder = self.tmp / 'keys'
        folder.mkdir(exist_ok=True)
        self.key = keypair(folder, 'user')
        pub = (folder / 'user.pub').read_text('utf-8').split()
        (self.data / 'trust').mkdir(exist_ok=True)
        (self.data / 'trust' / 'allowed_signers').write_text(f'site-owner namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='ascii')
        return self.key

    def ownership(self, root=None, checked=None, **kw):
        from tools import permit_draft
        root = root or self.site.root
        evidence(root, format_utc(checked or NOW - timedelta(days=1)), **kw)
        return permit_draft.cloudflare_ownership(root, json.loads((root / 'site.json').read_text('utf-8')), NOW)

    def grant(self, **over):
        return {'schema': http_authority.GRANT_SCHEMA, 'grant_id': 'http-g1', 'issued_by': 'site-owner', 'issued_at': format_utc(NOW), 'site_id': self.site.info['site_id'],
                'host': CF_HOST, 'port': 443, 'path': '/', 'method': 'GET', 'purpose': 'MONITOR', 'valid_from': format_utc(at(-3600)), 'valid_until': format_utc(at(86400)),
                'min_interval_seconds': 300, 'max_requests': 3, **over, 'ownership': over['ownership'] if 'ownership' in over else self.ownership()}

    def sign(self, body, root=None):
        f = (root or self.site.root) / 'http-grant.json'
        f.with_name('http-grant.json.sig').unlink(missing_ok=True)
        f.write_text(json.dumps(body), encoding='utf-8')
        subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(self.key), str(f)], check=True, capture_output=True)

    def refused(self, when=NOW, root=None, **kw):
        with self.assertRaises(http_authority.Refused) as caught:
            http_authority.authorize(root or self.site.root, when, **kw)
        return caught.exception

    def problems(self, interval=900):
        http_monitor._GRANT_CACHE.clear()
        return HttpMonitor(self.site, probe=lambda *a: None).grant_problems(NOW, interval)

    def ledger(self):
        return http_authority.ledger_file(self.site.root)


@needs_ssh
class Grant(Base):
    def test_a_valid_grant_authorises_exactly_the_registered_page(self):
        self.keys()
        self.assertEqual(self.refused().code, 'GRANT_INVALID')  # none yet
        self.sign(self.grant())
        self.assertEqual(self.problems(), [])
        allowed = http_authority.authorize(self.site.root, NOW, 'SCHEDULE', 900)
        self.assertEqual((allowed['host'], allowed['path'], allowed['used'], allowed['reserved_at']), (CF_HOST, '/', 1, format_utc(NOW)))

    def test_each_deviation_is_refused_even_though_it_is_signed(self):
        self.keys()
        day = timedelta(days=1)
        for label, over, text in (
                ('host', {'host': 'other.my-sub.workers.dev'}, '許可された対象'), ('path', {'path': '/x'}, '許可された対象'), ('site', {'site_id': 'site-00000000'}, '許可された対象'),
                ('port', {'port': 80}, '443'), ('port type', {'port': '443'}, '443'), ('method', {'method': 'POST'}, 'GET'), ('purpose', {'purpose': 'ANY'}, '目的'),
                ('expired', {'valid_until': format_utc(NOW)}, '有効期間外'), ('not yet', {'valid_from': format_utc(at(60))}, '有効期間外'),
                ('too long', {'valid_until': format_utc(NOW + 400 * day)}, '期間が長すぎる'), ('no period', {'valid_until': None}, '期間が不正'),
                ('reversed', {'valid_from': format_utc(NOW + day), 'valid_until': format_utc(NOW - day)}, '不正'),
                ('interval', {'min_interval_seconds': 1800}, '最短の間隔より短い'), ('interval too short', {'min_interval_seconds': 60}, '最短の間隔が不正'),
                ('interval bool', {'min_interval_seconds': True}, '最短の間隔が不正'), ('no limit', {'max_requests': None}, '回数が不正'), ('unlimited', {'max_requests': 10 ** 9}, '回数が不正'),
                ('zero', {'max_requests': 0}, '回数が不正'), ('id', {'grant_id': 'g1'}, 'IDが不正'), ('extra key', {'allow': '*'}, '項目が不正'),
                ('trial too long', {'purpose': 'LIMITED_TRIAL', 'valid_until': format_utc(NOW + 2 * day)}, '期間が長すぎる'),
                ('trial too many', {'purpose': 'LIMITED_TRIAL', 'valid_from': format_utc(NOW), 'valid_until': format_utc(at(3600)), 'max_requests': 21}, '回数が不正')):
            with self.subTest(label):
                self.sign(self.grant(**over))
                self.assertIn(text, ' '.join(self.problems()), label)
                self.refused(interval=900)
        self.assertEqual(http_authority.entries(self.site.root), [])  # a refusal is never counted

    def test_tampering_a_foreign_key_and_an_image_permit_are_refused(self):
        self.keys()
        self.sign(self.grant())
        f = self.site.root / 'http-grant.json'
        f.write_text(f.read_text('utf-8').replace('"max_requests": 3', '"max_requests": 9'), encoding='utf-8')
        self.assertIn('署名', self.refused().message)
        self.sign({**self.grant(), 'schema': permits.SCHEMA})
        self.assertIn('画像撮影の許可は使えません', self.refused().message)
        self.sign({**self.grant(), 'schema': 'siteproof.http-grant.v1'})
        self.assertIn('古い形式', self.refused().message)
        self.key = keypair(self.tmp / 'keys', 'stranger')
        self.sign(self.grant())
        self.assertIn('署名', self.refused().message)
        for name in ('http-grant.json', 'http-grant.json.sig'):  # and a valid HTTP grant is no image permit
            (self.site.root / 'real').mkdir(exist_ok=True)
            shutil.copy2(self.site.root / name, self.site.root / 'real' / name.replace('http-grant', 'permit'))
        from src.noxiworks.real_capture import RealCapture
        self.assertFalse(all(c['ok'] for c in RealCapture(self.site, docker_found=True).readiness(NOW)))

    def test_ownership_evidence_is_required_pinned_and_recent(self):
        self.keys()
        for label, own in (('none', None), ('declared only', {'method': 'well-known-file', 'verified_at': format_utc(NOW)}), ('no evidence pin', {**self.ownership(), 'evidence': {}})):
            with self.subTest(label):
                self.sign(self.grant(ownership=own))
                self.assertIn('所有権', self.refused().message)
        self.sign(self.grant())
        http_authority.authorize(self.site.root, at(0))  # as it should be
        evidence(self.site.root, format_utc(NOW))  # another evidence file than the pinned one
        self.assertIn('所有権', self.refused().message)
        self.sign(self.grant(ownership=self.ownership(checked=NOW - timedelta(days=91))))
        self.assertIn('古くなっています', self.refused().message)
        (self.site.root / 'real' / permits.OWNERSHIP_EVIDENCE).unlink()
        self.assertIn('所有権', self.refused().message)

    def test_one_sites_grant_is_useless_for_another_site(self):
        self.keys()
        self.sign(self.grant())
        other = Site.register(self.data / 'sites', 'Other', 'https://second.my-sub.workers.dev/', ['Desktop'], True, NOW)
        for name in ('http-grant.json', 'http-grant.json.sig'):
            shutil.copy2(self.site.root / name, other.root / name)
        shutil.copytree(self.site.root / 'real', other.root / 'real')
        self.assertIn('許可された対象', self.refused(root=other.root).message)
        copied = self.data / 'sites' / 'site-00000000'  # a renamed copy of a whole, validly granted site folder
        shutil.copytree(self.site.root, copied)
        self.assertEqual(self.refused(root=copied).code, 'TARGET')
        self.assertEqual([p.name for p in sites.folders(self.data)], sorted([self.site.root.name, other.root.name], key=lambda n: n))
        self.assertEqual([n for n, _ in sites.scan(self.data)[1]], ['site-00000000'])

    def test_expiry_is_decided_at_the_request(self):
        self.keys()
        self.sign(self.grant())
        self.assertEqual(self.refused(at(86400)).code, 'GRANT_EXPIRED')
        self.assertEqual(http_authority.authorize(self.site.root, at(86399))['used'], 1)


@needs_ssh
class Ledger(Base):
    def setUp(self):
        super().setUp()
        self.keys()
        self.sign(self.grant())

    def test_count_and_frequency_hold_for_manual_and_scheduled_checks_together(self):
        http_authority.authorize(self.site.root, at(0), 'SCHEDULE', 900)
        early = self.refused(at(299), trigger='MANUAL')
        self.assertEqual((early.code, early.not_before), ('RATE_LIMITED', format_utc(at(300))))
        http_authority.authorize(self.site.root, at(300), 'MANUAL')
        http_authority.authorize(self.site.root, at(600), 'SCHEDULE', 300)
        done = self.refused(at(6000), trigger='MANUAL')
        self.assertEqual((done.code, '3 / 3' in done.message), ('GRANT_EXHAUSTED', True))
        view = HttpMonitor(self.site, probe=lambda *a: None).grant_view(at(6000), 900)
        self.assertEqual((view['state'], view['valid'], view['used'], view['remaining']), ('EXHAUSTED', False, 3, 0))

    def test_a_renewed_grant_starts_a_new_count_but_not_a_new_interval(self):
        http_authority.authorize(self.site.root, at(0))
        self.sign(self.grant(grant_id='http-g2'))
        self.assertEqual(self.refused(at(10)).code, 'RATE_LIMITED')
        self.assertEqual(http_authority.authorize(self.site.root, at(300))['used'], 1)

    def test_a_clock_that_went_back_an_unreadable_line_and_another_sites_line_refuse(self):
        http_authority.authorize(self.site.root, at(1000))
        self.assertEqual(self.refused(at(0)).code, 'RATE_LIMITED')
        text = self.ledger().read_text('utf-8')
        for bad in (text + '{"torn', text + '\n\n{}\n', text.replace(self.site.root.name, 'site-00000000')):
            self.ledger().write_text(bad, encoding='utf-8')
            with self.subTest(bad[-20:]):
                self.assertEqual(self.refused(at(5000)).code, 'LEDGER')
                self.assertTrue(self.problems())

    def test_two_processes_cannot_both_take_the_same_turn(self):
        results = []

        def go():
            try:
                results.append(http_authority.authorize(self.site.root, at(0))['used'])
            except http_authority.Refused as exc:
                results.append(exc.code)
        threads = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(map(str, results)), ['1'] + ['RATE_LIMITED'] * 5)
        self.assertEqual(len(http_authority.entries(self.site.root)), 1)

    def test_a_ledger_that_stays_locked_refuses(self):
        self.ledger().parent.mkdir(parents=True, exist_ok=True)
        with filelock.held(self.ledger().with_suffix('.lock')), mock.patch.object(http_authority, 'LEDGER_LOCK_WAIT', 0.1):
            self.assertEqual(self.refused().code, 'LEDGER')


@needs_ssh
class Pages(Base):
    """A further page of the same host is a unit of its own: its own grant, ledger and count."""

    def page(self, path='/status', n=2):
        root = self.site.root / 'pages' / f'{self.site.root.name}-p{n}'
        root.mkdir(parents=True)
        (root / 'site.json').write_text(json.dumps({**self.site.info, 'page_id': root.name, 'url': self.site.info['origin'] + path}), encoding='utf-8')
        return root

    def test_the_sites_grant_never_covers_a_page_and_each_page_counts_for_itself(self):
        self.keys()
        self.sign(self.grant())
        page = self.page()
        self.assertEqual(self.refused(root=page).code, 'GRANT_INVALID')  # none of its own
        for name in ('http-grant.json', 'http-grant.json.sig'):
            shutil.copy2(self.site.root / name, page / name)
        self.assertIn('許可された対象', self.refused(root=page).message)  # the first page's grant names another path
        self.sign(self.grant(path='/status', grant_id='http-p2'), root=page)
        allowed = http_authority.authorize(page, NOW)
        self.assertEqual((allowed['host'], allowed['path']), (CF_HOST, '/status'))
        self.assertEqual(http_authority.authorize(self.site.root, NOW)['path'], '/')  # the first page's interval is its own
        self.assertEqual(sorted(f.name for f in (self.data / 'trust' / 'http-ledger').glob('*.jsonl')), [self.site.root.name + '-p2.jsonl', self.site.root.name + '.jsonl'])
        self.assertEqual(self.refused(root=page).code, 'RATE_LIMITED')

    def test_the_ownership_evidence_is_the_sites(self):
        self.keys()
        page = self.page()
        self.sign(self.grant(path='/status'), root=page)
        (self.site.root / 'real' / permits.OWNERSHIP_EVIDENCE).unlink()
        self.assertIn('所有権', self.refused(root=page).message)

    def test_a_moved_copied_or_foreign_page_folder_is_not_a_page(self):
        self.keys()
        page = self.page()
        self.sign(self.grant(path='/status'), root=page)
        other = Site.register(self.data / 'sites', 'Other', 'https://second.my-sub.workers.dev/', ['Desktop'], True, NOW)
        moved = other.root / 'pages' / page.name
        shutil.copytree(page, moved)
        renamed = self.site.root / 'pages' / (self.site.root.name + '-p3')
        shutil.copytree(page, renamed)
        for root in (moved, renamed):
            self.assertEqual(self.refused(root=root).code, 'TARGET', root)
        info = json.loads((page / 'site.json').read_text('utf-8'))
        for url in ('https://evil.example/status', self.site.info['url'], CF_URL.rstrip('/') + '.evil.example/'):
            (page / 'site.json').write_text(json.dumps({**info, 'url': url}), encoding='utf-8')
            self.assertEqual(self.refused(root=page).code, 'TARGET', url)
        self.assertEqual([p for p, _ in sites.pages(self.site.root)[1]], [page.name, renamed.name])
        self.assertEqual(sites.units(self.site.root), [self.site.root])


@needs_ssh
class Tool(Base):
    def call(self, *argv):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            return http_grant.main(['--data', str(self.data), '--key', str(self.key), '--yes', *argv]), out.getvalue()

    def real_now_evidence(self):
        evidence(self.site.root, format_utc(datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)))

    def test_it_signs_what_verifies_keeps_the_old_grant_and_starts_nothing(self):
        self.keys()
        code, text = self.call()
        self.assertEqual(code, 1)  # no ownership evidence: nothing is signed
        self.assertIn('所有権', text)
        self.assertFalse((self.site.root / 'http-grant.json').exists())
        self.real_now_evidence()
        self.assertEqual(self.call('--days', '3', '--min-interval', '900')[0], 0)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        grant, why = http_authority.read_grant(self.site.root)
        self.assertEqual(http_authority.grant_problems(grant, self.site.info, self.site.root, now, 900), [])
        self.assertTrue(http_authority.grant_problems(grant, self.site.info, self.site.root, now, 300))  # 5 minutes is shorter than granted
        self.assertEqual((grant['purpose'], grant['max_requests']), ('MONITOR', 317))
        first = grant['grant_id']
        time.sleep(1.1)
        self.assertEqual(self.call('--trial', '--hours', '2')[0], 0)
        trial, _ = http_authority.read_grant(self.site.root)
        self.assertEqual((trial['purpose'], trial['max_requests'], trial['min_interval_seconds']), ('LIMITED_TRIAL', 5, 60))
        self.assertEqual(trial['valid_until'], format_utc(datetime.fromisoformat(trial['valid_from'].replace('Z', '+00:00')) + timedelta(hours=2)))
        self.assertTrue((self.site.root / 'http-grant-history' / first / 'http-grant.json').is_file())
        for name in ('http-monitor.json', 'monitor.json'):
            self.assertFalse((self.site.root / name).exists())

    def test_it_refuses_an_untrusted_key_unusable_values_and_to_guess_between_sites(self):
        self.keys()
        self.real_now_evidence()
        trusted = self.key
        self.key = keypair(self.tmp / 'keys', 'other')
        code, text = self.call()
        self.assertEqual((code, '登録されていません' in text), (1, True))
        self.key = trusted
        self.assertEqual(self.call('--trial', '--max-requests', '50')[0], 1)
        self.assertEqual(self.call('--min-interval', '60')[0], 1)
        Site.register(self.data / 'sites', 'Second', 'https://second.my-sub.workers.dev/', ['Desktop'], True, NOW)
        code, text = self.call()
        self.assertEqual((code, '--site' in text), (1, True))
        self.assertEqual(self.call('--site', 'site-ffffffff')[0], 1)
        self.assertFalse((self.site.root / 'http-grant.json').exists())
        self.assertEqual(self.call('--site', self.site.root.name)[0], 0)


if __name__ == '__main__':
    unittest.main()

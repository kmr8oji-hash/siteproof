"""Ownership by DNS TXT challenge, offline: issue / check / recheck with INJECTED lookups (no DNS query is ever made), what the permit and the HTTP grant accept,
the kill switch of tools/dns_ownership.py (its runner is never called while off) and the screen's state. No network, no Docker, no key."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import domain_ownership as dom
from src.noxiworks import http_authority, permit as permits
from src.noxiworks.site_workflow import Site
from tools import dns_ownership, http_grant, permit_draft

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
URL, URL_B = 'https://www.acme-shop.com/', 'https://shop.other-corp.jp/'
EV = 'real/ownership-evidence.json'


def at(**kw):
    return NOW + timedelta(**kw)


def table(answers):
    """A lookup answering from {record name: [TXT strings]}; any other name does not exist."""
    def lookup(record):
        if record not in answers:
            raise dom.LookupFailed('NXDOMAIN')
        return list(answers[record])
    return lookup


def failing(code):
    def lookup(record):
        raise dom.LookupFailed(code)
    return lookup


def tree(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(root).rglob('*')) if p.is_file()}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-dns-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.site = Site.register(self.data / 'sites', 'Acme', URL, ['Desktop'], True, NOW)
        self.other = Site.register(self.data / 'sites', 'Other', URL_B, ['Desktop'], True, NOW)
        self.root, self.root_b = self.site.root, self.other.root
        self.site_id, self.host = self.site.info['site_id'], 'www.acme-shop.com'

    def published(self, challenge, *extra, **over):
        return {challenge['record_name']: [*extra, challenge['record_value']], **over}

    def verified(self, root=None, now=NOW):
        """issue + a successful check for a site; -> (challenge, evidence)."""
        root = root or self.root
        challenge = dom.issue(root, now)
        return challenge, dom.check(root, now, [('system', table(self.published(challenge)))])

    def refused(self, lookups, now=NOW, root=None):
        root = root or self.root
        before = tree(root)
        with self.assertRaises(dom.OwnershipRefused) as caught:
            dom.check(root, now, lookups)
        self.assertEqual(tree(root), before)  # nothing was written
        return str(caught.exception)

    def ownership(self, root=None, now=at(hours=1)):
        root = root or self.root
        return permit_draft.ownership_from_evidence(root, json.loads((root / 'site.json').read_text('utf-8')), now)

    def problems(self, ownership, now=at(hours=1), site_id=None, host=None, root=None):
        permit = {'site': {'site_id': site_id or self.site_id}, 'ownership': ownership}
        return permits.ownership_problems(permit, host or self.host, root or self.root, now)


class Issue(Base):
    def test_a_challenge_names_this_site_and_this_exact_host(self):
        c = dom.issue(self.root, NOW)
        self.assertEqual((c['schema'], c['site_id'], c['host'], c['record_name']), ('siteproof.ownership-challenge.v1', self.site_id, self.host, '_siteproof-challenge.' + self.host))
        self.assertEqual(c['record_value'], f"siteproof-site={self.site_id};token={c['token']}")
        self.assertEqual((c['challenge_id'], c['issued_at'], c['expires_at']), (f'dns-{self.site_id}-20261125T120000Z', '2026-11-25T12:00:00Z', '2026-12-02T12:00:00Z'))
        self.assertGreaterEqual(len(c['token']), 40)
        self.assertEqual(json.loads((self.root / 'real' / 'ownership-challenge.json').read_text('utf-8')), c)
        self.assertNotEqual(dom.issue(self.root_b, NOW)['token'], c['token'])

    def test_an_unexpired_challenge_is_returned_unchanged_and_an_expired_one_is_kept_and_replaced(self):
        c = dom.issue(self.root, NOW)
        self.assertEqual(dom.issue(self.root, at(days=6)), c)
        fresh = dom.issue(self.root, at(days=7))
        self.assertNotEqual(fresh['token'], c['token'])
        kept = list((self.root / 'real' / 'ownership-history').glob('ownership-challenge-expired-*.json'))
        self.assertEqual([json.loads(f.read_text('utf-8'))['token'] for f in kept], [c['token']])

    def test_a_token_is_not_reused_after_a_successful_check(self):
        c, _ = self.verified()
        again = dom.issue(self.root, at(minutes=1))
        self.assertNotEqual(again['token'], c['token'])
        self.assertFalse(list((self.root / 'real' / 'ownership-history').glob('ownership-challenge-expired-*')))  # consumed, not expired

    def test_a_page_folder_a_blocked_host_and_a_non_site_are_refused(self):
        page = self.root / 'pages' / (self.site_id + '-p2')
        page.mkdir(parents=True)
        (page / 'site.json').write_text(json.dumps({**self.site.info, 'page_id': page.name, 'url': URL + 'about'}), encoding='utf-8')
        for root in (page, self.tmp, self.data):
            with self.subTest(root.name), self.assertRaises(dom.OwnershipRefused):
                dom.issue(root, NOW)
        info = {**self.site.info, 'url': 'https://localhost/'}
        (self.root / 'site.json').write_text(json.dumps(info), encoding='utf-8')
        with self.assertRaises(dom.OwnershipRefused):
            dom.issue(self.root, NOW)
        self.assertFalse((page / 'real').exists() or (self.root / 'real' / 'ownership-challenge.json').exists())


class Check(Base):
    def setUp(self):
        super().setUp()
        self.c = dom.issue(self.root, NOW)
        self.name, self.value = self.c['record_name'], self.c['record_value']

    def test_every_lookup_agreeing_writes_the_evidence_and_consumes_the_challenge(self):
        ev = dom.check(self.root, at(hours=2), [('system', table({self.name: ['v=spf1 -all', self.value, 'google-site-verification=abc']})),
                                                ('dns:1.1.1.1', table({self.name: [self.value]}))])
        self.assertEqual((ev['schema'], ev['method'], ev['evidence_id'], ev['site_id'], ev['host'], ev['record_name']),
                         (permits.DNS_EVIDENCE_SCHEMA, 'DNS_TXT_CHALLENGE', self.c['challenge_id'], self.site_id, self.host, self.name))
        self.assertEqual((ev['checked_at'], ev['valid_until']), ('2026-11-25T14:00:00Z', '2027-02-23T14:00:00Z'))  # 90 days
        self.assertEqual(ev['token_sha256'], hashlib.sha256(self.c['token'].encode()).hexdigest())
        self.assertEqual((ev['challenge_issued_at'], ev['challenge_expires_at'], ev['checks']),
                         (self.c['issued_at'], self.c['expires_at'], {'record_found': True, 'exact_value': True, 'all_answers_agree': True}))
        self.assertEqual([x['resolver'] for x in ev['lookups']], ['system', 'dns:1.1.1.1'])
        self.assertEqual(ev['lookups'][1]['answers_sha256'], hashlib.sha256(json.dumps([self.value], ensure_ascii=False).encode()).hexdigest())
        self.assertEqual(json.loads((self.root / EV).read_text('utf-8')), ev)
        self.assertFalse((self.root / 'real' / 'ownership-challenge.json').exists())
        self.assertEqual(len(list((self.root / 'real' / 'ownership-history').glob('ownership-challenge-dns-*.json'))), 1)

    def test_the_token_is_not_in_the_evidence(self):
        dom.check(self.root, NOW, [('system', table({self.name: [self.value]}))])
        self.assertNotIn(self.c['token'], (self.root / EV).read_text('utf-8'))

    def test_each_wrong_answer_is_refused_and_writes_nothing(self):
        other_site = 'siteproof-site=site-00000000;token=abc'
        for label, lookups, text in (
                ('wrong value', [('system', table({self.name: [self.value + 'x']}))], '完全に一致'),
                ('partial value', [('system', table({self.name: [self.value[:-4]]}))], '完全に一致'),
                ('only the token', [('system', table({self.name: [self.c['token']]}))], '完全に一致'),
                ('another case', [('system', table({self.name: [self.value.upper()]}))], '完全に一致'),
                ('another site id', [('system', table({self.name: [f"siteproof-site={self.root_b.name};token={self.c['token']}"]}))], '他のサイト'),
                ('other site value next to ours', [('system', table({self.name: [self.value, other_site]}))], '他のサイト'),
                ('parent domain only', [('system', table({'_siteproof-challenge.acme-shop.com': [self.value]}))], 'NXDOMAIN'),
                ('the host itself, not the challenge name', [('system', table({self.host: [self.value]}))], 'NXDOMAIN'),
                ('nxdomain', [('system', failing('NXDOMAIN'))], 'NXDOMAIN'),
                ('timeout', [('system', failing('TIMEOUT'))], 'TIMEOUT'),
                ('empty answer', [('system', table({self.name: []}))], '完全に一致'),
                ('not a list', [('system', lambda record: self.value)], 'ERROR'),
                ('not strings', [('system', lambda record: [1, 2])], 'ERROR'),
                ('one resolver lacks it', [('system', table({self.name: [self.value]})), ('dns:8.8.8.8', table({self.name: ['other']}))], 'dns:8.8.8.8'),
                ('one resolver times out', [('system', table({self.name: [self.value]})), ('dns:8.8.8.8', failing('TIMEOUT'))], 'TIMEOUT'),
                ('no lookups', [], '問い合わせ先')):
            with self.subTest(label):
                self.assertIn(text, self.refused(lookups))
        self.assertTrue((self.root / 'real' / 'ownership-challenge.json').is_file())
        self.assertFalse((self.root / EV).exists())

    def test_an_expired_challenge_is_refused(self):
        self.assertIn('有効期限', self.refused([('system', table({self.name: [self.value]}))], now=at(days=7)))
        self.assertIn('有効期限', self.refused([('system', table({self.name: [self.value]}))], now=at(days=30)))

    def test_without_a_challenge_nothing_is_checked(self):
        asked = []
        self.assertIn('（チャレンジ）がありません',self.refused([('system', lambda r: asked.append(r) or [])], root=self.root_b))
        self.assertEqual(asked, [])

    def test_another_sites_challenge_copied_in_is_refused_before_any_lookup(self):
        other = dom.issue(self.root_b, NOW)
        shutil.copyfile(self.root_b / 'real' / 'ownership-challenge.json', self.root / 'real' / 'ownership-challenge.json')
        asked = []
        self.assertIn('このサイト・このホストのものではありません', self.refused([('system', lambda r: asked.append(r) or [other['record_value']])]))
        self.assertEqual(asked, [])

    def test_a_challenge_edited_to_another_host_is_refused(self):
        f = self.root / 'real' / 'ownership-challenge.json'
        edited = {**json.loads(f.read_text('utf-8')), 'host': 'acme-shop.com', 'record_name': '_siteproof-challenge.acme-shop.com'}
        f.write_text(json.dumps(edited), encoding='utf-8')
        self.assertIn('このサイト・このホストのものではありません', self.refused([('system', table({edited['record_name']: [self.value]}))]))

    def test_an_older_evidence_is_moved_to_the_history_not_deleted(self):
        _, first = self.verified(now=NOW)
        old = (self.root / EV).read_bytes()
        _, second = self.verified(now=at(days=60))
        self.assertNotEqual(first['evidence_id'], second['evidence_id'])
        kept = list((self.root / 'real' / 'ownership-history').glob('ownership-evidence-*.json'))
        self.assertEqual([f.read_bytes() for f in kept], [old])
        self.assertEqual(json.loads((self.root / EV).read_text('utf-8'))['evidence_id'], second['evidence_id'])


class Accepted(Base):
    def setUp(self):
        super().setUp()
        self.c, self.ev = self.verified()
        self.own = self.ownership()

    def test_the_permit_ownership_record_has_exactly_the_pinned_values(self):
        self.assertEqual((self.own['method'], self.own['verified_at']), ('DNS_TXT_CHALLENGE', self.ev['checked_at']))
        self.assertEqual(self.own['dns'], {'site_id': self.site_id, 'host': self.host, 'record_name': '_siteproof-challenge.' + self.host,
                                          'token_sha256': self.ev['token_sha256'], 'valid_until': self.ev['valid_until']})
        self.assertEqual(self.own['evidence'], {'evidence_id': self.ev['evidence_id'], 'sha256': hashlib.sha256((self.root / EV).read_bytes()).hexdigest()})
        self.assertEqual(self.problems(self.own), [])

    def test_the_image_permit_and_the_http_grant_accept_it(self):
        self.assertEqual(self.problems(self.own, now=at(days=89)), [])
        grant = http_grant.draft(self.root, self.site.info, at(hours=1), seconds=86400, min_interval=300, max_requests=10, purpose='MONITOR')
        self.assertEqual(grant['ownership'], self.own)
        self.assertEqual(http_authority.grant_problems(grant, self.site.info, self.root, at(hours=1)), [])
        self.assertEqual(grant['grant_id'], f'http-{self.site_id}-20261125T130000Z')

    def test_a_page_uses_the_evidence_of_its_site(self):
        page = self.root / 'pages' / (self.site_id + '-p2')
        page.mkdir(parents=True)
        info = {**self.site.info, 'page_id': page.name, 'url': URL + 'about'}
        (page / 'site.json').write_text(json.dumps(info), encoding='utf-8')
        self.assertEqual(permit_draft.ownership_from_evidence(page, info, at(hours=1)), self.own)
        self.assertEqual(http_authority.ownership_problems({'site_id': self.site_id, 'ownership': self.own}, self.host, page, at(hours=1)), [])
        self.assertFalse((page / 'real').exists())  # nothing was put into the page

    def test_each_deviation_is_refused(self):
        own = self.own
        evidence = json.loads((self.root / EV).read_text('utf-8'))

        def rewrite(**over):
            (self.root / EV).write_text(json.dumps({**evidence, **over}), encoding='utf-8')

        def swapped_dns(**over):
            return {**own, 'dns': {**own['dns'], **over}}
        cases = [('other site', lambda: self.problems(own, site_id='site-00000000'), 'ホスト'),
                 ('other host', lambda: self.problems(own, host='shop.acme-shop.com'), 'ホスト'),
                 ('parent host', lambda: self.problems(own, host='acme-shop.com'), 'ホスト'),
                 ('expired after 90 days', lambda: self.problems(own, now=at(days=91)), '期限'),
                 ('exactly at the end', lambda: self.problems(own, now=datetime(2027, 2, 23, 12, 0, 0, tzinfo=timezone.utc)), '期限'),
                 ('future', lambda: self.problems(own, now=at(minutes=-1)), '未来'),
                 ('token differs', lambda: self.problems(swapped_dns(token_sha256='0' * 64)), '証拠'),
                 ('record name differs', lambda: self.problems(swapped_dns(record_name='_siteproof-challenge.acme-shop.com')), 'ホスト'),
                 ('longer than 90 days', lambda: self.problems(swapped_dns(valid_until='2027-12-31T00:00:00Z')), '期限'),
                 ('dns-txt claim', lambda: self.problems({'method': 'dns-txt', 'verified_at': format_utc(NOW)}), '自動照合'),
                 ('well-known claim', lambda: self.problems({'method': 'well-known-file', 'verified_at': format_utc(NOW)}), '自動照合'),
                 ('no record', lambda: self.problems({'method': 'DNS_TXT_CHALLENGE', 'verified_at': format_utc(NOW)}), '不完全')]
        for label, check, text in cases:
            with self.subTest(label):
                found = check()
                self.assertTrue(found and all(p.startswith('所有権') for p in found), (label, found))
                self.assertIn(text, ' '.join(found))
        rewrite(host='shop.acme-shop.com')  # evidence swapped / edited
        self.assertIn('固定された内容', ' '.join(self.problems(own)))

    def test_an_evidence_of_another_site_copied_in_is_refused(self):
        _, ev_b = self.verified(self.root_b)
        shutil.copyfile(self.root_b / EV, self.root / EV)  # A's evidence replaced by B's, A's signed record unchanged
        self.assertIn('固定された内容', ' '.join(self.problems(self.own)))
        own_b = self.ownership(self.root_b)
        shutil.copyfile(self.root_b / EV, self.root / EV)
        self.assertNotEqual(self.problems(own_b), [])  # B's record does not fit A's site id and host either
        self.assertEqual(self.problems(own_b, site_id=self.root_b.name, host='shop.other-corp.jp', root=self.root_b), [])
        self.assertEqual(ev_b['host'], 'shop.other-corp.jp')

    def test_a_later_evidence_swapped_in_without_a_new_signature_is_refused(self):
        self.verified(now=at(days=1))  # a new evidence replaces the old one: the signed record pins the old bytes
        self.assertIn('固定された内容', ' '.join(self.problems(self.own, now=at(days=2))))

    def test_a_withdrawn_check_ends_it_at_once(self):
        (self.root / 'real' / 'ownership-revoked.json').write_text(json.dumps({'evidence_id': self.ev['evidence_id'], 'at': format_utc(NOW), 'reason': 'x'}), encoding='utf-8')
        self.assertIn('取り消されて', ' '.join(self.problems(self.own)))
        (self.root / 'real' / 'ownership-revoked.json').write_text('{broken', encoding='utf-8')
        self.assertIn('取り消されて', ' '.join(self.problems(self.own)))
        (self.root / 'real' / 'ownership-revoked.json').write_text(json.dumps({'evidence_id': 'dns-other', 'at': format_utc(NOW), 'reason': 'x'}), encoding='utf-8')
        self.assertEqual(self.problems(self.own), [])  # a marker about another evidence

    def test_the_draft_refuses_what_the_verifier_would_refuse(self):
        info = json.loads((self.root / 'site.json').read_text('utf-8'))
        with self.assertRaises(permit_draft.DraftRefused):
            permit_draft.ownership_from_evidence(self.root, info, at(days=91))
        with self.assertRaises(permit_draft.DraftRefused):
            permit_draft.ownership_from_evidence(self.root_b, json.loads((self.root_b / 'site.json').read_text('utf-8')), NOW)  # no evidence there
        (self.root / EV).write_text(json.dumps({'schema': 'something.else'}), encoding='utf-8')
        with self.assertRaises(permit_draft.DraftRefused):
            permit_draft.ownership_from_evidence(self.root, info, at(hours=1))


class Recheck(Base):
    def setUp(self):
        super().setUp()
        self.c, self.ev = self.verified()
        self.name, self.value = self.c['record_name'], self.c['record_value']
        self.own = self.ownership()
        self.marker = self.root / 'real' / 'ownership-revoked.json'

    def test_a_record_that_is_still_there_is_ok_and_extends_nothing(self):
        before = tree(self.root)
        done = dom.recheck(self.root, at(days=10), [('system', table({self.name: [self.value]})), ('dns:9.9.9.9', table({self.name: ['x', self.value]}))])
        self.assertEqual(done['status'], 'OK')
        self.assertEqual(tree(self.root), before)
        self.assertEqual(self.problems(self.own, now=at(days=10)), [])

    def test_a_record_every_lookup_reports_missing_withdraws_the_evidence(self):
        done = dom.recheck(self.root, at(days=10), [('system', table({self.name: ['other']})), ('dns:9.9.9.9', failing('NXDOMAIN'))])
        self.assertEqual(done['status'], 'REVOKED')
        marker = json.loads(self.marker.read_text('utf-8'))
        self.assertEqual((marker['evidence_id'], marker['at']), (self.ev['evidence_id'], '2026-12-05T12:00:00Z'))
        self.assertIn('取り消されて', ' '.join(self.problems(self.own, now=at(days=10))))

    def test_a_failed_or_disagreeing_lookup_is_not_a_withdrawal(self):
        for label, lookups, status in (('timeout', [('system', failing('TIMEOUT'))], 'UNKNOWN'), ('error', [('system', failing('ERROR'))], 'UNKNOWN'),
                                       ('one timeout one missing', [('system', failing('TIMEOUT')), ('dns:1.1.1.1', failing('NXDOMAIN'))], 'UNKNOWN'),
                                       ('disagree', [('system', table({self.name: [self.value]})), ('dns:1.1.1.1', failing('NXDOMAIN'))], 'DISAGREE')):
            with self.subTest(label):
                self.assertEqual(dom.recheck(self.root, at(days=10), lookups)['status'], status)
                self.assertFalse(self.marker.exists())

    def test_another_sites_value_in_the_answers_is_not_our_record(self):
        done = dom.recheck(self.root, NOW, [('system', table({self.name: [self.value, 'siteproof-site=site-00000000;token=x']}))])
        self.assertEqual(done['status'], 'UNKNOWN')  # ambiguous is not "missing": nothing is withdrawn
        self.assertFalse(self.marker.exists())

    def test_refused_without_dns_evidence_or_without_the_token(self):
        with self.assertRaises(dom.OwnershipRefused):
            dom.recheck(self.root_b, NOW, [('system', table({}))])
        for f in (self.root / 'real' / 'ownership-history').glob('ownership-challenge-dns-*.json'):
            f.unlink()
        with self.assertRaises(dom.OwnershipRefused):
            dom.recheck(self.root, NOW, [('system', table({self.name: [self.value]}))])


class State(Base):
    def test_the_screen_never_says_verified_from_a_challenge_alone(self):
        self.assertEqual((dom.state(self.root, NOW)['status'], dom.state(self.root, NOW)['method']), ('NONE', None))
        c = dom.issue(self.root, NOW)
        s = dom.state(self.root, at(hours=1))
        self.assertEqual((s['status'], s['method'], s['record_name'], s['record_value'], s['expires_at']), ('CHALLENGE', 'DNS_TXT_CHALLENGE', c['record_name'], c['record_value'], c['expires_at']))
        self.assertNotIn('確認済みです', s['guidance'])
        self.assertEqual(dom.state(self.root, at(days=8))['status'], 'EXPIRED')

    def test_verified_expired_and_revoked(self):
        _, ev = self.verified()
        s = dom.state(self.root, at(days=1))
        self.assertEqual((s['status'], s['method'], s['host'], s['checked_at'], s['valid_until']), ('VERIFIED', 'DNS_TXT_CHALLENGE', self.host, ev['checked_at'], ev['valid_until']))
        self.assertEqual(s['days_left'], 89.0)
        self.assertEqual(dom.state(self.root, at(days=91))['status'], 'EXPIRED')
        (self.root / 'real' / 'ownership-revoked.json').write_text(json.dumps({'evidence_id': ev['evidence_id']}), encoding='utf-8')
        self.assertEqual(dom.state(self.root, at(days=1))['status'], 'REVOKED')

    def test_a_new_challenge_next_to_valid_evidence_keeps_it_verified(self):
        self.verified()
        c = dom.issue(self.root, at(days=1))
        s = dom.state(self.root, at(days=1))
        self.assertEqual((s['status'], s['record_value']), ('VERIFIED', c['record_value']))

    def test_cloudflare_evidence_is_shown_as_such(self):
        (self.root / 'real').mkdir(exist_ok=True)
        (self.root / EV).write_text(json.dumps({'schema': permits.CF_EVIDENCE_SCHEMA, 'evidence_id': 'cf-1', 'checked_at': format_utc(NOW), 'host': self.host}), encoding='utf-8')
        s = dom.state(self.root, at(days=1))
        self.assertEqual((s['method'], s['status']), ('CLOUDFLARE_ACCOUNT_CONTROL', 'VERIFIED'))
        self.assertEqual(dom.state(self.root, at(days=91))['status'], 'EXPIRED')

    def test_evidence_of_another_host_is_not_shown_as_verified(self):
        self.verified()
        (self.root_b / 'real').mkdir(exist_ok=True)
        shutil.copyfile(self.root / EV, self.root_b / EV)
        self.assertEqual(dom.state(self.root_b, at(days=1))['status'], 'NONE')


class Tool(Base):
    def run_tool(self, *argv, runner=None, now=NOW, enabled=False):
        calls = []

        def default(argv, timeout):
            calls.append(argv)
            return 0, json.dumps([self.value_for(argv)])
        with mock.patch.object(dns_ownership, 'OWNERSHIP_DNS_ENABLED', enabled), mock.patch('builtins.print') as out:
            code = dns_ownership.main([*argv, '--data', str(self.data), '--site', self.site_id], runner or default, now)
        return code, calls, '\n'.join(str(c.args[0]) for c in out.call_args_list)

    def value_for(self, argv):
        return json.loads((self.root / 'real' / 'ownership-challenge.json').read_text('utf-8'))['record_value']

    def test_issue_and_status_work_while_lookups_are_off(self):
        code, calls, out = self.run_tool('issue')
        self.assertEqual((code, calls), (0, []))
        c = json.loads((self.root / 'real' / 'ownership-challenge.json').read_text('utf-8'))
        self.assertIn(c['record_name'], out)
        self.assertEqual(self.run_tool('status')[0], 0)

    def test_the_kill_switch_stops_check_and_recheck_before_any_lookup(self):
        dom.issue(self.root, NOW)
        boom = mock.MagicMock(side_effect=AssertionError('a lookup was made'))
        for action in ('check', 'recheck'):
            with self.subTest(action):
                code, calls, out = self.run_tool(action, '--server', '1.1.1.1', runner=boom)
                self.assertEqual(code, 1)
                self.assertIn('無効', out)
        boom.assert_not_called()
        self.assertFalse((self.root / EV).exists())
        self.assertFalse(dns_ownership.OWNERSHIP_DNS_ENABLED)  # shipped off

    def test_with_the_switch_on_the_system_resolver_and_each_server_are_asked_with_the_fixed_command(self):
        dom.issue(self.root, NOW)
        code, calls, out = self.run_tool('check', '--server', '1.1.1.1', '--server', '9.9.9.9', enabled=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(calls), 3)
        self.assertEqual([('-Server' in c[-1]) for c in calls], [False, True, True])
        for argv in calls:
            self.assertEqual(argv[:4], ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command'])
            self.assertIn('Resolve-DnsName -Name _siteproof-challenge.' + self.host + ' -Type TXT -DnsOnly -NoHostsFile', argv[4])
        self.assertIn('別の', out)
        self.assertEqual(dom.state(self.root, at(hours=1))['status'], 'VERIFIED')

    def test_a_failing_lookup_through_the_tool_writes_nothing(self):
        dom.issue(self.root, NOW)
        before = tree(self.root)

        def timeout(argv, seconds):
            raise __import__('subprocess').TimeoutExpired(argv, seconds)
        code, calls, out = self.run_tool('check', runner=timeout, enabled=True)
        self.assertEqual(code, 1)
        self.assertEqual(tree(self.root), before)
        self.assertIn('TIMEOUT', out)

    def test_only_the_challenge_record_name_and_ip_servers_can_be_asked(self):
        for bad in ('www.acme-shop.com', '_siteproof-challenge.', '_siteproof-challenge.com', "_siteproof-challenge.a.com'; calc", '_siteproof-challenge.a.com;x.com',
                    '_siteproof-challenge.a b.com', '_siteproof-challenge.' + 'a' * 300 + '.com', '$(whoami)', '_siteproof-challenge.-a.com'):
            with self.subTest(bad), self.assertRaises(dom.LookupFailed):
                dns_ownership.command(bad)
        for bad in ('1.1.1.1; calc', 'localhost', '-Server'):
            with self.subTest(bad), self.assertRaises(dom.LookupFailed):
                dns_ownership.command('_siteproof-challenge.a.com', bad)
        self.assertIn('-Server 1.1.1.1', dns_ownership.command('_siteproof-challenge.a.com', '1.1.1.1')[-1])
        with mock.patch('sys.stderr'), mock.patch('sys.stdout'):
            with self.assertRaises(SystemExit):
                dns_ownership.main(['check', '--data', str(self.data), '--server', 'x'])
            with self.assertRaises(SystemExit):
                dns_ownership.main(['check', '--data', str(self.data), '--server', '1.1.1.1', '--server', '1.0.0.1', '--server', '8.8.8.8', '--server', '9.9.9.9'])

    def test_what_the_process_prints_is_read_strictly(self):
        def reply(code, out):
            return lambda argv, timeout: (code, out)
        name = '_siteproof-challenge.a.com'
        self.assertEqual(dns_ownership.lookup_txt(name, None, reply(0, '["a","b"]')), ['a', 'b'])
        self.assertEqual(dns_ownership.lookup_txt(name, None, reply(0, '"only"')), ['only'])
        self.assertEqual(dns_ownership.lookup_txt(name, None, reply(0, '[]')), [])
        for out, code in (('ERR:DNS_ERROR_RCODE_NAME_ERROR,Microsoft.DnsClient', 'NXDOMAIN'), ('ERR:DNS_INFO_NO_RECORDS,x', 'NXDOMAIN'), ('ERR:Timeout', 'TIMEOUT'),
                          ('ERR:something', 'ERROR'), ('not json', 'ERROR'), ('[1]', 'ERROR'), ('{"a":1}', 'ERROR'), ('x' * (dns_ownership.MAX_OUTPUT + 5), 'ERROR')):
            with self.subTest(out[:20]), self.assertRaises(dom.LookupFailed) as caught:
                dns_ownership.lookup_txt(name, None, reply(3 if out.startswith('ERR') else 0, out))
            self.assertEqual(caught.exception.code, code)

    def test_recheck_through_the_tool_withdraws_only_on_a_definite_absence(self):
        _, _ = self.verified()
        code, calls, out = self.run_tool('recheck', runner=lambda argv, t: (3, 'ERR:DNS_ERROR_RCODE_NAME_ERROR,x'), enabled=True)
        self.assertEqual(code, 1)
        self.assertTrue((self.root / 'real' / 'ownership-revoked.json').is_file())
        self.assertIn('取り消しました', out)


class Setup(Base):
    def test_ownership_dns_uses_existing_evidence_and_asks_nothing(self):
        from tools import setup_monitoring
        info = json.loads((self.root / 'site.json').read_text('utf-8'))
        with self.assertRaises(setup_monitoring.SetupFailed):
            setup_monitoring.ownership_record(self.root, info, 'dns', None, NOW)  # no evidence yet
        with self.assertRaises(setup_monitoring.SetupFailed):
            setup_monitoring.ownership_record(self.root, info, None, None, NOW)
        self.verified()
        with mock.patch('subprocess.run', side_effect=AssertionError('a process was started')), mock.patch('urllib.request.urlopen', side_effect=AssertionError('network')), \
                mock.patch('builtins.print'):
            by_name = setup_monitoring.ownership_record(self.root, info, 'dns', None, at(hours=1))
            reused = setup_monitoring.ownership_record(self.root, info, None, None, at(hours=1))
        self.assertEqual((by_name['method'], reused), ('DNS_TXT_CHALLENGE', by_name))
        with self.assertRaises(setup_monitoring.SetupFailed):
            setup_monitoring.ownership_record(self.root, info, 'dns-txt', None, NOW)  # a claim stays refused

    def test_the_apps_setup_steps(self):
        from src.noxiworks.app import App
        app = App(self.data)
        app.docker_found, app.launcher = False, mock.MagicMock()
        app.background_query = mock.MagicMock(return_value=False)
        app.setup()
        both = {'site_id': self.site_id}
        with self.assertRaises(ValueError):  # no valid DNS evidence yet
            app.site_action('setup', {**both, 'step': 'setup', 'ownership': 'dns'})
        issued = app.site_action('setup', {**both, 'step': 'dns-issue'})
        self.assertEqual(issued['record_name'], '_siteproof-challenge.' + self.host)
        self.assertTrue(issued['record_value'].startswith(f'siteproof-site={self.site_id};token='))
        self.assertEqual(app.site_action('setup', {**both, 'step': 'dns-issue'})['record_value'], issued['record_value'])
        app.launcher.assert_not_called()
        app.site_action('setup', {**both, 'step': 'dns-check'})
        argv = [str(a) for a in app.launcher.call_args[0][0]]
        self.assertEqual((argv[2:4], argv[argv.index('--site') + 1], app.launcher.call_args[1]), (['tools/dns_ownership.py', 'check'], self.site_id, {'console': True}))
        self.assertNotIn('--yes', argv)
        app.launcher.reset_mock()
        with self.assertRaises(ValueError):  # a challenge alone is not evidence
            app.site_action('setup', {**both, 'step': 'setup', 'ownership': 'dns'})
        c = json.loads((self.root / 'real' / 'ownership-challenge.json').read_text('utf-8'))
        dom.check(self.root, datetime.now(timezone.utc).replace(microsecond=0), [('system', table({c['record_name']: [c['record_value']]}))])
        out = app.site_action('setup', {**both, 'step': 'setup'})  # no method given: the verified DNS evidence is the default for this host
        self.assertEqual(out['ownership'], 'dns')
        self.assertEqual([str(a) for a in app.launcher.call_args[0][0]][-3:], ['--pause', '--ownership', 'dns'])


if __name__ == '__main__':
    unittest.main()

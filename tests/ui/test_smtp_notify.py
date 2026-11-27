"""E-mail notification channel (offline: fake resolver / socket / smtplib objects, synthetic keys, temporary data; no network, no mail, no real credential).

Nothing here connects anywhere. The pinned smtplib subclasses are only exercised on an in-memory fake socket.
"""
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import shutil
import smtplib
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import filelock, notifications, notify_dispatch, smtp_notify
from src.noxiworks import permit as permits
from src.noxiworks.notify_dispatch import Dispatcher
from src.noxiworks.smtp_notify import MockSmtpProvider, SendResult, SmtpProvider
from tests.ui.test_real_capture import needs_ssh
from tools import notify_grant

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
PASSWORD = 'p4ss-SECRET-xyz'
GOOD_IP = '93.184.216.34'
ROOT = Path(__file__).resolve().parents[2]


def at(minutes=0):
    return NOW + timedelta(minutes=minutes)


def grant(**over):
    smtp = {'host': 'smtp.mail-provider.com', 'port': 587, 'security': 'STARTTLS', **over.pop('smtp', {})}
    return {'schema': smtp_notify.GRANT_SCHEMA, 'grant_id': 'notify-test-1', 'issued_by': 'site-owner', 'issued_at': format_utc(NOW), 'smtp': smtp,
            'sender': 'alerts@my-site.com', 'recipients': ['owner@example.org'], 'credential_ref': 'SiteProof-SMTP-main', 'valid_from': format_utc(NOW - timedelta(hours=1)),
            'valid_until': format_utc(NOW + timedelta(days=30)), 'max_messages_total': 100, 'max_messages_per_day': 20, **over}


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-notify-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)

    def make_site(self, site_id='site-aaaaaaaa'):
        root = self.data / 'sites' / site_id
        root.mkdir(parents=True)
        return SimpleNamespace(root=root, info={'site_id': site_id})


# ---- the signed grant
class Shape(Tmp):
    def test_a_valid_grant_has_no_problems_and_each_deviation_is_refused(self):
        self.assertEqual(smtp_notify.shape_problems(grant()), [])
        self.assertEqual(smtp_notify.shape_problems(grant(smtp={'port': 465, 'security': 'TLS'})), [])
        bad = {'port 25': grant(smtp={'port': 25}), 'port/security': grant(smtp={'port': 587, 'security': 'TLS'}), 'plain': grant(smtp={'security': 'NONE'}),
               'port text': grant(smtp={'port': '587'}), 'localhost': grant(smtp={'host': 'localhost'}), 'internal': grant(smtp={'host': 'smtp.internal'}),
               'ip literal': grant(smtp={'host': '93.184.216.34'}), 'no dot': grant(smtp={'host': 'smtp'}), 'upper': grant(smtp={'host': 'SMTP.mail-provider.com'}),
               '.local': grant(smtp={'host': 'mail.local'}), 'host url': grant(smtp={'host': 'smtp.mail-provider.com/x'}), 'no smtp': {**grant(), 'smtp': 'x'},
               'sender newline': grant(sender='a@b.com\nBcc: x@y.com'), 'sender display': grant(sender='Name <a@b.com>'), 'sender comma': grant(sender='a@b.com,c@d.com'),
               'no recipients': grant(recipients=[]), 'six recipients': grant(recipients=[f'u{i}@example.org' for i in range(6)]),
               'dup recipients': grant(recipients=['a@example.org', 'a@example.org']), 'bad recipient': grant(recipients=['owner@example.org', 'x y@example.org']),
               'str recipients': grant(recipients='owner@example.org'), 'unicode recipient': grant(recipients=['ｏwner@example.org']),
               'ref': grant(credential_ref='main'), 'ref chars': grant(credential_ref='SiteProof-SMTP-a b'), 'id prefix': grant(grant_id='http-1'),
               'id chars': grant(grant_id='notify-a/b'), 'total 0': grant(max_messages_total=0), 'total big': grant(max_messages_total=10001),
               'day 0': grant(max_messages_per_day=0), 'day big': grant(max_messages_per_day=201), 'bool': grant(max_messages_total=True), 'float': grant(max_messages_per_day=1.5),
               'too long': grant(valid_until=format_utc(NOW + timedelta(days=400))), 'reversed': grant(valid_until=format_utc(NOW - timedelta(days=2))),
               'schema': grant(schema='siteproof.http-grant.v1'), 'permit schema': grant(schema=permits.SCHEMA)}
        for label, g in bad.items():
            with self.subTest(label):
                self.assertTrue(smtp_notify.shape_problems(g), label)

    def test_addresses(self):
        for good in ('a@b.co', 'first.last+tag@sub.example.org', 'a_b-c@x-y.example.com'):
            self.assertTrue(smtp_notify.valid_address(good), good)
        for bad in ('', 'a@b', 'a@@b.com', '@b.com', 'a@.com', '.a@b.com', 'a.@b.com', 'a..b@b.com', 'a@b.com ', ' a@b.com', 'a@b.com\n', 'a@b.com\r\nX: y', '<a@b.com>', 'a b@c.com',
                    'a@b_c.com', None, 5, 'a@b.com' + 'x' * 260):
            self.assertFalse(smtp_notify.valid_address(bad), repr(bad))

    def test_the_period_is_judged_against_now(self):
        self.assertEqual(smtp_notify.period_problems(grant(), NOW), [])
        self.assertTrue(smtp_notify.period_problems(grant(valid_until=format_utc(at(-1))), NOW))
        self.assertTrue(smtp_notify.period_problems(grant(valid_from=format_utc(at(1))), NOW))
        self.assertEqual(smtp_notify.mask_address('owner@example.org'), 'o***@example.org')


@needs_ssh
class Signed(Tmp):
    def keys(self, name='k'):
        key = self.tmp / 'keys' / name
        key.parent.mkdir(exist_ok=True)
        subprocess.run([permits.ssh_keygen(), '-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-test-key', '-f', str(key)], check=True)
        return key

    def trust(self, key):
        pub = key.with_name(key.name + '.pub').read_text('utf-8').split()
        (self.data / 'trust').mkdir(exist_ok=True)
        (self.data / 'trust' / 'allowed_signers').write_text(f'site-owner namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='ascii')

    def sign(self, key, body):
        f = self.data / 'notify' / 'notify-grant.json'
        f.parent.mkdir(exist_ok=True)
        f.with_name(f.name + '.sig').unlink(missing_ok=True)
        f.write_text(json.dumps(body), encoding='utf-8')
        subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(key), str(f)], check=True, capture_output=True)

    def setUp(self):
        super().setUp()
        self.key = self.keys()
        self.trust(self.key)

    def test_refusals_speak_of_the_notification_grant_not_of_the_monitoring_permit(self):
        text = ' '.join(smtp_notify.verify_grant(self.data, NOW)[1])  # nothing signed yet
        self.assertIn('通知許可（notify-grant.json と notify-grant.json.sig）', text)
        for old in ('監視許可', 'real/permit.json', 'permit.json.sig'):
            self.assertNotIn(old, text)
        self.sign(self.key, grant())
        f = self.data / 'notify' / 'notify-grant.json'
        f.write_text(f.read_text('utf-8') + ' ', encoding='utf-8')
        text = ' '.join(smtp_notify.verify_grant(self.data, NOW)[1])
        self.assertIn('通知許可の署名が正しくありません', text)
        self.assertNotIn('監視許可', text)

    def test_a_signed_grant_passes_and_other_schemas_do_not(self):
        self.assertIsNone(smtp_notify.verify_grant(self.data, NOW)[0])  # nothing signed yet
        self.sign(self.key, grant())
        g, problems = smtp_notify.verify_grant(self.data, NOW)
        self.assertEqual((problems, g['grant_id']), ([], 'notify-test-1'))
        http_shaped = {'schema': 'siteproof.http-grant.v1', 'grant_id': 'g1', 'issued_by': 'site-owner', 'site_id': 'site-1', 'host': 'my-site.com', 'path': '/',
                       'valid_from': format_utc(at(-60)), 'valid_until': format_utc(at(600)), 'min_interval_seconds': 300}
        for body in (http_shaped, {**grant(), 'schema': permits.SCHEMA}):
            self.sign(self.key, body)
            g, problems = smtp_notify.verify_grant(self.data, NOW)
            self.assertIsNone(g)
            self.assertIn('通知許可の形式が違います', ' '.join(problems))

    def test_expired_not_yet_tampered_unsigned_and_untrusted_are_refused(self):
        self.sign(self.key, grant(valid_until=format_utc(at(-1)), valid_from=format_utc(at(-600))))
        self.assertIn('有効期間外', ' '.join(smtp_notify.verify_grant(self.data, NOW)[1]))
        self.sign(self.key, grant(valid_from=format_utc(at(5))))
        self.assertIn('有効期間外', ' '.join(smtp_notify.verify_grant(self.data, NOW)[1]))
        self.sign(self.key, grant())
        self.assertEqual(smtp_notify.verify_grant(self.data, NOW)[1], [])
        f = self.data / 'notify' / 'notify-grant.json'
        f.write_text(f.read_text('utf-8').replace('owner@example.org', 'evil@example.org'), encoding='utf-8')
        self.assertIn('署名', ' '.join(smtp_notify.verify_grant(self.data, NOW)[1]))  # edited after signing
        self.sign(self.key, grant())
        f.with_name(f.name + '.sig').unlink()
        self.assertTrue(smtp_notify.verify_grant(self.data, NOW)[1])
        other = self.keys('other')  # signed by a key that is not in the trust file
        self.sign(other, grant())
        self.assertIn('署名', ' '.join(smtp_notify.verify_grant(self.data, NOW)[1]))

    def test_the_send_time_check_is_never_a_cache_but_the_display_may_be(self):
        self.sign(self.key, grant())
        self.assertTrue(smtp_notify.cached_grant_view(self.data, NOW)[0])  # primes the display cache
        f = self.data / 'notify' / 'notify-grant.json'
        f.write_text(f.read_text('utf-8') + ' ', encoding='utf-8')  # tampered
        self.assertIsNone(smtp_notify.verify_grant(self.data, NOW)[0])  # seen at once
        self.sign(self.key, grant())
        self.assertIsNone(smtp_notify.verify_grant(self.data, at(60 * 24 * 40))[0])  # the period is always judged on the given time, also in the display view
        self.assertIsNone(smtp_notify.cached_grant_view(self.data, at(60 * 24 * 40))[0])

    def test_the_signing_tool_writes_a_grant_that_verifies_and_never_touches_credentials(self):
        argv = ['--data', str(self.data), '--key', str(self.key), '--yes', '--host', 'smtp.mail-provider.com', '--port', '587', '--sender', 'alerts@my-site.com',
                '--recipient', 'a@example.org', '--recipient', 'b@example.org', '--credential-ref', 'SiteProof-SMTP-main', '--days', '3', '--max-total', '50', '--max-per-day', '5']
        with mock.patch.object(smtp_notify, 'read_credential', side_effect=AssertionError('credential read')), mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(notify_grant.main(argv), 0, out.getvalue())
        g, problems = smtp_notify.verify_grant(self.data, datetime.now(timezone.utc))
        self.assertEqual(problems, [])
        self.assertEqual((g['smtp'], g['recipients'], g['max_messages_total'], g['max_messages_per_day']),
                         ({'host': 'smtp.mail-provider.com', 'port': 587, 'security': 'STARTTLS'}, ['a@example.org', 'b@example.org'], 50, 5))
        self.assertTrue(g['grant_id'].startswith('notify-'))
        self.assertFalse((self.data / 'notify' / 'email.json').exists())  # signing never turns the channel on
        self.assertNotIn('password', json.dumps(g).lower())

    def test_the_tool_refuses_bad_values_and_untrusted_keys_and_writes_nothing(self):
        base = ['--data', str(self.data), '--yes', '--sender', 'alerts@my-site.com', '--recipient', 'a@example.org', '--credential-ref', 'SiteProof-SMTP-main', '--port', '587']
        for label, extra in (('localhost', ['--host', 'localhost', '--key', str(self.key)]), ('internal', ['--host', 'mail.internal', '--key', str(self.key)]),
                             ('untrusted', ['--host', 'smtp.mail-provider.com', '--key', str(self.keys('other'))]),
                             ('no key', ['--host', 'smtp.mail-provider.com', '--key', str(self.tmp / 'keys' / 'nothing')])):
            with self.subTest(label), mock.patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(notify_grant.main(base + extra), 1)
            self.assertFalse((self.data / 'notify' / 'notify-grant.json').exists())
        self.assertFalse((self.tmp / 'keys' / 'nothing').exists())  # no key is created
        with mock.patch('sys.stdout', new_callable=io.StringIO), mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            notify_grant.main(base[:-1] + ['25', '--host', 'smtp.mail-provider.com', '--key', str(self.key)])  # port 25 is not a choice


# ---- the ledger
class Ledger(Tmp):
    def lines(self, g=None):
        f = smtp_notify.ledger_file(self.data, (g or grant())['grant_id'])
        return f.read_text('utf-8').splitlines() if f.is_file() else []

    def test_every_attempt_is_counted_before_it_is_made_and_limits_hold(self):
        g = grant(max_messages_total=3, max_messages_per_day=2)
        self.assertEqual(smtp_notify.reserve(self.data, g, NOW, 'a'), 1)
        self.assertEqual(smtp_notify.reserve(self.data, g, at(1), 'b'), 2)
        with self.assertRaises(smtp_notify.LedgerRefused) as cm:
            smtp_notify.reserve(self.data, g, at(2), 'c')
        self.assertEqual(cm.exception.reason, 'LIMIT_DAILY')
        self.assertEqual(smtp_notify.reserve(self.data, g, at(60 * 25), 'd'), 3)  # the 24 h window moved on
        with self.assertRaises(smtp_notify.LedgerRefused) as cm:
            smtp_notify.reserve(self.data, g, at(60 * 60), 'e')
        self.assertEqual(cm.exception.reason, 'LIMIT_TOTAL')
        self.assertEqual(len(self.lines(g)), 3)  # a refused reservation writes nothing
        usage = smtp_notify.ledger_usage(self.data, g, at(60 * 25))
        self.assertEqual((usage['total'], usage['today'], usage['remaining_total'], usage['remaining_today']), (3, 1, 0, 0))

    def test_fail_closed_on_an_unreadable_line_a_torn_line_or_a_clock_that_went_back(self):
        g = grant()
        f = smtp_notify.ledger_file(self.data, g['grant_id'])
        f.parent.mkdir(parents=True)
        for label, text in (('garbage', 'x\n'), ('blank', '\n'), ('no time', '{"ref":"a"}\n'), ('torn', '{"at": "2026-11-25T11'), ('bad time', '{"at": "yesterday"}\n'),
                            ('binary', None)):
            with self.subTest(label):
                f.write_bytes(b'\xff\xfe\x00' if text is None else text.encode())
                with self.assertRaises(smtp_notify.LedgerRefused) as cm:
                    smtp_notify.reserve(self.data, g, NOW, 'a')
                self.assertEqual(cm.exception.reason, 'LEDGER_CORRUPT')
        f.write_text(json.dumps({'at': format_utc(at(10))}) + '\n', encoding='utf-8')
        with self.assertRaises(smtp_notify.LedgerRefused) as cm:
            smtp_notify.reserve(self.data, g, NOW, 'a')  # 10 minutes in the past: the clock went back by more than 5
        self.assertEqual(cm.exception.reason, 'CLOCK_WENT_BACK')
        self.assertEqual(smtp_notify.reserve(self.data, g, at(6), 'a'), 2)  # 4 minutes back is tolerated
        with self.assertRaises(smtp_notify.LedgerRefused):
            smtp_notify.reserve(self.data, {**g, 'grant_id': '../x'}, NOW, 'a')

    def test_two_threads_cannot_pass_the_limit_together(self):
        g = grant(max_messages_total=5, max_messages_per_day=5)
        results = []

        def go():
            try:
                results.append(smtp_notify.reserve(self.data, g, NOW, 'a'))
            except smtp_notify.LedgerRefused as exc:
                results.append(exc.reason)
        threads = [threading.Thread(target=go) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(r for r in results if isinstance(r, int)), [1, 2, 3, 4, 5])
        self.assertEqual(len(self.lines(g)), 5)


# ---- the message and the credential
class Message(Tmp):
    def test_the_mail_is_built_from_the_grant_only_with_a_stable_id_and_an_honest_footer(self):
        body = '\n'.join(['SiteProof 監視: 障害を検知しました', '', '対象ページ : p1', '', '※ このメールは状態が変わったときだけ送られます。送信に失敗した通知は次回の監視実行で再送されます(重複することがあります)。',
                          '※ SNSへの送信成功は、メールの受信完了を保証するものではありません。'])
        msg = smtp_notify.build_message(grant(), notice_id='abc123', site_id='site-aaaaaaaa', subject='[SiteProof] FAIL x\r\nBcc: evil@example.org', body=body, now=NOW)
        self.assertEqual((msg['From'], msg['To'], msg['Message-ID']), ('alerts@my-site.com', 'owner@example.org', '<abc123.site-aaaaaaaa@siteproof.local>'))
        self.assertIsNone(msg['Bcc'])
        self.assertNotIn('\n', msg['Subject'])
        text = msg.get_content()
        self.assertIn('障害を検知しました', text)
        self.assertNotIn('SNS', text)
        self.assertNotIn('次回の監視実行で再送', text)
        self.assertIn('受信（メールボックスへの到着）を保証しません', text)
        self.assertIn('SiteProofアプリ（PC版）', text)
        again = smtp_notify.build_message(grant(), notice_id='abc123', site_id='site-aaaaaaaa', subject='s', body=body, now=at(5))
        self.assertEqual(again['Message-ID'], msg['Message-ID'])
        raw = msg.as_bytes()
        self.assertNotIn(b'\nBcc:', raw)  # the CR/LF became a space: no second header
        self.assertTrue(raw.isascii())  # 7-bit safe for any server
        self.assertLessEqual(len(smtp_notify.clean_subject('あ' * 400)), 150)
        with self.assertRaises(ValueError):
            smtp_notify.build_message(grant(), notice_id='a b', site_id='s', subject='s', body='b', now=NOW)

    def test_only_the_note_lines_of_the_aws_texts_are_dropped(self):
        body = '\n'.join(['対象ページ : sns-status (https://sns.example.org/)', '※ SNSへの送信成功は、メールの受信完了を保証するものではありません。', '※ 別の注記'])
        text = smtp_notify.mail_body(body)
        self.assertIn('sns-status (https://sns.example.org/)', text)
        self.assertIn('※ 別の注記', text)
        self.assertNotIn('送信成功は', text)

    def test_the_default_credential_reader_refuses_without_touching_anything_on_other_systems_and_bad_names(self):
        with self.assertRaises(smtp_notify.CredentialError) as cm:
            smtp_notify.read_credential('main')
        self.assertEqual(str(cm.exception), 'REF_INVALID')
        with mock.patch.object(smtp_notify.sys, 'platform', 'linux'), self.assertRaises(smtp_notify.CredentialError) as cm:
            smtp_notify.read_credential('SiteProof-SMTP-main')
        self.assertEqual(str(cm.exception), 'NOT_WINDOWS')
        self.assertIs(SmtpProvider().credentials, smtp_notify.read_credential)


# ---- the provider (fakes only)
class FakeSock:
    def __init__(self, peer):
        self.peer, self.closed, self.cut = peer, False, threading.Event()

    def shutdown(self, how):
        self.cut.set()

    def getpeername(self):
        return self.peer

    def close(self):
        self.closed = True

    def settimeout(self, value):
        pass


class FakeSmtp:
    def __init__(self, *, starttls=True, starttls_code=220, login=None, mail=250, rcpt=(250,), data=250):
        self.starttls_offered, self.starttls_code, self.login_exc, self.mail_code, self.rcpt_codes, self.data_result = starttls, starttls_code, login, mail, list(rcpt), data
        self.log, self.payload, self.recipients = [], None, []

    def ehlo(self, name=None):
        self.log.append('ehlo')
        return 250, b''

    def has_extn(self, name):
        return self.starttls_offered and name == 'starttls'

    def starttls(self, context=None):
        self.log.append('starttls')
        self.context = context
        return self.starttls_code, b''

    def login(self, user, password):
        self.log.append('login')
        self.credentials = (user, password)
        if self.login_exc:
            raise self.login_exc

    def mail(self, sender):
        self.log.append('mail')
        self.sender = sender
        return self.mail_code, b''

    def rcpt(self, recipient):
        self.log.append('rcpt')
        self.recipients.append(recipient)
        return (self.rcpt_codes.pop(0) if len(self.rcpt_codes) > 1 else self.rcpt_codes[0]), b''

    def data(self, payload):
        self.log.append('data')
        self.payload = payload
        if isinstance(self.data_result, BaseException):
            raise self.data_result
        return self.data_result, b''

    def quit(self):
        self.log.append('quit')

    def close(self):
        self.log.append('close')


class Provider(Tmp):
    """SmtpProvider with every outside dependency replaced; the kill switch is switched on only for the test that needs it."""

    def build(self, *, answers=(GOOD_IP,), smtp=None, peer=None, creds=None, g=None, **kw):
        self.g = g or grant()
        self.smtp = smtp or FakeSmtp(**kw)
        self.calls = {'resolve': [], 'connect': [], 'creds': [], 'factory': []}

        def resolver(host, port):
            self.calls['resolve'].append((host, port))
            if isinstance(answers, BaseException):
                raise answers
            return list(answers)

        def connector(ip, port, timeout):
            self.calls['connect'].append((ip, port))
            if isinstance(peer, BaseException):
                raise peer
            self.sock = FakeSock(peer or (ip, port))
            return self.sock

        def credentials(ref):
            self.calls['creds'].append(ref)
            if isinstance(creds, BaseException):
                raise creds
            return creds or ('mailuser', PASSWORD)

        def factory(security, host, port, sock, context, local, timeout):
            self.calls['factory'].append((security, host, port, local))
            self.smtp.sock = sock
            return self.smtp
        return SmtpProvider(resolver, connector, credentials, factory)

    def send(self, provider, g=None, now=NOW, enabled=True):
        g = g or self.g
        msg = smtp_notify.build_message(g, notice_id='n1', site_id='site-aaaaaaaa', subject='s', body='b', now=now)
        with mock.patch.object(smtp_notify, 'NOTIFY_EXTERNAL_ENABLED', enabled):
            return provider.send(g, self.data, msg, now)

    def ledger_lines(self):
        f = smtp_notify.ledger_file(self.data, 'notify-test-1')
        return f.read_text('utf-8').splitlines() if f.is_file() else []

    def test_the_kill_switch_stops_everything_before_any_lookup_connection_credential_or_ledger(self):
        provider = self.build()
        self.assertFalse(smtp_notify.NOTIFY_EXTERNAL_ENABLED)  # the shipped value
        self.assertFalse(provider.can_send())
        with self.assertRaises(smtp_notify.ExternalDisabled):
            self.send(provider, enabled=False)
        self.assertEqual(self.calls, {'resolve': [], 'connect': [], 'creds': [], 'factory': []})
        self.assertEqual(self.ledger_lines(), [])
        self.assertFalse((self.data / 'trust').exists())

    def test_starttls_session_order_login_only_after_tls_and_fixed_local_hostname(self):
        provider = self.build()
        result = self.send(provider)
        self.assertEqual(result, SendResult('ACCEPTED', 'SMTP_250'))
        self.assertEqual(self.smtp.log, ['ehlo', 'starttls', 'ehlo', 'login', 'mail', 'rcpt', 'data', 'quit', 'close'])
        self.assertEqual(self.calls['factory'], [('STARTTLS', 'smtp.mail-provider.com', 587, 'siteproof.local')])
        self.assertEqual(self.calls['connect'], [(GOOD_IP, 587)])  # one connection, to the approved address
        self.assertEqual((self.smtp.sender, self.smtp.recipients, self.smtp.credentials), ('alerts@my-site.com', ['owner@example.org'], ('mailuser', PASSWORD)))
        self.assertGreaterEqual(self.smtp.context.minimum_version.value, smtp_notify.ssl.TLSVersion.TLSv1_2.value)
        self.assertTrue(self.smtp.context.check_hostname)
        self.assertEqual(self.smtp.context.verify_mode, smtp_notify.ssl.CERT_REQUIRED)
        self.assertTrue(self.sock.closed)
        self.assertEqual(len(self.ledger_lines()), 1)
        self.assertIn(b'Message-ID: <n1.site-aaaaaaaa@siteproof.local>', self.smtp.payload)

    def test_implicit_tls_on_465(self):
        g = grant(smtp={'port': 465, 'security': 'TLS'})
        provider = self.build(g=g)
        self.assertEqual(self.send(provider).result, 'ACCEPTED')
        self.assertEqual(self.smtp.log, ['login', 'mail', 'rcpt', 'data', 'quit', 'close'])  # TLS is part of the connection: no STARTTLS step
        self.assertEqual(self.calls['connect'], [(GOOD_IP, 465)])

    def test_starttls_not_offered_or_failing_refuses_before_login_and_mail(self):
        for label, kw in (('not offered', {'starttls': False}), ('refused', {'starttls_code': 454})):
            with self.subTest(label):
                provider = self.build(**kw)
                result = self.send(provider)
                self.assertEqual(result.result, 'REFUSED')
                self.assertTrue(result.reason.startswith('STARTTLS'))
                self.assertNotIn('login', self.smtp.log)
                self.assertNotIn('mail', self.smtp.log)
                self.assertTrue(self.sock.closed)

    def test_destinations_that_are_not_public_are_refused_whole_and_nothing_is_dialled_or_counted(self):
        for label, answers in (('loopback', ['127.0.0.1']), ('private', ['10.1.2.3']), ('link-local', ['169.254.1.1']), ('mixed', [GOOD_IP, '192.168.0.9']), ('v6 loopback', ['::1']),
                               ('mapped', ['::ffff:93.184.216.34']), ('empty', []), ('garbage', ['not-an-ip']), ('unspecified', ['0.0.0.0'])):
            with self.subTest(label):
                provider = self.build(answers=answers)
                result = self.send(provider)
                self.assertEqual(result.result, 'REFUSED', label)
                self.assertTrue(result.reason.startswith('DESTINATION_'))
                self.assertEqual(self.calls['connect'], [])
                self.assertEqual(self.calls['factory'], [])
                self.assertEqual(self.ledger_lines(), [])
        # the real default connector refuses a non-public address on its own too
        with self.assertRaises(OSError):
            smtp_notify._connect('127.0.0.1', 587, 1)

    def test_ipv4_is_tried_first_and_only_one_connection_is_made(self):
        provider = self.build(answers=['2606:4700:4700::1111', GOOD_IP, '93.184.216.35'])
        self.assertEqual(self.send(provider).result, 'ACCEPTED')
        self.assertEqual(self.calls['connect'], [(GOOD_IP, 587)])
        provider = self.build(answers=['2606:4700:4700::1111'])
        self.send(provider)
        self.assertEqual(self.calls['connect'], [('2606:4700:4700::1111', 587)])

    def test_a_peer_that_is_not_the_approved_address_is_refused_before_any_smtp(self):
        for label, peer in (('other ip', ('93.184.216.99', 587)), ('other port', (GOOD_IP, 25)), ('private', ('10.0.0.1', 587)), ('garbage', ('x', 1))):
            with self.subTest(label):
                provider = self.build(peer=peer)
                result = self.send(provider)
                self.assertEqual(result, SendResult('REFUSED', 'PEER_MISMATCH'))
                self.assertEqual(self.calls['factory'], [])
                self.assertTrue(self.sock.closed)

    def test_a_grant_with_port_and_security_that_do_not_match_or_a_blocked_host_is_refused_first(self):
        for label, g in (('security', grant(smtp={'port': 587, 'security': 'TLS'})), ('port', grant(smtp={'port': 25, 'security': 'STARTTLS'})),
                         ('plain', grant(smtp={'port': 587, 'security': 'NONE'})), ('host', grant(smtp={'host': 'localhost'})), ('ip', grant(smtp={'host': GOOD_IP}))):
            with self.subTest(label):
                provider = self.build(g=g)
                result = self.send(provider)
                self.assertEqual(result.result, 'REFUSED')
                self.assertEqual(self.calls, {'resolve': [], 'connect': [], 'creds': [], 'factory': []})

    def test_results_are_classified(self):
        cases = (('accepted', {}, 'ACCEPTED'), ('rcpt all 550', {'rcpt': (550,)}, 'REJECTED'), ('rcpt all 451', {'rcpt': (451,)}, 'TEMPORARY'),
                 ('mail 553', {'mail': 553}, 'REJECTED'), ('mail 421', {'mail': 421}, 'TEMPORARY'), ('data 554', {'data': 554}, 'REJECTED'), ('data 451', {'data': 451}, 'TEMPORARY'),
                 ('data refused 554', {'data': smtplib.SMTPDataError(554, b'no')}, 'REJECTED'), ('data refused 451', {'data': smtplib.SMTPDataError(451, b'later')}, 'TEMPORARY'),
                 ('disconnect in data', {'data': smtplib.SMTPServerDisconnected('x')}, 'UNCERTAIN'), ('timeout in data', {'data': TimeoutError()}, 'UNCERTAIN'),
                 ('os error in data', {'data': ConnectionResetError()}, 'UNCERTAIN'), ('odd reply', {'data': 199}, 'UNCERTAIN'),
                 ('login 535', {'login': smtplib.SMTPAuthenticationError(535, b'bad ' + PASSWORD.encode())}, 'REFUSED'),
                 ('login 454', {'login': smtplib.SMTPAuthenticationError(454, b'try later')}, 'TEMPORARY'), ('no auth', {'login': smtplib.SMTPNotSupportedError('x')}, 'REFUSED'),
                 ('login disconnect', {'login': smtplib.SMTPServerDisconnected('x')}, 'TEMPORARY'))
        for label, kw, expected in cases:
            with self.subTest(label):
                result = self.send(self.build(**kw))
                self.assertEqual(result.result, expected, (label, result))
                if expected != 'ACCEPTED':
                    self.assertNotIn(PASSWORD, repr(result))
        partial = self.send(self.build(rcpt=(250, 550), g=grant(recipients=['a@example.org', 'b@example.org'])))
        self.assertEqual(partial, SendResult('PARTIAL', 'SOME_RECIPIENTS_REFUSED'))
        both = self.send(self.build(rcpt=(250, 250), g=grant(recipients=['a@example.org', 'b@example.org'])))
        self.assertEqual(both.result, 'ACCEPTED')
        self.assertEqual(self.smtp.recipients, ['a@example.org', 'b@example.org'])

    def test_connect_dns_timeout_and_tls_failures_are_temporary_and_nothing_is_sent(self):
        for label, kw, reason in (('dns error', {'answers': OSError('boom ' + PASSWORD)}, 'DNS_FAILED'), ('connect timeout', {'peer': TimeoutError()}, 'CONNECT_TIMEOUT'),
                                  ('connect refused', {'peer': ConnectionRefusedError()}, 'CONNECT_FAILED')):
            with self.subTest(label):
                provider = self.build(**kw)
                result = self.send(provider)
                self.assertEqual(result, SendResult('TEMPORARY', reason))
                self.assertNotIn('data', self.smtp.log)
        slow = self.build()
        slow.resolver = lambda host, port: threading.Event().wait(2) or [GOOD_IP]
        with mock.patch.object(smtp_notify, 'RESOLVE_TIMEOUT', 0.05):
            self.assertEqual(self.send(slow), SendResult('TEMPORARY', 'DNS_TIMEOUT'))
        self.assertEqual(self.calls['connect'], [])

    def test_a_credential_problem_refuses_and_its_text_goes_nowhere(self):
        for label, creds in (('raises', RuntimeError('store said ' + PASSWORD)), ('empty', ('', '')), ('wrong type', ('u', None))):
            with self.subTest(label):
                provider = self.build(creds=creds)
                result = self.send(provider)
                self.assertEqual(result, SendResult('REFUSED', 'CREDENTIAL_UNAVAILABLE'))
                self.assertEqual(self.calls['resolve'], [])  # no lookup, connection or count for a mail that cannot be authenticated
                self.assertEqual(self.ledger_lines(), [])

    def test_ledger_limits_stop_the_provider_before_it_dials(self):
        g = grant(max_messages_total=2, max_messages_per_day=2)
        provider = self.build(g=g)
        self.assertEqual([self.send(provider, g, at(i)).result for i in range(2)], ['ACCEPTED', 'ACCEPTED'])
        dialled = len(self.calls['connect'])
        result = self.send(provider, g, at(5))
        self.assertEqual(result, SendResult('REFUSED', 'LIMIT_TOTAL'))
        self.assertEqual(len(self.calls['connect']), dialled)
        smtp_notify.ledger_file(self.data, g['grant_id']).write_text('garbage\n', encoding='utf-8')
        self.assertEqual(self.send(provider, g, at(6)), SendResult('REFUSED', 'LEDGER_CORRUPT'))

    def test_the_password_appears_in_no_file_no_result_and_no_exception_text(self):
        for kw in ({}, {'login': smtplib.SMTPAuthenticationError(535, PASSWORD.encode())}, {'data': smtplib.SMTPServerDisconnected(PASSWORD)}):
            self.send(self.build(**kw))
        for f in self.tmp.rglob('*'):
            if f.is_file():
                self.assertNotIn(PASSWORD.encode(), f.read_bytes(), str(f))
                self.assertNotIn(b'mailuser', f.read_bytes(), str(f))

    def test_the_pinned_smtplib_classes_use_the_given_socket_and_never_resolve_or_leak_the_pc_name(self):
        class Sock(FakeSock):
            def __init__(self):
                super().__init__((GOOD_IP, 587))
                self.sent = []
                self.replies = io.BytesIO(b'220 ready\r\n250-mail\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n')

            def makefile(self, mode='rb', *a, **k):
                return self.replies

            def sendall(self, data):
                self.sent.append(bytes(data))

        sock = Sock()
        with mock.patch('socket.create_connection', side_effect=AssertionError('smtplib dialled by itself')), mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            client = smtp_notify._make_smtp('STARTTLS', 'smtp.mail-provider.com', 587, sock, smtp_notify.ssl.create_default_context(), 'siteproof.local', 5)
            client.ehlo('siteproof.local')
            self.assertTrue(client.has_extn('starttls'))
            self.assertEqual(client._host, 'smtp.mail-provider.com')  # the name TLS is checked against: the granted host
            with self.assertRaises(OSError):
                client._get_socket('smtp.mail-provider.com', 587, 5)  # the socket is single use
        sent = b''.join(sock.sent).lower()
        self.assertIn(b'ehlo siteproof.local', sent)
        self.assertEqual(sent.strip(), b'ehlo siteproof.local')  # nothing else, in particular not the name of this PC
        provider = self.build()
        provider.smtp_factory = smtp_notify._make_smtp  # implicit TLS on a socket that is not a TLS-capable socket: fails closed, nothing is sent
        result = self.send(provider, grant(smtp={'port': 465, 'security': 'TLS'}))
        self.assertEqual(result.result, 'TEMPORARY')

    def test_a_drip_feeding_server_cannot_stretch_the_session_past_the_deadline(self):
        ours, theirs = smtp_notify.socket.socketpair()  # a local pair, no network
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        stop = threading.Event()

        def drip():  # a greeting that never ends: every read succeeds in time, the sum never would
            try:
                theirs.send(b'220 ')
                while not stop.wait(0.05):
                    theirs.send(b'x')
            except OSError:
                return
        threading.Thread(target=drip, daemon=True).start()
        self.addCleanup(stop.set)

        class Proxy:
            def __init__(self, real):
                self.real = real

            def getpeername(self):
                return GOOD_IP, 587

            def __getattr__(self, name):
                return getattr(self.real, name)
        provider = self.build()
        provider.connector = lambda ip, port, timeout: Proxy(ours)
        provider.smtp_factory = smtp_notify._make_smtp  # the real pinned smtplib on a real (local) socket
        started = smtp_notify.time.monotonic()
        with mock.patch.object(smtp_notify, 'DEADLINE_SECONDS', 0.4):
            result = self.send(provider)
        self.assertEqual(result, SendResult('TEMPORARY', 'TIMEOUT'))
        self.assertLess(smtp_notify.time.monotonic() - started, 3)

    def test_the_deadline_before_data_is_temporary_and_after_data_started_is_uncertain(self):
        class Hang(FakeSmtp):
            def __init__(self, where, **kw):
                super().__init__(**kw)
                self.where = where

            def _wait(self, name):
                if self.where == name:
                    self.sock.cut.wait(5)  # blocked until the watchdog cuts the connection
                    raise smtplib.SMTPServerDisconnected('cut')

            def ehlo(self, name=None):
                self._wait('ehlo')
                return super().ehlo(name)

            def data(self, payload):
                self.log.append('data')
                self._wait('data')
        for where, expected in (('ehlo', SendResult('TEMPORARY', 'TIMEOUT')), ('data', SendResult('UNCERTAIN', 'DATA_INTERRUPTED'))):
            with self.subTest(where):
                provider = self.build(smtp=Hang(where))
                started = smtp_notify.time.monotonic()
                with mock.patch.object(smtp_notify, 'DEADLINE_SECONDS', 0.3):
                    self.assertEqual(self.send(provider), expected)
                self.assertLess(smtp_notify.time.monotonic() - started, 3)
                self.assertTrue(self.sock.cut.is_set())

    def test_the_mock_provider_hands_over_to_a_file_counts_the_ledger_and_scripts_results(self):
        mock_file = self.tmp / 'mock.jsonl'
        provider = MockSmtpProvider(mock_file, ['TEMPORARY', SendResult('REJECTED', 'X')])
        g = grant(max_messages_total=3)
        msg = smtp_notify.build_message(g, notice_id='n1', site_id='s', subject='subj', body='b', now=NOW)
        self.assertEqual([provider.send(g, self.data, msg, at(i)).result for i in range(3)], ['TEMPORARY', 'REJECTED', 'ACCEPTED'])
        self.assertEqual(provider.send(g, self.data, msg, at(5)).reason, 'LIMIT_TOTAL')
        self.assertEqual(len(mock_file.read_text('utf-8').splitlines()), 3)
        self.assertTrue(provider.can_send())


# ---- the outbox
class Outbox(Tmp):
    def test_many_threads_and_processes_announce_an_event_exactly_once(self):
        root = self.make_site().root
        made = []

        def go():
            made.append(notifications.Outbox(root).add('same-key', 'FAILURE', 't', 'T', 'B', 'http'))
        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for n in made if n), 1)
        code = 'from src.noxiworks.notifications import Outbox; import sys; Outbox(sys.argv[1]).add("proc-key", "FAILURE", "t", "T", "B", "http")'
        procs = [subprocess.Popen([sys.executable, '-B', '-c', code, str(root)], cwd=ROOT) for _ in range(3)]
        for p in procs:
            self.assertEqual(p.wait(60), 0)
        self.assertEqual(sorted(n['key'] for n in notifications.Outbox(root).all()), ['proc-key', 'same-key'])

    def test_a_torn_line_never_swallows_the_next_notice_and_old_records_keep_their_shape(self):
        root = self.make_site().root
        box = notifications.Outbox(root)
        first = box.add('k1', 'FAILURE', 't', 'T', 'B', 'http', 'S')
        with (root / 'notifications.jsonl').open('a', encoding='utf-8') as f:
            f.write('{"id": "torn", "key": "kx"')  # a crash in the middle of a write
        second = notifications.Outbox(root).add('k2', 'RECOVERY', 't', 'T', 'B', 'http')
        self.assertEqual([n['key'] for n in notifications.Outbox(root).all()], ['k1', 'k2'])
        self.assertEqual(first['delivery'], {'app': 'RECORDED', 'sink': None, 'received': 'UNKNOWN'})
        self.assertEqual((first['id'], first['subject'], second['subject']), (notifications.notice_id('k1'), 'S', '[SiteProof] T'))
        self.assertIsNone(notifications.Outbox(root).add('k1', 'FAILURE', 't', 'T', 'B', 'http'))


# ---- the dispatcher
class Dispatch(Tmp):
    def setUp(self):
        super().setUp()
        self.site = self.make_site()
        self.mock_file = self.tmp / 'mock.jsonl'
        self.g = grant()
        self.mock = MockSmtpProvider(self.mock_file)
        self.d = self.dispatcher()

    def dispatcher(self, site=None, provider=None, g=None):
        g = g or self.g
        return Dispatcher(site or self.site, provider or self.mock, grant=lambda now: (g, []))

    def notice(self, key, minutes, kind='FAILURE', site=None):
        return notifications.Outbox((site or self.site).root).add(key, kind, format_utc(at(minutes)), 'T:' + key, 'body ' + key + '\n※ SNSへの送信成功は…\n', 'http', '[SiteProof] ' + key)

    def on(self, d=None, now=NOW):
        d = d or self.d
        d.set_channel(True, now)
        d.set_site(True, now)

    def results(self, d=None):
        return [(e['notice_id'], e['attempt'], e['result']) for e in (d or self.d).entries()]

    def test_everything_is_off_by_default_and_the_app_notice_is_still_recorded(self):
        self.notice('k1', 0)
        self.assertEqual(self.d.run(at(1))['status'], 'off')
        s = self.d.status(at(1))
        self.assertEqual((s['configured'], s['enabled'], s['site_enabled'], s['pending']), (False, False, False, 0))
        self.assertEqual(self.mock.calls, [])
        self.assertEqual(len(notifications.Outbox(self.site.root).all()), 1)
        self.d.set_channel(True, NOW)
        self.assertEqual(self.d.run(at(1))['status'], 'site-off')  # a site must be turned on explicitly
        self.assertFalse(self.d.site_config()['enabled'])
        for f in (self.data / 'notify' / 'email.json', self.site.root / 'email-notify.json'):
            if f.is_file():
                text = f.read_text('utf-8').lower()
                self.assertTrue('password' not in text and 'user' not in text)

    def test_enabling_needs_a_valid_grant_and_a_provider_that_can_send(self):
        broken = Dispatcher(self.site, self.mock, grant=lambda now: (None, ['通知許可がありません']))
        with self.assertRaises(ValueError) as cm:
            broken.set_channel(True, NOW)
        self.assertIn('通知許可がありません', str(cm.exception))
        with self.assertRaises(ValueError):
            broken.set_site(True, NOW)
        real = Dispatcher(self.site, grant=lambda now: (self.g, []))  # the real provider: its kill switch is off
        with self.assertRaises(ValueError) as cm:
            real.set_channel(True, NOW)
        self.assertIn('無効', str(cm.exception))
        self.assertFalse(real.channel()['enabled'])
        self.assertFalse(real.status(NOW)['can_enable'])
        self.assertTrue(self.d.status(NOW)['can_enable'])
        (self.data / 'notify').mkdir(exist_ok=True)
        (self.site.root / 'email-notify.json').write_text(json.dumps({'enabled': True, 'enabled_at': format_utc(NOW)}), encoding='utf-8')
        (self.data / 'notify' / 'email.json').write_text(json.dumps({'enabled': True, 'enabled_at': format_utc(NOW), 'kinds': list(notify_dispatch.GROUPS)}), encoding='utf-8')
        self.assertEqual(real.run(at(1)), {'status': 'disabled', 'sent': 0, 'results': []})  # even a hand-edited "on" sends nothing with the kill switch off

    def test_enabling_never_mails_the_backlog_only_what_happens_afterwards(self):
        self.notice('old', -30)
        self.on()
        self.assertEqual(self.d.run(at(1))['sent'], 0)
        self.assertEqual(self.d.status(at(1))['pending'], 0)
        self.notice('new', 1)
        self.assertEqual(self.d.status(at(2))['pending'], 1)
        self.assertEqual(self.d.run(at(2))['sent'], 1)
        self.assertEqual([c['subject'] for c in self.mock.calls], ['[SiteProof] new'])

    def test_a_pending_notice_is_accepted_once_with_the_attempt_written_first(self):
        self.on()
        self.notice('k1', 1)
        order = []
        real_send = self.mock.send
        self.mock.send = lambda *a: (order.append([r['result'] for r in self.d._lines()]), real_send(*a))[1]
        self.assertEqual(self.d.run(at(2))['sent'], 1)
        self.assertEqual(order, [['ATTEMPT']])  # the ATTEMPT line existed when the provider was called
        self.assertEqual(self.results(), [(notifications.notice_id('k1'), 1, 'ACCEPTED')])
        self.assertEqual(self.d.run(at(3))['sent'], 0)
        self.assertEqual(len(self.mock.calls), 1)
        mail = self.mock.calls[0]
        self.assertEqual((mail['from'], mail['to']), ('alerts@my-site.com', 'owner@example.org'))
        self.assertNotIn('SNS', mail['body'])
        line = [json.loads(x) for x in (self.site.root / 'deliveries.jsonl').read_text('utf-8').splitlines()][-1]
        self.assertEqual({k: line[k] for k in ('result', 'channel', 'grant_id', 'attempt')}, {'result': 'ACCEPTED', 'channel': 'EMAIL', 'grant_id': 'notify-test-1', 'attempt': 1})
        self.assertIn('notice_id', line)
        self.assertEqual(notifications.Outbox(self.site.root).all()[0]['delivery']['received'], 'UNKNOWN')  # the notice itself is unchanged by the mail

    def test_two_dispatchers_and_a_restart_never_send_the_same_notice_twice(self):
        self.on()
        self.notice('k1', 1)
        other = self.dispatcher(SimpleNamespace(root=self.site.root, info=self.site.info))
        self.assertEqual(self.d.run(at(2))['sent'], 1)
        self.assertEqual(other.run(at(2))['sent'], 0)
        self.assertEqual(self.dispatcher().run(at(3))['sent'], 0)
        self.assertEqual(len(self.mock.calls), 1)
        with filelock.held(self.data / 'notify' / 'dispatch.lock'):
            self.notice('k2', 4)
            self.assertEqual(self.d.run(at(5)), 'busy')  # one run at a time, not waited for
        self.assertEqual(self.d.run(at(5))['sent'], 1)

    def test_temporary_failures_back_off_then_give_up_without_a_fourth_attempt(self):
        self.mock.script = ['TEMPORARY'] * 5
        self.on()
        self.notice('k1', 1)
        sent = [self.d.run(at(m))['sent'] for m in (2, 4, 7, 10, 37, 38, 90, 91)]
        self.assertEqual(sent, [1, 0, 1, 0, 1, 0, 0, 0])  # attempts at +2 min, +7 min (5 min later), +37 min (30 min later); the next look records GAVE_UP
        self.assertEqual(len(self.mock.calls), 3)
        self.assertEqual(self.results(), [(notifications.notice_id('k1'), 1, 'TEMPORARY'), (notifications.notice_id('k1'), 2, 'TEMPORARY'), (notifications.notice_id('k1'), 3, 'TEMPORARY'),
                                          (notifications.notice_id('k1'), 3, 'GAVE_UP')])
        self.assertEqual(self.d.status(at(91))['pending'], 0)

    def test_a_temporary_failure_followed_by_success_is_one_mail_in_the_end(self):
        self.mock.script = ['TEMPORARY']
        self.on()
        self.notice('k1', 1)
        self.d.run(at(2))
        self.assertEqual(self.d.run(at(8))['sent'], 1)
        self.assertEqual([r for _, _, r in self.results()], ['TEMPORARY', 'ACCEPTED'])
        self.assertEqual(self.d.run(at(60))['sent'], 0)

    def test_final_results_are_never_resent(self):
        for result in ('UNCERTAIN', 'REJECTED', 'PARTIAL'):
            with self.subTest(result):
                site = self.make_site('site-' + result.lower().ljust(8, 'x')[:8])
                provider = MockSmtpProvider(script=[result])
                d = Dispatcher(site, provider, grant=lambda now: (self.g, []))
                self.on(d)
                self.notice('k1', 1, site=site)
                d.run(at(2))
                for m in (10, 50, 500):
                    d.run(at(m))
                self.assertEqual(len(provider.calls), 1)
                self.assertEqual(self.results(d)[-1][2], result)

    def test_a_provider_that_raises_is_uncertain_and_not_resent_and_a_crash_leftover_attempt_too(self):
        self.mock.script = [RuntimeError('boom')]
        self.on()
        self.notice('k1', 1)
        self.d.run(at(2))
        self.d.run(at(60))
        self.assertEqual(len(self.mock.calls), 1)  # handed to the provider once, never again
        self.assertEqual(self.results()[-1][2], 'UNCERTAIN')
        self.notice('k2', 70)
        nid = notifications.Outbox(self.site.root).all()[-1]['id']
        notifications.append_jsonl(self.site.root / 'deliveries.jsonl', {'notice_id': nid, 'attempt': 1, 'at': format_utc(at(71)), 'result': 'ATTEMPT', 'reason': '', 'channel': 'EMAIL',
                                                                         'grant_id': 'notify-test-1'})  # the process died right after this line
        self.assertEqual(self.d.run(at(75))['sent'], 0)
        self.assertEqual(self.d.run(at(500))['sent'], 0)
        self.assertEqual(self.d.entries()[-1]['result'], 'UNCERTAIN')
        self.assertEqual(self.d.entries()[-1]['label'], '送信結果不明（再送しません）')
        self.assertEqual(self.d.status(at(75))['pending'], 0)

    def test_a_torn_delivery_line_is_skipped(self):
        self.on()
        self.notice('k1', 1)
        self.d.run(at(2))
        with (self.site.root / 'deliveries.jsonl').open('a', encoding='utf-8') as f:
            f.write('{"notice_id": "x", "att')
        self.notice('k2', 3)
        self.assertEqual(self.d.run(at(4))['sent'], 1)
        self.assertEqual(self.d.run(at(5))['sent'], 0)

    def test_stopping_sends_nothing_and_what_was_queued_is_not_mailed_after_a_restart(self):
        self.on()
        self.notice('during-on', 1)
        self.d.set_channel(False, at(2))
        self.notice('while-off', 3)
        self.assertEqual(self.d.run(at(4))['status'], 'off')
        self.assertEqual(self.d.channel()['stopped_reason'], 'USER')
        self.d.set_channel(True, at(10))
        self.assertEqual(self.d.run(at(11))['sent'], 0)  # both are older than the new enabled_at
        self.notice('after', 12)
        self.assertEqual(self.d.run(at(13))['sent'], 1)
        self.d.set_site(False, at(14))
        self.notice('site-off', 15)
        self.assertEqual(self.d.run(at(16))['status'], 'site-off')
        self.assertEqual(len(self.mock.calls), 1)

    def test_nothing_older_than_24_hours_is_sent_it_is_recorded_once_as_expired(self):
        self.d.set_channel(True, at(-60 * 30))
        self.d.set_site(True, at(-60 * 30))
        self.notice('stale', -60 * 25)
        self.notice('fresh', -60 * 23)
        out = self.d.run(NOW)
        self.assertEqual(out['sent'], 1)
        self.d.run(at(1))
        self.assertEqual([(r) for _, _, r in self.results()], ['EXPIRED', 'ACCEPTED'])
        self.assertEqual(self.d.entries()[0]['label'], '24時間を過ぎたため送りません')
        self.assertEqual(len(self.mock.calls), 1)

    def test_a_recovery_is_mailed_even_when_its_failure_never_was(self):
        self.notice('failure-before', -10, 'FAILURE')
        self.on()
        self.notice('recovery', 1, 'RECOVERY')
        self.d.run(at(2))
        self.assertEqual([c['subject'] for c in self.mock.calls], ['[SiteProof] recovery'])

    def test_only_the_chosen_kinds_are_mailed(self):
        self.on()
        self.d.set_kinds(['FAILURE', 'TLS'], at(0))
        for key, kind in (('a', 'FAILURE'), ('b', 'RECOVERY'), ('c', 'CONFIRMED'), ('d', 'TLS_WARN'), ('e', 'IMAGE_CHANGED'), ('f', 'UNKNOWN'), ('g', 'TLS_EXPIRED')):
            self.notice(key, 1, kind)
        self.d.run(at(2))
        self.assertEqual(sorted(c['subject'] for c in self.mock.calls), ['[SiteProof] a', '[SiteProof] d', '[SiteProof] g'])
        self.d.set_kinds(list(notify_dispatch.GROUPS), at(3))  # turning the rest on later: still inside 24 h, so they are mailed now
        self.d.run(at(4))
        self.assertEqual(len(self.mock.calls), 7)
        with self.assertRaises(ValueError):
            self.d.set_kinds(['NOPE'], at(5))

    def test_at_most_ten_messages_per_run(self):
        self.on()
        for i in range(12):
            self.notice(f'k{i:02d}', 1)
        self.assertEqual(self.d.run(at(2))['sent'], 10)
        self.assertEqual(self.d.run(at(3))['sent'], 2)

    def test_two_sites_in_one_data_folder_are_switched_independently(self):
        other = self.make_site('site-bbbbbbbb')
        db = self.dispatcher(other)
        self.d.set_channel(True, NOW)
        self.d.set_site(True, NOW)
        self.notice('a1', 1)
        self.notice('b1', 1, site=other)
        self.assertEqual(db.run(at(2))['status'], 'site-off')
        self.assertEqual(self.d.run(at(2))['sent'], 1)
        self.assertEqual([c['subject'] for c in self.mock.calls], ['[SiteProof] a1'])
        db.set_site(True, at(3))
        self.assertEqual(db.run(at(4))['sent'], 0)  # b1 happened before B was turned on
        self.notice('b2', 5, site=other)
        self.assertEqual(db.run(at(6))['sent'], 1)
        self.assertTrue(smtp_notify.ledger_file(self.data, 'notify-test-1').is_file())
        self.assertEqual(len(smtp_notify.ledger_file(self.data, 'notify-test-1').read_text('utf-8').splitlines()), 2)  # one grant, one shared count
        self.assertEqual([r for _, _, r in self.results(db)], ['ACCEPTED'])
        self.assertEqual([r for _, _, r in self.results(self.d)], ['ACCEPTED'])

    def test_a_refusal_sends_nothing_keeps_the_attempt_and_pauses_the_dispatch(self):
        self.mock.script = [SendResult('REFUSED', 'CREDENTIAL_UNAVAILABLE')]
        self.on()
        self.notice('k1', 1)
        out = self.d.run(at(2))
        self.assertEqual((out['status'], out['sent']), ('refused', 0))
        self.assertEqual(self.d.run(at(3))['status'], 'waiting')
        self.assertEqual(self.d.run(at(8))['sent'], 1)
        self.assertEqual([(a, r) for _, a, r in self.results()], [(1, 'REFUSED'), (1, 'ACCEPTED')])  # the refused one did not use up an attempt
        self.mock.script = [SendResult('REFUSED', 'AUTH_FAILED')]
        self.notice('k2', 20)
        self.d.run(at(21))
        self.assertEqual(self.d.run(at(60))['status'], 'waiting')  # an authentication failure is not hammered: one hour
        self.assertEqual(self.d.run(at(90))['sent'], 1)

    def test_the_real_provider_behind_the_kill_switch_sends_nothing_and_a_disabled_signal_is_a_refusal(self):
        with mock.patch.object(smtp_notify, 'NOTIFY_EXTERNAL_ENABLED', True):
            d = self.dispatcher(provider=SmtpProvider())
            self.on(d)
        self.notice('k1', 1)
        out = d.run(at(2))  # the switch is off again now
        self.assertEqual(out['status'], 'disabled')
        self.assertEqual(self.results(d), [])
        self.mock.script = [smtp_notify.ExternalDisabled('off')]
        self.on()
        self.notice('k2', 3)
        out = self.d.run(at(4))
        self.assertEqual((out['status'], out['reason']), ('refused', 'EXTERNAL_DISABLED'))

    def test_a_missing_or_expired_grant_sends_nothing_does_not_stop_the_channel_and_resumes(self):
        state = {'g': (None, ['通知許可が有効期間外です'])}
        d = Dispatcher(self.site, self.mock, grant=lambda now: state['g'])
        state['g'] = (self.g, [])
        self.on(d)
        self.notice('k1', 1)
        state['g'] = (None, ['通知許可が有効期間外です'])
        out = d.run(at(2))
        self.assertEqual((out['status'], out['sent']), ('no-grant', 0))
        s = d.status(at(2))
        self.assertTrue(s['enabled'])
        self.assertFalse(s['grant']['valid'])
        self.assertIn('有効期間外', s['block_reason'])
        self.assertFalse(s['active'])
        self.assertEqual(self.mock.calls, [])
        state['g'] = (self.g, [])
        self.assertEqual(d.run(at(3))['sent'], 1)

    def test_the_grant_is_checked_before_every_message(self):
        checks = []

        def check(now):
            checks.append(now)
            return self.g, []
        d = Dispatcher(self.site, self.mock, grant=check)
        self.on(d)
        checks.clear()
        for i in range(3):
            self.notice(f'k{i}', 1)
        d.run(at(2))
        self.assertEqual(len(checks), 3)

    def test_the_test_message_is_an_explicit_rate_limited_never_retried_send(self):
        self.assertTrue(self.d.send_test(at(0), 'owner')['ok'])  # works before the channel is turned on
        self.assertEqual(self.d.send_test(at(0), 'owner')['result'], 'RATE_LIMITED')
        self.assertEqual(self.d.send_test(at(0) + timedelta(seconds=59), 'owner')['result'], 'RATE_LIMITED')
        self.assertTrue(self.d.send_test(at(0) + timedelta(seconds=61), 'owner')['ok'])
        self.assertEqual(len(self.mock.calls), 2)
        entries = [e for e in self.d.entries() if e.get('test')]
        self.assertEqual((len(entries), entries[0]['actor'], entries[0]['title']), (2, 'owner', 'テスト送信'))
        self.mock.script = ['TEMPORARY']
        self.assertEqual(self.d.send_test(at(5), 'owner')['result'], 'TEMPORARY')
        self.on(self.d, at(6))
        self.d.run(at(30))
        self.assertEqual(len(self.mock.calls), 3)  # the failed test was not retried
        bad = Dispatcher(self.site, self.mock, grant=lambda now: (None, ['x']))
        self.assertEqual(bad.send_test(at(60), 'owner')['result'], 'REFUSED')
        killed = Dispatcher(self.site, grant=lambda now: (self.g, []))
        self.assertEqual(killed.send_test(at(60), 'owner')['result'], 'REFUSED')
        self.assertEqual(len(self.mock.calls), 3)

    def test_the_status_for_the_screen_never_says_received(self):
        self.on()
        self.mock.script = ['ACCEPTED', 'UNCERTAIN', 'TEMPORARY', 'REJECTED', 'PARTIAL']
        for i in range(5):
            self.notice(f'k{i}', 1 + i)
        self.d.run(at(10))
        s = self.d.status(at(11))
        g = s['grant']
        self.assertEqual((g['valid'], g['host'], g['port'], g['security'], g['recipients']), (True, 'smtp.mail-provider.com', 587, 'STARTTLS', ['o***@example.org']))
        self.assertEqual((g['remaining_total'], g['remaining_today'], g['days_left']), (95, 15, 29))
        self.assertEqual((s['enabled'], s['site_enabled'], s['external_enabled'], s['can_enable'], s['block_reason'], s['active']), (True, True, True, True, None, True))
        labels = [e['label'] for e in s['recent']]
        self.assertEqual(len(labels), 5)
        self.assertEqual(s['last_result'], list(reversed(s['recent']))[-1])
        self.assertIn('送信受付済み（受信は未確認）', labels)
        self.assertIn('送信結果不明（再送しません）', labels)
        for label in labels:
            self.assertNotIn('配信完了', label)
            self.assertNotIn('受信しました', label)
        self.assertNotIn('owner@', json.dumps(s, ensure_ascii=False))  # only the masked form
        for i in range(30):
            self.notice(f'm{i}', 20)
        self.assertEqual(len(self.d.status(at(30))['recent']), 5)  # only what was attempted is listed
        self.assertLessEqual(len(self.d.status(at(30))['recent']), notify_dispatch.RECENT)

    def test_a_ledger_that_cannot_be_trusted_blocks_enabling_and_shows_in_the_status(self):
        f = smtp_notify.ledger_file(self.data, 'notify-test-1')
        f.parent.mkdir(parents=True)
        f.write_text('garbage\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.d.set_channel(True, NOW)
        s = self.d.status(NOW)
        self.assertFalse(s['grant']['valid'])
        self.assertFalse(s['can_enable'])


class OneAuthMechanism(unittest.TestCase):
    """The real pinned smtplib class against a scripted server that refuses the first AUTH and hangs up (what Gmail did on 2026-11-27)."""

    def serve(self, server, script, seen):
        f = server.makefile('rwb')
        f.write(b'220 test ESMTP\r\n')
        f.flush()
        for line in f:
            cmd = line.decode('ascii', 'replace').strip()
            seen.append(' '.join(cmd.split(' ')[:2]) if cmd.upper().startswith('AUTH') else cmd.split(' ')[0])
            reply = script(cmd)
            if reply is None:
                break
            f.write(reply)
            f.flush()
            if reply.startswith(b'535'):
                break  # refused, then the server hangs up
        f.close()
        server.close()

    def session(self, script):
        client, server = socket.socketpair()
        seen = []
        t = threading.Thread(target=self.serve, args=(server, script, seen), daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(client.close)
        return smtp_notify._Pinned(client, 'smtp.example.com', 587, smtp_notify.LOCAL_HOSTNAME, 5), seen

    def test_a_refused_login_is_a_refusal_not_a_lost_connection(self):
        def script(cmd):
            if cmd.upper().startswith('EHLO'):
                return b'250-test\r\n250 AUTH PLAIN LOGIN\r\n'
            if cmd.upper().startswith('AUTH'):
                return b'535 5.7.8 rejected\r\n'
            return None
        smtp, seen = self.session(script)
        with self.assertRaises(smtplib.SMTPAuthenticationError) as e:
            smtp.login('user@example.com', 'not-the-password')
        self.assertEqual(e.exception.smtp_code, 535)
        self.assertEqual([c for c in seen if c.upper().startswith('AUTH')], ['AUTH PLAIN'])  # ONE mechanism, never a second try on a closed line

    def test_login_falls_back_to_login_only_when_plain_is_not_offered(self):
        replies = iter([b'334 VXNlcm5hbWU6\r\n', b'334 UGFzc3dvcmQ6\r\n', b'235 ok\r\n'])

        def script(cmd):
            if cmd.upper().startswith('EHLO'):
                return b'250-test\r\n250 AUTH LOGIN\r\n'
            if cmd.upper().startswith('QUIT'):
                return None
            return next(replies)
        smtp, seen = self.session(script)
        self.assertEqual(smtp.login('user@example.com', 'pw')[0], 235)
        self.assertEqual([c for c in seen if c.upper().startswith('AUTH')], ['AUTH LOGIN'])


if __name__ == '__main__':
    unittest.main()

"""Long-term operation helpers (offline, temporary folders only): bounded history, explicit archive, usage, gaps, stop reasons, expiry notices."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import filelock, notifications, retention
from src.noxiworks.retention import ArchiveRefused, HttpHistory

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def at(minutes=0):
    return NOW + timedelta(minutes=minutes)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-retention-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        self.site = self.data / 'sites' / 'site-aaaaaaaa'
        self.site.mkdir(parents=True)


class History(Tmp):
    def hist(self, **kw):
        return HttpHistory(self.site / 'http-history.jsonl', **kw)

    def test_a_full_history_says_so_and_never_grows_loses_or_truncates(self):
        h = self.hist(max_records=3)
        for i in range(3):
            self.assertTrue(h.append({'n': i})['ok'])
        before = h.path.read_bytes()
        result = h.append({'n': 3})
        self.assertEqual((result['ok'], result['full'], result['reason']), (False, True, 'HISTORY_FULL'))
        self.assertEqual(h.path.read_bytes(), before)
        usage = h.usage()
        self.assertEqual((usage['records'], usage['full'], usage['warn']), (3, True, True))
        small = self.hist(max_bytes=60)
        small.path.unlink()
        self.assertTrue(small.append({'a': 'x' * 10})['ok'])
        self.assertFalse(small.append({'a': 'y' * 60})['ok'])
        self.assertLessEqual(small.path.stat().st_size, 60)
        self.assertEqual(small.tail(10), [{'a': 'x' * 10}])

    def test_usage_warns_from_80_percent(self):
        h = self.hist(max_records=10)
        for i in range(7):
            h.append({'n': i})
        self.assertEqual((h.usage()['warn'], h.usage()['full']), (False, False))
        h.append({'n': 7})
        self.assertEqual((h.usage()['warn'], h.usage()['full'], h.usage()['records']), (True, False, 8))
        empty = HttpHistory(self.site / 'none.jsonl')
        self.assertEqual((empty.usage()['records'], empty.usage()['bytes'], empty.tail(5)), (0, 0, []))

    def test_a_torn_last_line_does_not_corrupt_the_next_record(self):
        h = self.hist()
        h.append({'n': 1})
        with h.path.open('a', encoding='utf-8') as f:
            f.write('{"n": 2, "tor')  # a crash in the middle of a write
        self.assertEqual(h.usage()['records'], 2)  # the torn line counts as a record (documented: approximate)
        self.assertTrue(h.append({'n': 3})['ok'])
        self.assertEqual(h.tail(10), [{'n': 1}, {'n': 3}])
        self.assertEqual(self.hist().tail(10), [{'n': 1}, {'n': 3}])
        self.assertEqual(h.path.read_bytes().count(b'\n'), 3)

    def test_the_count_follows_other_writers_and_a_replaced_file(self):
        h = self.hist()
        h.append({'n': 1})
        other = self.hist()
        other.append({'n': 2})
        self.assertEqual(h.usage()['records'], 2)  # incremental: only the new bytes are read
        h.archive(NOW, 'u', True)
        self.assertEqual(h.usage()['records'], 0)
        h.append({'n': 3})
        self.assertEqual(h.usage()['records'], 1)

    def test_tail_reads_from_the_end_and_skips_foreign_lines(self):
        h = self.hist(max_bytes=10 ** 9, max_records=10 ** 9)
        with h.path.open('w', encoding='utf-8') as f:
            for i in range(20000):
                f.write(json.dumps({'n': i, 'text': 'あいう' * 5}, ensure_ascii=False) + '\n')
            f.write('not json\n[1,2]\n{"n": 20000}\n{"torn')
        size = h.path.stat().st_size
        self.assertGreater(size, 1_000_000)
        read = []
        real_open = Path.open

        def counting(self, *a, **k):
            fh = real_open(self, *a, **k)

            class Proxy:
                def __enter__(s):
                    fh.__enter__()
                    return s

                def __exit__(s, *e):
                    return fh.__exit__(*e)

                def seek(s, *x):
                    return fh.seek(*x)

                def read(s, *x):
                    data = fh.read(*x)
                    read.append(len(data))
                    return data
            return Proxy()
        with mock.patch.object(Path, 'open', counting):
            tail = h.tail(5)
        self.assertEqual([r['n'] for r in tail], [19996, 19997, 19998, 19999, 20000])
        self.assertLess(sum(read), size // 5)
        self.assertEqual([r['n'] for r in h.tail(30000)][:3], [0, 1, 2])  # also the whole file when asked
        self.assertEqual(h.tail(0), [])

    def test_archive_needs_confirmation_moves_everything_and_deletes_nothing(self):
        h = self.hist()
        for i in range(5):
            h.append({'n': i})
        before = h.path.read_bytes()
        for bad in (False, None, 'yes', 1):
            with self.assertRaises(ArchiveRefused):
                h.archive(NOW, 'owner', bad)
        self.assertEqual(h.path.read_bytes(), before)  # untouched
        self.assertFalse((self.site / 'history-archive').exists())
        result = h.archive(NOW, 'owner', True)
        archived = self.site / 'history-archive' / 'http-history-20261125T120000Z.jsonl'
        self.assertEqual((result['archived'], result['records'], result['bytes']), (True, 5, len(before)))
        self.assertEqual(archived.read_bytes(), before)
        self.assertFalse(h.path.exists())
        log = [json.loads(x) for x in (self.site / 'maintenance-log.jsonl').read_text('utf-8').splitlines()]
        self.assertEqual((log[0]['action'], log[0]['actor'], log[0]['to']), ('ARCHIVE_HTTP_HISTORY', 'owner', 'history-archive/http-history-20261125T120000Z.jsonl'))
        self.assertTrue(h.append({'n': 'again'})['ok'])  # a fresh file
        h.archive(NOW, 'owner', True)  # the same second: a new name, the first archive stays
        self.assertEqual(len(list((self.site / 'history-archive').iterdir())), 2)
        self.assertEqual(archived.read_bytes(), before)
        self.assertEqual(h.archive(NOW, 'owner', True), {'archived': False, 'reason': 'EMPTY'})


class Notices(Tmp):
    def notice(self, box, key, minutes):
        return box.add(key, 'FAILURE', format_utc(at(minutes)), 't', 'b', 'http')

    def test_archiving_notices_keeps_old_events_from_being_announced_again(self):
        box = notifications.Outbox(self.site)
        for key in ('a', 'b', 'c'):
            self.notice(box, key, -60 * 72)
        (self.site / 'deliveries.jsonl').write_text(json.dumps({'notice_id': 'x', 'result': 'ACCEPTED'}) + '\n', encoding='utf-8')
        usage = retention.notification_usage(self.site)
        self.assertEqual((usage['notifications']['count'], usage['deliveries']['count'], usage['notifications']['warn']), (3, 1, False))
        with self.assertRaises(ArchiveRefused):
            retention.archive_notifications(self.site, NOW, 'owner', False)
        self.assertEqual(len(box.all()), 3)
        done = retention.archive_notifications(self.site, NOW, 'owner', True)
        self.assertTrue(done['notifications']['archived'] and done['deliveries']['archived'])
        self.assertFalse((self.site / 'notifications.jsonl').exists())
        self.assertEqual(len(list((self.site / 'history-archive').glob('notifications-*.jsonl'))), 1)
        self.assertEqual(len((self.site / 'notification-keys.txt').read_text('utf-8').split()), 3)
        for fresh in (box, notifications.Outbox(self.site)):  # the same object and a new one
            self.assertIsNone(self.notice(fresh, 'a', 1), 'an archived event must not be announced again')
        self.assertIsNotNone(self.notice(box, 'd', 2))
        self.assertEqual([n['key'] for n in notifications.Outbox(self.site).all()], ['d'])
        self.assertIsNone(self.notice(notifications.Outbox(self.site), 'c', 3))
        usage = retention.notification_usage(self.site)
        self.assertEqual((usage['notifications']['count'], usage['deliveries']['count']), (1, 0))
        self.assertEqual(len((self.site / 'maintenance-log.jsonl').read_text('utf-8').splitlines()), 2)

    def test_archiving_notices_is_refused_while_a_young_notice_or_a_dispatch_exists(self):
        box = notifications.Outbox(self.site)
        self.notice(box, 'old', -60 * 72)
        self.notice(box, 'young', -60)
        with self.assertRaises(ArchiveRefused) as cm:
            retention.archive_notifications(self.site, NOW, 'owner', True)
        self.assertIn('24時間以内', str(cm.exception))
        self.assertTrue((self.site / 'notifications.jsonl').exists())
        self.assertFalse((self.site / 'notification-keys.txt').exists())
        later = NOW + timedelta(days=2)
        (self.data / 'notify').mkdir()
        with filelock.held(self.data / 'notify' / 'dispatch.lock'), self.assertRaises(ArchiveRefused):
            retention.archive_notifications(self.site, later, 'owner', True)
        self.assertTrue((self.site / 'notifications.jsonl').exists())
        self.assertTrue(retention.archive_notifications(self.site, later, 'owner', True)['notifications']['archived'])

    def test_the_warning_thresholds(self):
        (self.site / 'notifications.jsonl').write_text('{}\n' * retention.NOTICE_WARN_RECORDS, encoding='utf-8')
        self.assertTrue(retention.notification_usage(self.site)['notifications']['warn'])
        self.assertEqual(retention.count_lines(self.site / 'missing'), 0)


class Usage(Tmp):
    def test_disk_and_data_usage_count_bytes_per_area_without_following_links(self):
        def put(rel, n, base=self.site):
            f = base / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b'x' * n)
        put('runs/r1/a.bin', 1000)
        put('runs/r2/b.bin', 500)
        put('workspace/w.db', 300)
        put('ui/g1/index.html', 200)
        put('http-history.jsonl', 70)
        put('history-archive/http-history-1.jsonl', 30)
        put('notifications.jsonl', 11)
        put('deliveries.jsonl', 22)
        put('site.json', 7)
        put('real/permit.json', 40)
        outside = self.tmp / 'outside'
        put('big.bin', 9999, outside)
        try:
            os.symlink(outside, self.site / 'runs' / 'link', target_is_directory=True)
        except (OSError, NotImplementedError):
            pass
        usage = retention.disk_usage(self.site)
        by = {a['key']: a['bytes'] for a in usage['areas']}
        self.assertEqual(by, {'runs': 1500, 'real': 40, 'workspace': 300, 'ui': 200, 'http': 100, 'notifications': 33, 'pages': 0, 'other': 7})
        self.assertEqual(usage['total'], 2180)
        self.assertTrue(all(a['label'] for a in usage['areas']))
        put('trust/allowed_signers', 100, self.data)
        put('notify/email.json', 20, self.data)
        put('background/a.log', 50, self.data)
        put('siteproof-backup-20260101T000000Z/f', 400, self.data)
        put('stray.txt', 5, self.data)
        data = retention.data_usage(self.data)
        by = {a['key']: a['bytes'] for a in data['areas']}
        self.assertEqual((by['sites'], by['trust'], by['notify'], by['background'], by['backups'], by['other']), (2180, 100, 20, 50, 400, 5))
        self.assertEqual(data['sites'], [{'site_id': 'site-aaaaaaaa', 'bytes': 2180}])
        self.assertEqual(data['total'], sum(by.values()))
        self.assertIsInstance(data['free_bytes'], int)
        self.assertEqual(retention.disk_usage(self.tmp / 'nothing')['total'], 0)


class Time(unittest.TestCase):
    def obs(self, *minutes, **extra):
        return [{'at': format_utc(at(m)), **extra} for m in minutes]

    def test_gaps_longer_than_two_intervals_are_listed_with_an_open_trailing_one(self):
        steady = self.obs(0, 15, 30, 45, 60)
        self.assertEqual(retention.observation_gaps(steady, at(70), 900), [])  # nothing missing; 2 intervals exactly is not a gap
        self.assertEqual(retention.observation_gaps(self.obs(0, 15, 30, 60), at(75), 900), [])
        gaps = retention.observation_gaps(self.obs(0, 15, 30, 31 + 180, 31 + 195), at(31 + 195 + 5), 900)
        self.assertEqual(gaps, [{'from': format_utc(at(30)), 'to': format_utc(at(211)), 'seconds': 181 * 60, 'missed': 11, 'open': False}])
        trailing = retention.observation_gaps(self.obs(0, 15), at(15 + 120), 900)
        self.assertEqual(trailing, [{'from': format_utc(at(15)), 'to': format_utc(at(135)), 'seconds': 120 * 60, 'missed': 7, 'open': True}])
        self.assertEqual(retention.observation_gaps([], at(500), 900), [])
        shuffled = list(reversed(self.obs(0, 15, 300)))
        self.assertEqual(len(retention.observation_gaps(shuffled, at(301), 900)), 1)

    def test_each_record_may_carry_its_own_interval(self):
        slow = self.obs(0, 60, 120, interval_seconds=3600)
        self.assertEqual(retention.observation_gaps(slow, at(150), 300), [])  # the given 5 minutes would call this all gaps
        mixed = self.obs(0, interval_seconds=300) + self.obs(60, interval_seconds=3600)
        gaps = retention.observation_gaps(mixed, at(70), 900)
        self.assertEqual([(g['seconds'], g['missed'], g['open']) for g in gaps], [(3600, 11, False)])
        junk = [{'at': 'yesterday'}, 'x', {'at': format_utc(at(0)), 'interval_seconds': -5}]
        self.assertEqual(len(retention.observation_gaps(junk, at(100), 900)), 1)  # the bad interval falls back to the given one

    def test_days_unobserved(self):
        self.assertEqual(retention.days_unobserved(format_utc(at(-60 * 24 * 3 - 5)), NOW), 3)
        self.assertEqual(retention.days_unobserved(at(10), NOW), 0)
        self.assertIsNone(retention.days_unobserved(None, NOW))
        self.assertIsNone(retention.days_unobserved('nonsense', NOW))


class Words(unittest.TestCase):
    def test_every_stop_reason_has_a_sentence_that_says_what_to_do(self):
        codes = (None, 'BLOCKED', 'COMPLETE', 'DISK_FULL', 'ON_HOLD', 'ANOMALY:CAPTURE_DIFF', 'DECISION:BASELINE', 'HISTORY_FULL', 'GRANT_EXPIRED', 'GRANT_EXHAUSTED', 'BOUNDARY', 'USER',
                 'SOMETHING_NEW')
        seen = set()
        for channel in ('HTTP', 'IMAGE', 'EMAIL'):
            for code in codes:
                text = retention.stop_reason_text({'paused_reason': code, 'enabled': False, 'ever_enabled': True}, channel)
                self.assertTrue(text.endswith('。'), (channel, code, text))
                self.assertIn(retention.CHANNEL_NAMES[channel], text)
                seen.add(text)
        self.assertEqual(len(seen), len(codes) * 3)
        self.assertIn('履歴を整理', retention.stop_reason_text({'paused_reason': 'HISTORY_FULL'}, 'HTTP'))
        self.assertIn('tools/http_grant.py', retention.stop_reason_text({'paused_reason': 'GRANT_EXPIRED'}, 'HTTP'))
        self.assertIn('tools/notify_grant.py', retention.stop_reason_text({'paused_reason': 'GRANT_EXHAUSTED'}, 'EMAIL'))
        self.assertIn('監視設定を更新', retention.stop_reason_text({'paused_reason': 'BLOCKED'}, 'IMAGE'))
        self.assertIn('CAPTURE_DIFF', retention.stop_reason_text({'paused_reason': 'ANOMALY:CAPTURE_DIFF'}, 'IMAGE'))
        self.assertIn('動作中', retention.stop_reason_text({'enabled': True}, 'HTTP'))
        self.assertIn('まだ開始していません', retention.stop_reason_text({'enabled': False}, 'HTTP'))
        self.assertIn('停止しています', retention.stop_reason_text({'paused_reason': 'ZZZ'}, 'X'))
        self.assertIn('まだ開始していません', retention.stop_reason_text(None, 'HTTP'))

    def test_expiry_notices(self):
        far = NOW + timedelta(days=60)
        self.assertIsNone(retention.expiry_notice(far, 100, NOW, 'http_grant'))
        self.assertIsNone(retention.expiry_notice(format_utc(far), None, NOW, 'permit'))
        week = retention.expiry_notice(NOW + timedelta(days=7), 100, NOW, 'http_grant')
        self.assertEqual(week['level'], 'warn')
        self.assertIn('tools/http_grant.py', week['text'])
        self.assertIsNone(retention.expiry_notice(NOW + timedelta(days=8), 100, NOW, 'http_grant'))
        self.assertEqual(retention.expiry_notice(far, 5, NOW, 'permit')['level'], 'warn')
        self.assertIn('監視設定を更新', retention.expiry_notice(far, 5, NOW, 'permit')['text'])
        self.assertIsNone(retention.expiry_notice(far, 6, NOW, 'permit'))
        self.assertEqual(retention.expiry_notice(far, 40, NOW, 'notify_grant', total=1000)['level'], 'warn')  # 4 % left
        self.assertIsNone(retention.expiry_notice(far, 60, NOW, 'notify_grant', total=1000))
        expired = retention.expiry_notice(NOW - timedelta(seconds=1), 100, NOW, 'notify_grant')
        self.assertEqual(expired['level'], 'error')
        self.assertIn('tools/notify_grant.py', expired['text'])
        self.assertEqual(retention.expiry_notice(far, 0, NOW, 'permit')['level'], 'error')
        self.assertEqual(retention.expiry_notice(NOW + timedelta(days=2), 0, NOW, 'permit')['level'], 'error')  # used up beats "soon"
        both = retention.expiry_notice(NOW + timedelta(days=2), 3, NOW, 'http_grant')['text']
        self.assertIn('あと2日', both)
        self.assertIn('あと3回', both)


if __name__ == '__main__':
    unittest.main()

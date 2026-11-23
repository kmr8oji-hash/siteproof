"""Monitoring status / history / events (src/noxiworks/monitoring.py) and their HOME / ACTIVITY screens. Offline only.
The integration test reads saved real runs under .local read-only and skips when they are absent."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile
import unittest

from src.aws_b.model import parse_utc
from src.noxiworks import baseline_registry
from src.noxiworks.home import build, render, render_activity
from src.noxiworks.local_capture import LocalCaptureRefused, attach
from src.noxiworks.monitoring import SCHEDULE_SCHEMA, build as monitoring_build, channel_status, history_entries, image_events, schedule_record
from src.noxiworks.product import empty_snapshot
from tests.comparison.support import synthetic_browser_audit

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / '.local'
DAY = 86400


def capture(job, kind, at, verdict='NO_VISUAL_CHANGE_DETECTED', *, baseline=True, execution='COMPLETED', reasons=()):
    op = {'schema': 'siteproof.operational-verdict.v1', 'verdict': verdict, 'reasons': list(reasons), 'profile_trust': 'UNATTESTED'}
    audit = {'schema': 'siteproof.network-audit.v2', 'source': 'TRUSTED_CONNECT_PROXY', 'complete': True, 'allowed': 1, 'blocked': 0, 'failed': 0, 'idle': 0,
             'entries': [{'host': 'h', 'port': 443, 'decision': 'ALLOW', 'reason': 'ALLOW', 'count': 1}],
             'prelude': {'allowed': 0, 'blocked': 0, 'failed': 0, 'idle': 0, 'entries': []}, 'anchor': {'seen': True}}
    return {'kind': kind, 'job_id': job, 'captured_at': at, 'execution': execution, 'status': 'SUCCEEDED' if execution == 'COMPLETED' else 'FAILED',
            'result': {'baseline': {'candidate_id': 'capture-b', 'version': 1} if baseline else None, 'operational': op, 'network_audit': audit,
                       'browser_audit': synthetic_browser_audit('ok'),
                       'metrics': {'changed_pixels': 0, 'total_pixels': 100} if baseline else None, 'capture_stability': {'value': 'STABLE'}}}


def runs(*captures, run='r1', page='ttn-home', synthetic=False):
    return [(run, page, {'captures': list(captures)}, synthetic)]


class History(unittest.TestCase):
    def test_one_entry_per_job_and_conflicts_refused(self):
        c = capture('j1', 'Desktop', '2026-11-19T00:00:00Z')
        entries = history_entries(runs(c) + runs(c, run='r2'), latest_run_ids={'r2'})
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]['in_review'])
        changed = capture('j1', 'Desktop', '2026-11-19T00:00:00Z', 'VISUAL_CHANGED')
        with self.assertRaises(ValueError):
            history_entries(runs(c) + runs(changed, run='r2'))

    def test_real_and_synthetic_never_mix(self):
        with self.assertRaises(ValueError):
            history_entries(runs(capture('j1', 'Desktop', '2026-11-19T00:00:00Z')) + runs(capture('j2', 'Desktop', '2026-11-20T00:00:00Z'), synthetic=True))

    def test_classes(self):
        e = history_entries(runs(capture('a', 'Desktop', '2026-11-19T00:00:00Z'), capture('b', 'Mobile', '2026-11-19T00:00:01Z', 'VISUAL_CHANGED'),
                                 capture('c', 'Desktop', '2026-11-19T00:00:02Z', 'UNKNOWN', reasons=['CAPTURE_UNSTABLE']),
                                 capture('d', 'Mobile', '2026-11-19T00:00:03Z', 'UNKNOWN', baseline=False, reasons=['BASELINE_PENDING']),
                                 capture('f', 'Desktop', '2026-11-19T00:00:04Z', execution='FAILED')))
        self.assertEqual([x['class'] for x in e], ['UNCHANGED', 'CHANGED', 'UNKNOWN', 'NOT_COMPARED', 'FAILED'])
        self.assertEqual(e[2]['reason_labels'], ['撮影が安定していません'])


class Events(unittest.TestCase):
    def test_only_state_changes_recovery_and_stale(self):
        entries = history_entries(runs(capture('1', 'Desktop', '2026-11-10T00:00:00Z'), capture('2', 'Desktop', '2026-11-11T00:00:00Z'),
                                       capture('3', 'Desktop', '2026-11-12T00:00:00Z', 'UNKNOWN', reasons=['CAPTURE_UNSTABLE']),
                                       capture('4', 'Desktop', '2026-11-13T00:00:00Z')))
        now = parse_utc('2026-11-14T00:00:00Z')
        types = [x['type'] for x in reversed(image_events(entries, now, DAY))]
        self.assertEqual(types, ['UNCHANGED', 'UNKNOWN', 'UNCHANGED', 'RECOVERED'])  # the repeated "unchanged" is one event
        later = [x['type'] for x in image_events(entries, parse_utc('2026-11-16T00:00:00Z'), DAY)]
        self.assertEqual(later[0], 'STALE')

    def test_repeated_input_gives_the_same_events(self):
        c = capture('1', 'Desktop', '2026-11-10T00:00:00Z', 'VISUAL_CHANGED')
        once = history_entries(runs(c))
        twice = history_entries(runs(c) + runs(c, run='r2') + runs(c, run='r3'))
        now = parse_utc('2026-11-10T01:00:00Z')
        self.assertEqual(image_events(once, now, DAY), image_events(twice, now, DAY))


class Schedule(unittest.TestCase):
    now = parse_utc('2026-11-20T00:00:00Z')

    def status(self, record, last='2026-11-19T12:00:00Z'):
        return channel_status(channel='capture', interval=DAY, last=last, last_success=last, last_outcome='COMPLETED', record=record, now=self.now)

    def record(self, **over):
        return schedule_record({'schema': SCHEDULE_SCHEMA, 'target_id': 'ttn-home', 'channel': 'capture', 'enabled': True,
                                'last_finished_at': None, 'last_outcome': None, 'next_due_at': '2026-11-20T12:00:00Z', 'source': 'test', **over})

    def test_without_a_provider_record_nothing_is_running_and_no_next_run_is_invented(self):
        s = self.status(None)
        self.assertEqual((s['schedule_state'], s['next_due_at'], s['freshness']), ('NOT_RUNNING', None, 'RECENT'))

    def test_stopped_overdue_and_stale_are_never_normal(self):
        self.assertEqual(self.status(self.record(enabled=False))['schedule_state'], 'STOPPED')
        overdue = self.status(self.record(next_due_at='2026-11-18T00:00:00Z'))
        self.assertEqual(overdue['schedule_state'], 'OVERDUE')
        self.assertTrue(overdue['attention'])
        stale = self.status(None, last='2026-11-17T00:00:00Z')
        self.assertEqual(stale['freshness'], 'STALE')
        self.assertTrue(stale['attention'])
        self.assertEqual(self.status(None, last=None)['freshness'], 'NONE')

    def test_a_provider_channel_without_its_state_is_unknown_and_an_old_reading_is_unverified(self):
        http = lambda record: channel_status(channel='http', interval=900, last='2026-11-15T11:58:00Z', last_success='2026-11-15T11:58:00Z',
                                            last_outcome='COMPLETED', record=record, now=self.now)
        self.assertEqual(http(None)['schedule_state'], 'PROVIDER_UNKNOWN')
        old = self.record(channel='http', observed_at='2026-11-15T10:46:48Z', next_due_at=None)
        self.assertEqual((http(old)['schedule_state'], http(old)['next_due_at']), ('UNVERIFIED', None))
        self.assertTrue(http(old)['attention'])
        fresh = self.record(channel='http', observed_at='2026-11-19T23:55:00Z', next_due_at='2026-11-20T00:10:00Z')
        self.assertEqual(http(fresh)['schedule_state'], 'SCHEDULED')

    def test_aws_b_verify_state_conversion(self):
        from tools.aws_b_schedule_state import records
        running = {'expect': 'Running', 'result': 'STATE_MATCHES_RUNNING', 'at': '2026-11-15T10:46:48Z', 'mismatches': 0,
                   'checks': [{'check': 'scheduler-5-ENABLED', 'ok': True}]}
        out = records(running, 'STATE_RUNNING.json')
        self.assertEqual(len(out), 5)
        self.assertTrue(all(r['enabled'] and r['observed_at'] == '2026-11-15T10:46:48Z' and r['next_due_at'] is None for r in out))
        for bad in ({**running, 'mismatches': 1}, {**running, 'result': 'STATE_MISMATCH'}, {**running, 'checks': []}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                records(bad, 'x')

    def test_malformed_records_are_refused(self):
        for bad in ({'enabled': 'yes'}, {'channel': 'dns'}, {'next_due_at': 'tomorrow'}, {'schema': 'x'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.record(**bad)
        with self.assertRaises(ValueError):
            schedule_record({'schema': SCHEDULE_SCHEMA})

    def test_notices_follow_the_latest_state_only(self):
        page = {'target_id': 'ttn-home', 'label': 'トップページ', 'domain': 'd', 'plan': {}, 'http': {'state': 'NOT_FETCHED'}}
        entries = history_entries(runs(capture('1', 'Desktop', '2026-11-19T00:00:00Z', 'VISUAL_CHANGED'), capture('2', 'Desktop', '2026-11-19T06:00:00Z'),
                                       capture('3', 'Mobile', '2026-11-19T06:00:00Z', 'UNKNOWN', reasons=['CAPTURE_UNSTABLE'])))
        m = monitoring_build([page], entries, None, self.now, http_interval=21600, capture_interval=DAY)
        self.assertEqual([(n['type'], n['kind']) for n in m['notices']], [('UNKNOWN', 'Mobile')])  # the old change is history, not a notice
        self.assertEqual(m['overall'], 'UNKNOWN')  # HTTP belongs to the provider, whose state was not read


RUNS = [LOCAL / n for n in ('s3-run-02', 's3c-run-01', 's3t-run-01', 's3t-run-02')]


@unittest.skipUnless(all((r / 'export-sha256.json').is_file() for r in RUNS) and (LOCAL / 'baseline-ttn-home-01').is_dir(), 'saved real runs not present')
class SavedRealRuns(unittest.TestCase):
    def test_home_and_activity_show_the_real_history_once(self):
        registry = baseline_registry.read(LOCAL / 'baseline-ttn-home-01')
        snapshot, assets = attach(empty_snapshot(), RUNS[:2], registry, [RUNS[2], RUNS[3], RUNS[3], RUNS[1]])  # duplicates on purpose
        self.assertEqual(len(snapshot['monitoring_history']), 8)
        now = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / 'assets'
            for tid, roles in assets.items():
                (staging / tid).mkdir(parents=True)
                for role, raw in roles.items():
                    (staging / tid / (role + '.png')).write_bytes(raw)
            view = build(Path(tmp) / 'ui', snapshot, now=now, assets=staging)
        m = view['monitoring']
        self.assertEqual(m['overall'], 'UNKNOWN')  # HTTP belongs to the provider, whose state was not read
        self.assertEqual([h['class'] for h in m['history'][:2]], ['UNCHANGED', 'UNCHANGED'])  # SP-D54
        home, activity = render(view), render_activity(view)
        self.assertIn('画像：自動実行なし（予定・未稼働）', home)
        self.assertIn('HTTP監視（AWS-B）が今も動いているかは未確認', home)
        self.assertIn('HTTP監視：結果なし 5ページ', home)
        self.assertEqual(len(re.findall(r'data-job-id="', activity)), 8)
        self.assertIn('画像監視の履歴（実測・保存済み）', activity)
        self.assertNotIn('合成', home + activity)
        self.assertIn('href="review.html#ttn-home"', activity)
        later = build_view_at(snapshot, datetime(2026, 11, 23, tzinfo=timezone.utc))
        self.assertIn('長期間未監視', render(later))

    def test_a_synthetic_run_is_refused_next_to_real_runs(self):
        demo = LOCAL / 's3c-offline-01' / 'changed' / 'run'
        if not (demo / 'export-sha256.json').is_file():
            self.skipTest('synthetic integration run not present')
        with self.assertRaises(LocalCaptureRefused):
            attach(empty_snapshot(), [RUNS[0], demo], baseline_registry.read(LOCAL / 's3c-offline-01' / 'registry-read-only-copy'))


ARCHIVE = LOCAL / 'run-archive'


@unittest.skipUnless((ARCHIVE / 'managed.json').is_file() and all((r / 'export-sha256.json').is_file() for r in RUNS[:2]), 'saved AWS-B archive not present')
class SavedHttpArchive(unittest.TestCase):
    def test_saved_http_results_are_shown_as_old_never_as_up(self):
        from src.noxiworks.archive import Archive
        from src.noxiworks.product import settings
        archive = Archive(ARCHIVE)
        self.assertEqual(archive.verify(), [])
        now = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
        pages = settings()['pages']
        snapshot = archive.home_snapshot(pages, now=now)
        snapshot['http_export']['fetched_at'] = archive.fetched_at()
        extra = archive.home_extra({p['target_id'] for p in pages})
        snapshot, _ = attach(snapshot, RUNS[:2], baseline_registry.read(LOCAL / 'baseline-ttn-home-01'))
        view = build_view_at(snapshot, now)
        view['archive'] = extra
        http = [c for r in view['monitoring']['rows'] for c in r['channels'] if c['channel'] == 'http' and c['schedule_state'] != 'NO_SETTING']
        self.assertEqual(len(http), 5)
        self.assertTrue(all(c['freshness'] == 'STALE' and c['last_success_at'] and c['last_outcome'] == 'COMPLETED' for c in http))
        self.assertTrue(all(p['http']['state'] == 'STALE' for p in view['pages'] if not p.get('local_capture')))
        home, activity = render(view), render_activity(view)
        self.assertIn('前回 正常（HTTP 200）', home)
        self.assertIn('HTTP監視：観測が古い 5ページ', home)
        self.assertIn('データ取得：<time>11/15 21:05 JST</time>', home)  # the archive's own acquisition time
        self.assertNotIn('data-state="UP"', home)
        self.assertIn('保存済みの監視記録（実サイト）', activity)
        self.assertIn('試験用Fixture · 実サイトの障害ではありません', activity)  # the 503 trial stays apart
        self.assertNotIn('aws-b-http-fixture', json.dumps(view['monitoring']))


def build_view_at(snapshot, now):
    from src.noxiworks.product import dashboard
    view = dashboard(snapshot, now=now)
    for page in view['pages']:
        page['available_assets'] = []
    return view


if __name__ == '__main__':
    unittest.main()

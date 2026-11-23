"""Offline tests of the run archive. No AWS, network or credentials: `aws` is a fake runner."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from src.noxiworks.archive import (Archive, checked_environment, fetch_live, import_alarm_history, import_snapshot,
                                   incidents, normalize_alarm, normalize_run)
from src.noxiworks.product import settings

T0 = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
SECRET_MARKERS = ('attempt_id', 'selected_ip', 'logical_run_key', 'expires_at', 'siteproof-b-', '-runs', 'arn:aws', '172.67.1.1')


def slot(i):
    return (T0 + timedelta(minutes=15 * i)).strftime('%Y-%m-%dT%H:%M:%SZ')


def item(target, i, outcome='PASS', status=200, state='RECORDED'):
    value = {'pk': {'S': 'RUN#' + target}, 'sk': {'S': slot(i)}, 'state': {'S': state}, 'schema': {'S': 'siteproof.monitor.record.v1'},
             'attempt_id': {'S': 'attempt-%s-%d' % (target, i)}, 'logical_run_key': {'S': 'k%d' % i}, 'claimed_at': {'S': slot(i)},
             'execution_generation': {'N': '5'}, 'policy_version': {'S': 'p1'}, 'expires_at': {'N': '1795948994'}}
    if state == 'RECORDED':
        value.update(outcome={'S': outcome}, reason={'S': 'HTTP_%d' % status}, http_status={'N': str(status)}, elapsed_ms={'N': str(100 + i)},
                     finished_at={'S': slot(i)}, selected_ip={'S': '172.67.1.1'}, tls_not_after={'S': 'Dec 22 10:31:37 2026 GMT'})
    return value


def head(target):
    return {'pk': {'S': 'CONTROL#' + target}, 'sk': {'S': 'HEAD'}, 'enabled': {'BOOL': True}, 'execution_generation': {'N': '5'}}


def snapshot(fetched_at, runs, source='AWS_EXPORT'):
    return {'schema': 'x', 'source': source, 'http_export': {'fetched_at': fetched_at},
            'http': {t: {'head': head(t), 'runs': items} for t, items in runs.items()}}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.clock_value = T0 + timedelta(hours=1)
        self.archive = Archive(self.tmp / 'archive', clock=lambda: self.clock_value)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name, value):
        path = self.tmp / name
        path.write_text(json.dumps(value), 'utf-8')
        return path

    def tick(self, minutes=10):
        self.clock_value += timedelta(minutes=minutes)

    def manifest(self):
        return json.loads((self.archive.public / 'MANIFEST.json').read_text('utf-8'))


class Import(Base):
    def test_import_counts_public_privacy_and_verification(self):
        path = self.write('s1.json', snapshot(slot(4), {'a-site': [item('a-site', i) for i in range(4)], 'b-site': [item('b-site', 0)]}))
        result = import_snapshot(self.archive, path)
        self.assertEqual(result['status'], 'IMPORTED')
        self.assertEqual(result['counts'], {'seen': 5, 'new': 5, 'upgraded': 0, 'duplicate': 0, 'rejected': 0, 'conflicts': 0})
        self.assertEqual(self.archive.verify(), [])
        manifest = self.manifest()
        self.assertEqual(manifest['targets']['a-site']['runs'], 4)
        self.assertEqual(manifest['targets']['a-site']['first_slot'], slot(0))
        runs = (self.archive.public / 'runs' / 'a-site.jsonl').read_text('utf-8').splitlines()
        self.assertEqual(len(runs), 4)
        self.assertEqual(json.loads(runs[0])['http_status'], 200)
        for public in self.archive.public.rglob('*'):
            if public.is_file():
                text = public.read_text('utf-8')
                for marker in SECRET_MARKERS:
                    self.assertNotIn(marker, text, '%s leaked into %s' % (marker, public.name))
        private = (self.archive.batches_dir / result['batch'] / 'raw' / 'a-site.json').read_text('utf-8')
        self.assertIn('attempt_id', private)   # raw AWS-side detail stays private

    def test_same_file_twice_and_overlapping_exports_do_not_duplicate(self):
        first = self.write('s1.json', snapshot(slot(3), {'t': [item('t', i) for i in range(3)]}))
        self.assertEqual(import_snapshot(self.archive, first)['status'], 'IMPORTED')
        before = {p.name: p.read_bytes() for p in self.archive.public.rglob('*') if p.is_file()}
        self.assertEqual(import_snapshot(self.archive, first)['status'], 'ALREADY_IMPORTED')
        self.assertEqual({p.name: p.read_bytes() for p in self.archive.public.rglob('*') if p.is_file()}, before)
        self.tick()
        second = self.write('s2.json', snapshot(slot(6), {'t': [item('t', i) for i in range(2, 6)]}))
        result = import_snapshot(self.archive, second)
        self.assertEqual((result['counts']['new'], result['counts']['duplicate']), (3, 1))
        self.assertEqual(self.manifest()['targets']['t']['runs'], 6)
        self.assertEqual(len(self.archive.batches()), 2)
        self.assertEqual(self.archive.verify(), [])

    def test_claimed_record_is_upgraded_and_conflicts_are_reported_not_overwritten(self):
        import_snapshot(self.archive, self.write('a.json', snapshot(slot(2), {'t': [item('t', 0, state='CLAIMED'), item('t', 1)]})))
        self.assertEqual(self.manifest()['targets']['t']['unknown'], 1)
        self.tick()
        result = import_snapshot(self.archive, self.write('b.json', snapshot(slot(3), {'t': [item('t', 0), item('t', 1, 'FAIL', 503)]})))
        self.assertEqual((result['counts']['upgraded'], result['counts']['conflicts']), (1, 1))
        manifest = self.manifest()
        self.assertEqual(manifest['targets']['t']['unknown'], 0)
        self.assertEqual(manifest['conflicts'], [{'target_id': 't', 'scheduled_slot': slot(1), 'batch': result['batch']}])
        kept = [json.loads(l) for l in (self.archive.public / 'runs' / 't.jsonl').read_text('utf-8').splitlines()]
        self.assertEqual(kept[1]['outcome'], 'PASS')   # first recorded result wins

    def test_fixture_and_empty_snapshots_and_garbage_items_are_refused(self):
        with self.assertRaises(ValueError):
            import_snapshot(self.archive, self.write('f.json', snapshot(slot(1), {'t': [item('t', 0)]}, source='FIXTURE')))
        bad = [{'pk': {'S': 'RUN#t'}}, {'pk': {'S': 'CONTROL#t'}, 'sk': {'S': slot(0)}}, item('t', 1, 'MAYBE'), 'x', item('t', 2)]
        result = import_snapshot(self.archive, self.write('g.json', snapshot(slot(3), {'t': bad})))
        self.assertEqual((result['counts']['new'], result['counts']['rejected']), (1, 4))

    def test_incidents_and_availability(self):
        rows = [item('t', 0), item('t', 1, 'FAIL', 503), item('t', 2, 'FAIL', 503), item('t', 3), item('t', 4, 'FAIL', 500)]
        import_snapshot(self.archive, self.write('i.json', snapshot(slot(5), {'t': rows})))
        manifest = self.manifest()
        self.assertEqual((manifest['targets']['t']['pass'], manifest['targets']['t']['fail']), (2, 3))
        self.assertEqual(manifest['targets']['t']['availability_percent'], 40.0)
        found = json.loads((self.archive.public / 'incidents.json').read_text('utf-8'))['incidents']
        self.assertEqual([(i['started_at'], i['recovered_at'], i['failed_runs'], i['ongoing']) for i in found],
                         [(slot(1), slot(3), 2, False), (slot(4), None, 1, True)])
        self.assertEqual(found[0]['http_statuses'], [503])
        self.assertEqual(incidents('t', []), [])

    def test_alarm_history_import_hides_alarm_identifiers(self):
        entry = {'AlarmName': 'siteproof-b-20261114-054215-aws-b-http-fixture-failure', 'Timestamp': '2026-11-15T16:19:43.969000+09:00',
                 'HistoryItemType': 'StateUpdate', 'HistorySummary': 'Alarm updated from OK to ALARM',
                 'HistoryData': json.dumps({'oldState': {'stateValue': 'OK'}, 'newState': {'stateValue': 'ALARM', 'stateReason': 'Threshold Crossed: 2 out of the last 3'}})}
        other = dict(entry, AlarmName='someone-elses-alarm')
        path = self.write('h.json', {'AlarmHistoryItems': [entry, entry, other]})
        result = import_alarm_history(self.archive, path)
        self.assertEqual((result['counts']['new'], result['counts']['duplicate'], result['counts']['rejected']), (1, 1, 1))
        events = json.loads((self.archive.public / 'alarm_events.json').read_text('utf-8'))['events']
        self.assertEqual(events, [{'target_id': 'aws-b-http-fixture', 'alarm_kind': 'failure', 'at': '2026-11-15T07:19:43Z',
                                   'old_state': 'OK', 'new_state': 'ALARM', 'reason': 'Threshold Crossed: 2 out of the last 3'}])
        self.assertNotIn('siteproof-b-', (self.archive.public / 'alarm_events.json').read_text('utf-8'))
        self.assertIsNone(normalize_alarm({'AlarmName': 'x'}))

    def test_normalize_run_rejects_non_records(self):
        self.assertIsNone(normalize_run({'pk': {'S': 'RUN#../x'}, 'sk': {'S': slot(0)}, 'state': {'S': 'RECORDED'}}))
        self.assertEqual(normalize_run(item('t', 0, state='CLAIMED'))['outcome'], 'UNKNOWN')


class Integrity(Base):
    def setUp(self):
        super().setUp()
        self.result = import_snapshot(self.archive, self.write('s.json', snapshot(slot(3), {'t': [item('t', i) for i in range(3)]})))

    def test_tampered_batch_public_and_extra_files_are_detected(self):
        raw = self.archive.batches_dir / self.result['batch'] / 'raw' / 't.json'
        original = raw.read_bytes()
        raw.write_bytes(original.replace(b'"200"', b'"500"'))
        self.assertTrue(any('SHA-256' in p for p in self.archive.verify()))
        raw.write_bytes(original)
        self.assertEqual(self.archive.verify(), [])
        public = self.archive.public / 'runs' / 't.jsonl'
        public.write_bytes(public.read_bytes().replace(b'"PASS"', b'"FAIL"'))
        self.assertTrue(any('differs' in p for p in self.archive.verify()))
        self.archive.rebuild()
        self.assertEqual(self.archive.verify(), [])
        (self.archive.public / 'extra.txt').write_text('x')
        self.assertTrue(any('unexpected' in p for p in self.archive.verify()))
        (self.archive.public / 'extra.txt').unlink()
        (self.archive.public / 'runs' / 't.jsonl').unlink()
        self.assertTrue(any('missing' in p for p in self.archive.verify()))

    def test_sha256sums_file_matches_public_files(self):
        import hashlib
        for line in (self.archive.public / 'SHA256SUMS.txt').read_text('utf-8').splitlines():
            digest, name = line.split(' *')
            self.assertEqual(hashlib.sha256((self.archive.public / name).read_bytes()).hexdigest(), digest)

    def test_lock_blocks_concurrent_runs_and_foreign_directories_are_refused(self):
        (self.archive.root / '.archive-lock').write_text('')
        with self.assertRaises(ValueError):
            import_snapshot(self.archive, self.write('n.json', snapshot(slot(9), {'t': [item('t', 8)]})))
        (self.archive.root / '.archive-lock').unlink()
        foreign = self.tmp / 'foreign'
        foreign.mkdir()
        (foreign / 'keep.txt').write_text('x')
        with self.assertRaises(ValueError):
            Archive(foreign).init()
        self.assertEqual([p.name for p in foreign.iterdir()], ['keep.txt'])

    def test_batches_are_never_modified_by_later_imports(self):
        before = {p: p.read_bytes() for p in (self.archive.batches_dir / self.result['batch']).rglob('*') if p.is_file()}
        self.tick()
        import_snapshot(self.archive, self.write('n.json', snapshot(slot(9), {'t': [item('t', i) for i in range(5, 8)]})))
        self.assertEqual({p: p.read_bytes() for p in before}, before)


class Fetch(Base):
    CONFIG = {'profile': 'siteproof-live', 'region': 'us-east-1', 'tables': {'t': 'siteproof-b-20261114-054215-t-runs'}}
    ENV = {'AWS_CONFIG_FILE': 'D:\\a\\config', 'AWS_SHARED_CREDENTIALS_FILE': 'D:\\a\\credentials', 'AWS_LOGIN_CACHE_DIRECTORY': 'D:\\a\\cache', 'USERPROFILE': 'D:\\a'}

    class Runner:
        def __init__(self, pages, fail=False):
            self.pages, self.calls, self.fail = list(pages), [], fail

        def __call__(self, command, **kwargs):
            self.calls.append(command)
            service, operation = command[1], command[2]
            body = {}
            if self.fail:
                return type('R', (), {'returncode': 255, 'stdout': '', 'stderr': 'denied'})()
            if operation == 'query':
                body = self.pages.pop(0)
            elif operation == 'get-item':
                body = {'Item': head('t')}
            elif operation == 'describe-alarm-history':
                body = {'AlarmHistoryItems': []}
            return type('R', (), {'returncode': 0, 'stdout': json.dumps(body), 'stderr': ''})()

    def request(self, call):
        return json.loads(call[call.index('--cli-input-json') + 1])

    def test_paginated_first_fetch_then_incremental_fetch_with_overlap(self):
        runner = self.Runner([{'Items': [item('t', 0), item('t', 1)], 'LastEvaluatedKey': {'pk': {'S': 'RUN#t'}, 'sk': {'S': slot(1)}}},
                              {'Items': [item('t', 2)]}])
        result = fetch_live(self.archive, self.CONFIG, runner=runner, environ=self.ENV)[0]
        self.assertEqual((result['status'], result['counts']['new']), ('IMPORTED', 3))
        queries = [self.request(c) for c in runner.calls if c[2] == 'query']
        self.assertEqual(len(queries), 2)
        self.assertNotIn('ExclusiveStartKey', queries[0])
        self.assertEqual(queries[1]['ExclusiveStartKey']['sk']['S'], slot(1))
        self.assertEqual(queries[0]['KeyConditionExpression'], '#pk = :pk')
        self.assertTrue(all('--no-paginate' in c for c in runner.calls if c[1] == 'dynamodb'))
        self.assertTrue(all(c[1] in ('dynamodb', 'cloudwatch') and c[2] in ('query', 'get-item', 'describe-alarm-history') for c in runner.calls))
        self.assertEqual(self.archive.verify(), [])
        self.tick()
        runner = self.Runner([{'Items': [item('t', 2), item('t', 3)]}])
        result = fetch_live(self.archive, self.CONFIG, runner=runner, environ=self.ENV)[0]
        self.assertEqual((result['counts']['new'], result['counts']['duplicate']), (1, 1))
        query = self.request(next(c for c in runner.calls if c[2] == 'query'))
        self.assertEqual(query['ExpressionAttributeValues'][':since']['S'], slot(2 - 4))   # last slot minus one hour
        self.assertEqual(self.manifest()['targets']['t']['runs'], 4)

    def test_only_read_operations_and_optional_alarm_history(self):
        runner = self.Runner([{'Items': [item('t', 0)]}])
        results = fetch_live(self.archive, self.CONFIG, alarm_history=True, runner=runner, environ=self.ENV)
        self.assertEqual(len(results), 2)
        names = {c[2] for c in runner.calls}
        self.assertEqual(names, {'query', 'get-item', 'describe-alarm-history'})
        alarm_calls = [c for c in runner.calls if c[2] == 'describe-alarm-history']
        self.assertEqual(len(alarm_calls), 3)
        self.assertIn('siteproof-b-20261114-054215-t-failure', alarm_calls[0])

    def test_failure_stores_nothing_and_environment_gate(self):
        with self.assertRaises(ValueError):
            fetch_live(self.archive, self.CONFIG, runner=self.Runner([], fail=True), environ=self.ENV)
        self.assertEqual(self.archive.batches(), []) if self.archive.batches_dir.exists() else None
        # no drive is required (any absolute path, or unset = AWS CLI defaults); relative paths and explicit credentials/endpoints are refused
        for bad in ({**self.ENV, 'AWS_ACCESS_KEY_ID': 'x'}, {**self.ENV, 'AWS_CONFIG_FILE': 'relative\\x'}, {**self.ENV, 'AWS_ENDPOINT_URL': 'http://x'}):
            with self.assertRaises(ValueError):
                checked_environment(bad)
        for good in ({**self.ENV, 'AWS_CONFIG_FILE': 'C:\\x'}, {}):
            checked_environment(good)


class HomeSnapshot(Base):
    def test_archived_data_renders_in_home_without_aws(self):
        from src.noxiworks.home import build
        pages = settings()['pages']
        rows = {p['target_id']: [item(p['target_id'], i) for i in range(4)] for p in pages}
        import_snapshot(self.archive, self.write('s.json', snapshot(slot(4), rows)))
        now = T0 + timedelta(hours=2)
        shot = self.archive.home_snapshot(pages, now)
        self.assertEqual(shot['source'], 'AWS_EXPORT')
        self.assertEqual({k for k in shot['http']}, {p['target_id'] for p in pages})
        out = self.tmp / 'home'
        view = build(out, shot, now=now)
        self.assertTrue((out / 'index.html').is_file())
        self.assertEqual(view['source'], 'AWS_EXPORT')

    def test_archive_history_separates_real_sites_from_fixture_trial_and_is_not_live(self):
        from src.noxiworks.home import build
        pages = settings()['pages']
        ids = {p['target_id'] for p in pages}
        rows = {tid: [item(tid, i) for i in range(3)] for tid in ids}
        rows['aws-b-trial-fixture'] = [item('aws-b-trial-fixture', 0), item('aws-b-trial-fixture', 1, 'FAIL', 503), item('aws-b-trial-fixture', 2, 'FAIL', 503), item('aws-b-trial-fixture', 3)]
        import_snapshot(self.archive, self.write('s.json', snapshot(slot(4), rows)))
        extra = self.archive.home_extra(ids)
        self.assertEqual(set(extra['sites']), ids)
        self.assertEqual(set(extra['trial']['targets']), {'aws-b-trial-fixture'})
        self.assertEqual(extra['sites'][sorted(ids)[0]]['incidents'], [])
        snap = self.archive.home_snapshot(pages)
        self.assertEqual(snap['http_export']['fetched_at'], slot(4))   # data time, not render time
        out = self.tmp / 'home2'
        build(out, snap, now=T0 + timedelta(minutes=60), archive=extra)
        activity = (out / 'activity.html').read_text('utf-8')
        index = (out / 'index.html').read_text('utf-8')
        details = (out / 'details.html').read_text('utf-8')
        self.assertIn('保存済みの監視記録（実サイト）', activity)
        self.assertIn('実サイトの障害記録：0件', activity)
        self.assertIn('実サイトの障害ではありません', activity)
        trial_part = activity[activity.index('id="trial"'):]
        self.assertIn('503', trial_part)
        self.assertNotIn('aws-b-trial-fixture', index + details)
        self.assertNotIn('503', activity[:activity.index('id="trial"')])
        self.assertIn('現在の稼働状態を示すものではありません', activity)
        self.assertIn('id="scope"', details)
        self.assertIn('データ取得：', index)
        for forbidden in ('現在稼働中', '正常稼働中', 'attempt_id', 'selected_ip', '172.67.1.1'):
            self.assertNotIn(forbidden, index + activity + details)

    def test_shared_menu_cards_filters_and_plain_wording(self):
        import re
        from src.noxiworks.home import build
        pages = settings()['pages']
        ids = {p['target_id'] for p in pages}
        import_snapshot(self.archive, self.write('s.json', snapshot(slot(3), {t: [item(t, i) for i in range(3)] for t in ids})))
        out = self.tmp / 'ux'
        build(out, self.archive.home_snapshot(pages), now=T0 + timedelta(hours=1), archive=self.archive.home_extra(ids))
        names = ['index', 'review', 'details', 'activity', 'evidence', 'aws-operations']
        menus = set()
        for name in names:
            html = (out / (name + '.html')).read_text('utf-8')
            nav = re.search(r'<nav class="global-nav".*?</nav>', html, re.S).group(0)
            self.assertEqual(nav.count('data-nav='), 6)
            self.assertEqual(nav.count('aria-current="page"'), 1)
            self.assertIn('global-nav.css', html)
            menus.add(re.sub(r' aria-current="page"', '', nav))
        self.assertEqual(len(menus), 1)   # identical on every screen apart from the highlight
        for label in ('HOME', '差分レビュー', 'DETAIL', '履歴・通知', '証拠一覧', 'AWS運用'):
            self.assertIn('>' + label + '</a>', next(iter(menus)))
        index = (out / 'index.html').read_text('utf-8')
        self.assertNotIn('id="functions"', index)
        self.assertNotIn('機能メニュー', index)
        hrefs = re.findall(r'<a class="status-card[^"]*" href="([^"]+)"', index)
        self.assertEqual(hrefs, ['index.html?filter=all#pages', 'index.html?filter=up#pages', 'review.html', 'index.html?filter=attention#pages'])
        self.assertIn('data-filter="up"', index)
        self.assertEqual(len(re.findall(r'<option value="(?:noxiworks|hms|ttn)"', index)), 3)
        self.assertIn('障害 0 ・ 未検証 5', index)        # real faults and unverified items are counted apart
        self.assertIn('<a class="aws-title-link" href="aws-operations.html">', index)
        self.assertNotIn('AWS管理画面を開く', index)
        for jargon in ('HISTORICAL', '取込データ', '保存観測', 'UNKNOWN（自動更新なし）'):
            self.assertNotIn(jargon, index)
        for name in ('review', 'details'):
            self.assertIn('id="' + ('review-project' if name == 'review' else 'detail-project') + '"', (out / (name + '.html')).read_text('utf-8'))

    def test_home_order_collapsible_projects_and_aws_service_cards(self):
        import re
        from src.noxiworks.home import build
        from src.noxiworks.operations import console_links, SERVICES
        pages = settings()['pages']
        ids = {p['target_id'] for p in pages}
        import_snapshot(self.archive, self.write('s.json', snapshot(slot(3), {t: [item(t, i) for i in range(3)] for t in ids})))
        out = self.tmp / 'ux2'
        build(out, self.archive.home_snapshot(pages), now=T0 + timedelta(hours=1), archive=self.archive.home_extra(ids))
        index = (out / 'index.html').read_text('utf-8')
        order = [index.index(k) for k in ('class="status-cards"', 'expiry-panel', 'id="activity"', 'id="aws-operations"', 'id="project-folders"', 'class="notice-list"')]
        self.assertEqual(order, sorted(order))   # cards -> expiry / log / AWS -> project list -> notices
        self.assertNotIn('class="panel snapshot-note"', index)   # the large notice box is gone ...
        self.assertIn('class="data-strip"', index)               # ... a small strip keeps "saved data, not real time"
        self.assertIn('データ取得：', index)
        self.assertIn('リアルタイムの情報ではありません', index)
        self.assertEqual(index.count('data-scroll-card'), 2)    # expiry + log cards scroll inside the card
        self.assertIn('scrollcard.js', index)
        self.assertIn('data-scroll="up"', index)
        self.assertIn('data-scroll="down"', index)
        self.assertLess(index.index('class="overview-row"'), index.index('id="aws-operations"'))
        self.assertEqual(index.count('class="overview-row"'), 1)
        activity = (out / 'activity.html').read_text('utf-8')
        agroups = re.findall(r'<details class="project-group"([^>]*)>.*?<strong>([^<]+)</strong><span class="group-count"[^>]*>([^<]+)</span>', activity, re.S)
        self.assertEqual([(g[1], g[2]) for g in agroups], [('NoxiWorks', '2ページ'), ('Hello, My Saitama', '2ページ'), ('Tokyo Trouble Navi', '1ページ')])
        self.assertEqual([' open' in g[0] for g in agroups], [True, False, False])
        self.assertEqual(activity.count('<table class="runs-table">'), 3)
        self.assertEqual(activity.count('data-label="正常率"'), 5)   # all five pages, none dropped
        for name, extra in (('details', ''), ('evidence', '保存画像 0件')):
            html = (out / (name + '.html')).read_text('utf-8')
            groups = re.findall(r'<details class="project-group"([^>]*)>.*?<strong>([^<]+)</strong><span class="group-count"[^>]*>([^<]+)</span>', html, re.S)
            self.assertEqual([(g[1], g[2].split(' · ')[0]) for g in groups], [('NoxiWorks', '2ページ'), ('Hello, My Saitama', '2ページ'), ('Tokyo Trouble Navi', '1ページ')])
            self.assertEqual([' open' in g[0] for g in groups], [True, False, False])   # only the first project starts open
            self.assertEqual(html.count('data-detail-section'), 5)
            self.assertIn('projectfilter.js', html)
            if extra:
                self.assertIn(extra, html)
                self.assertNotIn('<img', html)   # no evidence image is invented
        ops = (out / 'aws-operations.html').read_text('utf-8')
        cards = re.findall(r'<article class="service-card.*?</article>', ops, re.S)
        self.assertEqual(len(cards), 8)
        registry = console_links()
        for card, name in zip(cards, SERVICES):
            self.assertEqual(card.count('<a '), 1)                 # one link per card: no nested or double links
            self.assertIn('href="' + registry[name] + '"', card)
            self.assertIn('target="_blank"', card)
            self.assertIn('rel="noopener noreferrer external"', card)
            self.assertNotIn('外部 ↗', card)                         # no per-card "external" label; explained once above the grid
        self.assertIn('console-link::after{content:"";position:absolute;inset:0}', (out / 'operations' / 'operations.css').read_text('utf-8'))
        self.assertEqual(ops.count('各サービスのカードをクリックすると'), 1)
        css = (out / 'operations' / 'operations.css').read_text('utf-8')
        colours = re.findall(r'data-service="[^"]+"\]\{--svc:(#[0-9a-f]{6});--tint:(#[0-9a-f]{6})\}', css)
        self.assertEqual(len(colours), 8)
        self.assertEqual(len({c[0] for c in colours}), 8)       # eight different service colours
        self.assertEqual(len({c[1] for c in colours}), 8)
        for text in ('selected_ip', 'attempt_id'):
            self.assertNotIn(text, index + ops)
        self.assertIsNone(re.search(r'(?<!\d)\d{12}(?!\d)', index + ops))  # no AWS account ID (any standalone 12 digits)
        self.assertIsNone(re.search(r'(?i)[a-z]:[\\/]+users[\\/]', index + ops))  # no local user profile path


if __name__ == '__main__':
    unittest.main()

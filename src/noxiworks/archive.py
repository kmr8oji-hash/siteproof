"""Local, append-only archive of AWS-B monitoring records, so measured data survives the 14-day DynamoDB TTL.

    python -B -m src.noxiworks.archive import-snapshot  --archive DIR FILE [FILE ...]   (local files only, no AWS)
    python -B -m src.noxiworks.archive import-export    --archive DIR EXPORT_DIR [...]  (your own `aws dynamodb get-item/query` output saved
                                                        in the layout of src/noxiworks/aws_b_data.py; local files only, no AWS)
    python -B -m src.noxiworks.archive import-alarm-history --archive DIR FILE [...]   (local files only, no AWS)
    python -B -m src.noxiworks.archive fetch --archive DIR --config refresh-config.json --aws-read [--alarm-history]
    python -B -m src.noxiworks.archive verify   --archive DIR
    python -B -m src.noxiworks.archive rebuild  --archive DIR
    python -B -m src.noxiworks.archive snapshot --archive DIR --out NEW_FILE.json      (HOME input, no AWS)
    python -B -m src.noxiworks.archive home     --archive DIR --out NEW_DIR            (full HOME screens, no AWS)

Which pages are known comes from src/noxiworks/targets.json (the author's pages by default). For your own site pass
--targets FILE --capture-plan FILE (a registered site's <data>/sites/<id>/targets.json and capture_plan.json), on every command.

Layout (every private batch is immutable; public/ is rebuilt from the batches, never edited by hand):

    managed.json
    private/batches/<id>/batch.json + raw files   raw DynamoDB items / alarm history, INCLUDING AWS-side identifiers
    public/runs/<target>.jsonl                    one record per scheduled slot, no AWS identifiers
    public/incidents.json  alarm_events.json  MANIFEST.json  index.html  SHA256SUMS.txt

Reading AWS (`fetch`) uses only dynamodb query / get-item (the operations HOME refresh already uses) and, with
--alarm-history, cloudwatch describe-alarm-history. Nothing here writes to AWS.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from html import escape
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SCHEMA = 'siteproof.run-archive.v1'
PUBLIC_SCHEMA = 'siteproof.run-archive.public.v1'
SLOT = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
ALARM = re.compile(r'siteproof-b-\d{8}-\d{6}-(?P<target>.+)-(?P<kind>failure|unpersisted|function-error)')
RUN_FIELDS = ('target_id', 'scheduled_slot', 'state', 'outcome', 'reason', 'http_status', 'elapsed_ms',
              'claimed_at', 'finished_at', 'tls_not_after', 'execution_generation')
MAX_FILE_BYTES = 64 * 1024 * 1024
OVERLAP = timedelta(hours=1)
PRIVATE_ITEM_FIELDS = ('attempt_id', 'last_attempt_id', 'selected_ip', 'logical_run_key', 'expires_at')


def utc(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _canon(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _text(value, indent=None):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=indent) + '\n'


def _atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.' + os.urandom(6).hex())
    with tmp.open('xb') as stream:
        stream.write(data)
    os.replace(tmp, path)


def _s(item, key):
    value = item.get(key)
    return value.get('S') if isinstance(value, dict) and isinstance(value.get('S'), str) else None


def _n(item, key):
    value = item.get(key)
    try:
        return int(value['N']) if isinstance(value, dict) else None
    except (KeyError, TypeError, ValueError):
        return None


def normalize_run(item):
    """DynamoDB run item -> public record, or None when the item is not a valid run record."""
    if not isinstance(item, dict):
        return None
    pk, slot, state = _s(item, 'pk'), _s(item, 'sk'), _s(item, 'state')
    if not pk or not pk.startswith('RUN#') or not TARGET.fullmatch(pk[4:]):
        return None
    if not slot or not SLOT.fullmatch(slot) or state not in ('CLAIMED', 'RECORDED'):
        return None
    outcome = _s(item, 'outcome') if state == 'RECORDED' else 'UNKNOWN'
    if outcome not in ('PASS', 'FAIL', 'UNKNOWN'):
        return None
    return {'target_id': pk[4:], 'scheduled_slot': slot, 'state': state, 'outcome': outcome,
            'reason': _s(item, 'reason'), 'http_status': _n(item, 'http_status'), 'elapsed_ms': _n(item, 'elapsed_ms'),
            'claimed_at': _s(item, 'claimed_at'), 'finished_at': _s(item, 'finished_at'),
            'tls_not_after': _s(item, 'tls_not_after'), 'execution_generation': _n(item, 'execution_generation')}


def normalize_alarm(entry):
    """CloudWatch StateUpdate history item -> public event (no alarm name/ARN), or None."""
    try:
        match = ALARM.fullmatch(entry['AlarmName'])
        if not match or entry.get('HistoryItemType', 'StateUpdate') != 'StateUpdate':
            return None
        data = json.loads(entry['HistoryData'])
        at = utc(datetime.fromisoformat(str(entry['Timestamp']).replace('Z', '+00:00')))
        return {'target_id': match['target'], 'alarm_kind': match['kind'], 'at': at,
                'old_state': data['oldState']['stateValue'], 'new_state': data['newState']['stateValue'],
                'reason': str(data['newState'].get('stateReason', ''))[:400]}
    except (KeyError, TypeError, ValueError):
        return None


def incidents(target, records):
    """Maximal FAIL runs (UNKNOWN inside them is counted) that end at the first following PASS."""
    result, cur = [], None
    for rec in records:
        if rec['outcome'] == 'PASS':
            if cur:
                cur['recovered_at'] = rec['scheduled_slot']
                result.append(cur)
                cur = None
        elif rec['outcome'] == 'FAIL' or cur:
            if cur is None:
                cur = {'target_id': target, 'started_at': rec['scheduled_slot'], 'last_failure_at': None,
                       'recovered_at': None, 'failed_runs': 0, 'unknown_runs': 0, 'http_statuses': []}
            if rec['outcome'] == 'FAIL':
                cur['failed_runs'] += 1
                cur['last_failure_at'] = rec['scheduled_slot']
                if rec['http_status'] is not None and rec['http_status'] not in cur['http_statuses']:
                    cur['http_statuses'].append(rec['http_status'])
            else:
                cur['unknown_runs'] += 1
    if cur:
        result.append(cur)
    return [{**i, 'ongoing': i['recovered_at'] is None, 'http_statuses': sorted(i['http_statuses'])} for i in result]


def summarize(records):
    known = [r for r in records if r['state'] == 'RECORDED' and r['outcome'] in ('PASS', 'FAIL')]
    passed = sum(1 for r in known if r['outcome'] == 'PASS')
    times = [r['elapsed_ms'] for r in known if r['elapsed_ms'] is not None]
    return {'runs': len(records), 'pass': passed, 'fail': len(known) - passed,
            'unknown': len(records) - len(known),
            'availability_percent': round(100.0 * passed / len(known), 3) if known else None,
            'avg_elapsed_ms': round(sum(times) / len(times), 1) if times else None,
            'first_slot': records[0]['scheduled_slot'] if records else None,
            'last_slot': records[-1]['scheduled_slot'] if records else None}


class Archive:
    def __init__(self, root, clock=None):
        self.root = Path(root).absolute()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.batches_dir = self.root / 'private' / 'batches'
        self.public = self.root / 'public'

    # ---- housekeeping
    def _check_links(self):
        for part in (self.root, *self.root.parents):
            if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
                raise ValueError('linked archive paths refused')

    def init(self):
        self._check_links()
        marker = self.root / 'managed.json'
        if self.root.exists():
            if not marker.is_file() or json.loads(marker.read_text('utf-8')) != {'schema': SCHEMA}:
                raise ValueError('existing non-archive directory refused')
        else:
            self.root.mkdir(parents=True)
            _atomic(marker, _text({'schema': SCHEMA}).encode())
        self.batches_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def lock(self):
        self.init()
        path = self.root / '.archive-lock'
        try:
            stream = path.open('x')
        except FileExistsError:
            raise ValueError('archive is locked by another run (remove .archive-lock only if no run is active)')
        try:
            yield
        finally:
            stream.close()
            path.unlink(missing_ok=True)

    # ---- batches
    def batches(self, verify=True):
        found = []
        for directory in sorted(p for p in self.batches_dir.glob('*') if p.is_dir() and not p.name.startswith('.')):
            meta = json.loads((directory / 'batch.json').read_text('utf-8'))
            raw = {}
            for entry in meta['files']:
                path = directory / entry['name']
                if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError('invalid batch file ' + entry['name'])
                data = path.read_bytes()
                if verify and (_sha(data) != entry['sha256'] or len(data) != entry['bytes']):
                    raise ValueError(f'batch {meta["id"]}: {entry["name"]} does not match its recorded SHA-256')
                raw[entry['name']] = json.loads(data.decode('utf-8'))
            found.append((meta, raw))
        return found

    def merge(self, batches):
        """-> (runs{target:{slot:(record, raw_item)}}, heads{target:item}, alarms{key:event}, conflicts[], counts{batch:{...}})"""
        runs, heads, alarms, conflicts, counts = {}, {}, {}, [], {}
        for meta, raw in batches:
            tally = counts.setdefault(meta['id'], {'seen': 0, 'new': 0, 'upgraded': 0, 'duplicate': 0, 'rejected': 0, 'conflicts': 0})
            for name, body in raw.items():
                if meta['kind'] == 'alarm-history':
                    for entry in body.get('AlarmHistoryItems', []):
                        tally['seen'] += 1
                        event = normalize_alarm(entry)
                        if event is None:
                            tally['rejected'] += 1
                            continue
                        key = (event['target_id'], event['alarm_kind'], event['at'], event['new_state'])
                        tally['duplicate' if key in alarms else 'new'] += 1
                        alarms.setdefault(key, event)
                    continue
                if body.get('head'):
                    heads[body['head'].get('pk', {}).get('S', '')[8:]] = body['head']
                for item in body.get('items', []):
                    tally['seen'] += 1
                    rec = normalize_run(item)
                    if rec is None:
                        tally['rejected'] += 1
                        continue
                    slots = runs.setdefault(rec['target_id'], {})
                    old = slots.get(rec['scheduled_slot'])
                    if old is None:
                        slots[rec['scheduled_slot']] = (rec, item)
                        tally['new'] += 1
                    elif old[0] == rec:
                        tally['duplicate'] += 1
                    elif old[0]['state'] == 'CLAIMED' and rec['state'] == 'RECORDED':
                        slots[rec['scheduled_slot']] = (rec, item)
                        tally['upgraded'] += 1
                    elif old[0]['state'] == 'RECORDED' and rec['state'] == 'CLAIMED':
                        tally['duplicate'] += 1
                    else:
                        conflicts.append({'target_id': rec['target_id'], 'scheduled_slot': rec['scheduled_slot'], 'batch': meta['id']})
                        tally['conflicts'] += 1
        return runs, heads, alarms, conflicts, counts

    def add_batch(self, kind, source, fetched_at, files):
        """Store one immutable batch; identical content is never stored twice. -> result dict"""
        with self.lock():
            existing = self.batches()
            digest = _sha(_canon(files).encode('utf-8'))
            for meta, _ in existing:
                if meta['content_sha256'] == digest:
                    return {'status': 'ALREADY_IMPORTED', 'batch': meta['id']}
            created = self.clock()
            batch_id = '%s-%s-%s' % (created.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ'), kind, digest[:8])
            tmp = self.batches_dir / ('.tmp-' + batch_id)
            tmp.mkdir()
            entries = []
            for name, body in sorted(files.items()):
                data = _text(body, indent=1).encode('utf-8')
                _atomic(tmp / name, data)
                entries.append({'name': name, 'sha256': _sha(data), 'bytes': len(data)})
            meta = {'schema': SCHEMA, 'id': batch_id, 'kind': kind, 'source': source, 'fetched_at': fetched_at,
                    'created_at': utc(created), 'content_sha256': digest, 'files': entries}
            _atomic(tmp / 'batch.json', _text(meta, indent=1).encode('utf-8'))
            os.replace(tmp, self.batches_dir / batch_id)
            result = {'status': 'IMPORTED', 'batch': batch_id}
            self._write_public(self.batches())
            result.update(counts=self.merge(self.batches())[4][batch_id])
            return result

    # ---- public outputs
    def build_outputs(self, batches):
        runs, _heads, alarms, conflicts, counts = self.merge(batches)
        meta_by_target = _target_meta()
        updated = max((m['created_at'] for m, _ in batches), default=None)
        files, targets = {}, {}
        for target in sorted(runs):
            records = [runs[target][slot][0] for slot in sorted(runs[target])]
            files['runs/%s.jsonl' % target] = ''.join(_canon({k: r[k] for k in RUN_FIELDS}) + '\n' for r in records).encode('utf-8')
            targets[target] = {**meta_by_target.get(target, {}), **summarize(records), 'incidents': incidents(target, records)}
        events = [alarms[k] for k in sorted(alarms)]
        files['incidents.json'] = _text({'schema': PUBLIC_SCHEMA, 'incidents': [i for t in sorted(targets) for i in targets[t]['incidents']]}, 1).encode('utf-8')
        files['alarm_events.json'] = _text({'schema': PUBLIC_SCHEMA, 'events': events}, 1).encode('utf-8')
        listing = {n: {'sha256': _sha(b), 'bytes': len(b), 'lines': b.count(b'\n')} for n, b in sorted(files.items())}
        manifest = {'schema': PUBLIC_SCHEMA, 'updated_at': updated, 'targets': {t: {k: v for k, v in d.items() if k != 'incidents'} for t, d in targets.items()},
                    'alarm_events': len(events), 'conflicts': conflicts, 'files': listing,
                    'batches': [{'id': m['id'], 'kind': m['kind'], 'source': m['source'].get('type'), 'fetched_at': m['fetched_at'],
                                 'created_at': m['created_at'], **counts[m['id']]} for m, _ in batches]}
        files['MANIFEST.json'] = _text(manifest, 2).encode('utf-8')
        files['index.html'] = _html(manifest, targets, events).encode('utf-8')
        sums = ''.join('%s *%s\n' % (_sha(b), n) for n, b in sorted(files.items()))
        files['SHA256SUMS.txt'] = sums.encode('utf-8')
        return files

    def _write_public(self, batches):
        files = self.build_outputs(batches)
        for name, data in files.items():
            _atomic(self.public / name, data)
        return files

    def rebuild(self):
        with self.lock():
            return self._write_public(self.batches())

    def verify(self):
        """-> list of problems (empty = every batch hash, count and public file matches a fresh rebuild)."""
        problems = []
        try:
            self.init_check()
            batches = self.batches()
        except Exception as exc:
            return ['batches unreadable: %s' % exc]
        expected = self.build_outputs(batches)
        on_disk = {p.relative_to(self.public).as_posix() for p in self.public.rglob('*') if p.is_file()} if self.public.is_dir() else set()
        for name in sorted(set(expected) | on_disk):
            if name not in on_disk:
                problems.append('missing public file ' + name)
            elif name not in expected:
                problems.append('unexpected public file ' + name)
            elif (self.public / name).read_bytes() != expected[name]:
                problems.append('public file differs from a rebuild of the immutable batches: ' + name)
        return problems

    def init_check(self):
        marker = self.root / 'managed.json'
        if not marker.is_file() or json.loads(marker.read_text('utf-8')) != {'schema': SCHEMA}:
            raise ValueError('not a run archive')

    def last_slots(self):
        runs = self.merge(self.batches())[0]
        return {t: max(s) for t, s in runs.items() if s}

    def fetched_at(self):
        """Time of the newest stored observation batch (what the archive actually knows), as text."""
        return max((m['fetched_at'] for m, _ in self.batches() if m['kind'] != 'alarm-history'), default=None)

    def home_snapshot(self, pages, now=None):
        """HOME input built only from archived (private) raw items, for the registered pages.

        `now` defaults to the newest fetch time, so HOME shows the data as of that moment and
        marks it as a local import (never as a live reading)."""
        from .aws_b_data import LocalReadStore, read_stores
        batches = self.batches()
        runs, heads = self.merge(batches)[:2]
        if now is None:
            now = datetime.strptime(self.fetched_at(), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        stores = {p['target_id']: LocalReadStore(p['target_id'], heads.get(p['target_id']),
                  [raw for _, raw in runs.get(p['target_id'], {}).values()]) for p in pages}
        snapshot = read_stores(stores, now=now, interval_seconds=900)
        snapshot['http_export']['historical'] = True
        # HOME writes this snapshot into its output folder: drop AWS-side identifiers first.
        for entry in snapshot['http'].values():
            for item in [entry.get('head'), *entry.get('runs', [])]:
                for key in PRIVATE_ITEM_FIELDS:
                    (item or {}).pop(key, None)
        return snapshot

    def home_extra(self, registered):
        """Public-only archive summary for HOME. Registered targets are the real monitored sites;
        every other target (the Gate B fixture) goes to a separate 'trial' block and is never mixed in."""
        batches = self.batches()
        runs, _heads, alarms, _conflicts, _counts = self.merge(batches)

        def block(target):
            records = [runs[target][s][0] for s in sorted(runs[target])]
            return {**summarize(records), 'recent': records[-30:][::-1], 'incidents': incidents(target, records)}
        events = [alarms[k] for k in sorted(alarms)]
        return {'fetched_at': self.fetched_at(), 'sites': {t: block(t) for t in sorted(runs) if t in registered},
                'alarm_events': [e for e in events if e['target_id'] in registered],
                'trial': {'targets': {t: block(t) for t in sorted(runs) if t not in registered},
                          'alarm_events': [e for e in events if e['target_id'] not in registered]}}


def _target_meta():
    """Label / URL of every page an archive may hold. The repo's own pages (src/noxiworks/targets.json) are ALWAYS known, then the active targets
    (SITEPROOF_TARGETS / --targets) are added. So the public files of an archive are the same whichever targets file a build uses: a registered
    site's (signed) targets.json never has to list the AWS-B pages just to display them, and is never edited for that."""
    meta = {}
    try:
        from .product import CONFIG, settings
        for path in (CONFIG, None):
            try:
                meta.update({p['target_id']: {'label': p.get('label'), 'url': p.get('url')} for p in settings(path)['pages']})
            except Exception:
                pass
    except Exception:
        pass
    return meta


def _html(manifest, targets, events):
    rows = ''.join('<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        escape(t), d['runs'], d['pass'], d['fail'], d['unknown'], d['availability_percent'], d['avg_elapsed_ms'], d['first_slot'], d['last_slot'])
        for t, d in sorted(targets.items()))
    inc = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>' % (
        escape(i['target_id']), i['started_at'], i['last_failure_at'], i['recovered_at'] or 'ongoing', i['failed_runs'],
        escape(','.join(map(str, i['http_statuses'])))) for t in sorted(targets) for i in targets[t]['incidents'])
    ev = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s &rarr; %s</td></tr>' % (e['at'], escape(e['target_id']), e['alarm_kind'], e['old_state'], e['new_state']) for e in events)
    return ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>SiteProof run archive</title><style>body{font:14px system-ui;margin:16px;max-width:1000px}table{border-collapse:collapse;width:100%%;margin:8px 0 24px}'
            'td,th{border:1px solid #8884;padding:4px 8px;text-align:left}</style></head><body><h1>SiteProof run archive</h1>'
            '<p>Archive updated: %s (UTC). Static copy of stored observations; it does not show current state.</p>'
            '<h2>Targets</h2><table><tr><th>target</th><th>runs</th><th>pass</th><th>fail</th><th>unknown</th><th>availability %%</th><th>avg ms</th><th>first</th><th>last</th></tr>%s</table>'
            '<h2>Incidents</h2><table><tr><th>target</th><th>started</th><th>last failure</th><th>recovered</th><th>failed runs</th><th>HTTP</th></tr>%s</table>'
            '<h2>Alarm state changes</h2><table><tr><th>at (UTC)</th><th>target</th><th>alarm</th><th>change</th></tr>%s</table></body></html>\n'
            ) % (escape(str(manifest['updated_at'])), rows, inc, ev)


# ---- importers (local files only)
def import_snapshot(archive, path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('invalid snapshot file')
    return _add_snapshot(archive, json.loads(path.read_text('utf-8-sig')), path.name, _sha(path.read_bytes()))


def _add_snapshot(archive, snapshot, name, digest):
    export = snapshot.get('http_export') or {}
    if snapshot.get('source') != 'AWS_EXPORT' or not export.get('fetched_at') or not isinstance(snapshot.get('http'), dict):
        raise ValueError('only an AWS_EXPORT snapshot with fetched_at can be archived (FIXTURE/EMPTY data is refused)')
    files = {'raw/%s.json' % t: {'head': v.get('head'), 'items': v.get('runs', [])} for t, v in sorted(snapshot['http'].items()) if TARGET.fullmatch(t)}
    return archive.add_batch('snapshot', {'type': 'LOCAL_SNAPSHOT', 'file': name, 'file_sha256': digest}, export['fetched_at'], files)


def import_export(archive, directory):
    """The user's own saved GetItem/Query responses (aws_b_data.read_export layout) -> the same archive batch as a snapshot.

    Only pages of the configured targets are read (targets.json / --targets); the time of the export (manifest `exported_at`) is
    required and becomes the batch's acquisition time. Nothing here touches AWS.
    """
    from .aws_b_data import read_export
    snapshot = read_export(directory)
    if snapshot.get('source') != 'AWS_EXPORT' or not (snapshot.get('http_export') or {}).get('exported_at'):
        raise ValueError('an AWS_EXPORT manifest with exported_at (UTC) is required')
    snapshot['http_export']['fetched_at'] = snapshot['http_export']['exported_at']
    manifest = Path(directory) / 'manifest.json'
    return _add_snapshot(archive, snapshot, Path(directory).name, _sha(manifest.read_bytes()))


def import_alarm_history(archive, path):
    path = Path(path)
    body = json.loads(path.read_text('utf-8-sig'))
    if not isinstance(body.get('AlarmHistoryItems'), list):
        raise ValueError('describe-alarm-history output required')
    return archive.add_batch('alarm-history', {'type': 'LOCAL_ALARM_HISTORY', 'file': path.name, 'file_sha256': _sha(path.read_bytes())},
                             utc(datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)), {'alarm-history.json': {'AlarmHistoryItems': body['AlarmHistoryItems']}})


# ---- live read (AWS read-only; explicit gate)
def checked_environment(environ=None):
    env = dict(os.environ if environ is None else environ)
    for key in ('AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_LOGIN_CACHE_DIRECTORY', 'USERPROFILE'):
        if env.get(key) and not Path(env[key]).is_absolute():  # set ones must be absolute; no drive is required (unset = AWS CLI defaults)
            raise ValueError('absolute AWS authentication paths required')
    if any(env.get(k) for k in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_ENDPOINT_URL',
                                'AWS_ENDPOINT_URL_DYNAMODB', 'AWS_WEB_IDENTITY_TOKEN_FILE')):
        raise ValueError('ambiguous credential/endpoint environment refused')
    env.update(AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')
    return env


def fetch_live(archive, config, *, alarm_history=False, runner=None, environ=None, max_pages=200):
    from src.aws_b.model import head_key
    env, runner = checked_environment(environ), runner or subprocess.run
    last = archive.last_slots() if archive.root.exists() else {}

    def call(*args):
        result = runner(['aws', *args, '--profile', config['profile'], '--region', config['region'], '--output', 'json', '--no-cli-pager'],
                        capture_output=True, text=True, encoding='utf-8', timeout=60, env=env)
        if result.returncode != 0 or len(result.stdout.encode('utf-8')) > 8 * 1024 * 1024:
            raise ValueError('READ_FAILED')
        return json.loads(result.stdout.lstrip('﻿'))

    def dynamo(operation, request):
        return call('dynamodb', operation, '--endpoint-url', 'https://dynamodb.us-east-1.amazonaws.com', '--cli-input-json', json.dumps(request),
                    '--no-paginate', '--cli-connect-timeout', '5', '--cli-read-timeout', '20')

    files = {}
    for target, table in sorted(config['tables'].items()):
        request = {'TableName': table, 'KeyConditionExpression': '#pk = :pk', 'ExpressionAttributeNames': {'#pk': 'pk'},
                   'ExpressionAttributeValues': {':pk': {'S': 'RUN#' + target}}, 'ScanIndexForward': True, 'ConsistentRead': True, 'Limit': 500}
        if target in last:
            since = utc(datetime.strptime(last[target], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) - OVERLAP)
            request.update(KeyConditionExpression='#pk = :pk AND #sk >= :since', ExpressionAttributeNames={'#pk': 'pk', '#sk': 'sk'})
            request['ExpressionAttributeValues'][':since'] = {'S': since}
        items = []
        for _ in range(max_pages):
            page = dynamo('query', request)
            if not isinstance(page.get('Items'), list):
                raise ValueError('READ_FAILED')
            items += page['Items']
            if not page.get('LastEvaluatedKey'):
                break
            request['ExclusiveStartKey'] = page['LastEvaluatedKey']
        else:
            raise ValueError('READ_FAILED: too many pages')
        control = dynamo('get-item', {'TableName': table, 'Key': {k: {'S': v} for k, v in head_key(target).items()}, 'ConsistentRead': True})
        files['raw/%s.json' % target] = {'head': control.get('Item'), 'items': items}
    fetched = utc(archive.clock())
    results = [archive.add_batch('aws-dynamodb', {'type': 'AWS_DYNAMODB_QUERY'}, fetched, files)]
    if alarm_history:
        history = []
        for table in sorted(config['tables'].values()):
            for kind in ('failure', 'unpersisted', 'function-error'):
                history += call('cloudwatch', 'describe-alarm-history', '--alarm-name', '%s-%s' % (table[:-len('-runs')], kind),
                                '--history-item-type', 'StateUpdate').get('AlarmHistoryItems', [])
        results.append(archive.add_batch('alarm-history', {'type': 'AWS_CLOUDWATCH_ALARM_HISTORY'}, fetched, {'alarm-history.json': {'AlarmHistoryItems': history}}))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('import-snapshot', 'import-export', 'import-alarm-history', 'fetch', 'verify', 'rebuild', 'snapshot', 'home'):
        p = sub.add_parser(name)
        p.add_argument('--archive', required=True, type=Path)
        p.add_argument('--targets', type=Path, help="your site's targets.json (default: the author's pages)")
        p.add_argument('--capture-plan', type=Path, help="your site's capture_plan.json (default: the author's plan)")
        if name.startswith('import'):
            p.add_argument('files', nargs='+', type=Path)
        if name == 'fetch':
            p.add_argument('--config', required=True, type=Path)
            p.add_argument('--aws-read', action='store_true', help='explicit gate: separate AWS read approval required')
            p.add_argument('--alarm-history', action='store_true', help='also read cloudwatch describe-alarm-history (needs its own approval)')
        if name in ('snapshot', 'home'):
            p.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.targets:
        os.environ['SITEPROOF_TARGETS'] = str(args.targets.resolve())
    if args.capture_plan:
        os.environ['SITEPROOF_CAPTURE_PLAN'] = str(args.capture_plan.resolve())
    archive = Archive(args.archive)
    if args.command in ('import-snapshot', 'import-export', 'import-alarm-history'):
        importer = {'import-snapshot': import_snapshot, 'import-export': import_export}.get(args.command, import_alarm_history)
        for path in args.files:
            result = importer(archive, path)
            print('%s %s %s' % (result['status'], result['batch'], result.get('counts', '')))
    elif args.command == 'fetch':
        if not args.aws_read:
            parser.error('fetch requires --aws-read')
        from .refresh import load_config
        for result in fetch_live(archive, load_config(args.config), alarm_history=args.alarm_history):
            print('%s %s %s' % (result['status'], result['batch'], result.get('counts', '')))
    elif args.command == 'rebuild':
        print('rebuilt %d public files' % len(archive.rebuild()))
    elif args.command == 'snapshot':
        from .product import settings
        snapshot = archive.home_snapshot(settings()['pages'], datetime.now(timezone.utc))
        with args.out.open('x', encoding='utf-8') as stream:
            json.dump(snapshot, stream, ensure_ascii=False, indent=1)
        print(args.out)
    elif args.command == 'home':
        from .home import build
        from .product import settings
        pages = settings()['pages']
        problems = archive.verify()
        if problems:
            raise SystemExit('ARCHIVE_PROBLEMS: ' + '; '.join(problems))
        snapshot = archive.home_snapshot(pages)
        fetched = datetime.strptime(archive.fetched_at(), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        build(args.out, snapshot, now=fetched, archive=archive.home_extra({p['target_id'] for p in pages}))
        print(args.out.resolve() / 'index.html')
        print('HOME built from the local archive only / no AWS or network')
    if args.command in ('verify', 'import-snapshot', 'import-export', 'import-alarm-history', 'fetch', 'rebuild'):
        problems = archive.verify()
        manifest = json.loads((archive.public / 'MANIFEST.json').read_text('utf-8')) if (archive.public / 'MANIFEST.json').exists() else {}
        for target, d in sorted(manifest.get('targets', {}).items()):
            print('%-20s runs=%-5d pass=%-5d fail=%-4d unknown=%-3d %s .. %s' % (target, d['runs'], d['pass'], d['fail'], d['unknown'], d['first_slot'], d['last_slot']))
        print('ARCHIVE_VERIFIED' if not problems else 'ARCHIVE_PROBLEMS: ' + '; '.join(problems))
        if problems:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

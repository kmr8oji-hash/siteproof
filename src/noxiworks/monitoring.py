"""Monitoring status, image-monitoring history and events, derived at render time. Pure: no I/O, no scheduler, no notification.

Ownership (ADR-001 DRAFT, followed, not adopted here): the Monitor Provider (today AWS-B) owns HTTP intervals, results and
incidents (`http_view` / the run archive are shown unchanged); SiteProof owns captures, Baselines and comparisons. Nothing here
is a second incident database: events are recomputed from the saved observations every time and nothing is persisted.

* history: one entry per saved capture job (manifest-checked runs read by local_capture), de-duplicated by (page, job id);
  a job seen twice with different contents is refused. Synthetic runs only ever appear as demo data (never with real runs).
* events: per page and profile, only state CHANGES are events (the same result twice is one event, never a new notice);
  RECOVERED = a decided comparison after a failure / undecided one; STALE = no observation for 2 intervals (never "normal").
* schedule: the configured interval per channel. A real schedule state can only come from a provider / runner record
  (`snapshot['schedule']`, schema SCHEDULE_SCHEMA; see schedule_record) — that is the connection point for future automatic
  runs. Without one, a channel is NOT_RUNNING (予定・未稼働) and no "next run" is invented.
"""
from datetime import timedelta

from src.aws_b.model import format_utc, parse_utc
from src.comparison.operational import present

SCHEDULE_SCHEMA = 'siteproof.schedule-state.v1'
CHANNELS = {'http': 'HTTP（死活）', 'capture': '画像（撮影・比較）'}
STALE_INTERVALS = 2
# Comparison classes of one capture job.
CLASS_LABELS = {'UNCHANGED': '変更なし', 'CHANGED': '変更あり', 'UNKNOWN': '判定不能', 'FAILED': '撮影失敗', 'NOT_COMPARED': '比較なし（Baseline未承認）'}
EVENT_LABELS = {'UNCHANGED': '変更なしを確認', 'CHANGED': '画像の変更を検知', 'UNKNOWN': '判定不能', 'FAILED': '撮影・監視に失敗',
                'NOT_COMPARED': '撮影のみ（比較なし）', 'RECOVERED': '復旧（比較が再び確定）', 'STALE': '長期間未監視'}
ATTENTION = ('CHANGED', 'UNKNOWN', 'FAILED', 'STALE')
SCHEDULE_LABELS = {'NOT_RUNNING': '予定・未稼働', 'SCHEDULED': '自動実行中（記録あり）', 'STOPPED': '停止', 'OVERDUE': '予定時刻を過ぎて未実行',
                   'NO_SETTING': '監視設定なし', 'PROVIDER_UNKNOWN': 'Provider管理・現在未確認', 'UNVERIFIED': '有効の記録あり・現在未確認'}
# HTTP intervals belong to the Monitor Provider (ADR-001): without its state, "not running" would be a claim nobody made.


def classify(capture):
    """One saved capture job -> (class, operational presentation). A capture without an approved Baseline is not an alert."""
    if capture.get('execution') != 'COMPLETED' or capture.get('status') != 'SUCCEEDED':
        return 'FAILED', None
    result = capture.get('result') or {}
    visual = present(result, None)
    if result.get('baseline') is None:
        return 'NOT_COMPARED', visual
    return {'NO_VISUAL_CHANGE_DETECTED': 'UNCHANGED', 'VISUAL_CHANGED': 'CHANGED'}.get(visual.get('verdict'), 'UNKNOWN'), visual


def history_entries(runs, *, latest_run_ids=()):
    """runs: [(run_id, page_id, change, synthetic)] from local_capture.load -> entries, oldest first, one per job."""
    seen = {}
    for run_id, page_id, change, synthetic in runs:
        for c in change.get('captures', []):
            cls, visual = classify(c)
            result = c.get('result') or {}
            pin, metrics = result.get('baseline'), result.get('metrics') or {}
            entry = {'target_id': page_id, 'run_id': run_id, 'kind': c['kind'], 'job_id': c['job_id'], 'observed_at': c['captured_at'],
                     'execution': c.get('execution'), 'class': cls, 'label': CLASS_LABELS[cls],
                     'baseline': {'candidate_id': pin['candidate_id'], 'version': pin['version']} if pin else None,
                     'verdict': visual.get('verdict') if visual else None,
                     'reasons': list(visual.get('reasons') or []) if visual and cls == 'UNKNOWN' else [],
                     'reason_labels': list(visual.get('reason_labels') or []) if visual and cls == 'UNKNOWN' else [],
                     'changed_pixels': metrics.get('changed_pixels') if pin else None, 'total_pixels': metrics.get('total_pixels') if pin else None,
                     'stability': (result.get('capture_stability') or {}).get('value'), 'synthetic': synthetic is True,
                     'image_label': (visual or {}).get('image', {}).get('label') if pin else None,
                     'quality_label': (visual or {}).get('quality', {}).get('label') if pin else None,
                     'in_review': run_id in latest_run_ids}
            key = (page_id, c['job_id'])
            if key in seen:  # the same job reached through another run directory: its observation must be identical
                if ({k: v for k, v in seen[key].items() if k not in ('in_review', 'run_id')}
                        != {k: v for k, v in entry.items() if k not in ('in_review', 'run_id')}):
                    raise ValueError('the same capture job is recorded twice with different contents')
                seen[key]['in_review'] = seen[key]['in_review'] or entry['in_review']
                continue
            seen[key] = entry
    if len({e['synthetic'] for e in seen.values()}) > 1:
        raise ValueError('real and synthetic history are never mixed')
    return sorted(seen.values(), key=lambda e: (e['observed_at'], e['target_id'], e['kind']))


def _stale_at(last, interval):
    moment = parse_utc(last)
    return format_utc(moment + timedelta(seconds=interval * STALE_INTERVALS)) if moment else None


def image_events(entries, now, interval):
    """State changes per (page, profile), plus RECOVERED and a derived STALE. -> newest first. Idempotent for repeated inputs."""
    events, last = [], {}
    for e in entries:
        key = (e['target_id'], e['kind'])
        previous = last.get(key)
        if previous is None or previous['class'] != e['class']:
            recovered = previous is not None and previous['class'] in ('UNKNOWN', 'FAILED') and e['class'] in ('UNCHANGED', 'CHANGED')
            events.append({'at': e['observed_at'], 'target_id': e['target_id'], 'kind': e['kind'], 'type': e['class'],
                           'label': EVENT_LABELS[e['class']], 'job_id': e['job_id'], 'synthetic': e['synthetic']})
            if recovered:
                events.append({**events[-1], 'type': 'RECOVERED', 'label': EVENT_LABELS['RECOVERED']})
        last[key] = e
    for (target, kind), e in last.items():
        due = _stale_at(e['observed_at'], interval)
        if due and parse_utc(due) <= now:
            events.append({'at': due, 'target_id': target, 'kind': kind, 'type': 'STALE', 'label': EVENT_LABELS['STALE'],
                           'job_id': None, 'synthetic': e['synthetic']})
    # Newest first; at the same moment, the later-derived event (RECOVERED after its observation) comes first.
    order = sorted(range(len(events)), key=lambda i: (events[i]['at'], i), reverse=True)
    return [events[i] for i in order]


def schedule_record(raw):
    """Validate one provider / runner schedule record (read-only input). Anything malformed is refused, never repaired."""
    keys = {'schema', 'target_id', 'channel', 'enabled', 'last_finished_at', 'last_outcome', 'next_due_at', 'source'}
    # observed_at (optional): when the provider state itself was read. An old reading is shown as unverified, never as running.
    if (type(raw) is not dict or not keys <= set(raw) <= keys | {'observed_at'} or raw['schema'] != SCHEDULE_SCHEMA or raw['channel'] not in CHANNELS
            or type(raw['enabled']) is not bool or raw['last_outcome'] not in (None, 'COMPLETED', 'FAILED')
            or any(raw.get(k) is not None and parse_utc(raw[k]) is None for k in ('last_finished_at', 'next_due_at', 'observed_at'))
            or type(raw['source']) is not str or not raw['source']):
        raise ValueError('invalid schedule record')
    return dict(raw)


def channel_status(*, channel, interval, last, last_success, last_outcome, record, now, configured=True):
    """One page x channel. `last` = latest observation (any result); `record` = validated schedule record or None."""
    stale_at = _stale_at(last, interval)
    freshness = 'NONE' if last is None else 'STALE' if parse_utc(stale_at) <= now else 'RECENT'
    if not configured:
        state, next_due = 'NO_SETTING', None
    elif record is None:
        # SiteProof's own channel: no scheduler runs it. A provider channel: its state was not read, so it is unknown.
        state, next_due = ('PROVIDER_UNKNOWN' if channel == 'http' else 'NOT_RUNNING'), None
    elif record.get('observed_at') and parse_utc(record['observed_at']) + timedelta(seconds=interval * STALE_INTERVALS) <= now:
        state, next_due = ('UNVERIFIED' if record['enabled'] else 'STOPPED'), None
    elif not record['enabled']:
        state, next_due = 'STOPPED', None
    else:
        next_due = record['next_due_at']
        # A schedule whose next run is more than one interval overdue has missed runs: never shown as running normally.
        state = 'OVERDUE' if next_due and parse_utc(next_due) + timedelta(seconds=interval) < now else 'SCHEDULED'
    failed = last_outcome == 'FAILED'
    attention = failed or freshness in ('STALE', 'NONE') or state in ('STOPPED', 'OVERDUE', 'PROVIDER_UNKNOWN', 'UNVERIFIED')
    return {'channel': channel, 'channel_label': CHANNELS[channel], 'interval_seconds': interval, 'last_at': last,
            'last_success_at': last_success, 'last_outcome': last_outcome, 'freshness': freshness, 'stale_at': stale_at,
            'schedule_state': state, 'schedule_label': SCHEDULE_LABELS[state], 'next_due_at': next_due,
            'source': record['source'] if record else None, 'observed_at': record.get('observed_at') if record else None, 'attention': attention}


def build(pages, history, schedule, now, *, http_interval, capture_interval, synthetic=False):
    """-> view['monitoring']: per-page channel status, history, events, notices and the overall state. Pure."""
    records = {(r['target_id'], r['channel']): r for r in (schedule_record(x) for x in schedule or [])}
    by_page = {}
    for e in history:
        by_page.setdefault(e['target_id'], []).append(e)
    rows, notices = [], []
    events = image_events(history, now, capture_interval)
    for p in pages:
        tid, http = p['target_id'], p['http']
        http_last = http.get('last_checked_at')
        # The latest saved observation and its outcome (PASS stays a past PASS: freshness decides whether it is STALE).
        outcome = http.get('last_outcome')
        http_ok = http_last if outcome == 'PASS' else None
        http_row = channel_status(channel='http', interval=http_interval, last=http_last, last_success=http_ok,
                                  last_outcome={'FAIL': 'FAILED', 'PASS': 'COMPLETED'}.get(outcome), record=records.get((tid, 'http')), now=now,
                                  configured=not p.get('local_capture'))
        mine = by_page.get(tid, [])
        latest = {}
        for e in mine:
            latest[e['kind']] = e
        last = max((e['observed_at'] for e in mine), default=None)
        decided = [e['observed_at'] for e in mine if e['class'] in ('UNCHANGED', 'CHANGED')]
        capture_row = channel_status(channel='capture', interval=capture_interval, last=last, last_success=max(decided, default=None),
                                     last_outcome=('FAILED' if any(e['class'] == 'FAILED' for e in latest.values()) else 'COMPLETED') if latest else None,
                                     record=records.get((tid, 'capture')), now=now, configured=bool(p.get('plan')) or bool(mine))
        capture_row['latest'] = [{k: e[k] for k in ('kind', 'class', 'label', 'observed_at', 'job_id', 'reason_labels')} for e in latest.values()]
        rows.append({'target_id': tid, 'label': p['label'], 'site': p.get('site_name', p['domain']), 'channels': [http_row, capture_row]})
        for e in latest.values():
            if e['class'] in ATTENTION:
                notices.append({'type': e['class'], 'target_id': tid, 'kind': e['kind'], 'at': e['observed_at'], 'label': EVENT_LABELS[e['class']],
                                'detail': '／'.join(e['reason_labels'][:2]), 'synthetic': e['synthetic']})
        if capture_row['freshness'] == 'STALE':
            notices.append({'type': 'STALE', 'target_id': tid, 'kind': None, 'at': capture_row['stale_at'], 'label': EVENT_LABELS['STALE'],
                            'detail': '画像の監視が2回分の間隔を超えて行われていません', 'synthetic': synthetic})
    running = [c for r in rows for c in r['channels'] if c['schedule_state'] == 'SCHEDULED']
    configured = [c for r in rows for c in r['channels'] if c['schedule_state'] != 'NO_SETTING']
    successes = [(c['last_success_at'], c['channel'], r['target_id']) for r in rows for c in r['channels'] if c['last_success_at']]
    unknown = [c for c in configured if c['schedule_state'] in ('PROVIDER_UNKNOWN', 'UNVERIFIED')]
    overall = ('UNKNOWN' if unknown else 'NOT_RUNNING' if not running else 'ATTENTION' if any(c['attention'] for c in configured) else 'SCHEDULED')
    return {'rows': rows, 'history': list(reversed(history)), 'events': events, 'notices': notices, 'synthetic': synthetic,
            'overall': overall, 'overall_label': {'NOT_RUNNING': '自動監視は未稼働（保存済みの結果のみ）', 'ATTENTION': '要確認の監視があります',
                                                   'SCHEDULED': '自動実行の記録あり', 'UNKNOWN': '現在の監視状態は未確認（保存済みの結果のみ）'}[overall],
            'last_success': max(successes) if successes else None,
            'not_running': sum(c['schedule_state'] == 'NOT_RUNNING' for c in configured), 'provider_unknown': unknown}

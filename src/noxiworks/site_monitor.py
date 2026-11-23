"""Automatic monitoring of the registered site: initial inspection -> automatic initial Baseline -> scheduled, compared inspections.

Run one due inspection from an OS scheduler (GUI closed):   py -3.15 -B -m src.noxiworks.site_monitor --data DIR
The local app (src/noxiworks/app.py) calls the same Monitor.run_if_due() from its background thread while it is open. A lock file
(site/monitor.lock) keeps the two from ever running at the same time. This module registers nothing with the OS scheduler.

State is site/monitor.json (settings + last result + next due time, written atomically) and site/monitor-log.jsonl (one line per
finished inspection, including failures that produced no run).

Baseline rule:
  * no Baseline yet: the first inspection whose Desktop AND Mobile captures completed and were STABLE becomes the initial Baseline
    automatically (SQLiteBaselineStore.decide through Site.approve, actor = AUTO_ACTOR, recorded as AUTO_INITIAL and "not confirmed
    by the user"). An unstable or failed first inspection creates nothing; the next scheduled inspection tries again.
  * the user may mark it confirmed (a separate confirmation record; the approved Baseline itself is not touched).
  * a detected change NEVER updates the Baseline. Replacing a Baseline is not implemented.
Capture mode per inspection: REAL through src/noxiworks/real_capture.py when all its gates hold; otherwise NOTHING is captured
(REAL_NOT_READY). The offline fixture is used only when a test constructs Monitor(fixture_capture=True).
Storage: no saved inspection is ever deleted; at the per-site limit (disk_limit_bytes) monitoring pauses with DISK_FULL.
Optional stop policy (monitor.json "stop_policy", set explicitly for a bounded run such as the live lifecycle check; absent = unchanged
behaviour): monitoring PAUSES (enabled false, paused_reason) instead of scheduling the next inspection when an inspection ends in an
anomaly (halt_on), when it ends in an outcome that waits for the USER (pause_after), or when the planned number of good inspections is
done (stop_after_runs); and an inspection does not start (ON_HOLD, nothing captured, no permit run used) while the USER's Baseline
decision is open (hold_for_decisions: a formal approval of an automatic Baseline, a change waiting for "新しい基準にする", an unfinished
switch). The policy never starts, resumes or retries anything and never changes a permit; resuming is the USER's explicit action.
"""
import argparse
from datetime import timedelta
import json
import os
from pathlib import Path
import sys
import threading
import time

from src.aws_b.model import format_utc, parse_utc

NOT_READY_RETRY_SECONDS = 3600  # REAL_NOT_READY: look again within the hour (nothing is captured meanwhile)

INTERVALS = {900: '15分ごと', 3600: '1時間ごと', 21600: '6時間ごと', 86400: '24時間ごと'}
GOOD_OUTCOMES = ('BASELINE_CREATED', 'UNCHANGED', 'CHANGED')  # a finished, comparable inspection
DEFAULT_HALT_ON = ('FAILED', 'UNKNOWN', 'REAL_NOT_READY', 'NO_BASELINE', 'DISK_FULL')
POLICY_KEYS = {'halt_on', 'pause_after', 'stop_after_runs', 'hold_for_decisions', 'completed'}
DEFAULT_INTERVAL = 3600
AUTO_ACTOR = 'SiteProof自動作成（初回の安定した撮影・利用者は未確認）'
DISK_LIMIT = 2 * 1024 ** 3  # default per-site storage limit; at the limit monitoring pauses (nothing is deleted)
DISK_WARN = 0.8
LOCK_STALE_SECONDS = 900  # a lock older than this is left over from a crashed worker
SETTINGS_LOCK = threading.Lock()  # load-modify-save of monitor.json within this process (GUI vs scheduler thread)
OUTCOME_LABELS = {'BASELINE_CREATED': '初期Baselineを自動作成', 'NO_BASELINE': '撮影のみ（Baseline未作成：撮影が不安定）',
                  'UNCHANGED': '変更なし', 'CHANGED': '変更を検知', 'UNKNOWN': '判定不能', 'FAILED': '検査に失敗',
                  'DISK_FULL': '保存容量の上限で停止', 'REAL_NOT_READY': '実サイト監視の準備待ち（撮影せず）',
                  'ON_HOLD': 'Baselineの判断待ち（撮影せず）'}


def default_settings(now):
    return {'schema': 'siteproof.app-monitor.v1', 'enabled': True, 'interval_seconds': DEFAULT_INTERVAL, 'next_due_at': format_utc(now),
            'offline_fixture': 'same', 'last': None, 'baseline_confirmed': None}


def classify(summary, created):
    """One finished inspection -> outcome. A change outranks an undecided profile; an undecided one outranks 'unchanged'."""
    if not summary['compared']:
        return 'BASELINE_CREATED' if created else 'NO_BASELINE'
    verdicts = {p['verdict'] for p in summary['profiles'].values()}
    return 'CHANGED' if 'VISUAL_CHANGED' in verdicts else 'UNKNOWN' if verdicts - {'NO_VISUAL_CHANGE_DETECTED'} else 'UNCHANGED'


class Busy(Exception):
    pass


class _NotReady(Exception):
    pass


class Monitor:
    def __init__(self, site, docker_found=None, real_runner=None, fixture_capture=False):
        self.site = site
        self.docker_found, self.real_runner = docker_found, real_runner  # injectable for offline tests only
        # Synthetic captures for a registered site: OFF. Only tests of the monitoring engine turn it on (Python API, no GUI / CLI
        # switch), so a site that cannot be captured for real is never shown as successfully monitored with generated images.
        self.fixture_capture = fixture_capture
        self.path = site.root / 'monitor.json'
        self.log_path = site.root / 'monitor-log.jsonl'
        self.lock_path = site.root / 'monitor.lock'

    @classmethod
    def create(cls, site, now):
        m = cls(site)
        m.save(default_settings(now))
        return m

    def load(self):
        return json.loads(self.path.read_text('utf-8'))

    def save(self, settings):
        tmp = self.path.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        os.replace(tmp, self.path)

    def log(self, limit=10):
        if not self.log_path.is_file():
            return []
        lines = self.log_path.read_text('utf-8').splitlines()[-limit:]
        return [json.loads(x) for x in reversed(lines) if x.strip()]

    def update(self, now, interval_override=None, **changes):
        """Pause / resume / interval / offline fixture, from the GUI. Resuming never fires a burst: one inspection at most, when due."""
        with SETTINGS_LOCK:
            return self._update(now, changes, interval_override)

    def _update(self, now, changes, interval_override=None):
        settings = self.load()
        if 'interval_seconds' in changes and changes['interval_seconds'] not in INTERVALS:
            raise ValueError('検査間隔は 15分・1時間・6時間・24時間 から選んでください')
        if 'enabled' in changes and type(changes['enabled']) is not bool:
            raise ValueError('enabled must be true/false')
        if 'stop_policy' in changes:
            policy = changes['stop_policy']
            if policy is not None and (not isinstance(policy, dict) or set(policy) - POLICY_KEYS
                                       or any(type(policy.get(k)) is not t for k, t in (('stop_after_runs', int), ('hold_for_decisions', bool), ('completed', int)) if k in policy)
                                       or any(not isinstance(policy.get(k), list) for k in ('halt_on', 'pause_after') if k in policy)):
                raise ValueError('stop_policy is not valid')
        settings.update(changes)
        if changes.get('enabled') is True:
            settings.pop('paused_reason', None)
        if changes.get('enabled') is True or 'interval_seconds' in changes:
            last = parse_utc((settings.get('last') or {}).get('finished_at') or '')
            due = last + timedelta(seconds=interval_override or settings['interval_seconds']) if last else now
            settings['next_due_at'] = format_utc(max(due, now))
        self.save(settings)
        return settings

    def is_due(self, now):
        s = self.load()
        due = parse_utc(s['next_due_at'] or '')
        return s['enabled'] and due is not None and now >= due

    # ---- one inspection, serialised across processes by an exclusive lock file
    def _lock(self, now):
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - self.lock_path.stat().st_mtime
            except FileNotFoundError:
                age = 0
            if age < LOCK_STALE_SECONDS:
                raise Busy('another inspection is running') from None
            self.lock_path.unlink(missing_ok=True)  # left over from a crashed worker
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, json.dumps({'pid': os.getpid(), 'at': format_utc(now)}).encode())
        os.close(fd)

    def running(self):
        return self.lock_path.exists()

    def disk(self):
        """Bytes used by this site's folder (every saved inspection, workspace, Baseline) and the configured limit."""
        used = sum(f.stat().st_size for f in self.site.root.rglob('*') if f.is_file())
        limit = self.load().get('disk_limit_bytes', DISK_LIMIT)
        return {'used': used, 'limit': limit, 'warn': used >= limit * DISK_WARN, 'full': used >= limit}

    def real(self):
        from src.noxiworks.real_capture import RealCapture
        return RealCapture(self.site, docker_found=self.docker_found, runner=self.real_runner)

    def _hold(self, policy):
        """Why an inspection must not start now (the USER's Baseline decision is open), or None. Reads only; changes nothing."""
        if not policy or not policy.get('hold_for_decisions'):
            return None
        state = self.real().baseline_update_state()['state']
        if state == 'SWITCH_PENDING':
            return 'Baselineの更新の切替が未完了です'
        if state in ('AVAILABLE', 'BLOCKED'):
            return '変更の確認待ちです（内容を確認し、「新しい基準にする」かどうか決めてください）'
        if self.site.baseline_state()['state'] in ('AUTO', 'CONFIRMED'):
            return '自動作成のBaselineの正式承認待ちです（REVIEWで「このBaselineを正式承認」してください）'
        return None

    @staticmethod
    def _policy_stop(policy, entry):
        """-> the paused_reason when this finished inspection ends the bounded run, else None. Counts good inspections in the policy."""
        outcome = entry.get('outcome')
        if outcome in (policy.get('halt_on') or DEFAULT_HALT_ON):
            return 'ANOMALY:' + str(outcome)
        if outcome in GOOD_OUTCOMES:
            policy['completed'] = policy.get('completed', 0) + 1
            if policy.get('stop_after_runs') and policy['completed'] >= policy['stop_after_runs']:
                return 'COMPLETE'
            if outcome in (policy.get('pause_after') or ()):
                return 'DECISION:' + outcome
        return None

    def update_baseline(self, run_id, expected_versions, now, actor):
        """The USER's "new Baseline": serialised with inspections by the same lock (an inspection in progress keeps the Baseline it started
        with; an update never runs during one). It neither pauses nor restarts monitoring: the next inspection simply pins the new version."""
        try:
            self._lock(now)
        except Busy:
            raise Busy('検査中のため、Baselineを更新できません。検査が終わってからもう一度お試しください') from None
        try:
            return self.real().update_baseline(run_id, expected_versions, now, actor)
        finally:
            self.lock_path.unlink(missing_ok=True)

    def approve_baseline(self, expected, now, actor):
        """The USER's formal approval of the current Baseline: serialised with inspections and updates by the same lock; it does not
        start, stop or reschedule monitoring and does not touch the permit."""
        try:
            self._lock(now)
        except Busy:
            raise Busy('検査中のため、正式承認できません。検査が終わってからもう一度お試しください') from None
        try:
            return self.real().approve_baseline(expected, now, actor)
        finally:
            self.lock_path.unlink(missing_ok=True)

    def run(self, now, trigger, interval_override=None, clock=None):
        """Inspect once (Desktop + Mobile): REAL through the harness when all five real-capture gates hold, else the offline fixture.
        Create the initial Baseline from the first stable inspection, log, schedule the next. Stops (pauses) at the disk limit."""
        from src.noxiworks.site_workflow import Site
        self._lock(now)
        try:
            settings = self.load()
            entry = {'started_at': format_utc(now), 'trigger': trigger}
            disk = self.disk()
            hold = None if disk['full'] else self._hold(settings.get('stop_policy'))
            if disk['full']:
                # Nothing is deleted: monitoring pauses safely and the user decides (raise the limit or free space elsewhere).
                entry.update(outcome='DISK_FULL', mode=self.site.mode(), error=f"保存容量の上限に達しました（{disk['used']:,} / {disk['limit']:,} バイト）")
                with SETTINGS_LOCK:
                    current = self.load()
                    current.update(enabled=False, paused_reason='DISK_FULL', last=entry)
                    self.save(current)
            elif hold:
                # nothing is captured and no permit run is used: the USER's decision comes first; monitoring waits (paused) until resumed
                entry.update(outcome='ON_HOLD', mode=self.site.mode(), error=hold + '（撮影せず、監視を一時停止しました）')
                with SETTINGS_LOCK:
                    current = self.load()
                    current.update(enabled=False, paused_reason='ON_HOLD', last=entry)
                    self.save(current)
            else:
                real = self.real()
                mode = ('REAL' if real.ready(now) else 'OFFLINE_FIXTURE' if self.fixture_capture and self.site.mode() != 'REAL'
                        else 'REAL_NOT_READY')
                entry.update(mode=mode, fixture=None if mode != 'OFFLINE_FIXTURE' else settings['offline_fixture'])
                try:
                    created = False
                    if mode == 'REAL_NOT_READY':
                        # Not capturable for real: nothing is captured or generated; the entry says which gate is missing.
                        raise _NotReady('、'.join(c['label'] for c in real.readiness(now) if not c['ok']))
                    if mode == 'REAL':
                        summary = real.capture(now)
                        if self.site.real_registry() is None and Site.approvable(summary) is None and not summary['compared']:
                            real.create_baseline(summary, now, AUTO_ACTOR)
                            created = True
                    else:
                        summary = self.site.capture(settings['offline_fixture'], now)
                        if self.site.registry() is None and Site.approvable(summary) is None and not summary['compared']:
                            self.site.approve(summary['run_id'], now, actor=AUTO_ACTOR, origin='AUTO_INITIAL')
                            created = True
                    entry.update(outcome=classify(summary, created), run_id=summary['run_id'],
                                 profiles={k: {f: p.get(f) for f in ('verdict', 'reasons', 'changed_pixels', 'stability', 'compared', 'image_label', 'quality_label')}
                                           for k, p in summary['profiles'].items()})
                except _NotReady as exc:
                    entry.update(outcome='REAL_NOT_READY', error='実サイト撮影の条件が整っていないため撮影しませんでした：' + str(exc))
                except Exception as exc:  # recorded and shown; the schedule continues (no tight retry loop)
                    entry.update(outcome='FAILED', error=type(exc).__name__ + ': ' + str(exc)[:300])
                finished = (clock or (lambda: now))()
                entry['finished_at'] = format_utc(finished)
                interval = interval_override or settings['interval_seconds']
                if entry.get('outcome') == 'REAL_NOT_READY':
                    interval = min(interval, NOT_READY_RETRY_SECONDS)
                with SETTINGS_LOCK:
                    current = self.load()  # the GUI may have paused / changed the interval meanwhile
                    current['last'] = entry
                    current['next_due_at'] = format_utc(finished + timedelta(seconds=interval))
                    if current.get('stop_policy'):
                        stop = self._policy_stop(current['stop_policy'], entry)
                        if stop:  # the next inspection is NOT scheduled: monitoring pauses until the USER resumes it
                            current.update(enabled=False, paused_reason=stop)
                    self.save(current)
            entry.setdefault('finished_at', format_utc(now))
            with self.log_path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            return entry
        finally:
            self.lock_path.unlink(missing_ok=True)

    def run_if_due(self, now, interval_override=None, clock=None):
        if not self.is_due(now):  # a running inspection (lock) raises Busy; a stale lock from a crash is taken over
            return None
        return self.run(now, 'SCHEDULE', interval_override, clock)


def main(argv=None):
    """One pass for an OS scheduler: inspect the registered site if (and only if) it is due. Exit 0 also when nothing was due."""
    from datetime import datetime, timezone
    from src.noxiworks.site_workflow import Site
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True, help='the app data folder (the one the app uses)')
    args = parser.parse_args(argv)
    sites = sorted(p for p in (args.data / 'sites').glob('site-*') if (p / 'site.json').is_file()) if (args.data / 'sites').is_dir() else []
    if not sites:
        print('no registered site')
        return 0
    monitor = Monitor(Site(sites[0]))

    def clock():
        return datetime.now(timezone.utc).replace(microsecond=0)
    try:
        entry = monitor.run_if_due(clock(), clock=clock)
    except Busy:
        print('busy: another inspection is running')
        return 0
    print('not due' if entry is None else f"{entry['outcome']} {entry.get('run_id') or entry.get('error')}")
    return 0 if entry is None or entry['outcome'] != 'FAILED' else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Baseline update: the new capture of a CHANGED real inspection becomes version N+1 of the page's Baseline, by the USER's explicit approval.

Nothing new is invented here. The decision is the existing SQLiteBaselineStore.decide (one-shot candidate approval + the explicit
expected_current_version compare-and-swap, one transaction; a repeated approval raises AlreadyDecided and never makes a second version),
and the registry is the same registry folder the next capture already stages (baseline_runtime.stage / check_bindings).

build() works on a COPY: the compared run's workspace (which is the current registry's workspace plus that run's PENDING candidates) is
copied into a NEW registry folder and only the copy is decided. The run's evidence and the current registry are re-hashed before and
after and never written. Any refusal raises Stop with nothing approved and nothing left behind (the caller removes the new folder).
No browser, network, Docker, AWS or database other than the copied workspace.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time

from src.aws_b.model import format_utc
from src.baseline.model import BaselineStatus
from src.comparison.service import ComparisonService
from src.core.offline import OfflineWorkspace
from src.noxiworks.baseline_runtime import POLICY, read_registry
from tools.register_baseline import SCHEMA, Stop, check_candidate, read_candidates, sha, tree, verify_export


def history_rows(db, page_id, fingerprint):
    """(version, candidate_id) pairs of one page/profile, read through an immutable URI: the file is never opened for writing."""
    with closing(sqlite3.connect(Path(db).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as c:
        return [tuple(r) for r in c.execute('SELECT version,candidate_id FROM baseline_versions WHERE page_id=? AND profile_fingerprint=? ORDER BY version',
                                            (page_id, fingerprint))]


def candidates_of(run_dir, summary):
    """-> [(kind, candidate_id, png_sha)] of a finished inspection, from its own saved results (never from memory)."""
    out = []
    for kind, p in summary['profiles'].items():
        result = json.loads((Path(run_dir) / f'{kind}-run-result.json').read_text('utf-8'))
        out.append((kind, p['candidate'], result['state']['jobs'][0]['evidence']['digest']))
    return out


def check_updatable(summary):
    """None if this inspection's new capture may become the Baseline; else the reason (shown to the user). UNKNOWN is never approvable."""
    if not summary['compared']:
        return 'この検査はBaselineと比較していません'
    verdicts = {p['verdict'] for p in summary['profiles'].values()}
    if verdicts - {'NO_VISUAL_CHANGE_DETECTED', 'VISUAL_CHANGED'}:
        return '判定不能（UNKNOWN）の結果は、新しいBaselineにできません。もう一度検査してください'
    if 'VISUAL_CHANGED' not in verdicts:
        return '変更が検知されていないため、新しいBaselineにする必要はありません'
    for kind, p in summary['profiles'].items():
        if p['execution'] != 'COMPLETED':
            return f'{kind}の撮影が完了していません'
        if p['stability'] != 'STABLE':
            return f'{kind}の撮影が安定していません。もう一度検査してください'
    return None


def build(evidence, current, out, actor, instruction, profiles, summary, now=None):
    """-> the new registry's record (written under `out`, a NEW folder). `current` is the registry the inspection was compared with;
    `profiles` the capture plan's profiles of the page; `summary` the inspection's saved summary (Site.summary)."""
    evidence, current, out = Path(evidence).resolve(), Path(current).resolve(), Path(out).resolve()
    if out.exists():
        raise Stop('registry output exists; nothing overwritten')
    why = check_updatable(summary)
    if why:
        raise Stop(why)
    before_run, before_current = verify_export(evidence), verify_export(current)
    old = read_registry(current)  # manifest-checked
    report = json.loads((evidence / 'validation-result.json').read_text('utf-8'))
    if report.get('passed') is not True or report.get('synthetic') is True or report.get('baseline_approved') is not False or report.get('baseline_compared') is not True:
        raise Stop('only a passed, real, compared run can update the Baseline')
    planned = {p['kind']: {**p, 'page_id': old['page_id']} for p in profiles}
    old_by_kind = {b['kind']: b for b in old['baselines']}
    approvals = candidates_of(evidence, summary)
    if sorted(k for k, _, _ in approvals) != sorted(old_by_kind) or sorted(planned) != sorted(old_by_kind):
        raise Stop('the inspection does not cover exactly the profiles of the current Baseline')
    rows = read_candidates(evidence / 'workspace' / 'siteproof.sqlite')
    checked = []
    for kind, cid, png_sha in approvals:
        job, stability = check_candidate(evidence, report, kind, cid, png_sha, planned[kind])
        b = old_by_kind[kind]
        result = json.loads((evidence / f'{kind}-run-result.json').read_text('utf-8'))
        comp = next(r for r in result['comparison']['results'] if r.get('job_id') == job['job_id'])
        # the inspection was compared with exactly the Baseline that is current now (the old version is named, not assumed)
        if comp.get('baseline') != {'candidate_id': b['candidate_id'], 'version': b['version'], 'digest': b['candidate_digest'],
                                    'fingerprint': b['profile_fingerprint']}:
            raise Stop(f'{kind}: the inspection was not compared with the current Baseline (it changed since)')
        row = rows.get(cid)
        if row is None or row['decided'] or row['artifact_sha256'] != png_sha or row['page_id'] != job['page_id'] or row['profile_fingerprint'] != b['profile_fingerprint']:
            raise Stop(f'{kind}: the candidate is missing, already decided, or bound to another image or profile')
        before_history = history_rows(evidence / 'workspace' / 'siteproof.sqlite', job['page_id'], b['profile_fingerprint'])
        if before_history != history_rows(current / 'workspace' / 'siteproof.sqlite', job['page_id'], b['profile_fingerprint']) or \
                not before_history or before_history[-1] != (b['version'], b['candidate_id']):
            raise Stop(f'{kind}: the inspection workspace does not continue the current Baseline history')
        checked.append((kind, cid, png_sha, job, stability, row, b, before_history))
    source = evidence / 'workspace'
    for side in ('-journal', '-wal', '-shm'):
        if (source / ('siteproof.sqlite' + side)).exists():
            raise Stop('run database has a live sidecar file')
    out.mkdir(parents=True)
    shutil.copytree(source, out / 'workspace')
    if tree(out / 'workspace') != tree(source):
        raise Stop('workspace copy differs from the evidence')
    workspace = OfflineWorkspace((out / 'workspace' / 'siteproof.sqlite').resolve(), (out / 'workspace').resolve())
    service = ComparisonService(workspace, policy=POLICY, allow_unattested_preview=True)
    store = workspace.repo.baselines
    approved_at = format_utc(now or datetime.now(timezone.utc))
    baselines = []
    for kind, cid, png_sha, job, stability, row, b, before_history in checked:
        service.validate_candidate(cid)  # M4 evidence re-check (plan, S1 manifest, image) before deciding
        item = store.read_page(limit=1, candidate_id=cid).items[0]
        record = item.record
        if (record.status is not BaselineStatus.PENDING or record.revision != 0 or item.current_version != b['version']
                or record.registered_digest != row['digest'] or record.candidate.artifact_sha256 != png_sha):
            raise Stop(f'{kind}: the copied candidate is not the reviewed PENDING record of the current version')
        store.decide(cid, decision=BaselineStatus.APPROVED, actor=actor, expected_revision=0,
                     reviewed_digest=record.registered_digest, expected_current_version=b['version'])
        history = store.history(record.candidate.page_id, record.candidate.profile_fingerprint)
        if ([(h.version, h.record.candidate.candidate_id) for h in history] != before_history + [(b['version'] + 1, cid)]
                or not history[-1].record.is_valid_approval() or any(not h.record.is_valid_approval() for h in history)):
            raise Stop(f'{kind}: the approval could not be read back, or an older version changed')
        attrs = job['profile']['attributes']
        baselines.append({
            'kind': kind, 'page_id': job['page_id'], 'candidate_id': cid, 'job_id': job['job_id'], 'version': history[-1].version,
            'status': 'APPROVED', 'revision': history[-1].record.revision, 'candidate_digest': record.registered_digest, 'png_sha256': png_sha,
            'artifact_ref': row['artifact_ref'], 'profile_fingerprint': row['profile_fingerprint'],
            'viewport': [attrs['viewport_width'], attrs['viewport_height']], 'full_page': attrs['full_page'],
            'captured_at': report['windows']['CAPTURE-' + kind]['opened_at'], 'stability': stability, 'quality': 'UNKNOWN',
            'profile_reason': 'PROFILE_UNATTESTED', 'source': job['source'], 'approved_at': approved_at, 'actor': actor})
    if verify_export(evidence) != before_run or verify_export(current) != before_current:
        raise Stop('capture evidence or the current Baseline changed during the update')
    created = json.loads((evidence / 'workspace-created.json').read_text('utf-8'))
    record = {'schema': SCHEMA, 'registry_id': out.name, 'page_id': old['page_id'], 'url': created['url'], 'decision': 'APPROVED',
              'approved_at': approved_at, 'actor': actor, 'instruction': instruction,
              'mechanism': 'SQLiteBaselineStore.decide (APPROVED, expected_revision 0, expected_current_version = the version compared with)',
              'source_run': {'run_id': evidence.name, 'task': report.get('task'), 'export_sha256_json': before_run,
                             'database_sha256': sha(source / 'siteproof.sqlite'), 'copied_database_sha256': sha(out / 'workspace' / 'siteproof.sqlite'),
                             'unchanged_after': True, 'candidates_in_run': sorted(rows)},
              'previous': {'registry_id': old['registry_id'] if 'registry_id' in old else current.name, 'export_sha256_json': before_current,
                           'versions': {k: b['version'] for k, b in old_by_kind.items()}},
              'distinct_from': [], 'baselines': baselines,
              'not_changed': {'quality': 'UNKNOWN', 'profile': 'PROFILE_UNATTESTED', 'other_candidates_approved': 0,
                              'real_site_access': False, 'monitoring_started': False, 'compared': False}}
    (out / 'APPROVAL-RECORD.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out / 'export-sha256.json').write_text(json.dumps(tree(out), indent=2) + '\n', encoding='utf-8')
    return record


# ---- the first Baseline's formal approval: the USER approves the Baseline that is already current, as version N (no new version).
# The store's decision of a candidate is one-shot (an automatic Baseline's candidate is already APPROVED, by SiteProof), so nothing is decided
# again. The USER's act is a separate record bound to the exact registry (its export hash) and Baselines (candidate, version, digest, image
# hash) -- the same kind of record as the existing "確認済み" one, but stronger. It is written next to the registry folder, never inside it,
# so the registry, its images, the evidence and every permit pin stay byte for byte as they were.
def approve_current(real, record, expected, actor, now):
    """Write the formal-approval record for the current registry. `record`: its APPROVAL-RECORD (already manifest-checked by the caller);
    `expected`: what the USER saw {kind: {candidate_id, version, candidate_digest, png_sha256}}. -> the record written."""
    from src.noxiworks.baseline_registry import BOUND, FORMAL, FORMAL_SCHEMA, bound, valid_formal
    real = Path(real)
    registry = real / 'registry'
    if pending(real):
        raise Stop('Baselineの更新の切替が未完了です。先に切替を完了してください')
    current = bound(record['baselines'])
    shown = sorted(({'kind': k, **{f: (v or {}).get(f) for f in BOUND[1:]}} for k, v in (expected or {}).items()), key=lambda x: str(x['kind']))
    if shown != current:
        raise Stop('画面に表示したBaselineが現在のBaselineと一致しません（更新が済んでいます）。画面を更新してください')
    if valid_formal(registry, record['baselines']) is not None:
        raise Stop('このBaselineはすでに正式承認済みです')
    if any(not str(b.get('actor', '')).startswith('SiteProof自動作成') for b in record['baselines']):
        raise Stop('正式承認が必要なのは、SiteProofが自動作成したBaselineだけです')
    if any((b.get('stability') or {}).get('value') != 'STABLE' or b.get('quality') != 'UNKNOWN' for b in record['baselines']):
        raise Stop('Baselineの撮影の安定性または品質の記録が想定と異なります')
    body = {'schema': FORMAL_SCHEMA, 'approved_at': format_utc(now), 'actor': actor,
            'basis': '撮影画像を確認し、画面の「このBaselineを正式承認」でUSERが正式に承認（SiteProofが自動作成したBaselineを、そのまま承認）',
            'registry_export_sha256': export_hash(registry), 'baselines': current,
            'not_changed': {'quality': 'UNKNOWN', 'profile': 'PROFILE_UNATTESTED', 'baseline_version': 'same', 'permit': 'untouched',
                            'monitoring_started': False}}
    final, tmp = real / FORMAL, real / (FORMAL + '.tmp')
    if final.exists():
        raise Stop('既存の承認記録が現在のBaselineと一致しません。そのままにして、状況を確認してください')
    tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2) + chr(10), encoding='utf-8')
    try:
        os.link(tmp, final)  # exclusive and atomic: a second approval (or a racing one) cannot overwrite or create it twice
    except FileExistsError:
        raise Stop('このBaselineはすでに正式承認済みです') from None
    finally:
        tmp.unlink(missing_ok=True)
    if valid_formal(registry, record['baselines']) != body:
        final.unlink(missing_ok=True)
        raise Stop('承認記録を読み戻せませんでした（何も承認していません）')
    return body


# ---- the switch: the new registry takes the place of the current one; the current one is kept as history, never deleted.
# Two renames cannot be one atomic step on a filesystem, so the intent is written first and finish_switch() completes an interrupted
# switch the same way every time. While an intent exists the switch is NOT done: switch() never returns as if it were, nothing deletes the
# new registry the intent names, recovery comes before any new update, and a pending switch blocks captures (they would pin a half-switched
# Baseline). An unrecognised state is left exactly as it is (fail closed) and reported with its reason.
SWITCH = 'baseline-switch.json'
HISTORY = 'registry-history'
RETRY_DELAYS = (0.1, 0.2, 0.4, 0.8)  # seconds: a short, bounded wait for a Windows file lock (indexer, antivirus); never unbounded
sleep = time.sleep


class SwitchIncomplete(Exception):
    """The switch was started (its intent is on disk) but did not finish. Nothing is lost: the intent and the new registry are kept."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def export_hash(registry):
    return sha(Path(registry) / 'export-sha256.json')


def write_json(path, body):
    tmp = Path(str(path) + '.tmp')
    tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2) + chr(10), encoding='utf-8')
    tmp.replace(path)


def pending(real):
    """True while a switch is recorded and not finished."""
    return (Path(real) / SWITCH).is_file()


def pending_reason(real):
    """What the unfinished switch last said (or a generic line); never raises."""
    try:
        return str(json.loads((Path(real) / SWITCH).read_text('utf-8')).get('last_error') or '')
    except (OSError, ValueError):
        return ''


def _rename(src, dst, retry):
    """Rename; on a Windows PermissionError wait briefly and try again a few times (only when `retry`). The last error is raised."""
    delays = iter(RETRY_DELAYS if retry else ())
    while True:
        try:
            Path(src).rename(dst)
            return
        except PermissionError:
            delay = next(delays, None)
            if delay is None:
                raise
            sleep(delay)


def switch(real, new_dir, origin):
    """Put `new_dir` (a verified, finished registry) in place of real/registry. -> the history folder name of the old one.
    Raises Stop when nothing was started; SwitchIncomplete when it was started but is not finished (nothing is discarded then)."""
    real, new_dir = Path(real), Path(new_dir)
    current = real / 'registry'
    old_hash = export_hash(current)
    versions = '-'.join(f'{b["kind"]}{b["version"]}' for b in json.loads((current / 'APPROVAL-RECORD.json').read_text('utf-8'))['baselines'])
    name = f'v{versions}-{old_hash[:12]}'
    if (real / HISTORY / name).exists() or pending(real):
        raise Stop('a Baseline switch is already recorded; nothing changed')
    (real / HISTORY).mkdir(exist_ok=True)
    write_json(real / SWITCH, {'schema': 'siteproof.baseline-switch.v1', 'from_export_sha256': old_hash, 'to_export_sha256': export_hash(new_dir),
                               'history': name, 'new_dir': new_dir.name, 'origin': origin})
    status, reason = finish_switch(real, retry=True)
    if status != 'DONE':
        raise SwitchIncomplete(reason)
    return name


def finish_switch(real, retry=False):
    """Complete an interrupted switch from the recorded intent; idempotent. -> ('NONE' | 'DONE' | 'PENDING', reason).
    PENDING keeps the intent and the new registry exactly as they are and records why in the intent (`last_error`).
    `retry`: wait briefly and retry a Windows PermissionError (explicit update / recovery only; plain reads try once)."""
    real = Path(real)
    intent_file = real / SWITCH
    if not intent_file.is_file():
        return 'NONE', ''

    def stay(reason):
        try:
            body = json.loads(intent_file.read_text('utf-8'))
            write_json(intent_file, {**body, 'last_error': reason})
        except (OSError, ValueError):
            pass
        return 'PENDING', reason
    try:
        intent = json.loads(intent_file.read_text('utf-8'))
        registry, history, new_dir = real / 'registry', real / HISTORY / intent['history'], real / intent['new_dir']
        if registry.is_dir() and (registry / 'export-sha256.json').is_file() and export_hash(registry) == intent['from_export_sha256']:
            if history.exists() or not new_dir.is_dir():
                return stay('切替の記録と保存済みの内容が一致しません（履歴の保存先がすでにあるか、新しいBaselineが見つかりません）')
            _rename(registry, history, retry)  # step 1: the current Baseline moves to history (atomic rename)
        if not registry.exists() and new_dir.is_dir() and history.is_dir():
            _rename(new_dir, registry, retry)  # step 2: the verified new registry takes its place (atomic rename)
        if registry.is_dir() and (registry / 'export-sha256.json').is_file() and export_hash(registry) == intent['to_export_sha256']:
            write_json(real / 'registry-origin.json', intent['origin'])
            intent_file.unlink()
            return 'DONE', ''
        return stay('切替の途中の状態を判別できません。保存した内容は変更していません')
    except (OSError, ValueError, KeyError) as exc:
        return stay(type(exc).__name__ + ': ' + str(exc)[:200])

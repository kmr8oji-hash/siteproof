"""Formal Baseline registration of USER-approved capture candidates. No browser, network, Docker or AWS.

Run: py -3.15 -B tools/register_baseline.py --evidence .local\\s3t-run-02 --out .local\\NEW_REGISTRY
         --approve Desktop:capture-<job>:<png sha256> --approve Mobile:capture-<job>:<png sha256>
         --actor "USER (name)" --instruction "approval text" [--distinct-from .local\\OTHER_RUN ...]

The capture run is evidence and is never written: its whole export-sha256.json is re-hashed before and after.
Its S1 + Baseline + M4 workspace is copied into a NEW registry directory, every copied byte is checked, and only the
copy receives the decision, through the existing SQLiteBaselineStore (one-shot APPROVED, version 1 per page/profile).
Each candidate must be exactly the one named: same capture job, same PNG SHA-256, a STABLE trusted stability record,
the capture plan's profile, PENDING, and absent from every --distinct-from run. Anything else: STOP, nothing approved.
quality stays UNKNOWN and PROFILE_UNATTESTED stays as recorded; approving a Baseline never certifies a profile.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.baseline.model import BaselineStatus
from src.comparison.service import ComparisonService
from src.core.offline import OfflineWorkspace
from src.noxiworks.baseline_runtime import POLICY
from src.noxiworks.product import capture_plan

SCHEMA = 'siteproof.baseline-registry.v1'


class Stop(Exception):
    pass


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def verify_export(run):
    """Every file of the run must be listed in, and equal to, its export-sha256.json (nothing extra, nothing missing)."""
    manifest = json.loads((run / 'export-sha256.json').read_text('utf-8'))
    actual = tree(run)
    actual.pop('export-sha256.json', None)
    if actual != manifest:
        raise Stop('capture run differs from its export-sha256.json')
    return sha(run / 'export-sha256.json')


def read_candidates(db):
    """Baseline rows of a saved run, read through an immutable URI: the file is never opened for writing."""
    # closing(): sqlite3's own context manager only ends the transaction; the connection (and its Windows file lock) must be closed.
    with closing(sqlite3.connect(Path(db).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as c:
        rows = c.execute('SELECT candidate_id,page_id,profile_fingerprint,artifact_ref,artifact_sha256,digest FROM baseline_candidates').fetchall()
        decided = {r[0] for r in c.execute('SELECT candidate_id FROM baseline_decisions')}
    keys = ('candidate_id', 'page_id', 'profile_fingerprint', 'artifact_ref', 'artifact_sha256', 'digest')
    return {r[0]: {**dict(zip(keys, r)), 'decided': r[0] in decided} for r in rows}


def check_candidate(run, report, kind, cid, png_sha, planned):
    """The named candidate must be exactly this run's capture of this profile."""
    capture = report['captures'].get(kind) or {}
    job_id = capture.get('job_id')
    if cid != 'capture-' + str(job_id):
        raise Stop(f'{kind}: {cid} is not the candidate of this run (job {job_id})')
    result = json.loads((run / f'{kind}-run-result.json').read_text('utf-8'))
    jobs = result['state']['jobs']
    if len(jobs) != 1 or jobs[0]['job_id'] != job_id or jobs[0]['kind'] != kind or jobs[0]['execution'] != 'COMPLETED':
        raise Stop(f'{kind}: run result does not hold exactly this completed job')
    job = jobs[0]
    attrs = job['profile']['attributes']
    if (job['page_id'] != planned['page_id'] or (attrs['viewport_width'], attrs['viewport_height'], attrs['full_page'])
            != (planned['width'], planned['height'], planned['full_page'])):
        raise Stop(f'{kind}: capture profile is not the planned {planned["width"]}x{planned["height"]} full_page={planned["full_page"]}')
    stability = capture.get('stability') or {}
    # The settled run is the LAST `required_identical` shots (earlier shots of a still-loading page may differ: not part of it).
    required = (stability.get('policy') or {}).get('required_identical')
    settled = stability.get('shots')[-required:] if type(required) is int and required >= 2 and stability.get('shots') else []
    if (stability.get('value') != 'STABLE' or stability.get('reason') is not None
            or len(settled) != required or any(s['sha256'] != png_sha for s in settled)):
        raise Stop(f'{kind}: no STABLE stability record for this exact image')
    if capture.get('quality') != 'UNKNOWN' or 'PROFILE_UNATTESTED' not in (capture.get('comparison_reasons') or []):
        raise Stop(f'{kind}: unexpected quality / profile state')
    listed = [b for b in result['baselines'] if b.get('candidate_id') == cid]
    if len(listed) != 1 or listed[0].get('approval_state') != 'PENDING':
        raise Stop(f'{kind}: candidate is not PENDING in the run result')
    png = run / 'workspace' / job['evidence']['artifact_ref']
    if sha(png) != png_sha or job['evidence']['digest'] != png_sha:
        raise Stop(f'{kind}: PNG SHA-256 differs from the approved value')
    return job, stability


def register(evidence, out, approvals, actor, instruction, distinct_from=(), page_id='ttn-home', profiles=None):
    """page_id / profiles: the captured page and its planned profiles (default: the TTN top page of the repository's capture plan)."""
    evidence, out = Path(evidence).resolve(), Path(out).resolve()
    if out.exists():
        raise Stop('registry output exists; nothing overwritten')
    before = verify_export(evidence)
    report = json.loads((evidence / 'validation-result.json').read_text('utf-8'))
    if report.get('passed') is not True or report.get('baseline_approved') is not False:
        raise Stop('only a passed run with no approval can be registered')
    if len({kind for kind, _, _ in approvals}) != len(approvals) or len({cid for _, cid, _ in approvals}) != len(approvals):
        raise Stop('one candidate per profile')
    profiles = {p['kind']: {**p, 'page_id': page_id} for p in (profiles or capture_plan()['pages'][page_id]['profiles'])}
    rows = read_candidates(evidence / 'workspace' / 'siteproof.sqlite')
    if set(rows) != {'capture-' + c['job_id'] for c in report['captures'].values()}:
        raise Stop('run database holds other candidates than its own captures')
    checked = []
    for kind, cid, png_sha in approvals:
        if kind not in profiles:
            raise Stop('unplanned profile ' + kind)
        job, stability = check_candidate(evidence, report, kind, cid, png_sha, profiles[kind])
        row = rows.get(cid)
        if row is None or row['decided'] or row['artifact_sha256'] != png_sha or row['page_id'] != job['page_id']:
            raise Stop(f'{kind}: database candidate is missing, decided, or bound to another image')
        checked.append((kind, cid, png_sha, job, stability, row))
    if len({row['profile_fingerprint'] for *_, row in checked}) != len(checked):
        raise Stop('Desktop and Mobile must be separate Baselines (distinct profile scopes)')
    # Re-used IDs: the same candidate ID in another run would make "this candidate" ambiguous. Equal images are expected and reported.
    others = []
    for other in distinct_from:
        other = Path(other).resolve()
        other_rows = read_candidates(other / 'workspace' / 'siteproof.sqlite')
        clash = sorted({cid for _, cid, *_ in checked} & set(other_rows))
        if clash:
            raise Stop(f'candidate id re-used in {other.name}: {clash}')
        others.append({'run_id': other.name, 'candidate_ids': sorted(other_rows),
                       'same_image_sha256': sorted(r['artifact_sha256'] for r in other_rows.values()
                                                   if r['artifact_sha256'] in {c[2] for c in checked})})
    # Copy the workspace (database + capture folders) into the NEW registry; the run itself is never opened for writing.
    source = evidence / 'workspace'
    for side in ('-journal', '-wal', '-shm'):
        if (source / ('siteproof.sqlite' + side)).exists():
            raise Stop('run database has a live sidecar file')
    out.mkdir(parents=True)
    shutil.copytree(source, out / 'workspace')
    if tree(out / 'workspace') != tree(source):
        raise Stop('workspace copy differs from the evidence')
    copied_db_sha = sha(out / 'workspace' / 'siteproof.sqlite')
    workspace = OfflineWorkspace((out / 'workspace' / 'siteproof.sqlite').resolve(), (out / 'workspace').resolve())
    service = ComparisonService(workspace, policy=POLICY, allow_unattested_preview=True)
    store = workspace.repo.baselines
    approved_at = format_utc(datetime.now(timezone.utc))
    baselines = []
    for kind, cid, png_sha, job, stability, row in checked:
        service.validate_candidate(cid)  # M4 evidence re-check (plan, S1 manifest, image) before deciding, as the approval UI does.
        item = store.read_page(limit=1, candidate_id=cid).items[0]
        record = item.record
        if (record.status is not BaselineStatus.PENDING or record.revision != 0 or item.current_version is not None
                or record.registered_digest != row['digest'] or record.candidate.artifact_sha256 != png_sha):
            raise Stop(f'{kind}: copied candidate is not the reviewed PENDING record')
        store.decide(cid, decision=BaselineStatus.APPROVED, actor=actor, expected_revision=0,
                     reviewed_digest=record.registered_digest, expected_current_version=0)
        history = store.history(record.candidate.page_id, record.candidate.profile_fingerprint)
        if len(history) != 1 or history[0].record.candidate.candidate_id != cid or not history[0].record.is_valid_approval():
            raise Stop(f'{kind}: approval readback failed')
        attrs = job['profile']['attributes']
        baselines.append({
            'kind': kind, 'page_id': job['page_id'], 'candidate_id': cid, 'job_id': job['job_id'],
            'version': history[0].version, 'status': 'APPROVED', 'revision': history[0].record.revision,
            'candidate_digest': record.registered_digest, 'png_sha256': png_sha, 'artifact_ref': row['artifact_ref'],
            'profile_fingerprint': row['profile_fingerprint'], 'viewport': [attrs['viewport_width'], attrs['viewport_height']],
            'full_page': attrs['full_page'], 'captured_at': report['windows']['CAPTURE-' + kind]['opened_at'],
            'stability': stability, 'quality': 'UNKNOWN', 'profile_reason': 'PROFILE_UNATTESTED', 'source': job['source'],
            'approved_at': approved_at, 'actor': actor})
    if verify_export(evidence) != before:
        raise Stop('capture evidence changed during registration')
    created = json.loads((evidence / 'workspace-created.json').read_text('utf-8'))
    record = {'schema': SCHEMA, 'registry_id': out.name, 'page_id': page_id, 'url': created['url'],
              'decision': 'APPROVED', 'approved_at': approved_at, 'actor': actor, 'instruction': instruction,
              'mechanism': 'SQLiteBaselineStore.decide (one-shot APPROVED, expected_revision 0, expected_current_version 0)',
              'source_run': {'run_id': evidence.name, 'task': report.get('task'), 'export_sha256_json': before,
                             'database_sha256': sha(source / 'siteproof.sqlite'), 'copied_database_sha256': copied_db_sha,
                             'unchanged_after': True, 'candidates_in_run': sorted(rows)},
              'distinct_from': others, 'baselines': baselines,
              'not_changed': {'quality': 'UNKNOWN', 'profile': 'PROFILE_UNATTESTED', 'other_candidates_approved': 0,
                              'real_site_access': False, 'monitoring_started': False, 'compared': False}}
    (out / 'APPROVAL-RECORD.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    files = tree(out)
    (out / 'export-sha256.json').write_text(json.dumps(files, indent=2) + '\n', encoding='utf-8')
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--approve', required=True, action='append', metavar='KIND:CANDIDATE_ID:PNG_SHA256')
    parser.add_argument('--actor', required=True)
    parser.add_argument('--instruction', required=True)
    parser.add_argument('--distinct-from', type=Path, action='append', default=[])
    args = parser.parse_args(argv)
    try:
        approvals = [tuple(a.split(':')) for a in args.approve]
        if any(len(a) != 3 for a in approvals):
            raise Stop('--approve KIND:CANDIDATE_ID:PNG_SHA256')
        record = register(args.evidence, args.out, approvals, args.actor, args.instruction, args.distinct_from)
    except Stop as exc:
        print('STOP / nothing approved: ' + str(exc), file=sys.stderr)
        return 1
    for b in record['baselines']:
        print(f'{b["kind"]}: {b["candidate_id"]} APPROVED v{b["version"]} png {b["png_sha256"]}')
    print(str(Path(args.out).resolve() / 'APPROVAL-RECORD.json'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Formal Baseline registry -> the runtime of the NEXT real capture. No capture, approval, network, Docker or AWS here.

A live run builds its runtime with capture.create_runtime on a NEW, empty workspace, so ComparisonService.prepare finds no approved head
and every job is bound with no Baseline (BASELINE_PENDING). This module is the missing connection, kept apart from the hash-pinned capture
files: stage() copies the registry's workspace, byte-checked, as the run's new workspace (the registry itself is only read); open_runtime()
opens it exactly like create_runtime does (same explicit policy); check_bindings() proves that each profile's next job pins the registry's
approved head of THAT profile, with the exact context fingerprint (not the mismatch fallback). prepare_job() binds one owner-page job the
way tests/runtime/s3_worker.prepare does. Source, stability, audits and the pixel policy are the product's, unchanged.
"""
import hashlib
import json
from pathlib import Path
import shutil
import uuid

from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.frames import CheckType
from src.core.model import JobIntent
from src.core.offline import OfflineWorkspace, read_profile
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.worker.trusted import TrustedWorker

REGISTRY_SCHEMA = 'siteproof.baseline-registry.v1'
# The same explicit policy create_runtime gives every live run (tests assert they stay equal). Not a quality threshold.
POLICY = PixelPolicy(0, 'SiteProof暫定: 1ピクセル以上の差分をレビュー対象にする。品質の閾値ではない')
OWNER_SOURCE = 'OWNER_SITE_UNATTESTED'


class BaselineConnectionRefused(ValueError):
    pass


def _refuse(why):
    raise BaselineConnectionRefused(why)


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


def read_registry(directory):
    """The registry's APPROVAL-RECORD, after checking that every file equals its export-sha256.json (nothing extra, nothing missing)."""
    root = Path(directory).resolve()
    try:
        manifest = json.loads((root / 'export-sha256.json').read_text('utf-8'))
        actual = tree(root)
        actual.pop('export-sha256.json', None)
        record = json.loads((root / 'APPROVAL-RECORD.json').read_text('utf-8'))
    except (OSError, ValueError) as exc:
        raise BaselineConnectionRefused('registry unreadable: ' + type(exc).__name__) from None
    if actual != manifest:
        _refuse('registry differs from its export-sha256.json')
    kinds = [b.get('kind') for b in record.get('baselines', [])]
    if (record.get('schema') != REGISTRY_SCHEMA or record.get('decision') != 'APPROVED' or not kinds or len(set(kinds)) != len(kinds)
            or any(b.get('status') != 'APPROVED' or b.get('page_id') != record.get('page_id') for b in record['baselines'])):
        _refuse('not an APPROVED Baseline registry with one Baseline per profile')
    return record


def stage(registry_dir, workspace_dir):
    """Copy the registry's workspace as a NEW run workspace. -> the registry record. The registry is re-hashed afterwards."""
    record = read_registry(registry_dir)
    source, dest = Path(registry_dir).resolve() / 'workspace', Path(workspace_dir).resolve()
    if dest.exists():
        _refuse('run workspace exists; nothing overwritten')
    # Bytes only, never file modes: a read-only registry (mount or file attributes) must still give a writable run workspace.
    dest.mkdir(parents=True)
    for p in sorted(source.rglob('*')):
        if p.is_symlink():
            _refuse('linked file in the registry')
        target = dest / p.relative_to(source)
        if p.is_dir():
            target.mkdir()
        else:
            shutil.copyfile(p, target)
    if tree(dest) != tree(source):
        _refuse('staged workspace differs from the registry')
    read_registry(registry_dir)
    return record


def open_runtime(workspace_dir):
    """RuntimeService over an existing (staged) workspace, built exactly like capture.create_runtime builds a new one."""
    root = Path(workspace_dir).resolve()
    workspace = OfflineWorkspace(root / 'siteproof.sqlite', root)
    comparison = ComparisonService(workspace, policy=POLICY, allow_unattested_preview=True)
    worker = TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(workspace.db_path), ArtifactStore(root))))
    return RuntimeService(workspace, worker, comparison=comparison)


def _profile(runtime, page_id, kind):
    """Latest M1 profile of one page/kind, read-only (RuntimeStore.snapshot would record a batch)."""
    with runtime.workspace.repo.read() as c:
        row = c.execute('SELECT * FROM m1_profiles WHERE page_id=? AND kind=? ORDER BY revision DESC LIMIT 1', (page_id, kind)).fetchone()
    if row is None:
        _refuse(f'workspace has no {kind} profile for {page_id}')
    profile = read_profile(row['body'])
    if profile.fingerprint != row['fingerprint']:
        _refuse('capture profile mismatch')
    return profile


def check_bindings(runtime, record, planned=None):
    """-> {kind: pin}. Each profile's next job must pin exactly that profile's approved registry head, or nothing is captured.

    `planned` (capture_plan profiles) must describe the same profiles: a changed plan has no approved Baseline yet.
    """
    page_id = record['page_id']
    if planned is not None and sorted(p['kind'] for p in planned) != sorted(b['kind'] for b in record['baselines']):
        _refuse('planned profiles and approved Baselines differ')
    store = runtime.comparison.baselines
    pins = {}
    for b in record['baselines']:
        kind = b['kind']
        profile = _profile(runtime, page_id, kind)
        attrs = profile.attributes
        if planned is not None:
            p = next(p for p in planned if p['kind'] == kind)
            if (attrs['viewport_width'], attrs['viewport_height'], attrs['full_page']) != (p['width'], p['height'], p['full_page']):
                _refuse(f'{kind}: planned profile differs from the approved Baseline profile')
        plan = runtime.comparison.prepare(profile, page_id, kind, OWNER_SOURCE)
        pin = plan['baseline']
        expected = {'candidate_id': b['candidate_id'], 'version': b['version'], 'digest': b['candidate_digest'], 'fingerprint': b['profile_fingerprint']}
        if pin != expected or plan['context_fingerprint'] != b['profile_fingerprint']:
            _refuse(f'{kind}: next job would not pin the approved Baseline {b["candidate_id"]} (got {pin and pin["candidate_id"]})')
        history = store.history(page_id, b['profile_fingerprint'])
        if not history or history[-1].version != b['version'] or not history[-1].record.is_valid_approval():
            _refuse(f'{kind}: approved head is not the registry version')
        runtime.comparison.validate_candidate(b['candidate_id'])  # M4 evidence re-check (plan, S1 manifest, image)
        job_id = runtime.comparison.store.body('candidates', b['candidate_id'])['job_id']
        if hashlib.sha256(runtime.comparison.image(job_id)).hexdigest() != b['png_sha256']:
            _refuse(f'{kind}: Baseline image differs from the approval record')
        pins[kind] = pin
    return pins


def prepare_job(runtime, page_id, kind, source=OWNER_SOURCE):
    """One owner-page job in its own batch, bound like tests/runtime/s3_worker.prepare. -> (batch_id, job_id, plan)."""
    batch = uuid.uuid4().hex
    snapshot = runtime.store.snapshot(batch)
    page = next(p for p in snapshot['pages'] if p['page_id'] == page_id)
    row = next(r for r in snapshot['profiles'] if r['page_id'] == page_id and r['kind'] == kind)
    profile = read_profile(row['body'])
    if profile.fingerprint != row['fingerprint']:
        _refuse('capture profile mismatch')
    plan = runtime.comparison.prepare(profile, page_id, kind, source)
    intent = JobIntent(snapshot['site']['origin'] + page['path'], page_id, profile.profile_id, tuple(CheckType),
                       plan['baseline']['candidate_id'] if plan['baseline'] else None)
    job = runtime.repo.accept_job('s3-' + uuid.uuid4().hex, intent).job
    runtime.store.bind(job.job_id, batch, {'page': page, 'profile': {'profile_id': profile.profile_id, 'attributes': dict(profile.attributes)},
                                           'fingerprint': profile.fingerprint, 'profile_revision': row['revision'], 'kind': kind,
                                           'snapshot_sha256': job.snapshot.sha256, 'source': source})
    runtime.comparison.bind(job, plan)
    return batch, job.job_id, plan


def comparison_export(runtime, job_id):
    """Files a run exports next to its run result so REVIEW can show the comparison: `{kind}-diff.png` (only when a diff exists)."""
    rows = runtime.comparison.store.rows('results', job_id=job_id, limit=1)
    if not rows:
        return {}
    result = runtime.comparison.result(rows[0]['result_id'])
    if not result['diff_sha256'] or result['source_availability'] != 'VERIFIED':
        return {}
    return {f'{result["kind"]}-diff.png': runtime.comparison.result_image(result['result_id'], 'diff')}


# ---- live-run integration: the trusted worker (tests/runtime/s3t_worker.py) and the host harness (tests/runtime/validate_s3t.py)

def open_staged_runtime(registry_dir, workspace_dir, url, planned):
    """Worker side, before any capture window: stage + open + bind check. -> (runtime, summary). Any refusal: no workspace to capture into.

    The staged workspace must be the registered page itself (origin + path == url), so a registry of another site can never be used.
    """
    record = stage(registry_dir, workspace_dir)
    if record.get('url') != url:
        _refuse('registry belongs to another page URL')
    runtime = open_runtime(workspace_dir)
    with runtime.workspace.repo.read() as c:
        site = c.execute('SELECT origin FROM m1_site').fetchone()
        page = c.execute('SELECT path FROM m1_pages WHERE page_id=?', (record['page_id'],)).fetchone()
    if site is None or page is None or site['origin'] + page['path'] != url:
        _refuse('staged workspace is not the registered page')
    pins = check_bindings(runtime, record, planned)
    manifest = hashlib.sha256((Path(registry_dir).resolve() / 'export-sha256.json').read_bytes()).hexdigest()
    return runtime, {'registry_export_sha256': manifest, 'page_id': record['page_id'], 'pins': pins,
                     'baseline_jobs': {b['kind']: b['job_id'] for b in record['baselines']},
                     'baseline_png_sha256': {b['kind']: b['png_sha256'] for b in record['baselines']}}


def export_comparisons(runtime, job_ids, out_dir):
    """Worker side, after a run: write each job's `{kind}-diff.png` into out_dir. -> {file name: {sha256, bytes, job_id}}."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for job_id in job_ids:
        for name, raw in comparison_export(runtime, job_id).items():
            if (out / name).exists():
                _refuse('export exists; nothing overwritten: ' + name)
            (out / name).write_bytes(raw)
            written[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'job_id': job_id}
    return written


def expected_baseline(record):
    """What an identity file pins for a compare run: the registry manifest and, per profile, the exact pin / Baseline job / image."""
    return {'page_id': record['page_id'], 'url': record.get('url'),
            'pins': {b['kind']: {'candidate_id': b['candidate_id'], 'version': b['version'], 'digest': b['candidate_digest'],
                                 'fingerprint': b['profile_fingerprint']} for b in record['baselines']},
            'baseline_jobs': {b['kind']: b['job_id'] for b in record['baselines']},
            'baseline_png_sha256': {b['kind']: b['png_sha256'] for b in record['baselines']}}


def created_matches(summary, expect):
    """Host side, before the first window: the worker staged exactly the registry the identity names, and every profile is bound."""
    return (type(summary) is dict and summary.get('registry_export_sha256') == expect.get('registry_export_sha256')
            and all(summary.get(k) == expect.get(k) for k in ('page_id', 'pins', 'baseline_jobs', 'baseline_png_sha256')))


def comparison_matches(comp, kind, expect):
    """Host side, after a capture: this job was compared with that profile's formal Baseline, and nothing was promoted."""
    return (type(comp) is dict and comp.get('baseline') == expect['pins'].get(kind) and comp.get('baseline_job_id') == expect['baseline_jobs'].get(kind)
            and comp.get('baseline_sha256') == expect['baseline_png_sha256'].get(kind) and comp.get('quality') in ('UNKNOWN', 'FAIL')
            and (comp.get('operational') or {}).get('verdict') in ('VISUAL_CHANGED', 'NO_VISUAL_CHANGE_DETECTED', 'UNKNOWN'))


def candidates_match(baselines, job_id, expect):
    """Host side: the new capture's candidate is saved and not approved; the only APPROVED records are the registry's own Baselines.

    "The registry's own Baselines" are, per profile, its WHOLE approved version chain 1..N (N = the pinned version): a registry made by a
    Baseline update carries its earlier versions in the workspace it stages, and those stay APPROVED. Exactly that chain is accepted --
    version N must be the pinned candidate (same id and digest), versions 1..N-1 must each appear once, and any other approved record (another
    profile, a version above N, a duplicate) fails the check, as does a pinned Baseline that is not approved. Records without version
    information (the older record shape) are held to the strict rule: the approved set must equal the pinned candidates."""
    pending = any(b['candidate_id'] == 'capture-' + job_id and b.get('approval_state') == 'PENDING' for b in baselines)
    approved = [b for b in baselines if b.get('approval_state') == 'APPROVED']
    pins = list(expect['pins'].values())
    if not all(type(b.get('candidate_version')) is int and b.get('profile_fingerprint') for b in approved):
        return pending and {b['candidate_id'] for b in approved} == {p['candidate_id'] for p in pins}
    chains = {}
    for b in approved:
        versions = chains.setdefault((b.get('page_id'), b['profile_fingerprint']), {})
        if b['candidate_version'] in versions:
            return False  # two approved records claim the same version
        versions[b['candidate_version']] = b
    if len(chains) != len(pins) or sum(len(v) for v in chains.values()) != sum(p['version'] for p in pins):
        return False  # an approved record of another profile / page, or a version beyond the pinned one
    for p in pins:
        chain = next((v for (page, fp), v in chains.items() if fp == p['fingerprint']), None)
        top = (chain or {}).get(p['version'])
        if (chain is None or sorted(chain) != list(range(1, p['version'] + 1)) or top['candidate_id'] != p['candidate_id']
                or top.get('digest') not in (None, p['digest'])):
            return False
    return pending

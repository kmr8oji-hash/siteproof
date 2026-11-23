"""Read-only adapter: a formal Baseline registry (tools/register_baseline.py) and its offline demo (tools/offline_baseline_demo.py)
-> the page's change record, on top of the capture runs local_capture.attach() already added.

The registry may only name the very captures already shown for that page (same candidate, job and PNG SHA-256); it marks the
page's Baseline approved and records that no comparison has been made since. The demo is SYNTHETIC: it is kept apart under
`offline_demo`, never becomes the page's comparison result, change state or history, and its Baseline image must be the
approved Baseline itself. Files are read through local_capture.Run (bounded, manifest-checked). No write, network or database.
"""
import hashlib
import json

from src.comparison.operational import present
from .local_capture import Run, _refuse

REGISTRY_SCHEMA = 'siteproof.baseline-registry.v1'
DEMO_SCHEMA = 'siteproof.offline-baseline-demo.v1'
# (scenario, title, operational verdict it must have). The verdict is re-derived from the saved result, never read from the summary.
SCENARIOS = (('unchanged', '実証A 変更なし', 'NO_VISUAL_CHANGE_DETECTED'), ('changed', '実証B 変更あり', 'VISUAL_CHANGED'),
             ('unstable', '実証C 判定不能', 'UNKNOWN'))
KINDS = {'Desktop': ('desktop', 'current'), 'Mobile': ('mobile', 'mobile')}  # kind -> (tab key, stage image role)
DEMO_ROLES = tuple(f'demo_{s}_{k}{suffix}' for s, _, _ in SCENARIOS for k in ('desktop', 'mobile') for suffix in ('', '_diff'))


def read(directory):
    """-> registry: the APPROVED record (bounded, manifest-checked), its Baselines by kind and their image bytes (digest-checked)."""
    run = Run(directory)
    record = run.json('APPROVAL-RECORD.json')
    if record.get('schema') != REGISTRY_SCHEMA or record.get('decision') != 'APPROVED':
        _refuse('not an APPROVED Baseline registry')
    baselines, pngs = [], {}
    for b in record['baselines']:
        if b['status'] != 'APPROVED' or type(b['version']) is not int or b['version'] < 1 or b['kind'] in pngs:
            _refuse('one APPROVED Baseline version per profile required')
        raw = run.png('workspace/' + b['artifact_ref'])
        if hashlib.sha256(raw).hexdigest() != b['png_sha256']:
            _refuse('registry image differs from its record')
        if b['quality'] != 'UNKNOWN' or b['profile_reason'] != 'PROFILE_UNATTESTED':
            _refuse('a registry may not upgrade quality or profile trust')
        pngs[b['kind']] = raw
        baselines.append({k: b[k] for k in ('kind', 'candidate_id', 'job_id', 'version', 'status', 'candidate_digest', 'png_sha256',
                                            'profile_fingerprint', 'viewport', 'full_page', 'captured_at', 'approved_at', 'actor',
                                            'quality', 'profile_reason', 'stability')})
    return {'registry_id': run.root.name, 'page_id': record['page_id'], 'approved_at': record['approved_at'], 'actor': record['actor'],
            'instruction': record['instruction'], 'mechanism': record['mechanism'], 'source_run': record['source_run'],
            'distinct_from': record.get('distinct_from', []), 'baselines': baselines, 'by_kind': {b['kind']: b for b in baselines},
            'pngs': pngs, 'export_sha256_json': hashlib.sha256(run._raw('export-sha256.json', 8 * 1024 * 1024, listed=False)).hexdigest()}


def public(registry):
    """The registry as stored in a snapshot: no image bytes, no lookup table."""
    return {k: v for k, v in registry.items() if k not in ('pngs', 'by_kind')}


AUTO_ACTOR_PREFIX = 'SiteProof自動作成'  # site_monitor.AUTO_ACTOR: the first stable capture became the Baseline without a person approving it
# standing -> (short label, sentence). A comparison that succeeded never turns an automatic Baseline into a formal approval.
STANDING_LABELS = {'AUTO_UNCONFIRMED': ('自動作成・未確認', '自動作成のBaselineです（利用者は未確認・正式な承認ではありません）'),
                   'AUTO_CONFIRMED': ('自動作成・USER確認済み', '自動作成のBaselineを利用者が画面で確認済みです（正式な承認ではありません）'),
                   'USER': ('正式承認済み', 'USERが正式に承認したBaselineです')}


FORMAL = 'baseline-approval.json'   # next to the registry folder (never inside it: the registry's own hash is pinned by permits)
FORMAL_SCHEMA = 'siteproof.baseline-formal-approval.v1'
BOUND = ('kind', 'candidate_id', 'version', 'candidate_digest', 'png_sha256')


def bound(baselines):
    """The identity of each approved Baseline an approval record is bound to: profile, candidate id, version, candidate digest, image hash."""
    return sorted(({k: b.get(k) for k in BOUND} for b in baselines), key=lambda x: str(x['kind']))


def valid_formal(directory, baselines):
    """The USER's formal approval of THIS registry, or None. Valid only while the record names exactly this registry (its export hash) and
    exactly these Baselines (candidate, version, digest, image hash); any change to either makes it not count (fail closed, never "approved")."""
    from pathlib import Path
    base = Path(directory)
    try:
        f = base.parent / FORMAL
        if not f.is_file() or f.stat().st_size > 65536:
            return None
        record = json.loads(f.read_text('utf-8'))
        actor = str(record.get('actor', ''))
        if (record.get('schema') != FORMAL_SCHEMA or not actor or actor.startswith(AUTO_ACTOR_PREFIX) or not record.get('approved_at')
                or record.get('registry_export_sha256') != hashlib.sha256((base / 'export-sha256.json').read_bytes()).hexdigest()
                or record.get('baselines') != bound(baselines)):
            return None
        return record
    except (OSError, ValueError, TypeError):
        return None


def standing(directory, registry):
    """AUTO_UNCONFIRMED | AUTO_CONFIRMED | USER for a registry folder. Read-only: the origin note and the user's confirmation are the
    separate records next to the registry folder (Site.baseline_state reads the same ones); the registry itself is never touched."""
    from pathlib import Path
    base = Path(directory)

    def small(name):
        f = base.parent / name
        try:
            return json.loads(f.read_text('utf-8')) if f.is_file() and f.stat().st_size <= 65536 else None
        except (OSError, ValueError):
            return None
    origin = (small('registry-origin.json') or {}).get('origin')
    auto = (str(registry.get('actor', '')).startswith(AUTO_ACTOR_PREFIX) or origin == 'AUTO_INITIAL'
            or any(str(b.get('actor', '')).startswith(AUTO_ACTOR_PREFIX) for b in registry.get('baselines', [])))
    if not auto or valid_formal(base, registry.get('baselines', [])):
        return 'USER'
    return 'AUTO_CONFIRMED' if isinstance(small('baseline-confirmation.json'), dict) else 'AUTO_UNCONFIRMED'


def baseline_standing(change):
    """The standing of the Baseline a page was compared with, from its snapshot record; None when it has no registry (fixtures, samples).
    A record without a stated standing is judged by its actor: an automatic one is never shown as a formal approval."""
    registry = change.get('baseline_registry')
    if not isinstance(registry, dict):
        return None
    if registry.get('standing') in STANDING_LABELS:
        return registry['standing']
    actors = [str(registry.get('actor', ''))] + [str(b.get('actor', '')) for b in registry.get('baselines', [])]
    return 'AUTO_UNCONFIRMED' if any(a.startswith(AUTO_ACTOR_PREFIX) for a in actors) else 'USER'


def _registry(registry, change):
    """The registry must name exactly the captures shown for this page (its own source run, not yet compared)."""
    captures = {c['kind']: c for c in change.get('captures', [])}
    if registry['page_id'] != change['page_id'] or set(captures) != set(registry['by_kind']):
        _refuse('every shown capture needs exactly one registry Baseline')
    for kind, b in registry['by_kind'].items():
        c = captures[kind]
        if (c['job_id'] != b['job_id'] or c['sha256'] != b['png_sha256'] or (c.get('candidate') or {}).get('candidate_id') != b['candidate_id']
                or (c.get('candidate') or {}).get('digest') != b['candidate_digest']):
            _refuse('registry Baseline is not the capture shown for ' + kind)
    return public(registry)


def _demo(directory, change, registry):
    run = Run(directory)
    summary = run.json('OFFLINE-DEMO.json')
    if (summary.get('schema') != DEMO_SCHEMA or summary.get('synthetic') is not True or summary.get('real_site_access') is not False
            or summary.get('passed') is not True or summary.get('registry', {}).get('registry_id') != registry['registry_id']
            or summary['registry'].get('export_sha256_json') != registry['export_sha256_json']):
        _refuse('not a passed synthetic demo of this Baseline registry')
    by_kind = {b['kind']: b for b in registry['baselines']}
    scenarios, pngs, assets = [], {}, {}
    for key, title, expected in SCENARIOS:
        kinds = {}
        for kind, (tab, stage_role) in KINDS.items():
            if kind not in by_kind:
                continue
            result = run.json(f'{key}/{kind}-result.json')
            b = by_kind[kind]
            if ((result.get('baseline') or {}).get('candidate_id') != b['candidate_id'] or result.get('baseline_job_id') != b['job_id']
                    or result.get('baseline_sha256') != b['png_sha256'] or result.get('quality') != 'UNKNOWN'
                    or result.get('profile_trust') != 'UNATTESTED'):
                _refuse(f'demo {key}/{kind} was not compared with the approved Baseline')
            visual = present(result, None)
            if visual['verdict'] != expected:
                _refuse(f'demo {key}/{kind} verdict {visual["verdict"]} is not {expected}')
            role = f'demo_{key}_{tab}'
            current = run.png(f'{key}/{kind}-current.png')
            if hashlib.sha256(current).hexdigest() != result['current_sha256']:
                _refuse('demo image differs from its result')
            pngs[role], assets[role] = current, result['current_sha256']
            diff_role = None
            if expected != 'UNKNOWN':  # An undecided comparison has no confirmed diff to show.
                diff = run.png(f'{key}/{kind}-diff.png')
                if hashlib.sha256(diff).hexdigest() != result['diff_sha256']:
                    _refuse('demo diff differs from its result')
                diff_role = role + '_diff'
                pngs[diff_role], assets[diff_role] = diff, result['diff_sha256']
            m = result.get('metrics') or {}
            kinds[tab] = {'kind': kind, 'verdict': visual['verdict'], 'label': visual['label'], 'reasons': visual['reason_labels'],
                          'changed_pixels': m.get('changed_pixels'), 'total_pixels': m.get('total_pixels'),
                          'baseline_role': stage_role, 'current_role': role, 'diff_role': diff_role,
                          'result_id': result['result_id'], 'job_id': result['job_id'], 'strict_reasons': result['reasons'],
                          'stability': (result.get('capture_stability') or {}).get('value')}
        scenarios.append({'key': key, 'title': title, 'kinds': kinds})
    return {'run_id': run.root.name, 'synthetic': True, 'label': summary['label'], 'producer': summary['producer'],
            'change': summary.get('change'), 'scenarios': scenarios, 'assets': assets}, pngs


def is_source_shown(snapshot, registry):
    """True when the run the registry was made from is one of the runs shown (then the page reads "approved, not compared since")."""
    runs = (snapshot.get('local_capture') or {}).get('runs', [])
    return any(r['run_id'] == registry['source_run']['run_id'] and r['page_id'] == registry['page_id'] for r in runs)


def attach(snapshot, assets, registry, demo_dir=None):
    """-> (snapshot, assets) with the registry (and demo) applied to its own source capture. Inputs are not modified."""
    changes = snapshot.get('changes', {})
    page_id = registry['page_id']
    if not is_source_shown(snapshot, registry) or page_id not in changes:
        _refuse('the registry was made from a capture run that is not shown')
    public_registry = _registry(registry, changes[page_id])
    # `metrics: None`: an inspection that was compared with the PREVIOUS version is the new version's source; it is shown as "approved,
    # not compared since" (its own comparison stays in the run's evidence and in the monitoring history, which are not changed here).
    change = {**changes[page_id], 'baseline_approved': True, 'reasons': ['PROFILE_UNATTESTED', 'COMPARISON_NOT_RUN'], 'metrics': None,
              'baseline_registry': public_registry, 'comparison_after_approval': 'NOT_RUN'}
    out_assets = {tid: dict(roles) for tid, roles in assets.items()}
    if demo_dir is not None:
        demo, pngs = _demo(demo_dir, change, public_registry)
        change['offline_demo'] = demo
        out_assets.setdefault(page_id, {}).update(pngs)
    return {**snapshot, 'changes': {**changes, page_id: change}}, out_assets

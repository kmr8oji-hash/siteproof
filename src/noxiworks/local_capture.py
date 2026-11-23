"""Read-only adapter: saved capture runs (S3-1 and later) -> a SiteProof snapshot fragment plus the page-bound PNG bytes.

A run of a registered monitoring target (the TTN top page `/`) is shown on that target's own record; a run of any other page of a
registered site (TTN `/about`) becomes an extra, non-monitored page. Labels come from capture_plan.json.

Reads files and nothing else: no write, no network, no AWS, no Docker. It never approves a Baseline and never compares. A run whose
jobs WERE compared (a capture made after the Baseline approval) is shown only with the formal registry it was compared with: each job's
saved Baseline pin, Baseline image and diff must match that registry and the run's own files, or the run is refused.
Every file it uses is size-bounded, must be a regular file inside the run directory, and must match the run's own
`export-sha256.json`; a PNG must also match the digest the capture job recorded. Anything else is refused (fail closed).
Absolute paths never enter the snapshot (only the run directory's name).
"""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.aws_b.model import format_utc, parse_utc
from src.comparison.preview import dimensions
from src.core.model import validate_id
from .product import capture_plan, settings

SCHEMA = 'siteproof.local-capture.v1'
# (profile kind, image role). `current` is the primary image every other screen already knows; `mobile` is the second one.
KINDS = (('Desktop', 'current'), ('Mobile', 'mobile'))
COMPARE_ROLES = {'current': ('baseline', 'diff'), 'mobile': ('mobile_baseline', 'mobile_diff')}  # role -> (Baseline role, diff role)
# Which profile's result speaks for the page: a change first, then an undecided one, then "no change" (never hide a change).
VERDICT_ORDER = {'VISUAL_CHANGED': 0, 'UNKNOWN': 1, 'NO_VISUAL_CHANGE_DETECTED': 2}
JSON_LIMIT = 8 * 1024 * 1024
PNG_LIMIT = 32 * 1024 * 1024
KEEP_RESULT = ('baseline', 'baseline_job_id', 'baseline_profile_trust', 'baseline_sha256', 'browser_audit', 'capture_stability', 'checks', 'context_fingerprint',
               'current_sha256', 'diff_sha256', 'execution', 'job_id', 'kind', 'metrics', 'network_audit', 'operational', 'page_id',
               'policy', 'profile_compatibility', 'profile_reason', 'profile_trust', 'quality', 'reasons', 'result_id', 'source', 'source_availability',
               'trust_domain')


class LocalCaptureRefused(ValueError):
    pass


def _refuse(why):
    raise LocalCaptureRefused(why)


class Run:
    """Bounded, manifest-checked reader over one run directory."""

    def __init__(self, directory):
        root = Path(directory)
        if root.is_symlink() or not root.is_dir():
            _refuse('run directory required')
        self.root = root.resolve()
        raw = self._raw('export-sha256.json', JSON_LIMIT, listed=False)
        manifest = json.loads(raw)
        if type(manifest) is not dict or not all(type(k) is str and re.fullmatch(r'[0-9a-f]{64}', str(v)) for k, v in manifest.items()):
            _refuse('invalid export-sha256.json')
        self.manifest = manifest

    def _raw(self, rel, limit, listed=True):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', rel) or '..' in rel.split('/'):
            _refuse('unsafe relative path')
        path = self.root.joinpath(*rel.split('/'))
        if path.is_symlink() or not path.is_file() or self.root not in path.resolve().parents:
            _refuse('missing or unsafe file: ' + rel)
        if path.stat().st_size > limit:
            _refuse('file too large: ' + rel)
        data = path.read_bytes()
        if listed and self.manifest.get(rel) != hashlib.sha256(data).hexdigest():
            _refuse('file is not listed in, or differs from, export-sha256.json: ' + rel)
        return data

    def json(self, rel):
        return json.loads(self._raw(rel, JSON_LIMIT).decode('utf-8'))

    def png(self, rel):
        return self._raw(rel, PNG_LIMIT)


def _utc(value, what):
    moment = parse_utc(value)
    if moment is None:
        _refuse('invalid time: ' + what)
    return format_utc(moment)


def _capture(run, kind, role, window, head, meta, registry=None):
    result = run.json(f'{kind}-run-result.json')
    jobs = result['state']['jobs']
    if len(jobs) != 1 or jobs[0]['kind'] != kind:
        _refuse('exactly one job per profile required')
    # A staged registry workspace also holds the Baseline jobs' own results: take this job's result only.
    comparison = [r for r in result['comparison']['results'] if r.get('kind') == kind and r.get('job_id') == jobs[0]['job_id']]
    if len(comparison) != 1:
        _refuse('exactly one comparison result per profile required')
    job, comp = jobs[0], comparison[0]
    candidates = [b for b in result['baselines'] if b.get('candidate_id') == 'capture-' + job['job_id']]
    if len(candidates) != 1 or candidates[0].get('approval_state') != 'PENDING':
        _refuse('only a PENDING Baseline candidate is supported; this adapter never shows or makes an approval')
    candidate = candidates[0]
    attrs = job['profile']['attributes']
    record = {
        'kind': kind, 'role': role, 'job_id': job['job_id'], 'execution': job['execution'], 'reason': job.get('reason'),
        'captured_at': _utc(window['opened_at'], kind + ' window'), 'window_closed_at': _utc(window['closed_at'], kind + ' window'),
        'viewport': [attrs['viewport_width'], attrs['viewport_height']], 'full_page': attrs.get('full_page') is True,
        'profile': attrs, 'fingerprint': job['fingerprint'], 'profile_trust': comp.get('profile_trust') or 'UNATTESTED',
        'browser_version': (meta[0].get('sandbox') or {}).get('browser_version'), 'source': job.get('source'),
        # Browser self-report at capture time (display only, never a verdict). Older runs lack these fields: None = not recorded.
        'load_state': {k: (meta[0].get('runtime') or {}).get(k) for k in ('readyState', 'scrollHeight', 'bodyTextLength', 'images', 'brokenImages', 'fontsStatus')},
        'http': {'status': head.get('http_status'), 'tls': (head.get('tls') or {}).get('result'), 'redirect': bool(head.get('redirect')),
                 'location': bool((head.get('http_headers') or {}).get('location')), 'verified_host': (head.get('tls') or {}).get('verified_against')},
        'candidate': {k: candidate.get(k) for k in ('candidate_id', 'approval_state', 'digest')},
        'checks': job.get('checks', []), 'repeat_identical': (result['capture_info'].get(job['job_id']) or {}).get('repeat_identical'),
        'status': 'FAILED', 'image_size': None, 'bytes': None, 'sha256': None, 'manifest_sha256': None, 'verified': False,
        'result': {k: comp[k] for k in KEEP_RESULT if k in comp}}
    pin, extra = comp.get('baseline'), {}
    if not registry:  # None, or no registry given
        if pin is not None or comp.get('baseline_sha256') is not None:
            _refuse('a capture compared with a Baseline needs the Baseline registry it was compared with')
    else:
        # `registry`: the current registry first, then earlier versions kept by Baseline updates. The inspection must have been compared with
        # exactly one of them (candidate, version, digest, profile, job and image all equal), never with "some" Baseline.
        registries = [registry] if isinstance(registry, dict) else list(registry)
        found = None
        for candidate_registry in registries:
            b = candidate_registry['by_kind'].get(kind)
            if (b is not None and pin == {'candidate_id': b['candidate_id'], 'version': b['version'], 'digest': b['candidate_digest'],
                                          'fingerprint': b['profile_fingerprint']}
                    and comp.get('baseline_job_id') == b['job_id'] and comp.get('baseline_sha256') == b['png_sha256']):
                found = candidate_registry
                break
        if found is None:
            _refuse(f'{kind} was not compared with the approved registry Baseline')
        registry = found
        base_role, diff_role = COMPARE_ROLES[role]
        extra[base_role] = registry['pngs'][kind]
        if comp.get('diff_sha256'):
            diff = run.png(f'{kind}-diff.png')
            if hashlib.sha256(diff).hexdigest() != comp['diff_sha256']:
                _refuse('diff image differs from the comparison record')
            extra[diff_role] = diff
    record['compare_assets'] = {r: hashlib.sha256(raw).hexdigest() for r, raw in extra.items()}
    evidence = job.get('evidence')
    png = None
    if job['execution'] == 'COMPLETED' and evidence:
        rel = 'workspace/' + evidence['artifact_ref']
        png = run.png(rel)
        digest = hashlib.sha256(png).hexdigest()
        if not digest == evidence['digest'] == comp.get('current_sha256'):
            _refuse('PNG digest differs from the capture record')
        size = dimensions(png, max_pixels=16 * 1024 * 1024, max_bytes=PNG_LIMIT)
        record.update(status='SUCCEEDED', image_size=[int(size[0]), int(size[1])], bytes=len(png), sha256=digest, verified=True,
                      manifest_sha256=run.manifest.get('workspace/' + evidence['manifest_ref']))
    return record, png, extra


def load(directory, registry=None):
    """-> (local_capture, changes, assets). `assets` is {target_id: {role: png bytes}}; nothing is written anywhere."""
    run = Run(directory)
    report = run.json('validation-result.json')
    compared = report.get('baseline_compared')
    if compared is True and not registry:
        _refuse('a compared run can only be shown with its Baseline registry (--baseline-registry)')
    if (report.get('passed') is not True or report.get('baseline_approved') is not False or compared not in (True, False)
            or report.get('aws_touched') is not False or report.get('site_modified') is not False or report.get('monitoring_started') is not False):
        _refuse('only a passed run that approved, compared and modified nothing can be shown')
    created = run.json('workspace-created.json')
    config = settings()
    site = next((s for s in config['sites'] if s['origin'] == created['origin']), None)
    url = urlsplit(created['url'])
    if (site is None or f'{url.scheme}://{url.netloc}' != site['origin'] or url.query or url.fragment or url.username or not url.path.startswith('/')
            or url.port not in (None, 443)):
        _refuse('capture URL is not a page of a registered site')
    captures, pngs, page_id = [], {}, None
    for kind, role in KINDS:
        window = report['windows'].get('CAPTURE-' + kind)
        if window is None:
            continue
        head, meta = run.json(f'{kind}-head.json'), run.json(f'{kind}-capture-meta.json')
        record, png, extra = _capture(run, kind, role, window, head, meta, registry if compared else None)
        result = run.json(f'{kind}-run-result.json')
        page_id = page_id or result['state']['jobs'][0]['page_id']
        if result['state']['jobs'][0]['page_id'] != page_id:
            _refuse('profiles belong to different pages')
        captures.append(record)
        if png is not None:
            pngs[role] = png
            pngs.update(extra)
    if not captures:
        _refuse('no capture in this run')
    validate_id(page_id, 'target_id')
    # A registered monitoring target (e.g. the top page) gets its captures on its own record; any other page of the site is an extra page.
    target = next((p for p in config['pages'] if p['target_id'] == page_id), None)
    if target is not None and target['url'] != created['url']:
        _refuse('the captured page id clashes with a registered monitoring target')
    if target is None and url.path == '/':
        _refuse('the top page can only be shown as its registered monitoring target')
    planned = capture_plan(config)['pages'].get(page_id)
    first = (min(captures, key=lambda c: VERDICT_ORDER.get((c['result'].get('operational') or {}).get('verdict'), 1))
             if compared else captures[0])
    verified = all(c['verified'] for c in captures if c['status'] == 'SUCCEEDED') and any(c['status'] == 'SUCCEEDED' for c in captures)
    result = dict(first['result'])  # The page-level result carries the first profile's audits; every capture keeps its own copy.
    for key in ('baseline_sha256', 'diff_sha256'):
        result.pop(key, None)  # page-level image digests are per profile role, set below
    for c in captures:
        if c['sha256']:
            result[c['role'] + '_sha256'] = c['sha256']
        for r, digest in c.pop('compare_assets').items():
            result[r + '_sha256'] = digest
    change ={'page_id': page_id, 'url': created['url'], 'observed_at': max(c['captured_at'] for c in captures), 'baseline_approved': compared,
              'source_availability': 'VERIFIED' if verified else 'UNAVAILABLE', 'metrics': first['result'].get('metrics') if compared else None,
              'reasons': list(first['result'].get('reasons') or []) if compared else ['PROFILE_UNATTESTED', 'BASELINE_PENDING'],
              'profile_trust': 'UNATTESTED', 'quality': 'UNKNOWN', 'result': result,
              'manifests': {c['role']: {'job_id': c['job_id'], 'manifest_sha256': c['manifest_sha256']} for c in captures if c['manifest_sha256']},
              'captures': captures, **({'synthetic': True} if report.get('synthetic') is True else {})}
    label = planned['label'] if planned and planned['url'] == created['url'] else url.path
    local = {'schema': SCHEMA, 'run_id': run.root.name, 'task': report.get('task'), 'isolation': 'NOT VERIFIED',
             'synthetic': report.get('synthetic') is True,  # an offline integration run: shown only as demo data, never as monitoring
             'pages': [] if target else [{'target_id': page_id, 'site_id': site['site_id'], 'label': label, 'url': created['url']}]}
    return local, {page_id: change}, {page_id: pngs}


def attach(snapshot, directories, registry=None, history=(), older=()):
    """New snapshot = `snapshot` (EMPTY or an AWS export, untouched) + one or more capture runs. -> (snapshot, assets).

    `history`: earlier runs of the shown pages, read and checked exactly like the shown runs, that only add monitoring-history
    entries (no images, no change record). Every run, shown or history, becomes history (monitoring.history_entries).
    """
    if snapshot.get('source') not in ('EMPTY', 'AWS_EXPORT', 'FIXTURE') or 'local_capture' in snapshot:
        _refuse('a capture can only be added to an empty, AWS-export or synthetic (FIXTURE) snapshot')
    directories = [directories] if isinstance(directories, (str, Path)) else list(directories)
    changes, assets, pages, runs, synthetic, observed = dict(snapshot.get('changes', {})), {}, [], [], set(), []
    registries = [registry, *older] if registry else []  # the current Baseline registry and the earlier versions an update kept
    for directory in directories:
        local, found, pngs = load(directory, registries)
        synthetic.add(local['synthetic'])
        observed += [(local['run_id'], pid, change, local['synthetic']) for pid, change in found.items()]
        if set(found) & set(changes):
            _refuse('page already has a change record')
        changes.update(found)
        assets.update(pngs)
        pages += local['pages']
        runs.append({'run_id': local['run_id'], 'task': local['task'], 'page_id': next(iter(found))})
    if not runs:
        _refuse('no capture run given')
    for directory in history:
        local, found, _ = load(directory, registries)
        synthetic.add(local['synthetic'])
        if not set(found) <= {r['page_id'] for r in runs}:
            _refuse('a history run must belong to a page that is shown')
        observed += [(local['run_id'], pid, change, local['synthetic']) for pid, change in found.items()]
    # A FIXTURE snapshot (synthetic HTTP values, the offline demo) only ever carries synthetic runs, and a synthetic run never real data.
    if True in synthetic and (len(synthetic) > 1 or snapshot.get('source') not in ('EMPTY', 'FIXTURE')) or (
            snapshot.get('source') == 'FIXTURE' and True not in synthetic):
        _refuse('a synthetic run is never shown together with real captures or monitoring data')
    local = {'schema': SCHEMA, 'run_id': runs[0]['run_id'], 'task': runs[0]['task'], 'isolation': 'NOT VERIFIED', 'pages': pages, 'runs': runs}
    from .monitoring import history_entries
    try:
        entries = history_entries(observed, latest_run_ids={r['run_id'] for r in runs})
    except ValueError as exc:
        _refuse(str(exc))
    out = {**snapshot, 'changes': changes, 'local_capture': local, 'monitoring_history': entries}
    if True in synthetic:  # the existing demo labelling (FIXTURE): banner, "合成デモ" captions, never an imported monitoring result
        notice = 'オフライン統合テストの合成データです。実サイトの撮影・監視結果ではありません。品質UNKNOWN。'
        out.update(source='FIXTURE', sample_notice=' '.join(filter(None, (snapshot.get('sample_notice'), notice))))
    elif out['source'] == 'EMPTY':
        out['source'] = 'LOCAL_CAPTURE'
    return out, assets

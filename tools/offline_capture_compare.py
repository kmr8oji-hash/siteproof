"""Offline integration of capture -> formal Baseline comparison -> REVIEW, through the REAL compare-mode Worker code. No network.

Run: py -3.15 -B tools/offline_capture_compare.py --registry .local\\baseline-ttn-home-01 --out .local\\NEW_DIR

What is real: tests/runtime/s3t_worker (apply / create / run_and_export, compare mode via SITEPROOF_BASELINE_REGISTRY), the staging,
binding and export in noxiworks.baseline_runtime, RuntimeService.run, S1 ingest, ComparisonService, the stability verify(), the
host-side checks the harness applies (created_matches / comparison_matches / candidates_match / diff digest), the REVIEW adapter and pages.
What is a stand-in: tests.runtime.s3_worker, the Linux-container module that owns the brokered real-site transport, is replaced
in-process by a producer that hands back stored / edited Baseline bytes with synthetic proxy and browser records (the
tests/comparison/support.py stand-ins). Its prepare() is baseline_runtime.prepare_job, the same binding s3_worker.prepare performs.
The registry is used through a READ-ONLY copy (files made read-only) and both copies are re-hashed at the end. Every run directory
says `synthetic: true`; REVIEW shows it as demo data (FIXTURE), never as a capture or as monitoring history.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.noxiworks import baseline_registry
from src.noxiworks.baseline_runtime import (candidates_match, comparison_matches, created_matches, expected_baseline, prepare_job,
                                            read_registry, tree)
from src.noxiworks.home import build
from src.noxiworks.local_capture import attach
from src.noxiworks.product import capture_plan, empty_snapshot, settings
from src.runtime.stability import policy
from src.worker.capture import capture, MemoryChannel
import tests.runtime
from tests.comparison.support import synthetic_browser_audit
from tests.runtime import s3t_worker
from tools.offline_baseline_demo import RESOURCES, DemoLease, StoredImageDriver, changed_image, stability_record

SCHEMA = 'siteproof.offline-capture-compare.v1'
CASES = {'unchanged': 'NO_VISUAL_CHANGE_DETECTED', 'changed': 'VISUAL_CHANGED', 'unstable': 'UNKNOWN'}


class StandIn(types.ModuleType):
    """In-process replacement for tests.runtime.s3_worker: same names s3t_worker uses, synthetic producer, no transport."""

    def __init__(self, case):
        super().__init__('tests.runtime.s3_worker')
        page = next(p for p in settings()['pages'] if p['target_id'] == 'ttn-home')
        site = next(s for s in settings()['sites'] if s['site_id'] == page['site_id'])
        self.case, self.page_url, self.site = case, page['url'], site
        self.PATH, self.PAGE_ID, self.STABILITY, self.RUNTIME, self.INFO = '/about', 'ttn-about', None, {}, {}
        self.create = self.run = None  # replaced by s3t_worker.apply(), exactly as in the container

    def registered(self):
        host = self.page_url.split('/')[2]
        return host, 'https://' + host + self.PATH, self.site

    def prepare(self, kind):
        runtime = self.RUNTIME['runtime']
        batch, job_id, plan = prepare_job(runtime, self.PAGE_ID, kind)
        return {'batch': batch, 'job_id': job_id, 'kind': kind, 'baseline': plan['baseline']}

    def base_run(self, batch):
        """What s3_worker.run returns, with the producer replaced: {state, comparison, baselines, capture_info}."""
        runtime = self.RUNTIME['runtime']
        (job_id, _, body), = runtime.store.bindings(batch)
        kind = body['kind']
        record = next(b for b in read_registry(os.environ[s3t_worker.REGISTRY_ENV])['baselines'] if b['kind'] == kind)
        stored = runtime.comparison.image(record['job_id'])  # the approved Baseline bytes, re-verified from S1
        edited = changed_image(stored)
        image = edited if self.case == 'changed' else stored
        stability = stability_record(image, edited if self.case == 'unstable' else None, self.STABILITY)
        lease = DemoLease(runtime.repo.get_job(job_id).snapshot.intent.target_url)

        def remote(request, remaining):
            out = capture(request, StoredImageDriver(image, lease.ledger), lease, RESOURCES)
            runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))  # synthetic: no browser ran
            runtime.record_capture_stability(job_id, stability)
            self.INFO[job_id] = {'screenshot_sha256': hashlib.sha256(image).hexdigest(), 'repeat_identical': stability['value'] == 'STABLE',
                                 'stability': stability, 'synthetic': True}
            return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed

        state = runtime.run(batch, remote, lease, RESOURCES)
        return {'state': state, 'comparison': runtime.comparison.state(), 'baselines': runtime.workspace.state()['baselines'],
                'capture_info': dict(self.INFO)}


@contextmanager
def worker_container(stand_in, registry, evidence):
    """The trusted Worker's view: the stand-in module, the registry 'mount' in the environment, /evidence/{ws,exports}."""
    saved = (sys.modules.get('tests.runtime.s3_worker'), getattr(tests.runtime, 's3_worker', None), os.environ.get(s3t_worker.REGISTRY_ENV),
             s3t_worker.WORKSPACE, s3t_worker.EXPORTS, dict(s3t_worker.PLAN_STATE))
    stand_in.run = stand_in.base_run
    sys.modules['tests.runtime.s3_worker'], tests.runtime.s3_worker = stand_in, stand_in
    os.environ[s3t_worker.REGISTRY_ENV] = str(registry)
    s3t_worker.WORKSPACE, s3t_worker.EXPORTS = evidence / 'ws', evidence / 'exports'
    try:
        s3t_worker.apply()
        yield stand_in
    finally:
        module, attr, env, s3t_worker.WORKSPACE, s3t_worker.EXPORTS, plan = saved
        s3t_worker.PLAN_STATE.clear(); s3t_worker.PLAN_STATE.update(plan)
        for key, value in (('tests.runtime.s3_worker', module),):
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
        if attr is None:
            tests.runtime.__dict__.pop('s3_worker', None)
        else:
            tests.runtime.s3_worker = attr
        if env is None:
            os.environ.pop(s3t_worker.REGISTRY_ENV, None)
        else:
            os.environ[s3t_worker.REGISTRY_ENV] = env


def read_only_copy(registry, dest):
    shutil.copytree(registry, dest)
    for p in dest.rglob('*'):
        if p.is_file():
            os.chmod(p, stat.S_IREAD)
    return dest


def run_case(case, registry, expect, out, now):
    """One harness-shaped run (Desktop then Mobile) through the compare-mode Worker. -> (run dir, summary)."""
    evidence = out / 'worker-evidence'
    run_dir = out / 'run'
    checks, results, exports = {}, {}, {}
    with worker_container(StandIn(case), registry, evidence) as s3:
        created = s3.create()
        checks['S_workspace_staged_from_the_pinned_registry_and_every_profile_bound'] = created_matches(created['baseline'], expect)
        if not checks['S_workspace_staged_from_the_pinned_registry_and_every_profile_bound']:
            raise ValueError('BASELINE_NOT_BOUND')
        for kind in ('Desktop', 'Mobile'):
            prep = s3.prepare(kind)
            msg = {'type': 'result', **s3.run(prep['batch'])}
            comp = next(r for r in msg['comparison']['results'] if r.get('job_id') == prep['job_id'])
            k = kind[0]
            checks[f'K{k}_job_bound_to_the_formal_baseline_before_capture'] = prep['baseline'] == expect['pins'][kind]
            checks[f'K{k}_candidate_saved_pending_and_only_the_registry_baselines_approved'] = candidates_match(msg['baselines'], prep['job_id'], expect)
            checks[f'K{k}_compared_with_the_formal_baseline_of_this_profile'] = comparison_matches(comp, kind, expect)
            names = [n for n, x in msg['comparison_exports'].items() if x['job_id'] == prep['job_id']]
            ok = names == ([f'{kind}-diff.png'] if comp.get('diff_sha256') else [])
            for n in names:
                raw = (evidence / 'exports' / n).read_bytes()
                ok = ok and hashlib.sha256(raw).hexdigest() == msg['comparison_exports'][n]['sha256'] == comp['diff_sha256']
                exports[n] = raw
            checks[f'K{k}_diff_exported_and_matches_the_comparison'] = ok
            results[kind] = (msg, comp)
    compared = all(comparison_matches(comp, kind, expect) for kind, (_, comp) in results.items())
    at = format_utc(now)
    files = {'workspace-created.json': {k: created[k] for k in ('site', 'origin', 'url', 'page_id', 'profiles', 'plan_sha256', 'targets_sha256', 'baseline')},
             'validation-result.json': {'task': 'SITEPROOF-S3-1C-OFFLINE-INTEGRATION', 'synthetic': True, 'passed': all(checks.values()),
                                        'baseline_approved': False, 'baseline_compared': compared, 'aws_touched': False, 'site_modified': False,
                                        'monitoring_started': False, 'navigated_to_real_site': False, 'checks': checks,
                                        'windows': {'CAPTURE-' + kind: {'opened_at': at, 'closed_at': at} for kind in results}}}
    for kind, (msg, comp) in results.items():
        files[f'{kind}-run-result.json'] = msg
        files[f'{kind}-head.json'] = {'synthetic': True, 'http_status': None, 'note': 'no HEAD: offline integration, no network'}
        files[f'{kind}-capture-meta.json'] = [{'job_id': comp['job_id'], 'reason': 'CAPTURE_COMPLETE', 'synthetic': True, 'sandbox': {}, 'runtime': {}}]
    run_dir.mkdir(parents=True)
    for name, body in files.items():
        (run_dir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for name, raw in exports.items():
        (run_dir / name).write_bytes(raw)
    shutil.copytree(evidence / 'ws', run_dir / 'workspace')
    (run_dir / 'export-sha256.json').write_text(json.dumps(tree(run_dir), indent=2) + '\n', encoding='utf-8')
    summary = {kind: {'verdict': comp['operational']['verdict'], 'operational_reasons': comp['operational']['reasons'], 'quality': comp['quality'],
                      'strict_reasons': comp['reasons'], 'changed_pixels': (comp['metrics'] or {}).get('changed_pixels'), 'baseline': comp['baseline'],
                      'job_id': comp['job_id'], 'result_id': comp['result_id'], 'diff_sha256': comp['diff_sha256']} for kind, (_, comp) in results.items()}
    return run_dir, {'checks': checks, 'baseline_compared': compared, 'profiles': summary}


def build_review(run_dir, registry, out, now):
    snapshot, assets = attach(empty_snapshot(), [run_dir], baseline_registry.read(registry))
    with tempfile.TemporaryDirectory(prefix='siteproof-s3c-') as staging:
        for tid, roles in assets.items():
            (Path(staging) / tid).mkdir()
            for role, raw in roles.items():
                (Path(staging) / tid / (role + '.png')).write_bytes(raw)
        return build(out, snapshot, now=now, assets=staging)


def integrate(registry, out):
    registry, out = Path(registry).resolve(), Path(out).resolve()
    if out.exists():
        raise ValueError('output exists; nothing overwritten')
    original = tree(registry)
    out.mkdir(parents=True)
    copy = read_only_copy(registry, out / 'registry-read-only-copy')
    record = read_registry(copy)
    expect = {**expected_baseline(record), 'registry_export_sha256': hashlib.sha256((copy / 'export-sha256.json').read_bytes()).hexdigest()}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    report = {'schema': SCHEMA, 'synthetic': True, 'real_site_access': False, 'registry': registry.name, 'expect': expect, 'cases': {}, 'failures': []}
    for case, verdict in CASES.items():
        run_dir, summary = run_case(case, copy, expect, out / case, now)
        view = build_review(run_dir, copy, out / case / 'ui', now)
        page = next(p for p in view['pages'] if p['target_id'] == 'ttn-home')
        summary['review'] = {'source': view['source'], 'change_state': page['change']['state'], 'baseline_approved': page['change'].get('baseline_approved'),
                             'assets': sorted(page.get('available_assets', []))}
        report['cases'][case] = summary
        for kind, p in summary['profiles'].items():
            if p['verdict'] != verdict or p['quality'] != 'UNKNOWN' or (case == 'unstable' and 'CAPTURE_UNSTABLE' not in p['operational_reasons']):
                report['failures'].append(f'{case}/{kind}: {p["verdict"]} {p["operational_reasons"]}')
        if not all(summary['checks'].values()):
            report['failures'].append(f'{case}: checks ' + ', '.join(k for k, v in summary['checks'].items() if not v))
    copy_tree = tree(copy)
    copy_tree.pop('export-sha256.json')
    report['registry_copy_unchanged'] = copy_tree == json.loads((copy / 'export-sha256.json').read_text('utf-8'))
    report['registry_unchanged'] = tree(registry) == original
    if not (report['registry_copy_unchanged'] and report['registry_unchanged']):
        report['failures'].append('registry changed')
    report['passed'] = not report['failures']
    (out / 'OFFLINE-INTEGRATION.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--registry', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    report = integrate(args.registry, args.out)
    for case, s in report['cases'].items():
        for kind, p in s['profiles'].items():
            print(f'{case:9} {kind:7} {p["verdict"]:26} changed_pixels={p["changed_pixels"]} reasons={p["operational_reasons"]}')
        print(f'{"":9} checks {sum(s["checks"].values())}/{len(s["checks"])}  REVIEW: {s["review"]["source"]} state={s["review"]["change_state"]}')
    print(('PASSED' if report['passed'] else 'FAILED: ' + '; '.join(report['failures'])) + ' / SYNTHETIC offline integration, no network')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

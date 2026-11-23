"""Offline proof of the Baseline comparison on an ISOLATED copy of a Baseline registry. No browser, network, Docker or AWS.

Run: py -3.15 -B tools/offline_baseline_demo.py --registry .local\\baseline-ttn-home-01 --out .local\\NEW_DIR

Three scenarios, each on its own fresh copy of the registry workspace (the registry itself is only read and re-hashed):
  unchanged  the stored, approved Baseline image itself                -> expected NO_VISUAL_CHANGE_DETECTED
  changed    the Baseline image with a red band painted across it      -> expected VISUAL_CHANGED
  unstable   the Baseline image, but its stability shots flicker       -> expected UNKNOWN / CAPTURE_UNSTABLE
Each runs the product pipeline (RuntimeService -> S1 ingest -> ComparisonService.compare against the approved head of the
same profile). The "capture" is a synthetic producer that hands back stored or edited bytes; its proxy and browser records
are synthetic too (the same stand-ins as tests/comparison/support.py). Every job carries an `offline_demo` event and the
output is labelled SYNTHETIC: these are not real-site captures, never Baselines, never monitoring history.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.comparison import preview
from src.comparison.service import MAX_BYTES, MAX_PIXELS
from src.isolation.ledger import ConnectLedger
from src.noxiworks.baseline_runtime import open_runtime, prepare_job, tree
from src.noxiworks.product import capture_plan
from src.runtime.browser import ResourceLimits
from src.runtime.stability import SCHEMA as STABILITY, policy, verify
from src.worker.capture import capture, MemoryChannel
from tests.comparison.support import Driver, synthetic_browser_audit

SCHEMA = 'siteproof.offline-baseline-demo.v1'
RESOURCES = ResourceLimits(120, 30, 16 * 1024 * 1024, 768 * 1024 * 1024, 16, 64, 60, 64 * 1024 * 1024)
SCENARIOS = {'unchanged': 'NO_VISUAL_CHANGE_DETECTED', 'changed': 'VISUAL_CHANGED', 'unstable': 'UNKNOWN'}
BAND = (96, 176, b'\xd3\x2f\x2f\xff')  # rows y0..y1 painted in one opaque red: an obvious "display change"


class DemoLease:
    """In-memory stand-in for the proxy lease. It never opens a socket; the URL is an identifier only."""
    def __init__(self, url):
        self.url, self.active, self.ledger = url, True, ConnectLedger()

    def check(self, url=None):
        if not self.active or url is not None and url != self.url:
            raise ValueError('offline demo lease refused')
        return 'http://127.0.0.1:9'

    def stop(self):
        self.active = False
        return True


class StoredImageDriver(Driver):
    """The fixture Driver (synthetic proxy record for the job's own host), but its screenshot is the given stored bytes."""
    def __init__(self, image, ledger):
        super().__init__(ledger=ledger)
        self.image = image

    def capture(self, profile, seconds):
        return self.image


def changed_image(png):
    w, h, rgba = preview.decode(png, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES)
    pixels = bytearray(rgba)
    y0, y1, color = BAND
    for y in range(y0, min(y1, h)):
        pixels[y * w * 4:(y + 1) * w * 4] = color * w
    return preview.png(w, h, pixels, max_pixels=MAX_PIXELS)


def stability_record(image, flicker, rules):
    """Run the trusted verify() over a producer report: three identical spaced shots, or six alternating ones."""
    digest = hashlib.sha256(image).hexdigest()
    if flicker is None:
        shots, previous, value = [(438, digest), (945, digest), (1445, digest)], image, 'STABLE'
    else:
        other = hashlib.sha256(flicker).hexdigest()
        shots = [(438 + 500 * i, other if i % 2 == 0 else digest) for i in range(6)]
        previous, value = flicker, 'UNSTABLE'
    report = {'schema': STABILITY, 'value': value, 'policy': rules, 'attempts': len(shots), 'elapsed_ms': shots[-1][0],
              'shots': [{'t_ms': t, 'sha256': s} for t, s in shots]}
    return verify(report, image, previous, rules)


def prepare(runtime, kind, scenario):
    """The product binding of the next owner-page job (baseline_runtime.prepare_job), tagged as a synthetic demo job."""
    batch, job_id, plan = prepare_job(runtime, 'ttn-home', kind)
    runtime.store.event(job_id, {'offline_demo': {'schema': SCHEMA, 'scenario': scenario, 'synthetic': True,
                                                  'real_site_access': False, 'not_a_baseline': True}})
    return batch, job_id, plan, runtime.repo.get_job(job_id).snapshot.intent.target_url


def run_scenario(runtime, scenario, kind, baseline, rules):
    batch, job_id, plan, url = prepare(runtime, kind, scenario)
    pin = plan['baseline']
    if not pin or pin['candidate_id'] != baseline['candidate_id'] or pin['version'] != baseline['version']:
        raise ValueError(f'{kind}: job did not pin the approved Baseline {baseline["candidate_id"]}')
    stored = runtime.comparison.image(baseline['job_id'])  # Re-verified S1 read of the approved Baseline image
    if hashlib.sha256(stored).hexdigest() != baseline['png_sha256']:
        raise ValueError(f'{kind}: Baseline image differs from the approval record')
    edited = changed_image(stored) if scenario != 'unchanged' else None
    image = edited if scenario == 'changed' else stored
    stability = stability_record(image, edited if scenario == 'unstable' else None, rules)
    lease = DemoLease(url)

    def factory(request, remaining):
        out = capture(request, StoredImageDriver(image, lease.ledger), lease, RESOURCES)
        runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))  # Synthetic: no browser ran.
        runtime.record_capture_stability(job_id, stability)
        return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed

    runtime.run(batch, factory, lease, RESOURCES)
    rows = runtime.comparison.store.rows('results', job_id=job_id, limit=1)
    if not rows:
        raise ValueError(f'{scenario}/{kind}: no comparison result')
    result = runtime.comparison.result(rows[0]['result_id'])
    images = {}
    for role in ('current', 'baseline', 'diff'):
        try:
            images[role] = runtime.comparison.result_image(result['result_id'], role)
        except Exception:
            pass
    return result, images


def demo(registry, out):
    registry, out = Path(registry).resolve(), Path(out).resolve()
    if out.exists():
        raise ValueError('output exists; nothing overwritten')
    manifest = json.loads((registry / 'export-sha256.json').read_text('utf-8'))
    before = tree(registry)
    before.pop('export-sha256.json')
    if before != manifest:
        raise ValueError('Baseline registry differs from its export-sha256.json')
    record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
    rules = policy(capture_plan()['pages']['ttn-home']['stability'])
    out.mkdir(parents=True)
    summary = {'schema': SCHEMA, 'synthetic': True, 'real_site_access': False, 'monitoring': False,
               'label': 'オフライン実証（合成）：実サイトの撮影・監視結果ではありません',
               'registry': {'registry_id': registry.name, 'export_sha256_json': hashlib.sha256((registry / 'export-sha256.json').read_bytes()).hexdigest()},
               'producer': 'synthetic (stored / edited Baseline bytes); proxy and browser records are synthetic stand-ins',
               'change': {'band_rows': [BAND[0], BAND[1]], 'rgba': list(BAND[2])}, 'scenarios': {}}
    failures = []
    for scenario, expected in SCENARIOS.items():
        directory = out / scenario
        shutil.copytree(registry / 'workspace', directory / 'workspace')
        runtime = open_runtime(directory / 'workspace')
        entries = {}
        for baseline in record['baselines']:
            kind = baseline['kind']
            result, images = run_scenario(runtime, scenario, kind, baseline, rules)
            op = result['operational']
            for role, raw in images.items():
                (directory / f'{kind}-{role}.png').write_bytes(raw)
            (directory / f'{kind}-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            ok = (op['verdict'] == expected and result['quality'] == 'UNKNOWN' and result['profile_trust'] == 'UNATTESTED'
                  and result['source_availability'] == 'VERIFIED' and result['baseline']['candidate_id'] == baseline['candidate_id']
                  and (scenario != 'unstable' or 'CAPTURE_UNSTABLE' in op['reasons']))
            if not ok:
                failures.append(f'{scenario}/{kind}: {op["verdict"]} {op["reasons"]}')
            entries[kind] = {'expected': expected, 'verdict': op['verdict'], 'operational_reasons': op['reasons'],
                             'strict_quality': result['quality'], 'strict_reasons': result['reasons'], 'profile_trust': result['profile_trust'],
                             'metrics': result['metrics'], 'baseline': result['baseline'], 'baseline_job_id': result['baseline_job_id'],
                             'job_id': result['job_id'], 'result_id': result['result_id'], 'capture_stability': result['capture_stability'],
                             'current_sha256': result['current_sha256'], 'baseline_sha256': result['baseline_sha256'],
                             'diff_sha256': result['diff_sha256'], 'images': sorted(f'{kind}-{r}.png' for r in images), 'passed': ok}
        summary['scenarios'][scenario] = entries
    after = tree(registry)
    after.pop('export-sha256.json')
    summary['registry']['unchanged_after'] = after == manifest
    if after != manifest:
        failures.append('Baseline registry changed')
    summary['passed'] = not failures
    summary['failures'] = failures
    (out / 'OFFLINE-DEMO.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out / 'export-sha256.json').write_text(json.dumps(tree(out), indent=2) + '\n', encoding='utf-8')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--registry', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    summary = demo(args.registry, args.out)
    for scenario, entries in summary['scenarios'].items():
        for kind, x in entries.items():
            pixels = (x['metrics'] or {}).get('changed_pixels')
            print(f'{scenario:9} {kind:7} {x["verdict"]:26} changed_pixels={pixels} reasons={x["operational_reasons"]} {"OK" if x["passed"] else "UNEXPECTED"}')
    print(('PASSED' if summary['passed'] else 'FAILED: ' + '; '.join(summary['failures'])) + ' / SYNTHETIC offline demo, no network')
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

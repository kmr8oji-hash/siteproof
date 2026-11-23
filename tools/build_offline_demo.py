"""Offline demo of the whole product from repository content only. No browser, network, Docker, AWS or .local evidence.

Run: py -3.15 -B tools/build_offline_demo.py --out NEW_DIR      (then open NEW_DIR/ui/index.html)

Everything shown is SYNTHETIC and labelled so (FIXTURE banner, 合成デモ captions):
  HTTP     src.noxiworks.sample synthetic HTTP / TLS / domain values for the five registered pages (no request is made);
           the latest result is HTTP 200 except one page (HTTP 503), so HOME shows both states
  Baseline a synthetic "page" image per profile (Desktop 1440 / Mobile 390, the capture plan's profiles), approved by a
           synthetic actor through the same SQLiteBaselineStore.decide as tools/register_baseline.py, inside NEW_DIR only
  images   three runs through the compare-mode Worker of tools/offline_capture_compare.py, against that Baseline:
             unchanged (26 h ago) -> NO_VISUAL_CHANGE_DETECTED,  unstable (14 h ago) -> UNKNOWN / CAPTURE_UNSTABLE,
             changed (2 h ago, shown in REVIEW) -> VISUAL_CHANGED
  schedule synthetic Monitor Provider records for the HTTP channel; the image channel has none (予定・未稼働), as in production
The clock is fixed (--now, default DEMO_NOW) so every build is identical. Real evidence is never read or shown here.
"""
import argparse
import hashlib
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc, parse_utc
from src.baseline.model import BaselineStatus
from src.comparison import preview
from src.comparison.service import MAX_PIXELS
from src.noxiworks.baseline_runtime import expected_baseline, prepare_job, read_registry, tree
from src.noxiworks.capture import create_runtime
from src.noxiworks.monitoring import SCHEDULE_SCHEMA
from src.noxiworks.product import capture_plan, settings
from src.noxiworks.sample import make_sample
from src.runtime.stability import policy
from src.worker.capture import capture, MemoryChannel
from tests.comparison.support import synthetic_browser_audit
from tools.offline_baseline_demo import RESOURCES, DemoLease, StoredImageDriver, stability_record
from tools.offline_capture_compare import run_case

DEMO_NOW = '2026-11-22T03:00:00Z'
PAGE_ID = 'ttn-home'
ACTOR = 'synthetic-demo-operator'
HEIGHTS = {'Desktop': 1200, 'Mobile': 1400}
DOWN_PAGE = 'hms-concierge'
CASES = (('unchanged', 26), ('unstable', 14), ('changed', 2))  # case, hours before --now; the last one is shown in REVIEW


def page_image(width, height):
    """A plain mock web page (header, hero, card grid, footer) drawn as flat colours: obviously not a real site."""
    px = bytearray(b'\xf4\xf6\xfa\xff' * (width * height))

    def rect(x0, y0, x1, y1, rgba):
        for y in range(max(0, y0), min(height, y1)):
            row = y * width * 4
            px[row + max(0, x0) * 4:row + min(width, x1) * 4] = bytes(rgba) * (min(width, x1) - max(0, x0))

    m = max(12, width // 40)
    rect(0, 0, width, 64, (28, 52, 92, 255))
    rect(m, 20, m + width // 6, 44, (236, 240, 248, 255))
    rect(m, 96, width - m, 96 + height // 5, (210, 224, 244, 255))
    cols = 3 if width >= 800 else 1
    card_w = (width - m * (cols + 1)) // cols
    y = 96 + height // 5 + m
    while y + 180 < height - 96:
        for c in range(cols):
            x = m + c * (card_w + m)
            rect(x, y, x + card_w, y + 160, (255, 255, 255, 255))
            rect(x + 16, y + 20, x + card_w // 2, y + 36, (120, 136, 160, 255))
            rect(x + 16, y + 52, x + card_w - 16, y + 60, (200, 208, 220, 255))
            rect(x + 16, y + 72, x + card_w - 40, y + 80, (200, 208, 220, 255))
        y += 160 + m
    rect(0, height - 72, width, height, (48, 56, 72, 255))
    return preview.png(width, height, px, max_pixels=MAX_PIXELS)


def make_registry(root, now):
    """A synthetic Baseline registry in the shape of tools/register_baseline.py output (same store, same decide())."""
    page = next(p for p in settings()['pages'] if p['target_id'] == PAGE_ID)
    plan = capture_plan()['pages'][PAGE_ID]
    profiles = plan['profiles']
    rules = policy(plan['stability'])
    config = {'pages': [{'target_id': PAGE_ID, 'label': page['label'], 'url': page['url'], 'site_name': 'SYNTHETIC DEMO', 'profiles': profiles}]}
    runtime = create_runtime(root / 'source-ws', config)
    store = runtime.comparison.baselines
    baselines = []
    at = format_utc(now - timedelta(days=3))
    for p in profiles:
        kind = p['kind']
        png = page_image(p['width'], HEIGHTS[kind])
        batch, job_id, _ = prepare_job(runtime, PAGE_ID, kind)
        lease = DemoLease(runtime.repo.get_job(job_id).snapshot.intent.target_url)

        def factory(request, remaining, png=png, job_id=job_id, lease=lease):
            out = capture(request, StoredImageDriver(png, lease.ledger), lease, RESOURCES)
            runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))  # synthetic: no browser ran
            runtime.record_capture_stability(job_id, stability_record(png, None, rules))
            return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed

        runtime.run(batch, factory, lease, RESOURCES)
        cid = 'capture-' + job_id
        record = store.get(cid)
        store.decide(cid, decision=BaselineStatus.APPROVED, actor=ACTOR, expected_revision=0,
                     reviewed_digest=record.registered_digest, expected_current_version=0)
        c = record.candidate
        baselines.append({'kind': kind, 'page_id': PAGE_ID, 'candidate_id': cid, 'job_id': job_id, 'version': 1, 'status': 'APPROVED',
                          'revision': 1, 'candidate_digest': record.registered_digest, 'png_sha256': c.artifact_sha256,
                          'artifact_ref': c.artifact_ref, 'profile_fingerprint': c.profile_fingerprint,
                          'viewport': [p['width'], p['height']], 'full_page': p['full_page'], 'captured_at': at,
                          'stability': {'value': 'STABLE'}, 'quality': 'UNKNOWN', 'profile_reason': 'PROFILE_UNATTESTED',
                          'source': 'OWNER_SITE_UNATTESTED', 'approved_at': at, 'actor': ACTOR})
    registry = root / 'registry'
    registry.mkdir()
    (root / 'source-ws').rename(registry / 'workspace')
    record = {'schema': 'siteproof.baseline-registry.v1', 'registry_id': 'synthetic-demo-registry', 'page_id': PAGE_ID, 'url': page['url'],
              'decision': 'APPROVED', 'approved_at': at, 'actor': ACTOR, 'instruction': 'SYNTHETIC offline demo (tools/build_offline_demo.py)',
              'mechanism': 'SQLiteBaselineStore.decide', 'synthetic': True,
              'source_run': {'run_id': 'synthetic-demo-source', 'task': 'OFFLINE-DEMO', 'export_sha256_json': 'synthetic'},
              'distinct_from': [], 'baselines': baselines}
    (registry / 'APPROVAL-RECORD.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (registry / 'export-sha256.json').write_text(json.dumps(tree(registry), indent=2) + '\n', encoding='utf-8')
    return registry


def schedule(now):
    """Synthetic provider state at the configured HTTP interval, last run 5 min ago. No image channel record: it is not scheduled."""
    config = settings()
    last = now - timedelta(minutes=5)
    return [{'schema': SCHEDULE_SCHEMA, 'target_id': p['target_id'], 'channel': 'http', 'enabled': True,
             'last_finished_at': format_utc(last), 'last_outcome': 'COMPLETED',
             'next_due_at': format_utc(last + timedelta(seconds=config['http_interval_seconds'])), 'observed_at': format_utc(now - timedelta(minutes=1)),
             'source': 'SYNTHETIC DEMO（合成のMonitor Provider記録）'} for p in config['pages']]


def build_demo(out, now):
    out = Path(out).resolve()
    if out.exists():
        raise ValueError('output exists; nothing overwritten')
    work = out / 'data'
    work.mkdir(parents=True)
    registry = make_registry(work, now)
    expect = {**expected_baseline(read_registry(registry)),
              'registry_export_sha256': hashlib.sha256((registry / 'export-sha256.json').read_bytes()).hexdigest()}
    runs, summary = {}, {}
    for case, hours in CASES:
        run_dir, s = run_case(case, registry, expect, work / case, now - timedelta(hours=hours))
        if not all(s['checks'].values()):
            raise ValueError(f'{case}: host checks failed')
        runs[case] = run_dir
        summary[case] = {kind: p['verdict'] for kind, p in s['profiles'].items()}
    snapshot = make_sample(work / 'sample-http', now)
    snapshot['changes'] = {}  # the image results come from the three runs above
    for tid, http in snapshot['http'].items():  # the demo story: one page down (HTTP 503), the others recovered (HTTP 200)
        last = http['runs'][-1]
        if tid != DOWN_PAGE:
            last.update(outcome={'S': 'PASS'}, reason={'S': 'HTTP_200'}, http_status={'N': '200'})
    for domain in snapshot['domains'].values():
        domain['expires_at'] = format_utc(now + timedelta(days=240))
    snapshot['sample_notice'] = '合成HTTP値・合成画像・合成人物の承認。実サイト未アクセス。'
    (work / 'snapshot.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (work / 'schedule.json').write_text(json.dumps(schedule(now), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    command = [sys.executable, '-B', '-m', 'src.noxiworks', '--out', str(out / 'ui'), '--now', format_utc(now),
               '--snapshot', str(work / 'snapshot.json'), '--schedule', str(work / 'schedule.json'),
               '--local-capture', str(runs['changed']), '--history-run', str(runs['unchanged']), '--history-run', str(runs['unstable']),
               '--baseline-registry', str(registry)]
    subprocess.run(command, cwd=ROOT, check=True)
    report = {'schema': 'siteproof.offline-demo.v1', 'synthetic': True, 'real_site_access': False, 'aws_access': False,
              'now': format_utc(now), 'cases': summary, 'ui': str(out / 'ui' / 'index.html')}
    (out / 'DEMO.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--now', default=DEMO_NOW, help='fixed UTC demo clock')
    args = parser.parse_args(argv)
    now = parse_utc(args.now)
    if now is None:
        parser.error('--now must be a UTC time like 2026-11-22T03:00:00Z')
    report = build_demo(args.out, now)
    for case, kinds in report['cases'].items():
        print(f'{case:9} ' + '  '.join(f'{k} {v}' for k, v in kinds.items()))
    print(report['ui'])
    print('SYNTHETIC offline demo / no network, no AWS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

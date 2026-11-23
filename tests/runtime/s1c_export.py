"""S1-C host step: existing static HOME/REVIEW/DETAIL/EVIDENCE export from the real run's evidence.

Works on a COPY of the exported S1 evidence (the pristine export is never opened for write).
The Worker's signing key died with the run, so the copy is compared with no authority: strict
profile trust is PROFILE_UNATTESTED, exactly like the real-site configuration. The verdicts come
from ComparisonService.compare() over the stored audit events; nothing is typed in here.
The fixture result is shown under existing demo page slots, source FIXTURE ("デモ").
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import sys

from src.aws_b.model import format_utc
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace
from src.noxiworks.home import build
from src.noxiworks.review import page_view
from src.noxiworks.product import collect_comparison, empty_snapshot, settings
from tools.export_capture_fixture import verify_links

SLOTS = {'03-same-after-approval': 'noxiworks-home', '04-changed': 'noxiworks-taxi',
         '05-restored': 'hms-home', '06-blocked-and-failed-subresources': 'hms-concierge',
         '08-audit-withheld': 'ttn-home'}


def main(run):
    run = Path(run).resolve()
    pristine, work, out = run / 's1', run / 'ui-working', run / 'ui-export'
    if work.exists() or out.exists():
        raise SystemExit('ui outputs exist; refusing to overwrite')
    before = {p.relative_to(pristine).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in pristine.rglob('*') if p.is_file()}
    shutil.copytree(pristine, work)
    workspace = OfflineWorkspace(work / 'siteproof.sqlite', work)
    service = ComparisonService(workspace, policy=PixelPolicy(0, 'S1-C fixture: exact RGBA equality, no production threshold'),
                                allow_unattested_preview=True)
    now = datetime.now(timezone.utc)
    config = settings()
    pages = {p['target_id']: p for p in config['pages']}
    snapshot = empty_snapshot()
    snapshot.update(source='FIXTURE', sample_notice='S1-C オフラインfixture（実Chromium撮影）。実サイトの結果ではありません。品質UNKNOWN。')
    assets, shown = {}, {}
    for case, tid in SLOTS.items():
        job = next(j for j in json.loads((run / f'case-{case}.json').read_text('utf-8'))['jobs'] if j['kind'] == 'Desktop')
        change, images = collect_comparison(service, {'target_id': 'fixture-page', 'url': 'https://fixture.invalid/'},
                                            job['job_id'], format_utc(now))
        change.update(page_id=tid, url=pages[tid]['url'])
        snapshot['changes'][tid], assets[tid] = change, images
        shown[tid] = {'case': case, 'job_id': job['job_id'], 'quality': change['result']['quality'],
                      'operational': change['result']['operational'], 'profile_trust': change['profile_trust']}
    staging = run / 'ui-assets'
    for tid, files in assets.items():
        (staging / tid).mkdir(parents=True)
        for name, raw in files.items():
            (staging / tid / name).write_bytes(raw)
    view = build(out, snapshot, now=now, assets=staging)
    links = verify_links(out)
    after = {p.relative_to(pristine).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in pristine.rglob('*') if p.is_file()}
    pages_out = {p['target_id']: p for p in view['pages']}
    texts = {n: (out / n).read_text('utf-8') for n in ('index.html', 'review.html', 'details.html', 'evidence.html')
             if (out / n).is_file()}
    reviewed = {t: pages_out[t]['change']['visual']['verdict'] for t in shown}
    checks = {
        'verdicts_shown_match_the_runs': reviewed == {
            'noxiworks-home': 'NO_VISUAL_CHANGE_DETECTED', 'noxiworks-taxi': 'VISUAL_CHANGED', 'hms-home': 'NO_VISUAL_CHANGE_DETECTED',
            'hms-concierge': 'UNKNOWN', 'ttn-home': 'UNKNOWN'},
        'three_states_labelled_in_home_and_review': all(
            x in texts[n] for n in ('index.html', 'review.html') for x in ('設定条件では変化未検出', '画像の変化あり・要確認', '画像検査の判定不能')),
        'changed_page_has_baseline_current_diff_images': all(
            (out / 'evidence' / 'noxiworks-taxi' / f'{r}.png').is_file() for r in ('baseline', 'current', 'diff')),
        'unknown_pages_show_no_diff_image_in_review': all(
            page_view(pages_out[t], 'FIXTURE')['images']['diff'] is None for t, v in reviewed.items() if v == 'UNKNOWN'),
        'pristine_evidence_unchanged': before == after,
        'local_links_verified': links > 0,
        'source_is_fixture_demo': view['source'] == 'FIXTURE' and 'デモ' in texts['index.html'],
        'no_remote_assets_or_scripts': all(not re.search(r'<(?:script|link|img|iframe)[^>]*(?:src|href)="https?://', t)
                                           for t in texts.values()),
        'no_quality_pass_claim': all(not re.search(r'品質(?:：|:)?\s*PASS(?!ではありません)', t) for t in texts.values()),
        'unknown_not_shown_as_normal': all(pages_out[t]['change']['state'] == 'UNKNOWN'
                                           for t, s in shown.items() if s['operational']['verdict'] == 'UNKNOWN'),
        'unknown_label_and_reason_displayed': all(x in texts['index.html'] for x in ('画像検査の判定不能', '撮影に必要な通信が遮断されました'))
                                               and '画像検査は判定不能' in texts['review.html'],
        'audit_reason_in_detail': '通信記録' in texts['details.html'] and 'blocked.invalid' in texts['details.html'],
        'fixture_not_labelled_real': 'AWS_EXPORT' not in json.dumps(view['source']),
        'review_has_visual_state': 'id="review-visual"' in texts['review.html'],
        'strict_quality_unknown_all': all(s['quality'] == 'UNKNOWN' for s in shown.values()),
        'profile_unattested_retained_all': all(s['profile_trust'] == 'UNATTESTED' for s in shown.values()),
    }
    summary = {'pages': {t: {'state': pages_out[t]['change']['state'], 'visual': pages_out[t]['change']['visual']['verdict'],
                             'reasons': pages_out[t]['change']['visual']['reasons'],
                             'audit': pages_out[t]['change']['visual']['audit']['state'], **shown[t]}
                         for t in shown}, 'local_links': links, 'checks': checks}
    (run / 'ui-check.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    # UI outputs sealed last, over exactly the files this step created (the S1 run manifest stays untouched).
    created = sorted(p for d in (work, out, staging) for p in d.rglob('*') if p.is_file()) + [run / 'ui-check.json']
    (run / 'ui-sha256.json').write_text(json.dumps({p.relative_to(run).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                                    for p in created}, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:6000])


if __name__ == '__main__':
    main(sys.argv[1])

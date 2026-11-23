"""S3-1T trusted Worker (UID 1001): first real-site capture of the TTN TOP PAGE `/` (target `ttn-home`), Desktop + Mobile, full page.

Everything is the S3-1 Worker (tests/runtime/s3_worker.py), reused unchanged through its module: Broker-resolved single host, production
ConnectTransport, RuntimeService.run, Baseline CANDIDATE registration (never approval), HEAD of the exact page. Only three things differ:
  * the path is `/` and the page id is the registered target `ttn-home` itself (no extra page id);
  * the capture profiles come from src/noxiworks/capture_plan.json, read read-only from the trusted overlay and checked here against
    targets.json and against the profiles the USER approved (Desktop 1440x900 / Mobile 390x844, full page). Anything else: no Worker.
  * the workspace label is the plan's label.
`apply()` is also used by the offline rehearsal (s3p_worker) with the fixture host; it never enables real-site access by itself.

Compare mode (only when the host sets SITEPROOF_BASELINE_REGISTRY to the read-only registry mount): instead of a NEW empty workspace,
the formal Baseline registry is staged, byte-checked, as /evidence/ws and each profile must pin its own approved head
(noxiworks.baseline_runtime.open_staged_runtime). Any refusal raises before a workspace exists, so nothing is captured without its
Baseline. After each run the job's diff PNG is written to /evidence/exports and reported; the comparison itself is the unchanged
RuntimeService/ComparisonService path (source, stability, audits, policy). Nothing is approved here.
"""
import hashlib
import os
from pathlib import Path

from src.noxiworks.baseline_runtime import export_comparisons, open_staged_runtime
from src.noxiworks.capture import create_runtime
from src.noxiworks.product import CONFIG, PLAN, capture_plan

TARGET_ID = os.environ.get('SITEPROOF_TARGET_ID') or 'ttn-home'  # permit mode: the signed target (the harness verified the permit)
PERMIT_MODE = bool(os.environ.get('SITEPROOF_TARGET_ID'))
APPROVED_PROFILES = [{'kind': 'Desktop', 'width': 1440, 'height': 900, 'full_page': True},
                     {'kind': 'Mobile', 'width': 390, 'height': 844, 'full_page': True}]
# TTN's first full-page screenshot re-rasterises the fixed footer once (21 px): settle on 3 identical shots >= 0.8 s apart, bounded.
APPROVED_STABILITY = {'settle_ms': 300, 'interval_ms': 400, 'required_identical': 3, 'min_span_ms': 800, 'max_attempts': 6, 'max_total_ms': 4500}
PLAN_STATE = {}
REGISTRY_ENV = 'SITEPROOF_BASELINE_REGISTRY'
WORKSPACE = Path('/evidence/ws')  # the evidence volume; the host copies it out after the run
EXPORTS = Path('/evidence/exports')


class PlanRefused(RuntimeError):
    pass


def checked_plan():
    """The validated plan entry of the top page. Missing, malformed or different from the approval: refuse (never guess)."""
    try:
        entry = capture_plan()['pages'][TARGET_ID]
    except Exception as exc:  # Missing file, bad JSON, failed validation: all the same, no capture.
        raise PlanRefused('capture plan unreadable or invalid: ' + type(exc).__name__) from None
    if PERMIT_MODE:
        # The files are the ones the signed permit pins (the harness checked before mounting; re-checked here inside the container).
        if (hashlib.sha256(target_plan_path().read_bytes()).hexdigest() != os.environ.get('SITEPROOF_PLAN_SHA256')
                or hashlib.sha256(target_config_path().read_bytes()).hexdigest() != os.environ.get('SITEPROOF_TARGET_SHA256')):
            raise PlanRefused('target files differ from the signed permit')
        if (entry['role'] != 'PRIMARY' or entry['path'] != '/' or entry['registered'] is not True
                or not entry['profiles'] or any(p not in APPROVED_PROFILES for p in entry['profiles']) or entry['stability'] is None):
            raise PlanRefused('capture plan is not an approved top-page capture')
        return entry
    if (entry['role'] != 'PRIMARY' or entry['path'] != '/' or entry['registered'] is not True or entry['site_id'] != 'ttn'
            or entry['profiles'] != APPROVED_PROFILES or entry['stability'] != APPROVED_STABILITY):
        raise PlanRefused('capture plan differs from the approved top-page capture')
    return entry


def target_plan_path():
    return Path(os.environ.get('SITEPROOF_CAPTURE_PLAN') or PLAN)


def target_config_path():
    return Path(os.environ.get('SITEPROOF_TARGETS') or CONFIG)


def create():
    from tests.runtime import s3_worker as s3
    host, url, site = s3.registered()
    entry = PLAN_STATE['entry']
    registry = os.environ.get(REGISTRY_ENV)
    baseline = None
    if registry:  # compare mode: the formal registry or nothing (open_staged_runtime raises; no empty-workspace fallback)
        runtime, baseline = open_staged_runtime(registry, WORKSPACE, url, entry['profiles'])
    else:
        config = {'pages': [{'target_id': s3.PAGE_ID, 'label': entry['label'], 'url': url, 'site_name': site['name'], 'profiles': entry['profiles']}]}
        runtime = create_runtime(WORKSPACE, config)
    s3.RUNTIME.update(runtime=runtime, url=url)
    return {'site': site['name'], 'origin': 'https://' + host, 'url': url, 'page_id': s3.PAGE_ID, 'profiles': entry['profiles'],
            'plan_sha256': PLAN_STATE['plan_sha256'], 'targets_sha256': PLAN_STATE['targets_sha256'], 'baseline': baseline}


def run_and_export(batch):
    """s3_worker.run, then (compare mode) this batch's diff PNGs to /evidence/exports, reported with their digests."""
    from tests.runtime import s3_worker as s3
    out = PLAN_STATE['run'](batch)
    if os.environ.get(REGISTRY_ENV):
        runtime = s3.RUNTIME['runtime']
        out['comparison_exports'] = export_comparisons(runtime, [j for j, _, _ in runtime.store.bindings(batch)], EXPORTS)
    return out


def apply():
    from tests.runtime import s3_worker as s3  # Linux-container module; imported here so the plan check runs anywhere.
    entry = checked_plan()
    PLAN_STATE.update(entry=entry, plan_sha256=hashlib.sha256(target_plan_path().read_bytes()).hexdigest(),
                      targets_sha256=hashlib.sha256(target_config_path().read_bytes()).hexdigest())
    s3.PATH, s3.PAGE_ID = entry['path'], TARGET_ID
    s3.STABILITY = entry['stability']
    s3.create = create
    PLAN_STATE['run'] = s3.run
    s3.run = run_and_export
    return PLAN_STATE


if __name__ == '__main__':
    apply()  # Raises (no Worker, no window) unless the plan is exactly the approved top-page capture.
    from tests.runtime import s3_worker
    s3_worker.main()

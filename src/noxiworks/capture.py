"""Prepare the two owner-page jobs for the existing isolated RuntimeService.

No driver, Docker, Playwright launch or network call is supplied by this module.
Execution still needs an explicitly supplied isolated channel factory and ProxyLease.
"""
from pathlib import Path
import uuid
from urllib.parse import urlsplit

from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.frames import CheckType
from src.core.model import JobIntent
from src.core.offline import OfflineWorkspace, read_profile
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.comparison import initialize as initialize_comparison
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize as initialize_runtime
from src.worker.trusted import TrustedWorker
from .product import capture_plan, settings, site_configs


def create_runtime(output, config=None):
    """Create a NEW local evidence workspace; never replace or auto-approve Baselines."""
    config = config or settings()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    origins = {urlsplit(p['url']).scheme + '://' + urlsplit(p['url']).netloc for p in config['pages']}
    if len(origins) != 1:
        raise ValueError('use create_runtimes for multiple sites')
    workspace = OfflineWorkspace.create(output / 'siteproof.sqlite', output)
    workspace.save_site({'label': config['pages'][0].get('site_name', 'SiteProof'), 'origin': origins.pop(), 'expected_revision': 0})
    planned = capture_plan()['pages']
    for page in config['pages']:
        workspace.save_page({'page_id': page['target_id'], 'label': page['label'],
            'path': urlsplit(page['url']).path, 'expected_revision': 0})
        entry = planned.get(page['target_id'])
        # Explicit profiles (a capture worker that has already checked the plan) first; else the plan's profiles only for the very
        # page it names (same URL); anything else keeps the original Desktop 1440x900.
        profiles = (page['profiles'] if page.get('profiles') else entry['profiles'] if entry and entry['url'] == page['url']
                    else [{'kind': 'Desktop', 'width': 1440, 'height': 900, 'full_page': False}])
        for p in profiles:
            workspace.save_profile({'page_id': page['target_id'], 'kind': p['kind'], 'width': p['width'], 'height': p['height'],
                'full_page': p['full_page'], 'expected_revision': 1})
    initialize_runtime(workspace.db_path, output)
    initialize_comparison(workspace.db_path, output)
    comparison = ComparisonService(workspace,
        policy=PixelPolicy(0, 'SiteProof暫定: 1ピクセル以上の差分をレビュー対象にする。品質の閾値ではない'),
        allow_unattested_preview=True)
    worker = TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(workspace.db_path), ArtifactStore(output))))
    return RuntimeService(workspace, worker, comparison=comparison)


def prepare_batch(runtime, config=None):
    """Bind page-specific JobIntent/Baseline using M1/M5; never start the batch.

    Existing RuntimeService.submit accepts fixture provenance only. This adapter
    records owner-site intent explicitly rather than labelling a real URL fixture.
    RuntimeService.run, with its isolation/cleanup/deadline checks, is unchanged.
    """
    config = config or settings()
    batch = uuid.uuid4().hex
    snapshot = runtime.store.snapshot(batch)
    pages = {p['page_id']: p for p in snapshot['pages']}
    expected = {p['target_id']: p for p in config['pages']}
    if set(pages) != set(expected):
        raise ValueError('workspace pages do not match configured targets')
    prepared = []
    for row in snapshot['profiles']:
        if row['kind'] != 'Desktop':
            continue  # M1 also initializes Mobile; this minimum product uses Desktop only.
        page = expected[row['page_id']]
        url = snapshot['site']['origin'] + pages[row['page_id']]['path']
        if url != page['url']:
            raise ValueError('workspace URL mismatch')
        profile = read_profile(row['body'])
        if profile.fingerprint != row['fingerprint'] or row['kind'] != 'Desktop':
            raise ValueError('capture profile mismatch')
        source = 'OWNER_SITE_UNATTESTED'
        plan = runtime.comparison.prepare(profile, page['target_id'], row['kind'], source)
        intent = JobIntent(url, page['target_id'], profile.profile_id, tuple(CheckType),
            plan['baseline']['candidate_id'] if plan['baseline'] else None)
        prepared.append((row, profile, intent, plan, source))
    if {row['page_id'] for row, *_ in prepared} != set(expected):
        raise ValueError('every page needs a profile')
    for row, profile, intent, plan, source in prepared:
        job = runtime.repo.accept_job('nx-' + uuid.uuid4().hex, intent).job
        runtime.store.bind(job.job_id, batch, {'page': pages[row['page_id']],
            'profile': {'profile_id': profile.profile_id, 'attributes': dict(profile.attributes)},
            'fingerprint': profile.fingerprint, 'profile_revision': row['revision'], 'kind': row['kind'],
            'snapshot_sha256': job.snapshot.sha256, 'source': source})
        runtime.comparison.bind(job, plan)
    return batch


def create_runtimes(output, config=None):
    """New per-site evidence databases preserve M1's single-origin contract."""
    groups = site_configs(config)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    return {key: create_runtime(output / key, group) for key, group in groups.items()}


def prepare_batches(runtimes, config=None):
    groups = site_configs(config)
    if set(runtimes) != set(groups):
        raise ValueError('site/runtime registry mismatch')
    return {key: prepare_batch(runtimes[key], group) for key, group in groups.items()}

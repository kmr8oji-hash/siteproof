"""Explicit synthetic sample: existing M1 PNG, Baseline, comparison and SQLite only.

    This creates synthetic human approval solely inside the sample database.
    It never approves a real capture or opens an existing workspace.
"""
from datetime import timedelta
from pathlib import Path

from src.baseline.model import BaselineStatus
from src.comparison.preview import digest
from src.core.offline import OfflineWorkspace
from src.aws_b.model import format_utc
from .product import empty_snapshot, settings


def make_sample(output, now):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    workspaces = {}
    config = settings()
    snapshot = empty_snapshot()
    snapshot['source'] = 'FIXTURE'
    snapshot['sample_notice'] = '合成HTTP値・合成日時・合成画像・合成人物の承認。実サイト未アクセス。'
    for index, page in enumerate(config['pages']):
        tid = page['target_id']
        from urllib.parse import urlsplit
        u = urlsplit(page['url'])
        site_id = page.get('site_id', u.hostname)
        if site_id not in workspaces:
            work = output / 'fixture-workspaces' / site_id
            work.mkdir(parents=True)
            workspace = OfflineWorkspace.create(work / 'fixture.sqlite', work)
            workspace.save_site({'label': 'SAMPLE ONLY', 'origin': u.scheme + '://' + u.netloc, 'expected_revision': 0})
            workspaces[site_id] = workspace
        workspace = workspaces[site_id]
        workspace.save_page({'page_id': tid, 'label': page['label'], 'path': urlsplit(page['url']).path, 'expected_revision': 0})
        workspace.save_profile({'page_id': tid, 'kind': 'Desktop', 'width': 8, 'height': 8, 'expected_revision': 1})
        before = workspace.save_fixture({'page_id': tid, 'kind': 'Desktop', 'fixture': 'original'})
        candidate = workspace.register_candidate({'capture_id': before['capture_id']})
        directory = output / tid
        directory.mkdir()
        if index == 1:
            workspace.repo.baselines.decide(candidate['candidate_id'], decision=BaselineStatus.APPROVED,
                actor='synthetic-human-sample-only', expected_revision=candidate['revision'],
                reviewed_digest=candidate['digest'], expected_current_version=0)
            after = workspace.save_fixture({'page_id': tid, 'kind': 'Desktop', 'fixture': 'changed'})
            result = workspace.compare({'capture_id': after['capture_id'], 'baseline_id': candidate['candidate_id']})
            assets = {'baseline': workspace.image(before['capture_id']), 'current': workspace.image(after['capture_id']),
                      'diff': workspace.diff_image(result['result_id'])}
            # M1 has no runtime manifest: retain that limitation explicitly.
            result.update(current_sha256=digest(assets['current']), baseline_sha256=digest(assets['baseline']))
            snapshot['changes'][tid] = {'page_id': tid, 'url': page['url'], 'observed_at': format_utc(now - timedelta(hours=1)),
                'baseline_approved': True, 'source_availability': 'VERIFIED', 'metrics': result['metrics'],
                'reasons': ['PROFILE_UNATTESTED'], 'profile_trust': 'UNATTESTED', 'result': result,
                'manifests': {}, 'manifest_status': 'M1_SYNTHETIC_ONLY_NO_S1_MANIFEST'}
        else:
            assets = {'current': workspace.image(before['capture_id'])}
            snapshot['changes'][tid] = {'page_id': tid, 'url': page['url'], 'observed_at': format_utc(now - timedelta(hours=2)),
                'baseline_approved': False, 'source_availability': 'VERIFIED', 'metrics': None,
                'reasons': ['BASELINE_PENDING'], 'result': {'current_sha256': digest(assets['current'])}}
        for role, raw in assets.items():
            (directory / (role + '.png')).write_bytes(raw)
        head = {'pk': {'S': 'CONTROL#' + tid}, 'sk': {'S': 'HEAD'}, 'enabled': {'BOOL': True},
                'execution_generation': {'N': '1'}, 'policy_version': {'S': 'p1'}, 'target_hostname': {'S': u.hostname}}
        outcomes = ['PASS', 'FAIL', 'PASS'] if index == 0 else ['PASS', 'FAIL']
        runs = []
        for n, outcome in enumerate(outcomes):
            at = format_utc(now - timedelta(hours=(len(outcomes)-1-n)*6, minutes=5))
            runs.append({'pk': {'S': 'RUN#' + tid}, 'sk': {'S': at}, 'state': {'S': 'RECORDED'},
                'finished_at': {'S': at}, 'outcome': {'S': outcome}, 'reason': {'S': 'HTTP_200' if outcome == 'PASS' else 'HTTP_503'},
                'http_status': {'N': '200' if outcome == 'PASS' else '503'}, 'elapsed_ms': {'N': str(120 + index*40)},
                'execution_generation': {'N': '1'}, 'policy_version': {'S': 'p1'},
                'tls_not_after': {'S': format_utc(now + timedelta(days=60))}})
        snapshot['http'][tid] = {'head': head, 'runs': runs}
    for domain in {p.get('registration_domain', p['domain']) for p in config['pages']} - {None}:
        snapshot['domains'][domain] = {'scope': domain, 'expires_at': format_utc(now - timedelta(days=1)),
            'observed_at': format_utc(now - timedelta(hours=2)), 'source': 'SYNTHETIC_FIXTURE', 'auto_renew_expected': True}
    return snapshot

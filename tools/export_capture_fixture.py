"""Export synthetic M5/S1 fixtures to the existing HOME. No browser or network.

Run: py -3.15 -B tools/export_capture_fixture.py --out D:\new\fixture-directory
Only a new, unlinked D: directory is accepted. Synthetic approvals never touch a
real Baseline. Profiles remain unattested and aggregate quality stays UNKNOWN.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.aws_c.evidence import verify_local
from src.baseline.model import BaselineStatus
from src.noxiworks.capture import create_runtimes
from src.noxiworks.home import build
from src.noxiworks.product import collect_comparison, empty_snapshot, settings
from src.worker.capture import capture, MemoryChannel
from tests.comparison.support import Driver, Lease, LIMITS, synthetic_browser_audit


class FixtureLease(Lease):
    """In-memory fixture lease; URL strings are identifiers, never destinations."""
    def __init__(self, urls):
        super().__init__()
        self.urls = frozenset(urls)

    def check(self, url=None):
        if url is not None and url not in self.urls:
            raise ValueError('unregistered fixture page')
        return super().check()  # No socket/proxy is created by the synthetic lease.


def _new_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.drive.upper() != 'D:':
        raise ValueError('an absolute, new D: output directory is required')
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.is_junction():
            raise ValueError('linked output refused')
    if path.resolve().drive.upper() != 'D:' or path.exists():
        raise ValueError('output exists or escapes D:; nothing overwritten')
    path.mkdir(parents=True, exist_ok=False)
    return path


def _run(runtime, changed):
    batch = runtime.submit(source='OFFLINE_FIXTURE_UNATTESTED')
    bindings = runtime.store.bindings(batch)
    urls = {runtime.repo.get_job(jid).snapshot.intent.target_url for jid, _, _ in bindings}
    lease = FixtureLease(urls)

    def channel(request, seconds):
        result = capture(request, Driver(changed=request.page_id in changed, ledger=lease.ledger), lease, LIMITS)  # Synthetic stand-in for the proxy record.
        running = [j for j, _, _ in runtime.store.bindings() if runtime.repo.get_job(j).status.value == 'RUNNING']
        runtime.record_browser_audit(running[0], synthetic_browser_audit('ok'))  # Synthetic: the fixture has no real browser.
        return MemoryChannel(result.wire), result.reason, result.cleanup_confirmed

    runtime.run(batch, channel, lease, LIMITS)
    jobs = {}
    for jid, _, _ in bindings:
        _, plan, job = runtime.comparison.plan(jid)
        if job.status.value != 'COMPLETED':
            raise ValueError('synthetic runtime did not complete: ' + jid)
        if plan['kind'] == 'Desktop':
            jobs[plan['page_id']] = jid
    return jobs


def prepare_fixture(output, *, now=None):
    """Generate fresh, synthetic-only M5 workspaces using the existing fixture Driver."""
    output = _new_directory(output)
    config = settings()
    runtimes = create_runtimes(output / 'workspaces', config)
    pending = {p['target_id'] for i, p in enumerate(config['pages']) if i % 3 == 2}
    changed = {p['target_id'] for i, p in enumerate(config['pages']) if i % 2 and p['target_id'] not in pending}
    jobs, approvals = {}, []
    for site_id, runtime in runtimes.items():
        # Same small PNG fixture used by tests/comparison/support.py. No real capture.
        for profile in runtime.store.snapshot('fixture-profiles')['profiles']:
            runtime.workspace.save_profile({'page_id': profile['page_id'], 'kind': profile['kind'],
                'width': 8, 'height': 8, 'expected_revision': profile['revision']})
        baseline_jobs = _run(runtime, set())
        for tid, jid in baseline_jobs.items():
            candidate = runtime.comparison.candidate(jid)
            if tid in pending:
                continue
            record = runtime.comparison.baselines.read_page(limit=1, candidate_id=candidate['candidate_id']).items[0]
            runtime.comparison.baselines.decide(candidate['candidate_id'], decision=BaselineStatus.APPROVED,
                actor='synthetic-human-fixture-only', expected_revision=record.record.revision,
                reviewed_digest=record.record.registered_digest,
                expected_current_version=record.current_version or 0)
            approvals.append({'page_id': tid, 'candidate_id': candidate['candidate_id'],
                              'actor': 'synthetic-human-fixture-only', 'source': 'FIXTURE'})
        for tid, jid in _run(runtime, changed).items():
            jobs[tid] = {'site_id': site_id, 'job_id': jid}
    return {'root': output, 'runtimes': runtimes, 'jobs': jobs, 'approvals': approvals,
            'now': now or datetime.now(timezone.utc), 'config': config}


class _Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links, self.ids = [], set()
        self.references = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        for field in ('href', 'src'):
            if field in attrs:
                self.links.append(attrs[field])
                self.references.append((tag, field, attrs[field], attrs.copy()))


def verify_links(home):
    """Check actual local files and fragment targets, without opening a browser."""
    home = Path(home).resolve()
    from src.noxiworks.home import safe_site_url
    from src.noxiworks.operations import console_links
    # Navigational links are deliberate; remote assets/scripts remain forbidden.
    allowed = {p['url'] for p in settings()['pages']} | set(console_links().values())
    count = 0
    for document in home.glob('*.html'):
        for tag, field, link, attrs in _Links(document.read_text('utf-8')).references:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                if (tag != 'a' or field != 'href' or link not in allowed
                        or safe_site_url(link) is None or attrs.get('target') != '_blank'
                        or not {'noopener', 'noreferrer'} <= set(attrs.get('rel', '').split())):
                    raise ValueError('unsafe/non-navigational external reference refused')
                count += 1
                continue
            target = (document.parent / unquote(parsed.path)).resolve() if parsed.path else document
            if not target.is_relative_to(home) or not target.is_file():
                raise ValueError('missing/escaping local link: ' + link)
            if parsed.fragment and parsed.fragment not in _Links(target.read_text('utf-8')).ids:
                raise ValueError('missing fragment: ' + link)
            count += 1
    return count


def export_fixture(fixture):
    """Verify all S1 sources before comparison/export. Any mismatch rejects the run."""
    root, now = fixture['root'], fixture['now']
    if (root / 'home').exists() or (root / 'home.incomplete').exists():
        raise ValueError('export exists; refusing to overwrite')
    verified = {}
    for site, runtime in fixture['runtimes'].items():
        report = verify_local(runtime.workspace.db_path, runtime.workspace.storage_root)
        if report['status'] != 'CONSISTENT':
            raise ValueError('S1_EVIDENCE_REJECTED: ' + json.dumps(report))
        verified[site] = report
    snapshot = empty_snapshot()
    snapshot.update(source='FIXTURE', sample_notice='M5合成PNG・合成Baseline承認。実サイト撮影なし。品質UNKNOWN。')
    assets, manifests = {}, {}
    for page in fixture['config']['pages']:
        tid = page['target_id']
        binding = fixture['jobs'][tid]
        service = fixture['runtimes'][binding['site_id']].comparison
        change, images = collect_comparison(service, page, binding['job_id'], format_utc(now))
        if change['source_availability'] != 'VERIFIED' or change['quality'] != 'UNKNOWN':
            raise ValueError('unverified comparison refused')
        if change['result']['quality'] != 'UNKNOWN' or change['result']['profile_trust'] != 'UNATTESTED':
            raise ValueError('synthetic evidence must remain unattested/UNKNOWN')
        change['evidence_links'] = {}
        for role, pin in change['manifests'].items():
            origin = pin['origin']
            if origin['page_id'] != tid:
                raise ValueError('cross-page manifest refused')
            file = pin['manifest']
            path = service.workspace.storage_root / file['artifact_ref']
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != file['sha256'] or len(raw) != file['byte_length']:
                raise ValueError('manifest digest mismatch')
            relative = f'evidence/{tid}/{role}.manifest.json'
            manifests[relative] = raw
            change['evidence_links'][role + '_manifest'] = relative
        snapshot['changes'][tid], assets[tid] = change, images
    staging_assets = root / 'assets'
    staging_assets.mkdir(exist_ok=False)
    for tid, files in assets.items():
        directory = staging_assets / tid
        directory.mkdir()
        for name, raw in files.items():
            (directory / name).write_bytes(raw)
    incomplete = root / 'home.incomplete'
    view = build(incomplete, snapshot, now=now, assets=staging_assets)
    for relative, raw in manifests.items():
        with (incomplete / relative).open('xb') as f:
            f.write(raw)
    links = verify_links(incomplete)
    summary = {'source': 'FIXTURE', 'quality': 'UNKNOWN', 'profile_trust': 'PROFILE_UNATTESTED',
        's1_verification': verified, 'synthetic_approvals': fixture['approvals'],
        'pages': [{'page_id': p['target_id'], 'change': p['change']['state'],
                   'quality': p['change']['quality'], 'metrics': p['change'].get('metrics'),
                   'baseline_approved': p['change'].get('baseline_approved'),
                   'evidence_links': p['change']['evidence_links']} for p in view['pages']],
        'verified_local_html_links': links,
        'gates': ['AWS-C LIVE NO-GO', 'C-02 DEFERRED / OPEN', 'LOCAL-ISOLATION NOT VERIFIED',
                  'M5 PROFILE_UNATTESTED', 'formal T01〜T21 UNKNOWN', 'v0.8.1 DRAFT / NOT ADOPTED / NOT FROZEN']}
    (root / 'fixture-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    incomplete.rename(root / 'home')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        fixture = prepare_fixture(args.out)
        export_fixture(fixture)
    except Exception as exc:
        print('FIXTURE export rejected: ' + str(exc), file=sys.stderr)
        return 1
    print(str(fixture['root'] / 'home/index.html'))
    print('FIXTURE / デモ / quality UNKNOWN / no browser, network or AWS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
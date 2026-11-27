"""Write an UNSIGNED monitoring-permit draft for the registered site, with the exact values the harness will check. Offline; never signs.

Run: py -3.15 -B tools/permit_draft.py --data <app data folder> --permit-id <id> --days 7 --max-runs 3 --out <NEW file>
     [--valid-from <UTC, e.g. 2026-11-22T00:00:00Z>] [--cloudflare-evidence]
--cloudflare-evidence fills `ownership` (CLOUDFLARE_ACCOUNT_CONTROL, or DNS_TXT_CHALLENGE for evidence written by tools/dns_ownership.py) from the site's
real/ownership-evidence.json: its values, its check time and its SHA-256, refused here already if permit.ownership_problems would refuse them.
The draft fills in what must be exact (site, target, SHA-256 of the site's targets.json / capture_plan.json, the harness IDENTITY_FILES
hashes, the pinned capture image ID, the browser bundle manifest SHA-256) and leaves `ownership` for the USER to complete after the
ownership check. The USER reviews it, saves it as <site>/real/permit.json and signs it with their own key:
    ssh-keygen -Y sign -n siteproof-monitoring-permit -f <USER key> permit.json
This tool never writes permit.json and never runs `ssh-keygen -Y sign`: a draft grants nothing until the USER signs it.
"""
import argparse
import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.noxiworks import permit as permits
from src.noxiworks import sites


def harness_constants():
    """IDENTITY_FILES and M5_IMAGE read from the harness source (not imported: no side effects)."""
    tree = ast.parse((ROOT / 'tests/runtime/validate_s3t.py').read_text('utf-8'))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and getattr(node.targets[0], 'id', None) in ('IDENTITY_FILES', 'M5_IMAGE'):
            found[node.targets[0].id] = ast.literal_eval(node.value)
    return found['IDENTITY_FILES'], found['M5_IMAGE']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


TO_FILL = {'method': 'TO_FILL: CLOUDFLARE_ACCOUNT_CONTROL | DNS_TXT_CHALLENGE', 'verified_at': 'TO_FILL: UTC time of the check',
           'cloudflare': 'CLOUDFLARE_ACCOUNT_CONTROL only (else delete): {"account_id_sha256", "worker", "workers_dev_subdomain"}',
           'evidence': f'CLOUDFLARE_ACCOUNT_CONTROL only (else delete): {{"evidence_id", "sha256"}} of real/{permits.OWNERSHIP_EVIDENCE}'}


class DraftRefused(ValueError):
    pass


def registered_site(data, site_id=None):
    """-> (site folder, site.json) of the named site, or of the only registered one (several and no name: refused)."""
    try:
        root = sites.resolve(data, site_id)
    except sites.SiteUnknown as exc:
        raise DraftRefused('no registered site in ' + str(data) + '：' + str(exc)) from None
    return root, json.loads((root / 'site.json').read_text('utf-8'))


def cloudflare_ownership(site_root, site, now):
    """The ownership record for CLOUDFLARE_ACCOUNT_CONTROL from the evidence file the USER placed; refused here already if
    permit.ownership_problems would refuse it."""
    f = Path(site_root) / 'real' / permits.OWNERSHIP_EVIDENCE
    if not f.is_file():
        raise DraftRefused('no ' + str(f))
    ev = json.loads(f.read_text('utf-8'))
    ownership = {'method': 'CLOUDFLARE_ACCOUNT_CONTROL', 'verified_at': ev.get('checked_at'),
                 'cloudflare': {k: ev.get(k) for k in ('account_id_sha256', 'worker', 'workers_dev_subdomain')},
                 'evidence': {'evidence_id': ev.get('evidence_id'), 'sha256': sha(f)}}
    problems = permits.ownership_problems({'ownership': ownership}, site['url'].split('/')[2], site_root, now)
    if problems:
        raise DraftRefused('the ownership evidence would be refused: ' + '; '.join(problems))
    return ownership


def ownership_from_evidence(site_root, site, now):
    """The ownership record for whatever evidence the SITE holds (Cloudflare account control, or a DNS TXT challenge), pinned by hash and verified through
    permit.ownership_problems with this site id and host before it is returned. A page folder uses the evidence of its site (it is about the host)."""
    root = sites.site_root_of(site_root)
    f = root / 'real' / permits.OWNERSHIP_EVIDENCE
    if not f.is_file():
        raise DraftRefused('no ' + str(f))
    try:
        ev = json.loads(f.read_text('utf-8'))
        schema = ev.get('schema')
    except (OSError, ValueError, AttributeError):
        raise DraftRefused('the ownership evidence cannot be read: ' + str(f)) from None
    if schema == permits.CF_EVIDENCE_SCHEMA:
        return cloudflare_ownership(root, site, now)
    if schema != permits.DNS_EVIDENCE_SCHEMA:
        raise DraftRefused('the ownership evidence has an unknown format')
    host = site['url'].split('/')[2]
    ownership = {'method': 'DNS_TXT_CHALLENGE', 'verified_at': ev.get('checked_at'),
                 'dns': {'site_id': ev.get('site_id'), 'host': ev.get('host'), 'record_name': ev.get('record_name'), 'token_sha256': ev.get('token_sha256'),
                         'valid_until': ev.get('valid_until')},
                 'evidence': {'evidence_id': ev.get('evidence_id'), 'sha256': sha(f)}}
    problems = permits.ownership_problems({'ownership': ownership, 'site_id': site['site_id']}, host, root, now)
    if problems:
        raise DraftRefused('the ownership evidence would be refused: ' + '; '.join(problems))
    return ownership


def build_draft(site_root, site, *, permit_id, valid_from, valid_until, max_runs, ownership, issued_by='site-owner', now=None):
    """The UNSIGNED permit for the registered site with the exact values the harness will check. Never signs, never writes."""
    from tests.runtime.browser_bundle import stage_browser_bundle
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    files, image = harness_constants()
    with tempfile.TemporaryDirectory(prefix='siteproof-bundle-') as tmp:
        stage_browser_bundle(ROOT, Path(tmp) / 'bundle')  # the same staging the harness does (file copies only)
        bundle = sha(Path(tmp) / 'bundle' / 'MANIFEST.json')
    return {'schema': permits.SCHEMA, 'permit_id': permit_id, 'issued_by': issued_by, 'issued_at': format_utc(now),
            'site': {'site_id': site['site_id'], 'origin': site['origin'], 'host': site['url'].split('/')[2]},
            'target': {'target_id': site['page_id'], 'url': site['url']},
            'target_files': {n: sha(Path(site_root) / n) for n in permits.TARGET_FILES},
            'valid_from': format_utc(valid_from), 'valid_until': format_utc(valid_until), 'max_runs': max_runs,
            'ownership': ownership,
            'identity': {'files': {rel: sha(ROOT / rel) for rel in files}, 'image_id': image, 'bundle_manifest_sha256': bundle},
            'baseline_policy': 'AUTO_INITIAL_THEN_COMPARE'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='site id; required when several sites are registered')
    parser.add_argument('--permit-id', required=True)
    parser.add_argument('--days', type=int, default=7)
    parser.add_argument('--max-runs', type=int, default=3)
    parser.add_argument('--issued-by', default='site-owner', help='the principal of the USER key in trust/allowed_signers')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--valid-from', help='start of the validity window (UTC, second resolution); default: now')
    parser.add_argument('--cloudflare-evidence', action='store_true', help='fill ownership from <site>/real/ownership-evidence.json (Cloudflare or DNS TXT)')
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.name == 'permit.json':
        parser.error('--out must be a NEW file and not permit.json (this tool only drafts)')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = permits.parse_utc(args.valid_from) if args.valid_from else now
    if start is None:
        parser.error('--valid-from must look like 2026-11-22T00:00:00Z')
    try:
        root, site = registered_site(args.data, args.site)
        ownership = ownership_from_evidence(root, site, now) if args.cloudflare_evidence else TO_FILL
        draft = build_draft(root, site, permit_id=args.permit_id, valid_from=start, valid_until=start + timedelta(days=args.days),
                            max_runs=args.max_runs, ownership=ownership, issued_by=args.issued_by, now=now)
    except DraftRefused as exc:
        parser.error(str(exc))
    args.out.write_text(json.dumps(draft, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    todo = '' if args.cloudflare_evidence else 'complete "ownership", '
    print(f'UNSIGNED draft written: {args.out}  ({todo}review, save as permit.json, sign with your own key)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

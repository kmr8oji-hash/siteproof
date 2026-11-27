"""Sign the HTTP-monitoring grant of one registered site -- run by the USER, never by the app. Independent of the image-capture permit.

    py -3.15 -B tools/http_grant.py --data <app data folder> [--site <site id>] [--page <page id>] [--days 30] [--min-interval 300] [--max-requests N]
                                    [--trial] [--key ~/.ssh/siteproof_permit] [--yes] [--pause]

The grant (<site>/http-grant.json + .sig, schema siteproof.http-grant.v2, src/noxiworks/http_authority.py) names ONE host, ONE path, a period, the
shortest interval between any two requests (manual checks included), the total number of requests, its purpose and the ownership record. With several
registered sites --site is required (the tool never picks one). --max-requests defaults to what the period and interval need plus 10 %.
--trial makes a LIMITED_TRIAL grant for a first, bounded measurement: 24 hours (or --hours), at most 20 requests (default 5), 60 s apart or more.
--page signs the grant of a further page (<site>/pages/<page id>/http-grant.json, grant_id http-<page id>-<UTC>): one signature covers one path only, so
every page is confirmed on its own and there is no "all pages" option. The ownership evidence is the site's, also for a page.
Ownership: the evidence file <site>/real/ownership-evidence.json (tools/cf_ownership.py: workers.dev only, read-only Cloudflare check; or
tools/dns_ownership.py: DNS TXT challenge for any public host) must be there, is checked here already and is pinned by hash under the signature; it must
not be older than 90 days. Without it nothing is signed.
It is signed with the USER's own key (OpenSSH SSHSIG, the same trust file <data>/trust/allowed_signers the image permit uses) and verified before
every check. A previous grant is kept in http-grant-history/. It does not start monitoring, does not touch the image permit, monitor.json or
http-monitor.json, and never creates a key or a trust entry (run tools/setup_monitoring.py first for those). Even with a valid grant no real
request is made while HTTP_EXTERNAL_ENABLED is False in http_monitor.py: that switch is for after the network boundary has been measured.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.noxiworks import http_authority, http_monitor, sites
from src.noxiworks import permit as permits
from tools import permit_draft

PRINCIPAL = 'site-owner'
TRIAL_REQUESTS, TRIAL_INTERVAL = 5, 60


class GrantFailed(RuntimeError):
    pass


def say(text):
    print(text, flush=True)


def draft(site_root, site, now, *, seconds, min_interval, max_requests, purpose):
    host, path = http_authority.target(site)  # the same derivation as the monitor's target
    try:
        ownership = permit_draft.ownership_from_evidence(site_root, site, now)  # the SITE's evidence, also for a further page
    except permit_draft.DraftRefused as exc:
        raise GrantFailed('所有権の確認記録がありません（または使えません）。先に tools/cf_ownership.py か tools/dns_ownership.py で確認してください：' + str(exc)) from None
    return {'schema': http_authority.GRANT_SCHEMA, 'grant_id': f"http-{Path(site_root).name}-{now:%Y%m%dT%H%M%SZ}", 'issued_by': PRINCIPAL, 'issued_at': format_utc(now),
            'site_id': site['site_id'], 'host': host, 'port': 443, 'path': path, 'method': 'GET', 'purpose': purpose, 'valid_from': format_utc(now),
            'valid_until': format_utc(now + timedelta(seconds=seconds)), 'min_interval_seconds': min_interval, 'max_requests': max_requests, 'ownership': ownership}


def archive_grant(site_root):
    """Keep the grant that is being replaced (nothing is deleted)."""
    old = site_root / 'http-grant.json'
    if not old.is_file():
        return None
    try:
        name = str(json.loads(old.read_text('utf-8')).get('grant_id'))
    except (OSError, ValueError, AttributeError):
        name = ''
    keep = site_root / 'http-grant-history' / (name if http_authority.GRANT_ID.match(name) else 'unnamed-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    keep.mkdir(parents=True, exist_ok=True)
    for f in (old, old.with_name('http-grant.json.sig')):
        if f.is_file():
            shutil.copy2(f, keep / f.name)
    return keep


def run(args):
    try:
        site_root = sites.resolve_unit(args.data, args.site, args.page)
    except sites.SiteUnknown as exc:
        raise GrantFailed(str(exc)) from None
    site = json.loads((site_root / 'site.json').read_text('utf-8'))
    trust = Path(args.data) / 'trust' / 'allowed_signers'
    pub = args.key.with_name(args.key.name + '.pub')
    if not args.key.is_file() or not pub.is_file():
        raise GrantFailed(f'署名鍵が見つかりません（{args.key}）。新しい鍵は作りません（先に tools/setup_monitoring.py を実行してください）')
    if not trust.is_file() or pub.read_text('utf-8').split()[1] not in trust.read_text('utf-8'):
        raise GrantFailed('この鍵は、このデータフォルダの trust/allowed_signers に登録されていません。何も変更していません')
    if args.trial:
        purpose, seconds, interval, most = 'LIMITED_TRIAL', args.hours * 3600, args.min_interval or TRIAL_INTERVAL, args.max_requests or TRIAL_REQUESTS
    else:
        purpose, seconds, interval = 'MONITOR', args.days * 86400, args.min_interval or 300
        most = args.max_requests or math.ceil(seconds / interval * 1.1)
        if interval not in http_monitor.INTERVALS:
            raise GrantFailed('--min-interval は 300・900・1800・3600 のどれかです')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    grant = draft(site_root, site, now, seconds=seconds, min_interval=interval, max_requests=most, purpose=purpose)
    problems = http_authority.target_problems(site) + [m for _, m in http_authority.grant_problems(grant, site, site_root, now)]
    if problems:  # the app would refuse it: never sign what cannot be used
        raise GrantFailed('この内容では使えません：' + '／'.join(problems))
    say('HTTP監視の許可（署名前）：')
    say(f"   サイト {site['name']}（{site['site_id']}）／ 目的 {'限定試験' if args.trial else '監視'}")
    say(f"   対象 https://{grant['host']}{grant['path']}（GET・443のみ） ／ 期間 {grant['valid_from']} 〜 {grant['valid_until']}")
    say(f"   最短の間隔 {interval} 秒（手動検査を含む） ／ 最大 {most} 回 ／ 所有権 {grant['ownership']['method']}（{grant['ownership']['verified_at']}）")
    say('   これは画像撮影の許可とは別のものです。署名しても監視は始まらず、外部通信も有効にはなりません。')
    if not args.yes and input('   この内容で署名しますか？ [y/N] ').strip().lower() not in ('y', 'yes'):
        raise GrantFailed('署名しませんでした（何も変更していません）')
    pending = site_root / 'http-grant.json.new'
    pending.write_text(json.dumps(grant, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    sig = pending.with_name(pending.name + '.sig')
    sig.unlink(missing_ok=True)
    subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(args.key), str(pending)], check=True, stdout=subprocess.DEVNULL)
    kept = archive_grant(site_root)
    sig.replace(site_root / 'http-grant.json.sig')
    pending.replace(site_root / 'http-grant.json')
    permits.verify_signature(site_root / 'http-grant.json', trust)
    say('署名しました：' + str(site_root / 'http-grant.json') + (f'（以前の許可は {kept} に保存）' if kept else ''))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='site id; required when several sites are registered')
    parser.add_argument('--page', help='page id (<site id>-p2 .. -p5) of a further page of the site; each page is confirmed and signed on its own')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--hours', type=int, default=24, help='--trial only')
    parser.add_argument('--min-interval', type=int)
    parser.add_argument('--max-requests', type=int)
    parser.add_argument('--trial', action='store_true', help='a LIMITED_TRIAL grant (at most 24 h and 20 requests)')
    parser.add_argument('--key', type=Path, default=Path.home() / '.ssh' / 'siteproof_permit')
    parser.add_argument('--yes', action='store_true', help='sign without asking (the USER has reviewed the values)')
    parser.add_argument('--pause', action='store_true', help='wait for Enter before closing (the window the app opens)')
    args = parser.parse_args(argv)
    if not 1 <= args.days <= 366 or not 1 <= args.hours <= 24:
        parser.error('--days must be 1..366, --hours 1..24')
    if any(v is not None and v < 1 for v in (args.min_interval, args.max_requests)):
        parser.error('--min-interval / --max-requests must be positive')
    try:
        code = run(args)
    except (GrantFailed, permits.PermitRefused) as exc:
        say('中止しました：' + str(exc))
        code = 1
    if args.pause:
        input('Enterキーで閉じます。')
    return code


if __name__ == '__main__':
    raise SystemExit(main())

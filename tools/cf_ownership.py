"""CLOUDFLARE_ACCOUNT_CONTROL evidence for a workers.dev site, from a READ-ONLY Cloudflare API check with the USER's own Wrangler login.

Run by the USER (directly or through tools/setup_monitoring.py), never by the app:
    py -3.15 -B tools/cf_ownership.py --data <app data folder> [--wrangler <path to wrangler.js or wrangler.cmd>]
Only HTTP GET to https://api.cloudflare.com/client/v4 on a fixed path allowlist. The OAuth token comes from `wrangler auth token --json`,
stays in this process's memory and is never printed or written. Worker code is never downloaded and nothing on Cloudflare is changed.
The account is found from the host name itself: <worker>.<subdomain>.workers.dev names exactly one account's workers.dev subdomain.
Writes <site>/real/ownership-evidence.json (the account ID only as SHA-256) and keeps the raw API answers (with the full account ID)
in <site>/real/ownership-raw/<UTC time>/ -- private, next to the site's other records. A check that does not confirm every value
writes no evidence: nothing is guessed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import permit as permits

API = 'https://api.cloudflare.com/client/v4'
ACCOUNT = r'[0-9a-f]{32}'


class OwnershipCheckFailed(RuntimeError):
    pass


def utc_text():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def split_host(host):
    m = re.fullmatch(rf'({permits.DNS_LABEL})\.({permits.DNS_LABEL})\.workers\.dev', host or '')
    if not m:
        raise OwnershipCheckFailed(f'{host} は <Worker名>.<サブドメイン>.workers.dev ではありません（CLOUDFLARE_ACCOUNT_CONTROL は workers.dev のホストだけです）')
    return m[1], m[2]


def find_wrangler(explicit=None):
    """-> argv prefix running wrangler. An explicit path, else wrangler on PATH."""
    if explicit:
        p = Path(explicit)
        return ['node', str(p)] if p.suffix == '.js' else [str(p)]
    found = shutil.which('wrangler')
    if not found and sys.stdin is not None and sys.stdin.isatty():  # the setup window: ask instead of failing
        typed = input('wrangler が見つかりません。wrangler.cmd か wrangler.js の場所を入力してください（空欄で中止）：').strip().strip('"')
        if typed and Path(typed).is_file():
            return find_wrangler(typed)
    if not found:
        raise OwnershipCheckFailed('wrangler が見つかりません（--wrangler で wrangler.js か wrangler.cmd を指定してください。ログイン済みであること）')
    return [found]


def wrangler_token(wrangler):
    env = {**os.environ, 'WRANGLER_SEND_METRICS': 'false'}
    p = subprocess.run(wrangler + ['auth', 'token', '--json'], env=env, capture_output=True, text=True, timeout=120)
    if p.returncode != 0 or '{' not in p.stdout:
        raise OwnershipCheckFailed('wrangler auth token に失敗しました（wrangler login が必要かもしれません）')
    data = json.loads(p.stdout[p.stdout.index('{'):])
    token = data.get('token') or data.get('value')
    if not token:
        raise OwnershipCheckFailed('wrangler auth token の結果にトークンがありません')
    return token


class ReadOnlyApi:
    """GET only, api.cloudflare.com only, allowlisted paths only; every request logged (without the token)."""

    def __init__(self, token, worker, opener=None):
        self.token, self.opener, self.log = token, opener, []
        self.allowed = [r'/accounts', rf'/accounts/{ACCOUNT}/workers/subdomain', rf'/accounts/{ACCOUNT}/workers/scripts',
                        rf'/accounts/{ACCOUNT}/workers/scripts/{re.escape(worker)}/subdomain', rf'/accounts/{ACCOUNT}/workers/domains']

    def get(self, path, query=''):
        if not any(re.fullmatch(a, path) for a in self.allowed):
            raise OwnershipCheckFailed('許可していないAPIパスです: ' + path)
        req = urllib.request.Request(API + path + ('?' + query if query else ''), method='GET',
                                     headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'})
        if req.get_method() != 'GET' or req.host != 'api.cloudflare.com':
            raise OwnershipCheckFailed('READ-ONLY以外の要求です')
        at = utc_text()
        try:
            with (self.opener or urllib.request.urlopen)(req, timeout=30) as r:  # looked up per call (tests replace it)
                status, body = r.status, json.loads(r.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            status, body = e.code, json.loads(e.read().decode('utf-8') or '{}')
        self.log.append({'at': at, 'method': 'GET', 'path': path, 'query': query, 'status': status})
        return status, body


def check(api, host):
    """-> (evidence dict, raw answers). Raises OwnershipCheckFailed unless every value is confirmed by the API."""
    worker, sub = split_host(host)
    checked_at = utc_text()
    raw = {}
    s, accounts = api.get('/accounts', 'per_page=50')
    raw['accounts'] = {'status': s, 'body': accounts}
    if s != 200:
        raise OwnershipCheckFailed(f'アカウントの一覧を取得できません（HTTP {s}）')
    owner = None
    for acct in [a.get('id') for a in accounts.get('result') or [] if re.fullmatch(ACCOUNT, str(a.get('id')))]:
        s, answer = api.get(f'/accounts/{acct}/workers/subdomain')
        raw[f'subdomain-{acct}'] = {'status': s, 'body': answer}
        if s == 200 and (answer.get('result') or {}).get('subdomain') == sub:
            owner = acct
            break
    if owner is None:
        raise OwnershipCheckFailed(f'workers.devサブドメイン {sub} を持つアカウントが、このログインでは見つかりません')
    s, scripts = api.get(f'/accounts/{owner}/workers/scripts')
    raw['scripts'] = {'status': s, 'body': scripts}
    names = [x.get('id') for x in scripts.get('result') or []] if s == 200 else []
    if worker not in names:
        raise OwnershipCheckFailed(f'Worker {worker} がアカウントにありません')
    s, script_sub = api.get(f'/accounts/{owner}/workers/scripts/{worker}/subdomain')
    raw['script-subdomain'] = {'status': s, 'body': script_sub}
    enabled = (script_sub.get('result') or {}).get('enabled') if s == 200 else None
    if enabled is not True:
        raise OwnershipCheckFailed(f'Worker {worker} はworkers.devで公開されていません（または確認できません）')
    s, domains = api.get(f'/accounts/{owner}/workers/domains', 'service=' + worker)
    raw['custom-domains'] = {'status': s, 'body': domains}
    evidence = {'schema': permits.CF_EVIDENCE_SCHEMA, 'evidence_id': 'cf-' + checked_at.replace('-', '').replace(':', '').lower(),
                'method': 'CLOUDFLARE_ACCOUNT_CONTROL', 'checked_at': checked_at,
                'account_id_sha256': hashlib.sha256(owner.encode()).hexdigest(), 'worker': worker, 'workers_dev_subdomain': sub, 'host': host,
                'checks': {'worker_in_account': True, 'account_workers_dev_subdomain': sub, 'script_workers_dev_enabled': True,
                           'custom_domains': [d.get('hostname') for d in domains.get('result') or []] if s == 200 else None},
                'sources': ['Cloudflare API v4, HTTP GET only, the USER\'s Wrangler login'] + [f"GET {e['path'].replace(owner, owner[:4] + '…' + owner[-2:])} {e['status']}" for e in api.log]}
    return evidence, raw


def write(site_root, evidence, raw, log):
    real = Path(site_root) / 'real'
    keep = real / 'ownership-raw' / evidence['checked_at'].replace(':', '')
    keep.mkdir(parents=True, exist_ok=False)
    for name, body in {**raw, 'REQUEST-LOG': log}.items():
        (keep / (name + '.json')).write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    f = real / permits.OWNERSHIP_EVIDENCE
    f.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return f


def run(site_root, host, wrangler=None):
    api = ReadOnlyApi(wrangler_token(find_wrangler(wrangler)), split_host(host)[0])
    evidence, raw = check(api, host)
    return write(site_root, evidence, raw, api.log)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='site id; required when several sites are registered')
    parser.add_argument('--wrangler')
    args = parser.parse_args(argv)
    from src.noxiworks import sites
    try:
        root = sites.resolve(args.data, args.site)
    except sites.SiteUnknown as exc:
        parser.error(str(exc))
    host = json.loads((root / 'site.json').read_text('utf-8'))['url'].split('/')[2]
    try:
        f = run(root, host, args.wrangler)
    except OwnershipCheckFailed as exc:
        print('所有権を確認できませんでした：' + str(exc))
        return 1
    print('所有権の証拠を書きました：' + str(f))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

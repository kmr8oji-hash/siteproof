"""Ownership of a domain by DNS TXT challenge -- run by the USER, never by the app's schedulers. A communication of its own, apart from monitoring.

    py -3.15 -B tools/dns_ownership.py issue|check|recheck|status --data <app data folder> [--site <site id>] [--server <DNS server IP> ...up to 3] [--pause]

issue    makes (or shows again) the one-time record to publish: name `_siteproof-challenge.<host>`, value `siteproof-site=<site id>;token=<token>`, valid 7 days.
check    asks DNS for that record (the system resolver, and each --server) and writes <site>/real/ownership-evidence.json only when EVERY answer holds exactly the value.
recheck  asks again for the record of existing evidence; only a record every lookup reports missing withdraws it (a timeout never does).
status   shows what the app shows. No lookup.
check / recheck are one DNS TXT question each (PowerShell Resolve-DnsName, 10 s, the fixed record name only) and are OFF while OWNERSHIP_DNS_ENABLED is False:
they refuse before any lookup. That switch is for after the USER has approved DNS lookups. This tool never reads a grant, never turns monitoring on, never signs and
never starts anything: the evidence it writes changes nothing until the USER signs a permit or grant that names it (tools/setup_monitoring.py / tools/http_grant.py).
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import domain_ownership as dom
from src.noxiworks import permit as permits
from src.noxiworks import sites

OWNERSHIP_DNS_ENABLED = False  # kill switch: no DNS lookup is made while this is False (issue and status never look anything up)
TIMEOUT_SECONDS = 10
MAX_OUTPUT = 64 * 1024
MAX_SERVERS = 3
RECORD = re.compile(re.escape(permits.DNS_RECORD_PREFIX) + rf'(?:{permits.DNS_LABEL}\.)+{permits.DNS_LABEL}\Z')
SCRIPT = ("try { $r = @(Resolve-DnsName -Name {name} -Type TXT -DnsOnly -NoHostsFile{server} -ErrorAction Stop); $o = @(); "
          "foreach ($x in $r) { if ($x.Type -eq 'TXT') { $o += (-join $x.Strings) } }; ConvertTo-Json -InputObject @($o) -Compress } "
          "catch { Write-Output ('ERR:' + $_.FullyQualifiedErrorId); exit 3 }")
DEFINITE_MISSING = ('DNS_ERROR_RCODE_NAME_ERROR', 'DNS_INFO_NO_RECORDS', 'DNS_ERROR_RCODE_NXRRSET')


class Disabled(RuntimeError):
    pass


def say(text):
    print(text, flush=True)


def command(record, server=None):
    """The one command line a lookup runs. The record name and the server are validated here, so nothing else can be asked."""
    if len(record) > 253 or not RECORD.fullmatch(record):
        raise dom.LookupFailed('ERROR', 'この名前は問い合わせません')
    extra = ''
    if server is not None:
        try:
            extra = ' -Server ' + str(ipaddress.ip_address(server))
        except ValueError:
            raise dom.LookupFailed('ERROR', 'DNSサーバはIPアドレスで指定してください') from None
    return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', SCRIPT.replace('{name}', record).replace('{server}', extra)]


def run_process(argv, timeout):
    """-> (exit code, stdout text). The only place a process is started."""
    p = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return p.returncode, p.stdout[:MAX_OUTPUT + 1].decode('utf-8', 'replace')


def lookup_txt(record, server=None, runner=run_process):
    """-> the TXT strings of one record (each record's strings joined). Raises dom.LookupFailed (TIMEOUT | NXDOMAIN | ERROR)."""
    argv = command(record, server)
    try:
        code, out = runner(argv, TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise dom.LookupFailed('TIMEOUT') from None
    except OSError:
        raise dom.LookupFailed('ERROR', 'PowerShellを起動できません') from None
    if len(out) > MAX_OUTPUT:
        raise dom.LookupFailed('ERROR', '答えが大きすぎます')
    out = out.strip()
    if code != 0 or out.startswith('ERR:'):
        raise dom.LookupFailed('NXDOMAIN' if any(m in out for m in DEFINITE_MISSING) else 'TIMEOUT' if 'TIMEOUT' in out.upper() else 'ERROR')
    try:
        found = json.loads(out or '[]')
    except ValueError:
        raise dom.LookupFailed('ERROR', '答えを読み取れません') from None
    if isinstance(found, str):
        found = [found]
    if not isinstance(found, list) or not all(isinstance(a, str) for a in found):
        raise dom.LookupFailed('ERROR', '答えの形式が不正です')
    return found


def lookups_for(servers, runner=run_process):
    """The system resolver first, then each named server: every one of them must answer."""
    return [('system', lambda record: lookup_txt(record, None, runner))] + [(f'dns:{s}', lambda record, s=s: lookup_txt(record, s, runner)) for s in servers]


def describe(state):
    say(f"   ホスト {state['host']} ／ 方式 {state['method'] or '-'} ／ 状態 {state['status']}")
    if state['valid_until']:
        say(f"   確認 {state['checked_at']} ／ 有効期限 {state['valid_until']}（あと{state['days_left']}日）")
    say('   ' + state['guidance'])


def run(args, runner=run_process, now=None):
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    try:
        root = sites.resolve(args.data, args.site)
    except sites.SiteUnknown as exc:
        raise dom.OwnershipRefused(str(exc)) from None
    if args.action == 'status':
        describe(dom.state(root, now))
        return 0
    if args.action == 'issue':
        c = dom.issue(root, now)
        say(f"DNSに、次のTXTレコードを登録してください（{c['host']}・{c['expires_at']} まで有効）：")
        say(f"   名前  {c['record_name']}")
        say(f"   値    {c['record_value']}")
        say('登録して反映されたら、tools/dns_ownership.py check で確認します（この画面では確認しません）。')
        return 0
    if not OWNERSHIP_DNS_ENABLED:  # before any lookup
        raise Disabled('DNSの照会は、承認されるまで無効です（OWNERSHIP_DNS_ENABLED = False）。何も問い合わせていません')
    say('これはSiteProofの監視とは別の、1回限りのDNS照会（TXT）です。許可は読まず、監視も開始しません。')
    lookups = lookups_for(args.server, runner)
    if args.action == 'check':
        ev = dom.check(root, now, lookups)
        say(f"所有権を確認しました：{ev['host']}（{ev['checked_at']}・{ev['valid_until']} まで）。署名済みの許可に入れるには、監視設定の更新が必要です。")
        return 0
    done = dom.recheck(root, now, lookups)
    say({'OK': '記録は今も見つかりました（有効期限は延びません）。', 'REVOKED': 'DNSの記録がどの照会でも見つかりませんでした。所有権の確認を取り消しました。',
         'UNKNOWN': '照会に失敗したものがあり、判断しませんでした（取り消しません）。', 'DISAGREE': '照会の答えが食い違いました。判断しませんでした（取り消しません）。'}[done['status']])
    for d in done['detail']:
        say(f"   {d['resolver']}：{d['result']}")
    return 0 if done['status'] == 'OK' else 1


def main(argv=None, runner=run_process, now=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('issue', 'check', 'recheck', 'status'))
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='site id; required when several sites are registered')
    parser.add_argument('--server', action='append', default=[], help=f'a DNS server IP to ask as well (up to {MAX_SERVERS})')
    parser.add_argument('--pause', action='store_true', help='wait for Enter before closing (the window the app opens)')
    args = parser.parse_args(argv)
    if len(args.server) > MAX_SERVERS:
        parser.error(f'--server: at most {MAX_SERVERS}')
    for s in args.server:
        try:
            ipaddress.ip_address(s)
        except ValueError:
            parser.error('--server must be an IP address')
    try:
        code = run(args, runner, now)
    except (dom.OwnershipRefused, Disabled) as exc:
        say('中止しました：' + str(exc))
        code = 1
    if args.pause:
        input('Enterキーで閉じます。')
    return code


if __name__ == '__main__':
    raise SystemExit(main())

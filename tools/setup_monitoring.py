"""One-time setup (and renewal) of REAL monitoring for one registered site -- run by the USER, never by the app.

    py -3.15 -B tools/setup_monitoring.py --data <app data folder> [--site <site id>] [--url https://my-worker.my-sub.workers.dev/ --name "My site"]
                                          [--ownership cloudflare|dns] [--max-runs N] [--manual-only]
                                          [--days 30] [--key ~/.ssh/siteproof_permit] [--no-passphrase] [--yes]

What it does, in order (each step is skipped when already done):
  1. registers the site in the data folder when --url is given and none is registered (files only, as the app's registration)
  2. creates the USER's signing key if it does not exist (OpenSSH Ed25519; ssh-keygen asks for the passphrase unless --no-passphrase)
  3. writes <data>/trust/allowed_signers for that key (never replaces a different trusted key)
  4. records the ownership check: `cloudflare` runs the READ-ONLY Cloudflare check (tools/cf_ownership.py) for a workers.dev host.
     `dns` takes the DNS TXT challenge evidence tools/dns_ownership.py wrote (any public host; this tool asks DNS nothing); no method given reuses the
     evidence already there (renewal). well-known-file / dns-txt are NOT supported (nothing can verify them, so a permit made with one could never
     capture): they are refused first of all, before any key, trust file, status, permit or permit history is touched
  5. drafts the permit (tools/permit_draft.build_draft): now .. now + days, enough runs for the site's interval plus retries (or exactly
     --max-runs N, N >= 1, checked before anything is touched); on renewal the previous permit is kept in real/permit-history/ and its
     Baseline is carried over by name and hash (the USER signs that too)
  6. shows the permit and signs it with the USER's key (`ssh-keygen -Y sign`, asking first unless --yes). With --manual-only the
     automatic monitoring is switched OFF (enabled false, next_due_at untouched) after the USER's confirmation and BEFORE the new
     permit is put in place, and stays off: nothing starts by itself, the app's "今すぐ再検査" (or one site_monitor pass) is the only
     way to capture. Refused up front, changing nothing, while an inspection is running (monitor.lock)
  7. prints the five readiness checks the app will see
The authorization boundary is unchanged: the app (src/) holds no key and cannot sign; this tool runs in the USER's own shell with the
USER's own key, and the harness and the app verify the signature, the ownership evidence and every pin exactly as before.
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
from src.noxiworks import permit as permits
from src.noxiworks import sites
from src.noxiworks.real_capture import UNSUPPORTED_OWNERSHIP, UNSUPPORTED_OWNERSHIP_MESSAGE
from tools import permit_draft

PRINCIPAL = 'site-owner'
SETUP_STATUS = 'setup-status.json'  # <site>/setup-status.json: what the app's HOME shows while this window is open (no secret in it)


def write_status(site_root, state, message):
    """RUNNING / DONE / NOT_READY / FAILED, for the app's screen. Best effort: a status that cannot be written never stops the setup."""
    try:
        f = Path(site_root) / SETUP_STATUS
        f.write_text(json.dumps({'state': state, 'message': message, 'at': format_utc(datetime.now(timezone.utc).replace(microsecond=0))},
                                ensure_ascii=False) + '\n', encoding='utf-8')
    except OSError:
        pass


class SetupFailed(RuntimeError):
    pass


def say(text):
    print(text, flush=True)


def ensure_site(data, url, name, interval, site_id=None):
    if site_id or sites.folders(data):  # something is registered: exactly the named site, or the only one (never a guess)
        try:
            return permit_draft.registered_site(data, site_id)
        except permit_draft.DraftRefused as exc:
            raise SetupFailed(str(exc)) from None
    if not url:
        raise SetupFailed('サイトが登録されていません（--url で登録するか、アプリで登録してください）')
    from src.noxiworks.app import App
    app = App(Path(data))
    app.setup()
    app.site_action('register', {'name': name or url.split('/')[2], 'url': url, 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True,
                                 'interval_seconds': interval})
    say(f'1. サイトを登録しました：{url}')
    return permit_draft.registered_site(data)


def ensure_key(key, no_passphrase):
    if key.is_file() and key.with_name(key.name + '.pub').is_file():
        return False
    key.parent.mkdir(parents=True, exist_ok=True)
    args = [permits.ssh_keygen(), '-q', '-t', 'ed25519', '-C', 'siteproof-permit', '-f', str(key)]
    subprocess.run(args + (['-N', ''] if no_passphrase else []), check=True)
    return True


def ensure_trust(data, key):
    pub = key.with_name(key.name + '.pub').read_text('utf-8').split()
    line = f'{PRINCIPAL} namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}'
    trust = Path(data) / 'trust' / 'allowed_signers'
    if trust.is_file():
        if any(l.split()[-1:] == [pub[1]] for l in trust.read_text('utf-8').splitlines() if l.strip()):
            return False
        raise SetupFailed(f'{trust} には別の鍵が登録されています（置き換えません。不要なら利用者が自分で削除してください）')
    trust.parent.mkdir(parents=True, exist_ok=True)
    trust.write_text(line + '\n', encoding='ascii')
    return True


def refuse_unsupported_ownership(method):
    """Raised before anything is written: an unsupported method must not start a setup that replaces a working permit."""
    if method in UNSUPPORTED_OWNERSHIP:
        raise SetupFailed(UNSUPPORTED_OWNERSHIP_MESSAGE)


def ownership_record(site_root, site, method, wrangler, now):
    refuse_unsupported_ownership(method)
    if method == 'cloudflare':
        from tools import cf_ownership
        try:
            f = cf_ownership.run(site_root, site['url'].split('/')[2], wrangler)
        except cf_ownership.OwnershipCheckFailed as exc:
            raise SetupFailed('所有権を確認できませんでした：' + str(exc)) from None
        say(f'4. Cloudflareで所有権を確認しました（READ-ONLY）：{f}')
        return permit_draft.cloudflare_ownership(site_root, site, datetime.now(timezone.utc))  # checked just now, after `now`
    f = Path(site_root) / 'real' / permits.OWNERSHIP_EVIDENCE
    if method == 'dns':  # the evidence tools/dns_ownership.py wrote: no lookup here
        try:
            schema = json.loads(f.read_text('utf-8')).get('schema')
        except (OSError, ValueError, AttributeError):
            schema = None
        if schema != permits.DNS_EVIDENCE_SCHEMA:
            raise SetupFailed('DNSの所有権確認の証拠がありません。先に tools/dns_ownership.py で issue → DNSに登録 → check を行ってください（この画面ではDNSを照会しません）')
        say(f'4. DNSの所有権確認の記録を使います（照会はしません）：{f}')
        return permit_draft.ownership_from_evidence(site_root, site, now)
    if f.is_file():  # no method given: reuse the evidence that is already there (renewal), whatever its kind
        return permit_draft.ownership_from_evidence(site_root, site, now)
    raise SetupFailed('--ownership cloudflare（workers.devのサイト）か、tools/dns_ownership.py で確認してから --ownership dns を指定してください')


def positive_int(text):
    """argparse type for --max-runs: a whole number >= 1 (a bool, a float, 0 or a negative number is refused before anything is touched)."""
    try:
        value = int(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('1以上の整数で指定してください（例 --max-runs 1）') from None
    if str(value) != str(text).strip().lstrip('+') or value < 1:
        raise argparse.ArgumentTypeError('1以上の整数で指定してください（例 --max-runs 1）')
    return value


def max_runs_for(site_root, days, override=None):
    if override is not None:
        return override
    settings = json.loads((Path(site_root) / 'monitor.json').read_text('utf-8'))
    planned = math.ceil(days * 86400 / settings['interval_seconds'])
    return planned + max(3, planned // 4)  # manual re-inspections and failed runs count too (fail-closed)


def carryover(real, old):
    """The Baseline made under the previous permit, named by permit id and registry hash (signed as part of the new permit)."""
    origin = real / 'registry-origin.json'
    if old is None or not origin.is_file():
        return None
    o = json.loads(origin.read_text('utf-8'))
    if o.get('permit_id') not in (old.get('permit_id'), (old.get('baseline_carryover') or {}).get('permit_id')):
        return None
    return {'permit_id': o['permit_id'], 'registry_export_sha256': o['registry_export_sha256']}


def archive_permit(real, old):
    keep = real / 'permit-history' / str(old.get('permit_id') or 'unnamed')
    keep.mkdir(parents=True, exist_ok=True)
    for name in ('permit.json', 'permit.json.sig'):
        if (real / name).is_file():
            shutil.copy2(real / name, keep / name)
    return keep


def readiness(site_root, now, docker_found=None):
    """The same five checks the app shows before every real capture."""
    from src.noxiworks.real_capture import RealCapture
    from src.noxiworks.site_workflow import Site
    return RealCapture(Site(site_root), docker_found=docker_found).readiness(now)


def refuse_while_running(site_root):
    """--manual-only promises that nothing starts by itself once the permit is in place: an inspection that is already running (or whose
    lock is still held) cannot be fenced off by switching monitoring off, so the setup stops and says so instead of going on."""
    from src.noxiworks.site_monitor import Monitor
    from src.noxiworks.site_workflow import Site
    if Monitor(Site(site_root)).running():
        raise SetupFailed('検査が実行中です（monitor.lock があります）。--manual-only は、実行中の検査がない状態でしか安全に切り替えられません。'
                          '検査が終わってから、もう一度実行してください。許可・鍵・監視設定は何も変更していません')


def switch_monitoring_off(site_root):
    """Monitoring off, before the new permit exists. Only `enabled` changes: next_due_at and the rest of monitor.json stay as they were."""
    from src.noxiworks.site_monitor import Monitor
    from src.noxiworks.site_workflow import Site
    monitor = Monitor(Site(site_root))
    refuse_while_running(site_root)
    with monitor.settings_lock():
        settings = monitor.load()
        settings['enabled'] = False
        monitor.save(settings)


def setup(args):
    refuse_unsupported_ownership(args.ownership)  # first: no registration, key, trust file, status or permit is touched
    now = datetime.now(timezone.utc).replace(microsecond=0)
    site_root, site = ensure_site(args.data, args.url, args.name, args.interval, args.site)
    args.site_root = site_root
    if args.manual_only:
        refuse_while_running(site_root)  # before the key, the trust file, the status or the permit are touched
    write_status(site_root, 'RUNNING', 'セットアップの画面で操作しています')
    real = site_root / 'real'
    real.mkdir(exist_ok=True)
    say(f'1. 対象：{site["url"]}（{site["site_id"]}）')
    created = ensure_key(args.key, args.no_passphrase)
    say(f'2. 署名鍵：{args.key}（{"作成しました" if created else "既存の鍵を使います"}）')
    trusted = ensure_trust(args.data, args.key)
    say(f'3. 信頼する公開鍵：{"登録しました" if trusted else "登録済み"}')
    ownership = ownership_record(site_root, site, args.ownership, args.wrangler, now)
    old = None
    if (real / 'permit.json').is_file():
        try:
            old = permits.verify_signature(real / 'permit.json', Path(args.data) / 'trust' / 'allowed_signers')
        except permits.PermitRefused:
            old = json.loads((real / 'permit.json').read_text('utf-8'))
    permit_id = f"{site['site_id']}-{now:%Y%m%dT%H%M%SZ}"
    draft = permit_draft.build_draft(site_root, site, permit_id=permit_id, valid_from=now, valid_until=now + timedelta(days=args.days),
                                     max_runs=max_runs_for(site_root, args.days, args.max_runs), ownership=ownership, issued_by=PRINCIPAL, now=now)
    carried = carryover(real, old)
    if carried:
        draft['baseline_carryover'] = carried
    say('5. 監視許可（署名前）：')
    say(f"   対象 {draft['target']['url']} ／ 期間 {draft['valid_from']} 〜 {draft['valid_until']} ／ 最大 {draft['max_runs']} 回"
        + ('（指定）' if args.max_runs is not None else '（期間と検査間隔から自動計算）'))
    if args.manual_only:
        say('   自動監視：開始しません（手動撮影のみ。署名の前に自動監視を停止します。撮影は画面の「今すぐ再検査」で行います）')
    say(f"   所有権 {ownership['method']}（{ownership['verified_at']}）／ 撮影イメージ {draft['identity']['image_id'][:19]}…"
        + (f" ／ Baselineを引き継ぐ（{carried['permit_id']}）" if carried else ''))
    if not args.yes and input('   この内容で署名しますか？ [y/N] ').strip().lower() not in ('y', 'yes'):
        raise SetupFailed('署名しませんでした（何も変更していません）')
    if args.manual_only:
        switch_monitoring_off(site_root)  # off BEFORE the new permit is in place, so nothing can start by itself in between
        say('   自動監視を停止しました（手動撮影のみ）')
    if old is not None:
        say(f'   以前の許可を保存しました：{archive_permit(real, old)}')
    pending = real / 'permit.json.new'
    pending.write_text(json.dumps(draft, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    sig = pending.with_name(pending.name + '.sig')
    sig.unlink(missing_ok=True)
    subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(args.key), str(pending)], check=True,
                   stdout=subprocess.DEVNULL)
    sig.replace(real / 'permit.json.sig')
    pending.replace(real / 'permit.json')
    permits.verify_signature(real / 'permit.json', Path(args.data) / 'trust' / 'allowed_signers')
    say('6. 署名しました：' + str(real / 'permit.json'))
    from src.noxiworks.site_monitor import Monitor
    from src.noxiworks.site_workflow import Site
    monitor = Monitor(Site(site_root))
    if not args.manual_only:
        with monitor.settings_lock():  # the next inspection is due now: the app (or the background task) starts it on its next tick
            settings = monitor.load()
            settings.update(enabled=True, next_due_at=format_utc(now))
            settings.pop('paused_reason', None)
            monitor.save(settings)
    checks = readiness(site_root, datetime.now(timezone.utc).replace(microsecond=0))  # now, not the start: the ownership check ran since
    say('7. 実サイト監視の準備：')
    for c in checks:
        say(f"   {'OK ' if c['ok'] else 'NG '} {c['label']}：{c['state']}")
    ok = all(c['ok'] for c in checks)
    write_status(site_root, 'DONE' if ok else 'NOT_READY', '準備ができました' if ok else '、'.join(c['label'] for c in checks if not c['ok']) + ' が整っていません')
    return ok


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='site id; required when several sites are registered')
    parser.add_argument('--url')
    parser.add_argument('--name')
    parser.add_argument('--interval', type=int, default=86400, help='inspection interval in seconds when registering (default 24 h)')
    parser.add_argument('--ownership', choices=('cloudflare', 'dns') + UNSUPPORTED_OWNERSHIP,
                        help='cloudflare (workers.dev) or dns (the evidence tools/dns_ownership.py wrote; no lookup here); none: reuse the evidence that is there; '
                             'the others are listed so that they are refused with a clear message')
    parser.add_argument('--wrangler')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--max-runs', type=positive_int, help='the permit allows exactly this many captures (whole number >= 1); default: computed from --days and the interval')
    parser.add_argument('--manual-only', action='store_true',
                        help='do not start automatic monitoring: it is switched off before signing and stays off (capture with 今すぐ再検査)')
    parser.add_argument('--key', type=Path, default=Path.home() / '.ssh' / 'siteproof_permit')
    parser.add_argument('--no-passphrase', action='store_true')
    parser.add_argument('--yes', action='store_true', help='sign without asking (the USER has reviewed the values)')
    parser.add_argument('--pause', action='store_true', help='wait for Enter before closing (the window the app opens)')
    args = parser.parse_args(argv)
    if not 1 <= args.days <= 366:
        parser.error('--days must be 1..366')
    try:
        ready = setup(args)
    except (SetupFailed, permit_draft.DraftRefused, permits.PermitRefused) as exc:
        say('中止しました：' + str(exc))
        if getattr(args, 'site_root', None):
            write_status(args.site_root, 'FAILED', str(exc)[:300])
        ready = None
    if ready is not None:
        say('準備ができました。SiteProofの画面に戻ってください（次の検査から実サイトを撮影します）。' if ready
            else '準備が整っていない項目があります（上の NG を確認してください）。')
    if args.pause:
        input('Enterキーで閉じます。')
    return 1 if ready is None else 0 if ready else 2


if __name__ == '__main__':
    raise SystemExit(main())

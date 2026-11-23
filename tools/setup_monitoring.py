"""One-time setup (and renewal) of REAL monitoring for the registered site -- run by the USER, never by the app.

    py -3.15 -B tools/setup_monitoring.py --data <app data folder> [--url https://my-worker.my-sub.workers.dev/ --name "My site"]
                                          [--ownership cloudflare | well-known-file --verified-at <UTC> | dns-txt --verified-at <UTC>]
                                          [--days 30] [--key ~/.ssh/siteproof_permit] [--no-passphrase] [--yes]

What it does, in order (each step is skipped when already done):
  1. registers the site in the data folder when --url is given and none is registered (files only, as the app's registration)
  2. creates the USER's signing key if it does not exist (OpenSSH Ed25519; ssh-keygen asks for the passphrase unless --no-passphrase)
  3. writes <data>/trust/allowed_signers for that key (never replaces a different trusted key)
  4. records the ownership check: `cloudflare` runs the READ-ONLY Cloudflare check (tools/cf_ownership.py) for a workers.dev host;
     well-known-file / dns-txt record the time the USER checked it themselves (--verified-at)
  5. drafts the permit (tools/permit_draft.build_draft): now .. now + days, enough runs for the site's interval plus retries; on renewal
     the previous permit is kept in real/permit-history/ and its Baseline is carried over by name and hash (the USER signs that too)
  6. shows the permit and signs it with the USER's key (`ssh-keygen -Y sign`, asking first unless --yes)
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


def ensure_site(data, url, name, interval):
    try:
        return permit_draft.registered_site(data)
    except permit_draft.DraftRefused:
        if not url:
            raise SetupFailed('サイトが登録されていません（--url で登録するか、アプリで登録してください）') from None
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


def ownership_record(site_root, site, method, verified_at, wrangler, now):
    if method == 'cloudflare':
        from tools import cf_ownership
        try:
            f = cf_ownership.run(site_root, site['url'].split('/')[2], wrangler)
        except cf_ownership.OwnershipCheckFailed as exc:
            raise SetupFailed('所有権を確認できませんでした：' + str(exc)) from None
        say(f'4. Cloudflareで所有権を確認しました（READ-ONLY）：{f}')
        return permit_draft.cloudflare_ownership(site_root, site, datetime.now(timezone.utc))  # checked just now, after `now`
    if method in ('well-known-file', 'dns-txt'):
        if permits.parse_utc(verified_at or '') is None:
            raise SetupFailed('--verified-at に、自分で確認したUTC時刻（例 2026-11-21T03:00:00Z）を指定してください')
        return {'method': method, 'verified_at': verified_at}
    f = Path(site_root) / 'real' / permits.OWNERSHIP_EVIDENCE
    if f.is_file():  # no method given: reuse the evidence that is already there (renewal)
        return permit_draft.cloudflare_ownership(site_root, site, now)
    raise SetupFailed('--ownership（cloudflare / well-known-file / dns-txt）を指定してください')


def max_runs_for(site_root, days):
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


def setup(args):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    site_root, site = ensure_site(args.data, args.url, args.name, args.interval)
    args.site_root = site_root
    write_status(site_root, 'RUNNING', 'セットアップの画面で操作しています')
    real = site_root / 'real'
    real.mkdir(exist_ok=True)
    say(f'1. 対象：{site["url"]}（{site["site_id"]}）')
    created = ensure_key(args.key, args.no_passphrase)
    say(f'2. 署名鍵：{args.key}（{"作成しました" if created else "既存の鍵を使います"}）')
    trusted = ensure_trust(args.data, args.key)
    say(f'3. 信頼する公開鍵：{"登録しました" if trusted else "登録済み"}')
    ownership = ownership_record(site_root, site, args.ownership, args.verified_at, args.wrangler, now)
    old = None
    if (real / 'permit.json').is_file():
        try:
            old = permits.verify_signature(real / 'permit.json', Path(args.data) / 'trust' / 'allowed_signers')
        except permits.PermitRefused:
            old = json.loads((real / 'permit.json').read_text('utf-8'))
    permit_id = f"{site['site_id']}-{now:%Y%m%dT%H%M%SZ}"
    draft = permit_draft.build_draft(site_root, site, permit_id=permit_id, valid_from=now, valid_until=now + timedelta(days=args.days),
                                     max_runs=max_runs_for(site_root, args.days), ownership=ownership, issued_by=PRINCIPAL, now=now)
    carried = carryover(real, old)
    if carried:
        draft['baseline_carryover'] = carried
    say('5. 監視許可（署名前）：')
    say(f"   対象 {draft['target']['url']} ／ 期間 {draft['valid_from']} 〜 {draft['valid_until']} ／ 最大 {draft['max_runs']} 回")
    say(f"   所有権 {ownership['method']}（{ownership['verified_at']}）／ 撮影イメージ {draft['identity']['image_id'][:19]}…"
        + (f" ／ Baselineを引き継ぐ（{carried['permit_id']}）" if carried else ''))
    if not args.yes and input('   この内容で署名しますか？ [y/N] ').strip().lower() not in ('y', 'yes'):
        raise SetupFailed('署名しませんでした（何も変更していません）')
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
    from src.noxiworks.site_monitor import Monitor, SETTINGS_LOCK
    from src.noxiworks.site_workflow import Site
    monitor = Monitor(Site(site_root))
    with SETTINGS_LOCK:  # the next inspection is due now: the app (or the background task) starts it on its next tick
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
    parser.add_argument('--url')
    parser.add_argument('--name')
    parser.add_argument('--interval', type=int, default=86400, help='inspection interval in seconds when registering (default 24 h)')
    parser.add_argument('--ownership', choices=('cloudflare', 'well-known-file', 'dns-txt'))
    parser.add_argument('--verified-at')
    parser.add_argument('--wrangler')
    parser.add_argument('--days', type=int, default=30)
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

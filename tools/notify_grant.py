"""Sign the e-mail notification grant -- run by the USER, never by the app. Independent of the HTTP-monitoring grant and the image-capture permit.

    py -3.15 -B tools/notify_grant.py --data <app data folder> --host smtp.example.org --port 587 --sender from@example.org --recipient you@example.org
        --credential-ref SiteProof-SMTP-main [--security STARTTLS] [--days 30] [--max-total 500] [--max-per-day 20] [--key ~/.ssh/siteproof_permit] [--yes]

The grant (<data>/notify/notify-grant.json + .sig, schema siteproof.notify-grant.v1) names ONE mail server (port 465 = TLS, 587 = STARTTLS), the sender, 1..5 recipients,
the NAME of the Windows credential (generic credential in the Credential Manager, created by you), a period (max 366 days) and the message limits. It is signed with the
USER's own key (OpenSSH SSHSIG, the trust file <data>/trust/allowed_signers) and verified by src/noxiworks/smtp_notify.py before every message.
This tool never creates a key or a trust entry, never reads or writes any credential or password, never turns e-mail notification on, and never sends a message. Even with a
valid grant nothing is sent while NOTIFY_EXTERNAL_ENABLED is False in smtp_notify.py: that switch is for after the network boundary has been measured.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc
from src.noxiworks import permit as permits
from src.noxiworks import smtp_notify

PRINCIPAL = 'site-owner'


class GrantFailed(RuntimeError):
    pass


def say(text):
    print(text, flush=True)


def draft(args, now):
    security = args.security or smtp_notify.SECURITY.get(args.port)
    return {'schema': smtp_notify.GRANT_SCHEMA, 'grant_id': f'notify-{now:%Y%m%dT%H%M%SZ}', 'issued_by': PRINCIPAL, 'issued_at': format_utc(now),
            'smtp': {'host': args.host, 'port': args.port, 'security': security}, 'sender': args.sender, 'recipients': list(args.recipient),
            'credential_ref': args.credential_ref, 'valid_from': format_utc(now), 'valid_until': format_utc(now + timedelta(days=args.days)),
            'max_messages_total': args.max_total, 'max_messages_per_day': args.max_per_day}


def run(args):
    data = Path(args.data)
    trust = data / 'trust' / 'allowed_signers'
    pub = args.key.with_name(args.key.name + '.pub')
    if not args.key.is_file() or not pub.is_file():
        raise GrantFailed(f'署名鍵が見つかりません（{args.key}）。新しい鍵は作りません（先に tools/setup_monitoring.py を実行してください）')
    if not trust.is_file() or pub.read_text('utf-8').split()[1] not in trust.read_text('utf-8'):
        raise GrantFailed('この鍵は、このデータフォルダの trust/allowed_signers に登録されていません。何も変更していません')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    grant = draft(args, now)
    problems = smtp_notify.shape_problems(grant)
    if problems:
        raise GrantFailed('内容に問題があります：' + '／'.join(problems))
    cfg = grant['smtp']
    say('メール通知の許可（署名前）：')
    say(f"   サーバー {cfg['host']}:{cfg['port']}（{cfg['security']}） ／ 送信元 {grant['sender']} ／ 宛先 {', '.join(grant['recipients'])}")
    say(f"   期間 {grant['valid_from']} 〜 {grant['valid_until']} ／ 合計 {grant['max_messages_total']} 通・1日 {grant['max_messages_per_day']} 通まで")
    say(f"   資格情報の名前 {grant['credential_ref']}（Windowsの資格情報マネージャーに、あなたが登録してください。このツールは触りません）")
    say('   署名しても通知は始まらず、外部通信も有効にはなりません（アプリ側で別に有効にします）。')
    if not args.yes and input('   この内容で署名しますか？ [y/N] ').strip().lower() not in ('y', 'yes'):
        raise GrantFailed('署名しませんでした（何も変更していません）')
    folder = data / 'notify'
    folder.mkdir(parents=True, exist_ok=True)
    pending = folder / 'notify-grant.json.new'
    pending.write_text(json.dumps(grant, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    sig = pending.with_name(pending.name + '.sig')
    sig.unlink(missing_ok=True)
    subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(args.key), str(pending)], check=True, stdout=subprocess.DEVNULL)
    sig.replace(folder / 'notify-grant.json.sig')
    pending.replace(folder / 'notify-grant.json')
    verified, problems = smtp_notify.verify_grant(data, now)
    if verified is None:
        raise GrantFailed('署名後の確認に失敗しました：' + '／'.join(problems))
    say('署名しました：' + str(folder / 'notify-grant.json'))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True, choices=sorted(smtp_notify.SECURITY))
    parser.add_argument('--security', choices=sorted(set(smtp_notify.SECURITY.values())), help='default: TLS for 465, STARTTLS for 587')
    parser.add_argument('--sender', required=True)
    parser.add_argument('--recipient', action='append', required=True, help='repeat for up to 5 recipients')
    parser.add_argument('--credential-ref', required=True, help='name of the Windows Credential Manager entry: SiteProof-SMTP-<name>')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--max-total', type=int, default=500)
    parser.add_argument('--max-per-day', type=int, default=20)
    parser.add_argument('--key', type=Path, default=Path.home() / '.ssh' / 'siteproof_permit')
    parser.add_argument('--yes', action='store_true', help='sign without asking (the USER has reviewed the values)')
    args = parser.parse_args(argv)
    if not 1 <= args.days <= 366:
        parser.error('--days must be 1..366')
    try:
        return run(args)
    except (GrantFailed, permits.PermitRefused) as exc:
        say('中止しました：' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

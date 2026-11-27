"""Restore a SiteProof backup into a NEW folder -- run by the USER. Local copy only: nothing is uploaded, and no existing data is changed or deleted.

    py -3.15 -B tools/restore_backup.py --backup <siteproof-backup-... folder> --dest <NEW folder> [--site site-xxxxxxxx] [--yes]

The backup is verified first (a backup that does not verify is not restored). The destination must not exist (or be an empty folder) and must not overlap the backup.
Every file is copied and hashed again. Afterwards every monitor and the e-mail switches of the COPY are OFF (reason RESTORED): nothing observes or mails by itself.
Permits, grants and their counters are copied as they are: use either the original data folder or the copy, never both (the counts would diverge).
Then start the app on the copy with: SiteProof.cmd --data <NEW folder>
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import backup


def say(text):
    print(text, flush=True)


def main(argv=None, ask=input, now=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--backup', type=Path, required=True, help='the backup folder (the one with MANIFEST.json)')
    parser.add_argument('--dest', type=Path, required=True, help='a NEW folder (or an empty one) that becomes the restored data folder')
    parser.add_argument('--site', help='restore only sites/<site id> of the backup')
    parser.add_argument('--yes', action='store_true', help='do not ask for the confirmation')
    args = parser.parse_args(argv)
    when = now or datetime.now(timezone.utc).replace(microsecond=0)
    if not args.yes:
        say(f'復元します：{args.backup} → {args.dest}' + (f'（サイト {args.site} だけ）' if args.site else ''))
        say('  ・先にバックアップの内容を確認し、新しいフォルダへ写します。元のデータは変更しません')
        say('  ・写したあと、すべての監視とメール通知は「停止」になります。許可や回数の記録は、バックアップの時点のままです')
        say('  ・元のデータフォルダと、復元したフォルダを、同時に使わないでください')
        try:
            answer = ask('よろしいですか？ [y/N] ')
        except EOFError:
            answer = ''
        if answer.strip().lower() not in ('y', 'yes'):
            say('中止しました。何も変更していません')
            return 1
    try:
        result = backup.restore(args.backup, args.dest, when, args.site)
    except backup.BackupRefused as exc:
        say('中止しました：' + str(exc) + '。何も変更していません')
        return 1
    if not result['ok']:
        say(f"復元は完了しませんでした：{result['path']} に途中までのコピーを残しています（{result['files']} ファイル）。ほかのフォルダには触れていません")
        for problem in result['problems']:
            say('   問題：' + problem)
        say('   このフォルダは使わず、原因を取り除いてから、新しい別のフォルダで復元し直してください')
        return 2
    say(f"復元しました：{result['path']}（{result['files']} ファイル・{result['bytes']} バイト・すべて照合済み）")
    say(f"   停止にしたもの：{len(result['switched_off'])} 件（監視・メール通知。理由 RESTORED）。内容を確認してから、必要なものだけ開始してください")
    say('   元のデータフォルダと、このフォルダを同時に使わないでください。使い始めるには：SiteProof.cmd --data "' + result['path'] + '"')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

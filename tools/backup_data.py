"""Back up the SiteProof data folder to a NEW local folder, or check an existing backup -- run by the USER. Local copy only: nothing is uploaded.

    py -3.15 -B tools/backup_data.py --data <app data folder> --dest <existing folder> [--site site-xxxxxxxx]
    py -3.15 -B tools/backup_data.py --verify <backup folder>

Creates <dest>/siteproof-backup-<UTC>/ with the files and a MANIFEST.json (SHA-256 per file). It never overwrites or deletes anything, never copies a private key, does not
follow links, and refuses a destination inside the data folder. Restore: tools/restore_backup.py (into a NEW folder; every monitor of the copy is OFF).
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path)
    parser.add_argument('--dest', type=Path)
    parser.add_argument('--site', help='back up only sites/<site id>')
    parser.add_argument('--verify', type=Path, help='check an existing backup folder against its MANIFEST.json (read only)')
    args = parser.parse_args(argv)
    if args.verify:
        result = backup.verify(args.verify)
        say(('OK：' if result['ok'] else 'NG：') + f"{result['checked']} ファイルを確認しました。不足 {len(result['missing'])}・不一致 {len(result['mismatch'])}・余分 {len(result['extra'])}"
            + ('・' + ' '.join(result['problems']) if result['problems'] else ''))
        return 0 if result['ok'] else 1
    if not args.data or not args.dest:
        parser.error('--data and --dest are required (or --verify)')
    try:
        result = backup.create(args.data, args.dest, datetime.now(timezone.utc).replace(microsecond=0), args.site)
    except backup.BackupRefused as exc:
        say('中止しました：' + str(exc))
        return 1
    say(f"{'完了' if result['ok'] else '完了（注意あり）'}：{result['path']}")
    say(f"   {result['files']} ファイル・{result['bytes']} バイト（除外 {result['excluded']}）。どこにも送信していません")
    for item in result['skipped']:
        say(f"   コピーしませんでした：{item['path']}（{item['reason']}）")
    for rel in result['changed']:
        say(f'   コピー中に変更されました：{rel}（取り直してください）')
    for problem in result['problems']:
        say('   問題：' + problem)
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main())

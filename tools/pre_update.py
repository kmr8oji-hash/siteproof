"""Before you update the SiteProof program folder: check the environment, make a verified backup of the data folder, and say what to keep. Run by the USER.

    py -3.15 -B tools/pre_update.py --data <app data folder> [--no-docker]

1. the same read-only report as tools/doctor.py (only what is missing or needs attention is listed);
2. a backup of the whole data folder into <data folder>-backups\\siteproof-backup-<UTC>\\ (next to it, never inside), then verify of that backup;
3. a list of what you keep and what the update may replace.
No program file is changed, downloaded or replaced here: updating the program folder is yours (docs/INSTALL.md, 「更新と元に戻す」). The data folder is only read.
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import backup, environment


def main(argv=None, probes=None, now=None, out=print):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--no-docker', action='store_true', help='skip the Docker probes (UNKNOWN)')
    args = parser.parse_args(argv)
    data = args.data.resolve()
    if not data.is_dir():
        out(f'中止しました：データフォルダ {data} がありません。何も変更していません')
        return 1
    result = environment.report(data, probes, docker=not args.no_docker)
    c = result['counts']
    out(f"1. 導入環境：OK {c['OK']}・ない {c['MISSING']}・注意 {c['WARN']}・不明 {c['UNKNOWN']}（全項目は tools/doctor.py --data で確認できます）")
    for it in result['items']:
        if it['status'] in ('MISSING', 'WARN'):
            out(f"   [{it['status']}] {it['label']}：{it['detail']}  → {it['next']}")
    parent = data.with_name(data.name + '-backups')
    try:
        parent.mkdir(exist_ok=True)
        done = backup.create(data, parent, now or datetime.now(timezone.utc).replace(microsecond=0))
    except (backup.BackupRefused, OSError) as exc:
        out('中止しました：バックアップを作れませんでした（' + str(exc) + '）。更新はしないでください。データは何も変更していません')
        return 1
    checked = backup.verify(done['path'])
    out(f"2. バックアップ：{done['path']}（{done['files']} ファイル・{done['bytes']} バイト）・確認 " + ('OK' if checked['ok'] else 'NG（作り直してください）'))
    for rel in done['changed']:
        out(f'   コピー中に変更されました：{rel}（アプリを閉じてから取り直してください）')
    for item in done['skipped']:
        out(f"   コピーしませんでした：{item['path']}（{item['reason']}）")
    for problem in done['problems']:
        out('   問題：' + problem)
    good = done['ok'] and checked['ok']
    out('3. 更新の前に、次のものを残してください（更新は、プログラムのフォルダだけを入れ替えます）：')
    out(f'   ・データフォルダ：{data}（そのまま。更新で触りません）')
    out(f"   ・このバックアップ：{done['path']}（更新が終わって動作を確認するまで消さないでください）")
    out('   ・あなたの秘密鍵（~/.ssh）と、Windowsの資格情報マネージャーの SiteProof-SMTP-…（SiteProofのフォルダの外にあります）')
    out('   ・元のプログラムのフォルダ（名前を変えて残すと、元に戻せます）')
    out('   更新したあとは、署名した許可が「撮影構成の同一性」で止まることがあります。サイトの画面の「監視設定を更新」で署名し直してください')
    out('プログラムの更新は行っていません。' + ('' if good else '（バックアップに注意があります。上を確認して、問題がなくなってから更新してください）'))
    return 0 if good else 2


if __name__ == '__main__':
    raise SystemExit(main())

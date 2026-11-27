"""What SiteProof leaves outside its program folder, and the exact commands YOU may run to remove it. Read only: this tool removes nothing, stops nothing, registers nothing.

    py -3.15 -B tools/uninstall_check.py --data <app data folder>

Lists the Windows tasks (asked with a read-only `schtasks /Query`, by name), the data folder, the backups next to it, the remembered-folder settings file and the background
folder of launchers and logs. Deleting the program folder alone removes none of these: the tasks keep running their launchers, and the data stays.
Your keys in ~/.ssh and the Windows Credential Manager entries (SiteProof-SMTP-...) are yours: SiteProof does not list or touch them.
"""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.noxiworks import sites
from tools import background_monitor

CHANNEL_LABEL = {'image': '画像監視', 'http': 'HTTP監視'}


def size_of(folder):
    return sum(p.stat().st_size for p in Path(folder).rglob('*') if p.is_file()) if Path(folder).is_dir() else 0


def collect(data, query=None, settings=None, backups=None):
    """-> {'tasks': [{site, channel, name, registered}], 'data', 'backups', 'settings', 'background'}. `query(data, site_id, channel)` -> True / False / None (cannot be asked)."""
    from src.noxiworks import app
    data = Path(data).resolve()
    query = query or app.query_background_task
    tasks = []
    for folder in sites.folders(data):
        for channel in background_monitor.CHANNELS:
            try:
                found = query(data, folder.name, channel)
            except Exception:
                found = None
            tasks.append({'site': folder.name, 'channel': channel, 'name': background_monitor.task_name(data, folder.name, channel), 'registered': found})
    kept = Path(backups) if backups else data.with_name(data.name + '-backups')
    found_backups = sorted(p.name for p in kept.iterdir() if p.name.startswith('siteproof-backup-')) if kept.is_dir() else []
    settings = Path(settings) if settings else app.settings_file()
    return {'tasks': tasks, 'data': {'path': str(data), 'exists': data.is_dir(), 'bytes': size_of(data)},
            'backups': {'path': str(kept), 'items': found_backups}, 'settings': {'path': str(settings), 'exists': settings.is_file()},
            'background': {'path': str(data / 'background'), 'exists': (data / 'background').is_dir()}}


def lines(found):
    out = ['SiteProof がプログラムのフォルダの外に持っているもの（読み取りだけ・何も削除していません）']
    out.append('1. Windowsのタスク（アプリを閉じても監視する、を登録した場合だけ）')
    if not found['tasks']:
        out.append('   サイトが登録されていないため、確認するタスクはありません')
    for t in found['tasks']:
        state = '登録されています' if t['registered'] else '登録されていません' if t['registered'] is False else '問い合わせられませんでした（Windows以外、または失敗）'
        out.append(f"   - {t['name']}（{t['site']}・{CHANNEL_LABEL[t['channel']]}）：{state}")
    d, b, s, g = found['data'], found['backups'], found['settings'], found['background']
    out.append(f"2. データフォルダ：{d['path']}（{'あります・' + format(d['bytes'] / 1048576, '.1f') + ' MB' if d['exists'] else 'ありません'}）。設定・Baseline・撮影画像・許可・履歴が入っています")
    out.append(f"3. バックアップ：{b['path']}（{len(b['items'])}件）" + ''.join(f'\n   - {n}' for n in b['items'][-5:]))
    out.append(f"4. 保存したデータフォルダの設定：{s['path']}（{'あります' if s['exists'] else 'ありません'}）")
    out.append(f"5. バックグラウンド監視の起動ファイルとログ：{g['path']}（{'あります' if g['exists'] else 'ありません'}。データフォルダの中です）")
    out.append('6. あなたのもの：~/.ssh の署名用の鍵、Windowsの資格情報マネージャーの SiteProof-SMTP-…（SiteProofは一覧も削除もしません）')
    out.append('')
    out.append('プログラムのフォルダを削除しても、上の 1〜5 は残ります。データを残したままやめるときは、タスクだけ解除してください。')
    out.append('あなたが実行するコマンド（必要なものだけ。順に確認してください）：')
    cmds = [f"py -3.15 -B tools/background_monitor.py remove --data \"{d['path']}\" --site {t['site']} --channel {t['channel']}" for t in found['tasks'] if t['registered'] is True]
    out += [f'  [タスクを解除] {c}' for c in cmds] or ['  [タスクを解除] 登録されているタスクはありません（問い合わせられなかった場合は、status で確認：'
                                                      f'py -3.15 -B tools/background_monitor.py status --data "{d["path"]}"）']
    out.append(f"  [設定を消す] Remove-Item -LiteralPath \"{s['path']}\"   ← 保存したデータフォルダの選択だけを忘れます（データは消えません）")
    out.append(f"  [データを消す・元に戻せません] Remove-Item -Recurse -LiteralPath \"{d['path']}\"   ← データを本当に捨てるときだけ。先にバックアップを別の場所へ")
    out.append(f"  [バックアップを消す・元に戻せません] Remove-Item -Recurse -LiteralPath \"{b['path']}\"   ← 不要だと確認できたときだけ")
    return out


def main(argv=None, query=None, settings=None, out=print):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    args = parser.parse_args(argv)
    for line in lines(collect(args.data, query, settings)):
        out(line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

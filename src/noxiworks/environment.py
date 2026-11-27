"""導入環境の確認 (doctor): what this PC has for SiteProof, as a list of {key, label, status: OK | MISSING | WARN | UNKNOWN, detail, next}. Read only.

Guarantees: nothing is started, installed, registered, created, pulled, signed, sent or changed; every probe can be replaced (`probes`), so tests never reach Docker, Windows
tasks, the registry or the network. The Docker probes are the existing read-only ones (`docker info`, `docker image inspect`; never a pull, build or tag) and are skipped
(UNKNOWN) with docker=False. A probe that cannot answer is UNKNOWN, never OK. The three external-communication switches are facts (無効 / 有効), not errors.
Not guaranteed: a green report does not mean a real capture works (the harness checks its own isolation before every run); writability is os.access, not a test write;
Japanese paths with the real Docker bind mount are not measured.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys

from src.aws_b.model import parse_utc
from src.noxiworks import sites

MIN_PYTHON = (3, 12)
LOW_DISK_BYTES = 2 << 30
OLD_BACKUP_DAYS = 14
DOCKER_CLI = Path(r'C:\Program Files\Docker\Docker\resources\bin\docker.exe')
STATUSES = ('OK', 'MISSING', 'WARN', 'UNKNOWN')
CHANNEL_LABEL = {'image': '画像監視', 'http': 'HTTP監視'}


def item(key, label, status, detail, next_step=''):
    return {'key': key, 'label': label, 'status': status, 'detail': detail, 'next': next_step if status in ('MISSING', 'WARN') else ''}


def default_probes():
    """The real, read-only probes. Imported lazily: a report on a PC without Docker must still be produced."""
    from src.noxiworks import http_isolation, permit, real_capture

    def background(data, site_id, channel):
        from src.noxiworks.app import query_background_task
        return query_background_task(data, site_id, channel)

    def path_problem(data):
        from tests.runtime.browser_bundle import staged_path_problem
        sample = '00000000T000000Z-00-real'
        return staged_path_problem(real_capture.ROOT, Path(data) / 'sites' / 'site-00000000' / 'runs' / ('.tmp-' + sample) / sample)

    return {'python': lambda: (sys.version_info[:3], sys.executable), 'ssh_keygen': permit.ssh_keygen,
            'docker_cli': lambda: shutil.which('docker') or (str(DOCKER_CLI) if DOCKER_CLI.is_file() else None),
            'docker_engine': real_capture.docker_engine_answers, 'pinned_image': http_isolation.pinned_image, 'docker_image': real_capture.docker_image_id,
            'background': background, 'path_problem': path_problem, 'free_bytes': lambda p: shutil.disk_usage(p).free,
            'writable': lambda p: os.access(p, os.W_OK), 'now': lambda: datetime.now(timezone.utc).replace(microsecond=0), 'switches': switches}


def switches():
    """The three kill switches in the source, as booleans. A module that cannot be read counts as off (nothing can be sent without it)."""
    out = {}
    for key, module, name in (('http', 'src.noxiworks.http_monitor', 'HTTP_EXTERNAL_ENABLED'), ('mail', 'src.noxiworks.smtp_notify', 'NOTIFY_EXTERNAL_ENABLED'),
                              ('dns', 'tools.dns_ownership', 'OWNERSHIP_DNS_ENABLED')):
        try:
            out[key] = getattr(__import__(module, fromlist=[name]), name) is True
        except Exception:
            out[key] = False
    return out


def asked(probe, *args):
    """-> (answer, None) or (None, error type): one failing probe never stops the report."""
    try:
        return probe(*args), None
    except Exception as exc:
        return None, type(exc).__name__


def backups_of(data):
    """The backups next to the data folder (the app's own convention): [(folder name, created_at text or '')], oldest first."""
    kept = Path(data).with_name(Path(data).name + '-backups')
    found = []
    for p in sorted(kept.iterdir()) if kept.is_dir() else []:
        if p.name.startswith('siteproof-backup-') and (p / 'MANIFEST.json').is_file():
            try:
                found.append((p.name, str(json.loads((p / 'MANIFEST.json').read_text('utf-8')).get('created_at') or '')))
            except (OSError, ValueError, AttributeError):
                found.append((p.name, ''))
    return found


def python_items(probe):
    answer, err = asked(probe['python'])
    if err or not answer:
        return [item('python', 'Python', 'UNKNOWN', 'Pythonのバージョンを確認できませんでした')]
    version, exe = answer
    text = '.'.join(str(x) for x in version)
    if tuple(version[:2]) >= MIN_PYTHON:
        return [item('python', 'Python（3.12以降）', 'OK', f'Python {text}（{exe}）')]
    return [item('python', 'Python（3.12以降）', 'MISSING', f'Python {text}（{exe}）は古く、動きません',
                 'https://www.python.org/ からPython 3.12以降をインストールし、「py launcher」を有効にしてください')]


def tool_items(probe, docker):
    out = []
    found, err = asked(probe['ssh_keygen'])
    out.append(item('ssh_keygen', 'OpenSSH（ssh-keygen）', 'OK' if found else 'UNKNOWN' if err else 'MISSING', found or ('確認できませんでした' if err else '見つかりません'),
                    'Windowsの「設定 → システム → オプション機能」で「OpenSSH クライアント」を追加してください（監視許可の署名・検証に使います）'))
    if not docker:
        skipped = 'Dockerの確認を省略しました（--no-docker）'
        return out + [item(k, label, 'UNKNOWN', skipped) for k, label in (('docker_cli', 'Docker CLI'), ('docker_engine', 'Docker Desktop（エンジン）'), ('docker_image', '撮影イメージ（固定）'))]
    cli, err = asked(probe['docker_cli'])
    out.append(item('docker_cli', 'Docker CLI', 'OK' if cli else 'UNKNOWN' if err else 'MISSING', cli if cli else '確認できませんでした' if err else 'dockerコマンドが見つかりません',
                    '実サイトの撮影・HTTP監視にだけ必要です。Docker Desktopをインストールしてください（表示の確認や合成デモには不要）'))
    if not cli:
        return out + [item('docker_engine', 'Docker Desktop（エンジン）', 'UNKNOWN', 'Docker CLIがないため確認していません'),
                      item('docker_image', '撮影イメージ（固定）', 'UNKNOWN', 'Docker CLIがないため確認していません')]
    engine, err = asked(probe['docker_engine'])
    out.append(item('docker_engine', 'Docker Desktop（エンジン）', 'UNKNOWN' if err else 'OK' if engine else 'MISSING', '確認できませんでした' if err else '応答しています' if engine else '応答しません',
                    'Docker Desktopを起動してください（サイトの画面の「Docker Desktopを起動」ボタン、またはスタートメニューから。起動に1〜2分かかります）'))
    pinned, err = asked(probe['pinned_image'])
    if err or not pinned:
        return out + [item('docker_image', '撮影イメージ（固定）', 'UNKNOWN', '固定したイメージIDを読めませんでした')]
    if not engine:
        return out + [item('docker_image', '撮影イメージ（固定）', 'UNKNOWN', 'Dockerが応答しないため、確認していません')]
    found, err = asked(probe['docker_image'], pinned)
    if err or found is None:
        return out + [item('docker_image', '撮影イメージ（固定）', 'UNKNOWN', 'イメージを確認できませんでした（Dockerに問い合わせても答えがありません）')]
    if found == '':
        return out + [item('docker_image', '撮影イメージ（固定）', 'MISSING', f'このPCのDockerに、固定したイメージがありません（{pinned[:19]}…）',
                           'docs/INSTALL.md「撮影イメージを別のPCへ移す」を見てください。SiteProofはイメージの取得・ビルドをしません')]
    if found != pinned:
        return out + [item('docker_image', '撮影イメージ（固定）', 'WARN', f'イメージはありますが、IDが固定したものと違います（{found[:19]}…）。SiteProofはこのイメージを使いません',
                           'docs/INSTALL.md「撮影イメージを別のPCへ移す」を見てください（イメージの保存方式によってIDが変わることがあります）')]
    return out + [item('docker_image', '撮影イメージ（固定）', 'OK', f'固定したIDと一致しています（{pinned[:19]}…）')]


def data_items(data, probe):
    data = Path(data)
    out = []
    exists = data.is_dir()
    writable, err = asked(probe['writable'], data) if exists else (None, None)
    if not exists:
        out.append(item('data_folder', 'データフォルダ', 'MISSING', f'{data} はまだありません', 'SiteProof.cmd を起動すると作られます（別の場所を使うときは --data を付けます）'))
    elif err:
        out.append(item('data_folder', 'データフォルダ', 'UNKNOWN', f'{data}（書き込めるか確認できませんでした）'))
    elif not writable:
        out.append(item('data_folder', 'データフォルダ', 'WARN', f'{data} は書き込めない可能性があります', 'フォルダの権限を確認するか、別のフォルダを --data で指定してください'))
    else:
        out.append(item('data_folder', 'データフォルダ', 'OK', f'{data}（存在し、書き込めます）'))
    here = data
    while not here.exists() and here != here.parent:
        here = here.parent
    free, err = asked(probe['free_bytes'], here)
    if err or free is None:
        out.append(item('data_space', 'ディスクの空き', 'UNKNOWN', '確認できませんでした'))
    elif free < LOW_DISK_BYTES:
        out.append(item('data_space', 'ディスクの空き', 'WARN', f'空き {free / 1073741824:.1f} GB（2 GB未満）', '撮影画像と履歴で増えます。空きを作るか、別のドライブのフォルダを --data で指定してください'))
    else:
        out.append(item('data_space', 'ディスクの空き', 'OK', f'空き {free / 1073741824:.1f} GB'))
    text = str(data.resolve()) if data.is_absolute() or exists else str(data)
    problem, err = asked(probe['path_problem'], data)
    if err:
        out.append(item('data_path_length', 'データフォルダのパスの長さ', 'UNKNOWN', '確認できませんでした'))
    elif problem:
        out.append(item('data_path_length', 'データフォルダのパスの長さ', 'WARN', f'{len(text)}文字。' + problem, 'C:\\spe のような短いパスのフォルダを --data に指定してください（既存のデータは勝手に移しません）'))
    else:
        out.append(item('data_path_length', 'データフォルダのパスの長さ', 'OK', f'{len(text)}文字（Dockerへ渡す撮影ファイルのパスが長すぎる心配はありません）'))
    if text.isascii():
        out.append(item('data_path_ascii', 'データフォルダのパスの文字', 'OK', '英数字だけです'))
    else:
        out.append(item('data_path_ascii', 'データフォルダのパスの文字', 'WARN', 'パスに日本語などの文字が含まれます。アプリ・バックグラウンドの起動ファイルは対応していますが、実撮影（Dockerへ渡す場所）は日本語パスでは未検証です',
                        '確実に動かすには、英数字だけのパス（例：C:\\spe）に --data を変えてください'))
    trust = data / 'trust' / 'allowed_signers'
    out.append(item('trust', '署名を信頼する公開鍵（trust\\allowed_signers）', 'OK' if trust.is_file() else 'MISSING',
                    str(trust) if trust.is_file() else 'ありません（監視許可の署名を確認できません）',
                    f'自分の公開鍵を、{trust} に1行置いてください（書式は docs/REAL_CAPTURE.md。SiteProofは書き込みません）'))
    return out


def site_items(data, probe):
    found, bad = sites.scan(data)
    pages, page_bad = 0, []
    for folder in found:
        good, broken = sites.pages(folder)
        pages += len(good)
        page_bad += [(f'{folder.name}/pages/{name}', why) for name, why in broken]
    problems = bad + page_bad
    out = []
    if not found:
        out.append(item('sites', '登録したサイト', 'MISSING', 'まだ登録していません', 'アプリのHOMEで「サイトを追加」を押してください'))
    else:
        out.append(item('sites', '登録したサイト', 'OK', f'{len(found)}サイト・追加ページ{pages}件'))
    if problems:
        out.append(item('site_folders', '使われていないサイトのフォルダ', 'WARN', '、'.join(f'{n}（{why}）' for n, why in problems[:5]) + ('…' if len(problems) > 5 else ''),
                        'フォルダ名とsite.jsonが一致しない・コピーされた等です。何も削除していません。不要なら自分で確認して片付けてください'))
    for folder in found:
        for channel in ('image', 'http'):
            on, err = asked(probe['background'], Path(data), folder.name, channel)
            label = f'アプリを閉じても監視（{folder.name}・{CHANNEL_LABEL[channel]}）'
            key = f'background:{folder.name}:{channel}'
            if err or on is None:
                out.append(item(key, label, 'UNKNOWN', 'Windowsのタスクに問い合わせられませんでした（Windows以外、または問い合わせに失敗）'))
            elif on:
                out.append(item(key, label, 'OK', '登録されています'))
            else:
                out.append(item(key, label, 'MISSING', '登録されていません（アプリを閉じている間は監視しません）',
                                f'必要な場合だけ、サイトの画面の「{"アプリを閉じても監視する" if channel == "image" else "アプリを閉じてもHTTP監視する"}」を押してください'))
    return out


def parse_name(name):
    """The time in a backup folder's name (siteproof-backup-20261125T010203Z), or None."""
    try:
        return datetime.strptime(name[len('siteproof-backup-'):], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def backup_items(data, probe):
    found = backups_of(data)
    if not found:
        return [item('backup', '最後のバックアップ', 'MISSING', 'ありません', 'サイトの画面の「保存容量・整理・バックアップ」で「全データをバックアップ」を押してください（tools/backup_data.py でも可）')]
    name, created = found[-1]
    now, _ = asked(probe['now'])
    at = parse_utc(created) or parse_name(name)
    if at is None or now is None:
        return [item('backup', '最後のバックアップ', 'UNKNOWN', f'{name}（作成日時を読めませんでした）')]
    days = int((now - at).total_seconds() // 86400)
    if days > OLD_BACKUP_DAYS:
        return [item('backup', '最後のバックアップ', 'WARN', f'{name}（{days}日前）', 'そろそろ新しいバックアップを作ってください（内容の確認は tools/backup_data.py --verify）')]
    return [item('backup', '最後のバックアップ', 'OK', f'{name}（{days}日前。内容の照合はここでは行いません）')]


def switch_items(probe):
    on, err = asked(probe['switches'])
    on = on if isinstance(on, dict) else {}
    out = []
    for key, label, off_text in (('http', 'HTTP監視の外部通信', '無効：サイトへ通信しません（実サイトでの試験と承認が済むまで）'),
                                 ('mail', 'メール送信', '無効：メールを送りません（実測と承認が済むまで）'),
                                 ('dns', 'DNSの照会（所有権の確認）', '無効：DNSへ問い合わせません（承認されるまで）')):
        out.append(item('switch_' + key, label, 'UNKNOWN' if err else 'OK', '確認できませんでした' if err else '有効：許可された範囲で通信します' if on.get(key) else off_text))
    return out


def report(data, probes=None, docker=True):
    """-> {'schema', 'checked_at', 'data', 'items', 'counts'}. `probes` replaces any of default_probes() by key (tests inject every one)."""
    probe = {**default_probes(), **(probes or {})}
    items = python_items(probe) + tool_items(probe, docker) + data_items(data, probe) + site_items(data, probe) + backup_items(data, probe) + switch_items(probe)
    now, _ = asked(probe['now'])
    return {'schema': 'siteproof.environment.v1', 'checked_at': now.strftime('%Y-%m-%dT%H:%M:%SZ') if now else None, 'data': str(data), 'items': items,
            'counts': {s: sum(1 for i in items if i['status'] == s) for s in STATUSES}}

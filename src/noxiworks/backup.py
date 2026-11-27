"""Local backup of the SiteProof data folder (or one site of it) into a NEW folder, with a SHA-256 manifest. Local copy only: nothing is uploaded or sent anywhere.

    <dest_parent>/siteproof-backup-<UTC>/   the copied files (same relative paths) + MANIFEST.json

Guarantees
  * Never overwrites, never deletes, never touches the data folder: the backup folder must not exist, must not be inside the data folder, and files are created with
    exclusive-create. A failed run leaves its partial folder (no MANIFEST.json, so verify() refuses it) rather than deleting anything.
  * Symlinks and junctions / reparse points are neither followed nor copied (reported as skipped). A file that starts with a PEM private-key header refuses the whole
    backup before anything is written (the data folder holds only the PUBLIC trust file; a private key there would be a mistake to fix, not to copy).
  * Each file is copied, hashed while copying, and the copy is hashed again from disk; a source that changed while it was copied is reported (manifest + result), SQLite
    files go through the sqlite3 backup API (a consistent snapshot) or are skipped with a report when they are locked.
  * Left out on purpose: ui/ and empty/ folders (regenerated), *.lock, .tmp-* , background/*.log, SQLite -wal/-shm/-journal sidecars.
restore() copies a verified backup into a NEW (or empty) folder, re-hashes every copy, and switches every monitor and e-mail switch OFF in the copy (paused / stopped reason
'RESTORED'), so a restored copy never starts observing or mailing by itself, least of all next to the original. It never touches the backup or any other folder; a failure
leaves the new folder and says so (RESTORE-RECORD.json). Permits, grants and ledgers are copied as they are: use the original OR the copy, not both (the counts would diverge).
Not guaranteed: protection of the copy itself (it holds your settings, evidence and grants); keep it where you keep the originals.
"""
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3

SCHEMA = 'siteproof.backup-manifest.v1'
MANIFEST = 'MANIFEST.json'
EXCLUDE_DIRS = ('ui', 'empty', 'sites/*/ui', 'sites/*/empty')
EXCLUDE_NAMES = ('*.lock', '.tmp-*')
EXCLUDE_PATHS = ('background/*.log',)
SIDECARS = ('-wal', '-shm', '-journal')
SQLITE_HEADER = b'SQLite format 3\x00'
REPARSE_POINT = 0x400
_SITE_RE = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
CHUNK = 1024 * 1024
BUSY_TRIES = 4


class BackupRefused(ValueError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK), b''):
            h.update(chunk)
    return h.hexdigest()


def _inside(inner, outer):
    return inner == outer or outer in inner.parents


def _is_link(entry):
    if entry.is_symlink():
        return True
    try:
        return bool(getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & REPARSE_POINT)
    except OSError:
        return True


def _excluded(rel, name, names, is_dir):
    if name.startswith('.tmp-'):
        return True
    if is_dir:
        return any(fnmatch.fnmatchcase(rel, pattern) for pattern in EXCLUDE_DIRS)
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in EXCLUDE_NAMES) or any(fnmatch.fnmatchcase(rel, pattern) for pattern in EXCLUDE_PATHS):
        return True
    return any(name.endswith(s) and name[:-len(s)] in names for s in SIDECARS)


def _scan(base, prefix):
    """-> (files [(rel, abs, size)], excluded [rel], skipped [{path, reason}]), sorted; no link is followed."""
    files, excluded, skipped = [], [], []
    stack = [(Path(base), prefix)]
    while stack:
        folder, rel = stack.pop()
        entries = sorted(os.scandir(folder), key=lambda e: e.name)
        names = {e.name for e in entries}
        for e in entries:
            r = (rel + '/' if rel else '') + e.name
            if _is_link(e):
                skipped.append({'path': r, 'reason': 'LINK'})
            elif e.is_dir(follow_symlinks=False):
                if _excluded(r, e.name, names, True):
                    excluded.append(r + '/')
                else:
                    stack.append((Path(e.path), r))
            elif e.is_file(follow_symlinks=False):
                if _excluded(r, e.name, names, False):
                    excluded.append(r)
                else:
                    files.append((r, Path(e.path), e.stat(follow_symlinks=False).st_size))
            else:
                skipped.append({'path': r, 'reason': 'SPECIAL_FILE'})
    return sorted(files), sorted(excluded), skipped


def _has_private_key(path):
    with open(path, 'rb') as f:
        head = f.read(64)
    return head.startswith(b'-----BEGIN') and b'PRIVATE KEY' in head


def _copy_plain(src, dst):
    h, copied = hashlib.sha256(), 0
    before = os.stat(src)
    with open(src, 'rb') as i, open(dst, 'xb') as o:  # 'x': an existing file is an error, never overwritten
        for chunk in iter(lambda: i.read(CHUNK), b''):
            h.update(chunk)
            o.write(chunk)
            copied += len(chunk)
        o.flush()
        os.fsync(o.fileno())
    after = os.stat(src)
    changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or copied != after.st_size
    return h.hexdigest(), copied, changed


def _copy_sqlite(src, dst):
    """A consistent snapshot through the sqlite3 backup API, written only once it is complete. -> bytes written, or None when it is locked / unreadable."""
    source = memory = None
    busy = []

    def progress(status, remaining, total):  # sqlite3's backup retries a busy database for ever: stop after a few tries
        if status in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
            busy.append(1)
            if len(busy) >= BUSY_TRIES:
                raise sqlite3.OperationalError('database is locked')
    try:
        source = sqlite3.connect(Path(src).resolve().as_uri() + '?mode=ro', uri=True, timeout=1)
        memory = sqlite3.connect(':memory:')
        source.backup(memory, sleep=0.05, progress=progress)
        data = memory.serialize()
    except sqlite3.Error:
        return None
    finally:
        for c in (source, memory):
            if c is not None:
                c.close()
    with open(dst, 'xb') as o:
        o.write(data)
        o.flush()
        os.fsync(o.fileno())
    return len(data)


def create(data, dest_parent, now, site=None):
    """Copy `data` (or only sites/<site>) to dest_parent/siteproof-backup-<UTC>. -> {'ok', 'path', 'files', 'bytes', 'excluded', 'skipped', 'changed', 'problems'}.
    ok is False when a file changed while it was copied, a copy did not verify or anything was skipped (locked SQLite, a link); the manifest says so either way."""
    data, parent = Path(data).resolve(), Path(dest_parent).resolve()
    if not data.is_dir():
        raise BackupRefused('データフォルダがありません')
    if not parent.is_dir():
        raise BackupRefused('保存先のフォルダがありません')
    dest = parent / ('siteproof-backup-' + now.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    if _inside(dest, data) or _inside(data, dest):
        raise BackupRefused('保存先がデータフォルダの中にあります（別の場所を指定してください）')
    if dest.exists():
        raise BackupRefused('同じ名前のバックアップがすでにあります（上書きしません）')
    if site is None:
        base, prefix, scope = data, '', 'ALL'
    else:
        if not isinstance(site, str) or not _SITE_RE.fullmatch(site) or not (data / 'sites' / site).is_dir():
            raise BackupRefused('指定したサイトが見つかりません')
        base, prefix, scope = data / 'sites' / site, 'sites/' + site, 'SITE'
    files, excluded, skipped = _scan(base, prefix)
    for rel, path, _ in files:
        if _has_private_key(path):
            raise BackupRefused('秘密鍵のように見えるファイルがあります（' + rel + '）。バックアップしません。データフォルダから取り除いてください')
    need = sum(size for _, _, size in files)
    if shutil.disk_usage(parent).free < need + need // 10 + (1 << 20):
        raise BackupRefused('保存先の空き容量が足りません')
    dest.mkdir()  # exist_ok=False: never an existing folder
    manifest_files, changed, problems = {}, [], []
    for rel, path, size in files:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'rb') as f:
            sqlite = f.read(16) == SQLITE_HEADER
        try:
            if sqlite:
                written = _copy_sqlite(path, target)
                if written is None:
                    skipped.append({'path': rel, 'reason': 'SQLITE_LOCKED'})
                    problems.append('SQLITE_LOCKED:' + rel)
                    continue
                digest, copied, was_changed, method = _sha256(target), written, False, 'sqlite-backup'
            else:
                streamed, copied, was_changed = _copy_plain(path, target)
                digest, method = _sha256(target), 'copy'
                if digest != streamed:
                    problems.append('COPY_MISMATCH:' + rel)
        except OSError as exc:
            problems.append('COPY_FAILED:' + rel + ':' + type(exc).__name__)
            continue
        manifest_files[rel] = {'sha256': digest, 'bytes': copied, 'method': method, **({'changed_while_copying': True} if was_changed else {})}
        if was_changed:
            changed.append(rel)
    ok = not problems and not changed and not skipped
    manifest = {'schema': SCHEMA, 'created_at': now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'scope': scope, 'site_id': site,
                'note': 'ローカルのコピーです。どこにも送信していません。', 'files': manifest_files, 'counts': {'files': len(manifest_files), 'bytes': sum(f['bytes'] for f in manifest_files.values())},
                'excluded': excluded, 'skipped': skipped, 'changed_while_copying': changed, 'problems': problems}
    with open(dest / MANIFEST, 'x', encoding='utf-8') as f:
        f.write(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
        f.flush()
        os.fsync(f.fileno())
    return {'ok': ok, 'path': str(dest), 'files': len(manifest_files), 'bytes': manifest['counts']['bytes'], 'excluded': len(excluded), 'skipped': skipped, 'changed': changed,
            'problems': problems}


def verify(backup):
    """Re-read every file of a backup and compare it with its MANIFEST.json. -> {'ok', 'checked', 'missing', 'mismatch', 'extra', 'problems'}. Read only."""
    backup = Path(backup)
    out = {'ok': False, 'checked': 0, 'missing': [], 'mismatch': [], 'extra': [], 'problems': []}
    try:
        manifest = json.loads((backup / MANIFEST).read_text('utf-8'))
        files = manifest['files']
        assert manifest['schema'] == SCHEMA and isinstance(files, dict)
    except (OSError, ValueError, KeyError, AssertionError):
        out['problems'].append('MANIFEST_UNREADABLE')
        return out
    for rel, meta in files.items():
        parts = rel.split('/')
        if rel.startswith('/') or '..' in parts or ':' in rel or not isinstance(meta, dict):
            out['problems'].append('UNSAFE_PATH:' + rel)
            continue
        path = backup / rel
        try:
            st = path.lstat()
        except OSError:
            out['missing'].append(rel)
            continue
        if path.is_symlink() or not path.is_file():
            out['mismatch'].append(rel)
            continue
        out['checked'] += 1
        if st.st_size != meta.get('bytes') or _sha256(path) != meta.get('sha256'):
            out['mismatch'].append(rel)
    known = set(files) | {MANIFEST}
    stack = [backup]
    while stack:
        for e in sorted(os.scandir(stack.pop()), key=lambda e: e.name):
            rel = Path(e.path).relative_to(backup).as_posix()
            if e.is_dir(follow_symlinks=False):
                stack.append(Path(e.path))
            elif rel not in known:
                out['extra'].append(rel)
    out['ok'] = not (out['missing'] or out['mismatch'] or out['extra'] or out['problems'])
    return out


RESTORE_RECORD = 'RESTORE-RECORD.json'
RESTORED = 'RESTORED'
OFF_SWITCHES = {'monitor.json': 'paused_reason', 'http-monitor.json': 'paused_reason', 'email-notify.json': 'stopped_reason'}  # file name -> the reason key it records


def _off_key(rel):
    """The reason key of a restored file that switches something on (monitor / HTTP monitor / a site's mail switch / the data-wide mail channel), else None."""
    if rel == 'notify/email.json':
        return 'stopped_reason'
    return OFF_SWITCHES.get(rel.rsplit('/', 1)[-1]) if rel.startswith('sites/') else None


def _switch_off(path, key):
    """enabled -> false with the reason RESTORED, written atomically. -> {'was_enabled', 'was_reason'}."""
    value = json.loads(Path(path).read_text('utf-8'))
    if not isinstance(value, dict):
        raise ValueError('not an object')
    was = {'was_enabled': value.get('enabled') is True, 'was_reason': value.get(key)}
    value.update(enabled=False, **{key: RESTORED})
    if key == 'paused_reason':
        value['next_due_at'] = None
    tmp = Path(path).with_name(Path(path).name + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(tmp, path)
    return was


def restore(backup, dest, now, site=None):
    """Copy a verified backup into `dest` (a NEW folder, or an existing EMPTY one), optionally only sites/<site>. -> {'ok', 'path', 'files', 'bytes', 'switched_off', 'problems'}.
    Refused (BackupRefused, nothing written) when the backup does not verify, dest is not new / empty, or one lies inside the other. Every file is copied with exclusive-create
    and hashed again from disk; empty runs/ ui/ folders are recreated; every monitor and mail switch of the copy is turned OFF (RESTORED). A failure after the folder was made
    leaves it as it is, listed in `problems` and in RESTORE-RECORD.json (complete: false): the caller reports it and touches nothing else."""
    backup, dest = Path(backup).resolve(), Path(dest).resolve()
    checked = verify(backup)
    if not checked['ok']:
        raise BackupRefused('バックアップの確認に失敗しました（不足 %d・不一致 %d・余分 %d%s）。復元しません' % (
            len(checked['missing']), len(checked['mismatch']), len(checked['extra']), '・' + ' '.join(checked['problems']) if checked['problems'] else ''))
    manifest = json.loads((backup / MANIFEST).read_text('utf-8'))
    files = manifest['files']
    if site is not None:
        if not isinstance(site, str) or not _SITE_RE.fullmatch(site):
            raise BackupRefused('指定したサイトが見つかりません')
        files = {rel: meta for rel, meta in files.items() if rel.startswith('sites/' + site + '/')}
        if not files:
            raise BackupRefused('このバックアップに、指定したサイトのファイルがありません')
    if _inside(dest, backup) or _inside(backup, dest):
        raise BackupRefused('復元先とバックアップが重なっています（別の新しいフォルダを指定してください）')
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise BackupRefused('復元先がすでにあります（新しいフォルダ、または空のフォルダだけ使えます。上書きしません）')
    here = dest
    while not here.exists():
        here = here.parent
    need = sum(meta['bytes'] for meta in files.values())
    if shutil.disk_usage(here).free < need + need // 10 + (1 << 20):
        raise BackupRefused('復元先の空き容量が足りません')
    dest.mkdir(parents=True, exist_ok=True)
    problems, copied_bytes, copied = [], 0, []
    for rel, meta in sorted(files.items()):
        target = dest / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            streamed, size, _ = _copy_plain(backup / rel, target)
            if streamed != meta['sha256'] or _sha256(target) != meta['sha256'] or size != meta['bytes']:
                problems.append('COPY_MISMATCH:' + rel)
                continue
        except OSError as exc:
            problems.append('COPY_FAILED:' + rel + ':' + type(exc).__name__)
            continue
        copied.append(rel)
        copied_bytes += size
    units = {'' if site is None and manifest.get('scope') == 'ALL' else None}
    units |= {m.group(1) for m in (re.match(r'(sites/[^/]+(?:/pages/[^/]+)?)/', rel) for rel in copied) if m}
    units.discard(None)
    for unit in sorted(units):
        for name in ('runs', 'ui'):  # empty folders are not part of a backup: the app expects them
            try:
                (dest / unit / name).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                problems.append('FOLDER_FAILED:' + (unit + '/' if unit else '') + name + ':' + type(exc).__name__)
    switched = []
    for rel in copied:
        key = _off_key(rel)
        if key is None:
            continue
        try:
            switched.append({'path': rel, **_switch_off(dest / rel, key)})
        except (OSError, ValueError):
            problems.append('NOT_SWITCHED_OFF:' + rel)  # a monitor that could not be turned off is a failed restore, never a quiet one
    complete = not problems
    record = {'schema': 'siteproof.restore-record.v1', 'restored_at': now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'source': str(backup),
              'backup_created_at': manifest.get('created_at'), 'scope': 'SITE' if site is not None or manifest.get('scope') == 'SITE' else 'ALL', 'site_id': site or manifest.get('site_id'),
              'files': len(copied), 'bytes': copied_bytes, 'complete': complete, 'problems': problems, 'switched_off': switched,
              'note': ['すべての監視（画像・HTTP）とメール通知は停止した状態です（理由 RESTORED）。内容を確認してから、必要なものだけ開始してください。',
                       '許可・許可の回数の記録・履歴は、バックアップの時点のままです。元のデータフォルダとこの復元したフォルダを、同時に使わないでください（回数・履歴がずれます）。',
                       '上の switched_off のファイルは、停止のため復元後に書き換えています（バックアップのSHA-256とは一致しません）。']}
    try:
        with open(dest / RESTORE_RECORD, 'x', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
            f.flush()
            os.fsync(f.fileno())
    except OSError as exc:
        problems.append('RECORD_FAILED:' + type(exc).__name__)
        complete = False
    return {'ok': complete and not problems, 'path': str(dest), 'files': len(copied), 'bytes': copied_bytes, 'switched_off': [s['path'] for s in switched], 'problems': problems}

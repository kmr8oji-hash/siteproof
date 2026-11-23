"""Minimal read-only code bundle for Browser-identity containers (S3-1-UNBLOCK). Host-side only; stdlib; no network.

Why: a Browser container that a real site can drive must not be able to read the development repository. The runtime image bakes an
older copy of the project into /opt/siteproof (src, tests, runtime, web) and the harness used to bind-mount the worktree's whole `src`
and `tests/runtime` over parts of it. Instead, the Browser gets ONE read-only bind of a staged directory over the whole /opt/siteproof:
exactly the Python files that its entry modules import (computed statically, relative imports included), nothing else.

stage_browser_bundle() refuses: a non-.py file, a symlink, a file outside the repository, anything that looks like a secret.
verify_bundle() re-reads the staged tree and compares it with the manifest (exact file set, SHA-256, no symlinks, nothing writable-by-design).
The fixture CA is not code and is never part of a bundle; real runs mount none.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re

# The Python entry modules that run under a Browser identity (UID 1000) in the S3 flow.
BROWSER_ENTRIES = ('tests/runtime/s3_browser.py', 'tests/runtime/s2b_browser.py', 'tests/runtime/s2h_probe.py', 'tests/runtime/s2a_probe.py')
SECRET = re.compile(rb'AKIA[0-9A-Z]{16}|aws_secret_access_key|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|xox[baprs]-[0-9A-Za-z-]{10,}')


# Docker Desktop on Windows cannot read a bind-mounted tree whose files have paths beyond about 260 characters (EIO inside the container).
# Checked BEFORE a run is counted against a permit: a refused placement costs nothing.
MAX_STAGED_PATH = 240


class BundleError(ValueError):
    pass


def _dotted(root, path):
    parts = path.relative_to(root).with_suffix('').parts
    return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts), parts[-1] == '__init__'


def _file_for(root, module):
    p = root.joinpath(*module.split('.')).with_suffix('.py')
    if p.is_file():
        return p
    p = root.joinpath(*module.split('.')) / '__init__.py'
    return p if p.is_file() else None


def import_closure(root, entries=BROWSER_ENTRIES):
    """{relative path: sorted importers}. Follows absolute and relative imports inside `src` and `tests` only."""
    root = Path(root).resolve()
    graph, done, todo = {}, set(), [root / e for e in entries]
    while todo:
        f = todo.pop()
        rel = f.relative_to(root).as_posix()
        graph.setdefault(rel, set())
        if rel in done:
            continue
        done.add(rel)
        package, is_init = _dotted(root, f)
        base = package if is_init else package.rsplit('.', 1)[0] if '.' in package else ''
        for node in ast.walk(ast.parse(f.read_text(encoding='utf-8'))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    anchor = base.split('.') if base else []
                    anchor = anchor[:len(anchor) - (node.level - 1)] if node.level > 1 else anchor
                    prefix = '.'.join(anchor + ([node.module] if node.module else []))
                else:
                    prefix = node.module or ''
                names = [prefix] + [prefix + '.' + a.name for a in node.names if prefix]
            for name in names:
                if not name.split('.')[0] in ('src', 'tests'):
                    continue
                target = _file_for(root, name)
                if target is None:
                    continue
                parts = name.split('.')
                needed = [target] + [p for i in range(1, len(parts)) for p in [_file_for(root, '.'.join(parts[:i]))] if p]
                for t in needed:
                    todo.append(t)
                    graph.setdefault(t.relative_to(root).as_posix(), set()).add(rel)
    return {k: sorted(v) for k, v in sorted(graph.items())}


def staged_path_problem(root, evidence, entries=BROWSER_ENTRIES, limit=MAX_STAGED_PATH, windows=None):
    """None, or a message for the user, when the bundle that will be staged under `evidence` has files whose paths exceed `limit`.

    Windows only (other systems have no such limit). Pure path arithmetic over the static import closure: no Docker, no file is written.
    """
    if not (os.name == 'nt' if windows is None else windows):
        return None
    tree = Path(evidence).resolve() / 'browser-bundle' / 'opt-siteproof'
    longest = max((len(str(tree / rel)) for rel in import_closure(Path(root).resolve(), entries)), default=len(str(tree)))
    if longest <= limit:
        return None
    return (f'証拠の保存先のパスが長すぎます（最長のファイルで{longest}文字、上限{limit}文字）。WindowsのDockerは、約260文字を超えるパスの'
            f'フォルダを読めず、撮影が始まる前に失敗します。データフォルダを短いパス（例：C:\\spe）に変えて（--data）やり直してください。'
            f'許可の回数は消費していません。')


def stage_browser_bundle(root, dest, entries=BROWSER_ENTRIES):
    """Copy the closure into dest/opt-siteproof (the tree to mount) and write dest/MANIFEST.json beside it (never mounted)."""
    root, dest = Path(root).resolve(), Path(dest).resolve()
    closure = import_closure(root, entries)
    tree = dest / 'opt-siteproof'
    tree.mkdir(parents=True, exist_ok=False)
    files = {}
    for rel, importers in closure.items():
        src = root / rel
        if src.is_symlink() or not src.is_file() or src.suffix != '.py' or root not in src.resolve().parents:
            raise BundleError('only plain .py files inside the repository may be staged: ' + rel)
        data = src.read_bytes()
        if SECRET.search(data):
            raise BundleError('secret-like content refused: ' + rel)
        out = tree / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        files[rel] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                      'why': 'entry module run under a Browser identity' if rel in entries else 'imported by ' + ', '.join(importers)}
    manifest = {'schema': 'siteproof.browser-bundle.v1', 'entries': list(entries), 'files': files, 'file_count': len(files),
                'mount': 'read-only bind of opt-siteproof over the whole /opt/siteproof (hides the image-baked project copy)',
                'excluded_by_construction': ['non-.py files (no CA, no JSON, no targets.json)', 'symlinks', 'anything not imported by an entry module']}
    (dest / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
    verify_bundle(dest)
    return tree, manifest


def verify_bundle(dest):
    dest = Path(dest)
    manifest = json.loads((dest / 'MANIFEST.json').read_text(encoding='utf-8'))
    tree, seen = dest / 'opt-siteproof', {}
    for p in sorted(tree.rglob('*')):
        if p.is_symlink():
            raise BundleError('symlink in bundle: ' + p.relative_to(tree).as_posix())
        if p.is_file():
            if p.suffix != '.py':
                raise BundleError('non-.py file in bundle: ' + p.relative_to(tree).as_posix())
            seen[p.relative_to(tree).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    expected = {k: v['sha256'] for k, v in manifest['files'].items()}
    if seen != expected:
        raise BundleError('bundle content differs from its manifest')
    return True


def mount_args(tree):
    """The ONE mount a Browser-identity container gets for project code."""
    return ['--mount', f'type=bind,src={Path(tree).resolve()},dst=/opt/siteproof,readonly']

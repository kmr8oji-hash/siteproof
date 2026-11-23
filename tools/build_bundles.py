"""Build deterministic deployment bundles into a NEW local directory. No upload, no AWS.

    py -3.15 -B tools/build_bundles.py <new-output-directory>

Outputs:
    lambda-bundle.zip    AWS-B probe + AWS-C controller/watchdog and their import closure
    worker-bundle.zip    AWS-C worker host sources (existing src/, runtime harness, seccomp)
    bundle-manifest.json per-file and per-archive SHA-256, git HEAD, dirty flag

Rules: explicit allowlists only (never the whole repository); the output directory must
not exist; links are refused; archives are byte-identical for identical inputs (fixed
timestamps, sorted names, LF line endings for text). A hash is an integrity value, not a
signature and not a USER approval. Uploading is a separate, approved, manual step.
"""
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".json", ".md", ".sh"}
EPOCH = (1980, 1, 1, 0, 0, 0)

LAMBDA_FILES = (
    ["src/aws_b/" + n for n in ("__init__.py", "handler.py", "model.py", "notify.py", "probe.py",
                                "store.py", "view.py")]
    + ["src/aws_c/" + n for n in ("__init__.py", "control.py", "controller.py",
                                  "watchdog.py")]
    + ["src/isolation/" + n for n in ("__init__.py", "destination.py", "connector.py")])
LAMBDA_DIRS = ["src/core"]
WORKER_DIRS = ["src", "tests/runtime", "runtime/docker"]
WORKER_FILES = ["tests/__init__.py", "tests/isolation/transport_fixtures.py"]
FORBIDDEN_PARTS = {".local", ".git", "secrets", "private", "__pycache__", "node_modules"}
FORBIDDEN_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".pem", ".key", ".log", ".env", ".pyc"}


def _expand(files, directories, suffixes):
    names = set(files)
    for directory in directories:
        base = ROOT / directory
        if not base.is_dir():
            raise SystemExit("missing directory: " + directory)
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                names.add(path.relative_to(ROOT).as_posix())
    return sorted(names)


def _read(name):
    path = ROOT / name
    parts = set(Path(name).parts)
    if parts & FORBIDDEN_PARTS or path.suffix in FORBIDDEN_SUFFIXES or ".." in parts:
        raise SystemExit("refused by policy: " + name)
    if path.is_symlink() or not path.is_file():
        raise SystemExit("not a regular file: " + name)
    resolved = path.resolve()
    if ROOT.resolve() not in resolved.parents:
        raise SystemExit("outside repository: " + name)
    data = path.read_bytes()
    if path.suffix in TEXT_SUFFIXES:
        data = data.replace(b"\r\n", b"\n")
    return data


def _archive(target, names):
    entries = {}
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            data = _read(name)
            info = zipfile.ZipInfo(name, date_time=EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
            entries[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return entries


def _git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def build(output):
    output = Path(output)
    if output.exists():
        raise SystemExit("output directory already exists; nothing is overwritten")
    if not output.parent.is_dir():
        raise SystemExit("parent of the output directory must exist")
    output.mkdir()
    manifest = {"schema": "siteproof.bundle-manifest.v1",
                "git_head": _git("rev-parse", "HEAD") or "UNKNOWN",
                "git_dirty": bool(_git("status", "--porcelain")),
                "line_endings": "LF for " + ",".join(sorted(TEXT_SUFFIXES)),
                "status": "LOCAL BUILD ONLY / NOT UPLOADED / NOT USER-APPROVED",
                "archives": {}}
    plans = {"lambda-bundle.zip": _expand(LAMBDA_FILES, LAMBDA_DIRS, {".py"}),
             "worker-bundle.zip": _expand(WORKER_FILES, WORKER_DIRS, {".py", ".json"})}
    for name, names in plans.items():
        entries = _archive(output / name, names)
        raw = (output / name).read_bytes()
        manifest["archives"][name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                                      "bytes": len(raw), "files": entries}
    (output / "bundle-manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    result = build(sys.argv[1])
    for archive_name, details in result["archives"].items():
        print(archive_name, details["sha256"], details["bytes"], len(details["files"]), "files")

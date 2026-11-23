"""Local single-writer artifact store: temp write -> no-overwrite publish -> read-back."""
from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.errors import ArtifactExistsError, EvidenceMismatch, StorageError
from ..core.model import validate_id
from .failpoints import Failpoints, hit

TMP_DIRNAME = "_tmp"


@dataclass(frozen=True)
class StoredFile:
    rel_path: str  # posix style, relative to the store root
    sha256: str
    byte_length: int


class ArtifactStore:
    """Layout: <root>/<job_id>/<attempt_id>/<name>; temp files in <root>/_tmp/ (same filesystem).

    Never overwrites, never deletes pre-existing files.
    """

    def __init__(self, root: str | os.PathLike[str], *,
                 failpoints: Optional[Failpoints] = None) -> None:
        self.root = Path(root).resolve()
        self._fp = failpoints

    def attempt_dir(self, job_id: str, attempt_id: str) -> Path:
        validate_id(job_id, "job_id")
        validate_id(attempt_id, "attempt_id")
        return self.root / job_id / attempt_id

    def resolve(self, rel_path: str) -> Path:
        p = (self.root / rel_path).resolve()
        if self.root != p and self.root not in p.parents:
            raise StorageError(f"path escapes store root: {rel_path!r}")
        return p

    def write_new(self, job_id: str, attempt_id: str, name: str, data: bytes) -> StoredFile:
        """Durably write `data` as a new file; fail if the destination exists; read it back."""
        if not name or "/" in name or "\\" in name or name.startswith(".") or name == TMP_DIRNAME:
            raise StorageError(f"invalid artifact name: {name!r}")
        adir = self.attempt_dir(job_id, attempt_id)
        dest = adir / name
        tmp_dir = self.root / TMP_DIRNAME
        tmp_dir.mkdir(parents=True, exist_ok=True)
        adir.mkdir(parents=True, exist_ok=True)
        tmp = tmp_dir / f"{uuid.uuid4().hex}.tmp"
        with open(tmp, "xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        hit(self._fp, "after_tmp_write")
        try:
            self._publish_no_overwrite(tmp, dest)
        except ArtifactExistsError:
            tmp.unlink(missing_ok=True)  # our own just-created temp file; holds no evidence
            raise
        hit(self._fp, "after_publish")
        self._fsync_dir(adir)
        stored = self.read_back(dest.relative_to(self.root).as_posix())
        expected = StoredFile(stored.rel_path, hashlib.sha256(data).hexdigest(), len(data))
        if stored != expected:
            raise EvidenceMismatch(f"read-back mismatch for {stored.rel_path}")
        return stored

    @staticmethod
    def _publish_no_overwrite(tmp: Path, dest: Path) -> None:
        # os.link fails atomically if dest exists (also on Windows/NTFS).
        try:
            os.link(tmp, dest)
        except FileExistsError as e:
            raise ArtifactExistsError(str(dest)) from e
        except OSError:
            if os.name != "nt":
                raise
            try:  # Windows rename refuses to replace an existing file
                os.rename(tmp, dest)
                return
            except FileExistsError as e:
                raise ArtifactExistsError(str(dest)) from e
        try:
            tmp.unlink()  # second name of the same inode; the data stays at dest
        except OSError:
            pass  # leftover temp name is reported by recovery, not hidden

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        if os.name == "nt":
            return  # directory fsync is not available on Windows; durability is unproven
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read_back(self, rel_path: str) -> StoredFile:
        data = self.read_bytes(rel_path)
        return StoredFile(rel_path, hashlib.sha256(data).hexdigest(), len(data))

    def read_bytes(self, rel_path: str) -> bytes:
        with open(self.resolve(rel_path), "rb") as f:
            return f.read()

    def exists(self, rel_path: str) -> bool:
        return self.resolve(rel_path).is_file()

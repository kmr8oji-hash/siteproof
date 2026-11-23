"""Read-only S1 capture evidence foundation; no baseline or comparison writes.

Existing Repository readers share one mode=ro SQLite read transaction. Existing
manifest verifiers are reused through a confined, bounded ArtifactStore reader.
Filesystem checks observe links/identity/content before returning, but do not
claim atomic filesystem+SQLite snapshots or protection from a hostile concurrent
filesystem administrator. Returned references must be reverified on later use.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import sqlite3
import stat

from src.comparison.profile import CaptureProfile, is_sha256_hex
from src.core.errors import (SiteProofError, StorageError, UnknownAttempt,
                             UnknownJob, ValidationError)
from src.core.frames import CheckType, FrameKind
from src.core.model import CheckOutcome, JobStatus, validate_id
from src.core.records import parse_record
from src.storage.artifacts import ArtifactStore
from src.storage.manifest import compare_with_db, verify_published
from src.storage.repository import Repository
from src.storage.schema import connect

from .s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
                             EvidenceReadResult, EvidenceRejection,
                             UnattestedProfileDeclaration, RejectionReason as R,
                             StructurallyCheckedCaptureEvidence,
                             UnattestedProfileFingerprint)


class _Rejected(Exception):
    def __init__(self, reason, detail=""):
        self.reason, self.detail = reason, detail


def _require(condition, reason, detail=""):
    if not condition:
        raise _Rejected(reason, detail)


class _PinnedRepository(Repository):
    """Reuse S1 read methods with its existing protected connection hook."""

    def __init__(self, conn):
        self._conn = conn

    @contextmanager
    def _read(self):
        yield self._conn


def _no_links(path):
    # Reject junctions and other Windows reparse points too, even if they currently
    # point inside the root. Do not resolve away their original lexical location.
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        _require(not stat.S_ISLNK(info.st_mode) and not (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), R.LINK_NOT_ALLOWED)


def _file_identity(info):
    dev, ino = getattr(info, "st_dev", None), getattr(info, "st_ino", None)
    _require(type(dev) is int and dev >= 0 and type(ino) is int and ino > 0,
             R.FILE_IDENTITY_UNAVAILABLE)
    links = getattr(info, "st_nlink", None)
    _require(type(links) is int, R.FILE_IDENTITY_UNAVAILABLE)
    _require(links == 1, R.LINK_NOT_ALLOWED)
    _require(stat.S_ISREG(info.st_mode), R.PATH_INVALID)
    return dev, ino


def _identity(info):
    # Birth time is creation time, NOT a metadata-change counter. Its availability
    # depends on Python/platform. Windows st_ctime_ns has legacy/deprecated
    # creation-time semantics; do not assume it detects metadata changes.
    # Times only supplement the file identity, link count and content rehash.
    birth = getattr(info, "st_birthtime_ns", None)
    change = info.st_ctime_ns if os.name != "nt" else None
    return (_file_identity(info), info.st_size, info.st_mtime_ns, birth, change)


_WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789\u00b9\u00b2\u00b3"
}


def _canonical_component(name):
    # Apply the Windows boundary rules on every host. A dot/extension does not
    # make a device name safe; spaces before that extension are aliases too.
    return (not name.endswith((".", " "))
            and not any(c in '<>"|?*' for c in name)
            and name.split(".", 1)[0].rstrip(" ").upper() not in _WINDOWS_DEVICES)


class _ConfinedStore(ArtifactStore):
    # Additional bridge refusal limits, not a change to the S1 storage contract.
    # S1's default ingest limit is 32 MiB per frame / 64 MiB total payload.
    _MAX_FILE = 32 * 1024 * 1024
    _MAX_TOTAL = 65 * 1024 * 1024  # Includes the manifest.

    def __init__(self, root, job_id, attempt_id):
        root = Path(root).absolute()
        _no_links(root)
        _require(root.is_dir(), R.PATH_INVALID)
        super().__init__(root)
        self.job_id, self.attempt_id = job_id, attempt_id
        self._cache = {}
        self._observations = {}  # ref -> ((st_dev, st_ino), hash of opened bytes)
        self._owners = {}  # physical identity -> exact ref, not a path-string set

    def checked_path(self, ref):
        _require(type(ref) is str and bool(ref), R.PATH_INVALID)
        _require(not PureWindowsPath(ref).drive and not PurePosixPath(ref).is_absolute(),
                 R.PATH_ESCAPE)
        _require("\\" not in ref and ":" not in ref and
                 not any(ord(c) < 32 or ord(c) == 127 for c in ref), R.PATH_INVALID)
        parts = ref.split("/")
        _require(len(parts) == 3 and all(p and p not in (".", "..") for p in parts),
                 R.PATH_INVALID)
        _require(all(_canonical_component(p) for p in parts), R.PATH_INVALID)
        _require(parts[:2] == [self.job_id, self.attempt_id], R.PATH_ESCAPE)
        path = self.root.joinpath(*parts)
        _no_links(path)
        parent = self.root
        for name in parts:
            with os.scandir(parent) as entries:
                exact = any(entry.name == name for entry in entries)
            # Reject case aliases and short names even if Win32 opens the file.
            _require(exact, R.PATH_INVALID)
            parent /= name
        resolved = path.resolve(strict=True)
        _require(resolved.is_relative_to(self.root)
                 and resolved.parent == self.root / self.job_id / self.attempt_id,
                 R.PATH_ESCAPE)
        _require(stat.S_ISREG(path.lstat().st_mode), R.PATH_INVALID)
        return path

    def _read_once(self, ref):
        path = self.checked_path(ref)
        before = path.lstat()
        before_state = _identity(before)
        _require(before.st_size <= self._MAX_FILE, R.READ_LIMIT_EXCEEDED)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            opened = os.fstat(handle.fileno())
            opened_state = _identity(opened)
            _require(before_state == opened_state, R.SOURCE_CHANGED)
            key = _file_identity(opened)
            _require(self._owners.get(key, ref) == ref, R.FILE_IDENTITY_DUPLICATE)
            data = handle.read(self._MAX_FILE + 1)
            _require(len(data) <= self._MAX_FILE, R.READ_LIMIT_EXCEEDED)
            digest = hashlib.sha256(data).hexdigest()
            _require(opened_state == _identity(os.fstat(handle.fileno())),
                     R.SOURCE_CHANGED)
            # Recheck the lexical name while the hashed file handle is open.
            after = self.checked_path(ref).lstat()
            _require(before_state == _identity(after) and len(data) == after.st_size,
                     R.SOURCE_CHANGED)
        observation = key, digest
        _require(self._observations.get(ref, observation) == observation,
                 R.SOURCE_CHANGED)
        self._observations[ref] = observation
        self._owners[key] = ref
        return data

    def read_bytes(self, ref):
        if ref not in self._cache:
            data = self._read_once(ref)
            _require(sum(map(len, self._cache.values())) + len(data) <= self._MAX_TOTAL,
                     R.READ_LIMIT_EXCEEDED)
            self._cache[ref] = data
        return self._cache[ref]

    def check_members(self, refs):
        directory = self.root / self.job_id / self.attempt_id
        _no_links(directory)
        for path in directory.iterdir():
            self.checked_path(path.relative_to(self.root).as_posix())
            _require(path.relative_to(self.root).as_posix() in refs, R.ORPHAN_EVIDENCE)

    def confirm_unchanged(self):
        for ref, data in self._cache.items():
            _require(self._read_once(ref) == data, R.SOURCE_CHANGED)


def _file(row):
    return EvidenceFile(row.rel_path, row.sha256, row.byte_length)


def _artifact(row):
    return EvidenceArtifact(row.seq, row.kind.value, row.check_type.value, _file(row))


def _read(conn, evidence_root, job_id, attempt_id, binding, payload=None):
    repo = _PinnedRepository(conn)
    try:
        job = repo.get_job(job_id)
    except StorageError as e:
        raise _Rejected(R.SNAPSHOT_INVALID) from e
    snap = job.snapshot
    _require(job.status is JobStatus.COMPLETED, R.JOB_NOT_COMPLETED)
    _require(job.adopted_attempt_id is not None, R.NO_ADOPTED_ATTEMPT)
    _require(attempt_id is None or attempt_id == job.adopted_attempt_id,
             R.ATTEMPT_NOT_ADOPTED)
    attempt = repo.get_attempt(job_id, job.adopted_attempt_id)
    _require(attempt.job_id == job_id and attempt.attempt_id == job.adopted_attempt_id
             and attempt == repo.latest_attempt(job_id), R.ATTEMPT_MISMATCH)
    raw = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    _require((raw["page_id"], raw["profile_id"], raw["baseline_id"], raw["created_at"],
              raw["required_checks"]) ==
             (snap.page_id, snap.profile_id, snap.baseline_id, snap.created_at,
              ",".join(c.value for c in snap.required_checks)), R.SNAPSHOT_INVALID)
    required = tuple(CheckType(r[0]) for r in conn.execute(
        "SELECT check_type FROM job_required_checks WHERE job_id=?", (job_id,)))
    _require(CheckType.CAPTURE in snap.required_checks, R.CAPTURE_NOT_SUCCEEDED)
    checks = repo.list_check_results(job_id, attempt.attempt_id)
    rows = repo.list_artifacts(job_id, attempt.attempt_id)
    manifest = repo.get_manifest_row(job_id, attempt.attempt_id)
    _require(manifest is not None, R.MANIFEST_MISSING)
    _require(len({r.seq for r in rows}) == len(rows)
             and len({(r.check_type, r.kind) for r in rows}) == len(rows)
             and len({r.rel_path for r in rows}) == len(rows)
             and manifest.rel_path not in {r.rel_path for r in rows}
             and len({c.check_type for c in checks}) == len(checks), R.EVIDENCE_AMBIGUOUS)
    for row in [manifest, *rows]:
        _require(is_sha256_hex(row.sha256) and type(row.byte_length) is int
                 and row.byte_length > 0, R.DB_RECORD_INVALID)
    _require(manifest.rel_path == f"{job_id}/{attempt.attempt_id}/manifest.json",
             R.PATH_INVALID)
    for c in checks:
        _require((c.job_id, c.attempt_id, c.page_id, c.profile_id) ==
                 (job_id, attempt.attempt_id, snap.page_id, snap.profile_id),
                 R.IDENTITY_MISMATCH)
    for a in rows:
        _require((a.page_id, a.profile_id) == (snap.page_id, snap.profile_id),
                 R.IDENTITY_MISMATCH)
    pngs = [a for a in rows if a.kind is FrameKind.SCREENSHOT_PNG
            and a.check_type is CheckType.CAPTURE]
    records = [a for a in rows if a.kind is FrameKind.CAPTURE_RECORD
               and a.check_type is CheckType.CAPTURE]
    _require(len(pngs) == 1 and len(records) == 1, R.EVIDENCE_MISSING)
    store = _ConfinedStore(evidence_root, job_id, attempt.attempt_id)
    refs = {manifest.rel_path, *(r.rel_path for r in rows)}
    for ref in refs:
        store.checked_path(ref)
    store.check_members(refs)
    doc = verify_published(store, rows, manifest, snap, attempt)
    problems = compare_with_db(doc, snap, checks, rows, required)
    _require(not problems, R.EVIDENCE_MISMATCH, ";".join(problems))
    rec = parse_record(FrameKind.CAPTURE_RECORD, store.read_bytes(records[0].rel_path))
    capture_checks = [c for c in checks if c.check_type is CheckType.CAPTURE]
    _require(rec.state == "SUCCEEDED" and len(capture_checks) == 1
             and capture_checks[0].outcome is CheckOutcome.UNKNOWN,
             R.CAPTURE_NOT_SUCCEEDED)
    origin = EvidenceOrigin(job_id, attempt.attempt_id, attempt.lease_epoch,
                            snap.sha256, snap.intent.intent_hash, snap.page_id,
                            snap.profile_id, snap.baseline_id)
    _require(binding is not None, R.PROFILE_DECLARATION_MISSING)
    _require(type(binding) is UnattestedProfileDeclaration, R.PROFILE_DECLARATION_MISMATCH)
    _require(type(binding.declared_profile) is CaptureProfile
             and binding.declared_profile.is_intact()
             and binding.declared_profile.profile_id == snap.profile_id
             and binding.origin == origin and binding.screenshot == _file(pngs[0])
             and binding.manifest == _file(manifest),
             R.PROFILE_DECLARATION_MISMATCH)
    fingerprint = binding.declared_profile.fingerprint
    _require(is_sha256_hex(binding.declared_fingerprint)
             and binding.declared_fingerprint == fingerprint,
             R.PROFILE_DECLARATION_MISMATCH)
    store.confirm_unchanged()
    store.check_members(refs)
    if payload is not None:
        payload.append(store.read_bytes(pngs[0].rel_path))
    return StructurallyCheckedCaptureEvidence(
        origin, _file(manifest), _artifact(records[0]), _artifact(pngs[0]),
        UnattestedProfileFingerprint(fingerprint))


def _observe(db_path, evidence_root, job_id, *, profile_declaration=None,
             attempt_id=None, payload=None) -> EvidenceReadResult:
    """Read only the adopted capture, or return a reasoned refusal.

    ``attempt_id`` is an optional assertion, never an alternative selection.
    Profiles are caller-supplied UNATTESTED declarations. Validation only checks
    internal consistency, never the authenticity of capture-time conditions.
    Success MUST NOT be used for trusted profile compatibility, baseline
    registration/approval, trusted comparison, or CAPTURE PASS/CHANGED.
    No candidate registration, approval, ComparisonRequest or CheckOutcome write
    occurs. A missing declaration is a refusal, not an inferred profile.
    """
    try:
        validate_id(job_id, "job_id")
        if attempt_id is not None:
            validate_id(attempt_id, "attempt_id")
        # A missing DB is never implicitly created by a Repository read.
        conn = connect(db_path, read_only=True)
        try:
            conn.execute("PRAGMA query_only = ON")
            conn.execute("BEGIN")
            evidence = _read(conn, evidence_root, job_id, attempt_id, profile_declaration, payload)
        finally:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
            finally:
                conn.close()
        return EvidenceReadResult(evidence=evidence)
    except _Rejected as e:
        return EvidenceReadResult(rejection=EvidenceRejection(e.reason, e.detail))
    except UnknownJob:
        reason = R.JOB_NOT_FOUND
    except UnknownAttempt:
        reason = R.ATTEMPT_MISMATCH
    except ValidationError:
        reason = R.INVALID_INPUT
    except FileNotFoundError:
        reason = R.EVIDENCE_MISSING
    except SiteProofError:
        reason = R.EVIDENCE_MISMATCH
    except (OSError, sqlite3.Error):
        reason = R.SOURCE_UNREADABLE
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        reason = R.DB_RECORD_INVALID
    return EvidenceReadResult(rejection=EvidenceRejection(reason))


def read_s1_capture(db_path, evidence_root, job_id, *, profile_declaration=None,
                    attempt_id=None) -> EvidenceReadResult:
    """Read adopted structural evidence. Declarations remain UNATTESTED."""
    return _observe(db_path, evidence_root, job_id, profile_declaration=profile_declaration,
                    attempt_id=attempt_id)


def read_s1_capture_payload(db_path, evidence_root, job_id, *, profile_declaration=None):
    """Return verified PNG bytes from the SAME bounded observation as the manifest.

    No profile authentication is implied. M4 must independently validate its
    pre-capture plan and trusted receipt before a quality comparison is eligible.
    Legacy S2 refusal adapters remain refusal-only.
    """
    payload = []
    result = _observe(db_path, evidence_root, job_id,
                      profile_declaration=profile_declaration, payload=payload)
    return result, payload[0] if result.accepted else None

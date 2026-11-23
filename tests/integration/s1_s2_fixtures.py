"""Fresh, dedicated synthetic S0 -> S1 evidence; never opens development DBs."""

import hashlib
from contextlib import closing
import itertools
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from src.bridge import EvidenceBridge
from src.bridge.s1_s2_contract import EvidenceFile, EvidenceOrigin, UnattestedProfileDeclaration
from src.comparison.profile import CaptureProfile
from src.core.frames import FrameKind
from src.storage.artifacts import ArtifactStore
from src.storage.failpoints import Failpoints
from src.storage.finalizer import CommitState, EvidenceFinalizer
from src.storage.manifest import manifest_bytes
from src.storage.repository import Repository
from tests.integration.fixtures import complete
from tests.integration.support import IntegrationCase


def fixture_root():
    root = Path(tempfile.gettempdir())
    if root.name != "siteproof-s1s2-bridge-foundation-01":
        root /= "siteproof-s1s2-bridge-foundation-01"
    root.mkdir(parents=True, exist_ok=True)
    return root


def directory_link(link, target):
    """Exercise actual links, without commands, elevation or host configuration."""
    if os.name == "nt":
        # Junction creation needs no symlink privilege. Both are reparse points.
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


class FoundationCase(IntegrationCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="capture-", dir=fixture_root())
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.fp = Failpoints()
        self.ids = itertools.count(1)
        self.repo = Repository(self.base / "s1.sqlite3",
                               id_factory=lambda: f"job-{next(self.ids)}", failpoints=self.fp)
        self.repo.init()
        self.store = ArtifactStore(self.base / "evidence", failpoints=self.fp)
        self.finalizer = EvidenceFinalizer(self.repo, self.store, failpoints=self.fp)
        self.bridge = EvidenceBridge(self.finalizer)
        self.saved, self.attempt = self.completed()
        self.png = next(a for a in self.repo.list_artifacts(
            self.saved.job_id, self.attempt.attempt_id) if a.kind is FrameKind.SCREENSHOT_PNG)
        self.binding = self.binding_for(self.saved, self.attempt)

    def completed(self, baseline=None, *, older_attempt=False):
        job, attempt = self.job(baseline=baseline)
        if older_attempt:
            attempt = self.repo.register_attempt(job.job_id, "attempt-2", 2)
        result = self.run_wire(job, attempt, complete(baseline))
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        return self.repo.get_job(job.job_id), attempt

    def binding_for(self, job, attempt):
        # Synthetic declaration only: S1 persisted no authenticated profile.
        profile = CaptureProfile(job.snapshot.profile_id, {
            "viewport_width": 1366, "viewport_height": 768, "device_scale_factor": 1,
            "color_scheme": "light", "locale": "ja-JP", "timezone": "Asia/Tokyo",
            "user_agent": "offline-fixture/1", "reduced_motion": True, "full_page": False,
        })
        png = next(a for a in self.repo.list_artifacts(job.job_id, attempt.attempt_id)
                   if a.kind is FrameKind.SCREENSHOT_PNG)
        snap = job.snapshot
        origin = EvidenceOrigin(job.job_id, attempt.attempt_id, attempt.lease_epoch,
                                snap.sha256, snap.intent.intent_hash, snap.page_id,
                                snap.profile_id, snap.baseline_id)
        manifest = self.repo.get_manifest_row(job.job_id, attempt.attempt_id)
        return UnattestedProfileDeclaration(origin, EvidenceFile(png.rel_path, png.sha256,
                                                         png.byte_length),
                                     profile, profile.fingerprint,
                                     EvidenceFile(manifest.rel_path, manifest.sha256,
                                                  manifest.byte_length))

    def screenshot_ref(self, filename, *, rename_file=False):
        """Coherently rewrite only this fresh fixture, including declaration pins.

        Keeping the real filename unchanged permits actual Win32 alias probes.
        These rewritten pins are untrusted declarations, never provenance.
        """
        import json
        old_ref = self.png.rel_path
        new_ref = old_ref.rsplit("/", 1)[0] + "/" + filename
        if rename_file:
            (self.store.root / old_ref).rename(self.store.root / new_ref)
        self.corrupt_db("UPDATE artifacts SET rel_path=? WHERE kind='SCREENSHOT_PNG'",
                        (new_ref,))
        manifest = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        path = self.store.root / manifest.rel_path
        doc = json.loads(path.read_bytes())
        next(a for a in doc["artifacts"] if a["kind"] == "SCREENSHOT_PNG")["rel_path"] = new_ref
        raw = manifest_bytes(doc)
        path.write_bytes(raw)
        self.corrupt_db("UPDATE manifests SET sha256=?, byte_length=?",
                        (hashlib.sha256(raw).hexdigest(), len(raw)))
        self.png = next(a for a in self.repo.list_artifacts(
            self.saved.job_id, self.attempt.attempt_id) if a.kind is FrameKind.SCREENSHOT_PNG)
        self.binding = self.binding_for(self.saved, self.attempt)

    def corrupt_db(self, sql, args=()):
        # Corrupt only this test's fresh DB, as existing S1 recovery fixtures do.
        with closing(sqlite3.connect(self.repo.db_path)) as conn, conn:
            triggers = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
            for (name,) in triggers:
                conn.execute('DROP TRIGGER "' + name + '"')
            conn.execute(sql, args)

    def snapshot(self):
        """Hash fixture files without following any injected link/junction."""
        found = {}

        def walk(directory):
            for p in directory.iterdir():
                info = p.lstat()
                rel = p.relative_to(self.base).as_posix()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
                        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                    found[rel] = ("link", os.readlink(p))
                elif p.is_dir():
                    walk(p)
                else:
                    found[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

        walk(self.base)
        return found

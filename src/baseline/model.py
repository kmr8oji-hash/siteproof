"""Immutable baseline candidate (pure; no I/O)."""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from src.comparison.profile import is_clean_text, is_sha256_hex


class CandidateError(ValueError):
    """Candidate field is missing or malformed."""


class BaselineStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class BaselineCandidate:
    candidate_id: str
    page_id: str
    profile_fingerprint: str
    artifact_ref: str
    artifact_sha256: str

    def __post_init__(self):
        for name in ("candidate_id", "page_id", "artifact_ref"):
            if not is_clean_text(getattr(self, name)):
                raise CandidateError(f"invalid {name}")
        for name in ("profile_fingerprint", "artifact_sha256"):
            if not is_sha256_hex(getattr(self, name)):
                raise CandidateError(f"invalid {name}: expected lowercase sha256 hex")

    def is_intact(self) -> bool:
        """Re-validate stored fields (they may have been altered after construction)."""
        values = vars(self)
        text = ("candidate_id", "page_id", "artifact_ref")
        hexes = ("profile_fingerprint", "artifact_sha256")
        return all(n in values and is_clean_text(values[n]) for n in text) and all(
            n in values and is_sha256_hex(values[n]) for n in hexes
        )

    @property
    def digest(self) -> str:
        """Content digest over every field; any alteration changes it."""
        body = {
            "schema": "siteproof.baseline.candidate.v1",
            "candidate_id": self.candidate_id,
            "page_id": self.page_id,
            "profile_fingerprint": self.profile_fingerprint,
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

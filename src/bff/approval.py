"""Gateway-only approval of an existing candidate; no schema or identity service.

The trusted local starter supplies actor. It denotes that local operator, not a
verified real-world identity. HTTP clients cannot choose it. Store.decide owns
the transaction, both revision checks, immutable versions and one-shot decisions.
Its writes cannot forcibly interrupt an OS/filesystem stall; a missing reply is
ambiguous and must be reconciled through GET, never automatically retried.
"""

import re
import threading
import time

from src.baseline.approval import (AlreadyDecided, ApprovalError, CandidateTampered,
    RevisionConflict, UnknownCandidate, _is_human_actor)
from src.baseline.model import BaselineStatus
from src.baseline.sqlite_store import (AmbiguousBaselineCommit, BaselineStoreError,
                                      SQLiteBaselineStore)
from .baseline import _RequestFailure
from src.storage.m1 import M1Error


class LocalApproval:
    def __init__(self, db_path, storage_root, actor, candidate_validator=None):
        if actor is not None and not _is_human_actor(actor):
            raise ValueError("explicit local operator required")
        self._path, self._root, self._actor = db_path, storage_root, actor
        self._lock = threading.Lock()
        self._candidate_validator = candidate_validator

    @property
    def enabled(self):
        return self._actor is not None

    def approve(self, obj, session, credential, deadline, max_db_bytes):
        fields = {"candidate_id", "expected_revision", "reviewed_digest",
                  "expected_current_version", "confirmed"}
        if (type(obj) is not dict or set(obj) != fields
                or type(obj["candidate_id"]) is not str or not obj["candidate_id"]
                or len(obj["candidate_id"]) > 2048
                or obj["candidate_id"] != obj["candidate_id"].strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in obj["candidate_id"])
                or type(obj["reviewed_digest"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", obj["reviewed_digest"])
                or any(type(obj[k]) is not int or not 0 <= obj[k] <= 9007199254740991
                       for k in ("expected_revision", "expected_current_version"))):
            raise _RequestFailure(400, "INVALID_APPROVAL")
        if obj["confirmed"] is not True:
            raise _RequestFailure(400, "CONFIRMATION_REQUIRED")
        if not self.enabled:
            raise _RequestFailure(503, "APPROVAL_UNAVAILABLE")
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise _RequestFailure(503, "APPROVAL_UNAVAILABLE")
        try:
            if not session.accepts(credential):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            store = SQLiteBaselineStore(self._path, self._root)
            if store.path.stat().st_size > max_db_bytes:
                raise BaselineStoreError("DB size limit")
            item = store.read_page(limit=1, candidate_id=obj["candidate_id"],
                                   deadline=deadline).items[0]
            record = item.record
            if (record.revision != obj["expected_revision"]
                    or record.status is not BaselineStatus.PENDING
                    or (item.current_version or 0) != obj["expected_current_version"]):
                raise RevisionConflict()
            if record.registered_digest != obj["reviewed_digest"]:
                raise CandidateTampered()
            if obj['candidate_id'].startswith('capture-'):
                if self._candidate_validator is None:
                    raise _RequestFailure(503, 'COMPARISON_UNAVAILABLE')
                self._candidate_validator(obj['candidate_id'])
            if not session.accepts(credential):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            if time.monotonic() >= deadline:
                raise _RequestFailure(503, "APPROVAL_UNAVAILABLE")
            store.decide(obj["candidate_id"], decision=BaselineStatus.APPROVED,
                actor=self._actor, expected_revision=obj["expected_revision"],
                reviewed_digest=obj["reviewed_digest"],
                expected_current_version=obj["expected_current_version"])
            return {"approved": True}
        except (RevisionConflict, AlreadyDecided):
            raise _RequestFailure(409, "REVISION_CONFLICT") from None
        except CandidateTampered:
            raise _RequestFailure(422, "DIGEST_MISMATCH") from None
        except UnknownCandidate:
            raise _RequestFailure(404, "NOT_FOUND") from None
        except AmbiguousBaselineCommit:
            raise _RequestFailure(503, "RESULT_UNKNOWN") from None
        except ApprovalError:
            raise _RequestFailure(400, "APPROVAL_REJECTED") from None
        except (BaselineStoreError, OSError, TimeoutError):
            raise _RequestFailure(503, "APPROVAL_UNAVAILABLE") from None
        except M1Error as exc:
            raise _RequestFailure(exc.status, exc.code) from None
        finally:
            self._lock.release()

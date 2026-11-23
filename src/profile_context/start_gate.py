"""Readback-before-simulated-start gate; never invokes or attests S0/S1/browser.

A permission is local and one-shot in this honest dedicated ledger. A crash
after reservation can leave a consumed reservation without any execution; retry
then returns UNKNOWN. No automatic recovery or production credential is issued.
Legacy jobs with no context remain UNATTESTED and cannot use this offline gate.
Even a coherent context cannot prove new-intake provenance. The optional
provenance requirement therefore returns UNKNOWN without touching the ledger.
"""

from dataclasses import dataclass
from enum import Enum

from src.bridge.s1_s2_contract import ProfileTrust, UnattestedProfileError
from .sqlite_store import SQLiteContextStore, StoreError, StoreReason


class StartStatus(str, Enum):
    AUTHORIZED_SIMULATION = "AUTHORIZED_SIMULATION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class StartDecision:
    status: StartStatus
    reason: str
    context_sha256: str | None = None
    decision_id: str | None = None

    @property
    def trust(self):
        return ProfileTrust.UNATTESTED

    @property
    def intake_provenance_status(self):
        """No caller-supplied record proves when/how a job was accepted."""
        return StartStatus.UNKNOWN

    @property
    def lease_fencing_status(self):
        """The final readback is a snapshot, never a continuing execution lease."""
        return StartStatus.UNKNOWN

    def require_trusted_use(self, operation):
        raise UnattestedProfileError("simulated start is not capture/profile attestation")


def request_simulated_start(store, spec, context, *, require_intake_provenance=False):
    """Persist and independently read back before reserving a simulated start.

    Exact registration retries are safe; a reserved start is NEVER re-granted,
    even when a previous reply was lost. This is no evidence of actual capture.
    Caller-supplied objects and hashes do not create independent profile trust.
    Freshness is checked at the final independent read transaction, not forever:
    another caller may register a newer epoch immediately afterwards. This gate
    provides no continuing lease fencing or permission to start a real browser.
    Existing three-argument calls retain simulation-only semantics. Callers
    requiring verified new intake must opt in; no available record can satisfy
    that requirement. A boolean or a declared timestamp cannot confer trust.
    """
    if spec is None or context is None:
        return StartDecision(StartStatus.UNKNOWN, "LEGACY_PROFILE_CONTEXT_MISSING")
    if type(store) is not SQLiteContextStore:
        return StartDecision(StartStatus.UNKNOWN, StoreReason.INVALID_INPUT.value)
    if type(require_intake_provenance) is not bool:
        return StartDecision(StartStatus.UNKNOWN, StoreReason.INVALID_INPUT.value)
    if require_intake_provenance:
        return StartDecision(StartStatus.UNKNOWN, "INTAKE_PROVENANCE_UNVERIFIED")
    try:
        registration = store.register(spec, context)
        # Use defensive validated records returned from independent readback.
        record = registration.record
        decision = store.reserve_simulated_start(record.spec, record.context)
        return StartDecision(StartStatus.AUTHORIZED_SIMULATION, "OFFLINE_LEDGER_READBACK_ONLY",
                             record.context.sha256, decision)
    except StoreError as error:
        return StartDecision(StartStatus.UNKNOWN, error.reason.value)
    except Exception:
        return StartDecision(StartStatus.UNKNOWN, StoreReason.UNAVAILABLE.value)

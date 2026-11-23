"""Capture/Comparison profiles and strict fingerprint compatibility (pure; no I/O).

A fingerprint is SHA-256 over canonical JSON of (kind, attributes). ``profile_id`` is a
label only and never participates in compatibility. Missing, unknown or mistyped
attributes are rejected; nothing is defaulted.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping

_SCHEMA = "siteproof.profile.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_TEXT = 2048

_POS_INT = "pos_int"
_TEXT = "text"
_BOOL = "bool"
_SHA256 = "sha256"


class ProfileError(ValueError):
    """Profile id/attributes are missing, unknown, or of the wrong type."""


class ProfileKind(str, Enum):
    CAPTURE = "capture"
    COMPARISON = "comparison"


_SCHEMAS = {
    ProfileKind.CAPTURE: {
        "viewport_width": _POS_INT,
        "viewport_height": _POS_INT,
        "device_scale_factor": _POS_INT,
        "color_scheme": _TEXT,
        "locale": _TEXT,
        "timezone": _TEXT,
        "user_agent": _TEXT,
        "reduced_motion": _BOOL,
        "full_page": _BOOL,
    },
    ProfileKind.COMPARISON: {
        "capture_fingerprint": _SHA256,
        "method": _TEXT,
        "method_version": _TEXT,
        "threshold_policy": _TEXT,
    },
}


def is_clean_text(value) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= _MAX_TEXT
        and value == value.strip()
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def is_sha256_hex(value) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _valid(rule: str, value) -> bool:
    if rule == _POS_INT:
        return type(value) is int and value > 0
    if rule == _BOOL:
        return type(value) is bool
    if rule == _SHA256:
        return is_sha256_hex(value)
    return is_clean_text(value)


def _normalise(kind: ProfileKind, attributes) -> Mapping[str, object]:
    if not isinstance(attributes, Mapping):
        raise ProfileError("attributes must be a mapping")
    schema = _SCHEMAS[kind]
    # One snapshot: validation and the returned mapping read the same values.
    snapshot = dict(attributes)
    keys = set(snapshot)
    if not all(type(k) is str for k in keys):
        raise ProfileError("attribute names must be strings")
    unknown = sorted(keys - set(schema))
    if unknown:
        raise ProfileError(f"unknown attributes: {unknown}")
    missing = sorted(set(schema) - keys)
    if missing:
        raise ProfileError(f"missing attributes: {missing}")
    for name, rule in schema.items():
        if not _valid(rule, snapshot[name]):
            raise ProfileError(f"invalid value for attribute {name!r}")
    return MappingProxyType({name: snapshot[name] for name in sorted(schema)})


@dataclass(frozen=True)
class _Profile:
    profile_id: str
    attributes: Mapping[str, object]

    KIND = None  # set by subclasses

    def __post_init__(self):
        if not is_clean_text(self.profile_id):
            raise ProfileError("profile_id must be a clean non-empty string")
        object.__setattr__(self, "attributes", _normalise(self.KIND, self.attributes))

    @property
    def kind(self) -> ProfileKind:
        return type(self).KIND

    def _validated_attributes(self) -> dict:
        """Re-validates the internal state (it can be corrupted via ``object.__setattr__``).

        Returns a validated snapshot or raises ProfileError. Only the class-level kind is
        trusted; an instance-level shadow of KIND, extra/missing fields, a swapped
        attributes container or an invalid value all count as corruption.
        """
        cls = type(self)
        if _CONCRETE_KINDS.get(cls) is not cls.KIND:
            raise ProfileError("unsupported profile class")
        state = vars(self)
        if type(state) is not dict or set(state) != {"profile_id", "attributes"}:
            raise ProfileError("profile state is corrupt: unexpected fields")
        if not is_clean_text(state["profile_id"]):
            raise ProfileError("profile state is corrupt: profile_id")
        attributes = state["attributes"]
        if type(attributes) is not MappingProxyType:
            raise ProfileError("profile state is corrupt: attributes container")
        return dict(_normalise(cls.KIND, attributes))

    def is_intact(self) -> bool:
        try:
            self._validated_attributes()
        except ProfileError:
            return False
        return True

    @property
    def fingerprint(self) -> str:
        attributes = self._validated_attributes()
        body = {"schema": _SCHEMA, "kind": type(self).KIND.value, "attributes": attributes}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CaptureProfile(_Profile):
    KIND = ProfileKind.CAPTURE


@dataclass(frozen=True)
class ComparisonProfile(_Profile):
    KIND = ProfileKind.COMPARISON


# Exact classes only: a subclass could override ``fingerprint`` / ``kind``.
_CONCRETE_KINDS = {CaptureProfile: ProfileKind.CAPTURE, ComparisonProfile: ProfileKind.COMPARISON}


@dataclass(frozen=True)
class ProfileCompatibility:
    compatible: bool
    reason: str


def check_profile_compatibility(expected, actual) -> ProfileCompatibility:
    """Strict: same kind and identical fingerprint. ``profile_id`` is ignored."""
    for p in (expected, actual):
        if not isinstance(p, _Profile):
            return ProfileCompatibility(False, "NOT_A_PROFILE")
        if not p.is_intact():
            # A corrupted profile is not a valid profile; never matched by profile_id or kind.
            return ProfileCompatibility(False, "NOT_A_PROFILE")
    if expected.kind is not actual.kind:
        return ProfileCompatibility(False, "KIND_MISMATCH")
    if expected.fingerprint != actual.fingerprint:
        return ProfileCompatibility(False, "FINGERPRINT_MISMATCH")
    return ProfileCompatibility(True, "FINGERPRINT_MATCH")

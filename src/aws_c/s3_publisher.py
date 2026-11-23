"""Write-once publication of evidence bytes to S3, with service-side checksum and read-back.

The local write-once store (src/storage/artifacts.py) is unchanged; this adds a second,
durable publication step with the same rules: never overwrite, never delete, read back
what was written and compare hashes, and report anything uncertain as uncertain.

    PUT  If-None-Match: *  +  x-amz-checksum-sha256   (S3 rejects a wrong body or an
                                                       existing key)
    GetObjectAttributes -> stored SHA-256 must equal the local SHA-256
    GetObject           -> bytes re-hashed locally (optional, on by default)
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Optional

_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,900}\Z", re.ASCII)
MAX_OBJECT_BYTES = 64 * 1024 * 1024

PUBLISHED = "PUBLISHED"
EXISTS_IDENTICAL = "EXISTS_IDENTICAL"      # same bytes already there: idempotent re-run
CONFLICT = "CONFLICT"                      # different bytes already there: never replaced
UNCERTAIN = "UNCERTAIN"                    # outcome unknown; treated as not published
MISMATCH = "READBACK_MISMATCH"
REJECTED = "REJECTED"


@dataclass(frozen=True)
class Published:
    status: str
    key: str
    sha256: Optional[str] = None
    byte_length: Optional[int] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status in (PUBLISHED, EXISTS_IDENTICAL)


def _code(exc: BaseException) -> Optional[str]:
    response = getattr(exc, "response", None)
    if isinstance(response, dict) and isinstance(response.get("Error"), dict):
        return response["Error"].get("Code")
    return None


def _b64(digest: bytes) -> str:
    return base64.b64encode(digest).decode("ascii")


class S3Publisher:
    def __init__(self, client: Any, bucket: str, prefix: str, *, read_back: bool = True):
        if not _KEY_RE.fullmatch(prefix) or not prefix.endswith("/") or ".." in prefix:
            raise ValueError("prefix must be a plain key prefix ending with '/'")
        self._client, self._bucket, self._prefix, self._read_back = (
            client, bucket, prefix, read_back)

    def key_for(self, relative: str) -> str:
        if (type(relative) is not str or not _KEY_RE.fullmatch(relative)
                or ".." in relative or relative.startswith("/") or "//" in relative):
            raise ValueError(f"invalid evidence name: {relative!r}")
        return self._prefix + relative

    def publish(self, relative: str, data: bytes, *,
                content_type: str = "application/octet-stream") -> Published:
        try:
            key = self.key_for(relative)
        except ValueError as exc:
            return Published(REJECTED, str(relative), error=str(exc))
        if type(data) is not bytes or len(data) > MAX_OBJECT_BYTES:
            return Published(REJECTED, key, error="payload type or size")
        digest = hashlib.sha256(data).digest()
        hex_digest, checksum = digest.hex(), _b64(digest)
        try:
            self._client.put_object(
                Bucket=self._bucket, Key=key, Body=data, IfNoneMatch="*",
                ChecksumAlgorithm="SHA256", ChecksumSHA256=checksum,
                ContentType=content_type, Metadata={"sha256": hex_digest})
            created = True
        except Exception as exc:
            code = _code(exc)
            if code not in ("PreconditionFailed", "ConditionalRequestConflict"):
                # Includes timeouts and lost acknowledgements: the object may exist.
                # Resolve from what S3 actually holds; never retry the write blindly.
                verdict = self._verify(key, checksum, data)
                if verdict == PUBLISHED:
                    return Published(PUBLISHED, key, hex_digest, len(data))
                return Published(UNCERTAIN, key, error=code or type(exc).__name__)
            created = False
        verdict = self._verify(key, checksum, data)
        if verdict == PUBLISHED:
            return Published(PUBLISHED if created else EXISTS_IDENTICAL, key,
                             hex_digest, len(data))
        if not created and verdict == MISMATCH:
            return Published(CONFLICT, key)
        return Published(verdict, key)

    def _verify(self, key: str, checksum: str, data: bytes) -> str:
        try:
            attributes = self._client.get_object_attributes(
                Bucket=self._bucket, Key=key, ObjectAttributes=["Checksum", "ObjectSize"])
            stored = attributes.get("Checksum", {}).get("ChecksumSHA256")
            if stored != checksum or attributes.get("ObjectSize") != len(data):
                return MISMATCH
            if self._read_back:
                body = self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read(
                    MAX_OBJECT_BYTES + 1)
                if body != data:
                    return MISMATCH
        except Exception:
            return UNCERTAIN
        return PUBLISHED

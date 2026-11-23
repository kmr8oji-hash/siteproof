"""Signature adapter for the AWS-C run manifest (CANDIDATE; cost and need to be approved).

The existing M4/M5 plan/receipt binding is an HMAC with a key held only in the trusted
worker's memory: it proves integrity to that process and cannot be verified once the key
is gone. For evidence that outlives the instance, an asymmetric KMS key lets the worker
role sign (kms:Sign only) while anyone holding the public key can verify later.

A signature covers the bytes of the run manifest. It says who published which hashes; it
does NOT attest how the browser rendered a page. PROFILE_UNATTESTED / quality UNKNOWN are
unaffected, and existing M4/M5 records are neither re-signed nor upgraded.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Protocol

SIGNATURE_SCHEMA = "siteproof.awsc.signature.v1"
ALGORITHM = "ECDSA_SHA_256"


class Signer(Protocol):
    def sign(self, message: bytes) -> dict[str, Any]: ...


class UnsignedSigner:
    """Explicit absence of a signature. Never reported as signed."""

    def sign(self, message: bytes) -> dict[str, Any]:
        return {"schema": SIGNATURE_SCHEMA, "status": "UNSIGNED",
                "signed_sha256": hashlib.sha256(message).hexdigest()}


class KmsSigner:
    def __init__(self, client: Any, key_id: str) -> None:
        self._client, self._key_id = client, key_id

    def sign(self, message: bytes) -> dict[str, Any]:
        digest = hashlib.sha256(message).digest()
        base = {"schema": SIGNATURE_SCHEMA, "signed_sha256": digest.hex(),
                "key_id": self._key_id, "algorithm": ALGORITHM}
        try:
            response = self._client.sign(KeyId=self._key_id, Message=digest,
                                         MessageType="DIGEST", SigningAlgorithm=ALGORITHM)
            signature = response["Signature"]
            if type(signature) is not bytes or not signature:
                raise ValueError("empty signature")
        except Exception as exc:
            # A failed signature is recorded as such; it is never silently dropped.
            return {**base, "status": "SIGN_FAILED", "error": type(exc).__name__}
        return {**base, "status": "SIGNED",
                "signature_b64": base64.b64encode(signature).decode("ascii")}


def verify_with_kms(client: Any, envelope: dict[str, Any], message: bytes) -> str:
    """Verifier-side check through KMS. Returns VALID / INVALID / UNSIGNED / UNVERIFIABLE."""
    if type(envelope) is not dict or envelope.get("schema") != SIGNATURE_SCHEMA:
        return "UNVERIFIABLE"
    digest = hashlib.sha256(message).digest()
    if envelope.get("signed_sha256") != digest.hex():
        return "INVALID"
    if envelope.get("status") != "SIGNED":
        return "UNSIGNED"
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        response = client.verify(KeyId=envelope["key_id"], Message=digest,
                                 MessageType="DIGEST", Signature=signature,
                                 SigningAlgorithm=envelope["algorithm"])
    except Exception as exc:
        # KMS reports a wrong signature as an error, not as SignatureValid=False.
        response = getattr(exc, "response", None)
        code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
        return "INVALID" if code == "KMSInvalidSignatureException" else "UNVERIFIABLE"
    return "VALID" if response.get("SignatureValid") is True else "INVALID"

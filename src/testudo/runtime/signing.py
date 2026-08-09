# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Asymmetric capability-token signing interfaces.

The host control plane owns private keys. Testudo receives a signer callback or
public verifier, never a keychain/TPM private-key export. ``P256Signer`` is a
small ES256 implementation for host adapters and deterministic tests; an
agentic-driver adapter can wrap its ``sign`` operation around Secure Enclave,
Keychain, TPM2 or PKCS#11 without changing the token format.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class SigningError(ValueError):
    """A signer key or signature is invalid."""


class TokenSigner(Protocol):
    """Minimal host-side signer/verifier contract."""

    algorithm: str
    key_id: str

    def sign(self, payload: bytes) -> str:
        """Sign canonical payload bytes and return a transport-safe string."""

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a transport-safe signature against canonical payload bytes."""


def _encode(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _decode(signature: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, UnicodeError) as exc:
        raise SigningError("signature is not valid base64url") from exc


def _ensure_p256(key: ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey) -> None:
    if not isinstance(key.curve, ec.SECP256R1):
        raise SigningError("capability signer requires a P-256 key")


@dataclass(frozen=True, slots=True)
class P256Signer:
    """ES256 signer with an optional external host-keystore callback.

    ``private_key`` is intended for a process that can call a hardware-backed
    provider directly. ``sign_callback`` is the preferred adapter path when a
    Keychain/TPM/PKCS#11 service performs signing without exporting the key.
    """

    key_id: str
    public_key: ec.EllipticCurvePublicKey
    private_key: ec.EllipticCurvePrivateKey | None = None
    sign_callback: Callable[[bytes], bytes] | None = None

    algorithm = "ES256"

    def __post_init__(self) -> None:
        if not self.key_id:
            raise SigningError("key_id is required")
        _ensure_p256(self.public_key)
        if self.private_key is not None:
            _ensure_p256(self.private_key)
            if self.private_key.public_key().public_numbers() != self.public_key.public_numbers():
                raise SigningError("private and public signing keys do not match")
        # A verifier intentionally has neither a private key nor a callback.

    @classmethod
    def generate(cls, key_id: str = "test-key") -> P256Signer:
        """Create an in-memory signer for tests or an explicit software fallback."""
        private = ec.generate_private_key(ec.SECP256R1())
        return cls(key_id, private.public_key(), private_key=private)

    @classmethod
    def from_private_pem(
        cls, pem: bytes, *, key_id: str, password: bytes | None = None
    ) -> P256Signer:
        """Load a PEM key for a host adapter that intentionally permits export."""
        try:
            key = serialization.load_pem_private_key(pem, password=password)
        except (TypeError, ValueError) as exc:
            raise SigningError("invalid P-256 private key PEM") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SigningError("private PEM is not an EC key")
        return cls(key_id, key.public_key(), private_key=key)

    @classmethod
    def from_public_pem(cls, pem: bytes, *, key_id: str) -> P256Signer:
        """Create a verifier using only a host-published public key."""
        try:
            key = serialization.load_pem_public_key(pem)
        except (TypeError, ValueError) as exc:
            raise SigningError("invalid P-256 public key PEM") from exc
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SigningError("public PEM is not an EC key")
        return cls(key_id, key)

    @classmethod
    def from_external(
        cls,
        *,
        key_id: str,
        public_key_pem: bytes,
        sign_callback: Callable[[bytes], bytes],
    ) -> P256Signer:
        """Wrap a non-exporting Secure Enclave/TPM/PKCS#11 sign operation."""
        verifier = cls.from_public_pem(public_key_pem, key_id=key_id)
        return cls(key_id, verifier.public_key, sign_callback=sign_callback)

    def sign(self, payload: bytes) -> str:
        if self.private_key is not None:
            signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        elif self.sign_callback is not None:
            signature = self.sign_callback(payload)
        else:  # pragma: no cover - guarded by __post_init__
            raise SigningError("signing key is unavailable")
        if not isinstance(signature, bytes) or not signature:
            raise SigningError("sign callback returned no signature")
        return _encode(signature)

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            self.public_key.verify(_decode(signature), payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, SigningError):
            return False
        return True

    def public_key_pem(self) -> bytes:
        """Return the public key for a VM/host verifier, never a private key."""
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


__all__ = ["P256Signer", "SigningError", "TokenSigner"]

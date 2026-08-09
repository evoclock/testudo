# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for host-side asymmetric capability signing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from testudo.runtime.capability import CapabilityToken
from testudo.runtime.signing import P256Signer, SigningError

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def test_p256_signer_round_trips_and_public_verifier_cannot_sign() -> None:
    signer = P256Signer.generate("host-key-1")
    payload = b"canonical capability payload"
    signature = signer.sign(payload)

    assert signer.verify(payload, signature)
    assert not signer.verify(b"tampered", signature)
    verifier = P256Signer.from_public_pem(signer.public_key_pem(), key_id="host-key-1")
    assert verifier.verify(payload, signature)
    with pytest.raises(SigningError, match="unavailable"):
        verifier.sign(payload)


def test_capability_token_uses_es256_metadata() -> None:
    signer = P256Signer.generate("secure-enclave-key")
    token = CapabilityToken.issue(
        signer=signer,
        run_id="run-1", lease_id="lease-1", host_id="mac-mini", vm_id="vm-1",
        repository="testudo-agents", branch="agent/T-0254/run-1",
        base_sha="a" * 40, capabilities=("export",),
        allowed_paths=("agents/checkpoints/",), lifetime=timedelta(minutes=10), now=NOW,
    )

    serialized = token.to_dict()
    assert serialized["signature_alg"] == "ES256"
    assert serialized["key_id"] == "secure-enclave-key"
    verified = CapabilityToken.verify(serialized, signer=signer, now=NOW)
    assert verified.signature_algorithm == "ES256"
    assert verified.key_id == "secure-enclave-key"


def test_external_sign_callback_does_not_export_private_key() -> None:
    source = P256Signer.generate("hardware-key")
    calls: list[bytes] = []

    def sign(payload: bytes) -> bytes:
        calls.append(payload)
        # The callback represents Secure Enclave/TPM/PKCS#11; the private key
        # remains owned by the separate signer in this deterministic fixture.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        return source.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]

    external = P256Signer.from_external(
        key_id="hardware-key", public_key_pem=source.public_key_pem(), sign_callback=sign
    )
    signature = external.sign(b"payload")
    assert calls == [b"payload"]
    assert external.verify(b"payload", signature)

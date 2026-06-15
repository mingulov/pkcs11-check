"""Crypto-output parameter-fidelity helpers.

Recover the ACTUAL structural parameter a module used for an operation and
classify it against what was requested. Pure software (no PKCS#11 calls).

See docs/superpowers/specs/2026-06-15-parameter-fidelity-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.classification import fail_as, xfail_as


@dataclass(frozen=True)
class FidelityResult:
    """Outcome of a parameter-fidelity probe.

    - valid: output is cryptographically sound under SOME legal parameter set.
    - conforms: the recovered actual parameters equal the requested ones.
    - interpretable: the output structure could be parsed at all (e.g. a GCM
      tag of plausible length; an OAEP ciphertext that decrypted under some
      candidate). When False, the result routes to not_operational, NEVER
      wrong_result (spec G4/G5).
    - requested / actual: dicts of the probed fields (actual field -> None if
      not recovered).
    - detail: human-readable summary fragment.
    """

    valid: bool
    conforms: bool
    interpretable: bool
    requested: dict[str, Any]
    actual: dict[str, Any]
    detail: str = ""


def classify_fidelity(
    result: FidelityResult, *, label: str, operation: str, mechanism: str
) -> None:
    """Route a FidelityResult to pass / honest_deviation / wrong_result / not_operational.

    Invariant (spec G7): a FidelityResult is built only when the module returned
    CKR_OK output. A clean CKR refusal is classified by the caller BEFORE building
    a FidelityResult, so this function never sees a refusal. not_operational is
    emitted here only for an UNINTERPRETABLE structure.

    Only PSS reaches wrong_result via this router (its signature is always a
    fixed-width, parseable value); OAEP/GCM set interpretable=False on ambiguous
    failure and their crypto-break detection is delegated (spec).
    """
    if not result.interpretable:
        xfail_as(
            "not_operational",
            kind="lifecycle",
            label=label,
            operation=operation,
            mechanism=mechanism,
            summary=f"{label}: module output could not be interpreted ({result.detail})",
        )
    if not result.valid:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            summary=f"{label}: output invalid under every legal parameter ({result.detail})",
        )
    if result.conforms:
        return
    xfail_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=result.requested,
        actual=result.actual,
        summary=(
            f"{label}: requested {result.requested}, module used {result.actual} ({result.detail})"
        ),
    )


def recover_pss_salt_len(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    mgf_hash: hashes.HashAlgorithm,
    digest: hashes.HashAlgorithm,
) -> int | None:
    """Return the exact PSS salt length under which *sig* verifies, or None.

    Scans 0 .. emLen-hLen-2 (the maximum legal PSS salt, spec G8) using the
    already-recovered *mgf_hash* and the message *digest*. emLen = ceil((modBits-1)/8).
    """
    em_len = (pub.key_size + 6) // 8  # ceil((key_size-1)/8)
    max_salt = em_len - digest.digest_size - 2
    if max_salt < 0:
        return None
    for salt_len in range(0, max_salt + 1):
        pad = padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=salt_len)
        try:
            pub.verify(sig, data, pad, digest)
            return salt_len
        except InvalidSignature:
            continue
    return None

"""Crypto-output parameter-fidelity helpers.

Recover the ACTUAL structural parameter a module used for an operation and
classify it against what was requested. Pure software (no PKCS#11 calls).

See docs/superpowers/specs/2026-06-15-parameter-fidelity-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
        # The probed parameters are structured data, not CKR codes -- carry them in
        # ``detail`` (``expected``/``actual`` are routed through ckr_name and would
        # mangle a dict). The human-readable form is already in ``summary``.
        detail={"requested": result.requested, "actual": result.actual},
        summary=(
            f"{label}: requested {result.requested}, module used {result.actual} ({result.detail})"
        ),
    )


def recover_pss_salt_len(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    mgf_hash: hashes.HashAlgorithm,
    hash_alg: hashes.HashAlgorithm,
) -> int | None:
    """Return the exact PSS salt length under which *sig* verifies, or None.

    Scans 0 .. emLen-hLen-2 (the maximum legal PSS salt, spec G8) using the
    already-recovered *mgf_hash* and the message digest *hash_alg* (named to match
    ``_local_verify.rsa_pss_local``). emLen = ceil((modBits-1)/8).
    """
    em_len = (pub.key_size + 6) // 8  # ceil((key_size-1)/8)
    max_salt = em_len - hash_alg.digest_size - 2
    if max_salt < 0:
        return None
    for salt_len in range(0, max_salt + 1):
        pad = padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=salt_len)
        try:
            pub.verify(sig, data, pad, hash_alg)
            return salt_len
        except InvalidSignature:
            continue
    return None


def build_gcm_fidelity(
    aes_key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
    module_output: bytes,
    requested_tag_bits: int,
) -> FidelityResult:
    """Interpret AES-GCM module output (ciphertext||tag) and check tag-length fidelity.

    Uses the low-level Cipher/modes.GCM API (the AESGCM convenience class is fixed
    at a 16-byte tag and cannot verify shorter tags). A trailer that is not a
    plausible tag length (4..16 bytes) or fails to decrypt is treated as a
    non-append / unparseable layout -> interpretable=False -> not_operational
    (spec G4); genuine GCM corruption stays covered by test_aead cross-verify.
    """
    tag_len = len(module_output) - len(plaintext)
    base = {"tag_bits": requested_tag_bits}
    if tag_len < 4 or tag_len > 16:
        return FidelityResult(
            valid=False,
            conforms=False,
            interpretable=False,
            requested=base,
            actual={"tag_len_bytes": tag_len},
            detail=f"implausible GCM tag length {tag_len} bytes (non-append layout?)",
        )
    ct, tag = module_output[:-tag_len], module_output[-tag_len:]
    dec = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag, min_tag_length=tag_len)).decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    try:
        recovered = dec.update(ct) + dec.finalize()
    except InvalidTag:
        return FidelityResult(
            valid=False,
            conforms=False,
            interpretable=False,
            requested=base,
            actual={"tag_bits": tag_len * 8},
            detail=f"GCM output did not authenticate at tag_len={tag_len} (non-append layout?)",
        )
    actual_bits = tag_len * 8
    strength = "weaker auth" if actual_bits < requested_tag_bits else "stronger auth"
    # ``valid`` is True whenever decryption authenticated (no InvalidTag above): GCM's
    # AEAD guarantee means an authentic tag implies recovered == plaintext, so the
    # ``valid=False, interpretable=True`` path that would route to wrong_result is
    # effectively unreachable here. GCM correctness is owned by test_aead cross-verify;
    # this probe only judges tag-length fidelity.
    return FidelityResult(
        valid=(recovered == plaintext),
        conforms=(actual_bits == requested_tag_bits),
        interpretable=True,
        requested=base,
        actual={"tag_bits": actual_bits},
        detail=(
            "GCM tag length honored"
            if actual_bits == requested_tag_bits
            else f"tag {actual_bits}-bit vs requested {requested_tag_bits}-bit ({strength})"
        ),
    )


def recover_oaep_params(
    priv: rsa.RSAPrivateKey,
    ciphertext: bytes,
    expected_plaintext: bytes,
    candidate_alg_hashes: tuple[hashes.HashAlgorithm, ...],
    candidate_mgf_hashes: tuple[hashes.HashAlgorithm, ...],
    candidate_labels: tuple[bytes | None, ...],
) -> tuple[hashes.HashAlgorithm, hashes.HashAlgorithm, bytes | None] | None:
    """Return (oaep_hash, mgf_hash, label) whose local decrypt yields the expected
    plaintext, or None if no candidate combination recovers it.

    Tries the product of the candidate families. A combination cryptography cannot
    perform raises UnsupportedAlgorithm; one that simply does not decrypt raises
    ValueError -- both are EXPECTED for a non-matching combination, so only those two
    specific exceptions are skipped (any other exception propagates as a real bug).
    None => the module's OAEP params are not interpretable from our candidate set ->
    caller marks interpretable=False.
    """
    for alg in candidate_alg_hashes:
        for mgf in candidate_mgf_hashes:
            for label in candidate_labels:
                pad = padding.OAEP(mgf=padding.MGF1(mgf), algorithm=alg, label=label)
                try:
                    if priv.decrypt(ciphertext, pad) == expected_plaintext:
                        return (alg, mgf, label)
                except (ValueError, UnsupportedAlgorithm):
                    continue
    return None

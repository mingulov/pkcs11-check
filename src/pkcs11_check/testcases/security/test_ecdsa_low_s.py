"""ECDSA low-s / malleability posture probe.

Records whether a module produces low-s ECDSA signatures and whether it accepts
the malleable (r, n-s) twin. Neither behaviour is a defect: FIPS 186-5 does not
mandate low-s normalisation, and ECDSA malleability is a known property of the
scheme (SEC1 §4.1.3).

The posture observations are recorded via compliance.note(). Clean provider
refusals of an advertised operation are recorded as xfail; harness failures and
unexpected return values remain visible as hard failures.

References:
    FIPS 186-5 §6.4  — ECDSA signature generation
    SEC1 §4.1.3      — ECDSA signature-malleability
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import destroy_quietly, sign_single, verify_single
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import gen_ec_keypair_or_xfail, xfail_if_known_ckr

pytestmark = pytest.mark.security

# P-256 (secp256r1) group order — NIST FIPS 186-5 / SEC 2 §2.4.2 public constant.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Fixed 32-byte test message digest (SHA-256 of a deterministic string).
_DATA = hashlib.sha256(b"pkcs11-check:ecdsa-low-s-posture-probe").digest()

_ECDSA_SIGN_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


class TestEcdsaLowSPosture:
    """Posture probe: low-s enforcement and signature malleability."""

    def test_low_s_and_malleability(self, p11_raw_session: Any) -> None:
        """Record ECDSA low-s posture and malleable-twin acceptance.

        Signs a fixed digest with CKM_ECDSA (raw, no hash) and inspects the
        resulting (r, s) pair.  Then presents the malleable twin (r, n-s) to
        C_Verify and notes whether the module accepts or rejects it.

        All outcomes are compliance notes — this test can never fail.
        """
        rs = p11_raw_session

        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported by this module")

        pub: int | None = None
        priv: int | None = None
        try:
            pub, priv = gen_ec_keypair_or_xfail(
                rs,
                encode_named_curve_parameters("secp256r1"),
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            )

            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ECDSA,
                    _DATA,
                    output_size_hint=64,
                )
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _ECDSA_SIGN_RUNTIME_REJECT_RVS,
                    "CKM_ECDSA advertised but sign is not operational",
                )

            if len(sig) != 64:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_ECDSA signature length",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                    expected=64,
                    actual=len(sig),
                    summary=(
                        "CKM_ECDSA returned an unexpected P-256 signature length: "
                        f"got {len(sig)}, expected 64"
                    ),
                )

            # --- Parse raw r || s (each 32 bytes, big-endian) ---
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")

            half_n = _P256_N // 2

            # --- Record low-s posture ---
            test_id = "TestEcdsaLowSPosture.test_low_s_and_malleability"
            if s > half_n:
                note(
                    "ECDSA produced a high-s signature"
                    " (low-s not enforced; permitted by FIPS 186-5)",
                    ComplianceLevel.EXTENDED,
                    reference="FIPS 186-5 §6.4; SEC1 §4.1.3",
                    test_id=test_id,
                )
            else:
                note(
                    "ECDSA produced a low-s signature (s ≤ n/2; low-s normalisation enforced)",
                    ComplianceLevel.STANDARD,
                    reference="FIPS 186-5 §6.4; SEC1 §4.1.3",
                    test_id=test_id,
                )

            # --- Construct the malleable twin (r, n-s) and probe C_Verify ---
            s2 = _P256_N - s
            sig2 = r.to_bytes(32, "big") + s2.to_bytes(32, "big")

            try:
                twin_accepted = verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_ECDSA,
                    _DATA,
                    sig2,
                )
            except CkrAssertionError as exc:
                # verify_single handles the two expected invalid-signature CKRs and
                # returns False. Any other explicitly known clean refusal is an
                # advertised-but-not-operational provider deviation; all other
                # exceptions remain visible to the harness.
                xfail_if_known_ckr(
                    exc,
                    _ECDSA_SIGN_RUNTIME_REJECT_RVS,
                    "CKM_ECDSA advertised but malleable-twin verification is not operational",
                )

            if twin_accepted:
                note(
                    "ECDSA accepted the malleable (r, n-s) twin — signature malleability "
                    "present; permitted by FIPS 186-5 / SEC1",
                    ComplianceLevel.EXTENDED,
                    reference="FIPS 186-5 §6.4; SEC1 §4.1.3",
                    test_id=test_id,
                )
            else:
                note(
                    "ECDSA rejected the malleable (r, n-s) twin — low-s / malleability "
                    "check present",
                    ComplianceLevel.STANDARD,
                    reference="FIPS 186-5 §6.4; SEC1 §4.1.3",
                    test_id=test_id,
                )

        finally:
            if pub is not None:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv is not None:
                destroy_quietly(rs.raw, rs.sh, priv)

"""CKR compliance tests for C_VerifyInit and C_Verify.

Source: PKCS#11 v3.2 (C_VerifyInit, C_Verify).
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_secret_key,
    sign_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_SIGN,
    CKF_VERIFY,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_ECDSA,
    CKM_EDDSA,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._ec_export import (
    SECP256R1_ORDER,
    assert_exact_dss_width_or_classify,
    parse_raw_dss_or_classify,
)
from pkcs11_check.testcases._signature_policy import (
    OP_NOT_OPERATIONAL_RVS,
    SIGNATURE_REJECT_RVS,
    xfail_if_op_not_operational,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_VERIFY, assert_ckr
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    classify_lifecycle_effect,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_edwards_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_ec_private_key_negotiated,
    import_ec_public_key_negotiated,
    is_known_error,
    skip_unless_create_object_supported,
    skip_unless_mechanism_flag,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access

# Fixed P-256 vector (QC5a, issue #57.1): both halves of the raw signature
# start with a zero byte, so each half can be shortened by one byte while
# keeping valid scalars and equal halves. d = sha256("QC5a P-256 fixed
# private") mod (n-1) + 1; digest = sha256("QC5a P-256 fixed digest"); k
# iterated from 1, first k with r,s < 2**248 (k=81953). Independently
# verified with the `cryptography` package (Prehashed SHA-256), both the
# full 64-byte and the shortened 62-byte encoding of the same (r, s).
_QC5A_D = bytes.fromhex("8f9406107943901436d1df4869542b662c2a4276bd66220e6efb2fa3cec7522c")
_QC5A_QX = 0x9C1E48819ADD8B9400B03B0577B56794BBBD8D4C803CAB2BFF254CC88C3C772D
_QC5A_QY = 0xCC0C0E0C9F9FE37822E9EE3A3502B3C885D034C675929760A5EE5AD3CE98B3F4
_QC5A_DIGEST = bytes.fromhex("2a285e19f4ad9f1c910f31e0a0cfe5b17b5a2c65224372b64d5a040e12259126")
_QC5A_R = 0x00BFC7D9A26C4B000FFF24596BE6473D3E0CF038D6E26F516F4629A63E3A0903
_QC5A_S = 0x0096F21BCA871507F3100EB63974BFCCB5E82FA52638BC726C3AD893906CC10F
_QC5A_SIG_FULL = _QC5A_R.to_bytes(32, "big") + _QC5A_S.to_bytes(32, "big")
assert _QC5A_SIG_FULL[0] == 0 and _QC5A_SIG_FULL[32] == 0  # both halves shortenable
_QC5A_SIG_SHORT = _QC5A_SIG_FULL[1:32] + _QC5A_SIG_FULL[33:64]
assert len(_QC5A_SIG_SHORT) == 62
_QC5A_PAD_LENS = (1, 2, 100)

# Clean C_CreateObject refusals while staging the fixed P-256 vector: the
# module advertises CKM_ECDSA but cannot stage the vector, so the verify
# oracle never ran -- xfail (recorded), never a crypto finding. Curve
# absence (EC_CURVE_UNSUPPORTED_RVS) is a genuine capability skip instead.
_QC5A_IMPORT_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
)


def _verify_init_or_classify(rs: Any, mech: Any, pub: int, *, label: str) -> None:
    """Run C_VerifyInit for an advertised verify operation; classify, never skip.

    The mechanism-flag gate proved C_Verify advertised and key setup
    succeeded, so a non-OK result cannot mean missing capability: a
    recognized clean refusal xfails as not_operational with the original RV,
    any other defined RV xfails as a non-spec deviation, and an undefined RV
    fails as a metadata self-contradiction.
    """
    rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
    if rv == CKR_OK:
        return
    if rv in OP_NOT_OPERATIONAL_RVS:
        xfail_as(
            "not_operational",
            label=label,
            operation="C_VerifyInit",
            mechanism="CKM_ECDSA",
            actual=rv,
            summary=f"{label}: C_VerifyInit refused with {ckr_name(rv)}",
        )
    if not is_standard_ckr(rv) and not is_vendor_defined_ckr(rv):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_VerifyInit",
            mechanism="CKM_ECDSA",
            actual=rv,
            summary=f"{label}: C_VerifyInit returned an undefined CK_RV {ckr_name(rv)}",
        )
    xfail_as(
        "nonspec_reject",
        label=label,
        operation="C_VerifyInit",
        mechanism="CKM_ECDSA",
        expected=tuple(OP_NOT_OPERATIONAL_RVS),
        actual=rv,
        summary=(
            f"{label}: C_VerifyInit refused with defined-but-unrecognized "
            f"{ckr_name(rv)}; expected CKR_OK or a recognized clean refusal"
        ),
    )


def _control_verify_or_classify(rs: Any, digest: bytes, sig: bytes, *, label: str) -> None:
    """Verify a control signature that MUST verify; classify any refusal.

    An evaluated rejection (SIGNATURE_INVALID/LEN_RANGE) of a control that
    must verify is a genuine verification contradiction -> wrong_result fail.
    A clean refusal without evaluation means the premise is unestablished ->
    not_operational xfail with the original RV; any other defined RV is a
    non-spec xfail; an undefined RV fails as metadata.
    """
    data_buf = (ctypes.c_ubyte * len(digest))(*digest)
    sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
    rv = rs.raw.C_Verify(rs.sh, data_buf, len(digest), sig_buf, len(sig))
    if rv == CKR_OK:
        return
    if rv in SIGNATURE_REJECT_RVS:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Verify",
            mechanism="CKM_ECDSA",
            expected=CKR_OK,
            actual=rv,
            summary=(
                f"{label}: C_Verify evaluated and rejected a control signature "
                f"that must verify ({ckr_name(rv)})"
            ),
        )
    if rv in OP_NOT_OPERATIONAL_RVS:
        xfail_as(
            "not_operational",
            label=label,
            operation="C_Verify",
            mechanism="CKM_ECDSA",
            actual=rv,
            summary=f"{label}: C_Verify refused the control without evaluating ({ckr_name(rv)})",
        )
    if not is_standard_ckr(rv) and not is_vendor_defined_ckr(rv):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_Verify",
            mechanism="CKM_ECDSA",
            actual=rv,
            summary=f"{label}: C_Verify on the control returned an undefined CK_RV {ckr_name(rv)}",
        )
    xfail_as(
        "nonspec_reject",
        label=label,
        operation="C_Verify",
        mechanism="CKM_ECDSA",
        expected=CKR_OK,
        actual=rv,
        summary=(
            f"{label}: C_Verify on the control refused with defined-but-unrecognized "
            f"{ckr_name(rv)}; expected CKR_OK"
        ),
    )


class TestVerifyInitErrors:
    """Per-parameter error conditions for C_VerifyInit (Sec.5.11.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for verify -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="policy",
                    label="C_VerifyInit:AES-mechanism",
                    operation="C_VerifyInit",
                    actual=rv,
                    summary="Should have rejected AES_ECB as verify mechanism",
                )
            assert_ckr(CKR_VERIFY["init_mechanism_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_key_type_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key with RSA verify mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            exp = CKR_VERIFY["init_key_type_inconsistent"]
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), key)
            # crypto-correctness: accepting an AES key under an RSA verify
            # mechanism (CKR_OK) is key-type confusion -> fail; an expected
            # reject -> pass; another clean reject -> xfail (3-way assert_ckr).
            assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_handle_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Verify with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair_or_xfail(rs, 2048)
        destroy_quietly(rs.raw, rs.sh, _priv)
        destroy_rv = rs.raw.C_DestroyObject(rs.sh, pub)
        mech = mech_simple(CKM_SHA256_RSA_PKCS)
        rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
        if rv == CKR_OK:
            # lifecycle use-after-destroy: destroy claimed CKR_OK yet C_VerifyInit
            # on the same handle still succeeded -> contradiction.
            classify_lifecycle_effect(
                claimed_success=destroy_rv == CKR_OK,
                effect_observed=True,
                label="C_VerifyInit on a destroyed key handle (use-after-destroy)",
            )
        else:
            assert_ckr(CKR_VERIFY["init_key_handle_invalid"], rv, ckr_strict)


class TestVerifyErrors:
    """Error conditions for C_Verify (Sec.5.11.2)."""

    def test_signature_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Tampered RSA signature -> CKR_SIGNATURE_INVALID."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_SHA256_RSA_PKCS, int(CKF_VERIFY))
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            data = b"CKR compliance test data"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Tamper last byte
            tampered = bytearray(sig)
            tampered[-1] ^= 0xFF

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(tampered))(*tampered)
            rv = rs.raw.C_Verify(
                rs.sh,
                data_buf,
                len(data),
                sig_buf,
                len(tampered),
            )
            # CKR_DEVICE_ERROR is a clean non-spec reject -> classified as a noted
            # deviation (xfail) by assert_ckr via _TOKEN_UNIVERSAL; no provider-
            # specific pre-guard (it would leak provider identity into the report).
            if rv == CKR_OK:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="C_Verify:tampered-signature",
                    operation="C_Verify",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    actual=rv,
                    summary="Tampered signature verified as valid!",
                )
            assert_ckr(CKR_VERIFY["signature_invalid"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_SHA256_RSA_PKCS, int(CKF_VERIFY))
        pub, _priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            exp = CKR_VERIFY["signature_len_range"]
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # RSA-2048 signature should be 256 bytes, provide 128
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 128)(*([0] * 128))
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 128)
            # CKR_DEVICE_ERROR is a clean non-spec reject -> classified as a noted
            # deviation (xfail) by assert_ckr via _TOKEN_UNIVERSAL; no provider-
            # specific pre-guard (it would leak provider identity into the report).
            # crypto-correctness: a wrong-length RSA signature that
            # verifies (CKR_OK) is a break -> fail; an expected reject -> pass;
            # another clean reject -> xfail (3-way assert_ckr).
            assert_ckr(exp, rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_ecdsa_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """ECDSA signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_ECDSA, int(CKF_VERIFY))
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, _priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_ECDSA)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # P-256 raw ECDSA signature is 64 bytes (two 32-byte scalars), provide 32
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 32)(*([0] * 32))
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 32)
            # A wrong-length ECDSA signature that verifies (CKR_OK) is a crypto
            # break -> fail; expected reject -> pass; other clean reject -> xfail.
            assert_ckr(CKR_VERIFY["ecdsa_signature_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    @pytest.mark.parametrize("pad_len", [pytest.param(v, id=f"pad-{v}") for v in _QC5A_PAD_LENS])
    def test_ecdsa_overlong_zero_padded_halves(
        self, p11_raw_session: Any, ckr_strict: bool, pad_len: int
    ) -> None:
        """ECDSA signature with each half zero-padded -> CKR_SIGNATURE_LEN_RANGE.

        QC5a (issue #57.1): start with the token's own valid P-256 signature
        and prepend ``pad_len`` zero bytes to EACH half, keeping valid scalar
        values and equal halves. The unmodified signature is verified first
        as a control (it must verify -- W1 requires starting from a VALID
        token-signed signature); only then is the padded form submitted.
        PKCS#11 v3.2 section 6.3.1 caps an ECDSA signature at 2*nLen octets,
        and section 5.15.2 expects CKR_SIGNATURE_LEN_RANGE when a signature
        is invalid purely on length. CKR_OK here is the issue's crypto break
        -> fail; the expected reject -> pass; any other clean refusal ->
        xfail with the original RV.
        """
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_ECDSA, int(CKF_VERIFY))
        skip_unless_mechanism_flag(rs, CKM_ECDSA, int(CKF_SIGN))
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            digest = hashlib.sha256(b"QC5a overlong-half stimulus").digest()
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            except CkrAssertionError as exc:
                # A clean refusal produces no output -> not_operational xfail
                # (original RV preserved); it demonstrates no wrong signature.
                xfail_if_op_not_operational(exc, "CKM_ECDSA QC5a overlong-half stimulus sign")
            # Premise: the stimulus must be a well-formed 64-byte raw
            # signature with in-range scalars; a malformed token signature
            # is itself a wrong_result finding, not a skippable setup gap.
            parse_raw_dss_or_classify(
                sig,
                half_len=32,
                order=SECP256R1_ORDER,
                label="CKM_ECDSA:sign QC5a overlong stimulus",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )

            mech = mech_simple(CKM_ECDSA)
            _verify_init_or_classify(
                rs, mech, pub, label="CKM_ECDSA QC5a overlong-half control verify init"
            )
            _control_verify_or_classify(
                rs, digest, sig, label="CKM_ECDSA QC5a overlong-half control"
            )
            padded = b"\x00" * pad_len + sig[:32] + b"\x00" * pad_len + sig[32:]

            # A completed C_Verify terminates the operation, so re-init for
            # the padded negative.
            _verify_init_or_classify(
                rs, mech, pub, label="CKM_ECDSA QC5a overlong-half negative verify init"
            )
            data_buf = (ctypes.c_ubyte * len(digest))(*digest)
            sig_buf = (ctypes.c_ubyte * len(padded))(*padded)
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(digest), sig_buf, len(padded))
            # An overlong ECDSA signature that verifies (CKR_OK) is a crypto
            # break -> fail; expected reject -> pass; other clean reject -> xfail.
            assert_ckr(CKR_VERIFY["ecdsa_signature_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ecdsa_fixed_vector_shorter_even_encoding_verifies(self, p11_raw_session: Any) -> None:
        """Fixed P-256 vector: Verify permits a shorter even encoding (pass).

        QC5a (issue #57.1): the fixed vector's halves can both be shortened
        (62 bytes, equal halves, same scalars). Per section 6.3.1 an ECDSA
        signature is an even-length octet string of AT MOST 2*nLen, so the
        shortened encoding verifies (pass). The full 64-byte encoding is the
        control and must verify. A clean refusal of the shorter encoding is
        a noted strict-length deviation (xfail, original RV preserved); an
        undefined RV or a rejected control is a fail. Verdicts are
        mode-independent: this is a positive leg, not an assert_ckr negative.
        """
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_ECDSA, int(CKF_VERIFY))
        skip_unless_create_object_supported(rs)
        ec_params = encode_named_curve_parameters("secp256r1")
        point = b"\x04" + _QC5A_QX.to_bytes(32, "big") + _QC5A_QY.to_bytes(32, "big")
        try:
            pub = import_ec_public_key_negotiated(
                rs,
                ec_params=ec_params,
                ec_point=bytes([0x04, len(point)]) + point,
                attrs={CKA_VERIFY: True},
                purpose="QC5a fixed P-256 vector",
            )
        except AssertionError as exc:
            if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
                pytest.skip(f"Module cleanly rejects P-256 import: {exc}")
            xfail_if_known_ckr(
                exc,
                _QC5A_IMPORT_RUNTIME_REJECT_RVS,
                "CKM_ECDSA advertised but fixed-vector import is not operational",
            )
            raise
        try:
            mech = mech_simple(CKM_ECDSA)
            _verify_init_or_classify(
                rs, mech, pub, label="CKM_ECDSA fixed-vector full-length control verify init"
            )
            data_buf = (ctypes.c_ubyte * len(_QC5A_DIGEST))(*_QC5A_DIGEST)
            _control_verify_or_classify(
                rs,
                _QC5A_DIGEST,
                _QC5A_SIG_FULL,
                label="CKM_ECDSA fixed-vector full-length control",
            )
            # A completed C_Verify terminates the operation, so re-init for
            # the shortened encoding.
            _verify_init_or_classify(
                rs, mech, pub, label="CKM_ECDSA fixed-vector shorter-encoding verify init"
            )
            short_buf = (ctypes.c_ubyte * len(_QC5A_SIG_SHORT))(*_QC5A_SIG_SHORT)
            rv_short = rs.raw.C_Verify(
                rs.sh, data_buf, len(_QC5A_DIGEST), short_buf, len(_QC5A_SIG_SHORT)
            )
            if rv_short == CKR_OK:
                return
            if is_standard_ckr(rv_short) or is_vendor_defined_ckr(rv_short):
                xfail_as(
                    "honest_deviation",
                    kind="crypto",
                    label="CKM_ECDSA fixed-vector shorter even encoding",
                    operation="C_Verify",
                    mechanism="CKM_ECDSA",
                    expected=CKR_OK,
                    actual=rv_short,
                    summary=(
                        "C_Verify refused the valid 62-byte shorter even encoding "
                        f"with {ckr_name(rv_short)}; the token requires exactly 2*nLen"
                    ),
                    detail={"encoding": "shorter-even", "signature_length": 62},
                )
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="CKM_ECDSA fixed-vector shorter even encoding",
                operation="C_Verify",
                mechanism="CKM_ECDSA",
                expected=CKR_OK,
                actual=rv_short,
                summary=(
                    "C_Verify on the shorter even encoding returned an undefined "
                    f"CK_RV {ckr_name(rv_short)}"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_ecdsa_fixed_vector_sign_returns_exact_width(self, p11_raw_session: Any) -> None:
        """Fixed P-256 vector: Sign must return exactly 2*nLen (fail otherwise).

        QC5a (issue #57.1): same fixed vector as the Verify direction. Per
        section 6.3.1 token-created signatures are ALWAYS exactly 2*nLen
        (64 bytes here); anything else is wrong_result -> fail. The fresh
        signature must also verify independently (Prehashed SHA-256).
        """
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_ECDSA, int(CKF_SIGN))
        skip_unless_create_object_supported(rs)
        ec_params = encode_named_curve_parameters("secp256r1")
        try:
            priv = import_ec_private_key_negotiated(
                rs,
                ec_params=ec_params,
                value=_QC5A_D,
                attrs={CKA_SIGN: True},
                purpose="QC5a fixed P-256 vector",
            )
        except AssertionError as exc:
            if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
                pytest.skip(f"Module cleanly rejects P-256 import: {exc}")
            xfail_if_known_ckr(
                exc,
                _QC5A_IMPORT_RUNTIME_REJECT_RVS,
                "CKM_ECDSA advertised but fixed-vector import is not operational",
            )
            raise
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, _QC5A_DIGEST)
            except CkrAssertionError as exc:
                # A clean refusal produces no output -> not_operational xfail
                # (original RV preserved); it demonstrates no wrong signature.
                xfail_if_op_not_operational(exc, "CKM_ECDSA QC5a fixed-vector sign")
            # Width gate first: token-created output must be exactly 2*nLen
            # even when it is a well-formed DER signature (the parser below
            # leniently xfails DER, which must not leak into this leg).
            assert_exact_dss_width_or_classify(
                sig,
                half_len=32,
                label="CKM_ECDSA:sign QC5a fixed-vector width",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )
            r, s = parse_raw_dss_or_classify(
                sig,
                half_len=32,
                order=SECP256R1_ORDER,
                label="CKM_ECDSA:sign QC5a fixed-vector width",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )
            pub = ec.EllipticCurvePublicNumbers(_QC5A_QX, _QC5A_QY, ec.SECP256R1()).public_key()
            try:
                pub.verify(
                    encode_dss_signature(r, s),
                    _QC5A_DIGEST,
                    ec.ECDSA(Prehashed(hashes.SHA256())),
                )
            except InvalidSignature:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_ECDSA:sign QC5a fixed-vector independent verify",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                    summary=(
                        "Token ECDSA signature over the fixed P-256 vector does "
                        "not verify independently"
                    ),
                    detail={"digest_length": len(_QC5A_DIGEST), "signature_length": len(sig)},
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hmac_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """SHA-256 HMAC tag with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_SHA256_HMAC, int(CKF_VERIFY))
        key_bytes = bytes(range(32))
        hmac_key = 0
        for key_type in (CKK_SHA256_HMAC, CKK_GENERIC_SECRET):
            try:
                hmac_key = import_secret_key(
                    rs.raw,
                    rs.sh,
                    key_type,
                    key_bytes,
                    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
                )
                break
            except AssertionError as exc:
                if is_known_error(
                    exc,
                    {CKR_MECHANISM_INVALID, CKR_KEY_SIZE_RANGE, CKR_TEMPLATE_INCONSISTENT},
                ):
                    continue
                raise
        if hmac_key == 0:
            pytest.skip("Cannot create HMAC key for SHA256_HMAC verify")
        try:
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_SHA256_HMAC)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), hmac_key)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # SHA-256 HMAC tag is 32 bytes; provide a 16-byte wrong-length tag
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 16)(*([0] * 16))
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 16)
            # A wrong-length HMAC tag that verifies (CKR_OK) is a crypto break ->
            # fail; expected reject -> pass; other clean reject -> xfail.
            assert_ckr(CKR_VERIFY["hmac_signature_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, hmac_key)

    def test_eddsa_signature_wrong_length(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """EdDSA (Ed25519) signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        rs = p11_raw_session
        skip_unless_mechanism_flag(rs, CKM_EDDSA, int(CKF_VERIFY))
        curve_oid = encode_named_curve_parameters("ed25519")
        pub, _priv = gen_edwards_keypair_or_xfail(rs, curve_oid)
        try:
            data = b"CKR compliance test data"

            mech = mech_simple(CKM_EDDSA)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                pytest.skip(f"C_VerifyInit failed: {ckr_name(rv)}")

            # Ed25519 signature is 64 bytes; provide a 32-byte wrong-length buffer
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * 32)(*([0] * 32))
            rv = rs.raw.C_Verify(rs.sh, data_buf, len(data), sig_buf, 32)
            # A wrong-length EdDSA signature that verifies (CKR_OK) is a crypto
            # break -> fail; expected reject -> pass; other clean reject -> xfail.
            assert_ckr(CKR_VERIFY["eddsa_signature_len_range"], rv, ckr_strict)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

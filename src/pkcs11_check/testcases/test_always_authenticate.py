"""CKA_ALWAYS_AUTHENTICATE enforcement tests.

When a private key has `CKA_ALWAYS_AUTHENTICATE=TRUE`, the PKCS#11 spec
requires the application to call `C_Login(CKU_CONTEXT_SPECIFIC, pin)`
*immediately before each operation* that uses the key.  The re-auth is
single-use: a second operation on the same key requires another
`CKU_CONTEXT_SPECIFIC` login.

This file exercises the operational enforcement.  test_attribute_enforcement.py
already covers attribute readability and keygen-time setting; the work
here is the runtime "sign-needs-reauth" path that historically has been
mis-implemented (multiple HSMs have shipped CVE-class bugs here).

Source: PKCS#11 v2.40 §11.6, v3.0 §5.5 (CKU_CONTEXT_SPECIFIC semantics).
"""

from __future__ import annotations

import ctypes
import uuid
from ctypes import byref
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from pkcs11_check import classification
from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.bootstrap import close_session_quietly
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects_exhaustive,
    gen_rsa_keypair,
    partition_proved_new,
    read_attributes,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CK_UTF8CHAR,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_DECRYPT,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_VERIFY,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKR_BUFFER_TOO_SMALL,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_COUNT,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_CONTEXT_SPECIFIC,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._local_verify import rsa_pkcs15_local
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = [pytest.mark.access]


def _pin_bytes(p11_config: Any) -> bytes | None:
    if p11_config.pin is None:
        return None
    encoded: bytes = p11_config.pin.get_secret_value().encode("utf-8")
    return encoded


def _context_specific_login(raw: Any, sh: int, pin: bytes) -> int:
    pin_buf = (CK_UTF8CHAR * len(pin))(*pin)
    return int(raw.C_Login(sh, CKU_CONTEXT_SPECIFIC, pin_buf, len(pin)))


def _try_gen_always_auth_keypair(rs: Any) -> tuple[int, int] | None:
    """Generate an RSA-2048 keypair with CKA_ALWAYS_AUTHENTICATE=True.

    Returns (pub, priv) on success, or None when the module cleanly refuses
    the advertised setup/readback.  The latter is recorded as a visible
    provider deviation; callers may stop only the dependent enforcement path.
    """
    try:
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits=2048,
            public_attrs={CKA_VERIFY: True},
            private_attrs={CKA_SIGN: True, CKA_ALWAYS_AUTHENTICATE: True},
        )
    except CkrAssertionError as exc:
        if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            xfail_as(
                "not_operational",
                kind="metadata",
                label="CKA_ALWAYS_AUTHENTICATE key generation",
                operation="C_GenerateKeyPair",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    "CKM_RSA_PKCS_KEY_PAIR_GEN is advertised, but the provider "
                    "rejected CKA_ALWAYS_AUTHENTICATE=True at key generation"
                ),
            )
        fail_as(
            "self_contradiction",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE key generation",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            expected=CKR_OK,
            actual=exc.rv,
            detail={
                "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                "producer_operation": "C_GenerateKeyPair",
                "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
            },
            summary=(
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned an undefined CK_RV while "
                "creating a CKA_ALWAYS_AUTHENTICATE=True key"
            ),
        )

    # Verify the module actually persisted the attribute.  Some modules
    # silently drop it; we want enforcement tests, not fake-pass tests.
    retain_handles = False
    try:
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ALWAYS_AUTHENTICATE])
        except CkrAssertionError as exc:
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                classification.record_as(
                    "not_operational",
                    kind="metadata",
                    label="CKA_ALWAYS_AUTHENTICATE setup readback",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=exc.rv,
                    detail={
                        "attribute": {
                            "name": "CKA_ALWAYS_AUTHENTICATE",
                            "id": int(CKA_ALWAYS_AUTHENTICATE),
                        },
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "CKA_ALWAYS_AUTHENTICATE readback was rejected after "
                        "successful key generation"
                    ),
                )
                return None
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="CKA_ALWAYS_AUTHENTICATE setup readback",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                detail={
                    "attribute": {
                        "name": "CKA_ALWAYS_AUTHENTICATE",
                        "id": int(CKA_ALWAYS_AUTHENTICATE),
                    },
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary="CKA_ALWAYS_AUTHENTICATE readback returned an undefined CK_RV",
            )

        value = attr_or_record(
            attrs,
            CKA_ALWAYS_AUTHENTICATE,
            label=(
                "CKA_ALWAYS_AUTHENTICATE setup readback "
                "(producer_operation=C_GenerateKeyPair, "
                "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            kind="metadata",
            inherit_mechanism=False,
        )
        if value is MISSING_ATTRIBUTE:
            missing_record = classification.get_records()[-1]
            if missing_record.detail is not None:
                missing_record.detail.update(
                    {
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    }
                )
            return None

        if type(value) is not bool:
            # F11/N2 (minimal redaction): type+length only, never value bytes.
            if isinstance(value, (bytes, bytearray, list, tuple, str)):
                _actual_len: int | None = len(value)
            else:
                _actual_len = None
            fail_as(
                "wrong_result",
                kind="policy",
                label="CKA_ALWAYS_AUTHENTICATE setup readback",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "expected_shape": "CK_BBOOL",
                    "expected_value": True,
                    "actual_type": type(value).__name__,
                    "actual_len": _actual_len,
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=("C_GetAttributeValue returned a malformed CKA_ALWAYS_AUTHENTICATE value"),
            )
        if value is not True:
            fail_as(
                "wrong_result",
                kind="policy",
                label="CKA_ALWAYS_AUTHENTICATE setup readback",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "expected_value": True,
                    "actual_value": value,
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    "C_GenerateKeyPair returned CKR_OK but did not preserve "
                    "CKA_ALWAYS_AUTHENTICATE=True"
                ),
            )
        retain_handles = True
        return pub, priv
    finally:
        if not retain_handles:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestAlwaysAuthenticateEnforcement:
    """Operational enforcement of CKA_ALWAYS_AUTHENTICATE=TRUE on private keys."""

    def test_sign_without_context_specific_login_rejected(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_SignInit on always-auth key + C_Sign without prior
        CKU_CONTEXT_SPECIFIC login must return CKR_USER_NOT_LOGGED_IN.

        The CKU_USER login established by the fixture is NOT sufficient
        on its own for always-auth keys — every operation needs a fresh
        context-specific re-auth.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("SHA256_RSA_PKCS not supported")
        if _pin_bytes(p11_config) is None:
            pytest.skip("Requires PIN to test context-specific re-auth")

        keypair = _try_gen_always_auth_keypair(rs)
        if keypair is None:
            pytest.skip("Module does not support CKA_ALWAYS_AUTHENTICATE=True keys")
        pub, priv = keypair

        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv_init = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            assert rv_init == CKR_OK, f"C_SignInit failed: {ckr_name(rv_init)}"

            # Attempt to sign without first calling CKU_CONTEXT_SPECIFIC login.
            # Spec: must return CKR_USER_NOT_LOGGED_IN.
            msg = b"always-auth-no-reauth-test"
            msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(256)
            rv_sign = int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, byref(sig_len)))

            if rv_sign == CKR_OK:
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_ALWAYS_AUTHENTICATE:C_Sign without re-auth",
                    operation="C_Sign",
                    summary=(
                        "C_Sign on CKA_ALWAYS_AUTHENTICATE=True key succeeded "
                        "without prior CKU_CONTEXT_SPECIFIC login — module is "
                        "not enforcing the spec-mandated re-authentication. "
                        "This is a CVE-class security gap."
                    ),
                )
            assert rv_sign == int(CKR_USER_NOT_LOGGED_IN), (
                f"C_Sign without re-auth returned {ckr_name(rv_sign)}, "
                f"expected CKR_USER_NOT_LOGGED_IN"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_with_context_specific_login_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """After CKU_CONTEXT_SPECIFIC login, C_Sign on the always-auth key succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("SHA256_RSA_PKCS not supported")
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("Requires PIN to test context-specific re-auth")

        keypair = _try_gen_always_auth_keypair(rs)
        if keypair is None:
            pytest.skip("Module does not support CKA_ALWAYS_AUTHENTICATE=True keys")
        pub, priv = keypair

        try:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv_init = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            assert rv_init == CKR_OK, f"C_SignInit (sign-with-reauth): {ckr_name(rv_init)}"

            # Context-specific re-auth
            rv_ctx = _context_specific_login(rs.raw, rs.sh, pin)
            if rv_ctx == int(CKR_FUNCTION_NOT_SUPPORTED):
                xfail_as(
                    "not_operational",
                    label="CKU_CONTEXT_SPECIFIC login",
                    operation="C_Login",
                    actual=rv_ctx,
                    summary="Module does not implement CKU_CONTEXT_SPECIFIC login",
                )
            assert rv_ctx == CKR_OK, f"CKU_CONTEXT_SPECIFIC login failed: {ckr_name(rv_ctx)}"

            # Sign should now succeed
            msg = b"always-auth-with-reauth"
            msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(256)
            rv_sign = int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, byref(sig_len)))
            assert rv_sign == CKR_OK, (
                f"C_Sign after CKU_CONTEXT_SPECIFIC login failed: {ckr_name(rv_sign)}"
            )
            assert sig_len.value == 256, f"Unexpected sig length: {sig_len.value}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_second_sign_requires_fresh_reauth(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Re-auth is single-use: a second operation needs a second CKU_CONTEXT_SPECIFIC.

        This is the property that makes CKA_ALWAYS_AUTHENTICATE meaningful.
        If a module re-uses the re-auth across operations, the attribute
        provides no security improvement over a normal CKU_USER login.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("SHA256_RSA_PKCS not supported")
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("Requires PIN to test context-specific re-auth")

        keypair = _try_gen_always_auth_keypair(rs)
        if keypair is None:
            pytest.skip("Module does not support CKA_ALWAYS_AUTHENTICATE=True keys")
        pub, priv = keypair

        def attempt_sign() -> int:
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv_init = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            if rv_init != CKR_OK:
                return rv_init
            msg = b"second-sign-needs-reauth"
            msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(256)
            return int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, byref(sig_len)))

        try:
            # First sign: re-auth + sign should succeed.
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv_init = int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))
            assert rv_init == CKR_OK
            rv_ctx = _context_specific_login(rs.raw, rs.sh, pin)
            if rv_ctx == int(CKR_FUNCTION_NOT_SUPPORTED):
                xfail_as(
                    "not_operational",
                    label="CKU_CONTEXT_SPECIFIC login",
                    operation="C_Login",
                    actual=rv_ctx,
                    summary="Module does not implement CKU_CONTEXT_SPECIFIC login",
                )
            assert rv_ctx == CKR_OK

            msg = b"first-sign"
            msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
            sig_buf = (ctypes.c_ubyte * 256)()
            sig_len = CK_ULONG(256)
            rv1 = int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, byref(sig_len)))
            assert rv1 == CKR_OK, f"First C_Sign failed: {ckr_name(rv1)}"

            # Second sign without a fresh re-auth: must fail.
            rv2 = attempt_sign()
            if rv2 == CKR_OK:
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_ALWAYS_AUTHENTICATE:re-auth reused",
                    operation="C_Sign",
                    summary=(
                        "Second C_Sign on always-auth key succeeded without a "
                        "fresh CKU_CONTEXT_SPECIFIC login — module is reusing "
                        "the re-auth.  The CKA_ALWAYS_AUTHENTICATE security "
                        "guarantee is not being enforced."
                    ),
                )
            assert rv2 == int(CKR_USER_NOT_LOGGED_IN), (
                f"Second C_Sign without re-auth returned {ckr_name(rv2)}, "
                f"expected CKR_USER_NOT_LOGGED_IN"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_specific_login_without_active_op_rejected(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKU_CONTEXT_SPECIFIC login outside an active operation must be rejected.

        Spec: re-auth is only meaningful in the context of an active
        operation on an always-auth key.  Calling it standalone must
        return CKR_OPERATION_NOT_INITIALIZED.  Any other clean rejection
        (including CKR_USER_NOT_LOGGED_IN, which is not in the spec's
        C_Login return list for this context) is a classified deviation.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("Requires PIN to test context-specific login")

        rv = _context_specific_login(rs.raw, rs.sh, pin)
        if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC login",
                operation="C_Login",
                actual=rv,
                summary="Module does not implement CKU_CONTEXT_SPECIFIC login",
            )
        if rv == CKR_OK:
            classify(
                "self_contradiction",
                kind="lifecycle",
                label="CKU_CONTEXT_SPECIFIC login outside active operation",
                operation="C_Login",
                summary=(
                    "Module accepted CKU_CONTEXT_SPECIFIC login outside any active "
                    "operation — spec requires CKR_OPERATION_NOT_INITIALIZED."
                ),
            )
        if rv == int(CKR_USER_TYPE_INVALID):
            classify(
                "not_operational",
                kind="lifecycle",
                label="CKU_CONTEXT_SPECIFIC login outside active operation",
                operation="C_Login",
                expected=[CKR_OPERATION_NOT_INITIALIZED, CKR_USER_NOT_LOGGED_IN],
                actual=rv,
                summary=(
                    "Module rejected CKU_CONTEXT_SPECIFIC login outside any active "
                    "operation with CKR_USER_TYPE_INVALID; this is a visible "
                    "non-spec rejection."
                ),
            )
        if rv == int(CKR_OPERATION_NOT_INITIALIZED):
            return
        # N-004: spec-mandated code is CKR_OPERATION_NOT_INITIALIZED only;
        # CKR_USER_NOT_LOGGED_IN is not in the spec's C_Login return list
        # for improper context-specific login. Keep the probe: any other
        # clean rejection is an explicit classified deviation, never a
        # pass and never a raw assert. An undefined CK_RV is a hard failure.
        if not is_standard_ckr(rv) and not is_vendor_defined_ckr(rv):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="CKU_CONTEXT_SPECIFIC login outside active operation",
                operation="C_Login",
                expected=int(CKR_OPERATION_NOT_INITIALIZED),
                actual=rv,
                detail={"ckr_validity": "undefined"},
                summary=(
                    "CKU_CONTEXT_SPECIFIC login without active op returned "
                    f"an undefined CK_RV {ckr_name(rv)}; spec requires "
                    "CKR_OPERATION_NOT_INITIALIZED"
                ),
            )
        xfail_as(
            "nonspec_reject",
            kind="lifecycle",
            label="CKU_CONTEXT_SPECIFIC login outside active operation",
            operation="C_Login",
            expected=int(CKR_OPERATION_NOT_INITIALIZED),
            actual=rv,
            summary=(
                "CKU_CONTEXT_SPECIFIC login without active op returned "
                f"{ckr_name(rv)}; spec requires CKR_OPERATION_NOT_INITIALIZED"
            ),
        )


# ---------------------------------------------------------------------------
# QC10b: context-authentication grant transitions (#52.5)
#
# Grant model (v3.2 §4.10): C_Login(CKU_CONTEXT_SPECIFIC) immediately after
# the operation is initiated sets the active key in an authenticated state
# that lasts until the cryptographic operation has successfully or
# unsuccessfully been completed. The login call is session-scoped, so the
# grant binds (session, active operation): it must not authorize a
# replacement operation, another session, or any use after a terminal call.
# Termination rules are per function (v3.2 §5.10-§5.15): single-part and
# Final calls always terminate unless they return CKR_BUFFER_TOO_SMALL or
# are a successful length query; Encrypt/Decrypt Update terminates on any
# error other than BTS; Sign/Digest Update terminates on any error; Verify
# always terminates. CKA_ALWAYS_AUTHENTICATE's normative scope is sign or
# decrypt private-key uses (attribute table row); verify/digest/encrypt
# carry no grant.
# ---------------------------------------------------------------------------

_QC10B_GRANT_APPLIES: frozenset[str] = frozenset({"sign", "decrypt"})

_QC10B_FUNCTION_SCOPE: dict[str, str] = {
    "sign": "private-key use: the context grant applies (v3.2 §4.10)",
    "decrypt": "private-key use: the context grant applies (v3.2 §4.10)",
    "verify": "public-key operation: no context grant (not a sign-or-decrypt use)",
    "digest": "keyless operation: no context grant (C_DigestKey edge unreviewed)",
    "encrypt": "public-key operation: no context grant (not a sign-or-decrypt use)",
}

_QC10B_AUTH_REJECT_RVS = (int(CKR_USER_NOT_LOGGED_IN),)
_QC10B_BAD_CIPHERTEXT_RVS = (int(CKR_ENCRYPTED_DATA_INVALID),)
_QC10B_RSA_BYTES = 256


def _qc10b_grant_applies(function: str) -> bool:
    """Whether the context-specific grant model applies to ``function``."""
    return function in _QC10B_GRANT_APPLIES


def _qc10b_is_terminal(*, function: str, call: str, rv: int, is_length_query: bool = False) -> bool:
    """Per-function termination: did this call complete the active operation?

    ``function`` is one of sign/decrypt/verify/digest/encrypt; ``call`` is
    one of single/final/update. Single-part and Final calls always terminate
    unless they return CKR_BUFFER_TOO_SMALL or are a successful length
    query; Encrypt/Decrypt Update terminates on any error other than BTS;
    Sign/Digest Update terminates on any error; Verify always terminates.
    """
    ok = int(CKR_OK)
    bts = int(CKR_BUFFER_TOO_SMALL)
    if call == "update":
        if function in ("encrypt", "decrypt"):
            return rv != ok and rv != bts
        return rv != ok
    if function == "verify":
        return True
    if rv == bts:
        return False
    if rv == ok and is_length_query:
        return False
    return True


def _qc10b_is_clean(rv: int) -> bool:
    return bool(is_standard_ckr(rv) or is_vendor_defined_ckr(rv))


def _qc10b_stage_ok(rv: int, *, operation: str, label: str) -> None:
    """Staging-call judge: CKR_OK proceeds; clean refusal xfails the premise."""
    if rv == int(CKR_OK):
        return
    if _qc10b_is_clean(rv):
        xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: staging {operation} refused with {ckr_name(rv)}",
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        detail={"ckr_validity": "undefined"},
        summary=f"{label}: staging {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10b_init_or_judge(
    rv: int, *, operation: str, function: str, after_terminal: bool, label: str
) -> None:
    """Init-call judge: CKR_OPERATION_ACTIVE after a terminal call is mis-termination."""
    if rv == int(CKR_OK):
        return
    if not _qc10b_is_clean(rv):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            detail={"ckr_validity": "undefined"},
            summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
        )
    if after_terminal and rv == int(CKR_OPERATION_ACTIVE):
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            detail={"function": function, "phase": "re-init-after-terminal-call"},
            summary=(
                f"{label}: {operation} returned CKR_OPERATION_ACTIVE after a "
                "terminal call -- the operation was not terminated"
            ),
        )
    xfail_as(
        "not_operational",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        summary=f"{label}: staging {operation} refused with {ckr_name(rv)}",
    )


def _qc10b_output_length_or_judge(
    reported: int,
    capacity: int,
    *,
    operation: str,
    mechanism: str,
    label: str,
    expected_len: int | None = None,
) -> None:
    """OK-return output contract (v3.2 §5.2): the reported length must fit the buffer.

    A CKR_OK return claims ``reported`` bytes were written into a ``capacity``
    buffer; a larger report is a length violation that callers must not clamp.
    Where the output size is deterministic (single-shot RSA-2048 PKCS#1 v1.5
    encrypt/sign/final), ``expected_len`` pins the exact report; variable-length
    outputs (C_Decrypt plaintext) stay capacity-only.
    """
    if reported < 0 or reported > capacity:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={"reported_length": reported, "buffer_capacity": capacity},
            summary=(
                f"{label}: {operation} returned CKR_OK with reported length "
                f"{reported} for a {capacity}-byte buffer"
            ),
        )
    if expected_len is not None and reported != expected_len:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={
                "reported_length": reported,
                "buffer_capacity": capacity,
                "expected_length": expected_len,
            },
            summary=(
                f"{label}: {operation} returned CKR_OK reporting {reported} "
                f"bytes, expected exactly {expected_len}"
            ),
        )


def _qc10b_positive_or_judge(
    rv: int,
    *,
    operation: str,
    mechanism: str,
    label: str,
    reported_len: int,
    capacity: int,
    expected_len: int | None = None,
) -> None:
    """Positive crypto call: CKR_OK proceeds; clean refusal xfails, never passes."""
    if rv == int(CKR_OK):
        _qc10b_output_length_or_judge(
            reported_len,
            capacity,
            operation=operation,
            mechanism=mechanism,
            label=label,
            expected_len=expected_len,
        )
        return
    if _qc10b_is_clean(rv):
        xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            summary=f"{label}: {operation} refused a valid granted call with {ckr_name(rv)}",
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        detail={"ckr_validity": "undefined"},
        summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10b_grantless_or_judge(
    rv: int, *, operation: str, mechanism: str, function: str, phase: str, label: str
) -> None:
    """Grantless use: canonical rejection passes; success fails (grant leak)."""
    if not _qc10b_grant_applies(function):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={"function": function, "phase": phase, "harness": "misuse"},
            summary=(
                f"{label}: grantless judging called for {function}, which is "
                "outside the context-grant model"
            ),
        )
    if rv in _QC10B_AUTH_REJECT_RVS:
        return
    if rv == int(CKR_OK):
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_USER_NOT_LOGGED_IN,
            actual=CKR_OK,
            detail={"function": function, "phase": phase},
            summary=(
                f"{label}: {operation} succeeded without a context grant "
                f"({function}/{phase}) -- grant leaked or was never required"
            ),
        )
    if _qc10b_is_clean(rv):
        classify(
            "nonspec_reject",
            label=label,
            operation=operation,
            mechanism=mechanism,
            actual=rv,
            expected=(CKR_USER_NOT_LOGGED_IN,),
            detail={"function": function, "phase": phase},
            summary=(
                f"{label}: rejected with {ckr_name(rv)}; "
                f"spec requires {ckr_name(int(CKR_USER_NOT_LOGGED_IN))}"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_USER_NOT_LOGGED_IN,
        actual=rv,
        detail={"function": function, "phase": phase, "ckr_validity": "undefined"},
        summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10b_reuse_update_or_judge(rv: int, *, mechanism: str, label: str) -> None:
    """Grantless reuse Update: canonical rejection passes; OK proceeds.

    CKR_OK proceeds to the Final judge (some providers check the grant only
    at Final); any other clean refusal is an honest alternate rejection like
    the grantless Final path -- not a broken premise; undefined fails.
    """
    if rv in _QC10B_AUTH_REJECT_RVS or rv == int(CKR_OK):
        return
    if _qc10b_is_clean(rv):
        classify(
            "nonspec_reject",
            label=label,
            operation="C_SignUpdate",
            mechanism=mechanism,
            actual=rv,
            expected=(CKR_USER_NOT_LOGGED_IN,),
            detail={"function": "sign", "phase": "grantless-reuse-update"},
            summary=(
                f"{label}: reuse Update rejected with {ckr_name(rv)}; "
                f"spec requires {ckr_name(int(CKR_USER_NOT_LOGGED_IN))}"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_SignUpdate",
        inherit_mechanism=False,
        expected=CKR_USER_NOT_LOGGED_IN,
        actual=rv,
        detail={"function": "sign", "phase": "grantless-reuse-update"},
        summary=f"{label}: reuse Update returned undefined {ckr_name(rv)}",
    )


def _qc10b_preserved_or_judge(
    rv: int,
    *,
    operation: str,
    mechanism: str,
    function: str,
    phase: str,
    label: str,
    reported_len: int,
    capacity: int,
    expected_len: int | None = None,
) -> None:
    """Post-nonterminal call: success proves preservation; auth rejection is loss.

    Both CKR_USER_NOT_LOGGED_IN (grant consumed) and
    CKR_OPERATION_NOT_INITIALIZED (operation terminated) prove the preceding
    nonterminal call killed live state it must preserve.
    """
    if not _qc10b_grant_applies(function):
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={"function": function, "phase": phase, "harness": "misuse"},
            summary=(
                f"{label}: preservation judging called for {function}, which is "
                "outside the context-grant model"
            ),
        )
    if rv == int(CKR_OK):
        _qc10b_output_length_or_judge(
            reported_len,
            capacity,
            operation=operation,
            mechanism=mechanism,
            label=label,
            expected_len=expected_len,
        )
        return
    if rv in _QC10B_AUTH_REJECT_RVS or rv == int(CKR_OPERATION_NOT_INITIALIZED):
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            detail={"function": function, "phase": phase},
            summary=(
                f"{label}: {operation} rejected with {ckr_name(rv)} after a "
                f"nonterminal {phase} -- live state was consumed by a call that "
                "must preserve it"
            ),
        )
    if _qc10b_is_clean(rv):
        xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_OK,
            actual=rv,
            detail={"function": function, "phase": phase},
            summary=(
                f"{label}: {operation} refused with {ckr_name(rv)} after a "
                f"nonterminal {phase}; grant state ambiguous"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_OK,
        actual=rv,
        detail={"function": function, "phase": phase, "ckr_validity": "undefined"},
        summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10b_ctx_login_or_xfail(raw: Any, sh: int, pin: bytes, *, label: str) -> None:
    """Context-specific login as staging: refusal xfails the grant premise."""
    rv = _context_specific_login(raw, sh, pin)
    _qc10b_stage_ok(rv, operation="C_Login", label=label)


def _qc10b_open_session_or_skip(rs: Any) -> int:
    """Open a second RW session; CKR_SESSION_COUNT is a capability skip."""
    try:
        return raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    except CkrAssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open the second session required by the context-auth matrix: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _qc10b_setup_inventory_or_xfail(
    rs: Any,
    *,
    phase: str,
    label: str,
    pending_op_rv: int | None = None,
    pending_operation: str = "C_GenerateKeyPair",
    pending_label: str | None = None,
) -> list[int]:
    """Setup inventory: clean refusal xfails the premise, undefined fails.

    When ``pending_op_rv`` is an undefined operation RV, a failed inventory
    must not mask it (R16-01): FAIL loud with both RVs, mirroring
    ``_qc10a_after_inventory_or_judge``'s undefined-preservation branch.

    Only CkrAssertionError is routed (this file is masking-guarded); a Find
    protocol violation propagates as a loud plugin-gate failure, never masked.
    """
    try:
        return find_objects_exhaustive(rs.raw, rs.sh)
    except CkrAssertionError as exc:
        rv = int(exc.rv)
        if pending_op_rv is not None and not _qc10b_is_clean(pending_op_rv):
            op_label = pending_label if pending_label is not None else label
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=op_label,
                operation=pending_operation,
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=pending_op_rv,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "phase": phase,
                    "operation_rv": ckr_name(pending_op_rv),
                    "inventory_rv": ckr_name(rv),
                    "producer_operation": pending_operation,
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    f"{pending_operation} returned undefined {ckr_name(pending_op_rv)}; "
                    f"{phase} inventory failed with {ckr_name(rv)}"
                ),
            )
        if not _qc10b_is_clean(rv):
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=rv,
                detail={"phase": phase, "rv": ckr_name(rv)},
                summary=f"{label}: {phase} inventory returned undefined {ckr_name(rv)}",
            )
        xfail_as(
            "not_operational",
            label=f"{label}: object inventory not operational",
            operation="C_FindObjects",
            inherit_mechanism=False,
            actual=rv,
            detail={"phase": phase, "rv": ckr_name(rv)},
            summary=f"{label}: {phase} inventory refused with {ckr_name(rv)}",
        )


def _qc10b_unique_label(prefix: str) -> str:
    return f"qc10b-{prefix}-{uuid.uuid4().hex[:8]}"


def _qc10b_gen_always_auth_keypair(rs: Any) -> tuple[int, int] | None:
    """Generate an RSA-2048 sign+decrypt keypair with CKA_ALWAYS_AUTHENTICATE=True.

    Mirrors ``_try_gen_always_auth_keypair`` tiers (clean keygen refusal
    xfails with producer context, clean/unreadable readback returns None so
    the caller skips, malformed/dropped attribute fails) with CKA_DECRYPT
    added so the same key serves the sign and decrypt transition legs.
    Returns (pub, priv) on success, or None when the module cleanly refuses
    the advertised setup/readback.

    Setup handles need ownership proof too: each returned handle is proved
    independently against the before/after inventory delta. Proved returned
    handles are destroyed on the unproved/mixed exits; foreign handles are
    never read as ours, never destroyed (unproved xfail, left alive).
    A refused keygen runs the
    after-inventory as well: a proved-new leftover is destroyed and fails,
    an unproved delta stays alive, and only a zero delta keeps the premise
    xfail. Both halves carry a unique setup label as the proof anchor.
    """
    setup_label = "CKA_ALWAYS_AUTHENTICATE setup inventory (QC10b)"
    before = _qc10b_setup_inventory_or_xfail(rs, phase="setup-before", label=setup_label)
    key_label = _qc10b_unique_label("setup-key")
    pub_attempt: dict[Any, Any] = {CKA_VERIFY: True, CKA_LABEL: key_label}
    priv_attempt: dict[Any, Any] = {
        CKA_SIGN: True,
        CKA_DECRYPT: True,
        CKA_ALWAYS_AUTHENTICATE: True,
        CKA_LABEL: key_label,
    }
    try:
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits=2048,
            public_attrs=pub_attempt,
            private_attrs=priv_attempt,
        )
    except CkrAssertionError as exc:
        # A refused keygen may still have created our key: run the
        # after-inventory and the refusal-ownership tiers (proved leftovers
        # are destroyed and fail, unproved deltas stay alive) before judging
        # the setup premise. The pending op RV rides along so an undefined
        # keygen survives a failed after-inventory (R16-01).
        after = _qc10b_setup_inventory_or_xfail(
            rs,
            phase="setup-after",
            label=setup_label,
            pending_op_rv=int(exc.rv),
            pending_operation="C_GenerateKeyPair",
            pending_label="CKA_ALWAYS_AUTHENTICATE key generation (QC10b)",
        )
        proved, unproved = partition_proved_new(
            rs.raw,
            rs.sh,
            before,
            after,
            attempt_templates=(dict(pub_attempt), dict(priv_attempt)),
        )
        if proved:
            for leaked in proved:
                destroy_quietly(rs.raw, rs.sh, leaked)
        if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            if proved:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label="CKA_ALWAYS_AUTHENTICATE key generation (QC10b)",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=exc.rv,
                    detail={
                        "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                        "disposition": "refused-but-created",
                        "new_handles": sorted(
                            {int(handle) for handle in after} - {int(handle) for handle in before}
                        ),
                        "proved_new_handles": sorted(proved),
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "CKM_RSA_PKCS_KEY_PAIR_GEN refused with "
                        f"{ckr_name(int(exc.rv))} but created {sorted(proved)}"
                    ),
                )
            if unproved:
                xfail_as(
                    "honest_deviation",
                    kind="metadata",
                    label="CKA_ALWAYS_AUTHENTICATE key generation (QC10b)",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=exc.rv,
                    detail={
                        "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                        "disposition": "unproved-effect",
                        "new_handles": sorted(
                            {int(handle) for handle in after} - {int(handle) for handle in before}
                        ),
                        "unproved_new_handles": sorted(unproved),
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "CKM_RSA_PKCS_KEY_PAIR_GEN refused with "
                        f"{ckr_name(int(exc.rv))} with an unproved inventory "
                        "delta; left alive"
                    ),
                )
            xfail_as(
                "not_operational",
                kind="metadata",
                label="CKA_ALWAYS_AUTHENTICATE key generation (QC10b)",
                operation="C_GenerateKeyPair",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    "CKM_RSA_PKCS_KEY_PAIR_GEN is advertised, but the provider "
                    "rejected CKA_ALWAYS_AUTHENTICATE=True at key generation"
                ),
            )
        fail_as(
            "self_contradiction",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE key generation (QC10b)",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            expected=CKR_OK,
            actual=exc.rv,
            detail={
                "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                "new_handles": sorted(
                    {int(handle) for handle in after} - {int(handle) for handle in before}
                ),
                "proved_new_handles": sorted(proved),
                "unproved_new_handles": sorted(unproved),
                "producer_operation": "C_GenerateKeyPair",
                "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
            },
            summary=(
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned an undefined CK_RV while "
                "creating a CKA_ALWAYS_AUTHENTICATE=True key"
            ),
        )

    if int(pub) == int(priv):
        # Aliased outputs are contradictory before any membership check: the
        # same handle cannot be both halves. Reject without using or
        # destroying it (either use would corrupt the mate), ahead of the
        # after-inventory so the known failure survives inventory gaps.
        fail_as(
            "self_contradiction",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE setup ownership (QC10b)",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            actual=CKR_OK,
            detail={
                "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                "disposition": "aliased-handles",
                "returned_handles": [int(pub), int(priv)],
                "producer_operation": "C_GenerateKeyPair",
                "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
            },
            summary=(
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK with the same "
                "handle for both halves; the handback is contradictory, left alone"
            ),
        )
    after = _qc10b_setup_inventory_or_xfail(rs, phase="setup-after", label=setup_label)
    proved, unproved = partition_proved_new(
        rs.raw,
        rs.sh,
        before,
        after,
        attempt_templates=(dict(pub_attempt), dict(priv_attempt)),
    )
    new_handles = sorted({int(handle) for handle in after} - {int(handle) for handle in before})
    extras = sorted(handle for handle in proved if handle != int(pub) and handle != int(priv))
    if extras:
        for leaked in extras:
            destroy_quietly(rs.raw, rs.sh, leaked)
        if int(pub) in proved and int(priv) in proved:
            destroy_quietly(rs.raw, rs.sh, int(pub))
            destroy_quietly(rs.raw, rs.sh, int(priv))
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="CKA_ALWAYS_AUTHENTICATE setup ownership (QC10b)",
                operation="C_GenerateKeyPair",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "phase": "setup",
                    "disposition": "created-extra",
                    "returned_handles": [int(pub), int(priv)],
                    "new_handles": new_handles,
                    "proved_new_handles": sorted(proved),
                    "extra_handles": extras,
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK but created extra "
                    f"proved objects {extras} beside the returned pair"
                ),
            )
        # Mixed ownership (R17-01): each proved returned handle is
        # destroyed independently; foreign handles are never touched.
        proved_returned = [handle for handle in (int(pub), int(priv)) if handle in proved]
        for handle in proved_returned:
            destroy_quietly(rs.raw, rs.sh, handle)
        mixed_detail: dict[str, Any] = {
            "attribute": int(CKA_ALWAYS_AUTHENTICATE),
            "phase": "setup",
            "disposition": "created-extra",
            "returned_handles": [int(pub), int(priv)],
            "new_handles": new_handles,
            "proved_new_handles": sorted(proved),
            "extra_handles": extras,
            "returned_handles_proved": False,
            "producer_operation": "C_GenerateKeyPair",
            "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
        }
        if proved_returned:
            foreign_returned = [handle for handle in (int(pub), int(priv)) if handle not in proved]
            mixed_detail["destroyed_returned_handles"] = proved_returned
            mixed_summary = (
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK with partially "
                f"proved handles but created proved objects {extras}; proved "
                f"returned {proved_returned} destroyed, foreign "
                f"{foreign_returned} left alive"
            )
        else:
            mixed_summary = (
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK with unproved handles "
                f"but created proved objects {extras}; the returned handles are "
                "foreign, left alive"
            )
        fail_as(
            "self_contradiction",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE setup ownership (QC10b)",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            actual=CKR_OK,
            detail=mixed_detail,
            summary=mixed_summary,
        )
    if int(pub) not in proved or int(priv) not in proved:
        # Partial ownership (R17-01): each proved returned handle is
        # destroyed independently; foreign handles are never touched.
        proved_returned = [handle for handle in (int(pub), int(priv)) if handle in proved]
        for handle in proved_returned:
            destroy_quietly(rs.raw, rs.sh, handle)
        unproved_detail: dict[str, Any] = {
            "attribute": int(CKA_ALWAYS_AUTHENTICATE),
            "phase": "setup",
            "disposition": "unproved-handle",
            "returned_handles": [int(pub), int(priv)],
            "new_handles": new_handles,
            "producer_operation": "C_GenerateKeyPair",
            "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
        }
        if proved_returned:
            foreign_returned = [handle for handle in (int(pub), int(priv)) if handle not in proved]
            unproved_detail["proved_new_handles"] = sorted(proved)
            unproved_detail["destroyed_returned_handles"] = proved_returned
            unproved_summary = (
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK with partially "
                f"proved handles; proved {proved_returned} destroyed, foreign "
                f"{foreign_returned} left alive"
            )
        else:
            unproved_summary = (
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK but the handles are "
                "not proved in the setup inventory delta; they are foreign, left alive"
            )
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE setup ownership (QC10b)",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            actual=CKR_OK,
            detail=unproved_detail,
            summary=unproved_summary,
        )
    if unproved:
        destroy_quietly(rs.raw, rs.sh, int(pub))
        destroy_quietly(rs.raw, rs.sh, int(priv))
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label="CKA_ALWAYS_AUTHENTICATE setup ownership (QC10b)",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            actual=CKR_OK,
            detail={
                "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                "phase": "setup",
                "disposition": "unproved-effect",
                "returned_handles": [int(pub), int(priv)],
                "new_handles": sorted(unproved),
                "proved_new_handles": [int(pub), int(priv)],
                "producer_operation": "C_GenerateKeyPair",
                "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
            },
            summary=(
                "CKM_RSA_PKCS_KEY_PAIR_GEN returned CKR_OK with unexpected delta "
                f"companions {sorted(unproved)}"
            ),
        )

    retain_handles = False
    try:
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ALWAYS_AUTHENTICATE])
        except CkrAssertionError as exc:
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
                classification.record_as(
                    "not_operational",
                    kind="metadata",
                    label="CKA_ALWAYS_AUTHENTICATE setup readback (QC10b)",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=CKR_OK,
                    actual=exc.rv,
                    detail={
                        "attribute": {
                            "name": "CKA_ALWAYS_AUTHENTICATE",
                            "id": int(CKA_ALWAYS_AUTHENTICATE),
                        },
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    },
                    summary=(
                        "CKA_ALWAYS_AUTHENTICATE readback was rejected after "
                        "successful key generation"
                    ),
                )
                return None
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="CKA_ALWAYS_AUTHENTICATE setup readback (QC10b)",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=exc.rv,
                detail={
                    "attribute": {
                        "name": "CKA_ALWAYS_AUTHENTICATE",
                        "id": int(CKA_ALWAYS_AUTHENTICATE),
                    },
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary="CKA_ALWAYS_AUTHENTICATE readback returned an undefined CK_RV",
            )

        value = attr_or_record(
            attrs,
            CKA_ALWAYS_AUTHENTICATE,
            label=(
                "CKA_ALWAYS_AUTHENTICATE setup readback (QC10b) "
                "(producer_operation=C_GenerateKeyPair, "
                "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            kind="metadata",
            inherit_mechanism=False,
        )
        if value is MISSING_ATTRIBUTE:
            missing_record = classification.get_records()[-1]
            if missing_record.detail is not None:
                missing_record.detail.update(
                    {
                        "producer_operation": "C_GenerateKeyPair",
                        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                    }
                )
            return None

        if type(value) is not bool:
            if isinstance(value, (bytes, bytearray, list, tuple, str)):
                actual_len: int | None = len(value)
            else:
                actual_len = None
            fail_as(
                "wrong_result",
                kind="policy",
                label="CKA_ALWAYS_AUTHENTICATE setup readback (QC10b)",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "expected_shape": "CK_BBOOL",
                    "expected_value": True,
                    "actual_type": type(value).__name__,
                    "actual_len": actual_len,
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=("C_GetAttributeValue returned a malformed CKA_ALWAYS_AUTHENTICATE value"),
            )
        if value is not True:
            fail_as(
                "wrong_result",
                kind="policy",
                label="CKA_ALWAYS_AUTHENTICATE setup readback (QC10b)",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                expected=CKR_OK,
                actual=CKR_OK,
                detail={
                    "attribute": int(CKA_ALWAYS_AUTHENTICATE),
                    "expected_value": True,
                    "actual_value": value,
                    "producer_operation": "C_GenerateKeyPair",
                    "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                },
                summary=(
                    "C_GenerateKeyPair returned CKR_OK but did not preserve "
                    "CKA_ALWAYS_AUTHENTICATE=True"
                ),
            )
        retain_handles = True
        return pub, priv
    finally:
        if not retain_handles:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


def _qc10b_sign_raw(raw: Any, sh: int, msg: bytes, *, capacity: int) -> tuple[int, bytes, int]:
    """C_Sign with an explicit buffer capacity; returns (rv, output, reported_len)."""
    msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
    sig_buf = (ctypes.c_ubyte * capacity)()
    sig_len = CK_ULONG(capacity)
    rv = int(raw.C_Sign(sh, msg_buf, len(msg), sig_buf, byref(sig_len)))
    reported = int(sig_len.value)
    return rv, bytes(sig_buf[: min(reported, capacity)]), reported


def _qc10b_sign_query_raw(raw: Any, sh: int, msg: bytes) -> tuple[int, int]:
    """C_Sign NULL-buffer length query; returns (rv, reported_len)."""
    msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
    sig_len = CK_ULONG(0)
    rv = int(raw.C_Sign(sh, msg_buf, len(msg), None, byref(sig_len)))
    return rv, int(sig_len.value)


def _qc10b_sign_update_raw(raw: Any, sh: int, part: bytes) -> int:
    """C_SignUpdate; returns the raw CK_RV."""
    buf = (ctypes.c_ubyte * len(part))(*part)
    return int(raw.C_SignUpdate(sh, buf, len(part)))


def _qc10b_sign_final_raw(raw: Any, sh: int, *, capacity: int) -> tuple[int, bytes, int]:
    """C_SignFinal with an explicit buffer capacity; returns (rv, output, reported_len)."""
    sig_buf = (ctypes.c_ubyte * capacity)()
    sig_len = CK_ULONG(capacity)
    rv = int(raw.C_SignFinal(sh, sig_buf, byref(sig_len)))
    reported = int(sig_len.value)
    return rv, bytes(sig_buf[: min(reported, capacity)]), reported


def _qc10b_decrypt_raw(raw: Any, sh: int, data: bytes, *, capacity: int) -> tuple[int, bytes, int]:
    """C_Decrypt with an explicit buffer capacity; returns (rv, output, reported_len)."""
    in_buf = (ctypes.c_ubyte * len(data))(*data)
    out_buf = (ctypes.c_ubyte * capacity)()
    out_len = CK_ULONG(capacity)
    rv = int(raw.C_Decrypt(sh, in_buf, len(data), out_buf, byref(out_len)))
    reported = int(out_len.value)
    return rv, bytes(out_buf[: min(reported, capacity)]), reported


def _qc10b_encrypt_raw(raw: Any, sh: int, data: bytes) -> tuple[int, bytes, int]:
    """C_Encrypt (RSA-2048 single shot); returns (rv, ciphertext, reported_len)."""
    in_buf = (ctypes.c_ubyte * len(data))(*data)
    out_buf = (ctypes.c_ubyte * _QC10B_RSA_BYTES)()
    out_len = CK_ULONG(_QC10B_RSA_BYTES)
    rv = int(raw.C_Encrypt(sh, in_buf, len(data), out_buf, byref(out_len)))
    reported = int(out_len.value)
    return rv, bytes(out_buf[: min(reported, _QC10B_RSA_BYTES)]), reported


def _qc10b_verify_rsa_signature(
    rs: Any,
    pub: int,
    msg: bytes,
    sig: bytes,
    *,
    label: str,
    operation: str,
    mechanism: str,
) -> None:
    """Independently verify an RSA signature against token-read public material.

    Passes silently on a valid signature. A wrong-length or invalid
    signature fails; unreadable public material xfails unproved (single
    record); malformed material or an undefined read RV fails.
    """
    if len(sig) != _QC10B_RSA_BYTES:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={"expected_length": _QC10B_RSA_BYTES, "actual_length": len(sig)},
            summary=f"{label}: signature length {len(sig)} != {_QC10B_RSA_BYTES}",
        )
    try:
        attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
    except CkrAssertionError as exc:
        rv = int(exc.rv)
        if _qc10b_is_clean(rv):
            xfail_as(
                "not_operational",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=rv,
                detail={"disposition": "unreadable-value"},
                summary=f"{label}: public-key readback refused with {ckr_name(rv)}",
            )
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=rv,
            detail={"ckr_validity": "undefined"},
            summary=f"{label}: public-key readback returned undefined {ckr_name(rv)}",
        )
    modulus = attr_or_record(
        attrs,
        CKA_MODULUS,
        label=f"{label} CKA_MODULUS readback",
        kind="metadata",
        inherit_mechanism=False,
    )
    if modulus is MISSING_ATTRIBUTE:
        record = classification.get_records()[-1]
        record.detail = {**(record.detail or {}), "disposition": "unreadable-value"}
        classification.raise_for_record(record)
    else:
        exponent = attr_or_record(
            attrs,
            CKA_PUBLIC_EXPONENT,
            label=f"{label} CKA_PUBLIC_EXPONENT readback",
            kind="metadata",
            inherit_mechanism=False,
        )
        if exponent is MISSING_ATTRIBUTE:
            record = classification.get_records()[-1]
            record.detail = {**(record.detail or {}), "disposition": "unreadable-value"}
            classification.raise_for_record(record)
        else:
            _qc10b_check_rsa_signature(label, operation, mechanism, msg, sig, modulus, exponent)


def _qc10b_check_rsa_signature(
    label: str,
    operation: str,
    mechanism: str,
    msg: bytes,
    sig: bytes,
    modulus: Any,
    exponent: Any,
) -> None:
    """Malformed-shape check plus independent verification of an RSA signature."""
    if (
        not isinstance(modulus, bytes)
        or len(modulus) != _QC10B_RSA_BYTES
        or not isinstance(exponent, bytes)
        or not 0 < len(exponent) <= 8
    ):
        fail_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            detail={
                "actual_modulus_type": type(modulus).__name__,
                "actual_exponent_type": type(exponent).__name__,
            },
            summary=f"{label}: public-key readback is malformed",
        )
    try:
        pubkey = rsa.RSAPublicNumbers(
            int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
        ).public_key()
    except ValueError:
        fail_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: public-key numbers are not a valid RSA key",
        )
    if not rsa_pkcs15_local(pubkey, msg, sig, hashes.SHA256()):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            detail={"signature_length": len(sig)},
            summary=f"{label}: independent verification of the {operation} output failed",
        )


def _qc10b_sign_init(rs: Any, sh: int, key: int, *, after_terminal: bool, label: str) -> None:
    mech = mech_simple(CKM_SHA256_RSA_PKCS)
    rv = int(rs.raw.C_SignInit(sh, mech.byref(), key))
    _qc10b_init_or_judge(
        rv, operation="C_SignInit", function="sign", after_terminal=after_terminal, label=label
    )


def _qc10b_decrypt_init(rs: Any, sh: int, key: int, *, after_terminal: bool, label: str) -> None:
    mech = mech_simple(CKM_RSA_PKCS)
    rv = int(rs.raw.C_DecryptInit(sh, mech.byref(), key))
    _qc10b_init_or_judge(
        rv,
        operation="C_DecryptInit",
        function="decrypt",
        after_terminal=after_terminal,
        label=label,
    )


def _qc10b_encrypt_init(rs: Any, sh: int, key: int, *, label: str) -> None:
    mech = mech_simple(CKM_RSA_PKCS)
    rv = int(rs.raw.C_EncryptInit(sh, mech.byref(), key))
    _qc10b_init_or_judge(
        rv, operation="C_EncryptInit", function="encrypt", after_terminal=False, label=label
    )


def _qc10b_bts_stage_or_judge(rv: int, *, operation: str, mechanism: str, label: str) -> None:
    """Tiny-buffer call must return CKR_BUFFER_TOO_SMALL; OK fails; else premise."""
    if rv == int(CKR_BUFFER_TOO_SMALL):
        return
    if rv == int(CKR_OK):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism=mechanism,
            summary=(
                f"{label}: {operation} into a 1-byte buffer returned CKR_OK instead "
                "of CKR_BUFFER_TOO_SMALL"
            ),
        )
    if _qc10b_is_clean(rv):
        xfail_as(
            "not_operational",
            label=label,
            operation=operation,
            mechanism=mechanism,
            expected=CKR_BUFFER_TOO_SMALL,
            actual=rv,
            summary=(
                f"{label}: {operation} into a 1-byte buffer refused with "
                f"{ckr_name(rv)}; BTS-preservation premise unmet"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        expected=CKR_BUFFER_TOO_SMALL,
        actual=rv,
        detail={"ckr_validity": "undefined"},
        summary=f"{label}: {operation} returned undefined {ckr_name(rv)}",
    )


def _qc10b_failure_stage_or_judge(rv: int, *, label: str) -> None:
    """Garbage decrypt must fail canonically; other outcomes xfail the premise."""
    if rv in _QC10B_BAD_CIPHERTEXT_RVS:
        return
    if _qc10b_is_clean(rv) or rv == int(CKR_OK):
        xfail_as(
            "not_operational",
            label=label,
            operation="C_Decrypt",
            mechanism="CKM_RSA_PKCS",
            expected=CKR_ENCRYPTED_DATA_INVALID,
            actual=rv,
            summary=(
                f"{label}: C_Decrypt of invalid padding returned {ckr_name(rv)}; "
                "failure-terminates premise unmet"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_Decrypt",
        inherit_mechanism=False,
        expected=CKR_ENCRYPTED_DATA_INVALID,
        actual=rv,
        detail={"ckr_validity": "undefined"},
        summary=f"{label}: C_Decrypt returned undefined {ckr_name(rv)}",
    )


def _qc10b_require_sign_gates(rs: Any, p11_config: Any) -> bytes:
    """Gate a sign leg on mechanisms + PIN; returns the PIN bytes."""
    if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("CKM_SHA256_RSA_PKCS not supported")
    pin = _pin_bytes(p11_config)
    if pin is None:
        pytest.skip("Requires PIN to test context-specific re-auth")
    return pin


def _qc10b_require_decrypt_gates(rs: Any, p11_config: Any) -> bytes:
    """Gate a decrypt leg on mechanisms + PIN; returns the PIN bytes."""
    pin = _qc10b_require_sign_gates(rs, p11_config)
    if not rs.has_mechanism("RSA_PKCS"):
        pytest.skip("CKM_RSA_PKCS not supported")
    return pin


def _qc10b_setup_keypair_or_skip(rs: Any) -> tuple[int, int]:
    """Generate one QC10b always-auth keypair; skip when unsupported."""
    keypair = _qc10b_gen_always_auth_keypair(rs)
    if keypair is None:
        pytest.skip("Module does not support CKA_ALWAYS_AUTHENTICATE=True keys")
    return keypair


class TestContextAuthTransitions:
    """Context-grant binding across keys, sessions, and terminality (v3.2 §4.10).

    Two-key/two-session matrix over the always-authenticate context model:
    replacement, cross-session misuse, reauthentication, terminal
    consumption, nonterminal length query, and BUFFER_TOO_SMALL retry.
    Mis-termination in either direction fails with function + phase in
    evidence; every leg consumes or judges each staged operation exactly
    once, so no dangling operation survives a verdict.
    """

    def test_context_terminal_sign_consumes_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Granted C_Sign succeeds (verified) and consumes the grant."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context terminal sign"
        msg = b"qc10b-terminal-sign"
        try:
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv, sig, reported = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                msg,
                sig,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=True, label=label)
            rv2, _, _ = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="second-use-without-reauth",
                label=label,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_replacement_key_requires_fresh_reauth(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A consumed grant does not authorize a replacement operation on key 2."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub1, priv1 = _qc10b_setup_keypair_or_skip(rs)
        pub2, priv2 = _qc10b_setup_keypair_or_skip(rs)
        label = "context replacement key"
        msg = b"qc10b-replacement-key"
        try:
            _qc10b_sign_init(rs, rs.sh, priv1, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv, sig, reported = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub1,
                msg,
                sig,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
            _qc10b_sign_init(rs, rs.sh, priv2, after_terminal=True, label=label)
            rv2, _, _ = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="replacement-key-without-reauth",
                label=label,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)

    def test_context_grant_rejected_across_sessions(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A session-1 grant must not authorize session-2 use; session 1 stays live."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        s2 = _qc10b_open_session_or_skip(rs)
        label = "context cross-session grant"
        msg = b"qc10b-cross-session"
        try:
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            _qc10b_sign_init(rs, s2, priv, after_terminal=False, label=label)
            rv_misuse, _, _ = _qc10b_sign_raw(rs.raw, s2, msg, capacity=_QC10B_RSA_BYTES)
            rv_live, sig, live_reported = _qc10b_sign_raw(
                rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES
            )
            if not _qc10b_is_clean(rv_misuse) and rv_misuse != int(CKR_OK):
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_Sign",
                    inherit_mechanism=False,
                    actual=rv_misuse,
                    detail={"function": "sign", "phase": "cross-session-misuse"},
                    summary=f"{label}: cross-session use returned undefined {ckr_name(rv_misuse)}",
                )
            if not _qc10b_is_clean(rv_live) and rv_live != int(CKR_OK):
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_Sign",
                    inherit_mechanism=False,
                    actual=rv_live,
                    detail={"function": "sign", "phase": "granting-session-liveness"},
                    summary=f"{label}: granting-session use returned undefined {ckr_name(rv_live)}",
                )
            if rv_misuse == int(CKR_OK):
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    expected=CKR_USER_NOT_LOGGED_IN,
                    actual=CKR_OK,
                    detail={"function": "sign", "phase": "cross-session-misuse"},
                    summary=(
                        f"{label}: C_Sign on session 2 succeeded on a session-1 "
                        "grant -- the grant is not session-bound"
                    ),
                )
            # The granting session is judged FIRST: a non-canonical misuse
            # rejection must never mask an independently-judgeable session-1
            # failure (liveness, output, or termination). The cross-session
            # xfail below fires only for a healthy session 1.
            if rv_live == int(CKR_OK):
                _qc10b_output_length_or_judge(
                    live_reported,
                    _QC10B_RSA_BYTES,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    label=label,
                    expected_len=_QC10B_RSA_BYTES,
                )
                _qc10b_verify_rsa_signature(
                    rs,
                    pub,
                    msg,
                    sig,
                    label=label,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                )
                if rv_misuse not in _QC10B_AUTH_REJECT_RVS:
                    classify(
                        "nonspec_reject",
                        label=label,
                        operation="C_Sign",
                        mechanism="CKM_SHA256_RSA_PKCS",
                        actual=rv_misuse,
                        expected=(CKR_USER_NOT_LOGGED_IN,),
                        detail={"function": "sign", "phase": "cross-session-misuse"},
                        summary=(
                            f"{label}: cross-session use rejected with {ckr_name(rv_misuse)}; "
                            f"spec requires {ckr_name(int(CKR_USER_NOT_LOGGED_IN))}"
                        ),
                    )
                return
            if rv_live in _QC10B_AUTH_REJECT_RVS:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    expected=CKR_OK,
                    actual=rv_live,
                    detail={"function": "sign", "phase": "granting-session-liveness"},
                    summary=(
                        f"{label}: the granting session lost its live grant without "
                        "any terminal call"
                    ),
                )
            if rv_live == int(CKR_OPERATION_NOT_INITIALIZED):
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    expected=CKR_OK,
                    actual=rv_live,
                    detail={"function": "sign", "phase": "granting-session-liveness"},
                    summary=(
                        f"{label}: the granting-session operation terminated "
                        "prematurely without any terminal call"
                    ),
                )
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                expected=CKR_OK,
                actual=rv_live,
                detail={"function": "sign", "phase": "granting-session-liveness"},
                summary=(
                    f"{label}: granting-session use refused with {ckr_name(rv_live)}; "
                    "grant liveness unproven"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            close_session_quietly(rs.raw, s2)

    def test_context_reauthentication_restores_after_consumption(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Consume, reject without re-auth, then re-authenticate and succeed."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        s2 = _qc10b_open_session_or_skip(rs)
        label = "context reauthentication"
        msg = b"qc10b-reauth"
        try:
            _qc10b_sign_init(rs, s2, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, s2, pin, label=label)
            rv, sig, reported = _qc10b_sign_raw(rs.raw, s2, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                msg,
                sig,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
            _qc10b_sign_init(rs, s2, priv, after_terminal=True, label=label)
            rv2, _, _ = _qc10b_sign_raw(rs.raw, s2, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="second-use-without-reauth",
                label=label,
            )
            _qc10b_sign_init(rs, s2, priv, after_terminal=True, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, s2, pin, label=label)
            rv3, sig3, reported3 = _qc10b_sign_raw(rs.raw, s2, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv3,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                label=label,
                reported_len=reported3,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                msg,
                sig3,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            close_session_quietly(rs.raw, s2)

    def test_context_length_query_preserves_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A successful NULL-buffer length query must not consume the grant."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        s2 = _qc10b_open_session_or_skip(rs)
        label = "context length query"
        msg = b"qc10b-length-query"
        try:
            _qc10b_sign_init(rs, s2, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, s2, pin, label=label)
            rv_query, reported = _qc10b_sign_query_raw(rs.raw, s2, msg)
            _qc10b_stage_ok(rv_query, operation="C_Sign", label=f"{label} query")
            # v3.2 §5.2 permits a NULL-buffer query to overestimate: only an
            # under-estimate (below the 256-byte RSA-2048 size) misleads the
            # caller and would overrun a real buffer. Overestimates proceed to
            # the exactly-judged + independently verified followup below.
            if reported < _QC10B_RSA_BYTES:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=label,
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    detail={
                        "expected_length": _QC10B_RSA_BYTES,
                        "actual_length": reported,
                    },
                    summary=(
                        f"{label}: length query reported {reported}, "
                        f"below the {_QC10B_RSA_BYTES}-byte minimum"
                    ),
                )
            rv, sig, sig_reported = _qc10b_sign_raw(rs.raw, s2, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_preserved_or_judge(
                rv,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="length-query-preservation",
                label=label,
                reported_len=sig_reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                msg,
                sig,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            close_session_quietly(rs.raw, s2)

    def test_context_buffer_too_small_preserves_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKR_BUFFER_TOO_SMALL must not consume the grant; retry succeeds."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context sign BTS retry"
        msg = b"qc10b-bts-retry"
        try:
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv_tiny, _, _ = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=1)
            _qc10b_bts_stage_or_judge(
                rv_tiny, operation="C_Sign", mechanism="CKM_SHA256_RSA_PKCS", label=label
            )
            rv, sig, reported = _qc10b_sign_raw(rs.raw, rs.sh, msg, capacity=_QC10B_RSA_BYTES)
            _qc10b_preserved_or_judge(
                rv,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="too-small-retry-preservation",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                msg,
                sig,
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_multipart_update_preserves_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Successful C_SignUpdate calls must not consume the grant."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context multipart update"
        part1 = b"qc10b-multipart-part-1-"
        part2 = b"qc10b-multipart-part-2"
        try:
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv_u1 = _qc10b_sign_update_raw(rs.raw, rs.sh, part1)
            _qc10b_stage_ok(rv_u1, operation="C_SignUpdate", label=label)
            rv_u2 = _qc10b_sign_update_raw(rs.raw, rs.sh, part2)
            _qc10b_stage_ok(rv_u2, operation="C_SignUpdate", label=label)
            rv, sig, reported = _qc10b_sign_final_raw(rs.raw, rs.sh, capacity=_QC10B_RSA_BYTES)
            _qc10b_preserved_or_judge(
                rv,
                operation="C_SignFinal",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="multipart-update-preservation",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                part1 + part2,
                sig,
                label=label,
                operation="C_SignFinal",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_sign_update_error_terminates_operation(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A clean C_SignUpdate error terminates the operation: Final must report dead."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context sign update error"
        part = b"qc10b-sign-update-error"
        try:
            _qc10b_sign_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv_u = _qc10b_sign_update_raw(rs.raw, rs.sh, part)
            if rv_u == int(CKR_OK):
                xfail_as(
                    "not_operational",
                    label=label,
                    operation="C_SignUpdate",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    actual=rv_u,
                    summary=(
                        f"{label}: Update returned CKR_OK; no update error to judge termination on"
                    ),
                )
            # No BTS exception: v3.2 §5.13.3 gives SignUpdate errors no
            # BUFFER_TOO_SMALL carve-out, so BTS routes through the termination
            # table below like any other clean Update error.
            if not _qc10b_is_clean(rv_u):
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_SignUpdate",
                    inherit_mechanism=False,
                    actual=rv_u,
                    detail={"function": "sign", "phase": "update-error"},
                    summary=f"{label}: Update returned undefined {ckr_name(rv_u)}",
                )
            # The termination table is the single source for the dead-op
            # premise (provably True here: a clean non-OK sign Update, BTS
            # included); its answer rides in the evidence below.
            terminal = _qc10b_is_terminal(function="sign", call="update", rv=rv_u)
            rv_f, _, _ = _qc10b_sign_final_raw(rs.raw, rs.sh, capacity=_QC10B_RSA_BYTES)
            if rv_f == int(CKR_OPERATION_NOT_INITIALIZED):
                return
            if rv_f == int(CKR_OK):
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_SignFinal",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    expected=CKR_OPERATION_NOT_INITIALIZED,
                    actual=rv_f,
                    detail={
                        "function": "sign",
                        "phase": "final-after-error-terminated-update",
                        "update_rv": ckr_name(rv_u),
                        "terminal": terminal,
                    },
                    summary=(
                        f"{label}: Final succeeded after an error-terminated "
                        "Update; the operation should be dead"
                    ),
                )
            if _qc10b_is_clean(rv_f):
                classify(
                    "nonspec_reject",
                    label=label,
                    operation="C_SignFinal",
                    mechanism="CKM_SHA256_RSA_PKCS",
                    actual=rv_f,
                    expected=(CKR_OPERATION_NOT_INITIALIZED,),
                    detail={
                        "function": "sign",
                        "phase": "final-after-error-terminated-update",
                        "update_rv": ckr_name(rv_u),
                        "terminal": terminal,
                    },
                    summary=(
                        f"{label}: Final reported {ckr_name(rv_f)} after an "
                        "error-terminated Update; spec requires "
                        f"{ckr_name(int(CKR_OPERATION_NOT_INITIALIZED))}"
                    ),
                )
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_SignFinal",
                inherit_mechanism=False,
                actual=rv_f,
                detail={
                    "function": "sign",
                    "phase": "final-after-error-terminated-update",
                    "update_rv": ckr_name(rv_u),
                },
                summary=f"{label}: Final returned undefined {ckr_name(rv_f)}",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_multipart_final_consumes_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A consumed multipart grant authorizes no second multipart operation."""
        rs = p11_raw_session
        pin = _qc10b_require_sign_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        s2 = _qc10b_open_session_or_skip(rs)
        label = "context multipart final"
        part = b"qc10b-multipart-final"
        try:
            _qc10b_sign_init(rs, s2, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, s2, pin, label=label)
            rv_u = _qc10b_sign_update_raw(rs.raw, s2, part)
            _qc10b_stage_ok(rv_u, operation="C_SignUpdate", label=label)
            rv, sig, reported = _qc10b_sign_final_raw(rs.raw, s2, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv,
                operation="C_SignFinal",
                mechanism="CKM_SHA256_RSA_PKCS",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_verify_rsa_signature(
                rs,
                pub,
                part,
                sig,
                label=label,
                operation="C_SignFinal",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
            _qc10b_sign_init(rs, s2, priv, after_terminal=True, label=label)
            rv_u2 = _qc10b_sign_update_raw(rs.raw, s2, part)
            if rv_u2 in _QC10B_AUTH_REJECT_RVS:
                # The provider checks the grant at Update: consumption proven.
                return
            _qc10b_reuse_update_or_judge(
                rv_u2, mechanism="CKM_SHA256_RSA_PKCS", label=f"{label} reuse"
            )
            rv2, _, _ = _qc10b_sign_final_raw(rs.raw, s2, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_SignFinal",
                mechanism="CKM_SHA256_RSA_PKCS",
                function="sign",
                phase="multipart-final-without-reauth",
                label=label,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            close_session_quietly(rs.raw, s2)

    def test_context_terminal_decrypt_consumes_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Granted C_Decrypt round-trips and consumes the grant."""
        rs = p11_raw_session
        pin = _qc10b_require_decrypt_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context terminal decrypt"
        msg = b"qc10b-decrypt-plaintext"
        try:
            _qc10b_encrypt_init(rs, rs.sh, pub, label=label)
            rv_enc, ct, reported_enc = _qc10b_encrypt_raw(rs.raw, rs.sh, msg)
            _qc10b_stage_ok(rv_enc, operation="C_Encrypt", label=label)
            _qc10b_output_length_or_judge(
                reported_enc,
                _QC10B_RSA_BYTES,
                operation="C_Encrypt",
                mechanism="CKM_RSA_PKCS",
                label=label,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_decrypt_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv, pt, reported = _qc10b_decrypt_raw(rs.raw, rs.sh, ct, capacity=_QC10B_RSA_BYTES)
            _qc10b_positive_or_judge(
                rv,
                operation="C_Decrypt",
                mechanism="CKM_RSA_PKCS",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
            )
            if pt != msg:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=label,
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS",
                    detail={"expected_length": len(msg), "actual_length": len(pt)},
                    summary=f"{label}: C_Decrypt output does not match the plaintext",
                )
            _qc10b_decrypt_init(rs, rs.sh, priv, after_terminal=True, label=label)
            rv2, _, _ = _qc10b_decrypt_raw(rs.raw, rs.sh, ct, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_Decrypt",
                mechanism="CKM_RSA_PKCS",
                function="decrypt",
                phase="second-use-without-reauth",
                label=label,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_context_decrypt_failure_terminates_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A terminally failed decrypt consumes the grant like a success."""
        rs = p11_raw_session
        pin = _qc10b_require_decrypt_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        s2 = _qc10b_open_session_or_skip(rs)
        label = "context decrypt failure"
        msg = b"qc10b-decrypt-failure"
        garbage = b"\x55" * _QC10B_RSA_BYTES
        try:
            _qc10b_encrypt_init(rs, s2, pub, label=label)
            rv_enc, ct, reported_enc = _qc10b_encrypt_raw(rs.raw, s2, msg)
            _qc10b_stage_ok(rv_enc, operation="C_Encrypt", label=label)
            _qc10b_output_length_or_judge(
                reported_enc,
                _QC10B_RSA_BYTES,
                operation="C_Encrypt",
                mechanism="CKM_RSA_PKCS",
                label=label,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_decrypt_init(rs, s2, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, s2, pin, label=label)
            rv_bad, _, _ = _qc10b_decrypt_raw(rs.raw, s2, garbage, capacity=_QC10B_RSA_BYTES)
            _qc10b_failure_stage_or_judge(rv_bad, label=label)
            _qc10b_decrypt_init(rs, s2, priv, after_terminal=True, label=label)
            rv2, _, _ = _qc10b_decrypt_raw(rs.raw, s2, ct, capacity=_QC10B_RSA_BYTES)
            _qc10b_grantless_or_judge(
                rv2,
                operation="C_Decrypt",
                mechanism="CKM_RSA_PKCS",
                function="decrypt",
                phase="use-after-terminal-failure-without-reauth",
                label=label,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            close_session_quietly(rs.raw, s2)

    def test_context_decrypt_bts_preserves_grant(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Decrypt CKR_BUFFER_TOO_SMALL must not consume the grant; retry succeeds."""
        rs = p11_raw_session
        pin = _qc10b_require_decrypt_gates(rs, p11_config)
        pub, priv = _qc10b_setup_keypair_or_skip(rs)
        label = "context decrypt BTS retry"
        msg = b"qc10b-decrypt-bts"
        try:
            _qc10b_encrypt_init(rs, rs.sh, pub, label=label)
            rv_enc, ct, reported_enc = _qc10b_encrypt_raw(rs.raw, rs.sh, msg)
            _qc10b_stage_ok(rv_enc, operation="C_Encrypt", label=label)
            _qc10b_output_length_or_judge(
                reported_enc,
                _QC10B_RSA_BYTES,
                operation="C_Encrypt",
                mechanism="CKM_RSA_PKCS",
                label=label,
                expected_len=_QC10B_RSA_BYTES,
            )
            _qc10b_decrypt_init(rs, rs.sh, priv, after_terminal=False, label=label)
            _qc10b_ctx_login_or_xfail(rs.raw, rs.sh, pin, label=label)
            rv_tiny, _, _ = _qc10b_decrypt_raw(rs.raw, rs.sh, ct, capacity=1)
            _qc10b_bts_stage_or_judge(
                rv_tiny, operation="C_Decrypt", mechanism="CKM_RSA_PKCS", label=label
            )
            rv, pt, reported = _qc10b_decrypt_raw(rs.raw, rs.sh, ct, capacity=_QC10B_RSA_BYTES)
            _qc10b_preserved_or_judge(
                rv,
                operation="C_Decrypt",
                mechanism="CKM_RSA_PKCS",
                function="decrypt",
                phase="too-small-retry-preservation",
                label=label,
                reported_len=reported,
                capacity=_QC10B_RSA_BYTES,
            )
            if pt != msg:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=label,
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS",
                    detail={"expected_length": len(msg), "actual_length": len(pt)},
                    summary=f"{label}: C_Decrypt output does not match the plaintext",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

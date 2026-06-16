"""CKA_ALWAYS_AUTHENTICATE enforcement tests.

When a private key has `CKA_ALWAYS_AUTHENTICATE=TRUE`, the PKCS#11 spec
requires the application to call `C_Login(CKU_CONTEXT_SPECIFIC, pin)`
*immediately before each operation* that uses the key.  The re-auth is
single-use: a second operation on the same key requires another
`CKU_CONTEXT_SPECIFIC` login.

This file exercises the operational enforcement.  test_attribute_enforcement.py
already covers attribute readability and keygen-time setting; the work
here is the runtime "sign-needs-reauth" path that historically has been
mis-implemented (YubiHSM2, Thales Luna both had CVE-class bugs).

Source: PKCS#11 v2.40 §11.6, v3.0 §5.5 (CKU_CONTEXT_SPECIFIC semantics).
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CK_UTF8CHAR,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_SIGN,
    CKA_VERIFY,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
    CKU_CONTEXT_SPECIFIC,
)

pytestmark = [pytest.mark.access]


# CKR codes signaling "module doesn't support CKA_ALWAYS_AUTHENTICATE=True
# at keygen" — skip gracefully rather than failing.
_KEYGEN_ATTR_SKIP_RVS: frozenset[int] = frozenset(
    {
        CKR_TEMPLATE_INCONSISTENT,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_ARGUMENTS_BAD,
    }
)


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

    Returns (pub, priv) on success, or None when the module rejects the
    attribute at keygen time (in which case the caller should pytest.skip).
    """
    try:
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits=2048,
            public_attrs={CKA_VERIFY: True},
            private_attrs={CKA_SIGN: True, CKA_ALWAYS_AUTHENTICATE: True},
        )
    except AssertionError as exc:
        rv = getattr(exc, "rv", None)
        if rv in _KEYGEN_ATTR_SKIP_RVS:
            return None
        raise

    # Verify the module actually persisted the attribute.  Some modules
    # silently drop it; we want enforcement tests, not fake-pass tests.
    try:
        attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ALWAYS_AUTHENTICATE])
    except AssertionError:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)
        return None

    if CKA_ALWAYS_AUTHENTICATE not in attrs or attrs[CKA_ALWAYS_AUTHENTICATE] is not True:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)
        return None

    return pub, priv


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
                pytest.skip("Module does not implement CKU_CONTEXT_SPECIFIC login")
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
                pytest.skip("Module does not implement CKU_CONTEXT_SPECIFIC login")
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
        return CKR_OPERATION_NOT_INITIALIZED (or
        CKR_USER_NOT_LOGGED_IN).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("Requires PIN to test context-specific login")

        rv = _context_specific_login(rs.raw, rs.sh, pin)
        if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.skip("Module does not implement CKU_CONTEXT_SPECIFIC login")
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
        # CKR_OPERATION_NOT_INITIALIZED is spec-mandated; some modules
        # return CKR_USER_NOT_LOGGED_IN which is also defensible.
        assert rv in (
            int(CKR_OPERATION_NOT_INITIALIZED),
            int(CKR_USER_NOT_LOGGED_IN),
        ), (
            f"CKU_CONTEXT_SPECIFIC login without active op returned "
            f"{ckr_name(rv)}; expected CKR_OPERATION_NOT_INITIALIZED"
        )

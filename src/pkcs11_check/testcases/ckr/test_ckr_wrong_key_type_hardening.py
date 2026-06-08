"""Crash-safe wrong-key-type operation hardening.

These probes extend basic ``*Init`` CKR checks by continuing into the terminal
operation when a module incorrectly accepts a mismatched asymmetric key.
"""

from __future__ import annotations

from textwrap import dedent
from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKA_VERIFY
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
        slot_label="pkcs11-check",
    )


def _require_rsa_sign_verify_setup(rs: Any) -> None:
    pub = priv = 0
    try:
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


_RSA_KEYPAIR_SETUP = """\
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKA_VERIFY

try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
        private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:RSA sign/verify keypair setup rejected: {exc}", flush=True)
    cleanup()
    raise SystemExit(0)
"""


_SIGN_WITH_RSA_UNDER_ECDSA = """\
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKM_ECDSA,
    CK_MECHANISM,
    CK_ULONG,
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)

allowed = {
    int(CKR_KEY_TYPE_INCONSISTENT),
    int(CKR_MECHANISM_INVALID),
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_FUNCTION_FAILED),
}
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    if int(rv) in allowed:
        print(f"OK:C_SignInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
    elif rv != CKR_OK:
        raise AssertionError(
            "C_SignInit(CKM_ECDSA, RSA private key) returned unexpected "
            f"{ckr_name(rv)}"
        )
    else:
        data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        sig = (ctypes.c_ubyte * 512)()
        sig_len = CK_ULONG(512)
        sign_rv = raw.C_Sign(sh, data, 32, sig, ctypes.byref(sig_len))
        raise AssertionError(
            "C_SignInit(CKM_ECDSA, RSA private key) returned CKR_OK; "
            f"subsequent C_Sign returned {ckr_name(sign_rv)}"
        )
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
    cleanup()
"""


_VERIFY_WITH_RSA_UNDER_ECDSA = """\
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKM_ECDSA,
    CK_MECHANISM,
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)

allowed = {
    int(CKR_KEY_TYPE_INCONSISTENT),
    int(CKR_MECHANISM_INVALID),
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_FUNCTION_FAILED),
}
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
    if int(rv) in allowed:
        print(f"OK:C_VerifyInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
    elif rv != CKR_OK:
        raise AssertionError(
            "C_VerifyInit(CKM_ECDSA, RSA public key) returned unexpected "
            f"{ckr_name(rv)}"
        )
    else:
        data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        sig = (ctypes.c_ubyte * 64)(*([0xA5] * 64))
        verify_rv = raw.C_Verify(sh, data, 32, sig, 64)
        raise AssertionError(
            "C_VerifyInit(CKM_ECDSA, RSA public key) returned CKR_OK; "
            f"subsequent C_Verify returned {ckr_name(verify_rv)}"
        )
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
    cleanup()
"""


class TestWrongAsymmetricKeyTypeContinuation:
    """Wrong asymmetric key types must not leave a usable operation behind."""

    def test_wrong_asymmetric_key_type_sign_continuation_no_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """RSA private key under CKM_ECDSA must reject before C_Sign can run."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        _require_rsa_sign_verify_setup(rs)

        script = _preamble(p11_config) + dedent(_RSA_KEYPAIR_SETUP + _SIGN_WITH_RSA_UNDER_ECDSA)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_ckr_subprocess_ok(
            rc,
            stdout,
            stderr,
            context=(
                "C_SignInit(CKM_ECDSA, RSA private key) followed by C_Sign if accepted"
            ),
        )

    def test_wrong_asymmetric_key_type_verify_continuation_no_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """RSA public key under CKM_ECDSA must reject before C_Verify can run."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        _require_rsa_sign_verify_setup(rs)

        script = (
            _preamble(p11_config) + dedent(_RSA_KEYPAIR_SETUP + _VERIFY_WITH_RSA_UNDER_ECDSA)
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_ckr_subprocess_ok(
            rc,
            stdout,
            stderr,
            context=(
                "C_VerifyInit(CKM_ECDSA, RSA public key) followed by C_Verify if accepted"
            ),
        )

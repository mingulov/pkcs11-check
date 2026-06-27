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
)

# The contract is "a wrong key type must not leave a USABLE operation behind".
# Classify by effect, not by the *Init return code:
#   - C_SignInit rejects (any clean CK_RV)            -> no usable op    (OK)
#   - C_SignInit lenient (CKR_OK), C_Sign refuses     -> safe deviation  (xfail)
#   - C_SignInit lenient (CKR_OK), C_Sign PRODUCES sig-> usable wrong-key op (fail)
#   - either call crashes                             -> signal death    (fail)
# Some modules take the safe-deviation path (SignInit CKR_OK, C_Sign CKR_GENERAL_ERROR);
# others reject at init. PKCS#11 5.2 prefers
# CKR_KEY_TYPE_INCONSISTENT at C_SignInit, but a late-but-safe refusal is a
# recorded deviation, not a forgery.
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    if rv != CKR_OK:
        print(f"OK:C_SignInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
    else:
        data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        sig = (ctypes.c_ubyte * 512)()
        sig_len = CK_ULONG(512)
        sign_rv = raw.C_Sign(sh, data, 32, sig, ctypes.byref(sig_len))
        if int(sign_rv) == int(CKR_OK):
            print(
                "BREAK:C_SignInit(CKM_ECDSA, RSA private key) returned CKR_OK and "
                "C_Sign PRODUCED a signature -- usable wrong-key operation",
                flush=True,
            )
        else:
            print(
                "DEVIATION_XFAIL:C_SignInit(CKM_ECDSA, RSA private key) accepted "
                f"(CKR_OK) but C_Sign safely refused with {ckr_name(sign_rv)} -- "
                "lenient init, no usable operation (PKCS#11 5.2 prefers "
                "CKR_KEY_TYPE_INCONSISTENT at init)",
                flush=True,
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
)

# Same effect-based contract as the sign probe: a usable wrong-key C_Verify is
# the break; a late-but-safe refusal after a lenient C_VerifyInit is a recorded
# deviation. A wrong-key C_Verify that returns CKR_OK would mean the module
# claims to have verified an ECDSA signature with an RSA key.
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDSA
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
    if rv != CKR_OK:
        print(f"OK:C_VerifyInit rejected wrong RSA key for ECDSA: {ckr_name(rv)}", flush=True)
    else:
        data = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        sig = (ctypes.c_ubyte * 64)(*([0xA5] * 64))
        verify_rv = raw.C_Verify(sh, data, 32, sig, 64)
        if int(verify_rv) == int(CKR_OK):
            print(
                "BREAK:C_VerifyInit(CKM_ECDSA, RSA public key) returned CKR_OK and "
                "C_Verify ACCEPTED a signature -- usable wrong-key operation",
                flush=True,
            )
        else:
            print(
                "DEVIATION_XFAIL:C_VerifyInit(CKM_ECDSA, RSA public key) accepted "
                f"(CKR_OK) but C_Verify safely refused with {ckr_name(verify_rv)} -- "
                "lenient init, no usable operation (PKCS#11 5.2 prefers "
                "CKR_KEY_TYPE_INCONSISTENT at init)",
                flush=True,
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
            context=("C_SignInit(CKM_ECDSA, RSA private key) followed by C_Sign if accepted"),
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

        script = _preamble(p11_config) + dedent(_RSA_KEYPAIR_SETUP + _VERIFY_WITH_RSA_UNDER_ECDSA)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_ckr_subprocess_ok(
            rc,
            stdout,
            stderr,
            context=("C_VerifyInit(CKM_ECDSA, RSA public key) followed by C_Verify if accepted"),
        )

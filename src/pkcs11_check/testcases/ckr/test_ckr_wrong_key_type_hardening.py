"""Crash-safe wrong-key-type operation hardening.

These probes extend basic ``*Init`` CKR checks by continuing into the terminal
operation when a module incorrectly accepts a mismatched asymmetric key.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKA_VERIFY
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


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

        result = run_probe(
            "ckr_wrong_key_type_hardening",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
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

        result = run_probe(
            "ckr_wrong_key_type_hardening",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_ckr_subprocess_ok(
            rc,
            stdout,
            stderr,
            context=("C_VerifyInit(CKM_ECDSA, RSA public key) followed by C_Verify if accepted"),
        )

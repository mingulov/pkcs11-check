"""RSA PKCS#1 v1.5 and OAEP error path exercisers.

All tests run in a subprocess (the ``error_path_rsa`` probe) for crash safety.
Each test generates an RSA 2048-bit keypair, crafts a malformed ciphertext or
signature, and calls C_Decrypt / C_Verify.  The module must return an error code
cleanly -- never crash.

Covers:
- PKCS#1 v1.5: random bytes, truncated, extended, all-zeros, all-0xFF
- OAEP: random bytes, truncated
- Verify: corrupted (bit-flipped) signature
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


def _require_rsa_decrypt_setup(rs: Any) -> None:
    """Ensure the provider can create the setup key before spawning a crash probe."""
    pub = priv = 0
    try:
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


def _require_rsa_verify_setup(rs: Any) -> None:
    """Ensure the provider can create the setup key before spawning a crash probe."""
    pub = priv = 0
    try:
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


def _run_decrypt_probe(p11_config: Any, *, mech: str, variant: str, context: str) -> None:
    """Launch the error_path_rsa decrypt probe and assert it did not crash."""
    result = run_probe(
        "error_path_rsa",
        {
            "module_path": str(p11_config.module),
            "slot_id": p11_config.slot,
            "probe": "decrypt",
            "mech": mech,
            "variant": variant,
        },
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    rc, stdout, stderr = result.returncode, result.stdout, result.stderr
    assert_subprocess_no_crash(rc, stdout, stderr, context=context)


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 decrypt error paths
# ---------------------------------------------------------------------------


class TestRsaPkcsDecryptErrorPaths:
    """RSA PKCS#1 v1.5 decrypt with malformed ciphertext -- 5 corruption variants.

    Each test generates a fresh RSA 2048-bit keypair, crafts malformed input
    sized relative to the actual modulus, and calls C_DecryptInit + C_Decrypt.
    The module must return a CKR error, not crash.

    PKCS#11 v3.2: modules must validate ciphertext length and
    format before performing any decryption. Crashes are bugs.
    """

    def test_rsa_pkcs_decrypt_random_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Random bytes (no PKCS#1 v1.5 0x00 0x02 header) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="pkcs",
            variant="random",
            context="RSA_PKCS decrypt: random ciphertext",
        )

    def test_rsa_pkcs_decrypt_truncated(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Ciphertext shorter than modulus (half length) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="pkcs",
            variant="truncated",
            context="RSA_PKCS decrypt: truncated ciphertext (half modulus)",
        )

    def test_rsa_pkcs_decrypt_extended(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Ciphertext longer than modulus (modulus+16 bytes) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="pkcs",
            variant="extended",
            context="RSA_PKCS decrypt: extended ciphertext (modulus + 16)",
        )

    def test_rsa_pkcs_decrypt_all_zeros(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Modulus-length all-zero ciphertext (no 0x00 0x02 header) -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="pkcs",
            variant="all_zeros",
            context="RSA_PKCS decrypt: all-zero ciphertext",
        )

    def test_rsa_pkcs_decrypt_all_ff(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Modulus-length 0xFF ciphertext -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="pkcs",
            variant="all_ff",
            context="RSA_PKCS decrypt: all-0xFF ciphertext",
        )


# ---------------------------------------------------------------------------
# RSA OAEP decrypt error paths
# ---------------------------------------------------------------------------


class TestRsaOaepDecryptErrorPaths:
    """RSA OAEP decrypt with malformed ciphertext -- 2 corruption variants.

    Each test generates a fresh RSA 2048-bit keypair and crafts malformed
    OAEP input. The module must return a CKR error, not crash.

    PKCS#11 v3.2: OAEP ciphertext validation must not cause
    heap overflow or undefined behaviour on invalid input.
    """

    def test_rsa_oaep_decrypt_random_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Random bytes -> OAEP C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="oaep",
            variant="random",
            context="RSA_PKCS_OAEP decrypt: random ciphertext",
        )

    def test_rsa_oaep_decrypt_truncated(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Truncated OAEP ciphertext (half modulus length) -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        _require_rsa_decrypt_setup(rs)

        _run_decrypt_probe(
            p11_config,
            mech="oaep",
            variant="truncated",
            context="RSA_PKCS_OAEP decrypt: truncated ciphertext (half modulus)",
        )


# ---------------------------------------------------------------------------
# RSA signature verify with corrupted signature
# ---------------------------------------------------------------------------


class TestRsaVerifyCorruptedSignature:
    """RSA verify with a bit-flipped signature -- must return verification failure, not crash.

    Signs valid data, flips the first bit of the signature, then calls
    C_VerifyInit + C_Verify. The module must return CKR_SIGNATURE_INVALID
    or CKR_SIGNATURE_LEN_RANGE cleanly.

    PKCS#11 v3.2: C_Verify must validate the signature and return
    CKR_SIGNATURE_INVALID for a non-matching signature -- never crash.
    """

    def test_rsa_verify_corrupted_signature(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Sign valid data, flip a bit in signature, verify -> must return error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_rsa_verify_setup(rs)

        result = run_probe(
            "error_path_rsa",
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
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="RSA SHA256_RSA_PKCS verify: corrupted (bit-flipped) signature",
        )

"""Mechanism-driven sign-recover / verify-recover tests.

Tests the C_SignRecoverInit / C_SignRecover / C_VerifyRecoverInit / C_VerifyRecover
API path using high-level recipes.  Low-level raw-ctypes and CKR error-path tests
live in test_sign_recover.py and testcases/ckr/.
"""
from __future__ import annotations

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_recover_single,
    verify_recover_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_VERIFY_RECOVER,
    CKM_RSA_X_509,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign_recover]


def _rsa_x509_keypair(rs: RawSession) -> tuple[int, int]:
    """Generate a 2048-bit RSA keypair with sign-recover/verify-recover attributes."""
    return gen_rsa_keypair(
        rs.raw,
        rs.sh,
        2048,
        public_attrs={CKA_TOKEN: False, CKA_VERIFY_RECOVER: True},
        private_attrs={CKA_TOKEN: False, CKA_SIGN_RECOVER: True},
    )


class TestSignRecover:
    """Sign-recover and verify-recover for CKM_RSA_X_509."""

    def test_rsa_x509_sign_recover_roundtrip(self, p11_raw_session: RawSession) -> None:
        """RSA X.509 sign-recover -> verify-recover roundtrip recovers original data.

        C_SignRecover (PKCS#11 Sec.5.10.6): embeds the data directly in the RSA
        block so it can be extracted by C_VerifyRecover without the caller holding
        a separate copy.  CKM_RSA_X_509 (raw RSA) is the standard mechanism for
        this operation.

        Data must be PKCS#1 raw-RSA padded to the modulus length (256 bytes for
        2048-bit key).  The sign-recover_single recipe handles the padding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        pub, priv = _rsa_x509_keypair(rs)
        try:
            # Pad data to 256 bytes for raw RSA (modulus size for 2048-bit key)
            data = b"\x00\x01" + b"\xff" * 218 + b"\x00" + b"SignRecover data"
            assert len(data) == 256
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            assert len(sig) == 256, f"Unexpected signature length: {len(sig)}"

            ok, recovered = verify_recover_single(
                rs.raw, rs.sh, pub, CKM_RSA_X_509, sig
            )
            assert ok, "verify_recover_single reported invalid signature"
            assert recovered == data, (
                f"Recovered data mismatch: {recovered!r} != {data!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_x509_verify_recover_invalid_sig(self, p11_raw_session: RawSession) -> None:
        """C_VerifyRecover rejects an all-zero signature as invalid."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        pub, priv = _rsa_x509_keypair(rs)
        try:
            bad_sig = b"\x00" * 256
            ok, recovered = verify_recover_single(
                rs.raw, rs.sh, pub, CKM_RSA_X_509, bad_sig
            )
            assert not ok, (
                f"Module accepted all-zero signature as valid; recovered={recovered!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

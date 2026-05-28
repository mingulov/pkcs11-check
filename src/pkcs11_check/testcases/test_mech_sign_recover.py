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
from pkcs11_check.testcases.conftest import CIPHER_OP_RUNTIME_REJECT_RVS, xfail_if_known_ckr

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.sign_recover]

# Phase 5 P1b: produce-leg (sign-recover) reject set. A clean "advertised but
# not operational" reject -> xfail; C_SignRecover genuinely absent -> skip
# (NotImplementedError, handled separately). The dependent verify-recover leg
# stays a hard failure (self-contradiction).
_SIGN_RECOVER_REJECT_RVS = CIPHER_OP_RUNTIME_REJECT_RVS


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
            # Pad data to 256 bytes for raw RSA (modulus size for 2048-bit key).
            # Layout: 0x00 0x01 || PS (0xff bytes) || 0x00 || M
            # PS length = 256 - 2 - 1 - len(M) = 256 - 2 - 1 - 16 = 237
            data = b"\x00\x01" + b"\xff" * 237 + b"\x00" + b"SignRecover data"
            assert len(data) == 256
            try:
                sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            except NotImplementedError:
                pytest.skip("C_SignRecover not supported by this module")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _SIGN_RECOVER_REJECT_RVS, "CKM_RSA_X_509 sign-recover not operational"
                )
                raise
            assert len(sig) == 256, f"Unexpected signature length: {len(sig)}"

            try:
                ok, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, sig)
            except NotImplementedError:
                pytest.skip("C_VerifyRecover not supported by this module")
            assert ok, "verify_recover_single reported invalid signature"
            assert recovered == data, f"Recovered data mismatch: {recovered!r} != {data!r}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_x509_verify_recover_invalid_sig(self, p11_raw_session: RawSession) -> None:
        """C_VerifyRecover on tampered data does not recover the original message.

        CKM_RSA_X_509 is raw RSA: C_VerifyRecover computes sig^e mod n and returns
        whatever bytes result.  There is no padding validation, so a tampered
        signature rarely returns CKR_SIGNATURE_INVALID.  Instead, the recovered
        bytes will differ from the original data -- that is the observable test.

        Modules that do not implement C_VerifyRecover at all return
        CKR_FUNCTION_NOT_SUPPORTED; those are skipped.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        pub, priv = _rsa_x509_keypair(rs)
        try:
            # Build a valid PKCS#1 raw-RSA padded block (same layout as roundtrip test)
            data = b"\x00\x01" + b"\xff" * 237 + b"\x00" + b"SignRecover data"
            assert len(data) == 256
            try:
                sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            except NotImplementedError:
                pytest.skip("C_SignRecover not supported by this module")

            # Tamper: flip the last byte of the signature
            tampered = sig[:-1] + bytes([sig[-1] ^ 0xFF])

            try:
                ok, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, tampered)
            except NotImplementedError:
                pytest.skip("C_VerifyRecover not supported by this module")

            # For raw RSA the operation may or may not return CKR_SIGNATURE_INVALID.
            # What must hold: if it claims ok, the recovered bytes are not the
            # original data (because the tampered sig decrypts to something else).
            if ok:
                assert recovered != data, (
                    f"Tampered signature recovered original data -- "
                    f"module accepted forged signature as valid: recovered={recovered!r}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

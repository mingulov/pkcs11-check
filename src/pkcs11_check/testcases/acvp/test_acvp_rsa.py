"""NIST ACVP RSA signature test vectors (FIPS 186-4/5).

Tests RSA signature generation and verification using official NIST ACVP vectors:
- RSA-SigGen-FIPS186-4/5: Signature generation (legacy and current)
- RSA-SigVer-FIPS186-2/4/5: Signature verification (legacy and current)

Mechanisms tested:
- CKM_SHA*_RSA_PKCS (PKCS#1 v1.5 with hash)
- CKM_SHA*_RSA_PKCS_PSS (RSA-PSS with hash)

SoftHSM2 Known Issues:
- RSA-PSS: Only supports hashAlg == mgf (no distinct hashes)

Requires: scripts/fetch-optional-data.sh acvp
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack_mechanisms import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    import_rsa_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_VERIFY
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.acvp.rsa.base_loader import (
    load_siggen_pkcs15_vectors,
    load_siggen_pss_vectors,
    load_sigver_pkcs15_vectors,
    load_sigver_pss_vectors,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_PKCS15_SIGN = load_siggen_pkcs15_vectors()
_PSS_SIGN = load_siggen_pss_vectors()
_PKCS15_VER = load_sigver_pkcs15_vectors()
_PSS_VER = load_sigver_pss_vectors()


class TestRsaPkcs15:
    """RSA-PKCS#1 v1.5 signature tests."""

    @pytest.mark.parametrize("vec_id,vec", _PKCS15_SIGN, ids=[v[0] for v in _PKCS15_SIGN])
    def test_rsa_pkcs15_sign_verify(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA PKCS#1 v1.5 sign and verify with ACVP vectors."""
        rs = p11_raw_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        key_bits = vec["modulo"] if vec["modulo"] else 2048

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = priv_key = 0
        try:
            pub_key, priv_key = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=key_bits,
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
            )
            sig = sign_single(rs.raw, rs.sh, priv_key, mech_int, vec["message"])
            assert verify_single(rs.raw, rs.sh, pub_key, mech_int, vec["message"], sig)
        except AssertionError as exc:
            if "CKR_KEY_SIZE_RANGE" in str(exc) or "CKR_MECHANISM_INVALID" in str(exc):
                pytest.skip(f"RSA {key_bits}-bit not supported")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestRsaPss:
    """RSA-PSS signature tests."""

    @pytest.mark.parametrize("vec_id,vec", _PSS_SIGN, ids=[v[0] for v in _PSS_SIGN])
    def test_rsa_pss_sign_verify(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA-PSS sign and verify with ACVP vectors."""
        rs = p11_raw_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        hash_mech = vec["hash_mech"]
        mgf: int = vec["mgf"]
        salt_len: int = vec["salt_len"]
        key_bits = vec["modulo"] if vec["modulo"] else 2048

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = priv_key = 0
        try:
            pub_key, priv_key = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=key_bits,
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
            )
            mech_param = mech_pss(mech_int, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            sig = sign_single(
                rs.raw, rs.sh, priv_key, mech_int, vec["message"], mech_param=mech_param
            )
            assert verify_single(
                rs.raw, rs.sh, pub_key, mech_int, vec["message"], sig, mech_param=mech_param
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR_KEY_SIZE_RANGE" in exc_msg or "CKR_MECHANISM_INVALID" in exc_msg:
                pytest.skip(f"RSA {key_bits}-bit not supported")
            if "CKR_MECHANISM_PARAM_INVALID" in exc_msg:
                pytest.skip("PSS params not supported (hashAlg != mgf)")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestRsaSigVer:
    """RSA signature verification tests with valid/invalid vectors."""

    @pytest.mark.parametrize("vec_id,vec", _PKCS15_VER, ids=[v[0] for v in _PKCS15_VER])
    def test_rsa_pkcs15_verify(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA PKCS#1 v1.5 signature verification."""
        rs = p11_raw_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        expected_pass: bool = vec["expected_pass"]

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = 0
        try:
            pub_key = import_rsa_public_key(
                rs.raw, rs.sh, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
            )
            verified = verify_single(
                rs.raw, rs.sh, pub_key, mech_int, vec["message"], vec["signature"]
            )

            if not expected_pass and verified:
                pytest.fail(f"{vec_id}: ACCEPTED INVALID signature - security concern")
            if expected_pass and not verified:
                pytest.xfail(f"{vec_id}: rejected VALID signature - module issue")
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_KEY_SIZE_RANGE", "CKR_TEMPLATE_INCONSISTENT")):
                pytest.skip("RSA key import failed")
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
            else:
                raise  # Unexpected error for invalid-sig vector
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

    @pytest.mark.parametrize("vec_id,vec", _PSS_VER, ids=[v[0] for v in _PSS_VER])
    def test_rsa_pss_verify(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test RSA-PSS signature verification."""
        rs = p11_raw_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        hash_mech = vec["hash_mech"]
        mgf: int = vec["mgf"]
        salt_len: int = vec["salt_len"]
        expected_pass: bool = vec["expected_pass"]

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = 0
        try:
            pub_key = import_rsa_public_key(
                rs.raw, rs.sh, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
            )
            mech_param = mech_pss(mech_int, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            verified = verify_single(
                rs.raw,
                rs.sh,
                pub_key,
                mech_int,
                vec["message"],
                vec["signature"],
                mech_param=mech_param,
            )

            if not expected_pass and verified:
                pytest.fail(f"{vec_id}: ACCEPTED INVALID PSS signature - security concern")
            if expected_pass and not verified:
                pytest.xfail(f"{vec_id}: rejected VALID PSS signature - module issue")
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_KEY_SIZE_RANGE", "CKR_TEMPLATE_INCONSISTENT")):
                pytest.skip("RSA key import failed")
            if "CKR_MECHANISM_PARAM_INVALID" in exc_msg:
                pytest.skip("PSS params not supported")
            if not expected_pass and any(
                c in exc_msg for c in ("CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE")
            ):
                pass  # Expected
            elif expected_pass:
                raise
            else:
                raise  # Unexpected error for invalid-sig vector
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

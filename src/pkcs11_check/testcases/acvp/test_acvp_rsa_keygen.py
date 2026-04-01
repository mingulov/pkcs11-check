"""NIST ACVP RSA key generation test vectors (FIPS 186-4/5).

Tests RSA key pair generation using official NIST ACVP vectors:
- RSA-KeyGen-FIPS186-4: Key generation per FIPS 186-4
- RSA-KeyGen-FIPS186-5: Key generation per FIPS 186-5

Mechanism tested:
- CKM_RSA_PKCS_KEY_PAIR_GEN: RSA key pair generation

Test approach:
ACVP internalProjection.json contains deterministic key generation vectors
with seeds and expected key values. Since PKCS#11 does not support
deterministic key generation from external seeds, we:
1. Generate RSA key pairs with specified modulus lengths (2048, 3072, 4096)
2. Verify generated keys are valid (can sign/verify)
3. Check key attributes match expected specifications

Note: FIPS 186-4/5 require specific prime generation methods (B.3.2, B.3.4,
provable primes, probable primes). PKCS#11 implementations may vary in
compliance with these specific methods.

Requires: scripts/fetch-optional-data.sh acvp
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    get_mechanism_info,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN,
    CKA_VERIFY,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.acvp.rsa.base_loader import load_keygen_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_RSA_KEYGEN_VECTORS = load_keygen_vectors()


class TestRsaKeyGen:
    """RSA key generation tests using ACVP vectors."""

    @pytest.mark.parametrize(
        "vec_id,vec", _RSA_KEYGEN_VECTORS, ids=[v[0] for v in _RSA_KEYGEN_VECTORS]
    )
    def test_rsa_keygen_basic(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test RSA keypair generation with basic sign/verify roundtrip."""
        rs = p11_raw_session
        modulo = vec["modulo"]

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")

        pub_key = priv_key = 0
        try:
            # Generate RSA key pair with specified modulus size
            pub_key, priv_key = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=modulo,
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
            )

            assert pub_key != 0, f"{vec_id}: Public key handle is zero"
            assert priv_key != 0, f"{vec_id}: Private key handle is zero"

            # Verify key works with a basic sign/verify operation
            test_msg = b"RSA KeyGen ACVP test vector"
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SHA256_RSA_PKCS, test_msg)
            assert verify_single(rs.raw, rs.sh, pub_key, CKM_SHA256_RSA_PKCS, test_msg, sig), (
                f"{vec_id}: Sign/verify roundtrip failed"
            )

        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_TEMPLATE_INCOMPLETE",
                    "CKR_KEY_SIZE_RANGE",
                )
            ):
                pytest.skip(f"RSA {modulo}-bit key generation not supported: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

    @pytest.mark.parametrize(
        "vec_id,vec", _RSA_KEYGEN_VECTORS, ids=[v[0] for v in _RSA_KEYGEN_VECTORS]
    )
    def test_rsa_keygen_attributes(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA keypair attributes match expected specifications."""
        rs = p11_raw_session
        modulo = vec["modulo"]

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")

        pub_key = priv_key = 0
        try:
            pub_key, priv_key = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=modulo,
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
            )

            # Read key attributes
            attrs = read_attributes(
                rs.raw, rs.sh, pub_key, [CKA_MODULUS_BITS, CKA_MODULUS, CKA_PUBLIC_EXPONENT]
            )

            # Verify modulus bits
            actual_bits = attrs.get(CKA_MODULUS_BITS)
            if isinstance(actual_bits, int):
                assert actual_bits == modulo, (
                    f"{vec_id}: Modulus size mismatch: expected {modulo}, got {actual_bits}"
                )

            # Verify public exponent
            exp_val = attrs.get(CKA_PUBLIC_EXPONENT)
            if isinstance(exp_val, bytes):
                actual_exp = int.from_bytes(exp_val, "big")
            elif isinstance(exp_val, int):
                actual_exp = exp_val
            else:
                actual_exp = None

            if actual_exp is not None:
                # Public exponent should be odd and > 2 (FIPS 186-4/5 requirement)
                assert actual_exp % 2 == 1, f"{vec_id}: Public exponent must be odd"
                assert actual_exp > 2, f"{vec_id}: Public exponent must be > 2"
                # Common values: 3, 65537 (F4), or other reasonable values
                assert actual_exp < (1 << 256), f"{vec_id}: Public exponent unreasonably large"

        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_TEMPLATE_INCOMPLETE",
                    "CKR_KEY_SIZE_RANGE",
                )
            ):
                pytest.skip(f"RSA {modulo}-bit key attribute query failed: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestRsaKeyGenBySize:
    """RSA key generation tests organized by modulus size."""

    @pytest.mark.parametrize("bits", [2048, 3072, 4096], ids=["2048", "3072", "4096"])
    def test_rsa_keygen_by_size(self, p11_raw_session: Any, bits: int) -> None:
        """Test RSA key generation for specific modulus sizes."""
        rs = p11_raw_session

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")

        # Check if mechanism supports this key size
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
            min_key_size = info.get("min_key_size", 0)
            max_key_size = info.get("max_key_size", 0)
            if bits < min_key_size or bits > max_key_size:
                pytest.skip(
                    f"RSA {bits}-bit not supported (mechanism limits: "
                    f"{min_key_size}-{max_key_size})"
                )
        except Exception:
            pass  # Continue anyway, will fail in generation if truly unsupported

        pub_key = priv_key = 0
        try:
            pub_key, priv_key = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=bits,
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
            )

            # Verify key works
            test_msg = f"RSA {bits}-bit test".encode()
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SHA256_RSA_PKCS, test_msg)
            assert verify_single(rs.raw, rs.sh, pub_key, CKM_SHA256_RSA_PKCS, test_msg, sig), (
                f"RSA {bits}-bit sign/verify failed"
            )

        except AssertionError as exc:
            if any(
                name in str(exc)
                for name in (
                    "CKR_MECHANISM_INVALID",
                    "CKR_KEY_SIZE_RANGE",
                )
            ):
                pytest.skip(f"RSA {bits}-bit not supported by this module")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

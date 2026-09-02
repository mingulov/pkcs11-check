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

The ACVP internal-projection seed and expected-key values are retained in the
loaded vectors, but current PKCS#11 key generation APIs cannot consume those
seeds. Repeated vectors with the same provider-visible modulus are therefore
collected and reported as skipped duplicates after the first representative.
Future PKCS#11 revisions could make these exact ACVP KeyGen checks possible by
standardizing deterministic validation inputs, but there is no portable API for
that today.

Note: FIPS 186-4/5 require specific prime generation methods (B.3.2, B.3.4,
provable primes, probable primes). PKCS#11 implementations may vary in
compliance with these specific methods.

Requires: scripts/fetch-optional-data.sh acvp
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
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
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases.acvp._duplicates import skip_duplicate_pkcs11_input
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.acvp.rsa.base_loader import load_keygen_vectors
from pkcs11_check.testcases.conftest import is_known_error, require_keygen_key_size

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_RSA_KEYGEN_VECTORS = load_keygen_vectors()

_RSA_KEYGEN_CAPABILITY_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
)


def _require_rsa_keygen_attribute(
    attrs: dict[int, Any], attr_id: int, vec_id: str, name: str
) -> Any:
    """Require a generated RSA public-key attribute instead of ignoring absence."""
    value = attrs.get(attr_id)
    if value is None:
        fail_as(
            "wrong_result",
            kind="metadata",
            label=f"{vec_id}:{name}",
            operation="C_GetAttributeValue",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            summary=f"{vec_id}: generated RSA public key omitted required {name}",
        )
    return value


class TestRsaKeyGen:
    """RSA key generation tests using ACVP vectors."""

    @pytest.mark.parametrize(
        "vec_id,vec", _RSA_KEYGEN_VECTORS, ids=[v[0] for v in _RSA_KEYGEN_VECTORS]
    )
    def test_rsa_keygen_basic(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA keypair generation with basic sign/verify roundtrip."""
        rs = p11_module_session
        modulo = vec["modulo"]

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported by module")
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", modulo, label=vec_id)
        skip_duplicate_pkcs11_input(vec, "RSA KeyGen")

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
            if is_known_error(exc, _RSA_KEYGEN_CAPABILITY_CKRS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:keygen",
                    summary=f"Advertised RSA {modulo}-bit keygen/sign flow rejected: {exc}",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED}):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:keygen",
                    summary=f"CKM_RSA_PKCS_KEY_PAIR_GEN advertised but keygen failed: {exc}",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

    @pytest.mark.parametrize(
        "vec_id,vec", _RSA_KEYGEN_VECTORS, ids=[v[0] for v in _RSA_KEYGEN_VECTORS]
    )
    def test_rsa_keygen_attributes(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA keypair attributes match expected specifications."""
        rs = p11_module_session
        modulo = vec["modulo"]

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", modulo, label=vec_id)
        skip_duplicate_pkcs11_input(vec, "RSA KeyGen")

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

            actual_bits = _require_rsa_keygen_attribute(
                attrs, CKA_MODULUS_BITS, vec_id, "CKA_MODULUS_BITS"
            )
            if isinstance(actual_bits, bool) or not isinstance(actual_bits, int):
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_MODULUS_BITS",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="int",
                    actual=type(actual_bits).__name__,
                    summary=f"{vec_id}: CKA_MODULUS_BITS has malformed readback",
                )
            if actual_bits != modulo:
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_MODULUS_BITS",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected=modulo,
                    actual=actual_bits,
                    summary=(
                        f"{vec_id}: Modulus size mismatch: expected {modulo}, got {actual_bits}"
                    ),
                )

            modulus = _require_rsa_keygen_attribute(attrs, CKA_MODULUS, vec_id, "CKA_MODULUS")
            if not isinstance(modulus, bytes) or not modulus:
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_MODULUS",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="non-empty bytes",
                    actual=type(modulus).__name__,
                    summary=f"{vec_id}: CKA_MODULUS has malformed readback",
                )

            exp_val = _require_rsa_keygen_attribute(
                attrs, CKA_PUBLIC_EXPONENT, vec_id, "CKA_PUBLIC_EXPONENT"
            )
            if isinstance(exp_val, bytes) and exp_val:
                actual_exp = int.from_bytes(exp_val, "big")
            elif isinstance(exp_val, int) and not isinstance(exp_val, bool):
                actual_exp = exp_val
            else:
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_PUBLIC_EXPONENT",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="non-empty bytes or int",
                    actual=type(exp_val).__name__,
                    summary=f"{vec_id}: CKA_PUBLIC_EXPONENT has malformed readback",
                )

            # Public exponent should be odd and > 2 (FIPS 186-4/5 requirement).
            if actual_exp % 2 != 1:
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_PUBLIC_EXPONENT",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="odd integer",
                    actual=actual_exp,
                    summary=f"{vec_id}: Public exponent must be odd",
                )
            if actual_exp <= 2:
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_PUBLIC_EXPONENT",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="> 2",
                    actual=actual_exp,
                    summary=f"{vec_id}: Public exponent must be > 2",
                )
            if actual_exp >= (1 << 256):
                fail_as(
                    "wrong_result",
                    kind="metadata",
                    label=f"{vec_id}:CKA_PUBLIC_EXPONENT",
                    operation="C_GetAttributeValue",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    expected="< 2**256",
                    actual=actual_exp,
                    summary=f"{vec_id}: Public exponent unreasonably large",
                )

        except AssertionError as exc:
            if is_known_error(exc, _RSA_KEYGEN_CAPABILITY_CKRS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:key-attributes",
                    summary=f"Advertised RSA {modulo}-bit keygen/attribute flow rejected: {exc}",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED}):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:keygen",
                    summary=f"CKM_RSA_PKCS_KEY_PAIR_GEN advertised but keygen failed: {exc}",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestRsaKeyGenBySize:
    """RSA key generation tests organized by modulus size."""

    @pytest.mark.parametrize("bits", [2048, 3072, 4096], ids=["2048", "3072", "4096"])
    def test_rsa_keygen_by_size(self, p11_module_session: Any, bits: int) -> None:
        """Test RSA key generation for specific modulus sizes."""
        rs = p11_module_session

        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported by module")

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        min_key_size = info.get("min_key_size", 0)
        max_key_size = info.get("max_key_size", 0)
        if bits < min_key_size or bits > max_key_size:
            pytest.skip(
                f"RSA {bits}-bit not supported (mechanism limits: {min_key_size}-{max_key_size})"
            )

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
            if is_known_error(exc, _RSA_KEYGEN_CAPABILITY_CKRS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:keygen",
                    summary=f"Advertised RSA {bits}-bit keygen/sign flow rejected: {exc}",
                )
            if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED}):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_KEY_PAIR_GEN:keygen",
                    summary=f"CKM_RSA_PKCS_KEY_PAIR_GEN advertised but keygen failed: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)

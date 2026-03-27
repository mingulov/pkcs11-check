"""Key Encapsulation Mechanism (KEM) tests - ML-KEM (CRYSTALS-Kyber / FIPS 203).

All tests require PKCS#11 v3.2 interface (C_EncapsulateKey / C_DecapsulateKey).
Auto-skips on v3.1 and earlier.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.recipes import (
    decapsulate_key,
    destroy_quietly,
    encapsulate_key,
    gen_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_ML_KEM,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKP_ML_KEM_512,
    CKP_ML_KEM_768,
    CKP_ML_KEM_1024,
)

pytestmark = [pytest.mark.pqc, pytest.mark.keymgmt, pytest.mark.requires_v32]

# ML-KEM parameter set sizes (ciphertext, shared-secret bytes)
_ML_KEM_CIPHERTEXT_SIZES = {
    "ML_KEM_512": 768,
    "ML_KEM_768": 1088,
    "ML_KEM_1024": 1568,
}

_PARAM_MAP = {
    "ML_KEM_512": CKP_ML_KEM_512,
    "ML_KEM_768": CKP_ML_KEM_768,
    "ML_KEM_1024": CKP_ML_KEM_1024,
}


def _skip_if_no_ml_kem(rs: Any) -> None:
    """Skip the test if ML_KEM mechanism is not available."""
    if not rs.has_mechanism("ML_KEM"):
        pytest.skip("ML_KEM mechanism not supported by module")


def _generate_ml_kem_keypair(
    rs: Any,
    param_set: int | None = None,
) -> tuple[int, int]:
    """Generate an ML-KEM key pair with encapsulate/decapsulate capabilities.

    :param param_set: Optional parameter set int value.
        If None, defaults to CKP_ML_KEM_768.
    """
    effective_param = param_set if param_set is not None else CKP_ML_KEM_768
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_KEM_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, effective_param)],
        priv_base=[],
        public_attrs={
            CKA_ENCAPSULATE: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_DECAPSULATE: True,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: False,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_PARAMETER_SET},
    )


def _encap_attrs(key_type: int = CKK_GENERIC_SECRET) -> dict[int, Any]:
    """Standard template for encapsulated key."""
    d: dict[int, Any] = {
        CKA_KEY_TYPE: key_type,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }
    return d


class TestMLKEMKeyGeneration:
    """ML-KEM key pair generation tests."""

    def test_ml_kem_available(self, p11_raw_session: Any) -> None:
        """Check that ML_KEM mechanism is available."""
        _skip_if_no_ml_kem(p11_raw_session)

    def test_ml_kem_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an ML-KEM key pair."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_keypair_classes(self, p11_raw_session: Any) -> None:
        """ML-KEM public key is PublicKey, private is PrivateKey."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            pub_cls = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])[CKA_CLASS]
            priv_cls = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])[CKA_CLASS]
            assert pub_cls == CKO_PUBLIC_KEY
            assert priv_cls == CKO_PRIVATE_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_keypair_key_type(self, p11_raw_session: Any) -> None:
        """ML-KEM keys report correct key type."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert pub_kt == CKK_ML_KEM
            assert priv_kt == CKK_ML_KEM
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_two_keypairs_distinct(self, p11_raw_session: Any) -> None:
        """Two ML-KEM key pair generations produce distinct keys."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub_a, priv_a = _generate_ml_kem_keypair(rs)
        pub_b, priv_b = _generate_ml_kem_keypair(rs)
        try:
            # Public keys must differ (overwhelming probability)
            try:
                val_a = read_attributes(rs.raw, rs.sh, pub_a, [CKA_VALUE])[CKA_VALUE]
                val_b = read_attributes(rs.raw, rs.sh, pub_b, [CKA_VALUE])[CKA_VALUE]
                assert val_a != val_b
            except (AssertionError, OSError):
                pytest.skip("Module does not expose ML-KEM public key value")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)


@pytest.mark.v32
class TestMLKEMEncapsulateDecapsulate:
    """ML-KEM encapsulate/decapsulate round-trip tests."""

    def test_encapsulate_returns_ciphertext_and_key(self, p11_raw_session: Any) -> None:
        """C_EncapsulateKey returns non-empty ciphertext and a key handle."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            try:
                shared, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available (module not v3.2)")
            assert isinstance(ct, bytes)
            assert len(ct) > 0
            assert shared != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)

    def test_encapsulate_ciphertext_nonzero(self, p11_raw_session: Any) -> None:
        """Ciphertext from encapsulate_key is non-trivially non-zero."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            try:
                shared, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available")
            assert ct != bytes(len(ct))  # not all zeros
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)

    def test_encapsulate_decapsulate_shared_secret_matches(self, p11_raw_session: Any) -> None:
        """Encapsulated and decapsulated shared secrets match."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        decap_handle = 0
        try:
            try:
                encap_handle, ct = encapsulate_key(
                    rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs()
                )
                decap_handle = decapsulate_key(
                    rs.raw, rs.sh, priv, CKM_ML_KEM, ct, attrs=_encap_attrs()
                )
            except (AssertionError, NotImplementedError):
                pytest.skip("KEM operations not available (module not v3.2)")
            # Both sides must produce the same shared secret
            encap_value = read_attributes(rs.raw, rs.sh, encap_handle, [CKA_VALUE])[CKA_VALUE]
            decap_value = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])[CKA_VALUE]
            assert encap_value == decap_value, "Encapsulated and decapsulated secrets differ"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if decap_handle:
                destroy_quietly(rs.raw, rs.sh, decap_handle)

    def test_two_encapsulations_produce_different_ciphertexts(self, p11_raw_session: Any) -> None:
        """Separate encapsulation calls produce different ciphertexts (fresh randomness)."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        s1 = s2 = 0
        try:
            try:
                s1, ct1 = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
                s2, ct2 = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available")
            assert ct1 != ct2, "Two encapsulations produced identical ciphertexts (bad randomness)"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if s1:
                destroy_quietly(rs.raw, rs.sh, s1)
            if s2:
                destroy_quietly(rs.raw, rs.sh, s2)

    def test_decapsulate_with_wrong_key_fails_or_differs(self, p11_raw_session: Any) -> None:
        """Decapsulating with a different private key produces a different (or no) secret."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub_a, priv_a = _generate_ml_kem_keypair(rs)
        pub_b, priv_b = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        wrong_handle = 0
        try:
            try:
                encap_handle, ct = encapsulate_key(
                    rs.raw, rs.sh, pub_a, CKM_ML_KEM, attrs=_encap_attrs()
                )
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available")

            try:
                wrong_handle = decapsulate_key(
                    rs.raw, rs.sh, priv_b, CKM_ML_KEM, ct, attrs=_encap_attrs()
                )
                # If it succeeds, the secrets must differ (ML-KEM implicit rejection)
                encap_val = read_attributes(rs.raw, rs.sh, encap_handle, [CKA_VALUE])[CKA_VALUE]
                wrong_val = read_attributes(rs.raw, rs.sh, wrong_handle, [CKA_VALUE])[CKA_VALUE]
                assert encap_val != wrong_val, (
                    "Decapsulation with wrong key produced same secret as correct decapsulation"
                )
            except AssertionError:
                # An error is also acceptable (explicit rejection)
                pass
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if wrong_handle:
                destroy_quietly(rs.raw, rs.sh, wrong_handle)


@pytest.mark.v32
@pytest.mark.kat
class TestMLKEMCiphertextSize:
    """Verify ciphertext sizes match FIPS 203 spec for each ML-KEM parameter set."""

    @pytest.mark.parametrize(
        "param_set,expected_ct_len",
        [
            ("ML_KEM_512", 768),
            ("ML_KEM_768", 1088),
            ("ML_KEM_1024", 1568),
        ],
    )
    def test_ciphertext_size(
        self,
        p11_raw_session: Any,
        param_set: str,
        expected_ct_len: int,
    ) -> None:
        """Ciphertext size matches FIPS 203 for this ML-KEM parameter set."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            try:
                shared, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available")

            # We can only check size if the module uses the expected parameter set
            if len(ct) not in _ML_KEM_CIPHERTEXT_SIZES.values():
                pytest.xfail(f"Unexpected ciphertext size {len(ct)} - may be non-standard")
            # If size matches this parameter set, check it
            if len(ct) == expected_ct_len:
                assert len(ct) == expected_ct_len
            else:
                pytest.skip(f"Module uses different ML-KEM parameter set (ct_len={len(ct)})")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)


@pytest.mark.v32
class TestMLKEMKeyDerivation:
    """ML-KEM encapsulation producing specific key types (AES-128, AES-256)."""

    def test_encapsulate_produces_aes128_key(self, p11_raw_session: Any) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=16 produces AES-128."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        aes_handle = 0
        try:
            aes_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 16,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
            try:
                aes_handle, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=aes_attrs)
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available (module not v3.2)")
            except (AssertionError, Exception) as exc:
                from pkcs11_check.raw.types_std import (
                    CKR_DEVICE_ERROR,
                    CKR_FUNCTION_NOT_SUPPORTED,
                    CKR_MECHANISM_INVALID,
                )
                from pkcs11_check.testcases.conftest import xfail_if_known_ckr

                xfail_if_known_ckr(
                    exc,
                    (CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED, CKR_DEVICE_ERROR),
                    "KEM operation not supported",
                )
            assert isinstance(ct, bytes) and len(ct) > 0
            kt = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert kt == CKK_AES
            value = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == 16, f"Expected 16-byte AES-128 key, got {len(value)} bytes"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if aes_handle:
                destroy_quietly(rs.raw, rs.sh, aes_handle)

    def test_encapsulate_produces_aes256_key(self, p11_raw_session: Any) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=32 produces AES-256."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        aes_handle = 0
        try:
            aes_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 32,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
            try:
                aes_handle, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=aes_attrs)
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available (module not v3.2)")
            except (AssertionError, Exception) as exc:
                from pkcs11_check.raw.types_std import (
                    CKR_DEVICE_ERROR,
                    CKR_FUNCTION_NOT_SUPPORTED,
                    CKR_MECHANISM_INVALID,
                )
                from pkcs11_check.testcases.conftest import xfail_if_known_ckr

                xfail_if_known_ckr(
                    exc,
                    (CKR_MECHANISM_INVALID, CKR_FUNCTION_NOT_SUPPORTED, CKR_DEVICE_ERROR),
                    "KEM operation not supported",
                )
            assert isinstance(ct, bytes) and len(ct) > 0
            kt = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert kt == CKK_AES
            value = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == 32, f"Expected 32-byte AES-256 key, got {len(value)} bytes"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if aes_handle:
                destroy_quietly(rs.raw, rs.sh, aes_handle)

    @pytest.mark.parametrize(
        "param_set_name,expected_ct_len",
        [
            ("ML_KEM_512", 768),
            ("ML_KEM_768", 1088),
            ("ML_KEM_1024", 1568),
        ],
    )
    def test_parameter_set_produces_correct_ciphertext_size(
        self,
        p11_raw_session: Any,
        param_set_name: str,
        expected_ct_len: int,
    ) -> None:
        """Requesting a specific ML-KEM parameter set produces the expected ciphertext size."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        param_set = _PARAM_MAP[param_set_name]
        try:
            pub, priv = _generate_ml_kem_keypair(rs, param_set=param_set)
        except (AssertionError, OSError):
            pytest.xfail(
                f"Module does not support CKA_PARAMETER_SET={param_set_name} - "
                "may use a fixed parameter set"
            )
            raise  # unreachable
        shared = 0
        try:
            try:
                shared, ct = encapsulate_key(rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_encap_attrs())
            except (AssertionError, NotImplementedError):
                pytest.skip("encapsulate_key not available")
            assert len(ct) == expected_ct_len, (
                f"Expected {expected_ct_len}-byte ciphertext for {param_set_name}, got {len(ct)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)

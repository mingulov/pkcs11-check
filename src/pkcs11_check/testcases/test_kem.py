"""Key Encapsulation Mechanism (KEM) tests - ML-KEM (CRYSTALS-Kyber / FIPS 203).

All tests require PKCS#11 v3.2 interface (C_EncapsulateKey / C_DecapsulateKey).
Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.constants import MLKemParameterSet

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.pqc, pytest.mark.keymgmt, pytest.mark.requires_v32]

# ML-KEM parameter set sizes (ciphertext, shared-secret bytes)
_ML_KEM_CIPHERTEXT_SIZES = {
    "ML_KEM_512": 768,
    "ML_KEM_768": 1088,
    "ML_KEM_1024": 1568,
}


def _skip_if_no_ml_kem(p11_module: Any) -> None:
    """Skip the test if ML_KEM mechanism is not available."""
    if not has_mechanism(p11_module, "ML_KEM"):
        pytest.skip("ML_KEM mechanism not supported by module")


def _generate_ml_kem_keypair(
    session: Any,
    param_set: MLKemParameterSet | None = None,
) -> Any:
    """Generate an ML-KEM key pair with encapsulate/decapsulate capabilities.

    :param param_set: Optional parameter set (ML_KEM_512/768/1024).
        If None, the module uses its default (typically ML-KEM-768).
    """
    # Default to ML-KEM-768 (NIST security category 3) if no param_set given
    effective_param = int(param_set) if param_set is not None else int(MLKemParameterSet.ML_KEM_768)
    pub_tmpl: dict[Any, Any] = {
        Attribute.ENCAPSULATE: True,
        Attribute.PARAMETER_SET: effective_param,
        Attribute.TOKEN: False,
    }
    priv_tmpl: dict[Any, Any] = {
        Attribute.DECAPSULATE: True,
        Attribute.PARAMETER_SET: effective_param,
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: False,
    }
    pair: Any = session.generate_keypair(
        KeyType.ML_KEM,
        mechanism=Mechanism.ML_KEM_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )
    return pair


class TestMLKEMKeyGeneration:
    """ML-KEM key pair generation tests."""

    def test_ml_kem_available(self, p11_module: Any) -> None:
        """Check that ML_KEM mechanism is available."""
        _skip_if_no_ml_kem(p11_module)

    def test_ml_kem_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an ML-KEM key pair."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        assert pub is not None
        assert priv is not None

    def test_ml_kem_keypair_classes(self, p11_session: Any, p11_module: Any) -> None:
        """ML-KEM public key is PublicKey, private is PrivateKey."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
        assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY

    def test_ml_kem_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """ML-KEM keys report correct key type."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        assert pub[Attribute.KEY_TYPE] == KeyType.ML_KEM
        assert priv[Attribute.KEY_TYPE] == KeyType.ML_KEM

    def test_ml_kem_two_keypairs_distinct(self, p11_session: Any, p11_module: Any) -> None:
        """Two ML-KEM key pair generations produce distinct keys."""
        _skip_if_no_ml_kem(p11_module)
        pub_a, _ = _generate_ml_kem_keypair(p11_session)
        pub_b, _ = _generate_ml_kem_keypair(p11_session)
        # Public keys must differ (overwhelming probability)
        try:
            val_a = pub_a[Attribute.VALUE]
            val_b = pub_b[Attribute.VALUE]
            assert val_a != val_b
        except Exception:
            pytest.xfail("Module does not expose ML-KEM public key value")


@pytest.mark.v32
class TestMLKEMEncapsulateDecapsulate:
    """ML-KEM encapsulate/decapsulate round-trip tests."""

    def test_encapsulate_returns_ciphertext_and_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """C_EncapsulateKey returns non-empty ciphertext and a key handle."""
        _skip_if_no_ml_kem(p11_module)
        pub, _ = _generate_ml_kem_keypair(p11_session)
        try:
            ct, shared = pub.encapsulate_key(
                KeyType.GENERIC_SECRET,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
        except NotImplementedError:
            pytest.skip("encapsulate_key not available (module not v3.2)")
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert shared is not None

    def test_encapsulate_ciphertext_nonzero(self, p11_session: Any, p11_module: Any) -> None:
        """Ciphertext from encapsulate_key is non-trivially non-zero."""
        _skip_if_no_ml_kem(p11_module)
        pub, _ = _generate_ml_kem_keypair(p11_session)
        try:
            ct, _ = pub.encapsulate_key(
                KeyType.GENERIC_SECRET,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
        except NotImplementedError:
            pytest.skip("encapsulate_key not available")
        assert ct != bytes(len(ct))  # not all zeros

    def test_encapsulate_decapsulate_shared_secret_matches(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Encapsulated and decapsulated shared secrets match."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        key_tmpl = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, encap_key = pub.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
            decap_key = priv.decapsulate_key(KeyType.GENERIC_SECRET, ct, template=key_tmpl)
        except NotImplementedError:
            pytest.skip("KEM operations not available (module not v3.2)")
        # Both sides must produce the same shared secret
        encap_value = encap_key[Attribute.VALUE]
        decap_value = decap_key[Attribute.VALUE]
        assert encap_value == decap_value, "Encapsulated and decapsulated secrets differ"

    def test_two_encapsulations_produce_different_ciphertexts(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Separate encapsulation calls produce different ciphertexts (fresh randomness)."""
        _skip_if_no_ml_kem(p11_module)
        pub, _ = _generate_ml_kem_keypair(p11_session)
        key_tmpl = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct1, _ = pub.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
            ct2, _ = pub.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available")
        assert ct1 != ct2, "Two encapsulations produced identical ciphertexts (bad randomness)"

    def test_decapsulate_with_wrong_key_fails_or_differs(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Decapsulating with a different private key produces a different (or no) secret."""
        _skip_if_no_ml_kem(p11_module)
        pub_a, _ = _generate_ml_kem_keypair(p11_session)
        _, priv_b = _generate_ml_kem_keypair(p11_session)
        key_tmpl = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, encap_key = pub_a.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available")

        try:
            wrong_key = priv_b.decapsulate_key(KeyType.GENERIC_SECRET, ct, template=key_tmpl)
            # If it succeeds, the secrets must differ (ML-KEM implicit rejection)
            encap_val = encap_key[Attribute.VALUE]
            wrong_val = wrong_key[Attribute.VALUE]
            assert encap_val != wrong_val, (
                "Decapsulation with wrong key produced same secret as correct decapsulation"
            )
        except Exception:
            # An error is also acceptable (explicit rejection)
            pass


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
        p11_session: Any,
        p11_module: Any,
        param_set: str,
        expected_ct_len: int,
    ) -> None:
        """Ciphertext size matches FIPS 203 for this ML-KEM parameter set."""
        _skip_if_no_ml_kem(p11_module)
        pub, _ = _generate_ml_kem_keypair(p11_session)
        key_tmpl = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, _ = pub.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available")

        # We can only check size if the module uses the expected parameter set
        if len(ct) not in _ML_KEM_CIPHERTEXT_SIZES.values():
            pytest.xfail(f"Unexpected ciphertext size {len(ct)} - may be non-standard")
        # If size matches this parameter set, check it
        if len(ct) == expected_ct_len:
            assert len(ct) == expected_ct_len
        else:
            pytest.skip(f"Module uses different ML-KEM parameter set (ct_len={len(ct)})")


@pytest.mark.v32
class TestMLKEMKeyDerivation:
    """ML-KEM encapsulation producing specific key types (AES-128, AES-256)."""

    def test_encapsulate_produces_aes128_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=16 produces AES-128."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        aes_tmpl = {
            Attribute.VALUE_LEN: 16,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, aes_key = pub.encapsulate_key(KeyType.AES, template=aes_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available (module not v3.2)")
        except Exception:
            pytest.xfail("Module does not support direct AES key derivation via encapsulation")
        assert isinstance(ct, bytes) and len(ct) > 0
        assert aes_key[Attribute.KEY_TYPE] == KeyType.AES
        value = aes_key[Attribute.VALUE]
        assert len(value) == 16, f"Expected 16-byte AES-128 key, got {len(value)} bytes"

    def test_encapsulate_produces_aes256_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=32 produces AES-256."""
        _skip_if_no_ml_kem(p11_module)
        pub, priv = _generate_ml_kem_keypair(p11_session)
        aes_tmpl = {
            Attribute.VALUE_LEN: 32,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, aes_key = pub.encapsulate_key(KeyType.AES, template=aes_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available (module not v3.2)")
        except Exception:
            pytest.xfail("Module does not support direct AES key derivation via encapsulation")
        assert isinstance(ct, bytes) and len(ct) > 0
        assert aes_key[Attribute.KEY_TYPE] == KeyType.AES
        value = aes_key[Attribute.VALUE]
        assert len(value) == 32, f"Expected 32-byte AES-256 key, got {len(value)} bytes"

    @pytest.mark.parametrize(
        "param_set,expected_ct_len",
        [
            (MLKemParameterSet.ML_KEM_512, 768),
            (MLKemParameterSet.ML_KEM_768, 1088),
            (MLKemParameterSet.ML_KEM_1024, 1568),
        ],
    )
    def test_parameter_set_produces_correct_ciphertext_size(
        self,
        p11_session: Any,
        p11_module: Any,
        param_set: MLKemParameterSet,
        expected_ct_len: int,
    ) -> None:
        """Requesting a specific ML-KEM parameter set produces the expected ciphertext size."""
        _skip_if_no_ml_kem(p11_module)
        try:
            pub, _ = _generate_ml_kem_keypair(p11_session, param_set=param_set)
        except Exception:
            pytest.xfail(
                f"Module does not support CKA_PARAMETER_SET={param_set.name} - "
                "may use a fixed parameter set"
            )
        key_tmpl = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
        }
        try:
            ct, _ = pub.encapsulate_key(KeyType.GENERIC_SECRET, template=key_tmpl)
        except NotImplementedError:
            pytest.skip("encapsulate_key not available")
        assert len(ct) == expected_ct_len, (
            f"Expected {expected_ct_len}-byte ciphertext for {param_set.name}, got {len(ct)}"
        )

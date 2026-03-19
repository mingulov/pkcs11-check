"""CKR compliance tests for C_EncapsulateKey and C_DecapsulateKey.

v3.2 only — requires ML-KEM mechanism support.
Only Kryoptic currently implements KEM operations.

Source: PKCS#11 v3.2 §5.14.7 (C_EncapsulateKey), §5.14.8 (C_DecapsulateKey).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.constants import MLKemParameterSet
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEM, assert_ckr
from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.access, pytest.mark.pqc, pytest.mark.requires_v32]


def _generate_ml_kem_keypair(session: Any) -> tuple[Any, Any]:
    """Generate ML-KEM-768 keypair for tests."""
    param_set = int(MLKemParameterSet.ML_KEM_768)
    pub_tmpl = {
        Attribute.ENCAPSULATE: True,
        Attribute.PARAMETER_SET: param_set,
        Attribute.TOKEN: False,
    }
    priv_tmpl = {
        Attribute.DECAPSULATE: True,
        Attribute.PARAMETER_SET: param_set,
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: False,
    }
    return session.generate_keypair(
        KeyType.ML_KEM,
        mechanism=Mechanism.ML_KEM_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


class TestEncapsulateKeyErrors:
    """Error conditions for C_EncapsulateKey (§5.14.7)."""

    def test_mechanism_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """Using AES mechanism for encapsulate -> CKR_MECHANISM_INVALID."""
        if not has_mechanism(p11_module, "ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, _priv = _generate_ml_kem_keypair(p11_session)
        try:
            pub.encapsulate_key(
                KeyType.AES,
                mechanism=Mechanism.AES_ECB,  # Wrong: not a KEM mechanism
            )
            pytest.fail("Should have rejected AES_ECB as encapsulate mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_KEM["encap_mechanism_invalid"], e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """RSA key with ML-KEM mechanism -> CKR_KEY_TYPE_INCONSISTENT.

        python-pkcs11 only adds encapsulate_key() to ML-KEM public keys.
        RSA PublicKey won't have the method. Skip if wrapper blocks.
        """
        if not has_mechanism(p11_module, "ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        if not hasattr(pub, "encapsulate_key"):
            pytest.skip(
                "python-pkcs11 doesn't expose encapsulate_key on non-KEM keys "
                "(testable via ctypes in Tier 6)"
            )
        try:
            pub.encapsulate_key(KeyType.AES, mechanism=Mechanism.ML_KEM)
            pytest.fail("Should have rejected RSA key with ML-KEM mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_KEM["encap_key_type_inconsistent"], e, ckr_strict)


class TestDecapsulateKeyErrors:
    """Error conditions for C_DecapsulateKey (§5.14.8)."""

    def test_mechanism_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """Using AES mechanism for decapsulate -> CKR_MECHANISM_INVALID."""
        if not has_mechanism(p11_module, "ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(p11_session)
        try:
            priv.decapsulate_key(
                KeyType.AES,
                b"\x00" * 1088,  # ML-KEM-768 ciphertext size
                mechanism=Mechanism.AES_ECB,  # Wrong: not a KEM mechanism
            )
            pytest.fail("Should have rejected AES_ECB as decapsulate mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_KEM["decap_mechanism_invalid"], e, ckr_strict)

    def test_garbage_ciphertext(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """Decapsulate garbage ciphertext — reject or implicit rejection."""
        if not has_mechanism(p11_module, "ML_KEM"):
            pytest.skip("ML_KEM not supported")
        _pub, priv = _generate_ml_kem_keypair(p11_session)
        exp = CKR_KEM["decap_ciphertext_invalid"]
        try:
            # ML-KEM-768 ciphertext = 1088 bytes. Provide garbage.
            priv.decapsulate_key(
                KeyType.AES,
                b"\xFF" * 1088,
                mechanism=Mechanism.ML_KEM,
            )
            # ML-KEM implicit rejection: may produce a key (spec allows this)
            if not exp.allow_success:
                pytest.fail("Should have rejected garbage ciphertext")
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

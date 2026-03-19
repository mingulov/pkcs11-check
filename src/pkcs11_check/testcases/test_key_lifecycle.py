"""End-to-end key lifecycle tests.

Tests the full lifecycle of cryptographic keys:
generate -> use -> export/wrap -> import/unwrap -> verify -> destroy.
Catches integration bugs that unit tests miss.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


class TestRSAKeyLifecycle:
    """Full RSA key lifecycle: generate -> sign -> export -> import -> verify."""

    def test_rsa_export_import_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Generate RSA, sign, export pub components, import, verify signature."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA not supported")

        # Generate
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        # Sign
        data = b"RSA lifecycle test data"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256

        # Export public key components
        modulus = pub[Attribute.MODULUS]
        exponent = pub[Attribute.PUBLIC_EXPONENT]

        # Import as new public key
        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: exponent,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )

        # Verify with imported key
        assert imported.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Destroy all
        pub.destroy()
        priv.destroy()
        imported.destroy()


class TestAESKeyWrapLifecycle:
    """Full AES key wrap lifecycle: generate wrapping key, wrap target, unwrap, verify."""

    def test_aes_wrap_unwrap_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap AES key with another AES key, unwrap, verify material matches."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        # Generate wrapping key (256-bit AES)
        wrap_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        # Generate target key to be wrapped
        target = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        original_value = target[Attribute.VALUE]

        # Wrap
        wrapped = wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)
        assert wrapped != original_value

        # Unwrap
        unwrapped = wrap_key.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.AES_KEY_WRAP,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )

        # Verify material matches
        assert unwrapped[Attribute.VALUE] == original_value

    def test_aes_wrapped_key_functional(self, p11_session: Any, p11_module: Any) -> None:
        """Unwrapped AES key can encrypt/decrypt correctly."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        wrap_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )

        target = p11_session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )

        # Encrypt with original key
        plaintext = b"lifecycle test!!" * 2  # 32 bytes
        ct = target.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        # Wrap and unwrap
        wrapped = wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)
        unwrapped = wrap_key.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.AES_KEY_WRAP,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )

        # Decrypt with unwrapped key
        pt = unwrapped.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext


class TestECKeyLifecycle:
    """Full EC key lifecycle: generate -> sign -> export -> import -> verify."""

    def test_ec_export_import_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Generate EC, sign, export point, import, verify signature."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC not supported")
        if not has_mechanism(p11_module, "ECDSA"):
            pytest.skip("ECDSA not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub, priv = params.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip("secp256r1 not supported")
            return

        # Sign
        data = b"EC lifecycle test"
        sig = priv.sign(data, mechanism=Mechanism.ECDSA)

        # Export
        ec_point = pub[Attribute.EC_POINT]
        ec_params = pub[Attribute.EC_PARAMS]

        # Import
        imported = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.EC_PARAMS: ec_params,
                Attribute.EC_POINT: ec_point,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )

        # Verify
        assert imported.verify(data, sig, mechanism=Mechanism.ECDSA)

        # Cleanup
        pub.destroy()
        priv.destroy()
        imported.destroy()


class TestKeyDestroyVerification:
    """Verify that destroyed keys are truly gone."""

    def test_destroyed_key_not_findable(self, p11_session: Any) -> None:
        """After destroy, key cannot be found by any search."""
        key = p11_session.generate_key(KeyType.AES, 256, label="destroy-verify")
        key.destroy()

        # Search by label
        by_label = list(p11_session.get_objects({Attribute.LABEL: "destroy-verify"}))
        assert len(by_label) == 0

    def test_destroy_does_not_affect_other_keys(self, p11_session: Any) -> None:
        """Destroying one key doesn't affect other keys."""
        k1 = p11_session.generate_key(KeyType.AES, 128, label="keep-me")
        k2 = p11_session.generate_key(KeyType.AES, 128, label="destroy-me")

        k2.destroy()

        # k1 should still work
        ct = k1.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 16
        k1.destroy()

"""RSA key wrapping tests.

Tests C_WrapKey / C_UnwrapKey with RSA-PKCS and RSA-OAEP mechanisms.
Wraps an AES key with an RSA public key, unwraps with the private key,
and verifies the key material matches.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


def _make_rsa_pair(session: Any) -> tuple[Any, Any]:
    """Generate RSA-2048 keypair with default capabilities (includes WRAP/UNWRAP)."""
    result: tuple[Any, Any] = session.generate_keypair(KeyType.RSA, 2048)
    return result


def _make_extractable_aes(session: Any, bits: int = 128) -> Any:
    """Generate an extractable AES key suitable for wrapping."""
    return session.generate_key(
        KeyType.AES,
        bits,
        template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
    )


class TestRSAPKCSWrap:
    """Test RSA-PKCS (v1.5) key wrapping."""

    def test_wrap_unwrap_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap AES-128 key with RSA, unwrap, verify key material matches."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(p11_session)
        aes_key = _make_extractable_aes(p11_session, 128)
        original_value = aes_key[Attribute.VALUE]

        wrapped = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS)
        assert wrapped != original_value
        assert len(wrapped) == 256  # 2048-bit RSA -> 256 bytes

        unwrapped = priv.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.RSA_PKCS,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert unwrapped[Attribute.VALUE] == original_value

    def test_wrap_unwrap_aes256(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap AES-256 key -- larger key material still fits in RSA-2048."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(p11_session)
        aes_key = _make_extractable_aes(p11_session, 256)
        original_value = aes_key[Attribute.VALUE]

        wrapped = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS)
        unwrapped = priv.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.RSA_PKCS,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert unwrapped[Attribute.VALUE] == original_value

    def test_wrapped_key_is_different_each_time(self, p11_session: Any, p11_module: Any) -> None:
        """RSA-PKCS wrapping is randomized -- same key wraps differently each time."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, _priv = _make_rsa_pair(p11_session)
        aes_key = _make_extractable_aes(p11_session)

        wrapped1 = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS)
        wrapped2 = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS)
        assert wrapped1 != wrapped2  # Randomized padding


class TestRSAOAEPWrap:
    """Test RSA-OAEP key wrapping (more secure than PKCS v1.5)."""

    def test_wrap_unwrap_oaep(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap/unwrap AES key with RSA-OAEP."""
        if not has_mechanism(p11_module, "RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")

        pub, priv = _make_rsa_pair(p11_session)
        aes_key = _make_extractable_aes(p11_session, 128)
        original_value = aes_key[Attribute.VALUE]

        wrapped = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS_OAEP)
        unwrapped = priv.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.RSA_PKCS_OAEP,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert unwrapped[Attribute.VALUE] == original_value


class TestWrappedKeyUsability:
    """Verify unwrapped keys are fully functional."""

    def test_unwrapped_key_encrypts(self, p11_session: Any, p11_module: Any) -> None:
        """An unwrapped AES key can be used for encryption."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(p11_session)
        aes_key = p11_session.generate_key(
            KeyType.AES,
            128,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )

        # Encrypt with original key
        plaintext = b"wrap-test-data!!" * 2  # 32 bytes
        ct = aes_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        # Wrap -> unwrap -> decrypt with unwrapped key
        wrapped = pub.wrap_key(aes_key, mechanism=Mechanism.RSA_PKCS)
        unwrapped = priv.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            mechanism=Mechanism.RSA_PKCS,
            template={
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )
        pt = unwrapped.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    def test_non_extractable_key_cannot_be_wrapped(self, p11_session: Any, p11_module: Any) -> None:
        """EXTRACTABLE=False key must not be wrappable."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, _priv = _make_rsa_pair(p11_session)
        non_extractable = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.EXTRACTABLE: False},
        )

        with pytest.raises(Exception):  # noqa: B017
            pub.wrap_key(non_extractable, mechanism=Mechanism.RSA_PKCS)

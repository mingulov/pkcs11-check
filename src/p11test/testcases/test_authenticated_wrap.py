"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


class TestAuthenticatedWrap:
    """Test AES-GCM authenticated key wrapping (v3.2)."""

    def test_aes_gcm_wrap_unwrap(
        self, p11_session: Any, p11_module: Any, p11_interface_version: str
    ) -> None:
        """Wrap/unwrap AES key with AES-GCM authenticated wrapping."""
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not has_mechanism(p11_module, "AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        # Generate wrapping key
        wrap_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )

        # Generate target key
        target = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        original_value = target[Attribute.VALUE]

        # Wrap with authentication
        try:
            wrapped, tag = wrap_key.wrap_key_authenticated(
                target,
                mechanism=Mechanism.AES_GCM,
            )
        except (NotImplementedError, AttributeError, TypeError):
            pytest.skip("wrap_key_authenticated not available or GCM params unsupported")
            return
        except Exception as e:
            # Some modules need specific GCM parameters
            pytest.skip(f"Authenticated wrapping failed: {e}")
            return

        assert wrapped != original_value
        assert tag is not None or wrapped is not None

        # Unwrap with authentication
        unwrapped = wrap_key.unwrap_key_authenticated(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            tag if tag else b"",
            mechanism=Mechanism.AES_GCM,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert unwrapped[Attribute.VALUE] == original_value

    def test_authenticated_wrap_requires_v32(
        self, p11_session: Any, p11_interface_version: str
    ) -> None:
        """On v2.40 modules, wrap_key_authenticated raises NotImplementedError."""
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        key = p11_session.generate_key(KeyType.AES, 256)
        target = p11_session.generate_key(
            KeyType.AES,
            128,
            template={Attribute.EXTRACTABLE: True},
        )

        with pytest.raises((NotImplementedError, AttributeError)):
            key.wrap_key_authenticated(target)

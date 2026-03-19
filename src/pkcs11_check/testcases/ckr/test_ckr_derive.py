"""CKR compliance tests for C_DeriveKey.

Source: PKCS#11 v3.1 §5.14.5.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.ckr._ckr_spec import CKR_DERIVE, assert_ckr
from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestDeriveKeyErrors:
    """Error conditions for C_DeriveKey (§5.14.5)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for derive -> CKR_MECHANISM_INVALID."""
        key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.DERIVE: True},
        )
        try:
            key.derive_key(
                KeyType.AES, 128,
                mechanism=Mechanism.SHA256,
            )
            pytest.fail("Should have rejected SHA256 as derive mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_DERIVE["mechanism_invalid"], e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """RSA key with ECDH derive mechanism -> CKR_KEY_TYPE_INCONSISTENT.

        python-pkcs11 requires CKA_DERIVE=True on the key to expose derive_key().
        RSA keys don't normally have DERIVE, so we skip if wrapper blocks it.
        Full ctypes testing in Tier 6.
        """
        if not has_mechanism(p11_module, "ECDH1_DERIVE"):
            pytest.skip("ECDH1_DERIVE not supported")
        _pub, priv = p11_session.generate_keypair(
            KeyType.RSA, 2048,
            private_template={Attribute.DERIVE: True},
        )
        if not hasattr(priv, "derive_key"):
            pytest.skip("python-pkcs11 doesn't expose derive_key on RSA without DERIVE attr")
        try:
            priv.derive_key(
                KeyType.AES, 128,
                mechanism=Mechanism.ECDH1_DERIVE,
                mechanism_param=b"\x00" * 65,
            )
            pytest.fail("Should have rejected RSA key with ECDH derive")
        except PKCS11Error as e:
            assert_ckr(CKR_DERIVE["key_type_inconsistent"], e, ckr_strict)

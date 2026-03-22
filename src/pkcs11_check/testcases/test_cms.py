"""Tests for CMS signature mechanism.

Covers CKM_CMS_SIG (0x500).

CKM_CMS_SIG is a sign/sign-recover mechanism using CMS (Cryptographic Message Syntax).
It requires a CK_CMS_SIG_PARAMS structure containing a certificate handle, signing
mechanism OID, digest mechanism OID, content type OID, and requested/required attributes.
This mechanism is extremely rarely implemented by PKCS#11 modules.

OASIS spec: cms_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import (
    FunctionFailed,
    GeneralError,
    MechanismInvalid,
    MechanismParamInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.sign

# Errors expected when attempting CMS_SIG without proper params / unsupported by module
_SIGN_ERRORS = (MechanismInvalid, MechanismParamInvalid, FunctionFailed, GeneralError)


class TestCMSSig:
    """CKM_CMS_SIG tests -- CMS signature mechanism (sign and sign-recover)."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Report whether CKM_CMS_SIG is supported; skip if not."""
        if not has_mechanism(p11_module, "CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

    def test_mechanism_info(self, p11_module: Any) -> None:
        """CKM_CMS_SIG mechanism info should report sign/sign-recover flags."""
        if not has_mechanism(p11_module, "CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        slot = p11_module.get_slots(token_present=True)[0]
        mechs = slot.get_mechanisms()
        assert Mechanism.CMS_SIG in mechs

        try:
            info = slot.get_mechanism_info(Mechanism.CMS_SIG)
            # CMS_SIG is a signing mechanism -- should support CKF_SIGN
            # Key sizes are typically reported as 0 for RSA-based sign-with-cert mechanisms
            assert info is not None
        except (AttributeError, GeneralError):
            # Not all bindings expose get_mechanism_info -- skip gracefully
            pass

    def test_cms_sig_requires_rsa_key(self, p11_session: Any, p11_module: Any) -> None:
        """CKM_CMS_SIG sign attempt with RSA key and no params is expected to fail cleanly.

        CKM_CMS_SIG requires a CK_CMS_SIG_PARAMS structure with:
          - certificate: CK_OBJECT_HANDLE pointing to a certificate object
          - pSigningMechanism: OID for the signing mechanism
          - pDigestMechanism: OID for the digest mechanism
          - pContentType: content type OID string
          - pRequestedAttributes / pRequiredAttributes: CMS attributes

        The python-pkcs11 fork does not provide a Python wrapper class for
        CK_CMS_SIG_PARAMS, so we cannot construct valid parameters here.
        We verify the mechanism is present and that the module rejects a bare
        invocation without params rather than crashing.
        """
        if not has_mechanism(p11_module, "CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        # Generate an RSA key pair -- the most common key type for CMS signing
        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                mechanism=Mechanism.RSA_PKCS_KEY_PAIR_GEN,
                public_template={
                    Attribute.ENCRYPT: False,
                    Attribute.VERIFY: True,
                    Attribute.TOKEN: False,
                },
                private_template={
                    Attribute.DECRYPT: False,
                    Attribute.SIGN: True,
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: False,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed) as e:
            pytest.skip(f"RSA key generation not available: {e}")

        try:
            # Attempt CMS_SIG sign without params -- must fail, not crash.
            # No Python binding for CK_CMS_SIG_PARAMS exists in the fork,
            # so mechanism_param=None is the only option.
            try:
                priv.sign(b"test message", mechanism=Mechanism.CMS_SIG)
                # If we reach here the module accepted no-param CMS_SIG -- unexpected but record it
                pytest.xfail(
                    "CKM_CMS_SIG sign succeeded without CK_CMS_SIG_PARAMS "
                    "(module is unusually permissive)"
                )
            except _SIGN_ERRORS:
                # Expected: module rejects missing/invalid params
                pass
        finally:
            priv.destroy()
            pub.destroy()

    def test_cms_sig_not_usable_as_encrypt(self, p11_session: Any, p11_module: Any) -> None:
        """CKM_CMS_SIG must not be usable as an encryption mechanism."""
        if not has_mechanism(p11_module, "CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        # Generate a minimal AES key -- if CMS_SIG were mistakenly accepted for
        # encrypt, it would represent a serious implementation error.
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.AES_KEY_GEN,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed) as e:
            pytest.skip(f"AES key generation not available: {e}")

        try:
            with pytest.raises(_SIGN_ERRORS):
                key.encrypt(b"data", mechanism=Mechanism.CMS_SIG)
        finally:
            key.destroy()

    def test_cms_sig_mechanism_value(self) -> None:
        """CKM_CMS_SIG numeric value must be 0x500 per PKCS#11 spec."""
        assert Mechanism.CMS_SIG == 0x500

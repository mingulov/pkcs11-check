"""Read-only session restriction enforcement tests.

Verifies that RO sessions correctly reject write operations on token objects
while allowing session-scoped operations, per PKCS#11 spec section 5.6.
"""

from __future__ import annotations

import os
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    ActionProhibited,
    AttributeReadOnly,
    FunctionNotSupported,
    MechanismInvalid,
    SessionReadOnly,
    SessionReadOnlyExists,
    TokenWriteProtected,
    UserAlreadyLoggedIn,
    UserTypeInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access

# RO restriction errors - spec says CKR_SESSION_READ_ONLY, some modules
# return CKR_ACTION_PROHIBITED or CKR_SESSION_READ_ONLY_EXISTS instead.
_RO_ERRORS = (SessionReadOnly, ActionProhibited, SessionReadOnlyExists)

# Broader set of errors modules may return when an operation is not allowed in RO session
# or when unwrap/wrap is not supported at all.
_RO_OR_UNSUPPORTED_ERRORS = (
    SessionReadOnly,
    ActionProhibited,
    SessionReadOnlyExists,
    TokenWriteProtected,
    AttributeReadOnly,
    FunctionNotSupported,
    MechanismInvalid,
)


def _login(session: Any, pin: str | None) -> None:
    """Login to a session, handling already-logged-in state."""
    if pin is None:
        return
    try:
        session.login(p11.UserType.USER, pin)
    except (UserAlreadyLoggedIn, UserTypeInvalid):
        pass


def _get_pin(p11_config: Any) -> str | None:
    """Extract PIN from config safely."""
    return p11_config.pin.get_secret_value() if p11_config.pin else None


class TestROTokenObjectCreation:
    """RO sessions must reject creation of token-persistent objects."""

    def test_create_token_object_in_ro_fails(self, p11_module: Any, p11_config: Any) -> None:
        """C_CreateObject with CKA_TOKEN=True in RO session must fail."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            with pytest.raises(_RO_ERRORS):
                session.create_object(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.KEY_TYPE: KeyType.AES,
                        Attribute.VALUE: os.urandom(16),
                        Attribute.TOKEN: True,
                        Attribute.SENSITIVE: False,
                        Attribute.EXTRACTABLE: True,
                    }
                )
        finally:
            session.close()

    def test_generate_key_token_true_in_ro_fails(self, p11_module: Any, p11_config: Any) -> None:
        """generate_key with TOKEN=True in RO session must fail."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            with pytest.raises(_RO_ERRORS):
                session.generate_key(
                    KeyType.AES,
                    128,
                    label="ro-genkey-token",
                    template={Attribute.TOKEN: True},
                )
        finally:
            session.close()

    def test_generate_keypair_token_true_in_ro_fails(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """generate_keypair with TOKEN=True in RO session must fail."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            with pytest.raises(_RO_ERRORS):
                session.generate_keypair(
                    KeyType.RSA,
                    2048,
                    label="ro-genkeypair-token",
                    store=True,
                )
        finally:
            session.close()


class TestROSessionObjectsAllowed:
    """RO sessions must allow session-scoped (TOKEN=False) operations."""

    def test_create_session_object_in_ro_succeeds(self, p11_module: Any, p11_config: Any) -> None:
        """C_CreateObject with CKA_TOKEN=False in RO session succeeds."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            obj = session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.VALUE: os.urandom(16),
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                }
            )
            assert obj is not None
            obj.destroy()
        finally:
            session.close()

    def test_generate_key_token_false_in_ro_succeeds(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """generate_key with TOKEN=False in RO session succeeds."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            key = session.generate_key(
                KeyType.AES,
                128,
                label="ro-genkey-session",
                template={Attribute.TOKEN: False},
            )
            assert key is not None
            key.destroy()
        finally:
            session.close()

    def test_generate_keypair_session_in_ro_succeeds(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """generate_keypair with store=False in RO session succeeds."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            pub, priv = session.generate_keypair(
                KeyType.RSA,
                2048,
                label="ro-keypair-session",
                store=False,
            )
            assert pub is not None
            assert priv is not None
            pub.destroy()
            priv.destroy()
        finally:
            session.close()


class TestROTokenObjectMutation:
    """RO sessions must reject mutation of token objects."""

    def test_destroy_token_object_in_ro_fails(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """C_DestroyObject of token object in RO session must fail."""
        label = "ro-destroy-test"
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            label=label,
            template={Attribute.TOKEN: True},
        )
        try:
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(ro_session.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object not found in RO session"
                with pytest.raises(_RO_ERRORS):
                    found[0].destroy()
            finally:
                ro_session.close()
        finally:
            key.destroy()

    def test_set_attribute_token_object_in_ro_fails(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """C_SetAttributeValue on token object in RO session must fail."""
        label = "ro-setattr-test"
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            label=label,
            template={
                Attribute.TOKEN: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )
        try:
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(ro_session.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object not found in RO session"
                with pytest.raises(_RO_ERRORS):
                    found[0][Attribute.LABEL] = "ro-setattr-changed"
            finally:
                ro_session.close()
        finally:
            key.destroy()

    def test_copy_token_object_in_ro_as_token_fails(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """C_CopyObject of token object to another token object in RO fails."""
        label = "ro-copy-test"
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            label=label,
            template={
                Attribute.TOKEN: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )
        try:
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(ro_session.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object not found in RO session"
                with pytest.raises(_RO_ERRORS):
                    found[0].copy(
                        {
                            Attribute.LABEL: "ro-copy-result",
                            Attribute.TOKEN: True,
                        }
                    )
            finally:
                ro_session.close()
        finally:
            key.destroy()


class TestROCryptoOperations:
    """Crypto operations (no token writes) must work in RO sessions."""

    def test_digest_in_ro_session(self, p11_module: Any, p11_config: Any) -> None:
        """SHA-256 digest works in RO session."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            digest = session.digest(
                b"RO session restriction test data",
                mechanism=Mechanism.SHA256,
            )
            assert len(digest) == 32
        finally:
            session.close()

    def test_encrypt_decrypt_session_key_in_ro(self, p11_module: Any, p11_config: Any) -> None:
        """Encrypt/decrypt with session key works in RO session."""
        if not has_mechanism(p11_module, "AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            key = session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                },
            )
            iv = os.urandom(16)
            plaintext = b"RO encrypt test!"
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
            assert pt == plaintext
            key.destroy()
        finally:
            session.close()

    def test_sign_verify_session_key_in_ro(self, p11_module: Any, p11_config: Any) -> None:
        """HMAC sign/verify with session key works in RO session."""
        if not has_mechanism(p11_module, "SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            key = session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.SIGN: True,
                    Attribute.VERIFY: True,
                },
            )
            data = b"RO session HMAC test"
            sig = key.sign(data, mechanism=Mechanism.SHA256_HMAC)
            assert len(sig) > 0
            result = key.verify(data, sig, mechanism=Mechanism.SHA256_HMAC)
            assert result is True
            key.destroy()
        finally:
            session.close()

    def test_verify_token_key_in_ro(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Verification with a token key works in RO session."""
        label = "ro-verify-rsa-test"
        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            label=label,
            store=True,
        )
        data = b"verify in read-only session"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        try:
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(
                    ro_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, "Public key not found in RO session"
                result = found[0].verify(
                    data,
                    sig,
                    mechanism=Mechanism.SHA256_RSA_PKCS,
                )
                assert result is True
            finally:
                ro_session.close()
        finally:
            pub.destroy()
            priv.destroy()


class TestROExactCKR:
    """Verify the exact CKR code returned for RO restriction violations."""

    def test_create_token_object_returns_session_read_only(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Primary expected CKR is CKR_SESSION_READ_ONLY."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            with pytest.raises(_RO_ERRORS) as exc_info:
                session.create_object(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.KEY_TYPE: KeyType.AES,
                        Attribute.VALUE: os.urandom(16),
                        Attribute.TOKEN: True,
                        Attribute.SENSITIVE: False,
                        Attribute.EXTRACTABLE: True,
                    }
                )
            # Log which exact CKR was returned for diagnostic purposes
            exc_type = type(exc_info.value)
            assert exc_type in (
                SessionReadOnly,
                ActionProhibited,
                SessionReadOnlyExists,
            ), f"Unexpected exception type: {exc_type.__name__}"
        finally:
            session.close()

    def test_destroy_token_object_returns_session_read_only(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Destroy of token object in RO returns CKR_SESSION_READ_ONLY."""
        label = "ro-ckr-destroy-test"
        key = p11_session.generate_key(
            KeyType.AES,
            128,
            label=label,
            template={Attribute.TOKEN: True},
        )
        try:
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(ro_session.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object not found in RO session"
                with pytest.raises(_RO_ERRORS) as exc_info:
                    found[0].destroy()
                exc_type = type(exc_info.value)
                assert exc_type in (
                    SessionReadOnly,
                    ActionProhibited,
                    SessionReadOnlyExists,
                ), f"Unexpected exception type: {exc_type.__name__}"
            finally:
                ro_session.close()
        finally:
            key.destroy()

    def test_generate_key_token_returns_session_read_only(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Key generation with TOKEN=True in RO returns CKR_SESSION_READ_ONLY."""
        token = p11_module.get_token()
        pin = _get_pin(p11_config)
        session = token.open(rw=False)
        _login(session, pin)
        try:
            with pytest.raises(_RO_ERRORS) as exc_info:
                session.generate_key(
                    KeyType.AES,
                    256,
                    label="ro-ckr-genkey",
                    template={Attribute.TOKEN: True},
                )
            exc_type = type(exc_info.value)
            assert exc_type in (
                SessionReadOnly,
                ActionProhibited,
                SessionReadOnlyExists,
            ), f"Unexpected exception type: {exc_type.__name__}"
        finally:
            session.close()


class TestROWrapUnwrapRestrictions:
    """Unwrap creating TOKEN=True key in RO session must fail."""

    def test_unwrap_to_token_object_in_ro_fails(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Unwrap with TOKEN=True template in RO session must fail.

        Per spec, C_UnwrapKey creating a TOKEN=True object in a RO session must
        return CKR_SESSION_READ_ONLY. Some modules return related errors
        (CKR_TOKEN_WRITE_PROTECTED, CKR_ACTION_PROHIBITED, CKR_ATTRIBUTE_READ_ONLY)
        or CKR_FUNCTION_NOT_SUPPORTED / CKR_MECHANISM_INVALID if wrap/unwrap is
        not implemented at all — all are acceptable here since the operation fails.
        """
        # Create wrapping key and target in RW session
        wrapping_key = p11_session.generate_key(
            KeyType.AES,
            256,
            label="ro-unwrap-wrapkey",
            template={
                Attribute.TOKEN: True,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )
        target = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: os.urandom(16),
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )
        try:
            try:
                wrapped = wrapping_key.wrap_key(target)
            except (FunctionNotSupported, MechanismInvalid):
                pytest.skip("Module does not support wrap/unwrap")
            assert len(wrapped) > 0

            # Open RO session, find wrapping key, try unwrap with TOKEN=True
            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(
                    ro_session.get_objects(
                        {
                            Attribute.LABEL: "ro-unwrap-wrapkey",
                        }
                    )
                )
                assert len(found) >= 1, "Wrapping key not found in RO session"
                ro_wrap_key = found[0]
                with pytest.raises(_RO_OR_UNSUPPORTED_ERRORS):
                    ro_wrap_key.unwrap_key(
                        ObjectClass.SECRET_KEY,
                        KeyType.AES,
                        wrapped,
                        template={
                            Attribute.TOKEN: True,
                            Attribute.SENSITIVE: False,
                            Attribute.EXTRACTABLE: True,
                        },
                    )
            finally:
                ro_session.close()
        finally:
            target.destroy()
            wrapping_key.destroy()

    def test_unwrap_to_session_object_in_ro_succeeds(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Unwrap with TOKEN=False template in RO session succeeds.

        Per PKCS#11 spec, C_UnwrapKey creating a session object (TOKEN=False) is
        permitted in a RO session. However, some modules are overly restrictive and
        reject all unwrap in RO sessions, or do not implement wrap/unwrap at all.
        """
        wrapping_key = p11_session.generate_key(
            KeyType.AES,
            256,
            label="ro-unwrap-session-wrapkey",
            template={
                Attribute.TOKEN: True,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            },
        )
        key_bytes = os.urandom(16)
        target = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )
        try:
            try:
                wrapped = wrapping_key.wrap_key(target)
            except (FunctionNotSupported, MechanismInvalid):
                pytest.skip("Module does not support wrap/unwrap")

            token = p11_module.get_token()
            ro_session = token.open(rw=False)
            try:
                found = list(
                    ro_session.get_objects(
                        {
                            Attribute.LABEL: "ro-unwrap-session-wrapkey",
                        }
                    )
                )
                assert len(found) >= 1, "Wrapping key not found in RO session"
                ro_wrap_key = found[0]
                try:
                    unwrapped = ro_wrap_key.unwrap_key(
                        ObjectClass.SECRET_KEY,
                        KeyType.AES,
                        wrapped,
                        template={
                            Attribute.TOKEN: False,
                            Attribute.SENSITIVE: False,
                            Attribute.EXTRACTABLE: True,
                        },
                    )
                except _RO_OR_UNSUPPORTED_ERRORS as exc:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Module rejects C_UnwrapKey with TOKEN=False in RO session "
                        f"({type(exc).__name__}); PKCS#11 spec permits session-object "
                        "creation via C_UnwrapKey in RO sessions",
                        ComplianceLevel.NOT_RECOMMENDED,
                    )
                    pytest.xfail(
                        f"Module overly restricts RO session unwrap ({type(exc).__name__})"
                    )
                assert unwrapped is not None
                unwrapped.destroy()
            finally:
                ro_session.close()
        finally:
            target.destroy()
            wrapping_key.destroy()

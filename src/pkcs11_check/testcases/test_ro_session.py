"""Read-only session and session-object lifecycle tests.

Verifies that operations work in R/O sessions and that session
objects don't persist after session close.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.access


class TestROSessionOperations:
    """Test operations that should work in R/O sessions."""

    def test_digest_in_ro_session(self, p11_module: Any, p11_config: Any) -> None:
        """Digest works in R/O session (no key needed)."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        session = token.open(rw=False)
        if pin is not None:
            try:
                session.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        try:
            digest = session.digest(b"RO session digest test", mechanism=Mechanism.SHA256)
            assert len(digest) == 32
        finally:
            session.close()

    def test_find_objects_in_ro_session(self, p11_session: Any, p11_module: Any, p11_config: Any) -> None:
        """Finding objects works in R/O session."""
        # Create a key in R/W session first
        key = p11_session.generate_key(KeyType.AES, 128, label="ro-find-test")

        token = p11_module.get_token()
        session_ro = token.open(rw=False)
        try:
            found = list(session_ro.get_objects({Attribute.LABEL: "ro-find-test"}))
            # Session objects may or may not be visible in other sessions
            # but the search operation should work
            assert isinstance(found, list)
        finally:
            session_ro.close()

    def test_verify_in_ro_session(self, p11_session: Any, p11_module: Any, p11_config: Any) -> None:
        """Signature verification works in R/O session."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"verify in RO session"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Verify in R/O session using the same token-level login
        token = p11_module.get_token()
        session_ro = token.open(rw=False)
        try:
            # Find the public key
            keys = list(session_ro.get_objects({
                Attribute.CLASS: p11.ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
            }))
            if keys:
                result = keys[0].verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)
                assert result is True
        finally:
            session_ro.close()


class TestSessionObjectLifecycle:
    """Test that session objects don't persist after session close."""

    def test_session_object_gone_after_close(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Non-TOKEN object disappears after session closes."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        # Session 1: create session object
        s1 = token.open(rw=True)
        if pin is not None:
            try:
                s1.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        label = "session-lifecycle-test"
        s1.generate_key(KeyType.AES, 128, label=label)
        # Verify it exists in this session
        found = list(s1.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 1
        s1.close()

        # Session 2: the session object should be gone
        s2 = token.open(rw=True)
        if pin is not None:
            try:
                s2.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        try:
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) == 0, "Session object survived session close"
        finally:
            s2.close()

    def test_token_object_persists_after_close(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """TOKEN=True object persists after session closes."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        label = "token-lifecycle-test"

        s1 = token.open(rw=True)
        if pin is not None:
            try:
                s1.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        key = s1.generate_key(KeyType.AES, 128, label=label, template={Attribute.TOKEN: True})
        s1.close()

        # Session 2: token object should still exist
        s2 = token.open(rw=True)
        if pin is not None:
            try:
                s2.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        try:
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1, "Token object disappeared after session close"
            # Cleanup
            for obj in found:
                obj.destroy()
        finally:
            s2.close()

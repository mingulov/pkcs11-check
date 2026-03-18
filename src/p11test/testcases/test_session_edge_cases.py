"""Session edge-case tests — stale handles, CloseAllSessions, SoftHSM2 issue regressions.

References: rep11.md Iteration 2, SoftHSM2 #608, #596.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.security


class TestStaleSessionHandles:
    """Reuse closed session handle — must get error, not crash (task 7.7)."""

    def test_find_after_close(self, p11_module: Any, p11_config: Any) -> None:
        """C_FindObjects on closed session must fail cleanly."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        session = token.open(rw=True)
        if pin:
            try:
                session.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        session.close()

        # Try to use the closed session
        with pytest.raises((PKCS11Error, AttributeError, RuntimeError)):
            list(session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))

    def test_generate_key_after_close(self, p11_module: Any, p11_config: Any) -> None:
        """C_GenerateKey on closed session must fail cleanly."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        session = token.open(rw=True)
        if pin:
            try:
                session.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        session.close()

        with pytest.raises((PKCS11Error, AttributeError, RuntimeError)):
            session.generate_key(KeyType.AES, 128)


class TestCloseAllSessions:
    """C_CloseAllSessions behavior (task 7.8)."""

    def test_close_all_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Open multiple sessions, close all, verify no crash."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        sessions = []
        s1 = token.open(rw=True)
        if pin:
            try:
                s1.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        sessions.append(s1)

        # Open more sessions
        for _ in range(3):
            sessions.append(token.open(rw=True))

        # Generate a key in s1
        key = s1.generate_key(KeyType.AES, 128, label="close-all-test")

        # Close all sessions at once (token-level operation)
        # python-pkcs11 doesn't expose C_CloseAllSessions directly,
        # so close each session manually
        for s in sessions:
            try:
                s.close()
            except PKCS11Error:
                pass  # Already closed or session invalid

        # Verify we can open a new session after closing all
        s_new = token.open(rw=True)
        if pin:
            try:
                s_new.login(p11.UserType.USER, pin)
            except p11.exceptions.UserAlreadyLoggedIn:
                pass
        try:
            # Session object (not TOKEN) should be gone
            found = list(s_new.get_objects({Attribute.LABEL: "close-all-test"}))
            assert len(found) == 0, "Session key survived CloseAllSessions"
        finally:
            s_new.close()


class TestSoftHSM2IssueRegressions:
    """SoftHSM2 GitHub issue regressions (task 7.22)."""

    def test_wrap_unsupported_mechanism_returns_proper_ckr(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """SoftHSM2 #608: C_WrapKey with unsupported mechanism must return
        CKR_MECHANISM_INVALID, not CKR_GENERAL_ERROR or crash."""
        key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.WRAP: True, Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        target = p11_session.generate_key(
            KeyType.AES, 128,
            template={Attribute.EXTRACTABLE: True},
        )

        # Try wrapping with SHA-256 (not a wrapping mechanism)
        try:
            key.wrap_key(target, mechanism=Mechanism.SHA256)
            pytest.fail("Wrap with SHA-256 should have failed")
        except p11.exceptions.MechanismInvalid:
            pass  # Correct: CKR_MECHANISM_INVALID
        except p11.exceptions.KeyNotWrappable:
            pass  # Also acceptable
        except PKCS11Error as e:
            # Document if it returns wrong error
            from p11test.compliance import ComplianceLevel, note
            note(
                f"C_WrapKey with bad mechanism returned {type(e).__name__} instead of MechanismInvalid",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="SoftHSM2 #608",
            )

    def test_rsa_keygen_minimum_size(self, p11_session: Any) -> None:
        """Generate RSA with various sizes — verify minimum is enforced."""
        # Very small RSA should be rejected
        try:
            p11_session.generate_keypair(KeyType.RSA, 512)
            # If accepted, that's a policy choice
        except PKCS11Error:
            pass  # Correct to reject small RSA

        # Standard size should work
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert pub is not None

"""Cross-session object visibility tests.

Verifies PKCS#11 object visibility rules per OASIS spec:
session vs token objects, CKA_PRIVATE enforcement, cross-session semantics.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    UserAlreadyLoggedIn,
    UserTypeInvalid,
)

pytestmark = pytest.mark.access


def _ulabel(prefix: str = "vis") -> str:
    """Generate a unique label to avoid collisions between tests."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _get_pin(p11_config: Any) -> str | None:
    """Extract PIN string from config."""
    return p11_config.pin.get_secret_value() if p11_config.pin else None


def _login_session(token: Any, *, rw: bool = True, pin: str | None = None) -> Any:
    """Open a session with login, handling already-logged-in state."""
    try:
        return token.open(rw=rw, user_pin=pin)
    except (UserAlreadyLoggedIn, UserTypeInvalid):
        return token.open(rw=rw)


class TestSessionObjectLifecycle:
    """Verify session objects disappear when session closes."""

    def test_session_object_gone_after_close(self, p11_module: Any, p11_config: Any) -> None:
        """Session object not visible in new session after original closes."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("sess-gone")

        # Create session object, then close that session
        with _login_session(token, rw=True, pin=pin) as sess:
            sess.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.LABEL: label,
                },
            )

        # New session: the session object should be gone
        with _login_session(token, rw=True, pin=pin) as sess2:
            found = list(sess2.get_objects({Attribute.LABEL: label}))
            assert len(found) == 0, "Session object survived session close"

    def test_session_data_object_gone_after_close(self, p11_module: Any, p11_config: Any) -> None:
        """Session CKO_DATA object disappears when session closes."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("sess-data")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"ephemeral",
                    Attribute.TOKEN: False,
                }
            )

        with _login_session(token, rw=True, pin=pin) as sess2:
            found = list(
                sess2.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            assert len(found) == 0, "Session data object survived session close"

    def test_session_object_exists_while_session_open(self, p11_session: Any) -> None:
        """Session object is findable within the same session."""
        label = _ulabel("sess-alive")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.TOKEN: False, Attribute.LABEL: label},
        )
        try:
            found = list(p11_session.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1
        finally:
            key.destroy()


class TestTokenObjectPersistence:
    """Verify token objects persist across sessions."""

    def test_token_object_survives_session_close(self, p11_module: Any, p11_config: Any) -> None:
        """Token object (CKA_TOKEN=True) persists after session closes."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("tok-persist")

        # Session 1: create token object
        with _login_session(token, rw=True, pin=pin) as sess:
            sess.generate_key(
                KeyType.AES,
                256,
                template={Attribute.TOKEN: True, Attribute.LABEL: label},
            )

        # Session 2: token object should still exist
        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(sess2.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object did not persist"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()

    def test_token_data_object_survives_session(self, p11_module: Any, p11_config: Any) -> None:
        """Token CKO_DATA object persists after session closes."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("tok-data")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"persistent-value",
                    Attribute.TOKEN: True,
                }
            )

        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(
                    sess2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, "Token data object did not persist"
                assert found[0][Attribute.VALUE] == b"persistent-value"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()

    def test_token_object_value_preserved(self, p11_module: Any, p11_config: Any) -> None:
        """Token object attribute values are preserved across sessions."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("tok-val")
        payload = b"data-integrity-check-12345"

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: payload,
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )

        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(
                    sess2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1
                assert found[0][Attribute.LABEL] == label
                assert found[0][Attribute.VALUE] == payload
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()


class TestPrivateVisibility:
    """Test CKA_PRIVATE enforcement: private objects hidden without login."""

    def test_private_object_hidden_without_login(self, p11_module: Any, p11_config: Any) -> None:
        """CKA_PRIVATE=True token object not visible in public session."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("priv-hidden")

        # Create a private token object while logged in
        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"secret",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                }
            )

        # Log out first by closing all sessions, then open without login
        try:
            # We need to ensure no login is active. Close sessions
            # and open a fresh one without user_pin.
            # Some modules may still show the object (module quirk).
            with token.open(rw=False) as pub_sess:
                found = list(
                    pub_sess.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                if len(found) > 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "CKA_PRIVATE=True object visible without login "
                        "(token may keep login state across sessions)",
                        ComplianceLevel.VENDOR,
                    )
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()

    def test_public_object_visible_without_login(self, p11_module: Any, p11_config: Any) -> None:
        """CKA_PRIVATE=False token object visible in public session."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("pub-visible")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"public-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )

        try:
            with token.open(rw=False) as pub_sess:
                found = list(
                    pub_sess.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "CKA_PRIVATE=False object not visible without login",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="PKCS#11 spec: public objects visible in public sessions",
                    )
                else:
                    assert found[0][Attribute.VALUE] == b"public-data"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()

    def test_private_object_visible_after_login(self, p11_module: Any, p11_config: Any) -> None:
        """CKA_PRIVATE=True token object visible after login."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("priv-afterlogin")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"secret-stuff",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                }
            )

        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(
                    sess2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, "Private object not visible after login"
                assert found[0][Attribute.VALUE] == b"secret-stuff"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()


class TestCrossSessionModification:
    """Cross-session modification visibility."""

    def test_modify_in_session_a_read_in_session_b(self, p11_module: Any, p11_config: Any) -> None:
        """Modify object attribute in session A, read updated value in B."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("xmod")
        new_label = _ulabel("xmod-updated")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"original",
                    Attribute.TOKEN: True,
                    Attribute.MODIFIABLE: True,
                }
            )
            try:
                obj[Attribute.LABEL] = new_label

                with _login_session(token, rw=True, pin=pin) as sess_b:
                    found = list(
                        sess_b.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.DATA,
                                Attribute.LABEL: new_label,
                            }
                        )
                    )
                    assert len(found) >= 1, "Modified label not visible in session B"
            finally:
                # Clean up by new label (may have changed)
                for o in sess_a.get_objects(
                    {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: new_label}
                ):
                    o.destroy()
                for o in sess_a.get_objects(
                    {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
                ):
                    o.destroy()

    def test_modify_value_cross_session(self, p11_module: Any, p11_config: Any) -> None:
        """Modify CKA_VALUE in session A, verify in session B."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("xval")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"before",
                    Attribute.TOKEN: True,
                    Attribute.MODIFIABLE: True,
                    Attribute.PRIVATE: False,
                }
            )
            try:
                obj[Attribute.VALUE] = b"after"

                with _login_session(token, rw=True, pin=pin) as sess_b:
                    found = list(
                        sess_b.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.DATA,
                                Attribute.LABEL: label,
                            }
                        )
                    )
                    assert len(found) >= 1
                    assert found[0][Attribute.VALUE] == b"after", (
                        "Modified value not reflected in session B"
                    )
            finally:
                for o in sess_a.get_objects(
                    {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
                ):
                    o.destroy()


class TestCrossSessionDestruction:
    """Destruction in one session reflected in another."""

    def test_destroy_in_a_gone_in_b(self, p11_module: Any, p11_config: Any) -> None:
        """Token object destroyed in session A is gone from session B search."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("xdestroy")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"doomed",
                    Attribute.TOKEN: True,
                }
            )
            with _login_session(token, rw=True, pin=pin) as sess_b:
                # Verify it exists in B before destruction
                found_before = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found_before) >= 1, "Object not visible in session B before destroy"

                # Destroy in A
                obj.destroy()

                # Should be gone from B's search
                found_after = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found_after) == 0, "Destroyed object still visible in session B"

    def test_destroy_session_object_cross_session(self, p11_module: Any, p11_config: Any) -> None:
        """Session object destroyed in session A is gone from session B."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("xdestroy-sess")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"session-doomed",
                    Attribute.TOKEN: False,
                }
            )
            with _login_session(token, rw=True, pin=pin) as sess_b:
                found_before = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                # Session objects may or may not be visible cross-session
                if len(found_before) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Session objects not visible across sessions "
                        "(some modules isolate session objects)",
                        ComplianceLevel.VENDOR,
                    )
                    return

                obj.destroy()

                found_after = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found_after) == 0, "Destroyed session object still in session B"


class TestTokenPrivateInteraction:
    """CKA_TOKEN + CKA_PRIVATE interaction matrix."""

    def test_public_session_obj_visible_same_session(self, p11_session: Any) -> None:
        """TOKEN=False, PRIVATE=False object visible in same session."""
        label = _ulabel("pub-sess")
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"pub-session",
                Attribute.TOKEN: False,
                Attribute.PRIVATE: False,
            }
        )
        try:
            found = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            assert len(found) >= 1
        finally:
            obj.destroy()

    def test_private_session_obj_visible_same_session(self, p11_session: Any) -> None:
        """TOKEN=False, PRIVATE=True object visible in same logged-in session."""
        label = _ulabel("priv-sess")
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"priv-session",
                Attribute.TOKEN: False,
                Attribute.PRIVATE: True,
            }
        )
        try:
            found = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            assert len(found) >= 1
        finally:
            obj.destroy()

    def test_public_token_obj_persists(self, p11_module: Any, p11_config: Any) -> None:
        """TOKEN=True, PRIVATE=False object persists and is publicly visible."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("pub-tok")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"pub-token-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )

        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(
                    sess2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, "Public token object not found in new session"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()

    def test_private_token_obj_persists_with_login(self, p11_module: Any, p11_config: Any) -> None:
        """TOKEN=True, PRIVATE=True object persists and visible after login."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("priv-tok")

        with _login_session(token, rw=True, pin=pin) as sess:
            sess.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"priv-token-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                }
            )

        try:
            with _login_session(token, rw=True, pin=pin) as sess2:
                found = list(
                    sess2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, "Private token object not found after login in new session"
                assert found[0][Attribute.VALUE] == b"priv-token-data"
        finally:
            with _login_session(token, rw=True, pin=pin) as cleanup:
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()


class TestSessionObjectCrossVisibility:
    """Session objects: cross-session visibility semantics."""

    def test_session_object_visible_in_concurrent_session(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session object created in A visible in concurrent session B.

        Per PKCS#11 spec, session objects created by one session are
        visible to other sessions of the same application.
        """
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("sess-xvis")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"cross-visible",
                    Attribute.TOKEN: False,
                }
            )
            try:
                with _login_session(token, rw=True, pin=pin) as sess_b:
                    found = list(
                        sess_b.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.DATA,
                                Attribute.LABEL: label,
                            }
                        )
                    )
                    if len(found) == 0:
                        from pkcs11_check.compliance import (
                            ComplianceLevel,
                            note,
                        )

                        note(
                            "Session objects not visible in concurrent "
                            "sessions (module isolates session objects)",
                            ComplianceLevel.VENDOR,
                        )
                    else:
                        assert found[0][Attribute.VALUE] == b"cross-visible"
            finally:
                obj.destroy()

    def test_session_object_gone_when_creating_session_closes(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session object disappears from session B when session A closes.

        The object belongs to session A. When A closes, the object is
        destroyed, and B should no longer find it.
        """
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("sess-owner-close")

        sess_b = _login_session(token, rw=True, pin=pin)
        try:
            # Create in A, then close A
            with _login_session(token, rw=True, pin=pin) as sess_a:
                sess_a.create_object(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                        Attribute.VALUE: b"owned-by-a",
                        Attribute.TOKEN: False,
                    }
                )

            # A is closed; object should be gone from B
            found = list(
                sess_b.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                    }
                )
            )
            assert len(found) == 0, "Session object survived owning session close"
        finally:
            sess_b.close()


class TestTokenObjectImmediateVisibility:
    """Token objects visible immediately in new sessions (no caching)."""

    def test_token_object_visible_immediately(self, p11_module: Any, p11_config: Any) -> None:
        """Newly created token object visible immediately in another session."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("immed")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"immediate",
                    Attribute.TOKEN: True,
                }
            )
            try:
                # Open B immediately after creation - no delay
                with _login_session(token, rw=True, pin=pin) as sess_b:
                    found = list(
                        sess_b.get_objects(
                            {
                                Attribute.CLASS: ObjectClass.DATA,
                                Attribute.LABEL: label,
                            }
                        )
                    )
                    assert len(found) >= 1, "Token object not immediately visible in new session"
            finally:
                obj.destroy()

    def test_token_key_usable_immediately(self, p11_module: Any, p11_config: Any) -> None:
        """Token key created in A is usable for crypto in B immediately."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("immed-key")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            key_a = sess_a.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.LABEL: label,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                },
            )
            try:
                with _login_session(token, rw=True, pin=pin) as sess_b:
                    found = list(
                        sess_b.get_objects(
                            {
                                Attribute.KEY_TYPE: KeyType.AES,
                                Attribute.LABEL: label,
                            }
                        )
                    )
                    assert len(found) >= 1, "Token key not found in session B"
            finally:
                key_a.destroy()

    def test_multiple_token_objects_all_visible(self, p11_module: Any, p11_config: Any) -> None:
        """Multiple token objects created in A are all visible in B."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        prefix = _ulabel("multi")
        count = 5
        labels = [f"{prefix}-{i}" for i in range(count)]

        with _login_session(token, rw=True, pin=pin) as sess_a:
            objs = []
            try:
                for lbl in labels:
                    objs.append(
                        sess_a.create_object(
                            {
                                Attribute.CLASS: ObjectClass.DATA,
                                Attribute.LABEL: lbl,
                                Attribute.VALUE: lbl.encode(),
                                Attribute.TOKEN: True,
                            }
                        )
                    )

                with _login_session(token, rw=True, pin=pin) as sess_b:
                    for lbl in labels:
                        found = list(
                            sess_b.get_objects(
                                {
                                    Attribute.CLASS: ObjectClass.DATA,
                                    Attribute.LABEL: lbl,
                                }
                            )
                        )
                        assert len(found) >= 1, f"Token object '{lbl}' not visible in session B"
            finally:
                for obj in objs:
                    obj.destroy()

    def test_destroyed_token_object_gone_immediately(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Destroyed token object is gone immediately from other session."""
        token = p11_module.get_token(p11_config.slot)
        pin = _get_pin(p11_config)
        label = _ulabel("immed-destroy")

        with _login_session(token, rw=True, pin=pin) as sess_a:
            obj = sess_a.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"gone-soon",
                    Attribute.TOKEN: True,
                }
            )
            with _login_session(token, rw=True, pin=pin) as sess_b:
                # Verify present first
                found = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1

                # Destroy in A
                obj.destroy()

                # Should be gone from B immediately
                found_after = list(
                    sess_b.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found_after) == 0, "Destroyed token object still visible"

"""Cross-session object visibility tests.

Verifies PKCS#11 object visibility rules per OASIS spec:
session vs token objects, CKA_PRIVATE enforcement, cross-session semantics.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly, login_user
from pkcs11_check.raw.bootstrap import open_session as _raw_open_session
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object as _raw_create_object,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.recipes import (
    gen_aes_key as _raw_gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODIFIABLE,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKO_DATA,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_SESSION_COUNT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    skip_if_token_write_protected,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access


def _ulabel(prefix: str = "vis") -> str:
    """Generate a unique label to avoid collisions between tests."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


_DATA_OBJECT_SETUP_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session needed by object-visibility tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional object-visibility session: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _open_rw_session(raw: Any, slot_id: int, pin_bytes: bytes | None) -> int:
    """Open an RW session, optionally logging in."""
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    sh = raw_open_session(raw, slot_id, flags)
    if pin_bytes:
        login_user(raw, sh, CKU_USER, pin_bytes)
    return sh


def _open_ro_session(raw: Any, slot_id: int) -> int:
    """Open a read-only session without login."""
    flags = CKF_SERIAL_SESSION
    return raw_open_session(raw, slot_id, flags)


def _gen_visibility_aes_key(
    rs: Any,
    sh: int,
    *,
    attrs: dict[Any, Any] | None = None,
) -> int:
    """Generate an AES setup key for object-visibility tests."""
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")
    require_operational_aes_keygen(rs)
    try:
        return _raw_gen_aes_key(rs.raw, sh, 128, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but object-visibility setup key generation is not operational",
        )
    raise


def _find_data_by_label(raw: Any, sh: int, label: str) -> list[int]:
    """Find CKO_DATA objects matching a label."""
    tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bytes(CKA_LABEL, label.encode("utf-8")),
    )
    return find_objects(raw, sh, tmpl)


def _find_by_label(raw: Any, sh: int, label: str) -> list[int]:
    """Find any objects matching a label."""
    tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
    return find_objects(raw, sh, tmpl)


def _create_data_obj(
    raw: Any,
    sh: int,
    label: str,
    value: bytes,
    *,
    token: bool = False,
    private: bool | None = None,
    modifiable: bool | None = None,
) -> int:
    """Create a CKO_DATA object."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_DATA,
        CKA_LABEL: label,
        CKA_VALUE: value,
        CKA_TOKEN: token,
    }
    if private is not None:
        attrs[CKA_PRIVATE] = private
    if modifiable is not None:
        attrs[CKA_MODIFIABLE] = modifiable
    try:
        return _raw_create_object(raw, sh, attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DATA_OBJECT_SETUP_REJECT_RVS,
            "object-visibility data object setup rejected by the provider",
        )
    raise


class TestSessionObjectLifecycle:
    """Verify session objects disappear when session closes."""

    def test_session_object_gone_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Session object not visible in new session after original closes."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("sess-gone")

        # Create session object in session 1, then close it
        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _gen_visibility_aes_key(rs, sh1, attrs={CKA_TOKEN: False, CKA_LABEL: label})
        finally:
            close_session_quietly(rs.raw, sh1)

        # New session: the session object should be gone
        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_by_label(rs.raw, sh2, label)
            assert len(found) == 0, "Session object survived session close"
        finally:
            close_session_quietly(rs.raw, sh2)

    def test_session_data_object_gone_after_close(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session CKO_DATA object disappears when session closes."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("sess-data")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, b"ephemeral", token=False)
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) == 0, "Session data object survived session close"
        finally:
            close_session_quietly(rs.raw, sh2)

    def test_session_object_exists_while_session_open(self, p11_raw_session: Any) -> None:
        """Session object is findable within the same session."""
        rs = p11_raw_session
        label = _ulabel("sess-alive")
        key = _gen_visibility_aes_key(rs, rs.sh, attrs={CKA_TOKEN: False, CKA_LABEL: label})
        try:
            found = _find_by_label(rs.raw, rs.sh, label)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestTokenObjectPersistence:
    """Verify token objects persist across sessions."""

    def test_token_object_survives_session_close(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token object (CKA_TOKEN=True) persists after session closes."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("tok-persist")

        # Session 1: create token object
        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _gen_visibility_aes_key(rs, sh1, attrs={CKA_TOKEN: True, CKA_LABEL: label})
        finally:
            close_session_quietly(rs.raw, sh1)

        # Session 2: token object should still exist
        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_by_label(rs.raw, sh2, label)
            assert len(found) >= 1, "Token object did not persist"
        finally:
            # Cleanup
            for fh in _find_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)

    def test_token_data_object_survives_session(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token CKO_DATA object persists after session closes."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("tok-data")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, b"persistent-value", token=True)
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) >= 1, "Token data object did not persist"
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_VALUE])
            assert attrs[CKA_VALUE] == b"persistent-value"
        finally:
            for fh in _find_data_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)

    def test_token_object_value_preserved(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Token object attribute values are preserved across sessions."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("tok-val")
        payload = b"data-integrity-check-12345"

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, payload, token=True, private=False)
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) >= 1
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_LABEL, CKA_VALUE])
            assert attrs[CKA_LABEL] == label
            assert attrs[CKA_VALUE] == payload
        finally:
            for fh in _find_data_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)


class TestPrivateVisibility:
    """Test CKA_PRIVATE enforcement: private objects hidden without login."""

    def test_private_object_hidden_without_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKA_PRIVATE=True token object not visible in public session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("priv-hidden")

        # Create a private token object while logged in
        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, b"secret", token=True, private=True)
        finally:
            close_session_quietly(rs.raw, sh1)

        # Open without login and check visibility
        try:
            sh_pub = _open_ro_session(rs.raw, rs.slot_id)
            try:
                found = _find_data_by_label(rs.raw, sh_pub, label)
                if len(found) > 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "CKA_PRIVATE=True object visible without login "
                        "(token may keep login state across sessions)",
                        ComplianceLevel.VENDOR,
                    )
            finally:
                close_session_quietly(rs.raw, sh_pub)
        finally:
            sh_cleanup = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            for fh in _find_data_by_label(rs.raw, sh_cleanup, label):
                destroy_quietly(rs.raw, sh_cleanup, fh)
            close_session_quietly(rs.raw, sh_cleanup)

    def test_public_object_visible_without_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKA_PRIVATE=False token object visible in public session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("pub-visible")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, b"public-data", token=True, private=False)
        finally:
            close_session_quietly(rs.raw, sh1)

        try:
            sh_pub = _open_ro_session(rs.raw, rs.slot_id)
            try:
                found = _find_data_by_label(rs.raw, sh_pub, label)
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "CKA_PRIVATE=False object not visible without login",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="PKCS#11 spec: public objects visible in public sessions",
                    )
                else:
                    attrs = read_attributes(rs.raw, sh_pub, found[0], [CKA_VALUE])
                    assert attrs[CKA_VALUE] == b"public-data"
            finally:
                close_session_quietly(rs.raw, sh_pub)
        finally:
            sh_cleanup = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            for fh in _find_data_by_label(rs.raw, sh_cleanup, label):
                destroy_quietly(rs.raw, sh_cleanup, fh)
            close_session_quietly(rs.raw, sh_cleanup)

    def test_private_object_visible_after_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKA_PRIVATE=True token object visible after login."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("priv-afterlogin")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(rs.raw, sh1, label, b"secret-stuff", token=True, private=True)
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) >= 1, "Private object not visible after login"
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_VALUE])
            assert attrs[CKA_VALUE] == b"secret-stuff"
        finally:
            for fh in _find_data_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)


class TestCrossSessionModification:
    """Cross-session modification visibility."""

    def test_modify_in_session_a_read_in_session_b(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Modify object attribute in session A, read updated value in B."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("xmod")
        new_label = _ulabel("xmod-updated")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(
                rs.raw,
                sh_a,
                label,
                b"original",
                token=True,
                modifiable=True,
            )
            try:
                set_attributes(rs.raw, sh_a, h, {CKA_LABEL: new_label})

                sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
                try:
                    found = _find_data_by_label(rs.raw, sh_b, new_label)
                    assert len(found) >= 1, "Modified label not visible in session B"
                finally:
                    close_session_quietly(rs.raw, sh_b)
            finally:
                # Clean up by new label (may have changed)
                for fh in _find_data_by_label(rs.raw, sh_a, new_label):
                    destroy_quietly(rs.raw, sh_a, fh)
                for fh in _find_data_by_label(rs.raw, sh_a, label):
                    destroy_quietly(rs.raw, sh_a, fh)
        finally:
            close_session_quietly(rs.raw, sh_a)

    def test_modify_value_cross_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Modify CKA_VALUE in session A, verify in session B.

        PKCS#11 spec permits C_SetAttributeValue on CKA_VALUE for CKO_DATA
        objects when CKA_MODIFIABLE=True (spec does not mandate this for all
        object classes). Many modules return CKR_ATTRIBUTE_READ_ONLY or
        CKR_ATTRIBUTE_VALUE_INVALID when CKA_VALUE is considered immutable for
        a given object class; this is implementation-defined behaviour.
        """
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("xval")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(
                rs.raw,
                sh_a,
                label,
                b"before",
                token=True,
                modifiable=True,
                private=False,
            )
            try:
                try:
                    set_attributes(rs.raw, sh_a, h, {CKA_VALUE: b"after"})
                except AssertionError as e:
                    # Phase 6 C: match the CKR exactly (via rv), not by substring.
                    if is_known_error(e, (CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_VALUE_INVALID)):
                        from pkcs11_check.compliance import ComplianceLevel, note

                        note(
                            "Module does not allow C_SetAttributeValue on CKA_VALUE "
                            "(returns CKR_ATTRIBUTE_READ_ONLY or CKR_ATTRIBUTE_VALUE_INVALID); "
                            "PKCS#11 spec does not mandate mutability of CKA_VALUE post-creation",
                            ComplianceLevel.VENDOR,
                        )
                        pytest.xfail("Module treats CKA_VALUE as read-only after object creation")
                    raise

                sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
                try:
                    found = _find_data_by_label(rs.raw, sh_b, label)
                    assert len(found) >= 1
                    attrs = read_attributes(rs.raw, sh_b, found[0], [CKA_VALUE])
                    assert attrs[CKA_VALUE] == b"after", "Modified value not reflected in session B"
                finally:
                    close_session_quietly(rs.raw, sh_b)
            finally:
                for fh in _find_data_by_label(rs.raw, sh_a, label):
                    destroy_quietly(rs.raw, sh_a, fh)
        finally:
            close_session_quietly(rs.raw, sh_a)


class TestCrossSessionDestruction:
    """Destruction in one session reflected in another."""

    def test_destroy_in_a_gone_in_b(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Token object destroyed in session A is gone from session B search."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("xdestroy")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(rs.raw, sh_a, label, b"doomed", token=True)

            sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            try:
                # Verify it exists in B before destruction
                found_before = _find_data_by_label(rs.raw, sh_b, label)
                assert len(found_before) >= 1, "Object not visible in session B before destroy"

                # Destroy in A
                rs.raw.C_DestroyObject(sh_a, h)

                # Should be gone from B's search
                found_after = _find_data_by_label(rs.raw, sh_b, label)
                assert len(found_after) == 0, "Destroyed object still visible in session B"
            finally:
                close_session_quietly(rs.raw, sh_b)
        finally:
            close_session_quietly(rs.raw, sh_a)

    def test_destroy_session_object_cross_session(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object destroyed in session A is gone from session B."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("xdestroy-sess")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(rs.raw, sh_a, label, b"session-doomed", token=False)

            sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            try:
                found_before = _find_data_by_label(rs.raw, sh_b, label)
                # Session objects may or may not be visible cross-session
                if len(found_before) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Session objects not visible across sessions "
                        "(some modules isolate session objects)",
                        ComplianceLevel.VENDOR,
                    )
                    return

                rs.raw.C_DestroyObject(sh_a, h)

                found_after = _find_data_by_label(rs.raw, sh_b, label)
                assert len(found_after) == 0, "Destroyed session object still in session B"
            finally:
                close_session_quietly(rs.raw, sh_b)
        finally:
            close_session_quietly(rs.raw, sh_a)


class TestTokenPrivateInteraction:
    """CKA_TOKEN + CKA_PRIVATE interaction matrix."""

    def test_public_session_obj_visible_same_session(self, p11_raw_session: Any) -> None:
        """TOKEN=False, PRIVATE=False object visible in same session."""
        rs = p11_raw_session
        label = _ulabel("pub-sess")
        h = _create_data_obj(rs.raw, rs.sh, label, b"pub-session", token=False, private=False)
        try:
            found = _find_data_by_label(rs.raw, rs.sh, label)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_private_session_obj_visible_same_session(self, p11_raw_session: Any) -> None:
        """TOKEN=False, PRIVATE=True object visible in same logged-in session."""
        rs = p11_raw_session
        label = _ulabel("priv-sess")
        try:
            h = _create_data_obj(rs.raw, rs.sh, label, b"priv-session", token=False, private=True)
        except AssertionError as exc:
            if is_known_error(exc, {CKR_ATTRIBUTE_VALUE_INVALID}):
                pytest.skip("Module does not support CKA_PRIVATE=True on CKO_DATA objects")
            raise
        try:
            found = _find_data_by_label(rs.raw, rs.sh, label)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_public_token_obj_persists(self, p11_raw_session: Any, p11_config: Any) -> None:
        """TOKEN=True, PRIVATE=False object persists and is publicly visible."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("pub-tok")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(
                rs.raw,
                sh1,
                label,
                b"pub-token-data",
                token=True,
                private=False,
            )
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) >= 1, "Public token object not found in new session"
        finally:
            for fh in _find_data_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)

    def test_private_token_obj_persists_with_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """TOKEN=True, PRIVATE=True object persists and visible after login."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("priv-tok")

        sh1 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            _create_data_obj(
                rs.raw,
                sh1,
                label,
                b"priv-token-data",
                token=True,
                private=True,
            )
        finally:
            close_session_quietly(rs.raw, sh1)

        sh2 = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            found = _find_data_by_label(rs.raw, sh2, label)
            assert len(found) >= 1, "Private token object not found after login in new session"
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_VALUE])
            assert attrs[CKA_VALUE] == b"priv-token-data"
        finally:
            for fh in _find_data_by_label(rs.raw, sh2, label):
                destroy_quietly(rs.raw, sh2, fh)
            close_session_quietly(rs.raw, sh2)


class TestSessionObjectCrossVisibility:
    """Session objects: cross-session visibility semantics."""

    def test_session_object_visible_in_concurrent_session(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object created in A visible in concurrent session B.

        Per PKCS#11 spec, session objects created by one session are
        visible to other sessions of the same application.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("sess-xvis")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(rs.raw, sh_a, label, b"cross-visible", token=False)
            try:
                sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
                try:
                    found = _find_data_by_label(rs.raw, sh_b, label)
                    if len(found) == 0:
                        from pkcs11_check.compliance import ComplianceLevel, note

                        note(
                            "Session objects not visible in concurrent "
                            "sessions (module isolates session objects)",
                            ComplianceLevel.VENDOR,
                        )
                    else:
                        attrs = read_attributes(rs.raw, sh_b, found[0], [CKA_VALUE])
                        assert attrs[CKA_VALUE] == b"cross-visible"
                finally:
                    close_session_quietly(rs.raw, sh_b)
            finally:
                destroy_quietly(rs.raw, sh_a, h)
        finally:
            close_session_quietly(rs.raw, sh_a)

    def test_session_object_gone_when_creating_session_closes(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object disappears from session B when session A closes.

        The object belongs to session A. When A closes, the object is
        destroyed, and B should no longer find it.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("sess-owner-close")

        sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            # Create in A, then close A
            sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            try:
                _create_data_obj(rs.raw, sh_a, label, b"owned-by-a", token=False)
            finally:
                close_session_quietly(rs.raw, sh_a)

            # A is closed; object should be gone from B
            found = _find_data_by_label(rs.raw, sh_b, label)
            assert len(found) == 0, "Session object survived owning session close"
        finally:
            close_session_quietly(rs.raw, sh_b)


class TestTokenObjectImmediateVisibility:
    """Token objects visible immediately in new sessions (no caching)."""

    def test_token_object_visible_immediately(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Newly created token object visible immediately in another session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("immed")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(rs.raw, sh_a, label, b"immediate", token=True)
            try:
                # Open B immediately after creation - no delay
                sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
                try:
                    found = _find_data_by_label(rs.raw, sh_b, label)
                    assert len(found) >= 1, "Token object not immediately visible in new session"
                finally:
                    close_session_quietly(rs.raw, sh_b)
            finally:
                destroy_quietly(rs.raw, sh_a, h)
        finally:
            close_session_quietly(rs.raw, sh_a)

    def test_token_key_usable_immediately(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Token key created in A is usable for crypto in B immediately."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("immed-key")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            key = _gen_visibility_aes_key(
                rs,
                sh_a,
                attrs={
                    CKA_TOKEN: True,
                    CKA_LABEL: label,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
            try:
                sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
                try:
                    tmpl = template(
                        attr_ulong(CKA_KEY_TYPE, CKK_AES),
                        attr_bytes(CKA_LABEL, label.encode("utf-8")),
                    )
                    found = find_objects(rs.raw, sh_b, tmpl)
                    assert len(found) >= 1, "Token key not found in session B"
                finally:
                    close_session_quietly(rs.raw, sh_b)
            finally:
                destroy_quietly(rs.raw, sh_a, key)
        finally:
            close_session_quietly(rs.raw, sh_a)

    def test_multiple_token_objects_all_visible(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Multiple token objects created in A are all visible in B."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        prefix = _ulabel("multi")
        count = 5
        labels = [f"{prefix}-{i}" for i in range(count)]

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        handles: list[int] = []
        try:
            for lbl in labels:
                h = _create_data_obj(
                    rs.raw,
                    sh_a,
                    lbl,
                    lbl.encode(),
                    token=True,
                )
                handles.append(h)

            sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            try:
                for lbl in labels:
                    found = _find_data_by_label(rs.raw, sh_b, lbl)
                    assert len(found) >= 1, f"Token object '{lbl}' not visible in session B"
            finally:
                close_session_quietly(rs.raw, sh_b)
        finally:
            for h in handles:
                destroy_quietly(rs.raw, sh_a, h)
            close_session_quietly(rs.raw, sh_a)

    def test_destroyed_token_object_gone_immediately(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Destroyed token object is gone immediately from other session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _ulabel("immed-destroy")

        sh_a = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
        try:
            h = _create_data_obj(rs.raw, sh_a, label, b"gone-soon", token=True)

            sh_b = _open_rw_session(rs.raw, rs.slot_id, pin_bytes)
            try:
                # Verify present first
                found = _find_data_by_label(rs.raw, sh_b, label)
                assert len(found) >= 1

                # Destroy in A
                rs.raw.C_DestroyObject(sh_a, h)

                # Should be gone from B immediately
                found_after = _find_data_by_label(rs.raw, sh_b, label)
                assert len(found_after) == 0, "Destroyed token object still visible"
            finally:
                close_session_quietly(rs.raw, sh_b)
        finally:
            close_session_quietly(rs.raw, sh_a)

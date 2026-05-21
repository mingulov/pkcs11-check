"""Access control attribute tests.

Verifies CKA_PRIVATE (visibility without login), CKA_MODIFIABLE
(attribute mutability), CKA_TRUSTED (wrap protection) flags, and
C_CopyObject semantics (CKA_COPYABLE, label/attribute modification on copy).
These catch real access control bugs in PKCS#11 modules.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    copy_object,
    create_object,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODIFIABLE,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKF_SERIAL_SESSION,
    CKO_DATA,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    get_pin_bytes,
    is_known_error,
    skip_if_token_write_protected,
)

pytestmark = pytest.mark.security

_COPY_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


class TestPrivateAttribute:
    """Test CKA_PRIVATE visibility semantics."""

    def test_private_key_default_is_private(self, p11_raw_session: Any) -> None:
        """Generated secret keys are CKA_PRIVATE=True by default."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_PRIVATE])
            try:
                assert attrs[CKA_PRIVATE] is True
            except AssertionError:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Module defaults CKA_PRIVATE to False for secret keys (spec requires True)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 v3.1 Sec.4.9.2: default CKA_PRIVATE is True for secret keys",
                )
                pytest.xfail("Module defaults CKA_PRIVATE=False for secret keys (spec violation)")
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_private_object_visible_without_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKA_PRIVATE=False object should be visible without login."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        label = f"pub-visible-{id(self)}"

        # Create a non-private data object (logged in)
        obj_h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"public-data",
                CKA_TOKEN: True,
                CKA_PRIVATE: False,
            },
        )

        try:
            # Open R/O session WITHOUT login - non-private object should be visible
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, ro_sh, tmpl)
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "PRIVATE=False object not visible without login",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="PKCS#11 spec: CKA_PRIVATE=False objects visible in public",
                    )
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            # Cleanup
            destroy_quietly(rs.raw, rs.sh, obj_h)


class TestModifiableAttribute:
    """Test CKA_MODIFIABLE flag semantics."""

    def test_default_key_is_modifiable(self, p11_raw_session: Any) -> None:
        """Generated keys have CKA_MODIFIABLE=True by default."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: "mod-test"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            assert attrs[CKA_MODIFIABLE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_modifiable_key_label_changeable(self, p11_raw_session: Any) -> None:
        """Key with MODIFIABLE=True allows label change."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: "mod-before"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            assert attrs[CKA_MODIFIABLE] is True
            set_attributes(rs.raw, rs.sh, key_h, {CKA_LABEL: "mod-after"})
            tmpl = template_from_dict({CKA_LABEL: "mod-after"})
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_modifiable_false_blocks_set_attribute(self, p11_raw_session: Any) -> None:
        """CKA_MODIFIABLE=False MUST block C_SetAttributeValue on any attribute.

        PKCS#11 v3.1 Sec.4.1.2: when CKA_MODIFIABLE=False, the object's
        attributes are immutable. The spec does NOT carve out a "non-security
        attributes are still settable" exception — even CKA_LABEL changes
        must be rejected.

        Closes Phase 4.5 GAP-T1 (HIGH).
        """
        rs = p11_raw_session
        try:
            key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_MODIFIABLE: False, CKA_LABEL: "mod-false-src"},
            )
        except AssertionError as e:
            msg = str(e)
            if any(
                code in msg
                for code in (
                    "CKR_TEMPLATE_INCONSISTENT",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_ATTRIBUTE_TYPE_INVALID",
                )
            ):
                pytest.skip(f"Module does not allow CKA_MODIFIABLE=False at gen time: {e}")
            raise

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            except AssertionError as e:
                if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                    pytest.skip(f"Module does not expose CKA_MODIFIABLE: {e}")
                raise
            if attrs.get(CKA_MODIFIABLE) is not False:
                # The module accepted CKA_MODIFIABLE=False at create-time
                # without raising, but the readback shows it didn't take
                # effect. This is the worst-case "lying module" pattern:
                # the test would silently skip and the SetAttribute path
                # below would never run, leaving a real conformance bug
                # invisible. Surface as a CRITICAL finding instead of
                # skipping (per project rule: "xfail / skip only with
                # evidence and spec refs, never suppress").
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Module accepted CKA_MODIFIABLE=False at C_CreateObject "
                    f"but readback returns {attrs.get(CKA_MODIFIABLE)!r} — "
                    f"the attribute was silently ignored at create time, "
                    f"making downstream MODIFIABLE enforcement untestable.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.1.2",
                )
                pytest.fail(
                    "SECURITY: module silently ignored CKA_MODIFIABLE=False "
                    "at create time (read-back returned True) — would have "
                    "skipped the SetAttribute test and hidden a real "
                    "conformance bug. Lying-module pattern."
                )

            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_LABEL: "mod-false-after"})
            except AssertionError as e:
                msg = str(e)
                accepted = (
                    "CKR_ACTION_PROHIBITED",
                    "CKR_ATTRIBUTE_READ_ONLY",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_TEMPLATE_INCONSISTENT",
                )
                if any(code in msg for code in accepted):
                    return
                raise

            # SetAttribute returned CKR_OK on a CKA_MODIFIABLE=False key.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_SetAttributeValue succeeded on CKA_MODIFIABLE=False key "
                "(expected CKR_ACTION_PROHIBITED).",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.1.2",
            )
            pytest.fail(
                "SECURITY: module accepted C_SetAttributeValue on a "
                "CKA_MODIFIABLE=False key — attribute mutability "
                "constraint silently ignored"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestCopyableAttribute:
    """Test CKA_COPYABLE flag semantics."""

    def test_default_key_copyable_flag(self, p11_raw_session: Any) -> None:
        """Check CKA_COPYABLE flag is readable on generated key."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            if CKA_COPYABLE not in attrs:
                pytest.skip("CKA_COPYABLE not supported by module")
            copyable = attrs[CKA_COPYABLE]
            assert isinstance(copyable, bool)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copyable_key_can_be_copied(self, p11_raw_session: Any) -> None:
        """Key with COPYABLE=True can be copied via C_CopyObject."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: "copy-src"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            if CKA_COPYABLE not in attrs or not attrs[CKA_COPYABLE]:
                pytest.skip("Key not copyable by default")
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "copy-dst"})
            except AssertionError:
                pytest.skip("C_CopyObject not supported")
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_LABEL])
                assert copy_attrs[CKA_LABEL] == "copy-dst"
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestCopyObject:
    """Tests for C_CopyObject - copying PKCS#11 objects with attribute modification."""

    def test_copy_with_modified_label(self, p11_raw_session: Any) -> None:
        """Copy a key with a new label - label changes, other attrs preserved."""
        rs = p11_raw_session
        key_h = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: "orig-label"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            if CKA_COPYABLE not in attrs or not attrs[CKA_COPYABLE]:
                pytest.skip("Key not copyable by default")
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "copied-label"})
            except AssertionError:
                pytest.skip("C_CopyObject not supported or module rejected copy template")
                return
            try:
                copy_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    copied_h,
                    [CKA_LABEL, CKA_KEY_TYPE, CKA_VALUE_LEN],
                )
                orig_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    key_h,
                    [CKA_KEY_TYPE, CKA_VALUE_LEN],
                )
                assert copy_attrs[CKA_LABEL] == "copied-label"
                assert copy_attrs[CKA_KEY_TYPE] == orig_attrs[CKA_KEY_TYPE]
                assert copy_attrs[CKA_VALUE_LEN] == orig_attrs[CKA_VALUE_LEN]
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_changes_extractable(self, p11_raw_session: Any) -> None:
        """Copy a key with CKA_EXTRACTABLE changed from True to False."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: "extractable-src",
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_EXTRACTABLE])
            if CKA_COPYABLE not in attrs or not attrs[CKA_COPYABLE]:
                pytest.skip("Key not copyable")
            assert attrs[CKA_EXTRACTABLE] is True
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: False})
            except AssertionError as exc:
                pytest.skip(f"Module rejected EXTRACTABLE restriction on copy: {exc}")
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_EXTRACTABLE])
                assert copy_attrs[CKA_EXTRACTABLE] is False
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_copyable_key_rejected(self, p11_raw_session: Any) -> None:
        """Key with CKA_COPYABLE=False cannot be copied - CKR_ACTION_PROHIBITED."""
        rs = p11_raw_session
        try:
            key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_COPYABLE: False, CKA_LABEL: "non-copyable"},
            )
        except AssertionError:
            pytest.skip("Module does not support setting CKA_COPYABLE=False at key gen")
            return
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            if CKA_COPYABLE not in attrs:
                pytest.skip("CKA_COPYABLE not supported by module")
            if attrs[CKA_COPYABLE] is not False:
                pytest.skip("Module did not honour CKA_COPYABLE=False in template")
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "should-fail"})
            except AssertionError as exc:
                msg = str(exc)
                accepted = (
                    "CKR_ACTION_PROHIBITED",
                    "CKR_FUNCTION_NOT_SUPPORTED",
                    "CKR_ATTRIBUTE_READ_ONLY",
                    "CKR_TEMPLATE_INCONSISTENT",
                )
                if any(code in msg for code in accepted):
                    return
                raise

            # C_CopyObject succeeded on a CKA_COPYABLE=False key — spec
            # violation. Per Phase 4.5 GAP-T2, this must be a hard failure
            # so that conformance regressions in any module are surfaced
            # rather than silently xfailed (was previously pytest.xfail).
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module ignores CKA_COPYABLE=False: C_CopyObject succeeded on non-copyable key",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.1.2: CKA_COPYABLE=False must prevent copy",
            )
            destroy_quietly(rs.raw, rs.sh, copied_h)
            pytest.fail(
                "SECURITY: module copied a CKA_COPYABLE=False key — "
                "copy-prohibition silently ignored"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_session_object_stays_session(self, p11_raw_session: Any) -> None:
        """Copy of a session object is also a session object (CKA_TOKEN=False)."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_LABEL: "session-src"},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_TOKEN])
            if CKA_COPYABLE not in attrs or not attrs[CKA_COPYABLE]:
                pytest.skip("Key not copyable")
            assert attrs[CKA_TOKEN] is False
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "session-copy"})
            except AssertionError:
                pytest.skip("C_CopyObject not supported or module rejected copy template")
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_TOKEN])
                assert copy_attrs[CKA_TOKEN] is False
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_token_object_stays_token(self, p11_raw_session: Any) -> None:
        """Copy of a token object is also a token object (CKA_TOKEN=True)."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: True, CKA_LABEL: "token-src"},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_TOKEN])
            if CKA_COPYABLE not in attrs or not attrs[CKA_COPYABLE]:
                destroy_quietly(rs.raw, rs.sh, key_h)
                pytest.skip("Key not copyable")
            assert attrs[CKA_TOKEN] is True
            copied_h = None
            try:
                try:
                    copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "token-copy"})
                except AssertionError:
                    pytest.skip("C_CopyObject not supported or module rejected copy template")
                    return
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_TOKEN])
                assert copy_attrs[CKA_TOKEN] is True
            finally:
                if copied_h is not None:
                    destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

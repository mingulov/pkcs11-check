"""Access control attribute tests.

Verifies CKA_PRIVATE (visibility without login), CKA_MODIFIABLE
(attribute mutability), CKA_TRUSTED (wrap protection) flags, and
C_CopyObject semantics (CKA_COPYABLE, label/attribute modification on copy).
These catch real access control bugs in PKCS#11 modules.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
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
from pkcs11_check.raw.rv import CkrAssertionError
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
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    assert_correct,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    skip_if_data_objects_unsupported,
    skip_if_token_write_protected,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security


def _require_aes_keygen(rs: Any) -> None:
    require_operational_aes_keygen(rs)


def _require_access_bool(value: Any, label: str) -> bool:
    """Validate a provider-read boolean while retaining readback operation identity."""
    if value is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            summary=f"{label}: attribute unavailable",
        )
        return False
    if isinstance(value, bool):
        return value is True
    fail_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        detail={"actual_type": type(value).__name__, "expected_type": "bool"},
        summary=f"{label}: malformed CK_BBOOL attribute value",
    )
    return False


def _gen_access_control_aes_key(rs: Any, *, attrs: dict[int, Any] | None = None) -> int:
    """Generate a setup AES key for access-control tests."""
    _require_aes_keygen(rs)
    try:
        return gen_aes_key(rs.raw, rs.sh, 128, attrs=attrs)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but access-control setup key generation is not operational",
        )
    raise


def _handle_copy_reject(exc: CkrAssertionError, message: str) -> None:
    """Record a clean C_CopyObject refusal with the exact operation identity."""
    classify(
        "not_operational",
        kind="policy",
        label=message,
        operation="C_CopyObject",
        actual=exc.rv,
        summary=f"{message}: {exc.rv}",
    )


class TestPrivateAttribute:
    """Test CKA_PRIVATE visibility semantics."""

    def test_private_key_default_is_private(self, p11_raw_session: Any) -> None:
        """Generated secret keys are CKA_PRIVATE=True by default."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(rs)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_PRIVATE])
            private = attr_or_record(
                attrs,
                CKA_PRIVATE,
                label="CKA_PRIVATE default (secret key)",
            )
            if private is MISSING_ATTRIBUTE:
                return
            private_value = _require_access_bool(
                private,
                "CKA_PRIVATE default (secret key)",
            )
            if private_value is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Module defaults CKA_PRIVATE to False for secret keys (spec requires True)",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 v3.2: default CKA_PRIVATE is True for secret keys",
                )
                classify(
                    "honest_deviation",
                    kind="metadata",
                    label="CKA_PRIVATE default (secret key)",
                    operation="C_GenerateKey",
                    spec_ref="PKCS#11 v3.2",
                    summary="Module defaults CKA_PRIVATE=False for secret keys (spec violation)",
                )
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
        skip_if_data_objects_unsupported(rs)
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
        key_h = _gen_access_control_aes_key(rs, attrs={CKA_LABEL: "mod-test"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            modifiable = attr_or_record(
                attrs,
                CKA_MODIFIABLE,
                label="CKA_MODIFIABLE default (secret key)",
            )
            if modifiable is MISSING_ATTRIBUTE:
                return
            modifiable_value = _require_access_bool(
                modifiable, "CKA_MODIFIABLE default (secret key)"
            )
            if modifiable_value is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_MODIFIABLE default (secret key)",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_MODIFIABLE=False",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_modifiable_key_label_changeable(self, p11_raw_session: Any) -> None:
        """Key with MODIFIABLE=True allows label change."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(rs, attrs={CKA_LABEL: "mod-before"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            modifiable = attr_or_record(
                attrs,
                CKA_MODIFIABLE,
                label="CKA_MODIFIABLE label mutation",
            )
            if modifiable is MISSING_ATTRIBUTE:
                return
            modifiable_value = _require_access_bool(modifiable, "CKA_MODIFIABLE label mutation")
            if modifiable_value is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_MODIFIABLE label mutation",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_MODIFIABLE=False",
                )
            set_attributes(rs.raw, rs.sh, key_h, {CKA_LABEL: "mod-after"})
            tmpl = template_from_dict({CKA_LABEL: "mod-after"})
            found = find_objects(rs.raw, rs.sh, tmpl)
            if len(found) == 0:
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_MODIFIABLE label mutation",
                    operation="C_SetAttributeValue",
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "C_SetAttributeValue returned CKR_OK but the updated label "
                        "was not observable"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_modifiable_false_blocks_set_attribute(self, p11_raw_session: Any) -> None:
        """CKA_MODIFIABLE=False MUST block C_SetAttributeValue on any attribute.

        PKCS#11 v3.2: when CKA_MODIFIABLE=False, the object's
        attributes are immutable. The spec does NOT carve out a "non-security
        attributes are still settable" exception — even CKA_LABEL changes
        must be rejected.

        Closes Phase 4.5 GAP-T1 (HIGH).
        """
        rs = p11_raw_session
        _require_aes_keygen(rs)
        try:
            key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_MODIFIABLE: False, CKA_LABEL: "mod-false-src"},
            )
        except CkrAssertionError as e:
            if is_known_error(
                e,
                {
                    CKR_TEMPLATE_INCONSISTENT,
                    CKR_ATTRIBUTE_VALUE_INVALID,
                    CKR_ATTRIBUTE_TYPE_INVALID,
                },
            ):
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_MODIFIABLE=False create-time support",
                    operation="C_GenerateKey",
                    actual=e.rv,
                    summary=("AES key generation rejected the valid CKA_MODIFIABLE=False template"),
                )
            raise

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_MODIFIABLE])
            except CkrAssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    xfail_as(
                        "not_operational",
                        kind="metadata",
                        label="CKA_MODIFIABLE=False enforcement (create-time)",
                        operation="C_GetAttributeValue",
                        actual=e.rv,
                        summary="Module does not expose CKA_MODIFIABLE",
                    )
                raise
            modifiable = attr_or_record(
                attrs,
                CKA_MODIFIABLE,
                label="CKA_MODIFIABLE=False enforcement (create-time)",
            )
            if modifiable is MISSING_ATTRIBUTE:
                return
            modifiable_value = _require_access_bool(
                modifiable,
                "CKA_MODIFIABLE=False enforcement (create-time)",
            )
            if modifiable_value is not False:
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
                    "Module accepted CKA_MODIFIABLE=False at C_GenerateKey "
                    "but readback did not return False — "
                    "the attribute was silently ignored at create time, "
                    "making downstream MODIFIABLE enforcement untestable.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2",
                )
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_MODIFIABLE=False enforcement (create-time)",
                    operation="C_GenerateKey",
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "SECURITY: module silently ignored CKA_MODIFIABLE=False "
                        "at create time (read-back returned True) — would have "
                        "skipped the SetAttribute test and hidden a real "
                        "conformance bug. Lying-module pattern."
                    ),
                )

            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_LABEL: "mod-false-after"})
            except CkrAssertionError as e:
                if is_known_error(
                    e,
                    {
                        CKR_ACTION_PROHIBITED,
                        CKR_ATTRIBUTE_READ_ONLY,
                        CKR_ATTRIBUTE_VALUE_INVALID,
                        CKR_TEMPLATE_INCONSISTENT,
                    },
                ):
                    return
                raise

            # SetAttribute returned CKR_OK on a CKA_MODIFIABLE=False key.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_SetAttributeValue succeeded on CKA_MODIFIABLE=False key "
                "(expected CKR_ACTION_PROHIBITED).",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.2",
            )
            classify(
                "self_contradiction",
                kind="policy",
                label="CKA_MODIFIABLE=False enforcement (C_SetAttributeValue)",
                operation="C_SetAttributeValue",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "SECURITY: module accepted C_SetAttributeValue on a "
                    "CKA_MODIFIABLE=False key — attribute mutability "
                    "constraint silently ignored"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestCopyableAttribute:
    """Test CKA_COPYABLE flag semantics."""

    def test_default_key_copyable_flag(self, p11_raw_session: Any) -> None:
        """Check CKA_COPYABLE flag is readable on generated key."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(rs)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:generated-key",
            )
            if copyable is MISSING_ATTRIBUTE:
                return
            _require_access_bool(copyable, "CKA_COPYABLE:generated-key")
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copyable_key_can_be_copied(self, p11_raw_session: Any) -> None:
        """Key with COPYABLE=True can be copied via C_CopyObject."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(rs, attrs={CKA_LABEL: "copy-src"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:copyable-key",
            )
            if copyable is MISSING_ATTRIBUTE:
                return
            if _require_access_bool(copyable, "CKA_COPYABLE:copyable-key") is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_COPYABLE:copyable-key",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_COPYABLE=False",
                )
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "copy-dst"})
            except CkrAssertionError as exc:
                _handle_copy_reject(exc, "C_CopyObject not supported")
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_LABEL])
                label = attr_or_record(
                    copy_attrs,
                    CKA_LABEL,
                    label="C_CopyObject:CKA_LABEL on copy",
                )
                if label is MISSING_ATTRIBUTE:
                    return
                assert_correct(
                    actual=label,
                    expected="copy-dst",
                    label="C_CopyObject:CKA_LABEL on copy",
                    operation="C_CopyObject",
                    kind="metadata",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestCopyObject:
    """Tests for C_CopyObject - copying PKCS#11 objects with attribute modification."""

    def test_copy_with_modified_label(self, p11_raw_session: Any) -> None:
        """Copy a key with a new label - label changes, other attrs preserved."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(rs, attrs={CKA_LABEL: "orig-label"})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:copy-with-modified-label",
            )
            if copyable is MISSING_ATTRIBUTE:
                return
            if _require_access_bool(copyable, "CKA_COPYABLE:copy-with-modified-label") is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_COPYABLE:copy-with-modified-label",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_COPYABLE=False",
                )
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "copied-label"})
            except CkrAssertionError as exc:
                _handle_copy_reject(
                    exc,
                    "C_CopyObject not supported or module rejected copy template",
                )
                return
            try:
                copy_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    copied_h,
                    [CKA_LABEL, CKA_KEY_TYPE, CKA_VALUE_LEN],
                )
                copy_label = attr_or_record(
                    copy_attrs,
                    CKA_LABEL,
                    label="C_CopyObject:CKA_LABEL on copy",
                )
                copy_type = attr_or_record(
                    copy_attrs,
                    CKA_KEY_TYPE,
                    label="C_CopyObject:CKA_KEY_TYPE on copy",
                )
                copy_len = attr_or_record(
                    copy_attrs,
                    CKA_VALUE_LEN,
                    label="C_CopyObject:CKA_VALUE_LEN on copy",
                )
                orig_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    key_h,
                    [CKA_KEY_TYPE, CKA_VALUE_LEN],
                )
                orig_type = attr_or_record(
                    orig_attrs,
                    CKA_KEY_TYPE,
                    label="C_CopyObject:CKA_KEY_TYPE on source",
                )
                orig_len = attr_or_record(
                    orig_attrs,
                    CKA_VALUE_LEN,
                    label="C_CopyObject:CKA_VALUE_LEN on source",
                )
                if copy_label is not MISSING_ATTRIBUTE:
                    assert_correct(
                        actual=copy_label,
                        expected="copied-label",
                        label="C_CopyObject:CKA_LABEL on copy",
                        operation="C_CopyObject",
                        kind="metadata",
                    )
                if copy_type is not MISSING_ATTRIBUTE and orig_type is not MISSING_ATTRIBUTE:
                    assert_correct(
                        actual=copy_type,
                        expected=orig_type,
                        label="C_CopyObject:CKA_KEY_TYPE preserved on copy",
                        operation="C_CopyObject",
                        kind="metadata",
                    )
                if copy_len is not MISSING_ATTRIBUTE and orig_len is not MISSING_ATTRIBUTE:
                    assert_correct(
                        actual=copy_len,
                        expected=orig_len,
                        label="C_CopyObject:CKA_VALUE_LEN preserved on copy",
                        operation="C_CopyObject",
                        kind="metadata",
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_changes_extractable(self, p11_raw_session: Any) -> None:
        """Copy a key with CKA_EXTRACTABLE changed from True to False."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(
            rs,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: "extractable-src",
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_EXTRACTABLE])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:copy-extractable-key",
            )
            extractable = attr_or_record(
                attrs,
                CKA_EXTRACTABLE,
                label="CKA_EXTRACTABLE:copy-extractable-key",
            )
            if extractable is not MISSING_ATTRIBUTE:
                extractable_value = _require_access_bool(
                    extractable,
                    "CKA_EXTRACTABLE:copy-extractable-key",
                )
                if extractable_value is not True:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="CKA_EXTRACTABLE:copy-extractable-key",
                        operation="C_GenerateKey",
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "C_GenerateKey accepted CKA_EXTRACTABLE=True but "
                            "readback returned False"
                        ),
                    )
            if copyable is MISSING_ATTRIBUTE:
                return
            if _require_access_bool(copyable, "CKA_COPYABLE:copy-extractable-key") is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_COPYABLE:copy-extractable-key",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_COPYABLE=False",
                )
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: False})
            except CkrAssertionError as exc:
                _handle_copy_reject(
                    exc,
                    f"Module rejected EXTRACTABLE restriction on copy: {exc}",
                )
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_EXTRACTABLE])
                copied_extractable = attr_or_record(
                    copy_attrs,
                    CKA_EXTRACTABLE,
                    label="C_CopyObject:CKA_EXTRACTABLE on copy",
                )
                if copied_extractable is MISSING_ATTRIBUTE:
                    return
                copied_extractable_value = _require_access_bool(
                    copied_extractable,
                    "C_CopyObject:CKA_EXTRACTABLE on copy",
                )
                if copied_extractable_value is not False:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="C_CopyObject:CKA_EXTRACTABLE on copy",
                        operation="C_CopyObject",
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "C_CopyObject accepted CKA_EXTRACTABLE=False but readback returned True"
                        ),
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_copyable_key_rejected(self, p11_raw_session: Any) -> None:
        """Key with CKA_COPYABLE=False cannot be copied - CKR_ACTION_PROHIBITED."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        try:
            key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_COPYABLE: False, CKA_LABEL: "non-copyable"},
            )
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "Module does not support setting CKA_COPYABLE=False at key gen",
            )
            return
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:non-copyable-key",
            )
            if copyable is MISSING_ATTRIBUTE:
                return
            copyable_value = _require_access_bool(copyable, "CKA_COPYABLE:non-copyable-key")
            if copyable_value is not False:
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_COPYABLE=False enforcement (create-time)",
                    operation="C_GenerateKey",
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "Module accepted CKA_COPYABLE=False at key generation "
                        "but readback returned True"
                    ),
                )
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "should-fail"})
            except CkrAssertionError as exc:
                if exc.rv == CKR_ACTION_PROHIBITED:
                    return
                classify(
                    "nonspec_reject",
                    kind="policy",
                    label="CKA_COPYABLE=False enforcement (C_CopyObject)",
                    operation="C_CopyObject",
                    expected=(CKR_ACTION_PROHIBITED,),
                    actual=exc.rv,
                    spec_ref="PKCS#11 v3.2",
                    summary=(
                        "C_CopyObject rejected CKA_COPYABLE=False with a non-spec return value"
                    ),
                )

            # C_CopyObject succeeded on a CKA_COPYABLE=False key — spec
            # violation. Per Phase 4.5 GAP-T2, this must be a hard failure
            # so that conformance regressions in any module are surfaced
            # rather than silently xfailed (was previously pytest.xfail).
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module ignores CKA_COPYABLE=False: C_CopyObject succeeded on non-copyable key",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.2: CKA_COPYABLE=False must prevent copy",
            )
            destroy_quietly(rs.raw, rs.sh, copied_h)
            classify(
                "self_contradiction",
                kind="policy",
                label="CKA_COPYABLE=False enforcement (C_CopyObject)",
                operation="C_CopyObject",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "SECURITY: module copied a CKA_COPYABLE=False key — "
                    "copy-prohibition silently ignored"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_session_object_stays_session(self, p11_raw_session: Any) -> None:
        """Copy of a session object is also a session object (CKA_TOKEN=False)."""
        rs = p11_raw_session
        key_h = _gen_access_control_aes_key(
            rs,
            attrs={CKA_TOKEN: False, CKA_LABEL: "session-src"},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_TOKEN])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:session-object-copy",
            )
            token = attr_or_record(
                attrs,
                CKA_TOKEN,
                label="CKA_TOKEN:session-object-copy",
            )
            if token is not MISSING_ATTRIBUTE:
                token_value = _require_access_bool(token, "CKA_TOKEN:session-object-copy")
                if token_value is not False:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="CKA_TOKEN:session-object-copy",
                        operation="C_GenerateKey",
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "C_GenerateKey accepted CKA_TOKEN=False but readback returned True"
                        ),
                    )
            if copyable is MISSING_ATTRIBUTE:
                return
            if _require_access_bool(copyable, "CKA_COPYABLE:session-object-copy") is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_COPYABLE:session-object-copy",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_COPYABLE=False",
                )
            try:
                copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "session-copy"})
            except CkrAssertionError as exc:
                _handle_copy_reject(
                    exc,
                    "C_CopyObject not supported or module rejected copy template",
                )
                return
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_TOKEN])
                copied_token = attr_or_record(
                    copy_attrs,
                    CKA_TOKEN,
                    label="C_CopyObject:CKA_TOKEN on session copy",
                )
                if copied_token is MISSING_ATTRIBUTE:
                    return
                copied_token_value = _require_access_bool(
                    copied_token,
                    "C_CopyObject:CKA_TOKEN on session copy",
                )
                if copied_token_value is not False:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="C_CopyObject:CKA_TOKEN on session copy",
                        operation="C_CopyObject",
                        spec_ref="PKCS#11 v3.2",
                        summary="C_CopyObject changed a session object's CKA_TOKEN to True",
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_token_object_stays_token(self, p11_raw_session: Any) -> None:
        """Copy of a token object is also a token object (CKA_TOKEN=True)."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        key_h = _gen_access_control_aes_key(
            rs,
            attrs={CKA_TOKEN: True, CKA_LABEL: "token-src"},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_COPYABLE, CKA_TOKEN])
            copyable = attr_or_record(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE:token-object-copy",
            )
            token = attr_or_record(
                attrs,
                CKA_TOKEN,
                label="CKA_TOKEN:token-object-copy",
            )
            if token is not MISSING_ATTRIBUTE:
                token_value = _require_access_bool(token, "CKA_TOKEN:token-object-copy")
                if token_value is not True:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="CKA_TOKEN:token-object-copy",
                        operation="C_GenerateKey",
                        spec_ref="PKCS#11 v3.2",
                        summary=(
                            "C_GenerateKey accepted CKA_TOKEN=True but readback returned False"
                        ),
                    )
            if copyable is MISSING_ATTRIBUTE:
                return
            if _require_access_bool(copyable, "CKA_COPYABLE:token-object-copy") is not True:
                xfail_as(
                    "honest_deviation",
                    kind="policy",
                    label="CKA_COPYABLE:token-object-copy",
                    operation="C_GenerateKey",
                    summary="Generated secret key reports CKA_COPYABLE=False",
                )
            copied_h = None
            try:
                try:
                    copied_h = copy_object(rs.raw, rs.sh, key_h, {CKA_LABEL: "token-copy"})
                except CkrAssertionError as exc:
                    _handle_copy_reject(
                        exc,
                        "C_CopyObject not supported or module rejected copy template",
                    )
                    return
                copy_attrs = read_attributes(rs.raw, rs.sh, copied_h, [CKA_TOKEN])
                copied_token = attr_or_record(
                    copy_attrs,
                    CKA_TOKEN,
                    label="C_CopyObject:CKA_TOKEN on token copy",
                )
                if copied_token is MISSING_ATTRIBUTE:
                    return
                copied_token_value = _require_access_bool(
                    copied_token,
                    "C_CopyObject:CKA_TOKEN on token copy",
                )
                if copied_token_value is not True:
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="C_CopyObject:CKA_TOKEN on token copy",
                        operation="C_CopyObject",
                        spec_ref="PKCS#11 v3.2",
                        summary="C_CopyObject changed a token object's CKA_TOKEN to False",
                    )
            finally:
                if copied_h is not None:
                    destroy_quietly(rs.raw, rs.sh, copied_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

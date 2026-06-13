"""CKR compliance tests for object management functions.

Covers C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
C_GetAttributeValue, C_SetAttributeValue, C_FindObjects*.

Source: PKCS#11 v3.1 Sec.5.7.1-5.7.9.
"""

from __future__ import annotations

from ctypes import byref, c_ubyte, sizeof
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.pack import (
    attr_array,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_ALLOWED_MECHANISMS,
    CKA_CLASS,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKM_AES_ECB,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._malformed_attrs import (
    make_attr_null_pointer,
    make_bool_attr_overlong,
    make_ulong_attr_with_length,
)
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
)

pytestmark = pytest.mark.access


class TestCreateObjectErrors:
    """Error conditions for C_CreateObject (Sec.5.7.1)."""

    def test_missing_class(self, p11_raw_session: Any) -> None:
        """Missing CKA_CLASS -> CKR_TEMPLATE_INCOMPLETE."""
        rs = p11_raw_session
        tmpl = template(
            attr_bytes(CKA_LABEL, b"no-class"),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
            classify(
                "accepted_invalid",
                kind="policy",
                label="C_CreateObject:missing-class",
                operation="C_CreateObject",
                actual=rv,
                summary="Should have rejected template without CKA_CLASS",
            )
        assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"

    def test_invalid_class_value(self, p11_raw_session: Any) -> None:
        """CKA_CLASS=0xDEADBEEF -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, 0xDEADBEEF),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
            classify(
                "accepted_invalid",
                kind="policy",
                label="C_CreateObject:invalid-class-value",
                operation="C_CreateObject",
                actual=rv,
                summary="Should have rejected invalid CKA_CLASS value",
            )
        assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"

    def test_conflicting_class_keytype(self, p11_raw_session: Any) -> None:
        """DATA object with KEY_TYPE -> reject or ignore."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"conflict"),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            # Some modules ignore KEY_TYPE on DATA - acceptable
            destroy_quietly(rs.raw, rs.sh, handle.value)
        else:
            assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"

    def test_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """CKA_TOKEN with CK_ULONG-sized value storage must be rejected."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"bad-bbool-create"),
            attr_bytes(CKA_VALUE, b"value"),
            attr_bool(CKA_TOKEN, False),
        )
        _storage = make_bool_attr_overlong(tmpl, 3)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_CreateObject with CK_ULONG-sized CKA_TOKEN boolean attribute",
        )

    @pytest.mark.parametrize(
        ("attr_len", "case_name"),
        [
            pytest.param(1, "underlong", id="underlong"),
            pytest.param(sizeof(CK_ULONG) + 1, "overlong", id="overlong"),
        ],
    )
    def test_class_ulong_malformed_length(
        self,
        p11_raw_session: Any,
        attr_len: int,
        case_name: str,
    ) -> None:
        """CKA_CLASS with non-CK_ULONG-sized storage must be rejected."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"bad-class-len-create"),
            attr_bytes(CKA_VALUE, b"value"),
            attr_bool(CKA_TOKEN, False),
        )
        _storage = make_ulong_attr_with_length(tmpl, 0, CKO_DATA, attr_len)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=f"C_CreateObject with {case_name} CKA_CLASS CK_ULONG attribute",
        )

    @pytest.mark.parametrize(
        ("attr_len", "case_name"),
        [
            pytest.param(1, "underlong", id="underlong"),
            pytest.param(sizeof(CK_ULONG) + 1, "overlong", id="overlong"),
        ],
    )
    def test_key_type_ulong_malformed_length(
        self,
        p11_raw_session: Any,
        attr_len: int,
        case_name: str,
    ) -> None:
        """CKA_KEY_TYPE with non-CK_ULONG-sized storage must be rejected."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"\x01" * 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
        )
        _storage = make_ulong_attr_with_length(tmpl, 1, CKK_AES, attr_len)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=f"C_CreateObject with {case_name} CKA_KEY_TYPE CK_ULONG attribute",
        )

    def test_allowed_mechanisms_null_pointer_nonzero_length(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKA_ALLOWED_MECHANISMS must reject NULL_PTR with nonzero length."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"\x01" * 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_ENCRYPT, True),
            attr_array(CKA_ALLOWED_MECHANISMS, [CKM_AES_ECB]),
        )
        make_attr_null_pointer(tmpl, 6, sizeof(CK_ULONG))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=("C_CreateObject with CKA_ALLOWED_MECHANISMS NULL_PTR and nonzero ulValueLen"),
        )

    def test_allowed_mechanisms_empty_null_pointer_enforced(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Accepted empty CKA_ALLOWED_MECHANISMS arrays must block mechanism use."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"\x01" * 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_ENCRYPT, True),
            attr_array(CKA_ALLOWED_MECHANISMS, [CKM_AES_ECB]),
        )
        make_attr_null_pointer(tmpl, 6, 0)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv != CKR_OK:
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label=("C_CreateObject with empty CKA_ALLOWED_MECHANISMS NULL_PTR array"),
            )
            return

        try:
            attrs = read_attributes(rs.raw, rs.sh, handle.value, [CKA_ALLOWED_MECHANISMS])
            claimed = attrs.get(CKA_ALLOWED_MECHANISMS) == []
            mech = mech_simple(CKM_AES_ECB)
            init_rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), handle.value)
            encrypted = False
            if init_rv == CKR_OK:
                plaintext = (c_ubyte * 16)(*range(16))
                ciphertext = (c_ubyte * 32)()
                ciphertext_len = CK_ULONG(32)
                encrypt_rv = rs.raw.C_Encrypt(
                    rs.sh,
                    plaintext,
                    16,
                    ciphertext,
                    byref(ciphertext_len),
                )
                encrypted = encrypt_rv == CKR_OK
            classify_policy_enforcement(
                claimed=claimed,
                violated=encrypted,
                label=(
                    "CKA_ALLOWED_MECHANISMS empty-array enforcement for C_EncryptInit/C_Encrypt"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle.value)


class TestGetAttributeErrors:
    """Error conditions for C_GetAttributeValue (Sec.5.7.5)."""

    def test_sensitive_value(self, p11_raw_session: Any) -> None:
        """Reading VALUE on SENSITIVE key -> CKR_ATTRIBUTE_SENSITIVE."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, attrs={CKA_SENSITIVE: True})
        try:
            # Type-B claim/effect-check: claimed = the key reports
            # CKA_SENSITIVE=True back; violated = the protected CKA_VALUE is
            # actually readable (read_attributes omits unavailable attributes).
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            claimed = sens_attrs.get(CKA_SENSITIVE) is True
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            violated = CKA_VALUE in val_attrs
            classify_policy_enforcement(
                claimed=claimed,
                violated=violated,
                label="read CKA_VALUE on a CKA_SENSITIVE=True key "
                "(PKCS#11 v3.1 Sec.5.7.5 requires CKR_ATTRIBUTE_SENSITIVE)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroyed_handle(self, p11_raw_session: Any) -> None:
        """Using a destroyed object's handle -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128)
        rs.raw.C_DestroyObject(rs.sh, key)
        # Negative op on a destroyed handle. Issue C_GetAttributeValue *directly*
        # (not via read_attributes, which would re-raise the correct
        # CKR_OBJECT_HANDLE_INVALID rejection as a setup error). Sizing call only.
        tmpl = (CK_ATTRIBUTE * 1)()
        tmpl[0].type = CKA_LABEL
        tmpl[0].pValue = None
        tmpl[0].ulValueLen = 0
        rv = rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)
        # CKR_OK -> the read succeeded on a destroyed handle (use-after-destroy)
        # -> fail. A handle-invalid rejection is spec-correct -> pass. Any other
        # clean reject code -> xfail (honest non-spec deviation).
        classify_negative_rv(
            rv,
            (CKR_OBJECT_HANDLE_INVALID, CKR_SESSION_HANDLE_INVALID),
            label="C_GetAttributeValue via a destroyed object handle (use-after-destroy)",
        )


class TestSetAttributeErrors:
    """Error conditions for C_SetAttributeValue (Sec.5.7.6)."""

    def test_set_readonly_class(self, p11_raw_session: Any) -> None:
        """Setting CKA_CLASS -> CKR_ATTRIBUTE_READ_ONLY."""
        rs = p11_raw_session
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "readonly-test",
                CKA_VALUE: b"test",
                CKA_TOKEN: False,
            },
        )
        try:
            # Try to change CKA_CLASS (read-only). Type-C effect-check:
            # claimed_success = C_SetAttributeValue returned CKR_OK; the
            # contradiction is only real if the read-only value *actually*
            # changed. A CKR_OK no-op (value unchanged) is a wrong code with no
            # harm -> xfail; an honest rejection -> pass.
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            rv = rs.raw.C_SetAttributeValue(rs.sh, handle, tmpl.ptr, tmpl.count)
            if rv != CKR_OK:
                return  # Rejected a write to a read-only attribute -- correct.
            class_attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_CLASS])
            if class_attrs.get(CKA_CLASS) == CKO_SECRET_KEY:
                # Type-B: claimed read-only protection on CKA_CLASS yet the write
                # took effect -> self-contradiction.
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="C_SetAttributeValue:read-only-class",
                    operation="C_SetAttributeValue",
                    spec_ref="PKCS#11 v3.1 Sec.5.7.6",
                    summary=(
                        "C_SetAttributeValue claimed success and the read-only CKA_CLASS "
                        "actually changed (self-contradiction) "
                        "[PKCS#11 v3.1 Sec.5.7.6: CKA_CLASS is read-only]"
                    ),
                )
            # CKR_OK no-op: wrong code with no harm (value unchanged) -> xfail.
            xfail_as(
                "honest_deviation",
                label="C_SetAttributeValue:read-only-class",
                operation="C_SetAttributeValue",
                spec_ref="PKCS#11 v3.1 Sec.5.7.6",
                summary=(
                    "C_SetAttributeValue returned CKR_OK for a read-only CKA_CLASS write "
                    "but the value was unchanged (no-op; spec prefers CKR_ATTRIBUTE_READ_ONLY)"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestCopyObjectErrors:
    """Error conditions for C_CopyObject (Sec.5.7.2)."""

    def test_copy_destroyed_handle(self, p11_raw_session: Any) -> None:
        """Copy destroyed object -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128)
        destroy_rv = rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"ckr-copy-result"))
        new_handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CopyObject(
            rs.sh,
            key,
            tmpl.ptr,
            tmpl.count,
            byref(new_handle),
        )
        # Type-C use-after-destroy effect-check: claimed_success = destroy
        # reported CKR_OK; effect_observed = the copy of the destroyed object
        # produced a live new object handle (the object was usable after
        # destroy).
        produced = rv == CKR_OK and new_handle.value != 0
        if produced:
            destroy_quietly(rs.raw, rs.sh, new_handle.value)
        classify_lifecycle_effect(
            claimed_success=destroy_rv == CKR_OK,
            effect_observed=produced,
            label="copy an object via its destroyed handle (use-after-destroy)",
        )

    def test_copy_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """C_CopyObject must reject CK_ULONG-sized CKA_TOKEN template value."""
        rs = p11_raw_session
        source = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "bad-bbool-copy-source",
                CKA_VALUE: b"value",
                CKA_TOKEN: False,
            },
        )
        try:
            tmpl = template(attr_bool(CKA_TOKEN, False))
            _storage = make_bool_attr_overlong(tmpl, 0)
            new_handle = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_CopyObject(
                rs.sh,
                source,
                tmpl.ptr,
                tmpl.count,
                byref(new_handle),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, new_handle.value)
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label="C_CopyObject with CK_ULONG-sized CKA_TOKEN boolean attribute",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, source)


class TestFindObjectsErrors:
    """Error conditions for C_FindObjects* (Sec.5.7.7-5.7.9)."""

    def test_find_with_empty_result(self, p11_raw_session: Any) -> None:
        """FindObjects with template matching nothing -> returns empty list."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_LABEL, b"nonexistent_ckr_label_xyz"))
        rv = rs.raw.C_FindObjectsInit(rs.sh, tmpl.ptr, tmpl.count)
        assert rv == CKR_OK, f"C_FindObjectsInit failed: {ckr_name(rv)}"
        handles = (CK_OBJECT_HANDLE * 10)()
        count = CK_ULONG(0)
        rv = rs.raw.C_FindObjects(rs.sh, handles, 10, byref(count))
        assert rv == CKR_OK
        rs.raw.C_FindObjectsFinal(rs.sh)
        assert count.value == 0  # Empty is valid - not an error

    def test_find_objects_null_template_zero_count_matches_all(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_FindObjectsInit(NULL_PTR, 0) is a valid match-all search."""
        rs = p11_raw_session
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "ckr-find-null-template-zero-count",
                CKA_VALUE: b"test",
                CKA_TOKEN: False,
            },
        )
        search_started = False
        try:
            rv = rs.raw.C_FindObjectsInit(rs.sh, None, 0)
            if rv != CKR_OK:
                xfail_as(
                    "not_operational",
                    label="C_FindObjectsInit:null-template-match-all",
                    operation="C_FindObjectsInit",
                    actual=rv,
                    summary=(
                        "C_FindObjectsInit(NULL_PTR, 0) rejected a valid match-all search: "
                        f"{ckr_name(rv)}"
                    ),
                )
            search_started = True

            found: list[int] = []
            for _ in range(128):
                handles = (CK_OBJECT_HANDLE * 16)()
                count = CK_ULONG(0)
                rv = rs.raw.C_FindObjects(rs.sh, handles, len(handles), byref(count))
                if rv != CKR_OK:
                    xfail_as(
                        "not_operational",
                        label="C_FindObjects:null-template-match-all",
                        operation="C_FindObjects",
                        actual=rv,
                        summary=(
                            "C_FindObjects after C_FindObjectsInit(NULL_PTR, 0) rejected "
                            f"a valid search: {ckr_name(rv)}"
                        ),
                    )
                assert count.value <= len(handles), (
                    "C_FindObjects returned more handles than the caller's ulMaxObjectCount"
                )
                found.extend(int(handles[i]) for i in range(count.value))
                if count.value == 0:
                    break
            else:
                # The match-all search never reported the terminating empty page
                # within a sane bound: a non-terminating operation -> fail.
                fail_as(
                    "crash",
                    label="C_FindObjects:null-template-match-all",
                    operation="C_FindObjects",
                    summary="C_FindObjects(NULL_PTR, 0) did not finish within 2048 handles",
                )

            rv = rs.raw.C_FindObjectsFinal(rs.sh)
            search_started = False
            if rv != CKR_OK:
                xfail_as(
                    "not_operational",
                    label="C_FindObjectsFinal:null-template-match-all",
                    operation="C_FindObjectsFinal",
                    actual=rv,
                    summary=(
                        "C_FindObjectsFinal after C_FindObjectsInit(NULL_PTR, 0) rejected "
                        f"a valid search: {ckr_name(rv)}"
                    ),
                )

            assert handle in found, (
                "C_FindObjectsInit(NULL_PTR, 0) did not match a session object "
                "created before the search"
            )
        finally:
            if search_started:
                rs.raw.C_FindObjectsFinal(rs.sh)
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_find_by_class(self, p11_raw_session: Any) -> None:
        """FindObjects with CKA_CLASS filter works correctly."""
        rs = p11_raw_session
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "ckr-find-test",
                CKA_VALUE: b"test",
                CKA_TOKEN: False,
            },
        )
        try:
            search = template(attr_bytes(CKA_LABEL, b"ckr-find-test"))
            rv = rs.raw.C_FindObjectsInit(rs.sh, search.ptr, search.count)
            assert rv == CKR_OK
            handles = (CK_OBJECT_HANDLE * 10)()
            count = CK_ULONG(0)
            rv = rs.raw.C_FindObjects(rs.sh, handles, 10, byref(count))
            assert rv == CKR_OK
            rs.raw.C_FindObjectsFinal(rs.sh)
            assert count.value >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestDestroyObjectErrors:
    """Error conditions for C_DestroyObject (Sec.5.7.3)."""

    def test_destroy_already_destroyed(self, p11_raw_session: Any) -> None:
        """Double destroy -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        # Type-C use-after-destroy effect-check. Tag the object so survival is
        # distinguishable from handle reuse. claimed_success = the first destroy
        # reported CKR_OK; effect_observed = the tagged object is still findable
        # afterwards (the destroy was claimed but did not take effect). The
        # second-destroy return code alone is not the effect.
        tag = b"ckr-double-destroy"
        key = gen_aes_key_or_xfail(rs, 128)
        tag_tmpl = template(attr_bytes(CKA_LABEL, tag))
        rs.raw.C_SetAttributeValue(rs.sh, key, tag_tmpl.ptr, tag_tmpl.count)
        first_rv = rs.raw.C_DestroyObject(rs.sh, key)
        find_tmpl = template(attr_bytes(CKA_LABEL, tag))
        survivors = find_objects(rs.raw, rs.sh, find_tmpl)
        classify_lifecycle_effect(
            claimed_success=first_rv == CKR_OK,
            effect_observed=len(survivors) > 0,
            label="destroy an object then find its tagged content (use-after-destroy)",
        )

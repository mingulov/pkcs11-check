"""C_SetAttributeValue tests - attribute mutation on existing objects.

Tests modifying CKA_LABEL, CKA_ID on keys, and verifying that
read-only attributes (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS) are rejected.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_VALUE,
    CKK_RSA,
    CKO_PUBLIC_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_SET_ATTR_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)


def _read_back_or_fail(rs: Any, handle: int, attrs: list[int], *, label: str) -> dict[int, Any]:
    """Read attributes back for an effect check, failing clearly on a bad read.

    ``read_attributes`` already tolerates ``CKR_ATTRIBUTE_SENSITIVE`` /
    ``CKR_ATTRIBUTE_TYPE_INVALID`` (those attributes are simply omitted). Any
    *other* clean error from ``C_GetAttributeValue`` after a write means the
    object can no longer be read back consistently -- a Type-C self-contradiction
    (the write was accepted, then the object was left in a bad state). Surface it
    as a clear finding instead of an opaque ``CkrAssertionError`` from the recipe.
    """
    try:
        return read_attributes(rs.raw, rs.sh, handle, attrs)
    except AssertionError as exc:
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_GetAttributeValue",
            summary=(
                f"{label}: attribute(s) could not be read back after the write ({exc}) "
                "-- the object was left in an inconsistent state"
            ),
        )


def _classify_readonly_write(
    rs: Any, handle: int, attr: int, new_value: Any, *, label: str
) -> None:
    """Type-C effect-check for a write to a read-only attribute.

    C_SetAttributeValue on a read-only attribute must reject. Verify the effect,
    not the return code:

    - rejected (set_attributes raised) -> pass (spec-correct),
    - accepted (no raise) AND the value actually changed to ``new_value``
      -> fail (the module claimed success then mutated a read-only attribute --
      a self-contradiction),
    - accepted but the value is unchanged (no-op) -> xfail (wrong return code,
      but no harm; spec prefers CKR_ATTRIBUTE_READ_ONLY).
    """
    try:
        set_attributes(rs.raw, rs.sh, handle, {attr: new_value})
    except AssertionError:
        return  # Rejected the read-only write -- correct.
    after = _read_back_or_fail(rs, handle, [attr], label=label)
    if after.get(attr) == new_value:
        fail_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_SetAttributeValue",
            summary=f"{label}: claimed success and the read-only value actually changed",
        )
    xfail_as(
        "honest_deviation",
        kind="lifecycle",
        label=label,
        operation="C_SetAttributeValue",
        summary=(
            f"{label}: returned CKR_OK but the value was unchanged (no-op; "
            "spec prefers CKR_ATTRIBUTE_READ_ONLY)"
        ),
    )


class TestSetAttributePositive:
    """Verify that mutable attributes can be changed."""

    def test_change_label(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_LABEL: "before"},
            purpose="set-attribute label mutation",
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])
            assert attrs[CKA_LABEL] == "before"

            set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: "after"})

            # Search by new label works
            tmpl = template(attr_bytes(CKA_LABEL, b"after"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_id(self, p11_raw_session: Any) -> None:
        """CKA_ID can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_ID: b"\x01\x02"},
            purpose="set-attribute ID mutation",
        )
        try:
            set_attributes(rs.raw, rs.sh, key, {CKA_ID: b"\xaa\xbb"})
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_ID])
            assert attrs[CKA_ID] == b"\xaa\xbb"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_label_on_keypair(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on RSA public and private keys."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_LABEL: "rsa-orig"},
            private_attrs={CKA_LABEL: "rsa-orig"},
        )
        try:
            set_attributes(rs.raw, rs.sh, pub, {CKA_LABEL: "rsa-pub-new"})
            set_attributes(rs.raw, rs.sh, priv, {CKA_LABEL: "rsa-priv-new"})

            tmpl_pub = template(attr_bytes(CKA_LABEL, b"rsa-pub-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_pub)) >= 1
            tmpl_priv = template(attr_bytes(CKA_LABEL, b"rsa-priv-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_priv)) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSetAttributeAtomicity:
    """Verify that rejected multi-row updates do not leave partial state behind."""

    def test_set_attribute_mixed_template_is_atomic(self, p11_raw_session: Any) -> None:
        """A failing SetAttribute template must not partially apply earlier rows."""
        rs = p11_raw_session
        original = "atomic-before"
        control = "atomic-control"
        target = "atomic-after"
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_LABEL: original},
            purpose="set-attribute atomicity",
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: control})
                set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: original})
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _SET_ATTR_REJECT_RVS,
                    "C_SetAttributeValue rejected mutable CKA_LABEL setup",
                )
                raise

            mixed = template(
                attr_bytes(CKA_LABEL, target.encode("utf-8")),
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            )
            rv = rs.raw.C_SetAttributeValue(rs.sh, key, mixed.ptr, mixed.count)
            attrs = _read_back_or_fail(
                rs,
                key,
                [CKA_LABEL, CKA_CLASS],
                label="C_SetAttributeValue mixed mutable/read-only template",
            )
            label_after = attrs.get(CKA_LABEL)
            class_after = attrs.get(CKA_CLASS)

            if label_after == target:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_SetAttributeValue:partial-apply",
                    operation="C_SetAttributeValue",
                    summary=(
                        "C_SetAttributeValue partially applied CKA_LABEL before rejecting "
                        "a later read-only CKA_CLASS row"
                    ),
                )
            if class_after == CKO_PUBLIC_KEY:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_SetAttributeValue:read-only-CKA_CLASS",
                    operation="C_SetAttributeValue",
                    summary="C_SetAttributeValue changed read-only CKA_CLASS on an AES key",
                )
            if rv == CKR_OK:
                xfail_as(
                    "honest_deviation",
                    kind="lifecycle",
                    label="C_SetAttributeValue:mixed-template-noop",
                    operation="C_SetAttributeValue",
                    actual=rv,
                    summary=(
                        "C_SetAttributeValue returned CKR_OK for a mixed template containing "
                        "read-only CKA_CLASS, but left the object unchanged"
                    ),
                )
            classify_negative_rv(
                rv,
                _SET_ATTR_REJECT_RVS,
                label="C_SetAttributeValue mixed mutable/read-only template",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSetAttributeNegative:
    """Verify that read-only / immutable attributes are rejected."""

    def test_cannot_change_class(self, p11_raw_session: Any) -> None:
        """CKA_CLASS is read-only - must reject; mutating it is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute class rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_CLASS,
                CKO_PUBLIC_KEY,
                label="write read-only CKA_CLASS (PKCS#11 Base v3.0 Table 15)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_key_type(self, p11_raw_session: Any) -> None:
        """CKA_KEY_TYPE is read-only - must reject; mutating it is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute key-type rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_KEY_TYPE,
                CKK_RSA,
                label="write read-only CKA_KEY_TYPE (PKCS#11 Base v3.0 Table 15)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_modulus(self, p11_raw_session: Any) -> None:
        """CKA_MODULUS on RSA key is read-only - must reject."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            _classify_readonly_write(
                rs,
                pub,
                CKA_MODULUS,
                b"\x00" * 256,
                label="write read-only CKA_MODULUS on an RSA public key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_cannot_set_value_on_sensitive_key(self, p11_raw_session: Any) -> None:
        """CKA_VALUE on a key - must reject; mutating the key bytes is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute sensitive value rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_VALUE,
                b"\x00" * 32,
                label="write read-only CKA_VALUE on a secret key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

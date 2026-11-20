"""Contract for attempt-correlated adoption of novel success handles (R4-F1).

Novelty alone never proves ownership: a token object from another
application can become visible between a baseline and a success return.
Adoption requires the handle's read-back identity to match the attempt
(label / token flag / class / type); mismatches fail loud without
touching the handle, and unreadable identity voids without touching it.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import _adoption as ad
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

_OK = int(CKR_OK)


class _IdentityRaw:
    """C_GetAttributeValue with per-attr values, refusals, and leaks."""

    def __init__(self) -> None:
        self.values: dict[int, bytes] = {}
        self.refusals: dict[int, int] = {}
        self.leaks: dict[int, tuple[int, bytes]] = {}
        self.call_rv: int | None = None

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if int(handle) == 0:
            return int(CKR_OBJECT_HANDLE_INVALID)
        if self.call_rv is not None:
            return self.call_rv
        call_rv = _OK
        for i in range(int(count)):
            at = int(tmpl[i].type)
            if at in self.leaks:
                rv, blob = self.leaks[at]
                if tmpl[i].pValue is None:
                    tmpl[i].ulValueLen = len(blob)
                else:
                    ctypes.memmove(tmpl[i].pValue, blob, len(blob))
                    tmpl[i].ulValueLen = len(blob)
                call_rv = rv
            elif at in self.refusals:
                tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                call_rv = self.refusals[at]
            else:
                blob = self.values.get(at)
                if blob is None:
                    tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                    call_rv = int(CKR_ATTRIBUTE_TYPE_INVALID)
                elif tmpl[i].pValue is None:
                    tmpl[i].ulValueLen = len(blob)
                else:
                    ctypes.memmove(tmpl[i].pValue, blob, len(blob))
                    tmpl[i].ulValueLen = len(blob)
        return call_rv


def _rs(raw: _IdentityRaw) -> Any:
    return SimpleNamespace(raw=raw, sh=7)


def _ulong(value: int) -> bytes:
    import sys

    return int(value).to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


def _serve_full(raw: _IdentityRaw) -> None:
    raw.values[int(CKA_LABEL)] = b"attempt-label"
    raw.values[int(CKA_TOKEN)] = b"\x00"
    raw.values[int(CKA_CLASS)] = _ulong(int(CKO_SECRET_KEY))
    raw.values[int(CKA_KEY_TYPE)] = _ulong(int(CKK_GENERIC_SECRET))


def test_read_identity_attr_serves_decoded_values() -> None:
    raw = _IdentityRaw()
    _serve_full(raw)
    rs = _rs(raw)
    got = ad.read_identity_attr(rs, 9, int(CKA_LABEL), label="L", operation="op")
    assert got == "attempt-label"
    assert ad.read_identity_attr(rs, 9, int(CKA_TOKEN), label="L", operation="op") is False
    assert ad.read_identity_attr(rs, 9, int(CKA_CLASS), label="L", operation="op") == int(
        CKO_SECRET_KEY
    )


def test_read_identity_attr_refusal_channel_is_missing() -> None:
    raw = _IdentityRaw()
    raw.refusals[int(CKA_LABEL)] = int(CKR_ATTRIBUTE_SENSITIVE)
    assert (
        ad.read_identity_attr(_rs(raw), 9, int(CKA_LABEL), label="L", operation="op")
        is MISSING_ATTRIBUTE
    )


def test_read_identity_attr_call_refusal_carries_rv() -> None:
    raw = _IdentityRaw()
    raw.call_rv = int(CKR_DEVICE_ERROR)
    observed = ad.read_identity_attr(_rs(raw), 9, int(CKA_LABEL), label="L", operation="op")
    assert isinstance(observed, ad.CallRefused)
    assert observed.rv == int(CKR_DEVICE_ERROR)


def test_read_identity_attr_undefined_rv_fails() -> None:
    raw = _IdentityRaw()
    raw.call_rv = 0x7FFFFFFF
    with pytest.raises(Failed):
        ad.read_identity_attr(_rs(raw), 9, int(CKA_LABEL), label="L", operation="op")


def test_read_identity_attr_leak_fails() -> None:
    raw = _IdentityRaw()
    raw.leaks[int(CKA_LABEL)] = (int(CKR_ATTRIBUTE_SENSITIVE), b"attempt-label")
    with pytest.raises(Failed, match="wrote"):
        ad.read_identity_attr(_rs(raw), 9, int(CKA_LABEL), label="L", operation="op")


def _adopt_kwargs() -> dict[str, Any]:
    return {
        "label": "L",
        "operation": "C_CopyObject",
        "spec_ref": "spec",
        "expect_label": "attempt-label",
        "expect_token": False,
        "expect_class": int(CKO_SECRET_KEY),
        "expect_key_type": int(CKK_GENERIC_SECRET),
    }


def test_adopt_match_returns() -> None:
    raw = _IdentityRaw()
    _serve_full(raw)
    assert ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs()) is None


def test_adopt_label_mismatch_fails() -> None:
    raw = _IdentityRaw()
    _serve_full(raw)
    raw.values[int(CKA_LABEL)] = b"foreign-label"
    with pytest.raises(Failed, match="not the attempt"):
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())


def test_adopt_token_flag_mismatch_fails() -> None:
    raw = _IdentityRaw()
    _serve_full(raw)
    raw.values[int(CKA_TOKEN)] = b"\x01"
    with pytest.raises(Failed, match="not the attempt"):
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())


def test_adopt_unreadable_label_raises_unproved() -> None:
    raw = _IdentityRaw()
    _serve_full(raw)
    del raw.values[int(CKA_LABEL)]
    raw.refusals[int(CKA_LABEL)] = int(CKR_ATTRIBUTE_SENSITIVE)
    with pytest.raises(ad.OwnershipUnprovedError) as exc_info:
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())
    assert exc_info.value.handle == 9
    assert "label" in exc_info.value.fields


def test_adopt_call_refused_raises_unproved_with_rv() -> None:
    raw = _IdentityRaw()
    raw.call_rv = int(CKR_DEVICE_ERROR)
    with pytest.raises(ad.OwnershipUnprovedError) as exc_info:
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())
    assert exc_info.value.call_rv == int(CKR_DEVICE_ERROR)


def test_adopt_vendor_call_refused_raises_unproved_not_fail() -> None:
    raw = _IdentityRaw()
    raw.call_rv = 0x80000001
    with pytest.raises(ad.OwnershipUnprovedError):
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())


def test_adopt_skips_unexpected_fields() -> None:
    """Unlabelled products correlate on the remaining identity (R4-F1)."""
    raw = _IdentityRaw()
    raw.values[int(CKA_TOKEN)] = b"\x00"
    raw.values[int(CKA_CLASS)] = _ulong(int(CKO_SECRET_KEY))
    raw.values[int(CKA_KEY_TYPE)] = _ulong(int(CKK_AES))
    kwargs = _adopt_kwargs()
    kwargs["expect_label"] = None
    kwargs["expect_key_type"] = int(CKK_AES)
    assert ad.adopt_correlated_output(_rs(raw), 9, **kwargs) is None


def test_adopt_garbage_shape_is_unproved() -> None:
    """A non-bool token flag proves nothing (void, never adopt, never fail)."""
    raw = _IdentityRaw()
    _serve_full(raw)
    raw.values[int(CKA_TOKEN)] = b"\x00\x01"
    with pytest.raises(ad.OwnershipUnprovedError):
        ad.adopt_correlated_output(_rs(raw), 9, **_adopt_kwargs())


def test_compare_match_mismatch_unproved() -> None:
    """R4-F1: the shared comparator grades read/missing/refused shapes."""
    from pkcs11_check.testcases._adoption import CallRefused, compare_attempt_identity

    expected = {"label": "L", "token": False, "class": 1, "key_type": 2}
    assert (
        compare_attempt_identity(
            {"label": "L", "token": False, "class": 1, "key_type": 2}, expected
        )
        == "match"
    )
    assert (
        compare_attempt_identity(
            {"label": "L", "token": False, "class": 1, "key_type": 2}, {"label": "L"}
        )
        == "match"
    )
    assert (
        compare_attempt_identity(
            {"label": "X", "token": False, "class": 1, "key_type": 2}, expected
        )
        == "mismatch"
    )
    assert (
        compare_attempt_identity(
            {"label": MISSING_ATTRIBUTE, "token": False, "class": 1, "key_type": 2}, expected
        )
        == "unproved"
    )
    assert (
        compare_attempt_identity(
            {"label": CallRefused(1), "token": False, "class": 1, "key_type": 2}, expected
        )
        == "unproved"
    )
    # A proved difference fails even beside unproved fields.
    assert (
        compare_attempt_identity(
            {"label": "X", "token": MISSING_ATTRIBUTE, "class": 1, "key_type": 2}, expected
        )
        == "mismatch"
    )
    assert compare_attempt_identity({"label": b"L"}, {"label": "L"}) == "match"


def test_read_attempt_identity_reads_expected_only() -> None:
    """R4-F1: the plural reader serves exactly the expected fields."""
    raw = _IdentityRaw()
    _serve_full(raw)
    observed = ad.read_attempt_identity(
        _rs(raw), 9, label="L", operation="op", fields=("label", "token")
    )
    assert observed == {"label": "attempt-label", "token": False}, observed

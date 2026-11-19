"""Contract for the QC3b private-exponent verify legs (B4).

The exponent fixture is deliberately unsealed, so readback decides by
integer identity: an unchanged integer proves ignore, the injected
integer proves a rewrite, any other integer proves an alteration, and
encoding-only differences never count. Readback steps attribute the
C_GetAttributeValue operation; mutation terminals carry actual=CKR_OK.
A sanctioned refusal is followed by a post-refusal readback: a proved
change fails as refusal-after-mutation, unreadable state voids.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_DEVICE_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases.security import test_api_security as sec

LABEL = "C_SetAttributeValue private_exponent (QC3b table)"
SPEC = "QC3b private-exponent row"
ORIGINAL = bytes([0x01]) + bytes(127)
INJECTED = sec._QC3B_INJECTED_EXPONENT


class _ExpRaw:
    """Two-call C_GetAttributeValue stub serving one canned exponent."""

    def __init__(self, value: bytes | None, *, read_rv: int = int(CKR_OK)) -> None:
        self._value = value
        self._read_rv = read_rv
        self._calls = 0

    def C_GetAttributeValue(self, _sh: int, _handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self._calls += 1
        if self._read_rv != int(CKR_OK):
            return self._read_rv
        assert self._value is not None
        if self._calls == 1:
            tmpl[0].ulValueLen = len(self._value)
            return int(CKR_OK)
        ctypes.memmove(tmpl[0].pValue, self._value, len(self._value))
        tmpl[0].ulValueLen = len(self._value)
        return int(CKR_OK)


def _rs(value: bytes | None, *, read_rv: int = int(CKR_OK)) -> Any:
    return SimpleNamespace(raw=_ExpRaw(value, read_rv=read_rv), sh=7)


def _accept(rs: Any) -> None:
    sec._verify_private_exponent_accept(
        rs, 100, ORIGINAL, spec_ref=SPEC, label=LABEL, operation="C_SetAttributeValue"
    )


def test_accept_unchanged_integer_xfails_ignored() -> None:
    with pytest.raises(XFailed):
        _accept(_rs(ORIGINAL))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert "ignored" in (record.summary or "")


def test_accept_leading_zero_encoding_is_still_ignored() -> None:
    """B4: encoding-only differences never count as a change."""
    with pytest.raises(XFailed):
        _accept(_rs(b"\x00\x00" + ORIGINAL))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert "ignored" in (record.summary or "")


def test_accept_injected_rewrite_fails_with_ok() -> None:
    with pytest.raises(Failed):
        _accept(_rs(INJECTED))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert "rewrote" in (record.summary or "")
    assert record.actual_ckr == "CKR_OK", record.summary


def test_accept_other_integer_fails_altered_with_ok() -> None:
    with pytest.raises(Failed):
        _accept(_rs(bytes([0x02]) + bytes(127)))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert "altered" in (record.summary or "")
    assert record.actual_ckr == "CKR_OK", record.summary


def test_accept_refused_readback_attributes_getattr() -> None:
    """B4: the readback RV is recorded under C_GetAttributeValue, not C_Set."""
    with pytest.raises(XFailed):
        _accept(_rs(None, read_rv=int(CKR_DEVICE_ERROR)))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.operation == "C_GetAttributeValue", record.operation
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.summary


def _refused(rs: Any) -> None:
    sec._verify_exponent_unchanged_after_refusal(
        rs,
        100,
        ORIGINAL,
        spec_ref=SPEC,
        label=LABEL,
        operation="C_SetAttributeValue",
        refusal_rv=int(CKR_ATTRIBUTE_READ_ONLY),
    )


def test_refusal_unchanged_returns_silently() -> None:
    _refused(_rs(ORIGINAL))
    assert classification.get_records() == []


def test_refusal_changed_fails_after_mutation() -> None:
    with pytest.raises(Failed):
        _refused(_rs(bytes([0x02]) + bytes(127)))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert "refusal-after-mutation" in (record.summary or "")
    assert record.actual_ckr == "CKR_ATTRIBUTE_READ_ONLY", record.summary


def test_refusal_unreadable_voids_no_change() -> None:
    with pytest.raises(XFailed):
        _refused(_rs(None, read_rv=int(CKR_DEVICE_ERROR)))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.operation == "C_GetAttributeValue", record.operation

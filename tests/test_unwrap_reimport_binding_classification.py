"""CKA_UNWRAP_TEMPLATE claim and return-value routing regressions."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.security import test_unwrap_reimport as target

_DEFAULT_TEMPLATE = object()


class _Raw:
    def __init__(self, rv: int) -> None:
        self.rv = rv

    def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802
        _args[-1]._obj.value = 7
        return self.rv


def _session(rv: int) -> SimpleNamespace:
    return SimpleNamespace(raw=_Raw(rv), sh=1, has_mechanism=lambda _name: True)


def test_unwrap_template_keygen_unexpected_standard_rv_xfails() -> None:
    with pytest.raises(XFailed, match="C_GenerateKey with CKA_UNWRAP_TEMPLATE"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(int(CKR_DEVICE_ERROR))
        )


def test_unwrap_template_keygen_undefined_rv_fails() -> None:
    with pytest.raises(Failed, match="undefined CK_RV"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(0x12345678)
        )


def test_unwrap_template_accepted_but_missing_readback_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(XFailed, match="readback"):
        _run_binding_result(monkeypatch, True, template_value=None)


def test_unwrap_template_accepted_but_missing_readback_does_not_mask_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed, match="CKA_UNWRAP_TEMPLATE sensitivity binding bypassed"):
        _run_binding_result(monkeypatch, False, template_value=None)


def test_unwrap_template_readback_operational_error_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        target,
        "_read_unwrap_template_claim",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("rv", int(CKR_FUNCTION_FAILED))),
    )
    monkeypatch.setattr(target, "read_attributes", lambda *_a, **_k: {CKA_SENSITIVE: True})
    monkeypatch.setattr(target, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(target, "gen_aes_key_or_xfail", lambda *_a, **_k: 8)
    monkeypatch.setattr(target, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(target, "unwrap_key", lambda *_a, **_k: 9)

    with pytest.raises(XFailed, match="accepted CKA_UNWRAP_TEMPLATE.*metadata readback"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(int(CKR_OK))
        )


def _run_binding_result(
    monkeypatch: pytest.MonkeyPatch,
    result: object,
    *,
    template_value: object = _DEFAULT_TEMPLATE,
    unwrap_error: CkrAssertionError | None = None,
    readback_error: CkrAssertionError | None = None,
) -> None:
    issue = None if template_value is _DEFAULT_TEMPLATE else "malformed readback"

    def _read_claim(*_a: object, **_k: object) -> str | None:
        if readback_error is not None:
            raise readback_error
        return issue

    monkeypatch.setattr(target, "_read_unwrap_template_claim", _read_claim)

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, object]:
        return {CKA_SENSITIVE: result}

    monkeypatch.setattr(target, "read_attributes", _read)
    monkeypatch.setattr(target, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(target, "gen_aes_key_or_xfail", lambda *_a, **_k: 8)
    monkeypatch.setattr(target, "wrap_key", lambda *_a, **_k: b"wrapped")

    def _unwrap(*_a: object, **_k: object) -> int:
        if unwrap_error is not None:
            raise unwrap_error
        return 9

    monkeypatch.setattr(target, "unwrap_key", _unwrap)
    target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(_session(int(CKR_OK)))


class _ReadbackRaw:
    def __init__(
        self,
        *,
        rv: int = int(CKR_OK),
        outer_type: int | None = None,
        outer_length: int | None = None,
        inner_type: int | None = None,
        inner_length: int | None = None,
        inner_value: int = 1,
    ) -> None:
        self.rv = rv
        self.outer_type = outer_type
        self.outer_length = outer_length
        self.inner_type = inner_type
        self.inner_length = inner_length
        self.inner_value = inner_value
        self.count: int | None = None

    def C_GetAttributeValue(  # noqa: N802 - raw PKCS#11 API shape
        self,
        _session: int,
        _handle: int,
        attrs: Any,
        count: int,
    ) -> int:
        self.count = count
        if self.rv != int(CKR_OK):
            return self.rv
        outer = attrs[0]
        if self.outer_type is not None:
            outer.type = self.outer_type
        if self.outer_length is not None:
            outer.ulValueLen = self.outer_length
        inner = ctypes.cast(outer.pValue, ctypes.POINTER(CK_ATTRIBUTE))[0]
        if self.inner_type is not None:
            inner.type = self.inner_type
        if self.inner_length is not None:
            inner.ulValueLen = self.inner_length
        ctypes.cast(inner.pValue, ctypes.POINTER(CK_BBOOL))[0] = self.inner_value
        return int(CKR_OK)


def test_raw_unwrap_template_readback_validates_owned_nested_value() -> None:
    raw = _ReadbackRaw()
    assert target._read_unwrap_template_claim(raw, 1, 2) is None
    assert raw.count == 1


@pytest.mark.parametrize(
    ("outer_length", "inner_type", "inner_length", "inner_value"),
    [
        (ctypes.sizeof(CK_ATTRIBUTE) + 1, None, None, 1),
        (None, int(CKA_SENSITIVE) + 1, ctypes.sizeof(CK_BBOOL), 1),
        (None, None, 0, 1),
        (None, None, ctypes.sizeof(CK_BBOOL), 0),
    ],
)
def test_raw_unwrap_template_readback_rejects_invalid_nested_value(
    outer_length: int | None,
    inner_type: int | None,
    inner_length: int | None,
    inner_value: int,
) -> None:
    raw = _ReadbackRaw(
        outer_length=outer_length,
        inner_type=inner_type,
        inner_length=inner_length,
        inner_value=inner_value,
    )
    issue = target._read_unwrap_template_claim(raw, 1, 2)
    assert issue is not None


@pytest.mark.parametrize("rv", [int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)])
def test_raw_unwrap_template_readback_reports_unavailable(rv: int) -> None:
    raw = _ReadbackRaw(rv=rv)
    issue = target._read_unwrap_template_claim(raw, 1, 2)
    assert issue is not None


def test_unwrap_template_literal_true_result_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_binding_result(monkeypatch, True)


def test_unwrap_template_literal_false_result_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_binding_result(monkeypatch, False)
    assert not isinstance(ei.value, XFailed)


def test_unwrap_template_inconsistent_rejection_proves_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_binding_result(
        monkeypatch,
        True,
        unwrap_error=CkrAssertionError("rv", int(CKR_TEMPLATE_INCONSISTENT)),
    )


def test_standard_readback_error_does_not_mask_binding_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed, match="CKA_UNWRAP_TEMPLATE sensitivity binding bypassed"):
        _run_binding_result(
            monkeypatch,
            False,
            readback_error=CkrAssertionError("rv", int(CKR_BUFFER_TOO_SMALL)),
        )


def test_standard_readback_error_defers_metadata_on_safe_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(XFailed, match="standard CK_RV"):
        _run_binding_result(
            monkeypatch,
            True,
            readback_error=CkrAssertionError("rv", int(CKR_BUFFER_TOO_SMALL)),
        )


@pytest.mark.parametrize("rv", [CKR_TEMPLATE_INCOMPLETE, CKR_ARGUMENTS_BAD])
def test_unwrap_template_other_clean_rejections_xfail(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    with pytest.raises(XFailed, match="unwrap not operational"):
        _run_binding_result(
            monkeypatch,
            True,
            unwrap_error=CkrAssertionError("rv", int(rv)),
        )


def test_unwrap_template_missing_result_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed, match="CKA_SENSITIVE=None"):
        _run_binding_result(monkeypatch, None)


def test_unwrap_template_malformed_result_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed, match="CKA_SENSITIVE='true'"):
        _run_binding_result(monkeypatch, "true")


def test_unwrap_template_malformed_readback_does_not_mask_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = b"malformed-template"
    with pytest.raises(Failed, match="CKA_UNWRAP_TEMPLATE sensitivity binding bypassed"):
        _run_binding_result(monkeypatch, False, template_value=malformed)


def test_unwrap_template_malformed_readback_defers_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = b"malformed-template"
    with pytest.raises(XFailed, match="readback"):
        _run_binding_result(monkeypatch, True, template_value=malformed)


def _run_default_strip_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sensitive: object = False,
    extractable: object = True,
    value: object = b"\x11" * 16,
) -> list[str]:
    notes: list[str] = []
    monkeypatch.setattr(target, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(target, "gen_aes_key_or_xfail", lambda *_a, **_k: 2)
    monkeypatch.setattr(target, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(target, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(target, "unwrap_key", lambda *_a, **_k: 3)
    monkeypatch.setattr(target, "note", lambda description, *_a, **_k: notes.append(description))

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, object]:
        assert attrs == [CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_VALUE]
        result: dict[int, object] = {CKA_VALUE: value}
        if sensitive is not None:
            result[CKA_SENSITIVE] = sensitive
        if extractable is not None:
            result[CKA_EXTRACTABLE] = extractable
        return result

    monkeypatch.setattr(target, "read_attributes", _read)
    target.TestDefaultStripIsPermitted().test_default_strip_is_permitted(_session(int(CKR_OK)))
    return notes


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(True, True), (False, False), (True, None), (None, False)],
)
def test_default_strip_definitive_protection_claim_fails(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: bool,
    extractable: bool,
) -> None:
    with pytest.raises(Failed, match="default-strip C_UnwrapKey result contains nonempty"):
        _run_default_strip_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(None, True), (False, None), ("false", True)],
)
def test_default_strip_malformed_protection_readback_xfails(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    with pytest.raises(XFailed, match="Default-strip result-key protection readback"):
        _run_default_strip_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(True, True), (False, False), (True, False)],
)
def test_default_strip_different_result_template_xfails_without_value(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    with pytest.raises(XFailed, match="did not honor the requested output template"):
        _run_default_strip_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
            value=b"",
        )


def test_default_strip_valid_unprotected_result_is_posture_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notes = _run_default_strip_result(monkeypatch)
    assert notes and "Default wrap+unwrap strip posture" in notes[0]

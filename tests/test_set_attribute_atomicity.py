"""Focused C_SetAttributeValue mixed-template atomicity regressions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_LABEL,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_GENERAL_ERROR,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_set_attribute as set_attr


def _run(monkeypatch: pytest.MonkeyPatch, rv: int) -> list[str]:
    notes: list[str] = []
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_args: int(rv))
    rs = SimpleNamespace(raw=raw, sh=1)
    monkeypatch.setattr(set_attr, "gen_aes_key_or_xfail", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(set_attr, "set_attributes", lambda *_args, **_kwargs: None)
    readbacks = iter(
        (
            {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: "atomic-after", CKA_CLASS: CKO_PUBLIC_KEY},
        )
    )
    monkeypatch.setattr(set_attr, "read_attributes", lambda *_args, **_kwargs: next(readbacks))
    monkeypatch.setattr(set_attr, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        set_attr,
        "note",
        lambda description, *_args, **_kwargs: notes.append(description),
    )

    set_attr.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(rs)
    return notes


def test_general_error_partial_state_is_reported_but_not_false_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notes = _run(monkeypatch, CKR_GENERAL_ERROR)
    assert notes and "explicitly unspecified" in notes[0]


def test_ordinary_reject_partial_state_remains_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.fail.Exception, match="partially applied"):
        _run(monkeypatch, CKR_ATTRIBUTE_READ_ONLY)


def test_atomicity_ckr_ok_malformed_post_readback_keeps_setter_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(set_attr, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    destroyed: list[int] = []
    monkeypatch.setattr(
        set_attr,
        "destroy_quietly",
        lambda _raw, _sh, key: destroyed.append(key),
    )
    monkeypatch.setattr(set_attr, "set_attributes", lambda *_a, **_k: None)
    readbacks = iter(
        (
            {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: False, CKA_CLASS: CKO_SECRET_KEY},
        )
    )
    monkeypatch.setattr(set_attr, "read_attributes", lambda *_a, **_k: next(readbacks))
    monkeypatch.setattr(
        set_attr,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0)
    session = SimpleNamespace(raw=raw, sh=1)

    with pytest.raises(pytest.fail.Exception) as exc_info:
        set_attr.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)
    assert not isinstance(exc_info.value, pytest.xfail.Exception)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[1].reason == "honest_deviation"
    assert records[1].actual_ckr == "CKR_OK"
    assert records[1].detail is not None
    assert records[1].detail["attributes"][0]["readback"] == "malformed"
    assert destroyed == [7]


def _readonly_write(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    classification.clear()
    monkeypatch.setattr(
        set_attr,
        "set_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exc),
    )
    monkeypatch.setattr(
        set_attr,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_CLASS: 0x04},
    )
    set_attr._classify_readonly_write(
        SimpleNamespace(raw=object(), sh=1),
        7,
        CKA_CLASS,
        CKO_PUBLIC_KEY,
        label="read-only attribute",
    )


def test_readonly_write_expected_rejection_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _readonly_write(
        monkeypatch,
        CkrAssertionError("read-only", int(CKR_ATTRIBUTE_READ_ONLY)),
    )
    assert classification.get_records() == []


@pytest.mark.parametrize("rv", [CKR_GENERAL_ERROR, int(CKR_VENDOR_DEFINED) + 1])
def test_readonly_write_clean_nonspec_rejection_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _readonly_write(monkeypatch, CkrAssertionError("clean refusal", int(rv)))
    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_readonly_write_undefined_ckr_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _readonly_write(monkeypatch, CkrAssertionError("undefined", 0x7FFFFFFF))
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_readonly_write_non_ckr_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError, match="harness bug"):
        _readonly_write(monkeypatch, AssertionError("harness bug"))

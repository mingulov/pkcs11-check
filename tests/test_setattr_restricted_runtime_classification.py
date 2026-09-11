"""Runtime regressions for restricted-attribute evidence handling."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_SENSITIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_setattr_restricted as restricted
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _session(setter_rv: int = int(CKR_OK)) -> SimpleNamespace:
    raw = SimpleNamespace(
        C_SetAttributeValue=lambda *_args, **_kwargs: int(setter_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)


def _setup_key(monkeypatch: pytest.MonkeyPatch, *, reads: Any) -> None:
    monkeypatch.setattr(restricted, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(restricted, "read_attributes", reads)
    monkeypatch.setattr(restricted, "destroy_quietly", lambda *_a, **_k: None)


def test_setattr_restricted_attribute_access_slice_is_analyzer_clean() -> None:
    path = (
        Path(__file__).parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "test_setattr_restricted.py"
    )

    assert analyze_file(path) == []


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_read_bool_distinguishes_present_false_like_values(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(
        restricted,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: value},
    )

    result = restricted._read_bool(_session(), 7, CKA_SENSITIVE)

    assert result is value
    assert result is not MISSING_ATTRIBUTE
    assert C.get_records() == []


def test_read_bool_missing_is_structured_and_noncolliding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(restricted, "read_attributes", lambda *_a, **_k: {})

    result = restricted._read_bool(_session(), 7, CKA_SENSITIVE)

    assert result is MISSING_ATTRIBUTE
    record = C.get_records()[0]
    assert record.reason == "honest_deviation"
    assert record.operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert record.mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_GEN" in record.label
    assert record.actual_ckr is None
    assert record.detail == {
        "attribute": {"name": "CKA_SENSITIVE", "id": int(CKA_SENSITIVE)},
    }


@pytest.mark.parametrize("value", [0, b"", None])
def test_present_malformed_bool_is_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    _setup_key(monkeypatch, reads=lambda *_a, **_k: {CKA_SENSITIVE: value})
    destroyed: list[int] = []
    monkeypatch.setattr(
        restricted,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_downgrade_sensitive_to_false(_session())

    assert not isinstance(exc_info.value, XFailed)
    record = next(
        record
        for record in C.get_records()
        if record.reason == "wrong_result" and record.mechanism == "CKM_AES_KEY_GEN"
    )
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == int(CKA_SENSITIVE)
    assert destroyed == [7]


def test_missing_baseline_still_attempts_setter_and_preserves_setter_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return {}

    _setup_key(monkeypatch, reads=_read)
    session = _session(int(CKR_FUNCTION_NOT_SUPPORTED))
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(XFailed):
        restricted.test_cannot_downgrade_sensitive_to_false(session)

    assert calls == ["read", "set", "read"]
    setter_records = [
        record for record in C.get_records() if record.operation == "C_SetAttributeValue"
    ]
    assert len(setter_records) == 1
    assert setter_records[0].actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert setter_records[0].expected_ckr


def test_missing_baseline_with_accepted_class_target_does_not_infer_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(({}, {int(CKA_CLASS): 0}))

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    session = _session()
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(XFailed):
        restricted.test_cannot_mutate_class(session)

    assert calls == ["read", "set", "read"]
    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "honest_deviation",
    ]
    setter_record = C.get_records()[-1]
    assert setter_record.operation == "C_SetAttributeValue"
    assert setter_record.mechanism is None
    assert setter_record.actual_ckr == "CKR_OK"
    assert setter_record.detail is not None
    assert setter_record.detail["effect"] == "unproven"
    assert setter_record.kind == "lifecycle"
    assert setter_record.reason == "honest_deviation"
    assert not any(record.reason == "self_contradiction" for record in C.get_records())


def test_preexisting_data_class_is_not_attributed_to_rejected_setter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(({int(CKA_CLASS): 0}, {int(CKA_CLASS): 0}))

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    session = _session(int(CKR_ATTRIBUTE_READ_ONLY))
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(XFailed):
        restricted.test_cannot_mutate_class(session)

    assert calls == ["read", "set", "read"]
    assert [record.reason for record in C.get_records()] == ["honest_deviation"]
    assert not any(record.reason == "self_contradiction" for record in C.get_records())


def test_class_ok_unchanged_is_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(
        (
            {int(CKA_CLASS): int(CKO_SECRET_KEY)},
            {int(CKA_CLASS): int(CKO_SECRET_KEY)},
        )
    )

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    session = _session()
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(XFailed):
        restricted.test_cannot_mutate_class(session)

    assert calls == ["read", "set", "read"]
    setter_records = [
        record for record in C.get_records() if record.operation == "C_SetAttributeValue"
    ]
    assert len(setter_records) == 1
    assert setter_records[0].reason == "honest_deviation"
    assert setter_records[0].kind == "lifecycle"
    assert setter_records[0].mechanism is None
    assert setter_records[0].actual_ckr == "CKR_OK"
    assert setter_records[0].expected_ckr
    assert setter_records[0].detail is not None
    assert setter_records[0].detail["effect"] == "unchanged"
    assert not any(record.reason == "self_contradiction" for record in C.get_records())


def test_class_ok_trusted_transition_is_hard_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(
        (
            {int(CKA_CLASS): int(CKO_SECRET_KEY)},
            {int(CKA_CLASS): 0},
        )
    )

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        restricted,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    session = _session()
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_mutate_class(session)

    assert not isinstance(exc_info.value, XFailed)
    assert calls == ["read", "set", "read"]
    assert destroyed == [7]
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.operation == "C_SetAttributeValue"
    assert record.mechanism is None
    assert record.expected_ckr
    assert record.actual_ckr == "CKR_OK"
    assert record.detail is not None
    assert record.detail["expected"] == "CKO_SECRET_KEY"
    assert record.detail["actual"] == "CKO_DATA"


def test_rejected_setter_that_changes_class_is_a_hard_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: Iterator[dict[int, Any]] = iter(
        (
            {int(CKA_CLASS): int(CKO_SECRET_KEY)},
            {int(CKA_CLASS): 0},
        )
    )
    _setup_key(monkeypatch, reads=lambda *_a, **_k: next(reads))
    session = _session(int(CKR_ATTRIBUTE_READ_ONLY))

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_mutate_class(session)

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.operation == "C_SetAttributeValue"
    assert record.actual_ckr == "CKR_ATTRIBUTE_READ_ONLY"
    assert record.detail is not None
    assert record.detail["expected"] == "CKO_SECRET_KEY"
    assert record.detail["actual"] == "CKO_DATA"


def test_malformed_class_baseline_still_runs_setter_and_postread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(
        (
            {int(CKA_CLASS): b"bad"},
            {int(CKA_CLASS): int(CKO_SECRET_KEY)},
        )
    )

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    session = _session(int(CKR_ATTRIBUTE_READ_ONLY))
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_mutate_class(session)

    assert not isinstance(exc_info.value, XFailed)
    assert calls == ["read", "set", "read"]
    assert any(record.reason == "wrong_result" for record in C.get_records())
    assert not any(record.reason == "self_contradiction" for record in C.get_records())


def test_malformed_bool_baseline_runs_setter_and_postread_before_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    reads: Iterator[dict[int, Any]] = iter(
        (
            {int(CKA_SENSITIVE): 0},
            {int(CKA_SENSITIVE): True},
        )
    )

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        calls.append("read")
        return next(reads)

    _setup_key(monkeypatch, reads=_read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        restricted,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    session = _session(int(CKR_FUNCTION_NOT_SUPPORTED))
    original_setter = session.raw.C_SetAttributeValue

    def _set(*args: object, **kwargs: object) -> int:
        calls.append("set")
        return int(original_setter(*args, **kwargs))

    session.raw.C_SetAttributeValue = _set

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_downgrade_sensitive_to_false(session)

    assert not isinstance(exc_info.value, XFailed)
    assert calls == ["read", "set", "read"]
    assert destroyed == [7]
    assert [record.reason for record in C.get_records()] == [
        "wrong_result",
        "nonspec_reject",
    ]


def test_class_setter_ok_evidence_is_retained_when_readback_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup_key(monkeypatch, reads=lambda *_a, **_k: {CKA_CLASS: b"malformed"})

    with pytest.raises(Failed) as exc_info:
        restricted.test_cannot_mutate_class(_session())

    assert not isinstance(exc_info.value, XFailed)
    setter_records = [
        record for record in C.get_records() if record.operation == "C_SetAttributeValue"
    ]
    assert len(setter_records) == 1
    assert setter_records[0].actual_ckr == "CKR_OK"
    assert setter_records[0].reason == "honest_deviation"
    assert setter_records[0].kind == "lifecycle"
    assert setter_records[0].detail is not None
    assert setter_records[0].detail["attribute"]["id"] == int(CKA_CLASS)
    assert setter_records[0].detail["effect"] == "unproven"


def test_class_readback_ckr_does_not_erase_setter_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup_key(
        monkeypatch,
        reads=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected readback error", int(CKR_ATTRIBUTE_TYPE_INVALID))
        ),
    )

    with pytest.raises(XFailed):
        restricted.test_cannot_mutate_class(_session())

    setter_records = [
        record for record in C.get_records() if record.operation == "C_SetAttributeValue"
    ]
    assert len(setter_records) == 1
    assert setter_records[0].reason == "honest_deviation"
    assert setter_records[0].kind == "lifecycle"
    assert setter_records[0].actual_ckr == "CKR_OK"
    assert setter_records[0].detail is not None
    assert setter_records[0].detail["effect"] == "unproven"

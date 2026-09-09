"""Runtime classification meta-tests for test_set_attribute read-only writes (lifecycle).

A write to a read-only attribute via C_SetAttributeValue is classified by effect:
- claimed success (no raise) AND the value actually changed -> fail (self-contradiction),
- claimed success but the value is unchanged (no-op) -> xfail (wrong code, no harm),
- rejected -> pass.
"""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_VALUE,
    CKK_AES,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases import test_set_attribute as tsa
from tests._attribute_access_guard import analyze_file


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    classification.clear()
    yield
    classification.clear()


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    accepted: bool,
    readback: dict[Any, Any],
    readbacks: tuple[dict[Any, Any], dict[Any, Any]] | None = None,
) -> None:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    if accepted:
        monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    else:

        def _reject(*_a: object, **_k: object) -> None:
            raise CkrAssertionError("rv", int(CKR_ATTRIBUTE_READ_ONLY))

        monkeypatch.setattr(tsa, "set_attributes", _reject)
    if readbacks is None:
        monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: dict(readback))
    else:
        values = iter(readbacks)
        monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(values))


_CASES = {
    "class": (
        "test_cannot_change_class",
        "TestSetAttributeNegative",
        CKA_CLASS,
        CKO_PUBLIC_KEY,
    ),
    "key_type": (
        "test_cannot_change_key_type",
        "TestSetAttributeNegative",
        CKA_KEY_TYPE,
        CKK_RSA,
    ),
    "modulus": (
        "test_cannot_change_modulus",
        "TestSetAttributeNegative",
        CKA_MODULUS,
        b"\x00" * 256,
    ),
    "value": (
        "test_cannot_set_value_on_sensitive_key",
        "TestSetAttributeNegative",
        CKA_VALUE,
        b"\x00" * 32,
    ),
}


def _run(monkeypatch: pytest.MonkeyPatch, case: str, *, accepted: bool, changed: bool) -> None:
    method, cls, attr, new_val = _CASES[case]
    # When "changed", the read-back returns the attempted value.  Otherwise it
    # returns a well-typed original value, which is evidence of a no-op.  An
    # omitted value is a separate case: it cannot prove either effect.
    unchanged: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_MODULUS: b"original-modulus",
        CKA_VALUE: b"original-value",
    }
    readback = {attr: new_val} if changed else {attr: unchanged[attr]}
    readbacks = (
        ({attr: unchanged[attr]}, {attr: new_val})
        if changed
        else ({attr: unchanged[attr]}, {attr: unchanged[attr]})
    )
    _setup(monkeypatch, accepted=accepted, readback=readback, readbacks=readbacks)
    getattr(getattr(tsa, cls)(), method)(_session())


@pytest.mark.parametrize("case", list(_CASES))
def test_changed_fails(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, case, accepted=True, changed=True)
    assert not isinstance(ei.value, XFailed)


@pytest.mark.parametrize("case", list(_CASES))
def test_noop_xfails(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, case, accepted=True, changed=False)


@pytest.mark.parametrize("case", list(_CASES))
def test_rejected_passes(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    _run(monkeypatch, case, accepted=False, changed=False)


def _positive_label_setup(
    monkeypatch: pytest.MonkeyPatch,
    readbacks: tuple[dict[int, Any] | CkrAssertionError, dict[int, Any] | CkrAssertionError],
    *,
    setter_error: CkrAssertionError | None = None,
) -> tuple[SimpleNamespace, list[int], list[int]]:
    destroyed: list[int] = []
    setters: list[int] = []
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda _raw, _sh, key: destroyed.append(key))
    if setter_error is None:
        monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: setters.append(1))
    else:

        def _set(*_a: object, **_k: object) -> None:
            setters.append(1)
            raise setter_error

        monkeypatch.setattr(tsa, "set_attributes", _set)
    values = iter(readbacks)

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        value = next(values)
        if isinstance(value, CkrAssertionError):
            raise value
        return value

    monkeypatch.setattr(tsa, "read_attributes", _read)
    monkeypatch.setattr(tsa, "find_objects", lambda *_a, **_k: [1])
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=1),
    )
    return _session(), destroyed, setters


@pytest.mark.parametrize("initial", [False, "provider-before"])
def test_positive_label_initial_bad_readback_does_not_skip_setter_or_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    initial: Any,
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        ({CKA_LABEL: initial}, {CKA_LABEL: "after"}),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributePositive().test_change_label(session)

    records = classification.get_records()
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].reason == ("wrong_result" if initial is False else "wrong_result")
    assert len(setters) == 1
    assert destroyed == [1]
    assert all(record.operation is not None for record in records)


def test_positive_label_post_semantic_mismatch_is_setter_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        ({CKA_LABEL: "before"}, {CKA_LABEL: "unexpected-after"}),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributePositive().test_change_label(session)

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_SetAttributeValue"
    assert records[0].reason == "wrong_result"
    assert records[0].actual_ckr == "CKR_OK"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr("unexpected-after")
    assert len(setters) == 1
    assert destroyed == [1]


@pytest.mark.parametrize("post", ["after", "third-after"])
def test_positive_label_rejected_setter_then_transition_is_hard(
    monkeypatch: pytest.MonkeyPatch,
    post: str,
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        ({CKA_LABEL: "before"}, {CKA_LABEL: post}),
        setter_error=CkrAssertionError("read-only", int(CKR_ATTRIBUTE_READ_ONLY)),
    )

    with pytest.raises(Failed) as exc_info:
        tsa.TestSetAttributePositive().test_change_label(session)
    assert not isinstance(exc_info.value, XFailed)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_SetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[0].reason == "nonspec_reject"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_READ_ONLY"
    assert records[1].reason == "self_contradiction"
    assert records[1].kind == "lifecycle"
    assert records[1].actual_ckr == "CKR_ATTRIBUTE_READ_ONLY"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["baseline"] == repr("before")
    assert records[1].detail["attribute"]["actual"] == repr(post)
    assert len(setters) == 1
    assert destroyed == [1]


def test_positive_label_general_error_change_is_explicitly_unspecified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        ({CKA_LABEL: "before"}, {CKA_LABEL: "after"}),
        setter_error=CkrAssertionError("unspecified", int(CKR_GENERAL_ERROR)),
    )

    with pytest.raises(XFailed):
        tsa.TestSetAttributePositive().test_change_label(session)

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_SetAttributeValue"
    assert records[0].reason == "nonspec_reject"
    assert records[0].actual_ckr == "CKR_GENERAL_ERROR"
    assert all(record.reason != "self_contradiction" for record in records)
    assert len(setters) == 1
    assert destroyed == [1]


@pytest.mark.parametrize("post", [{}, {CKA_LABEL: False}])
def test_positive_label_post_unavailable_or_malformed_is_get_finding(
    monkeypatch: pytest.MonkeyPatch,
    post: dict[int, Any],
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        ({CKA_LABEL: "before"}, post),
    )

    if post:
        with pytest.raises(Failed):
            tsa.TestSetAttributePositive().test_change_label(session)
    else:
        tsa.TestSetAttributePositive().test_change_label(session)

    records = classification.get_records()
    assert records[-1].operation == "C_GetAttributeValue"
    assert records[-1].detail is not None
    assert records[-1].detail["attribute"]["id"] == int(CKA_LABEL)
    assert len(setters) == 1
    assert destroyed == [1]


def test_positive_label_reader_ckr_is_get_finding_and_setter_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, destroyed, setters = _positive_label_setup(
        monkeypatch,
        (
            {CKA_LABEL: "before"},
            CkrAssertionError("readback", int(CKR_GENERAL_ERROR)),
        ),
    )

    with pytest.raises(XFailed):
        tsa.TestSetAttributePositive().test_change_label(session)

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr == "CKR_GENERAL_ERROR"
    assert records[0].outcome == "xfail"
    assert len(setters) == 1
    assert destroyed == [1]


def test_missing_readback_is_visible_without_claiming_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=True, readback={})

    tsa.TestSetAttributeNegative().test_cannot_change_class(_session())

    records = classification.get_records()
    assert len(records) == 3
    assert [record.reason for record in records] == [
        "honest_deviation",
        "honest_deviation",
        "honest_deviation",
    ]
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert all(record.outcome == "xfail" for record in records)
    assert all(record.actual_ckr is None for record in records[:2])
    assert records[0].detail == {
        "attribute": {"name": "CKA_CLASS", "id": int(CKA_CLASS)},
    }
    assert records[2].actual_ckr == "CKR_OK"


@pytest.mark.parametrize(
    ("case", "value"),
    [
        ("class", False),
        ("value", None),
    ],
)
def test_present_malformed_readback_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    value: Any,
) -> None:
    method, cls, attr, _new_value = _CASES[case]
    _setup(monkeypatch, accepted=True, readback={attr: value})

    with pytest.raises(Failed) as exc_info:
        getattr(getattr(tsa, cls)(), method)(_session())
    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == int(attr)
    assert record.detail["attribute"]["actual"] == repr(value)


def test_readonly_ckr_ok_malformed_post_readback_keeps_setter_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(
        monkeypatch,
        accepted=True,
        readback={CKA_CLASS: CKO_SECRET_KEY},
        readbacks=({CKA_CLASS: CKO_SECRET_KEY}, {CKA_CLASS: False}),
    )

    with pytest.raises(Failed) as exc_info:
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())
    assert not isinstance(exc_info.value, XFailed)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].reason == "honest_deviation"
    assert records[1].operation == "C_SetAttributeValue"
    assert records[1].actual_ckr == "CKR_OK"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["readback"] == "malformed"


def test_false_like_present_values_are_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=True, readback={CKA_CLASS: 0})

    # Zero is a present, well-typed CK_ULONG.  It is not an omission and it
    # cannot be used as the generated AES key's CKA_CLASS baseline.
    with pytest.raises(Failed):
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())

    record = classification.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(0)


def test_readonly_third_state_is_hard_failure_not_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=True, readback={CKA_CLASS: CKO_SECRET_KEY})
    readbacks = iter(({CKA_CLASS: CKO_SECRET_KEY}, {CKA_CLASS: 0}))
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(readbacks))

    with pytest.raises(Failed) as exc_info:
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())
    assert not isinstance(exc_info.value, XFailed)

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_SetAttributeValue"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail is not None
    assert record.detail["attribute"]["baseline"] == repr(CKO_SECRET_KEY)
    assert record.detail["attribute"]["actual"] == repr(0)


def test_readonly_mismatched_baseline_still_detects_later_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=True, readback={CKA_CLASS: CKO_SECRET_KEY})
    readbacks = iter(({CKA_CLASS: 0}, {CKA_CLASS: CKO_SECRET_KEY}))
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(readbacks))

    with pytest.raises(Failed):
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[0].reason == "wrong_result"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr(0)
    assert records[1].reason == "self_contradiction"
    assert records[1].operation == "C_SetAttributeValue"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["baseline"] == repr(0)
    assert records[1].detail["attribute"]["actual"] == repr(CKO_SECRET_KEY)


def test_readonly_baseline_equal_to_requested_unchanged_is_not_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=True, readback={CKA_CLASS: CKO_PUBLIC_KEY})
    readbacks = iter(({CKA_CLASS: CKO_PUBLIC_KEY}, {CKA_CLASS: CKO_PUBLIC_KEY}))
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(readbacks))

    with pytest.raises(Failed):
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())

    records = classification.get_records()
    assert len(records) == 2
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].reason == "honest_deviation"
    assert records[1].operation == "C_SetAttributeValue"


def test_readonly_expected_reject_with_changed_post_is_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, accepted=False, readback={CKA_CLASS: CKO_SECRET_KEY})
    readbacks = iter(({CKA_CLASS: CKO_SECRET_KEY}, {CKA_CLASS: CKO_PUBLIC_KEY}))
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(readbacks))

    with pytest.raises(Failed):
        tsa.TestSetAttributeNegative().test_cannot_change_class(_session())

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].operation == "C_SetAttributeValue"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_READ_ONLY"


def test_atomicity_retains_missing_evidence_for_each_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable multi-attribute oracle must not collapse to one omission."""
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0x12)
    session = SimpleNamespace(raw=raw, sh=1)

    tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
    ]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_LABEL),
        int(CKA_CLASS),
        int(CKA_LABEL),
        int(CKA_CLASS),
    ]
    assert all(record.actual_ckr is None for record in records)


def test_atomicity_ckr_ok_missing_readback_is_effect_unobservable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0)
    session = SimpleNamespace(raw=raw, sh=1)

    tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[4].actual_ckr == "CKR_OK"
    assert records[4].detail is not None
    assert "attributes" in records[4].detail


def test_atomicity_retains_missing_and_malformed_before_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed present row remains a hard finding without hiding another omission."""
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_LABEL: False},
    )
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0x12)
    session = SimpleNamespace(raw=raw, sh=1)

    with pytest.raises(Failed) as exc_info:
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)
    assert not isinstance(exc_info.value, XFailed)

    records = classification.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "wrong_result",
        "honest_deviation",
        "wrong_result",
    ]
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
        "C_GetAttributeValue",
    ]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_CLASS),
        int(CKA_LABEL),
        int(CKA_CLASS),
        int(CKA_LABEL),
    ]


def test_atomicity_records_both_malformed_legs_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_LABEL: False, CKA_CLASS: False},
    )
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0x12)
    session = SimpleNamespace(raw=raw, sh=1)

    with pytest.raises(Failed) as exc_info:
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)
    assert not isinstance(exc_info.value, XFailed)

    records = classification.get_records()
    assert [record.reason for record in records] == [
        "wrong_result",
        "wrong_result",
        "wrong_result",
        "wrong_result",
    ]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_LABEL),
        int(CKA_CLASS),
        int(CKA_LABEL),
        int(CKA_CLASS),
    ]


def _atomic_session(
    monkeypatch: pytest.MonkeyPatch,
    *,
    rv: int,
    readbacks: tuple[dict[int, Any], dict[int, Any]],
) -> SimpleNamespace:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    reads = iter(readbacks)
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    return SimpleNamespace(
        raw=SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: int(rv)),
        sh=1,
    )


def test_atomicity_uses_observed_baseline_and_attributes_setup_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed setup state is not silently compared with an assumed baseline."""
    session = _atomic_session(
        monkeypatch,
        rv=CKR_ATTRIBUTE_READ_ONLY,
        readbacks=(
            {CKA_LABEL: "provider-before", CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: "provider-before", CKA_CLASS: CKO_SECRET_KEY},
        ),
    )

    with pytest.raises(Failed, match="setup did not preserve"):
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["name"] == "CKA_LABEL"
    assert records[0].detail["attribute"]["actual"] == repr("provider-before")


def test_atomicity_mismatched_baseline_still_records_later_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _atomic_session(
        monkeypatch,
        rv=CKR_ATTRIBUTE_READ_ONLY,
        readbacks=(
            {CKA_LABEL: "provider-before", CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: "atomic-after", CKA_CLASS: CKO_SECRET_KEY},
        ),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert records[0].reason == "wrong_result"
    assert records[1].reason == "self_contradiction"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["name"] == "CKA_LABEL"
    assert records[1].detail["attribute"]["baseline"] == repr("provider-before")


def test_atomicity_baseline_equal_to_requested_unchanged_is_not_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _atomic_session(
        monkeypatch,
        rv=0,
        readbacks=(
            {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_PUBLIC_KEY},
            {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_PUBLIC_KEY},
        ),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.reason for record in records] == [
        "wrong_result",
        "honest_deviation",
    ]
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]


@pytest.mark.parametrize("rv", [int(CKR_ATTRIBUTE_READ_ONLY), 0])
def test_atomicity_evaluates_both_third_state_legs(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    session = _atomic_session(
        monkeypatch,
        rv=rv,
        readbacks=(
            {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: "unexpected-label", CKA_CLASS: CKO_PRIVATE_KEY},
        ),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.reason for record in records] == [
        "self_contradiction",
        "self_contradiction",
    ]
    assert [record.operation for record in records] == [
        "C_SetAttributeValue",
        "C_SetAttributeValue",
    ]
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_LABEL",
        "CKA_CLASS",
    ]
    assert all(
        record.actual_ckr == ("CKR_OK" if rv == 0 else "CKR_ATTRIBUTE_READ_ONLY")
        for record in records
    )


@pytest.mark.parametrize(
    ("rv", "reason", "outcome", "actual"),
    [
        (int(CKR_GENERAL_ERROR), "nonspec_reject", "xfail", "CKR_GENERAL_ERROR"),
        (0x7FFFFFFF, "self_contradiction", "fail", "0x7fffffff"),
    ],
)
def test_atomicity_retains_setter_ckr_alongside_hard_read(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    reason: str,
    outcome: str,
    actual: str,
) -> None:
    session = _atomic_session(
        monkeypatch,
        rv=rv,
        readbacks=(
            {CKA_LABEL: False, CKA_CLASS: CKO_SECRET_KEY},
            {CKA_LABEL: False, CKA_CLASS: CKO_SECRET_KEY},
        ),
    )

    with pytest.raises(Failed):
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_GetAttributeValue",
    ]
    setter_record = records[1]
    assert setter_record.reason == reason
    assert setter_record.outcome == outcome
    assert setter_record.actual_ckr == actual
    assert records[0].reason == "wrong_result"
    assert records[2].reason == "wrong_result"


@pytest.mark.parametrize(
    ("reader_rv", "exception", "raises"),
    [
        (
            int(CKR_GENERAL_ERROR),
            CkrAssertionError("defined post read", int(CKR_GENERAL_ERROR)),
            False,
        ),
        (0x7FFFFFFF, CkrAssertionError("undefined post read", 0x7FFFFFFF), True),
    ],
)
def test_atomicity_post_reader_ckr_preserves_setter_effect_evidence(
    monkeypatch: pytest.MonkeyPatch,
    reader_rv: int,
    exception: CkrAssertionError,
    raises: bool,
) -> None:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    reads: list[dict[int, Any] | CkrAssertionError] = [
        {CKA_LABEL: "atomic-before", CKA_CLASS: CKO_SECRET_KEY},
        exception,
    ]

    def _read(*_a: object, **_k: object) -> dict[int, Any]:
        item = reads.pop(0)
        if isinstance(item, CkrAssertionError):
            raise item
        return item

    monkeypatch.setattr(tsa, "read_attributes", _read)
    monkeypatch.setattr(
        tsa,
        "template",
        lambda *_a, **_k: SimpleNamespace(ptr=None, count=2),
    )
    session = SimpleNamespace(
        raw=SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: 0),
        sh=1,
    )

    context = pytest.raises(Failed) if raises else nullcontext()
    with context:
        tsa.TestSetAttributeAtomicity().test_set_attribute_mixed_template_is_atomic(session)

    records = classification.get_records()
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
    ]
    reader_record, setter_record = records
    assert reader_record.operation == "C_GetAttributeValue"
    assert reader_record.actual_ckr == (
        "CKR_GENERAL_ERROR" if reader_rv == int(CKR_GENERAL_ERROR) else "0x7fffffff"
    )
    assert reader_record.outcome == ("xfail" if not raises else "fail")
    assert setter_record.reason == "honest_deviation"
    assert setter_record.actual_ckr == "CKR_OK"


def test_set_attribute_access_slice_is_analyzer_clean() -> None:
    assert analyze_file("src/pkcs11_check/testcases/test_set_attribute.py") == []

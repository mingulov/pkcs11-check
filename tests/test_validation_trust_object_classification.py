"""Regression tests for validation/trust metadata error routing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ISSUER,
    CKA_TRUST_SERVER_AUTH,
    CKA_VALIDATION_AUTHORITY_TYPE,
    CKA_VALIDATION_MODULE_ID,
    CKA_VALIDATION_TYPE,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_FAILED,
    CKT_TRUST_UNKNOWN,
)
from pkcs11_check.testcases import test_trust_objects as trust
from pkcs11_check.testcases import test_validation_objects as validation


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    clear_notes()
    yield
    C.clear()
    clear_notes()


@pytest.mark.parametrize(
    ("finder", "module"),
    [
        (validation._find_validation_objects, validation),
        (trust._find_trust_objects, trust),
    ],
)
def test_metadata_enumeration_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
    finder: Any,
    module: Any,
) -> None:
    monkeypatch.setattr(
        module,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("harness bug")),
    )

    with pytest.raises(AssertionError, match="harness bug"):
        finder(_session().raw, 1)


@pytest.mark.parametrize(
    "finder",
    [validation._find_validation_objects, trust._find_trust_objects],
)
def test_metadata_enumeration_ckr_failure_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
    finder: Any,
) -> None:
    monkeypatch.setattr(
        validation if finder is validation._find_validation_objects else trust,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))
        ),
    )

    with pytest.raises(XFailed):
        finder(_session().raw, 1)


def test_validation_enumeration_undefined_ckr_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation,
        "find_objects",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("undefined CK_RV", 0x12345678)
        ),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        validation._find_validation_objects(_session().raw, 1)


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_READ_ONLY, CKR_ACTION_PROHIBITED])
def test_validation_read_only_write_acceptance_and_rejections_are_distinct(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(
        validation,
        "set_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CkrAssertionError("read-only", int(rv))),
    )

    validation.TestValidationObjects().test_validation_objects_are_read_only(_session())


def test_validation_read_only_write_acceptance_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(validation, "set_attributes", lambda *_args, **_kwargs: None)

    with pytest.raises(Failed, match="accepted"):
        validation.TestValidationObjects().test_validation_objects_are_read_only(_session())


def test_validation_unknown_type_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1])
    monkeypatch.setattr(
        validation,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALIDATION_TYPE: 0x1234},
    )

    with pytest.raises(AssertionError, match="Unknown non-vendor validation type"):
        validation.TestValidationObjects().test_validation_type_is_known(_session())


def test_trust_unknown_value_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_args: [1])
    monkeypatch.setattr(
        trust,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_TRUST_SERVER_AUTH: 0x1234},
    )

    with pytest.raises(AssertionError, match="Unknown TRUST_SERVER_AUTH"):
        trust.TestTrustObjects().test_trust_server_auth_is_known_value(_session())


def test_trust_read_failure_with_undefined_ckr_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_args: [1])
    monkeypatch.setattr(
        trust,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("undefined CK_RV", 0x12345678)
        ),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        trust.TestTrustObjects().test_trust_server_auth_is_known_value(_session())


def test_missing_required_trust_issuer_records_and_continues_to_next_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "_find_trust_objects", lambda *_args: [1, 2])
    read_handles: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, object]:
        read_handles.append(handle)
        return {}

    monkeypatch.setattr(trust, "read_attributes", _read)

    trust.TestTrustObjects().test_trust_objects_have_issuer(_session())

    assert read_handles == [1, 2]
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "honest_deviation"]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_ISSUER),
        int(CKA_ISSUER),
    ]


@pytest.mark.parametrize(
    ("method_name", "attribute"),
    [
        (
            "test_validation_authority_type_is_known",
            CKA_VALIDATION_AUTHORITY_TYPE,
        ),
        ("test_validation_module_id_is_string", CKA_VALIDATION_MODULE_ID),
    ],
)
def test_missing_required_validation_metadata_records_and_continues(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    attribute: int,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_args: [1, 2])
    read_handles: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, object]:
        read_handles.append(handle)
        return {}

    monkeypatch.setattr(validation, "read_attributes", _read)

    getattr(validation.TestValidationObjects(), method_name)(_session())

    assert read_handles == [1, 2]
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "honest_deviation"]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(attribute),
        int(attribute),
    ]


def test_absent_trust_usage_uses_table_25_unknown_default_without_record() -> None:
    """The Table 25 absent-default is the spec-defined case, not a deviation from
    it: applying it must NEVER emit a classification record (that would manufacture
    a finding against a conformant provider)."""
    present, value = trust._trust_usage_value_or_unknown({}, CKA_TRUST_SERVER_AUTH)

    assert present is False
    assert value == CKT_TRUST_UNKNOWN
    assert C.get_records() == []


def test_absent_trust_usage_still_emits_a_compliance_note() -> None:
    """The classification-free Table 25 default must not silently drop the
    observation either: the omitted attribute is surfaced via a non-gating
    compliance note so a report can still distinguish a provider that returns
    trust usages from one that returns none."""
    present, value = trust._trust_usage_value_or_unknown({}, CKA_TRUST_SERVER_AUTH)

    assert present is False
    assert value == CKT_TRUST_UNKNOWN
    notes = get_notes()
    assert len(notes) == 1
    assert "CKA_TRUST_SERVER_AUTH" in notes[0].description
    assert C.get_records() == []


def test_trust_usage_value_or_unknown_rejects_non_trust_attribute() -> None:
    """The Table 25 absent-default is bounded to the CKA_TRUST_* usage-attribute
    family; it must never silently apply to an unrelated attribute id."""
    with pytest.raises(ValueError, match="CKA_TRUST_"):
        trust._trust_usage_value_or_unknown({}, CKA_ISSUER)

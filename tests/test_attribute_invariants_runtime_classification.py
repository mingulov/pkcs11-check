"""Runtime classification meta-tests for test_attribute_invariants (metadata).

metadata = derived-attribute invariant. A suite-generated key created with
``CKA_EXTRACTABLE=False`` and never modified MUST read back
``CKA_NEVER_EXTRACTABLE=True`` (PKCS#11 v3.1 Sec.4.9.4); a key created with
``CKA_SENSITIVE=True`` and never modified MUST read back
``CKA_ALWAYS_SENSITIVE=True``.

The classification (3-way):

- precondition holds (the base attribute reads back the protective value) AND
  the derived attribute contradicts it (False) -> ``fail`` (self-contradiction),
- the derived attribute is absent / unsupported -> ``xfail`` (honest non-support),
- the base attribute itself did not take effect (isolated wrong value, not the
  derived-invariant contradiction under test) -> ``xfail``,
- precondition holds and the derived attribute agrees (True) -> ``pass``.
"""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_GEN_MECHANISM,
    CKA_LOCAL,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_VERIFY,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases import test_attribute_invariants as tai
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _reader(values: dict[int, object]):  # type: ignore[no-untyped-def]
    """read_attributes stub returning only the requested+present attributes."""

    def _read(
        _raw: object, _sh: object, _handle: object, attr_list: list[int]
    ) -> dict[int, object]:
        return {a: values[a] for a in attr_list if a in values}

    return _read


class _GetForbiddenMapping(dict[int, object]):
    """Provider mapping whose convenience ``get`` transport must not be used."""

    def get(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("provider attribute access must use membership and indexing")


def _setup(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    monkeypatch.setattr(tai, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(tai, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tai, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tai, "read_attributes", _reader(values))


# --- NEVER_EXTRACTABLE invariant -----------------------------------------


def _run_never_extractable(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    _setup(monkeypatch, values)
    tai.TestDerivedAttributeInvariants().test_never_extractable_when_created_non_extractable(
        _session()
    )


def test_never_extractable_contradiction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # EXTRACTABLE=False (precondition holds) but NEVER_EXTRACTABLE=False -> contradiction.
    C.set_mechanism("CKM_SHA256", "C_Sign")
    with pytest.raises(Failed) as ei:
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: False, CKA_NEVER_EXTRACTABLE: False},
        )
    assert not isinstance(ei.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2"
    assert record.detail == {
        "attribute": {"name": "CKA_NEVER_EXTRACTABLE", "id": int(CKA_NEVER_EXTRACTABLE)},
        "expected": True,
        "actual": False,
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_never_extractable_present_malformed_derived_is_hard_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_SHA256", "C_Sign")
    with pytest.raises(Failed) as exc_info:
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: False, CKA_NEVER_EXTRACTABLE: 0},
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.detail == {
        "attribute": {"name": "CKA_NEVER_EXTRACTABLE", "id": int(CKA_NEVER_EXTRACTABLE)},
        "expected": "CK_BBOOL boolean",
        "actual": "0",
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_never_extractable_absent_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # NEVER_EXTRACTABLE not reported (unsupported) -> honest non-support.
    _run_never_extractable(monkeypatch, {CKA_EXTRACTABLE: False})

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    # Readback attribution: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_GEN" in records[0].label
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_NEVER_EXTRACTABLE", "id": int(CKA_NEVER_EXTRACTABLE)},
    }


def test_never_extractable_missing_pair_records_each_attribute_before_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tai, "_classify_derived_invariant", lambda **_kwargs: None)
    _run_never_extractable(monkeypatch, {})

    records = C.get_records()
    assert [(record.operation, record.actual_ckr) for record in records] == [
        ("C_GetAttributeValue", None),
        ("C_GetAttributeValue", None),
    ]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_EXTRACTABLE),
        int(CKA_NEVER_EXTRACTABLE),
    ]


def test_never_extractable_base_not_applied_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # EXTRACTABLE read back True: the module ignored our False request -- an
    # isolated wrong value, not the derived-invariant contradiction under test.
    with pytest.raises(pytest.xfail.Exception):
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: True, CKA_NEVER_EXTRACTABLE: False},
        )


def test_never_extractable_base_deviation_keeps_exact_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_SHA256", "C_Sign")
    with pytest.raises(pytest.xfail.Exception):
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: True, CKA_NEVER_EXTRACTABLE: False},
        )

    record = C.get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.detail == {
        "attribute": {"name": "CKA_EXTRACTABLE", "id": int(CKA_EXTRACTABLE)},
        "expected": False,
        "actual": True,
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_never_extractable_consistent_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_never_extractable(
        monkeypatch,
        {CKA_EXTRACTABLE: False, CKA_NEVER_EXTRACTABLE: True},
    )


# --- ALWAYS_SENSITIVE invariant ------------------------------------------


def _run_always_sensitive(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    _setup(monkeypatch, values)
    tai.TestDerivedAttributeInvariants().test_always_sensitive_when_created_sensitive(_session())


def test_always_sensitive_contradiction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    C.set_mechanism("CKM_SHA256", "C_Sign")
    with pytest.raises(Failed) as ei:
        _run_always_sensitive(
            monkeypatch,
            {CKA_SENSITIVE: True, CKA_ALWAYS_SENSITIVE: False},
        )
    assert not isinstance(ei.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2"
    assert record.detail == {
        "attribute": {"name": "CKA_ALWAYS_SENSITIVE", "id": int(CKA_ALWAYS_SENSITIVE)},
        "expected": True,
        "actual": False,
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_always_sensitive_present_malformed_base_is_hard_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_SHA256", "C_Sign")
    with pytest.raises(Failed) as exc_info:
        _run_always_sensitive(
            monkeypatch,
            {CKA_SENSITIVE: 1, CKA_ALWAYS_SENSITIVE: True},
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.detail == {
        "attribute": {"name": "CKA_SENSITIVE", "id": int(CKA_SENSITIVE)},
        "expected": "CK_BBOOL boolean",
        "actual": "1",
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_always_sensitive_absent_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_always_sensitive(monkeypatch, {CKA_SENSITIVE: True})

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_GEN" in records[0].label
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_ALWAYS_SENSITIVE", "id": int(CKA_ALWAYS_SENSITIVE)},
    }


def test_always_sensitive_base_not_applied_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_always_sensitive(
            monkeypatch,
            {CKA_SENSITIVE: False, CKA_ALWAYS_SENSITIVE: False},
        )


def test_always_sensitive_consistent_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_always_sensitive(
        monkeypatch,
        {CKA_SENSITIVE: True, CKA_ALWAYS_SENSITIVE: True},
    )


# --- generated-key origin invariant --------------------------------------


def _run_generated_aes_origin(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    _setup(monkeypatch, values)
    tai.TestDerivedAttributeInvariants().test_generated_aes_key_reports_local_key_gen_mechanism(
        _session()
    )


def test_generated_aes_origin_wrong_mechanism_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_generated_aes_origin(
            monkeypatch,
            {
                CKA_LOCAL: True,
                CKA_KEY_GEN_MECHANISM: int(CKM_GENERIC_SECRET_KEY_GEN),
            },
        )
    assert not isinstance(ei.value, XFailed)
    record = C.get_records()[-1]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.detail == {
        "attribute": {
            "name": "CKA_KEY_GEN_MECHANISM",
            "id": int(CKA_KEY_GEN_MECHANISM),
        },
        "expected": int(CKM_AES_KEY_GEN),
        "actual": int(CKM_GENERIC_SECRET_KEY_GEN),
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_generated_aes_origin_missing_local_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_generated_aes_origin(
        monkeypatch,
        {CKA_KEY_GEN_MECHANISM: int(CKM_AES_KEY_GEN)},
    )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_GEN" in records[0].label
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_generated_origin_missing_pair_records_each_linked_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tai, "_classify_generated_key_origin_invariant", lambda **_kwargs: None)
    _run_generated_aes_origin(monkeypatch, {})

    records = C.get_records()
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_LOCAL),
        int(CKA_KEY_GEN_MECHANISM),
    ]
    assert all(record.actual_ckr is None for record in records)
    assert all(record.mechanism is None for record in records)
    assert all("producer_mechanism=CKM_AES_KEY_GEN" in record.label for record in records)


def test_generated_origin_wrong_mechanism_remains_hard_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_generated_aes_origin(
            monkeypatch,
            {
                CKA_LOCAL: True,
                CKA_KEY_GEN_MECHANISM: int(CKM_GENERIC_SECRET_KEY_GEN),
            },
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.outcome == "fail"


def test_generated_aes_origin_local_false_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_generated_aes_origin(
            monkeypatch,
            {CKA_LOCAL: False, CKA_KEY_GEN_MECHANISM: int(CKM_AES_KEY_GEN)},
        )


def test_generated_origin_present_malformed_local_is_hard_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_generated_aes_origin(
            monkeypatch,
            {CKA_LOCAL: 1, CKA_KEY_GEN_MECHANISM: int(CKM_AES_KEY_GEN)},
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
        "expected": "CK_BBOOL boolean",
        "actual": "1",
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_generated_aes_origin_missing_mechanism_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_generated_aes_origin(monkeypatch, {CKA_LOCAL: True})

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_GEN" in records[0].label
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_KEY_GEN_MECHANISM", "id": int(CKA_KEY_GEN_MECHANISM)},
    }


def test_generated_aes_origin_consistent_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_generated_aes_origin(
        monkeypatch,
        {CKA_LOCAL: True, CKA_KEY_GEN_MECHANISM: int(CKM_AES_KEY_GEN)},
    )


def test_generated_origin_preserves_mapping_values_without_get_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tai, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(tai, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tai, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        tai,
        "read_attributes",
        lambda *_a, **_k: _GetForbiddenMapping(
            {CKA_LOCAL: True, CKA_KEY_GEN_MECHANISM: int(CKM_AES_KEY_GEN)}
        ),
    )

    tai.TestDerivedAttributeInvariants().test_generated_aes_key_reports_local_key_gen_mechanism(
        _session()
    )


# --- imported-key origin invariant ---------------------------------------


def _run_imported_aes_origin(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[int, object],
    keygen_state: tuple[str, int | None],
) -> None:
    _setup(monkeypatch, values)
    monkeypatch.setattr(tai, "import_secret_key", lambda *_a, **_k: 1, raising=False)
    monkeypatch.setattr(tai, "_read_ulong_attr_state", lambda *_a: keygen_state, raising=False)
    monkeypatch.setattr(
        tai, "skip_unless_create_object_supported", lambda *_a, **_k: None, raising=False
    )
    tai.TestDerivedAttributeInvariants().test_imported_aes_key_reports_not_local_no_key_gen_mechanism(
        _session()
    )


def test_imported_aes_origin_readable_mechanism_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as ei:
        _run_imported_aes_origin(
            monkeypatch,
            {CKA_LOCAL: False},
            ("present", int(CKM_AES_KEY_GEN)),
        )
    assert not isinstance(ei.value, XFailed)
    record = C.get_records()[-1]
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.detail == {
        "attribute": {
            "name": "CKA_KEY_GEN_MECHANISM",
            "id": int(CKA_KEY_GEN_MECHANISM),
        },
        "expected": "CK_UNAVAILABLE_INFORMATION",
        "actual": int(CKM_AES_KEY_GEN),
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
    }


def test_imported_aes_origin_unavailable_mechanism_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_imported_aes_origin(monkeypatch, {CKA_LOCAL: False}, ("unavailable", None))


def test_imported_origin_present_malformed_local_is_hard_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_imported_aes_origin(monkeypatch, {CKA_LOCAL: 0}, ("unavailable", None))

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
        "expected": "CK_BBOOL boolean",
        "actual": "0",
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
    }


def test_imported_aes_origin_missing_local_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_imported_aes_origin(monkeypatch, {}, ("unavailable", None))

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_imported_origin_missing_local_records_exact_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tai, "_classify_imported_key_origin_invariant", lambda **_kwargs: None)
    _run_imported_aes_origin(monkeypatch, {}, ("unavailable", None))

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_faithful_readback_missing_pair_records_both_before_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {})
    monkeypatch.setattr(tai, "fail_as", lambda *_args, **_kwargs: None)

    tai.TestContradictoryCreationFaithfulness()._check_faithful_or_reject(
        _session(),
        attrs={CKA_SIGN: True, CKA_VERIFY: True},
        check_attrs=[CKA_SIGN, CKA_VERIFY],
        label="faithful readback",
    )

    records = C.get_records()
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_SIGN),
        int(CKA_VERIFY),
    ]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(
        f"attribute {attr!r} (producer_mechanism=CKM_AES_KEY_GEN)" in record.label
        for record, attr in zip(records, [CKA_SIGN, CKA_VERIFY], strict=True)
    )


def test_faithful_readback_missing_value_does_not_hide_present_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {CKA_VERIFY: False})

    with pytest.raises(Failed):
        tai.TestContradictoryCreationFaithfulness()._check_faithful_or_reject(
            _session(),
            attrs={CKA_SIGN: True, CKA_VERIFY: True},
            check_attrs=[CKA_SIGN, CKA_VERIFY],
            label="faithful readback",
        )

    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "self_contradiction",
    ]
    assert records[0].detail == {"attribute": {"name": "CKA_SIGN", "id": int(CKA_SIGN)}}
    assert records[1].actual_ckr is None
    assert records[1].expected_ckr is None
    assert records[1].operation == "C_GenerateKey"
    assert records[1].mechanism == "CKM_AES_KEY_GEN"
    assert records[1].detail is not None
    assert records[1].detail["actual"] is False
    assert records[1].detail["expected"] is True


def test_faithful_readback_bool_type_is_checked_before_equality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {CKA_SIGN: 1, CKA_VERIFY: True})

    with pytest.raises(Failed) as exc_info:
        tai.TestContradictoryCreationFaithfulness()._check_faithful_or_reject(
            _session(),
            attrs={CKA_SIGN: True, CKA_VERIFY: True},
            check_attrs=[CKA_SIGN, CKA_VERIFY],
            label="faithful readback",
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.detail == {
        "attribute": {"name": str(CKA_SIGN), "id": int(CKA_SIGN)},
        "expected": "CK_BBOOL boolean",
        "actual": "1",
    }


def test_imported_aes_origin_local_true_with_present_mechanism_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_imported_aes_origin(monkeypatch, {CKA_LOCAL: True}, ("present", int(CKM_AES_KEY_GEN)))

    assert not isinstance(exc_info.value, XFailed)
    assert C.get_records()[-1].reason == "self_contradiction"


def test_generated_origin_missing_local_does_not_hide_mechanism_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_generated_aes_origin(
            monkeypatch,
            {CKA_KEY_GEN_MECHANISM: int(CKM_GENERIC_SECRET_KEY_GEN)},
        )

    assert not isinstance(exc_info.value, XFailed)
    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]
    assert C.get_records()[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_imported_origin_missing_local_does_not_hide_present_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_imported_aes_origin(
            monkeypatch,
            {},
            ("present", int(CKM_AES_KEY_GEN)),
        )

    assert not isinstance(exc_info.value, XFailed)
    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]
    assert C.get_records()[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_imported_origin_missing_local_survives_later_reader_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {})
    monkeypatch.setattr(tai, "import_secret_key", lambda *_a, **_k: 1, raising=False)
    monkeypatch.setattr(
        tai,
        "skip_unless_create_object_supported",
        lambda *_a, **_k: None,
        raising=False,
    )

    def _raise_reader(*_args: object) -> tuple[str, int | None]:
        raise RuntimeError("later attribute reader failure")

    monkeypatch.setattr(tai, "_read_ulong_attr_state", _raise_reader)

    with pytest.raises(RuntimeError, match="later attribute reader failure"):
        tai.TestDerivedAttributeInvariants().test_imported_aes_key_reports_not_local_no_key_gen_mechanism(
            _session()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
    }


def test_imported_origin_malformed_local_survives_later_reader_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {CKA_LOCAL: 0})
    monkeypatch.setattr(tai, "import_secret_key", lambda *_a, **_k: 1, raising=False)
    monkeypatch.setattr(
        tai,
        "skip_unless_create_object_supported",
        lambda *_a, **_k: None,
        raising=False,
    )

    def _raise_reader(*_args: object) -> tuple[str, int | None]:
        raise RuntimeError("later attribute reader failure")

    monkeypatch.setattr(tai, "_read_ulong_attr_state", _raise_reader)

    with pytest.raises(RuntimeError, match="later attribute reader failure"):
        tai.TestDerivedAttributeInvariants().test_imported_aes_key_reports_not_local_no_key_gen_mechanism(
            _session()
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail == {
        "attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)},
        "expected": "CK_BBOOL boolean",
        "actual": "0",
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
    }


def test_imported_aes_origin_unsupported_mechanism_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_imported_aes_origin(monkeypatch, {CKA_LOCAL: False}, ("unsupported", None))

    record = C.get_records()[-1]
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def test_attribute_invariants_attribute_access_is_analyzer_clean() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "test_attribute_invariants.py"
    )
    assert analyze_file(source) == []


def _raw_ulong_reader(
    *,
    query_rv: int = int(CKR_OK),
    query_length: int = ctypes.sizeof(CK_ULONG),
    value_rv: int = int(CKR_OK),
    value_length: int = ctypes.sizeof(CK_ULONG),
    value: int = 0,
) -> tuple[SimpleNamespace, list[int]]:
    calls: list[int] = []

    def _get_attribute(_session: int, _handle: int, template: Any, _count: int) -> int:
        calls.append(1)
        attr = ctypes.cast(template, ctypes.POINTER(CK_ATTRIBUTE)).contents
        if len(calls) == 1:
            attr.ulValueLen = query_length
            return query_rv
        attr.ulValueLen = value_length
        ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value = value
        return value_rv

    return SimpleNamespace(C_GetAttributeValue=_get_attribute), calls


def test_ulong_attribute_state_preserves_unsupported_and_unavailable() -> None:
    unsupported_raw, unsupported_calls = _raw_ulong_reader(
        query_rv=int(CKR_ATTRIBUTE_TYPE_INVALID),
    )
    assert tai._read_ulong_attr_state(unsupported_raw, 1, 2, CKA_KEY_GEN_MECHANISM) == (
        "unsupported",
        None,
    )
    assert len(unsupported_calls) == 1

    unavailable_raw, unavailable_calls = _raw_ulong_reader(
        query_length=int(CK_UNAVAILABLE_INFORMATION),
    )
    assert tai._read_ulong_attr_state(unavailable_raw, 1, 2, CKA_KEY_GEN_MECHANISM) == (
        "unavailable",
        None,
    )
    assert len(unavailable_calls) == 1


def test_ulong_attribute_state_preserves_present_false_like_zero() -> None:
    raw, calls = _raw_ulong_reader(value=0)
    assert tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM) == ("present", 0)
    assert len(calls) == 2


def test_ulong_attribute_malformed_length_is_structured_failure() -> None:
    raw, _calls = _raw_ulong_reader(query_length=1)

    with pytest.raises(Failed) as exc_info:
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail == {
        "attribute": {
            "name": "CKA_KEY_GEN_MECHANISM",
            "id": int(CKA_KEY_GEN_MECHANISM),
        },
        "expected": ctypes.sizeof(CK_ULONG),
        "actual": 1,
    }


def test_ulong_attribute_second_read_malformed_length_is_structured_failure() -> None:
    raw, _calls = _raw_ulong_reader(value_length=1)

    with pytest.raises(Failed) as exc_info:
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail == {
        "attribute": {
            "name": "CKA_KEY_GEN_MECHANISM",
            "id": int(CKA_KEY_GEN_MECHANISM),
        },
        "expected": ctypes.sizeof(CK_ULONG),
        "actual": 1,
    }


def test_ulong_attribute_unavailable_value_with_malformed_length_is_failure() -> None:
    raw, _calls = _raw_ulong_reader(
        value_length=1,
        value=int(CK_UNAVAILABLE_INFORMATION),
    )

    with pytest.raises(Failed) as exc_info:
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.detail == {
        "attribute": {
            "name": "CKA_KEY_GEN_MECHANISM",
            "id": int(CKA_KEY_GEN_MECHANISM),
        },
        "expected": ctypes.sizeof(CK_ULONG),
        "actual": 1,
    }


def test_ulong_attribute_unexpected_read_rv_is_structured_failure() -> None:
    raw, _calls = _raw_ulong_reader(value_rv=0x12345678)

    with pytest.raises(pytest.xfail.Exception):
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    record = C.get_records()[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.reason == "not_operational"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_ulong_attribute_query_error_is_visible_not_operational_xfail() -> None:
    raw, _calls = _raw_ulong_reader(query_rv=0x12345678)

    with pytest.raises(pytest.xfail.Exception):
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_ulong_attribute_value_error_is_visible_not_operational_xfail() -> None:
    raw, _calls = _raw_ulong_reader(value_rv=0x12345678)

    with pytest.raises(pytest.xfail.Exception):
        tai._read_ulong_attr_state(raw, 1, 2, CKA_KEY_GEN_MECHANISM)

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_faithful_clean_rejection_keeps_operation_and_mechanism_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(monkeypatch, {})

    def _reject(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError("device error", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(tai, "gen_aes_key", _reject)

    with pytest.raises(pytest.xfail.Exception):
        tai.TestContradictoryCreationFaithfulness()._check_faithful_or_reject(
            _session(),
            attrs={CKA_SIGN: True, CKA_VERIFY: True},
            check_attrs=[CKA_SIGN, CKA_VERIFY],
            label="faithful readback",
        )

    record = C.get_records()[0]
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"

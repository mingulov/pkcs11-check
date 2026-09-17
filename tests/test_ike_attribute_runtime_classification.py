"""Runtime regressions for IKE derived-value evidence and cleanup."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_ike as ike
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def _patch_nonce_runs(
    monkeypatch: pytest.MonkeyPatch,
    values: list[dict[int, Any]],
    *,
    first_derive_error: BaseException | None = None,
    second_derive_error: BaseException | None = None,
    handles: tuple[int, ...] = (101, 102),
) -> list[str]:
    events: list[str] = []
    derived = iter(handles)
    run_count = 0

    monkeypatch.setattr(ike, "_create_base_key", lambda _rs: 7)

    def fake_derive(*_args: Any, **_kwargs: Any) -> int:
        nonlocal run_count
        run_count += 1
        events.append("derive")
        if run_count == 1 and first_derive_error is not None:
            raise first_derive_error
        if run_count == 2 and second_derive_error is not None:
            raise second_derive_error
        return next(derived)

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        events.append("read")
        return values.pop(0)

    def fake_destroy(_raw: Any, _sh: int, handle: int) -> None:
        events.append(f"destroy:{handle}")

    monkeypatch.setattr(ike, "_derive_generic", fake_derive)
    monkeypatch.setattr(ike, "read_attributes", fake_read)
    monkeypatch.setattr(ike, "destroy_quietly", fake_destroy)
    return events


def test_missing_nonce_outputs_are_visible_and_do_not_stop_second_derivation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_nonce_runs(monkeypatch, [{}, {}])

    ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    # Readback attribution: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer already lives in the label (set by every
    # caller of _get_value).
    assert all(record.mechanism is None for record in records)
    assert all("CKM_IKE2_PRF_PLUS_DERIVE" in record.label for record in records)
    assert all(
        record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
        for record in records
    )
    assert events == ["derive", "read", "destroy:101", "derive", "read", "destroy:102", "destroy:7"]
    assert MISSING_ATTRIBUTE is not False


def test_missing_first_output_survives_second_derive_rejection_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_nonce_runs(
        monkeypatch,
        [{}],
        second_derive_error=CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
        ),
    )

    with pytest.raises(BaseException):
        ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "CKM_IKE2_PRF_PLUS_DERIVE" in records[0].label
    assert records[1].operation == "C_DeriveKey"
    assert records[1].mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"
    assert events == ["derive", "read", "destroy:101", "derive", "destroy:7"]


def test_clean_attribute_rejection_in_first_leg_does_not_stop_second_leg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    derived = iter((101, 102))
    second_value: dict[int, Any] = {CKA_VALUE: b"b" * 32}
    reads: Iterator[BaseException | dict[int, Any]] = iter(
        (
            CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID", int(CKR_ATTRIBUTE_TYPE_INVALID)
            ),
            second_value,
        )
    )

    monkeypatch.setattr(ike, "_create_base_key", lambda _rs: 7)

    def fake_derive(*_args: Any, **_kwargs: Any) -> int:
        events.append("derive")
        return next(derived)

    monkeypatch.setattr(ike, "_derive_generic", fake_derive)

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        events.append("read")
        value = next(reads)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(ike, "read_attributes", fake_read)
    monkeypatch.setattr(
        ike,
        "destroy_quietly",
        lambda _raw, _sh, handle: events.append(f"destroy:{handle}"),
    )

    with pytest.raises(pytest.xfail.Exception):
        ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert records[0].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert events == ["derive", "read", "destroy:101", "derive", "read", "destroy:102", "destroy:7"]


@pytest.mark.parametrize(
    ("derive_error", "reason", "outcome", "actual"),
    [
        (
            CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID", int(CKR_ATTRIBUTE_TYPE_INVALID)
            ),
            "not_operational",
            pytest.xfail.Exception,
            "CKR_ATTRIBUTE_TYPE_INVALID",
        ),
        (
            CkrAssertionError("Unexpected CK_RV 0x80000001", int(CKR_VENDOR_DEFINED) + 1),
            "not_operational",
            pytest.xfail.Exception,
            "0x80000001",
        ),
        (
            CkrAssertionError("Unexpected CK_RV 0x12345678", 0x12345678),
            "self_contradiction",
            pytest.fail.Exception,
            "0x12345678",
        ),
    ],
)
def test_pair_continues_after_first_leg_derive_rejection(
    monkeypatch: pytest.MonkeyPatch,
    derive_error: CkrAssertionError,
    reason: str,
    outcome: type[BaseException],
    actual: str,
) -> None:
    events = _patch_nonce_runs(
        monkeypatch,
        [{}],
        first_derive_error=derive_error,
    )

    with pytest.raises(outcome):
        ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    record = C.get_records()[0]
    assert record.reason == reason
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert record.actual_ckr == actual
    assert events == ["derive", "derive", "read", "destroy:101", "destroy:7"]


def test_malformed_pair_outputs_are_both_recorded_before_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_nonce_runs(
        monkeypatch,
        [{CKA_VALUE: b"short"}, {CKA_VALUE: b"also-short"}],
    )

    with pytest.raises(pytest.fail.Exception):
        ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert all(record.kind == "crypto" for record in records)
    assert all(record.operation == "C_DeriveKey" for record in records)
    assert all(record.mechanism == "CKM_IKE2_PRF_PLUS_DERIVE" for record in records)
    assert events == ["derive", "read", "destroy:101", "derive", "read", "destroy:102", "destroy:7"]


def test_equal_wrong_length_deterministic_outputs_remain_hard_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_nonce_runs(
        monkeypatch,
        [{CKA_VALUE: b"short"}, {CKA_VALUE: b"short"}],
    )

    with pytest.raises(pytest.fail.Exception):
        ike.TestIKE2PRFPlusDerive().test_derive_deterministic(_session())

    records = C.get_records()
    # The two exact-length checks are hard failures; relation checking is
    # intentionally not meaningful once either present output is malformed.
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert all(record.operation == "C_DeriveKey" for record in records)
    assert events == ["derive", "read", "destroy:101", "derive", "read", "destroy:102", "destroy:7"]


def test_zero_first_derived_handle_is_lifecycle_failure_but_second_leg_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_nonce_runs(
        monkeypatch,
        [{CKA_VALUE: b"b" * 32}],
        handles=(0, 102),
    )

    with pytest.raises(pytest.fail.Exception):
        ike.TestIKE2PRFPlusDerive().test_different_nonces_produce_different_keys(_session())

    records = C.get_records()
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert events == ["derive", "derive", "read", "destroy:102", "destroy:7"]


def test_zero_created_handle_is_a_create_object_lifecycle_failure() -> None:
    with pytest.raises(pytest.fail.Exception):
        ike._require_created_handle(0, label="IKE setup")

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None


def test_create_object_rejection_is_not_reclassified_as_derive_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_error = CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID)
    )
    monkeypatch.setattr(
        ike,
        "create_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(setup_error),
    )

    with pytest.raises(pytest.xfail.Exception):
        ike._create_object_checked(_session(), {}, label="IKE setup")

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_CreateObject"
    assert record.mechanism is None
    assert record.actual_ckr == "CKR_MECHANISM_INVALID"


def test_undefined_create_ckr_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ike,
        "create_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("Unexpected CK_RV 0x12345678", 0x12345678)
        ),
    )

    with pytest.raises(pytest.fail.Exception):
        ike._create_object_checked(_session(), {}, label="IKE setup")

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_CreateObject"
    assert record.actual_ckr == "0x12345678"


def test_second_setup_rejection_cleans_first_handle_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    session = _session()

    monkeypatch.setattr(ike, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    monkeypatch.setattr(
        ike,
        "create_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError(
                "Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE", int(CKR_TEMPLATE_INCOMPLETE)
            )
        ),
    )
    with pytest.raises(pytest.xfail.Exception):
        ike._acquire_second_or_cleanup(
            session,
            7,
            lambda: ike._create_object_checked(session, {}, label="IKE paired setup"),
        )

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_CreateObject"
    assert record.actual_ckr == "CKR_TEMPLATE_INCOMPLETE"
    assert destroyed == [7]


def test_second_setup_zero_handle_cleans_first_and_records_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(ike, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        ike._acquire_second_or_cleanup(_session(), 7, lambda: 0)

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_CreateObject"
    assert destroyed == [7]


def test_malformed_present_value_is_a_metadata_failure_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(ike, "_create_base_key", lambda _rs: 7)
    monkeypatch.setattr(ike, "_derive_generic", lambda *_args, **_kwargs: 101)
    monkeypatch.setattr(ike, "read_attributes", lambda *_args: {CKA_VALUE: False})
    monkeypatch.setattr(
        ike, "destroy_quietly", lambda _raw, _sh, handle: events.append(str(handle))
    )

    with pytest.raises(pytest.fail.Exception):
        ike.TestIKE2PRFPlusDerive().test_derive_generic_secret(_session())

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == "False"
    assert events == ["101", "7"]


def test_attribute_reader_exception_is_not_reclassified_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader_error = CkrAssertionError(
        "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID", int(CKR_ATTRIBUTE_TYPE_INVALID)
    )
    monkeypatch.setattr(ike, "read_attributes", lambda *_args: (_ for _ in ()).throw(reader_error))

    with pytest.raises(pytest.xfail.Exception):
        ike._get_value(
            _session(),
            101,
            mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
            label="IKE CKA_VALUE",
        )

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def test_undefined_attribute_reader_ckr_is_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader_error = CkrAssertionError("Unexpected CK_RV 0x12345678", 0x12345678)
    monkeypatch.setattr(ike, "read_attributes", lambda *_args: (_ for _ in ()).throw(reader_error))

    with pytest.raises(pytest.fail.Exception):
        ike._get_value(
            _session(),
            101,
            mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
            label="IKE CKA_VALUE",
        )

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_IKE2_PRF_PLUS_DERIVE"
    assert record.actual_ckr == "0x12345678"


def test_plain_attribute_reader_assertion_propagates_without_provider_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader_error = AssertionError("harness reader assertion")
    monkeypatch.setattr(ike, "read_attributes", lambda *_args: (_ for _ in ()).throw(reader_error))

    with pytest.raises(AssertionError, match="harness reader assertion"):
        ike._get_value(
            _session(),
            101,
            mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
            label="IKE CKA_VALUE",
        )

    assert C.get_records() == []


def test_ike_attribute_access_slice_is_analyzer_clean() -> None:
    source = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_ike.py"
    assert analyze_file(source) == []

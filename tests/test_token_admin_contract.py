"""QC11b contracts for bounded session exhaustion and cleanup ownership."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_SESSION_COUNT,
)
from pkcs11_check.testcases import test_session_exhaustion as tse


def _as_int(value: object) -> int:
    if not isinstance(value, int):
        raise TypeError(f"expected integer test result, got {type(value).__name__}")
    return value


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _Raw:
    def __init__(self, close_results: list[object] | None = None) -> None:
        self.close_results = list(close_results or [])
        self.close_calls: list[int] = []

    def C_CloseSession(self, handle: int) -> int:  # noqa: N802 - PKCS#11 name.
        self.close_calls.append(handle)
        result = self.close_results.pop(0) if self.close_results else int(CKR_OK)
        if isinstance(result, BaseException):
            raise result
        return _as_int(result)


class _Scenario:
    def __init__(
        self,
        open_results: list[object] | None = None,
        *,
        close_results: list[object] | None = None,
        login_results: list[object] | None = None,
        key_result: object = 41,
        pin: bool = False,
    ) -> None:
        self.open_results = list(open_results or [])
        self.login_results = list(login_results or [])
        self.key_result = key_result
        self.pin = pin
        self.next_handle = 101
        self.open_calls: list[tuple[int, int]] = []
        self.login_calls: list[int] = []
        self.key_calls: list[int] = []
        self.raw = _Raw(close_results)

    def open(self, _raw: object, slot_id: int, flags: int) -> int:
        self.open_calls.append((slot_id, flags))
        result = self.open_results.pop(0) if self.open_results else self.next_handle
        if not isinstance(result, BaseException):
            self.next_handle = _as_int(result) + 1
        if isinstance(result, BaseException):
            raise result
        return _as_int(result)

    def login(self, _raw: object, handle: int, _user_type: int, _pin: bytes) -> None:
        self.login_calls.append(handle)
        result = self.login_results.pop(0) if self.login_results else None
        if isinstance(result, BaseException):
            raise result

    def gen(self, _rs: Any, _bits: int, *, sh: int) -> int:
        self.key_calls.append(sh)
        if isinstance(self.key_result, BaseException):
            raise self.key_result
        return _as_int(self.key_result)


def _run(monkeypatch: pytest.MonkeyPatch, scenario: _Scenario) -> None:
    monkeypatch.setattr(tse, "raw_open_session", scenario.open)
    monkeypatch.setattr(tse, "login_user", scenario.login)
    monkeypatch.setattr(tse, "gen_aes_key_or_xfail", scenario.gen)
    session = SimpleNamespace(
        raw=scenario.raw,
        sh=99,
        slot_id=7,
        has_mechanism=lambda _name: True,
    )
    config = SimpleNamespace(pin=_Pin() if scenario.pin else None)
    tse.TestSessionExhaustion().test_open_many_sessions(session, config)


def _ckr(rv: int) -> CkrAssertionError:
    return CkrAssertionError(f"test CK_RV {rv}", int(rv))


def _lifecycle_records() -> list[classification.Classification]:
    records = classification.get_records()
    assert records
    assert all(record.mechanism is None for record in records)
    assert all(
        record.reason not in {"unclassified", "harness_error", "probe_incomplete"}
        for record in records
    )
    return records


def test_canonical_session_count_runs_one_bounded_recovery_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario([11, 12, _ckr(int(CKR_SESSION_COUNT)), 13])

    _run(monkeypatch, scenario)

    assert [slot_id for slot_id, _ in scenario.open_calls] == [7, 7, 7, 7]
    assert [flags for _, flags in scenario.open_calls] == [
        int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
    ] * 4
    assert scenario.raw.close_calls == [11, 12, 13]
    assert scenario.key_calls == [13]
    assert classification.get_records() == []


def test_noncanonical_open_refusal_is_xfail_with_exact_rv_and_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario([11, _ckr(int(CKR_GENERAL_ERROR)), 12])

    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.kind == "lifecycle"
    assert record.operation == "C_OpenSession"
    assert record.expected_ckr == ["CKR_SESSION_COUNT"]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"
    assert record.detail == {"phase": "saturation"}
    assert scenario.raw.close_calls == [11, 12]
    assert scenario.key_calls == [12]


@pytest.mark.parametrize("failure", [AssertionError("open bug"), RuntimeError("open bug")])
def test_bare_open_failures_propagate_after_owned_sessions_close(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    scenario = _Scenario([11, failure])

    with pytest.raises(type(failure)) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value is failure
    assert scenario.raw.close_calls == [11]
    assert len(scenario.open_calls) == 2
    assert scenario.key_calls == []


def test_initial_login_failure_closes_its_owned_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(
        [11],
        login_results=[_ckr(int(CKR_GENERAL_ERROR))],
        pin=True,
    )

    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_Login"
    assert records[0].expected_ckr == ["CKR_OK"]
    assert records[0].actual_ckr == "CKR_GENERAL_ERROR"
    assert records[0].detail == {"phase": "initial", "handle": 11}
    assert scenario.raw.close_calls == [11]
    assert scenario.open_calls == [(7, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))]


def test_pin_none_does_not_attempt_login(monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = _Scenario([11, _ckr(int(CKR_SESSION_COUNT)), 12])

    _run(monkeypatch, scenario)

    assert scenario.login_calls == []
    assert scenario.key_calls == [12]


def test_recovery_login_failure_closes_initial_and_recovery_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        login_results=[None, _ckr(int(CKR_GENERAL_ERROR))],
        pin=True,
    )

    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert records[-1].operation == "C_Login"
    assert records[-1].detail == {"phase": "recovery", "handle": 12}
    assert records[-1].actual_ckr == "CKR_GENERAL_ERROR"
    assert scenario.raw.close_calls == [11, 12]
    assert scenario.key_calls == []


def test_clean_close_refusal_is_recorded_and_recovery_still_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(
        [11, 12, _ckr(int(CKR_SESSION_COUNT)), 13],
        close_results=[int(CKR_GENERAL_ERROR), int(CKR_OK), int(CKR_OK)],
    )

    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_CloseSession"
    assert records[0].expected_ckr == ["CKR_OK"]
    assert records[0].actual_ckr == "CKR_GENERAL_ERROR"
    assert records[0].detail == {"phase": "initial", "handle": 11}
    assert scenario.raw.close_calls == [11, 12, 13]
    assert scenario.key_calls == [13]


def test_cleanup_attempts_later_handles_and_preserves_raw_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_failure = RuntimeError("close bug")
    scenario = _Scenario(
        [11, 12, _ckr(int(CKR_SESSION_COUNT))],
        close_results=[cleanup_failure, int(CKR_OK)],
    )

    with pytest.raises(RuntimeError) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value is cleanup_failure
    assert scenario.raw.close_calls == [11, 12]
    assert len(scenario.open_calls) == 3
    assert scenario.key_calls == []
    assert cleanup_failure.__notes__ == [
        "C_CloseSession cleanup raised for owned handle 11 during initial"
    ]
    assert classification.get_records() == []


def test_primary_and_cleanup_failures_are_retained_as_exception_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("recovery setup bug")
    cleanup = AssertionError("recovery close bug")
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[int(CKR_OK), cleanup],
        key_result=primary,
    )

    with pytest.raises(BaseExceptionGroup) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value.exceptions == (primary, cleanup)
    assert scenario.raw.close_calls == [11, 12]


def test_primary_failure_survives_clean_close_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("recovery setup bug")
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[int(CKR_OK), _ckr(int(CKR_GENERAL_ERROR))],
        key_result=primary,
    )

    with pytest.raises(RuntimeError) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value is primary
    record = _lifecycle_records()[0]
    assert record.operation == "C_CloseSession"
    assert record.actual_ckr == "CKR_GENERAL_ERROR"
    assert record.detail == {"phase": "recovery", "handle": 12}
    assert scenario.raw.close_calls == [11, 12]


def test_undefined_open_rv_is_a_metadata_failure_not_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario([11, _ckr(0x7FFFFFFF), 12])

    with pytest.raises(pytest.fail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_OpenSession"
    assert records[0].actual_ckr == "0x7fffffff"
    assert scenario.raw.close_calls == [11, 12]
    assert scenario.key_calls == [12]


def test_undefined_close_rv_is_a_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[_ckr(0x7FFFFFFF), int(CKR_OK)],
    )

    with pytest.raises(pytest.fail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_CloseSession"
    assert records[0].actual_ckr == "0x7fffffff"
    assert scenario.raw.close_calls == [11, 12]


def test_open_and_close_clean_refusals_are_both_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(
        [11, _ckr(int(CKR_GENERAL_ERROR)), 12],
        close_results=[_ckr(int(CKR_GENERAL_ERROR)), int(CKR_OK)],
    )

    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, scenario)

    records = _lifecycle_records()
    assert [(record.operation, record.actual_ckr) for record in records] == [
        ("C_OpenSession", "CKR_GENERAL_ERROR"),
        ("C_CloseSession", "CKR_GENERAL_ERROR"),
    ]


def test_cleanup_failure_cannot_be_hidden_by_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup = RuntimeError("close bug")
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[int(CKR_OK), cleanup],
        key_result=pytest.skip.Exception("AES key generation unavailable"),
    )

    with pytest.raises(BaseExceptionGroup) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value.exceptions[0] is scenario.key_result
    assert exc_info.value.exceptions[1] is cleanup
    assert scenario.raw.close_calls == [11, 12]


def test_capability_skip_is_retained_when_close_refusal_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skip = pytest.skip.Exception("AES key generation unavailable")
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[int(CKR_OK), _ckr(int(CKR_GENERAL_ERROR))],
        key_result=skip,
    )

    with pytest.raises(pytest.xfail.Exception) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value.__cause__ is skip
    record = _lifecycle_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_CloseSession"
    assert record.detail == {
        "phase": "recovery",
        "handle": 12,
        "capability_skip": {"exception_type": type(skip).__name__, "reason": str(skip)},
    }
    serialized = classification.serialize([record])[0]
    assert serialized["detail"] == record.detail
    assert scenario.raw.close_calls == [11, 12]


def test_capability_skip_is_retained_when_close_rv_is_undefined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skip = pytest.skip.Exception("AES key generation unavailable")
    scenario = _Scenario(
        [11, _ckr(int(CKR_SESSION_COUNT)), 12],
        close_results=[int(CKR_OK), _ckr(0x7FFFFFFF)],
        key_result=skip,
    )

    with pytest.raises(pytest.fail.Exception) as exc_info:
        _run(monkeypatch, scenario)

    assert exc_info.value.__cause__ is skip
    record = _lifecycle_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_CloseSession"
    assert record.actual_ckr == "0x7fffffff"
    assert record.detail == {
        "phase": "recovery",
        "handle": 12,
        "capability_skip": {"exception_type": type(skip).__name__, "reason": str(skip)},
    }
    assert scenario.raw.close_calls == [11, 12]


def test_lifecycle_records_ignore_foreign_mechanism_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario([11, _ckr(int(CKR_GENERAL_ERROR)), 12])
    classification.set_mechanism("CKM_AES_KEY_GEN", "C_GenerateKey", expect_success=True)

    records: list[classification.Classification]
    try:
        with pytest.raises(pytest.xfail.Exception):
            _run(monkeypatch, scenario)
        records = _lifecycle_records()
    finally:
        classification.clear()

    record = records[0]
    assert record.mechanism is None
    assert record.operation == "C_OpenSession"


def test_session_exhaustion_keeps_the_historical_hundred_session_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario()

    _run(monkeypatch, scenario)

    assert len(scenario.open_calls) == 101
    assert scenario.raw.close_calls == list(range(101, 202))
    assert scenario.key_calls == [201]

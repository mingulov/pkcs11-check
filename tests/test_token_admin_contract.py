"""QC11b contracts for bounded session exhaustion and cleanup ownership.

Plus QC11 destructive-administration contracts (#52.6-.8): sacrificial-token
capability/mint/reset helpers, token_admin child probes and trace parsing, and
the QC11a lockout/countdown, QC11b session-limit/PIN-length, and QC11c
provisioning-journey/reset judges. Fakes only; no provider is loaded.
"""

from __future__ import annotations

import ctypes
import os
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_TOKEN_INFO,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CK_UNAVAILABLE_INFORMATION_32,
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_COUNT_LOW,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_INITIALIZED,
    CKF_USER_PIN_LOCKED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_LOCKED,
    CKR_SESSION_COUNT,
    CKR_SESSION_EXISTS,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_PIN_NOT_INITIALIZED,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases import _throwaway_token as throwaway
from pkcs11_check.testcases import test_pin as pin_case
from pkcs11_check.testcases import test_session_exhaustion as tse
from pkcs11_check.testcases import test_so_pin as sopin_case
from pkcs11_check.testcases._probes import token_admin
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.ckr import test_ckr_destructive as ckr_case
from tests._skip_assert import assert_skips, assert_xfails


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


_OK = int(CKR_OK)
_PIN_INCORRECT = int(CKR_PIN_INCORRECT)
_PIN_LOCKED = int(CKR_PIN_LOCKED)
_PIN_LEN_RANGE = int(CKR_PIN_LEN_RANGE)
_SESSION_COUNT = int(CKR_SESSION_COUNT)
_GENERAL_ERROR = int(CKR_GENERAL_ERROR)
_NOT_SUPPORTED = int(CKR_FUNCTION_NOT_SUPPORTED)
_NOT_LOGGED_IN = int(CKR_USER_NOT_LOGGED_IN)
_PIN_NOT_INITIALIZED = int(CKR_USER_PIN_NOT_INITIALIZED)
_SESSION_EXISTS = int(CKR_SESSION_EXISTS)
_UNDEFINED_RV = 0x7FFFFFFF
_VENDOR_RV = 0x80000001
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)
_UNAVAILABLE_32 = int(CK_UNAVAILABLE_INFORMATION_32)
_USER = int(CKU_USER)
_SO = int(CKU_SO)

_USER_COUNTER_FLAGS = (
    int(CKF_USER_PIN_COUNT_LOW),
    int(CKF_USER_PIN_FINAL_TRY),
    int(CKF_USER_PIN_LOCKED),
)
_SO_COUNTER_FLAGS = (
    int(CKF_SO_PIN_COUNT_LOW),
    int(CKF_SO_PIN_FINAL_TRY),
    int(CKF_SO_PIN_LOCKED),
)
_ROLE_FLAGS = {"user": _USER_COUNTER_FLAGS, "so": _SO_COUNTER_FLAGS}

_FIXTURE_SH = 7


def _fill_ulong(ptr: Any, value: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_ULONG)).contents.value = value


def _read_ptr_bytes(ptr: Any, length: int) -> bytes:
    """Read ``length`` bytes from a child-passed buffer (array, pointer, None)."""
    if ptr is None or int(length) == 0:
        return b""
    if isinstance(ptr, (bytes, bytearray)):
        return bytes(ptr)[: int(length)]
    if isinstance(ptr, ctypes.Array):
        return bytes(ptr)[: int(length)]
    return ctypes.string_at(ptr, int(length))


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    if tmpl is None:
        assert int(count) == 0
        return {}
    decoded: dict[int, bytes] = {}
    for i in range(int(count)):
        attr = tmpl[i]
        alen = int(attr.ulValueLen)
        decoded[int(attr.type)] = _read_ptr_bytes(attr.pValue, alen)
    return decoded


class _FakeAdminRaw:
    """Scriptable sacrificial-token fake for the QC11 child probes and judges."""

    def __init__(self) -> None:
        self.ops: list[str] = []
        self.logins: list[tuple[str, bytes]] = []
        self.pin_values: list[bytes] = []
        self.closes: list[int] = []
        self.destroys: list[int] = []
        self.slots: list[int] = [0]
        self.getslotlist_rv: int = _OK
        self.flags: int = int(CKF_TOKEN_INITIALIZED)
        self.flags_manual: bool = False
        self.gettokeninfo_rv: int = _OK
        self.gettokeninfo_script: list[int] = []
        self.min_pin: int = 4
        self.max_pin: int = 32
        self.max_total: int | None = 100
        self.max_rw: int | None = 100
        self.ambient_total: int = 1
        self.ambient_rw: int = 1
        self.sessions: set[int] = set()
        self._next_session: int = 10
        self.open_script: list[int] = []
        self.open_refusal_at: int | None = None
        self.open_refusal_rv: int = _SESSION_COUNT
        self.enforce_max: bool = True
        self.close_script: list[int] = []
        self.user_pin: bytes | None = bytes(token_admin.TEST_USER_PIN)
        self.so_pin: bytes | None = bytes(token_admin.TEST_SO_PIN)
        self.logged_in: str | None = None
        self.threshold: dict[str, int] = {"user": 5, "so": 5}
        self.remaining: dict[str, int] = {"user": 5, "so": 5}
        self.reset_on_success: bool = True
        self.login_script: dict[str, list[int]] = {"user": [], "so": []}
        self.init_token_script: list[int] = []
        self.init_token_always: int | None = None
        self.init_token_keep_flags: bool = False
        self.init_pin_script: list[int] = []
        self.init_pin_always: int | None = None
        self.set_pin_script: list[int] = []
        self.set_pin_always: int | None = None
        self.create_script: list[int] = []
        self.find_rv: int = _OK
        self.objects: dict[int, dict[int, bytes]] = {}
        self._next_handle: int = 500
        self._search_label: bytes | None = None
        self._search: list[int] = []

    # -- slots / token info -------------------------------------------
    def C_GetSlotList(self, _present: int, slot_ptr: Any, count_ptr: Any) -> int:  # noqa: N802
        self.ops.append("getslotlist")
        if self.getslotlist_rv != _OK:
            return self.getslotlist_rv
        if slot_ptr is None:
            _fill_ulong(count_ptr, len(self.slots))
            return _OK
        for i, slot_id in enumerate(self.slots):
            slot_ptr[i] = slot_id
        _fill_ulong(count_ptr, len(self.slots))
        return _OK

    def C_GetTokenInfo(self, _slot_id: int, info_ptr: Any) -> int:  # noqa: N802
        self.ops.append("gettokeninfo")
        if self.gettokeninfo_script:
            return self.gettokeninfo_script.pop(0)
        if self.gettokeninfo_rv != _OK:
            return self.gettokeninfo_rv
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_TOKEN_INFO)).contents
        info.flags = self.flags
        info.ulMaxSessionCount = _UNAVAILABLE if self.max_total is None else self.max_total
        info.ulSessionCount = len(self.sessions) + self.ambient_total
        info.ulMaxRwSessionCount = _UNAVAILABLE if self.max_rw is None else self.max_rw
        info.ulRwSessionCount = len(self.sessions) + self.ambient_rw
        info.ulMinPinLen = self.min_pin
        info.ulMaxPinLen = self.max_pin
        return _OK

    # -- sessions ------------------------------------------------------
    def C_OpenSession(  # noqa: N802
        self, _slot_id: int, _flags: int, _app: Any, _notify: Any, sess_ptr: Any
    ) -> int:
        if self.open_script:
            rv = self.open_script.pop(0)
            if rv == _OK:
                handle = self._next_session
                self._next_session += 1
                self.sessions.add(handle)
                _fill_ulong(sess_ptr, handle)
            self.ops.append(f"open:{rv:#x}")
            return rv
        total = len(self.sessions) + self.ambient_total
        if self.open_refusal_at is not None and len(self.sessions) >= self.open_refusal_at:
            self.ops.append(f"open:{self.open_refusal_rv:#x}")
            return self.open_refusal_rv
        if self.enforce_max and self.max_total is not None and total >= self.max_total:
            self.ops.append(f"open:{_SESSION_COUNT:#x}")
            return _SESSION_COUNT
        if self.enforce_max and self.max_rw is not None and total >= self.max_rw:
            self.ops.append(f"open:{_SESSION_COUNT:#x}")
            return _SESSION_COUNT
        handle = self._next_session
        self._next_session += 1
        self.sessions.add(handle)
        _fill_ulong(sess_ptr, handle)
        self.ops.append(f"open:{handle}")
        return _OK

    def C_CloseSession(self, session: int) -> int:  # noqa: N802
        self.closes.append(int(session))
        self.sessions.discard(int(session))
        self.ops.append(f"close:{int(session)}")
        if self.close_script:
            return self.close_script.pop(0)
        return _OK

    # -- login / PIN ---------------------------------------------------
    def _sync_counter_flags(self, role: str) -> None:
        if self.flags_manual:
            return
        low, final, locked = _ROLE_FLAGS[role]
        self.flags &= ~(low | final | locked)
        left = self.remaining[role]
        if left <= 0:
            self.flags |= locked
        elif left == 1:
            self.flags |= final
        elif left < self.threshold[role]:
            self.flags |= low

    def C_Login(self, _sh: int, user_type: int, pin_ptr: Any, pin_len: int) -> int:  # noqa: N802
        role = "so" if int(user_type) == _SO else "user"
        pin = _read_ptr_bytes(pin_ptr, pin_len)
        self.logins.append((role, pin))
        self.ops.append(f"login:{role}:{len(pin)}")
        if self.login_script[role]:
            return self.login_script[role].pop(0)
        stored = self.so_pin if role == "so" else self.user_pin
        if stored is None:
            return _PIN_NOT_INITIALIZED
        if self.remaining[role] <= 0:
            return _PIN_LOCKED
        if pin != stored:
            self.remaining[role] -= 1
            self._sync_counter_flags(role)
            if self.remaining[role] <= 0:
                return _PIN_LOCKED
            return _PIN_INCORRECT
        self.logged_in = role
        if self.reset_on_success:
            self.remaining[role] = self.threshold[role]
            self._sync_counter_flags(role)
        return _OK

    def C_Logout(self, _sh: int) -> int:  # noqa: N802
        self.ops.append("logout")
        self.logged_in = None
        return _OK

    # -- admin ops ------------------------------------------------------
    def C_InitToken(self, _slot: int, pin_ptr: Any, pin_len: int, _label: Any) -> int:  # noqa: N802
        pin = _read_ptr_bytes(pin_ptr, pin_len)
        self.pin_values.append(pin)
        self.ops.append(f"inittoken:{len(pin)}")
        if self.init_token_script:
            return self.init_token_script.pop(0)
        if self.init_token_always is not None:
            return self.init_token_always
        if self.sessions:
            return _SESSION_EXISTS
        if self.so_pin is not None and pin != self.so_pin:
            return _PIN_INCORRECT
        self.so_pin = pin
        self.user_pin = None
        self.logged_in = None
        self.objects.clear()
        self.remaining = dict(self.threshold)
        if not self.init_token_keep_flags:
            self.flags = int(CKF_TOKEN_INITIALIZED)
        return _OK

    def C_InitPIN(self, _sh: int, pin_ptr: Any, pin_len: int) -> int:  # noqa: N802
        pin = _read_ptr_bytes(pin_ptr, pin_len)
        self.pin_values.append(pin)
        self.ops.append(f"initpin:{len(pin)}")
        if self.init_pin_script:
            return self.init_pin_script.pop(0)
        if self.init_pin_always is not None:
            return self.init_pin_always
        if self.logged_in != "so":
            return _NOT_LOGGED_IN
        if len(pin) < self.min_pin or len(pin) > self.max_pin:
            return _PIN_LEN_RANGE
        self.user_pin = pin
        self.remaining["user"] = self.threshold["user"]
        self.flags |= int(CKF_USER_PIN_INITIALIZED)
        self._sync_counter_flags("user")
        return _OK

    def C_SetPIN(  # noqa: N802
        self, _sh: int, old_ptr: Any, old_len: int, new_ptr: Any, new_len: int
    ) -> int:
        old = _read_ptr_bytes(old_ptr, old_len)
        new = _read_ptr_bytes(new_ptr, new_len)
        self.pin_values.extend((old, new))
        self.ops.append(f"setpin:{len(old)}->{len(new)}")
        if self.set_pin_script:
            return self.set_pin_script.pop(0)
        if self.set_pin_always is not None:
            return self.set_pin_always
        if self.logged_in not in ("user", "so"):
            return _NOT_LOGGED_IN
        stored = self.so_pin if self.logged_in == "so" else self.user_pin
        if stored is None or old != stored:
            return _PIN_INCORRECT
        if len(new) < self.min_pin or len(new) > self.max_pin:
            return _PIN_LEN_RANGE
        if self.logged_in == "so":
            self.so_pin = new
        else:
            self.user_pin = new
        return _OK

    # -- objects / inventory ---------------------------------------------
    def C_CreateObject(  # noqa: N802
        self, _sh: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        attrs = _decode_template(tmpl, count)
        if self.create_script:
            return self.create_script.pop(0)
        self._next_handle += 1
        handle = self._next_handle
        self.objects[handle] = attrs
        self.ops.append(f"create:{handle}")
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = handle
        return _OK

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        if self.find_rv != _OK:
            return self.find_rv
        attrs = _decode_template(tmpl, count)
        self._search_label = attrs.get(int(CKA_LABEL))
        self._search = [
            handle
            for handle, have in self.objects.items()
            if self._search_label is None or have.get(int(CKA_LABEL)) == self._search_label
        ]
        self.ops.append(f"findinit:{len(self._search)}")
        return _OK

    def C_FindObjects(self, _sh: int, buf: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        take = self._search[: int(max_count)]
        for i, handle in enumerate(take):
            buf[i] = handle
        _fill_ulong(found_ptr, len(take))
        self._search = self._search[len(take) :]
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self._search = []
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroys.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK


def _ctx(raw: Any) -> Any:
    return ProbeContext(raw=raw, sh=None, slot_id=None, cleanup=lambda: None, module_path="fake")


def _rs(fake: _FakeAdminRaw) -> SimpleNamespace:
    return SimpleNamespace(raw=fake, sh=_FIXTURE_SH, slot_id=0)


class _ScriptedChild:
    def __init__(self, out: str, *, rc: int = 0, err: str = "") -> None:
        self.rc = rc
        self.out = out
        self.err = err


_MINTED = throwaway.MintedToken(
    module_path="/fake/throwaway.so",
    conf_path="/fake/token/module.conf",
    token_dir="/fake/token",
    prefix="pkcs11_check_qc11_test_",
)


class _StrictConfig:
    """p11_config stand-in whose .pin explodes (behavioral I3 proof)."""

    interface = "auto"

    @property
    def pin(self) -> Any:
        raise AssertionError("I3 violation: orchestration read p11_config.pin")


class _FakeLaunch:
    """Scriptable child-launch seam: scripted outputs plus a full call record."""

    def __init__(self, script: list[_ScriptedChild]) -> None:
        self._script = list(script)
        self.calls: list[tuple[Any, str, dict[str, Any], Any]] = []

    def __call__(
        self, minted: Any, probe: str, params: Mapping[str, Any], *, p11_config: Any
    ) -> throwaway.ChildOutput:
        self.calls.append((minted, probe, dict(params), p11_config))
        if not self._script:
            raise AssertionError(f"unscripted child launch: {probe} {dict(params)}")
        child = self._script.pop(0)
        return child.rc, child.out, child.err


@contextmanager
def _fake_session_factory(
    *, exit_error: BaseException | None = None, record: list[Any] | None = None
) -> Iterator[Any]:
    if record is not None:
        record.append(_MINTED)
    yield _MINTED
    if exit_error is not None:
        raise exit_error


def _session_factory(
    *, exit_error: BaseException | None = None, record: list[Any] | None = None
) -> Any:
    def _factory(_cap: throwaway.ThrowawayCapability, *, prefix: str) -> Any:
        del prefix
        return _fake_session_factory(exit_error=exit_error, record=record)

    return _factory


def _capability() -> throwaway.ThrowawayCapability:
    return throwaway.ThrowawayCapability(
        module_path="/fake/throwaway.so",
        mint_cmd_template="true",
        conf_env_var="FAKE_TOKEN_CONF",
    )


def _assert_fails(fn: Any, *args: Any, **kwargs: Any) -> Failed:
    try:
        fn(*args, **kwargs)
    except XFailed as exc:
        pytest.fail(f"expected pytest.fail(), got pytest.xfail() instead: {exc}")
    except Failed as exc:
        return exc
    pytest.fail(f"expected {fn} to call pytest.fail(), but it returned normally")


def _single_record() -> Any:
    records = classification.get_records()
    assert len(records) == 1, [(rec.reason, rec.outcome) for rec in records]
    return records[0]


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    rec = _single_record()
    assert rec.reason == reason, rec.reason
    assert rec.kind == kind, rec.kind
    assert rec.outcome == "fail", rec.outcome
    return rec


def _assert_xfail_record(reason: str) -> Any:
    rec = _single_record()
    assert rec.reason == reason, rec.reason
    assert rec.outcome == "xfail", rec.outcome
    return rec


# --- Part 0: sacrificial-token capability / mint / reset ---------------------

_CAPABILITY_VARS = (
    "PKCS11_CHECK_THROWAWAY_MODULE",
    "PKCS11_CHECK_TOKEN_MINT_CMD",
    "PKCS11_CHECK_TOKEN_CONF_ENV",
)


@pytest.fixture
def _clean_capability_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for var in _CAPABILITY_VARS:
        monkeypatch.delenv(var, raising=False)
    yield


def _set_capability_env(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
    values = {
        "PKCS11_CHECK_THROWAWAY_MODULE": "/fake/throwaway.so",
        "PKCS11_CHECK_TOKEN_MINT_CMD": 'echo qc11 > "{conf_path}"',
        "PKCS11_CHECK_TOKEN_CONF_ENV": "FAKE_TOKEN_CONF",
    }
    values.update(overrides)
    for var, value in values.items():
        monkeypatch.setenv(var, value)


@pytest.mark.parametrize("missing", _CAPABILITY_VARS)
def test_capability_none_when_any_var_missing(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    _set_capability_env(monkeypatch)
    monkeypatch.delenv(missing)
    assert throwaway.throwaway_capability() is None


def test_capability_none_when_all_vars_missing(_clean_capability_env: None) -> None:
    assert throwaway.throwaway_capability() is None


def test_capability_present_when_all_vars_set(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.throwaway_capability()
    assert cap is not None
    assert cap.module_path == "/fake/throwaway.so"
    assert cap.mint_cmd_template == 'echo qc11 > "{conf_path}"'
    assert cap.conf_env_var == "FAKE_TOKEN_CONF"


def test_capability_ignores_pin_only_environment(_clean_capability_env: None) -> None:
    os.environ["PKCS11_CHECK_PIN"] = "live-pin-must-be-ignored"
    os.environ["P11TEST_SO_PIN"] = "live-so-pin-must-be-ignored"
    try:
        assert throwaway.throwaway_capability() is None
    finally:
        del os.environ["PKCS11_CHECK_PIN"]
        del os.environ["P11TEST_SO_PIN"]


def test_require_capability_skips_when_missing(_clean_capability_env: None) -> None:
    skipped = assert_skips(throwaway.require_throwaway_capability)
    assert "PKCS11_CHECK_THROWAWAY_MODULE" in str(skipped)


def test_require_capability_returns_capability(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    assert cap.module_path == "/fake/throwaway.so"


def test_mint_success_with_harmless_template(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    minted = throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")
    try:
        assert os.path.isdir(minted.token_dir)
        assert os.path.isfile(minted.conf_path)
        assert minted.module_path == "/fake/throwaway.so"
    finally:
        throwaway.reset_throwaway_token(minted)
    assert not os.path.exists(minted.token_dir)


def test_mint_failure_raises_and_cleans_up(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch, PKCS11_CHECK_TOKEN_MINT_CMD="exit 3")
    cap = throwaway.require_throwaway_capability()
    before = set(os.listdir(tempfile.gettempdir()))
    with pytest.raises(throwaway.ThrowawayMintError, match="3"):
        throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")
    after = set(os.listdir(tempfile.gettempdir()))
    assert after - before == set()


def test_mint_without_conf_artifact_raises(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch, PKCS11_CHECK_TOKEN_MINT_CMD="exit 0")
    cap = throwaway.require_throwaway_capability()
    with pytest.raises(throwaway.ThrowawayMintError, match="conf"):
        throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")


def test_reset_rejects_directory_outside_temp() -> None:
    outside = os.path.join(
        os.path.dirname(os.path.realpath(tempfile.gettempdir())), "qc11-must-not-delete"
    )
    forged = throwaway.MintedToken(
        module_path="/fake/throwaway.so",
        conf_path=os.path.join(outside, "module.conf"),
        token_dir=outside,
        prefix="pkcs11_check_qc11_test_",
    )
    with pytest.raises(throwaway.ThrowawayResetError, match="containment"):
        throwaway.reset_throwaway_token(forged)


def test_reset_rejects_prefix_mismatch(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    minted = throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")
    try:
        forged = throwaway.MintedToken(
            module_path=minted.module_path,
            conf_path=minted.conf_path,
            token_dir=minted.token_dir,
            prefix="some-other-prefix-",
        )
        with pytest.raises(throwaway.ThrowawayResetError, match="prefix"):
            throwaway.reset_throwaway_token(forged)
        assert os.path.isdir(minted.token_dir)
    finally:
        throwaway.reset_throwaway_token(minted)


def test_reset_rejects_conf_outside_token_dir(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    minted = throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")
    try:
        forged = throwaway.MintedToken(
            module_path=minted.module_path,
            conf_path=os.path.join(tempfile.gettempdir(), "qc11-escape.conf"),
            token_dir=minted.token_dir,
            prefix="pkcs11_check_qc11_test_",
        )
        with pytest.raises(throwaway.ThrowawayResetError, match="containment"):
            throwaway.reset_throwaway_token(forged)
    finally:
        throwaway.reset_throwaway_token(minted)


def test_reset_missing_directory_raises_loud(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    minted = throwaway.mint_throwaway_token(cap, prefix="pkcs11_check_qc11_test_")
    throwaway.reset_throwaway_token(minted)
    with pytest.raises(throwaway.ThrowawayResetError, match="gone|missing|no such"):
        throwaway.reset_throwaway_token(minted)


def test_throwaway_token_context_resets_on_success(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    with throwaway.throwaway_token(cap, prefix="pkcs11_check_qc11_test_") as minted:
        assert os.path.isdir(minted.token_dir)
        token_dir = minted.token_dir
    assert not os.path.exists(token_dir)


def test_throwaway_token_mint_failure_skips(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch, PKCS11_CHECK_TOKEN_MINT_CMD="exit 3")
    cap = throwaway.require_throwaway_capability()

    def _enter() -> None:
        with throwaway.throwaway_token(cap, prefix="pkcs11_check_qc11_test_"):
            pytest.fail("must not enter the body when minting fails")

    skipped = assert_skips(_enter)
    assert "mint" in str(skipped)


def test_throwaway_token_body_error_propagates_after_clean_reset(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    token_dir = ""
    with pytest.raises(ValueError, match="boom"):

        def _body() -> None:
            nonlocal token_dir
            with throwaway.throwaway_token(cap, prefix="pkcs11_check_qc11_test_") as minted:
                token_dir = minted.token_dir
                raise ValueError("boom")

        _body()
    assert not os.path.exists(token_dir)


def test_throwaway_token_reset_failure_is_loud(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    with pytest.raises(throwaway.ThrowawayResetError):
        with throwaway.throwaway_token(cap, prefix="pkcs11_check_qc11_test_") as minted:
            throwaway.reset_throwaway_token(minted)


def test_throwaway_token_body_and_reset_failures_chain(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    with pytest.raises(throwaway.ThrowawayResetError) as exc_info:
        with throwaway.throwaway_token(cap, prefix="pkcs11_check_qc11_test_") as minted:
            throwaway.reset_throwaway_token(minted)
            raise ValueError("original-boom")
    assert isinstance(exc_info.value.__context__, ValueError)


def test_conf_env_sets_and_restores(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    monkeypatch.delenv("FAKE_TOKEN_CONF", raising=False)
    with throwaway.throwaway_conf_env(cap, "/fake/conf"):
        assert os.environ["FAKE_TOKEN_CONF"] == "/fake/conf"
    assert "FAKE_TOKEN_CONF" not in os.environ
    monkeypatch.setenv("FAKE_TOKEN_CONF", "/prev/conf")
    with throwaway.throwaway_conf_env(cap, "/fake/conf"):
        assert os.environ["FAKE_TOKEN_CONF"] == "/fake/conf"
    assert os.environ["FAKE_TOKEN_CONF"] == "/prev/conf"


def test_admin_session_points_conf_and_resets(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch)
    cap = throwaway.require_throwaway_capability()
    monkeypatch.delenv("FAKE_TOKEN_CONF", raising=False)
    with throwaway.admin_session(cap, prefix="pkcs11_check_qc11_test_") as minted:
        assert os.path.isdir(minted.token_dir)
        assert os.environ["FAKE_TOKEN_CONF"] == minted.conf_path
        token_dir = minted.token_dir
    assert not os.path.exists(token_dir)
    assert "FAKE_TOKEN_CONF" not in os.environ


def test_admin_session_mint_failure_skips(
    _clean_capability_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_capability_env(monkeypatch, PKCS11_CHECK_TOKEN_MINT_CMD="exit 3")
    cap = throwaway.require_throwaway_capability()

    def _enter() -> None:
        with throwaway.admin_session(cap, prefix="pkcs11_check_qc11_test_"):
            pytest.fail("must not enter the body when minting fails")

    skipped = assert_skips(_enter)
    assert "mint" in str(skipped)


def test_launch_admin_probe_threads_module_and_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def _fake_run_probe(module: str, params: dict[str, Any], **kwargs: Any) -> Any:
        seen["module"] = module
        seen["params"] = params
        seen["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(throwaway, "run_probe", _fake_run_probe)
    config = _StrictConfig()
    rc, out, err = throwaway.launch_admin_probe(
        _MINTED, "qc11a_burn", {"role": "user"}, p11_config=config
    )
    assert (rc, out, err) == (0, "OK", "")
    assert seen["module"] == "token_admin"
    assert seen["params"] == {
        "module_path": "/fake/throwaway.so",
        "probe": "qc11a_burn",
        "role": "user",
    }
    assert seen["kwargs"]["interface"] == "auto"
    assert seen["kwargs"]["coverage"] == "session"


# --- Part 1: child output-trace parsing --------------------------------------

_FULL_TRACE = """PINBOUNDS:4:32
FLAGS:initial:0x00000000
STEP:login:user:wrong:1:CKR:0x000000a0
FLAGS:attempt-1:0x00010000
STEP:login:user:correct:CKR:0x00000000
INV:objects=1
OK
"""


def test_parse_full_trace() -> None:
    trace = token_admin.parse_admin_trace(_FULL_TRACE)
    assert trace.ok is True
    assert trace.no_slots is False
    assert trace.assumption_failed is None
    assert trace.pin_bounds == (4, 32)
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("login:user:wrong:1", _PIN_INCORRECT),
        ("login:user:correct", _OK),
    ]
    assert trace.flags == (("initial", 0x0), ("attempt-1", int(CKF_USER_PIN_COUNT_LOW)))
    assert trace.inv_objects == (1,)


def test_parse_empty_and_garbage_yields_incomplete_trace() -> None:
    for out in ("", "hello\nworld\n", "P11_RV_TRACE_JSON: {}\n"):
        trace = token_admin.parse_admin_trace(out)
        assert trace.ok is False
        assert trace.steps == ()
        assert trace.flags == ()
        assert trace.pin_bounds is None
        assert trace.inv_objects == ()


def test_parse_ignores_unknown_lines_but_keeps_ok() -> None:
    trace = token_admin.parse_admin_trace("diagnostic noise\nOK\nP11_RV_TRACE_JSON: {}\n")
    assert trace.ok is True
    assert trace.steps == ()


def test_parse_no_slots_and_assumption_failed() -> None:
    trace = token_admin.parse_admin_trace("NO_SLOTS\n")
    assert trace.no_slots is True
    assert trace.ok is False
    trace = token_admin.parse_admin_trace("ASSUMPTION_FAILED:not_pristine\nOK\n")
    assert trace.assumption_failed == "not_pristine"
    assert trace.ok is True


def test_parse_assumption_failed_requires_reason() -> None:
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("ASSUMPTION_FAILED:\nOK\n")


def test_parse_malformed_step_raises() -> None:
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("STEP:login:CKR:0xZZZZ\nOK\n")
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("STEP:nameless\nOK\n")


def test_parse_malformed_flags_raises() -> None:
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("FLAGS:initial:banana\nOK\n")
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("FLAGS:noname\nOK\n")


def test_parse_flags_unknown_value() -> None:
    trace = token_admin.parse_admin_trace("FLAGS:after_reset:unknown\nOK\n")
    assert trace.flags == (("after_reset", None),)


def test_parse_malformed_pinbounds_raises() -> None:
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("PINBOUNDS:x\nOK\n")
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("PINBOUNDS:4:x\nOK\n")


def test_parse_pinbounds_unknown() -> None:
    trace = token_admin.parse_admin_trace("PINBOUNDS:unknown\nOK\n")
    assert trace.pin_bounds is None
    assert trace.ok is True


def test_parse_pinbounds_last_reread_wins() -> None:
    trace = token_admin.parse_admin_trace("PINBOUNDS:4:32\nPINBOUNDS:6:16\nOK\n")
    assert trace.pin_bounds == (6, 16)


def test_parse_malformed_inv_raises() -> None:
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("INV:objects=many\nOK\n")
    with pytest.raises(token_admin.TraceParseError):
        token_admin.parse_admin_trace("INV:objects=-1\nOK\n")


def test_setup_failure_finder() -> None:
    trace = token_admin.parse_admin_trace("STEP:setup:open:CKR:0x00000005\nOK\n")
    failed = token_admin.setup_failure(trace)
    assert failed is not None
    assert failed.name == "setup:open"
    assert failed.rv == _GENERAL_ERROR
    trace = token_admin.parse_admin_trace("STEP:login:user:wrong:1:CKR:0x000000a0\nOK\n")
    assert token_admin.setup_failure(trace) is None


# --- Part 2: token_admin child probes -----------------------------------------

_LOGIN_ROLES = ("user", "so")


def _run_probe(probe: str, fake: _FakeAdminRaw, extra: dict[str, Any], capsys: Any) -> str:
    token_admin._PROBES[probe](_ctx(fake), extra)
    return str(capsys.readouterr().out)


def _burn_extra(role: str = "user", attempts: int = 3, **overrides: Any) -> dict[str, Any]:
    extra: dict[str, Any] = {
        "role": role,
        "attempts": attempts,
        "then_correct": True,
        "then_other_role_correct": False,
        "post_success_wrongs": 0,
    }
    extra.update(overrides)
    return extra


@pytest.mark.parametrize("role", _LOGIN_ROLES)
def test_burn_happy_path(role: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11a_burn", fake, _burn_extra(role), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert trace.assumption_failed is None
    expected = [("init_token", _OK), ("setup:open", _OK)]
    if role == "user":
        expected += [("setup:so_login", _OK), ("setup:init_pin", _OK)]
    expected += [
        (f"login:{role}:wrong:1", _PIN_INCORRECT),
        (f"login:{role}:wrong:2", _PIN_INCORRECT),
        (f"login:{role}:wrong:3", _PIN_INCORRECT),
        (f"login:{role}:correct", _OK),
    ]
    assert [(step.name, step.rv) for step in trace.steps] == expected
    assert [tag for tag, _ in trace.flags] == [
        "initial",
        "attempt-1",
        "attempt-2",
        "attempt-3",
        "final",
    ]
    assert trace.pin_bounds == (4, 32)
    wrong_pin = token_admin.WRONG_SO_PIN if role == "so" else token_admin.WRONG_USER_PIN
    right_pin = token_admin.TEST_SO_PIN if role == "so" else token_admin.TEST_USER_PIN
    expected_logins = [wrong_pin] * 3 + [right_pin]
    if role == "user":
        expected_logins = [bytes(token_admin.TEST_SO_PIN)] + expected_logins
    assert [pin for _, pin in fake.logins] == expected_logins


def test_burn_stops_after_lockout(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.threshold["user"] = 2
    fake.remaining["user"] = 2
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 5), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("init_token", _OK),
        ("setup:open", _OK),
        ("setup:so_login", _OK),
        ("setup:init_pin", _OK),
        ("login:user:wrong:1", _PIN_INCORRECT),
        ("login:user:wrong:2", _PIN_LOCKED),
        ("login:user:correct", _PIN_LOCKED),
    ]
    assert len(fake.logins) == 4


@pytest.mark.parametrize("role", _LOGIN_ROLES)
def test_burn_refuses_non_pristine_counter(role: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.flags_manual = True
    low, _, _ = _ROLE_FLAGS[role]
    fake.flags |= low
    # The gate reads the provisioned state: only counters surviving InitToken
    # refuse the burn (a clean provision resets arrival wear).
    fake.init_token_keep_flags = True
    out = _run_probe("qc11a_burn", fake, _burn_extra(role), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed == "not_pristine"
    assert trace.ok is True
    assert [(step.name, step.rv) for step in trace.steps] == [("init_token", _OK)]
    assert fake.logins == []


def test_burn_no_slots(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.slots = []
    out = _run_probe("qc11a_burn", fake, _burn_extra(), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.no_slots is True
    assert fake.logins == []


def test_burn_self_provisions_raw_token(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.so_pin = None
    fake.user_pin = None
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is None
    assert trace.ok is True
    by_name = [(step.name, step.rv) for step in trace.steps]
    assert ("init_token", _OK) in by_name
    assert ("login:user:wrong:1", _PIN_INCORRECT) in by_name
    assert ("login:user:correct", _OK) in by_name
    pin_case._judge_lockout_trace(trace, role="user")
    assert classification.get_records() == []


def test_burn_init_token_refusal_is_explicit_unexercised_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _GENERAL_ERROR
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "self_provision" in trace.assumption_failed
    skipped = assert_skips(token_admin.check_child_output, 0, out, "", label="QC11a user countdown")
    assert "self_provision" in str(skipped)


def test_burn_foreign_so_pin_is_explicit_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.so_pin = b"mint-used-another-so-pin"
    out = _run_probe("qc11a_burn", fake, _burn_extra("so", 2), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "self_provision" in trace.assumption_failed
    assert trace.ok is True


def test_burn_user_init_pin_refusal_is_explicit_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_pin_always = _GENERAL_ERROR
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "setup_init_pin" in trace.assumption_failed
    assert trace.ok is True
    assert [s for s in trace.steps if ":wrong:" in s.name] == []


def test_burn_refuses_counters_surviving_provision(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.flags_manual = True
    low, _, _ = _ROLE_FLAGS["user"]
    fake.flags |= low
    fake.init_token_keep_flags = True
    out = _run_probe("qc11a_burn", fake, _burn_extra("user"), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed == "not_pristine"
    assert trace.ok is True
    assert fake.logins == []


def test_burn_unknown_role_rejected(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    with pytest.raises(ValueError, match="role"):
        _run_probe("qc11a_burn", fake, _burn_extra("admin"), capsys)


def test_burn_other_role_check(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe(
        "qc11a_burn", fake, _burn_extra("user", 2, then_other_role_correct=True), capsys
    )
    trace = token_admin.parse_admin_trace(out)
    assert ("login:so:correct", _OK) in [(s.name, s.rv) for s in trace.steps]
    final = trace.flags[-1][1]
    assert final is not None
    assert not (final & (int(CKF_SO_PIN_COUNT_LOW) | int(CKF_SO_PIN_FINAL_TRY)))
    assert ("so", bytes(token_admin.TEST_SO_PIN)) in fake.logins


def test_burn_post_success_wrongs_observe_reset(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 4, post_success_wrongs=1), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    post = [value for tag, value in trace.flags if tag == "post-1"]
    assert len(post) == 1 and post[0] is not None
    assert post[0] & int(CKF_USER_PIN_COUNT_LOW)
    assert not (post[0] & int(CKF_USER_PIN_LOCKED))


def test_burn_post_success_wrongs_observe_no_reset(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.reset_on_success = False
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 4, post_success_wrongs=1), capsys)
    trace = token_admin.parse_admin_trace(out)
    post = [value for tag, value in trace.flags if tag == "post-1"]
    assert len(post) == 1 and post[0] is not None
    assert post[0] & int(CKF_USER_PIN_LOCKED)


def test_read_snapshots_flags_and_checks_correct_login(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.min_pin = 6
    fake.max_pin = 16
    out = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert trace.pin_bounds == (6, 16)
    assert [tag for tag, _ in trace.flags] == ["initial", "final"]
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("setup:open", _OK),
        ("login:user:correct", _OK),
    ]
    assert fake.logins == [("user", bytes(token_admin.TEST_USER_PIN))]


def test_read_unknown_role_rejected(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    with pytest.raises(ValueError, match="role"):
        _run_probe("qc11a_read", fake, {"role": "admin"}, capsys)


def test_read_no_slots(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.slots = []
    out = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.no_slots is True
    assert fake.logins == []


def test_read_survives_unreadable_tokeninfo(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _GENERAL_ERROR
    out = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert trace.pin_bounds is None
    assert ("login:user:correct", _OK) in [(s.name, s.rv) for s in trace.steps]


@pytest.mark.parametrize("op", ("init_pin", "set_pin"))
def test_pin_lengths_matrix_against_declared_bounds(op: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11b_pin_lengths", fake, {"op": op}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert trace.pin_bounds == (4, 32)
    by_length = {
        int(step.name.removeprefix("setlen:")): step.rv
        for step in trace.steps
        if step.name.startswith("setlen:")
    }
    assert by_length[1] == _PIN_LEN_RANGE
    assert by_length[4] == _OK
    assert by_length[32] == _OK
    assert by_length[33] == _PIN_LEN_RANGE
    assert by_length[256] == _PIN_LEN_RANGE
    setup = [step for step in trace.steps if step.name == "setup:login"]
    assert len(setup) == 1 and setup[0].rv == _OK


def test_pin_lengths_set_pin_tracks_current_pin(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "set_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    in_bounds = [
        int(step.name.removeprefix("setlen:"))
        for step in trace.steps
        if step.name.startswith("setlen:") and step.rv == _OK
    ]
    assert in_bounds, "expected at least one accepted in-bounds SetPIN leg"
    assert fake.user_pin == token_admin.candidate_pin(max(in_bounds))


def test_pin_lengths_setup_login_failure_is_assumption(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.login_script["so"] = [_PIN_INCORRECT]
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "init_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "setup_login" in trace.assumption_failed
    assert trace.ok is True
    assert [s for s in trace.steps if s.name.startswith("setlen:")] == []


def test_pin_lengths_unreadable_bounds_skip_leg(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _GENERAL_ERROR
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "set_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.pin_bounds is None
    assert trace.ok is True
    # F3: the failed bounds read keeps its raw RV as a snapshot step (defined
    # here, so the judge still skips the leg as untestable).
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("init_token", _OK),
        ("snapshot:pinbounds", _GENERAL_ERROR),
    ]
    assert [s for s in trace.steps if s.name.startswith("setlen:")] == []


@pytest.mark.parametrize("op", ("init_pin", "set_pin"))
def test_pin_lengths_self_provisions_raw_token(op: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.so_pin = None
    fake.user_pin = None
    out = _run_probe("qc11b_pin_lengths", fake, {"op": op}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is None
    assert trace.ok is True
    assert ("init_token", _OK) in [(step.name, step.rv) for step in trace.steps]
    assert [s for s in trace.steps if s.name.startswith("setlen:")] != []


def test_pin_lengths_set_pin_init_pin_refusal_is_explicit_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_pin_always = _GENERAL_ERROR
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "set_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "setup_init_pin" in trace.assumption_failed
    assert trace.ok is True
    assert [s for s in trace.steps if s.name.startswith("setlen:")] == []


def test_pin_lengths_init_token_refusal_is_explicit_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _GENERAL_ERROR
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "set_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "self_provision" in trace.assumption_failed
    skipped = assert_skips(token_admin.check_child_output, 0, out, "", label="QC11b set_pin")
    assert "self_provision" in str(skipped)


def test_pin_lengths_unknown_op_rejected(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    with pytest.raises(ValueError, match="op"):
        _run_probe("qc11b_pin_lengths", fake, {"op": "login"}, capsys)


def test_journey_happy_path(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert [(s.name, s.rv) for s in trace.steps] == [
        ("init_token", _OK),
        ("setup:open", _OK),
        ("so_login", _OK),
        ("init_pin", _OK),
        ("user_login", _OK),
        ("set_pin", _OK),
        ("old_rejected", _PIN_INCORRECT),
        ("new_accepted", _OK),
        ("create_canary", _OK),
    ]
    assert trace.inv_objects == (1,)
    assert trace.pin_bounds == (4, 32)
    assert [pin for _, pin in fake.logins] == [
        bytes(token_admin.TEST_SO_PIN),
        bytes(token_admin.TEST_USER_PIN),
        bytes(token_admin.TEST_USER_PIN),
        bytes(token_admin.TEST_USER_PIN_2),
    ]
    labels = [attrs.get(int(CKA_LABEL)) for attrs in fake.objects.values()]
    assert bytes(token_admin.CANARY_LABEL) in labels


def test_journey_stops_after_positive_refusal(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_pin_always = _GENERAL_ERROR
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    names = [s.name for s in trace.steps]
    assert names == ["init_token", "setup:open", "so_login", "init_pin"]
    assert trace.steps[-1].rv == _GENERAL_ERROR


def test_journey_set_pin_refusal_runs_no_mutation_probes(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.set_pin_always = _GENERAL_ERROR
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    by_name = {s.name: s.rv for s in trace.steps}
    assert by_name["set_pin"] == _GENERAL_ERROR
    assert by_name["verify:old_after_refused_setpin"] == _OK
    assert by_name["verify:new_after_refused_setpin"] == _PIN_INCORRECT
    assert "old_rejected" not in by_name


def test_journey_no_slots(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.slots = []
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    assert token_admin.parse_admin_trace(out).no_slots is True


def test_verify_after_restart(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    _run_probe("qc11c_journey", fake, {}, capsys)
    out = _run_probe("qc11c_verify", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert [(s.name, s.rv) for s in trace.steps] == [
        ("setup:open", _OK),
        ("old_rejected", _PIN_INCORRECT),
        ("new_accepted", _OK),
    ]
    assert trace.inv_objects == (1,)


def test_reset_happy_path(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    _run_probe("qc11c_journey", fake, {}, capsys)
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert [(s.name, s.rv) for s in trace.steps] == [
        ("reset_init_token", _OK),
        ("setup:open", _OK),
        ("so_login", _OK),
        ("old_user_after_reset", _PIN_NOT_INITIALIZED),
    ]
    assert trace.inv_objects == (0,)


def test_reset_refusal_stops(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _GENERAL_ERROR
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert [(s.name, s.rv) for s in trace.steps] == [("reset_init_token", _GENERAL_ERROR)]


def test_unknown_probe_raises() -> None:
    with pytest.raises(ValueError, match="unknown probe"):
        token_admin._run(_ctx(_FakeAdminRaw()), {"probe": "bogus"})


def test_child_pins_are_hardcoded_test_fixtures_only(capsys: Any) -> None:
    """Invariant I3 at the child layer: every observed PIN is a test fixture."""
    allowed_logins = {
        bytes(token_admin.TEST_SO_PIN),
        bytes(token_admin.TEST_USER_PIN),
        bytes(token_admin.TEST_USER_PIN_2),
        bytes(token_admin.WRONG_SO_PIN),
        bytes(token_admin.WRONG_USER_PIN),
    }
    allowed_admin = set(allowed_logins)
    runs: list[tuple[str, dict[str, Any]]] = [
        ("qc11a_burn", _burn_extra("user", 2, then_other_role_correct=True)),
        ("qc11a_burn", _burn_extra("so", 2)),
        ("qc11a_read", {"role": "user"}),
        ("qc11b_pin_lengths", {"op": "init_pin"}),
        ("qc11b_pin_lengths", {"op": "set_pin"}),
        ("qc11c_journey", {}),
        ("qc11c_verify", {}),
        ("qc11c_reset", {}),
    ]
    for probe, extra in runs:
        fake = _FakeAdminRaw()
        if probe == "qc11c_verify":
            _run_probe("qc11c_journey", fake, {}, capsys)
        if probe == "qc11c_reset":
            _run_probe("qc11c_journey", fake, {}, capsys)
        fake.logins.clear()
        fake.pin_values.clear()
        _run_probe(probe, fake, extra, capsys)
        for _, pin in fake.logins:
            assert pin in allowed_logins, (probe, pin)
        for value in fake.pin_values:
            if value in allowed_admin:
                continue
            assert value == token_admin.candidate_pin(len(value)), (probe, value)


# --- Part 3: QC11a lockout/countdown judges + orchestration -------------------

_BASE_FLAGS = int(CKF_TOKEN_INITIALIZED)


def _flags_for(role: str, rank: int) -> int:
    if rank <= 0:
        return _BASE_FLAGS
    low, final, locked = _ROLE_FLAGS[role]
    return _BASE_FLAGS | (low, final, locked)[min(rank, 3) - 1]


def _lockout_trace(
    role: str,
    wrong_rvs: list[int],
    *,
    wrong_ranks: list[int] | None = None,
    correct_rv: int | None = _OK,
    final_rank: int | None = None,
    post_rvs: list[int] | None = None,
    post_ranks: list[int] | None = None,
    other_rv: int | None = None,
    initial_rank: int = 0,
) -> token_admin.AdminTrace:
    steps: list[token_admin.AdminStep] = [token_admin.AdminStep("setup:open", _OK)]
    flags: list[tuple[str, int | None]] = [("initial", _flags_for(role, initial_rank))]
    ranks = wrong_ranks if wrong_ranks is not None else [1] * len(wrong_rvs)
    for i, (rv, rank) in enumerate(zip(wrong_rvs, ranks, strict=True)):
        steps.append(token_admin.AdminStep(f"login:{role}:wrong:{i + 1}", rv))
        flags.append((f"attempt-{i + 1}", _flags_for(role, rank)))
    if correct_rv is not None:
        steps.append(token_admin.AdminStep(f"login:{role}:correct", correct_rv))
    for j, rv in enumerate(post_rvs or []):
        steps.append(token_admin.AdminStep(f"login:{role}:post:{j + 1}", rv))
        rank = (post_ranks or [1] * len(post_rvs or []))[j]
        flags.append((f"post-{j + 1}", _flags_for(role, rank)))
    if other_rv is not None:
        other = "so" if role == "user" else "user"
        steps.append(token_admin.AdminStep(f"login:{other}:correct", other_rv))
    if final_rank is not None:
        flags.append(("final", _flags_for(role, final_rank)))
    return token_admin.AdminTrace(
        steps=tuple(steps),
        flags=tuple(flags),
        pin_bounds=(4, 32),
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def test_qc11a_canonical_refusal_table() -> None:
    assert pin_case._QC11A_CANONICAL_WRONG == (_PIN_INCORRECT,)
    assert pin_case._QC11A_CANONICAL_LOCKED == (_PIN_LOCKED,)


def test_countdown_healthy_passes() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 3, final_rank=0)
    pin_case._judge_lockout_trace(trace, role="user")
    assert classification.get_records() == []


def test_countdown_wrong_acceptance_fails_and_preserves_first_attempts() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT, _PIN_INCORRECT, _OK], final_rank=1)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == "C_Login"
    attempts = rec.detail["attempts"]
    assert [a["op"] for a in attempts[:3]] == [
        "login:user:wrong:1",
        "login:user:wrong:2",
        "login:user:wrong:3",
    ]
    assert attempts[2]["rv"] == ckr_name(_OK)


def test_countdown_undefined_rv_fails() -> None:
    trace = _lockout_trace("user", [_UNDEFINED_RV], correct_rv=None)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_countdown_other_clean_refusal_xfails_with_original_rv() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None)
    assert_xfails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(_GENERAL_ERROR)


def test_countdown_vendor_clean_refusal_xfails() -> None:
    trace = _lockout_trace("user", [_VENDOR_RV], correct_rv=None)
    assert_xfails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(_VENDOR_RV)


def test_countdown_locked_without_flag_xfails() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 1], correct_rv=_PIN_LOCKED
    )
    assert_xfails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_xfail_record("honest_deviation")


def test_countdown_flag_locked_with_later_incorrect_fails() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_INCORRECT], wrong_ranks=[3, 3], correct_rv=None
    )
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_regressing_flags_fail() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_INCORRECT], wrong_ranks=[1, 0], correct_rv=None
    )
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_final_and_locked_together_fail() -> None:
    both = _BASE_FLAGS | int(CKF_USER_PIN_FINAL_TRY) | int(CKF_USER_PIN_LOCKED)
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=None)
    flags = (("initial", _BASE_FLAGS), ("attempt-1", both))
    trace = trace._replace(flags=flags)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_later_wrong_acceptance_preempts_earlier_xfail() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR, _OK], correct_rv=None)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == "C_Login"
    assert "login:user:wrong:2" in rec.label


def test_countdown_later_undefined_rv_preempts_earlier_xfail() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR, _UNDEFINED_RV], correct_rv=None)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "login:user:wrong:2" in rec.label


def test_countdown_later_flag_contradiction_preempts_earlier_xfail() -> None:
    both = _BASE_FLAGS | int(CKF_USER_PIN_FINAL_TRY) | int(CKF_USER_PIN_LOCKED)
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=_GENERAL_ERROR, final_rank=0)
    flags = tuple((tag, both if tag == "final" else value) for tag, value in trace.flags)
    trace = trace._replace(flags=flags)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_independence_inherits_fail_prescan() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR, _OK], correct_rv=None, other_rv=_OK)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    _assert_fail_record("accepted_invalid", None)


def test_countdown_correct_refused_xfails_when_no_lockout() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=_GENERAL_ERROR)
    assert_xfails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_xfail_record("not_operational")


def test_countdown_correct_undefined_fails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=_UNDEFINED_RV)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_correct_ok_after_lockout_fails_as_bypass() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=_OK
    )
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_countdown_correct_incorrect_after_lockout_fails() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=_PIN_INCORRECT
    )
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_correct_locked_with_evidence_passes() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=_PIN_LOCKED
    )
    pin_case._judge_lockout_trace(trace, role="user")
    assert classification.get_records() == []


def test_countdown_unknown_flags_tolerated_but_rvs_judged() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT, _OK], correct_rv=None)
    flags = tuple((tag, None) for tag, _ in trace.flags)
    trace = trace._replace(flags=flags)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_countdown_non_pristine_initial_is_harness_bug() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=None, initial_rank=1)
    with pytest.raises(AssertionError, match="pristine"):
        pin_case._judge_lockout_trace(trace, role="user")


def test_countdown_post_success_acceptance_fails() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT],
        post_rvs=[_OK],
        post_ranks=[1],
        final_rank=1,
    )
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_countdown_unknown_role_rejected() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=None)
    with pytest.raises(ValueError, match="role"):
        pin_case._judge_lockout_trace(trace, role="admin")


def test_countdown_correct_locked_without_evidence_xfails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, wrong_ranks=[1, 1], correct_rv=_PIN_LOCKED)
    assert_xfails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_xfail_record("honest_deviation")


def test_countdown_correct_ok_with_locked_final_fails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], correct_rv=_OK, final_rank=3)
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_countdown_locked_final_explained_by_post_wrongs_passes() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT],
        post_rvs=[_PIN_LOCKED],
        post_ranks=[3],
        final_rank=3,
    )
    pin_case._judge_lockout_trace(trace, role="user")
    assert classification.get_records() == []


def _phase2_trace(
    role: str, correct_rv: int, *, initial_rank: int = 0, final_rank: int | None = None
) -> token_admin.AdminTrace:
    steps = (
        token_admin.AdminStep("setup:open", _OK),
        token_admin.AdminStep(f"login:{role}:correct", correct_rv),
    )
    flags: list[tuple[str, int | None]] = [("initial", _flags_for(role, initial_rank))]
    if final_rank is not None:
        flags.append(("final", _flags_for(role, final_rank)))
    return token_admin.AdminTrace(
        steps=steps,
        flags=tuple(flags),
        pin_bounds=(4, 32),
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def test_persistence_stable_unlocked_passes() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _OK, initial_rank=1)
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_persistence_spontaneous_lockout_fails() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _OK, initial_rank=3)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_persistence_lockout_persists_passes() -> None:
    first = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=None
    )
    second = _phase2_trace("user", _PIN_LOCKED, initial_rank=3)
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_persistence_forgotten_lockout_passes_without_contradiction() -> None:
    first = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=None
    )
    second = _phase2_trace("user", _OK, initial_rank=0)
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_persistence_correct_ok_against_locked_flags_fails_as_bypass() -> None:
    first = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=None
    )
    second = _phase2_trace("user", _OK, initial_rank=3)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_persistence_spontaneous_locked_declaration_xfails() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _PIN_LOCKED, initial_rank=1)
    assert_xfails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_xfail_record("honest_deviation")


def test_persistence_correct_refused_xfails_when_unlocked() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _GENERAL_ERROR, initial_rank=1)
    assert_xfails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_xfail_record("not_operational")


def test_persistence_correct_incorrect_against_locked_fails() -> None:
    first = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=None
    )
    second = _phase2_trace("user", _PIN_INCORRECT, initial_rank=3)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_persistence_phase1_finding_preempts() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT, _OK], correct_rv=None)
    second = _phase2_trace("user", _OK, initial_rank=0)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_persistence_no_metadata_hard_lockout_plausible() -> None:
    first = _lockout_trace(
        "user", [_PIN_INCORRECT] * 2, wrong_ranks=[0, 0], correct_rv=None, final_rank=0
    )
    second = _phase2_trace("user", _PIN_LOCKED, initial_rank=0)
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_persistence_escalation_preempts_first_trace_xfail() -> None:
    first = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _OK, initial_rank=2)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "escalated across restart" in rec.summary


def test_persistence_bypass_preempts_first_trace_xfail() -> None:
    first = _lockout_trace("user", [_GENERAL_ERROR], wrong_ranks=[0], correct_rv=None, final_rank=3)
    second = _phase2_trace("user", _OK, initial_rank=3)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    rec = _assert_fail_record("accepted_invalid", None)
    assert "despite LOCKED flags after restart" in rec.summary


def test_persistence_denies_lockout_preempts_first_trace_xfail() -> None:
    first = _lockout_trace("user", [_GENERAL_ERROR], wrong_ranks=[0], correct_rv=None, final_rank=3)
    second = _phase2_trace("user", _PIN_INCORRECT, initial_rank=3)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "denies declared lockout" in rec.summary


def test_persistence_undefined_second_rv_preempts_first_trace_xfail() -> None:
    first = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _UNDEFINED_RV, initial_rank=1)
    _assert_fails(pin_case._judge_restart_persistence, first, second, role="user")
    _assert_fail_record("self_contradiction", "metadata")


def _render_trace(trace: token_admin.AdminTrace) -> str:
    lines: list[str] = []
    if trace.pin_bounds is not None:
        lines.append(f"PINBOUNDS:{trace.pin_bounds[0]}:{trace.pin_bounds[1]}")
    for step in trace.steps:
        lines.append(f"STEP:{step.name}:CKR:0x{step.rv:08x}")
    for tag, value in trace.flags:
        lines.append(f"FLAGS:{tag}:unknown" if value is None else f"FLAGS:{tag}:0x{value:08x}")
    for count in trace.inv_objects:
        lines.append(f"INV:objects={count}")
    if trace.no_slots:
        lines.append("NO_SLOTS")
    if trace.assumption_failed is not None:
        lines.append(f"ASSUMPTION_FAILED:{trace.assumption_failed}")
    if trace.ok:
        lines.append("OK")
    return "\n".join(lines) + "\n"


def test_check_child_output_crash_fails_loud() -> None:
    with pytest.raises(AssertionError, match="rc=-11"):
        token_admin.check_child_output(-11, "", "segfault", label="QC11a")


def test_check_child_output_missing_ok_fails_loud() -> None:
    with pytest.raises(AssertionError, match="no OK"):
        token_admin.check_child_output(0, "STEP:x:CKR:0x0\n", "", label="QC11a")


def test_check_child_output_no_slots_skips() -> None:
    skipped = assert_skips(token_admin.check_child_output, 0, "NO_SLOTS\n", "", label="QC11a")
    assert "slot" in str(skipped)


def test_check_child_output_assumption_skips() -> None:
    out = "ASSUMPTION_FAILED:not_pristine\nOK\n"
    skipped = assert_skips(token_admin.check_child_output, 0, out, "", label="QC11a")
    assert "not_pristine" in str(skipped)


def test_check_child_output_setup_failure_skips_with_rv() -> None:
    out = "STEP:setup:open:CKR:0x00000005\nOK\n"
    skipped = assert_skips(token_admin.check_child_output, 0, out, "", label="QC11a")
    assert "setup:open" in str(skipped)
    assert "CKR_GENERAL_ERROR" in str(skipped)


def test_check_child_output_happy_returns_trace() -> None:
    trace = token_admin.check_child_output(0, _FULL_TRACE, "", label="QC11a")
    assert trace.ok is True
    assert len(trace.steps) == 2


def test_burn_node_countdown_params_and_verdict() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 3, final_rank=0)
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    config = _StrictConfig()
    pin_case._run_qc11a_burn_node(
        _capability(),
        config,
        role="user",
        mode="countdown",
        _session_factory=factory,
        _launch=launch,
    )
    assert sessions == [_MINTED]
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        (
            "qc11a_burn",
            {
                "role": "user",
                "attempts": 3,
                "then_correct": True,
                "then_other_role_correct": False,
                "post_success_wrongs": 0,
            },
        )
    ]
    assert launch.calls[0][0] is _MINTED
    assert launch.calls[0][3] is config


def test_burn_node_lockout_uses_bound_and_skips_when_unreached() -> None:
    trace = _lockout_trace("so", [_PIN_INCORRECT] * 10, final_rank=0)
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    skipped = assert_skips(
        pin_case._run_qc11a_burn_node,
        _capability(),
        _StrictConfig(),
        role="so",
        mode="lockout",
        _session_factory=factory,
        _launch=launch,
    )
    assert "untestable" in str(skipped)
    assert launch.calls[0][2]["attempts"] == 10


def test_burn_node_bad_mode_rejected() -> None:
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    launch = _FakeLaunch([])
    with pytest.raises(ValueError, match="mode"):
        pin_case._run_qc11a_burn_node(
            _capability(),
            _StrictConfig(),
            role="user",
            mode="hammer",
            _session_factory=factory,
            _launch=launch,
        )
    assert sessions == []
    assert launch.calls == []


def test_burn_node_assumption_gate_precedes_judge() -> None:
    bad = _lockout_trace("user", [_OK], correct_rv=None)
    bad = bad._replace(assumption_failed="not_pristine")
    launch = _FakeLaunch([_ScriptedChild(_render_trace(bad))])
    factory = _session_factory()
    skipped = assert_skips(
        pin_case._run_qc11a_burn_node,
        _capability(),
        _StrictConfig(),
        role="user",
        mode="countdown",
        _session_factory=factory,
        _launch=launch,
    )
    assert "not_pristine" in str(skipped)
    assert classification.get_records() == []


def test_independence_node_params() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_OK)
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    pin_case._run_qc11a_independence_node(
        _capability(),
        _StrictConfig(),
        burned_role="user",
        _session_factory=factory,
        _launch=launch,
    )
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        (
            "qc11a_burn",
            {
                "role": "user",
                "attempts": 2,
                "then_correct": False,
                "then_other_role_correct": True,
                "post_success_wrongs": 0,
            },
        )
    ]


def test_reset_node_params() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 4,
        wrong_ranks=[1, 1, 1, 2],
        post_rvs=[_PIN_INCORRECT],
        post_ranks=[1],
    )
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    pin_case._run_qc11a_reset_node(
        _capability(), _StrictConfig(), role="user", _session_factory=factory, _launch=launch
    )
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        (
            "qc11a_burn",
            {
                "role": "user",
                "attempts": 10,
                "then_correct": True,
                "then_other_role_correct": False,
                "post_success_wrongs": 1,
                "stop_at": "final",
            },
        )
    ]


def test_persistence_node_runs_two_phases_on_one_session() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _OK, initial_rank=1)
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(first)), _ScriptedChild(_render_trace(second))]
    )
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    pin_case._run_qc11a_persistence_node(
        _capability(),
        _StrictConfig(),
        role="user",
        _session_factory=factory,
        _launch=launch,
    )
    assert sessions == [_MINTED]
    assert [probe for _, probe, _, _ in launch.calls] == ["qc11a_burn", "qc11a_read"]
    assert launch.calls[0][2]["attempts"] == 2
    assert launch.calls[0][2]["then_correct"] is False
    assert launch.calls[1][2] == {"role": "user"}
    assert launch.calls[0][0] is launch.calls[1][0] is _MINTED


def test_persistence_two_phase_real_child_measures_countdown(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out1 = _run_probe("qc11a_burn", fake, _burn_extra("user", 2, then_correct=False), capsys)
    first = token_admin.parse_admin_trace(out1)
    assert any((v or 0) & int(CKF_USER_PIN_COUNT_LOW) for _, v in first.flags)
    out2 = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    second = token_admin.parse_admin_trace(out2)
    assert second.assumption_failed is None
    assert ("login:user:correct", _OK) in [(s.name, s.rv) for s in second.steps]
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_read_measures_burned_token_without_pristine_gate(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.threshold["user"] = 1
    fake.remaining["user"] = 1
    out1 = _run_probe("qc11a_burn", fake, _burn_extra("user", 1, then_correct=False), capsys)
    first = token_admin.parse_admin_trace(out1)
    assert any((v or 0) & int(CKF_USER_PIN_LOCKED) for _, v in first.flags)
    out2 = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    second = token_admin.parse_admin_trace(out2)
    assert second.assumption_failed is None
    assert ("login:user:correct", _PIN_LOCKED) in [(s.name, s.rv) for s in second.steps]
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_persistence_phase1_skip_blocks_phase2() -> None:
    launch = _FakeLaunch([_ScriptedChild("NO_SLOTS\n")])
    factory = _session_factory()
    assert_skips(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role="user",
        _session_factory=factory,
        _launch=launch,
    )
    assert len(launch.calls) == 1


_LAUNCH_PARAM_ALLOWLIST = {
    "role",
    "attempts",
    "then_correct",
    "then_other_role_correct",
    "post_success_wrongs",
    "stop_at",
    "op",
}

_LIVE_PIN_SENTINEL = b"LIVE-PIN-SENTINEL-0001"


def test_qc11a_launch_params_carry_no_pins() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _phase2_trace("user", _OK, initial_rank=1)
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(first)), _ScriptedChild(_render_trace(second))]
    )
    factory = _session_factory()
    config = _StrictConfig()
    pin_case._run_qc11a_persistence_node(
        _capability(), config, role="user", _session_factory=factory, _launch=launch
    )
    for _, _, params, seen_config in launch.calls:
        assert set(params) <= _LAUNCH_PARAM_ALLOWLIST, params
        for value in params.values():
            assert value != _LIVE_PIN_SENTINEL
            if isinstance(value, bytes):
                assert _LIVE_PIN_SENTINEL not in value
        assert seen_config is config


def test_qc11a_orchestration_threads_config_without_pin() -> None:
    import inspect

    for fn in (
        pin_case._run_qc11a_burn_node,
        pin_case._run_qc11a_independence_node,
        pin_case._run_qc11a_reset_node,
        pin_case._run_qc11a_persistence_node,
    ):
        params = set(inspect.signature(fn).parameters)
        assert "p11_config" in params, fn.__name__
        assert "pin" not in params, fn.__name__
        assert "p11_raw_session" not in params, fn.__name__


_QC11A_NODES = (
    ("TestUserLockoutCountdown", "test_user_countdown_consistent"),
    ("TestUserLockoutCountdown", "test_user_lockout_enforced"),
    ("TestSOLockoutCountdown", "test_so_countdown_consistent"),
    ("TestSOLockoutCountdown", "test_so_lockout_enforced"),
    ("TestRoleCounterIndependence", "test_user_failures_leave_so_usable"),
    ("TestRoleCounterIndependence", "test_so_failures_leave_user_usable"),
    ("TestCounterSuccessReset", "test_user_success_resets_counter"),
    ("TestCounterSuccessReset", "test_so_success_resets_counter"),
    ("TestCounterRestartPersistence", "test_user_counter_restart_persistence"),
    ("TestCounterRestartPersistence", "test_so_counter_restart_persistence"),
)


@pytest.mark.parametrize(("cls_name", "method"), _QC11A_NODES)
def test_qc11a_nodes_skip_without_capability_and_touch_no_live_session(
    _clean_capability_env: None, cls_name: str, method: str
) -> None:
    import inspect

    cls = getattr(pin_case, cls_name)
    fn = getattr(cls, method)
    params = set(inspect.signature(fn).parameters)
    assert "p11_raw_session" not in params, f"{cls_name}::{method} must not bind a live session"
    config = SimpleNamespace(interface="auto")
    skipped = assert_skips(getattr(cls(), method), config)
    assert "PKCS11_CHECK_THROWAWAY_MODULE" in str(skipped)


def test_burn_stop_at_final_stops_before_lockout(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    extra = _burn_extra("user", 10, then_correct=True)
    extra["stop_at"] = "final"
    out = _run_probe("qc11a_burn", fake, extra, capsys)
    trace = token_admin.parse_admin_trace(out)
    wrongs = [s for s in trace.steps if ":wrong:" in s.name]
    assert len(wrongs) == 4
    assert all(s.rv == _PIN_INCORRECT for s in wrongs)
    provisioned = _flags_for("user", 2) | int(CKF_USER_PIN_INITIALIZED)
    assert trace.flags[-2] == ("attempt-4", provisioned)


def test_burn_default_stop_locks_when_threshold_reached(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 5), capsys)
    trace = token_admin.parse_admin_trace(out)
    wrongs = [s for s in trace.steps if ":wrong:" in s.name]
    assert [s.rv for s in wrongs] == [_PIN_INCORRECT] * 4 + [_PIN_LOCKED]


# --- Part 4: QC11b session-limit + PIN-length judges + orchestration -----------


def _session_policy(
    max_total: int | None, max_rw: int | None, ambient_total: int = 1, ambient_rw: int = 1
) -> tse.SessionLimitPolicy:
    return tse.SessionLimitPolicy(
        max_total=max_total, max_rw=max_rw, ambient_total=ambient_total, ambient_rw=ambient_rw
    )


def test_is_unavailable_accepts_both_spellings() -> None:
    # audit-ok: accept-both behavior holds on 4-byte and 8-byte CK_ULONG alike
    # (the spellings coincide where CK_ULONG is 32 bits); nothing here inverts.
    assert tse._is_unavailable(_UNAVAILABLE) is True
    assert tse._is_unavailable(_UNAVAILABLE_32) is True
    assert tse._is_unavailable(100) is False
    assert tse._is_unavailable(0) is False


def test_read_session_policy_maps_unavailable_to_none() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = None
    fake.max_rw = 8
    fake.ambient_total = 2
    policy, rv = tse._read_session_policy(fake, 0)
    assert rv == _OK
    assert policy is not None
    assert policy.max_total is None
    assert policy.max_rw == 8
    assert policy.ambient_total == 2


def test_read_session_policy_refusal_returns_rv() -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _GENERAL_ERROR
    policy, rv = tse._read_session_policy(fake, 0)
    assert policy is None
    assert rv == _GENERAL_ERROR


def test_session_canonical_at_total_max_passes() -> None:
    tse._judge_session_exhaustion(
        policy=_session_policy(100, 100),
        own_opens=99,
        refused_rv=_SESSION_COUNT,
        total_now=100,
        rw_now=100,
    )
    assert classification.get_records() == []


def test_session_canonical_at_rw_max_passes() -> None:
    tse._judge_session_exhaustion(
        policy=_session_policy(1000, 10),
        own_opens=9,
        refused_rv=_SESSION_COUNT,
        total_now=10,
        rw_now=10,
    )
    assert classification.get_records() == []


def test_session_early_refusal_fails_with_both_counts() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, 100),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=6,
        rw_now=6,
    )
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.detail["own_opens"] == 5
    assert rec.detail["advertised_max_total"] == 100
    assert rec.detail["observed_total"] == 6


def test_session_early_refusal_fails_regardless_of_rv() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, 100),
        own_opens=5,
        refused_rv=_GENERAL_ERROR,
        total_now=6,
        rw_now=6,
    )
    _assert_fail_record("self_contradiction", "metadata")


def test_session_at_max_other_clean_xfails_with_original_rv() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, 100),
        own_opens=99,
        refused_rv=_GENERAL_ERROR,
        total_now=100,
        rw_now=100,
    )
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(_GENERAL_ERROR)


def test_session_undefined_refusal_fails() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, 100),
        own_opens=99,
        refused_rv=_UNDEFINED_RV,
        total_now=100,
        rw_now=100,
    )
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_session_over_delivery_xfails_even_with_canonical_rv() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(2, 2),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=6,
        rw_now=6,
    )
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["observed_total"] == 6
    assert rec.detail["advertised_max_total"] == 2


def test_session_undeclared_maxima_refusal_xfails_never_passes() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(None, None),
        own_opens=4,
        refused_rv=_SESSION_COUNT,
        total_now=5,
        rw_now=5,
    )
    _assert_xfail_record("honest_deviation")


def test_session_mixed_finite_dimension_early_refusal_fails() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, None),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=6,
        rw_now=6,
    )
    _assert_fail_record("self_contradiction", "metadata")


def test_session_single_finite_total_early_refusal_fails() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(50, None),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=6,
        rw_now=6,
    )
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "earlier than advertised" in rec.summary


def test_session_single_finite_rw_early_refusal_fails() -> None:
    _assert_fails(
        tse._judge_session_exhaustion,
        policy=_session_policy(None, 50),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=6,
        rw_now=6,
    )
    _assert_fail_record("self_contradiction", "metadata")


def test_session_single_finite_dimension_unknown_count_xfails() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(50, None),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=None,
        rw_now=None,
    )
    _assert_xfail_record("honest_deviation")


def test_session_mixed_at_declared_total_applies_tiers() -> None:
    tse._judge_session_exhaustion(
        policy=_session_policy(100, None),
        own_opens=99,
        refused_rv=_SESSION_COUNT,
        total_now=100,
        rw_now=100,
    )
    assert classification.get_records() == []


def test_session_unknown_counts_with_proved_at_max_applies_tiers() -> None:
    tse._judge_session_exhaustion(
        policy=_session_policy(100, 100),
        own_opens=100,
        refused_rv=_SESSION_COUNT,
        total_now=None,
        rw_now=None,
    )
    assert classification.get_records() == []


def test_session_unknown_counts_unprovable_xfails() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(100, 100),
        own_opens=5,
        refused_rv=_SESSION_COUNT,
        total_now=None,
        rw_now=None,
    )
    _assert_xfail_record("honest_deviation")


def test_session_no_refusal_skips_as_boundary_untested() -> None:
    skipped = assert_skips(
        tse._judge_session_exhaustion,
        policy=_session_policy(1000000, 1000000),
        own_opens=100,
        refused_rv=None,
        total_now=101,
        rw_now=101,
    )
    assert "boundary-untested" in str(skipped)
    assert "100" in str(skipped)


def test_session_zero_max_is_benign_over_delivery_not_failure() -> None:
    assert_xfails(
        tse._judge_session_exhaustion,
        policy=_session_policy(0, 0),
        own_opens=1,
        refused_rv=_SESSION_COUNT,
        total_now=2,
        rw_now=2,
    )
    _assert_xfail_record("honest_deviation")


def _run_limit_node(fake: _FakeAdminRaw) -> None:
    tse.TestAdvertisedSessionLimits().test_session_limit_matches_advertised_maxima(_rs(fake))


def test_limit_node_at_max_passes_and_closes_owned() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = 3
    fake.max_rw = 3
    fake.ambient_total = 1
    fake.ambient_rw = 1
    _run_limit_node(fake)
    assert classification.get_records() == []
    assert fake.sessions == set()
    assert fake.closes == [10, 11]
    assert fake.logins == []


def test_limit_node_early_refusal_fails_and_closes_owned() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = 100
    fake.max_rw = 100
    fake.open_refusal_at = 2
    _assert_fails(_run_limit_node, fake)
    _assert_fail_record("self_contradiction", "metadata")
    assert fake.sessions == set()
    assert fake.closes == [10, 11]


def test_limit_node_over_delivery_xfails() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = 2
    fake.max_rw = 2
    fake.open_script = [_OK] * 5 + [_SESSION_COUNT]
    assert_xfails(_run_limit_node, fake)
    _assert_xfail_record("honest_deviation")
    assert fake.sessions == set()
    assert len(fake.closes) == 5


def test_limit_node_safety_cap_skips_as_boundary_untested() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = None
    fake.max_rw = None
    skipped = assert_skips(_run_limit_node, fake)
    assert "boundary-untested" in str(skipped)
    assert fake.sessions == set()
    assert len(fake.closes) == 100


def test_limit_node_unreadable_maxima_skips() -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _GENERAL_ERROR
    skipped = assert_skips(_run_limit_node, fake)
    assert "unreadable" in str(skipped)
    assert fake.sessions == set()
    assert [op for op in fake.ops if op.startswith("open:")] == []


def test_limit_node_undefined_refusal_fails() -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_UNDEFINED_RV]
    _assert_fails(_run_limit_node, fake)
    _assert_fail_record("self_contradiction", "metadata")


def test_limit_node_cleanup_refusal_after_pass_is_terminal() -> None:
    fake = _FakeAdminRaw()
    fake.max_total = 3
    fake.max_rw = 3
    fake.close_script = [_GENERAL_ERROR, _OK]
    assert_xfails(_run_limit_node, fake)
    rec = _assert_xfail_record("not_operational")
    assert rec.operation == "C_CloseSession"
    assert fake.closes == [10, 11]


class _DriftingRaw(_FakeAdminRaw):
    def __init__(self) -> None:
        super().__init__()
        self._drifted = False

    def C_OpenSession(  # noqa: N802
        self, slot_id: int, flags: int, app: Any, notify: Any, sess_ptr: Any
    ) -> int:
        rv = super().C_OpenSession(slot_id, flags, app, notify, sess_ptr)
        if len(self.sessions) == 2 and not self._drifted:
            self._drifted = True
            self.ambient_total += 10
        return rv


def test_limit_node_ambient_drift_is_visible_in_evidence() -> None:
    fake = _DriftingRaw()
    fake.max_total = 10
    fake.max_rw = 100
    fake.open_script = [_OK, _OK, _GENERAL_ERROR]
    assert_xfails(_run_limit_node, fake)
    rec = _assert_xfail_record("honest_deviation")
    assert rec.detail["ambient_before_total"] == 1
    assert rec.detail["observed_total"] == 13
    assert rec.detail["own_opens"] == 2


def test_limit_node_binds_live_session_not_config() -> None:
    import inspect

    params = set(
        inspect.signature(
            tse.TestAdvertisedSessionLimits.test_session_limit_matches_advertised_maxima
        ).parameters
    )
    assert "p11_raw_session" in params
    assert "p11_config" not in params


def _lengths_trace(
    bounds: tuple[int, int] | None, legs: list[tuple[int, int]]
) -> token_admin.AdminTrace:
    steps = [
        token_admin.AdminStep("setup:open", _OK),
        token_admin.AdminStep("setup:login", _OK),
    ]
    steps.extend(token_admin.AdminStep(f"setlen:{length}", rv) for length, rv in legs)
    return token_admin.AdminTrace(
        steps=tuple(steps),
        flags=(),
        pin_bounds=bounds,
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def test_pin_lengths_canonical_matrix_passes() -> None:
    trace = _lengths_trace(
        (4, 32),
        [(1, _PIN_LEN_RANGE), (4, _OK), (18, _OK), (32, _OK), (33, _PIN_LEN_RANGE)],
    )
    tse._judge_pin_lengths(trace, op="init_pin")
    assert classification.get_records() == []


def test_pin_lengths_over_max_accepted_fails() -> None:
    trace = _lengths_trace((4, 32), [(4, _OK), (64, _OK)])
    _assert_fails(tse._judge_pin_lengths, trace, op="set_pin")
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == "C_SetPIN"


def test_pin_lengths_under_min_accepted_fails() -> None:
    trace = _lengths_trace((4, 32), [(1, _OK)])
    _assert_fails(tse._judge_pin_lengths, trace, op="init_pin")
    rec = _assert_fail_record("accepted_invalid", None)
    assert rec.operation == "C_InitPIN"


def test_pin_lengths_in_bounds_refused_xfails() -> None:
    trace = _lengths_trace((4, 32), [(8, _GENERAL_ERROR)])
    assert_xfails(tse._judge_pin_lengths, trace, op="set_pin")
    rec = _assert_xfail_record("not_operational")
    assert rec.actual_ckr == ckr_name(_GENERAL_ERROR)


def test_pin_lengths_out_of_bounds_other_clean_xfails() -> None:
    trace = _lengths_trace((4, 32), [(1, _GENERAL_ERROR)])
    assert_xfails(tse._judge_pin_lengths, trace, op="init_pin")
    rec = _assert_xfail_record("nonspec_reject")
    assert rec.actual_ckr == ckr_name(_GENERAL_ERROR)


def test_pin_lengths_undefined_rv_fails() -> None:
    trace = _lengths_trace((4, 32), [(8, _UNDEFINED_RV)])
    _assert_fails(tse._judge_pin_lengths, trace, op="set_pin")
    _assert_fail_record("self_contradiction", "metadata")


def test_pin_lengths_unreadable_bounds_skip() -> None:
    trace = _lengths_trace(None, [])
    skipped = assert_skips(tse._judge_pin_lengths, trace, op="init_pin")
    assert "untestable" in str(skipped)


def test_pin_lengths_impossible_bounds_fail_as_metadata() -> None:
    trace = _lengths_trace((32, 4), [(8, _PIN_LEN_RANGE)])
    _assert_fails(tse._judge_pin_lengths, trace, op="init_pin")
    _assert_fail_record("self_contradiction", "metadata")


def test_pin_lengths_missing_legs_is_harness_bug() -> None:
    trace = _lengths_trace((4, 32), [])
    with pytest.raises(AssertionError, match="setlen"):
        tse._judge_pin_lengths(trace, op="init_pin")


def test_pin_lengths_bad_op_rejected() -> None:
    trace = _lengths_trace((4, 32), [(4, _OK)])
    with pytest.raises(ValueError, match="op"):
        tse._judge_pin_lengths(trace, op="login")


def test_pin_lengths_strongest_wins_over_early_xfail() -> None:
    trace = _lengths_trace((4, 32), [(8, _GENERAL_ERROR), (64, _OK)])
    _assert_fails(tse._judge_pin_lengths, trace, op="set_pin")
    fails = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert [(rec.reason, rec.kind) for rec in fails] == [("accepted_invalid", None)]


def test_pin_length_legs_cap_absurd_bounds() -> None:
    legs = token_admin._pin_length_legs(4, 2**32 - 1)
    assert legs
    assert max(legs) <= 4096


def test_pin_length_legs_cover_normal_bounds() -> None:
    assert token_admin._pin_length_legs(4, 32) == [1, 3, 4, 18, 32, 33, 256]


def test_pin_length_legs_boundary_at_cap() -> None:
    assert 4096 in token_admin._pin_length_legs(4, 4095)
    assert 4097 not in token_admin._pin_length_legs(4, 4096)
    assert token_admin.pin_sweep_capped(4, 4095) is False
    assert token_admin.pin_sweep_capped(4, 4096) is True
    assert token_admin.pin_sweep_capped(4, 32) is False


def test_pin_lengths_absurd_bounds_capped_and_recorded() -> None:
    lengths = token_admin._pin_length_legs(4, 2**32 - 1)
    trace = _lengths_trace(
        (4, 2**32 - 1),
        [(length, _OK if length >= 4 else _PIN_LEN_RANGE) for length in lengths],
    )
    assert_xfails(tse._judge_pin_lengths, trace, op="init_pin")
    rec = _assert_xfail_record("not_operational")
    assert "sweep cap" in rec.summary


def test_pin_lengths_absurd_min_recorded() -> None:
    trace = _lengths_trace(
        (5000, 9000), [(1, _PIN_LEN_RANGE), (4, _PIN_LEN_RANGE), (256, _PIN_LEN_RANGE)]
    )
    assert_xfails(tse._judge_pin_lengths, trace, op="set_pin")
    rec = _assert_xfail_record("not_operational")
    assert "sweep cap" in rec.summary


def test_pin_lengths_one_byte_positive_leg_when_min_is_one() -> None:
    trace = _lengths_trace((1, 32), [(1, _OK)])
    tse._judge_pin_lengths(trace, op="init_pin")
    assert classification.get_records() == []
    refused = _lengths_trace((1, 32), [(1, _GENERAL_ERROR)])
    assert_xfails(tse._judge_pin_lengths, refused, op="init_pin")
    _assert_xfail_record("not_operational")


@pytest.mark.parametrize("op", ("init_pin", "set_pin"))
def test_pin_length_node_params_and_verdict(op: str) -> None:
    trace = _lengths_trace((4, 32), [(4, _OK), (1, _PIN_LEN_RANGE)])
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    config = _StrictConfig()
    tse._run_qc11b_pin_length_node(
        _capability(), config, op=op, _session_factory=factory, _launch=launch
    )
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        ("qc11b_pin_lengths", {"op": op})
    ]
    assert launch.calls[0][3] is config


def test_pin_length_node_bad_op_rejected_without_launch() -> None:
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    launch = _FakeLaunch([])
    with pytest.raises(ValueError, match="op"):
        tse._run_qc11b_pin_length_node(
            _capability(), _StrictConfig(), op="login", _session_factory=factory, _launch=launch
        )
    assert sessions == []
    assert launch.calls == []


def test_pin_length_node_unreadable_bounds_skips() -> None:
    trace = _lengths_trace(None, [])
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    skipped = assert_skips(
        tse._run_qc11b_pin_length_node,
        _capability(),
        _StrictConfig(),
        op="init_pin",
        _session_factory=factory,
        _launch=launch,
    )
    assert "untestable" in str(skipped)


def test_pin_length_node_assumption_skips_without_records() -> None:
    launch = _FakeLaunch([_ScriptedChild("ASSUMPTION_FAILED:setup_login\nOK\n")])
    factory = _session_factory()
    skipped = assert_skips(
        tse._run_qc11b_pin_length_node,
        _capability(),
        _StrictConfig(),
        op="set_pin",
        _session_factory=factory,
        _launch=launch,
    )
    assert "setup_login" in str(skipped)
    assert classification.get_records() == []


def test_pin_length_launch_params_carry_no_pins() -> None:
    trace = _lengths_trace((4, 32), [(4, _OK)])
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    tse._run_qc11b_pin_length_node(
        _capability(), _StrictConfig(), op="set_pin", _session_factory=factory, _launch=launch
    )
    for _, _, params, _ in launch.calls:
        assert set(params) <= _LAUNCH_PARAM_ALLOWLIST, params
        for value in params.values():
            assert value != _LIVE_PIN_SENTINEL


@pytest.mark.parametrize("method", ("test_init_pin_length_policy", "test_set_pin_length_policy"))
def test_pin_length_nodes_skip_without_capability_and_stay_off_live(
    _clean_capability_env: None, method: str
) -> None:
    import inspect

    cls = tse.TestPinLengthPolicyOnDisposableToken
    fn = getattr(cls, method)
    params = set(inspect.signature(fn).parameters)
    assert "p11_raw_session" not in params
    marks = getattr(cls, "pytestmark", [])
    marks = list(marks) if isinstance(marks, list) else [marks]
    assert any(mark.name == "destructive" for mark in marks)
    skipped = assert_skips(fn, cls(), SimpleNamespace(interface="auto"))
    assert "PKCS11_CHECK_THROWAWAY_MODULE" in str(skipped)


# --- Part 5: QC11c journey + reset judges + orchestration ----------------------

_JOURNEY_POSITIVE = ("init_token", "so_login", "init_pin", "user_login", "set_pin")
_TINIT = int(CKF_TOKEN_INITIALIZED)
_UINIT = int(CKF_USER_PIN_INITIALIZED)


def _journey_flags(
    *, init_set: bool = True, user_init_set: bool = True
) -> tuple[tuple[str, int | None], ...]:
    return (
        ("after_init_token", _TINIT if init_set else 0),
        ("after_so_login", _TINIT),
        ("after_init_pin", _TINIT | (_UINIT if user_init_set else 0)),
        ("after_user_login", _TINIT | _UINIT),
        ("after_set_pin", _TINIT | _UINIT),
        ("end", _TINIT | _UINIT),
    )


def _journey_trace(
    steps: list[tuple[str, int]] | None = None,
    *,
    flags: tuple[tuple[str, int | None], ...] | None = None,
    inv: tuple[int, ...] = (1,),
) -> token_admin.AdminTrace:
    if steps is None:
        steps = [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _OK),
            ("old_rejected", _PIN_INCORRECT),
            ("new_accepted", _OK),
            ("create_canary", _OK),
        ]
    return token_admin.AdminTrace(
        steps=tuple(token_admin.AdminStep(name, rv) for name, rv in steps),
        flags=_journey_flags() if flags is None else flags,
        pin_bounds=(4, 32),
        inv_objects=inv,
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def _verify_trace(
    steps: list[tuple[str, int]] | None = None, *, inv: tuple[int, ...] = (1,)
) -> token_admin.AdminTrace:
    if steps is None:
        steps = [("setup:open", _OK), ("old_rejected", _PIN_INCORRECT), ("new_accepted", _OK)]
    return token_admin.AdminTrace(
        steps=tuple(token_admin.AdminStep(name, rv) for name, rv in steps),
        flags=(("verify", _TINIT | _UINIT),),
        pin_bounds=(4, 32),
        inv_objects=inv,
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def _reset_trace(
    steps: list[tuple[str, int]] | None = None, *, inv: tuple[int, ...] = (0,)
) -> token_admin.AdminTrace:
    if steps is None:
        steps = [
            ("reset_init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("old_user_after_reset", _PIN_NOT_INITIALIZED),
        ]
    return token_admin.AdminTrace(
        steps=tuple(token_admin.AdminStep(name, rv) for name, rv in steps),
        flags=(("after_reset_init_token", _TINIT), ("end", _TINIT)),
        pin_bounds=(4, 32),
        inv_objects=inv,
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def test_journey_happy_assesses_clean_and_reached() -> None:
    records, reached = sopin_case._assess_provision_journey(_journey_trace())
    assert reached is True
    assert records == []
    assert classification.get_records() == []


def test_journey_positive_refusal_is_unexercised_not_green() -> None:
    trace = _journey_trace([("init_token", _OK), ("setup:open", _OK), ("so_login", _GENERAL_ERROR)])
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]
    assert "unexercised" in records[0].summary
    assert records[0].actual_ckr == ckr_name(_GENERAL_ERROR)


def test_journey_unsupported_api_is_unexercised() -> None:
    trace = _journey_trace([("init_token", _NOT_SUPPORTED)])
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_journey_undefined_positive_rv_fails() -> None:
    trace = _journey_trace([("init_token", _UNDEFINED_RV)])
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "metadata")]


def test_journey_init_pin_refusal_proves_no_mutation() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _GENERAL_ERROR),
        ],
        flags=(("after_init_token", _TINIT), ("after_init_pin", _TINIT)),
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert len(records) == 1
    assert records[0].reason == "not_operational"


def test_journey_refused_init_pin_with_mutated_flag_fails() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _GENERAL_ERROR),
        ],
        flags=(("after_init_token", _TINIT), ("after_init_pin", _TINIT | _UINIT)),
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert [(rec.reason, rec.outcome) for rec in records] == [
        ("not_operational", "xfail"),
        ("self_contradiction", "fail"),
    ]


def test_journey_refused_set_pin_with_clean_verify_is_unexercised() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _GENERAL_ERROR),
            ("verify:old_after_refused_setpin", _OK),
            ("verify:new_after_refused_setpin", _PIN_INCORRECT),
        ]
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_journey_refused_but_mutated_set_pin_fails() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _GENERAL_ERROR),
            ("verify:old_after_refused_setpin", _PIN_INCORRECT),
            ("verify:new_after_refused_setpin", _OK),
        ]
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert ("self_contradiction", "fail") in [(rec.reason, rec.outcome) for rec in records]


def test_journey_refused_set_pin_with_unreadable_state_xfails() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _GENERAL_ERROR),
            ("verify:old_after_refused_setpin", _GENERAL_ERROR),
            ("verify:new_after_refused_setpin", _PIN_INCORRECT),
        ]
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert all(rec.outcome == "xfail" for rec in records)
    assert len(records) == 2


def test_journey_missing_verify_steps_is_harness_bug() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _GENERAL_ERROR),
        ]
    )
    with pytest.raises(AssertionError, match="verify"):
        sopin_case._assess_provision_journey(trace)


def _reached_trace(**overrides: int) -> token_admin.AdminTrace:
    steps = [
        ("init_token", _OK),
        ("setup:open", _OK),
        ("so_login", _OK),
        ("init_pin", _OK),
        ("user_login", _OK),
        ("set_pin", _OK),
        ("old_rejected", _PIN_INCORRECT),
        ("new_accepted", _OK),
        ("create_canary", _OK),
    ]
    by_name = dict(steps)
    by_name.update(overrides)
    return _journey_trace([(name, by_name[name]) for name, _ in steps])


def test_journey_old_pin_accepted_fails() -> None:
    records, reached = sopin_case._assess_provision_journey(_reached_trace(old_rejected=_OK))
    assert reached is True
    assert [(rec.reason, rec.kind) for rec in records] == [("accepted_invalid", "lifecycle")]


def test_journey_old_pin_other_clean_xfails() -> None:
    records, reached = sopin_case._assess_provision_journey(
        _reached_trace(old_rejected=_GENERAL_ERROR)
    )
    assert reached is True
    assert [(rec.reason, rec.outcome) for rec in records] == [("nonspec_reject", "xfail")]


def test_journey_new_pin_refused_xfails_never_passes() -> None:
    records, reached = sopin_case._assess_provision_journey(
        _reached_trace(new_accepted=_GENERAL_ERROR)
    )
    assert reached is True
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_journey_canary_refused_xfails_and_suppresses_inv() -> None:
    records, reached = sopin_case._assess_provision_journey(
        _reached_trace(create_canary=_GENERAL_ERROR)
    )
    assert reached is True
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_journey_canary_created_then_gone_fails() -> None:
    trace = _reached_trace()
    trace = trace._replace(inv_objects=(0,))
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is True
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "lifecycle")]


def test_journey_unreadable_inventory_xfails() -> None:
    trace = _reached_trace()
    trace = trace._replace(inv_objects=())
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is True
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_journey_unset_token_initialized_flag_xfails() -> None:
    trace = _reached_trace()
    trace = trace._replace(flags=_journey_flags(init_set=False))
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is True
    assert [(rec.reason, rec.kind) for rec in records] == [("honest_deviation", "metadata")]


def test_journey_unset_user_initialized_flag_xfails() -> None:
    trace = _reached_trace()
    trace = trace._replace(flags=_journey_flags(user_init_set=False))
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is True
    assert [(rec.reason, rec.kind) for rec in records] == [("honest_deviation", "metadata")]


def test_journey_refused_set_pin_clearing_user_init_fails() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _GENERAL_ERROR),
            ("verify:old_after_refused_setpin", _OK),
            ("verify:new_after_refused_setpin", _PIN_INCORRECT),
        ],
        flags=(("after_refused_setpin", _TINIT),),
    )
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is False
    assert ("self_contradiction", "fail") in [(rec.reason, rec.outcome) for rec in records]


def test_journey_missing_positive_step_is_harness_bug() -> None:
    trace = _journey_trace([("so_login", _OK)])
    with pytest.raises(AssertionError, match="incomplete"):
        sopin_case._assess_provision_journey(trace)


def test_journey_missing_old_when_reached_is_harness_bug() -> None:
    trace = _journey_trace(
        [
            ("init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("init_pin", _OK),
            ("user_login", _OK),
            ("set_pin", _OK),
            ("new_accepted", _OK),
            ("create_canary", _OK),
        ]
    )
    with pytest.raises(AssertionError, match="old_rejected"):
        sopin_case._assess_provision_journey(trace)


def test_persistence_happy_assesses_clean() -> None:
    assert sopin_case._assess_provision_persistence(_verify_trace(), canary_established=True) == []
    assert classification.get_records() == []


def test_persistence_old_accepted_fails() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace([("setup:open", _OK), ("old_rejected", _OK), ("new_accepted", _OK)]),
        canary_established=True,
    )
    assert [(rec.reason, rec.kind) for rec in records] == [("accepted_invalid", "lifecycle")]


def test_persistence_old_other_clean_xfails() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(
            [("setup:open", _OK), ("old_rejected", _GENERAL_ERROR), ("new_accepted", _OK)]
        ),
        canary_established=True,
    )
    assert [(rec.reason, rec.outcome) for rec in records] == [("nonspec_reject", "xfail")]


def test_persistence_new_refused_xfails() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(
            [
                ("setup:open", _OK),
                ("old_rejected", _PIN_INCORRECT),
                ("new_accepted", _GENERAL_ERROR),
            ]
        ),
        canary_established=True,
    )
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_persistence_lost_canary_fails() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(inv=(0,)), canary_established=True
    )
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "lifecycle")]


def test_persistence_unreadable_inventory_xfails() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(inv=()), canary_established=True
    )
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_persistence_unestablished_canary_suppresses_loss_fail() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(inv=(0,)), canary_established=False
    )
    assert records == []


def test_persistence_unestablished_canary_suppresses_unreadable() -> None:
    records = sopin_case._assess_provision_persistence(
        _verify_trace(inv=()), canary_established=False
    )
    assert records == []


def test_reset_happy_assesses_clean() -> None:
    assert ckr_case._assess_sacrificial_reset(_reset_trace()) == []
    assert classification.get_records() == []


def test_reset_old_user_incorrect_also_canonical() -> None:
    trace = _reset_trace(
        [
            ("reset_init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("old_user_after_reset", _PIN_INCORRECT),
        ]
    )
    assert ckr_case._assess_sacrificial_reset(trace) == []


def test_reset_refusal_is_unexercised_and_stops() -> None:
    records = ckr_case._assess_sacrificial_reset(
        _reset_trace([("reset_init_token", _GENERAL_ERROR)])
    )
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]
    assert "unexercised" in records[0].summary


def test_reset_undefined_rv_fails() -> None:
    records = ckr_case._assess_sacrificial_reset(
        _reset_trace([("reset_init_token", _UNDEFINED_RV)])
    )
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "metadata")]


def test_reset_so_refused_xfails_and_suppresses_inv() -> None:
    trace = _reset_trace(
        [
            ("reset_init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _GENERAL_ERROR),
            ("old_user_after_reset", _PIN_NOT_INITIALIZED),
        ],
        inv=(),
    )
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_reset_old_user_accepted_fails() -> None:
    trace = _reset_trace(
        [
            ("reset_init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("old_user_after_reset", _OK),
        ]
    )
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.kind) for rec in records] == [("accepted_invalid", "lifecycle")]


def test_reset_old_user_other_clean_xfails() -> None:
    trace = _reset_trace(
        [
            ("reset_init_token", _OK),
            ("setup:open", _OK),
            ("so_login", _OK),
            ("old_user_after_reset", _GENERAL_ERROR),
        ]
    )
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.outcome) for rec in records] == [("nonspec_reject", "xfail")]


def test_reset_surviving_canary_fails() -> None:
    records = ckr_case._assess_sacrificial_reset(_reset_trace(inv=(1,)))
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "lifecycle")]


def test_reset_unreadable_inventory_xfails() -> None:
    records = ckr_case._assess_sacrificial_reset(_reset_trace(inv=()))
    assert [(rec.reason, rec.outcome) for rec in records] == [("not_operational", "xfail")]


def test_reset_unset_token_flag_xfails() -> None:
    trace = _reset_trace()
    trace = trace._replace(flags=(("after_reset_init_token", 0), ("end", 0)))
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.kind) for rec in records] == [("honest_deviation", "metadata")]


def test_reset_lingering_user_init_flag_xfails() -> None:
    trace = _reset_trace()
    trace = trace._replace(flags=(("after_reset_init_token", _TINIT | _UINIT), ("end", _TINIT)))
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.kind) for rec in records] == [("honest_deviation", "metadata")]


def test_reset_missing_step_is_harness_bug() -> None:
    with pytest.raises(AssertionError, match="reset_init_token"):
        ckr_case._assess_sacrificial_reset(_reset_trace([("setup:open", _OK)]))


def test_raise_strongest_empty_returns() -> None:
    sopin_case._raise_strongest_qc11c([])
    assert classification.get_records() == []


def test_raise_strongest_prefers_fail_and_keeps_first_on_tie() -> None:
    trace = _reached_trace(old_rejected=_GENERAL_ERROR)
    first, _ = sopin_case._assess_provision_journey(trace)
    trace = _reached_trace(old_rejected=_OK)
    second, _ = sopin_case._assess_provision_journey(trace)
    assert [rec.outcome for rec in first] == ["xfail"]
    assert [rec.outcome for rec in second] == ["fail"]
    classification.clear()
    with pytest.raises(Failed):
        sopin_case._raise_strongest_qc11c(first + second)


def test_raise_strongest_keeps_first_maximal_on_tie() -> None:
    trace = _reached_trace(new_accepted=_GENERAL_ERROR)
    first, _ = sopin_case._assess_provision_journey(trace)
    second = sopin_case._assess_provision_persistence(
        _verify_trace(
            [
                ("setup:open", _OK),
                ("old_rejected", _PIN_INCORRECT),
                ("new_accepted", _GENERAL_ERROR),
            ]
        ),
        canary_established=True,
    )
    assert [rec.outcome for rec in first + second] == ["xfail", "xfail"]
    first_label = first[0].label
    with pytest.raises(XFailed) as exc_info:
        sopin_case._raise_strongest_qc11c(first + second)
    raised = getattr(exc_info.value, "_pkcs11_check_classification", None)
    assert raised is not None
    assert raised.label == first_label


def test_journey_positive_step_table() -> None:
    assert sopin_case._QC11C_JOURNEY_POSITIVE_STEPS == _JOURNEY_POSITIVE


def test_check_child_output_no_slots_fail_loud() -> None:
    _assert_fails(
        token_admin.check_child_output, 0, "NO_SLOTS\n", "", label="QC11c", no_slots="fail"
    )
    _assert_fail_record("self_contradiction", "lifecycle")


def test_journey_node_happy_runs_two_phases() -> None:
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(_render_trace(_verify_trace())),
        ]
    )
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    config = _StrictConfig()
    sopin_case._run_qc11c_journey_node(
        _capability(), config, _session_factory=factory, _launch=launch
    )
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        ("qc11c_journey", {}),
        ("qc11c_verify", {}),
    ]
    assert sessions == [_MINTED]
    assert launch.calls[0][3] is config
    assert classification.get_records() == []


def test_journey_node_unreached_blocks_phase_two() -> None:
    trace = _journey_trace([("init_token", _GENERAL_ERROR)])
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    assert_xfails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    _assert_xfail_record("not_operational")
    assert len(launch.calls) == 1


def test_journey_node_reached_defect_runs_verify_and_keeps_both() -> None:
    phase1 = _reached_trace(old_rejected=_OK)
    phase2 = _verify_trace([("setup:open", _OK), ("old_rejected", _OK), ("new_accepted", _OK)])
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    factory = _session_factory()
    _assert_fails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    fails = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert len(fails) == 2
    assert all(rec.reason == "accepted_invalid" for rec in fails)


def test_journey_node_phase_two_no_slots_fails() -> None:
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(_journey_trace())), _ScriptedChild("NO_SLOTS\n")]
    )
    factory = _session_factory()
    _assert_fails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    _assert_fail_record("self_contradiction", "lifecycle")


def test_journey_node_refused_canary_never_fails_as_lost() -> None:
    phase1 = _reached_trace(create_canary=_GENERAL_ERROR)._replace(inv_objects=(0,))
    phase2 = _verify_trace(inv=(0,))
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    factory = _session_factory()
    assert_xfails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    _assert_xfail_record("not_operational")


def test_journey_node_unreadable_phase1_inventory_never_fails_as_lost() -> None:
    phase1 = _reached_trace()._replace(inv_objects=())
    phase2 = _verify_trace(inv=(0,))
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    factory = _session_factory()
    assert_xfails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    _assert_xfail_record("not_operational")


def test_journey_node_established_then_lost_canary_still_fails() -> None:
    phase2 = _verify_trace(inv=(0,))
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(_journey_trace())), _ScriptedChild(_render_trace(phase2))]
    )
    factory = _session_factory()
    _assert_fails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    rec = _assert_fail_record("self_contradiction", "lifecycle")
    assert "canary lost" in rec.summary


def test_reset_node_happy_runs_provision_then_reset() -> None:
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(_render_trace(_reset_trace())),
        ]
    )
    sessions: list[Any] = []
    factory = _session_factory(record=sessions)
    ckr_case._run_qc11c_reset_node(
        _capability(), _StrictConfig(), _session_factory=factory, _launch=launch
    )
    assert [(probe, params) for _, probe, params, _ in launch.calls] == [
        ("qc11c_journey", {}),
        ("qc11c_reset", {}),
    ]
    assert sessions == [_MINTED]
    assert classification.get_records() == []


def test_reset_node_unreached_provision_blocks_reset() -> None:
    trace = _journey_trace([("init_token", _GENERAL_ERROR)])
    launch = _FakeLaunch([_ScriptedChild(_render_trace(trace))])
    factory = _session_factory()
    assert_xfails(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    _assert_xfail_record("not_operational")
    assert len(launch.calls) == 1


def test_reset_node_keeps_original_defect_when_reset_also_fails() -> None:
    phase1 = _reached_trace(old_rejected=_OK)
    phase2 = _reset_trace(inv=(1,))
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    factory = _session_factory()
    _assert_fails(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    records = classification.get_records()
    assert [rec.outcome for rec in records] == ["fail", "fail"]
    assert "old PIN" in records[0].summary


def test_reset_node_provision_xfail_with_clean_reset_xfails() -> None:
    phase1 = _reached_trace(new_accepted=_GENERAL_ERROR)
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(phase1)),
            _ScriptedChild(_render_trace(_reset_trace())),
        ]
    )
    factory = _session_factory()
    assert_xfails(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=factory,
        _launch=launch,
    )
    recs = classification.get_records()
    assert len(recs) == 1 and recs[0].outcome == "xfail"


def test_qc11c_orchestration_threads_config_without_pin() -> None:
    import inspect

    for fn in (sopin_case._run_qc11c_journey_node, ckr_case._run_qc11c_reset_node):
        params = set(inspect.signature(fn).parameters)
        assert "p11_config" in params, fn.__name__
        assert "pin" not in params, fn.__name__
        assert "p11_raw_session" not in params, fn.__name__


@pytest.mark.parametrize(
    ("module", "cls_name", "method"),
    (
        ("sopin", "TestSacrificialProvisioningJourney", "test_sacrificial_provisioning_journey"),
        ("ckr", "TestSacrificialResetSemantics", "test_reset_destroys_only_resettable_data"),
    ),
)
def test_qc11c_nodes_skip_without_capability_and_stay_off_live(
    _clean_capability_env: None, module: str, cls_name: str, method: str
) -> None:
    import inspect

    mod = sopin_case if module == "sopin" else ckr_case
    marks = getattr(mod, "pytestmark", [])
    marks = list(marks) if isinstance(marks, list) else [marks]
    assert any(mark.name == "destructive" for mark in marks)
    cls = getattr(mod, cls_name)
    fn = getattr(cls, method)
    assert "p11_raw_session" not in set(inspect.signature(fn).parameters)
    skipped = assert_skips(fn, cls(), SimpleNamespace(interface="auto"))
    assert "PKCS11_CHECK_THROWAWAY_MODULE" in str(skipped)


def test_lockout_enforced_passes() -> None:
    trace = _lockout_trace(
        "user", [_PIN_INCORRECT, _PIN_LOCKED], wrong_ranks=[1, 3], correct_rv=_PIN_LOCKED
    )
    pin_case._judge_lockout_enforced(trace, role="user")
    assert classification.get_records() == []


def test_lockout_unreached_skips_with_attempt_log() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 3, final_rank=0)
    skipped = assert_skips(pin_case._judge_lockout_enforced, trace, role="user")
    assert "untestable" in str(skipped)
    assert "CKR_PIN_INCORRECT" in str(skipped)


def test_lockout_inconsistency_preempts_untestable_skip() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT, _OK], final_rank=1)
    _assert_fails(pin_case._judge_lockout_enforced, trace, role="user")
    _assert_fail_record("accepted_invalid", None)


def test_independence_healthy_passes() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_OK)
    pin_case._judge_independence(trace, burned_role="user")
    assert classification.get_records() == []


def test_independence_other_counter_moved_fails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_OK)
    polluted = _BASE_FLAGS | int(CKF_SO_PIN_COUNT_LOW)
    flags = trace.flags + (("final", polluted),)
    trace = trace._replace(flags=flags)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_independence_other_login_refused_xfails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_GENERAL_ERROR)
    assert_xfails(pin_case._judge_independence, trace, burned_role="user")
    _assert_xfail_record("not_operational")


def test_independence_other_login_undefined_fails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_UNDEFINED_RV)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_independence_missing_other_step_is_harness_bug() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None)
    with pytest.raises(AssertionError, match="other"):
        pin_case._judge_independence(trace, burned_role="user")


def test_independence_other_locked_by_burns_fails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_PIN_LOCKED)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_independence_other_locked_without_initial_xfails() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_PIN_LOCKED)
    flags = tuple((tag, None) if tag == "initial" else (tag, value) for tag, value in trace.flags)
    trace = trace._replace(flags=flags)
    assert_xfails(pin_case._judge_independence, trace, burned_role="user")
    _assert_xfail_record("honest_deviation")


def test_independence_dirty_other_initial_skips() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_OK)
    dirty = _BASE_FLAGS | int(CKF_SO_PIN_COUNT_LOW)
    flags = (("initial", dirty),) + tuple(
        (tag, value) for tag, value in trace.flags if tag != "initial"
    )
    trace = trace._replace(flags=flags)
    skipped = assert_skips(pin_case._judge_independence, trace, burned_role="user")
    assert "untestable" in str(skipped)


def test_independence_own_flag_fail_preempts_trace_xfail() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, other_rv=_OK)
    both_worn = _BASE_FLAGS | int(CKF_USER_PIN_COUNT_LOW) | int(CKF_SO_PIN_COUNT_LOW)
    flags = trace.flags + (("final", both_worn),)
    trace = trace._replace(flags=flags)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "consumed the so retry counter" in rec.summary


def test_independence_own_locked_fail_preempts_trace_xfail() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, other_rv=_PIN_LOCKED)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert "locked by" in rec.summary


def test_independence_undefined_other_rv_preempts_trace_xfail() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, other_rv=_UNDEFINED_RV)
    _assert_fails(pin_case._judge_independence, trace, burned_role="user")
    _assert_fail_record("self_contradiction", "metadata")


def test_independence_dirty_initial_skips_despite_moved_flags() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_OK)
    dirty = _BASE_FLAGS | int(CKF_SO_PIN_COUNT_LOW)
    flags = (("initial", dirty),) + tuple(
        (tag, value) for tag, value in trace.flags if tag != "initial"
    )
    flags = flags + (("final", dirty | int(CKF_USER_PIN_COUNT_LOW)),)
    trace = trace._replace(flags=flags)
    skipped = assert_skips(pin_case._judge_independence, trace, burned_role="user")
    assert "untestable" in str(skipped)


def test_independence_trace_xfail_preserved_when_premise_broken() -> None:
    trace = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, other_rv=_OK)
    dirty = _BASE_FLAGS | int(CKF_SO_PIN_COUNT_LOW)
    flags = (("initial", dirty),) + tuple(
        (tag, value) for tag, value in trace.flags if tag != "initial"
    )
    trace = trace._replace(flags=flags)
    assert_xfails(pin_case._judge_independence, trace, burned_role="user")
    _assert_xfail_record("nonspec_reject")


def test_independence_undefined_other_rv_fails_despite_dirty_initial() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, other_rv=_UNDEFINED_RV)
    dirty = _BASE_FLAGS | int(CKF_SO_PIN_COUNT_LOW)
    flags = (("initial", dirty),) + tuple(
        (tag, value) for tag, value in trace.flags if tag != "initial"
    )
    trace = trace._replace(flags=flags)
    try:
        pin_case._judge_independence(trace, burned_role="user")
    except Failed:
        pass
    except Skipped as exc:
        pytest.fail(f"premise skip must not mask premise-free undefined-RV FAIL: {exc}")
    else:
        pytest.fail("expected pytest.fail() for undefined other-role RV")
    _assert_fail_record("self_contradiction", "metadata")


def test_success_reset_observed_passes() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 4,
        wrong_ranks=[1, 1, 1, 2],
        post_rvs=[_PIN_INCORRECT],
        post_ranks=[1],
    )
    pin_case._judge_success_reset(trace, role="user")
    assert classification.get_records() == []


def test_success_reset_absent_xfails() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 4,
        wrong_ranks=[1, 1, 2, 2],
        post_rvs=[_PIN_LOCKED],
        post_ranks=[3],
    )
    assert_xfails(pin_case._judge_success_reset, trace, role="user")
    _assert_xfail_record("honest_deviation")


def test_success_reset_equal_rank_skips_as_unproven() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 4,
        wrong_ranks=[1, 1, 2, 2],
        post_rvs=[_PIN_INCORRECT],
        post_ranks=[2],
    )
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


def test_success_reset_shallow_countdown_skips() -> None:
    trace = _lockout_trace("user", [_PIN_INCORRECT], post_rvs=[_PIN_INCORRECT], post_ranks=[1])
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


def test_success_reset_missing_legs_skip() -> None:
    trace = _lockout_trace("user", [], correct_rv=_OK)
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


def test_success_reset_no_countdown_before_success_skips() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 2,
        wrong_ranks=[0, 0],
        post_rvs=[_PIN_INCORRECT],
        post_ranks=[1],
    )
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


def test_success_reset_without_success_skips() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT, _PIN_LOCKED],
        wrong_ranks=[2, 3],
        correct_rv=_PIN_LOCKED,
        post_rvs=[_PIN_LOCKED],
        post_ranks=[3],
    )
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


def test_success_reset_unreadable_post_skips() -> None:
    trace = _lockout_trace(
        "user",
        [_PIN_INCORRECT] * 4,
        wrong_ranks=[1, 1, 2, 2],
        post_rvs=[_PIN_INCORRECT],
        post_ranks=[1],
    )
    flags = tuple((tag, None) if tag == "post-1" else (tag, value) for tag, value in trace.flags)
    trace = trace._replace(flags=flags)
    skipped = assert_skips(pin_case._judge_success_reset, trace, role="user")
    assert "untestable" in str(skipped)


# --- Part 7: Task 22 fix round 2 (Codex round 19: R19-01..R19-04) ------------


def _r19_assert_fail_preempts_skip(fn: Any, *args: Any, **kwargs: Any) -> Failed:
    """Run a two-phase node; a phase-two skip masking a phase-one FAIL is RED."""
    try:
        fn(*args, **kwargs)
    except XFailed as exc:
        pytest.fail(f"expected pytest.fail(), got pytest.xfail() instead: {exc}")
    except Skipped as exc:
        pytest.fail(f"phase-two setup skip masked an established phase-one FAIL: {exc}")
    except Failed as exc:
        return exc
    pytest.fail("expected pytest.fail(), but the node returned normally")


def _r19_assert_gate_fails(out: str, *, label: str) -> Failed:
    """Run the child gate; an unexercised skip over an undefined RV is RED."""
    try:
        token_admin.check_child_output(0, out, "", label=label)
    except XFailed as exc:
        pytest.fail(f"expected pytest.fail(), got pytest.xfail() instead: {exc}")
    except Skipped as exc:
        pytest.fail(f"undefined provisioning RV skipped as unexercised: {exc}")
    except Failed as exc:
        return exc
    pytest.fail("expected pytest.fail(), but the gate returned a trace")


def _r19_ph2_setup_refused(role: str) -> token_admin.AdminTrace:
    return token_admin.AdminTrace(
        steps=(token_admin.AdminStep("setup:open", _GENERAL_ERROR),),
        flags=(("initial", _flags_for(role, 1)),),
        pin_bounds=(4, 32),
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def _r19_ph2_snapshot(role: str, snapshot_rv: int, correct_rv: int) -> token_admin.AdminTrace:
    return token_admin.AdminTrace(
        steps=(
            token_admin.AdminStep("snapshot:initial", snapshot_rv),
            token_admin.AdminStep("setup:open", _OK),
            token_admin.AdminStep(f"login:{role}:correct", correct_rv),
            token_admin.AdminStep("snapshot:final", snapshot_rv),
        ),
        flags=(("initial", None), ("final", None)),
        pin_bounds=None,
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )


def test_r19_01_so_burn_provisions_user_for_other_role_check(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11a_burn", fake, _burn_extra("so", 2, then_other_role_correct=True), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is None
    assert ("setup:init_pin", _OK) in [(s.name, s.rv) for s in trace.steps]
    assert ("login:user:correct", _OK) in [(s.name, s.rv) for s in trace.steps]


def test_r19_01_so_independence_genuine_measurement(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    out = _run_probe("qc11a_burn", fake, _burn_extra("so", 2, then_other_role_correct=True), capsys)
    trace = token_admin.parse_admin_trace(out)
    try:
        pin_case._judge_independence(trace, burned_role="so")
    except XFailed as exc:
        pytest.fail(f"genuine SO independence measurement xfailed: {exc}")
    assert classification.get_records() == []


def test_r19_01_so_burn_init_pin_refusal_is_explicit_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_pin_always = _GENERAL_ERROR
    out = _run_probe("qc11a_burn", fake, _burn_extra("so", 2, then_other_role_correct=True), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.assumption_failed is not None
    assert "setup_init_pin" in trace.assumption_failed
    skipped = assert_skips(
        token_admin.check_child_output, 0, out, "", label="QC11a so independence"
    )
    assert "setup_init_pin" in str(skipped)


@pytest.mark.parametrize("role", _LOGIN_ROLES)
def test_r19_02_persistence_phase1_acceptance_preempts_phase2_skip(role: str) -> None:
    first = _lockout_trace(role, [_GENERAL_ERROR, _OK], correct_rv=None, final_rank=1)
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(first)),
            _ScriptedChild(_render_trace(_r19_ph2_setup_refused(role))),
        ]
    )
    _r19_assert_fail_preempts_skip(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role=role,
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_fail_record("accepted_invalid", None)
    assert "authentication bypass" in rec.summary


@pytest.mark.parametrize("role", _LOGIN_ROLES)
def test_r19_02_persistence_phase1_undefined_preempts_phase2_skip(role: str) -> None:
    first = _lockout_trace(role, [_GENERAL_ERROR, _UNDEFINED_RV], correct_rv=None, final_rank=1)
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(first)),
            _ScriptedChild(_render_trace(_r19_ph2_setup_refused(role))),
        ]
    )
    _r19_assert_fail_preempts_skip(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role=role,
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_r19_02_journey_phase1_fail_preempts_phase2_skip() -> None:
    phase1 = _reached_trace(old_rejected=_OK)
    phase2 = _verify_trace([("setup:open", _GENERAL_ERROR)])
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    _r19_assert_fail_preempts_skip(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_fail_record("accepted_invalid", "lifecycle")
    assert "old PIN" in rec.summary


def test_r19_02_reset_phase1_fail_preempts_phase2_skip() -> None:
    phase1 = _reached_trace(old_rejected=_OK)
    phase2 = _reset_trace([("reset_init_token", _OK), ("setup:open", _GENERAL_ERROR)])
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    _r19_assert_fail_preempts_skip(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_fail_record("accepted_invalid", "lifecycle")
    assert "old PIN" in rec.summary


def test_r19_02_persistence_phase1_xfail_still_skips_on_phase2_setup_refusal() -> None:
    first = _lockout_trace("user", [_GENERAL_ERROR], correct_rv=None, final_rank=1)
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(first)),
            _ScriptedChild(_render_trace(_r19_ph2_setup_refused("user"))),
        ]
    )
    assert_skips(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role="user",
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert classification.get_records() == []


def test_r19_02_journey_reached_clean_still_skips_on_phase2_setup_refusal() -> None:
    phase2 = _verify_trace([("setup:open", _GENERAL_ERROR)])
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(_render_trace(phase2)),
        ]
    )
    assert_skips(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert classification.get_records() == []


def test_r19_02_reset_reached_clean_still_skips_on_phase2_setup_refusal() -> None:
    phase2 = _reset_trace([("reset_init_token", _OK), ("setup:open", _GENERAL_ERROR)])
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(_render_trace(phase2)),
        ]
    )
    assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert classification.get_records() == []


def test_r19_03_burn_init_token_undefined_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _UNDEFINED_RV
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    _r19_assert_gate_fails(out, label="QC11a user countdown")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in rec.summary.lower()


@pytest.mark.parametrize("op", ("init_pin", "set_pin"))
def test_r19_03_pin_lengths_init_token_undefined_fails(op: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _UNDEFINED_RV
    out = _run_probe("qc11b_pin_lengths", fake, {"op": op}, capsys)
    _r19_assert_gate_fails(out, label=f"QC11b {op}")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in rec.summary.lower()


def test_r19_03_setup_init_pin_undefined_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_pin_always = _UNDEFINED_RV
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    _r19_assert_gate_fails(out, label="QC11a user countdown")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_r19_03_setup_open_undefined_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_UNDEFINED_RV]
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    _r19_assert_gate_fails(out, label="QC11a user countdown")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_r19_03_tokeninfo_undefined_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    _r19_assert_gate_fails(out, label="QC11a user countdown")
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


def test_r19_03_vendor_init_token_refusal_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.init_token_always = _VENDOR_RV
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    skipped = assert_skips(token_admin.check_child_output, 0, out, "", label="QC11a user countdown")
    assert "self_provision" in str(skipped)
    assert classification.get_records() == []


def test_r19_04_read_preserves_undefined_snapshot_rv(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11a_read", fake, {"role": "user"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert ("snapshot:initial", _UNDEFINED_RV) in [(s.name, s.rv) for s in trace.steps]
    assert ("snapshot:final", _UNDEFINED_RV) in [(s.name, s.rv) for s in trace.steps]


def test_r19_04_persistence_undefined_snapshot_fails() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _r19_ph2_snapshot("user", _UNDEFINED_RV, _OK)
    try:
        pin_case._judge_restart_persistence(first, second, role="user")
    except Failed:
        rec = _assert_fail_record("self_contradiction", "metadata")
        assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    else:
        pytest.fail("undefined phase-two snapshot RV passed with zero records")


def test_r19_04_persistence_node_undefined_snapshot_fails() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _r19_ph2_snapshot("user", _UNDEFINED_RV, _OK)
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(first)), _ScriptedChild(_render_trace(second))]
    )
    try:
        pin_case._run_qc11a_persistence_node(
            _capability(),
            _StrictConfig(),
            role="user",
            _session_factory=_session_factory(),
            _launch=launch,
        )
    except Failed:
        rec = _assert_fail_record("self_contradiction", "metadata")
        assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    else:
        pytest.fail("undefined phase-two snapshot RV passed with zero records")


def test_r19_04_defined_snapshot_failure_still_passes() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = _r19_ph2_snapshot("user", _GENERAL_ERROR, _OK)
    pin_case._judge_restart_persistence(first, second, role="user")
    assert classification.get_records() == []


def test_r19_04_snapshot_undefined_preempts_phase2_setup_skip() -> None:
    first = _lockout_trace("user", [_PIN_INCORRECT] * 2, correct_rv=None, final_rank=1)
    second = token_admin.AdminTrace(
        steps=(
            token_admin.AdminStep("snapshot:initial", _UNDEFINED_RV),
            token_admin.AdminStep("setup:open", _GENERAL_ERROR),
        ),
        flags=(("initial", None),),
        pin_bounds=None,
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(first)), _ScriptedChild(_render_trace(second))]
    )
    _r19_assert_fail_preempts_skip(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role="user",
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)


# --- Part 8: Task 22 fix round 3 (F1-F3 undefined-RV preservation) ----------


def _with_snapshot(trace: token_admin.AdminTrace, name: str, rv: int) -> token_admin.AdminTrace:
    """Return a copy of a scripted trace with one extra raw-RV snapshot step."""
    return trace._replace(steps=(*trace.steps, token_admin.AdminStep(name, rv)))


def _assert_snapshot_fail_record() -> Any:
    """The single fail record cites the undefined snapshot RV via C_GetTokenInfo."""
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GetTokenInfo"
    assert rec.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in rec.summary.lower()
    return rec


def test_f1_journey_child_preserves_undefined_snapshot_rvs(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    by_name = [(s.name, s.rv) for s in trace.steps]
    for tag in (
        "after_init_token",
        "after_so_login",
        "after_init_pin",
        "after_user_login",
        "after_set_pin",
        "end",
    ):
        assert (f"snapshot:{tag}", _UNDEFINED_RV) in by_name
    assert ("snapshot:pinbounds", _UNDEFINED_RV) in by_name
    assert trace.pin_bounds is None
    assert [value for _, value in trace.flags] == [None] * len(trace.flags)


def test_f1_journey_undefined_snapshot_fails() -> None:
    trace = _with_snapshot(_journey_trace(), "snapshot:after_so_login", _UNDEFINED_RV)
    records, reached = sopin_case._assess_provision_journey(trace)
    assert reached is True
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "metadata")]
    assert records[0].operation == "C_GetTokenInfo"
    assert records[0].actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in records[0].summary.lower()


def test_f1_journey_node_undefined_snapshot_fails() -> None:
    phase1 = _with_snapshot(_journey_trace(), "snapshot:after_so_login", _UNDEFINED_RV)
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(_verify_trace()))]
    )
    _r19_assert_fail_preempts_skip(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    _assert_snapshot_fail_record()


def test_f1_verify_child_preserves_undefined_snapshot_rv(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    _run_probe("qc11c_journey", fake, {}, capsys)
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11c_verify", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert ("snapshot:verify", _UNDEFINED_RV) in [(s.name, s.rv) for s in trace.steps]


def test_f1_verify_undefined_snapshot_fails() -> None:
    trace = _with_snapshot(_verify_trace(), "snapshot:verify", _UNDEFINED_RV)
    records = sopin_case._assess_provision_persistence(trace, canary_established=True)
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "metadata")]
    assert records[0].operation == "C_GetTokenInfo"
    assert records[0].actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in records[0].summary.lower()


def test_f1_reset_child_preserves_undefined_snapshot_rvs(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    _run_probe("qc11c_journey", fake, {}, capsys)
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    by_name = [(s.name, s.rv) for s in trace.steps]
    assert ("snapshot:after_reset_init_token", _UNDEFINED_RV) in by_name
    assert ("snapshot:end", _UNDEFINED_RV) in by_name


def test_f1_reset_undefined_snapshot_fails() -> None:
    trace = _with_snapshot(_reset_trace(), "snapshot:end", _UNDEFINED_RV)
    records = ckr_case._assess_sacrificial_reset(trace)
    assert [(rec.reason, rec.kind) for rec in records] == [("self_contradiction", "metadata")]
    assert records[0].operation == "C_GetTokenInfo"
    assert records[0].actual_ckr == ckr_name(_UNDEFINED_RV)
    assert "undefined" in records[0].summary.lower()


def test_f1_journey_snapshot_fail_preempts_phase2_skip() -> None:
    phase1 = _with_snapshot(_journey_trace(), "snapshot:after_so_login", _UNDEFINED_RV)
    phase2 = _verify_trace([("setup:open", _GENERAL_ERROR)])
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(phase2))]
    )
    _r19_assert_fail_preempts_skip(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    _assert_snapshot_fail_record()


def test_f1_defined_snapshot_failures_tolerated() -> None:
    journey = _with_snapshot(_journey_trace(), "snapshot:after_so_login", _GENERAL_ERROR)
    records, reached = sopin_case._assess_provision_journey(journey)
    assert reached is True
    assert records == []
    verify = _with_snapshot(_verify_trace(), "snapshot:verify", _GENERAL_ERROR)
    assert sopin_case._assess_provision_persistence(verify, canary_established=True) == []
    reset = _with_snapshot(_reset_trace(), "snapshot:end", _GENERAL_ERROR)
    assert ckr_case._assess_sacrificial_reset(reset) == []
    assert classification.get_records() == []


def test_f2_trace_skip_reason_reports_setup_failure_regardless_of_definedness() -> None:
    failed = token_admin.AdminTrace(
        steps=(token_admin.AdminStep("setup:open", _UNDEFINED_RV),),
        flags=(),
        pin_bounds=None,
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )
    reason = token_admin.trace_skip_reason(failed)
    assert reason is not None
    assert "setup:open" in reason
    clean = token_admin.AdminTrace(
        steps=(),
        flags=(),
        pin_bounds=None,
        inv_objects=(),
        ok=True,
        no_slots=False,
        assumption_failed=None,
    )
    assert token_admin.trace_skip_reason(clean) is None


def test_f3_burn_child_preserves_midrun_undefined_tokeninfo(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    # Call 1 (initial read) succeeds with a zeroed struct so the pristine gate
    # holds; call 2 (attempt-1 read) goes undefined mid-run; later reads are
    # normal again. PINBOUNDS:0:0 here is a script artifact, not wire behavior.
    fake.gettokeninfo_script = [_OK, _UNDEFINED_RV]
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert ("snapshot:attempt-1", _UNDEFINED_RV) in [(s.name, s.rv) for s in trace.steps]
    assert dict(trace.flags).get("attempt-1") is None


def test_f3_burn_midrun_undefined_tokeninfo_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_OK, _UNDEFINED_RV]
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2), capsys)
    trace = token_admin.check_child_output(0, out, "", label="QC11a user countdown")
    _assert_fails(pin_case._judge_lockout_trace, trace, role="user")
    _assert_snapshot_fail_record()


def test_f3_burn_undefined_snapshot_preempts_phase2_setup_skip(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_OK, _UNDEFINED_RV]
    out = _run_probe("qc11a_burn", fake, _burn_extra("user", 2, then_correct=False), capsys)
    launch = _FakeLaunch(
        [_ScriptedChild(out), _ScriptedChild(_render_trace(_r19_ph2_setup_refused("user")))]
    )
    _r19_assert_fail_preempts_skip(
        pin_case._run_qc11a_persistence_node,
        _capability(),
        _StrictConfig(),
        role="user",
        _session_factory=_session_factory(),
        _launch=launch,
    )
    _assert_snapshot_fail_record()


def test_f3_burn_defined_snapshot_failure_tolerated() -> None:
    trace = _with_snapshot(
        _lockout_trace("user", [_PIN_INCORRECT] * 3, final_rank=0),
        "snapshot:attempt-1",
        _GENERAL_ERROR,
    )
    pin_case._judge_lockout_trace(trace, role="user")
    assert classification.get_records() == []


def test_f3_pin_lengths_child_preserves_undefined_bounds_rv(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "init_pin"}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert trace.ok is True
    assert ("snapshot:pinbounds", _UNDEFINED_RV) in [(s.name, s.rv) for s in trace.steps]
    assert trace.pin_bounds is None


@pytest.mark.parametrize("op", ("init_pin", "set_pin"))
def test_f3_pin_lengths_undefined_bounds_fails(op: str, capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _UNDEFINED_RV
    out = _run_probe("qc11b_pin_lengths", fake, {"op": op}, capsys)
    trace = token_admin.check_child_output(0, out, "", label=f"QC11b {op} lengths")
    _r19_assert_fail_preempts_skip(tse._judge_pin_lengths, trace, op=op)
    _assert_snapshot_fail_record()


def test_f3_pin_lengths_defined_bounds_failure_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_rv = _GENERAL_ERROR
    out = _run_probe("qc11b_pin_lengths", fake, {"op": "set_pin"}, capsys)
    trace = token_admin.check_child_output(0, out, "", label="QC11b set_pin lengths")
    skipped = assert_skips(tse._judge_pin_lengths, trace, op="set_pin")
    assert "PIN bounds unreadable" in str(skipped)
    assert classification.get_records() == []


# --- R20-01: same-trace setup skip must not mask undefined snapshots ---------

_R20_UNDEFINED_RV = 0x7FFFFFFE


def _r20_assert_fail_preempts_skip(fn: Any, *args: Any, **kwargs: Any) -> Failed:
    """Run a QC11c node; a same-trace setup skip masking an undefined snapshot is RED."""
    try:
        fn(*args, **kwargs)
    except XFailed as exc:
        pytest.fail(f"expected pytest.fail(), got pytest.xfail() instead: {exc}")
    except Skipped as exc:
        pytest.fail(f"same-trace setup skip masked an undefined snapshot FAIL: {exc}")
    except Failed as exc:
        return exc
    pytest.fail("expected pytest.fail(), but the node returned normally")


def _assert_r20_snapshot_fail_record() -> Any:
    """The single fail record cites the 0x7FFFFFFE snapshot RV via C_GetTokenInfo."""
    rec = _assert_fail_record("self_contradiction", "metadata")
    assert rec.operation == "C_GetTokenInfo"
    assert rec.actual_ckr == ckr_name(_R20_UNDEFINED_RV)
    assert "undefined" in rec.summary.lower()
    return rec


def test_r20_01a_journey_own_setup_failure_undefined_snapshot_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_R20_UNDEFINED_RV]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("init_token", _OK),
        ("snapshot:after_init_token", _R20_UNDEFINED_RV),
        ("setup:open", _GENERAL_ERROR),
    ]
    launch = _FakeLaunch([_ScriptedChild(out)])
    _r20_assert_fail_preempts_skip(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_r20_snapshot_fail_record()
    assert "after_init_token" in rec.label


def test_r20_01b_reset_own_setup_failure_undefined_snapshot_fails(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_R20_UNDEFINED_RV]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("reset_init_token", _OK),
        ("snapshot:after_reset_init_token", _R20_UNDEFINED_RV),
        ("setup:open", _GENERAL_ERROR),
    ]
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(out),
        ]
    )
    _r20_assert_fail_preempts_skip(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_r20_snapshot_fail_record()
    assert "after_reset_init_token" in rec.label


def test_r20_01a_journey_defined_snapshot_setup_failure_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_GENERAL_ERROR]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    launch = _FakeLaunch([_ScriptedChild(out)])
    skipped = assert_skips(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c journey: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r20_01b_reset_defined_snapshot_setup_failure_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_GENERAL_ERROR]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(out),
        ]
    )
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c reset: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r20_01a_journey_setup_failure_without_snapshots_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [step for step in trace.steps if step.name.startswith("snapshot")] == []
    launch = _FakeLaunch([_ScriptedChild(out)])
    skipped = assert_skips(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c journey: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r20_01b_reset_setup_failure_without_snapshots_still_skips(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_reset", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [step for step in trace.steps if step.name.startswith("snapshot")] == []
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(out),
        ]
    )
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c reset: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r20_01a_no_double_judge_clean_gating_journey_uses_record_path() -> None:
    phase1 = _with_snapshot(
        _reached_trace(old_rejected=_OK), "snapshot:after_so_login", _R20_UNDEFINED_RV
    )
    launch = _FakeLaunch(
        [_ScriptedChild(_render_trace(phase1)), _ScriptedChild(_render_trace(_verify_trace()))]
    )
    _assert_fails(
        sopin_case._run_qc11c_journey_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    # Phase two launched: the would-skip-conditional prescan did not raise early.
    assert len(launch.calls) == 2
    records = classification.get_records()
    assert [rec.outcome for rec in records] == ["fail", "fail"]
    assert {rec.reason for rec in records} == {"self_contradiction", "accepted_invalid"}


def test_r20_01b_no_double_judge_clean_gating_reset_uses_record_path() -> None:
    phase2 = _with_snapshot(
        _reset_trace(
            [
                ("reset_init_token", _OK),
                ("setup:open", _OK),
                ("so_login", _OK),
                ("old_user_after_reset", _OK),
            ]
        ),
        "snapshot:end",
        _R20_UNDEFINED_RV,
    )
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(_render_trace(phase2)),
        ]
    )
    _assert_fails(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    # Both assessor records collected: the would-skip-conditional prescan did
    # not raise early (an early raise would leave exactly one record).
    records = classification.get_records()
    assert [rec.outcome for rec in records] == ["fail", "fail"]
    assert {rec.reason for rec in records} == {"self_contradiction", "accepted_invalid"}


# --- Part 9: Task 22 fix round 5 (R21-01/F-R20-01c reset-provision prescan) ---


def test_r21_01_reset_provision_own_setup_failure_undefined_snapshot_fails(
    capsys: Any,
) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_R20_UNDEFINED_RV]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [(step.name, step.rv) for step in trace.steps] == [
        ("init_token", _OK),
        ("snapshot:after_init_token", _R20_UNDEFINED_RV),
        ("setup:open", _GENERAL_ERROR),
    ]
    launch = _FakeLaunch([_ScriptedChild(out)])
    _r20_assert_fail_preempts_skip(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    rec = _assert_r20_snapshot_fail_record()
    assert "after_init_token" in rec.label


def test_r21_01_reset_provision_defined_snapshot_setup_failure_still_skips(
    capsys: Any,
) -> None:
    fake = _FakeAdminRaw()
    fake.gettokeninfo_script = [_GENERAL_ERROR]
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    launch = _FakeLaunch([_ScriptedChild(out)])
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c reset/provision: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r21_01_reset_provision_setup_failure_without_snapshots_still_skips(
    capsys: Any,
) -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_GENERAL_ERROR]
    out = _run_probe("qc11c_journey", fake, {}, capsys)
    trace = token_admin.parse_admin_trace(out)
    assert [step for step in trace.steps if step.name.startswith("snapshot")] == []
    launch = _FakeLaunch([_ScriptedChild(out)])
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c reset/provision: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert classification.get_records() == []


def test_r21_01_reset_provision_no_slots_still_skips() -> None:
    launch = _FakeLaunch([_ScriptedChild("NO_SLOTS\n")])
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == "QC11c reset/provision: no present slot on the sacrificial token"
    assert classification.get_records() == []


def test_r21_01_reset_provision_healthy_reaches_reset_leg(capsys: Any) -> None:
    fake = _FakeAdminRaw()
    fake.open_script = [_GENERAL_ERROR]
    reset_out = _run_probe("qc11c_reset", fake, {}, capsys)
    reset_trace = token_admin.parse_admin_trace(reset_out)
    assert [step for step in reset_trace.steps if step.name.startswith("snapshot")] == []
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(_journey_trace())),
            _ScriptedChild(reset_out),
        ]
    )
    skipped = assert_skips(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    assert str(skipped) == (
        "QC11c reset: sacrificial setup failed: "
        "setup:open=CKR_GENERAL_ERROR; destructive legs untestable"
    )
    assert len(launch.calls) == 2
    assert classification.get_records() == []


def test_r21_01_no_double_judge_clean_gating_provision_uses_record_path() -> None:
    provision = _with_snapshot(
        _reached_trace(old_rejected=_OK), "snapshot:after_so_login", _R20_UNDEFINED_RV
    )
    launch = _FakeLaunch(
        [
            _ScriptedChild(_render_trace(provision)),
            _ScriptedChild(_render_trace(_reset_trace())),
        ]
    )
    _assert_fails(
        ckr_case._run_qc11c_reset_node,
        _capability(),
        _StrictConfig(),
        _session_factory=_session_factory(),
        _launch=launch,
    )
    # The reset leg launched: the would-skip-conditional prescan did not raise
    # early on a clean-gating provision trace.
    assert len(launch.calls) == 2
    records = classification.get_records()
    assert [rec.outcome for rec in records] == ["fail", "fail"]
    assert {rec.reason for rec in records} == {"self_contradiction", "accepted_invalid"}

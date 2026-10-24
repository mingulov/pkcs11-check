"""Production-method contracts for the search-lifecycle oracles (QC6c).

Drives the real testcase methods in
``pkcs11_check.testcases.test_session_edge_cases`` with a scriptable fake
token at the raw ``C_*`` layer:

- repaired sequential stale-handle oracles (``test_find_after_close``,
  ``test_generate_key_after_close``): closure proven via an explicit
  ``C_CloseSession == CKR_OK``; canonical ``CKR_SESSION_HANDLE_INVALID``
  passes; ``CKR_SESSION_CLOSED`` is an alternate clean refusal recorded as
  xfail with the original RV preserved; acceptance (``CKR_OK``) fails;
- active-search invalidation (``TestActiveSearchInvalidation``): exact
  invalid-session RVs plus output effects (no objects delivered, no state
  carried) across ``C_CloseSession`` and ``C_CloseAllSessions``;
- handle-reuse temporal identity: a fresh search after close + reopen must
  behave as a fresh search, and the oracle must never declare a reused
  integer permanently stale.

Fakes only; no provider is loaded.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_KEY_GEN,
    CKR_FUNCTION_FAILED,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_session_edge_cases as tse
from tests._skip_assert import assert_xfails

_OK = int(CKR_OK)
_HANDLE_INVALID = int(CKR_SESSION_HANDLE_INVALID)
_SESSION_CLOSED = int(CKR_SESSION_CLOSED)
_CLEAN_REJECT = int(CKR_FUNCTION_FAILED)
_OBJECT_INVALID = int(CKR_OBJECT_HANDLE_INVALID)
_UNDEFINED_RV = 0x7FFFFFFF

_S1 = 7
_S2_REUSED = 7
_S2_FRESH = 9
_KEY = 55
_OTHER = 77


def _decode_template(tmpl: Any, count: int) -> dict[int, Any]:
    """Decode a captured template ptr + count into {CKA_*: value}.

    Values: CKA_LABEL -> str, bool attrs -> bool, ulong attrs -> int,
    anything else -> raw bytes. NULL (None, 0) decodes to {}.
    """
    if tmpl is None:
        assert count == 0, (tmpl, count)
        return {}
    decoded: dict[int, Any] = {}
    for i in range(count):
        attr = tmpl[i]
        atype = int(attr.type)
        alen = int(attr.ulValueLen)
        addr = attr.pValue
        raw = ctypes.string_at(addr, alen) if addr and alen > 0 else b""
        if atype == int(CKA_LABEL):
            decoded[atype] = raw.decode("utf-8")
        elif atype in (int(CKA_TOKEN), int(CKA_PRIVATE)):
            assert alen == 1, (atype, alen)
            decoded[atype] = bool(raw[0]) if raw else False
        elif atype == int(CKA_VALUE_LEN):
            decoded[atype] = int.from_bytes(raw, "little") if raw else 0
        else:
            decoded[atype] = raw
    return decoded


def _decode_mech(mech: Any) -> int:
    """Decode a mech_simple byref into its CKM_* int."""
    return int(mech._obj.mechanism)


class _SearchRaw:
    """Scriptable fake token for the search-lifecycle oracle legs."""

    def __init__(
        self,
        *,
        close_rv: int = _OK,
        close_all_rv: int = _OK,
        op_rv: int = _OK,
        init_script: list[int] | None = None,
        find_script: list[tuple[int, tuple[int, ...]] | tuple[int, tuple[int, ...], int]]
        | None = None,
        final_rv: int = _HANDLE_INVALID,
        info_rv: int = _OK,
        opens: list[int] | None = None,
        open_rv: int = _OK,
        open_script: list[int] | None = None,
        gen_handle: int = _KEY,
        destroy_script: list[int] | None = None,
    ) -> None:
        self._close_rv = close_rv
        self._close_all_rv = close_all_rv
        self._op_rv = op_rv
        self._init_script = list(init_script if init_script is not None else [_OK])
        self._find_script = list(find_script if find_script is not None else [(_OK, ())])
        self._final_rv = final_rv
        self._info_rv = info_rv
        self._opens = list(opens if opens is not None else [_S1])
        self._open_script = list(open_script if open_script is not None else [open_rv])
        self._gen_handle = gen_handle
        self._destroy_script = list(destroy_script) if destroy_script is not None else None
        self.ops: list[str] = []
        self.closed: list[int] = []
        self.destroyed: list[tuple[int, int]] = []
        self.init_sessions: list[int] = []
        self.find_sessions: list[int] = []
        self.final_sessions: list[int] = []
        self.info_sessions: list[int] = []
        self.close_all_calls: list[int] = []
        self.init_calls: list[dict[str, Any]] = []
        self.genkey_calls: list[dict[str, Any]] = []

    def C_OpenSession(  # noqa: N802
        self, _slot_id: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any
    ) -> int:
        self.ops.append("open")
        if len(self._open_script) > 1:
            rv = self._open_script.pop(0)
        else:
            rv = self._open_script[0]
        if rv != _OK:
            return rv
        handle = self._opens.pop(0)
        ctypes.cast(sh_ptr, ctypes.POINTER(CK_SESSION_HANDLE)).contents.value = handle
        return _OK

    def C_CloseSession(self, sh: int) -> int:  # noqa: N802
        self.ops.append("close")
        self.closed.append(int(sh))
        return self._close_rv

    def C_CloseAllSessions(self, slot_id: int) -> int:  # noqa: N802
        self.ops.append("close-all")
        self.close_all_calls.append(int(slot_id))
        return self._close_all_rv

    def C_GetSessionInfo(self, sh: int, _info: Any) -> int:  # noqa: N802
        self.ops.append("info")
        self.info_sessions.append(int(sh))
        return self._info_rv

    def C_FindObjectsInit(self, sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.ops.append("init")
        self.init_sessions.append(int(sh))
        self.init_calls.append(
            {
                "sh": int(sh),
                "is_null": tmpl is None,
                "count": int(count),
                "attrs": _decode_template(tmpl, int(count)),
            }
        )
        if self._init_script:
            return self._init_script.pop(0)
        return _OK

    def C_FindObjects(  # noqa: N802
        self, sh: int, handles: Any, max_count: int, found_ptr: Any
    ) -> int:
        self.ops.append("find")
        self.find_sessions.append(int(sh))
        entry = self._find_script.pop(0)
        if len(entry) == 2:
            rv, found = entry  # type: ignore[misc]
            report_count = len(found)
        else:
            rv, found, report_count = entry  # type: ignore[misc]
        for index, handle in enumerate(found[:max_count]):
            handles[index] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = report_count
        return rv

    def C_FindObjectsFinal(self, sh: int) -> int:  # noqa: N802
        self.ops.append("final")
        self.final_sessions.append(int(sh))
        return self._final_rv

    def C_GenerateKey(  # noqa: N802
        self, sh: int, mech: Any, tmpl: Any, count: int, key_ptr: Any
    ) -> int:
        self.ops.append("genkey")
        self.genkey_calls.append(
            {
                "sh": int(sh),
                "mech": _decode_mech(mech),
                "count": int(count),
                "attrs": _decode_template(tmpl, int(count)),
            }
        )
        ctypes.cast(key_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._gen_handle
        return self._op_rv

    def C_DestroyObject(self, sh: int, handle: int) -> int:  # noqa: N802
        self.ops.append("destroy")
        self.destroyed.append((int(sh), int(handle)))
        if self._destroy_script:
            return self._destroy_script.pop(0)
        if self._destroy_script is not None and not self._destroy_script:
            return _OK
        return _OK


def _session(raw: _SearchRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=1,
        slot_id=0,
        has_mechanism=lambda *_a: True,
    )


def _patch_common(monkeypatch: pytest.MonkeyPatch, *, opened: int = _S1) -> None:
    monkeypatch.setattr(tse, "get_pin_bytes", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "raw_open_session", lambda *_a, **_k: opened)
    monkeypatch.setattr(tse, "login_user", lambda *_a, **_k: None)


def _patch_no_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch everything except ``raw_open_session`` (the real open path stays live)."""
    monkeypatch.setattr(tse, "get_pin_bytes", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "login_user", lambda *_a, **_k: None)


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == reason
    assert records[0].kind == kind
    assert records[0].outcome == "fail"
    return records[0]


def _assert_xfail_record(reason: str) -> Any:
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == reason
    assert records[0].outcome == "xfail"
    return records[0]


# --- Part A: repaired sequential stale-handle oracles -----------------------


def _a_find_raw(op_rv: int, *, close_rv: int = _OK) -> _SearchRaw:
    return _SearchRaw(close_rv=close_rv, init_script=[op_rv])


def _a_gen_raw(op_rv: int, *, close_rv: int = _OK) -> _SearchRaw:
    return _SearchRaw(close_rv=close_rv, op_rv=op_rv)


def test_find_close_refusal_xfails_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_find_raw(_HANDLE_INVALID, close_rv=_CLEAN_REJECT)
    _patch_common(monkeypatch)
    assert_xfails(
        tse.TestStaleSessionHandles().test_find_after_close,
        _session(raw),
        SimpleNamespace(),
    )
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_CloseSession"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_find_close_undefined_rv_fails_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_find_raw(_HANDLE_INVALID, close_rv=_UNDEFINED_RV)
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        tse.TestStaleSessionHandles().test_find_after_close(_session(raw), SimpleNamespace())
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_CloseSession"


def test_find_canonical_invalid_handle_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_find_raw(_HANDLE_INVALID)
    _patch_common(monkeypatch)
    tse.TestStaleSessionHandles().test_find_after_close(_session(raw), SimpleNamespace())
    assert get_records() == []
    assert raw.closed == [_S1]
    assert len(raw.init_calls) == 1
    assert raw.init_calls[0]["sh"] == _S1
    assert raw.init_calls[0]["is_null"] is True
    assert raw.init_calls[0]["count"] == 0
    assert raw.init_calls[0]["attrs"] == {}


def test_find_session_closed_xfails_with_original_rv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _a_find_raw(_SESSION_CLOSED)
    _patch_common(monkeypatch)
    assert_xfails(
        tse.TestStaleSessionHandles().test_find_after_close,
        _session(raw),
        SimpleNamespace(),
    )
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.expected_ckr == ["CKR_SESSION_HANDLE_INVALID"]
    assert raw.init_calls[0]["is_null"] is True


def test_find_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_find_raw(_OK)
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        tse.TestStaleSessionHandles().test_find_after_close(_session(raw), SimpleNamespace())
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("accepted_invalid", None)
    assert raw.init_calls[0]["is_null"] is True


def test_genkey_close_refusal_xfails_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_gen_raw(_HANDLE_INVALID, close_rv=_CLEAN_REJECT)
    _patch_common(monkeypatch)
    assert_xfails(
        tse.TestStaleSessionHandles().test_generate_key_after_close,
        _session(raw),
        SimpleNamespace(),
    )
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_CloseSession"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_genkey_close_undefined_rv_fails_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_gen_raw(_HANDLE_INVALID, close_rv=_UNDEFINED_RV)
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        tse.TestStaleSessionHandles().test_generate_key_after_close(
            _session(raw), SimpleNamespace()
        )
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_CloseSession"


def test_genkey_canonical_invalid_handle_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_gen_raw(_HANDLE_INVALID)
    _patch_common(monkeypatch)
    tse.TestStaleSessionHandles().test_generate_key_after_close(_session(raw), SimpleNamespace())
    assert get_records() == []
    assert raw.closed == [_S1]
    assert len(raw.genkey_calls) == 1
    call = raw.genkey_calls[0]
    assert call["sh"] == _S1
    assert call["mech"] == int(CKM_AES_KEY_GEN)
    assert call["count"] == 1
    assert call["attrs"].get(int(CKA_VALUE_LEN)) == 16


def test_genkey_session_closed_xfails_with_original_rv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _a_gen_raw(_SESSION_CLOSED)
    _patch_common(monkeypatch)
    assert_xfails(
        tse.TestStaleSessionHandles().test_generate_key_after_close,
        _session(raw),
        SimpleNamespace(),
    )
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.expected_ckr == ["CKR_SESSION_HANDLE_INVALID"]


def test_genkey_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _a_gen_raw(_OK)
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        tse.TestStaleSessionHandles().test_generate_key_after_close(
            _session(raw), SimpleNamespace()
        )
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("accepted_invalid", None)
    assert raw.genkey_calls[0]["sh"] == _S1


# --- Part B.1: active search invalidated by C_CloseSession ------------------


def _run_close_search(raw: _SearchRaw) -> None:
    tse.TestActiveSearchInvalidation().test_find_and_final_after_close(
        _session(raw), SimpleNamespace()
    )


def test_active_search_canonical_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, ())])
    _patch_common(monkeypatch)
    _run_close_search(raw)
    assert get_records() == []
    assert raw.ops == ["init", "close", "find", "final"]
    assert raw.init_sessions == raw.find_sessions == raw.final_sessions == [_S1]
    assert len(raw.init_calls) == 1
    assert raw.init_calls[0]["is_null"] is False
    assert raw.init_calls[0]["count"] == 1
    assert raw.init_calls[0]["attrs"].get(int(CKA_LABEL)) == tse._STALE_SEARCH_LABEL


def test_active_search_find_alternate_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_SESSION_CLOSED, ())])
    _patch_common(monkeypatch)
    assert_xfails(_run_close_search, raw)
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_FindObjects"
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.expected_ckr == ["CKR_SESSION_HANDLE_INVALID"]
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_CLOSED"
    assert record.detail["final_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["delivered"] == 0
    assert record.detail["buffer"] == []


def test_active_search_count_only_alternate_keeps_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(find_script=[(_SESSION_CLOSED, (), 1)])
    _patch_common(monkeypatch)
    assert_xfails(_run_close_search, raw)
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_FindObjects"
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_CLOSED"
    assert record.detail["final_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["delivered"] == 1
    assert record.detail["buffer"] == [tse._STALE_SEARCH_SENTINEL]


def test_stale_search_alternate_without_buffer_omits_buffer_key() -> None:
    """The delivery guard stays exact: no buffer passed means no buffer key."""
    assert_xfails(
        tse._raise_stale_search,
        label="probe",
        tag=tse._SEARCH_ALTERNATE,
        rv=_SESSION_CLOSED,
        operation="C_FindObjects",
        delivered=2,
        rv_find=_SESSION_CLOSED,
        rv_final=_HANDLE_INVALID,
    )
    record = _assert_xfail_record("nonspec_reject")
    assert record.detail is not None
    assert record.detail["delivered"] == 2
    assert "buffer" not in record.detail


def test_active_search_final_alternate_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        find_script=[(_HANDLE_INVALID, ())],
        final_rv=_SESSION_CLOSED,
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_search, raw)
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_FindObjectsFinal"
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["final_rv"] == "CKR_SESSION_CLOSED"
    assert record.detail["delivered"] == 0
    assert record.detail["buffer"] == []


def test_active_search_find_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_OK, (41, 42))])
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("accepted_invalid", "lifecycle")
    assert record.operation == "C_FindObjects"
    assert record.detail is not None
    assert record.detail["delivered"] == 2


def test_active_search_find_acceptance_without_delivery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(find_script=[(_OK, ())])
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("accepted_invalid", "lifecycle")
    assert record.operation == "C_FindObjects"


def test_active_search_error_with_delivery_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, (41,))])
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.operation == "C_FindObjects"
    assert record.actual_ckr == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail is not None
    assert record.detail["delivered"] == 1
    assert record.detail["buffer"] == [41]


def test_active_search_count_only_refusal_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, (), 1)])
    _patch_common(monkeypatch)
    _run_close_search(raw)
    assert get_records() == []


def test_active_search_final_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, ())], final_rv=_OK)
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("accepted_invalid", "lifecycle")
    assert record.operation == "C_FindObjectsFinal"
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["final_rv"] == "CKR_OK"
    assert record.detail["delivered"] == 0
    assert record.detail["buffer"] == []


def test_active_search_undefined_find_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_UNDEFINED_RV, ())])
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.detail is not None
    assert "buffer" in record.detail


def test_active_search_final_undefined_keeps_find_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        find_script=[(_HANDLE_INVALID, ())],
        final_rv=_UNDEFINED_RV,
    )
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsFinal"
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["final_rv"] == ckr_name(_UNDEFINED_RV)
    assert record.detail["delivered"] == 0
    assert record.detail["buffer"] == []


def test_active_search_close_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        close_rv=_CLEAN_REJECT,
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_CloseSession"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_active_search_close_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        close_rv=_UNDEFINED_RV,
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_CloseSession"


def test_active_search_init_refusal_xfails_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        init_script=[_CLEAN_REJECT],
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsInit"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert _S1 in raw.closed


def test_active_search_init_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        init_script=[_UNDEFINED_RV],
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsInit"
    assert _S1 in raw.closed


# --- Part B.2: active search invalidated by C_CloseAllSessions --------------


def _run_close_all_search(raw: _SearchRaw) -> None:
    tse.TestActiveSearchInvalidation().test_find_and_final_after_close_all(
        _session(raw), SimpleNamespace()
    )


def test_close_all_search_canonical_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, ())])
    _patch_common(monkeypatch)
    _run_close_all_search(raw)
    assert get_records() == []
    assert raw.close_all_calls == [0]
    assert raw.ops == ["init", "close-all", "find", "final", "close"]
    assert _S1 in raw.closed


def test_close_all_search_alternate_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        find_script=[(_HANDLE_INVALID, ())],
        final_rv=_SESSION_CLOSED,
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_all_search, raw)
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_FindObjectsFinal"
    assert record.actual_ckr == "CKR_SESSION_CLOSED"
    assert record.detail is not None
    assert record.detail["find_rv"] == "CKR_SESSION_HANDLE_INVALID"
    assert record.detail["final_rv"] == "CKR_SESSION_CLOSED"
    assert record.detail["delivered"] == 0
    assert record.detail["buffer"] == []
    assert _S1 in raw.closed


def test_close_all_search_find_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(find_script=[(_OK, (_KEY,))])
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_all_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("accepted_invalid", "lifecycle")
    assert record.operation == "C_FindObjects"
    assert _S1 in raw.closed


def test_close_all_search_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        close_all_rv=_CLEAN_REJECT,
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_all_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_CloseAllSessions"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert _S1 in raw.closed


def test_close_all_search_undefined_refusal_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        close_all_rv=_UNDEFINED_RV,
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_all_search(raw)
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "metadata")


def test_close_all_search_count_only_refusal_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(find_script=[(_HANDLE_INVALID, (), 1)])
    _patch_common(monkeypatch)
    _run_close_all_search(raw)
    assert get_records() == []
    assert _S1 in raw.closed


def test_close_all_search_init_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        init_script=[_CLEAN_REJECT],
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    assert_xfails(_run_close_all_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsInit"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert _S1 in raw.closed


def test_close_all_search_init_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _SearchRaw(
        init_script=[_UNDEFINED_RV],
        find_script=[(_HANDLE_INVALID, ())],
    )
    _patch_common(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_close_all_search(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsInit"
    assert _S1 in raw.closed


# --- Part B.3: handle-reuse temporal identity -------------------------------


def _run_reuse(raw: _SearchRaw) -> None:
    tse.TestActiveSearchInvalidation().test_search_state_not_resurrected_on_handle_reuse(
        _session(raw), SimpleNamespace()
    )


def _reuse_raw(
    fresh_hits: tuple[int, ...],
    *,
    s2: int = _S2_REUSED,
    info_rv: int = _OK,
    pre_hits: tuple[int, ...] = (_KEY,),
    pre_rv: int = _OK,
    fresh_rv: int = _OK,
    close_rv: int = _OK,
    init_script: list[int] | None = None,
    destroy_script: list[int] | None = None,
    op_rv: int = _OK,
    find_script: list[tuple[int, tuple[int, ...]] | tuple[int, tuple[int, ...], int]] | None = None,
) -> _SearchRaw:
    return _SearchRaw(
        opens=[_S1, s2],
        op_rv=op_rv,
        init_script=list(init_script) if init_script is not None else [_OK, _OK],
        find_script=list(find_script)
        if find_script is not None
        else [(pre_rv, pre_hits), (fresh_rv, fresh_hits)],
        final_rv=_OK,
        info_rv=info_rv,
        close_rv=close_rv,
        destroy_script=list(destroy_script) if destroy_script is not None else None,
    )


def _assert_reuse_stimulus(raw: _SearchRaw, *, s2: int) -> str:
    assert len(raw.genkey_calls) == 1
    gen = raw.genkey_calls[0]
    assert gen["sh"] == _S1
    assert gen["mech"] == int(CKM_AES_KEY_GEN)
    assert gen["attrs"].get(int(CKA_TOKEN)) is False
    assert gen["attrs"].get(int(CKA_PRIVATE)) is False
    assert gen["attrs"].get(int(CKA_VALUE_LEN)) == 16
    label = gen["attrs"].get(int(CKA_LABEL))
    assert isinstance(label, str) and label
    base = tse._SEARCH_REUSE_OBJECT_LABEL
    assert label != base
    assert label.startswith(base + "-")
    assert len(raw.init_calls) == 2
    for call, sh in zip(raw.init_calls, [_S1, s2], strict=True):
        assert call["sh"] == sh
        assert call["is_null"] is False
        assert call["count"] == 1
        assert call["attrs"].get(int(CKA_LABEL)) == label
    return label


def test_reuse_fresh_search_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw(())
    _patch_no_open(monkeypatch)
    _run_reuse(raw)
    assert get_records() == []
    # The reopened (numerically reused) handle is proven operational and
    # searched as a live session: never declared permanently stale.
    assert raw.info_sessions == [_S2_REUSED]
    assert raw.init_sessions == [_S1, _S2_REUSED]
    assert raw.find_sessions == [_S1, _S2_REUSED]
    assert raw.final_sessions == [_S2_REUSED]
    assert raw.closed == [_S1, _S2_REUSED]
    assert raw.destroyed == []
    _assert_reuse_stimulus(raw, s2=_S2_REUSED)


def test_distinct_handle_fresh_search_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), s2=_S2_FRESH)
    _patch_no_open(monkeypatch)
    _run_reuse(raw)
    assert get_records() == []
    assert raw.info_sessions == [_S2_FRESH]
    assert raw.closed == [_S1, _S2_FRESH]
    assert raw.destroyed == []
    _assert_reuse_stimulus(raw, s2=_S2_FRESH)


def test_reuse_resurrected_results_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((_KEY,), destroy_script=[_OBJECT_INVALID])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.operation == "C_FindObjects"
    assert "resurrect" in record.summary
    assert record.expected_ckr == ["fresh search finds no trace of the closed session"]
    assert record.actual_ckr == f"resurrected {[_KEY]}"
    assert record.detail is not None
    assert record.detail["handle_reused"] is True
    assert record.detail["found"] == [_KEY]
    assert raw.closed == [_S1, _S2_REUSED]
    assert raw.destroyed == [(_S2_REUSED, _KEY)]
    _assert_reuse_stimulus(raw, s2=_S2_REUSED)


def test_distinct_resurrected_results_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((_KEY,), s2=_S2_FRESH, destroy_script=[_OBJECT_INVALID])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.operation == "C_FindObjects"
    assert "resurrect" in record.summary
    assert record.detail is not None
    assert record.detail["handle_reused"] is False
    assert raw.destroyed == [(_S2_FRESH, _KEY)]


def test_reuse_unprovable_reopened_session_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), info_rv=_HANDLE_INVALID)
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_GetSessionInfo"
    assert record.actual_ckr == "CKR_SESSION_HANDLE_INVALID"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_unprovable_reopened_session_undefined_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), info_rv=_UNDEFINED_RV)
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_GetSessionInfo"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_missing_premise_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), pre_hits=())
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjects"
    assert "premise" in record.summary
    assert record.actual_ckr == "CKR_OK"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.detail is not None
    assert record.detail["hits"] == []
    assert record.detail["staged_handle"] == _KEY
    assert (_S1, _KEY) in raw.destroyed
    assert _S1 in raw.closed


def test_reuse_reopen_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        opens=[_S1],
        open_script=[_OK, _CLEAN_REJECT],
        op_rv=_OK,
        init_script=[_OK],
        find_script=[(_OK, (_KEY,))],
        final_rv=_OK,
    )
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_OpenSession"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert raw.closed == [_S1]


def test_reuse_reopen_undefined_rv_fails_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _SearchRaw(
        opens=[_S1],
        open_script=[_OK, _UNDEFINED_RV],
        op_rv=_OK,
        init_script=[_OK],
        find_script=[(_OK, (_KEY,))],
        final_rv=_OK,
    )
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_OpenSession"
    assert raw.closed == [_S1]


def test_reuse_pre_init_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), init_script=[_CLEAN_REJECT, _OK])
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsInit"
    assert (_S1, _KEY) in raw.destroyed
    assert _S1 in raw.closed


def test_reuse_pre_init_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), init_script=[_UNDEFINED_RV, _OK])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsInit"


def test_reuse_pre_find_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), pre_rv=_CLEAN_REJECT, pre_hits=())
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjects"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.detail is not None
    assert record.detail["hits"] == []
    assert record.detail["staged_handle"] == _KEY
    assert record.detail["expectation"] == "pre-close search returns the staged object"
    assert (_S1, _KEY) in raw.destroyed
    assert _S1 in raw.closed


def test_reuse_pre_find_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), pre_rv=_UNDEFINED_RV, pre_hits=())
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV)
    assert record.expected_ckr == ["CKR_OK"]


def test_reuse_close_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), close_rv=_CLEAN_REJECT)
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_CloseSession"
    assert (_S1, _KEY) in raw.destroyed


def test_reuse_close_undefined_rv_fails_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), close_rv=_UNDEFINED_RV)
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_CloseSession"


def test_reuse_fresh_init_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), init_script=[_OK, _CLEAN_REJECT])
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsInit"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_fresh_init_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), init_script=[_OK, _UNDEFINED_RV])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsInit"


def test_reuse_fresh_find_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), fresh_rv=_CLEAN_REJECT)
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjects"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_fresh_find_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((), fresh_rv=_UNDEFINED_RV)
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"


def test_reuse_unrelated_object_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((_OTHER,))
    _patch_no_open(monkeypatch)
    _run_reuse(raw)
    assert get_records() == []
    assert raw.closed == [_S1, _S2_REUSED]
    assert raw.destroyed == []


def test_reuse_persistence_fails_as_persistence(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((_KEY,), destroy_script=[_OK])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.operation == "C_CloseSession"
    assert "persist" in record.summary.lower()
    assert "QC9b" in record.summary
    assert "not resurrected" in record.summary.lower()
    assert "resurrected [" not in record.summary
    assert record.expected_ckr == ["session object destroyed by C_CloseSession"]
    assert record.actual_ckr == f"surviving object {_KEY}"
    assert record.detail is not None
    assert record.detail["found"] == [_KEY]
    assert raw.closed == [_S1, _S2_REUSED]
    assert raw.destroyed == [(_S2_REUSED, _KEY)]


def test_reuse_liveness_inconclusive_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((_KEY,), destroy_script=[_CLEAN_REJECT])
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_DestroyObject"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_liveness_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw((_KEY,), destroy_script=[_UNDEFINED_RV])
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_DestroyObject"


def test_reuse_pre_malformed_count_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evil = tuple(range(1, 9))
    raw = _reuse_raw(
        (),
        find_script=[(_OK, evil, 9), (_OK, ())],
    )
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    assert record.expected_ckr == [f"find count <= {tse._STALE_SEARCH_MAX_OBJECTS}"]
    assert record.actual_ckr == "find count 9"
    assert record.detail is not None
    assert record.detail["count"] == 9
    assert record.detail["buffer"] == list(evil)
    assert (_S1, _KEY) in raw.destroyed
    assert _S1 in raw.closed


def test_reuse_fresh_malformed_count_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evil = tuple(range(1, 9))
    raw = _reuse_raw(
        (),
        find_script=[(_OK, (_KEY,)), (_OK, evil, 9)],
    )
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    assert record.expected_ckr == [f"find count <= {tse._STALE_SEARCH_MAX_OBJECTS}"]
    assert record.actual_ckr == "find count 9"
    assert record.detail is not None
    assert record.detail["count"] == 9
    assert record.detail["buffer"] == list(evil)
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_per_run_namespace_unique(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_no_open(monkeypatch)
    raw1 = _reuse_raw(())
    _run_reuse(raw1)
    assert get_records() == []
    label1 = _assert_reuse_stimulus(raw1, s2=_S2_REUSED)
    raw2 = _reuse_raw(())
    _run_reuse(raw2)
    assert get_records() == []
    label2 = _assert_reuse_stimulus(raw2, s2=_S2_REUSED)
    assert label1 != label2


def test_reuse_genkey_missing_capability_closes_s1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _reuse_raw(())
    _patch_no_open(monkeypatch)
    session = _session(raw)
    session.has_mechanism = lambda *_a: False
    with pytest.raises(pytest.skip.Exception):
        tse.TestActiveSearchInvalidation().test_search_state_not_resurrected_on_handle_reuse(
            session, SimpleNamespace()
        )
    assert _S1 in raw.closed


def test_reuse_genkey_refusal_closes_s1(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _reuse_raw((), op_rv=_CLEAN_REJECT)
    _patch_no_open(monkeypatch)
    assert_xfails(_run_reuse, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_GenerateKey"
    assert _S1 in raw.closed

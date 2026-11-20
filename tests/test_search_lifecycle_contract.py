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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check._plugin_report_attach import _apply_recorded_outcome
from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_BASE,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PRIME,
    CKA_PRIVATE,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_DH,
    CKK_DSA,
    CKK_EC,
    CKK_X9_42_DH,
    CKM_AES_KEY_GEN,
    CKO_PUBLIC_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_FUNCTION_FAILED,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_dh_key_agreement as dh_case
from pkcs11_check.testcases import test_dsa_complete as dsa_case
from pkcs11_check.testcases import test_mech_derive as derive_case
from pkcs11_check.testcases import test_session_edge_cases as tse
from pkcs11_check.testcases import test_x942_dh as x942_case
from pkcs11_check.testcases._ec_export import ConventionalECPoint
from pkcs11_check.testcases._exact_search import observe_exact_search
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
        elif atype in (int(CKA_VALUE_LEN), int(CKA_CLASS), int(CKA_KEY_TYPE)):
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
        final_script: list[int] | None = None,
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
        self._final_script = list(final_script) if final_script is not None else None
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
            rv, found = entry
            report_count = len(found)
        else:
            rv, found, report_count = entry
        for index, handle in enumerate(found[:max_count]):
            handles[index] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = report_count
        return rv

    def C_FindObjectsFinal(self, sh: int) -> int:  # noqa: N802
        self.ops.append("final")
        self.final_sessions.append(int(sh))
        if self._final_script:
            return self._final_script.pop(0)
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
    final_rv: int = _OK,
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
        final_rv=final_rv,
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


# --- Part D: QC6a exact public-value search ---------------------------------
#
# Drives the real DH / X9.42 / DSA / derived-EC search nodes through the
# shared exact-search helper at the raw C_FindObjects* layer (_SearchRaw).
# Staging (key generation / import / derive / readback) is monkeypatched in
# each production module's namespace; verdicts, templates, pagination and
# cleanup are the production code under test.

_QC6_PUB = 41
_QC6_PRIV = 42
_QC6_OTHER = 77
_QC6_OTHER2 = 78
_QC6_Y = bytes(range(1, 33))
_QC6_Y_CHANGED = _QC6_Y[:-1] + bytes([_QC6_Y[-1] ^ 1])


def _qc6_session(raw: _SearchRaw, mechs: set[str]) -> Any:
    return SimpleNamespace(
        raw=raw,
        sh=1,
        slot_id=0,
        has_mechanism=lambda name: name in mechs,
    )


def _qc6_pass_script(pub: int = _QC6_PUB) -> list[tuple[int, tuple[int, ...]]]:
    """Exact leg finds pub among others then exhausts; changed leg is empty."""
    return [(_OK, (_QC6_OTHER, pub)), (_OK, ()), (_OK, ())]


def _qc6_raw(
    find_script: list[Any],
    *,
    init_script: list[int] | None = None,
    final_script: list[int] | None = None,
) -> _SearchRaw:
    return _SearchRaw(
        init_script=init_script if init_script is not None else [_OK, _OK],
        find_script=find_script,
        final_rv=_OK,
        final_script=final_script,
    )


def _stage_dh_search(monkeypatch: pytest.MonkeyPatch, readback: dict[Any, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _gen(*_args: Any, **kwargs: Any) -> tuple[int, int]:
        captured["gen_kwargs"] = dict(kwargs)
        return _QC6_PUB, _QC6_PRIV

    monkeypatch.setattr(dh_case, "_gen_dh_keypair", _gen)
    monkeypatch.setattr(dh_case, "read_attributes", lambda *_a, **_k: dict(readback))
    return captured


def _run_dh_search(raw: _SearchRaw) -> None:
    # Keygen-only premise: DH_PKCS_DERIVE is deliberately NOT advertised.
    session = _qc6_session(raw, {"DH_PKCS_KEY_PAIR_GEN"})
    dh_case.TestDHKeyAgreement().test_dh_search_by_exact_public_value(session)


def _assert_staged_destroyed(raw: _SearchRaw, staged: list[int]) -> None:
    assert raw.destroyed == [(1, handle) for handle in staged], raw.destroyed


def test_exact_search_expected_among_others_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expected-among (not global exactly-one) passes with unrelated hits."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(_qc6_pass_script())
    _run_dh_search(raw)
    assert get_records() == []
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_only_other_handle_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A result set holding only a foreign handle fails (no len>=1 oracle)."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_OTHER,)), (_OK, ()), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_empty_result_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Init OK plus an exhausted empty exact search fails."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, ()), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    _assert_fail_record("self_contradiction", "metadata")
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_changed_value_search_matching_expected_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The changed-value leg must not return the staged handle."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_PUB,)), (_OK, ()), (_OK, (_QC6_PUB,)), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    assert len(raw.init_calls) == 2
    exact_attrs = raw.init_calls[0]["attrs"]
    changed_attrs = raw.init_calls[1]["attrs"]
    assert exact_attrs[int(CKA_VALUE)] == _QC6_Y
    assert changed_attrs[int(CKA_VALUE)] == _QC6_Y_CHANGED
    assert changed_attrs[int(CKA_LABEL)] == exact_attrs[int(CKA_LABEL)]
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_dh_exact_search_template_is_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    """DH template is exactly {unique label, class, CKK_DH, exact value}."""
    captured = _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(_qc6_pass_script())
    _run_dh_search(raw)
    attrs = raw.init_calls[0]["attrs"]
    label = attrs.pop(int(CKA_LABEL))
    assert isinstance(label, str) and label.startswith("pkcs11-check-qc6a-dh-")
    assert captured["gen_kwargs"]["extra_pub"][CKA_LABEL] == label
    assert attrs == {
        int(CKA_CLASS): int(CKO_PUBLIC_KEY),
        int(CKA_KEY_TYPE): int(CKK_DH),
        int(CKA_VALUE): _QC6_Y,
    }


def test_exact_search_init_refusal_xfails_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean FindObjectsInit refusal xfails with the original RV kept."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, ())], init_script=[_CLEAN_REJECT, _OK])
    assert_xfails(_run_dh_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsInit"
    assert record.actual_ckr == ckr_name(_CLEAN_REJECT)
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_init_undefined_rv_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An undefined FindObjectsInit RV fails the return-value contract."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, ())], init_script=[_UNDEFINED_RV, _OK])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsInit"
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_changed_leg_init_refusal_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact-leg pass cannot hide a changed-leg Init refusal."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_PUB,)), (_OK, ())], init_script=[_OK, _CLEAN_REJECT])
    assert_xfails(_run_dh_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_CLEAN_REJECT)
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_paginates_until_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhaustion pages past a full first page to the expected handle."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_OTHER,)), (_OK, (_QC6_PUB,)), (_OK, ()), (_OK, ())])
    _run_dh_search(raw)
    assert get_records() == []
    assert len(raw.find_sessions) == 4
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_absent_after_exhaustion_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence is decided only after the terminating empty page."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_OTHER,)), (_OK, (_QC6_OTHER2,)), (_OK, ()), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    _assert_fail_record("self_contradiction", "metadata")
    assert len(raw.find_sessions) == 4
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_malformed_count_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reported count above capacity fails; the other leg still runs."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (), 17), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects"
    assert record.detail is not None
    assert record.detail["count"] == 17
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_cleanup_destroys_only_staged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Foreign search hits are never destroyed, on the failing path too."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (_QC6_OTHER,)), (_OK, ()), (_OK, (_QC6_OTHER2,)), (_OK, ())])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    assert (1, _QC6_OTHER) not in raw.destroyed
    assert (1, _QC6_OTHER2) not in raw.destroyed
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_dh_exact_search_missing_readback_never_searches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing DH public readback records xfail and never calls FindInit."""
    _stage_dh_search(monkeypatch, {})
    raw = _qc6_raw(_qc6_pass_script())
    _run_dh_search(raw)
    _assert_xfail_record("not_operational")
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_dh_exact_search_malformed_readback_never_searches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty DH public readback is a shape fail before any search."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: b""})
    raw = _qc6_raw(_qc6_pass_script())
    with pytest.raises(Failed):
        _run_dh_search(raw)
    _assert_fail_record("wrong_result", "metadata")
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def _stage_x942_search(monkeypatch: pytest.MonkeyPatch, readback: dict[Any, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _gen(*_args: Any, **kwargs: Any) -> tuple[int, int]:
        captured["gen_kwargs"] = dict(kwargs)
        return _QC6_PUB, _QC6_PRIV

    monkeypatch.setattr(x942_case, "_generate_x942_keypair", _gen)
    monkeypatch.setattr(x942_case, "read_attributes", lambda *_a, **_k: dict(readback))
    return captured


def _run_x942_search(raw: _SearchRaw) -> None:
    session = _qc6_session(raw, {"X9_42_DH_KEY_PAIR_GEN"})
    x942_case.TestX942DHKeyPairGen().test_keypair_search_by_exact_public_value(session)


def test_x942_exact_search_template_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """X9.42 template is exactly {unique label, class, CKK_X9_42_DH, value}."""
    captured = _stage_x942_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(_qc6_pass_script())
    _run_x942_search(raw)
    assert get_records() == []
    attrs = raw.init_calls[0]["attrs"]
    label = attrs.pop(int(CKA_LABEL))
    assert isinstance(label, str) and label.startswith("pkcs11-check-qc6a-x942-")
    assert captured["gen_kwargs"]["label"] == label
    assert attrs == {
        int(CKA_CLASS): int(CKO_PUBLIC_KEY),
        int(CKA_KEY_TYPE): int(CKK_X9_42_DH),
        int(CKA_VALUE): _QC6_Y,
    }
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_x942_exact_search_missing_readback_never_searches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing X9.42 public readback records xfail and never searches."""
    _stage_x942_search(monkeypatch, {})
    raw = _qc6_raw(_qc6_pass_script())
    _run_x942_search(raw)
    _assert_xfail_record("not_operational")
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def _fixed_dsa_attrs(**overrides: Any) -> dict[Any, Any]:
    attrs: dict[Any, Any] = {
        CKA_PRIME: dsa_case._FIXED_DSA_P,
        CKA_SUBPRIME: dsa_case._FIXED_DSA_Q,
        CKA_BASE: dsa_case._FIXED_DSA_G,
        CKA_VALUE: dsa_case._FIXED_DSA_Y,
    }
    attrs.update(overrides)
    return attrs


def _stage_dsa_search(monkeypatch: pytest.MonkeyPatch, readback: dict[Any, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _import(*_args: Any, **kwargs: Any) -> tuple[int, int]:
        captured["import_kwargs"] = dict(kwargs)
        return _QC6_PUB, _QC6_PRIV

    monkeypatch.setattr(dsa_case, "_import_fixed_dsa_keypair", _import)
    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(dsa_case, "read_attributes", lambda *_a, **_k: dict(readback))
    return captured


def _run_dsa_search(raw: _SearchRaw) -> None:
    session = _qc6_session(raw, {"DSA"})
    dsa_case.TestDSAPublicValueSearch().test_fixed_dsa_search_by_exact_public_value(session)


def test_dsa_exact_search_template_is_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    """DSA template is exactly {unique label, class, CKK_DSA, fixed Y}."""
    captured = _stage_dsa_search(monkeypatch, _fixed_dsa_attrs())
    raw = _qc6_raw(_qc6_pass_script())
    _run_dsa_search(raw)
    assert get_records() == []
    attrs = raw.init_calls[0]["attrs"]
    label = attrs.pop(int(CKA_LABEL))
    assert isinstance(label, str) and label.startswith("pkcs11-check-qc6a-dsa-")
    assert captured["import_kwargs"]["label"] == label
    assert attrs == {
        int(CKA_CLASS): int(CKO_PUBLIC_KEY),
        int(CKA_KEY_TYPE): int(CKK_DSA),
        int(CKA_VALUE): dsa_case._FIXED_DSA_Y,
    }
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_dsa_exact_search_incoherent_import_never_searches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong present Y fails coherence before search, even with an omission."""
    readback = _fixed_dsa_attrs()
    readback[CKA_VALUE] = _QC6_Y
    del readback[CKA_BASE]
    _stage_dsa_search(monkeypatch, readback)
    raw = _qc6_raw(_qc6_pass_script())
    with pytest.raises(Failed):
        _run_dsa_search(raw)
    _assert_fail_record("wrong_result", "metadata")
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def _dsa_public_session() -> Any:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "DSA")


def test_dsa_public_staging_imports_public_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """R2-A3: public-only staging never imports the private half."""
    purposes: list[str] = []

    def _create(_rs: Any, _attrs: Any, *, purpose: str) -> int:
        purposes.append(purpose)
        return _QC6_PUB

    monkeypatch.setattr(dsa_case, "create_object_negotiated", _create)
    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    assert dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True) == _QC6_PUB
    assert purposes == ["QC6b fixed DSA-2048 public-only import"], purposes


def test_dsa_public_staging_ignores_encoding_divergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2-A3: no byte-identical coherence gate on the public-only path."""

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("public-only staging must not read back for coherence")

    monkeypatch.setattr(dsa_case, "create_object_negotiated", lambda *_a, **_k: _QC6_PUB)
    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(dsa_case, "read_attributes", _boom)
    assert dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True) == _QC6_PUB


def test_dsa_public_staging_refusal_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """R2-A3/R3-A3: every import RV grades at source; DSA-less surfaces as refusal."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_PIN_INCORRECT, CKR_TEMPLATE_INCONSISTENT

    def _refuse(*_args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("refused", int(CKR_TEMPLATE_INCONSISTENT))

    def _fail(*_args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("failed", int(CKR_PIN_INCORRECT))

    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(dsa_case, "create_object_negotiated", _refuse)
    with pytest.raises(XFailed):
        dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True)
    # R3-A3: an unlisted standard refusal xfails unexpected-but-clean (no raw raise).
    monkeypatch.setattr(dsa_case, "create_object_negotiated", _fail)
    with pytest.raises(XFailed):
        dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True)
    # R3-A3: no CKM_DSA gate -- a DSA-less provider surfaces as the graded refusal.
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: False)
    with pytest.raises(XFailed):
        dsa_case._stage_fixed_dsa_public(rs, copyable=True)


def test_dsa_public_staging_vendor_refusal_xfails_alternate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3-A3: a vendor import refusal xfails as the visible alternate."""
    from pkcs11_check.raw.rv import CkrAssertionError

    def _vendor(*_args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("vendor refused", 0x80000001)

    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(dsa_case, "create_object_negotiated", _vendor)
    with pytest.raises(XFailed) as exc_info:
        dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True)
    assert type(exc_info.value) is XFailed
    (record,) = [rec for rec in get_records() if rec.outcome == "xfail"]
    assert record.reason == "nonspec_reject", record.summary


def test_dsa_public_staging_undefined_refusal_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3-A3: an undefined import RV fails the metadata contract."""
    from _pytest.outcomes import Failed

    from pkcs11_check.raw.rv import CkrAssertionError

    def _undefined(*_args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("undefined", 0x7FFFFFFF)

    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(dsa_case, "create_object_negotiated", _undefined)
    with pytest.raises(Failed) as exc_info:
        dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True)
    assert type(exc_info.value) is Failed
    (record,) = [rec for rec in get_records() if rec.outcome == "fail"]
    assert record.reason == "self_contradiction", record.summary
    assert record.kind == "metadata", record.summary


def test_dsa_public_staging_non_ckr_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3-A3: a non-CKR fixture bug reraises untouched (never graded)."""
    monkeypatch.setattr(dsa_case, "skip_unless_create_object_supported", lambda _rs: None)

    def _bug(*_args: Any, **kwargs: Any) -> int:
        raise AssertionError("fixture bug")

    monkeypatch.setattr(dsa_case, "create_object_negotiated", _bug)
    with pytest.raises(AssertionError, match="fixture bug"):
        dsa_case._stage_fixed_dsa_public(_dsa_public_session(), copyable=True)


def test_dsa_compare_node_stages_public_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """R2-A3: the compare node stages, compares, and destroys one handle."""
    seen: dict[str, Any] = {}

    def _stage(_rs: Any, **kwargs: Any) -> int:
        seen["stage_kwargs"] = dict(kwargs)
        return 777

    def _leg(_rs: Any, handle: int, _template: Any, **kwargs: Any) -> Any:
        seen.setdefault("legs", []).append((handle, kwargs.get("leg")))
        return ("ok", b"Y")

    def _judge(**kwargs: Any) -> None:
        seen["judged"] = True

    def _destroy(_raw: Any, _sh: int, handle: int) -> None:
        seen.setdefault("destroyed", []).append(handle)

    monkeypatch.setattr(dsa_case, "_stage_fixed_dsa_public", _stage)
    monkeypatch.setattr(dsa_case, "_read_dsa_public_value_or_void", lambda *_a, **_k: b"Y")
    monkeypatch.setattr(dsa_case, "run_copy_compare_leg", _leg)
    monkeypatch.setattr(dsa_case, "judge_copy_compare", _judge)
    monkeypatch.setattr(dsa_case, "destroy_quietly", _destroy)
    dsa_case.TestDSAPublicCopyCompare().test_fixed_dsa_public_copy_empty_vs_restated(
        SimpleNamespace(raw=object(), sh=1)
    )
    assert seen["stage_kwargs"] == {"copyable": True}, seen
    assert seen["legs"] == [(777, "empty"), (777, "restated")], seen
    assert seen.get("judged") is True, seen
    assert seen["destroyed"] == [777], seen


_EC_PUB = 11
_EC_PRIV = 12
_EC_DERIVED = 21
_EC_PARAMS = bytes.fromhex("06082a8648ce3d030107")


def _ec_public_key() -> ec.EllipticCurvePublicKey:
    return ec.generate_private_key(ec.SECP256R1()).public_key()


def _sec1(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _der_wrap(sec1: bytes) -> bytes:
    assert len(sec1) < 128
    return bytes([0x04, len(sec1)]) + sec1


def _stage_ec_search(
    monkeypatch: pytest.MonkeyPatch,
    *,
    derived: ConventionalECPoint,
    original: ConventionalECPoint,
    params: bytes | None = _EC_PARAMS,
) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _derive(*_args: Any, **kwargs: Any) -> int:
        captured["derive_kwargs"] = dict(kwargs)
        return _EC_DERIVED

    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_a, **_k: (_EC_PUB, _EC_PRIV))
    monkeypatch.setattr(derive_case, "derive_key", _derive)
    monkeypatch.setattr(derive_case, "mech_simple", lambda *_a, **_k: object())
    monkeypatch.setattr(
        derive_case,
        "read_attributes",
        lambda *_a, **_k: {} if params is None else {CKA_EC_PARAMS: params},
    )
    points = {_EC_DERIVED: derived, _EC_PUB: original}
    monkeypatch.setattr(
        derive_case,
        "read_conventional_ec_point_or_xfail",
        lambda _rs, handle, _curve, *, label="": points[handle],
    )
    return captured


def _run_ec_search(raw: _SearchRaw) -> None:
    session = _qc6_session(raw, {"EC_KEY_PAIR_GEN", "PUB_KEY_FROM_PRIV_KEY"})
    derive_case.TestDerivedECPublicSearch().test_derived_ec_public_search_by_exact_params_and_point(
        session
    )


def _ec_pair_same() -> tuple[ConventionalECPoint, ConventionalECPoint, bytes]:
    pub = _ec_public_key()
    sec1 = _sec1(pub)
    point = ConventionalECPoint(sec1, sec1, pub)
    return point, point, sec1


def test_derived_ec_exact_search_template_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EC template is exactly {label, class, CKK_EC, params, point}."""
    derived, original, sec1 = _ec_pair_same()
    captured = _stage_ec_search(monkeypatch, derived=derived, original=original)
    raw = _qc6_raw(_qc6_pass_script(pub=_EC_DERIVED))
    _run_ec_search(raw)
    assert get_records() == []
    attrs = raw.init_calls[0]["attrs"]
    label = attrs.pop(int(CKA_LABEL))
    assert isinstance(label, str) and label.startswith("pkcs11-check-qc6a-ec-")
    assert captured["derive_kwargs"]["attrs"][CKA_LABEL] == label
    assert attrs == {
        int(CKA_CLASS): int(CKO_PUBLIC_KEY),
        int(CKA_KEY_TYPE): int(CKK_EC),
        int(CKA_EC_PARAMS): _EC_PARAMS,
        int(CKA_EC_POINT): sec1,
    }
    _assert_staged_destroyed(raw, [_EC_PUB, _EC_PRIV, _EC_DERIVED])


def test_derived_ec_search_uses_provider_bytes_not_sec1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DER-wrapped derived point is searched by its provider bytes verbatim."""
    pub = _ec_public_key()
    sec1 = _sec1(pub)
    provider_bytes = _der_wrap(sec1)
    derived = ConventionalECPoint(provider_bytes, sec1, pub)
    original = ConventionalECPoint(sec1, sec1, pub)
    _stage_ec_search(monkeypatch, derived=derived, original=original)
    raw = _qc6_raw(_qc6_pass_script(pub=_EC_DERIVED))
    _run_ec_search(raw)
    exact_point = raw.init_calls[0]["attrs"][int(CKA_EC_POINT)]
    assert exact_point == provider_bytes
    assert exact_point != sec1
    changed_point = raw.init_calls[1]["attrs"][int(CKA_EC_POINT)]
    assert changed_point == provider_bytes[:-1] + bytes([provider_bytes[-1] ^ 1])
    assert raw.init_calls[1]["attrs"][int(CKA_EC_PARAMS)] == _EC_PARAMS


def test_derived_ec_point_differs_from_original_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid but wrong derived point fails the semantic oracle pre-search."""
    derived_pub, original_pub = _ec_public_key(), _ec_public_key()
    derived = ConventionalECPoint(_sec1(derived_pub), _sec1(derived_pub), derived_pub)
    original = ConventionalECPoint(_sec1(original_pub), _sec1(original_pub), original_pub)
    _stage_ec_search(monkeypatch, derived=derived, original=original)
    raw = _qc6_raw(_qc6_pass_script(pub=_EC_DERIVED))
    with pytest.raises(Failed):
        _run_ec_search(raw)
    record = _assert_fail_record("wrong_result", "crypto")
    assert record.operation == "C_DeriveKey"
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_EC_PUB, _EC_PRIV, _EC_DERIVED])


def test_derived_ec_missing_params_or_point_xfails_without_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing derived CKA_EC_PARAMS xfails recorded and never searches."""
    derived, original, _sec1_bytes = _ec_pair_same()
    _stage_ec_search(monkeypatch, derived=derived, original=original, params=None)
    raw = _qc6_raw(_qc6_pass_script(pub=_EC_DERIVED))
    assert_xfails(_run_ec_search, raw)
    _assert_xfail_record("not_operational")
    assert raw.init_calls == []
    _assert_staged_destroyed(raw, [_EC_PUB, _EC_PRIV, _EC_DERIVED])


# --- PR64 P5: C_FindObjectsFinal results are captured and classified ------


def _reported_outcome_p5() -> str:
    """Replay the record stream through the real report hook (P5 sibling)."""
    report = SimpleNamespace(outcome="passed")
    _apply_recorded_outcome(report, get_records())
    if report.outcome == "failed":
        return "fail"
    if getattr(report, "wasxfail", None) is not None:
        return "xfail"
    return "pass"


def test_exact_search_final_clean_refusal_xfails_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5: a clean Final refusal xfails; the sibling leg still runs."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(_qc6_pass_script(), final_script=[_CLEAN_REJECT, _OK])
    assert_xfails(_run_dh_search, raw)
    record = _assert_xfail_record("not_operational")
    assert record.operation == "C_FindObjectsFinal", record.operation
    assert record.actual_ckr == ckr_name(_CLEAN_REJECT), record.actual_ckr
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_final_undefined_rv_fails_metadata_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5: an undefined Final RV fails the return-value contract."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(_qc6_pass_script(), final_script=[_UNDEFINED_RV, _OK])
    with pytest.raises(Failed):
        _run_dh_search(raw)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjectsFinal", record.operation
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV), record.actual_ckr
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_final_failure_keeps_stronger_find_fail_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5: a Final xfail never replaces a proved Find failure."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_OK, (), 17), (_OK, ())], final_script=[_CLEAN_REJECT, _OK])
    with pytest.raises(Failed) as ei:
        _run_dh_search(raw)
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    fails = [r for r in records if r.outcome == "fail"]
    xfails = [r for r in records if r.outcome == "xfail"]
    assert len(fails) == 1, [(r.reason, r.operation) for r in records]
    assert fails[0].operation == "C_FindObjects", fails[0].operation
    assert (fails[0].detail or {}).get("count") == 17, fails[0].detail
    assert len(xfails) == 1, [(r.reason, r.operation) for r in records]
    assert xfails[0].operation == "C_FindObjectsFinal", xfails[0].operation
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_final_failure_keeps_membership_fail_r5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5: a clean Final failure must not suppress the exact-leg membership FAIL."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(
        [(_OK, (_QC6_OTHER,)), (_OK, ()), (_OK, ())],
        final_script=[_CLEAN_REJECT, _OK],
    )
    with pytest.raises(Failed) as ei:
        _run_dh_search(raw)
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    fails = [r for r in records if r.outcome == "fail"]
    xfails = [r for r in records if r.outcome == "xfail"]
    assert len(fails) == 1, [(r.reason, r.operation) for r in records]
    assert fails[0].reason == "self_contradiction", fails[0].reason
    assert fails[0].kind == "metadata", fails[0].kind
    assert fails[0].operation == "C_FindObjects", fails[0].operation
    assert len(xfails) == 1, [(r.reason, r.operation) for r in records]
    assert xfails[0].operation == "C_FindObjectsFinal", xfails[0].operation
    assert len(raw.init_calls) == 2, "changed leg still observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_changed_search_final_failure_keeps_membership_fail_r5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R5: a clean Final failure must not suppress the changed-leg FAIL."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw(
        [(_OK, (_QC6_PUB,)), (_OK, ()), (_OK, (_QC6_PUB,)), (_OK, ())],
        final_script=[_OK, _CLEAN_REJECT],
    )
    with pytest.raises(Failed) as ei:
        _run_dh_search(raw)
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    fails = [r for r in records if r.outcome == "fail"]
    xfails = [r for r in records if r.outcome == "xfail"]
    assert len(fails) == 1, [(r.reason, r.operation) for r in records]
    assert fails[0].reason == "self_contradiction", fails[0].reason
    assert fails[0].kind == "metadata", fails[0].kind
    assert fails[0].operation == "C_FindObjects", fails[0].operation
    assert len(xfails) == 1, [(r.reason, r.operation) for r in records]
    assert xfails[0].operation == "C_FindObjectsFinal", xfails[0].operation
    assert len(raw.init_calls) == 2, "both legs observed"
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


def test_exact_search_final_undefined_beats_find_refusal_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5: an undefined Final FAIL outranks a clean Find-refusal xfail."""
    _stage_dh_search(monkeypatch, {CKA_VALUE: _QC6_Y})
    raw = _qc6_raw([(_CLEAN_REJECT, ()), (_OK, ())], final_script=[_UNDEFINED_RV, _OK])
    with pytest.raises(Failed) as ei:
        _run_dh_search(raw)
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    fails = [r for r in records if r.outcome == "fail"]
    xfails = [r for r in records if r.outcome == "xfail"]
    assert len(fails) == 1, [(r.reason, r.operation) for r in records]
    assert fails[0].reason == "self_contradiction", fails[0].reason
    assert fails[0].kind == "metadata", fails[0].kind
    assert fails[0].operation == "C_FindObjectsFinal", fails[0].operation
    assert len(xfails) == 1, [(r.reason, r.operation) for r in records]
    assert xfails[0].operation == "C_FindObjects", xfails[0].operation
    _assert_staged_destroyed(raw, [_QC6_PUB, _QC6_PRIV])


class _NoFinalRaw:
    """Raw surface without C_FindObjectsFinal (fake-tolerance pin, P5)."""

    # noqa comments below: raw PKCS#11 entry-point names are mandated.
    def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        return _OK

    def C_FindObjects(  # noqa: N802
        self, _sh: int, _handles: Any, _max_count: int, found_ptr: Any
    ) -> int:
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = 0
        return _OK


def test_observe_exact_search_without_final_tolerated_p5() -> None:
    """P5 pin: a raw without C_FindObjectsFinal still yields its handles."""
    rs = SimpleNamespace(raw=_NoFinalRaw(), sh=1)
    observed = observe_exact_search(rs, {CKA_LABEL: "p5-no-final"}, label="p5-no-final")
    assert observed.handles == ()
    assert observed.record is None
    assert get_records() == []


def test_reuse_fresh_final_clean_refusal_recorded_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5 sibling: fresh Final refusal is recorded, verdict flow unchanged."""
    raw = _reuse_raw((), final_rv=_CLEAN_REJECT)
    _patch_no_open(monkeypatch)
    _run_reuse(raw)
    records = get_records()
    assert len(records) == 1, [(r.reason, r.operation) for r in records]
    assert records[0].reason == "not_operational", records[0].reason
    assert records[0].outcome == "xfail", records[0].outcome
    assert records[0].operation == "C_FindObjectsFinal", records[0].operation
    assert records[0].actual_ckr == ckr_name(_CLEAN_REJECT), records[0].actual_ckr
    assert _reported_outcome_p5() == "xfail"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_fresh_final_undefined_recorded_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5 sibling: an undefined fresh Final RV records a metadata FAIL."""
    raw = _reuse_raw((), final_rv=_UNDEFINED_RV)
    _patch_no_open(monkeypatch)
    _run_reuse(raw)
    records = get_records()
    assert len(records) == 1, [(r.reason, r.operation) for r in records]
    assert records[0].reason == "self_contradiction", records[0].reason
    assert records[0].kind == "metadata", records[0].kind
    assert records[0].outcome == "fail", records[0].outcome
    assert records[0].operation == "C_FindObjectsFinal", records[0].operation
    assert records[0].actual_ckr == ckr_name(_UNDEFINED_RV), records[0].actual_ckr
    assert _reported_outcome_p5() == "fail"
    assert raw.closed == [_S1, _S2_REUSED]


def test_reuse_fresh_final_failure_preserves_resurrection_fail_p5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5 sibling: the recorded Final defect never hides resurrection."""
    raw = _reuse_raw((_KEY,), destroy_script=[_OBJECT_INVALID], final_rv=_CLEAN_REJECT)
    _patch_no_open(monkeypatch)
    with pytest.raises(Failed) as ei:
        _run_reuse(raw)
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    fails = [r for r in records if r.outcome == "fail"]
    xfails = [r for r in records if r.outcome == "xfail"]
    assert len(fails) == 1, [(r.reason, r.operation) for r in records]
    assert fails[0].reason == "self_contradiction", fails[0].reason
    assert fails[0].kind == "lifecycle", fails[0].kind
    assert "resurrect" in fails[0].summary, fails[0].summary
    assert len(xfails) == 1, [(r.reason, r.operation) for r in records]
    assert xfails[0].operation == "C_FindObjectsFinal", xfails[0].operation
    assert raw.closed == [_S1, _S2_REUSED]


class _ScriptedFindRaw:
    """Find surface scripted by searched template: pages keyed by (attr, value).

    Each Init validates the FULL template (class, key type, value attr)
    and serves the next scripted page for THAT (attr, value) pair; a
    search for an unscripted pair fails loud, so a template mixup in the
    source cannot go green. ``refuse_after`` scripts a Find RV for the
    call after the served page, modelling a mid-search refusal.
    """

    # noqa comments below: raw PKCS#11 entry-point names are mandated.

    def __init__(
        self,
        pages: dict[tuple[int, bytes], list[tuple[int, ...]]],
        refuse_after: dict[tuple[int, bytes], int] | None = None,
        *,
        sticky: bool = False,
    ) -> None:
        self._pages = {key: list(value) for key, value in pages.items()}
        self._refuse_after = dict(refuse_after or {})
        self._sticky = sticky
        self.inits = 0
        self.searched: list[tuple[int, bytes]] = []
        self._page: tuple[int, ...] = ()
        self._served = True
        self._tail_rv: int | None = None

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.inits += 1
        sought = _searched_template_key(tmpl, int(count))
        self.searched.append(sought)
        assert sought in self._pages, f"search for unscripted template {sought!r}"
        assert self._pages[sought], f"no page left for {sought!r}"
        self._page = self._pages[sought].pop(0)
        self._served = False
        self._tail_rv = self._refuse_after.pop(sought, None)
        return _OK

    def C_FindObjects(  # noqa: N802
        self, _sh: int, handles: Any, _max_count: int, found_ptr: Any
    ) -> int:
        if self._served and not self._sticky:
            if self._tail_rv is not None:
                rv, self._tail_rv = self._tail_rv, None
                return rv
            page: tuple[int, ...] = ()
        else:
            page = self._page
            self._served = not self._sticky
        for i, handle in enumerate(page):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(page)
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK


def _searched_template_key(tmpl: Any, count: int) -> tuple[int, bytes]:
    """Decode and validate a search template: (value-attr type, value bytes).

    The class/key-type scope is asserted (the production legs always
    search public EC keys); only the value attribute varies per leg.
    The ENTIRE template is checked (R3F10): exactly one value
    predicate besides the scope, so a production leg searching extra
    (or missing) attributes cannot hide behind first-predicate
    matching.
    """
    seen_class = False
    seen_key_type = False
    for i in range(count):
        attr_type = int(tmpl[i].type)
        if attr_type == int(CKA_CLASS):
            seen_class = True
            length = int(tmpl[i].ulValueLen)
            value = int.from_bytes(bytes(ctypes.string_at(tmpl[i].pValue, length)), "little")
            assert value == int(CKO_PUBLIC_KEY), value
        elif attr_type == int(CKA_KEY_TYPE):
            seen_key_type = True
            length = int(tmpl[i].ulValueLen)
            value = int.from_bytes(bytes(ctypes.string_at(tmpl[i].pValue, length)), "little")
            assert value == int(CKK_EC), value
    assert seen_class and seen_key_type, "search template misses class/key-type scope"
    values = [
        i for i in range(count) if int(tmpl[i].type) not in (int(CKA_CLASS), int(CKA_KEY_TYPE))
    ]
    assert len(values) == 1, f"search template must carry exactly one value attr, got {len(values)}"
    i = values[0]
    attr_type = int(tmpl[i].type)
    length = int(tmpl[i].ulValueLen)
    if tmpl[i].pValue is None or length == 0:
        return (attr_type, b"")
    return (attr_type, bytes(ctypes.string_at(tmpl[i].pValue, length)))


_SEP_DERIVED = 101
_SEP_ORIGINAL = 102
_SEP_BYTES = b"shared-provider-bytes"
_SEP_BYTES_D = b"derived-provider-bytes"
_SEP_BYTES_O = b"original-provider-bytes"


def _sep_records(
    pages: dict[bytes, list[tuple[int, ...]]],
    *,
    attr: int | None = None,
    attr_name: str = "params",
    refuse_after: dict[bytes, int] | None = None,
    **kw: Any,
) -> list[Any]:
    from pkcs11_check.testcases._exact_search import separate_search_records

    resolved = int(CKA_EC_PARAMS) if attr is None else int(attr)
    keyed = {(resolved, value): list(served) for value, served in pages.items()}
    tails = {(resolved, value): rv for value, rv in (refuse_after or {}).items()}
    raw = _ScriptedFindRaw(keyed, refuse_after=tails)
    rs = SimpleNamespace(raw=raw, sh=1)
    return separate_search_records(rs, attr=resolved, attr_name=attr_name, **kw)


def _flipped(value: bytes) -> bytes:
    from pkcs11_check.testcases._exact_search import flip_last_byte

    return flip_last_byte(value)


def test_separate_search_agreeing_bytes_both_present_passes() -> None:
    """Shared bytes returning both handles produce no records."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    assert records == [None] * 6


def test_separate_search_agreeing_bytes_derived_missing_fails() -> None:
    """Shared bytes hiding the derived key fail (the #58.2 defect)."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_ORIGINAL,), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    fails = [record for record in records if record is not None]
    assert len(fails) == 1, [(record.reason, record.summary) for record in fails]
    assert fails[0].reason == "self_contradiction"
    assert fails[0].outcome == "fail"


def test_separate_search_agreeing_bytes_cross_missing_fails() -> None:
    """The cross leg fails when the sibling search hides a shared-bytes key."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_ORIGINAL,)],
            _flipped(_SEP_BYTES): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    fails = [record for record in records if record is not None]
    assert len(fails) == 1, [(record.reason, record.summary) for record in fails]
    assert fails[0].reason == "self_contradiction"
    assert "cross" in (fails[0].summary or "")


def test_separate_search_changed_match_fails() -> None:
    """A changed-value search returning a staged key fails."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [(_SEP_DERIVED,)],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    fails = [record for record in records if record is not None]
    assert len(fails) == 1, [(record.reason, record.summary) for record in fails]
    assert fails[0].reason == "self_contradiction"
    assert "changed-value" in (fails[0].summary or "")


def test_separate_search_diverging_bytes_self_present_passes() -> None:
    """Diverging bytes with reciprocal exclusion produce no records."""
    records = _sep_records(
        {
            _SEP_BYTES_D: [(_SEP_DERIVED,)],
            _SEP_BYTES_O: [(_SEP_ORIGINAL,)],
            _flipped(_SEP_BYTES_D): [()],
            _flipped(_SEP_BYTES_O): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES_D),
        original=(_SEP_ORIGINAL, _SEP_BYTES_O),
        label="sep",
    )
    assert records == [None] * 8


def test_separate_search_diverging_bytes_self_missing_fails() -> None:
    """A key missing from its own-bytes search fails."""
    records = _sep_records(
        {
            _SEP_BYTES_D: [()],
            _SEP_BYTES_O: [(_SEP_ORIGINAL,)],
            _flipped(_SEP_BYTES_D): [()],
            _flipped(_SEP_BYTES_O): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES_D),
        original=(_SEP_ORIGINAL, _SEP_BYTES_O),
        label="sep",
    )
    fails = [record for record in records if record is not None]
    assert len(fails) == 1, [(record.reason, record.summary) for record in fails]
    assert fails[0].reason == "self_contradiction"


def test_separate_search_diverging_bytes_cross_hit_fails() -> None:
    """C2: an exact search returning both handles on diverging bytes fails."""
    records = _sep_records(
        {
            _SEP_BYTES_D: [(_SEP_DERIVED, _SEP_ORIGINAL)],
            _SEP_BYTES_O: [(_SEP_ORIGINAL,)],
            _flipped(_SEP_BYTES_D): [()],
            _flipped(_SEP_BYTES_O): [()],
        },
        derived=(_SEP_DERIVED, _SEP_BYTES_D),
        original=(_SEP_ORIGINAL, _SEP_BYTES_O),
        label="sep",
    )
    fails = [record for record in records if record is not None]
    assert len(fails) == 1, [(record.reason, record.summary) for record in fails]
    assert fails[0].reason == "self_contradiction"
    assert "cross" in (fails[0].summary or "")


def test_separate_search_unscripted_template_fails_loud() -> None:
    """C2: a search for bytes the test never scripted fails the fake, never passes."""
    with pytest.raises(AssertionError, match="unscripted template"):
        _sep_records(
            {_SEP_BYTES_D: [(_SEP_DERIVED,)]},
            derived=(_SEP_DERIVED, _SEP_BYTES_D),
            original=(_SEP_ORIGINAL, _SEP_BYTES_O),
            label="sep",
        )


def test_separate_search_point_leg_agreeing_bytes_passes() -> None:
    """R2B5: the production point leg runs under the same contract."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [()],
        },
        attr=int(CKA_EC_POINT),
        attr_name="point",
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    assert records == [None] * 6


def test_searched_template_key_rejects_extra_predicate() -> None:
    """R3F10: the fake checks the entire template, not just the first value attr."""
    from pkcs11_check.raw.pack import template_from_dict

    tmpl = template_from_dict(
        {
            int(CKA_CLASS): int(CKO_PUBLIC_KEY),
            int(CKA_KEY_TYPE): int(CKK_EC),
            int(CKA_EC_PARAMS): b"params",
            int(CKA_LABEL): b"extra",
        }
    )
    with pytest.raises(AssertionError, match="exactly one value attr"):
        _searched_template_key(tmpl.ptr, tmpl.count)


def test_separate_search_params_point_legs_distinguished() -> None:
    """R2B5: pages scripted for params never serve the point leg."""
    with pytest.raises(AssertionError, match="unscripted template"):
        _sep_records(
            {
                _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
                _flipped(_SEP_BYTES): [()],
            },
            attr=int(CKA_EC_POINT),
            attr_name="point",
            derived=(_SEP_DERIVED, _SEP_BYTES_D),
            original=(_SEP_ORIGINAL, _SEP_BYTES_D),
            label="sep",
        )


def test_separate_search_changed_hit_before_refusal_fails() -> None:
    """R2B5: a forbidden hit on a delivered page fails despite a later refusal."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [(_SEP_DERIVED,)],
        },
        refuse_after={_flipped(_SEP_BYTES): int(CKR_FUNCTION_FAILED)},
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    fails = [record for record in records if record is not None and record.outcome == "fail"]
    assert len(fails) == 1, [(r.reason, r.summary) for r in records if r is not None]
    # R3F14: the terminal states the proved hit, never a later refusal or cause.
    assert "on a successfully delivered page" in (fails[0].summary or ""), fails[0].summary
    assert "refused" not in (fails[0].summary or ""), fails[0].summary
    assert "ignored" not in (fails[0].summary or ""), fails[0].summary
    assert fails[0].actual_ckr == "CKR_OK", fails[0].summary
    assert fails[0].detail is not None and _SEP_DERIVED in fails[0].detail["partial_handles"]


def test_changed_hit_on_capped_search_states_proved_hit() -> None:
    """R3F14: a cap-ended all-OK search with a delivered hit fails without refusal language."""
    from pkcs11_check.testcases._exact_search import expected_not_among_record, observe_exact_search

    raw = _ScriptedFindRaw({(int(CKA_EC_PARAMS), _SEP_BYTES): [(_SEP_DERIVED,)]}, sticky=True)
    rs = SimpleNamespace(raw=raw, sh=1)
    obs = observe_exact_search(
        rs,
        {CKA_CLASS: CKO_PUBLIC_KEY, CKA_KEY_TYPE: CKK_EC, CKA_EC_PARAMS: _SEP_BYTES},
        label="cap",
    )
    assert obs.handles is None, obs
    record = expected_not_among_record(obs, _SEP_DERIVED, label="cap")
    assert record is not None and record.outcome == "fail"
    assert "on a successfully delivered page" in (record.summary or ""), record.summary
    assert "refused" not in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.summary


def test_separate_search_changed_miss_before_refusal_keeps_refusal() -> None:
    """R2B5: absence from a partial set stays unproved and keeps the defect."""
    records = _sep_records(
        {
            _SEP_BYTES: [(_SEP_DERIVED, _SEP_ORIGINAL), (_SEP_DERIVED, _SEP_ORIGINAL)],
            _flipped(_SEP_BYTES): [(999,)],
        },
        refuse_after={_flipped(_SEP_BYTES): int(CKR_FUNCTION_FAILED)},
        derived=(_SEP_DERIVED, _SEP_BYTES),
        original=(_SEP_ORIGINAL, _SEP_BYTES),
        label="sep",
    )
    pending = [record for record in records if record is not None]
    assert pending, "the refusal must surface"
    assert all(record.outcome == "xfail" for record in pending)
    assert all(record.reason == "not_operational" for record in pending)


def test_observe_exact_search_bounded_unfinished_is_inconclusive() -> None:
    """R2B5: a search filling the paging bound is inconclusive, not a defect."""
    from pkcs11_check.testcases import _exact_search as exact

    pages = [(tuple(range(n * 16 + 1, n * 16 + 17))) for n in range(exact.MAX_PAGES)]

    class _BoundedRaw:
        def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
            self._pages = list(pages)
            return int(CKR_OK)

        def C_FindObjects(  # noqa: N802
            self, _sh: int, handles: Any, _max_count: int, found_ptr: Any
        ) -> int:
            page = self._pages.pop(0)
            for i, handle in enumerate(page):
                handles[i] = handle
            ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(page)
            return int(CKR_OK)

        def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
            return int(CKR_OK)

    rs = SimpleNamespace(raw=_BoundedRaw(), sh=1)
    obs = observe_exact_search(rs, {int(CKA_EC_PARAMS): b"v"}, label="bounded")
    assert obs.handles is None
    assert obs.record is not None and obs.record.outcome == "xfail"
    assert obs.record.reason == "not_operational", obs.record.summary
    assert "inconclusive" in (obs.record.summary or ""), obs.record.summary
    assert obs.record.detail is not None
    assert obs.record.detail["repeated_pages"] is False
    assert len(obs.partial) == exact.MAX_PAGES * exact.PAGE_SIZE


def test_observe_exact_search_stuck_cursor_flagged_in_detail() -> None:
    """R2B5: a bound-filling search repeating pages flags repetition."""

    class _StuckRaw:
        def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
            return int(CKR_OK)

        def C_FindObjects(  # noqa: N802
            self, _sh: int, handles: Any, _max_count: int, found_ptr: Any
        ) -> int:
            for i in range(16):
                handles[i] = 7
            ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = 16
            return int(CKR_OK)

        def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
            return int(CKR_OK)

    rs = SimpleNamespace(raw=_StuckRaw(), sh=1)
    obs = observe_exact_search(rs, {int(CKA_EC_PARAMS): b"v"}, label="stuck")
    assert obs.record is not None and obs.record.outcome == "xfail"
    assert obs.record.detail is not None
    assert obs.record.detail["repeated_pages"] is True
    assert obs.record.detail["unique_handles"] == 1


def test_adopt_derived_pub_clean_returns_candidate() -> None:
    """R2B5: a fresh handle adopts without records."""
    assert derive_case._adopt_derived_pub(55, pub_a=11, priv_a=12, label="t") == 55
    assert get_records() == []


def test_adopt_derived_pub_zero_fails_classified() -> None:
    """R3F10: a null derive output is a classified CKR_OK contradiction."""
    from _pytest.outcomes import Failed

    with pytest.raises(Failed, match="handle 0"):
        derive_case._adopt_derived_pub(0, pub_a=11, priv_a=12, label="t")
    (record,) = [rec for rec in get_records() if rec.outcome == "fail"]
    assert record.reason == "self_contradiction", record.summary
    assert record.kind == "policy", record.summary


def test_adopt_derived_pub_public_alias_fails() -> None:
    """R2B5: adopting the comparison handle fails before adoption."""
    from _pytest.outcomes import Failed

    with pytest.raises(Failed, match="vacuo-pass"):
        derive_case._adopt_derived_pub(11, pub_a=11, priv_a=12, label="t")
    (record,) = [rec for rec in get_records() if rec.outcome == "fail"]
    assert "comparison public" in (record.summary or ""), record.summary


def test_adopt_derived_pub_input_alias_fails() -> None:
    """R2B5: adopting the derive input handle fails before adoption."""
    from _pytest.outcomes import Failed

    with pytest.raises(Failed, match="vacuo-pass"):
        derive_case._adopt_derived_pub(12, pub_a=11, priv_a=12, label="t")
    (record,) = [rec for rec in get_records() if rec.outcome == "fail"]
    assert "derive input" in (record.summary or ""), record.summary


def _p256_point_bytes() -> bytes:
    """A real P-256 public point (raw uncompressed; the parser checks the curve)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


class _SepNodeRaw:
    """Full-node fake for the derived-EC separate-search node (R3F10).

    Serves keygen (101/102), PUB_KEY_FROM_PRIV_KEY derive (103),
    point/params readbacks with per-handle refusal scripting, paged
    Finds keyed by the entire template, and destroys. Search pages
    and read refusals are scripted per test.
    """

    def __init__(
        self,
        *,
        point_d: bytes,
        point_o: bytes,
        params_d: bytes,
        params_o: bytes,
        pages: dict[tuple[int, bytes], list[tuple[int, ...]]],
        point_refuse: dict[int, int] | None = None,
        params_refuse: dict[int, int] | None = None,
    ) -> None:
        self._point = {101: point_o, 103: point_d}
        self._params = {101: params_o, 103: params_d}
        self._point_refuse = dict(point_refuse or {})
        self._params_refuse = dict(params_refuse or {})
        self._pages = {key: list(value) for key, value in pages.items()}
        self._page: tuple[int, ...] = ()
        self._served = True
        self.searched: list[tuple[int, bytes]] = []
        self.reads: list[tuple[int, int]] = []
        self.destroyed: list[int] = []
        self.inits = 0

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _pub_tmpl: Any,
        _pub_count: int,
        _priv_tmpl: Any,
        _priv_count: int,
        pub_ptr: Any,
        priv_ptr: Any,
    ) -> int:
        ctypes.cast(pub_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 101
        ctypes.cast(priv_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 102
        return int(CKR_OK)

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, _base: int, _tmpl: Any, _count: int, handle_ptr: Any
    ) -> int:
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 103
        return int(CKR_OK)

    def C_GetAttributeValue(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int
    ) -> int:
        assert int(count) == 1, "node reads one attribute at a time"
        attr = int(tmpl[0].type)
        self.reads.append((int(handle), attr))
        if attr == int(CKA_EC_POINT):
            if int(handle) in self._point_refuse:
                return self._point_refuse[int(handle)]
            value = self._point[int(handle)]
        elif attr == int(CKA_EC_PARAMS):
            if int(handle) in self._params_refuse:
                return self._params_refuse[int(handle)]
            value = self._params[int(handle)]
        else:
            raise AssertionError(f"node fake serves only point/params, got {attr:#x}")
        if tmpl[0].pValue is None:
            tmpl[0].ulValueLen = len(value)
        else:
            ctypes.memmove(tmpl[0].pValue, value, len(value))
            tmpl[0].ulValueLen = len(value)
        return int(CKR_OK)

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.inits += 1
        sought = _searched_template_key(tmpl, int(count))
        self.searched.append(sought)
        assert sought in self._pages, f"search for unscripted template {sought!r}"
        assert self._pages[sought], f"no page left for {sought!r}"
        self._page = self._pages[sought].pop(0)
        self._served = False
        return int(CKR_OK)

    def C_FindObjects(  # noqa: N802
        self, _sh: int, handles: Any, _max_count: int, found_ptr: Any
    ) -> int:
        page = () if self._served else self._page
        self._served = True
        for i, handle in enumerate(page):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(page)
        return int(CKR_OK)

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        return int(CKR_OK)


def _run_sep_node(fake: _SepNodeRaw) -> None:
    rs = SimpleNamespace(
        raw=fake,
        sh=1,
        has_mechanism=lambda name: name in {"EC_KEY_PAIR_GEN", "PUB_KEY_FROM_PRIV_KEY"},
    )
    node = derive_case.TestDerivedECPublicSearch()
    node.test_derived_ec_public_search_by_separate_params_and_point(rs)


_SEP_PARAMS = b"params-separate-bytes"


def _sep_healthy_pages(point: bytes) -> dict[tuple[int, bytes], list[tuple[int, ...]]]:
    from pkcs11_check.testcases._exact_search import flip_last_byte

    return {
        (int(CKA_EC_PARAMS), _SEP_PARAMS): [(101, 103), (101, 103)],
        (int(CKA_EC_PARAMS), flip_last_byte(_SEP_PARAMS)): [()],
        (int(CKA_EC_POINT), point): [(101, 103), (101, 103)],
        (int(CKA_EC_POINT), flip_last_byte(point)): [()],
    }


def test_sep_node_healthy_passes() -> None:
    """R3F10: the driven node passes with both legs running and cleaned up."""
    point = _p256_point_bytes()
    fake = _SepNodeRaw(
        point_d=point,
        point_o=point,
        params_d=_SEP_PARAMS,
        params_o=_SEP_PARAMS,
        pages=_sep_healthy_pages(point),
    )
    assert _run_sep_node(fake) is None
    assert fake.inits == 6, fake.searched
    assert {key[0] for key in fake.searched} == {int(CKA_EC_PARAMS), int(CKA_EC_POINT)}
    assert fake.destroyed == [101, 102, 103], fake.destroyed


def test_sep_node_point_search_miss_fails() -> None:
    """R3F10: a point search hiding the derived key fails (the point leg runs)."""
    point = _p256_point_bytes()
    pages = _sep_healthy_pages(point)
    pages[(int(CKA_EC_POINT), point)] = [(101,), (101, 103)]
    fake = _SepNodeRaw(
        point_d=point,
        point_o=point,
        params_d=_SEP_PARAMS,
        params_o=_SEP_PARAMS,
        pages=pages,
    )
    with pytest.raises(Failed, match="point") as exc_info:
        _run_sep_node(fake)
    assert type(exc_info.value) is Failed, exc_info.value
    assert any(key[0] == int(CKA_EC_POINT) for key in fake.searched), fake.searched


def test_sep_node_point_refused_params_fail_wins() -> None:
    """R3F10: a refused point read voids only point legs; the params fail wins."""
    point = _p256_point_bytes()
    pages = _sep_healthy_pages(point)
    pages[(int(CKA_EC_PARAMS), _SEP_PARAMS)] = [(101,), (101, 103)]
    fake = _SepNodeRaw(
        point_d=point,
        point_o=point,
        params_d=_SEP_PARAMS,
        params_o=_SEP_PARAMS,
        pages=pages,
        point_refuse={103: int(CKR_ATTRIBUTE_SENSITIVE)},
    )
    with pytest.raises(Failed, match="params") as exc_info:
        _run_sep_node(fake)
    assert type(exc_info.value) is Failed, exc_info.value
    assert all(key[0] != int(CKA_EC_POINT) for key in fake.searched), fake.searched
    assert (103, int(CKA_EC_POINT)) in fake.reads, fake.reads


def test_sep_node_params_refused_point_fail_wins() -> None:
    """R3F10: a refused params read voids only params legs; the point fail wins."""
    point = _p256_point_bytes()
    pages = _sep_healthy_pages(point)
    pages[(int(CKA_EC_POINT), point)] = [(101,), (101, 103)]
    # The params search never runs; drop its pages so any attempt errors.
    pages = {key: value for key, value in pages.items() if key[0] != int(CKA_EC_PARAMS)}
    fake = _SepNodeRaw(
        point_d=point,
        point_o=point,
        params_d=_SEP_PARAMS,
        params_o=_SEP_PARAMS,
        pages=pages,
        params_refuse={103: int(CKR_ATTRIBUTE_SENSITIVE)},
    )
    with pytest.raises(Failed, match="point") as exc_info:
        _run_sep_node(fake)
    assert type(exc_info.value) is Failed, exc_info.value
    assert all(key[0] != int(CKA_EC_PARAMS) for key in fake.searched), fake.searched


def test_sep_node_point_mismatch_fails() -> None:
    """R3F10: derived/original point mismatch fails even with passing searches."""
    from pkcs11_check.testcases._exact_search import flip_last_byte

    point_d = _p256_point_bytes()
    point_o = _p256_point_bytes()
    pages = _sep_healthy_pages(point_d)
    pages[(int(CKA_EC_POINT), point_d)] = [(103,)]
    pages[(int(CKA_EC_POINT), flip_last_byte(point_d))] = [()]
    pages[(int(CKA_EC_POINT), point_o)] = [(101,)]
    pages[(int(CKA_EC_POINT), flip_last_byte(point_o))] = [()]
    fake = _SepNodeRaw(
        point_d=point_d,
        point_o=point_o,
        params_d=_SEP_PARAMS,
        params_o=_SEP_PARAMS,
        pages=pages,
    )
    with pytest.raises(Failed, match="does not equal"):
        _run_sep_node(fake)

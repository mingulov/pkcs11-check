"""Runtime classification meta-tests for test_session_edge_cases (Phase 4 N2).

Stale-session-handle guards check that an operation on a *closed* session
rejects. Converted from a flat ``assert rv in (CKR_SESSION_HANDLE_INVALID,
CKR_SESSION_CLOSED)`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the module performed an op on a closed session) -> ``fail``,
- ``CKR_SESSION_HANDLE_INVALID`` / ``CKR_SESSION_CLOSED`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_session_edge_cases as tse
from tests._skip_assert import assert_xfails


def _session(op_rv: int) -> SimpleNamespace:
    def _op(*_a: object, **_k: object) -> int:
        return int(op_rv)

    raw = SimpleNamespace(C_FindObjectsInit=_op, C_GenerateKey=_op)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tse, "get_pin_bytes", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tse, "login_user", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "close_session_quietly", lambda *_a, **_k: None)


def _run_find(monkeypatch: pytest.MonkeyPatch, op_rv: int) -> None:
    _patch(monkeypatch)
    tse.TestStaleSessionHandles().test_find_after_close(_session(op_rv), SimpleNamespace())


def _run_gen(monkeypatch: pytest.MonkeyPatch, op_rv: int) -> None:
    _patch(monkeypatch)
    tse.TestStaleSessionHandles().test_generate_key_after_close(_session(op_rv), SimpleNamespace())


def test_find_accepted_on_closed_session_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_find(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_find_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_find(monkeypatch, int(CKR_SESSION_HANDLE_INVALID))
    _run_find(monkeypatch, int(CKR_SESSION_CLOSED))


def test_find_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_find(monkeypatch, int(CKR_FUNCTION_FAILED))


def test_gen_accepted_on_closed_session_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_gen(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_gen_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_gen(monkeypatch, int(CKR_SESSION_HANDLE_INVALID))
    _run_gen(monkeypatch, int(CKR_SESSION_CLOSED))


def test_gen_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_gen(monkeypatch, int(CKR_FUNCTION_FAILED))


# --- C_CloseAllSessions lifecycle effects ----------------------------------
#
# The probe generates one session key under a unique exact label with explicit
# CKA_TOKEN=False/CKA_PRIVATE=False, observes C_GetSessionInfo for EVERY old
# handle (fixture session, named auxiliary session, all additional handles)
# after a CKR_OK close, reopens a session, proves it operational, and searches
# for the identical label. Canonical CKR_SESSION_HANDLE_INVALID everywhere plus
# an absent object is the only PASS; SESSION_CLOSED/another defined clean
# result is xfail; a surviving handle/object or undefined RV is fail. Every
# opened handle is closed on refusal, partial success, xfail, and fail paths.

_CLOSE_OK = int(CKR_OK)
_UNDEFINED_RV = 0x7FFFFFFF
_AUX_HANDLES = (11, 12, 13, 14)
_NEW_HANDLE = 21


class _CloseAllRaw:
    """Scriptable fake for the CloseAllSessions lifecycle path."""

    def __init__(
        self,
        *,
        close_rv: int = _CLOSE_OK,
        info_rvs: dict[int, int] | None = None,
        find_handles: tuple[int, ...] = (),
    ) -> None:
        self._close_rv = close_rv
        self._info_rvs = dict(info_rvs or {})
        self._find_handles = tuple(find_handles)
        self.info_calls: list[int] = []
        self.closed: list[int] = []
        self.find_sessions: list[int] = []

    def C_CloseAllSessions(self, _slot_id: int) -> int:  # noqa: N802
        return self._close_rv

    def C_GetSessionInfo(self, sh: int, _info: Any) -> int:  # noqa: N802
        self.info_calls.append(int(sh))
        return self._info_rvs.get(int(sh), int(CKR_SESSION_HANDLE_INVALID))

    def C_CloseSession(self, sh: int) -> int:  # noqa: N802
        self.closed.append(int(sh))
        return _CLOSE_OK

    def C_FindObjectsInit(self, sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        self.find_sessions.append(int(sh))
        return _CLOSE_OK

    def C_FindObjects(self, _sh: int, handles: Any, _max: int, found_ptr: Any) -> int:  # noqa: N802
        for index, handle in enumerate(self._find_handles):
            handles[index] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(self._find_handles)
        return _CLOSE_OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _CLOSE_OK


class _CloseAllHarness:
    """Patched environment capturing the probe's keygen/search contract."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, raw: _CloseAllRaw) -> None:
        self.raw = raw
        self.keygen_calls: list[dict[str, Any]] = []
        self.search_templates: list[dict[Any, Any]] = []
        opens = list(_AUX_HANDLES) + [_NEW_HANDLE]

        def _open_session(*_a: object, **_k: object) -> int:
            return opens.pop(0)

        def _gen_key(rs: Any, bits: int, attrs: Any = None, **kw: Any) -> int:
            self.keygen_calls.append({"bits": bits, "attrs": attrs, **kw})
            return 99

        real_template = tse.template_from_dict

        def _template(mapping: dict[Any, Any]) -> Any:
            self.search_templates.append(dict(mapping))
            return real_template(mapping)

        monkeypatch.setattr(tse, "get_pin_bytes", lambda *_a, **_k: None)
        monkeypatch.setattr(tse, "raw_open_session", _open_session)
        monkeypatch.setattr(tse, "gen_aes_key_or_xfail", _gen_key)
        monkeypatch.setattr(tse, "template_from_dict", _template)

    def run(self) -> None:
        session = SimpleNamespace(raw=self.raw, sh=1, slot_id=0)
        tse.TestCloseAllSessions().test_close_all_sessions(session, SimpleNamespace())

    @property
    def label(self) -> str:
        label = tse._CLOSE_ALL_SESSION_LABEL
        assert isinstance(label, str) and label
        return label


def _canonical_info() -> dict[int, int]:
    return {sh: int(CKR_SESSION_HANDLE_INVALID) for sh in (1, *_AUX_HANDLES)}


def _assert_fail_record(reason: str, kind: str | None) -> None:
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == reason
    assert records[0].kind == kind
    assert records[0].outcome == "fail"


def test_close_all_canonical_pass_observes_and_cleans_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    info = _canonical_info()
    info[_NEW_HANDLE] = _CLOSE_OK  # reopened session proves operational
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info))
    harness.run()
    assert get_records() == []

    # Every old handle observed: fixture session, named auxiliary, all additional.
    assert harness.raw.info_calls == [1, *_AUX_HANDLES, _NEW_HANDLE]
    # The reopened session searched the identical unique label.
    assert harness.raw.find_sessions == [_NEW_HANDLE]
    # Session key: exact label, explicit session-object template, in the aux session.
    assert harness.keygen_calls == [
        {
            "bits": 128,
            "attrs": {
                CKA_LABEL: harness.label,
                CKA_TOKEN: False,
                CKA_PRIVATE: False,
            },
            "sh": _AUX_HANDLES[0],
        }
    ]
    assert harness.search_templates == [{CKA_LABEL: harness.label}]
    # Every opened handle closed; the fixture-owned session handle never is.
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}
    assert 1 not in harness.raw.closed


def test_close_all_clean_refusal_xfails_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(close_rv=int(CKR_FUNCTION_FAILED)))
    assert_xfails(harness.run)
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_CloseAllSessions"
    assert records[0].actual_ckr == ckr_name(int(CKR_FUNCTION_FAILED))
    # No old-handle observations on the refusal path; every opened handle closed.
    assert harness.raw.info_calls == []
    assert set(harness.raw.closed) == set(_AUX_HANDLES)


def test_close_all_undefined_refusal_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(close_rv=_UNDEFINED_RV))
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "metadata")
    assert set(harness.raw.closed) == set(_AUX_HANDLES)


def test_close_all_surviving_handle_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _canonical_info()
    info[_AUX_HANDLES[1]] = _CLOSE_OK  # one old handle survives the claimed close
    info[_NEW_HANDLE] = _CLOSE_OK
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info))
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}


def test_close_all_undefined_info_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _canonical_info()
    info[_AUX_HANDLES[2]] = _UNDEFINED_RV
    info[_NEW_HANDLE] = _CLOSE_OK
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info))
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "metadata")
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}


@pytest.mark.parametrize("stale_rv", [int(CKR_SESSION_CLOSED), int(CKR_FUNCTION_FAILED)])
def test_close_all_noncanonical_clean_result_xfails(
    monkeypatch: pytest.MonkeyPatch, stale_rv: int
) -> None:
    info = _canonical_info()
    info[_AUX_HANDLES[0]] = stale_rv
    info[_NEW_HANDLE] = _CLOSE_OK
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info))
    assert_xfails(harness.run)
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].actual_ckr == ckr_name(stale_rv)
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}


def test_close_all_surviving_object_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _canonical_info()
    info[_NEW_HANDLE] = _CLOSE_OK
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info, find_handles=(99,)))
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "lifecycle"
    assert harness.search_templates == [{CKA_LABEL: harness.label}]
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}


def test_close_all_broken_new_session_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reopened session that cannot prove itself operational contradicts the close."""
    info = _canonical_info()
    info[_NEW_HANDLE] = int(CKR_SESSION_HANDLE_INVALID)
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=info))
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert set(harness.raw.closed) == {*_AUX_HANDLES, _NEW_HANDLE}


def test_close_all_reopen_failure_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """C_OpenSession failing after a claimed CloseAllSessions success is fail."""
    harness = _CloseAllHarness(monkeypatch, _CloseAllRaw(info_rvs=_canonical_info()))
    opens = list(_AUX_HANDLES)

    def _open_then_fail(*_a: object, **_k: object) -> int:
        if opens:
            return opens.pop(0)
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", 0x06)

    monkeypatch.setattr(tse, "raw_open_session", _open_then_fail)
    with pytest.raises(Failed) as ei:
        harness.run()
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert set(harness.raw.closed) == set(_AUX_HANDLES)

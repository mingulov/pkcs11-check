"""Session edge-case tests - stale handles, CloseAllSessions, session issue regressions.

References: rep11.md Iteration 2.
"""

from __future__ import annotations

import uuid
from ctypes import byref
from dataclasses import dataclass, field
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import fail_as, record_as, xfail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_ULONG,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_WRAP,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_SESSION_HANDLE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    get_pin_bytes,
)

pytestmark = pytest.mark.security

_CLOSE_ALL_SESSION_LABEL = "pkcs11-check-close-all-sessions"

_CLOSE_ALL_REFUSED_LABEL = "C_CloseAllSessions:close refused"
_CLOSE_ALL_EFFECTS_LABEL = "C_CloseAllSessions:lifecycle effects"

_REFUSAL_CLEAN = "refusal_clean"
_REFUSAL_UNDEFINED = "refusal_undefined"
_INFO_UNDEFINED = "info_undefined"
_HANDLE_SURVIVED = "handle_survived"
_STAGING_FAILED = "staging_failed"
_OBJECT_SURVIVED = "object_survived"
_INFO_NONCANONICAL = "info_noncanonical"


@dataclass(frozen=True)
class _CloseAllPending:
    """A decided-but-unraised CloseAllSessions verdict retained across cleanup.

    The probe computes it from the observations, closes every handle it
    opened, then raises it — cleanup completes before the classification is
    emitted, so teardown can never erase the primary evidence.
    """

    tag: str
    label: str
    summary: str
    rv: int = 0
    detail: dict[str, Any] = field(default_factory=dict)


def _session_info(raw: Any, session: int) -> tuple[int, CK_SESSION_INFO]:
    """Return the (CK_RV, info) of C_GetSessionInfo without asserting on it."""
    info = CK_SESSION_INFO()
    return int(raw.C_GetSessionInfo(session, byref(info))), info


def _session_info_rv(raw: Any, session: int) -> int:
    """Return the raw CK_RV of C_GetSessionInfo without asserting on it."""
    rv, _ = _session_info(raw, session)
    return rv


def _close_all_refusal_pending(rv: int) -> _CloseAllPending:
    """Decide a refused C_CloseAllSessions: defined/vendor clean refusal is
    exact-RV ``not_operational`` xfail; undefined RV is metadata fail."""
    label = _CLOSE_ALL_REFUSED_LABEL
    detail = {"close_rv": ckr_name(rv)}
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        return _CloseAllPending(
            tag=_REFUSAL_CLEAN,
            label=label,
            summary=(
                f"{label}: C_CloseAllSessions is not operational; rejected with {ckr_name(rv)}"
            ),
            rv=rv,
            detail=detail,
        )
    return _CloseAllPending(
        tag=_REFUSAL_UNDEFINED,
        label=label,
        summary=f"{label}: C_CloseAllSessions returned undefined CK_RV {ckr_name(rv)}",
        rv=rv,
        detail=detail,
    )


def _close_all_effects_pending(
    observations: list[tuple[int, int]],
    found: list[int],
    staging: tuple[str, int] | None,
) -> _CloseAllPending | None:
    """Decide the post-close verdict from the retained observations.

    Canonical CKR_SESSION_HANDLE_INVALID for every old handle plus an absent
    session object is the only pass. A surviving handle, a surviving object,
    an unrestorable session namespace (``staging``), or an undefined RV is
    fail; CKR_SESSION_CLOSED or another defined clean result is xfail.
    """
    label = _CLOSE_ALL_EFFECTS_LABEL
    detail = {
        "session_observations": [
            {"handle": handle, "rv": ckr_name(rv)} for handle, rv in observations
        ],
        "object_search_label": _CLOSE_ALL_SESSION_LABEL,
        "object_search_hits": list(found),
    }
    for handle, rv in observations:
        if rv != CKR_OK and not is_standard_ckr(rv) and not is_vendor_defined_ckr(rv):
            return _CloseAllPending(
                tag=_INFO_UNDEFINED,
                label=label,
                summary=(
                    f"{label}: old session handle {handle} returned undefined "
                    f"CK_RV {ckr_name(rv)} after C_CloseAllSessions claimed CKR_OK"
                ),
                rv=rv,
                detail=detail,
            )
    for handle, rv in observations:
        if rv == CKR_OK:
            return _CloseAllPending(
                tag=_HANDLE_SURVIVED,
                label=label,
                summary=(
                    f"{label}: old session handle {handle} survived C_CloseAllSessions success"
                ),
                rv=rv,
                detail=detail,
            )
    if staging is not None:
        operation, rv = staging
        return _CloseAllPending(
            tag=_STAGING_FAILED,
            label=label,
            summary=(
                f"{label}: C_CloseAllSessions claimed CKR_OK but the "
                f"follow-up {operation} returned {ckr_name(rv)}"
            ),
            rv=rv,
            detail=detail,
        )
    if found:
        return _CloseAllPending(
            tag=_OBJECT_SURVIVED,
            label=label,
            summary=(
                f"{label}: C_CloseAllSessions claimed CKR_OK but the session "
                f"object {_CLOSE_ALL_SESSION_LABEL!r} survived"
            ),
            detail=detail,
        )
    for handle, rv in observations:
        if rv != CKR_SESSION_HANDLE_INVALID:
            return _CloseAllPending(
                tag=_INFO_NONCANONICAL,
                label=label,
                summary=(
                    f"{label}: old session handle {handle} returned "
                    f"{ckr_name(rv)} instead of CKR_SESSION_HANDLE_INVALID"
                ),
                rv=rv,
                detail=detail,
            )
    return None


def _xfail_close_all(*, label: str, actual: int, summary: str, detail: dict[str, Any]) -> NoReturn:
    xfail_as(
        "not_operational",
        label=label,
        operation="C_CloseAllSessions",
        expected=CKR_OK,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _fail_close_all(
    *, kind: str, label: str, actual: int, summary: str, detail: dict[str, Any]
) -> NoReturn:
    fail_as(
        "self_contradiction",
        kind=kind,
        label=label,
        operation="C_CloseAllSessions",
        expected=CKR_OK,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _fail_session_info(
    *, kind: str, label: str, actual: int, summary: str, detail: dict[str, Any]
) -> NoReturn:
    fail_as(
        "self_contradiction",
        kind=kind,
        label=label,
        operation="C_GetSessionInfo",
        expected=CKR_SESSION_HANDLE_INVALID,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _xfail_session_info(
    *, label: str, actual: int, summary: str, detail: dict[str, Any]
) -> NoReturn:
    xfail_as(
        "not_operational",
        label=label,
        operation="C_GetSessionInfo",
        expected=CKR_SESSION_HANDLE_INVALID,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _fail_object_survived(*, label: str, summary: str, detail: dict[str, Any]) -> NoReturn:
    fail_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation="C_FindObjects",
        summary=summary,
        detail=detail,
    )


def _raise_close_all(pending: _CloseAllPending) -> NoReturn:
    """Emit the retained verdict after cleanup with literal attribution."""
    tag = pending.tag
    if tag == _REFUSAL_CLEAN:
        _xfail_close_all(
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    elif tag == _REFUSAL_UNDEFINED:
        _fail_close_all(
            kind="metadata",
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    elif tag == _INFO_UNDEFINED:
        _fail_session_info(
            kind="metadata",
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    elif tag == _HANDLE_SURVIVED:
        _fail_session_info(
            kind="lifecycle",
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    elif tag == _STAGING_FAILED:
        _fail_close_all(
            kind="lifecycle",
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    elif tag == _OBJECT_SURVIVED:
        _fail_object_survived(label=pending.label, summary=pending.summary, detail=pending.detail)
    elif tag == _INFO_NONCANONICAL:
        _xfail_session_info(
            label=pending.label,
            actual=pending.rv,
            summary=pending.summary,
            detail=pending.detail,
        )
    else:
        raise AssertionError(f"unknown CloseAll verdict tag: {tag!r}")


def _reopen_and_search(
    rs: Any, slot_id: int, flags: int, pin_bytes: bytes | None
) -> tuple[int, tuple[str, int] | None, list[int]]:
    """Reopen a session, prove it operational, and search the identical label.

    Provider failures never raise here: they come back as ``(operation, rv)``
    staging data so the caller can clean up before classifying.
    """
    try:
        new_sh = raw_open_session(rs.raw, slot_id, flags)
    except CkrAssertionError as exc:
        return 0, ("C_OpenSession", exc.rv), []
    if pin_bytes is not None:
        try:
            login_user(rs.raw, new_sh, CKU_USER, pin_bytes)
        except CkrAssertionError as exc:
            return new_sh, ("C_Login", exc.rv), []
    proof_rv = _session_info_rv(rs.raw, new_sh)
    if proof_rv != CKR_OK:
        return new_sh, ("C_GetSessionInfo", proof_rv), []
    try:
        found = find_objects(
            rs.raw, new_sh, template_from_dict({CKA_LABEL: _CLOSE_ALL_SESSION_LABEL})
        )
    except CkrAssertionError as exc:
        return new_sh, ("C_FindObjects", exc.rv), []
    return new_sh, None, found


# --- Stale-search oracles (QC6c) -------------------------------------------
#
# A session the test itself closed is stale from that point on: under v3.2
# S5.1.2 an operation naming the closed handle must refuse with the canonical
# CKR_SESSION_HANDLE_INVALID. CKR_SESSION_CLOSED (the closed-during
# notification) is an alternate clean refusal recorded as xfail with the
# original RV preserved; acceptance (CKR_OK) is a fail under the applicable
# effect oracle. Closure itself is always proven with an explicit CKR_OK --
# no quiet close on a stale-premise path.

_SEARCH_CLOSE_LABEL = "C_FindObjects:stale search after C_CloseSession"
_SEARCH_CLOSE_ALL_LABEL = "C_FindObjects:stale search after C_CloseAllSessions"
_SEARCH_REUSE_LABEL = "C_FindObjects:search state across handle reuse"

_STALE_SEARCH_LABEL = "pkcs11-check-stale-search"
_SEARCH_REUSE_OBJECT_LABEL = "pkcs11-check-search-handle-reuse"
_STALE_SEARCH_MAX_OBJECTS = 8

# Pre-call fill for stale-search output buffers. A slot still holding this
# value after C_FindObjects returned proves the provider left it untouched;
# 0 is the null handle (no object). Delivery is proven only by a slot that
# is neither (see _observe_stale_find).
_STALE_SEARCH_SENTINEL = 0xA5A5A5A5

_FIND_ACCEPTED = "find_accepted"
_FIND_DELIVERED_ON_ERROR = "find_delivered_on_error"
_FIND_UNDEFINED = "find_undefined"
_FINAL_ACCEPTED = "final_accepted"
_FINAL_UNDEFINED = "final_undefined"
_SEARCH_ALTERNATE = "search_alternate"


def _fail_stale_search(
    *,
    reason: str,
    kind: str,
    label: str,
    operation: str,
    expected: object,
    actual: object,
    summary: str,
    detail: dict[str, Any],
) -> NoReturn:
    fail_as(
        reason,
        kind=kind,
        label=label,
        operation=operation,
        expected=expected,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _xfail_stale_search(
    *, label: str, operation: str, actual: int, summary: str, detail: dict[str, Any]
) -> NoReturn:
    xfail_as(
        "nonspec_reject",
        label=label,
        operation=operation,
        expected=CKR_SESSION_HANDLE_INVALID,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _xfail_stale_staging(
    *,
    label: str,
    operation: str,
    expected: object,
    actual: object,
    summary: str,
    detail: dict[str, Any],
) -> NoReturn:
    xfail_as(
        "not_operational",
        label=label,
        operation=operation,
        expected=expected,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _record_fresh_final(rv: int, *, label: str, detail: dict[str, Any]) -> None:
    """Record a fresh-search Final defect without terminating (P5).

    The fresh Find observations keep their own verdicts; this only keeps
    a bad terminator on a live session from passing silently. Clean
    refusals record the staging not_operational xfail shape; an
    undefined RV records the metadata FAIL shape.
    """
    summary = f"{label}: fresh C_FindObjectsFinal on the reopened session returned {ckr_name(rv)}"
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        record_as(
            "not_operational",
            label=label,
            operation="C_FindObjectsFinal",
            expected=CKR_OK,
            actual=rv,
            summary=summary,
            detail=detail,
        )
        return
    record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_FindObjectsFinal",
        expected=CKR_OK,
        actual=rv,
        summary=f"{summary} (return-value contract violation)",
        detail=detail,
    )


def _raise_stale_staging(
    *,
    label: str,
    operation: str,
    rv: int,
    expected: object,
    actual: object,
    summary: str,
    detail: dict[str, Any],
) -> NoReturn:
    """Raise a staging premise that never established: defined clean RVs xfail.

    A clean refusal (HOST_MEMORY, FUNCTION_FAILED, even after earlier success)
    never claimed the premise, so no contradiction is proven. Only an
    undefined RV fails (metadata). Callers stop the dependent probe.
    """
    if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
        _xfail_stale_staging(
            label=label,
            operation=operation,
            expected=expected,
            actual=actual,
            summary=summary,
            detail=detail,
        )
    _fail_stale_search(
        reason="self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        expected=expected,
        actual=actual,
        summary=summary,
        detail=detail,
    )


def _observe_stale_find(
    *, rv_find: int, raw_count: int, buf: Any, capacity: int
) -> tuple[int, list[int], bool]:
    """Observe a stale Find's output: raw count, bounded buffer, proven delivery.

    C_FindObjects supplies no zero-on-error guarantee for host output memory,
    so a bare nonzero count proves nothing. Delivery is proven only when the
    provider both claims objects (0 < count <= capacity) on a defined error
    leg AND at least one claimed slot holds a non-trivial handle (neither the
    pre-call sentinel nor the null handle 0). The buffer snapshot is bounded
    to the claimed prefix so a malformed count can never over-read.
    """
    claim_len = min(max(raw_count, 0), capacity)
    buffer_head = [int(buf[i]) for i in range(claim_len)]
    proven = (
        rv_find != CKR_OK
        and (is_standard_ckr(rv_find) or is_vendor_defined_ckr(rv_find))
        and 0 < raw_count <= capacity
        and any(h != _STALE_SEARCH_SENTINEL and h != 0 for h in buffer_head)
    )
    return raw_count, buffer_head, proven


def _decide_stale_search(
    *, rv_find: int, delivered_proven: bool, rv_final: int
) -> tuple[str, int, str] | None:
    """Decide the stale-search verdict from the retained observations.

    The Find leg is adjudicated before the Final leg. Either leg accepting
    (CKR_OK), the Find leg provably delivering objects while refusing (see
    _observe_stale_find), or either leg returning an undefined RV is fail;
    canonical CKR_SESSION_HANDLE_INVALID on both legs is the only pass; any
    other defined clean refusal is xfail. Returns ``(tag, rv, operation)`` or
    ``None`` for the canonical pass.
    """
    if rv_find == CKR_OK:
        return (_FIND_ACCEPTED, rv_find, "C_FindObjects")
    if not is_standard_ckr(rv_find) and not is_vendor_defined_ckr(rv_find):
        return (_FIND_UNDEFINED, rv_find, "C_FindObjects")
    if delivered_proven:
        return (_FIND_DELIVERED_ON_ERROR, rv_find, "C_FindObjects")
    if rv_final == CKR_OK:
        return (_FINAL_ACCEPTED, rv_final, "C_FindObjectsFinal")
    if not is_standard_ckr(rv_final) and not is_vendor_defined_ckr(rv_final):
        return (_FINAL_UNDEFINED, rv_final, "C_FindObjectsFinal")
    if rv_find == CKR_SESSION_HANDLE_INVALID and rv_final == CKR_SESSION_HANDLE_INVALID:
        return None
    if rv_find != CKR_SESSION_HANDLE_INVALID:
        return (_SEARCH_ALTERNATE, rv_find, "C_FindObjects")
    return (_SEARCH_ALTERNATE, rv_final, "C_FindObjectsFinal")


def _raise_stale_search(
    *,
    label: str,
    tag: str,
    rv: int,
    operation: str,
    delivered: int,
    rv_find: int,
    rv_final: int,
    buffer: list[int] | None = None,
) -> NoReturn:
    """Emit the retained stale-search verdict with literal attribution."""
    both = {"find_rv": ckr_name(rv_find), "final_rv": ckr_name(rv_final)}
    find_detail: dict[str, Any] = {"delivered": delivered, **both}
    if buffer is not None:
        find_detail["buffer"] = list(buffer)
    if tag == _FIND_ACCEPTED:
        _fail_stale_search(
            reason="accepted_invalid",
            kind="lifecycle",
            label=label,
            operation=operation,
            expected=CKR_SESSION_HANDLE_INVALID,
            actual=rv,
            summary=(
                f"{label}: C_FindObjects returned CKR_OK on the closed session "
                f"(delivered {delivered} objects) instead of refusing; the active "
                "search survived the close"
            ),
            detail=dict(find_detail),
        )
    elif tag == _FIND_DELIVERED_ON_ERROR:
        _fail_stale_search(
            reason="self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            expected=CKR_SESSION_HANDLE_INVALID,
            actual=rv,
            summary=(
                f"{label}: C_FindObjects refused with {ckr_name(rv)} but delivered "
                f"{delivered} objects"
            ),
            detail=dict(find_detail),
        )
    elif tag == _FIND_UNDEFINED:
        _fail_stale_search(
            reason="self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            expected=CKR_SESSION_HANDLE_INVALID,
            actual=rv,
            summary=(
                f"{label}: {operation} returned undefined CK_RV {ckr_name(rv)} "
                "on the closed session"
            ),
            detail=dict(find_detail),
        )
    elif tag == _FINAL_UNDEFINED:
        _fail_stale_search(
            reason="self_contradiction",
            kind="metadata",
            label=label,
            operation=operation,
            expected=CKR_SESSION_HANDLE_INVALID,
            actual=rv,
            summary=(
                f"{label}: {operation} returned undefined CK_RV {ckr_name(rv)} "
                "on the closed session"
            ),
            detail=dict(find_detail),
        )
    elif tag == _FINAL_ACCEPTED:
        _fail_stale_search(
            reason="accepted_invalid",
            kind="lifecycle",
            label=label,
            operation=operation,
            expected=CKR_SESSION_HANDLE_INVALID,
            actual=rv,
            summary=(
                f"{label}: C_FindObjectsFinal returned CKR_OK on the closed session "
                "instead of refusing; search state was carried across the close"
            ),
            detail=dict(find_detail),
        )
    elif tag == _SEARCH_ALTERNATE:
        _xfail_stale_search(
            label=label,
            operation=operation,
            actual=rv,
            summary=(
                f"{label}: {operation} refused with {ckr_name(rv)} instead of "
                "CKR_SESSION_HANDLE_INVALID"
            ),
            detail=dict(find_detail),
        )
    else:
        raise AssertionError(f"unknown stale-search verdict tag: {tag!r}")


def _raise_unproven_close(*, label: str, handle: int, close_rv: int) -> NoReturn:
    """Raise a stale premise whose invalidating close did not claim CKR_OK.

    Honest refusals xfail (not_operational, original RV); only an undefined
    RV fails (metadata). Callers best-effort-clean the still-live handle
    before raising and stop the dependent probe.
    """
    _raise_stale_staging(
        label=label,
        operation="C_CloseSession",
        rv=close_rv,
        expected=CKR_OK,
        actual=close_rv,
        summary=(
            f"{label}: C_CloseSession returned {ckr_name(close_rv)} instead of "
            "CKR_OK, so the session was never proven closed and the stale "
            "premise is unproven"
        ),
        detail={"handle": handle},
    )


class TestStaleSessionHandles:
    """Reuse closed session handle - must get error, not crash (task 7.7)."""

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_find_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_FindObjects on closed session must fail cleanly."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        # Prove the session closed: the stale premise below is only valid on
        # an explicit CKR_OK (v3.2 S5.1.2 invalid-before-invocation).
        label = "C_FindObjectsInit on closed session"
        close_rv = int(rs.raw.C_CloseSession(test_sh))
        if close_rv != CKR_OK:
            close_session_quietly(rs.raw, test_sh)
            _raise_unproven_close(label=label, handle=test_sh, close_rv=close_rv)

        # Try to use the closed session -- must reject, not crash or succeed.
        # Canonical CKR_SESSION_HANDLE_INVALID passes; CKR_SESSION_CLOSED is
        # an alternate clean refusal recorded as xfail with the original RV.
        rv = rs.raw.C_FindObjectsInit(test_sh, None, 0)
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID,),
            label=label,
        )

    def test_generate_key_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_GenerateKey on closed session must fail cleanly."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        # Prove the session closed: the stale premise below is only valid on
        # an explicit CKR_OK (v3.2 S5.1.2 invalid-before-invocation).
        label = "C_GenerateKey on closed session"
        close_rv = int(rs.raw.C_CloseSession(test_sh))
        if close_rv != CKR_OK:
            close_session_quietly(rs.raw, test_sh)
            _raise_unproven_close(label=label, handle=test_sh, close_rv=close_rv)

        # Try to generate a key on the closed session
        from pkcs11_check.raw.pack import attr_ulong, template

        tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
        mech = mech_simple(CKM_AES_KEY_GEN)
        key_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(test_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID,),
            label=label,
        )


class TestActiveSearchInvalidation:
    """Active-search invalidation across session close (QC6c).

    Separate from ``TestCloseAllSessions``: these oracles start a real
    ``C_FindObjectsInit`` search, invalidate the session, then drive the
    stale handle through the rest of the search lifecycle.
    """

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_find_and_final_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Find/Final on a session closed mid-search must refuse with effects pinned."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        label = _SEARCH_CLOSE_LABEL
        tmpl = template_from_dict({CKA_LABEL: _STALE_SEARCH_LABEL})
        rv_init = int(rs.raw.C_FindObjectsInit(test_sh, tmpl.ptr, tmpl.count))
        if rv_init != CKR_OK:
            close_session_quietly(rs.raw, test_sh)
            _raise_stale_staging(
                label=label,
                operation="C_FindObjectsInit",
                rv=rv_init,
                expected=CKR_OK,
                actual=rv_init,
                summary=(
                    f"{label}: C_FindObjectsInit returned {ckr_name(rv_init)} on "
                    "the live session, so no active search was ever staged"
                ),
                detail={"handle": test_sh},
            )

        close_rv = int(rs.raw.C_CloseSession(test_sh))
        if close_rv != CKR_OK:
            close_session_quietly(rs.raw, test_sh)
            _raise_unproven_close(label=label, handle=test_sh, close_rv=close_rv)

        # Both stale legs are observed before any verdict is emitted, so one
        # alternate refusal cannot hide the other leg's acceptance.
        found = CK_ULONG(0)
        buf = (CK_OBJECT_HANDLE * _STALE_SEARCH_MAX_OBJECTS)()
        for i in range(_STALE_SEARCH_MAX_OBJECTS):
            buf[i] = _STALE_SEARCH_SENTINEL
        rv_find = int(rs.raw.C_FindObjects(test_sh, buf, _STALE_SEARCH_MAX_OBJECTS, byref(found)))
        rv_final = int(rs.raw.C_FindObjectsFinal(test_sh))
        delivered, buffer_head, proven = _observe_stale_find(
            rv_find=rv_find,
            raw_count=int(found.value),
            buf=buf,
            capacity=_STALE_SEARCH_MAX_OBJECTS,
        )
        decision = _decide_stale_search(rv_find=rv_find, delivered_proven=proven, rv_final=rv_final)
        if decision is not None:
            tag, rv, operation = decision
            _raise_stale_search(
                label=label,
                tag=tag,
                rv=rv,
                operation=operation,
                delivered=delivered,
                rv_find=rv_find,
                rv_final=rv_final,
                buffer=buffer_head,
            )

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_find_and_final_after_close_all(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Find/Final after C_CloseAllSessions must refuse with effects pinned."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        label = _SEARCH_CLOSE_ALL_LABEL
        tmpl = template_from_dict({CKA_LABEL: _STALE_SEARCH_LABEL})
        rv_init = int(rs.raw.C_FindObjectsInit(test_sh, tmpl.ptr, tmpl.count))
        if rv_init != CKR_OK:
            close_session_quietly(rs.raw, test_sh)
            _raise_stale_staging(
                label=label,
                operation="C_FindObjectsInit",
                rv=rv_init,
                expected=CKR_OK,
                actual=rv_init,
                summary=(
                    f"{label}: C_FindObjectsInit returned {ckr_name(rv_init)} on "
                    "the live session, so no active search was ever staged"
                ),
                detail={"handle": test_sh},
            )

        refusal: _CloseAllPending | None = None
        decision: tuple[str, int, str] | None = None
        rv_find = int(CKR_OK)
        rv_final = int(CKR_OK)
        delivered = 0
        buffer_head: list[int] = []
        try:
            rv_close = int(rs.raw.C_CloseAllSessions(rs.slot_id))
            if rv_close != CKR_OK:
                refusal = _close_all_refusal_pending(rv_close)
            else:
                found = CK_ULONG(0)
                buf = (CK_OBJECT_HANDLE * _STALE_SEARCH_MAX_OBJECTS)()
                for i in range(_STALE_SEARCH_MAX_OBJECTS):
                    buf[i] = _STALE_SEARCH_SENTINEL
                rv_find = int(
                    rs.raw.C_FindObjects(test_sh, buf, _STALE_SEARCH_MAX_OBJECTS, byref(found))
                )
                rv_final = int(rs.raw.C_FindObjectsFinal(test_sh))
                delivered, buffer_head, proven = _observe_stale_find(
                    rv_find=rv_find,
                    raw_count=int(found.value),
                    buf=buf,
                    capacity=_STALE_SEARCH_MAX_OBJECTS,
                )
                decision = _decide_stale_search(
                    rv_find=rv_find, delivered_proven=proven, rv_final=rv_final
                )
        finally:
            close_session_quietly(rs.raw, test_sh)
        if refusal is not None:
            _raise_close_all(refusal)
        if decision is not None:
            tag, rv, operation = decision
            _raise_stale_search(
                label=label,
                tag=tag,
                rv=rv,
                operation=operation,
                delivered=delivered,
                rv_find=rv_find,
                rv_final=rv_final,
                buffer=buffer_head,
            )

    def test_search_state_not_resurrected_on_handle_reuse(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """A fresh search after close + reopen must behave as a fresh search.

        The reopened session keeps temporal identity: even when the token
        reissues the closed session's integer, the new session is live and
        its search must not resurrect the former session's results.

        The staged object uses a per-run unique label, so a pre-existing
        same-label token object can never false-positive the premise, and
        only the probe-owned staged handle can fail. A fresh hit on the
        staged handle is disambiguated by an independent liveness probe
        (C_DestroyObject): a live object is persistence (object-lifetime,
        QC9b territory), a gone object behind a returned handle is true
        search-state resurrection (the QC6c property, proven independent of
        destruction). Non-probe-owned hits are unrelated and pass.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = _SEARCH_REUSE_LABEL
        search_label = f"{_SEARCH_REUSE_OBJECT_LABEL}-{uuid.uuid4().hex[:8]}"
        capacity = _STALE_SEARCH_MAX_OBJECTS
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        s1_live = True
        key: int | None = None
        staged = 0
        try:
            if pin_bytes is not None:
                login_user(rs.raw, s1, CKU_USER, pin_bytes)

            key = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_LABEL: search_label,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                },
                sh=s1,
            )
            staged = key
            tmpl = template_from_dict({CKA_LABEL: search_label})
            rv_init = int(rs.raw.C_FindObjectsInit(s1, tmpl.ptr, tmpl.count))
            if rv_init != CKR_OK:
                _raise_stale_staging(
                    label=label,
                    operation="C_FindObjectsInit",
                    rv=rv_init,
                    expected=CKR_OK,
                    actual=rv_init,
                    summary=(
                        f"{label}: pre-close C_FindObjectsInit returned "
                        f"{ckr_name(rv_init)}, so the resurrection premise is unproven"
                    ),
                    detail={"handle": s1, "staged_handle": key},
                )

            pre_count = CK_ULONG(0)
            pre_buf = (CK_OBJECT_HANDLE * capacity)()
            rv_pre = int(rs.raw.C_FindObjects(s1, pre_buf, capacity, byref(pre_count)))
            pre_hits: list[int] = []
            if rv_pre == CKR_OK:
                raw_pre = int(pre_count.value)
                if raw_pre > capacity:
                    buffer_obs = [int(pre_buf[i]) for i in range(capacity)]
                    _fail_stale_search(
                        reason="self_contradiction",
                        kind="metadata",
                        label=label,
                        operation="C_FindObjects",
                        expected=(f"find count <= {capacity}",),
                        actual=f"find count {raw_pre}",
                        summary=(
                            f"{label}: pre-close C_FindObjects claimed CKR_OK with "
                            f"count {raw_pre} on a {capacity}-element buffer"
                        ),
                        detail={
                            "handle": s1,
                            "staged_handle": key,
                            "count": raw_pre,
                            "capacity": capacity,
                            "buffer": buffer_obs,
                        },
                    )
                pre_hits = [int(pre_buf[i]) for i in range(raw_pre)]
            if rv_pre != CKR_OK or key not in pre_hits:
                _raise_stale_staging(
                    label=label,
                    operation="C_FindObjects",
                    rv=rv_pre,
                    expected=CKR_OK,
                    actual=rv_pre,
                    summary=(
                        f"{label}: pre-close search returned {ckr_name(rv_pre)} with "
                        f"hits {pre_hits} instead of the staged object {key}, so the "
                        "resurrection premise is unproven"
                    ),
                    detail={
                        "handle": s1,
                        "staged_handle": key,
                        "hits": pre_hits,
                        "expectation": "pre-close search returns the staged object",
                    },
                )

            close_rv = int(rs.raw.C_CloseSession(s1))
            if close_rv != CKR_OK:
                _raise_unproven_close(label=label, handle=s1, close_rv=close_rv)

            # Proven closed: release s1 ownership before opening s2 so a
            # numerically reused handle can never cause stale cleanup. The
            # close destroyed s1's session objects; never touch key via s1.
            s1_live = False
            key = None

            try:
                s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            except CkrAssertionError as exc:
                _raise_stale_staging(
                    label=label,
                    operation="C_OpenSession",
                    rv=exc.rv,
                    expected=CKR_OK,
                    actual=exc.rv,
                    summary=(
                        f"{label}: reopening a session after the proven close "
                        f"returned {ckr_name(exc.rv)}, so no fresh search can be staged"
                    ),
                    detail={"handle": s1},
                )
            try:
                proof_rv = _session_info_rv(rs.raw, s2)
                if proof_rv != CKR_OK:
                    _raise_stale_staging(
                        label=label,
                        operation="C_GetSessionInfo",
                        rv=proof_rv,
                        expected=CKR_OK,
                        actual=proof_rv,
                        summary=(
                            f"{label}: reopened session {s2} is unusable "
                            f"({ckr_name(proof_rv)}), so no fresh search can be staged"
                        ),
                        detail={"handle": s2},
                    )
                rv_fresh_init = int(rs.raw.C_FindObjectsInit(s2, tmpl.ptr, tmpl.count))
                if rv_fresh_init != CKR_OK:
                    _raise_stale_staging(
                        label=label,
                        operation="C_FindObjectsInit",
                        rv=rv_fresh_init,
                        expected=CKR_OK,
                        actual=rv_fresh_init,
                        summary=(
                            f"{label}: fresh C_FindObjectsInit on reopened session "
                            f"{s2} returned {ckr_name(rv_fresh_init)}"
                        ),
                        detail={"handle": s2},
                    )
                fresh_count = CK_ULONG(0)
                fresh_buf = (CK_OBJECT_HANDLE * capacity)()
                rv_fresh = int(rs.raw.C_FindObjects(s2, fresh_buf, capacity, byref(fresh_count)))
                if rv_fresh != CKR_OK:
                    _raise_stale_staging(
                        label=label,
                        operation="C_FindObjects",
                        rv=rv_fresh,
                        expected=CKR_OK,
                        actual=rv_fresh,
                        summary=(
                            f"{label}: fresh C_FindObjects on reopened session {s2} "
                            f"returned {ckr_name(rv_fresh)}"
                        ),
                        detail={"handle": s2},
                    )
                raw_fresh = int(fresh_count.value)
                if raw_fresh > capacity:
                    buffer_obs = [int(fresh_buf[i]) for i in range(capacity)]
                    _fail_stale_search(
                        reason="self_contradiction",
                        kind="metadata",
                        label=label,
                        operation="C_FindObjects",
                        expected=(f"find count <= {capacity}",),
                        actual=f"find count {raw_fresh}",
                        summary=(
                            f"{label}: fresh C_FindObjects claimed CKR_OK with "
                            f"count {raw_fresh} on a {capacity}-element buffer"
                        ),
                        detail={
                            "stale_handle": s1,
                            "fresh_handle": s2,
                            "staged_handle": staged,
                            "count": raw_fresh,
                            "capacity": capacity,
                            "buffer": buffer_obs,
                        },
                    )
                found = [int(fresh_buf[i]) for i in range(raw_fresh)]
                # Release the fresh search. The terminator result is
                # recorded without terminating (P5): the Find verdicts
                # below are unchanged, but a bad Final is never silent.
                rv_fresh_final = int(rs.raw.C_FindObjectsFinal(s2))
                if rv_fresh_final != CKR_OK:
                    _record_fresh_final(
                        rv_fresh_final,
                        label=label,
                        detail={
                            "stale_handle": s1,
                            "fresh_handle": s2,
                            "staged_handle": staged,
                            "final_rv": ckr_name(rv_fresh_final),
                        },
                    )
                if staged in found:
                    liveness_rv = int(rs.raw.C_DestroyObject(s2, staged))
                    if liveness_rv == CKR_OK:
                        _fail_stale_search(
                            reason="self_contradiction",
                            kind="lifecycle",
                            label=label,
                            operation="C_CloseSession",
                            expected=("session object destroyed by C_CloseSession",),
                            actual=f"surviving object {staged}",
                            summary=(
                                f"{label}: staged session object {staged} survived "
                                f"C_CloseSession({s1}) and is still live on reopened "
                                f"session {s2} (object-lifetime persistence, QC9b "
                                "territory; not resurrected search state)"
                            ),
                            detail={
                                "stale_handle": s1,
                                "fresh_handle": s2,
                                "handle_reused": s2 == s1,
                                "staged_handle": staged,
                                "found": found,
                                "liveness_rv": ckr_name(liveness_rv),
                            },
                        )
                    if liveness_rv == CKR_OBJECT_HANDLE_INVALID:
                        _fail_stale_search(
                            reason="self_contradiction",
                            kind="lifecycle",
                            label=label,
                            operation="C_FindObjects",
                            expected=("fresh search finds no trace of the closed session",),
                            actual=f"resurrected {found}",
                            summary=(
                                f"{label}: fresh search on reopened session {s2} "
                                f"resurrected {found} from closed session {s1}"
                            ),
                            detail={
                                "stale_handle": s1,
                                "fresh_handle": s2,
                                "handle_reused": s2 == s1,
                                "staged_handle": staged,
                                "found": found,
                                "liveness_rv": ckr_name(liveness_rv),
                            },
                        )
                    _raise_stale_staging(
                        label=label,
                        operation="C_DestroyObject",
                        rv=liveness_rv,
                        expected=(CKR_OK, CKR_OBJECT_HANDLE_INVALID),
                        actual=liveness_rv,
                        summary=(
                            f"{label}: liveness probe for staged object {staged} "
                            f"returned {ckr_name(liveness_rv)}, so persistence and "
                            "resurrection cannot be distinguished"
                        ),
                        detail={
                            "stale_handle": s1,
                            "fresh_handle": s2,
                            "staged_handle": staged,
                            "found": found,
                        },
                    )
            finally:
                close_session_quietly(rs.raw, s2)
        finally:
            if s1_live:
                if key is not None:
                    destroy_quietly(rs.raw, s1, key)
                close_session_quietly(rs.raw, s1)


class TestCloseAllSessions:
    """C_CloseAllSessions behavior (task 7.8)."""

    def test_close_all_sessions(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_CloseAllSessions must invalidate every old handle and session object.

        One session key is generated under a unique exact label with explicit
        CKA_TOKEN=False/CKA_PRIVATE=False. After C_CloseAllSessions claims
        CKR_OK, every old handle (fixture session, named auxiliary session,
        all additional handles) must report CKR_SESSION_HANDLE_INVALID, and a
        reopened, proven-operational session must not find the labelled object.
        """
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        aux: list[int] = []
        new_sh = 0
        pending: _CloseAllPending | None = None
        try:
            s1 = raw_open_session(rs.raw, rs.slot_id, flags)
            if pin_bytes is not None:
                login_user(rs.raw, s1, CKU_USER, pin_bytes)
            aux.append(s1)

            # Open more sessions
            for _ in range(3):
                aux.append(raw_open_session(rs.raw, rs.slot_id, flags))
            old_handles = [rs.sh, *aux]

            # Generate a session key in s1 with the unique exact label.
            gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_LABEL: _CLOSE_ALL_SESSION_LABEL,
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                },
                sh=s1,
            )

            rv_close = rs.raw.C_CloseAllSessions(rs.slot_id)
            if rv_close != CKR_OK:
                pending = _close_all_refusal_pending(rv_close)
            else:
                observations = [
                    (handle, _session_info_rv(rs.raw, handle)) for handle in old_handles
                ]
                new_sh, staging, found = _reopen_and_search(rs, rs.slot_id, flags, pin_bytes)
                pending = _close_all_effects_pending(observations, found, staging)
        finally:
            for handle in aux:
                close_session_quietly(rs.raw, handle)
            if new_sh:
                close_session_quietly(rs.raw, new_sh)
        if pending is not None:
            _raise_close_all(pending)


class TestSessionEdgeRegressions:
    """Session and mechanism edge case regressions (task 7.22)."""

    def test_wrap_unsupported_mechanism_returns_proper_ckr(self, p11_raw_session: Any) -> None:
        """C_WrapKey with unsupported mechanism must return
        CKR_MECHANISM_INVALID, not CKR_GENERAL_ERROR or crash."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        target = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True},
        )

        try:
            # Try wrapping with SHA-256 (not a wrapping mechanism)
            mech = mech_simple(CKM_SHA256)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(rs.sh, mech.byref(), key, target, None, byref(out_len))
            if rv == CKR_OK:
                fail_as(
                    "accepted_invalid",
                    kind="policy",
                    label="C_WrapKey:non-wrapping-mechanism",
                    operation="C_WrapKey",
                    mechanism="CKM_SHA256",
                    actual=rv,
                    summary="Wrap with SHA-256 should have failed",
                )
            # CKR_MECHANISM_INVALID or CKR_KEY_NOT_WRAPPABLE are correct
            # Other errors are module quirks - document but don't fail
            if rv not in (
                CKR_MECHANISM_INVALID,
                0x00000069,  # CKR_KEY_NOT_WRAPPABLE
            ):
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"C_WrapKey with bad mechanism returned {ckr_name(rv)} "
                    "instead of CKR_MECHANISM_INVALID",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="wrap-unsupported-mechanism",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_keygen_minimum_size(self, p11_raw_session: Any) -> None:
        """Generate RSA with various sizes - verify minimum enforcement behaviour.

        PKCS#11 mandates no minimum RSA key size, so accepting a 512-bit key is
        spec-legal (if not recommended).  Rejection with CKR_KEY_SIZE_RANGE or
        CKR_ATTRIBUTE_VALUE_INVALID is also acceptable.  We record acceptance as a
        not-recommended deviation via compliance.note; we never fail_as here.
        """
        rs = p11_raw_session

        # Very small RSA: acceptance is spec-legal but not recommended;
        # rejection is equally valid.
        try:
            from pkcs11_check.compliance import ComplianceLevel
            from pkcs11_check.compliance import note as compliance_note
            from pkcs11_check.raw.recipes import gen_rsa_keypair

            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 512)
            # Provider accepted 512-bit RSA: spec-legal but not recommended.
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)
            compliance_note(
                "Module generated a 512-bit RSA key on explicit request; "
                "PKCS#11 imposes no minimum size but 512-bit RSA is cryptographically weak",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v2.40 §2.1 (no mandated minimum); NIST SP 800-131Ar2 §2",
            )
        except AssertionError as exc:
            # Rejection of a small RSA key is acceptable; route through classifier.
            # A non-CkrAssertionError has no .rv; propagate it as a real failure
            # rather than passing CKR_OK (0) which would mis-route to accepted_invalid.
            if not hasattr(exc, "rv"):
                raise
            classify_negative_rv(
                exc.rv,
                (CKR_KEY_SIZE_RANGE, CKR_ATTRIBUTE_VALUE_INVALID),
                label="RSA-512-keygen:size-rejection",
            )

        # Standard size should work
        from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            assert pub != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


# Need CKA_VALUE_LEN for the generate key test
from pkcs11_check.raw.types_std import CKA_VALUE_LEN  # noqa: E402

_OPEN_SESSION_MATRIX: dict[str, dict[str, bool]] = {
    "null-null": {"notify": False, "app_data": False},
    "null-data": {"notify": False, "app_data": True},
    "callback-null": {"notify": True, "app_data": False},
    "callback-data": {"notify": True, "app_data": True},
}


class TestCKNotifyCallback:
    """Test that C_OpenSession accepts CK_NOTIFY callback parameter.

    Per OASIS spec, C_OpenSession takes a notification callback (CK_NOTIFY)
    and an application pointer.  Most modules ignore the callback, but they
    must accept it without error.
    """

    def test_open_session_with_null_callback(self, p11_raw_session: Any) -> None:
        """C_OpenSession with NULL CK_NOTIFY (standard usage) succeeds."""
        from pkcs11_check.raw.types_std import (
            CK_NOTIFY,
            CK_SESSION_HANDLE,
            CKF_RW_SESSION,
            CKF_SERIAL_SESSION,
            CKR_OK,
        )

        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)
        sh = CK_SESSION_HANDLE(0)
        # Pass explicit CK_NOTIFY() (null callback) and NULL application pointer
        rv = rs.raw.C_OpenSession(rs.slot_id, flags, None, CK_NOTIFY(), byref(sh))
        if rv == CKR_OK:
            close_session_quietly(rs.raw, sh.value)
        else:
            # Some modules limit concurrent sessions -- acceptable
            ckr = ckr_name(rv)
            assert "SESSION_COUNT" in ckr or "PARALLEL" in ckr, (
                f"C_OpenSession with null CK_NOTIFY failed unexpectedly: {ckr}"
            )

    @pytest.mark.parametrize(
        "matrix_case",
        list(_OPEN_SESSION_MATRIX.values()),
        ids=list(_OPEN_SESSION_MATRIX),
    )
    def test_open_session_callback_matrix(
        self, p11_raw_session: Any, matrix_case: dict[str, bool]
    ) -> None:
        """Every callback/app-data combination opens (or hits session limits).

        The callback always returns CKR_OK; modules must accept the
        combination without error and must never crash on it.
        """
        import ctypes

        from pkcs11_check.raw.types_std import (
            CK_NOTIFY,
            CK_SESSION_HANDLE,
            CKF_RW_SESSION,
            CKF_SERIAL_SESSION,
            CKR_OK,
        )

        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)
        label = "C_OpenSession:callback matrix"

        calls: list[tuple[int, int, Any]] = []

        def _notify(session: int, event: int, application: Any) -> int:
            calls.append((session, event, application))
            return int(CKR_OK)

        notify = CK_NOTIFY(_notify) if matrix_case["notify"] else CK_NOTIFY()
        app_data = ctypes.c_ulong(0xA5A5A5A5)
        app_arg: Any = byref(app_data) if matrix_case["app_data"] else None
        sh = CK_SESSION_HANDLE(0)
        rv = rs.raw.C_OpenSession(rs.slot_id, flags, app_arg, notify, byref(sh))
        if rv != CKR_OK:
            # Only a session-count refusal is acceptable: CKF_SERIAL_SESSION
            # IS set, so CKR_SESSION_PARALLEL_NOT_SUPPORTED (or any other RV)
            # is a real flag-handling bug, not a limit.
            if rv == CKR_SESSION_COUNT:
                return
            fail_as(
                "wrong_result",
                kind="lifecycle",
                label=label,
                operation="C_OpenSession",
                expected=(CKR_OK, CKR_SESSION_COUNT),
                actual=rv,
                summary=(
                    f"{label}: C_OpenSession failed unexpectedly with {ckr_name(rv)}; "
                    "the serial flag is set so only CKR_SESSION_COUNT is acceptable"
                ),
            )
        if sh.value == 0:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_OpenSession",
                summary=f"{label}: returned CKR_OK with a null handle",
            )
        if sh.value == int(rs.sh):
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_OpenSession",
                summary=(
                    f"{label}: returned CKR_OK with the live fixture handle "
                    f"{int(rs.sh)} instead of a fresh session"
                ),
                detail={"handle": sh.value, "fixture_handle": int(rs.sh)},
            )
        info_rv, info = _session_info(rs.raw, sh.value)
        if info_rv != CKR_OK:
            close_session_quietly(rs.raw, sh.value)
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_GetSessionInfo",
                expected=CKR_OK,
                actual=info_rv,
                summary=(
                    f"{label}: new handle {sh.value} is unusable "
                    f"({ckr_name(info_rv)}) despite C_OpenSession claiming CKR_OK"
                ),
                detail={"handle": sh.value},
            )
        info_slot = int(info.slotID)
        if info_slot != int(rs.slot_id):
            close_session_quietly(rs.raw, sh.value)
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_GetSessionInfo",
                expected=(f"slot {int(rs.slot_id)}",),
                actual=f"slot {info_slot}",
                summary=(
                    f"{label}: new handle {sh.value} reports slot {info_slot}, "
                    f"expected slot {int(rs.slot_id)} from C_OpenSession"
                ),
                detail={
                    "handle": sh.value,
                    "slot_id": info_slot,
                    "expected_slot_id": int(rs.slot_id),
                },
            )
        info_flags = int(info.flags)
        if (info_flags & flags) != flags:
            close_session_quietly(rs.raw, sh.value)
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_GetSessionInfo",
                expected=(f"flags 0x{flags:08x}",),
                actual=f"flags 0x{info_flags:08x}",
                summary=(
                    f"{label}: new handle {sh.value} reports flags "
                    f"0x{info_flags:08x}, expected requested flags 0x{flags:08x}"
                ),
                detail={
                    "handle": sh.value,
                    "flags": info_flags,
                    "expected_flags": flags,
                },
            )
        close_rv = rs.raw.C_CloseSession(sh.value)
        if close_rv != CKR_OK:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_CloseSession",
                expected=CKR_OK,
                actual=close_rv,
                summary=(
                    f"{label}: C_CloseSession({sh.value}) returned "
                    f"{ckr_name(close_rv)} for the session C_OpenSession just opened"
                ),
                detail={"handle": sh.value},
            )
        dead_rv = _session_info_rv(rs.raw, sh.value)
        if matrix_case["notify"]:
            # Invocation itself is optional, but every delivered call must
            # identify the new session and echo the supplied app pointer
            # (ctypes delivers CK_VOID_PTR as the address int, or None).
            # Validated after the final provider call completes so callbacks
            # delivered during C_CloseSession and the post-close probe are
            # covered too; the close has already run, so there is nothing
            # left to clean up on this path.
            expected_app: int | None = (
                None if app_arg is None else int(ctypes.cast(app_arg, ctypes.c_void_p).value or 0)
            )
            for session, _event, application in calls:
                if session != sh.value or application != expected_app:
                    fail_as(
                        "self_contradiction",
                        kind="lifecycle",
                        label=label,
                        operation="C_OpenSession",
                        summary=(
                            f"{label}: callback delivered session {session} "
                            f"app {application!r}, expected session {sh.value} "
                            f"app {expected_app!r}"
                        ),
                        detail={
                            "handle": sh.value,
                            "callback_session": session,
                            "callback_app": application,
                            "expected_app": expected_app,
                        },
                    )
        if dead_rv == CKR_OK:
            _fail_session_info(
                kind="lifecycle",
                label=label,
                actual=dead_rv,
                summary=(
                    f"{label}: closed handle {sh.value} still answers "
                    "C_GetSessionInfo after C_CloseSession claimed CKR_OK"
                ),
                detail={"handle": sh.value},
            )
        if dead_rv != CKR_SESSION_HANDLE_INVALID:
            if is_standard_ckr(dead_rv) or is_vendor_defined_ckr(dead_rv):
                _xfail_session_info(
                    label=label,
                    actual=dead_rv,
                    summary=(
                        f"{label}: closed handle {sh.value} returned "
                        f"{ckr_name(dead_rv)} instead of CKR_SESSION_HANDLE_INVALID"
                    ),
                    detail={"handle": sh.value},
                )
            _fail_session_info(
                kind="metadata",
                label=label,
                actual=dead_rv,
                summary=(
                    f"{label}: closed handle {sh.value} returned undefined "
                    f"CK_RV {ckr_name(dead_rv)} after C_CloseSession claimed CKR_OK"
                ),
                detail={"handle": sh.value},
            )

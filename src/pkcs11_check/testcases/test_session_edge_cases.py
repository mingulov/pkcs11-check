"""Session edge-case tests - stale handles, CloseAllSessions, session issue regressions.

References: rep11.md Iteration 2.
"""

from __future__ import annotations

from ctypes import byref
from dataclasses import dataclass, field
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import fail_as, xfail_as
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
    CKR_OK,
    CKR_SESSION_CLOSED,
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


def _session_info_rv(raw: Any, session: int) -> int:
    """Return the raw CK_RV of C_GetSessionInfo without asserting on it."""
    info = CK_SESSION_INFO()
    return int(raw.C_GetSessionInfo(session, byref(info)))


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

        # Close the session
        close_session_quietly(rs.raw, test_sh)

        # Try to use the closed session -- must reject, not crash or succeed
        rv = rs.raw.C_FindObjectsInit(test_sh, None, 0)
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED),
            label="C_FindObjectsInit on closed session",
        )

    def test_generate_key_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_GenerateKey on closed session must fail cleanly."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        # Close the session
        close_session_quietly(rs.raw, test_sh)

        # Try to generate a key on the closed session
        from pkcs11_check.raw.pack import attr_ulong, template

        tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
        mech = mech_simple(CKM_AES_KEY_GEN)
        key_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(test_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED),
            label="C_GenerateKey on closed session",
        )


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
        info_rv = _session_info_rv(rs.raw, sh.value)
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
        if matrix_case["notify"]:
            # Invocation itself is optional, but every delivered call must
            # identify the new session and echo the supplied app pointer
            # (ctypes delivers CK_VOID_PTR as the address int, or None).
            expected_app: int | None = (
                None if app_arg is None else int(ctypes.cast(app_arg, ctypes.c_void_p).value or 0)
            )
            for session, _event, application in calls:
                if session != sh.value or application != expected_app:
                    close_session_quietly(rs.raw, sh.value)
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

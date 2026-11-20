"""Probe: QC11 sacrificial-token administration (lockout, PIN lengths, journey, reset).

Each probe runs against a *throwaway* token: the parent mints a disposable
token, passes its module path as ``module_path``, and points the module's
config file at the child via the ``PKCS11_CHECK_TOKEN_CONF_ENV``-named env var
(inherited from the parent's environment). Runs through ``probe_main`` at
``Level.INIT``; each probe body performs its own slot discovery and session
management.

Burn and PIN-length children self-provision with ``C_InitToken`` first
(pristine-by-construction, same containment as the journey probe): the mint is
NOT required to establish any PIN. An InitToken refusal ends the probe with an
explicit ``ASSUMPTION_FAILED:self_provision`` skip, never a silent pass.

Invariant I3: probe bodies authenticate with HARDCODED TEST PINs only (the
``TEST_*``/``WRONG_*`` fixtures below); the configured module PIN is never
read, embedded, or forwarded. Length-sweep PINs come from ``candidate_pin``.

Unlike the legacy ``ckr_destructive`` probes, these children NEVER assert on
provider behavior: every provider outcome is printed as a ``STEP``/``FLAGS``
line and the probe ends with ``OK`` so the parent can judge setup failures as
skips, positive-leg refusals as xfails, and contradictions as failures.

Output protocol (parsed parent-side by ``parse_admin_trace``):
  ``STEP:{name}:CKR:0x{rv:08x}`` -- one admin/login/setup op result
  ``STEP:snapshot:{tag}:CKR:0x{rv:08x}`` -- failed token-info read (raw RV kept)
  ``FLAGS:{tag}:0x{flags:08x}`` (or ``FLAGS:{tag}:unknown``) -- token snapshot
  ``PINBOUNDS:{min}:{max}`` (or ``PINBOUNDS:unknown``) -- declared PIN bounds
  ``INV:objects={n}``            -- label-filtered canary inventory count
  ``OK``                         -- probe reached its expected point
  ``NO_SLOTS``                   -- no present slot (parent skips)
  ``ASSUMPTION_FAILED:{what}``   -- mint assumption broken (parent skips)

Dispatch on ``extra["probe"]``: ``qc11a_burn``, ``qc11a_read``,
``qc11b_pin_lengths``, ``qc11c_journey``, ``qc11c_verify``, ``qc11c_reset``.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import hashlib
import threading
from collections.abc import Callable
from contextlib import suppress
from typing import Any, NamedTuple

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_C_INITIALIZE_ARGS,
    CK_NOTIFY,
    CK_OBJECT_HANDLE,
    CK_TOKEN_INFO,
    CKA_CLASS,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_OS_LOCKING_OK,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_COUNT_LOW,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_LOCKED,
    CKO_DATA,
    CKR_CANT_LOCK,
    CKR_OK,
    CKR_PIN_LOCKED,
    CKR_TOKEN_NOT_PRESENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

TEST_SO_PIN = b"87654321"
TEST_USER_PIN = b"1234"
TEST_USER_PIN_2 = b"5678"
WRONG_SO_PIN = b"WRONG_SO_PIN_01"
WRONG_USER_PIN = b"WRONG_USER_PIN_01"
CANARY_LABEL = b"qc11-canary"
CANARY_VALUE = b"qc11-canary-value"

_ROLE_COUNTER_FLAGS = {
    "user": (int(CKF_USER_PIN_COUNT_LOW), int(CKF_USER_PIN_FINAL_TRY), int(CKF_USER_PIN_LOCKED)),
    "so": (int(CKF_SO_PIN_COUNT_LOW), int(CKF_SO_PIN_FINAL_TRY), int(CKF_SO_PIN_LOCKED)),
}


def candidate_pin(length: int) -> bytes:
    """Deterministic ASCII test PIN of exactly ``length`` bytes (length >= 1)."""
    if length < 1:
        raise ValueError(f"candidate PIN length must be >= 1, got {length}")
    unit = f"NP{length:04d}".encode("ascii")
    return (unit * ((length // len(unit)) + 1))[:length]


class AdminStep(NamedTuple):
    name: str
    rv: int


class AdminUseCheck(NamedTuple):
    name: str
    length: int
    sha256: str


class AdminTrace(NamedTuple):
    steps: tuple[AdminStep, ...]
    flags: tuple[tuple[str, int | None], ...]
    pin_bounds: tuple[int, int] | None
    inv_objects: tuple[int, ...]
    ok: bool
    no_slots: bool
    assumption_failed: str | None
    use_checks: tuple[AdminUseCheck, ...] = ()


class TraceParseError(ValueError):
    """A known-prefix child line was malformed; always loud, never ignored."""


def _parse_hex(token: str, *, what: str) -> int:
    text = token.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise TraceParseError(f"malformed {what} hex value: {token!r}")
    return int(text, 16)


def _parse_use_line(line: str) -> AdminUseCheck:
    """Parse one ``USE:<name>=<len>:<sha256hex>`` post-use integrity line."""
    body = line[len("USE:") :]
    name, sep, rest = body.partition("=")
    length_text, sep2, digest = rest.partition(":")
    if not sep or not sep2 or not name.strip() or not digest:
        raise TraceParseError(f"malformed USE line: {line!r}")
    try:
        length = int(length_text.strip())
    except ValueError:
        raise TraceParseError(f"malformed USE line: {line!r}") from None
    digest = digest.strip().lower()
    if length < 0 or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise TraceParseError(f"malformed USE line: {line!r}")
    return AdminUseCheck(name.strip(), length, digest)


def parse_admin_trace(out: str) -> AdminTrace:
    """Parse child protocol output; unknown lines are ignored, malformed known lines fail."""
    steps: list[AdminStep] = []
    flags: list[tuple[str, int | None]] = []
    pin_bounds: tuple[int, int] | None = None
    inv_objects: list[int] = []
    use_checks: list[AdminUseCheck] = []
    ok = False
    no_slots = False
    assumption_failed: str | None = None
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line == "OK":
            ok = True
            continue
        if line == "NO_SLOTS":
            no_slots = True
            continue
        if line == "ASSUMPTION_FAILED" or line.startswith("ASSUMPTION_FAILED:"):
            reason = line.partition(":")[2].strip()
            if not reason:
                raise TraceParseError("ASSUMPTION_FAILED without a reason")
            assumption_failed = reason
            continue
        if line.startswith("STEP:"):
            name, sep, rvpart = line[len("STEP:") :].rpartition(":CKR:")
            if not sep or not name:
                raise TraceParseError(f"malformed STEP line: {line!r}")
            steps.append(AdminStep(name, _parse_hex(rvpart, what="STEP RV")))
            continue
        if line.startswith("FLAGS:"):
            tag, sep, value = line[len("FLAGS:") :].partition(":")
            if not sep or not tag:
                raise TraceParseError(f"malformed FLAGS line: {line!r}")
            if value.strip() == "unknown":
                flags.append((tag, None))
            else:
                flags.append((tag, _parse_hex(value, what="FLAGS")))
            continue
        if line.startswith("PINBOUNDS:"):
            body = line[len("PINBOUNDS:") :].strip()
            if body == "unknown":
                pin_bounds = None
                continue
            lo, sep, hi = body.partition(":")
            if not sep:
                raise TraceParseError(f"malformed PINBOUNDS line: {line!r}")
            try:
                bounds = (int(lo), int(hi))
            except ValueError:
                raise TraceParseError(f"malformed PINBOUNDS line: {line!r}") from None
            if bounds[0] < 0 or bounds[1] < 0:
                raise TraceParseError(f"malformed PINBOUNDS line: {line!r}")
            pin_bounds = bounds
            continue
        if line.startswith("INV:objects="):
            try:
                count = int(line[len("INV:objects=") :].strip())
            except ValueError:
                raise TraceParseError(f"malformed INV line: {line!r}") from None
            if count < 0:
                raise TraceParseError(f"malformed INV line: {line!r}")
            inv_objects.append(count)
            continue
        if line.startswith("USE:"):
            check = _parse_use_line(line)
            use_checks.append(check)
            continue
    return AdminTrace(
        steps=tuple(steps),
        flags=tuple(flags),
        pin_bounds=pin_bounds,
        inv_objects=tuple(inv_objects),
        ok=ok,
        no_slots=no_slots,
        assumption_failed=assumption_failed,
        use_checks=tuple(use_checks),
    )


def setup_failure(trace: AdminTrace) -> AdminStep | None:
    """Return the first failed ``setup:*`` step, or None when setup held."""
    for step in trace.steps:
        if step.name == "setup" or step.name.startswith("setup:"):
            if step.rv != int(CKR_OK):
                return step
    return None


_PROVISIONING_STEP_OPERATIONS = {
    "init_token": "C_InitToken",
    "setup:open": "C_OpenSession",
    "setup:so_login": "C_Login",
    "setup:login": "C_Login",
    "setup:init_pin": "C_InitPIN",
}

_ASSUMPTION_OPERATIONS = {
    "self_provision": "C_InitToken",
    "tokeninfo": "C_GetTokenInfo",
    "setup_login": "C_Login",
    "setup_init_pin": "C_InitPIN",
}


def _assumption_rv(reason: str) -> tuple[str, int | None]:
    """Split an ASSUMPTION_FAILED reason into (head, trailing raw RV or None)."""
    head, sep, tail = reason.rpartition(":")
    if not sep:
        return reason, None
    text = tail.strip()
    digits = text[2:] if text.lower().startswith("0x") else None
    if digits is None or not digits or any(c not in "0123456789abcdefABCDEF" for c in digits):
        return reason, None
    return head, int(digits, 16)


def _fail_on_undefined_provisioning(trace: AdminTrace, *, label: str) -> None:
    """R19-03: undefined self-provisioning RVs FAIL; clean refusals stay skips."""
    for step in trace.steps:
        if step.name == "init_token" or step.name == "setup" or step.name.startswith("setup:"):
            if not (is_standard_ckr(step.rv) or is_vendor_defined_ckr(step.rv)):
                classification.fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=f"{label}: {step.name}",
                    operation=_PROVISIONING_STEP_OPERATIONS.get(step.name),
                    mechanism=None,
                    inherit_mechanism=False,
                    actual=step.rv,
                    summary=(
                        f"{label}: self-provisioning {step.name} returned "
                        f"undefined CK_RV {ckr_name(step.rv)}"
                    ),
                )
    if trace.assumption_failed is not None:
        head, rv = _assumption_rv(trace.assumption_failed)
        if rv is not None and not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
            classification.fail_as(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: {trace.assumption_failed}",
                operation=_ASSUMPTION_OPERATIONS.get(head),
                mechanism=None,
                inherit_mechanism=False,
                actual=rv,
                summary=(
                    f"{label}: self-provisioning {head} returned undefined CK_RV {ckr_name(rv)}"
                ),
            )


def _undefined_snapshot_steps(trace: AdminTrace) -> list[AdminStep]:
    """Snapshot steps carrying undefined RVs; defined failures stay tolerated."""
    return [
        step
        for step in trace.steps
        if (step.name == "snapshot" or step.name.startswith("snapshot:"))
        and not (is_standard_ckr(step.rv) or is_vendor_defined_ckr(step.rv))
    ]


def fail_on_undefined_snapshots(trace: AdminTrace, *, label: str, detail: dict[str, Any]) -> None:
    """R19-04/F1/F3: undefined ``snapshot:*`` RVs FAIL; defined failures stay tolerated."""
    for step in _undefined_snapshot_steps(trace):
        classification.fail_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {step.name}",
            operation="C_GetTokenInfo",
            mechanism=None,
            inherit_mechanism=False,
            actual=step.rv,
            summary=f"{label}: token snapshot returned undefined CK_RV {ckr_name(step.rv)}",
            detail=detail,
        )


def undefined_snapshot_records(
    trace: AdminTrace, *, label: str, detail: dict[str, Any]
) -> list[classification.Classification]:
    """Record-collecting twin of ``fail_on_undefined_snapshots`` for QC11c assessors."""
    return [
        classification.record_as(
            "self_contradiction",
            kind="metadata",
            label=f"{label}: {step.name}",
            operation="C_GetTokenInfo",
            mechanism=None,
            inherit_mechanism=False,
            actual=step.rv,
            summary=f"{label}: token snapshot returned undefined CK_RV {ckr_name(step.rv)}",
            detail=detail,
        )
        for step in _undefined_snapshot_steps(trace)
    ]


def parse_child_output(rc: int, out: str, err: str, *, label: str) -> AdminTrace:
    """Parse one child result; crashes and incomplete output fail loud, never skip."""
    assert rc == 0, f"{label}: child failed (rc={rc}): {err[-300:]}"
    trace = parse_admin_trace(out)
    if not trace.no_slots:
        assert "OK" in out, f"{label}: child incomplete (no OK marker): {out[-300:]!r}"
    return trace


def trace_skip_reason(trace: AdminTrace, *, no_slots: str = "skip") -> str | None:
    """Return the gate skip reason for a parsed trace, or None when it gates clean.

    ``no_slots="fail"`` reports None for a vanished token (the gate fails loud
    there); otherwise a reason is reported whenever the gate would skip,
    whatever the RV definedness (undefined RVs FAIL inside ``gate_child_trace``
    before the skip is taken). Callers use this for R19-02 collect-then-judge:
    a non-None reason means the gate would skip, so phase-one FAIL grades must
    be judged first.
    """
    if trace.no_slots:
        if no_slots == "fail":
            return None
        return "no present slot on the sacrificial token"
    if trace.assumption_failed is not None:
        return f"sacrificial-token assumption failed: {trace.assumption_failed}"
    failed = setup_failure(trace)
    if failed is not None:
        return (
            f"sacrificial setup failed: {failed.name}={ckr_name(failed.rv)}; "
            "destructive legs untestable"
        )
    return None


def gate_child_trace(trace: AdminTrace, *, label: str, no_slots: str = "skip") -> AdminTrace:
    """Apply the skip/fail gate to a parsed trace; returns the trace when clean."""
    if trace.no_slots:
        if no_slots == "fail":
            classification.fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=label,
                operation="C_GetSlotList",
                mechanism=None,
                inherit_mechanism=False,
                summary=f"{label}: provisioned token absent after restart",
            )
        pytest.skip(f"{label}: no present slot on the sacrificial token")
    _fail_on_undefined_provisioning(trace, label=label)
    if trace.assumption_failed is not None:
        pytest.skip(f"{label}: sacrificial-token assumption failed: {trace.assumption_failed}")
    failed = setup_failure(trace)
    if failed is not None:
        pytest.skip(
            f"{label}: sacrificial setup failed: {failed.name}={ckr_name(failed.rv)}; "
            "destructive legs untestable"
        )
    return trace


def check_child_output(
    rc: int, out: str, err: str, *, label: str, no_slots: str = "skip"
) -> AdminTrace:
    """Gate one child result: crash/incomplete fail, no-slot/assumption/setup skip.

    ``no_slots="fail"`` turns a vanished token into a lifecycle failure (for
    later phases whose token was already proven present, e.g. after restart).
    Undefined self-provisioning RVs fail (R19-03); multi-launch nodes split
    this into ``parse_child_output`` + ``gate_child_trace`` for collect-then-
    judge (R19-02).
    """
    trace = parse_child_output(rc, out, err, label=label)
    return gate_child_trace(trace, label=label, no_slots=no_slots)


def _buf(data: bytes) -> Any:
    return (ctypes.c_ubyte * len(data))(*data)


def _step(name: str, rv: int) -> None:
    print(f"STEP:{name}:CKR:0x{rv:08x}")


def _flags(tag: str, value: int | None) -> None:
    if value is None:
        print(f"FLAGS:{tag}:unknown")
    else:
        print(f"FLAGS:{tag}:0x{value:08x}")


def _discover_slot(ctx: ProbeContext) -> int | None:
    sc = ctypes.c_ulong(0)
    rv = ctx.raw.C_GetSlotList(1, None, ctypes.byref(sc))
    if int(rv) != int(CKR_OK) or sc.value == 0:
        return None
    sl = (ctypes.c_ulong * sc.value)()
    ctx.raw.C_GetSlotList(1, sl, ctypes.byref(sc))
    if sc.value == 0:
        return None
    return int(sl[0])


_BURN_TOKEN_LABEL = b"qc11-admin-test"


def _rediscover_burn_slot(
    ctx: ProbeContext,
) -> tuple[tuple[int, ...], int, tuple[tuple[int, int], ...]]:
    """Find the burn token by label after restart.

    Returns (matches, enum_rv, info_refusals): every slot whose token
    label matches, the enumeration RV, and (slot, rv) for each refused
    C_GetTokenInfo. Per-slot refusals are preserved (never discarded):
    a match hidden behind a refusal is unproved, not absent. The
    pre-restart slot is never reused blindly: slot numbering may shift
    across C_Finalize/C_Initialize.
    """
    sc = ctypes.c_ulong(0)
    rv = int(ctx.raw.C_GetSlotList(1, None, ctypes.byref(sc)))
    if rv != int(CKR_OK):
        return (), rv, ()
    if sc.value == 0:
        return (), int(CKR_OK), ()
    sl = (ctypes.c_ulong * sc.value)()
    rv = int(ctx.raw.C_GetSlotList(1, sl, ctypes.byref(sc)))
    if rv != int(CKR_OK):
        return (), rv, ()
    matches: list[int] = []
    info_refusals: list[tuple[int, int]] = []
    for i in range(int(sc.value)):
        slot = int(sl[i])
        info = CK_TOKEN_INFO()
        irv = int(ctx.raw.C_GetTokenInfo(slot, ctypes.byref(info)))
        if irv != int(CKR_OK):
            info_refusals.append((slot, irv))
            continue
        if bytes(info.label).rstrip(b" \x00") == _BURN_TOKEN_LABEL:
            matches.append(slot)
    return tuple(matches), int(CKR_OK), tuple(info_refusals)


def _phase2_rediscovery_outcome(
    matches: tuple[int, ...], info_refusals: tuple[tuple[int, int], ...]
) -> tuple[str, str | int]:
    """Decide the post-restart attribution (R2C5a).

    Returns ("proceed", slot) only for exactly one label match under
    complete visibility; ("absent", 0) only when no slot matches and
    every slot answered; otherwise ("assumption", reason). Absence is
    never declared while a match could hide behind a refusal, and a
    duplicated label never resolves to one slot silently.
    """
    if len(matches) > 1:
        return ("assumption", f"burn token label ambiguous across {len(matches)} slots")
    if not matches:
        if info_refusals:
            return (
                "assumption",
                "burn token identity unproved: "
                f"C_GetTokenInfo refused on {len(info_refusals)} slot(s)",
            )
        return ("absent", 0)
    if info_refusals:
        return (
            "assumption",
            "burn token uniqueness unproved: "
            f"C_GetTokenInfo refused on {len(info_refusals)} slot(s)",
        )
    return ("proceed", matches[0])


def _open_rw(ctx: ProbeContext, slot: int) -> tuple[int, int]:
    sess = ctypes.c_ulong(0)
    rv = ctx.raw.C_OpenSession(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, CK_NOTIFY(), ctypes.byref(sess)
    )
    return int(rv), int(sess.value)


def _token_info(ctx: ProbeContext, slot: int) -> tuple[int, int, int, int]:
    info = CK_TOKEN_INFO()
    rv = int(ctx.raw.C_GetTokenInfo(slot, ctypes.byref(info)))
    if rv != int(CKR_OK):
        return rv, 0, 0, 0
    return rv, int(info.flags), int(info.ulMinPinLen), int(info.ulMaxPinLen)


def _login(ctx: ProbeContext, sh: int, role: str, pin: bytes) -> int:
    user_type = CKU_SO if role == "so" else CKU_USER
    return int(ctx.raw.C_Login(sh, user_type, _buf(pin), len(pin)))


def _quiet_close(ctx: ProbeContext, sh: int) -> None:
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    try:
        ctx.raw.C_CloseSession(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_CloseSession:{type(exc).__name__}")


def _count_labeled(ctx: ProbeContext, sh: int, label: bytes) -> tuple[int, int]:
    label_buf = _buf(label)
    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = CKA_LABEL
    tmpl[0].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
    tmpl[0].ulValueLen = len(label)
    rv = int(ctx.raw.C_FindObjectsInit(sh, tmpl, 1))
    if rv != int(CKR_OK):
        return rv, -1
    total = 0
    buf = (ctypes.c_ulong * 16)()
    while True:
        found = ctypes.c_ulong(0)
        rv = int(ctx.raw.C_FindObjects(sh, buf, len(buf), ctypes.byref(found)))
        if rv != int(CKR_OK):
            try:
                ctx.raw.C_FindObjectsFinal(sh)
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
                print(f"CLEANUP_IGNORED:C_FindObjectsFinal:{type(exc).__name__}")
            return rv, -1
        total += int(found.value)
        if int(found.value) < len(buf):
            break
    try:
        ctx.raw.C_FindObjectsFinal(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_FindObjectsFinal:{type(exc).__name__}")
    return int(CKR_OK), total


def _setup_burn_session(ctx: ProbeContext, role: str, then_other: bool) -> tuple[int, int] | None:
    """Provision a pristine token + open provisioned session; None when untestable.

    Shared by the two-phase burn and the same-process burn/read op:
    discovery, self-provision InitToken, pristine gate, open, and user
    PIN provisioning print identical steps; every early return prints
    its own terminal marker (OK, NO_SLOTS, or ASSUMPTION_FAILED).
    """
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return None
    itrv = _init_token(ctx, slot, TEST_SO_PIN)
    _step("init_token", itrv)
    if itrv != int(CKR_OK):
        print(f"ASSUMPTION_FAILED:self_provision:{itrv:#x}")
        print("OK")
        return None
    info_rv, flags, min_pin, max_pin = _token_info(ctx, slot)
    if info_rv != int(CKR_OK):
        print("PINBOUNDS:unknown")
        print(f"ASSUMPTION_FAILED:tokeninfo:{info_rv:#x}")
        print("OK")
        return None
    print(f"PINBOUNDS:{min_pin}:{max_pin}")
    print(f"FLAGS:initial:0x{flags:08x}")
    low, final, locked = _ROLE_COUNTER_FLAGS[role]
    if flags & (low | final | locked):
        print("ASSUMPTION_FAILED:not_pristine")
        print("OK")
        return None
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return None
    if role == "user" or then_other:
        # InitToken establishes only the SO PIN; provision the user PIN
        # whenever this child exercises USER (as the burn target or as the
        # other-role check), so an SO burn measures genuine independence
        # instead of USER_PIN_NOT_INITIALIZED.
        sorv = _login(ctx, sh, "so", TEST_SO_PIN)
        _step("setup:so_login", sorv)
        if sorv != int(CKR_OK):
            print(f"ASSUMPTION_FAILED:setup_login:{sorv:#x}")
            print("OK")
            return None
        iprv = int(ctx.raw.C_InitPIN(sh, _buf(TEST_USER_PIN), len(TEST_USER_PIN)))
        _step("setup:init_pin", iprv)
        if iprv != int(CKR_OK):
            print(f"ASSUMPTION_FAILED:setup_init_pin:{iprv:#x}")
            print("OK")
            return None
        try:
            ctx.raw.C_Logout(sh)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
            print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    return slot, sh


def _burn_attempts(
    ctx: ProbeContext, slot: int, sh: int, role: str, attempts: int, stop_at: str
) -> None:
    """Wrong-PIN burn loop shared by the two-phase and same-process ops."""
    low, final, _locked = _ROLE_COUNTER_FLAGS[role]
    wrong = WRONG_SO_PIN if role == "so" else WRONG_USER_PIN
    for i in range(1, attempts + 1):
        lrv = _login(ctx, sh, role, wrong)
        _step(f"login:{role}:wrong:{i}", lrv)
        _info_rv, flags_now, _, _ = _token_info(ctx, slot)
        if _info_rv != int(CKR_OK):
            _step(f"snapshot:attempt-{i}", _info_rv)
        _flags(f"attempt-{i}", flags_now if _info_rv == int(CKR_OK) else None)
        if lrv == int(CKR_PIN_LOCKED):
            break
        if stop_at == "final" and _info_rv == int(CKR_OK) and (flags_now & final):
            break


def _qc11a_burn(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    role = str(extra["role"])
    attempts = int(extra["attempts"])
    then_correct = bool(extra["then_correct"])
    then_other = bool(extra["then_other_role_correct"])
    post_wrongs = int(extra["post_success_wrongs"])
    stop_at = str(extra.get("stop_at", "locked"))
    if role not in ("user", "so"):
        raise ValueError(f"unknown role {role!r}")
    if stop_at not in ("locked", "final"):
        raise ValueError(f"unknown stop_at {stop_at!r}")
    setup = _setup_burn_session(ctx, role, then_other)
    if setup is None:
        return
    slot, sh = setup
    right = TEST_SO_PIN if role == "so" else TEST_USER_PIN
    wrong = WRONG_SO_PIN if role == "so" else WRONG_USER_PIN
    _burn_attempts(ctx, slot, sh, role, attempts, stop_at)
    if then_correct:
        crv = _login(ctx, sh, role, right)
        _step(f"login:{role}:correct", crv)
        try:
            ctx.raw.C_Logout(sh)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
            print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
        for j in range(1, post_wrongs + 1):
            prv = _login(ctx, sh, role, wrong)
            _step(f"login:{role}:post:{j}", prv)
            _info_rv, flags_now, _, _ = _token_info(ctx, slot)
            if _info_rv != int(CKR_OK):
                _step(f"snapshot:post-{j}", _info_rv)
            _flags(f"post-{j}", flags_now if _info_rv == int(CKR_OK) else None)
    if then_other:
        other = "so" if role == "user" else "user"
        orv = _login(ctx, sh, other, TEST_SO_PIN if other == "so" else TEST_USER_PIN)
        _step(f"login:{other}:correct", orv)
    _info_rv, flags_end, _, _ = _token_info(ctx, slot)
    if _info_rv != int(CKR_OK):
        _step("snapshot:final", _info_rv)
    _flags("final", flags_end if _info_rv == int(CKR_OK) else None)
    _quiet_close(ctx, sh)
    print("OK")


def _qc11a_read(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Phase-2 persistence reader: snapshot flags, then check the correct PIN.

    Runs on the phase-1-burned token, so it takes NO pristine gate (unlike
    ``_qc11a_burn``) and performs NO provisioning (an InitToken here would wipe
    the burned counters under test). Failed snapshots keep their raw RV as a
    ``snapshot:*`` step (like ``inv_read``), so undefined token-info RVs stay
    judgable instead of dissolving into ``unknown``.
    """
    role = str(extra["role"])
    if role not in ("user", "so"):
        raise ValueError(f"unknown role {role!r}")
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    _read_phase(ctx, slot, role)
    print("OK")


def _read_phase(ctx: ProbeContext, slot: int, role: str) -> None:
    """Snapshot flags, then check the correct PIN (shared read leg).

    Runs on a burned token: no pristine gate, no provisioning (an
    InitToken here would wipe the burned counters under test). Failed
    snapshots keep their raw RV as a step so undefined token-info RVs
    stay judgable. Used by the two-phase read op and the same-process
    op after its in-process Finalize/Initialize cycle.
    """
    info_rv, flags, min_pin, max_pin = _token_info(ctx, slot)
    if info_rv != int(CKR_OK):
        _step("snapshot:initial", info_rv)
        print("PINBOUNDS:unknown")
        print("FLAGS:initial:unknown")
    else:
        print(f"PINBOUNDS:{min_pin}:{max_pin}")
        print(f"FLAGS:initial:0x{flags:08x}")
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        return
    right = TEST_SO_PIN if role == "so" else TEST_USER_PIN
    crv = _login(ctx, sh, role, right)
    _step(f"login:{role}:correct", crv)
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    _info_rv, flags_end, _, _ = _token_info(ctx, slot)
    if _info_rv != int(CKR_OK):
        _step("snapshot:final", _info_rv)
    _flags("final", flags_end if _info_rv == int(CKR_OK) else None)
    _quiet_close(ctx, sh)


# Longest PIN the length sweep will ever build: absurd declared bounds (up to
# 2**32 - 1) must cap the sweep, never attempt GB allocations in the child.
PIN_SWEEP_CAP = 4096


def pin_sweep_capped(min_pin: int, max_pin: int) -> bool:
    """True when the sweep cap drops coverable legs for these declared bounds."""
    return min_pin > PIN_SWEEP_CAP or max_pin >= PIN_SWEEP_CAP


def _pin_length_legs(min_pin: int, max_pin: int) -> list[int]:
    mid = (min_pin + max_pin) // 2 if max_pin > min_pin else min_pin
    return sorted(
        {
            n
            for n in (1, 4, min_pin - 1, min_pin, mid, max_pin, max_pin + 1, 256)
            if 1 <= n <= PIN_SWEEP_CAP
        }
    )


def _qc11b_pin_lengths(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    op = str(extra["op"])
    if op not in ("init_pin", "set_pin"):
        raise ValueError(f"unknown op {op!r}")
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    itrv = _init_token(ctx, slot, TEST_SO_PIN)
    _step("init_token", itrv)
    if itrv != int(CKR_OK):
        print(f"ASSUMPTION_FAILED:self_provision:{itrv:#x}")
        print("OK")
        return
    info_rv, flags, min_pin, max_pin = _token_info(ctx, slot)
    if info_rv != int(CKR_OK):
        # F3: keep the raw bounds-read RV as a snapshot step so the judge can
        # FAIL undefined RVs instead of dissolving them into the skip below.
        _step("snapshot:pinbounds", info_rv)
        print("PINBOUNDS:unknown")
        print("OK")
        return
    print(f"PINBOUNDS:{min_pin}:{max_pin}")
    print(f"FLAGS:initial:0x{flags:08x}")
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    if op == "set_pin":
        # InitToken establishes only the SO PIN; the SetPIN legs need a known
        # user PIN as their chaining start.
        sorv = _login(ctx, sh, "so", TEST_SO_PIN)
        _step("setup:so_login", sorv)
        if sorv != int(CKR_OK):
            print(f"ASSUMPTION_FAILED:setup_login:{sorv:#x}")
            print("OK")
            return
        iprv = int(ctx.raw.C_InitPIN(sh, _buf(TEST_USER_PIN), len(TEST_USER_PIN)))
        _step("setup:init_pin", iprv)
        if iprv != int(CKR_OK):
            print(f"ASSUMPTION_FAILED:setup_init_pin:{iprv:#x}")
            print("OK")
            return
        try:
            ctx.raw.C_Logout(sh)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
            print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    if op == "init_pin":
        setup_rv = _login(ctx, sh, "so", TEST_SO_PIN)
    else:
        setup_rv = _login(ctx, sh, "user", TEST_USER_PIN)
    _step("setup:login", setup_rv)
    if setup_rv != int(CKR_OK):
        print(f"ASSUMPTION_FAILED:setup_login:{setup_rv:#x}")
        print("OK")
        return
    current = TEST_USER_PIN
    for length in _pin_length_legs(min_pin, max_pin):
        candidate = candidate_pin(length)
        if op == "init_pin":
            lrv = int(ctx.raw.C_InitPIN(sh, _buf(candidate), len(candidate)))
        else:
            lrv = int(
                ctx.raw.C_SetPIN(sh, _buf(current), len(current), _buf(candidate), len(candidate))
            )
            if lrv == int(CKR_OK):
                current = candidate
        _step(f"setlen:{length}", lrv)
    _quiet_close(ctx, sh)
    print("OK")


def _init_token(
    ctx: ProbeContext, slot: int, so_pin: bytes, label: bytes = _BURN_TOKEN_LABEL
) -> int:
    padded = label.ljust(32)
    return int(ctx.raw.C_InitToken(slot, _buf(so_pin), len(so_pin), _buf(padded)))


def _snapshot(ctx: ProbeContext, slot: int, tag: str) -> None:
    """Emit a token-flags snapshot; failed reads keep their raw RV as a step.

    Like ``_qc11a_read`` (R19-04): dissolving the RV into ``unknown`` would
    hide undefined CK_RVs from the judges, so every failed read also emits a
    ``snapshot:{tag}`` step carrying the raw RV.
    """
    info_rv, flags, _, _ = _token_info(ctx, slot)
    if info_rv != int(CKR_OK):
        _step(f"snapshot:{tag}", info_rv)
    _flags(tag, flags if info_rv == int(CKR_OK) else None)


def _create_canary(ctx: ProbeContext, sh: int) -> int:
    cls_val = ctypes.c_ulong(CKO_DATA)
    tok_true = ctypes.c_ubyte(1)
    priv_false = ctypes.c_ubyte(0)
    label_buf = _buf(CANARY_LABEL)
    value_buf = _buf(CANARY_VALUE)
    tmpl = (CK_ATTRIBUTE * 5)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_TOKEN
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(tok_true), ctypes.c_void_p)
    tmpl[1].ulValueLen = 1
    tmpl[2].type = CKA_PRIVATE
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(priv_false), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_LABEL
    tmpl[3].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
    tmpl[3].ulValueLen = len(CANARY_LABEL)
    tmpl[4].type = CKA_VALUE
    tmpl[4].pValue = ctypes.cast(value_buf, ctypes.c_void_p)
    tmpl[4].ulValueLen = len(CANARY_VALUE)
    handle = CK_OBJECT_HANDLE(0)
    return int(ctx.raw.C_CreateObject(sh, tmpl, 5, ctypes.byref(handle)))


def _qc11c_journey(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    del extra
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    itrv = _init_token(ctx, slot, TEST_SO_PIN)
    _step("init_token", itrv)
    _snapshot(ctx, slot, "after_init_token")
    if itrv != int(CKR_OK):
        print("OK")
        return
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    bounds_rv, _, min_pin, max_pin = _token_info(ctx, slot)
    if bounds_rv != int(CKR_OK):
        # F1: never fabricate bounds from a failed read; keep the raw RV as a
        # snapshot step and report the bounds as unknown.
        _step("snapshot:pinbounds", bounds_rv)
        print("PINBOUNDS:unknown")
    else:
        print(f"PINBOUNDS:{min_pin}:{max_pin}")
    sorv = _login(ctx, sh, "so", TEST_SO_PIN)
    _step("so_login", sorv)
    _snapshot(ctx, slot, "after_so_login")
    if sorv != int(CKR_OK):
        print("OK")
        return
    iprv = int(ctx.raw.C_InitPIN(sh, _buf(TEST_USER_PIN), len(TEST_USER_PIN)))
    _step("init_pin", iprv)
    _snapshot(ctx, slot, "after_init_pin")
    if iprv != int(CKR_OK):
        print("OK")
        return
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    ulrv = _login(ctx, sh, "user", TEST_USER_PIN)
    _step("user_login", ulrv)
    _snapshot(ctx, slot, "after_user_login")
    if ulrv != int(CKR_OK):
        print("OK")
        return
    sprv = int(
        ctx.raw.C_SetPIN(
            sh, _buf(TEST_USER_PIN), len(TEST_USER_PIN), _buf(TEST_USER_PIN_2), len(TEST_USER_PIN_2)
        )
    )
    _step("set_pin", sprv)
    _snapshot(ctx, slot, "after_set_pin")
    if sprv != int(CKR_OK):
        old_rv = _login(ctx, sh, "user", TEST_USER_PIN)
        _step("verify:old_after_refused_setpin", old_rv)
        try:
            ctx.raw.C_Logout(sh)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
            print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
        new_rv = _login(ctx, sh, "user", TEST_USER_PIN_2)
        _step("verify:new_after_refused_setpin", new_rv)
        _snapshot(ctx, slot, "after_refused_setpin")
        print("OK")
        return
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    old_rv = _login(ctx, sh, "user", TEST_USER_PIN)
    _step("old_rejected", old_rv)
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    new_rv = _login(ctx, sh, "user", TEST_USER_PIN_2)
    _step("new_accepted", new_rv)
    ccrv = _create_canary(ctx, sh)
    _step("create_canary", ccrv)
    inv_rv, inv_count = _count_labeled(ctx, sh, CANARY_LABEL)
    if inv_rv != int(CKR_OK):
        _step("inv_read", inv_rv)
    else:
        print(f"INV:objects={inv_count}")
    _snapshot(ctx, slot, "end")
    _quiet_close(ctx, sh)
    print("OK")


def _qc11c_verify(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    del extra
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    old_rv = _login(ctx, sh, "user", TEST_USER_PIN)
    _step("old_rejected", old_rv)
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    new_rv = _login(ctx, sh, "user", TEST_USER_PIN_2)
    _step("new_accepted", new_rv)
    inv_rv, inv_count = _count_labeled(ctx, sh, CANARY_LABEL)
    if inv_rv != int(CKR_OK):
        _step("inv_read", inv_rv)
    else:
        print(f"INV:objects={inv_count}")
    _snapshot(ctx, slot, "verify")
    _quiet_close(ctx, sh)
    print("OK")


def _qc11c_reset(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    del extra
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    # Re-initialize with the CURRENT SO PIN: tokens that verify-then-wipe accept
    # it, and tokens that set-new accept it too (same value). Either way the
    # user PIN, user objects, and canary must be destroyed while the token stays
    # functional; the SO PIN value itself is out of scope.
    rtrv = _init_token(ctx, slot, TEST_SO_PIN)
    _step("reset_init_token", rtrv)
    _snapshot(ctx, slot, "after_reset_init_token")
    if rtrv != int(CKR_OK):
        print("OK")
        return
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    sorv = _login(ctx, sh, "so", TEST_SO_PIN)
    _step("so_login", sorv)
    if sorv == int(CKR_OK):
        inv_rv, inv_count = _count_labeled(ctx, sh, CANARY_LABEL)
        if inv_rv != int(CKR_OK):
            _step("inv_read", inv_rv)
        else:
            print(f"INV:objects={inv_count}")
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    old_user_rv = _login(ctx, sh, "user", TEST_USER_PIN_2)
    _step("old_user_after_reset", old_user_rv)
    _snapshot(ctx, slot, "end")
    _quiet_close(ctx, sh)
    print("OK")


_QC9B_TARGET_TOKEN_LABEL = b"qc9b-target"
_QC9B_CONTROL_TOKEN_LABEL = b"qc9b-control"
_QC9B_TARGET_WITNESS_LABEL = b"qc9b-target-witness"
_QC9B_CONTROL_WITNESS_LABEL = b"qc9b-control-witness"
_QC9B_WITNESS_VALUE = b"qc9b-witness"


def _uninitialized_slots(ctx: ProbeContext) -> list[int]:
    """Slots whose token is absent or not initialized (InitToken candidates)."""
    count = ctypes.c_ulong(0)
    if int(ctx.raw.C_GetSlotList(0, None, ctypes.byref(count))) != int(CKR_OK):
        return []
    slots = (ctypes.c_ulong * count.value)()
    if int(ctx.raw.C_GetSlotList(0, slots, ctypes.byref(count))) != int(CKR_OK):
        return []
    out: list[int] = []
    for index in range(count.value):
        slot = int(slots[index])
        info = CK_TOKEN_INFO()
        rv = int(ctx.raw.C_GetTokenInfo(slot, ctypes.byref(info)))
        if rv == int(CKR_TOKEN_NOT_PRESENT):
            out.append(slot)
        elif rv == int(CKR_OK) and not (int(info.flags) & int(CKF_TOKEN_INITIALIZED)):
            out.append(slot)
    return out


def _create_private_session_witness(ctx: ProbeContext, sh: int, label: bytes) -> tuple[int, int]:
    """Create a private session data object; return (rv, handle)."""
    cls_val = ctypes.c_ulong(CKO_DATA)
    tok_false = ctypes.c_ubyte(0)
    priv_true = ctypes.c_ubyte(1)
    label_buf = _buf(label)
    value_buf = _buf(_QC9B_WITNESS_VALUE)
    tmpl = (CK_ATTRIBUTE * 5)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_TOKEN
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(tok_false), ctypes.c_void_p)
    tmpl[1].ulValueLen = 1
    tmpl[2].type = CKA_PRIVATE
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(priv_true), ctypes.c_void_p)
    tmpl[2].ulValueLen = 1
    tmpl[3].type = CKA_LABEL
    tmpl[3].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
    tmpl[3].ulValueLen = len(label)
    tmpl[4].type = CKA_VALUE
    tmpl[4].pValue = ctypes.cast(value_buf, ctypes.c_void_p)
    tmpl[4].ulValueLen = len(_QC9B_WITNESS_VALUE)
    handle = CK_OBJECT_HANDLE(0)
    rv = int(ctx.raw.C_CreateObject(sh, tmpl, 5, ctypes.byref(handle)))
    return rv, int(handle.value)


def _read_value_rv(ctx: ProbeContext, sh: int, handle: int) -> int:
    """Read CKA_VALUE off one handle; return the raw RV (never raises)."""
    buf = (ctypes.c_ubyte * 64)()
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE
    attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
    attr.ulValueLen = len(buf)
    return int(ctx.raw.C_GetAttributeValue(sh, handle, ctypes.byref(attr), 1))


def _read_witness_bytes(ctx: ProbeContext, sh: int, handle: int) -> tuple[int, bytes]:
    """Read the witness value bytes; (rv, b"") unless the read succeeds."""
    buf = (ctypes.c_ubyte * 64)()
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE
    attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
    attr.ulValueLen = len(buf)
    rv = int(ctx.raw.C_GetAttributeValue(sh, handle, ctypes.byref(attr), 1))
    if rv != int(CKR_OK):
        return rv, b""
    length = int(attr.ulValueLen)
    return rv, bytes(buf[:length])


def _read_witness_flags(
    ctx: ProbeContext, sh: int, handle: int
) -> tuple[int, bool | None, bool | None]:
    """Read CKA_PRIVATE/CKA_TOKEN off a witness; (rv, None, None) unless OK."""
    priv = ctypes.c_ubyte(0)
    tok = ctypes.c_ubyte(0)
    tmpl = (CK_ATTRIBUTE * 2)()
    tmpl[0].type = CKA_PRIVATE
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(priv), ctypes.c_void_p)
    tmpl[0].ulValueLen = 1
    tmpl[1].type = CKA_TOKEN
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(tok), ctypes.c_void_p)
    tmpl[1].ulValueLen = 1
    rv = int(ctx.raw.C_GetAttributeValue(sh, handle, tmpl, 2))
    if rv != int(CKR_OK):
        return rv, None, None
    return rv, bool(priv.value), bool(tok.value)


def _emit_use_check(name: str, value: bytes) -> None:
    """Print a post-use integrity line (length + sha256, never the bytes)."""
    print(f"USE:{name}={len(value)}:{hashlib.sha256(value).hexdigest()}")


def qc9b_witness_digest() -> tuple[int, str]:
    """(length, sha256) of the fixed cross-token witness value (judge side)."""
    return (
        len(_QC9B_WITNESS_VALUE),
        hashlib.sha256(_QC9B_WITNESS_VALUE).hexdigest(),
    )


def _verify_witness_binding(
    ctx: ProbeContext, sh: int, handle: int, label: bytes, name: str
) -> str | None:
    """Prove a witness is a findable private session object (D1, R2C4).

    Emits ``setup:{name}_witness_flags`` (the CKA_PRIVATE/CKA_TOKEN
    readback RV) and ``setup:{name}_prefind`` (the pre-logout label
    search RV). Returns an ASSUMPTION_FAILED reason when the binding
    is unproved (wrong flags or not uniquely visible) so the caller
    voids the fixture; None when bound. A non-OK step RV also returns
    None (the failed setup step skips via the gate); only a
    successful-but-wrong observation voids explicitly.
    """
    frv, is_private, is_token = _read_witness_flags(ctx, sh, handle)
    _step(f"setup:{name}_witness_flags", frv)
    if frv != int(CKR_OK):
        return None
    if is_private is not True or is_token is not False:
        return f"{name} witness not a private session object"
    prv, pcount = _count_labeled(ctx, sh, label)
    _step(f"setup:{name}_prefind", prv)
    if prv != int(CKR_OK):
        return None
    if pcount != 1:
        return f"{name} witness not uniquely visible pre-logout"
    return None


def _qc9b_cross_token(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """QC9b (#52.3): logout on one token leaves another token's login usable.

    Self-provisions two tokens (target + control) with the hardcoded TEST
    PINs, logs into both, creates a private session witness on each,
    logs out on the target, then observes: target find count, control
    find count (INV lines in that order), control use WITHOUT relogin,
    and stale target-handle use. All provisioning legs are ``setup:*``
    (fixture failures skip via the gate); the five judgment steps are
    plain-named for the parent judge.
    """
    del extra
    # Greedy init: some providers (SoftHSM) surface a fresh spare slot
    # after each InitToken, so recount before every init instead of
    # requiring two inittable slots up front.
    inited: list[int] = []
    for role, token_label in (
        ("target", _QC9B_TARGET_TOKEN_LABEL),
        ("control", _QC9B_CONTROL_TOKEN_LABEL),
    ):
        slots = _uninitialized_slots(ctx)
        if not slots:
            print("ASSUMPTION_FAILED:need two inittable slots")
            print("OK")
            return
        irv = _init_token(ctx, slots[0], TEST_SO_PIN, label=token_label)
        _step(f"setup:{role}_init_token", irv)
        if irv != int(CKR_OK):
            print("OK")
            return
        inited.append(slots[0])
    target_slot, control_slot = inited
    if target_slot == control_slot:
        print("ASSUMPTION_FAILED:target and control share one slot")
        print("OK")
        return
    topen, tsh = _open_rw(ctx, target_slot)
    _step("setup:target_open", topen)
    copen, csh = _open_rw(ctx, control_slot)
    _step("setup:control_open", copen)
    if topen != int(CKR_OK) or copen != int(CKR_OK):
        print("OK")
        return
    tso = _login(ctx, tsh, "so", TEST_SO_PIN)
    _step("setup:target_so_login", tso)
    cso = _login(ctx, csh, "so", TEST_SO_PIN)
    _step("setup:control_so_login", cso)
    if tso != int(CKR_OK) or cso != int(CKR_OK):
        print("OK")
        return
    tiprv = int(ctx.raw.C_InitPIN(tsh, _buf(TEST_USER_PIN), len(TEST_USER_PIN)))
    _step("setup:target_init_pin", tiprv)
    ciprv = int(ctx.raw.C_InitPIN(csh, _buf(TEST_USER_PIN), len(TEST_USER_PIN)))
    _step("setup:control_init_pin", ciprv)
    if tiprv != int(CKR_OK) or ciprv != int(CKR_OK):
        print("OK")
        return
    for sh in (tsh, csh):
        try:
            ctx.raw.C_Logout(sh)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
            print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    tulogin = _login(ctx, tsh, "user", TEST_USER_PIN)
    _step("setup:target_login", tulogin)
    culogin = _login(ctx, csh, "user", TEST_USER_PIN)
    _step("setup:control_login", culogin)
    if tulogin != int(CKR_OK) or culogin != int(CKR_OK):
        print("OK")
        return
    twrv, thandle = _create_private_session_witness(ctx, tsh, _QC9B_TARGET_WITNESS_LABEL)
    _step("setup:target_witness", twrv)
    cwrv, chandle = _create_private_session_witness(ctx, csh, _QC9B_CONTROL_WITNESS_LABEL)
    _step("setup:control_witness", cwrv)
    if twrv != int(CKR_OK) or cwrv != int(CKR_OK):
        print("OK")
        return
    # Premise (D1): both witnesses read back byte-exact before logout,
    # so later use verdicts isolate the logout effect. A mismatch voids
    # the fixture (skip), never the verdict.
    for sh, handle, name in ((tsh, thandle, "target"), (csh, chandle, "control")):
        prv, pbytes = _read_witness_bytes(ctx, sh, handle)
        _step(f"setup:{name}_witness_read", prv)
        if prv != int(CKR_OK):
            print("OK")
            return
        if pbytes != _QC9B_WITNESS_VALUE:
            print(f"ASSUMPTION_FAILED:{name} witness content mismatch")
            print("OK")
            return
    # Binding (D1): each witness must be a uniquely findable private
    # session object before logout proves anything about logout.
    for sh, handle, witness_label, name in (
        (tsh, thandle, _QC9B_TARGET_WITNESS_LABEL, "target"),
        (csh, chandle, _QC9B_CONTROL_WITNESS_LABEL, "control"),
    ):
        unbound = _verify_witness_binding(ctx, sh, handle, witness_label, name)
        if unbound is not None:
            print(f"ASSUMPTION_FAILED:{unbound}")
            print("OK")
            return
    lrv = int(ctx.raw.C_Logout(tsh))
    _step("target_logout", lrv)
    tfrv, tcount = _count_labeled(ctx, tsh, _QC9B_TARGET_WITNESS_LABEL)
    _step("target_find", tfrv)
    if tfrv == int(CKR_OK):
        print(f"INV:objects={tcount}")
    cfrv, ccount = _count_labeled(ctx, csh, _QC9B_CONTROL_WITNESS_LABEL)
    _step("control_find", cfrv)
    if cfrv == int(CKR_OK):
        print(f"INV:objects={ccount}")
    curv, cubytes = _read_witness_bytes(ctx, csh, chandle)
    _step("control_use", curv)
    if curv == int(CKR_OK):
        # Post-use integrity (R2C4): CKR_OK alone cannot prove the
        # control value survived; the length + hash travel separately
        # for the judge to verify independently.
        _emit_use_check("control", cubytes)
    _step("target_stale_use", _read_value_rv(ctx, tsh, thandle))
    _quiet_close(ctx, tsh)
    _quiet_close(ctx, csh)
    print("OK")


def _qc11a_same_process(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Burn, Finalize/Initialize in-process, then read (#52.6 same-process leg).

    Same burn setup/loop and same read leg as the two-phase ops (shared
    helpers, identical step vocabulary), with an in-process
    C_Finalize/C_Initialize cycle between them. Prints a PHASE2 marker
    before the read leg so the parent can split the output and judge
    both halves with the two-phase verdicts. Reinit failures end the
    run after the marker (the parent skips: restart untestable); a
    vanished token after restart prints NO_SLOTS (the parent fails:
    provisioned token absent).
    """
    role = str(extra["role"])
    attempts = int(extra["attempts"])
    stop_at = str(extra.get("stop_at", "locked"))
    if role not in ("user", "so"):
        raise ValueError(f"unknown role {role!r}")
    if stop_at not in ("locked", "final"):
        raise ValueError(f"unknown stop_at {stop_at!r}")
    setup = _setup_burn_session(ctx, role, False)
    if setup is None:
        return
    slot, sh = setup
    _burn_attempts(ctx, slot, sh, role, attempts, stop_at)
    _info_rv, flags_end, _, _ = _token_info(ctx, slot)
    if _info_rv != int(CKR_OK):
        _step("snapshot:final", _info_rv)
    _flags("final", flags_end if _info_rv == int(CKR_OK) else None)
    _quiet_close(ctx, sh)
    frv = int(ctx.raw.C_Finalize(None))
    _step("reinit:finalize", frv)
    irv = int(ctx.raw.C_Initialize(None))
    _step("reinit:initialize", irv)
    print("PHASE2")
    if frv != int(CKR_OK) or irv != int(CKR_OK):
        print("OK")
        return
    matches, enum_rv, info_refusals = _rediscover_burn_slot(ctx)
    _step("setup:phase2_enumerate", enum_rv)
    for slot, irv in info_refusals:
        # Plain info steps (not setup:*): preserved per-slot RVs that
        # document the scan without tripping the setup-failure skip.
        _step(f"info:phase2_tokeninfo_{slot}", irv)
    if enum_rv != int(CKR_OK):
        print("OK")
        return
    action, detail = _phase2_rediscovery_outcome(matches, info_refusals)
    if action == "absent":
        print("NO_SLOTS")
        print("OK")
        return
    if action == "assumption":
        print(f"ASSUMPTION_FAILED:{detail}")
        print("OK")
        return
    assert action == "proceed" and isinstance(detail, int)
    _read_phase(ctx, detail, role)
    print("OK")


_QC11C_RACE_THREADS = 4
_QC11C_RACE_PINS = (b"11111111", b"22222222", b"33333333", b"44444444")


def _qc11c_concurrent_pin(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Race user-PIN changes across threads; final state must linearize (#52.8).

    Re-initializes with OS locking (threads under the entry NULL init
    would be application misuse), then four threads race SetPIN with
    distinct new PINs from a barrier. Each thread prints login/setpin
    steps; the sequential tail tries every candidate PIN (reported
    winners first, then P0, then failed writers, so retries burn last)
    and the parent requires exactly one to work. Workers return lines
    for ordered printing (no interleaved stdout); unexpected worker
    exceptions propagate loud (harness bugs must fail, never mask).
    A provider crash or hang surfaces through the child disposition.
    """
    del extra
    setup = _setup_burn_session(ctx, "user", False)
    if setup is None:
        return
    slot, sh = setup
    _quiet_close(ctx, sh)
    frv = int(ctx.raw.C_Finalize(None))
    _step("setup:refinalize", frv)
    if frv != int(CKR_OK):
        print("OK")
        return
    args = CK_C_INITIALIZE_ARGS()
    args.flags = int(CKF_OS_LOCKING_OK)
    irv = int(ctx.raw.C_Initialize(ctypes.byref(args)))
    _step("setup:relock_init", irv)
    if irv == int(CKR_CANT_LOCK):
        print("ASSUMPTION_FAILED:cannot_lock")
        print("OK")
        return
    if irv != int(CKR_OK):
        print("OK")
        return
    barrier = threading.Barrier(_QC11C_RACE_THREADS)

    def race(index: int) -> list[tuple[str, int]]:
        lines: list[tuple[str, int]] = []
        orv, wsh = _open_rw(ctx, slot)
        lines.append((f"thread:{index}:open", orv))
        if orv == int(CKR_OK):
            try:
                lrv = _login(ctx, wsh, "user", TEST_USER_PIN)
                lines.append((f"thread:{index}:login", lrv))
                barrier.wait()
                if lrv == int(CKR_OK) or lrv == int(CKR_USER_ALREADY_LOGGED_IN):
                    new_pin = _QC11C_RACE_PINS[index]
                    srv = int(
                        ctx.raw.C_SetPIN(
                            wsh,
                            _buf(TEST_USER_PIN),
                            len(TEST_USER_PIN),
                            _buf(new_pin),
                            len(new_pin),
                        )
                    )
                    lines.append((f"thread:{index}:setpin", srv))
            finally:
                with suppress(Exception):  # best-effort per-thread cleanup  # noqa: BLE001
                    ctx.raw.C_Logout(wsh)
                with suppress(Exception):  # best-effort per-thread cleanup  # noqa: BLE001
                    ctx.raw.C_CloseSession(wsh)
        else:
            barrier.wait()
        return lines

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_QC11C_RACE_THREADS, thread_name_prefix="qc11c-race"
    ) as pool:
        results = list(pool.map(race, range(_QC11C_RACE_THREADS)))
    for lines in results:
        for name, rv in lines:
            _step(name, rv)
    # D2: verify reported winners first. Every failed tail login burns a
    # retry; trying successful writers before P0 and failed writers keeps
    # a conformant token from locking before its winner is attempted.
    winners: set[int] = set()
    for lines in results:
        for name, rv in lines:
            if name.endswith(":setpin") and rv == int(CKR_OK):
                winners.add(int(name.split(":")[1]))
    ordered = [i for i in range(_QC11C_RACE_THREADS) if i in winners]
    ordered += [i for i in range(_QC11C_RACE_THREADS) if i not in winners]
    candidates = [(f"P{i + 1}", _QC11C_RACE_PINS[i]) for i in ordered]
    candidates.insert(len(winners), ("P0", TEST_USER_PIN))
    for tag, pin in candidates:
        orv, fsh = _open_rw(ctx, slot)
        if orv != int(CKR_OK):
            _step("setup:final_open", orv)
            print("OK")
            return
        lrv = _login(ctx, fsh, "user", pin)
        _step(f"final:login:{tag}", lrv)
        _quiet_close(ctx, fsh)
    print("OK")


_PROBES: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "qc11a_burn": _qc11a_burn,
    "qc11a_read": _qc11a_read,
    "qc11a_same_process": _qc11a_same_process,
    "qc11c_concurrent_pin": _qc11c_concurrent_pin,
    "qc11b_pin_lengths": _qc11b_pin_lengths,
    "qc11c_journey": _qc11c_journey,
    "qc11c_verify": _qc11c_verify,
    "qc11c_reset": _qc11c_reset,
    "qc9b_cross_token": _qc9b_cross_token,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_run, level=Level.INIT)

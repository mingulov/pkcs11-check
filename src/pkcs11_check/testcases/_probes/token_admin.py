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

import ctypes
from collections.abc import Callable
from typing import Any, NamedTuple

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_NOTIFY,
    CK_OBJECT_HANDLE,
    CK_TOKEN_INFO,
    CKA_CLASS,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKF_USER_PIN_COUNT_LOW,
    CKF_USER_PIN_FINAL_TRY,
    CKF_USER_PIN_LOCKED,
    CKO_DATA,
    CKR_OK,
    CKR_PIN_LOCKED,
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


class AdminTrace(NamedTuple):
    steps: tuple[AdminStep, ...]
    flags: tuple[tuple[str, int | None], ...]
    pin_bounds: tuple[int, int] | None
    inv_objects: tuple[int, ...]
    ok: bool
    no_slots: bool
    assumption_failed: str | None


class TraceParseError(ValueError):
    """A known-prefix child line was malformed; always loud, never ignored."""


def _parse_hex(token: str, *, what: str) -> int:
    text = token.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise TraceParseError(f"malformed {what} hex value: {token!r}")
    return int(text, 16)


def parse_admin_trace(out: str) -> AdminTrace:
    """Parse child protocol output; unknown lines are ignored, malformed known lines fail."""
    steps: list[AdminStep] = []
    flags: list[tuple[str, int | None]] = []
    pin_bounds: tuple[int, int] | None = None
    inv_objects: list[int] = []
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
    return AdminTrace(
        steps=tuple(steps),
        flags=tuple(flags),
        pin_bounds=pin_bounds,
        inv_objects=tuple(inv_objects),
        ok=ok,
        no_slots=no_slots,
        assumption_failed=assumption_failed,
    )


def setup_failure(trace: AdminTrace) -> AdminStep | None:
    """Return the first failed ``setup:*`` step, or None when setup held."""
    for step in trace.steps:
        if step.name == "setup" or step.name.startswith("setup:"):
            if step.rv != int(CKR_OK):
                return step
    return None


def check_child_output(
    rc: int, out: str, err: str, *, label: str, no_slots: str = "skip"
) -> AdminTrace:
    """Gate one child result: crash/incomplete fail, no-slot/assumption/setup skip.

    ``no_slots="fail"`` turns a vanished token into a lifecycle failure (for
    later phases whose token was already proven present, e.g. after restart).
    """
    assert rc == 0, f"{label}: child failed (rc={rc}): {err[-300:]}"
    trace = parse_admin_trace(out)
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
    assert "OK" in out, f"{label}: child incomplete (no OK marker): {out[-300:]!r}"
    if trace.assumption_failed is not None:
        pytest.skip(f"{label}: sacrificial-token assumption failed: {trace.assumption_failed}")
    failed = setup_failure(trace)
    if failed is not None:
        pytest.skip(
            f"{label}: sacrificial setup failed: {failed.name}={ckr_name(failed.rv)}; "
            "destructive legs untestable"
        )
    return trace


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
        print("PINBOUNDS:unknown")
        print(f"ASSUMPTION_FAILED:tokeninfo:{info_rv:#x}")
        print("OK")
        return
    print(f"PINBOUNDS:{min_pin}:{max_pin}")
    print(f"FLAGS:initial:0x{flags:08x}")
    low, final, locked = _ROLE_COUNTER_FLAGS[role]
    if flags & (low | final | locked):
        print("ASSUMPTION_FAILED:not_pristine")
        print("OK")
        return
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    if role == "user":
        # InitToken establishes only the SO PIN; provision the user PIN the
        # burn is about to exercise.
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
    wrong = WRONG_SO_PIN if role == "so" else WRONG_USER_PIN
    right = TEST_SO_PIN if role == "so" else TEST_USER_PIN
    for i in range(1, attempts + 1):
        lrv = _login(ctx, sh, role, wrong)
        _step(f"login:{role}:wrong:{i}", lrv)
        _info_rv, flags_now, _, _ = _token_info(ctx, slot)
        _flags(f"attempt-{i}", flags_now if _info_rv == int(CKR_OK) else None)
        if lrv == int(CKR_PIN_LOCKED):
            break
        if stop_at == "final" and _info_rv == int(CKR_OK) and (flags_now & final):
            break
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
            _flags(f"post-{j}", flags_now if _info_rv == int(CKR_OK) else None)
    if then_other:
        other = "so" if role == "user" else "user"
        orv = _login(ctx, sh, other, TEST_SO_PIN if other == "so" else TEST_USER_PIN)
        _step(f"login:{other}:correct", orv)
    _info_rv, flags_end, _, _ = _token_info(ctx, slot)
    _flags("final", flags_end if _info_rv == int(CKR_OK) else None)
    _quiet_close(ctx, sh)
    print("OK")


def _qc11a_read(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Phase-2 persistence reader: snapshot flags, then check the correct PIN.

    Runs on the phase-1-burned token, so it takes NO pristine gate (unlike
    ``_qc11a_burn``) and performs NO provisioning (an InitToken here would wipe
    the burned counters under test).
    """
    role = str(extra["role"])
    if role not in ("user", "so"):
        raise ValueError(f"unknown role {role!r}")
    slot = _discover_slot(ctx)
    if slot is None:
        print("NO_SLOTS")
        return
    info_rv, flags, min_pin, max_pin = _token_info(ctx, slot)
    if info_rv != int(CKR_OK):
        print("PINBOUNDS:unknown")
        print("FLAGS:initial:unknown")
    else:
        print(f"PINBOUNDS:{min_pin}:{max_pin}")
        print(f"FLAGS:initial:0x{flags:08x}")
    open_rv, sh = _open_rw(ctx, slot)
    _step("setup:open", open_rv)
    if open_rv != int(CKR_OK):
        print("OK")
        return
    right = TEST_SO_PIN if role == "so" else TEST_USER_PIN
    crv = _login(ctx, sh, role, right)
    _step(f"login:{role}:correct", crv)
    try:
        ctx.raw.C_Logout(sh)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup, reported not swallowed
        print(f"CLEANUP_IGNORED:C_Logout:{type(exc).__name__}")
    _info_rv, flags_end, _, _ = _token_info(ctx, slot)
    _flags("final", flags_end if _info_rv == int(CKR_OK) else None)
    _quiet_close(ctx, sh)
    print("OK")


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


def _init_token(ctx: ProbeContext, slot: int, so_pin: bytes) -> int:
    label = b"qc11-admin-test".ljust(32)
    return int(ctx.raw.C_InitToken(slot, _buf(so_pin), len(so_pin), _buf(label)))


def _snapshot(ctx: ProbeContext, slot: int, tag: str) -> None:
    info_rv, flags, _, _ = _token_info(ctx, slot)
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
    _, _, min_pin, max_pin = _token_info(ctx, slot)
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


_PROBES: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "qc11a_burn": _qc11a_burn,
    "qc11a_read": _qc11a_read,
    "qc11b_pin_lengths": _qc11b_pin_lengths,
    "qc11c_journey": _qc11c_journey,
    "qc11c_verify": _qc11c_verify,
    "qc11c_reset": _qc11c_reset,
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

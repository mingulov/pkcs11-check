"""Crash-safe token/login probe for `pkcs11-check doctor`.

Runs in a short-lived subprocess (so a buggy module that segfaults on login is
diagnosed, not fatal). Maps C_OpenSession / C_Login return values to the three
newcomer cliffs: wrong PIN, locked PIN, and an unrecognized/uninitialized token.
The PIN is read from the P11TEST_PIN env var, never an argv (no `ps` leak), and
is never written to output.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import warnings
from dataclasses import asdict, dataclass
from pathlib import Path

from pkcs11_check.core.crash_codes import (
    crash_detail_name,
    ctypes_access_violation_code,
    is_crash_returncode,
)
from pkcs11_check.core.preflight import (
    PreflightCounters,
    append_preflight_evidence,
    collect_preflight_counters,
    preflight_child_env,
)


@dataclass(frozen=True)
class LoginProbe:
    """Result of the token/login probe."""

    status: (
        str  # ok | pin_incorrect | pin_locked | token_not_recognized | error | crashed | timeout
    )
    detail: str = ""
    returncode: int | None = None


def probe_login(module: Path, interface: str, slot: int, pin: bytes) -> LoginProbe:
    """Open a session and attempt a single C_Login, mapping the result."""
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.bootstrap import get_slot_ids
    from pkcs11_check.raw.types_std import (
        CK_NOTIFY,
        CKF_SERIAL_SESSION,
        CKR_OK,
        CKR_PIN_INCORRECT,
        CKR_PIN_LOCKED,
        CKR_TOKEN_NOT_RECOGNIZED,
        CKU_USER,
    )

    raw = RawPKCS11.from_lib(str(module), interface=interface)
    raw.C_Initialize(None)
    try:
        slot_ids = get_slot_ids(raw, token_present=True)
        if slot >= len(slot_ids):
            return LoginProbe(
                "error",
                f"slot index {slot} out of range ({len(slot_ids)} token-present slots)",
            )
        sess = ctypes.c_ulong(0)
        rv = raw.C_OpenSession(
            slot_ids[slot], int(CKF_SERIAL_SESSION), None, CK_NOTIFY(), ctypes.byref(sess)
        )
        if rv == int(CKR_TOKEN_NOT_RECOGNIZED):
            return LoginProbe(
                "token_not_recognized", "C_OpenSession returned CKR_TOKEN_NOT_RECOGNIZED"
            )
        if rv != int(CKR_OK):
            return LoginProbe("error", f"C_OpenSession returned 0x{rv:08x}")
        pin_buf = (ctypes.c_ubyte * len(pin))(*pin)
        rv = raw.C_Login(sess.value, int(CKU_USER), pin_buf, len(pin))
        try:
            raw.C_Logout(sess.value)
            raw.C_CloseSession(sess.value)
        except (AttributeError, OSError, ctypes.ArgumentError) as exc:
            if ctypes_access_violation_code(exc) is not None:
                raise
            pass  # cleanup of the probe session is best-effort
        if rv == int(CKR_OK):
            return LoginProbe("ok")
        if rv == int(CKR_PIN_INCORRECT):
            return LoginProbe("pin_incorrect")
        if rv == int(CKR_PIN_LOCKED):
            return LoginProbe("pin_locked")
        if rv == int(CKR_TOKEN_NOT_RECOGNIZED):
            return LoginProbe("token_not_recognized")
        return LoginProbe("error", f"C_Login returned 0x{rv:08x}")
    finally:
        try:
            raw.C_Finalize(None)
        except (AttributeError, OSError, ctypes.ArgumentError) as exc:
            if ctypes_access_violation_code(exc) is not None:
                raise
            pass  # finalize is best-effort during a probe


def run_login_probe_subprocess(
    module: Path,
    *,
    interface: str,
    slot: int,
    pin: bytes,
    timeout: int,
    counters: PreflightCounters | None = None,
) -> LoginProbe:
    """Run the login probe in a fresh subprocess (crash survival).

    ``counters`` engages counter collection for the probe child (the
    test-path U1 probe, preflight unit / attempt 1); ``None`` (doctor)
    keeps today's uncounted behavior with a scrubbed child env.
    Collection never alters the returned verdict and never raises:
    evidence failures warn.
    """
    env = preflight_child_env(counters)
    env["P11TEST_PIN"] = pin.decode("utf-8", "surrogateescape")
    cmd = [
        sys.executable,
        "-m",
        "pkcs11_check.core.doctor_probe",
        "--module",
        str(module),
        "--interface",
        interface,
        "--slot",
        str(slot),
    ]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        # F18: provider bytes on the pipe must not lose the login verdict.
        errors="replace",
        env=env,
    )
    raw_pid = getattr(process, "pid", None)
    child_pid = raw_pid if isinstance(raw_pid, int) else None
    try:
        out, err = process.communicate(timeout=timeout)
        returncode: int | None = process.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        # Reap without draining: wait() cannot hang on grandchildren-held
        # pipes the way a second communicate() could (R18-5 hang class).
        process.kill()
        returncode = process.wait()
        out, err = "", ""
        timed_out = True
    except KeyboardInterrupt:
        # run() parity: Ctrl-C kills the direct child instead of orphaning
        # it; the interrupt propagates (no verdict on an aborted probe).
        process.kill()
        process.wait()
        raise

    def _retain(status: str, reason: str | None) -> None:
        # Mirror of run_preflight_subprocess._retain (kept local so the
        # shipped manifest flow stays untouched); keep in sync.
        if counters is None:
            return
        try:
            records, commit = collect_preflight_counters(
                counters,
                child_pid=child_pid,
                returncode=returncode,
                timed_out=timed_out,
                manifest_status=status,
                manifest_reason=reason,
            )
        except Exception as exc:  # noqa: BLE001 -- counters never fail the probe; warn
            warnings.warn(
                f"login probe counter evidence not collected: {exc}",
                UserWarning,
                stacklevel=2,
            )
            return
        try:
            append_preflight_evidence(counters.evidence_path, records)
        except OSError as exc:
            warnings.warn(
                f"login probe counter evidence not retained: {exc}",
                UserWarning,
                stacklevel=2,
            )
            return
        commit()

    if timed_out:
        detail = f"login probe timed out after {timeout}s"
        _retain("timeout", detail)
        return LoginProbe("timeout", detail, returncode)
    assert returncode is not None
    if is_crash_returncode(returncode):
        detail = f"login probe crashed ({crash_detail_name(returncode)})"
        _retain("crashed", detail)
        return LoginProbe("crashed", detail, returncode)
    for line in reversed(out.strip().splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "status" in payload:
            _retain("ok", None)
            return LoginProbe(str(payload["status"]), str(payload.get("detail", "")), returncode)
    detail = err.strip()[-200:] or "no probe result"
    _retain("error", detail)
    return LoginProbe("error", detail, returncode)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PKCS#11 token/login probe")
    parser.add_argument("--module", required=True)
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--slot", type=int, default=0)
    return parser.parse_args()


def main() -> None:
    """Subprocess entry point: probe and print the result as one JSON line."""
    args = _parse_args()
    pin = os.environ.get("P11TEST_PIN", "").encode("utf-8", "surrogateescape")
    result = probe_login(Path(args.module), interface=args.interface, slot=args.slot, pin=pin)
    sys.stdout.write(json.dumps(asdict(result)) + "\n")


if __name__ == "__main__":
    main()

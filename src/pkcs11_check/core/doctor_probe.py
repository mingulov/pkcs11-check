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
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoginProbe:
    """Result of the token/login probe."""

    status: (
        str  # ok | pin_incorrect | pin_locked | token_not_recognized | error | crashed | timeout
    )
    detail: str = ""


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

    del interface  # raw login is interface-agnostic; kept for signature symmetry
    raw = RawPKCS11.from_lib(str(module))
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
        except (AttributeError, OSError, ctypes.ArgumentError):
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
        except (AttributeError, OSError, ctypes.ArgumentError):
            pass  # finalize is best-effort during a probe


def run_login_probe_subprocess(
    module: Path, *, interface: str, slot: int, pin: bytes, timeout: int
) -> LoginProbe:
    """Run the login probe in a fresh subprocess (crash survival)."""
    env = dict(os.environ)
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
    try:
        completed = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        return LoginProbe("timeout", f"login probe timed out after {timeout}s")
    if completed.returncode < 0:
        return LoginProbe("crashed", f"login probe crashed (signal {-completed.returncode})")
    out = completed.stdout.strip().splitlines()
    for line in reversed(out):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "status" in payload:
            return LoginProbe(str(payload["status"]), str(payload.get("detail", "")))
    return LoginProbe("error", completed.stderr.strip()[-200:] or "no probe result")


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

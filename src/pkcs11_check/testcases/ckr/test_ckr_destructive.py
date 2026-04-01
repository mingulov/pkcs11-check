"""CKR destructive token operation tests.

Tests that require modifying token state (InitToken, SetPIN, InitPIN).
Each test runs in subprocess with a TEMPORARY SoftHSM2 token to avoid
damaging the main test token.

Marked @destructive - skipped unless --p11-destructive is passed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess, pytest.mark.destructive]


def _create_temp_softhsm_token() -> tuple[str, str, str]:
    """Create a temporary SoftHSM2 token. Returns (conf_path, module_path, token_dir)."""
    token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_")
    conf_path = os.path.join(token_dir, "softhsm2.conf")
    with open(conf_path, "w") as f:
        f.write(f"directories.tokendir = {token_dir}/tokens\n")
        f.write("objectstore.backend = file\n")
    os.makedirs(os.path.join(token_dir, "tokens"), exist_ok=True)

    # Initialize token
    env = os.environ.copy()
    env["SOFTHSM2_CONF"] = conf_path
    subprocess.run(
        [
            "softhsm2-util",
            "--init-token",
            "--slot",
            "0",
            "--label",
            "ckr-temp",
            "--so-pin",
            "87654321",
            "--pin",
            "1234",
        ],
        env=env,
        capture_output=True,
        check=True,
    )
    return conf_path, "/usr/lib/softhsm/libsofthsm2.so", token_dir


def _run_destructive(test_code: str) -> tuple[int, str, str]:
    """Run a destructive test against a temporary token."""
    conf, module, token_dir = _create_temp_softhsm_token()
    script = (
        textwrap.dedent(f"""\
        import os, ctypes
        os.environ["SOFTHSM2_CONF"] = "{conf}"
        from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import (
    CKR_OK, CKR_SESSION_EXISTS, CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE, CKR_USER_NOT_LOGGED_IN, CKR_PIN_LOCKED,
    CKR_PIN_TOO_WEAK, CKR_TOKEN_NOT_INITIALIZED, CKR_ARGUMENTS_BAD,
    CKF_SERIAL_SESSION, CKF_RW_SESSION,
)
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        sc = ctypes.c_ulong(0)
        raw.C_GetSlotList(1, None, ctypes.byref(sc))
        sl = (ctypes.c_ulong * sc.value)()
        raw.C_GetSlotList(1, sl, ctypes.byref(sc))
        slot = sl[0]
    """)
        + textwrap.dedent(test_code)
        + "\nraw.C_Finalize(None)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )

    # Cleanup temp token
    import shutil

    shutil.rmtree(token_dir, ignore_errors=True)

    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestInitTokenErrors:
    """C_InitToken error conditions."""

    def test_init_token_session_exists(self) -> None:
        """C_InitToken with open session -> CKR_SESSION_EXISTS."""
        rc, out, err = _run_destructive("""\
# Open a session first
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK, f"OpenSession: 0x{rv:08x}"

# Try InitToken with session open
so_pin = b"87654321"
so_pin_buf = (ctypes.c_ubyte * len(so_pin))(*so_pin)
label = b"reinit-test     "  # 32 bytes padded
label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
rv = raw.C_InitToken(slot, so_pin_buf, len(so_pin), label_buf)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_SESSION_EXISTS, f"Expected SESSION_EXISTS, got 0x{rv:08x}"
print("OK")
raw.C_CloseSession(sess.value)
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_init_token_wrong_so_pin(self) -> None:
        """C_InitToken with wrong SO PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive("""\
wrong_pin = b"WRONGPIN"
pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
label = b"reinit-test     "
label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
rv = raw.C_InitToken(slot, pin_buf, len(wrong_pin), label_buf)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_PIN_INCORRECT, f"Expected PIN_INCORRECT, got 0x{rv:08x}"
print("OK")
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out


class TestSetPINErrors:
    """C_SetPIN error conditions."""

    def test_set_pin_wrong_old(self) -> None:
        """C_SetPIN with wrong old PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive("""\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
# Login with correct PIN first
pin = b"1234"
raw.C_Login(sh, 1, (ctypes.c_ubyte * 4)(*pin), 4)
# Try SetPIN with wrong old PIN
wrong = b"WRONG"
new_pin = b"5678"
rv = raw.C_SetPIN(sh, (ctypes.c_ubyte * 5)(*wrong), 5, (ctypes.c_ubyte * 4)(*new_pin), 4)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_PIN_INCORRECT, f"Expected PIN_INCORRECT, got 0x{rv:08x}"
print("OK")
raw.C_Logout(sh)
raw.C_CloseSession(sh)
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out


class TestInitPINErrors:
    """C_InitPIN error conditions."""

    def test_init_pin_not_logged_in(self) -> None:
        """C_InitPIN without SO login -> CKR_USER_NOT_LOGGED_IN."""
        rc, out, err = _run_destructive("""\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
# Don't login - try InitPIN
new_pin = b"9999"
rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_USER_NOT_LOGGED_IN, f"Expected USER_NOT_LOGGED_IN, got 0x{rv:08x}"
print("OK")
raw.C_CloseSession(sh)
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_init_pin_short_pin(self) -> None:
        """C_InitPIN with 1-byte PIN -> CKR_PIN_TOO_WEAK or related PIN error."""
        rc, out, err = _run_destructive("""\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
# Login as SO
so_pin = b"87654321"
rv = raw.C_Login(sh, 0, (ctypes.c_ubyte * len(so_pin))(*so_pin), len(so_pin))
assert rv == CKR_OK, f"SO login failed: 0x{rv:08x}"
# Try InitPIN with a 1-byte PIN
short_pin = b"X"
rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 1)(*short_pin), 1)
print(f"CKR:0x{rv:08x}")
ok_codes = (CKR_PIN_TOO_WEAK, CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD)
assert rv in ok_codes, (
    f"Expected PIN_TOO_WEAK/PIN_LEN_RANGE/PIN_INCORRECT/ARGUMENTS_BAD, got 0x{rv:08x}"
)
print("OK")
raw.C_Logout(sh)
raw.C_CloseSession(sh)
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_init_pin_token_not_initialized(self) -> None:
        """C_InitPIN on uninitialized token -> CKR_TOKEN_NOT_INITIALIZED."""
        token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_uninit_")
        conf_path = os.path.join(token_dir, "softhsm2.conf")
        with open(conf_path, "w") as f:
            f.write(f"directories.tokendir = {token_dir}/tokens\n")
            f.write("objectstore.backend = file\n")
        os.makedirs(os.path.join(token_dir, "tokens"), exist_ok=True)

        env = os.environ.copy()
        env["SOFTHSM2_CONF"] = conf_path
        script = textwrap.dedent(f"""\
        import os, ctypes
        os.environ["SOFTHSM2_CONF"] = "{conf_path}"
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import (
            CKR_OK, CKR_TOKEN_NOT_INITIALIZED, CKR_SLOT_ID_INVALID,
            CKF_SERIAL_SESSION, CKF_RW_SESSION,
        )
        raw = RawPKCS11.from_lib("/usr/lib/softhsm/libsofthsm2.so")
        raw.C_Initialize(None)
        sc = ctypes.c_ulong(0)
        rv = raw.C_GetSlotList(1, None, ctypes.byref(sc))
        if rv != CKR_OK:
            print(f"CKR:0x{{rv:08x}}")
            raw.C_Finalize(None)
            exit(0)
        sl = (ctypes.c_ulong * sc.value)()
        raw.C_GetSlotList(1, sl, ctypes.byref(sc))
        if sc.value == 0:
            print("NO_SLOTS")
            raw.C_Finalize(None)
            exit(0)
        slot = sl[0]
        sess = ctypes.c_ulong(0)
        rv = raw.C_OpenSession(
            slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess)
        )
        if rv != CKR_OK:
            print(f"CKR:0x{{rv:08x}}")
            raw.C_Finalize(None)
            exit(0)
        sh = sess.value
        new_pin = b"1234"
        rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
        print(f"CKR:0x{{rv:08x}}")
        print("OK")
        raw.C_CloseSession(sh)
        raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        import shutil

        shutil.rmtree(token_dir, ignore_errors=True)

        if result.returncode != 0:
            assert False, f"Crash: {result.stderr[-300:]}"
        if "NO_SLOTS" in result.stdout:
            pytest.skip("No slots available on uninitialized token")
        assert "OK" in result.stdout
        acceptable = (
            "TOKEN_NOT_INITIALIZED" in result.stdout or "USER_NOT_LOGGED_IN" in result.stdout
        )
        assert acceptable, f"Unexpected CKR in output: {result.stdout}"

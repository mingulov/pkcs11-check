"""CKR destructive token operation tests.

Tests that require modifying token state (InitToken, SetPIN, InitPIN).
Each test runs in subprocess with a TEMPORARY SoftHSM2 token to avoid
damaging the main test token.

Marked @destructive - skipped unless --p11-destructive is passed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_PIN_TOO_WEAK,
    CKR_SESSION_EXISTS,
    CKR_TOKEN_NOT_INITIALIZED,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.ckr._subprocess import (
    ckr_subprocess_cleanup_setup,
    ckr_subprocess_rv_trace_setup,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess, pytest.mark.destructive]


def _classify_destructive_ckr(out: str, expected_rvs: tuple[int, ...], *, label: str) -> None:
    """Parent-side 3-way classifier over a child script's ``CKR:0x...`` line.

    The destructive probes run in a subprocess and print ``CKR:0x{rv:08x}`` for
    the negative op under test. Classification happens here (not via an in-child
    ``assert``) so a non-spec clean reject becomes ``xfail`` instead of crashing
    the child and being mislabeled as a crash:

    - ``CKR_OK`` (the forbidden/invalid op was accepted) -> ``fail``,
    - ``rv in expected_rvs`` (spec) -> ``pass``,
    - any other clean reject code -> ``xfail``.
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            rv = int(line.removeprefix("CKR:"), 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, expected_rvs, label=label)


def _mint_throwaway_token() -> tuple[str, str, str] | None:
    """Provision a disposable token using env-configured mint command.

    Reads PKCS11_CHECK_THROWAWAY_MODULE (path to module .so) and
    PKCS11_CHECK_TOKEN_MINT_CMD (shell template; {token_dir} and {conf_path}
    are substituted). Returns (module_path, conf_path, token_dir) or None if
    either variable is unset or the mint command fails; callers skip the test.
    """
    module_path = os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE")
    mint_cmd_tmpl = os.environ.get("PKCS11_CHECK_TOKEN_MINT_CMD")
    if not module_path or not mint_cmd_tmpl:
        return None
    token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_")
    conf_path = os.path.join(token_dir, "module.conf")
    mint_cmd = mint_cmd_tmpl.format(token_dir=token_dir, conf_path=conf_path)
    proc = subprocess.run(["/bin/sh", "-c", mint_cmd], capture_output=True, check=False)
    if proc.returncode != 0:
        shutil.rmtree(token_dir, ignore_errors=True)
        return None
    return module_path, conf_path, token_dir


def _run_destructive(test_code: str) -> tuple[int, str, str]:
    """Run a destructive test against a temporary throwaway token."""
    mint_result = _mint_throwaway_token()
    if mint_result is None:
        pytest.skip(
            "throwaway-token capability not configured "
            "(set PKCS11_CHECK_THROWAWAY_MODULE and PKCS11_CHECK_TOKEN_MINT_CMD)"
        )
    module, conf_path, token_dir = mint_result
    script = (
        textwrap.dedent(f"""\
        import os, ctypes
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import (
            CKR_OK, CKR_SESSION_EXISTS, CKR_PIN_INCORRECT,
            CKR_PIN_LEN_RANGE, CKR_USER_NOT_LOGGED_IN, CKR_PIN_LOCKED,
            CKR_PIN_TOO_WEAK, CKR_TOKEN_NOT_INITIALIZED, CKR_ARGUMENTS_BAD,
            CKF_SERIAL_SESSION, CKF_RW_SESSION,
        )
        raw = RawPKCS11.from_lib("{module}")
{ckr_subprocess_rv_trace_setup(indent="        ")}
        raw.C_Initialize(None)
        sc = ctypes.c_ulong(0)
        raw.C_GetSlotList(1, None, ctypes.byref(sc))
        sl = (ctypes.c_ulong * sc.value)()
        raw.C_GetSlotList(1, sl, ctypes.byref(sc))
        slot = sl[0]
    """)
        + textwrap.dedent(test_code)
        + textwrap.dedent("""\
        _p11check_cleanup = globals().get("_p11check_cleanup_session")
        if _p11check_cleanup is not None:
            _p11check_cleanup()
        else:
            raw.C_Finalize(None)
    """)
    )

    env = os.environ.copy()
    conf_env_var = os.environ.get("PKCS11_CHECK_TOKEN_CONF_ENV")
    if conf_env_var:
        env[conf_env_var] = conf_path

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )

    shutil.rmtree(token_dir, ignore_errors=True)

    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestInitTokenErrors:
    """C_InitToken error conditions."""

    def test_init_token_session_exists(self) -> None:
        """C_InitToken with open session -> CKR_SESSION_EXISTS."""
        rc, out, err = _run_destructive(
            """\
# Open a session first
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK, f"OpenSession: 0x{rv:08x}"
sh = sess.value
"""
            + ckr_subprocess_cleanup_setup()
            + """\

# Try InitToken with session open
so_pin = b"87654321"
so_pin_buf = (ctypes.c_ubyte * len(so_pin))(*so_pin)
label = b"reinit-test     "  # 32 bytes padded
label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
rv = raw.C_InitToken(slot, so_pin_buf, len(so_pin), label_buf)
print(f"CKR:0x{rv:08x}")
print("OK")
"""
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_SESSION_EXISTS,), label="C_InitToken with an open session"
        )

    def test_init_token_wrong_so_pin(self) -> None:
        """C_InitToken with wrong SO PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive("""\
wrong_pin = b"WRONGPIN"
pin_buf = (ctypes.c_ubyte * len(wrong_pin))(*wrong_pin)
label = b"reinit-test     "
label_buf = (ctypes.c_ubyte * 32)(*label.ljust(32))
rv = raw.C_InitToken(slot, pin_buf, len(wrong_pin), label_buf)
print(f"CKR:0x{rv:08x}")
print("OK")
""")
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_PIN_INCORRECT,), label="C_InitToken with a wrong SO PIN"
        )


class TestSetPINErrors:
    """C_SetPIN error conditions."""

    def test_set_pin_wrong_old(self) -> None:
        """C_SetPIN with wrong old PIN -> CKR_PIN_INCORRECT."""
        rc, out, err = _run_destructive(
            """\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
"""
            + ckr_subprocess_cleanup_setup()
            + """\
# Login with correct PIN first
pin = b"1234"
raw.C_Login(sh, 1, (ctypes.c_ubyte * 4)(*pin), 4)
# Try SetPIN with wrong old PIN
wrong = b"WRONG"
new_pin = b"5678"
rv = raw.C_SetPIN(sh, (ctypes.c_ubyte * 5)(*wrong), 5, (ctypes.c_ubyte * 4)(*new_pin), 4)
print(f"CKR:0x{rv:08x}")
print("OK")
raw.C_Logout(sh)
"""
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(out, (CKR_PIN_INCORRECT,), label="C_SetPIN with a wrong old PIN")


class TestInitPINErrors:
    """C_InitPIN error conditions."""

    def test_init_pin_not_logged_in(self) -> None:
        """C_InitPIN without SO login -> CKR_USER_NOT_LOGGED_IN."""
        rc, out, err = _run_destructive(
            """\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
"""
            + ckr_subprocess_cleanup_setup()
            + """\
# Don't login - try InitPIN
new_pin = b"9999"
rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
print(f"CKR:0x{rv:08x}")
print("OK")
"""
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out, (CKR_USER_NOT_LOGGED_IN,), label="C_InitPIN without SO login"
        )

    def test_init_pin_short_pin(self) -> None:
        """C_InitPIN with 1-byte PIN -> CKR_PIN_TOO_WEAK or related PIN error."""
        rc, out, err = _run_destructive(
            """\
sess = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
assert rv == CKR_OK
sh = sess.value
"""
            + ckr_subprocess_cleanup_setup()
            + """\
# Login as SO
so_pin = b"87654321"
rv = raw.C_Login(sh, 0, (ctypes.c_ubyte * len(so_pin))(*so_pin), len(so_pin))
assert rv == CKR_OK, f"SO login failed: 0x{rv:08x}"
# Try InitPIN with a 1-byte PIN
short_pin = b"X"
rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 1)(*short_pin), 1)
print(f"CKR:0x{rv:08x}")
print("OK")
raw.C_Logout(sh)
"""
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        _classify_destructive_ckr(
            out,
            (CKR_PIN_TOO_WEAK, CKR_PIN_LEN_RANGE, CKR_PIN_INCORRECT, CKR_ARGUMENTS_BAD),
            label="C_InitPIN with a 1-byte PIN (weak/too-short)",
        )

    def test_init_pin_token_not_initialized(self) -> None:
        """C_InitPIN on uninitialized token -> CKR_TOKEN_NOT_INITIALIZED."""
        if not os.environ.get("PKCS11_CHECK_THROWAWAY_MODULE"):
            pytest.skip("throwaway module not configured (PKCS11_CHECK_THROWAWAY_MODULE unset)")
        token_dir = tempfile.mkdtemp(prefix="pkcs11_check_ckr_uninit_")
        # This test writes a SoftHSM2-style uninitialized-token config and therefore
        # assumes the configured throwaway module is SoftHSM2-compatible.
        conf_path = os.path.join(token_dir, "module.conf")
        with open(conf_path, "w") as f:
            f.write(f"directories.tokendir = {token_dir}/tokens\n")
            f.write("objectstore.backend = file\n")
        os.makedirs(os.path.join(token_dir, "tokens"), exist_ok=True)

        env = os.environ.copy()
        conf_env_var = os.environ.get("PKCS11_CHECK_TOKEN_CONF_ENV")
        if conf_env_var:
            env[conf_env_var] = conf_path
        script = textwrap.dedent(f"""\
        import os, ctypes
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import (
            CKR_OK, CKR_TOKEN_NOT_INITIALIZED, CKR_SLOT_ID_INVALID,
            CKF_SERIAL_SESSION, CKF_RW_SESSION,
        )
        raw = RawPKCS11.from_lib(os.environ["PKCS11_CHECK_THROWAWAY_MODULE"])
{ckr_subprocess_rv_trace_setup(indent="        ")}
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
{ckr_subprocess_cleanup_setup(indent="        ")}
        new_pin = b"1234"
        rv = raw.C_InitPIN(sh, (ctypes.c_ubyte * 4)(*new_pin), 4)
        print(f"CKR:0x{{rv:08x}}")
        print("OK")
        _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        shutil.rmtree(token_dir, ignore_errors=True)

        if result.returncode != 0:
            assert False, f"Crash: {result.stderr[-300:]}"
        if "NO_SLOTS" in result.stdout:
            pytest.skip("No slots available on uninitialized token")
        assert "OK" in result.stdout
        _classify_destructive_ckr(
            result.stdout,
            (CKR_TOKEN_NOT_INITIALIZED, CKR_USER_NOT_LOGGED_IN),
            label="C_InitPIN on an uninitialized token",
        )

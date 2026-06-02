"""CKR multipart operation error tests via raw ctypes calls.

Tests CKR conditions that python-pkcs11 wrapper prevents:
- C_EncryptUpdate/Final without C_EncryptInit
- C_DecryptUpdate/Final without C_DecryptInit
- C_SignUpdate/Final without C_SignInit
- C_DigestUpdate/Final without C_DigestInit

All tests run in subprocess for safety (raw calls can crash on bugs).

Requires: pkcs11.raw.RawPKCS11
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OPERATION_NOT_INITIALIZED
from pkcs11_check.testcases.ckr._subprocess import (
    assert_ckr_subprocess_ok,
    ckr_subprocess_rv_trace_setup,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_multipart_ckr(out: str, *, label: str) -> None:
    """Parent-side 3-way classifier over a child script's ``CKR:0x...`` line.

    A C_*Update/Final without the matching C_*Init must reject with
    CKR_OPERATION_NOT_INITIALIZED. Classification happens here (not via an
    in-child ``assert``) so a non-spec clean reject becomes ``xfail`` instead of
    crashing the child and being mislabeled as a crash:

    - ``CKR_OK`` (the multipart op ran without init) -> ``fail``,
    - ``CKR_OPERATION_NOT_INITIALIZED`` (spec) -> ``pass``,
    - any other clean reject code -> ``xfail``.
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            rv = int(line.removeprefix("CKR:"), 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, (CKR_OPERATION_NOT_INITIALIZED,), label=label)


def _run_raw_test(module_path: str, pin: str | None, test_code: str) -> tuple[int, str, str]:
    """Run a raw PKCS#11 test in subprocess."""
    pin_arg = f'"{pin}"' if pin else "None"
    script = textwrap.dedent(f"""\
        import ctypes, os
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.types_std import (
            CK_NOTIFY, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_OK,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_OPERATION_ACTIVE, CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_BUFFER_TOO_SMALL, CKR_DATA_LEN_RANGE,
            CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
            CKR_ARGUMENTS_BAD, CKR_MECHANISM_INVALID,
        )

        raw = RawPKCS11.from_lib("{module_path}")
{ckr_subprocess_rv_trace_setup(indent="        ")}
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED), f"Init failed: 0x{{rv:08x}}"

        # Get first slot
        slot_count = ctypes.c_ulong(0)
        raw.C_GetSlotList(1, None, ctypes.byref(slot_count))
        slots = (ctypes.c_ulong * slot_count.value)()
        raw.C_GetSlotList(1, slots, ctypes.byref(slot_count))

        # Open session (use CK_NOTIFY() to create null function pointer)
        session = ctypes.c_ulong(0)
        rv = raw.C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               None, CK_NOTIFY(), ctypes.byref(session))
        assert rv == CKR_OK, f"OpenSession failed: 0x{{rv:08x}}"
        sh = session.value

        # Login if needed
        pin = {pin_arg}
        if pin:
            pin_bytes = pin.encode()
            pin_buf = (ctypes.c_ubyte * len(pin_bytes))(*pin_bytes)
            raw.C_Login(sh, 1, pin_buf, len(pin_bytes))

{textwrap.indent(textwrap.dedent(test_code), "        ")}

        raw.C_CloseSession(sh)
        raw.C_Finalize(None)
    """)
    import os

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestMultipartNotInitialized:
    """C_*Update/Final without Init -> CKR_OPERATION_NOT_INITIALIZED."""

    def test_encrypt_update_no_init(self, p11_config: Any) -> None:
        """C_EncryptUpdate without C_EncryptInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            data = (ctypes.c_ubyte * 16)(*([0]*16))
            out = (ctypes.c_ubyte * 32)()
            out_len = ctypes.c_ulong(32)
            rv = raw.C_EncryptUpdate(sh, data, 16, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptUpdate without init")
        _classify_multipart_ckr(out, label="C_EncryptUpdate without C_EncryptInit")

    def test_encrypt_final_no_init(self, p11_config: Any) -> None:
        """C_EncryptFinal without C_EncryptInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            out = (ctypes.c_ubyte * 32)()
            out_len = ctypes.c_ulong(32)
            rv = raw.C_EncryptFinal(sh, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptFinal without init")
        _classify_multipart_ckr(out, label="C_EncryptFinal without C_EncryptInit")

    def test_decrypt_update_no_init(self, p11_config: Any) -> None:
        """C_DecryptUpdate without C_DecryptInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            data = (ctypes.c_ubyte * 16)(*([0]*16))
            out = (ctypes.c_ubyte * 32)()
            out_len = ctypes.c_ulong(32)
            rv = raw.C_DecryptUpdate(sh, data, 16, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptUpdate without init")
        _classify_multipart_ckr(out, label="C_DecryptUpdate without C_DecryptInit")

    def test_sign_update_no_init(self, p11_config: Any) -> None:
        """C_SignUpdate without C_SignInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            data = (ctypes.c_ubyte * 16)(*([0]*16))
            rv = raw.C_SignUpdate(sh, data, 16)
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignUpdate without init")
        _classify_multipart_ckr(out, label="C_SignUpdate without C_SignInit")

    def test_digest_update_no_init(self, p11_config: Any) -> None:
        """C_DigestUpdate without C_DigestInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            data = (ctypes.c_ubyte * 16)(*([0]*16))
            rv = raw.C_DigestUpdate(sh, data, 16)
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_DigestUpdate without init")
        _classify_multipart_ckr(out, label="C_DigestUpdate without C_DigestInit")

    def test_digest_final_no_init(self, p11_config: Any) -> None:
        """C_DigestFinal without C_DigestInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            out = (ctypes.c_ubyte * 64)()
            out_len = ctypes.c_ulong(64)
            rv = raw.C_DigestFinal(sh, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_DigestFinal without init")
        _classify_multipart_ckr(out, label="C_DigestFinal without C_DigestInit")

    def test_decrypt_final_no_init(self, p11_config: Any) -> None:
        """C_DecryptFinal without C_DecryptInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            out = (ctypes.c_ubyte * 32)()
            out_len = ctypes.c_ulong(32)
            rv = raw.C_DecryptFinal(sh, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptFinal without init")
        _classify_multipart_ckr(out, label="C_DecryptFinal without C_DecryptInit")

    def test_sign_final_no_init(self, p11_config: Any) -> None:
        """C_SignFinal without C_SignInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            out = (ctypes.c_ubyte * 256)()
            out_len = ctypes.c_ulong(256)
            rv = raw.C_SignFinal(sh, out, ctypes.byref(out_len))
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignFinal without init")
        _classify_multipart_ckr(out, label="C_SignFinal without C_SignInit")

    def test_verify_update_no_init(self, p11_config: Any) -> None:
        """C_VerifyUpdate without C_VerifyInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            data = (ctypes.c_ubyte * 16)(*([0]*16))
            rv = raw.C_VerifyUpdate(sh, data, 16)
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_VerifyUpdate without init")
        _classify_multipart_ckr(out, label="C_VerifyUpdate without C_VerifyInit")

    def test_verify_final_no_init(self, p11_config: Any) -> None:
        """C_VerifyFinal without C_VerifyInit."""
        rc, out, err = _run_raw_test(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
            sig = (ctypes.c_ubyte * 32)(*([0]*32))
            rv = raw.C_VerifyFinal(sh, sig, 32)
            print(f"CKR:0x{rv:08x}")
            print("OK")
            """,
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_VerifyFinal without init")
        _classify_multipart_ckr(out, label="C_VerifyFinal without C_VerifyInit")

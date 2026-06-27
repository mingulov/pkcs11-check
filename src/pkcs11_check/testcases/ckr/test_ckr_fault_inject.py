"""CKR fault injection tests via proxy module.

Tests that the test framework correctly handles device/token errors
by loading the fault-proxy.so which wraps a real PKCS#11 module.

Requires: fault-proxy.so available as P11TEST_FAULT_PROXY_SO or at
/usr/lib/pkcs11/fault-proxy.so.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.testcases.ckr._subprocess import (
    assert_ckr_subprocess_ok,
    ckr_subprocess_cleanup_setup,
    ckr_subprocess_rv_trace_setup,
)

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_FAULT_PROXY_PATHS = [
    Path("/usr/lib/pkcs11/fault-proxy.so"),
]
# Explicit override (set by an external harness/conftest).
_env_proxy = os.environ.get("P11TEST_FAULT_PROXY_SO")
if _env_proxy:
    _FAULT_PROXY_PATHS.insert(0, Path(_env_proxy))

_PROXY_PATH = next((p for p in _FAULT_PROXY_PATHS if p.exists()), None)


def _skip_if_no_proxy() -> None:
    """Skip if fault-proxy.so is not built."""
    if _PROXY_PATH is None or not _PROXY_PATH.exists():
        pytest.skip(
            "fault-proxy not available (set P11TEST_FAULT_PROXY_SO or install to /usr/lib/pkcs11/)"
        )


class TestFaultInjection:
    """Real error injection via fault-proxy."""

    def test_inject_device_removed_on_encrypt(self, p11_config: Any) -> None:
        """Inject CKR_DEVICE_REMOVED on C_Encrypt."""
        _skip_if_no_proxy()
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import os, ctypes
            from ctypes import byref
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.recipes import gen_aes_key
            from pkcs11_check.raw.pack import mech_simple
            from pkcs11_check.raw.rv import ckr_name
            from pkcs11_check.raw.types_std import (
                CK_ULONG, CKF_RW_SESSION, CKF_SERIAL_SESSION,
                CKM_AES_ECB, CKR_DEVICE_REMOVED, CKR_OK, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_Encrypt"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000032"  # CKR_DEVICE_REMOVED
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], (CKF_SERIAL_SESSION | CKF_RW_SESSION))
{ckr_subprocess_cleanup_setup(indent="            ")}
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, CKU_USER, pin.encode())
            try:
                key = gen_aes_key(raw, sh, 256)
            except AssertionError as exc:
                print(f"SETUP_XFAIL:C_GenerateKey for fault-injected encrypt failed: {{exc}}")
            else:
                mech = mech_simple(CKM_AES_ECB)
                rv = raw.C_EncryptInit(sh, mech.byref(), key)
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_EncryptInit for fault injection failed: {{ckr_name(rv)}}")
                else:
                    data = (ctypes.c_ubyte * 16)(*([0] * 16))
                    out_len = CK_ULONG(32)
                    out_buf = (ctypes.c_ubyte * 32)()
                    rv = raw.C_Encrypt(sh, data, 16, out_buf, byref(out_len))
                    if rv == CKR_DEVICE_REMOVED:
                        print("OK:DEVICE_REMOVED")
                    elif rv == CKR_OK:
                        print("FAIL:no_error")
                    else:
                        print(f"OTHER:0x{{rv:08x}}")
            _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy C_Encrypt CKR_DEVICE_REMOVED injection",
        )
        assert "OK:DEVICE_REMOVED" in result.stdout

    def test_inject_device_error_on_sign(self, p11_config: Any) -> None:
        """Inject CKR_DEVICE_ERROR on C_Sign."""
        _skip_if_no_proxy()
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import os, ctypes
            from ctypes import byref
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.recipes import gen_rsa_keypair
            from pkcs11_check.raw.pack import mech_simple
            from pkcs11_check.raw.rv import ckr_name
            from pkcs11_check.raw.types_std import (
                CK_ULONG, CKF_RW_SESSION, CKF_SERIAL_SESSION,
                CKM_SHA256_RSA_PKCS, CKR_DEVICE_ERROR, CKR_OK, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_Sign"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000030"  # CKR_DEVICE_ERROR
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], (CKF_SERIAL_SESSION | CKF_RW_SESSION))
{ckr_subprocess_cleanup_setup(indent="            ")}
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, CKU_USER, pin.encode())
            try:
                _pub, priv = gen_rsa_keypair(raw, sh, 2048)
            except AssertionError as exc:
                print(f"SETUP_XFAIL:C_GenerateKeyPair for fault-injected sign failed: {{exc}}")
            else:
                mech = mech_simple(CKM_SHA256_RSA_PKCS)
                rv = raw.C_SignInit(sh, mech.byref(), priv)
                if rv != CKR_OK:
                    print(f"SETUP_XFAIL:C_SignInit for fault injection failed: {{ckr_name(rv)}}")
                else:
                    data = (ctypes.c_ubyte * 4)(*b"test")
                    sig_len = CK_ULONG(256)
                    sig_buf = (ctypes.c_ubyte * 256)()
                    rv = raw.C_Sign(sh, data, 4, sig_buf, byref(sig_len))
                    if rv == CKR_DEVICE_ERROR:
                        print("OK:DEVICE_ERROR")
                    elif rv == CKR_OK:
                        print("FAIL:no_error")
                    else:
                        print(f"OTHER:0x{{rv:08x}}")
            _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy C_Sign CKR_DEVICE_ERROR injection",
        )
        assert "OK:DEVICE_ERROR" in result.stdout

    def test_inject_device_memory_on_generate_key(self, p11_config: Any) -> None:
        """Inject CKR_DEVICE_MEMORY on C_GenerateKey."""
        _skip_if_no_proxy()
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import os, ctypes
            from ctypes import byref
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
            from pkcs11_check.raw.types_std import (
                CK_OBJECT_HANDLE, CKA_VALUE_LEN,
                CKF_RW_SESSION, CKF_SERIAL_SESSION,
                CKM_AES_KEY_GEN, CKR_DEVICE_MEMORY, CKR_OK, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_GenerateKey"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000031"  # CKR_DEVICE_MEMORY
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], (CKF_SERIAL_SESSION | CKF_RW_SESSION))
{ckr_subprocess_cleanup_setup(indent="            ")}
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, CKU_USER, pin.encode())
            mech = mech_simple(CKM_AES_KEY_GEN)
            tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
            key = CK_OBJECT_HANDLE(0)
            rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
            if rv == CKR_DEVICE_MEMORY:
                print("OK:DEVICE_MEMORY")
            elif rv == CKR_OK:
                print("FAIL:no_error")
            else:
                print(f"OTHER:0x{{rv:08x}}")
            _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy C_GenerateKey CKR_DEVICE_MEMORY injection",
        )
        assert "OK:DEVICE_MEMORY" in result.stdout


class TestFaultProxyBasic:
    """Verify fault-proxy loads and delegates correctly."""

    def test_proxy_loads_real_module(self, p11_config: Any) -> None:
        """Proxy loads real module and lists slots."""
        _skip_if_no_proxy()
        module = str(p11_config.module)

        script = textwrap.dedent(f"""\
            import os
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            print(f"OK:{{len(slots)}}_slots")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy slot delegation",
        )
        assert "OK:" in result.stdout

    def test_proxy_encrypt_decrypt(self, p11_config: Any) -> None:
        """Proxy supports full encrypt/decrypt cycle."""
        _skip_if_no_proxy()
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import os
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.recipes import gen_aes_key, encrypt_single, decrypt_single
            from pkcs11_check.raw.types_std import (
                CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_AES_ECB, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
{ckr_subprocess_rv_trace_setup(indent="            ")}
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], (CKF_SERIAL_SESSION | CKF_RW_SESSION))
{ckr_subprocess_cleanup_setup(indent="            ")}
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, CKU_USER, pin.encode())
            try:
                key = gen_aes_key(raw, sh, 256)
            except AssertionError as exc:
                print(f"SETUP_XFAIL:C_GenerateKey for proxy roundtrip failed: {{exc}}")
            else:
                ct = encrypt_single(raw, sh, key, CKM_AES_ECB, b"\\x00" * 16)
                pt = decrypt_single(raw, sh, key, CKM_AES_ECB, ct)
                assert pt == b"\\x00" * 16
                print("OK:encrypt_decrypt_roundtrip")
            _p11check_cleanup_session()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy AES roundtrip delegation",
        )
        assert "OK:" in result.stdout

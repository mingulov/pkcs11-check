"""CKR fault injection tests via proxy module.

Tests that the test framework correctly handles device/token errors
by loading the fault-proxy.so which wraps a real PKCS#11 module.

Requires: fault-proxy.so built (bash local-builds/build.sh fault-proxy).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_PROXY_PATH = Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so"


def _skip_if_no_proxy() -> None:
    """Skip if fault-proxy.so is not built."""
    if not _PROXY_PATH.exists():
        pytest.skip("fault-proxy not built (run: bash local-builds/build.sh fault-proxy)")


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
            from pkcs11_check.raw.types_std import (
                CK_ULONG, CKF_RW_SESSION, CKF_SERIAL_SESSION,
                CKM_AES_ECB, CKR_DEVICE_REMOVED, CKR_OK, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_Encrypt"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000032"  # CKR_DEVICE_REMOVED
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            key = gen_aes_key(raw, sh, 256)
            mech = mech_simple(CKM_AES_ECB)
            rv = int(raw.C_EncryptInit(sh, mech.byref(), key))
            if rv != int(CKR_OK):
                print(f"FAIL:init_error:0x{{rv:08x}}")
            else:
                data = (ctypes.c_ubyte * 16)(*([0] * 16))
                out_len = CK_ULONG(32)
                out_buf = (ctypes.c_ubyte * 32)()
                rv = int(raw.C_Encrypt(sh, data, 16, out_buf, byref(out_len)))
                if rv == int(CKR_DEVICE_REMOVED):
                    print("OK:DEVICE_REMOVED")
                elif rv == int(CKR_OK):
                    print("FAIL:no_error")
                else:
                    print(f"OTHER:0x{{rv:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
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
            from pkcs11_check.raw.types_std import (
                CK_ULONG, CKF_RW_SESSION, CKF_SERIAL_SESSION,
                CKM_SHA256_RSA_PKCS, CKR_DEVICE_ERROR, CKR_OK, CKU_USER,
            )
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            os.environ["PKCS11_INJECT_FUNCTION"] = "C_Sign"
            os.environ["PKCS11_INJECT_ERROR"] = "0x00000030"  # CKR_DEVICE_ERROR
            raw = RawPKCS11.from_lib("{_PROXY_PATH}")
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            _pub, priv = gen_rsa_keypair(raw, sh, 2048)
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = int(raw.C_SignInit(sh, mech.byref(), priv))
            if rv != int(CKR_OK):
                print(f"FAIL:sign_init_error:0x{{rv:08x}}")
            else:
                data = (ctypes.c_ubyte * 4)(*b"test")
                sig_len = CK_ULONG(256)
                sig_buf = (ctypes.c_ubyte * 256)()
                rv = int(raw.C_Sign(sh, data, 4, sig_buf, byref(sig_len)))
                if rv == int(CKR_DEVICE_ERROR):
                    print("OK:DEVICE_ERROR")
                elif rv == int(CKR_OK):
                    print("FAIL:no_error")
                else:
                    print(f"OTHER:0x{{rv:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
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
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            mech = mech_simple(CKM_AES_KEY_GEN)
            tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
            key = CK_OBJECT_HANDLE(0)
            rv = int(raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key)))
            if rv == int(CKR_DEVICE_MEMORY):
                print("OK:DEVICE_MEMORY")
            elif rv == int(CKR_OK):
                print("FAIL:no_error")
            else:
                print(f"OTHER:0x{{rv:08x}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Crash: {result.stderr[-200:]}"
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
        assert result.returncode == 0, f"Proxy failed: {result.stderr}"
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
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            key = gen_aes_key(raw, sh, 256)
            ct = encrypt_single(raw, sh, key, CKM_AES_ECB, b"\\x00" * 16)
            pt = decrypt_single(raw, sh, key, CKM_AES_ECB, ct)
            assert pt == b"\\x00" * 16
            print("OK:encrypt_decrypt_roundtrip")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Proxy encrypt/decrypt failed: {result.stderr}"
        assert "OK:" in result.stdout

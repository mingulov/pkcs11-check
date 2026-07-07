"""CKR fault injection tests via proxy module.

Tests that the test framework correctly handles device/token errors
by loading the fault-proxy.so which wraps a real PKCS#11 module.

Requires: fault-proxy.so available as P11TEST_FAULT_PROXY_SO or at
/usr/lib/pkcs11/fault-proxy.so.

Each test launches the ``ckr_fault_inject`` probe module (``_probes/ckr_fault_inject.py``)
via ``run_probe``.  ``module_path`` is the fault-proxy; the real provider + injection config
ride in the probe params as plain data (``real_module`` / ``inject_function`` / ``inject_error``,
never a PIN) and the probe sets them into the child environment before the proxy loads.  The four
session probes run at ``Level.LOGIN``: the probe opens a session and -- only when a PIN is
configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN`` env var (never
embedded in source or params -- Invariant I3).  This CLOSES the legacy leak that formatted the PIN
literal into the generated child-script source.  Raw calls run in the subprocess for crash
survival.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

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
        result = run_probe(
            "ckr_fault_inject",
            {
                "module_path": str(_PROXY_PATH),
                "probe": "inject_device_removed_on_encrypt",
                "real_module": str(p11_config.module),
                "inject_function": "C_Encrypt",
                "inject_error": "0x00000032",  # CKR_DEVICE_REMOVED
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
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
        result = run_probe(
            "ckr_fault_inject",
            {
                "module_path": str(_PROXY_PATH),
                "probe": "inject_device_error_on_sign",
                "real_module": str(p11_config.module),
                "inject_function": "C_Sign",
                "inject_error": "0x00000030",  # CKR_DEVICE_ERROR
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
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
        result = run_probe(
            "ckr_fault_inject",
            {
                "module_path": str(_PROXY_PATH),
                "probe": "inject_device_memory_on_generate_key",
                "real_module": str(p11_config.module),
                "inject_function": "C_GenerateKey",
                "inject_error": "0x00000031",  # CKR_DEVICE_MEMORY
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
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
        result = run_probe(
            "ckr_fault_inject",
            {
                "module_path": str(_PROXY_PATH),
                "probe": "proxy_loads_real_module",
                "real_module": str(p11_config.module),
            },
            timeout=15,
            coverage="session",
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
        result = run_probe(
            "ckr_fault_inject",
            {
                "module_path": str(_PROXY_PATH),
                "probe": "proxy_encrypt_decrypt",
                "real_module": str(p11_config.module),
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_ckr_subprocess_ok(
            result.returncode,
            result.stdout,
            result.stderr,
            context="fault-proxy AES roundtrip delegation",
        )
        assert "OK:" in result.stdout

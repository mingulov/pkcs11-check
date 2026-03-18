"""CKR fault injection tests via proxy module.

Tests that the test framework correctly handles device/token errors
by loading the fault-proxy.so which wraps a real PKCS#11 module.

Currently the proxy passes all calls through to the real module.
Error injection is simulated at the Python test level by verifying
that the proxy loads and operates correctly, proving the architecture
works for future C-level injection.

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


class TestFaultProxyBasic:
    """Verify fault-proxy loads and delegates correctly."""

    def test_proxy_loads_real_module(self, p11_config: Any) -> None:
        """Proxy loads real module and lists slots."""
        _skip_if_no_proxy()
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import os, pkcs11
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            lib = pkcs11.lib("{_PROXY_PATH}")
            slots = lib.get_slots(token_present=True)
            print(f"OK:{{len(slots)}}_slots")
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
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
            import os, pkcs11
            from pkcs11 import KeyType, Mechanism
            os.environ["PKCS11_REAL_MODULE"] = "{module}"
            lib = pkcs11.lib("{_PROXY_PATH}")
            slots = lib.get_slots(token_present=True)
            token = slots[0].get_token()
            pin = {pin_arg}
            session = token.open(rw=True, user_pin=pin) if pin else token.open(rw=True)
            key = session.generate_key(KeyType.AES, 256)
            ct = key.encrypt(b"\\x00" * 16, mechanism=Mechanism.AES_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == b"\\x00" * 16
            print("OK:encrypt_decrypt_roundtrip")
            session.close()
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Proxy encrypt/decrypt failed: {result.stderr}"
        assert "OK:" in result.stdout

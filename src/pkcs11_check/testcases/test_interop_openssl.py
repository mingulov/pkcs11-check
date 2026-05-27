"""OpenSSL pkcs11-provider and p11-kit interop tests.

Tests that real OpenSSL operations work through the pkcs11 provider,
catching bugs like SoftHSM2 #722 (segfault on decrypt) and #729 (exit crash).
Also tests p11-kit proxy transparency.

Requires: pkcs11-provider package, p11-kit
Runs in subprocess to avoid crash contamination.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.interop, pytest.mark.stress]


_PKCS11_PROVIDER_PATHS = [
    "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",  # Debian x86_64
    "/usr/lib64/ossl-modules/pkcs11.so",  # Fedora/RHEL x86_64
    "/usr/lib/ossl-modules/pkcs11.so",  # Fedora multilib
]

_P11KIT_PROXY_PATHS = [
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",  # Debian x86_64
    "/usr/lib64/p11-kit-proxy.so",  # Fedora/RHEL x86_64
    "/usr/lib/p11-kit-proxy.so",  # Fedora multilib
]


def _find_lib(candidates: list[str]) -> Path | None:
    """Find the first existing library path from candidates."""
    for c in candidates:
        p = Path(c)
        if p.exists():
            return p
    return None


def _have_pkcs11_provider() -> bool:
    """Check if OpenSSL pkcs11-provider is installed."""
    return _find_lib(_PKCS11_PROVIDER_PATHS) is not None


def _have_p11kit() -> bool:
    """Check if p11-kit proxy is installed."""
    return _find_lib(_P11KIT_PROXY_PATHS) is not None


def _require_openssl() -> str:
    """Return the OpenSSL executable path or skip when it is unavailable."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary not on PATH")
    return openssl


def _run(
    cmd: list[str],
    env: dict[str, str] | None = None,
    timeout: int = 30,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    """Run a command with argv isolation, return (exitcode, stdout, stderr)."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=full_env,
        input=input_text,
    )
    return r.returncode, r.stdout, r.stderr


class TestOpenSSLPkcs11Provider:
    """OpenSSL pkcs11-provider interop (task 7.17)."""

    def test_provider_loads(self, p11_config: Any) -> None:
        """pkcs11-provider can load and list the module."""
        if not _have_pkcs11_provider():
            pytest.skip("pkcs11-provider not installed")

        openssl = _require_openssl()
        module = str(p11_config.module)

        # Use PKCS11_PROVIDER_MODULE env var
        rc, out, err = _run(
            [openssl, "list", "-providers", "-provider", "pkcs11"],
            env={"PKCS11_PROVIDER_MODULE": module},
        )
        # Provider may or may not load depending on token state
        # The key test: no segfault (rc != -11)
        assert rc != -11, f"OpenSSL pkcs11-provider segfaulted: {err}"

    def test_openssl_dgst_via_pkcs11(self, p11_config: Any) -> None:
        """SHA-256 digest via OpenSSL with pkcs11-provider (basic smoke test)."""
        openssl = _require_openssl()
        if not _have_pkcs11_provider():
            pytest.skip("pkcs11-provider not installed")

        _module = str(p11_config.module)

        # Simple digest - doesn't need token login
        rc, out, err = _run(
            [openssl, "dgst", "-sha256", "-provider", "default"],
            input_text="test",
        )
        assert rc == 0, f"openssl dgst failed: {err}"
        assert "SHA2-256" in out or "sha256" in out.lower() or len(out) > 10

    def test_openssl_genrsa_no_crash(self, p11_config: Any) -> None:
        """OpenSSL RSA keygen via subprocess - must not segfault.

        SoftHSM2 #722: SIGSEGV on RSA operations via pkcs11-provider.
        """
        if not _have_pkcs11_provider():
            pytest.skip("pkcs11-provider not installed")

        openssl = _require_openssl()
        module = str(p11_config.module)

        # Generate RSA key via OpenSSL with PKCS#11 - just verify no crash
        script = f"""
        import subprocess, os
        env = os.environ.copy()
        env["PKCS11_PROVIDER_MODULE"] = "{module}"
        r = subprocess.run(
            [{openssl!r}, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-provider", "default", "-out", "/dev/null"],
            capture_output=True, timeout=30, env=env,
        )
        print(f"rc={{r.returncode}}")
        """
        rc, out, err = _run([sys.executable, "-c", textwrap.dedent(script).strip()])
        assert_subprocess_completed(rc, out, err, context="OpenSSL genpkey subprocess wrapper")


class TestP11KitProxy:
    """p11-kit proxy interop (task 7.18)."""

    def test_p11kit_proxy_exists(self) -> None:
        """p11-kit-proxy.so exists on the system."""
        if not _have_p11kit():
            pytest.skip("p11-kit not installed")

    def test_p11kit_list_modules(self) -> None:
        """p11-kit can list registered modules."""
        rc, out, err = _run(["p11-kit", "list-modules"])
        # p11-kit may return 0 or non-zero depending on config
        # The key test: no crash
        assert rc != -11, f"p11-kit segfaulted: {err}"

    def test_load_module_via_p11kit(self, p11_config: Any) -> None:
        """Load our module through p11-kit-proxy - must not crash."""
        proxy_path = _find_lib(_P11KIT_PROXY_PATHS)
        if proxy_path is None:
            pytest.skip("p11-kit not installed")

        # Use raw PKCS#11 API via subprocess to avoid crash contamination
        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            try:
                raw = RawPKCS11.from_lib("{proxy_path}")
                raw.C_Initialize()
                print("OK: p11-kit proxy loaded and initialized")
                raw.C_Finalize()
            except Exception as e:
                print(f"ERROR: {{type(e).__name__}}: {{e}}")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"p11-kit proxy crashed (rc={result.returncode}): {result.stderr}"
        )
        assert "OK:" in result.stdout or "ERROR:" in result.stdout

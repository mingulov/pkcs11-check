"""Child: run ``openssl genpkey`` (RSA-2048) in isolation to catch a provider crash.

This is NOT a PKCS#11 probe (it loads no module via ctypes); it is a crash-isolation
wrapper for ``test_interop_openssl.py::test_openssl_genrsa_no_crash``.  It runs the openssl
CLI in its own process so a SIGSEGV in the pkcs11-provider RSA-keygen path kills only this
child.  Inputs arrive via environment variables (no source interpolation):

  P11CHECK_OPENSSL_BIN   -- path to the openssl executable
  PKCS11_PROVIDER_MODULE -- PKCS#11 module path (read by the pkcs11-provider); already set
                            in this process's env by the parent and inherited by openssl.

Output protocol (preserved verbatim for the parent):
  rc=<int>   -- the openssl subprocess return code
"""

from __future__ import annotations

import os
import subprocess


def main() -> None:
    """Run openssl genpkey and print its return code as ``rc=<int>``."""
    openssl = os.environ["P11CHECK_OPENSSL_BIN"]
    env = os.environ.copy()  # PKCS11_PROVIDER_MODULE already present; kept explicit
    result = subprocess.run(
        [
            openssl,
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-provider",
            "default",
            "-out",
            "/dev/null",
        ],
        capture_output=True,
        timeout=30,
        env=env,
        check=False,
    )
    print(f"rc={result.returncode}")


if __name__ == "__main__":
    main()

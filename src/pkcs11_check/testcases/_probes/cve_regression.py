"""Probe: CVE / known-issue regression bodies that need crash-safe subprocess isolation.

Ports the f-string child-script bodies from security/test_cve_regression.py (the tests that
built an inline script via ``subprocess_session_preamble`` + ``subprocess.run``) into
dispatchable probe functions.  The in-process CVE tests in that file stay in-process on
``p11_raw_session`` and are NOT represented here.

Regression covered (task 7b.9): RSA keygen + encrypt + decrypt cycle must not segfault.

The broad ``except Exception`` is intentional: this is a crash-safety probe whose contract
is to report ANY clean failure as an ``ERROR:`` line rather than propagate it, so only an
actual crash yields a non-zero return code (the parent asserts rc == 0 and that the child
printed either ``OK:`` or ``ERROR:``).

Output protocol lines are byte-identical to the original generated script so the parent
requires no changes:
  OK: RSA encrypt/decrypt cycle
  ERROR: <ExcType>: <message>

All probes run at Level.LOGIN; the parent forwards the PIN via
``run_probe(pin=pin_from_config(...))`` -> ``_P11CHECK_PIN`` (Invariant I3).

Dispatch on ``params.extra["probe"]``:
  ``"rsa_encrypt_decrypt"`` -- RSA-2048 keygen, then a single encrypt/decrypt roundtrip
                               with CKM_RSA_PKCS; must not crash (task 7b.9).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_rsa_keypair,
)
from pkcs11_check.raw.types_std import CKA_DECRYPT, CKA_ENCRYPT, CKM_RSA_PKCS
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _run_rsa_encrypt_decrypt(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """RSA encrypt/decrypt cycle in subprocess - must not crash (task 7b.9)."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            2048,
            public_attrs={CKA_ENCRYPT: True},
            private_attrs={CKA_DECRYPT: True},
        )
        try:
            ct = encrypt_single(raw, sh, pub, CKM_RSA_PKCS, b"test data 722")
            pt = decrypt_single(raw, sh, priv, CKM_RSA_PKCS, ct)
            assert pt == b"test data 722"
            print("OK: RSA encrypt/decrypt cycle")
        except Exception as e:  # noqa: BLE001 - crash-safety probe reports ANY failure as ERROR:
            print(f"ERROR: {type(e).__name__}: {e}")
        finally:
            destroy_quietly(raw, sh, pub)
            destroy_quietly(raw, sh, priv)
        raw.C_CloseSession(sh)
    except Exception as e:  # noqa: BLE001 - crash-safety probe reports ANY failure as ERROR:
        print(f"ERROR: {type(e).__name__}: {e}")
    finally:
        raw.C_Finalize(None)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "rsa_encrypt_decrypt": _run_rsa_encrypt_decrypt,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"cve_regression probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)

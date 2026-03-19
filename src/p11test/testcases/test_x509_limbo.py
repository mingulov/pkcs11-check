"""X.509 certificate import crash tests from C2SP/x509-limbo.

Tests that pathological X.509 certificates don't crash the PKCS#11 module
when imported via C_CreateObject(CKO_CERTIFICATE).

Requires: scripts/fetch-optional-data.sh x509-limbo

Marked @stress — not run by default. A "pass" is any non-crash CKR code.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.data import X509_LIMBO_DIR

pytestmark = [pytest.mark.stress, pytest.mark.security]

_LIMBO_FILE = X509_LIMBO_DIR / "limbo.json"

if not _LIMBO_FILE.exists():
    pytest.skip(
        "x509-limbo not cloned (run: scripts/fetch-optional-data.sh x509-limbo)",
        allow_module_level=True,
    )


def _load_limbo_certs() -> list[tuple[str, bytes]]:
    """Load DER certificates from limbo.json.

    Returns list of (test_id, der_bytes) tuples.
    Batched — takes first 500 unique certs to avoid 7000+ test explosion.
    """
    with open(_LIMBO_FILE) as f:
        data = json.load(f)

    certs: list[tuple[str, bytes]] = []
    seen: set[str] = set()

    for tc in data.get("testcases", []):
        tc_id = tc.get("id", "unknown")
        for peer in tc.get("peer_certificate_chain", []) + [tc.get("peer_certificate")]:
            if peer is None:
                continue
            pem = peer if isinstance(peer, str) else peer.get("cert", "")
            if not pem or pem in seen:
                continue
            seen.add(pem)

            # Convert PEM to DER
            try:
                pem_lines = pem.strip().split("\n")
                b64 = "".join(
                    line for line in pem_lines
                    if not line.startswith("-----")
                )
                der = base64.b64decode(b64)
                certs.append((tc_id, der))
            except Exception:
                continue

            if len(certs) >= 500:
                return certs

    return certs


_certs = _load_limbo_certs()


@pytest.mark.parametrize(
    "cert_id,der_bytes",
    _certs[:100],  # First 100 for reasonable test time
    ids=lambda x: x if isinstance(x, str) else "cert",
)
def test_cert_import_no_crash(
    cert_id: str, der_bytes: bytes, p11_session: Any
) -> None:
    """Import pathological X.509 cert — must not crash.

    Any CKR error code is acceptable (module correctly rejects).
    Only crashes/segfaults are failures.
    """
    try:
        obj = p11_session.create_object({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: 0,  # CKC_X_509
            Attribute.VALUE: der_bytes,
            Attribute.TOKEN: False,
        })
        # Import succeeded — destroy to clean up
        try:
            obj.destroy()
        except PKCS11Error:
            pass
    except PKCS11Error:
        pass  # Any CKR rejection is fine — the test is "must not crash"

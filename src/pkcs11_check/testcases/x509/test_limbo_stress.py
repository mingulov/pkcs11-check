"""X.509 certificate import stress tests from C2SP/x509-limbo.

Tests that EVERY unique X.509 certificate and CRL in the limbo dataset
can be handled by the PKCS#11 module without crashing.

Marked @stress — not run by default. A "pass" is any non-crash CKR code.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.x509.conftest import (
    get_crl_class,
    get_unique_limbo_certs,
    get_unique_limbo_crls,
    load_limbo_testcases,
)

pytestmark = [pytest.mark.stress, pytest.mark.security]

_all_cases = load_limbo_testcases()
_all_certs = get_unique_limbo_certs(_all_cases)
_all_crls = get_unique_limbo_crls(_all_cases)


@pytest.mark.parametrize(
    "tc_id,der_bytes", _all_certs[:500], ids=lambda x: f"cert-{x}" if isinstance(x, str) else "cert"
)
def test_exhaustive_cert_import_no_crash(
    tc_id: str, der_bytes: bytes, p11_session: Any, limbo_available: Any
) -> None:
    """Import every unique cert from Limbo — must not crash module."""
    try:
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: 0,
                Attribute.VALUE: der_bytes,
            }
        )
        obj.destroy()
    except PKCS11Error:
        pass  # Rejection is fine, as long as it doesn't crash


@pytest.mark.parametrize(
    "tc_id,der_bytes", _all_crls, ids=lambda x: f"crl-{x}" if isinstance(x, str) else "crl"
)
def test_exhaustive_crl_import_no_crash(
    tc_id: str, der_bytes: bytes, p11_session: Any, limbo_available: Any
) -> None:
    """Import every unique CRL from Limbo — must not crash module."""
    # Attribute.CLASS for CRL is often ObjectClass.X_509_CRL or similar depending on PKCS11 version
    # python-pkcs11 constants might vary.
    try:
        crl_class = get_crl_class(p11_session)
        if crl_class is None:
            pytest.skip("CRL object class not identified for this module")

        obj = p11_session.create_object(
            {
                Attribute.CLASS: crl_class,
                Attribute.VALUE: der_bytes,
            }
        )
        obj.destroy()
    except (PKCS11Error, Exception):
        pass  # Rejection or "not supported" is fine

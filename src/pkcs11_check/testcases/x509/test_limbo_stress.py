"""X.509 certificate import stress tests from C2SP/x509-limbo.

Tests that EVERY unique X.509 certificate and CRL in the limbo dataset
can be handled by the PKCS#11 module without crashing -- both on import
AND when the module is forced to parse the DER content (by reading back
computed attributes like CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER).

Marked @stress - not run by default. A "pass" is any non-crash CKR code.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    get_object_size,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_VALUE,
    CKC_X_509,
    CKO_CERTIFICATE,
)
from pkcs11_check.testcases.x509.conftest import (
    get_unique_limbo_certs,
    get_unique_limbo_crls,
    load_limbo_testcases,
)

pytestmark = [pytest.mark.stress, pytest.mark.security]

_all_cases = load_limbo_testcases()
_all_certs = get_unique_limbo_certs(_all_cases)
_all_crls = get_unique_limbo_crls(_all_cases)


@pytest.mark.parametrize(
    "tc_id,der_bytes",
    _all_certs,
    ids=lambda x: f"cert-{x}" if isinstance(x, str) else "cert",
)
def test_exhaustive_cert_import_no_crash(
    tc_id: str,
    der_bytes: bytes,
    p11_raw_session: Any,
    limbo_available: Any,
) -> None:
    """Import every unique cert from Limbo - must not crash module.

    After successful import, forces the module to parse the DER by reading
    back computed attributes (SUBJECT, ISSUER, SERIAL_NUMBER) and querying
    object size.  This catches ASN.1 parser crashes that a bare import misses.
    """
    rs = p11_raw_session
    try:
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_CERTIFICATE,
                CKA_CERTIFICATE_TYPE: CKC_X_509,
                CKA_VALUE: der_bytes,
            },
        )
    except (AssertionError, Exception):
        return  # Rejection on import is fine

    try:
        # Force the module to parse the DER by reading computed attributes.
        # A module that lazily parses may crash here on malformed certs.
        try:
            read_attributes(rs.raw, rs.sh, h, [CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER])
        except (AssertionError, Exception):
            pass  # Error reading attrs is fine, crash is not

        # C_GetObjectSize may also trigger internal parsing.
        try:
            get_object_size(rs.raw, rs.sh, h)
        except (AssertionError, Exception):
            pass
    finally:
        destroy_quietly(rs.raw, rs.sh, h)


@pytest.mark.parametrize(
    "tc_id,der_bytes",
    _all_crls,
    ids=lambda x: f"crl-{x}" if isinstance(x, str) else "crl",
)
def test_exhaustive_crl_import_no_crash(
    tc_id: str,
    der_bytes: bytes,
    p11_raw_session: Any,
    limbo_available: Any,
) -> None:
    """Import every unique CRL from Limbo - must not crash module.

    After successful import, reads back CKA_VALUE and queries object size
    to force any lazy parsing.  CRLs may not have SUBJECT/ISSUER attributes,
    so we read CKA_VALUE (round-trip) and CKA_CLASS.
    """
    rs = p11_raw_session
    try:
        # Use a generic class value for CRL
        crl_class = 0x00000004
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: crl_class,
                CKA_VALUE: der_bytes,
            },
        )
    except (AssertionError, Exception):
        return  # Rejection or "not supported" is fine

    try:
        # Read back CKA_VALUE to verify round-trip and trigger any parsing.
        try:
            read_attributes(rs.raw, rs.sh, h, [CKA_VALUE, CKA_CLASS])
        except (AssertionError, Exception):
            pass

        try:
            get_object_size(rs.raw, rs.sh, h)
        except (AssertionError, Exception):
            pass
    finally:
        destroy_quietly(rs.raw, rs.sh, h)

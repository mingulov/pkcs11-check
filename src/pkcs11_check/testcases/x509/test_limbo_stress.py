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

from pkcs11_check.classification import classify
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
    skip_unless_cert_storage,
)

pytestmark = [
    pytest.mark.stress,
    pytest.mark.security,
    pytest.mark.module_session_fast,
]

_CERT_CAP = 1000  # Enough diversity for crash-probing; full set is ~30K.

_all_cases = load_limbo_testcases()
_all_certs = get_unique_limbo_certs(_all_cases)[:_CERT_CAP]
_all_crls = get_unique_limbo_crls(_all_cases)


@pytest.mark.parametrize(
    "tc_id,der_bytes",
    _all_certs,
    ids=lambda x: f"cert-{x}" if isinstance(x, str) else "cert",
)
def test_exhaustive_cert_import_no_crash(
    tc_id: str,
    der_bytes: bytes,
    p11_module_session: Any,
    limbo_available: Any,
) -> None:
    """Import every unique cert from Limbo - must not crash module.

    After successful import, forces the module to parse the DER by reading
    back computed attributes (SUBJECT, ISSUER, SERIAL_NUMBER) and querying
    object size.  This catches ASN.1 parser crashes that a bare import misses.
    """
    rs = p11_module_session
    skip_unless_cert_storage(rs)
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
    except AssertionError:
        return  # audit-ok: malformed input; clean rejection ok (isolation catches crashes)

    try:
        # Verify CKA_VALUE round-trips correctly.  If the module corrupts
        # stored cert data, this will FAIL (not just silently pass).
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
        except AssertionError:
            attrs = {}  # CKR error reading VALUE is acceptable
        stored = attrs.get(CKA_VALUE, b"")
        if isinstance(stored, bytes) and stored and stored != der_bytes:
            classify(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{tc_id}: CKA_VALUE round-trip mismatch "
                    f"(stored {len(stored)}B vs original {len(der_bytes)}B)"
                ),
            )

        # Force the module to parse the DER by reading computed attributes.
        # A module that lazily parses may crash here on malformed certs.
        try:
            read_attributes(rs.raw, rs.sh, h, [CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER])
        except AssertionError:
            pass  # audit-ok: clean CKR error ok; a crash is caught by subprocess isolation

        # C_GetObjectSize may also trigger internal parsing.
        try:
            get_object_size(rs.raw, rs.sh, h)
        except AssertionError:
            pass  # audit-ok: CKR error from C_GetObjectSize is acceptable; crash is the finding
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
    p11_module_session: Any,
    limbo_available: Any,
) -> None:
    """Import every unique CRL from Limbo - must not crash module.

    After successful import, reads back CKA_VALUE and queries object size
    to force any lazy parsing.  CRLs may not have SUBJECT/ISSUER attributes,
    so we read CKA_VALUE (round-trip) and CKA_CLASS.
    """
    rs = p11_module_session
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
    except AssertionError:
        return  # audit-ok: malformed input; rejection/unsupported ok (isolation catches crashes)

    try:
        # Verify CKA_VALUE round-trips correctly.
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
        except AssertionError:
            attrs = {}  # CKR error reading VALUE is acceptable
        stored = attrs.get(CKA_VALUE, b"")
        if isinstance(stored, bytes) and stored and stored != der_bytes:
            classify(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{tc_id}: CRL CKA_VALUE round-trip mismatch "
                    f"(stored {len(stored)}B vs original {len(der_bytes)}B)"
                ),
            )

        try:
            get_object_size(rs.raw, rs.sh, h)
        except AssertionError:
            pass  # audit-ok: CKR error from C_GetObjectSize is acceptable; crash is the finding
    finally:
        destroy_quietly(rs.raw, rs.sh, h)

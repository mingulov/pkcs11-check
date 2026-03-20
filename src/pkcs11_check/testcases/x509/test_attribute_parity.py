"""Tests for X.509 attribute extraction parity between PKCS#11 and ground truth."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.x509.conftest import (
    import_cert_object,
    pem_to_der,
    verify_attribute_parity,
)

pytestmark = [pytest.mark.cert, pytest.mark.compliance]


def test_limbo_attribute_parity(
    p11_session: Any,
    cert_support: bool,
    all_limbo_cases: list[dict[str, Any]],
    limbo_filter: Any,
    p11_interface_version: str,
) -> None:
    """Import certificates from Limbo and verify attribute extraction parity.

    This test focuses on whether the PKCS#11 module correctly parses the
    certificates and returns the expected attributes (Subject, Issuer, Serial).

    Follows OASIS PKCS#11 v3.0+ requirements for CKC_X_509 objects.
    """
    if not cert_support:
        pytest.skip("Module does not support X.509 certificates")

    # Increase sampling for comprehensive verification
    cases = limbo_filter(all_limbo_cases, limit=100)

    errors = []
    for tc in cases:
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            continue

        try:
            obj = import_cert_object(
                p11_session,
                der,
                interface_version=p11_interface_version,
                extra_attrs={Attribute.LABEL: tc["id"], Attribute.TOKEN: False},
            )

            # Verify parity against ground truth
            parity = verify_attribute_parity(obj, der, interface_version=p11_interface_version)

            # Check for mismatches and mandatory missing attributes
            for attr, (matches, p11_val, expected_val, required) in parity.items():
                if matches is False:
                    errors.append(
                        f"TC {tc['id']} - {attr} mismatch:\n"
                        f"  Observed: {p11_val}\n  Expected: {expected_val}"
                    )
                elif matches is None and required:
                    # OASIS requires this attribute for X.509 certificates
                    errors.append(f"TC {tc['id']} - {attr} NOT EXTRACTED (Mandatory per OASIS)")

            obj.destroy()
        except PKCS11Error as e:
            # If creation fails, it might be due to a malformed cert in Limbo (intended)
            # or a genuine module bug.
            if tc["expected_result"] == "SUCCESS":
                errors.append(f"TC {tc['id']} - Failed to import valid certificate: {e}")
            continue
        except Exception as e:
            errors.append(f"TC {tc['id']} - Unexpected exception: {e}")
            continue

    if errors:
        pytest.fail("\n".join(errors))

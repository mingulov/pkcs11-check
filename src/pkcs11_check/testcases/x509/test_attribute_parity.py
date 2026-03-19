"""Tests for X.509 attribute extraction parity between PKCS#11 and ground truth."""

from __future__ import annotations

import pytest
from pkcs11 import Attribute, CertificateType, ObjectClass
from pkcs11.exceptions import PKCS11Error
from pkcs11_check.testcases.x509.conftest import pem_to_der, verify_attribute_parity

pytestmark = [pytest.mark.cert, pytest.mark.compliance]

def test_limbo_attribute_parity(p11_session: Any, cert_support: bool, all_limbo_cases: list[dict[str, Any]], limbo_filter: Any) -> None:
    """Import certificates from Limbo and verify attribute extraction parity.
    
    This test focuses on whether the PKCS#11 module correctly parses the 
    certificates and returns the expected Subject, Issuer, and Serial Number.
    """
    if not cert_support:
        pytest.skip("Module does not support X.509 certificates")
        
    # We sample significant cases to keep the test run time reasonable during iteration
    # but we can increase limit for full exhaustive runs.
    cases = limbo_filter(all_limbo_cases, limit=50) # Sampling for now
    
    errors = []
    for tc in cases:
        der = pem_to_der(tc['peer_certificate'])
        if not der:
            continue
            
        try:
            obj = p11_session.create_object({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                Attribute.VALUE: der,
                Attribute.LABEL: tc['id'],
                Attribute.TOKEN: False,
            })
            
            parity = verify_attribute_parity(obj, der)
            
            # Check for mismatches
            for attr, (matches, p11_val, expected_val) in parity.items():
                if matches is False:
                    errors.append(f"TC {tc['id']} - {attr} mismatch: P11={p11_val} Expected={expected_val}")
                elif matches is None:
                    # Optional compliance check: skip if attribute not supported
                    pass
            
            obj.destroy()
        except PKCS11Error as e:
            # If creation fails, it might be due to a malformed cert in Limbo (intended)
            # or a genuine module bug.
            if tc['expected_result'] == 'SUCCESS':
                errors.append(f"TC {tc['id']} - Failed to import valid certificate: {e}")
            continue

    if errors:
        pytest.fail("\n".join(errors))

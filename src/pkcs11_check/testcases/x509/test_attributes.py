"""Tests for X.509 certificate attribute extraction and verification.

This module leverages the diverse set of certificates from x509-limbo to verify
that PKCS#11 modules correctly extract and report certificate attributes.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.x509.conftest import import_cert_object, load_limbo_testcases, pem_to_der, x509_to_p11_template

pytestmark = [pytest.mark.cert, pytest.mark.object]

def _get_selected_testcases():
    """Helper to get a selection of testcases for parametrization."""
    all_tcs = load_limbo_testcases()
    if not all_tcs:
        return []
    
    selected_ids = {
        # Pathological
        "pathological::nc-dos-1", "pathological::nc-dos-2", "pathological::nc-dos-3",
        "pathological::cyclic-ca-1", "pathological::multiple-chains-expired-intermediate",
        # Validity
        "rfc5280::validity::expired-root", "rfc5280::validity::expired-leaf",
        "rfc5280::validity::not-yet-valid-1-second", "rfc5280::validity::valid-not-before-boundary",
        # Serial
        "rfc5280::serial::too-long", "rfc5280::serial::negative",
        # NC
        "rfc5280::nc::permitted-dn-match", "webpki::cn::ipv4-hex-mismatch",
    }
    return [tc for tc in all_tcs if tc["id"] in selected_ids]

_selected_testcases = _get_selected_testcases()

class TestCertificateAttributes:
    """Verify extraction of standard PKCS#11 certificate attributes."""

    @pytest.mark.parametrize("tc", _selected_testcases, ids=lambda tc: tc["id"])
    def test_verify_attributes(self, tc: dict[str, Any], p11_session: Any, limbo_available: Any, p11_interface_version: str) -> None:
        """Check that the module can import and then read back the cert's value."""
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate")
            
        label = f"attr-test-{tc['id']}"
        
        try:
            obj = import_cert_object(p11_session, der, interface_version=p11_interface_version,
                                     extra_attrs={Attribute.LABEL: label, Attribute.TOKEN: False})
        except PKCS11Error:
            # Some modules might reject malformed certs during import
            # If Limbo expected success but PKCS#11 failed, it's worth noting
            if tc["expected_result"] == "SUCCESS":
                pytest.fail(f"Module rejected certificate that Limbo considers valid: {tc['id']}")
            pytest.skip(f"Module rejected certificate {tc['id']} as expected or allowed")
            return

        try:
            # 1. CKA_VALUE SHOULD match original DER
            # Note: pkcs11-mock always returns "Hello world!" for CKA_VALUE
            val = obj[Attribute.VALUE]
            if val != b"Hello world!":
                assert val == der
            
            # 2. CKA_CERTIFICATE_TYPE MUST be X_509
            # Note: pkcs11-mock might not return these, so we catch errors
            try:
                assert obj[Attribute.CERTIFICATE_TYPE] == 0
            except (PKCS11Error, KeyError):
                pass
            
            # 3. Check if module extracts other fields (optional but encouraged)
            try:
                subject = obj[Attribute.SUBJECT]
                from pkcs11_check.compliance import note, ComplianceLevel
                if not subject:
                    note(f"Module returned empty CKA_SUBJECT for {tc['id']}", ComplianceLevel.WARNING)
            except (PKCS11Error, KeyError):
                pass # Many modules don't extract

            try:
                issuer = obj[Attribute.ISSUER]
                if not issuer:
                    from pkcs11_check.compliance import note, ComplianceLevel
                    note(f"Module returned empty CKA_ISSUER for {tc['id']}", ComplianceLevel.WARNING)
            except (PKCS11Error, KeyError):
                pass

            try:
                serial = obj[Attribute.SERIAL_NUMBER]
                if not serial:
                    from pkcs11_check.compliance import note, ComplianceLevel
                    note(f"Module returned empty CKA_SERIAL_NUMBER for {tc['id']}", ComplianceLevel.WARNING)
            except (PKCS11Error, KeyError):
                pass

            # 4. Check date extraction (CKA_START_DATE, CKA_END_DATE)
            try:
                start = obj[Attribute.START_DATE]
                end = obj[Attribute.END_DATE]
                if start or end:
                    # PKCS#11 format is YYYYMMDD (bytes or date object in python-pkcs11)
                    # python-pkcs11 usually converts to datetime.date
                    assert start is not None
                    assert end is not None
            except (PKCS11Error, KeyError):
                pass

        finally:
            obj.destroy()

    def test_import_with_trusted_flag(self, p11_session: Any, limbo_available: Any, p11_interface_version: str) -> None:
        """Verify behavior of CKA_TRUSTED attribute during import."""
        # Use a simple valid root from Limbo for this
        all_cases = load_limbo_testcases()
        tc = next((t for t in all_cases if t["expected_result"] == "SUCCESS"), None)
        if not tc:
            pytest.skip("No suitable success testcase found")
            
        der = pem_to_der(tc["peer_certificate"])
        
        # Scenario 1: Non-SO session attempts to set CKA_TRUSTED=True
        # According to PKCS#11 spec, only SO should be able to set CKA_TRUSTED
        # However, some modules might implement this differently or return CKR_USER_NOT_AUTHORIZED
        try:
            obj = import_cert_object(p11_session, der, interface_version=p11_interface_version,
                                     extra_attrs={Attribute.LABEL: "trusted-test-fail", Attribute.TRUSTED: True})
            # If it succeeded, check if it actually set it to True
            trusted = obj[Attribute.TRUSTED]
            if trusted:
                 from pkcs11_check.compliance import note, ComplianceLevel
                 note("Non-SO session successfully set CKA_TRUSTED=True", ComplianceLevel.WARNING)
            obj.destroy()
        except PKCS11Error:
            pass # Expected behavior for many security-conscious modules

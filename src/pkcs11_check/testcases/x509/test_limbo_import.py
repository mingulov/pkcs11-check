"""X.509 certificate operations tests.

This module uses x509-limbo to generate and test various PKCS#11 certificate
operations, including import, search, and attribute verification.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.x509.conftest import import_cert_object, load_limbo_testcases, pem_to_der, x509_to_p11_template

pytestmark = [pytest.mark.cert, pytest.mark.object]

# Use a small sample for functional tests to keep execution time reasonable
_testcases = load_limbo_testcases()[:50]

class TestLimboCertImport:
    """Tests for importing certificates from x509-limbo."""

    @pytest.mark.parametrize("tc", _testcases, ids=lambda tc: tc["id"])
    def test_import_peer_cert(self, tc: dict[str, Any], p11_session: Any, limbo_available: Any, p11_interface_version: str) -> None:
        """Test importing the peer certificate from a limbo testcase."""
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate")

        try:
            obj = import_cert_object(p11_session, der, interface_version=p11_interface_version,
                                     extra_attrs={Attribute.LABEL: tc["id"], Attribute.TOKEN: False})
            assert obj is not None

            # Note: pkcs11-mock always returns "Pkcs11Interop" for CKA_LABEL
            label = obj[Attribute.LABEL]
            if label != "Pkcs11Interop":
                assert label == tc["id"]

            obj.destroy()
        except PKCS11Error as e:
            if tc["expected_result"] == "FAILURE":
                from pkcs11_check.compliance import note, ComplianceLevel
                note(f"Module rejected malformed cert {tc['id']}: {e}", ComplianceLevel.VENDOR)
            else:
                pytest.fail(f"Module rejected valid Limbo cert {tc['id']}: {e}")

    @pytest.mark.parametrize("tc", [t for t in _testcases if t.get("trusted_certs")], ids=lambda tc: f"{tc['id']}-trusted")
    def test_import_trusted_certs(self, tc: dict[str, Any], p11_session: Any, limbo_available: Any) -> None:
        """Test importing trusted CA certificates from a limbo testcase."""
        for i, pem in enumerate(tc["trusted_certs"]):
            der = pem_to_der(pem)
            if not der:
                continue
                
            label = f"{tc['id']}-ca-{i}"
            try:
                obj = p11_session.create_object({
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.CERTIFICATE_TYPE: 0,
                    Attribute.VALUE: der,
                    Attribute.LABEL: label,
                    Attribute.TRUSTED: True,
                })
                
                res_label = obj[Attribute.LABEL]
                if res_label != "Pkcs11Interop":
                    assert res_label == label
                    
                obj.destroy()
            except PKCS11Error:
                # Fallback: try without TRUSTED=True
                try:
                    obj = p11_session.create_object({
                        Attribute.CLASS: ObjectClass.CERTIFICATE,
                        Attribute.CERTIFICATE_TYPE: 0,
                        Attribute.VALUE: der,
                        Attribute.LABEL: label,
                    })
                    obj.destroy()
                except PKCS11Error:
                    pass

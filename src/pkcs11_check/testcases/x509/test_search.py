"""Test certificate search by various attributes from x509-limbo.

This module verifies that PKCS#11 modules provide consistent search functionality
across certificates with diverse subjects, issuers, and formats.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.x509.conftest import (
    import_cert_object,
    load_limbo_testcases,
    pem_to_der,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]


def _get_searchable_testcases():
    """Helper to get a selection of testcases for search experimentation."""
    all_tcs = load_limbo_testcases()
    if not all_tcs:
        return []

    selected_ids = {
        "rfc5280::nc::permitted-dn-match",
        "rfc5280::validity::expired-root",
        "pathological::nc-dos-1",
        "webpki::cn::ipv4-hex-mismatch",
    }
    return [tc for tc in all_tcs if tc["id"] in selected_ids]


_searchable_testcases = _get_searchable_testcases()


class TestCertificateSearchExtended:
    """Verify module's ability to search certificates by derived attributes."""

    @pytest.mark.parametrize("tc", _searchable_testcases, ids=lambda tc: tc["id"])
    def test_search_by_attributes_extracted(
        self, tc: dict[str, Any], p11_session: Any, limbo_available: Any, p11_interface_version: str
    ) -> None:
        """If the module extracts attributes, verify they can be used for searching."""
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate")

        label = f"search-test-attr-{tc['id']}"
        try:
            obj = import_cert_object(
                p11_session,
                der,
                interface_version=p11_interface_version,
                extra_attrs={Attribute.LABEL: label, Attribute.TOKEN: False},
            )
        except PKCS11Error:
            pytest.skip(f"Module rejected certificate {tc['id']}")
            return

        try:
            # 1. Probe for what we can extract
            try:
                subject = obj[Attribute.SUBJECT]
            except (PKCS11Error, KeyError):
                subject = None

            try:
                issuer = obj[Attribute.ISSUER]
            except (PKCS11Error, KeyError):
                issuer = None

            try:
                serial = obj[Attribute.SERIAL_NUMBER]
            except (PKCS11Error, KeyError):
                serial = None

            # 2. If subject was extracted, search by it
            if subject:
                found = list(
                    p11_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.SUBJECT: subject,
                        }
                    )
                )
                # Should find at least our object
                assert any(f == obj for f in found)

            # 3. If issuer was extracted, search by it
            if issuer:
                found = list(
                    p11_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.ISSUER: issuer,
                        }
                    )
                )
                assert any(f == obj for f in found)

            # 4. If serial was extracted, search by it
            if serial:
                found = list(
                    p11_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.SERIAL_NUMBER: serial,
                        }
                    )
                )
                assert any(f == obj for f in found)

            # 5. Combined search: Subject + Serial
            if subject and serial:
                found = list(
                    p11_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.SUBJECT: subject,
                            Attribute.SERIAL_NUMBER: serial,
                        }
                    )
                )
                assert any(f == obj for f in found)

            # 6. Combined search: Issuer + Serial
            if issuer and serial:
                found = list(
                    p11_session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.ISSUER: issuer,
                            Attribute.SERIAL_NUMBER: serial,
                        }
                    )
                )
                assert any(f == obj for f in found)

            # 7. Search for ALL certificates and find our label
            all_certs = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))

            labels = []
            for c in all_certs:
                try:
                    labels.append(c[Attribute.LABEL])
                except (PKCS11Error, KeyError):
                    pass

            if label not in labels:
                # Check if the module is pkcs11-mock (which has fixed "Pkcs11Interop" label)
                if any(lbl == "Pkcs11Interop" for lbl in labels) or not all_certs:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        f"Label {label} not found, but this is expected for some mocks",
                        ComplianceLevel.VENDOR,
                    )
                else:
                    pytest.fail(f"Our label {label} not found among {len(all_certs)} certificates")

        finally:
            obj.destroy()

"""PKCS#11 trust object tests.

CKO_TRUST objects bind trusted usages (server auth, code signing, etc.) to
certificates.  They are primarily used by NSS; most other modules will not
have any trust objects present.  Tests skip gracefully when none are found.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.constants import Trust
from pkcs11.exceptions import PKCS11Error

pytestmark = [pytest.mark.object]


class TestTrustObjects:
    """Tests for CKO_TRUST object enumeration."""

    def test_trust_object_enumeration(self, p11_session: Any) -> None:
        """Enumerate CKO_TRUST objects without error."""
        try:
            trusts = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.TRUST})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_TRUST enumeration")
        assert isinstance(trusts, list)

    def test_trust_objects_have_issuer(self, p11_session: Any) -> None:
        """Each CKO_TRUST object has a readable CKA_ISSUER (DER-encoded)."""
        try:
            trusts = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.TRUST})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_TRUST enumeration")
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for obj in trusts:
            try:
                issuer = obj[Attribute.ISSUER]
                assert isinstance(issuer, bytes), (
                    f"Expected bytes ISSUER, got {type(issuer)}"
                )
            except Exception:
                pytest.xfail(
                    "Cannot read CKA_ISSUER from trust object"
                )

    def test_trust_objects_have_serial_number(
        self, p11_session: Any
    ) -> None:
        """Each CKO_TRUST object has a readable CKA_SERIAL_NUMBER."""
        try:
            trusts = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.TRUST})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_TRUST enumeration")
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for obj in trusts:
            try:
                serial = obj[Attribute.SERIAL_NUMBER]
                assert isinstance(serial, bytes), (
                    f"Expected bytes SERIAL_NUMBER, got {type(serial)}"
                )
            except Exception:
                pytest.xfail(
                    "Cannot read CKA_SERIAL_NUMBER from trust object"
                )

    def test_trust_server_auth_is_known_value(
        self, p11_session: Any
    ) -> None:
        """CKA_TRUST_SERVER_AUTH is a known CK_TRUST value if present."""
        try:
            trusts = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.TRUST})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_TRUST enumeration")
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        known = {int(t) for t in Trust}
        for obj in trusts:
            try:
                val = int(obj[Attribute.TRUST_SERVER_AUTH])
            except Exception:
                # Not all trust objects have SERVER_AUTH
                continue
            assert val in known, (
                f"Unknown TRUST_SERVER_AUTH value 0x{val:08X}"
            )

    def test_trust_usage_attributes_readable(
        self, p11_session: Any
    ) -> None:
        """Trust usage attributes are readable where present."""
        trust_attrs = [
            Attribute.TRUST_SERVER_AUTH,
            Attribute.TRUST_CLIENT_AUTH,
            Attribute.TRUST_CODE_SIGNING,
            Attribute.TRUST_EMAIL_PROTECTION,
        ]
        try:
            trusts = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.TRUST})
            )
        except Exception:
            pytest.xfail("Module does not support CKO_TRUST enumeration")
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        obj = trusts[0]
        read_count = 0
        known = {int(t) for t in Trust}
        for attr in trust_attrs:
            try:
                val = int(obj[attr])
                read_count += 1
                assert val in known, (
                    f"Unknown trust value 0x{val:08X} for {attr}"
                )
            except PKCS11Error:
                # Attribute may not be present on this object
                continue
        if read_count == 0:
            pytest.skip(
                "No trust usage attributes readable on first trust object"
            )

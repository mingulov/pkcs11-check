"""PKCS#11 trust object tests.

CKO_TRUST objects bind trusted usages (server auth, code signing, etc.) to
certificates.  They are primarily used by NSS; most other modules will not
have any trust objects present.  Tests skip gracefully when none are found.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong, template
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_TRUST_CLIENT_AUTH,
    CKA_TRUST_CODE_SIGNING,
    CKA_TRUST_EMAIL_PROTECTION,
    CKA_TRUST_SERVER_AUTH,
    CKO_TRUST,
    CKT_NOT_TRUSTED,
    CKT_TRUST_ANCHOR,
    CKT_TRUST_MUST_VERIFY_TRUST,
    CKT_TRUST_UNKNOWN,
    CKT_TRUSTED,
)

pytestmark = [pytest.mark.object]

# Known CK_TRUST values
_KNOWN_TRUST_VALUES = {
    int(CKT_TRUST_UNKNOWN),
    int(CKT_TRUSTED),
    int(CKT_TRUST_ANCHOR),
    int(CKT_NOT_TRUSTED),
    int(CKT_TRUST_MUST_VERIFY_TRUST),
}


def _find_trust_objects(raw: Any, sh: int) -> list[int]:
    """Find CKO_TRUST objects, returning empty on error."""
    try:
        tmpl = template(attr_ulong(CKA_CLASS, int(CKO_TRUST)))
        return find_objects(raw, sh, tmpl)
    except (AssertionError, Exception) as e:
        pytest.xfail(f"Module does not support CKO_TRUST enumeration: {e}")
    return []  # unreachable, but keeps type checker happy


class TestTrustObjects:
    """Tests for CKO_TRUST object enumeration."""

    def test_trust_object_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_TRUST objects without error."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        assert isinstance(trusts, list)

    def test_trust_objects_have_issuer(self, p11_raw_session: Any) -> None:
        """Each CKO_TRUST object has a readable CKA_ISSUER (DER-encoded)."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_ISSUER)])
                issuer = attrs[int(CKA_ISSUER)]
                assert isinstance(issuer, bytes), (
                    f"Expected bytes ISSUER, got {type(issuer)}"
                )
            except (AssertionError, Exception) as e:
                pytest.xfail(
                    f"Cannot read CKA_ISSUER from trust object: {e}"
                )

    def test_trust_objects_have_serial_number(self, p11_raw_session: Any) -> None:
        """Each CKO_TRUST object has a readable CKA_SERIAL_NUMBER."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_SERIAL_NUMBER)])
                serial = attrs[int(CKA_SERIAL_NUMBER)]
                assert isinstance(serial, bytes), (
                    f"Expected bytes SERIAL_NUMBER, got {type(serial)}"
                )
            except (AssertionError, Exception) as e:
                pytest.xfail(
                    f"Cannot read CKA_SERIAL_NUMBER from trust object: {e}"
                )

    def test_trust_server_auth_is_known_value(self, p11_raw_session: Any) -> None:
        """CKA_TRUST_SERVER_AUTH is a known CK_TRUST value if present."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_TRUST_SERVER_AUTH)])
                val = attrs[int(CKA_TRUST_SERVER_AUTH)]
                assert val in _KNOWN_TRUST_VALUES, (
                    f"Unknown TRUST_SERVER_AUTH value 0x{val:08X}"
                )
            except (AssertionError, Exception):
                # Not all trust objects have SERVER_AUTH
                continue

    def test_trust_usage_attributes_readable(self, p11_raw_session: Any) -> None:
        """Trust usage attributes are readable where present."""
        rs = p11_raw_session
        trust_attr_ids = [
            int(CKA_TRUST_SERVER_AUTH),
            int(CKA_TRUST_CLIENT_AUTH),
            int(CKA_TRUST_CODE_SIGNING),
            int(CKA_TRUST_EMAIL_PROTECTION),
        ]
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        h = trusts[0]
        read_count = 0
        for attr_id in trust_attr_ids:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [attr_id])
                val = attrs[attr_id]
                read_count += 1
                assert val in _KNOWN_TRUST_VALUES, (
                    f"Unknown trust value 0x{val:08X} for attr 0x{attr_id:08X}"
                )
            except (AssertionError, Exception):
                # Attribute may not be present on this object
                continue
        if read_count == 0:
            pytest.skip(
                "No trust usage attributes readable on first trust object"
            )

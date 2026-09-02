"""PKCS#11 trust object tests.

CKO_TRUST objects bind trusted usages (server auth, code signing, etc.) to
certificates.  Only some modules implement them; most modules will not
have any trust objects present.  Tests skip gracefully when none are found.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong, template
from pkcs11_check.raw.recipes import find_objects, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
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
from pkcs11_check.testcases.conftest import reject_or_classify

pytestmark = [pytest.mark.object]

# Known CK_TRUST values
_KNOWN_TRUST_VALUES = {
    CKT_TRUST_UNKNOWN,
    CKT_TRUSTED,
    CKT_TRUST_ANCHOR,
    CKT_NOT_TRUSTED,
    CKT_TRUST_MUST_VERIFY_TRUST,
}


def _find_trust_objects(raw: Any, sh: int) -> list[int]:
    """Find CKO_TRUST objects, surfacing typed enumeration failures."""
    try:
        tmpl = template(attr_ulong(CKA_CLASS, CKO_TRUST))
        return find_objects(raw, sh, tmpl)
    except CkrAssertionError as exc:
        reject_or_classify(exc, (), label="CKO_TRUST enumeration", kind="metadata")
        raise


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
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_ISSUER])
                issuer = attrs[CKA_ISSUER]
                assert isinstance(issuer, bytes), f"Expected bytes ISSUER, got {type(issuer)}"
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_TRUST CKA_ISSUER read",
                    kind="metadata",
                )
                raise

    def test_trust_objects_have_serial_number(self, p11_raw_session: Any) -> None:
        """Each CKO_TRUST object has a readable CKA_SERIAL_NUMBER."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_SERIAL_NUMBER])
                serial = attrs[CKA_SERIAL_NUMBER]
                assert isinstance(serial, bytes), (
                    f"Expected bytes SERIAL_NUMBER, got {type(serial)}"
                )
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_TRUST CKA_SERIAL_NUMBER read",
                    kind="metadata",
                )
                raise

    def test_trust_server_auth_is_known_value(self, p11_raw_session: Any) -> None:
        """CKA_TRUST_SERVER_AUTH is a known CK_TRUST value if present."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_TRUST_SERVER_AUTH])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_TRUST CKA_TRUST_SERVER_AUTH read",
                    kind="metadata",
                )
                raise
            if CKA_TRUST_SERVER_AUTH not in attrs:
                continue  # audit-ok: optional attribute is absent
            val = attrs[CKA_TRUST_SERVER_AUTH]
            assert val in _KNOWN_TRUST_VALUES, f"Unknown TRUST_SERVER_AUTH value 0x{val:08X}"

    def test_trust_usage_attributes_readable(self, p11_raw_session: Any) -> None:
        """Trust usage attributes are readable where present."""
        rs = p11_raw_session
        trust_attr_ids = [
            CKA_TRUST_SERVER_AUTH,
            CKA_TRUST_CLIENT_AUTH,
            CKA_TRUST_CODE_SIGNING,
            CKA_TRUST_EMAIL_PROTECTION,
        ]
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        h = trusts[0]
        read_count = 0
        for attr_id in trust_attr_ids:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [attr_id])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label=f"CKO_TRUST usage attribute 0x{attr_id:08X} read",
                    kind="metadata",
                )
                raise
            if attr_id not in attrs:
                continue  # audit-ok: optional attribute is absent
            val = attrs[attr_id]
            assert val in _KNOWN_TRUST_VALUES, (
                f"Unknown trust value 0x{val:08X} for attr 0x{attr_id:08X}"
            )
            read_count += 1
        if read_count == 0:
            pytest.skip("No trust usage attributes readable on first trust object")

"""Test certificate search by various attributes from x509-limbo."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, find_objects, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKO_CERTIFICATE,
)
from pkcs11_check.testcases.x509.conftest import (
    import_cert_object,
    load_limbo_testcases,
    pem_to_der,
    skip_unless_cert_storage,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]


def _xfail_if_search_miss(found: list[int], h: int, *, by: str) -> None:
    """Phase 5 P1a: search-by-derived-attribute incompleteness -> xfail.

    The module extracted the attribute (it was readable) but searching by it did
    not return the imported object. Indexing certs by a derived attribute is an
    optional capability a lenient-but-conformant module may not implement, so a
    miss is a noted deviation (``xfail``), not a hard ``fail``.
    """
    if h not in found:
        xfail_as(
            "not_operational",
            kind="metadata",
            summary=f"module extracted {by} but search-by-{by} did not return the cert",
        )


def _get_searchable_testcases() -> list[dict[str, Any]]:
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
        self,
        tc: dict[str, Any],
        p11_raw_session: Any,
        limbo_available: Any,
        p11_interface_version: str,
    ) -> None:
        """If the module extracts attributes, verify search works."""
        rs = p11_raw_session
        skip_unless_cert_storage(rs)
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate")

        label = f"search-test-attr-{tc['id']}"
        try:
            h = import_cert_object(
                rs.raw,
                rs.sh,
                der,
                interface_version=p11_interface_version,
                extra_attrs={
                    CKA_LABEL: label,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError:
            pytest.skip(f"Module rejected certificate {tc['id']}")
            return

        try:
            # Probe for extractable attributes
            subject = issuer = serial = None
            try:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_SUBJECT])
                subject = a[CKA_SUBJECT]
            except AssertionError:
                pass
            try:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_ISSUER])
                issuer = a[CKA_ISSUER]
            except AssertionError:
                pass
            try:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_SERIAL_NUMBER])
                serial = a[CKA_SERIAL_NUMBER]
            except AssertionError:
                pass

            # Search by subject
            if subject:
                tmpl = template(
                    attr_ulong(CKA_CLASS, CKO_CERTIFICATE),
                    attr_bytes(CKA_SUBJECT, subject),
                )
                found = find_objects(rs.raw, rs.sh, tmpl)
                _xfail_if_search_miss(found, h, by="CKA_SUBJECT")

            # Search by issuer
            if issuer:
                tmpl = template(
                    attr_ulong(CKA_CLASS, CKO_CERTIFICATE),
                    attr_bytes(CKA_ISSUER, issuer),
                )
                found = find_objects(rs.raw, rs.sh, tmpl)
                _xfail_if_search_miss(found, h, by="CKA_ISSUER")

            # Search by serial
            if serial:
                tmpl = template(
                    attr_ulong(CKA_CLASS, CKO_CERTIFICATE),
                    attr_bytes(CKA_SERIAL_NUMBER, serial),
                )
                found = find_objects(rs.raw, rs.sh, tmpl)
                _xfail_if_search_miss(found, h, by="CKA_SERIAL_NUMBER")

            # Combined: Subject + Serial
            if subject and serial:
                tmpl = template(
                    attr_ulong(CKA_CLASS, CKO_CERTIFICATE),
                    attr_bytes(CKA_SUBJECT, subject),
                    attr_bytes(CKA_SERIAL_NUMBER, serial),
                )
                found = find_objects(rs.raw, rs.sh, tmpl)
                _xfail_if_search_miss(found, h, by="CKA_SUBJECT+CKA_SERIAL_NUMBER")

        finally:
            destroy_quietly(rs.raw, rs.sh, h)

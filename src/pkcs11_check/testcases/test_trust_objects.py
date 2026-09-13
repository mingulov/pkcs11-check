"""PKCS#11 trust object tests.

CKO_TRUST objects bind trusted usages (server auth, code signing, etc.) to
certificates.  Only some modules implement them; most modules will not
have any trust objects present.  Tests skip gracefully when none are found.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.metadata_std import ATTR_NAMES
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
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
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

# The CKA_TRUST_* usage-attribute family (PKCS#11 v3.2 Table 25) this module reads.
# Bounds the Table-25-footnote-3 absent-default below to *only* these attributes --
# an explicit membership guard, not a file/provider/path allowlist -- so the default
# can never be misapplied to an unrelated attribute id.
_CKA_TRUST_USAGE_ATTRS = frozenset(
    {
        CKA_TRUST_SERVER_AUTH,
        CKA_TRUST_CLIENT_AUTH,
        CKA_TRUST_CODE_SIGNING,
        CKA_TRUST_EMAIL_PROTECTION,
    }
)


def _trust_usage_value_or_unknown(attrs: Mapping[int, Any], attr_id: int) -> tuple[bool, Any]:
    """Return an optional trust usage value with Table 25's absent default.

    PKCS#11 v3.2 Table 25 footnote 3 treats an absent ``CKA_TRUST_XXX`` as
    ``CKT_TRUST_UNKNOWN`` -- this IS the spec-defined case, not a deviation from
    it: v3.2 defines seven ``CKA_TRUST_*`` usages and no ``CKO_TRUST`` object sets
    all seven, so each is optional-with-default (the provider omits the key on
    ``CKR_ATTRIBUTE_TYPE_INVALID``/``CKR_ATTRIBUTE_SENSITIVE``, which is the
    conformant answer for an object that simply does not carry that usage). A
    membership guard (not ``attr_or_record()``) is used deliberately: recording
    this as a *classification* would manufacture a finding against a conformant
    provider -- unlike ``CKA_ISSUER``/``CKA_SERIAL_NUMBER`` elsewhere in this file,
    which ARE required for ``CKO_TRUST`` and so DO get recorded (and classified)
    on absence.

    The omission is still a real, non-gating cross-provider signal worth keeping
    (one provider advertising four usages versus zero is a genuine observable
    difference), so it is logged via ``compliance.note()`` -- the project's
    channel for a conformant-but-notable difference -- rather than dropped
    silently. Preserve the presence bit so an actual on-the-wire
    ``CKT_TRUST_UNKNOWN`` remains distinct from the spec-defined absent case.

    ``attr_id`` MUST be one of ``_CKA_TRUST_USAGE_ATTRS`` -- the spec default this
    function applies is defined only for that trust-usage-attribute family, never
    for an arbitrary attribute.
    """
    if attr_id not in _CKA_TRUST_USAGE_ATTRS:
        raise ValueError(
            "_trust_usage_value_or_unknown is bounded to the CKA_TRUST_* usage-attribute "
            f"family (Table 25); got attribute id 0x{attr_id:08X}"
        )
    if attr_id in attrs:
        return True, attrs[attr_id]
    attr_name = ATTR_NAMES.get(attr_id, f"0x{attr_id:08X}")
    note(
        f"CKO_TRUST object omits {attr_name} (PKCS#11 v3.2 Table 25 footnote 3: an "
        "absent trust usage attribute defaults to CKT_TRUST_UNKNOWN)",
        ComplianceLevel.STANDARD,
        reference="PKCS#11 v3.2 Table 25 footnote 3",
    )
    return False, CKT_TRUST_UNKNOWN


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
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_TRUST CKA_ISSUER read",
                    kind="metadata",
                )
                raise
            issuer = attr_or_record(
                attrs,
                CKA_ISSUER,
                inherit_mechanism=False,
                label="CKO_TRUST CKA_ISSUER",
            )
            if issuer is MISSING_ATTRIBUTE:
                continue
            assert isinstance(issuer, bytes), f"Expected bytes ISSUER, got {type(issuer)}"

    def test_trust_objects_have_serial_number(self, p11_raw_session: Any) -> None:
        """Each CKO_TRUST object has a readable CKA_SERIAL_NUMBER."""
        rs = p11_raw_session
        trusts = _find_trust_objects(rs.raw, rs.sh)
        if not trusts:
            pytest.skip("No CKO_TRUST objects present")
        for h in trusts:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_SERIAL_NUMBER])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_TRUST CKA_SERIAL_NUMBER read",
                    kind="metadata",
                )
                raise
            serial = attr_or_record(
                attrs,
                CKA_SERIAL_NUMBER,
                inherit_mechanism=False,
                label="CKO_TRUST CKA_SERIAL_NUMBER",
            )
            if serial is MISSING_ATTRIBUTE:
                continue
            assert isinstance(serial, bytes), f"Expected bytes SERIAL_NUMBER, got {type(serial)}"

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
            present, val = _trust_usage_value_or_unknown(attrs, CKA_TRUST_SERVER_AUTH)
            if not present:
                continue  # Table 25 footnote 3: absent means CKT_TRUST_UNKNOWN
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
            present, val = _trust_usage_value_or_unknown(attrs, attr_id)
            if not present:
                continue  # Table 25 footnote 3: absent means CKT_TRUST_UNKNOWN
            assert val in _KNOWN_TRUST_VALUES, (
                f"Unknown trust value 0x{val:08X} for attr 0x{attr_id:08X}"
            )
            read_count += 1
        if read_count == 0:
            pytest.skip("No trust usage attributes readable on first trust object")

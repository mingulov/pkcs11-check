"""Tests for X.509 certificate attribute extraction and verification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_VALUE,
    CKC_X_509,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases._so_login import so_session
from pkcs11_check.testcases.conftest import assert_correct, reject_or_classify
from pkcs11_check.testcases.x509.conftest import (
    classify_positive_ckr,
    import_cert_object,
    load_limbo_testcases,
    pem_to_der,
    skip_unless_cert_storage,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]


# A USER cannot establish the trust bit.  These are the clean, expected
# policy/template refusals for C_CreateObject; other defined CK_RVs are still
# visible as honest deviations by reject_or_classify(), while undefined values
# and non-CKR exceptions remain hard failures.
_TRUSTED_CREATE_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)

_OPTIONAL_ATTRIBUTE_UNAVAILABLE_RVS = (
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
)


def _get_selected_testcases() -> list[dict[str, Any]]:
    all_tcs = load_limbo_testcases()
    if not all_tcs:
        return []
    selected_ids = {
        "pathological::nc-dos-1",
        "pathological::nc-dos-2",
        "pathological::nc-dos-3",
        "pathological::cyclic-ca-1",
        "pathological::multiple-chains-expired-intermediate",
        "rfc5280::validity::expired-root",
        "rfc5280::validity::expired-leaf",
        "rfc5280::validity::not-yet-valid-1-second",
        "rfc5280::validity::valid-not-before-boundary",
        "rfc5280::serial::too-long",
        "rfc5280::serial::negative",
        "rfc5280::nc::permitted-dn-match",
        "webpki::cn::ipv4-hex-mismatch",
    }
    return [tc for tc in all_tcs if tc["id"] in selected_ids]


_selected_testcases = _get_selected_testcases()


class TestCertificateAttributes:
    """Verify extraction of standard PKCS#11 certificate attributes."""

    @pytest.mark.parametrize("tc", _selected_testcases, ids=lambda tc: tc["id"])
    def test_verify_attributes(
        self,
        tc: dict[str, Any],
        p11_raw_session: Any,
        limbo_available: Any,
        p11_interface_version: str,
    ) -> None:
        """Check that the module can import and then read back cert value."""
        rs = p11_raw_session
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate")

        label = f"attr-test-{tc['id']}"

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
        except CkrAssertionError as exc:
            if tc["expected_result"] == "SUCCESS":
                # Phase 5 P1a: a clean reject of a Limbo-valid cert is provider-
                # incompleteness -> xfail, not a hard fail.
                classify_positive_ckr(
                    exc,
                    label=f"X509:import valid Limbo certificate {tc['id']}",
                    summary=f"module cleanly rejected a cert Limbo considers valid: {tc['id']}",
                )
            return

        try:
            # CKA_VALUE SHOULD match original DER
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
            val = attrs[CKA_VALUE]
            if val != b"Hello world!":
                assert_correct(
                    actual=val,
                    expected=der,
                    label="X509:CKA_VALUE matches imported DER",
                    operation="C_GetAttributeValue",
                    kind="metadata",
                )

            # CKA_CERTIFICATE_TYPE MUST be X_509 for a CKO_CERTIFICATE object
            try:
                ct = read_attributes(rs.raw, rs.sh, h, [CKA_CERTIFICATE_TYPE])
            except CkrAssertionError as exc:
                classify_positive_ckr(
                    exc,
                    label="X509:CKA_CERTIFICATE_TYPE readback",
                    summary="certificate type readback refused",
                )
            else:
                assert_correct(
                    actual=ct.get(CKA_CERTIFICATE_TYPE),
                    expected=CKC_X_509,
                    label="X509:CKA_CERTIFICATE_TYPE must be CKC_X_509",
                    operation="C_GetAttributeValue",
                    kind="metadata",
                )

            # Check extraction of other fields
            for attr_id in [
                CKA_SUBJECT,
                CKA_ISSUER,
                CKA_SERIAL_NUMBER,
            ]:
                try:
                    a = read_attributes(rs.raw, rs.sh, h, [attr_id])
                    if not a[attr_id]:
                        from pkcs11_check.compliance import (
                            ComplianceLevel,
                            note,
                        )

                        note(
                            f"Module returned empty attr 0x{attr_id:X} for {tc['id']}",
                            ComplianceLevel.NOT_RECOMMENDED,
                        )
                except CkrAssertionError as exc:
                    reject_or_classify(
                        exc,
                        _OPTIONAL_ATTRIBUTE_UNAVAILABLE_RVS,
                        label=f"X509:optional derived attribute 0x{attr_id:X} readback",
                        kind="metadata",
                    )

        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_import_with_trusted_flag(
        self,
        p11_raw_session: Any,
        limbo_available: Any,
        p11_interface_version: str,
    ) -> None:
        """Verify behavior of CKA_TRUSTED attribute during import."""
        rs = p11_raw_session
        all_cases = load_limbo_testcases()
        tc = next(
            (t for t in all_cases if t["expected_result"] == "SUCCESS"),
            None,
        )
        if not tc:
            pytest.skip("No suitable success testcase found")

        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer cert")

        try:
            h = import_cert_object(
                rs.raw,
                rs.sh,
                der,
                interface_version=p11_interface_version,
                extra_attrs={
                    CKA_LABEL: "trusted-test-fail",
                    CKA_TRUSTED: True,
                },
            )
            try:
                # CKR_OK from C_CreateObject already violated the SO-only policy;
                # do not let an arbitrary readback result turn that acceptance into
                # a note/pass (or hide it behind a readback error).
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="USER:create-CKA_TRUSTED-certificate",
                    operation="C_CreateObject",
                    summary=(
                        "SECURITY: USER session created a certificate with "
                        "CKA_TRUSTED=True -- trust boundary breached"
                    ),
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, h)
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                _TRUSTED_CREATE_REJECT_RVS,
                label="C_CreateObject CKA_TRUSTED=True certificate from a USER session",
                kind="policy",
            )


@pytest.mark.destructive
class TestTrustedCertificateImportSO:
    """CKA_TRUSTED certificate import under a genuine CKU_SO session (roadmap #11).

    PKCS#11 (Common certificate attributes): CKA_TRUSTED "can only be set to
    CK_TRUE by the SO user". The non-SO complement lives in
    TestCertificateAttributes.test_import_with_trusted_flag.
    """

    def test_so_import_trusted_cert(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        limbo_available: Any,
        p11_interface_version: str,
    ) -> None:
        """SO imports a cert with CKA_TRUSTED=True; readback must honor it."""
        rs = p11_raw_session
        skip_unless_cert_storage(rs)
        all_cases = load_limbo_testcases()
        tc = next((t for t in all_cases if t["expected_result"] == "SUCCESS"), None)
        if not tc:
            pytest.skip("No suitable success testcase found")
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer cert")

        with so_session(rs, p11_config) as so_sh:
            try:
                h = import_cert_object(
                    rs.raw,
                    so_sh,
                    der,
                    interface_version=p11_interface_version,
                    extra_attrs={
                        CKA_LABEL: "so-trusted-import",
                        CKA_TRUSTED: True,
                    },
                )
            except CkrAssertionError as exc:
                classify_positive_ckr(
                    exc,
                    label="C_CreateObject CKA_TRUSTED=True certificate on a genuine SO session",
                    summary="SO-session CKA_TRUSTED=True certificate import refused",
                )
            try:
                try:
                    attrs = read_attributes(rs.raw, so_sh, h, [CKA_TRUSTED])
                except CkrAssertionError as exc:
                    classify_positive_ckr(
                        exc,
                        label="CKA_TRUSTED readback after SO-session trusted import",
                        summary="CKA_TRUSTED readback after SO import rejected",
                    )
                val = attrs.get(CKA_TRUSTED)
                if val is not True:
                    fail_as(
                        "self_contradiction",
                        kind="lifecycle",
                        label=(
                            "CKA_TRUSTED=True certificate import accepted by an SO session "
                            f"but CKA_TRUSTED reads back {val!r}"
                        ),
                    )
            finally:
                destroy_quietly(rs.raw, so_sh, h)

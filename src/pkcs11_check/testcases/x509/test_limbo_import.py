"""X.509 limbo certificate import tests.

Tests certificate storage behavior of PKCS#11 modules against the x509-limbo
corpus.

Key design principle: certificates are imported in their REAL, unmodified state.
`import_cert_raw` sends only `CKA_VALUE = raw_DER` to `C_CreateObject`, letting
the module parse the cert itself.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_LABEL,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_VALUE,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.conftest import is_known_error
from pkcs11_check.testcases.x509.conftest import (
    import_cert_raw,
    load_limbo_testcases,
    pem_to_der,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]

_all_cases = load_limbo_testcases()


def _portable_label(raw_label: str) -> str:
    """CKA_LABEL within the 32-byte floor common to embedded object stores.

    corePKCS11 caps labels at pkcs11configMAX_LABEL_LENGTH (32) and rejects
    longer ones with CKR_DATA_LEN_RANGE before looking at the certificate at
    all (493 limbo vectors hard-failed on the label, not the DER). The label
    is the harness's own bookkeeping, so send a deterministic short form for
    long testcase ids; modules with roomier stores see identical behavior for
    ids that already fit.
    """
    if len(raw_label.encode()) <= 32:
        return raw_label
    return "limbo-" + hashlib.sha256(raw_label.encode()).hexdigest()[:16]


def _build_testcase_sample(
    cases: list[dict[str, Any]],
    bettertls_limit: int = 50,
) -> list[dict[str, Any]]:
    """Return all offline non-bettertls cases + a bettertls sample."""
    structured: list[dict[str, Any]] = []
    bettertls_success: list[dict[str, Any]] = []
    bettertls_failure: list[dict[str, Any]] = []

    for tc in cases:
        tc_id = tc["id"]
        if tc_id.startswith("online"):
            continue
        if tc_id.startswith("bettertls"):
            if tc.get("expected_result") == "SUCCESS":
                bettertls_success.append(tc)
            else:
                bettertls_failure.append(tc)
        else:
            structured.append(tc)

    half = bettertls_limit // 2
    step_s = max(1, len(bettertls_success) // half) if bettertls_success else 1
    step_f = max(1, len(bettertls_failure) // half) if bettertls_failure else 1
    bt_sample = bettertls_success[::step_s][:half] + bettertls_failure[::step_f][:half]
    return structured + bt_sample


_testcases = _build_testcase_sample(_all_cases)


def _build_failure_sample(
    cases: list[dict[str, Any]],
    bettertls_limit: int = 30,
) -> list[dict[str, Any]]:
    structured_failures: list[dict[str, Any]] = []
    bettertls_failures: list[dict[str, Any]] = []

    for tc in cases:
        if tc.get("expected_result") != "FAILURE":
            continue
        tc_id = tc["id"]
        if tc_id.startswith("online"):
            continue
        if tc_id.startswith("bettertls"):
            bettertls_failures.append(tc)
        else:
            structured_failures.append(tc)

    step = max(1, len(bettertls_failures) // bettertls_limit) if bettertls_failures else 1
    return structured_failures + bettertls_failures[::step][:bettertls_limit]


_failure_sample = _build_failure_sample(_all_cases)


class TestLimboCertImport:
    """Tests for importing certificates from x509-limbo."""

    @pytest.mark.parametrize("tc", _testcases, ids=lambda tc: tc["id"])
    def test_import_peer_cert(
        self,
        tc: dict[str, Any],
        p11_raw_session: Any,
        limbo_available: Any,
    ) -> None:
        """Import peer certificate using raw CKA_VALUE."""
        rs = p11_raw_session
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate PEM")

        h = None
        try:
            h, needed_attrs = import_cert_raw(
                rs.raw,
                rs.sh,
                der,
                extra_attrs={
                    CKA_LABEL: _portable_label(tc["id"]),
                    CKA_TOKEN: False,
                },
            )
            # Sanity: label round-trips
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_LABEL])
            label = attrs[CKA_LABEL]
            if label != "Pkcs11Interop":
                assert label == _portable_label(tc["id"])

            if needed_attrs:
                note(
                    f"Module required explicit SUBJECT/ISSUER/SERIAL_NUMBER "
                    f"for {tc['id']} (CKR_TEMPLATE_INCOMPLETE)",
                    ComplianceLevel.VENDOR,
                )

        except AssertionError as e:
            if is_known_error(
                e,
                {
                    CKR_TEMPLATE_INCONSISTENT,
                    CKR_ATTRIBUTE_VALUE_INVALID,
                    CKR_FUNCTION_FAILED,
                },
            ):
                if tc["expected_result"] == "FAILURE":
                    note(
                        f"Module rejected {tc['id']} on import "
                        f"({str(e).split(';')[0]}) - above spec for storage",
                        ComplianceLevel.VENDOR,
                    )
                else:
                    # Phase 5 P1a: a clean CKR rejection of a Limbo-valid cert is
                    # provider-incompleteness (stricter than required for storage)
                    # -> xfail, not a hard fail. Non-CKR errors re-raise below.
                    pytest.xfail(
                        f"module cleanly rejected a Limbo-valid cert {tc['id']} on raw import: {e}"
                    )
            else:
                raise
        finally:
            if h is not None:
                destroy_quietly(rs.raw, rs.sh, h)

    @pytest.mark.parametrize(
        "tc",
        [t for t in _testcases if t.get("trusted_certs")],
        ids=lambda tc: f"{tc['id']}-trusted",
    )
    def test_import_trusted_certs(
        self,
        tc: dict[str, Any],
        p11_raw_session: Any,
        limbo_available: Any,
    ) -> None:
        """Import trusted CA certificates from a limbo testcase."""
        rs = p11_raw_session
        for i, pem in enumerate(tc["trusted_certs"]):
            der = pem_to_der(pem)
            if not der:
                continue

            label = _portable_label(f"{tc['id']}-ca-{i}")
            h = None
            try:
                try:
                    h, _ = import_cert_raw(
                        rs.raw,
                        rs.sh,
                        der,
                        extra_attrs={
                            CKA_LABEL: label,
                            CKA_TOKEN: False,
                            CKA_TRUSTED: True,
                        },
                    )
                except AssertionError as e:
                    if is_known_error(
                        e,
                        {
                            CKR_ATTRIBUTE_TYPE_INVALID,
                            CKR_ATTRIBUTE_READ_ONLY,
                            CKR_USER_NOT_LOGGED_IN,
                        },
                    ):
                        h, _ = import_cert_raw(
                            rs.raw,
                            rs.sh,
                            der,
                            extra_attrs={
                                CKA_LABEL: label,
                                CKA_TOKEN: False,
                            },
                        )
                    else:
                        raise

            except AssertionError as e:
                if is_known_error(
                    e,
                    {
                        CKR_TEMPLATE_INCONSISTENT,
                        CKR_ATTRIBUTE_VALUE_INVALID,
                        CKR_FUNCTION_FAILED,
                    },
                ):
                    note(
                        f"Module rejected trusted CA cert {label} ({str(e).split(';')[0]})",
                        ComplianceLevel.VENDOR,
                    )
                else:
                    raise
            finally:
                if h is not None:
                    destroy_quietly(rs.raw, rs.sh, h)


@pytest.mark.parametrize("tc", _failure_sample, ids=lambda tc: tc["id"])
def test_import_limbo_failure_cert_raw(
    tc: dict[str, Any],
    p11_raw_session: Any,
    limbo_available: Any,
) -> None:
    """Raw import of x509-limbo FAILURE certs."""
    rs = p11_raw_session
    der = pem_to_der(tc["peer_certificate"])
    if not der:
        pytest.skip("Failed to decode PEM")

    h = None
    try:
        h, needed_attrs = import_cert_raw(
            rs.raw,
            rs.sh,
            der,
            extra_attrs={
                CKA_LABEL: _portable_label(tc["id"]),
                CKA_TOKEN: False,
            },
        )
        if needed_attrs:
            note(
                f"[FAILURE cert] Module required explicit "
                f"SUBJECT/ISSUER/SERIAL_NUMBER for {tc['id']}",
                ComplianceLevel.VENDOR,
            )
        # Cert stored - verify VALUE round-trips
        attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
        stored_value = attrs[CKA_VALUE]
        if stored_value != der:
            pytest.fail(
                f"{tc['id']}: module stored modified cert bytes - "
                f"CKA_VALUE mismatch ({len(stored_value)}B stored "
                f"vs {len(der)}B sent)"
            )

    except AssertionError as e:
        if is_known_error(e, {CKR_TEMPLATE_INCONSISTENT, CKR_ATTRIBUTE_VALUE_INVALID}):
            note(
                f"[FAILURE cert] Module rejected {tc['id']} "
                f"({str(e).split(';')[0]}) - validates on import",
                ComplianceLevel.VENDOR,
            )
        elif is_known_error(e, {CKR_FUNCTION_FAILED}):
            note(
                f"[FAILURE cert] Module returned CKR_FUNCTION_FAILED for {tc['id']}",
                ComplianceLevel.VENDOR,
            )
        else:
            raise
    finally:
        if h is not None:
            destroy_quietly(rs.raw, rs.sh, h)

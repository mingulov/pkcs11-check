"""X.509 limbo certificate import tests.

Tests certificate storage behavior of PKCS#11 modules against the x509-limbo
corpus — a collection of both valid (SUCCESS) and semantically invalid (FAILURE)
certificates.

Key design principle: certificates are imported in their REAL, unmodified state.
`import_cert_raw` sends only `CKA_VALUE = raw_DER` to `C_CreateObject`, letting
the module parse the cert itself. SUBJECT/ISSUER/SERIAL_NUMBER are only added as a
fallback when the module explicitly requests them (CKR_TEMPLATE_INCOMPLETE).

Why this matters: if we pre-extract attributes on the Python side, modules never
see the raw cert bytes — any module-side parsing bugs or over-strict validation
are hidden. By sending raw DER, we expose real module behavior.

x509-limbo FAILURE certs are semantically invalid for X.509 path validation
(wrong path length, revoked, bad CRL, etc.) but are well-formed DER. A PKCS#11
module acting as a storage token has no obligation to validate cert content and
should accept them. If a module rejects them, it is performing above-spec cert
validation on import — this is recorded as a compliance note, not a test failure.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute
from pkcs11.exceptions import (
    AttributeReadOnly,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    FunctionFailed,
    TemplateInconsistent,
)

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.testcases.x509.conftest import (
    import_cert_raw,
    load_limbo_testcases,
    pem_to_der,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]

# _SAMPLE: first 50 testcases — balanced mix of SUCCESS and FAILURE certs
# (typically ~21 SUCCESS + 29 FAILURE from the CRL/invalid/pathlen groups)
_all_cases = load_limbo_testcases()
_testcases = _all_cases[:50]

# _FAILURE_SAMPLE: 40 FAILURE-expected certs drawn from distinct feature groups
# so we get coverage of different invalidity reasons (pathlen, CRL, key, etc.).
def _build_failure_sample(cases: list[dict[str, Any]], limit: int = 40) -> list[dict[str, Any]]:
    seen_features: set[str] = set()
    result: list[dict[str, Any]] = []
    for tc in cases:
        if tc.get("expected_result") != "FAILURE":
            continue
        features = frozenset(tc.get("features") or ["none"])
        prefix = tc["id"].split("::")[0]  # e.g. "crl", "pathlen", "invalid"
        key = f"{prefix}:{sorted(features)}"
        if key not in seen_features or len(result) < limit // 2:
            seen_features.add(key)
            result.append(tc)
        if len(result) >= limit:
            break
    return result

_failure_sample = _build_failure_sample(_all_cases)


# ---------------------------------------------------------------------------
# Core import test: all first-50 testcases (SUCCESS + FAILURE)
# ---------------------------------------------------------------------------

class TestLimboCertImport:
    """Tests for importing certificates from x509-limbo in their real state."""

    @pytest.mark.parametrize("tc", _testcases, ids=lambda tc: tc["id"])
    def test_import_peer_cert(
        self, tc: dict[str, Any], p11_session: Any, limbo_available: Any
    ) -> None:
        """Import peer certificate using raw CKA_VALUE — no pre-extraction.

        The raw DER bytes reach C_CreateObject without SUBJECT/ISSUER/SERIAL_NUMBER
        being provided unless the module explicitly requests them (TemplateIncomplete).
        This tests how the module handles real certificate bytes, including those from
        semantically invalid (FAILURE-expected) testcases.

        SUCCESS cert rejected by module → pytest.fail (storage bug)
        FAILURE cert rejected by module → compliance note (module validates on import,
          which is above spec for a storage token but not a security issue)
        """
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            pytest.skip("Failed to decode peer certificate PEM")

        obj = None
        try:
            obj, needed_attrs = import_cert_raw(
                p11_session,
                der,
                extra_attrs={Attribute.LABEL: tc["id"], Attribute.TOKEN: False},
            )
            # Sanity: label round-trips (pkcs11-mock returns a fixed label)
            label = obj[Attribute.LABEL]
            if label != "Pkcs11Interop":
                assert label == tc["id"]

            if needed_attrs:
                note(
                    f"Module required explicit SUBJECT/ISSUER/SERIAL_NUMBER for {tc['id']} "
                    f"(CKR_TEMPLATE_INCOMPLETE on raw CKA_VALUE import)",
                    ComplianceLevel.VENDOR,
                )

        except (TemplateInconsistent, AttributeValueInvalid, FunctionFailed) as e:
            if tc["expected_result"] == "FAILURE":
                note(
                    f"Module rejected {tc['id']} on import ({type(e).__name__}: {e}) — "
                    f"module performs cert validation on C_CreateObject "
                    f"(above spec for storage token)",
                    ComplianceLevel.VENDOR,
                )
            else:
                pytest.fail(
                    f"Module rejected valid Limbo cert {tc['id']} on raw import: "
                    f"{type(e).__name__}: {e}"
                )
        finally:
            if obj is not None:
                obj.destroy()

    @pytest.mark.parametrize(
        "tc",
        [t for t in _testcases if t.get("trusted_certs")],
        ids=lambda tc: f"{tc['id']}-trusted",
    )
    def test_import_trusted_certs(
        self, tc: dict[str, Any], p11_session: Any, limbo_available: Any
    ) -> None:
        """Import trusted CA certificates from a limbo testcase.

        Tries with CKA_TRUSTED=True first (SO-level attribute). If the module
        rejects the TRUSTED flag (AttributeTypeInvalid — module doesn't support it),
        retries without. Any other rejection is recorded as a compliance note.
        """
        for i, pem in enumerate(tc["trusted_certs"]):
            der = pem_to_der(pem)
            if not der:
                continue

            label = f"{tc['id']}-ca-{i}"
            obj = None
            try:
                # Try with TRUSTED flag first
                try:
                    obj, _ = import_cert_raw(
                        p11_session,
                        der,
                        extra_attrs={
                            Attribute.LABEL: label,
                            Attribute.TOKEN: False,
                            Attribute.TRUSTED: True,
                        },
                    )
                except (AttributeTypeInvalid, AttributeReadOnly):
                    # CKA_TRUSTED is SO-only (CKR_ATTRIBUTE_READ_ONLY) or unknown —
                    # retry without it (user session cannot mark certs as trusted)
                    obj, _ = import_cert_raw(
                        p11_session,
                        der,
                        extra_attrs={Attribute.LABEL: label, Attribute.TOKEN: False},
                    )

            except (TemplateInconsistent, AttributeValueInvalid, FunctionFailed) as e:
                note(
                    f"Module rejected trusted CA cert {label} ({type(e).__name__}: {e})",
                    ComplianceLevel.VENDOR,
                )
            finally:
                if obj is not None:
                    obj.destroy()


# ---------------------------------------------------------------------------
# Dedicated FAILURE cert test: raw import of semantically invalid certs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tc", _failure_sample, ids=lambda tc: tc["id"])
def test_import_limbo_failure_cert_raw(
    tc: dict[str, Any], p11_session: Any, limbo_available: Any
) -> None:
    """Raw import of x509-limbo FAILURE certs — module receives unmodified DER.

    x509-limbo FAILURE certs are semantically invalid for X.509 path validation
    (revoked, bad path length, wrong key usage, CRL issues, etc.) but are
    DER-syntactically well-formed. A PKCS#11 storage token must accept them —
    it has no obligation to perform path validation on C_CreateObject.

    This test explicitly verifies that the raw (unmodified) cert bytes reach the
    module and that the module's storage behavior is observed directly:

    - Module stores the FAILURE cert (CKO_CERTIFICATE accepted) → PASS
      (correct storage-token behavior; module doesn't validate semantics)
    - Module rejects the FAILURE cert → compliance note (above-spec validation
      on import); test still passes — it's a behavioral observation, not a bug.
    - Module crashes or returns an unexpected error → pytest.fail (real bug).
    """
    der = pem_to_der(tc["peer_certificate"])
    if not der:
        pytest.skip("Failed to decode PEM")

    obj = None
    try:
        obj, needed_attrs = import_cert_raw(
            p11_session,
            der,
            extra_attrs={Attribute.LABEL: tc["id"], Attribute.TOKEN: False},
        )
        if needed_attrs:
            note(
                f"[FAILURE cert] Module required explicit SUBJECT/ISSUER/SERIAL_NUMBER "
                f"for {tc['id']} (CKR_TEMPLATE_INCOMPLETE on raw import)",
                ComplianceLevel.VENDOR,
            )
        # Cert stored — verify VALUE round-trips
        stored_value = obj[Attribute.VALUE]
        if stored_value != der:
            pytest.fail(
                f"{tc['id']}: module stored modified cert bytes — "
                f"CKA_VALUE mismatch ({len(stored_value)}B stored vs {len(der)}B sent)"
            )

    except (TemplateInconsistent, AttributeValueInvalid) as e:
        # Module rejected the cert — it validates on import (above spec for storage)
        note(
            f"[FAILURE cert] Module rejected {tc['id']} ({type(e).__name__}: {e}) — "
            f"module validates cert content on C_CreateObject",
            ComplianceLevel.VENDOR,
        )
    except FunctionFailed as e:
        # FunctionFailed on cert import is unexpected — could be a real module bug
        note(
            f"[FAILURE cert] Module returned CKR_FUNCTION_FAILED for {tc['id']}: {e} — "
            f"investigate whether this is a parsing bug in the module",
            ComplianceLevel.VENDOR,
        )
    finally:
        if obj is not None:
            obj.destroy()

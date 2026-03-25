"""Tests for X.509 attribute extraction parity between PKCS#11 and ground truth."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import CKA_LABEL, CKA_TOKEN
from pkcs11_check.testcases.x509.conftest import (
    import_cert_object,
    pem_to_der,
    verify_attribute_parity,
)

pytestmark = [pytest.mark.cert, pytest.mark.compliance]


def test_limbo_attribute_parity(
    p11_raw_session: Any,
    cert_support: bool,
    all_limbo_cases: list[dict[str, Any]],
    limbo_filter: Any,
    p11_interface_version: str,
) -> None:
    """Import certificates from Limbo and verify attribute extraction parity."""
    if not cert_support:
        pytest.skip("Module does not support X.509 certificates")

    rs = p11_raw_session
    cases = limbo_filter(all_limbo_cases, limit=100)

    errors: list[str] = []
    for tc in cases:
        der = pem_to_der(tc["peer_certificate"])
        if not der:
            continue

        try:
            h = import_cert_object(
                rs.raw, rs.sh,
                der,
                interface_version=p11_interface_version,
                extra_attrs={
                    int(CKA_LABEL): tc["id"],
                    int(CKA_TOKEN): False,
                },
            )

            parity = verify_attribute_parity(
                rs.raw, rs.sh, h, der,
                interface_version=p11_interface_version,
            )

            for attr, (matches, p11_val, expected_val, required) in (
                parity.items()
            ):
                if matches is False:
                    errors.append(
                        f"TC {tc['id']} - {attr} mismatch:\n"
                        f"  Observed: {p11_val}\n"
                        f"  Expected: {expected_val}"
                    )
                elif matches is None and required:
                    errors.append(
                        f"TC {tc['id']} - {attr} NOT EXTRACTED "
                        f"(Mandatory per OASIS)"
                    )

            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as e:
            if tc["expected_result"] == "SUCCESS":
                errors.append(
                    f"TC {tc['id']} - Failed to import valid cert: {e}"
                )
            continue
        except Exception as e:
            errors.append(f"TC {tc['id']} - Unexpected exception: {e}")
            continue

    if errors:
        pytest.fail("\n".join(errors))

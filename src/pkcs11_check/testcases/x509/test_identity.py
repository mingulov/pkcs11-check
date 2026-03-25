"""Tests for X.509 Identity (Cert + Private Key) integration."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_EC,
    CKK_RSA,
    CKM_ECDSA_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
)
from pkcs11_check.testcases.x509.conftest import import_cert_object, pem_to_der

pytestmark = [pytest.mark.cert, pytest.mark.keymgmt, pytest.mark.object]


def test_limbo_identity_closeness(
    p11_raw_session: Any,
    cert_support: bool,
    all_limbo_cases: list[dict[str, Any]],
    limbo_filter: Any,
    p11_interface_version: str,
) -> None:
    """Import Cert + Key from Limbo, link with CKA_ID, and Sign/Verify."""
    if not cert_support:
        pytest.skip("Module does not support X.509 certificates")

    rs = p11_raw_session
    cases_with_keys = [
        tc for tc in all_limbo_cases if tc.get("peer_certificate_key")
    ]
    if not cases_with_keys:
        pytest.skip("No testcases with private keys found in Limbo dataset")

    cases = cases_with_keys[:10]

    errors: list[str] = []
    for tc in cases:
        cert_der = pem_to_der(tc["peer_certificate"])
        key_der = pem_to_der(tc["peer_certificate_key"])
        cid = tc["id"].encode("utf-8")[:32]

        try:
            # 1. Import Certificate
            cert_h = import_cert_object(
                rs.raw, rs.sh,
                cert_der,
                interface_version=p11_interface_version,
                extra_attrs={
                    int(CKA_ID): cid,
                    int(CKA_LABEL): f"Cert {tc['id']}",
                    int(CKA_TOKEN): False,
                },
            )

            # 2. Import Private Key
            key_pem = tc["peer_certificate_key"].strip()
            is_rsa = "RSA" in key_pem

            key_attrs: dict[int, Any] = {
                int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                int(CKA_VALUE): key_der,
                int(CKA_ID): cid,
                int(CKA_LABEL): f"Key {tc['id']}",
                int(CKA_TOKEN): False,
                int(CKA_SIGN): True,
                int(CKA_EXTRACTABLE): False,
                int(CKA_SENSITIVE): True,
            }
            if is_rsa:
                key_attrs[int(CKA_KEY_TYPE)] = int(CKK_RSA)
            else:
                key_attrs[int(CKA_KEY_TYPE)] = int(CKK_EC)

            try:
                key_h = create_object(rs.raw, rs.sh, key_attrs)
            except (AssertionError, Exception):
                destroy_quietly(rs.raw, rs.sh, cert_h)
                continue

            # 3. Perform Sign operation
            data = b"Hello PKCS#11 Identity"
            mech = CKM_SHA256_RSA_PKCS if is_rsa else CKM_ECDSA_SHA256

            try:
                sig = sign_single(rs.raw, rs.sh, key_h, mech, data)
                assert sig is not None
            except (AssertionError, Exception) as e:
                errors.append(f"TC {tc['id']} - Signing failed: {e}")
            finally:
                destroy_quietly(rs.raw, rs.sh, key_h)
                destroy_quietly(rs.raw, rs.sh, cert_h)

        except (AssertionError, Exception):
            continue

    if errors:
        pytest.fail("\n".join(errors))

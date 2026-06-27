"""Detect how a module accepts EdDSA public-key encodings.

The PKCS#11 spec requires raw RFC 8032 public-key bytes for
``CKK_EC_EDWARDS`` ``CKA_EC_POINT``. Some modules only verify signatures when
the same bytes are wrapped in a DER OCTET STRING; this test keeps that behavior
visible while vector tests use the encoding that actually works.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.testcases._eddsa_public_key import probe_eddsa_public_key_encodings

pytestmark = pytest.mark.kat
REQUIRED_MECHANISMS = ["EDDSA"]

_ED25519_OID = bytes.fromhex("06032b6570")

# RFC 8032 Section 7.1, Ed25519 test 1.
_RFC8032_ED25519_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_RFC8032_ED25519_MESSAGE = b""
_RFC8032_ED25519_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_eddsa_public_key_encoding_support(p11_raw_session: Any) -> None:
    """Show whether EdDSA verification works with raw or DER-wrapped CKA_EC_POINT."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported by module")

    support = probe_eddsa_public_key_encodings(
        rs.raw,
        rs.sh,
        ec_params=_ED25519_OID,
        public_key=_RFC8032_ED25519_PUBLIC_KEY,
        message=_RFC8032_ED25519_MESSAGE,
        signature=_RFC8032_ED25519_SIGNATURE,
    )

    if support["raw"]:
        if support["der"]:
            note(
                "EdDSA public-key import also accepts DER-wrapped CKA_EC_POINT",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=(
                    "OASIS PKCS#11 v3.2 spec: CKK_EC_EDWARDS CKA_EC_POINT uses raw RFC 8032 bytes"
                ),
            )
        return

    if support["der"]:
        classify(
            "not_operational",
            kind="crypto",
            label="EDDSA:public-key-encoding",
            operation="C_Verify",
            mechanism="EDDSA",
            summary=(
                "EdDSA verifies only with DER-wrapped CKA_EC_POINT; "
                "PKCS#11 requires raw RFC 8032 public-key bytes for CKK_EC_EDWARDS"
            ),
        )

    classify(
        "not_operational",
        kind="crypto",
        label="EDDSA:public-key-encoding",
        operation="C_Verify",
        mechanism="EDDSA",
        summary=(
            "EdDSA cannot verify the RFC 8032 Ed25519 vector with raw or DER-wrapped CKA_EC_POINT"
        ),
    )

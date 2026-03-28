"""Wycheproof X25519 and X448 key exchange vectors.

Tests Montgomery curve Diffie-Hellman (RFC 7748) using CKM_ECDH1_DERIVE
with EC_MONTGOMERY key type across raw, ASN.1, PEM, and JWK encodings.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_ec_private_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_EC_MONTGOMERY,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
)
from pkcs11_check.testcases.wycheproof._key_decoders import (
    decode_xdh_private_bytes,
    decode_xdh_public_bytes,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# OIDs for Montgomery curves
X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])  # 1.3.101.110
X448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])  # 1.3.101.111

_X25519_X448_FILES = [
    ("x25519_test.json", X25519_OID, 32, "raw"),
    ("x25519_asn_test.json", X25519_OID, 32, "asn"),
    ("x25519_jwk_test.json", X25519_OID, 32, "jwk"),
    ("x25519_pem_test.json", X25519_OID, 32, "pem"),
    ("x448_test.json", X448_OID, 56, "raw"),
    ("x448_asn_test.json", X448_OID, 56, "asn"),
    ("x448_jwk_test.json", X448_OID, 56, "jwk"),
    ("x448_pem_test.json", X448_OID, 56, "pem"),
]


def _load_xdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load X25519/X448 key exchange vectors."""
    vectors = []
    for filename, oid, key_size, encoding_name in _X25519_X448_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_oid"] = oid
                test["_key_size"] = key_size
                test["_encoding"] = encoding_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_XDH_VECTORS = _load_xdh_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_XDH_VECTORS, ids=[v[0] for v in _ALL_XDH_VECTORS])
def test_xdh(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """X25519/X448 key exchange from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDH1_DERIVE"):
        pytest.skip("ECDH1_DERIVE not supported")

    oid = vec["_oid"]
    key_size = vec["_key_size"]
    encoding_name = vec["_encoding"]
    try:
        public_bytes = decode_xdh_public_bytes(vec["public"], encoding_name)
        private_bytes = decode_xdh_private_bytes(vec["private"], encoding_name)
    except Exception as exc:
        pytest.skip(f"Cannot decode {encoding_name} XDH vector: {type(exc).__name__}")
    shared_expected = bytes.fromhex(vec["shared"])
    result = vec["result"]

    # Import Montgomery private key
    try:
        priv_key = import_ec_private_key(
            rs.raw, rs.sh,
            ec_params=oid, value=private_bytes,
            key_type=int(CKK_EC_MONTGOMERY),
            attrs={CKA_DERIVE: True},
        )
    except (AssertionError, AttributeError):
        if result == "invalid":
            return
        pytest.skip("Cannot import Montgomery private key")

    # Derive shared secret
    ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=public_bytes)
    shared = None
    try:
        derived = derive_key(
            rs.raw,
            rs.sh,
            priv_key,
            CKM_ECDH1_DERIVE,
            attrs={
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: key_size,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=ecdh_param,
        )
        attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
        shared = attrs[CKA_VALUE]
        assert isinstance(shared, bytes)
        destroy_quietly(rs.raw, rs.sh, derived)
    except (AssertionError, TypeError):
        if result == "valid":
            pytest.fail(f"X25519/X448 derive failed for valid vector {vec_id}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and shared is not None:
        assert shared == shared_expected

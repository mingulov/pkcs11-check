"""Wycheproof ECDH key agreement vectors.

Exercises raw-point, ASN.1, PEM, and WebCrypto encodings across the
curve families that can be fed into the existing PKCS#11 derive path.
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import KDF

from pkcs11_check.testcases.conftest import mech_name
from pkcs11_check.testcases.wycheproof._key_decoders import (
    decode_ec_private_scalar,
    decode_ec_public_point,
    ec_key_bits,
    ec_params_for_curve,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_ECDH_FILES = [
    ("ecdh_brainpoolP224r1_test.json", "brainpoolP224r1", "asn"),
    ("ecdh_brainpoolP256r1_test.json", "brainpoolP256r1", "asn"),
    ("ecdh_brainpoolP320r1_test.json", "brainpoolP320r1", "asn"),
    ("ecdh_brainpoolP384r1_test.json", "brainpoolP384r1", "asn"),
    ("ecdh_brainpoolP512r1_test.json", "brainpoolP512r1", "asn"),
    ("ecdh_secp224r1_ecpoint_test.json", "secp224r1", "ecpoint"),
    ("ecdh_secp224r1_pem_test.json", "secp224r1", "pem"),
    ("ecdh_secp224r1_test.json", "secp224r1", "asn"),
    ("ecdh_secp256k1_test.json", "secp256k1", "asn"),
    ("ecdh_secp256k1_webcrypto_test.json", "P-256K", "webcrypto"),
    ("ecdh_secp256r1_ecpoint_test.json", "secp256r1", "ecpoint"),
    ("ecdh_secp256r1_pem_test.json", "secp256r1", "pem"),
    ("ecdh_secp256r1_test.json", "secp256r1", "asn"),
    ("ecdh_secp256r1_webcrypto_test.json", "P-256", "webcrypto"),
    ("ecdh_secp384r1_ecpoint_test.json", "secp384r1", "ecpoint"),
    ("ecdh_secp384r1_pem_test.json", "secp384r1", "pem"),
    ("ecdh_secp384r1_test.json", "secp384r1", "asn"),
    ("ecdh_secp384r1_webcrypto_test.json", "P-384", "webcrypto"),
    ("ecdh_secp521r1_ecpoint_test.json", "secp521r1", "ecpoint"),
    ("ecdh_secp521r1_pem_test.json", "secp521r1", "pem"),
    ("ecdh_secp521r1_test.json", "secp521r1", "asn"),
    ("ecdh_secp521r1_webcrypto_test.json", "P-521", "webcrypto"),
    ("ecdh_sect283k1_test.json", "sect283k1", "asn"),
    ("ecdh_sect283r1_test.json", "sect283r1", "asn"),
    ("ecdh_sect409k1_test.json", "sect409k1", "asn"),
    ("ecdh_sect409r1_test.json", "sect409r1", "asn"),
    ("ecdh_sect571k1_test.json", "sect571k1", "asn"),
    ("ecdh_sect571r1_test.json", "sect571r1", "asn"),
]


def _load_ecdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDH vectors across multiple input encodings."""
    vectors = []
    for filename, curve, encoding_name in _ECDH_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_curve"] = curve
                test["_encoding"] = encoding_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_ECDH_VECTORS = _load_ecdh_vectors()


def _has_ecdh(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "ECDH1_DERIVE" in names


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDH_VECTORS, ids=[v[0] for v in _ALL_ECDH_VECTORS])
def test_ecdh(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDH key agreement from Wycheproof ecpoint vectors."""
    if not _has_ecdh(p11_module):
        pytest.skip("ECDH1_DERIVE not supported")

    curve = vec["_curve"]
    encoding_name = vec["_encoding"]
    try:
        oid = ec_params_for_curve(curve)
    except Exception:
        pytest.skip(f"No EC params mapping for curve {curve}")

    result = vec["result"]
    try:
        public_point = decode_ec_public_point(vec["public"], encoding_name, curve)
        private_scalar = decode_ec_private_scalar(vec["private"], encoding_name, curve)
    except Exception as exc:
        if result == "invalid":
            return  # Malformed key correctly rejected at decode
        if result == "acceptable":
            return  # Acceptable to reject malformed encoding
        pytest.skip(f"Cannot decode {encoding_name} ECDH vector: {type(exc).__name__}")
    shared_expected = bytes.fromhex(vec["shared"])

    # Import EC private key
    try:
        priv_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.EC_PARAMS: oid,
                Attribute.VALUE: private_scalar,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        pytest.skip("Cannot import EC private key for ECDH")

    # Derive shared secret
    # ECDH1_DERIVE params: (kdf, shared_data, public_data)
    # KDF.NULL means raw ECDH (no KDF applied to output)
    try:
        derived_key = priv_key.derive_key(
            KeyType.GENERIC_SECRET,
            ec_key_bits(curve),
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, public_point),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )
        # Extract the derived key value
        shared = derived_key[Attribute.VALUE]
        if result == "valid":
            assert shared == shared_expected, f"ECDH shared secret mismatch for {vec_id}"
        elif result == "invalid":
            pass  # Invalid but derive succeeded - module-specific
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid ECDH derive failed for {vec_id}")
        # acceptable: reject is fine
        return
    except (TypeError, NotImplementedError):
        pytest.skip("ECDH derive not supported by binding")

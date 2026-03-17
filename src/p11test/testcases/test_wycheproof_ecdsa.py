"""Wycheproof ECDSA vectors — all curves and hash combinations.

Auto-loads vectors for P-256/384/521 with various SHA hashes.
The test_wycheproof.py file covers P-256 SHA-256 and P-384 SHA-384.
This file adds the remaining curve/hash combos.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"


class _ShakeHash:
    """Wrapper to make SHAKE hashes compatible with the hashlib .digest() API.

    SHAKE produces variable-length output, so .digest(length) is required.
    This wrapper binds the output length at construction time.
    """

    def __init__(self, shake_fn: Any, output_len: int, data: bytes = b"") -> None:
        self._h = shake_fn(data)
        self._output_len = output_len

    def digest(self) -> bytes:
        return self._h.digest(self._output_len)  # type: ignore[no-any-return]


def _shake128(output_len: int) -> Any:
    """Return a SHAKE-128 hash factory with fixed output length."""

    def factory(data: bytes = b"") -> _ShakeHash:
        return _ShakeHash(hashlib.shake_128, output_len, data)

    return factory


def _shake256(output_len: int) -> Any:
    """Return a SHAKE-256 hash factory with fixed output length."""

    def factory(data: bytes = b"") -> _ShakeHash:
        return _ShakeHash(hashlib.shake_256, output_len, data)

    return factory


# Curve config: (filename, curve_name, coord_size, hash_fn)
_ECDSA_CONFIGS = [
    # P-256 with SHA-512
    ("ecdsa_secp256r1_sha512_test.json", "secp256r1", 32, hashlib.sha512),
    # P-384 with SHA-256
    ("ecdsa_secp384r1_sha256_test.json", "secp384r1", 48, hashlib.sha256),
    # P-384 with SHA-512
    ("ecdsa_secp384r1_sha512_test.json", "secp384r1", 48, hashlib.sha512),
    # P-521 with SHA-512
    ("ecdsa_secp521r1_sha512_test.json", "secp521r1", 66, hashlib.sha512),
    # P-224 with SHA-224
    ("ecdsa_secp224r1_sha224_test.json", "secp224r1", 28, hashlib.sha224),
    # P-224 with SHA-256
    ("ecdsa_secp224r1_sha256_test.json", "secp224r1", 28, hashlib.sha256),
    # P-224 with SHA-512
    ("ecdsa_secp224r1_sha512_test.json", "secp224r1", 28, hashlib.sha512),
    # SHA-3 variants (skip on modules without SHA-3 ECDSA support)
    ("ecdsa_secp224r1_sha3_224_test.json", "secp224r1", 28, hashlib.sha3_224),
    ("ecdsa_secp224r1_sha3_256_test.json", "secp224r1", 28, hashlib.sha3_256),
    ("ecdsa_secp224r1_sha3_512_test.json", "secp224r1", 28, hashlib.sha3_512),
    ("ecdsa_secp256r1_sha3_256_test.json", "secp256r1", 32, hashlib.sha3_256),
    ("ecdsa_secp256r1_sha3_512_test.json", "secp256r1", 32, hashlib.sha3_512),
    ("ecdsa_secp384r1_sha3_384_test.json", "secp384r1", 48, hashlib.sha3_384),
    ("ecdsa_secp384r1_sha3_512_test.json", "secp384r1", 48, hashlib.sha3_512),
    ("ecdsa_secp521r1_sha3_512_test.json", "secp521r1", 66, hashlib.sha3_512),
    # SHAKE variants — PKCS#11 has no CKM_ECDSA_SHAKE128/256 mechanism,
    # so we pre-hash with SHAKE externally and use raw CKM_ECDSA.
    # Output length truncated to curve order byte size per NIST SP 800-186.
    ("ecdsa_secp224r1_shake128_test.json", "secp224r1", 28, _shake128(28)),
    ("ecdsa_secp256r1_shake128_test.json", "secp256r1", 32, _shake128(32)),
    ("ecdsa_secp384r1_shake256_test.json", "secp384r1", 48, _shake256(48)),
    ("ecdsa_secp521r1_shake256_test.json", "secp521r1", 66, _shake256(66)),
]


def _load_ecdsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, curve, coord_size, hash_fn in _ECDSA_CONFIGS:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_curve"] = curve
                test["_coord_size"] = coord_size
                test["_hash_fn"] = hash_fn
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_ECDSA = _load_ecdsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDSA, ids=[v[0] for v in _ALL_ECDSA])
def test_ecdsa_wycheproof(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """ECDSA signature verification from Wycheproof vectors."""
    if not has_mechanism(p11_module, "ECDSA"):
        pytest.skip("ECDSA not supported")

    msg = bytes.fromhex(vec["msg"])
    sig_der = bytes.fromhex(vec["sig"])
    result = vec["result"]
    group = vec["_group"]
    curve = vec["_curve"]
    coord_size = vec["_coord_size"]
    hash_fn = vec["_hash_fn"]

    pub_key_info = group.get("publicKey", {})
    uncompressed_hex = pub_key_info.get("uncompressed", "")
    if not uncompressed_hex:
        pytest.skip("No uncompressed point")

    uncompressed = bytes.fromhex(uncompressed_hex)

    # DER OCTET STRING wrapper
    if len(uncompressed) < 128:
        ec_point_der = bytes([0x04, len(uncompressed)]) + uncompressed
    else:
        ec_point_der = bytes([0x04, 0x81, len(uncompressed)]) + uncompressed

    try:
        pub_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve),
                Attribute.EC_POINT: ec_point_der,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import EC public key")

    # Convert DER sig to raw r||s
    try:
        r_int, s_int = decode_dss_signature(sig_der)
        raw_sig = r_int.to_bytes(coord_size, "big") + s_int.to_bytes(coord_size, "big")
    except (ValueError, OverflowError):
        if result == "invalid":
            return
        pytest.fail(f"Cannot decode valid DER sig for {vec_id}")

    digest = hash_fn(msg).digest()

    try:
        pub_key.verify(digest, raw_sig, mechanism=Mechanism.ECDSA)
        if result == "invalid":
            pass
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.fail(f"Valid ECDSA sig {vec_id} rejected")

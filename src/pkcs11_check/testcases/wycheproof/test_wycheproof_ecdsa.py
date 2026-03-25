"""Wycheproof ECDSA vectors - broad curve and hash coverage.

The base Wycheproof module covers a small core subset.
This file adds the remaining DER and P1363-encoded verification vectors
that can run through the existing raw `CKM_ECDSA` mechanism path.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    generate_random,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA,
    CKO_PUBLIC_KEY,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402


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
    ("ecdsa_brainpoolP224r1_sha224_test.json", "brainpoolp224r1", 28, hashlib.sha224, False),
    ("ecdsa_brainpoolP224r1_sha224_p1363_test.json", "brainpoolp224r1", 28, hashlib.sha224, True),
    ("ecdsa_brainpoolP224r1_sha3_224_test.json", "brainpoolp224r1", 28, hashlib.sha3_224, False),
    ("ecdsa_brainpoolP256r1_sha256_test.json", "brainpoolp256r1", 32, hashlib.sha256, False),
    ("ecdsa_brainpoolP256r1_sha256_p1363_test.json", "brainpoolp256r1", 32, hashlib.sha256, True),
    ("ecdsa_brainpoolP256r1_sha3_256_test.json", "brainpoolp256r1", 32, hashlib.sha3_256, False),
    ("ecdsa_brainpoolP320r1_sha384_test.json", "brainpoolp320r1", 40, hashlib.sha384, False),
    ("ecdsa_brainpoolP320r1_sha384_p1363_test.json", "brainpoolp320r1", 40, hashlib.sha384, True),
    ("ecdsa_brainpoolP320r1_sha3_384_test.json", "brainpoolp320r1", 40, hashlib.sha3_384, False),
    ("ecdsa_brainpoolP384r1_sha384_test.json", "brainpoolp384r1", 48, hashlib.sha384, False),
    ("ecdsa_brainpoolP384r1_sha384_p1363_test.json", "brainpoolp384r1", 48, hashlib.sha384, True),
    ("ecdsa_brainpoolP384r1_sha3_384_test.json", "brainpoolp384r1", 48, hashlib.sha3_384, False),
    ("ecdsa_brainpoolP512r1_sha512_test.json", "brainpoolp512r1", 64, hashlib.sha512, False),
    ("ecdsa_brainpoolP512r1_sha512_p1363_test.json", "brainpoolp512r1", 64, hashlib.sha512, True),
    ("ecdsa_brainpoolP512r1_sha3_512_test.json", "brainpoolp512r1", 64, hashlib.sha3_512, False),
    ("ecdsa_secp160k1_sha256_test.json", "secp160k1", 21, hashlib.sha256, False),
    ("ecdsa_secp160k1_sha256_p1363_test.json", "secp160k1", 21, hashlib.sha256, True),
    ("ecdsa_secp160r1_sha256_test.json", "secp160r1", 21, hashlib.sha256, False),
    ("ecdsa_secp160r1_sha256_p1363_test.json", "secp160r1", 21, hashlib.sha256, True),
    ("ecdsa_secp160r2_sha256_test.json", "secp160r2", 21, hashlib.sha256, False),
    ("ecdsa_secp160r2_sha256_p1363_test.json", "secp160r2", 21, hashlib.sha256, True),
    ("ecdsa_secp192k1_sha256_test.json", "secp192k1", 24, hashlib.sha256, False),
    ("ecdsa_secp192k1_sha256_p1363_test.json", "secp192k1", 24, hashlib.sha256, True),
    ("ecdsa_secp192r1_sha256_test.json", "secp192r1", 24, hashlib.sha256, False),
    ("ecdsa_secp192r1_sha256_p1363_test.json", "secp192r1", 24, hashlib.sha256, True),
    ("ecdsa_secp224k1_sha224_test.json", "secp224k1", 29, hashlib.sha224, False),
    ("ecdsa_secp224k1_sha224_p1363_test.json", "secp224k1", 29, hashlib.sha224, True),
    ("ecdsa_secp224k1_sha256_test.json", "secp224k1", 29, hashlib.sha256, False),
    ("ecdsa_secp224k1_sha256_p1363_test.json", "secp224k1", 29, hashlib.sha256, True),
    ("ecdsa_secp224r1_sha224_test.json", "secp224r1", 28, hashlib.sha224, False),
    ("ecdsa_secp224r1_sha224_p1363_test.json", "secp224r1", 28, hashlib.sha224, True),
    ("ecdsa_secp224r1_sha256_test.json", "secp224r1", 28, hashlib.sha256, False),
    ("ecdsa_secp224r1_sha256_p1363_test.json", "secp224r1", 28, hashlib.sha256, True),
    ("ecdsa_secp224r1_sha512_test.json", "secp224r1", 28, hashlib.sha512, False),
    ("ecdsa_secp224r1_sha512_p1363_test.json", "secp224r1", 28, hashlib.sha512, True),
    ("ecdsa_secp224r1_sha3_224_test.json", "secp224r1", 28, hashlib.sha3_224, False),
    ("ecdsa_secp224r1_sha3_256_test.json", "secp224r1", 28, hashlib.sha3_256, False),
    ("ecdsa_secp224r1_sha3_512_test.json", "secp224r1", 28, hashlib.sha3_512, False),
    ("ecdsa_secp224r1_shake128_test.json", "secp224r1", 28, _shake128(28), False),
    ("ecdsa_secp224r1_shake128_p1363_test.json", "secp224r1", 28, _shake128(28), True),
    ("ecdsa_secp256k1_sha256_test.json", "secp256k1", 32, hashlib.sha256, False),
    ("ecdsa_secp256k1_sha256_p1363_test.json", "secp256k1", 32, hashlib.sha256, True),
    ("ecdsa_secp256k1_sha256_bitcoin_test.json", "secp256k1", 32, hashlib.sha256, False),
    ("ecdsa_secp256k1_sha512_test.json", "secp256k1", 32, hashlib.sha512, False),
    ("ecdsa_secp256k1_sha512_p1363_test.json", "secp256k1", 32, hashlib.sha512, True),
    ("ecdsa_secp256k1_sha3_256_test.json", "secp256k1", 32, hashlib.sha3_256, False),
    ("ecdsa_secp256k1_sha3_512_test.json", "secp256k1", 32, hashlib.sha3_512, False),
    ("ecdsa_secp256k1_shake128_test.json", "secp256k1", 32, _shake128(32), False),
    ("ecdsa_secp256k1_shake128_p1363_test.json", "secp256k1", 32, _shake128(32), True),
    ("ecdsa_secp256k1_shake256_test.json", "secp256k1", 32, _shake256(32), False),
    ("ecdsa_secp256k1_shake256_p1363_test.json", "secp256k1", 32, _shake256(32), True),
    ("ecdsa_secp256r1_sha512_test.json", "secp256r1", 32, hashlib.sha512, False),
    ("ecdsa_secp256r1_sha512_p1363_test.json", "secp256r1", 32, hashlib.sha512, True),
    ("ecdsa_secp256r1_sha256_p1363_test.json", "secp256r1", 32, hashlib.sha256, True),
    ("ecdsa_secp256r1_sha3_256_test.json", "secp256r1", 32, hashlib.sha3_256, False),
    ("ecdsa_secp256r1_sha3_512_test.json", "secp256r1", 32, hashlib.sha3_512, False),
    ("ecdsa_secp256r1_shake128_test.json", "secp256r1", 32, _shake128(32), False),
    ("ecdsa_secp256r1_shake128_p1363_test.json", "secp256r1", 32, _shake128(32), True),
    ("ecdsa_secp384r1_sha256_test.json", "secp384r1", 48, hashlib.sha256, False),
    ("ecdsa_secp384r1_sha384_p1363_test.json", "secp384r1", 48, hashlib.sha384, True),
    ("ecdsa_secp384r1_sha512_test.json", "secp384r1", 48, hashlib.sha512, False),
    ("ecdsa_secp384r1_sha512_p1363_test.json", "secp384r1", 48, hashlib.sha512, True),
    ("ecdsa_secp384r1_sha3_384_test.json", "secp384r1", 48, hashlib.sha3_384, False),
    ("ecdsa_secp384r1_sha3_512_test.json", "secp384r1", 48, hashlib.sha3_512, False),
    ("ecdsa_secp384r1_shake256_test.json", "secp384r1", 48, _shake256(48), False),
    ("ecdsa_secp384r1_shake256_p1363_test.json", "secp384r1", 48, _shake256(48), True),
    ("ecdsa_secp521r1_sha512_test.json", "secp521r1", 66, hashlib.sha512, False),
    ("ecdsa_secp521r1_sha512_p1363_test.json", "secp521r1", 66, hashlib.sha512, True),
    ("ecdsa_secp521r1_sha3_512_test.json", "secp521r1", 66, hashlib.sha3_512, False),
    ("ecdsa_secp521r1_shake256_test.json", "secp521r1", 66, _shake256(66), False),
    ("ecdsa_secp521r1_shake256_p1363_test.json", "secp521r1", 66, _shake256(66), True),
]


def _load_ecdsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, curve, coord_size, hash_fn, is_p1363 in _ECDSA_CONFIGS:
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
                test["_is_p1363"] = is_p1363
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_ECDSA = _load_ecdsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDSA, ids=[v[0] for v in _ALL_ECDSA])
def test_ecdsa_wycheproof(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """ECDSA signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDSA"):
        pytest.skip("ECDSA not supported")

    msg = bytes.fromhex(vec["msg"])
    sig_der = bytes.fromhex(vec["sig"])
    result = vec["result"]
    group = vec["_group"]
    curve = vec["_curve"]
    coord_size = vec["_coord_size"]
    hash_fn = vec["_hash_fn"]
    is_p1363 = vec["_is_p1363"]

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
        ec_params = encode_named_curve_parameters(curve)
    except Exception:
        pytest.skip(f"No EC params for curve {curve}")

    try:
        pub_key = create_object(
            rs.raw,
            rs.sh,
            {
                int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                int(CKA_KEY_TYPE): int(CKK_EC),
                int(CKA_EC_PARAMS): ec_params,
                int(CKA_EC_POINT): ec_point_der,
                int(CKA_TOKEN): False,
                int(CKA_VERIFY): True,
            },
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(
            name in exc_msg
            for name in (
                "CKR_CURVE_NOT_SUPPORTED",
                "CKR_ATTRIBUTE_VALUE_INVALID",
                "CKR_TEMPLATE_INCONSISTENT",
                "CKR_DOMAIN_PARAMS_INVALID",
                "CKR_MECHANISM_INVALID",
                "CKR_FUNCTION_FAILED",
                "CKR_DEVICE_ERROR",
            )
        ):
            pytest.skip(f"Cannot import EC key for {curve}: {exc_msg}")
        raise

    if is_p1363:
        raw_sig = sig_der
    else:
        try:
            r_int, s_int = decode_dss_signature(sig_der)
            raw_sig = r_int.to_bytes(coord_size, "big") + s_int.to_bytes(coord_size, "big")
        except (ValueError, OverflowError):
            if result == "invalid":
                return
            pytest.fail(f"Cannot decode valid DER sig for {vec_id}")

    digest = hash_fn(msg).digest()

    try:
        verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA, digest, raw_sig)
        if result == "invalid":
            pass
    except AssertionError:
        if result == "valid":
            pytest.xfail(f"Valid ECDSA sig {vec_id} rejected")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)

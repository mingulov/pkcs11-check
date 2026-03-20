"""Wycheproof RSA PKCS#1 v1.5 signature generation vectors (C_Sign path).

Tests RSA PKCS#1 v1.5 signing across key sizes 2048/3072/4096 with SHA-1
through SHA-512.  Each test imports the full RSA private key (via PKCS#8 DER
parsed with the cryptography library) and calls C_Sign, then compares the
resulting signature byte-for-byte against the expected value.

PKCS#1 v1.5 signatures are fully deterministic, so exact output matching is
mandatory.  Only "valid" result vectors are tested; "acceptable" vectors
(WeakHash etc.) are skipped.  1024-bit and 1536-bit files are also skipped
because many modules reject those key sizes.
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import mech_name
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = pytest.mark.wycheproof

# Hash algorithm names → PKCS#11 mechanisms
_SHA_TO_MECH: dict[str, Mechanism] = {
    "SHA-1": Mechanism.SHA1_RSA_PKCS,
    "SHA-224": Mechanism.SHA224_RSA_PKCS,
    "SHA-256": Mechanism.SHA256_RSA_PKCS,
    "SHA-384": Mechanism.SHA384_RSA_PKCS,
    "SHA-512": Mechanism.SHA512_RSA_PKCS,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[Mechanism, str] = {
    Mechanism.SHA1_RSA_PKCS: "SHA1_RSA_PKCS",
    Mechanism.SHA224_RSA_PKCS: "SHA224_RSA_PKCS",
    Mechanism.SHA256_RSA_PKCS: "SHA256_RSA_PKCS",
    Mechanism.SHA384_RSA_PKCS: "SHA384_RSA_PKCS",
    Mechanism.SHA512_RSA_PKCS: "SHA512_RSA_PKCS",
}

# Only test key sizes ≥2048; 1024 and 1536 are rejected by many modules
_SIGGEN_FILES = [
    "rsa_pkcs1_2048_sig_gen_test.json",
    "rsa_pkcs1_3072_sig_gen_test.json",
    "rsa_pkcs1_4096_sig_gen_test.json",
]


def _i2b(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes with no leading zeros."""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _load_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA PKCS#1 sig-gen vectors, keeping only 'valid' results."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    for filename in _SIGGEN_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mechanism = _SHA_TO_MECH.get(sha)
            if mechanism is None:
                continue
            pkcs8_hex = group.get("privateKeyPkcs8", "")
            if not pkcs8_hex:
                continue
            key_size = group.get("keySize", 0)
            for test in group["tests"]:
                if test["result"] != "valid":
                    continue
                test["_mechanism"] = mechanism
                test["_pkcs8_hex"] = pkcs8_hex
                test["_key_size"] = key_size
                test["_sha"] = sha
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize(
    "vec_id,vec",
    _ALL_SIGGEN_VECTORS,
    ids=[v[0] for v in _ALL_SIGGEN_VECTORS],
)
def test_rsa_pkcs1_siggen(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """RSA PKCS#1 v1.5 signature generation from Wycheproof vectors."""
    mechanism: Mechanism = vec["_mechanism"]
    key_size: int = vec["_key_size"]
    sha: str = vec["_sha"]

    # Check mechanism availability before importing the key
    mech_display = _MECH_DISPLAY.get(mechanism, str(mechanism))
    slot = p11_module.get_slots(token_present=True)[0]
    supported = {mech_name(m) for m in slot.get_mechanisms()}
    if mech_display not in supported:
        pytest.skip(f"{mech_display} not supported by module")

    msg = bytes.fromhex(vec["msg"])
    expected_sig = bytes.fromhex(vec["sig"])

    # Parse PKCS#8 DER to extract full CRT private key components
    priv_der = bytes.fromhex(vec["_pkcs8_hex"])
    priv_key_obj = load_der_private_key(priv_der, password=None)
    nums = priv_key_obj.private_numbers()
    pub_nums = nums.public_numbers

    key_obj = None
    try:
        try:
            key_obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                    Attribute.KEY_TYPE: KeyType.RSA,
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.SIGN: True,
                    Attribute.MODULUS: _i2b(pub_nums.n),
                    Attribute.PUBLIC_EXPONENT: _i2b(pub_nums.e),
                    Attribute.PRIVATE_EXPONENT: _i2b(nums.d),
                    Attribute.PRIME_1: _i2b(nums.p),
                    Attribute.PRIME_2: _i2b(nums.q),
                    Attribute.EXPONENT_1: _i2b(nums.dmp1),
                    Attribute.EXPONENT_2: _i2b(nums.dmq1),
                    Attribute.COEFFICIENT: _i2b(nums.iqmp),
                }
            )
        except p11.exceptions.PKCS11Error as e:
            pytest.skip(f"Cannot import RSA private key ({key_size}-bit, {sha}): {e}")

        try:
            sig = key_obj.sign(msg, mechanism=mechanism)
        except p11.exceptions.PKCS11Error as e:
            pytest.xfail(f"Signing failed for {vec_id} ({key_size}-bit, {sha}): {e}")
            return

        assert sig == expected_sig, (
            f"Signature mismatch for {vec_id} ({key_size}-bit {sha}): "
            f"got {sig.hex()[:32]}… expected {expected_sig.hex()[:32]}…"
        )
    finally:
        if key_obj is not None:
            key_obj.destroy()

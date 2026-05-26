"""Wycheproof DSA signature verification vectors.

Tests DSA across key sizes 2048/3072 with SHA-224/SHA-256.
Supports both ASN.1 DER and IEEE P1363 signature encodings.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.der import ecdsa_sig_der_to_p1363
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_dsa_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_DSA_SHA224,
    CKM_DSA_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["DSA_SHA256"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_SHA_MECHANISMS: dict[str, int] = {
    "SHA-224": CKM_DSA_SHA224,
    "SHA-256": CKM_DSA_SHA256,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_DSA_SHA224: "DSA_SHA224",
    CKM_DSA_SHA256: "DSA_SHA256",
}

_DSA_FILES = [
    "dsa_2048_224_sha224_test.json",
    "dsa_2048_224_sha224_p1363_test.json",
    "dsa_2048_224_sha256_test.json",
    "dsa_2048_224_sha256_p1363_test.json",
    "dsa_2048_256_sha256_test.json",
    "dsa_2048_256_sha256_p1363_test.json",
    "dsa_3072_256_sha256_test.json",
    "dsa_3072_256_sha256_p1363_test.json",
]

_DSA_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


_DsaFingerprint = tuple[int, bytes, bytes, bytes, bytes, bytes, bytes]


def _pkcs11_dsa_fingerprint(test: dict[str, Any]) -> _DsaFingerprint | None:
    """Return PKCS#11-visible DSA verify inputs for duplicate detection."""
    try:
        sig_hex = test.get("_pkcs11_sig")
        if sig_hex is None:
            return None
        public_key = test["_group"]["publicKey"]
        return (
            int(test["_mechanism"]),
            bytes.fromhex(public_key["p"]),
            bytes.fromhex(public_key["q"]),
            bytes.fromhex(public_key["g"]),
            bytes.fromhex(public_key["y"]),
            bytes.fromhex(test["msg"]),
            bytes.fromhex(sig_hex),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _canonical_duplicate_id(entries: list[tuple[str, dict[str, Any]]]) -> str:
    """Choose the most PKCS#11-meaningful representative for duplicate vectors."""
    for preferred in ("valid", "acceptable"):
        for vec_id, test in entries:
            if test["result"] == preferred:
                return vec_id
    return entries[0][0]


def _mark_pkcs11_duplicate_vectors(vectors: list[tuple[str, dict[str, Any]]]) -> None:
    groups: dict[_DsaFingerprint, list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_dsa_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


def _load_dsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all DSA vectors."""
    vectors = []
    for filename in _DSA_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mechanism = _SHA_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            is_p1363 = "p1363" in filename
            q = int.from_bytes(bytes.fromhex(group.get("publicKey", {}).get("q", "")), "big")
            q_len = (q.bit_length() + 7) // 8
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                test["_is_p1363"] = is_p1363
                if is_p1363:
                    test["_pkcs11_sig"] = test["sig"]
                else:
                    try:
                        sig = ecdsa_sig_der_to_p1363(bytes.fromhex(test["sig"]), q_len)
                    except (OverflowError, ValueError) as exc:
                        test["_pkcs11_sig_error"] = str(exc)
                    else:
                        test["_pkcs11_sig"] = sig.hex()
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_DSA_VECTORS = _load_dsa_vectors()


def _xfail_if_dsa_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised DSA verify runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _DSA_RUNTIME_REJECT_CKRS,
        f"{label}: advertised DSA verify is not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_DSA_VECTORS, ids=[v[0] for v in _ALL_DSA_VECTORS])
def test_dsa(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """DSA signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 DSA operation input; covered by {duplicate_of}")

    msg = bytes.fromhex(vec["msg"])
    result = vec["result"]
    sig_error = vec.get("_pkcs11_sig_error")
    if sig_error is not None:
        if result == "valid":
            pytest.fail(f"Valid DSA sig {vec_id} cannot be converted for PKCS#11: {sig_error}")
        pytest.skip(f"DSA signature cannot be represented as PKCS#11 P1363: {sig_error}")
    sig = bytes.fromhex(vec["_pkcs11_sig"])
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    pk = group.get("publicKey", {})
    p_hex = pk.get("p", "")
    q_hex = pk.get("q", "")
    g_hex = pk.get("g", "")
    y_hex = pk.get("y", "")
    if not all([p_hex, q_hex, g_hex, y_hex]):
        pytest.skip("Incomplete DSA public key")

    prime = bytes.fromhex(p_hex)
    subprime = bytes.fromhex(q_hex)
    base = bytes.fromhex(g_hex)
    value = bytes.fromhex(y_hex)

    try:
        pub_key = import_dsa_public_key(
            rs.raw,
            rs.sh,
            prime=prime,
            subprime=subprime,
            base_g=base,
            value=value,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError:
        pytest.skip("Cannot import DSA public key")

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig)
        if result == "invalid":
            if verified:
                pytest.fail(f"Invalid DSA sig {vec_id} accepted by module")
            return
        if result == "valid" and not verified:
            pytest.fail(f"Valid DSA sig {vec_id} rejected by module")
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_dsa_runtime_reject(exc, vec_id)
            pytest.fail(f"Valid DSA sig {vec_id} rejected: {exc}")
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)

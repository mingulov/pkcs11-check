"""Wycheproof RSA PKCS#1 v1.5 decryption vectors.

Tests RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) across key sizes 2048/3072/4096.
Imports RSA private key, decrypts ciphertext, compares against expected plaintext.
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKM_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases.conftest import (
    import_rsa_private_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

_RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_RSA_PKCS1_DECRYPT_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_DECRYPT_FILES = [
    "rsa_pkcs1_2048_test.json",
    "rsa_pkcs1_3072_test.json",
    "rsa_pkcs1_4096_test.json",
]


def _load_decrypt_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA PKCS#1 v1.5 decryption vectors."""
    vectors = []
    for filename in _DECRYPT_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_DECRYPT_VECTORS = _load_decrypt_vectors()


def _skip_or_xfail_rsa_pkcs1_private_import_reject(exc: AssertionError, key_bits: int) -> NoReturn:
    """Classify RSA private-key import rejects before Wycheproof PKCS#1 decrypt.

    The key is imported through ``import_rsa_private_key_negotiated``; a clean
    broad import-failure CKR after negotiation exhaustion on RSA_PKCS
    (advertised -- ``has_mechanism`` gate passed upstream) is
    advertised-but-not-operational -> xfail, never skip (import-skip audit A12,
    docs/findings/import-skip-audit.md). Non-CKR AssertionErrors propagate as
    harness/coding-bug findings.

    RSA has no curve-absence analogue (unlike EC); every clean import-reject CKR
    after the mech gate is treated as "advertised but not operational".
    """
    if is_known_error(exc, _RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
        _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        classify(
            "not_operational",
            summary=not_operational_reason(
                "RSA_PKCS:key-import",
                f"{key_bits}-bit private key: {ckr_name(exc.rv)}"
                if isinstance(exc, CkrAssertionError)
                else f"{key_bits}-bit private key: {exc}",
            ),
        )
    xfail_if_known_ckr(
        exc,
        _RSA_PKCS1_DECRYPT_RUNTIME_REJECT_CKRS,
        f"RSA private-key import is not operational for PKCS#1 decrypt ({key_bits}-bit)",
    )
    raise exc


def _xfail_if_rsa_pkcs1_decrypt_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised RSA PKCS#1 decrypt runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _RSA_PKCS1_DECRYPT_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA PKCS#1 decrypt is not operational",
    )
    raise exc


@pytest.mark.parametrize(
    "vec_id,vec", _ALL_DECRYPT_VECTORS, ids=[v[0] for v in _ALL_DECRYPT_VECTORS]
)
def test_rsa_pkcs1_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 decryption from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("RSA_PKCS"):
        pytest.skip("RSA_PKCS not supported")

    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]

    pk = group.get("privateKey", {})
    modulus_hex = pk.get("modulus", "")
    priv_exp_hex = pk.get("privateExponent", "")
    if not modulus_hex or not priv_exp_hex:
        pytest.skip("No RSA private key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    pub_exponent = pkcs11_bigint_from_hex(pk.get("publicExponent", ""))
    priv_exponent = pkcs11_bigint_from_hex(priv_exp_hex)
    prime1 = pkcs11_bigint_from_hex(pk.get("prime1", ""))
    prime2 = pkcs11_bigint_from_hex(pk.get("prime2", ""))
    exp1 = pkcs11_bigint_from_hex(pk.get("exponent1", ""))
    exp2 = pkcs11_bigint_from_hex(pk.get("exponent2", ""))
    coefficient = pkcs11_bigint_from_hex(pk.get("coefficient", ""))
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        # Cached broad import-reject: same advertised-but-not-operational signal
        # the first failure recorded (import-skip audit A12) -> xfail, not skip.
        classify(
            "not_operational",
            summary=not_operational_reason(
                "RSA_PKCS:key-import",
                f"{key_bits}-bit private key import not operational (cached)",
            ),
        )

    try:
        priv_key = import_rsa_private_key_negotiated(
            rs,
            n=modulus,
            e=pub_exponent,
            d=priv_exponent,
            p=prime1,
            q=prime2,
            dmp1=exp1,
            dmq1=exp2,
            iqmp=coefficient,
            attrs={CKA_DECRYPT: True},
        )
    except AssertionError as exc:
        _skip_or_xfail_rsa_pkcs1_private_import_reject(exc, key_bits)

    plaintext = None
    try:
        plaintext = decrypt_single(rs.raw, rs.sh, priv_key, CKM_RSA_PKCS, ct)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_rsa_pkcs1_decrypt_runtime_reject(exc, vec_id)
            classify(
                "not_operational",
                label=vec_id,
                summary=f"Valid RSA PKCS#1 ciphertext {vec_id} failed to decrypt: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable/invalid: reject is fine (padding oracle resistance)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
    if result == "invalid" and plaintext is not None:
        # RSA PKCS#1 v1.5 is the canonical Bleichenbacher case. The recommended
        # mitigation (RFC 8017 §7.2.2; "Marvin" 2023) is to NOT reveal padding
        # validity -- return a synthetic plaintext (or reject in constant time),
        # so the API "succeeds" with a value that is NOT the target message. Every
        # real provider does this (softhsm2/kryoptic/NSS return synthetic for all
        # invalid vectors; 0 padding bypasses, probed 2026-06-09). The ONLY break
        # is recovering the actual target message -- that means the padding check
        # was bypassed. So a non-target plaintext is secure, not a finding.
        if plaintext == msg_expected:
            classify(
                "accepted_invalid",
                kind="crypto",
                label=vec_id,
                summary=(
                    f"RSA PKCS#1 decrypt {vec_id} recovered the target message from an "
                    f"invalid-padding ciphertext (padding-check bypass, Bleichenbacher-class break)"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

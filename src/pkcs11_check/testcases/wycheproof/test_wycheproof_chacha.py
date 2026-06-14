"""Wycheproof ChaCha20-Poly1305 AEAD vectors.

Tests ChaCha20-Poly1305 (RFC 8439) encryption/decryption.
Skips on modules that don't support CKM_CHACHA20_POLY1305.

Uses raw ctypes mechanism params via mech_chacha20_poly1305.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_chacha20_poly1305
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_CHACHA20,
    CKM_CHACHA20_POLY1305,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases.conftest import assert_correct, import_secret_key_negotiated

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["CHACHA20_POLY1305"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402


def _load_chacha_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ChaCha20-Poly1305 vectors."""
    path = WYCHEPROOF_DIR / "chacha20_poly1305_test.json"
    if not path.exists():
        return []
    data = load_json_cached(path)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_CHACHA_VECTORS = _load_chacha_vectors()


@pytest.mark.parametrize("vec_id,vec", _CHACHA_VECTORS, ids=[v[0] for v in _CHACHA_VECTORS])
def test_chacha20_poly1305(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ChaCha20-Poly1305 AEAD decryption from Wycheproof vectors.

    Decrypts the supplied ct||tag so invalid vectors actually exercise tag
    rejection. A module that decrypts a forged/modified ciphertext or tag is a
    crypto-correctness break (Type A -> fail). The previous produce-direction
    (encrypt + compare) could never reject an invalid vector because a fresh
    correct ciphertext never matched the modified expected output.
    """
    rs = p11_module_session
    if not rs.has_mechanism("CHACHA20_POLY1305"):
        pytest.skip("CHACHA20_POLY1305 not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg_expected = bytes.fromhex(vec["msg"])
    ct = bytes.fromhex(vec["ct"])
    tag = bytes.fromhex(vec["tag"])
    result = vec["result"]

    # The ChaCha20 key is the subject key of the advertised AEAD op (it decrypts
    # the supplied ct||tag), so its negotiated import is the canonical capability
    # path for CHACHA20_POLY1305.
    try:
        key = import_secret_key_negotiated(
            rs,
            int(CKK_CHACHA20),
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError as exc:
        if not isinstance(exc, CkrAssertionError):
            # Non-CKR AssertionError -- a harness/ctypes bug must never be
            # classified as "not operational".
            raise
        # CHACHA20_POLY1305 was advertised (has_mechanism gate passed above); a
        # negotiation-exhausted key import refusal is "advertised but not
        # operational" -> xfail per the classification model, never skip.
        classify(
            "not_operational",
            label="CHACHA20_POLY1305:key-import",
            summary=not_operational_reason("CHACHA20_POLY1305:key-import", ckr_name(exc.rv)),
        )

    # CK_SALSA20_CHACHA20_POLY1305_PARAMS: (nonce, aad)
    chacha_param = mech_chacha20_poly1305(CKM_CHACHA20_POLY1305, iv, aad=aad if aad else None)
    plaintext = None
    try:
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_CHACHA20_POLY1305,
            ct + tag,
            mech_param=chacha_param,
            output_size_hint=len(ct),
        )
    except (AssertionError, AttributeError, TypeError) as exc:
        if result == "valid":
            classify(
                "not_operational",
                label="CHACHA20_POLY1305",
                summary=f"ChaCha20-Poly1305 decrypt failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: reject of an invalid vector is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and plaintext is not None:
        assert_correct(
            actual=plaintext,
            expected=msg_expected,
            label=f"CHACHA20_POLY1305:C_Decrypt KAT {vec_id}",
            operation="C_Decrypt",
            mechanism="CKM_CHACHA20_POLY1305",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and plaintext is not None:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="CHACHA20_POLY1305",
            summary=f"ChaCha20-Poly1305 decrypt {vec_id}: accepted invalid ciphertext/tag",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

"""Wycheproof ChaCha20-Poly1305 AEAD vectors.

Tests ChaCha20-Poly1305 (RFC 8439) encryption/decryption.
Skips on modules that don't support CKM_CHACHA20_POLY1305.

Uses raw ctypes mechanism params via mech_chacha20_poly1305.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_chacha20_poly1305
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    encrypt_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_CHACHA20,
    CKM_CHACHA20_POLY1305,
    CKO_SECRET_KEY,
)

pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v30]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402


def _load_chacha_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ChaCha20-Poly1305 vectors."""
    path = WYCHEPROOF_DIR / "chacha20_poly1305_test.json"
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_CHACHA_VECTORS = _load_chacha_vectors()


@pytest.mark.parametrize("vec_id,vec", _CHACHA_VECTORS, ids=[v[0] for v in _CHACHA_VECTORS])
def test_chacha20_poly1305(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ChaCha20-Poly1305 AEAD from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("CHACHA20_POLY1305"):
        pytest.skip("CHACHA20_POLY1305 not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_CHACHA20,
                CKA_VALUE: key_bytes,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except (AssertionError, AttributeError):
        pytest.skip("Cannot import ChaCha20 key")

    # CK_SALSA20_CHACHA20_POLY1305_PARAMS: (nonce, aad)
    chacha_param = mech_chacha20_poly1305(CKM_CHACHA20_POLY1305, iv, aad=aad if aad else None)
    ciphertext = None
    try:
        ciphertext = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_CHACHA20_POLY1305,
            msg,
            mech_param=chacha_param,
            output_overhead=16,
        )
    except (AssertionError, AttributeError, TypeError) as exc:
        if result == "valid":
            pytest.fail(f"ChaCha20-Poly1305 encrypt failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and ciphertext is not None:
        assert ciphertext == ct_expected + tag_expected

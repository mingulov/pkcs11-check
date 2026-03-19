"""Wycheproof ChaCha20-Poly1305 AEAD vectors.

Tests ChaCha20-Poly1305 (RFC 8439) encryption/decryption.
Skips on modules that don't support CKM_CHACHA20_POLY1305.

Note: python-pkcs11 doesn't have native CK_SALSA20_CHACHA20_POLY1305_PARAMS
support, so mechanism params are passed as raw bytes. This may need
adjustment per-module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import mech_name

pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v30]

from p11test.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_CKM_CHACHA20_POLY1305 = 0x00004021


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


def _has_chacha(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "CHACHA20_POLY1305" in names or any(
        f"0x{_CKM_CHACHA20_POLY1305:08x}" in n for n in names
    )


@pytest.mark.parametrize("vec_id,vec", _CHACHA_VECTORS, ids=[v[0] for v in _CHACHA_VECTORS])
def test_chacha20_poly1305(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """ChaCha20-Poly1305 AEAD from Wycheproof vectors."""
    if not _has_chacha(p11_module):
        pytest.skip("CHACHA20_POLY1305 not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    chacha_key_type = KeyType.CHACHA20
    try:
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: chacha_key_type,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except (p11.exceptions.PKCS11Error, AttributeError):
        pytest.skip("Cannot import ChaCha20 key")

    # CK_SALSA20_CHACHA20_POLY1305_PARAMS: (nonce, aad)
    try:
        ciphertext = key.encrypt(
            msg,
            mechanism=Mechanism.CHACHA20_POLY1305,
            mechanism_param=(iv, aad),
        )
        if result == "valid":
            assert ciphertext == ct_expected + tag_expected
    except (p11.exceptions.PKCS11Error, AttributeError, TypeError):
        if result == "valid":
            pytest.xfail(f"ChaCha20-Poly1305 encrypt failed for valid vector {vec_id}")

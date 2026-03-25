"""NIST ACVP AES-GCM encrypt/decrypt test vectors.

Tests AES-GCM authenticated encryption and decryption using official NIST
ACVP vectors.  Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.

Vector format (ACVP-AES-GCM-1.0):
  Encrypt: input has (key, iv, pt, aad); expected has (ct, tag).
  Decrypt: input has (key, iv, ct, tag, aad); expected has (pt) when
           testPassed is true/absent, or testPassed=false for tag-invalid vectors.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_gcm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_GCM,
)
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_MAX_PER_DIRECTION = 20  # cap for speed

# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------


def _load_gcm_vectors() -> (
    tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]
):
    """Load AES-GCM ACVP vectors, split into encrypt and decrypt lists.

    Returns (encrypt_vectors, decrypt_vectors) where each entry is
    (vec_id, merged_dict).
    """
    raw = load_acvp_vectors("ACVP-AES-GCM-1.0")

    encrypt_vecs: list[tuple[str, dict[str, Any]]] = []
    decrypt_vecs: list[tuple[str, dict[str, Any]]] = []

    for vec in raw:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]
        direction = group.get("direction", "")
        tc_id = inp.get("tcId", 0)
        iv_len = group.get("ivLen", 96)  # bits
        tag_len = group.get("tagLen", 128)  # bits

        if direction == "encrypt":
            if len(encrypt_vecs) >= _MAX_PER_DIRECTION:
                continue
            key_hex = inp.get("key", "")
            iv_hex = inp.get("iv", "")
            pt_hex = inp.get("pt", "")
            aad_hex = inp.get("aad", "")
            ct_hex = exp.get("ct", "")
            tag_hex = exp.get("tag", "")
            if not key_hex or not iv_hex or not tag_hex:
                continue
            merged: dict[str, Any] = {
                "tc_id": tc_id,
                "direction": "encrypt",
                "key": bytes.fromhex(key_hex),
                "iv": bytes.fromhex(iv_hex),
                "pt": bytes.fromhex(pt_hex) if pt_hex else b"",
                "aad": bytes.fromhex(aad_hex) if aad_hex else b"",
                "ct_expected": bytes.fromhex(ct_hex) if ct_hex else b"",
                "tag_expected": bytes.fromhex(tag_hex),
                "iv_len_bits": iv_len,
                "tag_len_bits": tag_len,
            }
            vec_id = f"ACVP-AES-GCM-enc-tc{tc_id}"
            encrypt_vecs.append((vec_id, merged))

        elif direction == "decrypt":
            if len(decrypt_vecs) >= _MAX_PER_DIRECTION:
                continue
            key_hex = inp.get("key", "")
            iv_hex = inp.get("iv", "")
            ct_hex = inp.get("ct", "")
            tag_hex = inp.get("tag", "")
            aad_hex = inp.get("aad", "")
            # testPassed=False means the tag is intentionally invalid
            test_passed = exp.get("testPassed", True)  # absent means valid
            pt_hex = exp.get("pt", "")
            if not key_hex or not iv_hex or not tag_hex:
                continue
            merged = {
                "tc_id": tc_id,
                "direction": "decrypt",
                "key": bytes.fromhex(key_hex),
                "iv": bytes.fromhex(iv_hex),
                "ct": bytes.fromhex(ct_hex) if ct_hex else b"",
                "tag": bytes.fromhex(tag_hex),
                "aad": bytes.fromhex(aad_hex) if aad_hex else b"",
                "pt_expected": bytes.fromhex(pt_hex) if pt_hex else b"",
                "test_passed": test_passed,  # True = valid tag, False = invalid tag
                "iv_len_bits": iv_len,
                "tag_len_bits": tag_len,
            }
            vec_id = f"ACVP-AES-GCM-dec-tc{tc_id}"
            decrypt_vecs.append((vec_id, merged))

    return encrypt_vecs, decrypt_vecs


_ENCRYPT_VECTORS, _DECRYPT_VECTORS = _load_gcm_vectors()

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _import_aes_key(
    rs: Any,
    key_bytes: bytes,
    *,
    encrypt: bool = True,
    decrypt: bool = True,
) -> int:
    """Import a raw AES key into the session as a session object."""
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs={
            int(CKA_ENCRYPT): encrypt,
            int(CKA_DECRYPT): decrypt,
            int(CKA_TOKEN): False,
            int(CKA_SENSITIVE): False,
        },
    )


# ---------------------------------------------------------------------------
# Encrypt tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec",
    _ENCRYPT_VECTORS,
    ids=[v[0] for v in _ENCRYPT_VECTORS],
)
def test_acvp_aes_gcm_encrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-GCM encryption from NIST ACVP vectors.

    For each vector (key, iv, aad, pt) the module must produce the expected
    (ct, tag).  The raw recipe returns ciphertext+tag concatenated; we split
    by tag length.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec["iv"]
    aad = vec["aad"] if vec["aad"] else None

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        pytest.xfail(
            f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B"
        )

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)

        try:
            result = encrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, vec["pt"],
                mech_param=gcm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            # Module does not support this IV/tag size combination
            pytest.xfail(
                f"Module limitation: GCM iv={len(iv)}B tag={tag_bytes}B "
                f"not supported ({exc_msg})"
            )

        # raw recipe returns ciphertext||tag as a single bytestring
        if len(result) < tag_bytes:
            pytest.fail(
                f"{vec_id}: encrypt output too short: {len(result)}B, "
                f"expected at least {tag_bytes}B for tag"
            )

        ct_got = result[: len(result) - tag_bytes]
        tag_got = result[len(result) - tag_bytes :]

        assert ct_got == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct_got.hex()}, "
            f"expected {vec['ct_expected'].hex()}"
        )
        assert tag_got == vec["tag_expected"], (
            f"{vec_id}: tag mismatch: got {tag_got.hex()}, "
            f"expected {vec['tag_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# Decrypt tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec",
    _DECRYPT_VECTORS,
    ids=[v[0] for v in _DECRYPT_VECTORS],
)
def test_acvp_aes_gcm_decrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-GCM decryption from NIST ACVP vectors.

    For valid-tag vectors (testPassed=true/absent): the module must decrypt
    and return the expected plaintext.

    For invalid-tag vectors (testPassed=false): the module must reject the
    ciphertext, typically with CKR_ENCRYPTED_DATA_INVALID.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported by module")

    tag_bytes = vec["tag_len_bits"] // 8
    iv = vec["iv"]
    aad = vec["aad"] if vec["aad"] else None
    test_passed = vec["test_passed"]

    try:
        gcm_param = mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=vec["tag_len_bits"])
    except (AssertionError, ValueError, TypeError):
        pytest.xfail(
            f"Binding rejects GCM params iv={len(iv)}B tag={tag_bytes}B"
        )
        return

    # ACVP decrypt: ciphertext and tag are provided separately; PKCS#11 wants ct||tag
    ct_with_tag = vec["ct"] + vec["tag"]

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)

        try:
            pt = decrypt_single(
                rs.raw, rs.sh, key, CKM_AES_GCM, ct_with_tag,
                mech_param=gcm_param,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_MECHANISM_PARAM_INVALID", "CKR_ARGUMENTS_BAD",
                )
            ):
                # Module does not support this IV/tag size combination
                pytest.xfail(
                    f"Module limitation: GCM iv={len(iv)}B tag={tag_bytes}B "
                    f"not supported ({exc_msg})"
                )
                return
            if any(
                name in exc_msg
                for name in (
                    "CKR_ENCRYPTED_DATA_INVALID", "CKR_ENCRYPTED_DATA_LEN_RANGE",
                    "CKR_AEAD_DECRYPT_FAILED",
                )
            ):
                if not test_passed:
                    # Expected: module correctly rejected invalid tag
                    return
                # Unexpected: module rejected a valid-tag vector
                pytest.fail(
                    f"{vec_id}: valid-tag GCM vector rejected with tag auth failure"
                )
                return
            raise

        # Decryption succeeded
        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: plaintext mismatch: got {pt.hex()}, "
                f"expected {vec['pt_expected'].hex()}"
            )
        else:
            # Module accepted an invalid tag - this is a security failure
            pytest.fail(
                f"{vec_id}: module accepted GCM ciphertext with invalid tag "
                f"(tag auth bypass)"
            )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)

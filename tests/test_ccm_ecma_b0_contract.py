"""Meta-tests: CCM-ECMA B_0 translation contract (issue #20 correction).

The pinned ECMA dataset's 16-byte ``iv`` is a formatted CCM ``B_0`` block, not
a nonce. The loader must validate it as ``B_0`` (flags, reserved bit, tag
encoding, AAD-presence flag, payload length) and pass only the embedded
13-byte nonce (``B_0[1:14]``) to PKCS #11, preserving the raw ``B_0``.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE


def _require_vectors() -> None:
    if not ACVP_AVAILABLE:
        pytest.skip("ACVP vectors not cloned")


def _load_ecma() -> tuple[list[tuple[str, Any]], list[tuple[str, Any]]]:
    _require_vectors()
    from pkcs11_check.testcases.acvp.aes.test_ccm import _load_ccm_ecma_vectors

    return _load_ccm_ecma_vectors()


def test_ecma_loader_extracts_13byte_nonce_and_preserves_b0() -> None:
    """Every normalized ECMA vector carries the 13-byte nonce plus raw B_0."""
    enc, dec = _load_ecma()
    assert len(enc) == 44
    assert len(dec) == 44
    for _vec_id, vec in enc + dec:
        assert len(vec["nonce"]) == 13, _vec_id
        assert len(vec["ecma_b0"]) == 16, _vec_id
        assert vec["ecma_b0"][1:14] == vec["nonce"], _vec_id


def test_ecma_tc45_exact_translation() -> None:
    """AES-dec-tc45: exact B_0, nonce, tag length, and provenance."""
    _enc, dec = _load_ecma()
    vec = next(v for vid, v in dec if vid == "AES-dec-tc45")
    assert vec["ecma_b0"] == bytes.fromhex("5971ca9378057e4b0068444858f90020")
    assert vec["nonce"] == bytes.fromhex("71ca9378057e4b0068444858f9")
    assert vec["tag_len"] == 8
    assert vec["_source"] == "acvp:ACVP-AES-CCM-ECMA-1.0"
    assert vec["_vector_id"] == "tcId=45"


def test_all_88_ecma_vectors_verify_against_independent_oracle() -> None:
    """cryptography.AESCCM reproduces every pinned ECMA expected output."""
    enc, dec = _load_ecma()
    checked = 0
    for _vec_id, vec in enc:
        aead = AESCCM(vec["key"], tag_length=vec["tag_len"])
        assert (
            aead.encrypt(vec["nonce"], vec["pt"], vec.get("aad") or None) == vec["ct_expected"]
        ), _vec_id
        checked += 1
    for _vec_id, vec in dec:
        assert vec["test_passed"] is True, _vec_id
        aead = AESCCM(vec["key"], tag_length=vec["tag_len"])
        assert (
            aead.decrypt(vec["nonce"], vec["ct"], vec.get("aad") or None) == vec["pt_expected"]
        ), _vec_id
        checked += 1
    assert checked == 88


# --- B_0 normalization unit contract --------------------------------------


def _normalize(b0: bytes, *, tag_len: int, aad: bytes, payload_len: int) -> bytes:
    from pkcs11_check.testcases.acvp.aes.test_ccm import normalize_ecma_b0

    return normalize_ecma_b0(b0, tag_len=tag_len, aad=aad, payload_len=payload_len)


def test_normalize_valid_b0_returns_embedded_nonce() -> None:
    b0 = bytes.fromhex("5971ca9378057e4b0068444858f90020")
    assert _normalize(b0, tag_len=8, aad=bytes(32), payload_len=32) == b0[1:14]


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        ("truncate", "exactly 16 bytes"),
        ("extend", "exactly 16 bytes"),
        ("reserved-bit", "reserved"),
        ("aad-flag-set-without-aad", "AAD"),
        ("aad-flag-clear-with-aad", "AAD"),
        ("tag-mismatch", "tag"),
        ("payload-mismatch", "payload"),
        ("length-field-mismatch", "nonce"),
    ],
)
def test_normalize_malformed_b0_fails_visibly(mutate: str, reason: str) -> None:
    """Malformed source B_0 fails at normalization, never silently slices."""
    b0 = bytearray(bytes.fromhex("5971ca9378057e4b0068444858f90020"))
    tag_len, aad, payload_len = 8, bytes(32), 32
    if mutate == "truncate":
        raw = bytes(b0[:15])
    elif mutate == "extend":
        raw = bytes(b0) + b"\x00"
    elif mutate == "reserved-bit":
        b0[0] |= 0x80
        raw = bytes(b0)
    elif mutate == "aad-flag-set-without-aad":
        aad = b""
        raw = bytes(b0)
    elif mutate == "aad-flag-clear-with-aad":
        b0[0] &= 0xBF
        raw = bytes(b0)
    elif mutate == "tag-mismatch":
        tag_len = 16
        raw = bytes(b0)
    elif mutate == "payload-mismatch":
        payload_len = 31
        raw = bytes(b0)
    else:  # length-field-mismatch: L=3 -> 12-byte nonce field, not 13
        b0[0] = (b0[0] & 0xF8) | 0x02
        raw = bytes(b0)
    with pytest.raises(ValueError, match=reason):
        _normalize(raw, tag_len=tag_len, aad=aad, payload_len=payload_len)


# --- Loaded-nonce range pin (issue #20 follow-up) ---------------------------


def _load_standard_ccm() -> tuple[list[tuple[str, Any]], list[tuple[str, Any]]]:
    _require_vectors()
    from pkcs11_check.testcases.acvp.aes.test_ccm import _load_ccm_vectors

    return _load_ccm_vectors()


def test_all_loaded_ccm_nonces_within_spec_range() -> None:
    """Every nonce any CCM loader feeds PKCS #11 must satisfy 7 <= len <= 13.

    PKCS #11 v3.2 ulNonceLen bound; guards future dataset repins (issue #20 follow-up).
    """
    enc, dec = _load_standard_ccm()
    enc_e, dec_e = _load_ecma()
    # Anti-vacuity: every loader contributed (today 8310 standard + 88 ECMA).
    assert enc and dec and enc_e and dec_e
    for vec_id, vec in enc + dec + enc_e + dec_e:
        assert 7 <= len(vec["nonce"]) <= 13, vec_id

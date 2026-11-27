"""fw#43: X9.31 hash+trailer transformer and block oracle.

The application applies the X9.31 trailer: sign input is digest || trailer-ID
(a bare digest is invalid input). Trailer IDs are ISO/IEC 10118 part numbers
per OpenSSL rsa_x931.c RSA_X931_hash_id (SHA-1 0x33, SHA-256 0x34, SHA-512
0x35, SHA-384 0x36); the block layout mirrors RSA_padding_add_X931 /
RSA_padding_check_X931 (header 0x6B/0x6A, 0xBB pad, 0xBA separator, H,
trailer-ID, fixed 0xCC). Digests below are hardcoded NIST vectors so the
transformer test does not merely re-run hashlib.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pkcs11_check.testcases import _x931

_SHA256_ABC = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
_SHA1_ABC = bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")

# Toy 512-bit RSA key (test-only, generated once with openssl genpkey):
_TOY_N = int(
    "c45f90ebd7fc4eaace356e7775a8098a251be970f0976a1810fa347a437373f6b5e544b93"
    "2e720c2fa7a0e1cf0a916115f1235be65e6497610e3def20c707efd",
    16,
)
_TOY_E = 0x10001
_TOY_D = int(
    "4f580dc63d4ec4ba5ef757db0cbf089bb8c2be5fd3d65a17bf44594fcd5128d921120fa6c6"
    "8400d0ec84e47d745327805894294a9aca6c3eb12a0f48d8ef1e41",
    16,
)
_TOY_K = 64


def _pad_x931(h_and_id: bytes, k: int) -> bytes:
    """Encode an X9.31 block per OpenSSL RSA_padding_add_X931."""
    flen = len(h_and_id)
    j = k - flen - 2
    assert j >= 0
    if j == 0:
        block = b"\x6a"
    else:
        block = b"\x6b" + b"\xbb" * (j - 1) + b"\xba"
    return block + h_and_id + b"\xcc"


def test_sign_input_appends_trailer_id() -> None:
    """Transformer output is digest || trailer-ID (fw#43)."""
    assert _x931.x931_sign_input(b"abc", "sha256") == _SHA256_ABC + b"\x34"
    assert _x931.x931_sign_input(b"abc", "sha1") == _SHA1_ABC + b"\x33"
    assert len(_x931.x931_sign_input(b"abc", "sha256")) == 33
    assert len(_x931.x931_sign_input(b"abc", "sha384")) == 49
    assert len(_x931.x931_sign_input(b"abc", "sha512")) == 65


def test_sign_input_rejects_unknown_hash() -> None:
    """Hashes outside the trailer table fail loud, never silently (fw#43)."""
    with pytest.raises(ValueError, match="md5"):
        _x931.x931_sign_input(b"abc", "md5")


def test_check_valid_block() -> None:
    """A well-formed block with matching hash verifies clean (fw#43)."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    assert _x931.check_x931_block(block, _TOY_K, b"abc", "sha256") is None


def test_check_minimal_no_padding_block() -> None:
    """The j==0 0x6A form (no padding) is accepted (fw#43)."""
    h_and_id = _SHA256_ABC + b"\x34"
    block = _pad_x931(h_and_id, len(h_and_id) + 2)
    assert block[0] == 0x6A
    assert _x931.check_x931_block(block, len(block), b"abc", "sha256") is None


@pytest.mark.parametrize(
    ("mutate", "reason_match"),
    [
        (lambda b: b"\x6c" + b[1:], "header"),
        (lambda b: b[:5] + b"\xbc" + b[6:], "padding"),
        # Strip every 0xBA (separator and any digest bytes): with none left,
        # the missing-separator arm fires (OpenSSL reports a padding error
        # when a digest 0xBA stands in, same as here).
        (lambda b: b.replace(b"\xba", b"\xbb"), "separator"),
        (lambda b: b[:-1] + b"\xcd", "trailer"),
        (lambda b: b[:-2] + b"\x33" + b[-1:], "trailer"),
        (lambda b: b[:-34] + b"\x00" + b[-33:], "digest"),
        (lambda b: b + b"\x00", "length"),
        (lambda b: b[:-1], "length"),
    ],
)
def test_check_rejects_malformed_blocks(
    mutate: Callable[[bytes], bytes], reason_match: str
) -> None:
    """Every structural violation yields a reason, never silent accept."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    bad = mutate(block)
    reason = _x931.check_x931_block(bad, _TOY_K, b"abc", "sha256")
    assert reason is not None
    assert reason_match in reason


def test_check_rejects_wrong_message_or_hash() -> None:
    """Hash mismatch (wrong message) and trailer mismatch (wrong hash) report."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    reason = _x931.check_x931_block(block, _TOY_K, b"abd", "sha256")
    assert reason is not None and "digest" in reason
    reason = _x931.check_x931_block(block, _TOY_K, b"abc", "sha1")
    assert reason is not None and "trailer" in reason


def test_verify_roundtrip_with_toy_key() -> None:
    """Raw-RSA recover + parse accepts a well-formed signature (fw#43)."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    sig = pow(int.from_bytes(block, "big"), _TOY_D, _TOY_N).to_bytes(_TOY_K, "big")
    assert _x931.verify_x931_signature(sig, _TOY_E, _TOY_N, b"abc", "sha256") is None


def test_verify_rejects_tampered_signature() -> None:
    """A flipped signature byte fails verification (oracle discriminates)."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    sig = bytearray(pow(int.from_bytes(block, "big"), _TOY_D, _TOY_N).to_bytes(_TOY_K, "big"))
    sig[-1] ^= 0xFF
    reason = _x931.verify_x931_signature(bytes(sig), _TOY_E, _TOY_N, b"abc", "sha256")
    assert reason is not None


def test_verify_rejects_wrong_message() -> None:
    """A valid signature for another message fails the oracle (fw#43)."""
    block = _pad_x931(_SHA256_ABC + b"\x34", _TOY_K)
    sig = pow(int.from_bytes(block, "big"), _TOY_D, _TOY_N).to_bytes(_TOY_K, "big")
    reason = _x931.verify_x931_signature(sig, _TOY_E, _TOY_N, b"abd", "sha256")
    assert reason is not None and "digest" in reason

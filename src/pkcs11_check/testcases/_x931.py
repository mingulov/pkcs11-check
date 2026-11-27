"""X9.31 hash+trailer input builder and signature-block oracle (fw#43).

The application applies the X9.31 trailer: sign input is digest ||
trailer-ID, and a bare digest is invalid input (the "prehash" shape was
tried and reverted in 0d1fcac2 for exactly this reason).

Trailer IDs are ISO/IEC 10118 part numbers per OpenSSL rsa_x931.c
``RSA_X931_hash_id``; the block layout mirrors ``RSA_padding_add_X931`` /
``RSA_padding_check_X931``: header 0x6B (0x6A when the input fills the
block with no padding room), 0xBB padding, 0xBA separator, hash, trailer
ID, fixed trailing 0xCC appended by the signer.
"""

from __future__ import annotations

import hashlib

_X931_TRAILER_IDS = {
    "sha1": 0x33,
    "sha256": 0x34,
    "sha512": 0x35,
    "sha384": 0x36,
}
_FINAL_TRAILER_BYTE = 0xCC


def x931_sign_input(message: bytes, hash_name: str) -> bytes:
    """Build the app-side X9.31 sign input: digest(message) || trailer-ID.

    Raises ValueError for hashes outside the trailer table -- only hashes
    with a defined X9.31 trailer ID can produce valid positive input.
    """
    try:
        trailer_id = _X931_TRAILER_IDS[hash_name]
    except KeyError:
        supported = ", ".join(sorted(_X931_TRAILER_IDS))
        raise ValueError(
            f"no X9.31 trailer ID for hash {hash_name!r} (have: {supported})"
        ) from None
    digest = hashlib.new(hash_name, message, usedforsecurity=False).digest()
    return digest + bytes([trailer_id])


def check_x931_block(block: bytes, k: int, message: bytes, hash_name: str) -> str | None:
    """Check a recovered X9.31 block; None when valid, else a reason string.

    Mirrors OpenSSL ``RSA_padding_check_X931`` structurally, then matches the
    recovered hash and trailer ID against the message and hash name.
    """
    if len(block) != k:
        return f"length {len(block)}, expected modulus size {k}"
    if block[0] not in (0x6A, 0x6B):
        return f"header {block[0]:#04x}, expected 0x6a or 0x6b"
    if block[0] == 0x6A:
        body = block[1:-1]
    else:
        try:
            sep = block.index(0xBA, 1, -1)
        except ValueError:
            return "separator 0xba missing"
        pad = block[1:sep]
        if len(pad) < 1 or any(b != 0xBB for b in pad):
            return "padding is not 0xbb bytes"
        body = block[sep + 1 : -1]
    if block[-1] != _FINAL_TRAILER_BYTE:
        return f"trailer {block[-1]:#04x}, expected 0xcc"
    try:
        trailer_id = _X931_TRAILER_IDS[hash_name]
    except KeyError:
        return f"no X9.31 trailer ID for hash {hash_name!r}"
    if len(body) < 2 or body[-1] != trailer_id:
        got = f"{body[-1]:#04x}" if body else "empty"
        return f"trailer ID {got}, expected {trailer_id:#04x} for {hash_name}"
    expected = hashlib.new(hash_name, message, usedforsecurity=False).digest()
    if body[:-1] != expected:
        return "digest does not match the message"
    return None


def verify_x931_signature(sig: bytes, e: int, n: int, message: bytes, hash_name: str) -> str | None:
    """Raw-RSA recover (m = s^e mod n) then check the X9.31 block.

    Independent oracle for module-produced X9.31 signatures: None when the
    signature is a well-formed X9.31 encoding of the message digest, else a
    reason string.
    """
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return f"signature length {len(sig)}, expected modulus size {k}"
    recovered = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    return check_x931_block(recovered, k, message, hash_name)

"""fw#92: Camellia-CTR nonce-diversity premise pins.

A correct CTR keystream depends on the counter block, not on the width
alone: from cb=0, widths 32 and 64 emit identical counter sequences for
short plaintexts, so a bits-only ciphertext comparison is a false oracle.
The reference below models PKCS#11 CTR (low `bits` bits of cb increment
big-endian) over real AES so both the bug and the fix premise execute.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_KEY = bytes(range(16))
_PLAINTEXT = b"CTR nonce independence test!!"  # 29 bytes, as in the testcase


def _ctr_encrypt(key: bytes, bits: int, cb: bytes, plaintext: bytes) -> bytes:
    """Reference CTR: low `bits` bits of cb increment, AES-ECB keystream."""
    assert len(cb) == 16 and 0 < bits <= 128
    base = int.from_bytes(cb, "big")
    low_mask = (1 << bits) - 1
    high = base & ~low_mask
    low = base & low_mask
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for index in range((len(plaintext) + 15) // 16):
        block = (high | ((low + index) & low_mask)).to_bytes(16, "big")
        keystream = encryptor.update(block)
        chunk = plaintext[index * 16 : (index + 1) * 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)


def test_bits_only_difference_yields_identical_ciphertext() -> None:
    """The old oracle (bits 32 vs 64, same cb) is false on a correct CTR."""
    cb = bytes(16)
    assert _ctr_encrypt(_KEY, 32, cb, _PLAINTEXT) == _ctr_encrypt(_KEY, 64, cb, _PLAINTEXT)


def test_different_counter_blocks_yield_different_ciphertext() -> None:
    """The new oracle (differ cb at equal bits) holds on a correct CTR."""
    cb1 = bytes(16)
    cb2 = bytes(15) + b"\x01"
    assert _ctr_encrypt(_KEY, 64, cb1, _PLAINTEXT) != _ctr_encrypt(_KEY, 64, cb2, _PLAINTEXT)


def test_width_wrap_divergence_at_low32_max() -> None:
    """32- vs 64-bit widths diverge once the low 32 bits wrap (block 2)."""
    cb = bytes(12) + b"\xff\xff\xff\xff"
    assert _ctr_encrypt(_KEY, 32, cb, _PLAINTEXT) != _ctr_encrypt(_KEY, 64, cb, _PLAINTEXT)

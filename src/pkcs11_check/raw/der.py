"""Minimal hand-written DER/ASN.1 encoding and decoding for PKCS#11 tests."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Internal DER primitives
# ---------------------------------------------------------------------------


def _der_encode_length(length: int) -> bytes:
    """Encode DER definite length."""
    if length < 128:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _der_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode DER length at *offset*. Returns (length, next_offset)."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite-length DER is not supported")
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _der_encode_integer(value: int) -> bytes:
    """Encode integer as DER INTEGER (tag 0x02)."""
    if value == 0:
        body = b"\x00"
    else:
        byte_length = (value.bit_length() + 7) // 8
        body = value.to_bytes(byte_length, "big")
        # Prepend 0x00 if the high bit is set (sign extension)
        if body[0] & 0x80:
            body = b"\x00" + body
    return b"\x02" + _der_encode_length(len(body)) + body


def _der_decode_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Decode DER INTEGER at *offset*. Returns (value, next_offset)."""
    if data[offset] != 0x02:
        raise ValueError(f"Expected DER INTEGER tag 0x02, got 0x{data[offset]:02x}")
    length, offset = _der_decode_length(data, offset + 1)
    body = data[offset : offset + length]
    value = int.from_bytes(body, "big")
    return value, offset + length


# ---------------------------------------------------------------------------
# Step 3.1: ECDSA signature format conversion
# ---------------------------------------------------------------------------


def ecdsa_sig_to_der(r: int, s: int) -> bytes:
    """Encode (r, s) integers as DER ASN.1 SEQUENCE { INTEGER, INTEGER }."""
    r_enc = _der_encode_integer(r)
    s_enc = _der_encode_integer(s)
    body = r_enc + s_enc
    return b"\x30" + _der_encode_length(len(body)) + body


def ecdsa_sig_from_der(der: bytes) -> tuple[int, int]:
    """Decode DER ECDSA signature to (r, s) integers."""
    if not der:
        raise ValueError("DER data is empty")
    if der[0] != 0x30:
        raise ValueError(f"Expected DER SEQUENCE tag 0x30, got 0x{der[0]:02x}")
    seq_len, offset = _der_decode_length(der, 1)
    seq_end = offset + seq_len
    r, offset = _der_decode_integer(der, offset)
    s, offset = _der_decode_integer(der, offset)
    if offset != seq_end:
        raise ValueError(f"Trailing data in DER SEQUENCE: {seq_end - offset} bytes")
    return r, s


def ecdsa_sig_p1363_to_der(raw_sig: bytes) -> bytes:
    """Convert PKCS#11 P1363 format (r||s) to DER."""
    if len(raw_sig) % 2 != 0:
        raise ValueError(f"P1363 signature length must be even, got {len(raw_sig)}")
    half = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half], "big")
    s = int.from_bytes(raw_sig[half:], "big")
    return ecdsa_sig_to_der(r, s)


def ecdsa_sig_der_to_p1363(der_sig: bytes, key_size: int) -> bytes:
    """Convert DER to PKCS#11 P1363 format (r||s).

    *key_size* is the byte length of the curve order (32 for P-256, 48 for
    P-384, 66 for P-521).
    """
    r, s = ecdsa_sig_from_der(der_sig)
    r_bytes = r.to_bytes(key_size, "big")
    s_bytes = s.to_bytes(key_size, "big")
    return r_bytes + s_bytes


# ---------------------------------------------------------------------------
# Step 3.2: EC point encoding/decoding
# ---------------------------------------------------------------------------


def encode_ec_point(x: int, y: int, key_size: int) -> bytes:
    """Encode EC point as DER OCTET STRING wrapping uncompressed 0x04||x||y."""
    x_bytes = x.to_bytes(key_size, "big")
    y_bytes = y.to_bytes(key_size, "big")
    point = b"\x04" + x_bytes + y_bytes
    return b"\x04" + _der_encode_length(len(point)) + point


def decode_ec_point(der: bytes) -> bytes:
    """Unwrap DER OCTET STRING to raw point bytes (0x04||x||y)."""
    if not der:
        raise ValueError("DER data is empty")
    if der[0] != 0x04:
        raise ValueError(f"Expected DER OCTET STRING tag 0x04, got 0x{der[0]:02x}")
    length, offset = _der_decode_length(der, 1)
    return der[offset : offset + length]


# ---------------------------------------------------------------------------
# Step 3.3: RSA key DER encoding
# ---------------------------------------------------------------------------


def encode_rsa_public_key_der(modulus: bytes, exponent: bytes) -> bytes:
    """Encode RSA public key as PKCS#1 DER (SEQUENCE { INTEGER, INTEGER })."""
    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    n_enc = _der_encode_integer(n)
    e_enc = _der_encode_integer(e)
    body = n_enc + e_enc
    return b"\x30" + _der_encode_length(len(body)) + body


def decode_rsa_public_key_der(der: bytes) -> tuple[bytes, bytes]:
    """Decode PKCS#1 DER to (modulus, exponent) bytes."""
    if not der:
        raise ValueError("DER data is empty")
    if der[0] != 0x30:
        raise ValueError(f"Expected DER SEQUENCE tag 0x30, got 0x{der[0]:02x}")
    _, offset = _der_decode_length(der, 1)
    n, offset = _der_decode_integer(der, offset)
    e, offset = _der_decode_integer(der, offset)
    # Return as big-endian bytes with no leading zeros (canonical form)
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return n_bytes, e_bytes

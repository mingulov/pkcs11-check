"""Helpers for decoding Wycheproof key encodings into PKCS#11-friendly forms."""

from __future__ import annotations

import base64
from math import ceil
from typing import Any

from asn1crypto import pem  # type: ignore[import-untyped]
from asn1crypto.keys import (  # type: ignore[import-untyped]
    ECPrivateKey,
    PrivateKeyInfo,
    PublicKeyInfo,
)
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pkcs11_check.raw.ec import encode_named_curve_parameters

_EC_CURVE_ALIASES: dict[str, tuple[str, int]] = {
    "P-256": ("secp256r1", 256),
    "P-384": ("secp384r1", 384),
    "P-521": ("secp521r1", 521),
    "P-256K": ("secp256k1", 256),
    "brainpoolP224r1": ("brainpoolp224r1", 224),
    "brainpoolP256r1": ("brainpoolp256r1", 256),
    "brainpoolP320r1": ("brainpoolp320r1", 320),
    "brainpoolP384r1": ("brainpoolp384r1", 384),
    "brainpoolP512r1": ("brainpoolp512r1", 512),
    "secp224r1": ("secp224r1", 224),
    "secp256k1": ("secp256k1", 256),
    "secp256r1": ("secp256r1", 256),
    "secp384r1": ("secp384r1", 384),
    "secp521r1": ("secp521r1", 521),
    "sect283k1": ("sect283k1", 283),
    "sect283r1": ("sect283r1", 283),
    "sect409k1": ("sect409k1", 409),
    "sect409r1": ("sect409r1", 409),
    "sect571k1": ("sect571k1", 571),
    "sect571r1": ("sect571r1", 571),
}


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _pem_to_der(value: str) -> bytes:
    _type_name, _headers, der = pem.unarmor(value.encode())
    return bytes(der)


def pkcs11_bigint_from_hex(value: str) -> bytes:
    """Convert third-party integer hex to Cryptoki unsigned big-endian bytes."""
    if value == "":
        return b""
    raw = bytes.fromhex(value)
    return raw.lstrip(b"\x00") or b"\x00"


def normalize_ec_curve(curve_name: str) -> tuple[str, int]:
    return _EC_CURVE_ALIASES.get(curve_name, (curve_name.lower(), 256))


def ec_params_for_curve(curve_name: str) -> bytes:
    canonical, _bits = normalize_ec_curve(curve_name)
    return encode_named_curve_parameters(canonical)


def ec_key_bits(curve_name: str) -> int:
    _canonical, bits = normalize_ec_curve(curve_name)
    return ceil(bits / 8) * 8


def ec_coord_size(curve_name: str) -> int:
    _canonical, bits = normalize_ec_curve(curve_name)
    return ceil(bits / 8)


def decode_ec_public_point(value: Any, encoding_name: str, curve_name: str) -> bytes:
    if encoding_name == "ecpoint":
        return bytes.fromhex(value)
    if encoding_name == "asn":
        info = PublicKeyInfo.load(bytes.fromhex(value))
        return bytes(info["public_key"])
    if encoding_name == "pem":
        info = PublicKeyInfo.load(_pem_to_der(value))
        return bytes(info["public_key"])
    if encoding_name == "webcrypto":
        coord_size = ec_coord_size(curve_name)
        x = _b64url_decode(value["x"]).rjust(coord_size, b"\x00")
        y = _b64url_decode(value["y"]).rjust(coord_size, b"\x00")
        return b"\x04" + x + y
    raise ValueError(f"Unsupported EC public encoding: {encoding_name}")


def decode_ec_private_scalar(value: Any, encoding_name: str, curve_name: str) -> bytes:
    if encoding_name in {"asn", "ecpoint"}:
        raw = bytes.fromhex(value)
        # Strip leading zero from DER integer encoding (sign byte)
        coord_size = ec_coord_size(curve_name)
        if len(raw) == coord_size + 1 and raw[0] == 0:
            raw = raw[1:]
        return raw
    if encoding_name == "pem":
        info = PrivateKeyInfo.load(_pem_to_der(value))
        key = ECPrivateKey.load(info["private_key"].parsed.dump())
        raw = key["private_key"].contents
        coord_size = ec_coord_size(curve_name)
        if len(raw) == coord_size + 1 and raw[0] == 0:
            raw = raw[1:]
        return bytes(raw)
    if encoding_name == "webcrypto":
        coord_size = ec_coord_size(curve_name)
        return _b64url_decode(value["d"]).rjust(coord_size, b"\x00")
    raise ValueError(f"Unsupported EC private encoding: {encoding_name}")


def _extract_spki_bitstring_raw(der: bytes) -> bytes | None:
    """Minimal ASN.1 extraction of public key bytes from SubjectPublicKeyInfo.

    Extracts the BIT STRING content without validating the AlgorithmIdentifier.
    Used as a fallback when Python's crypto library rejects the DER (wrong OID,
    wrong key length) — we still want to send the raw bytes to the PKCS#11
    module to test its input validation.

    Returns None if the DER structure can't be parsed at all.
    """
    try:
        if len(der) < 4 or der[0] != 0x30:  # outer SEQUENCE
            return None
        pos = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
        # Skip inner SEQUENCE (AlgorithmIdentifier)
        if pos >= len(der) or der[pos] != 0x30:
            return None
        inner_len = der[pos + 1]
        if inner_len >= 0x80:
            n_bytes = inner_len & 0x7F
            inner_len = int.from_bytes(der[pos + 2 : pos + 2 + n_bytes], "big")
            pos += 2 + n_bytes + inner_len
        else:
            pos += 2 + inner_len
        # Now at BIT STRING
        if pos >= len(der) or der[pos] != 0x03:
            return None
        bs_len = der[pos + 1]
        if bs_len >= 0x80:
            n_bytes = bs_len & 0x7F
            bs_len = int.from_bytes(der[pos + 2 : pos + 2 + n_bytes], "big")
            pos += 2 + n_bytes
        else:
            pos += 2
        # Skip the "unused bits" byte (should be 0x00)
        if pos >= len(der):
            return None
        pos += 1
        bs_len -= 1
        return der[pos : pos + bs_len]
    except (IndexError, ValueError):
        return None


def _decode_xdh_public_der(der: bytes) -> bytes:
    key = serialization.load_der_public_key(der)
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _decode_xdh_private_der(der: bytes) -> bytes:
    key = serialization.load_der_private_key(der, password=None)
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def decode_xdh_public_bytes(value: Any, encoding_name: str) -> bytes:
    """Decode XDH public key bytes from various encodings.

    For ASN.1 and PEM encodings, uses a fallback minimal parser when the
    crypto library rejects the DER (wrong OID, wrong key length).  This lets
    us send malformed public keys to the PKCS#11 module for input validation.
    """
    if encoding_name == "raw":
        return bytes.fromhex(value)
    if encoding_name in ("asn", "pem"):
        der = bytes.fromhex(value) if encoding_name == "asn" else _pem_to_der(value)
        try:
            return _decode_xdh_public_der(der)
        except (UnsupportedAlgorithm, ValueError):
            raw = _extract_spki_bitstring_raw(der)
            if raw is not None:
                return raw
            raise
    if encoding_name == "jwk":
        return _b64url_decode(value["x"])
    raise ValueError(f"Unsupported XDH public encoding: {encoding_name}")


def decode_xdh_private_bytes(value: Any, encoding_name: str) -> bytes:
    if encoding_name == "raw":
        return bytes.fromhex(value)
    if encoding_name == "asn":
        return _decode_xdh_private_der(bytes.fromhex(value))
    if encoding_name == "pem":
        return _decode_xdh_private_der(_pem_to_der(value))
    if encoding_name == "jwk":
        return _b64url_decode(value["d"])
    raise ValueError(f"Unsupported XDH private encoding: {encoding_name}")

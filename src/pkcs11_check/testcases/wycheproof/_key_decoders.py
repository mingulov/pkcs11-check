"""Helpers for decoding Wycheproof key encodings into PKCS#11-friendly forms."""

from __future__ import annotations

import base64
from math import ceil
from typing import Any

from asn1crypto import pem
from asn1crypto.keys import ECPrivateKey, PrivateKeyInfo, PublicKeyInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pkcs11 import util as p11_util

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
    return der


def normalize_ec_curve(curve_name: str) -> tuple[str, int]:
    return _EC_CURVE_ALIASES.get(curve_name, (curve_name.lower(), 256))


def ec_params_for_curve(curve_name: str) -> bytes:
    canonical, _bits = normalize_ec_curve(curve_name)
    return p11_util.ec.encode_named_curve_parameters(canonical)


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
        return bytes.fromhex(value)
    if encoding_name == "pem":
        info = PrivateKeyInfo.load(_pem_to_der(value))
        key = ECPrivateKey.load(info["private_key"].parsed.dump())
        return key["private_key"].contents
    if encoding_name == "webcrypto":
        coord_size = ec_coord_size(curve_name)
        return _b64url_decode(value["d"]).rjust(coord_size, b"\x00")
    raise ValueError(f"Unsupported EC private encoding: {encoding_name}")


def _decode_xdh_public_der(der: bytes) -> bytes:
    key = serialization.load_der_public_key(der)
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _decode_xdh_private_der(der: bytes) -> bytes:
    key = serialization.load_der_private_key(der, password=None)
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def decode_xdh_public_bytes(value: Any, encoding_name: str) -> bytes:
    if encoding_name == "raw":
        return bytes.fromhex(value)
    if encoding_name == "asn":
        return _decode_xdh_public_der(bytes.fromhex(value))
    if encoding_name == "pem":
        return _decode_xdh_public_der(_pem_to_der(value))
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

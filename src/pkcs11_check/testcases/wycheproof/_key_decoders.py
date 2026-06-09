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


# Short-Weierstrass domain parameters (p, a, b) for the prime-field,
# cofactor-1 curves used by the Wycheproof ECDH suites (SEC 2 / RFC 5639).
# Cofactor 1 matters: every on-curve point except infinity has full order,
# so an on-curve point cannot mount a small-subgroup attack.
_PRIME_COFACTOR1_CURVE_PARAMS: dict[str, tuple[int, int, int]] = {
    "secp224r1": (
        2**224 - 2**96 + 1,
        -3,
        0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    ),
    "secp256k1": (2**256 - 2**32 - 977, 0, 7),
    "secp256r1": (
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        -3,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    ),
    "secp384r1": (
        2**384 - 2**128 - 2**96 + 2**32 - 1,
        -3,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    ),
    "secp521r1": (
        2**521 - 1,
        -3,
        0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    ),
    "brainpoolp224r1": (
        0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF,
        0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43,
        0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B,
    ),
    "brainpoolp256r1": (
        0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
        0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
        0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
    ),
    "brainpoolp320r1": (
        0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27,
        0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4,
        0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6,
    ),
    "brainpoolp384r1": (
        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
        0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
        0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11,
    ),
    "brainpoolp512r1": (
        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
        0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
        0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723,
    ),
}


def _ec_affine_add(
    pt1: tuple[int, int] | None,
    pt2: tuple[int, int] | None,
    p: int,
    a: int,
) -> tuple[int, int] | None:
    """Affine point addition; None is the point at infinity."""
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if pt1 == pt2:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def ecdh_cofactor1_shared_x(
    curve_name: str,
    public_point: bytes,
    private_scalar: bytes,
) -> bytes | None:
    """x-coordinate of ``scalar * point`` on a known cofactor-1 prime curve.

    Returns None when the curve is unknown, the encoding is not a canonical
    uncompressed on-curve point, or the result is the point at infinity —
    callers must then keep treating the vector by its original result class.
    Used to detect Wycheproof "invalid" ECDH vectors whose invalidity lives
    only in ASN.1 curve parameters that CK_ECDH1_DERIVE_PARAMS cannot carry.
    """
    canonical, _bits = normalize_ec_curve(curve_name)
    params = _PRIME_COFACTOR1_CURVE_PARAMS.get(canonical)
    if params is None:
        return None
    p, a, b = params
    coord = ec_coord_size(curve_name)
    if len(public_point) != 1 + 2 * coord or public_point[:1] != b"\x04":
        return None
    x = int.from_bytes(public_point[1 : 1 + coord], "big")
    y = int.from_bytes(public_point[1 + coord :], "big")
    if x >= p or y >= p or (y * y - (x * x * x + a * x + b)) % p != 0:
        return None
    k = int.from_bytes(private_scalar, "big")
    result: tuple[int, int] | None = None
    base: tuple[int, int] | None = (x, y)
    while k:
        if k & 1:
            result = _ec_affine_add(result, base, p, a)
        base = _ec_affine_add(base, base, p, a)
        k >>= 1
    if result is None:
        return None
    return result[0].to_bytes(coord, "big")


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

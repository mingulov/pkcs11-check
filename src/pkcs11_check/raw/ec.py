"""EC curve DER OID encoding for PKCS#11 CKA_EC_PARAMS."""

from __future__ import annotations

# DER-encoded OIDs for named curves used in PKCS#11 CKA_EC_PARAMS.
# Each value is a complete ASN.1 OID TLV (tag 0x06 + length + OID bytes).
_CURVE_OIDS: dict[str, bytes] = {
    # NIST/SEC P-curves (ANSI X9.62)
    "secp256r1": bytes([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    "secp384r1": bytes([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]),
    "secp521r1": bytes([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]),
    # Edwards and Montgomery curves (RFC 8410)
    "ed25519": bytes([0x06, 0x03, 0x2B, 0x65, 0x70]),
    "ed448": bytes([0x06, 0x03, 0x2B, 0x65, 0x71]),
    "x25519": bytes([0x06, 0x03, 0x2B, 0x65, 0x6E]),
    "x448": bytes([0x06, 0x03, 0x2B, 0x65, 0x6F]),
    # Brainpool (RFC 5639)
    "brainpoolp256r1": bytes([0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]),
    "brainpoolp384r1": bytes([0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B]),
    "brainpoolp512r1": bytes([0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D]),
    # secp256k1 (Bitcoin)
    "secp256k1": bytes([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]),
}

# Common aliases
_ALIASES: dict[str, str] = {
    "p-256": "secp256r1",
    "p-384": "secp384r1",
    "p-521": "secp521r1",
    "prime256v1": "secp256r1",
    "nistp256": "secp256r1",
    "nistp384": "secp384r1",
    "nistp521": "secp521r1",
}


def encode_named_curve_parameters(name: str) -> bytes:
    """Return the DER-encoded OID for a named EC curve.

    Accepts standard names (secp256r1, ed25519) and common aliases
    (P-256, prime256v1). Case-insensitive.
    """
    key = name.lower().strip()
    canonical = _ALIASES.get(key, key)
    oid = _CURVE_OIDS.get(canonical)
    if oid is None:
        raise ValueError(f"Unknown curve: {name!r}")
    return oid

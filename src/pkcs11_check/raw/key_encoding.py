"""PKCS#8 DER encoders for RSA and EC private keys.

Converts raw PKCS#11 key material (CRT components for RSA, scalar + ec_params for EC)
into DER-encoded PKCS#8 PrivateKeyInfo structures suitable for C_UnwrapKey injection.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ObjectIdentifier

from pkcs11_check.raw.types_std import CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY

_DER_PKCS8 = serialization.Encoding.DER
_PKCS8_FORMAT = serialization.PrivateFormat.PKCS8
_NO_ENCRYPTION = serialization.NoEncryption()


def _decode_der_oid(data: bytes) -> str:
    """Decode a DER-encoded OBJECT IDENTIFIER (tag 0x06) to a dotted string.

    Args:
        data: Raw DER bytes starting with tag 0x06.

    Returns:
        Dotted OID string (e.g. "1.2.840.10045.3.1.7").

    Raises:
        ValueError: If data is not a valid DER OID encoding.
    """
    if len(data) < 2:
        raise ValueError(f"DER OID too short: {len(data)} byte(s)")
    if data[0] != 0x06:
        raise ValueError(f"Expected DER OID tag 0x06, got 0x{data[0]:02x}")
    oid_len = data[1]
    if oid_len & 0x80:
        raise ValueError("unsupported long-form DER length in EC params OID")
    body = data[2 : 2 + oid_len]
    if len(body) != oid_len:
        raise ValueError("DER OID length mismatch")

    # First byte encodes the first two sub-identifiers.
    # arc-0: first < 40 → (0, first)
    # arc-1: 40 <= first < 80 → (1, first - 40)
    # arc-2: first >= 80 → (2, first - 80)
    first = body[0]
    a, b = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    components = [a, b]

    # Remaining bytes are base-128 varint-encoded sub-identifiers
    i = 1
    while i < len(body):
        value = 0
        while i < len(body):
            byte = body[i]
            i += 1
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                break
        components.append(value)

    return ".".join(str(c) for c in components)


def rsa_pkcs8_from_crt(
    *,
    n: bytes,
    e: bytes,
    d: bytes,
    p: bytes,
    q: bytes,
    dmp1: bytes,
    dmq1: bytes,
    iqmp: bytes,
) -> bytes:
    """Encode RSA CRT components as a DER PKCS#8 PrivateKeyInfo.

    Args:
        n: RSA modulus (big-endian bytes).
        e: Public exponent (big-endian bytes).
        d: Private exponent (big-endian bytes).
        p: First prime factor (big-endian bytes).
        q: Second prime factor (big-endian bytes).
        dmp1: d mod (p-1) (big-endian bytes).
        dmq1: d mod (q-1) (big-endian bytes).
        iqmp: q^{-1} mod p (big-endian bytes).

    Returns:
        DER-encoded PKCS#8 PrivateKeyInfo bytes.
    """
    pub = rsa.RSAPublicNumbers(
        e=int.from_bytes(e, "big"),
        n=int.from_bytes(n, "big"),
    )
    priv = rsa.RSAPrivateNumbers(
        p=int.from_bytes(p, "big"),
        q=int.from_bytes(q, "big"),
        d=int.from_bytes(d, "big"),
        dmp1=int.from_bytes(dmp1, "big"),
        dmq1=int.from_bytes(dmq1, "big"),
        iqmp=int.from_bytes(iqmp, "big"),
        public_numbers=pub,
    )
    key = priv.private_key()
    return key.private_bytes(_DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION)


def ec_pkcs8_from_private(*, scalar: bytes, ec_params: bytes, key_type: int) -> bytes:
    """Encode an EC private scalar as a DER PKCS#8 PrivateKeyInfo.

    Handles three key types:
    - CKK_EC: Named-curve EC key; ``ec_params`` must be a DER OID (tag 0x06).
    - CKK_EC_EDWARDS: Edwards curve key (Ed25519 for 32-byte scalar, Ed448 for 57 bytes).
    - CKK_EC_MONTGOMERY: Montgomery curve key (X25519 for 32-byte scalar, X448 for 56 bytes).

    Args:
        scalar: Raw private key bytes (big-endian for CKK_EC, raw for Edwards/Montgomery).
        ec_params: DER-encoded OID for CKK_EC; ignored for Edwards/Montgomery.
        key_type: PKCS#11 key type constant (CKK_EC, CKK_EC_EDWARDS, or CKK_EC_MONTGOMERY).

    Returns:
        DER-encoded PKCS#8 PrivateKeyInfo bytes.

    Raises:
        ValueError: For unsupported key_type or unresolvable curve OID.
    """
    if key_type == CKK_EC:
        return _ec_named_curve_pkcs8(scalar=scalar, ec_params=ec_params)
    elif key_type == CKK_EC_EDWARDS:
        return _edwards_pkcs8(scalar=scalar)
    elif key_type == CKK_EC_MONTGOMERY:
        return _montgomery_pkcs8(scalar=scalar)
    else:
        raise ValueError(f"Unsupported key_type: 0x{key_type:08x}")


def _ec_named_curve_pkcs8(*, scalar: bytes, ec_params: bytes) -> bytes:
    """Encode a named-curve EC private key as PKCS#8 DER."""
    dotted = _decode_der_oid(ec_params)
    try:
        oid = ObjectIdentifier(dotted)
        curve = ec.get_curve_for_oid(oid)()
    except Exception as exc:
        raise ValueError(f"Cannot resolve EC curve OID {dotted!r}: {exc}") from exc
    key = ec.derive_private_key(int.from_bytes(scalar, "big"), curve)
    return key.private_bytes(_DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION)


def _edwards_pkcs8(*, scalar: bytes) -> bytes:
    """Encode an Edwards-curve private key as PKCS#8 DER."""
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

    n = len(scalar)
    if n == 32:  # noqa: PLR2004
        return ed25519.Ed25519PrivateKey.from_private_bytes(scalar).private_bytes(
            _DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION
        )
    if n == 57:  # noqa: PLR2004
        return ed448.Ed448PrivateKey.from_private_bytes(scalar).private_bytes(
            _DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION
        )
    raise ValueError(f"CKK_EC_EDWARDS scalar must be 32 (Ed25519) or 57 (Ed448) bytes, got {n}")


def _montgomery_pkcs8(*, scalar: bytes) -> bytes:
    """Encode a Montgomery-curve private key as PKCS#8 DER."""
    from cryptography.hazmat.primitives.asymmetric import x448, x25519

    n = len(scalar)
    if n == 32:  # noqa: PLR2004
        return x25519.X25519PrivateKey.from_private_bytes(scalar).private_bytes(
            _DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION
        )
    if n == 56:  # noqa: PLR2004
        return x448.X448PrivateKey.from_private_bytes(scalar).private_bytes(
            _DER_PKCS8, _PKCS8_FORMAT, _NO_ENCRYPTION
        )
    raise ValueError(f"CKK_EC_MONTGOMERY scalar must be 32 (X25519) or 56 (X448) bytes, got {n}")

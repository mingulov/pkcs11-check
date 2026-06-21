import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (  # noqa: E501
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

from pkcs11_check.raw.key_encoding import ec_pkcs8_from_private, rsa_pkcs8_from_crt
from pkcs11_check.raw.types_std import CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY


def _b(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")


def test_rsa_pkcs8_round_trips() -> None:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = k.private_numbers()
    pub = n.public_numbers
    der = rsa_pkcs8_from_crt(
        n=_b(pub.n),
        e=_b(pub.e),
        d=_b(n.d),
        p=_b(n.p),
        q=_b(n.q),
        dmp1=_b(n.dmp1),
        dmq1=_b(n.dmq1),
        iqmp=_b(n.iqmp),
    )
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_numbers().d == n.d


def test_ec_named_curve_pkcs8_round_trips() -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    scalar = k.private_numbers().private_value.to_bytes(32, "big")
    p256_oid_der = bytes.fromhex("06082a8648ce3d030107")
    der = ec_pkcs8_from_private(scalar=scalar, ec_params=p256_oid_der, key_type=CKK_EC)
    loaded = serialization.load_der_private_key(der, password=None)
    assert loaded.private_numbers().private_value == k.private_numbers().private_value


def test_ed25519_pkcs8_round_trips() -> None:
    k = ed25519.Ed25519PrivateKey.generate()
    raw = k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_EDWARDS)
    loaded = serialization.load_der_private_key(der, password=None)
    assert (
        loaded.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        == raw
    )


def test_x25519_pkcs8_round_trips() -> None:
    k = x25519.X25519PrivateKey.generate()
    raw = k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_MONTGOMERY)
    loaded = serialization.load_der_private_key(der, password=None)
    assert (
        loaded.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        == raw
    )


def test_ed448_pkcs8_round_trips() -> None:
    k = ed448.Ed448PrivateKey.generate()
    raw = k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_EDWARDS)
    loaded = serialization.load_der_private_key(der, password=None)
    assert (
        loaded.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        == raw
    )


def test_x448_pkcs8_round_trips() -> None:
    k = x448.X448PrivateKey.generate()
    raw = k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    der = ec_pkcs8_from_private(scalar=raw, ec_params=b"", key_type=CKK_EC_MONTGOMERY)
    loaded = serialization.load_der_private_key(der, password=None)
    assert (
        loaded.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        == raw
    )


def test_ec_pkcs8_unsupported_key_type_raises() -> None:
    with pytest.raises(ValueError):
        ec_pkcs8_from_private(scalar=b"\x00" * 32, ec_params=b"", key_type=0x9999)


def test_ec_pkcs8_malformed_ec_params_raises() -> None:
    # OID tag 0x06, length 0x01, body 0x99 — decodes to a dotted string that
    # resolves to no known EC curve, so ec.get_curve_for_oid() raises.
    with pytest.raises(ValueError):
        ec_pkcs8_from_private(scalar=b"\x00" * 32, ec_params=b"\x06\x01\x99", key_type=CKK_EC)

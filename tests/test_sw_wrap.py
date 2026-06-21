import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding

from pkcs11_check.raw import sw_wrap


def _rsa_pub_priv() -> tuple[bytes, rsa.RSAPrivateKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub_der, priv


def test_rsa_aes_key_wrap_roundtrip_large_target() -> None:
    pub_der, priv = _rsa_pub_priv()
    target = os.urandom(1217)  # ~ RSA-2048 PKCS#8 private key size; OAEP alone cannot wrap this
    blob = sw_wrap.rsa_aes_key_wrap_blob(pub_der, target, aes_bits=256)
    # blob = c (modulus_bytes) || c' ; recover T then AES-KWP-unwrap to verify
    mod_bytes = priv.key_size // 8
    c, cprime = blob[:mod_bytes], blob[mod_bytes:]
    # Default is SHA-1 OAEP
    kek_t = priv.decrypt(
        c,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),  # nosec B303
    )
    assert aes_key_unwrap_with_padding(kek_t, cprime) == target


def test_rsa_aes_key_wrap_roundtrip_sha256() -> None:
    """Explicit sha256 path: blob must be decryptable with SHA-256 OAEP."""
    pub_der, priv = _rsa_pub_priv()
    target = os.urandom(64)
    blob = sw_wrap.rsa_aes_key_wrap_blob(pub_der, target, aes_bits=256, oaep_hash="sha256")
    mod_bytes = priv.key_size // 8
    c, cprime = blob[:mod_bytes], blob[mod_bytes:]
    kek_t = priv.decrypt(
        c,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert aes_key_unwrap_with_padding(kek_t, cprime) == target


def test_rsa_oaep_wrap_sha1_roundtrip() -> None:
    pub_der, priv = _rsa_pub_priv()
    payload = b"test-kek-bytes-32" + b"\x00" * 15
    blob = sw_wrap.rsa_oaep_wrap(pub_der, payload, oaep_hash="sha1")
    recovered = priv.decrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),  # nosec B303
    )
    assert recovered == payload


def test_oaep_max_payload() -> None:
    pub_der, _ = _rsa_pub_priv()
    # Default is SHA-1: 256 - 2*20 - 2 = 214
    assert sw_wrap.oaep_max_payload(pub_der) == 214
    # Explicit SHA-256: 256 - 2*32 - 2 = 190
    assert sw_wrap.oaep_max_payload(pub_der, oaep_hash="sha256") == 190


def test_oaep_unknown_hash_raises() -> None:
    pub_der, _ = _rsa_pub_priv()
    with pytest.raises(ValueError, match="oaep_hash"):
        sw_wrap.oaep_max_payload(pub_der, oaep_hash="md5")

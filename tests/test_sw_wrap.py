import os

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
    kek_t = priv.decrypt(
        c,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert aes_key_unwrap_with_padding(kek_t, cprime) == target


def test_oaep_max_payload() -> None:
    pub_der, _ = _rsa_pub_priv()
    assert sw_wrap.oaep_max_payload(pub_der) == 2048 // 8 - 2 * 32 - 2  # 190

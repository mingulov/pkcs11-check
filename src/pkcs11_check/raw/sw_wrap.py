"""Software-side construction of PKCS#11 wrap blobs (CKM_RSA_AES_KEY_WRAP / OAEP / AES-KWP).

Builds the exact bytes the module's C_UnwrapKey will decrypt. OAEP params default to
SHA-1 / MGF1-SHA1 / empty label for maximum HSM compatibility and MUST match the
CK_RSA_*_PARAMS passed to the module.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.hazmat.primitives.serialization import load_der_public_key


def _oaep_hashlen(oaep_hash: str) -> int:
    if oaep_hash == "sha1":
        return 20
    if oaep_hash == "sha256":
        return 32
    raise ValueError(f"Unknown oaep_hash: {oaep_hash!r}; expected 'sha1' or 'sha256'")


def _oaep_padding(oaep_hash: str) -> padding.OAEP:
    if oaep_hash == "sha1":
        h: hashes.HashAlgorithm = hashes.SHA1()  # nosec B303
    elif oaep_hash == "sha256":
        h = hashes.SHA256()
    else:
        raise ValueError(f"Unknown oaep_hash: {oaep_hash!r}; expected 'sha1' or 'sha256'")
    return padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None)


def _load_rsa_pub(rsa_pub_der: bytes) -> RSAPublicKey:
    pub = load_der_public_key(rsa_pub_der)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError(f"Expected RSAPublicKey, got {type(pub)}")
    return pub


def oaep_max_payload(rsa_pub_der: bytes, oaep_hash: str = "sha1") -> int:
    """Max OAEP payload for this key: modulus_bytes - 2*hashlen - 2.

    SHA-1: 214 bytes for RSA-2048. SHA-256: 190 bytes for RSA-2048.
    """
    pub = _load_rsa_pub(rsa_pub_der)
    return pub.key_size // 8 - 2 * _oaep_hashlen(oaep_hash) - 2


def rsa_oaep_wrap(rsa_pub_der: bytes, payload: bytes, oaep_hash: str = "sha1") -> bytes:
    """RSA-OAEP encrypt payload."""
    return _load_rsa_pub(rsa_pub_der).encrypt(payload, _oaep_padding(oaep_hash))


def aes_kwp_wrap(kek: bytes, payload: bytes) -> bytes:
    """AES Key Wrap with Padding (RFC 5649) of ``payload`` under ``kek``."""
    return aes_key_wrap_with_padding(kek, payload)


def rsa_aes_key_wrap_blob(
    rsa_pub_der: bytes, target: bytes, *, aes_bits: int = 256, oaep_hash: str = "sha1"
) -> bytes:
    """CKM_RSA_AES_KEY_WRAP blob: RSA-OAEP(pub, T) || AES-KWP(T, target)."""
    if aes_bits not in (128, 192, 256):
        raise ValueError(f"aes_bits must be 128/192/256, got {aes_bits}")
    kek = os.urandom(aes_bits // 8)
    return rsa_oaep_wrap(rsa_pub_der, kek, oaep_hash=oaep_hash) + aes_kwp_wrap(kek, target)

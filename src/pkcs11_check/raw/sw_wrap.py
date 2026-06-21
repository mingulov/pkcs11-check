"""Software-side construction of PKCS#11 wrap blobs (CKM_RSA_AES_KEY_WRAP / OAEP / AES-KWP).

Builds the exact bytes the module's C_UnwrapKey will decrypt. OAEP params are fixed to
SHA-256 / MGF1-SHA256 / empty label and MUST match the CK_RSA_*_PARAMS passed to the module.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _load_rsa_pub(rsa_pub_der: bytes) -> RSAPublicKey:
    pub = load_der_public_key(rsa_pub_der)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError(f"Expected RSAPublicKey, got {type(pub)}")
    return pub


def oaep_max_payload(rsa_pub_der: bytes) -> int:
    """Max OAEP-SHA256 payload for this key: modulus_bytes - 2*hashlen - 2."""
    pub = _load_rsa_pub(rsa_pub_der)
    return pub.key_size // 8 - 2 * 32 - 2


def rsa_oaep_wrap(rsa_pub_der: bytes, payload: bytes) -> bytes:
    """RSA-OAEP(SHA-256) encrypt ``payload`` (<= oaep_max_payload)."""
    return _load_rsa_pub(rsa_pub_der).encrypt(payload, _OAEP)


def aes_kwp_wrap(kek: bytes, payload: bytes) -> bytes:
    """AES Key Wrap with Padding (RFC 5649) of ``payload`` under ``kek``."""
    return aes_key_wrap_with_padding(kek, payload)


def rsa_aes_key_wrap_blob(rsa_pub_der: bytes, target: bytes, *, aes_bits: int = 256) -> bytes:
    """CKM_RSA_AES_KEY_WRAP blob: RSA-OAEP(pub, T) || AES-KWP(T, target), T a fresh AES KEK."""
    if aes_bits not in (128, 192, 256):
        raise ValueError(f"aes_bits must be 128/192/256, got {aes_bits}")
    kek = os.urandom(aes_bits // 8)
    return rsa_oaep_wrap(rsa_pub_der, kek) + aes_kwp_wrap(kek, target)

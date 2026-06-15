"""Per-family local cryptographic verifiers for cross-checking PKCS#11 signatures.

These functions are pure software oracles — they never touch a PKCS#11 module.
They are intentionally strict:
- PSS salt length is passed in exactly (never AUTO / PKCS1v15).
- ECDSA uses curve-aware coord_len via split_raw_ecdsa.
- MalformedSignature from split_raw_ecdsa is NOT caught here; callers map it.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from pkcs11_check.testcases._ec_export import MalformedSignature as MalformedSignature  # re-export
from pkcs11_check.testcases._ec_export import split_raw_ecdsa


def rsa_pkcs15_local(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    hash_alg: hashes.HashAlgorithm,
) -> bool:
    """Verify *sig* over *data* with RSA PKCS#1 v1.5 using *hash_alg*.

    Returns True on valid signature, False on InvalidSignature.
    """
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hash_alg)
        return True
    except InvalidSignature:
        return False


def rsa_pss_local(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    hash_alg: hashes.HashAlgorithm,
    mgf_hash: hashes.HashAlgorithm,
    salt_len: int,
) -> bool:
    """Verify *sig* over *data* with RSA-PSS.

    *salt_len* is the EXACT integer salt length used when signing (e.g. 0 or 32).
    This is critical: passing AUTO would reject zero-salt ACVP groups.
    """
    pss_pad = padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=salt_len)
    try:
        pub.verify(sig, data, pss_pad, hash_alg)
        return True
    except InvalidSignature:
        return False


def ecdsa_local(
    pub: ec.EllipticCurvePublicKey,
    data: bytes,
    sig_raw: bytes,
    hash_alg: hashes.HashAlgorithm,
    coord_len: int,
) -> bool:
    """Verify a raw (r || s) ECDSA signature over *data*.

    *coord_len* is the byte length of a single coordinate for the curve
    (e.g. 32 for P-256, 48 for P-384, 66 for P-521).

    Raises MalformedSignature (from split_raw_ecdsa) if len(sig_raw) != 2 * coord_len.
    That exception is intentionally not caught here — callers map it to xfail.
    """
    r, s = split_raw_ecdsa(sig_raw, coord_len)
    der = utils.encode_dss_signature(r, s)
    try:
        pub.verify(der, data, ec.ECDSA(hash_alg))
        return True
    except InvalidSignature:
        return False

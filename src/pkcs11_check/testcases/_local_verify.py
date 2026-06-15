"""Per-family local cryptographic verifiers for cross-checking PKCS#11 signatures.

These functions are pure software oracles — they never touch a PKCS#11 module.
They are intentionally strict:
- PSS salt length is passed in exactly (never AUTO / PKCS1v15).
- ECDSA uses curve-aware coord_len via split_raw_ecdsa.
- MalformedSignature from split_raw_ecdsa is NOT caught here; callers map it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.recipes import verify_single
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM
from pkcs11_check.testcases._ec_export import MalformedSignature as MalformedSignature  # re-export
from pkcs11_check.testcases._ec_export import split_raw_ecdsa
from pkcs11_check.testcases._signature_policy import (
    MODULE_VERIFY_UNUSABLE_RVS as _MODULE_VERIFY_UNUSABLE_RVS,
)
from pkcs11_check.testcases._signature_policy import (
    signature_rejected_or_xfail,
)


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


def rsa_pss_local_any_salt(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    hash_alg: hashes.HashAlgorithm,
    mgf_hash: hashes.HashAlgorithm,
) -> bool:
    """Verify RSA-PSS accepting ANY salt length (``PSS.AUTO``).

    Answers "is this a cryptographically valid PSS signature for this key+message,
    regardless of salt length". Used to tell a module that produced a VALID PSS
    signature but did not honor the requested ``saltLen`` (an honest_deviation)
    apart from one that produced a genuinely INVALID signature (wrong_result).
    """
    pss_pad = padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=padding.PSS.AUTO)
    try:
        pub.verify(sig, data, pss_pad, hash_alg)
        return True
    except InvalidSignature:
        return False


# Standard MGF1 hashes a PKCS#11 module might use for RSA-PSS. The message digest
# is intrinsic to the signing mechanism (CKM_SHA*_RSA_PKCS_PSS) and is never varied;
# only the MGF1 hash is probed, since that is the parameter a module can silently
# substitute while still producing a cryptographically valid signature.
_PSS_MGF_CANDIDATES: tuple[hashes.HashAlgorithm, ...] = (
    hashes.SHA1(),
    hashes.SHA224(),
    hashes.SHA256(),
    hashes.SHA384(),
    hashes.SHA512(),
)


def rsa_pss_local_recover_mgf(
    pub: rsa.RSAPublicKey,
    data: bytes,
    sig: bytes,
    hash_alg: hashes.HashAlgorithm,
) -> hashes.HashAlgorithm | None:
    """Return the MGF1 hash under which *sig* verifies as RSA-PSS (any salt), or None.

    Tries each standard MGF1 hash (:data:`_PSS_MGF_CANDIDATES`) with ``PSS.AUTO``
    salt. Used to tell a module that produced a VALID PSS signature with a
    non-requested MGF1 hash (an honest_deviation) apart from one whose signature
    is invalid under EVERY standard MGF (a real wrong_result, never masked).
    *hash_alg* is the message digest, intrinsic to the mechanism and never varied.
    """
    for mgf_hash in _PSS_MGF_CANDIDATES:
        pss_pad = padding.PSS(mgf=padding.MGF1(mgf_hash), salt_length=padding.PSS.AUTO)
        try:
            pub.verify(sig, data, pss_pad, hash_alg)
            return mgf_hash
        except InvalidSignature:
            continue
    return None


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


def verify_roundtrip(
    rs: Any,
    *,
    mechanism: CKM | int,
    data: bytes,
    signature: bytes,
    local: Callable[[], bool],
    module_pub_handle: int,
    mech_param: PackedMechanism | None = None,
    label: str,
) -> None:
    """Judge a ROUNDTRIP signature: local oracle is the always-run authority.

    *local* is a no-arg callable returning True iff the local python-cryptography
    oracle accepts the module-produced *signature*. *module_pub_handle* is the
    handle the module's own C_Verify should use; *verify_single* runs that verify.

    Outcomes:

    1. *local* raises :class:`MalformedSignature` -> xfail ``nonspec_reject`` (a
       malformed signature WIDTH is never a crypto fail).
    2. *local* returns False -> fail ``wrong_result`` (kind=crypto): the module's
       OWN signature is invalid by cross-verify -- a real crypto break.
    3. module C_Verify raises :class:`CkrAssertionError`:
       - rv in :data:`_MODULE_VERIFY_UNUSABLE_RVS` -> ``return`` (pass): the module
         cannot verify here, so its real result stands; the verify-capability
         finding belongs to a separate test.
       - otherwise -> :func:`signature_rejected_or_xfail` (-> xfail for
         OPERATION_ACTIVE / PARAM_INVALID / etc.) and ``return``. NEVER re-raise.
    4. module C_Verify returns False (and *local* accepted) -> fail
       ``self_contradiction`` (kind=crypto): the module rejected a signature the
       local oracle accepts as valid.
    5. local valid AND module valid -> ``return`` (pass).
    """
    try:
        local_ok = local()
    except MalformedSignature as exc:
        xfail_as(
            "nonspec_reject",
            kind="metadata",
            label=label,
            summary=f"{label}: module signature has non-spec width: {exc}",
        )

    if not local_ok:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            summary=f"{label}: module signature INVALID by local cross-verify",
        )

    try:
        mod_ok = verify_single(
            rs.raw,
            rs.sh,
            module_pub_handle,
            mechanism,
            data,
            signature,
            mech_param=mech_param,
        )
    except CkrAssertionError as exc:
        if getattr(exc, "rv", None) in _MODULE_VERIFY_UNUSABLE_RVS:
            return
        signature_rejected_or_xfail(exc, label)
        return

    if not mod_ok:
        fail_as(
            "self_contradiction",
            kind="crypto",
            label=label,
            summary=(
                f"{label}: module C_Verify rejected a signature local cross-verify accepts as valid"
            ),
        )

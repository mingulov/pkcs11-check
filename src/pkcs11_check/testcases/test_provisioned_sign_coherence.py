"""Coherence of pre-provisioned signing keys (no-import / Cloud-KMS-class providers).

A generate-only, no-import module cannot seed keys via C_CreateObject, and
C_GenerateKeyPair may need a vendor template. Its keys are instead created
server-side and exposed as PKCS#11 objects. This test gives such a module REAL
crypto coverage with no import: for each findable private signing key it signs a
message in PKCS#11 and verifies the signature in software against the key's
exported public key. ``verify_roundtrip`` makes the local python-cryptography oracle
the authority -- a signature the oracle rejects is a ``wrong_result`` crypto FAIL,
so a broken module signing path is surfaced, not masked.

Provider-general: it skips cleanly when the token exposes no findable signing keys
(the common case for software HSMs whose tokens start empty), so it is a no-op
everywhere except modules that pre-expose signing keys.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import find_objects, read_attributes, sign_single
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SIGN,
    CKK_EC,
    CKK_RSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases._ec_export import coord_len_for_curve, read_ec_public_key_or_xfail
from pkcs11_check.testcases._local_verify import ecdsa_local, rsa_pkcs15_local, verify_roundtrip
from pkcs11_check.testcases._rsa_export import read_rsa_public_key_or_xfail
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.crossverify

_MSG = b"pkcs11-check provisioned-key sign coherence"

# Named-curve CKA_EC_PARAMS (DER OID) -> (curve, single-hash ECDSA mechanism, hash).
_EC_PARAMS = {
    bytes.fromhex("06082a8648ce3d030107"): (ec.SECP256R1(), CKM_ECDSA_SHA256, hashes.SHA256()),
    bytes.fromhex("06052b81040022"): (ec.SECP384R1(), CKM_ECDSA_SHA384, hashes.SHA384()),
}

# Clean codes meaning "this key does not permit this mechanism" -> try next /
# skip this key (NOT a finding: single-algorithm modules refuse mechanisms not
# provisioned for the key, so an RSA-PSS key cleanly refuses CKM_SHA256_RSA_PKCS).
_MECH_NOT_FOR_KEY = (
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
)


def _match_public(rs: Any, priv_attrs: dict[Any, Any]) -> int | None:
    """Find the public key paired with a private key (by CKA_ID, then CKA_LABEL)."""
    for key in (CKA_ID, CKA_LABEL):
        val = priv_attrs.get(key)
        if val:
            handles = find_objects(
                rs.raw, rs.sh, template_from_dict({CKA_CLASS: CKO_PUBLIC_KEY, key: val})
            )
            if handles:
                return handles[0]
    return None


def test_provisioned_signing_keys_are_coherent(p11_module_session: Any) -> None:
    rs = p11_module_session
    priv_handles = find_objects(rs.raw, rs.sh, template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY}))
    verified = 0
    for priv in priv_handles:
        attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SIGN, CKA_KEY_TYPE, CKA_ID, CKA_LABEL])
        if not attrs.get(CKA_SIGN):
            continue
        pub = _match_public(rs, attrs)
        if pub is None:
            continue
        kt = attrs.get(CKA_KEY_TYPE)

        if kt == int(CKK_RSA):
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, _MSG)
            except AssertionError as exc:
                # PSS-only (or otherwise non-PKCS1) key cleanly refuses -> skip key.
                if is_known_error(exc, set(_MECH_NOT_FOR_KEY)):
                    continue
                raise
            rsa_pub = read_rsa_public_key_or_xfail(rs, pub, label="provisioned RSA public key")
            verify_roundtrip(
                rs,
                mechanism=CKM_SHA256_RSA_PKCS,
                data=_MSG,
                signature=sig,
                local=lambda: rsa_pkcs15_local(rsa_pub, _MSG, sig, hashes.SHA256()),
                module_pub_handle=pub,
                label="provisioned RSA-PKCS1 sign",
            )
            verified += 1

        elif kt == int(CKK_EC):
            ec_params = read_attributes(rs.raw, rs.sh, priv, [CKA_EC_PARAMS]).get(CKA_EC_PARAMS)
            spec = _EC_PARAMS.get(bytes(ec_params)) if ec_params else None
            if spec is None:
                continue  # curve not in the small map -> not covered here
            curve, mech, hash_alg = spec
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, _MSG)
            except AssertionError as exc:
                if is_known_error(exc, set(_MECH_NOT_FOR_KEY)):
                    continue
                raise
            ec_pub = read_ec_public_key_or_xfail(rs, pub, curve, label="provisioned EC public key")
            coord_len = coord_len_for_curve(curve)
            verify_roundtrip(
                rs,
                mechanism=mech,
                data=_MSG,
                signature=sig,
                local=lambda: ecdsa_local(ec_pub, _MSG, sig, hash_alg, coord_len),
                module_pub_handle=pub,
                label="provisioned ECDSA sign",
            )
            verified += 1

    if verified == 0:
        pytest.skip("Module exposes no findable provisioned signing keys")

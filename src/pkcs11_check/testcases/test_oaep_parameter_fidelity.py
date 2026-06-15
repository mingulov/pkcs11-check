"""RSA-OAEP parameter-fidelity probe.

Import a known RSA keypair (the local oracle keeps the python private key).
Two directions (spec G5):

- Encrypt-direction fidelity: the module encrypts requesting hashAlg=SHA256,
  mgf=MGF1-SHA1, label=b"fidelity". Local recover_oaep_params finds the ACTUAL
  (hash, mgf, label) used; mismatch -> honest_deviation. No candidate recovers ->
  not_operational (interpretable=False), never wrong_result.
- Decrypt-direction correctness: local encrypts a known ciphertext with the
  requested params; the module decrypts. A DIFFERENT plaintext -> wrong_result
  (clean crypto-break signal); a clean error -> not_operational; correct -> pass.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_oaep
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly, encrypt_single
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._param_fidelity import (
    FidelityResult,
    classify_fidelity,
    recover_oaep_params,
)
from pkcs11_check.testcases.conftest import (
    import_rsa_private_key_negotiated,
    import_rsa_public_key_negotiated,
    is_known_error,
)

pytestmark = pytest.mark.crossverify

_PLAINTEXT = b"OAEP parameter-fidelity probe"
_LABEL = b"fidelity"
_OAEP_HASHES = (hashes.SHA1(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
_OAEP_REFUSED = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_ARGUMENTS_BAD,
)


def _int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def _import_known_keypair(rs: Any) -> tuple[rsa.RSAPrivateKey, int, int]:
    """Generate a python RSA-2048 keypair and import both halves into the module."""
    k = rsa.generate_private_key(65537, 2048)
    pn = k.private_numbers()
    pub_n = k.public_key().public_numbers()
    priv_handle = import_rsa_private_key_negotiated(
        rs,
        n=_int_to_bytes(pub_n.n),
        e=_int_to_bytes(pub_n.e),
        d=_int_to_bytes(pn.d),
        p=_int_to_bytes(pn.p),
        q=_int_to_bytes(pn.q),
        dmp1=_int_to_bytes(pn.dmp1),
        dmq1=_int_to_bytes(pn.dmq1),
        iqmp=_int_to_bytes(pn.iqmp),
        attrs={CKA_DECRYPT: True},
    )
    pub_handle = import_rsa_public_key_negotiated(
        rs, n=_int_to_bytes(pub_n.n), e=_int_to_bytes(pub_n.e), attrs={CKA_ENCRYPT: True}
    )
    return k, priv_handle, pub_handle


class TestOaepParameterFidelity:
    def test_oaep_encrypt_param_fidelity(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        label = "OAEP:encrypt hashAlg=SHA256/mgf=MGF1-SHA1/label fidelity"
        priv_h = pub_h = 0
        try:
            try:
                k, priv_h, pub_h = _import_known_keypair(rs)
            except AssertionError as exc:
                pytest.skip(f"RSA keypair import refused: {exc}")
            mech_param = mech_oaep(
                CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA1, source_data=_LABEL
            )
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub_h,
                    CKM_RSA_PKCS_OAEP,
                    _PLAINTEXT,
                    mech_param=mech_param,
                    output_overhead=256,
                )
            except AssertionError as exc:
                if is_known_error(exc, _OAEP_REFUSED):
                    xfail_as(
                        "not_operational",
                        kind="lifecycle",
                        label=label,
                        operation="C_Encrypt",
                        mechanism="CKM_RSA_PKCS_OAEP",
                        summary=not_operational_reason(label, f"OAEP params refused: {exc}"),
                    )
                raise
            recovered = recover_oaep_params(
                k, ct, _PLAINTEXT, _OAEP_HASHES, _OAEP_HASHES, (_LABEL, None)
            )
            if recovered is None:
                result = FidelityResult(
                    valid=False,
                    conforms=False,
                    interpretable=False,
                    requested={"hash": "sha256", "mgf": "sha1", "label": _LABEL.hex()},
                    actual={"hash": None, "mgf": None, "label": None},
                    detail="OAEP params not recoverable from candidate set",
                )
            else:
                alg, mgf, lab = recovered
                result = FidelityResult(
                    valid=True,
                    conforms=(alg.name == "sha256" and mgf.name == "sha1" and lab == _LABEL),
                    interpretable=True,
                    requested={"hash": "sha256", "mgf": "sha1", "label": _LABEL.hex()},
                    actual={
                        "hash": alg.name,
                        "mgf": mgf.name,
                        "label": lab.hex() if lab else None,
                    },
                    detail="OAEP encrypt-direction fidelity",
                )
            classify_fidelity(
                result, label=label, operation="C_Encrypt", mechanism="CKM_RSA_PKCS_OAEP"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)

    def test_oaep_decrypt_correctness(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        label = "OAEP:decrypt SHA256/MGF1-SHA256 correctness"
        priv_h = pub_h = 0
        try:
            try:
                k, priv_h, pub_h = _import_known_keypair(rs)
            except AssertionError as exc:
                pytest.skip(f"RSA keypair import refused: {exc}")
            # Local-encrypt a known ciphertext with the requested (matched) params.
            ct = k.public_key().encrypt(
                _PLAINTEXT,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
                ),
            )
            mech_param = mech_oaep(
                CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256, source_data=None
            )
            try:
                recovered = decrypt_single(
                    rs.raw,
                    rs.sh,
                    priv_h,
                    CKM_RSA_PKCS_OAEP,
                    ct,
                    mech_param=mech_param,
                    output_size_hint=len(_PLAINTEXT) + 8,
                )
            except AssertionError as exc:
                if is_known_error(exc, _OAEP_REFUSED):
                    xfail_as(
                        "not_operational",
                        kind="lifecycle",
                        label=label,
                        operation="C_Decrypt",
                        mechanism="CKM_RSA_PKCS_OAEP",
                        summary=not_operational_reason(label, f"OAEP decrypt refused: {exc}"),
                    )
                raise
            if recovered != _PLAINTEXT:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=label,
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    summary=f"{label}: module decrypted OAEP to the WRONG plaintext",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)

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
- Source-param self-contradiction probe (WS4-P2): CKM_RSA_PKCS_OAEP with
  source=CKZ_DATA_SPECIFIED, pSourceData=NULL, ulSourceDataLen=4. The OASIS
  PKCS#11 spec (v2.40/v3.0, CK_RSA_PKCS_OAEP_PARAMS table) states: "If the
  parameter is empty, pSourceData must be NULL and ulSourceDataLen must be zero."
  A non-zero ulSourceDataLen with a NULL pointer is therefore a self-contradictory
  struct that a conformant module MUST reject.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_oaep, mech_oaep_source_contradiction
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
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
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
_OAEP_HASHES = (hashes.SHA1(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())  # nosec B303
_OAEP_REFUSED = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_ARGUMENTS_BAD,
    # Module-operational-failure codes: advertised OAEP but the imported key
    # handle / size / type is not usable for the op (e.g. craton imports the key
    # CKR_OK then rejects the handle on C_Encrypt/C_Decrypt). Aligns with the
    # framework's MODULE_VERIFY_UNUSABLE_RVS -> not_operational (xfail), never a
    # raw hard fail.
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
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


class TestOaepParamMismatch:
    """OAEP source-parameter self-contradiction probe (WS4-P2).

    Supply CKM_RSA_PKCS_OAEP with a self-contradictory CK_RSA_PKCS_OAEP_PARAMS:
    source=CKZ_DATA_SPECIFIED, pSourceData=NULL, ulSourceDataLen=4.

    The OASIS PKCS#11 spec (v2.40 and v3.0, CK_RSA_PKCS_OAEP_PARAMS table) states:
    "If the parameter is empty, pSourceData must be NULL and ulSourceDataLen must
    be zero."  Setting ulSourceDataLen=4 while pSourceData=NULL violates this
    constraint: the struct claims 4 bytes of encoding parameter data but supplies no
    pointer.  A conformant module MUST reject this with CKR_MECHANISM_PARAM_INVALID
    or CKR_ARGUMENTS_BAD.

    Note: independent hashAlg/mgf choices are NOT forbidden by the spec — only the
    hash-specific PSS mechanism (CKM_SHA*_RSA_PKCS_PSS) has an explicit hash
    consistency requirement. This probe uses a genuine struct self-contradiction
    instead.

    Three-state classification (same as TestOaepParameterFidelity):
    - Module rejects with a clean CKR -> xfail(not_operational) -- correct.
    - Module encrypts: recover_oaep_params tries all (hash, mgf) combinations
      against the ciphertext.  conforms=False by construction (accepting a
      self-contradictory param struct is a spec violation regardless of output).
    - No candidate recovers the plaintext -> not_operational (interpretable=False).
    """

    def test_oaep_source_param_self_contradiction(self, p11_raw_session: Any) -> None:
        """CKM_RSA_PKCS_OAEP + source=CKZ_DATA_SPECIFIED, pSourceData=NULL, ulSourceDataLen=4."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        label = "OAEP:source-contradiction CKZ_DATA_SPECIFIED/pSourceData=NULL/len=4"
        priv_h = pub_h = 0
        try:
            try:
                k, priv_h, pub_h = _import_known_keypair(rs)
            except AssertionError as exc:
                pytest.skip(f"RSA keypair import refused: {exc}")
            # Spec-illegal: source=CKZ_DATA_SPECIFIED, pSourceData=NULL, ulSourceDataLen=4.
            # OASIS spec requires "if the parameter is empty, pSourceData must be NULL
            # and ulSourceDataLen must be zero" — nonzero len with NULL pointer contradicts this.
            mech_param = mech_oaep_source_contradiction(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
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
                        summary=not_operational_reason(
                            label, f"OAEP self-contradiction params refused: {exc}"
                        ),
                    )
                raise
            # Module encrypted despite the self-contradictory param struct.
            # Recover what params it actually used (if any standard combo matches).
            recovered = recover_oaep_params(k, ct, _PLAINTEXT, _OAEP_HASHES, _OAEP_HASHES, (None,))
            if recovered is None:
                result = FidelityResult(
                    valid=False,
                    conforms=False,
                    interpretable=False,
                    requested={"source": "CKZ_DATA_SPECIFIED", "pSourceData": "NULL", "len": 4},
                    actual={"hash": None, "mgf": None},
                    detail="OAEP source-contradiction: output not recoverable from candidate set",
                )
            else:
                alg, mgf, _lab = recovered
                # conforms=False by construction: accepting a self-contradictory param
                # struct (NULL pointer with nonzero length) is a spec violation.
                result = FidelityResult(
                    valid=True,
                    conforms=False,
                    interpretable=True,
                    requested={"source": "CKZ_DATA_SPECIFIED", "pSourceData": "NULL", "len": 4},
                    actual={"hash": alg.name, "mgf": mgf.name},
                    detail="OAEP source self-contradiction accepted by module",
                )
            classify_fidelity(
                result, label=label, operation="C_Encrypt", mechanism="CKM_RSA_PKCS_OAEP"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)

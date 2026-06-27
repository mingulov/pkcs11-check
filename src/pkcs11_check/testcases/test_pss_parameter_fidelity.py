"""RSA-PSS parameter-fidelity probes.

Deliberately request a NON-DEFAULT structural parameter and check whether the
module honored it, recovering the ACTUAL value used (spec
docs/superpowers/specs/2026-06-15-parameter-fidelity-design.md):

- salt probe: request saltLen=8 (non-digest-length), mgf==hash. A module that
  produces a valid signature with a different salt -> honest_deviation reporting
  the actual salt (observed on some modules).
- mgf probe (secondary): request mgf=MGF1-SHA1 with hashAlg=SHA256 (legal but
  unusual). Often refused -> not_operational; if honored/substituted, recover the
  actual MGF.
- mismatch probe: CKM_SHA256_RSA_PKCS_PSS mechanism but PSS param struct supplies
  hashAlg=CKM_SHA_1 (inconsistent with the mechanism's mandated SHA-256). A clean
  reject is correct (pass/xfail); a module that signs and produces a VALID
  signature reports what param it actually used (honest_deviation if different
  from requested, wrong_result if the signature is invalid under all candidates).
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_pss
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair, sign_single
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._local_verify import rsa_pss_local_recover_mgf
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._param_fidelity import (
    FidelityResult,
    classify_fidelity,
    recover_pss_salt_len,
)
from pkcs11_check.testcases._rsa_export import read_rsa_public_key_or_xfail
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.crossverify

_PSS_PARAM_REFUSED = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_ARGUMENTS_BAD,
    # Module-operational-failure codes: advertised PSS but the key handle/type
    # is not usable for the op -> not_operational (xfail), never a hard fail.
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
)
_MSG = b"PSS parameter-fidelity probe message"


def _xfail_pss_param_refused(exc: AssertionError, label: str) -> None:
    """A clean refusal of the requested PSS param combo -> not_operational; else re-raise."""
    if is_known_error(exc, _PSS_PARAM_REFUSED):
        xfail_as(
            "not_operational",
            kind="lifecycle",
            label=label,
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS_PSS",
            summary=not_operational_reason(label, f"requested PSS param refused: {exc}"),
        )
    raise exc


def _gen_pss_keypair(rs: Any) -> tuple[int, int]:
    return gen_rsa_keypair(
        rs.raw,
        rs.sh,
        bits=2048,
        public_attrs={CKA_VERIFY: True},
        private_attrs={CKA_SIGN: True},
    )


class TestPssParameterFidelity:
    def test_pss_salt_length_honored(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        label = "PSS:saltLen=8 fidelity"
        pub = priv = 0
        try:
            pub, priv = _gen_pss_keypair(rs)
            mech_param = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256, salt_len=8
            )
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS_PSS, _MSG, mech_param=mech_param
                )
            except AssertionError as exc:
                _xfail_pss_param_refused(exc, label)
            pubkey = read_rsa_public_key_or_xfail(rs, pub, label=label)
            mgf = rsa_pss_local_recover_mgf(pubkey, _MSG, sig, hashes.SHA256())
            salt = (
                recover_pss_salt_len(pubkey, _MSG, sig, mgf, hashes.SHA256())
                if mgf is not None
                else None
            )
            valid = mgf is not None and salt is not None
            classify_fidelity(
                FidelityResult(
                    valid=valid,
                    conforms=mgf is not None and mgf.name == "sha256" and salt == 8,
                    interpretable=True,
                    requested={"mgf": "sha256", "salt": 8},
                    actual={"mgf": mgf.name if mgf else None, "salt": salt},
                    detail="PSS saltLen fidelity",
                ),
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS_PSS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pss_mgf_hash_honored(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        label = "PSS:mgf=MGF1-SHA1 fidelity"
        pub = priv = 0
        try:
            pub, priv = _gen_pss_keypair(rs)
            mech_param = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA1, salt_len=32
            )
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS_PSS, _MSG, mech_param=mech_param
                )
            except AssertionError as exc:
                _xfail_pss_param_refused(exc, label)
            pubkey = read_rsa_public_key_or_xfail(rs, pub, label=label)
            mgf = rsa_pss_local_recover_mgf(pubkey, _MSG, sig, hashes.SHA256())
            salt = (
                recover_pss_salt_len(pubkey, _MSG, sig, mgf, hashes.SHA256())
                if mgf is not None
                else None
            )
            valid = mgf is not None and salt is not None
            classify_fidelity(
                FidelityResult(
                    valid=valid,
                    conforms=mgf is not None and mgf.name == "sha1",
                    interpretable=True,
                    requested={"mgf": "sha1"},
                    actual={"mgf": mgf.name if mgf else None, "salt": salt},
                    detail="PSS MGF1 fidelity",
                ),
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS_PSS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestPssParamMismatch:
    """PSS mechanism-parameter MISMATCH probe (WS4-P2).

    Supply CKM_SHA256_RSA_PKCS_PSS with a PSS param struct that sets
    hashAlg=CKM_SHA_1 (inconsistent: the mechanism mandates SHA-256 but the
    struct claims SHA-1).  This is a genuinely malformed parameter combination
    that a conformant module MUST reject.

    Three-state classification:
    - Module rejects with a clean CKR -> xfail(not_operational) -- correct
      behaviour, recorded as a policy deviation rather than a finding.
    - Module signs and the signature is cryptographically valid -> use the
      established fidelity oracle (rsa_pss_local_recover_mgf +
      recover_pss_salt_len) to recover what param it actually used:
        - conforms=False always (the mechanism requires SHA-256 but the param
          struct requested SHA-1; any acceptance is a spec deviation).
        - actual params reported via honest_deviation so the deviation is
          recorded, never silently passed.
    - Module signs but the signature is invalid under every standard MGF ->
      wrong_result (crypto break).
    """

    def test_pss_hash_mismatch(self, p11_raw_session: Any) -> None:
        """CKM_SHA256_RSA_PKCS_PSS + hashAlg=SHA-1 in param struct."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        label = "PSS:mismatch hashAlg=SHA-1 vs SHA256-PSS mechanism"
        pub = priv = 0
        try:
            pub, priv = _gen_pss_keypair(rs)
            # hashAlg=SHA-1 is inconsistent with CKM_SHA256_RSA_PKCS_PSS (mandates SHA-256).
            # mgf=MGF1-SHA256 is consistent with the mechanism but not with hashAlg=SHA-1,
            # making the struct doubly inconsistent (hash/mgf pairing is also mismatched).
            mech_param = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA256,
                salt_len=20,
            )
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS_PSS, _MSG, mech_param=mech_param
                )
            except AssertionError as exc:
                _xfail_pss_param_refused(exc, label)
            # Module signed despite the mismatch: recover the actual param used.
            pubkey = read_rsa_public_key_or_xfail(rs, pub, label=label)
            mgf = rsa_pss_local_recover_mgf(pubkey, _MSG, sig, hashes.SHA256())
            salt = (
                recover_pss_salt_len(pubkey, _MSG, sig, mgf, hashes.SHA256())
                if mgf is not None
                else None
            )
            valid = mgf is not None and salt is not None
            # conforms=False by construction: the mechanism requires SHA-256 but
            # the param struct requested SHA-1; accepting and signing with any
            # param is a deviation from the spec constraint.
            classify_fidelity(
                FidelityResult(
                    valid=valid,
                    conforms=False,
                    interpretable=True,
                    requested={
                        "hashAlg": "sha1 (mismatched vs SHA256-PSS mechanism)",
                        "mgf": "sha256",
                    },
                    actual={"mgf": mgf.name if mgf else None, "salt": salt},
                    detail="PSS hash/mechanism mismatch accepted",
                ),
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS_PSS",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

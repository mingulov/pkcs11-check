"""NIST ACVP EdDSA test vectors (FIPS 186-5 / RFC 8032).

Tests Ed25519 and Ed448:
- Key generation (EDDSA-KeyGen-1.0)
- Key verification (EDDSA-KeyVer-1.0)
- Signature verification (EDDSA-SigVer-1.0)
- Signature generation (EDDSA-SigGen-1.0)

Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_bytes
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_keypair,
    import_ec_private_key,
    import_ec_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_SIGN,
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
    signature_rejected_or_xfail,
)
from pkcs11_check.testcases.acvp._duplicates import skip_duplicate_pkcs11_input
from pkcs11_check.testcases.acvp._eddsa_helpers import (
    load_eddsa_keygen_vectors,
    load_eddsa_keyver_vectors,
    load_eddsa_siggen_vectors,
    load_eddsa_sigver_vectors,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_CURVE_UNSUPPORTED_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
)

_UNUSABLE_KEY_RVS = (
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

_KEYVER_IMPORT_REJECT_RVS = (
    *_CURVE_UNSUPPORTED_RVS,
    CKR_FUNCTION_FAILED,
    CKR_KEY_TYPE_INCONSISTENT,
)

_EDDSA_PARAM_XFAIL_MSG = (
    "Module rejects explicit EdDSA mechanism params on an advertised EdDSA path"
)

_EDDSA_RUNTIME_REJECT_RVS = (
    *NON_CLEAN_SIGNATURE_REJECT_RVS,
    *_UNUSABLE_KEY_RVS,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _handle_unsupported_curve(exc: AssertionError, curve: str) -> None:
    """Check if exception indicates unsupported curve and skip if so."""
    if is_known_error(exc, _CURVE_UNSUPPORTED_RVS):
        pytest.skip(f"Curve {curve} not supported: {exc}")
    raise


def _xfail_if_eddsa_runtime_reject(exc: AssertionError, label: str) -> None:
    xfail_if_known_ckr(
        exc,
        _EDDSA_RUNTIME_REJECT_RVS,
        f"{label}: advertised EdDSA operation rejected",
    )


_KEYGEN_VECTORS = load_eddsa_keygen_vectors()
_KEYVER_VECTORS = load_eddsa_keyver_vectors()
_SIGVER_VECTORS = load_eddsa_sigver_vectors()
_SIGGEN_VECTORS = load_eddsa_siggen_vectors()


class TestEdDsaKeyGen:
    """EdDSA key generation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
    def test_eddsa_keygen(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test EdDSA keypair generation and roundtrip sign/verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_EDWARDS_KEY_PAIR_GEN"):
            pytest.skip("EC_EDWARDS_KEY_PAIR_GEN not supported by module")
        skip_duplicate_pkcs11_input(vec, "EdDSA KeyGen")

        pub_key = priv_key = 0
        try:
            try:
                pub_key, priv_key = gen_keypair(
                    rs.raw,
                    rs.sh,
                    mechanism=int(CKM_EC_EDWARDS_KEY_PAIR_GEN),
                    pub_base=[attr_bytes(CKA_EC_PARAMS, vec["ec_params"])],
                    priv_base=[],
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                    pub_skip={CKA_EC_PARAMS},
                )
            except AssertionError as exc:
                _handle_unsupported_curve(exc, vec["curve"])

            assert pub_key != 0, f"{vec_id}: Public key handle is zero"
            assert priv_key != 0, f"{vec_id}: Private key handle is zero"

            try:
                test_msg = b"EdDSA keygen test message"
                sig = sign_single(rs.raw, rs.sh, priv_key, CKM_EDDSA, test_msg)
                verified = verify_single(rs.raw, rs.sh, pub_key, CKM_EDDSA, test_msg, sig)
            except AssertionError as exc:
                _xfail_if_eddsa_runtime_reject(exc, vec_id)
            assert verified, f"{vec_id}: Roundtrip sign/verify failed"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestEdDsaKeyVer:
    """EdDSA key verification tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _KEYVER_VECTORS, ids=[v[0] for v in _KEYVER_VECTORS])
    def test_eddsa_keyver(
        self, p11_raw_session: Any, p11_config: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test EdDSA public key verification."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("EDDSA mechanism not supported by module")

        pub_key = 0
        try:
            try:
                pub_key = import_ec_public_key(
                    rs.raw,
                    rs.sh,
                    ec_params=vec["ec_params"],
                    ec_point=vec["ec_point"],
                    key_type=int(CKK_EC_EDWARDS),
                    attrs={CKA_VERIFY: True},
                )
            except AssertionError as e:
                if vec["expected_pass"]:
                    xfail_if_known_ckr(
                        e,
                        _KEYVER_IMPORT_REJECT_RVS,
                        f"{vec_id}: valid EdDSA key import rejected by advertised EDDSA path",
                    )
                return

            try:
                dummy_msg = b"x" * 32
                sig_len = 64 if "25519" in vec["curve"] else 114
                dummy_sig = b"\x00" * sig_len
                verify_single(rs.raw, rs.sh, pub_key, CKM_EDDSA, dummy_msg, dummy_sig)
                key_usable = True
            except AssertionError as exc:
                if is_known_error(exc, SIGNATURE_REJECT_RVS):
                    key_usable = True
                elif is_known_error(exc, NON_CLEAN_SIGNATURE_REJECT_RVS):
                    pytest.xfail(f"{vec_id}: invalid signature rejected with non-clean CKR")
                elif is_known_error(exc, _UNUSABLE_KEY_RVS):
                    key_usable = False
                else:
                    key_usable = True

            if not vec["expected_pass"] and key_usable:
                pytest.fail(f"{vec_id}: Module ACCEPTED an INVALID EdDSA key")
            if vec["expected_pass"] and not key_usable:
                pytest.fail(f"{vec_id}: Module rejected a VALID EdDSA key")
        finally:
            if pub_key:
                destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
def test_acvp_eddsa_sigver(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """EdDSA signature verification from NIST ACVP SigVer vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported by module")

    pub_key = 0
    try:
        try:
            pub_key = import_ec_public_key(
                rs.raw,
                rs.sh,
                ec_params=vec["ec_params"],
                ec_point=vec["ec_point"],
                key_type=int(CKK_EC_EDWARDS),
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            if is_known_error(exc, _CURVE_UNSUPPORTED_RVS):
                pytest.skip(f"Cannot import EdDSA public key for {vec['curve']}: {exc}")
            xfail_if_known_ckr(
                exc,
                _KEYVER_IMPORT_REJECT_RVS,
                f"{vec_id}: ACVP EdDSA public-key import rejected by advertised EDDSA path",
            )
            raise

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_EDDSA, vec["msg"], vec["sig"])
        except AssertionError as exc:
            if is_known_error(exc, {CKR_MECHANISM_PARAM_INVALID}):
                pytest.xfail(f"{vec_id}: {_EDDSA_PARAM_XFAIL_MSG} for {vec['curve']}")
            verified = signature_rejected_or_xfail(exc, vec_id)

        if not vec["expected_pass"] and verified:
            pytest.fail(f"{vec_id}: module ACCEPTED an INVALID EdDSA signature")
        if vec["expected_pass"] and not verified:
            pytest.fail(f"{vec_id}: module rejected a VALID EdDSA signature")
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_acvp_eddsa_siggen(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Ed25519 signature generation from NIST ACVP SigGen vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported by module")

    priv_key = 0
    try:
        try:
            priv_key = import_ec_private_key(
                rs.raw,
                rs.sh,
                ec_params=vec["ec_params"],
                value=vec["d"],
                key_type=int(CKK_EC_EDWARDS),
                attrs={CKA_SIGN: True},
            )
        except AssertionError as exc:
            if is_known_error(exc, _CURVE_UNSUPPORTED_RVS):
                pytest.skip(f"Cannot import Ed25519 private key for {vec_id}: {exc}")
            raise

        try:
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_EDDSA, vec["msg"])
        except AssertionError as exc:
            _xfail_if_eddsa_runtime_reject(exc, vec_id)

        if sig != vec["expected_sig"]:
            pytest.fail(f"{vec_id}: EdDSA signature mismatch")
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)

"""NIST ACVP RSA signature test vectors (FIPS 186-4/5).

Tests RSA signature generation and verification using official NIST ACVP vectors:
- RSA-SigGen-FIPS186-4/5: Signature generation (legacy and current)
- RSA-SigVer-FIPS186-2/4/5: Signature verification (legacy and current)

Mechanisms tested:
- CKM_SHA*_RSA_PKCS (PKCS#1 v1.5 with hash)
- CKM_SHA*_RSA_PKCS_PSS (RSA-PSS with hash)

SoftHSM2 Known Issues:
- RSA-PSS: Only supports hashAlg == mgf (no distinct hashes)

Requires: scripts/fetch-optional-data.sh acvp
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack_mechanisms import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    probe_operability,
    xfail_vacuous_reject,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.acvp.rsa.base_loader import (
    load_siggen_pkcs15_vectors,
    load_siggen_pss_vectors,
    load_sigver_pkcs15_vectors,
    load_sigver_pss_vectors,
)
from pkcs11_check.testcases.conftest import (
    import_rsa_public_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_PKCS15_SIGN = load_siggen_pkcs15_vectors()
_PSS_SIGN = load_siggen_pss_vectors()
_PKCS15_VER = load_sigver_pkcs15_vectors()
_PSS_VER = load_sigver_pss_vectors()

_RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
)

_RSA_SIGGEN_KEYGEN_CAPABILITY_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_RSA_SIGGEN_RUNTIME_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _skip_rsa_public_import_reject(exc: AssertionError) -> None:
    """Skip RSA SigVer vectors when the provider cannot import the public key."""
    if is_known_error(exc, _RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
        pytest.skip(f"RSA public key import failed: {exc}")
    raise exc


def _skip_or_xfail_rsa_siggen_keygen_reject(exc: AssertionError, key_bits: int) -> None:
    """Classify RSA SigGen setup key-generation rejection."""
    if is_known_error(exc, _RSA_SIGGEN_KEYGEN_CAPABILITY_CKRS):
        pytest.skip(f"RSA {key_bits}-bit key generation failed: {exc}")
    xfail_if_known_ckr(
        exc,
        (CKR_MECHANISM_INVALID,),
        "CKM_RSA_PKCS_KEY_PAIR_GEN advertised but keygen failed",
    )


def _xfail_rsa_siggen_runtime_reject(exc: AssertionError, mech_name: str) -> None:
    """Classify advertised RSA SigGen sign/verify runtime rejection."""
    xfail_if_known_ckr(
        exc,
        _RSA_SIGGEN_RUNTIME_REJECT_RVS,
        f"{mech_name} advertised but sign/verify is not operational",
    )


class TestRsaPkcs15:
    """RSA-PKCS#1 v1.5 signature tests."""

    @pytest.mark.parametrize("vec_id,vec", _PKCS15_SIGN, ids=[v[0] for v in _PKCS15_SIGN])
    def test_rsa_pkcs15_sign_verify(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA PKCS#1 v1.5 sign and verify with ACVP vectors."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        key_bits = vec["modulo"] if vec["modulo"] else 2048

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")

        pub_key = priv_key = 0
        try:
            try:
                pub_key, priv_key = gen_rsa_keypair(
                    rs.raw,
                    rs.sh,
                    bits=key_bits,
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
            except AssertionError as exc:
                _skip_or_xfail_rsa_siggen_keygen_reject(exc, key_bits)

            try:
                sig = sign_single(rs.raw, rs.sh, priv_key, mech_int, vec["message"])
                verified = verify_single(rs.raw, rs.sh, pub_key, mech_int, vec["message"], sig)
            except AssertionError as exc:
                _xfail_rsa_siggen_runtime_reject(exc, mech_name)
            assert verified
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestRsaPss:
    """RSA-PSS signature tests."""

    @pytest.mark.parametrize("vec_id,vec", _PSS_SIGN, ids=[v[0] for v in _PSS_SIGN])
    def test_rsa_pss_sign_verify(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA-PSS sign and verify with ACVP vectors."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        hash_mech = vec["hash_mech"]
        mgf: int = vec["mgf"]
        salt_len: int = vec["salt_len"]
        key_bits = vec["modulo"] if vec["modulo"] else 2048

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported by module")

        pub_key = priv_key = 0
        try:
            try:
                pub_key, priv_key = gen_rsa_keypair(
                    rs.raw,
                    rs.sh,
                    bits=key_bits,
                    public_attrs={CKA_VERIFY: True},
                    private_attrs={CKA_SIGN: True},
                )
            except AssertionError as exc:
                _skip_or_xfail_rsa_siggen_keygen_reject(exc, key_bits)

            mech_param = mech_pss(mech_int, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv_key, mech_int, vec["message"], mech_param=mech_param
                )
                verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub_key,
                    mech_int,
                    vec["message"],
                    sig,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                _xfail_rsa_siggen_runtime_reject(exc, mech_name)
            assert verified
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


def _pkcs15_sigver_operability(rs: Any, mech_name: str, key_bits: int) -> OperabilityResult:
    """Canonical (mech, key-bits) SigVer probe: imported public key + single verify.

    INCONCLUSIVE when staging fails (import refused / no canonical vector available) --
    no mechanism evidence either way; NOT_OPERATIONAL when the canonical known-valid vector
    is refused (CkrAssertionError) or verifies False; OPERATIONAL on True.

    Three-state design (triage H2): tpm2 rejects all 27 valid SHA-1 SigVer vectors while
    still rejecting every invalid one.  A reject of EVERY valid vector of a (mechanism,
    key-size) class is "advertised but not operational" (classification model: xfail), not a
    pile of per-vector findings; a staging failure (key import refused) must not masquerade as
    NOT_OPERATIONAL -- it is INCONCLUSIVE (no mechanism evidence either way).

    Non-CkrAssertionError exceptions from the probe are harness bugs and always propagate.
    """

    def probe() -> OperabilityResult:
        for _vec_id, vec in _PKCS15_VER:
            if (
                vec["mech_name"] != mech_name
                or not vec["expected_pass"]
                or len(vec["n"]) * 8 != key_bits
            ):
                continue
            pub_key = 0
            try:
                try:
                    pub_key = import_rsa_public_key_negotiated(
                        rs, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
                    )
                except CkrAssertionError as exc:
                    return OperabilityResult(
                        Operability.INCONCLUSIVE, f"canonical public-key import failed: {exc}"
                    )
                try:
                    ok = verify_single(
                        rs.raw, rs.sh, pub_key, vec["mech_int"], vec["message"], vec["signature"]
                    )
                except CkrAssertionError as exc:
                    return OperabilityResult(
                        Operability.NOT_OPERATIONAL, f"canonical verify rejected: {exc}"
                    )
                if not ok:
                    return OperabilityResult(
                        Operability.NOT_OPERATIONAL, "canonical known-valid vector verifies False"
                    )
                return OperabilityResult(Operability.OPERATIONAL, "canonical verify OK")
            finally:
                destroy_quietly(rs.raw, rs.sh, pub_key)
        return OperabilityResult(
            Operability.INCONCLUSIVE, f"no canonical valid vector for {mech_name}/{key_bits}"
        )

    return probe_operability(f"{mech_name}:{key_bits}:verify", probe)


class TestRsaSigVer:
    """RSA signature verification tests with valid/invalid vectors."""

    @pytest.mark.parametrize("vec_id,vec", _PKCS15_VER, ids=[v[0] for v in _PKCS15_VER])
    def test_rsa_pkcs15_verify(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA PKCS#1 v1.5 signature verification."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        expected_pass: bool = vec["expected_pass"]

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = 0
        try:
            try:
                pub_key = import_rsa_public_key_negotiated(
                    rs, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
                )
            except AssertionError as exc:
                _skip_rsa_public_import_reject(exc)
            try:
                verified = verify_single(
                    rs.raw, rs.sh, pub_key, mech_int, vec["message"], vec["signature"]
                )
            except AssertionError as exc:
                verified = signature_rejected_or_xfail(exc, vec_id)

            if not expected_pass and verified:
                pytest.fail(f"{vec_id}: ACCEPTED INVALID signature - security concern")
            if not expected_pass and not verified:
                # The invalid vector was rejected -- a genuine pass ONLY if the
                # mechanism actually verifies anything. tpm2 rejects all 27 valid
                # SHA-1 SigVer vectors while "passing" 135 invalid ones: those
                # rejections never evaluated the signature -> vacuous (xfail). The
                # probe is INCONCLUSIVE-safe (canonical import refused never fires).
                key_bits = len(vec["n"]) * 8
                xfail_vacuous_reject(
                    _pkcs15_sigver_operability(rs, mech_name, key_bits),
                    label=f"{vec_id}: {mech_name} invalid-signature reject",
                )
            if expected_pass and not verified:
                key_bits = len(vec["n"]) * 8
                result = _pkcs15_sigver_operability(rs, mech_name, key_bits)
                if result.status is Operability.NOT_OPERATIONAL:
                    pytest.xfail(
                        f"{vec_id}: {mech_name} canonical known-valid ACVP vector for "
                        f"{key_bits}-bit imported keys does not verify ({result.detail}) "
                        "-- advertised but not operational"
                    )
                if result.status is Operability.INCONCLUSIVE:
                    pytest.xfail(
                        f"{vec_id}: {mech_name} canonical probe inconclusive ({result.detail})"
                        " -- cannot distinguish deviation from module bug, recorded as xfail"
                    )
                pytest.fail(f"{vec_id}: rejected VALID signature")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

    @pytest.mark.parametrize("vec_id,vec", _PSS_VER, ids=[v[0] for v in _PSS_VER])
    def test_rsa_pss_verify(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test RSA-PSS signature verification."""
        rs = p11_module_session
        mech_name: str = vec["mech_name"]
        mech_int = vec["mech_int"]
        hash_mech = vec["hash_mech"]
        mgf: int = vec["mgf"]
        salt_len: int = vec["salt_len"]
        expected_pass: bool = vec["expected_pass"]

        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        pub_key = 0
        try:
            try:
                pub_key = import_rsa_public_key_negotiated(
                    rs, n=vec["n"], e=vec["e"], attrs={CKA_VERIFY: True}
                )
            except AssertionError as exc:
                _skip_rsa_public_import_reject(exc)
            mech_param = mech_pss(mech_int, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            try:
                verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub_key,
                    mech_int,
                    vec["message"],
                    vec["signature"],
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                if is_known_error(exc, {CKR_MECHANISM_PARAM_INVALID}):
                    pytest.xfail(
                        f"{mech_name} advertised but PSS params are not operational: {exc}"
                    )
                verified = signature_rejected_or_xfail(exc, vec_id)

            if not expected_pass and verified:
                pytest.fail(f"{vec_id}: ACCEPTED INVALID PSS signature - security concern")
            if expected_pass and not verified:
                pytest.fail(f"{vec_id}: rejected VALID PSS signature")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)

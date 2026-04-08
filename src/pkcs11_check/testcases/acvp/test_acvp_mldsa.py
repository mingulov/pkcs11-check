"""NIST ACVP ML-DSA test vectors (FIPS 204).

Tests ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets:
- Key generation (ML-DSA-keyGen-FIPS204)
- Signature generation (ML-DSA-sigGen-FIPS204)
- Signature verification (ML-DSA-sigVer-FIPS204)

Supports both pure ML-DSA and Hash-ML-DSA variants.

Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_keypair,
    import_pqc_private_key,
    import_pqc_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_VERIFY,
    CKK_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
)
from pkcs11_check.testcases.acvp._mldsa_helpers import (
    get_mldsa_mechanism,
    load_mldsa_keygen_vectors,
    load_mldsa_siggen_vectors,
    load_mldsa_sigver_vectors,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

pytestmark = [pytest.mark.kat, pytest.mark.acvp, pytest.mark.pqc]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# Parameter set display names
_PARAM_SET_NAMES: dict[int, str] = {
    int(CKP_ML_DSA_44): "ML-DSA-44",
    int(CKP_ML_DSA_65): "ML-DSA-65",
    int(CKP_ML_DSA_87): "ML-DSA-87",
}

_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_ATTRIBUTE_READ_ONLY",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_MECHANISM_PARAM_INVALID",
)


def _get_mech_name(pre_hash: str) -> str:
    """Get mechanism name from pre-hash type."""
    if pre_hash == "pure":
        return "ML_DSA"
    # Map hash algorithm names to mechanism suffixes
    hash_suffix_map = {
        "SHA-224": "SHA224",
        "SHA-256": "SHA256",
        "SHA-384": "SHA384",
        "SHA-512": "SHA512",
        "SHA3-224": "SHA3_224",
        "SHA3-256": "SHA3_256",
        "SHA3-384": "SHA3_384",
        "SHA3-512": "SHA3_512",
        "SHAKE128": "SHAKE128",
        "SHAKE256": "SHAKE256",
    }
    suffix = hash_suffix_map.get(pre_hash)
    if suffix:
        return f"HASH_ML_DSA_{suffix}"
    return "ML_DSA"


def _handle_unsupported(exc: AssertionError, param_set: str) -> None:
    """Check if exception indicates unsupported parameter set and skip if so."""
    if any(name in str(exc) for name in _UNSUPPORTED_ERRORS):
        pytest.skip(f"ML-DSA parameter set {param_set} not supported: {exc}")
    raise


_KEYGEN_VECTORS = load_mldsa_keygen_vectors()
_SIGGEN_VECTORS = load_mldsa_siggen_vectors()
_SIGVER_VECTORS = load_mldsa_sigver_vectors()


class TestMlDsaKeyGen:
    """ML-DSA key generation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
    def test_mldsa_keygen(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ML-DSA keypair generation and roundtrip sign/verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
            pytest.skip("ML_DSA_KEY_PAIR_GEN not supported by module")

        param_set_name = vec["param_set"]

        pub_key = priv_key = 0
        try:
            # Generate keypair with specific parameter set
            pub_key, priv_key = gen_keypair(
                rs.raw,
                rs.sh,
                mechanism=int(CKM_ML_DSA_KEY_PAIR_GEN),
                pub_base=[attr_ulong(CKA_PARAMETER_SET, vec["parameter_set"])],
                priv_base=[attr_ulong(CKA_PARAMETER_SET, vec["parameter_set"])],
                public_attrs={CKA_VERIFY: True},
                private_attrs={CKA_SIGN: True},
                pub_skip={CKA_PARAMETER_SET},
            )
            assert pub_key != 0, f"{vec_id}: Public key handle is zero"
            assert priv_key != 0, f"{vec_id}: Private key handle is zero"

            # Test roundtrip sign/verify using pure ML-DSA mechanism
            test_msg = b"ML-DSA keygen test message"
            mech = get_mldsa_mechanism("pure")  # Pure ML-DSA
            sig = sign_single(rs.raw, rs.sh, priv_key, mech, test_msg)
            verified = verify_single(rs.raw, rs.sh, pub_key, mech, test_msg, sig)
            assert verified, f"{vec_id}: Roundtrip sign/verify failed"
        except AssertionError as exc:
            _handle_unsupported(exc, param_set_name)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestMlDsaSigGen:
    """ML-DSA signature generation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
    def test_mldsa_siggen(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ML-DSA signature generation from NIST ACVP SigGen vectors."""
        rs = p11_raw_session
        pre_hash_for_check = vec["pre_hash"]
        if pre_hash_for_check == "preHash":
            pre_hash_for_check = vec.get("hash_alg", "pure")
        mech_name = _get_mech_name(pre_hash_for_check)
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} mechanism not supported by module")

        priv_key = 0
        try:
            # Import the private key from the vector
            if "sk" not in vec:
                pytest.skip(f"No private key available for {vec_id}")

            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_DSA),
                value=vec["sk"],
                parameter_set=vec["parameter_set"],
                attrs={CKA_SIGN: True},
            )

            # Get the mechanism for signing (pure or hash-specific)
            pre_hash = vec["pre_hash"]
            if pre_hash == "preHash":
                pre_hash = vec.get("hash_alg", "pure")
            mech = get_mldsa_mechanism(pre_hash)

            # Sign the message, passing context via CK_SIGN_ADDITIONAL_CONTEXT
            # when non-empty (pure ML-DSA only -- hash variants use mech_hash_sign_context)
            context = vec.get("context", b"")
            if isinstance(context, str):
                context = bytes.fromhex(context) if context else b""
            mech_param = mech_sign_context(mech, context=context) if context else None
            sig = sign_single(rs.raw, rs.sh, priv_key, mech, vec["msg"], mech_param=mech_param)

            # Note: ML-DSA is probabilistic, so we can't compare signatures
            # Instead, verify the signature we just generated (if pk available)
            pk_bytes = vec.get("pk", b"")
            if not pk_bytes:
                return

            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_DSA),
                value=pk_bytes,
                parameter_set=vec["parameter_set"],
                attrs={CKA_VERIFY: True},
            )

            try:
                verified = verify_single(rs.raw, rs.sh, pub_key, mech, vec["msg"], sig)
                if not verified:
                    pytest.fail(f"{vec_id}: Generated signature failed verification")
            finally:
                destroy_quietly(rs.raw, rs.sh, pub_key)

        except AssertionError as exc:
            _handle_unsupported(exc, vec["param_set"])
        finally:
            if priv_key:
                destroy_quietly(rs.raw, rs.sh, priv_key)


class TestMlDsaSigVer:
    """ML-DSA signature verification tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
    def test_acvp_mldsa_sigver(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """ML-DSA signature verification from NIST ACVP SigVer vectors."""
        rs = p11_raw_session
        pre_hash_for_check = vec["pre_hash"]
        if pre_hash_for_check == "preHash":
            pre_hash_for_check = vec.get("hash_alg", "pure")
        mech_name = _get_mech_name(pre_hash_for_check)

        # Check if the mechanism is supported
        # Pure ML-DSA uses CKM_ML_DSA, Hash-ML-DSA uses hash-specific mechanisms
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} mechanism not supported by module")

        pub_key = 0
        try:
            # Import the public key from the vector
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_DSA),
                value=vec["pk"],
                parameter_set=vec["parameter_set"],
                attrs={CKA_VERIFY: True},
            )

            # Get the mechanism for verification (pure or hash-specific)
            pre_hash = vec["pre_hash"]
            if pre_hash == "preHash":
                pre_hash = vec.get("hash_alg", "pure")
            mech = get_mldsa_mechanism(pre_hash)

            # Verify the signature, passing context when non-empty
            context = vec.get("context", b"")
            if isinstance(context, str):
                context = bytes.fromhex(context) if context else b""
            mech_param = mech_sign_context(mech, context=context) if context else None
            try:
                verified = verify_single(
                    rs.raw, rs.sh, pub_key, mech, vec["msg"], vec["sig"],
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                exc_msg = str(exc)
                if any(
                    name in exc_msg
                    for name in (
                        "CKR_SIGNATURE_INVALID",
                        "CKR_SIGNATURE_LEN_RANGE",
                    )
                ):
                    verified = False
                elif "CKR_MECHANISM_PARAM_INVALID" in exc_msg:
                    pytest.skip(f"{vec_id}: module requires mechanism params for Hash-ML-DSA")
                else:
                    raise

            if not vec["expected_pass"] and verified:
                pytest.fail(f"{vec_id}: module ACCEPTED an INVALID ML-DSA signature")
            if vec["expected_pass"] and not verified:
                pytest.fail(f"{vec_id}: module rejected a VALID ML-DSA signature")
        except AssertionError as exc:
            _handle_unsupported(exc, vec["param_set"])
        finally:
            if pub_key:
                destroy_quietly(rs.raw, rs.sh, pub_key)

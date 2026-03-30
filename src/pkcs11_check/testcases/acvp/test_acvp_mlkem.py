"""NIST ACVP ML-KEM test vectors (FIPS 203).

Tests ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameter sets:
- Key generation (ML-KEM-keyGen-FIPS203)
- Encapsulation (ML-KEM-encapDecap-FIPS203 encapsulation)
- Decapsulation (ML-KEM-encapDecap-FIPS203 decapsulation)

Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.recipes import (
    decapsulate_key,
    destroy_quietly,
    encapsulate_key,
    gen_keypair,
    import_pqc_private_key,
    import_pqc_public_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_PARAMETER_SET,
    CKK_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
)
from pkcs11_check.testcases.acvp._mlkem_helpers import (
    get_mlkem_mechanism,
    load_mlkem_decap_vectors,
    load_mlkem_encap_vectors,
    load_mlkem_keygen_vectors,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

pytestmark = [pytest.mark.kat, pytest.mark.acvp, pytest.mark.pqc]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

_UNSUPPORTED_ERRORS = (
    "CKR_MECHANISM_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
    "CKR_KEY_SIZE_RANGE",
    "CKR_DEVICE_ERROR",
    "CKR_MECHANISM_PARAM_INVALID",
    "CKR_FUNCTION_NOT_SUPPORTED",
)

_KEYGEN_VECTORS = load_mlkem_keygen_vectors()
_ENCAP_VECTORS = load_mlkem_encap_vectors()
_DECAP_VECTORS = load_mlkem_decap_vectors()


def _handle_unsupported(exc: AssertionError, param_set: str) -> None:
    """Check if exception indicates unsupported parameter set and skip if so."""
    if any(name in str(exc) for name in _UNSUPPORTED_ERRORS):
        pytest.skip(f"ML-KEM parameter set {param_set} not supported: {exc}")
    raise


class TestMlKemKeyGen:
    """ML-KEM key generation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
    def test_mlkem_keygen(self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ML-KEM keypair generation and roundtrip encap/decap."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM_KEY_PAIR_GEN"):
            pytest.skip("ML_KEM_KEY_PAIR_GEN not supported by module")

        param_set_name = vec["param_set"]

        pub_key = priv_key = 0
        try:
            # Generate keypair with specific parameter set
            pub_key, priv_key = gen_keypair(
                rs.raw,
                rs.sh,
                mechanism=int(CKM_ML_KEM_KEY_PAIR_GEN),
                pub_base=[attr_ulong(CKA_PARAMETER_SET, vec["parameter_set"])],
                priv_base=[attr_ulong(CKA_PARAMETER_SET, vec["parameter_set"])],
                public_attrs={CKA_ENCRYPT: True},
                private_attrs={CKA_DERIVE: True},
                pub_skip={CKA_PARAMETER_SET},
            )
            assert pub_key != 0, f"{vec_id}: Public key handle is zero"
            assert priv_key != 0, f"{vec_id}: Private key handle is zero"

            # Test roundtrip encapsulate/decapsulate
            mech = get_mlkem_mechanism(param_set_name)
            secret_handle, ciphertext = encapsulate_key(
                rs.raw, rs.sh, pub_key, mech, attrs={CKA_DERIVE: True}
            )
            assert secret_handle != 0, f"{vec_id}: Secret key handle is zero"
            assert ciphertext, f"{vec_id}: Ciphertext is empty"

            # Decapsulate to recover shared secret
            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                ciphertext,
                attrs={CKA_DERIVE: True},
            )
            assert decap_handle != 0, f"{vec_id}: Decapsulated key handle is zero"

            # Clean up the ephemeral keys
            destroy_quietly(rs.raw, rs.sh, secret_handle)
            destroy_quietly(rs.raw, rs.sh, decap_handle)
        except AssertionError as exc:
            _handle_unsupported(exc, param_set_name)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestMlKemEncapsulate:
    """ML-KEM encapsulation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _ENCAP_VECTORS, ids=[v[0] for v in _ENCAP_VECTORS])
    def test_mlkem_encapsulate(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test ML-KEM encapsulation using ACVP vectors.

        Imports the public key from the vector and verifies that
        encapsulation produces a valid ciphertext and shared secret.
        """
        rs = p11_raw_session
        param_set = vec["param_set"]

        # Check for specific parameter-set mechanism
        mech_map = {
            "ML-KEM-512": "ML_KEM_512",
            "ML-KEM-768": "ML_KEM_768",
            "ML-KEM-1024": "ML_KEM_1024",
        }
        specific_mech = mech_map.get(param_set)
        if specific_mech and not rs.has_mechanism(specific_mech):
            pytest.skip(f"{specific_mech} mechanism not supported by module")

        pub_key = 0
        secret_handle = 0
        try:
            # Import the public key from the vector
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_KEM),
                value=vec["ek"],
                parameter_set=vec["parameter_set"],
                attrs={CKA_ENCRYPT: True},
            )

            # Get the mechanism for encapsulation
            mech = get_mlkem_mechanism(param_set)

            # Encapsulate to generate ciphertext and shared secret
            secret_handle, ciphertext = encapsulate_key(
                rs.raw, rs.sh, pub_key, mech, attrs={CKA_DERIVE: True}
            )

            assert secret_handle != 0, f"{vec_id}: Secret key handle is zero"
            assert ciphertext, f"{vec_id}: Ciphertext is empty"
            assert len(ciphertext) == len(vec["c"]), (
                f"{vec_id}: Ciphertext len mismatch: expected {len(vec['c'])}, "
                f"got {len(ciphertext)}"
            )

        except AssertionError as exc:
            _handle_unsupported(exc, param_set)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, secret_handle)


class TestMlKemDecapsulate:
    """ML-KEM decapsulation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _DECAP_VECTORS, ids=[v[0] for v in _DECAP_VECTORS])
    def test_mlkem_decapsulate(
        self, p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test ML-KEM decapsulation using ACVP vectors.

        Imports the private key from the vector and verifies that
        decapsulation recovers the expected shared secret.
        """
        rs = p11_raw_session
        param_set = vec["param_set"]

        # Check for specific parameter-set mechanism
        mech_map = {
            "ML-KEM-512": "ML_KEM_512",
            "ML-KEM-768": "ML_KEM_768",
            "ML-KEM-1024": "ML_KEM_1024",
        }
        specific_mech = mech_map.get(param_set)
        if specific_mech and not rs.has_mechanism(specific_mech):
            pytest.skip(f"{specific_mech} mechanism not supported by module")

        priv_key = 0
        decap_handle = 0
        try:
            # Import the private key from the vector
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_KEM),
                value=vec["dk"],
                parameter_set=vec["parameter_set"],
                attrs={CKA_DERIVE: True},
            )

            # Get the mechanism for decapsulation
            mech = get_mlkem_mechanism(param_set)

            # Decapsulate to recover shared secret
            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                vec["c"],
                attrs={CKA_DERIVE: True},
            )

            assert decap_handle != 0, f"{vec_id}: Decapsulated key handle is zero"

        except AssertionError as exc:
            _handle_unsupported(exc, param_set)
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)
            destroy_quietly(rs.raw, rs.sh, decap_handle)

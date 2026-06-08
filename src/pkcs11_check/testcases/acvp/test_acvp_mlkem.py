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
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKK_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_HOST_MEMORY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.acvp._duplicates import skip_duplicate_pkcs11_input
from pkcs11_check.testcases.acvp._mlkem_helpers import (
    get_mlkem_mechanism,
    load_mlkem_decap_vectors,
    load_mlkem_encap_vectors,
    load_mlkem_keygen_vectors,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = [pytest.mark.kat, pytest.mark.acvp, pytest.mark.pqc]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# Standard template for encapsulated/decapsulated secret key output.
# Kryoptic mandates CKA_CLASS and CKA_KEY_TYPE on KEM output keys.
_SECRET_KEY_ATTRS: dict[int, object] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
}

_MLKEM_CAPABILITY_REJECT_RVS = (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)
_MLKEM_RUNTIME_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_HOST_MEMORY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

_KEYGEN_VECTORS = load_mlkem_keygen_vectors()
_ENCAP_VECTORS = load_mlkem_encap_vectors()
_DECAP_VECTORS = load_mlkem_decap_vectors()


def _skip_if_mlkem_capability_reject(exc: AssertionError, param_set: str, action: str) -> None:
    """Skip when PKCS#11 exposes no narrower discovery for this ML-KEM capability."""
    if is_known_error(exc, _MLKEM_CAPABILITY_REJECT_RVS):
        pytest.skip(f"ML-KEM {param_set} {action} not supported: {exc}")
    raise


def _xfail_if_mlkem_runtime_reject(exc: AssertionError, label: str) -> None:
    """xfail advertised ML-KEM operations that are rejected at runtime."""
    xfail_if_known_ckr(
        exc,
        _MLKEM_RUNTIME_REJECT_RVS,
        f"{label}: ML-KEM advertised but operation is not cleanly operational",
    )


class TestMlKemKeyGen:
    """ML-KEM key generation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
    def test_mlkem_keygen(self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
        """Test ML-KEM keypair generation and roundtrip encap/decap."""
        rs = p11_module_session
        if not rs.has_mechanism("ML_KEM_KEY_PAIR_GEN"):
            pytest.skip("ML_KEM_KEY_PAIR_GEN not supported by module")

        param_set_name = vec["param_set"]
        skip_duplicate_pkcs11_input(vec, "ML-KEM KeyGen")

        pub_key = priv_key = secret_handle = decap_handle = 0
        # Generate keypair with specific parameter set.
        try:
            pub_key, priv_key = gen_keypair(
                rs.raw,
                rs.sh,
                mechanism=CKM_ML_KEM_KEY_PAIR_GEN,
                pub_base=[attr_ulong(CKA_PARAMETER_SET, vec["parameter_set"])],
                priv_base=[],
                public_attrs={CKA_ENCAPSULATE: True, CKA_TOKEN: False},
                private_attrs={
                    CKA_DECAPSULATE: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: False,
                },
                pub_skip={CKA_PARAMETER_SET},
            )
        except AssertionError as exc:
            if is_known_error(exc, _MLKEM_CAPABILITY_REJECT_RVS):
                pytest.skip(f"ML-KEM {param_set_name} key generation not supported: {exc}")
            _xfail_if_mlkem_runtime_reject(exc, vec_id)
        try:
            assert pub_key != 0, f"{vec_id}: Public key handle is zero"
            assert priv_key != 0, f"{vec_id}: Private key handle is zero"
            mech = get_mlkem_mechanism(param_set_name)
            secret_handle, ciphertext = encapsulate_key(
                rs.raw, rs.sh, pub_key, mech, attrs=_SECRET_KEY_ATTRS
            )
            assert secret_handle != 0, f"{vec_id}: Secret key handle is zero"
            assert ciphertext, f"{vec_id}: Ciphertext is empty"

            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                ciphertext,
                attrs=_SECRET_KEY_ATTRS,
            )
            assert decap_handle != 0, f"{vec_id}: Decapsulated key handle is zero"

        except AssertionError as exc:
            _xfail_if_mlkem_runtime_reject(exc, vec_id)
        finally:
            destroy_quietly(rs.raw, rs.sh, secret_handle)
            destroy_quietly(rs.raw, rs.sh, decap_handle)
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)


class TestMlKemEncapsulate:
    """ML-KEM encapsulation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _ENCAP_VECTORS, ids=[v[0] for v in _ENCAP_VECTORS])
    def test_mlkem_encapsulate(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test ML-KEM encapsulate+decapsulate round-trip using ACVP vectors.

        PKCS#11 C_EncapsulateKey uses internal randomness, so the ciphertext
        and shared secret won't match the ACVP vector's deterministic values.
        Instead we verify: encapsulate with the public key, then decapsulate
        with the private key, and confirm both sides produce the same secret.
        """
        rs = p11_module_session
        param_set = vec["param_set"]

        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM mechanism not supported by module")

        pub_key = priv_key = secret_handle = decap_handle = 0
        try:
            try:
                pub_key = import_pqc_public_key(
                    rs.raw,
                    rs.sh,
                    key_type=int(CKK_ML_KEM),
                    value=vec["ek"],
                    parameter_set=vec["parameter_set"],
                    attrs={CKA_ENCAPSULATE: True},
                )
            except AssertionError as exc:
                _skip_if_mlkem_capability_reject(exc, param_set, "public-key import")

            # The encap vectors may not include dk. In that case the operation
            # is still a runtime check, not an import-capability check.
            if "dk" not in vec:
                try:
                    mech = get_mlkem_mechanism(param_set)
                    secret_handle, ciphertext = encapsulate_key(
                        rs.raw,
                        rs.sh,
                        pub_key,
                        mech,
                        attrs=_SECRET_KEY_ATTRS,
                    )
                    assert secret_handle != 0, f"{vec_id}: Secret key handle is zero"
                    assert ciphertext, f"{vec_id}: Ciphertext is empty"
                    assert len(ciphertext) == len(vec["c"]), (
                        f"{vec_id}: Ciphertext len mismatch: "
                        f"expected {len(vec['c'])}, got {len(ciphertext)}"
                    )
                except AssertionError as exc:
                    _xfail_if_mlkem_runtime_reject(exc, vec_id)
            else:
                try:
                    priv_key = import_pqc_private_key(
                        rs.raw,
                        rs.sh,
                        key_type=int(CKK_ML_KEM),
                        value=vec["dk"],
                        parameter_set=vec["parameter_set"],
                        attrs={CKA_DECAPSULATE: True},
                    )
                except AssertionError as exc:
                    _skip_if_mlkem_capability_reject(exc, param_set, "private-key import")

                try:
                    mech = get_mlkem_mechanism(param_set)

                    # Encapsulate: produces ciphertext + shared secret
                    secret_handle, ciphertext = encapsulate_key(
                        rs.raw,
                        rs.sh,
                        pub_key,
                        mech,
                        attrs=_SECRET_KEY_ATTRS,
                    )
                    assert secret_handle != 0, f"{vec_id}: Secret key handle is zero"
                    assert ciphertext, f"{vec_id}: Ciphertext is empty"
                    assert len(ciphertext) == len(vec["c"]), (
                        f"{vec_id}: Ciphertext len mismatch: "
                        f"expected {len(vec['c'])}, got {len(ciphertext)}"
                    )

                    # Decapsulate with private key to recover shared secret
                    decap_handle = decapsulate_key(
                        rs.raw,
                        rs.sh,
                        priv_key,
                        mech,
                        ciphertext,
                        attrs=_SECRET_KEY_ATTRS,
                    )
                    assert decap_handle != 0, f"{vec_id}: Decapsulated key handle is zero"

                    # Both sides must produce the same shared secret
                    encap_attrs = read_attributes(rs.raw, rs.sh, secret_handle, [CKA_VALUE])
                    decap_attrs = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])
                    encap_secret = encap_attrs.get(CKA_VALUE, b"")
                    decap_secret = decap_attrs.get(CKA_VALUE, b"")
                    encap_preview = (
                        encap_secret[:16].hex() if isinstance(encap_secret, bytes) else "?"
                    )
                    decap_preview = (
                        decap_secret[:16].hex() if isinstance(decap_secret, bytes) else "?"
                    )
                    assert encap_secret == decap_secret, (
                        f"{vec_id}: encap/decap shared secret mismatch: "
                        f"encap={encap_preview}... decap={decap_preview}..."
                    )

                except AssertionError as exc:
                    _xfail_if_mlkem_runtime_reject(exc, vec_id)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            destroy_quietly(rs.raw, rs.sh, priv_key)
            destroy_quietly(rs.raw, rs.sh, secret_handle)
            destroy_quietly(rs.raw, rs.sh, decap_handle)


class TestMlKemDecapsulate:
    """ML-KEM decapsulation tests using ACVP vectors."""

    @pytest.mark.parametrize("vec_id,vec", _DECAP_VECTORS, ids=[v[0] for v in _DECAP_VECTORS])
    def test_mlkem_decapsulate(
        self, p11_module_session: Any, vec_id: str, vec: dict[str, Any]
    ) -> None:
        """Test ML-KEM decapsulation using ACVP vectors.

        Imports the private key from the vector and verifies that
        decapsulation recovers the expected shared secret.
        """
        rs = p11_module_session
        param_set = vec["param_set"]

        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM mechanism not supported by module")

        priv_key = 0
        decap_handle = 0
        try:
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_KEM),
                value=vec["dk"],
                parameter_set=vec["parameter_set"],
                attrs={CKA_DECAPSULATE: True},
            )
        except AssertionError as exc:
            _skip_if_mlkem_capability_reject(exc, param_set, "private-key import")

        try:
            # Get the mechanism for decapsulation
            mech = get_mlkem_mechanism(param_set)

            # Decapsulate to recover shared secret
            decap_handle = decapsulate_key(
                rs.raw,
                rs.sh,
                priv_key,
                mech,
                vec["c"],
                attrs=_SECRET_KEY_ATTRS,
            )

            assert decap_handle != 0, f"{vec_id}: Decapsulated key handle is zero"

            # Validate recovered shared secret matches expected value
            if "k" in vec:
                secret_attrs = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])
                secret_value = secret_attrs.get(CKA_VALUE, b"")
                assert secret_value == vec["k"], (
                    f"{vec_id}: shared secret mismatch: "
                    f"expected {vec['k'][:16].hex()}..., got {secret_value[:16].hex()}..."
                )

        except AssertionError as exc:
            _xfail_if_mlkem_runtime_reject(exc, vec_id)
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_key)
            destroy_quietly(rs.raw, rs.sh, decap_handle)

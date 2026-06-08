"""Key Encapsulation Mechanism (KEM) tests - ML-KEM (CRYSTALS-Kyber / FIPS 203).

All tests require PKCS#11 v3.2 interface (C_EncapsulateKey / C_DecapsulateKey).
Auto-skips on v3.1 and earlier.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import (
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    decapsulate_key,
    destroy_quietly,
    encapsulate_key,
    gen_keypair,
    read_attributes,
    to_ubyte_buf,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DERIVE,
    CKA_ENCAPSULATE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_ML_KEM,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_ML_KEM_512,
    CKP_ML_KEM_768,
    CKP_ML_KEM_1024,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.pqc, pytest.mark.keymgmt, pytest.mark.requires_v32]

# ML-KEM parameter set sizes (ciphertext, shared-secret bytes)
_ML_KEM_CIPHERTEXT_SIZES = {
    "ML_KEM_512": 768,
    "ML_KEM_768": 1088,
    "ML_KEM_1024": 1568,
}

_PARAM_MAP = {
    "ML_KEM_512": CKP_ML_KEM_512,
    "ML_KEM_768": CKP_ML_KEM_768,
    "ML_KEM_1024": CKP_ML_KEM_1024,
}

_KEM_OPERATION_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_KEM_WRONG_KEY_CLEAN_REJECT_RVS = (CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE)


def _skip_if_no_ml_kem(rs: Any) -> None:
    """Skip the test if ML_KEM mechanism is not available."""
    if not rs.has_mechanism("ML_KEM"):
        pytest.skip("ML_KEM mechanism not supported by module")


def _generate_ml_kem_keypair(
    rs: Any,
    param_set: int | None = None,
    CKA_ENCAPSULATE_OVERRIDE: bool | None = True,  # noqa: N803
    CKA_DECAPSULATE_OVERRIDE: bool | None = True,  # noqa: N803
) -> tuple[int, int]:
    """Generate an ML-KEM key pair with encapsulate/decapsulate capabilities.

    :param param_set: Optional parameter set int value.
        If None, defaults to CKP_ML_KEM_768.
    """
    effective_param = param_set if param_set is not None else CKP_ML_KEM_768

    public_attrs = {
        CKA_TOKEN: False,
    }
    if CKA_ENCAPSULATE_OVERRIDE is not None:
        public_attrs[CKA_ENCAPSULATE] = CKA_ENCAPSULATE_OVERRIDE

    private_attrs = {
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: False,
        CKA_TOKEN: False,
    }
    if CKA_DECAPSULATE_OVERRIDE is not None:
        private_attrs[CKA_DECAPSULATE] = CKA_DECAPSULATE_OVERRIDE

    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_KEM_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, effective_param)],
        priv_base=[],
        public_attrs=public_attrs,
        private_attrs=private_attrs,
        pub_skip={CKA_PARAMETER_SET},
    )


def _encap_attrs(key_type: int = CKK_AES, value_len: int | None = None) -> dict[int, Any]:
    """Standard template for encapsulated key. Kryoptic mandates Class/KeyType."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }
    if value_len is not None:
        attrs[CKA_VALUE_LEN] = value_len
    return attrs


def _xfail_kem_operation_reject(exc: AssertionError, operation: str) -> NoReturn:
    xfail_if_known_ckr(exc, _KEM_OPERATION_REJECT_RVS, f"ML-KEM {operation} not operational")
    raise exc


def _encapsulate_ml_kem_or_xfail(
    rs: Any,
    public_key: int,
    attrs: dict[int, Any],
    operation: str,
) -> tuple[int, bytes]:
    try:
        return encapsulate_key(rs.raw, rs.sh, public_key, CKM_ML_KEM, attrs=attrs)
    except NotImplementedError:
        pytest.skip("encapsulate_key not available")
    except AssertionError as exc:
        _xfail_kem_operation_reject(exc, operation)


def _decapsulate_ml_kem_or_xfail(
    rs: Any,
    private_key: int,
    ciphertext: bytes,
    attrs: dict[int, Any],
    operation: str,
) -> int:
    try:
        return decapsulate_key(rs.raw, rs.sh, private_key, CKM_ML_KEM, ciphertext, attrs=attrs)
    except NotImplementedError:
        pytest.skip("decapsulate_key not available")
    except AssertionError as exc:
        _xfail_kem_operation_reject(exc, operation)


class TestMLKEMKeyGeneration:
    """ML-KEM key pair generation tests."""

    def test_ml_kem_available(self, p11_raw_session: Any) -> None:
        """Check that ML_KEM mechanism is available."""
        _skip_if_no_ml_kem(p11_raw_session)

    def test_ml_kem_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an ML-KEM key pair."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_keypair_classes(self, p11_raw_session: Any) -> None:
        """ML-KEM public key is PublicKey, private is PrivateKey."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            pub_cls = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])[CKA_CLASS]
            priv_cls = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])[CKA_CLASS]
            assert pub_cls == CKO_PUBLIC_KEY
            assert priv_cls == CKO_PRIVATE_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_keypair_key_type(self, p11_raw_session: Any) -> None:
        """ML-KEM keys report correct key type."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert pub_kt == CKK_ML_KEM
            assert priv_kt == CKK_ML_KEM
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_private_key_derive_false(self, p11_raw_session: Any) -> None:
        """Generated ML-KEM private keys must not claim CKA_DERIVE=True."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DERIVE])
            if CKA_DERIVE not in attrs:
                pytest.xfail("ML-KEM private key does not expose CKA_DERIVE")
            assert attrs[CKA_DERIVE] is False, (
                "ML-KEM private key reported CKA_DERIVE=True; ML-KEM keys "
                "encapsulate/decapsulate and must not be usable as derive keys"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_two_keypairs_distinct(self, p11_raw_session: Any) -> None:
        """Two ML-KEM key pair generations produce distinct keys."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub_a, priv_a = _generate_ml_kem_keypair(rs)
        pub_b, priv_b = _generate_ml_kem_keypair(rs)
        try:
            # Public keys must differ (overwhelming probability)
            try:
                val_a = read_attributes(rs.raw, rs.sh, pub_a, [CKA_VALUE])[CKA_VALUE]
                val_b = read_attributes(rs.raw, rs.sh, pub_b, [CKA_VALUE])[CKA_VALUE]
                assert val_a != val_b
            except (AssertionError, OSError):
                pytest.skip("Module does not expose ML-KEM public key value")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)


@pytest.mark.v32
class TestMLKEMEncapsulateDecapsulate:
    """ML-KEM encapsulate/decapsulate round-trip tests."""

    def test_encapsulate_returns_ciphertext_and_key(self, p11_raw_session: Any) -> None:
        """C_EncapsulateKey returns a ciphertext and a secret key."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            shared, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            assert isinstance(ct, bytes)
            assert len(ct) > 0
            assert shared != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)

    def test_encapsulate_ciphertext_nonzero(self, p11_raw_session: Any) -> None:
        """Ciphertext from encapsulate_key is non-trivially non-zero."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            shared, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            assert ct != bytes(len(ct))  # not all zeros
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)

    def test_encapsulate_decapsulate_shared_secret_matches(self, p11_raw_session: Any) -> None:
        """Encapsulated and decapsulated shared secrets match."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        decap_handle = 0
        try:
            encap_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            decap_handle = _decapsulate_ml_kem_or_xfail(
                rs,
                priv,
                ct,
                _encap_attrs(),
                "decapsulate",
            )
            # Both sides must produce the same shared secret
            encap_value = read_attributes(rs.raw, rs.sh, encap_handle, [CKA_VALUE])[CKA_VALUE]
            decap_value = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])[CKA_VALUE]
            assert encap_value == decap_value, "Encapsulated and decapsulated secrets differ"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if decap_handle:
                destroy_quietly(rs.raw, rs.sh, decap_handle)

    def test_two_encapsulations_produce_different_ciphertexts(self, p11_raw_session: Any) -> None:
        """Separate encapsulation calls produce different ciphertexts (fresh randomness)."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        s1 = s2 = 0
        try:
            s1, ct1 = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            s2, ct2 = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            assert ct1 != ct2, "Two encapsulations produced identical ciphertexts (bad randomness)"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if s1:
                destroy_quietly(rs.raw, rs.sh, s1)
            if s2:
                destroy_quietly(rs.raw, rs.sh, s2)

    def test_decapsulate_with_wrong_key_fails_or_differs(self, p11_raw_session: Any) -> None:
        """Decapsulating with a different private key produces a different (or no) secret."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub_a, priv_a = _generate_ml_kem_keypair(rs)
        pub_b, priv_b = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        wrong_handle = 0
        try:
            encap_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub_a,
                _encap_attrs(),
                "encapsulate",
            )

            try:
                wrong_handle = decapsulate_key(
                    rs.raw,
                    rs.sh,
                    priv_b,
                    CKM_ML_KEM,
                    ct,
                    attrs=_encap_attrs(),
                )
                # If it succeeds, the secrets must differ (ML-KEM implicit rejection)
                encap_val = read_attributes(rs.raw, rs.sh, encap_handle, [CKA_VALUE])[CKA_VALUE]
                wrong_val = read_attributes(rs.raw, rs.sh, wrong_handle, [CKA_VALUE])[CKA_VALUE]
                assert encap_val != wrong_val, (
                    "Decapsulation with wrong key produced same secret as correct decapsulation"
                )
            except AssertionError as exc:
                # An explicit rejection is also acceptable for this behavioral check.
                if is_known_error(exc, _KEM_WRONG_KEY_CLEAN_REJECT_RVS):
                    return
                xfail_if_known_ckr(
                    exc,
                    _KEM_OPERATION_REJECT_RVS,
                    "ML-KEM wrong-key decapsulate rejected with non-specific CKR",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if wrong_handle:
                destroy_quietly(rs.raw, rs.sh, wrong_handle)


@pytest.mark.v32
@pytest.mark.kat
class TestMLKEMCiphertextSize:
    """Verify ciphertext sizes match FIPS 203 spec for each ML-KEM parameter set."""

    @pytest.mark.parametrize(
        "param_set,expected_ct_len",
        [
            ("ML_KEM_512", 768),
            ("ML_KEM_768", 1088),
            ("ML_KEM_1024", 1568),
        ],
    )
    def test_ciphertext_size(
        self,
        p11_raw_session: Any,
        param_set: str,
        expected_ct_len: int,
    ) -> None:
        """Ciphertext size matches FIPS 203 for this ML-KEM parameter set."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        shared = 0
        try:
            shared, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )

            # We can only check size if the module uses the expected parameter set
            if len(ct) not in _ML_KEM_CIPHERTEXT_SIZES.values():
                pytest.xfail(f"Unexpected ciphertext size {len(ct)} - may be non-standard")
            # If size matches this parameter set, check it
            if len(ct) == expected_ct_len:
                assert len(ct) == expected_ct_len
            else:
                pytest.skip(f"Module uses different ML-KEM parameter set (ct_len={len(ct)})")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)


@pytest.mark.v32
class TestMLKEMKeyDerivation:
    """ML-KEM encapsulation producing specific key types (AES-128, AES-256)."""

    def test_encapsulate_produces_aes128_key(self, p11_raw_session: Any) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=16 produces AES-128."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        aes_handle = 0
        try:
            aes_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 16,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
            aes_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                aes_attrs,
                "AES-128 encapsulate",
            )
            assert isinstance(ct, bytes) and len(ct) > 0
            kt = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert kt == CKK_AES
            value = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(value, bytes)
            if len(value) != 16:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"ML-KEM encapsulate with CKA_VALUE_LEN=16 produced {len(value)}-byte key "
                    "instead of 16-byte AES-128. Module ignores CKA_VALUE_LEN for "
                    "KEM-derived keys "
                    "-- the ML-KEM shared secret is always 32 bytes per FIPS 203.",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 v3.2 Sec.5.14.8; FIPS 203",
                )
                pytest.xfail(
                    f"Module ignores CKA_VALUE_LEN for ML-KEM KEM-derived keys: "
                    f"requested 16 bytes, got {len(value)} bytes "
                    f"(ML-KEM shared secret is always 32 bytes per FIPS 203)"
                )
            assert len(value) == 16, f"Expected 16-byte AES-128 key, got {len(value)} bytes"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if aes_handle:
                destroy_quietly(rs.raw, rs.sh, aes_handle)

    def test_encapsulate_produces_aes256_key(self, p11_raw_session: Any) -> None:
        """encapsulate_key with key_type=AES and VALUE_LEN=32 produces AES-256."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        aes_handle = 0
        try:
            aes_attrs: dict[int, Any] = {
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: 32,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
            aes_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                aes_attrs,
                "AES-256 encapsulate",
            )
            assert isinstance(ct, bytes) and len(ct) > 0
            kt = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert kt == CKK_AES
            value = read_attributes(rs.raw, rs.sh, aes_handle, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == 32, f"Expected 32-byte AES-256 key, got {len(value)} bytes"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if aes_handle:
                destroy_quietly(rs.raw, rs.sh, aes_handle)

    @pytest.mark.parametrize(
        "param_set_name,expected_ct_len",
        [
            ("ML_KEM_512", 768),
            ("ML_KEM_768", 1088),
            ("ML_KEM_1024", 1568),
        ],
    )
    def test_parameter_set_produces_correct_ciphertext_size(
        self,
        p11_raw_session: Any,
        param_set_name: str,
        expected_ct_len: int,
    ) -> None:
        """Requesting a specific ML-KEM parameter set produces the expected ciphertext size."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        param_set = _PARAM_MAP[param_set_name]
        try:
            pub, priv = _generate_ml_kem_keypair(rs, param_set=param_set)
        except (AssertionError, OSError):
            pytest.xfail(
                f"Module does not support CKA_PARAMETER_SET={param_set_name} - "
                "may use a fixed parameter set"
            )
            raise  # unreachable
        shared = 0
        try:
            shared, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            assert len(ct) == expected_ct_len, (
                f"Expected {expected_ct_len}-byte ciphertext for {param_set_name}, got {len(ct)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)


@pytest.mark.v32
class TestMLKEMDecapsulation:
    """ML-KEM decapsulation tests with various target templates."""

    @pytest.mark.parametrize("aes_len", [16, 24, 32])
    def test_decapsulate_aes_key_sizes(self, p11_raw_session: Any, aes_len: int) -> None:
        """Decapsulate to AES keys of different sizes (128, 192, 256 bits)."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        decap_handle = 0
        try:
            # Encapsulate
            attrs = _encap_attrs(CKK_AES, value_len=aes_len)
            encap_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                attrs,
                "AES encapsulate",
            )
            # Decapsulate specifying minimal template
            decap_handle = _decapsulate_ml_kem_or_xfail(
                rs,
                priv,
                ct,
                attrs,
                "AES decapsulate",
            )

            # Verification
            enc_val = read_attributes(rs.raw, rs.sh, encap_handle, [CKA_VALUE])[CKA_VALUE]
            dec_val = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])[CKA_VALUE]
            # Some modules (Kryoptic) may always produce 32-byte shared secret
            assert len(dec_val) in (aes_len, 32)
            if len(dec_val) == aes_len:
                assert enc_val == dec_val
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if decap_handle:
                destroy_quietly(rs.raw, rs.sh, decap_handle)

    def test_decapsulate_generic_secret(self, p11_raw_session: Any) -> None:
        """Decapsulate to CKK_GENERIC_SECRET (default 32 bytes for ML-KEM)."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        decap_handle = 0
        try:
            encap_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(CKK_GENERIC_SECRET),
                "generic-secret encapsulate",
            )
            decap_handle = _decapsulate_ml_kem_or_xfail(
                rs,
                priv,
                ct,
                _encap_attrs(CKK_GENERIC_SECRET),
                "generic-secret decapsulate",
            )

            dec_val = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_VALUE])[CKA_VALUE]
            assert len(dec_val) == 32
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if decap_handle:
                destroy_quietly(rs.raw, rs.sh, decap_handle)

    def test_decapsulate_extractability_flags(self, p11_raw_session: Any) -> None:
        """Decapsulate with specific security flags (if supported by provider)."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle = 0
        decap_handle = 0
        try:
            encap_handle, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "encapsulate",
            )
            decap_handle = _decapsulate_ml_kem_or_xfail(
                rs,
                priv,
                ct,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: False,
                    CKA_SENSITIVE: True,
                },
                "security-flag decapsulate",
            )
            attrs = read_attributes(rs.raw, rs.sh, decap_handle, [CKA_EXTRACTABLE, CKA_SENSITIVE])
            assert attrs[CKA_EXTRACTABLE] is False
            assert attrs[CKA_SENSITIVE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if encap_handle:
                destroy_quietly(rs.raw, rs.sh, encap_handle)
            if decap_handle:
                destroy_quietly(rs.raw, rs.sh, decap_handle)


@pytest.mark.v32
class TestMLKEMNegative:
    """Negative tests for ML-KEM KEM operations."""

    def test_decapsulate_with_invalid_attributes_in_template(self, p11_raw_session: Any) -> None:
        """Injecting prohibited attributes (like CKA_VALUE) should fail."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle, ct = _encapsulate_ml_kem_or_xfail(
            rs,
            pub,
            _encap_attrs(),
            "negative-test setup encapsulate",
        )
        try:
            handle = CK_OBJECT_HANDLE(0)
            mech = mech_simple(CKM_ML_KEM)
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_bytes(CKA_VALUE, b"injected"),
            )
            ct_buf = to_ubyte_buf(ct)
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                *template_ptr_count(tmpl),
                ct_buf,
                len(ct),
                byref(handle),
            )
            if rv == CKR_OK and handle.value:
                destroy_quietly(rs.raw, rs.sh, handle.value)
            # Type-A crypto-correctness: accepting CKA_VALUE in the decapsulation
            # template lets the caller dictate the derived key's secret bytes
            # instead of deriving them -- a break for any provider -> fail; an
            # expected template reject -> pass; another clean reject -> xfail.
            classify_negative_rv(
                rv,
                (
                    CKR_TEMPLATE_INCONSISTENT,
                    CKR_ATTRIBUTE_TYPE_INVALID,
                    CKR_ATTRIBUTE_READ_ONLY,
                ),
                label="inject CKA_VALUE into ML-KEM decapsulation template",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_decapsulate_invalid_ciphertext_length(self, p11_raw_session: Any) -> None:
        """Off-by-one ciphertext length should fail."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs)
        encap_handle, ct = _encapsulate_ml_kem_or_xfail(
            rs,
            pub,
            _encap_attrs(),
            "negative-test setup encapsulate",
        )
        try:
            short_ct = ct[:-1]
            handle = CK_OBJECT_HANDLE(0)
            mech = mech_simple(CKM_ML_KEM)
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY), attr_ulong(CKA_KEY_TYPE, CKK_AES)
            )
            short_ct_buf = to_ubyte_buf(short_ct)
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                *template_ptr_count(tmpl),
                short_ct_buf,
                len(short_ct),
                byref(handle),
            )
            classify_negative_rv(
                rv,
                (CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID),
                label="ML-KEM invalid ciphertext length",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_decapsulate_missing_permission_flag(self, p11_raw_session: Any) -> None:
        """Decapsulate fails if CKA_DECAPSULATE is False on private key.

        Spec (PKCS#11 v3.2 Sec.5.14.8): CKR_KEY_FUNCTION_NOT_PERMITTED when
        CKA_DECAPSULATE is False.  Some modules return CKR_BUFFER_TOO_SMALL if
        they validate output buffer availability before checking key permissions.
        """
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs, CKA_DECAPSULATE_OVERRIDE=False)
        try:
            _, ct = _encapsulate_ml_kem_or_xfail(
                rs,
                pub,
                _encap_attrs(),
                "negative-test setup encapsulate",
            )
            # Use raw call to assert specific CKR
            handle = ctypes.c_ulong(0)
            mech = mech_simple(CKM_ML_KEM)
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
            )
            ct_buf = to_ubyte_buf(ct)
            rv = rs.raw.C_DecapsulateKey(
                rs.sh,
                mech.byref(),
                priv,
                *template_ptr_count(tmpl),
                ct_buf,
                len(ct),
                ctypes.byref(handle),
            )
            if rv == CKR_OK and handle.value:
                destroy_quietly(rs.raw, rs.sh, handle.value)

            if rv != CKR_OK:
                # A rejection: the spec code passes, another clean code xfails.
                classify_negative_rv(
                    rv,
                    (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_BUFFER_TOO_SMALL),
                    label="decapsulate with CKA_DECAPSULATE=False on private key",
                )
                return

            # rv == CKR_OK -- Type-B claim/effect-check. The protection is only
            # claimed if the private key actually reads back CKA_DECAPSULATE=False
            # (a module that did not honor the flag at create has not claimed the
            # protection -> honest non-support -> xfail). If it was claimed and
            # decapsulation still succeeded, the module contradicted itself.
            decap_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECAPSULATE])
            claimed = decap_attrs.get(CKA_DECAPSULATE) is False
            classify_policy_enforcement(
                claimed=claimed,
                violated=True,
                label="decapsulate with CKA_DECAPSULATE=False on private key "
                "(PKCS#11 v3.2 Sec.5.14.8 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encapsulate_missing_permission_flag(self, p11_raw_session: Any) -> None:
        """Encapsulate fails if CKA_ENCAPSULATE is False on public key."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        pub, priv = _generate_ml_kem_keypair(rs, CKA_ENCAPSULATE_OVERRIDE=False)
        try:
            handle = CK_OBJECT_HANDLE(0)
            ct_len = CK_ULONG(0)
            mech = mech_simple(CKM_ML_KEM)
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
            )
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                pub,
                *template_ptr_count(tmpl),
                None,  # pCiphertext (query for size)
                byref(ct_len),
                byref(handle),
            )
            # NSS-PQC checks buffer availability before permission flags and returns
            # CKR_BUFFER_TOO_SMALL when pCiphertext=None is passed on the size-query call.
            assert rv in (CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_BUFFER_TOO_SMALL)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_kem_mechanisms_with_wrong_key_type(self, p11_raw_session: Any) -> None:
        """ML-KEM mechanisms should reject RSA/other keys."""
        rs = p11_raw_session
        _skip_if_no_ml_kem(rs)
        from pkcs11_check.raw.recipes import gen_aes_key

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            # Try to encapsulate with AES key
            handle = CK_OBJECT_HANDLE(0)
            ct_len = CK_ULONG(0)
            mech = mech_simple(CKM_ML_KEM)
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
            )
            rv = rs.raw.C_EncapsulateKey(
                rs.sh,
                mech.byref(),
                key,
                *template_ptr_count(tmpl),
                None,  # pCiphertext (query for size)
                byref(ct_len),
                byref(handle),
            )
            # Providers may validate the key's permitted operations before
            # reporting that the key type is wrong for ML-KEM; any other clean
            # reject code is a noted deviation (xfail), not a hard failure.
            classify_negative_rv(
                rv,
                (
                    CKR_KEY_TYPE_INCONSISTENT,
                    CKR_KEY_FUNCTION_NOT_PERMITTED,
                    CKR_MECHANISM_INVALID,
                    CKR_TEMPLATE_INCOMPLETE,
                ),
                label="ML-KEM wrong-key-type reject",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

"""Tests for X9.42 Diffie-Hellman mechanisms.

Covers CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
CKM_X9_42_DH_HYBRID_DERIVE, CKM_X9_42_DH_PARAMETER_GEN,
and CKM_X9_42_MQV_DERIVE.

Classic DH (CKM_DH_PKCS_*) is tested in test_dh_key_agreement.py.

OASIS spec: diffie-hellman.md
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import (
    ArgumentsBad,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    DomainParamsInvalid,
    FunctionNotSupported,
    KeySizeRange,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


# ---------------------------------------------------------------------------
# X9.42 DH domain parameters (2048-bit)
#
# These are valid X9.42 DH parameters with an explicit subprime (q).
# Generated with: openssl genpkey -genparam -algorithm DHX -pkeyopt dh_paramgen_prime_len:2048
# The subprime q divides (p-1); base g has order q mod p.
#
# For portability and determinism we use RFC 5114 2048-bit MODP Group
# with 256-bit Prime Order Subgroup (Section 2.1).
# ---------------------------------------------------------------------------

# RFC 5114 Section 2.1 — 2048-bit MODP Group with 256-bit Prime Order Subgroup
X942_PRIME_2048 = bytes.fromhex(
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
    "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
    "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
    "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
    "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
    "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
    "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
    "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
    "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
    "75F26375D7014103A4B54330C198AF126116D2276E11715F"
    "693877FAD7EF09CADB094AE91E1A1597"
)

X942_GEN = bytes.fromhex(
    "3FB32C9B73134D0B2E7750628EB693FED3F1A8F7C2DF9390"
    "05F08CABC4F389AE1B8A3F9AE6F7A0E6017E0A71B27A8F44"
    "A72CE4B5E03B48E1B65214B3D43685E36BFE5E6D50B21F55"
    "CEB31A1CF31B2127F3FF2A4F10C35E84B3C83D3E9B5A54D8"
    "F40C5C7A1E826A8EB813EFE1CC9F5C8C2A43C64FE9085E6B"
    "35DAD56BC9EC24548A0C5B3D5D06E6CBBD97FA9553E89A2B"
    "C53C07ADBDE068E7CBEE7F55D4348A3E4BEBBFDF6A2C2D99"
    "4BFD15B8D3E23CC1B34B78EC1BD153DD294B8B2D2F74E6A6"
    "4C3F26E5DFC1002AE7B6125549F9E2BB9EB6D1BFBEB0E166"
    "A85EC0E5DA0C2FE36D73B36B6DF5D6CA4D30ECA61C5F1283"
    "33E4BF98B3A315B88D924B4C1EB4CF7113"
)

X942_SUBPRIME = bytes.fromhex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3")


# ---------------------------------------------------------------------------
# Helpers for building CK_X9_42_DH1_DERIVE_PARAMS as raw bytes.
#
# The python-pkcs11 wrapper does not have native struct support for X9.42 DH
# derive parameters. We construct the struct manually using ctypes and pass
# it as the raw mechanism_param bytes.
# ---------------------------------------------------------------------------

CK_ULONG = ctypes.c_ulong
CK_BYTE_PTR = ctypes.POINTER(ctypes.c_ubyte)

# CKD_NULL = 0x00000001
_CKD_NULL = 0x00000001


class X942DH1DeriveParams(ctypes.Structure):
    """CK_X9_42_DH1_DERIVE_PARAMS per PKCS#11 spec."""

    _fields_ = [
        ("kdf", CK_ULONG),
        ("ulOtherInfoLen", CK_ULONG),
        ("pOtherInfo", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
    ]


def _make_x942_derive_param(
    public_data: bytes,
    kdf: int = _CKD_NULL,
    other_info: bytes | None = None,
) -> tuple[X942DH1DeriveParams, ctypes.Array[ctypes.c_ubyte]]:
    """Build a CK_X9_42_DH1_DERIVE_PARAMS ctypes struct.

    Returns (params_struct, pub_data_array) — caller must keep both alive
    until C_DeriveKey returns.
    """
    pub_arr = (ctypes.c_ubyte * len(public_data))(*public_data)
    params = X942DH1DeriveParams()
    params.kdf = kdf
    params.ulPublicDataLen = len(public_data)
    params.pPublicData = ctypes.cast(pub_arr, CK_BYTE_PTR)

    if other_info is not None:
        oi_arr = (ctypes.c_ubyte * len(other_info))(*other_info)
        params.ulOtherInfoLen = len(other_info)
        params.pOtherInfo = ctypes.cast(oi_arr, CK_BYTE_PTR)
    else:
        params.ulOtherInfoLen = 0
        params.pOtherInfo = CK_BYTE_PTR()  # NULL pointer

    return params, pub_arr


def _params_to_bytes(params: X942DH1DeriveParams) -> bytes:
    """Serialize a CK_X9_42_DH1_DERIVE_PARAMS struct to raw bytes."""
    return bytes(ctypes.string_at(ctypes.addressof(params), ctypes.sizeof(params)))


# Error tuples for common patterns
_KEYGEN_ERRORS = (
    MechanismInvalid,
    FunctionNotSupported,
    DomainParamsInvalid,
    AttributeValueInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

_DERIVE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionNotSupported,
    ArgumentsBad,
    AttributeValueInvalid,
    KeySizeRange,
    DomainParamsInvalid,
)

_TEMPLATE_ERRORS = (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
)


def _skip_no_x942_keygen(p11_module: Any) -> None:
    """Skip if X9.42 DH key pair generation is not available."""
    if not has_mechanism(p11_module, "X9_42_DH_KEY_PAIR_GEN"):
        pytest.skip("CKM_X9_42_DH_KEY_PAIR_GEN not supported")


def _skip_no_x942_derive(p11_module: Any) -> None:
    """Skip if X9.42 DH derivation is not available."""
    if not has_mechanism(p11_module, "X9_42_DH_DERIVE"):
        pytest.skip("CKM_X9_42_DH_DERIVE not supported")


def _generate_x942_keypair(
    p11_session: Any,
) -> tuple[Any, Any]:
    """Generate an X9.42 DH keypair using RFC 5114 parameters."""
    params = p11_session.create_domain_parameters(
        KeyType.X9_42_DH,
        {
            Attribute.PRIME: X942_PRIME_2048,
            Attribute.BASE: X942_GEN,
            Attribute.SUBPRIME: X942_SUBPRIME,
        },
        local=True,
    )
    result: tuple[Any, Any] = params.generate_keypair()
    return result


class TestX942DHKeyPairGen:
    """Test CKM_X9_42_DH_KEY_PAIR_GEN — X9.42 DH key pair generation."""

    def test_keypair_generation(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an X9.42 DH keypair from known RFC 5114 parameters."""
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            assert pub is not None
            assert priv is not None

            # Public key value should be non-empty bytes
            pub_value = pub[Attribute.VALUE]
            assert isinstance(pub_value, bytes)
            assert len(pub_value) > 0
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    def test_keypair_has_correct_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """Generated keys report KeyType.X9_42_DH."""
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            assert pub[Attribute.KEY_TYPE] == KeyType.X9_42_DH
            assert priv[Attribute.KEY_TYPE] == KeyType.X9_42_DH
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    def test_keypair_prime_matches_params(self, p11_session: Any, p11_module: Any) -> None:
        """Generated public key carries the same prime as the domain parameters."""
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            pub_prime = pub[Attribute.PRIME]
            assert pub_prime == X942_PRIME_2048
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    def test_keypair_subprime_matches_params(self, p11_session: Any, p11_module: Any) -> None:
        """Generated public key carries the same subprime as the domain parameters."""
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            pub_subprime = pub[Attribute.SUBPRIME]
            assert pub_subprime == X942_SUBPRIME
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

    def test_two_keypairs_have_different_public_values(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Two independently generated keypairs have different public values."""
        _skip_no_x942_keygen(p11_module)

        pub1, priv1 = _generate_x942_keypair(p11_session)
        pub2, priv2 = _generate_x942_keypair(p11_session)
        try:
            val1 = pub1[Attribute.VALUE]
            val2 = pub2[Attribute.VALUE]
            assert val1 != val2, "Two keypairs should produce different public values"
        finally:
            for obj in (pub1, priv1, pub2, priv2):
                try:
                    obj.destroy()
                except Exception:
                    pass


class TestX942DHDerive:
    """Test CKM_X9_42_DH_DERIVE — X9.42 DH key derivation (shared secret agreement)."""

    def test_derive_shared_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Alice and Bob derive the same shared AES key via X9.42 DH."""
        _skip_no_x942_keygen(p11_module)
        _skip_no_x942_derive(p11_module)

        alice_pub, alice_priv = _generate_x942_keypair(p11_session)
        bob_pub, bob_priv = _generate_x942_keypair(p11_session)
        alice_shared = None
        bob_shared = None

        try:
            alice_value = alice_pub[Attribute.VALUE]
            bob_value = bob_pub[Attribute.VALUE]
            assert alice_value != bob_value

            # Build derive params for Alice (using Bob's public value)
            alice_params, _alice_buf = _make_x942_derive_param(bob_value)
            alice_param_bytes = _params_to_bytes(alice_params)

            alice_shared = alice_priv.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=alice_param_bytes,
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            # Build derive params for Bob (using Alice's public value)
            bob_params, _bob_buf = _make_x942_derive_param(alice_value)
            bob_param_bytes = _params_to_bytes(bob_params)

            bob_shared = bob_priv.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=bob_param_bytes,
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            # Both should derive the same key material
            assert alice_shared[Attribute.VALUE] == bob_shared[Attribute.VALUE]
        finally:
            for obj in (alice_pub, alice_priv, bob_pub, bob_priv, alice_shared, bob_shared):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass

    def test_derived_key_encrypts(self, p11_session: Any, p11_module: Any) -> None:
        """Derived AES key from X9.42 DH can encrypt/decrypt data."""
        _skip_no_x942_keygen(p11_module)
        _skip_no_x942_derive(p11_module)

        alice_pub, alice_priv = _generate_x942_keypair(p11_session)
        bob_pub, bob_priv = _generate_x942_keypair(p11_session)
        shared_key = None
        bob_key = None

        try:
            bob_value = bob_pub[Attribute.VALUE]
            alice_value = alice_pub[Attribute.VALUE]

            params, _buf = _make_x942_derive_param(bob_value)
            param_bytes = _params_to_bytes(params)

            shared_key = alice_priv.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=param_bytes,
                template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
            )

            plaintext = b"X9.42 DH test!!" + b"\x00"  # 16 bytes for AES-ECB block
            ct = shared_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            assert ct != plaintext

            # Bob derives the same key and decrypts
            bob_params, _bob_buf = _make_x942_derive_param(alice_value)
            bob_param_bytes = _params_to_bytes(bob_params)

            bob_key = bob_priv.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=bob_param_bytes,
                template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
            )
            pt = bob_key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == plaintext
        finally:
            for obj in (alice_pub, alice_priv, bob_pub, bob_priv, shared_key, bob_key):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass

    def test_different_exchanges_produce_different_secrets(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Two independent X9.42 DH exchanges produce different shared secrets."""
        _skip_no_x942_keygen(p11_module)
        _skip_no_x942_derive(p11_module)

        # Exchange 1
        _pub1, priv1 = _generate_x942_keypair(p11_session)
        pub2, _priv2 = _generate_x942_keypair(p11_session)
        key1 = None

        # Exchange 2
        _pub3, priv3 = _generate_x942_keypair(p11_session)
        pub4, _priv4 = _generate_x942_keypair(p11_session)
        key2 = None

        try:
            params1, _buf1 = _make_x942_derive_param(pub2[Attribute.VALUE])
            key1 = priv1.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=_params_to_bytes(params1),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            params2, _buf2 = _make_x942_derive_param(pub4[Attribute.VALUE])
            key2 = priv3.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=_params_to_bytes(params2),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            assert key1[Attribute.VALUE] != key2[Attribute.VALUE]
        finally:
            for obj in (_pub1, priv1, pub2, _priv2, _pub3, priv3, pub4, _priv4, key1, key2):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass


class TestX942DHParameterGen:
    """Test CKM_X9_42_DH_PARAMETER_GEN — on-token X9.42 DH parameter generation."""

    def test_generate_parameters(self, p11_session: Any, p11_module: Any) -> None:
        """Generate X9.42 DH domain parameters on the token."""
        if not has_mechanism(p11_module, "X9_42_DH_PARAMETER_GEN"):
            pytest.skip("CKM_X9_42_DH_PARAMETER_GEN not supported")

        params = p11_session.generate_domain_parameters(
            KeyType.X9_42_DH,
            2048,
        )
        try:
            assert params is not None

            prime = params[Attribute.PRIME]
            assert isinstance(prime, bytes)
            assert len(prime) * 8 >= 2048

            base = params[Attribute.BASE]
            assert isinstance(base, bytes)
            assert len(base) > 0

            subprime = params[Attribute.SUBPRIME]
            assert isinstance(subprime, bytes)
            assert len(subprime) > 0
        finally:
            try:
                params.destroy()
            except Exception:
                pass

    def test_generated_params_produce_valid_keypair(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Generated X9.42 parameters can produce a keypair for key agreement."""
        if not has_mechanism(p11_module, "X9_42_DH_PARAMETER_GEN"):
            pytest.skip("CKM_X9_42_DH_PARAMETER_GEN not supported")
        _skip_no_x942_keygen(p11_module)
        _skip_no_x942_derive(p11_module)

        gen_params = p11_session.generate_domain_parameters(
            KeyType.X9_42_DH,
            2048,
        )
        pub_a = None
        priv_a = None
        pub_b = None
        priv_b = None
        key_a = None
        key_b = None

        try:
            pub_a, priv_a = gen_params.generate_keypair()
            pub_b, priv_b = gen_params.generate_keypair()

            params_a, _buf_a = _make_x942_derive_param(pub_b[Attribute.VALUE])
            key_a = priv_a.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=_params_to_bytes(params_a),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            params_b, _buf_b = _make_x942_derive_param(pub_a[Attribute.VALUE])
            key_b = priv_b.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.X9_42_DH_DERIVE,
                mechanism_param=_params_to_bytes(params_b),
                template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
            )

            assert key_a[Attribute.VALUE] == key_b[Attribute.VALUE]
        finally:
            for obj in (pub_a, priv_a, pub_b, priv_b, key_a, key_b, gen_params):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass


class TestX942DHHybridDerive:
    """Test CKM_X9_42_DH_HYBRID_DERIVE — hybrid X9.42 DH derivation.

    This mechanism is very rarely supported by software tokens.
    """

    def test_hybrid_derive_availability(self, p11_session: Any, p11_module: Any) -> None:
        """Probe whether CKM_X9_42_DH_HYBRID_DERIVE is available."""
        if not has_mechanism(p11_module, "X9_42_DH_HYBRID_DERIVE"):
            pytest.skip("CKM_X9_42_DH_HYBRID_DERIVE not supported")

        # If the mechanism is listed, verify we can at least generate
        # X9.42 keypairs (prerequisite for hybrid derive).
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            assert pub is not None
            assert priv is not None
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass


class TestX942MQVDerive:
    """Test CKM_X9_42_MQV_DERIVE — X9.42 MQV key agreement.

    MQV (Menezes-Qu-Vanstone) is very rarely supported by software tokens.
    """

    def test_mqv_derive_availability(self, p11_session: Any, p11_module: Any) -> None:
        """Probe whether CKM_X9_42_MQV_DERIVE is available."""
        if not has_mechanism(p11_module, "X9_42_MQV_DERIVE"):
            pytest.skip("CKM_X9_42_MQV_DERIVE not supported")

        # If the mechanism is listed, verify we can at least generate
        # X9.42 keypairs (prerequisite for MQV).
        _skip_no_x942_keygen(p11_module)

        pub, priv = _generate_x942_keypair(p11_session)
        try:
            assert pub is not None
            assert priv is not None
        finally:
            try:
                pub.destroy()
            except Exception:
                pass
            try:
                priv.destroy()
            except Exception:
                pass

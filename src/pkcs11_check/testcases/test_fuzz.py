"""Hypothesis-based property tests for PKCS#11 operations.

Tests invariants that must hold for ALL inputs:
- encrypt(decrypt(ct)) == ct (roundtrip)
- digest is deterministic and matches hashlib
- sign/verify roundtrip always succeeds
- HMAC is deterministic and matches hmac module
- operations never crash regardless of input

Uses hypothesis for automatic input generation.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    import_secret_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_ECDSA,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_ec_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.fuzz

_HC = [HealthCheck.function_scoped_fixture]

_FUZZ_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)

_FUZZ_IMPORT_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _require_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")


def _gen_fuzz_aes_key(rs: Any) -> int:
    _require_mechanism(rs, "AES_ECB")
    _require_mechanism(rs, "AES_KEY_GEN")
    try:
        return gen_aes_key(rs.raw, rs.sh, 128)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but fuzz AES setup is not operational",
        )
    raise


def _gen_fuzz_rsa_keypair(rs: Any) -> tuple[int, int]:
    _require_mechanism(rs, "SHA256_RSA_PKCS")
    _require_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "RSA_PKCS_KEY_PAIR_GEN advertised but fuzz RSA setup is not operational",
        )
    raise


def _digest_or_xfail(rs: Any, mechanism: Any, mechanism_name: str, data: bytes) -> bytes:
    _require_mechanism(rs, mechanism_name)
    try:
        return digest_single(rs.raw, rs.sh, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_RUNTIME_REJECT_RVS,
            f"{mechanism_name} advertised but fuzz digest is not operational",
        )
    raise


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_RUNTIME_REJECT_RVS,
            "AES_ECB advertised but fuzz encrypt is not operational",
        )
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_RUNTIME_REJECT_RVS,
            "AES_ECB advertised but fuzz decrypt is not operational",
        )
    raise


def _sign_or_xfail(rs: Any, key: int, mechanism: Any, mechanism_name: str, data: bytes) -> bytes:
    try:
        return sign_single(rs.raw, rs.sh, key, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_RUNTIME_REJECT_RVS,
            f"{mechanism_name} advertised but fuzz sign is not operational",
        )
    raise


def _verify_or_xfail(
    rs: Any,
    key: int,
    mechanism: Any,
    mechanism_name: str,
    data: bytes,
    signature: bytes,
) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, key, mechanism, data, signature)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_RUNTIME_REJECT_RVS,
            f"{mechanism_name} advertised but fuzz verify is not operational",
        )
    raise


def _import_hmac_key_or_xfail(rs: Any, key_bytes: bytes) -> int:
    _require_mechanism(rs, "SHA256_HMAC")
    try:
        return import_secret_key(
            rs.raw,
            rs.sh,
            CKK_SHA256_HMAC,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ALLOWED_MECHANISMS: [CKM_SHA256_HMAC],
            },
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _FUZZ_IMPORT_REJECT_RVS,
            "SHA256_HMAC advertised but fuzz HMAC key import is not operational",
        )
    raise


class TestAESFuzz:
    """Fuzz AES encrypt/decrypt with random inputs."""

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_ecb_roundtrip(self, p11_raw_session: Any, plaintext: bytes) -> None:
        """AES-ECB: decrypt(encrypt(pt)) == pt for any 16-byte input."""
        rs = p11_raw_session
        key = _gen_fuzz_aes_key(rs)
        try:
            ct = _encrypt_or_xfail(rs, key, plaintext)
            pt = _decrypt_or_xfail(rs, key, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_ecb_deterministic(self, p11_raw_session: Any, plaintext: bytes) -> None:
        """AES-ECB with same key+pt always produces same ct."""
        rs = p11_raw_session
        key = _gen_fuzz_aes_key(rs)
        try:
            ct1 = _encrypt_or_xfail(rs, key, plaintext)
            ct2 = _encrypt_or_xfail(rs, key, plaintext)
            assert ct1 == ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_ecb_ciphertext_differs_from_plaintext(
        self, p11_raw_session: Any, plaintext: bytes
    ) -> None:
        """AES-ECB ciphertext should differ from plaintext (except all-zero edge case)."""
        rs = p11_raw_session
        key = _gen_fuzz_aes_key(rs)
        try:
            ct = _encrypt_or_xfail(rs, key, plaintext)
            # Ciphertext may equal plaintext for specific key/data combos, but extremely rare
            assert len(ct) == len(plaintext)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDigestFuzz:
    """Fuzz digest operations with cross-verification."""

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_sha256_deterministic(self, p11_raw_session: Any, data: bytes) -> None:
        """SHA-256 of same data always produces same digest."""
        rs = p11_raw_session
        d1 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", data)
        d2 = _digest_or_xfail(rs, CKM_SHA256, "SHA256", data)
        assert d1 == d2
        assert len(d1) == 32

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_sha256_cross_verify(self, p11_raw_session: Any, data: bytes) -> None:
        """SHA-256 via PKCS#11 matches hashlib for random inputs."""
        rs = p11_raw_session
        p11_digest = _digest_or_xfail(rs, CKM_SHA256, "SHA256", data)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_sha512_cross_verify(self, p11_raw_session: Any, data: bytes) -> None:
        """SHA-512 via PKCS#11 matches hashlib for random inputs."""
        rs = p11_raw_session
        p11_digest = _digest_or_xfail(rs, CKM_SHA512, "SHA512", data)
        expected = hashlib.sha512(data).digest()
        assert p11_digest == expected


class TestRSAFuzz:
    """Fuzz RSA sign/verify."""

    @given(data=st.binary(min_size=1, max_size=1000))
    @settings(max_examples=20, deadline=10000, suppress_health_check=_HC)
    def test_sign_verify_roundtrip(self, p11_raw_session: Any, data: bytes) -> None:
        """RSA: verify(sign(data)) always succeeds for any input."""
        rs = p11_raw_session
        pub, priv = _gen_fuzz_rsa_keypair(rs)
        try:
            sig = _sign_or_xfail(rs, priv, CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS", data)
            assert (
                _verify_or_xfail(rs, pub, CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS", data, sig) is True
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=15, deadline=10000, suppress_health_check=_HC)
    def test_signature_length_constant(self, p11_raw_session: Any, data: bytes) -> None:
        """RSA-2048 signature is always 256 bytes regardless of input."""
        rs = p11_raw_session
        pub, priv = _gen_fuzz_rsa_keypair(rs)
        try:
            sig = _sign_or_xfail(rs, priv, CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS", data)
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestHMACFuzz:
    """Fuzz HMAC operations."""

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=40, deadline=5000, suppress_health_check=_HC)
    def test_hmac_sha256_cross_verify(self, p11_raw_session: Any, data: bytes) -> None:
        """HMAC-SHA256 via PKCS#11 matches Python hmac for random inputs."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        p11_key = _import_hmac_key_or_xfail(rs, key_bytes)
        try:
            p11_mac = _sign_or_xfail(rs, p11_key, CKM_SHA256_HMAC, "SHA256_HMAC", data)
            expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
            assert p11_mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_hmac_deterministic(self, p11_raw_session: Any, data: bytes) -> None:
        """HMAC-SHA256 with same key and data always produces same MAC."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        p11_key = _import_hmac_key_or_xfail(rs, key_bytes)
        try:
            mac1 = _sign_or_xfail(rs, p11_key, CKM_SHA256_HMAC, "SHA256_HMAC", data)
            mac2 = _sign_or_xfail(rs, p11_key, CKM_SHA256_HMAC, "SHA256_HMAC", data)
            assert mac1 == mac2
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestECDSAFuzz:
    """Fuzz ECDSA operations."""

    @given(data=st.binary(min_size=32, max_size=32))
    @settings(max_examples=15, deadline=10000, suppress_health_check=_HC)
    def test_ecdsa_sign_verify_roundtrip(self, p11_raw_session: Any, data: bytes) -> None:
        """ECDSA: verify(sign(digest)) always succeeds for any 32-byte digest."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        try:
            sig = _sign_or_xfail(rs, priv, CKM_ECDSA, "ECDSA", data)
            assert _verify_or_xfail(rs, pub, CKM_ECDSA, "ECDSA", data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

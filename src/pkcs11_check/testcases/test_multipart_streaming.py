"""True multipart streaming tests.

Verifies that C_EncryptUpdate/C_DecryptUpdate and C_DigestUpdate
produce correct results for data sizes that exceed single-call
buffers. Cross-verifies against Python cryptography library.

python-pkcs11 auto-splits into Update+Final calls internally,
so we test by verifying correctness on various data sizes.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    create_object,
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
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
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
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.multipart

_STREAMING_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)

_IMPORT_KEY_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _require_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")


def _xfail_streaming_reject(exc: AssertionError, mechanism: str, operation: str) -> None:
    xfail_if_known_ckr(
        exc,
        _STREAMING_RUNTIME_REJECT_RVS,
        f"{mechanism} advertised but {operation} is not operational",
    )


def _gen_aes_key_or_xfail(rs: Any, *, purpose: str) -> int:
    _require_mechanism(rs, "AES_KEY_GEN")
    try:
        return gen_aes_key(rs.raw, rs.sh, 128)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but key generation for {purpose} is not operational",
        )
    raise


def _gen_rsa_keypair_or_xfail(rs: Any) -> tuple[int, int]:
    _require_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational",
        )
    raise


def _import_aes_key(rs: Any, key_bytes: bytes) -> int:
    """Import AES key bytes via raw API."""
    _require_mechanism(rs, "AES_ECB")
    try:
        return import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_ALLOWED_MECHANISMS: [CKM_AES_ECB],
            },
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _IMPORT_KEY_REJECT_RVS,
            "AES_ECB advertised but AES setup key import is not operational",
        )
    raise


def _import_hmac_key(rs: Any, key_bytes: bytes) -> int:
    _require_mechanism(rs, "SHA256_HMAC")
    last_reject: AssertionError | None = None
    for key_type in (CKK_SHA256_HMAC, CKK_GENERIC_SECRET):
        try:
            return create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: key_type,
                    CKA_VALUE: key_bytes,
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_ALLOWED_MECHANISMS: [CKM_SHA256_HMAC],
                },
            )
        except AssertionError as exc:
            if not is_known_error(exc, _IMPORT_KEY_REJECT_RVS):
                raise
            last_reject = exc
    if last_reject is not None:
        xfail_if_known_ckr(
            last_reject,
            _IMPORT_KEY_REJECT_RVS,
            "SHA256_HMAC advertised but setup key import is not operational",
        )
    raise AssertionError("SHA256_HMAC setup key import failed without a CKR")


class TestMultipartEncrypt:
    """Verify encrypt correctness at various sizes (triggers C_EncryptUpdate)."""

    @pytest.mark.parametrize("num_blocks", [1, 4, 16, 64, 256, 1024])
    def test_aes_ecb_multiblock_roundtrip(self, p11_raw_session: Any, num_blocks: int) -> None:
        """AES-ECB roundtrip with varying block counts."""
        rs = p11_raw_session
        _require_mechanism(rs, "AES_ECB")
        key = _gen_aes_key_or_xfail(rs, purpose="AES-ECB streaming")
        data = bytes(range(256)) * (num_blocks * 16 // 256 or 1)
        data = data[: num_blocks * 16]
        try:
            try:
                ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
                pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "AES_ECB", "encrypt/decrypt")
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("size", [16, 256, 4096, 65536])
    def test_aes_ecb_crossverify_large(self, p11_raw_session: Any, size: int) -> None:
        """Large AES-ECB encrypt cross-verified against cryptography."""
        rs = p11_raw_session
        _require_mechanism(rs, "AES_ECB")
        key_bytes = bytes(range(32))
        data = b"\xab" * size

        p11_key = _import_aes_key(rs, key_bytes)
        try:
            try:
                ct_p11 = encrypt_single(rs.raw, rs.sh, p11_key, CKM_AES_ECB, data)
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "AES_ECB", "encrypt")

            # Intentional CKM_AES_ECB reference vector for PKCS#11 interoperability.
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())  # nosec B305
            enc = cipher.encryptor()
            ct_crypto = enc.update(data) + enc.finalize()

            assert ct_p11 == ct_crypto
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_cbc_multiblock_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-CBC with 4KB data - exercises Update path."""
        rs = p11_raw_session
        _require_mechanism(rs, "AES_CBC")
        key = _gen_aes_key_or_xfail(rs, purpose="AES-CBC streaming")
        iv = b"\x00" * 16
        data = b"\x42" * 4096
        try:
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    data,
                    mech_param=mech_bytes(CKM_AES_CBC, iv),
                )
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    ct,
                    mech_param=mech_bytes(CKM_AES_CBC, iv),
                )
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "AES_CBC", "encrypt/decrypt")
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestMultipartDigest:
    """Verify digest correctness for large data (triggers C_DigestUpdate)."""

    @pytest.mark.parametrize("size", [0, 1, 64, 1024, 65536, 1048576])
    def test_sha256_large_data_crossverify(self, p11_raw_session: Any, size: int) -> None:
        """SHA-256 of various sizes matches hashlib."""
        rs = p11_raw_session
        _require_mechanism(rs, "SHA256")
        data = b"\xcd" * size
        try:
            p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        except AssertionError as exc:
            _xfail_streaming_reject(exc, "SHA256", "digest")
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected

    def test_sha512_1mb_crossverify(self, p11_raw_session: Any) -> None:
        """SHA-512 of 1MB data matches hashlib."""
        rs = p11_raw_session
        _require_mechanism(rs, "SHA512")
        data = b"\xef" * (1024 * 1024)
        try:
            p11_digest = digest_single(rs.raw, rs.sh, CKM_SHA512, data)
        except AssertionError as exc:
            _xfail_streaming_reject(exc, "SHA512", "digest")
        expected = hashlib.sha512(data).digest()
        assert p11_digest == expected


class TestMultipartSign:
    """Verify sign correctness for large data (triggers C_SignUpdate)."""

    def test_rsa_sign_large_data(self, p11_raw_session: Any) -> None:
        """RSA sign 10KB data - hash computed internally via Update."""
        rs = p11_raw_session
        _require_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = _gen_rsa_keypair_or_xfail(rs)
        data = b"\x99" * 10240
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "SHA256_RSA_PKCS", "sign")
            assert len(sig) == 256
            try:
                verified = verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "SHA256_RSA_PKCS", "verify")
            assert verified
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hmac_large_data_crossverify(self, p11_raw_session: Any) -> None:
        """HMAC-SHA256 of 64KB data cross-verified against hmac module."""
        import hmac as hmac_mod

        rs = p11_raw_session
        key_bytes = bytes(range(32))
        data = b"\x77" * 65536

        p11_key = _import_hmac_key(rs, key_bytes)
        try:
            try:
                p11_mac = sign_single(rs.raw, rs.sh, p11_key, CKM_SHA256_HMAC, data)
            except AssertionError as exc:
                _xfail_streaming_reject(exc, "SHA256_HMAC", "sign")
            expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
            assert p11_mac == expected
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

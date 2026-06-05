"""Memory, handle, and resource safety tests.

Tests for leaks, exhaustion, use-after-destroy, and cleanup behavior.
These help catch bugs that only manifest under sustained load.
"""

from __future__ import annotations

from typing import Any

import psutil
import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    sign_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_LABEL,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SESSION_COUNT,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    get_pin_bytes,
    is_known_error,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.stress

_RESOURCE_OPERATION_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _get_rss_mb() -> float:
    """Get current process RSS in megabytes."""
    return psutil.Process().memory_info().rss / (1024 * 1024)  # type: ignore[no-any-return]


def _aes_resource_key(rs: Any, *, attrs: dict[Any, Any] | None = None) -> int:
    return gen_aes_key_or_xfail(rs, 128, attrs=attrs, purpose="resource/stress setup")


def _open_extra_session_or_skip(raw: Any, slot_id: int, flags: int) -> int:
    from pkcs11_check.raw.bootstrap import open_session as raw_open_session

    try:
        return raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by resource test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _digest_or_xfail(rs: Any, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "SHA256")
    try:
        return digest_single(rs.raw, rs.sh, CKM_SHA256, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _RESOURCE_OPERATION_REJECT_RVS, "SHA256 digest rejected")
    raise


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _RESOURCE_OPERATION_REJECT_RVS, "AES_ECB encrypt rejected")
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _RESOURCE_OPERATION_REJECT_RVS, "AES_ECB decrypt rejected")
    raise


class TestMemoryLeaks:
    """Check for memory leaks during repeated operations."""

    def test_key_generation_no_leak(self, p11_raw_session: Any) -> None:
        """Generate and destroy 1000 keys - RSS should not grow significantly."""
        rs = p11_raw_session
        rss_before = _get_rss_mb()
        for _ in range(1000):
            key = _aes_resource_key(rs)
            destroy_quietly(rs.raw, rs.sh, key)
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 key gen/destroy cycles"

    @pytest.mark.slow
    def test_encrypt_cycle_no_leak(self, p11_raw_session: Any) -> None:
        """1000 encrypt/decrypt cycles - RSS should not grow significantly."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _aes_resource_key(rs)
        plaintext = b"leak test data!!"  # 16 bytes
        try:
            rss_before = _get_rss_mb()
            for _ in range(1000):
                ct = _encrypt_or_xfail(rs, key, plaintext)
                _decrypt_or_xfail(rs, key, ct)
            rss_after = _get_rss_mb()
            growth = rss_after - rss_before
            assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 encrypt cycles"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_cycle_no_leak(self, p11_raw_session: Any) -> None:
        """1000 digest operations - no leak."""
        rs = p11_raw_session
        data = b"X" * 1024
        rss_before = _get_rss_mb()
        for _ in range(1000):
            _digest_or_xfail(rs, data)
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 digest cycles"


class TestUseAfterDestroy:
    """Verify that using destroyed objects fails cleanly (no crash)."""

    def test_encrypt_after_destroy(self, p11_raw_session: Any) -> None:
        """Using a destroyed key for encryption must fail, not crash."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _aes_resource_key(rs)
        destroy_quietly(rs.raw, rs.sh, key)
        # Raw C_EncryptInit with destroyed handle should return error CKR
        with pytest.raises(AssertionError):
            encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"0123456789abcdef")

    def test_sign_after_destroy(self, p11_raw_session: Any) -> None:
        """Using a destroyed key for signing must fail, not crash."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        destroy_quietly(rs.raw, rs.sh, priv)
        with pytest.raises(AssertionError):
            sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"data")
        destroy_quietly(rs.raw, rs.sh, pub)

    def test_double_destroy(self, p11_raw_session: Any) -> None:
        """Destroying an already-destroyed object must fail cleanly."""
        rs = p11_raw_session
        key = _aes_resource_key(rs)
        destroy_quietly(rs.raw, rs.sh, key)
        # Second destroy - should not crash (destroy_quietly swallows errors)
        rv = rs.raw.C_DestroyObject(rs.sh, key)
        # Crash-only check -- any CKR is acceptable
        assert rv is not None

    def test_read_attribute_after_destroy(self, p11_raw_session: Any) -> None:
        """Reading attributes of destroyed object must fail cleanly."""
        from pkcs11_check.raw.recipes import read_attributes

        rs = p11_raw_session
        key = _aes_resource_key(rs, attrs={CKA_LABEL: "destroy-attr"})
        destroy_quietly(rs.raw, rs.sh, key)
        with pytest.raises(AssertionError):
            read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])


class TestSessionChurn:
    """Test rapid session open/close cycles."""

    @pytest.mark.slow
    def test_rapid_session_cycles(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Open and close 100 sessions rapidly - no leak or crash."""
        from pkcs11_check.raw.bootstrap import (
            close_session_quietly,
            login_user,
        )
        from pkcs11_check.raw.types_std import (
            CKF_RW_SESSION,
            CKF_SERIAL_SESSION,
            CKU_USER,
        )

        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        rss_before = _get_rss_mb()
        for _ in range(100):
            flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
            sh = _open_extra_session_or_skip(rs.raw, rs.slot_id, flags)
            if pin_bytes is not None:
                login_user(rs.raw, sh, CKU_USER, pin_bytes)
            close_session_quietly(rs.raw, sh)
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 100 session cycles"


class TestBulkOperations:
    """Test creating many objects simultaneously."""

    def test_100_keys_coexist(self, p11_raw_session: Any) -> None:
        """Create 100 keys, verify all exist, then destroy all."""
        rs = p11_raw_session
        keys = []
        for i in range(100):
            key = _aes_resource_key(rs, attrs={CKA_LABEL: f"bulk100-{i:03d}"})
            keys.append(key)

        # Verify all exist
        found = find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_CLASS: CKO_SECRET_KEY}),
        )
        assert len(found) >= 100

        # Destroy all
        for key in keys:
            destroy_quietly(rs.raw, rs.sh, key)

        # Verify cleanup
        found = find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_LABEL: "bulk100-000"}),
        )
        assert len(found) == 0

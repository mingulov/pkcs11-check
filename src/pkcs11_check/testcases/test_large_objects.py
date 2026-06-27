"""Large object stress tests.

Verifies that PKCS#11 modules handle large data correctly:
- 1MB CKO_DATA objects
- Large random generation
- Large plaintext encryption
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKO_DATA,
    CKR_ARGUMENTS_BAD,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    skip_if_data_objects_unsupported,
)

pytestmark = pytest.mark.security


def _unique_label(prefix: str = "large") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestLargeDataObjects:
    """Test large CKO_DATA object storage."""

    def test_1mb_data_object(self, p11_raw_session: Any) -> None:
        """Create and read back a 1MB CKO_DATA object."""
        rs = p11_raw_session
        skip_if_data_objects_unsupported(rs)
        label = _unique_label()
        big_data = b"\xab" * (1024 * 1024)  # 1MB

        obj = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: big_data,
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, obj, [CKA_VALUE])
            stored = attrs[CKA_VALUE]
            assert stored == big_data
            assert len(stored) == 1024 * 1024
        finally:
            destroy_quietly(rs.raw, rs.sh, obj)

    def test_100kb_data_object(self, p11_raw_session: Any) -> None:
        """Create and read back a 100KB CKO_DATA object."""
        rs = p11_raw_session
        skip_if_data_objects_unsupported(rs)
        label = _unique_label()
        data = bytes(range(256)) * 400  # 102,400 bytes

        obj = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: data,
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, obj, [CKA_VALUE])
            assert attrs[CKA_VALUE] == data
        finally:
            destroy_quietly(rs.raw, rs.sh, obj)


class TestLargeRandomGeneration:
    """Test large random number generation."""

    def test_generate_100kb_random(self, p11_raw_session: Any) -> None:
        """Generate 100KB of random data via C_GenerateRandom.

        NSS deviation: NSS returns CKR_ARGUMENTS_BAD for C_GenerateRandom
        requests larger than approximately 32KB -- NSS has an internal size
        limit on single random generation calls.
        """
        rs = p11_raw_session
        try:
            rand = generate_random(rs.raw, rs.sh, 100 * 1024)
            assert len(rand) == 100 * 1024
        except AssertionError as exc:
            from pkcs11_check.testcases.conftest import xfail_if_known_ckr

            xfail_if_known_ckr(
                exc,
                {CKR_ARGUMENTS_BAD},
                "some modules reject C_GenerateRandom(100KB) with CKR_ARGUMENTS_BAD - "
                "an internal size limit on single random generation calls",
            )
            raise

    def test_generate_1kb_random_is_unique(self, p11_raw_session: Any) -> None:
        """Two 1KB random blocks should be different."""
        rs = p11_raw_session
        r1 = generate_random(rs.raw, rs.sh, 1024)
        r2 = generate_random(rs.raw, rs.sh, 1024)
        assert r1 != r2


class TestLargeEncryption:
    """Test encryption of large plaintexts."""

    def test_encrypt_64kb_aes_ecb(self, p11_raw_session: Any) -> None:
        """AES-ECB encrypt/decrypt 64KB data."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        data = b"\x42" * 65536  # 64KB, block-aligned
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_encrypt_1mb_aes_cbc(self, p11_raw_session: Any) -> None:
        """AES-CBC encrypt/decrypt 1MB data."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        data = b"\x99" * (1024 * 1024)  # 1MB
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
            assert pt == data
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

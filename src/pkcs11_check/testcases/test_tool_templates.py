"""Default tool template tests and concurrent stress.

Tests key creation patterns used by common tools (pkcs11-tool, Java keytool)
and concurrent object operations.

References: Tookan paper (default templates), rep11.md Iteration 2 (session/object hidden failures).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    gen_aes_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_WRAP,
    CKM_AES_ECB,
    CKM_SHA256_RSA_PKCS,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases.conftest import (
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
)

pytestmark = pytest.mark.security


class TestDefaultToolTemplates:
    """Test key templates that pkcs11-tool and Java keytool use (task 7.10)."""

    def test_pkcs11_tool_rsa_defaults(self, p11_raw_session: Any) -> None:
        """pkcs11-tool RSA keygen defaults: sign+verify+encrypt+decrypt+wrap+unwrap.

        This is the Tookan-risky template that most tools use.
        Module should accept but ideally warn about security policy.
        """
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: True,
                CKA_VERIFY: True,
                CKA_WRAP: True,
                CKA_TOKEN: False,
            },
            private_attrs={
                CKA_DECRYPT: True,
                CKA_SIGN: True,
                CKA_UNWRAP: True,
                CKA_SENSITIVE: True,
                CKA_EXTRACTABLE: False,
                CKA_TOKEN: False,
            },
        )
        try:
            # Key must work - this is the standard tool pattern
            data = b"tool-template-test"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pkcs11_tool_aes_defaults(self, p11_raw_session: Any) -> None:
        """pkcs11-tool AES keygen: encrypt+decrypt+wrap+unwrap."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
            },
        )
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == b"\x00" * 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestConcurrentFindObjects:
    """FindObjects while other sessions modify objects (task 7.11)."""

    def test_find_during_sequential_create_destroy(self, p11_raw_session: Any) -> None:
        """Sequential create/destroy interleaved with search - must not crash.

        Note: Truly concurrent multi-thread operations on a single PKCS#11
        session can segfault some modules (SQLite concurrency issues).
        This test uses sequential interleaving instead.
        """
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        prefix = f"conc-find-{uuid.uuid4().hex[:6]}"
        for i in range(20):
            key = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: f"{prefix}-{i}"})
            # Search while objects exist
            found = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_SECRET_KEY}),
            )
            assert len(found) >= 1
            destroy_quietly(rs.raw, rs.sh, key)

        # All destroyed
        found = find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_LABEL: f"{prefix}-0"}),
        )
        assert len(found) == 0


class TestDBStress:
    """Database stress under sequential writes (task 7.12)."""

    def test_rapid_keygen_destroy_500(self, p11_raw_session: Any) -> None:
        """500 key gen+destroy cycles. Tests SQLite transaction handling.

        Note: SQLite transaction errors can occur under load in some modules.
        Concurrent multi-thread on same session causes segfaults.
        Sequential rapid cycles are safer and still catch DB issues.
        """
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        for i in range(500):
            key = gen_aes_key(rs.raw, rs.sh, 128)
            destroy_quietly(rs.raw, rs.sh, key)

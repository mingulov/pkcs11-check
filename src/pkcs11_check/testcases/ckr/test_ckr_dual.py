"""CKR compliance tests for operation state machine conflicts.

Tests cross-operation conflicts and state violations:
- CKR_OPERATION_NOT_INITIALIZED: calling operation without Init
- CKR_OPERATION_ACTIVE: starting new operation while one is active

Source: PKCS#11 v3.2 (OPERATION_ACTIVE, OPERATION_NOT_INITIALIZED).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    encrypt_single,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
)
from pkcs11_check.testcases._probes.runner import ProbeResult, run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
)

pytestmark = pytest.mark.access


def _assert_operation_subprocess_ok(result: ProbeResult, *, context: str) -> None:
    assert_subprocess_completed(result.returncode, result.stdout, result.stderr, context=context)
    assert "OK:" in result.stdout, (
        f"{context}: child subprocess did not emit an OK marker; "
        f"stdout: {result.stdout[-300:]}; stderr: {result.stderr[-300:]}"
    )


class TestOperationStateWrapper:
    """State machine tests via raw API."""

    def test_encrypt_twice_succeeds(self, p11_raw_session: Any) -> None:
        """Two consecutive single-shot encrypts should both work.

        Single-shot C_Encrypt resets the operation state, so the second
        call requires a new C_EncryptInit.
        """
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            purpose="operation-state encrypt wrapper setup",
        )
        try:
            ct1 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            ct2 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x11" * 16)
            assert len(ct1) == 16
            assert len(ct2) == 16
            assert ct1 != ct2  # Different plaintext -> different ciphertext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_twice_succeeds(self, p11_raw_session: Any) -> None:
        """Two consecutive digests should both work."""
        rs = p11_raw_session
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data1")
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data2")
        assert len(d1) == 32
        assert len(d2) == 32
        assert d1 != d2

    def test_sign_then_encrypt(self, p11_raw_session: Any) -> None:
        """Sign then encrypt with same session - no conflict."""
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        key = gen_aes_key_or_xfail(
            rs,
            128,
            purpose="operation-state sign/encrypt wrapper setup",
        )
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"data")
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            assert len(sig) == 256
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestOperationStateSubprocess:
    """State machine tests requiring raw C API access (subprocess).

    Each test launches the ``ckr_dual`` probe module (``_probes/ckr_dual.py``) via
    ``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a
    PIN is configured -- logs in, with the PIN travelling solely through the
    ``_P11CHECK_PIN`` env var (never embedded in source or params -- Invariant I3).
    """

    def test_encrypt_without_init(self, p11_config: Any) -> None:
        """C_Encrypt without C_EncryptInit -> CKR_OPERATION_NOT_INITIALIZED."""
        result = run_probe(
            "ckr_dual",
            {"module_path": str(p11_config.module), "probe": "encrypt_without_init"},
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        _assert_operation_subprocess_ok(result, context="C_Encrypt without C_EncryptInit")

    def test_double_digest_init_via_subprocess(self, p11_config: Any) -> None:
        """Two DigestInit calls without Digest -> second should get OPERATION_ACTIVE."""
        result = run_probe(
            "ckr_dual",
            {"module_path": str(p11_config.module), "probe": "double_digest_init"},
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        _assert_operation_subprocess_ok(result, context="double C_DigestInit")

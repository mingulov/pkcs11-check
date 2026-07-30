"""Concurrency and stress tests for PKCS#11 modules.

Tests multi-session behavior, rapid operation cycling, and
resource limits. These help find threading bugs and leaks
that only manifest under sustained load.

Hang detection is the runner's job, not an inline wall-clock budget. These loops
deliberately assert only on CORRECTNESS (round-trip equality, digest stability,
no duplicate random output) and never on elapsed time.

A hard-coded budget ("1000 cycles must finish in 30s") is a benchmark against
unspecified hardware, and it fails the provider rather than the host: on a 2-vCPU
Windows container driving BouncyHsm over loopback RPC the same 1000 encrypt/decrypt
cycles take 87s, and 1000 C_GenerateRandom calls take 11s -- legitimate throughput
for that deployment, reported as a provider defect. Recording a finding against a
conformant module is the one outcome the classification rules single out as harmful,
and slow-but-correct hardware (embedded HSMs, smartcards, emulators, remote daemons)
would trip these thresholds the same way.

The per-unit ``--timeout`` (default 180s) already terminates a genuinely hung unit and
records it as a crash/timeout finding, which is both stronger than an aggregate budget
(it catches any hang, not only one that pushes the total past a constant) and free of
the hardware assumption.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
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
    is_known_error,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.stress

_STRESS_OPERATION_REJECT_RVS = (
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


def open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session required by stress tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by stress test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _aes_stress_key(rs: Any, *, attrs: dict[Any, Any] | None = None) -> int:
    return gen_aes_key_or_xfail(rs, 128, attrs=attrs, purpose="resource/stress setup")


def _digest_or_xfail(rs: Any, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "SHA256")
    try:
        return digest_single(rs.raw, rs.sh, CKM_SHA256, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _STRESS_OPERATION_REJECT_RVS, "SHA256 digest rejected")
    raise


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _STRESS_OPERATION_REJECT_RVS, "AES_ECB encrypt rejected")
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _STRESS_OPERATION_REJECT_RVS, "AES_ECB decrypt rejected")
    raise


def _sign_or_xfail(rs: Any, private_key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
    try:
        return sign_single(rs.raw, rs.sh, private_key, CKM_SHA256_RSA_PKCS, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _STRESS_OPERATION_REJECT_RVS, "SHA256_RSA_PKCS sign rejected")
    raise


def _verify_or_xfail(rs: Any, public_key: int, data: bytes, signature: bytes) -> bool:
    skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
    try:
        return verify_single(rs.raw, rs.sh, public_key, CKM_SHA256_RSA_PKCS, data, signature)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _STRESS_OPERATION_REJECT_RVS, "SHA256_RSA_PKCS verify rejected")
    raise


class TestMultiSessionConcurrency:
    """Test concurrent operations across multiple sessions.

    NOTE: Many PKCS#11 modules have limited thread safety. These tests
    verify the module doesn't crash under concurrency, even if some
    operations fail.
    """

    def test_sequential_multi_session(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Open multiple sessions sequentially and operate independently."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Open first session (p11_raw_session already has one)
        # Generate a key in the existing session
        key1 = _aes_stress_key(rs, attrs={CKA_LABEL: b"multi-s1"})

        # Open second session (already logged in at token level)
        sh2 = open_session(rs.raw, rs.slot_id, flags)
        try:
            key2 = gen_aes_key_or_xfail(
                SimpleNamespace(raw=rs.raw, sh=sh2, has_mechanism=rs.has_mechanism),
                128,
                attrs={CKA_LABEL: b"multi-s2"},
                purpose="resource/stress setup",
            )
            destroy_quietly(rs.raw, sh2, key2)
        finally:
            close_session_quietly(rs.raw, sh2)
        destroy_quietly(rs.raw, rs.sh, key1)

    def test_sequential_digest_sessions(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Multiple sessions can each compute independent digests."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        digests = []
        d1 = _digest_or_xfail(rs, b"session 1 data")
        digests.append(d1)

        sh2 = open_session(rs.raw, rs.slot_id, flags)
        try:
            d2 = _digest_or_xfail(
                SimpleNamespace(raw=rs.raw, sh=sh2, has_mechanism=rs.has_mechanism),
                b"session 2 data",
            )
            digests.append(d2)
        finally:
            close_session_quietly(rs.raw, sh2)

        assert len(digests) == 2
        assert digests[0] != digests[1]  # Different data -> different digest


class TestRapidOperations:
    """Test rapid cycling of operations without pause."""

    def test_rapid_encrypt_decrypt_1000(self, p11_raw_session: Any) -> None:
        """1000 encrypt/decrypt cycles in quick succession."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _aes_stress_key(rs)
        plaintext = b"rapid cycling!!!"  # 16 bytes

        try:
            for _ in range(1000):
                ct = _encrypt_or_xfail(rs, key, plaintext)
                pt = _decrypt_or_xfail(rs, key, ct)
                assert pt == plaintext
            # No wall-clock budget here: see the module note on hang detection.
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rapid_digest_1000(self, p11_raw_session: Any) -> None:
        """1000 SHA-256 digest operations."""
        rs = p11_raw_session
        data = b"rapid digest test data"
        expected = _digest_or_xfail(rs, data)

        for _ in range(1000):
            result = _digest_or_xfail(rs, data)
            assert result == expected
        # No wall-clock budget here: see the module note on hang detection.

    def test_rapid_random_1000(self, p11_raw_session: Any) -> None:
        """1000 random generation calls."""
        rs = p11_raw_session
        seen: set[bytes] = set()
        for _ in range(1000):
            data = generate_random(rs.raw, rs.sh, 32)
            seen.add(data)
        assert len(seen) == 1000, "Random generation produced duplicates"
        # No wall-clock budget here: see the module note on hang detection.

    def test_rapid_sign_verify_100(self, p11_raw_session: Any) -> None:
        """100 RSA sign/verify cycles."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        data = b"rapid sign test"

        try:
            for _ in range(100):
                sig = _sign_or_xfail(rs, priv, data)
                assert _verify_or_xfail(rs, pub, data, sig) is True
            # No wall-clock budget here: see the module note on hang detection.
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSessionStress:
    """Test session lifecycle under stress."""

    def test_session_open_close_100(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Open and close 100 sessions rapidly."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        for _i in range(100):
            sh = open_session(rs.raw, rs.slot_id, flags)
            try:
                generate_random(rs.raw, sh, 64)
            finally:
                close_session_quietly(rs.raw, sh)

    def test_create_destroy_cycle(self, p11_raw_session: Any) -> None:
        """Create and destroy 500 keys rapidly."""
        rs = p11_raw_session
        for _i in range(500):
            key = _aes_stress_key(rs)
            destroy_quietly(rs.raw, rs.sh, key)

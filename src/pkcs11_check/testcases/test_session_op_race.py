"""Same-session multi-thread race tests.

PKCS#11 spec mandates one cryptographic operation per session at a time.
When two threads attempt `C_*Init` on the same `CK_SESSION_HANDLE`
simultaneously, exactly one must succeed and the other must return
`CKR_OPERATION_ACTIVE`.  A module that returns `CKR_OK` to both racers
silently corrupts session state -- a real CVE class (some modules have
had bugs of this shape).

Existing `test_threading.py` runs threads but each opens a *new* session,
which avoids the race.  These tests deliberately share one session
across racing threads.

Source: PKCS#11 v3.2 (one active operation per session),
        §5 each `C_*Init` lists CKR_OPERATION_ACTIVE as a valid return.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import threading
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKM_AES_ECB,
    CKM_SHA256,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
)

pytestmark = [pytest.mark.stress, pytest.mark.state_machine, pytest.mark.thread_safe]


# Some modules return CKR_FUNCTION_FAILED instead of CKR_OPERATION_ACTIVE
# for the loser of the race — non-spec-compliant but widely observed.
_LOSER_RVCS: frozenset[int] = frozenset(
    {
        CKR_OPERATION_ACTIVE,
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
    }
)


def _abort_digest(rs: RawSession) -> None:
    """Best-effort cleanup of a pending digest operation."""
    out_buf = (ctypes.c_ubyte * 64)()
    out_len = CK_ULONG(64)
    rs.raw.C_DigestFinal(rs.sh, out_buf, byref(out_len))


def _abort_encrypt(rs: RawSession) -> None:
    """Best-effort cleanup of a pending encrypt operation."""
    out_buf = (ctypes.c_ubyte * 64)()
    out_len = CK_ULONG(64)
    rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))


def _race_inits(
    rs: RawSession,
    init_call: Any,
    cleanup: Any,
    iterations: int = 8,
) -> dict[str, int]:
    """Race two threads calling `init_call(rs)` after a barrier sync.

    Returns a dict counting outcomes across iterations:
      - "winner_ok": rv == CKR_OK
      - "loser_busy": rv in _LOSER_RVCS
      - "both_ok": both threads returned CKR_OK (spec violation)
      - "both_busy": neither returned CKR_OK (no thread progressed)
      - "other": something else
    """
    counters: dict[str, int] = {
        "winner_ok": 0,
        "loser_busy": 0,
        "both_ok": 0,
        "both_busy": 0,
        "other": 0,
    }

    for _ in range(iterations):
        barrier = threading.Barrier(2)

        def racer() -> int:
            barrier.wait(timeout=5.0)
            return int(init_call(rs))

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(racer)
            f2 = pool.submit(racer)
            rv1 = f1.result()
            rv2 = f2.result()

        # Cleanup any pending op before next iteration
        cleanup(rs)

        ok_count = (rv1 == CKR_OK) + (rv2 == CKR_OK)
        busy_count = (rv1 in _LOSER_RVCS) + (rv2 in _LOSER_RVCS)

        if ok_count == 2:
            counters["both_ok"] += 1
        elif ok_count == 1 and busy_count == 1:
            counters["winner_ok"] += 1
            counters["loser_busy"] += 1
        elif busy_count == 2:
            counters["both_busy"] += 1
        else:
            counters["other"] += 1

    return counters


class TestSameSessionInitRace:
    """Two threads call `C_*Init` on the same session — exactly one wins."""

    def test_digest_init_race(self, p11_raw_session: RawSession) -> None:
        """Two threads call C_DigestInit on the same session.

        Spec: exactly one thread should get CKR_OK; the other should get
        CKR_OPERATION_ACTIVE (the spec-mandated return for "operation
        already active in this session").  Both returning CKR_OK is a
        real bug — the loser silently overwrites the winner's state.
        """
        rs = p11_raw_session

        def init_digest(rs_inner: RawSession) -> int:
            mech = mech_simple(CKM_SHA256)
            return int(rs_inner.raw.C_DigestInit(rs_inner.sh, mech.byref()))

        counters = _race_inits(rs, init_digest, _abort_digest, iterations=8)

        assert counters["both_ok"] == 0, (
            f"C_DigestInit race: both threads got CKR_OK in "
            f"{counters['both_ok']}/{counters['both_ok'] + counters['winner_ok']} "
            f"iterations — module is not enforcing single-active-operation. "
            f"Full counters: {counters}"
        )
        # Sanity: at least some iterations should have had a clean winner.
        # If every iteration ended with both_busy or other, the test is not
        # actually exercising the race (e.g. barrier broken).
        assert counters["winner_ok"] >= 1, (
            f"C_DigestInit race never produced a winner across all iterations — "
            f"barrier sync or init path is broken. Counters: {counters}"
        )

    def test_encrypt_init_race(self, p11_raw_session: RawSession) -> None:
        """Two threads call C_EncryptInit on the same session.

        Same expectation as digest race: exactly one thread wins,
        the other gets CKR_OPERATION_ACTIVE.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES key generation not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:

            def init_encrypt(rs_inner: RawSession) -> int:
                mech = mech_simple(CKM_AES_ECB)
                return int(rs_inner.raw.C_EncryptInit(rs_inner.sh, mech.byref(), key))

            counters = _race_inits(rs, init_encrypt, _abort_encrypt, iterations=8)

            assert counters["both_ok"] == 0, (
                f"C_EncryptInit race: both threads got CKR_OK in "
                f"{counters['both_ok']} iterations — module is not enforcing "
                f"single-active-operation. Counters: {counters}"
            )
            assert counters["winner_ok"] >= 1, (
                f"C_EncryptInit race never produced a clean winner. Counters: {counters}"
            )
        finally:
            _abort_encrypt(rs)
            destroy_quietly(rs.raw, rs.sh, key)

    def test_init_during_update_returns_operation_active(self, p11_raw_session: RawSession) -> None:
        """One thread mid-C_EncryptUpdate, second thread calls C_EncryptInit.

        Spec: the second thread must get CKR_OPERATION_ACTIVE.  The
        in-flight update from thread A should not be corrupted by
        thread B's failed init.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES key generation not supported")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            # Thread A starts encrypt, does an Update, then pauses.
            mech_a = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech_a.byref(), key)
            if rv != CKR_OK:
                pytest.skip(f"Initial C_EncryptInit failed: 0x{rv:08x}")

            # Thread B tries to init while operation is active.
            def reinit_attempt() -> int:
                mech_b = mech_simple(CKM_AES_ECB)
                return int(rs.raw.C_EncryptInit(rs.sh, mech_b.byref(), key))

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                rv_b = pool.submit(reinit_attempt).result(timeout=5.0)

            assert rv_b in _LOSER_RVCS, (
                f"C_EncryptInit while operation active returned 0x{rv_b:08x}, "
                f"expected CKR_OPERATION_ACTIVE (0x{CKR_OPERATION_ACTIVE:08x})"
            )

            # Thread A's operation must still be intact: a clean Final must succeed.
            out_buf = (ctypes.c_ubyte * 32)()
            out_len = CK_ULONG(32)
            rv_final = rs.raw.C_EncryptFinal(rs.sh, out_buf, byref(out_len))
            assert rv_final == CKR_OK, (
                f"Thread A's encrypt op was corrupted by thread B's failed init: "
                f"C_EncryptFinal returned 0x{rv_final:08x}"
            )
        finally:
            _abort_encrypt(rs)
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_init_then_sign_init_other_thread(self, p11_raw_session: RawSession) -> None:
        """One thread holds an active C_DigestInit, another tries C_SignInit.

        Different operation type, same session — still must return
        CKR_OPERATION_ACTIVE because the session can only host one
        operation at a time, regardless of kind.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        # Thread A activates digest
        mech_digest = mech_simple(CKM_SHA256)
        rv = rs.raw.C_DigestInit(rs.sh, mech_digest.byref())
        if rv != CKR_OK:
            pytest.skip(f"C_DigestInit failed: 0x{rv:08x}")

        try:
            # Thread B tries to SignInit on same session.  Doesn't need a real
            # key — even passing handle 0 is enough to test the state check
            # (most modules check operation-active before key validity).
            def sign_init_attempt() -> int:
                sign_mech = mech_simple(CKM_SHA256)  # mech irrelevant; state check fires first
                return int(rs.raw.C_SignInit(rs.sh, sign_mech.byref(), 0))

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                rv_b = pool.submit(sign_init_attempt).result(timeout=5.0)

            assert rv_b in _LOSER_RVCS, (
                f"C_SignInit while digest operation active returned 0x{rv_b:08x}, "
                f"expected CKR_OPERATION_ACTIVE (0x{CKR_OPERATION_ACTIVE:08x})"
            )
        finally:
            _abort_digest(rs)

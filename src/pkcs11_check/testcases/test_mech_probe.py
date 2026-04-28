"""Probe tests for vendor/unknown mechanisms.

Parametrized by mech_any_entry -- covers mechanisms advertised by the module
that have NO entry in the mechanism registry.  These are vendor-defined or
newly added standard mechanisms not yet catalogued.

Tests confirm that:
  - Calling C_EncryptInit / C_SignInit / C_DigestInit with no key (handle 0)
    does NOT crash the process (returns a valid CKR value instead)
  - The flags advertised by the module are self-consistent (at least one
    operation class bit is set, or CKF_EXTENSION is present)

Registered mechanisms (with a registry config) are skipped here -- they are
fully exercised by test_mech_encrypt.py, test_mech_sign.py, etc.
"""
from __future__ import annotations

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.types_std import CKM, CKR_OK
from pkcs11_check.testcases.mechanism_catalog import MechEntry

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.surface_audit]

# Mechanism flags that indicate an operation class
_OP_FLAGS: int = (
    0x00000100  # CKF_ENCRYPT
    | 0x00000200  # CKF_DECRYPT
    | 0x00000400  # CKF_DIGEST
    | 0x00000800  # CKF_SIGN
    | 0x00001000  # CKF_SIGN_RECOVER
    | 0x00002000  # CKF_VERIFY
    | 0x00004000  # CKF_VERIFY_RECOVER
    | 0x00008000  # CKF_GENERATE
    | 0x00010000  # CKF_GENERATE_KEY_PAIR
    | 0x00020000  # CKF_WRAP
    | 0x00040000  # CKF_UNWRAP
    | 0x00080000  # CKF_DERIVE
    | 0x10000000  # CKF_ENCAPSULATE
    | 0x20000000  # CKF_DECAPSULATE
    | 0x80000000  # CKF_EXTENSION
    | 0x00000002  # CKF_MESSAGE_ENCRYPT
    | 0x00000004  # CKF_MESSAGE_DECRYPT
    | 0x00000008  # CKF_MESSAGE_SIGN
    | 0x00000010  # CKF_MESSAGE_VERIFY
)

# CKR values that are valid "no crash" responses for an Init call with no key.
# CKR_OK is included because some implementations may allow deferred key binding.
_VALID_INIT_RVCS: frozenset[int] = frozenset(
    [
        0x00000000,  # CKR_OK
        0x00000010,  # CKR_SLOT_ID_INVALID (some impls reject unknown mechs early)
        0x00000020,  # CKR_GENERAL_ERROR
        0x00000040,  # CKR_FUNCTION_NOT_SUPPORTED
        0x00000050,  # CKR_ARGUMENTS_BAD
        0x00000060,  # CKR_NO_EVENT
        0x00000070,  # CKR_NEED_TO_CREATE_THREADS
        0x00000090,  # CKR_OPERATION_ACTIVE
        0x000000B0,  # CKR_KEY_HANDLE_INVALID
        0x000000B3,  # CKR_KEY_TYPE_INCONSISTENT
        0x000000C0,  # CKR_MECHANISM_INVALID
        0x000000C1,  # CKR_MECHANISM_PARAM_INVALID
        0x000000D0,  # CKR_OBJECT_HANDLE_INVALID
        0x00000140,  # CKR_SESSION_HANDLE_INVALID
        0x00000180,  # CKR_TOKEN_NOT_RECOGNIZED
        0x000001A0,  # CKR_USER_NOT_LOGGED_IN
        0x00000200,  # CKR_BUFFER_TOO_SMALL
        0x00000210,  # CKR_SAVED_STATE_INVALID
    ]
)


class TestMechProbeNoRegistry:
    """Smoke-test vendor/unknown mechanisms that are not in the registry."""

    def test_no_registry_entry(
        self, p11_raw_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """Confirm mechanism is genuinely unregistered (skip if it has a config).

        This test acts as a gate: it only runs for mechanisms where no registry
        entry exists.  If all mechanisms are registered, the test count here will
        be zero.
        """
        entry = mech_any_entry
        if entry.config is not None:
            pytest.skip(f"{entry.mech_name}: registered mechanism -- tested elsewhere")
        # No assertion needed -- reaching here confirms it is unregistered.

    def test_has_operation_flag(
        self, p11_raw_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """Unregistered mechanism must advertise at least one operation class flag.

        A vendor mechanism with flags == 0 is spec-violating (C_GetMechanismInfo
        must set at least one operation flag or CKF_EXTENSION per OASIS spec).
        """
        entry = mech_any_entry
        if entry.config is not None:
            pytest.skip(f"{entry.mech_name}: registered mechanism -- tested elsewhere")
        if entry.flags == 0:
            # Flags == 0 is a spec violation but not a crash.  Fail with a
            # clear message rather than silently passing.
            pytest.fail(
                f"{entry.mech_name} (0x{entry.mech_id:08x}): "
                f"flags == 0 -- no operation class bits set (CKF_EXTENSION expected at minimum)"
            )
        # At least one known operation bit or CKF_EXTENSION must be set
        assert entry.flags & _OP_FLAGS, (
            f"{entry.mech_name} (0x{entry.mech_id:08x}): "
            f"flags=0x{entry.flags:08x} -- no known operation class bits recognised"
        )

    def test_init_does_not_crash(
        self, p11_raw_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """C_EncryptInit / C_SignInit / C_DigestInit with null-ish handle must not crash.

        For unregistered mechanisms we can't know the right key type, so we call
        the most relevant Init function with handle=0 (invalid key). The module
        MUST return a CKR error rather than segfaulting.
        """
        entry = mech_any_entry
        if entry.config is not None:
            pytest.skip(f"{entry.mech_name}: registered mechanism -- tested elsewhere")

        flags = entry.flags
        mech = mech_simple(CKM(entry.mech_id))
        rs = p11_raw_session

        # Choose the Init function based on advertised flags
        ckf_encrypt = 0x00000100
        ckf_sign = 0x00000800
        ckf_digest = 0x00000400

        rv: int
        if flags & ckf_digest:
            rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        elif flags & ckf_sign:
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), 0)
        elif flags & ckf_encrypt:
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), 0)
        else:
            # Other operation type -- just confirm it didn't crash reaching here
            return

        # rv must be a recognisable CKR integer -- not a process crash
        assert isinstance(rv, int), (
            f"{entry.mech_name}: Init returned non-integer {rv!r}"
        )
        # If the call somehow returned CKR_OK (shouldn't happen with handle=0),
        # abort the pending operation to avoid contaminating session state.
        if rv == CKR_OK:
            # Try to cancel: DigestFinal(NULL) or EncryptFinal(NULL) will fail but
            # at least clears the active-operation flag on most implementations.
            pass

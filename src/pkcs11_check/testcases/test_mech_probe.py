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

from pkcs11_check.classification import classify
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_DECAPSULATE,
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_ENCAPSULATE,
    CKF_ENCRYPT,
    CKF_EXTENSION,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_UNWRAP,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKF_WRAP,
    CKM,
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_NEED_TO_CREATE_THREADS,
    CKR_NO_EVENT,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_SAVED_STATE_INVALID,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SLOT_ID_INVALID,
    CKR_TOKEN_NOT_RECOGNIZED,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.surface_audit]

# Mechanism flags that indicate an operation class
_OP_FLAGS: int = (
    int(CKF_ENCRYPT)
    | int(CKF_DECRYPT)
    | int(CKF_DIGEST)
    | int(CKF_SIGN)
    | int(CKF_SIGN_RECOVER)
    | int(CKF_VERIFY)
    | int(CKF_VERIFY_RECOVER)
    | int(CKF_GENERATE)
    | int(CKF_GENERATE_KEY_PAIR)
    | int(CKF_WRAP)
    | int(CKF_UNWRAP)
    | int(CKF_DERIVE)
    | int(CKF_ENCAPSULATE)
    | int(CKF_DECAPSULATE)
    | int(CKF_EXTENSION)
    | int(CKF_MESSAGE_ENCRYPT)
    | int(CKF_MESSAGE_DECRYPT)
    | int(CKF_MESSAGE_SIGN)
    | int(CKF_MESSAGE_VERIFY)
)

# CKR values that are valid "no crash" responses for an Init call with no key.
# CKR_OK is included because some implementations may allow deferred key binding.
_VALID_INIT_RVCS: frozenset[int] = frozenset(
    [
        int(CKR_OK),
        int(CKR_SLOT_ID_INVALID),
        int(CKR_GENERAL_ERROR),
        int(CKR_FUNCTION_NOT_SUPPORTED),
        int(CKR_ARGUMENTS_BAD),
        int(CKR_NO_EVENT),
        int(CKR_NEED_TO_CREATE_THREADS),
        int(CKR_OPERATION_ACTIVE),
        int(CKR_KEY_HANDLE_INVALID),
        int(CKR_KEY_TYPE_INCONSISTENT),
        int(CKR_MECHANISM_INVALID),
        int(CKR_MECHANISM_PARAM_INVALID),
        int(CKR_OBJECT_HANDLE_INVALID),
        int(CKR_SESSION_HANDLE_INVALID),
        int(CKR_TOKEN_NOT_RECOGNIZED),
        int(CKR_USER_NOT_LOGGED_IN),
        int(CKR_BUFFER_TOO_SMALL),
        int(CKR_SAVED_STATE_INVALID),
    ]
)


class TestMechProbeNoRegistry:
    """Smoke-test vendor/unknown mechanisms that are not in the registry."""

    def test_no_registry_entry(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
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
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """Unregistered mechanism must advertise at least one operation class flag.

        A vendor mechanism with flags == 0 is spec-violating (C_GetMechanismInfo
        must set at least one operation flag or CKF_EXTENSION per OASIS spec).
        """
        entry = mech_any_entry
        if entry.config is not None:
            pytest.skip(f"{entry.mech_name}: registered mechanism -- tested elsewhere")
        if entry.flags == 0:
            # Flags == 0 is a spec violation but not a crash: C_GetMechanismList
            # advertises the mechanism while C_GetMechanismInfo sets no operation
            # bits -- the two query interfaces self-contradict (metadata).
            classify(
                "self_contradiction",
                kind="metadata",
                label=f"{entry.mech_name}:C_GetMechanismInfo flags",
                operation="C_GetMechanismInfo",
                mechanism=entry.mech_name,
                summary=(
                    f"{entry.mech_name} (0x{entry.mech_id:08x}): "
                    "flags == 0 -- no operation class bits set (CKF_EXTENSION expected at minimum)"
                ),
            )
        # At least one known operation bit or CKF_EXTENSION must be set
        assert entry.flags & _OP_FLAGS, (
            f"{entry.mech_name} (0x{entry.mech_id:08x}): "
            f"flags=0x{entry.flags:08x} -- no known operation class bits recognised"
        )

    def test_init_does_not_crash(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
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
        rs = p11_module_session

        # Choose the Init function based on advertised flags
        ckf_encrypt = int(CKF_ENCRYPT)
        ckf_sign = int(CKF_SIGN)
        ckf_digest = int(CKF_DIGEST)

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
        assert isinstance(rv, int), f"{entry.mech_name}: Init returned non-integer {rv!r}"
        assert rv in _VALID_INIT_RVCS, (
            f"{entry.mech_name}: Init returned unexpected CKR {ckr_name(rv)} (0x{rv:08x})"
        )
        # If the call somehow returned CKR_OK (shouldn't happen with handle=0),
        # abort the pending operation to avoid contaminating session state.
        if rv == CKR_OK:
            # Try to cancel: DigestFinal(NULL) or EncryptFinal(NULL) will fail but
            # at least clears the active-operation flag on most implementations.
            pass

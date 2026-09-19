"""Mechanism flag validation tests.

Parametrized by mech_any_entry -- checks every mechanism advertised by the
module against the PKCS#11 mechanism capability expectations stored in the
registry.

Tests:
  - Expected CKF_* flags from the registry are reported as partial-capability
    xfail findings when missing
  - min_key_size <= max_key_size (sanity check on C_GetMechanismInfo output)
  - Each advertised CKF_*Init flag (CKF_ENCRYPT, CKF_DIGEST, CKF_SIGN, etc.)
    corresponds to a callable function: i.e. the matching C_*Init does NOT
    return CKR_MECHANISM_INVALID / CKR_FUNCTION_NOT_SUPPORTED.  This catches
    the most common conformance bug — modules over-advertising flags they
    don't actually implement.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any, Literal

import pytest
from _pytest.outcomes import Skipped, XFailed

from pkcs11_check.classification import classify, fail_as, record_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKF_DECRYPT,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    generate_key_for_encrypt,
    generate_key_for_sign,
    make_mech_param_or_skip,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.flag_validation]

# CKR codes that mean "the module says this mechanism is not implemented".
# If the module advertised the corresponding flag in C_GetMechanismInfo, one
# of these returns is a *candidate* contradiction (a flag-lie) -- but the
# minimal probe alone cannot carry a FAIL (F-009). A hard self-contradiction
# claim needs the valid-key retry below to return a lie-RV too.
_LIE_RVCS: frozenset[int] = frozenset(
    {
        int(CKR_MECHANISM_INVALID),
        int(CKR_FUNCTION_NOT_SUPPORTED),
    }
)

_KeyRole = Literal["encrypt", "decrypt", "sign", "verify"]

# Mechanism-flag names for readable failure messages.
# These are the standard CKF_* flags returned by C_GetMechanismInfo.
_MECH_FLAG_NAMES: dict[int, str] = {
    0x00000001: "CKF_HW",
    0x00000002: "CKF_MESSAGE_ENCRYPT",
    0x00000004: "CKF_MESSAGE_DECRYPT",
    0x00000008: "CKF_MESSAGE_SIGN",
    0x00000010: "CKF_MESSAGE_VERIFY",
    0x00000020: "CKF_MULTI_MESSAGE",
    0x00000040: "CKF_FIND_OBJECTS",
    0x00000100: "CKF_ENCRYPT",
    0x00000200: "CKF_DECRYPT",
    0x00000400: "CKF_DIGEST",
    0x00000800: "CKF_SIGN",
    0x00001000: "CKF_SIGN_RECOVER",
    0x00002000: "CKF_VERIFY",
    0x00004000: "CKF_VERIFY_RECOVER",
    0x00008000: "CKF_GENERATE",
    0x00010000: "CKF_GENERATE_KEY_PAIR",
    0x00020000: "CKF_WRAP",
    0x00040000: "CKF_UNWRAP",
    0x00080000: "CKF_DERIVE",
    0x10000000: "CKF_ENCAPSULATE",
    0x20000000: "CKF_DECAPSULATE",
    0x80000000: "CKF_EXTENSION",
}


def _flag_names(mask: int) -> list[str]:
    """Convert a bitmask to a sorted list of CKF_* flag name strings."""
    names = []
    bit = 1
    while bit <= mask:
        if mask & bit:
            names.append(_MECH_FLAG_NAMES.get(bit, f"0x{bit:08x}"))
        bit <<= 1
    return names


class TestMechFlags:
    """Validate mechanism flags reported by C_GetMechanismInfo."""

    def test_expected_flags_present(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """Report registry-expected CKF_* flags missing from actual flags.

        The registry records the expected capability surface for each mechanism.
        Missing flags are useful interoperability evidence, but PKCS#11
        mechanism flags are capability reports from the module rather than a
        universal requirement that every implementation expose every operation.
        """
        entry = mech_any_entry
        if entry.config is None:
            pytest.skip("No registry config for flag validation")
        if entry.config.expected_flags == 0:
            pytest.skip("No expected flags defined in registry for this mechanism")

        expected = entry.config.expected_flags
        actual = entry.flags
        missing = expected & ~actual
        if missing:
            missing_names = _flag_names(missing)
            note(
                f"{entry.mech_name}: missing expected mechanism capability flags {missing_names}",
                ComplianceLevel.VENDOR,
                reference=(
                    "PKCS#11 C_GetMechanismInfo flags report operations supported by this module"
                ),
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label=f"{entry.mech_name}:missing-flags",
                operation="C_GetMechanismInfo",
                mechanism=entry.mech_name,
                summary=(
                    f"{entry.mech_name}: missing expected mechanism capability flags "
                    f"{missing_names} (registry expected=0x{expected:08x}, "
                    f"module reported=0x{actual:08x})"
                ),
            )

    def test_min_le_max_key_size(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        """min_key_size must be <= max_key_size from C_GetMechanismInfo.

        Both being 0 is valid (digest mechanisms or mechanisms with no key size
        constraints return 0/0 per spec).
        """
        entry = mech_any_entry
        if entry.min_key_size == 0 and entry.max_key_size == 0:
            return  # 0/0 means "no key size constraint" -- valid
        assert entry.min_key_size <= entry.max_key_size, (
            f"{entry.mech_name}: min_key_size ({entry.min_key_size}) > "
            f"max_key_size ({entry.max_key_size}) -- invalid C_GetMechanismInfo output"
        )


def _abort_op(rs: RawSession, final_func_name: str) -> None:
    """Best-effort cleanup of a pending operation via the matching *Final."""
    final_fn: Any = getattr(rs.raw, final_func_name, None)
    if final_fn is None:
        return
    out_buf = (ctypes.c_ubyte * 256)()
    out_len = CK_ULONG(256)
    final_fn(rs.sh, out_buf, byref(out_len))


def _probe_init_with_key(
    rs: RawSession,
    init_func_name: str,
    mech_id: int,
) -> int | None:
    """Call C_*Init with a dummy key handle (0).

    Returns the CKR code, or None if the function isn't in the module's
    function list.  Using handle 0 separates mechanism-rejection
    (CKR_MECHANISM_INVALID — a flag lie) from key-rejection
    (CKR_KEY_HANDLE_INVALID etc. — mech accepted, key irrelevant).
    """
    init_fn: Any = getattr(rs.raw, init_func_name, None)
    if init_fn is None or not callable(init_fn):
        return None
    mech = mech_simple(mech_id)
    rv: Any = init_fn(rs.sh, mech.byref(), 0)
    return int(rv)


def _probe_digest_init(rs: RawSession, mech_id: int) -> int | None:
    """C_DigestInit takes no key handle — probe directly."""
    init_fn: Any = getattr(rs.raw, "C_DigestInit", None)
    if init_fn is None:
        return None
    mech = mech_simple(mech_id)
    rv: Any = init_fn(rs.sh, mech.byref())
    return int(rv)


def _lie_rv_name(rv: int) -> str:
    """Readable name for a lie-RV (or hex for an unexpected code)."""
    return {
        int(CKR_MECHANISM_INVALID): "CKR_MECHANISM_INVALID",
        int(CKR_FUNCTION_NOT_SUPPORTED): "CKR_FUNCTION_NOT_SUPPORTED",
    }.get(rv, f"0x{rv:08x}")


def _retry_init_with_valid_key(
    rs: RawSession,
    entry: MechEntry,
    init_name: str,
    *,
    key_role: _KeyRole | None,
    final_name: str | None,
) -> int | None:
    """Re-run a C_*Init probe with a valid key and recipe parameters.

    Returns the retry RV, or None when no valid key/params can be
    provisioned (unregistered mechanism, domain-parameter key types,
    keygen unsupported or rejected, runtime-data params). Callers treat
    None as "cannot strengthen": the minimal-probe rejection stands as a
    diagnostic deviation, never a fail. ``key_role`` selects the
    operation-correct handle (None for the keyless digest probe).
    """
    config = entry.config
    if config is None:
        return None
    try:
        params = make_mech_param_or_skip(entry)
        handles: list[int] = []
        handle = 0
        if key_role in ("encrypt", "decrypt"):
            enc, dec = generate_key_for_encrypt(rs, entry, config)
            handles = [h for h in (enc, dec) if h is not None]
            handle = dec if key_role == "decrypt" and dec is not None else enc
        elif key_role in ("sign", "verify"):
            sig, ver = generate_key_for_sign(rs, entry, config)
            handles = [h for h in (sig, ver) if h is not None]
            handle = ver if key_role == "verify" and ver is not None else sig
    except (Skipped, XFailed, CkrAssertionError):
        # audit-ok: provisioning failure only selects the unstrengthened
        # path; the caller's xfail retains the minimal-probe rejection, so
        # no finding is hidden. Plain AssertionError (harness bugs) still
        # propagates.
        return None
    init_fn: Any = getattr(rs.raw, init_name, None)
    if init_fn is None or not callable(init_fn):
        for h in dict.fromkeys(handles):
            destroy_quietly(rs.raw, rs.sh, h)
        return None
    mech = params if params is not None else mech_simple(entry.mech_id)
    try:
        if key_role is None:
            retry_rv = int(init_fn(rs.sh, mech.byref()))
        else:
            retry_rv = int(init_fn(rs.sh, mech.byref(), handle))
        if retry_rv == CKR_OK and final_name is not None:
            _abort_op(rs, final_name)
    finally:
        for h in dict.fromkeys(handles):
            destroy_quietly(rs.raw, rs.sh, h)
    return retry_rv


def _assert_not_lie(
    rs: RawSession,
    entry: MechEntry,
    flag_name: str,
    init_name: str,
    rv: int | None,
    *,
    key_role: _KeyRole | None,
    final_name: str | None = None,
) -> None:
    """Check a flag probe: lie-RVs need valid-key strengthening for a FAIL."""
    if rv is None:
        pytest.skip(f"{init_name} not present in module function list")
    if rv not in _LIE_RVCS:
        return
    # F-009: the minimal probe (handle 0, NULL params) cannot carry a FAIL
    # alone -- its rejection does not establish behavior with a valid key
    # and parameters. Strengthen with a valid-key retry when available.
    rv_name = _lie_rv_name(rv)
    retry_rv = _retry_init_with_valid_key(
        rs, entry, init_name, key_role=key_role, final_name=final_name
    )
    label = f"{entry.mech_name}:{flag_name}"
    if retry_rv is None:
        xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=init_name,
            mechanism=entry.mech_name,
            actual=rv,
            summary=(
                f"{entry.mech_name} advertises {flag_name} in C_GetMechanismInfo "
                f"(flags=0x{entry.flags:08x}), but the minimal {init_name} probe "
                f"returned {rv_name}; no valid key could be provisioned to "
                "strengthen the probe -- retained as a diagnostic deviation"
            ),
        )
    if retry_rv in _LIE_RVCS:
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation=init_name,
            mechanism=entry.mech_name,
            actual=retry_rv,
            summary=(
                f"{entry.mech_name} advertises {flag_name} in C_GetMechanismInfo "
                f"(flags=0x{entry.flags:08x}), but {init_name} returned "
                f"{_lie_rv_name(retry_rv)} with a valid key and parameters "
                f"(minimal probe also returned {rv_name}). Module is "
                "advertising a mechanism it does not actually implement."
            ),
        )
    if retry_rv == CKR_OK:
        record_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation=init_name,
            mechanism=entry.mech_name,
            actual=rv,
            summary=(
                f"{entry.mech_name} {flag_name}: minimal {init_name} probe returned "
                f"{rv_name}, but the valid-key retry succeeded -- the flag claim "
                "holds; the minimal rejection was a degenerate-input artifact"
            ),
        )
        return
    xfail_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation=init_name,
        mechanism=entry.mech_name,
        actual=retry_rv,
        summary=(
            f"{entry.mech_name} {flag_name}: minimal {init_name} probe returned "
            f"{rv_name}, valid-key retry returned {ckr_name(retry_rv)} -- inconclusive"
        ),
    )


class TestMechFlagBehavioralConformance:
    """For each advertised CKF_* flag, the corresponding C_*Init function must
    not reject the mechanism as unknown.

    Other return codes (CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE) indicate the mechanism IS supported and the
    minimal probe didn't supply the right key/template — that's fine.  A
    lie-RV (CKR_MECHANISM_INVALID / CKR_FUNCTION_NOT_SUPPORTED) from the
    minimal probe (handle 0, NULL params) cannot carry a FAIL alone
    (F-009): it is strengthened with a valid-key retry. Only a lie-RV on
    the retry too is a self-contradiction FAIL; otherwise the observation
    is retained as a diagnostic deviation (xfail), or a pass when the
    retry proves the flag claim holds.
    """

    def test_encrypt_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_ENCRYPT)):
            pytest.skip(f"{entry.mech_name}: CKF_ENCRYPT not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_EncryptInit", entry.mech_id)
        try:
            _assert_not_lie(
                p11_module_session,
                entry,
                "CKF_ENCRYPT",
                "C_EncryptInit",
                rv,
                key_role="encrypt",
                final_name="C_EncryptFinal",
            )
        finally:
            if rv == CKR_OK:
                _abort_op(p11_module_session, "C_EncryptFinal")

    def test_decrypt_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_DECRYPT)):
            pytest.skip(f"{entry.mech_name}: CKF_DECRYPT not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_DecryptInit", entry.mech_id)
        try:
            _assert_not_lie(
                p11_module_session,
                entry,
                "CKF_DECRYPT",
                "C_DecryptInit",
                rv,
                key_role="decrypt",
                final_name="C_DecryptFinal",
            )
        finally:
            if rv == CKR_OK:
                _abort_op(p11_module_session, "C_DecryptFinal")

    def test_digest_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_DIGEST)):
            pytest.skip(f"{entry.mech_name}: CKF_DIGEST not advertised")
        rv = _probe_digest_init(p11_module_session, entry.mech_id)
        try:
            _assert_not_lie(
                p11_module_session,
                entry,
                "CKF_DIGEST",
                "C_DigestInit",
                rv,
                key_role=None,
                final_name="C_DigestFinal",
            )
        finally:
            if rv == CKR_OK:
                _abort_op(p11_module_session, "C_DigestFinal")

    def test_sign_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_SIGN)):
            pytest.skip(f"{entry.mech_name}: CKF_SIGN not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_SignInit", entry.mech_id)
        try:
            _assert_not_lie(
                p11_module_session,
                entry,
                "CKF_SIGN",
                "C_SignInit",
                rv,
                key_role="sign",
                final_name="C_SignFinal",
            )
        finally:
            if rv == CKR_OK:
                _abort_op(p11_module_session, "C_SignFinal")

    def test_verify_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_VERIFY)):
            pytest.skip(f"{entry.mech_name}: CKF_VERIFY not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_VerifyInit", entry.mech_id)
        # C_VerifyFinal needs an input signature; skip cleanup — Final
        # without buffer is best-effort only.  Module may end up in odd
        # state, but the probe itself completed.
        _assert_not_lie(
            p11_module_session, entry, "CKF_VERIFY", "C_VerifyInit", rv, key_role="verify"
        )

    def test_sign_recover_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_SIGN_RECOVER)):
            pytest.skip(f"{entry.mech_name}: CKF_SIGN_RECOVER not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_SignRecoverInit", entry.mech_id)
        _assert_not_lie(
            p11_module_session, entry, "CKF_SIGN_RECOVER", "C_SignRecoverInit", rv, key_role="sign"
        )

    def test_verify_recover_flag_callable(
        self, p11_module_session: RawSession, mech_any_entry: MechEntry
    ) -> None:
        entry = mech_any_entry
        if not (entry.flags & int(CKF_VERIFY_RECOVER)):
            pytest.skip(f"{entry.mech_name}: CKF_VERIFY_RECOVER not advertised")
        rv = _probe_init_with_key(p11_module_session, "C_VerifyRecoverInit", entry.mech_id)
        _assert_not_lie(
            p11_module_session,
            entry,
            "CKF_VERIFY_RECOVER",
            "C_VerifyRecoverInit",
            rv,
            key_role="verify",
        )

"""Tests for C_GetOperationState and C_SetOperationState.

Happy-path functional tests exercising state save/restore for active operations.
Error-path CKR tests are in ckr/test_ckr_state.py.

Source: PKCS#11 v3.2 (C_GetOperationState, C_SetOperationState).

Most PKCS#11 modules return CKR_STATE_UNSAVEABLE for active operations - this is
spec-conformant behaviour (Sec.5.6.5: the token may return CKR_STATE_UNSAVEABLE if the
state cannot be saved). Tests that require a saveable state skip gracefully when the
module does not support it.

The actual state save/restore round-trip uses a ctypes subprocess to call
C_DigestInit / C_DigestUpdate / C_GetOperationState / C_SetOperationState /
C_DigestFinal directly, because the python-pkcs11 high-level API does not expose
init/update/final as individually callable Python steps for digest.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.operation_state


# ---------------------------------------------------------------------------
# Tests: high-level API availability
# ---------------------------------------------------------------------------


class TestGetOperationStateAPI:
    """Verify C_GetOperationState / C_SetOperationState are present and respond correctly."""

    def test_api_exists(self, p11_raw_session: Any) -> None:
        """Raw session exposes C_GetOperationState and C_SetOperationState."""
        rs = p11_raw_session
        assert hasattr(rs.raw, "C_GetOperationState")
        assert hasattr(rs.raw, "C_SetOperationState")

    def test_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_GetOperationState with no active operation returns known CKR.

        Spec Sec.5.6.5: if no operation is active the token must return
        CKR_OPERATION_NOT_INITIALIZED. Some modules also return
        CKR_STATE_UNSAVEABLE or CKR_FUNCTION_NOT_SUPPORTED.
        """
        import ctypes

        from pkcs11_check.raw.rv import ckr_name
        from pkcs11_check.raw.types_std import (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
        )
        from pkcs11_check.raw.types_std import (
            CKR_OK as _CKR_OK,
        )

        rs = p11_raw_session
        state_len = ctypes.c_ulong(0)
        rv = rs.raw.C_GetOperationState(rs.sh, None, ctypes.byref(state_len))
        acceptable = {
            _CKR_OK,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
            CKR_FUNCTION_NOT_SUPPORTED,
        }
        assert rv in acceptable, f"C_GetOperationState returned unexpected {ckr_name(rv)}"

    def test_garbage_state_raises_saved_state_invalid(
        self,
        p11_raw_session: Any,
    ) -> None:
        """C_SetOperationState with garbage -> CKR_SAVED_STATE_INVALID.

        Spec Sec.5.6.6: the token must return CKR_SAVED_STATE_INVALID if
        the supplied state blob is unrecognisable.
        """
        import ctypes

        from pkcs11_check.raw.types_std import (
            CKR_ARGUMENTS_BAD,
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_SAVED_STATE_INVALID,
            CKR_STATE_UNSAVEABLE,
        )

        rs = p11_raw_session
        garbage = b"\xde\xad\xbe\xef" * 16
        buf = (ctypes.c_ubyte * len(garbage))(*garbage)
        rv = rs.raw.C_SetOperationState(rs.sh, buf, len(garbage), 0, 0)
        if rv in (
            CKR_FUNCTION_NOT_SUPPORTED,
            CKR_STATE_UNSAVEABLE,
        ):
            pytest.skip("Module does not support C_SetOperationState")
        if rv == CKR_ARGUMENTS_BAD:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_SetOperationState rejected a garbage state blob with "
                "CKR_ARGUMENTS_BAD instead of the more specific "
                "CKR_SAVED_STATE_INVALID",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2 C_SetOperationState return values",
            )
        # 3-way: accepting a garbage state blob (CKR_OK) -> fail; the spec code
        # CKR_SAVED_STATE_INVALID -> pass; another clean reject (e.g.
        # CKR_OPERATION_NOT_INITIALIZED, CKR_ARGUMENTS_BAD) -> xfail.
        classify_negative_rv(
            rv,
            (CKR_SAVED_STATE_INVALID,),
            label="C_SetOperationState with a garbage state blob (PKCS#11 v3.2)",
        )


# ---------------------------------------------------------------------------
# Tests: digest state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


@pytest.mark.usefixtures("p11_module")
class TestDigestStateRoundTrip:
    """State save/restore round-trip for a SHA-256 multi-part digest.

    The python-pkcs11 high-level digest API does not expose C_DigestInit /
    C_DigestUpdate / C_DigestFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.  This also mirrors how real applications use state save/restore.
    """

    def test_digest_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """SHA-256 state save/restore on the same session produces the correct digest.

        Steps:
        1. Compute reference = SHA-256(part1 + part2) via hashlib.
        2. PKCS#11: DigestInit(SHA-256) -> DigestUpdate(part1) -> GetOperationState.
        3. SetOperationState (restore) -> DigestUpdate(part2) -> DigestFinal.
        4. Assert final digest equals reference.

        Skips when the module returns CKR_STATE_UNSAVEABLE (most software tokens
        and many hardware tokens do not support state save).
        """
        _skip_missing_mechanisms(p11_raw_session, ("SHA256",))

        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_same_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped state test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            fail_as(
                "crash",
                label="digest-state-roundtrip",
                operation="C_GetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"State round-trip digest mismatch: expected {ref!r}, got {restored!r}"
        )

    def test_digest_state_cross_session(self, p11_config: Any) -> None:
        """Restoring digest state on a second session is rejected or handled per spec.

        Spec Sec.5.6.6 notes that tokens may reject cross-session restore with
        CKR_SAVED_STATE_INVALID.  Acceptance is also implementation-defined.
        This test verifies the module does not crash and returns a CKR code.

        Skips when the module returns CKR_STATE_UNSAVEABLE at the save step.
        """
        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_cross_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped cross-session test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            fail_as(
                "crash",
                label="cross-session-state",
                operation="C_SetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "CROSS_SESSION_ACCEPTED" in lines_map or "CROSS_SESSION_REJECTED" in lines_map, (
            f"Expected CROSS_SESSION_ACCEPTED or CROSS_SESSION_REJECTED; stdout={stdout!r}"
        )

        if "CROSS_SESSION_REJECTED" in lines_map:
            # Verify the rejection code is an expected CKR value.
            # CKR_SAVED_STATE_INVALID (0x160) is mandated by spec Sec.5.6.6 for
            # cross-session restore.  Some modules may also return
            # CKR_STATE_UNSAVEABLE (0x180) or CKR_FUNCTION_NOT_SUPPORTED (0x54).
            acceptable_reject_codes = {0x160, 0x180, 0x54}
            rejected_hex = lines_map["CROSS_SESSION_REJECTED"]
            try:
                rejected_code = int(rejected_hex, 16)
            except ValueError:
                rejected_code = -1
            assert rejected_code in acceptable_reject_codes, (
                f"Cross-session restore rejected with unexpected CKR 0x{rejected_code:08x}; "
                f"expected one of {[hex(c) for c in acceptable_reject_codes]}"
            )


# ---------------------------------------------------------------------------
# Tests: encrypt state round-trip via ctypes subprocess
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestEncryptStateRoundTrip:
    """State save/restore round-trip for an AES-CBC multi-part encrypt operation.

    The python-pkcs11 high-level encrypt API does not expose C_EncryptInit /
    C_EncryptUpdate / C_EncryptFinal as individually callable Python steps, so
    these tests use a ctypes subprocess to exercise the C-level functions
    directly.

    Most modules return CKR_STATE_UNSAVEABLE for active encrypt operations - the
    tests skip gracefully when the module does not support saving encrypt state.
    """

    def test_encrypt_state_same_session(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """AES-CBC state save/restore on the same session produces correct ciphertext.

        Steps:
        1. Generate an AES-256 key via C_GenerateKey.
        2. C_EncryptInit(AES-CBC, IV) -> C_EncryptUpdate(part1) -> C_GetOperationState.
        3. C_SetOperationState (restore, passing the key handle) -> C_EncryptUpdate(part2)
           -> C_EncryptFinal.
        4. Compare with a reference encryption that does not use state save/restore.

        Skips when the module returns CKR_STATE_UNSAVEABLE or
        CKR_FUNCTION_NOT_SUPPORTED (most software tokens do not save encrypt state).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC"))

        result = run_probe(
            "operation_state",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "encrypt_same_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr

        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped encrypt state test: {lines_map['SKIP']}")

        if returncode != 0:
            fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
            detail = fatals[0] if fatals else f"stdout={stdout!r} stderr={stderr!r}"
            # Some modules return CKR_STATE_UNSAVEABLE (0x180) or
            # CKR_OPERATION_NOT_INITIALIZED (0x91) for encrypt state -- they do not
            # support saving encrypt operation state. Both are conformant:
            # CKR_STATE_UNSAVEABLE is explicitly permitted by spec Sec.5.6.5;
            # CKR_OPERATION_NOT_INITIALIZED can occur when EncryptUpdate has cleared
            # the "active operation" flag before GetOperationState is called.
            _state_codes = (
                "0x00000180",
                "STATE_UNSAVEABLE",
                "0x00000054",
                "NOT_SUPPORTED",
                "0x00000091",
                "OPERATION_NOT_INITIALIZED",
            )
            if any(code in detail for code in _state_codes):
                xfail_as(
                    "not_operational",
                    label="encrypt-state-save",
                    operation="C_GetOperationState",
                    summary=(
                        f"Module does not support saving encrypt operation state: {detail} "
                        f"(PKCS#11 spec Sec.5.6.5 CKR_STATE_UNSAVEABLE is allowed)"
                    ),
                )
            fail_as(
                "crash",
                label="encrypt-state-roundtrip",
                operation="C_GetOperationState",
                summary=f"Subprocess failed: {detail}",
                detail={"returncode": returncode},
            )

        assert "REFERENCE" in lines_map, f"Missing REFERENCE in output: {stdout!r}"
        assert "RESTORED" in lines_map, f"Missing RESTORED in output: {stdout!r}"

        ref = lines_map["REFERENCE"]
        restored = lines_map["RESTORED"]
        assert restored == ref, (
            f"Encrypt state round-trip mismatch: expected {ref!r}, got {restored!r}"
        )

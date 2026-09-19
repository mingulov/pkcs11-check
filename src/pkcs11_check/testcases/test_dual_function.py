"""Tests for dual-function operations.

Covers all four PKCS#11 dual-function operations:
  Sec.5.14.1 C_DigestEncryptUpdate  (index 54)
  Sec.5.14.2 C_DecryptDigestUpdate  (index 55)
  Sec.5.14.3 C_SignEncryptUpdate    (index 56)
  Sec.5.14.4 C_DecryptVerifyUpdate  (index 57)

Most PKCS#11 modules do NOT implement these operations and return
CKR_FUNCTION_NOT_SUPPORTED (0x54).  Some modules reject the second active
operation with CKR_OPERATION_ACTIVE (0x90) because they only allow one
active operation type per session.  Tests skip gracefully in both cases.

These operations are only available via the raw C API - python-pkcs11 has no
high-level wrappers.  The C-level init/update/final steps run in an isolated
subprocess via the ``_probes/dual_function.py`` probe module, launched with
``run_probe`` (same pattern as test_operation_state.py).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import (
    Classification,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import assert_correct

pytestmark = pytest.mark.full


def _skip_missing_mechanisms(rs: Any, names: tuple[str, ...]) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported by module")


def _skip_missing_functions(rs: Any, names: tuple[str, ...]) -> None:
    """Gate function capabilities independently from mechanism advertisement."""
    available_fn = getattr(rs.raw, "available_function_names", None)
    if not callable(available_fn):
        return
    available = set(available_fn())
    missing = [name for name in names if name not in available]
    if missing:
        pytest.skip(f"required PKCS#11 function(s) not available: {', '.join(missing)}")


def _protocol_records(stdout: str, context: str) -> tuple[list[Classification], bool]:
    """Collect semantic child markers before applying process disposition."""
    records: list[Classification] = []
    malformed = False
    for line in stdout.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            reason, kind, prefix = "not_operational", None, "SETUP_XFAIL:"
        elif line.startswith("BREAK:"):
            reason, kind, prefix = "self_contradiction", "crypto", "BREAK:"
        elif line.startswith("DEVIATION_XFAIL:"):
            reason, kind, prefix = "honest_deviation", None, "DEVIATION_XFAIL:"
        else:
            continue
        payload = line.removeprefix(prefix).strip()
        if not payload:
            malformed = True
            continue
        outcome, severity = derive_verdict(reason, kind)
        records.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=f"{context}: {payload}",
                detail={"protocol_marker": prefix.removesuffix(":")},
            )
        )
    return records, malformed


def _ckr_records(stdout: str, context: str) -> tuple[list[Classification], bool]:
    """Parse CKR:<operation>:<value> measurements without terminating early."""
    records: list[Classification] = []
    malformed = False
    for line in stdout.splitlines():
        if not line.startswith("CKR:"):
            continue
        parts = line.split(":")
        if len(parts) != 3 or not parts[1].strip():
            malformed = True
            continue
        try:
            rv = int(parts[2].strip(), 0)
        except ValueError:
            malformed = True
            continue
        if rv == 0:
            continue
        outcome, severity = derive_verdict("not_operational", "crypto")
        operation = parts[1].strip()
        records.append(
            Classification(
                reason="not_operational",
                outcome=outcome,
                severity=severity,
                kind="crypto",
                label=context,
                operation=operation,
                actual_ckr=ckr_name(rv),
                summary=f"{context}: {operation} is not operational ({ckr_name(rv)})",
                detail={"protocol_marker": "CKR", "operation": operation},
            )
        )
    return records, malformed


def _inspect_probe(
    returncode: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> tuple[list[Classification], list[Classification]]:
    """Record complete semantic evidence before signal/SEH/timeout disposition."""
    semantic, malformed_semantic = _protocol_records(stdout, context)
    measurements, malformed_ckr = _ckr_records(stdout, context)
    for item in (*semantic, *measurements):
        record(item)
    _termination, explicit_harness = assert_subprocess_completed(
        returncode, stdout, stderr, context=context
    )
    if explicit_harness:
        return semantic, measurements
    if malformed_semantic or malformed_ckr:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: malformed CKR or semantic protocol marker",
            detail={"probe_incomplete": True, "protocol": "malformed_marker"},
        )
    return semantic, measurements


def _require_result_fields(
    stdout: str,
    fields: dict[str, str],
    *,
    context: str,
    semantic: list[Classification],
    measurements: list[Classification],
    required: tuple[str, ...],
) -> None:
    """Require complete result fields after process disposition has been checked."""
    if measurements:
        _raise_provider_disposition(semantic, measurements)
    if semantic and not any(line == "OK" or line.startswith("OK:") for line in stdout.splitlines()):
        _raise_provider_disposition(semantic, measurements)
    if not any(line == "OK" or line.startswith("OK:") for line in stdout.splitlines()):
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: child subprocess did not emit a complete result",
            detail={"probe_incomplete": True, "protocol": "missing_terminal_marker"},
        )
    missing = [name for name in required if name not in fields]
    if missing:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: missing result field(s): {', '.join(missing)}",
            detail={"probe_incomplete": True, "protocol": "missing_result"},
        )


def _raise_provider_disposition(
    semantic: list[Classification], measurements: list[Classification]
) -> None:
    """Raise the strongest provider disposition already recorded."""
    for item in (*measurements, *semantic):
        if item.outcome == "fail":
            raise_for_record(item)
    if measurements:
        raise_for_record(measurements[0])
    if semantic:
        raise_for_record(semantic[0])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestDigestEncryptUpdate:
    """C_DigestEncryptUpdate functional tests (AES-CBC + SHA-256).

    C_DigestEncryptUpdate (Sec.5.14.1): Continues a multiple-part combined digest
    and encryption operation, processing another data part.  Requires both a
    digest operation and an encrypt operation to be active on the session.

    The combined operation must produce output identical to running the digest
    and encrypt operations separately over the same data.
    """

    def test_digest_encrypt_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DigestEncryptUpdate produces same ciphertext and digest as separate operations.

        Steps:
        1. Generate an AES-256 session key.
        2. Reference path - separate operations:
           a. Reference digest via hashlib SHA-256.
           b. EncryptInit(AES-CBC, key, IV) -> EncryptUpdate(data) -> EncryptFinal -> ct_ref.
        3. Dual-function path:
           a. DigestInit(SHA-256)
           b. EncryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + encrypt on the same session)
           c. DigestEncryptUpdate(data) -> ciphertext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. EncryptFinal -> remaining ciphertext
           e. DigestFinal -> digest
        4. Assert: ciphertext == ct_ref AND digest == SHA-256(data).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))
        _skip_missing_functions(
            p11_raw_session,
            (
                "C_GenerateKey",
                "C_EncryptInit",
                "C_EncryptUpdate",
                "C_EncryptFinal",
                "C_DigestInit",
                "C_DigestFinal",
                "C_DigestEncryptUpdate",
            ),
        )

        result = run_probe(
            "dual_function",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest_encrypt_update",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        semantic, measurements = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="C_DigestEncryptUpdate",
        )
        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")
        _require_result_fields(
            stdout,
            lines_map,
            context="C_DigestEncryptUpdate",
            semantic=semantic,
            measurements=measurements,
            required=("DIGEST_REF", "CT_REF", "CT_DUAL", "DIGEST_DUAL"),
        )

        ct_ref = lines_map["CT_REF"]
        ct_dual = lines_map["CT_DUAL"]
        digest_ref = lines_map["DIGEST_REF"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert_correct(
            actual=ct_dual,
            expected=ct_ref,
            label="C_DigestEncryptUpdate:ciphertext vs separate encrypt",
            operation="C_DigestEncryptUpdate",
        )
        assert_correct(
            actual=digest_dual,
            expected=digest_ref,
            label="C_DigestEncryptUpdate:digest vs reference SHA-256",
            operation="C_DigestEncryptUpdate",
        )


@pytest.mark.usefixtures("p11_module")
class TestDecryptDigestUpdate:
    """C_DecryptDigestUpdate functional tests (AES-CBC + SHA-256).

    C_DecryptDigestUpdate (Sec.5.14.2): Continues a multiple-part combined decryption
    and digest operation, processing another encrypted data part.  The ciphertext
    is decrypted and the resulting plaintext is simultaneously digested.

    The combined operation must recover the original plaintext and produce a digest
    equal to SHA-256(original plaintext).
    """

    def test_decrypt_digest_update_round_trip(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """DecryptDigestUpdate recovers plaintext and produces correct SHA-256 digest.

        Steps:
        1. Generate an AES-256 session key.
        2. Encrypt plaintext via separate C_EncryptInit/Update/Final to get ciphertext.
        3. Dual-function decryption path:
           a. DigestInit(SHA-256)
           b. DecryptInit(AES-CBC, key, IV) - skips if CKR_OPERATION_ACTIVE (module
              does not allow simultaneous digest + decrypt on the same session)
           c. DecryptDigestUpdate(ciphertext) -> plaintext_chunk - skips if
              CKR_FUNCTION_NOT_SUPPORTED
           d. DecryptFinal -> remaining plaintext
           e. DigestFinal -> digest of decrypted plaintext
        4. Assert: recovered plaintext == original data AND digest == SHA-256(data).

        Source: PKCS#11 v3.2.
        """
        _skip_missing_mechanisms(p11_raw_session, ("AES_KEY_GEN", "AES_CBC", "SHA256"))
        _skip_missing_functions(
            p11_raw_session,
            (
                "C_GenerateKey",
                "C_EncryptInit",
                "C_EncryptUpdate",
                "C_EncryptFinal",
                "C_DigestInit",
                "C_DigestFinal",
                "C_DecryptInit",
                "C_DecryptDigestUpdate",
                "C_DecryptFinal",
            ),
        )

        result = run_probe(
            "dual_function",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "decrypt_digest_update",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        semantic, measurements = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="C_DecryptDigestUpdate",
        )
        if "SKIP" in lines_map:
            pytest.skip(f"Module does not support dual-function: {lines_map['SKIP']}")
        _require_result_fields(
            stdout,
            lines_map,
            context="C_DecryptDigestUpdate",
            semantic=semantic,
            measurements=measurements,
            required=("PT_REF", "DIGEST_REF", "RECOVERED", "DIGEST_DUAL"),
        )

        pt_ref = lines_map["PT_REF"]
        digest_ref = lines_map["DIGEST_REF"]
        recovered = lines_map["RECOVERED"]
        digest_dual = lines_map["DIGEST_DUAL"]

        assert_correct(
            actual=recovered,
            expected=pt_ref,
            label="C_DecryptDigestUpdate:recovered plaintext vs reference",
            operation="C_DecryptDigestUpdate",
        )
        assert_correct(
            actual=digest_dual,
            expected=digest_ref,
            label="C_DecryptDigestUpdate:digest vs reference SHA-256",
            operation="C_DecryptDigestUpdate",
        )

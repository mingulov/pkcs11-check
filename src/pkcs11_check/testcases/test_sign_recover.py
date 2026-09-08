"""Tests for C_SignRecoverInit / C_SignRecover and C_VerifyRecoverInit / C_VerifyRecover.

Happy-path functional tests exercising sign-recover and verify-recover operations.

Source: PKCS#11 v3.2 (C_SignRecoverInit, C_SignRecover,
        C_VerifyRecoverInit, C_VerifyRecover).

C_SignRecover produces a signature from which the original data can be recovered.
C_VerifyRecover takes a signature and recovers the original data (and verifies it).
The primary mechanism is CKM_RSA_X_509 (raw RSA, no padding).

The vectors use a representative full-length input (2048 bits -> 256 bytes).  The
token performs raw modular exponentiation; the caller is responsible for any padding.
CKM_RSA_X_509 is widely supported in hardware and software tokens as the
recovery-capable RSA mechanism.

These operations are only accessible via the raw C API - python-pkcs11 does not
expose high-level sign_recover() / verify_recover() methods on Key or Session
objects.  Tests use a ctypes subprocess in the same pattern as test_operation_state.py.

CK_FUNCTION_LIST indices (0-based, after the CK_VERSION field):
  C_SignRecoverInit = 45
  C_SignRecover     = 46
  C_VerifyRecoverInit = 51
  C_VerifyRecover     = 52
  C_GenerateKeyPair   = 59
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import (
    Classification,
    classify,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_recover_single,
    verify_recover_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKM_RSA_X_509,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import assert_correct, classify_negative_rv

pytestmark = pytest.mark.full


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


def _ckr_records(stdout: str, context: str) -> tuple[list[Classification], bool, bool]:
    """Parse CKR:<operation>:<value> measurements without raising on malformed output."""
    records: list[Classification] = []
    malformed = False
    found = False
    for line in stdout.splitlines():
        if not line.startswith("CKR:"):
            continue
        found = True
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
    return records, malformed, found


def _skip_missing_functions(module: Any, names: tuple[str, ...]) -> None:
    """Gate raw function capabilities independently from mechanism support."""
    raw = getattr(module, "raw", None)
    available_fn = getattr(raw, "available_function_names", None)
    if not callable(available_fn):
        return
    available = set(available_fn())
    missing = [name for name in names if name not in available]
    if missing:
        pytest.skip(f"required PKCS#11 function(s) not available: {', '.join(missing)}")


def _inspect_probe(
    returncode: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> tuple[list[Classification], list[Classification], bool, bool]:
    """Record all provider observations, then apply signal/SEH/timeout handling."""
    semantic, malformed_semantic = _protocol_records(stdout, context)
    measurements, malformed_ckr, has_ckr = _ckr_records(stdout, context)
    for item in (*semantic, *measurements):
        record(item)
    _termination, explicit_harness = assert_subprocess_completed(
        returncode, stdout, stderr, context=context
    )
    if explicit_harness:
        return semantic, measurements, malformed_semantic or malformed_ckr, has_ckr
    if malformed_semantic or malformed_ckr:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: malformed CKR or semantic protocol marker",
            detail={"probe_incomplete": True, "protocol": "malformed_marker"},
        )
    return semantic, measurements, False, has_ckr


def _raise_provider_disposition(
    semantic: list[Classification], measurements: list[Classification]
) -> None:
    """Raise the strongest complete provider disposition after process inspection."""
    for item in (*measurements, *semantic):
        if item.outcome == "fail":
            raise_for_record(item)
    if measurements:
        raise_for_record(measurements[0])
    if semantic:
        raise_for_record(semantic[0])


def _require_result_fields(
    stdout: str,
    fields: dict[str, str],
    *,
    context: str,
    semantic: list[Classification],
    measurements: list[Classification],
    required: tuple[str, ...],
) -> None:
    """Require a complete normal-return result, except for terminal refusals."""
    if measurements:
        _raise_provider_disposition(semantic, measurements)
    if semantic and not any(line == "OK" or line.startswith("OK:") for line in stdout.splitlines()):
        _raise_provider_disposition(semantic, measurements)
    if not any(line == "OK" or line.startswith("OK:") for line in stdout.splitlines()):
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: child subprocess did not emit a complete result",
            detail={"probe_incomplete": True, "protocol": "missing_terminal_marker"},
        )
    missing = [name for name in required if name not in fields]
    if missing:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: missing result field(s): {', '.join(missing)}",
            detail={"probe_incomplete": True, "protocol": "missing_result"},
        )
    empty = [name for name in required if not fields[name].strip()]
    if empty:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: malformed empty result field(s): {', '.join(empty)}",
            detail={"probe_incomplete": True, "protocol": "malformed_result"},
        )
    hex_fields = set(required).intersection({"SIG", "ORIGINAL", "RECOVERED"})
    malformed_hex = [
        name
        for name in hex_fields
        if len(fields[name]) % 2
        or any(char not in "0123456789abcdefABCDEF" for char in fields[name])
    ]
    if malformed_hex:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: malformed hexadecimal result field(s): {', '.join(malformed_hex)}",
            detail={"probe_incomplete": True, "protocol": "malformed_result"},
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestSignRecover:
    """C_SignRecover / C_VerifyRecover functional tests using CKM_RSA_X_509.

    C_SignRecover (Sec.5.10.6): Signs data with a private key using a mechanism
    that allows the original data to be recovered from the signature.

    C_VerifyRecover (Sec.5.11.6): Verifies a signature and recovers the original
    data from the signature using the corresponding public key.

    CKM_RSA_X_509 (raw RSA) is the standard mechanism for these operations.
    The vectors use a representative full-length input (2048 bits -> 256 bytes).
    """

    def test_sign_recover_produces_output(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with RSA X.509 produces a 256-byte signature block.

        Steps:
        1. Generate RSA-2048 key pair with CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER.
        2. C_SignRecoverInit(CKM_RSA_X_509, privateKey).
        3. C_SignRecover(padded_data) -> signature.
        4. Verify signature length equals modulus size (256 bytes).

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")
        _skip_missing_functions(
            p11_module,
            ("C_GenerateKeyPair", "C_SignRecoverInit", "C_SignRecover"),
        )

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_recover_produces_output",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        semantic, measurements, _malformed, _has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="sign-recover subprocess",
        )
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover: {lines_map['SKIP']}")
        _require_result_fields(
            stdout,
            lines_map,
            context="sign-recover subprocess",
            semantic=semantic,
            measurements=measurements,
            required=("SIG_LEN", "SIG"),
        )
        try:
            sig_len = int(lines_map["SIG_LEN"], 0)
        except (TypeError, ValueError):
            fail_as(
                "harness_error",
                label="sign-recover subprocess",
                summary=f"Malformed SIG_LEN result: {lines_map.get('SIG_LEN')!r}",
                detail={"probe_incomplete": True, "protocol": "malformed_result"},
            )
        assert_correct(
            actual=sig_len,
            expected=256,
            label="C_SignRecover signature length",
            operation="C_SignRecover",
            mechanism="CKM_RSA_X_509",
            kind="metadata",
        )

    def test_verify_recover_round_trip(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover then C_VerifyRecover recovers the original padded data.

        Steps:
        1. Generate RSA-2048 key pair.
        2. C_SignRecoverInit -> C_SignRecover(padded_data) -> signature.
        3. C_VerifyRecoverInit -> C_VerifyRecover(signature) -> recovered_data.
        4. Assert recovered_data == padded_data.

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")
        _skip_missing_functions(
            p11_module,
            (
                "C_GenerateKeyPair",
                "C_SignRecoverInit",
                "C_SignRecover",
                "C_VerifyRecoverInit",
                "C_VerifyRecover",
            ),
        )

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify_recover_round_trip",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        semantic, measurements, _malformed, _has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="sign/verify-recover subprocess",
        )
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign/verify-recover: {lines_map['SKIP']}")
        _require_result_fields(
            stdout,
            lines_map,
            context="sign/verify-recover subprocess",
            semantic=semantic,
            measurements=measurements,
            required=("ORIGINAL", "RECOVERED"),
        )

        original = lines_map["ORIGINAL"]
        recovered = lines_map["RECOVERED"]
        assert_correct(
            actual=recovered,
            expected=original,
            label="CKM_RSA_X_509:Sign/VerifyRecover round-trip",
            operation="C_VerifyRecover",
            mechanism="CKM_RSA_X_509",
        )

    def test_sign_recover_wrong_data_length(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with oversize data returns a PKCS#11 error (not a crash).

        For CKM_RSA_X_509 with a 2048-bit key, inputs up to 256 bytes are valid.
        Passing 257 bytes must return CKR_DATA_LEN_RANGE.  CKR_ARGUMENTS_BAD or any
        other clean rejection is a non-spec provider deviation; the module must not
        crash or silently succeed.

        Source: PKCS#11 v3.1, Table 41 (C_SignRecover input-length constraint);
        §5.13.6 (C_SignRecover return values).
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")
        _skip_missing_functions(
            p11_module,
            ("C_GenerateKeyPair", "C_SignRecoverInit", "C_SignRecover"),
        )

        result = run_probe(
            "sign_recover",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign_recover_wrong_data_length",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
        lines_map = _parse_output(stdout)

        semantic, measurements, _malformed, _has_ckr = _inspect_probe(
            returncode,
            stdout,
            stderr,
            context="sign-recover length subprocess",
        )
        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover error test: {lines_map['SKIP']}")
        _require_result_fields(
            stdout,
            lines_map,
            context="sign-recover length subprocess",
            semantic=semantic,
            measurements=measurements,
            required=("RESULT",),
        )

        # The module must reject an input larger than the RSA modulus.  Inputs at
        # or below k are valid for CKM_RSA_X_509, so this vector deliberately uses k+1.
        result_line = lines_map["RESULT"]
        expected_rejections = (CKR_DATA_LEN_RANGE,)
        if result_line == "ACCEPTED_OVERSIZE_DATA":
            classify_negative_rv(
                CKR_OK,
                expected_rejections,
                label="CKM_RSA_X_509:C_SignRecover oversize data",
                kind="crypto",
            )
        elif result_line.startswith("REJECTED:"):
            rv_text = result_line.removeprefix("REJECTED:").strip()
            try:
                rv = int(rv_text, 0)
            except ValueError:
                fail_as(
                    "harness_error",
                    label="sign-recover length subprocess",
                    summary=f"Malformed RESULT CKR: {rv_text!r}",
                    detail={"probe_incomplete": True, "protocol": "malformed_result"},
                )
            classify_negative_rv(
                rv,
                expected_rejections,
                label="CKM_RSA_X_509:C_SignRecover oversize data",
                kind="crypto",
            )
        else:
            fail_as(
                "harness_error",
                label="sign-recover length subprocess",
                summary=f"Malformed RESULT marker: {result_line!r}",
                detail={"probe_incomplete": True, "protocol": "malformed_result"},
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _has_rsa_x509(p11_module: Any) -> bool:
    """Return True if the module's first token supports CKM_RSA_X_509."""
    slots = list(p11_module.get_slots(token_present=True))
    if not slots:
        return False

    mechs = {getattr(m, "name", str(m)) for m in slots[0].get_mechanisms()}
    return "RSA_X_509" in mechs


class TestSignRecoverRecipes:
    """In-process tests exercising sign_recover_single / verify_recover_single recipes."""

    @staticmethod
    def _check_sign_recover(rs: Any) -> None:
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        try:
            mech = mech_simple(CKM_RSA_X_509)
            rv = rs.raw.C_SignRecoverInit(rs.sh, mech.byref(), 0)
        except (AttributeError, TypeError):
            pytest.skip("C_SignRecoverInit not available")
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("C_SignRecover not supported by module")

    @staticmethod
    def _gen_recover_key(rs: Any) -> tuple[int, int]:
        TestSignRecoverRecipes._check_sign_recover(rs)
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)

    def test_sign_recover_single_returns_signature(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            assert isinstance(sig, bytes)
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_round_trip(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should recover the original data from a valid signature.

        Some modules recover wrong/unexpected data on CKM_RSA_X_509 --
        the recovered bytes do not match the original padded input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, sig)
            assert valid is True
            # Raw RSA (CKM_RSA_X_509) VerifyRecover returns sig^e mod n, i.e. the signed
            # value AS AN INTEGER. Compare as integers so a benign leading-zero / length
            # representation difference is not mis-flagged. A genuine integer mismatch IS a
            # crypto-correctness break (the module recovered the wrong value) -> wrong_result
            # (crypto fail), not a tolerable deviation. (Any documented per-module bug is
            # cross-referenced as KNOWN_ISSUE at the report layer, not hidden here.)
            recovered_int = int.from_bytes(recovered, "big") if recovered else -1
            if recovered_int != int.from_bytes(data, "big"):
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover recovered data",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        "C_VerifyRecover recovered the wrong value for CKM_RSA_X_509 "
                        "(recovered integer != signed integer) -- crypto-correctness break"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_invalid_signature(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should reject an invalid signature.

        Some modules return valid=True and non-empty recovered data for an
        invalid (all-zero) signature block, failing to detect the invalid input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            bad_sig = b"\x00" * 256
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, bad_sig)
            if valid is True or recovered != b"":
                classify(
                    "honest_deviation",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover invalid signature",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        f"Module C_VerifyRecover accepted invalid all-zero signature: "
                        f"valid={valid}, recovered={recovered!r} -- "
                        f"the signature block is not validated in C_VerifyRecover"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.classification import HARNESS_REASONS, get_records, serialize
from pkcs11_check.core.subprocess_trace import (
    drain_subprocess_rv_trace,
)
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import _CK_ULONG_MAX, CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.health import outcome_counts
from pkcs11_check.testcases._probes import ckr_raw_multipart as multipart_probe
from pkcs11_check.testcases._probes import ckr_v30_raw, ckr_v32_raw
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from pkcs11_check.testcases.ckr import (
    test_ckr_dual,
    test_ckr_fault_inject,
    test_ckr_null_params,
    test_ckr_raw_args_bad,
    test_ckr_raw_multipart,
    test_ckr_raw_state,
    test_ckr_universal,
    test_ckr_v30_raw,
    test_ckr_v32_raw,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

RawCheck = Callable[[int, str, str, str], None]


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


def test_v30_probe_returns_normally_after_unexpected_ckr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ctx = SimpleNamespace(
        raw=SimpleNamespace(C_MessageEncryptInit=lambda *_args: 0x00000007),
        sh=1,
    )

    ckr_v30_raw._message_encrypt_mech_invalid(ctx)

    assert capsys.readouterr().out == (
        "RESULT:C_MessageEncryptInit:CKR:0x00000007\nOK:C_MessageEncryptInit\n"
    )


def test_v32_probe_returns_normally_after_unexpected_ckr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ctx = SimpleNamespace(
        raw=SimpleNamespace(C_VerifySignatureInit=lambda *_args: 0x00000000),
        sh=1,
    )

    ckr_v32_raw._verify_signature_mech_invalid(ctx)

    assert capsys.readouterr().out == (
        "RESULT:C_VerifySignatureInit:CKR:0x00000000\nOK:C_VerifySignatureInit\n"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_signal_as_crash(check: RawCheck) -> None:
    """Negative subprocess return codes are crash findings."""
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        check(-11, "", "segmentation fault", "C_Test")


@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_positive_exit_as_subprocess_failure(check: RawCheck) -> None:
    """Assertion failures inside the child process are not crash findings.

    Here the parent can say more than "the child exited 1": the bare ``CKR:`` line is a
    legacy marker this protocol no longer accepts, which is a defect in our own probe.
    A positively identified cause outranks the unresolved-attribution fallback, and
    `harness_error` is earned rather than inferred.
    """
    with pytest.raises(pytest.fail.Exception, match="invalid child result protocol"):
        check(1, "CKR:0x00000007", "AssertionError: unexpected CKR", "C_Test")

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_v30_raw_message_encrypt_dispatches_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migrated v3.0 CKR test dispatches the ``ckr_v30_raw`` probe via run_probe.

    Replaces the deleted white-box script-string assertion for ``test_ckr_v30_raw``:
    the PIN routes through run_probe's ``pin=`` only (never the params), and the probe
    name + ``probe`` key select the right child body.
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(
            returncode=0,
            stdout="RESULT:C_MessageEncryptInit:CKR:0x00000070\nOK:C_MessageEncryptInit\n",
            stderr="",
        )

    monkeypatch.setattr(test_ckr_v30_raw, "run_probe", fake_run_probe)

    test_ckr_v30_raw.TestMessageEncryptErrors().test_mechanism_invalid(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_v30_raw"
    assert params["probe"] == "message_encrypt_mech_invalid"


def test_v32_raw_verify_signature_dispatches_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migrated v3.2 CKR test dispatches the ``ckr_v32_raw`` probe via run_probe.

    Replaces the deleted white-box rv-trace / script-string assertion for
    ``test_ckr_v32_raw`` (its hand-rolled child-script generation is gone; rv-trace
    preservation is now covered by the shared ``probe_main`` infra).  The PIN routes
    through run_probe's ``pin=`` only (never the params), and the probe name +
    ``probe`` key select the right child body.
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(
            returncode=0,
            stdout="RESULT:C_VerifySignatureInit:CKR:0x00000070\nOK:C_VerifySignatureInit\n",
            stderr="",
        )

    monkeypatch.setattr(test_ckr_v32_raw, "run_probe", fake_run_probe)

    test_ckr_v32_raw.TestVerifySignatureErrors().test_mechanism_invalid(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_v32_raw"
    assert params["probe"] == "verify_signature_mech_invalid"


def test_ckr_subprocess_helper_reports_positive_exit_as_child_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_ckr_subprocess_ok(
            1,
            "",
            "AssertionError: setup failed",
            context="CKR setup probe",
        )


def test_ckr_subprocess_helper_converts_setup_marker_to_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="AES key generation rejected"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            context="CKR setup probe",
        )


def test_clean_positive_exit_is_not_crash() -> None:
    """A complete CKR protocol on an unexplained positive exit is not a crash.

    It is not a harness defect either: nothing here identifies a cause. The record must
    stay a loud provider-side fail with attribution stated as unresolved, because the
    child's streams are just as likely to hold a module observation as our own bug.
    """
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_ckr_subprocess_ok(
            1,
            "CKR:0x00000007\nOK:C_Test rejected the mechanism\n",
            "",
            context="C_Test CKR probe",
        )

    records = get_records()
    assert [record.reason for record in records] == ["probe_incomplete"]
    assert records[0].reason not in HARNESS_REASONS
    assert "NOT the module under test" not in (records[0].summary or "")
    assert records[0].detail is not None
    assert records[0].detail["probe_incomplete"] is True
    assert records[0].detail["termination"]["kind"] == "exit"


def test_v3_result_protocol_classifies_clean_wrong_ckr_as_provider_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="non-spec rejection"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x00000007\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["nonspec_reject"]
    assert records[0].actual_ckr == "CKR_ARGUMENTS_BAD"
    assert records[0].expected_ckr == ["CKR_MECHANISM_INVALID"]


@pytest.mark.parametrize(
    ("check", "func", "phase"),
    [
        (test_ckr_v30_raw._check, "C_MessageEncryptInit", "C_MessageEncryptInit"),
        (test_ckr_v32_raw._check, "C_WrapKeyAuthenticated", "C_WrapKeyAuthenticated"),
        (test_ckr_v32_raw._check, "C_AsyncGetID", "C_AsyncGetID"),
        (test_ckr_v32_raw._check, "C_DecapsulateKey", "C_DecapsulateKey"),
    ],
)
def test_v3_clean_function_not_supported_skips_and_is_not_a_deviation(
    check: RawCheck, func: str, phase: str
) -> None:
    """CKR_FUNCTION_NOT_SUPPORTED is capability absence: a skip, never a deviation.

    It must also never be a *pass*. A pass asserts the module answered the negative op
    correctly when in fact it declined the function outright, which erases the
    observation from the report and inflates the provider's PASS count. The skip keeps
    the declining function named.

    ``pytest.xfail()``/``pytest.fail()`` raise ``OutcomeException`` subclasses that
    ``pytest.raises(pytest.fail.Exception, ...)`` would silently let through as an
    uncaught (green-exit) xfail rather than a hard test failure -- catch both
    explicitly and turn either into a real assertion failure.
    """
    try:
        check(
            0,
            f"RESULT:{phase}:CKR:0x00000054\nOK:{phase}\n",
            "",
            func,
        )
    except (pytest.xfail.Exception, pytest.fail.Exception) as exc:
        pytest.fail(f"{func}: clean CKR_FUNCTION_NOT_SUPPORTED must not be a deviation: {exc!r}")
    except pytest.skip.Exception as exc:
        assert func in str(exc)
        assert phase in str(exc)
        assert "CKR_FUNCTION_NOT_SUPPORTED" in str(exc)
    else:
        pytest.fail(f"{func}: clean CKR_FUNCTION_NOT_SUPPORTED must skip, not pass silently")

    assert get_records() == []


def test_v3_result_protocol_classifies_ckr_ok_as_provider_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted invalid"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x00000000\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["accepted_invalid"]
    assert records[0].actual_ckr == "CKR_OK"


def test_v3_hollow_ok_without_result_is_probe_incomplete() -> None:
    with pytest.raises(pytest.fail.Exception, match="missing_result"):
        test_ckr_v30_raw._check(0, "OK:C_MessageEncryptInit\n", "", "C_MessageEncryptInit")

    records = get_records()
    assert [record.reason for record in records] == ["probe_incomplete"]
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "missing_result"


def test_v3_duplicate_result_is_harness_only_and_not_provider_evidence() -> None:
    with pytest.raises(pytest.fail.Exception, match="duplicate_result"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x00000070\n"
            "RESULT:C_MessageEncryptInit:CKR:0x00000007\n"
            "OK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "duplicate_result"


def test_v3_mixed_result_phases_are_harness_only() -> None:
    with pytest.raises(pytest.fail.Exception, match="unexpected_result_phase"):
        test_ckr_v32_raw._check(
            0,
            "RESULT:C_VerifySignature:CKR:0x00000091\nOK:C_VerifySignatureInit\n",
            "",
            "C_VerifySignatureInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "unexpected_result_phase"


def test_v32_null_probe_requires_each_distinct_phase() -> None:
    with pytest.raises(pytest.fail.Exception, match="wrong_result_cardinality"):
        test_ckr_v32_raw._check(
            0,
            "RESULT:C_EncapsulateKey.pMechanism:CKR:0x00000070\nOK:C_EncapsulateKey_NULLs\n",
            "",
            "C_EncapsulateKey_NULLs",
        )

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]


def test_v32_null_probe_accepts_all_expected_negative_results() -> None:
    test_ckr_v32_raw._check(
        0,
        "RESULT:C_EncapsulateKey.pMechanism:CKR:0x00000007\n"
        "RESULT:C_EncapsulateKey.pulCiphertextLen:CKR:0x00000007\n"
        "OK:C_EncapsulateKey_NULLs\n",
        "",
        "C_EncapsulateKey_NULLs",
    )

    assert get_records() == []


def test_v32_null_probe_acceptance_failure_dominates_clean_deviation() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted invalid"):
        test_ckr_v32_raw._check(
            0,
            "RESULT:C_EncapsulateKey.pMechanism:CKR:0x00000070\n"
            "RESULT:C_EncapsulateKey.pulCiphertextLen:CKR:0x00000000\n"
            "OK:C_EncapsulateKey_NULLs\n",
            "",
            "C_EncapsulateKey_NULLs",
        )

    records = get_records()
    assert [record.reason for record in records] == ["nonspec_reject", "accepted_invalid"]


def test_v3_setup_and_result_are_mixed_harness_evidence() -> None:
    with pytest.raises(pytest.fail.Exception, match="mixed_terminal_markers"):
        test_ckr_v30_raw._check(
            0,
            "SETUP_XFAIL:C_Login rejected with CKR_GENERAL_ERROR\n"
            "RESULT:C_MessageEncryptInit:CKR:0x00000070\n"
            "OK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]


@pytest.mark.parametrize(
    ("rc", "err", "failure"),
    [
        pytest.param(
            -11,
            "segmentation fault",
            "module crashed with signal 11",
            marks=pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics"),
        ),
        (124, f"{SUBPROCESS_TIMEOUT_MARKER}:30s", "timed out"),
        (
            1,
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
            "module crashed",
        ),
    ],
)
def test_v32_partial_prefix_survives_crash_without_cardinality_record(
    rc: int,
    err: str,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if rc == 1:
        monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match=failure):
        test_ckr_v32_raw._check(
            rc,
            "RESULT:C_EncapsulateKey.pMechanism:CKR:0x00000000\n",
            err,
            "C_EncapsulateKey_NULLs",
        )

    records = get_records()
    assert [record.reason for record in records] == ["accepted_invalid", "crash"]
    assert all(
        record.detail is None or record.detail.get("protocol") != "wrong_result_cardinality"
        for record in records
    )


def test_v3_wrong_terminal_phase_is_harness_only() -> None:
    with pytest.raises(pytest.fail.Exception, match="unexpected_terminal_phase"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x00000000\nOK:C_EncryptMessage\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]


def test_v3_distinct_setup_markers_are_harness_only() -> None:
    with pytest.raises(pytest.fail.Exception, match="duplicate_marker"):
        test_ckr_v30_raw._check(
            0,
            "SETUP_XFAIL:first setup refusal\nSETUP_XFAIL:second setup refusal\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_v3_distinct_skip_markers_are_harness_only() -> None:
    with pytest.raises(pytest.fail.Exception, match="duplicate_marker"):
        test_ckr_v30_raw._check(
            0,
            "SKIP:v2.40_only\nSKIP:no_v3_funcs\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_v3_skip_token_must_be_possible_for_the_checked_function() -> None:
    with pytest.raises(pytest.fail.Exception, match="invalid_skip_token"):
        test_ckr_v30_raw._check(
            0,
            "SKIP:no_SessionCancel\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_v3_bare_ok_is_not_a_terminal_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed_terminal_marker"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x00000070\nOK\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_v3_measurement_marker_is_not_a_provider_result() -> None:
    with pytest.raises(pytest.fail.Exception, match="unexpected_result_marker"):
        test_ckr_v30_raw._check(
            0,
            "MEASUREMENT:C_MessageEncryptInit:CKR:0x00000000\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    "result_marker",
    [
        "RESULT:C_MessageEncryptInit:0x00000070",
        "RESULT:C_MessageEncryptInit:0x00000000",
    ],
)
def test_v3_result_requires_literal_ckr_field(result_marker: str) -> None:
    try:
        test_ckr_v30_raw._check(
            0,
            f"{result_marker}\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )
    except BaseException:
        pass

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "malformed_result"


def test_v3_arbitrary_setup_payload_is_harness_only() -> None:
    try:
        test_ckr_v30_raw._check(
            0,
            "SETUP_XFAIL:key setup rejected\n",
            "",
            "C_MessageEncryptInit",
        )
    except BaseException:
        pass

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "invalid_setup_marker"


@pytest.mark.parametrize(
    "setup_marker",
    [
        "SETUP_XFAIL:C_Initialize rejected with CKR_GENERAL_ERROR",
        "SETUP_XFAIL:C_GetSlotList rejected with 0x00000007",
        "SETUP_XFAIL:C_GetSlotList rejected with 0x80000001",
        "SETUP_XFAIL:no slot with a present token",
        "SETUP_XFAIL:C_OpenSession rejected with CKR_DEVICE_ERROR",
        "SETUP_XFAIL:C_Login rejected with 0x00000007",
    ],
)
def test_v3_level_login_setup_markers_are_provider_refusals(setup_marker: str) -> None:
    with pytest.raises(pytest.xfail.Exception):
        test_ckr_v30_raw._check(
            0,
            f"{setup_marker}\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert records[0].expected_ckr == ["CKR_OK"]


@pytest.mark.parametrize(
    ("check", "setup_marker"),
    [
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with CKR_OK",
        ),
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with 0x00000000",
        ),
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with CKR_CRYPTOKI_ALREADY_INITIALIZED",
        ),
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with 0x00000191",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with CKR_OK",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with 0x00000000",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with CKR_CRYPTOKI_ALREADY_INITIALIZED",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Initialize rejected with 0x00000191",
        ),
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Login rejected with CKR_USER_ALREADY_LOGGED_IN",
        ),
        (
            test_ckr_v30_raw._check,
            "SETUP_XFAIL:C_Login rejected with 0x00000100",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Login rejected with CKR_USER_ALREADY_LOGGED_IN",
        ),
        (
            test_ckr_v32_raw._check,
            "SETUP_XFAIL:C_Login rejected with 0x00000100",
        ),
    ],
)
def test_v3_setup_success_states_are_harness_only(check: RawCheck, setup_marker: str) -> None:
    try:
        check(1, f"{setup_marker}\n", "setup child failed", "C_Test")
    except BaseException:
        pass

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "impossible_setup_result"


def test_v3_unknown_symbolic_setup_ckr_is_harness_only() -> None:
    try:
        test_ckr_v30_raw._check(
            1,
            "SETUP_XFAIL:C_Login rejected with CKR_NOT_A_REAL_RV\n",
            "setup child failed",
            "C_Test",
        )
    except BaseException:
        pass

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "invalid_setup_marker"


@pytest.mark.parametrize(
    "setup_marker",
    [
        "SETUP_XFAIL: C_Login rejected with CKR_GENERAL_ERROR",
        "SETUP_XFAIL:C_Login rejected with CKR_GENERAL_ERROR ",
    ],
)
def test_v3_setup_whitespace_is_harness_only(setup_marker: str) -> None:
    try:
        test_ckr_v30_raw._check(1, f"{setup_marker}\n", "setup child failed", "C_Test")
    except BaseException:
        pass

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "invalid_setup_marker"


def test_v3_skip_whitespace_is_harness_only() -> None:
    try:
        test_ckr_v30_raw._check(
            1,
            "SKIP:no_v3_funcs \n",
            "setup child failed",
            "C_MessageEncryptInit",
        )
    except BaseException:
        pass

    records = get_records()
    assert records
    assert all(record.reason == "harness_error" for record in records)
    assert records[0].detail is not None
    assert records[0].detail["protocol"] == "invalid_skip_token"


def test_v3_undefined_numeric_setup_ckr_is_self_contradiction() -> None:
    try:
        test_ckr_v30_raw._check(
            0,
            "SETUP_XFAIL:C_Login rejected with 0x100000007\n",
            "",
            "C_MessageEncryptInit",
        )
    except BaseException:
        pass

    records = get_records()
    assert [record.reason for record in records] == ["self_contradiction"]
    assert records[0].actual_ckr == "0x100000007"
    assert records[0].expected_ckr == ["CKR_OK"]
    assert records[0].kind == "metadata"


def test_v3_high_width_undefined_ckr_is_provider_self_contradiction() -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        test_ckr_v30_raw._check(
            0,
            "RESULT:C_MessageEncryptInit:CKR:0x100000007\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    records = get_records()
    assert [record.reason for record in records] == ["self_contradiction"]
    assert records[0].actual_ckr == "0x100000007"
    assert records[0].expected_ckr == ["CKR_MECHANISM_INVALID"]
    assert records[0].kind == "metadata"


@pytest.mark.parametrize(
    "result_marker",
    [
        "RESULT:C_MessageEncryptInit:CKR:0x0000000A",
        "RESULT:C_MessageEncryptInit:CKR:0x10000000000000000",
    ],
)
def test_v3_ckr_hex_shape_rejects_uppercase_and_overwidth(
    result_marker: str,
) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed_result"):
        test_ckr_v30_raw._check(
            0,
            f"{result_marker}\nOK:C_MessageEncryptInit\n",
            "",
            "C_MessageEncryptInit",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_zero_exit_missing_terminal_marker_is_incomplete() -> None:
    with pytest.raises(pytest.fail.Exception, match="terminal marker"):
        assert_ckr_subprocess_ok(0, "CKR:0x00000007\n", "", context="C_Test CKR probe")

    records = get_records()
    assert [record.reason for record in records] == ["probe_incomplete"]
    assert records[0].detail is not None
    assert records[0].detail["probe_incomplete"] is True
    assert records[0].detail["termination"]["kind"] == "exit"
    assert records[0].detail["termination"]["raw_code"] == 0


def test_incidental_ok_substring_is_not_completion() -> None:
    with pytest.raises(pytest.fail.Exception, match="terminal marker"):
        assert_ckr_subprocess_ok(
            0,
            "NOT_OK: provider said OK in prose\noperation was not OK\n",
            "",
            context="C_Test CKR probe",
        )

    assert [record.reason for record in get_records()] == ["probe_incomplete"]


def test_break_survives_earlier_setup_xfail() -> None:
    with pytest.raises(pytest.fail.Exception, match="forbidden operation"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:key setup rejected\nBREAK:forbidden operation produced output\n",
            "",
            context="C_Test CKR probe",
        )

    records = get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "self_contradiction",
    ]
    assert records[0].outcome == "xfail"
    assert records[1].outcome == "fail"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_crash_survives_earlier_skip_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        assert_ckr_subprocess_ok(
            -11,
            "SETUP_XFAIL:key setup rejected\n",
            "segmentation fault",
            context="C_Test CKR probe",
        )

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]
    assert records[1].detail is not None
    assert records[1].detail["termination"]["kind"] == "signal"


def test_windows_seh_positive_exit_is_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        assert_ckr_subprocess_ok(
            1,
            "SETUP_XFAIL:key setup rejected\n",
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
            context="C_Test CKR probe",
        )

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]
    record = records[-1]
    assert record.detail is not None
    assert record.detail["termination"]["kind"] == "exception"
    assert record.detail["termination"]["raw_code"] == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize(
    ("check", "func", "skip"),
    [
        (test_ckr_v30_raw._check, "C_MessageEncryptInit", "no_v3_funcs"),
        (test_ckr_v32_raw._check, "C_VerifySignatureInit", "no_v32_funcs"),
    ],
)
def test_v3_skip_marker_does_not_hide_signal_crash(check: RawCheck, func: str, skip: str) -> None:
    """A capability skip is provisional until the child process disposition is known."""
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        check(-11, f"SKIP:{skip}\n", "segmentation fault", func)

    records = get_records()
    assert [item.reason for item in records] == ["crash"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize("check", [test_ckr_v30_raw._check, test_ckr_v32_raw._check])
def test_v3_break_evidence_survives_signal_crash(check: RawCheck) -> None:
    """A semantic provider finding remains visible when the child later crashes."""
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        check(
            -11,
            "RESULT:C_Test:CKR:0x00000000\nOK:C_Test\n",
            "segmentation fault",
            "C_Test",
        )

    records = get_records()
    assert [item.reason for item in records] == ["accepted_invalid", "crash"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize("check", [test_ckr_v30_raw._check, test_ckr_v32_raw._check])
def test_v3_result_survives_signal_before_completion_marker(check: RawCheck) -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        check(
            -11,
            "RESULT:C_Test:CKR:0x00000000\n",
            "segmentation fault",
            "C_Test",
        )

    records = get_records()
    assert [item.reason for item in records] == ["accepted_invalid", "crash"]


@pytest.mark.parametrize("check", [test_ckr_v30_raw._check, test_ckr_v32_raw._check])
def test_v3_semantic_evidence_survives_cleanup_failure(check: RawCheck) -> None:
    check(
        0,
        "RESULT:C_Test:CKR:0x00000000\nOK:C_Test\nHARNESS_ERROR:cleanup failed after measurement\n",
        "",
        "C_Test",
    )

    assert [item.reason for item in get_records()] == ["accepted_invalid", "harness_error"]


@pytest.mark.parametrize(
    ("check", "func", "skip"),
    [
        (test_ckr_v30_raw._check, "C_MessageEncryptInit", "no_v3_funcs"),
        (test_ckr_v32_raw._check, "C_VerifySignatureInit", "no_v32_funcs"),
    ],
)
def test_v3_skip_marker_does_not_hide_windows_seh(
    check: RawCheck, func: str, skip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A positive Windows exit carrying an access violation remains a crash."""
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        check(
            1,
            f"SKIP:{skip}\n",
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
            func,
        )

    records = get_records()
    assert [item.reason for item in records] == ["crash"]


@pytest.mark.parametrize(
    ("check", "func", "skip"),
    [
        (test_ckr_v30_raw._check, "C_MessageEncryptInit", "no_v3_funcs"),
        (test_ckr_v32_raw._check, "C_VerifySignatureInit", "no_v32_funcs"),
    ],
)
def test_v3_skip_marker_does_not_hide_timeout(check: RawCheck, func: str, skip: str) -> None:
    """A timeout is a crash-class finding even if setup emitted a skip marker."""
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        check(
            124,
            f"SKIP:{skip}\n",
            f"{SUBPROCESS_TIMEOUT_MARKER}:15s\n",
            func,
        )

    records = get_records()
    assert [item.reason for item in records] == ["crash"]


@pytest.mark.parametrize("check", [test_ckr_v30_raw._check, test_ckr_v32_raw._check])
def test_v3_complete_semantic_evidence_survives_cleanup_failure(check: RawCheck) -> None:
    """A provider semantic finding and a later harness cleanup defect are additive."""
    check(
        0,
        "RESULT:C_Test:CKR:0x00000000\nOK:C_Test\nHARNESS_ERROR:cleanup failed after measurement\n",
        "",
        "C_Test",
    )

    records = get_records()
    assert [item.reason for item in records] == ["accepted_invalid", "harness_error"]


@pytest.mark.parametrize("check", [test_ckr_v30_raw._check, test_ckr_v32_raw._check])
def test_v3_duplicate_semantic_marker_is_one_harness_record(check: RawCheck) -> None:
    with pytest.raises(pytest.fail.Exception, match="duplicate_result"):
        check(
            0,
            "RESULT:C_Test:CKR:0x00000000\nRESULT:C_Test:CKR:0x00000000\nOK:C_Test\n",
            "",
            "C_Test",
        )

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_malformed_terminal_marker_is_probe_incomplete() -> None:
    with pytest.raises(pytest.fail.Exception, match="terminal marker"):
        assert_ckr_subprocess_ok(0, "OKAY:almost complete\n", "", context="C_Test CKR probe")

    record = get_records()[-1]
    assert record.reason == "probe_incomplete"
    assert record.detail is not None
    assert record.detail["protocol"] == "missing_terminal_marker"
    assert record.detail["termination"]["kind"] == "exit"
    assert record.detail["termination"]["raw_code"] == 0


@pytest.mark.parametrize(
    "marker",
    ["SETUP_XFAIL:", "BREAK:", "DEVIATION_XFAIL:"],
)
def test_empty_semantic_marker_is_harness_evidence(marker: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        assert_ckr_subprocess_ok(0, f"{marker}   \n", "", context="C_Test CKR probe")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    record = records[0]
    assert record.summary
    assert record.detail is not None
    assert record.detail["protocol"] == "malformed_marker"
    assert record.detail["termination"]["kind"] == "exit"
    assert record.detail["termination"]["raw_code"] == 0


def test_explicit_harness_marker_is_terminal_for_ckr_measurement() -> None:
    stdout = "CKR:0x00000007\nHARNESS_ERROR:cleanup failed after measurement\n"
    assert_ckr_subprocess_ok(0, stdout, "", context="C_Test CKR probe")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].detail is not None
    assert records[0].detail["termination"]["kind"] == "exit"


def test_malformed_marker_and_cleanup_keep_distinct_harness_records() -> None:
    stdout = "SETUP_XFAIL:   \nHARNESS_ERROR:cleanup failed after measurement\n"
    assert_ckr_subprocess_ok(0, stdout, "", context="C_Test CKR probe")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "harness_error"]
    assert records[0].detail is not None
    assert records[1].detail is not None
    assert records[0].detail != records[1].detail
    assert "protocol" not in records[0].detail
    assert records[1].detail["protocol"] == "malformed_marker"


def test_cleanup_harness_keeps_valid_semantic_failure() -> None:
    stdout = (
        "RESULT:C_Test:CKR:0x00000000\nOK:C_Test\nHARNESS_ERROR:cleanup failed after measurement\n"
    )
    test_ckr_v30_raw._check(0, stdout, "", "C_Test")

    records = get_records()
    assert [record.reason for record in records] == ["accepted_invalid", "harness_error"]
    assert records.count(records[-1]) == 1
    assert records[-1].reason == "harness_error"


def test_fault_proxy_dispatches_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migrated fault-proxy CKR test dispatches the ``ckr_fault_inject`` probe.

    Replaces the deleted white-box script-string / rv-trace assertion for
    ``test_ckr_fault_inject`` (its hand-rolled child-script generation is gone; rv-trace
    preservation is now covered by the shared ``probe_main`` infra).  ``module_path`` is the
    fault-proxy; the real module rides in the probe params as plain data (``real_module``,
    never a PIN), and the probe name + ``probe`` key select the right child body.
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:encrypt_decrypt_roundtrip\n", stderr="")

    monkeypatch.setattr(test_ckr_fault_inject, "_skip_if_no_proxy", lambda: None)
    monkeypatch.setattr(test_ckr_fault_inject, "_PROXY_PATH", "/tmp/fault-proxy.so")
    monkeypatch.setattr(test_ckr_fault_inject, "run_probe", fake_run_probe)

    test_ckr_fault_inject.TestFaultProxyBasic().test_proxy_encrypt_decrypt(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_fault_inject"
    assert params["probe"] == "proxy_encrypt_decrypt"
    assert params["real_module"] == "/tmp/provider.so"


def test_double_encrypt_init_dispatches_state_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-EncryptInit state test dispatches the operation-state probe.

    (rv-trace preservation is now handled + covered in the shared ``probe_main``
    infra, so the legacy in-script rv-trace assertions are dropped here.)
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000000\nOK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_state, "run_probe", fake_run_probe)

    test_ckr_raw_state.TestOperationActive().test_double_encrypt_init(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_state"
    assert params["probe"] == "double_encrypt_init"


def test_multipart_encrypt_update_dispatches_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migrated multipart CKR test dispatches the ``ckr_raw_multipart`` probe.

    Replaces the deleted white-box rv-trace / script-string assertion for
    ``test_ckr_raw_multipart`` (its hand-rolled child-script generation is gone; rv-trace
    preservation is now covered by the shared ``probe_main`` infra).  The PIN routes through
    run_probe's ``pin=`` only (never the params), and the probe name + ``probe`` key select
    the right child body.
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="CKR:0x00000091\nOK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_multipart, "run_probe", fake_run_probe)

    test_ckr_raw_multipart.TestMultipartNotInitialized().test_encrypt_update_no_init(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_multipart"
    assert params["probe"] == "encrypt_update"


def test_ckr_null_result_positive_exit_records_child_trace() -> None:
    """Parent-side NULL probe failures must retain child RV trace output."""
    marker = (
        'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_OpenSession","rv":176,"rv_name":"CKR_SESSION_COUNT"}]'
    )

    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        test_ckr_null_params._check_null_result("C_GenerateRandom", 1, marker, "")

    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_OpenSession", "rv": 176, "rv_name": "CKR_SESSION_COUNT"}
    ]


def test_ckr_null_result_parses_ckr_before_trace_marker() -> None:
    """Trace marker lines appended to stdout must not break CKR parsing."""
    test_ckr_null_params._check_null_result(
        "C_GetInfo",
        0,
        'CKR:0x00000007\nP11_RV_TRACE_JSON:[{"i":0,"fn":"C_GetInfo","rv":7}]',
        "",
    )
    assert drain_subprocess_rv_trace() == [{"i": 0, "fn": "C_GetInfo", "rv": 7}]


def test_ckr_subprocess_helper_requires_ok_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="did not emit an OK marker"):
        assert_ckr_subprocess_ok(0, "CKR:0x00000000\n", "", context="CKR setup probe")


def test_universal_fault_proxy_dispatches_device_removed_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fault-proxy universal test dispatches the device-removed probe.

    module_path is the fault-proxy; the real module + injection config ride in the
    probe params as plain data (never a PIN).  (rv-trace preservation is now handled +
    covered in the shared ``probe_main`` infra, so the legacy in-script rv-trace
    assertions are dropped here.)
    """
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:DEVICE_REMOVED\n", stderr="")

    monkeypatch.setattr(Path, "exists", lambda _self: True)
    monkeypatch.setattr(test_ckr_universal, "run_probe", fake_run_probe)

    test_ckr_universal.TestUniversalRealTriggers().test_device_removed_via_fault_proxy(
        SimpleNamespace(module="/tmp/provider.so")
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_universal"
    assert params["probe"] == "device_removed"
    assert params["real_module"] == "/tmp/provider.so"


def test_raw_args_bad_setup_marker_is_xfail() -> None:
    """NULL-mechanism rows should classify failed setup key generation."""
    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ckr_raw_args_bad._assert_ok(
            0,
            "SETUP_XFAIL:AES setup unavailable: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            "C_EncryptInit(NULL mech)",
        )


def test_raw_args_bad_encrypt_null_mech_dispatches_encrypt_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encrypt-init NULL-mechanism test dispatches the encrypt-init probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_args_bad, "run_probe", fake_run_probe)

    test_ckr_raw_args_bad.TestArgsBadNullPointers().test_encrypt_init_null_mechanism(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_args_bad"
    assert params["probe"] == "encrypt_init"


def test_raw_args_bad_generate_key_null_mech_dispatches_generate_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generate-key NULL-mechanism test dispatches the generate-key probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    monkeypatch.setattr(test_ckr_raw_args_bad, "run_probe", fake_run_probe)

    test_ckr_raw_args_bad.TestArgsBadNullPointers().test_generate_key_null_mechanism(
        SimpleNamespace(module="/tmp/provider.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_raw_args_bad"
    assert params["probe"] == "generate_key"


def test_ckr_dual_reports_positive_subprocess_exit_as_child_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR operation-state child assertion exits must not be labelled crashes."""

    def fake_run_probe(probe: str, params: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="AssertionError: setup failed",
        )

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))


def test_ckr_dual_encrypt_wrapper_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="128-bit key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_encrypt_twice_succeeds(rs)


def test_ckr_dual_sign_then_encrypt_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (10, 11),
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", lambda *_args, **_kwargs: (10, 11))
    monkeypatch.setattr(test_ckr_dual, "sign_single", lambda *_args, **_kwargs: b"s" * 256)
    monkeypatch.setattr(test_ckr_dual, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN", "RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="128-bit key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_sign_then_encrypt(rs)


def test_encrypt_without_init_dispatches_encrypt_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encrypt-without-init test dispatches its own probe (no AES key setup)."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:encrypt_without_init\n", stderr="")

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_dual"
    assert params["probe"] == "encrypt_without_init"


def test_double_digest_init_dispatches_digest_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-DigestInit test dispatches the operation-active probe."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_run_probe(probe: str, params: dict[str, Any], **_kwargs: Any) -> SimpleNamespace:
        calls.append((probe, params))
        return SimpleNamespace(returncode=0, stdout="OK:double_digest_init_active\n", stderr="")

    monkeypatch.setattr(test_ckr_dual, "run_probe", fake_run_probe)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_double_digest_init_via_subprocess(
        SimpleNamespace(module="/fake/p11.so", pin=None)
    )

    assert len(calls) == 1
    probe, params = calls[0]
    assert probe == "ckr_dual"
    assert params["probe"] == "double_digest_init"


# --- QF5 multipart-family rollout: after-final setup refusals (fw#28) ---
#
# Each fake refuses exactly one setup call with CKR_FUNCTION_FAILED (0x06)
# and records every raw call. The post-final target Update must never run
# (exact call-sequence assertion), cleanup effects are preserved, and the
# refusal path emits a lone SETUP_REFUSED marker (no legacy text, no CKR
# measurement, no OK completion).


class _MultipartDigestFake:
    def __init__(self, refuse: str) -> None:
        self._refuse = refuse
        self.calls: list[str] = []

    def _rv(self, op: str) -> int:
        self.calls.append(op)
        return 0x06 if op == self._refuse else 0

    def C_DigestInit(self, *args: Any) -> int:  # noqa: N802
        return self._rv("C_DigestInit")

    def C_DigestUpdate(self, *args: Any) -> int:  # noqa: N802
        return self._rv("C_DigestUpdate")

    def C_DigestFinal(self, *args: Any) -> int:  # noqa: N802
        return self._rv("C_DigestFinal")


class _MultipartEncryptFake:
    def __init__(self, refuse: str) -> None:
        self._refuse = refuse
        self.calls: list[str] = []

    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_GenerateKey")
        if self._refuse == "C_GenerateKey":
            return 0x06
        args[-1]._obj.value = 7
        return 0

    def C_EncryptInit(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_EncryptInit")
        return 0x06 if self._refuse == "C_EncryptInit" else 0

    def C_EncryptUpdate(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_EncryptUpdate")
        return 0x06 if self._refuse == "C_EncryptUpdate" else 0

    def C_EncryptFinal(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_EncryptFinal")
        return 0x06 if self._refuse == "C_EncryptFinal" else 0

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_DestroyObject")
        return 0


@pytest.mark.parametrize(
    ("probe", "op", "refuse", "expected_calls"),
    [
        (
            "_digest_update_after_final",
            "C_DigestInit",
            "C_DigestInit",
            ["C_DigestInit"],
        ),
        (
            "_digest_update_after_final",
            "C_DigestUpdate",
            "C_DigestUpdate",
            ["C_DigestInit", "C_DigestUpdate"],
        ),
        (
            "_digest_update_after_final",
            "C_DigestFinal",
            "C_DigestFinal",
            ["C_DigestInit", "C_DigestUpdate", "C_DigestFinal"],
        ),
        (
            "_encrypt_update_after_final",
            "C_GenerateKey",
            "C_GenerateKey",
            ["C_GenerateKey"],
        ),
        (
            "_encrypt_update_after_final",
            "C_EncryptInit",
            "C_EncryptInit",
            ["C_GenerateKey", "C_EncryptInit", "C_DestroyObject"],
        ),
        (
            "_encrypt_update_after_final",
            "C_EncryptUpdate",
            "C_EncryptUpdate",
            ["C_GenerateKey", "C_EncryptInit", "C_EncryptUpdate", "C_DestroyObject"],
        ),
        (
            "_encrypt_update_after_final",
            "C_EncryptFinal",
            "C_EncryptFinal",
            [
                "C_GenerateKey",
                "C_EncryptInit",
                "C_EncryptUpdate",
                "C_EncryptFinal",
                "C_DestroyObject",
            ],
        ),
    ],
)
def test_migrated_multipart_site_emits_setup_refused(
    probe: str,
    op: str,
    refuse: str,
    expected_calls: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """QF5 multipart rollout: each refused setup emits SETUP_REFUSED, target unrun."""
    if probe == "_digest_update_after_final":
        fake: Any = _MultipartDigestFake(refuse)
    else:
        fake = _MultipartEncryptFake(refuse)
    ctx = ProbeContext(
        raw=cast(Any, fake),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    getattr(multipart_probe, probe)(ctx)
    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    assert "SETUP_XFAIL" not in out
    assert not any(line.startswith("CKR:") for line in out.splitlines())
    assert "OK" not in out.splitlines()
    assert fake.calls == expected_calls


def test_shared_helper_records_structured_setup_refusal() -> None:
    """QF5: the shared CKR helper attributes a refusal to the setup op + RV."""
    with pytest.raises(pytest.xfail.Exception, match="setup C_EncryptInit refused"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_REFUSED:C_EncryptInit:0x00000006\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    setup = [
        record
        for record in get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(setup) == 1
    record = setup[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.operation == "C_EncryptInit"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert "target untested" in record.summary
    assert record.detail is not None
    assert record.detail["setup_operation"] == "C_EncryptInit"
    assert record.detail["setup_rv"] == 0x06
    assert record.detail["target_reached"] is False


@pytest.mark.parametrize(
    "line",
    [
        "SETUP_REFUSED:\n",
        "SETUP_REFUSED:not-a-payload\n",
        "SETUP_REFUSED:C_EncryptInit:-1\n",
        "SETUP_REFUSED:!!!:0x6\n",
        "SETUP_REFUSED:C_EncryptInit:0x0\n",
        f"SETUP_REFUSED:C_EncryptInit:0x{_CK_ULONG_MAX + 1:X}\n",
        "SETUP_REFUSED:C_A:B:0x6\n",
        "SETUP_REFUSED:C_!!!:0x6\n",
    ],
)
def test_shared_helper_malformed_refusal_is_harness_error(line: str) -> None:
    """QF5: empty/garbage/contradictory/unrepresentable refusals fail loud."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        assert_ckr_subprocess_ok(0, line, "", context="C_EncryptUpdate after C_EncryptFinal")
    assert any(record.reason == "harness_error" for record in get_records())


def test_shared_helper_max_ulong_refusal_still_xfails() -> None:
    """QF5: the largest representable CK_RV is a refusal, not malformed (boundary)."""
    with pytest.raises(pytest.xfail.Exception, match="setup C_EncryptInit refused"):
        assert_ckr_subprocess_ok(
            0,
            f"SETUP_REFUSED:C_EncryptInit:0x{_CK_ULONG_MAX:X}\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )


@pytest.mark.parametrize(
    "stdout",
    [
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nSETUP_REFUSED:C_GenerateKey:0x00000006\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nSETUP_XFAIL:legacy key setup refused\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nDEVIATION_XFAIL:safely refused at end\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nOK\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nCKR:0x00000091\nOK\n",
        "CKR:0x00000091\nSETUP_REFUSED:C_GenerateKey:0x00000006\n",
        "SETUP_REFUSED:not-a-payload\nSETUP_XFAIL:legacy key setup refused\n",
    ],
)
def test_shared_helper_refusal_contradictions_are_malformed(stdout: str) -> None:
    """QF5: duplicate/contradictory refusals fail loud, never xfail."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        assert_ckr_subprocess_ok(0, stdout, "", context="C_EncryptUpdate after C_EncryptFinal")
    assert any(record.reason == "harness_error" for record in get_records())


def test_shared_helper_refusal_contradiction_with_provider_fail_raises_fail() -> None:
    """QF5: fail-before-malformed -- parsed provider evidence beats the protocol failure."""
    stdout = (
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "BREAK:target produced output after refused setup\n"
    )
    with pytest.raises(pytest.fail.Exception, match="target produced output"):
        assert_ckr_subprocess_ok(0, stdout, "", context="C_EncryptUpdate after C_EncryptFinal")
    assert any(record.reason == "self_contradiction" for record in get_records())


@pytest.mark.parametrize(
    "empty_marker",
    ["SETUP_XFAIL:", "DEVIATION_XFAIL:", "BREAK:"],
)
@pytest.mark.parametrize("refusal_first", [True, False])
def test_shared_helper_refusal_beside_empty_marker_is_malformed(
    empty_marker: str, refusal_first: bool
) -> None:
    """Fix round 1: a valid refusal must not override an empty legacy marker.

    Either order fails loud as malformed-marker harness evidence. The xfail
    branch is caught explicitly: an uncaught refusal xfail would report as an
    expected xfail and mask the defect this test pins.
    """
    refusal = "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
    malformed_line = f"{empty_marker}\n"
    stdout = refusal + malformed_line if refusal_first else malformed_line + refusal
    try:
        assert_ckr_subprocess_ok(0, stdout, "", context="C_EncryptUpdate after C_EncryptFinal")
    except pytest.xfail.Exception as exc:
        # Caught first: XFailed subclasses Failed in this pytest, so the fail
        # branch below would otherwise swallow the exact regression pinned here.
        pytest.fail(f"refusal overrode empty {empty_marker} marker with xfail: {exc!r}")
    except pytest.fail.Exception as exc:
        assert "malformed" in str(exc)
    else:
        pytest.fail(f"refusal beside empty {empty_marker} marker must fail loud")
    assert any(record.reason == "harness_error" for record in get_records())


def test_shared_helper_empty_marker_with_refusal_keeps_provider_fail_first() -> None:
    """Fix round 1: parsed provider BREAK still beats refusal+empty-marker evidence."""
    stdout = (
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "SETUP_XFAIL:\n"
        "BREAK:target produced output after refused setup\n"
    )
    with pytest.raises(pytest.fail.Exception, match="target produced output"):
        assert_ckr_subprocess_ok(0, stdout, "", context="C_EncryptUpdate after C_EncryptFinal")
    assert any(record.reason == "self_contradiction" for record in get_records())


def test_shared_helper_lone_refusal_without_completion_still_xfails() -> None:
    """QF5: a lone refusal without OK is terminal, not probe_incomplete."""
    with pytest.raises(pytest.xfail.Exception, match="setup C_DigestInit refused"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_REFUSED:C_DigestInit:0x00000006\n",
            "",
            context="C_DigestUpdate after C_DigestFinal",
        )
    assert [record.reason for record in get_records()] == ["not_operational"]


def test_shared_helper_legacy_setup_marker_keeps_leniency() -> None:
    """QF5 pin: legacy SETUP_XFAIL (even beside OK/duplicates) still xfails."""
    with pytest.raises(pytest.xfail.Exception, match="legacy key setup refused"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:legacy key setup refused\nOK\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:first setup refusal\nSETUP_XFAIL:second setup refusal\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )


def test_shared_helper_refusal_survives_json_grouping_without_target_credit(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """QF5 + fix round 1: captured M7 probe output keeps attribution via grouping.

    End-to-end: production multipart probe (C_EncryptFinal refused) →
    production parent → production ``extract_groups``. The refusing op/RV
    survive grouping; the untested post-final C_EncryptUpdate gets no credit.
    """
    fake = _MultipartEncryptFake("C_EncryptFinal")
    ctx = ProbeContext(
        raw=cast(Any, fake),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    multipart_probe._encrypt_update_after_final(ctx)
    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_EncryptFinal:0x00000006" in out
    with pytest.raises(pytest.xfail.Exception, match="setup C_EncryptFinal refused"):
        assert_ckr_subprocess_ok(
            0,
            out,
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py::Test::after_final",
    )
    assert len(groups) == 1
    grp = groups[0]
    assert grp["operation"] == "C_EncryptFinal"
    assert grp["expected_ckr"] == ["CKR_OK"]
    assert grp["actual_ckr"] == "CKR_FUNCTION_FAILED"
    assert grp["reason"] == "not_operational"
    assert grp["outcome"] == "xfail"
    assert grp["detail"]["setup_operation"] == "C_EncryptFinal"
    assert grp["detail"]["setup_rv"] == 0x06
    assert grp["detail"]["target_reached"] is False
    assert grp["count"] == 1
    assert all(group["operation"] != "C_EncryptUpdate" for group in groups)
    counts = outcome_counts(groups)
    assert counts["xfail"] == 1
    assert counts["fail"] == 0
    assert counts["harness_error"] == 0
    assert counts["crash"] == 0


# --- Fix round 1: multipart end-to-end grouping proof + grouping controls ---


@pytest.mark.parametrize(
    ("probe", "refuse", "op", "target"),
    [
        ("_digest_update_after_final", "C_DigestInit", "C_DigestInit", "C_DigestUpdate"),
        ("_digest_update_after_final", "C_DigestUpdate", "C_DigestUpdate", None),
        ("_digest_update_after_final", "C_DigestFinal", "C_DigestFinal", "C_DigestUpdate"),
        ("_encrypt_update_after_final", "C_GenerateKey", "C_GenerateKey", "C_EncryptUpdate"),
        ("_encrypt_update_after_final", "C_EncryptInit", "C_EncryptInit", "C_EncryptUpdate"),
        ("_encrypt_update_after_final", "C_EncryptUpdate", "C_EncryptUpdate", None),
        ("_encrypt_update_after_final", "C_EncryptFinal", "C_EncryptFinal", "C_EncryptUpdate"),
    ],
)
def test_injected_multipart_refusals_survive_production_grouping(
    probe: str,
    refuse: str,
    op: str,
    target: str | None,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Fix round 1: every injected multipart refusal keeps attribution via grouping.

    End-to-end per site: production probe → production parent → production
    ``extract_groups``. Same-name setup/target sites (pre-final Update refused)
    keep attribution via target_reached=false + xfail; distinct-target sites
    additionally credit no group to the untested post-final Update.
    """
    fake: Any
    if probe == "_digest_update_after_final":
        fake = _MultipartDigestFake(refuse)
        context = "C_DigestUpdate after C_DigestFinal"
    else:
        fake = _MultipartEncryptFake(refuse)
        context = "C_EncryptUpdate after C_EncryptFinal"
    ctx = ProbeContext(
        raw=cast(Any, fake),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    getattr(multipart_probe, probe)(ctx)
    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    with pytest.raises(pytest.xfail.Exception, match=f"setup {op} refused"):
        assert_ckr_subprocess_ok(0, out, "", context=context)
    groups = _grouped_parent_records(
        tmp_path,
        f"src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py::Test::{probe}",
    )
    assert len(groups) == 1
    grp = groups[0]
    assert grp["operation"] == op
    assert grp["expected_ckr"] == ["CKR_OK"]
    assert grp["actual_ckr"] == "CKR_FUNCTION_FAILED"
    assert grp["reason"] == "not_operational"
    assert grp["outcome"] == "xfail"
    assert grp["detail"]["setup_operation"] == op
    assert grp["detail"]["setup_rv"] == 0x06
    assert grp["detail"]["target_reached"] is False
    assert grp["count"] == 1
    if target is not None:
        assert all(group["operation"] != target for group in groups)
    counts = outcome_counts(groups)
    assert counts["xfail"] == 1
    assert counts["fail"] == 0
    assert counts["harness_error"] == 0
    assert counts["crash"] == 0


def test_grouped_identical_refusals_merge_across_nodeids(tmp_path: Path) -> None:
    """Fix round 1 merge control: grouping merges identical keys (count 2).

    A serialization round-trip alone can never merge; count==2 with both
    nodeids proves the production grouping ran.
    """
    with pytest.raises(pytest.xfail.Exception, match="setup C_GenerateKey refused"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_REFUSED:C_GenerateKey:0x00000006\n",
            "",
            context="CKR operation-state raw probe",
        )
    payload = json.loads(json.dumps(serialize(get_records())))
    base = "src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py::Test"
    groups = extract_groups(
        _write_report_jsonl(
            tmp_path, [(f"{base}::test_one", payload), (f"{base}::test_two", payload)]
        ),
        crashes=[],
    )
    assert len(groups) == 1
    assert groups[0]["operation"] == "C_GenerateKey"
    assert groups[0]["count"] == 2
    assert len(groups[0]["nodeids"]) == 2


def test_grouped_legacy_setup_xfail_keeps_unattributed_operation(tmp_path: Path) -> None:
    """Fix round 1 legacy control: free-text refusals group without an operation."""
    with pytest.raises(pytest.xfail.Exception, match="legacy key setup refused"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:legacy key setup refused\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py::Test::legacy",
    )
    assert len(groups) == 1
    assert groups[0]["reason"] == "not_operational"
    assert groups[0]["operation"] is None
    assert groups[0]["outcome"] == "xfail"


def test_grouped_refusal_contradiction_accounts_harness_error(tmp_path: Path) -> None:
    """Fix round 1 malformed control: refusal+OK groups a harness_error failure."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_REFUSED:C_GenerateKey:0x00000006\nOK\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py::Test::contradiction",
    )
    # Both observations survive grouping; the raised headline was the failure.
    assert sorted(group["reason"] for group in groups) == [
        "harness_error",
        "not_operational",
    ]
    failed = [group for group in groups if group["reason"] == "harness_error"]
    assert len(failed) == 1
    assert failed[0]["outcome"] == "fail"
    counts = outcome_counts(groups)
    assert counts["harness_error"] == 1
    assert counts["xfail"] == 1
    assert counts["fail"] == 0
    assert counts["crash"] == 0


def test_grouped_provider_break_accounts_fail(tmp_path: Path) -> None:
    """Fix round 1 provider control: BREAK groups as a self_contradiction fail."""
    with pytest.raises(pytest.fail.Exception, match="target produced output"):
        assert_ckr_subprocess_ok(
            0,
            "BREAK:target produced output after refused setup\n",
            "",
            context="C_EncryptUpdate after C_EncryptFinal",
        )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py::Test::provider_fail",
    )
    assert len(groups) == 1
    assert groups[0]["reason"] == "self_contradiction"
    assert groups[0]["outcome"] == "fail"
    counts = outcome_counts(groups)
    assert counts["fail"] == 1
    assert counts["xfail"] == 0
    assert counts["harness_error"] == 0


# --- Fix round 1: production JSONL/grouping test helpers (finding 2) ---


def _write_report_jsonl(tmp_path: Path, entries: list[tuple[str, list[Any]]]) -> Path:
    """Write TestReport lines carrying phase-scoped pkcs11_classification lists.

    Same record shape the runner persists (cf. test_report_extract.py); the
    payload round-trips through JSON exactly as the JSONL artifact requires.
    """
    lines = [
        {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": nodeid,
            "outcome": "failed",
            "user_properties": [["pkcs11_classification", payload]],
        }
        for nodeid, payload in entries
    ]
    path = tmp_path / "report.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


def _grouped_parent_records(tmp_path: Path, nodeid: str) -> list[dict[str, Any]]:
    """Feed parent records through the production JSONL report grouping."""
    payload = json.loads(json.dumps(serialize(get_records())))
    return extract_groups(_write_report_jsonl(tmp_path, [(nodeid, payload)]), crashes=[])

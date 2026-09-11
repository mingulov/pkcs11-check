"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.classification import HARNESS_REASONS, get_records
from pkcs11_check.core.subprocess_trace import (
    drain_subprocess_rv_trace,
)
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases._probes import ckr_v30_raw, ckr_v32_raw
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


def test_v3_hollow_ok_without_result_is_harness_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="missing_result"):
        test_ckr_v30_raw._check(0, "OK:C_MessageEncryptInit\n", "", "C_MessageEncryptInit")

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
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
        (-11, "segmentation fault", "module crashed with signal 11"),
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
    assert [record.reason for record in records] == ["harness_error"]
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

    assert [record.reason for record in get_records()] == ["harness_error"]


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


def test_malformed_terminal_marker_is_harness_evidence() -> None:
    with pytest.raises(pytest.fail.Exception, match="terminal marker"):
        assert_ckr_subprocess_ok(0, "OKAY:almost complete\n", "", context="C_Test CKR probe")

    record = get_records()[-1]
    assert record.reason == "harness_error"
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

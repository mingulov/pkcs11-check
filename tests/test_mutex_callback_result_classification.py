"""Runtime classification regressions for raw mutex callback probes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.types_std import CKR_CANT_LOCK, CKR_FUNCTION_FAILED
from pkcs11_check.testcases import test_mutex_callback_safety as mutex
from pkcs11_check.testcases._probes.runner import ProbeResult
from tests._skip_assert import assert_skips


def test_mutex_missing_rv_is_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout="OK\n", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="harness"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert get_records()[-1].reason == "harness_error"


def test_mutex_missing_rv_after_signal_is_not_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=-11, stdout="", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["crash"]


def test_mutex_cleanup_preserves_setup_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                "SETUP_XFAIL:provider refused initialization\n"
                "HARNESS_ERROR:cleanup failed after setup\n"
            ),
            stderr="",
        ),
    )
    mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
        SimpleNamespace(module="x", slot=0, pin=None)
    )
    assert [item.reason for item in get_records()] == ["harness_error", "harness_error"]


def test_mutex_cleanup_preserves_provider_rv_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="RV=0x00000000\nHARNESS_ERROR:cleanup failed after result\n",
            stderr="",
        ),
    )
    mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
        SimpleNamespace(module="x", slot=0, pin=None)
    )
    assert [item.reason for item in get_records()] == ["honest_deviation", "harness_error"]


def test_mutex_provider_rv_survives_outer_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=-11, stdout="RV=0x00000000\n", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["honest_deviation", "crash"]


def test_mutex_duplicate_rv_is_one_harness_record(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="RV=0x00000000\nRV=0x00000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate RV"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_duplicate_setup_has_no_provider_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:provider refused\nSETUP_XFAIL:provider refused again\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate setup"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_setup_and_rv_conflict_is_harness_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:provider refused\nRV=0x00000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="setup/result"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_setup_marker_is_always_harness_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:provider refused\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="unexpected setup"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_non_hex_rv_marker_is_harness_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout="RV=7\n", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed RV"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_64bit_shaped_undefined_create_rv_is_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="RV=0x1000000000000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction"]


def test_mutex_64bit_shaped_undefined_lock_rv_is_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=("INIT_RV=0x00000000\nCALL_RV=0x1000000000000000\n"),
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction"]


@pytest.mark.parametrize("marker", ["RV=0x00000000 ", "RV= 0x00000000"])
def test_mutex_whitespace_in_rv_marker_is_harness_error(
    monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=f"{marker}\n", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed RV"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("INIT_RV= 0x00000000", "malformed INIT_RV"),
        ("CALL_RV=0x00000000 ", "malformed CALL_RV"),
    ],
)
def test_mutex_whitespace_in_lock_marker_is_harness_error(
    monkeypatch: pytest.MonkeyPatch, marker: str, expected: str
) -> None:
    stdout = marker if marker.startswith("INIT_RV=") else f"INIT_RV=0x00000000\n{marker}"
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=f"{stdout}\n", stderr=""),
    )
    with pytest.raises(pytest.fail.Exception, match=expected):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_reversed_lock_markers_are_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CALL_RV=0x00000006\nINIT_RV=0x00000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="marker order"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_call_only_protocol_is_recorded_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout="CALL_RV=0x00000006\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


def test_mutex_lock_ok_call_ok_records_ignored_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="INIT_RV=0x00000000\nCALL_RV=0x00000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    records = get_records()
    assert [item.reason for item in records] == ["honest_deviation"]
    assert records[0].kind == "lifecycle"


def test_mutex_lock_defined_nonzero_call_result_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"INIT_RV=0x00000000\nCALL_RV=0x{int(CKR_FUNCTION_FAILED):08x}\n"),
            stderr="",
        ),
    )
    mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
        SimpleNamespace(module="x", slot=0, pin=None)
    )
    assert get_records() == []


def test_mutex_duplicate_lock_result_is_harness_only_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout="INIT_RV=0x00000000\nCALL_RV=0x00000000\nCALL_RV=0x00000006\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


def test_mutex_lock_missing_init_rv_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CALL_RV=0x00000006\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="marker order"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]


def test_mutex_lock_defined_init_refusal_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"INIT_RV=0x{int(CKR_FUNCTION_FAILED):08x}\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.xfail.Exception):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["nonspec_reject"]


def test_mutex_lock_cant_lock_is_the_only_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"INIT_RV=0x{int(CKR_CANT_LOCK):08x}\n",
            stderr="",
        ),
    )
    assert_skips(
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call,
        SimpleNamespace(module="x", slot=0, pin=None),
    )
    assert get_records() == []


def test_mutex_create_defined_nonzero_callback_result_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"RV=0x{int(CKR_FUNCTION_FAILED):08x}\n",
            stderr="",
        ),
    )
    mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
        SimpleNamespace(module="x", slot=0, pin=None)
    )
    assert get_records() == []


def test_mutex_lock_undefined_init_refusal_fails_as_protocol_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="INIT_RV=0x7fffffff\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        mutex.TestMutexCallbackErrorHandling().test_lock_mutex_callback_returning_general_error_during_call(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["self_contradiction"]


def test_mutex_protocol_error_is_recorded_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout="RV=0x00000000\nRV=0x00000000\n",
            stderr="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        mutex.TestMutexCallbackErrorHandling().test_create_mutex_callback_returning_general_error(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error", "crash"]


def test_mutex_python_exception_requires_exact_result_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mutex,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout="", stderr="traceback"),
    )
    with pytest.raises(pytest.fail.Exception, match="missing RV"):
        mutex.TestMutexCallbackErrorHandling().test_python_exception_in_create_mutex_callback(
            SimpleNamespace(module="x", slot=0, pin=None)
        )
    assert [item.reason for item in get_records()] == ["harness_error"]

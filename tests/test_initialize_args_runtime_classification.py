"""Runtime classification meta-tests for test_initialize_args arg guards (Phase 4 N2).

C_Initialize arg-validation guards (non-NULL pReserved, partial mutex callbacks)
expect CKR_ARGUMENTS_BAD per spec Sec.5.4. Converted from a flat
``assert rv == CKR_ARGUMENTS_BAD`` to a 3-way classification:

- ``CKR_OK`` (module accepted the spec-violating arg) -> ``xfail`` (honest
  non-compliance, not security-impacting; symmetric with the pReserved sibling),
- ``CKR_ARGUMENTS_BAD`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.

A real segfault on these probes still ``fail``s via the existing rc<0 guard.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_CANT_LOCK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_FUNCTION_FAILED,
    CKR_OK,
)
from pkcs11_check.testcases import test_initialize_args as tia


def _patch(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (0, f"RV=0x{int(rv):08x}", ""),
    )


_CASES = ("test_init_reserved_non_null_rejected", "test_init_partial_callbacks_rejected")


@pytest.mark.parametrize("method", _CASES)
def test_accepted_xfails(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_OK))
    with pytest.raises(pytest.xfail.Exception):
        getattr(tia.TestInitArgsMatrix(), method)(_config())


@pytest.mark.parametrize("method", _CASES)
def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_ARGUMENTS_BAD))
    getattr(tia.TestInitArgsMatrix(), method)(_config())


@pytest.mark.parametrize("method", _CASES)
def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    _patch(monkeypatch, int(CKR_FUNCTION_FAILED))
    with pytest.raises(pytest.xfail.Exception):
        getattr(tia.TestInitArgsMatrix(), method)(_config())


def test_initialize_args_positive_seh_is_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            1,
            "RV=0x00000000\n",
            "OSError: exception: access violation reading 0xFFFFFFFFFFFFFFFF",
        ),
    )
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        tia.TestInitArgsMatrix().test_init_null_args(_config())

    assert [item.reason for item in get_records()] == ["crash"]


def test_initialize_args_missing_rv_after_signal_is_not_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tia, "_run_init_args_probe", lambda *_a, **_k: (-11, "", ""))
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        tia.TestInitArgsMatrix().test_init_null_args(_config())

    assert [item.reason for item in get_records()] == ["crash"]


def test_initialize_args_cleanup_preserves_setup_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:C_Initialize refused with 0x00000006\n"
            "HARNESS_ERROR:cleanup failed after setup\n",
            "",
        ),
    )
    tia.TestFinalizeArgs().test_finalize_reserved_non_null(_config())

    assert [item.reason for item in get_records()] == ["not_operational", "harness_error"]


def test_initialize_args_cleanup_preserves_provider_rv_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "RV=0x00000000\nHARNESS_ERROR:cleanup failed after result\n",
            "",
        ),
    )
    tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["honest_deviation", "harness_error"]


def test_initialize_args_provider_rv_survives_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (-11, "RV=0x00000000\n", ""),
    )
    with pytest.raises(pytest.fail.Exception, match="crashed"):
        tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["honest_deviation", "crash"]


def test_initialize_args_duplicate_rv_is_one_harness_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (0, "RV=0x00000000\nRV=0x00000000\n", ""),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate RV"):
        tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_duplicate_setup_has_no_provider_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:provider refused\nSETUP_XFAIL:provider refused again\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate setup"):
        tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_setup_and_rv_conflict_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:provider refused\nRV=0x00000000\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="setup/result"):
        tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_setup_refusal_is_rejected_for_init_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (0, "SETUP_XFAIL:C_Initialize refused with 0x00000006\n", ""),
    )
    with pytest.raises(pytest.fail.Exception, match="unexpected setup"):
        tia.TestInitArgsMatrix().test_init_null_args(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_finalize_zero_setup_rv_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:C_Initialize refused with 0x00000000\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        tia.TestFinalizeArgs().test_finalize_reserved_non_null(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_wrong_family_markers_are_harness_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "RV=0x00000000\nINIT_RV=0x00000000\nCALL_RV=0x00000000\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="wrong result marker"):
        tia.TestInitArgsMatrix().test_init_reserved_non_null_rejected(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_64bit_shaped_undefined_rv_is_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, 0x1000000000000000)
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        tia.TestInitArgsMatrix().test_init_null_args(_config())

    assert [item.reason for item in get_records()] == ["self_contradiction"]


def test_initialize_args_allowed_init_state_cannot_be_setup_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:C_Initialize refused with "
            f"0x{int(CKR_CRYPTOKI_ALREADY_INITIALIZED):08x}\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="malformed setup"):
        tia.TestFinalizeArgs().test_finalize_reserved_non_null(_config())

    assert [item.reason for item in get_records()] == ["harness_error"]


def test_initialize_args_64bit_undefined_setup_rv_is_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tia,
        "_run_init_args_probe",
        lambda *_a, **_k: (
            0,
            "SETUP_XFAIL:C_Initialize refused with 0x1000000000000000\n",
            "",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        tia.TestFinalizeArgs().test_finalize_reserved_non_null(_config())

    assert [item.reason for item in get_records()] == ["self_contradiction"]


def test_initialize_args_positive_clean_refusal_is_not_raw_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, int(CKR_FUNCTION_FAILED))
    with pytest.raises(pytest.xfail.Exception):
        tia.TestInitArgsMatrix().test_init_null_args(_config())

    records = get_records()
    assert [item.reason for item in records] == ["not_operational"]
    assert records[0].actual_ckr == "CKR_FUNCTION_FAILED"


def test_initialize_args_allowed_cant_lock_remains_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, int(CKR_CANT_LOCK))
    tia.TestInitArgsMatrix().test_init_app_mutex_callbacks(_config())
    assert get_records() == []


def _config() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(module="x", slot=0, pin=None, token_label=None)

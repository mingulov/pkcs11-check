from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED, CKR_OPERATION_NOT_INITIALIZED
from pkcs11_check.testcases import test_remaining_gaps
from tests._skip_assert import assert_skips


def _config() -> SimpleNamespace:
    return SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)


def _raw_session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


@pytest.mark.parametrize(
    "method_name",
    [
        "test_wrap_template_attribute_readable",
        "test_unwrap_template_attribute_readable",
        "test_derive_template_attribute_readable",
    ],
)
def test_template_constraint_aes_setup_rejects_are_xfailed(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    monkeypatch.setattr(
        test_remaining_gaps,
        "gen_aes_key_or_xfail",
        lambda *_args, **_kwargs: pytest.xfail("AES_KEY_GEN advertised but rejected setup"),
    )

    test_obj = test_remaining_gaps.TestTemplateConstraintAttributes()
    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        getattr(test_obj, method_name)(_raw_session("AES_KEY_GEN"))


@pytest.mark.parametrize(
    ("method_name", "marker"),
    [
        ("test_get_function_status_returns_not_parallel", "GFS"),
        ("test_cancel_function_returns_not_parallel", "CF"),
    ],
)
def test_legacy_parallel_function_not_supported_is_documented_note(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    marker: str,
) -> None:
    monkeypatch.setattr(
        test_remaining_gaps,
        "_run_gap_probe",
        lambda *_args, **_kwargs: (0, f"{marker}:0x00000054\n", ""),
    )

    clear_notes()
    try:
        getattr(test_remaining_gaps.TestLegacyParallelFunctions(), method_name)(
            _config(),
        )
        assert any("CKR_FUNCTION_NOT_SUPPORTED" in note.description for note in get_notes())
    finally:
        clear_notes()


def test_dual_function_probe_rejects_undefined_ckr() -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        test_remaining_gaps._parse_defined_probe_ckr(
            "SEU:0x12345678",
            "SEU",
            "C_SignEncryptUpdate",
        )


def test_dual_function_probe_accepts_defined_ckr() -> None:
    assert test_remaining_gaps._parse_defined_probe_ckr(
        f"SEU:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}",
        "SEU",
        "C_SignEncryptUpdate",
    ) == int(CKR_FUNCTION_NOT_SUPPORTED)


@pytest.mark.parametrize(
    ("method_name", "marker"),
    [
        ("test_sign_encrypt_update_callable", "SEU"),
        ("test_decrypt_verify_update_callable", "DVU"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_dual_function_ckr_is_recorded_before_cleanup_crash(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    marker: str,
) -> None:
    """A complete provider CKR remains visible when cleanup later crashes.

    CKR_GENERAL_ERROR is a genuine operational deviation here (not
    CKR_FUNCTION_NOT_SUPPORTED / CKR_OPERATION_NOT_INITIALIZED, which are the
    spec-sanctioned non-deviation answers to this uninitialised dual-function call --
    see ``test_dual_function_fns_and_uninitialized_are_not_deviations`` below).
    """
    monkeypatch.setattr(
        test_remaining_gaps,
        "_run_gap_probe",
        lambda *_args, **_kwargs: (-11, f"{marker}:0x00000005\n", "segmentation fault"),
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        getattr(test_remaining_gaps.TestDualFunctionRemaining(), method_name)(_config())

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]
    assert records[0].actual_ckr == "CKR_GENERAL_ERROR"
    assert records[1].detail is not None
    assert records[1].detail["termination"]["kind"] == "signal"


@pytest.mark.parametrize(
    ("method_name", "marker"),
    [
        ("test_sign_encrypt_update_callable", "SEU"),
        ("test_decrypt_verify_update_callable", "DVU"),
    ],
)
@pytest.mark.parametrize(
    "ckr",
    [CKR_FUNCTION_NOT_SUPPORTED, CKR_OPERATION_NOT_INITIALIZED],
)
def test_dual_function_fns_and_uninitialized_are_not_deviations(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    marker: str,
    ckr: int,
) -> None:
    """FNS (capability absence) and OPERATION_NOT_INITIALIZED (spec-required answer to
    an uninitialised dual-function call) must never become a `not_operational` deviation
    record; mechanism advertisement is orthogonal and cannot promote either."""
    monkeypatch.setattr(
        test_remaining_gaps,
        "_run_gap_probe",
        lambda *_args, **_kwargs: (0, f"{marker}:0x{int(ckr):08x}\n", ""),
    )
    if ckr == CKR_FUNCTION_NOT_SUPPORTED:
        assert_skips(
            getattr(test_remaining_gaps.TestDualFunctionRemaining(), method_name), _config()
        )
    else:
        getattr(test_remaining_gaps.TestDualFunctionRemaining(), method_name)(_config())

    assert get_records() == []


class _WaitForSlotEventRaw:
    def __init__(self, rv: int) -> None:
        self._rv = rv

    def C_WaitForSlotEvent(self, *_args: object) -> int:  # noqa: N802
        return self._rv


def test_wait_for_slot_event_function_not_supported_is_skip() -> None:
    """C_WaitForSlotEvent is mandatory-in-table but its return-value table (v2.40+
    Sec.5.6) explicitly defines CKR_FUNCTION_NOT_SUPPORTED -- capability absence, not
    a deviation. Regression for the fix that skips instead of xfailing."""
    rs = SimpleNamespace(raw=_WaitForSlotEventRaw(int(CKR_FUNCTION_NOT_SUPPORTED)), sh=1)
    assert_skips(
        test_remaining_gaps.TestWaitForSlotEvent().test_wait_for_slot_event_non_blocking,
        rs,
        match="C_WaitForSlotEvent",
    )


@pytest.mark.parametrize("stdout", ["", "SEU:not-a-ckr\n"])
def test_dual_function_missing_or_malformed_ckr_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    monkeypatch.setattr(
        test_remaining_gaps,
        "_run_gap_probe",
        lambda *_args, **_kwargs: (0, stdout, ""),
    )
    with pytest.raises(pytest.fail.Exception, match="protocol marker"):
        test_remaining_gaps.TestDualFunctionRemaining().test_sign_encrypt_update_callable(_config())

    assert get_records()[-1].reason == "harness_error"

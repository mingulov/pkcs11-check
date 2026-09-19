"""Meta-tests for undersized-output-buffer measurement classification.

Every buffer probe over-allocates the real buffer, declares a smaller size, and
counts bytes written past the declared boundary, so the return code and an
actual OOB write are independent signals. ``classify_buffer_measurement``
(the live path used by every ``TestBufferTooSmall`` case) turns a guard
overwrite into ``self_contradiction``/``policy`` regardless of the return code,
and never lets a clean return-code deviation suppress contradictory size or
retry evidence.
"""

from __future__ import annotations

import inspect
import sys
from types import SimpleNamespace

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe
from pkcs11_check.testcases.ckr import test_ckr_raw_buffer as raw_buffer
from pkcs11_check.testcases.ckr.test_ckr_raw_buffer import classify_buffer_measurement


def test_count_mismatch_is_metadata_failure_not_crash() -> None:
    """A provider count contradiction is metadata fail, not a child crash."""
    with pytest.raises(pytest.fail.Exception, match="count"):
        classify_buffer_measurement(
            {
                "INITIAL_COUNT": "210",
                "CKR": "0x00000150",
                "RETURNED_COUNT": "1",
                "GUARD_OVERWRITTEN": "0",
                "RETRY_CKR": "0x00000000",
                "RETRY_LENGTH": "210",
                "OUTPUT_CORRECT": "1",
            },
            expected_count=210,
            count_mode="exact",
            context="C_GetMechanismList",
        )


def test_guard_overwrite_fails_even_with_expected_ckr() -> None:
    """A guard overwrite is a hard finding even with CKR_BUFFER_TOO_SMALL."""
    with pytest.raises(pytest.fail.Exception, match="guard"):
        classify_buffer_measurement(
            {
                "INITIAL_COUNT": "210",
                "CKR": "0x00000150",
                "RETURNED_COUNT": "210",
                "GUARD_OVERWRITTEN": "1",
                "RETRY_CKR": "0x00000000",
                "RETRY_LENGTH": "210",
                "OUTPUT_CORRECT": "1",
            },
            expected_count=210,
            count_mode="exact",
            context="C_GetMechanismList",
        )


def test_clean_wrong_ckr_does_not_hide_retry_failure() -> None:
    """A retry failure outranks an initial clean CKR deviation."""
    with pytest.raises(pytest.fail.Exception, match="retry|count"):
        classify_buffer_measurement(
            {
                "INITIAL_COUNT": "210",
                "CKR": "0x00000000",
                "RETURNED_COUNT": "210",
                "GUARD_OVERWRITTEN": "0",
                "RETRY_CKR": "0x00000006",
                "RETRY_LENGTH": "210",
                "OUTPUT_CORRECT": "1",
            },
            expected_count=210,
            count_mode="exact",
            context="C_GetMechanismList",
        )


def test_clean_wrong_ckr_does_not_hide_count_mismatch() -> None:
    """A clean initial CKR deviation cannot suppress contradictory count evidence."""
    with pytest.raises(pytest.fail.Exception, match="count"):
        classify_buffer_measurement(
            {
                "INITIAL_COUNT": "210",
                "CKR": "0x00000000",
                "RETURNED_COUNT": "1",
                "GUARD_OVERWRITTEN": "0",
            },
            expected_count=210,
            count_mode="exact",
            context="C_GetMechanismList",
        )
    assert any(record.kind == "metadata" for record in get_records())


@pytest.mark.parametrize(
    "field",
    ["RETRY_OUTPUT_CORRECT", "FINAL_OK", "OUTPUT_LENGTH_WITHIN_DECLARED", "SIZE_SENTINEL_CORRECT"],
)
def test_zero_effect_field_is_structured_hard_failure(field: str) -> None:
    """Every explicit zero-valued provider effect remains a structured failure."""
    fields = {
        "CKR": "0x00000150",
        "GUARD_OVERWRITTEN": "0",
        "RETRY_CKR": "0x00000000",
        field: "0",
    }
    with pytest.raises(pytest.fail.Exception, match=field):
        classify_buffer_measurement(fields, context="C_EncryptFinal", expected_ckr=None)


def test_buffer_measurement_missing_ckr_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child OK marker without its required CKR cannot pass as a measurement."""
    monkeypatch.setattr(raw_buffer, "_run_probe", lambda *_a, **_k: (0, "OK\n", ""))
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="missing CKR"):
        raw_buffer.TestBufferTooSmall().test_encrypt_buffer_too_small(config)
    assert get_records()[-1].reason == "probe_incomplete"


def test_buffer_measurement_missing_guard_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CKR/OK pair without guard evidence is incomplete protocol."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: (0, "CKR:0x00000150\nRETURNED_COUNT:16\nOK\n", ""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="GUARD_OVERWRITTEN"):
        raw_buffer.TestBufferTooSmall().test_encrypt_buffer_too_small(config)
    assert get_records()[-1].reason == "probe_incomplete"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_setup_marker_is_retained_before_later_crash() -> None:
    """A clean setup refusal printed before a crash remains provider evidence."""
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        raw_buffer._check_buffer_probe(
            -11,
            "SETUP_XFAIL:key setup rejected\n",
            "segmentation fault",
            context="C_Encrypt undersized buffer",
        )
    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]


def test_pure_setup_marker_does_not_fabricate_missing_measurements() -> None:
    """A setup terminal is complete on its own and must only record xfail."""
    with pytest.raises(pytest.xfail.Exception, match="key setup rejected"):
        raw_buffer._check_buffer_probe(
            0,
            "SETUP_XFAIL:key setup rejected\n",
            "",
            context="C_Encrypt undersized buffer",
        )
    assert [record.reason for record in get_records()] == ["not_operational"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_crash_without_markers_records_only_crash() -> None:
    """A crashed child with no protocol fields must not fabricate harness fields."""
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        raw_buffer._check_buffer_probe(
            -11,
            "",
            "segmentation fault",
            context="C_Encrypt undersized buffer",
        )
    assert [record.reason for record in get_records()] == ["crash"]


def test_missing_retry_field_on_normal_exit_is_probe_incomplete() -> None:
    """A normal BUFFER_TOO_SMALL result without retry evidence is incomplete."""
    with pytest.raises(pytest.fail.Exception, match="RETRY_CKR"):
        raw_buffer._check_buffer_probe(
            0,
            "CKR:0x00000150\n"
            "INITIAL_COUNT:16\n"
            "RETURNED_COUNT:16\n"
            "GUARD_OVERWRITTEN:0\n"
            "OK:encrypt-buffer\n",
            "",
            context="C_Encrypt undersized buffer",
            expected_count=16,
            require_retry=True,
        )
    assert [record.reason for record in get_records()] == ["probe_incomplete"]


def test_encrypt_and_sign_protocol_measures_real_guards() -> None:
    """Encrypt/sign must report measured guard bytes, never a fabricated zero."""
    for probe in (raw_probe._encrypt_buffer_too_small, raw_probe._sign_buffer_too_small):
        source = inspect.getsource(probe)
        assert "GUARD_OVERWRITTEN:0" not in source
        assert "sum(1 for byte in probe.guard" in source


def test_cbc_one_shot_decrypt_accepts_ciphertext_upper_bound() -> None:
    """A CBC-PAD one-shot retry may return the padded ciphertext size."""
    assert (
        classify_buffer_measurement(
            {
                "CKR": "0x00000150",
                "INITIAL_COUNT": "14",
                "RETURNED_COUNT": "16",
                "GUARD_OVERWRITTEN": "0",
            },
            expected_count=14,
            count_mode="range",
            count_min=14,
            count_max=16,
            context="C_Decrypt AES-CBC-PAD undersized output buffer guard",
        )
        is None
    )


@pytest.mark.parametrize("context", ["C_DecryptUpdate", "C_DecryptFinal"])
def test_update_and_final_do_not_assume_equal_counts(context: str) -> None:
    """Streaming update/final paths have no generic initial/returned equality."""
    assert (
        classify_buffer_measurement(
            {
                "CKR": "0x00000000",
                "INITIAL_COUNT": "14",
                "RETURNED_COUNT": "16",
                "GUARD_OVERWRITTEN": "0",
            },
            expected_ckr=None,
            context=context,
        )
        is None
    )


@pytest.mark.parametrize("returned_count", [13, 17])
def test_cbc_one_shot_decrypt_rejects_count_outside_range(returned_count: int) -> None:
    """CBC-PAD one-shot counts below plaintext or above ciphertext are invalid."""
    with pytest.raises(pytest.fail.Exception, match="count"):
        classify_buffer_measurement(
            {
                "CKR": "0x00000150",
                "INITIAL_COUNT": "14",
                "RETURNED_COUNT": str(returned_count),
                "GUARD_OVERWRITTEN": "0",
            },
            expected_count=14,
            count_mode="range",
            count_min=14,
            count_max=16,
            context="C_Decrypt AES-CBC-PAD undersized output buffer guard",
        )
    assert get_records()[-1].kind == "metadata"


def test_missing_terminal_incomplete_controls_provider_deviation() -> None:
    """Provider deviation evidence cannot mask a missing terminal OK marker."""
    with pytest.raises(pytest.fail.Exception, match="complete OK measurement"):
        raw_buffer._check_buffer_probe(
            0,
            "CKR:0x00000000\n"
            "INITIAL_COUNT:16\n"
            "RETURNED_COUNT:16\n"
            "GUARD_OVERWRITTEN:0\n"
            "DEVIATION_XFAIL:provider deviation\n",
            "",
            context="C_Encrypt undersized buffer",
            expected_count=16,
        )
    records = get_records()
    assert any(record.reason == "honest_deviation" for record in records)
    assert records[-1].reason == "probe_incomplete"

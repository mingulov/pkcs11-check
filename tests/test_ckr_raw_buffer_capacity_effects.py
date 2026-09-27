"""Meta-tests for CBC-PAD buffer-capacity and Update-effect classification.

P11C-0198-020: the AES-CBC-PAD ``C_EncryptFinal`` probe hard-coded
``INITIAL_COUNT:16`` and the parent compared the provider's retry output
against that invented reference. A correct 32-byte retry with a verified
round-trip failed as "retry length 32 is unusable; expected 16". Retry
bounds must come from the provider-reported required length (``NEEDED``).

P11C-0198-021: the one-byte ``C_DecryptUpdate``/``C_DecryptFinal`` probes and
their classifier dropped the lengths needed to judge ``CKR_OK``. The
classifier must parse and retain ``NEEDED`` (required length behind a
``CKR_BUFFER_TOO_SMALL``) and ``LEN`` (actual length), accept ``CKR_OK``
only when output fits with an intact guard plus Final and round-trip
evidence, and require ``CKR_BUFFER_TOO_SMALL`` only when the measured
required output exceeds the declared capacity.

Tests asserting a *new* verdict fail on the pre-fix code (RED) and pass
after the fix; tests marked as loudness pins assert preserved behavior
and pass both before and after.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe
from pkcs11_check.testcases.ckr import test_ckr_raw_buffer as raw_buffer
from pkcs11_check.testcases.ckr.test_ckr_raw_buffer import classify_buffer_measurement

_GUARDS = raw_buffer.TestDecryptBufferTooSmallGuards()
_ENCRYPT_FINAL_NODE = "test_aes_cbc_pad_encrypt_final_buffer_too_small_preserves_guard_and_retries"
_DECRYPT_UPDATE_NODE = (
    "test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries"
)
_DECRYPT_FINAL_NODE = "test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries"


def _check(node: str) -> Callable[[SimpleNamespace], None]:
    return getattr(_GUARDS, node)


def _config() -> SimpleNamespace:
    return SimpleNamespace(module="x", slot=0, pin=None)


_ENCRYPT_FINAL = _check(_ENCRYPT_FINAL_NODE)
_DECRYPT_UPDATE = _check(_DECRYPT_UPDATE_NODE)
_DECRYPT_FINAL = _check(_DECRYPT_FINAL_NODE)


def _ok(output: str) -> tuple[int, str, str]:
    return (0, output, "")


# --- P11C-0198-020: EncryptFinal retry bounds ---


def test_encrypt_final_retry_uses_provider_needed_not_initial_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A correct 32-byte retry must not be judged against a hard-coded 16."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:32\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:32\n"
            "INITIAL_COUNT:16\n"
            "NEEDED:32\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:32\n"
            "RETRY_MATCH:1\n"
            "RETRY_LENGTH:32\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    assert _ENCRYPT_FINAL(_config()) is None


def test_encrypt_final_requires_needed_when_retry_expected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry without the provider-reported capacity is incomplete evidence."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:16\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:16\n"
            "INITIAL_COUNT:16\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:16\n"
            "RETRY_MATCH:1\n"
            "RETRY_LENGTH:16\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="NEEDED"):
        _ENCRYPT_FINAL(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_encrypt_final_short_retry_fails_against_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry shorter than the reported capacity cites the provider length."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:32\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:32\n"
            "NEEDED:32\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:16\n"
            "RETRY_LENGTH:16\n"
            "RETRY_OUTPUT_CORRECT:0\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="expected 32"):
        _ENCRYPT_FINAL(_config())
    assert [record.reason for record in get_records()] == [
        "self_contradiction",
        "wrong_result",
    ]


def test_encrypt_final_probe_reports_provider_needed() -> None:
    """The EncryptFinal probe must emit NEEDED, never a fabricated 16."""
    source = inspect.getsource(raw_probe._aes_cbc_pad_encrypt_final_buffer_too_small)
    assert "INITIAL_COUNT:16" not in source
    assert "NEEDED:" in source


# --- P11C-0198-021: DecryptUpdate lengths ---


def test_decrypt_update_retry_uses_provider_needed_not_plaintext_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 32+16 multipart split must not be judged against plaintext length 48."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:32\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:32\n"
            "INITIAL_COUNT:48\n"
            "NEEDED:32\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:32\n"
            "RETRY_LENGTH:32\n"
            "FINAL_CKR:0x00000000\n"
            "FINAL_LEN:16\n"
            "RETRY_MATCH:1\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    assert _DECRYPT_UPDATE(_config()) is None


def test_decrypt_update_requires_needed_when_retry_expected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry without the provider-reported capacity is incomplete evidence."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:48\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:48\n"
            "INITIAL_COUNT:48\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:48\n"
            "RETRY_LENGTH:48\n"
            "FINAL_CKR:0x00000000\n"
            "FINAL_LEN:0\n"
            "RETRY_MATCH:1\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="NEEDED"):
        _DECRYPT_UPDATE(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_update_ok_path_requires_actual_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK alone is never enough: the actual length must be retained."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "INITIAL_COUNT:48\n"
            "OUTPUT_LENGTH_WITHIN_DECLARED:1\n"
            "FINAL_CKR:0x00000000\n"
            "FINAL_LEN:48\n"
            "MATCH:1\n"
            "FINAL_OK:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="LEN"):
        _DECRYPT_UPDATE(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_update_ok_path_with_lengths_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loudness pin: buffered CKR_OK with fit, guard, Final, round-trip passes."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "LEN:0\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "OUTPUT_LENGTH_WITHIN_DECLARED:1\n"
            "FINAL_CKR:0x00000000\n"
            "FINAL_LEN:48\n"
            "MATCH:1\n"
            "FINAL_OK:1\n"
            "OK\n"
        ),
    )
    assert _DECRYPT_UPDATE(_config()) is None


def test_decrypt_update_spurious_buffer_too_small_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loudness pin: BUFFER_TOO_SMALL with no capacity beyond declared fails."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:1\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:1\n"
            "NEEDED:1\n"
            "RETRY_USABLE:0\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="unusable"):
        _DECRYPT_UPDATE(_config())
    assert get_records()[-1].reason == "self_contradiction"


def test_decrypt_update_probe_reports_provider_needed() -> None:
    """The DecryptUpdate probe must emit NEEDED, never a plaintext-length bound."""
    source = inspect.getsource(raw_probe._aes_cbc_pad_decrypt_update_buffer_too_small)
    assert "INITIAL_COUNT:" not in source
    assert "NEEDED:" in source


# --- P11C-0198-021: DecryptFinal lengths ---


def test_decrypt_final_requires_needed_when_retry_expected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry without the provider-reported capacity is incomplete evidence."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:15\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:15\n"
            "INITIAL_COUNT:15\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:15\n"
            "RETRY_MATCH:1\n"
            "RETRY_LENGTH:15\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="NEEDED"):
        _DECRYPT_FINAL(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_final_retry_uses_provider_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loudness pin: retry at the reported capacity with round-trip passes."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:15\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:15\n"
            "NEEDED:15\n"
            "RETRY_USABLE:1\n"
            "RETRY_CKR:0x00000000\n"
            "RETRY_LEN:15\n"
            "RETRY_MATCH:1\n"
            "RETRY_LENGTH:15\n"
            "RETRY_OUTPUT_CORRECT:1\n"
            "OK\n"
        ),
    )
    assert _DECRYPT_FINAL(_config()) is None


def test_decrypt_final_ok_path_requires_actual_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK alone is never enough: the actual length must be retained."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "INITIAL_COUNT:15\n"
            "OUTPUT_LENGTH_WITHIN_DECLARED:1\n"
            "MATCH:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="LEN"):
        _DECRYPT_FINAL(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_final_ok_rejects_output_beyond_declared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loudness pin: CKR_OK with output beyond declared capacity fails."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "LEN:5\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:5\n"
            "OUTPUT_LENGTH_WITHIN_DECLARED:0\n"
            "MATCH:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="OUTPUT_LENGTH_WITHIN_DECLARED"):
        _DECRYPT_FINAL(_config())
    assert get_records()[-1].reason == "self_contradiction"


def test_decrypt_final_spurious_buffer_too_small_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BUFFER_TOO_SMALL is required only when required output exceeds declared."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000150\n"
            "LEN:1\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:1\n"
            "INITIAL_COUNT:15\n"
            "NEEDED:1\n"
            "RETRY_USABLE:0\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="unusable"):
        _DECRYPT_FINAL(_config())
    assert [record.reason for record in get_records()] == ["self_contradiction"]


def test_decrypt_final_probe_reports_provider_needed_and_fit() -> None:
    """The DecryptFinal probe must emit NEEDED, usability, and the OK-path fit."""
    source = inspect.getsource(raw_probe._aes_cbc_pad_decrypt_final_buffer_too_small)
    assert "INITIAL_COUNT:" not in source
    assert "NEEDED:" in source
    assert "RETRY_USABLE:" in source
    assert "OUTPUT_LENGTH_WITHIN_DECLARED:" in source
    # Exactly one fixed plaintext-sized allocation remains: the Update output
    # buffer. The Final retry itself must be sized from the provider length.
    assert source.count("CK_ULONG(len(plaintext))") == 1


# --- Helper rule: a named retry reference must be measured ---


def test_named_retry_reference_is_required_with_retry_evidence() -> None:
    """A named NEEDED reference without the measurement is incomplete."""
    with pytest.raises(pytest.fail.Exception, match="NEEDED"):
        classify_buffer_measurement(
            {
                "CKR": "0x00000150",
                "GUARD_OVERWRITTEN": "0",
                "RETURNED_COUNT": "32",
                "RETRY_CKR": "0x00000000",
                "RETRY_LENGTH": "32",
            },
            retry_length_reference="NEEDED",
            require_retry=True,
            context="C_EncryptFinal",
        )


def test_named_retry_reference_judges_retry_length() -> None:
    """A retry shorter than the named NEEDED reference fails against it."""
    with pytest.raises(pytest.fail.Exception, match="expected 32"):
        classify_buffer_measurement(
            {
                "CKR": "0x00000150",
                "GUARD_OVERWRITTEN": "0",
                "RETURNED_COUNT": "32",
                "NEEDED": "32",
                "RETRY_CKR": "0x00000000",
                "RETRY_LENGTH": "16",
            },
            retry_length_reference="NEEDED",
            require_retry=True,
            context="C_EncryptFinal",
        )


def test_always_required_reference_is_not_double_required() -> None:
    """Loudness pin: one missing NEEDED yields one incomplete record, not two."""
    with pytest.raises(pytest.fail.Exception, match="missing NEEDED"):
        classify_buffer_measurement(
            {
                "CKR": "0x00000150",
                "GUARD_OVERWRITTEN": "0",
                "RETURNED_COUNT": "16",
                "RETRY_CKR": "0x00000000",
                "RETRY_LENGTH": "16",
            },
            required_fields=("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT", "NEEDED"),
            retry_length_reference="NEEDED",
            require_retry=True,
            context="C_GetAttributeValue",
        )
    records = get_records()
    assert [record.reason for record in records] == ["probe_incomplete"]
    assert "; " not in (records[0].summary or "")


# --- Review hardening: the fit marker is required, not merely validated ---


def test_encrypt_final_ok_path_requires_fit_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A silent fit omission on the OK path is incomplete, not a pass."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "LEN:0\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "MATCH:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="OUTPUT_LENGTH_WITHIN_DECLARED"):
        _ENCRYPT_FINAL(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_update_ok_path_requires_fit_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A silent fit omission on the OK path is incomplete, not a pass."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "LEN:0\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "FINAL_CKR:0x00000000\n"
            "FINAL_LEN:48\n"
            "MATCH:1\n"
            "FINAL_OK:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="OUTPUT_LENGTH_WITHIN_DECLARED"):
        _DECRYPT_UPDATE(_config())
    assert get_records()[-1].reason == "probe_incomplete"


def test_decrypt_final_ok_path_requires_fit_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A silent fit omission on the OK path is incomplete, not a pass."""
    monkeypatch.setattr(
        raw_buffer,
        "_run_probe",
        lambda *_a, **_k: _ok(
            "CKR:0x00000000\n"
            "LEN:0\n"
            "OVERWRITTEN:0\n"
            "GUARD_OVERWRITTEN:0\n"
            "RETURNED_COUNT:0\n"
            "MATCH:1\n"
            "OK\n"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="OUTPUT_LENGTH_WITHIN_DECLARED"):
        _DECRYPT_FINAL(_config())
    assert get_records()[-1].reason == "probe_incomplete"

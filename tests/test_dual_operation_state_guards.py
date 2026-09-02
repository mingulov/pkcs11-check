from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases import test_dual_function, test_operation_state


def _config() -> SimpleNamespace:
    return SimpleNamespace(module="/tmp/provider.so", slot=0, pin=None)


def _raw_session(*mechanisms: str, raw: Any | None = None) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=raw if raw is not None else object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_dual_digest_encrypt_skips_before_child_when_aes_setup_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_dual_function,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("child subprocess should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN"):
        test_dual_function.TestDigestEncryptUpdate().test_digest_encrypt_update_round_trip(
            _config(),
            _raw_session("AES_CBC", "SHA256"),
        )


def test_dual_decrypt_digest_skips_before_child_when_digest_setup_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_dual_function,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("child subprocess should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256"):
        test_dual_function.TestDecryptDigestUpdate().test_decrypt_digest_update_round_trip(
            _config(),
            _raw_session("AES_KEY_GEN", "AES_CBC"),
        )


def test_operation_state_digest_skips_before_child_when_sha256_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_operation_state,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("child subprocess should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256"):
        test_operation_state.TestDigestStateRoundTrip().test_digest_state_same_session(
            _config(),
            _raw_session(),
        )


def test_operation_state_encrypt_skips_before_child_when_aes_keygen_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_operation_state,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("child subprocess should not run"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN"):
        test_operation_state.TestEncryptStateRoundTrip().test_encrypt_state_same_session(
            _config(),
            _raw_session("AES_CBC"),
        )


def test_operation_state_garbage_arguments_bad_xfails_with_note() -> None:
    """CKR_ARGUMENTS_BAD is a non-spec reject for a garbage state blob.

    Under the 3-way classification it is an xfail (not the spec
    CKR_SAVED_STATE_INVALID), while the more-specific-code compliance note is
    still emitted before the classification.
    """

    class _Raw:
        def C_SetOperationState(self, *_args: object) -> int:  # noqa: N802
            return int(CKR_ARGUMENTS_BAD)

    clear_notes()
    try:
        with pytest.raises(pytest.xfail.Exception):
            test_operation_state.TestGetOperationStateAPI().test_garbage_state_raises_saved_state_invalid(
                _raw_session(raw=_Raw()),
            )
        assert any("CKR_ARGUMENTS_BAD" in note.description for note in get_notes())
    finally:
        clear_notes()

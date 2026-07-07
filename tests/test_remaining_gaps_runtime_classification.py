from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.testcases import test_remaining_gaps


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

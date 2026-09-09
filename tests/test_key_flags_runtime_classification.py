"""Regression tests for key-flag setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_LOCAL,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_key_flags


def _session(raw: object | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        raw=object() if raw is None else raw,
        sh=1,
        has_mechanism=lambda _name: True,
    )


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def test_key_flags_aes_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_key_flags, "gen_aes_key", _keygen_reject)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_key_flags.TestNeverExtractable().test_generated_non_extractable_is_never_extractable(
            _session()
        )


def test_imported_key_missing_local_readback_records_exact_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_key_flags, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_key_flags, "skip_unless_create_object_supported", lambda *_args, **_kwargs: None
    )

    raw = SimpleNamespace(C_GetAttributeValue=lambda *_args: CKR_ATTRIBUTE_TYPE_INVALID)

    test_key_flags.TestLocalFlag().test_imported_key_is_not_local(_session(raw))

    record = C.get_records()[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.detail == {"attribute": {"name": "CKA_LOCAL", "id": int(CKA_LOCAL)}}


def test_missing_required_flag_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_key_flags, "gen_aes_key", lambda *_args, **_kwargs: 17)
    monkeypatch.setattr(test_key_flags, "read_attributes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        test_key_flags, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_key_flags.TestNeverExtractable().test_generated_non_extractable_is_never_extractable(
        _session()
    )

    assert destroyed == [17]
    assert [(rec.reason, rec.label) for rec in C.get_records()] == [
        ("honest_deviation", "CKA_NEVER_EXTRACTABLE:generated-non-extractable")
    ]


def test_missing_default_flag_does_not_hide_later_invariant_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_key_flags, "gen_aes_key", lambda *_args, **_kwargs: 23)
    monkeypatch.setattr(test_key_flags, "read_attributes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(test_key_flags, "_read_bool_attr_safe", lambda *_args: False)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="CKA_NEVER_EXTRACTABLE"):
        test_key_flags.TestNeverExtractable().test_extractable_and_never_extractable_consistent(
            _session()
        )

    assert [rec.reason for rec in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]


def test_missing_one_sensitive_flag_does_not_hide_present_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_key_flags, "gen_aes_key", lambda *_args, **_kwargs: 29)
    monkeypatch.setattr(
        test_key_flags,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_ALWAYS_SENSITIVE: False},
    )
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="CKA_ALWAYS_SENSITIVE"):
        test_key_flags.TestAlwaysSensitive().test_sensitive_key_always_sensitive(_session())

    assert [rec.reason for rec in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]


def test_flag_reader_propagates_unexpected_ckr() -> None:
    raw = SimpleNamespace(C_GetAttributeValue=lambda *_args: CKR_DEVICE_ERROR)
    rs = SimpleNamespace(raw=raw, sh=1)

    with pytest.raises(CkrAssertionError) as exc_info:
        test_key_flags._read_bool_attr_safe(rs, 7, CKA_LOCAL)

    assert exc_info.value.rv == int(CKR_DEVICE_ERROR)
    assert C.get_records() == []


def test_missing_public_local_does_not_hide_private_local_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def _get_attribute(_sh: int, handle: int, *_args: Any) -> int:
        return CKR_ATTRIBUTE_TYPE_INVALID if handle == 31 else CKR_OK

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    monkeypatch.setattr(test_key_flags, "gen_rsa_keypair", lambda *_a, **_k: (31, 32))
    monkeypatch.setattr(
        test_key_flags,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception, match="CKA_LOCAL"):
        test_key_flags.TestLocalFlag().test_generated_rsa_keypair_is_local(_session(raw))

    assert destroyed == [31, 32]
    assert [rec.reason for rec in C.get_records()] == [
        "honest_deviation",
        "self_contradiction",
    ]


def test_present_wrong_imported_local_is_hard_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_key_flags, "import_secret_key", lambda *_a, **_k: 41)
    monkeypatch.setattr(test_key_flags, "_read_bool_attr_safe", lambda *_a, **_k: True)
    monkeypatch.setattr(test_key_flags, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(
        test_key_flags, "skip_unless_create_object_supported", lambda *_a, **_k: None
    )

    with pytest.raises(pytest.fail.Exception, match="CKA_LOCAL"):
        test_key_flags.TestLocalFlag().test_imported_key_is_not_local(_session())

    assert C.get_records()[0].reason == "self_contradiction"

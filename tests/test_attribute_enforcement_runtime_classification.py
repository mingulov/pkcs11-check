"""Runtime evidence tests for the attribute-enforcement testcase.

These tests model provider responses rather than requiring a live PKCS#11 module.
They protect the distinction between an omitted attribute (an honest, structured
deviation) and a present value that contradicts the operation that produced it.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CHECK_VALUE,
    CKA_COPYABLE,
    CKA_DESTROYABLE,
    CKA_END_DATE,
    CKA_KEY_GEN_MECHANISM,
    CKA_START_DATE,
    CKA_TOKEN,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_attribute_enforcement as tae
from tests._attribute_access_guard import analyze_paths


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=SimpleNamespace(C_DestroyObject=lambda *_args: int(CKR_OK)),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    reads: Any,
    set_attributes: Any | None = None,
) -> None:
    monkeypatch.setattr(tae, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tae, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(tae, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: 4)
    monkeypatch.setattr(tae, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tae, "read_attributes", reads)
    if set_attributes is not None:
        monkeypatch.setattr(tae, "set_attributes", set_attributes)


def _records() -> list[classification.Classification]:
    return classification.get_records()


def _has_attribute_record(record: classification.Classification, attribute: int) -> bool:
    detail = record.detail
    if detail is None:
        return False
    evidence = detail.get("attribute")
    if isinstance(evidence, dict):
        return evidence.get("id") == int(attribute)
    return evidence == int(attribute)


def test_missing_copyable_is_structured_and_does_not_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {})

    tae.TestCopyableOneWay().test_copyable_false_cannot_be_set_true(_session())

    assert len(_records()) == 1
    rec = _records()[0]
    assert rec.outcome == "xfail"
    assert rec.reason == "honest_deviation"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.actual_ckr is None
    assert _has_attribute_record(rec, CKA_COPYABLE)


def test_false_like_copyable_is_present_and_allows_independent_set_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    calls: list[dict[Any, Any]] = []

    def read(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        result = {CKA_COPYABLE: False}
        calls.append(result)
        return result

    def reject(*_args: object, **_kwargs: object) -> None:
        raise CkrAssertionError("read-only", int(CKR_ATTRIBUTE_READ_ONLY))

    _setup(monkeypatch, reads=read, set_attributes=reject)

    tae.TestCopyableOneWay().test_copyable_false_cannot_be_set_true(_session())

    assert len(calls) == 1
    assert _records() == []


def test_valid_copyable_downgrade_rejection_is_visible_as_positive_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()

    def reject(*_args: object, **_kwargs: object) -> None:
        raise CkrAssertionError("read-only", int(CKR_ATTRIBUTE_READ_ONLY))

    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: {CKA_COPYABLE: True},
        set_attributes=reject,
    )

    with pytest.raises(pytest.xfail.Exception):
        tae.TestCopyableOneWay().test_copyable_true_can_be_set_false(_session())

    rec = _records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "policy"
    assert rec.operation == "C_SetAttributeValue"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_READ_ONLY"
    assert rec.detail == {"attribute": CKA_COPYABLE}


def test_copyable_escalation_readback_rejection_is_not_setter_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    reads = iter(
        (
            {CKA_COPYABLE: False},
            CkrAssertionError("readback failed", int(CKR_ATTRIBUTE_TYPE_INVALID)),
        )
    )

    def read(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        value = next(reads)
        if isinstance(value, CkrAssertionError):
            raise value
        return value

    _setup(monkeypatch, reads=read, set_attributes=lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception):
        tae.TestCopyableOneWay().test_copyable_false_cannot_be_set_true(_session())

    rec = _records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert rec.detail == {"attribute": CKA_COPYABLE}


def test_copyable_downgrade_readback_rejection_is_not_setter_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    reads = iter(
        (
            {CKA_COPYABLE: True},
            CkrAssertionError("readback failed", int(CKR_ATTRIBUTE_TYPE_INVALID)),
        )
    )

    def read(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        value = next(reads)
        if isinstance(value, CkrAssertionError):
            raise value
        return value

    _setup(monkeypatch, reads=read, set_attributes=lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception):
        tae.TestCopyableOneWay().test_copyable_true_can_be_set_false(_session())

    rec = _records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert rec.detail == {"attribute": CKA_COPYABLE}


def test_attribute_enforcement_reports_aes_keygen_setup_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()

    def reject(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError(
            "C_GenerateKey rejected setup",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(raw_recipes, "gen_aes_key", reject)

    with pytest.raises(pytest.xfail.Exception):
        tae.TestDestroyable().test_destroyable_readable(_session())

    rec = _records()[-1]
    assert rec.reason == "not_operational"
    assert rec.operation == "C_GenerateKey"
    assert rec.mechanism == "CKM_AES_KEY_GEN"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"


def test_attribute_read_rejection_is_structured_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    destroyed: list[int] = []

    def reject(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        raise CkrAssertionError("attribute read rejected", int(CKR_ATTRIBUTE_TYPE_INVALID))

    _setup(monkeypatch, reads=reject)
    monkeypatch.setattr(tae, "destroy_quietly", lambda *_a: destroyed.append(1))

    with pytest.raises(pytest.xfail.Exception):
        tae.TestDestroyable().test_destroyable_readable(_session())

    rec = _records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert rec.detail == {"attribute": CKA_DESTROYABLE}
    assert destroyed == [1]


def test_attribute_read_undefined_ckr_is_a_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("undefined CKR", 0x12345678)
        ),
    )

    with pytest.raises(Failed):
        tae.TestDestroyable().test_destroyable_readable(_session())

    rec = _records()[-1]
    assert rec.reason == "self_contradiction"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "0x12345678"


def test_unknown_aes_setup_ckr_is_not_consumed_by_attribute_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()

    def reject(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError("unknown setup CKR", int(CKR_SESSION_HANDLE_INVALID))

    monkeypatch.setattr(raw_recipes, "gen_aes_key", reject)

    with pytest.raises(CkrAssertionError):
        tae.TestCopyableOneWay().test_copyable_false_cannot_be_set_true(_session())

    assert _records() == []


def test_present_key_generation_mechanism_mismatch_is_a_hard_readback_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: {CKA_KEY_GEN_MECHANISM: 0x1234},
    )

    with pytest.raises(Failed):
        tae.TestKeyGenMechanism().test_generated_aes_key_has_aes_key_gen(_session())

    rec = _records()[-1]
    assert rec.reason == "self_contradiction"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism == "CKM_AES_KEY_GEN"


def test_kcv_reads_both_keys_before_equality_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    events: list[str] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: object) -> dict[int, object]:
        events.append(f"read:{handle}")
        if handle == 4:
            return {}
        return {CKA_CHECK_VALUE: b"abc"}

    monkeypatch.setattr(tae, "encrypt_single", lambda *_a, **_k: b"abc" + b"rest")
    _setup(monkeypatch, reads=read)
    handles = iter((4, 5))

    def import_key(*_args: object, **_kwargs: object) -> int:
        handle = next(handles)
        events.append(f"import:{handle}")
        return handle

    monkeypatch.setattr(
        tae,
        "import_secret_key_negotiated",
        import_key,
    )
    monkeypatch.setattr(
        tae,
        "destroy_quietly",
        lambda _raw, _sh, handle: events.append(f"destroy:{handle}"),
    )

    tae.TestCheckValue().test_same_key_material_same_kcv(_session())

    assert events == ["import:4", "read:4", "destroy:4", "import:5", "read:5", "destroy:5"]
    assert len(_records()) == 1
    assert _records()[0].reason == "honest_deviation"


def test_missing_first_kcv_does_not_hide_malformed_second_leg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    reads = iter(({}, {CKA_CHECK_VALUE: b""}))
    handles = iter((4, 5))
    _setup(monkeypatch, reads=lambda *_a, **_k: next(reads))
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))
    destroyed: list[int] = []
    monkeypatch.setattr(
        tae,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(Failed):
        tae.TestCheckValue().test_same_key_material_same_kcv(_session())

    assert destroyed == [4, 5]
    assert [rec.reason for rec in _records()] == ["honest_deviation", "wrong_result"]
    assert _records()[-1].operation == "C_GetAttributeValue"


def test_kcv_read_rejection_does_not_hide_second_leg_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    reads = iter(
        (
            CkrAssertionError("first read rejected", int(CKR_ATTRIBUTE_TYPE_INVALID)),
            {CKA_CHECK_VALUE: b""},
        )
    )
    handles = iter((4, 5))

    def read(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        value = next(reads)
        if isinstance(value, CkrAssertionError):
            raise value
        return value

    _setup(monkeypatch, reads=read)
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))
    destroyed: list[int] = []
    monkeypatch.setattr(
        tae,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(Failed):
        tae.TestCheckValue().test_same_key_material_same_kcv(_session())

    assert destroyed == [4, 5]
    assert [rec.reason for rec in _records()] == ["not_operational", "wrong_result"]
    assert _records()[0].operation == "C_GetAttributeValue"
    assert _records()[0].expected_ckr == ["CKR_OK"]
    assert _records()[0].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert _records()[-1].detail is not None


def test_present_malformed_kcv_is_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b""})

    with pytest.raises(Failed):
        tae.TestCheckValue().test_generated_key_has_check_value(_session())

    rec = _records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.operation == "C_GetAttributeValue"


def test_imported_kcv_mismatch_is_a_crypto_ecb_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b"\x00\x00\x00"})
    monkeypatch.setattr(tae, "encrypt_single", lambda *_a, **_k: b"\x01\x02\x03rest")

    with pytest.raises(Failed):
        tae.TestCheckValue().test_imported_key_kcv_matches_ecb_encrypt(_session())

    rec = _records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"
    assert rec.operation == "C_Encrypt"
    assert rec.mechanism == "CKM_AES_ECB"
    assert rec.detail == {
        "attribute": CKA_CHECK_VALUE,
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
        "comparison_operation": "C_Encrypt",
        "comparison_mechanism": "CKM_AES_ECB",
    }


def test_missing_start_date_does_not_hide_end_date_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: {CKA_END_DATE: "wrong-date"},
    )

    with pytest.raises(Failed):
        tae.TestDateAttributes().test_start_end_date_on_generated_key(_session())

    assert any(_has_attribute_record(rec, CKA_START_DATE) for rec in _records())
    assert _records()[-1].reason == "wrong_result"


def test_both_present_date_contradictions_are_recorded_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: {
            CKA_START_DATE: "wrong-start",
            CKA_END_DATE: "wrong-end",
        },
    )

    with pytest.raises(Failed):
        tae.TestDateAttributes().test_start_end_date_on_generated_key(_session())

    assert [rec.reason for rec in _records()] == ["wrong_result", "wrong_result"]
    assert [
        _has_attribute_record(rec, attr)
        for rec, attr in zip(_records(), (CKA_START_DATE, CKA_END_DATE), strict=True)
    ] == [True, True]


def test_reader_python_exception_propagates_and_cleanup_still_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    destroyed: list[int] = []
    _setup(monkeypatch, reads=lambda *_a, **_k: (_ for _ in ()).throw(TypeError("reader bug")))
    monkeypatch.setattr(tae, "destroy_quietly", lambda *_a: destroyed.append(1))

    with pytest.raises(TypeError, match="reader bug"):
        tae.TestDateAttributes().test_start_end_date_on_generated_key(_session())

    assert destroyed == [1]


def test_missing_token_readback_does_not_claim_promotion_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    reads = iter(({CKA_TOKEN: False}, {}))
    _setup(monkeypatch, reads=lambda *_a, **_k: next(reads), set_attributes=lambda *_a: None)

    tae.TestTokenAttributePromotion().test_setattr_token_promotion_consistency(_session())

    assert len(_records()) == 1
    assert _records()[0].reason == "honest_deviation"


def test_attribute_enforcement_access_slice_is_analyzer_clean() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "test_attribute_enforcement.py"
    )
    assert analyze_paths([source]) == []

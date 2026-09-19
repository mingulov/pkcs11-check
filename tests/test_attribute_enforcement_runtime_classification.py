"""Runtime evidence tests for the attribute-enforcement testcase.

These tests model provider responses rather than requiring a live PKCS#11 module.
They protect the distinction between an omitted attribute (an honest, structured
deviation) and a present value that contradicts the operation that produced it.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CHECK_VALUE,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DESTROYABLE,
    CKA_ENCRYPT,
    CKA_END_DATE,
    CKA_KEY_GEN_MECHANISM,
    CKA_START_DATE,
    CKA_TOKEN,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_attribute_enforcement as tae
from tests._attribute_access_guard import analyze_paths
from tests._skip_assert import assert_skips


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


def test_copyable_mutation_type_invalid_after_successful_read_is_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-010: read-then-TYPE_INVALID-on-mutate is a deviation, not a pass.

    The module read CKA_COPYABLE successfully (so it recognises the
    attribute type); rejecting the mutation with CKR_ATTRIBUTE_TYPE_INVALID
    is unjustified by that read. Reading and changing are different
    operations -- the rejection proves no bypass and must stay visible.
    """
    classification.clear()

    def reject(*_args: object, **_kwargs: object) -> None:
        raise CkrAssertionError("type invalid", int(CKR_ATTRIBUTE_TYPE_INVALID))

    _setup(
        monkeypatch,
        reads=lambda *_a, **_k: {CKA_COPYABLE: False},
        set_attributes=reject,
    )

    with pytest.raises(pytest.xfail.Exception):
        tae.TestCopyableOneWay().test_copyable_false_cannot_be_set_true(_session())

    rec = _records()[-1]
    assert rec.outcome == "xfail"
    assert rec.reason == "nonspec_reject"
    assert rec.kind == "policy"
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


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


def test_kcv_one_missing_leg_is_a_support_inconsistency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    events: list[str] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: object) -> dict[int, object]:
        events.append(f"read:{handle}")
        if handle == 4:
            return {}
        return {CKA_CHECK_VALUE: b"abc"}

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

    with pytest.raises(Failed):
        tae.TestCheckValue().test_same_key_material_same_kcv(_session())

    assert events == ["import:4", "read:4", "destroy:4", "import:5", "read:5", "destroy:5"]
    assert len(_records()) == 1
    assert _records()[0].reason == "self_contradiction"
    assert _records()[0].kind == "metadata"


def test_kcv_absent_on_both_identical_keys_is_optional_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    handles = iter((4, 5))
    _setup(monkeypatch, reads=lambda *_a, **_k: {})
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))

    assert_skips(
        tae.TestCheckValue().test_same_key_material_same_kcv,
        _session(),
        match="CKA_CHECK_VALUE is not supported",
    )

    assert _records() == []


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
    assert [rec.reason for rec in _records()] == ["wrong_result", "self_contradiction"]
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
    assert [rec.reason for rec in _records()] == ["wrong_result", "self_contradiction"]
    assert _records()[-1].detail is not None


def test_kcv_sensitive_refusal_does_not_hide_support_inconsistency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    refused = AttrReadResult()
    refused.refusals[int(CKA_CHECK_VALUE)] = AttrRefusal(int(CKR_ATTRIBUTE_SENSITIVE))
    reads = iter((refused, {CKA_CHECK_VALUE: b"abc"}))
    handles = iter((4, 5))

    def read(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        return next(reads)

    _setup(monkeypatch, reads=read)
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))

    with pytest.raises(Failed):
        tae.TestCheckValue().test_same_key_material_same_kcv(_session())

    assert [record.reason for record in _records()] == [
        "honest_deviation",
        "self_contradiction",
    ]
    assert _records()[-1].mechanism is None


def test_generated_kcv_absence_is_optional_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {})

    assert_skips(
        tae.TestCheckValue().test_generated_key_has_check_value,
        _session(),
        match="CKA_CHECK_VALUE is not supported",
    )

    assert _records() == []


def test_generated_kcv_attribute_type_invalid_is_optional_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()

    def reject(*_args: object, **_kwargs: object) -> dict[Any, Any]:
        raise CkrAssertionError("unsupported", int(CKR_ATTRIBUTE_TYPE_INVALID))

    _setup(monkeypatch, reads=reject)

    assert_skips(
        tae.TestCheckValue().test_generated_key_has_check_value,
        _session(),
        match="CKA_CHECK_VALUE is not supported",
    )

    assert _records() == []


def test_generated_kcv_per_attribute_type_invalid_is_optional_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    attrs = AttrReadResult()
    attrs.refusals[int(CKA_CHECK_VALUE)] = AttrRefusal(int(CKR_ATTRIBUTE_TYPE_INVALID))
    _setup(monkeypatch, reads=lambda *_a, **_k: attrs)

    assert_skips(
        tae.TestCheckValue().test_generated_key_has_check_value,
        _session(),
        match="CKA_CHECK_VALUE is not supported",
    )

    assert _records() == []


def test_generated_kcv_sensitive_refusal_remains_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    attrs = AttrReadResult()
    attrs.refusals[int(CKA_CHECK_VALUE)] = AttrRefusal(int(CKR_ATTRIBUTE_SENSITIVE))
    _setup(monkeypatch, reads=lambda *_a, **_k: attrs)

    with pytest.raises(pytest.xfail.Exception):
        tae.TestCheckValue().test_generated_key_has_check_value(_session())

    assert [record.reason for record in _records()] == ["honest_deviation"]


def test_optional_kcv_refusal_with_data_remains_self_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    attrs = AttrReadResult()
    attrs.refusals[int(CKA_CHECK_VALUE)] = AttrRefusal(
        int(CKR_ATTRIBUTE_TYPE_INVALID), leaked_len=3
    )
    _setup(monkeypatch, reads=lambda *_a, **_k: attrs)

    with pytest.raises(Failed):
        tae.TestCheckValue().test_generated_key_has_check_value(_session())

    assert [record.reason for record in _records()] == ["self_contradiction"]


def test_present_malformed_kcv_is_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b""})
    classification.set_mechanism("CKM_STALE", operation="C_Stale")

    with pytest.raises(Failed):
        tae.TestCheckValue().test_generated_key_has_check_value(_session())

    rec = _records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_imported_kcv_mismatch_is_a_crypto_ecb_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b"\x00\x00\x00"})
    classification.set_mechanism("CKM_STALE", operation="C_Stale")

    with pytest.raises(Failed):
        tae.TestCheckValue().test_imported_key_kcv_matches_ecb_encrypt(_session())

    rec = _records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert rec.detail == {
        "attribute": CKA_CHECK_VALUE,
        "producer_operation": "C_CreateObject",
        "producer_mechanism": None,
        "comparison_mechanism": "CKM_AES_ECB",
        "oracle": "AES-128(key=00..00, plaintext=00..00)[:3]",
        "expected_hex": "66e94b",
        "actual_hex": "000000",
    }


def test_imported_kcv_uses_independent_aes_known_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b"\x66\xe9\x4b"})

    tae.TestCheckValue().test_imported_key_kcv_matches_ecb_encrypt(_session())

    assert _records() == []


def test_supported_kcv_is_supplied_when_encrypt_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    handles = iter((4, 5))
    imported_attrs: list[dict[int, object]] = []

    def import_key(*_args: object, **kwargs: object) -> int:
        attrs = kwargs["attrs"]
        assert isinstance(attrs, Mapping)
        imported_attrs.append(dict(attrs))
        return next(handles)

    _setup(monkeypatch, reads=lambda *_a, **_k: {CKA_CHECK_VALUE: b"\x66\xe9\x4b"})
    monkeypatch.setattr(tae, "import_secret_key_negotiated", import_key)

    tae.TestCheckValue().test_check_value_present_when_encrypt_false(_session())

    assert imported_attrs == [
        {CKA_ENCRYPT: True, CKA_DECRYPT: True},
        {CKA_ENCRYPT: False, CKA_DECRYPT: True},
    ]
    assert _records() == []


def test_supported_kcv_missing_when_encrypt_false_is_a_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    handles = iter((4, 5))
    reads = iter(({CKA_CHECK_VALUE: b"\x66\xe9\x4b"}, {}))
    _setup(monkeypatch, reads=lambda *_a, **_k: next(reads))
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))

    with pytest.raises(Failed):
        tae.TestCheckValue().test_check_value_present_when_encrypt_false(_session())

    record = _records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.mechanism is None
    assert record.detail == {
        "attribute": CKA_CHECK_VALUE,
        "enabled_supported": True,
        "disabled_supported": False,
    }


def test_reverse_kcv_policy_asymmetry_records_its_actual_direction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    handles = iter((4, 5))
    reads = iter(({}, {CKA_CHECK_VALUE: b"\x66\xe9\x4b"}))
    _setup(monkeypatch, reads=lambda *_a, **_k: next(reads))
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))

    with pytest.raises(Failed):
        tae.TestCheckValue().test_check_value_present_when_encrypt_false(_session())

    record = _records()[-1]
    assert record.reason == "self_contradiction"
    assert record.summary == "CKA_CHECK_VALUE support changed with CKA_ENCRYPT policy"
    assert record.detail == {
        "attribute": CKA_CHECK_VALUE,
        "enabled_supported": False,
        "disabled_supported": True,
    }


def test_kcv_absent_with_both_encrypt_policies_is_optional_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    handles = iter((4, 5))
    _setup(monkeypatch, reads=lambda *_a, **_k: {})
    monkeypatch.setattr(tae, "import_secret_key_negotiated", lambda *_a, **_k: next(handles))

    assert_skips(
        tae.TestCheckValue().test_check_value_present_when_encrypt_false,
        _session(),
        match="CKA_CHECK_VALUE is not supported",
    )

    assert _records() == []


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


def test_optional_absence_escape_hatch_is_scoped_to_kcv() -> None:
    testcase_root = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases"
    approved_source = testcase_root / "test_attribute_enforcement.py"
    guarded_calls: list[ast.Call] = []
    for source in testcase_root.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            function_name = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else None
            )
            keyword = next(
                (keyword for keyword in call.keywords if keyword.arg == "optional_if_absent"),
                None,
            )
            if function_name != "attr_or_record" or keyword is None:
                continue
            assert source == approved_source
            assert isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            assert len(call.args) >= 2
            assert isinstance(call.args[1], ast.Name)
            assert call.args[1].id == "CKA_CHECK_VALUE"
            ancestor = parents[call]
            while not isinstance(ancestor, ast.ClassDef):
                ancestor = parents[ancestor]
            assert ancestor.name == "TestCheckValue"
            guarded_calls.append(call)
    assert guarded_calls


def test_attribute_enforcement_access_slice_is_analyzer_clean() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "test_attribute_enforcement.py"
    )
    assert analyze_paths([source]) == []

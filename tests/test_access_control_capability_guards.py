"""Regression tests for access-control capability guards."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_COPYABLE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODIFIABLE,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_access_control
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def test_access_control_attribute_access_slice_is_analyzer_clean() -> None:
    """The access-control migration remains covered by the F7 prevention gate."""
    path = (
        Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_access_control.py"
    )

    assert analyze_file(path) == []


def test_secret_key_access_control_skips_when_aes_keygen_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Secret-key access-control tests require AES key generation capability."""

    def _unexpected_keygen(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(test_access_control, "gen_aes_key", _unexpected_keygen)
    rs = SimpleNamespace(has_mechanism=lambda _name: False)

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_access_control.TestPrivateAttribute().test_private_key_default_is_private(rs)


def test_secret_key_access_control_xfails_when_advertised_aes_keygen_rejects_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised-but-nonoperational AES key generation is an xfail finding."""

    def _rejected_keygen(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(raw_recipes, "gen_aes_key", _rejected_keygen)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_access_control.TestPrivateAttribute().test_private_key_default_is_private(rs)


def test_secret_key_access_control_uses_operational_aes128_setup_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def _gen_aes_key(*args: Any, **_kwargs: Any) -> int:
        bits = int(args[2])
        calls.append(bits)
        if bits != 128:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return 1

    monkeypatch.setattr(test_access_control, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_control, "gen_aes_key", _gen_aes_key)
    monkeypatch.setattr(
        test_access_control,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_PRIVATE: True},
    )
    monkeypatch.setattr(test_access_control, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = SimpleNamespace(raw=object(), sh=1)

    test_access_control.TestPrivateAttribute().test_private_key_default_is_private(rs)

    assert calls == [128]


def test_copy_access_control_does_not_swallow_harness_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Python assertion in C_CopyObject setup must remain a real failure."""
    monkeypatch.setattr(
        test_access_control,
        "_gen_access_control_aes_key",
        lambda _rs, **_kwargs: 1,
    )
    monkeypatch.setattr(
        test_access_control,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_COPYABLE: True},
    )
    monkeypatch.setattr(
        test_access_control,
        "copy_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    monkeypatch.setattr(test_access_control, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(AssertionError, match="harness bug"):
        test_access_control.TestCopyableAttribute().test_copyable_key_can_be_copied(rs)


@pytest.mark.parametrize(
    ("rv", "actual_ckr"),
    [
        (CKR_FUNCTION_NOT_SUPPORTED, "CKR_FUNCTION_NOT_SUPPORTED"),
        (CKR_GENERAL_ERROR, "CKR_GENERAL_ERROR"),
        (CKR_VENDOR_DEFINED + 1, "0x80000001"),
    ],
)
def test_copy_rejection_is_visible_as_nonoperational_copy_finding(
    rv: int,
    actual_ckr: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean C_CopyObject refusal is not mistaken for absent test capability."""
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_access_control, "read_attributes", lambda *_a, **_k: {CKA_COPYABLE: True}
    )
    monkeypatch.setattr(
        test_access_control,
        "copy_object",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError(
                f"Unexpected CK_RV {actual_ckr}",
                int(rv),
            )
        ),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_access_control.TestCopyableAttribute().test_copyable_key_can_be_copied(
            SimpleNamespace(raw=object(), sh=1)
        )

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_CopyObject"
    assert record.actual_ckr == actual_ckr
    assert destroyed == [1]


def test_modifiable_success_without_label_effect_is_structured_policy_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful setter that has no effect must not become an unclassified assert."""
    monkeypatch.setattr(test_access_control, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_control, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_access_control,
        "read_attributes",
        lambda *_a, **_k: {CKA_MODIFIABLE: True},
    )
    monkeypatch.setattr(test_access_control, "set_attributes", lambda *_a, **_k: None)
    monkeypatch.setattr(test_access_control, "template_from_dict", lambda *_a, **_k: object())
    monkeypatch.setattr(test_access_control, "find_objects", lambda *_a, **_k: [])
    monkeypatch.setattr(test_access_control, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        test_access_control.TestModifiableAttribute().test_modifiable_key_label_changeable(
            SimpleNamespace(raw=object(), sh=1)
        )

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "policy"
    assert record.operation == "C_SetAttributeValue"


def test_copy_extractable_contradiction_is_checked_when_copyable_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_COPYABLE cannot hide a contradictory CKA_EXTRACTABLE readback."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_access_control, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False}
    )
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_access_control.TestCopyObject().test_copy_changes_extractable(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert destroyed == [7]
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "policy"
    assert records[1].operation == "C_GenerateKey"


@pytest.mark.parametrize(
    ("method_name", "returned"),
    [
        ("test_copy_session_object_stays_session", True),
        ("test_copy_token_object_stays_token", False),
    ],
)
def test_copy_token_contradiction_is_checked_when_copyable_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    returned: bool,
) -> None:
    """Missing CKA_COPYABLE cannot hide opposite CKA_TOKEN producer readback."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_access_control, "skip_if_token_write_protected", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        test_access_control, "read_attributes", lambda *_a, **_k: {CKA_TOKEN: returned}
    )
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    method = getattr(test_access_control.TestCopyObject(), method_name)
    with pytest.raises(pytest.fail.Exception):
        method(SimpleNamespace(raw=object(), sh=1, slot_id=1))

    assert destroyed == [7]
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "self_contradiction"]
    assert records[1].kind == "policy"
    assert records[1].operation == "C_GenerateKey"


def test_missing_copyable_attribute_records_and_cleans_up_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_access_control, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_access_control.TestCopyableAttribute().test_copyable_key_can_be_copied(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert destroyed == [7]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_COPYABLE", "id": int(CKA_COPYABLE)},
    }


def test_copy_comparison_checks_independent_attributes_when_some_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An omitted copy attribute suppresses only its own dependent comparison."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_access_control, "copy_object", lambda *_a, **_k: 8)
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    def _read(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_COPYABLE]:
            return {CKA_COPYABLE: True}
        if handle == 8:
            return {CKA_KEY_TYPE: 42, CKA_VALUE_LEN: 16}
        return {CKA_VALUE_LEN: 16}

    monkeypatch.setattr(test_access_control, "read_attributes", _read)

    test_access_control.TestCopyObject().test_copy_with_modified_label(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert destroyed == [8, 7]
    records = C.get_records()
    assert [record.operation for record in records] == ["C_GetAttributeValue"] * 2
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_LABEL",
        "CKA_KEY_TYPE",
    ]


def test_copy_missing_attribute_does_not_hide_later_policy_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing label cannot mask a contradictory copied key type."""
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_access_control, "copy_object", lambda *_a, **_k: 8)
    monkeypatch.setattr(test_access_control, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_COPYABLE]:
            return {CKA_COPYABLE: True}
        if handle == 8:
            return {CKA_KEY_TYPE: 1, CKA_VALUE_LEN: 16}
        return {CKA_KEY_TYPE: 2, CKA_VALUE_LEN: 16}

    monkeypatch.setattr(test_access_control, "read_attributes", _read)

    with pytest.raises(pytest.fail.Exception):
        test_access_control.TestCopyObject().test_copy_with_modified_label(
            SimpleNamespace(raw=object(), sh=1)
        )

    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "wrong_result"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].operation == "C_CopyObject"


def test_copy_records_copied_attribute_evidence_before_source_read_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later source read failure cannot erase earlier copied-object evidence."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_access_control, "copy_object", lambda *_a, **_k: 8)
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    def _read(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_COPYABLE]:
            return {CKA_COPYABLE: True}
        if handle == 8:
            return {}
        raise RuntimeError("source read failed")

    monkeypatch.setattr(test_access_control, "read_attributes", _read)

    with pytest.raises(RuntimeError, match="source read failed"):
        test_access_control.TestCopyObject().test_copy_with_modified_label(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert destroyed == [8, 7]
    records = C.get_records()
    assert [record.operation for record in records] == ["C_GetAttributeValue"] * 3
    assert [record.detail["attribute"]["name"] for record in records if record.detail] == [
        "CKA_LABEL",
        "CKA_KEY_TYPE",
        "CKA_VALUE_LEN",
    ]


@pytest.mark.parametrize(
    ("rv", "actual_ckr"),
    [
        (CKR_FUNCTION_NOT_SUPPORTED, "CKR_FUNCTION_NOT_SUPPORTED"),
        (CKR_GENERAL_ERROR, "CKR_GENERAL_ERROR"),
        (CKR_VENDOR_DEFINED + 1, "0x80000001"),
    ],
)
def test_noncopyable_nonspec_rejection_is_visible_with_actual_ckr(
    rv: int,
    actual_ckr: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only CKR_ACTION_PROHIBITED is a passing non-copyable rejection."""
    destroyed: list[int] = []
    monkeypatch.setattr(test_access_control, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_control, "_gen_access_control_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_access_control, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_access_control,
        "read_attributes",
        lambda *_a, **_k: {CKA_COPYABLE: False},
    )
    monkeypatch.setattr(
        test_access_control,
        "copy_object",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError(
                f"Unexpected CK_RV {actual_ckr}",
                int(rv),
            )
        ),
    )
    monkeypatch.setattr(
        test_access_control,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_access_control.TestCopyObject().test_non_copyable_key_rejected(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert destroyed == [7]
    record = C.get_records()[0]
    assert record.reason == "nonspec_reject"
    assert record.kind == "policy"
    assert record.operation == "C_CopyObject"
    assert record.actual_ckr == actual_ckr
    assert record.expected_ckr == ["CKR_ACTION_PROHIBITED"]


def test_modifiable_create_readback_contradiction_uses_generator_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An accepted false template followed by true readback is a generator finding."""
    monkeypatch.setattr(test_access_control, "_require_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(test_access_control, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_access_control,
        "read_attributes",
        lambda *_a, **_k: {CKA_MODIFIABLE: True},
    )
    monkeypatch.setattr(test_access_control, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception):
        test_access_control.TestModifiableAttribute().test_modifiable_false_blocks_set_attribute(
            SimpleNamespace(raw=object(), sh=1)
        )

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "policy"
    assert record.operation == "C_GenerateKey"

"""Runtime regressions for ML-KEM provider output readback classification."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_ENCAPSULATE,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKK_AES,
    CKK_ML_KEM,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_kem as kem
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_keypair_missing_outputs_are_structured_and_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {})
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    kem.TestMLKEMKeyGeneration().test_ml_kem_keypair_classes(_rs())

    assert destroyed == [11, 12]
    records = C.get_records()
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_CLASS),
        int(CKA_CLASS),
    ]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.actual_ckr is None for record in records)
    # Readback attribution: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert all(record.mechanism is None for record in records)
    assert all("producer_mechanism=CKM_ML_KEM_KEY_PAIR_GEN" in record.label for record in records)


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_false_like_kem_output_is_present_and_structured(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "_decapsulate_ml_kem_or_xfail", lambda *_args: 22)
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {CKA_VALUE: value})
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMDecapsulation().test_decapsulate_generic_secret(_rs())

    assert destroyed == [11, 12, 21, 22]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr(value)
    assert MISSING_ATTRIBUTE is not value


def test_raw_ciphertext_output_is_structured_and_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b""))
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMEncapsulateDecapsulate().test_encapsulate_returns_ciphertext_and_key(_rs())

    assert destroyed == [11, 12, 21]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_EncapsulateKey"
    assert records[0].mechanism == "CKM_ML_KEM"
    assert records[0].detail == {
        "output": {"expected": "non-empty bytes", "actual": "b''"},
    }


def test_missing_first_secret_does_not_hide_later_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "_decapsulate_ml_kem_or_xfail", lambda *_args: 22)

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 21 else {CKA_VALUE: b"short"}

    monkeypatch.setattr(kem, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMEncapsulateDecapsulate().test_encapsulate_decapsulate_shared_secret_matches(
            _rs()
        )

    assert destroyed == [11, 12, 21, 22]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_ML_KEM" in records[0].label
    assert records[1].mechanism == "CKM_ML_KEM"
    assert records[-1].kind == "crypto"


def test_metadata_and_crypto_mismatches_raise_strongest_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))

    def _read(_raw: object, _sh: int, _handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_KEY_TYPE]:
            return {CKA_KEY_TYPE: CKK_ML_KEM}
        return {CKA_VALUE: False}

    monkeypatch.setattr(kem, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMKeyDerivation().test_encapsulate_produces_aes128_key(_rs())

    assert destroyed == [11, 12, 21]
    records = C.get_records()
    assert [record.kind for record in records] == ["metadata", "crypto"]
    assert records[-1].kind == "crypto"


def test_aes_size_outputs_validate_both_values_and_compare_permitted_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "_decapsulate_ml_kem_or_xfail", lambda *_args: 22)

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_VALUE: b"e" * 32} if handle == 21 else {CKA_VALUE: b"d" * 32}

    monkeypatch.setattr(kem, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMDecapsulation().test_decapsulate_aes_key_sizes(_rs(), 16)

    assert destroyed == [11, 12, 21, 22]
    records = C.get_records()
    assert [record.reason for record in records] == [
        "honest_deviation",
        "honest_deviation",
        "wrong_result",
    ]
    assert records[0].detail is not None
    assert records[0].detail["attribute"] == {"expected": "16", "actual": "32"}
    assert records[1].detail is not None
    assert records[1].detail["attribute"] == {"expected": "16", "actual": "32"}
    assert records[2].operation == "C_DecapsulateKey"
    assert records[2].mechanism == "CKM_ML_KEM"


def test_aes_size_permitted_deviation_remains_xfail_when_values_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "_decapsulate_ml_kem_or_xfail", lambda *_args: 22)
    monkeypatch.setattr(
        kem,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"s" * 32},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception):
        kem.TestMLKEMDecapsulation().test_decapsulate_aes_key_sizes(_rs(), 16)

    assert destroyed == [11, 12, 21, 22]
    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "honest_deviation",
    ]


def test_encapsulate_permission_retains_size_query_handle_until_second_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {CKA_ENCAPSULATE: True})
    calls: list[int] = []
    destroyed: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        if len(calls) == 1:
            output_handle.value = 31
            args[-2]._obj.value = 1024
            return CKR_OK
        assert output_handle.value == 31
        assert destroyed == []
        return CKR_KEY_FUNCTION_NOT_PERMITTED

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception):
        kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
        )

    assert calls == [1, 2]
    assert destroyed[:2] == [31, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_EncapsulateKey"
    assert records[0].mechanism == "CKM_ML_KEM"


def test_encapsulate_permission_zero_size_query_handle_then_reject_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        assert output_handle.value == 0
        if len(calls) == 1:
            args[-2]._obj.value = 1024
            return CKR_OK
        return CKR_KEY_FUNCTION_NOT_PERMITTED

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    monkeypatch.setattr(
        kem,
        "read_attributes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not read policy attr")),
    )

    kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
    )

    assert calls == [1, 2]
    assert destroyed == [11, 12]
    assert C.get_records() == []


def test_encapsulate_permission_distinct_handles_are_each_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {CKA_ENCAPSULATE: False})
    calls: list[int] = []
    destroyed: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        if len(calls) == 1:
            output_handle.value = 31
            args[-2]._obj.value = 1024
            return CKR_OK
        assert output_handle.value == 31
        assert destroyed == []
        output_handle.value = 32
        return CKR_KEY_FUNCTION_NOT_PERMITTED

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
        )

    assert calls == [1, 2]
    assert destroyed[:2] == [31, 32]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "accepted_invalid"
    assert records[0].operation == "C_EncapsulateKey"
    assert records[0].mechanism == "CKM_ML_KEM"


def test_encapsulate_missing_readback_but_violated_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: _generate_ml_kem_keypair() already proves
    creation-time acceptance of CKA_ENCAPSULATE=False (gen_keypair() raises
    unless CKR_OK), so a missing CKA_ENCAPSULATE readback must not downgrade a
    proven encapsulate-permission violation to xfail (mutation: restoring the
    pre-fix `elif encap_flag is not MISSING_ATTRIBUTE:` guard -- which skipped
    the policy record entirely on MISSING_ATTRIBUTE -- turns this back into a
    silent pass instead of a fail)."""
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {})
    calls: list[int] = []
    destroyed: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        if len(calls) == 1:
            output_handle.value = 31
            args[-2]._obj.value = 1024
            return CKR_OK
        assert output_handle.value == 31
        assert destroyed == []
        output_handle.value = 32
        return CKR_KEY_FUNCTION_NOT_PERMITTED

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
        )

    assert calls == [1, 2]
    assert destroyed[:2] == [31, 32]
    records = C.get_records()
    assert records[-1].reason == "accepted_invalid"
    assert records[-1].operation == "C_EncapsulateKey"
    assert records[-1].mechanism == "CKM_ML_KEM"


@pytest.mark.parametrize(
    ("value", "reason", "record_count"),
    [
        # F7 claim-sweep: creation-time acceptance of CKA_ENCAPSULATE=False is
        # already proven (gen_keypair() raises unless CKR_OK), so a missing
        # readback must not downgrade the proven violation to a silent pass --
        # it still fails, alongside the "not_operational" readback record.
        (MISSING_ATTRIBUTE, "accepted_invalid", 2),
        (True, "honest_deviation", 1),
        (False, "accepted_invalid", 1),
        (0, "wrong_result", 1),
    ],
    ids=["missing", "true", "false", "malformed"],
)
def test_encapsulate_permission_actual_success_classifies_policy_once(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
    reason: str,
    record_count: int,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    attrs = {} if value is MISSING_ATTRIBUTE else {CKA_ENCAPSULATE: value}
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: attrs)
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        if len(calls) == 1:
            output_handle.value = 31
            args[-2]._obj.value = 1024
            return CKR_OK
        assert output_handle.value == 31
        return CKR_KEY_FUNCTION_NOT_PERMITTED

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    outcome = (
        pytest.raises(pytest.fail.Exception)
        if reason in {"accepted_invalid", "wrong_result"}
        else pytest.raises(pytest.xfail.Exception)
        if reason == "honest_deviation"
        else None
    )
    if outcome is None:
        kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
        )
    else:
        with outcome:
            kem.TestMLKEMNegative().test_encapsulate_missing_permission_flag(
                SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
            )

    assert calls == [1, 2]
    assert destroyed == [31, 11, 12]
    records = C.get_records()
    assert len(records) == record_count
    assert records[-1].reason == reason


@pytest.mark.parametrize("malformed", [b"", False, None], ids=["empty", "false", "none"])
def test_wrong_key_malformed_secret_fails_independent_of_difference(
    monkeypatch: pytest.MonkeyPatch,
    malformed: Any,
) -> None:
    handles = iter([(11, 12), (13, 14)])
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: next(handles))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "decapsulate_key", lambda *_args, **_kwargs: 22)

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_VALUE: b"e" * 32 if handle == 21 else malformed}

    monkeypatch.setattr(kem, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMEncapsulateDecapsulate().test_decapsulate_with_wrong_key_fails_or_differs(
            _rs()
        )

    assert destroyed == [11, 12, 13, 14, 21, 22]
    records = C.get_records()
    assert records
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_ML_KEM"


def test_second_kem_keypair_acquisition_failure_cleans_first_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = iter([(11, 12)])

    def _generate(_rs: Any) -> tuple[int, int]:
        try:
            return next(calls)
        except StopIteration:
            raise RuntimeError("second keypair acquisition failed")

    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", _generate)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="second keypair acquisition failed"):
        kem.TestMLKEMKeyGeneration().test_ml_kem_two_keypairs_distinct(_rs())

    assert destroyed == [11, 12]


def test_decapsulation_permission_setup_secret_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    raw = SimpleNamespace(C_DecapsulateKey=lambda *_args: CKR_KEY_FUNCTION_NOT_PERMITTED)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    kem.TestMLKEMNegative().test_decapsulate_missing_permission_flag(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
    )

    assert destroyed == [11, 12, 21]


def test_decapsulation_permission_acceptance_keeps_operation_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(kem, "_encapsulate_ml_kem_or_xfail", lambda *_args: (21, b"ct"))
    monkeypatch.setattr(kem, "read_attributes", lambda *_args: {CKA_DECAPSULATE: False})
    raw = SimpleNamespace(C_DecapsulateKey=lambda *_args: CKR_OK)
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        kem.TestMLKEMNegative().test_decapsulate_missing_permission_flag(
            SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
        )

    assert destroyed == [11, 12, 21]
    records = C.get_records()
    assert records[-1].reason == "accepted_invalid"
    assert records[-1].operation == "C_DecapsulateKey"
    assert records[-1].mechanism == "CKM_ML_KEM"


# FABLE C-1 regression: read_attributes() returns plain int/bool values (see
# raw/recipes.py read_attributes()), never a CK_CONSTANT. _check_equal_attribute
# previously compared repr(value) == expected where expected was itself
# repr(CK_CONSTANT) (e.g. "<CKO_PUBLIC_KEY: 0x00000002>"), so a fully conformant
# int readback (repr "2") could never match and every call fabricated a
# wrong_result fail. Mutation check: reverting _check_equal_attribute to
# `if repr(value) == expected` (with callers restored to `expected=repr(...)`)
# turns test_conformant_int_readback_produces_no_finding red and
# test_wrong_int_readback_still_fails green-for-the-wrong-reason (message
# changes from a real mismatch to a repr-format artifact) -- both are covered
# below by asserting the exact detail contents, not just outcome/reason.


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (2, CKO_PUBLIC_KEY),  # plain int equal to a CK_CONSTANT's numeric value
        (3, CKO_PRIVATE_KEY),
        (73, CKK_ML_KEM),
        (31, CKK_AES),
        (False, False),  # plain bool readback, not wrapped in a CK_CONSTANT
        (True, True),
    ],
)
def test_conformant_int_readback_produces_no_finding(value: Any, expected: Any) -> None:
    """A plain int/bool readback that numerically matches must not fabricate a fail."""
    assert (
        kem._check_equal_attribute(
            value,
            expected=expected,
            label="regression:plain-int-readback",
            mechanism="CKM_ML_KEM",
        )
        is None
    )


def test_wrong_int_readback_still_fails() -> None:
    """A genuinely wrong plain int readback must still be reported."""
    record = kem._check_equal_attribute(
        73,  # CKK_ML_KEM's value, wrong for a CKA_CLASS check
        expected=CKO_PUBLIC_KEY,
        label="regression:plain-int-readback",
        mechanism="CKM_ML_KEM",
    )
    assert record is not None
    assert record.reason == "wrong_result"
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == "73"
    assert "CKO_PUBLIC_KEY" in record.detail["attribute"]["expected"]


def test_keypair_classes_plain_int_readback_produces_no_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a live provider readback is a plain int, never a CK_CONSTANT --
    conformant CKA_CLASS values (2, 3) must pass test_ml_kem_keypair_classes
    cleanly, with no fabricated wrong_result records."""
    monkeypatch.setattr(kem, "_generate_ml_kem_keypair", lambda _rs: (11, 12))
    destroyed: list[int] = []
    monkeypatch.setattr(kem, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_CLASS: 2 if handle == 11 else 3}

    monkeypatch.setattr(kem, "read_attributes", _read)

    kem.TestMLKEMKeyGeneration().test_ml_kem_keypair_classes(_rs())

    assert destroyed == [11, 12]
    assert C.get_records() == []

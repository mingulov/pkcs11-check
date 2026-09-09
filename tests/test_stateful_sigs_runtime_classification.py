"""Runtime classification meta-test for test_stateful_sigs HSS leaf-budget guard (Phase 4 N2).

The 33rd sign on a 32-leaf HSS key must reject (one-time-key reuse is a security
gap). Converted from a local 'fail on unexpected reject CKR' to the shared
reject_or_classify 3-way:

- the over-budget sign succeeds (no raise) -> fail (key reuse),
- the spec-compatible exhaustion code -> pass,
- any other clean reject code -> xfail.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKK_HSS,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_EXHAUSTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_stateful_sigs as tss
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


def _exhaustion_rv() -> int:
    return int(CKR_KEY_EXHAUSTED)


def _run(monkeypatch: pytest.MonkeyPatch, *, thirty_third: object) -> int:
    """Run the stress probe; return the number of sign attempts performed."""
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_a, **_k: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tss, "_destroy_pair", lambda *_a, **_k: None)

    state = {"calls": 0}

    def _sign(*_a: object, **_k: object) -> bytes:
        state["calls"] += 1
        if state["calls"] <= 32:
            return b"\x01" * 16
        if isinstance(thirty_third, bytes):
            return thirty_third
        raise CkrAssertionError("rv", int(cast(int, thirty_third)))

    monkeypatch.setattr(tss, "sign_single", _sign)
    tss.TestHSSKeyExhaustion().test_hss_sign_past_leaf_budget_returns_key_exhausted(_session())
    return state["calls"]


def _run_with_early_refusal(monkeypatch: pytest.MonkeyPatch, refusal: BaseException) -> int:
    """Run the exhaustion probe with a refusal on its first positive sign."""
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_a, **_k: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tss, "_destroy_pair", lambda *_a, **_k: None)

    state = {"calls": 0}

    def _sign(*_a: object, **_k: object) -> bytes:
        state["calls"] += 1
        if state["calls"] == 1:
            raise refusal
        return b"\x01" * 16

    monkeypatch.setattr(tss, "sign_single", _sign)
    tss.TestHSSKeyExhaustion().test_hss_sign_past_leaf_budget_returns_key_exhausted(_session())
    return state["calls"]


def test_over_budget_success_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, thirty_third=b"\x02" * 16)
    assert not isinstance(ei.value, XFailed)


def test_spec_exhaustion_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run(monkeypatch, thirty_third=_exhaustion_rv()) == 34


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # CKR_GENERAL_ERROR is a clean reject NOT in the exhaustion-compatible set.
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, thirty_third=int(CKR_GENERAL_ERROR))


@pytest.mark.parametrize("rv", [CKR_KEY_EXHAUSTED, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 7])
def test_early_positive_sign_refusal_is_not_operational(
    rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_with_early_refusal(monkeypatch, CkrAssertionError("early refusal", int(rv)))

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == (
        "CKR_KEY_EXHAUSTED"
        if rv == CKR_KEY_EXHAUSTED
        else "CKR_GENERAL_ERROR"
        if rv == CKR_GENERAL_ERROR
        else "0x80000007"
    )


def test_early_positive_sign_undefined_refusal_is_hard_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as exc_info:
        _run_with_early_refusal(monkeypatch, CkrAssertionError("undefined", 0x12345678))

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_early_positive_sign_plain_exception_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("harness failure")
    with pytest.raises(RuntimeError, match="harness failure"):
        _run_with_early_refusal(monkeypatch, error)
    assert C.get_records() == []


def test_stateful_attribute_access_slice_is_analyzer_clean() -> None:
    path = (
        Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_stateful_sigs.py"
    )
    assert analyze_file(path) == []


def test_missing_attribute_does_not_hide_malformed_sibling() -> None:
    attrs = {CKA_KEY_TYPE: "wrong-shape"}

    with pytest.raises(Failed) as exc_info:
        tss._raise_strongest(
            tss._check_expected_attributes(
                attrs,
                expected=(
                    (CKA_SENSITIVE, True, "HSS:private CKA_SENSITIVE"),
                    (CKA_KEY_TYPE, CKK_HSS, "HSS:private CKA_KEY_TYPE"),
                ),
                mechanism="CKM_HSS_KEY_PAIR_GEN",
            )
        )

    assert not isinstance(exc_info.value, XFailed)
    records = C.get_records()
    assert [(record.operation, record.mechanism) for record in records] == [
        ("C_GetAttributeValue", "CKM_HSS_KEY_PAIR_GEN"),
        ("C_GetAttributeValue", "CKM_HSS_KEY_PAIR_GEN"),
    ]
    assert records[0].detail == {
        "attribute": {"name": "CKA_SENSITIVE", "id": int(CKA_SENSITIVE)},
    }
    assert records[1].reason == "wrong_result"
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["id"] == int(CKA_KEY_TYPE)


def test_false_like_attributes_are_present_and_checked() -> None:
    records = tss._check_expected_attributes(
        {
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: 0,
        },
        expected=(
            (CKA_SENSITIVE, True, "HSS:private CKA_SENSITIVE"),
            (CKA_EXTRACTABLE, False, "HSS:private CKA_EXTRACTABLE"),
        ),
        mechanism="CKM_HSS_KEY_PAIR_GEN",
    )

    assert len(records) == 2
    assert all(record.reason == "wrong_result" for record in records)
    assert all(record.operation == "C_GetAttributeValue" for record in records)


def test_ckr_ok_zero_handle_is_lifecycle_finding_and_cleans_partial_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(
        tss,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(int(handle)),
    )

    with pytest.raises(Failed) as exc_info:
        tss._finish_keypair_generation(
            SimpleNamespace(raw=object(), sh=1),
            CK_OBJECT_HANDLE(0),
            CK_OBJECT_HANDLE(23),
            int(CKR_OK),
            name="HSS",
            mechanism="CKM_HSS_KEY_PAIR_GEN",
        )

    assert not isinstance(exc_info.value, XFailed)
    assert destroyed == [23]
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_HSS_KEY_PAIR_GEN"
    assert record.actual_ckr == "CKR_OK"


def test_keygen_error_cleans_any_partial_pair_before_typed_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(
        tss,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(int(handle)),
    )

    with pytest.raises(CkrAssertionError) as exc_info:
        tss._finish_keypair_generation(
            SimpleNamespace(raw=object(), sh=1),
            CK_OBJECT_HANDLE(11),
            CK_OBJECT_HANDLE(12),
            int(CKR_FUNCTION_FAILED),
            name="HSS",
            mechanism="CKM_HSS_KEY_PAIR_GEN",
        )

    assert exc_info.value.rv == int(CKR_FUNCTION_FAILED)
    assert destroyed == [11, 12]
    assert C.get_records() == []


def test_successful_sign_with_empty_signature_is_hard_crypto_finding() -> None:
    with pytest.raises(Failed) as exc_info:
        tss._require_signature(b"", name="HSS", mechanism="CKM_HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_HSS"
    assert record.actual_ckr is None


def test_tampered_signature_acceptance_is_hard_crypto_finding() -> None:
    with pytest.raises(Failed) as exc_info:
        tss._require_tampered_rejection(True, name="HSS", mechanism="CKM_HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "accepted_invalid"
    assert record.kind == "crypto"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_HSS"
    assert record.actual_ckr == "CKR_OK"


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_KEY_HANDLE_INVALID])
def test_exhaustion_alternative_is_visible_xfail_and_runs_both_attempts(
    rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert _run(monkeypatch, thirty_third=int(rv)) == 34

    records = C.get_records()
    assert len(records) == 2
    assert all(record.reason == "nonspec_reject" for record in records)
    assert all(record.expected_ckr == ["CKR_KEY_EXHAUSTED"] for record in records)
    assert all(record.actual_ckr == str(rv) for record in records)
    assert all(record.operation == "C_Sign" for record in records)
    assert all(record.mechanism == "CKM_HSS" for record in records)


def test_undefined_exhaustion_rv_is_hard_metadata_finding_and_runs_both_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    undefined_rv = 0x12345678
    with pytest.raises(Failed) as exc_info:
        assert _run(monkeypatch, thirty_third=undefined_rv) == 34

    assert not isinstance(exc_info.value, XFailed)
    records = C.get_records()
    assert len(records) == 2
    assert all(record.reason == "self_contradiction" for record in records)
    assert all(record.kind == "metadata" for record in records)
    assert all(record.expected_ckr == ["CKR_KEY_EXHAUSTED"] for record in records)
    assert all(record.actual_ckr == "0x12345678" for record in records)


def test_keygen_clean_standard_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    def _reject(_rs: object) -> tuple[int, int]:
        raise CkrAssertionError("rejected", int(CKR_GENERAL_ERROR))

    with pytest.raises(pytest.xfail.Exception):
        tss._try_keygen(_reject, _session(), "HSS")

    record = C.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_HSS_KEY_PAIR_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_keygen_undefined_refusal_is_hard_metadata_finding() -> None:
    def _reject(_rs: object) -> tuple[int, int]:
        raise CkrAssertionError("undefined", 0x12345678)

    with pytest.raises(Failed) as exc_info:
        tss._try_keygen(_reject, _session(), "HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_HSS_KEY_PAIR_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_sign_undefined_refusal_is_hard_metadata_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tss,
        "sign_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CkrAssertionError("undefined", 0x12345678)),
    )

    with pytest.raises(Failed) as exc_info:
        tss._try_sign(_session(), 2, 0, "HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_sign_clean_vendor_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tss,
        "sign_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("vendor", int(CKR_VENDOR_DEFINED) + 7)
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        tss._try_sign(_session(), 2, 0, "HSS")

    record = C.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x80000007"


def test_valid_verify_undefined_refusal_is_hard_metadata_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tss,
        "verify_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CkrAssertionError("undefined", 0x12345678)),
    )
    with pytest.raises(Failed) as exc_info:
        tss._try_verify(_session(), 1, 0, b"msg", b"sig", name="HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x12345678"


def test_sign_plain_exception_is_not_reclassified(monkeypatch: pytest.MonkeyPatch) -> None:
    error = RuntimeError("harness failure")
    monkeypatch.setattr(tss, "sign_single", lambda *_args, **_kwargs: (_ for _ in ()).throw(error))

    with pytest.raises(RuntimeError, match="harness failure"):
        tss._try_sign(_session(), 2, 0, "HSS")
    assert C.get_records() == []


def test_valid_verify_clean_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tss,
        "verify_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("refused", int(CKR_GENERAL_ERROR))
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        tss._try_verify(_session(), 1, 0, b"msg", b"sig", name="HSS")

    record = C.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_valid_verify_false_is_hard_crypto_finding() -> None:
    with pytest.raises(Failed) as exc_info:
        tss._require_valid_verification(False, name="HSS", mechanism="CKM_HSS")

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_HSS"
    assert record.actual_ckr is None


@pytest.mark.parametrize("rv", [CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE])
def test_tampered_verify_spec_rejection_is_pass(rv: int) -> None:
    tss._handle_tampered_verify_error(
        CkrAssertionError("mismatch", int(rv)),
        name="HSS",
        mechanism="CKM_HSS",
    )
    assert C.get_records() == []


def test_tampered_verify_other_clean_rejection_is_exact_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        tss._handle_tampered_verify_error(
            CkrAssertionError("other", int(CKR_GENERAL_ERROR)),
            name="HSS",
            mechanism="CKM_HSS",
        )

    record = C.get_records()[-1]
    assert record.reason == "nonspec_reject"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_HSS"
    assert record.expected_ckr == ["CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE"]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_tampered_verify_undefined_rejection_is_hard_metadata_finding() -> None:
    with pytest.raises(Failed) as exc_info:
        tss._handle_tampered_verify_error(
            CkrAssertionError("undefined", 0x12345678),
            name="HSS",
            mechanism="CKM_HSS",
        )

    assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.expected_ckr == ["CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE"]
    assert record.actual_ckr == "0x12345678"


@pytest.mark.parametrize(
    ("test_case", "method_name"),
    [
        (tss.TestHSSKeyGeneration, "test_keypair_key_type"),
        (tss.TestXMSSKeyGeneration, "test_keypair_key_type"),
        (tss.TestXMSSMTKeyGeneration, "test_keypair_key_type"),
        (tss.TestHSSKeyGeneration, "test_keypair_classes"),
        (tss.TestXMSSKeyGeneration, "test_keypair_classes"),
        (tss.TestXMSSMTKeyGeneration, "test_keypair_classes"),
    ],
)
@pytest.mark.parametrize(
    ("first_rv", "second_rv"),
    [
        (CKR_GENERAL_ERROR, 0x12345678),
        (0x12345678, CKR_GENERAL_ERROR),
    ],
)
def test_pair_attribute_refusals_are_independent_and_preserve_order(
    test_case: type[Any],
    method_name: str,
    first_rv: int,
    second_rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both key legs are read before the strongest deferred result is raised."""
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(tss, "_destroy_pair", lambda *_args, **_kwargs: None)
    handles: list[int] = []
    refusals = [
        CkrAssertionError("pair read", first_rv),
        CkrAssertionError("pair read", second_rv),
    ]

    def _read(_raw: object, _session: int, handle: int, _attrs: object) -> dict[int, object]:
        handles.append(handle)
        raise refusals.pop(0)

    monkeypatch.setattr(tss, "read_attributes", _read)

    with pytest.raises(Failed) as exc_info:
        getattr(test_case(), method_name)(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert handles == [1, 2]
    records = C.get_records()
    assert len(records) == 2
    assert records[0].expected_ckr == ["CKR_OK"]
    assert records[1].expected_ckr == ["CKR_OK"]
    assert records[0].actual_ckr == (
        "CKR_GENERAL_ERROR" if first_rv == int(CKR_GENERAL_ERROR) else "0x12345678"
    )
    assert records[1].actual_ckr == (
        "CKR_GENERAL_ERROR" if second_rv == int(CKR_GENERAL_ERROR) else "0x12345678"
    )
    if second_rv == 0x12345678:
        assert records[0].reason == "not_operational"
        assert records[1].reason == "self_contradiction"
        assert "undefined" in str(exc_info.value)
    else:
        assert records[0].reason == "self_contradiction"
        assert records[1].reason == "not_operational"


@pytest.mark.parametrize(
    ("test_case", "mechanism"),
    [
        (tss.TestHSSKeyGeneration, "CKM_HSS_KEY_PAIR_GEN"),
        (tss.TestXMSSKeyGeneration, "CKM_XMSS_KEY_PAIR_GEN"),
        (tss.TestXMSSMTKeyGeneration, "CKM_XMSSMT_KEY_PAIR_GEN"),
    ],
)
@pytest.mark.parametrize("rv", [CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 7, 0x12345678])
def test_private_attribute_read_refusal_is_structured_and_cleans_pair(
    test_case: type[Any],
    mechanism: str,
    rv: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        tss,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )
    refusal = CkrAssertionError("private attributes", rv)
    monkeypatch.setattr(
        tss,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
    )

    outcome: type[BaseException] = Failed if rv == 0x12345678 else pytest.xfail.Exception
    with pytest.raises(outcome) as exc_info:
        test_case().test_private_key_attributes(_session())

    if rv == 0x12345678:
        assert not isinstance(exc_info.value, XFailed)
    record = C.get_records()[-1]
    assert record.reason == ("self_contradiction" if rv == 0x12345678 else "not_operational")
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == mechanism
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == (
        "0x12345678"
        if rv == 0x12345678
        else "CKR_GENERAL_ERROR"
        if rv == CKR_GENERAL_ERROR
        else "0x80000007"
    )
    assert destroyed == [1, 2]


@pytest.mark.parametrize(
    ("test_case", "mechanism"),
    [
        (tss.TestHSSKeyGeneration, "CKM_HSS_KEY_PAIR_GEN"),
        (tss.TestXMSSKeyGeneration, "CKM_XMSS_KEY_PAIR_GEN"),
        (tss.TestXMSSMTKeyGeneration, "CKM_XMSSMT_KEY_PAIR_GEN"),
    ],
)
def test_private_attribute_readback_preserves_missing_and_malformed_siblings(
    test_case: type[Any],
    mechanism: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        tss,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )
    monkeypatch.setattr(tss, "read_attributes", lambda *_args, **_kwargs: {CKA_EXTRACTABLE: 0})

    with pytest.raises(Failed) as exc_info:
        test_case().test_private_key_attributes(_session())

    assert not isinstance(exc_info.value, XFailed)
    records = C.get_records()
    assert len(records) == 2
    assert records[0].reason == "not_operational"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["id"] == int(CKA_SENSITIVE)
    assert records[1].reason == "wrong_result"
    assert records[1].mechanism == mechanism
    assert records[1].detail is not None
    assert records[1].detail["attribute"]["id"] == int(CKA_EXTRACTABLE)
    assert destroyed == [1, 2]


@pytest.mark.parametrize(
    "test_case",
    [tss.TestHSSKeyGeneration, tss.TestXMSSKeyGeneration, tss.TestXMSSMTKeyGeneration],
)
def test_private_attribute_plain_read_exception_propagates_after_cleanup(
    test_case: type[Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(tss, "_skip_if_no", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tss, "_try_keygen", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        tss,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )
    error = RuntimeError("harness failure")
    monkeypatch.setattr(
        tss,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )

    with pytest.raises(RuntimeError, match="harness failure"):
        test_case().test_private_key_attributes(_session())
    assert C.get_records() == []
    assert destroyed == [1, 2]

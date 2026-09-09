"""F7 regressions for key-usage attribute readback and ML-KEM policy probes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCAPSULATE,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_key_usage_policy as policy
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_paths


@pytest.fixture(autouse=True)
def _clear_classifications():  # type: ignore[no-untyped-def]
    C.clear()
    yield
    C.clear()


def _session(raw: object | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        raw=SimpleNamespace() if raw is None else raw,
        sh=1,
        has_mechanism=lambda _name: True,
    )


def test_missing_capability_readback_does_not_hide_forbidden_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(policy, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(policy, "gen_aes_key", lambda *_a, **_k: 17)
    monkeypatch.setattr(policy, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(policy, "destroy_quietly", lambda *_a, **_k: None)

    def _encrypt_init(*_args: object) -> int:
        calls.append("C_EncryptInit")
        return int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(C_EncryptInit=_encrypt_init)
    policy.TestAESKeyUsagePolicy().test_decrypt_only_key_cannot_encrypt(_session(raw))

    assert calls == ["C_EncryptInit"]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["id"] == int(CKA_DECRYPT)
    assert MISSING_ATTRIBUTE is not False


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_present_false_like_capability_is_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(policy, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(policy, "gen_aes_key", lambda *_a, **_k: 17)
    monkeypatch.setattr(
        policy,
        "read_attributes",
        lambda *_a, **_k: {CKA_DECRYPT: value},
    )
    monkeypatch.setattr(policy, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(policy, "encrypt_single", lambda *_a, **_k: b"\x00" * 16)
    raw = SimpleNamespace(C_EncryptInit=lambda *_a, **_k: int(CKR_KEY_FUNCTION_NOT_PERMITTED))

    with pytest.raises(pytest.fail.Exception):
        policy.TestAESKeyUsagePolicy().test_decrypt_only_key_cannot_encrypt(_session(raw))

    assert C.get_records()
    assert C.get_records()[-1].reason == "wrong_result"


def test_kem_size_query_handle_survives_rejecting_second_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(policy, "read_attributes", lambda *_a, **_k: {CKA_ENCAPSULATE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        output_len = args[-2]._obj
        if len(calls) == 1:
            output_handle.value = 31
            output_len.value = 1088
            return int(CKR_OK)
        assert output_handle.value == 0
        return int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session(raw))

    assert calls == [1, 2]
    assert 31 in destroyed
    assert destroyed[-2:] == [11, 12]


def test_kem_cleanup_deduplicates_handles_shared_by_keypair_and_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handles from independent raw sources are destroyed exactly once."""
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (31, 32))
    monkeypatch.setattr(policy, "read_attributes", lambda *_a, **_k: {CKA_ENCAPSULATE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 31
        args[-2]._obj.value = 1088
        return int(CKR_OK) if calls == 1 else int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session(raw))
    assert calls == 2
    assert destroyed == [31, 32]


def test_kem_buffer_too_small_size_query_still_runs_full_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        output_len = args[-2]._obj
        output_handle.value = 0
        output_len.value = 1088
        return int(CKR_BUFFER_TOO_SMALL) if len(calls) == 1 else int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session(raw))

    assert calls == [1, 2]
    assert destroyed == [11, 12]


def test_kem_full_ok_without_handle_is_hard_lifecycle_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 0
        args[-2]._obj.value = 1088
        return int(CKR_OK)

    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert calls == 2
    assert destroyed == [11, 12]
    record = next(record for record in C.get_records() if "output handle" in record.label)
    assert record.operation == "C_EncapsulateKey"
    assert record.actual_ckr == "CKR_OK"


def test_kem_malformed_ciphertext_never_reaches_decapsulation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    decapsulation_calls = 0

    def _encapsulate(*args: Any) -> int:
        args[-1]._obj.value = 31 if args[-3] is not None else 0
        args[-2]._obj.value = 32
        return int(CKR_OK)

    def _decapsulate(*_args: Any) -> int:
        nonlocal decapsulation_calls
        decapsulation_calls += 1
        return int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate, C_DecapsulateKey=_decapsulate)
    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session(raw))
    assert decapsulation_calls == 0
    assert 31 in destroyed
    assert 11 in destroyed and 12 in destroyed
    assert any(
        record.kind == "crypto" and record.operation == "C_EncapsulateKey"
        for record in C.get_records()
    )


def test_kem_size_query_effect_is_checked_when_full_call_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(policy, "read_attributes", lambda *_a, **_k: {CKA_ENCAPSULATE: False})
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        output_handle = args[-1]._obj
        output_len = args[-2]._obj
        if len(calls) == 1:
            output_handle.value = 31
            output_len.value = 1088
            return int(CKR_OK)
        output_handle.value = 0
        return int(CKR_BUFFER_TOO_SMALL)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session(raw))

    assert calls == [1, 2]
    assert destroyed[:2] == [31, 11]
    assert destroyed[-1] == 12
    records = C.get_records()
    assert records[-1].reason == "accepted_invalid"


def test_kem_malformed_query_length_preserves_independent_policy_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        assert attrs == [CKA_ENCAPSULATE]
        return {CKA_ENCAPSULATE: False}

    monkeypatch.setattr(policy, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            assert args[-3] is None
            args[-1]._obj.value = 31
            args[-2]._obj.value = 32
            return int(CKR_OK)
        assert args[-3] is not None
        assert args[-1]._obj.value == 0
        return int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    with pytest.raises(pytest.fail.Exception) as raised:
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )

    assert calls == 2
    assert reads == [11]
    assert destroyed == [31, 11, 12]
    records = C.get_records()
    assert len(records) == 2
    malformed, policy_record = records
    assert malformed.reason == "wrong_result"
    assert malformed.kind == "crypto"
    assert malformed.outcome == "fail"
    assert malformed.operation == "C_EncapsulateKey"
    assert malformed.mechanism == "CKM_ML_KEM"
    assert malformed.actual_ckr == "CKR_OK"
    assert malformed.detail == {
        "phase": "size-query",
        "expected_length": 1088,
        "actual_length": 32,
        "capacity": 1088,
        "return_value": int(CKR_OK),
    }
    assert policy_record.reason == "accepted_invalid"
    assert policy_record.kind == "policy"
    assert policy_record.outcome == "fail"
    assert policy_record.operation == "C_EncapsulateKey"
    assert policy_record.mechanism == "CKM_ML_KEM"
    assert policy_record.actual_ckr == "CKR_OK"
    assert policy_record.expected_ckr == ["CKR_KEY_FUNCTION_NOT_PERMITTED"]
    strongest = getattr(raised.value, "_pkcs11_check_classification")
    assert strongest == malformed
    assert strongest.outcome == "fail"


@pytest.mark.parametrize("claimed", [False, None], ids=["restricted", "missing"])
@pytest.mark.parametrize("full_handle", [0, 32], ids=["missing-handle", "present-handle"])
def test_kem_valid_query_effect_survives_malformed_full_output(
    monkeypatch: pytest.MonkeyPatch,
    claimed: bool | None,
    full_handle: int,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        assert attrs == [CKA_ENCAPSULATE]
        return {} if claimed is None else {CKA_ENCAPSULATE: claimed}

    monkeypatch.setattr(policy, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 31 if calls == 1 else full_handle
        args[-2]._obj.value = 1088 if calls == 1 else 32
        return int(CKR_OK)

    with pytest.raises(pytest.fail.Exception) as raised:
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )

    assert calls == 2
    assert reads == [11]
    assert destroyed == ([31, 32, 11, 12] if full_handle else [31, 11, 12])
    records = C.get_records()
    malformed = next(record for record in records if "full-call ciphertext output" in record.label)
    assert malformed.reason == "wrong_result"
    assert malformed.kind == "crypto"
    policy_record = records[-1]
    assert policy_record.reason == ("not_operational" if claimed is None else "accepted_invalid")
    assert policy_record.operation == "C_EncapsulateKey"
    assert policy_record.actual_ckr == "CKR_OK"
    strongest = getattr(raised.value, "_pkcs11_check_classification")
    assert strongest.outcome == "fail"
    assert strongest.kind == "crypto"
    assert strongest.severity == malformed.severity


def test_kem_decapsulation_setup_uses_restricted_pair_and_retains_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated: list[dict[str, bool]] = []

    def _generate(_rs: Any, **kwargs: bool) -> tuple[int, int]:
        generated.append(kwargs)
        return 11, 12

    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        _generate,
    )
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    encapsulate_calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal encapsulate_calls
        encapsulate_calls += 1
        output_handle = args[-1]._obj
        output_len = args[-2]._obj
        if encapsulate_calls == 1:
            output_handle.value = 31
            output_len.value = 1088
        else:
            output_handle.value = 32
            output_len.value = 1088
        return int(CKR_OK)

    decap_private_handles: list[int] = []

    def _decapsulate(*args: Any) -> int:
        decap_private_handles.append(args[2])
        return int(CKR_KEY_FUNCTION_NOT_PERMITTED)

    raw = SimpleNamespace(
        C_EncapsulateKey=_encapsulate,
        C_DecapsulateKey=_decapsulate,
    )
    policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session(raw))

    assert generated == [{"encapsulate": True, "decapsulate": False}]
    assert decap_private_handles == [12]
    assert destroyed == [31, 32, 11, 12]


def test_kem_keypair_setup_reject_has_exact_operation_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unsupported", int(CKR_FUNCTION_NOT_SUPPORTED))
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session())

    record = C.get_records()[0]
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_ML_KEM_KEY_PAIR_GEN"
    assert record.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"


def test_f7_policy_attribute_access_scoped_analyzer_is_clean() -> None:
    root = Path(__file__).parents[1]
    paths = [
        root / "src/pkcs11_check/testcases/test_key_usage_policy.py",
        root / "src/pkcs11_check/testcases/test_sensitivity.py",
    ]
    assert analyze_paths(paths) == []


def test_kem_missing_claim_is_structured_when_operation_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(policy, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls: list[int] = []

    def _encapsulate(*args: Any) -> int:
        calls.append(len(calls) + 1)
        args[-1]._obj.value = 31
        args[-2]._obj.value = 1088
        return int(CKR_OK)

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate)
    with pytest.raises(pytest.xfail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session(raw))

    assert calls == [1, 2]
    assert destroyed[-2:] == [11, 12]
    records = C.get_records()
    assert records
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_ML_KEM"

"""ML-KEM policy routing keeps provider and harness failures distinguishable."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_FUNCTION_NOT_SUPPORTED, CKR_OK
from pkcs11_check.testcases import test_key_usage_policy as policy


def _session(raw: object) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "ML_KEM",
    )


@pytest.fixture(autouse=True)
def _clear_classifications():  # type: ignore[no-untyped-def]
    C.clear()
    yield
    C.clear()


@pytest.mark.parametrize("exc", [OSError("access violation"), AssertionError("harness bug")])
def test_encapsulate_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exc),
    )

    with pytest.raises(type(exc), match=str(exc)):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace())
        )


@pytest.mark.parametrize("exc", [OSError("access violation"), AssertionError("harness bug")])
def test_decapsulate_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    # The decapsulation probe intentionally owns one restricted pair.  A plain
    # Python failure from that sole setup call must not be reclassified as CKR.
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exc),
    )

    with pytest.raises(type(exc), match=str(exc)):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(
            _session(SimpleNamespace())
        )


@pytest.mark.parametrize("exc", [OSError("encapsulation access violation"), AssertionError("bug")])
def test_encapsulate_calls_preserve_exception_and_written_handles(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        output_handle = args[-1]._obj
        output_len = args[-2]._obj
        output_handle.value = 31 + calls - 1
        output_len.value = 1088
        if calls == 2:
            raise exc
        return int(CKR_OK)

    with pytest.raises(type(exc), match=str(exc)):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert calls == 2
    assert destroyed == [31, 32, 1, 2]


def test_encapsulate_query_written_handle_is_retained_when_query_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    def _encapsulate(*args: Any) -> int:
        args[-1]._obj.value = 31
        args[-2]._obj.value = 1088
        raise OSError("query access violation")

    with pytest.raises(OSError, match="query access violation"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert destroyed == [31, 1, 2]


@pytest.mark.parametrize("exc", [OSError("decapsulation access violation"), AssertionError("bug")])
def test_decapsulate_call_preserves_exception_and_written_handle(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    encapsulate_calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal encapsulate_calls
        encapsulate_calls += 1
        args[-1]._obj.value = 31 + encapsulate_calls - 1
        args[-2]._obj.value = 1088
        return int(CKR_OK)

    def _decapsulate(*args: Any) -> int:
        args[-1]._obj.value = 41
        raise exc

    raw = SimpleNamespace(C_EncapsulateKey=_encapsulate, C_DecapsulateKey=_decapsulate)
    with pytest.raises(type(exc), match=str(exc)):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session(raw))
    assert encapsulate_calls == 2
    assert destroyed == [31, 32, 41, 1, 2]


@pytest.mark.parametrize("raising_call", [1, 2])
def test_decapsulate_setup_calls_preserve_each_written_handle_on_exception(
    monkeypatch: pytest.MonkeyPatch,
    raising_call: int,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 30 + calls
        args[-2]._obj.value = 1088
        if calls == raising_call:
            raise OSError(f"setup call {raising_call} access violation")
        return int(CKR_OK)

    with pytest.raises(OSError, match=f"setup call {raising_call} access violation"):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert calls == raising_call
    assert destroyed == [31, 32][:raising_call] + [1, 2]


def test_provider_xfail_does_not_mask_cleanup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []

    def _destroy(_raw: object, _sh: object, handle: int) -> None:
        destroyed.append(handle)
        raise OSError(f"cleanup failed for {handle}")

    monkeypatch.setattr(policy, "destroy_quietly", _destroy)
    calls = 0

    def _encapsulate(*args: Any) -> int:
        nonlocal calls
        calls += 1
        args[-1]._obj.value = 0
        args[-2]._obj.value = 1088
        return int(CKR_BUFFER_TOO_SMALL) if calls == 1 else int(CKR_FUNCTION_NOT_SUPPORTED)

    with pytest.raises(OSError, match="cleanup failed for 1"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert destroyed == [1, 2]
    records = C.get_records()
    assert any(record.reason == "nonspec_reject" for record in records)
    assert [record for record in records if record.reason == "harness_error"]


def test_cleanup_error_is_recorded_without_replacing_plain_provider_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []

    def _destroy(_raw: object, _sh: object, handle: int) -> None:
        destroyed.append(handle)
        raise OSError(f"cleanup failed for {handle}")

    monkeypatch.setattr(policy, "destroy_quietly", _destroy)

    def _encapsulate(*args: Any) -> int:
        args[-1]._obj.value = 31
        args[-2]._obj.value = 1088
        raise OSError("provider call failed")

    with pytest.raises(OSError, match="provider call failed"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    assert destroyed == [31, 1, 2]
    assert any(record.reason == "harness_error" for record in C.get_records())


def test_advertised_clean_setup_refusal_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
    )

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM keypair generation"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace())
        )
    record = C.get_records()[-1]
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_ML_KEM_KEY_PAIR_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"


def test_unknown_setup_ckr_is_hard_and_exactly_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = CkrAssertionError("Unexpected CK_RV", 0x7FFFFFFF)
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
    )

    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace())
        )
    record = C.get_records()[0]
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_ML_KEM_KEY_PAIR_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "0x7fffffff"


def test_setup_ckr_ok_exception_is_hard_policy_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = CkrAssertionError("unexpected successful setup", int(CKR_OK))
    monkeypatch.setattr(
        policy,
        "_gen_ml_kem_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(refusal),
    )

    with pytest.raises(pytest.fail.Exception):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(
            _session(SimpleNamespace())
        )
    record = C.get_records()[0]
    assert record.reason == "accepted_invalid"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_ML_KEM_KEY_PAIR_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_OK"


def test_encapsulation_setup_refusal_is_visible_with_raw_operation_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    destroyed: list[int] = []
    monkeypatch.setattr(
        policy, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    def _encapsulate(*_args: Any) -> int:
        return int(CKR_FUNCTION_NOT_SUPPORTED)

    with pytest.raises(pytest.xfail.Exception):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(
            _session(SimpleNamespace(C_EncapsulateKey=_encapsulate))
        )
    record = C.get_records()[-1]
    assert record.operation == "C_EncapsulateKey"
    assert record.mechanism == "CKM_ML_KEM"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert destroyed == [1, 2]

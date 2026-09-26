"""F6 premise regressions for ALWAYS_AUTHENTICATE enforcement (P11C-0198-008).

``test_always_authenticate_requires_context_login`` must read back
``CKA_ALWAYS_AUTHENTICATE`` from the exact private key and require
``type(value) is bool and value is True`` before any Sign call: a bypass
claim on a key that discarded the attribute is invalid. A bomb Sign helper
proves only exact bool TRUE reaches enforcement.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_AUTHENTICATE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases import test_attribute_enforcement as tae


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    classification.clear()
    yield
    classification.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=SimpleNamespace(), sh=1, has_mechanism=lambda _name: True)


def _setup_keygen(
    monkeypatch: pytest.MonkeyPatch, destroyed: list[int], *, exc: BaseException | None = None
) -> None:
    if exc is None:
        monkeypatch.setattr(tae, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    else:

        def _raise(*_a: object, **_k: object) -> tuple[int, int]:
            raise exc

        monkeypatch.setattr(tae, "gen_rsa_keypair", _raise)
    monkeypatch.setattr(tae, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))


def _bomb_sign(monkeypatch: pytest.MonkeyPatch, calls: list[bytes]) -> None:
    def _explode(*args: object, **kwargs: object) -> bytes:
        data = args[4] if len(args) > 4 else b""
        calls.append(data if isinstance(data, bytes) else b"")
        raise AssertionError("bomb: Sign must not run before exact TRUE readback")

    monkeypatch.setattr(tae, "sign_single", _explode)


def _last_record() -> classification.Classification:
    records = classification.get_records()
    assert len(records) == 1
    return records[0]


def test_defined_keygen_refusal_is_metadata_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed, exc=CkrAssertionError("busy", int(CKR_GENERAL_ERROR)))
    _bomb_sign(monkeypatch, sign_calls)

    with pytest.raises(XFailed):
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert sign_calls == []
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_undefined_keygen_ckr_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed, exc=CkrAssertionError("weird", 0x12345678))
    _bomb_sign(monkeypatch, sign_calls)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert sign_calls == []
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_GenerateKeyPair"
    assert record.actual_ckr == "0x12345678"


def test_defined_readback_rejection_is_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)

    def _refuse(*_a: object, **_k: object) -> dict[int, Any]:
        raise CkrAssertionError("busy", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(tae, "read_attributes", _refuse)

    with pytest.raises(XFailed):
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_undefined_readback_ckr_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)

    def _refuse(*_a: object, **_k: object) -> dict[int, Any]:
        raise CkrAssertionError("weird", 0x12345678)

    monkeypatch.setattr(tae, "read_attributes", _refuse)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"


def test_missing_readback_returns_honest_deviation_without_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: {})

    tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "honest_deviation"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None


def test_clean_attribute_refusal_returns_honest_deviation_without_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)
    attrs = AttrReadResult()
    attrs.refusals[int(CKA_ALWAYS_AUTHENTICATE)] = AttrRefusal(int(CKR_ATTRIBUTE_TYPE_INVALID))
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: attrs)

    tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "honest_deviation"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def test_refusal_with_leaked_bytes_is_a_policy_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)
    attrs = AttrReadResult()
    attrs.refusals[int(CKA_ALWAYS_AUTHENTICATE)] = AttrRefusal(
        int(CKR_ATTRIBUTE_TYPE_INVALID), leaked_len=4
    )
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: attrs)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.kind == "policy"
    assert record.operation == "C_GetAttributeValue"


@pytest.mark.parametrize("value", [1, b"\x01", "True"])
def test_present_non_bool_readback_is_a_metadata_failure(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: value})

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail is not None
    assert record.detail["expected_shape"] == "CK_BBOOL"
    assert record.detail["actual_type"] == type(value).__name__
    assert record.detail["actual_repr"] == repr(value)
    assert record.detail["producer_operation"] == "C_GenerateKeyPair"
    assert record.detail["producer_mechanism"] == "CKM_RSA_PKCS_KEY_PAIR_GEN"


def test_exact_false_readback_is_a_keygen_policy_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    sign_calls: list[bytes] = []
    _setup_keygen(monkeypatch, destroyed)
    _bomb_sign(monkeypatch, sign_calls)
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: False})

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert sign_calls == []
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "policy"
    assert record.operation == "C_GenerateKeyPair"
    assert record.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    assert record.detail is not None
    assert record.detail["actual_value"] is False


def _setup_exact_true(
    monkeypatch: pytest.MonkeyPatch, destroyed: list[int], sign_impl: Any
) -> None:
    _setup_keygen(monkeypatch, destroyed)
    monkeypatch.setattr(tae, "read_attributes", lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True})
    monkeypatch.setattr(tae, "sign_single", sign_impl)


def test_canonical_not_logged_in_is_enforcement_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def _reject(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError("reauth required", int(CKR_USER_NOT_LOGGED_IN))

    _setup_exact_true(monkeypatch, destroyed, _reject)

    tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert destroyed == [3, 2]
    assert classification.get_records() == []


def test_other_clean_sign_refusal_is_nonspec_reject_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def _reject(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError("failed", int(CKR_FUNCTION_FAILED))

    _setup_exact_true(monkeypatch, destroyed, _reject)

    with pytest.raises(XFailed):
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "nonspec_reject"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_RSA_PKCS"
    assert record.expected_ckr == ["CKR_USER_NOT_LOGGED_IN"]
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"


def test_undefined_sign_ckr_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []

    def _reject(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError("weird", 0x12345678)

    _setup_exact_true(monkeypatch, destroyed, _reject)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_RSA_PKCS"


def test_usable_sign_success_is_a_policy_bypass_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    _setup_exact_true(monkeypatch, destroyed, lambda *_a, **_k: b"s" * 256)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.kind == "policy"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_RSA_PKCS"
    assert record.actual_ckr == "CKR_OK"
    assert record.detail is not None
    assert record.detail["signature_length"] == 256


@pytest.mark.parametrize("bad_sig", [b"", b"s" * 128])
def test_malformed_sign_success_is_a_crypto_failure(
    monkeypatch: pytest.MonkeyPatch, bad_sig: bytes
) -> None:
    destroyed: list[int] = []
    _setup_exact_true(monkeypatch, destroyed, lambda *_a, **_k: bad_sig)

    with pytest.raises(Failed) as exc_info:
        tae.TestAlwaysAuthenticate().test_always_authenticate_requires_context_login(_session())

    assert not isinstance(exc_info.value, XFailed)
    assert destroyed == [3, 2]
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_RSA_PKCS"
    assert record.detail is not None
    assert record.detail["actual_length"] == len(bad_sig)

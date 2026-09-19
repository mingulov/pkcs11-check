"""Runtime regressions for CKA_ALWAYS_AUTHENTICATE setup evidence."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_AUTHENTICATE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases import test_always_authenticate as taa
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    classification.clear()
    yield
    classification.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=SimpleNamespace(), sh=1)


def _record() -> classification.Classification:
    records = classification.get_records()
    assert len(records) == 1
    return records[0]


def test_missing_always_auth_readback_is_visible_and_nonterminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(taa, "gen_rsa_keypair", lambda *_args, **_kwargs: (11, 22))
    monkeypatch.setattr(taa, "read_attributes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        taa,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )

    assert taa._try_gen_always_auth_keypair(_session()) is None

    rec = _record()
    assert rec.reason == "honest_deviation"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    # Readback attribution: a plain C_GetAttributeValue readback is never stamped with the mechanism
    # that produced the object being read; the producer still survives in detail
    # (post-hoc merge) and in the label.
    assert rec.mechanism is None
    assert "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN" in rec.label
    assert rec.actual_ckr is None
    assert rec.detail == {
        "attribute": {"name": "CKA_ALWAYS_AUTHENTICATE", "id": int(CKA_ALWAYS_AUTHENTICATE)},
        "producer_operation": "C_GenerateKeyPair",
        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
    }
    assert destroyed == [11, 22]


def test_defined_readback_refusal_is_visible_and_nonterminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(taa, "gen_rsa_keypair", lambda *_args, **_kwargs: (11, 22))
    monkeypatch.setattr(
        taa,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("readback", int(CKR_ATTRIBUTE_TYPE_INVALID))
        ),
    )
    monkeypatch.setattr(
        taa,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )

    assert taa._try_gen_always_auth_keypair(_session()) is None

    rec = _record()
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert rec.detail == {
        "attribute": {"name": "CKA_ALWAYS_AUTHENTICATE", "id": int(CKA_ALWAYS_AUTHENTICATE)},
        "producer_operation": "C_GenerateKeyPair",
        "producer_mechanism": "CKM_RSA_PKCS_KEY_PAIR_GEN",
    }
    assert destroyed == [11, 22]


def test_defined_keygen_refusal_is_visible_xfail_with_producer_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        taa,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            CkrAssertionError("template", int(CKR_ATTRIBUTE_TYPE_INVALID))
        ),
    )

    with pytest.raises(XFailed):
        taa._try_gen_always_auth_keypair(_session())

    rec = _record()
    assert rec.reason == "not_operational"
    assert rec.operation == "C_GenerateKeyPair"
    assert rec.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    assert rec.expected_ckr == ["CKR_OK"]
    assert rec.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


@pytest.mark.parametrize("value", [False, b"\x01"])
def test_present_incorrect_always_auth_readback_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(taa, "gen_rsa_keypair", lambda *_args, **_kwargs: (11, 22))
    monkeypatch.setattr(
        taa,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_ALWAYS_AUTHENTICATE: value},
    )
    monkeypatch.setattr(
        taa,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )

    with pytest.raises(Failed) as exc_info:
        taa._try_gen_always_auth_keypair(_session())

    assert not isinstance(exc_info.value, XFailed)
    rec = _record()
    assert rec.reason == "wrong_result"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    assert rec.actual_ckr == "CKR_OK"
    assert rec.detail is not None
    assert rec.detail["attribute"] == int(CKA_ALWAYS_AUTHENTICATE)
    assert rec.detail["producer_operation"] == "C_GenerateKeyPair"
    assert rec.detail["producer_mechanism"] == "CKM_RSA_PKCS_KEY_PAIR_GEN"
    if value is False:
        assert rec.detail["actual_value"] is False
        assert "expected_shape" not in rec.detail
        assert "actual_type" not in rec.detail
    else:
        assert rec.detail["expected_shape"] == "CK_BBOOL"
        assert rec.detail["actual_type"] == "bytes"
        assert rec.detail["actual_repr"] == repr(value)
        assert "actual_value" not in rec.detail
    assert destroyed == [11, 22]


def test_plain_readback_exception_propagates_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(taa, "gen_rsa_keypair", lambda *_args, **_kwargs: (11, 22))
    monkeypatch.setattr(
        taa,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("harness bug")),
    )
    monkeypatch.setattr(
        taa,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )

    with pytest.raises(RuntimeError, match="harness bug"):
        taa._try_gen_always_auth_keypair(_session())
    assert destroyed == [11, 22]
    assert not classification.get_records()


def test_always_authenticate_attribute_access_is_analyzer_clean() -> None:
    violations = analyze_file(
        "src/pkcs11_check/testcases/test_always_authenticate.py",
    )
    assert violations == []


# --- N-004: context-specific login oracle ------------------------------------
# Spec identifies CKR_OPERATION_NOT_INITIALIZED for improper context-specific
# login; C_Login's return list has no CKR_USER_NOT_LOGGED_IN here. The probe
# stays; NLI and other clean rejects are classified deviations, never passes
# and never raw asserts.


def _run_context_login(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(taa, "_context_specific_login", lambda *_a, **_k: int(login_rv))
    config = SimpleNamespace(pin=SimpleNamespace(get_secret_value=lambda: "1234"))
    taa.TestAlwaysAuthenticateEnforcement().test_context_specific_login_without_active_op_rejected(
        _session(), config
    )


def test_context_login_not_logged_in_is_deviation(monkeypatch: pytest.MonkeyPatch) -> None:
    """N-004: NLI is not in spec's return list here -> xfail, never pass."""
    with pytest.raises(pytest.xfail.Exception):
        _run_context_login(monkeypatch, int(CKR_USER_NOT_LOGGED_IN))
    rec = _record()
    assert rec.reason == "nonspec_reject"
    assert rec.outcome == "xfail"


def test_context_login_unexpected_reject_is_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N-004: other rejects get an explicit record, never a raw assert."""
    with pytest.raises(pytest.xfail.Exception):
        _run_context_login(monkeypatch, int(CKR_FUNCTION_FAILED))
    rec = _record()
    assert rec.reason == "nonspec_reject"
    assert rec.kind == "lifecycle"
    assert rec.operation == "C_Login"
    assert rec.actual_ckr == "CKR_FUNCTION_FAILED"


def test_context_login_not_initialized_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_context_login(monkeypatch, int(CKR_OPERATION_NOT_INITIALIZED))
    assert classification.get_records() == []


def test_context_login_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_context_login(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_context_login_not_supported_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_context_login(monkeypatch, int(CKR_FUNCTION_NOT_SUPPORTED))


def test_context_login_user_type_invalid_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_context_login(monkeypatch, int(CKR_USER_TYPE_INVALID))

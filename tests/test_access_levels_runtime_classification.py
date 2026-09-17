"""Runtime classification meta-tests for test_access_levels login guards (Phase 4 N2).

The login/SO-conflict guards check that a forbidden login rejects. Converted
from a flat ``assert rv in (...)`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the forbidden login succeeded) -> ``fail``,
- the spec-preferred code -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_AUTHENTICATE,
    CKA_PRIVATE,
    CKA_TRUSTED,
    CKA_WRAP_WITH_TRUSTED,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_access_levels as tal
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    classification.clear()
    yield
    classification.clear()


def _session(login_rv: int) -> SimpleNamespace:
    def _login(*_a: object, **_k: object) -> int:
        return int(login_rv)

    def _token_info(_slot_id: object, info_ref: object) -> int:
        info_ref._obj.flags = 0  # type: ignore[attr-defined]
        return int(CKR_OK)

    raw = SimpleNamespace(C_Login=_login, C_GetTokenInfo=_token_info)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(tal, "raw_open_session", lambda *_a, **_k: 3)
    monkeypatch.setattr(tal, "_logout_safe", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "close_session_quietly", lambda *_a, **_k: None)
    tal.TestSOOnROSession().test_so_login_rejected_on_ro_session(
        _session(login_rv), SimpleNamespace(pin="1234", so_pin=None)
    )


def test_so_login_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_SESSION_READ_ONLY_EXISTS))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_SESSION_READ_ONLY))
    record = classification.get_records()[-1]
    assert record.operation == "C_Login"
    assert record.mechanism is None
    assert record.expected_ckr == ["CKR_SESSION_READ_ONLY_EXISTS"]
    assert record.actual_ckr == "CKR_SESSION_READ_ONLY"


def test_quirk_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_USER_TYPE_INVALID))
    record = classification.get_records()[-1]
    assert record.operation == "C_Login"
    assert record.mechanism is None


class _GetForbiddenMapping(dict[int, object]):
    """Provider mapping whose convenience ``get`` transport must not be used."""

    def get(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("provider attribute access must use membership and indexing")


def _access_session() -> SimpleNamespace:
    return SimpleNamespace(raw=SimpleNamespace(), sh=1, slot_id=0, has_mechanism=lambda _: True)


def test_presence_helper_preserves_false_like_values() -> None:
    for value in (False, 0, b"", None):
        attrs = _GetForbiddenMapping({CKA_TRUSTED: value})
        assert attr_or_record(attrs, CKA_TRUSTED, label="trusted") is value
    assert (
        tal._require_bool_attribute(
            False,
            attr=CKA_TRUSTED,
            label="trusted",
            mechanism="CKM_AES_KEY_GEN",
        )
        is False
    )
    assert not classification.get_records()


@pytest.mark.parametrize("value", [0, b"", None])
def test_bool_consumer_rejects_present_non_boolean_values(value: object) -> None:
    assert value is not False
    with pytest.raises(Failed) as exc_info:
        tal._require_bool_attribute(
            value,
            attr=CKA_TRUSTED,
            label="trusted",
            mechanism="CKM_AES_KEY_GEN",
        )
    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    classification.clear()


def test_missing_trusted_is_structured_without_using_mapping_get() -> None:
    attrs = _GetForbiddenMapping()
    value = attr_or_record(attrs, CKA_TRUSTED, label="trusted")

    assert value is MISSING_ATTRIBUTE
    records = classification.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_TRUSTED", "id": int(CKA_TRUSTED)},
    }


def test_missing_initial_trusted_read_keeps_setter_probe_and_omission_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    setter_calls = 0
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)

    def _set(*_args: object, **_kwargs: object) -> None:
        nonlocal setter_calls
        setter_calls += 1
        raise CkrAssertionError("not logged in", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: _GetForbiddenMapping())
    monkeypatch.setattr(tal, "set_attributes", _set)
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    tal.TestTrustedAttribute().test_user_cannot_setattr_trusted(session)

    assert setter_calls == 1
    assert destroyed == [7]
    records = classification.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].label == (
        "USER:setattr-CKA_TRUSTED initial readback (producer_mechanism=CKM_AES_KEY_GEN)"
    )
    assert records[0].operation == "C_GetAttributeValue"
    # Readback attribution: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert records[0].mechanism is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_TRUSTED", "id": int(CKA_TRUSTED)},
    }


@pytest.mark.parametrize(
    "helper",
    ["setter", "operation_rejection", "operation_unavailable", "negative_rv"],
)
def test_rejection_helpers_fail_for_undefined_ckr_with_exact_context(helper: str) -> None:
    undefined_rv = 0x12345678

    with pytest.raises(Failed) as exc_info:
        if helper == "setter":
            tal._classify_setter_rejection(
                CkrAssertionError("undefined", undefined_rv),
                expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                attr=CKA_TRUSTED,
                label="undefined setter CKR",
            )
        elif helper == "operation_rejection":
            tal._classify_operation_rejection(
                CkrAssertionError("undefined", undefined_rv),
                expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                label="undefined operation CKR",
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
            )
        elif helper == "operation_unavailable":
            tal._classify_operation_unavailable(
                CkrAssertionError("undefined", undefined_rv),
                label="undefined unavailable CKR",
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        else:
            tal._classify_negative_operation_rv(
                undefined_rv,
                expected_rvs=(CKR_SESSION_READ_ONLY_EXISTS,),
                label="undefined negative CKR",
                operation="C_Login",
                mechanism=None,
                kind="policy",
            )

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x12345678"
    assert record.detail is not None
    assert record.detail["ckr_validity"] == "undefined"
    if helper == "setter":
        assert record.operation == "C_SetAttributeValue"
        assert record.mechanism is None
    elif helper == "operation_rejection":
        assert record.operation == "C_GenerateKey"
        assert record.mechanism == "CKM_AES_KEY_GEN"
    elif helper == "operation_unavailable":
        assert record.operation == "C_Sign"
        assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    else:
        assert record.operation == "C_Login"
        assert record.mechanism is None


@pytest.mark.parametrize(
    "helper", ["setter", "operation_rejection", "operation_unavailable", "negative_rv"]
)
def test_rejection_helpers_keep_vendor_defined_ckr_as_xfail(helper: str) -> None:
    vendor_rv = int(CKR_VENDOR_DEFINED)

    with pytest.raises(pytest.xfail.Exception):
        if helper == "setter":
            tal._classify_setter_rejection(
                CkrAssertionError("vendor", vendor_rv),
                expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                attr=CKA_TRUSTED,
                label="vendor setter CKR",
            )
        elif helper == "operation_rejection":
            tal._classify_operation_rejection(
                CkrAssertionError("vendor", vendor_rv),
                expected_rvs=(CKR_USER_NOT_LOGGED_IN,),
                label="vendor operation CKR",
                operation="C_GenerateKey",
                mechanism="CKM_AES_KEY_GEN",
            )
        elif helper == "operation_unavailable":
            tal._classify_operation_unavailable(
                CkrAssertionError("vendor", vendor_rv),
                label="vendor unavailable CKR",
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
            )
        else:
            tal._classify_negative_operation_rv(
                vendor_rv,
                expected_rvs=(CKR_SESSION_READ_ONLY_EXISTS,),
                label="vendor negative CKR",
                operation="C_Login",
                mechanism=None,
                kind="policy",
            )

    record = classification.get_records()[-1]
    assert record.reason in {"nonspec_reject", "not_operational"}
    assert record.outcome == "xfail"


def test_access_levels_attribute_access_is_analyzer_clean() -> None:
    """Keep the access-level slice free of provider-mapping ``.get()`` access."""
    source = (
        Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_access_levels.py"
    )
    assert analyze_file(source) == []


def test_so_trusted_missing_disables_only_dependent_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def _so_session(*_args: object, **_kwargs: object) -> Iterator[int]:
        yield 1

    monkeypatch.setattr(tal, "so_session", _so_session)
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: _GetForbiddenMapping())
    destroyed: list[int] = []
    monkeypatch.setattr(tal, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    tal.TestTrustedAttribute().test_so_can_set_trusted(_access_session(), SimpleNamespace())

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].label == (
        "SO:create-CKA_TRUSTED readback (producer_mechanism=CKM_AES_KEY_GEN)"
    )
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert destroyed == [7]


def test_present_malformed_trusted_is_a_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _so_session(*_args: object, **_kwargs: object) -> Iterator[int]:
        yield 1

    monkeypatch.setattr(tal, "so_session", _so_session)
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: _GetForbiddenMapping({CKA_TRUSTED: None}),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tal, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(Failed) as exc_info:
        tal.TestTrustedAttribute().test_so_can_set_trusted(_access_session(), SimpleNamespace())
    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert destroyed == [7]


def test_wrapper_acquisition_failure_still_cleans_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    calls = 0

    def _generate(*_args: object, **_kwargs: object) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CkrAssertionError("device", int(CKR_DEVICE_ERROR))
        return 7

    monkeypatch.setattr(tal, "_gen_access_aes_key", _generate)
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_WRAP_WITH_TRUSTED: True},
    )
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(CkrAssertionError):
        tal.TestTrustedAttribute().test_wrap_with_trusted_rejects_untrusted(session)

    assert destroyed == [7]


def test_always_auth_missing_is_reported_without_running_dependent_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: _GetForbiddenMapping())
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    tal.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(session)

    records = classification.get_records()
    assert len(records) == 1
    assert records[0].label == (
        "CKA_ALWAYS_AUTHENTICATE setup readback (producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
    )
    assert records[0].mechanism is None


def test_public_private_missing_readback_is_still_claimed_as_policy_breach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """gen_aes_key() succeeding with CKA_PRIVATE=True on an unauthenticated session
    already proves creation-time acceptance of the claim; a missing CKA_PRIVATE
    readback must not downgrade the resulting self-contradiction to a non-fail."""
    session = _access_session()
    config = SimpleNamespace(pin="1234")
    monkeypatch.setattr(tal, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "gen_aes_key", lambda *_a, **_k: 9)
    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: _GetForbiddenMapping())
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "raw_open_session", lambda *_a, **_k: 4)
    monkeypatch.setattr(tal, "close_session_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "_login_user_raw", lambda *_a, **_k: None)
    session.raw.C_Logout = lambda *_a, **_k: int(CKR_OK)

    with pytest.raises(Failed) as exc_info:
        tal.TestPublicSessionRestrictions().test_public_cannot_create_private_token_object(
            session, config
        )
    assert not isinstance(exc_info.value, XFailed)

    records = classification.get_records()
    assert records[0].label == (
        "public CKA_PRIVATE=True token object readback (producer_mechanism=CKM_AES_KEY_GEN)"
    )
    assert records[0].mechanism is None
    assert records[-1].reason == "self_contradiction"
    assert records[-1].detail is not None
    assert records[-1].detail["actual"] == "missing"


def test_user_granted_trusted_is_a_hard_policy_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "gen_aes_key", lambda *_a, **_k: 9)
    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: {CKA_TRUSTED: True})
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestTrustedAttribute().test_user_cannot_set_trusted(session)

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "policy"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.expected_ckr == [
        "CKR_ACTION_PROHIBITED",
        "CKR_ATTRIBUTE_READ_ONLY",
        "CKR_ATTRIBUTE_TYPE_INVALID",
        "CKR_ATTRIBUTE_VALUE_INVALID",
        "CKR_TEMPLATE_INCOMPLETE",
        "CKR_TEMPLATE_INCONSISTENT",
        "CKR_USER_NOT_LOGGED_IN",
    ]
    assert record.actual_ckr == "CKR_OK"


def test_user_default_trusted_is_a_hard_policy_contradiction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 9)
    monkeypatch.setattr(tal, "read_attributes", lambda *_a, **_k: {CKA_TRUSTED: True})
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestTrustedAttribute().test_user_cannot_setattr_trusted(session)

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.operation == "C_GenerateKey"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.actual_ckr == "CKR_OK"


def test_always_auth_success_without_context_login_is_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True},
    )
    monkeypatch.setattr(tal, "sign_single", lambda *_a, **_k: b"signature")
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(session)

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    assert record.expected_ckr == ["CKR_USER_NOT_LOGGED_IN"]
    assert record.actual_ckr == "CKR_OK"


def test_always_auth_context_login_empty_signature_is_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    session.raw.C_Login = lambda *_a, **_k: int(CKR_OK)
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True},
    )
    monkeypatch.setattr(tal, "sign_single", lambda *_a, **_k: b"")
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestAlwaysAuthenticate().test_always_authenticate_with_context_login(
            session, SimpleNamespace(pin="1234")
        )

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    assert record.actual_ckr is None


def test_always_auth_unexpected_pre_context_reject_is_exact_csign_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True},
    )
    monkeypatch.setattr(
        tal,
        "sign_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("provider error", int(CKR_GENERAL_ERROR))
        ),
    )
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception):
        tal.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(session)

    record = classification.get_records()[-1]
    assert record.reason == "nonspec_reject"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    assert record.expected_ckr == ["CKR_USER_NOT_LOGGED_IN"]
    assert record.actual_ckr == "CKR_GENERAL_ERROR"


def test_always_auth_context_login_user_not_logged_in_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    session.raw.C_Login = lambda *_a, **_k: int(CKR_OK)
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True},
    )
    monkeypatch.setattr(
        tal,
        "sign_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("not logged in", int(CKR_USER_NOT_LOGGED_IN))
        ),
    )
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestAlwaysAuthenticate().test_always_authenticate_with_context_login(
            session, SimpleNamespace(pin="1234")
        )

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_USER_NOT_LOGGED_IN"


def test_always_auth_pre_context_empty_signature_is_not_a_policy_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    monkeypatch.setattr(tal, "gen_rsa_keypair", lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_ALWAYS_AUTHENTICATE: True},
    )
    monkeypatch.setattr(tal, "sign_single", lambda *_a, **_k: b"")
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as exc_info:
        tal.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(session)

    assert not isinstance(exc_info.value, XFailed)
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_SHA256_RSA_PKCS"
    assert record.actual_ckr is None


@pytest.mark.parametrize(
    ("size_length", "final_length", "expected_reason", "expected_kind", "call_count"),
    [
        (0, 0, "wrong_result", "metadata", 1),
        (16, 0, "wrong_result", "crypto", 2),
        (16, 16, "self_contradiction", "policy", 2),
    ],
)
def test_wrap_output_is_classified_by_phase_and_actual_output(
    monkeypatch: pytest.MonkeyPatch,
    size_length: int,
    final_length: int,
    expected_reason: str,
    expected_kind: str,
    call_count: int,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    generated = iter((7, 8))
    calls = 0

    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: next(generated))
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: {CKA_WRAP_WITH_TRUSTED: True},
    )
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    def _wrap(*args: object) -> int:
        nonlocal calls
        calls += 1
        output_length = size_length if calls == 1 else final_length
        args[-1]._obj.value = output_length  # type: ignore[attr-defined]
        return int(CKR_OK)

    session.raw.C_WrapKey = _wrap

    with pytest.raises(Failed) as exc_info:
        tal.TestTrustedAttribute().test_wrap_with_trusted_rejects_untrusted(session)

    assert not isinstance(exc_info.value, XFailed)
    assert calls == call_count
    assert destroyed == [8, 7]
    record = classification.get_records()[-1]
    assert record.reason == expected_reason
    assert record.kind == expected_kind
    assert record.operation == "C_WrapKey"
    assert record.mechanism == "CKM_AES_KEY_WRAP"
    if expected_reason == "wrong_result":
        assert record.detail is not None
        assert record.detail["phase"] == ("size_query" if call_count == 1 else "final")
    else:
        assert record.expected_ckr == ["CKR_ACTION_PROHIBITED", "CKR_KEY_NOT_WRAPPABLE"]
        assert record.actual_ckr == "CKR_OK"


def test_post_success_read_ckr_is_retained_and_target_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("sensitive", int(CKR_ATTRIBUTE_SENSITIVE))
        ),
    )
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        tal.TestTrustedAttribute().test_wrap_with_trusted_rejects_untrusted(session)

    assert destroyed == [7]
    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert record.detail == {
        "attribute": {"name": "CKA_WRAP_WITH_TRUSTED", "id": int(CKA_WRAP_WITH_TRUSTED)},
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_post_success_invalid_handle_is_a_lifecycle_failure_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("stale", int(CKR_OBJECT_HANDLE_INVALID))
        ),
    )
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(Failed) as exc_info:
        tal.TestTrustedAttribute().test_wrap_with_trusted_rejects_untrusted(session)

    assert not isinstance(exc_info.value, XFailed)
    assert destroyed == [7]
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert record.detail == {
        "attribute": {
            "name": "CKA_WRAP_WITH_TRUSTED",
            "id": int(CKA_WRAP_WITH_TRUSTED),
        },
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_unavailable_initial_trusted_read_does_not_skip_setter_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    destroyed: list[int] = []
    setter_calls = 0
    monkeypatch.setattr(tal, "_gen_access_aes_key", lambda *_a, **_k: 7)

    def _read(*_args: object, **_kwargs: object) -> object:
        raise CkrAssertionError("sensitive", int(CKR_ATTRIBUTE_SENSITIVE))

    def _set(*_args: object, **_kwargs: object) -> None:
        nonlocal setter_calls
        setter_calls += 1
        raise CkrAssertionError("not logged in", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(tal, "read_attributes", _read)
    monkeypatch.setattr(tal, "set_attributes", _set)
    monkeypatch.setattr(
        tal,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    tal.TestTrustedAttribute().test_user_cannot_setattr_trusted(session)

    assert setter_calls == 1
    assert destroyed == [7]
    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"


def test_private_read_ckr_is_not_converted_to_a_policy_breach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _access_session()
    config = SimpleNamespace(pin="1234")
    monkeypatch.setattr(tal, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "gen_aes_key", lambda *_a, **_k: 9)
    monkeypatch.setattr(
        tal,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("sensitive", int(CKR_ATTRIBUTE_SENSITIVE))
        ),
    )
    monkeypatch.setattr(tal, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "raw_open_session", lambda *_a, **_k: 4)
    monkeypatch.setattr(tal, "close_session_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "_login_user_raw", lambda *_a, **_k: None)
    session.raw.C_Logout = lambda *_a, **_k: int(CKR_OK)

    with pytest.raises(pytest.xfail.Exception):
        tal.TestPublicSessionRestrictions().test_public_cannot_create_private_token_object(
            session, config
        )

    record = classification.get_records()[-1]
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert record.detail is not None
    assert record.detail["attribute"] == {
        "name": "CKA_PRIVATE",
        "id": int(CKA_PRIVATE),
    }

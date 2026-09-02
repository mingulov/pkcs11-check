"""Meta-tests for provider-general CKR_USER_TYPE_INVALID routing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
)


def _rs() -> Any:
    return SimpleNamespace(raw=object(), sh=1)


def test_private_policy_uses_per_class_create_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases import test_private_key_import_policy as policy

    calls: list[tuple[Any, str]] = []
    monkeypatch.setattr(
        policy,
        "skip_unless_can_create",
        lambda rs, obj_class: calls.append((rs, obj_class)),
    )
    monkeypatch.setattr(policy, "import_ec_private_key", lambda *args, **kwargs: 17)
    monkeypatch.setattr(policy, "destroy_quietly", lambda *args, **kwargs: None)

    rs = _rs()
    policy.test_ec_private_key_import_accepts_standard_policy_attrs(rs)

    assert calls == [(rs, "private")]


def test_private_policy_refusal_stays_visible_and_unexpected_ckr_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases import test_private_key_import_policy as policy

    monkeypatch.setattr(policy, "skip_unless_can_create", lambda *args: None)
    rs = _rs()

    monkeypatch.setattr(
        policy,
        "import_ec_private_key",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            CkrAssertionError("policy shape refused", int(CKR_ATTRIBUTE_READ_ONLY))
        ),
    )
    with pytest.raises(pytest.xfail.Exception, match="spec-legal EC private-key import"):
        policy.test_ec_private_key_import_accepts_standard_policy_attrs(rs)

    monkeypatch.setattr(
        policy,
        "import_ec_private_key",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            CkrAssertionError("unexpected provider error", int(CKR_GENERAL_ERROR))
        ),
    )
    with pytest.raises(CkrAssertionError, match="unexpected provider error"):
        policy.test_ec_private_key_import_accepts_standard_policy_attrs(rs)


def test_context_login_user_type_invalid_is_visible_nonspec_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check import classification
    from pkcs11_check.testcases import test_always_authenticate as always_auth

    monkeypatch.setattr(always_auth, "_pin_bytes", lambda cfg: b"pin")
    monkeypatch.setattr(
        always_auth,
        "_context_specific_login",
        lambda raw, sh, pin: int(CKR_USER_TYPE_INVALID),
    )
    classification.clear()
    with pytest.raises(pytest.xfail.Exception, match="CKR_USER_TYPE_INVALID"):
        always_auth.TestAlwaysAuthenticateEnforcement().test_context_specific_login_without_active_op_rejected(
            _rs(), SimpleNamespace()
        )
    records = classification.serialize(classification.get_records())
    assert records[-1]["reason"] == "not_operational"


def test_context_login_ok_remains_a_security_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases import test_always_authenticate as always_auth

    monkeypatch.setattr(always_auth, "_pin_bytes", lambda cfg: b"pin")
    monkeypatch.setattr(always_auth, "_context_specific_login", lambda raw, sh, pin: int(CKR_OK))
    with pytest.raises(pytest.fail.Exception, match="accepted CKU_CONTEXT_SPECIFIC"):
        always_auth.TestAlwaysAuthenticateEnforcement().test_context_specific_login_without_active_op_rejected(
            _rs(), SimpleNamespace()
        )


@pytest.mark.parametrize("rv", [CKR_OPERATION_NOT_INITIALIZED, CKR_USER_NOT_LOGGED_IN])
def test_context_login_preferred_rejections_pass(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    from pkcs11_check.testcases import test_always_authenticate as always_auth

    monkeypatch.setattr(always_auth, "_pin_bytes", lambda cfg: b"pin")
    monkeypatch.setattr(always_auth, "_context_specific_login", lambda raw, sh, pin: int(rv))
    always_auth.TestAlwaysAuthenticateEnforcement().test_context_specific_login_without_active_op_rejected(
        _rs(), SimpleNamespace()
    )

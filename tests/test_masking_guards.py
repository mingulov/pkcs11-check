"""Regression tests for provider-error routing in small export/access helpers."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_TYPE_INVALID
from pkcs11_check.testcases import _ec_export, _rsa_export, test_access_levels
from pkcs11_check.testcases.security import test_ecdsa_low_s


def test_ec_export_does_not_route_generic_assertion_to_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(AssertionError, match="binding bug"):
        _ec_export.read_ec_public_key_or_xfail(rs, 1, _ec_export.ec.SECP256R1())


def test_rsa_export_does_not_route_generic_assertion_to_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _rsa_export,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(AssertionError, match="binding bug"):
        _rsa_export.read_rsa_public_key_or_xfail(rs, 1)


def test_access_aes_setup_does_not_route_generic_assertion_to_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_access_levels, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(
        test_access_levels,
        "gen_aes_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(AssertionError, match="binding bug"):
        test_access_levels._gen_access_aes_key(rs, 1)


def test_ecdsa_low_s_does_not_route_generic_sign_assertion_to_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_ecdsa_low_s, "gen_ec_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(
        test_ecdsa_low_s,
        "sign_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    monkeypatch.setattr(test_ecdsa_low_s, "destroy_quietly", lambda *_args: None)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(AssertionError, match="binding bug"):
        test_ecdsa_low_s.TestEcdsaLowSPosture().test_low_s_and_malleability(rs)


def test_access_session_open_does_not_route_generic_assertion_to_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_access_levels,
        "raw_open_session",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    rs = SimpleNamespace(raw=object(), slot_id=1)

    with pytest.raises(AssertionError, match="binding bug"):
        test_access_levels._open_access_session_or_skip(rs, 0)


def test_so_trusted_setup_ok_but_readback_false_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def _so_session(*_args: object, **_kwargs: object):
        yield 1

    monkeypatch.setattr(test_access_levels, "so_session", _so_session)
    monkeypatch.setattr(test_access_levels, "_gen_access_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_access_levels,
        "read_attributes",
        lambda *_a, **_k: {test_access_levels.CKA_TRUSTED: False},
    )
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_a, **_k: None)
    rs = SimpleNamespace(raw=object())

    with pytest.raises(Failed, match="CKA_TRUSTED=True"):
        test_access_levels.TestTrustedAttribute().test_so_can_set_trusted(rs, object())


def test_wrap_with_trusted_setup_ok_but_readback_false_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_access_levels, "_gen_access_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_access_levels,
        "read_attributes",
        lambda *_a, **_k: {test_access_levels.CKA_WRAP_WITH_TRUSTED: False},
    )
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_a, **_k: None)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(Failed, match="CKA_WRAP_WITH_TRUSTED=True"):
        test_access_levels.TestTrustedAttribute().test_wrap_with_trusted_cannot_be_cleared_once_true(
            rs
        )


def test_always_auth_setup_ok_but_readback_false_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_access_levels, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(
        test_access_levels,
        "read_attributes",
        lambda *_a, **_k: {test_access_levels.CKA_ALWAYS_AUTHENTICATE: False},
    )
    monkeypatch.setattr(test_access_levels, "destroy_quietly", lambda *_a, **_k: None)
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS"},
    )

    with pytest.raises(Failed, match="CKA_ALWAYS_AUTHENTICATE=True"):
        test_access_levels.TestAlwaysAuthenticate().test_always_authenticate_key_requires_reauth(rs)


def test_user_trusted_creation_classifies_expected_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_access_levels, "require_operational_aes_keygen", lambda _rs: None)
    monkeypatch.setattr(
        test_access_levels,
        "gen_aes_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID", int(CKR_ATTRIBUTE_TYPE_INVALID)
            )
        ),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    test_access_levels.TestTrustedAttribute().test_user_cannot_set_trusted(rs)

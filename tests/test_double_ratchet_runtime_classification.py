"""Regression tests for X2RATCHET setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKR_CURVE_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_double_ratchet


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _curve_oid_from_pub_base(pub_base: list[Any]) -> bytes:
    return bytes(pub_base[0].storage)


def test_x2ratchet_setup_uses_montgomery_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def _gen_keypair(
        _raw: object,
        _sh: int,
        mechanism: int,
        pub_base: list[Any],
        priv_base: list[Any],
        *,
        public_attrs: dict[int, Any] | None,
        private_attrs: dict[int, Any] | None,
        pub_skip: set[int] | None,
    ) -> tuple[int, int]:
        assert public_attrs is not None
        assert private_attrs is not None
        assert pub_skip is not None
        assert pub_base
        assert priv_base == []
        calls.append(int(mechanism))
        return (11, 12)

    def _classic_ec_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("classic EC keygen should not be used for X2RATCHET")

    monkeypatch.setattr(test_double_ratchet, "gen_keypair", _gen_keypair, raising=False)
    monkeypatch.setattr(test_double_ratchet, "gen_ec_keypair", _classic_ec_keypair, raising=False)

    result = test_double_ratchet._create_ec_keypair(
        _session_with_mechanisms("EC_MONTGOMERY_KEY_PAIR_GEN")
    )

    assert result == (11, 12)
    assert calls == [int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN)]


def test_x2ratchet_setup_does_not_swallow_python_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _bug_then_success(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("local setup bug")
        return (11, 12)

    monkeypatch.setattr(test_double_ratchet, "gen_keypair", _bug_then_success, raising=False)
    monkeypatch.setattr(test_double_ratchet, "gen_ec_keypair", _bug_then_success, raising=False)

    with pytest.raises(ValueError, match="local setup bug"):
        test_double_ratchet._create_ec_keypair(
            _session_with_mechanisms("EC_MONTGOMERY_KEY_PAIR_GEN")
        )


def test_x2ratchet_setup_falls_back_from_x25519_to_x448(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_curves: list[bytes] = []
    x25519_oid = encode_named_curve_parameters("x25519")
    x448_oid = encode_named_curve_parameters("x448")

    def _gen_keypair(
        _raw: object,
        _sh: int,
        mechanism: int,
        pub_base: list[Any],
        priv_base: list[Any],
        *,
        public_attrs: dict[int, Any] | None,
        private_attrs: dict[int, Any] | None,
        pub_skip: set[int] | None,
    ) -> tuple[int, int]:
        assert public_attrs is not None
        assert private_attrs is not None
        assert pub_skip is not None
        assert int(mechanism) == int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN)
        assert priv_base == []
        curve_oid = _curve_oid_from_pub_base(pub_base)
        seen_curves.append(curve_oid)
        if curve_oid == x25519_oid:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED",
                int(CKR_CURVE_NOT_SUPPORTED),
            )
        return (21, 22)

    def _classic_ec_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("classic EC keygen should not be used for X2RATCHET")

    monkeypatch.setattr(test_double_ratchet, "gen_keypair", _gen_keypair, raising=False)
    monkeypatch.setattr(test_double_ratchet, "gen_ec_keypair", _classic_ec_keypair, raising=False)

    result = test_double_ratchet._create_ec_keypair(
        _session_with_mechanisms("EC_MONTGOMERY_KEY_PAIR_GEN")
    )

    assert result == (21, 22)
    assert seen_curves == [x25519_oid, x448_oid]

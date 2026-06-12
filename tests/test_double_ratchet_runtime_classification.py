"""Regression tests for X2RATCHET setup classification."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_X2RATCHET_INITIALIZE_PARAMS,
    CK_X2RATCHET_RESPOND_PARAMS,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKK_X2RATCHET,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_X2RATCHET_INITIALIZE,
    CKM_X2RATCHET_RESPOND,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_MECHANISM_PARAM_INVALID,
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


def test_x2ratchet_initialize_mechanism_packs_spec_params() -> None:
    mech = test_double_ratchet._mech_x2ratchet_initialize(
        shared_secret=b"shared-secret-for-x2ratchet",
        peer_public_prekey=11,
        peer_public_identity=12,
        own_public_identity=21,
    )

    assert int(mech.ck.mechanism) == int(CKM_X2RATCHET_INITIALIZE)
    assert mech.ck.ulParameterLen == ctypes.sizeof(CK_X2RATCHET_INITIALIZE_PARAMS)
    assert isinstance(mech.params, CK_X2RATCHET_INITIALIZE_PARAMS)
    assert mech.params.sk is not None
    assert mech.params.peer_public_prekey == 11
    assert mech.params.peer_public_identity == 12
    assert mech.params.own_public_identity == 21
    assert mech.params.eCurve == 255


def test_x2ratchet_initialize_runtime_calls_derive_with_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(
        (
            (101, 201),
            (102, 202),
            (103, 203),
        )
    )
    derive_calls: list[dict[str, Any]] = []
    destroyed: list[int] = []

    def _create_keypair(_rs: Any) -> tuple[int, int]:
        return next(handles)

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return 999

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", _create_keypair)
    monkeypatch.setattr(test_double_ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(
        test_double_ratchet,
        "destroy_quietly",
        lambda _raw, _sh, h: destroyed.append(h),
    )

    test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_derive_generic_secret(
        _session_with_mechanisms("X2RATCHET_INITIALIZE")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 201
    assert derive_calls[0]["mechanism"] == int(CKM_X2RATCHET_INITIALIZE)
    assert isinstance(derive_calls[0]["mech_param"].params, CK_X2RATCHET_INITIALIZE_PARAMS)
    assert 999 in destroyed


def test_x2ratchet_initialize_sensitivity_probe_uses_spec_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(
        (
            (101, 201),
            (102, 202),
            (103, 203),
            (104, 204),
        )
    )
    derived_keys = iter((301, 302))
    derive_calls: list[dict[str, Any]] = []

    def _create_keypair(_rs: Any) -> tuple[int, int]:
        return next(handles)

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return next(derived_keys)

    def _read_attributes(
        _raw: object, _sh: int, handle: int, _attrs: list[int]
    ) -> dict[int, bytes]:
        return {CKA_VALUE: f"x2ratchet-{handle}".encode("ascii")}

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", _create_keypair)
    monkeypatch.setattr(test_double_ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(test_double_ratchet, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_double_ratchet, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(
        _session_with_mechanisms("X2RATCHET_INITIALIZE")
    )

    assert [call["base_key"] for call in derive_calls] == [201, 202]
    assert [call["mechanism"] for call in derive_calls] == [
        int(CKM_X2RATCHET_INITIALIZE),
        int(CKM_X2RATCHET_INITIALIZE),
    ]
    assert all(
        isinstance(call["mech_param"].params, CK_X2RATCHET_INITIALIZE_PARAMS)
        for call in derive_calls
    )


def test_x2ratchet_respond_x2ratchet_key_type_uses_spec_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[dict[str, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return 999

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", lambda _rs: (101, 201))
    monkeypatch.setattr(test_double_ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(test_double_ratchet, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_respond_derives_x2ratchet_key_type(
        _session_with_mechanisms("X2RATCHET_RESPOND")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 201
    assert derive_calls[0]["mechanism"] == int(CKM_X2RATCHET_RESPOND)
    assert derive_calls[0]["attrs"][CKA_KEY_TYPE] == CKK_X2RATCHET
    assert isinstance(derive_calls[0]["mech_param"].params, CK_X2RATCHET_RESPOND_PARAMS)


def test_x2ratchet_initialize_invalid_curve_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(((101, 201), (102, 202), (103, 203)))
    derive_calls: list[dict[str, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", lambda _rs: next(handles))
    monkeypatch.setattr(test_double_ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(test_double_ratchet, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_rejects_invalid_curve(
        _session_with_mechanisms("X2RATCHET_INITIALIZE")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 201
    assert derive_calls[0]["mechanism"] == int(CKM_X2RATCHET_INITIALIZE)
    assert derive_calls[0]["mech_param"].params.eCurve == 256


def test_x2ratchet_respond_invalid_curve_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(((101, 201), (102, 202), (103, 203)))
    derive_calls: list[dict[str, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", lambda _rs: next(handles))
    monkeypatch.setattr(test_double_ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(test_double_ratchet, "destroy_quietly", lambda *_args, **_kwargs: None)

    test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_respond_rejects_invalid_curve(
        _session_with_mechanisms("X2RATCHET_RESPOND")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 201
    assert derive_calls[0]["mechanism"] == int(CKM_X2RATCHET_RESPOND)
    assert derive_calls[0]["mech_param"].params.eCurve == 256


def test_x2ratchet_initialize_invalid_curve_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(((101, 201), (102, 202), (103, 203)))

    monkeypatch.setattr(test_double_ratchet, "_create_ec_keypair", lambda _rs: next(handles))
    monkeypatch.setattr(test_double_ratchet, "derive_key", lambda *_args, **_kwargs: 999)
    monkeypatch.setattr(test_double_ratchet, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(Failed, match="X2RATCHET_INITIALIZE invalid curve"):
        test_double_ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_rejects_invalid_curve(
            _session_with_mechanisms("X2RATCHET_INITIALIZE")
        )

"""Regression tests for X3DH runtime coverage."""

from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CK_X3DH_INITIATE_PARAMS, CKM_X3DH_INITIALIZE
from pkcs11_check.testcases import test_x3dh


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_x3dh_file_contains_runtime_derive_coverage() -> None:
    source = Path(test_x3dh.__file__).read_text(encoding="utf-8")

    assert "CK_X3DH_INITIATE_PARAMS" in source
    assert "CK_X3DH_RESPOND_PARAMS" in source
    assert "derive_key(" in source
    assert "test_x3dh_initialize_derive_generic_secret" in source
    assert "test_x3dh_respond_derive_generic_secret" in source


def test_x3dh_initialize_mechanism_packs_spec_params() -> None:
    mech = test_x3dh._mech_x3dh_initialize(
        peer_identity=11,
        peer_prekey=12,
        prekey_signature=b"sig",
        onetime_key=b"",
        own_identity=21,
        own_ephemeral=22,
    )

    assert int(mech.ck.mechanism) == int(CKM_X3DH_INITIALIZE)
    assert mech.ck.ulParameterLen == ctypes.sizeof(CK_X3DH_INITIATE_PARAMS)
    assert isinstance(mech.params, CK_X3DH_INITIATE_PARAMS)
    assert mech.params.pPeer_identity == 11
    assert mech.params.pPeer_prekey == 12
    assert mech.params.pPrekey_signature is not None
    assert mech.params.pOnetime_key is not None
    assert mech.params.pOwn_identity == 21
    assert mech.params.pOwn_ephemeral == 22


def test_x3dh_initialize_runtime_calls_derive_with_params(
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

    monkeypatch.setattr(test_x3dh, "_create_ec_keypair", _create_keypair)
    monkeypatch.setattr(test_x3dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x3dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    test_x3dh.TestX3DH().test_x3dh_initialize_derive_generic_secret(
        _session_with_mechanisms("X3DH_INITIALIZE")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 201
    assert derive_calls[0]["mechanism"] == int(CKM_X3DH_INITIALIZE)
    assert isinstance(derive_calls[0]["mech_param"].params, CK_X3DH_INITIATE_PARAMS)
    assert 999 in destroyed

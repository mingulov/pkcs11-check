"""Regression tests for advertised CT-KIP runtime coverage."""

from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CK_KIP_PARAMS, CKM_KIP_DERIVE, CKM_SHA256
from pkcs11_check.testcases import test_otp


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_ct_kip_file_does_not_skip_advertised_runtime_work() -> None:
    source = Path(test_otp.__file__).read_text(encoding="utf-8")

    assert "requires CT-KIP parameter setup" not in source
    assert "requires specialized key types" not in source
    assert "test_kip_derive_derives_generic_secret" in source
    assert "test_kip_wrap_wraps_generic_secret" in source
    assert "test_kip_mac_signs_and_verifies" in source
    assert "CK_KIP_PARAMS" in source


def test_kip_mechanism_packs_spec_params() -> None:
    mech = test_otp._mech_kip(
        CKM_KIP_DERIVE,
        underlying_mechanism=CKM_SHA256,
        h_key=17,
        seed=b"seed",
    )

    assert int(mech.ck.mechanism) == int(CKM_KIP_DERIVE)
    assert mech.ck.ulParameterLen == ctypes.sizeof(CK_KIP_PARAMS)
    assert isinstance(mech.params, CK_KIP_PARAMS)
    assert mech.params.pMechanism is not None
    assert mech.params.hKey == 17
    assert mech.params.pSeed is not None
    assert mech.params.ulSeedLen == 4


def test_kip_derive_runtime_calls_derive_with_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = iter((101, 102))
    derive_calls: list[dict[str, Any]] = []
    destroyed: list[int] = []

    def _create_secret(_rs: Any, **_kwargs: Any) -> int:
        return next(created)

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

    monkeypatch.setattr(test_otp, "_create_kip_secret_key", _create_secret)
    monkeypatch.setattr(test_otp, "derive_key", _derive_key)
    monkeypatch.setattr(test_otp, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    test_otp.TestCTKIP().test_kip_derive_derives_generic_secret(
        _session_with_mechanisms("KIP_DERIVE")
    )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_KIP_DERIVE)
    assert isinstance(derive_calls[0]["mech_param"].params, CK_KIP_PARAMS)
    assert 999 in destroyed

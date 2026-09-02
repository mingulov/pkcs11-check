"""Regression tests for CMS_SIG runtime parameter coverage."""

from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_CMS_SIG_PARAMS,
    CKM_CMS_SIG,
    CKM_SHA256_RSA_PKCS,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases import test_cms


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=0,
        has_mechanism=lambda name: name in names,
    )


def test_cms_file_contains_param_runtime_coverage() -> None:
    source = Path(test_cms.__file__).read_text(encoding="utf-8")

    assert "CK_CMS_SIG_PARAMS" in source
    assert "_mech_cms_sig" in source
    assert "test_cms_sig_signs_with_params" in source
    assert "sign_single(" in source


def test_cms_mechanism_packs_spec_params() -> None:
    mech = test_cms._mech_cms_sig(
        signing_mechanism=CKM_SHA256_RSA_PKCS,
        digest_mechanism=None,
        content_type="application/octet-stream",
        requested_attributes=None,
        required_attributes=b"",
    )

    assert int(mech.ck.mechanism) == int(CKM_CMS_SIG)
    assert mech.ck.ulParameterLen == ctypes.sizeof(CK_CMS_SIG_PARAMS)
    assert isinstance(mech.params, CK_CMS_SIG_PARAMS)
    assert mech.params.certificateHandle == 0
    assert mech.params.pSigningMechanism is not None
    assert mech.params.pDigestMechanism is None
    assert mech.params.pContentType is not None
    assert mech.params.pRequestedAttributes is None
    assert mech.params.pRequiredAttributes is not None
    assert mech.params.ulRequiredAttributesLen == 0


def test_cms_runtime_calls_sign_with_params(monkeypatch: pytest.MonkeyPatch) -> None:
    sign_calls: list[dict[str, Any]] = []
    destroyed: list[int] = []

    monkeypatch.setattr(test_cms, "gen_rsa_keypair", lambda *_args, **_kwargs: (101, 201))
    monkeypatch.setattr(test_cms, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    def _sign_single(
        _raw: object,
        _sh: int,
        key: int,
        mechanism: int,
        data: bytes,
        *,
        mech_param: Any,
        output_size_hint: int = 0,
    ) -> bytes:
        sign_calls.append(
            {
                "key": key,
                "mechanism": int(mechanism),
                "data": data,
                "mech_param": mech_param,
                "output_size_hint": output_size_hint,
            }
        )
        return b"\x30\x03\x02\x01\x01"

    monkeypatch.setattr(test_cms, "sign_single", _sign_single)

    test_cms.TestCMSSig().test_cms_sig_signs_with_params(_session_with_mechanisms("CMS_SIG"))

    assert len(sign_calls) == 1
    assert sign_calls[0]["key"] == 201
    assert sign_calls[0]["mechanism"] == int(CKM_CMS_SIG)
    assert isinstance(sign_calls[0]["mech_param"].params, CK_CMS_SIG_PARAMS)
    assert destroyed == [201, 101]


def test_advertised_cms_mechanism_info_refusal_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_cms,
        "get_mechanism_info",
        lambda *_a: (_ for _ in ()).throw(
            CkrAssertionError("CKR_GENERAL_ERROR", CKR_GENERAL_ERROR)
        ),
    )
    with pytest.raises(pytest.xfail.Exception):
        test_cms.TestCMSSig().test_mechanism_info(_session_with_mechanisms("CMS_SIG"))


def test_advertised_cms_mechanism_info_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_cms,
        "get_mechanism_info",
        lambda *_a: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        test_cms.TestCMSSig().test_mechanism_info(_session_with_mechanisms("CMS_SIG"))

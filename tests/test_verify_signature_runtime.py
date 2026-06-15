"""Regression tests for the PKCS#11 v3 VerifySignature API tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OK
from pkcs11_check.testcases import test_verify_signature


class _VerifySignatureRaw:
    def __init__(self) -> None:
        self.updated_lengths: list[int] = []

    def available_function_names(self) -> set[str]:
        return {"C_VerifySignatureInit", "C_VerifySignatureUpdate", "C_VerifySignatureFinal"}

    def C_VerifySignatureInit(  # noqa: N802
        self,
        _session: int,
        _mechanism: object,
        _key: int,
        _signature: object,
        _signature_len: int,
    ) -> int:
        return int(CKR_OK)

    def C_VerifySignatureUpdate(  # noqa: N802
        self,
        _session: int,
        _data: object,
        data_len: int,
    ) -> int:
        self.updated_lengths.append(data_len)
        return int(CKR_OK)

    def C_VerifySignatureFinal(self, _session: int) -> int:  # noqa: N802
        return int(CKR_OK)


class _WrongSignatureRaw(_VerifySignatureRaw):
    def C_VerifySignature(self, _session: int, _data: object, _data_len: int) -> int:  # noqa: N802
        return int(CKR_DEVICE_ERROR)


def test_verify_signature_multipart_uses_single_shot_signature_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _VerifySignatureRaw()
    rs = SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "RSA_PKCS",
        has_mechanism_flag=lambda _m, _f: True,
    )
    monkeypatch.setattr(test_verify_signature, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_verify_signature, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_verify_signature, "sign_single", lambda *_args: b"\x01" * 256)
    monkeypatch.setattr(
        test_verify_signature,
        "sign_multipart",
        lambda *_args: pytest.fail("signature setup should use single-shot signing"),
        raising=False,
    )

    test_verify_signature.TestVerifySignatureRoundtrip().test_verify_signature_multipart(rs)

    assert raw.updated_lengths == [10, 10, 11]


def test_verify_signature_wrong_sig_device_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _WrongSignatureRaw()
    rs = SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "RSA_PKCS",
        has_mechanism_flag=lambda _m, _f: True,
    )
    monkeypatch.setattr(test_verify_signature, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_verify_signature, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_verify_signature.TestVerifySignatureRoundtrip().test_verify_signature_wrong_sig(rs)

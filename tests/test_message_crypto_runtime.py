"""Regression tests for message-based crypto result classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OK
from pkcs11_check.testcases import test_message_crypto


class _MessageVerifyRaw:
    def C_VerifyMessage(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_DEVICE_ERROR)

    def C_VerifyMessageBegin(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_VerifyMessageNext(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageVerifyInit(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageVerifyFinal(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)


def test_message_verify_bad_signature_device_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=_MessageVerifyRaw(),
        sh=1,
        has_mechanism=lambda name: name == "SHA256_RSA_PKCS",
    )
    monkeypatch.setattr(test_message_crypto, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_message_crypto, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_message_crypto.TestMessageSignVerify().test_message_verify_bad_signature(rs)

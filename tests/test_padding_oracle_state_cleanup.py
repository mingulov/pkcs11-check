"""Regression tests for padding-oracle probe state cleanup."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.testcases.security import test_padding_oracle


class _DecryptStateRaw:
    def __init__(self) -> None:
        self.active = False
        self.abort_count = 0

    def C_DecryptFinal(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        self.active = False
        self.abort_count += 1
        return 0


def test_rsa_padding_oracle_aborts_after_expected_decrypt_reject(
    monkeypatch: Any,
) -> None:
    raw = _DecryptStateRaw()

    def _decrypt_single(
        _raw: Any,
        _sh: int,
        _key: int,
        _mech: int,
        _ciphertext: bytes,
        **_kwargs: Any,
    ) -> bytes:
        if raw.active:
            raise AssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE")
        raw.active = True
        raise AssertionError("Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID")

    monkeypatch.setattr(
        test_padding_oracle,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kw: (1, 2),
    )
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_args: b"\x11" * 256)
    monkeypatch.setattr(test_padding_oracle, "decrypt_single", _decrypt_single)
    monkeypatch.setattr(test_padding_oracle, "destroy_quietly", lambda *_args: None)

    test_padding_oracle.TestRSAPaddingOracle().test_pkcs1v15_error_uniformity(
        SimpleNamespace(raw=raw, sh=1)
    )

    assert raw.abort_count == 10

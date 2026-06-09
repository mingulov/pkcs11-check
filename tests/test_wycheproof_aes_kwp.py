from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_AES_KEY_WRAP_KWP
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes


class _KwpSession:
    raw = object()
    sh = 1

    def __init__(self) -> None:
        self.mechanism_checks: list[str] = []

    def has_mechanism(self, name: str) -> bool:
        self.mechanism_checks.append(name)
        return name == "AES_KEY_WRAP_KWP"


def test_wycheproof_aes_kwp_vectors_use_rfc5649_encrypt_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wycheproof KWP vectors are raw RFC 5649 data, not deprecated PAD wrapping."""
    session = _KwpSession()
    calls: dict[str, Any] = {}
    expected_ct = bytes.fromhex("aabbccdd")

    def import_secret_key(*_args: Any, **_kwargs: Any) -> int:
        calls["imported"] = calls.get("imported", 0) + 1
        return 10

    def encrypt_single(
        _raw: object,
        _sh: int,
        _key: int,
        mechanism: int,
        data: bytes,
        **_kwargs: Any,
    ) -> bytes:
        calls["mechanism"] = int(mechanism)
        calls["data"] = data
        return expected_ct

    monkeypatch.setattr(aes, "import_secret_key_negotiated", import_secret_key)
    monkeypatch.setattr(aes, "encrypt_single", encrypt_single, raising=False)
    # The KWP path uses C_Encrypt (RFC 5649), never C_WrapKey: the module no
    # longer imports wrap_key at all (the AES-KW family unwraps instead), so the
    # absence of a wrap_key symbol is itself the guarantee here.
    assert not hasattr(aes, "wrap_key")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_args, **_kwargs: None)

    try:
        aes.test_aes_kwp(
            session,
            "tc-rfc5649-valid",
            {
                "key": "00" * 16,
                "msg": "112233",
                "ct": expected_ct.hex(),
                "result": "valid",
            },
        )
    except pytest.skip.Exception as exc:
        pytest.fail(f"KWP vectors should require AES_KEY_WRAP_KWP, not skip: {exc}")

    assert session.mechanism_checks == ["AES_KEY_WRAP_KWP"]
    assert calls == {
        "imported": 1,
        "mechanism": int(CKM_AES_KEY_WRAP_KWP),
        "data": bytes.fromhex("112233"),
    }

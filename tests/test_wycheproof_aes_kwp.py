from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_KEY_WRAP_KWP,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes


class _KwpSession:
    raw = object()
    sh = 1

    def __init__(self) -> None:
        self.mechanism_checks: list[str] = []

    def has_mechanism(self, name: str) -> bool:
        self.mechanism_checks.append(name)
        return name == "AES_KEY_WRAP_KWP"

    def has_mechanism_flag(self, _mechanism: int, _flag: int) -> bool:
        return True


def test_wycheproof_aes_kwp_vectors_use_rfc5649_decrypt_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wycheproof KWP vectors decrypt supplied RFC 5649 ciphertext."""
    session = _KwpSession()
    calls: dict[str, Any] = {}
    supplied_ct = bytes.fromhex("aabbccdd")
    expected_msg = bytes.fromhex("112233")

    def import_secret_key(*_args: Any, **_kwargs: Any) -> int:
        calls["imported"] = calls.get("imported", 0) + 1
        return 10

    def decrypt_single(
        _raw: object,
        _sh: int,
        _key: int,
        mechanism: int,
        data: bytes,
        **_kwargs: Any,
    ) -> bytes:
        calls["mechanism"] = int(mechanism)
        calls["data"] = data
        return expected_msg

    monkeypatch.setattr(aes, "import_secret_key_negotiated", import_secret_key)
    monkeypatch.setattr(aes, "decrypt_single", decrypt_single)
    # The KWP path uses C_Decrypt over the supplied ciphertext, never a
    # produce-direction wrap operation.
    assert not hasattr(aes, "wrap_key")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_args, **_kwargs: None)

    try:
        aes.test_aes_kwp(
            session,
            "tc-rfc5649-valid",
            {
                "key": "00" * 16,
                "msg": expected_msg.hex(),
                "ct": supplied_ct.hex(),
                "result": "valid",
            },
        )
    except pytest.skip.Exception as exc:
        pytest.fail(f"KWP vectors should require AES_KEY_WRAP_KWP, not skip: {exc}")

    assert session.mechanism_checks == ["AES_KEY_WRAP_KWP"]
    assert calls == {
        "imported": 1,
        "mechanism": int(CKM_AES_KEY_WRAP_KWP),
        "data": supplied_ct,
    }


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_VENDOR_DEFINED + 1],
    ids=["device-error", "vendor-defined"],
)
def test_wycheproof_aes_kwp_invalid_reject_is_classified(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "invalid"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("reject", int(rv))),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        aes.test_aes_kwp(session, "tc-invalid", vec)
    assert classification.get_records()[-1].reason == "nonspec_reject"


@pytest.mark.parametrize("rv", [CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE])
def test_wycheproof_aes_kwp_invalid_expected_reject_passes(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "invalid"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("reject", int(rv))),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    aes.test_aes_kwp(session, "tc-invalid", vec)


def test_wycheproof_aes_kwp_invalid_acceptance_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "invalid"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: b"wrong")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        aes.test_aes_kwp(session, "tc-invalid", vec)


def test_wycheproof_aes_kwp_invalid_undefined_reject_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "invalid"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("undefined", 0x7FFFFFFF)),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        aes.test_aes_kwp(session, "tc-invalid", vec)
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_wycheproof_aes_kwp_invalid_non_ckr_reject_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "invalid"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(AssertionError, match="binding bug"):
        aes.test_aes_kwp(session, "tc-invalid", vec)


def test_wycheproof_aes_kwp_acceptable_output_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "acceptable"}

    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_a, **_k: 10)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: b"wrong")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        aes.test_aes_kwp(session, "tc-acceptable", vec)


def test_wycheproof_aes_kwp_acceptable_setup_refusal_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _KwpSession()
    vec = {"key": "00" * 16, "msg": "112233", "ct": "aabbccdd", "result": "acceptable"}

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("setup refused", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(aes, "import_secret_key_negotiated", _reject)

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        aes.test_aes_kwp(session, "tc-acceptable", vec)

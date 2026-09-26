"""Regression tests for message-based crypto result classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKF_MULTI_MESSAGE,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_message_crypto
from tests._skip_assert import assert_skips, assert_xfails


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


class _MessageSignInitRaw:
    def __init__(self, rv: int) -> None:
        self._rv = rv

    def C_MessageSignInit(self, *_args: object) -> int:  # noqa: N802
        return self._rv


class _MessageEncryptRaw:
    def C_MessageEncryptInit(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessage(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessageBegin(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessageNext(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageEncryptFinal(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)


class _ExactSignRaw:
    """Non-variadic fake that exposes the pinned v3 sign ABI and call order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def C_MessageSignInit(self, _session: int, _mechanism: object, _key: int) -> int:  # noqa: N802
        self.calls.append(("init", 0))
        return int(CKR_OK)

    def C_SignMessage(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        _data: object,
        _data_len: int,
        signature: object,
        signature_len: object,
    ) -> int:
        size = 3
        signature_len._obj.value = size  # type: ignore[attr-defined]
        self.calls.append(("single-output" if signature is not None else "single-size", size))
        if signature is not None:
            signature[0] = ord("s")  # type: ignore[index]
            signature[1] = ord("i")  # type: ignore[index]
            signature[2] = ord("g")  # type: ignore[index]
        return int(CKR_OK)

    def C_MessageSignFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append(("final", 0))
        return int(CKR_OK)

    def C_SignMessageBegin(  # noqa: N802
        self, _session: int, _params: object, _params_len: int
    ) -> int:
        self.calls.append(("begin", 0))
        return int(CKR_OK)

    def C_SignMessageNext(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        data: object,
        data_len: int,
        signature: object,
        signature_len: object,
    ) -> int:
        if signature is not None:
            call_name = "next-output"
        elif signature_len is not None:
            call_name = "next-query"
        else:
            call_name = "next-intermediate"
        self.calls.append((call_name, data_len))
        assert data is not None
        if signature_len is not None:
            signature_len._obj.value = 3  # type: ignore[attr-defined]
        if signature is not None:
            signature[0] = ord("s")  # type: ignore[index]
            signature[1] = ord("i")  # type: ignore[index]
            signature[2] = ord("g")  # type: ignore[index]
        return int(CKR_OK)


class _ExactVerifyRaw:
    """Non-variadic fake that exposes the pinned v3 verify ABI and call order."""

    def __init__(self, verify_rv: int = int(CKR_OK)) -> None:
        self.calls: list[tuple[str, int]] = []
        self.verify_rv = verify_rv

    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, _mechanism: object, _key: int
    ) -> int:
        self.calls.append(("init", 0))
        return int(CKR_OK)

    def C_VerifyMessage(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        _data: object,
        _data_len: int,
        _signature: object,
        _signature_len: int,
    ) -> int:
        self.calls.append(("single", 0))
        return self.verify_rv

    def C_MessageVerifyFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append(("final", 0))
        return int(CKR_OK)

    def C_VerifyMessageBegin(  # noqa: N802
        self, _session: int, _params: object, _params_len: int
    ) -> int:
        self.calls.append(("begin", 0))
        return int(CKR_OK)

    def C_VerifyMessageNext(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        data: object,
        data_len: int,
        signature: object,
        signature_len: int,
    ) -> int:
        call_name = "next-signature" if signature is not None else "next-intermediate"
        self.calls.append((call_name, data_len))
        assert data is not None
        if signature is not None:
            assert signature_len == 3
        return self.verify_rv if signature is not None else int(CKR_OK)


def _message_rs(raw: object) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=7)


def test_message_verify_bad_signature_device_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=_MessageVerifyRaw(),
        sh=1,
        has_mechanism=lambda name: name == "SHA256_RSA_PKCS",
        has_mechanism_flag=lambda _mechanism, _flag: True,
    )
    monkeypatch.setattr(test_message_crypto, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_message_crypto, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_message_crypto.TestMessageSignVerify().test_message_verify_bad_signature(rs)


def test_message_sign_init_mechanism_invalid_is_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_message_crypto.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_MECHANISM_INVALID)), sh=1)

    with pytest.raises(pytest.fail.Exception, match="advertised"):
        test_message_crypto._message_sign(rs, 1, 1, b"data")


def test_message_sign_init_function_not_supported_is_failure() -> None:
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_FUNCTION_NOT_SUPPORTED)), sh=1)

    with pytest.raises(pytest.fail.Exception, match="advertised"):
        test_message_crypto._message_sign(rs, 1, 1, b"data")


def test_message_sign_init_defined_refusal_is_xfail() -> None:
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_ARGUMENTS_BAD)), sh=1)

    assert_xfails(
        test_message_crypto._message_sign,
        rs,
        1,
        1,
        b"data",
        match="C_MessageSignInit rejected advertised",
    )


def test_advertised_argument_error_is_failure_like_xfail() -> None:
    classification.clear()

    assert_xfails(
        test_message_crypto._handle_message_rv,
        int(CKR_ARGUMENTS_BAD),
        "C_MessageSignInit",
        advertised=True,
        match="CKR_ARGUMENTS_BAD",
    )


def test_advertised_undefined_rv_is_metadata_failure() -> None:
    classification.clear()
    undefined_rv = 0x7FFFFFFF

    with pytest.raises(pytest.fail.Exception, match="undefined"):
        test_message_crypto._handle_message_rv(
            undefined_rv,
            "C_MessageSignInit",
            advertised=True,
        )

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x7fffffff"


def test_message_encrypt_uses_aes_keygen_xfail_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_message_crypto,
        "gen_aes_key",
        lambda *_args, **_kwargs: pytest.fail("raw AES keygen helper used"),
        raising=False,
    )
    monkeypatch.setattr(
        test_message_crypto,
        "gen_aes_key_or_xfail",
        lambda *_args, **_kwargs: pytest.xfail("AES_KEY_GEN advertised but rejected"),
        raising=False,
    )
    rs = SimpleNamespace(
        raw=_MessageEncryptRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_CBC", "AES_KEY_GEN"},
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_message_crypto.TestMessageEncryptDecrypt().test_message_encrypt_single(rs)


def test_skip_if_message_op_not_implemented_skips_on_fns() -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    assert_skips(
        test_message_crypto._skip_if_message_op_not_implemented,
        exc,
        "message encrypt",
        match="message encrypt",
    )


def test_skip_if_message_op_not_implemented_ignores_other_ckr() -> None:
    exc = CkrAssertionError("CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID))
    # Must return quietly so the caller's own xfail_if_known_ckr path runs.
    test_message_crypto._skip_if_message_op_not_implemented(exc, "message encrypt")


def test_message_encrypt_single_fns_is_skip_not_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """C_MessageEncryptInit/C_EncryptMessage are optional v3.0 functions; FNS from
    message_encrypt() is capability absence, not a deviation (site: line ~262)."""
    rs = SimpleNamespace(
        raw=_MessageEncryptRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_CBC", "AES_KEY_GEN"},
    )
    monkeypatch.setattr(test_message_crypto, "gen_aes_key_or_xfail", lambda *_a, **_k: 42)
    monkeypatch.setattr(test_message_crypto, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))

    # test_message_encrypt_single() does `from pkcs11_check.raw.recipes import
    # message_encrypt` locally, so the patch target is the recipes module, not
    # the test_message_crypto module namespace.
    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "message_encrypt", _raise)

    assert_skips(
        test_message_crypto.TestMessageEncryptDecrypt().test_message_encrypt_single,
        rs,
        match="message encrypt",
    )


def test_message_sign_single_finalizes_after_completed_message() -> None:
    raw = _ExactSignRaw()

    assert test_message_crypto._message_sign(_message_rs(raw), 11, 1, b"data") == b"sig"
    assert raw.calls == [
        ("init", 0),
        ("single-size", 3),
        ("single-output", 3),
        ("final", 0),
    ]


def test_message_verify_single_finalizes_after_completed_message() -> None:
    raw = _ExactVerifyRaw()

    assert test_message_crypto._message_verify(_message_rs(raw), 12, 1, b"data", b"sig") is True
    assert raw.calls == [("init", 0), ("single", 0), ("final", 0)]


def test_message_sign_multipart_uses_begin_once_and_repeats_final_part() -> None:
    raw = _ExactSignRaw()

    assert test_message_crypto._message_sign_multipart(
        _message_rs(raw), 11, 1, [b"one", b"two", b"three"]
    ) == b"sig"
    assert raw.calls == [
        ("init", 0),
        ("begin", 0),
        ("next-intermediate", 3),
        ("next-intermediate", 3),
        ("next-query", 5),
        ("next-output", 5),
        ("final", 0),
    ]


def test_message_verify_multipart_puts_signature_only_on_final_next() -> None:
    raw = _ExactVerifyRaw()

    assert test_message_crypto._message_verify_multipart(
        _message_rs(raw), 12, 1, [b"one", b"two", b"three"], b"sig"
    ) is True
    assert raw.calls == [
        ("init", 0),
        ("begin", 0),
        ("next-intermediate", 3),
        ("next-intermediate", 3),
        ("next-signature", 5),
        ("final", 0),
    ]


def test_message_verify_multipart_bad_signature_preserves_rejection_policy() -> None:
    from pkcs11_check.raw.types_std import CKR_SIGNATURE_INVALID

    raw = _ExactVerifyRaw(int(CKR_SIGNATURE_INVALID))

    assert test_message_crypto._message_verify_multipart(
        _message_rs(raw), 12, 1, [b"one", b"two"], b"bad", expect_valid=False
    ) is False
    assert raw.calls == [
        ("init", 0),
        ("begin", 0),
        ("next-intermediate", 3),
        ("next-signature", 3),
        ("final", 0),
    ]


@pytest.mark.parametrize(
    ("rv", "expected"),
    [
        (int(CKR_FUNCTION_NOT_SUPPORTED), pytest.fail.Exception),
        (int(CKR_MECHANISM_INVALID), pytest.fail.Exception),
    ],
)
def test_advertised_sign_setup_self_contradiction_is_failure(
    rv: int, expected: type[BaseException]
) -> None:
    with pytest.raises(expected, match="advertised"):
        test_message_crypto._message_sign(_message_rs(_MessageSignInitRaw(rv)), 1, 1, b"data")


def test_message_flag_gate_checks_each_required_flag_before_keygen() -> None:
    calls: list[tuple[str, int]] = []

    def _has_flag(mechanism: str, flag: int) -> bool:
        calls.append((mechanism, flag))
        return flag != int(CKF_MULTI_MESSAGE)

    rs = SimpleNamespace(
        has_mechanism_flag=_has_flag,
    )

    assert_skips(
        test_message_crypto._require_message_flags,
        rs,
        "SHA256_RSA_PKCS",
        (int(CKF_MESSAGE_SIGN), int(CKF_MULTI_MESSAGE)),
        "multipart sign",
        match="CKF_MULTI_MESSAGE",
    )
    assert calls == [
        ("SHA256_RSA_PKCS", int(CKF_MESSAGE_SIGN)),
        ("SHA256_RSA_PKCS", int(CKF_MULTI_MESSAGE)),
    ]


def test_multipart_verify_gate_does_not_require_message_sign_flag() -> None:
    calls: list[int] = []

    def _has_flag(_mechanism: str, flag: int) -> bool:
        calls.append(flag)
        return flag != int(CKF_MESSAGE_SIGN)

    rs = SimpleNamespace(
        has_mechanism_flag=_has_flag,
    )

    # The verify gate asks only for VERIFY + MULTI; a missing SIGN flag is irrelevant.
    test_message_crypto._require_message_flags(
        rs,
        "SHA256_RSA_PKCS",
        (int(CKF_MESSAGE_VERIFY), int(CKF_MULTI_MESSAGE)),
        "multipart verify",
    )
    assert calls == [int(CKF_MESSAGE_VERIFY), int(CKF_MULTI_MESSAGE)]

"""Regression tests for message-based crypto result classification."""

from __future__ import annotations

import ctypes
import hashlib
from types import SimpleNamespace

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.pack import mech_ulong
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKF_MULTI_MESSAGE,
    CKK_GENERIC_SECRET,
    CKM_BLAKE2B_160_HMAC_GENERAL,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases import test_mech_message, test_message_crypto
from pkcs11_check.testcases.conftest import assert_correct
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


class _PackedSignRaw(_ExactSignRaw):
    def C_MessageSignInit(  # noqa: N802
        self, _session: int, mechanism: object, _key: int
    ) -> int:
        packed = ctypes.cast(mechanism, ctypes.POINTER(CK_MECHANISM)).contents
        assert int(packed.mechanism) == int(CKM_BLAKE2B_160_HMAC_GENERAL)
        assert int(packed.ulParameterLen) == ctypes.sizeof(CK_ULONG)
        value = ctypes.cast(packed.pParameter, ctypes.POINTER(CK_ULONG)).contents.value
        assert int(value) == 8
        return super().C_MessageSignInit(_session, mechanism, _key)


class _PackedVerifyRaw(_ExactVerifyRaw):
    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, mechanism: object, _key: int
    ) -> int:
        packed = ctypes.cast(mechanism, ctypes.POINTER(CK_MECHANISM)).contents
        assert int(packed.mechanism) == int(CKM_BLAKE2B_160_HMAC_GENERAL)
        assert int(packed.ulParameterLen) == ctypes.sizeof(CK_ULONG)
        value = ctypes.cast(packed.pParameter, ctypes.POINTER(CK_ULONG)).contents.value
        assert int(value) == 8
        return super().C_MessageVerifyInit(_session, mechanism, _key)


class _OutputSignRaw(_ExactSignRaw):
    def __init__(self, output: bytes) -> None:
        super().__init__()
        self.output = output

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
        signature_len._obj.value = len(self.output)  # type: ignore[attr-defined]
        self.calls.append(
            ("single-output" if signature is not None else "single-size", len(self.output))
        )
        if signature is not None:
            for index, byte in enumerate(self.output):
                signature[index] = byte  # type: ignore[index]
        return int(CKR_OK)


class _Blake2MessagePositiveRaw:
    """Controllable raw module for the registry-driven BLAKE2 message nodes."""

    def __init__(
        self,
        case: test_mech_message._Blake2MessageCase,
        *,
        accept_any_verify: bool = False,
        wrong_sign_output: bool = False,
        raise_on_sign: bool = False,
        raise_on_verify: bool = False,
    ) -> None:
        self.case = case
        self.accept_any_verify = accept_any_verify
        self.wrong_sign_output = wrong_sign_output
        self.raise_on_sign = raise_on_sign
        self.raise_on_verify = raise_on_verify
        self.calls: list[str] = []
        self.verify_rvs: list[int] = []

    def _check_mechanism(self, mechanism: object, operation: str, key: int) -> None:
        packed = ctypes.cast(mechanism, ctypes.POINTER(CK_MECHANISM)).contents
        assert int(packed.mechanism) == int(self.case.mechanism)
        if self.case.general:
            assert int(packed.ulParameterLen) == ctypes.sizeof(CK_ULONG)
            value = ctypes.cast(packed.pParameter, ctypes.POINTER(CK_ULONG)).contents.value
            assert int(value) == 8
        else:
            assert int(packed.ulParameterLen) == 0
            assert not packed.pParameter
        assert key == 99
        self.calls.append(operation)

    def _tag(self, data: object, data_len: int) -> bytes:
        payload = bytes(data[:data_len])  # type: ignore[index]
        full = hashlib.blake2b(
            payload,
            key=b"\x42" * 32,
            digest_size=self.case.digest_size,
        ).digest()
        return full[:8] if self.case.general else full

    def C_MessageSignInit(  # noqa: N802
        self, _session: int, mechanism: object, key: int
    ) -> int:
        self._check_mechanism(mechanism, "sign-init", key)
        return int(CKR_OK)

    def C_SignMessage(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        data: object,
        data_len: int,
        signature: object,
        signature_len: object,
    ) -> int:
        if self.raise_on_sign:
            raise RuntimeError("sign effect sentinel")
        tag = self._tag(data, data_len)
        if self.wrong_sign_output:
            tag = bytes([tag[0] ^ 1]) + tag[1:]
        signature_len._obj.value = len(tag)  # type: ignore[attr-defined]
        self.calls.append("sign-output" if signature is not None else "sign-size")
        if signature is not None:
            for index, byte in enumerate(tag):
                signature[index] = byte  # type: ignore[index]
        return int(CKR_OK)

    def C_MessageSignFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append("sign-final")
        return int(CKR_OK)

    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, mechanism: object, key: int
    ) -> int:
        self._check_mechanism(mechanism, "verify-init", key)
        return int(CKR_OK)

    def C_VerifyMessage(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        data: object,
        data_len: int,
        signature: object,
        signature_len: int,
    ) -> int:
        if self.raise_on_verify:
            raise RuntimeError("verify effect sentinel")
        expected = self._tag(data, data_len)
        actual = bytes(signature[:signature_len])  # type: ignore[index]
        self.calls.append("verify")
        if self.accept_any_verify or actual == expected:
            self.verify_rvs.append(int(CKR_OK))
            return int(CKR_OK)
        self.verify_rvs.append(int(CKR_SIGNATURE_INVALID))
        return int(CKR_SIGNATURE_INVALID)

    def C_MessageVerifyFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append("verify-final")
        return int(CKR_OK)


class _MissingSignMessageRaw:
    def C_MessageSignInit(self, _session: int, _mechanism: object, _key: int) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageSignFinal(self, _session: int) -> int:  # noqa: N802
        return int(CKR_OK)


class _MissingVerifyMessageRaw:
    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, _mechanism: object, _key: int
    ) -> int:
        return int(CKR_OK)

    def C_MessageVerifyFinal(self, _session: int) -> int:  # noqa: N802
        return int(CKR_OK)


def _message_rs(raw: object) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=7)


def _registry_message_rs(raw: _Blake2MessagePositiveRaw, flag: int) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=7,
        has_mechanism=lambda name: name == raw.case.name,
        has_mechanism_flag=lambda name, requested: name == raw.case.name and requested == flag,
    )


def _patch_registry_message_key_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[tuple[int, bytes, dict[int, object], str]], list[tuple[object, int, int]]]:
    imported: list[tuple[int, bytes, dict[int, object], str]] = []
    destroyed: list[tuple[object, int, int]] = []

    def _import(
        _rs: object,
        key_type: int,
        value: bytes,
        *,
        attrs: dict[int, object],
        purpose: str,
    ) -> int:
        imported.append((int(key_type), value, dict(attrs), purpose))
        return 99

    monkeypatch.setattr(test_mech_message, "import_secret_key_negotiated", _import)
    monkeypatch.setattr(
        test_mech_message,
        "destroy_quietly",
        lambda raw, session, key: destroyed.append((raw, session, key)),
    )
    return imported, destroyed


@pytest.mark.parametrize(
    "case",
    test_mech_message._BLAKE2_MESSAGE_CASES,
    ids=[case.name for case in test_mech_message._BLAKE2_MESSAGE_CASES],
)
def test_registry_blake2_sign_node_executes_generic_secret_effects(
    monkeypatch: pytest.MonkeyPatch,
    case: test_mech_message._Blake2MessageCase,
) -> None:
    classification.clear()
    imported, destroyed = _patch_registry_message_key_setup(monkeypatch)
    raw = _Blake2MessagePositiveRaw(case)
    rs = _registry_message_rs(raw, int(CKF_MESSAGE_SIGN))

    test_mech_message.TestRegistryMessageBlake2GenericSecret().test_registry_message_blake2_generic_secret_sign(
        p11_raw_session=rs, case=case
    )

    assert imported == [
        (
            int(CKK_GENERIC_SECRET),
            b"\x42" * 32,
            {CKA_TOKEN: False, CKA_SIGN: True, CKA_VERIFY: True},
            f"{case.name} message generic-secret sign setup",
        )
    ]
    assert destroyed == [(raw, 7, 99)]
    assert raw.calls == [
        "sign-init",
        "sign-final",
        "sign-init",
        "sign-size",
        "sign-output",
        "sign-final",
    ]
    assert classification.get_records() == []


@pytest.mark.parametrize(
    "case",
    test_mech_message._BLAKE2_MESSAGE_CASES,
    ids=[case.name for case in test_mech_message._BLAKE2_MESSAGE_CASES],
)
def test_registry_blake2_verify_node_executes_generic_secret_effects(
    monkeypatch: pytest.MonkeyPatch,
    case: test_mech_message._Blake2MessageCase,
) -> None:
    classification.clear()
    imported, destroyed = _patch_registry_message_key_setup(monkeypatch)
    raw = _Blake2MessagePositiveRaw(case)
    rs = _registry_message_rs(raw, int(CKF_MESSAGE_VERIFY))

    test_mech_message.TestRegistryMessageBlake2GenericSecret().test_registry_message_blake2_generic_secret_verify(
        p11_raw_session=rs, case=case
    )

    assert imported == [
        (
            int(CKK_GENERIC_SECRET),
            b"\x42" * 32,
            {CKA_TOKEN: False, CKA_SIGN: True, CKA_VERIFY: True},
            f"{case.name} message generic-secret verify setup",
        )
    ]
    assert destroyed == [(raw, 7, 99)]
    assert raw.calls == [
        "verify-init",
        "verify-final",
        "verify-init",
        "verify",
        "verify-final",
        "verify-init",
        "verify",
        "verify-final",
    ]
    assert raw.verify_rvs == [int(CKR_OK), int(CKR_SIGNATURE_INVALID)]
    assert classification.get_records() == []


def test_registry_blake2_sign_node_classifies_wrong_same_length_mac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    imported, destroyed = _patch_registry_message_key_setup(monkeypatch)
    case = test_mech_message._BLAKE2_MESSAGE_CASES[1]
    raw = _Blake2MessagePositiveRaw(case, wrong_sign_output=True)

    with pytest.raises(pytest.fail.Exception, match="output does not match"):
        test_mech_message.TestRegistryMessageBlake2GenericSecret().test_registry_message_blake2_generic_secret_sign(
            p11_raw_session=_registry_message_rs(raw, int(CKF_MESSAGE_SIGN)), case=case
        )

    assert imported and destroyed == [(raw, 7, 99)]
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_registry_blake2_verify_node_classifies_accept_any_wrong_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    imported, destroyed = _patch_registry_message_key_setup(monkeypatch)
    case = test_mech_message._BLAKE2_MESSAGE_CASES[1]
    raw = _Blake2MessagePositiveRaw(case, accept_any_verify=True)

    with pytest.raises(pytest.fail.Exception, match="output does not match"):
        test_mech_message.TestRegistryMessageBlake2GenericSecret().test_registry_message_blake2_generic_secret_verify(
            p11_raw_session=_registry_message_rs(raw, int(CKF_MESSAGE_VERIFY)), case=case
        )

    assert imported and destroyed == [(raw, 7, 99)]
    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


@pytest.mark.parametrize(
    ("method_name", "flag", "error_text"),
    [
        (
            "test_registry_message_blake2_generic_secret_sign",
            int(CKF_MESSAGE_SIGN),
            "sign effect sentinel",
        ),
        (
            "test_registry_message_blake2_generic_secret_verify",
            int(CKF_MESSAGE_VERIFY),
            "verify effect sentinel",
        ),
    ],
)
def test_registry_blake2_nodes_preserve_effect_exception_and_destroy_key(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    flag: int,
    error_text: str,
) -> None:
    classification.clear()
    imported, destroyed = _patch_registry_message_key_setup(monkeypatch)
    case = test_mech_message._BLAKE2_MESSAGE_CASES[1]
    raw = _Blake2MessagePositiveRaw(
        case,
        raise_on_sign=flag == int(CKF_MESSAGE_SIGN),
        raise_on_verify=flag == int(CKF_MESSAGE_VERIFY),
    )

    with pytest.raises(RuntimeError, match=error_text):
        getattr(test_mech_message.TestRegistryMessageBlake2GenericSecret(), method_name)(
            p11_raw_session=_registry_message_rs(raw, flag), case=case
        )

    assert imported
    assert destroyed == [(raw, 7, 99)]
    assert classification.get_records() == []


@pytest.mark.parametrize(
    ("method_name", "raw_type", "flag", "missing_name"),
    [
        (
            "test_registry_message_blake2_generic_secret_sign",
            _MissingSignMessageRaw,
            int(CKF_MESSAGE_SIGN),
            "C_SignMessage",
        ),
        (
            "test_registry_message_blake2_generic_secret_verify",
            _MissingVerifyMessageRaw,
            int(CKF_MESSAGE_VERIFY),
            "C_VerifyMessage",
        ),
    ],
)
def test_registry_blake2_nodes_skip_when_effect_function_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    raw_type: type[object],
    flag: int,
    missing_name: str,
) -> None:
    case = test_mech_message._BLAKE2_MESSAGE_CASES[0]
    raw = raw_type()
    rs = SimpleNamespace(
        raw=raw,
        sh=7,
        has_mechanism=lambda name: name == case.name,
        has_mechanism_flag=lambda name, requested: name == case.name and requested == flag,
    )
    monkeypatch.setattr(
        test_mech_message,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("key import should not run before capability skip"),
    )

    with pytest.raises(pytest.skip.Exception, match=missing_name):
        getattr(test_mech_message.TestRegistryMessageBlake2GenericSecret(), method_name)(
            p11_raw_session=rs, case=case
        )


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


def test_advertised_vendor_rv_is_defined_refusal_xfail() -> None:
    """A vendor-defined CK_RV on an advertised op is a defined provider
    refusal (not_operational), not an undefined-CKR contradiction."""
    classification.clear()

    assert_xfails(
        test_message_crypto._handle_message_rv,
        0x80000001,
        "C_MessageSignInit",
        advertised=True,
        match="rejected advertised",
    )
    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"


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
        has_mechanism_flag=lambda _mechanism, _flag: True,
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
        has_mechanism_flag=lambda _mechanism, _flag: True,
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


def test_message_sign_accepts_packed_general_mechanism() -> None:
    raw = _PackedSignRaw()
    packed = mech_ulong(CKM_BLAKE2B_160_HMAC_GENERAL, 8)

    assert test_message_crypto._message_sign(_message_rs(raw), 11, packed, b"data") == b"sig"


def test_message_verify_accepts_packed_general_mechanism() -> None:
    raw = _PackedVerifyRaw()
    packed = mech_ulong(CKM_BLAKE2B_160_HMAC_GENERAL, 8)

    assert (
        test_message_crypto._message_verify(_message_rs(raw), 12, packed, b"data", b"sig") is True
    )


def test_message_sign_healthy_and_wrong_same_length_outputs_are_distinguished() -> None:
    expected = b"\xa5" * 8
    healthy = _OutputSignRaw(expected)
    assert test_message_crypto._message_sign(_message_rs(healthy), 11, 1, b"data") == expected

    wrong = _OutputSignRaw(b"\x5a" * 8)
    with pytest.raises(pytest.fail.Exception, match="output does not match"):
        assert_correct(
            actual=test_message_crypto._message_sign(_message_rs(wrong), 11, 1, b"data"),
            expected=expected,
            label="same-length message MAC",
            operation="C_SignMessage",
            mechanism="CKM_BLAKE2B_160_HMAC_GENERAL",
        )


def test_message_verify_strict_reject_and_accept_any_controls() -> None:
    strict = _ExactVerifyRaw(int(CKR_SIGNATURE_INVALID))
    assert (
        test_message_crypto._message_verify(
            _message_rs(strict), 12, 1, b"data", b"wrong!", expect_valid=False
        )
        is False
    )

    accept_any = _ExactVerifyRaw(int(CKR_OK))
    with pytest.raises(pytest.fail.Exception, match="output does not match"):
        assert_correct(
            actual=test_message_crypto._message_verify(
                _message_rs(accept_any), 12, 1, b"data", b"wrong!", expect_valid=False
            ),
            expected=False,
            label="message verification rejects wrong tag",
            operation="C_VerifyMessage",
            mechanism="CKM_BLAKE2B_160_HMAC_GENERAL",
        )


def test_message_sign_multipart_uses_begin_once_and_repeats_final_part() -> None:
    raw = _ExactSignRaw()

    assert (
        test_message_crypto._message_sign_multipart(
            _message_rs(raw), 11, 1, [b"one", b"two", b"three"]
        )
        == b"sig"
    )
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

    assert (
        test_message_crypto._message_verify_multipart(
            _message_rs(raw), 12, 1, [b"one", b"two", b"three"], b"sig"
        )
        is True
    )
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

    assert (
        test_message_crypto._message_verify_multipart(
            _message_rs(raw), 12, 1, [b"one", b"two"], b"bad", expect_valid=False
        )
        is False
    )
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

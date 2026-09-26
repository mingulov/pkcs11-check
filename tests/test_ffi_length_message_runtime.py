"""Regression tests for the v3 message length-probe ABI."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import (
    CKF_MESSAGE_SIGN,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._probes import _ffi_length_message as probe
from pkcs11_check.testcases.security import test_ffi_length_boundary as boundary
from tests._skip_assert import assert_skips


class _ExactMultipartRaw:
    """Exact-arity fake: wrong Begin/Next calls fail before provider entry."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def C_MessageSignInit(self, _session: int, _mechanism: object, _key: int) -> int:  # noqa: N802
        self.calls.append(("sign-init", 0))
        return int(CKR_OK)

    def C_SignMessageBegin(  # noqa: N802
        self, _session: int, _params: object, params_len: int
    ) -> int:
        self.calls.append(("sign-begin", params_len))
        return int(CKR_OK)

    def C_SignMessageNext(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        _data: object,
        data_len: int,
        _signature: object,
        _signature_len: object,
    ) -> int:
        self.calls.append(("sign-next", data_len))
        return int(CKR_OK)

    def C_MessageSignFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append(("sign-final", 0))
        return int(CKR_OK)

    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, _mechanism: object, _key: int
    ) -> int:
        self.calls.append(("verify-init", 0))
        return int(CKR_OK)

    def C_VerifyMessageBegin(  # noqa: N802
        self, _session: int, _params: object, params_len: int
    ) -> int:
        self.calls.append(("verify-begin", params_len))
        return int(CKR_OK)

    def C_VerifyMessageNext(  # noqa: N802
        self,
        _session: int,
        _params: object,
        _params_len: int,
        _data: object,
        data_len: int,
        _signature: object,
        signature_len: int,
    ) -> int:
        self.calls.append(("verify-next", data_len if signature_len == 256 else signature_len))
        return int(CKR_OK)

    def C_MessageVerifyFinal(self, _session: int) -> int:  # noqa: N802
        self.calls.append(("verify-final", 0))
        return int(CKR_OK)


def _ctx(raw: _ExactMultipartRaw) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=9)


@pytest.fixture(autouse=True)
def _patch_probe_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "demand_zero_buffer", lambda: (ctypes.c_ubyte * 16)())
    monkeypatch.setattr(probe, "gen_rsa_keypair", lambda *_args, **_kwargs: (10, 11))
    monkeypatch.setattr(probe, "sign_single", lambda *_args, **_kwargs: b"sig")
    monkeypatch.setattr(probe, "destroy_quietly", lambda *_args: None)


def test_sign_begin_probe_targets_parameter_length_with_three_arguments() -> None:
    raw = _ExactMultipartRaw()

    probe._run_sign_message_multipart(
        _ctx(raw), {"op": "C_SignMessageBegin", "data_len": 0x1234}
    )

    assert raw.calls == [
        ("sign-init", 0),
        ("sign-begin", 0x1234),
        ("sign-final", 0),
    ]


def test_sign_next_probe_uses_seven_argument_abi_and_data_length() -> None:
    raw = _ExactMultipartRaw()

    probe._run_sign_message_multipart(
        _ctx(raw), {"op": "C_SignMessageNext", "data_len": 0x5678}
    )

    assert raw.calls == [
        ("sign-init", 0),
        ("sign-begin", 0),
        ("sign-next", 0x5678),
        ("sign-final", 0),
    ]


def test_verify_begin_probe_uses_parameter_length_with_three_arguments() -> None:
    raw = _ExactMultipartRaw()

    probe._run_verify_message_multipart(
        _ctx(raw),
        {
            "field": "begin_parameter",
            "begin_param_len": 0x1234,
            "next_data_len": 16,
            "next_signature_len": 256,
        },
    )

    assert raw.calls == [
        ("verify-init", 0),
        ("verify-begin", 0x1234),
        ("verify-final", 0),
    ]


@pytest.mark.parametrize("field", ["next_data", "next_signature"])
def test_verify_next_probe_uses_seven_argument_abi(field: str) -> None:
    raw = _ExactMultipartRaw()

    probe._run_verify_message_multipart(
        _ctx(raw),
        {
            "field": field,
            "begin_param_len": 0,
            "next_data_len": 0x2345 if field == "next_data" else 16,
            "next_signature_len": 0x3456 if field == "next_signature" else 256,
        },
    )

    target_len = 0x2345 if field == "next_data" else 0x3456
    assert raw.calls == [
        ("verify-init", 0),
        ("verify-begin", 0),
        ("verify-next", target_len),
        ("verify-final", 0),
    ]


@pytest.mark.parametrize("rv", [CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID])
def test_advertised_setup_reject_has_distinct_protocol(
    rv: int, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(probe._SetupRejected):
        probe._message_setup_reject(int(rv), "C_MessageSignInit", advertised=True)

    assert capsys.readouterr().out == (
        f"SETUP_CONTRADICTION:C_MessageSignInit:0x{int(rv):08x}\n"
    )


@pytest.mark.parametrize("rv", [CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID])
def test_parent_setup_contradiction_fails_before_target_classification(rv: int) -> None:
    from pkcs11_check import classification

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="C_MessageSignInit"):
        boundary._classify_unhonorable_length_outcome(
            0,
            f"SETUP_CONTRADICTION:C_MessageSignInit:0x{int(rv):08x}\n",
            "",
            reject_rvs=(CKR_OK,),
            label_op="C_SignMessage(data_len=0x7fff)",
            test_id="test_sign_message_isize_input_len",
        )

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.operation == "C_MessageSignInit"
    assert record.actual_ckr == (
        "CKR_FUNCTION_NOT_SUPPORTED"
        if rv == CKR_FUNCTION_NOT_SUPPORTED
        else "CKR_MECHANISM_INVALID"
    )
    assert record.label == "C_MessageSignInit"


class _BoundaryRaw:
    def available_function_names(self) -> set[str]:
        return {
            "C_MessageSignInit",
            "C_SignMessage",
            "C_MessageSignFinal",
            "C_SignMessageBegin",
            "C_SignMessageNext",
        }


def _boundary_inputs() -> tuple[SimpleNamespace, SimpleNamespace]:
    rs = SimpleNamespace(
        raw=_BoundaryRaw(),
        slot_id=1,
        has_mechanism=lambda _name: True,
    )
    config = SimpleNamespace(module="module", slot=1, interface="auto")
    return rs, config


def test_single_hostile_sign_requires_message_sign_before_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs, config = _boundary_inputs()
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_info",
        lambda *_args: {"flags": 0},
    )
    monkeypatch.setattr(
        boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kwargs: pytest.fail("key generation must not run after a gate skip"),
    )
    monkeypatch.setattr(
        boundary,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("probe must not run after a gate skip"),
    )

    assert_skips(
        boundary.TestMessageApiLengthBoundary().test_sign_message_isize_input_len,
        rs,
        config,
        boundary._ISIZE_MAX_64,
        match="CKF_MESSAGE_SIGN",
    )


def test_single_hostile_sign_does_not_require_multi_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReachedKeyGenerationError(Exception):
        pass

    def _reach_key_generation(*_args: object, **_kwargs: object) -> None:
        raise ReachedKeyGenerationError

    rs, config = _boundary_inputs()
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_info",
        lambda *_args: {"flags": int(CKF_MESSAGE_SIGN)},
    )
    monkeypatch.setattr(
        boundary,
        "gen_rsa_keypair_or_xfail",
        _reach_key_generation,
    )

    with pytest.raises(ReachedKeyGenerationError):
        boundary.TestMessageApiLengthBoundary().test_sign_message_isize_input_len(
            rs,
            config,
            boundary._ISIZE_MAX_64,
        )


def test_multipart_hostile_sign_requires_multi_message_before_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs, config = _boundary_inputs()
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.get_mechanism_info",
        lambda *_args: {"flags": int(CKF_MESSAGE_SIGN)},
    )
    monkeypatch.setattr(
        boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kwargs: pytest.fail("key generation must not run after a gate skip"),
    )
    monkeypatch.setattr(
        boundary,
        "run_probe",
        lambda *_args, **_kwargs: pytest.fail("probe must not run after a gate skip"),
    )

    assert_skips(
        boundary.TestMessageApiLengthBoundary().test_sign_message_multipart_isize_input_len,
        rs,
        config,
        boundary._ISIZE_MAX_64,
        "C_SignMessageBegin",
        match="CKF_MULTI_MESSAGE",
    )

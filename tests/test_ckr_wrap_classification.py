"""Classification meta-tests for ckr/test_ckr_wrap non-extractable wrap (Phase 6 C).

policy: a module that claims CKA_EXTRACTABLE=False then wraps (exports) the key
is a self-contradiction -> fail (was masked by skip). A module that does not
claim the protection -> xfail. A claimed-and-rejected wrap -> pass.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_WRAP,
    CKM_AES_KEY_WRAP,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases.ckr import test_ckr_wrap as tcw


def _session(*, extractable_readback: int, getattr_rv: int, wrap_rv: int) -> SimpleNamespace:
    keys = iter([10, 11])  # wrap_key, target

    def _gen(*_a: object, **_k: object) -> int:
        return next(keys)

    def _getattr(_sh: int, _obj: int, check: Any, _n: int) -> int:
        # check[0].pValue points at a CK_BBOOL; write the read-back value.
        bbool = ctypes.cast(check[0].pValue, ctypes.POINTER(ctypes.c_ubyte))
        bbool[0] = extractable_readback
        return int(getattr_rv)

    raw = SimpleNamespace(
        C_GenerateKey=lambda *_a, **_k: None,
        C_GetAttributeValue=_getattr,
        C_WrapKey=lambda *_a, **_k: int(wrap_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda _n: True)


def _run(monkeypatch: pytest.MonkeyPatch, **kw: int) -> None:
    monkeypatch.setattr(tcw, "gen_aes_key", lambda *_a, **_k: 10)
    monkeypatch.setattr(tcw, "destroy_quietly", lambda *_a, **_k: None)
    tcw.TestWrapKeyErrors().test_key_not_extractable(_session(**kw), False)


def test_claimed_then_wrapped_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module honoured EXTRACTABLE=False (readback 0) but wrap succeeded.
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, extractable_readback=0, getattr_rv=int(CKR_OK), wrap_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module did NOT honour EXTRACTABLE=False (readback 1) -> honest non-support.
    with pytest.raises(XFailed):
        _run(monkeypatch, extractable_readback=1, getattr_rv=int(CKR_OK), wrap_rv=int(CKR_OK))


def test_claimed_and_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Honoured EXTRACTABLE=False and wrap rejected (CKR_KEY_UNEXTRACTABLE=0x68).
    _run(monkeypatch, extractable_readback=0, getattr_rv=int(CKR_OK), wrap_rv=0x68)


def test_missing_readback_but_wrapped_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F7 claim-sweep regression: gen_aes_key() raises unless C_GenerateKey
    returns CKR_OK, so reaching the enforcement probe already proves
    creation-time acceptance of CKA_EXTRACTABLE=False. An unreadable readback
    (CKR_ATTRIBUTE_TYPE_INVALID, a known accepted precondition-check outcome)
    must not downgrade a proven wrap-extraction self-contradiction to xfail
    (mutation: restoring the pre-fix ``claimed = rv == CKR_OK and val.value ==
    0`` derivation -- False when rv != CKR_OK -- turns this back into an
    xfail)."""
    with pytest.raises(Failed) as ei:
        _run(
            monkeypatch,
            extractable_readback=1,  # ignored: readback rv below is not CKR_OK
            getattr_rv=int(CKR_ATTRIBUTE_TYPE_INVALID),
            wrap_rv=int(CKR_OK),
        )
    assert not isinstance(ei.value, XFailed)


class _WrapKeyFake:
    """Stateful raw/factory fake for the existing stale-wrap-key oracle."""

    def __init__(
        self,
        *,
        wrap_rv: int = int(CKR_WRAPPING_KEY_HANDLE_INVALID),
        has_mechanism: bool = True,
        target_error: BaseException | None = None,
        destroy_rv: int = int(CKR_OK),
        wrap_error: BaseException | None = None,
    ) -> None:
        self.wrap_rv = wrap_rv
        self.has_mechanism_value = has_mechanism
        self.target_error = target_error
        self.destroy_rv = destroy_rv
        self.wrap_error = wrap_error
        self.generate_calls: list[tuple[int, int, dict[Any, Any]]] = []
        self.destroy_calls: list[tuple[int, int]] = []
        self.quiet_destroy_calls: list[tuple[int, int]] = []
        self.wrap_calls: list[tuple[int, int, int, int, int]] = []
        self.output_before_call: bytes | None = None
        self.operation_at_call: str | None = None
        self.claimed_op_at_call: str | None = None
        self.events: list[str] = []
        self._next_handle = 41
        self.raw = SimpleNamespace(
            C_DestroyObject=self._destroy_object,
            C_WrapKey=self._wrap_key,
        )
        self.session = SimpleNamespace(
            raw=self.raw,
            sh=7,
            has_mechanism=lambda _name: self.has_mechanism_value,
        )

    def generate_key(
        self,
        _raw: Any,
        _session: int,
        bits: int,
        *,
        attrs: dict[Any, Any],
    ) -> int:
        self.events.append("generate")
        self.generate_calls.append((bits, len(self.generate_calls), dict(attrs)))
        if len(self.generate_calls) == 2 and self.target_error is not None:
            raise self.target_error
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def _destroy_object(self, session: int, handle: int) -> int:
        self.events.append("destroy")
        self.destroy_calls.append((session, handle))
        return self.destroy_rv if len(self.destroy_calls) == 1 else int(CKR_OK)

    def quiet_destroy(self, _raw: Any, session: int, handle: int) -> None:
        self.events.append("quiet-destroy")
        self.quiet_destroy_calls.append((session, handle))

    def _wrap_key(
        self,
        session: int,
        mechanism: Any,
        wrapping_key: int,
        target: int,
        output: Any,
        output_len: Any,
    ) -> int:
        self.operation_at_call = classification.current_operation()
        self.claimed_op_at_call = classification.current_claimed_op()
        assert self.operation_at_call == "C_WrapKey"
        assert self.claimed_op_at_call is None
        self.events.append("wrap")
        mechanism_value = int(mechanism._obj.mechanism)
        params_value = int(mechanism._obj.ulParameterLen)
        output_len_value = int(output_len._obj.value)
        self.wrap_calls.append((session, wrapping_key, target, mechanism_value, output_len_value))
        self.output_before_call = bytes(output)
        assert mechanism._obj.pParameter is None
        assert params_value == 0
        assert len(output) == 256
        if self.wrap_error is not None:
            raise self.wrap_error
        return self.wrap_rv


def _run_stale_wrap_oracle(monkeypatch: pytest.MonkeyPatch, fake: _WrapKeyFake) -> None:
    monkeypatch.setattr(tcw, "gen_aes_key", fake.generate_key)
    monkeypatch.setattr(tcw, "destroy_quietly", fake.quiet_destroy)
    tcw.TestWrapKeyErrors().test_wrapping_key_handle_invalid(fake.session, False)


def test_stale_wrap_oracle_uses_valid_setup_and_current_raw_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _WrapKeyFake()

    _run_stale_wrap_oracle(monkeypatch, fake)

    assert fake.generate_calls == [
        (256, 0, {CKA_WRAP: True}),
        (128, 1, {CKA_EXTRACTABLE: True, CKA_SENSITIVE: False}),
    ]
    assert fake.destroy_calls == [(7, 41)]
    assert fake.quiet_destroy_calls == [(7, 42)]
    assert fake.events == ["generate", "generate", "destroy", "wrap", "quiet-destroy"]
    assert fake.wrap_calls == [(7, 41, 42, int(CKM_AES_KEY_WRAP), 256)]
    assert fake.output_before_call == b"\x00" * 256
    assert fake.operation_at_call == "C_WrapKey"
    assert fake.claimed_op_at_call is None
    assert classification.current_operation() == "C_WrapKey"
    assert classification.current_claimed_op() is None


@pytest.mark.parametrize(
    ("rv", "outcome"),
    (
        (int(CKR_WRAPPING_KEY_HANDLE_INVALID), "pass"),
        (int(CKR_KEY_HANDLE_INVALID), "xfail"),
        (int(CKR_OBJECT_HANDLE_INVALID), "xfail"),
        (int(CKR_FUNCTION_FAILED), "xfail"),
        (0x80000001, "xfail"),
        (0x12345678, "fail"),
        (int(CKR_OK), "fail"),
    ),
)
def test_stale_wrap_oracle_classifies_every_raw_rv(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    outcome: str,
) -> None:
    fake = _WrapKeyFake(wrap_rv=rv)
    classification.set_mechanism("CKM_FOREIGN", "C_Foreign", expect_success=True)

    if outcome == "pass":
        _run_stale_wrap_oracle(monkeypatch, fake)
    elif outcome == "xfail":
        with pytest.raises(XFailed):
            _run_stale_wrap_oracle(monkeypatch, fake)
    else:
        with pytest.raises(Failed):
            _run_stale_wrap_oracle(monkeypatch, fake)

    assert fake.wrap_calls == [(7, 41, 42, int(CKM_AES_KEY_WRAP), 256)]
    assert fake.operation_at_call == "C_WrapKey"
    assert fake.claimed_op_at_call is None
    assert fake.quiet_destroy_calls == [(7, 42)]
    assert classification.current_operation() == "C_WrapKey"
    assert classification.current_claimed_op() is None
    if outcome == "pass":
        assert classification.get_records() == []
    else:
        record = classification.get_records()[-1]
        assert record.label == "C_WrapKey:stale-wrap-key-handle"
        assert record.operation == "C_WrapKey"
        assert record.mechanism == "CKM_AES_KEY_WRAP"
        if rv != int(CKR_OK):
            assert record.actual_ckr == ckr_name(rv)
            assert record.expected_ckr == ["CKR_WRAPPING_KEY_HANDLE_INVALID"]
        if outcome == "xfail":
            assert record.reason == "nonspec_reject"
            assert record.kind == "lifecycle"
        elif rv == int(CKR_OK):
            assert record.reason == "self_contradiction"
            assert record.kind == "lifecycle"
        else:
            assert record.reason == "self_contradiction"
            assert record.kind == "metadata"


def test_stale_wrap_oracle_skips_before_setup_when_mechanism_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _WrapKeyFake(has_mechanism=False)

    with pytest.raises(pytest.skip.Exception):
        _run_stale_wrap_oracle(monkeypatch, fake)

    assert fake.generate_calls == []
    assert fake.destroy_calls == []
    assert fake.wrap_calls == []


def test_stale_wrap_oracle_cleans_owned_wrap_key_when_target_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("target setup failed")
    fake = _WrapKeyFake(target_error=error)

    with pytest.raises(RuntimeError, match="target setup failed") as exc_info:
        _run_stale_wrap_oracle(monkeypatch, fake)

    assert exc_info.value is error
    assert fake.destroy_calls == []
    assert fake.quiet_destroy_calls == [(7, 41)]
    assert fake.wrap_calls == []


def test_stale_wrap_oracle_cleans_owned_handles_on_initial_destroy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _WrapKeyFake(destroy_rv=int(CKR_GENERAL_ERROR))

    with pytest.raises(AssertionError, match="CKR=0x00000005"):
        _run_stale_wrap_oracle(monkeypatch, fake)

    assert fake.destroy_calls == [(7, 41)]
    assert sorted(fake.quiet_destroy_calls) == [(7, 41), (7, 42)]
    assert fake.wrap_calls == []


def test_stale_wrap_oracle_preserves_raw_wrap_exception_and_cleans_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("raw wrap failed")
    fake = _WrapKeyFake(wrap_error=error)

    with pytest.raises(RuntimeError, match="raw wrap failed") as exc_info:
        _run_stale_wrap_oracle(monkeypatch, fake)

    assert exc_info.value is error
    assert fake.destroy_calls == [(7, 41)]
    assert fake.quiet_destroy_calls == [(7, 42)]
    assert fake.wrap_calls == [(7, 41, 42, int(CKM_AES_KEY_WRAP), 256)]

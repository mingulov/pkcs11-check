"""Regression tests for single-part operation termination checks."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OK, CKR_OPERATION_ACTIVE
from pkcs11_check.testcases import test_mech_state


class _DigestLeavesActiveRaw:
    def __init__(self) -> None:
        self.active = False

    def C_DigestInit(self, _session: int, _mech: Any) -> int:  # noqa: N802
        if self.active:
            return CKR_OPERATION_ACTIVE
        self.active = True
        return CKR_OK

    def C_Digest(  # noqa: N802
        self,
        _session: int,
        _data: Any,
        _data_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        if out is None:
            out_len._obj.value = 32
            return CKR_OK
        out_len._obj.value = 32
        return CKR_OK

    def C_DigestFinal(self, *_args: Any) -> int:  # noqa: N802
        self.active = False
        return CKR_OK


class _SignLeavesActiveRaw:
    def __init__(self) -> None:
        self.active = False

    def C_SignInit(self, _session: int, _mech: Any, _key: int) -> int:  # noqa: N802
        if self.active:
            return CKR_OPERATION_ACTIVE
        self.active = True
        return CKR_OK

    def C_Sign(  # noqa: N802
        self,
        _session: int,
        _data: Any,
        _data_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        if out is None:
            out_len._obj.value = 32
            return CKR_OK
        out_len._obj.value = 32
        return CKR_OK

    def C_SignFinal(self, *_args: Any) -> int:  # noqa: N802
        self.active = False
        return CKR_OK


def _session(raw: Any) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)


def test_digest_termination_check_fails_when_single_part_call_leaves_state_active() -> None:
    with pytest.raises(AssertionError, match="successful C_Digest"):
        test_mech_state.TestDigestState().test_digest_single_part_output_call_terminates(
            _session(_DigestLeavesActiveRaw())
        )


def test_sign_termination_check_fails_when_single_part_call_leaves_state_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_mech_state, "import_secret_key", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(test_mech_state, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="successful C_Sign"):
        test_mech_state.TestSignState().test_sign_single_part_output_call_terminates(
            _session(_SignLeavesActiveRaw())
        )

"""Meta-tests for the SO-login helper: PIN resolution, lockout gate, rejection cache."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from pkcs11_check.raw.types_std import (
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
)
from pkcs11_check.testcases import _so_login


class _FakeRaw:
    """Serves C_GetTokenInfo flags; records C_Login calls."""

    def __init__(self, *, token_flags: int = 0, info_rv: int = int(CKR_OK)) -> None:
        self.token_flags = token_flags
        self.info_rv = info_rv
        self.info_calls = 0

    def C_GetTokenInfo(self, _slot_id: int, info_ref: Any) -> int:  # noqa: N802
        self.info_calls += 1
        info_ref._obj.flags = self.token_flags
        return self.info_rv


def _cfg(*, so_pin: str | None = None, pin: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        so_pin=SecretStr(so_pin) if so_pin is not None else None,
        pin=SecretStr(pin) if pin is not None else None,
    )


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_so_login, "_SO_PIN_REJECTED", False)


class TestResolveSoPin:
    def test_explicit_so_pin_wins(self) -> None:
        assert _so_login.resolve_so_pin(_cfg(so_pin="so123", pin="u456")) == (b"so123", True)

    def test_falls_back_to_user_pin_guess(self) -> None:
        assert _so_login.resolve_so_pin(_cfg(pin="u456")) == (b"u456", False)

    def test_none_when_no_pins(self) -> None:
        assert _so_login.resolve_so_pin(_cfg()) == (None, False)

    def test_config_without_so_pin_attr_falls_back(self) -> None:
        cfg = SimpleNamespace(pin=SecretStr("u456"))
        assert _so_login.resolve_so_pin(cfg) == (b"u456", False)


class TestGuardSoLockout:
    @pytest.mark.parametrize("explicit", [True, False])
    def test_locked_always_skips(self, explicit: bool) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_LOCKED))
        with pytest.raises(pytest.skip.Exception, match="CKF_SO_PIN_LOCKED"):
            _so_login.guard_so_lockout(raw, 0, explicit=explicit)

    @pytest.mark.parametrize("explicit", [True, False])
    def test_final_try_always_skips(self, explicit: bool) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_FINAL_TRY))
        with pytest.raises(pytest.skip.Exception, match="CKF_SO_PIN_FINAL_TRY"):
            _so_login.guard_so_lockout(raw, 0, explicit=explicit)

    def test_count_low_skips_the_guess(self) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_COUNT_LOW))
        with pytest.raises(pytest.skip.Exception, match="CKF_SO_PIN_COUNT_LOW"):
            _so_login.guard_so_lockout(raw, 0, explicit=False)

    def test_count_low_lets_explicit_proceed(self) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_COUNT_LOW))
        _so_login.guard_so_lockout(raw, 0, explicit=True)  # no skip

    def test_count_low_skips_explicit_when_pristine_required(self) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_COUNT_LOW))
        with pytest.raises(pytest.skip.Exception, match="CKF_SO_PIN_COUNT_LOW"):
            _so_login.guard_so_lockout(raw, 0, explicit=True, require_pristine=True)

    def test_clean_flags_proceed(self) -> None:
        _so_login.guard_so_lockout(_FakeRaw(token_flags=0), 0, explicit=False)  # no skip

    def test_token_info_error_does_not_gate(self) -> None:
        raw = _FakeRaw(token_flags=int(CKF_SO_PIN_LOCKED), info_rv=int(CKR_GENERAL_ERROR))
        _so_login.guard_so_lockout(raw, 0, explicit=False)  # gate is a safety net only

    def test_rejection_cache_short_circuits_before_token_info(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_so_login, "_SO_PIN_REJECTED", True)
        raw = _FakeRaw()
        with pytest.raises(pytest.skip.Exception, match="already rejected"):
            _so_login.guard_so_lockout(raw, 0, explicit=True)
        assert raw.info_calls == 0


class TestSkipIfSoPinRejected:
    def test_ok_rv_is_a_no_op(self) -> None:
        _so_login.skip_if_so_pin_rejected(int(CKR_OK), explicit=True)
        assert _so_login._SO_PIN_REJECTED is False

    def test_guess_rejection_keeps_historical_message(self) -> None:
        with pytest.raises(pytest.skip.Exception, match="SO PIN differs from user PIN"):
            _so_login.skip_if_so_pin_rejected(int(CKR_PIN_INCORRECT), explicit=False)
        assert _so_login._SO_PIN_REJECTED is True

    def test_explicit_rejection_names_the_config_knob(self) -> None:
        with pytest.raises(pytest.skip.Exception, match="configured SO PIN rejected"):
            _so_login.skip_if_so_pin_rejected(int(CKR_PIN_INCORRECT), explicit=True)
        assert _so_login._SO_PIN_REJECTED is True

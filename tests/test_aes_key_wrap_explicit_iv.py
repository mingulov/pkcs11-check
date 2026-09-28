"""Pins for the AES-KW explicit-IV matrix row.

``test_aes_key_wrap_explicit_iv_roundtrip`` must wrap once with NULL params
(default IV) and once with an explicit 8-byte IV, prove the IV is honored
(distinct blobs), roundtrip the explicit-IV blob, and prove the negative
control (unwrap explicit blob with the default IV fails). These tests drive
the real node with stubbed recipes and decode the captured mechanism params.
"""

from __future__ import annotations

import ctypes
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_WRAPPED_KEY_INVALID
from pkcs11_check.testcases import test_mech_wrap as wrap

_IV = b"\x01\x02\x03\x04\x05\x06\x07\x08"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def _packed_bytes(mech_param: Any) -> bytes | None:
    """Decode raw-bytes mechanism params (None for NULL)."""
    if mech_param is None:
        return None
    return bytes(ctypes.string_at(mech_param.ck.pParameter, mech_param.ck.ulParameterLen))


def _stub_key_setup(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub key setup/cipher/destroy; return the capture dict."""
    captured: dict[str, Any] = {"destroyed": []}
    handles = iter([11, 12])
    monkeypatch.setattr(wrap, "gen_aes_key", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(wrap, "encrypt_single", lambda *_a, **_k: b"C" * 16)
    monkeypatch.setattr(wrap, "decrypt_single", lambda *_a, **_k: b"\x5a\xa5\x5a\xa5" * 4)
    monkeypatch.setattr(wrap, "destroy_quietly", lambda _r, _s, h: captured["destroyed"].append(h))
    return captured


def test_explicit_iv_row_sends_both_param_shapes_and_roundtrips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The node wraps with NULL then the explicit IV, unwraps the explicit
    blob with the explicit IV, and the negative control (default-IV unwrap
    of the explicit blob) is rejected."""
    _stub_key_setup(monkeypatch)
    wrap_params: list[Any] = []
    unwrap_params: list[Any] = []

    def _wrap(*args: Any, **kwargs: Any) -> bytes:
        wrap_params.append(kwargs.get("mech_param"))
        return b"D" * 24 if len(wrap_params) == 1 else b"E" * 24

    def _unwrap(*args: Any, **kwargs: Any) -> int:
        unwrap_params.append(kwargs.get("mech_param"))
        if kwargs.get("mech_param") is None:
            raise CkrAssertionError("unwrap rejected", int(CKR_WRAPPED_KEY_INVALID))
        return 13

    monkeypatch.setattr(wrap, "wrap_key", _wrap)
    monkeypatch.setattr(wrap, "unwrap_key_for_mechanism_roundtrip", _unwrap)

    wrap.TestMechWrapRoundtrip().test_aes_key_wrap_explicit_iv_roundtrip(_rs(), object())

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(wrap_params) == 2
    assert _packed_bytes(wrap_params[0]) is None
    assert _packed_bytes(wrap_params[1]) == _IV
    assert len(unwrap_params) == 2
    assert _packed_bytes(unwrap_params[0]) == _IV
    assert _packed_bytes(unwrap_params[1]) is None


def test_explicit_iv_row_fails_when_iv_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical blobs for default-IV and explicit-IV wraps fail the node:
    the module ignored the IV."""
    _stub_key_setup(monkeypatch)
    monkeypatch.setattr(wrap, "wrap_key", lambda *_a, **_k: b"D" * 24)
    monkeypatch.setattr(wrap, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 13)

    with pytest.raises(AssertionError, match="ignored the explicit IV"):
        wrap.TestMechWrapRoundtrip().test_aes_key_wrap_explicit_iv_roundtrip(_rs(), object())


def test_explicit_iv_row_fails_when_control_unwraps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit-IV blob that unwraps under the default IV fails
    accepted_invalid: integrity binding is broken."""
    _stub_key_setup(monkeypatch)
    calls = iter([b"D" * 24, b"E" * 24])
    monkeypatch.setattr(wrap, "wrap_key", lambda *_a, **_k: next(calls))
    monkeypatch.setattr(wrap, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 13)

    with pytest.raises(pytest.fail.Exception):
        wrap.TestMechWrapRoundtrip().test_aes_key_wrap_explicit_iv_roundtrip(_rs(), object())

    (rec,) = C.get_records()
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"

"""Pins for SLH-DSA sigVer context handling (P11C-003, F17).

The SLH-DSA sigVer loader must carry each vector's ``context`` bytes and the
sigVer test must pass non-empty context via ``mech_sign_context``
(CK_SIGN_ADDITIONAL_CONTEXT), keeping NULL params for pure vectors -- exact
ML-DSA parity with ``test_acvp_mldsa.py`` (same conditional shape, same
helper).
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.types_std import CK_SIGN_ADDITIONAL_CONTEXT
from pkcs11_check.testcases.acvp import test_acvp_slhdsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SLH_DSA",
        has_mechanism_flag=lambda _m, _f: True,
    )


def _fake_sigver_vectors() -> list[dict[str, Any]]:
    """Synthetic ``load_acvp_vectors`` rows: context present/empty/absent."""
    group = {"parameterSet": "SLH-DSA-SHA2-128f"}
    expected = {"testPassed": True}
    rows = [
        ("aa55", 101),  # non-empty context
        ("", 102),  # explicit empty context
        (None, 103),  # pure vector: no context key at all
    ]
    vectors = []
    for context, tc_id in rows:
        test: dict[str, Any] = {
            "tcId": tc_id,
            "pk": "aa" * 32,
            "message": "bb" * 16,
            "signature": "cc" * 64,
        }
        if context is not None:
            test["context"] = context
        vectors.append({"input": test, "expected": expected, "group": group})
    return vectors


def test_sigver_loader_carries_context_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loader pins context bytes per vector; ML-DSA parity (``ctx_bytes`` shape)."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_sigver_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_sigver_vectors())
    assert loaded["sigVer-SLH-DSA-SHA2-128f-tc101"]["context"] == bytes.fromhex("aa55")
    assert loaded["sigVer-SLH-DSA-SHA2-128f-tc102"]["context"] == b""
    assert loaded["sigVer-SLH-DSA-SHA2-128f-tc103"]["context"] == b""


def _sigver_vec(context: Any) -> dict[str, Any]:
    vec: dict[str, Any] = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "pk": b"public",
        "msg": b"message",
        "sig": b"signature",
        "expected_pass": True,
    }
    if context is not ...:
        vec["context"] = context
    return vec


def _run_sigver(monkeypatch: pytest.MonkeyPatch, vec: dict[str, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _capture(*_args: Any, **_kwargs: Any) -> bool:
        captured.update(_kwargs)
        return True

    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _capture)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)
    test_acvp_slhdsa.test_slhdsa_sigver(_session(), "sigVer-pin-tc1", vec)
    return captured


def _packed_context(mech_param: PackedMechanism) -> bytes:
    params = mech_param.params
    assert isinstance(params, CK_SIGN_ADDITIONAL_CONTEXT)
    assert params.pContext is not None
    return ctypes.string_at(params.pContext, params.ulContextLen)


def test_sigver_nonempty_context_selects_mech_sign_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-empty context packs via mech_sign_context; ML-DSA parity (same helper)."""
    captured = _run_sigver(monkeypatch, _sigver_vec(b"\xaa\x55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == b"\xaa\x55"


def test_sigver_hex_str_context_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hex-str context normalizes to bytes; ML-DSA parity (same conditional shape)."""
    captured = _run_sigver(monkeypatch, _sigver_vec("aa55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == bytes.fromhex("aa55")


@pytest.mark.parametrize("context", [b"", ...], ids=["empty-bytes", "missing-key"])
def test_sigver_pure_vector_keeps_null_params(
    monkeypatch: pytest.MonkeyPatch, context: Any
) -> None:
    """Empty/missing context keeps NULL params; ML-DSA parity (``if context`` guard)."""
    captured = _run_sigver(monkeypatch, _sigver_vec(context))
    assert captured.get("mech_param") is None

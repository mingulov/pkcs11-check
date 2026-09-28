"""Pins for SLH-DSA sigGen context handling (NULL-matrix row).

The SLH-DSA sigGen loader must carry each vector's ``context`` bytes, take
every pure vector (both context shapes stay covered as a consequence), and
skip preHash groups (their messages are digests for the hash-sign mechanisms,
not pure ``CKM_SLH_DSA`` inputs). The sigGen test must pass non-empty context
via ``mech_sign_context`` (CK_SIGN_ADDITIONAL_CONTEXT), keeping NULL params
for pure vectors -- exact sigVer parity (same conditional shape, same helper).
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


def _fake_siggen_vectors() -> list[dict[str, Any]]:
    """Synthetic ``load_acvp_vectors`` rows: mixed shapes plus a preHash group."""
    vectors = []
    # Mixed set: two non-empty rows, then an empty-context row.
    group = {"parameterSet": "SLH-DSA-SHA2-128f", "preHash": "pure"}
    for context, tc_id in (("aa55", 101), ("bb66", 102), ("", 103)):
        vectors.append(
            {
                "input": {
                    "tcId": tc_id,
                    "sk": "aa" * 64,
                    "message": "bb" * 16,
                    "context": context,
                },
                "group": group,
            }
        )
    # Uniform set: every row carries a non-empty context.
    group = {"parameterSet": "SLH-DSA-SHA2-128s", "preHash": "pure"}
    for tc_id in (201, 202):
        vectors.append(
            {
                "input": {
                    "tcId": tc_id,
                    "sk": "aa" * 64,
                    "message": "bb" * 16,
                    "context": "cc77",
                },
                "group": group,
            }
        )
    # PreHash group first in file order: must be skipped outright.
    vectors.append(
        {
            "input": {
                "tcId": 301,
                "sk": "aa" * 64,
                "message": "bb" * 16,
                "context": "dd88",
            },
            "group": {"parameterSet": "SLH-DSA-SHA2-192f", "preHash": "preHash"},
        }
    )
    vectors.append(
        {
            "input": {
                "tcId": 302,
                "sk": "aa" * 64,
                "message": "bb" * 16,
            },
            "group": {"parameterSet": "SLH-DSA-SHA2-192f", "preHash": "pure"},
        }
    )
    return vectors


def test_siggen_loader_carries_context_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loader pins context bytes per vector; sigVer parity (``ctx_bytes`` shape)."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc101"]["context"] == bytes.fromhex("aa55")
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc103"]["context"] == b""


def test_siggen_loader_takes_all_pure_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """No per-set sampling: every pure vector loads, so both context shapes
    (NULL and explicit parameters) stay covered for every parameter set."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert "sigGen-SLH-DSA-SHA2-128f-tc101" in loaded
    assert "sigGen-SLH-DSA-SHA2-128f-tc102" in loaded
    assert "sigGen-SLH-DSA-SHA2-128f-tc103" in loaded
    assert "sigGen-SLH-DSA-SHA2-128s-tc201" in loaded
    assert "sigGen-SLH-DSA-SHA2-128s-tc202" in loaded
    contexts_128f = {
        loaded[f"sigGen-SLH-DSA-SHA2-128f-tc{tc}"]["context"] for tc in (101, 102, 103)
    }
    assert contexts_128f == {bytes.fromhex("aa55"), bytes.fromhex("bb66"), b""}


def test_siggen_loader_skips_pre_hash_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """PreHash groups are skipped: their messages are digests for the
    hash-sign mechanisms, not pure CKM_SLH_DSA inputs."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert "sigGen-SLH-DSA-SHA2-192f-tc301" not in loaded
    assert "sigGen-SLH-DSA-SHA2-192f-tc302" in loaded
    assert loaded["sigGen-SLH-DSA-SHA2-192f-tc302"]["context"] == b""


def _siggen_vec(context: Any) -> dict[str, Any]:
    vec: dict[str, Any] = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "sk": b"secret",
        "msg": b"message",
        "tc_id": 1,
    }
    if context is not ...:
        vec["context"] = context
    return vec


def _run_siggen(monkeypatch: pytest.MonkeyPatch, vec: dict[str, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def _capture(*_args: Any, **_kwargs: Any) -> bytes:
        captured.update(_kwargs)
        return b"fake-signature"

    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _capture)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)
    test_acvp_slhdsa.test_slhdsa_siggen(_session(), "sigGen-pin-tc1", vec)
    return captured


def _packed_context(mech_param: PackedMechanism) -> bytes:
    params = mech_param.params
    assert isinstance(params, CK_SIGN_ADDITIONAL_CONTEXT)
    assert params.pContext is not None
    return ctypes.string_at(params.pContext, params.ulContextLen)


def test_siggen_nonempty_context_selects_mech_sign_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-empty context packs via mech_sign_context; sigVer parity (same helper)."""
    captured = _run_siggen(monkeypatch, _siggen_vec(b"\xaa\x55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == b"\xaa\x55"


def test_siggen_hex_str_context_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hex-str context normalizes to bytes; sigVer parity (same conditional shape)."""
    captured = _run_siggen(monkeypatch, _siggen_vec("aa55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == bytes.fromhex("aa55")


@pytest.mark.parametrize("context", [b"", ...], ids=["empty-bytes", "missing-key"])
def test_siggen_pure_vector_keeps_null_params(
    monkeypatch: pytest.MonkeyPatch, context: Any
) -> None:
    """Empty/missing context keeps NULL params; sigVer parity (``if context`` guard)."""
    captured = _run_siggen(monkeypatch, _siggen_vec(context))
    assert captured.get("mech_param") is None

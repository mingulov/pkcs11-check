"""Regression tests for WTLS protocol-KDF coverage."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.pack import mech_wtls_prf
from pkcs11_check.raw.types_std import CK_ULONG, CKM_SHA256, CKM_WTLS_PRF, CKR_OK
from pkcs11_check.testcases import test_wtls


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_wtls_prf_helper_uses_output_buffer_and_null_key_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packed = mech_wtls_prf(
        CKM_WTLS_PRF,
        digest_mechanism=CKM_SHA256,
        seed=b"seed",
        label=b"label",
        output_len=8,
    )
    calls: list[tuple[int, object, int, object, int, object]] = []

    class Raw:
        def C_DeriveKey(  # noqa: N802 - mirrors the PKCS#11 entry point name.
            self,
            session: int,
            mechanism: object,
            base_key: int,
            template: object,
            attribute_count: int,
            new_key: object,
        ) -> int:
            calls.append((session, mechanism, base_key, template, attribute_count, new_key))
            ctypes.memmove(packed.params.pOutput, b"abc", 3)
            output_len = ctypes.cast(
                packed.params.pulOutputLen, ctypes.POINTER(CK_ULONG)
            )
            output_len[0] = 3
            return int(CKR_OK)

    monkeypatch.setattr(test_wtls, "mech_wtls_prf", lambda *_args, **_kwargs: packed)

    result = test_wtls._derive_wtls_prf_output(
        SimpleNamespace(raw=Raw(), sh=42),
        7,
        seed=b"seed",
        label=b"label",
        output_len=8,
    )

    assert result == b"abc"
    assert len(calls) == 1
    assert calls[0][0] == 42
    assert calls[0][2] == 7
    assert calls[0][3] is None
    assert calls[0][4] == 0
    assert calls[0][5] is None


def test_wtls_prf_seed_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        test_wtls,
        "_derive_wtls_prf_output",
        lambda *_args, **_kwargs: b"same-prf-output!",
    )
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("WTLS_PRF")
    with pytest.raises(AssertionError, match="WTLS PRF seed"):
        test_wtls.TestWTLSPRF().test_prf_seed_affects_output(rs)


def test_wtls_prf_label_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        test_wtls,
        "_derive_wtls_prf_output",
        lambda *_args, **_kwargs: b"same-prf-output!",
    )
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("WTLS_PRF")
    with pytest.raises(AssertionError, match="WTLS PRF label"):
        test_wtls.TestWTLSPRF().test_prf_label_affects_output(rs)

"""Operational EC consumers pass explicit curves to provider-point recovery."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.testcases import test_crossverify, test_interop


def test_crossverify_export_uses_curve_aware_provider_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    curve = ec.SECP256R1()
    public_key = ec.generate_private_key(curve).public_key()
    calls: list[tuple[int, ec.EllipticCurve]] = []

    def _read(_rs: Any, handle: int, selected: ec.EllipticCurve, **_kw: Any):
        calls.append((handle, selected))
        return public_key

    monkeypatch.setattr(test_crossverify, "read_ec_public_key_or_xfail", _read)

    result = test_crossverify.TestECDSACrossVerify()._export_ec_pubkey(
        SimpleNamespace(raw=object(), sh=1), 7, curve
    )

    assert result is public_key
    assert calls == [(7, curve)]


def test_interop_export_normalizes_with_explicit_curve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    curve = ec.SECP384R1()
    public_key = ec.generate_private_key(curve).public_key()
    calls: list[tuple[int, ec.EllipticCurve]] = []

    def _read(_rs: Any, handle: int, selected: ec.EllipticCurve, **_kw: Any):
        calls.append((handle, selected))
        return public_key

    monkeypatch.setattr(test_interop, "read_ec_public_key_or_xfail", _read)

    point = test_interop.TestECDSAInterop._extract_ec_point_bytes(
        SimpleNamespace(raw=object(), sh=1), 9, curve
    )

    assert calls == [(9, curve)]
    assert point == public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

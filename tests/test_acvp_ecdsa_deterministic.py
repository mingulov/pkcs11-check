"""Regression tests for deterministic ACVP ECDSA applicability."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_ECDSA_SHA256
from pkcs11_check.testcases.acvp import test_acvp_ecdsa as ecdsa


class _Session:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDSA_SHA256"


def test_deterministic_ecdsa_siggen_skips_standard_pkcs11_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RFC6979 ACVP vectors are not applicable to standard random PKCS#11 ECDSA."""

    def fail_if_reached(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("key generation should not run for deterministic ECDSA")

    monkeypatch.setattr(ecdsa, "gen_ec_keypair", fail_if_reached)

    vec: dict[str, Any] = {
        "curve": "P-256",
        "ec_params": b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        "mech_name": "ECDSA_SHA256",
        "mech_int": CKM_ECDSA_SHA256,
        "msg": b"message",
    }

    with pytest.raises(pytest.skip.Exception, match="Deterministic ECDSA ACVP"):
        ecdsa.TestDetEcdsa().test_det_ecdsa_siggen(_Session(), "DetECDSA-tc1", vec)

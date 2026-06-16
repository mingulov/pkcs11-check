"""test_ec_curves uses skip_unless_capability for CKM_ECDSA sign."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.testcases import test_ec_curves as mod


def test_ecdsa_test_skips_when_ecdsa_not_in_range(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []

    def _skip_unless(rs: Any, mechanism: int, **kw: Any) -> None:
        calls.append((mechanism, kw))
        pytest.skip("gated")

    monkeypatch.setattr(mod, "skip_unless_capability", _skip_unless)
    rs = SimpleNamespace(raw=object(), sh=1, slot_id=0, has_mechanism=lambda _n: True)

    with pytest.raises(pytest.skip.Exception):
        mod.TestECDSACrossVerify().test_ecdsa_sign_p11_verify_crypto(
            rs, "secp256r1", 32, ec.SECP256R1(), hashes.SHA256()
        )
    assert calls and calls[0][1].get("operation") is not None

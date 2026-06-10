"""Meta-tests: SigVer canonical probe is three-state, not bool.

bool collapsed canonical STAGING failure (public-key import refused) into
"not operational", which would let the vacuous-reject downgrade fire with no
mechanism evidence. Three-state: import failure -> INCONCLUSIVE; canonical
verify refusal/False -> NOT_OPERATIONAL; verify True -> OPERATIONAL.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases._operability import Operability, reset_operability_cache
from pkcs11_check.testcases.acvp import test_acvp_rsa as mod


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _wire(monkeypatch: pytest.MonkeyPatch, *, import_key: Any, verify: Any) -> None:
    monkeypatch.setattr(mod, "import_rsa_public_key_negotiated", import_key)
    monkeypatch.setattr(mod, "verify_single", verify)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *a, **k: None)
    # one canonical valid vector for the probe to find
    monkeypatch.setattr(
        mod,
        "_PKCS15_VER",
        [
            (
                "canon",
                {
                    "mech_name": "SHA1_RSA_PKCS",
                    "mech_int": 6,
                    "expected_pass": True,
                    "n": b"\x01" * 256,
                    "e": b"\x01\x00\x01",
                    "message": b"m",
                    "signature": b"s",
                },
            )
        ],
    )


def test_import_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    _wire(monkeypatch, import_key=refuse_import, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.INCONCLUSIVE


def test_verify_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_verify(*_a: Any, **_k: Any) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=refuse_verify)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.NOT_OPERATIONAL


def test_verify_true_is_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.OPERATIONAL


def test_no_canonical_vector_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=lambda *a, **k: True)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA256_RSA_PKCS", 4096)
    assert result.status is Operability.INCONCLUSIVE

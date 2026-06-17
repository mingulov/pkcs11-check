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


def test_plain_assertion_error_from_verify_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain AssertionError (harness bug) from verify_single must propagate, not be cached."""

    def buggy_verify(*_a: Any, **_k: Any) -> bool:
        raise AssertionError("harness bug: not a CKR error")

    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=buggy_verify)
    with pytest.raises(AssertionError, match="harness bug"):
        mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    # Must not be cached as any verdict
    from pkcs11_check.testcases._operability import _CACHE

    assert not any("SHA1_RSA_PKCS" in k for k in _CACHE)


def test_verify_false_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_single returning False -> NOT_OPERATIONAL."""
    _wire(monkeypatch, import_key=lambda *a, **k: 7, verify=lambda *a, **k: False)
    result = mod._pkcs15_sigver_operability(_rs(), "SHA1_RSA_PKCS", 2048)
    assert result.status is Operability.NOT_OPERATIONAL


def test_different_key_bits_produce_distinct_cache_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix 2 mirror: key_bits is part of the SigVer probe cache key; two calls
    with the same mech_name but different key_bits must each run the probe once
    and produce independent cache entries.  A dropped ``:{key_bits}`` suffix
    would collapse both calls onto the same key so the second call silently
    returns the first result (cross-contamination of verdicts across key sizes).
    """
    call_count = 0

    def counting_import(*_a: Any, **_k: Any) -> int:
        nonlocal call_count
        call_count += 1
        return 7

    # Provide canonical vectors for both 2048 and 4096
    monkeypatch.setattr(mod, "verify_single", lambda *a, **k: True)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(mod, "import_rsa_public_key_negotiated", counting_import)
    monkeypatch.setattr(
        mod,
        "_PKCS15_VER",
        [
            (
                "canon-2048",
                {
                    "mech_name": "SHA1_RSA_PKCS",
                    "mech_int": 6,
                    "expected_pass": True,
                    "n": b"\x01" * 256,  # 256 bytes = 2048 bits
                    "e": b"\x01\x00\x01",
                    "message": b"m",
                    "signature": b"s",
                },
            ),
            (
                "canon-4096",
                {
                    "mech_name": "SHA1_RSA_PKCS",
                    "mech_int": 6,
                    "expected_pass": True,
                    "n": b"\x01" * 512,  # 512 bytes = 4096 bits
                    "e": b"\x01\x00\x01",
                    "message": b"m",
                    "signature": b"s",
                },
            ),
        ],
    )

    rs = _rs()
    # First call: 2048-bit
    r1 = mod._pkcs15_sigver_operability(rs, "SHA1_RSA_PKCS", 2048)
    # Second call: same mech, different key size
    r2 = mod._pkcs15_sigver_operability(rs, "SHA1_RSA_PKCS", 4096)

    assert r1.status is Operability.OPERATIONAL
    assert r2.status is Operability.OPERATIONAL
    # The probe (key import) must have run exactly twice — once per key size
    assert call_count == 2, (
        f"expected 2 probe runs (one per key_bits), got {call_count}; "
        "key_bits is likely missing from the cache key"
    )

    from pkcs11_check.testcases._operability import _CACHE

    sha1_keys = [k for k in _CACHE if "SHA1_RSA_PKCS" in k]
    assert len(sha1_keys) == 2, f"expected 2 cache entries, got: {sha1_keys}"

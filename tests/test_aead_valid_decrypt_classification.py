"""Meta-tests: valid GCM/CCM decrypt vectors classify clean refusals as XFAIL.

For valid-tag decrypt vectors, any defined standard/vendor clean refusal --
including clean authentication-error CKRs -- is failure-like XFAIL. Only
``CKR_OK`` with wrong output is FAIL. Undefined CK_RV is always FAIL, guarded
before every ``classify_kat_clean_error`` XFAIL route including the canonical
operability probe.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_AEAD_DECRYPT_FAILED,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
    reset_operability_cache,
)
from pkcs11_check.testcases.acvp.aes import base_runner_aead as runner


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    reset_operability_cache()


class _AeadSession:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(name: str) -> bool:
        return name in ("AES_CCM", "AES_GCM")


def _gcm_valid_vec() -> dict[str, Any]:
    return {
        "key": bytes(16),
        "iv": bytes(12),
        "ct": bytes(16),
        "tag": bytes(16),
        "aad": b"",
        "pt_expected": bytes(16),
        "test_passed": True,
        "tag_len_bits": 128,
    }


def _ccm_valid_vec() -> dict[str, Any]:
    return {
        "key": bytes(16),
        "nonce": bytes(13),
        "ct": bytes(24),
        "aad": b"",
        "pt_expected": bytes(8),
        "test_passed": True,
        "tag_len": 16,
    }


def _raise_ckr(rv: int) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError(f"Unexpected CK_RV 0x{rv:08x}", rv)

    return _raise


def _operational_probe(*_args: Any, **_kwargs: Any) -> OperabilityResult:
    return OperabilityResult(Operability.OPERATIONAL, "stubbed operational probe")


def _not_operational_probe(*_args: Any, **_kwargs: Any) -> OperabilityResult:
    return OperabilityResult(Operability.NOT_OPERATIONAL, "stubbed dead probe")


@pytest.mark.parametrize(
    "rv",
    [
        int(CKR_ENCRYPTED_DATA_INVALID),
        int(CKR_AEAD_DECRYPT_FAILED),
        int(CKR_GENERAL_ERROR),
        int(CKR_MECHANISM_PARAM_INVALID),
        int(CKR_VENDOR_DEFINED),
    ],
)
def test_gcm_valid_tag_clean_refusal_on_live_mech_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    """Valid-tag GCM clean refusal (incl. tag-auth codes) is XFAIL, not FAIL."""
    monkeypatch.setattr(runner, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(runner, "decrypt_single", _raise_ckr(rv))
    monkeypatch.setattr(runner, "_aead_operability", _operational_probe)
    with pytest.raises(pytest.xfail.Exception):
        runner.run_gcm_decrypt_test(_AeadSession(), "tc-valid", _gcm_valid_vec())


@pytest.mark.parametrize(
    "rv",
    [
        int(CKR_ENCRYPTED_DATA_INVALID),
        int(CKR_AEAD_DECRYPT_FAILED),
        int(CKR_DEVICE_ERROR),
        int(CKR_GENERAL_ERROR),
        int(CKR_VENDOR_DEFINED),
    ],
)
def test_ccm_valid_tag_clean_refusal_on_live_mech_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    """Valid-tag CCM clean refusal (incl. tag-auth codes) is XFAIL, not FAIL."""
    monkeypatch.setattr(runner, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(runner, "decrypt_single", _raise_ckr(rv))
    monkeypatch.setattr(runner, "_aead_operability", _operational_probe)
    with pytest.raises(pytest.xfail.Exception):
        runner.run_ccm_decrypt_test(_AeadSession(), "tc-valid", _ccm_valid_vec())


@pytest.mark.parametrize(
    "run,vec",
    [
        (runner.run_gcm_decrypt_test, _gcm_valid_vec()),
        (runner.run_ccm_decrypt_test, _ccm_valid_vec()),
    ],
    ids=["gcm", "ccm"],
)
def test_valid_tag_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, run: Any, vec: dict[str, Any]
) -> None:
    monkeypatch.setattr(runner, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **_k: None)
    monkeypatch.setattr(runner, "decrypt_single", _raise_ckr(0x7FFFFFFF))
    monkeypatch.setattr(runner, "_aead_operability", _operational_probe)
    # NOTE: match= is load-bearing: XFailed subclasses Failed, so a bare
    # raises(Failed) would also catch the current wrong xfail.
    with pytest.raises(Failed, match="undefined CK_RV"):
        run(_AeadSession(), "tc-valid", vec)


@pytest.mark.parametrize(
    "run,vec",
    [
        (runner.run_gcm_decrypt_test, _gcm_valid_vec()),
        (runner.run_ccm_decrypt_test, _ccm_valid_vec()),
    ],
    ids=["gcm", "ccm"],
)
def test_valid_tag_ok_with_wrong_output_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, run: Any, vec: dict[str, Any]
) -> None:
    monkeypatch.setattr(runner, "import_secret_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **_k: None)
    monkeypatch.setattr(runner, "decrypt_single", lambda *_a, **_k: b"\xff")
    monkeypatch.setattr(runner, "_aead_operability", _operational_probe)
    with pytest.raises(Failed, match="does not match known answer"):
        run(_AeadSession(), "tc-valid", vec)


@pytest.mark.parametrize(
    "status",
    [Operability.OPERATIONAL, Operability.NOT_OPERATIONAL, Operability.INCONCLUSIVE],
)
def test_classify_kat_undefined_ckr_never_xfails(status: Operability) -> None:
    """The defined-or-vendor guard precedes every classify_kat_clean_error XFAIL."""
    exc = CkrAssertionError("Unexpected CK_RV 0x7fffffff", 0x7FFFFFFF)
    # NOTE: match= is load-bearing: XFailed subclasses Failed.
    with pytest.raises(Failed, match="undefined CK_RV"):
        classify_kat_clean_error(exc, result=OperabilityResult(status, "stub"), label="unit")


def test_classify_kat_defined_ckr_on_dead_mech_still_xfails() -> None:
    exc = CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        classify_kat_clean_error(
            exc,
            result=OperabilityResult(Operability.NOT_OPERATIONAL, "stub"),
            label="unit",
        )


def test_classify_kat_vendor_ckr_on_live_mech_still_xfails() -> None:
    exc = CkrAssertionError("Unexpected CK_RV vendor", int(CKR_VENDOR_DEFINED))
    with pytest.raises(pytest.xfail.Exception, match="cleanly rejected"):
        classify_kat_clean_error(
            exc,
            result=OperabilityResult(Operability.OPERATIONAL, "stub"),
            label="unit",
        )


@pytest.mark.parametrize("mech_name", ["AES_GCM", "AES_CCM"])
@pytest.mark.parametrize("direction", ["encrypt", "decrypt"])
def test_canonical_probe_undefined_ckr_never_masks(
    monkeypatch: pytest.MonkeyPatch, mech_name: str, direction: str
) -> None:
    """An undefined CK_RV from the canonical probe must not yield NOT_OPERATIONAL."""
    monkeypatch.setattr(runner, "_import_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(runner, "destroy_quietly", lambda *a, **_k: None)
    monkeypatch.setattr(runner, "encrypt_single", _raise_ckr(0x7FFFFFFF))
    monkeypatch.setattr(runner, "decrypt_single", _raise_ckr(0x7FFFFFFF))
    result = runner._canonical_aead_probe(_AeadSession(), mech_name, direction)
    assert result.status is Operability.WRONG_OUTPUT
    assert "undefined" in result.detail

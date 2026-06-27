"""Regression tests for ACVP SLH-DSA runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases.acvp import test_acvp_slhdsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SLH_DSA",
        has_mechanism_flag=lambda _m, _f: True,
    )


def _device_error(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


def test_slhdsa_valid_sigver_runtime_reject_has_valid_signature_xfail_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "pk": b"public",
        "msg": b"message",
        "sig": b"signature",
        "expected_pass": True,
    }
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _device_error)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="valid SLH-DSA signature"):
        test_acvp_slhdsa.test_slhdsa_sigver(
            _session(),
            "sigVer-SLH-DSA-SHA2-128f-tc2",
            vec,
        )


def test_slhdsa_siggen_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "sk": b"private",
        "msg": b"message",
    }
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _device_error)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="SLH-DSA.*operation"):
        test_acvp_slhdsa.test_slhdsa_siggen(
            _session(),
            "sigGen-SLH-DSA-SHA2-128f-tc1",
            vec,
        )


# ---------------------------------------------------------------------------
# D3: import-stage classification.
#
# SLH_DSA is advertised (has_mechanism gate passed). An import reject on an
# advertised PQC mechanism is "advertised but not operational" -> xfail, NOT
# skip -- mirroring the ML-DSA precedent (test_wycheproof_mldsa* xfail on
# _MLDSA_*_IMPORT_REJECT_CKRS) and the documented ML-KEM raw-private import
# convention (CKR_ATTRIBUTE_VALUE_INVALID -> xfail).
# The boundary is mechanism advertisement: not-advertised = skip (above the
# import), advertised + any broad clean CKR = xfail. There is no PQC
# genuine-absence import CKR analogous to CKR_CURVE_NOT_SUPPORTED.
# ---------------------------------------------------------------------------


def _ckr(rv: int) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(f"Unexpected CK_RV {int(rv)}", int(rv))

    return _raise


def _keygen_vec() -> dict[str, Any]:
    return {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "sk": b"private",
        "pk": b"public",
        "tc_id": 1,
    }


def test_slhdsa_import_broad_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broad import-unsupported CKR (CKR_ATTRIBUTE_VALUE_INVALID) on advertised
    SLH-DSA -> xfail (advertised but not operational), not skip."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "import_pqc_private_key", _ckr(int(CKR_ATTRIBUTE_VALUE_INVALID))
    )
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_acvp_slhdsa.test_slhdsa_keygen(
                _session(), "keyGen-SLH-DSA-SHA2-128f-tc1", _keygen_vec()
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_slhdsa_import_function_failed_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_FUNCTION_FAILED at import on advertised SLH-DSA -> xfail (same bucket)."""
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", _ckr(int(CKR_FUNCTION_FAILED)))
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_acvp_slhdsa.test_slhdsa_keygen(
                _session(), "keyGen-SLH-DSA-SHA2-128f-tc1", _keygen_vec()
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_slhdsa_import_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-CKR AssertionError at import propagates (harness-bug path; not xfail/skip)."""

    def _raise(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("ctypes packing bug")

    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", _raise)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_acvp_slhdsa.test_slhdsa_keygen(
            _session(), "keyGen-SLH-DSA-SHA2-128f-tc1", _keygen_vec()
        )

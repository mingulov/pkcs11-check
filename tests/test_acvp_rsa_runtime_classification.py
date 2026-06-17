"""Regression tests for ACVP RSA setup/result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases.acvp import test_acvp_rsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=0,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _m, _f: True,
    )


@pytest.fixture(autouse=True)
def _advertise_keygen_in_range(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the require_keygen_key_size gate see an in-range advertised size.

    These tests stub a module that advertises every mechanism (has_mechanism
    True) and force a specific keygen/sign/import reject; the new ACVP key-size
    gate must pass through to that reject rather than short-circuit on a stub
    C_GetMechanismInfo that has no real range. A wide [512, 16384] range keeps
    the 2048-bit vectors in range so the downstream classification under test
    still runs.
    """

    def _fake(_raw: object, _slot: int, _mech: int) -> dict[str, int]:
        return {"min_key_size": 512, "max_key_size": 16384, "flags": 0}

    monkeypatch.setattr("pkcs11_check.raw.recipes.get_mechanism_info", _fake)


def _pkcs15_vec(*, expected_pass: bool = True) -> dict[str, Any]:
    return {
        "mech_name": "SHA1_RSA_PKCS",
        "mech_int": int(CKM_SHA1_RSA_PKCS),
        "modulo": 2048,
        "expected_pass": expected_pass,
        "n": b"\x01",
        "e": b"\x01",
        "message": b"message",
        "signature": b"signature",
    }


def _pss_vec(*, expected_pass: bool = True) -> dict[str, Any]:
    return {
        "mech_name": "SHA1_RSA_PKCS_PSS",
        "mech_int": int(CKM_SHA1_RSA_PKCS_PSS),
        "hash_mech": int(CKM_SHA_1),
        "mgf": 1,
        "salt_len": 20,
        "modulo": 2048,
        "expected_pass": expected_pass,
        "n": b"\x01",
        "e": b"\x01",
        "message": b"message",
        "signature": b"signature",
    }


def _attribute_value_invalid(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
        int(CKR_ATTRIBUTE_VALUE_INVALID),
    )


def _device_error(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_DEVICE_ERROR",
        int(CKR_DEVICE_ERROR),
    )


def test_acvp_rsa_pkcs15_siggen_keygen_reject_is_setup_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_acvp_rsa, "gen_rsa_keypair", _attribute_value_invalid)
    monkeypatch.setattr(test_acvp_rsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.skip.Exception, match="RSA 2048-bit key generation failed"):
        test_acvp_rsa.TestRsaPkcs15().test_rsa_pkcs15_sign_verify(
            _session(),
            "SigGen-pkcs15-SHA2-256-tc31",
            _pkcs15_vec(),
        )


def test_acvp_rsa_pss_siggen_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_acvp_rsa, "gen_rsa_keypair", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(test_acvp_rsa, "sign_single", _device_error)
    monkeypatch.setattr(test_acvp_rsa, "verify_single", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(test_acvp_rsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_acvp_rsa.TestRsaPss().test_rsa_pss_sign_verify(
            _session(),
            "SigGen-pss-SHA2-256-tc31",
            _pss_vec(),
        )


def test_acvp_rsa_pkcs15_public_import_reject_is_not_operational_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negotiation-exhausted RSA public key import on an advertised mechanism -> xfail.

    The mechanism was already advertised (has_mechanism gate passed), so a
    negotiation-exhausted import refusal is "advertised but not operational" per
    the classification model.  The old contract (pytest.skip "RSA public key
    import failed") was replaced by Batch 1; this test pins the new contract.

    Hard-pin: an unexpected skip escaping instead of an xfail is caught and
    converted to a hard fail so CI cannot silently swallow a regression.
    """
    monkeypatch.setattr(test_acvp_rsa, "import_rsa_public_key_negotiated", _attribute_value_invalid)

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(
                _session(),
                "SigVer-pkcs15-ver-SHA-1-tc181_0",
                _pkcs15_vec(),
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_acvp_rsa_pss_public_import_reject_is_not_operational_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negotiation-exhausted RSA public key import on an advertised mechanism -> xfail.

    Same contract as the PKCS#1.5 variant: the mechanism was already advertised,
    so import refusal is "advertised but not operational", not a setup skip.
    The old contract (pytest.skip "RSA public key import failed") was replaced
    by Batch 1; this test pins the new contract.

    Hard-pin: an unexpected skip escaping instead of an xfail is caught and
    converted to a hard fail so CI cannot silently swallow a regression.
    """
    monkeypatch.setattr(test_acvp_rsa, "import_rsa_public_key_negotiated", _attribute_value_invalid)

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            test_acvp_rsa.TestRsaSigVer().test_rsa_pss_verify(
                _session(),
                "SigVer-pss-ver-SHA-1-tc181_0",
                _pss_vec(),
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_acvp_rsa_verify_attribute_value_invalid_is_runtime_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_acvp_rsa, "import_rsa_public_key_negotiated", lambda *_args, **_kwargs: 1
    )
    monkeypatch.setattr(test_acvp_rsa, "verify_single", _attribute_value_invalid)
    monkeypatch.setattr(test_acvp_rsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_ATTRIBUTE_VALUE_INVALID"):
        test_acvp_rsa.TestRsaSigVer().test_rsa_pkcs15_verify(
            _session(),
            "SigVer-pkcs15-ver-SHA-1-tc181_0",
            _pkcs15_vec(expected_pass=False),
        )

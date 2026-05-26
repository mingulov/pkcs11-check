"""Regression tests for ACVP EdDSA key-verification result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.acvp import test_acvp_eddsa
from pkcs11_check.testcases.acvp._eddsa_helpers import (
    load_eddsa_keyver_vectors,
    load_eddsa_sigver_vectors,
)


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_eddsa_acvp_public_keys_use_raw_rfc8032_encoding() -> None:
    """CKK_EC_EDWARDS CKA_EC_POINT is raw public-key bytes, not DER wrapped."""
    for _vec_id, vec in [*load_eddsa_keyver_vectors(), *load_eddsa_sigver_vectors()]:
        assert vec["ec_point"] == vec["q"]
        assert len(vec["ec_point"]) in (32, 57)


def test_eddsa_keyver_valid_key_import_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _reject_valid_key(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    vec = {
        "ec_params": b"params",
        "ec_point": b"point",
        "curve": "ED-test",
        "expected_pass": True,
    }
    monkeypatch.setattr(
        test_acvp_eddsa,
        "import_eddsa_public_key_with_supported_encoding",
        _reject_valid_key,
    )

    with pytest.raises(pytest.xfail.Exception, match="valid EdDSA key import rejected"):
        test_acvp_eddsa.TestEdDsaKeyVer().test_eddsa_keyver(
            _session(),
            SimpleNamespace(),
            "EDDSA-KeyVer-valid",
            vec,
        )


def test_eddsa_keyver_probe_curve_reject_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    def _reject_probe_curve(*_args: Any, **_kwargs: Any) -> str:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_DOMAIN_PARAMS_INVALID",
            int(CKR_DOMAIN_PARAMS_INVALID),
        )

    vec = {
        "ec_params": b"params",
        "q": b"Q" * 57,
        "ec_point": b"Q" * 57,
        "curve": "ED-448",
        "expected_pass": True,
    }
    monkeypatch.setitem(
        test_acvp_eddsa._SIGVER_PROBES_BY_CURVE,
        "ED-448",
        {
            "ec_params": b"params",
            "q": b"Q" * 57,
            "curve": "ED-448",
            "msg": b"message",
            "sig": b"S" * 114,
            "expected_pass": True,
        },
    )
    monkeypatch.setattr(test_acvp_eddsa, "select_eddsa_public_key_encoding", _reject_probe_curve)

    with pytest.raises(pytest.skip.Exception, match="Cannot import EdDSA public key"):
        test_acvp_eddsa.TestEdDsaKeyVer().test_eddsa_keyver(
            _session(),
            SimpleNamespace(),
            "EDDSA-KeyVer-ED-448-tc1",
            vec,
        )


def test_eddsa_keygen_sign_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _device_error(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    vec = {
        "ec_params": b"params",
        "curve": "ED-25519",
    }
    monkeypatch.setattr(test_acvp_eddsa, "gen_keypair", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(test_acvp_eddsa, "sign_single", _device_error)
    monkeypatch.setattr(test_acvp_eddsa, "verify_single", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(test_acvp_eddsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_acvp_eddsa.TestEdDsaKeyGen().test_eddsa_keygen(
            _session(),
            "EDDSA-KeyGen-ED-25519-tc1",
            vec,
        )


def test_eddsa_siggen_sign_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _device_error(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    vec = {
        "ec_params": b"params",
        "curve": "ED-25519",
        "d": b"private",
        "msg": b"message",
        "expected_sig": b"signature",
    }
    monkeypatch.setattr(test_acvp_eddsa, "import_ec_private_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_acvp_eddsa, "sign_single", _device_error)
    monkeypatch.setattr(test_acvp_eddsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_acvp_eddsa.test_acvp_eddsa_siggen(
            _session(),
            "EDDSA-SigGen-ED-25519-tc41",
            vec,
        )


def test_eddsa_keyver_invalid_key_acceptance_stays_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = {
        "ec_params": b"params",
        "ec_point": b"point",
        "curve": "ED-test",
        "expected_pass": False,
    }
    monkeypatch.setattr(
        test_acvp_eddsa,
        "import_eddsa_public_key_with_supported_encoding",
        lambda *_args, **_kwargs: 1,
    )
    monkeypatch.setattr(
        test_acvp_eddsa,
        "verify_eddsa_signature_with_supported_params",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(test_acvp_eddsa, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="ACCEPTED an INVALID EdDSA key"):
        test_acvp_eddsa.TestEdDsaKeyVer().test_eddsa_keyver(
            _session(),
            SimpleNamespace(),
            "EDDSA-KeyVer-invalid",
            vec,
        )

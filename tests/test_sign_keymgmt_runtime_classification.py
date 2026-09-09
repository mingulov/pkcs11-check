"""Regression tests for legacy sign/key-management classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKM_SHA384_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases import test_keymgmt, test_sign, test_sign_recover
from pkcs11_check.testcases._probes.runner import ProbeResult


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def _raise_mechanism_invalid(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_INVALID",
        int(CKR_MECHANISM_INVALID),
    )


def test_rsa_sign_missing_mechanism_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_sign,
        "gen_rsa_keypair",
        lambda *_a, **_k: pytest.fail("RSA setup should have been skipped"),
        raising=False,
    )
    monkeypatch.setattr(
        test_sign,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: pytest.fail("RSA setup should have been skipped"),
        raising=False,
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_sign.TestRSASignature().test_rsa_pkcs_sign_verify(_session("RSA_PKCS_KEY_PAIR_GEN"))


def test_rsa_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_sign,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_sign, "sign_single", _raise_mechanism_invalid)
    monkeypatch.setattr(test_sign, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS sign rejected"):
        test_sign.TestRSASignature().test_rsa_pkcs_sign_verify(
            _session("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
        )


def test_rsa_hash_missing_mechanism_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_sign,
        "gen_rsa_keypair",
        lambda *_a, **_k: pytest.fail("RSA setup should have been skipped"),
        raising=False,
    )
    monkeypatch.setattr(
        test_sign,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: pytest.fail("RSA setup should have been skipped"),
        raising=False,
    )

    with pytest.raises(pytest.skip.Exception, match="SHA384_RSA_PKCS not supported"):
        test_sign.TestRSASignature().test_rsa_hash_mechanisms(
            _session("RSA_PKCS_KEY_PAIR_GEN"),
            CKM_SHA384_RSA_PKCS,
        )


def test_keymgmt_roundtrip_missing_aes_ecb_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_keymgmt,
        "import_secret_key",
        lambda *_a, **_k: pytest.fail("AES import should have been skipped"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_keymgmt.TestKeyImport().test_import_aes_key_roundtrip(_session())


def test_keymgmt_copy_missing_aes_keygen_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_keymgmt,
        "gen_aes_key",
        lambda *_a, **_k: pytest.fail("AES setup should have been skipped"),
        raising=False,
    )
    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        test_keymgmt.TestKeyCopy().test_copy_preserves_attributes(_session())


def test_keymgmt_wrong_exported_value_remains_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_keymgmt, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        test_keymgmt,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"Hello world!"},
    )
    monkeypatch.setattr(test_keymgmt, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        test_keymgmt.TestKeyImport().test_extractable_key_export(_session())


def test_sign_recover_missing_result_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_sign_recover, "_has_rsa_x509", lambda _module: True)
    monkeypatch.setattr(
        test_sign_recover,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="KEYGEN_OK:1:2\nOK\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="SIG_LEN"):
        test_sign_recover.TestSignRecover().test_sign_recover_produces_output(
            config,
            SimpleNamespace(get_slots=lambda **_k: []),
        )

    from pkcs11_check.classification import get_records

    assert get_records()[-1].reason == "harness_error"


def _run_sign_recover_length_probe(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    monkeypatch.setattr(test_sign_recover, "_has_rsa_x509", lambda _module: True)
    monkeypatch.setattr(
        test_sign_recover,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    test_sign_recover.TestSignRecover().test_sign_recover_wrong_data_length(
        config,
        SimpleNamespace(get_slots=lambda **_k: []),
    )


def test_sign_recover_oversize_acceptance_is_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A k+1-byte RSA-X.509 input must not be accepted as a valid operation."""
    with pytest.raises(pytest.fail.Exception, match="accepted invalid"):
        _run_sign_recover_length_probe(
            monkeypatch,
            "RESULT:ACCEPTED_OVERSIZE_DATA\nOK:sign_recover_wrong_data_length\n",
        )

    from pkcs11_check.classification import get_records

    assert get_records()[-1].reason == "accepted_invalid"
    assert get_records()[-1].kind == "crypto"


def test_sign_recover_oversize_expected_reject_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_sign_recover_length_probe(
        monkeypatch,
        f"RESULT:REJECTED:0x{int(CKR_DATA_LEN_RANGE):08x}\nOK:sign_recover_wrong_data_length\n",
    )


def test_sign_recover_oversize_arguments_bad_is_nonspec_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only CKR_DATA_LEN_RANGE is normative for the oversize vector."""
    with pytest.raises(pytest.xfail.Exception, match="CKR_DATA_LEN_RANGE"):
        _run_sign_recover_length_probe(
            monkeypatch,
            f"RESULT:REJECTED:0x{int(CKR_ARGUMENTS_BAD):08x}\nOK:sign_recover_wrong_data_length\n",
        )

    from pkcs11_check.classification import get_records

    assert get_records()[-1].reason == "nonspec_reject"


def test_sign_recover_oversize_nonstandard_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_sign_recover_length_probe(
            monkeypatch,
            f"RESULT:REJECTED:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            "OK:sign_recover_wrong_data_length\n",
        )

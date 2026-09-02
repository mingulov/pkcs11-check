"""Regression tests for provider-operation exception boundaries."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.testcases import (
    test_ec_curves,
    test_ec_import_export,
    test_ecdh_known_answer,
    test_eddsa,
    test_kem,
    test_pqc_sign,
)
from pkcs11_check.testcases.acvp.aes import base_cts
from pkcs11_check.testcases.security import test_crypto_weakness

_TARGETS = (
    "test_eddsa.py",
    "test_ecdh_known_answer.py",
    "test_ec_curves.py",
    "test_ec_import_export.py",
    "test_pqc_sign.py",
    "test_kem.py",
    "security/test_crypto_weakness.py",
    "acvp/aes/base_cts.py",
    "acvp/aes/test_gcm.py",
    "test_surface_audit.py",
    "test_mechanism_objects.py",
    "test_profiles.py",
    "test_hw_features.py",
)


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_eddsa_operation_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(test_eddsa, "sign_single", lambda *_a, **_k: (_ for _ in ()).throw(exc))
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(type(exc), match=str(exc)):
        test_eddsa._sign_eddsa(rs, 1, b"message")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_ec_keygen_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_ec_curves, "gen_ec_keypair", lambda *_a, **_k: (_ for _ in ()).throw(exc)
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            test_ec_curves._try_gen_ec(rs, "secp256r1")
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


def test_ckr_operation_refusal_remains_classifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", 0x00000006)
    monkeypatch.setattr(test_eddsa, "sign_single", lambda *_a, **_k: (_ for _ in ()).throw(refusal))
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(pytest.xfail.Exception):
        test_eddsa._sign_eddsa(rs, 1, b"message")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_ecdh_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "gen_ec_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            test_ecdh_known_answer._gen_p256_or_skip(rs)
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_ec_import_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_ec_import_export,
        "gen_ec_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            test_ec_import_export._make_ec_keypair(rs, "secp256r1")
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_cts_detection_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    from pkcs11_check.raw import recipes

    monkeypatch.setattr(recipes, "gen_aes_key", lambda *_a, **_k: (_ for _ in ()).throw(exc))
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "AES_CTS")

    with pytest.raises(type(exc), match=str(exc)):
        base_cts._detect_cts_variant(rs)


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_security_probe_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_crypto_weakness,
        "gen_rsa_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(type(exc), match=str(exc)):
        test_crypto_weakness.TestWeakRsaKeySize().test_weak_rsa_key_generation(rs, 512, "CRITICAL")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_pqc_keygen_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_pqc_sign,
        "_generate_slh_dsa_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(type(exc), match=str(exc)):
        test_pqc_sign.TestSLHDSAKeyGeneration().test_slh_dsa_keypair_gen(rs)


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_kem_keygen_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(
        test_kem,
        "_generate_ml_kem_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(type(exc), match=str(exc)):
        test_kem.TestMLKEMKeyDerivation().test_parameter_set_produces_correct_ciphertext_size(
            rs, "ML_KEM_512", 768
        )


def test_provider_operation_handlers_do_not_catch_python_or_os_errors() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
    for relative in _TARGETS:
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            caught: set[str] = set()
            if handler.type is None:
                continue
            for node in ast.walk(handler.type):
                if isinstance(node, ast.Name):
                    caught.add(node.id)
            assert not ({"AssertionError", "OSError"} & caught), (
                f"{relative}:{handler.lineno} catches a non-CKR provider/harness exception"
            )

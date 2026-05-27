"""Regression tests for benchmark setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_benchmark


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def test_benchmark_rsa_keypair_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", _keygen_reject)
    monkeypatch.setattr(
        test_benchmark.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        next(test_benchmark.rsa2048_keypair.__wrapped__(_session("RSA_PKCS_KEY_PAIR_GEN")))


def test_benchmark_ec_keypair_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keygen_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(raw_recipes, "gen_ec_keypair", _keygen_reject)
    monkeypatch.setattr(
        test_benchmark.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="EC_KEY_PAIR_GEN advertised"):
        next(test_benchmark.ec_p256_keypair.__wrapped__(_session("EC_KEY_PAIR_GEN")))


def test_benchmark_aes_cbc_probe_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encrypt_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_benchmark, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_benchmark, "generate_random", lambda *_args, **_kwargs: b"\0" * 16)
    monkeypatch.setattr(test_benchmark, "encrypt_single", _encrypt_reject)
    monkeypatch.setattr(test_benchmark, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        test_benchmark.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_CBC benchmark probe"):
        test_benchmark.test_bench_aes256_cbc_encrypt(
            lambda func: func(),
            _session("AES_KEY_GEN"),
        )


def test_benchmark_rsa_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session("SHA256_RSA_PKCS")
    monkeypatch.setattr(test_benchmark, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="RSA SHA256 benchmark sign"):
        test_benchmark.test_bench_rsa2048_sign(lambda func: func(), (1, 2, rs))


def test_benchmark_rsa_verify_setup_sign_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session("SHA256_RSA_PKCS")
    monkeypatch.setattr(test_benchmark, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="RSA SHA256 benchmark verify setup"):
        test_benchmark.test_bench_rsa2048_verify(lambda func: func(), (1, 2, rs))


def test_benchmark_sha256_digest_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _digest_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_benchmark, "digest_single", _digest_reject)

    with pytest.raises(pytest.xfail.Exception, match="SHA256 benchmark digest"):
        test_benchmark.test_bench_sha256_digest(lambda func: func(), _session("SHA256"))

"""Regression tests for PC-3: tpm2-style keygen rejects during security
probes must be classified as a missing-capability ``skip``, not a hard
``fail``.

tpm2-pkcs11 returns ``CKR_ATTRIBUTE_VALUE_INVALID`` on the
``gen_rsa_keypair(...)`` / ``gen_ec_keypair(...)`` setup step of several
weak-parameter probes because of its restrictive key-attribute policy.
Each probe targets a *weak operation parameter* (zero-salt PSS, MD5 in
PSS, SHA-1 MGF in OAEP, invalid EC point in ECDH, etc.), not keygen
support; if the provider cannot generate the test key, the probe is a
missing-capability ``skip`` (mechanism advertised, key shape not
operational), not a ``fail``.

Catalog FP entries on softhsm2 baseline: 1 + 1 + 1 + 1 + 3 = 7 tpm2
false-fails resolved by this guard.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases.security import test_parameter_validation as tpv


def _exc(rv: int, ckr_name: str) -> CkrAssertionError:
    return CkrAssertionError(f"Unexpected CK_RV {ckr_name}; expected one of: CKR_OK", rv)


def _bad_keygen(*_a: Any, **_kw: Any) -> tuple[int, int]:
    raise _exc(int(CKR_ATTRIBUTE_VALUE_INVALID), "CKR_ATTRIBUTE_VALUE_INVALID")


def _expect_skip(monkeypatch: Any, run: Callable[[Any], None]) -> None:
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(tpv, "gen_rsa_keypair", _bad_keygen)
    monkeypatch.setattr(tpv, "gen_ec_keypair", _bad_keygen)
    monkeypatch.setattr(tpv, "destroy_quietly", lambda *_a, **_kw: None)
    with pytest.raises(pytest.skip.Exception):
        run(rs)


def test_rsa_pss_md5_hash_skips_when_keygen_rejects(monkeypatch: Any) -> None:
    _expect_skip(monkeypatch, lambda rs: tpv.TestRsaPssMd5Hash().test_rsa_pss_md5_hash(rs))


def test_pss_zero_salt_length_skips_when_keygen_rejects(monkeypatch: Any) -> None:
    _expect_skip(
        monkeypatch,
        lambda rs: tpv.TestPssSaltLength().test_pss_zero_salt_length(rs, 0),
    )


def test_pss_excessive_salt_length_skips_when_keygen_rejects(monkeypatch: Any) -> None:
    _expect_skip(
        monkeypatch,
        lambda rs: tpv.TestPssSaltLength().test_pss_excessive_salt_length(rs),
    )


def test_rsa_oaep_sha1_mgf_skips_when_keygen_rejects(monkeypatch: Any) -> None:
    _expect_skip(monkeypatch, lambda rs: tpv.TestRsaOaepSha1Mgf().test_rsa_oaep_sha1_mgf(rs))


def test_ecdh_invalid_point_skips_when_keygen_rejects(monkeypatch: Any) -> None:
    _expect_skip(
        monkeypatch,
        lambda rs: tpv.TestEcPointValidation().test_ecdh_invalid_point(rs, "infinity"),
    )

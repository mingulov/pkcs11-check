"""Regression tests for surface-audit outcome boundaries."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification
from pkcs11_check.raw import recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_HOST_MEMORY,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases import test_surface_audit as surface


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    classification.clear()


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name in advertised,
    )


def _raise(exc: BaseException) -> Any:
    def raiser(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return raiser


def test_zero_length_random_plain_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface, "generate_random", _raise(AssertionError("harness bug")))

    with pytest.raises(AssertionError, match="harness bug"):
        surface.TestFunctionRobustness().test_random_with_zero_bits(_session())


def test_zero_length_random_undefined_ckr_is_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        surface,
        "generate_random",
        _raise(CkrAssertionError("undefined return", 0x7FFFFFFF)),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        surface.TestFunctionRobustness().test_random_with_zero_bits(_session())


def test_advertised_digest_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        surface,
        "digest_single",
        _raise(CkrAssertionError("digest unavailable", int(CKR_FUNCTION_NOT_SUPPORTED))),
    )

    with pytest.raises(pytest.xfail.Exception, match="SHA_1 advertised"):
        surface.TestFunctionRobustness().test_digest_all_hash_mechanisms(_session("SHA_1"))


def test_advertised_digest_plain_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface, "digest_single", _raise(AssertionError("wrong harness")))

    with pytest.raises(AssertionError, match="wrong harness"):
        surface.TestFunctionRobustness().test_digest_all_hash_mechanisms(_session("SHA_1"))


def test_advertised_encrypt_refusal_is_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(surface, "get_mechanism_info", lambda *_a, **_k: {})
    monkeypatch.setattr(surface, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        surface,
        "encrypt_single",
        _raise(CkrAssertionError("unavailable", int(CKR_FUNCTION_NOT_SUPPORTED))),
    )
    monkeypatch.setattr(surface, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception, match="AES_ECB advertised"):
        surface.TestMechanismFlagsConsistency().test_aes_encrypt_flag_matches_capability(
            _session("AES_ECB", "AES_KEY_GEN")
        )


def test_advertised_mechanism_info_failure_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = CkrAssertionError("mechanism info failed", int(CKR_FUNCTION_NOT_SUPPORTED))
    monkeypatch.setattr(surface, "get_mechanism_info", _raise(error))

    with pytest.raises(CkrAssertionError, match="mechanism info failed"):
        surface.TestMechanismLimitProbing().test_aes_oversize_key(_session("AES_KEY_GEN"))


def test_aes_acceptance_beyond_advertised_max_is_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        surface,
        "get_mechanism_info",
        lambda *_a, **_k: {"min_key_size": 16, "max_key_size": 32},
    )
    monkeypatch.setattr(surface, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(surface, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed):
        surface.TestMechanismLimitProbing().test_aes_oversize_key(_session("AES_KEY_GEN"))

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"


@pytest.mark.parametrize(
    ("rv", "outcome"),
    [
        (int(CKR_HOST_MEMORY), "xfail"),
        (int(CKR_VENDOR_DEFINED) + 1, "xfail"),
        (0x7FFFFFFF, "fail"),
    ],
)
def test_aes_oversize_rejection_uses_exact_key_size_errors(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    outcome: str,
) -> None:
    monkeypatch.setattr(
        surface,
        "get_mechanism_info",
        lambda *_a, **_k: {"min_key_size": 16, "max_key_size": 32},
    )
    monkeypatch.setattr(
        surface,
        "gen_aes_key",
        _raise(CkrAssertionError("key-size rejection", rv)),
    )
    monkeypatch.setattr(surface, "destroy_quietly", lambda *_a, **_k: None)

    expected = pytest.xfail.Exception if outcome == "xfail" else Failed
    with pytest.raises(expected):
        surface.TestMechanismLimitProbing().test_aes_oversize_key(_session("AES_KEY_GEN"))


@pytest.mark.parametrize("exc", [AssertionError("harness bug"), OSError("provider fault")])
def test_hmac_short_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch,
    exc: BaseException,
) -> None:
    monkeypatch.setattr(recipes, "create_object", _raise(exc))
    monkeypatch.setattr(surface, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(type(exc), match=str(exc)):
        surface.TestMechanismLimitProbing().test_hmac_short_key(_session())


def test_hmac_short_undefined_ckr_is_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recipes,
        "create_object",
        _raise(CkrAssertionError("undefined HMAC result", 0x7FFFFFFF)),
    )
    monkeypatch.setattr(surface, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed, match="undefined CK_RV"):
        surface.TestMechanismLimitProbing().test_hmac_short_key(_session())


def test_domain_search_plain_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(recipes, "find_objects", _raise(AssertionError("search harness bug")))

    with pytest.raises(AssertionError, match="search harness bug"):
        surface.TestFunctionRobustness().test_find_with_domain_parameters_class(_session())


def test_domain_search_undefined_ckr_is_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recipes,
        "find_objects",
        _raise(CkrAssertionError("undefined search result", 0x7FFFFFFF)),
    )

    with pytest.raises(Failed, match="undefined CK_RV"):
        surface.TestFunctionRobustness().test_find_with_domain_parameters_class(_session())

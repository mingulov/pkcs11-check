"""Attribute-fuzz probes must not count impossible requests as passes."""

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.testcases import test_attribute_fuzz as fuzz


def test_oversized_aes_key_acceptance_is_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fuzz, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(fuzz, "destroy_quietly", lambda *_a: None)
    with pytest.raises(Failed, match="impossible 0xFFFFFFFF-byte AES key length"):
        fuzz.TestMalformedAttributes().test_negative_key_length(SimpleNamespace(raw=object(), sh=1))


def test_oversized_aes_key_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fuzz,
        "gen_aes_key",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        fuzz.TestMalformedAttributes().test_negative_key_length(SimpleNamespace(raw=object(), sh=1))

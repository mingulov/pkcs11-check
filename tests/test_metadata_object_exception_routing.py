"""Metadata-object probes must not turn harness/provider defects into absence."""

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.testcases import test_hw_features as hw
from pkcs11_check.testcases import test_mechanism_objects as mechanisms
from pkcs11_check.testcases import test_profiles as profiles


def test_mechanism_enumeration_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mechanisms,
        "find_objects",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        mechanisms._mechanism_objects(SimpleNamespace(raw=object(), sh=1))


def test_hw_type_plain_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hw,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        hw._hw_type(SimpleNamespace(raw=object(), sh=1), 1)


def test_profile_id_read_failure_is_not_empty_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(profiles, "find_objects", lambda *_a, **_k: [1])
    monkeypatch.setattr(
        profiles,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        profiles._read_profile_ids(SimpleNamespace(raw=object(), sh=1))


def test_mechanism_read_only_acceptance_is_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mechanisms, "_mechanism_objects", lambda _rs: [1])
    monkeypatch.setattr(mechanisms, "set_attributes", lambda *_a, **_k: None)
    with pytest.raises(Failed, match="read-only CKO_MECHANISM"):
        mechanisms.TestMechanismObjects().test_mechanism_objects_are_read_only(
            SimpleNamespace(raw=object(), sh=1)
        )

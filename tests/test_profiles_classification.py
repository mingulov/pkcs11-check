"""Classification meta-tests for test_profiles conformance legs (Phase 5 P1a).

A module that advertises a profile but does not fully implement its mandatory
functions / mechanisms / object classes is provider-incompleteness -> ``xfail``,
not a hard ``fail`` (the suite is provider-general and has no single reference
implementation to declare the module broken).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check import compliance_profiles as cp
from pkcs11_check.testcases import test_profiles as tp


def _profile(**kw: Any) -> SimpleNamespace:
    base = {
        "profile_name": "TestProfile",
        "required_functions": set(),
        "required_mechanisms": set(),
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_missing_functions_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp, "_read_profile_ids", lambda _rs: {0x10})
    monkeypatch.setattr(cp, "lookup_profile", lambda _pid: _profile(required_functions={"C_Foo"}))
    monkeypatch.setattr(cp, "PROFILE_TEST_EXCLUDED", set(), raising=False)
    rs = SimpleNamespace(raw=SimpleNamespace(available_function_names=lambda: []))
    with pytest.raises(XFailed):
        tp.TestProfileBehavioralConformance().test_advertised_profiles_have_required_functions(rs)


def test_missing_mechanisms_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp, "_read_profile_ids", lambda _rs: {0x10})
    monkeypatch.setattr(
        cp, "lookup_profile", lambda _pid: _profile(required_mechanisms={0x00001234})
    )
    monkeypatch.setattr(cp, "PROFILE_TEST_EXCLUDED", set(), raising=False)
    rs = SimpleNamespace(raw=object(), has_mechanism=lambda _n: False)
    with pytest.raises(XFailed):
        tp.TestProfileBehavioralConformance().test_advertised_profiles_have_required_mechanisms(rs)


def test_pubcert_find_failure_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp, "_read_profile_ids", lambda _rs: {0x00000004})
    monkeypatch.setattr(cp, "lookup_profile", lambda _pid: _profile())
    monkeypatch.setattr(cp, "PROFILE_TEST_EXCLUDED", set(), raising=False)

    def _raise_find(*_a: Any, **_k: Any) -> list[int]:
        raise AssertionError("CKR_FUNCTION_FAILED")

    monkeypatch.setattr(tp, "find_objects", _raise_find)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(XFailed):
        tp.TestProfileBehavioralConformance().test_advertised_profiles_have_required_object_classes(
            rs
        )


def test_pubcert_no_certs_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tp, "_read_profile_ids", lambda _rs: {0x00000004})
    monkeypatch.setattr(cp, "lookup_profile", lambda _pid: _profile())
    monkeypatch.setattr(cp, "PROFILE_TEST_EXCLUDED", set(), raising=False)
    monkeypatch.setattr(tp, "find_objects", lambda *_a, **_k: [])
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(XFailed):
        tp.TestProfileBehavioralConformance().test_advertised_profiles_have_required_object_classes(
            rs
        )

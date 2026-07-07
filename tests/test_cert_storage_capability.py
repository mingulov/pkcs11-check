"""Meta-test: cert_storage_supported probe (no real module needed)."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID
from pkcs11_check.testcases.x509 import conftest as x509conftest


def _fake_module(monkeypatch, *, accept_on: int | None, raise_rv: int) -> tuple[Any, list[int]]:
    """accept_on: 0-based attempt index that stores OK; None = always refuse.
    Returns (rs, attempts) where attempts[0] is the create_object call count."""
    attempts = [0]

    def fake_create_object(raw: Any, sh: int, tmpl: dict[Any, Any]) -> int:
        i = attempts[0]
        attempts[0] += 1
        if accept_on is not None and i == accept_on:
            return 7
        raise CkrAssertionError("refuse", raise_rv)

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", lambda *a, **k: None)
    x509conftest._CERT_STORAGE_SUPPORTED.clear()
    rs = type("RS", (), {"raw": object(), "sh": 0, "slot_id": 0})()
    return rs, attempts


def test_supported_when_any_template_accepted(monkeypatch):
    rs, _ = _fake_module(monkeypatch, accept_on=1, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    assert x509conftest.cert_storage_supported(rs) is True


def test_unsupported_only_after_trying_all(monkeypatch):
    rs, attempts = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    assert x509conftest.cert_storage_supported(rs) is False
    assert attempts[0] >= 2  # exhaustive before concluding (no false-skip)


def test_non_refusal_ckr_propagates(monkeypatch):
    # CKR_GENERAL_ERROR is NOT a clean cert-storage refusal -> propagates from the probe
    # (not swallowed as a silent skip). The skip gate then records it (next test).
    rs, _ = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_GENERAL_ERROR))
    with pytest.raises(CkrAssertionError):
        x509conftest.cert_storage_supported(rs)


def test_skip_gate_records_general_error_as_not_operational(monkeypatch):
    # A KMS that returns CKR_GENERAL_ERROR for every cert template: the skip gate records
    # a not_operational xfail (a visible deviation) rather than raising raw at the gate
    # (which the plugin would stamp with its reserved reason). cosmian: 1663 in the
    # 2026-06-29 round (limbo import + stress), finding F1.
    from pkcs11_check import classification

    rs, _ = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_GENERAL_ERROR))
    classification.clear()
    with pytest.raises(BaseException):  # noqa: B017,PT011 - classify raises the xfail outcome
        x509conftest.skip_unless_cert_storage(rs)
    recs = classification.serialize(classification.get_records())
    assert recs and recs[-1]["reason"] == "not_operational", recs


def test_skip_helper_skips_when_unsupported(monkeypatch):
    rs, _ = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    with pytest.raises(pytest.skip.Exception):
        x509conftest.skip_unless_cert_storage(rs)


def test_probe_minimal_fallback_detects_support(monkeypatch):
    from pkcs11_check.raw.types_std import CKA_SUBJECT
    from pkcs11_check.testcases.x509 import conftest as x509c

    # A module that refuses every spec-complete (CKA_SUBJECT-bearing) template but accepts
    # the omit-SUBJECT minimal one -> probe still reports supported via the fallback.
    def fake_create_object(raw, sh, tmpl):
        if CKA_SUBJECT in tmpl:
            raise CkrAssertionError("refuse", int(CKR_KEY_HANDLE_INVALID))
        return 7

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", lambda *a, **k: None)
    x509c._CERT_STORAGE_SUPPORTED.clear()
    rs = type("RS", (), {"raw": object(), "sh": 0, "slot_id": 0})()
    assert x509c.cert_storage_supported(rs) is True


def test_templates_have_subject_and_minimal_does_not():
    from pkcs11_check.raw.types_std import CKA_SUBJECT
    from pkcs11_check.testcases.x509 import conftest as x509c

    der = x509c._canonical_self_signed_cert_der()
    names = [n for n, _t in x509c.cert_storage_templates(der)]
    assert "minimal" not in names  # minimal is now a negative case, not a positive template
    assert "san_only_empty_subject" in names
    for _n, tmpl in x509c.cert_storage_templates(der):
        assert CKA_SUBJECT in tmpl  # every positive template carries CKA_SUBJECT
    san = dict(x509c.cert_storage_templates(der))["san_only_empty_subject"]
    assert san[CKA_SUBJECT] == bytes.fromhex("3000")  # CKA_SUBJECT present = empty Name
    assert CKA_SUBJECT not in x509c._minimal_cert_template(der)  # negative template omits it


def test_negative_subject_verdict_mapping(monkeypatch):
    from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCOMPLETE
    from pkcs11_check.testcases.x509 import test_cert_storage as suite

    calls: list[str] = []
    monkeypatch.setattr(suite, "classify", lambda reason, **kw: calls.append(reason))
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", lambda *a, **k: None)
    rs = type("RS", (), {"raw": object(), "sh": 0})()

    def _raise(rv):
        def f(raw, sh, tmpl):
            raise CkrAssertionError("refuse", rv)

        return f

    # accepted -> honest_deviation (stored a cert omitting mandatory CKA_SUBJECT)
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", lambda raw, sh, tmpl: 7)
    suite.test_cert_storage_requires_subject(rs)
    assert calls == ["honest_deviation"]

    # rejected CKR_TEMPLATE_INCOMPLETE -> pass (no classify)
    calls.clear()
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object", _raise(int(CKR_TEMPLATE_INCOMPLETE))
    )
    suite.test_cert_storage_requires_subject(rs)
    assert calls == []

    # rejected with another clean code -> nonspec_reject
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.create_object", _raise(int(CKR_ATTRIBUTE_VALUE_INVALID))
    )
    suite.test_cert_storage_requires_subject(rs)
    assert calls == ["nonspec_reject"]

"""Classification meta-tests for x509/test_attribute_parity (Phase 5 P1a).

A wrong extracted attribute value (the module claims a value contradicting the
cert) is a hard ``fail``. An *absent* mandatory attribute, or a clean rejection
of a Limbo-valid cert, is provider-incompleteness -> ``xfail`` (a lenient-but-
conformant module may legitimately not extract every derived attribute).
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.testcases.x509 import test_attribute_parity as tap


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def _patch_common(monkeypatch: pytest.MonkeyPatch, parity: dict[Any, Any]) -> None:
    monkeypatch.setattr(tap, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(tap, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(tap, "verify_attribute_parity", lambda *_a, **_k: parity)
    monkeypatch.setattr(tap, "destroy_quietly", lambda *_a, **_k: None)


def _run(monkeypatch: pytest.MonkeyPatch, parity: dict[Any, Any]) -> None:
    _patch_common(monkeypatch, parity)
    cases = [{"id": "tc1", "peer_certificate": "pem", "expected_result": "SUCCESS"}]
    tap.test_limbo_attribute_parity(
        _RawSession(),
        True,  # cert_support
        cases,  # all_limbo_cases
        lambda c, limit=100: c,  # limbo_filter
        "v3.0",  # p11_interface_version
    )


def test_value_mismatch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # matches is False -> the module extracted a wrong value -> fail
    parity = {"CKA_SUBJECT": (False, b"observed", b"expected", True)}
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, parity)
    assert not isinstance(ei.value, XFailed)


def test_missing_mandatory_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # matches is None and required -> mandatory attr absent -> xfail
    parity = {"CKA_SUBJECT": (None, None, b"expected", True)}
    with pytest.raises(XFailed):
        _run(monkeypatch, parity)


def test_all_match_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    parity = {"CKA_SUBJECT": (True, b"v", b"v", True)}
    _run(monkeypatch, parity)


def test_mismatch_dominates_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # a real mismatch alongside a missing-mandatory still fails (mismatch wins)
    parity = {
        "CKA_SUBJECT": (False, b"observed", b"expected", True),
        "CKA_ISSUER": (None, None, b"expected", True),
    }
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, parity)
    assert not isinstance(ei.value, XFailed)

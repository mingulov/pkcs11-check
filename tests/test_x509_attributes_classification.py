"""Classification meta-tests for x509/test_attributes valid-cert reject (Phase 5 P1a).

A clean rejection of a Limbo-valid cert on import is provider-incompleteness ->
``xfail``, not a hard ``fail``.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_SUBJECT,
    CKA_VALUE,
    CKC_X_509,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.x509 import test_attributes as ta


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def test_valid_cert_clean_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID))

    monkeypatch.setattr(ta, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ta, "import_cert_object", _raise_import)
    monkeypatch.setattr(ta, "destroy_quietly", lambda *_a, **_k: None)

    tc = {"id": "tc-valid", "peer_certificate": "pem", "expected_result": "SUCCESS"}
    with pytest.raises(XFailed):
        ta.TestCertificateAttributes().test_verify_attributes(tc, _RawSession(), object(), "v3.0")


def _run_user_trusted_import(
    monkeypatch: pytest.MonkeyPatch,
    import_cert: Any,
) -> None:
    monkeypatch.setattr(
        ta,
        "load_limbo_testcases",
        lambda: [{"expected_result": "SUCCESS", "peer_certificate": "pem"}],
    )
    monkeypatch.setattr(ta, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ta, "import_cert_object", import_cert)
    monkeypatch.setattr(ta, "destroy_quietly", lambda *_args: None)
    ta.TestCertificateAttributes().test_import_with_trusted_flag(_RawSession(), object(), "v3.0")


@pytest.mark.parametrize(
    "rv",
    (
        CKR_ACTION_PROHIBITED,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_USER_NOT_LOGGED_IN,
    ),
)
def test_user_trusted_expected_create_refusal_passes(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    """The exact policy/template refusal set is accepted, without a silent catch-all."""
    classification.clear()

    def reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("expected refusal", int(rv))

    _run_user_trusted_import(monkeypatch, reject)
    assert classification.get_records() == []


def test_user_trusted_unexpected_standard_refusal_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()

    def reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("unexpected refusal", int(CKR_GENERAL_ERROR))

    with pytest.raises(XFailed):
        _run_user_trusted_import(monkeypatch, reject)
    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_user_trusted_undefined_rv_is_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    classification.clear()

    def reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("undefined return value", 0x12345678)

    with pytest.raises(Failed):
        _run_user_trusted_import(monkeypatch, reject)
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_user_trusted_generic_assertion_is_not_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("harness bug")

    with pytest.raises(AssertionError, match="harness bug"):
        _run_user_trusted_import(monkeypatch, reject)


def test_user_trusted_acceptance_is_policy_failure_without_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    monkeypatch.setattr(
        ta,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("must not read"),
    )

    with pytest.raises(Failed, match="USER session created"):
        _run_user_trusted_import(monkeypatch, lambda *_args, **_kwargs: 7)
    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction" and record.kind == "policy"


def test_optional_derived_attribute_only_accepts_unavailable_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    tc = {"id": "tc", "peer_certificate": "pem", "expected_result": "SUCCESS"}
    monkeypatch.setattr(ta, "load_limbo_testcases", lambda: [tc])
    monkeypatch.setattr(ta, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ta, "import_cert_object", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(ta, "destroy_quietly", lambda *_args: None)

    def read(_raw: Any, _session: int, _handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_VALUE]:
            return {CKA_VALUE: b"der"}
        if attrs == [CKA_CERTIFICATE_TYPE]:
            return {CKA_CERTIFICATE_TYPE: CKC_X_509}
        if attrs == [CKA_SUBJECT]:
            raise CkrAssertionError("subject unavailable", int(CKR_ATTRIBUTE_TYPE_INVALID))
        return {attrs[0]: b"derived"}

    monkeypatch.setattr(ta, "read_attributes", read)
    ta.TestCertificateAttributes().test_verify_attributes(tc, _RawSession(), object(), "v3.0")
    assert classification.get_records() == []


def test_optional_derived_attribute_generic_error_is_not_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tc = {"id": "tc", "peer_certificate": "pem", "expected_result": "SUCCESS"}
    monkeypatch.setattr(ta, "load_limbo_testcases", lambda: [tc])
    monkeypatch.setattr(ta, "pem_to_der", lambda _pem: b"der")
    monkeypatch.setattr(ta, "import_cert_object", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(ta, "destroy_quietly", lambda *_args: None)

    def read(_raw: Any, _session: int, _handle: int, attrs: list[int]) -> dict[int, Any]:
        if attrs == [CKA_VALUE]:
            return {CKA_VALUE: b"der"}
        if attrs == [CKA_CERTIFICATE_TYPE]:
            return {CKA_CERTIFICATE_TYPE: CKC_X_509}
        raise AssertionError("harness bug")

    monkeypatch.setattr(ta, "read_attributes", read)
    with pytest.raises(AssertionError, match="harness bug"):
        ta.TestCertificateAttributes().test_verify_attributes(tc, _RawSession(), object(), "v3.0")

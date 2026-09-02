"""Classification meta-tests for x509/test_core_ops v3.0 attr accept (Phase 5 P1a).

A v3.0+ module that cleanly rejects a v3.0 cert attribute with
CKR_ATTRIBUTE_VALUE_INVALID / CKR_ATTRIBUTE_TYPE_INVALID is advertised-but-not-
operational -> ``xfail`` (provider-incompleteness), not a hard ``fail``. A
non-CKR error still propagates.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_SUBJECT,
    CKA_VALUE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases.x509 import test_core_ops as tco


class _RawSession:
    raw = object()
    sh = 1
    slot_id = 0


def _ca_cert_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x509-core-ops")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _run(monkeypatch: pytest.MonkeyPatch, version: str, exc: BaseException) -> None:
    def _raise_create(*_a: Any, **_k: Any) -> int:
        raise exc

    monkeypatch.setattr(tco, "create_object", _raise_create)
    monkeypatch.setattr(tco, "destroy_quietly", lambda *_a, **_k: None)
    tco.TestV30CertAttributes().test_v30_cert_attr_accepted(
        "PUBLIC_KEY_INFO", _RawSession(), version, _ca_cert_der()
    )


def test_v30_clean_attr_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID))
    with pytest.raises(XFailed):
        _run(monkeypatch, "3.0", exc)


def test_v240_clean_attr_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = CkrAssertionError("CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID))
    with pytest.raises(XFailed):
        _run(monkeypatch, "2.40", exc)


def test_non_ckr_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="harness bug"):
        _run(monkeypatch, "3.0", ValueError("harness bug"))


def test_search_empty_result_is_non_green(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tco, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(tco, "find_objects", lambda *_a, **_k: [])
    monkeypatch.setattr(tco, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed):
        tco.TestCertificateSearch().test_search_by_label(_RawSession(), b"der", "3.0")


def test_search_provider_refusal_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tco, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        tco,
        "find_objects",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("refused", int(CKR_ATTRIBUTE_VALUE_INVALID))
        ),
    )
    monkeypatch.setattr(tco, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(XFailed):
        tco.TestCertificateSearch().test_search_by_label(_RawSession(), b"der", "3.0")


@pytest.mark.parametrize(
    ("method_name", "attribute"),
    (
        ("test_certificate_type_is_x509", CKA_CERTIFICATE_TYPE),
        ("test_read_value_matches_der", CKA_VALUE),
        ("test_subject_is_der_encoded", CKA_SUBJECT),
    ),
)
def test_required_certificate_readback_refusal_is_visible(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    attribute: int,
) -> None:
    monkeypatch.setattr(tco, "import_cert_object", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        tco,
        "read_attributes",
        lambda _raw, _sh, _h, attrs: (
            (_ for _ in ()).throw(
                CkrAssertionError("required attribute unavailable", int(CKR_ATTRIBUTE_TYPE_INVALID))
            )
            if attrs == [attribute]
            else {}
        ),
    )
    monkeypatch.setattr(tco, "destroy_quietly", lambda *_a, **_k: None)

    suite = (
        tco.TestCertificateImport()
        if method_name == "test_certificate_type_is_x509"
        else tco.TestCertificateExtractFields()
    )
    with pytest.raises(XFailed):
        getattr(suite, method_name)(_RawSession(), b"der", "3.0")

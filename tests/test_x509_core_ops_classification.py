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
from _pytest.outcomes import XFailed
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID
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

"""F7 slice 12 runtime-behavior regressions: x509/conftest.py, x509/test_attributes.py,
x509/test_core_ops.py routed through ``attr_or_record()``.

These are *behavior* tests, not analyzer-count tests: each proves that an omitted
provider attribute now produces a structured, mechanism-free classification record
(never a ``KeyError``/``AttributeError`` crash and never a silently degraded value fed
into a comparison), that independent oracles in the same test still run and report
correctly (the aggregate-oracle hazard), and that a genuinely present-but-wrong value
still hard-fails (the migration must not soften existing hard findings).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.x509.oid import NameOID as _NameOID

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_END_DATE,
    CKA_ISSUER,
    CKA_PUBLIC_KEY_INFO,
    CKA_SERIAL_NUMBER,
    CKA_START_DATE,
    CKA_SUBJECT,
    CKA_TRUSTED,
    CKA_VALUE,
    CKC_X_509,
)
from pkcs11_check.testcases.x509 import conftest as x509_conftest
from pkcs11_check.testcases.x509 import test_attributes as x509_test_attributes
from pkcs11_check.testcases.x509 import test_core_ops as x509_test_core_ops

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _make_cert() -> cx509.Certificate:
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name([cx509.NameAttribute(_NameOID.COMMON_NAME, "f7-s12-x509-core-test")])
    return (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(dt.datetime(2040, 1, 1, tzinfo=dt.UTC))
        .sign(key, _hashes.SHA256())
    )


_CERT = _make_cert()
_CERT_DER = _CERT.public_bytes(_ser.Encoding.DER)
_CERT_PEM = _CERT.public_bytes(_ser.Encoding.PEM).decode("ascii")


def _full_attr_values(cert: cx509.Certificate) -> dict[Any, Any]:
    """Ground-truth attribute values matching what verify_attribute_parity expects,
    so every un-omitted attribute independently reports a genuine match."""
    sn = cert.serial_number
    if sn == 0:
        serial = b"\x02\x01\x00"
    else:
        nb = sn.to_bytes((sn.bit_length() + 8) // 8, "big", signed=True)
        serial = b"\x02" + bytes([len(nb)]) + nb
    return {
        CKA_SUBJECT: cert.subject.public_bytes(_ser.Encoding.DER),
        CKA_ISSUER: cert.issuer.public_bytes(_ser.Encoding.DER),
        CKA_SERIAL_NUMBER: serial,
        CKA_START_DATE: cert.not_valid_before_utc.date().strftime("%Y%m%d"),
        CKA_END_DATE: cert.not_valid_after_utc.date().strftime("%Y%m%d"),
        CKA_PUBLIC_KEY_INFO: cert.public_key().public_bytes(
            _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo
        ),
    }


def _make_read_attributes(values: dict[Any, Any], omit: set[Any]) -> Any:
    """A fake ``read_attributes()`` that always CKR_OK's but omits ``omit`` from the
    returned mapping -- exactly the provider behavior F7 must turn into evidence
    instead of a KeyError crash or a silently degraded None."""

    def _read(_raw: Any, _sh: Any, _handle: Any, attrs: list[Any]) -> dict[Any, Any]:
        return {a: values[a] for a in attrs if a in values and a not in omit}

    return _read


@contextmanager
def _fake_so_session(_rs: Any, _config: Any) -> Iterator[int]:
    yield 5


def _assert_missing_attribute_record(rec: C.Classification, reason: str) -> None:
    assert rec.reason == reason
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == _SPEC_REF


# --------------------------------------------------------------------------------
# x509/conftest.py :: verify_attribute_parity (6 sites)
# --------------------------------------------------------------------------------


def test_parity_missing_mandatory_subject_is_not_operational_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_SUBJECT] -> attr_or_record: an omitted mandatory attribute is recorded
    (not_operational), the dependent SUBJECT==expected oracle is disabled, and every
    OTHER independent per-attribute oracle in the same call still runs and reports."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    values = _full_attr_values(_CERT)
    monkeypatch.setattr(
        x509_conftest, "read_attributes", _make_read_attributes(values, omit={CKA_SUBJECT})
    )

    parity = x509_conftest.verify_attribute_parity(
        object(), 1, 99, _CERT_DER, interface_version="3.0"
    )

    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")

    matches, p11_val, _expected_val, required = parity["SUBJECT"]
    assert matches is None
    assert p11_val is None
    assert required is True

    assert parity["ISSUER"][0] is True
    assert parity["SERIAL_NUMBER"][0] is True
    assert parity["START_DATE"][0] is True
    assert parity["END_DATE"][0] is True
    assert parity["PUBLIC_KEY_INFO"][0] is True


def test_parity_missing_optional_pubkey_info_is_honest_deviation_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_PUBLIC_KEY_INFO] -> attr_or_record: an omitted OPTIONAL attribute is
    honest_deviation (not not_operational), and every other independent oracle --
    including the mandatory ones -- still runs and reports correctly."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    values = _full_attr_values(_CERT)
    monkeypatch.setattr(
        x509_conftest,
        "read_attributes",
        _make_read_attributes(values, omit={CKA_PUBLIC_KEY_INFO}),
    )

    parity = x509_conftest.verify_attribute_parity(
        object(), 1, 99, _CERT_DER, interface_version="3.0"
    )

    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "honest_deviation")

    matches, p11_val, _expected_val, required = parity["PUBLIC_KEY_INFO"]
    assert matches is None
    assert p11_val is None
    assert required is False

    assert parity["SUBJECT"][0] is True
    assert parity["ISSUER"][0] is True
    assert parity["SERIAL_NUMBER"][0] is True


# --------------------------------------------------------------------------------
# x509/test_attributes.py :: TestCertificateAttributes.test_verify_attributes (3 sites)
# --------------------------------------------------------------------------------


def test_attrs_missing_value_is_not_operational_and_continues_to_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_VALUE] -> attr_or_record: an omitted CKA_VALUE must not crash the
    whole test before the CKA_CERTIFICATE_TYPE and subject/issuer/serial checks run,
    and the handle must still be destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 42
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_attributes, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_attributes, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    values: dict[Any, Any] = {
        CKA_CERTIFICATE_TYPE: CKC_X_509,
        CKA_SUBJECT: b"subj",
        CKA_ISSUER: b"iss",
        CKA_SERIAL_NUMBER: b"\x01",
    }
    monkeypatch.setattr(
        x509_test_attributes, "read_attributes", _make_read_attributes(values, omit={CKA_VALUE})
    )

    tc = {"id": "f7-s12-tc-value", "peer_certificate": _CERT_PEM, "expected_result": "SUCCESS"}
    x509_test_attributes.TestCertificateAttributes().test_verify_attributes(
        tc, _session(), None, "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_attrs_missing_loop_attributes_are_honest_deviation_and_loop_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """a[attr_id] -> attr_or_record inside the SUBJECT/ISSUER/SERIAL_NUMBER loop: an
    omission of ONE attribute must not stop the loop from evaluating the others --
    proven here by omitting TWO of the three and observing two independent records."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 43
    monkeypatch.setattr(x509_test_attributes, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_attributes, "destroy_quietly", lambda *a: None)
    values: dict[Any, Any] = {
        CKA_VALUE: b"Hello world!",  # mock sentinel -> CKA_VALUE compare is skipped
        CKA_CERTIFICATE_TYPE: CKC_X_509,
        CKA_SUBJECT: b"subj",
    }
    monkeypatch.setattr(
        x509_test_attributes,
        "read_attributes",
        _make_read_attributes(values, omit={CKA_ISSUER, CKA_SERIAL_NUMBER}),
    )

    tc = {"id": "f7-s12-tc-loop", "peer_certificate": _CERT_PEM, "expected_result": "SUCCESS"}
    x509_test_attributes.TestCertificateAttributes().test_verify_attributes(
        tc, _session(), None, "3.0"
    )

    records = C.get_records()
    assert len(records) == 2
    for rec in records:
        _assert_missing_attribute_record(rec, "honest_deviation")


# --------------------------------------------------------------------------------
# x509/test_attributes.py :: TestTrustedCertificateImportSO (1 site)
# --------------------------------------------------------------------------------


def test_so_trusted_missing_readback_is_not_operational_not_a_false_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs.get(CKA_TRUSTED) -> attr_or_record: an omitted CKA_TRUSTED must be
    recorded as an honest omission, NOT fed into the ``val is not True`` oracle as a
    degraded None (which would manufacture a false self_contradiction fail against a
    conformant provider that simply didn't report the attribute)."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 51
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_attributes, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_attributes, "so_session", _fake_so_session)
    monkeypatch.setattr(x509_test_attributes, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_attributes, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(
        x509_test_attributes,
        "load_limbo_testcases",
        lambda: [{"expected_result": "SUCCESS", "peer_certificate": _CERT_PEM}],
    )
    monkeypatch.setattr(x509_test_attributes, "read_attributes", _make_read_attributes({}, set()))

    x509_test_attributes.TestTrustedCertificateImportSO().test_so_import_trusted_cert(
        _session(), None, None, "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_so_trusted_present_false_still_hard_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present-but-wrong CKA_TRUSTED (module honored neither the SO trust request nor
    reports it truthfully) must stay a hard self_contradiction fail -- the migration
    must never downgrade an actual policy/lifecycle contradiction into an omission."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 52
    monkeypatch.setattr(x509_test_attributes, "skip_unless_cert_storage", lambda *a: None)
    monkeypatch.setattr(x509_test_attributes, "so_session", _fake_so_session)
    monkeypatch.setattr(x509_test_attributes, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(x509_test_attributes, "destroy_quietly", lambda *a: None)
    monkeypatch.setattr(
        x509_test_attributes,
        "load_limbo_testcases",
        lambda: [{"expected_result": "SUCCESS", "peer_certificate": _CERT_PEM}],
    )
    monkeypatch.setattr(
        x509_test_attributes,
        "read_attributes",
        _make_read_attributes({CKA_TRUSTED: False}, set()),
    )

    with pytest.raises(pytest.fail.Exception):
        x509_test_attributes.TestTrustedCertificateImportSO().test_so_import_trusted_cert(
            _session(), None, None, "3.0"
        )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].outcome == "fail"


# --------------------------------------------------------------------------------
# x509/test_core_ops.py (7 sites across several tests)
# --------------------------------------------------------------------------------


def test_core_ops_missing_certificate_type_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_CERTIFICATE_TYPE] -> attr_or_record: omission must not crash before
    the handle is destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 61
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_core_ops, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_core_ops, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(x509_test_core_ops, "read_attributes", _make_read_attributes({}, set()))

    x509_test_core_ops.TestCertificateImport().test_certificate_type_is_x509(
        _session(), _CERT_DER, "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")


def test_core_ops_missing_one_of_combined_attrs_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """attrs[CKA_SUBJECT]/attrs[CKA_ISSUER] read together in one call -> attr_or_record
    for each: an omission of ONE of the two must disable only the SUBJECT==ISSUER
    compare, not crash before the handle is destroyed."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    handle = 62
    destroyed: list[int] = []
    monkeypatch.setattr(x509_test_core_ops, "import_cert_object", lambda *a, **k: handle)
    monkeypatch.setattr(
        x509_test_core_ops, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h)
    )
    monkeypatch.setattr(
        x509_test_core_ops,
        "read_attributes",
        _make_read_attributes({CKA_SUBJECT: b"subj"}, set()),
    )

    x509_test_core_ops.TestCertificateExtractFields().test_self_signed_subject_equals_issuer(
        _session(), _CERT_DER, "3.0"
    )

    assert destroyed == [handle]
    records = C.get_records()
    assert len(records) == 1
    _assert_missing_attribute_record(records[0], "not_operational")

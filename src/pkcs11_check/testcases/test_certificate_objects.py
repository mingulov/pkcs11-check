"""CKO_CERTIFICATE object tests.

Verifies import of X.509 DER certificates, search by subject/issuer,
extraction of fields, and destruction.

Uses cryptography library to generate a self-signed cert at module scope
so tests are self-contained with no external fixture files.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pkcs11 import Attribute, CertificateType, ObjectClass
from pkcs11.util.x509 import decode_x509_certificate

pytestmark = pytest.mark.keymgmt


# ---------------------------------------------------------------------------
# Module-scoped fixtures: generate a self-signed cert once per test module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca_key() -> rsa.RSAPrivateKey:
    """RSA private key for the self-signed cert."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ca_cert_der(ca_key: rsa.RSAPrivateKey) -> bytes:
    """DER-encoded self-signed X.509 certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pkcs11-check"),
            x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11-check CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _unique_label(prefix: str = "cert") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCertificateImport:
    """Test importing X.509 DER certificates as CKO_CERTIFICATE objects."""

    def test_import_der_certificate(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Import a DER-encoded X.509 cert into the token."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        assert cert is not None

    def test_certificate_type_is_x509(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Imported cert has CKA_CERTIFICATE_TYPE = CKC_X_509."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        assert cert[Attribute.CERTIFICATE_TYPE] == CertificateType.X_509

    def test_import_with_extended_set(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Import with extended_set=True includes dates and key hashes."""
        template = decode_x509_certificate(ca_cert_der, extended_set=True)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        assert cert is not None


class TestCertificateSearch:
    """Test searching for certificate objects by various attributes."""

    def test_search_by_label(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Find certificate by CKA_LABEL."""
        label = _unique_label()
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = label
        p11_session.create_object(template)

        found = list(
            p11_session.get_objects(
                {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: label}
            )
        )
        assert len(found) >= 1

    def test_search_by_subject(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Find certificate by CKA_SUBJECT (DER-encoded)."""
        template = decode_x509_certificate(ca_cert_der)
        subject_der = template[Attribute.SUBJECT]
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        p11_session.create_object(template)

        found = list(
            p11_session.get_objects(
                {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.SUBJECT: subject_der}
            )
        )
        assert len(found) >= 1

    def test_search_by_issuer(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Find certificate by CKA_ISSUER (DER-encoded)."""
        template = decode_x509_certificate(ca_cert_der)
        issuer_der = template[Attribute.ISSUER]
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        p11_session.create_object(template)

        found = list(
            p11_session.get_objects(
                {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.ISSUER: issuer_der}
            )
        )
        assert len(found) >= 1

    def test_search_by_class(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Search by ObjectClass.CERTIFICATE finds our cert."""
        label = _unique_label()
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = label
        p11_session.create_object(template)

        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
        labels = [obj[Attribute.LABEL] for obj in found]
        assert label in labels


class TestCertificateExtractFields:
    """Test reading certificate fields back from the token."""

    def test_read_value_matches_der(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """CKA_VALUE matches the original DER bytes."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        assert cert[Attribute.VALUE] == ca_cert_der

    def test_subject_is_der_encoded(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """CKA_SUBJECT is DER-encoded and non-empty."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        subject = cert[Attribute.SUBJECT]
        assert isinstance(subject, bytes)
        assert len(subject) > 0

    def test_issuer_is_der_encoded(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """CKA_ISSUER is DER-encoded and non-empty."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        issuer = cert[Attribute.ISSUER]
        assert isinstance(issuer, bytes)
        assert len(issuer) > 0

    def test_serial_number_readable(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """CKA_SERIAL_NUMBER is readable and non-empty."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        serial = cert[Attribute.SERIAL_NUMBER]
        assert isinstance(serial, bytes)
        assert len(serial) > 0

    def test_self_signed_subject_equals_issuer(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Self-signed cert has SUBJECT == ISSUER."""
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = _unique_label()
        cert = p11_session.create_object(template)
        assert cert[Attribute.SUBJECT] == cert[Attribute.ISSUER]


class TestCertificateDestroy:
    """Test certificate object destruction."""

    def test_destroy_certificate(self, p11_session: Any, ca_cert_der: bytes) -> None:
        """Destroyed certificate is no longer findable."""
        label = _unique_label()
        template = decode_x509_certificate(ca_cert_der)
        template[Attribute.TOKEN] = False
        template[Attribute.LABEL] = label
        cert = p11_session.create_object(template)
        cert.destroy()

        found = list(
            p11_session.get_objects(
                {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: label}
            )
        )
        assert len(found) == 0

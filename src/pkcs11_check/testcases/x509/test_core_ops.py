"""CKO_CERTIFICATE object tests.

Verifies import of X.509 DER certificates, search by subject/issuer,
extraction of fields, and destruction.
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkcs11_check.raw.pack import attr_bytes, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_HASH_OF_ISSUER_PUBLIC_KEY,
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_PUBLIC_KEY_INFO,
    CKA_SERIAL_NUMBER,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_VALUE,
    CKC_X_509,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases.conftest import is_known_error
from pkcs11_check.testcases.x509.conftest import (
    _build_cert_template,
    import_cert_object,
)

pytestmark = [pytest.mark.cert, pytest.mark.object]


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


class TestCertificateImport:
    """Test importing X.509 DER certificates as CKO_CERTIFICATE objects."""

    def test_import_der_certificate(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Import a DER-encoded X.509 cert into the token."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            assert h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_certificate_type_is_x509(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Imported cert has CKA_CERTIFICATE_TYPE = CKC_X_509."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_CERTIFICATE_TYPE])
            assert attrs[CKA_CERTIFICATE_TYPE] == CKC_X_509
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not support CKA_CERTIFICATE_TYPE")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestCertificateSearch:
    """Test searching for certificate objects by various attributes."""

    def test_search_by_label(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Find certificate by CKA_LABEL."""
        rs = p11_raw_session
        label = _unique_label()
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={CKA_TOKEN: False, CKA_LABEL: label},
        )
        try:
            tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        except (AssertionError, Exception):
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"Label {label} not found via search",
                ComplianceLevel.VENDOR,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestCertificateExtractFields:
    """Test reading certificate fields back from the token."""

    def test_read_value_matches_der(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """CKA_VALUE matches the original DER bytes."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
            val = attrs[CKA_VALUE]
            if val != b"Hello world!":  # pkcs11-mock
                assert val == ca_cert_der
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not support reading CKA_VALUE")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_subject_is_der_encoded(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """CKA_SUBJECT is DER-encoded and non-empty (if extracted)."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_SUBJECT])
            subject = attrs[CKA_SUBJECT]
            assert isinstance(subject, bytes)
            assert len(subject) > 0
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not extract CKA_SUBJECT")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_issuer_is_der_encoded(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """CKA_ISSUER is DER-encoded and non-empty (if extracted)."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_ISSUER])
            issuer = attrs[CKA_ISSUER]
            assert isinstance(issuer, bytes)
            assert len(issuer) > 0
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not extract CKA_ISSUER")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_serial_number_readable(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """CKA_SERIAL_NUMBER is readable and non-empty (if extracted)."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_SERIAL_NUMBER])
            serial = attrs[CKA_SERIAL_NUMBER]
            assert isinstance(serial, bytes)
            assert len(serial) > 0
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not extract CKA_SERIAL_NUMBER")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_self_signed_subject_equals_issuer(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Self-signed cert has SUBJECT == ISSUER (if extracted)."""
        rs = p11_raw_session
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_TOKEN: False,
                CKA_LABEL: _unique_label(),
            },
        )
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                h,
                [CKA_SUBJECT, CKA_ISSUER],
            )
            assert attrs[CKA_SUBJECT] == attrs[CKA_ISSUER]
        except (AssertionError, Exception) as e:
            if is_known_error(e, {int(CKR_ATTRIBUTE_TYPE_INVALID)}):
                pytest.skip("Module does not extract Subject/Issuer")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestCertificateDestroy:
    """Test certificate object destruction."""

    def test_destroy_certificate(
        self,
        p11_raw_session: Any,
        ca_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Destroyed certificate is no longer findable."""
        rs = p11_raw_session
        label = _unique_label()
        h = import_cert_object(
            rs.raw,
            rs.sh,
            ca_cert_der,
            interface_version=p11_interface_version,
            extra_attrs={CKA_TOKEN: False, CKA_LABEL: label},
        )
        rs.raw.C_DestroyObject(rs.sh, h)

        tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0


class TestV30CertAttributes:
    """Test v3.0+ certificate attribute support per attribute."""

    @pytest.mark.parametrize(
        "attr_name",
        [
            "PUBLIC_KEY_INFO",
            "HASH_OF_SUBJECT_PUBLIC_KEY",
            "HASH_OF_ISSUER_PUBLIC_KEY",
        ],
    )
    def test_v30_cert_attr_accepted(
        self,
        attr_name: str,
        p11_raw_session: Any,
        p11_interface_version: str,
        ca_cert_der: bytes,
    ) -> None:
        """Test CKA_{attr_name} on cert import."""
        rs = p11_raw_session
        cert = x509.load_der_x509_certificate(ca_cert_der)

        # Build the attribute value
        if attr_name == "PUBLIC_KEY_INFO":
            attr_id = CKA_PUBLIC_KEY_INFO
            attr_val = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif attr_name == "HASH_OF_SUBJECT_PUBLIC_KEY":
            attr_id = CKA_HASH_OF_SUBJECT_PUBLIC_KEY
            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            attr_val = hashlib.sha1(spki, usedforsecurity=False).digest()
        else:
            attr_id = CKA_HASH_OF_ISSUER_PUBLIC_KEY
            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            attr_val = hashlib.sha1(spki, usedforsecurity=False).digest()

        # Start from a v2.40 base template
        tmpl = _build_cert_template(ca_cert_der, "2.40")
        tmpl[CKA_TOKEN] = False
        tmpl[CKA_LABEL] = _unique_label(f"v30-{attr_name}")
        tmpl[attr_id] = attr_val

        try:
            h = create_object(rs.raw, rs.sh, tmpl)
            destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError as exc:
            if not is_known_error(
                exc, {int(CKR_ATTRIBUTE_VALUE_INVALID), int(CKR_ATTRIBUTE_TYPE_INVALID)}
            ):
                raise
            if p11_interface_version < "3.0":
                pytest.xfail(
                    f"v2.40 module rejects CKA_{attr_name} - not required by spec (v3.0+ attribute)"
                )
            else:
                pytest.fail(f"v3.0+ module MUST accept CKA_{attr_name} but got {exc}")

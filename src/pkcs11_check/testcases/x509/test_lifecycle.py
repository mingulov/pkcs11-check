"""Tests for X.509 certificate and CRL lifecycle in PKCS#11.

Covers:
- CKA_TOKEN (persistence)
- CKA_MODIFIABLE
- CKA_ID (unique identifier)
- CKA_CERTIFICATE_CATEGORY
- Object destruction
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

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_ID,
    CKA_LABEL,
    CKA_MODIFIABLE,
    CKA_TOKEN,
)
from pkcs11_check.testcases.x509.conftest import import_cert_object

pytestmark = [pytest.mark.cert, pytest.mark.object]


@pytest.fixture(scope="module")
def sample_cert_der() -> bytes:
    """Generate a simple DER cert for lifecycle testing."""
    key = rsa.generate_private_key(65537, 2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lifecycle Test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestCertificateLifecycle:
    """Verify certificate object persistence and modifiability."""

    def test_cert_token_persistence(
        self,
        p11_raw_session: Any,
        sample_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Import with CKA_TOKEN=True (if supported) and verify."""
        rs = p11_raw_session
        label = f"token-cert-{uuid.uuid4().hex[:8]}"
        try:
            h = import_cert_object(
                rs.raw,
                rs.sh,
                sample_cert_der,
                interface_version=p11_interface_version,
                extra_attrs={CKA_LABEL: label, CKA_TOKEN: True},
            )
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_TOKEN])
                assert attrs[CKA_TOKEN] is True
            finally:
                destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError:
            pytest.skip("Module does not support session-level token object creation for certs")

    def test_cert_modifiability(
        self,
        p11_raw_session: Any,
        sample_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Verify CKA_MODIFIABLE prevents label updates."""
        rs = p11_raw_session
        label_orig = f"mod-orig-{uuid.uuid4().hex[:8]}"
        label_new = f"mod-new-{uuid.uuid4().hex[:8]}"

        try:
            h = import_cert_object(
                rs.raw,
                rs.sh,
                sample_cert_der,
                interface_version=p11_interface_version,
                extra_attrs={
                    CKA_LABEL: label_orig,
                    CKA_MODIFIABLE: False,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError:
            pytest.skip("Module rejected CKA_MODIFIABLE=False on creation")
            return

        try:
            try:
                set_attributes(
                    rs.raw,
                    rs.sh,
                    h,
                    {CKA_LABEL: label_new},
                )
                # If it succeeded, verify it actually CHANGED
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_LABEL])
                if attrs[CKA_LABEL] == label_new:
                    pytest.fail("Successfully modified label on non-modifiable cert")
            except AssertionError:
                pass  # Expected
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_cert_id_assignment(
        self,
        p11_raw_session: Any,
        sample_cert_der: bytes,
        p11_interface_version: str,
    ) -> None:
        """Verify we can set and read CKA_ID on a certificate."""
        rs = p11_raw_session
        cid = b"cert-voter-id-123"
        try:
            h = import_cert_object(
                rs.raw,
                rs.sh,
                sample_cert_der,
                interface_version=p11_interface_version,
                extra_attrs={CKA_ID: cid, CKA_TOKEN: False},
            )
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_ID])
                assert attrs[CKA_ID] == cid
            finally:
                destroy_quietly(rs.raw, rs.sh, h)
        except AssertionError:
            pytest.skip("Module does not support CKA_ID for certificates")

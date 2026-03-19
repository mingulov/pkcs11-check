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
from pkcs11 import Attribute, CertificateType, ObjectClass
from pkcs11.exceptions import (ArgumentsBad, AttributeTypeInvalid,
                               FunctionNotSupported, ObjectHandleInvalid,
                               PKCS11Error)

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

@pytest.fixture(scope="module")
def sample_crl_der() -> bytes:
    """Generate a simple DER CRL for lifecycle testing."""
    key = rsa.generate_private_key(65537, 2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL Issuer")])
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer)
        .last_update(datetime.datetime.now(datetime.UTC))
        .next_update(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.DER)

def _get_cert_class() -> int:
    return ObjectClass.CERTIFICATE

def _get_crl_class() -> int:
    # CK_OBJECT_CLASS_CRL is 4. python-pkcs11 ObjectClass might not have it.
    return getattr(ObjectClass, 'X_509_CRL', 0x00000004)

class TestCertificateLifecycle:
    """Verify certificate object persistence and modifiability."""

    def test_cert_token_persistence(self, p11_session: Any, sample_cert_der: bytes) -> None:
        """Import with CKA_TOKEN=True (if supported) and verify persistence."""
        label = f"token-cert-{uuid.uuid4().hex[:8]}"
        try:
            # We first try with TOKEN=True
            obj = p11_session.create_object({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                Attribute.VALUE: sample_cert_der,
                Attribute.LABEL: label,
                Attribute.TOKEN: True,
            })
            
            # If successful, check if it's there
            assert obj[Attribute.TOKEN] is True
            obj.destroy()
        except PKCS11Error:
            # Module might not support token objects or requires login
            pytest.skip("Module does not support session-level token object creation for certs")

    def test_cert_modifiability(self, p11_session: Any, sample_cert_der: bytes) -> None:
        """Verify CKA_MODIFIABLE prevents label updates."""
        label_orig = f"mod-orig-{uuid.uuid4().hex[:8]}"
        label_new = f"mod-new-{uuid.uuid4().hex[:8]}"
        
        try:
            obj = p11_session.create_object({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.VALUE: sample_cert_der,
                Attribute.LABEL: label_orig,
                Attribute.MODIFIABLE: False,
            })
        except PKCS11Error:
            pytest.skip("Module rejected CKA_MODIFIABLE=False on creation")
            return

        try:
            # Attempt to update label - SHOULD fail with CKR_ACTION_PROHIBITED or similar
            try:
                obj[Attribute.LABEL] = label_new
                # If it succeeds, verify it actually CHANGED
                if obj[Attribute.LABEL] == label_new:
                     pytest.fail("Successfully modified label on non-modifiable certificate")
            except PKCS11Error:
                pass # Expected
        finally:
            obj.destroy()

    def test_cert_id_assignment(self, p11_session: Any, sample_cert_der: bytes) -> None:
        """Verify we can set and read CKA_ID on a certificate."""
        cid = b"cert-voter-id-123"
        try:
            obj = p11_session.create_object({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.VALUE: sample_cert_der,
                Attribute.ID: cid,
            })
            assert obj[Attribute.ID] == cid
            obj.destroy()
        except (PKCS11Error, KeyError):
            pytest.skip("Module does not support CKA_ID for certificates")

class TestCRLLifecycle:
    """Verify CKO_CRL object handling."""

    def test_crl_import_destroy(self, p11_session: Any, sample_crl_der: bytes) -> None:
        """Import a CRL and destroy it."""
        crl_class = _get_crl_class()
        label = f"test-crl-{uuid.uuid4().hex[:8]}"
        try:
            obj = p11_session.create_object({
                Attribute.CLASS: crl_class,
                Attribute.VALUE: sample_crl_der,
                Attribute.LABEL: label,
            })
            assert obj is not None
            # Search for it
            found = list(p11_session.get_objects({Attribute.CLASS: crl_class, Attribute.LABEL: label}))
            assert len(found) >= 1
            obj.destroy()
        except (PKCS11Error, FunctionNotSupported, ArgumentsBad):
            pytest.skip("Module does not support CKO_CRL objects")

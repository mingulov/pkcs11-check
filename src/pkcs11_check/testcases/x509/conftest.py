"""Shared fixtures and utilities for X.509 certificate tests."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from pkcs11 import Attribute, CertificateType, ObjectClass
from pkcs11.exceptions import PKCS11Error, FunctionNotSupported, ArgumentsBad
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pkcs11_check.testcases.data import X509_LIMBO_DIR

_LIMBO_FILE = X509_LIMBO_DIR / "limbo.json"

def pem_to_der(pem: str | dict[str, Any] | None) -> bytes | None:
    """Convert PEM string (or Limbo cert/key dict) to DER bytes."""
    if pem is None:
        return None
    if isinstance(pem, dict):
        # Limbo certificates have 'cert' key, keys have 'key' key
        pem = pem.get("cert") or pem.get("key") or ""
    
    if not isinstance(pem, str) or not pem:
        return None
        
    try:
        lines = pem.strip().split("\n")
        # Handle cases where PEM is already just base64 or has headers
        b64 = "".join(line for line in lines if not line.startswith("-----"))
        return base64.b64decode(b64)
    except Exception:
        return None

def verify_attribute_parity(p11_obj: Any, der_data: bytes) -> dict[str, Any]:
    """Compare PKCS#11 attributes against ground truth from cryptography.
    
    Returns a dict of {attribute_name: (matches, p11_val, expected_val)}.
    """
    cert = x509.load_der_x509_certificate(der_data)
    results = {}
    
    # CKA_SUBJECT
    try:
        p11_subject = p11_obj[Attribute.SUBJECT]
        expected_subject = cert.subject.public_bytes(serialization.Encoding.DER)
        results['SUBJECT'] = (p11_subject == expected_subject, p11_subject.hex(), expected_subject.hex())
    except (PKCS11Error, KeyError):
        results['SUBJECT'] = (None, None, None)
        
    # CKA_ISSUER
    try:
        p11_issuer = p11_obj[Attribute.ISSUER]
        expected_issuer = cert.issuer.public_bytes(serialization.Encoding.DER)
        results['ISSUER'] = (p11_issuer == expected_issuer, p11_issuer.hex(), expected_issuer.hex())
    except (PKCS11Error, KeyError):
        results['ISSUER'] = (None, None, None)
        
    # CKA_SERIAL_NUMBER
    try:
        p11_serial = p11_obj[Attribute.SERIAL_NUMBER]
        # PKCS#11 CKA_SERIAL_NUMBER is DER-encoded INTEGER
        expected_serial = x509.load_der_x509_certificate(der_data).serial_number
        # DER encoding of integer: 0x02 <len> <bytes>
        # We can just use cryptography to encode a dummy to get the DER if needed, 
        # or just compare the values if python-pkcs11 handles conversion.
        # python-pkcs11 returns bytes for SERIAL_NUMBER if not mapped to int.
        # Actually it's mapped to handle_bytes in our new attributes.py.
        # So it SHOULD be the raw DER integer.
        
        # Helper to get DER integer bytes
        def to_der_int(n):
            b = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True)
            return b'\x02' + bytes([len(b)]) + b
            
        expected_serial_der = to_der_int(cert.serial_number)
        results['SERIAL_NUMBER'] = (p11_serial == expected_serial_der, p11_serial.hex() if p11_serial else None, expected_serial_der.hex())
    except (PKCS11Error, KeyError):
        results['SERIAL_NUMBER'] = (None, None, None)

    # v3.0+ attributes
    # CKA_PUBLIC_KEY_INFO
    try:
        p11_pk_info = p11_obj[Attribute.PUBLIC_KEY_INFO]
        expected_pk_info = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        results['PUBLIC_KEY_INFO'] = (p11_pk_info == expected_pk_info, p11_pk_info.hex() if p11_pk_info else None, expected_pk_info.hex())
    except (PKCS11Error, KeyError, AttributeError):
        results['PUBLIC_KEY_INFO'] = (None, None, None)

    # CKA_SKID (Subject Key Identifier)
    try:
        p11_skid = p11_obj[Attribute.SKID]
        # In cryptography, we extract the extension
        skid_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        expected_skid = skid_ext.key_identifier
        results['SKID'] = (p11_skid == expected_skid, p11_skid.hex() if p11_skid else None, expected_skid.hex())
    except (PKCS11Error, KeyError, x509.ExtensionNotFound):
        results['SKID'] = (None, None, None)

    return results

def get_crl_class(p11_session: Any) -> int | None:
    """Probe for the correct CKO_X_509_CRL value on this module."""
    # Common vendor values: 0x00000004 (NSS conflict!), 0x10000001, etc.
    # If the module doesn't support a specific class, applications use CKO_DATA.
    
    # We try to find any existing CRL first
    possible_classes = [0x00000004, 0x10000001, 0x10000002] # Add more if known
    for cls in possible_classes:
        try:
            objs = list(p11_session.get_objects({Attribute.CLASS: cls}))
            if objs:
                return cls
        except:
            continue
            
    # If nothing found, we return a default but warn about the 0x4 conflict
    return getattr(ObjectClass, 'X_509_CRL', 0x00000004)

def load_limbo_testcases() -> list[dict[str, Any]]:
    """Load all testcases from limbo.json."""
    if not _LIMBO_FILE.exists():
        return []
        
    with open(_LIMBO_FILE) as f:
        data = json.load(f)
        
    return data.get("testcases", [])

def get_unique_limbo_certs(cases: list[dict[str, Any]]) -> list[tuple[str, bytes]]:
    """Extract every unique DER certificate from limbo.json."""
    certs: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for tc in cases:
        chain = tc.get("peer_certificate_chain", []) or []
        # Support peer_certificate as either dict or str (old/new Limbo)
        peer = tc.get("peer_certificate")
        all_pems = [peer] + list(chain)
        
        # Add trusted and intermediates
        all_pems += list(tc.get("trusted_certs", []) or [])
        all_pems += list(tc.get("untrusted_intermediates", []) or [])
        
        for pem in all_pems:
            if not pem: continue
            der = pem_to_der(pem)
            if der and der not in seen:
                seen.add(der)
                certs.append((tc["id"], der))
    return certs

def get_unique_limbo_crls(cases: list[dict[str, Any]]) -> list[tuple[str, bytes]]:
    """Extract every unique DER CRL from limbo.json."""
    crls: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for tc in cases:
        for pem in tc.get("crls", []) or []:
            if not pem: continue
            der = pem_to_der(pem)
            if der and der not in seen:
                seen.add(der)
                crls.append((tc["id"], der))
    return crls

@pytest.fixture(scope="session")
def limbo_available() -> None:
    if not _LIMBO_FILE.exists():
        pytest.skip("x509-limbo data not found. Run scripts/fetch-optional-data.sh x509-limbo")

@pytest.fixture
def cert_support(p11_session: Any) -> bool:
    """Probe if the PKCS#11 module supports CKO_CERTIFICATE objects.
    
    Returns True if supported, False otherwise.
    Used to skip certificate tests on non-supporting modules.
    """
    # A very simple self-signed cert placeholder for probing
    # If the module rejects this with CKR_FUNCTION_NOT_SUPPORTED or template inconsistent
    # then we assume no certificate support.
    probe_der = b"\x30\x82\x01\x0a\x30\x82\x01\x21\x02\x01\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x1f\x31\x1d" # Truncated but enough to probe create_object
    try:
        obj = p11_session.create_object({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: 0,
            Attribute.VALUE: probe_der,
            Attribute.LABEL: "probe",
            Attribute.TOKEN: False,
        })
        obj.destroy()
        return True
    except (PKCS11Error, Exception):
        # Many modules return CKR_TEMPLATE_INCONSISTENT or CKR_DATA_INVALID
        # We check if they even support the class.
        try:
             # Just try finding anything of class CERTIFICATE
             list(p11_session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
             return True
        except (PKCS11Error, Exception):
             return False

@pytest.fixture(scope="session")
def all_limbo_cases(limbo_available: Any) -> list[dict[str, Any]]:
    return load_limbo_testcases()

@pytest.fixture
def limbo_filter():
    """Returns a function to filter limbo testcases."""
    def _filter(cases: list[dict[str, Any]], 
                features: list[str] | None = None, 
                importance: list[str] | None = None,
                expected_result: str | None = None,
                limit: int | None = None) -> list[dict[str, Any]]:
        result = cases
        if features:
            result = [tc for tc in result if any(f in tc.get("features", []) for f in features)]
        if importance:
            result = [tc for tc in result if tc.get("importance") in importance]
        if expected_result:
            result = [tc for tc in result if tc.get("expected_result") == expected_result]
        
        if limit:
            result = result[:limit]
        return result
    return _filter

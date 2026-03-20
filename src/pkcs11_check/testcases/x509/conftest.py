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
from pkcs11.util.x509 import decode_x509_certificate

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

def verify_attribute_parity(p11_obj: Any, der_data: bytes, interface_version: str = "2.40") -> dict[str, Any]:
    """Compare PKCS#11 attributes against ground truth from cryptography.
    
    Returns a dict of {attribute_name: (matches, p11_val, expected_val, required)}.
    'required' is based on the OASIS spec for CKC_X_509.
    """
    cert = x509.load_der_x509_certificate(der_data)
    results = {}
    
    def _to_hex(val: Any) -> str:
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        return str(val)

    # CKA_SUBJECT (Mandatory)
    try:
        p11_subject = p11_obj[Attribute.SUBJECT]
        expected_subject = cert.subject.public_bytes(serialization.Encoding.DER)
        results['SUBJECT'] = (p11_subject == expected_subject, _to_hex(p11_subject), _to_hex(expected_subject), True)
    except (PKCS11Error, KeyError):
        results['SUBJECT'] = (None, None, _to_hex(cert.subject.public_bytes(serialization.Encoding.DER)), True)
        
    # CKA_ISSUER (Mandatory in v3.0+)
    try:
        p11_issuer = p11_obj[Attribute.ISSUER]
        expected_issuer = cert.issuer.public_bytes(serialization.Encoding.DER)
        results['ISSUER'] = (p11_issuer == expected_issuer, _to_hex(p11_issuer), _to_hex(expected_issuer), True)
    except (PKCS11Error, KeyError):
        results['ISSUER'] = (None, None, _to_hex(cert.issuer.public_bytes(serialization.Encoding.DER)), True)
        
    # CKA_SERIAL_NUMBER (Mandatory in v3.0+)
    try:
        p11_serial = p11_obj[Attribute.SERIAL_NUMBER]
        def to_der_int(n):
            if n == 0: return b'\x02\x01\x00'
            b = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True)
            return b'\x02' + bytes([len(b)]) + b
            
        expected_serial_der = to_der_int(cert.serial_number)
        results['SERIAL_NUMBER'] = (p11_serial == expected_serial_der, _to_hex(p11_serial), _to_hex(expected_serial_der), True)
    except (PKCS11Error, KeyError):
        results['SERIAL_NUMBER'] = (None, None, _to_hex(to_der_int(cert.serial_number)), True)

    # CKA_START_DATE (Optional, default empty)
    try:
        p11_start = p11_obj[Attribute.START_DATE]
        # Use UTC for modern cryptography
        expected_start = cert.not_valid_before_utc.strftime("%Y%m%d").encode("ascii")
        results['START_DATE'] = (p11_start == expected_start if p11_start else None, _to_hex(p11_start), _to_hex(expected_start), False)
    except (PKCS11Error, KeyError, AttributeError):
        results['START_DATE'] = (None, None, None, False)

    # CKA_END_DATE (Optional, default empty)
    try:
        p11_end = p11_obj[Attribute.END_DATE]
        expected_end = cert.not_valid_after_utc.strftime("%Y%m%d").encode("ascii")
        results['END_DATE'] = (p11_end == expected_end if p11_end else None, _to_hex(p11_end), _to_hex(expected_end), False)
    except (PKCS11Error, KeyError, AttributeError):
        results['END_DATE'] = (None, None, None, False)

    # v3.0+ attributes (optional — many modules don't populate these even on v3.0+)
    # CKA_PUBLIC_KEY_INFO
    try:
        p11_pk_info = p11_obj[Attribute.PUBLIC_KEY_INFO]
        expected_pk_info = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        results['PUBLIC_KEY_INFO'] = (p11_pk_info == expected_pk_info if p11_pk_info else None, _to_hex(p11_pk_info), _to_hex(expected_pk_info), False)
    except (PKCS11Error, KeyError, AttributeError):
        results['PUBLIC_KEY_INFO'] = (None, None, None, False)

    # CKA_SKID (Optional)
    try:
        p11_skid = p11_obj[Attribute.SKID]
        skid_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        expected_skid = skid_ext.key_identifier
        results['SKID'] = (p11_skid == expected_skid if p11_skid else None, _to_hex(p11_skid), _to_hex(expected_skid), False)
    except (PKCS11Error, KeyError, x509.ExtensionNotFound):
        results['SKID'] = (None, None, None, False)

    return results

def x509_to_p11_template(der_data: bytes, interface_version: str = "2.40") -> dict[Attribute, Any]:
    """Convert DER certificate to PKCS#11 attribute template.
    
    Filters out attributes not supported by the specified interface version.
    """
    template = decode_x509_certificate(der_data)
    
    # Filter out v3.0+ attributes if interface is older
    v30_attrs = {
        Attribute.PUBLIC_KEY_INFO,
        Attribute.SKID,
        Attribute.AKID,
        Attribute.HASH_OF_SUBJECT_PUBLIC_KEY,
        Attribute.HASH_OF_ISSUER_PUBLIC_KEY,
    }
    
    if interface_version < "3.0":
        for attr in v30_attrs:
            if attr in template:
                del template[attr]
                
    return template

def import_cert_object(
    p11_session: Any,
    der_data: bytes,
    interface_version: str = "2.40",
    extra_attrs: dict[Attribute, Any] | None = None,
) -> Any:
    """Import a DER certificate into PKCS#11, handling v3.0+ attribute bugs.

    Tries with full v3.0+ attributes first. If the module returns
    AttributeValueInvalid (known Kryoptic bug), retries with v3.0+ attrs
    stripped and records a compliance note.
    """
    from pkcs11.exceptions import AttributeValueInvalid
    from pkcs11_check.compliance import note, ComplianceLevel

    template = x509_to_p11_template(der_data, interface_version=interface_version)
    if extra_attrs:
        template.update(extra_attrs)

    try:
        return p11_session.create_object(template)
    except AttributeValueInvalid:
        if interface_version < "3.0":
            raise
        # Retry with v3.0+ attributes stripped
        template_v240 = x509_to_p11_template(der_data, interface_version="2.40")
        if extra_attrs:
            template_v240.update(extra_attrs)
        obj = p11_session.create_object(template_v240)
        note(
            "Module claims v3.0+ but rejects v3.0+ cert attributes "
            "(CKA_PUBLIC_KEY_INFO/CKA_SKID/CKA_AKID) — falling back to v2.40 template",
            ComplianceLevel.VENDOR,
        )
        return obj


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
        except Exception:
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
def cert_support(p11_session: Any, p11_interface_version: str) -> bool:
    """Probe if the PKCS#11 module supports CKO_CERTIFICATE objects.
    
    Returns True if supported, False otherwise.
    Used to skip certificate tests on non-supporting modules.
    """
    # A very simple self-signed cert placeholder for probing
    # If the module rejects this with CKR_FUNCTION_NOT_SUPPORTED or template inconsistent
    # then we assume no certificate support.
    # Generate a minimal valid self-signed cert for probing
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.x509.oid import NameOID as _NameOID
        import datetime as _dt

        key = _rsa.generate_private_key(65537, 2048)
        subject = issuer = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "probe")])
        probe_cert = (
            _x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.UTC))
            .not_valid_after(_dt.datetime.now(_dt.UTC) + _dt.timedelta(days=1))
            .sign(key, _hashes.SHA256())
        )
        probe_der = probe_cert.public_bytes(_ser.Encoding.DER)
    except Exception:
        return False

    try:
        obj = import_cert_object(p11_session, probe_der, interface_version=p11_interface_version,
                                 extra_attrs={Attribute.LABEL: "probe", Attribute.TOKEN: False})
        obj.destroy()
        return True
    except (PKCS11Error, Exception):
        try:
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

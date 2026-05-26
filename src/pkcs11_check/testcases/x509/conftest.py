"""Shared fixtures and utilities for X.509 certificate tests."""

from __future__ import annotations

import base64
import datetime
import json
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_END_DATE,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_PUBLIC_KEY_INFO,
    CKA_SERIAL_NUMBER,
    CKA_START_DATE,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_VALUE,
    CKC_X_509,
    CKO_CERTIFICATE,
)
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


def _parse_cert_attrs(der_data: bytes) -> dict[int, Any]:
    """Extract PKCS#11 cert attributes from DER bytes using cryptography lib."""
    cert = x509.load_der_x509_certificate(der_data)
    attrs: dict[int, Any] = {}
    attrs[CKA_SUBJECT] = cert.subject.public_bytes(serialization.Encoding.DER)
    attrs[CKA_ISSUER] = cert.issuer.public_bytes(serialization.Encoding.DER)
    # Serial as DER INTEGER
    sn = cert.serial_number
    if sn == 0:
        attrs[CKA_SERIAL_NUMBER] = b"\x02\x01\x00"
    else:
        b = sn.to_bytes((sn.bit_length() + 8) // 8, "big", signed=True)
        attrs[CKA_SERIAL_NUMBER] = b"\x02" + bytes([len(b)]) + b
    return attrs


def verify_attribute_parity(
    raw: Any,
    sh: int,
    handle: int,
    der_data: bytes,
    interface_version: str = "2.40",
) -> dict[str, Any]:
    """Compare PKCS#11 attributes against ground truth from cryptography.

    Returns a dict of {attribute_name: (matches, p11_val, expected_val, required)}.
    'required' is based on the OASIS spec for CKC_X_509.
    """
    cert = x509.load_der_x509_certificate(der_data)
    results: dict[str, Any] = {}

    def _to_hex(val: Any) -> str:
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        return str(val)

    # CKA_SUBJECT (Mandatory)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_SUBJECT])
        p11_subject = attrs[CKA_SUBJECT]
        expected_subject = cert.subject.public_bytes(serialization.Encoding.DER)
        results["SUBJECT"] = (
            p11_subject == expected_subject,
            _to_hex(p11_subject),
            _to_hex(expected_subject),
            True,
        )
    except AssertionError:
        results["SUBJECT"] = (
            None,
            None,
            _to_hex(cert.subject.public_bytes(serialization.Encoding.DER)),
            True,
        )

    # CKA_ISSUER (Mandatory in v3.0+)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_ISSUER])
        p11_issuer = attrs[CKA_ISSUER]
        expected_issuer = cert.issuer.public_bytes(serialization.Encoding.DER)
        results["ISSUER"] = (
            p11_issuer == expected_issuer,
            _to_hex(p11_issuer),
            _to_hex(expected_issuer),
            True,
        )
    except AssertionError:
        results["ISSUER"] = (
            None,
            None,
            _to_hex(cert.issuer.public_bytes(serialization.Encoding.DER)),
            True,
        )

    # CKA_SERIAL_NUMBER (Mandatory in v3.0+)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_SERIAL_NUMBER])
        p11_serial = attrs[CKA_SERIAL_NUMBER]

        def to_der_int(n: int) -> bytes:
            if n == 0:
                return b"\x02\x01\x00"
            b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
            return b"\x02" + bytes([len(b)]) + b

        expected_serial_der = to_der_int(cert.serial_number)
        results["SERIAL_NUMBER"] = (
            p11_serial == expected_serial_der,
            _to_hex(p11_serial),
            _to_hex(expected_serial_der),
            True,
        )
    except AssertionError:
        results["SERIAL_NUMBER"] = (None, None, None, True)

    # CKA_START_DATE (Optional)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_START_DATE])
        p11_start = attrs[CKA_START_DATE]
        expected_start = cert.not_valid_before_utc.date()
        if not p11_start:
            results["START_DATE"] = (None, "empty", str(expected_start), False)
        else:
            results["START_DATE"] = (
                str(p11_start) == expected_start.strftime("%Y%m%d"),
                str(p11_start),
                str(expected_start),
                False,
            )
    except AssertionError:
        results["START_DATE"] = (None, None, None, False)

    # CKA_END_DATE (Optional)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_END_DATE])
        p11_end = attrs[CKA_END_DATE]
        expected_end = cert.not_valid_after_utc.date()
        if not p11_end:
            results["END_DATE"] = (None, "empty", str(expected_end), False)
        else:
            results["END_DATE"] = (
                str(p11_end) == expected_end.strftime("%Y%m%d"),
                str(p11_end),
                str(expected_end),
                False,
            )
    except AssertionError:
        results["END_DATE"] = (None, None, None, False)

    # CKA_PUBLIC_KEY_INFO (v3.0+)
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_PUBLIC_KEY_INFO])
        p11_pk_info = attrs[CKA_PUBLIC_KEY_INFO]
        expected_pk_info = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        results["PUBLIC_KEY_INFO"] = (
            p11_pk_info == expected_pk_info if p11_pk_info else None,
            _to_hex(p11_pk_info),
            _to_hex(expected_pk_info),
            False,
        )
    except AssertionError:
        results["PUBLIC_KEY_INFO"] = (None, None, None, False)

    return results


def _build_cert_template(
    der_data: bytes,
    interface_version: str = "2.40",
    extra_attrs: dict[int, Any] | None = None,
) -> dict[int, Any]:
    """Build a CKO_CERTIFICATE template from DER data."""
    cert = x509.load_der_x509_certificate(der_data)

    tmpl: dict[int, Any] = {
        CKA_CLASS: CKO_CERTIFICATE,
        CKA_CERTIFICATE_TYPE: CKC_X_509,
        CKA_VALUE: der_data,
        CKA_SUBJECT: cert.subject.public_bytes(serialization.Encoding.DER),
        CKA_ISSUER: cert.issuer.public_bytes(serialization.Encoding.DER),
    }

    # Serial as DER INTEGER
    sn = cert.serial_number
    if sn == 0:
        tmpl[CKA_SERIAL_NUMBER] = b"\x02\x01\x00"
    else:
        b = sn.to_bytes((sn.bit_length() + 8) // 8, "big", signed=True)
        tmpl[CKA_SERIAL_NUMBER] = b"\x02" + bytes([len(b)]) + b

    # v3.0+ attributes
    if interface_version >= "3.0":
        try:
            tmpl[CKA_PUBLIC_KEY_INFO] = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError, UnsupportedAlgorithm):
            pass

    if extra_attrs:
        tmpl.update(extra_attrs)

    return tmpl


def import_cert_object(
    raw: Any,
    sh: int,
    der_data: bytes,
    interface_version: str = "2.40",
    extra_attrs: dict[int, Any] | None = None,
) -> int:
    """Import a DER certificate into PKCS#11, handling v3.0+ attribute bugs.

    Returns object handle.

    Tries with full v3.0+ attributes first. If the module returns
    CKR_ATTRIBUTE_VALUE_INVALID, retries with v3.0+ attrs stripped.
    """
    from pkcs11_check.compliance import ComplianceLevel, note

    tmpl = _build_cert_template(der_data, interface_version, extra_attrs)

    try:
        return create_object(raw, sh, tmpl)
    except AssertionError as e:
        if "CKR_ATTRIBUTE_VALUE_INVALID" not in str(e):
            raise
        if interface_version < "3.0":
            raise
        # Retry with v3.0+ attributes stripped
        tmpl_v240 = _build_cert_template(der_data, "2.40", extra_attrs)
        h = create_object(raw, sh, tmpl_v240)
        note(
            "Module claims v3.0+ but rejects v3.0+ cert attributes "
            "(CKA_PUBLIC_KEY_INFO) - falling back to v2.40 template",
            ComplianceLevel.VENDOR,
        )
        return h


def import_cert_raw(
    raw: Any,
    sh: int,
    der_data: bytes,
    extra_attrs: dict[int, Any] | None = None,
) -> tuple[int, bool]:
    """Import a DER certificate using a minimal template (CKA_VALUE only).

    Returns (handle, needed_explicit_attrs).
    """
    from asn1crypto.x509 import Certificate as Asn1Cert  # type: ignore[import-untyped]

    minimal: dict[int, Any] = {
        CKA_CLASS: CKO_CERTIFICATE,
        CKA_CERTIFICATE_TYPE: CKC_X_509,
        CKA_VALUE: der_data,
    }
    if extra_attrs:
        minimal.update(extra_attrs)

    try:
        return create_object(raw, sh, minimal), False
    except AssertionError as e:
        if "CKR_TEMPLATE_INCOMPLETE" not in str(e):
            raise

    # Module requires explicit SUBJECT/ISSUER/SERIAL_NUMBER
    cert_asn1 = Asn1Cert.load(der_data)
    full: dict[int, Any] = dict(minimal)
    full[CKA_SUBJECT] = cert_asn1.subject.dump()
    full[CKA_ISSUER] = cert_asn1.issuer.dump()
    full[CKA_SERIAL_NUMBER] = cert_asn1["tbs_certificate"]["serial_number"].dump()
    return create_object(raw, sh, full), True


def load_limbo_testcases() -> list[dict[str, Any]]:
    """Load all testcases from limbo.json."""
    if not _LIMBO_FILE.exists():
        return []

    with open(_LIMBO_FILE) as f:
        data = json.load(f)

    cases: list[dict[str, Any]] = data.get("testcases", [])
    return cases


def get_unique_limbo_certs(
    cases: list[dict[str, Any]],
) -> list[tuple[str, bytes]]:
    """Extract every unique DER certificate from limbo.json."""
    certs: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for tc in cases:
        chain = tc.get("peer_certificate_chain", []) or []
        peer = tc.get("peer_certificate")
        all_pems = [peer] + list(chain)

        all_pems += list(tc.get("trusted_certs", []) or [])
        all_pems += list(tc.get("untrusted_intermediates", []) or [])

        for pem in all_pems:
            if not pem:
                continue
            der = pem_to_der(pem)
            if der and der not in seen:
                seen.add(der)
                certs.append((tc["id"], der))
    return certs


def get_unique_limbo_crls(
    cases: list[dict[str, Any]],
) -> list[tuple[str, bytes]]:
    """Extract every unique DER CRL from limbo.json."""
    crls: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    for tc in cases:
        for pem in tc.get("crls", []) or []:
            if not pem:
                continue
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
def cert_support(
    p11_raw_session: Any,
    p11_interface_version: str,
) -> bool:
    """Probe if the PKCS#11 module supports CKO_CERTIFICATE objects."""
    rs = p11_raw_session
    key = rsa.generate_private_key(65537, 2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe")])
    probe_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    probe_der = probe_cert.public_bytes(serialization.Encoding.DER)

    try:
        h = import_cert_object(
            rs.raw,
            rs.sh,
            probe_der,
            interface_version=p11_interface_version,
            extra_attrs={
                CKA_LABEL: "probe",
                CKA_TOKEN: False,
            },
        )
        destroy_quietly(rs.raw, rs.sh, h)
        return True
    except AssertionError:
        return False


@pytest.fixture(scope="session")
def all_limbo_cases(limbo_available: Any) -> list[dict[str, Any]]:
    return load_limbo_testcases()


@pytest.fixture
def limbo_filter() -> Any:
    """Returns a function to filter limbo testcases."""

    def _filter(
        cases: list[dict[str, Any]],
        features: list[str] | None = None,
        importance: list[str] | None = None,
        expected_result: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
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

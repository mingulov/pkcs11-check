"""Shared fixtures and utilities for X.509 certificate tests."""

from __future__ import annotations

import base64
import functools
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.recipes import (
    create_object,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CERTIFICATE_CATEGORY,
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_END_DATE,
    CKA_ID,
    CKA_ISSUER,
    CKA_LABEL,
    CKA_PUBLIC_KEY_INFO,
    CKA_SERIAL_NUMBER,
    CKA_START_DATE,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_VALUE,
    CKC_X_509,
    CKO_CERTIFICATE,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases.data import X509_LIMBO_DIR, load_json_cached

_LIMBO_FILE = X509_LIMBO_DIR / "limbo.json"

# Clean cert-storage refusal codes: the module is declaring it won't store this shape.
# Anything else (or a crash) is NOT a clean refusal -> propagate as a real finding.
# CKR_KEY_HANDLE_INVALID is the broadest entry: it is non-spec for a no-input-handle
# C_CreateObject, but some modules use it to mean "I don't store cert objects".
# It is still a *clean* refusal (recorded once per template as xfail by test_cert_storage,
# which flags it as non-spec); the gate skips only when EVERY template refuses, so a single
# odd code never triggers a false-skip.
_CERT_STORAGE_REFUSAL_CKRS: tuple[int, ...] = (
    int(CKR_KEY_HANDLE_INVALID),
    int(CKR_TEMPLATE_INCOMPLETE),
    int(CKR_TEMPLATE_INCONSISTENT),
    int(CKR_ATTRIBUTE_VALUE_INVALID),
    int(CKR_ATTRIBUTE_TYPE_INVALID),
    int(CKR_FUNCTION_NOT_SUPPORTED),
    int(CKR_ARGUMENTS_BAD),
    int(CKR_USER_TYPE_INVALID),
)

# Non-clean-refusal codes a KMS-style module returns when it stores no certificate
# objects at all. These are NOT added to the refusal set above (a refusal -> silent
# skip would risk hiding a real cert-storage bug); instead the gate records them as a
# not_operational xfail (a recorded deviation), so the behavior stays visible but does
# not surface as a raw failure (reserved-reason backlog).
_CERT_STORAGE_NOT_OPERATIONAL_CKRS: tuple[int, ...] = (int(CKR_GENERAL_ERROR),)

# slot_id -> can store a cert object. Process-global per slot (cert-storage capability is
# stable for a slot across a run), mirroring the _IMPORT_SHAPE_WINNERS cache convention.
_CERT_STORAGE_SUPPORTED: dict[int, bool] = {}

# C_GetAttributeValue may report these cleanly when a derived attribute is not
# available.  Any other CK_RV is an unexpected provider/harness failure.
_ATTRIBUTE_UNAVAILABLE_RVS: frozenset[int] = frozenset(
    {int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)}
)


def classify_positive_ckr(exc: CkrAssertionError, *, label: str, summary: str) -> None:
    """Expose a positive-operation refusal without trusting undefined CK_RVs."""
    if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
        classify(
            "self_contradiction",
            kind="metadata",
            label=label,
            actual=exc.rv,
            summary=f"{summary}: undefined CK_RV {exc.rv:#x}",
        )
    xfail_as(
        "not_operational",
        kind="metadata",
        label=label,
        actual=exc.rv,
        summary=f"{summary}: clean refusal with CK_RV {exc.rv:#x}",
    )


@functools.cache
def _canonical_self_signed_cert_der() -> bytes:
    """A minimal self-signed RSA certificate, generated once, for capability probing
    (mirrors the ca_cert_der fixture pattern in test_core_ops.py)."""
    import datetime as _dt

    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID as _NameOID

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = cx509.Name([cx509.NameAttribute(_NameOID.COMMON_NAME, "p11chk-cert-probe")])
    cert = (
        cx509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(_dt.datetime(2020, 1, 1))
        .not_valid_after(_dt.datetime(2040, 1, 1))
        .sign(key, _hashes.SHA256())
    )
    return cert.public_bytes(_ser.Encoding.DER)


@functools.cache
def _san_only_cert_der() -> bytes:
    """A subject-less X.509 cert (RFC 5280 4.1.2.6): EMPTY subject DN, NON-empty issuer,
    and a critical subjectAltName. Only the subject is empty -- the non-empty issuer
    isolates the subject-less variable. Signed by its own key (not a valid PKI chain;
    irrelevant to a storage test)."""
    import datetime as _dt

    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID as _NameOID

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = cx509.Name([cx509.NameAttribute(_NameOID.COMMON_NAME, "p11chk-test-issuer")])
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([]))  # empty subject DN; identity is in the SAN
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(_dt.datetime(2020, 1, 1))
        .not_valid_after(_dt.datetime(2040, 1, 1))
        .add_extension(
            cx509.SubjectAlternativeName([cx509.RFC822Name("p11chk@example.com")]),
            critical=True,
        )
        .sign(key, _hashes.SHA256())
    )
    return cert.public_bytes(_ser.Encoding.DER)


def _minimal_cert_template(der: bytes) -> dict[int, Any]:
    """A spec-INCOMPLETE cert template that OMITS the mandatory CKA_SUBJECT (CKA_VALUE only).
    Per the OASIS PKCS#11 certificate-objects spec, CKA_SUBJECT footnote ^1^ MUST be
    specified at creation, so a conformant module rejects this with
    CKR_TEMPLATE_INCOMPLETE. Used by the negative conformance test and as the probe's
    last-resort fallback."""
    return {CKA_CLASS: CKO_CERTIFICATE, CKA_CERTIFICATE_TYPE: CKC_X_509, CKA_VALUE: der}


def cert_storage_templates(der: bytes) -> list[tuple[str, dict[int, Any]]]:
    """The spec-complete (CKA_SUBJECT present) cert templates -- single source of truth
    shared by the capability probe and the characterization suite. The spec-incomplete
    omit-CKA_SUBJECT template is NOT here; it is a negative case (_minimal_cert_template)."""
    full = _build_cert_template(der)  # adds SUBJECT/ISSUER/SERIAL (+ v3.0 PUBLIC_KEY_INFO)
    san_only = _build_cert_template(_san_only_cert_der())  # CKA_SUBJECT present = empty Name
    return [
        ("full", full),
        ("full+label", {**full, CKA_LABEL: b"p11chk-cert"}),
        ("full+id", {**full, CKA_ID: b"\x01\x02\x03\x04"}),
        ("full+session", {**full, CKA_TOKEN: False}),
        ("full+token", {**full, CKA_TOKEN: True}),
        ("full+trusted_false", {**full, CKA_TRUSTED: False}),
        ("full+category", {**full, CKA_CERTIFICATE_CATEGORY: 0}),
        ("san_only_empty_subject", san_only),
    ]


def attempt_store_cert(rs: Any, template: dict[int, Any]) -> tuple[int | None, int | None]:
    """Try to store one cert object. Returns ``(handle, None)`` on success (caller
    destroys), or ``(None, rv)`` on a CLEAN cert-storage refusal. A non-refusal CKR or
    a crash propagates (real finding, never swallowed). Shared by probe and suite."""
    from pkcs11_check.raw.recipes import create_object as _create_object
    from pkcs11_check.raw.rv import CkrAssertionError as _CkrAssertionError

    try:
        return _create_object(rs.raw, rs.sh, template), None
    except _CkrAssertionError as exc:
        if exc.rv not in _CERT_STORAGE_REFUSAL_CKRS:
            raise
        return None, exc.rv


def cert_storage_supported(rs: Any) -> bool:
    """Cached behavioral probe: can the module store ANY certificate object? Tries every
    cert_storage_templates() shape, then the spec-incomplete omit-CKA_SUBJECT minimal
    template as a last-resort fallback (a module that only accepts the minimal template --
    which import_cert_raw also tries first -- is still detected as supported). True on first
    success, False ONLY if all are cleanly refused (exhaustive). Non-refusal CKR propagates."""
    cached = _CERT_STORAGE_SUPPORTED.get(rs.slot_id)
    if cached is not None:
        return cached

    from pkcs11_check.raw.recipes import destroy_quietly as _destroy_quietly

    der = _canonical_self_signed_cert_der()
    candidates = [tmpl for _n, tmpl in cert_storage_templates(der)]
    candidates.append(_minimal_cert_template(der))  # last-resort fallback
    supported = False
    for tmpl in candidates:
        handle, _rv = attempt_store_cert(rs, tmpl)
        if handle is not None:
            _destroy_quietly(rs.raw, rs.sh, handle)
            supported = True
            break
    _CERT_STORAGE_SUPPORTED[rs.slot_id] = supported
    return supported


def skip_unless_cert_storage(rs: Any) -> None:
    """Skip when the module cannot store certificate objects at all (probe-established).

    If the probe fails with a non-clean-refusal CKR (a KMS that returns the generic
    CKR_GENERAL_ERROR for every cert object), record a not_operational xfail rather than
    raising raw at the gate: the module presents as a token but cert-object storage is
    not operational. A non-CKR error still propagates (real / harness bug).
    """
    import pytest as _pytest

    from pkcs11_check.raw.rv import CkrAssertionError as _CkrAssertionError
    from pkcs11_check.testcases.conftest import xfail_if_known_ckr as _xfail_if_known_ckr

    try:
        supported = cert_storage_supported(rs)
    except _CkrAssertionError as exc:
        _xfail_if_known_ckr(
            exc,
            _CERT_STORAGE_NOT_OPERATIONAL_CKRS,
            "cert-object storage not operational (probe)",
        )
        raise
    if not supported:
        _pytest.skip("module cannot store CKO_CERTIFICATE objects (cert-storage probe)")


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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["SUBJECT"] = (
            None,
            None,
            _to_hex(cert.subject.public_bytes(serialization.Encoding.DER)),
            True,
        )
    except KeyError:
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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["ISSUER"] = (
            None,
            None,
            _to_hex(cert.issuer.public_bytes(serialization.Encoding.DER)),
            True,
        )
    except KeyError:
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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["SERIAL_NUMBER"] = (None, None, None, True)
    except KeyError:
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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["START_DATE"] = (None, None, None, False)
    except KeyError:
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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["END_DATE"] = (None, None, None, False)
    except KeyError:
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
    except CkrAssertionError as exc:
        if exc.rv not in _ATTRIBUTE_UNAVAILABLE_RVS:
            raise
        results["PUBLIC_KEY_INFO"] = (None, None, None, False)
    except KeyError:
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
    except CkrAssertionError as e:
        if e.rv != int(CKR_ATTRIBUTE_VALUE_INVALID):
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
    except CkrAssertionError as e:
        if e.rv != int(CKR_TEMPLATE_INCOMPLETE):
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

    data = load_json_cached(_LIMBO_FILE)

    cases: list[dict[str, Any]] = data.get("testcases", [])
    for tc in cases:
        tc["_source"] = "x509:limbo.json"
        tc["_vector_id"] = f"id={tc.get('id')}"
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
def cert_support(p11_raw_session: Any) -> bool:
    """Require the shared exhaustive CKO_CERTIFICATE storage probe."""
    skip_unless_cert_storage(p11_raw_session)
    return True


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

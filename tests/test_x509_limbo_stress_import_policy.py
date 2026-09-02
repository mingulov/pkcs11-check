"""Regression tests for x509-limbo stress import error handling."""

from __future__ import annotations

import ast
import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases.x509 import conftest as x509_helpers
from pkcs11_check.testcases.x509 import test_attribute_parity, test_limbo_stress


class _RawSession:
    raw = object()
    sh = 1


def _sample_cert_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x509-boundary")])
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


def test_cert_object_fallback_requires_typed_exact_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(x509_helpers, "_build_cert_template", lambda *_a, **_k: {})
    errors: list[BaseException] = [
        AssertionError("harness bug mentioning CKR_ATTRIBUTE_VALUE_INVALID"),
        CkrAssertionError("misleading CKR_ATTRIBUTE_VALUE_INVALID text", 0x12345678),
    ]
    for error in errors:
        calls = 0

        def create(*_args: Any, **_kwargs: Any) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise error
            return 7

        monkeypatch.setattr(
            x509_helpers,
            "create_object",
            create,
        )
        with pytest.raises(type(error)) as caught:
            x509_helpers.import_cert_object(object(), 1, b"der", interface_version="3.0")
        assert caught.value is error
        assert calls == 1


def test_cert_raw_fallback_requires_typed_exact_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    errors: list[BaseException] = [
        AssertionError("harness bug mentioning CKR_TEMPLATE_INCOMPLETE"),
        CkrAssertionError("misleading CKR_TEMPLATE_INCOMPLETE text", 0x12345678),
    ]
    for error in errors:
        monkeypatch.setattr(
            x509_helpers,
            "create_object",
            lambda *_a, _error=error, **_k: (_ for _ in ()).throw(_error),
        )
        with pytest.raises(type(error)) as caught:
            x509_helpers.import_cert_raw(object(), 1, b"der")
        assert caught.value is error


@pytest.mark.parametrize(
    ("helper", "rv"),
    [
        ("object", CKR_ATTRIBUTE_VALUE_INVALID),
        ("raw", CKR_TEMPLATE_INCOMPLETE),
    ],
)
def test_cert_fallback_accepts_typed_exact_ckr(
    monkeypatch: pytest.MonkeyPatch, helper: str, rv: int
) -> None:
    calls = 0

    def create(*_args: Any, **_kwargs: Any) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CkrAssertionError("expected compatibility refusal", int(rv))
        return 7

    monkeypatch.setattr(x509_helpers, "create_object", create)
    if helper == "object":
        monkeypatch.setattr(x509_helpers, "_build_cert_template", lambda *_a, **_k: {})
        assert x509_helpers.import_cert_object(object(), 1, b"der", "3.0") == 7
    else:

        class _Dumpable:
            def dump(self) -> bytes:
                return b"der"

        class _TbsCertificate:
            def __getitem__(self, _name: str) -> _Dumpable:
                return _Dumpable()

        class _Certificate:
            subject = issuer = _Dumpable()

            def __getitem__(self, _name: str) -> _TbsCertificate:
                return _TbsCertificate()

        class _Asn1Cert:
            @staticmethod
            def load(_der: bytes) -> _Certificate:
                return _Certificate()

        monkeypatch.setattr("asn1crypto.x509.Certificate", _Asn1Cert)
        assert x509_helpers.import_cert_raw(object(), 1, b"der") == (7, True)
    assert calls == 2


def test_attribute_parity_does_not_swallow_python_read_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """X.509 parity checks should only classify PKCS#11 assertion failures."""

    def broken_read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise ValueError("decoder bug while handling CKR_FUNCTION_FAILED text")

    monkeypatch.setattr(x509_helpers, "read_attributes", broken_read_attributes)

    with pytest.raises(ValueError, match="decoder bug"):
        x509_helpers.verify_attribute_parity(
            object(),
            1,
            7,
            _sample_cert_der(),
        )


def test_attribute_parity_does_not_swallow_plain_assertions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain assertion is a harness failure, not an absent provider attribute."""

    def broken_read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise AssertionError("harness assertion mentions CKR_ATTRIBUTE_TYPE_INVALID")

    monkeypatch.setattr(x509_helpers, "read_attributes", broken_read_attributes)

    with pytest.raises(AssertionError, match="harness assertion"):
        x509_helpers.verify_attribute_parity(
            object(),
            1,
            7,
            _sample_cert_der(),
        )


def test_attribute_parity_accepts_only_expected_typed_missing_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two read-attribute refusal CK_RVs remain an explicit missing value."""

    def missing_attribute(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("attribute unavailable", int(CKR_ATTRIBUTE_TYPE_INVALID))

    monkeypatch.setattr(x509_helpers, "read_attributes", missing_attribute)
    result = x509_helpers.verify_attribute_parity(object(), 1, 7, _sample_cert_der())

    assert result["SUBJECT"][0] is None
    assert result["ISSUER"][0] is None
    assert result["SERIAL_NUMBER"][0] is None


def test_attribute_parity_does_not_swallow_undefined_typed_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An undefined CK_RV is a provider failure and must remain visible."""

    def unexpected_ckr(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("undefined provider return", 0x12345678)

    monkeypatch.setattr(x509_helpers, "read_attributes", unexpected_ckr)

    with pytest.raises(CkrAssertionError, match="undefined provider"):
        x509_helpers.verify_attribute_parity(object(), 1, 7, _sample_cert_der())


def test_attribute_parity_does_not_swallow_plain_import_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain import assertion must not become missing-mandatory xfail."""

    monkeypatch.setattr(test_attribute_parity, "pem_to_der", lambda _pem: b"der")

    def broken_import(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("harness assertion mentions CKR_TEMPLATE_INCOMPLETE")

    monkeypatch.setattr(test_attribute_parity, "import_cert_object", broken_import)

    with pytest.raises(AssertionError, match="harness assertion"):
        test_attribute_parity.test_limbo_attribute_parity(
            _RawSession(),
            True,
            [{"id": "tc1", "peer_certificate": "pem", "expected_result": "SUCCESS"}],
            lambda cases, limit=100: cases,
            "3.0",
        )


def test_x509_metadata_paths_do_not_catch_generic_exception() -> None:
    """X.509 metadata compatibility paths should not catch arbitrary Python exceptions."""
    paths = (
        Path("src/pkcs11_check/testcases/x509/conftest.py"),
        Path("src/pkcs11_check/testcases/x509/test_attributes.py"),
        Path("src/pkcs11_check/testcases/x509/test_core_ops.py"),
        Path("src/pkcs11_check/testcases/x509/test_identity.py"),
        Path("src/pkcs11_check/testcases/x509/test_lifecycle.py"),
        Path("src/pkcs11_check/testcases/x509/test_search.py"),
    )
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or node.type is None:
                continue
            caught_names = {
                child.id for child in ast.walk(node.type) if isinstance(child, ast.Name)
            }
            catches_generic = "Exception" in caught_names
            current: ast.AST | None = node
            function_name = ""
            while current is not None:
                if isinstance(current, ast.FunctionDef):
                    function_name = current.name
                    break
                current = parents.get(current)
            if catches_generic and function_name != "pem_to_der":
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


def test_cert_stress_allows_pkcs11_import_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CKR-style import rejection is fine for malformed x509-limbo material."""

    def reject_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_limbo_stress, "create_object", reject_create_object)
    monkeypatch.setattr(test_limbo_stress, "skip_unless_cert_storage", lambda _rs: None)

    test_limbo_stress.test_exhaustive_cert_import_no_crash(
        "case",
        b"not-a-cert",
        _RawSession(),
        object(),
    )


@pytest.mark.parametrize(
    ("kind", "phase"),
    [
        ("cert", "create"),
        ("cert", "value"),
        ("cert", "computed"),
        ("cert", "size"),
        ("crl", "create"),
        ("crl", "value"),
        ("crl", "size"),
    ],
)
def test_stress_does_not_accept_undefined_ckr(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    phase: str,
) -> None:
    error = CkrAssertionError("undefined provider return", 0x12345678)
    material = b"malformed"

    def create(*_args: Any, **_kwargs: Any) -> int:
        if phase == "create":
            raise error
        return 7

    def read(_raw: Any, _session: int, _handle: int, attrs: list[int]) -> dict[int, Any]:
        if phase == "value" and attrs == [test_limbo_stress.CKA_VALUE]:
            raise error
        if phase == "computed" and attrs != [test_limbo_stress.CKA_VALUE]:
            raise error
        return {test_limbo_stress.CKA_VALUE: material}

    def size(*_args: Any, **_kwargs: Any) -> int:
        if phase == "size":
            raise error
        return len(material)

    monkeypatch.setattr(test_limbo_stress, "create_object", create)
    monkeypatch.setattr(test_limbo_stress, "read_attributes", read)
    monkeypatch.setattr(test_limbo_stress, "get_object_size", size)
    monkeypatch.setattr(test_limbo_stress, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_limbo_stress, "skip_unless_cert_storage", lambda _rs: None)

    test = (
        test_limbo_stress.test_exhaustive_cert_import_no_crash
        if kind == "cert"
        else test_limbo_stress.test_exhaustive_crl_import_no_crash
    )
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        test("case", material, _RawSession(), object())


def test_cert_stress_does_not_swallow_python_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected harness errors must remain visible instead of looking like rejects."""

    def broken_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("broken test harness")

    monkeypatch.setattr(test_limbo_stress, "create_object", broken_create_object)
    monkeypatch.setattr(test_limbo_stress, "skip_unless_cert_storage", lambda _rs: None)

    with pytest.raises(ValueError, match="broken test harness"):
        test_limbo_stress.test_exhaustive_cert_import_no_crash(
            "case",
            b"not-a-cert",
            _RawSession(),
            object(),
        )


def test_cert_stress_does_not_swallow_generic_assertion_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A harness assertion is not a provider CKR and must remain visible."""

    def broken_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("broken test harness assertion")

    monkeypatch.setattr(test_limbo_stress, "create_object", broken_create_object)
    monkeypatch.setattr(test_limbo_stress, "skip_unless_cert_storage", lambda _rs: None)

    with pytest.raises(AssertionError, match="broken test harness assertion"):
        test_limbo_stress.test_exhaustive_cert_import_no_crash(
            "case",
            b"not-a-cert",
            _RawSession(),
            object(),
        )


def test_crl_stress_does_not_swallow_python_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRL import stress has the same error boundary as certificate stress."""

    def broken_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise TypeError("broken CRL setup")

    monkeypatch.setattr(test_limbo_stress, "create_object", broken_create_object)

    with pytest.raises(TypeError, match="broken CRL setup"):
        test_limbo_stress.test_exhaustive_crl_import_no_crash(
            "case",
            b"not-a-crl",
            _RawSession(),
            object(),
        )

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

from pkcs11_check.testcases.x509 import conftest as x509_helpers
from pkcs11_check.testcases.x509 import test_limbo_stress


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
        raise AssertionError("CKR_ATTRIBUTE_VALUE_INVALID")

    monkeypatch.setattr(test_limbo_stress, "create_object", reject_create_object)
    monkeypatch.setattr(test_limbo_stress, "skip_unless_cert_storage", lambda _rs: None)

    test_limbo_stress.test_exhaustive_cert_import_no_crash(
        "case",
        b"not-a-cert",
        _RawSession(),
        object(),
    )


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

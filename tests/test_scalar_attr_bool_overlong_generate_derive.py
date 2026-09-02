"""Structural meta-tests for TestBoolOverlongInGenerateDerive (C2 Phase 1).

These are in-process probes that call the PKCS#11 API directly (not
subprocess-based), so full monkeypatching is not cost-effective.  Instead we
assert *structural* properties that guarantee finding-safety:

1. The class and all three probe methods exist.
2. Each probe body calls ``make_bool_attr_overlong`` (keep-alive binding).
3. Each probe body calls ``classify_negative_rv`` with ``TEMPLATE_ERRORS``.
4. Each probe is mechanism-guarded (``has_mechanism`` present in source).
5. The module compiles without syntax errors (implicit: import succeeds).
"""

from __future__ import annotations

import inspect

from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._malformed_attrs import make_bool_attr_overlong
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security import test_scalar_attr_length_extended as _mod

# ---------------------------------------------------------------------------
# Class presence
# ---------------------------------------------------------------------------


def test_class_exists() -> None:
    """TestBoolOverlongInGenerateDerive must be defined in the module."""
    assert hasattr(_mod, "TestBoolOverlongInGenerateDerive"), (
        "TestBoolOverlongInGenerateDerive not found in test_scalar_attr_length_extended"
    )


# ---------------------------------------------------------------------------
# Method presence
# ---------------------------------------------------------------------------


def test_generate_aes_key_method_exists() -> None:
    """AES keygen probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_generate_aes_key")


def test_generate_rsa_keypair_method_exists() -> None:
    """RSA keypair probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_generate_rsa_keypair")


def test_derive_ecdh_method_exists() -> None:
    """ECDH derive probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_derive_ecdh")


# ---------------------------------------------------------------------------
# Structural source checks per probe
# ---------------------------------------------------------------------------


def _src(method_name: str) -> str:
    return inspect.getsource(getattr(_mod.TestBoolOverlongInGenerateDerive, method_name))


def test_aes_probe_calls_make_bool_attr_overlong() -> None:
    """AES keygen probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_generate_aes_key")


def test_aes_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """AES keygen probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_generate_aes_key")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_aes_probe_is_mechanism_guarded() -> None:
    """AES keygen probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_generate_aes_key")


def test_rsa_probe_calls_make_bool_attr_overlong() -> None:
    """RSA keypair probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_generate_rsa_keypair")


def test_rsa_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """RSA keypair probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_generate_rsa_keypair")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_rsa_probe_is_mechanism_guarded() -> None:
    """RSA keypair probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_generate_rsa_keypair")


def test_derive_probe_calls_make_bool_attr_overlong() -> None:
    """ECDH derive probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_derive_ecdh")


def test_derive_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """ECDH derive probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_derive_probe_is_mechanism_guarded() -> None:
    """ECDH derive probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_derive_ecdh")


def test_derive_probe_destroys_setup_keys_in_finally() -> None:
    """ECDH derive probe must clean up base keypair handles in a finally block."""
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "finally" in src
    assert "destroy_quietly" in src


# ---------------------------------------------------------------------------
# Sanity: referenced helpers are importable (compile gate)
# ---------------------------------------------------------------------------


def test_make_bool_attr_overlong_importable() -> None:
    """make_bool_attr_overlong must be importable from _malformed_attrs."""
    assert callable(make_bool_attr_overlong)


def test_classify_negative_rv_importable() -> None:
    """classify_negative_rv must be importable from conftest."""
    assert callable(classify_negative_rv)


def test_template_errors_is_tuple() -> None:
    """TEMPLATE_ERRORS must be a tuple (used as the expected_rvs argument)."""
    assert isinstance(TEMPLATE_ERRORS, tuple)
    assert len(TEMPLATE_ERRORS) > 0

"""Structural meta-tests for TestRsaPrivatePartOversize (C2 Phase 2).

These are in-process probes that assert *structural* properties guaranteeing
finding-safety for the RSA private-part oversize probes:

1. The class and probe method exist.
2. The probe body passes ``LengthArg.explicit_value(_WILD_OVERSIZED_LENGTH)``
   (the byte-string keep-alive / oversize-declaration mechanism).
3. The probe body calls ``classify_negative_rv`` with ``TEMPLATE_ERRORS``.
4. The probe is guarded by ``skip_unless_create_object_supported``.
5. The probe parametrizes over CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1.
6. The module compiles without errors (implicit: import succeeds).
"""

from __future__ import annotations

import inspect

from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    skip_unless_create_object_supported,
)
from pkcs11_check.testcases.security import test_scalar_attr_length_extended as _mod

# ---------------------------------------------------------------------------
# Class presence
# ---------------------------------------------------------------------------


def test_class_exists() -> None:
    """TestRsaPrivatePartOversize must be defined in the module."""
    assert hasattr(_mod, "TestRsaPrivatePartOversize"), (
        "TestRsaPrivatePartOversize not found in test_scalar_attr_length_extended"
    )


# ---------------------------------------------------------------------------
# Method presence
# ---------------------------------------------------------------------------


def test_probe_method_exists() -> None:
    """The RSA private-part oversize probe method must exist."""
    cls = _mod.TestRsaPrivatePartOversize
    assert hasattr(cls, "test_rsa_private_part_wild_oversized_in_create")


# ---------------------------------------------------------------------------
# Structural source checks
# ---------------------------------------------------------------------------


def _src() -> str:
    return inspect.getsource(
        getattr(
            _mod.TestRsaPrivatePartOversize,
            "test_rsa_private_part_wild_oversized_in_create",
        )
    )


def test_probe_uses_wild_oversized_length() -> None:
    """Probe must use LengthArg.explicit_value (byte-string oversize mechanism)."""
    assert "LengthArg.explicit_value" in _src()
    assert "_WILD_OVERSIZED_LENGTH" in _src()


def test_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """Probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src()
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_probe_is_create_object_guarded() -> None:
    """Probe must guard on skip_unless_create_object_supported."""
    assert "skip_unless_create_object_supported" in _src()


def test_probe_covers_prime_1() -> None:
    """Probe must exercise CKA_PRIME_1."""
    assert "CKA_PRIME_1" in _src()


def test_probe_covers_prime_2() -> None:
    """Probe must exercise CKA_PRIME_2."""
    assert "CKA_PRIME_2" in _src()


def test_probe_covers_exponent_1() -> None:
    """Probe must exercise CKA_EXPONENT_1."""
    assert "CKA_EXPONENT_1" in _src()


def test_probe_destroys_on_ok() -> None:
    """Probe must call destroy_quietly when C_CreateObject returns CKR_OK."""
    assert "destroy_quietly" in _src()


# ---------------------------------------------------------------------------
# Sanity: referenced helpers are importable (compile gate)
# ---------------------------------------------------------------------------


def test_classify_negative_rv_importable() -> None:
    """classify_negative_rv must be importable from conftest."""
    assert callable(classify_negative_rv)


def test_skip_unless_create_object_supported_importable() -> None:
    """skip_unless_create_object_supported must be importable from conftest."""
    assert callable(skip_unless_create_object_supported)


def test_template_errors_is_nonempty_tuple() -> None:
    """TEMPLATE_ERRORS must be a non-empty tuple."""
    assert isinstance(TEMPLATE_ERRORS, tuple)
    assert len(TEMPLATE_ERRORS) > 0

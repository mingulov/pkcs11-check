"""Regression tests for domain-parameter generation negative coverage."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKA_PRIME_BITS,
    CKA_SUBPRIME_BITS,
    CKR_TEMPLATE_INCOMPLETE,
)
from pkcs11_check.testcases import test_dh_key_agreement, test_dsa_complete, test_x942_dh


def _attr_types(ptr: Any, count: int) -> list[int]:
    return [int(ptr[index].type) for index in range(count)]


def _session_with_generate_key(rv: int, mechanisms: set[str]) -> SimpleNamespace:
    calls: list[dict[str, Any]] = []

    def generate_key(
        sh: int,
        mechanism: Any,
        template_ptr: Any,
        template_count: int,
        handle_ptr: Any,
    ) -> int:
        calls.append(
            {
                "sh": sh,
                "mechanism": mechanism._obj.mechanism,
                "template_count": template_count,
                "attr_types": _attr_types(template_ptr, template_count),
            }
        )
        ctypes.cast(handle_ptr, ctypes.POINTER(type(handle_ptr._obj))).contents.value = 0
        return rv

    return SimpleNamespace(
        raw=SimpleNamespace(C_GenerateKey=generate_key),
        sh=7,
        calls=calls,
        has_mechanism=lambda name: name in mechanisms,
    )


def test_dh_parameter_gen_missing_prime_bits_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_generate_key(
        CKR_TEMPLATE_INCOMPLETE,
        {"DH_PKCS_PARAMETER_GEN"},
    )
    monkeypatch.setattr(test_dh_key_agreement, "destroy_quietly", lambda *_args: None)

    test_dh_key_agreement.TestDHParameterGeneration().test_parameter_gen_rejects_missing_prime_bits(
        rs
    )

    assert CKA_PRIME_BITS not in rs.calls[0]["attr_types"]


def test_dsa_parameter_gen_missing_prime_bits_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_generate_key(
        CKR_TEMPLATE_INCOMPLETE,
        {"DSA_PARAMETER_GEN"},
    )
    monkeypatch.setattr(test_dsa_complete, "destroy_quietly", lambda *_args: None)

    test_dsa_complete.TestDSAParameterGen().test_parameter_gen_rejects_missing_prime_bits(rs)

    assert CKA_PRIME_BITS not in rs.calls[0]["attr_types"]


def test_x942_parameter_gen_missing_subprime_bits_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session_with_generate_key(
        CKR_TEMPLATE_INCOMPLETE,
        {"X9_42_DH_PARAMETER_GEN"},
    )
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)

    test_x942_dh.TestX942DHParameterGen().test_parameter_gen_rejects_missing_subprime_bits(
        rs
    )

    assert CKA_PRIME_BITS in rs.calls[0]["attr_types"]
    assert CKA_SUBPRIME_BITS not in rs.calls[0]["attr_types"]

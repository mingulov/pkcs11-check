"""Meta-tests for negotiate_request (Pillar 1). No PKCS#11 module needed."""
from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKM_ECDH_AES_KEY_WRAP,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._negotiation import (
    TEMPLATE_SHAPE_REJECTS,
    negotiate_request,
    value_len_variant_allowed,
)


def _raise(rv):
    raise CkrAssertionError(f"Unexpected CK_RV; rv={rv}", rv)


def test_canonical_first_no_retry_on_success():
    calls = []
    def attempt(delta):
        calls.append(delta)
        return ("handle", )
    result, idx = negotiate_request(attempt, [{"a": 1}, {"a": 1, "b": 2}], label="t")
    assert idx == 0 and len(calls) == 1


def test_retry_on_shape_reject_then_succeed():
    calls = []
    def attempt(delta):
        calls.append(delta)
        if len(calls) == 1:
            _raise(CKR_TEMPLATE_INCONSISTENT)
        return "ok"
    result, idx = negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")
    assert idx == 1 and result == "ok"


def test_read_only_is_a_shape_reject():
    assert CKR_ATTRIBUTE_READ_ONLY in TEMPLATE_SHAPE_REJECTS


def test_value_invalid_is_NOT_a_shape_reject():  # noqa: N802
    assert CKR_ATTRIBUTE_VALUE_INVALID not in TEMPLATE_SHAPE_REJECTS


def test_non_shape_reject_propagates_immediately():
    def attempt(delta):
        _raise(CKR_ENCRYPTED_DATA_INVALID)
    with pytest.raises(CkrAssertionError) as ei:
        negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")
    assert ei.value.rv == CKR_ENCRYPTED_DATA_INVALID


def test_all_variants_shape_rejected_raises_last():
    def attempt(delta):
        _raise(CKR_ATTRIBUTE_READ_ONLY)
    with pytest.raises(CkrAssertionError):
        negotiate_request(attempt, [{}, {CKA_VALUE_LEN: 32}], label="t")


def test_value_len_variant_allowlist():
    # Determined-length UNWRAP mechs: CKA_VALUE_LEN permitted for generic-secret AND AES
    # (PKCS#11 v3.2 removed footnote 6 for AES; a length conflict -> CKR_WRAPPED_KEY_LEN_RANGE).
    assert value_len_variant_allowed(CKK_GENERIC_SECRET, CKM_AES_KEY_WRAP) is True
    assert value_len_variant_allowed(CKK_AES, CKM_AES_KEY_WRAP) is True
    assert value_len_variant_allowed(CKK_AES, CKM_ECDH_AES_KEY_WRAP) is True
    # The MECHANISM gate excludes derive mechs even for an allowlisted key type: a derive
    # mechanism's CKA_VALUE_LEN controls (truncates) the output, so it must NOT be negotiated.
    assert value_len_variant_allowed(CKK_GENERIC_SECRET, CKM_ECDH1_DERIVE) is False
    assert value_len_variant_allowed(CKK_AES, CKM_ECDH1_DERIVE) is False

"""Regression: a clean EC public-key import reject must classify, not raise raw.

A module that advertises ECDSA but cannot import an externally-supplied public key
(e.g. a KMS bridge) rejects C_CreateObject with a clean CKR. That is a positive-op
clean reject -> "advertised but not operational" -> xfail per the classification
model, NOT a raw pytest failure stamped `unclassified`. cosmian returned
CKR_ARGUMENTS_BAD, which was absent from the import allowlist, so 11.9k vectors
landed as unclassified (pool round 2026-06-29, finding F1).
"""

from __future__ import annotations

import pytest

from pkcs11_check import classification as C
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases.wycheproof import test_wycheproof as tw
from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdsa as twe


def test_ec_public_import_arguments_bad_routes_not_operational() -> None:
    C.clear()
    exc = CkrAssertionError("C_CreateObject EC public key -> CKR_ARGUMENTS_BAD", CKR_ARGUMENTS_BAD)
    with pytest.raises(BaseException):  # noqa: B017,PT011 - classify raises the xfail outcome
        tw._classify_ec_public_import_reject(exc, "secp256r1")
    recs = C.serialize(C.get_records())
    assert recs, "expected a classification record, got a raw re-raise (-> unclassified)"
    assert recs[-1]["reason"] == "not_operational", recs[-1]


def test_ecdsa_import_allowlist_includes_arguments_bad() -> None:
    # the inline import classifier in test_wycheproof_ecdsa.py uses this tuple; pin it
    # so the CKR_ARGUMENTS_BAD reject routes to not_operational instead of raising raw.
    assert CKR_ARGUMENTS_BAD in twe._EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS


def test_cctv_ed25519_valid_vector_import_failure_is_not_operational() -> None:
    # A valid Ed25519 vector whose public-key import fails cleanly = the module
    # advertises Ed25519 but cannot import an external public key -> not_operational
    # xfail, not a raw failure (cosmian: 388 unclassified, F1).
    from pkcs11_check.testcases import test_cctv_ed25519 as cctv

    C.clear()
    exc = CkrAssertionError("Ed25519 public import -> CKR_ARGUMENTS_BAD", CKR_ARGUMENTS_BAD)
    with pytest.raises(BaseException):  # noqa: B017,PT011
        cctv._invalid_public_key_rejected_cleanly(exc, [])  # [] = valid vector (no invalid flags)
    recs = C.serialize(C.get_records())
    assert recs and recs[-1]["reason"] == "not_operational", recs


def test_cert_storage_probe_general_error_is_not_operational() -> None:
    # A KMS cert-storage probe that fails with CKR_GENERAL_ERROR is recorded as a
    # not_operational xfail at the skip gate (full behavior in
    # test_cert_storage_capability); pin the gate's not-operational CKR set so the 1663
    # cosmian unclassified (limbo import+stress) stay classified, not raw.
    from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
    from pkcs11_check.testcases.x509 import conftest as x509_conftest

    assert int(CKR_GENERAL_ERROR) in x509_conftest._CERT_STORAGE_NOT_OPERATIONAL_CKRS

"""Regression: KEM output-key templates must declare CKA_VALUE_LEN.

PKCS#11 v3.2 (ML-KEM): C_EncapsulateKey/C_DecapsulateKey "contributes the result as the
CKA_VALUE attribute of the new key; other attributes required by the key type must be
specified in the template." A strict-but-conformant module (opencryptoki) therefore
rejects an output template with no CKA_VALUE_LEN as CKR_TEMPLATE_INCONSISTENT — and the
harness then *falsely* reports the module's working ML-KEM as "not operational". Lenient
modules (kryoptic/nss) infer 32 bytes. The harness must supply CKA_VALUE_LEN so the
operation is exercised on both.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import CKA_VALUE_LEN
from pkcs11_check.testcases.test_kem import _ML_KEM_SHARED_SECRET_BYTES, _encap_attrs


def test_default_kem_output_template_declares_value_len() -> None:
    attrs = _encap_attrs()
    assert CKA_VALUE_LEN in attrs, "KEM output template must declare CKA_VALUE_LEN"
    # FIPS 203: the ML-KEM shared secret is always 32 bytes for every parameter set.
    assert attrs[CKA_VALUE_LEN] == 32
    assert _ML_KEM_SHARED_SECRET_BYTES == 32


def test_explicit_value_len_still_overrides() -> None:
    attrs = _encap_attrs(value_len=16)
    assert attrs[CKA_VALUE_LEN] == 16

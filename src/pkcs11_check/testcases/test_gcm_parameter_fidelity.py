"""AES-GCM authentication-tag-length fidelity probe.

Import a known AES-256 key (so the local oracle can decrypt), request a
non-default tag length (ulTagBits=96), and check the module honored it:
the actual tag length is read from the output (ciphertext||tag) and confirmed
by a local decrypt. A shorter tag than requested is a (spec-valid but) weaker
authentication strength -> honest_deviation with an explicit note (spec G11).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_gcm
from pkcs11_check.raw.recipes import destroy_quietly, encrypt_single, import_secret_key
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKK_AES,
    CKM_AES_GCM,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._param_fidelity import build_gcm_fidelity, classify_fidelity
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.crossverify

_AES_KEY = bytes(range(32))  # fixed AES-256 key
_NONCE = bytes(range(12))  # 96-bit IV
_AAD = b"gcm-fidelity-aad"
_PLAINTEXT = b"AES-GCM tag-length fidelity probe body"
_GCM_REFUSED = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_ARGUMENTS_BAD,
    # Module-operational-failure codes: advertised GCM but the imported key
    # handle/type is not usable -> not_operational (xfail), never a hard fail.
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
)


class TestGcmParameterFidelity:
    def test_gcm_tag_length_honored(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        label = "AES-GCM:ulTagBits=96 fidelity"
        key = 0
        try:
            try:
                key = import_secret_key(
                    rs.raw,
                    rs.sh,
                    CKK_AES,
                    _AES_KEY,
                    attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
                )
            except AssertionError as exc:
                pytest.skip(f"AES key import refused: {exc}")
            mech_param = mech_gcm(CKM_AES_GCM, _NONCE, aad=_AAD, tag_bits=96)
            try:
                out = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    _PLAINTEXT,
                    mech_param=mech_param,
                    output_overhead=16,  # fit a larger-than-requested tag
                    # Some modules under-report the GCM output length on the size
                    # query (or use an IV-prefixed layout); re-read the module's
                    # required size and retry rather than mis-reading a sizing
                    # protocol response (CKR_BUFFER_TOO_SMALL) as a failure.
                    retry_on_buffer_too_small=True,
                )
            except AssertionError as exc:
                if is_known_error(exc, _GCM_REFUSED):
                    xfail_as(
                        "not_operational",
                        kind="lifecycle",
                        label=label,
                        operation="C_Encrypt",
                        mechanism="CKM_AES_GCM",
                        summary=not_operational_reason(label, f"GCM tag_bits=96 refused: {exc}"),
                    )
                raise
            result = build_gcm_fidelity(
                _AES_KEY, _NONCE, _AAD, _PLAINTEXT, out, requested_tag_bits=96
            )
            classify_fidelity(result, label=label, operation="C_Encrypt", mechanism="CKM_AES_GCM")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

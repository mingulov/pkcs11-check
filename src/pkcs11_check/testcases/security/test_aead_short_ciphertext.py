"""AEAD (GCM/CCM) ciphertext shorter than authentication tag must be rejected.

A ciphertext shorter than the authentication tag/MAC is structurally impossible:
there is no room for a valid tag, so no plaintext can be recovered.  A conformant
module must reject such inputs before attempting any decryption.

Reference:
- NIST SP 800-38D §5.2: GCM ciphertext must be at least ``t`` bits long (where
  ``t`` is the tag length), otherwise there is no tag to verify.
- NIST SP 800-38C §4: CCM input must be at least ``t`` bytes long for the same
  structural reason.
- CWE-191: integer underflow on ``ciphertext_len - tag_len`` can produce an
  undersized allocation or an out-of-bounds read if the check is missing.

Accepting CKR_OK on such input is an unambiguous crypto-correctness break
(``accepted_invalid``, ``kind="crypto"``): a conformant module ALWAYS rejects.
There is no false-accusation risk.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack_mechanisms import mech_ccm, mech_gcm
from pkcs11_check.raw.recipes import decrypt_single, destroy_quietly
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_TOKEN,
    CKF_DECRYPT,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    reject_or_classify,
    skip_unless_capability,
)

pytestmark = [pytest.mark.security]

# Spec-correct rejection codes for a ciphertext shorter than the tag.
# CKR_OK is intentionally absent: accepting a too-short ciphertext is always wrong.
_SHORT_CT_REJECT_RVS = (
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
)

# Ciphertext lengths to probe (both below the 16-byte / 128-bit GCM or CCM MAC).
_SHORT_CT_LENGTHS = [
    pytest.param(4, id="ct-4-bytes"),
    pytest.param(15, id="ct-15-bytes"),
]

_GCM_IV = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"  # 12 bytes
_CCM_NONCE = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"  # 13 bytes
_TAG_BYTES = 16  # 128-bit tag / MAC for both probes


class TestGcmShortCiphertext:
    """GCM ciphertext shorter than the 128-bit authentication tag must be rejected.

    NIST SP 800-38D §5.2 requires the ciphertext to be at least ``t`` bits
    (here 128 bits = 16 bytes).  A shorter input cannot contain a valid tag;
    accepting it (CKR_OK) is a crypto-correctness break (CWE-191).
    """

    @pytest.mark.parametrize("ct_len", _SHORT_CT_LENGTHS)
    def test_gcm_short_ciphertext_rejected(self, p11_raw_session: Any, ct_len: int) -> None:
        """C_Decrypt(AES-GCM, ciphertext shorter than 16-byte tag) must reject.

        The probe generates a 256-bit AES key, initialises a GCM decrypt
        with a 128-bit (16-byte) tag, then submits a ciphertext of ``ct_len``
        bytes (< 16).  A conformant module must reject before attempting tag
        verification.

        Reference: NIST SP 800-38D §5.2; CWE-191.
        """
        rs = p11_raw_session
        skip_unless_capability(rs, CKM_AES_GCM, operation=CKF_DECRYPT)

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            purpose="GCM short-ciphertext probe",
        )
        try:
            mech = mech_gcm(CKM_AES_GCM, _GCM_IV, tag_bits=_TAG_BYTES * 8)
            short_ct = b"\xaa" * ct_len
            label = (
                f"AES-GCM C_Decrypt of {ct_len}-byte ciphertext with 16-byte tag "
                f"(SP 800-38D: ciphertext must be >= tag length)"
            )
            reject_exc: AssertionError | None = None
            try:
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    short_ct,
                    mech_param=mech,
                    output_size_hint=ct_len,
                )
            except AssertionError as exc:
                reject_exc = exc
            reject_or_classify(
                reject_exc,
                _SHORT_CT_REJECT_RVS,
                label=label,
                kind="crypto",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCcmShortCiphertext:
    """CCM ciphertext shorter than the 128-bit MAC must be rejected.

    NIST SP 800-38C §4 requires the ciphertext to be at least ``t`` bytes
    (here 16 bytes for a 128-bit MAC).  A shorter input cannot contain a
    valid MAC; accepting it (CKR_OK) is a crypto-correctness break (CWE-191).
    """

    @pytest.mark.parametrize("ct_len", _SHORT_CT_LENGTHS)
    def test_ccm_short_ciphertext_rejected(self, p11_raw_session: Any, ct_len: int) -> None:
        """C_Decrypt(AES-CCM, ciphertext shorter than 16-byte MAC) must reject.

        The probe generates a 256-bit AES key, initialises a CCM decrypt
        with a 128-bit (16-byte) MAC and a 13-byte nonce, then submits a
        ciphertext of ``ct_len`` bytes (< 16).  A conformant module must
        reject before attempting MAC verification.

        Reference: NIST SP 800-38C §4; CWE-191.
        """
        rs = p11_raw_session
        skip_unless_capability(rs, CKM_AES_CCM, operation=CKF_DECRYPT)

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            purpose="CCM short-ciphertext probe",
        )
        try:
            mech = mech_ccm(
                CKM_AES_CCM,
                _CCM_NONCE,
                data_len=0,
                aad=None,
                mac_len=_TAG_BYTES,
            )
            short_ct = b"\xbb" * ct_len
            label = (
                f"AES-CCM C_Decrypt of {ct_len}-byte ciphertext with 16-byte MAC "
                f"(SP 800-38C: ciphertext must be >= MAC length)"
            )
            reject_exc: AssertionError | None = None
            try:
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CCM,
                    short_ct,
                    mech_param=mech,
                    output_size_hint=ct_len,
                )
            except AssertionError as exc:
                reject_exc = exc
            reject_or_classify(
                reject_exc,
                _SHORT_CT_REJECT_RVS,
                label=label,
                kind="crypto",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

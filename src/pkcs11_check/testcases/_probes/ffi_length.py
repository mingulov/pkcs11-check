"""Probe: isize::MAX (2^63) boundary lengths for PKCS#11 data / output functions.

Untrusted-caller probe.  On a 64-bit platform the largest valid byte count for a
contiguous slice is ``0x7FFFFFFFFFFFFFFF`` (2**63 - 1); passing that value (or one past
it) as a data/part/output length with a small real buffer must be rejected cleanly, never
form an out-of-bounds slice (CWE-681).  Input-length probes back the claimed length with a
demand-zero honeypot so a crash is unconditionally real (docs/probe-soundness.md); output-
length probes pass small real buffers and put the un-honorable value in the length field.
Output protocol is preserved verbatim for the parent classifiers in
security/test_ffi_length_boundary.py.

Dispatch on ``params.extra["probe"]``:
  ``"encrypt_isize"``       -- C_EncryptInit + C_Encrypt, honeypot data ptr, isize data_len
  ``"decrypt_isize"``       -- C_DecryptInit + C_Decrypt, honeypot data ptr, isize data_len
  ``"sign_isize"``          -- C_SignInit + C_Sign (HMAC), honeypot data ptr, isize data_len
  ``"verify_isize"``        -- C_VerifyInit + C_Verify (HMAC), honeypot data ptr, isize data_len
  ``"digest_isize"``        -- C_DigestInit + C_Digest, honeypot data ptr, isize data_len
  ``"update_isize"``        -- C_{Encrypt,Decrypt,Sign,Verify,Digest}Update, isize part len
  ``"seed_random_isize"``   -- C_SeedRandom, honeypot data ptr, isize seed len
  ``"sign_isize_output"``   -- C_Sign with isize CK_ULONG output-buffer length
  ``"digest_isize_output"`` -- C_Digest with isize CK_ULONG output-buffer length
  ``"verify_isize_sig_len"`` -- C_Verify with isize claimed signature length
  ``"encrypt_message"``     -- C_EncryptMessage (AES-GCM), honeypot aad/plaintext, isize input len
  ``"decrypt_message"``     -- C_DecryptMessage (AES-GCM), honeypot aad/ciphertext, isize input len
  ``"decrypt_message_multipart"`` -- C_DecryptMessageBegin/Next (AES-GCM), honeypot isize ciphertext
  ``"sign_message"``        -- C_SignMessage (RSA), honeypot data ptr, isize data len
  ``"verify_message"``      -- C_VerifyMessage (RSA), honeypot data/signature, isize input len
  ``"sign_message_multipart"`` -- C_SignMessageBegin/Next (RSA), honeypot isize data len
  ``"verify_message_multipart"`` -- C_VerifyMessageBegin/Next (RSA), honeypot isize begin/data/sig
  ``"encrypt_message_multipart"`` -- C_EncryptMessageBegin/Next (AES-GCM), honeypot isize plaintext

NULL-inner-parameter probes (valid CK_MECHANISM, but an inner struct field is NULL / an empty
non-NULL pointer where the paired length is non-zero); the module must validate before deref:
  ``"generate_key_oom"``     -- C_GenerateKey (AES) with a large-but-valid CKA_VALUE_LEN
  ``"gcm_null_iv"``          -- C_EncryptInit CK_AES_GCM_PARAMS pIv=NULL, ulIvLen=12
  ``"ecdh_null_public_data"`` -- C_DeriveKey CK_ECDH1_DERIVE_PARAMS pPublicData=NULL, len=65
  ``"oaep_null_source_data"`` -- C_EncryptInit CK_RSA_PKCS_OAEP_PARAMS pSourceData=NULL, len=16
  ``"hkdf_null_salt"``       -- C_DeriveKey CK_HKDF_PARAMS pSalt=NULL, ulSaltLen=16 (SALT_DATA)
  ``"hkdf_null_info"``       -- C_DeriveKey CK_HKDF_PARAMS pInfo=NULL, ulInfoLen=16 (SALT_NULL)
  ``"eddsa_null_context_data"`` -- C_SignInit CK_EDDSA_PARAMS pContextData=NULL, len=16
  ``"mldsa_empty_context"``  -- C_VerifyInit/C_Verify CK_SIGN_ADDITIONAL_CONTEXT non-NULL, len=0
  ``"ccm_null_nonce"``       -- C_EncryptInit CK_AES_CCM_PARAMS pNonce=NULL, ulNonceLen=7
  ``"concat_base_data_null"`` -- C_DeriveKey CK_KEY_DERIVATION_STRING_DATA pData=NULL, ulLen=16
  ``"tls_kdf_null_label"``   -- C_DeriveKey CK_TLS_KDF_PARAMS pLabel=NULL, ulLabelLength=16
  ``"sp800_108_null_data_params"`` -- C_DeriveKey CK_SP800_108_KDF_PARAMS pDataParams=NULL, count=1

Required extra keys (in addition to ``"module_path"`` / ``"slot_id"`` handled by the runner):
  ``"probe"``     -- one of the dispatch keys above.
  ``"value_len"`` -- int for ``"generate_key_oom"`` (the large-but-valid CKA_VALUE_LEN).
  ``"data_len"``  -- int (input-length probes: encrypt/decrypt/sign/verify/digest/update/seed and
                     ``"sign_message"`` / the ``"*_message_multipart"`` probes).
  ``"op"``        -- str for ``"update_isize"``: one of C_EncryptUpdate / C_DecryptUpdate /
                     C_SignUpdate / C_VerifyUpdate / C_DigestUpdate; also for
                     ``"encrypt_message_multipart"`` / ``"decrypt_message_multipart"`` /
                     ``"sign_message_multipart"`` (selects the *Begin vs *Next arm).
  ``"out_len"``   -- int for ``"sign_isize_output"`` / ``"digest_isize_output"``.
  ``"sig_len"``   -- int for ``"verify_isize_sig_len"``.
  ``"aad_len"`` / ``"plaintext_len"``   -- int for ``"encrypt_message"``.
  ``"aad_len"`` / ``"ciphertext_len"``  -- int for ``"decrypt_message"``.
  ``"verify_data_len"`` / ``"signature_len"``  -- int for ``"verify_message"``.
  ``"field"``     -- str for ``"verify_message_multipart"`` (begin_parameter / next_data /
                     next_signature), with ``"begin_param_len"`` / ``"next_data_len"`` /
                     ``"next_signature_len"`` (int).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pkcs11_check.testcases._probes._ffi_length_base import (
    _derived_aes_key_template as _derived_aes_key_template,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _derived_secret_key_template as _derived_secret_key_template,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _import_derive_base_key as _import_derive_base_key,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _import_generic_secret_derive_key as _import_generic_secret_derive_key,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _import_hmac_key as _import_hmac_key,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _import_hmac_key_notop as _import_hmac_key_notop,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _setup_reject_or_raise as _setup_reject_or_raise,
)
from pkcs11_check.testcases._probes._ffi_length_base import (
    _SetupRejected,
)
from pkcs11_check.testcases._probes._ffi_length_isize import (
    _run_decrypt_isize,
    _run_digest_isize,
    _run_digest_isize_output,
    _run_encrypt_isize,
    _run_seed_random_isize,
    _run_sign_isize,
    _run_sign_isize_output,
    _run_update_isize,
    _run_verify_isize,
    _run_verify_isize_sig_len,
)
from pkcs11_check.testcases._probes._ffi_length_length_params import (
    _run_aes_cbc_encrypt_data_malformed,
    _run_ccm_aad_length,
    _run_ccm_mac_length,
    _run_ccm_nonce_length,
    _run_eddsa_context_length,
    _run_gcm_aad_length,
    _run_gcm_iv_length,
    _run_gcm_tag_bits_length,
    _run_pbe_nested_length,
    _run_pbkdf2_nested_length,
    _run_rsa_oaep_source_data_length,
    _run_rsa_pss_salt_length,
    _run_sp800_108_additional_derived_key_count,
    _run_sp800_108_data_param_count,
    _run_tls_kdf_random_length,
)
from pkcs11_check.testcases._probes._ffi_length_message import (
    _run_decrypt_message,
    _run_decrypt_message_multipart,
    _run_encrypt_message,
    _run_encrypt_message_multipart,
    _run_sign_message,
    _run_sign_message_multipart,
    _run_verify_message,
    _run_verify_message_multipart,
)
from pkcs11_check.testcases._probes._ffi_length_null_params import (
    _run_ccm_null_nonce,
    _run_concat_base_data_null,
    _run_ecdh_null_public_data,
    _run_eddsa_null_context_data,
    _run_gcm_null_iv,
    _run_generate_key_oom,
    _run_hkdf_null_info,
    _run_hkdf_null_salt,
    _run_mldsa_empty_context,
    _run_oaep_null_source_data,
    _run_sp800_108_null_data_params,
    _run_tls_kdf_null_label,
)
from pkcs11_check.testcases._probes._ffi_length_state_guards import (
    _run_decrypt_final_continuation,
    _run_decrypt_single_shot_guard,
    _run_decrypt_update_continuation,
    _run_decrypt_update_guard,
    _run_encrypt_final_continuation,
    _run_encrypt_single_shot_guard,
    _run_encrypt_update_continuation,
    _run_encrypt_update_guard,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS as AES_KEYGEN_RUNTIME_REJECT_RVS,
)
from pkcs11_check.testcases.conftest import (
    KEYPAIR_RUNTIME_REJECT_RVS as KEYPAIR_RUNTIME_REJECT_RVS,
)
from pkcs11_check.testcases.conftest import (
    is_known_error as is_known_error,
)

_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "encrypt_isize": _run_encrypt_isize,
    "decrypt_isize": _run_decrypt_isize,
    "sign_isize": _run_sign_isize,
    "verify_isize": _run_verify_isize,
    "digest_isize": _run_digest_isize,
    "update_isize": _run_update_isize,
    "seed_random_isize": _run_seed_random_isize,
    "sign_isize_output": _run_sign_isize_output,
    "digest_isize_output": _run_digest_isize_output,
    "verify_isize_sig_len": _run_verify_isize_sig_len,
    "encrypt_message": _run_encrypt_message,
    "decrypt_message": _run_decrypt_message,
    "decrypt_message_multipart": _run_decrypt_message_multipart,
    "sign_message": _run_sign_message,
    "verify_message": _run_verify_message,
    "sign_message_multipart": _run_sign_message_multipart,
    "verify_message_multipart": _run_verify_message_multipart,
    "encrypt_message_multipart": _run_encrypt_message_multipart,
    "generate_key_oom": _run_generate_key_oom,
    "gcm_null_iv": _run_gcm_null_iv,
    "ecdh_null_public_data": _run_ecdh_null_public_data,
    "oaep_null_source_data": _run_oaep_null_source_data,
    "hkdf_null_salt": _run_hkdf_null_salt,
    "hkdf_null_info": _run_hkdf_null_info,
    "eddsa_null_context_data": _run_eddsa_null_context_data,
    "mldsa_empty_context": _run_mldsa_empty_context,
    "ccm_null_nonce": _run_ccm_null_nonce,
    "concat_base_data_null": _run_concat_base_data_null,
    "tls_kdf_null_label": _run_tls_kdf_null_label,
    "sp800_108_null_data_params": _run_sp800_108_null_data_params,
    "aes_cbc_encrypt_data_malformed": _run_aes_cbc_encrypt_data_malformed,
    "rsa_pss_salt_length": _run_rsa_pss_salt_length,
    "gcm_aad_length": _run_gcm_aad_length,
    "ccm_aad_length": _run_ccm_aad_length,
    "pbkdf2_nested_length": _run_pbkdf2_nested_length,
    "pbe_nested_length": _run_pbe_nested_length,
    "tls_kdf_random_length": _run_tls_kdf_random_length,
    "sp800_108_data_param_count": _run_sp800_108_data_param_count,
    "sp800_108_additional_derived_key_count": _run_sp800_108_additional_derived_key_count,
    "rsa_oaep_source_data_length": _run_rsa_oaep_source_data_length,
    "gcm_iv_length": _run_gcm_iv_length,
    "gcm_tag_bits_length": _run_gcm_tag_bits_length,
    "ccm_nonce_length": _run_ccm_nonce_length,
    "ccm_mac_length": _run_ccm_mac_length,
    "eddsa_context_length": _run_eddsa_context_length,
    "encrypt_update_guard": _run_encrypt_update_guard,
    "decrypt_update_guard": _run_decrypt_update_guard,
    "encrypt_update_continuation": _run_encrypt_update_continuation,
    "decrypt_update_continuation": _run_decrypt_update_continuation,
    "encrypt_final_continuation": _run_encrypt_final_continuation,
    "decrypt_final_continuation": _run_decrypt_final_continuation,
    "encrypt_single_shot_guard": _run_encrypt_single_shot_guard,
    "decrypt_single_shot_guard": _run_decrypt_single_shot_guard,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    fn = _DISPATCH.get(probe)
    if fn is None:
        raise ValueError(f"ffi_length probe: unknown probe {probe!r}")
    try:
        fn(ctx, extra)
    except _SetupRejected:
        return


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)

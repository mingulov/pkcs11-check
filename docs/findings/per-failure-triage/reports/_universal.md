# Cross-Provider Correlation

Universal patterns and provider-specific outliers, derived from `verdicts.jsonl`.

## Universal themes (multi-provider impact)

| Theme | Severity | Providers | Count | Example finding |
|---|---|---|---:|---|
| **Advertised-but-not-operational mechanism** | HIGH | 7 (corepkcs11, kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11) | 310 | `sha1:3632dccbed1b41cd#ph` test_hash_ml_dsa.py |
| **CBC-PKCS5 padding oracle (Vaudenay)** | HIGH | 6 (kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11) | 168 | `sha1:4185bd3e6dd737b6` test_ckr_raw_buffer.py |
| **Op-termination Type-C lifecycle** | HIGH | 6 (kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11) | 164 | `sha1:0694006e303c2696#ph` test_operation_termination.py |
| **Buffer-size protocol deviation** | MEDIUM | 5 (corepkcs11, kryoptic, nss, opencryptoki, wolfpkcs11) | 9 | `sha1:0f0f879139c47fd3#ph` test_buffers.py |
| **Trust-boundary attribute escalation** | HIGH | 4 (corepkcs11, kryoptic, nss, wolfpkcs11) | 12 | `sha1:f223c1ff3426a28c#ph` test_remaining_gaps.py |
| **Wrong-output / Type-A crypto-correctness** | CRITICAL | 4 (kryoptic, nss, softhsm2, wolfpkcs11) | 15 | `sha1:bbe36dcd8a03c859#ph` test_aes_kdf.py |
| **Wrong CKR for invalid signatures** | MEDIUM | 1 (wolfpkcs11) | 15 | `sha1:373b43f690e71469#ph` test_wycheproof_ecdsa.py |
| **NULL-pointer SIGSEGV family** | HIGH | 1 (nss) | 9 | `sha1:fe3f5f0bec77bb85#ph` test_api_boundary.py |
| **Wrap/unwrap policy bypass** | HIGH | 1 (nss) | 1 | `sha1:aa13aa83aaa5d25f#ph` test_remaining_gaps.py |

## Provider-specific HIGH/CRITICAL outliers

Findings that appear on exactly one provider — likely real provider-specific bugs worth filing upstream.

| Provider | HIGH+CRITICAL count | Sample finding |
|---|---:|---|
| wolfpkcs11-master | 39 | `-` CRASH — SIGABRT (rc=6) during HKDF wycheproof vector replay. Shard-4 per-test traces sho |
| opencryptoki-master | 152 | `test_padding_oracle.py` CLEAN_ERROR — Failed: SECURITY: RSA-OAEP padding oracle — non-uniform error codes: {'CKR_FUNCT |
| corepkcs11-main | 0 | — |
| kryoptic-main | 27 | `test_aes_kdf.py` OTHER — AssertionError: assert b'\x9aH\xa4L\x84.\x9f~\\<(\xc2\xd0\xaf\xb9G' != b'\x9aH\x |
| nss-main | 20 | `-` CRASH — SIGSEGV (rc=11) during mechanism-flags behavioral probe. Shard-0 per-test traces |
| softhsm2-main | 2 | `test_errors.py` CLEAN_ERROR — _pytest.outcomes.XFailed: C_EncryptInit with an undersized AES-CBC-PAD IV: rejec |
| tpm2 | 10 | `test_sensitivity.py` OTHER — Failed: raw C_GetAttributeValue copied CKA_VALUE bytes for a CKA_SENSITIVE=True  |

## Routing summary

| Routing | Records | What it means |
|---|---:|---|
| PROVIDER_REPORT | 1259 | File as upstream bug report |
| USER_ESCALATION | 148 | Investigate immediately; security-sensitive |
| HARNESS_FIX | 16 | Fix in pkcs11-check test code |
| DOCS_ONLY | 15 | Documented behaviour; no action |
| PROVIDER_REPORT(nss-main) | 3 | PROVIDER_REPORT(nss-main) |
| MANUAL_REVIEW | 3 | Needs human judgment |
| PROVIDER_REPORT(wolfpkcs11-master) | 2 | PROVIDER_REPORT(wolfpkcs11-master) |

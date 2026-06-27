# example-provider - conformance report
passed 44957 · xfail 3 · fail 8 · crash 1

━━ 🔴 CRASH · fail (1) ━━

[1] tests/test_arithmetic_overflow.py - tests/test_arithmetic_overflow.py: process crashed

━━ 🔴 CRITICAL · fail (4) ━━

### crypto · accepted_invalid
[2] C_Verify CKM_ECDSA_SHA256 - ECDSA accepts forged signature
  want CKR_SIGNATURE_INVALID · got CKR_OK · PKCS#11 v3.2 §6.8 · acvp · tc1 tc2

### crypto · wrong_result
[1] C_Decrypt CKM_RSA_PKCS_OAEP - RSA-OAEP decrypt returns wrong plaintext
  got CKR_OK · PKCS#11 v3.2 §6.7 · wycheproof · tc77

### policy · self_contradiction
[1] C_GetAttributeValue CKM_AES_KEY_GEN - CKA_SENSITIVE key value extractable
  got CKR_OK · PKCS#11 v3.2 §4.9

━━ 🟠 HIGH · fail (3) ━━

### lifecycle · self_contradiction
[1] C_DestroyObject - object usable after destroy reported success
  got CKR_OK · PKCS#11 v3.2 §5.7

### metadata · self_contradiction
[1] C_GetAttributeValue - imported key reports CKA_LOCAL=true and CKA_ALWAYS_SENSITIVE=true
  got CKR_OK · PKCS#11 v3.2 §4.9

### crypto · oracle
[1] C_Decrypt CKM_RSA_PKCS - distinguishable padding-error oracle (Bleichenbacher)
  PKCS#11 v3.2 §6.7

━━ 🟡 deviations · xfail (3) ━━

[1] not_operational - e.g. C_Encrypt CKM_AES_GCM
[1] nonspec_reject - e.g. C_Decrypt CKM_RSA_PKCS
[1] honest_deviation - e.g. C_Sign CKM_RSA_PKCS_PSS

⚪ compliance · 1 sanctioned refusals (CKR_OPERATION_NOT_VALIDATED)
⚪ 1 unclassified - un-migrated fail/xfail; see .jsonl

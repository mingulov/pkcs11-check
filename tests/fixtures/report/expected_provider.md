# example-provider - conformance report

passed 0/0 (0%) · fail 7 (CRITICAL 4 · HIGH 3) · crash 1 · xfail 3 · unclassified 1 (not scored)

## before you report

A PKCS#11 module runs in-process, inside the calling application's trust boundary, and is generally built assuming the application calls the API as documented. This suite deliberately sends hostile input (oversized lengths, malformed templates, invalid parameters) that a correct caller never sends; a finding from such a probe is, on its own, usually a hardening opportunity rather than an exploitable vulnerability in the in-process model. It becomes security-relevant when the module is exposed across a trust boundary (a remote/network PKCS#11 service, a proxy, or a multi-tenant host), a different threat model. Treat each finding as a lead to assess against your deployment - not as a CVE, and not as something to forward to the module's authors without that assessment.

## CRASH (1)

[1] tests/test_arithmetic_overflow.py - process crashed (SIGSEGV)

## CRITICAL - fail (4)

### crypto · accepted_invalid
[2] C_Verify CKM_ECDSA_SHA256 - ECDSA accepts forged signature
  want CKR_SIGNATURE_INVALID · got CKR_OK · PKCS#11 v3.2 §6.8 · tests/test_acvp_ecdsa.py::test_sigver[tc1] · repro acvp [tc1 tc2]

### crypto · wrong_result
[1] C_Decrypt CKM_RSA_PKCS_OAEP - RSA-OAEP decrypt returns wrong plaintext
  got CKR_OK · PKCS#11 v3.2 §6.7 · tests/test_rsa_decrypt.py::test_wrong_output · repro wycheproof [tc77]

### policy · self_contradiction
[1] C_GetAttributeValue CKM_AES_KEY_GEN - CKA_SENSITIVE key value extractable
  got CKR_OK · PKCS#11 v3.2 §4.9 · tests/test_attr_sensitive.py::test_leak

## HIGH - fail (3)

### lifecycle · self_contradiction
[1] C_DestroyObject - object usable after destroy reported success
  got CKR_OK · PKCS#11 v3.2 §5.7 · tests/test_lifecycle.py::test_destroy

### metadata · self_contradiction
[1] C_GetAttributeValue - imported key reports CKA_LOCAL=true and CKA_ALWAYS_SENSITIVE=true
  got CKR_OK · PKCS#11 v3.2 §4.9 · tests/test_attr_invariant.py::test_local_pair

### crypto · oracle
[1] C_Decrypt CKM_RSA_PKCS - distinguishable padding-error oracle (Bleichenbacher)
  PKCS#11 v3.2 §6.7 · (soft-token caveat) · tests/test_rsa_oracle.py::test_padding

## capability gaps

- no advertised-capability gaps observed

## deviations (xfail) (3)

[1] not_operational -> CAPABILITY_AUDIT - e.g. C_Encrypt CKM_AES_GCM
[1] nonspec_reject -> SPEC_REVIEW - e.g. C_Decrypt CKM_RSA_PKCS
[1] honest_deviation -> INVESTIGATE - e.g. C_Sign CKM_RSA_PKCS_PSS

## appendix

- compliance: 1 sanctioned refusals (CKR_OPERATION_NOT_VALIDATED)
- unclassified backlog: 1 un-migrated fail/xfail (framework debt)
- full detail (raw stdout/stderr, full traces, full hex): see <provider>.jsonl

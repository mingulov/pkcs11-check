# wolfpkcs11-master — Per-Failure Triage

**Effective records:** 514
**Categories:** {'PROVIDER_BUG': 251, 'UNKNOWN': 116, 'KNOWN_ISSUE': 111, 'SOFT_TOKEN_CAVEAT': 36}
**Severities:** {'MEDIUM': 199, 'LOW': 169, 'INFO': 94, 'HIGH': 52}

## Findings (287)

Ordered by severity then category.

### `-` (2 findings)

#### F001 [HIGH/PROVIDER_BUG] —  PROVIDER_REPORT(wolfpkcs11-master)
- **Signature:** `crash:wolfpkcs11-master:src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py`
- **Direction:** `CRASH` · **Outcome:** `crashed` · **Tests covered:** 3
- **Example nodeid:** ``
- **Message:** SIGABRT (rc=6) during HKDF wycheproof vector replay. Shard-4 per-test traces show 3 crashes in test_hkdf[tc25/tc51/tc85-valid] (all VALID vectors). Python stack: derive_key -> C_DeriveKey. C stack: li
- **Evidence:** SIGABRT (rc=6) during HKDF wycheproof vector replay. Shard-4 per-test traces show 3 crashes in test_hkdf[tc25/tc51/tc85-valid] (all VALID vectors). Python stack: derive_key -> C_DeriveKey. C stack: libwolfpkcs11.so C_DeriveKey+0x26e -> __libc_free -> abort, i.e. a heap corruption / double-free inside wolfPKCS11 HKDF derive on standard KAT input. Module crash on a valid derive = real provider bug.

#### F002 [HIGH/PROVIDER_BUG] —  PROVIDER_REPORT(wolfpkcs11-master)
- **Signature:** `crash:wolfpkcs11-master:src/pkcs11_check/testcases/x509/test_identity.py`
- **Direction:** `CRASH` · **Outcome:** `crashed` · **Tests covered:** 1
- **Example nodeid:** ``
- **Message:** SEGFAULT during test_limbo_identity_closeness (normal sign op on an imported Limbo identity key). Shard-5 per-test longrepr shows Python stack sign_single -> _two_call_output -> C_Sign, and C stack li
- **Evidence:** SEGFAULT during test_limbo_identity_closeness (normal sign op on an imported Limbo identity key). Shard-5 per-test longrepr shows Python stack sign_single -> _two_call_output -> C_Sign, and C stack libwolfpkcs11.so C_Sign+0x4c3 -> +0x1179f -> crash. Adaptive isolation confirmed the culprit: retry with this test deselected passed cleanly. (File-level rc=5/SIGTRAP is the process exit; the in-test crash was a SIGSEGV in C_Sign.) Module crash during a routine X.509 sign.

### `test_ccm.py` (45 findings)

#### F003 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:05ae18525f1cc2e8`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc45]`
- **Message:** Failed: AES-dec-tc45: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F004 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:515fd91adba97084`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc46]`
- **Message:** Failed: AES-dec-tc46: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F005 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8124e2bc701917f2`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc47]`
- **Message:** Failed: AES-dec-tc47: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F006 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f71701039dfdc4b3`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc48]`
- **Message:** Failed: AES-dec-tc48: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9538b34cdd95e9db`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc49]`
- **Message:** Failed: AES-dec-tc49: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F008 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:92fae3ade56bd4fc`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc50]`
- **Message:** Failed: AES-dec-tc50: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F009 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3632bfcace13011c`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc51]`
- **Message:** Failed: AES-dec-tc51: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4357e670a893f6ea`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc52]`
- **Message:** Failed: AES-dec-tc52: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ff7ae43312e65389`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc53]`
- **Message:** Failed: AES-dec-tc53: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F012 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:795b4e535e9baeee`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc54]`
- **Message:** Failed: AES-dec-tc54: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F013 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e65ecc50b745b544`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc55]`
- **Message:** Failed: AES-dec-tc55: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F014 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:21996ee6aab9f485`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc56]`
- **Message:** Failed: AES-dec-tc56: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F015 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:99df6cd598ace1af`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc57]`
- **Message:** Failed: AES-dec-tc57: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F016 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2dd2b23976bba459`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc58]`
- **Message:** Failed: AES-dec-tc58: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F017 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d5ade7309021835`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc59]`
- **Message:** Failed: AES-dec-tc59: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F018 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5d76eb007383cfa7`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc60]`
- **Message:** Failed: AES-dec-tc60: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F019 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bde4be8b5c8ec9be`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc61]`
- **Message:** Failed: AES-dec-tc61: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F020 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1658523b803b2307`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc62]`
- **Message:** Failed: AES-dec-tc62: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F021 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e9991fa9831cae4f`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc63]`
- **Message:** Failed: AES-dec-tc63: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F022 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:007f2c2308cbc000`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc64]`
- **Message:** Failed: AES-dec-tc64: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F023 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d6511f8172cc0386`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc65]`
- **Message:** Failed: AES-dec-tc65: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F024 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:30d4818ab55d471c`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc66]`
- **Message:** Failed: AES-dec-tc66: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F025 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b1c55bc7f6262094`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc67]`
- **Message:** Failed: AES-dec-tc67: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F026 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a5a20556adf8638c`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc68]`
- **Message:** Failed: AES-dec-tc68: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F027 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:73b16a2c97e40dad`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc69]`
- **Message:** Failed: AES-dec-tc69: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F028 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b60866ddf216571d`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc70]`
- **Message:** Failed: AES-dec-tc70: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F029 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:727d54ff26713efb`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc71]`
- **Message:** Failed: AES-dec-tc71: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F030 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8937b4470d3d8e39`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc72]`
- **Message:** Failed: AES-dec-tc72: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F031 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09820febd70d750a`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc73]`
- **Message:** Failed: AES-dec-tc73: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F032 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c94e307be28ba457`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc74]`
- **Message:** Failed: AES-dec-tc74: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F033 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:20f107b563c1279d`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc75]`
- **Message:** Failed: AES-dec-tc75: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F034 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f0ea1c8a27dea73b`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc76]`
- **Message:** Failed: AES-dec-tc76: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F035 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f9f77a33035e875`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc77]`
- **Message:** Failed: AES-dec-tc77: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F036 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:75a23412a5d61469`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc78]`
- **Message:** Failed: AES-dec-tc78: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F037 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3efe0a810e15e21f`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc79]`
- **Message:** Failed: AES-dec-tc79: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F038 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:63ccaf35a7c4c4c0`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc80]`
- **Message:** Failed: AES-dec-tc80: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F039 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d2657804cdead778`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc81]`
- **Message:** Failed: AES-dec-tc81: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F040 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:77807ae1024c6174`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc82]`
- **Message:** Failed: AES-dec-tc82: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F041 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da35265df0f7ee71`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc83]`
- **Message:** Failed: AES-dec-tc83: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F042 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a86f0331743c6c4b`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc84]`
- **Message:** Failed: AES-dec-tc84: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F043 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ea34ee13b45332a`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc85]`
- **Message:** Failed: AES-dec-tc85: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F044 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c609b6ca6b4bb7dc`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc86]`
- **Message:** Failed: AES-dec-tc86: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F045 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76511c33b39f0254`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc87]`
- **Message:** Failed: AES-dec-tc87: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F046 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fe11a227272eed25`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_decrypt[AES-dec-tc88]`
- **Message:** Failed: AES-dec-tc88: valid-tag CCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F047 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f025e230397ada52`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 44
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_ccm.py::test_acvp_aes_ccm_ecma_encrypt[AES-enc-tc1]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM encrypt nonce=16B tag=8B: mechanism operational but this request cleanly rejected (canonical AES_CCM encrypt OK); vector: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_gcm.py` (9 findings)

#### F048 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:828c34a69c60bea9`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc46]`
- **Message:** Failed: AES-dec-tc46: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F049 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4edb4377a4a3d17d`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc48]`
- **Message:** Failed: AES-dec-tc48: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F050 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:126828b1683fdb09`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc51]`
- **Message:** Failed: AES-dec-tc51: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F051 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a003d3b8ed1a38e9`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc52]`
- **Message:** Failed: AES-dec-tc52: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F052 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df33fbb9a3af5cb3`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc53]`
- **Message:** Failed: AES-dec-tc53: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F053 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df767b0aee36d3cb`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc54]`
- **Message:** Failed: AES-dec-tc54: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F054 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4d437ce18d618da`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc59]`
- **Message:** Failed: AES-dec-tc59: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F055 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8c2767e9616ed74c`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_decrypt[AES-dec-tc60]`
- **Message:** Failed: AES-dec-tc60: valid-tag GCM vector rejected with tag auth failure (Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK)
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F056 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:70b9c3c41f37a1bb`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 15
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_gcm.py::test_acvp_aes_gcm_encrypt[AES-enc-tc16]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM encrypt iv=15B tag=4B: mechanism operational but this request cleanly rejected (canonical AES_GCM encrypt OK); vector: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_acvp_mldsa.py` (1 findings)

#### F057 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4d1ab2f72eeb5a81#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 44
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py::TestMlDsaSigGen::test_mldsa_siggen[ML-DSA-sigGen-ML-DSA-44-tc17]`
- **Message:** _pytest.outcomes.XFailed: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_ckr_decrypt.py` (1 findings)

#### F058 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:58c9432ca9ac9063#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_key_function_not_permitted`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit(key_CKA_DECRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.9.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecryptInit(key_CKA_DECRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.9.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_derive.py` (1 findings)

#### F059 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5d23d722c04e55c2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_PARAM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_PARAM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_encrypt.py` (1 findings)

#### F060 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:69d43d1d4763a35e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_key_function_not_permitted`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit(key_CKA_ENCRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.8.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit(key_CKA_ENCRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.8.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_general.py` (1 findings)

#### F061 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5fb94fe5b6c98de1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_general.py::TestInitializeErrors::test_double_initialize`
- **Message:** Failed: C_Initialize double initialize: child subprocess did not emit an OK marker; stdout: CKR:already_init_accepted
; stderr:
- **Evidence:** W17: test_ckr_general::test_double_initialize — second C_Initialize in same process accepted (stdout 'already_init_accepted'); PKCS#11 v3.1 §3.3 expects CKR_CRYPTOKI_ALREADY_INITIALIZED on the nested call (idempotent but reporting required).

### `test_ckr_kem.py` (1 findings)

#### F062 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:86535e6aac3d5804#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_kem.py::TestEncapsulateKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_FUNCTION_NOT_PERMITTED, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_FUNCTION_NOT_PERMITTED, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_keygen.py` (4 findings)

#### F063 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a5a847afea703e81`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_kem_parameter_set_ulong_malformed_length[private-underlong]`
- **Message:** Failed: ML-KEM C_GenerateKeyPair with underlong private CKA_PARAMETER_SET CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F064 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:324b3827c56fe59a`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_kem_parameter_set_ulong_malformed_length[private-overlong]`
- **Message:** Failed: ML-KEM C_GenerateKeyPair with overlong private CKA_PARAMETER_SET CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9ad70eb8e27227e7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_dsa_parameter_set_ulong_malformed_length[public-underlong]`
- **Message:** _pytest.outcomes.XFailed: ML-DSA C_GenerateKeyPair with overlong public CKA_PARAMETER_SET CK_ULONG attribute: rejected with CKR_BUFFER_TOO_SMALL, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARGUMENTS_BAD', 'CKR_F
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-DSA C_GenerateKeyPair with overlong public CKA_PARAMETER_SET CK_ULONG attribute: rejected with CKR_BUFFER_TOO_SMALL, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSIS. Direction = reject-valid → functional gap (LOW).

#### F066 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5fbd8ab0a6fbeaca#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_kem_parameter_set_ulong_malformed_length[public-underlong]`
- **Message:** _pytest.outcomes.XFailed: ML-KEM C_GenerateKeyPair with overlong public CKA_PARAMETER_SET CK_ULONG attribute: rejected with CKR_BUFFER_TOO_SMALL, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARGUMENTS_BAD', 'CKR_F
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM C_GenerateKeyPair with overlong public CKA_PARAMETER_SET CK_ULONG attribute: rejected with CKR_BUFFER_TOO_SMALL, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSIS. Direction = reject-valid → functional gap (LOW).

### `test_ckr_object.py` (1 findings)

#### F067 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0b92c875357d9497#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestSetAttributeErrors::test_set_readonly_class`
- **Message:** Failed: C_SetAttributeValue claimed success and the read-only CKA_CLASS actually changed (self-contradiction) [PKCS#11 v3.1 Sec.5.7.6: CKA_CLASS is read-only]
- **Evidence:** W13 Type B: ckr/test_ckr_object::test_set_readonly_class — C_SetAttributeValue claimed CKR_OK and read-only CKA_CLASS actually changed. PKCS#11 v3.1 Sec.5.7.6.

### `test_ckr_raw_buffer.py` (3 findings)

#### F068 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4185bd3e6dd737b6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_Decrypt AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000000
LEN:14
OVERWRITTEN:13
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F069 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:05423bcaba242131`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_DecryptFinal AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000000
LEN:15
OVERWRITTEN:14
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F070 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e8911b3b14c8f788#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestAttributeBufferTooSmallGuards::test_get_attribute_value_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_GetAttributeValue undersized attribute buffer guard: subprocess failed with exit code 1
stdout: NEEDED:30
CKR:0x00000150
LEN:1
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK
- **Evidence:** Buffer-protocol OOB: test_ckr_raw_buffer::test_get_attribute_value_buffer_too_small_preserves_guard_and_retries — subprocess failed; C_GetAttributeValue on undersized buffer reports wrong retry length / writes past (per docs/module-issues.md: 'writes 13 bytes past a declared 1-byte buffer'). PKCS#11 §5.2 requires true length with no write on CKR_BUFFER_TOO_SMALL.

### `test_ckr_wrap.py` (1 findings)

#### F071 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5448a4e5c93e68ab#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py::TestWrapKeyErrors::test_wrapping_key_size_range`
- **Message:** Failed: C_WrapKey(wrapping_key_size_out_of_range): got CKR_MECHANISM_PARAM_INVALID, not in acceptable set ['CKR_WRAPPING_KEY_SIZE_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 'CKR_KEY_TYPE_INCONSISTENT', 'CKR_FUNCTION_FAILED', 'CKR_GENERAL_ERROR', 'CKR_HOST_MEMORY', 'CKR_SESSI
- **Evidence:** Wrong CKR: test_ckr_wrap::test_wrapping_key_size_range — C_WrapKey with wrapping_key_size out of range returned CKR_MECHANISM_PARAM_INVALID, not in acceptable set {CKR_WRAPPING_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE}.

### `test_api_security.py` (1 findings)

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f166fadaa5f0bb2a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_security.py::TestAccessControl::test_handle_prediction`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_FAILED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_FAILED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_arithmetic_overflow.py` (2 findings)

#### F073 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ee2c85577cbe6720`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow[pub_template_overflow]`
- **Message:** Failed: C_GenerateKeyPair(pub_count=0xffffffffffffffff, priv_count=0x1): module crashed with signal 7
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F074 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c54b70d1803014d6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow[priv_template_overflow]`
- **Message:** Failed: C_GenerateKeyPair(pub_count=0x1, priv_count=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_cve_regression.py` (1 findings)

#### F075 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:edf6142526c22a7c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_cve_regression.py::TestTookanUnwrapAttrs::test_unwrapped_key_preserves_extractable`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: C_WrapKey/C_UnwrapKey leaves an operation active after the call returns; next C_*Init in the same session returns CKR_OPERATION_ACTIVE. Spec PKCS#11 v3.1 Sec.5.14/5.15: wrap/unwrap always terminate. Evidence: test_unwrapped_key_preserves_extractable -> 'Unexpected CK_RV CKR_OPERATION_ACTIVE; expected CKR_OK'.

### `test_ffi_length_boundary.py` (17 findings)

#### F076 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:78bdc682358127c1`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRsaPssSaltLengthBoundary::test_rsa_pss_salt_length_boundary[isize_max]`
- **Message:** Failed: C_Sign(SHA256_RSA_PKCS_PSS, sLen=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F077 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:15a3d6fcc0c1074d`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[password-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, password length=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F078 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ee56a224e76d0d36`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[prf_data-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, prf_data length=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F079 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:518c95f9f005d407`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_sign_isize_boundary[isize_max]`
- **Message:** Failed: C_Sign(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F080 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:154d1d200a318f0f`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** Failed: C_Verify(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F081 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:fb60c5685a166c12`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F082 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e49360a8eab5a04a`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F083 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:80406251d7b42c1a`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F084 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:beb34bea4efa07e0`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F085 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e324a023521da04b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max_plus_1]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x8000000000000000): subprocess failed with exit code 1
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775808
rv=CKR_OK
rv_name=CKR_OK
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList"
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F086 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:15198c4af3d9a707`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_SeedRandom
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F087 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a54bf7d20e718872`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max_plus_1]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x8000000000000000): subprocess failed with exit code 1
stdout: TARGET:C_SeedRandom
LEN:9223372036854775808
rv=CKR_OK
rv_name=CKR_OK
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F088 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cada1019b3cf3871`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestGcmAadLengthBoundary::test_gcm_aad_length_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Encrypt(AES_GCM, ulAADLen=0x8000000000000000): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F089 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2195feb458b0fe2d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestCcmAadLengthBoundary::test_ccm_aad_length_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Encrypt(AES_CCM, ulAADLen=0x8000000000000000): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F090 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:41e18af739fc4809`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[salt-isize_max_plus_1]`
- **Message:** Failed: C_GenerateKey(PBKDF2, salt length=0x8000000000000000): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F091 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:13d0f3e1a756bc1d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestAesCbcEncryptDataMalformedParams::test_aes_cbc_encrypt_data_malformed_params[null_data_nonzero_length]`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(AES_CBC_ENCRYPT_DATA, pData=NULL,length=16): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_DATA_LEN_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCO
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F092 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2b7caeb2b743dee2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[salt-isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(PBKDF2, salt length=0x7fffffffffffffff): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_DATA_LEN_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONS
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_padding_oracle.py` (1 findings)

#### F093 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:85666aa1f4b4f1e1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_padding_oracle.py::TestAESPaddingOracle::test_cbc_pad_all_last_block_positions`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for AES-CBC-PAD oracle sweep setup is not operational: CKR_FUNCTION_FAILED
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_parameter_validation.py` (10 findings)

#### F094 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3b23b8e1bb7f615c`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[single-zero-byte-iv]`
- **Message:** Failed: AES-GCM with 1-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F095 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8e89d77f79bbf6a1`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[4-zero-bytes-iv]`
- **Message:** Failed: AES-GCM with 4-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F096 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c82dec4ac03eac58`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvReuse::test_gcm_iv_reuse_same_key`
- **Message:** Failed: AES-GCM IV reuse with the same key (NIST SP 800-38D requires unique IVs): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F097 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:133382a02e7a4cac`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=0]`
- **Message:** Failed: RSA keygen with cryptographically invalid exponent e=0: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F098 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08bbe0f743e46e57`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-0-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 0-bit tag (below NIST 96-bit minimum): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76a85d6e0f81677f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-8-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 8-bit tag (below NIST 96-bit minimum): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a2e801aac77a04b7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-32-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 32-bit tag (below NIST 96-bit minimum): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:36656722ba372842`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-64-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 64-bit tag (below NIST 96-bit minimum): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:edf09a1fe08b2d72#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=1]`
- **Message:** _pytest.outcomes.XFailed: RSA keygen with cryptographically invalid exponent e=1: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA keygen with cryptographically invalid exponent e=1: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLAT. Direction = reject-valid → functional gap (LOW).

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0140585e8f83ab3e#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestEcPointValidation::test_ecdh_invalid_point[off-curve-point]`
- **Message:** _pytest.outcomes.XFailed: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'C. Direction = reject-valid → functional gap (LOW).

### `test_recover_length_boundary.py` (2 findings)

#### F104 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:956b26aad0555d1a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_verify_recover_huge_signature_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_VerifyRecover with ulSignatureLen=0x7fffffffffffffff: rejected with CKR_FUNCTION_FAILED, expected ['CKR_SIGNATURE_LEN_RANGE']
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cadf5d18b6ec43ef#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_sign_recover_huge_data_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_SignRecoverInit rejected: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_SignRecoverInit rejected: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_secret_key_value_len.py` (8 findings)

#### F106 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3a48ff7ce26fe851#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestDeriveKeySecretKeyValueLen::test_hkdf_derive_max_output_value_len_does_not_crash[hkdf_sha256_max_output]`
- **Message:** Failed: C_DeriveKey(HKDF_SHA256, CKA_VALUE_LEN=0x1fe0): module crashed with signal 11
stdout: TARGET_RV:0x00000006
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech
- **Evidence:** C_DeriveKey(CKM_HKDF_DERIVE, CKA_VALUE_LEN=0x1fe0=8160) crashes signal 11. 8160 = 255*32 is the RFC 5869 maximum HKDF-SHA256 output, a legitimate spec value (not UB-provoked boundary). Module must derive or reject with CKR_KEY_SIZE_RANGE, not crash.

#### F107 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d2ec4300fe7cd6a2`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestCreateObjectSecretKeyValueLen::test_create_secret_key_with_oversized_value_len_does_not_crash[generic_secret_with_value]`
- **Message:** Failed: C_CreateObject(CKK_GENERIC_SECRET, CKA_VALUE_LEN=0xffffffffffffffff, include_value=False): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F108 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8f96548a785b8bdf`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_copy_secret_key_with_oversized_value_len_does_not_crash`
- **Message:** Failed: C_CopyObject(secret key, CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F109 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bf9698688cda85e8`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_set_secret_key_oversized_value_len_does_not_crash`
- **Message:** Failed: C_SetAttributeValue(secret key, CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F110 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d2b2596b5de5ef1e`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestDigestKeySecretKeyValueLen::test_digest_key_after_oversized_value_len_import_does_not_crash`
- **Message:** Failed: C_DigestKey(secret key imported with CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F111 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:eb634a6a888a86a5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestUnwrapSecretKeyValueLen::test_aes_ecb_unwrap_oversized_value_len_does_not_crash`
- **Message:** Failed: C_UnwrapKey(AES_ECB, CKA_VALUE_LEN=0xffffffffffffffff): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F112 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5dfad13cabf4b912`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestGenerateKeySecretKeyValueLen::test_generic_secret_generate_key_oversized_value_len_rejects_cleanly`
- **Message:** Failed: C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 11
stdout: CONTROL_BEGIN:32
CONTROL_RV:0x00000000
CONTROL_RV_NAME:CKR_OK
CONTROL_VALUE_LEN_RV:0x00000000
CONTROL_VALUE_LEN:32
TARGET_BEGIN:18446744073709551615
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F113 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:6b2b3ccbf622a49d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestGenerateKeySecretKeyValueLen::test_pbkdf2_generate_key_oversized_value_len_rejects_cleanly`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(PBKDF2, CKA_VALUE_LEN=0xffffffffffffffff): rejected with CKR_HOST_MEMORY, expected ['CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_MECHANISM_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_tookan.py` (1 findings)

#### F114 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7aa95fa1928271a1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_tookan.py::TestKeyTypeConfusionOnUnwrap::test_unwrap_aes_as_des3_rejected`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: security/test_tookan::test_unwrap_aes_as_des3_rejected failed with CKR_OPERATION_ACTIVE. Negative-op path still must terminate.

### `test_access.py` (1 findings)

#### F115 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:183461818709c745#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access.py::TestMultipleSessions::test_session_object_visible_in_other_session`
- **Message:** assert 0 >= 1
 +  where 0 = len([])
- **Evidence:** Type C: test_access::test_session_object_visible_in_other_session — session object created in A not visible in B. PKCS#11 v3.1 Sec.5.5: session objects visible across all sessions of the same slot.

### `test_access_control.py` (1 findings)

#### F116 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:85599209a8f94ea0#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_control.py::TestCopyObject::test_copy_token_object_stays_token`
- **Message:** assert False is True
- **Evidence:** Type B: test_access_control::test_copy_token_object_stays_token — C_CopyObject of a CKA_TOKEN=True object yields copy with CKA_TOKEN=False. PKCS#11 v3.1 Sec.5.3: copy must preserve CKA_TOKEN.

### `test_access_levels.py` (3 findings)

#### F117 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:847ce259f380025a#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestTrustedAttribute::test_user_cannot_set_trusted`
- **Message:** Failed: SECURITY: USER session created and was granted CKA_TRUSTED=True on a freshly-generated key — trust boundary breached
- **Evidence:** W12 Type B security: test_access_levels::test_user_cannot_set_trusted — USER session created a key with CKA_TRUSTED=True via C_GenerateKey. PKCS#11 v3.1 Sec.5.7.6: CKA_TRUSTED settable ONLY by SO. USER granting themselves trust = trust-boundary breach (opens CKA_WRAP_WITH_TRUSTED bypass).

#### F118 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8d5790426535889f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestTrustedAttribute::test_user_cannot_setattr_trusted`
- **Message:** Failed: SECURITY: USER session escalated a key's CKA_TRUSTED from False to True via C_SetAttributeValue — trust boundary breached, opens CKA_WRAP_WITH_TRUSTED bypass
- **Evidence:** W12 Type B: test_user_cannot_setattr_trusted — USER escalated CKA_TRUSTED False->True via C_SetAttributeValue. Trust boundary breach.

#### F119 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:be87bfff555dd79e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestTrustedAttribute::test_wrap_with_trusted_cannot_be_cleared_once_true`
- **Message:** Failed: SECURITY: CKA_WRAP_WITH_TRUSTED downgraded from True to False via C_SetAttributeValue
- **Evidence:** W12 Type B: test_wrap_with_trusted_cannot_be_cleared_once_true — CKA_WRAP_WITH_TRUSTED downgraded True->False via C_SetAttributeValue. Once set, must be sticky per PKCS#11 spec.

### `test_aes_modes.py` (1 findings)

#### F120 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:31e4b1da5603f7d7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTR::test_aes_ctr_roundtrip`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_BUFFER_TOO_SMALL; expected one of: CKR_OK
- **Evidence:** Wrong CKR: test_aes_modes::test_aes_ctr_roundtrip + sibling return CKR_BUFFER_TOO_SMALL where CKR_OK expected (output buffer correctly sized for AES-CTR). Bug in CTR output-length estimation.

### `test_always_authenticate.py` (3 findings)

#### F121 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6925877adb3007b5#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_always_authenticate.py::TestAlwaysAuthenticateEnforcement::test_sign_without_context_specific_login_rejected`
- **Message:** Failed: C_Sign on CKA_ALWAYS_AUTHENTICATE=True key succeeded without prior CKU_CONTEXT_SPECIFIC login — module is not enforcing the spec-mandated re-authentication. This is a CVE-class security gap.
- **Evidence:** W14 CVE-class security: test_always_authenticate::test_sign_without_context_specific_login_rejected — C_Sign on CKA_ALWAYS_AUTHENTICATE=True key SUCCEEDED without prior CKU_CONTEXT_SPECIFIC login. PKCS#11 v3.1 Sec.5.7.6+6.6.2: ALWAYS_AUTHENTICATE mandates fresh CKU_CONTEXT_SPECIFIC login before EACH use. Bypass = private-key op without re-auth.

#### F122 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4c24308122f23a96#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_always_authenticate.py::TestAlwaysAuthenticateEnforcement::test_sign_with_context_specific_login_succeeds`
- **Message:** AssertionError: CKU_CONTEXT_SPECIFIC login failed: CKR_OPERATION_NOT_INITIALIZED
assert 145 == <CKR_OK: 0x00000000>
- **Evidence:** WolfPKCS11: C_Login(CKU_CONTEXT_SPECIFIC) returns CKR_OPERATION_NOT_INITIALIZED (rv=145). Context-specific login path broken — login state machine not initialized when it should be. Blocks all CKA_ALWAYS_AUTHENTICATE flows.

#### F123 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3a36cac7a18345b8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_always_authenticate.py::TestAlwaysAuthenticateEnforcement::test_second_sign_requires_fresh_reauth`
- **Message:** assert 145 == <CKR_OK: 0x00000000>
- **Evidence:** WolfPKCS11: test_second_sign_requires_fresh_reauth — second C_Login(CKU_CONTEXT_SPECIFIC) returns CKR_OPERATION_NOT_INITIALIZED (rv=145). Fresh re-auth path broken.

### `test_attribute_enforcement.py` (1 findings)

#### F124 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:599d4a5871e6beb5#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_enforcement.py::TestTokenAttributePromotion::test_setattr_token_promotion_consistency`
- **Message:** Failed: SECURITY: module silently ignored C_SetAttributeValue(CKA_TOKEN=True) — half-promoted state. Lying-module pattern at the persistence boundary.
- **Evidence:** Type B lying-module: test_attribute_enforcement::test_setattr_token_promotion_consistency — module silently ignored C_SetAttributeValue(CKA_TOKEN=True) claiming CKR_OK without applying it. Half-promoted state. Self-contradiction at persistence boundary.

### `test_authenticated_wrap.py` (1 findings)

#### F125 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2d6175801c37ad6a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_authenticated_wrap.py::TestWrapIntegrity::test_aes_key_wrap_bit_flip_detected`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_authenticated_wrap::test_aes_key_wrap_bit_flip_detected failed with CKR_OPERATION_ACTIVE.

### `test_buffers.py` (3 findings)

#### F126 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5dab942f7f3b7178#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_digest_final_buffer_too_small_then_correct`
- **Message:** AssertionError: After CKR_BUFFER_TOO_SMALL, pulSize must equal required size; got 8, expected 32
assert 8 == 32
 +  where 8 = c_ulong(8).value
- **Evidence:** Buffer-protocol violation: test_buffers::test_digest_final_buffer_too_small_then_correct — after CKR_BUFFER_TOO_SMALL, pulSize must equal 32; wolfpkcs11 reports 8. PKCS#11 v3.1 §5.2: CKR_BUFFER_TOO_SMALL must report true required length.

#### F127 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8cffcd2d920c9ed5#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_digest_final_preserves_state_across_multiple_retries`
- **Message:** AssertionError: Retry #1: pulSize must be 32, got 1
assert 1 == 32
 +  where 1 = c_ulong(1).value
- **Evidence:** Buffer-protocol violation: test_digest_final_preserves_state_across_multiple_retries — Retry #1: pulSize must be 32, wolfpkcs11 reports 1. Retry-length reporting broken.

#### F128 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a85bd3aaa1684b93#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct`
- **Message:** AssertionError: C_SignFinal with 16-byte buffer for RSA-2048 returned 0x00000070, expected CKR_BUFFER_TOO_SMALL
assert 112 == <CKR_BUFFER_TOO_SMALL: 0x00000150>
- **Evidence:** Buffer-protocol violation: test_sign_final_buffer_too_small_then_correct — C_SignFinal with 16-byte buffer for RSA-2048 returned CKR_MECHANISM_INVALID (rv=0x70) instead of CKR_BUFFER_TOO_SMALL. Wrong CKR on buffer-too-small path.

### `test_crossverify.py` (1 findings)

#### F129 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bfc51ea58a0d618b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_crossverify.py::TestAESCrossVerify::test_aes_256_ecb_encrypt`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** WolfPKCS11 rejects minimal-template AES secret-key C_CreateObject ({CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE}) with CKR_ATTRIBUTE_VALUE_INVALID. Template is the minimal valid PKCS#11 secret-key template. Cross-verify tests blocked at import.

### `test_crossverify_extended.py` (1 findings)

#### F130 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b77ce0e7b39c1c89#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_crossverify_extended.py::TestAESCBCCrossVerify::test_aes_cbc_encrypt_crossverify`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** test_crossverify_extended::test_aes_cbc_encrypt_crossverify + 2 siblings fail with CKR_ATTRIBUTE_VALUE_INVALID on AES key import.

### `test_dh_key_agreement.py` (2 findings)

#### F131 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:49987a16c5a1c223#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len`
- **Message:** AssertionError: accepted CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0
- **Evidence:** Accept-invalid: test_dh_key_agreement::test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len — C_DeriveKey(CKM_DH_PKCS_DERIVE, CKA_VALUE_LEN=0) accepted. CKA_VALUE_LEN=0 invalid (spec requires positive output length). Type C accept-invalid.

#### F132 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d906de6e8f87af8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_different_keypairs_different_secrets`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Reject-valid: test_dh_key_agreement::test_dh_different_keypairs_different_secrets — CKR_FUNCTION_FAILED on valid DH derive. DH PKCS derive advertised but not fully operational.

### `test_errors.py` (1 findings)

#### F133 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:014b7105b593c168`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestEmptyInputs::test_encrypt_empty_data`
- **Message:** _pytest.outcomes.XFailed: C_Encrypt (length query) of empty data under AES-CBC-PAD: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_DATA_LEN_RANGE']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_fuzz.py` (1 findings)

#### F134 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:467e29861bf35c28#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestDigestFuzz::test_sha256_deterministic`
- **Message:** hypothesis.errors.FlakyFailure: Inconsistent results from replaying a test case!
  last: INTERESTING from XFailed at /app/.venv/lib/python3.14/site-packages/_pytest/outcomes.py:193
    context: CkrAssertionError at /app/src/pkcs11_check/raw/rv.py:53
  this: INTERESTING from CkrAssertionError at /app
- **Evidence:** WolfPKCS11-master digest path returns inconsistent CK_RV values across calls (Hypothesis FlakyFailure: one run xfails on the reject-rv list, next run returns a different code outside the list). Provider returns non-deterministic error codes for the same input on digest path.

### `test_interop.py` (1 findings)

#### F135 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:94c6d6acbd512b0d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_interop.py::TestAESInterop::test_aes_ecb_encrypt_p11_decrypt_crypto`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** test_interop::test_aes_ecb_encrypt_p11_decrypt_crypto + 4 siblings fail with CKR_ATTRIBUTE_VALUE_INVALID on AES/HMAC key import.

### `test_kem.py` (2 findings)

#### F136 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:dbe74c94846d484d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMNegative::test_decapsulate_with_invalid_attributes_in_template`
- **Message:** Failed: inject CKA_VALUE into ML-KEM decapsulation template: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F137 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:81e4a9d35def7fff#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMNegative::test_kem_mechanisms_with_wrong_key_type`
- **Message:** _pytest.outcomes.XFailed: ML-KEM wrong-key-type reject: rejected with CKR_KEY_HANDLE_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT', 'CKR_KEY_FUNCTION_NOT_PERMITTED', 'CKR_MECHANISM_INVALID', 'CKR_TEMPLATE_INCOMPLETE']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM wrong-key-type reject: rejected with CKR_KEY_HANDLE_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT', 'CKR_KEY_FUNCTION_NOT_PERMITTED', 'CKR_MECHANISM_INVALID', 'CKR_TEMPLATE_INCOMPLETE']. Direction = reject-valid → functional gap (LOW).

### `test_key_lifecycle.py` (1 findings)

#### F138 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9a83f1e8ece5ece5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_lifecycle.py::TestAESKeyWrapLifecycle::test_aes_wrap_unwrap_roundtrip`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_key_lifecycle::test_aes_wrap_unwrap_roundtrip failed with CKR_OPERATION_ACTIVE.

### `test_key_usage_policy.py` (3 findings)

#### F139 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:36b9aabb6203f9af#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestAESKeyUsagePolicy::test_decrypt_only_key_cannot_encrypt`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']. Direction = reject-valid → functional gap (LOW).

#### F140 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:82e232db77d9b9af#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestAESKeyUsagePolicy::test_encrypt_only_key_cannot_decrypt`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit on an AES key created CKA_DECRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecryptInit on an AES key created CKA_DECRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']. Direction = reject-valid → functional gap (LOW).

#### F141 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a74816273fea1c56#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestRSAKeyUsagePolicy::test_encrypt_only_rsa_cannot_sign`
- **Message:** _pytest.outcomes.XFailed: C_SignInit on an RSA private key created CKA_SIGN=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_SignInit on an RSA private key created CKA_SIGN=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']. Direction = reject-valid → functional gap (LOW).

### `test_keymgmt.py` (1 findings)

#### F142 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a5be66c86ab43470#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_keymgmt.py::TestKeyWrapUnwrap::test_wrap_unwrap_roundtrip`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_keymgmt::test_wrap_unwrap_roundtrip failed with CKR_OPERATION_ACTIVE.

### `test_large_objects.py` (1 findings)

#### F143 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ae9b975c3ec8e991#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_large_objects.py::TestLargeRandomGeneration::test_generate_100kb_random`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** C_GenerateRandom failure: test_large_objects::test_generate_100kb_random — wolfpkcs11 returns CKR_FUNCTION_FAILED on a 100KB C_GenerateRandom request. PKCS#11 §5.16: C_GenerateRandom must handle arbitrary-length requests (chunk internally).

### `test_mech_digest.py` (9 findings)

#### F144 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7995aecde61063df`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA224]`
- **Message:** _pytest.outcomes.XFailed: SHA224:digest: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F145 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ed675c95059e0ad6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA256]`
- **Message:** _pytest.outcomes.XFailed: SHA256:digest: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F146 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4a5bc6523f50fa91`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA384]`
- **Message:** _pytest.outcomes.XFailed: SHA384:digest: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F147 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a63c946d81a1231a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA3_224]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224:digest: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F148 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:94d82aae496722e8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA3_256]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256:digest: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F149 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:598197ea78bd83dd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA3_384]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384:digest: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F150 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3e77848789aa6800`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA3_512]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512:digest: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F151 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c2d3da86027c7334`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA512]`
- **Message:** _pytest.outcomes.XFailed: SHA512:digest: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F152 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:177ee2bdfd3aee0a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_digest.py::TestMechDigest::test_known_empty[SHA_1]`
- **Message:** _pytest.outcomes.XFailed: SHA_1:digest: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_encrypt.py` (1 findings)

#### F153 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dcc4b9f332c65fb7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR:decrypt: advertised but not operational (CKR_BUFFER_TOO_SMALL)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_lifecycle.py` (2 findings)

#### F154 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c4638c8126f23f64#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestAESWrapUnwrapUse::test_aes_wrap_roundtrip`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_mech_lifecycle::test_aes_wrap_roundtrip — C_WrapKey(CKM_AES_KEY_WRAP) returns CKR_OPERATION_ACTIVE; prior wrap left state dangling.

#### F155 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d0700b1313eb8b2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestRSAOAEPWrapLifecycle::test_rsa_oaep_wrap_aes_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_RSA_PKCS_OAEP:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_multipart.py` (15 findings)

#### F156 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e8436e6af0306275`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA224_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA224_RSA_PKCS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F157 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b5883a84727f27ec`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA256_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F158 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f9569afccc4d5600`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA384_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F159 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bd037e50f33f5acd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA512_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F160 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:31a6cf55163c60f7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB:multipart-encrypt: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F161 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d39cd2423c33fa41`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA1]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA1:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F162 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a8df8bb6758d6a51`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA224]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA224:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F163 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6a6dacf4eda52fa8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA256]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F164 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7283ec1b83c2b5b6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA384]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA384:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F165 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:837ce3f7deb5c271`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA512]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA512:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F166 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f8ced65e9e2281d1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F167 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fef1f3a4e8721704`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: ML_DSA:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F168 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ed2b39c65f34c7e3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA1_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F169 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:25768522cfbca5e8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA1_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F170 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f993c2b06fb987d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_negative.py` (32 findings)

#### F171 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f19765e574c2a4af#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[HASH_ML_DSA]`
- **Message:** Failed: HASH_ML_DSA C_SignInit with missing required params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** wolfpkcs11 returns CKR_OK for C_SignInit(CKM_HASH_ML_DSA) with NULL pParameter where the registry requires a CK_SIGN_ADDITIONAL_DATA_PARAMS (test_mech_negative.py:809-814 calls classify_negative_rv expecting CKR_MECHANISM_PARAM_INVALID). A signature operation can be initiated without the required mechanism parameter, so signatures may be made under an unspecified/missing parameter set. Type A crypto-correctness validation gap on an advertised sign mechanism.

#### F172 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:25adb0e88267139f#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_verify_missing_required_param[HASH_ML_DSA]`
- **Message:** Failed: HASH_ML_DSA C_VerifyInit with missing required params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** wolfpkcs11 returns CKR_OK for C_VerifyInit(CKM_HASH_ML_DSA) with NULL pParameter (test_mech_negative.py:855-861). Same validation gap as the SignInit sibling: verify can be initiated without the required CK_SIGN_ADDITIONAL_DATA_PARAMS. Type A crypto-correctness gap on the advertised verify path.

#### F173 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:64f7860f29268ed6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F174 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9d84e19f3a2123dc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F175 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:acd07865945ff003#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F176 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5f2b76cbb455bc6f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA1_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F177 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e32424790a7fa5e9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F178 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:14d4a71525db78e4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F179 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a9df47dd92051310#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F180 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:04f567caca8bb1b2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F181 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc4cad3da90ab1de#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_malformed_required_param[AES_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F182 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:33977bcb969ba750#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F183 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19fe2e9cbf53998a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_malformed_required_param[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F184 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b17c1f7d910f6601#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_verify_missing_required_param[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F185 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f7946cf3940aa785#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F186 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:999353380eb38593#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F187 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b53c06a1a08bee5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F188 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1640d2c28bc31359#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F189 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1deeb566d8e93013#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F190 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:53a2d884eb950371#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F191 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a0210408e9c4bbbb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F192 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3e714a735100c810#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F193 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc82356be36a8506#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F194 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e35c65f7cfeb9901#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F195 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:898f0b6a3797bcc1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F196 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:549fd6ca2485c37b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F197 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:879de3217eea3e34#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F198 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0b63f051466c4b46#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F199 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:510500dd764ae55c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F200 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:953d6970eb909520#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F201 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:429c64721ef3ccbb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F202 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:534b35d841cf0758#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_sign.py` (7 findings)

#### F203 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aca274b137dac6b8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA256]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Reject-valid: test_mech_sign::test_kat_vector[ECDSA_SHA256] + 2 siblings return CKR_FUNCTION_FAILED on advertised ECDSA sign. ECDSA partially operational — known KAT vectors rejected (W7 family).

#### F204 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:545c5e30143593ce`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F205 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f4419372d22ab653`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC:key-import: advertised but not operational (secret key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F206 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d57b60f17ea9f8f6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC:key-import: advertised but not operational (secret key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F207 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d1eb71ebe34be497`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC:key-import: advertised but not operational (secret key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F208 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e0b7ec61d88d7643`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC:key-import: advertised but not operational (secret key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F209 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b9e7375e29fac4d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC:key-import: advertised but not operational (secret key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_sign_recover.py` (2 findings)

#### F210 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c42041bdbc116750#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign_recover.py::TestSignRecover::test_rsa_x509_verify_recover_invalid_sig`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** test_mech_sign_recover::test_rsa_x509_verify_recover_invalid_sig — sign_recover_single on CKM_RSA_X_509 returns CKR_MECHANISM_INVALID. CKM_RSA_X_509 sign-recover path not operational despite being advertised.

#### F211 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:212873e4159e94a6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign_recover.py::TestSignRecover::test_rsa_x509_sign_recover_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_RSA_X_509:sign-recover: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_state.py` (1 findings)

#### F212 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:15821cf43936c995#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_state.py::TestZeroDataFinal::test_encrypt_final_no_update`
- **Message:** AssertionError: C_EncryptFinal with no Update returned 0x00000070; expected one of ['0x0', '0x21', '0x91', '0x63'] — generic or unexpected codes can mask zero-input memory-corruption bugs
assert <CKR_MECHANISM_INVALID: 0x00000070> in (<CKR_OK: 0x00000000>, 33, <CKR_OPERATION_NOT_INITIALIZED: 0x00000
- **Evidence:** Wrong CKR: test_mech_state::test_encrypt_final_no_update — C_EncryptFinal with no Update returned CKR_MECHANISM_INVALID (0x70), expected CKR_OK / CKR_OPERATION_NOT_INITIALIZED. Generic wrong-code can mask memory-corruption bugs.

### `test_mech_wrap.py` (3 findings)

#### F213 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:06b6aed3c0ecc0fe#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[AES_KEY_WRAP_PAD]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_mech_wrap::test_wrap_unwrap_aes_key[AES_KEY_WRAP_PAD] failed with CKR_OPERATION_ACTIVE.

#### F214 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:302387b26aa6f9b3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP:wrap: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F215 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a75b7f1e99018153`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[RSA_X_509]`
- **Message:** _pytest.outcomes.XFailed: RSA_X_509:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_message_crypto.py` (1 findings)

#### F216 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d29039273d484f8d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single`
- **Message:** _pytest.outcomes.XFailed: advertised message encrypt rejected (CKM_AES_CBC): CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: advertised message encrypt rejected (CKM_AES_CBC): CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_metamorphic.py` (1 findings)

#### F217 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8850d75e4302c7b1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_metamorphic.py::TestRoundTripInvariants::test_wrap_unwrap_preserves_material`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: test_metamorphic::test_wrap_unwrap_preserves_material failed with CKR_OPERATION_ACTIVE on CKM_AES_KEY_WRAP.

### `test_multipart_streaming.py` (3 findings)

#### F218 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:362357c39e324936#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartEncrypt::test_aes_ecb_crossverify_large[16]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB advertised but AES setup key import is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: AES_ECB advertised but AES setup key import is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F219 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:497568fb16cd8fa1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartDigest::test_sha256_large_data_crossverify[0]`
- **Message:** _pytest.outcomes.XFailed: SHA256 advertised but digest is not operational: CKR_ARGUMENTS_BAD
- **Evidence:** Capability gap: SHA256 advertised but digest is not operational: CKR_ARGUMENTS_BAD. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F220 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:824b8d954e83ea13#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartSign::test_hmac_large_data_crossverify`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but setup key import is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: SHA256_HMAC advertised but setup key import is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_operation_termination.py` (10 findings)

#### F221 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a23cfa29339a3949#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_digest_terminates_after_each_call`
- **Message:** Failed: SHA256: C_Digest(empty) returned CKR_ARGUMENTS_BAD but left the digest operation active (next C_DigestInit -> CKR_OPERATION_ACTIVE) -- the spec requires C_Digest to always terminate the active digest operation: success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: PKCS#11 spec 'C_Digest always terminates the active digest operation unless CKR_BUFFER_TOO_SMALL'. WolfPKCS11: C_Digest(empty) returned CKR_ARGUMENTS_BAD AND left the digest operation active (next C_DigestInit -> CKR_OPERATION_ACTIVE). Spec violation per classify_lifecycle_effect = self-contradiction.

#### F222 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e070daa9dae0b596#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-input]`
- **Message:** Failed: C_Encrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_Encrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active.

#### F223 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ffaaddd0ac3aa9f5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length]`
- **Message:** Failed: C_Encrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_Encrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active.

#### F224 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f9e1b3bb507d76c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-input]`
- **Message:** Failed: C_EncryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_EncryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active.

#### F225 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c6ae4ea50821eddc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-length]`
- **Message:** Failed: C_EncryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_EncryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active.

#### F226 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1c0bfbf46c90e6d8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-input]`
- **Message:** Failed: C_Decrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_Decrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active.

#### F227 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8ae9a04c6a0c081a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-length]`
- **Message:** Failed: C_Decrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_Decrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active.

#### F228 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5991e0811a2914fe#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-input]`
- **Message:** Failed: C_DecryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_DecryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active.

#### F229 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2e9652a090ebdd76#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-length]`
- **Message:** Failed: C_DecryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** Type C lifecycle: C_DecryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active.

#### F230 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3f7583e3221a873f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_final_terminates_after_rejected_signature`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** test_c_verify_final_terminates_after_rejected_signature setup failure: C_VerifyUpdate returned CKR_MECHANISM_INVALID for an RSA multipart verify that was Init'd OK. WolfPKCS11 accepts the Init but rejects Update for multipart verify — inconsistent (advertised but partially-implemented) verify path.

### `test_protocol_edge_cases.py` (1 findings)

#### F231 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9a8d9d0cd1e6e44c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_protocol_edge_cases.py::TestResourceExhaustion::test_generate_random_large`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** C_GenerateRandom failure: test_protocol_edge_cases::test_generate_random_large returns CKR_FUNCTION_FAILED on large random request.

### `test_resource.py` (1 findings)

#### F232 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6df4b75ac9ace761#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_resource.py::TestBulkOperations::test_100_keys_coexist`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_FAILED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_FAILED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ro_session_restrictions.py` (1 findings)

#### F233 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6d18572384404aeb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session_restrictions.py::TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_OPERATION_ACTIVE; expected one of: CKR_OK
- **Evidence:** Type C lifecycle: C_UnwrapKey leaves op active; subsequent op init returns CKR_OPERATION_ACTIVE. OPERATION_ACTIVE epidemic cohort.

### `test_rsa_key_wrapping.py` (1 findings)

#### F234 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2a182edcaf596b0b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_key_wrapping.py::TestRSAOAEPWrap::test_wrap_unwrap_oaep`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Mech reject-valid: test_rsa_key_wrapping::test_wrap_unwrap_oaep — C_WrapKey with OAEP returns CKR_MECHANISM_INVALID on a key where RSA-OAEP is advertised.

### `test_rsa_oaep.py` (1 findings)

#### F235 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:529479720199be17#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_oaep.py::TestRSAOAEPRoundtrip::test_oaep_empty_plaintext`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** W1 sibling: test_oaep_empty_plaintext rejected with CKR_FUNCTION_FAILED on empty-message OAEP. WolfPKCS11 fails on msglen=0 OAEP (also in wycheproof_rsa_oaep cohort). Reject-valid on empty plaintext.

### `test_search.py` (1 findings)

#### F236 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b240eb80ab08f85c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_search.py::TestObjectSearch::test_find_many_objects`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for bulk object search is not operational: CKR_FUNCTION_FAILED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for bulk object search is not operational: CKR_FUNCTION_FAILED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_session_state_machine.py` (1 findings)

#### F237 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:257f63e235b2b81c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_state_machine.py::TestConcurrentSessionLogin::test_login_in_one_session_visible_in_another`
- **Message:** AssertionError: Session B cannot see private object - login not shared
assert 0 >= 1
 +  where 0 = len([])
- **Evidence:** Type C: test_session_state_machine::test_login_in_one_session_visible_in_another — login in session A NOT visible in session B. PKCS#11 v3.1 Sec.5.5: login state is token-wide. WolfPKCS11 treats login per-session.

### `test_set_attribute.py` (2 findings)

#### F238 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f80b3106dc53e75#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeNegative::test_cannot_change_class`
- **Message:** Failed: write read-only CKA_CLASS (PKCS#11 Base v3.0 Table 15): claimed success and the read-only value actually changed
- **Evidence:** W13 Type B: test_set_attribute::test_cannot_change_class — C_SetAttributeValue(CKA_CLASS) returned CKR_OK AND the CKA_CLASS value actually changed. PKCS#11 Base v3.0 Table 15: CKA_CLASS is read-only. Self-contradiction.

#### F239 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1ab4bc019419d365#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeAtomicity::test_set_attribute_mixed_template_is_atomic`
- **Message:** Failed: C_SetAttributeValue partially applied CKA_LABEL before rejecting a later read-only CKA_CLASS row
- **Evidence:** Type B atomicity: test_set_attribute::test_set_attribute_mixed_template_is_atomic — C_SetAttributeValue PARTIALLY applied CKA_LABEL before rejecting a later read-only CKA_CLASS row. PKCS#11 v3.1 Sec.5.7.6: C_SetAttributeValue must be atomic.

### `test_sign_recover.py` (1 findings)

#### F240 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f31d2b214e2806aa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_sign_recover.py::TestSignRecoverRecipes::test_sign_recover_single_returns_signature`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** Mechanism not operational: test_sign_recover::test_sign_recover_single_returns_signature + 2 siblings return CKR_MECHANISM_INVALID / CKR_FUNCTION_FAILED on CKM_RSA_X_509 sign-recover.

### `test_tls12.py` (2 findings)

#### F241 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8ea94ed9832c8d3e`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_tls12.py::TestTLS12KeyAndMacDerive::test_key_and_mac_rejects_template_protection_conflict`
- **Message:** Failed: CKM_TLS12_KEY_AND_MAC_DERIVE template protection conflict: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F242 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ef5c0eb8ea20f313#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_tls12.py::TestTLS12MasterKeyDerive::test_master_key_derive`
- **Message:** _pytest.outcomes.XFailed: CKM_TLS12_MASTER_KEY_DERIVE not operational: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_TLS12_MASTER_KEY_DERIVE not operational: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_v30_session.py` (1 findings)

#### F243 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8639f9ce8afbf8cd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_v30_session.py::TestSessionCancel::test_cancel_with_no_active_operation`
- **Message:** _pytest.outcomes.XFailed: Module exposes v3.0 interface but C_SessionCancel returns CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: Module exposes v3.0 interface but C_SessionCancel returns CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_verify_signature.py` (1 findings)

#### F244 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:217d5a6749fd7342#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_verify_signature.py::TestVerifySignatureRoundtrip::test_verify_signature_wrong_key`
- **Message:** _pytest.outcomes.XFailed: C_VerifySignatureInit rejected the mismatched key with a non-clean CKR: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** wolfpkcs11 C_VerifySignatureInit rejects mismatched key with CKR_FUNCTION_NOT_SUPPORTED instead of spec-preferred CKR_KEY_TYPE_INCONSISTENT. WRONG_OUTPUT direction is misleading — wrong CKR, not wrong output.

### `test_wycheproof.py` (14 findings)

#### F245 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:1b28b74f983d6400#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc25-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc25 decrypted successfully
- **Evidence:** wolfpkcs11 DECRYPTED an invalid AES-CBC-PKCS5 ciphertext (tc25) that wycheproof flags invalid — true ACCEPT_INVALID direction (classifier mislabeled as OTHER). Module accepting invalid AES-CBC ciphertexts enables a Vaudenay padding oracle (active attack → CBC plaintext recovery). HIGH per §9.5 (accept-invalid on CBC-PAD).

#### F246 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a16073bdaceb36c7#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc97-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc97 decrypted successfully
- **Evidence:** wolfpkcs11 DECRYPTED an invalid AES-CBC-PKCS5 ciphertext (tc97) that wycheproof flags invalid — ACCEPT_INVALID direction (mislabeled OTHER). Vaudenay padding oracle enabler. HIGH per §9.5.

#### F247 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:6224114eb10ce058#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc169-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc169 decrypted successfully
- **Evidence:** wolfpkcs11 DECRYPTED an invalid AES-CBC-PKCS5 ciphertext (tc169) that wycheproof flags invalid — ACCEPT_INVALID direction (mislabeled OTHER). Vaudenay padding oracle enabler. HIGH per §9.5.

#### F248 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:52914bea6b1ef654#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc109-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc109: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for an invalid ECDSA P-256/SHA-256 sig (tc109, 2 tests). Correct direction, wrong CKR. MEDIUM.

#### F249 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6a29c6d1ec55b0c9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc169-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc169: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-256/SHA-256 sig (tc169, 2 tests). Correct direction, wrong CKR. MEDIUM.

#### F250 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e7958d42225e885f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc172-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc172: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-256/SHA-256 sig (tc172, 2 tests). Correct direction, wrong CKR. MEDIUM.

#### F251 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b6fa7026c4de0988#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc173-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc173: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-256/SHA-256 sig (tc173, 2 tests). Correct direction, wrong CKR. MEDIUM.

#### F252 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c95fb3c84c2590e4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc174-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc174: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-256/SHA-256 sig (tc174, 2 tests). Correct direction, wrong CKR. MEDIUM.

#### F253 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:960a717160acec42#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc383-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc383: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-384/SHA-384 sig (tc383, 1 test). Correct direction, wrong CKR. MEDIUM.

#### F254 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:271ecbfe3ec13416#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc393-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc393: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA P-384/SHA-384 sig (tc393, 1 test). Correct direction, wrong CKR. MEDIUM.

#### F255 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b56b49aa42597eb3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestRSASigWycheproof::test_rsa_sig_2048_sha256[tc21-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc21: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid RSA-2048/SHA-256 sig (tc21, 1 test). Correct direction, wrong CKR. MEDIUM.

#### F256 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b68db0088c3e37a1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestRSASigWycheproof::test_rsa_sig_2048_sha256[tc240-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc240: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid RSA-2048/SHA-256 sig (tc240, 1 test). Correct direction, wrong CKR. MEDIUM.

#### F257 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0418ec0ce9734505#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestRSASigWycheproof::test_rsa_sig_2048_sha256[tc241-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc241: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid RSA-2048/SHA-256 sig (tc241, 1 test). Correct direction, wrong CKR. MEDIUM.

#### F258 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bf044aa7c3b51c7c#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc433-valid]`
- **Message:** Failed: Valid ECDSA sig tc433 rejected by module
- **Evidence:** wolfpkcs11 rejects a valid ECDSA P-256/SHA-256 signature (tc433). Reject-valid functional bug, LOW.

### `test_wycheproof_ecdh.py` (1 findings)

#### F259 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:47def68698d89a4f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3298
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py::test_ecdh[ecdh_brainpoolP224r1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:EC-private-import: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_ecdsa.py` (9 findings)

#### F260 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:373b43f690e71469#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 392
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp224r1_sha224_test.json:tc109-invalid]`
- **Message:** _pytest.outcomes.XFailed: ecdsa_secp224r1_sha224_test.json:tc109-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID when verifying invalid ECDSA sigs (secp224r1/SHA-224, 392 cases). Correct direction (rejects), wrong/imprecise CKR. No oracle, no security impact.

#### F261 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d8f5638d9d72360a#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 334
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp384r1_sha256_test.json:tc108-invalid]`
- **Message:** _pytest.outcomes.XFailed: ecdsa_secp384r1_sha256_test.json:tc108-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA sigs (secp384r1/SHA-256, 334 cases). Correct direction, wrong CKR. MEDIUM.

#### F262 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76b53baa53c87d91#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 282
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp256r1_sha512_test.json:tc109-invalid]`
- **Message:** _pytest.outcomes.XFailed: ecdsa_secp256r1_sha512_test.json:tc109-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA sigs (secp256r1/SHA-512, 282 cases). Correct direction, wrong CKR. MEDIUM.

#### F263 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:45c3ffc27243b7cf#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 178
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp521r1_sha512_test.json:tc107-invalid]`
- **Message:** _pytest.outcomes.XFailed: ecdsa_secp521r1_sha512_test.json:tc107-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid ECDSA sigs (secp521r1/SHA-512, 178 cases). Correct direction, wrong CKR. MEDIUM.

#### F264 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:934520cf6957cefb`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6023
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_brainpoolP224r1_sha224_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (brainpoolp224r1: CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F265 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2c8dd9c5c91ed98a#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp224r1_sha256_test.json:tc423-valid]`
- **Message:** Failed: Valid ECDSA sig ecdsa_secp224r1_sha256_test.json:tc423-valid rejected by module
- **Evidence:** wolfpkcs11 rejects valid ECDSA signatures on secp224r1/SHA-256 (6 wycheproof 'valid' cases). Reject-valid functional bug: false negatives, clean CKR, no security impact.

#### F266 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:de027663b1301bdb#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp256r1_sha256_p1363_test.json:tc210-valid]`
- **Message:** Failed: Valid ECDSA sig ecdsa_secp256r1_sha256_p1363_test.json:tc210-valid rejected by module
- **Evidence:** wolfpkcs11 rejects valid ECDSA signatures (secp256r1/SHA-256 P1363 encoding, 3 cases). Reject-valid functional bug, LOW.

#### F267 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8cf4e14d510b4064#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp384r1_sha512_test.json:tc496-valid]`
- **Message:** Failed: Valid ECDSA sig ecdsa_secp384r1_sha3_384_test.json:tc468-valid rejected by module
- **Evidence:** wolfpkcs11 rejects valid ECDSA signatures (secp384r1/SHA3-384, 3 cases). Reject-valid functional bug, LOW.

#### F268 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:57e4bed5750a300c#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp521r1_sha512_test.json:tc501-valid]`
- **Message:** Failed: Valid ECDSA sig ecdsa_secp521r1_sha3_512_test.json:tc503-valid rejected by module
- **Evidence:** wolfpkcs11 rejects valid ECDSA signatures (secp521r1/SHA3-512, 2 cases). Reject-valid functional bug, LOW.

### `test_wycheproof_mldsa.py` (7 findings)

#### F269 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:602eef75a0bdccce#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_44_verify_test.json:tc64-invalid]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED for all ML-DSA verify attempts (12 cases): cannot process ML-DSA at all. Capability gap — ML-DSA mechanism advertised but not operational. MEDIUM.

#### F270 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:05d0a92979ac2b06#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 17
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_44_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_44_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** wolfpkcs11 returns CKR_MECHANISM_PARAM_INVALID instead of CKR_SIGNATURE_INVALID for invalid ML-DSA-44 sigs (17 cases). Correct direction, wrong CKR. MEDIUM.

#### F271 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d38212f251c0a9fa#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 18
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_65_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_65_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** wolfpkcs11 returns CKR_MECHANISM_PARAM_INVALID instead of CKR_SIGNATURE_INVALID for invalid ML-DSA-65 sigs (18 cases). Correct direction, wrong CKR. MEDIUM.

#### F272 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:585c17f362163e1f#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 18
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_87_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_87_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** wolfpkcs11 returns CKR_MECHANISM_PARAM_INVALID instead of CKR_SIGNATURE_INVALID for invalid ML-DSA-87 sigs (18 cases). Correct direction, wrong CKR. MEDIUM.

#### F273 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5f328fd726abecb6#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_44_verify_test.json:tc147-valid]`
- **Message:** Failed: Valid ML-DSA sig mldsa_44_verify_test.json:tc147-valid rejected by module
- **Evidence:** wolfpkcs11 rejects a valid ML-DSA-44 signature (tc147). Reject-valid functional bug, LOW.

#### F274 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1d83af5deffb10c7#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_65_verify_test.json:tc161-valid]`
- **Message:** Failed: Valid ML-DSA sig mldsa_65_verify_test.json:tc161-valid rejected by module
- **Evidence:** wolfpkcs11 rejects a valid ML-DSA-65 signature (tc161). Reject-valid functional bug, LOW.

#### F275 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ffffef96d9a3b56c#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_87_verify_test.json:tc174-valid]`
- **Message:** Failed: Valid ML-DSA sig mldsa_87_verify_test.json:tc174-valid rejected by module
- **Evidence:** wolfpkcs11 rejects a valid ML-DSA-87 signature (tc174). Reject-valid functional bug, LOW.

### `test_wycheproof_mldsa_sign.py` (3 findings)

#### F276 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dc4d394fbd1c4893#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py::test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc50-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_44_sign_noseed_test.json:tc50-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_44_sign_noseed_test.json:tc50-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DAT. Direction = reject-valid → functional gap (LOW).

#### F277 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e8cc751ed9c61b25#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py::test_mldsa_sign[mldsa_65_sign_noseed_test.json:tc54-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_65_sign_noseed_test.json:tc54-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_65_sign_noseed_test.json:tc54-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DAT. Direction = reject-valid → functional gap (LOW).

#### F278 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eac9ba041eed78c5#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py::test_mldsa_sign[mldsa_87_sign_noseed_test.json:tc45-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_87_sign_noseed_test.json:tc45-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_87_sign_noseed_test.json:tc45-invalid: InvalidPrivateKey import reject: rejected with CKR_FUNCTION_FAILED, expected ['CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DAT. Direction = reject-valid → functional gap (LOW).

### `test_wycheproof_rsa.py` (3 findings)

#### F279 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6230b7d5d6817eb9#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 949
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py::test_rsa_wycheproof[rsa_signature_2048_sha224_test.json:tc21-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_signature_2048_sha224_test.json:tc21-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 returns CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID for invalid RSA signatures (2048/SHA-224, 949 cases). Correct direction, wrong CKR. MEDIUM.

#### F280 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc4d3169a82c5e83#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `failure` · **Tests covered:** 21
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py::test_rsa_wycheproof[rsa_signature_8192_sha256_test.json:tc1-valid]`
- **Message:** Failed: Valid RSA sig rsa_signature_8192_sha256_test.json:tc1-valid rejected: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** wolfpkcs11 cannot verify valid RSA-8192 signatures: returns CKR_FUNCTION_FAILED for 21 wycheproof 'valid' cases. Reject-valid functional bug, likely resource/size limit. LOW.

#### F281 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4f051326c819313#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py::test_rsa_wycheproof[rsa_signature_8192_sha256_test.json:tc8-acceptable]`
- **Message:** _pytest.outcomes.XFailed: rsa_signature_8192_sha256_test.json:tc8-acceptable: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** wolfpkcs11 rejects wycheproof 'acceptable' (edge-case-valid) RSA-8192 sigs with CKR_FUNCTION_FAILED (3 cases). Reject-valid of edge cases, consistent with the RSA-8192 verify limitation. LOW.

### `test_wycheproof_rsa_decrypt.py` (1 findings)

#### F282 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a4c92ca1f0098e2f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py::test_rsa_pkcs1_decrypt[rsa_pkcs1_2048_test.json:tc1-valid]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK
- **Evidence:** Sibling of W1: wolfpkcs11-master rejects valid RSA-PKCS1 wycheproof decrypt vectors (tc1/tc2/tc3-valid) with CKR_ENCRYPTED_DATA_INVALID. RSA private key imported OK; C_Decrypt rejects. Pure reject-valid on PKCS#1 v1.5 decrypt — same operational-but-edge-rejecting class as OAEP W1.

### `test_wycheproof_rsa_oaep.py` (1 findings)

#### F283 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8dc8f31b553c3d56`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 13
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha512_224_mgf1sha1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA-OAEP SHA-512/224/SHA-1 advertised but not operational (canonical OAEP SHA-512/224/SHA-1 decrypt rejected: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK); vector: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_pss.py` (2 findings)

#### F284 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f7c3968f3f0f0e31#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 36
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_4096_sha256_mgf1_32_test.json:tc99-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_4096_sha256_mgf1_32_test.json:tc100-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** RSA padding hash-variant gap: rsa_pss_4096_sha256_mgf1_32_test.json:tc100-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED. Module only supports subset of RFC 8017 hash/MGF combinations.

#### F285 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8e47f1a3197a663f#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_3072_sha256_mgf1_32_params_test.json:tc99-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_3072_sha256_mgf1_32_params_test.json:tc100-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** RSA padding hash-variant gap: rsa_pss_3072_sha256_mgf1_32_params_test.json:tc100-invalid: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED. Module only supports subset of RFC 8017 hash/MGF combinations.

### `test_wycheproof_x25519.py` (1 findings)

#### F286 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:869a0bec2ca663a7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1017
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py::test_xdh[x25519_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:Montgomery-private-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_core_ops.py` (1 findings)

#### F287 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e3ab7e4983e1f886`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/x509/test_core_ops.py::TestV30CertAttributes::test_v30_cert_attr_accepted[PUBLIC_KEY_INFO]`
- **Message:** _pytest.outcomes.XFailed: v3.0+ module SHOULD accept CKA_PUBLIC_KEY_INFO but cleanly rejected it: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).


## Already documented in `docs/module-issues.md` (111 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (116 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 288 | CLEAN_ERROR | `test_acvp_rsa.py` | `sha1:6f88421ff6d55e81` |
| 54 | REJECT_VALID | `test_wycheproof_rsa_pss.py` | `sha1:fa5e902f4c593828` |
| 35 | CLEAN_ERROR | `test_acvp_mldsa.py` | `sha1:ffdc81d9752a7f32` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:48c52ac7356a5bb3` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:583ec6d7fa9cd10e` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:ecb0355744e32b45` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:d57751eaa9d3713b` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:888d6c4118d5d37a` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:e0df4fd6f1e4e4d8` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:edc0ac573ef4cc5e` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:249ae6e0d88876f0` |
| 16 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:44e86d8546b316db` |
| 12 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:57a3be1028e8f496` |
| 8 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:3b7d16587b88d8c5` |
| 6 | CLEAN_ERROR | `test_ckr_encrypt.py` | `sha1:92f07779c5451e86` |

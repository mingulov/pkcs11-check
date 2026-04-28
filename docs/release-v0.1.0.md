# Release v0.1.0 — Baseline Test Results

**Date:** 2026-04-09
**pkcs11-check commit:** `d6dff62` (dev branch)
**Test runner:** pytest 8.x with per-file subprocess isolation

---

## Provider Versions

All "main" builds use `--depth 1` shallow clones at Docker build time (unpinned HEAD).
Stable builds use the pinned tag or Fedora 44 system packages.

| Artifact | Provider | Source | Branch / Tag | Build Notes |
|----------|----------|--------|-------------|-------------|
| `softhsm2-main` | SoftHSM2 | github.com/softhsm/SoftHSMv2 | `main` (HEAD) | OpenSSL 3.6.1 from source; `--enable-mldsa` |
| `kryoptic-main` | Kryoptic | github.com/latchset/kryoptic | `main` (HEAD) | Rust, `--features pqc`; OpenSSL 4.0.0-beta1 |
| `nss-main` | NSS | hg.mozilla.org/projects/nss | `tip` (HEAD) | Mercurial; gyp+ninja; full PQC (ML-KEM) |
| `opencryptoki-master` | OpenCryptoki | github.com/opencryptoki/opencryptoki | `master` (HEAD) | OpenSSL 3.6.1 from source; SWToken only |
| `bouncyhsm` | BouncyHSM | github.com/harrison314/BouncyHsm | `v2.0.1` (tag) | .NET 10.0 SDK; 2 local patches applied |
| `tpm2` | tpm2-pkcs11 | Fedora 44 RPM | `1.9.1-7.fc44` | swtpm + tpm2-abrmd resource manager |

### Stable / release builds (not in artifacts, used for reference)

| Docker Target | Provider | Version |
|--------------|----------|---------|
| `test-softhsm2` | SoftHSM2 | tag `2.7.0` |
| `test-kryoptic` | Kryoptic | tag `v1.5.0`, `--features pqc` |
| `test-nss` | NSS | Fedora 44 RPM (nss-softokn) |
| `test-nss-pqc` | NSS | hg tip (configurable via `NSS_TAG`) |
| `test-opencryptoki` | OpenCryptoki | Fedora 44 RPM (`opencryptoki-3.26`) |
| `test-kryoptic-fips` | Kryoptic | `main`, `--features "fips,pqc"` |
| `test-pkcs11-mock` | pkcs11-mock | github.com/nicosResworworworworworg/pkcs11-mock, `main` |
| `test-qryptotoken` | qryptotoken | github.com/nicosResearch/qryptotoken, `main` |

---

## Test Results Summary

| Module | Passed | Failed | Skipped | Xfailed | Crashed | Total |
|--------|-------:|-------:|--------:|--------:|--------:|------:|
| OpenCryptoki (master) | 75,265 | 2,405 | 8,512 | 54 | 6 | 86,242 |
| BouncyHSM (v2.0.1) | 66,307 | 22,282 | 8,694 | 59 | 3 | 97,345 |
| Kryoptic (main) | 65,674 | 2,831 | 32,218 | 68 | 0 | 100,791 |
| SoftHSM2 (main) | 60,820 | 2,697 | 16,943 | 41 | 0 | 80,501 |
| NSS (main) | 46,185 | 2,018 | 34,454 | 105 | 1 | 82,763 |
| tpm2-pkcs11 (1.9.1) | 8,202 | 5,028 | 47,977 | 2 | 0 | 62,242 |
| **Total** | **322,453** | **37,261** | **148,798** | **329** | **10** | **509,884** |

---

## Tests by Category

Using SoftHSM2 (main) as reference — totals vary per module based on mechanism availability.

| Category | Tests | % | Source |
|----------|------:|--:|--------|
| Wycheproof | 63,310 | 78.6% | Google C2SP test vectors |
| ACVP | 11,456 | 14.2% | NIST algorithm validation vectors |
| Functional | 3,618 | 4.5% | Session, key, crypto, attribute, interop tests |
| X.509 / CRL | 1,674 | 2.1% | Certificate and CRL handling |
| Security | 268 | 0.3% | Tookan, CVE regression, padding oracle, FFI safety |
| CKR Compliance | 175 | 0.2% | PKCS#11 error code spec compliance |
| **Total** | **80,501** | 100% | |

### Test file and function counts

- **Test files:** 237 (in `src/pkcs11_check/testcases/`)
- **Test functions:** 2,335 (`def test_*` definitions)
- **Meta-tests:** 33 files, 574 functions (in `tests/`, testing the framework itself)

### Tests by category per module

| Category | SoftHSM2 | Kryoptic | NSS | OpenCryptoki | BouncyHSM | tpm2 |
|----------|-------:|-------:|-------:|-------:|-------:|-------:|
| Wycheproof | 63,310 | 63,251 | 65,076 | 60,898 | 62,018 | 43,358 |
| ACVP | 11,456 | 31,060 | 11,457 | 19,068 | 28,417 | 13,600 |
| Functional | 3,618 | 4,363 | 4,112 | 4,153 | 4,793 | 3,167 |
| X.509/CRL | 1,674 | 1,674 | 1,674 | 1,674 | 1,674 | 1,674 |
| Security | 268 | 268 | 268 | 268 | 265 | 268 |
| CKR | 175 | 175 | 175 | 175 | 175 | 175 |

---

## Coverage Metrics

| Metric | Value |
|--------|-------|
| PKCS#11 functions tested | 64 / 104 (61%) |
| Mechanisms exercised | 107 / 140 advertised (76%) |
| PKCS#11 versions tested | v2.40, v3.0, v3.2 |
| CKR conditions checked | 802 |
| CVE regression tests | 29 known CVEs |

---

## Issues Found by Module

### SoftHSM2 (main)

| Severity | Finding |
|----------|---------|
| HIGH | ECDSA_SHA* accepts 17/17 invalid ACVP SigVer vectors |
| HIGH | EdDSA accepts 8/8 invalid ACVP SigVer vectors |
| MEDIUM | RSA-OAEP hardcoded to SHA-1 only (RFC 8017 allows SHA-224/256/384/512) |
| MEDIUM | RSA-PSS rejects distinct hash/MGF algorithms (RFC 8017 allows) |
| LOW | DES_CBC_PAD/DES3_CBC_PAD wrap advertised but CKR_MECHANISM_INVALID |
| LOW | Session objects visible across concurrent sessions |

### Kryoptic (main)

| Severity | Finding |
|----------|---------|
| HIGH | C_Verify returns CKR_DEVICE_ERROR (0x30) instead of CKR_SIGNATURE_INVALID (0xC0) for ALL mechanisms |
| HIGH | EdDSA accepts 4/4 invalid ACVP SigVer vectors |
| HIGH | SLH-DSA accepts 15/15 invalid ACVP SigVer vectors |
| HIGH | C_SessionCancel crash (SIGSEGV) via v3.0+ function list |
| MEDIUM | v3.0+ cert attributes (CKA_PUBLIC_KEY_INFO, CKA_SKID, CKA_AKID) rejected |
| MEDIUM | ML-DSA seed-based key derivation not implemented (173+ Wycheproof vectors) |
| LOW | AES-CTS advertised but returns CKR_DEVICE_ERROR |

### NSS (main)

| Severity | Finding |
|----------|---------|
| **CRITICAL** | CKA_VALUE readable on CKA_SENSITIVE=True keys — private key material exposed |
| **CRITICAL** | CKA_EXTRACTABLE escalation False->True via C_CopyObject (Tookan vulnerability) |
| HIGH | Wrap-decrypt oracle: key permits both CKA_WRAP and CKA_DECRYPT |
| HIGH | CKA_COPYABLE escalation False->True via C_CopyObject |
| HIGH | C_Digest with 1-byte buffer returns CKR_OK (potential buffer overflow) |
| MEDIUM | RSA-OAEP non-uniform error codes (Manger 2001 padding oracle) |
| MEDIUM | CKA_WRAP_WITH_TRUSTED not enforced |
| MEDIUM | EdDSA rejects CK_EDDSA_PARAMS (spec requires explicit params) |
| MEDIUM | 9 attribute default violations (CKA_PRIVATE, CKA_LOCAL, CKA_EXTRACTABLE) |
| MEDIUM | CKA_COPYABLE, CKA_DESTROYABLE attributes not enforced |
| LOW | DSA verify rejects all 296 valid Wycheproof signatures (imported key limitation) |
| LOW | ChaCha20-Poly1305: non-standard param struct (256 xfails) |
| LOW | HKDF: incorrect output values (232 xfails) |
| LOW | AES-KWP: non-conformant to RFC 5649 (77 xfails, 3 failure patterns) |
| LOW | IKE derive, SP800-108 feedback/pipeline: advertised but not operational |

### BouncyHSM (v2.0.1)

| Severity | Finding |
|----------|---------|
| HIGH | Segfault on C_GetAttributeValue after C_DestroyObject (native shim bug) |
| HIGH | Segfault on >1MB data in digest, encryption, BLAKE2b operations |

### OpenCryptoki (master)

| Severity | Finding |
|----------|---------|
| HIGH | pkcsslotd daemon dies under sustained test load |
| HIGH | SSL3 master key derive crash (SIGSEGV on CKM_SSL3_MASTER_KEY_DERIVE) |

### tpm2-pkcs11 (1.9.1)

| Severity | Finding |
|----------|---------|
| LOW | Only 26 mechanisms — hardware TPM limitation (by design) |

---

## Security Findings Summary

| Severity | Count | Affected Modules |
|----------|------:|-----------------|
| CRITICAL | 2 | NSS (sensitive key exposure, Tookan extractable escalation) |
| HIGH | 9 | NSS (3), Kryoptic (2), BouncyHSM (2), OpenCryptoki (2) |
| MEDIUM | 9 | NSS (5), Kryoptic (2), SoftHSM2 (2) |
| LOW | 8 | All modules |

---

## Artifact Layout

Each module produces artifacts at `artifacts/<module>/`:

| File | Content |
|------|---------|
| `results.json` | Per-unit pass/fail/skip/xfail counts and statuses |
| `state.json` | Fingerprint, report records index, unit results |
| `quality.json` | Mechanism coverage, skip analysis, data quality warnings |
| `report.jsonl` | Individual test records (pytest report format) |
| `console.log` | Combined stdout/stderr from the test run |
| `coverage.json` | PKCS#11 function/mechanism call coverage data |

---

## What's Not Covered (Future Work)

- Multi-part streaming API (C_EncryptUpdate/Final, C_SignUpdate/Final)
- v3.0 message-based API (C_EncryptMessage, C_SignMessage, etc.)
- PIN management functions (C_InitToken, C_InitPIN, C_SetPIN)
- Remaining 33 legacy/deprecated mechanisms (RC2, CDMF, MD2, MD5)
- HMAC _GENERAL truncated variants
- Authenticated unwrap (C_UnwrapKeyAuthenticated)

# artifacts_base deep analysis — 2026-06-13

**Status:** ANALYSIS-ONLY (no fixes). Severity-classified inventory of every fail/crash/
timeout in `artifacts_base/`, plus a planned validation round. Output feeds downstream
bug reports (provider bugs) and pkcs11-check improvements (test bugs).

**Source artifact set:** `artifacts_base/` — fresh pool run **today (2026-06-13)**, 21 provider
variants, sharded + pooled. Read-only.

**Soft-token threat model (per user):** All providers here are soft-tokens (softhsm2, kryptic,
NSS softoken, opencryptoki, bouncyhsm, tpm2, wolfpkcs11, corepkcs11). Private keys are not
stored securely; host already has full key access. **Severity for findings that require a
malicious host app is correspondingly lower** — the value of those findings is robustness,
spec-conformance, and protection against module-reuse scenarios (HSM-backing, proxy
deployments), not direct exfiltration.

**pkcs11-mock exclusion:** `pkcs11-mock` is a canned mock, not a real PKCS#11 implementation.
Its 267 fails are expected and are excluded from this analysis (per user).

**On the word "preliminary" in §5 (corrected):** `artifacts_base` IS the fresh post-rebuild
run (1 hour old at time of writing). Findings in §2/§3 are **observed and real**, not
preliminary-by-staleness (cf. the 2026-06-09 `--no-build` pool, which was stale). The §5
"validation round" is therefore reframed: it is **not** staleness re-verification. Its two
real purposes are (a) **root-cause each observed finding in provider source** for the bug
report, and (b) **extract a minimal isolated repro** (single-test docker run with `-k`
filter) so the downstream bug report is clean and self-contained.

---

## Methodology

1. **Inventory** — Extracted per-provider `{results,coverage,quality}.json` summaries;
   cross-checked against `report.jsonl` per-nodeid verdicts.
2. **Crash attribution** — `_status_from_returncode()` at `core/file_runner.py:2085` maps
   rc<0 → `crashed`. Stored rc is `max(abs(r.returncode))` → rc=11 SIGSEGV, rc=6 SIGABRT,
   rc=5 SIGTRAP, rc=1 SIGHUP/signal-1. File-level granularity.
3. **Per-target extraction** — Built `/tmp/p11analysis/per_target/<path>.txt` for each of
   the **156 unique failing test files** with first 8000 chars of FAILURES detail per provider.
4. **Cross-provider grouping** — Aggregated by test file → provider spread, isolating
   universal (likely harness/UB) vs unique-to-provider (likely real) failures.
5. **Existing-doc reconciliation** — Cross-referenced against `docs/module-issues.md`
   (2100-line known-issue catalog), `docs/findings/findings-summary-2026-06-10.md`,
   `docs/findings/issues-triage.md` (POOL-STALENESS WARNING 2026-06-09), and
   `docs/findings/failure-inventory.json`.

**Pool-staleness status:** artifacts_base was generated today against the latest code;
no `--no-build` concern this round (cf. the 2026-06-09 staleness warning). However,
**new findings** not yet documented in `module-issues.md` are flagged for validation in §5.

---

## 1. Executive summary

### 1.1 Headline counts (artifacts_base, today)

| provider | P | F | xf | skip | crash-files | status |
|---|---|---|---|---|---|---|
| bouncyhsm | 54328 | 2122 | 16436 | 42060 | 3 / 5 indiv | improved (ΔF −10, Δcrash −2) |
| **corepkcs11** | 11088 | **683** | 9818 | 88862 | 0 | **⚠ +541 REGRESSION** |
| kryptic | 58684 | 157 | 24579 | 30480 | 0 | mild uptick |
| kryptic-fips | 43993 | 189 | 23686 | 38422 | 6 / 14 indiv | NEW (FIPS-mode SIGABRTs) |
| kryptic-main | 58685 | 158 | 24579 | 30480 | 0 | NEW (≈kryptic) |
| **nss (all 4 variants)** | 36927–38384 | 130–141 | 2121–2199 | 71581–73202 | **3 / 9 each** | **⚠ NEW CRASHES** (+3 to +6) |
| opencryptoki | 64557 | 215 | 2861 | 46463 | 0 | flat |
| pkcs11-mock | 749 | 267 | 79 | 109398 | 0 | excluded (mock) |
| softhsm2 | 44957 | 70 | 6194 | 60854 | 0 | flat |
| tpm2 | 18134 | 49 | 25562 | 67337 | 0 | **ΔF −63** (big improvement) |
| wolfpkcs11 | 46628 | 876 | 15968 | 47959 | 11 / 18 indiv | flat crash, ΔF −3 |
| wolfpkcs11-master | 48685 | 468 | 14065 | 48349 | 2 / 4 indiv | improved |

**Duplicate provider pairs** (analysed once): corepkcs11≈corepkcs11-main, kryptic≈kryptic-main,
opencryptoki≈opencryptoki-master, nss≈nss-pqc, nss-main≈nss-pqc (slot0 variants are tiny smoke).

### 1.2 Three things changed since the 2026-06-10 pool (Δ-flags above)

1. **corepkcs11 +541 regression** — concentrated in `test_wycheproof.py` (+346) +
   `test_wycheproof_rsa_decrypt.py` (+201). Root cause: corepkcs11 returns
   **`CKR_HOST_MEMORY`** for invalid EC-point imports (test_wycheproof.py) and
   **`CKR_ATTRIBUTE_TYPE_INVALID`** for RSA-decrypt template attrs
   (test_wycheproof_rsa_decrypt.py). Likely real corepkcs11 bugs surfaced by recent test
   additions (poor CKR mapping for invalid EC points; missing attribute support).
2. **NSS SIGSEGV (3 files × 4 variants = 12 new file-level crashes)** — `test_mech_flags.py`,
   `test_mech_negative.py`, `test_operation_termination.py`. Crash = the finding.
3. **tpm2 −63 fail** — big improvement, mostly the vacuous-reject / SigVer reclassification
   landing correctly. Confirms earlier fixes are taking effect.

---

## 2. Severity classification — findings table

Classification follows AGENTS.md §"Test-outcome classification model" with the soft-token
threat-model adjustment. **CVE-impact column** = impact if this provider were backed by real
hardware or reachable through a proxy.

### CRITICAL — crypto (crypto-correctness) or policy (protection violated)

| # | Provider | Finding | Class | Soft-token sev | CVE-impact sev | Source |
|---|---|---|---|---|---|---|
| C1 | **bouncyhsm** | EdDSA signatures **fail cryptography verify** (`InvalidSignature` raised). PKCS#11-produced sig doesn't validate per RFC 8032. | A | HIGH | **CRITICAL** | `test_eddsa.py::test_sign_p11_verify_crypto` (bouncyhsm-unique) |
| C2 | **bouncyhsm** | `CKA_MODULUS` is **changeable** on RSA private key; `C_SetAttributeValue` returns `CKR_OK` AND modulus actually mutates. Read-only protection violated. | B | HIGH | **CRITICAL** | `test_set_attribute.py::test_cannot_change_modulus` |
| C3 | **bouncyhsm** | AES-GCM **IV reuse accepted** (`CKR_OK` when must reject) — nonce-reuse crypto break. | A | HIGH | **CRITICAL** | `test_parameter_validation.py` (rc=11 crash-file, visible pre-crash) |
| C4 | **bouncyhsm** | AES-GCM **4-byte IV accepted** (must reject; spec min 8 for GCM, 12 recommended). | A | MEDIUM | HIGH | `test_parameter_validation.py` |
| C5 | **wolfpkcs11 + bouncyhsm** | AES-CCM **no-auth** (accepts tag-less ciphertext) — previously documented Critical. | A | HIGH | **CRITICAL** | see `findings-summary-2026-06-10.md` |
| C6 | **bouncyhsm** | RSA PKCS#1 v1.5 **non-uniform errors** (Bleichenbacher oracle); RSA-OAEP **non-uniform errors** (Manger oracle); AES-CBC-PAD **Vaudenay oracle**. 3 distinct padding oracles. | A | HIGH (concrete oracle) | **CRITICAL** | `test_padding_oracle.py` (bouncyhsm-unique set) |
| C7 | **wolfpkcs11** | **Digest subsystem non-functional** — `C_Digest` returns garbage `CK_RV = 0xffffffffffffff7c` (=-132 i64, **out of CKR_* range**) for SHA-1/SHA-2; returns `CKR_ARGUMENTS_BAD` for SHA-3. ~250 failing tests (`test_digest` 0P/19F, `test_kat` 8F, `test_acvp_hash` 160F, `test_multipart_streaming` 6F, `test_buffers` digest subset). Mechanism advertised but operation broken. | spec/A | HIGH | **CRITICAL** | wolfpkcs11 (+master) |

### HIGH — crashes (segfault = the finding), lifecycle self-contradiction, major spec breaks

| # | Provider | Finding | Class | Soft-token sev | CVE-impact sev | Source |
|---|---|---|---|---|---|---|
| H1 | **nss (all variants)** | **SIGSEGV** on `test_mech_flags.py`, `test_mech_negative.py`, `test_operation_termination.py`. 12 file-level crashes across 4 variants = 21+ total. | crash | MEDIUM (host-local) | HIGH (remote-trigger if proxied) | 3 files × nss{,-main,-pqc,-main-slot0,…} |
| H2 | **wolfpkcs11** | 7 SIGSEGV files (`test_ckr_keygen`, `test_mech_multipart`, `test_padding_oracle`, `test_dh_key_agreement`, `test_mech_encrypt`, `test_encrypt`, `test_key_flags`). | crash | MEDIUM | HIGH | wolfpkcs11-unique + master |
| H3 | **wolfpkcs11** | SIGABRT `wycheproof_hkdf.py` (rc=6), SIGTRAP `x509/test_identity.py` (rc=5), SIGHUP `test_access_levels.py` + `test_metamorphic.py` (rc=1). | crash | MEDIUM | HIGH | 4 more files |
| H4 | **kryptic-fips** | 5 SIGABRT files in FIPS mode: `test_ccm`, `test_mech_derive`, `test_mech_encrypt`, `test_misc_kdf`, `wycheproof_aes` (all rc=6). FIPS-mode self-aborts. | crash | MEDIUM | HIGH (FIPS contexts) | kryptic-fips-only |
| H5 | **bouncyhsm** | SIGSEGV `test_parameter_validation.py` (rc=11, after visible IV-reuse failures). SIGSEGV `test_ckr_object.py` (rc=11, crash stdout lost on retry). | crash | MEDIUM | HIGH | bouncyhsm |
| H6 | **bouncyhsm** | `C_Decrypt`/`DecryptUpdate` with NULL ptr returns `CKR_ARGUMENTS_BAD` but **leaves operation active** → `CKR_OPERATION_ACTIVE` on next init. lifecycle: claims cleanup, doesn't honor. | C | MEDIUM | HIGH | `test_operation_termination.py` |
| H7 | **bouncyhsm + wolfpkcs11** | Wrong `pulSize` after `CKR_BUFFER_TOO_SMALL`: returns **8 not 32, 16 not 256**. Retry preserves wrong state (stuck `pulSize=1`). Spec: caller needs correct size to alloc. | spec | MEDIUM | HIGH (DoS / memory unsafety in client) | `test_buffers.py` (bouncyhsm + wolfpkcs11, NOT bouncyhsm-only as initially thought) |
| H7b | **wolfpkcs11** | RSA-OAEP **accepts invalid ciphertexts** — 209 wycheproof `*-invalid` vectors decrypt successfully across SHA-1/224/256/384/512 × RSA-2048/3072/4096. Manger-style oracle. | A | MEDIUM (host) | HIGH | `test_wycheproof_rsa_oaep.py` (wolfpkcs11 + bouncyhsm) |
| H7c | **opencryptoki (root cause: OpenSSL PR #30663, upstream-known)** | AES-KWP **buffer overwrite on corrupted input** — `CKM_AES_KEY_WRAP_KWP` decrypt with corrupted AIV/padding returns `CKR_GENERAL_ERROR` BUT writes past the caller's output buffer (canary `guard=00000000000000004b` overwritten). Out-of-bounds write triggered by malformed ciphertext. **Root cause is upstream in OpenSSL's AES-KWP decrypt path (OpenSSL PR #30663), not in opencryptoki itself — surfaces through opencryptoki because it delegates KWP to libcrypto.** | A/unsafety | MEDIUM (host) | **HIGH** (memory safety, attacker-controlled input) | `security/test_error_path_kwp.py` (8F, opencryptoki-only among pool — other OpenSSL-backed providers either don't advertise CKM_AES_KEY_WRAP_KWP or use a different code path) |
| H8 | **corepkcs11** | +541 regression: `CKR_HOST_MEMORY` for invalid EC points (test_wycheproof.py), `CKR_ATTRIBUTE_TYPE_INVALID` for RSA-decrypt setup (test_wycheproof_rsa_decrypt.py). New. | spec | LOW (soft) | MEDIUM | `test_wycheproof.py`, `test_wycheproof_rsa_decrypt.py` |
| H9 | **NSS** | `TestBitFlipUnwrap` causes **NSS process abort** (5 per variant × 4 = 15 instances). Crash on malformed wrapped-key input. | crash | MEDIUM | HIGH | `failure-inventory.json` ABORT_exit |
| H10 | **softhsm2, kryptic, …** | GCM **null-AAD** abort (10 instances across providers). Module crashes on legitimate null-AAD GCM operation. | crash | MEDIUM | HIGH | `failure-inventory.json` ABORT_exit |

### MEDIUM — spec deviations, wrong error codes, universal UB-provoked

| # | Provider(s) | Finding | Class | Soft-token sev | Source |
|---|---|---|---|---|---|
| M1 | **20 providers (all soft-tokens)** | `ulDataLen=0x7fffffffffffffff` to `C_Encrypt/Decrypt/Sign/Verify/Digest` → **SIGSEGV** (20/20). Caller-contract UB but robust modules should return `CKR_ARGUMENTS_BAD`. | UB-provoked | LOW (host) | `security/test_ffi_length_boundary.py` |
| M2 | **15 providers** | Same pattern with arithmetic-overflow inputs. | UB-provoked | LOW | `security/test_arithmetic_overflow.py` |
| M3 | **17 providers** | `test_buffers.py` various — empty-input digest returns wrong CKR; retry-state corruption. | spec | LOW–MED | `test_buffers.py` |
| M4 | **5 soft-tokens (546 cases)** | `rsa_pkcs1_decrypt` **ACCEPT_INVALID** — accepts invalid PKCS#1 v1.5 ciphertexts uniformly. **Bleichenbacher mitigation gap.** Universal across soft-tokens. | A (oracle) | MEDIUM (host-local) | `failure-inventory.json` ACCEPT_INVALID |
| M5 | **opencryptoki (288 cases)** | AES-CBC-PKCS5 **lax padding** acceptance. Vaudenay padding oracle. | A | MEDIUM | `failure-inventory.json` |
| M6 | **tpm2** | RSA-PSS **rejects valid (43) + accepts invalid (39)**. Both directions wrong. | A | HIGH (TPM is hardware!) | `failure-inventory.json` |
| M7 | **kryptic** | After write to read-only attr, read-back returns `CKR_ATTRIBUTE_VALUE_INVALID` — object left in inconsistent state. | C (inconsistency) | MEDIUM | `test_set_attribute.py` |
| M8 | **6 providers (34 cases)** | EdDSA **ACCEPT_INVALID** — accepts invalid EdDSA signatures. | A | MEDIUM | `failure-inventory.json` |
| M9 | **4 providers (36 cases)** | ML-DSA **SigVer** fails. **Possibly harness-vector bug PC-2** — needs test-side verification. | TBD | TBD | `failure-inventory.json` |
| M10 | **NSS** | MAC-with-RSA-key SIGSEGV (previously documented, still present). | crash | MEDIUM | `findings-summary-2026-06-10.md` |
| M11 | **NSS** | `CKM_RSA_X_509` unwrap-leading-end handling. | spec | LOW | `findings-summary-2026-06-10.md` |
| M12 | **corepkcs11** | Silent EC **curve rebind** (changing `CKA_EC_PARAMS` rebinds key to new curve). | B | MEDIUM | `findings-summary-2026-06-10.md` |

### LOW — capability gaps, minor spec issues

| # | Provider(s) | Finding | Source |
|---|---|---|---|
| L1 | corepkcs11 | No RSA keypair generation (`CKR_MECHANISM_INVALID` for `CKM_RSA_PKCS_KEY_PAIR_GEN`); can't import AES keys; `C_GenerateRandom(4096)` returns `CKR_FUNCTION_FAILED`. Capability gap. | `test_cve_regression.py`, `test_buffers.py` |
| L2 | corepkcs11 | `C_CreateObject` returns `CKR_ATTRIBUTE_VALUE_INVALID` for basic templates; `C_FindObjectsInit` empty template returns `CKR_ARGUMENTS_BAD` not `CKR_OK`. | `test_ckr_object.py` |
| L3 | bouncyhsm | PQC test issues (ML-DSA, ML-KEM, SLH-DSA) — likely harness vectors + early-provider implementations. | `test_acvp_mldsa`, `test_acvp_slhdsa`, `test_wycheproof_mldsa_sign`, `test_wycheproof_mlkem` |
| L4 | tpm2 | EC curve/import limitations, RSA key import gaps — TPM hardware constraints, not bugs. | `test_ec_curves`, `test_ec_import_export`, `test_rsa_key_import`, 7 unique files |
| L5 | tpm2 | SHA-1 SigVer behavior, fork-timeout — documented TPM quirks. | `findings-summary-2026-06-10.md` |
| L6 | opencryptoki | AES-CTR `ulCounterBits` incorrect value. | `findings-summary-2026-06-10.md` |
| L7 | wolfpkcs11 | 9 unique fails (`test_ckr_dual`, `test_benchmark`, `test_dual_function`, `test_kat`, `test_multipart*`, `test_resource`, `test_stateful`, `test_stress`) — mostly state/resource handling in wolf-specific features. | wolfpkcs11-unique |

---

## 3. New findings vs. already-documented

**Already in `docs/module-issues.md` or `findings-summary-2026-06-10.md` (re-confirmed today):**
- C5 (wolfpkcs11 + bouncyhsm AES-CCM no-auth)
- H9 (NSS TestBitFlipUnwrap abort)
- H10 (GCM null-AAD abort)
- M4 (rsa_pkcs1_decrypt ACCEPT_INVALID universal)
- M6 (tpm2 RSA-PSS)
- M10, M11, M12 (NSS MAC/unwrap/curve-rebind)
- L5, L6 (tpm2 / opencryptoki minor)

**NEW findings (not previously documented — need validation):**
- **C1 — bouncyhsm EdDSA wrong signature** (`test_sign_p11_verify_crypto` → `InvalidSignature`). 
  Confirmed real: test signs via `C_Sign`, then calls `cryptography.hazmat...Ed25519PublicKey.verify()`.
  Other providers pass. This is a **genuine RFC-8032-correctness break in bouncyhsm**.
- **C2 — bouncyhsm `CKA_MODULUS` changeable.** policy protection violation.
- **C3 — bouncyhsm AES-GCM IV reuse accepted.** (May be related to existing C5; needs separation.)
- **C4 — bouncyhsm AES-GCM 4-byte IV accepted.**
- **C7 — wolfpkcs11 digest subsystem broken.** ~250 digest tests fail. Returns out-of-range CK_RV
  `0xffffffffffffff7c` (=-132 i64) for SHA-1/2 and `CKR_ARGUMENTS_BAD` for SHA-3. Mechanism is
  advertised but operation is broken — likely wolfCrypt internal error leaking through CK_RV.
- **H6 — bouncyhsm NULL-pr `C_Decrypt` leaves op active.** lifecycle.
- **H7 — bouncyhsm + wolfpkcs11 wrong `pulSize` after `CKR_BUFFER_TOO_SMALL`.** Shared bug
  (initially thought bouncyhsm-only).
- **H7b — wolfpkcs11 (and bouncyhsm) RSA-OAEP accepts invalid ciphertexts.** 209 wycheproof
  `*-invalid` vectors decrypt successfully.
- **H7c — opencryptoki AES-KWP buffer overwrite on corrupted input.** Out-of-bounds write past
  caller's output buffer on the error path of `CKM_AES_KEY_WRAP_KWP` decrypt. **Root cause is
  upstream in OpenSSL (PR #30663, known there) — surfaces through opencryptoki via libcrypto.
  Bug-report target: OpenSSL, not opencryptoki.** Memory-safety bug.
- **H8 — corepkcs11 +541 regression** (CKR_HOST_MEMORY / CKR_ATTRIBUTE_TYPE_INVALID for new test additions).
- **H1 — NSS SIGSEGV in 3 new files** (`test_mech_flags`, `test_mech_negative`, `test_operation_termination`).
  Prior NSS crashes were in `test_*` files not in this set; this is a new crash surface.
- **M9 — ML-DSA SigVer (36)** — needs test-side verification (harness-vector bug PC-2 candidate).

---

## 4. Test-bug candidates (vs. real provider bugs)

These findings are **more likely bugs in pkcs11-check itself** than provider bugs — flagged
for the pkcs11-check improvement track. Each needs verification before being promoted to
real provider finding.

| # | Pattern | Why suspect | Action |
|---|---|---|---|
| T1 | **M9 — ML-DSA SigVer 36 fails across 4 providers** | failure-inventory.json flags "harness-vector bug PC-2". Vectors may be misformatted. | Re-check vector loader; cross-verify with reference impl. |
| T2 | **Universal 20-provider `test_ffi_length_boundary.py` SIGSEGV** | Tests pass `ulDataLen=2^63-1` deliberately to probe UB. Realistic concern? — well-defined as a fuzz probe but caller-contract-violating by spec. | Keep as a finding-class (UB-robustness), not a per-provider bug. Document clearly. |
| T3 | **Universal 15-provider `test_arithmetic_overflow.py`** | Same as T2 — overflow probe. | Same. |
| T4 | **corepkcs11 +541 in test_wycheproof.py** — `CKR_HOST_MEMORY` | Looks like corepkcs11 returns wrong CKR for invalid EC points. Could the test be sending a malformed template? — unlikely (other providers reject cleanly). | Verify with corepkcs11 source. |
| T5 | **wolfpkcs11-master `test_authenticated_wrap`, `test_hash_ml_dsa`, `test_hkdf_extended`, `test_wycheproof_ecdsa` (unique)** | Master-only unique fails could indicate test relies on something wolf-master hasn't shipped yet. | Check feature-flag expectation. |

---

## 5. Validation round — plan

**Goal:** Confirm NEW findings (§3) and re-verify the headline CRITICAL/HIGH findings on
**fresh** docker rebuilds into `artifacts/` (live folder). No staleness. The pool-2026-06-09
staleness lesson (kryptic CCM showed 0P/3420xfail but fresh rebuild = 4890P) mandates this.

### 5.1 Priority-1 validations (CRITICAL — must run)

| Run | Provider | Test scope | Dockerfile | Why |
|---|---|---|---|---|
| V1 | bouncyhsm | `test_eddsa.py::TestEdDSACrossVerify::test_sign_p11_verify_crypto` + Ed448 sibling | `docker/bouncyhsm` | Confirm C1: wrong EdDSA signature |
| V2 | bouncyhsm | `test_set_attribute.py::test_cannot_change_modulus` + nearby | `docker/bouncyhsm` | Confirm C2: modulus changeable |
| V3 | bouncyhsm | `test_parameter_validation.py` (single-file, observe pre-crash) | `docker/bouncyhsm` | Confirm C3+C4: AES-GCM IV reuse + 4-byte IV |
| V4 | bouncyhsm | `test_padding_oracle.py` (full file) | `docker/bouncyhsm` | Confirm C6: 3 padding oracles |
| V4b | wolfpkcs11 | `test_digest.py` + `test_kat.py` + one ACVP hash vector | `docker/wolfpkcs11` | Confirm C7: digest broken, capture exact CK_RV trace for the bug report |
| V4c | wolfpkcs11 | `test_wycheproof_rsa_oaep.py -k "invalid"` | `docker/wolfpkcs11` | Confirm H7b: RSA-OAEP invalid-accept with a minimal vector set |
| V4d | opencryptoki | `security/test_error_path_kwp.py` (full file) — **LOW PRIORITY: bug already tracked upstream as OpenSSL PR #30663** | `docker/opencryptoki` | Only needed if a clean repro is wanted for the OpenSSL bug thread, or to confirm behavior after the OpenSSL fix lands and percolates into the opencryptoki docker image. Skip otherwise. |

### 5.2 Priority-2 validations (HIGH — should run)

| Run | Provider | Test scope | Dockerfile | Why |
|---|---|---|---|---|
| V5 | nss-main | `test_mech_flags.py`, `test_mech_negative.py`, `test_operation_termination.py` | `docker/nss-softoken/Dockerfile.main` | Isolate NSS SIGSEGV root cause (one variant is enough; all 4 share crash) |
| V6 | wolfpkcs11 | The 11 crash files (single-test isolation each) | `docker/wolfpkcs11` | Catalog wolfpkcs11 crash signatures |
| V7 | kryoptic-fips | 5 SIGABRT files in FIPS mode | `docker/kryptic` (FIPS mode) | Identify FIPS assertion triggers |
| V8 | bouncyhsm | `test_operation_termination.py` + `test_ckr_object.py` + `test_buffers.py` | `docker/bouncyhsm` | Confirm H6 (lifecycle), H7 (pulSize) |
| V9 | corepkcs11 | `test_wycheproof.py`, `test_wycheproof_rsa_decrypt.py` | `docker/corepkcs11` | Confirm H8: regression root cause |

### 5.3 Priority-3 validations (MEDIUM — nice to have)

| Run | Provider | Test scope | Why |
|---|---|---|---|
| V10 | kryptic | `test_set_attribute.py` | Confirm M7: object-state corruption |
| V11 | tpm2 | RSA-PSS test files | Confirm M6 still present after recent fix wave |
| V12 | softhsm2 + kryptic + nss + opencryptoki | ML-DSA SigVer test files | Determine if M9 is harness-vector bug PC-2 |
| V13 | opencryptoki | `test_padding_oracle.py` AES-CBC-PAD subset | Confirm M5: 288 lax-padding cases |

### 5.4 Validation execution pattern

```bash
# For each Vn: targeted single-provider docker run with --isolation auto,
# fresh build (no --no-build), results into artifacts/<provider>-validate-Vn/
bash docker/test.sh bouncyhsm \
  -k "test_sign_p11_verify_crypto or test_cannot_change_modulus" \
  --artifact-dir artifacts/bouncyhsm-validate-V1V2

# Cross-verify CRITICAL findings with reference impl where applicable
# (e.g. C1 EdDSA: use `python -c "from cryptography.hazmat..."` to re-verify
#  a captured signature against RFC 8032 test vectors).
```

**Validation gate:** A finding graduates from "preliminary" to "confirmed" only after a
fresh targeted run reproduces it on a clean rebuild. Until then it stays tagged
`preliminary` in downstream bug reports.

---

## 6. Per-provider headline (one-liner for each real provider)

| Provider | Headline |
|---|---|
| **bouncyhsm** | 4 new CRITICAL (EdDSA wrong sig, modulus mutable, GCM IV-reuse, GCM short-IV) + 3 padding oracles + multiple SIGSEGV. **Worst-performing real provider by severity.** |
| **wolfpkcs11** | **Digest subsystem completely broken** (C7 — ~250 digest tests fail with out-of-range CK_RV 0xffffffffffffff7c). Plus 11 SIGSEGV/SIGABRT crash files, AES-CCM no-auth, RSA-OAEP invalid-accept (209 vectors), wrong-pulSize-after-BUFFER_TOO_SMALL, wrong-key-type HMAC accepted. **Worst overall correctness posture** despite lower raw fail count than bouncyhsm. |
| **kryoptic-fips** | FIPS-mode self-aborts on 5 mechanism files. Non-FIPS kryptic clean. |
| **NSS (all variants)** | 3 new SIGSEGV files; MAC-with-RSA-key SIGSEGV persists; TestBitFlipUnwrap abort persists. |
| **corepkcs11** | +541 regression today (CKR_HOST_MEMORY for invalid EC points, missing RSA-decrypt attribute). Plus existing EC-curve-rebind + keygen gaps. |
| **opencryptoki** | **AES-KWP buffer overwrite on corrupted input** (H7c — memory-safety bug; **root cause upstream in OpenSSL PR #30663, not in opencryptoki**). 144 AES-CBC-PKCS5 padding-oracle cases. GCM weak-tag accepted. Otherwise clean. **No crashes.** |
| **tpm2** | Big improvement (ΔF −63). RSA-PSS still wrong both directions (TPM hardware concern). EC/import = capability gap. |
| **softhsm2** | Flat. EdDSA ACCEPT_INVALID (34 instances across soft-tokens) is the main remaining finding. No crashes. |
| **pkcs11-mock** | Excluded (mock). |

---

## 7. Soft-token severity-adjustment note

Per user's threat-model framing: all listed providers are soft-tokens. Findings categorised
as **"HIGH (host-local)" / "MEDIUM (host-local)"** retain full *correctness* severity but
have reduced *security* severity for the deployment where the host already owns the keys.

The findings become **CRITICAL** in any deployment where:
- The module is backed by real hardware (HSM, TPM-protected-key, secure-element)
- The module is reachable via a proxy/daemon (network-accessible attacker)
- The module is used as a reference implementation by downstream consumers

The "CVE-impact sev" column in §2 reflects this — the **max** severity the finding would
carry in any realistic deployment.

---

## 8. Next-step inputs (for the user)

1. **Bug-report track (provider bugs):** §2 CRITICAL + HIGH rows, validated via §5 P1 + P2,
   feed individual provider bug reports. **C1 (bouncyhsm EdDSA) is the single most
   reportable finding** — clean crypto-correctness break, easy repro.
2. **pkcs11-check improvement track (test bugs):** §4 T1–T5 — verify each is a harness bug,
   then patch the loader/test.
3. **Module-issues doc updates:** §3 NEW findings to be appended to
   `docs/module-issues.md` after validation.
4. **Validation execution:** §5 P1 first; only validated findings go to bug reports.

---

*Cross-references: `findings-summary-2026-06-10.md`, `failure-inventory.json`,
`crash-inventory.json` (INCOMPLETE — needs update from §2 H1–H10), `issues-triage.md`,
`pool-2026-06-10-comparison.md`, `module-issues.md`.*

---

## 9. Master-canonical reanalysis (2026-06-13, post-hoc)

**Per user directive:** for providers with a master/main variant in the pool, use that
variant as the canonical current state — release variants lag master and may already have
fixes (or swapped-bug-direction). Findings present in release but absent in master are
demoted (already fixed upstream).

### 9.1 Master-vs-release comparison summary

| Pair (release → master) | ΔF | Verdict |
|---|---|---|
| **wolfpkcs11 → wolfpkcs11-master** | **−408** (876→468) | Massive master improvement; several release bugs fixed; **new/different master bugs surface** (see §9.2) |
| opencryptoki → opencryptoki-master | 0 (215=215) | Identical. All findings stand. |
| corepkcs11 → corepkcs11-main | 0 (683=683) | Identical. +541 regression stands. |
| kryoptic → kryoptic-main | +1 (157→158) | Essentially identical. Findings stand. |
| nss → nss-main | −11 (141→130) | Marginal. NSS SIGSEGV crashes identical (9=9). Findings stand. |
| softhsm2 → softhsm2-main | −3 (70→67) | Marginal. Findings stand. |

### 9.2 wolfpkcs11-MASTER canonical findings (supersedes earlier wolf entries)

Comparing against `wolfpkcs11-master` (current tip) instead of `wolfpkcs11` (release), the
picture changes substantially. **Several earlier findings had the WRONG DIRECTION** because
release and master swapped bug directions on the same operation. Corrected below.

| ID | Finding (master-canonical) | Direction | Fails | Status |
|---|---|---|---|---|
| **W1** | **RSA-OAEP decrypt rejects VALID ciphertexts** — `tc1-valid` of every OAEP variant (SHA-1/224/256/384/512 × RSA-2048/3072/4096) returns `CKR_ENCRYPTED_DATA_INVALID`. OAEP decrypt is functionally broken in master. **Severity dropped from release:** the release accepted invalid ciphertexts (Manger oracle → Critical); master flipped to over-strict reject. **Reject-valid is NOT a security issue** (no oracle, no leak, no wrong output — just a clean false-negative error). Per AGENTS.md this is "advertised but not operational" → xfail-class, not a security finding. | reject-valid (clean error) | 210 | **LOW — functional bug, not security** |
| **W2** | **AES-CCM decrypt rejects VALID ciphertexts** — `tc45..tc50+` valid-tag vectors return `CKR_ENCRYPTED_DATA_INVALID`. CCM decrypt functionally broken in master. **Severity dropped from release:** C5 was release "accept-invalid" (Critical, crypto — AEAD authenticity bypassed); master flipped to "reject-valid". **Reject-valid does NOT violate any AES-CCM security property** — it's a false negative on a valid ciphertext, returned as a clean `CKR_ENCRYPTED_DATA_INVALID`. No leak, no forgery, no crash. | reject-valid (clean error) | 44 | **LOW — functional bug, not security** |
| **W3** | **`C_DigestKey` produces wrong digest** — output equals SHA-256 of empty input (`e3b0c44298fc1c14…`) regardless of key material. The key is not being mixed into the digest. Real correctness bug. | wrong output | 3 | **HIGH — report** |
| **W4** | **`C_DigestKey` accepts sensitive/non-extractable imported key** — `test_digest_key_sensitive_non_extractable_imported_key` fails: module digests a protected key. policy protection violation (sensitive key material shouldn't be digestable). | protection | 1 | **HIGH — report** |
| **W5** | **ML-DSA sign+verify roundtrip fails** with `CKR_FUNCTION_FAILED` for all hash variants (SHA-256/384/512, SHA3-256). ML-DSA broken in master. | fails | 4 | **HIGH — report** |
| **W6** | **ML-DSA verify** — mix of valid-sigs-rejected (`tc147-valid`, `tc161-valid`) and invalid-handling issues across mldsa_44/65. | mixed | 15 | **HIGH — report** |
| **W7** | **Valid ECDSA signatures rejected** on less-common curves/hashes: secp224r1, SHA3-224/256/384/512, SHAKE128, P1363. wolfCrypt curve/hash-support gap. | reject-valid | 14 | **MEDIUM — report** |
| **W8** | **HKDF derive returns `CKR_ATTRIBUTE_VALUE_INVALID`** for all HKDF-key/data derive operations. HKDF broken in master. | fails | 4 | **MEDIUM — report** |
| **W9** | **NULL-pointer lifecycle (lifecycle)** — `C_Encrypt/Decrypt/EncryptUpdate/DecryptUpdate` with NULL input/length pointer returns `CKR_ARGUMENTS_BAD` BUT **leaves the operation active** → next init gets `CKR_OPERATION_ACTIVE`. Same bug class as bouncyhsm H6. Also: SHA256 `C_Digest(empty)` returns `CKR_ARGUMENTS_BAD` but leaves op active. | C (lifecycle) | 10 | **HIGH — report** |
| **W10** | **SHA-3 empty-input digest returns `CKR_ARGUMENTS_BAD`** — SHA3_224/256/384/512 empty-input cases all fail. | spec | 4 | **MEDIUM — report** |
| W11 | Crash files remaining in master: `wycheproof/test_wycheproof_hkdf.py` (rc=6 SIGABRT), `x509/test_identity.py` (rc=5 SIGTRAP). Down from 18 → 4 crashes. | crash | 2 files | **HIGH — report** |

**RELEASE-ONLY findings now DEMOTED (fixed in master, no longer reportable):**
- C7 (release-only): garbage-CK_RV digest subsystem — **mostly fixed**, only the C_DigestKey correctness bug (W3/W4) remains.
- test_kat (8F release → 0 master): fixed.
- test_multipart_streaming (6F release → 0 master): fixed.
- test_ckr_dual, test_dual_function, test_stress, test_api_security, test_attribute_defaults, test_multipart: all release-only, fixed in master.

### 9.3 Providers WITHOUT master/main variant in pool — need fresh docker run

These providers have only one variant in `artifacts_base`. To check current tip, a fresh
docker rebuild + targeted run is required:

| Provider | What's in pool | Findings to re-verify on tip |
|---|---|---|
| **bouncyhsm** | release only | C1 (EdDSA wrong sig), C2 (modulus mutable), C3 (GCM IV reuse), C4 (GCM short IV), C6 (3 padding oracles), H5 (SIGSEGVs), H6 (lifecycle), H7 (wrong pulSize) |
| **tpm2** | release only | M6 (RSA-PSS both directions), L4 (EC/import limits) |
| **kryptic-fips** | FIPS only (no fips-main) | H4 (5 SIGABRT files in FIPS mode) |

→ Add these to §5 validation round as **P0** (build from latest git HEAD, not the release
snapshot the docker image may cache).

### 9.4 Net effect on §2 severity tables

- **C5 (wolfpkcs11+bouncyhsm AES-CCM no-auth)** — the wolfpkcs11 half is **recharacterized
  in master** as W2 (reject-valid, not accept-invalid). Severity drops from CRITICAL → LOW
  (reject-valid is a functional bug, not a security break). The bouncyhsm half stands pending
  fresh run (§9.3) — if bouncyhsm still accepts invalid, THAT remains Critical.
- **C7 (wolfpkcs11 digest broken)** — **demoted** to W3/W4 (C_DigestKey wrong output +
  protection violation). The subsystem-wide breakage is fixed in master.
- **H7b (wolfpkcs11 RSA-OAEP invalid-accept)** — **direction FLIPPED in master** (W1:
  reject-valid). Severity drops from HIGH (Manger oracle) → LOW (functional bug). Report
  against master-canonical W1.
- **H6 (bouncyhsm NULL-ptr lifecycle)** — also applies to **wolfpkcs11-master** (W9) and is
  not bouncyhsm-exclusive.

### 9.5 Severity-direction principle (generalised)

When the same operation has opposite bug directions in release vs master:

| Bug direction | Security property violated? | Severity |
|---|---|---|
| **accept-invalid** (lax) on auth/AEAD/RSA-PAD | YES — authenticity/integrity bypassed (oracle, forgery, Bleichenbacher/Manger/Vaudenay) | **Critical/High** |
| **reject-valid** (over-strict) on same | NO — false negative, clean error return, no leak/forgery/wrong-output | **Low** (functional bug, "advertised but not operational") |
| **wrong-output** on a successful operation | YES — crypto-correctness break (caller believes result is correct) | **Critical** |

This is why master's W1/W2 are LOW while the release's same-mechanism findings were Critical:
master traded a security break for a functional bug. **Always classify by what the module
DID vs what is correct, not by mechanism name alone.**

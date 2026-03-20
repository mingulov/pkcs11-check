# OASIS PKCS#11 Spec Compliance — Master Roadmap

> **For agentic workers:** Each phase below is a self-contained sub-project. To execute a phase:
> 1. Read this roadmap and the gap analysis at `docs/gap-analysis-oasis-spec.md`
> 2. Read the OASIS spec files listed in the phase (at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`)
> 3. Read the existing test patterns referenced (follow them exactly)
> 4. **Do a deep gap analysis** of the specific phase scope against what already exists — the gap analysis document may be stale
> 5. Use `superpowers:writing-plans` to create a detailed implementation plan for the phase
> 6. Use `superpowers:subagent-driven-development` to execute the plan
> 7. Run full regression (`bash local-builds/test.sh softhsm2` + `bash local-builds/test.sh kryoptic`) before declaring complete

**Goal:** Achieve comprehensive OASIS PKCS#11 v3.2 spec coverage across all mechanisms, API functions, object types, attributes, and session semantics.

**Architecture:** Each phase adds tests in `src/pkcs11_check/testcases/` following existing patterns. Tests auto-skip when mechanisms are unsupported. All tests must pass lint (`uv run ruff check src/`), type check (`uv run mypy src/`), and regression on SoftHSM2 + Kryoptic.

**Tech Stack:** Python 3.11+, pytest, python-pkcs11 fork (git submodule), uv, ruff, mypy

---

## How Each Phase Works

Every phase follows the same autonomous execution cycle:

```
1. READ this roadmap → understand phase scope
2. READ OASIS spec files → extract exact requirements
3. DEEP GAP ANALYSIS → verify what's already tested vs what's missing
   - grep for mechanism names in test files
   - check if claimed "gaps" are actually covered by existing Wycheproof/ACVP tests
   - produce a corrected gap list for the specific phase
4. WRITE detailed plan → use superpowers:writing-plans
5. EXECUTE plan → use superpowers:subagent-driven-development
6. SELF-REVIEW → after implementation:
   - Run ruff check + mypy on changed files
   - Run tests on SoftHSM2 and Kryoptic
   - Verify each mechanism/function/object from the phase scope is actually tested
   - Fix any gaps found during review
7. UPDATE docs/gap-analysis-oasis-spec.md with corrected coverage numbers
8. COMMIT + create PR branch
```

**Critical rule:** The gap analysis document (`docs/gap-analysis-oasis-spec.md`) may be outdated by the time a phase executes. Always re-verify current coverage before writing tests. Do NOT duplicate existing tests.

---

## Cross-Cutting Rules (ALL Phases Must Follow)

### Module-Specific Behavior Protocol
- Document module quirks in `docs/module-issues.md` (NOT as silent `pass` in code)
- Use `compliance.note()` for spec deviations that aren't bugs
- Use `pytest.xfail()` with explanation for known module bugs
- **NEVER** use generic `except PKCS11Error: pass` — always catch specific CKR subclasses

### Marker Assignment
- Mechanism availability: use `has_mechanism(p11_module, "MECHANISM_NAME")` + `pytest.skip()` (not `@pytest.mark.needs_mechanism`)
- v3.0+ tests: add `@pytest.mark.requires_v30` or `@pytest.mark.requires_v32`
- Assign `pytestmark` per file: `pytest.mark.cert`, `pytest.mark.keymgmt`, `pytest.mark.pqc`, etc.
- Mark destructive tests (PIN changes, finalize): `@pytest.mark.destructive`

### python-pkcs11 Fork Enum Coverage
- If a mechanism is in the OASIS spec but NOT in `python-pkcs11/pkcs11/mechanisms.py`, the enum must be added to the fork BEFORE tests can be written
- Do NOT use raw integer mechanism values for standard mechanisms
- Check `python-pkcs11/pkcs11/mechanisms.py` and `python-pkcs11/pkcs11/constants.py` first

### Documentation Updates
- Update `docs/test-coverage.md` after each phase (add new test files to the category tables)
- Run `scripts/generate-coverage-report.py` if it exists
- Update `docs/gap-analysis-oasis-spec.md` with corrected coverage numbers

### Extending vs Creating Test Files
- **Extend existing files** when the mechanism/function is already partially tested (e.g., test_token_flags.py for C_GetTokenInfo enhancements)
- **Create new files** only for entirely new mechanism families or object types
- Before creating a file, grep for existing coverage: `grep -r "MECHANISM_NAME" src/pkcs11_check/testcases/`

---

## Phase Dependencies

```
Phase A (API Functions) ──────────┐
Phase B (Objects & Attributes) ───┤─→ Can run in parallel
                                  │
Phase C (Tier 1 Mechanisms) ──────┤─→ After A+B (uses improved object/API tests)
Phase D (PQC Hash Variants) ──────┤─→ Independent (PQC-specific)
                                  │
Phase E (Legacy Ciphers) ─────────┤─→ Independent
Phase F (Protocol Mechanisms) ────┤─→ Independent
Phase G (Specialized) ────────────┤─→ Independent
                                  │
Phase H (Compliance Hardening) ───┘─→ Last (depends on all others)
```

Phases A+B should go first. C-G can run in any order after A+B. Phase H goes last.

---

## Phase A: Core API Function Completeness

**Goal:** Test every C_* function defined in the OASIS spec. Close the ~23 function gap.

**Duration:** 2-3 weeks

### Scope

**Functions needing NEW tests (not currently tested at all):**

| Function | Category | OASIS Spec File | Priority |
|----------|----------|----------------|----------|
| C_GetOperationState | Session | session_mgmt_functions.md | High |
| C_SetOperationState | Session | session_mgmt_functions.md | High |
| C_LoginUser | Session (v3.0) | session_mgmt_functions.md | Medium |
| C_SessionCancel | Session (v3.0) | session_mgmt_functions.md | Medium |
| C_DigestKey | Digest | message_digesting_functions.md | Medium |
| C_SignRecoverInit / C_SignRecover | Sign | signing_and_macing_functions.md | Medium |
| C_VerifyRecoverInit / C_VerifyRecover | Verify | functions_for_verifying_signatures_and_macs.md | Medium |
| C_WaitForSlotEvent | Slot/Token | slot_and_token_mgmt_functions.md | Low |
| C_GetFunctionStatus / C_CancelFunction | Parallel (legacy) | parallel_function_management_functions.md | Low |
| C_DigestEncryptUpdate | Dual-function | dual-function_cryptographic_functions.md | Medium |
| C_DecryptDigestUpdate | Dual-function | dual-function_cryptographic_functions.md | Medium |
| C_SignEncryptUpdate | Dual-function | dual-function_cryptographic_functions.md | Medium |
| C_DecryptVerifyUpdate | Dual-function | dual-function_cryptographic_functions.md | Medium |
| Message-based finalizers | v3.0 | message_based_*_functions.md | Medium |
| Async lifecycle | v3.0 | asynchronous_function_management_functions.md | Low |

**Functions needing ENHANCED tests (partial coverage exists — extend, don't duplicate):**

| Function | Existing Test File | What's Missing |
|----------|-------------------|----------------|
| C_GetInfo | test_token_flags.py, test_interface.py | Version field validation, flag semantics |
| C_GetSlotInfo | test_token_flags.py | Hardware/firmware version, flag semantics |
| C_GetTokenInfo | test_token_flags.py | Memory counters, all flag bits, session counts |
| C_GetInterfaceList | test_interface.py | Negative cases, interface enumeration depth |
| C_CopyObject | test_access_control.py, test_api_security.py | Attribute modification during copy, cross-session copy |
| C_CloseAllSessions | test_session_edge_cases.py | Multi-session cleanup, object visibility after |
| C_UnwrapKey | test_keymgmt.py, test_rsa_key_wrapping.py | Template enforcement, cross-mechanism unwrap |
| C_SeedRandom | test_rng.py | Entropy quality after seed, error paths |

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_init.py` — module lifecycle tests
- `src/pkcs11_check/testcases/test_slot.py` — slot/token info tests
- `src/pkcs11_check/testcases/test_interface.py` — v3.0 interface negotiation
- `src/pkcs11_check/testcases/test_object.py` — object CRUD operations
- `src/pkcs11_check/testcases/test_keymgmt.py` — key management (wrap/unwrap/derive)
- `src/pkcs11_check/testcases/test_multipart.py` — multi-part crypto operations

### Files to Create or Extend

- **Create** `src/pkcs11_check/testcases/test_operation_state.py` — C_GetOperationState / C_SetOperationState (entirely new)
- **Create** `src/pkcs11_check/testcases/test_sign_recover.py` — C_SignRecover / C_VerifyRecover (entirely new)
- **Create** `src/pkcs11_check/testcases/test_v30_session.py` — C_LoginUser, C_SessionCancel (v3.0+, entirely new)
- **Create** `src/pkcs11_check/testcases/test_dual_function.py` — Dual-function operations (entirely new)
- **Extend** `src/pkcs11_check/testcases/test_token_flags.py` — Enhance C_GetInfo, C_GetSlotInfo, C_GetTokenInfo
- **Extend** `src/pkcs11_check/testcases/test_access_control.py` — Enhance C_CopyObject coverage
- **Extend** `src/pkcs11_check/testcases/test_rng.py` — Enhance C_SeedRandom coverage

### Acceptance Criteria

- [ ] Every C_* function from the OASIS spec has at least one test
- [ ] Each function's primary success path is tested
- [ ] Each function's key error paths are tested (wrong state, invalid args)
- [ ] `uv run ruff check src/` passes
- [ ] `bash local-builds/test.sh softhsm2` — no new failures
- [ ] `bash local-builds/test.sh kryoptic` — no new failures
- [ ] `docs/gap-analysis-oasis-spec.md` updated: API coverage → ~95%+

### Test Commands

```bash
# Run only Phase A tests
bash local-builds/test.sh softhsm2 \
  src/pkcs11_check/testcases/test_token_info.py \
  src/pkcs11_check/testcases/test_operation_state.py \
  src/pkcs11_check/testcases/test_copy_object.py \
  src/pkcs11_check/testcases/test_unwrap.py \
  src/pkcs11_check/testcases/test_sign_recover.py \
  src/pkcs11_check/testcases/test_v30_session.py -v

# Full regression
bash local-builds/test.sh softhsm2
bash local-builds/test.sh kryoptic
```

---

## Phase B: Object Types & Attribute Enforcement

**Goal:** Test all 12 OASIS object types and verify attribute enforcement rules.

**Duration:** 2-3 weeks

### Scope

**Untested object types to add:**

| Object Type | CKO_ | Version | OASIS Spec Files |
|-------------|-------|---------|-----------------|
| CKO_HW_FEATURE | 0x05 | v2.40 | hardware_feature_objects.md |
| CKO_MECHANISM | 0x38 | v3.0 | mechanism_objects.md |
| CKO_TRUST | — | v2.40 | trust_objects.md |
| CKO_VALIDATION | 0x3A | v3.1 | validation_objects.md |
| CKO_OTP_KEY | 0x08 | v2.40 | otp_key_objects.md |
| CKO_DOMAIN_PARAMETERS | 0x06 | v2.40 | domain_parameter_objects.md (note: domain param *usage* is well-tested in test_dh_key_agreement.py etc. — the gap is object *attribute* coverage: CKA_PRIME, CKA_BASE, CKA_LOCAL as stored objects) |

**Attribute enforcement to test (across all object types):**

| Attribute Rule | Spec Section |
|---------------|-------------|
| CKA_COPYABLE: can't go FALSE → TRUE | common_attributes.md |
| CKA_DESTROYABLE: prevents C_DestroyObject when FALSE | common_attributes.md |
| CKA_SENSITIVE: can't go TRUE → FALSE | private_key_objects.md, secret_key_objects.md |
| CKA_EXTRACTABLE: can't go FALSE → TRUE | private_key_objects.md, secret_key_objects.md |
| CKA_LOCAL: read-only, set on generation | key_objects.md |
| CKA_KEY_GEN_MECHANISM: read-only, set on generation | key_objects.md |
| CKA_ALWAYS_SENSITIVE: reflects CKA_SENSITIVE history | key_objects.md |
| CKA_NEVER_EXTRACTABLE: reflects CKA_EXTRACTABLE history | key_objects.md |
| CKA_ALLOWED_MECHANISMS: restricts operations | key_objects.md |
| CKA_WRAP_WITH_TRUSTED: requires CKA_TRUSTED wrapping key | private_key_objects.md |
| CKA_ALWAYS_AUTHENTICATE: per-operation C_Login | private_key_objects.md |
| CKA_CHECK_VALUE: KCV computation | secret_key_objects.md |
| Template constraints: WRAP_TEMPLATE, UNWRAP_TEMPLATE, DERIVE_TEMPLATE | key_objects.md |
| CKA_START_DATE / CKA_END_DATE: date range | common_attributes.md |
| CKA_CERTIFICATE_CATEGORY: cert classification | certificate_objects.md |

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_object.py` — object CRUD
- `src/pkcs11_check/testcases/test_search.py` — attribute-based search
- `src/pkcs11_check/testcases/test_set_attribute.py` — attribute modification
- `src/pkcs11_check/testcases/test_api_security.py` — attribute protection
- `src/pkcs11_check/testcases/test_access_control.py` — access enforcement
- `src/pkcs11_check/testcases/test_profiles.py` — CKO_PROFILE enumeration

### Files to Create

- `src/pkcs11_check/testcases/test_hw_features.py` — HW feature enumeration
- `src/pkcs11_check/testcases/test_mechanism_objects.py` — CKO_MECHANISM probing (v3.0+)
- `src/pkcs11_check/testcases/test_trust_objects.py` — Trust binding
- `src/pkcs11_check/testcases/test_validation_objects.py` — CMVP/CC metadata (v3.1+)
- `src/pkcs11_check/testcases/test_domain_params.py` — Domain parameter objects
- `src/pkcs11_check/testcases/test_attribute_enforcement.py` — One-way flags, templates, dates
- `src/pkcs11_check/testcases/test_attribute_defaults.py` — Default value verification

### Acceptance Criteria

- [ ] All 12 OASIS object types have at least enumeration tests
- [ ] All one-way attribute flags verified (SENSITIVE, EXTRACTABLE, COPYABLE, DESTROYABLE)
- [ ] CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE verified
- [ ] CKA_CHECK_VALUE (KCV) tested
- [ ] Template constraint attributes (WRAP_TEMPLATE, etc.) tested where supported
- [ ] `docs/gap-analysis-oasis-spec.md` updated: Object coverage → 12/12, Attribute coverage → 60%+

---

## Phase C: Tier 1 Mechanism Gaps

**Goal:** Add tests for widely-deployed mechanisms that are missing from the test suite.

**Duration:** 3-4 weeks

### Scope

**AES modes (missing ~8 mechanisms):**
- CKM_AES_CTR, CKM_AES_CTS, CKM_AES_CFB8, CKM_AES_CFB64, CKM_AES_CFB128, CKM_AES_OFB
- CKM_AES_MAC, CKM_AES_MAC_GENERAL
- CKM_AES_XCBC_MAC, CKM_AES_XCBC_MAC_96
- CKM_AES_CMAC_GENERAL (parameterized tag length)
- CKM_AES_KEY_WRAP_PKCS7
- OASIS spec: aes.md, aes_with_counter.md, aes_cbc_with_ciphertext_stealing_cts.md, additional_aes_mechanisms.md, aes_cmac.md

**AES key derivation by encryption (2):**
- CKM_AES_CBC_ENCRYPT_DATA, CKM_AES_ECB_ENCRYPT_DATA
- OASIS spec: key_derivation_by_data_encryption_aes-des.md

**RSA gaps (5):**
- CKM_RSA_X_509 (raw RSA), CKM_RSA_X9_31, CKM_RSA_X9_31_KEY_PAIR_GEN
- CKM_RSA_AES_KEY_WRAP, CKM_RSA_PKCS_OAEP_TPM_1_1
- OASIS spec: rsa.md

**DSA completeness (10):**
- CKM_DSA_KEY_PAIR_GEN, CKM_DSA, CKM_DSA_SHA1, CKM_DSA_SHA384, CKM_DSA_SHA512
- CKM_DSA_SHA3_224, CKM_DSA_SHA3_256, CKM_DSA_SHA3_384, CKM_DSA_SHA3_512
- CKM_DSA_PARAMETER_GEN, CKM_DSA_PROBABILISTIC_PARAMETER_GEN
- OASIS spec: dsa.md

**ECDSA/ECDH gaps (10):**
- CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA3_224/256/384/512
- CKM_ECDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE
- CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS, CKM_EC_MONTGOMERY_KEY_PAIR_GEN
- CKM_XEDDSA
- OASIS spec: elliptic_curves.md

**X9.42 DH only (5) — note: CKM_DH_PKCS_* is already tested in test_dh_key_agreement.py:**
- CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE, CKM_X9_42_DH_HYBRID_DERIVE
- CKM_X9_42_DH_PARAMETER_GEN, CKM_X9_42_MQV_DERIVE
- OASIS spec: diffie-hellman.md

**SP800-108 KDF (3):**
- CKM_SP800_108_COUNTER_KDF, CKM_SP800_108_FEEDBACK_KDF, CKM_SP800_108_DOUBLE_PIPELINE_KDF
- OASIS spec: sp800-108_key_derivation.md

**HKDF remaining (2):**
- CKM_HKDF_DATA, CKM_HKDF_KEY_GEN
- OASIS spec: hkdf_mechanisms.md

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_encrypt.py` — AES/RSA encrypt roundtrip pattern
- `src/pkcs11_check/testcases/test_sign.py` — multi-mechanism sign/verify pattern
- `src/pkcs11_check/testcases/test_kdf.py` — key derivation pattern
- `src/pkcs11_check/testcases/test_ec_curves.py` — EC keygen + cross-verify
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py` — DSA with Wycheproof vectors
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py` — ECDH pattern

### Files to Create

- `src/pkcs11_check/testcases/test_aes_modes.py` — CTR, CTS, CFB, OFB, MAC variants
- `src/pkcs11_check/testcases/test_aes_kdf.py` — AES-based key derivation
- `src/pkcs11_check/testcases/test_rsa_extended.py` — RSA_X_509, X9.31, AES key wrap
- `src/pkcs11_check/testcases/test_dsa_complete.py` — Full DSA family
- `src/pkcs11_check/testcases/test_ecdsa_extended.py` — Missing prehash variants
- `src/pkcs11_check/testcases/test_ecdh_extended.py` — Cofactor, MQV, AES wrap
- `src/pkcs11_check/testcases/test_x942_dh.py` — X9.42 DH family
- `src/pkcs11_check/testcases/test_sp800_108_kdf.py` — SP800-108 counter/feedback/pipeline
- `src/pkcs11_check/testcases/test_hkdf_extended.py` — HKDF_DATA, HKDF_KEY_GEN

### Acceptance Criteria

- [ ] ~45 new mechanism tests added
- [ ] Each mechanism: availability check → keygen → operation → cross-verify where possible
- [ ] Mechanism coverage: 70 → ~115 (19% → 31%)
- [ ] Full regression passes on SoftHSM2 + Kryoptic

---

## Phase D: PQC Hash Variants & Stateful Signatures

**Goal:** Complete post-quantum mechanism coverage including all hash-prefixed variants and stateful signature schemes.

**Duration:** 2-3 weeks

### Scope

**ML-DSA hash variants (12):**
- CKM_HASH_ML_DSA_SHA224/256/384/512, CKM_HASH_ML_DSA_SHA3_224/256/384/512
- CKM_HASH_ML_DSA_SHAKE128/256
- CKM_ML_DSA_EXTERNAL_MU, CKM_ML_DSA_EXTERNAL_MU_GEN
- OASIS spec: ml_dsa.md

**SLH-DSA hash variants (12):**
- CKM_HASH_SLH_DSA_SHA224/256/384/512, CKM_HASH_SLH_DSA_SHA3_224/256/384/512
- CKM_HASH_SLH_DSA_SHAKE128/256
- OASIS spec: slh-dsa.md

**Stateful hash signatures (6):**
- CKM_HSS_KEY_PAIR_GEN, CKM_HSS
- CKM_XMSS_KEY_PAIR_GEN, CKM_XMSS
- CKM_XMSSMT_KEY_PAIR_GEN, CKM_XMSSMT
- OASIS spec: hss.md, xmss_and_xmss-mt.md

**KMAC (2):** CKM_KMAC_128, CKM_KMAC_256 — OASIS spec: kmac.md

**SHAKE XOF (4):** Already partially tested via SHA3; verify SHAKE128/256 standalone

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_pqc_sign.py` — ML-DSA/SLH-DSA keygen + sign/verify
- `src/pkcs11_check/testcases/test_kem.py` — ML-KEM encapsulate/decapsulate
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py` — ML-DSA Wycheproof verify
- `src/pkcs11_check/testcases/test_acvp_mldsa.py` — ACVP SigGen vectors

### Files to Create

- `src/pkcs11_check/testcases/test_hash_ml_dsa.py` — All HASH_ML_DSA_* variants
- `src/pkcs11_check/testcases/test_hash_slh_dsa.py` — All HASH_SLH_DSA_* variants
- `src/pkcs11_check/testcases/test_stateful_sigs.py` — HSS, XMSS, XMSS-MT
- `src/pkcs11_check/testcases/test_kmac.py` — KMAC-128/256

### Acceptance Criteria

- [ ] All ML-DSA hash variants tested (12 mechanisms)
- [ ] All SLH-DSA hash variants tested (12 mechanisms)
- [ ] HSS/XMSS/XMSS-MT keygen + sign/verify tested
- [ ] Tests auto-skip on modules without v3.2 or PQC support
- [ ] Mechanism coverage: ~115 → ~150 (31% → 40%)

---

## Phase E: Legacy & Regional Ciphers

**Goal:** Add tests for legacy and regional cipher algorithms defined in the OASIS spec.

**Duration:** 3-4 weeks

### Scope

**DES/DES3 (~22 mechanisms):**
- CKM_DES_KEY_GEN, CKM_DES3_KEY_GEN
- CKM_DES_ECB, CKM_DES_CBC, CKM_DES_CBC_PAD, CKM_DES_OFB64, CKM_DES_CFB8/64
- CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD, CKM_DES3_MAC, CKM_DES3_CMAC
- CKM_DES_CBC_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA
- OASIS spec: double_and_triple-length_des.md, double_and_triple-length_des_cmac.md

**Camellia (~8 mechanisms):**
- CKM_CAMELLIA_KEY_GEN, CKM_CAMELLIA_ECB, CKM_CAMELLIA_CBC, CKM_CAMELLIA_CBC_PAD
- CKM_CAMELLIA_MAC, CKM_CAMELLIA_MAC_GENERAL, CKM_CAMELLIA_CTR
- OASIS spec: camellia.md

**ARIA (~8 mechanisms):**
- CKM_ARIA_KEY_GEN, CKM_ARIA_ECB, CKM_ARIA_CBC, CKM_ARIA_CBC_PAD
- CKM_ARIA_MAC, CKM_ARIA_MAC_GENERAL
- OASIS spec: aria.md

**SEED (~8 mechanisms):**
- CKM_SEED_KEY_GEN, CKM_SEED_ECB, CKM_SEED_CBC, CKM_SEED_CBC_PAD
- CKM_SEED_MAC, CKM_SEED_MAC_GENERAL
- OASIS spec: seed.md

**Blowfish (~4):** CKM_BLOWFISH_KEY_GEN, CKM_BLOWFISH_CBC, CKM_BLOWFISH_CBC_PAD — OASIS spec: blowfish.md

**Twofish (~4):** CKM_TWOFISH_KEY_GEN, CKM_TWOFISH_CBC, CKM_TWOFISH_CBC_PAD — OASIS spec: twofish.md

**GOST (~12 mechanisms):**
- CKM_GOSTR3410_KEY_PAIR_GEN, CKM_GOSTR3410, CKM_GOSTR3410_WITH_GOSTR3411
- CKM_GOSTR3411, CKM_GOSTR3411_HMAC
- CKM_GOST28147_KEY_GEN, CKM_GOST28147, CKM_GOST28147_ECB, CKM_GOST28147_MAC
- OASIS spec: gost_28147-89.md, gost_r_34.10-2001.md, gost_r_34.11-94.md

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_encrypt.py` — block cipher encrypt/decrypt roundtrip
- `src/pkcs11_check/testcases/test_sign.py` — sign/verify pattern with multiple mechanisms
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` — AES mode test pattern

### Files to Create

- `src/pkcs11_check/testcases/test_des.py` — DES/DES3 all modes
- `src/pkcs11_check/testcases/test_camellia.py` — Camellia all modes
- `src/pkcs11_check/testcases/test_aria.py` — ARIA all modes
- `src/pkcs11_check/testcases/test_seed.py` — SEED all modes
- `src/pkcs11_check/testcases/test_blowfish.py` — Blowfish
- `src/pkcs11_check/testcases/test_twofish.py` — Twofish
- `src/pkcs11_check/testcases/test_gost.py` — GOST suite

### Acceptance Criteria

- [ ] All DES/DES3 modes tested
- [ ] All regional ciphers (Camellia, ARIA, SEED) tested
- [ ] GOST suite tested
- [ ] All tests auto-skip when mechanism unsupported
- [ ] Mechanism coverage: ~150 → ~230 (40% → 62%)

---

## Phase F: Protocol Mechanisms

**Goal:** Add tests for protocol-level key derivation and wrapping mechanisms (TLS, SSL, WTLS, IKE, PBE).

**Duration:** 2-3 weeks

### Scope

**TLS 1.2 (~8 mechanisms):**
- CKM_TLS12_MASTER_KEY_DERIVE, CKM_TLS12_KEY_AND_MAC_DERIVE
- CKM_TLS12_MASTER_KEY_DERIVE_DH, CKM_TLS12_KEY_SAFE_DERIVE
- CKM_TLS12_MAC, CKM_TLS12_KDF
- CKM_TLS_MAC, CKM_TLS_KDF
- OASIS spec: tls_1.2_mechanisms.md

**SSL3 (~8 mechanisms):**
- CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_MASTER_KEY_DERIVE
- CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH
- CKM_SSL3_MD5_MAC, CKM_SSL3_SHA1_MAC
- OASIS spec: ssl.md

**WTLS (~6 mechanisms):**
- CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_WTLS_MASTER_KEY_DERIVE
- CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE, CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
- CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
- OASIS spec: wtls.md

**IKE (~4 mechanisms):**
- CKM_IKE1_PRF_DERIVE, CKM_IKE1_EXTENDED_DERIVE
- CKM_IKE2_PRF_PLUS_DERIVE, CKM_IKE_PRF_DERIVE
- OASIS spec: ike_mechanisms.md

**PBE/PKCS#12 (~4 mechanisms):**
- CKM_PBE_SHA1_DES3_EDE_CBC, CKM_PBE_SHA1_DES2_EDE_CBC
- CKM_PKCS12_PBE_EXPORT, CKM_PKCS12_PBE_IMPORT
- OASIS spec: password-based_encryption.md, pkcs12_password-based_encryption-authentication.md

**CMS (1):** CKM_CMS_SIG — OASIS spec: cms_mechanisms.md

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_kdf.py` — key derivation pattern
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py` — PBES2 test pattern

### Files to Create

- `src/pkcs11_check/testcases/test_tls12.py` — TLS 1.2 PRF and key material
- `src/pkcs11_check/testcases/test_ssl3.py` — SSL3 key derivation
- `src/pkcs11_check/testcases/test_wtls.py` — WTLS mechanisms
- `src/pkcs11_check/testcases/test_ike.py` — IKE PRF mechanisms
- `src/pkcs11_check/testcases/test_pbe.py` — PBE/PKCS#12 mechanisms
- `src/pkcs11_check/testcases/test_cms.py` — CMS signature

### Acceptance Criteria

- [ ] TLS 1.2 key derivation round-trip tested
- [ ] SSL3 key derivation tested (legacy but spec-required)
- [ ] IKE PRF derivation tested
- [ ] PBE tested with known vectors where available
- [ ] Mechanism coverage: ~230 → ~260 (62% → 70%)

---

## Phase G: Specialized & Emerging Mechanisms

**Goal:** Add tests for OTP, messaging protocols, and remaining miscellaneous mechanisms.

**Duration:** 2-3 weeks

### Scope

**OTP (~6 mechanisms):**
- CKM_HOTP_KEY_GEN, CKM_HOTP, CKM_ACTI, CKM_ACTI_KEY_GEN
- CKM_SECURID_KEY_GEN, CKM_SECURID
- OASIS spec: otp_mechanisms.md

**CT-KIP (~3):**
- CKM_KIP_DERIVE, CKM_KIP_WRAP, CKM_KIP_MAC
- OASIS spec: ct-kip.md

**Double Ratchet (~4):**
- CKM_DOUBLE_RATCHET_INITIALIZE, CKM_DOUBLE_RATCHET_RESPOND
- CKM_DOUBLE_RATCHET_ENCRYPT, CKM_DOUBLE_RATCHET_DECRYPT
- OASIS spec: double_ratchet.md

**X3DH (~2):**
- CKM_X3DH_INITIALIZE, CKM_X3DH_RESPOND
- OASIS spec: extended_triple_diffie-hellman.md

**Stream ciphers (3):**
- CKM_SALSA20, CKM_SALSA20_KEY_GEN
- CKM_POLY1305 (standalone)
- CKM_CHACHA20 (standalone, without Poly1305)
- OASIS spec: salsa20.md, poly1305.md, chacha20.md

**Misc KDF (4):**
- CKM_CONCATENATE_BASE_AND_KEY, CKM_CONCATENATE_BASE_AND_DATA
- CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA
- OASIS spec: miscellaneous_simple_key_derivation_mechanisms.md

**NULL mechanism (1):** CKM_RSA_PKCS_NULL — OASIS spec: null_mechanism.md

**BLAKE2 (4):** CKM_BLAKE2B_160/256/384/512 — OASIS spec: digests.md

### Files to Create

- `src/pkcs11_check/testcases/test_otp.py` — OTP mechanisms
- `src/pkcs11_check/testcases/test_double_ratchet.py` — Signal Double Ratchet
- `src/pkcs11_check/testcases/test_x3dh.py` — Extended Triple DH
- `src/pkcs11_check/testcases/test_salsa20.py` — Salsa20 stream cipher
- `src/pkcs11_check/testcases/test_misc_kdf.py` — Concatenation and XOR KDFs
- `src/pkcs11_check/testcases/test_blake2.py` — BLAKE2 digests

### Acceptance Criteria

- [ ] OTP key generation and operation tested
- [ ] Messaging protocol mechanisms tested (or cleanly skipped if unsupported)
- [ ] Remaining stream ciphers and KDFs tested
- [ ] Mechanism coverage: ~260 → ~290 (70% → 78%)

---

## Phase H: Session Semantics & Compliance Hardening

**Goal:** Verify PKCS#11 session state machine, access control, and produce a machine-readable compliance report.

**Duration:** 2-3 weeks

### Scope

**Session state machine:**
- Object visibility: session objects vs token objects
- RO session restrictions: can't create/modify token objects
- Login state transitions: USER → SO → not-logged-in
- Concurrent session behavior: shared login state
- OASIS spec: session_mgmt_functions.md, creating_objects.md

**Access control:**
- CKA_PRIVATE enforcement: inaccessible without login
- CKA_TOKEN enforcement: persistence across sessions
- SO vs USER access levels: CKA_TRUSTED (SO-only)
- OASIS spec: objects.md, creating_objects.md

**Compliance reporting:**
- Machine-readable compliance matrix (JSON output)
- Per-mechanism compliance level (STANDARD, VENDOR, NOT_SUPPORTED)
- Per-function compliance status (PASS, FAIL, SKIP, NOT_APPLICABLE)
- Aggregate score per OASIS spec section

**CKR hardening:**
- For each function, verify that ALL spec-required CKR codes are either tested or documented as untestable
- Cross-reference `testcases/ckr/` with OASIS function_return_values.md
- Add missing CKR condition tests

### Existing Patterns to Follow

- `src/pkcs11_check/testcases/test_api_security.py` — access control tests
- `src/pkcs11_check/testcases/test_access_control.py` — session/object visibility
- `src/pkcs11_check/testcases/test_session_edge_cases.py` — session state tests
- `src/pkcs11_check/testcases/ckr/` — CKR return code verification (21 files)
- `src/pkcs11_check/compliance.py` — compliance note system

### Files to Create

- `src/pkcs11_check/testcases/test_session_state_machine.py` — Full state machine verification
- `src/pkcs11_check/testcases/test_object_visibility.py` — Cross-session object visibility
- `src/pkcs11_check/testcases/test_ro_session_restrictions.py` — RO session enforcement
- `src/pkcs11_check/testcases/test_access_levels.py` — SO vs USER vs public
- `src/pkcs11_check/compliance_report.py` — Machine-readable compliance report generator

### Acceptance Criteria

- [ ] Session state machine transitions tested comprehensively
- [ ] Object visibility rules verified across session types
- [ ] RO session restrictions enforced
- [ ] Compliance report generator produces JSON output
- [ ] All 802 CKR entries either tested or documented as untestable
- [ ] Full regression on all local-builds providers (SoftHSM2, Kryoptic, OpenCryptoki)
- [ ] Final `docs/gap-analysis-oasis-spec.md` update with complete coverage numbers

---

## Final Verification

After all 8 phases are complete, run one final verification:

```bash
# Count total test files
find src/pkcs11_check/testcases -name "test_*.py" | wc -l

# Count total tests
uv run pytest src/pkcs11_check/testcases --co -q 2>/dev/null | tail -1

# Full suite on all available backends
bash local-builds/test.sh softhsm2
bash local-builds/test.sh kryoptic
bash docker/test.sh opencryptoki

# Generate compliance report
uv run pkcs11-check compliance-report --output json > compliance-report.json

# Lint + type check
uv run ruff check src/
uv run mypy src/
```

**Target final state:**
- ~200+ test files
- ~40K+ tests
- ~290 of 370 mechanisms covered (78%)
- 68/68 API functions covered (100%)
- 12/12 object types covered (100%)
- 130+ of 190 attributes verified (68%+)
- Machine-readable compliance report

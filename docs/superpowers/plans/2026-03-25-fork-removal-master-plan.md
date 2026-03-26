# Fork Removal Master Plan

**Goal:** Remove dependency on python-pkcs11 fork. Replace with pkcs11_check.raw
for all PKCS#11 access. Audit and fix test quality along the way.

**Current state (2026-03-26):**
- ALL 171 test files migrated to pkcs11_check.raw (zero fork imports in testcases/)
- Raw layer complete: 45+ recipes, 25+ mechanism packers, DER/EC/bootstrap helpers
- python-pkcs11 submodule still present but unused by test code
- Next: remove submodule, then audit test quality on clean codebase

**References (CLAUDE.md has project rules, structure, commands):**
- `src/pkcs11_check/raw/README.md` - raw package contract
- `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md` - raw architecture
- `docs/superpowers/specs/2026-03-24-raw-typed-constants-and-migration-design.md` - typed constants
- OASIS spec: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`

**Core design principle: CKR values are data, not exceptions.**
Tests assert on CKR directly. No PKCS#11 exception hierarchy.
Raw C_* returns plain int. expect_rv() for recipes (AssertionError).

**Sub-projects (execute in order, each in a fresh session):**

1. **Raw Layer Completion** - builds missing infrastructure — DONE
2. **Test Migration (batch 1)** - simple tests first — DONE
3. **Test Migration (batch 2)** - complex tests — DONE (171 files, 34 commits)
4. **Fork Removal** - remove submodule, clean build/docs (reordered: before audit)
5. **Test Quality Audit** - audit on clean codebase with zero fork dependency

---

## Sub-project 1: Test Quality Audit

**Session prompt:**

```
Please read docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md,
section "Sub-project 1: Test Quality Audit" for full context.

Do a deep analysis of test quality in src/pkcs11_check/testcases/:

1. Audit all 344 xfail usages. Categorize each as:
   - VALID: spec says this CKR is acceptable (cite OASIS section)
   - WRONG: module bug being hidden (should fail, not xfail)
   - SKIP: should be pytest.skip (capability not available)
   Fix the WRONG and SKIP categories.

2. Audit all 390 "except PKCS11Error: pass" patterns.
   Each catch must list SPECIFIC acceptable CKR codes per CLAUDE.md rules.
   Fix generic catches to be specific.

3. Audit all 50 generic "except PKCS11Error:" catches.
   Same rule - must be specific exceptions.

4. Review skip justifications - are they checking the right condition?

5. Write a report at docs/reports/2026-03-25-test-quality-audit.md

Rules from CLAUDE.md:
- NEVER skip/disable/suppress real failures or crashes
- NEVER use generic "except PKCS11Error: pass"
- Only skip for missing capabilities (mechanism, interface version)
- xfail only if OASIS spec explicitly allows the failure
- Module bugs should FAIL, not xfail

Work in batches, commit after each category. Run tests after each batch.
```

**Expected output:** Report + fixed test files. Establishes quality baseline.

---

## Sub-project 2: Raw Layer Completion

**Session prompt:**

```
Please read docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md,
section "Sub-project 2: Raw Layer Completion" for full context.

Also read:
- docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md
- src/pkcs11_check/raw/README.md

The goal is to build the missing layers in pkcs11_check.raw so that test
files can be migrated away from the python-pkcs11 fork.

Current raw package has: RawPKCS11, typed constants, pack/fault/inspect,
bootstrap (session/login), recipes (keygen, encrypt, sign).

Missing layers to build:

A. No exception hierarchy:
   - Raw C_* calls return plain int CKR values (already done)
   - Tests assert CKR values directly: assert rv == CKR_KEY_TYPE_INCONSISTENT
   - expect_rv(rv, CKR_OK) already exists for recipes (raises AssertionError)
   - Add: ckr_is_ok(rv) -> bool, ckr_in(rv, *acceptable) -> bool
   - No CKRError, no PKCS11Error equivalent, no exception class hierarchy
   - Python exceptions (RuntimeError, OSError, AssertionError) for non-PKCS#11 errors only

B. Attribute helpers:
   - read_attributes(raw, session, handle, attr_types) -> dict
   - write_attributes not needed (C_SetAttributeValue via raw)
   - get_object_size(raw, session, handle) -> int

C. Object helpers:
   - find_objects(raw, session, template) -> list[int]
   - Already have: create_object (import_secret_key), destroy_quietly

D. Mechanism parameter struct packers:
   - mech_gcm(mechanism, iv, aad_len, tag_bits)
   - mech_pss(hash_mech, mgf, salt_len)
   - mech_oaep(hash_mech, mgf, source_type, source_data)
   - mech_ecdh(kdf, shared_data, public_data)
   - mech_hkdf(...)
   - Each returns PackedMechanism with owned storage

E. Digest/verify/decrypt recipes:
   - digest_single(raw, session, mechanism, data) -> bytes
   - verify_single(raw, session, key, mechanism, data, signature) -> bool
   - decrypt_single(raw, session, key, mechanism, ciphertext) -> bytes

F. Session fixture equivalent:
   - A pytest fixture that uses raw bootstrap, not the fork
   - p11_raw_session fixture
   - has_mechanism(raw, slot, mech_name) helper

G. EC curve encoding helper:
   - encode_named_curve_parameters(name) -> bytes (DER OID)
   - Currently in pkcs11.util.ec, needs equivalent

Brainstorm the design, write spec, plan, implement with TDD.
Each layer should be independently testable.
```

**Expected output:** Completed raw layer with all helpers needed for test migration.

---

## Sub-project 3: Test Migration (Batch 1 - Simple Tests)

**Session prompt:**

```
Please read docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md,
section "Sub-project 3" for full context.

Migrate the simplest test files from python-pkcs11 fork to pkcs11_check.raw.
Start with files that:
- Use only basic operations (keygen, encrypt, sign, verify)
- Don't use complex mechanism parameters
- Don't use object search or attribute access heavily

Suggested first batch (verify these are simple before migrating):
- test_encrypt.py
- test_sign.py
- test_digest.py
- test_errors.py
- test_generic_secret.py
- test_key_lifecycle.py
- test_data_objects.py
- test_slot.py
- test_interface.py
- test_session_info.py

Migration pattern:
1. Replace "from pkcs11 import Attribute, KeyType, Mechanism" with
   "from pkcs11_check.raw.types_std import CKA_*, CKM_*, CKK_*"
2. Replace p11_session.generate_key() with gen_aes_key() recipe
3. Replace key.encrypt() with encrypt_single() recipe
4. Replace key.sign() with sign_single() recipe
5. Replace p11_session fixture with p11_raw_session fixture
6. Replace has_mechanism(p11_module, "NAME") with raw equivalent
7. Replace exception catches with direct CKR value assertions
8. Run tests against SoftHSM2 after each file

Do NOT change test logic or skip/fail behavior.
Do NOT introduce new xfails.
Commit after each file or small batch.
```

**Expected output:** ~10-15 test files migrated.

---

## Sub-project 4: Test Migration (Batch 2 - Complex Tests)

**Session prompt:**

```
Please read docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md,
section "Sub-project 4" for full context.

Continue migrating test files that use complex features:
- Wycheproof vector tests (need EC key import, ECDH derive)
- TLS mechanism tests (need TLS struct packers)
- RSA OAEP/PSS tests (need OAEP/PSS struct packers)
- Key wrapping tests (need wrap/unwrap recipes)
- Object search/attribute tests (need find_objects, read_attributes)
- Cross-verify tests (need encrypt+decrypt+sign+verify combos)
- CVE regression tests
- Stress/threading tests

Work file by file or by test category. Commit frequently.
Run against SoftHSM2 after each batch.
```

**Expected output:** Remaining test files migrated.

---

## Sub-project 5: Fork Removal

**Session prompt:**

```
Please read docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md,
section "Sub-project 5" for full context.

Final cleanup:
1. Verify zero imports from pkcs11.* remain in src/pkcs11_check/
2. Remove python-pkcs11 submodule
3. Update pyproject.toml (remove python-pkcs11 dependency)
4. Update all Dockerfiles (remove python-pkcs11 copy/install)
5. Update CLAUDE.md (remove python-pkcs11 fork references)
6. Update docs/ (remove fork documentation)
7. Run full test suite against all Docker targets
8. Update README.md

grep -rn "from pkcs11 " src/ should return nothing.
grep -rn "python-pkcs11" should return nothing except git history.
```

**Expected output:** Clean codebase with no fork dependency.

---

## Dependency Graph

```
Sub-project 1 (Raw Layer Completion)         ✅ DONE
         |
         v (provides infrastructure)
Sub-project 2 (Migration Batch 1)            ✅ DONE
         |
         v
Sub-project 3 (Migration Batch 2)            ✅ DONE (171 files)
         |
         v (all tests use raw, fork unused)
Sub-project 4 (Fork Removal)                 ← NEXT
         |
         v (clean codebase, no fork artifacts)
Sub-project 5 (Test Quality Audit)
```

Sequential: each depends on the previous.
Fork removal runs before quality audit so the audit sees a clean
codebase without fork artifacts (submodule, dead imports, stale docs).
Quality audit then runs on the final clean state.

## Progress Tracking

After each sub-project, update this section:

- [x] Sub-project 1: Raw Layer Completion (2026-03-25: all recipes, packers, helpers)
- [x] Sub-project 2: Test Migration Batch 1 (2026-03-25: 10 files, 107 tests, 0 fork imports)
- [x] Sub-project 3: Test Migration Batch 2 (2026-03-26: 171 files, 34 commits, 0 fork imports)
- [x] Sub-project 4: Fork Removal (2026-03-26: submodule removed, zero fork imports, all tests passing)
- [ ] Sub-project 5: Test Quality Audit

# pkcs11-check Deep Audit Implementation Plan

> **For agentic workers:** This plan is designed for ralph-loop autonomous execution. Each task is one audit iteration. Execute tasks sequentially (Task 0 first, then 1-42). Each task is self-contained — read the task, execute all steps, commit, move to next.

**Goal:** Comprehensive audit of pkcs11-check against OASIS PKCS#11 v3.2 specs — fixing quality issues, correctness bugs, and coverage gaps across all 220+ test files and 480 mechanisms.

**Architecture:** Each iteration loads a component's source + test files, cross-references against the relevant OASIS spec markdown files at `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/`, identifies issues and gaps, applies fixes, writes new tests following existing patterns, writes an audit report, and commits.

**Tech Stack:** Python 3.13+, pytest, ctypes (PKCS#11 raw bindings), ruff, mypy --strict

**Spec:** `docs/superpowers/specs/2026-04-01-deep-audit-design.md`

---

## Key Paths

| Resource | Path |
|----------|------|
| OASIS specs | `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/` |
| PKCS#11 v3.2 header | `third_party/pkcs11-headers/3.2/pkcs11.h` |
| Testcases root | `src/pkcs11_check/testcases/` |
| Raw bindings | `src/pkcs11_check/raw/` |
| Core infrastructure | `src/pkcs11_check/core/` |
| Mechanism registry | `src/pkcs11_check/testcases/mechanism_registry/` |
| Audit reports output | `docs/audit/` |

## Project Rules (from CLAUDE.md — apply to ALL tasks)

- **NEVER skip, disable, or suppress real failures or crashes.** A segfault IS the finding.
- **NEVER use bare `except Exception: pass`** — every CKR check must list SPECIFIC acceptable return codes.
- PIN values are never logged, printed, or included in error messages.
- Type annotations on all public functions (mypy strict). Line length: 100. `ruff` for formatting.
- Tests expecting crashes MUST run in subprocess via `subprocess.run([sys.executable, "-c", script])`.
- Use `uv run` prefix for all tool invocations.
- Commit to `dev` branch. Never merge to `main`.

## Report Template

Every iteration writes `docs/audit/NN-component-name.md` using this structure:

```markdown
# Audit NN: Component Name

**Date:** YYYY-MM-DD
**OASIS specs referenced:** list of .md files read
**Files audited:** list of files read

## Findings

### Quality Issues
- [FIXED] Description — file:line — what was wrong and what was changed
- [NOTED] Description — file:line — documented for future attention

### Spec Deviations
- [FIXED] Description — spec requirement vs actual behavior
- [NOTED] Description — spec section that has no test coverage

### Coverage Gaps
- [ADDED] test_name — new test file/class/method added
- [GAP] Description — gap identified but not implemented (explain why)

## Changes Made
- Modified: file.py — description
- Created: file.py — description

## Statistics
- Files audited: N
- Issues found: N (N fixed, N noted)
- Tests added: N
- Lines changed: +N/-N
```

---

## Task 0: Pre-Audit Setup

**Files:**
- Create: `docs/audit/` directory

- [ ] **Step 1: Verify clean working tree**

```bash
git status
```

Expected: On branch `dev`, no uncommitted changes.

- [ ] **Step 2: Create audit output directory**

```bash
mkdir -p docs/audit
```

- [ ] **Step 3: Verify OASIS specs accessible**

```bash
ls /home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/*.md | wc -l
```

Expected: 118 files.

- [ ] **Step 4: Run baseline meta-tests**

```bash
uv run python -m pytest tests/ -x -q 2>&1 | tail -5
```

Record pass/fail counts as baseline.

- [ ] **Step 5: Commit setup**

```bash
git add docs/audit/
git commit -m "audit(00): create audit output directory"
```

---

## Task 1: Code Quality Sweep

**Files:**
- Modify: `src/pkcs11_check/testcases/test_subprocess_safety.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_multipart.py`
- Modify: `src/pkcs11_check/testcases/ckr/_ctypes_raw.py`
- Modify: `src/pkcs11_check/testcases/test_tls12.py`
- Modify: `src/pkcs11_check/testcases/test_mech_state.py`
- Audit: all files in `src/pkcs11_check/core/`, `src/pkcs11_check/` (root modules)
- Create: `docs/audit/01-code-quality.md`

- [ ] **Step 1: Fix known bare except**

Read `src/pkcs11_check/testcases/test_subprocess_safety.py` around line 98. Replace bare `except: pass` with a specific exception type (at minimum `except Exception:` with a comment, or better, the specific expected exception).

- [ ] **Step 2: Fix hardcoded hex CKR values**

Search and fix these patterns:

```bash
# Find all hardcoded hex CKR comparisons
grep -rn '0x191\|0x00000191' src/pkcs11_check/testcases/
grep -rn '0x69\b' src/pkcs11_check/testcases/
grep -rn '== 0x' src/pkcs11_check/testcases/ | grep -v types_std | grep -v '# hex'
```

Replace each with the symbolic constant from `pkcs11_check.raw.types_std`:
- `0x191` / `0x00000191` -> `CKR_CRYPTOKI_ALREADY_INITIALIZED`
- `0x69` -> look up in `types_std.py` what CKR code `0x69` maps to, import and use it

- [ ] **Step 3: Audit all except blocks in testcases/**

```bash
grep -rn 'except Exception' src/pkcs11_check/testcases/ | grep -v '# noqa'
grep -rn 'except:' src/pkcs11_check/testcases/
```

For each result:
- If it's a cleanup block (in `finally` or after `destroy_quietly`), add a comment explaining why broad catch is acceptable
- If it catches CKR errors, replace with specific CKR code tuple checks
- If it silently passes (`except Exception: pass`), add at minimum a descriptive comment or replace with specific exception

- [ ] **Step 4: Audit except blocks in core/ and root modules**

```bash
grep -rn 'except Exception' src/pkcs11_check/core/ src/pkcs11_check/plugin.py src/pkcs11_check/compliance_report.py src/pkcs11_check/fixtures.py
```

For infrastructure code (not testcases), broad `except Exception` may be justified for resilience. Verify each:
- Has a descriptive log/message (not silent)
- Does not hide PKCS#11 module bugs
- Is commented if the catch-all is intentional

- [ ] **Step 5: Check for PIN leaks**

```bash
grep -rn 'pin' src/pkcs11_check/ --include='*.py' | grep -i 'print\|log\|str(.*pin\|f".*pin\|format.*pin' | grep -v 'test_pin\|pin_len\|spinning\|pinning'
```

Verify no PIN values appear in log output, error messages, or string formatting.

- [ ] **Step 6: Write report and commit**

Write `docs/audit/01-code-quality.md` following the report template. Include every fix made and every issue noted.

```bash
git add -A src/pkcs11_check/ docs/audit/01-code-quality.md
git commit -m "audit(01): code quality sweep — fix bare excepts, hardcoded hex CKR values"
```

---

## Task 2: Raw Bindings Parity

**Files:**
- Audit: `src/pkcs11_check/raw/types_std.py`, `raw/metadata_std.py`, `raw/pack.py`, `raw/pack_mechanisms.py`, `raw/extensions.py`, `raw/attr_metadata.py`
- Reference: `third_party/pkcs11-headers/3.2/pkcs11.h`
- OASIS specs: `general_data_types.md`, `conventions_for_functions_output.md`
- Create: `docs/audit/02-raw-bindings.md`

- [ ] **Step 1: Diff CKM_* constants**

Read `third_party/pkcs11-headers/3.2/pkcs11.h` and extract all `#define CKM_*` values. Compare against `CKM_*` in `src/pkcs11_check/raw/types_std.py`. Report any missing or mismatched values.

```bash
grep -c '^CKM_' src/pkcs11_check/raw/types_std.py
grep -c '#define CKM_' third_party/pkcs11-headers/3.2/pkcs11.h
```

- [ ] **Step 2: Diff CKA_* constants**

Same approach for CKA_* attribute constants.

```bash
grep -c '^CKA_' src/pkcs11_check/raw/types_std.py
grep -c '#define CKA_' third_party/pkcs11-headers/3.2/pkcs11.h
```

- [ ] **Step 3: Verify CK_*_PARAMS structures**

Read `raw/pack.py` and `raw/pack_mechanisms.py`. For each `CK_*_PARAMS` structure packed, verify field names and types match the header definition. Cross-ref against `general_data_types.md` from OASIS spec.

- [ ] **Step 4: Check metadata function signatures**

Read `raw/metadata_std.py` function signature table. Verify against header prototypes (parameter count, types).

- [ ] **Step 5: Verify extensions registry**

Read `raw/extensions.py`. Verify all v3.0+, v3.1+, v3.2+ functions are registered. Cross-ref against header `#define CKF_INTERFACE_*` and function tables.

- [ ] **Step 6: Audit attr_metadata.py**

Read `raw/attr_metadata.py`. Cross-ref attribute type mappings against OASIS spec attribute tables (in `common_attributes.md`, `key_objects.md`, etc.).

- [ ] **Step 7: Fix any discrepancies found, write report, commit**

```bash
git add -A src/pkcs11_check/raw/ docs/audit/02-raw-bindings.md
git commit -m "audit(02): raw bindings parity — verify types, metadata, pack against v3.2 header"
```

---

## Task 3: Infrastructure Audit

**Files:**
- Audit: `src/pkcs11_check/plugin.py`, `fixtures.py`, `raw_fixtures.py`, `config.py`, `markers.py`
- Audit: `src/pkcs11_check/testcases/conftest.py`
- Audit: `src/pkcs11_check/core/collection.py`, `core/test_selection.py`, `testcases/mechanism_selection.py`
- OASIS specs: `general_purpose_functions.md`
- Create: `docs/audit/03-infrastructure.md`

- [ ] **Step 1: Audit session fixture**

Read `src/pkcs11_check/fixtures.py` and `raw_fixtures.py`. Verify:
- Login/logout per test in all code paths
- Session handle cleanup in error paths (no leaks)
- `CKR_USER_ALREADY_LOGGED_IN` handling
- `CKR_USER_TYPE_INVALID` (NSS quirk) handling
- `close_session_quietly` in all finally blocks

- [ ] **Step 2: Audit markers**

Read `src/pkcs11_check/markers.py`. List all defined markers. Cross-ref against v3.2 spec capabilities — verify `requires_v30`, `requires_v32`, etc. exist for all version-gated features.

- [ ] **Step 3: Audit mechanism selection**

Read `src/pkcs11_check/testcases/mechanism_selection.py`. Verify scenario flags (ENCRYPT, SIGN, WRAP, DERIVE, etc.) match OASIS spec mechanism flag definitions.

- [ ] **Step 4: Audit config precedence**

Read `src/pkcs11_check/config.py`. Verify CLI > env > TOML > defaults precedence is correctly implemented for all options.

- [ ] **Step 5: Audit conftest helpers**

Read `src/pkcs11_check/testcases/conftest.py`. Verify helper functions:
- `skip_unless_mechanism()` — correctly checks mechanism availability
- `xfail_if_known_ckr()` — only xfails on specified CKR codes, re-raises others
- `get_pin_bytes()` — handles None correctly

- [ ] **Step 6: Fix issues, write report, commit**

```bash
git add -A src/pkcs11_check/ docs/audit/03-infrastructure.md
git commit -m "audit(03): infrastructure audit — fixtures, markers, config, mechanism selection"
```

---

## Tasks 4-42: Audit Iterations

Each follows the same procedure. Below are the iteration-specific inputs.

### Procedure for Each Task N (4-41)

For each audit iteration, follow these steps exactly:

- [ ] **Step 1: Read all target files**

Read every file listed in the spec's "Target files" for this iteration. Note file sizes, structure, existing test classes.

- [ ] **Step 2: Read OASIS spec files**

Read every OASIS spec file listed for this iteration from `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/`. Extract:
- Required parameters and their valid ranges
- Expected behaviors and return codes
- Edge cases and error conditions
- Mandatory vs optional features

- [ ] **Step 3: Quality scan**

Run these searches scoped to the target files:

```bash
grep -n 'except Exception\|except:' <target_files>
grep -n '0x[0-9a-fA-F]' <target_files> | grep -v 'types_std\|# hex\|0x00\b'
grep -n 'pass$' <target_files>
grep -n 'TODO\|FIXME\|HACK\|XXX' <target_files>
```

Fix each issue following CLAUDE.md rules.

- [ ] **Step 4: Spec cross-reference**

For each mechanism/operation tested in the target files:
1. Verify parameter values match spec (IV sizes, key sizes, output sizes, tag lengths)
2. Verify expected return codes match spec error tables
3. Verify test assertions match spec-defined behavior
4. Note any spec requirements not exercised by tests

- [ ] **Step 5: Coverage gap analysis**

Identify:
- Mechanisms defined in spec but not tested
- Parameter combinations not exercised (e.g., different key sizes, different hash algorithms)
- Missing negative tests (invalid parameters that should return specific CKR codes)
- Missing multipart operation tests
- Missing edge cases described in spec

- [ ] **Step 6: Implement fixes and new tests**

Follow existing patterns:
- Import types from `pkcs11_check.raw.types_std`
- Use `gen_aes_key`, `gen_rsa_keypair`, etc. from `pkcs11_check.raw.recipes`
- Use `destroy_quietly` in finally blocks
- Use `rs.has_mechanism()` for skip checks
- Use `@pytest.mark` decorators matching existing conventions
- Use predefined `_ERROR_TUPLES` from `_error_tuples.py` for CKR checks

- [ ] **Step 7: Verify changes**

```bash
uv run ruff check <modified_files>
uv run ruff format --check <modified_files>
```

- [ ] **Step 8: Write report**

Write `docs/audit/NN-component-name.md` following the report template.

- [ ] **Step 9: Commit**

```bash
git add -A src/pkcs11_check/ docs/audit/NN-component-name.md
git commit -m "audit(NN): component-name — summary of changes"
```

---

### Task 4: AES Core Modes

**Iteration-specific inputs:**

**Target files:**
- `src/pkcs11_check/testcases/test_encrypt.py`
- `src/pkcs11_check/testcases/test_aes_modes.py`
- `src/pkcs11_check/testcases/test_aes_key_sizes.py`
- `src/pkcs11_check/testcases/test_buffers.py`
- `src/pkcs11_check/testcases/acvp/aes/test_other.py`
- `src/pkcs11_check/testcases/mechanism_registry/_aes.py`

**OASIS specs:**
- `aes.md`
- `aes_with_counter.md`
- `aes_cbc_with_ciphertext_stealing_cts.md`
- `additional_aes_mechanisms.md`
- `aes_xts.md`
- `general_block_cipher_mechanism_parameters.md`

**Focus areas:**
- CS1/CS3 variant detection in `test_other.py`
- `ulCounterBits` range validation (spec: 0 < value <= 128)
- IV length enforcement per mode (ECB=none, CBC/OFB/CFB=16, CTR=16, XTS=16)
- CBC-PAD vs CBC padding behavior
- XTS tweak value handling

**Report file:** `docs/audit/04-aes-core-modes.md`
**Commit:** `audit(04): AES core modes — spec cross-ref and coverage gaps`

---

### Task 5: AES ACVP Vector Audit

**Target files:**
- `src/pkcs11_check/testcases/acvp/aes/test_cfb.py`
- `src/pkcs11_check/testcases/acvp/aes/test_gcm.py`
- `src/pkcs11_check/testcases/acvp/aes/test_ccm.py`
- `src/pkcs11_check/testcases/acvp/aes/test_other.py`
- `src/pkcs11_check/testcases/acvp/aes/test_wrap.py`
- `src/pkcs11_check/testcases/acvp/aes/base_loader.py`
- `src/pkcs11_check/testcases/acvp/aes/base.py`
- `src/pkcs11_check/testcases/acvp/aes/base_runner_aead.py`
- `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py`
- `src/pkcs11_check/testcases/mechanism_registry/_aes.py`
- `src/pkcs11_check/testcases/mechanism_helpers.py`

**OASIS specs:** AES mechanism specs (same as Task 4)

**Known consistency issues to fix:**
- CCM `nonce_len` default: `_aes.py:259` uses 7, `test_ccm.py:70,146` defaults to 13 — reconcile
- `mechanism_helpers.py:702` CCM `tag_bits` double-conversion risk
- GCM tag lengths: verify spec-allowed values (4/8/12/13/14/15/16 bytes)
- CCM nonce constraints: 7-13 bytes per spec

**Report file:** `docs/audit/05-aes-acvp-vectors.md`
**Commit:** `audit(05): AES ACVP vectors — fix CCM nonce defaults, verify vector coverage`

---

### Task 6: DES/3DES

**Target files:**
- `src/pkcs11_check/testcases/test_des.py`
- `src/pkcs11_check/testcases/mechanism_registry/_des.py`

**OASIS specs:** `double_and_triple-length_des.md`, `double_and_triple-length_des_cmac.md`

**Focus:** Key parity, weak key detection, DES3-CBC-PAD wrap, deprecation handling.

**Report file:** `docs/audit/06-des.md`
**Commit:** `audit(06): DES/3DES — spec cross-ref and coverage gaps`

---

### Task 7: Other Symmetric Ciphers

**Target files:**
- `src/pkcs11_check/testcases/test_camellia.py`
- `src/pkcs11_check/testcases/test_aria.py`
- `src/pkcs11_check/testcases/test_seed.py`
- `src/pkcs11_check/testcases/test_blowfish.py`
- `src/pkcs11_check/testcases/test_twofish.py`
- `src/pkcs11_check/testcases/test_salsa20.py`
- `src/pkcs11_check/testcases/mechanism_registry/_ciphers.py`

**OASIS specs:** `camellia.md`, `aria.md`, `seed.md`, `blowfish.md`, `twofish.md`, `salsa20.md`, `chacha20.md`, `chacha20_salsa20_poly1305.md`, `key_derivation_by_data_encryption-aria.md`, `key_derivation_by_data_encryption-camelia.md`, `key_derivation_by_data_encryption-seed.md`

**Report file:** `docs/audit/07-other-symmetric.md`
**Commit:** `audit(07): other symmetric ciphers — Camellia, ARIA, SEED, Blowfish, Twofish, Salsa20`

---

### Task 8: AEAD Deep Audit

**Target files:**
- `src/pkcs11_check/testcases/test_aead.py`
- `src/pkcs11_check/testcases/test_authenticated_wrap.py`

**OASIS specs:** `chacha20_salsa20_poly1305.md`, `poly1305.md`

**Focus:** GCM AAD, CCM Adata encoding, tag verification failure behavior, Poly1305 standalone, authenticated wrap (v3.2).

**Report file:** `docs/audit/08-aead.md`
**Commit:** `audit(08): AEAD — GCM/CCM/ChaCha20-Poly1305 spec cross-ref`

---

### Task 9: Hash Functions

**Target files:**
- `src/pkcs11_check/testcases/test_digest.py`
- `src/pkcs11_check/testcases/test_sha3.py`
- `src/pkcs11_check/testcases/test_blake2.py`
- `src/pkcs11_check/testcases/test_mech_digest.py`
- `src/pkcs11_check/testcases/mechanism_registry/_hash.py`

**OASIS specs:** `digests.md`, `message_digesting_functions.md`

**Focus:** SHAKE-128/256 XOF via `C_DigestXof` (currently TODO), BLAKE2 params, multipart streaming, `C_DigestKey`.

**Report file:** `docs/audit/09-hash-functions.md`
**Commit:** `audit(09): hash functions — SHAKE XOF, BLAKE2, multipart digest`

---

### Task 10: MAC Operations

**Target files:**
- `src/pkcs11_check/testcases/test_mech_sign.py`
- `src/pkcs11_check/testcases/mechanism_registry/_hmac.py`

**OASIS specs:** `hmac_mechanisms.md`, `hash_based_message_authentication_codes.md`, `aes_cmac.md`, `kmac.md`, `poly1305.md`

**Focus:** HMAC key size constraints, HMAC_GENERAL truncation, KMAC-128/256 tests, CMAC/GMAC.

**Report file:** `docs/audit/10-mac-operations.md`
**Commit:** `audit(10): MAC operations — HMAC/CMAC/GMAC/KMAC spec cross-ref`

---

### Task 11: ACVP Hash/HMAC Audit

**Target files:**
- `src/pkcs11_check/testcases/acvp/test_acvp_hash.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_hmac.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_sha3.py`

**Focus:** Verify no dropped ACVP groups, Monte Carlo correctness, large-message handling.

**Report file:** `docs/audit/11-acvp-hash-hmac.md`
**Commit:** `audit(11): ACVP hash/HMAC — vector coverage verification`

---

### Task 12: RSA Operations

**Target files:**
- `src/pkcs11_check/testcases/test_rsa_extended.py`
- `src/pkcs11_check/testcases/test_rsa_oaep.py`
- `src/pkcs11_check/testcases/test_rsa_key_import.py`
- `src/pkcs11_check/testcases/test_rsa_key_wrapping.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_rsa_keygen.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa*.py`
- `src/pkcs11_check/testcases/mechanism_registry/_rsa.py`

**OASIS specs:** `rsa.md`

**Known issues:** Hardcoded 256-byte output sizes at `test_rsa_extended.py:185,295,320,589`.

**Report file:** `docs/audit/12-rsa.md`
**Commit:** `audit(12): RSA — fix hardcoded sizes, PSS/OAEP spec cross-ref`

---

### Task 13: EC/ECDSA

**Target files:**
- `src/pkcs11_check/testcases/test_ec_curves.py`
- `src/pkcs11_check/testcases/test_ecdsa_extended.py`
- `src/pkcs11_check/testcases/test_ec_import_export.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
- `src/pkcs11_check/testcases/mechanism_registry/_ec.py`

**OASIS specs:** `elliptic_curves.md`

**Report file:** `docs/audit/13-ec-ecdsa.md`
**Commit:** `audit(13): EC/ECDSA — curve OIDs, point encoding, signature format`

---

### Task 14: ECDH/X25519/X448

**Target files:**
- `src/pkcs11_check/testcases/test_ecdh_extended.py`
- `src/pkcs11_check/testcases/test_ecdh_known_answer.py`
- `src/pkcs11_check/testcases/test_dh_key_agreement.py`
- `src/pkcs11_check/testcases/test_x942_dh.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py`

**OASIS specs:** `elliptic_curves.md`, `diffie-hellman.md`

**Report file:** `docs/audit/14-ecdh-x25519.md`
**Commit:** `audit(14): ECDH/X25519/X448 — derive params, cofactor, KDF chaining`

---

### Task 15: EdDSA

**Target files:**
- `src/pkcs11_check/testcases/test_eddsa.py`
- `src/pkcs11_check/testcases/test_cctv_ed25519.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py`

**OASIS specs:** `elliptic_curves.md` (EdDSA section)

**Report file:** `docs/audit/15-eddsa.md`
**Commit:** `audit(15): EdDSA — Ed25519/Ed448 params, pre-hash, signature format`

---

### Task 16: DSA/DH

**Target files:**
- `src/pkcs11_check/testcases/test_dsa_complete.py`
- `src/pkcs11_check/testcases/test_dh_key_agreement.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py`
- `src/pkcs11_check/testcases/mechanism_registry/_dsa_dh.py`

**OASIS specs:** `dsa.md`, `diffie-hellman.md`, `extended_triple_diffie-hellman.md`

**Report file:** `docs/audit/16-dsa-dh.md`
**Commit:** `audit(16): DSA/DH — parameter generation, X3DH spec cross-ref`

---

### Task 17: ML-KEM & ML-DSA

**Target files:**
- `src/pkcs11_check/testcases/test_kem.py`
- `src/pkcs11_check/testcases/test_pqc_sign.py`
- `src/pkcs11_check/testcases/test_mech_kem.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_mlkem.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa*.py`
- `src/pkcs11_check/testcases/mechanism_registry/_pqc.py`

**OASIS specs:** `ml-kem.md`, `ml_dsa.md`

**Focus:** CK_SIGN_ADDITIONAL_CONTEXT TODO, parameter set handling, shared secret sizes.

**Report file:** `docs/audit/17-ml-kem-ml-dsa.md`
**Commit:** `audit(17): ML-KEM/ML-DSA — parameter sets, ACVP vectors, context params`

---

### Task 18: SLH-DSA

**Target files:**
- `src/pkcs11_check/testcases/test_pqc_sign.py`
- `src/pkcs11_check/testcases/test_hash_slh_dsa.py`
- `src/pkcs11_check/testcases/acvp/test_acvp_slhdsa.py`

**OASIS specs:** `slh-dsa.md`

**Report file:** `docs/audit/18-slh-dsa.md`
**Commit:** `audit(18): SLH-DSA — parameter sets, signature sizes, ACVP completeness`

---

### Task 19: Key Lifecycle

**Target files:**
- `src/pkcs11_check/testcases/test_keymgmt.py`
- `src/pkcs11_check/testcases/test_key_lifecycle.py`
- `src/pkcs11_check/testcases/test_key_flags.py`
- `src/pkcs11_check/testcases/test_key_sizes.py`
- `src/pkcs11_check/testcases/test_key_usage_policy.py`
- `src/pkcs11_check/testcases/test_sensitivity.py`
- `src/pkcs11_check/testcases/test_handle_reuse.py`

**OASIS specs:** `key_objects.md`, `private_key_objects.md`, `public_key_objects.md`, `secret_key_objects.md`, `key_management_functions.md`

**Report file:** `docs/audit/19-key-lifecycle.md`
**Commit:** `audit(19): key lifecycle — attribute transitions, Tookan mitigations`

---

### Task 20: KDF Operations

**Target files:**
- `src/pkcs11_check/testcases/test_kdf.py`
- `src/pkcs11_check/testcases/test_misc_kdf.py`
- `src/pkcs11_check/testcases/test_sp800_108_kdf.py`
- `src/pkcs11_check/testcases/test_hkdf_extended.py`
- `src/pkcs11_check/testcases/test_pbe.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py`
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py`
- `src/pkcs11_check/testcases/mechanism_registry/_kdf.py`

**OASIS specs:** `hash_based_key_derivations.md`, `hkdf_mechanisms.md`, `sp800-108_key_derivation.md`, `miscellaneous_simple_key_derivation_mechanisms.md`, `password-based_encryption.md`, `pkcs12_password-based_encryption-authentication.md`, `key_derivation_by_data_encryption_aes-des.md`

**Focus:** SHA3-based KDF key derivation (currently untested), PBKDF2 iteration count, SP800-108 modes, PBE mechanism coverage.

**Report file:** `docs/audit/20-kdf-operations.md`
**Commit:** `audit(20): KDF operations — HKDF, PBKDF2, SP800-108, PBE spec cross-ref`

---

### Task 21: Key Wrapping

**Target files:**
- `src/pkcs11_check/testcases/test_mech_wrap.py`
- `src/pkcs11_check/testcases/test_authenticated_wrap.py`
- `src/pkcs11_check/testcases/test_rsa_key_wrapping.py`
- `src/pkcs11_check/testcases/acvp/aes/test_wrap.py`

**OASIS specs:** `aes_key_wrap.md`, `wrapping-unwrapping_private_keys.md`

**Report file:** `docs/audit/21-key-wrapping.md`
**Commit:** `audit(21): key wrapping — AES-KW/KWP, RSA wrap, authenticated wrap`

---

### Task 22: Session Management

**Target files:**
- `src/pkcs11_check/testcases/test_session_edge_cases.py`
- `src/pkcs11_check/testcases/test_session_exhaustion.py`
- `src/pkcs11_check/testcases/test_session_info.py`
- `src/pkcs11_check/testcases/test_session_state_machine.py`
- `src/pkcs11_check/testcases/test_session_validation_flags.py`
- `src/pkcs11_check/testcases/test_concurrent_sessions.py`
- `src/pkcs11_check/testcases/test_v30_session.py`
- `src/pkcs11_check/testcases/test_ro_session.py`
- `src/pkcs11_check/testcases/test_ro_session_restrictions.py`

**OASIS specs:** `session_mgmt_functions.md`, `callback_functions.md`

**Report file:** `docs/audit/22-session-management.md`
**Commit:** `audit(22): session management — state machine, R/O restrictions, callbacks`

---

### Task 23: Object Management

**Target files:**
- `src/pkcs11_check/testcases/test_object.py`
- `src/pkcs11_check/testcases/test_object_search_patterns.py`
- `src/pkcs11_check/testcases/test_object_size.py`
- `src/pkcs11_check/testcases/test_object_visibility.py`
- `src/pkcs11_check/testcases/test_search.py`
- `src/pkcs11_check/testcases/test_data_objects.py`
- `src/pkcs11_check/testcases/test_token_objects.py`
- `src/pkcs11_check/testcases/test_validation_objects.py`
- `src/pkcs11_check/testcases/test_set_attribute.py`
- `src/pkcs11_check/testcases/test_attribute_defaults.py`
- `src/pkcs11_check/testcases/test_attribute_enforcement.py`

**OASIS specs:** `objects.md`, `object_classification.md`, `creating_objects.md`, `object_mgmt_functions.md`, `common_attributes.md`, `storage_objects.md`

**Report file:** `docs/audit/23-object-management.md`
**Commit:** `audit(23): object management — attributes, search, visibility, creation rules`

---

### Task 24: Token & PIN Management

**Target files:**
- `src/pkcs11_check/testcases/test_pin.py`
- `src/pkcs11_check/testcases/test_so_pin.py`
- `src/pkcs11_check/testcases/test_token_flags.py`
- `src/pkcs11_check/testcases/test_init.py`

**OASIS specs:** `slot_and_token_mgmt_functions.md`

**Report file:** `docs/audit/24-token-pin.md`
**Commit:** `audit(24): token & PIN — InitToken, InitPIN, SetPIN, SO/USER separation`

---

### Task 25: Message-Based API

**Target files:**
- `src/pkcs11_check/testcases/test_message_crypto.py`
- `src/pkcs11_check/testcases/test_mech_message.py`

**OASIS specs:** `message_based_encryption_functions.md`, `message_based_decryption_functions.md`, `message-based_signing_and_macing_functions.md`, `message-based_functions_for_verifying_signatures_and_macs.md`

**Report file:** `docs/audit/25-message-api.md`
**Commit:** `audit(25): message-based API — encrypt/decrypt/sign/verify message ops`

---

### Task 26: Protocol Operations

**Target files:**
- `src/pkcs11_check/testcases/test_tls12.py`
- `src/pkcs11_check/testcases/test_ssl3.py`
- `src/pkcs11_check/testcases/test_wtls.py`
- `src/pkcs11_check/testcases/test_ike.py`
- `src/pkcs11_check/testcases/test_x942_dh.py`
- `src/pkcs11_check/testcases/test_x3dh.py`
- `src/pkcs11_check/testcases/test_double_ratchet.py`
- `src/pkcs11_check/testcases/test_protocol_edge_cases.py`

**OASIS specs:** `tls_1.2_mechanisms.md`, `ssl.md`, `wtls.md`, `ike_mechanisms.md`, `double_ratchet.md`, `ct-kip.md`

**Known issue:** Fix hardcoded `0x69` in `test_tls12.py:922,971`.

**Report file:** `docs/audit/26-protocol-operations.md`
**Commit:** `audit(26): protocol operations — TLS/SSL/WTLS/IKE/X3DH spec cross-ref`

---

### Task 27: Async & Operation State

**Target files:**
- `src/pkcs11_check/testcases/test_operation_state.py`
- `src/pkcs11_check/testcases/test_remaining_gaps.py`

**OASIS specs:** `asynchronous_function_management_functions.md`, `parallel_function_management_functions.md`

**Focus:** Implement async lifecycle test (TODO at `test_remaining_gaps.py:409`), operation state save/restore, `C_SessionCancel`.

**Report file:** `docs/audit/27-async-opstate.md`
**Commit:** `audit(27): async & operation state — implement lifecycle test, state portability`

---

### Task 28: Security Audit

**Target files:**
- `src/pkcs11_check/testcases/test_padding_oracle.py`
- `src/pkcs11_check/testcases/test_nonce_quality.py`
- `src/pkcs11_check/testcases/test_tookan.py`
- `src/pkcs11_check/testcases/test_api_security.py`
- `src/pkcs11_check/testcases/test_fuzz.py`
- `src/pkcs11_check/testcases/test_attribute_fuzz.py`
- `src/pkcs11_check/testcases/test_mechanism_fuzz.py`
- `src/pkcs11_check/testcases/test_cve_regression.py`
- `docs/cve-regression.md`

**OASIS specs:** `security_and_privacy_considerations.md`, `random_number_generation_functions.md`

**Report file:** `docs/audit/28-security.md`
**Commit:** `audit(28): security — padding oracle, nonce quality, Tookan, CVE regression`

---

### Task 29: CKR Compliance

**Target files:**
- All 30 files in `src/pkcs11_check/testcases/ckr/`
- `src/pkcs11_check/testcases/ckr/_ckr_spec.py`

**OASIS specs:** `function_return_values.md`, plus error tables from each mechanism spec

**Report file:** `docs/audit/29-ckr-compliance.md`
**Commit:** `audit(29): CKR compliance — return code spec cross-ref, error priority`

---

### Task 30: X.509 Certificate Handling

**Target files:**
- All 8 files in `src/pkcs11_check/testcases/x509/`

**OASIS specs:** `certificate_objects.md`

**Report file:** `docs/audit/30-x509-certificates.md`
**Commit:** `audit(30): X.509 certificates — attributes, lifecycle, search, Limbo vectors`

---

### Task 31: Trust, Profile, HW, Validation & Data Objects

**Target files:**
- `src/pkcs11_check/testcases/test_trust_objects.py`
- `src/pkcs11_check/testcases/test_profiles.py`
- `src/pkcs11_check/testcases/test_hw_features.py`
- `src/pkcs11_check/testcases/test_validation_objects.py`
- `src/pkcs11_check/testcases/test_data_objects.py`
- `src/pkcs11_check/testcases/test_large_objects.py`
- `src/pkcs11_check/testcases/test_generic_secret.py`

**OASIS specs:** `trust_objects.md`, `profile_objects.md`, `hardware_feature_objects.md`, `validation_objects.md`, `data_objects.md`, `generic_secret_key.md`

**Report file:** `docs/audit/31-object-types.md`
**Commit:** `audit(31): object types — trust, profile, HW, validation, data, generic secret`

---

### Task 32: OTP, CT-KIP & CMS

**Target files:**
- `src/pkcs11_check/testcases/test_otp.py`
- `src/pkcs11_check/testcases/test_cms.py`

**OASIS specs:** `otp_mechanisms.md`, `otp_key_objects.md`, `ct-kip.md`, `cms_mechanisms.md`

**Report file:** `docs/audit/32-otp-cms.md`
**Commit:** `audit(32): OTP/CT-KIP/CMS — mechanism and key object spec cross-ref`

---

### Task 33: GOST Cryptography

**Target files:**
- `src/pkcs11_check/testcases/test_gost.py`
- `src/pkcs11_check/testcases/mechanism_registry/_misc.py`

**OASIS specs:** `gost_28147-89.md`, `gost_r_34.10-2001.md`, `gost_r_34.11-94.md`

**Report file:** `docs/audit/33-gost.md`
**Commit:** `audit(33): GOST — 28147-89 cipher, R 34.10 signature, R 34.11 hash`

---

### Task 34: Legacy Ciphers

**Target files:**
- `src/pkcs11_check/testcases/mechanism_registry/_legacy.py`
- `src/pkcs11_check/testcases/test_remaining_gaps.py`

**Focus:** 82 registered legacy mechanisms (RC2/4/5, CAST, IDEA, CDMF, Skipjack, BATON, JUNIPER, KEA). Verify constants, add smoke tests for any module-supported mechanisms, document deprecation status.

**Report file:** `docs/audit/34-legacy-ciphers.md`
**Commit:** `audit(34): legacy ciphers — RC, CAST, IDEA, CDMF, Skipjack smoke tests`

---

### Task 35: Interoperability & Cross-Verification

**Target files:**
- `src/pkcs11_check/testcases/test_interop.py`
- `src/pkcs11_check/testcases/test_interop_openssl.py`
- `src/pkcs11_check/testcases/test_crossverify.py`
- `src/pkcs11_check/testcases/test_crossverify_extended.py`
- `src/pkcs11_check/testcases/test_metamorphic.py`

**Report file:** `docs/audit/35-interop-crossverify.md`
**Commit:** `audit(35): interop & cross-verify — OpenSSL, metamorphic, PQC cross-verify`

---

### Task 36: Multipart, Dual-Function & Stateful Operations

**Target files:**
- `src/pkcs11_check/testcases/test_multipart.py`
- `src/pkcs11_check/testcases/test_multipart_streaming.py`
- `src/pkcs11_check/testcases/test_dual_function.py`
- `src/pkcs11_check/testcases/test_mech_multipart.py`
- `src/pkcs11_check/testcases/test_mech_state.py`
- `src/pkcs11_check/testcases/test_stateful_sigs.py`

**OASIS specs:** `dual-function_cryptographic_functions.md`, `encryption_functions.md`, `signing_and_macing_functions.md`

**Report file:** `docs/audit/36-multipart-dual.md`
**Commit:** `audit(36): multipart & dual-function — update/final sequences, state machine`

---

### Task 37: Threading, Stress & Resource Exhaustion

**Target files:**
- `src/pkcs11_check/testcases/test_threading.py`
- `src/pkcs11_check/testcases/test_stress.py`
- `src/pkcs11_check/testcases/test_resource.py`
- `src/pkcs11_check/testcases/test_session_exhaustion.py`
- `src/pkcs11_check/testcases/test_benchmark.py`

**Report file:** `docs/audit/37-threading-stress.md`
**Commit:** `audit(37): threading & stress — thread safety, resource limits, benchmarks`

---

### Task 38: Access Control & Visibility

**Target files:**
- `src/pkcs11_check/testcases/test_access.py`
- `src/pkcs11_check/testcases/test_access_control.py`
- `src/pkcs11_check/testcases/test_access_levels.py`
- `src/pkcs11_check/testcases/test_object_visibility.py`
- `src/pkcs11_check/testcases/test_ro_session.py`
- `src/pkcs11_check/testcases/test_ro_session_restrictions.py`

**OASIS specs:** `objects.md`, `session_mgmt_functions.md`

**Report file:** `docs/audit/38-access-control.md`
**Commit:** `audit(38): access control — R/O restrictions, CKA_PRIVATE, visibility rules`

---

### Task 39: HSS/XMSS, Domain Parameters & Mechanism Objects

**Target files:**
- `src/pkcs11_check/testcases/test_domain_params.py`
- `src/pkcs11_check/testcases/test_mechanism.py`
- `src/pkcs11_check/testcases/test_mechanism_objects.py`
- `src/pkcs11_check/testcases/test_remaining_gaps.py`

**OASIS specs:** `hss.md`, `xmss_and_xmss-mt.md`, `domain_parameter_objects.md`, `mechanism_objects.md`

**Report file:** `docs/audit/39-hss-xmss-domain.md`
**Commit:** `audit(39): HSS/XMSS, domain params, mechanism objects`

---

### Task 40: Parameter Consistency Fixes

**Target files:**
- `src/pkcs11_check/testcases/mechanism_registry/_aes.py`
- `src/pkcs11_check/testcases/mechanism_registry/_hash.py`
- `src/pkcs11_check/testcases/mechanism_helpers.py`
- `src/pkcs11_check/testcases/test_mech_digest.py`
- `src/pkcs11_check/testcases/test_mech_multipart.py`
- `src/pkcs11_check/testcases/test_rsa_extended.py`
- `src/pkcs11_check/raw/recipes.py`
- `src/pkcs11_check/raw/pack.py`
- `src/pkcs11_check/raw/pack_mechanisms.py`

**Known issues:**
- CCM `nonce_len` default mismatch (registry=7, ACVP=13) — if not already fixed in Task 5
- Hardcoded RSA 256-byte sizes — if not already fixed in Task 12
- `mechanism_helpers.py:702` CCM tag_bits double-conversion
- SHAKE mechanism IDs hardcoded (`test_mech_digest.py:51-52`, `test_mech_multipart.py:148-149`, `_hash.py:189`)
- 111 `# type: ignore` comments — verify each is justified

**Report file:** `docs/audit/40-parameter-consistency.md`
**Commit:** `audit(40): parameter consistency — reconcile defaults, fix hardcoded values`

---

### Task 41: Surface Audit, Scripts & Tooling

**Target files:**
- `src/pkcs11_check/testcases/test_surface_audit.py`
- `src/pkcs11_check/testcases/test_tool_templates.py`
- `scripts/mechanism-audit.py`
- `scripts/ckr-coverage-check.py`
- `scripts/mechanism_coverage.py`
- `scripts/mechanism-matrix.py`
- `scripts/generate_raw_standard.py`
- `scripts/check_raw_exports.py`

**Report file:** `docs/audit/41-surface-scripts.md`
**Commit:** `audit(41): surface audit & scripts — coverage tools, header parser verification`

---

### Task 42: Final Consolidation

**Files:**
- Create: `docs/audit/00-index.md`
- Audit: all `docs/audit/NN-*.md` reports

- [ ] **Step 1: Generate master index**

Create `docs/audit/00-index.md` with:
- Link to each iteration report
- Summary table: iteration | component | findings | fixes | tests added
- Aggregate statistics

- [ ] **Step 2: Compute coverage delta**

Compare mechanism/function coverage before and after the audit. Use:

```bash
grep -c '\[ADDED\]' docs/audit/*.md
grep -c '\[FIXED\]' docs/audit/*.md
grep -c '\[NOTED\]' docs/audit/*.md
grep -c '\[GAP\]' docs/audit/*.md
```

- [ ] **Step 3: Run meta-tests**

```bash
uv run python -m pytest tests/ -x -q 2>&1 | tail -5
```

Verify no regressions from audit changes.

- [ ] **Step 4: Run ruff and mypy**

```bash
uv run ruff check src/pkcs11_check/
uv run ruff format --check src/pkcs11_check/
```

Fix any issues introduced during audit.

- [ ] **Step 5: List deferred items**

Collect all `[GAP]` entries from all reports into a "Future Work" section of the index.

- [ ] **Step 6: Commit**

```bash
git add docs/audit/
git commit -m "audit(42): consolidation — master index, coverage delta, regression check"
```

---

## Execution Notes

- **Ralph-loop mode:** Execute Task 0, then iterate Tasks 1-42 sequentially. Each task is one ralph-loop cycle.
- **If a task is blocked** (e.g., OASIS spec file missing for a mechanism), document the blocker in the report, mark as `[GAP]`, and move to the next task.
- **If meta-tests fail** after changes, fix the regression before committing. If the fix is non-trivial, note it in the report and revert the breaking change.
- **Commit format:** `audit(NN): component-name — summary` (NN = zero-padded iteration number)
- **Branch:** All work on `dev`. Never merge to `main`.

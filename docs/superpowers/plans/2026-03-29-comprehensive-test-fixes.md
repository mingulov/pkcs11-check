# Comprehensive Test Bug Fixes -- Cross-Provider Analysis

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review and investigation tasks.

**Goal:** Fix all remaining test bugs found via deep analysis of SoftHSM2-main, Kryoptic-main, and NSS-PQC Docker artifacts. Estimated ~2,050 false failures eliminated, plus 3 performance optimizations removing ~180,000 redundant PKCS#11 calls.

**Architecture:** 3 phases: (1) Fix test bugs by priority (6 tasks), (2) Performance optimizations (3 tasks), (3) Docker verification. Each task is independent and can be executed by a Sonnet 4.6 subagent.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw, ctypes

**Analysis sources:** Deep Opus 4.6 audits of artifacts in `/home/user/src/m/pkcs11-check/artifacts/` for softhsm2-main, kryoptic-main, nss-pqc.

---

## Analysis Summary

| Provider | Total Fails | Test Bugs | Module Findings |
|----------|------------|-----------|-----------------|
| SoftHSM2-main | 1,205 | 0 | 1,205 (all genuine) |
| Kryoptic-main | 2,253 | ~1,510 | ~743 |
| NSS-PQC | 1,001 | ~289 | ~712 |
| **Total** | **4,459** | **~1,799** | **~2,660** |

---

## Phase 1: Test Bug Fixes (Tasks 1-6)

### Task 1: Fix PBES2 derive template -- missing CKA_CLASS (Sonnet, -1,260 failures)

**Impact:** Kryoptic: -1,260 failures. Largest single fix remaining.

**Root cause:** `test_wycheproof_pbes2.py` calls `C_GenerateKey` for PBKDF2 with a template missing `CKA_CLASS: CKO_SECRET_KEY`. Kryoptic returns `CKR_TEMPLATE_INCONSISTENT`.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py`

- [ ] **Step 1:** Read the file. Find `_generate_key_with_mech()` or the `C_GenerateKey` call. The template dict has `CKA_KEY_TYPE`, `CKA_VALUE_LEN`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_TOKEN`, `CKA_DECRYPT` -- but no `CKA_CLASS`.

- [ ] **Step 2:** Add `CKA_CLASS: CKO_SECRET_KEY` to the template dict. Add `CKA_CLASS` and `CKO_SECRET_KEY` to imports from `types_std`.

- [ ] **Step 3:** Lint: `uv run ruff check src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py`

- [ ] **Step 4:** Test locally (SoftHSM2 may not support PBKDF2):
```bash
bash local-builds/test.sh softhsm2 -k "test_pbes2" --no-header 2>&1 | tail -3
```

- [ ] **Step 5:** Commit:
```bash
git commit -m 'fix: add CKA_CLASS to PBES2 derive template -- fixes 1260 Kryoptic failures'
```

---

### Task 2: Fix HKDF salt_type auto-selection (Sonnet, -242 failures)

**Impact:** Kryoptic: -236 HKDF Wycheproof + -5 extended + -1 mech = -242 failures. Also fixes 4 xfails.

**Root cause:** `mech_hkdf()` in `pack_mechanisms.py` defaults `salt_type=1` (`CKF_HKDF_SALT_NULL`). When salt data IS provided, the correct value is `salt_type=2` (`CKF_HKDF_SALT_DATA`). Kryoptic correctly rejects the contradictory NULL-type + non-null-pointer with `CKR_MECHANISM_PARAM_INVALID`.

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py` -- fix `mech_hkdf()` default

- [ ] **Step 1:** Read `src/pkcs11_check/raw/pack_mechanisms.py`, find `mech_hkdf()`.

- [ ] **Step 2:** Change the `salt_type` parameter handling. Current code likely has `salt_type: int = 1`. Change to auto-select based on whether salt is provided:

```python
def mech_hkdf(
    mechanism_type: CKM,
    *,
    hash_mech: int,
    extract: bool = True,
    expand: bool = True,
    salt_type: int | None = None,  # None = auto-select
    salt: bytes | None = None,
    info: bytes | None = None,
    prk_len: int = 0,
) -> PackedMechanism:
```

In the body, before setting the struct field:
```python
if salt_type is None:
    salt_type = 2 if salt is not None else 1  # CKF_HKDF_SALT_DATA vs CKF_HKDF_SALT_NULL
```

- [ ] **Step 3:** Check all callers of `mech_hkdf` -- they should work with the new auto-selection:
```bash
grep -rn "mech_hkdf(" src/pkcs11_check/testcases/ | head -15
```
Callers that explicitly pass `salt_type=` will still work (not None). Callers that don't pass it will get auto-selection.

- [ ] **Step 4:** Lint: `uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py`

- [ ] **Step 5:** Commit:
```bash
git commit -m 'fix: auto-select HKDF salt_type based on salt presence'
```

---

### Task 3: Fix ChaCha20-Poly1305 output_overhead (Sonnet, -260 failures)

**Impact:** NSS: -256 ChaCha20 Wycheproof + -4 mech test failures.

**Root cause:** `test_wycheproof_chacha.py` calls `encrypt_single()` without `output_overhead=16` for ChaCha20-Poly1305 AEAD. NSS does not return the required output size during the NULL-buffer size-query pass, causing `CKR_BUFFER_TOO_SMALL`.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py`

- [ ] **Step 1:** Read the file. Find the `encrypt_single()` call.

- [ ] **Step 2:** Add `output_overhead=16` to the encrypt call (16 bytes for Poly1305 auth tag):
```python
ct = encrypt_single(rs.raw, rs.sh, key, CKM_CHACHA20_POLY1305,
                    plaintext, mech_param=mech_param,
                    output_overhead=16)
```

- [ ] **Step 3:** Also check `test_mech_encrypt.py` -- the roundtrip test for CHACHA20_POLY1305 may need the same fix. Read the file, check if `config.auth_tag_included` properly sets overhead for ChaCha20.

- [ ] **Step 4:** Lint and test:
```bash
uv run ruff check src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py
```

- [ ] **Step 5:** Commit:
```bash
git commit -m 'fix: add output_overhead=16 for ChaCha20-Poly1305 AEAD encrypt'
```

---

### Task 4: Fix EC Edwards/Montgomery keygen mechanism (Sonnet, -12 failures)

**Impact:** Kryoptic: -12 failures (mech_attribute + mech_keygen).

**Root cause:** `gen_keypair_for_mech()` in `mechanism_helpers.py` calls `gen_ec_keypair()` which hardcodes `CKM_EC_KEY_PAIR_GEN`. For Edwards keys this needs `CKM_EC_EDWARDS_KEY_PAIR_GEN`; for Montgomery keys this needs `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`. Kryoptic correctly returns `CKR_CURVE_NOT_SUPPORTED` because Ed25519/X25519 curves cannot use the Weierstrass keygen.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py` -- `gen_keypair_for_mech()`

- [ ] **Step 1:** Read `mechanism_helpers.py`, find `gen_keypair_for_mech()`. Find the EC branch that calls `gen_ec_keypair()`.

- [ ] **Step 2:** Add keygen mechanism selection based on `keygen_recipe.style`:
```python
if style == "ec_edwards":
    from pkcs11_check.raw.types_std import CKM_EC_EDWARDS_KEY_PAIR_GEN
    keygen_mech = int(CKM_EC_EDWARDS_KEY_PAIR_GEN)
elif style == "ec_montgomery":
    from pkcs11_check.raw.types_std import CKM_EC_MONTGOMERY_KEY_PAIR_GEN
    keygen_mech = int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN)
else:
    keygen_mech = int(CKM_EC_KEY_PAIR_GEN)
```

Or use `config.keygen_mech` which should already have the correct mechanism. Check if it does.

- [ ] **Step 3:** Test:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_keygen[EC_EDWARDS]" -v --no-header
```

- [ ] **Step 4:** Commit:
```bash
git commit -m 'fix: use correct keygen mechanism for Edwards/Montgomery EC curves'
```

---

### Task 5: Fix wrap test key type dispatch for Camellia/SEED/CDMF (Sonnet, -15 failures)

**Impact:** NSS: -15 failures.

**Root cause:** `test_mech_wrap.py` generates an AES wrapping key for ALL mechanisms in the `else` branch. Camellia needs `CKK_CAMELLIA`, SEED needs `CKK_SEED`, CDMF needs `CKK_CDMF`. Also, `_make_wrap_mech_param()` is missing Camellia/SEED CBC variants in its IV dispatch.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_wrap.py`

- [ ] **Step 1:** Read the file. Find `test_wrap_unwrap_aes_key` and the key generation logic. The `else` branch after RSA/DES/AES should dispatch based on `config.key_type`.

- [ ] **Step 2:** Add key type dispatch:
```python
from pkcs11_check.raw.types_std import CKK_CAMELLIA, CKK_SEED

if kt == int(CKK_CAMELLIA):
    wrap_key = _build_cipher_wrap_key(rs, entry, config, CKK_CAMELLIA, CKM_CAMELLIA_KEY_GEN)
elif kt == int(CKK_SEED):
    wrap_key = _build_cipher_wrap_key(rs, entry, config, CKK_SEED, CKM_SEED_KEY_GEN)
```

Or generalize: use `config.keygen_mech` and `config.key_type` directly from the registry to generate the correct wrapping key.

- [ ] **Step 3:** Add Camellia/SEED CBC modes to `_make_wrap_mech_param()` IV dispatch (16-byte IV, same as AES CBC).

- [ ] **Step 4:** Lint and test.

- [ ] **Step 5:** Commit:
```bash
git commit -m 'fix: dispatch correct wrapping key type for Camellia/SEED/CDMF in wrap test'
```

---

### Task 6: Fix param recipes for ChaCha20 and RC2 mechanisms (Opus, -9 failures)

**Impact:** NSS: -9 failures. Requires adding new param packer styles.

**Root cause:** ChaCha20, ChaCha20-Poly1305, RC2-ECB, RC2-CBC, RC2-CBC-PAD have `param_required=True` but `param_recipe=ParamRecipe("none")` in the registry. The tests need actual mechanism parameters.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py` -- add "chacha20" and "rc2" styles to `build_test_params()`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_ciphers.py` -- fix ChaCha20 param_recipe
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_legacy.py` -- fix RC2 param_recipe
- Possibly modify: `src/pkcs11_check/raw/pack_mechanisms.py` -- add `mech_chacha20_params()` if not exists

- [ ] **Step 1:** Check what param types these mechanisms need:
- ChaCha20: `CK_CHACHA20_PARAMS` (counter + nonce) -- check `types_std.py`
- ChaCha20-Poly1305: `CK_SALSA20_CHACHA20_POLY1305_PARAMS` (nonce + AAD)
- RC2: `CK_RC2_CBC_PARAMS` (effective bits + IV) for CBC; `CK_RC2_PARAMS` (effective bits) for ECB
- Check if packers already exist in `pack_mechanisms.py`

- [ ] **Step 2:** If packers exist, add styles to `build_test_params()`. If not, add them to `pack_mechanisms.py` first.

- [ ] **Step 3:** Update registry entries to use the new styles:
```python
# _ciphers.py
param_recipe=ParamRecipe("chacha20")  # for CKM_CHACHA20
param_recipe=ParamRecipe("chacha20_poly1305")  # for CKM_CHACHA20_POLY1305
# _legacy.py
param_recipe=ParamRecipe("rc2", defaults={"effective_bits": 128})  # for RC2
```

- [ ] **Step 4:** Test and commit:
```bash
git commit -m 'feat: add ChaCha20 and RC2 param recipes for mechanism tests'
```

---

## Phase 2: Performance Optimizations (Tasks 7-9)

### Task 7: Pre-populate RawSession mechanisms from manifest (Sonnet, -128K calls)

**Impact:** Eliminates ~128,968 `C_GetMechanismList` calls per SoftHSM2 run. Each test currently re-queries the mechanism list because `p11_raw_session` is function-scoped and `RawSession._mechanisms` starts as None.

**Root cause:** The preflight manifest already has the full mechanism list (`manifest.mechanisms`). The RawSession could be initialized with it instead of re-querying.

**Files:**
- Modify: `src/pkcs11_check/fixtures.py` -- pass manifest mechanisms to RawSession
- Modify: `src/pkcs11_check/fixtures.py` -- RawSession dataclass to accept pre-built mechanisms

- [ ] **Step 1:** Read `src/pkcs11_check/fixtures.py`. Find how `p11_raw_session` creates `RawSession`. Find how `_ensure_manifest()` is accessed in the plugin.

- [ ] **Step 2:** Add a parameter to RawSession for pre-populated mechanisms:
```python
@dataclass
class RawSession:
    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)
    # Add: allow pre-population
    _pre_mechanisms: frozenset[str] | None = field(default=None, repr=False)
```

In the `mechanisms` property, check `_pre_mechanisms` first:
```python
@property
def mechanisms(self) -> frozenset[str]:
    if self._mechanisms is None:
        if self._pre_mechanisms is not None:
            self._mechanisms = self._pre_mechanisms
        else:
            # existing C_GetMechanismList path
            ...
    return self._mechanisms
```

- [ ] **Step 3:** In the fixture, load the manifest and pass mechanisms:
```python
manifest = _ensure_manifest(config)
if manifest is not None:
    pre_mechs = _build_mechanism_set(manifest.mechanisms)
    yield RawSession(raw, sh, slot_id, _pre_mechanisms=pre_mechs)
```

The `_build_mechanism_set()` helper converts the manifest's mechanism name list to the same frozenset format as `RawSession.mechanisms` (both short "AES_CBC" and full "CKM_AES_CBC" forms).

- [ ] **Step 4:** Verify mechanism count is the same before and after:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_flags[AES_ECB]" -v --no-header
```

- [ ] **Step 5:** Commit:
```bash
git commit -m 'perf: pre-populate RawSession mechanisms from manifest, eliminate 128K C_GetMechanismList calls'
```

---

### Task 8: Cache unsupported EC curves per session (Sonnet, -50K probe calls)

**Impact:** Eliminates ~50,000 redundant `C_CreateObject` probe calls (25K on Kryoptic, 25K on NSS).

**Root cause:** Wycheproof ECDH/ECDSA tests try to import keys on curves the module doesn't support. Each vector triggers a fresh `C_CreateObject` that fails with `CKR_DOMAIN_PARAMS_INVALID`. The same curve fails thousands of times.

**Files:**
- Modify: `src/pkcs11_check/fixtures.py` -- add curve cache to RawSession
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py` -- use cache
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py` -- use cache
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py` -- use cache

- [ ] **Step 1:** Add a `_unsupported_curves` cache to RawSession:
```python
_unsupported_curves: set[str] = field(default_factory=set, repr=False)

def is_curve_unsupported(self, curve_name: str) -> bool:
    return curve_name in self._unsupported_curves

def mark_curve_unsupported(self, curve_name: str) -> None:
    self._unsupported_curves.add(curve_name)
```

- [ ] **Step 2:** In Wycheproof ECDH/ECDSA tests, before attempting key import:
```python
if rs.is_curve_unsupported(curve):
    pytest.skip(f"Curve {curve} known unsupported (cached)")
# ... try import ...
except AssertionError as exc:
    if "DOMAIN_PARAMS_INVALID" in str(exc) or "CURVE_NOT_SUPPORTED" in str(exc):
        rs.mark_curve_unsupported(curve)
        pytest.skip(f"Cannot import EC key for {curve}: {exc}")
```

- [ ] **Step 3:** Apply to all Wycheproof EC tests.

- [ ] **Step 4:** Test and commit:
```bash
git commit -m 'perf: cache unsupported EC curves to eliminate 50K redundant C_CreateObject calls'
```

---

### Task 9: Cache unsupported key imports per session (Sonnet, -4K probe calls)

**Impact:** Eliminates ~4,000 redundant probe calls for key types that fail on import.

Same pattern as Task 8 but for key type + mechanism combinations (RSA key sizes, DES import, etc.).

**Files:**
- Modify: `src/pkcs11_check/fixtures.py` -- add generic import cache
- Modify: Wycheproof tests that skip on import failure

- [ ] **Step 1:** Add `_unsupported_key_imports: set[tuple[int, int]]` to RawSession (key_type, key_size pairs).

- [ ] **Step 2:** Apply caching in tests that skip on import failure.

- [ ] **Step 3:** Commit:
```bash
git commit -m 'perf: cache unsupported key imports to eliminate redundant C_CreateObject probes'
```

---

## Phase 3: Verification (Task 10)

### Task 10: Docker verification on all 3 providers

- [ ] **Step 1:** Run SoftHSM2-main:
```bash
bash docker/test.sh softhsm2-main
```
Expected: ~1,205 failures (unchanged -- all module findings, no test bugs remaining).

- [ ] **Step 2:** Run Kryoptic-main:
```bash
bash docker/test.sh kryoptic-main
```
Expected: ~2,253 -> ~743 failures (-1,510 from test bug fixes).

- [ ] **Step 3:** Run NSS-PQC:
```bash
bash docker/test.sh nss-pqc
```
Expected: ~1,001 -> ~712 failures (-289 from test bug fixes).

- [ ] **Step 4:** Compare results and update `docs/module-matrix.md`.

---

## Expected Results

| Provider | Before | After | Fixed |
|----------|--------|-------|-------|
| SoftHSM2-main | 1,205 | ~1,205 | 0 (all genuine) |
| Kryoptic-main | 2,253 | ~743 | ~1,510 |
| NSS-PQC | 1,001 | ~712 | ~289 |
| **Total** | **4,459** | **~2,660** | **~1,799** |

Performance: ~180,000 fewer PKCS#11 calls per full test run.

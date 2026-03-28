# Mechanism-Driven Tests Continuation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review tasks.

**Goal:** Complete the mechanism-driven test system: fix manifest propagation so tests actually parametrize in Docker, wire KAT vector consumption, expand vector coverage, clean up code, and verify across all modules.

**Architecture:** 4 phases: (1) manifest propagation fix to enable parametrization, (2) KAT vector wiring + expansion, (3) code cleanup + KeygenRecipe resolution, (4) Docker verification across 3+ modules.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw, cryptography (for vector generation)

**Previous work:** `docs/superpowers/plans/2026-03-27-mechanism-driven-tests.md` (Phases A-C complete)

---

## Phase 1: Enable Mechanism Test Parametrization (Tasks 1-2)

### Task 1: Fix Manifest Propagation for mechanism_info

**Goal:** Make mechanism_info flow from the preflight manifest through the file_runner to each test subprocess, so pytest_generate_tests can build the MechanismCatalog.

**Files:**
- Modify: `src/pkcs11_check/core/preflight.py` (verify mechanism_info in subprocess path)
- Modify: `src/pkcs11_check/core/file_runner.py` (verify manifest path propagation)
- Modify: `src/pkcs11_check/plugin.py` (debug _ensure_mechanism_catalog)

- [ ] **Step 1:** Trace the exact data flow by adding temporary debug logging

Add at `plugin.py:_ensure_mechanism_catalog()`:
```python
import sys
manifest = _ensure_manifest(config)
if manifest is None:
    print("DEBUG: manifest is None", file=sys.stderr)
    return None
minfo = getattr(manifest, "mechanism_info", None)
print(f"DEBUG: manifest.mechanism_info has {len(minfo) if minfo else 0} entries", file=sys.stderr)
```

Run Docker test with a single mechanism test file:
```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_mech_flags.py
```

Check stderr in artifacts/softhsm2/console.log for the DEBUG lines. This tells us WHERE the flow breaks.

- [ ] **Step 2:** Fix based on the diagnosis

The most likely issues:
- **Preflight subprocess doesn't save mechanism_info:** Check that `save_manifest` uses `dataclasses.asdict()` which includes all fields. If it uses a custom dict, mechanism_info may be omitted.
- **File runner pre-computes manifest before mechanism_info extension:** Check if the file_runner calls its own preflight BEFORE our changes to preflight.py.
- **manifest_info is empty dict:** The `not getattr(manifest, "mechanism_info", None)` check in plugin.py treats empty dict `{}` as falsy. Change to `getattr(manifest, "mechanism_info", None) is None`.

- [ ] **Step 3:** Remove debug logging, verify with Docker
```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_mech_flags.py src/pkcs11_check/testcases/test_mech_keygen.py
```
Expected: tests are parametrized (not skipped with "No mechanism catalog").

- [ ] **Step 4:** Commit
```bash
git commit -m 'fix: mechanism_info manifest propagation for test parametrization'
```

---

### Task 2: Fix _ensure_mechanism_catalog Empty Dict Handling

**Goal:** Handle the case where mechanism_info exists but is empty (module's get_mechanism_info failed for all mechanisms).

**Files:**
- Modify: `src/pkcs11_check/plugin.py:_ensure_mechanism_catalog`

- [ ] **Step 1:** Change the empty-dict check

Current (line ~200):
```python
if manifest is None or not getattr(manifest, "mechanism_info", None):
    return None
```

Fix:
```python
if manifest is None:
    return None
mech_info = getattr(manifest, "mechanism_info", None)
if mech_info is None:
    return None
# Even empty dict is OK — catalog will have 0 entries but won't error
```

This allows the catalog to be built even with an empty dict (producing 0 parametrized tests = all skip, which is correct).

- [ ] **Step 2:** Commit
```bash
git commit -m 'fix: allow mechanism catalog with empty mechanism_info'
```

---

## Phase 2: KAT Vector Consumption + Expansion (Tasks 3-5)

### Task 3: Wire KAT Vector Loading into Encrypt/Digest/Sign Tests

**Goal:** Make test_mech_encrypt.py, test_mech_digest.py, and test_mech_sign.py actually load and verify KAT vectors from JSON files.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_encrypt.py`
- Modify: `src/pkcs11_check/testcases/test_mech_digest.py`
- Modify: `src/pkcs11_check/testcases/test_mech_sign.py`

- [ ] **Step 1:** Add KAT test to test_mech_encrypt.py

```python
class TestMechEncryptKAT:
    """Known-answer tests from pre-generated vectors."""

    def test_kat_vector(self, p11_raw_session: RawSession, mech_encrypt_entry: MechEntry) -> None:
        """Encrypt with known key/input, verify output matches vector."""
        config = mech_encrypt_entry.config
        if config is None or not config.vector_file:
            pytest.skip("No KAT vectors for this mechanism")

        from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors
        vectors = load_positive_vectors(config.vector_file)
        if not vectors:
            pytest.skip(f"No positive vectors in {config.vector_file}")

        for vec in vectors:
            key_hex = vec.get("key_hex")
            if not key_hex:
                continue
            key_bits = vec.get("key_bits", len(bytes.fromhex(key_hex)) * 8)
            # Import the known key
            key = import_secret_key(rs.raw, rs.sh, int(config.key_type),
                                   bytes.fromhex(key_hex),
                                   attrs={CKA_ENCRYPT: True, CKA_TOKEN: False})
            try:
                params = _build_params_from_vector(entry, config, vec)
                ct = encrypt_single(rs.raw, rs.sh, key, entry.mech_id,
                                   bytes.fromhex(vec["plaintext_hex"]),
                                   mech_param=params)
                expected = bytes.fromhex(vec["ciphertext_hex"])
                if config.auth_tag_included:
                    expected += bytes.fromhex(vec.get("tag_hex", ""))
                assert ct == expected, f"KAT mismatch: {vec['id']}"
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
```

- [ ] **Step 2:** Add KAT test to test_mech_digest.py

```python
class TestMechDigestKAT:
    def test_kat_vector(self, p11_raw_session: RawSession, mech_digest_entry: MechEntry) -> None:
        """Digest known input, verify matches pre-computed hash."""
        config = mech_digest_entry.config
        if config is None or not config.vector_file:
            pytest.skip("No KAT vectors")

        from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors
        vectors = load_positive_vectors(config.vector_file)
        # Filter vectors for this specific mechanism
        mech_name = entry.mech_name
        for vec in vectors:
            if vec.get("mechanism_name") and vec["mechanism_name"] != mech_name:
                continue
            digest = digest_single(rs.raw, rs.sh, entry.mech_id,
                                  bytes.fromhex(vec["input_hex"]))
            assert digest == bytes.fromhex(vec["digest_hex"]), f"KAT mismatch: {vec['id']}"
```

- [ ] **Step 3:** Lint and commit
```bash
git commit -m 'feat: wire KAT vector consumption into encrypt, digest, sign tests'
```

---

### Task 4: Expand KAT Vector Generation

**Goal:** Generate vectors for 15 more mechanism families.

**Files:**
- Modify: `scripts/generate_mechanism_vectors.py`
- Create: JSON files in `src/pkcs11_check/testcases/data/mechanism_vectors/`

- [ ] **Step 1:** Add generators for: AES-CBC-PAD, AES-CTR, AES-CCM, RSA-PKCS (encrypt), RSA-OAEP, RSA-PSS (sign), ECDSA (sign), HMAC-SHA384, HMAC-SHA512, SHA3 family, HKDF, DES3-ECB, ChaCha20-Poly1305

Each generator follows the same pattern as existing ones — use `cryptography` library with fixed seeds.

- [ ] **Step 2:** Generate all vectors
```bash
uv run python scripts/generate_mechanism_vectors.py --all
```

- [ ] **Step 3:** Update registry entries to point to new vector files

- [ ] **Step 4:** Commit
```bash
git add src/pkcs11_check/testcases/data/mechanism_vectors/
git commit -m 'feat: expand KAT vectors to 20 mechanism families'
```

---

### Task 5: Add _build_params_from_vector Helper

**Goal:** Build mechanism params from vector JSON data (e.g., use the IV from the vector, not random).

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py`

- [ ] **Step 1:** Add helper
```python
def build_params_from_vector(
    mech_id: int, recipe: ParamRecipe, vec: dict[str, Any]
) -> Any:
    """Build mechanism params using values from a KAT vector dict."""
    params = vec.get("params", {})
    style = recipe.style
    if style == "none":
        return None
    elif style == "iv":
        iv = bytes.fromhex(params.get("iv_hex", ""))
        if not iv:
            return None
        return mech_bytes(CKM(mech_id), iv)
    elif style == "gcm":
        iv = bytes.fromhex(params.get("iv_hex", ""))
        aad = bytes.fromhex(params.get("aad_hex", "")) or None
        tag_bits = params.get("tag_bits", 128)
        return mech_gcm(CKM(mech_id), iv=iv, tag_bits=tag_bits,
                       aad=aad if aad else None)
    # ... etc for each style
    return None
```

- [ ] **Step 2:** Commit
```bash
git commit -m 'feat: add build_params_from_vector for KAT tests'
```

---

## Phase 3: Code Cleanup (Tasks 6-9)

### Task 6: Replace Magic Hex Constants with Named Imports

**Goal:** Replace ~20 raw hex literals across test files with named imports.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_derive.py`
- Modify: `src/pkcs11_check/testcases/test_mech_lifecycle.py`
- Modify: `src/pkcs11_check/testcases/test_mech_wrap.py`
- Modify: `src/pkcs11_check/testcases/test_mech_negative.py`
- Modify: `src/pkcs11_check/testcases/test_mech_digest.py`
- Modify: `src/pkcs11_check/testcases/test_mech_multipart.py`
- Modify: `src/pkcs11_check/testcases/test_mech_state.py`

- [ ] **Step 1:** Replace all `_CKM_SHA256 = 0x00000250` with `from pkcs11_check.raw.types_std import CKM_SHA256` (and cast `int(CKM_SHA256)` where needed)

- [ ] **Step 2:** Replace all `_CKD_NULL = 0x00000001` with import from types_std

- [ ] **Step 3:** Replace all `_CKZ_SALT_SPECIFIED = 0x00000001` with import

- [ ] **Step 4:** For SHAKE_128/256 (0x0418/0x0419) which don't exist in types_std, keep integer literals but add comment: `# Not in vendored v3.2 header — defined in OASIS working spec`

- [ ] **Step 5:** Lint and commit
```bash
git commit -m 'refactor: replace magic hex constants with named imports from types_std'
```

---

### Task 7: Decompose test_mech_derive.py

**Goal:** Split the 240-line single test method into per-family helper functions.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_derive.py`

- [ ] **Step 1:** Extract helper functions
```python
def _derive_sha(rs, entry, config): ...
def _derive_hkdf(rs, entry, config): ...
def _derive_ecdh(rs, entry, config): ...
def _derive_concat(rs, entry, config): ...
def _derive_extract(rs, entry, config): ...
def _derive_aes_ecb(rs, entry, config): ...
```

- [ ] **Step 2:** Simplify test_derive_produces_key to a short dispatcher

- [ ] **Step 3:** Commit
```bash
git commit -m 'refactor: decompose test_mech_derive into per-family helpers'
```

---

### Task 8: Resolve KeygenRecipe — Wire Up or Remove

**Goal:** Either make KeygenRecipe consumed by test dispatch or remove it to reduce complexity.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/__init__.py`
- Potentially modify: All 12 registry submodules (if removing)

- [ ] **Step 1:** Wire up KeygenRecipe consumption

Replace the key-type dispatch in `gen_symmetric_key` and `gen_keypair_for_mech` with recipe-based dispatch:

```python
def generate_key_from_recipe(rs, entry, config, extra_attrs):
    """Generate key using KeygenRecipe style."""
    recipe = config.keygen_recipe
    if recipe.style == "symmetric":
        return gen_symmetric_key(rs, entry, config, extra_attrs)
    elif recipe.style == "rsa":
        return gen_rsa_keypair(rs.raw, rs.sh, key_size, ...)
    elif recipe.style == "ec":
        curve = recipe.defaults.get("curve", "secp256r1")
        ...
    # etc
```

- [ ] **Step 2:** Update test files to use the recipe-based function

- [ ] **Step 3:** Commit
```bash
git commit -m 'feat: wire KeygenRecipe consumption into key generation dispatch'
```

---

### Task 9: Remove Unused Imports Across Test Files

**Goal:** Clean up imports that are genuinely unused (not just Pyright false positives).

**Files:**
- All `test_mech_*.py` files

- [ ] **Step 1:** Run ruff with F401 (unused import) rule strictly:
```bash
uv run ruff check --select F401 src/pkcs11_check/testcases/test_mech_*.py
```

- [ ] **Step 2:** Fix any real unused imports found

- [ ] **Step 3:** Commit
```bash
git commit -m 'chore: clean up unused imports in mechanism test files'
```

---

## Phase 4: Docker Verification + Documentation (Tasks 10-13)

### Task 10: Docker Verification — SoftHSM2-main

- [ ] **Step 1:** Run full SoftHSM2-main Docker test
```bash
bash docker/test.sh softhsm2-main
```

- [ ] **Step 2:** Check results — mechanism tests should run (not all skip)
```python
python3 -c "
import json
d = json.load(open('artifacts/softhsm2-main/results.json'))
print(json.dumps(d['summary'], indent=2))
# Check for test_mech files in units
for u in d.get('units', []):
    if 'test_mech' in u.get('target', ''):
        print(f'{u[\"target\"]}: {u.get(\"counts\", {})}')
"
```

- [ ] **Step 3:** Fix any test failures (distinguish module bugs from test bugs)

---

### Task 11: Docker Verification — Kryoptic-main

- [ ] **Step 1:** Run full Kryoptic-main Docker test
```bash
bash docker/test.sh kryoptic-main
```

- [ ] **Step 2:** Check results — focus on mechanism test coverage improvement

- [ ] **Step 3:** Verify no new test ERRORS (pass/fail/skip/xfail all acceptable)

---

### Task 12: Docker Verification — NSS-PQC

- [ ] **Step 1:** Run full NSS-PQC Docker test
```bash
bash docker/test.sh nss-pqc
```

- [ ] **Step 2:** Verify no regressions from mechanism test additions

---

### Task 13: Update Documentation

**Files:**
- Modify: `docs/module-matrix.md` — add mechanism test coverage numbers
- Modify: `docs/status.md` — update with mechanism-driven test counts
- Modify: `docs/test-coverage.md` — add mechanism coverage section

- [ ] **Step 1:** Update module-matrix.md with post-mechanism-test results

- [ ] **Step 2:** Update status.md with mechanism-driven test system description

- [ ] **Step 3:** Commit
```bash
git commit -m 'docs: update matrix and status with mechanism-driven test results'
```

---

### Task 14: Final Opus Review

- [ ] **Step 1:** Dispatch Opus 4.6 review agent for the entire mechanism test system

Check:
- All test files import only from mechanism_helpers (no cross-test imports)
- No remaining param_packer/param_factory references
- No remaining magic hex constants (except documented SHAKE exceptions)
- KAT vectors consumed and verified
- Docker tests pass on all 3 modules
- Documentation accurate

- [ ] **Step 2:** Fix any findings

- [ ] **Step 3:** Final commit
```bash
git commit --allow-empty -m 'chore: mechanism-driven test system v1.0 — fully verified'
```

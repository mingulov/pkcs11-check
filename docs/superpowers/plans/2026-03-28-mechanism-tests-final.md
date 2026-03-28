# Mechanism Tests Final — Deferred Items

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review tasks.

**Goal:** Complete the four deferred items from the mechanism-driven test system: add CK_GCM_MESSAGE_PARAMS packer, add CK_HASH_SIGN_ADDITIONAL_CONTEXT packer, fix pkcs11f.h vendoring test, and close the 25-mechanism registry gap.

**Architecture:** 4 independent phases that can run sequentially. Each adds a ctypes packer or fixes vendoring/registry gaps. All struct definitions already exist in `types_std.py` — we only need packers in `pack_mechanisms.py` and test wiring.

**Tech Stack:** Python 3.11+, ctypes, pytest, pkcs11_check.raw

**Previous work:** `docs/superpowers/plans/2026-03-27-mechanism-tests-continuation.md` (all 14 tasks complete)

---

## Phase 1: CK_GCM_MESSAGE_PARAMS Packer (Tasks 1-2)

### Task 1: Add mech_gcm_message() to pack_mechanisms.py

**Goal:** Pack `CK_GCM_MESSAGE_PARAMS` struct for v3.0 message-based AEAD.

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`

The struct `CK_GCM_MESSAGE_PARAMS` is already defined in `types_std.py` (lines 1019-1026):
```python
CK_GCM_MESSAGE_PARAMS._fields_ = [
    ("pIv",           ctypes.c_void_p),
    ("ulIvLen",       CK_ULONG),
    ("ulIvFixedBits", CK_ULONG),
    ("ivGenerator",   CK_GENERATOR_FUNCTION),
    ("pTag",          ctypes.c_void_p),
    ("ulTagBits",     CK_ULONG),
]
```

Key difference vs `CK_GCM_PARAMS` (standard encrypt): no `pAAD`/`ulAADLen`/`ulIvBits`. Instead has `ulIvFixedBits`/`ivGenerator` and `pTag` (output buffer for auth tag).

- [ ] **Step 1:** Read `src/pkcs11_check/raw/pack_mechanisms.py` and find the existing `mech_gcm()` function (around line 54). The new function follows this exact pattern.

- [ ] **Step 2:** Add the packer after `mech_gcm()`:

```python
def mech_gcm_message(
    mechanism_type: CKM,
    iv: bytes,
    *,
    iv_fixed_bits: int = 0,
    iv_generator: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_GCM_MESSAGE_PARAMS for v3.0 message-based AEAD.

    The ``pTag`` field is a pre-allocated output buffer (tag_bits // 8 bytes)
    that the token writes the authentication tag to.
    """
    ka: list[Any] = []
    params = CK_GCM_MESSAGE_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvFixedBits = iv_fixed_bits
    params.ivGenerator = iv_generator
    # pTag is an OUTPUT buffer — allocate writable bytes for the token to fill
    tag_len = tag_bits // 8
    tag_buf = (ctypes.c_ubyte * tag_len)()
    ka.append(tag_buf)
    params.pTag = ctypes.cast(tag_buf, ctypes.c_void_p)
    params.ulTagBits = tag_bits
    return _mech_struct(mechanism_type, params, "mech_gcm_message", ka)
```

- [ ] **Step 3:** Add `CK_GCM_MESSAGE_PARAMS` to the imports from `types_std` at the top of `pack_mechanisms.py`. Search for the existing `from pkcs11_check.raw.types_std import` block and add it.

- [ ] **Step 4:** Lint
```bash
uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py
uv run ruff format src/pkcs11_check/raw/pack_mechanisms.py
```

- [ ] **Step 5:** Commit
```bash
git add src/pkcs11_check/raw/pack_mechanisms.py
git commit -m 'feat: add mech_gcm_message() packer for CK_GCM_MESSAGE_PARAMS'
```

---

### Task 2: Wire mech_gcm_message into test_mech_message.py

**Goal:** Remove the skip in test_mech_message.py and use the new packer.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_message.py`

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/test_mech_message.py` in full to understand the current skip logic and what the test wants to do.

- [ ] **Step 2:** Replace the `pytest.skip("Message-based AES-GCM test requires CK_GCM_MESSAGE_PARAMS packing...")` with actual implementation using `mech_gcm_message`. The test should:
1. Generate an AES key
2. Call `C_MessageEncryptInit` with the packed `CK_GCM_MESSAGE_PARAMS`
3. Call `C_EncryptMessage` with plaintext + AAD
4. Call `C_MessageEncryptFinal`
5. Repeat for decrypt: `C_MessageDecryptInit` / `C_DecryptMessage` / `C_MessageDecryptFinal`
6. Assert decrypted == original plaintext

Import `mech_gcm_message` from `pkcs11_check.raw.pack_mechanisms`.

**Important:** The `C_MessageEncryptInit`, `C_EncryptMessage`, `C_MessageDecryptInit`, `C_DecryptMessage` functions may not exist on all modules. Check the test already has `has_mechanism` and `hasattr` guards — keep those. If the raw API doesn't have these methods, the test should skip gracefully with a clear message.

- [ ] **Step 3:** Lint and format
```bash
uv run ruff check src/pkcs11_check/testcases/test_mech_message.py
uv run ruff format src/pkcs11_check/testcases/test_mech_message.py
```

- [ ] **Step 4:** Test locally (will skip on modules without v3.0 message API)
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_message" -v
```
Expected: skip on SoftHSM2 (v2.40, no message API). On Kryoptic (v3.2) it may work.

- [ ] **Step 5:** Commit
```bash
git add src/pkcs11_check/testcases/test_mech_message.py
git commit -m 'feat: wire mech_gcm_message into test_mech_message for v3.0 AEAD'
```

---

## Phase 2: CK_HASH_SIGN_ADDITIONAL_CONTEXT Packer (Tasks 3-4)

### Task 3: Add mech_hash_sign_context() to pack_mechanisms.py

**Goal:** Pack `CK_HASH_SIGN_ADDITIONAL_CONTEXT` for `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA`.

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`

The struct is in `types_std.py` (lines 1063-1068):
```python
CK_HASH_SIGN_ADDITIONAL_CONTEXT._fields_ = [
    ("hedgeVariant", CK_HEDGE_TYPE),
    ("pContext",     ctypes.c_void_p),
    ("ulContextLen", CK_ULONG),
    ("hash",         CK_MECHANISM_TYPE),
]
```

Constants needed from `types_std.py`:
- `CKH_HEDGE_PREFERRED` (default)
- `CKH_HEDGE_REQUIRED`
- `CKH_DETERMINISTIC_REQUIRED`

- [ ] **Step 1:** Read `pack_mechanisms.py` to find the existing PQC-related packers (e.g., `mech_eddsa`, `mech_pss`). The new function follows the same pattern.

- [ ] **Step 2:** Add the packer:

```python
def mech_hash_sign_context(
    mechanism_type: CKM,
    hash_mech: int,
    *,
    hedge: int | None = None,
    context: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_HASH_SIGN_ADDITIONAL_CONTEXT for CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA.

    The ``hash`` field is mandatory for the generic CKM_HASH_ML_DSA and
    CKM_HASH_SLH_DSA mechanisms (specifies which hash to use).
    ``hedge`` defaults to CKH_HEDGE_PREFERRED when omitted.
    ``context`` is the optional additional context bytes (default: no context).
    """
    ka: list[Any] = []
    params = CK_HASH_SIGN_ADDITIONAL_CONTEXT()
    if hedge is None:
        params.hedgeVariant = int(CKH_HEDGE_PREFERRED)
    else:
        params.hedgeVariant = hedge
    if context is not None:
        params.pContext, params.ulContextLen = _pack_bytes(context, ka)
    else:
        params.pContext = None
        params.ulContextLen = 0
    params.hash = hash_mech
    return _mech_struct(mechanism_type, params, "mech_hash_sign_context", ka)
```

- [ ] **Step 3:** Add `CK_HASH_SIGN_ADDITIONAL_CONTEXT`, `CKH_HEDGE_PREFERRED` to the imports from `types_std`.

- [ ] **Step 4:** Lint
```bash
uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py
```

- [ ] **Step 5:** Commit
```bash
git add src/pkcs11_check/raw/pack_mechanisms.py
git commit -m 'feat: add mech_hash_sign_context() packer for CK_HASH_SIGN_ADDITIONAL_CONTEXT'
```

---

### Task 4: Wire mech_hash_sign_context into test_hash_ml_dsa.py and test_hash_slh_dsa.py

**Goal:** Remove skips in the generic hash+sign test methods.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_hash_ml_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_hash_slh_dsa.py`

- [ ] **Step 1:** Read both test files in full. Find the `pytest.skip("CKM_HASH_ML_DSA/SLH_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT...")` lines. These are in the `TestHashMLDSAGeneric` / `TestHashSLHDSAGeneric` classes.

- [ ] **Step 2:** In `test_hash_ml_dsa.py`, replace the skip with:
```python
from pkcs11_check.raw.pack_mechanisms import mech_hash_sign_context
from pkcs11_check.raw.types_std import CKM_SHA256

# Build the mechanism param with SHA-256 as the hash
mech_param = mech_hash_sign_context(CKM(mech_id), hash_mech=int(CKM_SHA256))
```
Then use `mech_param` in the `sign_single` / `verify_single` calls. Keep existing keygen and cleanup logic.

- [ ] **Step 3:** Do the same for `test_hash_slh_dsa.py`, using the same pattern.

- [ ] **Step 4:** Lint both files:
```bash
uv run ruff check src/pkcs11_check/testcases/test_hash_ml_dsa.py src/pkcs11_check/testcases/test_hash_slh_dsa.py
```

- [ ] **Step 5:** Test locally (will skip on modules without ML-DSA/SLH-DSA):
```bash
bash local-builds/test.sh softhsm2 -k "test_hash_ml_dsa or test_hash_slh_dsa" -v
```
Expected: skip on SoftHSM2 (no PQC). On Kryoptic v3.2 it should run.

- [ ] **Step 6:** Commit
```bash
git add src/pkcs11_check/testcases/test_hash_ml_dsa.py src/pkcs11_check/testcases/test_hash_slh_dsa.py
git commit -m 'feat: wire CK_HASH_SIGN_ADDITIONAL_CONTEXT into hash ML-DSA/SLH-DSA tests'
```

---

## Phase 3: Fix pkcs11f.h/pkcs11t.h Vendoring (Task 5)

### Task 5: Fix test_raw_pack.py vendored header assertion

**Goal:** Make the vendored header test pass by either adding stub headers or adjusting the test for single-file header setups.

**Files:**
- Modify: `tests/test_raw_pack.py`
- Possibly create: `third_party/pkcs11-headers/3.2/pkcs11t.h` (stub)
- Possibly create: `third_party/pkcs11-headers/3.2/pkcs11f.h` (stub)

**Context:** The current vendored header is the latchset single-file `pkcs11.h` which contains ALL types and function declarations in one file. The OASIS standard uses three files (`pkcs11.h` + `pkcs11t.h` + `pkcs11f.h`). The test asserts all three exist, but only one does.

The generator script `scripts/generate_raw_standard.py` already handles both formats (single-file and 3-file), so the simplest fix is to update the test to only assert headers that actually exist.

- [ ] **Step 1:** Read `tests/test_raw_pack.py` around lines 540-560 to see the exact assertion and `_STANDARD_HEADERS` tuple.

- [ ] **Step 2:** Change the test to dynamically check which headers exist instead of hardcoding all three. The cleanest approach:

```python
# At module level or in the helper
_REQUIRED_HEADERS = ("pkcs11.h",)  # Always required
_OPTIONAL_HEADERS = ("pkcs11f.h", "pkcs11t.h")  # OASIS 3-file format only
```

In `_assert_standard_raw_pack_contents`, assert that `pkcs11.h` is always present, and only assert `pkcs11f.h`/`pkcs11t.h` if they exist in the source `third_party/` directory:

```python
for header in _REQUIRED_HEADERS:
    assert f"{header_prefix}/{header}" in archive_names, f"Missing required header {header}"

# Only check optional headers if they exist in source
source_dir = Path("third_party/pkcs11-headers/3.2")
for header in _OPTIONAL_HEADERS:
    if (source_dir / header).exists():
        assert f"{header_prefix}/{header}" in archive_names, f"Missing optional header {header}"
```

- [ ] **Step 3:** Run the test:
```bash
uv run python -m pytest tests/test_raw_pack.py::test_sdist_and_wheel_include_vendored_standard_headers_and_generated_raw_modules -v
```
Expected: PASS (only `pkcs11.h` asserted since others don't exist in source).

- [ ] **Step 4:** Lint
```bash
uv run ruff check tests/test_raw_pack.py
```

- [ ] **Step 5:** Commit
```bash
git add tests/test_raw_pack.py
git commit -m 'fix: adjust vendored header test for single-file pkcs11.h format'
```

---

## Phase 4: Close Registry Gap — 25 Missing Mechanisms (Tasks 6-7)

### Task 6: Identify and Add Missing Mechanism Registry Entries

**Goal:** Add the ~25 mechanisms present in `MECHANISM_NAMES` but missing from `MECHANISM_REGISTRY`.

**Files:**
- Modify: Appropriate `src/pkcs11_check/testcases/mechanism_registry/_*.py` submodules

**Current state:** 439 registered / 464 in MECHANISM_NAMES = 25 gap.

- [ ] **Step 1:** Write a script to identify the exact missing mechanisms:
```bash
uv run python -c "
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
missing = sorted(set(MECHANISM_NAMES.keys()) - set(MECHANISM_REGISTRY.keys()))
for mid in missing:
    print(f'  0x{mid:08x}  {MECHANISM_NAMES[mid]}')
print(f'Total missing: {len(missing)}')
"
```

- [ ] **Step 2:** For each missing mechanism, determine the correct submodule and add a `MechConfig` entry. Most will be minimal entries:

```python
registry[CKM_EXAMPLE] = MechConfig(
    key_type=None,  # or CKK_* if known
    keygen_mech=None,
    key_sizes=(),
    expected_flags=0,  # set if known from spec
    notes="Brief description from spec",
)
```

Group additions by family:
- AES-related → `_aes.py`
- RSA-related → `_rsa.py`
- EC-related → `_ec.py`
- Hash-related → `_hash.py`
- HMAC-related → `_hmac.py`
- PQC-related → `_pqc.py`
- KDF-related → `_kdf.py`
- DSA/DH-related → `_dsa_dh.py`
- DES/legacy → `_des.py` or `_legacy.py`
- Misc ciphers → `_ciphers.py`
- Other → `_misc.py`

For each mechanism, check the PKCS#11 spec for:
- Key type (`CKK_*`)
- Whether it's symmetric or keypair
- Expected flags (`CKF_ENCRYPT`, `CKF_SIGN`, `CKF_DIGEST`, etc.)
- Parameter requirements

The spec files are at: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`

- [ ] **Step 3:** Lint all modified registry files:
```bash
uv run ruff check src/pkcs11_check/testcases/mechanism_registry/
```

- [ ] **Step 4:** Verify the gap is closed:
```bash
uv run python -c "
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
missing = set(MECHANISM_NAMES.keys()) - set(MECHANISM_REGISTRY.keys())
print(f'Remaining gap: {len(missing)}')
print(f'Total registered: {len(MECHANISM_REGISTRY)}')
"
```
Expected: gap 0 (or close to 0 if some mechanisms are genuinely not registerable).

- [ ] **Step 5:** Commit
```bash
git add src/pkcs11_check/testcases/mechanism_registry/
git commit -m 'feat: close 25-mechanism registry gap — full MECHANISM_NAMES coverage'
```

---

### Task 7: Update Registry Docstring and Documentation

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/__init__.py` (docstring)
- Modify: `docs/status.md`
- Modify: `docs/test-coverage.md`

- [ ] **Step 1:** Update the `__init__.py` module docstring to reflect the actual count (was "480", should match real count).

- [ ] **Step 2:** Update `docs/status.md` to reflect the registry now covers all mechanisms in MECHANISM_NAMES.

- [ ] **Step 3:** Update `docs/test-coverage.md` mechanism-driven section with updated registry count.

- [ ] **Step 4:** Commit
```bash
git add src/pkcs11_check/testcases/mechanism_registry/__init__.py docs/status.md docs/test-coverage.md
git commit -m 'docs: update registry count and mechanism coverage documentation'
```

---

### Task 8: Update Project Memory

**Files:**
- Modify: `/home/user/.claude/projects/-home-user-src-m-pkcs11-check/memory/project_mechanism_tests_progress.md`

- [ ] **Step 1:** Read the current memory file.

- [ ] **Step 2:** Update with final status:
- Phase A tasks 1-4: complete (439 → 464 registry entries)
- Continuation plan: all 14 tasks complete
- Final plan: all phases complete
- KAT vectors: 12 JSON files, 12+ tests passing
- Docker verified: SoftHSM2-main, Kryoptic-main, NSS-PQC
- Remaining: none (or list any genuinely remaining items)

- [ ] **Step 3:** Verify MEMORY.md index is up to date.

---

## Docker Verification (Task 9)

### Task 9: Docker Smoke Test

- [ ] **Step 1:** Run targeted Docker tests on the changed test files:
```bash
bash docker/test.sh kryoptic-main -- src/pkcs11_check/testcases/test_mech_message.py
bash docker/test.sh kryoptic-main -- src/pkcs11_check/testcases/test_hash_ml_dsa.py src/pkcs11_check/testcases/test_hash_slh_dsa.py
```
Kryoptic v3.2 is the best target for message-based AEAD and PQC hash+sign tests.

- [ ] **Step 2:** Run meta-tests to verify pkcs11f.h fix:
```bash
uv run python -m pytest tests/test_raw_pack.py -v -x
```

- [ ] **Step 3:** Run mechanism flag tests to verify registry expansion:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_flags" --no-header
```
Expected: more parametrized tests than before (new registry entries).

- [ ] **Step 4:** If any errors found, fix and re-test. Commit fixes.

# Multi-Block CFB resultsArray Support - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add support for ACVP multi-block CFB test vectors (resultsArray format) that test CFB chaining behavior across 100 sequential blocks.

**Architecture:** Extend the simple CFB loader to detect resultsArray structures, extract block sequences, and add a multi-block runner that processes all blocks through a single cryptographic context, verifying each intermediate result matches ACVP expectations.

**Tech Stack:** Python 3.11, pytest, pkcs11-check raw ctypes API

---

## Files Overview

| File | Purpose | Action |
|------|---------|--------|
| `src/pkcs11_check/testcases/acvp/aes/base_loader.py` | Vector loading | Add resultsArray detection and block extraction |
| `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py` | Test execution | Add multi-block CFB runner function |
| `src/pkcs11_check/testcases/acvp/aes/test_cfb.py` | Test definitions | Add multi-block test parametrize |

---

## Implementation Tasks

### Task 1: Modify Loader to Extract resultsArray Blocks

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/base_loader.py:47-151`

**Background:** The ACVP CFB test vectors have two formats:
- Simple: Single `pt`/`ct` field (2138 cases)
- Multi-block: `resultsArray` with 100 chained blocks (16 cases total: 6 CFB128 + 5 CFB8 + 5 CFB1)

Current code skips resultsArray cases. We need to parse them into a blocks list.

- [ ] **Step 1: Remove the resultsArray skip in `_load_vectors`**

Current code (line ~53-56):
```python
# Skip multi-block test cases (resultsArray) - not supported by simple runner
if "resultsArray" in exp:
    continue
```

Remove this check entirely. The loop should process all vectors including those with resultsArray.

- [ ] **Step 2: Add resultsArray detection and field mapping in encrypt branch**

After extracting standard fields (line ~85-97), add:

```python
# Handle multi-block resultsArray format
if "resultsArray" in exp:
    blocks = []
    for idx, block in enumerate(exp["resultsArray"]):
        blocks.append({
            "block_index": idx,
            "key": bytes.fromhex(block["key"]) if block.get("key") else merged["key"],
            "iv": bytes.fromhex(block["iv"]) if block.get("iv") else (blocks[-1]["ct"] if blocks else merged["iv"]),
            "pt": bytes.fromhex(block["pt"]) if block.get("pt") else b"",
            "ct_expected": bytes.fromhex(block["ct"]) if block.get("ct") else b"",
        })
    merged["blocks"] = blocks
    merged["is_multiblock"] = True
else:
    merged["is_multiblock"] = False
```

Note: For CFB chaining, the IV of block N+1 is the ciphertext of block N (except block 0 uses the initial IV).

- [ ] **Step 3: Add similar resultsArray handling in decrypt branch**

After line ~147, add parallel logic for decrypt:

```python
# Handle multi-block resultsArray format for decrypt
if "resultsArray" in exp:
    blocks = []
    for idx, block in enumerate(exp["resultsArray"]):
        blocks.append({
            "block_index": idx,
            "key": bytes.fromhex(block["key"]) if block.get("key") else merged["key"],
            "iv": bytes.fromhex(block["iv"]) if block.get("iv") else (blocks[-1]["ct"] if blocks else merged["iv"]),
            "ct": bytes.fromhex(block["ct"]) if block.get("ct") else b"",
            "pt_expected": bytes.fromhex(block["pt"]) if block.get("pt") else b"",
        })
    merged["blocks"] = blocks
    merged["is_multiblock"] = True
else:
    merged["is_multiblock"] = False
```

- [ ] **Step 4: Verify loader changes**

Run: `python -c "from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors; vecs = _load_simple_vectors('ACVP-AES-CFB128-1.0'); print(f'Encrypt: {len(vecs[0])}, Decrypt: {len(vecs[1])}')"`

Expected: Encrypt: 1072, Decrypt: 1072 (includes the 6 multi-block cases now)

---

### Task 2: Add Multi-Block CFB Runner

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py:156+`

- [ ] **Step 1: Add multi-block encrypt runner function**

Insert after `run_simple_decrypt_test` function:

```python
def run_multiblock_encrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run multi-block CFB encryption test with chaining.

    Processes all blocks sequentially with a single context,
    verifying each intermediate result matches ACVP expectations.
    CFB chaining: block N+1 uses ciphertext of block N as IV.
    """
    rs = p11_raw_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    # Import key from first block (all blocks use same key in CFB tests)
    key = 0
    try:
        key = _import_aes_key(rs, blocks[0]["key"], encrypt=True, decrypt=False)

        # Initialize encryption context
        from pkcs11_check.raw.pack import mech_bytes
        if mech_param_func:
            mech = mech_param_func()
        else:
            mech = mech_bytes(mech_constant, blocks[0]["iv"])

        # Initialize single context for all blocks
        ctx = rs.raw.C_EncryptInit(rs.sh, mech, key)
        if ctx != 0:
            pytest.xfail(f"Module limitation: {mech_name} encrypt_init failed")

        # Process each block and verify intermediate results
        for block in blocks:
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    mech_constant,
                    block["pt"],
                    mech_param=mech,
                )
            except AssertionError as exc:
                pytest.xfail(f"Module limitation: {mech_name} encrypt failed at block {block['block_index']} ({exc})")

            assert ct == block["ct_expected"], (
                f"{vec_id}: block {block['block_index']} ciphertext mismatch: "
                f"got {ct.hex()}, expected {block['ct_expected'].hex()}"
            )

    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
```

- [ ] **Step 2: Add multi-block decrypt runner function**

Insert after the encrypt runner:

```python
def run_multiblock_decrypt_test(
    p11_raw_session: Any,
    vec_id: str,
    vec: dict[str, Any],
    mech_name: str,
    mech_constant: CKM,
    mech_param_func: Callable[[], Any] | None = None,
) -> None:
    """Run multi-block CFB decryption test with chaining.

    Processes all blocks sequentially with a single context,
    verifying each intermediate result matches ACVP expectations.
    """
    rs = p11_raw_session
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    blocks = vec.get("blocks", [])
    if not blocks:
        pytest.fail(f"{vec_id}: No blocks found in multi-block test")

    # Import key from first block
    key = 0
    try:
        key = _import_aes_key(rs, blocks[0]["key"], encrypt=False, decrypt=True)

        # Initialize decryption context
        from pkcs11_check.raw.pack import mech_bytes
        if mech_param_func:
            mech = mech_param_func()
        else:
            mech = mech_bytes(mech_constant, blocks[0]["iv"])

        # Initialize single context for all blocks
        ctx = rs.raw.C_DecryptInit(rs.sh, mech, key)
        if ctx != 0:
            pytest.xfail(f"Module limitation: {mech_name} decrypt_init failed")

        # Process each block and verify intermediate results
        for block in blocks:
            try:
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    mech_constant,
                    block["ct"],
                    mech_param=mech,
                )
            except AssertionError as exc:
                pytest.xfail(f"Module limitation: {mech_name} decrypt failed at block {block['block_index']} ({exc})")
                return

            assert pt == block["pt_expected"], (
                f"{vec_id}: block {block['block_index']} plaintext mismatch: "
                f"got {pt.hex()}, expected {block['pt_expected'].hex()}"
            )

    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
```

- [ ] **Step 3: Verify runner compiles**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py`
Expected: No errors (may have import sorting warnings that can be fixed with `--fix`)

---

### Task 3: Update Test File to Use Multi-Block Runners

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/test_cfb.py`

- [ ] **Step 1: Separate simple and multi-block vectors**

Current loading (line 35-36):
```python
_CFB128_ENCRYPT_VECTORS, _CFB128_DECRYPT_VECTORS = _load_simple_vectors("ACVP-AES-CFB128-1.0")
```

Change to:
```python
_CFB128_ALL_ENCRYPT, _CFB128_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB128-1.0")

# Separate simple vs multi-block vectors
_CFB128_ENCRYPT_VECTORS = [(vid, v) for vid, v in _CFB128_ALL_ENCRYPT if not v.get("is_multiblock")]
_CFB128_DECRYPT_VECTORS = [(vid, v) for vid, v in _CFB128_ALL_DECRYPT if not v.get("is_multiblock")]
_CFB128_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _CFB128_ALL_ENCRYPT if v.get("is_multiblock")]
_CFB128_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _CFB128_ALL_DECRYPT if v.get("is_multiblock")]
```

- [ ] **Step 2: Add imports for multi-block runners**

Add to imports (line 22-26):
```python
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    run_multiblock_decrypt_test,
    run_multiblock_encrypt_test,
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)
```

- [ ] **Step 3: Add multi-block encrypt test**

After line 43 (after simple encrypt test), add:

```python
@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _CFB128_MULTIBLOCK_ENCRYPT]
)
def test_acvp_aes_cfb128_multiblock_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)
```

- [ ] **Step 4: Add multi-block decrypt test**

After line 51 (after simple decrypt test), add:

```python
@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_MULTIBLOCK_DECRYPT, ids=[v[0] for v in _CFB128_MULTIBLOCK_DECRYPT]
)
def test_acvp_aes_cfb128_multiblock_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)
```

- [ ] **Step 5: Repeat for CFB8 and CFB1**

Apply the same pattern to CFB8 (line 57-74) and CFB1 (line 81-100):

For CFB8:
```python
_CFB8_ALL_ENCRYPT, _CFB8_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB8-1.0")
_CFB8_ENCRYPT_VECTORS = [(vid, v) for vid, v in _CFB8_ALL_ENCRYPT if not v.get("is_multiblock")]
_CFB8_DECRYPT_VECTORS = [(vid, v) for vid, v in _CFB8_ALL_DECRYPT if not v.get("is_multiblock")]
_CFB8_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _CFB8_ALL_ENCRYPT if v.get("is_multiblock")]
_CFB8_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _CFB8_ALL_DECRYPT if v.get("is_multiblock")]
```

Add multiblock tests for CFB8 and CFB1 following the same pattern as CFB128.

- [ ] **Step 6: Verify test file syntax**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/aes/test_cfb.py`
Expected: No errors

Run: `python -c "import pkcs11_check.testcases.acvp.aes.test_cfb"`
Expected: No ImportError

---

### Task 4: Test the Implementation

- [ ] **Step 1: Count expected tests**

Run: `python -c "
from pkcs11_check.testcases.acvp.aes.test_cfb import *
print(f'CFB128: {len(_CFB128_MULTIBLOCK_ENCRYPT)} encrypt, {len(_CFB128_MULTIBLOCK_DECRYPT)} decrypt multiblock')
print(f'CFB8: {len(_CFB8_MULTIBLOCK_ENCRYPT)} encrypt, {len(_CFB8_MULTIBLOCK_DECRYPT)} decrypt multiblock')
print(f'CFB1: {len(_CFB1_MULTIBLOCK_ENCRYPT)} encrypt, {len(_CFB1_MULTIBLOCK_DECRYPT)} decrypt multiblock')
"`

Expected:
- CFB128: 3 encrypt, 3 decrypt multiblock (6 total)
- CFB8: ~2-3 encrypt, ~2-3 decrypt multiblock (5 total)
- CFB1: ~2-3 encrypt, ~2-3 decrypt multiblock (5 total)

- [ ] **Step 2: Run a quick smoke test with SoftHSM2**

Run: `bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb128_multiblock_encrypt -v`

Expected: Tests discover and run (may pass or fail depending on SoftHSM2 CFB support)

- [ ] **Step 3: Run full CFB test suite**

Run: `bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/acvp/aes/test_cfb.py -v --tb=short 2>&1 | head -100`

Expected: All tests load and run. Simple tests should pass with SoftHSM2. Multi-block tests may xfail or fail based on module CFB chaining support.

---

## Testing Verification Commands

```bash
# Lint all modified files
uv run ruff check src/pkcs11_check/testcases/acvp/aes/base_loader.py
uv run ruff check src/pkcs11_check/testcases/acvp/aes/base_runner_simple.py
uv run ruff check src/pkcs11_check/testcases/acvp/aes/test_cfb.py

# Check imports work
python -c "from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors"
python -c "from pkcs11_check.testcases.acvp.aes.base_runner_simple import run_multiblock_encrypt_test"
python -c "import pkcs11_check.testcases.acvp.aes.test_cfb"

# Run a subset of tests
docker/test.sh softhsm2 -- src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb128_multiblock_encrypt -v
```

---

## Success Criteria

1. ✅ All 16 multi-block CFB test vectors are loaded (6 CFB128 + 5 CFB8 + 5 CFB1)
2. ✅ Multi-block tests appear in pytest collection
3. ✅ Each block's intermediate result is verified
4. ✅ Simple (single-block) tests continue to work
5. ✅ All files pass ruff linting
6. ✅ No ImportError when loading test module

---

## Notes

- CFB chaining: In CFB mode, ciphertext block N becomes the IV for block N+1
- ACVP vectors with resultsArray test this chaining across 100 blocks
- Each block must produce exact expected output for the test to pass
- The runners maintain a single cryptographic context across all blocks
- Key remains constant across all blocks in a multi-block test
- IV is dynamic (derived from previous ciphertext)
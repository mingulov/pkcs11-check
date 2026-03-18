# CKR Error Coverage & Adaptive Isolation Design

Date: 2026-03-18

## Problem

p11test has 101 test files and 29K+ tests with strong happy-path and security coverage, but systematic per-operation error parameter testing is thin. The PKCS#11 spec defines ~487 (function, error condition) pairs across 65 C_* functions, each with a mandated CKR return code. Current coverage:

- `test_ckr_spec_compliance.py` — 10 tests (6 functions)
- `test_ckr_codes.py` — basic CKR validation
- `test_attribute_fuzz.py` — 11 tests (crash prevention, not CKR compliance)
- `test_errors.py` — general error handling

Missing: systematic per-parameter invalid value tests for most operations, state machine violation tests, NULL parameter tests, device/token error simulation, and error priority ordering tests.

## Design Decisions

### Tiered CKR validation

Tests validate errors at two tiers, controlled by `--ckr-strict` pytest flag:

- **Compat mode (default):** Error must be within an acceptable error tuple (e.g., `MECHANISM_ERRORS`). If the spec-mandated CKR is not returned but an acceptable one is, a compliance note is logged. Tests pass.
- **Strict mode (`--ckr-strict`):** Error must be the exact CKR code the OASIS spec mandates. Deviations are test failures.

Both modes fail on unexpected errors outside the acceptable set (crashes, wrong error category).

### Full coverage — all C_* functions

Every PKCS#11 C_* function gets per-parameter error tests. ~487 spec conditions, ~442 directly Python-testable, ~40 more via ctypes/proxy techniques.

### Organization: `testcases/ckr/` subfolder

One file per operation family. 22 test files + 3 infrastructure files + 1 C proxy module.

### Prerequisites

Before implementing this spec:
- Fix the broad `except PKCS11Error: pass` in `fixtures.py` logout cleanup (replace with specific `(UserNotLoggedIn, SessionClosed)`) — task 7c.4 in master-plan.
- Register `thread_safe` marker in `markers.py` — task 7c.1.

## conftest.py — Flag and Fixtures

```python
# src/p11test/testcases/ckr/conftest.py

import pytest

def pytest_addoption(parser):
    group = parser.getgroup("ckr", "CKR spec compliance options")
    group.addoption(
        "--ckr-strict",
        action="store_true",
        default=False,
        help="Strict CKR compliance: spec deviations are test failures, not notes",
    )

@pytest.fixture
def ckr_strict(request) -> bool:
    """Whether to enforce exact spec CKR codes (True) or accept compatible alternatives (False)."""
    return request.config.getoption("--ckr-strict")
```

New markers to register in `src/p11test/markers.py`:

```python
"subprocess": "Test always runs in isolated subprocess (crash-prone operations)",
"subprocess_per_test": "Each test in file runs in its own subprocess",
```

## File Structure

```
src/p11test/testcases/ckr/
    __init__.py
    _ckr_spec.py              # Centralized spec tables + assertion helpers
    _ctypes_raw.py            # Raw ctypes PKCS#11 caller for NULL param tests
    conftest.py               # --ckr-strict flag, shared fixtures
    test_ckr_general.py       # C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList
    test_ckr_slot_token.py    # C_GetSlotList/Info, C_GetTokenInfo, C_GetMechanismList/Info,
                              #   C_InitToken, C_InitPIN, C_SetPIN, C_WaitForSlotEvent
    test_ckr_session.py       # C_OpenSession, C_CloseSession, C_CloseAllSessions,
                              #   C_GetSessionInfo, C_Login, C_Logout
    test_ckr_object.py        # C_CreateObject, C_CopyObject, C_DestroyObject,
                              #   C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue,
                              #   C_FindObjectsInit/FindObjects/FindObjectsFinal
    test_ckr_encrypt.py       # C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal
    test_ckr_decrypt.py       # C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal
    test_ckr_digest.py        # C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal
    test_ckr_sign.py          # C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecover*
    test_ckr_verify.py        # C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal, C_VerifyRecover*
    test_ckr_keygen.py        # C_GenerateKey, C_GenerateKeyPair
    test_ckr_wrap.py          # C_WrapKey, C_UnwrapKey
    test_ckr_derive.py        # C_DeriveKey
    test_ckr_kem.py           # C_EncapsulateKey, C_DecapsulateKey (v3.2)
    test_ckr_random.py        # C_SeedRandom, C_GenerateRandom
    test_ckr_state.py         # C_GetOperationState, C_SetOperationState
    test_ckr_dual.py          # Cross-operation state machine conflicts
    test_ckr_priority.py      # Error priority ordering (when 2+ conditions overlap)
    test_ckr_null_params.py   # NULL parameter tests via ctypes subprocess
    test_ckr_fault_inject.py  # Fault injection proxy tests

local-builds/fault-proxy/
    fault-proxy.c             # Fault injection PKCS#11 proxy module
local-builds/providers/
    fault-proxy.sh            # Build script for the proxy
```

## Core Data Model: `_ckr_spec.py`

### CkrExpectation dataclass

```python
@dataclass
class CkrExpectation:
    function: str                        # "C_EncryptInit"
    condition: str                       # "wrong_mechanism_for_key_type"
    spec_ckr: type | tuple[type, ...]    # MechanismInvalid or (DataLenRange, DataInvalid)
    compat_tuple: tuple[type, ...]       # MECHANISM_ERRORS (acceptable alternatives)
    spec_ref: str                        # "PKCS#11 v3.1 §5.8.1"
    allow_success: bool = False          # True if permissive modules may accept
    testable: bool = True                # False for NULL-ptr/C-memory conditions
    mechanisms: list[str] | None = None  # If mechanism-specific, which ones
    priority_note: str = ""              # "Higher priority than CKR_DATA_INVALID"
```

When `spec_ckr` is a tuple, the first element is the preferred/higher-priority CKR.

### Universal CKR auto-injection

```python
# Universal CKRs any function may return (spec §5.1.1)
_UNIVERSAL = (GeneralError, HostMemory, FunctionFailed)

# Session-using functions additionally (spec §5.1.2)
_SESSION_UNIVERSAL = (SessionHandleInvalid, DeviceRemoved, SessionClosed)

# Token-using functions additionally (spec §5.1.3)
_TOKEN_UNIVERSAL = (DeviceMemory, DeviceError, TokenNotPresent)

def full_compat(base_tuple: tuple, uses_session: bool = True) -> tuple:
    """Build full acceptable error set from base + universals.

    Duplicates with base_tuple (e.g. FunctionFailed already in most tuples)
    are harmless for isinstance() and kept for clarity — each layer adds
    what the spec says it may return.
    """
    result = base_tuple + _UNIVERSAL
    if uses_session:
        result += _SESSION_UNIVERSAL + _TOKEN_UNIVERSAL
    return result
```

### Assertion helper

```python
def assert_ckr(expectation: CkrExpectation, actual: PKCS11Error, strict: bool) -> None:
    """Validate CKR matches spec (strict) or is in acceptable set (compat)."""
    spec_types = expectation.spec_ckr if isinstance(expectation.spec_ckr, tuple) else (expectation.spec_ckr,)

    if strict:
        if not isinstance(actual, spec_types):
            pytest.fail(
                f"{expectation.function}({expectation.condition}): "
                f"spec requires {[t.__name__ for t in spec_types]}, "
                f"got {type(actual).__name__} [{expectation.spec_ref}]"
            )
    else:
        full = full_compat(expectation.compat_tuple)
        if not isinstance(actual, full):
            pytest.fail(
                f"{expectation.function}({expectation.condition}): "
                f"got {type(actual).__name__}, not in acceptable set"
            )
        if not isinstance(actual, spec_types):
            from p11test.compliance import ComplianceLevel, note
            note(
                f"{expectation.function}({expectation.condition}): "
                f"spec says {[t.__name__ for t in spec_types]}, "
                f"got {type(actual).__name__}",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=expectation.spec_ref,
            )
```

## Spec Tables

The `_ckr_spec.py` module contains all 487 entries organized by operation family as dicts:

```python
CKR_ENCRYPT = {
    "init_unsupported_mechanism": CkrExpectation(
        function="C_EncryptInit",
        condition="mechanism_not_supported",
        spec_ckr=MechanismInvalid,
        compat_tuple=MECHANISM_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "init_key_no_encrypt": CkrExpectation(
        function="C_EncryptInit",
        condition="key_missing_CKA_ENCRYPT",
        spec_ckr=KeyFunctionNotPermitted,
        compat_tuple=(KeyFunctionNotPermitted, KeyTypeInconsistent, MechanismInvalid),
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "init_key_type_inconsistent": CkrExpectation(
        function="C_EncryptInit",
        condition="key_type_wrong_for_mechanism",
        spec_ckr=KeyTypeInconsistent,
        compat_tuple=(KeyTypeInconsistent, MechanismInvalid, KeyFunctionNotPermitted),
        spec_ref="PKCS#11 v3.1 §5.8.1",
    ),
    "data_not_block_aligned": CkrExpectation(
        function="C_Encrypt",
        condition="data_not_multiple_of_block_size",
        spec_ckr=DataLenRange,
        compat_tuple=DATA_ERRORS,
        spec_ref="PKCS#11 v3.1 §5.8.2",
    ),
    # ... etc for all encrypt conditions
}

CKR_DECRYPT = { ... }
CKR_SIGN = { ... }
# ... one dict per operation family, matching the test files
```

The OASIS spec repo (https://github.com/oasis-tcs/pkcs11.git, `working/doc/spec/`) is the source of truth for all entries.

### Condition count per family (approximate)

| File | Functions | Conditions | Python-testable |
|------|-----------|-----------|-----------------|
| test_ckr_encrypt.py | 4 | 49 | 46 |
| test_ckr_decrypt.py | 4 | 43 | 42 |
| test_ckr_sign.py | 6 | 63 | 59 |
| test_ckr_verify.py | 8 | 76 | 71 |
| test_ckr_digest.py | 9 | 68 | 66 |
| test_ckr_keygen.py | 2 | ~30 | ~28 |
| test_ckr_wrap.py | 2 | ~25 | ~23 |
| test_ckr_derive.py | 1 | ~15 | ~14 |
| test_ckr_kem.py | 2 | ~15 | ~14 |
| test_ckr_object.py | 9 | 52 | 48 |
| test_ckr_session.py | 6 | ~50 | ~42 |
| test_ckr_slot_token.py | 9 | 41 | 36 |
| test_ckr_random.py | 2 | 16 | 15 |
| test_ckr_state.py | 2 | ~12 | ~10 |
| test_ckr_general.py | 4 | 16 | 9 |
| test_ckr_dual.py | — | ~20 | ~18 |
| test_ckr_priority.py | — | ~15 | ~15 |
| test_ckr_null_params.py | — | ~20 | 20 (ctypes) |
| test_ckr_fault_inject.py | — | ~20 | 20 (proxy) |
| **Total** | **65** | **~487** | **~482** |

## Test Pattern

Each test file follows a consistent structure:

```python
"""CKR compliance tests for C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal."""

from p11test.testcases.ckr._ckr_spec import CKR_ENCRYPT, assert_ckr
from p11test.testcases._error_tuples import MECHANISM_ERRORS, DATA_ERRORS

pytestmark = pytest.mark.access


class TestEncryptInitErrors:
    """Per-parameter error conditions for C_EncryptInit."""

    def test_unsupported_mechanism(self, p11_session, ckr_strict):
        """Mechanism not supported -> CKR_MECHANISM_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.SHA256)
            pytest.fail("Should have rejected digest mechanism for encrypt")
        except PKCS11Error as e:
            # Broad PKCS11Error catch is intentional here — assert_ckr
            # validates the specific type. This is the ONE place where
            # catching PKCS11Error is correct: we don't know which CKR
            # the module returns, and assert_ckr enforces the rules.
            assert_ckr(CKR_ENCRYPT["init_unsupported_mechanism"], e, ckr_strict)

    def test_key_missing_encrypt_attr(self, p11_session, ckr_strict):
        """Key without CKA_ENCRYPT=True -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.ENCRYPT: False}
        )
        exp = CKR_ENCRYPT["init_key_no_encrypt"]
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
            # Operation succeeded
            if not exp.allow_success:
                pytest.fail("Should have rejected key without ENCRYPT attr")
        except PKCS11Error as e:
            # Even when allow_success=True, if the module rejects,
            # it must reject with the correct CKR code.
            assert_ckr(exp, e, ckr_strict)


class TestEncryptDataErrors:
    """Data-level error conditions for C_Encrypt."""

    @pytest.mark.parametrize("size", [1, 7, 15, 17, 31, 33])
    def test_ecb_non_aligned(self, p11_session, ckr_strict, size):
        """AES-ECB with non-block-aligned data -> CKR_DATA_LEN_RANGE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.encrypt(b"\xAA" * size, mechanism=Mechanism.AES_ECB)
            pytest.fail(f"Should have rejected {size}-byte ECB data")
        except PKCS11Error as e:
            assert_ckr(CKR_ENCRYPT["data_not_block_aligned"], e, ckr_strict)
```

Key patterns:
- One class per C_* function or logical group
- `assert_ckr` is the single validation point
- `allow_success` cases use try/except without `pytest.fail` in the try block
- Mechanism-specific conditions use `@pytest.mark.parametrize`
- Conditions requiring raw C API access marked `@pytest.mark.subprocess`

## Testing "Untestable" Conditions

### Technique A: ctypes Direct Calls (~20 conditions)

For NULL/bad pointer parameters that python-pkcs11 prevents:

```python
# _ctypes_raw.py
class RawPkcs11:
    """Direct ctypes access to C_* functions, bypassing python-pkcs11 safety.

    Targets CK_FUNCTION_LIST v2.40 (68 function pointers after CK_VERSION).
    For v3.x functions, uses C_GetInterface to get CK_FUNCTION_LIST_3_0.
    The struct layout is defined in pkcs11t.h — offsets are stable across
    all compliant implementations.
    """
    def __init__(self, module_path: str):
        self._lib = ctypes.CDLL(module_path)
        # C_GetFunctionList is the only guaranteed exported symbol
        # Extract CK_FUNCTION_LIST pointer, read function pointers at offsets

    def call(self, func_name: str, *args) -> int:
        """Call C_* function with raw args. Returns CK_RV as int."""
```

All ctypes tests run in subprocess — modules may segfault on NULL instead of returning CKR. Segfault is also a valid finding (module fails to validate parameters). If the fault-proxy `.so` is not built, tests in `test_ckr_fault_inject.py` skip gracefully (check for file at collection time).

### Technique B: Fault-Injection Proxy (~15 conditions)

A minimal C proxy (`local-builds/fault-proxy/fault-proxy.c`, ~300 lines):

1. Loads real module via `PKCS11_REAL_MODULE` env var
2. Delegates all calls to real module
3. Reads `PKCS11_INJECT_ERROR` and `PKCS11_INJECT_FUNCTION` env vars
4. When target function is called, returns injected CKR instead of delegating

Covers: `CKR_DEVICE_REMOVED`, `CKR_DEVICE_ERROR`, `CKR_DEVICE_MEMORY`, `CKR_TOKEN_NOT_PRESENT`, `CKR_TOKEN_NOT_RECOGNIZED`.

Fault-proxy tests MUST use `_ctypes_raw.py` (not python-pkcs11) because the wrapper caches internal state (session handles, operation state) that becomes inconsistent when the proxy injects errors mid-operation.

### Technique C: Process Killing (~5 conditions)

For networked tokens, kill server process mid-session:
- BouncyHSM: kill .NET server -> real device removal
- tpm2-pkcs11 + swtpm: kill swtpm daemon -> real TPM disappearance

### Coverage summary

| Technique | Conditions covered | Effort |
|-----------|-------------------|--------|
| Python-testable (direct) | ~442 | Bulk of work |
| A: ctypes raw calls | ~20 | 4-6 hrs |
| B: Fault-injection proxy | ~15 | 6-8 hrs |
| C: Process killing | ~5 | 2-3 hrs |
| **Total testable** | **~482 / 487 (99%)** | |

Remaining ~5 untestable: mutex callbacks, cancel from within callback, implementation-internal.

## Adaptive Isolation Model

### Problem

CKR tests probe error conditions where buggy modules are most likely to crash. A single segfault shouldn't kill the entire 400-test run.

### Solution: Start fast, escalate on crash

No configuration flag needed. The runner adapts automatically:

**Mode 1: In-process sequential (default)**
- Normal pytest. Tests run in same process, one after another.
- Fastest. No subprocess overhead. Full pytest features.

**Mode 2: Per-file subprocess (after first crash)**
- After segfault/SIGBUS/SIGABRT kills a test, runner restarts in per-file mode.
- Each test file runs in its own subprocess (~0.5s overhead per file).
- Crash in one file doesn't kill the rest.

**Mode 3: Per-test subprocess (for crashed files)**
- Files that crashed in Mode 2 get re-run with each individual test in its own subprocess.
- Identifies exactly which test condition caused the crash.

### Flow

```
p11test test --module softhsm2.so

1. Mode 1 (in-process)
   test_ckr_encrypt.py .......... 35 passed
   test_ckr_decrypt.py .......... 28 passed
   test_ckr_null_params.py ...... CRASH (SIGSEGV)

   *** Switching to Mode 2 ***

2. Mode 2 (per-file subprocess)
   test_ckr_sign.py ............. 32 passed  [subprocess]
   test_ckr_fault_inject.py ..... CRASH      [subprocess]
     -> Re-run Mode 3 (per-test)
        test_device_removed ..... CRASH -> recorded
        test_device_memory ...... passed
   test_ckr_keygen.py ........... 41 passed  [subprocess]

3. Report: passed/failed/skipped/crash for everything
```

### Markers for forced isolation

```python
@pytest.mark.subprocess          # Always run in subprocess (ctypes, fault injection)
@pytest.mark.subprocess_per_test # Always per-test subprocess
```

Tests in `test_ckr_null_params.py` and `test_ckr_fault_inject.py` are always `@subprocess`.

### Implementation: outer orchestrator, not pytest plugin

A crash (SIGSEGV) kills the entire pytest process — no hook can intercept it from inside. The adaptive isolation lives in the **`p11test test` CLI command** (`src/p11test/cli/test_cmd.py`), which is an outer process that launches pytest as a subprocess:

```python
# src/p11test/cli/test_cmd.py (simplified)
class AdaptiveRunner:
    """Outer orchestrator that survives child crashes."""

    def run(self, test_paths, module, pin, ...):
        # Phase 1: try in-process (fast)
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *test_paths, ...],
            timeout=timeout,
        )
        if result.returncode >= 0:
            return result  # Clean exit (pass or fail, no crash)

        # Phase 2: crash detected — re-run per-file
        crashed_signal = -result.returncode
        self.crash_log.append(("phase1", crashed_signal))
        remaining = self._collect_remaining_files(test_paths, result)

        for test_file in remaining:
            file_result = subprocess.run(
                [sys.executable, "-m", "pytest", test_file, ...],
                timeout=timeout,
            )
            if file_result.returncode < 0:
                # Phase 3: file crashed — re-run per-test
                self._run_per_test(test_file)
            else:
                self._merge_results(file_result)

        return self._final_report()
```

The existing `core/isolation.py` `IsolatedRunner` is NOT reused — it uses `multiprocessing.Process` with fork semantics which is unsuitable for crash survival. The `AdaptiveRunner` uses `subprocess.run` (clean child process) like `test_subprocess_safety.py` already does.

### Subprocess marker handling in plugin

Tests marked `@subprocess` are collected by pytest but deferred to the outer runner:

```python
# In plugin.py
def pytest_collection_modifyitems(config, items):
    subprocess_items = [i for i in items if "subprocess" in i.own_markers]
    for item in subprocess_items:
        item.add_marker(pytest.mark.skip(reason="deferred to AdaptiveRunner"))
    # AdaptiveRunner runs these separately in isolated subprocesses
```

## Migration

- `test_ckr_spec_compliance.py` (10 tests) -> absorbed into `ckr/` files, then deleted
- `test_ckr_codes.py` -> absorbed into `ckr/` files, then deleted
- `test_attribute_fuzz.py` -> stays (crash prevention, not CKR compliance)
- `test_errors.py` -> stays (general error handling, different purpose)
- `_error_tuples.py` -> reused by `_ckr_spec.py`, not duplicated

## Scope

- ~487 spec conditions documented in `_ckr_spec.py`
- ~482 testable (442 Python + 20 ctypes + 15 proxy + 5 process-kill)
- ~350-400 pytest tests (some 1:1, some parametrized across mechanisms)
- 22 test files + 3 infrastructure + 1 C proxy
- All tests get `pytest.mark.access` marker
- `--ckr-strict` flag orthogonal to markers

## PKCS#11 Spec Reference

Source of truth for all CKR tables and error conditions:
- Repo: https://github.com/oasis-tcs/pkcs11.git
- Spec docs: `working/doc/spec/` (Markdown format)
- Key files: `function_return_values.md`, `encryption_functions.md`, `decryption_functions.md`, `signing_and_macing_functions.md`, `functions_for_verifying_signatures_and_macs.md`, `message_digesting_functions.md`, `key_management_functions.md`, `object_mgmt_functions.md`, `session_mgmt_functions.md`, `slot_and_token_mgmt_functions.md`, `random_number_generation_functions.md`, `general_purpose_functions.md`

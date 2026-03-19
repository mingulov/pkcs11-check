# Raw PKCS#11 Full Coverage Design

Date: 2026-03-19

## Problem

pkcs11-check has 244/487 CkrExpectation entries (50.1%), but 48 are marked `testable=False` because the python-pkcs11 wrapper prevents triggering them. Another ~94 conditions are achievable with raw ctypes access, destructive subprocess tests, and an upgraded fault-proxy. Total achievable: ~338/487 (69.4%).

## Solution: Three Components

### 1. `pkcs11/raw.py` — Full CK_FUNCTION_LIST ctypes wrapper

Pure Python module in the python-pkcs11 fork. No dependencies on fork internals — self-contained, movable to another project.

**API:**
```python
class RawPKCS11:
    def __init__(self, funclist_ptr: int, lib_path: str | None = None,
                 funclist3_ptr: int = 0, funclist32_ptr: int = 0): ...

    # All 68 v2.40 C_* functions as methods returning CK_RV (int)
    def C_Initialize(self, pInitArgs=None) -> int: ...
    def C_Finalize(self, pReserved=None) -> int: ...
    def C_EncryptInit(self, hSession, pMechanism, hKey) -> int: ...
    def C_Encrypt(self, hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen) -> int: ...
    def C_EncryptUpdate(self, ...) -> int: ...
    def C_EncryptFinal(self, ...) -> int: ...
    # ... all functions

    # Standalone mode: pass lib_path to load module independently
```

**Properties:**
- Returns raw CK_RV (int), never raises — test decides what's expected
- All args are ctypes types (c_ulong, c_void_p, POINTER)
- Helper constants: CKR_OK, CKR_ARGUMENTS_BAD, CKF_SERIAL_SESSION, etc.
- Helper structs: CK_MECHANISM, CK_ATTRIBUTE for building params
- ~400 lines total

**Self-contained:** Zero imports from pkcs11 package. Can be moved to separate package with one import-path change.

**Connection to fork:** Uses `lib._raw_funclist_ptr` / `lib._raw_funclist3_ptr` / `lib._raw_funclist32_ptr` as entry points.

### 2. Upgraded fault-proxy with C-level injection

Current `fault-proxy.c` is pass-through. Upgrade to intercept all 68 C_* functions:

```c
// For each function:
CK_RV C_Encrypt(CK_SESSION_HANDLE h, ...) {
    if (should_inject("C_Encrypt")) return inject_error;
    return real_funcs->C_Encrypt(h, ...);
}
```

~600 lines of C. Enables testing CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED on any function.

### 3. Destructive subprocess test pattern

For InitToken, InitPIN, SetPIN, PIN lockout — each test runs in subprocess with a temporary token:

```python
@pytest.mark.subprocess
@pytest.mark.destructive
def test_init_token_session_exists(p11_config):
    result = subprocess.run([sys.executable, "-c", script], ...)
```

Temporary token created/destroyed per test. Main test token untouched.

## Categories Unlocked

| Category | Conditions | Technique |
|----------|-----------|-----------|
| Multipart operations | ~20 | `RawPKCS11` ctypes calls |
| Attribute permission violations | ~10 | `RawPKCS11` bypasses wrapper checks |
| Operation state violations | ~8 | `RawPKCS11` double-Init, cross-op |
| Buffer sizing errors | ~6 | `RawPKCS11` with small buffers |
| Destructive token ops | ~25 | Subprocess + temp token |
| Hardware events | ~15 | Upgraded fault-proxy |
| Truly untestable | ~10 | Documented only |
| **Total new testable** | **~94** | |

## Coverage Projection

- Current: 244/487 (50.1%)
- After raw.py: +44 conditions → 288/487 (59.1%)
- After fault-proxy upgrade: +15 conditions → 303/487 (62.2%)
- After destructive subprocess: +25 conditions → 328/487 (67.4%)
- Truly untestable: ~10 (mutex callbacks, CKR_CANCEL, CKR_PENDING, legacy parallel)
- Universal CKRs: ~149 (covered by full_compat(), not individual entries)
- **Maximum achievable: ~338/487 (69.4%)**

## File Structure

```
python-pkcs11/
  pkcs11/
    raw.py                    # NEW: full CK_FUNCTION_LIST ctypes wrapper

local-builds/
  fault-proxy/
    fault-proxy.c             # UPGRADE: all 68 functions with injection

src/pkcs11-check/testcases/ckr/
    _ctypes_raw.py            # UPDATE: use RawPKCS11 instead of manual offsets
    test_ckr_multipart.py     # NEW: multipart operation error tests
    test_ckr_raw_attrs.py     # NEW: attribute permission tests via raw calls
    test_ckr_raw_state.py     # NEW: operation state violation tests
    test_ckr_raw_buffer.py    # NEW: buffer sizing tests
    test_ckr_destructive.py   # NEW: InitToken/PIN tests in subprocess
    test_ckr_fault_inject.py  # UPDATE: real injection tests
```

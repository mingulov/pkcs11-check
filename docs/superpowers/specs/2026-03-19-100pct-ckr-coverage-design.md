# 100% CKR Coverage Design

Date: 2026-03-19

## Definition of 100%

- **575 function-specific CkrExpectation entries** — one per non-universal CKR code per C_* function
- **12 universal CKR verification tests** — prove infrastructure handles CKR_GENERAL_ERROR, CKR_HOST_MEMORY, etc.
- **Total: 587 entries** in `_ckr_spec.py`
- Currently: 244 entries. Gap: **343 entries to add.**

Source: OASIS PKCS#11 spec, 76 C_* functions, 1334 total CKR entries, 575 function-specific.

## Universal CKR Handling

12 universal CKR codes appear across every function. They are NOT duplicated as individual entries. Instead:

1. `full_compat()` already injects them into every compat tuple
2. A new `test_ckr_universal.py` verifies each universal CKR is:
   - Present in `_UNIVERSAL`, `_SESSION_UNIVERSAL`, or `_TOKEN_UNIVERSAL`
   - Handled by `full_compat()`
   - Triggered at least once on a real module (via fault-proxy or real condition)
3. Coverage report counts: 575 specific + "12 universal (verified via infrastructure)" = 587

## Gap Breakdown

### New function families needed (not yet in any dict)

| Functions | CKR Count | Dict Name |
|-----------|----------|-----------|
| C_DecryptFinal | 8 | Add to CKR_DECRYPT |
| C_EncryptFinal | 6 | Add to CKR_ENCRYPT |
| C_VerifySignatureInit/Update/Final | 28 | New CKR_VERIFY_SIGNATURE |
| C_DigestXofInit/Update/Extract/Final/KeyValue | 23 | New CKR_DIGEST_XOF |
| C_SessionCancel | 2 | Add to CKR_SESSION |
| C_LoginUser | 12 | Add to CKR_SESSION |
| C_WrapKeyAuthenticated/UnwrapKeyAuthenticated | 46 | New CKR_WRAP_AUTH |
| C_GetInterface/C_GetInterfaceList | 4 | Add to CKR_GENERAL |
| C_GetSessionValidationFlags | 1 | Add to CKR_SESSION |
| C_EncapsulateKey/C_DecapsulateKey (remaining) | ~15 | Add to CKR_KEM |

### Existing dicts needing more entries

Per-function analysis shows most dicts are 40-70% complete. The remaining entries are mostly:
- `CKR_FUNCTION_CANCELED` (every *Init function)
- `CKR_PIN_EXPIRED` (every session-using function)
- `CKR_USER_NOT_LOGGED_IN` (every key-using function)
- `CKR_OPERATION_ACTIVE` (every *Init function)
- Mechanism-specific variants not yet covered

## Implementation Strategy

### Phase 1: Batch-add all missing entries to `_ckr_spec.py` (~331 entries)

Mechanical expansion — read each function's Return values list, add an entry for every specific CKR not yet present. Most entries will be `testable=False` initially for conditions requiring raw ctypes or special setup. This gets us to 575.

### Phase 2: Convert testable=False → testable=True (~90 entries)

Using `RawPKCS11`:
- All multipart operations (Update/Final without Init)
- Operation state violations (double Init, cross-op)
- Buffer sizing (too-small output)
- Attribute permission violations (CKA_ENCRYPT=False etc)

### Phase 3: Destructive subprocess tests (~25 entries)

Using subprocess + temporary token:
- C_InitToken with session open, wrong PIN
- C_InitPIN without SO login
- C_SetPIN wrong old PIN, too-short new PIN
- PIN lockout tests

### Phase 4: Fault-proxy upgrade (~15 entries)

Upgrade fault-proxy.c to intercept all functions. Test:
- CKR_DEVICE_REMOVED on any operation
- CKR_DEVICE_ERROR on any operation
- CKR_TOKEN_NOT_PRESENT

### Phase 5: Universal CKR tests + documentation

- `test_ckr_universal.py` with 12 parametrized tests
- Coverage report update

### Phase 6: Truly untestable (~10 entries)

Document as intentionally excluded with rationale:
- CKR_MUTEX_BAD/NOT_LOCKED (custom mutex callbacks)
- CKR_CANCEL (application callback)
- CKR_FUNCTION_NOT_PARALLEL (deprecated legacy)
- CKR_PENDING (async, v3.2 experimental)

Mark as `testable=False, rationale="..."` in spec table.

## File Changes

```
python-pkcs11/pkcs11/raw.py            # Already done

src/p11test/testcases/ckr/
    _ckr_spec.py                        # +331 entries (244→575)
    test_ckr_universal.py               # NEW: 12 universal CKR verification tests
    test_ckr_raw_multipart.py           # Already done (6 tests)
    test_ckr_raw_state.py               # Already done (3 tests)
    test_ckr_raw_buffer.py              # Already done (2 tests)
    test_ckr_raw_attrs.py               # NEW: attribute permission via raw (~5 tests)
    test_ckr_destructive.py             # NEW: InitToken/PIN subprocess tests (~10 tests)
    test_ckr_verify_signature.py        # NEW: v3.0+ VerifySignature* tests
    test_ckr_digest_xof.py             # NEW: v3.0+ DigestXof* tests (if supported)
    test_ckr_wrap_auth.py              # NEW: v3.2 WrapKeyAuthenticated tests

local-builds/fault-proxy/
    fault-proxy.c                       # UPGRADE: all 68 functions with injection
```

## Coverage Projection

| Phase | Entries | Tests | Coverage |
|-------|---------|-------|---------|
| Current | 244 | 119 | 42.4% of 575 |
| Phase 1 (batch add) | 575 | 119 | 100% entries, 42% tested |
| Phase 2 (raw tests) | 575 | ~165 | 100% entries, ~60% tested |
| Phase 3 (destructive) | 575 | ~190 | 100% entries, ~70% tested |
| Phase 4 (fault-proxy) | 575 | ~205 | 100% entries, ~75% tested |
| Phase 5 (universal) | 587 | ~217 | 100% documented |
| Phase 6 (untestable) | 587 | ~217 | 100% — with ~10 documented exclusions |

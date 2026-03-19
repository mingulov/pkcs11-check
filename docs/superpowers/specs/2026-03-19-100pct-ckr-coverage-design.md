# 100% CKR Coverage Design

Date: 2026-03-19

## Definition of 100%

**Every function-specific CKR code listed in the OASIS PKCS#11 spec has a CkrExpectation entry.** No fixed target number — the spec is the source of truth. A validation script continuously checks for gaps.

The OASIS spec defines ~100+ C_* functions (v2.40 + v3.0 message-based + v3.2 KEM/async) with ~800+ function-specific CKR entries (excluding universals). Currently: 244 entries across 15 dicts.

### What counts as "covered"

- **Function-specific CKR**: has a CkrExpectation entry in `_ckr_spec.py` with correct spec_ref
- **Universal CKR** (CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_FUNCTION_FAILED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_TOKEN_NOT_PRESENT, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_OPERATION_NOT_VALIDATED, CKR_TOKEN_NOT_INITIALIZED, CKR_OK, CKR_PENDING): covered by `full_compat()` + infrastructure tests
- **Truly untestable**: documented with rationale (CKR_MUTEX_BAD, CKR_CANCEL, CKR_FUNCTION_NOT_PARALLEL)

### Validation script

`scripts/ckr-coverage-check.py` parses the OASIS spec, extracts ALL (function, CKR) pairs, compares against `_ckr_spec.py`, and reports gaps. Run after every batch to ensure nothing is missed.

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

| Family | Functions | Dict Name |
|--------|-----------|-----------|
| v3.0 VerifySignature | C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate, C_VerifySignatureFinal | New CKR_VERIFY_SIGNATURE |
| v3.0 DigestXof | C_DigestXofInit, C_DigestXof, C_DigestXofUpdate, C_DigestXofExtract, C_DigestXofFinal, C_DigestXofKeyValue | New CKR_DIGEST_XOF |
| v3.0 Message-based encrypt | C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal | New CKR_MSG_ENCRYPT |
| v3.0 Message-based decrypt | C_MessageDecryptInit, C_DecryptMessage, etc. | New CKR_MSG_DECRYPT |
| v3.0 Message-based sign | C_MessageSignInit, C_SignMessage, etc. | New CKR_MSG_SIGN |
| v3.0 Message-based verify | C_MessageVerifyInit, C_VerifyMessage, etc. | New CKR_MSG_VERIFY |
| v3.2 Authenticated wrap | C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated | New CKR_WRAP_AUTH |
| v3.2 Async | C_AsyncComplete, C_AsyncGetID, C_AsyncJoin | New CKR_ASYNC |
| Dual-function | C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate | New CKR_DUAL |
| Legacy parallel | C_GetFunctionStatus, C_CancelFunction | Add to CKR_GENERAL |
| Session extras | C_SessionCancel, C_LoginUser, C_GetSessionValidationFlags | Add to CKR_SESSION |
| Interface | C_GetInterface, C_GetInterfaceList | Add to CKR_GENERAL |

### Existing dicts needing more entries

All 15 existing dicts are 40-70% complete. Common missing entries:
- `CKR_FUNCTION_CANCELED` (every *Init function)
- `CKR_PIN_EXPIRED` (every session-using function)
- `CKR_USER_NOT_LOGGED_IN` (every key-using function)
- `CKR_OPERATION_ACTIVE` (every *Init function)
- Mechanism-specific variants (RSA-PSS params, AES-GCM IV, ECDH KDF, etc.)
- All C_*Update/C_*Final entries for multipart operations

### Special cases

- **C_AsyncComplete**: return values are dynamic (same as the function it completes). Document as special case, not individual entries.
- **C_GetFunctionStatus / C_CancelFunction**: legacy, always return CKR_FUNCTION_NOT_PARALLEL. One entry each.
- **C_LoginUser**: same CKR set as C_Login. Can share entries or duplicate.

## Implementation Strategy

### Phase 0: Validation script

Create `scripts/ckr-coverage-check.py` that:
1. Parses ALL spec files in `/tmp/pkcs11/working/doc/spec/`
2. Extracts every `### C_*` function and its `Return values:` CKR list
3. Loads `_ckr_spec.py` and checks which (function, CKR) pairs exist
4. Reports: covered / missing / universal / total
5. Run after every batch to track progress toward 100%

### Phase 1: Batch-add all missing entries to `_ckr_spec.py`

Split into sub-batches by function family (one commit per dict expansion):
- 1a: Expand existing 15 dicts to full coverage
- 1b: Add new dicts for v3.0 families (VerifySignature, DigestXof, message-based)
- 1c: Add new dicts for v3.2 families (WrapAuth, Async)
- 1d: Add dual-function, legacy, session extras

After each sub-batch: run validation script to track progress. Most new entries start as `testable=False`.

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
scripts/ckr-coverage-check.py           # NEW: validation script — the source of truth

python-pkcs11/pkcs11/raw.py            # Already done

src/pkcs11-check/testcases/ckr/
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
    test_ckr_msg_encrypt.py            # NEW: v3.0 message-based encrypt tests
    test_ckr_msg_decrypt.py            # NEW: v3.0 message-based decrypt tests
    test_ckr_msg_sign.py               # NEW: v3.0 message-based sign tests
    test_ckr_msg_verify.py             # NEW: v3.0 message-based verify tests

local-builds/fault-proxy/
    fault-proxy.c                       # UPGRADE: all 68 functions with injection
```

## Coverage Projection

| Phase | What | Outcome |
|-------|------|---------|
| Phase 0 | Validation script | Exact gap count known |
| Phase 1a-d | Batch-add entries | 100% entries in spec table, most testable=False |
| Phase 2 | Raw ctypes tests | ~60% entries have real tests |
| Phase 3 | Destructive subprocess | ~70% entries have real tests |
| Phase 4 | Fault-proxy upgrade | ~75% entries have real tests |
| Phase 5 | Universal infrastructure | All CKRs verified at least once |
| Phase 6 | Document untestable | 100% — every entry documented, ~10 with exclusion rationale |

**"100% coverage" = validation script reports 0 missing entries + all testable entries have tests + untestable entries have rationale.**

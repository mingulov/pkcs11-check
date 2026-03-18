# CKR Error Coverage Matrix

Generated: 2026-03-19

## Summary

- **_ckr_spec.py entries:** 40
- **Test files:** 21 (in `testcases/ckr/`)
- **Tests collected:** 102
- **Spec functions:** ~81 C_* functions across 11 spec files
- **Coverage:** ~40/487 conditions = **8.2%** of full spec

## Per-Family Coverage

| Family | File | Spec Entries | Tests | Spec Functions | Tested Functions |
|--------|------|-------------|-------|----------------|-----------------|
| Encrypt | test_ckr_encrypt.py | 9 | 12 | 4 (Init/Encrypt/Update/Final) | 2 (Init, Encrypt) |
| Decrypt | test_ckr_decrypt.py | 6 | 10 | 4 | 2 (Init, Decrypt) |
| Sign | test_ckr_sign.py | 4 | 4 | 6 (Init/Sign/Update/Final/RecoverInit/Recover) | 2 (Init, Sign) |
| Verify | test_ckr_verify.py | 4 | 4 | 10 (Init/Verify/Update/Final/Recover*) | 2 (Init, Verify) |
| Digest | test_ckr_digest.py | 3 | 3 | 11 (Init/Digest/Update/Key/Final/Xof*) | 1 (Init) |
| KeyGen | test_ckr_keygen.py | 7 | 8 | 2 (GenerateKey/GenerateKeyPair) | 2 |
| Wrap | test_ckr_wrap.py | 0 | 3 | 2 (WrapKey/UnwrapKey) | 2 |
| Derive | test_ckr_derive.py | 3 | 2 | 1 (DeriveKey) | 1 |
| KEM | test_ckr_kem.py | 4 | 4 | 2 (Encapsulate/Decapsulate) | 2 |
| Object | test_ckr_object.py | 0 | 7 | 9 (Create/Copy/Destroy/GetSize/GetAttr/SetAttr/Find*) | 5 |
| Session | test_ckr_session.py | 0 | 4 | 11 (Open/Close/CloseAll/GetInfo/Login/Logout/...) | 3 |
| Slot/Token | test_ckr_slot_token.py | 0 | 2 | 9 (GetSlotList/Info/TokenInfo/MechList/MechInfo/...) | 2 |
| Random | test_ckr_random.py | 0 | 3 | 2 (SeedRandom/GenerateRandom) | 2 |
| General | test_ckr_general.py | 0 | 3 | 6 (Initialize/Finalize/GetInfo/GetFuncList/...) | 3 |
| State | test_ckr_state.py | 0 | 2 | 2 (GetOperationState/SetOperationState) | 2 |
| Dual | test_ckr_dual.py | 0 | 5 | — (cross-operation) | — |
| Priority | test_ckr_priority.py | 0 | 3 | — (priority ordering) | — |
| NULL params | test_ckr_null_params.py | 0 | 4 | — (NULL pointer) | 4 |
| Fault inject | test_ckr_fault_inject.py | 0 | 2 | — (proxy tests) | — |
| Legacy codes | test_ckr_codes.py | 0 | 7 | — (migrated) | — |
| Legacy compliance | test_ckr_spec_compliance.py | 0 | 10 | — (migrated) | — |

## Major Gaps (functions with zero or minimal CKR testing)

### Not yet in _ckr_spec.py (0 entries)
- C_EncryptUpdate / C_EncryptFinal
- C_DecryptUpdate / C_DecryptFinal
- C_SignUpdate / C_SignFinal / C_SignRecoverInit / C_SignRecover
- C_VerifyUpdate / C_VerifyFinal / C_VerifyRecoverInit / C_VerifyRecover
- C_Digest / C_DigestUpdate / C_DigestKey / C_DigestFinal
- C_WrapKey / C_UnwrapKey (tests exist but no spec entries)
- C_CopyObject / C_GetObjectSize
- C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
- C_OpenSession / C_CloseSession / C_CloseAllSessions / C_GetSessionInfo
- C_Login / C_Logout (tests exist but no spec entries)
- C_InitToken / C_InitPIN / C_SetPIN
- C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo
- C_GetMechanismList / C_GetMechanismInfo
- C_WaitForSlotEvent
- C_SeedRandom / C_GenerateRandom (tests exist but no spec entries)
- C_GetOperationState / C_SetOperationState (tests exist but no spec entries)

### Conditions tested but not in spec table
Many test files (object, session, slot, random, state, dual, priority, null, fault)
have tests but no corresponding CkrExpectation entries in _ckr_spec.py. These
tests validate behavior but don't use the assert_ckr() tiered validation.

## Module Validation Results

| Module | Passed | Failed | Skipped | xfail | Strict deviations |
|--------|--------|--------|---------|-------|-------------------|
| SoftHSM2 2.7.0 | 97 | 0 | 6 | 0 | 11 |
| Kryoptic 1.5.0+PQC | 99 | 0 | 3 | 1 | ~similar |
| NSS softokn | 91 | 5 (slot-0) | 7 | 0 | N/A |
| OpenCryptoki 3.26 | 90 | 0 | 6 | 0 | N/A |
| pkcs11-mock 2.0.0 | 10 | 7 | 6 | 0 | N/A |

## Next Steps

1. Add CkrExpectation entries for all tested-but-untracked conditions
2. Add multipart operation error tests (Update/Final for each family)
3. Add session/slot/token management spec entries
4. Add C_CopyObject, C_GetObjectSize, C_FindObjects* error tests
5. Add C_InitToken, C_InitPIN, C_SetPIN error tests (marked @destructive)

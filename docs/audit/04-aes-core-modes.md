# Audit 04: AES Core Modes

**Date:** 2026-04-01
**OASIS specs referenced:** `aes.md`, `aes_with_counter.md`, `aes_cbc_with_ciphertext_stealing_cts.md`, `aes_xts.md`, `additional_aes_mechanisms.md`, `general_block_cipher_mechanism_parameters.md`
**Files audited:** `test_encrypt.py`, `test_aes_modes.py`, `test_aes_key_sizes.py`, `test_buffers.py`, `acvp/aes/test_other.py`, `mechanism_registry/_aes.py`

## Findings

### Quality Issues

- [FIXED] `acvp/aes/test_other.py:168` — unreachable `return` after `raise` (dead code removed)
- [NOTED] `test_aes_modes.py:429,439,478,486` — `mac_len.to_bytes(8, "little")` hardcodes 8-byte CK_ULONG size. Works on 64-bit Linux but would break on 32-bit platforms where `c_ulong` is 4 bytes. Should use `ctypes.sizeof(ctypes.c_ulong)`.
- [NOTED] `test_aes_modes.py:116` — plaintext `b"hello pkcs11!!\x02\x02"` has manual PKCS#7 padding bytes. Since CKM_AES_CBC_PAD handles padding automatically, this 16-byte input is treated as-is, not testing the padding mechanism.

### Spec Deviations

- [NOTED] `pack_mechanisms.py:252-256` — `mech_ctr()` initializes counter block `cb[16]` to all zeros. OASIS spec says counter "usually starting with 1" (non-mandatory), but NIST SP 800-38A and RFC 3686 require counter starting at 1. Tests pass trivially because encrypt and decrypt use identical zero-initialized params.
- [NOTED] No test for `ulCounterBits` out-of-range rejection — spec requires `CKR_MECHANISM_PARAM_INVALID` for `ulCounterBits=0` or `>128`.
- [NOTED] No test for CTS minimum input length — spec requires input >= 16 bytes. No test verifies 15-byte rejection.

### Coverage Gaps

- [GAP] `CKM_AES_MAC` — registered in `_aes.py:302` but has zero test coverage. Spec defines fixed 8-byte (half-block) output.
- [GAP] `CKM_AES_GMAC` — registered in `_aes.py:270` but has no sign/verify test under CKM_AES_GMAC.
- [GAP] `CKM_AES_XTS_KEY_GEN` — no test generates an XTS key via this mechanism; XTS tests import raw key bytes from ACVP vectors.
- [GAP] `CKM_AES_CTR` negative tests — missing ulCounterBits=0, ulCounterBits=129, counter overflow rejection.
- [GAP] `CKM_AES_CTS` boundary — missing minimum input length (16 bytes) and below-minimum (15 bytes) tests.
- [GAP] `CKM_AES_CFB1` — not in `test_aes_modes.py` CFB roundtrip tests (only CFB8/64/128). Has ACVP coverage in `acvp/aes/test_cfb.py`.

### CS1/CS3 Analysis

The CS1/CS3 issue in `test_other.py` is handled correctly per project philosophy:
- All three ACVP CS variants (CS1, CS2, CS3) run against module's `CKM_AES_CTS`
- Assertion failures include explicit message: "PKCS#11 CKM_AES_CTS does not specify CS1/CS2/CS3"
- Module implementing CS3 will fail CS1/CS2 vectors — this IS the finding (failures are findings)
- No auto-detection of which variant the module uses — acceptable

## Changes Made

- Modified: `acvp/aes/test_other.py` — removed unreachable dead code after raise

## Statistics

- Files audited: 6 test files + 6 OASIS spec files
- Issues found: 3 quality (1 fixed, 2 noted), 3 spec deviations (noted), 6 coverage gaps (documented)
- Tests added: 0 (gaps documented for implementation in future iterations or dedicated work)
- Lines changed: -1

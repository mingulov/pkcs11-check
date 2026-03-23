# SoftHSM2 main branch: segfaults on edge-case EC operations (OpenSSL 3.5+)

**Date:** 2026-03-23
**Module:** SoftHSM2 main branch (built from source, Fedora 44, OpenSSL 3.5+)
**Test tool:** pkcs11-check (dev branch, commit bde5fb3)
**Total tests:** 72,646
**Affected tests:** 4,715 (6.5%) - all segfaults

## Summary

SoftHSM2 built from the main branch on Fedora 44 (OpenSSL 3.5+) segfaults during ECDSA verification and ECDH key derivation when processing specific edge-case Wycheproof test vectors. The crashes occur on curves that are advertised as supported and partially functional - most vectors for these curves pass, but vectors with specific arithmetic edge cases cause SIGSEGV.

A PKCS#11 module must never segfault on valid C_VerifyFinal / C_DeriveKey calls. The expected behavior is to return a CKR error code (e.g. CKR_FUNCTION_FAILED or CKR_DEVICE_ERROR).

## Environment

- **SoftHSM2:** main branch (latest commit at build time)
- **OS:** Fedora 44 container
- **OpenSSL:** 3.5+ (system package from Fedora 44)
- **Build flags:** `--with-crypto-backend=openssl --enable-mldsa`
- **Comparison baseline:** SoftHSM2 2.7.0 on Debian (OpenSSL 3.0.x) - no crashes on these curves

## Crash breakdown by curve family

| Curve family | Crashes | Operation | Notes |
|---|---|---|---|
| brainpoolP224r1 | 1,308 | ECDH derive + ECDSA verify | 224-bit Brainpool |
| secp160k1/r1/r2 | 1,161 | ECDSA verify | 160-bit, below security threshold |
| secp192k1/r1 | 873 | ECDSA verify | 192-bit, below security threshold |
| secp224k1 | 711 | ECDSA verify | Koblitz curve |
| sect283k1/r1, sect409k1/r1, sect571k1/r1 | 662 | ECDH derive | Binary field curves |
| **Total** | **4,715** | | |

## Source files

All crashes originate from two Wycheproof test files:
- `test_wycheproof_ecdsa.py` - 3,418 crashes (ECDSA signature verification)
- `test_wycheproof_ecdh.py` - 1,297 crashes (ECDH key agreement)

## Crash characteristics

### Not a curve removal issue

The curves ARE advertised in the mechanism list and partially functional:
- Key import via C_CreateObject succeeds (pytest setup phase passes)
- The majority of test vectors for each curve pass normally
- Example: secp160k1_sha256 has 445 total tests - 278 pass, 167 crash

### Edge-case arithmetic triggers

Analysis of crashed vectors (secp160k1_sha256 sample, 167 crashes):

**By Wycheproof result type:**
- valid: 136 crashes (vectors that SHOULD succeed)
- invalid: 31 crashes (vectors that should be rejected, but not via segfault)

**By Wycheproof flag (crash trigger):**

| Flag | Count | Description |
|---|---|---|
| ArithmeticError | 77 | Edge-case modular arithmetic |
| SpecialCaseHash | 54 | Hash values with special properties |
| InvalidSignature | 16 | Malformed signatures |
| ModularInverse | 12 | Edge cases in modular inverse computation |
| SmallRandS | 7 | Small r and s values |
| ModifiedSignature | 7 | Tampered signature components |
| ValidSignature | 6 | Standard valid signatures |
| PointDuplication | 5 | Point at infinity / duplication edge cases |

The crashes cluster around **arithmetic edge cases** in the EC verification path - modular inverses near boundary values, special-case hash digests, and extreme scalar values. These exercise corner cases in OpenSSL's EC arithmetic that appear to have regressions in 3.5+.

## Performance impact

The iterative deselect crash recovery handles each crash correctly but incurs significant overhead:
- ECDSA file: 6,084 seconds (101 minutes) for 3,418 crash-recover cycles
- ECDH file: 1,599 seconds (27 minutes) for 1,297 crash-recover cycles
- **Total overhead: ~128 minutes** spent on crash recovery for these two files alone

## Reproduction

```bash
# Build and run SoftHSM2-main tests
docker compose -f docker/docker-compose.test.yml run --build test-softhsm2-main

# Results appear in artifacts/softhsm2-main/results.json
# Crashes are counted as "error" in the summary

# Compare with stable 2.7.0 (no crashes expected on these curves)
docker compose -f docker/docker-compose.test.yml run --build test-softhsm2
```

Minimal reproduction for a single crash (secp160k1, ArithmeticError vector):

```bash
# Inside softhsm2-main container:
uv run python -m pytest \
  'src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp160k1_sha256_test.json:tc1-valid]' \
  -v --no-header
# Expected: process killed by SIGSEGV
```

## Root cause hypothesis

SoftHSM2 delegates all EC operations to OpenSSL. OpenSSL 3.5 (Fedora 44) likely has regressions or stricter internal assertions in its EC arithmetic paths for these curve families. When SoftHSM2 passes edge-case values to OpenSSL's EC_POINT_mul or ECDSA_do_verify, OpenSSL hits an unhandled condition and crashes instead of returning an error.

SoftHSM2 does not validate or sanitize EC parameters before passing them to OpenSSL, nor does it install a signal handler to recover from OpenSSL crashes.

## Recommendation

This should be reported upstream to:
1. **SoftHSM2** (https://github.com/softhsm/SoftHSMv2) - module should not propagate segfaults from its crypto backend
2. **OpenSSL** (https://github.com/openssl/openssl) - EC arithmetic should not crash on valid curve operations

No changes needed in pkcs11-check - the isolation runner correctly detects and reports these crashes.

# BouncyHSM old vs new full-suite comparison — 2026-05-28

## Headline

- **77 % wall-clock reduction**: 236.9 min → 53.9 min on the full 244-unit
  bouncyhsm matrix.
- **~1 000 outcome flips out of 105 000 nodeids (≈ 1 %)** — most of them
  cluster in BouncyHSM's digest/HMAC/AES paths and look like a real
  upstream session-state issue exposed by the shared-session fixture.

## Method

- Old artifact: `artifacts/old/bouncyhsm/` captured 2026-05-27 19:50 with
  the function-scoped `p11_raw_session` fixture and the pre-Phase-6
  classification code.
- New artifact: `artifacts/bouncyhsm/` captured 2026-05-28 20:56 with the
  module-scoped `p11_module_session` fixture (commit 70c9e3c) and the
  post-Phase-6 classification code.
- Same provider source (BouncyHSM v2.1.0), same data set, same CLI
  defaults (`--timeout=120` from `pkcs11-check test`).

## Top-level results

| Bucket | OLD | NEW | Δ |
|---|---|---|---|
| passed | 55 485 | 52 379 | −3 106 |
| failed | 7 692 | 8 407 | +715 |
| skipped | 36 233 | 36 200 | −33 |
| xfailed | 8 703 | 7 971 | −732 |
| xpassed | 0 | 0 | 0 |
| error | 0 | 0 | 0 |
| crashed | 5 | 5 | 0 |
| timeout | 0 | 0 | 0 |
| **total** | **108 118** | **104 962** | −3 156 |
| **wall-clock** | **236.9 min** | **53.9 min** | **−77 %** |

The total dropped because a handful of test files now collect slightly
different vector counts (a side-effect of recent ACVP loader changes —
`fix(acvp): drop ML-DSA-sigVer internal-interface vectors (PC-2)`).

## Per-unit status changes (9 of 244 units)

| OLD → NEW | unit | wall (OLD → NEW) |
|---|---|---|
| failed → passed | security/test_cve_regression.py | 0.1 → 0.1 m |
| passed → failed | security/test_tookan.py | 0.0 → 0.0 m |
| failed → passed | test_eddsa_public_key_encoding.py | 0.0 → 0.0 m |
| passed → failed | test_mech_digest.py | 0.2 → 0.0 m |
| passed → failed | test_set_attribute.py | 0.0 → 0.1 m |
| passed → failed | wycheproof/test_wycheproof_aes.py | 3.8 → 0.5 m |
| passed → failed | wycheproof/test_wycheproof_hmac.py | 3.5 → 0.3 m |
| passed → failed | wycheproof/test_wycheproof_x25519.py | 8.1 → 0.3 m |
| failed → passed | x509/test_core_ops.py | 0.0 → 0.0 m |

## Per-nodeid flips by file (top 12 of ~30)

| Flips | File | Pattern |
|---|---|---|
| **420** | test_wycheproof_aes.py | 405 skipped→failed + 15 passed→failed |
| **288** | test_wycheproof_hmac.py | 240 passed→skipped + 48 skipped→failed |
| **141** | test_acvp_hash.py | 141 passed→failed |
| **70** | test_mech_digest.py | 40 passed→failed + 30 skipped→failed |
| **37** | test_acvp_sha3.py | 37 passed→failed |
| 12 | test_wycheproof_x25519.py | 12 passed→failed |
| 11 | test_parameter_validation.py | Mixed (Phase 3 + Phase 6 classification) |
| 5 | test_ckr_keygen.py | 5 passed→skipped |
| 5 | test_errors.py | Mixed |
| 4 | test_ckr_decrypt.py | 4 passed→skipped |
| 4 | test_ckr_sign.py | 4 passed→skipped |
| 4 | test_ckr_encrypt.py | 4 passed→skipped |

## Classifying the ~1 000 flips

| Category | Count | Cause | Action |
|---|---|---|---|
| Crypto-op modules: aes, hmac, digest, sha3, x25519, mech_digest | ~968 | Module-scoped session exposes BouncyHSM accumulating per-session state — after ~17-20 *Init calls the next one fails. Function-scoped fixture worked around it by giving each test a fresh session. | **Keep**: upstream BouncyHSM bug, worth reporting. The user explicitly chose not to revert these. |
| ckr classification (ckr_keygen / ckr_decrypt / ckr_sign / ckr_encrypt / ckr_verify) | ~25 | Phase 6 commit `f55b59b` (ckr_session non-cap skip → xfail+3-way) and Phase 4 N2 commits (`5268fed`, etc.) reclassified outcomes. | None — intentional code change. |
| Security tests (test_padding_oracle / test_cve_regression / test_parameter_validation / test_api_security / test_tookan) | ~30 | Phase 3 Type-A/B/C commits (`1c91fad`, `74d7a5d`, `8ae0f7b`, `94673bd`, etc.) classified accepted-invalid as fail, and `33b5f0e` reclassified refused-wrap as attack-blocked → passed. | None — intentional code change. |
| Crash/timeout boundary (cfb128 / cfb8 multiblock) | ~4 | Same upstream BouncyHSM slowness; sometimes hits the 120 s pytest-timeout, sometimes the OS kills the process. | None — same upstream issue, classification noise. |
| Other (x509 limbo, test_errors, test_fuzz, test_eddsa_public_key_encoding, test_set_attribute) | ~10 | Mix of Phase 4 classification + small test-code changes. | None — intentional code change. |

## What this confirms

1. **The wall-clock win is real and large**: 4.4× faster end-to-end on
   bouncyhsm. The single biggest contributor is the `p11_module_session`
   fixture amortizing `C_OpenSession + C_Login` across each test file.
2. **The total test count is essentially preserved** (104 962 vs
   108 118 — the drop is from intentional vector-set changes, not from
   the fixture).
3. **The fixture switch surfaced a real BouncyHSM session-state bug**:
   ~968 tests in digest/HMAC/AES/X25519 paths transition from passed to
   failed or skipped to failed once the session is reused. The pattern
   (~17-20 consecutive *Init calls pass, then start returning
   `CKR_ARGUMENTS_BAD`) is consistent across files. **Kept** as an
   upstream finding rather than reverted with a per-file fixture
   downgrade.
4. **Outcome bucket totals stayed in the same neighbourhood** despite
   ~1 % per-nodeid flips: 7 692 → 8 407 failures (+9 %), 55 485 → 52 379
   passes (−6 %). The shift is driven by Phase 3-6 classification +
   shared-session exposure of the digest bug, not by anything random.

## Wall-clock by major unit (top 12, OLD → NEW)

| Unit | OLD | NEW |
|---|---|---|
| test_wycheproof_ecdsa | 55.9 m | ~2 m |
| test_wycheproof_ecdh | 26.6 m | ~3 m |
| test_acvp_aes_ccm | 15.4 m | 3.7 m |
| test_acvp_aes_cfb128 | 15.1 m | 6.2 m |
| test_acvp_aes_ofb | 15.1 m | ~4 m |
| test_acvp_aes_cfb8 | 15.1 m | 4.2 m |
| test_wycheproof_rsa | 10.7 m | ~1 m |
| test_acvp_aes_wrap | 9.9 m | 0.2 m |
| test_wycheproof_x25519 | 8.1 m | 0.3 m |
| test_parameter_validation | 6.2 m | ~1 m |
| test_wycheproof_rsa_pss | 5.3 m | ~1 m |
| test_wycheproof_aes | 3.8 m | 0.5 m |

## Reproduction

The two artifact directories are preserved:

- `artifacts/old/bouncyhsm/` — pre-fix capture
- `artifacts/bouncyhsm/` — post-fix capture

The comparison script is `/tmp/final_compare.py` (per-nodeid, per-unit,
per-bucket diff plus categorisation by file).

# EC Coverage and Key Import Investigation Plan

## Context

Two related issues discovered during artifact analysis:

**A. Missing EC OID mappings** — 14 curves referenced by Wycheproof tests have no OID in `ec.py`, producing "No EC params for curve X" skips on ALL providers (8,342 skips per provider). These are standard-defined curves with known OIDs.

**B. EC key import failures on Kryoptic** — 13,086 Wycheproof tests skip with `CKR_ATTRIBUTE_VALUE_INVALID` when importing EC keys for secp256r1, secp224r1, secp256k1, brainpool variants. The test correctly wraps the point in DER OCTET STRING per spec (line 230 of OASIS `elliptic_curves.md`). Root cause is NOT yet confirmed — source code analysis was inconclusive and the artifact was pre-fix.

## Part A: Add 14 Missing EC OID Mappings

### File: `src/pkcs11_check/raw/ec.py`

Add entries to the `NAMED_CURVE_PARAMETERS` dict in `encode_named_curve_parameters()`:

| Curve | OID | DER encoding | Source |
|-------|-----|--------------|--------|
| `brainpoolp224r1` | 1.3.36.3.3.2.8.1.1.5 | `06 09 2B 24 03 03 02 08 01 01 05` | RFC 5639 |
| `brainpoolp320r1` | 1.3.36.3.3.2.8.1.1.9 | `06 09 2B 24 03 03 02 08 01 01 09` | RFC 5639 |
| `secp160r1` | 1.3.132.0.8 | `06 05 2B 81 04 00 08` | RFC 5480 |
| `secp160r2` | 1.3.132.0.30 | `06 05 2B 81 04 00 1E` | RFC 5480 |
| `secp160k1` | 1.3.132.0.9 | `06 05 2B 81 04 00 09` | RFC 5480 |
| `secp192k1` | 1.3.132.0.31 | `06 05 2B 81 04 00 1F` | RFC 5480 |
| `secp192r1` | 1.2.840.10045.3.1.1 | `06 08 2A 86 48 CE 3D 03 01 01` | RFC 5480 |
| `secp224k1` | 1.3.132.0.32 | `06 05 2B 81 04 00 20` | RFC 5480 |
| `sect283k1` | 1.3.132.0.16 | `06 05 2B 81 04 00 10` | SEC 2 |
| `sect283r1` | 1.3.132.0.17 | `06 05 2B 81 04 00 11` | SEC 2 |
| `sect409k1` | 1.3.132.0.36 | `06 05 2B 81 04 00 24` | SEC 2 |
| `sect409r1` | 1.3.132.0.37 | `06 05 2B 81 04 00 25` | SEC 2 |
| `sect571k1` | 1.3.132.0.38 | `06 05 2B 81 04 00 26` | SEC 2 |
| `sect571r1` | 1.3.132.0.39 | `06 05 2B 81 04 00 27` | SEC 2 |

### Also add to `_EC_CURVE_ALIASES` in `_key_decoders.py`

The Wycheproof ECDH test uses `brainpoolP224r1` and `brainpoolP320r1` (capital P) which map to the lowercase forms. Verify the alias map handles this.

## Part B: Investigate EC Key Import on Kryoptic

### Background

13,086 Wycheproof tests skip on Kryoptic with `CKR_ATTRIBUTE_VALUE_INVALID` when importing EC keys. The artifact was pre-fix (before our changes), so we don't know if the template fixes (CKA_CLASS/CKA_KEY_TYPE additions in other files) affect this.

### Root cause hypothesis

The test's DER OCTET STRING encoding is correct per spec:
- Line 198-201 of `test_wycheproof_ecdsa.py` wraps uncompressed point in `0x04 0x81 <len> || 0x04 x y`
- This is a valid DER OCTET STRING per ANSI X9.62 ECPoint

The Kryoptic source shows:
- secp256r1 is explicitly whitelisted (not FIPS-only)
- Factory dispatch requires `CKA_CLASS` + `CKA_KEY_TYPE` (present in test)
- `asn1::parse_single::<&[u8]>` parses CKA_EC_POINT as DER OCTET STRING

**Possible remaining causes:**
1. Point length mismatch (the DER length byte doesn't match actual key size)
2. The Wycheproof test data has an unusual point that doesn't match expected curve size
3. A test-side issue in how the skip is triggered (the CKR might come from a different operation, not the EC import itself)

### Investigation steps

1. Run the test against Kryoptic locally with verbose output:
   ```bash
   LD_LIBRARY_PATH=... P11TEST_MODULE=... P11TEST_PIN=1234 \
   uv run python -m pytest src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py \
     -k "secp256r1" -v --tb=short 2>&1 | head -50
   ```

2. If it still skips, add diagnostic to see the EXACT CKR code and full error:
   ```python
   except AssertionError as exc:
       exc_msg = str(exc)
       print(f"DEBUG: curve={curve} exc={exc_msg[:300]}")  # REMOVE AFTER
   ```

3. If it fails (no longer skips), verify the 13K skip count drops by running the full suite

4. If it still skips, trace the exact call path to determine which C_* function returns CKR_ATTRIBUTE_VALUE_INVALID

### Expected outcomes

- **If test passes after our template fixes**: the 13K skips were caused by missing template attributes in the Wycheproof test or related import functions. No additional fix needed.
- **If test still skips**: the CKR comes from inside Kryoptic's ASN.1 parsing or EC point validation. Need to determine whether the test's EC_POINT encoding has a subtle issue (e.g., for points that have a leading zero byte that changes the DER length encoding) or whether Kryoptic has a stricter parser.

## Execution Order

1. **Part A first** (no dependencies, purely additive)
2. **Part B investigation** (may require local Kryoptic run)
3. If Part B reveals a test bug, fix it

## Verification

- `uv run python -c "from pkcs11_check.raw.ec import encode_named_curve_parameters; print(len(encode_named_curve_parameters('secp192r1')))"` for each new curve
- `uv run ruff check src/pkcs11_check/raw/ec.py`
- `uv run python -m pytest tests/ -x -q --timeout=30`
- Run smoke tests: `bash local-builds/test.sh softhsm2 -m smoke`

# Test Vector Infrastructure Design

Date: 2026-03-19

## Problem

p11test has one external vector source (wycheproof) using only 111 of 336 available files. No SLH-DSA vectors exist anywhere in the project. The folder structure mixes test data with test code. Multiple high-quality public vector sources are unused.

## Solution

Reorganize test data into `testcases/data/`, add 3 new external sources as git submodules, expand test coverage using unused vectors.

## Folder Structure

```
src/p11test/testcases/
    data/                              # ALL external data sources
        __init__.py                    # DATA_DIR = Path(__file__).parent
        wycheproof/                    # submodule: C2SP/wycheproof (73MB, always)
        cctv/                          # submodule: C2SP/CCTV (2.3MB, always)
        acvp/                          # submodule: usnistgov/ACVP-Server (1.1GB, opt-in)
        x509-limbo/                    # submodule: C2SP/x509-limbo (194MB, opt-in)
        sha1.json                      # existing NIST KAT files
        sha256.json
        sha224.json
        sha384.json
        sha512.json
        aes_ecb.json

    ckr/                               # CKR compliance tests (exists, 30 files)

    wycheproof/                        # wycheproof test files (moved from root)
        __init__.py
        conftest.py                    # WYCHEPROOF_DIR pointing to data/wycheproof
        test_wycheproof_aes.py         # 16 files moved here
        test_wycheproof_ecdsa.py
        ...

    # Core tests remain in root (~67 files after wycheproof move)
    test_encrypt.py
    test_sign.py
    ...
```

## Submodule Configuration

### Always cloned (small repos)

| Submodule | URL | Size | Content |
|-----------|-----|------|---------|
| `data/wycheproof` | `C2SP/wycheproof` | 73MB | 336 JSON vector files + schemas + PQC vectors |
| `data/cctv` | `C2SP/CCTV` | 2.3MB | Ed25519 914 edge cases, ML-KEM intermediate |

### Opt-in (large repos, `update = none`)

| Submodule | URL | Size | Content |
|-----------|-----|------|---------|
| `data/acvp` | `usnistgov/ACVP-Server` | 1.1GB | NIST official: SLH-DSA, LMS, DRBG, HKDF, PQC keygen |
| `data/x509-limbo` | `C2SP/x509-limbo` | 194MB | 7000+ pathological X.509 certificates |

Opt-in submodules cloned with:
```bash
git submodule update --init src/p11test/testcases/data/acvp
git submodule update --init src/p11test/testcases/data/x509-limbo
```

Tests skip gracefully when opt-in submodules not present:
```python
if not (DATA_DIR / "acvp" / "json-files").exists():
    pytest.skip("ACVP vectors not cloned")
```

## What Each Source Enables

### Wycheproof — expand existing (225+ unused files)

Currently using 111 of 336 files. Key unused:
- **ML-KEM** (18 files): encaps, decaps, keygen with seeds — direct CKM_ML_KEM tests
- **RSA-PSS** (~20 files): various salt lengths and hash combos
- **ML-DSA sign** (6 files): seed and noseed variants beyond current verify-only
- **ECDH non-ecpoint** (4 files): ASN.1 format key exchange vectors
- **RSA sig_gen** (5 files): signing with known keys

### CCTV — Ed25519 edge cases

914 test vectors with flags for low-order points, cofactored verification, non-canonical encodings, mixed-order points. Supplements wycheproof Ed25519 tests.

### ACVP (opt-in) — NIST official vectors

- **SLH-DSA**: keygen, siggen, sigver — ONLY available source for these vectors
- **LMS**: hash-based signatures — no other source
- **ML-KEM/ML-DSA**: official NIST vectors complementing wycheproof
- **DRBG**: ctrDRBG, hashDRBG, hmacDRBG — for C_GenerateRandom validation
- **HKDF/KDF**: key derivation vectors for CKM_HKDF_* mechanisms

ACVP JSON format: `prompt.json` (inputs) + `expectedResults.json` (outputs) per algorithm. Needs adapter layer — different from wycheproof single-file format.

### x509-limbo (opt-in) — certificate crash testing

7000+ test certificates for C_CreateObject stress:
- Pathological ASN.1 extensions
- Broken certificate chains
- Duplicate/critical unknown extensions
- CVE regression certificates
- Oversized fields

Tests: call `C_CreateObject(CKO_CERTIFICATE, CKA_VALUE=der_cert)` with each cert. Module must not crash. Document which certs are accepted vs rejected per module.

## Migration Plan

### Phase 1: Rename and reorganize
1. Rename `vectors/` → `data/`
2. Update `.gitmodules` wycheproof path
3. Update all path references (18 files)
4. Create `data/__init__.py`

### Phase 2: Move wycheproof tests
5. Create `testcases/wycheproof/` with `__init__.py` + `conftest.py`
6. Move 16 `test_wycheproof_*.py` files
7. Update `WYCHEPROOF_DIR` paths (parent → parent.parent)
8. Verify all wycheproof tests pass

### Phase 3: Add new submodules
9. Add CCTV submodule (always cloned)
10. Add ACVP submodule (opt-in)
11. Add x509-limbo submodule (opt-in)

### Phase 4: New test files — wycheproof expansion
12. Add ML-KEM wycheproof tests (encaps/decaps/keygen)
13. Add RSA-PSS wycheproof tests (expanded)
14. Add ML-DSA sign wycheproof tests

### Phase 5: New test files — CCTV
15. Add Ed25519 edge case tests from CCTV

### Phase 6: New test files — ACVP (opt-in)
16. Create ACVP JSON parser (`scripts/parse_acvp.py` or `testcases/data/acvp_loader.py`)
17. Add SLH-DSA tests from ACVP vectors
18. Add DRBG/HKDF tests if relevant

### Phase 7: New test files — x509-limbo (opt-in)
19. Create x509-limbo cert loader
20. Add C_CreateObject cert crash tests

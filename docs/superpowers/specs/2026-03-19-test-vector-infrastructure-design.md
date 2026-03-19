# Test Vector Infrastructure Design

Date: 2026-03-19

## Problem

p11test has one external vector source (wycheproof) using only 111 of 336 available files. No SLH-DSA vectors exist anywhere in the project. The folder structure mixes test data with test code. Multiple high-quality public vector sources are unused.

## Solution

Reorganize test data into `testcases/data/`, add new external sources, expand test coverage using unused vectors.

## Folder Structure

```
src/p11test/testcases/
    data/                              # ALL external data sources
        __init__.py                    # DATA_DIR, WYCHEPROOF_DIR, KAT_DIR constants
        wycheproof/                    # submodule: C2SP/wycheproof (73MB, always cloned)
        cctv/                          # submodule: C2SP/CCTV (2.3MB, always cloned)
        sha1.json                      # existing NIST KAT files
        sha256.json
        sha224.json
        sha384.json
        sha512.json
        aes_ecb.json

    ckr/                               # CKR compliance tests (exists, 30 files)

    wycheproof/                        # wycheproof test files (moved from root)
        __init__.py
        conftest.py                    # imports WYCHEPROOF_DIR from data/
        wycheproof_loader.py           # moved from testcases root
        test_wycheproof_aes.py         # 16 test files moved here
        test_wycheproof_ecdsa.py
        ...

    # Core tests remain in root (~67 files after wycheproof move)
    test_encrypt.py
    test_sign.py
    ...
```

## Submodule Configuration

### Always cloned (registered in .gitmodules)

| Submodule | URL | Size | Content |
|-----------|-----|------|---------|
| `data/wycheproof` | `C2SP/wycheproof` | 73MB | 336 JSON vector files + schemas + PQC vectors |
| `data/cctv` | `C2SP/CCTV` | 2.3MB | Ed25519 914 edge cases, ML-KEM intermediate |

### Opt-in (NOT in .gitmodules — added via script)

Large repos are NOT registered in `.gitmodules` to prevent `git clone --recurse-submodules` from downloading them. Instead, a helper script adds them on demand.

| Repo | URL | Size | Content |
|------|-----|------|---------|
| ACVP-Server | `usnistgov/ACVP-Server` | 1.1GB | NIST official: SLH-DSA, LMS, DRBG, HKDF, PQC |
| x509-limbo | `C2SP/x509-limbo` | 194MB | 7000+ pathological X.509 certificates |

**Why not in .gitmodules:** `update = none` does NOT prevent `--recurse-submodules` from cloning them. The only reliable way to keep them opt-in is to not register them.

Opt-in usage:
```bash
# Add ACVP vectors (one-time)
scripts/fetch-optional-data.sh acvp

# Add x509-limbo (one-time)
scripts/fetch-optional-data.sh x509-limbo
```

The script does:
```bash
git submodule add --depth 1 https://github.com/usnistgov/ACVP-Server.git \
    src/p11test/testcases/data/acvp
```

Tests skip gracefully when opt-in data not present:
```python
ACVP_DIR = DATA_DIR / "acvp" / "json-files"
if not ACVP_DIR.exists():
    pytest.skip("ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)")
```

## Centralized Path Constants

`data/__init__.py` is the single source of truth for ALL data paths:

```python
from pathlib import Path

DATA_DIR = Path(__file__).parent
WYCHEPROOF_DIR = DATA_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = DATA_DIR / "cctv"
ACVP_DIR = DATA_DIR / "acvp" / "json-files"
X509_LIMBO_DIR = DATA_DIR / "x509-limbo"
KAT_DIR = DATA_DIR  # sha1.json, aes_ecb.json live here
```

All test files import from here — no more hardcoded paths in 15+ files.

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

**ACVP JSON format adapter:** Lives at `testcases/data/acvp_loader.py`. Loads `prompt.json` + `expectedResults.json` pairs and returns a list of `dict` with unified keys (`input`, `expected`, `algorithm`, `test_type`). Pytest parametrize consumes this list. The adapter handles per-algorithm directory structure and test group dependencies.

### x509-limbo (opt-in) — certificate crash testing

7000+ test certificates for C_CreateObject stress:
- Pathological ASN.1 extensions
- Broken certificate chains
- Duplicate/critical unknown extensions
- CVE regression certificates
- Oversized fields

Tests marked `@pytest.mark.stress` — not run by default. Batched (not 7000 individual parametrized tests). A "pass" is any CKR return code that is NOT a crash/segfault. CKR_ATTRIBUTE_VALUE_INVALID = pass (module correctly rejects). Module-specific acceptance documented in `docs/module-issues.md`.

## Docker Impact

Add `.dockerignore` to prevent copying large data into images:

```
src/p11test/testcases/data/acvp/
src/p11test/testcases/data/x509-limbo/
local-builds/*/src/
python-pkcs11/.git/
.git/
```

The always-cloned submodules (wycheproof 73MB, cctv 2.3MB) are copied into Docker images — acceptable.

## Migration Plan

### Phase 1: Rename vectors/ → data/ and fix submodule

Exact git commands (submodule move is NOT a simple rename):
```bash
# Move submodule (git 2.34+)
git mv src/p11test/testcases/vectors/wycheproof src/p11test/testcases/data/wycheproof
git submodule sync

# Move non-submodule JSON files
mv src/p11test/testcases/vectors/*.json src/p11test/testcases/data/
rmdir src/p11test/testcases/vectors
```

Also fix python-pkcs11 submodule absolute path in `.gitmodules` if present.

1. Execute git mv + submodule sync
2. Move JSON files to `data/`
3. Create `data/__init__.py` with centralized path constants
4. Update `pyproject.toml` — ruff exclude and mypy overrides (`vectors/` → `data/`)
5. Update `test_kat.py` — `VECTORS_DIR` → import from `data`
6. Verify all tests pass

### Phase 2: Move wycheproof tests + consolidate paths

7. Create `testcases/wycheproof/` with `__init__.py`
8. Move `wycheproof_loader.py` into `wycheproof/`
9. Create `wycheproof/conftest.py` importing `WYCHEPROOF_DIR` from `data`
10. Move 16 `test_wycheproof_*.py` files
11. **Consolidate**: remove all hardcoded `WYCHEPROOF_DIR = Path(__file__).parent / ...` from test files. Import from `data` or `conftest.py` instead.
12. Verify all wycheproof tests pass

### Phase 3: Add new submodules

13. Add CCTV submodule (always cloned): `git submodule add https://github.com/C2SP/CCTV.git src/p11test/testcases/data/cctv`
14. Create `scripts/fetch-optional-data.sh` for ACVP and x509-limbo
15. Add `.dockerignore`

### Phase 4: New test files — wycheproof expansion

16. Add ML-KEM wycheproof tests (encaps/decaps/keygen)
17. Add RSA-PSS wycheproof tests (expanded)
18. Add ML-DSA sign wycheproof tests

### Phase 5: New test files — CCTV

19. Add Ed25519 edge case tests from CCTV

### Phase 6: New test files — ACVP (opt-in)

20. Create `testcases/data/acvp_loader.py` — ACVP JSON format adapter
21. Add SLH-DSA tests from ACVP vectors
22. Add DRBG/HKDF tests if relevant

### Phase 7: New test files — x509-limbo (opt-in)

23. Create x509-limbo cert loader (`testcases/data/x509_limbo_loader.py`)
24. Add C_CreateObject cert crash tests (`@pytest.mark.stress`)

# pkcs11-check

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## What it does

pkcs11-check runs comprehensive tests against PKCS#11 modules (hardware HSMs, software tokens, smart cards). It catches:

- **Crashes and segfaults** — per-file subprocess isolation recovers from SIGSEGV
- **CKR return code violations** — 802 spec conditions checked against OASIS PKCS#11 standard
- **CVE regressions** — 29 tests for known CVEs across NSS, SoftHSM2, TPM2, OpenCryptoki
- **Security policy violations** — Tookan paper vectors, attribute fuzzing, padding oracle detection
- **Interface negotiation bugs** — v2.40/v3.0/v3.1/v3.2 with automatic fallback

## Quick start

```bash
# Install
git clone --recurse-submodules https://github.com/mingulov/pkcs11-check
cd pkcs11-check
uv sync

# Run against SoftHSM2
bash local-builds/build.sh softhsm2
bash local-builds/test.sh softhsm2

# Run against Kryoptic (v3.2 with PQC)
bash local-builds/build.sh kryoptic
bash local-builds/test.sh kryoptic

# Run against system NSS
bash local-builds/test.sh nss-softokn
```

## Test suite

75,000+ tests across 150+ test files:

| Category | Tests | Description |
|----------|-------|-------------|
| Core crypto | ~15,000 | AES, RSA, ECDSA, EdDSA, HMAC, digest |
| Wycheproof | ~8,000 | Edge-case vectors from Google |
| PQC (v3.2) | ~500 | ML-KEM, ML-DSA, SLH-DSA |
| CKR compliance | 148 | Return code verification per OASIS spec |
| CVE regression | 29 | Known vulnerability tests |
| Security | ~200 | Attribute fuzz, Tookan, handle reuse |
| Stress | ~100 | Threading, resource exhaustion |

## Supported modules

| Module | Version | Status |
|--------|---------|--------|
| SoftHSM2 | 2.7.0 | Full support |
| Kryoptic | 1.5.0+PQC | Full support (v3.2) |
| NSS softokn | system | Crypto services (slot 0) |
| OpenCryptoki | 3.26 | Docker only |
| pkcs11-mock | 2.0.0 | Stub testing |
| tpm2-pkcs11 | 1.9.0 | Hardware TPM |

## Architecture

```
src/pkcs11_check/
  raw/          — pure ctypes PKCS#11 binding (v2.40-v3.2, PQC)
  cli/          — typer CLI (test, info, version commands)
  core/         — module loader, isolation runner, preflight
  testcases/    — 150+ test files (the product)
    ckr/        — CKR return code compliance tests
  plugin.py     — pytest plugin (markers, fixtures, collection)
  fixtures.py   — p11_session, p11_module, p11_config
  config.py     — four-layer config (CLI > env > TOML > defaults)

local-builds/   — build scripts for 10 soft token providers
docker/         — 12 Docker test targets
```

## Key features

- **`pkcs11_check.raw`** — pure Python ctypes binding with v2.40/v3.0/v3.1/v3.2 interface negotiation, 50+ PQC mechanisms, all 68 standard functions
- **`--isolation file`** mode runs each test file in its own subprocess — crashes don't kill the suite
- **`--ckr-strict`** mode enforces exact OASIS spec CKR codes (not just "any error")
- **Wycheproof + ACVP vectors** — cross-verification against C2SP and NIST test vectors

## Documentation

- `docs/architecture.md` — codebase structure and test writing guide
- `docs/commands.md` — build, test, and Docker commands
- `docs/module-issues.md` — per-module bugs and quirks
- `docs/cve-regression.md` — CVE coverage tracker
- `docs/file-isolation.md` — isolation runner design
- `docs/docker-artifacts.md` — Docker test runner contract

## License

See LICENSE file.

# pkcs11-check

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## What it does

pkcs11-check runs comprehensive tests against PKCS#11 modules (hardware HSMs, software tokens, smart cards). It catches:

- **Crashes and segfaults** — per-file subprocess isolation recovers from SIGSEGV
- **CKR return code violations** — different spec conditions checked against OASIS PKCS#11 standard
- **CVE regressions** — tests for known CVEs across NSS, SoftHSM2, TPM2, OpenCryptoki
- **Security policy violations** — Tookan paper vectors, attribute fuzzing, padding oracle detection
- **Interface negotiation bugs** — v2.40/v3.0/v3.1/v3.2 with automatic fallback

## Quick start

```bash
# Install
git clone https://github.com/mingulov/pkcs11-check
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

### First run in 60 seconds (from PyPI)

```bash
pip install pkcs11-check

# 1. Make a token (one-time; SoftHSM2 is the easiest provider)
export SOFTHSM2_CONF="$HOME/softhsm2.conf"
mkdir -p "$HOME/softhsm2-tokens"
echo "directories.tokendir = $HOME/softhsm2-tokens" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --slot 0 --label demo --pin 1234 --so-pin 5678

# 2. Diagnose the setup (module loads? slot / PIN / token OK?)
pkcs11-check doctor --module /usr/lib/softhsm/libsofthsm2.so --slot 0 --pin 1234

# 3. Fast first run (~2s)
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 --marker smoke

# 4. Optional: full coverage (downloads ~800 MB of vectors, then runs the suite)
pkcs11-check fetch-data all
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0
```

Two non-obvious rules:

- **`--slot` is a 0-based index** into the token-present slots, **not** the
  provider's slot ID. Run `pkcs11-check info --module <lib>` (or
  `pkcs11-check doctor`) to list them. (NSS, for example, uses index 1.)
- **`fetch-data` is optional** — only the KAT / Wycheproof / ACVP suites need
  it; without it those are skipped and the rest still runs.

If anything fails, run **`pkcs11-check doctor`** first — it checks the module,
slot, PIN, token, and data, and prints the exact next step for each problem.

## Test suite

Test categories:

| Category | Description |
|----------|-------------|
| Core crypto | AES, RSA, ECDSA, EdDSA, HMAC, digest |
| Wycheproof | Edge-case vectors from C2SP |
| PQC (v3.2) | ML-KEM, ML-DSA, SLH-DSA |
| CKR compliance | Return code verification per OASIS spec |
| CVE regression | Known vulnerability tests |
| Security | Attribute fuzz, Tookan, handle reuse |
| Stress | Threading, resource exhaustion |

## Supported modules

| Module | Version | Status |
|--------|---------|--------|
| SoftHSM2 | 2.7.0 | Full support |
| Kryoptic | 1.5.1+PQC | Full support (v3.2) |
| NSS softokn | system | Crypto services (slot 0) |
| OpenCryptoki | 3.27.0 | Docker only |
| pkcs11-mock | 2.0.0 | Stub testing |
| tpm2-pkcs11 | 1.10.0 | Hardware TPM |
| BouncyHSM | 2.1.1 | Docker only |

## Known limitations in v0.1.0

- SO login is not implemented yet, so trusted-certificate import with
  `CKA_TRUSTED=True` is not fully covered through `CKU_SO` workflows.
- CloudHSM/Thales in-band IV profiles, proxy/loader mutable-parameter
  preservation checks, and broader mutable-output simulator targets are tracked
  as post-v0.1.0 interop work.

## Architecture

```
src/pkcs11_check/
  raw/          — pure ctypes PKCS#11 binding (v2.40-v3.2, PQC)
  cli/          — typer CLI (test, doctor, info, version, … commands)
  core/         — module loader, isolation runner, preflight
  testcases/    — test files (the product)
    ckr/        — CKR return code compliance tests
  plugin.py     — pytest plugin (markers, fixtures, collection)
  fixtures.py   — p11_session, p11_module, p11_config
  config.py     — four-layer config (CLI > env > TOML > defaults)

local-builds/   — build scripts for soft token providers
docker/         — Docker test targets
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
- `docs/test-universe.md` — collected product-test counts by group
- `docs/mechanism-output-parameters.md` — generated IV/nonce/tag output-parameter coverage
- `docs/docker-provider-results.md` — current Docker provider source and result snapshot
- `docs/todo.md` — public roadmap and known limitations
- `docs/cve-regression.md` — CVE coverage tracker
- `docs/file-isolation.md` — isolation runner design
- `docs/docker-artifacts.md` — Docker test runner contract

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Third-party attributions

pkcs11-check bundles the public-domain PKCS#11 v3.2 header from
`latchset/pkcs11-headers`, and its `fetch-data` command downloads test
vectors from C2SP and NIST. See
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) for the full list and
per-source license terms.

# pkcs11-check

See how any PKCS#11 module really behaves - a broad, vendor-neutral test client
for providers, HSMs, tokens, and cloud KMS.

## What this is

pkcs11-check is a broad, vendor-neutral test client for any PKCS#11 module -
software tokens, HSMs, smart cards, cloud-KMS bridges, and internal or
proprietary providers. It drives the module through >100k behavioral checks - a
large hand-written suite of spec-conformance, CKR/API-negative, security, and
fuzz tests, plus the major public crypto vector corpora (Wycheproof, NIST ACVP,
CCTV, x509-limbo) - all with crash-survival, and shows what it supports, where it
diverges from the spec or its peers, and where it breaks.

It maximizes coverage instead of stopping at the first incompatibility, and
records every difference as evidence to investigate and compare - not a verdict.
Large xfail/fail counts are normal: PKCS#11 cannot express many constraints (for
example, there is no per-curve capability flag), so one capability gap
multiplies across thousands of vectors. Both xfail and fail are recorded
findings - how the module differed from the checked expectation - not defects in
pkcs11-check. See [docs/interpreting-results.md](docs/interpreting-results.md).

## What it is not

It does not replace your module's own tests - keep those; they are faster and
know your internals. Think of pkcs11-check as an extra, exceptionally wide
external client that exercises your module the way the real world will. It is not
a compliance certification (no FIPS/CC), and its findings are hardening
observations under a software-token threat model - not CVE claims against any
project.

## Who it's for

- *Building a PKCS#11 module?* Point pkcs11-check at it during development for a
  broad, independent second opinion on how it behaves (it complements your own
  unit tests, it does not replace them).
- *Adopting or migrating?* Validate a module before you deploy, and confirm
  parity when you switch providers, versions, or loaders
  (`pkcs11-check compare-results` / `pkcs11-check compare-coverage`).
- *Maintaining or comparing providers?* Produce reproducible behavioral
  evidence to compare and discuss.

## Quick start

```bash
# Install
git clone https://github.com/mingulov/pkcs11-check
cd pkcs11-check
uv sync

# Run against any PKCS#11 module you provide
uv run pkcs11-check test --module /path/to/module.so --pin 1234
```

(See "First run in 60 seconds" below for a complete SoftHSM2 example. For
container-based walkthroughs see [docs/docker-examples.md](docs/docker-examples.md).)

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
- **`fetch-data` is optional** - only the KAT / Wycheproof / ACVP suites need
  it; without it those are skipped and the rest still runs.

If anything fails, run **`pkcs11-check doctor`** first - it checks the module,
slot, PIN, token, and data, and prints the exact next step for each problem.

**New to this?** [docs/getting-started-softhsm2.md](docs/getting-started-softhsm2.md)
is a complete copy-pasteable walkthrough - install, create a SoftHSM2 config and
token from scratch, run the suite, and read the results.

### Saving a report

By default `pkcs11-check test` prints a human-readable summary and keeps **no**
report file. The `generated report log file: /tmp/pkcs11-check-...jsonl` lines you
may notice are *internal* per-process logs that the isolated runner aggregates and
then deletes - they are not meant to be read directly.

To save a machine-readable report, add `--output json` and `--output-file`. The
files are written next to the path you give:

```bash
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 \
    --output json --output-file ./reports/results.json
```

That writes into `./reports/`:

- **`report.jsonl`** - one JSON record per test (outcome, return code, notes)
- **`results.json`** - the consolidated run summary (counts, crashes, environment)
- **`coverage.json`**, **`quality.json`** - mechanism coverage and the
  per-outcome classification report

Use `--output junit --output-file ./reports/results.xml` for JUnit XML instead
(for CI). The output directory is taken from the `--output-file` path, so point it
wherever you want the files created.

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

## Validation snapshot

These are the modules used in the current validation snapshot - pkcs11-check runs against **any** PKCS#11 module. Versions are current and may change.

| Module | Version | Status |
|--------|---------|--------|
| SoftHSM2 | 2.7.0 | Full support |
| Kryoptic | 1.5.1+PQC | Full support (v3.2) |
| NSS softokn | system | Crypto services (slot 0) |
| OpenCryptoki | 3.27.0 | Docker only |
| pkcs11-mock | 2.0.0 | Stub testing |
| tpm2-pkcs11 | 1.10.0 | Hardware TPM |
| BouncyHSM | 2.1.1 | Docker only |
| wolfPKCS11 | 2.0.0-stable / master | Docker only |
| corePKCS11 | 3.6.4 | Docker only |

## Known limitations

- SO login is not implemented yet, so trusted-certificate import with
  `CKA_TRUSTED=True` is not fully covered through `CKU_SO` workflows.
- CloudHSM/Thales in-band IV profiles, proxy/loader mutable-parameter
  preservation checks, and broader mutable-output simulator targets are tracked
  as post-v0.1.0 interop work.

## Architecture

```
src/pkcs11_check/
  raw/          - pure ctypes PKCS#11 binding (v2.40-v3.2, PQC)
  cli/          - typer CLI (test, doctor, info, version, ... commands)
  core/         - module loader, isolation runner, preflight
  testcases/    - test files (the product)
    ckr/        - CKR return code compliance tests
  plugin.py     - pytest plugin (markers, fixtures, collection)
  fixtures.py   - p11_session, p11_module, p11_config
  config.py     - four-layer config (CLI > env > TOML > defaults)
```

## Key features

- **`pkcs11_check.raw`** - pure Python ctypes binding with v2.40/v3.0/v3.1/v3.2 interface negotiation, 50+ PQC mechanisms, all 68 standard functions
- **`--isolation file`** mode runs each test file in its own subprocess - crashes don't kill the suite
- **`--ckr-strict`** mode enforces exact OASIS spec CKR codes (not just "any error")
- **Wycheproof + ACVP vectors** - cross-verification against C2SP and NIST test vectors

## Documentation

- `docs/interpreting-results.md` - what the pass/xfail/fail/skip counts mean (read this first)
- `docs/architecture.md` - codebase structure and test writing guide
- `docs/commands.md` - build, test, and Docker commands
- `docs/test-universe.md` - collected product-test counts by group
- `docs/mechanism-output-parameters.md` - generated IV/nonce/tag output-parameter coverage
- `docs/file-isolation.md` - isolation runner design

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

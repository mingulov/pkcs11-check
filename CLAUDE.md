# p11test

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Quick Reference

- **Language:** Python 3.11+
- **Package manager:** uv
- **Build backend:** hatchling (src/ layout)
- **CLI framework:** typer + rich
- **Config:** pydantic-settings (TOML + CLI + env)
- **Testing:** pytest (meta-tests in `tests/`, product test cases in `src/p11test/testcases/`)
- **Linting:** ruff
- **Type checking:** mypy --strict
- **PKCS#11 binding:** python-pkcs11 fork (git submodule at `python-pkcs11/`)

## Commands

```bash
# Local builds (preferred for fast iteration)
bash local-builds/build.sh kryoptic           # build token
bash local-builds/test.sh kryoptic            # run full suite (~1 min)
bash local-builds/test.sh kryoptic -k test_encrypt -v  # specific tests
bash local-builds/test.sh softhsm2            # system SoftHSM2
bash local-builds/reset.sh kryoptic           # reset token data

# Standard commands
uv run p11test version              # check CLI works
uv run pytest tests/                # run meta-tests (p11test's own tests)
uv run ruff check src/ tests/       # lint
uv run ruff format src/ tests/      # format
uv run mypy src/                    # type check

# Docker (for final validation or modules needing daemons)
docker compose -f docker/docker-compose.test.yml run test-softhsm2
docker compose -f docker/docker-compose.test.yml run test-kryoptic
```

## Architecture

### Two test directories
- `src/p11test/testcases/` — the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` — META-TESTS: tests for p11test's own code (config parsing, markers, CLI)

### Core modules
- `core/loader.py` — PKCS#11 module loading with v2.40/v3.0/v3.1/v3.2 interface negotiation
- `core/isolation.py` — subprocess-based test execution for segfault survival
- `config.py` — four-layer config: CLI > env > TOML > defaults
- `plugin.py` — pytest11 entry point, registers markers, fixtures, collection hooks
- `fixtures.py` — p11_session (with explicit login/logout), p11_module, p11_config, p11_interface_version
- `testcases/conftest.py` — shared helpers: mech_name(), import_aes_key(), has_mechanism(), extract_ec_point(), open_session()
- `testcases/ckr/` — CKR error coverage tests (102 tests, 21 files). Use `--ckr-strict` for exact spec compliance. Spec: `docs/superpowers/specs/2026-03-18-ckr-error-coverage-design.md`
- `testcases/ckr/_ckr_spec.py` — CkrExpectation dataclass, assert_ckr() helper, spec tables
- `testcases/ckr/_ctypes_raw.py` — raw ctypes PKCS#11 caller for NULL parameter tests

### Local builds (`local-builds/`)
- `providers/<name>.sh` — one file per token with `build()` and `setup()` functions
- `build.sh` — dispatcher: `bash local-builds/build.sh kryoptic [branch]`
- `test.sh` — dispatcher: `bash local-builds/test.sh kryoptic [pytest-args]`
- `reset.sh` — reset token data: `bash local-builds/reset.sh kryoptic`
- Available: OpenSSL 3.6.1, Kryoptic 1.5.0+PQC, SoftHSM2 2.7.0, OpenCryptoki 3.26, pkcs11-mock 2.0.0, qryptotoken 0.4.1, tpm2-pkcs11 1.9.0, BouncyHSM 2.0.1, swtpm 0.10.1

### Test categories (101 files, ~29K tests)
- Core: interface, slot, object, mechanism, encrypt, sign, digest, errors
- Cross-verification: AES-ECB/GCM, RSA PKCS/PSS/OAEP, ECDSA P-256/384/521, EdDSA, HMAC, digest
- NIST KAT: SHA-1/224/256/384/512, AES-ECB from SP 800-38A
- Wycheproof: ECDSA, RSA, ECDH, DSA, AES, HMAC, Ed25519/Ed448, ChaCha20, X25519/X448, HKDF
- PQC (v3.2): ML-KEM, ML-DSA, SLH-DSA
- Key management: import, export, copy, wrap/unwrap, derive, KEM
- Security: attribute fuzz, Tookan vectors, handle reuse, padding oracle, ECDSA nonce, RNG stats
- CVE regression: 29 tests covering CVEs across NSS, SoftHSM2, TPM2, OpenCryptoki, BouncyHSM, Kryoptic
- CKR spec compliance: exact return code verification per PKCS#11 standard
- Interop: OpenSSL pkcs11-provider, p11-kit proxy
- Stress: 1000-cycle ops, threading, resource exhaustion, DB concurrent writes
- Fuzz: Hypothesis property tests, attribute template fuzzer

### Docker test matrix (12 targets)
- `test-softhsm2` / `test-softhsm2-main` — SoftHSM2 2.7.0 / main
- `test-kryoptic` / `test-kryoptic-main` / `test-kryoptic-fips` — Kryoptic v1.5.0 / main / FIPS
- `test-nss` / `test-nss-pqc` — NSS 3.120.1 / 3.121.0 PQC
- `test-opencryptoki` — OpenCryptoki 3.25.0
- `test-tpm2` — tpm2-pkcs11 + swtpm
- `test-bouncyhsm` — BouncyHSM 2.0.1
- `test-pkcs11-mock` — pkcs11-mock v3.1 stub
- `test-qryptotoken` — qryptotoken Rust PQC

### Key design decisions
- python-pkcs11 fork as git submodule with v3.0/3.1/3.2 interface negotiation, PQC mechanisms, 50+ new enums, specific CKR exception classes for ALL standard error codes
- `p11_session` fixture does explicit `login()` / `logout()` per test to avoid `UserAlreadyLoggedIn` cascading
- Tests auto-skip when interface version doesn't support them (@pytest.mark.requires_v30)
- Mechanism availability checked at runtime via `slot.get_mechanisms()` — tests skip cleanly
- PQC tests always provide `CKA_PARAMETER_SET` (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s defaults)
- PIN tests marked `@destructive` to prevent token lockout (OpenCryptoki, TPM)

## Coding Rules

### Error handling — CRITICAL
- **NEVER use generic `except PKCS11Error: pass`** — this hides real bugs. Every catch must list SPECIFIC acceptable CKR codes for that operation.
- Use predefined error tuples for common patterns:
  ```python
  _TEMPLATE_ERRORS = (AttributeTypeInvalid, AttributeValueInvalid,
                      TemplateIncomplete, TemplateInconsistent, ArgumentsBad)
  _KEY_SIZE_ERRORS = (AttributeValueInvalid, KeySizeRange, MechanismInvalid,
                      ArgumentsBad, TemplateIncomplete)
  ```
- If a module returns an unexpected error (e.g., `DeviceError` for a bad template), the test should FAIL — exposing the module bug.
- `UserAlreadyLoggedIn` handling: catch only `UserAlreadyLoggedIn` (standard) and `UserTypeInvalid` (NSS quirk). Never catch broad `PKCS11Error` for login failures.

### PIN handling
- PIN values are never logged, printed, or included in error messages
- When `p11_config.pin` is `None` (no `--p11-pin`), don't call `C_Login` — some modules don't need it (e.g., NSS crypto services slot)
- Never use `str(pin)` when pin might be `None` — this produces the string `"None"` which gets passed as an actual PIN

### Test isolation
- Tests that call `lib.finalize()` or `lib.initialize()` MUST be marked `@destructive`
- Tests expecting crashes (post-Finalize, fork) MUST run in subprocess via `subprocess.run([sys.executable, "-c", script])`
- Token-locking operations (wrong PIN tests) MUST be marked `@destructive`
- Multi-thread tests on the same session can segfault SoftHSM2 (#845) — use sequential approach by default, or mark with `@pytest.mark.stress`

### Module-specific behavior
- Document module quirks in `docs/module-issues.md`, not as silent `pass` in code
- Use `compliance.note()` for spec deviations that aren't bugs (e.g., SoftHSM2 allows Tookan-vulnerable templates)
- Use `pytest.xfail()` for known module bugs with an explanatory message (e.g., Kryoptic CKR_DEVICE_ERROR on verify)
- NSS uses slot 1 (Certificate DB), not slot 0 (crypto services). Pass `--p11-slot=1`

### Conventions
- Type annotations on all public functions (mypy strict)
- `ruff` for formatting and linting — no other formatters
- Imports sorted by ruff (isort-compatible)
- Line length: 100
- Test files prefixed with `test_`
- Use `rich.console` for all CLI output (no bare print)
- Config values: snake_case in TOML/Python, kebab-case for CLI flags
- CVE regression tests reference the CVE/issue number in docstring

## PKCS#11 Specification

The OASIS PKCS#11 spec is available in Markdown format:
- Repo: https://github.com/oasis-tcs/pkcs11.git
- Spec docs: `working/doc/spec/` (all in .md format)
- Use for exact CKR return code tables, attribute definitions, mechanism parameters, and operation semantics

## Documentation

- `docs/master-plan.md` — Current task plan (Tiers 1-9)
- `docs/module-issues.md` — Per-module bugs, quirks, compliance deviations
- `docs/module-matrix.md` — Test results per module (pass/fail/skip/xfail)
- `docs/cve-regression.md` — CVE coverage tracker (Covered/Documented/N-A/Pending)
- `docs/mechanism-audit.md` — Mechanism coverage gap report per module
- `docs/gap-analysis.md` — Deep gap analysis: execution backbone, packaging, CI weaknesses
- `docs/test-coverage.md` — Test coverage summary
- `docs/test-coverage-generated.md` — Auto-generated from `scripts/generate-coverage-report.py`
- `docs/python-pkcs11-fork.md` — Fork changes and upstream PR plan
- `docs/superpowers/specs/` — Phase 1 architecture, comprehensive testing, standards addendum

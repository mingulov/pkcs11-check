# pkcs11-check

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Quick Reference

- **Language:** Python 3.11+
- **Package manager:** uv
- **Build backend:** hatchling (src/ layout)
- **CLI framework:** typer + rich
- **Config:** pydantic-settings (TOML + CLI + env)
- **Testing:** pytest (meta-tests in `tests/`, product test cases in `src/pkcs11_check/testcases/`)
- **Linting:** ruff
- **Type checking:** mypy --strict
- **PKCS#11 binding:** python-pkcs11 fork (git submodule at `python-pkcs11/`)

## Commands

```bash
# Local builds (preferred for fast iteration)
bash local-builds/build.sh kryoptic           # build token
bash local-builds/test.sh kryoptic            # run full suite (~5 min)
bash local-builds/test.sh kryoptic -k test_encrypt -v  # specific tests
bash local-builds/test.sh softhsm2            # system SoftHSM2
bash local-builds/reset.sh kryoptic           # reset token data

# Test profiles (use -m to select)
bash local-builds/test.sh softhsm2 -m smoke                              # 27 tests, ~5s
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)"  # ~2300 tests, ~30s
bash local-builds/test.sh softhsm2 -m "wycheproof or acvp or cctv"       # ~72K vectors only
bash local-builds/test.sh softhsm2                                        # full: ~75K tests, ~5min

# Standard commands
uv run pkcs11-check version              # check CLI works
uv run python -m pytest tests/      # run meta-tests (pkcs11-check's own tests)
uv run ruff check src/ tests/       # lint
uv run ruff format src/ tests/      # format
uv run mypy src/                    # type check

# Docker (for final validation or modules needing daemons)
bash docker/test.sh softhsm2
bash docker/test.sh opencryptoki
bash docker/test.sh nss --timeout 30 -- src/pkcs11_check/testcases/test_interface.py
docker compose -f docker/docker-compose.test.yml run --build --rm test-softhsm2
```

## Architecture

### Two test directories
- `src/pkcs11_check/testcases/` — the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` — META-TESTS: tests for pkcs11-check's own code (config parsing, markers, CLI)

### Core modules
- `core/loader.py` — PKCS#11 module loading with v2.40/v3.0/v3.1/v3.2 interface negotiation
- `core/file_runner.py` — main isolated runner for `auto|file|test`, with resume, adaptive promotion, and aggregated reports
- `core/preflight.py` — collection-safe capability probe written through a helper subprocess manifest
- `core/collection.py` — pytest item metadata collection for marker-aware isolation planning
- `core/isolation.py` — lower-level `spawn` helper retained for focused tests and future integration
- `config.py` — four-layer config: CLI > env > TOML > defaults
- `plugin.py` — pytest11 entry point, registers markers, fixtures, collection hooks
- `fixtures.py` — p11_session (with explicit login/logout), p11_module, p11_config, p11_interface_version
- `testcases/conftest.py` — shared helpers: mech_name(), import_aes_key(), has_mechanism(), extract_ec_point(), open_session()
- `testcases/ckr/` — CKR error coverage tests (102 tests, 21 files). Use `--ckr-strict` for exact spec compliance. Spec: `docs/superpowers/specs/2026-03-18-ckr-error-coverage-design.md`
- `testcases/ckr/_ckr_spec.py` — CkrExpectation dataclass, assert_ckr() helper, spec tables
- `testcases/ckr/_ctypes_raw.py` — raw ctypes PKCS#11 caller for NULL parameter tests (legacy, prefer `pkcs11.raw.RawPKCS11`)

### Raw PKCS#11 access (pkcs11.raw.RawPKCS11)
For tests that need to bypass python-pkcs11's safety checks (NULL pointers, invalid handles, state corruption, wrapper-blocked CKR conditions), use `RawPKCS11` from the fork — pure Python ctypes, no C compilation needed.

```python
# In-process (shares session with python-pkcs11):
from pkcs11.raw import RawPKCS11
raw = RawPKCS11(lib._raw_funclist_ptr)  # lib is pkcs11.lib() return
rv = raw.C_GetTokenInfo(slot_id, byref(token_info))

# Standalone (subprocess, for crash-safe NULL tests):
from pkcs11.raw import RawPKCS11
raw = RawPKCS11.from_lib("/path/to/module.so")
raw.C_Initialize()
rv = raw.C_GetSlotList(1, None, byref(count))  # NULL pSlotList
```

- All 68 v2.40 functions + v3.0 message-based + v3.2 KEM functions available as methods
- Returns raw CK_RV integers — caller must check against CKR_* constants
- Use in subprocess for NULL/segfault tests (`subprocess.run([sys.executable, "-c", script])`)
- CKR tests in `testcases/ckr/` use this pattern extensively — see `test_ckr_raw_args_bad.py` for examples

### Local builds (`local-builds/`)
- `providers/<name>.sh` — one file per token with `build()` and `setup()` functions
- `build.sh` — dispatcher: `bash local-builds/build.sh kryoptic [branch]`
- `test.sh` — dispatcher: `bash local-builds/test.sh kryoptic [pytest-args]`
- `reset.sh` — reset token data: `bash local-builds/reset.sh kryoptic`
- Available: OpenSSL 3.6.1, Kryoptic 1.5.0+PQC, SoftHSM2 2.7.0, OpenCryptoki 3.26, pkcs11-mock 2.0.0, qryptotoken 0.4.1, tpm2-pkcs11 1.9.0, BouncyHSM 2.0.1, swtpm 0.10.1
- **Worktree Kryoptic testing:** Kryoptic requires OpenSSL 3.5.0+. In worktrees, use the pre-built module from the main repo instead of rebuilding:
  ```bash
  LD_LIBRARY_PATH=/home/user/src/m/pkcs11-check/local-builds/openssl/install/lib64 \
  P11TEST_MODULE=/home/user/src/m/pkcs11-check/local-builds/kryoptic/lib/libkryoptic_pkcs11.so \
  P11TEST_PIN=1234 uv run python -m pytest src/pkcs11_check/testcases/<test_file>.py -v
  ```

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
- `test-opencryptoki` — OpenCryptoki 3.26.0
- `test-tpm2` — tpm2-pkcs11 + swtpm
- `test-bouncyhsm` — BouncyHSM 2.0.1
- `test-pkcs11-mock` — pkcs11-mock v3.1 stub
- `test-qryptotoken` — qryptotoken Rust PQC

### Docker test usage
- Use [docker/test.sh](/home/user/src/m/pkcs11-check/docker/test.sh) as the common host-side entrypoint for all Docker providers
- Provider names can be passed with or without the `test-` prefix
- Arguments before `--` are extra `pkcs11-check test` options
- Arguments after `--` are explicit pytest targets or nodeids
- Docker runs write artifacts under `artifacts/<provider>/`
- Standard artifact files are `console.log`, `results.json`, and `state.json`
- Shared container-side runners are [docker/run-with-artifacts.sh](/home/user/src/m/pkcs11-check/docker/run-with-artifacts.sh) and [docker/run-pkcs11-check.sh](/home/user/src/m/pkcs11-check/docker/run-pkcs11-check.sh)

### Git workflow — CRITICAL
- **Development branch:** `dev` — ALL work merges here. NEVER merge directly to `main`.
- **Main branch:** `main` — production snapshot, updated from `dev` only when the user says so
- Feature branches (e.g., `phase-a/api-completeness`) → merge to `dev`, not `main`
- Worktrees: use `.worktrees/` directory (gitignored)
- When finishing a branch: `git checkout dev && git merge <branch>` — NEVER `git checkout main`

### Key design decisions
- python-pkcs11 fork as git submodule with v3.0/3.1/3.2 interface negotiation, PQC mechanisms, 50+ new enums, specific CKR exception classes for ALL standard error codes
- `pkcs11-check test` defaults to `--isolation auto`; explicit `--isolation none` is the unsafe fast path
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

## Writing New Tests

### Test pattern template (mechanism tests)
```python
"""CKM_EXAMPLE tests — short description."""
from __future__ import annotations
from typing import Any
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import MechanismInvalid, FunctionFailed
from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.encrypt]  # assign relevant marker

class TestExample:
    def test_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = p11_session.generate_key(
            KeyType.AES, 256,
            mechanism=Mechanism.AES_KEY_GEN,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False},
        )
        try:
            ct = key.encrypt(b"test data here!", mechanism=Mechanism.AES_CTR, mechanism_param=params)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_CTR, mechanism_param=params)
            assert pt == b"test data here!"
        finally:
            key.destroy()
```

### Key fixtures (all session-scoped unless noted)
- `p11_session` — open RW session with login; does login/logout per test (`@pytest.fixture` scope=function)
- `p11_module` — loaded PKCS#11 module (session-scoped)
- `p11_config` — merged config from CLI/env/TOML (session-scoped)
- `p11_interface_version` — negotiated version string: "2.40", "3.0", "3.1", "3.2"

### Mechanism availability pattern
```python
# ALWAYS check mechanism availability — never assume
if not has_mechanism(p11_module, "MECHANISM_NAME"):
    pytest.skip("CKM_MECHANISM_NAME not supported")
```

### Compliance notes (for above-spec behavior)
```python
from pkcs11_check.compliance import ComplianceLevel, note
note("Module does X which is above spec requirement Y", ComplianceLevel.VENDOR)
```

### Object cleanup pattern
Always destroy created objects in `finally` blocks or use `try/finally`:
```python
obj = p11_session.generate_key(...)
try:
    # test logic
finally:
    obj.destroy()
```

## PKCS#11 Specification

The OASIS PKCS#11 spec is available in Markdown format:
- Repo: https://github.com/oasis-tcs/pkcs11.git
- **Local copy:** `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/` (95 .md files)
- Use for exact CKR return code tables, attribute definitions, mechanism parameters, and operation semantics
- Key files: `rsa.md`, `aes.md`, `elliptic_curves.md`, `ml_dsa.md`, `slh-dsa.md`, `session_mgmt_functions.md`, `function_return_values.md`

## Documentation

- `docs/master-plan.md` — Current task plan (Tiers 1-9)
- `docs/module-issues.md` — Per-module bugs, quirks, compliance deviations
- `docs/module-matrix.md` — Test results per module (pass/fail/skip/xfail)
- `docs/cve-regression.md` — CVE coverage tracker (Covered/Documented/N-A/Pending)
- `docs/mechanism-audit.md` — Mechanism coverage gap report per module
- `docs/gap-analysis.md` — Deep gap analysis: execution backbone, packaging, CI weaknesses
- `docs/gap-analysis-oasis-spec.md` — OASIS spec compliance gap analysis (mechanisms, functions, objects, attributes)
- `docs/test-coverage.md` — Test coverage summary
- `docs/test-coverage-generated.md` — Auto-generated from `scripts/generate-coverage-report.py`
- `docs/python-pkcs11-fork.md` — Fork changes and upstream PR plan
- `docs/docker-artifacts.md` — Standard Docker test runner, artifacts, and wrapper usage
- `docs/superpowers/specs/` — Design specs (vendor extensions, CKR coverage, comprehensive testing)
- `docs/superpowers/plans/2026-03-20-oasis-compliance-roadmap.md` — 8-phase OASIS spec compliance roadmap (Phase A-H)

# p11test Design Specification

**Date:** 2026-03-16
**Status:** Draft
**PRD version:** 0.1.0 (March 2026)

## 1. Overview

p11test is a CLI-first PKCS#11 test suite that also installs as a pytest plugin.
It tests PKCS#11 modules across interface versions 2.40, 3.0, and 3.2, survives
module crashes (segfaults, hangs), and provides full v3.2 coverage including PQC.

## 2. Architecture Decision: Single Package

**Decision:** Ship as one installable package (`p11test`) containing CLI, pytest plugin,
core engine, and all test cases.

**Rationale:**
- pytest plugins are just entry points — no separate package needed
- Test cases are native pytest tests (not framework-agnostic wrappers) — eliminates
  the ~200-test boilerplate that a two-package split would require
- The target audience (HSM developers, security engineers) benefits from a single install
- Splitting later is easier than merging

**Package layout:**
```
src/p11test/
  __init__.py
  config.py              # pydantic-settings: TOML + CLI + env merge
  plugin.py              # pytest11 entry point
  fixtures.py            # pytest fixtures (p11_session, p11_module, etc.)
  cli/
    __init__.py
    app.py               # typer app, main entry
    test_cmd.py           # `p11test test`
    daemon_cmd.py         # `p11test daemon` (Phase 2)
  core/
    __init__.py
    loader.py             # Interface negotiation + module loading
    isolation.py          # Subprocess-based test execution
    timeout.py            # Per-op / per-test / global timeouts
    session.py            # PKCS#11 session lifecycle
  testcases/
    __init__.py
    conftest.py           # Shared fixtures for test categories
    test_interface.py     # Library & Interface Management
    test_slot.py          # Slot / Token / Session
    test_object.py        # Object / Key / Attribute
    test_mechanism.py     # Mechanism discovery (incl. PQC)
    test_encrypt.py       # Encrypt / Decrypt (incl. v3.0 message-based)
    test_sign.py          # Sign / Verify (incl. v3.2 VerifySignature*)
    test_digest.py        # Digest, MAC, Wrap/Unwrap (incl. v3.2 authenticated)
    test_pqc.py           # PQC: ML-KEM encapsulate/decapsulate, ML-DSA, SLH-DSA
    test_profiles.py      # Profiles & Validation (v3.0+)
    test_async.py         # Async operations (v3.2)
    test_concurrency.py   # Multi-thread / multi-session stress
    test_errors.py        # Error handling & edge cases
tests/                    # Meta-tests (testing p11test itself)
  conftest.py
  test_config.py
  test_loader.py
  test_isolation.py
  test_cli.py
```

## 3. PKCS#11 Binding Strategy

**Decision:** Minimal fork of python-pkcs11 with v3.x interface support (approach B3).

**Rationale:**
- python-pkcs11 (v0.9.3, Dec 2025) is Cython-based, supports v2.40 only
- Upstream review activity is low — PRs sit without response
- v3.0/v3.2 function lists are binary-compatible supersets of v2.40
  (same field offsets, new functions appended)
- Adding v3.x support requires ~150-200 lines of Cython (struct definitions +
  function wrappers following existing patterns)
- No ctypes glue needed in p11test itself

**Fork scope:**
- `_pkcs11.pxd`: Add CK_INTERFACE, CK_FUNCTION_LIST_3_0, CK_FUNCTION_LIST_3_2 structs
- `_pkcs11.pyx`: Add interface negotiation (C_GetInterface with fallback), wrappers for
  36 new v3.0/v3.2 functions (24 in v3.0 + 12 in v3.2)
- `types.py`: Python API for message-based ops, KEM, async, authenticated wrap

**Dependency:** `python-pkcs11 @ git+https://github.com/<owner>/python-pkcs11.git@v3-support`

## 4. Interface Negotiation

### Loading flow

```
dlopen(module.so)
  │
  ├─ Try C_GetInterface("PKCS 11", version=3.2)
  │    ├─ Success → CK_FUNCTION_LIST_3_2* (use for everything)
  │    ├─ CKR_FUNCTION_NOT_SUPPORTED → try 3.0
  │    └─ Crash/error → try 3.0
  │
  ├─ Try C_GetInterface("PKCS 11", version=3.0)
  │    ├─ Success → CK_FUNCTION_LIST_3_0*
  │    ├─ CKR_FUNCTION_NOT_SUPPORTED → fallback
  │    └─ Crash/error → fallback
  │
  └─ Fallback: C_GetFunctionList → CK_FUNCTION_LIST* (v2.40)
```

Since v3.2 function list IS a valid v2.40 function list (same offsets), python-pkcs11
uses the same pointer for all standard operations regardless of interface version.
v3.x-specific functions are accessed through the extended struct.

### Edge cases (learned from p11-kit and JDK)

- Module exports C_GetInterface but returns CKR_FUNCTION_NOT_SUPPORTED → fall back gracefully
- Module returns v3.2 interface but some function pointers are NULL → report as finding, skip those tests
- Module crashes during C_GetInterface → report as finding, fall back
- `--interface 3.2` forces v3.2 path: if C_GetInterface fails → exit code 3 (module error)

### Print on every run

```
Using PKCS#11 interface v3.2 (CK_FUNCTION_LIST_3_2) from /path/to/module.so
```

## 5. Complete v3.0/v3.2 Function Coverage

### v3.0 functions (24 new, beyond v2.40)

| Category | Functions |
|----------|-----------|
| Interface | C_GetInterfaceList, C_GetInterface |
| Session | C_LoginUser, C_SessionCancel |
| Message Encrypt | C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal |
| Message Decrypt | C_MessageDecryptInit, C_DecryptMessage, C_DecryptMessageBegin, C_DecryptMessageNext, C_MessageDecryptFinal |
| Message Sign | C_MessageSignInit, C_SignMessage, C_SignMessageBegin, C_SignMessageNext, C_MessageSignFinal |
| Message Verify | C_MessageVerifyInit, C_VerifyMessage, C_VerifyMessageBegin, C_VerifyMessageNext, C_MessageVerifyFinal |

### v3.2 functions (12 new, beyond v3.0)

| Category | Functions |
|----------|-----------|
| KEM | C_EncapsulateKey, C_DecapsulateKey |
| PQ Verify | C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate, C_VerifySignatureFinal |
| Session | C_GetSessionValidationFlags |
| Async | C_AsyncComplete, C_AsyncGetID, C_AsyncJoin |
| Auth Wrap | C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated |

### Test coverage mapping

| Test file | v2.40 | v3.0 | v3.2 | Functions covered |
|-----------|-------|------|------|-------------------|
| test_interface.py | x | x | x | C_GetFunctionList, C_GetInterfaceList, C_GetInterface |
| test_slot.py | x | x | x | Slot/Token/Session + C_LoginUser, C_SessionCancel, C_GetSessionValidationFlags |
| test_object.py | x | x | x | Object/Key/Attribute + CKO_PROFILE |
| test_mechanism.py | x | x | x | Mechanism discovery + PQC mechanisms |
| test_encrypt.py | x | x | x | Encrypt/Decrypt + MessageEncrypt/Decrypt (v2.40 tests also run on v3.x tables) |
| test_sign.py | x | x | x | Sign/Verify + MessageSign/Verify + VerifySignature* |
| test_digest.py | x | x | x | Digest, MAC, Wrap/Unwrap + WrapKeyAuthenticated |
| test_pqc.py | | | x | ML-KEM Encapsulate/Decapsulate, ML-DSA, SLH-DSA |
| test_profiles.py | | x | x | CKO_PROFILE objects, profile validation |
| test_async.py | | | x | C_AsyncComplete, C_AsyncGetID, C_AsyncJoin |
| test_concurrency.py | x | x | x | Multi-thread, multi-session stress |
| test_errors.py | x | x | x | Error handling, edge cases |

Tests automatically skip when the detected interface version doesn't support them
(via pytest markers: `@pytest.mark.requires_v30`, `@pytest.mark.requires_v32`).

## 6. Segfault Survival & Test Isolation

### Approach

Use `multiprocessing` (spawn mode) rather than `pytest-forked` because:
- pytest-forked is inactive (no maintainer) and Python 3.7-3.11 only
- fork() doesn't work on Windows; spawn works everywhere
- We need control over timeout, result reporting, and cleanup

### Isolation model

Each test runs in its own subprocess:

```
Main process (pytest runner or CLI)
  │
  ├─ Subprocess 1: test_aes_cbc_encrypt
  │    ├─ C_Initialize, C_OpenSession, ...
  │    ├─ [test body]
  │    ├─ C_CloseSession, C_Finalize
  │    └─ Exit(0) / Exit(1) / SIGSEGV / timeout
  │
  ├─ Subprocess 2: test_rsa_sign
  │    └─ ...
  │
  └─ Results collected via multiprocessing.Queue
```

- Subprocess crash (SIGSEGV) → test marked FAILED with "module crashed (signal 11)"
- Subprocess timeout → killed (SIGKILL on Linux/macOS, TerminateProcess on Windows),
  marked FAILED with "timeout after Ns"
- Subprocess success → result (pass/fail/skip) reported normally
- Main process never loads the PKCS#11 module directly

### Subprocess result message (via multiprocessing.Queue)

```python
@dataclass
class TestResult:
    name: str                    # fully qualified test name
    outcome: str                 # "passed", "failed", "skipped", "crashed", "timeout"
    duration_s: float
    signal: int | None           # signal number if crashed (e.g. 11 for SIGSEGV)
    error_message: str | None    # assertion message or crash description
    pkcs11_rc: int | None        # last CKR_ return code if relevant
    stdout: str                  # captured stdout
    stderr: str                  # captured stderr
```

### Session management

- `--sessions N` = N concurrent PKCS#11 sessions (N subprocess workers in CLI mode)
- `pytest -n N` = N pytest-xdist workers (each opens 1 PKCS#11 session)
- These are **mutually exclusive contexts**: `--sessions` is for CLI mode, `-n` is for pytest mode
- When using pytest plugin mode, `--sessions` is ignored (xdist controls parallelism)
- Default: 1 session, sequential execution

### Timeouts

- Per-operation: 30s default (a single PKCS#11 call)
- Per-test: 120s default (the entire test function)
- Global: none by default (all tests must complete)
- Configurable via TOML, CLI, env

## 7. Configuration

### Four-layer merge: CLI > env > TOML > defaults

Precedence follows pydantic-settings default: environment variables override TOML file
values, CLI flags override everything. This is the standard behavior and requires no
custom source ordering.

```python
class P11TestConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="P11TEST_",
        toml_file="p11test.toml",
    )

    module: Path                          # required
    slot: int = 0
    pin: SecretStr | None = None          # never logged
    interface: str = "auto"               # "auto", "2.40", "3.0", "3.2"
    timeout_operation: int = 30           # seconds
    timeout_test: int = 120
    destructive: bool = False             # enables destructive tests
    max_sessions: int = 1
    skip_unsupported: bool = True         # auto-skip tests for unavailable mechanisms
    log_level: str = "INFO"
    output: str = "rich"                  # "rich", "json", "junit"
```

Note: `safe_mode` was removed — `destructive` is the single toggle (default False = safe).
CLI offers both `--safe` and `--destructive` as aliases mapping to the same field.

### TOML search path (first found wins)

1. `$P11TEST_CONFIG` (env var pointing to specific file — highest priority)
2. `./p11test.toml` (current working directory)
3. `~/.config/p11test/config.toml` (user default)

### PIN security

- `--pin` on CLI: accepted but warning about process list visibility
- `P11TEST_PIN` env var: recommended
- `--pin-prompt`: interactive stdin prompt (default if pin not provided and needed)
- `pin` in TOML: accepted with warning about file permissions
- PIN is stored as `SecretStr` — never appears in logs, repr, or error messages
- Zeroed from memory after C_Login (best-effort via ctypes.memset on the underlying buffer)

## 8. CLI Design

### Commands

```
p11test test     [--module PATH] [--interface VER] [--sessions N] [--timeout N]
                 [--category CAT] [--match PATTERN] [--destructive] [--output FORMAT]
p11test info     [--module PATH]     # module info (see below)
p11test list     [--module PATH]     # list available tests (dry run)
p11test daemon                       # Phase 2
p11test session  list|cancel|close-all  # Phase 2
p11test version                      # show p11test version
```

### `p11test info` output

Displays module metadata without running tests:
- Library description, version, manufacturer ID
- Negotiated interface version (2.40 / 3.0 / 3.2)
- Available slots with token info (label, manufacturer, model, serial, flags)
- Mechanism list with key size ranges and flags
- Profile objects (if v3.0+)

### Test filtering

- `--category encrypt,sign` — run only named categories
- `--match "aes*"` — name pattern matching
- `--tag pqc` — run tests with specific markers
- `--skip-unsupported` — auto-skip tests for mechanisms the module doesn't advertise (default: on)

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | Some tests failed |
| 2 | Configuration error |
| 3 | Module load / interface error |
| 4 | Timeout (global) |
| 130 | Interrupted (Ctrl-C / SIGINT) |

### Output formats

- `rich` (default): human-readable with progress bar, colors, summary table
- `json`: machine-readable, one JSON object per test + summary
- `junit`: JUnit XML (pytest native — also available in pytest plugin mode)

## 9. pytest Plugin Mode

### Registration

```toml
[project.entry-points."pytest11"]
p11test = "p11test.plugin"
```

### Provided fixtures

- `p11_module` (session) — loaded and negotiated PKCS#11 module
- `p11_session` (function) — open session with login
- `p11_interface_version` — string: "2.40", "3.0", "3.2"
- `p11_config` — the merged P11TestConfig object

### CLI options added to pytest

```
--p11-module=PATH       module path
--p11-interface=VER     force interface version
--p11-pin=PIN           PIN (prefer P11TEST_PIN env)
--p11-slot=N            slot index
--p11-safe              safe mode (default)
--p11-destructive       enable destructive tests
```

### Markers

```python
@pytest.mark.requires_v30   # skip if interface < 3.0
@pytest.mark.requires_v32   # skip if interface < 3.2
@pytest.mark.destructive     # only runs with --p11-destructive
@pytest.mark.pqc             # PQC-specific tests
@pytest.mark.slow            # long-running tests
```

## 10. Test Modules for Development & CI

### Primary: SoftHSM2 (v2.40)
- Widely available, well-understood
- Covers all v2.40 operations
- Headers updated to v3.2 but no v3.x function implementations

### v3.2 target: Kryoptic (Rust, v1.5.0)
- Forces v3.2 interfaces in FIPS builds
- PQC algorithm support (ML-KEM, ML-DSA)
- Actively maintained (March 2026)
- Use for v3.0/v3.2 function testing

### NSS softoken (future)
- Working on v3.2 PQ support (Bug 1965329, in progress)
- Potential additional v3.2 target once stable

### Crash-test module (custom, Phase 2)
- Minimal .so that segfaults/hangs on configurable functions
- For testing p11test's own isolation and recovery
- Not needed for MVP — real buggy modules provide this naturally

## 11. Safe Mode vs Destructive

### Destructive operations (require `--destructive` flag)

- `C_InitToken` — reinitialize token, destroys all objects
- `C_InitPIN` — set user PIN
- `C_SetPIN` — change PIN
- `C_DestroyObject` — delete keys/certificates/objects
- `C_CreateObject` with `CKA_TOKEN=True` — create persistent objects

### Safe mode behavior (default)

- Use only session objects (non-persistent)
- Never modify token state
- Read-only operations on existing token objects
- Generate ephemeral keys for crypto tests, destroy after

### Destructive mode

- Explicit `--destructive` flag required
- CLI shows warning + confirmation prompt (unless `--yes`)
- Tests create and destroy token objects
- Tests may reinitialize tokens

## 12. Logging

- Framework: Python `logging` module with `rich` handler
- Destinations: stderr (default), file via `--log-file`
- Levels: DEBUG, INFO, WARNING, ERROR
- PKCS#11 call tracing: `--trace` flag logs every C_* call with parameters and return codes
  (like pkcs11-spy but in-process)
- PIN values NEVER logged at any level
- Key handles logged at DEBUG only

## 13. PRD Gap Resolutions

| # | PRD Gap | Resolution |
|---|---------|------------|
| 1 | python-pkcs11 doesn't support v3.x | B3: minimal fork with Cython v3.x additions |
| 2 | v3.0/v3.2 have 36 new functions, PRD lists few | Full coverage mapped in Section 5 |
| 3 | No v3.2 test module | Kryoptic (FIPS build) provides v3.2 interfaces |
| 4 | Subprocess isolation model | Per-test subprocess via multiprocessing spawn (Section 6) |
| 5 | Daemon IPC unspecified | Deferred to Phase 2 |
| 6 | "Sessions" ambiguous | --sessions = PKCS#11 sessions; pytest -n = workers |
| 7 | Safe/destructive boundary | Defined in Section 11 |
| 8 | Config search path | ./p11test.toml > $P11TEST_CONFIG > ~/.config/p11test/ |
| 9 | No test filtering in CLI | --category, --match, --tag, --skip-unsupported |
| 10 | No exit codes | Defined in Section 8 |
| 11 | No `p11test info` command | Added to CLI (Section 8) |
| 12 | PIN security unaddressed | SecretStr, env var, prompt, never logged (Section 7) |
| 13 | C_VerifySignature* vs C_Verify* | Separate test coverage in test_sign.py |
| 14 | Async operations (v3.2) not mentioned | Added test_async.py |
| 15 | Authenticated wrap/unwrap not mentioned | Added to test_digest.py |
| 16 | Profile objects are a full spec | Profile validation in test_profiles.py |
| 17 | C_LoginUser (v3.0) not mentioned | Covered in test_slot.py |
| 18 | C_SessionCancel (v3.0) not mentioned | Covered in test_slot.py |
| 19 | Loader edge cases (Luna-style failures) | Handled in Section 4 |
| 20 | Logging architecture missing | Defined in Section 12 |
| 21 | Output JSON schema undefined | Will define during implementation |
| 22 | License not specified | MIT (in pyproject.toml) |
| 23 | ~200 tests ambitious for MVP | Phased: v2.40 first, v3.x as test modules mature |
| 24 | concurrent.futures in tech stack (§8) | Dropped: multiprocessing alone is sufficient (see §14) |
| 25 | 32-bit in MVP scope (§4, §11, §12) | Deferred to Phase 2 (see §14) |
| 26 | safe_mode + destructive redundant fields | Single `destructive` field (see §7) |

## 14. PRD Deviations

| PRD statement | Design decision | Rationale |
|---------------|-----------------|-----------|
| "multiprocessing + concurrent.futures" (§6, §8) | multiprocessing only | concurrent.futures adds no value over raw multiprocessing for our subprocess-per-test model; it would add an unnecessary abstraction layer |
| 32-bit support in MVP (§4, §11, §12) | Deferred to Phase 2 | Python 3.11+ on 32-bit is increasingly rare; SoftHSM2/Kryoptic 32-bit packages are not readily available; Docker linux/386 CI adds build complexity |
| ~200 tests for MVP (§9) | ~50-80 tests in Phase 1 | Limited by v3.x test module availability; v2.40 coverage first, expand as Kryoptic/NSS mature |

## 15. Platform Notes

- **Linux** (primary): full support, SIGKILL for timeout, .so module loading
- **macOS**: supported via python-pkcs11's existing macOS support, .dylib modules
- **Windows**: limited — multiprocessing spawn works, but timeout uses TerminateProcess
  instead of SIGKILL; .dll modules; some PKCS#11 modules have Windows-specific quirks

## 16. Phasing

### Phase 1 (MVP)
- Core engine: loader, isolation, timeout, config
- python-pkcs11 fork with v3.x interface negotiation
- CLI: `test`, `info`, `list`, `version` commands
- pytest plugin with fixtures and markers
- ~50-80 v2.40 tests against SoftHSM2
- v3.0/v3.2 tests against Kryoptic (as available)
- Output: rich + JSON + JUnit XML

### Phase 2
- Daemon mode with session management
- Crash-test module (libcrashtest.so)
- Complete v3.2 test coverage (as modules mature)
- `p11test compare` (diff two runs)
- 32-bit CI (Docker linux/386)

## 17. Technical Stack

| Component | Choice |
|-----------|--------|
| Python | 3.11+ |
| PKCS#11 binding | python-pkcs11 fork (Cython, v3.x support) |
| CLI | typer + rich |
| Config | pydantic-settings + TOML |
| Test framework | pytest |
| Parallel execution | pytest-xdist |
| Isolation | multiprocessing (spawn) |
| Process management | psutil |
| Build | hatchling |
| Package manager | uv |
| Linting | ruff |
| Type checking | mypy --strict |
| License | MIT |

## 18. Dependencies

```toml
dependencies = [
    "python-pkcs11 @ git+https://github.com/<owner>/python-pkcs11.git@v3-support",
    "typer>=0.15",
    "rich>=13.0",
    "pydantic-settings>=2.0",
    "psutil>=5.9",
    "pytest>=8.0",
    "pytest-xdist>=3.5",
]

[project.optional-dependencies]
dev = [
    "pytest-cov",
    "mypy",
    "ruff",
]
```

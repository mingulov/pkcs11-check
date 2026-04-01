# pkcs11-check

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Quick Reference

- **Language:** Python 3.13+
- **Package manager:** uv
- **Build backend:** hatchling (src/ layout)
- **CLI framework:** typer + rich
- **Config:** pydantic-settings (TOML + CLI + env)
- **Testing:** pytest (meta-tests in `tests/`, product test cases in `src/pkcs11_check/testcases/`)
- **Linting:** ruff
- **Type checking:** mypy --strict
- **PKCS#11 binding:** pkcs11_check.raw (pure ctypes, no C compilation)

See [docs/commands.md](docs/commands.md) for all build/test/docker commands.
See [docs/architecture.md](docs/architecture.md) for codebase structure, modules, and test writing guide.

## Git workflow — CRITICAL

- **Development branch:** `dev` — ALL work merges here. NEVER merge directly to `main`.
- **Main branch:** `main` — production snapshot, updated from `dev` only when the user says so
- Feature branches → merge to `dev`, not `main`
- Worktrees: use `.worktrees/` directory (gitignored)
- When finishing a branch: `git checkout dev && git merge <branch>` — NEVER `git checkout main`

## Coding Rules

### Documentation updates — DO NOT update statistics after every change
- Do NOT update docs with exact test counts, pass/fail numbers, or Docker results after each code change
- Statistics are for OFFICIAL RELEASES only
- Exception: adding NEW sections or features to docs is fine
- Exception: updating Docker results table after a deliberate full Docker validation run is fine

### Test coverage philosophy — CRITICAL
- **NEVER skip, disable, or suppress real failures or crashes.** pkcs11-check exists to find and report module bugs. A segfault IS the finding.
- If a module crashes on valid parameters, that is a module bug to be reported, not a test to be skipped.
- Tests may only be skipped for **missing capabilities** (mechanism not advertised, interface version too old) — never to hide broken behavior.
- Do not add `pytest.skip()` or `pytest.xfail()` for crashes, segfaults, or unexpected errors.
- Acceptable skips: `rs.has_mechanism()` returns False, `@pytest.mark.requires_v30` on v2.40 module, optional test data not present.
- Unacceptable skips: module segfaults, module returns wrong error code, module hangs.

### Error handling — CRITICAL
- **NEVER use a bare `except Exception: pass` or catch-all CKR check** — this hides real bugs. Every CKR check must list SPECIFIC acceptable return codes.
- Use predefined CKR tuples for common patterns:
  ```python
  from pkcs11_check.raw.types_std import (
      CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
      CKR_ATTRIBUTE_VALUE_INVALID, CKR_MECHANISM_INVALID,
      CKR_KEY_SIZE_RANGE, CKR_ARGUMENTS_BAD,
  )
  _TEMPLATE_ERRORS = (CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
                      CKR_ATTRIBUTE_VALUE_INVALID, CKR_ARGUMENTS_BAD)
  ```
- If a module returns an unexpected CKR, the test should FAIL — exposing the module bug.
- Login error handling: check specifically for `CKR_USER_ALREADY_LOGGED_IN` and `CKR_USER_TYPE_INVALID` (NSS quirk).

### PIN handling
- PIN values are never logged, printed, or included in error messages
- When `p11_config.pin` is `None`, don't call `C_Login`
- Never use `str(pin)` when pin might be `None`

### Test isolation
- Tests that call `lib.finalize()` or `lib.initialize()` MUST be marked `@destructive`
- Tests expecting crashes MUST run in subprocess via `subprocess.run([sys.executable, "-c", script])`
- Token-locking operations (wrong PIN tests) MUST be marked `@destructive`

### Module-specific behavior
- Document module quirks in `docs/module-issues.md`, not as silent `pass` in code
- Use `compliance.note()` for spec deviations that aren't bugs
- Use `pytest.xfail()` for known module bugs with an explanatory message
- NSS uses slot 1 (Certificate DB), not slot 0. Pass `--p11-slot=1`

### Conventions
- Type annotations on all public functions (mypy strict)
- `ruff` for formatting and linting — no other formatters
- Imports sorted by ruff (isort-compatible)
- Line length: 100
- Test files prefixed with `test_`
- Use `rich.console` for all CLI output (no bare print)
- Config values: snake_case in TOML/Python, kebab-case for CLI flags
- CVE regression tests reference the CVE/issue number in docstring
- ALWAYS use `uv run` prefix — tools are NOT on PATH

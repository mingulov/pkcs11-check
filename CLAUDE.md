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
- Tests may only be skipped for **missing capabilities** (mechanism not advertised, v3.x function absent from the module) — never to hide broken behavior.
- Do not add `pytest.skip()` or `pytest.xfail()` for crashes, segfaults, or unexpected errors.
- Acceptable skips: `rs.has_mechanism()` returns False, `@pytest.mark.needs_function("C_X")` when the module lacks that v3.x function, optional test data not present.
- Unacceptable skips: module segfaults, module returns wrong error code, module hangs.

### Test-outcome classification model — ONE RULE

Every test classifies `pass`/`xfail`/`fail`/`skip` by one provider-general rule.
Classify by **what the module did versus what is correct** — the pivot is *direction*:
the right thing done imperfectly is `xfail`; the wrong thing done (or a crash) is `fail`.

| Verdict | Positive op (valid input, advertised mechanism) | Negative op (must reject invalid input / policy) |
|---|---|---|
| **pass** | `CKR_OK` + correct output/value | rejects with the **expected** spec CKR |
| **xfail** | clean error — advertised but not operational | rejects with **some other** (clean) code |
| **fail** | `CKR_OK` but **wrong** output/value | `CKR_OK`/accepted **and** it is a crypto-correctness break (Type A) or self-contradiction (Type B/C/D) |
| **fail** | crash / hang | crash / hang |
| **skip** | capability genuinely absent | capability genuinely absent |

**Core principle:** Self-contradiction = `fail`. A single honest deviation = `xfail`.
**Verify the *effect*, not the return code.** `xfail` is the universal provider-general
"noted deviation, investigate later" bucket — it is recorded, not hidden, and is **never
gated on provider identity**. No per-provider config, baselines, or allowlists.

- The four self-contradiction classes that `fail` on acceptance: **A** crypto-correctness
  (wrong/forgeable result), **B** attribute/permission (claimed a protection then violated
  it), **C** lifecycle/state (claimed success then didn't honor it), **D** derived-attribute
  invariant (two linked attributes that cannot both be true).
- Helpers (in `testcases/conftest.py`): `classify_negative_rv(rv, expected_rvs, *, label,
  allow_ok=False)` and `reject_or_classify(exc, expected_rvs, *, label)` for negative ops
  outside the table; `classify_policy_enforcement(*, claimed, violated, label)` for Type B;
  `classify_lifecycle_effect(*, claimed_success, effect_observed, label)` for Type C.
  Table-driven negative sites use `assert_ckr()` (3-way) over `CkrExpectation` in
  `testcases/ckr/_ckr_spec.py`.
- **This supersedes** the "use `pytest.xfail()` for known module bugs" guidance below for
  Type-A and self-contradiction (Type B/C/D) classes: those `fail`, they are not `xfail`ed.
- Full model + A/B/C/D rules: [docs/classification-model-design.md](docs/classification-model-design.md).

Two spec-grounded refinements (design: docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md):
- **Sanctioned policy refusal = pass:** in the `test_mech_*` claim layer, a clean refusal with
  `CKR_OPERATION_NOT_VALIDATED` (PKCS#11 v3.2 validation-policy code) is conformant → **pass** +
  `compliance.note`. Any other clean refusal of an advertised (mechanism, operation) stays xfail.
- **Vacuous reject = xfail:** where a canonical operability probe says NOT_OPERATIONAL, a
  negative-op "rejection" never evaluated the input → **xfail**, not pass (INCONCLUSIVE never
  triggers this; WRONG_OUTPUT also leaves the pass untouched).
- At claim-layer xfail sites the first refinement **supersedes** the "every CKR check must list
  SPECIFIC acceptable return codes" rule below; that rule remains in force for negative-op
  assertions.

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

### Execution model — segfault survival via isolation (CRITICAL mental model)
- **Purpose:** pkcs11-check is a general PKCS#11 conformance + bug-finding suite run
  against MANY modules **directly** (softhsm2/kryoptic/NSS/tpm2/bouncyhsm/
  opencryptoki/mock/…). A proxy/daemon in front is just ONE deployment, not the model.
  **"A segfault IS the finding."**
- `pkcs11-check test` defaults to `--isolation auto`: each test FILE (or each test,
  for `subprocess_per_test`) runs in its **own subprocess** (`core/file_runner.py`).
  A module crash kills only that unit's subprocess; the runner records it as a crash
  finding (`returncode < 0`, see `_status_from_returncode` / `_identify_crash_culprit`)
  and continues, bounded by `--max-crashes-per-file`.
- **So write ordinary tests in-process** (like `testcases/test_reinitialize.py`); the
  isolated runner provides crash survival. Do NOT wrap a normal test in `subprocess.run`
  just so a possible crash is survived — isolation already does that.
- `run_raw_subprocess` (`testcases/_raw_subprocess.py`) is ONLY for tests that need
  their OWN child to run a controlled crash-expecting sub-script, or to assert on a
  specific crash's `returncode` — not for general survival.

### Test isolation
- Tests that call `lib.finalize()` or `lib.initialize()` MUST be marked `@destructive`
- Tests that DELIBERATELY trigger a crash and assert on it run their own child via
  `subprocess.run([sys.executable, "-c", script])` (general survival is already provided
  by `--isolation auto`; see the execution model above)
- Token-locking operations (wrong PIN tests) MUST be marked `@destructive`

### Module-specific behavior
- Document module quirks in `docs/module-issues.md`, not as silent `pass` in code
- Use `compliance.note()` for spec deviations that aren't bugs
- Use `pytest.xfail()` for known module bugs with an explanatory message — but see the
  Test-outcome classification model above: Type-A and self-contradiction (B/C/D) classes
  `fail`, they are NOT `xfail`ed
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

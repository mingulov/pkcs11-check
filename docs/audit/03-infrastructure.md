# Audit 03: Infrastructure Audit

**Date:** 2026-04-01
**OASIS specs referenced:** `general_purpose_functions.md`
**Files audited:** `fixtures.py`, `raw_fixtures.py`, `config.py`, `markers.py`, `plugin.py`, `testcases/conftest.py`, `testcases/mechanism_selection.py`

## Findings

### Quality Issues

- [FIXED] `raw_fixtures.py:70-73` — bare `except Exception: pass` on C_Logout replaced with `logout_quietly()` which only catches `AttributeError, OSError, ctypes.ArgumentError`
- [FIXED] `fixtures.py:66-73` — session handle leak when `login_user()` raises: added try/except that calls `close_session_quietly()` before re-raising
- [FIXED] `fixtures.py:99-100,228-229` — raw `C_Logout()` with return value ignored replaced with `logout_quietly()` in both `p11_session` and `p11_raw_session` fixtures
- [FIXED] `markers.py:9-11` — missing `requires_v31` marker: added to `_MARKER_MIN_VERSION` and `MARKER_DEFINITIONS`. PKCS#11 v3.1 introduced profile objects and C_SessionCancel refinements; tests relying on v3.1 features now have proper skip gating.

### Spec Deviations

- [NOTED] Config precedence issue: `fixtures.py:26-32` — CLI defaults for `--p11-slot` (0), `--p11-interface` (auto), `--p11-destructive` (False) always override TOML/env values because `getoption()` returns the default, not None. The `--p11-pin` option correctly uses None sentinel. Fix requires changing CLI option defaults to None and filtering None values from kwargs — deferred to avoid breaking changes without testing.

### Coverage Gaps

- [NOTED] `mechanism_selection.py:192-213` — multipart guard when config is None skips adding `unsupported_multi_part` rejection reason, potentially underreporting in telemetry. Functional behavior is correct (mechanism is still rejected via `missing_registry_config`).
- [NOTED] `raw_fixtures.py:27-34` — session-scoped `raw_pkcs11` fixture never calls `C_Finalize`. Could cause resource leaks in multi-process scenarios. Noted for future fix.

## Changes Made

- Modified: `raw_fixtures.py` — replaced bare except with `logout_quietly()`
- Modified: `fixtures.py` — fixed session handle leak on login failure; replaced raw C_Logout with `logout_quietly()` in both fixtures
- Modified: `markers.py` — added `requires_v31` marker definition and version mapping

## Statistics

- Files audited: 7
- Issues found: 7 (4 fixed, 3 noted)
- Tests added: 0
- Lines changed: +13/-8

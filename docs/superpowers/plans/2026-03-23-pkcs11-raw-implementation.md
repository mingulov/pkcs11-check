# PKCS#11 Raw Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `pkcs11_check.raw` into the exact-call PKCS#11 substrate for pkcs11-check, with generated standard v3.2 declarations, explicit pack/fault/inspect layers, and the first migration of raw-heavy tests.

**Architecture:** Keep a strict trust boundary: generated standard declarations and metadata feed a hand-written raw dispatch layer that always returns integer `CK_RV` values and never auto-raises. Build explicit pack, fault, inspect, and bootstrap layers on top, then migrate raw-heavy tests away from ad hoc `ctypes` boilerplate before considering any higher-level convenience API.

**Tech Stack:** Python 3.11+, `ctypes`, `uv`, pytest, hatchling, pinned PKCS#11 v3.2 public-domain header, existing python-pkcs11 fork bridge

**Spec:** `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md`

---

## Worktree Note

Execution should happen in an isolated worktree. The current repository root is already dirty with in-progress raw refactor work, so implementers should start from a clean worktree rooted from `dev` before changing code.

## File Structure

### New Files

- `third_party/pkcs11-headers/3.2/pkcs11.h`
  - pinned standard header snapshot
- `scripts/generate_raw_standard.py`
  - constrained generator for the pinned standard header
- `src/pkcs11_check/raw/types_std.py`
  - generated constants, aliases, structs, and unions
- `src/pkcs11_check/raw/metadata_std.py`
  - generated function signatures, function-list indices, symbol tables, counts
- `src/pkcs11_check/raw/api.py`
  - exact `RawPKCS11` dispatch built on generated metadata
- `src/pkcs11_check/raw/pack.py`
  - exact valid-value packers and value model
- `src/pkcs11_check/raw/faults.py`
  - explicit malformed-input constructors
- `src/pkcs11_check/raw/inspect.py`
  - call rendering and debug helpers
- `src/pkcs11_check/raw/extensions.py`
  - explicit vendor-extension registry for names, structs, packers, and inspectors
- `src/pkcs11_check/raw/bootstrap.py`
  - explicit slot/session/login helpers with no crypto policy
- `tests/test_raw_generation.py`
  - meta-tests for generated symbol coverage and counts
- `tests/test_raw_api.py`
  - meta-tests for `RawPKCS11` public method surface and loading behavior
- `tests/test_raw_pack.py`
  - meta-tests for valid exact packing
- `tests/test_raw_faults.py`
  - meta-tests for malformed-input modeling
- `tests/test_raw_inspect.py`
  - meta-tests for call rendering
- `tests/test_raw_extensions.py`
  - meta-tests for vendor-extension registration without gating unknown vendor ids
- `tests/test_raw_bootstrap.py`
  - meta-tests for bootstrap/session helper explicitness

### Existing Files To Modify

- `src/pkcs11_check/raw/__init__.py`
  - export new standard layers
- `src/pkcs11_check/raw/core.py`
  - temporary compatibility wrapper to `api.py`
- `src/pkcs11_check/raw/template.py`
  - temporary compatibility wrapper to `pack.py`
- `src/pkcs11_check/raw/mechanism.py`
  - temporary compatibility wrapper to `pack.py`
- `src/pkcs11_check/raw/rv.py`
  - keep integer-first error naming helpers; add explicit `ckr_name` alias
- `src/pkcs11_check/raw/bridge.py`
  - keep bridge path to fork-loaded libraries
- `src/pkcs11_check/core/loader.py`
  - keep `raw()` / `get_interface_list()` aligned with new `api.py`
- `tests/test_raw.py`
  - convert current smoke tests into compatibility/import checks
- `tests/test_loader.py`
  - keep bridge integration tests
- `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py`
  - migrate to bootstrap/pack/fault helpers
- `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py`
  - migrate to bootstrap/pack helpers
- `src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py`
  - migrate to bootstrap/pack helpers
- `src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py`
  - migrate to bootstrap/pack helpers
- `src/pkcs11_check/testcases/test_tls12.py`
  - migrate raw negative template/mechanism setup to helpers
- `src/pkcs11_check/testcases/test_sign_recover.py`
  - remove ad hoc `C_GetFunctionList` / local structs
- `src/pkcs11_check/testcases/test_dual_function.py`
  - remove ad hoc `C_GetFunctionList` / local structs
- `src/pkcs11_check/testcases/test_operation_state.py`
  - remove ad hoc `C_GetFunctionList` / local structs
- `pyproject.toml`
  - include vendored header path in source distributions if needed

## Context For Implementers

- Current raw extraction exists in `src/pkcs11_check/raw/`
- Current bridge integration exists in `src/pkcs11_check/core/loader.py`
- Existing design spec: `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md`
- Existing raw-heavy tests are the first migration targets, not the final convenience layer
- The raw layer must always return integer `CK_RV` values and never auto-raise
- The raw layer must stay open to future vendor mechanisms and parameter structs without patching the
  generated standard modules

## Task 1: Vendor The Standard Header And Define Generator Expectations

**Files:**
- Create: `third_party/pkcs11-headers/3.2/pkcs11.h`
- Create: `tests/test_raw_generation.py`
- Create: `scripts/generate_raw_standard.py`

- [ ] **Step 1: Add the pinned PKCS#11 v3.2 public-domain header snapshot**

Place the exact standard header at `third_party/pkcs11-headers/3.2/pkcs11.h`. Do not add a downloader to the implementation path; generation must work offline from the vendored file.

- [ ] **Step 2: Write a failing generation smoke test**

Add to `tests/test_raw_generation.py`:

```python
from __future__ import annotations

import importlib.util
from pathlib import Path


def test_vendored_header_exists() -> None:
    assert Path("third_party/pkcs11-headers/3.2/pkcs11.h").is_file()


def test_generated_modules_exist() -> None:
    assert importlib.util.find_spec("pkcs11_check.raw.types_std") is not None
    assert importlib.util.find_spec("pkcs11_check.raw.metadata_std") is not None
```

- [ ] **Step 3: Run the generation tests and verify they fail**

Run: `uv run python -m pytest tests/test_raw_generation.py -q`
Expected: FAIL because generated modules do not exist yet

- [ ] **Step 4: Implement the minimal generator skeleton**

Create `scripts/generate_raw_standard.py` with:

```python
from __future__ import annotations

from pathlib import Path


HEADER = Path("third_party/pkcs11-headers/3.2/pkcs11.h")
OUT_TYPES = Path("src/pkcs11_check/raw/types_std.py")
OUT_METADATA = Path("src/pkcs11_check/raw/metadata_std.py")


def main() -> None:
    if not HEADER.is_file():
        raise SystemExit(f"missing header: {HEADER}")

    OUT_TYPES.write_text(
        '"""Generated PKCS#11 standard types/constants."""\\n'
        "from __future__ import annotations\\n\\n"
        "STANDARD_GENERATED = True\\n"
    )
    OUT_METADATA.write_text(
        '"""Generated PKCS#11 standard metadata."""\\n'
        "from __future__ import annotations\\n\\n"
        'STANDARD_COUNTS = {"functions": 0, "attrs": 0, "mechanisms": 0}\\n'
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run the generator and the existence tests**

Run:
- `uv run python scripts/generate_raw_standard.py`
- `uv run python -m pytest tests/test_raw_generation.py -q`
Expected: PASS for header/module existence checks only

- [ ] **Step 6: Commit**

```bash
git add third_party/pkcs11-headers/3.2/pkcs11.h \
  scripts/generate_raw_standard.py \
  src/pkcs11_check/raw/types_std.py \
  src/pkcs11_check/raw/metadata_std.py \
  tests/test_raw_generation.py
git commit -m "feat: add pkcs11 raw generation scaffold"
```

## Task 2: Generate Standard Constants, Structs, And Metadata

**Files:**
- Modify: `scripts/generate_raw_standard.py`
- Modify: `src/pkcs11_check/raw/types_std.py`
- Modify: `src/pkcs11_check/raw/metadata_std.py`
- Modify: `tests/test_raw_generation.py`

- [ ] **Step 1: Expand tests to assert real counts and representative symbols**

Add to `tests/test_raw_generation.py`:

```python
def test_generated_standard_symbols_cover_representative_values() -> None:
    from pkcs11_check.raw import metadata_std, types_std

    assert metadata_std.STANDARD_COUNTS["functions"] == 104
    assert metadata_std.STANDARD_COUNTS["attrs"] >= 160
    assert metadata_std.STANDARD_COUNTS["mechanisms"] >= 480
    assert hasattr(types_std, "CKA_CLASS")
    assert hasattr(types_std, "CKM_AES_GCM")
    assert hasattr(types_std, "CKK_AES")
    assert hasattr(types_std, "CK_GCM_PARAMS")
```

- [ ] **Step 2: Run tests and verify they fail on count/symbol expectations**

Run: `uv run python -m pytest tests/test_raw_generation.py -q`
Expected: FAIL on zero counts and missing generated symbols

- [ ] **Step 3: Implement constrained parsing for the vendored standard header**

In `scripts/generate_raw_standard.py`, add extraction for:

- `#define CKA_*`, `CKM_*`, `CKK_*`, `CKO_*`, `CKR_*`, `CKF_*`
- `struct CK_* { ... }` blocks
- `extern CK_RV C_*` prototypes

Represent the parsed output in an internal IR:

```python
symbols: dict[str, int | str]
structs: dict[str, list[tuple[str, str]]]
functions: list[tuple[str, list[str]]]
```

- [ ] **Step 4: Emit real generated modules**

Generate:
- `types_std.py` with constants, `ctypes` aliases, and representative standard structs
- `metadata_std.py` with `FUNCTION_SIGNATURES`, `FUNCTION_INDICES`, `STANDARD_COUNTS`, and symbol-name tables

- [ ] **Step 5: Re-run generator and tests**

Run:
- `uv run python scripts/generate_raw_standard.py`
- `uv run python -m pytest tests/test_raw_generation.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/generate_raw_standard.py \
  src/pkcs11_check/raw/types_std.py \
  src/pkcs11_check/raw/metadata_std.py \
  tests/test_raw_generation.py
git commit -m "feat: generate pkcs11 raw standard declarations"
```

## Task 3: Introduce `api.py` And Preserve Compatibility

**Files:**
- Create: `src/pkcs11_check/raw/api.py`
- Modify: `src/pkcs11_check/raw/__init__.py`
- Modify: `src/pkcs11_check/raw/core.py`
- Modify: `src/pkcs11_check/raw/bridge.py`
- Modify: `src/pkcs11_check/core/loader.py`
- Create: `tests/test_raw_api.py`
- Modify: `tests/test_raw.py`
- Modify: `tests/test_loader.py`

- [ ] **Step 1: Write failing API surface tests**

Add to `tests/test_raw_api.py`:

```python
from __future__ import annotations


def test_generated_standard_c_methods() -> None:
    from pkcs11_check.raw import metadata_std

    names = set(metadata_std.FUNCTION_SIGNATURES)
    assert "C_GetFunctionList" in names
    assert "C_CancelFunction" in names
    assert "C_DigestEncryptUpdate" in names
    assert len(names) >= 104


def test_rawpkcs11_available_function_names_are_explicit() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_GetFunctionList": object(), "C_CancelFunction": object()}

    assert raw.available_function_names() == {"C_GetFunctionList", "C_CancelFunction"}


def test_raw_api_never_auto_raises() -> None:
    from pkcs11_check.raw.rv import ckr_name

    assert ckr_name(0x00000007) == "CKR_ARGUMENTS_BAD"
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `uv run python -m pytest tests/test_raw_api.py tests/test_raw.py tests/test_loader.py -q`
Expected: FAIL because `api.py` does not exist and missing methods remain

- [ ] **Step 3: Implement `src/pkcs11_check/raw/api.py`**

Move the real `RawPKCS11` implementation into `api.py` and make it consume generated metadata rather than hand-maintained tables.

Key requirement:

```python
class RawPKCS11:
    def available_function_names(self) -> set[str]:
        return set(self._funcs)

    def _call(self, name: str, *args: Any) -> int:
        func = self._funcs.get(name)
        if func is None:
            raise AttributeError(f"{name} not available in this module")
        return int(func(*args))
```

- [ ] **Step 4: Turn `core.py` into a compatibility wrapper**

Replace most of `core.py` with re-exports from `api.py` and `types_std.py`, keeping existing imports working during migration.

- [ ] **Step 5: Update package exports and bridge users**

Adjust:
- `src/pkcs11_check/raw/__init__.py`
- `src/pkcs11_check/raw/bridge.py`
- `src/pkcs11_check/core/loader.py`

to import `RawPKCS11` from `api.py`.

- [ ] **Step 6: Run tests**

Run: `uv run python -m pytest tests/test_raw_api.py tests/test_raw.py tests/test_loader.py -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/raw/api.py \
  src/pkcs11_check/raw/__init__.py \
  src/pkcs11_check/raw/core.py \
  src/pkcs11_check/raw/bridge.py \
  src/pkcs11_check/core/loader.py \
  tests/test_raw_api.py \
  tests/test_raw.py \
  tests/test_loader.py
git commit -m "feat: add generated raw api layer"
```

## Task 4: Build The Exact Pack Layer

**Files:**
- Create: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/template.py`
- Modify: `src/pkcs11_check/raw/mechanism.py`
- Create: `tests/test_raw_pack.py`

- [ ] **Step 1: Write failing pack tests**

Add to `tests/test_raw_pack.py`:

```python
from __future__ import annotations


def test_pack_template_keeps_pointer_and_length_separate() -> None:
    from pkcs11_check.raw.pack import attr_ulong, explicit_length

    attr = attr_ulong(0x00000161, 32, length=explicit_length(1))
    assert attr.attribute.ulValueLen == 1


def test_pack_nested_templates_are_supported() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_template, template

    inner = template(attr_bool(0x00000104, True))
    outer = template(attr_template(0x40000211, inner))
    assert outer.count == 1
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `uv run python -m pytest tests/test_raw_pack.py -q`
Expected: FAIL because `pack.py` does not exist

- [ ] **Step 3: Implement value and helper types in `pack.py`**

Start with:
- `LengthArg`
- `PointerArg`
- `PackedAttribute`
- `PackedMechanism`
- `TemplateArg`
- `MechanismArg`
- scalar/bytes/string/date/array helpers

- [ ] **Step 4: Make `template.py` and `mechanism.py` compatibility wrappers**

Re-export the old helper names from `pack.py` so existing imports still work.

- [ ] **Step 5: Run tests**

Run: `uv run python -m pytest tests/test_raw_pack.py tests/test_raw.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/pack.py \
  src/pkcs11_check/raw/template.py \
  src/pkcs11_check/raw/mechanism.py \
  tests/test_raw_pack.py \
  tests/test_raw.py
git commit -m "feat: add exact raw pack layer"
```

## Task 5: Add Fault Modeling, Inspection, Extension Registration, And Error Naming

**Files:**
- Create: `src/pkcs11_check/raw/faults.py`
- Create: `src/pkcs11_check/raw/inspect.py`
- Create: `src/pkcs11_check/raw/extensions.py`
- Modify: `src/pkcs11_check/raw/rv.py`
- Create: `tests/test_raw_faults.py`
- Create: `tests/test_raw_inspect.py`
- Create: `tests/test_raw_extensions.py`

- [ ] **Step 1: Write failing fault tests**

Add to `tests/test_raw_faults.py`:

```python
from __future__ import annotations


def test_null_pointer_and_zero_length_are_distinct() -> None:
    from pkcs11_check.raw.faults import null_pointer, zero_length

    assert null_pointer() != zero_length()


def test_truncated_struct_keeps_explicit_short_length() -> None:
    from pkcs11_check.raw.faults import truncated_struct
    from pkcs11_check.raw.types_std import CK_GCM_PARAMS

    value = truncated_struct(CK_GCM_PARAMS, keep=8)
    assert value.explicit_length == 8
```

- [ ] **Step 2: Write failing inspection tests**

Add to `tests/test_raw_inspect.py`:

```python
from __future__ import annotations


def test_inspect_mechanism_shows_symbol_and_length() -> None:
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import mech_simple
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    text = render_mechanism(mech_simple(CKM_AES_KEY_GEN))
    assert "CKM_AES_KEY_GEN" in text
    assert "len=0" in text
```

- [ ] **Step 3: Write failing extension-registry tests**

Add to `tests/test_raw_extensions.py`:

```python
from __future__ import annotations


def test_unknown_vendor_numeric_id_needs_no_registration() -> None:
    from pkcs11_check.raw.pack import mech_simple

    mech = mech_simple(0x80010001)
    assert mech.ck.mechanism == 0x80010001


def test_extension_registration_adds_names_without_blocking_execution() -> None:
    from pkcs11_check.raw.extensions import lookup_symbol_name, register_extension

    register_extension(namespace="ibm", mechanisms={0x80010001: "CKM_IBM_KYBER"})
    assert lookup_symbol_name("mechanisms", 0x80010001) == "CKM_IBM_KYBER"
```

- [ ] **Step 4: Run tests and verify they fail**

Run:
`uv run python -m pytest tests/test_raw_faults.py tests/test_raw_inspect.py tests/test_raw_extensions.py -q`
Expected: FAIL because modules do not exist

- [ ] **Step 5: Implement faults, inspect, extensions, and `ckr_name`**

Implement:
- `null_pointer()`
- `explicit_length()`
- `truncated_struct()`
- call render helpers
- `register_extension()`
- `lookup_symbol_name()`
- `ckr_name()` as alias for `rv_name()`

- [ ] **Step 6: Run tests**

Run:
`uv run python -m pytest tests/test_raw_faults.py tests/test_raw_inspect.py tests/test_raw_extensions.py tests/test_raw_api.py -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/raw/faults.py \
  src/pkcs11_check/raw/inspect.py \
  src/pkcs11_check/raw/extensions.py \
  src/pkcs11_check/raw/rv.py \
  tests/test_raw_faults.py \
  tests/test_raw_inspect.py \
  tests/test_raw_extensions.py \
  tests/test_raw_api.py
git commit -m "feat: add raw fault, inspect, and extension layers"
```

## Task 6: Add Explicit Bootstrap Helpers

**Files:**
- Create: `src/pkcs11_check/raw/bootstrap.py`
- Create: `tests/test_raw_bootstrap.py`
- Modify: `src/pkcs11_check/raw/__init__.py`

- [ ] **Step 1: Write failing bootstrap tests**

Add to `tests/test_raw_bootstrap.py`:

```python
from __future__ import annotations

from unittest.mock import MagicMock


def test_open_session_requires_explicit_flags() -> None:
    from pkcs11_check.raw.bootstrap import open_session

    raw = MagicMock()
    open_session(raw, slot_id=5, flags=0x6)
    raw.C_OpenSession.assert_called_once()


def test_login_user_is_explicit() -> None:
    from pkcs11_check.raw.bootstrap import login_user

    raw = MagicMock()
    login_user(raw, session=7, user_type=1, pin=b"1234")
    raw.C_Login.assert_called_once()
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `uv run python -m pytest tests/test_raw_bootstrap.py -q`
Expected: FAIL because module does not exist

- [ ] **Step 3: Implement explicit bootstrap helpers**

Implement:
- `get_slot_ids(raw, token_present=True)`
- `open_session(raw, slot_id, flags)`
- `login_user(raw, session, user_type, pin)`
- `close_session_quietly(raw, session)` for teardown only

- [ ] **Step 4: Run tests**

Run: `uv run python -m pytest tests/test_raw_bootstrap.py tests/test_loader.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/raw/bootstrap.py \
  src/pkcs11_check/raw/__init__.py \
  tests/test_raw_bootstrap.py
git commit -m "feat: add explicit raw bootstrap helpers"
```

## Task 7: Migrate The First Raw-Heavy Product Tests

**Files:**
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py`
- Modify: `src/pkcs11_check/testcases/test_tls12.py`

- [ ] **Step 1: Replace duplicated session/bootstrap boilerplate in one file first**

Start with `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py` and replace local session setup with imports from:
- `pkcs11_check.raw.api`
- `pkcs11_check.raw.bootstrap`
- `pkcs11_check.raw.pack`
- `pkcs11_check.raw.faults`

- [ ] **Step 2: Run just that file**

Run:
`bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py -v`
Expected: same pass/skip behavior as before, with less embedded `ctypes` boilerplate

- [ ] **Step 3: Migrate the other CKR raw helper files**

Apply the same pattern to:
- `test_ckr_raw_buffer.py`
- `test_ckr_raw_attrs.py`
- `test_ckr_raw_state.py`

- [ ] **Step 4: Migrate the raw TLS negative setup**

Update `src/pkcs11_check/testcases/test_tls12.py` to use the new raw bootstrap/pack helpers for the existing subprocess raw snippet.

- [ ] **Step 5: Run the focused regression**

Run:
`bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py src/pkcs11_check/testcases/test_tls12.py -v`
Expected: PASS or existing module-specific skips/xfails only; no new semantic drift

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py \
  src/pkcs11_check/testcases/test_tls12.py
git commit -m "refactor: migrate raw-heavy tests to shared raw helpers"
```

## Task 8: Remove Remaining Ad Hoc Function-List Usage

**Files:**
- Modify: `src/pkcs11_check/testcases/test_sign_recover.py`
- Modify: `src/pkcs11_check/testcases/test_dual_function.py`
- Modify: `src/pkcs11_check/testcases/test_operation_state.py`
- Modify: `src/pkcs11_check/testcases/test_remaining_gaps.py`

- [ ] **Step 1: Migrate one manual file completely**

Start with `src/pkcs11_check/testcases/test_sign_recover.py` and replace:
- local `C_GetFunctionList` usage
- local `CK_MECHANISM` / `CK_ATTRIBUTE` definitions
- local PKCS#11 session bootstrap

with the new raw api/bootstrap/pack helpers.

- [ ] **Step 2: Run that file**

Run: `bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_sign_recover.py -v`
Expected: same behavior as before, no ad hoc PKCS#11 ctypes declarations remain

- [ ] **Step 3: Apply the same refactor to the other manual files**

Update:
- `test_dual_function.py`
- `test_operation_state.py`
- `test_remaining_gaps.py`

- [ ] **Step 4: Run the focused regression**

Run:
`bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_sign_recover.py src/pkcs11_check/testcases/test_dual_function.py src/pkcs11_check/testcases/test_operation_state.py src/pkcs11_check/testcases/test_remaining_gaps.py -v`
Expected: PASS or documented module-specific skips/xfails only

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/test_sign_recover.py \
  src/pkcs11_check/testcases/test_dual_function.py \
  src/pkcs11_check/testcases/test_operation_state.py \
  src/pkcs11_check/testcases/test_remaining_gaps.py
git commit -m "refactor: remove ad hoc raw ctypes from product tests"
```

## Task 9: Packaging, Docs, And Verification

**Files:**
- Modify: `pyproject.toml`
- Modify: `docs/test-coverage.md`
- Modify: `docs/gap-analysis-oasis-spec.md`
- Modify: `docs/python-pkcs11-fork.md`

- [ ] **Step 1: Ensure vendored header and generated modules are packaged**

Update `pyproject.toml` so source distributions and wheels include the vendored header and generated modules if needed by the generator/workflow.

- [ ] **Step 2: Add a simple drift check command**

Add a documented command:

```bash
uv run python scripts/generate_raw_standard.py
uv run python -m pytest tests/test_raw_generation.py -q
```

- [ ] **Step 3: Run meta-tests**

Run:
`uv run python -m pytest tests/test_raw_generation.py tests/test_raw_api.py tests/test_raw_pack.py tests/test_raw_faults.py tests/test_raw_inspect.py tests/test_raw_extensions.py tests/test_raw_bootstrap.py tests/test_raw.py tests/test_loader.py -q`
Expected: PASS

- [ ] **Step 4: Run targeted product regressions**

Run the commands from Tasks 7 and 8 again.
Expected: same behavior as before migration, without new semantic drift

- [ ] **Step 5: Run lint and type checks**

Run:
- `uv run ruff check src/ tests/`
- `uv run mypy src/`

Expected: PASS, or document environment/tooling gaps if the commands are unavailable

- [ ] **Step 6: Update docs**

Update:
- `docs/test-coverage.md`
- `docs/gap-analysis-oasis-spec.md`
- `docs/python-pkcs11-fork.md`

to reflect the new raw architecture, generated standard layer, and reduced fork responsibilities.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml \
  docs/test-coverage.md \
  docs/gap-analysis-oasis-spec.md \
  docs/python-pkcs11-fork.md
git commit -m "docs: document generated raw architecture rollout"
```

## Final Verification Checklist

- `uv run python -m pytest tests/test_raw_generation.py tests/test_raw_api.py tests/test_raw_pack.py tests/test_raw_faults.py tests/test_raw_inspect.py tests/test_raw_extensions.py tests/test_raw_bootstrap.py tests/test_raw.py tests/test_loader.py -q`
- `bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py src/pkcs11_check/testcases/test_tls12.py src/pkcs11_check/testcases/test_sign_recover.py src/pkcs11_check/testcases/test_dual_function.py src/pkcs11_check/testcases/test_operation_state.py src/pkcs11_check/testcases/test_remaining_gaps.py -v`
- `uv run ruff check src/ tests/`
- `uv run mypy src/`

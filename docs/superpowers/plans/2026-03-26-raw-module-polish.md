# Raw Module Polish (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a CK_NOTIFY bug, remove dead code, make private APIs public, apply DRY improvements, clean up style, and restructure imports across the pkcs11_check.raw module.

**Architecture:** 9 independent tasks executed in dependency order. Each task is self-contained with its own commit. Tasks 1-4 are safe mechanical changes. Tasks 5-6 involve more judgment (DRY refactors). Tasks 7-8 touch multiple files (subprocess helper, import cleanup). Task 9 is final verification.

**Tech Stack:** Python 3.11+, ctypes, pytest, ruff, mypy

**Spec:** `docs/superpowers/specs/2026-03-26-raw-module-polish-design.md`

---

### Task 1: Bug fix -- CK_NOTIFY in test_v30_session.py

**Files:**
- Modify: `src/pkcs11_check/testcases/test_v30_session.py`

- [ ] **Step 1: Fix the subprocess script**

In `test_v30_session.py`, find the subprocess script in `test_cancel_after_digest_init_subprocess` (around line 540-625). In the `from pkcs11_check.raw.types_std import (...)` block inside the script string, add `CK_NOTIFY` to the imports. Then find the `C_OpenSession` call (around line 578-581) and change the 4th argument from `None` to `CK_NOTIFY()`.

The current code:
```python
rv = raw.C_OpenSession(
    {actual_slot_id}, CKF_SERIAL_SESSION | CKF_RW_SESSION,
    None, None, byref(session_handle),
)
```

Change to:
```python
rv = raw.C_OpenSession(
    {actual_slot_id}, CKF_SERIAL_SESSION | CKF_RW_SESSION,
    None, CK_NOTIFY(), byref(session_handle),
)
```

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/pkcs11_check/testcases/test_v30_session.py --fix
uv run ruff format src/pkcs11_check/testcases/test_v30_session.py
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/test_v30_session.py
git commit -m "fix: use CK_NOTIFY() instead of None in test_v30_session subprocess

ctypes CFUNCTYPE is strict -- C_OpenSession's CK_NOTIFY parameter needs
a null function pointer instance, not bare None."
```

---

### Task 2: Dead code removal (B1-B5)

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/rv.py`
- Modify: `src/pkcs11_check/raw/extensions.py`
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `tests/test_raw.py`

- [ ] **Step 1: Remove dead aliases in pack.py**

Remove these two lines (around line 154-155):
```python
MechanismArg = PackedMechanism
CKTemplate = TemplateArg
```

- [ ] **Step 2: Collapse rv.py**

Replace the entire content of `src/pkcs11_check/raw/rv.py` with:

```python
"""Helpers for checking and describing raw CK_RV return values."""

from __future__ import annotations

from . import metadata_std
from .extensions import lookup_symbol_name
from .types_std import CKR

_RV_NAMES = dict(metadata_std.RV_NAMES)


def ckr_name(rv: int) -> str:
    """Return a symbolic CKR_* name for a CK_RV integer when known."""
    return lookup_symbol_name("rvs", rv) or _RV_NAMES.get(rv, f"0x{rv:08x}")


def expect_rv(rv: int, *allowed: CKR) -> int:
    """Return rv if allowed, otherwise raise an AssertionError."""
    if rv in allowed:
        return rv
    allowed_names = ", ".join(ckr_name(value) for value in allowed)
    raise AssertionError(f"Unexpected CK_RV {ckr_name(rv)}; expected one of: {allowed_names}")
```

This removes `rv_name` (renamed to `ckr_name`), `ckr_is_ok`, and `ckr_in`.

- [ ] **Step 3: Remove 4 meta-tests for deleted functions**

In `tests/test_raw.py`, remove the 4 test functions:
- `test_ckr_is_ok_returns_true_for_ok`
- `test_ckr_is_ok_returns_false_for_error`
- `test_ckr_in_matches_acceptable`
- `test_ckr_in_rejects_unacceptable`

Also remove any `from pkcs11_check.raw.rv import ckr_is_ok, ckr_in` imports that become unused.

- [ ] **Step 4: Remove _lookup_unique in extensions.py**

Remove the function `_lookup_unique` (around line 247-253 in extensions.py):
```python
def _lookup_unique(values: list[Any]) -> Any | None:
    if not values:
        return None
    first = values[0]
    if all(value == first for value in values[1:]):
        return first
    return None
```

- [ ] **Step 5: Narrow destroy_quietly in recipes.py**

In `recipes.py`, find `destroy_quietly` (around line 255-260). Change:
```python
    except Exception:
        pass
```
To:
```python
    except (AttributeError, OSError, ctypes.ArgumentError):
        pass
```

- [ ] **Step 6: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/raw/ tests/test_raw.py --fix
uv run ruff format src/pkcs11_check/raw/ tests/test_raw.py
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/rv.py \
  src/pkcs11_check/raw/extensions.py src/pkcs11_check/raw/recipes.py \
  tests/test_raw.py
git commit -m "refactor: remove dead code and narrow destroy_quietly

Remove MechanismArg/CKTemplate aliases, ckr_is_ok/ckr_in functions,
_lookup_unique, and collapse rv_name into ckr_name. Narrow
destroy_quietly to specific exception types."
```

---

### Task 3: API hygiene (C1-C2)

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/__init__.py`
- Modify: `src/pkcs11_check/testcases/test_eddsa.py`
- Modify: `src/pkcs11_check/testcases/test_pqc_sign.py`
- Modify: `src/pkcs11_check/testcases/test_kem.py`
- Modify: `src/pkcs11_check/testcases/test_hash_ml_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_ecdh_extended.py`
- Modify: `src/pkcs11_check/testcases/test_hash_slh_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_rsa_extended.py`
- Modify: 8 other test files importing `_pack_attrs`

- [ ] **Step 1: Rename _gen_keypair to gen_keypair in recipes.py**

Find `def _gen_keypair(` and rename to `def gen_keypair(`. Also update the 2 internal
callers (`gen_rsa_keypair` and `gen_ec_keypair` which call `_gen_keypair`).

- [ ] **Step 2: Rename _pack_attrs to pack_attrs in recipes.py**

Find `def _pack_attrs(` and rename to `def pack_attrs(`. Also update all internal
callers within recipes.py (grep for `_pack_attrs` within the file).

- [ ] **Step 3: Update __init__.py re-exports**

Add `gen_keypair` and `pack_attrs` to the imports from `.recipes` and to `__all__` in
`src/pkcs11_check/raw/__init__.py`.

- [ ] **Step 4: Update test file imports**

In all 6 test files importing `_gen_keypair`, change to `gen_keypair`:
- `test_eddsa.py`, `test_pqc_sign.py`, `test_kem.py`
- `test_hash_ml_dsa.py`, `test_ecdh_extended.py`, `test_hash_slh_dsa.py`

In all 9 test files importing `_pack_attrs`, change to `pack_attrs`:
- `test_seed.py`, `test_des.py`, `test_rsa_extended.py`, `test_twofish.py`
- `test_salsa20.py`, `test_blowfish.py`, `test_camellia.py`, `test_gost.py`, `test_aria.py`

In `test_rsa_extended.py`, also remove the `# noqa: PLC2701` suppression on the import line.

- [ ] **Step 5: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/raw/recipes.py src/pkcs11_check/raw/__init__.py --fix
uv run ruff format src/pkcs11_check/raw/recipes.py src/pkcs11_check/raw/__init__.py
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/recipes.py src/pkcs11_check/raw/__init__.py \
  src/pkcs11_check/testcases/
git commit -m "refactor: make _gen_keypair and _pack_attrs public APIs

Rename to gen_keypair and pack_attrs. Both were imported by multiple
test files as private helpers -- now properly public and re-exported."
```

---

### Task 4: Style cleanup (E1-E4)

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/bootstrap.py`
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`

- [ ] **Step 1: Move deferred datetime import in pack.py**

Find `import datetime` inside the `attr_auto()` function body. Remove it from there
and add `import datetime` at the module-level imports (near top of file, after
`from __future__ import annotations`).

- [ ] **Step 2: Move deferred CK_TOKEN_INFO import in bootstrap.py**

Find `from .types_std import CK_TOKEN_INFO` inside `get_slot_ids()`. Remove it from
there and add `CK_TOKEN_INFO` to the existing `from .types_std import (...)` block
at the top of bootstrap.py.

- [ ] **Step 3: Replace magic number in pack_mechanisms.py**

Find `params.saltSource = 1  # CKZ_SALT_SPECIFIED` and change to:
```python
params.saltSource = CKZ_SALT_SPECIFIED
```
Add `CKZ_SALT_SPECIFIED` to the `from .types_std import (...)` block in pack_mechanisms.py.

- [ ] **Step 4: Add docstring to pack_mechanisms.py**

Add or update the module-level docstring to include:
```python
"""Mechanism-specific parameter packers for PKCS#11 operations.

Callers should import mechanism packers from ``pkcs11_check.raw.pack``
(which re-exports all names), not directly from this module.
"""
```

- [ ] **Step 5: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/raw/ --fix
uv run ruff format src/pkcs11_check/raw/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/bootstrap.py \
  src/pkcs11_check/raw/pack_mechanisms.py
git commit -m "style: move deferred imports to module level, replace magic number

Move datetime import in pack.py and CK_TOKEN_INFO in bootstrap.py to
top of file. Replace saltSource=1 with CKZ_SALT_SPECIFIED constant.
Add docstring to pack_mechanisms.py."
```

---

### Task 5: Small DRY improvements (D1-D4)

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`
- Modify: `src/pkcs11_check/raw/pack.py`
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`
- Modify: `src/pkcs11_check/raw/extensions.py`

- [ ] **Step 1: Extract _to_ubyte_buf helper in recipes.py**

Add near the top of recipes.py (after the `_VERIFY_FAIL_RVS` line):
```python
def _to_ubyte_buf(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    """Convert bytes to a ctypes c_ubyte array."""
    return (ctypes.c_ubyte * len(data))(*data)
```

Then replace all ~23 occurrences of `(ctypes.c_ubyte * len(VAR))(*VAR)` with
`_to_ubyte_buf(VAR)` throughout recipes.py. The variable name varies
(`plaintext`, `data`, `signature`, `pin_bytes`, `state`, `seed`, etc.) but the
pattern is always `(ctypes.c_ubyte * len(x))(*x)`.

**Do NOT replace** patterns like `(ctypes.c_ubyte * out_len.value)()` which allocate
empty buffers of a given size -- those are different.

- [ ] **Step 2: Merge _fill_ssl3_random and _fill_wtls_random in pack_mechanisms.py**

Replace both `_fill_ssl3_random` (around line 262) and `_fill_wtls_random` (around
line 515) with a single function:

```python
def _fill_random_data(
    random_info: Any,
    client_random: bytes,
    server_random: bytes,
    keepalive: list[Any],
) -> None:
    """Fill pClientRandom/pServerRandom on SSL3 or WTLS random structs."""
    cr_ptr, cr_len = _pack_bytes(client_random, keepalive)
    sr_ptr, sr_len = _pack_bytes(server_random, keepalive)
    random_info.pClientRandom = cr_ptr
    random_info.ulClientRandomLen = cr_len
    random_info.pServerRandom = sr_ptr
    random_info.ulServerRandomLen = sr_len
```

Update all 7 call sites: 5 that called `_fill_ssl3_random` and 2 that called
`_fill_wtls_random` to call `_fill_random_data` instead.

- [ ] **Step 3: Parameterize lookup_packer/lookup_inspector in extensions.py**

Add a shared helper:
```python
def _lookup_helper(
    category: str, value: int | str, *, namespace: str | None = None
) -> Any | None:
    """Look up a vendor-registered helper (packer or inspector) by mechanism."""
    if namespace is not None:
        vendor = _EXTENSIONS.get(namespace)
        if vendor is None:
            return None
        helpers = getattr(vendor, category, {})
        if isinstance(value, int):
            return helpers.get(value)
        return helpers.get(value)
    matches: list[tuple[str, Any]] = []
    for ns_name, vendor in _EXTENSIONS.items():
        helpers = getattr(vendor, category, {})
        found = helpers.get(value)
        if found is not None:
            matches.append((ns_name, found))
    return _lookup_single_namespace(matches)
```

Then simplify `lookup_packer` and `lookup_inspector` to:
```python
def lookup_packer(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Look up a mechanism parameter packer function."""
    return _lookup_helper("packers", value, namespace=namespace)

def lookup_inspector(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Look up a mechanism parameter inspector function."""
    return _lookup_helper("inspectors", value, namespace=namespace)
```

- [ ] **Step 4: Add template_ptr_count helper in pack.py**

Add to pack.py (after the `TemplateArg` class, before the aliases removal point):
```python
def template_ptr_count(tmpl: TemplateArg | None) -> tuple[Any, int]:
    """Return (ptr, count) for an optional template, (None, 0) if None."""
    if tmpl is None:
        return None, 0
    return tmpl.ptr, tmpl.count
```

Then in recipes.py, replace all 7 occurrences of the pattern:
```python
tmpl.ptr if tmpl else None, tmpl.count if tmpl else 0
```
with:
```python
*template_ptr_count(tmpl)
```
(using splat to unpack the tuple into positional args).

Add `template_ptr_count` to the import from `.pack` in recipes.py.

- [ ] **Step 5: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/raw/ --fix
uv run ruff format src/pkcs11_check/raw/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/recipes.py src/pkcs11_check/raw/pack.py \
  src/pkcs11_check/raw/pack_mechanisms.py src/pkcs11_check/raw/extensions.py
git commit -m "refactor: DRY improvements across raw/ module

Extract _to_ubyte_buf helper (23 sites), merge _fill_ssl3_random/
_fill_wtls_random into _fill_random_data, parameterize lookup_packer/
lookup_inspector, add template_ptr_count helper (7 sites)."
```

---

### Task 6: Redesign _two_call_output (D5)

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`

- [ ] **Step 1: Change _two_call_output signature**

Replace the current `_two_call_output` with:
```python
def _two_call_output(
    raw: RawPKCS11,
    call_fn: str,
    *args: Any,
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern.

    ``args`` are ALL arguments before the output (buffer_ptr, buffer_len_ptr) pair,
    including session. The function appends the buffer pair automatically.
    """
    fn = getattr(raw, call_fn)
    out_len = CK_ULONG(0)
    rv = fn(*args, None, byref(out_len))
    expect_rv(rv, CKR_OK)
    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = fn(*args, out_buf, byref(out_len))
    expect_rv(rv, CKR_OK)
    return bytes(out_buf[: out_len.value])
```

- [ ] **Step 2: Update existing callers**

The existing callers (`encrypt_single`, `decrypt_single`, `sign_single`,
`digest_single`, and their `*Final` multipart variants) currently call:
```python
_two_call_output(raw, session, "C_Encrypt", in_buf, len(plaintext))
```

Change these to include `session` in the args:
```python
_two_call_output(raw, "C_Encrypt", session, in_buf, len(plaintext))
```

For each caller, `session` moves from being a separate parameter to being the
first element of `*args`. Find ALL calls to `_two_call_output` in recipes.py and
update accordingly.

- [ ] **Step 3: Refactor wrap_key to use _two_call_output**

Find the `wrap_key` function (which currently has inline two-call logic). Replace
the inline buffer sizing with:
```python
return _two_call_output(raw, "C_WrapKey", session, mech.byref(), wrapping_key, target_key)
```

Remove the manual `out_len`, first call, `out_buf`, second call pattern.

- [ ] **Step 4: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/raw/recipes.py --fix
uv run ruff format src/pkcs11_check/raw/recipes.py
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/raw/recipes.py
git commit -m "refactor: redesign _two_call_output to accept flexible args

Remove hardcoded session parameter -- callers now pass all args
including session. This enables wrap_key to use the shared helper
instead of inlining the two-call pattern."
```

---

### Task 7: Subprocess session preamble helper (D6)

**Files:**
- Create: `src/pkcs11_check/testcases/_subprocess_preamble.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py`
- Modify: `src/pkcs11_check/testcases/test_cve_regression.py`
- Modify: `src/pkcs11_check/testcases/test_remaining_gaps.py`

- [ ] **Step 1: Create _subprocess_preamble.py**

Create `src/pkcs11_check/testcases/_subprocess_preamble.py`:

```python
"""Shared subprocess session preamble for PKCS#11 test scripts.

Generates Python code strings that set up a PKCS#11 session in a subprocess.
Used by test files that need crash-safe isolation via subprocess.run().
"""

from __future__ import annotations

import textwrap


def subprocess_session_preamble(
    module_path: str,
    slot_id: int | None = None,
    pin: str | None = None,
    *,
    extra_imports: str = "",
    slot_label: str | None = None,
) -> str:
    """Return Python code that sets up a PKCS#11 session.

    After executing the returned code, these variables are available:
    - ``raw``: RawPKCS11 instance (initialized)
    - ``sh``: int session handle (opened, logged in if pin provided)
    - ``slot_id``: int slot used

    Call ``cleanup()`` to close the session and finalize the module.

    Args:
        module_path: Path to the PKCS#11 .so module.
        slot_id: Explicit slot ID. If None, uses first available slot.
        pin: User PIN for login. If None, skips login.
        extra_imports: Additional import lines to include in the script.
        slot_label: If set, filter slots by token label substring.
    """
    slot_discovery = ""
    if slot_id is not None:
        slot_discovery = f"slot_id = {slot_id}"
    elif slot_label is not None:
        slot_discovery = textwrap.dedent(f"""\
            slots = get_slot_ids(raw, label="{slot_label}")
            if not slots:
                slots = get_slot_ids(raw)
            slot_id = slots[0]""")
    else:
        slot_discovery = "slot_id = get_slot_ids(raw)[0]"

    login_block = ""
    if pin is not None:
        login_block = textwrap.dedent(f"""\
            login_user(raw, sh, CKU_USER, b"{pin}")""")

    return textwrap.dedent(f"""\
        from pkcs11_check.raw.api import RawPKCS11
        from pkcs11_check.raw.bootstrap import (
            close_session_quietly, get_slot_ids, login_user, open_session,
        )
        from pkcs11_check.raw.types_std import (
            CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_USER,
        )
        {extra_imports}

        raw = RawPKCS11.from_lib("{module_path}")
        rv = raw.C_Initialize(None)
        assert rv in (CKR_OK, 0x00000191), f"C_Initialize: 0x{{rv:08x}}"

        {slot_discovery}
        sh = open_session(raw, slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        {login_block}

        def cleanup():
            close_session_quietly(raw, sh)
            raw.C_Finalize(None)
    """)
```

- [ ] **Step 2: Update applicable test files**

For each of the ~5 applicable files, replace the inline preamble with a call to
`subprocess_session_preamble()`. Read each file first to understand its specific
preamble, then replace it preserving the test-specific logic that follows.

The general pattern in each file is:
1. Find the inline preamble (imports + from_lib + C_Initialize + open_session + login)
2. Replace with `preamble = subprocess_session_preamble(module_path, pin=pin, ...)`
3. Keep the test-specific body code that follows the preamble

Each file has subtle differences (slot_label vs first-slot, extra imports for
mechanism types, etc.) so read each one carefully before modifying.

- [ ] **Step 3: Lint, format, test**

```bash
uv run ruff check src/pkcs11_check/testcases/ --fix
uv run ruff format src/pkcs11_check/testcases/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/_subprocess_preamble.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py \
  src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py \
  src/pkcs11_check/testcases/test_cve_regression.py \
  src/pkcs11_check/testcases/test_remaining_gaps.py
git commit -m "refactor: extract subprocess session preamble helper

Shared helper generates PKCS#11 session setup code for subprocess
scripts. Replaces duplicated boilerplate in 5 test files."
```

---

### Task 8: Structural cleanup (F1-F3)

**Files:**
- Modify: `src/pkcs11_check/raw/__init__.py`
- Modify: `src/pkcs11_check/raw/der.py`
- Modify: `src/pkcs11_check/raw/faults.py`
- Modify: `src/pkcs11_check/raw/pack.py` (remove explicit_length if exported there)
- Modify: ~10 files that import constants from `pkcs11_check.raw`

- [ ] **Step 1: Clean up __init__.py constant re-exports (F1)**

In `src/pkcs11_check/raw/__init__.py`, remove the individual constant imports from
`types_std` (lines 8-62). Keep ONLY:
- Module imports: `der`, `extensions`, `metadata_std`, `pack`, `recipes`, `rv`, `types_std`
- Class/function imports: `RawPKCS11`, `close_session_quietly`, `get_slot_ids`,
  `login_user`, `open_session`
- Type class imports: `CK_ATTRIBUTE`, `CK_ATTRIBUTE_PTR`, `CK_CONSTANT`,
  `CK_MECHANISM`, `CK_OBJECT_HANDLE`
- Category classes (used for type annotations): `CKA`, `CKF`, `CKG`, `CKH`, `CKK`,
  `CKM`, `CKN`, `CKO`, `CKP`, `CKR`, `CKS`, `CKT`, `CKU`, `CKV`, `CKZ`

Remove specific constant instances like `CKA_CLASS`, `CKR_OK`, `CKM_AES_KEY_GEN` etc.
Update `__all__` to match.

- [ ] **Step 2: Update files importing constants from pkcs11_check.raw**

Find all files that import specific constants from `pkcs11_check.raw` and change them
to import from `pkcs11_check.raw.types_std` instead. The affected files include:
- `test_tls12.py`, `test_sign_recover.py`, `test_dual_function.py`,
  `test_remaining_gaps.py`, `test_operation_state.py`
- `tests/test_raw.py`, `tests/test_raw_bootstrap.py`, `tests/test_raw_api.py`
  and other meta-test files

For each file, change imports like:
```python
from pkcs11_check.raw import CKR_OK, CKA_CLASS, ...
```
To:
```python
from pkcs11_check.raw.types_std import CKR_OK, CKA_CLASS, ...
```

Keep imports of classes/functions/modules from `pkcs11_check.raw` unchanged
(e.g., `from pkcs11_check.raw import RawPKCS11` stays).

- [ ] **Step 3: DER sequence decoding deduplication (F2)**

In `src/pkcs11_check/raw/der.py`, add a shared helper:

```python
def _decode_der_sequence_integers(data: bytes, count: int) -> tuple[int, ...]:
    """Decode a DER SEQUENCE of ``count`` INTEGERs, return as tuple of ints."""
    if not data or data[0] != 0x30:
        raise ValueError("Expected SEQUENCE tag 0x30")
    seq_len, offset = _der_decode_length(data, 1)
    seq_end = offset + seq_len
    values: list[int] = []
    for _ in range(count):
        val, offset = _der_decode_integer(data, offset)
        values.append(val)
    if offset != seq_end:
        raise ValueError(f"Trailing data in SEQUENCE: {offset} != {seq_end}")
    if offset != len(data):
        raise ValueError(f"Trailing data after SEQUENCE: {len(data) - offset} bytes")
    return tuple(values)
```

Then simplify `ecdsa_sig_from_der` and `decode_rsa_public_key_der` to use it:

```python
def ecdsa_sig_from_der(der: bytes) -> tuple[int, int]:
    r, s = _decode_der_sequence_integers(der, 2)
    return r, s

def decode_rsa_public_key_der(der: bytes) -> tuple[bytes, bytes]:
    n_int, e_int = _decode_der_sequence_integers(der, 2)
    n_bytes = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    e_bytes = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")
    return n_bytes, e_bytes
```

- [ ] **Step 4: Eliminate explicit_length wrapper in faults.py (F3)**

In `src/pkcs11_check/raw/faults.py`, remove the `explicit_length` function and
the `pack_explicit_length` import alias. Update the 2 internal callers:

Change `zero_length()`:
```python
def zero_length() -> LengthArg:
    return LengthArg.explicit_value(0)
```

Change `_fault_from_storage()` to use `LengthArg.explicit_value(length)` directly
instead of `explicit_length(length)`.

Also remove the `explicit_length` re-export from pack.py if it exists there (check
pack.py line 158 area).

- [ ] **Step 5: Lint, format, test**

```bash
uv run ruff check src/ tests/ --fix
uv run ruff format src/ tests/
uv run python -m pytest tests/ -x -q
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/__init__.py src/pkcs11_check/raw/der.py \
  src/pkcs11_check/raw/faults.py src/pkcs11_check/raw/pack.py \
  src/pkcs11_check/testcases/ tests/
git commit -m "refactor: structural cleanup -- imports, DER dedup, faults

Clean up __init__.py constant re-exports (callers import from types_std).
Deduplicate DER SEQUENCE integer decoding. Remove explicit_length wrapper."
```

---

### Task 9: Final verification

- [ ] **Step 1: Run meta-tests**

```bash
uv run python -m pytest tests/ -x -q
```
Expected: all pass (minus pre-existing sdist test).

- [ ] **Step 2: Run SoftHSM2 smoke tests**

```bash
bash local-builds/test.sh softhsm2 -m smoke
```
Expected: all smoke tests pass.

- [ ] **Step 3: Run Kryoptic smoke tests (v3.0+ paths)**

```bash
bash local-builds/test.sh kryoptic -m smoke
```
Expected: smoke tests pass.

- [ ] **Step 4: Full lint and type check**

```bash
uv run ruff check src/ tests/
```
Expected: clean (or only pre-existing issues).

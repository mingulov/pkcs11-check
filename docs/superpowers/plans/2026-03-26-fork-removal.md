# Fork Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the python-pkcs11 fork submodule and all references, making pkcs11_check.raw the sole PKCS#11 access layer.

**Architecture:** The core loader and fixtures currently use the fork for module loading and session management. Replace with direct `RawPKCS11.from_lib()` calls. Remove bridge.py, update pyproject.toml, Dockerfiles, CI, and docs.

**Tech Stack:** Python 3.11+, git submodules, uv, Docker, GitHub Actions

**Prerequisites:** Test Migration Batch 2 complete (zero real fork imports in testcases/).

**Key constraint:** Do NOT run full Docker matrix test — that's deferred to the Quality Audit sub-project. Verify with SoftHSM2 local build only.

**Subprocess scripts:** ~8 test files embed `import pkcs11` / `pkcs11.lib()` inside subprocess script strings. These WILL break when the fork is removed. They must be rewritten to use `RawPKCS11.from_lib()` before the submodule is deleted (handled in Task 0).

---

## File Structure

**Files to modify:**
- `src/pkcs11_check/raw/api.py` — add `interface_version` property to RawPKCS11
- `src/pkcs11_check/core/loader.py` — rewrite to use RawPKCS11.from_lib() directly
- `src/pkcs11_check/fixtures.py` — replace fork session/login with raw bootstrap
- `src/pkcs11_check/raw/__init__.py` — may need updated exports
- `pyproject.toml` — remove python-pkcs11 dependency
- `.gitmodules` — remove python-pkcs11 entry (keep other submodules: wycheproof, CCTV, x509-limbo, ACVP)
- `.github/workflows/ci.yml` — keep `submodules: recursive` (other submodules need it)
- ~15 Dockerfiles — remove python-pkcs11 COPY/install/ENV lines
- `CLAUDE.md` — remove fork references
- `docs/python-pkcs11-fork.md` — archive/remove
- ~8 test files with subprocess scripts — rewrite to use RawPKCS11.from_lib()

**Files to delete:**
- `src/pkcs11_check/raw/bridge.py` — no longer needed
- `python-pkcs11/` — submodule directory

---

### Task 0: Add interface_version to RawPKCS11 and fix subprocess scripts

**Files:**
- Modify: `src/pkcs11_check/raw/api.py` — add `interface_version` property
- Modify: ~8 test files with subprocess scripts that use `pkcs11.lib()` / `lib._raw_funclist_ptr`

**Why first:** The `p11_interface_version` fixture (used by 26+ test files with `@requires_v30`/`@requires_v32` markers) reads the interface version from the loader. Currently this comes from the fork's `lib.interface_version`. We need a raw equivalent before rewriting the loader. Also, subprocess scripts that embed `import pkcs11` will break when the fork is removed.

- [ ] **Step 1:** Add `interface_version` property to RawPKCS11

Inspect `available_function_names()` to determine the version:
- If v3.2 functions present (C_EncapsulateKey, etc.) → "3.2"
- If v3.0 functions present (C_GetInterface, etc.) → "3.0" or "3.1"
- Else → "2.40"

```python
# In src/pkcs11_check/raw/api.py, add to RawPKCS11 class:
@property
def interface_version(self) -> str:
    """Detect negotiated PKCS#11 interface version."""
    names = self.available_function_names()
    if "C_EncapsulateKey" in names:
        return "3.2"
    if "C_GetInterface" in names:
        return "3.0"  # 3.0 and 3.1 share the same function set
    return "2.40"
```

- [ ] **Step 2:** Test the property

```bash
uv run python -c "
from pkcs11_check.raw.api import RawPKCS11
raw = RawPKCS11.from_lib('/usr/lib/softhsm/libsofthsm2.so')
print(f'Interface version: {raw.interface_version}')
"
```

- [ ] **Step 3:** Find all subprocess scripts with fork imports

```bash
grep -rn "pkcs11\.lib\|lib\._raw_funclist\|from pkcs11 import\|import pkcs11" src/pkcs11_check/testcases/ --include="*.py" | grep -v "from pkcs11_check" | grep -v "^[^:]*:[^:]*:#"
```

Review each match. For subprocess script strings (inside `f"""..."""` or `textwrap.dedent`), rewrite to use `RawPKCS11.from_lib()` instead of `pkcs11.lib()`.

Common replacement pattern in subprocess scripts:
```python
# OLD (fork):
import pkcs11
lib = pkcs11.lib("{module}")
raw = RawPKCS11(lib._raw_funclist_ptr)

# NEW (raw):
from pkcs11_check.raw.api import RawPKCS11
raw = RawPKCS11.from_lib("{module}")
```

- [ ] **Step 4:** Run affected tests

```bash
bash local-builds/test.sh softhsm2 -m smoke -v
```

- [ ] **Step 5:** Commit

```bash
git commit -m "feat: add interface_version to RawPKCS11, fix subprocess fork imports"
```

---

### Task 1: Rewrite loader.py to use RawPKCS11 directly

**Files:**
- Modify: `src/pkcs11_check/core/loader.py`

The loader currently does: `pkcs11.lib(path, interface=version)` which returns a fork lib object with `._raw_funclist_ptr` etc. Replace with `RawPKCS11.from_lib(path)` which does the same C_GetFunctionList/C_GetInterface calls natively.

- [ ] **Step 1:** Read current loader.py to understand the full interface

```bash
cat src/pkcs11_check/core/loader.py
```

- [ ] **Step 2:** Identify what the loader returns and who calls it

The loader provides a `P11Module` wrapper used by fixtures. Check:
```bash
grep -rn "P11Module\|load_module\|from.*loader import" src/pkcs11_check/ --include="*.py" | grep -v __pycache__
```

- [ ] **Step 3:** Rewrite loader to use RawPKCS11.from_lib()

Replace:
```python
import pkcs11
lib = pkcs11.lib(str(path), interface=interface)
```

With:
```python
from pkcs11_check.raw.api import RawPKCS11
raw = RawPKCS11.from_lib(str(path))
```

The `P11Module` wrapper should now hold a `RawPKCS11` instance instead of a fork lib object:
- `.raw()` returns the RawPKCS11 directly (no bridge)
- `.interface_version` reads from `raw.interface_version` (added in Task 0)
- Rewrite `get_slots()` → `get_slot_ids(raw)` from bootstrap
- Rewrite `get_token()` → `raw.C_GetTokenInfo(slot_id, byref(info))`
- Remove any `lib.get_slots()`, `token.open()` fork calls
- Check callers: `test_init.py`, `test_interface.py` may use `p11_module.lib` directly — they need migration too

Interface version negotiation: `RawPKCS11.from_lib()` already handles v2.40/v3.0/v3.1/v3.2 negotiation via `C_GetInterface`. The `interface_version` property (Task 0) provides the version string.

- [ ] **Step 4:** Run meta-tests

```bash
uv run python -m pytest tests/ -v --timeout=60
```

- [ ] **Step 5:** Run smoke test against SoftHSM2

```bash
bash local-builds/test.sh softhsm2 -m smoke -v
```

- [ ] **Step 6:** Commit

```bash
git add src/pkcs11_check/core/loader.py
git commit -m "refactor: rewrite loader.py to use RawPKCS11.from_lib() directly"
```

---

### Task 2: Rewrite fixtures.py to use raw bootstrap

**Files:**
- Modify: `src/pkcs11_check/fixtures.py`

The fixtures currently:
- `import pkcs11 as _p11` for UserType enum and exception classes
- Use `session.login(_p11.UserType.USER, pin)` from fork
- Catch fork-specific exceptions (UserAlreadyLoggedIn, etc.)
- Use `raw_from_module()` bridge to create RawPKCS11

Replace all with raw equivalents:
- `login_user(raw, sh, int(CKU_USER), pin_bytes)` from bootstrap
- Catch CKR values: `CKR_USER_ALREADY_LOGGED_IN`, `CKR_USER_NOT_LOGGED_IN`
- Create RawPKCS11 directly from the loader's P11Module (after Task 1)

**Important:** The `p11_session` fixture currently returns a fork Session object. Check if ANY test files still use `p11_session` (not `p11_raw_session`). If so, either:
- Migrate those tests to use `p11_raw_session` first, OR
- Rewrite `p11_session` to return a RawSession (same as p11_raw_session)

```bash
grep -rn "p11_session" src/pkcs11_check/testcases/ --include="*.py" | grep -v "p11_raw_session" | grep -v "__pycache__" | head -10
```

- [ ] **Step 1:** Read current fixtures.py

```bash
cat src/pkcs11_check/fixtures.py
```

- [ ] **Step 2:** Replace fork imports with raw equivalents

Remove:
```python
import pkcs11 as _p11
```

Replace login/logout with raw bootstrap calls. Replace exception catches with CKR checks.

- [ ] **Step 3:** Remove bridge.py import

The fixture should get RawPKCS11 from the loader's P11Module directly (after Task 1 made P11Module hold a RawPKCS11).

- [ ] **Step 4:** Run meta-tests

```bash
uv run python -m pytest tests/ -v --timeout=60
```

- [ ] **Step 5:** Run smoke test

```bash
bash local-builds/test.sh softhsm2 -m smoke -v
```

- [ ] **Step 6:** Commit

```bash
git add src/pkcs11_check/fixtures.py
git commit -m "refactor: rewrite fixtures.py to use raw bootstrap, remove fork dependency"
```

---

### Task 3: Remove bridge.py and clean up raw package

**Files:**
- Delete: `src/pkcs11_check/raw/bridge.py`
- Modify: `src/pkcs11_check/raw/__init__.py` — remove bridge exports

- [ ] **Step 1:** Verify bridge.py has no remaining callers

```bash
grep -rn "bridge\|raw_from_lib\|raw_from_module\|from_lib\|from_module" src/pkcs11_check/ --include="*.py" | grep -v __pycache__ | grep -v bridge.py
```

If any callers remain, update them to use `RawPKCS11.from_lib()` directly.

- [ ] **Step 2:** Remove bridge.py

```bash
git rm src/pkcs11_check/raw/bridge.py
```

- [ ] **Step 3:** Remove bridge exports from `__init__.py`

Edit `src/pkcs11_check/raw/__init__.py` to remove `raw_from_lib`, `raw_from_module`, `from_lib`, `from_module` exports.

- [ ] **Step 4:** Run meta-tests + smoke

```bash
uv run python -m pytest tests/ -v --timeout=60
bash local-builds/test.sh softhsm2 -m smoke -v
```

- [ ] **Step 5:** Commit

```bash
git add -u src/pkcs11_check/raw/
git commit -m "refactor: remove bridge.py — RawPKCS11.from_lib() replaces fork bridge"
```

---

### Task 4: Verify zero fork imports in all source code

**Files:** All of `src/pkcs11_check/`

- [ ] **Step 1:** AST-based scan for any remaining fork imports

```python
python3 -c "
import ast, os
for root, dirs, files in os.walk('src/pkcs11_check'):
    for fn in sorted(files):
        if not fn.endswith('.py'): continue
        path = os.path.join(root, fn)
        tree = ast.parse(open(path).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('pkcs11') and not node.module.startswith('pkcs11_check'):
                print(f'{path}:{node.lineno}: from {node.module} import ...')
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith('pkcs11') and not alias.name.startswith('pkcs11_check'):
                        print(f'{path}:{node.lineno}: import {alias.name}')
print('Done')
"
```

Must print only "Done" with no matches. If any remain, fix them.

- [ ] **Step 2:** Also check for string references that might break at runtime

```bash
grep -rn "pkcs11\.lib\|pkcs11\.UserType\|pkcs11\.exceptions" src/pkcs11_check/ --include="*.py" | grep -v __pycache__ | grep -v pkcs11_check
```

- [ ] **Step 3:** Run broader test (non-slow)

```bash
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)" -v
```

- [ ] **Step 4:** Commit if any fixes were needed

---

### Task 5: Remove submodule and update pyproject.toml

**Files:**
- Delete: `python-pkcs11/` submodule
- Modify: `.gitmodules`
- Modify: `pyproject.toml`

- [ ] **Step 1:** Deinit and remove submodule

```bash
git submodule deinit -f python-pkcs11
git rm -f python-pkcs11
rm -rf .git/modules/python-pkcs11
```

- [ ] **Step 2:** Verify .gitmodules

Other submodules exist (wycheproof, CCTV, x509-limbo, ACVP) so `.gitmodules` must NOT be deleted. The `git rm python-pkcs11` command above already removes the python-pkcs11 entry. Verify:
```bash
cat .gitmodules  # should still have other submodule entries, no python-pkcs11
```

- [ ] **Step 3:** Update pyproject.toml

Remove from `[project] dependencies`:
```
"python-pkcs11>=0.9.3"
```

Remove from `[tool.uv.sources]`:
```
python-pkcs11 = { path = "python-pkcs11", editable = true }
```

Update `[tool.mypy] overrides`: the current line is `module = ["pkcs11", "pkcs11.*", "psutil"]`. Remove `"pkcs11"` and `"pkcs11.*"` but keep `"psutil"`:
```toml
module = ["psutil"]
```

- [ ] **Step 4:** Regenerate lockfile

```bash
uv lock
```

- [ ] **Step 5:** Verify the package installs without the fork

```bash
uv sync
uv run pkcs11-check version
```

- [ ] **Step 6:** Commit

```bash
git add -A .gitmodules pyproject.toml uv.lock
git commit -m "feat: remove python-pkcs11 submodule and dependency"
```

---

### Task 6: Update Dockerfiles

**Files:** 14 Dockerfiles in `docker/`

Each Dockerfile has 3 lines to remove:
1. `COPY python-pkcs11/ python-pkcs11/`
2. `uv sync --frozen --reinstall-package python-pkcs11` (or similar)
3. `ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0` (if present)

- [ ] **Step 1:** Find all affected Dockerfiles

```bash
grep -rln "python-pkcs11" docker/
```

- [ ] **Step 2:** For each Dockerfile, remove the 3 fork-related lines

The `uv sync --frozen` line that reinstalls python-pkcs11 should be removed. If there's a separate `uv sync --frozen` for the main package, keep that one.

- [ ] **Step 3:** Verify Docker build works for at least one target

```bash
docker compose -f docker/docker-compose.test.yml build test-softhsm2 2>&1 | tail -20
```

- [ ] **Step 4:** Commit

```bash
git add docker/
git commit -m "refactor: remove python-pkcs11 from all Dockerfiles"
```

---

### Task 7: Update CI, CLAUDE.md, and docs

**Files:**
- Verify: `.github/workflows/ci.yml` — keep `submodules: recursive` (other submodules: wycheproof, CCTV, etc.)
- Modify: `CLAUDE.md` — remove fork references
- Remove or archive: `docs/python-pkcs11-fork.md`

- [ ] **Step 1:** Update CI checkout

```bash
grep -n "submodules" .github/workflows/ci.yml
```

Keep `submodules: recursive` — other submodules (wycheproof, CCTV, x509-limbo, ACVP) still need it. No CI changes needed for submodule checkout.

- [ ] **Step 2:** Update CLAUDE.md

Remove/update these sections:
- Line ~15: "**PKCS#11 binding:** python-pkcs11 fork (git submodule...)" → update to describe pkcs11_check.raw
- Lines ~69-85: "Raw PKCS#11 access" section — update bridge references
- Line ~143: "python-pkcs11 fork as git submodule" — remove
- Line ~280: "docs/python-pkcs11-fork.md" reference — remove

- [ ] **Step 3:** Handle docs/python-pkcs11-fork.md

This doc describes the fork's changes. Since the fork is being removed, this is historical. Either:
- Delete it (history is in git)
- Or move to `docs/archive/python-pkcs11-fork.md` with a header note

- [ ] **Step 4:** Commit

```bash
git add .github/ CLAUDE.md docs/
git commit -m "docs: update CLAUDE.md, CI, and docs for fork removal"
```

---

### Task 8: Final verification

- [ ] **Step 1:** Verify no references to python-pkcs11 remain (except git history)

```bash
# Should return nothing (or only the master plan referencing history)
grep -rn "python-pkcs11" . --include="*.py" --include="*.toml" --include="*.yml" --include="*.md" --include="Dockerfile*" | grep -v ".git/" | grep -v "__pycache__" | grep -v "plans/"
```

- [ ] **Step 2:** Verify no `from pkcs11` imports remain

```bash
grep -rn "from pkcs11 \|import pkcs11" src/ --include="*.py" | grep -v pkcs11_check | grep -v __pycache__
```

Subprocess strings in test files are acceptable (they run in isolation).

- [ ] **Step 3:** Run smoke tests

```bash
bash local-builds/test.sh softhsm2 -m smoke -v
```

- [ ] **Step 4:** Run broader test suite

```bash
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)" -v
```

- [ ] **Step 5:** Update master plan progress

In `docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md`, mark Sub-project 4 (Fork Removal) as complete.

- [ ] **Step 6:** Final commit if any cleanup needed

```bash
git commit -m "chore: complete fork removal — zero python-pkcs11 dependency"
```

# Key-Provisioning Phase 6 — External-Tool Provisioning Tier (all object classes)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Give backends that can provision **nothing** via the PKCS#11 API (kmsp11: no `C_CreateObject`, no operational keygen — confirmed `CKR_FUNCTION_NOT_SUPPORTED` — no `C_UnwrapKey`) a way to load KAT material via a **native external import command**, so their KAT/fixture tests RUN instead of skipping. **Extended to ALL object classes** (secret/private keys AND public keys, certificates, data objects) — because public/cert/data have no in-band unwrap alternative, the external tier is their ONLY run path on a no-create module (per user: a test that needs a public-key/cert/data fixture should support this config and RUN, not skip away its findings).

**Architecture:** A strictly **double-opt-in** (`--allow-external-provision` AND `--external-provision-cmd <template>`), off-by-default resolution step inserted **after** the in-band tiers: `create → unwrap → external → skip` (keys) / `create → external → skip` (public/cert/data). The suite writes the object material to a mode-`0600` temp file, substitutes `{keyfile} {label} {key_type} {key_class}` into the operator command, runs it with a timeout, then resolves the loaded object by `CKA_LABEL` via `C_FindObjects`. Honesty is non-negotiable: every external provision records `ran_via_external` + a `compliance.note`, and the run-summary banner (already wired in Phase 3) fires loudly. The suite ships **no** vendor commands.

**Tech Stack:** Python 3.12+, `subprocess` (timeout), `tempfile`, pure-ctypes `pkcs11_check.raw`.

## Global Constraints

- **NEVER `int()`-wrap `CKR_`/`CKA_`/`CKM_`/`CKK_`/`CKO_` constants.**
- **Double opt-in, off by default.** External provisioning is INERT unless BOTH `--allow-external-provision` (bool) and `--external-provision-cmd` (template) are set. Absent either → behaviour is exactly as today (skip).
- **WIRE END-TO-END (the Phase-3 lesson):** the two config fields MUST flow config → CLI typer flag → `pytest_addoption` → `p11_config` fixture → `_build_pytest_args` (feeds both isolation modes). A field that stops anywhere in that chain is unreachable. Verify with a real run, not just unit tests.
- **Honesty (non-negotiable):** an externally-provisioned object is NOT a PKCS#11-API capability. Record `ran_via_external` + `compliance.note("provisioned externally via …")`; the banner fires when `ran_via_external > 0`. Never let an external object masquerade as an in-API result.
- **Security:** runs an operator-supplied command and writes key material to disk. Temp file is mode `0600`, deleted in a `finally` (best-effort overwrite first). Timeout-bounded. PIN/secret values never logged. This is why it is double-opt-in deployment config (like `--pin`).
- **Finding-safe:** external is an ADD-ON run path. Without it, a no-create module still skips (unchanged). With it, the object loads and the test runs — any real violation still `fail`s. Failure of the external command / not-found → `pytest.skip` ("external provisioning failed"), never a target-op `fail`.
- All four gates before each commit.

**Empirical basis (2026-06-21):** kmsp11 (fakekms) returns `CKR_FUNCTION_NOT_SUPPORTED` for keygen + create + unwrap → every in-band tier ends in skip; external is the only path. softhsm2 will be used to validate the external MECHANISM (a mock command that loads the object so find-by-label succeeds + `ran_via_external` is recorded), since softhsm2 itself needs no external tier.

---

### Task 1: Config + end-to-end wiring of the two external flags

**Files:** `src/pkcs11_check/config.py`, `src/pkcs11_check/cli/test_cmd.py`, `src/pkcs11_check/plugin.py`, `src/pkcs11_check/fixtures.py`; Test: `tests/test_external_provision_wiring.py`

**Add to `P11TestConfig`:** `allow_external_provision: bool = False`, `external_provision_cmd: str | None = None`.

**Wire through ALL layers (mirror exactly how `key_inject` flows — it is the reference end-to-end example added in Phase 3):**
1. `cli/test_cmd.py`: typer options `--allow-external-provision` (bool flag) + `--external-provision-cmd` (str|None); pass both into the built config AND into `_build_pytest_args`; in `_build_pytest_args` emit `--p11-allow-external-provision` (when True) and `--p11-external-provision-cmd <val>` (when not None).
2. `plugin.py pytest_addoption`: register `--p11-allow-external-provision` (`action="store_true"`-style / store_true; dest `p11_allow_external_provision`, default False) and `--p11-external-provision-cmd` (dest `p11_external_provision_cmd`, default None).
3. `fixtures.py p11_config`: read both via `request.config.getoption(...)`, add to kwargs when set (True / not None).

- [ ] **Step 1: Write failing tests** — `_build_pytest_args(..., allow_external_provision=True, external_provision_cmd="load {keyfile}")` emits both `--p11-allow-external-provision` and `--p11-external-provision-cmd`,`load {keyfile}`; with defaults, neither appears. Plus a parser-level test that `pytest_addoption` registers both options.
- [ ] **Step 2-4: implement + gates; Step 5: commit** `feat(provisioning): config + end-to-end wiring for --allow-external-provision/--external-provision-cmd`.

---

### Task 2: External-provision core mechanism

**Files:** `src/pkcs11_check/testcases/_provisioning.py`; Test: `tests/test_external_provision.py`

**Produces:**
```python
def external_provision(
    rs: Any, cfg: Any, *,
    material: bytes, label: str, key_type: int, obj_class: str,
) -> int | None:
    """Provision an object via the operator's external command. Returns a handle, or None.

    Inert (returns None) unless cfg.allow_external_provision AND cfg.external_provision_cmd.
    Writes `material` to a 0600 temp file; substitutes {keyfile}/{label}/{key_type}/{key_class}
    into the command; runs it (timeout); resolves the loaded object by CKA_LABEL via C_FindObjects.
    Records a provisioning event + compliance.note on success. Non-zero exit / not-found → None.
    """
```
Implementation: `tempfile.NamedTemporaryFile(delete=False)` with `os.fchmod(fd, 0o600)`; write material; `finally` best-effort overwrite + unlink. Build args by `template.format(keyfile=path, label=label, key_type=str(key_type), key_class=obj_class)` then `shlex.split`; `subprocess.run(..., timeout=…, capture_output=True)`. On returncode 0, `find_objects` by `{CKA_LABEL: label.encode()}` (use the existing find recipe); return the first handle. Any failure (timeout, non-zero, not-found, exception) → return None (caller decides skip). On success: `record_provisioning_event(obj_class, "ran_via_external")` + `note(f"{label}: provisioned externally via operator command ({obj_class})", ComplianceLevel.CRITICAL)`. NEVER log the material or command stderr verbatim if it could contain key bytes (log only returncode + a generic message).

- [ ] **Step 1: Write failing tests (module-free, fake rs + monkeypatched subprocess/find):** (a) both flags set + fake command "succeeds" + find returns a handle → returns the handle, records `ran_via_external`, temp file deleted; (b) flags unset → returns None immediately (no subprocess); (c) command non-zero exit → None; (d) command ok but find returns nothing → None; (e) the temp file is mode 0600 and removed in finally. Monkeypatch `subprocess.run` + the find recipe.
- [ ] **Step 2-4: implement + gates; Step 5: commit** `feat(provisioning): external_provision core (temp-file + command + find-by-label)`.

---

### Task 3: Insert external tier into the key resolvers

**Files:** `src/pkcs11_check/testcases/_provisioning.py`; Tests: extend `tests/test_provision_secret_key.py` + `tests/test_provision_rsa_private_key.py`

In `provision_secret_key`, `provision_rsa_private_key`, `provision_ec_private_key`: BEFORE each terminal `pytest.skip("…no wrapping path…")` (i.e. when the in-band unwrap path is unavailable), attempt `external_provision(rs, cfg, material=<value or pkcs8>, label=label, key_type=key_type, obj_class=<"secret"|"private">)`. If it returns a handle → return it (the `ran_via_external` event + note were already recorded by `external_provision`). If None → fall through to the existing `pytest.skip`. The `material` is the raw secret value (secret) or the PKCS#8 DER (private — reuse the Task-2/4 encoders). Resolution becomes `create → unwrap → external → skip`. Keep `force-unwrap` semantics (it still skips create; external still applies after unwrap fails).

- [ ] **Step 1: Write failing tests** — force-unwrap + no wrap path + external configured & "succeeds" → provision returns the external handle + records `ran_via_external` (not `skipped_no_path`); external unconfigured → still `skipped_no_path` + skip.
- [ ] **Step 2-4: implement + gates; Step 5: commit** `feat(provisioning): create→unwrap→external→skip for secret/private resolvers`.

---

### Task 4: `provision_public_key` / `provision_certificate` / `provision_data` (create → external → skip)

**Files:** `src/pkcs11_check/testcases/_provisioning.py`; Test: `tests/test_provision_create_or_external.py`

Add three resolvers for the classes with NO unwrap path:
```python
def provision_public_key(rs, cfg, *, ec_params=None, ec_point=None, rsa_n=None, rsa_e=None,
                         key_type, attrs, label) -> int
def provision_certificate(rs, cfg, *, value, attrs, label) -> int
def provision_data(rs, cfg, *, value, attrs, label) -> int
```
Each resolves: if `create_verdict(class) == "create_available"` → create via the appropriate recipe (negotiated public importer / `create_object` for cert+data) and return; else attempt `external_provision(...)` (material = the object's encoded bytes: public-key SPKI DER, cert DER, data value) → handle or None; None → `record_provisioning_event(class, "skipped_no_path")` + `pytest.skip(f"{label}: no provisioning path for {class} (no C_CreateObject, external not configured/failed)")`. `force-*` modes do not apply to these (no unwrap); they always try create first unless create is absent/prohibited.

- [ ] **Step 1: Write failing module-free tests** for each: create_available → creates; create_absent + external configured & succeeds → external handle + `ran_via_external`; create_absent + no external → skip + `skipped_no_path`.
- [ ] **Step 2-4: implement + gates; Step 5: commit** `feat(provisioning): provision_public_key/certificate/data (create→external→skip)`.

---

### Task 5: Route public/cert/data FIXTURE-import sites through the new resolvers

**Files (the verify-KAT public sites + data-fixture sites that should RUN via external when configured — these are FIXTURE setups, NOT creation-tests or security-property tests; preserve existing handlers):**
- `src/pkcs11_check/testcases/test_cctv_ed25519.py` (Ed25519 public verify fixture) → `provision_public_key`.
- `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py`, `acvp/test_acvp_rsa.py`, `acvp/test_acvp_ecdh.py` public-import verify/encrypt fixtures → `provision_public_key` (these currently self-skip on a no-create module; routing makes them support external).
- `src/pkcs11_check/testcases/test_verify_operability.py` (public-key operability fixtures) → `provision_public_key`.
- (Cert) x509 fixtures already gate on a cert-storage capability probe; OPTIONAL: thread `provision_certificate` so x509 fixtures also support external — only if low-risk; else leave the existing gate.
- (Data) leave the security/visibility data tests (genuine-finding territory, per Phase 4 decision); route ONLY data-LIFECYCLE fixtures (test_object_size/test_large_objects/test_duplicate_labels already use `skip_if_data_objects_unsupported`) — OPTIONAL, only if they should support external.

Migration pattern: replace the bare/negotiated public-import call with `provision_public_key(rs, p11_config, …, label=…)`, add the `p11_config` fixture param, preserve every existing `except`/skip/xfail handler (provision's `pytest.skip` flies past `except AssertionError`). Each site that previously self-skipped now: create_available → creates+runs (unchanged); create-absent + external → runs via external; create-absent + no external → skips (unchanged).

- [ ] **Step 1:** per site, confirm it is a FIXTURE-import for a verify/derive/encrypt op (not a creation-test or security-property test); migrate; add imports + `p11_config`.
- [ ] **Step 2-3:** `uv run pytest --collect-only` clean; all four gates.
- [ ] **Step 4: commit** `refactor(provisioning): route public/cert verify-KAT fixtures through provision_* (support external config)`.

---

### Task 6: Controller validation (NOT a gate test)

**Controller-run.**
- [ ] **Mechanism validation on softhsm2** with a MOCK external command (a small script that loads the object into the same token by label — e.g. via `softhsm2-util`/`pkcs11-tool`, or a tiny python helper using the framework's own `create_object` so find-by-label succeeds). Run a routed file with `--key-inject=force-unwrap --allow-external-provision --external-provision-cmd "<mock> {keyfile} {label} {key_type} {key_class}"`; confirm `provisioning.json` shows `ran_via_external > 0`, the tests RUN (pass), and the banner fires.
- [ ] **Double-opt-in gating:** with only one of the two flags, confirm external is INERT (skips as before, `ran_via_external == 0`, no banner).
- [ ] **Security:** confirm the temp keyfile is `0600` and removed after the run (instrument the mock command to stat it).
- [ ] **kmsp11 (optional, real backend):** if a `gcloud kms keys import`-style command is feasible against fakekms, validate a real external load; else document the cookbook command in `docs/` and note fakekms limitations.
- [ ] Record results in the ledger; final whole-branch review → merge to `dev`.

## Notes
- The banner + `ran_via_external` counter were plumbed in Phase 3; this phase is the first to RECORD `ran_via_external`, so the banner becomes live.
- A `docs/` cookbook with example external commands (kmsp11 / a generic `pkcs11-tool --write-object`) is a nice-to-have; the suite ships no built-in vendor commands.
- Keygen-test hard-fails on kmsp11 (test_key_sizes FNS) are OUT OF SCOPE (keygen capability, not provisioning).

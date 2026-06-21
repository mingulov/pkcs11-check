# Key-Provisioning Phase 4 — Robust create-availability for public/cert/data setup sites

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

> **OUTCOME (revised after empirical grounding on the real freehsm-c module + user decision 2026-06-21):**
> **Infrastructure-only.** Tasks 1–2 (per-class create-availability probes + `skip_unless_can_create`
> guard) shipped as reusable create-or-skip infrastructure. **Tasks 3–5 (routing) were DROPPED** — grounding
> showed the planned routing targets are NOT provisioning mis-classifications: the data-lifecycle tests already
> use the *robust* `skip_if_data_objects_unsupported` (its `CKO_DATA_NOT_SUPPORTED_RVS` already includes
> `CKR_FUNCTION_NOT_SUPPORTED`); the bare public verify-KAT imports already self-handle via `except AssertionError`
> → skip/xfail; and the remaining freehsm-c hard-fails (`test_object_visibility` private-object leaks,
> `test_session_state_machine` session-flags, `test_access_*` keygen) are **GENUINE module findings or
> out-of-scope (session-model / keygen)**, which the framework MUST report — routing them through skips would
> SUPPRESS real findings (violates "failures ARE findings"). The clear provisioning mis-classifications (the 321
> wycheproof/acvp) were already fixed in Phases 1–2.

**Goal (original):** Eliminate framework MIS-CLASSIFICATIONS where a setup site creates a public-key / certificate / data-object FIXTURE and the module lacks `C_CreateObject` for that class. Public/cert/data have no unwrap alternative (spec §3.2), so the mechanism is a robust **create-or-skip** driven by the per-class `create_verdict`. (Empirically, no un-handled mis-classification sites remained — see OUTCOME above — so the routing was not applied.)

**Architecture:** Extend `ProvisioningProfile` with valid-material probes for `public`/`cert`/`data` (mirroring the existing `secret`/`private` probes), and a small guard `skip_unless_can_create(rs, obj_class)` that skips when `create_verdict(obj_class)` is `create_absent`/`create_prohibited`. Apply it at the data/public/cert FIXTURE-setup sites that hard-fail on freehsm-c. This is **finding-safe**: a module that genuinely creates the object (verdict `create_available`) still runs the test and any real leak/violation still `fail`s; only a genuine `C_CreateObject` capability-absence becomes a skip.

**Tech Stack:** Python 3.12+, pure-ctypes `pkcs11_check.raw`, pytest.

## Global Constraints

- **NEVER `int()`-wrap `CKR_`/`CKA_`/`CKM_`/`CKK_`/`CKO_` constants.**
- **FINDING-SAFE — never suppress a real finding.** The guard skips ONLY on a valid-material `C_CreateObject` capability-absence (`create_absent`/`create_prohibited`). It must NOT skip a test where the module creates the object and then violates a property (leak / wrong visibility / policy break) — those remain `fail`s. The guard is applied ONLY to FIXTURE-setup creates (the object is a prop for a *different* assertion), NEVER to creation-tests (where the create IS the subject) or negative tests.
- **Do NOT touch:** session-model tests (test_session_state_machine session/login/flag tests), keygen-based setup (`_gen_*` / `C_GenerateKey`), or creation-tests (test_object import-is-subject, test_rsa_key_import, attribute-enforcement). Those freehsm-c failures are genuine module behavior or out of provisioning scope.
- All four gates pass before each commit: `uv run ruff format --check .`, `uv run ruff check .`, `uv run --extra dev mypy --strict src`, `uv run pytest tests/`.

**Empirical basis (freehsm-c docker, key-inject=off):** `skip_unless_create_object_supported` probes `C_CreateObject` with an EMPTY template and only skips on FNS; freehsm-c returns a template-error for the empty probe (so the guard passes) but FNS for a real `CKO_DATA` create → the dependent assertion hard-fails. `create_verdict` (valid per-class material) detects the per-class FNS correctly.

---

### Task 1: Public/cert/data create-availability probes

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py` (`ProvisioningProfile._probe_private` is the template; add probes + dispatch)
- Test: `tests/test_provisioning_profile_classes.py`

**Behavior:** Extend `create_verdict(obj_class)` (currently dispatches `secret` → `_probe_secret`, else `_probe_private`) to dispatch `public` → `_probe_public`, `cert` → `_probe_cert`, `data` → `_probe_data`. Each new probe mirrors `_probe_secret`/`_probe_private`: create a valid throwaway object of that class via the raw recipe, map `CKR_FUNCTION_NOT_SUPPORTED → create_absent`, `rv in _CREATE_PROHIBITED_RVS → create_prohibited`, success → `destroy_quietly` + `create_available`, else re-raise.
- `_probe_public`: import a valid EC P-256 public key via `import_ec_public_key` (ec_params = `bytes.fromhex("06082a8648ce3d030107")`, a valid uncompressed P-256 `ec_point` — use a known-valid generator point DER, or reuse a constant the EC tests already define; if none handy, derive one with `cryptography` at import time of the test only — the PROBE needs a real point: use the P-256 generator `04` ‖ Gx ‖ Gy wrapped in `04 41 …` DER OCTET STRING).
- `_probe_cert`: create a minimal valid `CKO_CERTIFICATE` (CKC_X_509) via `create_object` with `CKA_VALUE` = a small valid DER cert (reuse a test cert constant from `testcases/x509/` if available; else a minimal self-signed DER built with `cryptography`).
- `_probe_data`: create a minimal valid `CKO_DATA` via `create_object` (`{CKA_CLASS: CKO_DATA, CKA_LABEL: b"probe", CKA_VALUE: b"\x00", CKA_TOKEN: False}`).

- [ ] **Step 1: Write failing tests** — for each class, monkeypatch the underlying recipe to (a) succeed → `create_available` + destroy called; (b) `CKR_FUNCTION_NOT_SUPPORTED` → `create_absent`; (c) `CKR_TEMPLATE_INCONSISTENT` → `create_prohibited`; (d) unexpected CKR → propagates. Mirror `tests/test_provisioning_profile_private.py`.
- [ ] **Step 2: Run → fail; Step 3: implement; Step 4: pass + gates; Step 5: commit** `feat(provisioning): public/cert/data create-availability probes`.

---

### Task 2: `skip_unless_can_create` robust guard

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py`
- Test: `tests/test_skip_unless_can_create.py`

**Produces:** `def skip_unless_can_create(rs: Any, obj_class: str) -> None` — `verdict = profile_for(rs).create_verdict(obj_class)`; if `verdict in ("create_absent", "create_prohibited")`: `record_provisioning_event(obj_class, "skipped_no_path")` then `pytest.skip(f"Module does not support C_CreateObject for {obj_class} objects ({verdict})")`. Otherwise return (create is available; the caller creates normally and any failure surfaces as a real finding).

- [ ] **Step 1: Write failing tests** — fake `rs` + monkeypatched probe: `create_available` → returns (no skip); `create_absent`/`create_prohibited` → `pytest.skip` + a `skipped_no_path` event recorded.
- [ ] **Step 2-4: implement + gates; Step 5: commit** `feat(provisioning): skip_unless_can_create per-class robust guard`.

---

### Task 3: Route hard-failing DATA-object fixture setups through the robust guard

**Files (replace the empty-template `skip_unless_create_object_supported(...)` guard at the DATA-fixture helpers with `skip_unless_can_create(rs, "data")`; these are FIXTURE setups for visibility/persistence/search assertions — confirm each is fixture-setup, not a creation-test):**
- `src/pkcs11_check/testcases/test_object_visibility.py` — the `_create_data_obj` helper (~line 130). Replace its `skip_unless_create_object_supported(SimpleNamespace(...))` with `skip_unless_can_create(SimpleNamespace(raw=raw, sh=sh), "data")`.
- `src/pkcs11_check/testcases/test_access_control.py` — the `create_object(CKO_DATA, ...)` fixture sites (guarded by `skip_if_data_objects_unsupported`; verify whether that probe is already robust — `skip_if_data_objects_unsupported` may already create a valid CKO_DATA. If it does and the file still hard-fails, the failing creates are elsewhere — guard those with `skip_unless_can_create(rs, "data")`).
- `src/pkcs11_check/testcases/test_session_state_machine.py` — the `_create_state_data_object` / `_raw_create_object(CKO_DATA)` FIXTURE sites used by object-lifecycle assertions (NOT the session-flag/login tests). Guard with `skip_unless_can_create`.
- `src/pkcs11_check/testcases/test_concurrent_sessions.py` — the `create_object(CKO_DATA, ...)` fixture for cross-session visibility (`test_create_in_both_sessions_no_conflict` etc.). Guard with `skip_unless_can_create(rs, "data")`.

For each: import `skip_unless_can_create` from `_provisioning`; preserve every downstream assertion. Where a helper builds a `SimpleNamespace(raw=, sh=)`, pass that.

- [ ] **Step 1:** read each helper/site; confirm it is fixture-setup (object is a prop for a different assertion), not a creation-test.
- [ ] **Step 2:** swap the guard; add the import.
- [ ] **Step 3:** `uv run pytest --collect-only` clean; all four gates.
- [ ] **Step 4: commit** `refactor(provisioning): robust create-or-skip guard at data-object fixture setups`.

---

### Task 4: Route hard-failing PUBLIC-key / CERT fixture setups

**Files (only the FIXTURE-setup sites that hard-fail on a no-create module — verify each is fixture, not creation-test):**
- `src/pkcs11_check/testcases/test_cctv_ed25519.py:133` — `import_ec_public_key` fixture for verify. Guard with `skip_unless_can_create(rs, "public")` before the import (or wrap so an FNS import → skip).
- `src/pkcs11_check/testcases/test_object.py:299` — the imported-RSA-public-then-verify site (fixture for verify; NOT the import-is-subject sites at 249/259). Guard with `skip_unless_can_create(rs, "public")`.
- `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py:312`, `acvp/test_acvp_ecdh.py:331`, `acvp/test_acvp_rsa.py` public-import sites — these feed verify/encrypt KATs. If they currently use the bare/negotiated importer and hard-fail on a no-create module, guard with `skip_unless_can_create(rs, "public")`. (Many use `import_*_public_key_negotiated`, which already skips on FNS — verify; only guard the ones that DON'T.)

Cert sites: `x509/conftest.py` already gates all x509 tests on a cert-storage capability probe — verify it skips cleanly on freehsm-c; if so, NO change needed for certs.

- [ ] **Step 1:** read each site; skip those already covered by a negotiated importer / existing capability gate.
- [ ] **Step 2:** guard the genuinely-unguarded public fixture sites.
- [ ] **Step 3:** gates.
- [ ] **Step 4: commit** `refactor(provisioning): robust create-or-skip guard at public-key fixture setups`.

---

### Task 5: Controller validation on freehsm-c (NOT a gate test)

**Controller-run.**
- [ ] Re-run the previously hard-failing files on freehsm-c (docker, key-inject=off): `test_object_visibility.py`, `test_access_control.py`, `test_concurrent_sessions.py`, `test_cctv_ed25519.py`, `test_object.py`. Confirm the DATA/public FIXTURE-setup failures are now clean **skips** (not fails).
- [ ] Confirm genuine findings are PRESERVED: any test where freehsm-c creates the object and violates a property must still `fail` (spot-check that the guard did not over-skip — e.g. a session-flag or leak test that is a real finding remains a fail).
- [ ] Confirm softhsm2 (create_available) is unperturbed: the same files still run + pass (verdict create_available → no skip).
- [ ] Record results in the ledger. Then final whole-branch review → merge to `dev`.

## Notes / out-of-scope (documented, NOT fixed here)
- freehsm-c **session-model** failures (test_session_state_machine session/login/flag tests) — genuine module behavior, not provisioning.
- **keygen-based** access setups (`_gen_access_aes_key` etc.) — keygen capability, separate from `C_CreateObject` provisioning.
- **creation-tests** (import IS the subject) — a create failure there is a real capability finding, correctly reported.
- PQC/DH **private** sites — Phase 2 deferred them; they degrade via existing handlers; revisit only if a no-create PQC/DH docker target appears.

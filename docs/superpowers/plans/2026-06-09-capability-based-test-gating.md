# Capability-Based Test Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate each test on the *minimal real capability its operations need* (mechanism or function), never on the module's self-reported interface version — so the suite stops silently skipping conformance coverage for capabilities that are actually present.

**Architecture:** Add the module's detected function set to `CapabilityManifest`; introduce a `needs_function("C_X")` marker gated on that set; migrate every `requires_v30`/`requires_v32` site to either (a) drop-the-marker + in-test `has_mechanism` guard (v2.40-function tests), (b) `needs_function` (v3.x-function tests), or (c) in-test `p11_interface_version` self-skip (genuine version-negotiation assertions); then retire the version-skip gate. Lock the regression with synthetic-manifest meta-tests.

**Tech Stack:** Python 3.13, pytest plugin (`src/pkcs11_check/plugin.py`), frozen dataclass manifest (`core/preflight.py`), pure-ctypes raw binding (`raw/api.py`), uv + ruff + mypy --strict.

**Model guidance (per user request):** Run Phase 1, Phase 4, and all meta-tests / version-assertion conversions on **Opus** (infra correctness, gate semantics). The mechanical marker-swap tasks in Phases 2–3 are **Sonnet**-suitable, but each must be verified by the static grep check + a targeted module run before commit, and reviewed.

---

## Design Corrections Folded Into This Plan

The gap analysis surfaced several inaccuracies in `docs/capability-gating-design-2026-06-09.md`. This plan supersedes the design on these points:

1. **No "crash hazard."** `plugin.py::_convert_missing_function_to_skip` (lines 683–707) already converts the uncaught `AttributeError("C_X not available in this module")` (raised at `api.py:521`) into a **skip**. The `encapsulate_key`/`decapsulate_key` recipes (`recipes.py:1741`/`1791`) call `raw.C_X` directly and never raise `NotImplementedError`, so the `test_kem` helper's `except NotImplementedError` is dead code for the absent-function path. The `except AttributeError` addition is **optional polish** (a cleaner, domain-specific skip message) — not a crash fix. `needs_function` (collection-time) is the primary gate; the global hook is the backstop.

2. **Complete site inventory.** The design enumerated only ML-DSA/ML-KEM/HKDF/KMAC. The true set is **~40 marked sites across 24 files** (full table below). EdDSA and SHA-3 tests carry **no** version markers (already mechanism-gated) — no work needed there.

3. **Wrong-tier markers.** `test_session_validation_flags.py` is `requires_v30` but calls `C_GetSessionValidationFlags` (**v3.2**). `test_remaining_gaps.py::TestAsyncLifecycle` is `requires_v30` but calls `C_Async*` (**v3.2**). Migration to `needs_function` fixes the tier.

4. **Genuine version-only tests (real gap).** A handful of tests assert the *negotiated version itself* and have no function/mechanism to gate on: `test_interface.py::TestInterfaceV30/V32` (negotiated + session-opens), and the inverse tests `test_v30_session.py::test_c_login_user_not_available_on_v240` and `test_authenticated_wrap.py::test_authenticated_wrap_requires_v32`. These convert to in-test `p11_interface_version` self-skips. **The design's Phase 2 item 9 (delete `should_skip_for_version`) is only safe after these conversions** — hence Phase 4 runs last.

5. **SPLIT files.** Several file-level `pytestmark` markers cover mixed buckets and must be split to per-class/per-test gates (see table).

---

## Authoritative Function Tiers (from `raw/api.py`)

Used to classify every site. `interface_version` is derived: `"3.2"` iff `C_EncapsulateKey` present, else `"3.0"` iff `C_GetInterface` present, else `"2.40"`.

- **v3.0 functions** (gate via `needs_function`): `C_GetInterface`, `C_GetInterfaceList`, `C_LoginUser`, `C_SessionCancel`, and all 18 message functions `C_{Encrypt,Decrypt,Sign,Verify}Message[Begin|Next]`, `C_Message{Encrypt,Decrypt,Sign,Verify}{Init,Final}`.
- **v3.2 functions** (gate via `needs_function`): `C_EncapsulateKey`, `C_DecapsulateKey`, `C_VerifySignature`, `C_VerifySignatureInit`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`, `C_GetSessionValidationFlags`, `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`.
- **Everything else is v2.40** (gate via mechanism / `has_mechanism`): `C_Sign`, `C_Verify`, `C_Encrypt`, `C_Decrypt`, `C_Digest`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey`, `C_CreateObject`, `C_FindObjects*`, `C_GetAttributeValue`, `C_Login`, etc.

---

## Full Classification Table (the deliverable the design deferred)

`A` = action. **DROP** = remove version marker, rely on existing in-test `has_mechanism` guard (add one only if noted MISSING). **NEEDS_FUNCTION(C_X)** = replace version marker with `@pytest.mark.needs_function("C_X")`. **VERSION_SELFSKIP** = remove marker, add in-test `p11_interface_version` skip. All listed in-test guards already exist unless marked **MISSING**.

### Phase 2 — ML-DSA (all DROP; guards present)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_extended_mechanisms.py:298,304,310,320` | method | `TestKMAC.*` (KMAC_128/256 availability + stub roundtrips) | DROP (`has_mechanism("KMAC_128"/"KMAC_256")`) |
| `test_extended_mechanisms.py:344,350` | method | `TestMLDSAExternalMU.*` | DROP (`has_mechanism("ML_DSA_EXTERNAL_MU"/"ML_DSA")`) |
| `test_wycheproof_mldsa_context.py:57` | file `pytestmark` | `test_mldsa_context` | DROP (`has_mechanism("ML_DSA")`; only C_Sign/C_Verify/C_CreateObject) |
| `test_remaining_gaps.py:1042,1047` | method | `TestMlDsaExternalMu.*_availability` | DROP (`has_mechanism("ML_DSA_EXTERNAL_MU"/"_GEN")`) |
| `ckr/test_ckr_keygen.py:608` | method | `test_ml_kem_parameter_set_ulong_malformed_length` | DROP (`has_mechanism("ML_KEM_KEY_PAIR_GEN")`; only C_GenerateKeyPair) |
| `ckr/test_ckr_keygen.py:702` | method | `test_ml_dsa_parameter_set_ulong_malformed_length` | DROP (`has_mechanism("ML_DSA_KEY_PAIR_GEN")`; only C_GenerateKeyPair) |

### Phase 2 — ML-KEM (split: keygen=DROP, encaps/decaps=NEEDS_FUNCTION)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_kem.py:79` | file `pytestmark` | `TestMLKEMKeyGeneration` | DROP (`has_mechanism("ML_KEM")`; keygen via C_GenerateKeyPair) |
| `test_kem.py:79` | file `pytestmark` | `TestMLKEMEncapsulateDecapsulate`, `TestMLKEMCiphertextSize`, `TestMLKEMKeyDerivation`, `TestMLKEMDecapsulation`, `TestMLKEMNegative` | NEEDS_FUNCTION(`C_EncapsulateKey`) per-class |
| `wycheproof/test_wycheproof_mlkem.py:32` | file `pytestmark` | `test_mlkem_decaps` | NEEDS_FUNCTION(`C_DecapsulateKey`) |
| `wycheproof/test_wycheproof_mlkem_encaps_modulus.py:61` | file `pytestmark` | `test_mlkem_encaps_modulus_overflow` | NEEDS_FUNCTION(`C_EncapsulateKey`) |
| `ckr/test_ckr_kem.py:41` | file `pytestmark` | `TestEncapsulateKeyErrors` | NEEDS_FUNCTION(`C_EncapsulateKey`) |
| `ckr/test_ckr_kem.py:41` | file `pytestmark` | `TestDecapsulateKeyErrors` | NEEDS_FUNCTION(`C_DecapsulateKey`) |
| `ckr/test_ckr_v32_raw.py:24` | file `pytestmark` | `TestVerifySignatureErrors` | NEEDS_FUNCTION(`C_VerifySignatureInit`) |
| `ckr/test_ckr_v32_raw.py:24` | file `pytestmark` | `TestEncapsulateKeyErrors` | NEEDS_FUNCTION(`C_EncapsulateKey`) |
| `ckr/test_ckr_v32_raw.py:24` | file `pytestmark` | `TestDecapsulateKeyErrors` | NEEDS_FUNCTION(`C_DecapsulateKey`) |
| `ckr/test_ckr_v32_raw.py:24` | file `pytestmark` | `TestAsyncErrors` | NEEDS_FUNCTION(`C_AsyncGetID`) |
| `ckr/test_ckr_v32_raw.py:24` | file `pytestmark` | `TestWrapKeyAuthenticatedErrors` | NEEDS_FUNCTION(`C_WrapKeyAuthenticated`) |
| `security/test_arithmetic_overflow.py:936` | method | `test_kem_output_template_count_overflow` | NEEDS_FUNCTION(`C_EncapsulateKey`) |

### Phase 3 — HKDF/KDF (all DROP; guards present)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_hkdf_extended.py:176` | class | `TestHKDFKeyGen` | DROP (`has_mechanism("HKDF_KEY_GEN"/"HKDF_DERIVE")`) |
| `test_hkdf_extended.py:272` | class | `TestHKDFData` | DROP (`has_mechanism("HKDF_DATA")`) |
| `test_kdf.py:152` | class | `TestHKDF` | DROP (`has_mechanism("HKDF_DERIVE")`) |
| `wycheproof/test_wycheproof_hkdf.py:40` | file `pytestmark` | `test_hkdf` | DROP (`has_mechanism("HKDF_DERIVE")`) |

### Phase 3 — Message-based (NEEDS_FUNCTION on the minimal init; DROP for digest-cancel)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_mech_message.py:22` | file `pytestmark` | encrypt tests (`test_message_encrypt_*`, `_rejects_decrypt_only_key`) | NEEDS_FUNCTION(`C_MessageEncryptInit`) per-test |
| `test_mech_message.py:22` | file `pytestmark` | `test_message_sign_aes_gmac` | NEEDS_FUNCTION(`C_MessageSignInit`) |
| `test_message_crypto.py:86` | file `pytestmark` | `TestMessageEncryptDecrypt` | NEEDS_FUNCTION(`C_MessageEncryptInit`) class-level |
| `test_message_crypto.py:86` | file `pytestmark` | `TestMessageSignVerify::test_message_sign_*` | NEEDS_FUNCTION(`C_MessageSignInit`) |
| `test_message_crypto.py:86` | file `pytestmark` | `TestMessageSignVerify::test_message_verify_*` | NEEDS_FUNCTION(`C_MessageVerifyInit`) |
| `test_message_crypto.py:86` | file `pytestmark` | `TestMessageAvailability::test_message_functions_available` | NEEDS_FUNCTION(`C_MessageEncryptInit`) (partial msg API = finding) |
| `ckr/test_ckr_v30_raw.py:24` | file `pytestmark` | `TestMessageEncryptErrors` | NEEDS_FUNCTION(`C_MessageEncryptInit`) |
| `ckr/test_ckr_v30_raw.py:24` | file `pytestmark` | `TestMessageDecryptErrors` | NEEDS_FUNCTION(`C_MessageDecryptInit`) |
| `ckr/test_ckr_v30_raw.py:24` | file `pytestmark` | `TestMessageSignErrors` | NEEDS_FUNCTION(`C_MessageSignInit`) |
| `ckr/test_ckr_v30_raw.py:24` | file `pytestmark` | `TestMessageVerifyErrors` | NEEDS_FUNCTION(`C_MessageVerifyInit`) |
| `ckr/test_ckr_v30_raw.py:24` | file `pytestmark` | `TestSessionCancelErrors` | NEEDS_FUNCTION(`C_SessionCancel`) |
| `test_remaining_gaps.py:911` | method | `test_message_encrypt_final_availability` | NEEDS_FUNCTION(`C_MessageEncryptFinal`) |
| `test_remaining_gaps.py:917` | method | `test_message_verify_final_availability` | NEEDS_FUNCTION(`C_MessageVerifyFinal`) |
| `test_operation_termination.py:301` | method | `test_digest_init_null_mechanism_cancels_active_digest` | DROP (`has_mechanism(SHA*)`; C_DigestInit is v2.40) |
| `security/test_ffi_length_boundary.py:567` | method | `test_encrypt_message_isize_input_len` | NEEDS_FUNCTION(`C_EncryptMessage`) |
| `security/test_ffi_length_boundary.py:699` | method | `test_decrypt_message_isize_input_len` | NEEDS_FUNCTION(`C_DecryptMessage`) |
| `security/test_ffi_length_boundary.py:831` | method | `test_decrypt_message_multipart_isize_input_len` | NEEDS_FUNCTION(`C_DecryptMessageBegin`) |
| `security/test_ffi_length_boundary.py:987` | method | `test_sign_message_isize_input_len` | NEEDS_FUNCTION(`C_SignMessage`) |
| `security/test_ffi_length_boundary.py:1093` | method | `test_verify_message_isize_input_len` | NEEDS_FUNCTION(`C_VerifyMessage`) |
| `security/test_ffi_length_boundary.py:1221` | method | `test_sign_message_multipart_isize_input_len` | NEEDS_FUNCTION(`C_SignMessageBegin`) |
| `security/test_ffi_length_boundary.py:1355` | method | `test_verify_message_multipart_isize_input_len` | NEEDS_FUNCTION(`C_VerifyMessageBegin`) |
| `security/test_ffi_length_boundary.py:1502` | method | `test_encrypt_message_multipart_isize_input_len` | NEEDS_FUNCTION(`C_EncryptMessageBegin`) |

### Phase 3 — Session/login (split; some tests are v2.40-only → DROP)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_v30_session.py:58` | file `pytestmark` | `TestLoginUserWithNameRecipe` (only class with no own marker) | NEEDS_FUNCTION(`C_LoginUser`) class-level |
| `test_v30_session.py:111` | class | `TestCLoginUser::*` except `test_c_login_user_not_available_on_v240` | NEEDS_FUNCTION(`C_LoginUser`) |
| `test_v30_session.py:111` | class | `TestCLoginUser::test_c_login_user_not_available_on_v240` (inverse) | VERSION_SELFSKIP (keep its `==2.40` check; no func marker) |
| `test_v30_session.py:320` | class | `TestContextSpecificLogin::test_context_specific_via_c_login_user` | NEEDS_FUNCTION(`C_LoginUser`) |
| `test_v30_session.py:320` | class | `TestContextSpecificLogin::{without_active_op, uses_c_login}` | DROP (only C_Login, v2.40) |
| `test_v30_session.py:450` | class | `TestLoginLogoutCycle::{test_c_login_user_then_logout, test_double_login_rejected}` | NEEDS_FUNCTION(`C_LoginUser`) |
| `test_v30_session.py:450` | class | `TestLoginLogoutCycle::test_normal_login_logout` | DROP (only C_Login/C_Logout, v2.40) |
| `test_v30_session.py:568` | class | `TestSessionCancel::*` | NEEDS_FUNCTION(`C_SessionCancel`) |
| `test_session_validation_flags.py:13` | file `pytestmark` | `TestSessionValidationFlags` | NEEDS_FUNCTION(`C_GetSessionValidationFlags`) — *was wrong-tier v30* |

### Phase 3 — Async (NEEDS_FUNCTION; was wrong-tier v30)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_remaining_gaps.py:944` | method | `test_async_function_availability` | NEEDS_FUNCTION(`C_AsyncComplete`) |
| `test_remaining_gaps.py:954` | method | `test_async_complete_no_active_operation` | NEEDS_FUNCTION(`C_AsyncComplete`) |
| `test_remaining_gaps.py:964` | method | `test_async_join_no_active_operation` | NEEDS_FUNCTION(`C_AsyncJoin`) |
| `test_remaining_gaps.py:974` | method | `test_async_get_id_no_active_operation` | NEEDS_FUNCTION(`C_AsyncGetID`) |

### Phase 3 — Objects/profiles/wrap (DROP or NEEDS_FUNCTION)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_mechanism_objects.py:28` | file `pytestmark` | `TestMechanismObjects` | DROP (C_FindObjects/C_GetAttributeValue, v2.40; self-skips on enum failure) |
| `test_validation_objects.py:34` | file `pytestmark` | `TestValidationObjects` | DROP (v2.40 object ops; self-skips when none present) |
| `test_profiles.py:31` | file `pytestmark` | `TestProfileObjects`, `TestProfileBehavioralConformance` | DROP (v2.40 object ops + introspection) |
| `test_aead_wrap_outputs.py:46` | file `pytestmark` | `test_gcm_wrap_*`, `test_ccm_wrap_*` | DROP (C_WrapKey v2.40; in-test `p11_interface_version!="3.2"` self-skip stays) |
| `test_authenticated_wrap.py` (no file marker) | per-test | tests using `wrap_key_authenticated` | add NEEDS_FUNCTION(`C_WrapKeyAuthenticated`) |
| `test_authenticated_wrap.py:329` | method | `test_authenticated_wrap_requires_v32` (inverse, v2.40-only) | leave as-is (no func marker; keep `==2.40` check) |

### Phase 3 — Interface (SPLIT)

| File:line | Scope | Test/class | A |
|---|---|---|---|
| `test_interface.py:53` | class | `TestInterfaceV30::test_v30_get_interface_list` | NEEDS_FUNCTION(`C_GetInterfaceList`) |
| `test_interface.py:53` | class | `TestInterfaceV30::test_v30_encrypt_decrypt_aes` | DROP + add `has_mechanism` guard (MISSING) |
| `test_interface.py:53` | class | `TestInterfaceV30::{test_v30_interface_negotiated, test_v30_session_opens}` | VERSION_SELFSKIP |
| `test_interface.py:115` | class | `TestInterfaceV32::{test_v32_interface_negotiated, test_v32_session_opens}` | VERSION_SELFSKIP |

---

## File Structure (what changes)

- **`src/pkcs11_check/core/preflight.py`** — add `functions` field to `CapabilityManifest`; populate it in `probe_capabilities`.
- **`src/pkcs11_check/markers.py`** — register `needs_function`; (Phase 4) delete `should_skip_for_version`, `_MARKER_MIN_VERSION`, `_VERSION_ORDER`, and the `requires_v30/v31/v32` `MarkerDef`s.
- **`src/pkcs11_check/plugin.py`** — add `needs_function` gate to `_runtime_skip_reason`; add `needs_function` to `_has_dynamic_markers`; (Phase 4) remove the version branch + `requires_v30/v32` from `_has_dynamic_markers`.
- **24 test files** under `src/pkcs11_check/testcases/` — marker migrations per the table.
- **`tests/test_plugin.py`, `tests/test_preflight.py`, `tests/test_markers.py`** — meta-tests for the new gate + manifest field; (Phase 4) repoint/remove version-gate tests.
- **`CLAUDE.md`, `docs/architecture.md`, the design doc** — doc updates (Phase 4).

---

# PHASE 1 — Capability-detection infrastructure (Opus)

### Task 1: Add `functions` to `CapabilityManifest`

**Files:**
- Modify: `src/pkcs11_check/core/preflight.py`
- Test: `tests/test_preflight.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_preflight.py`:

```python
def test_probe_capabilities_records_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe_capabilities populates manifest.functions from available_function_names()."""
    from pathlib import Path

    import pkcs11_check.core.preflight as preflight_mod

    class _FakeSlot:
        def get_mechanisms(self) -> list[object]:
            return []

        def get_mechanism_info(self, mech: object) -> None:
            return None

    class _FakeP11:
        interface_version = "2.40"

        def get_slots(self, token_present: bool = True) -> list[_FakeSlot]:
            return [_FakeSlot()]

        def available_function_names(self) -> set[str]:
            return {"C_Sign", "C_Verify", "C_GenerateKeyPair"}

    monkeypatch.setattr(preflight_mod, "load_module", lambda module, interface: _FakeP11())

    manifest = preflight_mod.probe_capabilities(Path("/tmp/m.so"), interface="auto", slot=0)

    assert manifest.status == "ok"
    assert manifest.functions == ["C_GenerateKeyPair", "C_Sign", "C_Verify"]  # sorted


def test_manifest_serialization_roundtrip_with_and_without_functions(tmp_path: "Path") -> None:
    """Old manifests (no functions key) deserialize to []; new ones round-trip."""
    import json
    from pathlib import Path

    from pkcs11_check.core.preflight import (
        CapabilityManifest,
        load_manifest,
        save_manifest,
    )

    # Forward: a manifest WITH functions survives asdict->json->load
    m = CapabilityManifest(
        status="ok",
        module_path="/tmp/m.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_KEM"],
        functions=["C_EncapsulateKey"],
    )
    path = tmp_path / "m.json"
    save_manifest(path, m)
    assert load_manifest(path).functions == ["C_EncapsulateKey"]

    # Backward: a manifest file lacking "functions" loads with [] default
    legacy = {
        "status": "ok",
        "module_path": "/tmp/m.so",
        "requested_interface": "auto",
        "interface_version": "2.40",
        "slot_index": 0,
        "slot_count": 1,
        "mechanisms": [],
    }
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy))
    assert load_manifest(legacy_path).functions == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_preflight.py::test_probe_capabilities_records_functions tests/test_preflight.py::test_manifest_serialization_roundtrip_with_and_without_functions -v`
Expected: FAIL — `TypeError: ... unexpected keyword argument 'functions'` and `AttributeError: ... no attribute 'functions'`.

- [ ] **Step 3: Add the field + populate it**

In `src/pkcs11_check/core/preflight.py`, add the field to the dataclass right after `mechanisms` (it has a default, so it must follow the last non-default field):

```python
    mechanisms: list[str]
    functions: list[str] = field(default_factory=list)
    error: str | None = None
    mechanism_info: dict[str, dict[str, Any]] = field(default_factory=dict)
```

In `probe_capabilities`, populate it in the success-path constructor (add the `functions=` kwarg):

```python
        return CapabilityManifest(
            status="ok",
            module_path=str(module),
            requested_interface=interface,
            interface_version=p11.interface_version,
            slot_index=slot,
            slot_count=len(slots),
            mechanisms=mechanisms,
            functions=sorted(p11.available_function_names()),
            mechanism_info=mech_info,
        )
```

Leave the error/timeout/crashed constructors unchanged — they fall through to the `[]` default.

- [ ] **Step 4: Run it to verify it passes**

Run: `uv run pytest tests/test_preflight.py -v`
Expected: PASS.

- [ ] **Step 5: Type-check + lint**

Run: `uv run mypy --strict src/pkcs11_check/core/preflight.py && uv run ruff check src/pkcs11_check/core/preflight.py tests/test_preflight.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/core/preflight.py tests/test_preflight.py
git commit -m "feat(preflight): record module function set in CapabilityManifest"
```

### Task 2: Register `needs_function` marker + gate + dynamic-marker hook

**Files:**
- Modify: `src/pkcs11_check/markers.py`, `src/pkcs11_check/plugin.py`
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_plugin.py` (reuse the existing `_FakeItem` / `CapabilityManifest` imports already in that file):

```python
def _manifest_with(functions: list[str], *, version: str = "2.40") -> CapabilityManifest:
    return CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version=version,
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_DSA"],
        functions=functions,
    )


def test_needs_function_skips_when_function_absent() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = _manifest_with(["C_Sign", "C_Verify"])  # no C_EncapsulateKey

    reason = plugin_mod._runtime_skip_reason(item, config, manifest)

    assert reason == "Function C_EncapsulateKey not present in module"


def test_needs_function_runs_when_function_present() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = _manifest_with(["C_EncapsulateKey", "C_DecapsulateKey"], version="3.2")

    assert plugin_mod._runtime_skip_reason(item, config, manifest) is None


def test_needs_function_registered_as_dynamic_marker() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    assert plugin_mod._has_dynamic_markers(item) is True
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_plugin.py -k needs_function -v`
Expected: FAIL — gate returns `None` (no `needs_function` branch yet) and `_has_dynamic_markers` is `False`.

- [ ] **Step 3: Register the marker**

In `src/pkcs11_check/markers.py`, add to `MARKER_DEFINITIONS` (next to `needs_mechanism`):

```python
    MarkerDef("needs_function", "Test needs a specific PKCS#11 C_* function to be present"),
```

- [ ] **Step 4: Add the gate + dynamic-marker registration**

In `src/pkcs11_check/plugin.py`, add `needs_function` to `_has_dynamic_markers`:

```python
def _has_dynamic_markers(item: pytest.Item) -> bool:
    return any(
        item.get_closest_marker(marker_name)
        for marker_name in (
            "requires_v30",
            "requires_v32",
            "needs_mechanism",
            "needs_function",
        )
    )
```

In `_runtime_skip_reason`, add an **unconditional** function gate (a genuinely-absent function would only AttributeError→skip at call time anyway — no value in running it). Place it after the version branch and before the `needs_mechanism` block:

```python
    function_marker = item.get_closest_marker("needs_function")
    if function_marker and function_marker.args:
        needed_fn = str(function_marker.args[0])
        if needed_fn not in manifest.functions:
            return f"Function {needed_fn} not present in module"
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/test_plugin.py -k needs_function -v && uv run pytest tests/test_markers.py -v`
Expected: PASS.

- [ ] **Step 6: Type-check + lint**

Run: `uv run mypy --strict src/pkcs11_check/plugin.py src/pkcs11_check/markers.py && uv run ruff check src/pkcs11_check/plugin.py src/pkcs11_check/markers.py tests/test_plugin.py`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/markers.py src/pkcs11_check/plugin.py tests/test_plugin.py
git commit -m "feat(plugin): add needs_function capability gate"
```

### Task 3: Regression meta-test — the confirmed bug must stay fixed

**Files:**
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Write the test**

This is the design's lock (item 6): an ML-DSA item must NOT skip on a v2.40 module that advertises the mechanism, while an ML-KEM-encaps item MUST skip when `C_EncapsulateKey` is absent.

```python
def test_mldsa_runs_but_mlkem_encaps_skips_on_v240_module() -> None:
    """A v2.40 module advertising CKM_ML_DSA but lacking C_EncapsulateKey:
    ML-DSA (mechanism-gated, no version/function marker) runs; ML-KEM encaps
    (needs_function) skips. Locks the silent-skip regression."""
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="2.40",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_DSA", "CKM_ML_DSA_KEY_PAIR_GEN"],
        functions=["C_Sign", "C_Verify", "C_GenerateKeyPair"],  # no C_EncapsulateKey
    )

    # ML-DSA test post-migration carries NO version/function marker (mechanism-gated in-test)
    mldsa_item = _FakeItem(Path("/tmp/testcases/test_mldsa.py"), {})
    assert plugin_mod._runtime_skip_reason(mldsa_item, config, manifest) is None

    # ML-KEM encaps test carries needs_function
    mlkem_item = _FakeItem(
        Path("/tmp/testcases/test_kem.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    assert (
        plugin_mod._runtime_skip_reason(mlkem_item, config, manifest)
        == "Function C_EncapsulateKey not present in module"
    )
```

- [ ] **Step 2: Run it**

Run: `uv run pytest tests/test_plugin.py::test_mldsa_runs_but_mlkem_encaps_skips_on_v240_module -v`
Expected: PASS (the gate already supports this after Task 2).

- [ ] **Step 3: Commit**

```bash
git add tests/test_plugin.py
git commit -m "test(plugin): lock capability-gating regression (ML-DSA runs, ML-KEM encaps skips on v2.40)"
```

---

# PHASE 2 — Fix the confirmed bug: ML-DSA + ML-KEM (Sonnet, with review)

> Each task: edit markers per the table, then **(a)** static-verify the marker is gone / `needs_function` added with grep, and **(b)** runtime-verify against a module. Per `feedback_docker_targeted_tests`, use `docker/test.sh <module> -- <path>` for targeted runs. Use `softhsm2-main` for ML-DSA (the confirmed-bug module) and `kryoptic` / `wolfpkcs11-master` for ML-KEM encaps/decaps.

### Task 4: ML-DSA — drop version markers (6 sites)

**Files:** `test_extended_mechanisms.py`, `wycheproof/test_wycheproof_mldsa_context.py`, `test_remaining_gaps.py`, `ckr/test_ckr_keygen.py` (all under `src/pkcs11_check/testcases/`)

- [ ] **Step 1: Edit each site** (every test already has the in-test `has_mechanism` guard — verified in gap analysis; do **not** add new guards):
  - `test_extended_mechanisms.py`: delete the `@pytest.mark.requires_v32` decorator line above each of the 6 methods at lines ~298, 304, 310, 320, 344, 350.
  - `wycheproof/test_wycheproof_mldsa_context.py:57`: change `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]`.
  - `test_remaining_gaps.py`: delete the `@pytest.mark.requires_v32` decorator above the two `TestMlDsaExternalMu` methods at lines ~1042, 1047.
  - `ckr/test_ckr_keygen.py`: delete the `@pytest.mark.requires_v32` decorator above the methods at lines ~608 and ~702.

- [ ] **Step 2: Static-verify the ML-DSA markers are gone**

Run: `grep -rn "requires_v32" src/pkcs11_check/testcases/test_extended_mechanisms.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_context.py src/pkcs11_check/testcases/ckr/test_ckr_keygen.py`
Expected: no output. (`test_remaining_gaps.py` still has the async/message `requires_v30` and is finished in Phase 3.)

- [ ] **Step 3: Confirm collection is clean**

Run: `uv run pytest --collect-only src/pkcs11_check/testcases/test_extended_mechanisms.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_context.py -q 2>&1 | tail -5`
Expected: items collected, no errors.

- [ ] **Step 4: Runtime-verify on softhsm2-main (the confirmed-bug module)**

Run: `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_context.py src/pkcs11_check/testcases/test_extended_mechanisms.py -k "ML_DSA or mldsa or KMAC"`
Expected: the ML-DSA tests now **run** (pass/xfail per real behavior) instead of skipping with "Requires v32, module has v2.40". If a real finding surfaces, that is the point — record it, do not re-gate.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/test_extended_mechanisms.py \
        src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_context.py \
        src/pkcs11_check/testcases/test_remaining_gaps.py \
        src/pkcs11_check/testcases/ckr/test_ckr_keygen.py
git commit -m "fix(testcases): gate ML-DSA tests on mechanism, not interface version"
```

### Task 5: ML-KEM `test_kem.py` — split file marker per class + helper polish

**Files:** `src/pkcs11_check/testcases/test_kem.py`

- [ ] **Step 1: Remove the file-level version marker**

Line 79: `pytestmark = [pytest.mark.pqc, pytest.mark.keymgmt, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.pqc, pytest.mark.keymgmt]`.

- [ ] **Step 2: Add per-class `needs_function` to the encaps/decaps classes**

Add `@pytest.mark.needs_function("C_EncapsulateKey")` immediately above each of these class declarations: `TestMLKEMEncapsulateDecapsulate` (line ~287), `TestMLKEMCiphertextSize` (~446), `TestMLKEMKeyDerivation` (~492), `TestMLKEMDecapsulation` (~620), `TestMLKEMNegative` (~735). Do **not** mark `TestMLKEMKeyGeneration` (~201) — it is keygen-only.

- [ ] **Step 3: Confirm `TestMLKEMKeyGeneration` has mechanism guards**

Each test in `TestMLKEMKeyGeneration` must reach `_skip_if_no_ml_kem(rs)` or `rs.has_mechanism("ML_KEM"...)` before any operation. Verify by reading the class; the first test already uses `has_mechanism`. If any method lacks the guard, add `_skip_if_no_ml_kem(rs)` as its first statement (the helper exists at line 109).

- [ ] **Step 4: Helper polish (optional defense-in-depth, NOT a crash fix)**

In `_encapsulate_ml_kem_or_xfail` (line ~178) and `_decapsulate_ml_kem_or_xfail` (line ~193), broaden the catch so a manifest-`None` run yields a domain-specific skip rather than relying solely on the global `_convert_missing_function_to_skip` backstop:

```python
    except (NotImplementedError, AttributeError):
        pytest.skip("encapsulate_key not available")
```

(and the decapsulate variant `"decapsulate_key not available"`). The `AttributeError` raised by `api.py:521` ends with "not available in this module" and is already skip-converted by the global hook; this just makes the local message explicit.

- [ ] **Step 5: Static + runtime verify**

Run: `grep -n "requires_v32\|needs_function" src/pkcs11_check/testcases/test_kem.py`
Expected: no `requires_v32`; 5 `needs_function("C_EncapsulateKey")` lines.

Run: `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_kem.py::TestMLKEMKeyGeneration`
Expected: keygen tests RUN on the v2.40-advertising module (was skipped before).

Run: `docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_kem.py`
Expected: encaps/decaps classes run; on softhsm2-main they cleanly **function-skip** (`Function C_EncapsulateKey not present in module`).

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/test_kem.py
git commit -m "fix(testcases): split ML-KEM gating — keygen on mechanism, encaps/decaps on needs_function"
```

### Task 6: ML-KEM — remaining wycheproof / ckr / security sites

**Files:** `wycheproof/test_wycheproof_mlkem.py`, `wycheproof/test_wycheproof_mlkem_encaps_modulus.py`, `ckr/test_ckr_kem.py`, `ckr/test_ckr_v32_raw.py`, `security/test_arithmetic_overflow.py` (under `src/pkcs11_check/testcases/`)

- [ ] **Step 1: Edit per the table**
  - `wycheproof/test_wycheproof_mlkem.py:32`: `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc, pytest.mark.needs_function("C_DecapsulateKey")]`.
  - `wycheproof/test_wycheproof_mlkem_encaps_modulus.py:61`: same shape → `...pytest.mark.needs_function("C_EncapsulateKey")]`.
  - `ckr/test_ckr_kem.py:41`: remove `requires_v32` from the file `pytestmark` (leave `[pytest.mark.access, pytest.mark.pqc]`), then add `@pytest.mark.needs_function("C_EncapsulateKey")` above `TestEncapsulateKeyErrors` and `@pytest.mark.needs_function("C_DecapsulateKey")` above `TestDecapsulateKeyErrors`.
  - `ckr/test_ckr_v32_raw.py:24`: remove `requires_v32` from the file `pytestmark` (leave `[pytest.mark.access, pytest.mark.subprocess]`), then add per-class markers: `TestVerifySignatureErrors`→`needs_function("C_VerifySignatureInit")`, `TestEncapsulateKeyErrors`→`needs_function("C_EncapsulateKey")`, `TestDecapsulateKeyErrors`→`needs_function("C_DecapsulateKey")`, `TestAsyncErrors`→`needs_function("C_AsyncGetID")`, `TestWrapKeyAuthenticatedErrors`→`needs_function("C_WrapKeyAuthenticated")`.
  - `security/test_arithmetic_overflow.py:936`: replace `@pytest.mark.requires_v32` above `test_kem_output_template_count_overflow` with `@pytest.mark.needs_function("C_EncapsulateKey")`.

- [ ] **Step 2: Static-verify**

Run: `grep -rn "requires_v32" src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem_encaps_modulus.py src/pkcs11_check/testcases/ckr/test_ckr_kem.py src/pkcs11_check/testcases/ckr/test_ckr_v32_raw.py src/pkcs11_check/testcases/security/test_arithmetic_overflow.py`
Expected: no output.

- [ ] **Step 3: Collection sanity**

Run: `uv run pytest --collect-only src/pkcs11_check/testcases/ckr/test_ckr_v32_raw.py src/pkcs11_check/testcases/ckr/test_ckr_kem.py -q 2>&1 | tail -5`
Expected: collected, no errors.

- [ ] **Step 4: Runtime verify**

Run: `docker/test.sh kryoptic -- src/pkcs11_check/testcases/ckr/test_ckr_v32_raw.py src/pkcs11_check/testcases/ckr/test_ckr_kem.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py`
Expected: run on kryoptic; clean function-skips on a v2.40 module.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py \
        src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem_encaps_modulus.py \
        src/pkcs11_check/testcases/ckr/test_ckr_kem.py \
        src/pkcs11_check/testcases/ckr/test_ckr_v32_raw.py \
        src/pkcs11_check/testcases/security/test_arithmetic_overflow.py
git commit -m "fix(testcases): gate ML-KEM/v3.2-raw error tests on needs_function"
```

---

# PHASE 3 — Systematic sweep of remaining sites (Sonnet, with review)

### Task 7: HKDF/KDF — drop markers (4 sites)

**Files:** `test_hkdf_extended.py`, `test_kdf.py`, `wycheproof/test_wycheproof_hkdf.py`

- [ ] **Step 1: Edit** (all guards present):
  - `test_hkdf_extended.py`: delete `@pytest.mark.requires_v30` above `TestHKDFKeyGen` (~176) and `TestHKDFData` (~272).
  - `test_kdf.py`: delete `@pytest.mark.requires_v30` above `TestHKDF` (~152).
  - `wycheproof/test_wycheproof_hkdf.py:40`: `pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v30]` → `pytestmark = [pytest.mark.wycheproof]`.
- [ ] **Step 2: Static-verify** — Run: `grep -rn "requires_v30" src/pkcs11_check/testcases/test_hkdf_extended.py src/pkcs11_check/testcases/test_kdf.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py` → no output.
- [ ] **Step 3: Runtime-verify** — Run: `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_hkdf_extended.py src/pkcs11_check/testcases/test_kdf.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py` → HKDF tests run on the v2.40 module (mechanism-gated), no version-skips.
- [ ] **Step 4: Commit** — `git commit -am "fix(testcases): gate HKDF/KDF tests on mechanism, not version"`

### Task 8: Message-based — needs_function (per the table)

**Files:** `test_mech_message.py`, `test_message_crypto.py`, `ckr/test_ckr_v30_raw.py`, `test_remaining_gaps.py` (lines 911,917), `test_operation_termination.py`, `security/test_ffi_length_boundary.py`

- [ ] **Step 1: Edit per the Phase-3 message table.** For each file-level `pytestmark` (`test_mech_message.py:22`, `test_message_crypto.py:86`, `ckr/test_ckr_v30_raw.py:24`), remove `requires_v30` from the list and add the per-test/per-class `@pytest.mark.needs_function("C_X")` decorators exactly as tabulated. For `security/test_ffi_length_boundary.py`, replace each of the 8 `@pytest.mark.requires_v30` decorators with the tabulated `needs_function`. For `test_remaining_gaps.py:911,917`, replace `requires_v30` with `needs_function("C_MessageEncryptFinal")` / `needs_function("C_MessageVerifyFinal")`. For `test_operation_termination.py:301`, **delete** the `requires_v30` decorator (DROP — `C_DigestInit` is v2.40; the `has_mechanism(SHA*)` guard stays).
- [ ] **Step 2: Static-verify** — Run: `grep -rn "requires_v30" src/pkcs11_check/testcases/test_mech_message.py src/pkcs11_check/testcases/test_message_crypto.py src/pkcs11_check/testcases/ckr/test_ckr_v30_raw.py src/pkcs11_check/testcases/test_operation_termination.py src/pkcs11_check/testcases/security/test_ffi_length_boundary.py` → no output. Then `grep -c needs_function` on each to confirm counts (8 in the ffi file).
- [ ] **Step 3: Collection sanity** — Run: `uv run pytest --collect-only src/pkcs11_check/testcases/security/test_ffi_length_boundary.py src/pkcs11_check/testcases/test_message_crypto.py -q 2>&1 | tail -5` → no errors.
- [ ] **Step 4: Runtime-verify** — Run: `docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_message_crypto.py src/pkcs11_check/testcases/ckr/test_ckr_v30_raw.py` (kryoptic supports message API) and confirm `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_message_crypto.py` cleanly function-skips.
- [ ] **Step 5: Commit** — `git commit -am "fix(testcases): gate message-based tests on needs_function"`

### Task 9: Session/login — split (some tests v2.40-only)

**Files:** `test_v30_session.py`, `test_session_validation_flags.py`

- [ ] **Step 1: `test_v30_session.py`** — Remove the file-level `requires_v30` from `pytestmark` (line 58, leave `[pytest.mark.access]`); the file-level marker only covered `TestLoginUserWithNameRecipe`, so add `@pytest.mark.needs_function("C_LoginUser")` to that class. Then per-class:
  - `TestCLoginUser` (111): remove the class `requires_v30`. Do **not** add a class-level marker — markers stack and cannot be un-applied on a single method, and `test_c_login_user_not_available_on_v240` is the v2.40-only inverse test (it asserts `C_LoginUser` is *absent*, so it must run precisely when the function is missing). Therefore add `@pytest.mark.needs_function("C_LoginUser")` to each of the **other 5** methods individually, and leave `test_c_login_user_not_available_on_v240` with no function marker (its in-test `p11_interface_version == "2.40"` self-skip is its gate).
  - `TestContextSpecificLogin` (320): remove class `requires_v30`; add `@pytest.mark.needs_function("C_LoginUser")` only to `test_context_specific_via_c_login_user`; the other two methods get no marker (they use C_Login, v2.40).
  - `TestLoginLogoutCycle` (450): remove class `requires_v30`; add `@pytest.mark.needs_function("C_LoginUser")` to `test_c_login_user_then_logout` and `test_double_login_rejected`; `test_normal_login_logout` gets no marker.
  - `TestSessionCancel` (568): remove class `requires_v30`; add `@pytest.mark.needs_function("C_SessionCancel")` to the class.
- [ ] **Step 2: `test_session_validation_flags.py:13`** — `pytestmark = [pytest.mark.requires_v30]` → `pytestmark = [pytest.mark.needs_function("C_GetSessionValidationFlags")]`. (Fixes the wrong-tier v30→v3.2 marker; the in-test `available_function_names()` self-skip stays.) Also fix the module docstring "v3.0+" → "v3.2".
- [ ] **Step 3: Static-verify** — `grep -rn "requires_v30" src/pkcs11_check/testcases/test_v30_session.py src/pkcs11_check/testcases/test_session_validation_flags.py` → no output.
- [ ] **Step 4: Runtime-verify** — `docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_v30_session.py src/pkcs11_check/testcases/test_session_validation_flags.py` and confirm the inverse test still runs where intended on softhsm2-main: `docker/test.sh softhsm2-main -- "src/pkcs11_check/testcases/test_v30_session.py::TestCLoginUser::test_c_login_user_not_available_on_v240"` (must RUN, not function-skip).
- [ ] **Step 5: Commit** — `git commit -am "fix(testcases): capability-gate v3.0 session/login tests; fix v30→v3.2 validation-flags tier"`

### Task 10: Async — needs_function (4 sites, was wrong-tier v30)

**Files:** `test_remaining_gaps.py`

- [ ] **Step 1: Edit** lines 944/954/964/974 — replace each `@pytest.mark.requires_v30` with the tabulated `needs_function`: `test_async_function_availability`→`C_AsyncComplete`, `test_async_complete_no_active_operation`→`C_AsyncComplete`, `test_async_join_no_active_operation`→`C_AsyncJoin`, `test_async_get_id_no_active_operation`→`C_AsyncGetID`.
- [ ] **Step 2: Static-verify** — `grep -n "requires_v30\|requires_v32" src/pkcs11_check/testcases/test_remaining_gaps.py` → no output (911/917 done in Task 8; 1042/1047 in Task 4).
- [ ] **Step 3: Collection sanity** — `uv run pytest --collect-only src/pkcs11_check/testcases/test_remaining_gaps.py -q 2>&1 | tail -3` → no errors.
- [ ] **Step 4: Commit** — `git commit -am "fix(testcases): gate async-lifecycle tests on needs_function (v3.2 tier)"`

### Task 11: Objects/profiles — drop markers (3 files)

**Files:** `test_mechanism_objects.py`, `test_validation_objects.py`, `test_profiles.py`

- [ ] **Step 1: Edit** (all use only v2.40 object ops and self-skip when the object class is absent):
  - `test_mechanism_objects.py:28`: `pytestmark = [pytest.mark.requires_v30, pytest.mark.object]` → `pytestmark = [pytest.mark.object]`.
  - `test_validation_objects.py:34`: same shape → `pytestmark = [pytest.mark.object]`.
  - `test_profiles.py:31`: `pytestmark = pytest.mark.requires_v30` → delete the line (or `pytestmark = pytest.mark.compliance` if a category marker is desired — confirm by reading the file's existing markers; default: remove the line).
- [ ] **Step 2: Static-verify** — `grep -rn "requires_v30" src/pkcs11_check/testcases/test_mechanism_objects.py src/pkcs11_check/testcases/test_validation_objects.py src/pkcs11_check/testcases/test_profiles.py` → no output.
- [ ] **Step 3: Runtime-verify** — `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_mechanism_objects.py src/pkcs11_check/testcases/test_validation_objects.py src/pkcs11_check/testcases/test_profiles.py` → tests run; those with no matching objects self-skip with a clear reason (not a version reason).
- [ ] **Step 4: Commit** — `git commit -am "fix(testcases): gate v3.x object/profile tests on object presence, not version"`

### Task 12: Wrap — authenticated-wrap needs_function + aead-wrap drop

**Files:** `test_aead_wrap_outputs.py`, `test_authenticated_wrap.py`

- [ ] **Step 1: `test_aead_wrap_outputs.py:46`** — `pytestmark = [pytest.mark.keymgmt, pytest.mark.wrap, pytest.mark.requires_v32]` → `pytestmark = [pytest.mark.keymgmt, pytest.mark.wrap]`. Both tests keep their in-test `p11_interface_version != "3.2"` self-skip (the generated-IV/nonce wrap param is a genuine v3.2-only feature with no function/mechanism handle — an in-test version self-skip is allowed; only the *marker* gate is being removed).
- [ ] **Step 2: `test_authenticated_wrap.py`** — Add `@pytest.mark.needs_function("C_WrapKeyAuthenticated")` to each test that calls `wrap_key_authenticated`: `TestAuthenticatedWrap::{test_aes_gcm_wrap_unwrap, test_aes_gcm_authenticated_wrap_generated_iv_and_tag, test_tampered_tag_rejected}`, `TestAuthenticatedWrapAAD::test_aes_gcm_unwrap_with_different_aad_rejected`, `TestWrapIntegrity::test_aes_gcm_wrap_bit_flip_detected`. **Do NOT** mark `test_authenticated_wrap_requires_v32` (it is the v2.40-only inverse test) or the `AES_KEY_WRAP`/`ECDH_AES_KEY_WRAP` tests (v2.40, mechanism-gated already).
- [ ] **Step 3: Static-verify** — `grep -rn "requires_v32" src/pkcs11_check/testcases/test_aead_wrap_outputs.py` → no output. `grep -c "needs_function" src/pkcs11_check/testcases/test_authenticated_wrap.py` → 5.
- [ ] **Step 4: Runtime-verify** — `docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_authenticated_wrap.py src/pkcs11_check/testcases/test_aead_wrap_outputs.py`; confirm the inverse test runs on softhsm2-main: `docker/test.sh softhsm2-main -- "src/pkcs11_check/testcases/test_authenticated_wrap.py::TestAuthenticatedWrap::test_authenticated_wrap_requires_v32"` (must RUN).
- [ ] **Step 5: Commit** — `git commit -am "fix(testcases): gate authenticated-wrap on needs_function; drop aead-wrap version marker"`

### Task 13: Interface — split (function gate + mechanism gate + version self-skip)

**Files:** `test_interface.py`

- [ ] **Step 1: `TestInterfaceV30` (class marker at line 53)** — remove the class `@pytest.mark.requires_v30`. Then:
  - `test_v30_get_interface_list`: add `@pytest.mark.needs_function("C_GetInterfaceList")`.
  - `test_v30_encrypt_decrypt_aes`: no marker; add an in-test mechanism guard as its first body statement (guard MISSING): `if not rs.has_mechanism("AES_CBC_PAD"): pytest.skip("AES-CBC-PAD not supported")` — match the exact mechanism the test uses (read the body; adjust the name if it uses `AES_CBC` or `AES_ECB`).
  - `test_v30_interface_negotiated`, `test_v30_session_opens`: add as the first body statement: `if p11_interface_version not in ("3.0", "3.1", "3.2"): pytest.skip("module did not negotiate v3.0+")` (these assert the negotiated version itself — there is no function to gate on). Ensure each takes the `p11_interface_version` fixture.
- [ ] **Step 2: `TestInterfaceV32` (class marker at line 115)** — remove the class `@pytest.mark.requires_v32`; add to each method's body: `if p11_interface_version != "3.2": pytest.skip("module did not negotiate v3.2")` (ensure the fixture is a parameter).
- [ ] **Step 3: Static-verify** — `grep -n "requires_v30\|requires_v32" src/pkcs11_check/testcases/test_interface.py` → no output.
- [ ] **Step 4: Runtime-verify** — `docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_interface.py` (V30/V32 negotiated tests self-skip cleanly on v2.40) and `docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_interface.py` (run on a v3.x module).
- [ ] **Step 5: Commit** — `git commit -am "fix(testcases): split interface tests — function gate, mechanism gate, version self-skip"`

### Task 14: Phase-3 completeness gate

- [ ] **Step 1: Confirm only intended residue remains**

Run: `grep -rln "requires_v30\|requires_v31\|requires_v32" src/pkcs11_check/testcases/`
Expected: **no output** — every test-file marker has been migrated. (If any file appears, migrate it per the table before proceeding to Phase 4.)

- [ ] **Step 2: Full meta-test suite still green**

Run: `uv run pytest tests/ -q`
Expected: PASS (the version-gate tests in `tests/test_markers.py` / `test_plugin.py` still pass — they are retired in Phase 4).

---

# PHASE 4 — Retire version-skipping (Opus)

> Safe only now: every test has been re-gated, so removing the version-skip gate cannot strand a test that still depends on it.

### Task 15: Remove the version-skip gate

**Files:** `src/pkcs11_check/plugin.py`, `src/pkcs11_check/markers.py`

- [ ] **Step 1: Update the meta-tests first (red)** — In `tests/test_plugin.py`, change `test_runtime_skip_reason_uses_manifest` so the item carries only `needs_mechanism` (drop the `requires_v32` key and the `"Requires v32..."` assertion); assert it returns `"Mechanism CKM_AES_ECB not supported by module"`. In `tests/test_markers.py`, delete `TestShouldSkipForVersion` (all `should_skip_for_version` tests) and remove the `should_skip_for_version` import; keep `TestMarkerDefinitions`. Run them to confirm they now fail against the current code only where expected, then proceed.

- [ ] **Step 2: Remove the version branch from `_runtime_skip_reason`** (plugin.py ~413–419) — delete the `for marker_name in ("requires_v30", "requires_v32"): ...` block and the now-unused `should_skip_for_version` import (plugin.py:32) and `_marker_version_label` helper (plugin.py:223) if no longer referenced.

- [ ] **Step 3: Remove `requires_v30`/`requires_v32` from `_has_dynamic_markers`** (keep `needs_mechanism`, `needs_function`):

```python
def _has_dynamic_markers(item: pytest.Item) -> bool:
    return any(
        item.get_closest_marker(marker_name)
        for marker_name in ("needs_mechanism", "needs_function")
    )
```

- [ ] **Step 4: Delete the version machinery in `markers.py`** — remove `should_skip_for_version`, `_MARKER_MIN_VERSION`, `_VERSION_ORDER`, and the three `MarkerDef("requires_v30"/"requires_v31"/"requires_v32", ...)` entries. Keep the `v30`/`v32` category `MarkerDef`s.

- [ ] **Step 5: Run** — `uv run pytest tests/ -q && uv run mypy --strict src/pkcs11_check/plugin.py src/pkcs11_check/markers.py && uv run ruff check src/pkcs11_check/`
Expected: PASS / clean. (Fix any dangling import or reference the compiler flags.)

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/plugin.py src/pkcs11_check/markers.py tests/test_plugin.py tests/test_markers.py
git commit -m "refactor: retire interface-version skip gate (capability gating supersedes it)"
```

### Task 16: Final regression guard — no version-skip markers may return

**Files:** `tests/test_markers.py` (or a new `tests/test_no_version_gating.py`)

- [ ] **Step 1: Write the guard test**

```python
def test_no_testcase_uses_interface_version_markers() -> None:
    """Capability gating is provider-general: no test may gate on interface version.
    Any future requires_v30/v31/v32 reintroduces the silent-skip bug this refactor fixed."""
    import re
    from pathlib import Path

    import pkcs11_check.testcases as testcases_pkg

    root = Path(testcases_pkg.__file__).parent
    pattern = re.compile(r"requires_v3[012]")
    offenders = [
        str(p.relative_to(root))
        for p in root.rglob("test_*.py")
        if pattern.search(p.read_text())
    ]
    assert offenders == [], f"interface-version markers must not be used: {offenders}"


def test_requires_version_markers_are_unregistered() -> None:
    """The requires_v30/v31/v32 markers are gone from the registry."""
    from pkcs11_check.markers import MARKER_DEFINITIONS

    names = {m.name for m in MARKER_DEFINITIONS}
    assert "requires_v30" not in names
    assert "requires_v32" not in names
    assert "needs_function" in names
```

- [ ] **Step 2: Run** — `uv run pytest tests/test_markers.py -k "no_testcase_uses or unregistered" -v`
Expected: PASS.

- [ ] **Step 3: Commit** — `git add tests/test_markers.py && git commit -m "test: lock out reintroduction of interface-version gating"`

### Task 17: Docs

**Files:** `CLAUDE.md`, `docs/architecture.md`, `docs/capability-gating-design-2026-06-09.md`

- [ ] **Step 1: `CLAUDE.md:41`** — change the acceptable-skip example from "`@pytest.mark.requires_v30` on v2.40 module" to "`needs_function('C_X')` when the module lacks that function; `has_mechanism()` returns False".
- [ ] **Step 2: `docs/architecture.md:85`** — replace "Tests auto-skip when interface version doesn't support them (@pytest.mark.requires_v30)" with a description of capability gating (`needs_function` for v3.x functions; in-test `has_mechanism` for mechanisms; version is reporting-only).
- [ ] **Step 3: `docs/capability-gating-design-2026-06-09.md`** — set `Status: implemented (<date>)` and add a one-line pointer to this plan. Do **not** add test-count statistics (per CLAUDE.md, stats are release-only).
- [ ] **Step 4: Commit** — `git commit -am "docs: capability gating supersedes interface-version markers"`

### Task 18: Full-matrix validation (deliberate run)

- [ ] **Step 1: Run the matrix** across the Docker modules (softhsm2-main, kryoptic, nss-pqc, wolfpkcs11-master, tpm2, bouncyhsm, opencryptoki as configured) for the touched suites: ML-DSA, ML-KEM, HKDF, message-based, session, objects, interface. Confirm the expected side effect — executed ML-DSA / ML-KEM-keygen / HKDF / KMAC tests **increase** on mechanism-advertising v2.40 modules, and v3.x function tests cleanly **function-skip** where absent (no version-skips anywhere).
- [ ] **Step 2: Triage new findings** — increased execution will likely surface real module deviations. Classify each per the project's pass/xfail/fail/skip model (`docs/classification-model-design.md`); record findings — **never** re-gate to hide them.
- [ ] **Step 3 (optional, release only):** update the Docker results table if a release snapshot is being cut.

---

## Self-Review (run against the spec)

- **Spec coverage:** Phase 1 implements design components 1 (`functions`), 2 (`needs_function` + `_has_dynamic_markers`), and 6 (regression meta-test). Phase 2 implements components 3–5 (ML-DSA, ML-KEM split, helper). Phase 3 implements component 7 (systematic sweep) and 8 (crash-safety: every function-needing test now carries `needs_function` or a verified self-skip — both confirmed). Phase 4 implements component 9 (retire version-skipping) — extended with the version-assertion conversions the design omitted.
- **Design deviations (intentional, documented above):** crash-hazard reframed as optional polish; full site inventory (40 sites/24 files) replaces the partial list; version-assertion tests converted to in-test self-skips before the gate is removed; wrong-tier markers (validation-flags, async) corrected during migration.
- **Type consistency:** `manifest.functions` (list[str]) is produced in Task 1 and consumed identically in Tasks 2/3; `needs_function("C_X")` marker arg is read as `marker.args[0]` in the gate and applied as a single positional string at every site; skip reason string `"Function {C_X} not present in module"` matches between gate and meta-tests.
- **Open decision (recorded):** version-assertion tests use in-test `p11_interface_version` self-skip + full marker retirement (faithful to the design's "version is reporting-only"). Alternative considered and rejected: keep a scoped version-skip gate for those ~4 tests (simpler but leaves a reintroduction vector; the Task 16 guard test would have to whitelist them).

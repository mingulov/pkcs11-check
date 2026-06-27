# Capability-based test gating - design

**Date:** 2026-06-09
**Status:** implemented (2026-06-09)
**Author:** brainstormed with Claude

## Problem

Tests are gated on the module's **self-reported PKCS#11 interface version**
(`@pytest.mark.requires_v30` / `requires_v32`). A module can implement a
mechanism while still reporting an older interface version, which makes the
suite **silently skip conformance coverage for capabilities that are actually
present** - a violation of the project's core rule ("skip only for
genuinely-absent capability; a skip must never hide a finding").

### Confirmed instance

`softhsm2-main` advertises `CKM_ML_DSA` + `CKM_ML_DSA_KEY_PAIR_GEN` (operational,
via the v2.40 `C_Sign`/`C_Verify`/`C_GenerateKeyPair` functions) but reports
`Interface: v2.40`. Every ML-DSA test is marked `requires_v32`, so **21 ML-DSA
tests skip** with "Requires v32, module has v2.40" despite the mechanism being
present and working.

### Root cause

- `RawPKCS11.available_function_names()` (raw/api.py) already knows exactly which
  `C_*` pointers are non-NULL; `interface_version` is merely *derived* from it
  ("3.2" iff `C_EncapsulateKey` is present).
- But `CapabilityManifest` (core/preflight.py) stores only the derived version
  string + advertised mechanisms - **not** the function set.
- `_runtime_skip_reason` (plugin.py) gates `requires_v30/v32` purely on the
  version string, with no awareness of which functions/mechanisms a test needs.

## Principle

**Gate each test on the *minimal real capability the operations it performs
actually need*** - never on the self-reported version number:

- A test that uses only **v2.40 functions** (`C_Sign`/`Verify`/`Encrypt`/
  `Decrypt`/`Digest`/`GenerateKey(Pair)`/`DeriveKey`/`Wrap`/`Unwrap`/
  `CreateObject`) with a newer **mechanism** → gate on the **mechanism**
  (`has_mechanism("X")`).
- A test that calls a **v3.x-only function** (`C_GetInterface[List]`,
  `C_EncapsulateKey`, `C_DecapsulateKey`, `C_*Message*`, `C_SignMessage`,
  `C_VerifySignature`, `C_LoginUser`, `C_SessionCancel`) → gate on the
  **function** (`needs_function("C_X")`).

The reported interface version becomes **reporting-only**, never a skip
decision. `v30`/`v32` survive as **category markers** for test selection.

### Gating is per-operation, at test/class granularity

A single mechanism can span both tiers. **ML-KEM** is the key example:

| Operation | Function used | Tier | Gate |
|---|---|---|---|
| availability check | (none) | mechanism | `has_mechanism("ML_KEM")` |
| key generation | `C_GenerateKeyPair` (v2.40) | mechanism | `has_mechanism("ML_KEM_KEY_PAIR_GEN")` |
| key import / attribute / param-set / malformed-ek import-reject | `C_CreateObject` (v2.40) | mechanism | `has_mechanism("ML_KEM")` |
| encapsulate | `C_EncapsulateKey` (v3.2) | function | `needs_function("C_EncapsulateKey")` |
| decapsulate | `C_DecapsulateKey` (v3.2) | function | `needs_function("C_DecapsulateKey")` |

So **ML-KEM keygen/import/attribute coverage must run on a v2.40 module that
advertises `CKM_ML_KEM(_KEY_PAIR_GEN)`** - only the encaps/decaps operations
need the v3.2 functions. This means **file-level `pytestmark` that buckets mixed
operations must be split to per-class/per-test gates** (see Mixed-bucket files).

## Components

### Phase 1 - function detection + the confirmed bugs

1. **`CapabilityManifest`** (core/preflight.py): add
   `functions: list[str] = field(default_factory=list)`, populated from
   `p11.available_function_names()` in `probe_capabilities`. Serialization is
   already `asdict`→json→`CapabilityManifest(**raw)`; the defaulted field is
   forward/backward compatible (old manifests deserialize to `[]`).
2. **`needs_function` marker** (markers.py) + gate in `_runtime_skip_reason`
   (plugin.py): skip iff the named function ∉ `manifest.functions`, reason
   `"Function C_X not present in module"`. **Register `needs_function` in
   `_has_dynamic_markers`** (plugin.py:211) so the preflight manifest is built
   when a function-gated test is collected - otherwise the manifest is `None`,
   the gate returns `None`, and the test runs unguarded.
3. **ML-DSA tests** (`test_extended_mechanisms.py`, `test_wycheproof_mldsa_context.py`,
   ML-DSA parts of `test_remaining_gaps.py`, `test_ckr_keygen.py`): **drop
   `requires_v32`**; rely on the existing in-test `has_mechanism("ML_DSA")`
   guard (proven, alias-aware). Do **not** introduce `needs_mechanism` (see
   Decision: avoid needs_mechanism).
4. **ML-KEM tests** - split by operation:
   - `test_kem.py::TestMLKEMKeyGeneration` → drop the marker for this class;
     in-test `has_mechanism("ML_KEM")` guard suffices.
   - `test_kem.py::TestMLKEMEncapsulateDecapsulate` + the direct-`C_EncapsulateKey`/
     `C_DecapsulateKey` tests → `needs_function("C_EncapsulateKey")` /
     `needs_function("C_DecapsulateKey")`.
   - `test_wycheproof_mlkem.py` (decaps) → `needs_function("C_DecapsulateKey")`.
   - `test_wycheproof_mlkem_encaps_modulus.py` → `needs_function("C_EncapsulateKey")`.
   - `ckr/test_ckr_kem.py`, `ckr/test_ckr_v32_raw.py`, `security/test_arithmetic_overflow.py`
     → `needs_function(...)` for the encaps/decaps functions they exercise.
   - `ckr/test_ckr_keygen.py` ML-KEM keygen test → drop marker (uses
     `C_GenerateKeyPair`).
5. **Fix the crash hazard in `test_kem.py`**: `_encapsulate_ml_kem_or_xfail` /
   `_decapsulate_ml_kem_or_xfail` currently `except NotImplementedError`, but the
   raw API raises **`AttributeError`** (`api.py:521`) when a function pointer is
   absent. Change to `except (NotImplementedError, AttributeError)` →
   `pytest.skip(...)` as defense-in-depth (the `needs_function` gate is the
   primary protection; this covers the manifest-`None` path).
6. **Meta-test** (tests/) on the gate with synthetic manifests:
   - `{interface_version:"2.40", mechanisms:["CKM_ML_DSA"], functions:[…no C_EncapsulateKey…]}`
     ⇒ an ML-DSA item is **not** skipped; an ML-KEM-encaps item **is** skipped
     with `"Function C_EncapsulateKey not present"`.
   - locks the regression so it cannot silently return.

### Phase 2 - systematic sweep + retire version-skipping

7. Apply per-test/class capability gating to **all remaining** `requires_v30`/
   `requires_v32` sites (HKDF derive/keygen/data, KMAC, EdDSA, SHA-3,
   message-based, `C_LoginUser`/`C_SessionCancel`, interface). Classify each per
   the **Principle** above (the implementation plan enumerates the full
   per-test/class table): mechanism-only → drop marker (rely on in-test
   `has_mechanism`, adding one if missing); function-needing → `needs_function`.
8. **Crash-safety audit:** confirm every function-needing test either carries a
   `needs_function` gate **or** has a verified graceful self-skip
   (`hasattr` / `available_function_names()` / `except AttributeError`).
   `test_message_crypto.py`, `test_mech_message.py`, `test_v30_session.py`,
   `test_verify_signature.py`, `security/test_ffi_length_boundary.py`,
   `test_authenticated_wrap.py` already self-skip; still add `needs_function`
   for collection-time gating + clean reporting.
9. Remove the `requires_v30`/`requires_v32` branch from `_runtime_skip_reason`;
   delete `should_skip_for_version` (markers.py - sole caller); update
   `_has_dynamic_markers` (drop `requires_v30`/`requires_v32`, ensure
   `needs_function` present). Keep `v30`/`v32` as category markers.

## Mixed-bucket files (must split file-level pytestmark)

- `test_kem.py` - `TestMLKEMKeyGeneration` (mechanism) vs
  `TestMLKEMEncapsulateDecapsulate` (function).
- `test_extended_mechanisms.py` - KMAC / ML-DSA-external-mu availability tests
  are mechanism-only (drop marker).
- `test_hkdf_extended.py` - `TestHKDFKeyGen` / `TestHKDFData` are mechanism-only.
- `wycheproof/test_wycheproof_hkdf.py` - file-level `requires_v30`, uses only
  `C_DeriveKey`; mechanism-only.
- `ckr/test_ckr_keygen.py` - ML-KEM keygen test is mechanism-only.

## Decisions / non-goals

- **Avoid `needs_mechanism`.** `manifest.mechanisms` is a single-form,
  alias-less set; the `needs_mechanism` gate does exact-`in` matching and is
  used in exactly one place (unproven). The in-test `RawSession.has_mechanism()`
  uses a both-forms + alias set and already guards every affected test. So
  mechanism-only tests are fixed by **removing the version marker**, not by
  adopting `needs_mechanism`. (Hardening `manifest.mechanisms` to carry both
  forms + aliases is a possible independent follow-up, out of scope here.)
- **Named-interface under-reporting (known limitation).** The loader probes
  `C_GetInterface(NULL, version)` then falls back to `C_GetFunctionList`; it does
  not probe *named* interfaces. A module exposing a v3.x function only via a
  named interface would have it missing from `available_function_names()`, so
  `needs_function` would *skip* (false-negative - the safe direction, lost
  coverage, not a crash). Fine for kryoptic/nss/wolfpkcs11 (default interface).
  Documented; optional follow-up to probe named interfaces.
- **Out of scope:** changing `needs_mechanism` semantics; auditing non-version
  skips; mechanism-flag-based gating; the optional new ML-KEM malformed-ek
  *import-only* rejection test (a coverage bonus, mechanism-gated, that would
  extend ModulusOverflow coverage to keygen/import-capable v2.40 modules).

## Verification confirmed during design (no mitigation needed)

- Preflight (subprocess) and live fixtures both call the same
  `load_module(interface)` → detected caps match runtime.
- Adding `functions` to the frozen dataclass is serialization-safe (kwargs-only
  construction, `asdict`/json round-trip, defensive `getattr` consumers).
- A non-NULL-but-stub function (returns `CKR_FUNCTION_NOT_SUPPORTED`) is already
  classified `xfail` in the ML-KEM tests - `needs_function` *surfaces* it rather
  than hiding it; no crash.
- `doctor_probe` uses the same loader; no separate gating bug.

## Testing

- Meta-test on `_runtime_skip_reason` with synthetic manifests (Phase 1, item 6),
  extended in Phase 2 to assert no version-based skips remain.
- Matrix validation: ML-DSA suite on `softhsm2-main` (expect passes/xfails, **no
  version-skips**); ML-KEM keygen runs on a mechanism-advertising v2.40 module;
  encaps/decaps still run on kryoptic / wolfpkcs11-master and cleanly
  function-skip where absent (softhsm2-main).
- Expected side effect (the point): executed ML-DSA/ML-KEM-keygen/HKDF/KMAC
  tests **increase** on several providers, likely surfacing real findings. Docker
  result tables will shift accordingly (statistics updated only on a deliberate
  validation run, per CLAUDE.md).

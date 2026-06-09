# Operator-supplied vendor-mechanism mapping — design

**Date:** 2026-06-09
**Status:** approved (brainstorm), pending implementation plan
**Author:** brainstormed with Claude

## Problem

Modules expose vendor-defined mechanisms (CKM ID ≥ `CKM_VENDOR_DEFINED` = `0x80000000`)
that pkcs11-check cannot name or test. Concretely, opencryptoki exposes IBM Dilithium
/ Kyber as `0x80010035`, `0x80010037`, … alongside the standard `CKM_ML_DSA`/`CKM_ML_KEM`.
Today these IDs:

- render as raw hex (`ckm_name(0x80010035) → "0x80010035"`),
- are **silently dropped** by `MechanismCatalog.from_manifest` (their hex name isn't in
  `MECHANISM_NAMES`, so `name_to_id.get(...)` is `None`),
- are invisible to `has_mechanism()` and never participate in any conformance test.

Many vendors define such mechanisms in different ways. A vendor mechanism often
implements the *same API* as a standard mechanism (e.g. behaves like ML-DSA sign/verify)
but is not bit-identical to the finalized standard.

## Core principle (non-negotiable)

**pkcs11-check is a general checker and MUST NOT carry built-in knowledge of any specific
PKCS#11 provider.** No vendor data ships in the source tree. The tool gains exactly one
*general* capability: consume an **operator-supplied** map that (1) names a vendor mechanism
and (2), only when the operator explicitly asserts it, tests that mechanism under a standard
mechanism's rules. The IBM example lives solely in `docs/` as a sample config.

**Opt-in and inert by default:** with no map supplied, behavior is byte-identical to today
(vendor mechanisms stay hex and untested).

## Decisions (from brainstorming)

- **Test scope:** full conformance routing, but **explicitly configured** per token/run by
  the operator — never inferred, never provider-coupled.
- **Declaration medium:** a **TOML data file** the operator points pkcs11-check at.
- **Identity model:** **independent identity + `resembles` note.** A vendor mechanism has its
  own identity (name/vendor/spec); reuse of a standard mechanism's *test rules* is a separate,
  explicit operator assertion (`test_as`), because IBM round-2/3 Dilithium/Kyber are NOT
  bit-identical to FIPS ML-DSA/ML-KEM and reusing the standard config blindly would create
  false failures.
- **Keygen mapping:** option **(a)** — the operator names the vendor keypair-gen mechanism
  inline via `keygen_id` on the sign/verify entry (self-contained). Alternative (b), declaring
  the keygen mech as its own entry and cross-referencing, is recorded as a future option.

## How it is supplied

Resolution order (first present wins), all optional:
1. CLI flag `--p11-vendor-map <path.toml>`
2. env `P11TEST_VENDOR_MAP=<path.toml>`
3. a `vendor_map = "<path.toml>"` key in the existing pydantic-settings TOML config

The path is resolved relative to the config file / CWD. Absent → feature off.

## TOML schema

One `[mechanism.<hexid>]` table per vendor mechanism. Keys:

| key | required | meaning |
|---|---|---|
| `name` | yes | display name, e.g. `"CKM_IBM_DILITHIUM"` — replaces hex in coverage / `has_mechanism` |
| `vendor` | yes | free-text vendor, e.g. `"IBM"` |
| `spec` | no | free-text spec/source reference (documentation only) |
| `resembles` | no | standard CKM name this mechanism is *like* (documentation only) |
| `test_as` | no | standard CKM name whose **test rules** to apply (the operator's API-equivalence assertion); absent ⇒ recognise/report only |
| `keygen_id` | no | vendor keypair/keygen mechanism ID to use when `test_as`'s rules need a freshly generated key |
| `key_param_sets` | no | narrow override of the param sets to exercise |
| `notes` | no | free-text caveats |

Example (sample only; ships under `docs/`, not in source):

```toml
[mechanism.0x80010035]
name      = "CKM_IBM_DILITHIUM"
vendor    = "IBM"
spec      = "IBM EP11 Dilithium round-2/3"
resembles = "CKM_ML_DSA"
test_as   = "CKM_ML_DSA"
keygen_id = 0x80010025
notes     = "round-2/3 Dilithium; not bit-identical to FIPS 204"

[mechanism.0x80010037]
name      = "CKM_IBM_KYBER"
vendor    = "IBM"
resembles = "CKM_ML_KEM"
# no test_as → named in coverage but not conformance-tested
```

## Architecture (units + boundaries)

A new self-contained config unit plus four small, surgical integration points into the
existing mechanism pipeline (all of which already exist and are documented in
`docs/architecture.md`).

### New unit: `core/vendor_map.py`
- `VendorMechSpec` (frozen dataclass): `mech_id, name, vendor, spec, resembles, test_as,
  keygen_id, key_param_sets, notes`.
- `load_vendor_map(path) -> dict[int, VendorMechSpec]`: parse + validate TOML. Validation
  errors (bad hex id, missing `name`/`vendor`, `test_as` naming an unknown standard CKM)
  are raised as a clear config error → `pytest.exit(returncode=2)`, never a silent mis-test.
- One responsibility: turn a TOML file into a validated id→spec map. No PKCS#11 knowledge
  beyond the standard CKM name table.

### Integration point 1 — manifest carries the map
`CapabilityManifest` gains `vendor_map: dict[str, dict] = field(default_factory=dict)`
(serialized form), populated in `_ensure_manifest` from the resolved config path.
Serialization-safe exactly like the `functions` field added in the capability-gating work.
The subprocess-isolated runners therefore see the same map.

### Integration point 2 — naming overlay
A small overlay so coverage/reporting prefer the operator's `name` for a vendor id, **without
mutating `types_std`**: a `vendor_names: dict[int,str]` derived from the manifest map, consulted
by the coverage/reporting layer (`pytest_sessionfinish`) and by `ckm_name`-display helpers via
an optional overlay argument. `metadata_std`/`types_std` stay immutable and provider-agnostic.

### Integration point 3 — `has_mechanism`
`RawSession.mechanisms` includes declared vendor `name`s (both `CKM_`/short forms) when a map
is present, so existing in-test `has_mechanism("CKM_IBM_DILITHIUM")` guards work unchanged.

### Integration point 4 — catalog + selection
`MechanismCatalog.from_manifest` stops dropping vendor IDs **when a map entry covers them**:
- For every advertised mechanism whose manifest name is a hex id matching a map entry, build a
  `MechEntry(mech_id=<vendor id>, mech_name=<declared name>, flags=<from mechanism_info>, …)`.
- If the entry has `test_as`, attach `config = copy of MECHANISM_REGISTRY[<standard id>]` with
  `keygen_mech` overridden to `keygen_id` (and `key_sizes`/param-sets overridden if declared).
- If no `test_as`, `config = None` (named-only; never selected for a scenario).

The untouched `select_for_scenario` engine then routes `test_as` entries into the correct
sign/verify/encrypt/wrap/keygen scenario, and the mechanism-driven tests call C_*Init with
`entry.mech_id` (the vendor id) using the borrowed config's recipes. A wrong `test_as`
assertion surfaces as an ordinary test failure — the suite is checking the operator's
declared expectation, which is exactly the point.

## Reporting

Coverage's `mechanism_coverage` distinguishes three buckets for vendor ids: **named+tested**
(`test_as` present), **named-only** (recognised, no `test_as`), and **unmapped** (still hex).
Each tested vendor mechanism is annotated `tested as <standard> per operator vendor-map` so a
reader never mistakes an operator assertion for a pkcs11-check claim.

## Safety / generality guarantees

- Absent map ⇒ zero behavior change.
- No provider names in the source tree; a meta-test asserts the codebase ships no
  vendor-mechanism *data* (only the loader + a `docs/` sample), keeping the suite general.
- Fail-fast validation: malformed id, missing required keys, `test_as`/`resembles` naming an
  unknown standard CKM, or a `test_as` mechanism not actually advertised by the token → a
  clear startup error, never a silent skip or mis-classification.
- Vendor mechanisms are tested **against their own ids**; the standard mechanism is only the
  source of *rules*, never substituted in the actual C_* calls.

## Out of scope

- Shipping any concrete vendor map in the source tree (only a `docs/` sample).
- Auto-detecting vendor mechanisms (no provider sniffing — explicit operator assertion only).
- Full independent per-entry `MechConfig` in TOML (reuse-by-reference + narrow overrides only).
- Keygen-as-own-entry normalization (option b) — recorded as a future refinement.

## Testing

- Unit: `load_vendor_map` parse/validation (good + each error class).
- Unit: `MechanismCatalog.from_manifest` builds a tested `MechEntry` for a `test_as` entry
  (config borrowed, `keygen_mech` overridden) and a named-only entry for one without.
- Unit: `has_mechanism` / coverage naming overlay see the declared name.
- Meta-test: no vendor-mechanism data files exist in `src/` (generality lock).
- Matrix (deliberate, opt-in): run with a sample IBM map against opencryptoki and confirm the
  IBM Dilithium/Kyber ids are named, and (where `test_as` is asserted) flow into the ML-DSA/
  ML-KEM conformance scenarios — surfacing real per-vendor deviations as findings.

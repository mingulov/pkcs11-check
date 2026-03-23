# PKCS#11 Raw Architecture Design

**Date:** 2026-03-23
**Status:** Proposed
**Scope:** `pkcs11_check.raw` as the exact-call PKCS#11 substrate for pkcs11-check

## Summary

`pkcs11_check.raw` should become the authoritative exact-control layer for pkcs11-check.

The design goal is not just "more raw helpers". The goal is a trust boundary where a test author can
state the exact pointers, lengths, structs, constants, and malformed inputs to pass into PKCS#11 and
know that the library will not silently normalize, default, infer, or suppress anything.

This design uses a two-stage architecture:

1. build an authoritative, generated, PKCS#11 v3.2 standard raw layer;
2. later add optional convenience layers on top of it without weakening exactness.

This means "approach 2 first, approach 3 later" rather than choosing between them.

## Current State

pkcs11-check already depends on raw PKCS#11 behavior heavily:

- CKR coverage uses `RawPKCS11` widely for negative and exact-control tests
- TLS negative attribute tests drop to raw calls because the high-level wrapper blocks them
- several older test files still carry manual `ctypes` PKCS#11 code outside the raw package

The current extracted raw package is a useful start, but it is still incomplete as a migration target:

- current public raw methods: `97`
- PKCS#11 v3.2 header functions: `104`
- current public raw structs: `3`
- PKCS#11 v3.2 header structs: `99`
- current public raw CKR constants: `81`
- PKCS#11 v3.2 header CKR values: `105`

The current package also lacks first-class support for:

- generated standard constants (`CKA_*`, `CKM_*`, `CKK_*`, `CKO_*`, `CKF_*`)
- generated parameter structs
- explicit malformed pointer/length/count modeling
- exact call inspection
- vendor extension registration

## Problem

The python-pkcs11 fork is still useful for many readable happy-path tests, but it is not a trustworthy
exact-call substrate because it contains policy:

- default mechanism selection
- default key capabilities
- default template injection
- high-level mechanism parameter packing behavior
- attribute-driven method exposure and filtering

For pkcs11-check, especially CKR, compliance, crash, negative, and spec-precision tests, those
behaviors are counterproductive. The test suite must be able to express both valid and intentionally
malformed calls without fighting the API.

## Goals

- make `pkcs11_check.raw` the exact-call trust boundary for pkcs11-check
- support the full standard PKCS#11 v3.2 raw surface from a pinned header snapshot
- support exact modeling of both valid and intentionally malformed calls
- keep manual `ctypes` escape hatches always possible
- support later vendor-specific mechanisms, parameters, and symbols without redesign
- allow stepwise migration away from the python-pkcs11 fork

## Non-Goals

- replacing the high-level fork immediately
- deleting the fork in this phase
- creating a new policy-heavy object/session API in the raw layer
- hiding malformedness behind a "safe" or "friendly" convenience API

## Core Invariants

The standard raw layer must obey these invariants:

- no default attributes
- no automatic mechanism selection
- no hidden capability inference
- no silent conversion of `None` to an empty buffer
- no silent conversion of an empty buffer to `NULL`
- no method hiding based on object attributes
- no silent retries or alternate code paths
- no mandatory registration for unknown vendor mechanisms

The library may help construct the call, but it must never silently change the call's meaning.

## Architecture

The raw stack is split into exact layers and later optional convenience layers.

### Exact Layers

#### `pkcs11_check.raw.types`

Generated from a pinned PKCS#11 v3.2 header snapshot.

Responsibilities:

- standard constants: `CKA_*`, `CKM_*`, `CKK_*`, `CKO_*`, `CKR_*`, `CKF_*`, and related symbol families
- typedef aliases
- struct and union declarations
- function signature metadata
- function-list layout metadata
- symbol name tables for reporting and inspection

This layer contains no policy and no convenience behavior.

#### `pkcs11_check.raw.api`

Hand-written exact dispatch layer built on generated metadata.

Responsibilities:

- `RawPKCS11`
- loading from `lib_path`
- loading from explicit function-list pointers
- version-aware access to v2.40, v3.0, and v3.2 entry points
- pure `C_*` dispatch returning raw `CK_RV`
- feature and availability introspection

This layer must accept manually prepared `ctypes` pointers directly.

#### `pkcs11_check.raw.pack`

Hand-written exact packing layer for standard and registered extension types.

Responsibilities:

- create owned storage for scalars, bytes, structs, arrays, and templates
- expose pointer and length/count fields separately
- allow exact valid packing without adding policy
- provide standard packers for common PKCS#11 argument shapes

This layer owns memory lifetime but does not own semantic interpretation.

#### `pkcs11_check.raw.faults`

Hand-written explicit malformed-input modeling layer.

Responsibilities:

- `NULL` pointer modeling
- non-`NULL` pointer with zero length
- non-`NULL` pointer with incorrect explicit length
- truncated struct bytes
- mismatched element count
- intentionally wrong buffer width or shape
- pointer-to-bytes vs pointer-to-struct vs pointer-to-scalar distinctions

Malformedness must be explicit and named, not accidental.

#### `pkcs11_check.raw.inspect`

Hand-written exact call rendering and debugging support.

Responsibilities:

- render exact mechanism/template/parameter layout
- show symbolic names when available
- show raw numeric values when not
- show pointer origin, byte content, and explicit lengths/counts
- make review of malformed test inputs easy

The main promise of this layer is: "show me exactly what will be passed".

### Later Optional Layer

#### `pkcs11_check.raw.recipes`

Optional convenience layer added only after the exact layers are solid.

Responsibilities:

- readable common-case helpers for pkcs11-check tests
- explicit recipes for standard operations
- helpers that still require explicit mechanisms/templates when correctness depends on them

This layer is allowed to improve readability, but it is not allowed to become a policy-heavy wrapper.

## Value Model

The raw design uses one value model for both valid and malformed inputs.

### Core Concepts

- `ScalarValue`
  - exact integer, boolean, or enum-like value
- `ByteValue`
  - exact byte sequence
- `StructValue`
  - exact `CK_*` struct with owned backing storage
- `ArrayValue`
  - exact repeated values with owned backing storage
- `PointerValue`
  - where the pointer points, or whether it is `NULL`
- `LengthValue`
  - explicit length field, independently controllable from pointed data
- `CountValue`
  - explicit element count, independently controllable from pointed arrays

### Critical Rule

Every pointer-bearing PKCS#11 field must be representable as:

- pointer target
- explicit length or count

with independent caller control over each.

This must make all of these distinct and representable:

- `NULL` pointer + zero length
- `NULL` pointer + non-zero length
- valid pointer + zero length
- valid pointer + shorter-than-native length
- valid pointer + longer-than-native length
- valid pointer + truncated struct bytes
- valid pointer + intentionally mismatched count

### Example Direction

Illustrative shape only:

```python
mech = MechanismArg(
    mechanism=CKM_AES_GCM,
    param=PointerArg.to_struct(gcm_params),
    param_len=LengthArg.explicit(7),
)

tmpl = TemplateArg([
    AttrArg(CKA_VALUE_LEN, PointerArg.to_ulong(32), LengthArg.native_ulong()),
    AttrArg(CKA_ENCRYPT, PointerArg.null(), LengthArg.explicit(1)),
])
```

The important point is not the exact spelling. The important point is that malformedness becomes
explicit and inspectable instead of being spread through hand-written `ctypes` code.

## Source Of Truth And Code Generation

The standard raw layer should be generated from a pinned header snapshot committed to the repo.

This follows the same general vendored-header pattern used by other low-level bindings such as
`rust-cryptoki`'s `cryptoki-sys`: pin the header snapshot, generate from it, and make drift visible.

### Proposed Source Chain

- vendored PKCS#11 v3.2 header snapshot in-repo
- generator script that parses the standard header into an internal representation
- generated Python modules for constants, typedefs, structs, and function metadata
- hand-written exact layers on top

### Proposed Layout

```text
third_party/pkcs11-headers/3.2/pkcs11.h
scripts/generate_raw_standard.py

src/pkcs11_check/raw/
  __init__.py
  api.py
  pack.py
  faults.py
  inspect.py
  extensions.py
  types_std.py          # generated
  metadata_std.py       # generated
```

### Generator Responsibilities

- generate all standard symbol families
- generate standard struct and union declarations
- generate function signature metadata
- generate function-list index metadata
- generate standard symbol-name tables

### Generator Non-Responsibilities

- no default behaviors
- no inferred mechanisms
- no object/session API
- no vendor policies
- no high-level data coercion rules

### Drift Control

CI should fail if:

- the pinned header changes but generated files are stale
- the generator misses standard symbols expected from the pinned header
- generated symbol counts regress unexpectedly

This turns standard support into a measurable property rather than a documentation claim.

## Vendor Extension Model

Vendor extensibility is a first-class requirement, but it must not pollute the standard baseline.

### Rules

- standard generated symbols live in the standard namespace
- vendor extensions are layered on top explicitly
- unknown vendor numeric ids must still work without registration
- registration improves readability and reuse, but is never required for execution

### Proposed Extension Layer

`pkcs11_check.raw.extensions`

Responsibilities:

- register vendor symbol names
- register vendor struct declarations
- register vendor packers
- register vendor inspectors
- keep vendor namespaces isolated

### Example Direction

```python
register_extension(
    namespace="ibm",
    mechanisms={0x80010001: "CKM_IBM_KYBER"},
    structs={"CK_IBM_KYBER_PARAMS": CkIbmKyberParams},
    packers={0x80010001: pack_ibm_kyber_params},
    inspectors={0x80010001: inspect_ibm_kyber_params},
)
```

### Important Property

This must always remain valid even before any extension exists:

```python
mech = MechanismArg(0x80010001, param=manual_vendor_param)
```

That keeps vendor support from being framework-gated.

## Relationship To The python-pkcs11 Fork

The fork remains useful during migration, but it should stop being the exact-call substrate.

### Near-Term Relationship

- keep the fork for readable happy-path tests where exact raw control is not the point
- keep the bridge from a loaded fork library into `pkcs11_check.raw`
- progressively move exact-control tests toward `pkcs11_check.raw`

### Long-Term Relationship

- `pkcs11_check.raw` becomes the authoritative exact layer
- the fork becomes optional infrastructure rather than the semantic center of the suite
- later convenience APIs, if desired, are layered on raw rather than replacing it

## Migration Plan

### Phase 0: Stabilize the Extraction

- keep `RawPKCS11` in `src/pkcs11_check/raw/`
- finish the missing `7` public `C_*` wrappers
- stop adding new ad hoc raw ctypes logic outside the raw package

### Phase 1: Build the Standard Generated Layer

- vendor the pinned PKCS#11 v3.2 header snapshot
- add the generator
- generate constants, structs, and function metadata
- refactor `RawPKCS11` to use generated metadata
- add drift checks

### Phase 2: Add Exact Pack/Fault/Inspect

- add exact packing helpers
- add explicit malformed-input helpers
- add exact call inspection
- make `pkcs11_check.raw` a trustworthy migration target

### Phase 3: Migrate Raw-Heavy Existing Tests

Start with files that already need exact raw behavior:

- CKR raw tests
- TLS negative raw tests
- `test_sign_recover.py`
- `test_dual_function.py`
- `test_operation_state.py`
- `test_remaining_gaps.py`
- remaining legacy `_ctypes_raw.py` patterns

The goal is to remove duplicated low-level ctypes glue from tests first.

### Phase 4: Add Optional Recipes

- add readability helpers on top of raw
- keep them explicit and policy-free
- never make recipes mandatory for exact work

### Phase 5: Stepwise Migration From The Fork

- migrate tests where the wrapper currently blocks spec-accurate behavior
- keep the fork for tests where it still buys readability without semantic risk
- reduce fork centrality over time rather than forcing a single cut-over

### Phase 6: Optional Raw-First Primary API

Only after earlier phases are stable:

- add a broader raw-first testing API if still desirable
- build it on top of the exact raw stack
- do not let it weaken exactness guarantees

## Verification Strategy

Verification must happen at three levels.

### 1. Generation Correctness

- generated symbol counts match the pinned header
- generated structs and function metadata match expected names
- CI fails on drift

### 2. Exactness Correctness

- packing tests prove both native and explicit lengths work
- fault tests prove malformed pointer/length/count states are representable
- inspection tests prove the rendered call matches the real dispatched state

### 3. Migration Correctness

- ported tests become simpler, not more magical
- no new manual `C_GetFunctionList` or ad hoc PKCS#11 ctypes definitions outside `pkcs11_check.raw`
- the fork remains usable during transition, but no longer owns exact semantics

## Acceptance Criteria

The standard raw layer is acceptable when:

- all `104` standard PKCS#11 v3.2 functions are callable through `pkcs11_check.raw`
- all standard symbol families are generated from the pinned header
- all standard parameter structs are available as typed raw values
- explicit malformed pointer/length/count modeling exists
- exact-call inspection exists
- unknown vendor numeric ids work without registration
- vendor registration can add names, structs, packers, and inspectors without patching standard generated code

The migration foundation is acceptable when:

- the major raw-heavy test files stop duplicating ad hoc PKCS#11 ctypes definitions
- legacy `_ctypes_raw.py` becomes small or unnecessary
- new exact-control tests naturally target `pkcs11_check.raw`

## Risks And Mitigations

### Risk: The generator grows into a policy engine

Mitigation:

- limit generation to declarations and metadata
- keep all semantics in hand-written exact layers

### Risk: Pack helpers become another opinionated wrapper

Mitigation:

- keep pointer and length/count independently controllable everywhere
- keep manual ctypes escape hatches always supported

### Risk: Tests continue writing one-off ctypes

Mitigation:

- migrate the worst raw-heavy files first
- treat new ad hoc PKCS#11 ctypes code outside `pkcs11_check.raw` as technical debt to avoid

### Risk: Vendor support becomes framework-gated

Mitigation:

- accept plain integer ids and manual pointers everywhere
- make registration optional and additive

## Decision

Proceed with:

- generated exact standard raw layer first
- explicit pack/fault/inspect layers second
- optional convenience layers only later and only on top of the exact layer

In short:

- build approach 2 first
- let approach 3 grow from it later
- keep `pkcs11_check.raw` as the trust boundary

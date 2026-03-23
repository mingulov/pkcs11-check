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
- support ABI-correct runtime sizing on the host platform rather than hardcoding LP64 assumptions
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

## Platform And ABI Model

The standard layer must be ABI-correct for the current Python process and host C ABI.

### Sizing Rules

- `CK_ULONG`, `CK_FLAGS`, handle types, and related aliases must be modeled through platform-native
  `ctypes` aliases rather than hardcoded widths
- on LP64 platforms this usually means `CK_ULONG == 8` bytes
- on LLP64 platforms such as 64-bit Windows this usually means `CK_ULONG == 4` bytes

The generator is responsible for symbol and declaration extraction, but runtime type aliases must be
bound through platform-native `ctypes` definitions.

### Packing Rules

- standard structs use the platform-default ABI layout as represented by `ctypes.Structure`
- the standard generated layer does not invent custom packing rules
- if a vendor extension requires non-standard packing or layout, that must live in the extension layer
  or in manual `ctypes` declarations

### Initial Support Envelope

The immediate target remains the project's current Linux-first environment, but the design must not
encode Linux-only assumptions into generated declarations or runtime sizing logic.

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

It must support two loading modes:

- standalone loading from a module path via exported `C_GetInterface` or `C_GetFunctionList`
- bridge loading from a library already loaded through the python-pkcs11 fork

This keeps the existing bridge useful without making the fork mandatory.

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

## Threading Model

`RawPKCS11` should be designed as a thin dispatch object with minimal mutable state.

### Wrapper-Level Guarantees

- function pointer tables are immutable after construction
- dispatch methods do not mutate global call state
- independently created packed values are safe to use concurrently as long as callers do not share and
  mutate the same backing objects across threads

### Non-Guarantees

- the raw layer does not add global locking around PKCS#11 calls
- it does not promise stronger thread safety than the underlying module provides
- it does not hide module bugs related to concurrent access

### Practical Rule

The wrapper itself should be reentrant for concurrent dispatch, but thread safety of actual PKCS#11
operations remains a property of the module, session usage pattern, and PKCS#11 initialization mode.

Crash-oriented and destructive tests should continue preferring subprocess isolation over in-process
threading where safety matters.

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

## Memory Lifetime Model

The raw layer must make lifetime rules explicit.

### Base Rule

Owned storage created by `pack` or `faults` must remain alive at least until the PKCS#11 call using it
returns.

### Standard Assumption

For standard PKCS#11 calls, mechanism parameters, templates, and input buffers are assumed to be
consumed during the call itself. The raw layer does not promise that helper-owned storage remains
valid beyond the end of that call unless the caller keeps the owner object alive explicitly.

This means:

- `C_EncryptInit`, `C_SignInit`, `C_DigestInit`, `C_CreateObject`, and similar calls only require the
  associated helper-owned storage to survive for the duration of that call
- output buffers must remain valid for the duration of the output-producing call
- if a caller wants longer retention, it must keep explicit references to the owner objects

### Conformance Note

If a module incorrectly retains caller-owned pointers after a call returns, that is a module behavior
or bug. The raw layer should not silently extend lifetimes to mask such behavior.

## Output Buffer Pattern

PKCS#11's standard two-call output pattern must remain explicit in the exact layer.

### Exact Layer Rule

`raw.api` keeps output probing manual:

1. call with `NULL` output buffer to query required length
2. allocate exact output storage
3. call again with the real buffer

This is important because many negative tests intentionally vary the pointer/length relationship.

### Optional Helper Rule

A small optional helper may exist outside the exact dispatch core for happy-path probing, but it must:

- expose both calls clearly
- surface both `CK_RV` values
- avoid hiding buffer sizes or retries
- remain unsuitable for malformed-input tests by design

## Bootstrap And Session Helpers

The raw architecture does not include a policy-heavy session/object API, but adoption still needs a
small amount of bootstrap support earlier than a full recipe layer.

### Allowed Bootstrap Scope

Small explicit helpers are acceptable for:

- loading the first slot or a requested slot
- opening a session with explicit flags
- logging in with an explicit user type and PIN
- closing/finalizing in teardown

These helpers are acceptable because they do not alter cryptographic call semantics. They only reduce
boilerplate required to reach the actual exact-control operations.

### Not Allowed In Bootstrap

- implicit object wrappers
- automatic attribute defaults
- automatic mechanism choice
- hidden retries
- stateful high-level session magic

## Source Of Truth And Code Generation

The standard raw layer should be generated from a pinned header snapshot committed to the repo.

This follows the same general vendored-header pattern used by other low-level bindings such as
`rust-cryptoki`'s `cryptoki-sys`: pin the header snapshot, generate from it, and make drift visible.

### Parsing Strategy

The initial generator should target the pinned, known PKCS#11 public-domain 3.2 header format rather
than pretending to parse arbitrary C headers.

Recommended approach:

- a constrained parser over the vendored standard header
- parse the declaration forms actually present in that header:
  - `#define` constants
  - typedef-style aliases/macros
  - function prototypes
  - `struct CK_* { ... }` blocks
- reject unsupported constructs loudly rather than guessing

This is preferable to regex-only scraping of arbitrary headers, and simpler than taking a heavy
dependency on a full C parser for phase 1.

### Limitations

- phase 1 generation targets the vendored standard header only
- vendor extension headers are not part of the initial generator scope
- vendor additions remain manual registrations unless a later importer is added intentionally

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

## Loading And Subprocess Model

The raw layer must support both in-process bridge use and standalone subprocess use.

### In-Process Bridge Mode

When pkcs11-check already loaded a module via the fork, `pkcs11_check.raw` may build a raw view from
the fork-exposed function-list pointers.

This preserves compatibility with existing fixtures and avoids double-loading the same module.

### Standalone Mode

For crash-safe or isolated tests, `pkcs11_check.raw` must also work from a module path alone:

- load the shared library directly
- attempt `C_GetInterface` first when available
- fall back to `C_GetFunctionList`
- initialize and operate without requiring the fork

This standalone mode is mandatory for subprocess crash tests and for reducing long-term dependence on
the python-pkcs11 fork.

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

- priority: immediate
- rough effort: 1-2 days
- keep `RawPKCS11` in `src/pkcs11_check/raw/`
- finish the missing `7` public `C_*` wrappers
- stop adding new ad hoc raw ctypes logic outside the raw package

### Phase 1: Build the Standard Generated Layer

- priority: highest structural priority
- rough effort: about 1-2 weeks
- vendor the pinned PKCS#11 v3.2 header snapshot
- add the generator
- generate constants, structs, and function metadata
- refactor `RawPKCS11` to use generated metadata
- add drift checks

This phase comes before broad migration because migrating onto an incomplete manually maintained base
would create churn and repeat work.

### Phase 2: Add Exact Pack/Fault/Inspect

- priority: highest usability priority after generation
- rough effort: about 1-2 weeks
- add exact packing helpers
- add explicit malformed-input helpers
- add exact call inspection
- make `pkcs11_check.raw` a trustworthy migration target

Minimal bootstrap helpers for session/slot/login setup may land here as part of adoption support.

### Phase 3: Migrate Raw-Heavy Existing Tests

- priority: start once phases 1-2 cover the needed surfaces
- rough effort: incremental, file-by-file
Start with files that already need exact raw behavior:

- CKR raw tests
- TLS negative raw tests
- `test_sign_recover.py`
- `test_dual_function.py`
- `test_operation_state.py`
- `test_remaining_gaps.py`
- remaining legacy `_ctypes_raw.py` patterns

The goal is to remove duplicated low-level ctypes glue from tests first.

Small tactical migrations can happen earlier for files already covered by the current surface, but the
main migration wave should wait for the generated exact layer to exist.

### Phase 4: Add Optional Recipes

- priority: optional after migration pressure appears
- rough effort: incremental
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

## Recipe Boundary Example

Recipes are allowed to reduce obvious boilerplate, but they must stay explicit.

Illustrative direction:

```python
slot = first_usable_slot(raw)
session = open_session(raw, slot=slot, flags=CKF_SERIAL_SESSION | CKF_RW_SESSION)
login_user(raw, session, pin_bytes)

template = secret_key_template(
    key_type=CKK_AES,
    value_len=32,
    attrs=[
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    ],
)

mech = mech_simple(CKM_AES_KEY_GEN)
key = c_object_handle()
rv = raw.C_GenerateKey(session, mech.byref(), template.ptr, template.count, key.byref())
```

What makes this acceptable:

- the slot, session flags, and login are explicit
- the mechanism is explicit
- the template contents are explicit
- the call site still chooses the raw function
- callers can still replace any helper-built value with manual `ctypes`

What would be unacceptable:

- `session.generate_aes_key(256)` selecting attributes implicitly
- helpers that silently probe mechanisms and choose alternatives
- helpers that remove attributes thought to be "invalid"
- helpers that switch between `NULL` and empty buffers automatically

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

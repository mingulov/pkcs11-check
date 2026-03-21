# Review: Vendor Extension System Design

## Recommendation

Postpone this change for now and keep pkcs11-check focused on official PKCS#11 mechanisms, key types, and attributes.

That is the lower-risk path for this codebase today. The current suite, fixtures, plugin flow, and python-pkcs11 fork are built around standard PKCS#11 names and behaviors. Vendor remapping adds a large compatibility surface and the IBM assumptions in this design do not line up with the local reference material.

## What "EP11 constants" means

Here "EP11 constants" means IBM Enterprise PKCS#11 vendor-defined numeric constants such as:

- `CKM_IBM_*` vendor mechanisms
- `CKK_IBM_*` vendor key types
- `CKA_IBM_*` vendor attributes

Examples from the local vendor research:

- `CKM_IBM_DILITHIUM = 0x80010023`
- `CKM_IBM_KYBER = 0x80010024`
- `CKK_IBM_PQC_DILITHIUM = 0x80010023`
- `CKK_IBM_PQC_KYBER = 0x80010024`
- `CKA_IBM_PQC_PARAMS = 0x8001000E`

Those are IBM-specific values from EP11/OpenCryptoki vendor interfaces, not standard PKCS#11 v3.2 constants.

## Findings

### 1. IBM PQC mapping is based on the wrong interface model

The design assumes IBM/OpenCryptoki PQC can be handled as a simple alias from standard ML-DSA/ML-KEM into `CKM_IBM_ML_DSA` / `CKM_IBM_ML_KEM`, with `CKA_PARAMETER_SET` remapping.

The local vendor docs point to a different model:

- IBM PQC mechanisms are documented as `CKM_IBM_DILITHIUM` and `CKM_IBM_KYBER`
- IBM PQC key types are documented as `CKK_IBM_PQC_DILITHIUM` and `CKK_IBM_PQC_KYBER`
- IBM PQC parameters are documented via `CKA_IBM_PQC_PARAMS`, not just standard `CKA_PARAMETER_SET`

That means the design is not just missing some IDs. It appears to target a different ABI shape than the local reference data.

## 2. "Transparent" integration is not actually transparent

The design says `has_mechanism()` becomes vendor-aware globally with zero changes, but the proposed API only checks vendor aliases when a resolver is explicitly passed in.

Most current tests call `has_mechanism(p11_module, "...")` directly. Those tests would still skip on vendor-only modules before any remapping helper runs.

## 3. The pytest plugin flow is underspecified

The proposed `@vendor` marker logic does not fully match the current plugin lifecycle.

Today, dynamic runtime skip handling is only entered for items that have one of the markers already recognized as dynamic. Adding `vendor` skip logic without also updating that selection path will leave gaps where vendor-only tests are not handled as intended.

## 4. Existing tests assert standard key types on read-back

The design accounts for remapping template input and mechanism arguments, but several current tests also assert that generated or imported objects report standard key types like `KeyType.ML_DSA` and `KeyType.ML_KEM`.

If a vendor module returns vendor key types, those assertions still fail unless the design also normalizes object attribute read-back or rewrites those tests.

## 5. The implementation cost is probably understated

The document estimates a fairly contained update, but vendor support cuts across:

- python-pkcs11 enum/value handling
- default capability logic in the fork
- pytest plugin option plumbing
- preflight manifest schema
- fixtures and helper APIs
- many test skip paths
- test assertions that currently assume standard identifiers

That is a meaningful maintenance commitment, not a small compatibility layer.

## Suggested Direction

For Phase 1, keep scope to official PKCS#11 only:

- Standard `CKM_*` mechanisms
- Standard `CKK_*` key types
- Standard `CKA_*` attributes
- Standard parameter structures supported by the current fork

If vendor support becomes important later, treat it as a separate phase with:

- one concrete target vendor
- one verified source of truth for constants and structs
- explicit non-goal that vendor aliases are not automatically equivalent to standard mechanisms
- dedicated wrapper or compatibility layer design before touching broad test coverage

## Bottom Line

I do not think this vendor-extension design should move forward in its current form.

Postponing it is the right call. The project gets more value right now from expanding and hardening standard PKCS#11 coverage than from adding a broad vendor alias system with uncertain semantics and a large maintenance surface.

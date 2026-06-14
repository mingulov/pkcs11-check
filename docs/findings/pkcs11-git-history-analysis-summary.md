# PKCS#11 Git History Analysis Summary

**Date:** 2026-06-08
**Source:** Derived from `pkcs11-hardening-test-gap-notes-2026-06-08.md`
**Purpose:** Document the methodology and findings from analyzing PKCS#11 implementation git histories

---

## ANALYSIS METHODOLOGY

### Scope and Constraints

The git history analysis followed these ground rules:

1. **Provider-neutral focus:** No provider names, external change references, repository URLs, commit IDs, or provider-specific findings are recorded
2. **Public API only:** Tests must exercise public Cryptoki entry points only
3. **Provider-general tests:** Each test must be useful against any PKCS#11 module that advertises the relevant mechanism, interface version, object class, or operation
4. **No provider allowlists:** Tests do not use provider-specific skips, allowlists, or known-bug masks

### Analysis Approach

**"Targeted refresh of recent commit messages"**

- Stayed local and exact-keyword based
- Searched for: public PKCS#11 API names, `CKR_`/`CKA_`/`CKM_` identifiers, buffer/length/null/overflow/crash terms
- Focused on commit subjects that pointed at concrete findings
- Did NOT require broad full-diff archaeology pass
- Used optimized review that was sufficient for current API surfaces

### Review Scope (provider-neutral)

The history review drew on the set of PKCS#11 modules in the project's Docker
test matrix. Per the source note's ground rule, this document records **no
provider names, version numbers, branches, or per-implementation findings** — a
recurring bug pattern is only useful here once it has been restated as a
public-API surface that applies to *any* module advertising the relevant
mechanism, interface version, object class, or operation.

The matrix spans pure-software tokens, FIPS-mode variants, post-quantum-capable
software modules, embedded/TEE modules, TPM-backed modules, and mock modules, so
the recurring bug classes below were observed across structurally different
implementations rather than tied to a single one.

---

## KEY FINDINGS BY BUG CLASS

### 1. Operation Initialization Validation Issues

**Finding:** Multiple implementations had bugs where operation initialization didn't validate key type and key usage before storing active operation state.

**Examples from history:**
- `C_SignInit(CKM_ECDSA, RSA private key)` returning `CKR_OK` incorrectly
- `C_VerifyInit(CKM_ECDSA, RSA public key)` returning `CKR_OK` incorrectly
- Various operation init calls accepting wrong key types

**Translation to provider-neutral tests:**
- Use crash-safe child process for operation init + follow-up operation
- If init incorrectly returns `CKR_OK`, continue into operation and verify behavior
- Cover less-common operations and follow-up valid-operation probes after clean rejections

### 2. Mechanism Parameter Serializer/Decoder Bugs

**Finding:** Multiple implementations had length and pointer cross-check issues in mechanism parameter serializers and decoders.

**Affected mechanisms from history:**
- RSA-PSS, RSA-OAEP
- AES-GCM, AES-CBC encrypt-data
- EdDSA
- TLS KDFs
- PBE
- HKDF
- ECDH-AES key wrap
- RSA-AES key wrap
- v3.2 KEM/PQC mechanisms

**Translation to provider-neutral tests:**
- Test through public `C_DeriveKey` API for nested parameter validation
- Initial AES-CBC encrypt-data derive coverage probes malformed nested `pData`/length pairs
- Extend to other mechanisms with nested pointer/array parameters

### 3. Buffer/State Management Issues

**Finding:** History repeatedly pointed at buffer sizing and state management issues:

**Affected APIs from history:**
- `C_GetAttributeValue` — size-query and undersized-buffer behavior
- `C_Encrypt`, `C_Decrypt` — output sizing
- `C_Sign` — output sizing
- `C_WrapKey` — output sizing
- unwrap/decrypt error paths — state preservation
- Array/list-returning APIs — guard-byte violations
- `C_GetSlotList`, `C_GetMechanismList`, `C_GetInterfaceList`, `C_FindObjects`

**Translation to provider-neutral tests:**
- Add guard-byte checks for size-query and undersized-buffer behavior
- Verify two-call retry after `CKR_BUFFER_TOO_SMALL`
- Check operation state preservation after errors
- Use honest undersized arrays with required-count updates

### 4. Object Template Consistency Issues

**Finding:** Multiple implementations had template consistency bugs:

**Template issues from history:**
- Missing required attributes not caught before persisting partial state
- Optional RSA private-key CRT fields not validated
- EC/Ed/Montgomery/PQC public-key encoding issues
- Nested wrap/unwrap/derive template inconsistencies
- Private/sensitive/default attribute handling
- Scalar attribute values with `ulValueLen` not matching PKCS#11 type width

**Translation to provider-neutral tests:**
- Test scalar-length validation for object-class and key-type `CK_ULONG` template attributes
- Test ML-KEM `CKA_PARAMETER_SET` keypair templates
- Test AES `CKA_VALUE_LEN` key-size templates
- Extend to additional scalar types and mechanism-specific coverage

### 5. Derived-Key Output Length Issues

**Finding:** Recurring correctness and memory-safety surface in derived-key output length handling:

**Affected mechanisms from history:**
- DH/ECDH key derivation
- HKDF
- TLS KDFs
- PBE KDFs

**Translation to provider-neutral tests:**
- Check exact requested length for derived keys
- Verify spec-correct truncation or padding
- Verify clean rejection of impossible lengths
- Initial DH coverage checks 16-byte derived secret is rightmost truncation of 32-byte derived secret

### 6. Access-Control Attribute State Machine Issues

**Finding:** Access-control attributes not enforced as state-machine invariants:

**Affected attributes from history:**
- `CKA_ALLOWED_MECHANISMS` — empty array enforcement
- `CKA_EXTRACTABLE` — transition rules
- `CKA_ALWAYS_SENSITIVE` — immutability
- `CKA_NEVER_EXTRACTABLE` — immutability
- `CKA_PRIVATE` — public session creation restrictions
- `CKA_COPYABLE` — enforcement
- `CKA_DESTROYABLE` — enforcement
- `CKA_WRAP_WITH_TRUSTED` — transition rules
- v3.2 KEM permission attributes

**Translation to provider-neutral tests:**
- Test attributes as state-machine invariants
- Empty `CKA_ALLOWED_MECHANISMS` array: distinguish unsupported templates from accepted-and-enforced empty allowlists
- Test transition rules for immutable attributes
- Test public session restrictions on private object creation

### 7. Session/Login/Operation Lifetime Issues

**Finding:** Lifetime bugs showing up as:

**Issues from history:**
- Stale locks
- Leaked active operations
- Double-close behavior
- Inconsistent login state under concurrency

**Translation to provider-neutral tests:**
- Small bounded subprocess stress probes
- Avoid broad soak tests
- Test concurrent operations with spec-valid locking modes
- Verify no crash, hang, double free, use-after-free, or corrupted later session state

### 8. Persistent-Token and Client/Transport Serialization Issues

**Finding:** Not always reproducible through pure PKCS#11 calls, but public API can stress decode paths.

**Translation to provider-neutral tests:**
- Stress decode paths through create/finalize/reinitialize/find/get/use/destroy cycles on disposable tokens
- Optional provider-state fuzz harness for persisted state corruption

### 9. Client-Side Serializer and RPC Shim Issues

**Finding:** Client-side serializers and RPC shims are part of public API risk surface:

**Issues from history:**
- Nullable arrays
- Partial large-payload transfers
- Template serialization leaks
- Mechanism-parameter integer overflow
- Data-pointer validation

**Translation to provider-neutral tests:**
- Tests that call official PKCS#11 functions with real small buffers plus impossible claimed lengths or counts
- Verify clean rejection of malformed input

### 10. Attribute and Object-Policy Commits

**Finding:** Attribute and object-policy commits clustered around:

**Areas from history:**
- Allowed mechanisms
- Always/never sensitive state
- Wrap/unwrap format handling
- Get-attribute output sizing
- Derive output size

**Translation to provider-neutral tests:**
- Effect-based tests: after `CKR_OK`, read object attributes or verify crypto output
- After clean reject, classify the rejection rather than hiding it

---

## SPECIFIC FINDINGS (all implemented as of the 2026-06-08 verification pass)

> Status update: every one of Findings 1–14 below now has a committed test,
> confirmed by file:line during the verification pass. They are retained here as
> the worked examples of translating a recurring provider-history pattern into a
> provider-neutral, effect-based test — not as outstanding work. The KEM
> permission finding (related to Finding 1's KEM family) also exposed and fixed a
> catch-all `assert rv in (...)` that had tolerated `CKR_OK`; see the companion
> action plan's "Verification Pass".

### Finding 1: ML-KEM Derive Capability

**History finding:** Generated ML-KEM private keys should not claim `CKA_DERIVE=True`.

**Provider-neutral test:** Read `CKA_DERIVE` from generated ML-KEM private key and fail only if module reports forbidden derive capability.

### Finding 2: Empty CKA_ALLOWED_MECHANISMS

**History finding:** Empty `CKA_ALLOWED_MECHANISMS` array behavior inconsistent across implementations.

**Provider-neutral test:** Create key with empty allowed mechanisms array, verify mechanism not usable if array accepted and enforced.

### Finding 3: C_FindObjectsInit(NULL_PTR, 0) Behavior

**History finding:** `C_FindObjectsInit(NULL_PTR, 0)` is empty-template match-all search, not NULL-template error.

**Provider-neutral test:** Create session object, start search with NULL pointer and zero count, verify object returned.

### Finding 4: Sensitive Attribute Direct Buffer Protection

**History finding:** Return-code-only sensitive-attribute tests incomplete; modules might copy protected bytes even while returning rejection.

**Provider-neutral test:** Call `C_GetAttributeValue` directly on known sensitive AES key with real `CKA_VALUE` output buffer, fail if module copies protected bytes.

### Finding 5: Digest Key Protected Key Edge

**History finding:** `CKA_SENSITIVE=True` / `CKA_EXTRACTABLE=False` key material can still be digested internally without exposing `CKA_VALUE`.

**Provider-neutral test:** Import protected AES key, digest it, verify exact SHA-256 digest if operation succeeds.

### Finding 6: Mixed-Attribute C_GetAttributeValue Behavior

**History finding:** Spec-mandated "continue filling the template" behavior after benign per-attribute errors not always honored.

**Provider-neutral test:** Request sensitive `CKA_VALUE` followed by safe `CKA_LABEL`, fail if later safe attribute left unfilled after `CKR_ATTRIBUTE_SENSITIVE`.

### Finding 7: C_SetAttributeValue Partial Update Risk

**History finding:** Partial-update risk when one row succeeds before later row fails.

**Provider-neutral test:** Prove mutable label updates operational, then submit `CKA_LABEL` followed by read-only `CKA_CLASS` in one template, fail if rejected call leaves new label behind.

### Finding 8: Mechanism List Filtering Gap

**History finding:** Querying nonsense mechanism ID is not same as querying real standard `CKM_*` value absent from slot's list.

**Provider-neutral test:** Pick common absent standard mechanism, query via `C_GetMechanismInfo`, require `CKR_MECHANISM_INVALID`.

### Finding 9: Encrypt/Decrypt Lifecycle State

**History finding:** Invalid argument validation can leave stale operation state behind.

**Provider-neutral test:** Start real AES-CBC encrypt/decrypt operation, call one-shot or update with NULL input pointer or NULL output-length pointer, verify rejected operation no longer blocks fresh init.

### Finding 10: Wrap Policy Attribute Transition

**History finding:** Wrap enforcement alone does not prove `CKA_WRAP_WITH_TRUSTED` transition rules.

**Provider-neutral test:** Create key with `CKA_WRAP_WITH_TRUSTED=True`, attempt to clear with `C_SetAttributeValue`, fail if stricter policy actually removed.

### Finding 11: NULL Mechanism Init State

**History finding:** NULL mechanism init probes only checked crash/reject behavior, not state cleanup.

**Provider-neutral test:** Start digest operation, call `C_DigestInit(NULL)`, fail if `CKR_OK` reported without making fresh digest init possible.

### Finding 12: NULL Template Valid Empty Path

**History finding:** NULL-template error probes did not cover valid empty-template path.

**Provider-neutral test:** Try fixed-length secret key generation with `pTemplate=NULL` and `ulCount=0`, verify generated object class and key type after `CKR_OK`.

### Finding 13: Derive Key Handle Validation

**History finding:** Existing derive tests covered wrong mechanisms and wrong key types but not literal invalid base-key handle.

**Provider-neutral test:** Call `C_DeriveKey` with advertised no-parameter mechanism, valid output template, and `hBaseKey=0`, require clean handle rejection.

### Finding 14: Caller Pointer Alignment Bugs

**History finding:** Multiple implementations assumed FFI callers always provide naturally aligned pointers.

**Provider-neutral test:** Probe with intentionally unaligned `CK_ATTRIBUTE.pValue` scalar storage and `CK_MECHANISM_PTR` struct storage. Success and clean rejection both acceptable; crash not acceptable.

---

## COVERAGE ANALYSIS

### Strong Coverage Areas

The following areas already have meaningful coverage and should be extended, not duplicated:

- Invalid handles, NULL mechanisms, NULL templates (`testcases/security/test_api_boundary.py`)
- Large data lengths, mechanism parameter length, template-count overflow (`testcases/security/test_arithmetic_overflow.py`)
- Size-boundary and inner-NULL probes for multiple mechanisms and KDFs (`testcases/security/test_ffi_length_boundary.py`)
- Unaligned scalar storage crash-safe probes (`testcases/security/test_ffi_alignment.py`)
- NULL pointer probes for update paths and selected v3.2 entry points (`testcases/security/test_ffi_null_pointer.py`)
- Output-buffer sizing and retry/state behavior (`testcases/ckr/test_ckr_raw_buffer.py`, `testcases/test_buffers.py`)
- Object access-control and read-only session behavior (`testcases/test_access_control.py`, `testcases/test_attribute_enforcement.py`, `testcases/test_ro_session_restrictions.py`)
- KEM, v3.2, and mechanism tests (`testcases/test_kem.py`, `testcases/ckr/test_ckr_kem.py`, `testcases/test_mech_kem.py`)

### Partial Coverage Areas

The following areas have partial coverage that needs strengthening:

- Template counts
- Attribute value lengths
- Secret-key `CKA_VALUE_LEN`
- Update/final operation-state recovery
- KDF nested lengths
- v3.0/v3.2 message APIs
- Wrap/unwrap output sizing
- Recover-signature APIs
- Slot/mechanism/interface list sizing
- Random/PIN lengths
- Thread/lifetime races

### Weak or Absent Coverage Areas

The following areas have weak or absent coverage:

- Provider-state corruption harnesses
- Large output counts for APIs that return arrays
- Nested template constraint enforcement
- Huge length fields in login/token-management APIs
- Generated output parameter guard bytes
- Public-session private-object creation through every object creation path

---

## TRANSLATION PRINCIPLES

### From Provider-Specific Finding to Provider-General Test

**Principle 1:** Identify the public-API surface, not the implementation bug

- Wrong: "Module X crashes when passing NULL pointer to RSA-OAEP parameter"
- Right: "Mechanisms with nested pointer parameters (RSA-OAEP/PSS, AES-GCM/CCM, HKDF, TLS KDF, v3.2 KEM/PQC) must validate NULL pointers and lengths"

**Principle 2:** Use capability gates and interface-version gates

- Test should only run when module advertises the relevant mechanism
- Test should check interface version before calling v3.0/v3.2 entry points
- Test should skip gracefully if capability not present

**Principle 3:** Use effect-based validation

- After `CKR_OK`, verify the actual effect (read attributes, verify crypto output, check object visibility)
- After clean reject, classify the rejection using standard helpers
- Don't rely on return code alone

**Principle 4:** Use subprocess isolation for dangerous probes

- Crash-risk tests run in subprocesses
- Parent process classifies child outcome
- One module crash doesn't stop suite

**Principle 5:** Distinguish between self-contradiction (fail) and deviation (xfail)

- Self-contradiction: Module claims protection then violates it (policy)
- Deviation: Module rejects advertised mechanism with clean error (xfail)
- Crash: Always fail (segfault IS the finding)

---

## RECOMMENDED IMPLEMENTATION ORDER

### Phase 1: Critical Memory Safety (Sprint 1-2)

**Priority:** Prevent crashes, memory corruption, and undefined behavior

1. Secret-key `CKA_VALUE_LEN` over-capacity tests
2. Operation initialization key type/usage validation
3. Mechanism parameter serializer/decoder validation
4. Data length truncation beyond one-shot operations
5. Scalar attribute length validation

### Phase 2: Protocol Correctness (Sprint 3-4)

**Priority:** Ensure PKCS#11 protocol correctness and state management

1. Attribute array pointer validation
2. Buffer/state management - size-query and undersized buffers
3. Access-control and object-policy state machine invariants
4. Nested template constraint enforcement
5. Operation-state cleanup after errors
6. Generated output parameter guarding

### Phase 3: Edge Cases and Robustness (Sprint 5-6)

**Priority:** Cover edge cases and improve robustness

1. Template count overflow on valid handles
2. Misaligned caller pointers (FFI robustness)
3. KDF and PBE length/parameter validation
4. Nested KDF array and additional-key counts
5. Other caller-controlled length surfaces

### Phase 4: Stress and Experimental (Sprint 7-8)

**Priority:** Stress testing and experimental coverage

1. Thread and lifetime stress tests
2. Destructive token policy tests
3. Optional provider-state fuzz harness
4. Attribute behavior edge cases
5. Lifecycle edge cases
6. Mechanism-specific gaps
7. KEM-specific checks

---

## SUCCESS METRICS

### Coverage Metrics (revised after the 2026-06-08 verification pass)

A source-grounded verification pass cross-checked each category's claimed
coverage against the actual test bodies (see the companion action plan's
"Verification Pass" section). Revised picture:

- **Implemented and verified:** the large majority of the 33 categories have
  real tests with genuine effect checks (guard-byte sentinels, `classify_*`
  helpers, subprocess isolation) — not return-code-only probes.
- **Genuinely outstanding:** only a handful remain — public-session
  private-object *creation* rejection, destructive token/SO-PIN policy on
  disposable tokens, subprocess-isolated thread/lifetime stress, and the
  optional provider-state fuzz harness. Several "remaining expansion" bullets
  (more mechanism families per existing pattern) are breadth, not new classes.
- **Target:** all categories with meaningful, effect-based coverage; no
  return-code-only acceptance and no catch-all `assert rv in (...)` on negative
  ops.

### Quality Metrics

- **Zero provider-specific code:** All tests use capability gates, not provider allowlists
- **Effect-based validation:** All `CKR_OK` paths verified with actual effect checks
- **Subprocess isolation:** All crash-risk tests run in subprocesses
- **Classification consistency:** All tests use standard classification helpers
- **No silent acceptance:** negative ops must classify 3-way; a plain
  `assert rv in (CKR_OK, ...)` that tolerates `CKR_OK` is a finding-hiding
  regression (one such case in the v3.2 KEM encapsulate permission test was
  found and fixed in this pass).

### Module Testing Metrics

- **Minimum coverage:** tests run against the primary software-token targets in the matrix
- **Broad coverage:** tests run against 6+ structurally different modules
- **Experimental coverage:** tests run against all Docker targets where the capability is advertised

---

## CONCLUSION

The git history analysis revealed consistent bug classes across multiple PKCS#11 implementations. By translating these provider-specific findings into provider-general tests, pkcs11-check can:

1. **Find existing bugs** in current and future implementations
2. **Prevent regressions** as implementations evolve
3. **Improve robustness** across the PKCS#11 ecosystem
4. **Provide clear diagnostics** for developers using PKCS#11 modules

The analysis methodology was provider-neutral and focused on public API behavior, ensuring that resulting tests are useful against any PKCS#11 module that advertises the relevant capabilities.

---

## REFERENCES

- Original hardening analysis: `docs/findings/pkcs11-hardening-test-gap-notes-2026-06-08.md`
- Test additions action plan: `docs/findings/pkcs11-security-test-additions.md`
- Classification model: `docs/classification-model-design.md`
- Architecture: `docs/architecture.md`

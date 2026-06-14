# PKCS#11 Hardening Test Gap Notes

Date: 2026-06-08

This is a scratch note for provider-neutral pkcs11-check hardening coverage.
It is not release documentation and should not record provider names, external
change references, repository URLs, commit IDs, or provider-specific findings.

The intent is to add tests that exercise public Cryptoki entry points only.
Provider-specific source review can suggest a bug class, but the resulting test
must be useful against any PKCS#11 module that advertises the relevant
mechanism, interface version, object class, or operation.

## Ground Rules

- Use capability gates, interface-version gates, and existing setup classifiers.
- Do not use provider allowlists, provider-specific skips, or known-bug masks.
- A crash, abort, signal, timeout, heap corruption, wrong successful output, or
  accepted self-contradictory protection claim is a finding.
- A clean rejection of an advertised but non-operational path is visible xfail
  evidence unless the classification model says the accepted behavior is a hard
  self-contradiction.
- Run dangerous raw pointer, huge length, and race probes in subprocesses so one
  module crash does not stop the rest of the suite.
- Keep provider-state corruption tests out of default runs unless the token
  store is disposable and explicitly controlled by the target.

## Existing Coverage To Preserve

These areas already have meaningful coverage and should be extended, not
duplicated:

- `testcases/security/test_api_boundary.py`: invalid handles, NULL mechanisms,
  NULL templates, and broad API-boundary crash probes.
- `testcases/security/test_arithmetic_overflow.py`: large data lengths,
  mechanism parameter length, template-count overflow, and some extreme
  `CKA_VALUE_LEN` probes.
- `testcases/security/test_ffi_length_boundary.py`: size-boundary and inner-NULL
  probes for multiple mechanisms and KDFs.
- `testcases/security/test_ffi_alignment.py`: crash-safe probes for unaligned
  scalar `CK_ATTRIBUTE.pValue` storage and unaligned `CK_MECHANISM_PTR` storage.
- `testcases/security/test_ffi_null_pointer.py`: NULL pointer probes for
  update paths and selected v3.2 entry points.
- `testcases/ckr/test_ckr_raw_buffer.py` and `testcases/test_buffers.py`:
  output-buffer sizing and some retry/state behavior, including ECDH-AES
  key-wrap output sizing with a compressed EC public key.
- `testcases/test_access_control.py`,
  `testcases/test_attribute_enforcement.py`, and
  `testcases/test_ro_session_restrictions.py`: object access-control and
  read-only session behavior.
- KEM, v3.2, and mechanism tests under `testcases/test_kem.py`,
  `testcases/ckr/test_ckr_kem.py`, and `testcases/test_mech_kem.py`.

## Deep Gap Analysis

The hardening backlog should be read as a coverage map, not as a list of
provider regressions. Current source already probes many crash-prone paths, but
the coverage is uneven across PKCS#11 entry-point families:

- **Strong coverage:** invalid handles, NULL mechanisms, NULL templates,
  several mechanism-parameter NULL/length pairs, one-shot encrypt/decrypt/sign/
  digest data lengths, some output buffer size paths, read-only session
  restrictions, basic KEM errors, and several access-control attributes.
- **Partial coverage:** template counts, attribute value lengths, secret-key
  `CKA_VALUE_LEN`, update/final operation-state recovery, KDF nested lengths,
  v3.0/v3.2 message APIs, wrap/unwrap output sizing, recover-signature APIs,
  slot/mechanism/interface list sizing, random/PIN lengths, and thread/lifetime
  races.
- **Weak or absent coverage:** provider-state corruption harnesses, large output
  counts for APIs that return arrays, nested template constraint enforcement,
  huge length fields in login/token-management APIs, generated output parameter
  guard bytes, and public-session private-object creation through every object
  creation path.

The main plan correction: do not add one more generic "huge length" test that
uses a bad handle or unsupported setup. Each hardening probe must reach the
intended validation path:

- Use real sessions, real objects, and advertised mechanisms where possible.
- Preflight setup in the parent process when a later child probe needs key
  generation or object import. Setup rejects should classify as visible setup
  xfail, not as a hard failure in the malformed call.
- Keep malformed raw calls in child processes. The child should report whether
  the target call returned cleanly, crashed, hung, or exited unexpectedly.
- Prefer exact effect checks over only "no crash": output lengths, guard bytes,
  object visibility, operation state, and object attributes after `CKR_OK`
  determine whether a clean return was actually correct.
- Add negative controls with in-range values for new helper families. Otherwise
  a provider that rejects setup for unrelated reasons can make a test look
  stronger than it is.
- Use destructive/disposable-token gating for PIN, token initialization, token
  object persistence, lockout, and provider-state corruption probes.

## History Review Synthesis

Recent provider histories point to the same public-API bug classes across
multiple implementations. These should be converted into tests by API surface,
not by implementation identity:

- A targeted refresh of recent commit messages was enough for this pass. The
  latest optimized provider-history review stayed local and exact-keyword
  based: public PKCS#11 API names, `CKR_`/`CKA_`/`CKM_` identifiers,
  buffer/length/null/overflow/crash terms, and commit subjects that already
  pointed at concrete findings. A broad full-diff archaeology pass is not
  needed until the remaining API surfaces below need deeper prioritization.
- Operation initialization must validate both key type and key usage before
  storing active operation state. Existing mechanism-negative tests cover many
  wrong-key paths. The new representative hardening coverage uses a crash-safe
  child process for `C_SignInit(CKM_ECDSA, RSA private key)` and
  `C_VerifyInit(CKM_ECDSA, RSA public key)`, then continues into `C_Sign` or
  `C_Verify` if init incorrectly returns `CKR_OK`. Remaining value is
  less-common operations and follow-up valid-operation probes after clean
  rejections.
- Mechanism parameter serializers and decoders need length and pointer
  cross-checks. Useful targets include RSA-PSS, RSA-OAEP, AES-GCM, AES-CBC
  encrypt-data, EdDSA, TLS KDFs, PBE, HKDF, ECDH-AESKW, RSA-AES key wrap, and
  v3.2 KEM/PQC mechanisms. Initial AES-CBC encrypt-data derive coverage now
  probes malformed nested `pData`/length pairs through the public `C_DeriveKey`
  API.
- Size-query and undersized-buffer behavior still needs broader guard-byte
  checks. The history scan repeatedly points at `C_GetAttributeValue`,
  `C_Encrypt`, `C_Decrypt`, `C_Sign`, `C_WrapKey`, unwrap/decrypt error paths,
  and array/list-returning APIs. Initial list-buffer guard coverage now includes
  `C_GetSlotList`, `C_GetMechanismList`, `C_GetInterfaceList`, and
  `C_FindObjects`.
- Object templates need consistency checks before any partial object state is
  persisted. This includes missing required attributes, optional RSA private-key
  CRT fields, EC/Ed/Montgomery/PQC public-key encodings, nested wrap/unwrap/
  derive templates, private/sensitive/default attributes, and scalar attribute
  values whose `ulValueLen` does not match the PKCS#11 type width. The newest
  scalar-length additions cover object-class and key-type `CK_ULONG` template
  attributes in `C_CreateObject` and ML-KEM `CKA_PARAMETER_SET` keypair
  templates, plus AES `CKA_VALUE_LEN` key-size templates in `C_GenerateKey`;
  additional scalar types still need broader mechanism-specific coverage.
- Derived-key output length is a recurring correctness and memory-safety
  surface. DH/ECDH/HKDF/TLS/PBE outputs should be checked for exact requested
  length, spec-correct truncation or padding, and clean rejection of impossible
  lengths. Initial DH coverage now checks that a 16-byte DH derived generic
  secret is the rightmost truncation of the same 32-byte derived secret.
- Access-control attributes should be tested as state-machine invariants:
  `CKA_ALLOWED_MECHANISMS`, `CKA_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`, `CKA_PRIVATE`, `CKA_COPYABLE`,
  `CKA_DESTROYABLE`, `CKA_WRAP_WITH_TRUSTED`, and v3.2 KEM permission
  attributes. Empty `CKA_ALLOWED_MECHANISMS` array coverage now distinguishes
  unsupported templates from accepted-and-enforced empty allowlists, and fails
  only if a module claims the empty allowlist then still permits mechanism use.
- Session, login, and operation lifetime bugs show up as stale locks, leaked
  active operations, double-close behavior, and inconsistent login state under
  concurrency. These need small bounded subprocess stress probes rather than
  broad soak tests.
- Persistent-token and client/transport serialization bugs are not always
  reproducible through pure PKCS#11 calls, but the public API can still stress
  their decode paths through create/finalize/reinitialize/find/get/use/destroy
  cycles on disposable tokens.
- Additional recent-history review reinforced that client-side serializers and
  RPC shims are part of the public API risk surface: nullable arrays, partial
  large-payload transfers, template serialization leaks, mechanism-parameter
  integer overflow, and data-pointer validation all need tests that call the
  official PKCS#11 functions with real small buffers plus impossible claimed
  lengths or counts.
- Attribute and object-policy commits clustered around allowed mechanisms,
  always/never sensitive state, wrap/unwrap format handling, get-attribute
  output sizing, and derive output size. The useful pkcs11-check translation is
  effect-based: after `CKR_OK`, read the object attributes or verify the crypto
  output; after a clean reject, classify the rejection rather than hiding it.
- The latest exact-history pass justified one narrow array-valued attribute
  pointer probe for `CKA_ALLOWED_MECHANISMS`, but did not justify another
  immediate broad test family: `CKA_TOKEN` scalar-length checks already cover
  create/copy/unwrap/generate paths, HKDF null-pointer probes exist, AES-KWP
  corrupted unwrap and DH right-truncation are covered, and v3.0 operation
  cancellation is exercised through `C_SessionCancel` tests plus
  NULL-mechanism boundary probes.
- A later exact-history pass found one small public-API gap in ML-KEM key
  generation: generated ML-KEM private keys should not claim `CKA_DERIVE=True`.
  The provider-neutral test now reads `CKA_DERIVE` from a generated ML-KEM
  private key and fails only if the module reports the forbidden derive
  capability.
- The same optimized review found one valid search-path gap:
  `C_FindObjectsInit(NULL_PTR, 0)` is an empty-template match-all search, not a
  NULL-template error. Coverage now creates a session object, starts the search
  with a literal NULL pointer and zero count, and verifies the object is returned.
- A sensitivity-history pass found that return-code-only sensitive-attribute
  tests are incomplete. Coverage now calls `C_GetAttributeValue` directly on a
  known sensitive AES key with a real `CKA_VALUE` output buffer and fails if the
  module copies the protected bytes even while returning a sensitive-attribute
  rejection.
- A digest-key history pass found an old `C_DigestKey` protected-key edge:
  `CKA_SENSITIVE=True` / `CKA_EXTRACTABLE=False` key material can still be
  digested internally without exposing `CKA_VALUE`. Coverage now imports a known
  protected AES key, accepts clean provider-policy rejections as visible xfail
  evidence, and verifies the exact SHA-256 digest if the operation succeeds.
- A mixed-attribute `C_GetAttributeValue` history pass found the spec-mandated
  "continue filling the template" behavior after benign per-attribute errors.
  Coverage now requests sensitive `CKA_VALUE` followed by safe `CKA_LABEL` and
  fails if the later safe attribute is left unfilled after
  `CKR_ATTRIBUTE_SENSITIVE`.
- A `C_SetAttributeValue` history pass found partial-update risk when one row
  succeeds before a later row fails. Coverage now proves mutable label updates
  are operational, then submits `CKA_LABEL` followed by read-only `CKA_CLASS` in
  one template and fails if the rejected call leaves the new label behind.
- A mechanism-list filtering pass found a narrower `C_GetMechanismInfo` gap:
  querying a nonsense mechanism ID is not the same as querying a real standard
  `CKM_*` value absent from the slot's `C_GetMechanismList`. Coverage now picks
  a common absent standard mechanism and requires `CKR_MECHANISM_INVALID`.
- An encrypt/decrypt lifecycle history pass found that invalid argument
  validation can leave stale operation state behind. Coverage now starts a real
  AES-CBC encrypt/decrypt operation, calls the one-shot or update function with
  either a NULL input pointer or NULL output-length pointer, then verifies the
  rejected operation no longer blocks a fresh init.
- A wrap-policy attribute pass found that wrap enforcement alone does not prove
  `CKA_WRAP_WITH_TRUSTED` transition rules. Coverage now creates a key with
  `CKA_WRAP_WITH_TRUSTED=True`, attempts to clear it with
  `C_SetAttributeValue`, and fails if the stricter policy is actually removed.
- A v3 operation-cancel pass found that NULL mechanism init probes only checked
  crash/reject behavior. Coverage now starts a digest operation, calls
  `C_DigestInit(NULL)`, and fails if `CKR_OK` is reported without making a fresh
  digest init possible.
- A key-generation template pass found that NULL-template error probes did not
  cover the valid empty-template path. Coverage now tries fixed-length secret
  key generation with `pTemplate=NULL` and `ulCount=0`, then verifies the
  generated object class and key type after `CKR_OK`.
- A derive-key handle pass found that existing derive tests covered wrong
  mechanisms and wrong key types but not a literal invalid base-key handle.
  Coverage now calls `C_DeriveKey` with an advertised no-parameter key
  derivation mechanism, a valid output template, and `hBaseKey=0`, requiring a
  clean handle rejection.
- Several histories also converged on caller-pointer alignment bugs. The
  provider-neutral lesson is not provider identity but API shape: modules should
  not assume that foreign-function callers always provide naturally aligned
  `CK_ATTRIBUTE.pValue` scalar storage or `CK_MECHANISM_PTR` structs.

## Highest-Priority Gaps

### Secret-Key `CKA_VALUE_LEN` Over-Capacity

Bug class: a module records a caller-controlled secret-key length before fully
validating it, then uses that stored length during cleanup, copy, derive,
unwrap, or zeroization.

Useful provider-neutral probes:

- `C_CreateObject` for `CKO_SECRET_KEY` using `CKK_GENERIC_SECRET` and `CKK_AES`
  with an oversized `CKA_VALUE_LEN`, both with and without `CKA_VALUE`.
- `C_GenerateKey` for mechanisms that accept variable-length secret keys, plus
  fixed-size AES negative controls.
- `C_DeriveKey` paths that create secret keys from caller templates, including
  HKDF and other advertised KDFs where setup is available.
- `C_UnwrapKey` output templates with oversized `CKA_VALUE_LEN`.
- `C_SetAttributeValue` on existing secret keys where the provider accepts that
  attribute for the object class.
- In-range negative controls for each entry point so the guard is not testing a
  broken setup path.

Initial coverage added in this area:

- Crash-safe `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`,
  `C_UnwrapKey`, and HKDF `C_DeriveKey` probes using oversized secret-key
  `CKA_VALUE_LEN`.
- Post-success effect checks for object-creating or object-mutating paths, so a
  clean `CKR_OK` cannot silently retain `CK_ULONG_MAX` as the object length.
- `C_GenerateKey` with `CKM_GENERIC_SECRET_KEY_GEN` now verifies a normal
  32-byte positive control, reads back `CKA_VALUE_LEN`, and then probes
  `CK_ULONG_MAX` as the requested generated-key length.

Remaining useful expansion:

- Additional variable-length `C_GenerateKey` mechanisms beyond generic-secret
  generation and PBKDF2-derived generation.
- Additional advertised KDFs beyond HKDF, especially paths with nested
  mechanism parameters or additional generated outputs.
- In-range positive controls for unwrap and derive families where setup is
  reliable across more providers.

Expected outcome: a clean operation-specific rejection such as
`CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_KEY_SIZE_RANGE`,
`CKR_TEMPLATE_INCONSISTENT`, or `CKR_TEMPLATE_INCOMPLETE`; or genuine success
for a size the module really supports. Crash, abort, hang, heap corruption, or
success followed by corrupted teardown is a hard failure.

Best location: a focused
`testcases/security/test_secret_key_value_len.py`, with shared helpers reused by
`testcases/security/test_arithmetic_overflow.py` where appropriate.

### Template Count Overflow On Valid Handles

Bug class: a module multiplies `ulCount * sizeof(CK_ATTRIBUTE)` or iterates a
caller-supplied count without rejecting impossible values.

Current tests already cover several entry points. Remaining useful probes should
strengthen remaining handle-zero probes with real handles where possible, so the
provider cannot reject an invalid handle before reaching the count path.

Initial coverage added in this area:

- Valid-handle `C_GetAttributeValue`, `C_SetAttributeValue`, and `C_CopyObject`
  probes using a temporary session `CKO_DATA` object and impossible template
  counts.
- Valid-base-key `C_DeriveKey` probe using
  `CKM_CONCATENATE_BASE_AND_DATA` and an impossible output-template count.
- v3.2 `C_EncapsulateKey` and `C_DecapsulateKey` probes using real ML-KEM
  keypairs, one real output-template attribute, and impossible output-template
  counts.

Remaining useful expansion:

- Continue replacing handle-zero probes with real handles where the target API
  would otherwise reject before reaching template processing.

Expected outcome: clean argument/template rejection. Crash, timeout, or huge
allocation attempt is a hard failure.

Best location: `testcases/security/test_arithmetic_overflow.py`.

### Scalar Attribute Length Validation

Bug class: a module accepts a boolean or integer-valued attribute whose
`ulValueLen` does not match the PKCS#11 scalar type, then reads the wrong
amount of caller memory or silently treats a malformed attribute as valid.

Initial coverage added:

- `C_CreateObject` with an otherwise valid data-object template but a
  `CK_ULONG`-sized `CKA_TOKEN` value. A template rejection passes; `CKR_OK`
  fails after the created object is destroyed.
- `C_CopyObject` with an existing session object and a copy template containing
  a `CK_ULONG`-sized `CKA_TOKEN` value. A template rejection passes; `CKR_OK`
  fails after the copied object is destroyed.
- `C_UnwrapKey` with valid AES key-wrap setup and an unwrap output template
  containing a `CK_ULONG`-sized `CKA_TOKEN` value. A template rejection passes;
  `CKR_OK` fails after the unwrapped object is destroyed. Clean non-spec
  rejections remain visible xfail evidence.
- `C_GenerateKey` with an advertised AES key-generation mechanism and an output
  template containing a `CK_ULONG`-sized `CKA_TOKEN` value. A template rejection
  passes; `CKR_OK` fails after the generated key is destroyed.
- `C_GenerateKeyPair` with an advertised RSA key-pair-generation mechanism and
  public-key or private-key templates containing a `CK_ULONG`-sized
  `CKA_TOKEN` value. A template rejection passes; `CKR_OK` fails after both
  generated keys are destroyed.
- `C_GenerateKeyPair` with an advertised EC key-pair-generation mechanism,
  positive-control P-256 setup, and public-key or private-key templates
  containing a `CK_ULONG`-sized `CKA_TOKEN` value. A template rejection passes;
  `CKR_OK` fails after both generated keys are destroyed.
- `C_CreateObject` with otherwise valid data-object templates whose
  `CKA_CLASS` value is stored in undersized or oversized `CK_ULONG` storage. A
  template rejection passes; `CKR_OK` fails after the created object is
  destroyed.
- `C_CreateObject` with otherwise valid AES secret-key templates whose
  `CKA_KEY_TYPE` value is stored in undersized or oversized `CK_ULONG` storage.
  A template rejection passes; `CKR_OK` fails after the created key is
  destroyed.
- `C_GenerateKeyPair` with advertised ML-KEM and ML-DSA key-pair-generation
  mechanisms, positive-control ML-KEM-768 / ML-DSA-65 setup, and public-key or
  private-key templates whose `CKA_PARAMETER_SET` value is stored in undersized
  or oversized `CK_ULONG` storage. A template rejection passes; `CKR_OK` fails
  after both generated keys are destroyed.
- `C_GenerateKey` with an advertised AES key-generation mechanism and an output
  template whose `CKA_VALUE_LEN` value is stored in undersized or oversized
  `CK_ULONG` storage. A template rejection passes; `CKR_OK` fails after the
  generated key is destroyed.

Remaining useful expansion:

- Additional `C_GenerateKeyPair` mechanisms with malformed boolean lengths,
  especially mechanisms with more complex required attributes such as EdDSA and
  PQC key pairs.
- Additional `C_UnwrapKey` variants that avoid earlier class/key-type template
  rejection on modules that do not accept those attributes in unwrap templates.
- Integer-valued scalar attributes with undersized or oversized lengths,
  especially create/copy/generate/unwrap surfaces beyond the initial
  object-class, key-type, AES value-length, ML-KEM parameter-set, and ML-DSA
  parameter-set coverage.

Expected outcome: clean attribute/template rejection. Accepting a malformed
scalar attribute as valid is a hard failure; a different clean rejection is
visible xfail evidence.

Best locations: `testcases/ckr/test_ckr_object.py` for create/copy coverage and
mechanism-specific CKR tests for generate/unwrap paths.

### Attribute Array Pointer Validation

Bug class: a module accepts an array-valued template attribute whose `pValue`
is `NULL_PTR` while `ulValueLen` is nonzero, then either treats the malformed
attribute as valid or dereferences it while parsing or persisting the object.

Initial coverage added:

- `C_CreateObject` with an otherwise valid AES secret-key template whose
  `CKA_ALLOWED_MECHANISMS` attribute has `pValue=NULL_PTR` and
  `ulValueLen=sizeof(CK_ULONG)`. A clean template or argument rejection passes;
  `CKR_OK` fails after the created key is destroyed.
- `C_CreateObject` with an otherwise valid AES secret-key template whose
  `CKA_ALLOWED_MECHANISMS` attribute is represented as the empty array
  (`pValue=NULL_PTR`, `ulValueLen=0`). If the module rejects the template, the
  rejection is classified. If the module accepts and reports an empty array
  back, the test verifies that a listed mechanism is not still usable.

Remaining useful expansion:

- Additional array-valued attributes where setup is practical, especially
  attributes used in copy, unwrap, derive, and v3.2 KEM templates.
- Additional zero-length `NULL_PTR` cases where array-valued attributes may
  legitimately represent empty arrays depending on the attribute and operation.

Expected outcome: clean attribute/template/argument rejection for nonzero
length with a NULL pointer. Accepting that malformed input as valid, crashing,
or persisting malformed object state is a hard failure.

Best location: `testcases/ckr/test_ckr_object.py` for create/copy coverage and
mechanism-specific CKR tests for generate/unwrap/derive paths.

### Data Length Truncation Beyond One-Shot Encrypt/Decrypt/Sign/Digest

Bug class: a module casts `CK_ULONG` data lengths to a narrower signed or
unsigned type and then reads, writes, hashes, signs, or verifies the wrong
amount of memory.

Useful probes:

- `C_Verify` with a small real data buffer and huge `ulDataLen`.
- `C_DigestUpdate`, `C_SignUpdate`, and `C_VerifyUpdate` with small real buffers
  and huge update lengths.
- `C_DigestKey` after importing or generating a digestable secret key, where the
  mechanism and key class make that operation meaningful.
- Use both `0x7fff_ffff_ffff_ffff` and `0x8000_0000_0000_0000` class values
  where the platform uses 64-bit `CK_ULONG`, because signed-boundary and
  unsigned-boundary truncations are different bug classes.

Initial coverage added in this area:

- HMAC `C_Verify` with a small real data buffer, normal signature buffer, and
  huge claimed `ulDataLen`.
- Initialized AES-ECB `C_EncryptUpdate` and `C_DecryptUpdate` probes with small
  real buffers and huge claimed update lengths.
- Initialized HMAC `C_SignUpdate`, HMAC `C_VerifyUpdate`, and SHA-256
  `C_DigestUpdate` probes with small real buffers and huge claimed update
  lengths.
- `C_DigestKey` consuming a temporary generic-secret key imported with a real
  16-byte `CKA_VALUE` and oversized `CKA_VALUE_LEN`, including no-crash
  teardown, toxic stored-length detection, and digest correctness if the
  operation reports success.
- `C_SignRecover` with tiny real data buffers and huge claimed `ulDataLen`
  values, using recover-capable RSA keys where the provider advertises the
  mechanism.
- `C_VerifyRecover` with tiny real signature buffers and huge claimed
  `ulSignatureLen` values, plus a valid-signature one-byte recovered-output
  buffer with adjacent guard bytes and required-length classification.
- `C_EncryptMessage` with tiny real associated-data/plaintext buffers and huge
  claimed `ulAssociatedDataLen` or `ulPlaintextLen` values, using advertised
  AES-GCM message-encrypt capability and classifying clean negative CKRs.
- `C_EncryptMessageBegin` and `C_EncryptMessageNext` with tiny real plaintext
  buffers and huge claimed plaintext lengths, preserving subprocess crash
  isolation and clean negative CKR classification.
- `C_DecryptMessage` with tiny real associated-data/ciphertext buffers and
  huge claimed `ulAssociatedDataLen` or `ulCiphertextLen` values, including
  decrypt-specific encrypted-data length rejection.
- `C_DecryptMessageBegin` and `C_DecryptMessageNext` with tiny real ciphertext
  buffers and huge claimed multipart ciphertext lengths.
- `C_SignMessage` with a tiny real data buffer and huge claimed `ulDataLen`,
  using RSA message-sign capability where advertised.
- `C_VerifyMessage` with a real signature over normal data, then huge claimed
  `ulDataLen` or `ulSignatureLen` values on the verify call.
- `C_SignMessageBegin` and `C_SignMessageNext` with tiny real data buffers and
  huge claimed multipart data lengths.
- `C_VerifyMessageBegin` with a tiny real message-parameter buffer and huge
  claimed parameter length, plus `C_VerifyMessageNext` with a real signature
  and huge claimed data or signature lengths.

Expected outcome: clean length/data rejection. `CKR_OK` for a claimed huge input
is suspicious unless the test can verify no out-of-bounds access and no wrong
effect occurred; crash or hang is a hard failure.

Remaining useful expansion: token-management lengths and operation-state
retry/preservation after cleanly rejected recover/update paths.

Best locations: `testcases/security/test_ffi_length_boundary.py` for generic
data lengths; `testcases/security/test_recover_length_boundary.py` for recover
APIs.

### Misaligned Caller Pointers

Bug class: a module casts caller-provided `void *` or struct pointers directly
to scalar types and dereferences them, crashing or reading the wrong value when
an FFI caller supplies a valid byte buffer at an unaligned address.

Useful provider-neutral probes:

- `CK_ATTRIBUTE.pValue` pointing to unaligned `CK_ULONG` / `CK_BBOOL` storage in
  object templates such as `C_GenerateKey`.
- `CK_MECHANISM_PTR` pointing to an unaligned `CK_MECHANISM` byte layout in
  operation initialization calls such as `C_EncryptInit`.
- Later expansion can cover mechanism-parameter structs with nested pointers,
  for example RSA-OAEP/PSS, AES-GCM/CCM, HKDF, TLS KDF, and v3.2 KEM/PQC
  parameter structs.

Initial coverage added:

- `C_GenerateKey` with an AES key template whose scalar attribute `pValue`
  pointers are intentionally shifted by one byte. Success and clean rejection
  are both acceptable; crash, abort, timeout, or child-script failure is not.
- `C_EncryptInit` with an otherwise valid AES-ECB mechanism struct stored at an
  intentionally unaligned address. Success and clean rejection are both
  acceptable; crash, abort, timeout, or child-script failure is not.

Expected outcome: no crash or forced process exit. This is a robustness probe,
not a strict conformance verdict, because the standard does not require modules
to accept every hostile FFI layout. Returning `CKR_OK` is acceptable if the
operation state remains coherent; rejecting cleanly is also acceptable.

Best location: `testcases/security/test_ffi_alignment.py`.

### Other Caller-Controlled Length Surfaces

The current note should not stop at crypto input lengths. Similar truncation and
oversized-copy mistakes can occur in several public API families:

- `C_WrapKey` output length and `C_UnwrapKey` wrapped-key input length, including
  two-call size query, undersized output buffer, and guard-byte checks.
- `C_SignRecover` and `C_VerifyRecover` data/signature/recovered-output lengths.
  Initial coverage includes huge claimed data/signature lengths and a
  `C_VerifyRecover` one-byte output buffer guard.
- v3.0/v3.2 message APIs, especially `*Message`, `*MessageBegin`, and
  `*MessageNext` with huge input lengths. Message finalizers have no buffer
  length parameters in the current raw binding, so they belong in lifecycle
  coverage rather than length-boundary coverage.
- `C_GenerateRandom` output length and `C_SeedRandom` seed length.
- `C_Login`, `C_LoginUser`, `C_InitPIN`, `C_SetPIN`, and `C_InitToken` PIN,
  username, and label lengths. Token-changing variants must be destructive and
  disposable-token gated.
- Output-list APIs: `C_GetSlotList`, `C_GetMechanismList`,
  `C_GetInterfaceList`, `C_FindObjects`, and `C_GetOperationState` should be
  tested with honest undersized arrays, required-count updates, and guard bytes
  where the API writes through caller buffers. Avoid blaming providers for a
  caller that claims a large output array while only allocating one element.

Initial coverage added in this area:

- `C_GetMechanismList` and `C_GetInterfaceList` undersized one-entry output
  buffers with adjacent guard bytes and required-count checks.
- `C_WrapKey` undersized one-byte output buffers with adjacent guard bytes,
  two-call required-length comparison, successful retry with the size-query
  length after `CKR_BUFFER_TOO_SMALL`, and parent-side classification for clean
  non-spec reject codes.
- `C_WrapKey` with `CKM_ECDH_AES_KEY_WRAP` now has a compressed P-256 public-key
  variant that checks one-byte output-buffer guard preservation, required length
  reporting, and retry after `CKR_BUFFER_TOO_SMALL`.
- `C_GetOperationState` undersized one-byte state buffers after an active
  SHA-256 digest update, with adjacent guard bytes, two-call required-length
  comparison, successful retry with the size-query length after
  `CKR_BUFFER_TOO_SMALL`, and parent-side classification for clean non-spec
  reject codes.
- `C_GenerateRandom` and `C_SeedRandom` extreme claimed-length probes using
  tiny real caller allocations. These are FFI robustness probes rather than
  two-call buffer-size conformance tests: they check for crash, forced process
  exit, oversized write into adjacent guard bytes, and success on an impossible
  length claim.
- `C_GetSlotList` undersized one-entry output arrays with adjacent guard bytes
  and required-count checks on targets that expose more than one slot.
- `C_FindObjects` one-handle output arrays with adjacent guard bytes after
  creating two matching temporary session objects. This is not a
  `CKR_BUFFER_TOO_SMALL` API; the rule is that `pulObjectCount` must not exceed
  the caller's `ulMaxObjectCount` and no extra handles may be written.
- `C_EncryptMessage` AES-GCM input lengths for `ulAssociatedDataLen` and
  `ulPlaintextLen` now use tiny real buffers with `isize::MAX` and
  `isize::MAX + 1` claimed lengths, while preserving crash isolation and
  provider-general negative CKR classification.
- `C_EncryptMessageBegin` and `C_EncryptMessageNext` now cover the same
  signed-boundary and unsigned-boundary plaintext length classes on the
  multipart message-encrypt path.
- `C_DecryptMessage` AES-GCM input lengths for `ulAssociatedDataLen` and
  `ulCiphertextLen` now use tiny real buffers with `isize::MAX` and
  `isize::MAX + 1` claimed lengths, while preserving crash isolation and
  provider-general negative CKR classification.
- `C_DecryptMessageBegin` and `C_DecryptMessageNext` now cover the same
  signed-boundary and unsigned-boundary ciphertext length classes on the
  multipart message-decrypt path.
- `C_SignMessage` and `C_VerifyMessage` now cover one-shot message sign/verify
  data and signature length boundaries, using real RSA keys and a real
  signature for verify setup.
- `C_SignMessageBegin` and `C_SignMessageNext` now cover multipart message-sign
  data length boundaries.
- `C_VerifyMessageBegin` and `C_VerifyMessageNext` now cover multipart
  message-verify parameter, data, and signature length boundaries.
- `C_GetAttributeValue` variable-size attribute reads with a NULL-buffer size
  query, one-byte non-NULL output buffer, adjacent guard bytes, and retry using
  the size-query length. For the undersized non-NULL call, `ulValueLen` is
  expected to become `CK_UNAVAILABLE_INFORMATION`; the exact required size comes
  from the earlier size query, not from the undersized call.
- One-shot `C_Decrypt` with `CKM_AES_CBC_PAD`, valid ciphertext generated in
  the same session, a one-byte output buffer with adjacent guard bytes, and a
  retry without reinitialization after `CKR_BUFFER_TOO_SMALL`. For padded
  decrypt, the first returned length is accepted if it is large enough to retry
  and no larger than the ciphertext; the retry must return the exact original
  plaintext.
- Multipart AES-CBC-PAD `C_DecryptUpdate` now covers a one-byte output buffer
  with adjacent guard bytes, a retry after `CKR_BUFFER_TOO_SMALL`, and final
  plaintext verification across update plus final output.
- One-shot `C_Digest` and `C_Sign` undersized output-buffer probes now retry the
  same operation with a known-correct output buffer after `CKR_BUFFER_TOO_SMALL`.
  The digest retry checks the SHA-256 value; the RSA sign retry checks successful
  completion with the fixed RSA-2048 signature size.
- Multipart AES-CBC-PAD `C_EncryptFinal` and `C_DecryptFinal` now cover a
  one-byte final output buffer with adjacent guard bytes after a valid update,
  and verify the combined result after either accepted one-byte final output or
  a retry following `CKR_BUFFER_TOO_SMALL`.

Remaining useful expansion:

- Follow-up retry/state-preservation checks after `CKR_BUFFER_TOO_SMALL` for
  remaining byte-output APIs such as additional attribute reads and recover
  outputs.
- Destructive/disposable-token coverage for PIN, SO-PIN, token-label, and
  username length surfaces.

Best locations: extend `testcases/security/test_ffi_length_boundary.py` for
crypto/random/PIN lengths; extend CKR raw/list tests for output-list sizing; add
message-finalizer lifecycle hardening near existing message operation tests.

## Buffer And State Gaps

### AES-CBC-PAD Decrypt Output Sizing

Useful probes:

- Multipart `C_DecryptUpdate` / `C_DecryptFinal` with undersized buffers.
- Size-query paths with `pData == NULL` and edge-case ciphertext lengths.
- Retry after `CKR_BUFFER_TOO_SMALL`; the operation must remain usable and must
  not produce corrupted plaintext or `CKR_OPERATION_NOT_INITIALIZED`.
- Guard bytes after the declared output buffer must remain unchanged.

Expected outcome: `CKR_BUFFER_TOO_SMALL` with a correct required length, or a
clean operation-specific rejection for invalid ciphertext shape. Buffer
overwrite, state loss after retry, wrong plaintext after `CKR_OK`, or crash is a
failure.

Initial coverage added:

- One-shot `C_Decrypt` with `CKM_AES_CBC_PAD` and valid ciphertext verifies
  guard preservation, sufficient retry length, retry without reinitialization,
  and exact plaintext on retry.
- Multipart `C_DecryptUpdate` with `CKM_AES_CBC_PAD` now verifies guard
  preservation, usable retry length, retry without reinitialization, and exact
  plaintext after `C_DecryptFinal`.
- Multipart `C_EncryptFinal` and `C_DecryptFinal` with `CKM_AES_CBC_PAD` verify
  guard preservation and retry/state behavior after valid update calls.

Best locations: `testcases/ckr/test_ckr_raw_buffer.py` for raw sizing and
`testcases/test_buffers.py` for retry/state preservation.

### ECDH-AES Hybrid Wrap Output Sizing

Useful probes:

- Functional `CKM_ECDH_AES_KEY_WRAP` roundtrip and bit-flip integrity remain in
  authenticated-wrap coverage.
- Raw output-buffer probes should include both ordinary EC public-key encodings
  and compressed public-key encodings when the provider accepts them.
- Retry after `CKR_BUFFER_TOO_SMALL` must preserve operation state and produce a
  wrapped blob with the same required length as the initial size query.
- Guard bytes after the declared output buffer must remain unchanged.

Initial coverage added:

- A compressed P-256 EC public key is imported as the wrapping public key, then
  `C_WrapKey` is called with a one-byte output buffer and adjacent guard bytes.
  The test verifies guard preservation, required-length reporting, and retry
  with the size-query length after `CKR_BUFFER_TOO_SMALL`.

Remaining useful expansion:

- Cofactor and alternate-curve variants where providers advertise and can set
  up those mechanisms reliably.
- Unwrap-side output-template and state-preservation variants.
- Generated or returned ephemeral public-data format checks where the API path
  exposes such output through public Cryptoki calls.

Best location: `testcases/ckr/test_ckr_raw_buffer.py` for raw sizing, with
functional checks staying near authenticated-wrap tests.

### Attribute Required-Size Reporting

Useful probes:

- Generate or import keys with variable-size public attributes.
- Read attributes such as `CKA_EC_POINT` with an undersized buffer.
- Verify `CKR_BUFFER_TOO_SMALL`, `CK_UNAVAILABLE_INFORMATION` on the undersized
  attribute's `ulValueLen`, unchanged guard bytes, and successful retry with
  the size-query length.
- Validate the returned encoding where the standard defines it.

Expected outcome: exact size reporting on the NULL-buffer query and no
overwrite on the undersized non-NULL call. Returning `CKR_OK` into an
undersized buffer, failing to mark the undersized attribute unavailable, or
corrupting guard bytes is a finding.

Best location: `testcases/ckr/test_ckr_raw_buffer.py`.

### Generated Output Parameter Guarding

Some mechanisms write generated IVs, nonces, tags, contexts, or key material
back into caller-provided mechanism-parameter structs. Functional tests can pass
while still missing output overwrite or size-reporting issues.

Useful probes:

- Generated IV/nonce/tag paths should use small declared buffers surrounded by
  guard bytes.
- Mechanism structs with output pointer set but output length too small should
  report a clean error or exact required size where the standard defines one.
- Generated outputs must be nonzero/non-default when `CKR_OK` claims the module
  generated them.
- The same mechanism should have a positive control with correctly sized output
  buffers.

Initial coverage added:

- `C_EncryptMessage` with `CK_GCM_MESSAGE_PARAMS.ivGenerator` now uses guarded
  caller buffers for the generated IV and tag outputs, then decrypts the result
  with an independent AES-GCM implementation. This catches generated-output
  writes beyond `ulIvLen` / `ulTagBits` on modules that expose and advertise the
  message encryption path.

Best location: existing generated-output and authenticated-wrap/message tests,
with raw guard-byte helpers rather than high-level wrappers.

## KDF And PBE Length Gaps

Useful probes:

- TLS 1.2 master-key and key-material derive parameters with undersized or
  NULL returned key-material buffers.
- PKCS#5 PBKDF2 parameter fields with oversized iteration count.
- Existing KDFs that take nested pointer arrays or nested length fields should
  keep inner-NULL and huge-length variants together in the same file.

Initial coverage added:

- `C_DeriveKey` with `CKM_DH_PKCS_DERIVE` now checks exact requested
  `CKA_VALUE_LEN` for extractable generic-secret outputs, including the
  relationship between 32-byte output and left-truncated 16-byte output.
- `C_GenerateKey` with `CKM_PKCS5_PBKD2` now probes `pPassword`,
  `pSaltSourceData`, and `pPrfData` using tiny real buffers with claimed
  `isize::MAX` and `isize::MAX + 1` lengths. The parent classifies `CKR_OK` as
  failure, expected mechanism/template rejects as pass, other clean rejects as
  xfail, and crashes as failures via subprocess isolation.
- `C_GenerateKey` with `CKM_PKCS5_PBKD2` now also probes requested output size
  through `CKA_VALUE_LEN=CK_ULONG_MAX`, rejecting `CKR_OK` as invalid success
  and preserving subprocess crash isolation.
- `C_GenerateKey` with the existing PKCS#12 PBE/PBA mechanism set now probes
  `CK_PBE_PARAMS.pPassword` and `pSalt` using tiny real buffers with claimed
  `isize::MAX` and `isize::MAX + 1` lengths, reusing the mechanism/key-type
  pairings from functional PBE coverage.
- `C_DeriveKey` with `CKM_TLS_KDF` now probes
  `CK_SSL3_RANDOM_DATA.pClientRandom` and `pServerRandom` using tiny real
  buffers with claimed `isize::MAX` and `isize::MAX + 1` lengths.
- `C_DeriveKey` with `CKM_SP800_108_COUNTER_KDF` now probes a real
  `pDataParams` array with a huge `ulNumberOfDataParams`, and a real
  one-entry `pAdditionalDerivedKeys` array with a huge
  `ulAdditionalDerivedKeys` count.

Remaining useful expansion:

- PBKDF2 iteration-count boundaries.
- Additional PKCS#12 PBE mechanisms beyond the functional PBE coverage set,
  if they become available in provider targets.
- TLS 1.2 master-key/key-material derive structures, especially version and
  returned-key-material output buffers.
- Additional KDFs with nested pointer arrays and additional-output templates,
  beyond the initial SP800-108 coverage above.

Expected outcome: clean `CKR_MECHANISM_PARAM_INVALID`,
`CKR_ARGUMENTS_BAD`, `CKR_DATA_LEN_RANGE`, or similarly specific rejection.
Crash, hang, excessive allocation, or success with nonsensical parameter lengths
is a failure.

Best location: `testcases/security/test_ffi_length_boundary.py`, borrowing setup
from existing TLS, PBE, PBKDF2, and KDF tests.

### Nested KDF Array And Additional-Key Counts

KDF parameter structs often contain arrays or secondary output templates. These
are separate from simple pointer+length bugs:

- Count fields for arrays of nested data parameters now have initial SP800-108
  coverage for both `NULL` arrays and real arrays with huge counts; extend the
  same pattern to other KDF structs as they become practical.
- Additional-derived-key arrays now have initial SP800-108 coverage with one
  real output template plus a huge additional-key count; extend that pattern to
  mechanisms with returned key-material structures or secondary outputs.
- Returned key-material structs should be tested with undersized or NULL output
  buffers where the mechanism supports writing material back to the caller.
- Derived-key templates in both primary and additional outputs need the same
  template-count and `CKA_VALUE_LEN` hardening as direct `C_DeriveKey`.

Best location: `testcases/security/test_ffi_length_boundary.py` plus KDF-specific
functional tests where the setup already exists.

## Access-Control And Object-Policy Gaps

Useful probes should fill only missing variants, because several access-control
classes are already covered:

- `CKA_DERIVE=False` must prevent `C_DeriveKey`. (Covered.)
- `CKA_ENCAPSULATE=False` and `CKA_DECAPSULATE=False` must prevent v3.2 KEM
  operations when those attributes and entry points are available. (Covered as a
  policy claim/effect check on both sides. A negative KEM permission probe must
  drive the **full** operation with a real output buffer — a size-query-only
  probe can be masked by a module whose `pCiphertext=NULL` query rejects before
  the permission check, and must never tolerate `CKR_OK` via a catch-all
  assertion.)
- `CKA_COPYABLE=False` must prevent copying; if a copy is allowed before the
  flag is false, later false-to-true escalation must be rejected. (Covered.)
- `CKA_DESTROYABLE=False` must prevent destruction. (Covered.)
- Public sessions without login must not create private token or private session
  objects through KEM, unwrap, derive, copy, or direct create paths. (**Gap:**
  public-session *visibility* of private objects is covered, but *creation*
  rejection across these paths is not — this is the genuine remaining
  access-control item.)

Expected outcome: clean access-control rejection. Creating or using an object
after claiming the relevant operation is prohibited is a self-contradiction and
must fail, not xfail.

Best locations: existing access-control, attribute-enforcement, RO-session, KEM,
and CKR KEM tests.

### Nested Template Constraint Enforcement

Readability of `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, and
`CKA_DERIVE_TEMPLATE` is not enough. The hardening gap is enforcement:

- A wrapping key with `CKA_WRAP_TEMPLATE` must not wrap a target that violates
  the nested template.
- An unwrapping key with `CKA_UNWRAP_TEMPLATE` must not create an object that
  violates the nested template.
- A deriving key with `CKA_DERIVE_TEMPLATE` must not derive an object that
  violates the nested template.
- If the module accepts and reports the constraint attribute, then later
  violating it is a policy permission self-contradiction and should fail.

Initial coverage added:

- `CKA_WRAP_TEMPLATE` enforcement now has a positive-control AES key-wrap path:
  a wrapping key is generated with a nested `CKA_LABEL` constraint, a matching
  target is checked first, and a second target with a different label must not
  be wrapped. If the module reports the template attribute and still accepts the
  violating target, the test fails as a policy self-contradiction; clean
  non-operational paths remain visible skips or xfails.
- `CKA_UNWRAP_TEMPLATE` enforcement now wraps a real AES key first, unwraps it
  once with a matching output template, then tries to unwrap the same blob with
  a violating `CKA_LABEL`. A claimed template followed by accepted violation is
  a policy self-contradiction.
- `CKA_DERIVE_TEMPLATE` enforcement now imports a real derivable generic-secret
  key with a nested label constraint, derives once through
  `CKM_CONCATENATE_BASE_AND_DATA` with a matching output template, then repeats
  with a violating label. Clean rejection is classified separately from accepted
  policy violation.

Remaining useful expansion:

- More mechanism families for the same attributes, especially RSA/OAEP unwrap,
  ECDH or HKDF derive, and v3.2 KEM encapsulate/decapsulate templates.
- Additional nested constraints beyond `CKA_LABEL`, such as key type, operation
  permissions, sensitivity/extractability, and allowed mechanisms.

Best location: extend `testcases/test_remaining_gaps.py` or split into a focused
attribute-template enforcement file.

## Operation-State Cleanup Gaps

Bug class: an early error from one operation leaves the session in a stale active
state that blocks the next `*Init`, causes wrong later results, or terminates the
wrong operation.

Useful probes:

- `C_DigestUpdate`, `C_SignUpdate`, `C_VerifyUpdate`, and `C_DigestKey` after
  cleanly rejected invalid inputs.
- Multipart decrypt and verify finalization after buffer-too-small or invalid
  length paths.
- Reinitialize the same operation after the error and verify the second valid
  operation works.
- Where the spec says the operation remains active after a specific error, retry
  the same operation and verify it is still usable.

Expected outcome: spec-correct active/terminated state. Wrong state after a
claimed successful or recoverable error is a lifecycle self-contradiction.

Best locations: `testcases/test_operation_termination.py`,
`testcases/test_operation_state.py`, and CKR raw multipart/state tests.

### State Cleanup After Buffer And Length Errors

The operation-state backlog should separate three cases:

- Functions that always terminate the operation after a terminal call, even on
  rejection.
- Functions that preserve the operation after `CKR_BUFFER_TOO_SMALL`, so retry is
  required and `CKR_OPERATION_NOT_INITIALIZED` is a failure.
- Functions where invalid input should terminate, and leaving a stale operation
  active causes cascade failures in later tests.

New tests should explicitly record which rule applies to the called function and
then probe the next `*Init`, retry call, or finalizer to verify the effect.

## Thread And Lifetime Stress Gaps

These should be non-default stress tests and should run in subprocesses with
bounded loops and timeouts.

Useful probes:

- Object search while another thread creates and destroys matching session
  objects.
- Two threads racing `C_CloseSession` on the same handle.
- One thread opening/closing sessions while another calls `C_CloseAllSessions`.
- Concurrent raw `C_Initialize`, simple read-only calls, and `C_Finalize` using
  valid locking flags.

Expected outcome: no crash, hang, double free, use-after-free, or corrupted later
session state. Clean stale-handle errors are acceptable where the race makes the
handle genuinely stale.

Best location: a dedicated stress file or extension of existing session/thread
tests, with a marker that keeps it out of fast default runs.

### Stress Test Design Risk

Thread tests are especially easy to make flaky. Keep them narrow:

- Use the spec-valid locking mode or application mutex callbacks.
- Bound loop counts and subprocess timeouts.
- Treat "both calls returned `CKR_OK` when only one operation/session state could
  win" as a state-machine failure, not merely a race artifact.
- Keep token-mutating stress probes off shared persistent tokens unless a
  disposable token is provisioned.
- Prefer several small deterministic race probes over one broad soak test.

## Destructive Token Policy Gap

Useful probe:

- On disposable tokens only, repeatedly call `C_InitToken` with a wrong SO PIN
  and verify it follows the same SO failure/lockout policy as the provider
  advertises for SO login.

Expected outcome: provider-policy-specific clean lockout or rejection. Unlimited
wrong SO PIN attempts through token initialization should be reported as a
security policy finding if the token otherwise enforces SO lockout.

Best location: `testcases/test_so_pin.py` or a new destructive SO-policy test.

## Optional Provider-State Fuzz Harness

This is not normal conformance coverage because it mutates provider-owned
persisted state outside the Cryptoki API. Keep it optional and explicit.

Useful harness shape:

- Create token objects through ordinary PKCS#11 calls.
- Finalize the module and corrupt length fields in a disposable token store.
- Reinitialize and call ordinary APIs that force object decode, such as
  `C_FindObjects`, `C_GetAttributeValue`, `C_SignInit`, `C_DeriveKey`, or
  `C_DestroyObject`.
- Require clean load rejection, missing object, or operation-specific CKR.

Crash, hang, excessive allocation, or heap corruption is a finding. This harness
needs provider-target metadata describing where the disposable token store lives;
it should not run against user-owned tokens.

## Implementation Guardrails

Before converting this scratch note into tests, add or reuse a few small helpers:

- A raw child-runner helper for malformed calls that reports `SETUP_XFAIL`,
  `TARGET_RV`, crash signal, timeout, and unexpected positive child exits
  consistently.
- A guard-buffer helper that builds declared-size buffers inside larger sentinel
  allocations and reports overwritten bytes.
- A valid-handle setup helper for data objects, secret keys, RSA/EC keys, KEM
  keys, and KDF base keys, so count/length probes reach the intended branch.
- A disposable-token capability helper for destructive token and provider-state
  fuzzing.
- A reusable "operation after error" helper that verifies terminate-vs-preserve
  semantics for a named function.

These helpers are not abstractions for style; they prevent false positives and
keep hardening tests provider-neutral.

## Verification Pass (2026-06-08)

An evidence-based review cross-checked the coverage claims in this note (and its
two companion docs) against the actual test bodies, not just commit subjects.
Result: the claims are overwhelmingly accurate — almost every "coverage added"
line maps to a real test with a genuine effect check (guard-byte sentinels,
`classify_*` helpers, subprocess isolation), confirmed by file:line. Four
initial "not found" flags were false alarms (DH truncation lives in
`test_dh_key_agreement.py`, the GCM ivGenerator guard in `test_mech_message.py`,
the null-arg encrypt/decrypt lifecycle in `test_operation_termination.py`, and
the unwrap `CKA_TOKEN` scalar in `ckr/test_ckr_wrap.py`).

The pass surfaced **one finding-hiding regression** and fixed it: the v3.2 KEM
*encapsulate* permission test used a catch-all `assert rv in (CKR_OK, ...)` and
only a size query, so a module ignoring `CKA_ENCAPSULATE=False` passed silently.
It now drives the full operation and classifies 3-way like the decapsulate test
(see the KEM permission note in *Access-Control And Object-Policy Gaps*). This is
the general lesson for any negative permission/length probe: drive the real
operation and classify by effect; never tolerate `CKR_OK` through a catch-all.

The genuinely outstanding work is narrow — see the revised backlog below.

## Stop Point And Continuation Backlog

Further provider-history investigation should stop here for now. The useful
commit-message signals from the current pass have already been reduced to
provider-neutral API bug classes. Continue by implementing tests from the list
below, not by repeating broad history searches. Reopen history only for a new
provider target, a new release with a relevant fix cluster, or a specific
unexplained crash/failure from the Docker matrix.

Current evidence scope:

- The review was intentionally optimized: exact local history searches for
  public PKCS#11 API names, `CKA_`/`CKM_`/`CKR_` identifiers, and
  buffer/length/null/overflow/crash terms. It was not a full diff audit.
- The findings were translated to API shapes only. This note should remain
  provider-neutral and should not grow provider names, external commit IDs, or
  issue references.
- Several exact-history classes are now covered by committed tests: mixed
  sensitive attribute filling, `C_SetAttributeValue` atomicity,
  unadvertised-but-standard mechanism info, operation-state cleanup after NULL
  data/output pointers, `CKA_WRAP_WITH_TRUSTED` transition rules,
  NULL-mechanism digest cancellation, valid empty key-generation templates,
  invalid derive base handles, AES-CBC encrypt-data nested parameters, and
  empty `CKA_ALLOWED_MECHANISMS` enforcement.
- A focused Docker run found a real provider-boundary finding for the AES-CBC
  encrypt-data huge nested length case: the child reaches the target
  `C_DeriveKey` call and exits before reporting a return value. That should
  remain a provider finding, not an xfail.

Add the following tests from existing information before doing more source
history review:

1. Extend nested mechanism-parameter length probes in
   `testcases/security/test_ffi_length_boundary.py` for RSA-PSS, RSA-OAEP,
   AES-GCM, AES-CCM, EdDSA, ECDH-AESKW, RSA-AES wrap, and v3.2 KEM/PQC
   mechanisms where a real setup key exists. Use child processes, tiny real
   buffers, and impossible claimed lengths.
2. Add more array-valued attribute checks in
   `testcases/ckr/test_ckr_object.py` and mechanism-specific CKR files:
   `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE`, and
   v3.2 KEM template arrays in create/copy/unwrap/derive paths. For accepted
   empty arrays, verify the effect instead of failing on `CKR_OK` alone.
3. Broaden scalar attribute length checks beyond the current object-class,
   key-type, token, AES value-length, and PQC parameter-set coverage. Priority
   attributes are operation permissions, sensitivity/extractability booleans,
   object-size-like integers, and mechanism-specific integer attributes in
   generate, unwrap, derive, and copy templates.
4. Add guard-byte checks for remaining output-buffer paths:
   `C_Sign`/`C_VerifyRecover`, `C_EncryptUpdate`/`C_DecryptUpdate`,
   `C_EncryptFinal`/`C_DecryptFinal`, `C_WrapKey`, and v3.0/v3.2 message or KEM
   output buffers. Keep size-query, undersized non-NULL, retry, and guard-byte
   assertions in the same test.
5. Add operation-state follow-up probes after cleanly rejected update/final
   calls. Each test must state whether the spec requires retry preservation or
   operation termination, then verify the next retry, finalizer, or fresh init.
6. Extend KDF output-effect checks: TLS key material returned buffers,
   PBKDF2/PBE boundary variants, returned additional-derived-key arrays, and
   exact derived output length for mechanisms beyond DH and HKDF.
7. Add access-control invariants not yet covered across all creation paths:
   `CKA_COPYABLE`, `CKA_DESTROYABLE`, `CKA_PRIVATE`, `CKA_EXTRACTABLE`,
   `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, and v3.2 KEM permissions.
   The test should fail only on self-contradiction after a claimed protection.
8. Add small non-default stress probes for session/search/lifetime races only
   after a bounded subprocess helper exists. Do not put broad soak tests in the
   default fast path.
9. Add destructive SO PIN and provider-state corruption harnesses only behind
   disposable-token metadata. These are not normal conformance tests and must
   never run against user-owned token stores.

Do not add at this stage:

- Provider allowlists, provider-specific xfails, or tests that hide crashes.
- More release-statistics documentation; this is not an official release
  results update.
- Another broad provider-history sweep without a new input signal.
- Tests that use invalid handles when the intended bug class is template,
  serializer, or output-buffer parsing on valid objects.

## Priority (revised 2026-06-08 after the verification pass)

**Done and verified — extend, do not re-add.** Shared child/guard/valid-handle
helpers; secret-key `CKA_VALUE_LEN`; valid-handle template-count overflow;
data-length truncation (update / verify / recover / message / random/seed);
AES-CBC-PAD decrypt buffer sizing + retry; scalar attribute length; array-pointer
validation; nested-template enforcement (wrap/unwrap/derive); generated-output
guard (GCM ivGenerator); operation-state cleanup after NULL args and
digest-init-NULL; ML-KEM derive-false; mechanism-list filtering; find-objects
NULL match-all; derive NULL base handle; misaligned-pointer probes;
wrong-key-type init + continuation; KDF/PBE/TLS/SP800-108 length probes; DH/HKDF
derive-length effect checks; v3.2 KEM encapsulate/decapsulate permission (policy,
encapsulate fixed this pass).

**Remaining, in priority order:**

1. Public-session (no-login) private-object **creation** rejection across direct
   create / unwrap / derive / copy / KEM paths. Self-contradiction = fail.
   (Visibility is already covered; creation is the gap.)
2. Sweep for other catch-all `assert rv in (...)` sites that tolerate `CKR_OK`
   on a negative op (the class the KEM encapsulate bug belonged to); convert each
   to 3-way effect-based classification.
3. Remaining nested mechanism-parameter length probes: RSA-PSS, RSA-OAEP,
   AES-GCM, AES-CCM, EdDSA — extend `test_ffi_length_boundary.py`.
4. Broaden scalar attribute length checks to operation-permission /
   sensitivity / extractability booleans and mechanism-specific integers in
   generate / unwrap / derive / copy templates.
5. More nested-template enforcement families (RSA/OAEP unwrap, ECDH/HKDF derive,
   v3.2 KEM templates) and constraints beyond `CKA_LABEL`.
6. Remaining guard-byte/retry coverage: `C_EncryptUpdate`/`C_DecryptUpdate` and
   recover outputs; operation-state terminate-vs-preserve for remaining
   update/final paths.
7. KDF output-effect breadth: TLS returned key-material buffers, PBKDF2
   iteration-count boundaries, returned additional-derived-key arrays, exact
   derived length beyond DH/HKDF.
8. Destructive token policy on disposable tokens: SO-PIN lockout via
   `C_InitToken`, plus PIN / SO-PIN / label / username length surfaces. New file
   `testcases/test_destructive_token_policy.py`.
9. Subprocess-isolated, bounded thread/lifetime race probes — the current
   `test_stress.py` probes run in-process; wrap them per the stress design rules.
   Non-default marker.
10. Optional provider-state fuzz harness, disposable-token-gated only.
11. Minor API edge cases: `C_WaitForSlotEvent` / `C_GetFunctionStatus` /
    `C_CancelFunction`; a systematic stale-handle probe across all operations.

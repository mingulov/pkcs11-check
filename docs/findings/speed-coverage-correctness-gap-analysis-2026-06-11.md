# Speed, Coverage, and Correctness Gap Analysis - 2026-06-11

This is an audit snapshot, not an official release-results update. Runtime
numbers are provider-local observations from the available `artifacts2/` and
`artifacts3/` directories. They must not be reused as cross-provider baselines.

## Evidence Snapshot

- Current branch during the audit: `dev` at `56e7a7a1`.
- Current `artifacts/` is empty. `artifacts2/` and `artifacts3/` each contain
  21 pooled provider results and 32 shard results.
- Product collection currently reports 254 test files and 110,060 collected
  test items.
- Source AST scan found 1,928 test functions and 698 test classes under
  `src/pkcs11_check/testcases`.
- Fixture usage is still heavily `p11_raw_session` oriented: 1,464 test
  functions take `p11_raw_session`; 269 take `p11_module_session`.
- `artifacts3/*-pooled/quality.json` reports `file_skipped_units=0` for every
  provider, even though the runner has static file-skip support.

## Artifact Comparison

`artifacts3` looks newer and materially better than `artifacts2` for failure
classification, but it is not a clean "everything got faster" proof. It still
contains pre-HKDF-isolation wolfPKCS11 long poles and provider-specific timing.

Notable outcome shifts from `artifacts2` to `artifacts3`:

- `bouncyhsm`: failed decreased by 6,065, xfailed increased by 7,254, crashed
  decreased by 1.
- `wolfpkcs11`: failed decreased by 2,192, crashed decreased by 3, but one
  timeout appeared and the HKDF file still took about 5,403s in this artifact.
- `corepkcs11` and `corepkcs11-main`: failed decreased by 22,614, with many
  outcomes moving to skipped or xfailed.
- `kryoptic`, `opencryptoki`, `softhsm2`, `nss`, and `tpm2` also show broad
  failure decreases, usually paired with more passes, skips, or xfails.

Interpretation: correctness classification and capability gating improved, but
the artifacts are still provider-specific and old enough that the just-merged
HKDF isolation work must be remeasured in a fresh pool.

## Speed Findings

### 1. Make duration-oracle input explicit

`docker/test_pool.py` currently reads prior durations only from
`artifacts/<provider>-pooled/results.json`. When `artifacts/` is deleted, a new
run falls back to synthetic-heavy scheduling even if valid provider-local
history exists in `artifacts2/` or `artifacts3/`.

Next task:

- Add an explicit option such as `--duration-artifacts-dir artifacts3`.
- Read only `<root>/<provider>-pooled/results.json` for that same provider.
- If a provider has no matching result in that root, fall back to synthetic
  planning for that provider only.

Acceptance checks:

- A dry-run with an empty `artifacts/` and `--duration-artifacts-dir artifacts3`
  prints `duration-oracle` for providers with matching results.
- No provider ever borrows another provider's durations.
- Tests cover a missing-provider fallback and a malformed/empty results file.

Status: fixed in the current branch. `docker/test_pool.py` now accepts
`--duration-artifacts-dir`, resolves it relative to the project root when
needed, and reads only `<root>/<provider>-pooled/results.json` for the same
provider. Focused tests cover provider-local dry-run planning, missing-provider
fallback, and empty/malformed history.

### 2. Verify static file-skip actually triggers in pooled runs

The runner has static skip logic through `extract_required_mechanisms`, but
`artifacts3` shows zero file-skipped units everywhere. This matters because
wolfPKCS11 spent roughly 965-1,001s on `test_cctv_ed25519.py` and 457-514s on
`test_cctv_mldsa.py` in `artifacts3`; for unsupported mechanisms these should
be file-level skips, not per-vector setup churn.

Next task:

- Audit high-count vector files for `REQUIRED_MECHANISMS`.
- Confirm `file_skipped_units` increments in isolated and pooled artifacts.
- Add a test that a missing required mechanism produces a file-skip record
  before pytest collection/execution of that file.

Status: fixed in the current branch. High-count vector files now declare
`REQUIRED_MECHANISMS`; isolated execution short-circuits files before pytest
collection when required mechanisms are absent; `results.json`,
`quality.json`, `report.jsonl`, and shard merge preserve `file_skip`
accounting. Focused tests cover missing required mechanisms,
any-missing-required-mechanism behavior, and merged accounting.

### 3. Guard subprocess-per-test expansion for crash-prone files

`artifacts3` still has `wycheproof/test_wycheproof_hkdf.py` at about 5,403s on
both wolf providers. Current source collects HKDF cases as `subprocess_per_test`,
and the branch already merged an HKDF split, but the old artifact proves the
pool needs a guard against silently running a marked file as a whole-file unit.

Next task:

- Add an artifact/runtime assertion that a file marked for subprocess-per-test
  expands to node-level units.
- Bound file-level timeout damage when collection metadata is available.
- Re-run at least wolfPKCS11 HKDF to prove the old 90-minute file unit is gone.

Status: fixed in the current branch. Auto-isolation expands
`subprocess_per_test` files to node-level units, resume rejects unexpanded
subprocess-per-test state, and focused tests cover the guard. wolfPKCS11 HKDF
remeasurement evidence now exists in the current local artifacts:
`artifacts/wolfpkcs11-pooled/results.json` and
`artifacts/wolfpkcs11-master-pooled/results.json` show
`wycheproof/test_wycheproof_hkdf.py` at roughly 241-252s, so the old roughly
5,403s file-level long pole is gone. The current HKDF units still record
provider crashes, which remain findings rather than skips or xfails.

### 4. Split or optimize bouncyhsm MCT long poles carefully

In `artifacts3`, bouncyhsm is call-bound, not setup-bound. Top file durations:

- `acvp/aes/test_ofb.py`: about 1,050s.
- `acvp/aes/test_cfb8.py`: about 1,042s.
- `acvp/aes/test_cfb128.py`: about 1,033s.
- `acvp/aes/test_ccm.py`: about 379s.

Next task:

- Spike node-level sharding for independent MCT cases, or multipart
  `C_EncryptUpdate` acceleration where the algorithm semantics are identical.
- If using multipart update, include a fallback to the existing
  `C_EncryptInit`/`C_Encrypt` path when update is missing or rejected cleanly
  (`CKR_FUNCTION_NOT_SUPPORTED`, operation-state errors, or mechanism-specific
  clean rejection).
- Keep canonical full-path tests so faster code does not reduce coverage.

Acceptance checks:

- Output equivalence against existing vectors is proven for each changed MCT
  mode.
- Fallback behavior is tested with a fake provider path that rejects update.
- bouncyhsm runtime is remeasured provider-locally; the result is not applied
  to other providers.

Current status:

- Implemented: provider-local duration-oracle data can split only duration-hot
  MCT files (`test_ofb.py`, `test_cfb8.py`, `test_cfb128.py`) into collected
  pytest node ids, so non-MCT files stay at file-shard granularity.
- Implemented: CFB/OFB MCT runners try one `C_EncryptInit`/`C_DecryptInit`
  plus repeated `C_EncryptUpdate`/`C_DecryptUpdate` calls, then fall back to the
  canonical per-iteration single-part path if multipart update/final is missing,
  operation-state-invalid, or cleanly rejected by the provider.
- Verified by focused tests: multipart fast path, fallback path, and official
  vector equivalence are covered in `tests/test_acvp_aes_runtime_classification.py`;
  duration-hot node expansion and caller environment propagation are covered in
  `tests/test_docker_pool.py`.
- Fresh bouncyhsm provider-local pool evidence exists. The current
  `artifacts/bouncyhsm-pooled/results.json` was produced from the preserved
  provider-local baseline under
  `/tmp/pkcs11-check-bouncyhsm-baseline-20260612080232`; `pkcs11-check
  compare-coverage ... --fail-on-loss` reports `No mechanism coverage state
  loss`. The former file-level MCT long poles are split into 13 emitted units
  each for `test_ofb.py`, `test_cfb8.py`, and `test_cfb128.py`, with the
  largest emitted MCT unit at about 334s instead of the prior roughly
  1,100s-per-file shape.

### 5. Reduce remaining setup cost for module-session vector files

wolfPKCS11 remains setup-bound in `artifacts3`. The worst setup-heavy files are
X.509 limbo stress/import and CCTV vector files. These already use
`p11_module_session` patterns in the recent speed work, so the next suspect is
the per-handout health check in `ReusableSessionManager.get_session`.

Next task:

- Measure health-check time separately from call time on wolfPKCS11.
- Consider a vector-file-only mode that checks health on open, on explicit
  reopen request, and after failures, while preserving fresh sessions for
  destructive, lifecycle, PIN, and state-machine tests.

Acceptance checks:

- A targeted wolfPKCS11 X.509/CCTV run shows lower setup time.
- Tests prove a damaged reusable session still reopens before reuse.

Current status:

- Implemented: reusable module-session health checks are timed separately from
  ordinary test-body C_* calls and exported under
  `function_coverage.module_session_health`.
- Implemented: high-count vector files that have independent per-item state use
  `pytest.mark.module_session_fast`, which skips steady-state health checks but
  still forces a health check after a failed fast-session call.
- Verified by focused tests: fixture behavior, forced health checks after
  failures, health-metric accumulation, JSONL aggregation, and fast-marker
  metadata are covered.
- Focused wolfPKCS11 X.509/CCTV evidence now exists in
  `artifacts/_focused/wolfpkcs11-health-current/results.json`: X.509 limbo
  import passed 663 tests in 2.809s, X.509 limbo stress passed 1009 tests in
  3.166s, CCTV Ed25519 file-skipped 914 tests, CCTV ML-DSA file-skipped 449
  tests, and the merged function coverage records
  `module_session_health: {"checks": 0, "duration_s": 0.0}` for the fast-marked
  run. This is the provider-local comparison point against the original
  setup-dominated wolfPKCS11 master measurements in
  `docs/superpowers/specs/2026-06-11-pkcs11-session-reuse-speed-design.md`
  (857s/424s CCTV setup and 548s/842s X.509 setup).

### 6. Continue artifact I/O and data-loader slimming

The artifact directories are large, and pooled `report.jsonl` files can be
hundreds of MB. Streaming merge helpers exist, but some paths still retain full
record lists. There are also remaining direct `json.load()` sites in vector
loaders despite the cached loader.

Next task:

- Move coverage, quality, and trace promotion toward single-pass processing.
- Convert safe vector loaders to `load_json_cached()`.
- Mount or prewarm the cache for Docker runs where the cache key is based on
  file identity, mtime, size, and interpreter, never on provider outcomes.

Current status:

- Implemented: normal Docker provider containers now mount a shared named
  `pkcs11-check-cache` volume at `/cache`, and `docker/run-pkcs11-check.sh`
  defaults `XDG_CACHE_HOME=/cache`. This lets the content-addressed collection
  metadata cache and vector marshal cache survive across pool shards without
  using provider outcome data.
- Verified by focused tests: Docker target guardrails assert the cache volume
  and runner environment are wired. Existing vector-loader guardrails already
  require product vector loaders to use `load_json_cached()` except subprocess
  coverage helpers that read temporary coverage JSON rather than vector data.
- Implemented: timeout/crash retry aggregation now streams source
  `report.jsonl` fragments directly into the per-unit report-record cache
  instead of building one parsed record list solely for cache output.
- Implemented: final isolated-run report generation now streams per-unit
  report-record cache shards when rebuilding merged `report.jsonl` and per-unit
  details, instead of loading the whole cached record map.
- Implemented: the complete/partial resume fallback now seeds missing per-unit
  report-record cache shards by streaming an existing merged `report.jsonl`,
  instead of splitting the whole merged report into an in-memory per-unit map.

## Coverage Findings

The registry is broad, but registry membership is not the same as semantic
coverage. Several mechanisms are either explicitly skipped, routed to generic
smoke behavior, or covered only by one narrow variation.

### Highest-value missing or shallow coverage

1. Dedicated protocol KDF semantic coverage exists outside the generic
   `test_mech_derive.py` dispatch path. The generic parametrized derive test
   still skips protocol KDFs because their parameter structures are
   mechanism-specific, but SP800-108 counter KDF has exact HMAC-SHA256 output
   checks, TLS 1.2 KDF has exact PRF output checks, and PBKDF2 has Wycheproof
   exact-output coverage. SSL3, WTLS, IKE, X3DH, and X2RATCHET also have
   dedicated operational probes. Remaining shallow protocol-KDF work is
   exact-vector expansion and richer negative/tamper coverage for those
   dedicated files, not basic runtime dispatch for the already-covered priority
   mechanisms. WTLS PRF seed-sensitivity coverage now verifies that changing
   the explicit `CK_WTLS_PRF_PARAMS.pSeed` input changes the derived output.
   WTLS PRF label-sensitivity coverage now verifies the same for
   `CK_WTLS_PRF_PARAMS.pLabel`. WTLS PRF raw output-buffer coverage now uses
   the OASIS `CKM_WTLS_PRF` convention: `C_DeriveKey` is called with a NULL
   template and NULL `phKey`, and the test reads the bytes returned through
   `CK_WTLS_PRF_PARAMS.pOutput`. IKE2 PRF+ base-key sensitivity coverage now
   verifies that changing the shared-secret input changes the derived output.
   IKE2 PRF+ HMAC-SHA256 exact-vector coverage now uses typed
   `CK_IKE2_PRF_PLUS_DERIVE_PARAMS` and checks the OASIS `prf+(baseKey,
   seedData)` recurrence.
   IKE PRF base-key sensitivity coverage now verifies the same for
   `CKM_IKE_PRF_DERIVE`. IKE PRF data-as-key HMAC-SHA256 exact-vector coverage
   now uses typed `CK_IKE_PRF_DERIVE_PARAMS` and checks the OASIS case-1
   `prf(Ni|Nr, baseKey)` output.
2. Regional cipher encrypt-data derive dispatch exists for Camellia, ARIA, and
   SEED ECB/CBC variants in `test_mech_derive.py`; focused meta-tests verify
   the family-specific CBC parameter structs are packed for generic derive
   dispatch. Remaining derive work is protocol KDF exact-vector expansion and
   any families whose PKCS#11 parameter semantics are still source-first.
3. Dedicated DSA/DH/X9.42 domain-parameter coverage exists in
   `test_dsa_complete.py`, `test_dh_key_agreement.py`, and `test_x942_dh.py`.
   The generic registry-driven keygen path still skips `dsa` and `dh` recipe
   styles because their parameter objects are mechanism-specific, but this is
   not the same as missing product coverage. Remaining work is broader
   exact-vector, negative, and provider-artifact evidence. DSA probabilistic/Shawe-Taylor/FIPS-G parameter variants
   are now covered in `test_dsa_complete.py` for the
   OASIS-defined p/q and g-generation outputs. Raw CKM_DSA wrong-length digest acceptance
   is now a hard failure via the shared negative classifier; the spec-correct
   rejection remains `CKR_DATA_LEN_RANGE`, and other clean rejects are recorded
   as xfail deviations. DSA prehash runtime-reject classification now uses the
   shared signature policy: advertised positive sign/verify refusals are xfail
   deviations, while tampered-data/signature tests treat clean signature
   rejection as the intended negative outcome. DSA_SHA224 now participates in
   the complete generated-key prehash roundtrip, tampered-data,
   tampered-signature, empty-data, and large-data matrix. Raw CKM_DSA
   wrong-signature-length coverage now verifies verification rejects a
   truncated signature through the shared invalid-signature policy. Classic DH
   RFC 3526 Group 14 exact-vector coverage now imports a fixed private value,
   derives with a fixed peer public value, and checks the exact derived
   generic-secret bytes. Classic DH derive runtime-reject classification now
   uses a shared wrapper for positive
   `CKM_DH_PKCS_DERIVE` operations:
   advertised clean derive refusals are provider-general xfail deviations,
   while successful derives still verify exact shared-secret and
   encryption/readback effects. Classic DH missing-peer-public negative
   coverage now verifies `CKM_DH_PKCS_DERIVE` rejects a missing peer public
   mechanism parameter through the shared negative classifier. Classic DH
   malformed-peer-public negative coverage now verifies the same derive path
   rejects a one-byte peer public value with domain/mechanism-parameter
   classification. X9.42 DH
   RFC 5114 exact-vector coverage now imports a fixed private value, derives
   with a fixed peer public value, and checks the exact derived generic-secret
   bytes. X9.42 DH missing-peer-public negative coverage now verifies
   `CKM_X9_42_DH_DERIVE` rejects a missing DH1 derive parameter struct through
   the same classifier. X9.42 DH malformed-peer-public negative coverage now
   verifies typed `CK_X9_42_DH1_DERIVE_PARAMS` carrying a one-byte public value
   is rejected through the same provider-general negative model. X9.42 DH
   CKD_NULL OtherInfo negative coverage now verifies the OASIS rule that
   `pOtherInfo` must be NULL and `ulOtherInfoLen` must be zero when the KDF is
   `CKD_NULL`.
4. Message API registry-driven init coverage exists for advertised
   `CKF_MESSAGE_*` flags through `TestRegistryMessageInit` and pytest plugin
   fixtures for message encrypt, decrypt, sign, and verify entries. Richer
   full-message semantic coverage is still representative for selected
   AES-GCM, AES-CCM, and AES-GMAC paths rather than exhaustive across every
   mechanism that advertises a message flag. Registry-driven message API
   permission negative coverage exists for `C_MessageEncryptInit`,
   `C_MessageDecryptInit`, `C_MessageSignInit`, and `C_MessageVerifyInit` on
   secret-key mechanisms that advertise the corresponding message flags.
   Registry-driven message API required-parameter coverage exists for
   `C_MessageEncryptInit`, `C_MessageDecryptInit`, `C_MessageSignInit`, and
   `C_MessageVerifyInit` on mechanisms that advertise the corresponding
   message flag and require mechanism parameters, including both missing
   parameters and malformed non-NULL one-byte parameter payloads.
5. Hybrid wrap parameter coverage exists for RSA-AES and ECDH-AES:
   `test_rsa_extended.py` covers `CK_RSA_AES_KEY_WRAP_PARAMS` positive
   roundtrips plus tampered-blob discrimination, and
   `test_authenticated_wrap.py` covers the `CK_ECDH_AES_KEY_WRAP_PARAMS`
   family (`CKM_ECDH_AES_KEY_WRAP`, `CKM_ECDH_COF_AES_KEY_WRAP`, and
   `CKM_ECDH_X_AES_KEY_WRAP`) with roundtrip and bit-flip integrity checks.
   AES-CTR wrap params are now covered by `test_mech_wrap.py`, which builds
   `CK_AES_CTR_PARAMS` through the shared `ctr` registry recipe and an
   explicit fallback for bare AES-CTR entries. AES-GCM and AES-CCM wrap params
   are now covered by `test_mech_wrap.py` using `CK_GCM_WRAP_PARAMS` and
   `CK_CCM_WRAP_PARAMS`. ChaCha20-Poly1305 generic wrap remains source-first:
   the registry expects only encrypt/decrypt flags for
   `CKM_CHACHA20_POLY1305`, and the local OASIS text classifies it as
   authenticated encryption/decryption using Encrypt, Decrypt, MessageEncrypt,
   and MessageDecrypt APIs rather than a generic `C_WrapKey` mechanism. Keep
   the explicit generic-wrap skip for anomalous providers that advertise
   `CKF_WRAP` until a defensible wrap/unwrap mapping exists.
6. BLAKE2B keyed coverage exists for HMAC, HMAC_GENERAL truncation, KEY_GEN,
   and KEY_DERIVE across 160/256/384/512-bit variants, with Python reference
   checks plus key-type and extracted-value assertions. BLAKE2B invalid-length
   HMAC_GENERAL parameter coverage now rejects zero-length and one-byte-too-long
   MAC requests against the OASIS 1..digest-length rule.
   BLAKE2B HMAC_GENERAL boundary-length coverage now checks the minimum valid
   one-byte MAC and the maximum digest-length MAC for every BLAKE2B keyed
   size. BLAKE2B HMAC_GENERAL tampered-MAC coverage now verifies truncated
   MAC verification rejects modified output bytes. BLAKE2B HMAC_GENERAL
   wrong-length MAC coverage now verifies that verification rejects extended
   and truncated MAC byte strings for the requested general-MAC length.
   Remaining BLAKE2B work is broader negative parameter/regression expansion
   and provider-artifact evidence, not basic keyed semantic coverage.
7. SHAKE/XOF dedicated coverage exists: raw `C_DigestXof*` function
   signatures are wired, and `test_extended_mechanisms.py` verifies both
   single-shot and multipart SHAKE-128/SHAKE-256 XOF output against Python
   `hashlib` references. ACVP SHAKE vector replay now loads the NIST
   `SHAKE-128-1.0` and `SHAKE-256-1.0` XOF vectors and runs them through
   `C_DigestXof` instead of the old unconditional skip. ML-DSA ExternalMu
   sign/verify coverage exists for a 64-byte `mu` value and rejects tampered
   `mu` input. KMAC parameter packing coverage exists through `CK_KMAC_PARAMS`
   and `mech_kmac`, and the KMAC sign/verify roundtrip stubs now build
   parameterized operations instead of skipping because the raw binding is
   missing. Remaining adjacent work is KMAC parameterized signing against
   providers with stable mechanism IDs plus deeper ML-DSA ExternalMuGen/PQC
   provider evidence, not basic SHAKE/XOF raw API coverage.
8. Legacy cipher coverage is now mixed rather than mostly generic: RC2, RC4,
   RC5, CAST/CAST3/CAST128/CAST5, IDEA, Blowfish, and Twofish have KAT-backed
   encrypt coverage where the PKCS#11 mechanism shape is reliable. RC2, RC5,
   CAST/CAST3/CAST128/CAST5, IDEA, Blowfish, and Twofish also have CBC_PAD exact-output
   vectors for padding behavior, with non-block-aligned plaintext covered where
   a reliable source exists. CKM_GOST28147 IV-parameter registry coverage
   now lets generic mechanism tests build the OASIS 8-byte IV parameter for
   advertised GOST 28147-89 non-ECB operations.
   `CKM_GOST28147_KEY_WRAP` now has an RFC 7836 TC26 param-Z exact-output KAT:
   the test uses the RFC-derived KEK directly, the RFC seed as the PKCS#11
   MAC-IV mechanism parameter, and checks the OASIS-defined `CEK_ENC || CEK_MAC`
   wrapped-key output.
   `CKM_GOST28147_ECB` now has an RFC 8891 Magma exact-output KAT with the
   same TC26 param-Z OID attached through `CKA_GOST28147_PARAMS`.
   `CKM_GOST28147_MAC` now has an RFC 7836 exact-output KAT for the
   TC26 param-Z `CEK_MAC` value, using the RFC seed as the OASIS MAC-IV
   mechanism parameter.
   SKIPJACK ECB64 exact-output KATs are covered from NIST SP 800-17.
   SKIPJACK CBC64/OFB64/CFB64 are deliberately back in source-first status:
   NIST SP 800-17 provides useful 64-bit mode algorithm vectors, but OASIS
   PKCS#11 historical mechanism text describes token-controlled 24-byte
   SKIPJACK IV parameters, so those vectors are not safe as deterministic
   PKCS#11 `C_Encrypt` KATs without a reconciled mechanism mapping.
   Remaining shallow areas are
   SKIPJACK IV modes, short-segment CFB, and wrap variants,
   BATON/JUNIPER, GOST28147
   non-ECB exact-output KATs, and the fixed-output MAC/MAC_GENERAL KATs where a
   block-vector source and output length mapping are still missing. GOST28147
   non-ECB exact-output KATs remain source-first until the vector source and
   parameter-set mapping are unambiguous.
   Older PBE variants now have semantic `C_GenerateKey` coverage for key type
   and IV writeback where `CK_PBE_PARAMS` applies, but not independent
   fixed-output KAT vectors. MAC_GENERAL mechanisms now assert the returned MAC
   length matches the requested parameter length, and RC2, RC5, CAST, CAST3,
   CAST128, IDEA, DES, 3DES, Camellia, ARIA, and SEED have expected-MAC
   vectors. DES, 3DES,
   Camellia, ARIA, and SEED fixed-output MAC KATs now cover the spec-defined
   half-block special case. RC2, RC5, CAST/CAST3/CAST128/CAST5, and IDEA
   fixed-output MAC KATs now do the same for the legacy 8-byte-block families
   with existing reliable full-block sources. DES3 CMAC/CMAC_GENERAL now have full-block CMAC
   KATs grounded in NIST SP 800-38B semantics and the local OASIS DES3-CMAC
   mapping. Continue this sweep for less-sourced legacy families, but gate
   each new vector on a reliable source and an unambiguous PKCS#11
   parameter mapping; SKIPJACK short-segment CFB/wrap variants and KEA are
   lower confidence until a defensible vector/operation source is identified.
9. CMS runtime parameter coverage exists for `CKM_CMS_SIG`: the test builds
   `CK_CMS_SIG_PARAMS` and reaches `C_Sign` with that parameter struct rather
   than stopping at mechanism-info or clean-reject checks. CT-KIP runtime
   coverage exists for `CKM_KIP_DERIVE`, `CKM_KIP_WRAP`, and `CKM_KIP_MAC`:
   the tests build `CK_KIP_PARAMS` and exercise derive, wrap, and sign/verify
   paths with generated keys. Remaining CMS/CT-KIP work is exact-output,
   interoperability, negative-parameter expansion, and provider-artifact
   evidence.
10. Generic negative coverage is improving but still incomplete relative to
    467 registry mechanisms. Registry-driven wrong-key-type coverage now
    includes encrypt, decrypt, sign, and verify operation families.
    Registry-driven decrypt/verify negative coverage exists for both
    wrong-key-type and missing-permission cases, alongside the existing
    encrypt/sign permission coverage. Registry-driven wrap/unwrap
    missing-permission coverage exists for advertised wrap-roundtrip
    mechanisms. Registry-driven derive missing-permission coverage exists for
    simple key-object derivation shapes: SHA key derivation, concatenate/XOR/
    extract, concatenate-key, and AES-ECB encrypt-data. Registry-driven
    missing-required-parameter coverage exists for advertised encrypt/decrypt,
    sign/verify, and digest mechanisms whose registry config requires a
    mechanism parameter. Registry-driven decrypt/verify required-parameter
    coverage exists for the second half of those operation pairs, using the
    same provider-general missing and malformed parameter classifiers.
    Registry-driven digest required-parameter coverage exists for
    `C_DigestInit`, including both missing and malformed non-NULL parameter
    shapes. Derived
    linked-attribute invariant coverage exists for
    `CKA_NEVER_EXTRACTABLE`/`CKA_EXTRACTABLE` and
    `CKA_ALWAYS_SENSITIVE`/`CKA_SENSITIVE` on suite-generated, never-modified
    keys, with Type-D self-contradictions classified as failures and honest
    non-support as xfail. Generated-key origin linked-attribute coverage exists
    for `CKA_LOCAL`/`CKA_KEY_GEN_MECHANISM` on AES keys generated by
    `CKM_AES_KEY_GEN`; isolated `CKA_LOCAL=False` remains xfail per the
    classification model, while a local generated key reporting the wrong
    generation mechanism fails as a linked-origin self-contradiction.
    Imported-key origin linked-attribute coverage exists for AES keys imported
    by `C_CreateObject`; an imported key with `CKA_LOCAL=False` must not expose
    a readable `CKA_KEY_GEN_MECHANISM`, and doing so fails as the opposite
    linked-origin self-contradiction. Honest non-support of either origin
    attribute remains xfail.
    Registry-driven malformed non-NULL parameter coverage exists for advertised
    encrypt/decrypt, sign/verify, and digest mechanisms whose registry config
    requires a mechanism parameter, using a valid non-NULL pointer with an
    invalid one-byte parameter length. Registry-driven derive
    malformed-parameter coverage exists for the simple key-object derivation
    shapes already supported by the generic negative helper, using the same
    invalid one-byte mechanism parameter shape. Remaining work is further
    linked-attribute
    families beyond derived protection and generated/imported-key origin,
    malformed parameter expansion beyond current classic/message init and simple
    derive coverage, and deeper derive/wrap/digest/message semantic negative
    coverage for protocol/asymmetric/custom-parameter families.
    Registry-driven unwrap malformed-blob coverage exists for advertised
    secret-key wrap mechanisms: the test wraps a key, truncates the resulting
    wrapped-key bytes, and classifies wrapped/encrypted-data invalid or
    length-range rejects as spec-correct. Registry-driven unwrap empty-blob
    coverage exists for the same advertised unwrap mechanisms and verifies that
    `C_UnwrapKey` rejects a zero-length wrapped-key input instead of accepting
    a forged secret key object. Registry-driven unwrap one-byte-blob coverage
    exists for the same path and verifies that a one-byte wrapped-key input is
    also rejected as malformed.

### Recommended coverage order

1. Expand DSA/DH/X9.42 coverage beyond the existing dedicated generated-parameter
   tests: exact-vector checks where practical and richer negative cases.
2. Protocol KDF expansion beyond the already-covered priority set
   (`CKM_SP800_108_COUNTER_KDF`, `CKM_TLS12_KDF`, and `CKM_PKCS5_PBKD2`):
   add exact external vectors and tamper/negative checks for SSL3, WTLS, IKE,
   X3DH, and X2RATCHET where the mechanism semantics allow it.
3. BLAKE2B keyed negative/parameter edge cases, now that HMAC, HMAC_GENERAL,
   KEY_GEN, and KEY_DERIVE positive semantics are covered.
4. No remaining generic AEAD wrap parameter gap: ChaCha20-Poly1305 stays
   source-first for wrap/unwrap unless a spec-backed `C_WrapKey` mapping appears.
5. Continue registry-driven negative tests for broader linked-attribute families
   beyond the current derived-protection and generated/imported-key-origin
   invariants,
   malformed parameter cases beyond current classic/message init and simple derive
   coverage, deeper derive custom-parameter cases, and additional unwrap
   tamper/shape variants beyond the current empty/one-byte/truncated-blob
   coverage.

## Correctness and Reporting Findings

### 1. Unknown non-CKR values can become xfail

`classify_negative_rv()` and `reject_or_classify()` xfail unexpected clean
return values. A direct probe shows both `0x7fffffff` and `0xdeadbeef` become
xfails when `CKR_ARGUMENTS_BAD` was expected.

Next task:

- Add a shared predicate for "known clean CKR" versus undefined values.
- Treat undefined values below `CKR_VENDOR_DEFINED` as failures.
- Decide and test vendor-defined CKR handling explicitly, likely as a distinct
  vendor-defined xfail/note rather than the same bucket as official CKRs.

Status: fixed in the current branch. The shared raw-RV helpers distinguish
standard CKRs, undefined non-vendor values, and vendor-defined values.
Undefined non-vendor values fail; vendor-defined values xfail with a distinct
message. Focused tests cover both raw-rv and exception-shaped classifiers.

### 2. Compliance notes are process-local and may vanish from artifacts

`compliance.note()` appends to a process-global list. The plugin clears notes
after each testcase item, and the compliance report reads the current process
list. I did not find an artifact serialization path that carries notes from
isolated test subprocesses into final merged reports.

Next task:

- Attach compliance notes to pytest item/report metadata before clearing.
- Carry notes through `report.jsonl`, `results.json`, and pooled merge.
- Add an end-to-end isolated-run test proving a note emitted in a testcase
  appears in final artifacts.

Status: fixed in the current branch. The pytest plugin attaches serialized
notes to call-phase report `user_properties` before teardown clears the
process-local collector. The isolated runner promotes those notes into
`results.json`; compliance report generation reloads notes from both
`results.json` and `report.jsonl`; shard merge preserves them. An end-to-end
isolated subprocess regression now proves a testcase-emitted note survives into
both the final `results.json` unit and the merged `report.jsonl`.

### 3. Compliance report coverage can overstate execution

`compliance_report.py` counts CKR spec entries statically and parses only
passed/failed/skipped buckets in several paths. It also maps functions by
filename keyword rather than observed C_* calls.

Next task:

- Include xfail, crash, timeout, and error outcomes in report classification.
- Prefer observed `coverage.json` and/or `report.jsonl` data over filename
  heuristics for execution coverage.
- Add regression tests where skipped/crashed/xfail tests cannot produce a
  misleading full-coverage PASS.

Status: fixed in the current branch. Compliance report outcome classification
now carries xfail, xpass, error, crash, and timeout buckets with timeout/crash
precedence over ordinary failures; observed `coverage.json` or sibling
`report.jsonl` traces prevent filename heuristics from manufacturing function
coverage; CKR coverage counts only executed CKR spec files, not unrelated or
all-skipped files. Focused tests cover xfail, crash, timeout, observed
coverage, and skipped-only CKR cases.

### 4. Mixed fail+crash units surface crash status

Earlier `_overall_unit_status()` behavior could let a mixed failed+crashed file
look like an ordinary failed unit to consumers that scan only unit status.

Completed task:

- Give crash/timeout precedence over ordinary failure in unit status.
- Keep ordinary failed counts in the same unit details.
- Add a unit test for mixed failed plus crashed file results.

Status: fixed in the current branch. `_overall_unit_status()` gives timeout
and crash precedence over ordinary failure while preserving failed counts in the
unit details. Merged per-test detail counts also promote the emitted unit status
when a crash or timeout is discovered during retry/confirmation rather than
represented as the final file process status. Regression tests cover both a file
with one failed test and one crashed test, and a failed file result whose merged
detail contains crash/timeout evidence: the emitted artifact unit surfaces the
special status, and the failed plus special counters survive.

### 5. Mechanism coverage telemetry needs more states

Current coverage data can show mechanisms as invoked even when they were only
attempted or selected, and some providers show more invoked mechanisms than
advertised available mechanisms. That makes it harder to prove a speed change
preserved meaningful coverage.

Next task:

- Split telemetry into advertised, selected, attempted, accepted/operational,
  rejected cleanly, skipped-by-capability, and crashed/timeout buckets.
- Use this to detect shallow registry-only coverage and speed-induced coverage
  loss.

Status: improved in the current branch. Coverage reports and JSONL merge now
preserve advertised, selected, attempted, accepted, rejected-cleanly,
skipped-by-capability, crash, and timeout buckets, and `quality.json`
mechanism findings surface those states instead of collapsing every mechanism
into old invoked/not-invoked status. The pure
`compare_mechanism_coverage_states()` helper can compare provider-local
baseline/candidate coverage buckets and flag lost mechanisms by state, and
`pkcs11-check compare-coverage ... --fail-on-loss` exposes it as a CI-friendly
gate. Docker pool runs can now take `--coverage-baseline-artifacts-dir` to
compare each just-merged `<provider>-pooled` artifact against the same
provider's baseline and fail the pool on lost mechanism states.

### 6. Controlled child subprocess crash/timeout stats

Crash-safe child probes intentionally report provider crashes and child
timeouts as failed tests, not as isolated-runner `crashed`/`timeout` units. That
classification is correct, but the pool headline table previously hid the
distinction inside the broad `failed` count.

Status: fixed in the current branch. `docker/test_pool.py` keeps the original
`failed`, `crashed`, and `timeout` counts intact, and adds `child_crash` and
`child_timeout` columns by scanning failed test longreprs for controlled
subprocess crash/timeout markers. Focused tests prove controlled child findings
are surfaced separately without double-counting unit-level crash records.

## Recommended Next Round

The next implementation round should be harness-first, because it makes every
later provider run more interpretable:

1. Continue targeted provider-speed work using provider-local
   `--duration-artifacts-dir` plus `--coverage-baseline-artifacts-dir` so speed
   changes prove coverage preservation.
2. Continue legacy/deprecated mechanism coverage where reliable vectors and
   PKCS#11 parameter mappings exist. Treat this as a registry-to-test gap
   sweep, not just another RC5/IDEA pass: RC5 and IDEA encrypt KATs are already
   present, and RC5 CBC_PAD is now covered from RFC 2040. Their next useful
   work is independent fixed-length MAC expected-output vectors, if the PKCS#11
   truncation/output-length rule is sourced clearly. SKIPJACK ECB64 now has
   NIST SP 800-17 exact-output KATs; the IV modes, short-segment CFB, wrap
   variants, and KEA remain lower-priority because their PKCS#11 vector and
   operation mappings are less straightforward.
3. Continue broader semantic coverage expansion once artifact semantics can prove
   coverage preservation.

After that, do the first coverage expansion round:

1. DSA/DH/X9.42 exact-vector, negative, and parameter-variant expansion beyond
   the existing dedicated generated-parameter coverage.
2. Protocol KDF exact-vector expansion beyond already-covered SP800-108
   counter KDF, TLS 1.2 KDF, and PBKDF2.
3. BLAKE2B keyed negative/parameter edge cases.
4. ChaCha20-Poly1305 wrap/unwrap only if a spec-backed `C_WrapKey` mapping is
   identified; otherwise keep it source-first and limited to encrypt/decrypt
   semantics.
5. Registry-driven wrong-key/permission negatives.
6. Legacy/deprecated mechanisms not yet covered by reliable KATs or semantic
   probes: remaining SKIPJACK short-segment CFB and wrap variants only with
   trustworthy operation-specific vectors and reconciled PKCS#11 parameters,
   KEA only with defensible domain-parameter/derive semantics, plus
   BATON/JUNIPER and GOST28147 exact-output KATs, and remaining MAC_GENERAL or
   fixed-output vectors where reliable sources exist.

Legacy/deprecated coverage addendum for the active goal:

- Inventory every legacy/deprecated registry entry against product tests and
  mechanism-vector files before adding the next family.
- Add only provider-general tests: skip when a mechanism is genuinely absent,
  xfail clean advertised-but-not-operational refusals, and fail wrong outputs,
  self-contradictions, crashes, or hangs.
- Prefer reliable, externally traceable vectors. RC5 and IDEA encrypt vectors
  are already covered; RC5 CBC_PAD is now covered directly from RFC 2040.
  Continue with fixed-length MAC and remaining CBC_PAD gaps only when the source
  and PKCS#11 mapping are unambiguous. SKIPJACK ECB64 now has source-backed
  KATs. SKIPJACK CBC64/OFB64/CFB64, CFB32/CFB16/CFB8, and wrap/private-wrap/
  RELAYX variants remain source-first because the historical vector and
  PKCS#11 operation mappings must be reconciled with the current registry
  recipes before adding exact-output KATs. KEA remains a source-first candidate
  because its vector and operation mapping is less straightforward.
  `CKM_GOST28147_KEY_WRAP` now has an RFC 7836 TC26 param-Z
  exact-output KAT mapped through the OASIS PKCS#11 key-wrap semantics, and
  `CKM_GOST28147_ECB` now has an RFC 8891 Magma TC26 param-Z exact-output KAT;
  `CKM_GOST28147_MAC` now has an RFC 7836 TC26 param-Z `CEK_MAC` KAT;
  GOST28147 non-ECB remains source-first. Also evaluate CAST/CAST3,
  BATON/JUNIPER, GOST28147,
  `CKM_KEY_WRAP_LYNKS`, `CKM_KEY_WRAP_SET_OAEP`, `CKM_FASTHASH`,
  old PBE fixed-output cases, and other deprecated mechanisms that a PKCS#11
  provider might still advertise. Treat the named families as starting points;
  the coverage round should account for every uncovered legacy/deprecated
  registry entry that can be tested with provider-general semantics.
- Current source-first operation inventory after the latest vector sweep:

  | Family | Operation mechanisms still without source-backed exact vectors |
  | --- | --- |
  | SKIPJACK | `CKM_SKIPJACK_CBC64`, `CKM_SKIPJACK_OFB64`, `CKM_SKIPJACK_CFB64`, `CKM_SKIPJACK_CFB32`, `CKM_SKIPJACK_CFB16`, `CKM_SKIPJACK_CFB8`, `CKM_SKIPJACK_WRAP`, `CKM_SKIPJACK_PRIVATE_WRAP`, `CKM_SKIPJACK_RELAYX` |
  | BATON | `CKM_BATON_ECB128`, `CKM_BATON_ECB96`, `CKM_BATON_CBC128`, `CKM_BATON_COUNTER`, `CKM_BATON_SHUFFLE`, `CKM_BATON_WRAP` |
  | JUNIPER | `CKM_JUNIPER_ECB128`, `CKM_JUNIPER_CBC128`, `CKM_JUNIPER_COUNTER`, `CKM_JUNIPER_SHUFFLE`, `CKM_JUNIPER_WRAP` |
  | GOST28147 | `CKM_GOST28147` |
  | Other legacy | `CKM_KEY_WRAP_LYNKS`, `CKM_KEY_WRAP_SET_OAEP`, `CKM_FASTHASH` |

  Key-generation-only entries are already exercised by generic keygen paths;
  the table is limited to encrypt, MAC, wrap, digest, and stream/counter
  operations where exact-output or semantic operation vectors would materially
  improve coverage.
- Source refresh: `CKM_SKIPJACK_CBC64`, `CKM_SKIPJACK_OFB64`, and
  `CKM_SKIPJACK_CFB64` are not wired to mechanism-vector KATs. The NIST
  SP 800-17 mode vectors are valid algorithm evidence, but the local OASIS
  PKCS#11 historical text describes 24-byte SKIPJACK IV parameters and
  token-selected encryption IVs; treating the 8-byte NIST values as
  deterministic PKCS#11 encrypt parameters would create false failures on
  conforming providers. Keep these modes source-first until the PKCS#11
  IV/wrap mapping is reconciled.
- Legacy vector source refresh (2026-06-12): the latest web/local
  primary-source pass found no safe immediate KAT to wire for the remaining
  classified historical mechanisms. BATON and JUNIPER remain source-first:
  the local OASIS historical PKCS#11 text describes operation shapes, but
  public exact-output algorithm vectors were not found. KEA remains
  source-first: RFC 2876 and RFC 2773 describe KEA/SKIPJACK protocol use, not
  PKCS#11 `CKM_KEA_DERIVE` or `CKM_KEA_KEY_DERIVE` exact-vector material.
  `CKM_KEY_WRAP_LYNKS`, `CKM_KEY_WRAP_SET_OAEP`, and `CKM_FASTHASH` likewise
  need operation-specific sources before exact-output tests. NIST SP 800-135
  and ACVP component-test material make protocol KDFs a better next
  exact-vector target than the remaining classified legacy ciphers.
- Added: `CKM_RC5_MAC_GENERAL` has a KAT-backed expected-MAC vector using the
  existing RFC 2040 RC5 block result as the one-block zero-IV CBC-MAC output,
  plus vector-param replay for word size, rounds, and MAC length. Fixed-length
  `CKM_RC5_MAC` is covered by the fixed-output legacy MAC vector set below.
- Added: `CKM_IDEA_MAC_GENERAL`, CAST/CAST3 MAC_GENERAL, and
  `CKM_CAST128_MAC_GENERAL` now have full-block expected-MAC vectors derived
  from the existing IDEA NESSIE and CAST RFC 2144 one-block ECB KATs under the
  same zero-IV CBC-MAC equivalence. Remaining MAC_GENERAL gaps should continue
  family by family only where the block KAT source and PKCS#11 parameter
  mapping are clear.
- Added: `CKM_RC2_MAC_GENERAL` now has a full-block expected-MAC vector derived
  from the existing OpenSSL legacy RC2 one-block ECB vector, plus vector-param
  replay for effective key bits and requested MAC length.
- Added: CAST/CAST3 ECB/CBC now have RFC 2144 exact-output KAT vectors plus
  registry `vector_file` links. The CBC rows use a zero IV and one full block,
  so their expected ciphertext is the same sourced block output as the ECB
  row, with vector-param replay for the IV.
- Added: `CKM_RC2_CBC_PAD`, CAST/CAST3 CBC_PAD, `CKM_CAST128_CBC_PAD`,
  `CKM_IDEA_CBC_PAD`, and `CKM_BLOWFISH_CBC_PAD` now have non-block-aligned
  exact-output KAT vectors and registry `vector_file` links, so providers that
  advertise those historical mechanisms are tested for PKCS#7 padding behavior
  rather than only CBC roundtrip behavior.
- Added: `CKM_RC5_CBC_PAD` now has an RFC 2040 section 9.3 exact-output
  `RC5_CBC_Pad` vector, including non-block-aligned plaintext and vector-param
  replay for word size, rounds, and IV. `CKM_TWOFISH_CBC_PAD` now has a
  source-backed exact-output vector generated with Bruce Schneier's Twofish
  reference C implementation, cross-checked against the published zero-key
  ECB KAT, and replayed as zero-IV CBC with PKCS#7 padding.
- Added: DES, 3DES, Camellia, ARIA, and SEED CBC_PAD now have
  non-block-aligned exact-output KAT vectors plus registry `vector_file` links.
  These cover the block-cipher padding families where existing CBC vector
  generation already had a reliable local cipher implementation. Twofish
  CBC_PAD is covered separately from the official Schneier reference
  implementation because the current local OpenSSL/cryptography setup does not
  expose Twofish.
- Added: DES, 3DES, Camellia, ARIA, and SEED MAC_GENERAL now have full-block
  exact-output KAT vectors plus registry `vector_file` links. The 16-byte block
  families use vector-level `mac_len=16`, and generic `mac_general` vector
  replay now honors the per-vector length instead of always using the registry
  default.
- Added: DES and 3DES fixed-output MAC now have half-block exact-output KAT
  vectors plus registry `vector_file` links. These reuse the existing
  FIPS-PUB-113-style CBC-MAC/ECB-equivalent full-block material and apply the
  general block cipher MAC rule that fixed `*_MAC` is the no-parameter special
  case producing half the block size.
- Added: RC2, RC5, CAST/CAST3/CAST128/CAST5, and IDEA fixed-output MAC now
  have half-block exact-output KAT vectors plus registry `vector_file` links.
  RC2 and RC5 keep their required effective-bits / rounds / word-size parameter
  replay fields, while CAST/CAST3/CAST128/CAST5 and IDEA use the general
  block-cipher fixed-MAC rule.
- Added: Camellia, ARIA, and SEED fixed-output MAC now have half-block
  exact-output KAT vectors plus registry `vector_file` links. These are sourced
  from the local OASIS mechanism text that defines each fixed `*_MAC` as the
  no-parameter special case of `*_MAC_GENERAL` producing half the block size.
- Added: DES3 CMAC/CMAC_GENERAL now have full-block exact-output KAT vectors
  plus registry `vector_file` links. These use NIST SP 800-38B CMAC via pyca
  cryptography and the local OASIS DES3-CMAC text, with a non-block-aligned
  input to exercise CMAC padding/subkey semantics.
- Added: CKM_SKIPJACK_ECB64 now has NIST SP 800-17 exact-output KATs plus a
  registry `vector_file` link. The rows cover both the variable-plaintext and
  variable-key known-answer tables while avoiding the less-clear stream and
  wrap-mode mappings.
- Added: CDMF ECB/CBC/CBC_PAD/MAC/MAC_GENERAL now have IBM CDMF
  key-shortening-derived exact-output KATs plus registry `vector_file` links.
  The vectors use an 8-byte odd-parity CDMF key value, replay the historical
  PKCS#11 general block-cipher mappings, and cover both full-block
  `MAC_GENERAL` and the fixed half-block `MAC` special case.
  The remaining less-sourced classified/obsolete families remain pending.

Provider-speed work for bouncyhsm MCT and wolfPKCS11 session health checks now
has provider-local evidence above. Further provider-speed work should begin
with a fresh current-artifact bottleneck audit rather than treating those two
paths as pending.

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

Status: fixed in the current branch, except the provider-local wolfPKCS11
remeasurement remains a fresh-run follow-up. Auto-isolation expands
`subprocess_per_test` files to node-level units, resume rejects unexpanded
subprocess-per-test state, and focused tests cover the guard.

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
- Remaining evidence: run a fresh bouncyhsm pool using provider-local
  `--duration-artifacts-dir` and `--coverage-baseline-artifacts-dir` before
  claiming a bouncyhsm wall-time improvement.

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
- Remaining evidence: run targeted wolfPKCS11 X.509/CCTV batches with
  provider-local duration and coverage baselines before claiming a provider
  wall-time reduction.

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
   `CK_WTLS_PRF_PARAMS.pLabel`.
2. Many derive mechanisms still lack runtime dispatch: Camellia/ARIA/SEED
   encrypt-data and any remaining protocol KDF variants not covered by
   dedicated files.
3. Dedicated DSA/DH/X9.42 domain-parameter coverage exists in
   `test_dsa_complete.py`, `test_dh_key_agreement.py`, and `test_x942_dh.py`.
   The generic registry-driven keygen path still skips `dsa` and `dh` recipe
   styles because their parameter objects are mechanism-specific, but this is
   not the same as missing product coverage. Remaining work is broader
   exact-vector, negative, and provider-artifact evidence. DSA probabilistic/Shawe-Taylor/FIPS-G parameter variants
   are now covered in `test_dsa_complete.py` for the
   OASIS-defined p/q and g-generation outputs.
4. Message API coverage is representative, not registry-driven. Scenario
   selection does not yet cover `CKF_MESSAGE_*` flags generically.
5. Hybrid and AEAD wrap coverage has explicit holes: RSA-AES key wrap,
   ECDH-AES key wrap, AEAD wrap styles, and AES-CTR wrap params.
6. BLAKE2B keyed coverage exists for HMAC, HMAC_GENERAL truncation, KEY_GEN,
   and KEY_DERIVE across 160/256/384/512-bit variants, with Python reference
   checks plus key-type and extracted-value assertions. BLAKE2B invalid-length HMAC_GENERAL
   parameter coverage now rejects zero-length and one-byte-too-long MAC requests
   against the OASIS 1..digest-length rule. Remaining BLAKE2B work is broader
   negative parameter/regression expansion and provider-artifact evidence, not
   basic keyed semantic coverage.
7. SHAKE/XOF and ML-DSA ExternalMu are registry/smoke only until raw XOF
   function signatures and KAT-backed tests exist.
8. Legacy cipher coverage is now mixed rather than mostly generic: RC2, RC4,
   RC5, CAST128/CAST5, IDEA, Blowfish, and Twofish have KAT-backed encrypt
   coverage where the PKCS#11 mechanism shape is reliable. RC2, RC5,
   CAST128/CAST5, IDEA, and Blowfish also have CBC_PAD exact-output vectors for
   padding behavior, with non-block-aligned plaintext covered where a reliable
   source exists. Remaining shallow areas are SKIPJACK, CDMF, CAST/CAST3
   variants, BATON/JUNIPER, GOST28147, Twofish CBC_PAD output, and the
   fixed-output MAC/MAC_GENERAL KATs where a block-vector source and output
   length mapping are still missing.
   Older PBE variants now have semantic `C_GenerateKey` coverage for key type
   and IV writeback where `CK_PBE_PARAMS` applies, but not independent
   fixed-output KAT vectors. MAC_GENERAL mechanisms now assert the returned MAC
   length matches the requested parameter length, and RC2/RC5/CAST128/IDEA plus
   DES, 3DES, Camellia, ARIA, and SEED have expected-MAC vectors. DES, 3DES,
   Camellia, ARIA, and SEED fixed-output MAC KATs now cover the spec-defined
   half-block special case. RC2, RC5, CAST128/CAST5, and IDEA fixed-output MAC
   KATs now do the same for the legacy 8-byte-block families with existing
   reliable full-block sources. DES3 CMAC/CMAC_GENERAL now have full-block CMAC
   KATs grounded in NIST SP 800-38B semantics and the local OASIS DES3-CMAC
   mapping. Continue this sweep for remaining CKM_CAST/CKM_CAST3 fixed-output
   `*_MAC`, CDMF, and less-sourced legacy families, but gate each new vector on
   a reliable source and an unambiguous PKCS#11 parameter mapping; SKIPJACK and
   KEA are lower confidence until a defensible vector/operation source is
   identified.
9. CMS and CT-KIP are shallow: current tests mostly check mechanism info or
   clean rejection rather than valid parameterized operations.
10. Generic negative coverage is narrow relative to 467 registry mechanisms.
    Wrong-key-type, missing-permission, bad-param, and linked-attribute
    self-contradiction tests should be table-driven from registry metadata.

### Recommended coverage order

1. Expand DSA/DH/X9.42 coverage beyond the existing dedicated generated-parameter
   tests: exact-vector checks where practical and richer negative cases.
2. Protocol KDF expansion beyond the already-covered priority set
   (`CKM_SP800_108_COUNTER_KDF`, `CKM_TLS12_KDF`, and `CKM_PKCS5_PBKD2`):
   add exact external vectors and tamper/negative checks for SSL3, WTLS, IKE,
   X3DH, and X2RATCHET where the mechanism semantics allow it.
3. BLAKE2B keyed negative/parameter edge cases, now that HMAC, HMAC_GENERAL,
   KEY_GEN, and KEY_DERIVE positive semantics are covered.
4. Hybrid wrap params: `CK_RSA_AES_KEY_WRAP_PARAMS` and
   `CK_ECDH_AES_KEY_WRAP_PARAMS`, with positive and tamper tests.
5. Registry-driven negative tests for wrong key type and missing operation
   permission across advertised operation families.

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
`results.json` and `report.jsonl`; shard merge preserves them.

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
unit details. A regression test covers a file with one failed test and one
crashed test: the emitted artifact unit has `status: "crashed"`, and both the
failed and crashed counters survive.

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
   truncation/output-length rule is sourced clearly. SKIPJACK and KEA remain
   lower-priority because their vector and operation mappings are less
   straightforward.
3. Continue broader semantic coverage expansion once artifact semantics can prove
   coverage preservation.

After that, do the first coverage expansion round:

1. DSA/DH/X9.42 exact-vector, negative, and parameter-variant expansion beyond
   the existing dedicated generated-parameter coverage.
2. Protocol KDF exact-vector expansion beyond already-covered SP800-108
   counter KDF, TLS 1.2 KDF, and PBKDF2.
3. BLAKE2B keyed negative/parameter edge cases.
4. RSA-AES and ECDH-AES wrap params.
5. Registry-driven wrong-key/permission negatives.
6. Legacy/deprecated mechanisms not yet covered by reliable KATs or semantic
   probes: SKIPJACK only if a trustworthy vector source is found, KEA only with
   defensible domain-parameter/derive semantics, plus CDMF, CAST/CAST3,
   BATON/JUNIPER, GOST28147, remaining CBC_PAD outputs such as Twofish, and
   RC2/RC5/CAST/IDEA MAC_GENERAL fixed-output vectors.

Legacy/deprecated coverage addendum for the active goal:

- Inventory every legacy/deprecated registry entry against product tests and
  mechanism-vector files before adding the next family.
- Add only provider-general tests: skip when a mechanism is genuinely absent,
  xfail clean advertised-but-not-operational refusals, and fail wrong outputs,
  self-contradictions, crashes, or hangs.
- Prefer reliable, externally traceable vectors. RC5 and IDEA encrypt vectors
  are already covered; RC5 CBC_PAD is now covered directly from RFC 2040.
  Continue with fixed-length MAC and remaining CBC_PAD gaps only when the source
  and PKCS#11 mapping are unambiguous. SKIPJACK and KEA remain source-first
  candidates because their vector and operation mappings are less
  straightforward. Also evaluate CDMF, CAST/CAST3, BATON/JUNIPER, GOST28147,
  old PBE fixed-output cases, and other deprecated mechanisms that a PKCS#11
  provider might still advertise. Treat the named families as starting points;
  the coverage round should account for every uncovered legacy/deprecated
  registry entry that can be tested with provider-general semantics.
- Started: `CKM_RC5_MAC_GENERAL` now has a KAT-backed expected-MAC vector using
  the existing RFC 2040 RC5 block result as the one-block zero-IV CBC-MAC
  output, plus vector-param replay for word size, rounds, and MAC length.
  Fixed-length `CKM_RC5_MAC` still needs a clearer source for its mandated
  truncation length before adding an expected-output KAT.
- Added: `CKM_IDEA_MAC_GENERAL` and `CKM_CAST128_MAC_GENERAL` now have
  full-block expected-MAC vectors derived from the existing IDEA NESSIE and
  CAST-128 RFC 2144 one-block ECB KATs under the same zero-IV CBC-MAC
  equivalence. Remaining MAC_GENERAL gaps should continue family by family
  only where the block KAT source and PKCS#11 parameter mapping are clear.
- Added: `CKM_RC2_MAC_GENERAL` now has a full-block expected-MAC vector derived
  from the existing OpenSSL legacy RC2 one-block ECB vector, plus vector-param
  replay for effective key bits and requested MAC length.
- Added: `CKM_RC2_CBC_PAD`, `CKM_CAST128_CBC_PAD`, `CKM_IDEA_CBC_PAD`, and
  `CKM_BLOWFISH_CBC_PAD` now have non-block-aligned exact-output KAT vectors
  and registry `vector_file` links, so providers that advertise those historical
  mechanisms are tested for PKCS#7 padding behavior rather than only CBC
  roundtrip behavior.
- Added: `CKM_RC5_CBC_PAD` now has an RFC 2040 section 9.3 exact-output
  `RC5_CBC_Pad` vector, including non-block-aligned plaintext and vector-param
  replay for word size, rounds, and IV. `CKM_TWOFISH_CBC_PAD` remains pending
  until a reliable padded-vector generator/source is available.
- Added: DES, 3DES, Camellia, ARIA, and SEED CBC_PAD now have
  non-block-aligned exact-output KAT vectors plus registry `vector_file` links.
  These cover the block-cipher padding families where existing CBC vector
  generation already had a reliable local cipher implementation. Twofish
  CBC_PAD remains pending because the current local OpenSSL/cryptography setup
  does not expose Twofish, so a stronger source or generator is still needed.
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
- Added: RC2, RC5, CAST128/CAST5, and IDEA fixed-output MAC now have half-block
  exact-output KAT vectors plus registry `vector_file` links. RC2 and RC5 keep
  their required effective-bits / rounds / word-size parameter replay fields,
  while CAST128/CAST5 and IDEA use the general block-cipher fixed-MAC rule.
- Added: Camellia, ARIA, and SEED fixed-output MAC now have half-block
  exact-output KAT vectors plus registry `vector_file` links. These are sourced
  from the local OASIS mechanism text that defines each fixed `*_MAC` as the
  no-parameter special case of `*_MAC_GENERAL` producing half the block size.
- Added: DES3 CMAC/CMAC_GENERAL now have full-block exact-output KAT vectors
  plus registry `vector_file` links. These use NIST SP 800-38B CMAC via pyca
  cryptography and the local OASIS DES3-CMAC text, with a non-block-aligned
  input to exercise CMAC padding/subkey semantics.
  CKM_CAST/CKM_CAST3 fixed-output MAC, CDMF, and the less-sourced
  classified/obsolete families remain pending.

Provider-speed work for bouncyhsm MCT and wolfPKCS11 session health checks
should follow once the harness can reuse provider-local history and prove
coverage did not silently drop.

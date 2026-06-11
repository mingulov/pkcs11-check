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

## Coverage Findings

The registry is broad, but registry membership is not the same as semantic
coverage. Several mechanisms are either explicitly skipped, routed to generic
smoke behavior, or covered only by one narrow variation.

### Highest-value missing or shallow coverage

1. Protocol KDFs are intentionally skipped in `test_mech_derive.py`: SP800-108,
   TLS, SSL3, WTLS, IKE, PBKDF2, X3DH, and X2RATCHET paths need runtime
   parameters and semantic assertions.
2. Many derive mechanisms still lack runtime dispatch: Camellia/ARIA/SEED
   encrypt-data, BLAKE2B key-derive variants, and several protocol KDFs.
3. DSA/DH/X9.42 domain parameter paths are mostly absent because key generation
   skips `dsa` and `dh` styles that need external domain parameters.
4. Message API coverage is representative, not registry-driven. Scenario
   selection does not yet cover `CKF_MESSAGE_*` flags generically.
5. Hybrid and AEAD wrap coverage has explicit holes: RSA-AES key wrap,
   ECDH-AES key wrap, AEAD wrap styles, and AES-CTR wrap params.
6. BLAKE2B coverage stops at unkeyed digest. HMAC, HMAC_GENERAL, KEY_GEN, and
   KEY_DERIVE variants need keyed reference tests and handle/value checks.
7. SHAKE/XOF and ML-DSA ExternalMu are registry/smoke only until raw XOF
   function signatures and KAT-backed tests exist.
8. Legacy cipher coverage is now mixed rather than mostly generic: RC2, RC4,
   RC5, CAST128/CAST5, IDEA, Blowfish, and Twofish have KAT-backed encrypt
   coverage where the PKCS#11 mechanism shape is reliable. Remaining shallow
   areas are SKIPJACK, CDMF, CAST/CAST3 variants, BATON/JUNIPER, GOST28147,
   older PBE variants, CBC_PAD outputs, and RC2/RC5/CAST/IDEA MAC_GENERAL
   parameter structures.
9. CMS and CT-KIP are shallow: current tests mostly check mechanism info or
   clean rejection rather than valid parameterized operations.
10. Generic negative coverage is narrow relative to 467 registry mechanisms.
    Wrong-key-type, missing-permission, bad-param, and linked-attribute
    self-contradiction tests should be table-driven from registry metadata.

### Recommended coverage order

1. Protocol KDF semantics: start with `CKM_SP800_108_COUNTER_KDF`,
   `CKM_TLS12_KDF`, and `CKM_PKCS5_PBKD2`.
2. DSA/DH domain parameter generation, then DSA sign/verify and DH/X9.42
   derive tests using generated parameters.
3. BLAKE2B keyed HMAC/HMAC_GENERAL and key-derive coverage.
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

### 4. Mixed fail+crash units can be summarized as failed

`_overall_unit_status()` currently gives `failed` precedence over `crashed`.
Crash counts are preserved elsewhere, but consumers that scan only unit status
can miss that a file had a crash.

Next task:

- Either give crash/timeout precedence, or add explicit `has_crash` and
  `has_timeout` fields.
- Add a unit test for mixed failed plus crashed file results.

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

## Recommended Next Round

The next implementation round should be harness-first, because it makes every
later provider run more interpretable:

1. Add provider-local `--duration-artifacts-dir` support to `docker/test_pool.py`.
2. Add a subprocess-per-test expansion guard for crash-prone files.
3. Repair/static-test file-skip accounting and high-count `REQUIRED_MECHANISMS`.
4. Fix unknown CKR classification for undefined non-vendor values.
5. Persist compliance notes through isolated artifacts.

After that, do the first coverage expansion round:

1. SP800-108 counter KDF, TLS 1.2 KDF, and PBKDF2 semantic tests.
2. DSA/DH parameter generation and DH/X9.42 derive.
3. BLAKE2B keyed HMAC/HMAC_GENERAL and key-derive.
4. RSA-AES and ECDH-AES wrap params.
5. Registry-driven wrong-key/permission negatives.

Provider-speed work for bouncyhsm MCT and wolfPKCS11 session health checks
should follow once the harness can reuse provider-local history and prove
coverage did not silently drop.

# Provider Crash And Failure Findings

This document summarizes crash, timeout, and broad failure evidence from the
current Docker provider artifact set. It complements
[docker-provider-results.md](docker-provider-results.md), which is the compact
source and result snapshot.

Source artifacts:

- `artifacts/_matrix/provider-summary.json`
- per-provider `artifacts/*/results.json`
- segmented BouncyHSM `artifacts/bouncyhsm-*/*results.json` and
  `artifacts/_focused/bouncyhsm-*/*results.json`

## Method

The extraction separates three different signals:

- **Runner-level crashes/timeouts**: `results.json` summary counters and unit
  counters where a pytest file-level worker crashed or timed out.
- **Subprocess signal findings**: ordinary failed tests whose `longrepr`
  records a subprocess crash, signal, abort, or `pytest-timeout`. These are
  intentional pkcs11-check isolation probes and are provider findings even when
  the top-level runner summary says `crashed=0`.
- **Broad failed-file buckets**: the largest failed test files by provider, to
  show whether a result is dominated by a small number of mechanism families.

The signal matcher used only explicit crash/timeout words such as
`Fatal Python error`, `Segmentation fault`, `Bus error`, `Aborted`,
`signal <number>`, `pytest-timeout`, `Timeout (>...)`, `TimeoutExpired`, and
`timed out`. It intentionally does not count cryptographic names such as
`sigGen`, `SigVer`, `signature`, or `signing`.

These counts are artifact-derived evidence, not root-cause proof. One provider
bug can produce many vector failures, and one broad vector family can dominate
a provider's failed count.

Result wording in the article should keep these categories separate:

- **Clean pass**: the provider produced the expected cryptographic result and
  the PKCS#11 return code matched the test's spec expectation.
- **Known deviation / xfail**: the provider reached a meaningful security
  outcome but used a non-conformant or non-specific CKR, or advertised a
  mechanism that is rejected at runtime. For example, Kryoptic's documented
  `CKR_DEVICE_ERROR` on invalid-signature verification is not a clean pass; it
  is evidence that tampering was rejected with a non-spec return code.
- **Skip**: the test could not apply because a mechanism was absent, optional
  data was unavailable, or PKCS#11 has no discovery surface for a narrower
  capability such as a curve or parameter set.
- **Failure/crash/timeout**: unclassified wrong results, wrong CKRs, aborts,
  signals, hangs, or isolation-runner crashes. These remain provider or harness
  findings until root-caused.

`xfail` is therefore a report category, not a pass category. In this project it
means "the test reached a known non-clean outcome that should stay visible
without being merged into the clean-pass count." For negative vectors this
distinction matters: accepting a bad signature is a security failure; rejecting
it with `CKR_DATA_INVALID`, `CKR_DEVICE_ERROR`, or another non-specific CKR is
still a PKCS#11 return-code deviation. CKR-focused tests may also attach
`compliance.note()` entries for these deviations; `--ckr-strict` promotes such
CKR deviations to hard failures.

## Runner-Level Crashes

These are crashes counted by the provider summary itself.

| Target | Runner crashes | Runner timeouts | Evidence units |
| --- | ---: | ---: | --- |
| `kryoptic-fips` | 12 | 0 | `acvp/aes/test_ccm.py` 3, `test_mech_derive.py` 1, `test_mech_encrypt.py` 2, `test_misc_kdf.py` 3, `wycheproof/test_wycheproof_aes.py` 3 |
| `nss` | 3 | 0 | `test_mech_flags.py` 3 |
| `nss-pqc` | 4 | 0 | `test_mech_flags.py` 3, `test_mech_negative.py` 1 |
| `nss-main` | 4 | 0 | `test_mech_flags.py` 3, `test_mech_negative.py` 1 |
| `bouncyhsm-segmented` | 4 | 0 | `acvp/aes/test_cfb8.py` 1, `security/test_parameter_validation.py` 3 |

No runner-level crashes are recorded for SoftHSM2, Kryoptic release/main,
OpenCryptoki release/master, TPM2 source, TPM2 archived Fedora package, or
pkcs11-mock. That does not mean those providers had no crash findings: several
crash probes were contained inside subprocess-based tests and therefore appear
as ordinary failed tests.

Focused current-source NSS-family reruns confirmed that the retained NSS
runner crashes are still real provider crashes, not stale harness artifacts.
All three NSS rows crash in `test_mech_flags.py` on
`test_sign_flag_callable[AES_MAC_GENERAL]`, where pkcs11-check calls
`C_SignInit(CKM_AES_MAC_GENERAL, key=0)` to check whether an advertised
`CKF_SIGN` mechanism is callable. The source-tag and main NSS rows also crash
in `test_mech_negative.py::test_hmac_sha256_with_rsa_key_rejected`, where
`C_SignInit(CKM_SHA256_HMAC, RSA private key)` should reject the wrong key type
with a CKR. In both cases, a segfault is the provider finding: the input is a
negative probe, but the provider must return an error code rather than aborting.

Focused artifacts:

- `artifacts/_focused/nss-mech-flags-current-20260526/`
- `artifacts/_focused/nss-main-mech-flags-current-20260526/`
- `artifacts/_focused/nss-pqc-mech-flags-current-20260526/`
- `artifacts/_focused/nss-main-mech-negative-current-20260526/`
- `artifacts/_focused/nss-pqc-mech-negative-current-20260526/`

## Subprocess Signal And Timeout Findings

| Target | Signal/timeout findings | Main evidence clusters | Frequent PKCS#11 calls in traces |
| --- | ---: | --- | --- |
| `softhsm2` | 9 | arithmetic-overflow template counts; GCM null-IV boundary | `C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_EncryptInit` |
| `softhsm2-generated-iv` | 8 | arithmetic-overflow template counts; generated-IV patch removes the GCM null-IV crash from this artifact | `C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair` |
| `softhsm2-main` | 9 | arithmetic-overflow template counts; GCM null-IV boundary | `C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair`, `C_EncryptInit` |
| `kryoptic` | 19 | NULL template/pointer probes, length-boundary probes, arithmetic-overflow probes, v3.0 session init behavior | `C_FindObjectsInit`, `C_GenerateKey`, `C_Sign`, `C_Digest`, `C_Initialize`, `C_DeriveKey` |
| `kryoptic-main` | 15 | length-boundary probes, arithmetic-overflow probes, NULL pointer probes, AES extreme key-size panic | `C_GenerateKey`, `C_FindObjectsInit`, `C_Sign`, `C_Digest`, `C_Initialize`, `C_DeriveKey` |
| `kryoptic-fips` | 45 | runner aborts plus arithmetic-overflow, length-boundary, NULL pointer, AES-CCM, and extract-key findings | `C_GenerateKey`, `C_Encrypt`, `C_Decrypt`, `C_FindObjectsInit`, `C_CreateObject`, `C_UnwrapKey` |
| `nss` | 17 | NULL pointer/template/data probes plus sign-flag mechanism probes | `C_Sign`, `C_DigestInit`, `C_CreateObject`, `C_FindObjectsInit`, `C_GenerateKey`, `C_EncryptInit` |
| `nss-pqc` | 18 | same as `nss`, plus one negative HMAC/RSA-key mechanism crash | `C_Sign`, `C_DigestInit`, `C_CreateObject`, `C_FindObjectsInit`, `C_GenerateKey`, `C_EncryptInit` |
| `nss-main` | 18 | same as `nss-pqc` | `C_Sign`, `C_DigestInit`, `C_CreateObject`, `C_FindObjectsInit`, `C_GenerateKey`, `C_EncryptInit` |
| `opencryptoki` | 7 | signal 7/bus-error boundary findings in template-count and data-length probes | `C_FindObjectsInit`, `C_Sign`, `C_Digest` |
| `opencryptoki-master` | 7 | same commit and same boundary finding shape as release | `C_FindObjectsInit`, `C_Sign`, `C_Digest` |
| `tpm2-source` | 4 | digest NULL-mechanism/data-length subprocess crashes and fork-after-initialize timeout | `C_DigestInit`, `C_Digest`, `C_Finalize`, `C_Initialize` |
| `tpm2-fedora-package-20260525` | 4 | archived package comparison: digest boundary crashes and fork-after-initialize timeout | `C_DigestInit`, `C_Digest`, `C_Finalize`, `C_Initialize` |
| `bouncyhsm-segmented` | 42 | CFB8/CFB128/OFB multiblock timeouts or segfaults; security arithmetic/length/parameter validation crashes | `C_Encrypt`, `C_Decrypt`, `C_GenerateKeyPair`, `C_CreateObject`, `C_SetAttributeValue`, `C_VerifyInit` |

`pkcs11-mock` has no signal/timeout findings in the current artifact set, but
it is a mock baseline rather than a provider conformance result.

## Largest Failure Buckets

These are the largest failed test files per target. They are useful for article
wording because they show which areas dominate each provider's failure shape.
This table is a retained artifact snapshot; follow-up notes below identify
buckets that have since been reclassified and need a fresh matrix rerun before
being used as current article numbers.

| Target | Largest failed buckets |
| --- | --- |
| `softhsm2` | ACVP ECDH 1,403; Wycheproof RSA-OAEP 668; Wycheproof RSA-PSS 435; Wycheproof ECDH 32; Wycheproof HMAC 24 |
| `softhsm2-generated-iv` | ACVP ECDH 1,403; Wycheproof RSA-OAEP 668; Wycheproof RSA-PSS 435; Wycheproof ECDH 32; Wycheproof HMAC 24 |
| `softhsm2-main` | ACVP ECDH 1,403; Wycheproof RSA-OAEP 668; Wycheproof RSA-PSS 435; ACVP ML-DSA 93; Wycheproof ECDH 32 |
| `kryoptic` | ACVP ECDH 1,403; Wycheproof ECDSA 467; ACVP AES-CTS 405; ACVP ML-DSA 249; Wycheproof AES 123 |
| `kryoptic-main` | ACVP ECDH 1,403; Wycheproof ECDSA 467; ACVP AES-CTS 405; ACVP ML-DSA 249; Wycheproof AES 123 |
| `kryoptic-fips` | ACVP ECDH 1,403; Wycheproof PBES2 1,080; Wycheproof ECDSA 467; ACVP AES-CTS 405; ACVP RSA 268 |
| `nss` | ACVP ECDH 1,403; Wycheproof DSA 296; ACVP ML-DSA 93; Wycheproof AES 77; ACVP ML-KEM 50 |
| `nss-pqc` | ACVP ECDH 1,403; Wycheproof DSA 296; Wycheproof AES 77; ACVP ML-KEM 50; mechanism attributes 39 |
| `nss-main` | ACVP ECDH 1,403; Wycheproof DSA 296; Wycheproof AES 77; ACVP ML-KEM 50; mechanism attributes 39 |
| `opencryptoki` | ACVP ECDH 1,403; Wycheproof RSA-PSS 435; ACVP AES-XTS 382; ACVP ML-DSA 164; Wycheproof AES 107 |
| `opencryptoki-master` | ACVP ECDH 1,403; Wycheproof RSA-PSS 435; ACVP AES-XTS 382; ACVP ML-DSA 164; Wycheproof AES 107 |
| `tpm2-source` | ACVP AES-CFB128 2,144; ACVP ECDH 1,734; generic Wycheproof 856; Wycheproof RSA-PSS 813; ACVP HMAC 444 |
| `tpm2-fedora-package-20260525` | ACVP AES-CFB128 2,144; generic Wycheproof 871; Wycheproof RSA-PSS 813; ACVP HMAC 444; Wycheproof HMAC 198 |
| `pkcs11-mock` | X.509 limbo stress 1,009; generic Wycheproof 729; Wycheproof RSA-OAEP 700; X.509 limbo import 169; ACVP RSA 162 |
| `bouncyhsm-segmented` | Wycheproof ECDH 11,945; ACVP AES-CCM 7,370; ACVP ECDH 1,736; Wycheproof AES 414; Wycheproof HMAC 180 |

### Follow-Up: ACVP ECDH 1,403 Bucket

The repeated `ACVP ECDH 1,403` bucket in the artifact table should not be used
as a provider finding until the matrix is rerun. Follow-up investigation found
that the count is exactly the P-384 and P-521 Wycheproof ECDH vector set
(`771 + 632`), while P-256 passed for SoftHSM2, Kryoptic, NSS, and
OpenCryptoki.

Root cause was in pkcs11-check's vector loader: the SubjectPublicKeyInfo
extractor searched for the first `0x04` byte and treated it as the uncompressed
EC point. That happened to work for P-256, but P-384 and P-521 curve OIDs
contain an earlier `0x04`, so the test passed malformed peer public data into
imports or `C_DeriveKey`.

The loader now parses the SubjectPublicKeyInfo DER structure and extracts the
BIT STRING EC point explicitly. A focused SoftHSM2 Docker check after the fix
selected 1,733 Wycheproof ECDH shared-secret tests and all passed. The full
provider matrix still needs to be rerun before updating provider result counts.

A later artifact scan showed the same bucket shape also mixed in
advertised-but-not-operational ECDH derive results such as
`CKR_DEVICE_ERROR` and `CKR_GENERAL_ERROR`. Those are not clean passes and are
not missing-capability skips. ACVP ECDH now classifies those generic runtime
rejects as visible xfail findings, matching the existing treatment for
`CKR_MECHANISM_PARAM_INVALID`, `CKR_FUNCTION_FAILED`, and related derive-time
rejects.

TPM2 needs separate wording. A current focused tpm2-pkcs11 source rerun of the
ACVP ECDH file no longer reproduces the old hard failure bucket. The vector rows
stop at EC private-key import with `CKR_ATTRIBUTE_VALUE_INVALID`, which the
source explains: `C_CreateObject` supports RSA public keys, data/certificate
objects, and secret keys, but not imported EC private keys. That means these
vectors cannot exercise `C_DeriveKey` on TPM2 through imported ACVP key
material. The generated-key probe still keeps a separate P-521 malformed
`CKA_EC_POINT` readback as visible xfail evidence.

### Follow-Up: NSS Wycheproof DSA 296 Bucket

The repeated NSS-family `Wycheproof DSA 296` bucket was also a pkcs11-check
loader issue, not provider evidence. The failures were only in the non-P1363
Wycheproof DSA files; the P1363 files did not produce the same failure shape.

Root cause was signature representation at the PKCS#11 boundary. Wycheproof's
non-P1363 DSA files store signatures as DER `SEQUENCE { r, s }`, while
`C_Verify` for DSA expects fixed-width raw `r || s`. The loader now converts
valid DER signatures to PKCS#11/P1363 form. It also computes the raw component
width from the integer value of `q`, not from the encoded byte string, because
some vectors encode DSA integers with a leading zero byte. Without that second
step, 224-bit signatures became 58 bytes instead of 56, and 256-bit signatures
became 66 bytes instead of 64.

A later focused review found the same leading-zero issue at DSA public-key
import time. PKCS#11 `Big integer` attributes are unsigned big-endian byte
strings, while Wycheproof's JSON can carry ASN.1-style positive sign padding in
`p`, `q`, and `y`. The loader now strips that sign padding before `C_CreateObject`
and before duplicate grouping. A focused SoftHSM2 rerun of the DSA file then
moved from 296 valid-signature failures to 0 failures: 613 passed and 1,343
skipped out of 1,956 collected DSA vectors. Current evidence is stored in
`artifacts/_focused/softhsm2-dsa-current-20260526/`.

A focused NSS Docker check after the fix selected 1,956 Wycheproof DSA tests:
1,055 passed and 901 skipped. The skips are invalid DER signatures that cannot
be represented as a PKCS#11 raw DSA signature input. The full provider matrix
still needs to be rerun before updating provider result counts.

### Follow-Up: Generic Wycheproof Buckets

The `pkcs11-mock` `generic Wycheproof 729` bucket was a pkcs11-check capability
guard bug. The legacy aggregate Wycheproof test file did not check advertised
mechanisms before running AES-GCM, HMAC-SHA256, ECDSA, AES-CBC-PAD, and RSA
signature vectors. `pkcs11-mock` does not advertise those mechanisms, so the old
failures should have been capability skips. After adding the same style of
mechanism guards used by the split Wycheproof files, a focused pkcs11-mock
Docker run selected 1,953 generic Wycheproof tests and skipped all 1,953.

The largest known part of the TPM2 `generic Wycheproof` bucket had the same
classification issue. The P-384 ECDSA subset accounted for 504 failures where
tpm2-pkcs11 rejected `secp384r1` public-key import with
`CKR_ATTRIBUTE_VALUE_INVALID`. That is an unsupported-curve/import condition for
this vector file, not a failed signature result. A focused TPM2 run now selects
504 P-384 generic ECDSA tests and skips all 504. The remaining old TPM2
generic Wycheproof AES-GCM, AES-CBC-PAD, and HMAC-SHA256 rows reached
advertised mechanisms and then returned `CKR_GENERAL_ERROR`. Current generic
Wycheproof coverage reports those explicit operation rejects as visible xfail
findings. Wrong plaintext/MAC, accepted invalid ciphertext/tag, and accepted
invalid signatures remain hard failures. Provider counts still need a matrix
refresh before using this bucket in release statistics.

### Follow-Up: ACVP Deterministic ECDSA Xfails

The ACVP deterministic ECDSA SigGen vectors should not be counted as provider
non-conformance for ordinary PKCS#11 ECDSA mechanisms. Those vectors require
RFC6979 deterministic nonce generation and exact signature matching, while
standard `CKM_ECDSA_SHA*` signing exposes no nonce-control parameter and most
PKCS#11 providers are allowed to use randomized nonces.

The test now treats deterministic ACVP ECDSA SigGen vectors as not applicable
to standard PKCS#11 ECDSA and skips them after the advertised-mechanism check.
A focused SoftHSM2-main Docker run selected 30 deterministic ECDSA SigGen cases
and skipped all 30.

### Follow-Up: Provider-Neutral Finding Messages

Several xfail and failure messages in the current artifact set correctly
recorded security or interoperability findings, but still used legacy
NSS-specific wording. The same behavior appeared in non-NSS targets including
BouncyHSM, Kryoptic, OpenCryptoki, SoftHSM2, and TPM2, so the wording was
misleading even when the underlying test classification was useful.

Runtime finding messages are now provider-neutral for `pytest.xfail`,
`pytest.fail`, compliance `note()`, and xfail/failure-message constants. This
does not suppress the findings; it prevents the report and article from
attributing a behavior to NSS when another provider shows the same class of
behavior.

### Follow-Up: ACVP AES Advertised-But-Rejected Paths

Some ACVP AES runners skipped vectors after `has_mechanism()` had already
confirmed that the provider advertised the mechanism, but the actual
`C_Encrypt` or `C_Decrypt` operation rejected it with mechanism or parameter
errors. Those cases are now xfailed as advertised-but-not-operational provider
findings instead of skipped as missing capability.

This affects AES-CFB/OFB simple and MCT runners, AES-GCM/CCM parameterized
operations, AES-KW/KWP raw wrapping, AES-XTS, and AES-CTS variant/error paths.
Missing mechanisms still skip normally; only runtime rejection after an
advertised mechanism is reclassified.

### Follow-Up: Security Subprocess Setup Preflights

The current `tpm2` and `pkcs11-mock` artifacts exposed a separate harness
classification issue in security crash probes. Several child scripts generated
setup AES/RSA/EC keys inside the crash-isolated subprocess. If a provider
advertised the outer operation but setup key generation was not operational,
the child exited with a Python assertion and the parent reported a failed crash
probe. That was not crash evidence.

Current source preflights setup key generation in the parent for the affected
API-boundary, arithmetic-overflow, FFI length-boundary, RSA error-path, and
NULL-pointer AES probes. A setup rejection now becomes the same visible
setup xfail/skip classification used elsewhere, while the actual malformed API
call still runs in the child when setup succeeds. The subprocess helper still
treats negative return codes as crash findings and positive child exits as
child-script failures, so this does not hide segfaults.

The same review fixed `C_SetPIN` and `C_InitToken` NULL-pointer child scripts
to pass valid PIN/label buffers as `CK_UTF8CHAR_PTR` instead of
`ctypes.c_void_p`. The old artifacts' PIN/token failures were Python
`ctypes` signature errors, not module behavior.

A focused current-source rerun of `test_ffi_null_pointer.py` on TPM2,
OpenCryptoki, and SoftHSM2 found no hard failures or crashes. TPM2 still
reports visible setup xfails for rows that require advertised-but-not-operational
AES key generation, while OpenCryptoki passes the full file and SoftHSM2 only
skips unsupported capabilities. The old NULL-pointer rows should therefore be
removed from public provider-failure wording unless a refreshed run reproduces
an actual signal exit or wrong result.

The destructive `test_so_pin.py` PIN-change row also had a catch boundary that
was too broad: any Python-side exception or generic CKR became a skip. It now
only skips exact token-policy/permission CKRs, xfails generic runtime rejects
such as `CKR_FUNCTION_FAILED`, and lets local setup exceptions fail. A focused
pkcs11-mock run in `artifacts/_focused/pkcs11-mock-so-pin-current-20260527/`
is destructive-gated, so it is gating evidence rather than provider
`C_SetPIN` behavior evidence.

The access-level `C_InitPIN` row had the same issue and one extra setup gap:
after the explicit SO-PIN/conflict skips, `C_Login(CKU_SO)` was not validated
before calling `C_InitPIN`. Current source now fails unexpected SO-login CKRs,
only skips exact token-policy/environment rejects from `C_InitPIN`, xfails
generic runtime rejects such as `CKR_FUNCTION_FAILED`, and lets Python-side
setup bugs fail. A focused pkcs11-mock run in
`artifacts/_focused/pkcs11-mock-access-levels-init-pin-current-20260527/`
reports 27 skipped and 0 failed, again as destructive/capability gating
evidence rather than provider PIN-initialization behavior.

`test_object_size.py` had a similar catch boundary around `C_GetObjectSize`:
arbitrary exceptions and generic CKRs were being reported as unsupported
object-size capability. Current source only treats successful zero or
`CK_UNAVAILABLE_INFORMATION` replies as the skip path, xfails generic runtime
rejects, and lets Python bugs fail. A focused pkcs11-mock rerun in
`artifacts/_focused/pkcs11-mock-object-size-current-20260527/` leaves one hard
wrong-result row where 100-byte and 10KB data objects both report size 256.

A focused current-source rerun of `test_arithmetic_overflow.py` changes only
part of the old crash-probe wording. Current TPM2 no longer has hard failures
in this file: it reports 18 passed, 6 skipped, and 15 xfailed setup rows in
`artifacts/_focused/tpm2-arithmetic-overflow-current-20260527/`. Those rows are
advertised-but-not-operational AES/RSA setup evidence, not arithmetic-overflow
crashes. The same focused slice still reproduces provider-side boundary
findings elsewhere: stock SoftHSM2 2.7.0 reports 9 hard probe failures,
OpenCryptoki reports 3 `C_FindObjectsInit` signal-7 crashes, and Kryoptic main
reports 5 panic/abort/segfault findings. These rows must stay visible; they are
not candidates for skip or xfail unless a later source-level review proves the
PKCS#11 call shape itself is invalid.

A focused current-source rerun of `test_ffi_length_boundary.py` also narrows
the old crash-boundary evidence. One pkcs11-check setup bug was fixed:
the EdDSA null-context probe now generates Ed25519 keys with
`CKM_EC_EDWARDS_KEY_PAIR_GEN` instead of generic `CKM_EC_KEY_PAIR_GEN`, so the
pre-fix OpenCryptoki/NSS/Kryoptic EdDSA setup failures should not be described
as provider findings. After that correction, TPM2 still has two digest
length-boundary signal-11 rows, OpenCryptoki has four HMAC/SHA256 sign/digest
signal-7 rows plus the ML-DSA explicit-empty-context abort, Kryoptic main has
seven signal/timeout boundary rows, and NSS main has two HMAC sign signal-11
rows plus the AES-GCM NULL-IV signal-11 row. pkcs11-mock has no hard FFI
failures in the focused run.

### Follow-Up: CKR Operation-State Subprocess Probes

The compact artifact scan after cleanup still contained old
`test_ckr_dual.py::TestOperationStateSubprocess::test_encrypt_without_init`
rows where TPM2 and pkcs11-mock child-process setup failures were reported as
`Subprocess crashed`. Current source no longer treats a positive child exit as
a crash for this file: signal exits remain crash findings, while assertion
exits inside the child are reported as child-script failures.

The operation-state probes were also tightened to test the named PKCS#11 state
errors directly. `test_encrypt_without_init` now calls raw `C_Encrypt` without
`C_EncryptInit` and expects `CKR_OPERATION_NOT_INITIALIZED`; it no longer
generates an AES key or calls the helper wrapper that initializes encryption.
The double-digest probe now calls `C_DigestInit` twice and expects
`CKR_OPERATION_ACTIVE`; it no longer uses `digest_single` twice, which performs
two independent one-shot digest operations.

Existing artifacts that mention these `test_ckr_dual.py` subprocess crashes
should be treated as pre-fix harness evidence. A focused provider rerun is
needed before these rows are used in article wording.

A current focused rerun changes that wording for the sampled providers:
OpenCryptoki and SoftHSM2 both pass all five `test_ckr_dual.py` rows. TPM2 now
has three passed rows and two xfailed wrapper setup rows because AES key
generation is advertised but not operational; those are setup evidence, not
operation-state failures and not crashes. The subprocess rows themselves pass
on TPM2 after the direct raw-operation correction.

### Follow-Up: CKR Raw/Fault Setup Classification

The compact artifact scan also showed `Crash:` wording in
`test_ckr_raw_attrs.py`, `test_ckr_raw_buffer.py`, `test_ckr_raw_state.py`, and
`test_ckr_fault_inject.py` for TPM2 and pkcs11-mock rows where the child process
failed during setup, such as AES key generation, RSA key generation, digest
initialization, or fault-proxy pass-through setup. Those rows were not signal
crashes; they were positive Python exits from assertions inside the child.

Current source uses a shared CKR subprocess classifier for those files. Negative
return codes still fail as module crash findings. Positive child exits now
report as child-script failures. Setup precondition rejects that prevent the
intended CKR probe from running are emitted as `SETUP_XFAIL:` and become visible
xfail evidence rather than a pass or a false crash. This keeps genuine CKR
failures visible: wrong return codes, missing injected fault errors, accepted
forbidden key usage, bad buffer handling, and subprocess signals still fail.

The same classifier now covers `test_ckr_general.py`,
`test_ckr_universal.py`, and `test_ckr_raw_multipart.py`. Those files were not
the dominant retained artifact buckets, but they used the same direct
`returncode == 0` pattern and now report positive child exits separately from
signal crashes. The v2.40-style `C_GetInterfaceList` path without a
`C_GetInterfaceList` symbol now emits an `OK` marker, so "no method" is a
completed probe rather than a failed child script.

Focused current-source reruns after this correction are in
`artifacts/_focused/tpm2-ckr-raw-fault-r3-20260527/` and
`artifacts/_focused/pkcs11-mock-ckr-raw-fault-r3-20260527/`.
pkcs11-mock now reports 29 passed, 16 xfailed, and 0 failed across the selected
45 CKR raw/fault/general rows; its old hard raw/fault rows were setup
classification noise. TPM2 reports 28 passed, 14 xfailed, and 3 failed. The
three remaining TPM2 failures are target raw-argument findings in
`test_ckr_raw_args_bad.py`: `C_DigestInit(NULL)` exits with signal 11, while
`C_GenerateKey(NULL)` and `C_WrapKey(NULL)` return
`CKR_FUNCTION_NOT_SUPPORTED` (`0x54`). The `C_GenerateKey(NULL)` test now
requires `CKR_ARGUMENTS_BAD`; unlike operation-init calls such as
`C_EncryptInit`, key generation has no PKCS#11 NULL-mechanism cancellation
success path.

### Follow-Up: Legacy Cipher Advertised-But-Rejected Paths

The same classification issue existed in legacy cipher coverage for ARIA,
Blowfish, Camellia, and Twofish. Missing key-generation or cipher mechanisms
still skip as absent capability, but `CKR_MECHANISM_INVALID` after the
mechanism was advertised is now an xfail provider finding instead of a skip.

### Follow-Up: Message API And HKDF Runtime Rejections

The v3 message-based API tests now treat `CKR_MECHANISM_INVALID` from
`C_MessageEncryptInit` or `C_MessageSignInit` as an xfail when the provider has
already advertised the mechanism and the relevant message-operation flag. The
basic HKDF derive test also no longer uses a catch-all skip for operational
failure: only specific CKR values become xfail evidence, while unexpected Python
errors or wrong derived outputs remain real failures.

### Follow-Up: SHAKE XOF Advertised-But-Rejected Paths

The SHAKE XOF checks still skip when the raw XOF functions are unavailable, but
`CKR_MECHANISM_INVALID` from `C_DigestXofInit` is now an xfail after the module
has advertised `CKM_SHAKE_128` or `CKM_SHAKE_256`. The draft mechanism ids are
also named locally instead of being passed as unexplained inline constants.

### Follow-Up: Extended ECDH And Montgomery Runtime Rejections

Extended ECDH coverage now keeps X25519/Montgomery keygen and cofactor-ECDH
AES-target derive rejections visible as xfail findings after the relevant
mechanism is advertised. X448 remains a clean skip when the provider rejects
that specific curve with a known unsupported-curve/domain-parameter/template
CKR, because a provider can reasonably support X25519 without supporting X448.

The Double Ratchet tests now follow the same Montgomery boundary. The local
PKCS#11 text describes X2RATCHET curve selection as 255 or 448, so the setup
helper no longer falls back to classic EC/P-256. It tries X25519 and then X448
through `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`, turns only explicit setup CKRs into
skip/xfail evidence, and lets Python-side setup bugs fail the test. A focused
pkcs11-mock rerun in
`artifacts/_focused/pkcs11-mock-double-ratchet-current-20260527/` confirms the
mock target simply has no X2RATCHET coverage; providers that advertise
X2RATCHET still need refreshed focused evidence.

### Follow-Up: OTP Runtime Rejections And CT-KIP Placeholder

OTP key-generation and sign-operation rejects now remain xfail findings after a
provider advertises the HOTP, SecurID, or ACTI mechanism. The CT-KIP derive
placeholder no longer calls `C_GenerateKey` with `CKM_KIP_DERIVE`; it skips as
an explicit coverage/precondition gap until the test supplies the
mechanism-specific CT-KIP parameter setup.

### Follow-Up: PBE/PBKDF2 Runtime Rejections

PBE and PBKDF2 key-generation helpers no longer translate known `C_GenerateKey`
rejections into `None` followed by a skip. After a provider advertises a PBE or
PBKDF2 mechanism, specific CKR rejects now become xfail findings with the
returned CKR named in the reason; missing mechanisms still skip normally.
Mechanism-driven PBKDF2 coverage also builds concrete
`CK_PKCS5_PBKD2_PARAMS2` test parameters instead of treating PBKDF2 as an
unavailable generic runtime-data recipe. If an advertised PBKDF2 path rejects
that spec-shaped keygen call with explicit runtime CKRs such as
`CKR_ARGUMENTS_BAD` or `CKR_DEVICE_ERROR`, the result is visible xfail evidence
rather than a hard setup assertion or a skipped mechanism.

### Follow-Up: HKDF Key-Generation Runtime Rejections

`CKM_HKDF_KEY_GEN` no longer returns `None` for every non-OK `C_GenerateKey`
result. Basic key-generation rejects now xfail for specific CKRs, unexpected
CKRs fail, and the derive-usability test can still try both `CKK_HKDF` and
`CKK_GENERIC_SECRET` before xfail-reporting that no tested key type was
operational. The HKDF lifecycle test now follows the same policy: if the
provider advertises both HKDF mechanisms but rejects base-key generation with a
specific runtime CKR, the row is visible xfail evidence rather than a raw
assertion failure.

Kryoptic has a narrower HKDF finding: `CKM_HKDF_KEY_GEN` can create a
`CKK_HKDF` key that remains usable for derive, but `C_GetAttributeValue` for
`CKA_VALUE` returns `CKR_ATTRIBUTE_VALUE_INVALID` even when the test requested a
non-sensitive, extractable key. pkcs11-check now reports that exact readback
rejection as xfail evidence while keeping key type, value length, and derived
output checks strict whenever readback succeeds.

### Follow-Up: Benchmark AES Keygen Rejections

Benchmark tests still skip when `CKM_AES_KEY_GEN` is absent, but an advertised
AES key-generation mechanism that rejects AES-256 keygen now becomes xfail
evidence. This preserves the TPM2 finding shape where `CKM_AES_KEY_GEN` was
listed but `C_GenerateKey` returned `CKR_FUNCTION_NOT_SUPPORTED`.

### Follow-Up: ML-DSA Benchmark Keygen Rejections

The CCTV ML-DSA sign/verify benchmark now distinguishes missing
`CKM_ML_DSA_KEY_PAIR_GEN` from an advertised keypair-generation path that
rejects `C_GenerateKeyPair`. Missing keypair generation still skips; specific
runtime CKRs now become xfail findings instead of disappearing as benchmark
setup skips.

### Follow-Up: Remaining HOTP Attribute Probe

The remaining-gap OTP attribute probe now matches the main OTP tests:
`CKM_HOTP_KEY_GEN` absence skips, but advertised HOTP key generation that
rejects `C_GenerateKey` becomes xfail evidence for specific CKRs.

### Follow-Up: ACVP HMAC Key Import Fallback

ACVP HMAC now mirrors the Wycheproof HMAC key setup path: it first tries the
typed HMAC key and then falls back to `CKK_GENERIC_SECRET`. Old skips for
typed-key import failure and key-handle invalid use no longer hide advertised
HMAC mechanisms; if both key forms are rejected, the test records an xfail
finding with the specific setup or use CKR evidence.

A focused current-source TPM2 rerun in
`artifacts/_focused/tpm2-hmac-current-20260526/` confirms that the old ACVP
HMAC hard-failure bucket is stale: 1,034 rows skipped for unavailable HMAC
variants, 444 rows xfailed as advertised-but-not-operational HMAC runtime
rejects, and 0 rows failed.

### Follow-Up: ACVP RSA-PSS Parameter Rejections

ACVP RSA still skips key sizes that a provider cannot generate or import, but
RSA-PSS parameter rejection after an advertised PSS mechanism is now xfail
evidence. This keeps mixed hash/MGF or salt-length limitations visible instead
of treating them as missing test capability.

ACVP FIPS186-5 RSA-PSS also contains SHAKE mask-function rows. These are a
separate loader-expressiveness case, not a provider runtime finding: current
PKCS#11 `CK_RSA_PKCS_MGF_TYPE` constants cover MGF1 with SHA/SHA3 hashes, but
do not expose `shake-128` or `shake-256` mask functions. pkcs11-check now skips
those ACVP rows before building PKCS#11 mechanism parameters instead of
substituting `MGF1-SHA3-*`. A focused OpenCryptoki ACVP RSA rerun after this
change reported 890 passed, 0 failed for the file.

### Follow-Up: ACVP RSA Keygen CKR Classification

ACVP RSA key generation now uses exact CKR constants instead of parsing CKR
names out of assertion text. Key-size and template capability rejects still
skip, while `CKR_MECHANISM_INVALID` after `CKM_RSA_PKCS_KEY_PAIR_GEN` was
advertised becomes xfail evidence.

The ACVP RSA SigGen sign/verify roundtrip tests now use the same setup/result
split. Rejection while generating the temporary RSA key is a setup capability
skip when the CKR is a key-size/template/attribute capability reject. Rejection
from the advertised RSA signing or verification operation is visible xfail
evidence instead. A generated signature that verifies as false, or returns a
clean signature-invalid result, remains a real failure.

### Follow-Up: Wycheproof EC Import Buckets

The largest remaining skip buckets are curve/import capability probes in
Wycheproof ECDSA, ECDH, and X25519/X448. The ECDSA and ECDH guards now match
specific CKR constants instead of parsing CKR names from exception text, and
ECDH no longer skips arbitrary `AssertionError`s from private-key import. These
remain capability skips because PKCS#11 does not expose a complete per-curve
support list through mechanism discovery.

The X25519/X448 guard received the same structured CKR treatment. Invalid JWK
vectors whose public key cannot be decoded now count as accepted invalid-vector
rejections instead of provider capability skips.

Ed25519/Ed448 import guards now also use exact CKR constants for Edwards curve
and public-key import rejects. Signature verification failures after a key was
successfully imported remain failures, not skips.

Stateful HSS/XMSS/XMSSMT keygen, sign, and tampered-verify guards were also
converted away from CKR-name substring checks. These tests still xfail known
provider substitutes such as `CKR_DEVICE_ERROR` for signature-invalid, but
unexpected CKRs remain visible.

ACVP ECDSA, EdDSA, ML-DSA, and SLH-DSA vector guards now follow the same
structured-CKR rule. Import and parameter-set capability rejects remain skips
where PKCS#11 lacks per-parameter-set discovery. Generic runtime failures such
as `CKR_DEVICE_ERROR`/`CKR_FUNCTION_FAILED` no longer make those vectors look
unsupported; they either become documented provider quirks or real failures.
Advertised mechanism parameter rejects in EdDSA and Hash-ML-DSA verification are
xfail evidence rather than silent skips.

ACVP ML-KEM now follows the same split. Earlier NSS-family artifacts showed a
50-call ML-KEM failure bucket split between 25 ML-KEM-512 public-key imports
returning `CKR_PARAMETER_SET_NOT_SUPPORTED` and 25 ML-KEM-512 key-generation
attempts returning `CKR_HOST_MEMORY`. The import case is a narrower
parameter-set capability result and skips; `CKR_HOST_MEMORY` during advertised
ML-KEM key generation is visible xfail evidence for a provider path that is not
cleanly operational. Focused current-source reruns for `nss`, `nss-main`, and
`nss-pqc` now report that file as 72 passed, 107 skipped, 1 xfailed, and 0 hard
failures. Full provider counts still require a matrix rerun.

### Follow-Up: Wycheproof Negative-Vector Success Paths

Several Wycheproof negative-vector tests previously treated successful provider
operations as pass-like flow when the vector result was `invalid`. That hid
important provider findings: an invalid signature verifying, a forged tag
matching, malformed ciphertext decrypting, or malformed derive input producing a
key is a real test failure, not a clean rejection.

The affected paths now fail accepted invalid outputs for signature verification,
HMAC, RSA-PKCS#1/RSA-OAEP decrypt, AES-GCM/AES-CBC-PAD, AES-CMAC/GMAC,
AES-KW/KWP, AES-CCM, ChaCha20-Poly1305, HKDF `SizeTooLarge`, and malformed
ML-KEM semi-expanded decapsulation vectors. XDH now fails if an invalid vector
with malformed public-key length still derives, and ECDH now fails when an
invalid vector with no expected shared secret still derives.

ECDH and XDH still need careful wording in reports. Many Wycheproof ECDH
invalid cases are invalid because of ASN.1, JWK, curve, order, or cofactor
metadata. pkcs11-check often decodes those containers and passes only the raw
point/scalar and the locally selected PKCS#11 curve parameters into the module.
When that metadata has been stripped, derivation success is not automatically a
provider bug. The current rule is intentionally narrower: fail accepted invalid
crypto results or malformed raw inputs that PKCS#11 actually sees, while leaving
metadata-only cases for separate loader/coverage wording.

The same review found exact duplicate decoded-operation inputs across ECDH and
XDH container encodings. Some WebCrypto vectors remain distinct after decoding
(`ecdh_secp256k1_test.json:tc70` and
`ecdh_secp256k1_webcrypto_test.json:tc70` have different public points and
shared secrets), but many ASN/PEM/ECPOINT/JWK/WebCrypto variants collapse to
the same PKCS#11-visible curve, public point, private scalar, expected shared
secret, and result. The loaders now mark exact duplicates as skipped before any
provider call: 7,023 of 13,128 loaded ECDH vectors and 3,087 of 4,176 loaded
XDH vectors. This keeps the source vector inventory visible while avoiding
inflated provider failure buckets for container formats that PKCS#11 never
sees.

ECDSA and DSA have the same post-decoding shape for signature encodings. The
test harness must convert DER signatures to raw `r || s` before calling
`C_Verify`, because PKCS#11 `CKM_ECDSA` and DSA mechanisms do not consume DER
signature containers. Therefore DER and P1363 vectors that normalize to the
same public key, message/digest, raw signature, mechanism, and expected result
are duplicate PKCS#11 operation inputs. The loaders now skip 6,707 of 28,915
loaded ECDSA vectors and 442 of 1,956 loaded DSA vectors as exact duplicates.
This also avoids false provider failures for invalid vectors whose only
invalidity is DER container metadata, or Bitcoin low-S policy metadata, after
that metadata has been normalized away.

ECDSA has one additional size-encoding caveat. Some Wycheproof P1363 negative
vectors are invalid only under a fixed-width P1363 convention: the `r || s`
string is shorter than `2*nLen` but still has equal-width `r` and `s`
components. The local OASIS PKCS#11 spec checkout says ECDSA signatures passed
to a token for verification may be shorter than `2*nLen` when composed that way.
Those size-only vectors are now skipped as PKCS#11-version-sensitive inputs
rather than counted as providers accepting invalid signatures. Odd-length,
empty, oversized, or mathematically invalid signatures remain negative tests.

A later focused SoftHSM2 review found another ECDSA loader issue limited to
`ecdsa_secp521r1_shake256_test.json`: pkcs11-check used the P-521 coordinate
width as the SHAKE256 output length. The Wycheproof valid signatures verify
with a 64-byte SHAKE256 output before raw `CKM_ECDSA`, not with 66 bytes. The
loader now uses SHAKE256(64) for the P-521/SHAKE256 files. A focused SoftHSM2
rerun of the ECDSA file no longer showed the P-521/SHAKE256 valid-vector
rejections, so those old rows should be treated as harness evidence until the
full matrix is refreshed. A focused NSS stable rerun of the same current-source
ECDSA file selected 28,915 vectors and completed with 6,832 passed, 22,083
skipped, and 0 failed. A focused OpenCryptoki rerun of the full ECDSA file also
selected 28,915 vectors and completed with 19,027 passed, 9,702 skipped,
186 xfailed, and 0 failed. The old NSS-family and OpenCryptoki ECDSA
hard-failure buckets should therefore be treated as pre-fix harness evidence
until the matrix is refreshed. OpenCryptoki's remaining xfails in this file are
valid signatures rejected with `CKR_FUNCTION_FAILED`, which is visible
non-clean provider evidence rather than a hard vector mismatch.

A focused Kryoptic rerun of the full Wycheproof ECDSA file on current source
also no longer reproduces the old hard-failure bucket:
`artifacts/_focused/kryoptic-ecdsa-current-20260526/` records 5,820 passed,
22,083 skipped, 1,012 xfailed, and 0 failed. The xfailed rows are all invalid
signatures rejected with Kryoptic's documented `CKR_DEVICE_ERROR` behavior.
That is visible non-clean return-code evidence, not a clean pass, but it is not
the old 467-row ECDSA hard-failure bucket.

RSA signature vectors have a smaller version of the same duplication problem.
After pkcs11-check maps a vector to a concrete PKCS#11 mechanism and parameter
set, some Wycheproof RSA-PSS and RSA PKCS#1 cases are identical at the module
boundary. The loaders now skip 913 of 2,502 loaded RSA-PSS vectors and 75 of
5,313 loaded RSA PKCS#1 signature vectors when the mechanism, mechanism
parameters, public key, message, and signature are exact duplicates. This
reduces inflated buckets while keeping distinct RSA-PSS parameter combinations
as real provider tests.

The RSA Wycheproof loaders also now share the same `Big integer` normalization
as DSA. A follow-up scan found ASN.1-style positive sign padding in all loaded
RSA-PSS public-key groups, all RSA-OAEP and RSA-PKCS#1 decrypt private-key
groups, and most RSA PKCS#1 signature public-key groups. PKCS#11 RSA key
attributes such as `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, `CKA_PRIVATE_EXPONENT`,
and CRT components are unsigned big-endian `Big integer` values, so the loader
strips this container padding before key import and duplicate grouping. A
focused SoftHSM2 run after the change no longer showed RSA-PSS, RSA signature
verification, or RSA-OAEP failures from the padded imports. The same run still
showed RSA PKCS#1 decrypt failures where invalid ciphertext was accepted; those
remain provider/security findings, not loader-padding artifacts.

A current focused SoftHSM2 rerun of
`test_wycheproof_rsa_decrypt.py` confirms that split: 142 passed, 59 failed,
0 skipped, and 0 xfailed in
`artifacts/_focused/softhsm2-rsa-decrypt-current-20260526/`. The 59 failures
are all invalid PKCS#1 v1.5 padding ciphertexts accepted after `CKR_OK`, across
the 2048-, 3072-, and 4096-bit Wycheproof files.

ACVP KeyGen internal-projection vectors are a different normalization case.
They include seeds and expected private/public key material, but current
PKCS#11 key-generation APIs do not accept deterministic external seed inputs.
The only provider-visible input is the generated-key parameter choice, such as
RSA modulus size, EC curve, or PQC parameter set. Current source therefore
collects the vectors but skips duplicate provider-visible KeyGen inputs after
the first representative: RSA 27 of 30, ECDSA 17 of 20, EdDSA 4 of 6, ML-DSA
72 of 75, and ML-KEM 72 of 75. Future PKCS#11 revisions could make exact ACVP
KeyGen validation possible by standardizing deterministic validation inputs,
but there is no portable API for that today.

### Other Large Buckets Checked In This Pass

These buckets were sampled after the ECDH and DSA loader fixes. They do not
currently show the same kind of obvious vector-loader bug, but they still need
deeper follow-up before being presented as final provider conclusions.

- **RSA-PSS mixed-parameter buckets**: SoftHSM2 and OpenCryptoki both show the
  same 435-failure shape, concentrated in Wycheproof PSS files with mixed MGF
  hash or unusual salt length. SoftHSM2 source explicitly rejects PSS params
  where `mgf` does not match `hashAlg`. TPM2 source similarly documents that
  the TPM fixes MGF to the hash algorithm and salt length to the hash length.
  This looks like provider/back-end parameter support, not a DER/vector-loader
  issue like ECDH or DSA. Wycheproof RSA-PSS now reports advertised valid-vector
  parameter rejects such as `CKR_ARGUMENTS_BAD`, `CKR_DEVICE_ERROR`, and
  `CKR_MECHANISM_PARAM_INVALID` as visible xfail findings. A successful
  verification result must still match the Wycheproof expectation.
- **TPM2 Wycheproof RSA-PSS semantic failures**: a current focused rerun of
  `test_wycheproof_rsa_pss.py` against the source-built tpm2-pkcs11 1.10.0
  Docker target reproduced the remaining 82 hard failures:
  788 passed, 943 skipped, 689 xfailed, and 82 failed in
  `artifacts/_focused/tpm2-rsapss-current-20260526/`. The failures split into
  43 valid signatures rejected by the advertised RSA-PSS mechanisms and
  39 invalid signatures accepted after `CKR_OK`. The invalid accepted group is
  concentrated in Wycheproof rows whose comment is `s_len changed to 0`; a
  local control check verifies those signatures fail when the vector's
  `CK_RSA_PKCS_PSS_PARAMS.sLen` is enforced but pass with OpenSSL-style
  automatic salt-length verification. The tpm2-pkcs11 source path matches that
  behavior: `src/lib/mech.c` validates PSS params, `src/lib/sign.c` routes RSA
  public-key verification through software OpenSSL, and `src/lib/ssl_util.c`
  sets RSA-PSS padding and signature digest but does not set the PSS salt
  length or MGF digest on the verification context. These rows are provider
  findings, not vector-loader or DER-shape failures. The SHA-1 valid-vector
  rejects remain a separate advertised-mechanism behavior to report or
  investigate upstream.
- **TPM2 ACVP RSA SHA-1 PKCS#1 SigVer failures**: a current focused rerun of
  `test_acvp_rsa.py` reports 279 passed, 390 skipped, 194 xfailed, and
  27 failed in `artifacts/_focused/tpm2-acvp-rsa-current-20260526/`. The hard
  failures are all valid ACVP `CKM_SHA1_RSA_PKCS` signature-verification rows
  rejected by the provider. Representative rows verify with `cryptography`,
  including both FIPS186-2 vectors with small public exponents and FIPS186-4
  vectors with larger public exponents, so the current evidence points to
  advertised SHA-1 PKCS#1 verification behavior rather than an ACVP loader
  projection issue. The PSS parameter rejects in the same file are visible
  xfail evidence, not hard failures.
- **TPM2 ACVP ECDSA stale hard failure**: the retained full TPM2 artifact had
  one hard `CKR_HOST_MEMORY` row in ACVP ECDSA P-521 KeyGen. A current focused
  rerun of `test_acvp_ecdsa.py` reports 31 passed, 67 skipped, 2 xfailed, and
  0 failed in `artifacts/_focused/tpm2-acvp-ecdsa-current-20260526/`. The old
  row should be treated as stale classifier evidence, not a current hard
  provider failure.
- **TPM2 Docker exit propagation**: the focused RSA-PSS rerun also found that
  `docker/tpm2-pkcs11/run-tpm2.sh` swallowed a failing pkcs11-check exit with
  `if ! bash /app/docker/run-pkcs11-check.sh; then ... fi`. That made Docker
  runs look successful even when the artifact had hard failures. Current source
  now lets `run-pkcs11-check.sh` exit directly, matching the project rule that
  Docker provider failures and crashes must stay visible.
- **Kryoptic AES-CTS old bucket**: reclassified from hard failures to visible
  xfail evidence after focused rerun. The remaining non-clean rows are mostly
  `CKR_DEVICE_ERROR` on encrypt after `CKM_AES_CTS` is advertised and selected.
  Kryoptic source maps `CKM_AES_CTS` to CTS mode CS1, and pkcs11-check's CTS
  test detects the module variant before selecting vectors. Focused evidence is
  stored in `artifacts/_focused/kryoptic-cts-current-20260526/`.
- **OpenCryptoki AES-XTS old bucket**: reclassified as a pkcs11-check ACVP
  loader issue after focused rerun. The old test ignored ACVP
  `sequenceNumber` for `tweakMode: number` rows and lost group-level
  `payloadLen`, so some bit-level vectors were sent through PKCS#11 as byte
  strings. Current source converts `sequenceNumber` to the little-endian
  16-byte `CKM_AES_XTS` data-unit sequence number, preserves
  `payloadLen`/`dataUnitLen`, chunks multi-data-unit inputs, and skips
  non-byte-aligned vectors. The focused current-source artifact
  `artifacts/_focused/opencryptoki-xts-after-loader-fix-20260526/` records the
  corrected classification.
- **OpenCryptoki generic Wycheproof AES-CBC-PAD 144**: a current-source focused
  rerun still fails the same invalid-padding family. The failures are
  successful `CKM_AES_CBC_PAD` decrypt calls on invalid Wycheproof vectors:
  zero padding, ANSI X.923, ISO 10126, ISO/IEC 7816-4, too-long padding,
  padding longer than the message, no padding, and empty ciphertext, across
  128-, 192-, and 256-bit AES keys. That is provider behavior/security
  evidence, not a vector loader mismatch.
- **TPM2 AES-CFB128 old large bucket**: all simple encrypt/decrypt vectors plus
  the small multiblock tail fail with `CKR_GENERAL_ERROR`. tpm2-pkcs11 advertises
  `CKM_AES_CFB128` only when the TPM reports `TPM2_ALG_CFB`; the bucket looks
  like an advertised-but-not-operational backend path, not a pkcs11-check
  vector-shape issue. A focused current-source rerun in
  `artifacts/_focused/tpm2-cfb128-current-20260526/` confirms these rows are
  now visible xfail evidence rather than hard failures.
- **TPM2 HMAC runtime rejects**: tpm2-pkcs11 registers `CKM_SHA*_HMAC`
  mechanisms when the TPM reports `TPM2_ALG_KEYEDHASH` plus the matching hash
  algorithm. The ACVP HMAC failures reach that advertised mechanism path and
  then return `CKR_GENERAL_ERROR`, so they should be visible xfail findings
  rather than capability skips. A focused current-source rerun in
  `artifacts/_focused/tpm2-hmac-current-20260526/` confirms this current
  classification.
- **TPM2 interop/crossverify runtime rejects**: the OpenSSL/Python
  cross-verification files now use the same rule for advertised AES/HMAC
  operation rejects. `CKR_GENERAL_ERROR` after a selected mechanism becomes
  visible xfail evidence, while exact-output mismatches after `CKR_OK` remain
  hard failures.
- **pkcs11-mock X.509 limbo buckets**: the large mock X.509 buckets are
  `CKA_VALUE` round-trip mismatch findings, not crash evidence. They are useful
  harness stress rows because the module accepts certificate objects but returns
  placeholder bytes instead of the DER supplied to `C_CreateObject`. The stress
  tests now allow CKR-style import rejection only via `AssertionError`; arbitrary
  Python exceptions at import setup are no longer swallowed as acceptable
  provider rejects. A current focused rerun in
  `artifacts/_focused/pkcs11-mock-x509-limbo-current-20260526/` reports
  `test_limbo_stress.py`: 1,009 failed, and `test_limbo_import.py`: 476 passed
  / 169 failed. All inspected failures are still `CKA_VALUE` placeholder
  readback mismatches. That rerun also exposed a Docker harness issue:
  pkcs11-mock had been masking `run-pkcs11-check.sh` failures with `|| true`,
  so old pkcs11-mock Docker exit statuses should not be used as pass/fail
  evidence.
- **BouncyHSM ECDH public-data encoding**: pkcs11-check sends raw uncompressed
  EC points in `CK_ECDH1_DERIVE_PARAMS.pPublicData`, matching the portable
  OASIS requirement. BouncyHSM 2.1.0 advertises `CKM_ECDH1_DERIVE`, but its
  source parses `pPublicData` through its `CKA_EC_POINT` DER decoder and its
  own integration tests pass DER-encoded points. The observed
  `CKR_MECHANISM_PARAM_INVALID` bucket is therefore a provider encoding
  limitation, not a reason for pkcs11-check to switch the default ECDH encoding.

### Follow-Up: All-Fail Runtime Classification Buckets

Several "zero clean passes among executed tests" buckets were not vector-loader
bugs, but they did expose inconsistent result classification in pkcs11-check.
The current rule is:

- absent setup capability is a skip;
- advertised setup or operation rejected at runtime is an xfail finding;
- wrong cryptographic output, accepted invalid input, crash, timeout, or
  subprocess signal remains a failure.

The following paths were tightened after inspecting the all-fail artifacts:

- **ACVP HMAC on TPM2**: executed vectors reached advertised HMAC mechanisms
  but signing returned `CKR_GENERAL_ERROR`. ACVP HMAC now treats explicit
  generic runtime rejects like other HMAC key-use rejects: visible xfail, not a
  clean pass and not a skip.
- **ACVP ML-DSA on Kryoptic**: SigGen vectors reached advertised ML-DSA
  mechanisms but `C_Sign` returned `CKR_DEVICE_ERROR` across the bucket. The
  ML-DSA tests now keep import and parameter-set capability skips narrow, while
  sign/verify runtime rejects such as `CKR_DEVICE_ERROR`, `CKR_FUNCTION_FAILED`,
  and `CKR_GENERAL_ERROR` become visible xfail findings.
- **ACVP ML-DSA non-empty context roundtrip**: old OpenCryptoki and BouncyHSM
  artifacts had SigGen rows where `C_Sign` returned a signature but the test's
  immediate verification failed for non-empty-context vectors. This was a
  pkcs11-check context-propagation bug: the sign call used
  `CK_SIGN_ADDITIONAL_CONTEXT`, but the follow-up verification of the generated
  signature did not pass the same mechanism parameter. The SigGen roundtrip now
  reuses the context for verification. The remaining SigVer rows that reject
  valid ACVP signatures are still provider findings unless they return an
  explicit runtime CKR covered by the xfail policy.
- **OpenCryptoki ML-DSA empty-context parameter abort**: a focused subprocess
  probe now exercises `CKM_ML_DSA` verification with an explicit
  `CK_SIGN_ADDITIONAL_CONTEXT` where `pContext` is non-NULL and
  `ulContextLen=0`. OpenCryptoki swtok aborts with `free(): invalid size`.
  Source review matches the crash shape: `verify_mgr.c` shallow-copies the
  parameter struct, `ml_dsa_dup_param()` returns early for zero-length context
  without clearing the copied `pContext`, and cleanup later frees the copied
  caller pointer. The ordinary ACVP empty-context path still uses absent
  mechanism parameters, which is the spec-normal default.
- **Wycheproof AES operation rejects**: BouncyHSM CMAC, Kryoptic CCM, and
  OpenCryptoki XTS vectors reached advertised AES mechanisms but returned
  runtime CKRs such as `CKR_GENERAL_ERROR`, `CKR_MECHANISM_PARAM_INVALID`, or
  `CKR_DATA_LEN_RANGE`. These are now visible xfail findings for valid vectors.
  Successful AES-KWP calls that return the wrong wrapped bytes or wrong length
  remain hard failures.
- **NSS/OpenCryptoki Wycheproof AES-KWP stale bucket**: the old KWP rows were a
  pkcs11-check mechanism-selection bug. Wycheproof `aes_kwp_test.json` is RFC
  5649 KWP raw data, but the test used deprecated `CKM_AES_KEY_WRAP_PAD` and
  `C_WrapKey`. The local OASIS spec tree says `CKM_AES_KEY_WRAP_KWP` is the
  RFC 5649 mechanism and `CKM_AES_KEY_WRAP_PAD` is deprecated. Current source
  uses `CKM_AES_KEY_WRAP_KWP` with `C_Encrypt`; focused `nss` and `nss-pqc`
  reruns both report 724 passed, 1,095 skipped, and 0 failed for the
  Wycheproof AES file. A focused OpenCryptoki rerun after the same fix reports
  726 passed, 1,013 skipped, 80 xfailed, and 0 failed; those remaining xfails
  are AES-XTS runtime rejects, not AES-KWP failures.
- **Wycheproof RSA-OAEP parameter/runtime rejects**: valid RSA-OAEP
  ciphertexts in SoftHSM2 and BouncyHSM artifacts reached an advertised
  `CKM_RSA_PKCS_OAEP` path, then rejected the decrypt operation with explicit
  CKRs such as `CKR_ARGUMENTS_BAD`, `CKR_GENERAL_ERROR`, or
  `CKR_KEY_TYPE_INCONSISTENT`. These are now visible xfail findings for
  advertised-but-not-operational parameter support. A current focused
  pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-rsa-oaep-current-20260526/` moved the old
  700-row hard bucket to 373 passed, 700 xfailed, and 0 failed. Successful
  decrypts still have to match the Wycheproof plaintext, and accepted invalid
  ciphertext remains a hard failure.
- **Wycheproof RSA PKCS#1 decrypt runtime rejects**: Kryoptic FIPS/PQC reached
  advertised `CKM_RSA_PKCS` decrypt with valid Wycheproof ciphertexts and
  returned `CKR_DEVICE_ERROR`; pkcs11-mock reached the same valid-vector path
  and returned `CKR_KEY_TYPE_INCONSISTENT`. Valid-vector runtime rejects are
  now visible xfail evidence, while wrong plaintext and accepted invalid
  ciphertexts remain hard failures. Current focused SoftHSM2 evidence keeps the
  accepted-invalid side visible: 59 invalid-padding ciphertexts decrypt
  successfully and therefore fail.
- **Wycheproof HMAC operation rejects**: valid HMAC vectors in TPM2,
  SoftHSM2, and BouncyHSM artifacts reached advertised HMAC mechanisms but
  failed at key use with explicit CKRs such as `CKR_GENERAL_ERROR`,
  `CKR_KEY_HANDLE_INVALID`, or `CKR_KEY_SIZE_RANGE`. These are now visible
  xfail findings. A focused current-source TPM2 rerun reports 320 passed,
  1,214 skipped, 198 xfailed, and 0 failed for `test_wycheproof_hmac.py`. If
  an invalid HMAC vector produces the supplied tag, the test still fails.
- **Wycheproof ECDH derive rejects**: BouncyHSM's large Wycheproof ECDH bucket
  is dominated by `CKR_MECHANISM_PARAM_INVALID` after `CKM_ECDH1_DERIVE` is
  advertised; SoftHSM2 artifacts also show generic derive-time rejects on valid
  vectors. pkcs11-check still sends raw uncompressed EC points in
  `CK_ECDH1_DERIVE_PARAMS.pPublicData`, so these rejects are reported as
  advertised derive-path xfail findings rather than capability skips. A derived
  but wrong shared secret remains a hard failure.
- **Generic Wycheproof runtime rejects**: the legacy aggregate Wycheproof file
  now follows the same policy for AES-GCM, AES-CBC-PAD, HMAC-SHA256, and
  RSA-PKCS#1 verification. Valid vectors that reach advertised mechanisms but
  return explicit setup or operation CKRs such as `CKR_GENERAL_ERROR`,
  `CKR_KEY_SIZE_RANGE`, `CKR_ARGUMENTS_BAD`, or `CKR_DEVICE_ERROR` are xfail
  findings. Wrong plaintext, wrong MAC, accepted invalid ciphertext/tag, and
  any rejection of valid signatures remain failures.
- **ACVP AES-CTS `CKR_DEVICE_ERROR` rows**: Kryoptic release, main, and
  FIPS/PQC artifacts all reached the advertised `CKM_AES_CTS` path and then
  returned `CKR_DEVICE_ERROR` for valid CS1 vectors. pkcs11-check keeps the
  compliance note, but now reports those rows as advertised-but-not-operational
  xfail findings instead of raw harness failures. Ciphertext/plaintext
  mismatches remain failures.
- **Wycheproof PBES2 runtime rejects**: Kryoptic FIPS/PQC reached advertised
  `CKM_PKCS5_PBKD2` plus `CKM_AES_CBC_PAD`, then returned `CKR_DEVICE_ERROR`
  during valid-vector key derivation. PBES2 setup and decrypt CKRs are now
  visible xfail findings, while successful decrypts still have to match the
  expected plaintext.
- **Wycheproof PBKDF2 runtime rejects**: standalone PBKDF2 Wycheproof vectors
  now use the same visible-finding path for advertised valid-vector
  `C_GenerateKey` rejects such as `CKR_DEVICE_ERROR`. Successful derivations
  still have to match the expected derived key bytes.
- **Wycheproof ECDSA/DSA valid verify rejects**: Kryoptic P-521/SHAKE ECDSA
  and NSS source DSA vectors reached advertised verify mechanisms but returned
  runtime CKRs such as `CKR_DEVICE_ERROR` or `CKR_ARGUMENTS_BAD` for valid
  signatures. These operation rejects are now visible xfail findings. A valid
  signature that cleanly verifies as false, or returns a signature-invalid
  result, remains a hard failure.
- **ACVP RSA SigVer setup/result split**: RSA PKCS#1/PSS verification vectors
  now handle public-key import separately from the verification operation.
  `CKR_ATTRIBUTE_VALUE_INVALID`, key-size, or template rejection while
  importing the ACVP public key is a setup capability skip; the same class of
  unexpected CKR from the actual verify call is not converted into a skip.
  ACVP RSA-PSS SHAKE mask-function rows are handled earlier as
  PKCS#11-unexpressible vectors, because current `CK_RSA_PKCS_MGF_TYPE`
  constants cannot represent `shake-128` or `shake-256`.
- **ACVP AES CFB/OFB simple-mode runners**: TPM2 CFB128 returned
  `CKR_GENERAL_ERROR` for valid encrypt/decrypt vectors. The simple and MCT
  runners now classify explicit generic runtime rejects as xfail while keeping
  wrong ciphertext/plaintext as failures. BouncyHSM CFB128/CFB8/OFB
  multiblock rows are ACVP MCT vectors, not ordinary short KATs: each selected
  test performs 100 blocks times 1,000 PKCS#11 encrypt/decrypt calls. The
  current BouncyHSM artifacts therefore prove that these tests exceed the
  configured 5s or 20s per-test timeout budget, and CFB8 additionally produced
  confirmed `C_Encrypt`/`C_Decrypt` segfaults in subprocess confirmation. Do
  not describe the timeout-only CFB128/OFB rows as cryptographic mismatches
  without a longer rerun; they remain visible timeout findings under the chosen
  validation budget.
- **SHA3/SHAKE key derivation**: the standalone SHA3/SHAKE KDF tests now match
  OASIS v3.2 sections 6.20.5 and 6.28-6.32. SHA3 derivation is SHA-1-style
  derivation over the base key value, and SHAKE derivation expands the input
  key; neither path uses `CK_KEY_DERIVATION_STRING_DATA`. SHA3 output lengths
  now use the digest size for the selected mechanism, so SHA3-224 no longer
  requests an invalid 32-byte output. Explicit `C_DeriveKey` CKR rejects are
  still reported as xfail advertised-but-not-operational evidence.
- **ACVP/Wycheproof EdDSA public-key encoding**: the local OASIS PKCS#11 spec
  tree requires raw RFC 8032 public-key bytes for `CKK_EC_EDWARDS`
  `CKA_EC_POINT`, while several current providers differ in practice. The
  vector tests now probe a known-good EdDSA signature first, trying raw and
  DER-wrapped points plus both observed `CKM_EDDSA` parameter modes, then use
  the working profile for cryptographic coverage. The standalone
  `test_eddsa_public_key_encoding_support` test keeps the spec-facing result
  visible: raw support is a clean pass, DER-only support is xfail evidence.
- **ACVP EdDSA key verification**: valid EdDSA public-key import rejected with
  explicit CKR values is now xfail evidence for an advertised EDDSA path that
  cannot import usable ACVP public keys. Accepting an invalid EdDSA key remains
  a hard failure because that is the actual negative key-verification result.
- **ACVP EdDSA SigVer public-key import**: SigVer now follows the same split as
  KeyVer. Unsupported curves remain skips, but `CKR_FUNCTION_FAILED` and other
  generic runtime rejects from ACVP public-key import become visible xfail
  evidence instead of raw harness failures.
- **ACVP EdDSA sign runtime rejects**: keygen and SigGen vectors now distinguish
  setup from use. Once a key is generated or imported, explicit EdDSA sign/use
  CKRs such as `CKR_DEVICE_ERROR` are visible xfail evidence for an advertised
  but non-operational path. Deterministic EdDSA signature mismatches remain
  real failures.
- **Signature-vector `CKR_FUNCTION_NOT_SUPPORTED` rejects**: advertised
  signature mechanisms that reach `C_VerifyInit` and then return
  `CKR_FUNCTION_NOT_SUPPORTED` are now classified with the same non-clean xfail
  policy as `CKR_FUNCTION_FAILED` and `CKR_DEVICE_ERROR`. This preserves the
  finding without treating a provider's runtime CKR as a harness exception.
- **ACVP SLH-DSA runtime rejects**: valid SigVer vectors now get a valid-signature
  runtime-reject xfail reason instead of being described as invalid-signature
  rejects. Keygen roundtrip and SigGen sign operation CKRs are also visible
  xfail evidence for advertised but non-operational SLH-DSA paths.
- **Mechanism-driven encryption**: roundtrip setup now skips when the required
  keygen mechanism is absent and xfails when advertised key generation rejects
  at runtime. KAT encrypt/decrypt paths now xfail explicit runtime CKRs but
  still fail ciphertext mismatches. `CKR_KEY_TYPE_INCONSISTENT` during
  encrypt initialization with the registry-selected key type is treated the
  same way: advertised-but-not-operational capability evidence, not a
  ciphertext failure.
- **Older general AES/access-control tests**: AES secret-key tests now probe
  `AES_KEY_GEN` before using it. General AES encryption and AES mode smoke
  tests use 128-bit setup keys unless they are explicitly checking AES key-size
  coverage, so providers are not failed just because an otherwise unrelated
  test chose AES-256 setup material. Missing keygen is a skip; advertised
  keygen returning explicit setup errors is an xfail finding. This removes
  keygen setup capability from provider-failure buckets without suppressing the
  actual encryption, mode, or access-control checks.
- **SO-login probes without an SO PIN**: tests that use the configured user PIN
  as a best-effort SO PIN now treat `CKR_PIN_INCORRECT` as counted setup skip
  evidence. This does not change probes where the SO login is actually
  reached; it prevents BouncyHSM-style "SO PIN differs from user PIN" setups
  from being reported as session-state or access-control failures.
- **Authenticated-wrap v2.40 availability probe**: the negative v3.2 API
  availability test now uses the same operational AES setup guard and 128-bit
  setup key policy. Providers that cannot generate setup AES keys after
  advertising `AES_KEY_GEN` are reported as setup xfail evidence instead of
  failing before the authenticated-wrap API behavior is reached.
- **Authenticated-wrap generated-IV path**: v3.2 authenticated wrap calls that
  reach `C_WrapKeyAuthenticated` and receive an explicit CKR reject are reported
  as xfail advertised-but-not-operational evidence. Missing API symbols remain
  skips, but runtime `CKR_FUNCTION_NOT_SUPPORTED` is no longer a clean skip.
- **TLS 1.2 key-and-MAC derivation**: `CKM_TLS12_KEY_AND_MAC_DERIVE` and
  `CKM_TLS12_KEY_SAFE_DERIVE` tests now follow the PKCS#11 return contract for
  key-material mechanisms: `C_DeriveKey` receives `phKey=NULL_PTR`, and the
  test validates the handles returned in `CK_SSL3_KEY_MAT_OUT` instead of
  reading a non-existent primary derived-key handle.
- **Message API generated IV/nonce writeback**: the AES-GCM/AES-CCM message
  tests intentionally remain hard failures when `C_EncryptMessage` returns
  `CKR_OK` but leaves the generated IV, nonce, or tag/MAC output buffer empty.
  The local packer tests verify that pkcs11-check exposes writable output
  buffers, so this artifact bucket is retained as provider writeback evidence.
- **Hash-ML-DSA sign probes**: providers that advertise `CKM_HASH_ML_DSA` but
  reject the sign operation with `CKR_DATA_LEN_RANGE` or `CKR_GENERAL_ERROR`
  are reported as advertised-but-not-operational xfail evidence. Successful
  signatures must still verify, and accepted tampered signatures remain hard
  failures.
- **VerifySignature multipart API**: the multipart `C_VerifySignature*` test no
  longer depends on multipart RSA-PKCS signing just to create setup data. It
  now creates the valid signature with single-shot `C_Sign` and exercises only
  the `C_VerifySignatureInit`/`Update`/`Final` path under test.
- **VerifySignature wrong-signature result**: `C_VerifySignature` no longer
  treats `CKR_DEVICE_ERROR` as a clean wrong-signature result. Clean signature
  rejects still pass, while generic/non-clean CKRs are reported as xfail
  evidence under the shared signature-result policy.
- **VerifyMessage wrong-signature result**: `C_VerifyMessage` now uses the same
  negative-signature split. `CKR_SIGNATURE_INVALID`/length-range are clean
  rejects, generic runtime CKRs are xfail evidence, and unexpected CKRs still
  fail the test instead of being collapsed into `False`.
- **ACVP RSA SigVer runtime rejects**: RSA public-key import still skips only
  when the key cannot be created. If import succeeds and `C_Verify` returns a
  non-clean runtime CKR such as `CKR_ATTRIBUTE_VALUE_INVALID`, the vector is
  reported as xfail evidence for an advertised verify path rather than as a
  setup skip or an unclassified raw failure.
- **Verify state CKR constants**: state-machine tests now use generated
  `CKR_SIGNATURE_INVALID` and `CKR_SIGNATURE_LEN_RANGE` constants instead of
  stale literal values when tolerating modules that prioritize signature checks
  over operation-state checks.
- **Miscellaneous KDF derive rejects**: `CKM_EXTRACT_KEY_FROM_KEY` now treats
  `CKR_ATTRIBUTE_VALUE_INVALID` at `C_DeriveKey` as an advertised mechanism
  rejected at runtime. Providers that return `CKR_OK` but derive the wrong
  bytes remain hard failures.
- **Mechanism-driven derive rejects**: the generic advertised-mechanism derive
  sweep now uses the same split as the dedicated KDF tests. BouncyHSM
  `CKM_EXTRACT_KEY_FROM_KEY` template rejects, NSS HKDF base-key generation
  rejects, and SoftHSM DES/DES3 encrypt-data derive rejects are reported as
  xfail evidence after the mechanism is advertised. Successful derives still
  have to return a non-zero handle, and wrong derived key material remains a
  hard failure in the dedicated value-checking tests.
- **DES/Salsa20/BLAKE2 edge probes**: DES modes that return
  `CKR_KEY_TYPE_INCONSISTENT`, Salsa20 encryption that returns
  `CKR_GENERAL_ERROR`, and BLAKE2 empty-message digesting that returns
  `CKR_ARGUMENTS_BAD` are now classified as explicit
  advertised-but-not-operational xfail evidence. If these mechanisms return
  `CKR_OK`, the tests still compare the actual ciphertext, plaintext, or
  digest bytes.
- **Mechanism-driven digest coverage**: generic digest smoke and KAT tests now
  use the same classification as the standalone BLAKE2 probes. If an advertised
  digest mechanism rejects the operation with a specific runtime CKR such as
  `CKR_ARGUMENTS_BAD`, it is reported as xfail evidence. If the digest succeeds,
  output length and known-answer bytes remain hard checks.
- **Standalone SHA KAT empty-message rejects**: the NIST SHA KAT file now uses
  the same digest runtime split. Missing SHA digest mechanisms are counted
  skips, and advertised SHA-1/SHA-2 KAT operations that reject valid vectors,
  including the empty-message vectors seen in BouncyHSM artifacts with
  `CKR_ARGUMENTS_BAD`, are visible xfail evidence. A successful digest still
  has to match the KAT bytes exactly.
- **GOST HMAC setup**: `CKM_GOSTR3411_HMAC` key import/template rejection is
  classified as an advertised-but-not-operational xfail. A successful setup
  still has to sign, verify, and reject wrong behavior normally.
- **AES-KEY-WRAP-PKCS7 unwrap template**: the standalone AES wrap/unwrap test
  no longer supplies `CKA_VALUE_LEN` when unwrapping an AES key whose wrapped
  bytes already determine the length. `CKA_VALUE_LEN` remains reserved for
  raw-block unwrap cases, matching the mechanism-driven wrap tests.
- **SSL3 pre-master generation**: legacy `CKM_SSL3_PRE_MASTER_KEY_GEN`
  returning `CKR_ATTRIBUTE_VALUE_INVALID` is classified as an advertised
  mechanism rejected at runtime. Successful generation still checks the
  48-byte value and embedded SSL version.
- **Buffer-size AES ECB smoke tests**: the input-size buffer tests now use the
  same AES setup policy. They still test one-block through 1 MiB AES-ECB buffer
  behavior, but they no longer turn an unrelated AES-256 setup-key rejection
  into a buffer-management failure. A focused pkcs11-mock setup-classifier
  batch now confirms the old setup failures are gone; the remaining
  `test_buffers.py` failures are AES imported-key readbacks returning the mock
  placeholder `Hello world!` instead of the requested key bytes. A focused TPM2
  setup-classifier batch reports 22 passed, 5 xfailed, and 0 failed for this
  file.
- **General RSA/EC setup paths**: RSA-OAEP, RSA wrapping, padding-oracle,
  key-lifecycle, tool-template, sign-recover, ECDSA nonce-quality, and
  mechanism-driven keypair helpers now treat advertised keypair generation
  rejected at runtime as xfail setup evidence. Wrong crypto output, accepted
  invalid input, crashes, and timeouts still fail.
- **AES-CBC-PAD padding-oracle setup**: AES padding-oracle and timing probes
  now use the same operational AES setup policy as other non-key-size tests.
  They use AES-128 fixture keys and report advertised `AES_KEY_GEN` runtime
  rejects as setup xfail evidence, while keeping distinct decrypt outcomes,
  accepted corrupted ciphertext, and timing gaps as hard security findings.
- **Generic-secret HMAC smoke tests**: imported HMAC keys that reach
  `C_SignInit`/`C_Sign` and receive explicit runtime rejects are now xfailed,
  matching the ACVP HMAC classification.
- **Mechanism-driven sign coverage**: `test_mech_sign.py` now uses the same
  split for advertised signing mechanisms. Valid sign/verify operations that
  return explicit runtime rejects become xfail findings, tampered-signature
  verification still fails if the provider accepts the tampering, and non-clean
  tampered-signature rejects use the shared signature policy. Known-answer tests
  skip only when their setup requires importing a private-key form that the
  provider rejects before any sign operation is reached.
- **Mechanism-driven multipart coverage**: multipart encrypt/decrypt, digest,
  sign, and verify now use the same advertised-but-not-operational split.
  Explicit CKR runtime rejects from the PKCS#11 operation become xfail findings,
  while ciphertext, plaintext, digest, signature, crash, and timeout mismatches
  remain failures. The old OpenCryptoki multipart rows for DES CFB/OFB
  `CKR_KEY_TYPE_INCONSISTENT`, AES-CTS/HASH-ML-DSA `CKR_FUNCTION_FAILED`,
  EDDSA/HMAC `CKR_MECHANISM_INVALID`, and SSL3 MAC `CKR_KEY_SIZE_RANGE`
  key-generation rejects are covered by the current runtime/setup
  classification and should be treated as stale raw-failure artifacts until the
  provider matrix is refreshed.
- **Standalone multipart streaming smoke coverage**: the older standalone
  streaming file now follows the same split as the mechanism-driven multipart
  tests. Missing AES/SHA/RSA/HMAC mechanisms skip, advertised AES/RSA setup
  rejects xfail, imported AES/HMAC setup keys set `CKA_ALLOWED_MECHANISMS`, HMAC
  setup can fall back from typed HMAC keys to generic-secret keys, and valid
  operation rejects become xfail evidence. `CKR_BUFFER_TOO_SMALL` from an
  advertised HMAC sign path is also treated as non-clean runtime evidence here;
  dedicated buffer tests retain direct coverage for buffer-size semantics.
  Output mismatches and actual crashes/timeouts remain failures. A focused
  current pkcs11-mock rerun reports all 20 standalone multipart rows skipped and
  0 failed, so the old pkcs11-mock `CKR_MECHANISM_INVALID` rows are stale. A
  focused current TPM2 rerun reports 8 passed, 12 xfailed, and 0 failed. The
  old TPM2 `CKR_FUNCTION_NOT_SUPPORTED`/`CKR_GENERAL_ERROR` hard rows are stale;
  BouncyHSM zero-length SHA-256 rows still need current reruns before article
  wording uses them as hard failures.
- **Legacy multipart smoke coverage**: the older `test_multipart.py` smoke file
  now uses the same capability/setup split before digest, AES-ECB, and
  RSA/SHA-256 sign checks. Missing mechanisms become counted skips; advertised
  setup or operation CKRs become visible xfail evidence. The AES rows use
  AES-128 setup keys because these rows test larger payload/block-count smoke
  behavior, not AES-256 key-size support. A focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-multipart-r2-20260527/` reports all 9 rows
  skipped and 0 failed, so the old pkcs11-mock `test_multipart.py`
  `CKR_MECHANISM_INVALID` rows are stale missing-capability artifacts.
- **General SHA digest coverage**: the general digest tests now skip missing
  SHA-family mechanisms before calling `C_Digest`, xfail explicit runtime
  rejects from advertised digest operations, and classify advertised-but-rejected
  AES setup before `C_DigestKey`. `CKR_FUNCTION_NOT_SUPPORTED` from
  `C_DigestKey` itself remains a clean optional-function skip. Digest output
  mismatches and wrong lengths after `CKR_OK` remain hard failures. A focused
  current pkcs11-mock rerun still reproduces the SHA-1 digest mismatch after
  `CKR_OK`, so that row is a mock crypto-output finding rather than setup
  noise. A focused current TPM2 rerun reports 15 passed, 2 skipped, 3 xfailed,
  and 0 failed for this file.
- **Standalone KAT AES-ECB coverage**: the standalone NIST KAT file now guards
  AES-ECB before importing AES test keys. pkcs11-mock does not advertise
  `CKM_AES_ECB`, so the old standalone AES KAT `CKR_MECHANISM_INVALID` rows
  are stale missing-capability artifacts, not cryptographic failures. If a
  provider advertises AES-ECB but rejects valid KAT key import, encrypt, or
  decrypt with an explicit CKR, the row is visible xfail evidence. Ciphertext,
  plaintext, and digest mismatches after `CKR_OK` remain hard failures. A
  focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-kat-r2-20260527/` reports 2 failed,
  18 skipped, and 1 xfailed; the two hard rows are SHA-1 digest mismatches.
- **Legacy sign/key-management coverage**: `test_sign.py` now checks RSA sign
  mechanisms before RSA setup and reports advertised RSA sign/verify rejects as
  visible xfail evidence. `test_keymgmt.py` now uses shared AES/RSA/EC setup
  classifiers and skips missing AES-ECB before AES import/copy roundtrips. A
  focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-sign-keymgmt-r2-20260527/` moved the slice
  from 2 passed / 14 failed / 12 skipped to 2 passed / 4 failed / 22 skipped.
  The remaining hard rows are key-management readback findings: blank imported
  AES key type, placeholder exported AES values, and blank RSA modulus.
- **Resource/stress setup coverage**: the legacy resource and stress files now
  use the same setup boundary as the rest of the suite. Missing AES/SHA/RSA
  mechanisms skip before fixture setup, advertised setup/operation CKR rejects
  become visible xfail evidence, and only exact `CKR_SESSION_COUNT` while
  opening an additional session is treated as a capacity skip. A focused
  pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-resource-stress-r2-20260527/` moved the slice
  from 1 passed / 16 failed to 16 skipped / 1 failed. The remaining hard row is
  `test_rapid_random_1000`, where all generated 32-byte random values are
  identical `0x01` bytes.
- **RNG sanity coverage**: a focused pkcs11-mock rerun of `test_rng.py` in
  `artifacts/_focused/pkcs11-mock-rng-current-20260527/` confirms the same
  random-output problem without setup noise. `C_GenerateRandom` succeeds, but
  returns repeated `0x01` bytes, so duplicate-sample, bit-frequency,
  byte-distribution, Shannon-entropy, and runs-test assertions fail. These rows
  should stay hard provider/mock behavior findings.
- **General error-path setup coverage**: `test_errors.py` now applies the same
  split to broad negative and edge-case rows. Missing AES/SHA/RSA mechanisms are
  capability skips before setup. Advertised AES/RSA setup rejects are xfail
  evidence, so TPM2-style key-generation failures no longer obscure the target
  invalid-parameter, empty-input, destroyed-key, or multi-operation check. The
  invalid AES key-size row still treats real key-size/template/argument CKRs as
  the target negative result; only function-unavailable evidence is xfail. A
  focused current TPM2 rerun reports 9 passed, 8 xfailed, and 0 failed for this
  file.
- **Mechanism attribute readback**: mechanism-generated key attribute tests now
  distinguish attribute read support from attribute value correctness. A module
  that rejects `C_GetAttributeValue` with a non-clean CKR such as
  `CKR_ATTRIBUTE_VALUE_INVALID` is reported as xfail evidence. A generated key
  that exposes `CKA_LOCAL=False` is also reported as xfail compliance evidence:
  it is not a clean pass, but it is a specific known PKCS#11 deviation rather
  than an unclassified harness/provider crash bucket.
- **Mechanism keygen `CKA_LOCAL` readback**: the lightweight keygen-local test
  now uses the same classification as the attribute-focused test. Missing or
  unsupported `CKA_LOCAL` readback is not counted as a wrong-value assertion,
  non-clean readback CKRs become xfail evidence, and `CKA_LOCAL=True` remains
  the only clean pass for generated keys.
- **General object attribute/setup coverage**: `test_object.py` now uses the
  shared AES/RSA/EC setup classifiers for object-label, object-search, keypair,
  and RSA import-copy rows. Generated RSA public attributes are validated before
  being reused as import input, so malformed readback becomes setup xfail
  evidence for the import-copy row. Dedicated readback rows remain strict:
  wrong or blank `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_MODULUS`,
  `CKA_PUBLIC_EXPONENT`, or `CKA_VALUE` after successful setup are still hard
  failures. A focused current pkcs11-mock rerun leaves five such strict
  failures: empty RSA class/modulus/exponent attributes, empty AES key type, and
  `CKA_VALUE` returning the mock placeholder instead of the requested key bytes.
  A focused current TPM2 rerun reports 10 passed, 6 xfailed, and 0 failed for
  this file.
- **Data-object storage behavior**: `test_data_objects.py` now treats
  `CKR_SESSION_COUNT` while opening extra sessions for token persistence as a
  setup skip. The current pkcs11-mock rerun still leaves nine hard CKO_DATA
  findings: empty data-object values are rejected, readback returns placeholder
  values such as `Hello world!` / `Pkcs11Interop`, searches ignore labels,
  destroyed objects remain findable, and `CKA_CLASS` reads back as empty bytes.
- **Security key-flag coverage**: `CKA_NEVER_EXTRACTABLE`, `CKA_LOCAL`,
  `CKA_ALWAYS_SENSITIVE`, and AES-CBC-PAD flag tests now xfail explicit
  `AES_KEY_GEN` setup rejects instead of reporting an unrelated key-attribute
  failure. Imported-key `CKA_LOCAL` readback uses the same missing-attribute
  xfail rule as generated-key readback; actual wrong boolean values remain
  compliance xfail evidence.
- **Mechanism wrap/unwrap coverage**: mechanism-driven wrap tests now build
  registry-defined wrap parameters for RC2 and other parameterized mechanisms,
  use the existing NSS-safe output-size hint for `AES_KEY_WRAP_KWP`, and report
  explicit setup/wrap/unwrap CKR rejects as xfail evidence. Wrong unwrapped key
  material, such as the `RSA_X_509` leading-vs-trailing raw block bug, remains
  a real failure.
- **Mechanism flag coverage**: registry expected flags are now treated as
  expected capability coverage, not hard universal OASIS minima. A module that
  advertises a mechanism but omits expected operation flags is reported as an
  xfail partial-capability finding. A module that advertises an operation flag
  and then rejects the matching `C_*Init` call with
  `CKR_MECHANISM_INVALID`/`CKR_FUNCTION_NOT_SUPPORTED` remains a real
  conformance failure.
- **Stateful AES lifecycle setup**: stateful lifecycle tests now use AES-128 for
  setup keys, matching the operational AES keygen probe. These tests are about
  session/object lifecycle, not AES-256 support. If advertised AES setup still
  rejects during the lifecycle path, the specific CKR is reported as an xfail
  setup finding instead of a raw setup failure.
- **Access-level setup paths**: SO/USER/public visibility tests now use the
  shared operational AES setup guard and AES-128 setup keys where the AES key is
  only a fixture for access-control behavior. Data-object setup rejections such
  as TPM2's `CKR_ATTRIBUTE_VALUE_INVALID` on `CKA_PRIVATE=False` are xfailed as
  setup evidence for the visibility tests instead of being counted as failed
  visibility assertions. The `CKA_TRUSTED` SetAttributeValue path now matches
  exact CKR values rather than CKR-name substrings, and the
  `CKA_WRAP_WITH_TRUSTED` fallback to `CKM_AES_CBC_PAD` now supplies the
  required IV parameter. The older `test_access.py` file now follows the same
  boundary: missing AES key generation and `CKR_SESSION_COUNT` while opening an
  extra fixture session are setup skips, while successful setup still leaves the
  access-control assertions strict.
- **TPM2 session/object semantics after setup cleanup**: a focused current TPM2
  setup-classifier rerun (`artifacts/_focused/tpm2-setup-classifiers-current-20260526-r3/`)
  reduces the selected setup-heavy files to five hard failures. These are not
  setup noise: private keys are visible in a public session before login,
  session-object secret-key creation and session-keypair generation in RO
  sessions return `CKR_SESSION_READ_ONLY`, and session objects survive their
  owning session close in two object-visibility rows.
- **CKR wrap setup guards**: old `test_ckr_wrap.py` failures for SoftHSM2, TPM2,
  and pkcs11-mock were rerun on current source. SoftHSM2 reports 6 passed and
  0 failed, while TPM2 and pkcs11-mock both report 6 capability skips and
  0 failed because they do not advertise the AES key-wrap mechanism needed for
  the CKR wrap rows. These old hard failures are stale setup/capability
  artifacts, not current provider wrap findings.
- **Access-control attribute setup keys**: the separate CKA_PRIVATE,
  CKA_MODIFIABLE, CKA_COPYABLE, and C_CopyObject tests now use AES-128 setup
  keys for neutral fixture objects. Tests where the template attribute itself is
  under test, such as `CKA_MODIFIABLE=False` or `CKA_COPYABLE=False`, still keep
  their specific rejection handling. Copying a non-copyable key remains a hard
  security failure.
- **API-security setup paths**: the broader `security/test_api_security.py`
  file now separates setup capability from security outcomes. Missing
  `AES_KEY_GEN`, non-operational AES/RSA setup, and `CKR_SESSION_COUNT` while
  opening the public fixture session are no longer reported as security
  failures or silent security passes. The current pkcs11-mock focused rerun
  leaves one hard finding: `CKA_PRIVATE_EXPONENT` is readable after RSA setup
  succeeds.
- **AES-KWP corrupted-data error path**: the old crash-regression harness for
  OpenCryptoki PR #932 and OpenSSL PR #30663 had two masking problems. First,
  generated child scripts could exit with a Python error and still be counted as
  "no crash" because only negative signal return codes were rejected. Second,
  the `C_Decrypt` branch over-allocated the output buffer, so it could not
  expose OpenSSL's `CRYPTO_128_unwrap_pad()` error-path overwrite. The harness
  now rejects positive child exits, keeps the generated script under its
  `try/finally`, and uses a minimal output buffer with guard bytes for
  corrupted AES-KWP decrypt attempts. A current Docker rerun against
  OpenCryptoki master built with OpenSSL 4.0.0 reports 8 AES-KWP decrypt
  guard-overwrite failures and 34 clean no-crash rows in
  `test_error_path_kwp.py`; evidence is retained in
  `artifacts/_focused/opencryptoki-master-error-path-current-20260527/`. This
  means the old OpenCryptoki artifacts that showed 42/42 passes for this file
  were false negatives for the OpenSSL-side KWP finding.
- **RSA decrypt error-path child scripts**: the same generated-script
  `try/finally` indentation problem existed in the RSA PKCS#1/OAEP decrypt
  error-path tests. The scripts are now built through one helper that indents
  the malformed-ciphertext setup and decrypt body under the key-generation
  `try`, and meta-tests compile representative PKCS#1 and OAEP variants. Older
  provider artifacts that show this file as fully passing should be treated as
  suspect no-crash evidence until the file is rerun with current source. A
  current Docker rerun against OpenCryptoki master built with OpenSSL 4.0.0
  reports all 8 RSA error-path rows passing, so the corrected OpenCryptoki
  finding is AES-KWP-specific, not RSA.
- **Subprocess result policy**: crash-survival helpers now share the same
  result rule: negative return code is a crash finding, positive return code is
  a child-script failure, and only return code 0 can be considered a completed
  no-crash probe. This policy is now used by the security subprocess helpers,
  mutex callback safety probes, and the OpenSSL interop wrapper. Most other raw
  subprocess tests already require `rc == 0` or required stdout markers, so a
  generated-script syntax/runtime error fails instead of becoming a no-crash
  pass.
- **Local syntax/generated-script gate**: meta-tests now parse every Python
  source file under `src/` and `tests/`, compile representative AES-KWP and RSA
  generated crash-regression child scripts, and check the shared subprocess
  result policy. This gives a fast local guard against broken test code before a
  long provider run turns it into misleading provider evidence.
- **OpenCryptoki PR #932 source-path audit**: PR #932 fixed the OpenCryptoki
  common `aeskw_unwrap_pad()` fallback by cleansing `*out_data_len` bytes on
  error, not the input length. It did not fix the swtok path. Current
  OpenCryptoki master still registers `token_specific_aes_key_wrap` for swtok,
  that function still calls `openssl_specific_aes_key_wrap()`, and
  `CKM_AES_KEY_WRAP_KWP` still maps to OpenSSL `EVP_aes_*_wrap_pad()`. OpenSSL
  PR #30663 remains unmerged, and OpenSSL master still contains the corresponding
  `OPENSSL_cleanse(out, inlen)` cleanup in `CRYPTO_128_unwrap_pad()`. Therefore
  "the swtok crash disappeared" should be described as previous harness/build
  behavior, not as an upstream OpenSSL-path fix.
- **Key-size and metamorphic setup paths**: AES key-size checks and metamorphic
  invariants now use the shared advertised-keygen setup classification. Missing
  `AES_KEY_GEN`, `RSA_PKCS_KEY_PAIR_GEN`, or `SHA256_RSA_PKCS` stays a skip,
  while explicit runtime rejection after advertisement is an xfail setup
  finding. Roundtrip, determinism, copy-equivalence, and wrong-output
  assertions still fail when the setup succeeds and the cryptographic invariant
  is wrong. A focused pkcs11-mock key-size rerun in
  `artifacts/_focused/pkcs11-mock-key-sizes-r2-20260527/` moves the old RSA
  sign rows to skips and leaves six hard readback findings: AES key export
  returns a placeholder value, and RSA public modulus reads back as empty bytes.
- **ECDSA prehash negative verification**: tampered-data checks for
  `CKM_ECDSA_SHA*` now use the same invalid-signature policy as Wycheproof,
  ACVP, and mechanism-driven sign tests. Clean signature rejects pass the
  negative test; non-specific rejects such as `CKR_DEVICE_ERROR` are visible
  xfail evidence; accepting the tampered signature remains a hard failure.
- **ML-KEM AES decapsulation key-size templates**: the AES-128/192/256
  decapsulation coverage now includes `CKA_VALUE_LEN` in both encapsulation and
  decapsulation templates, so the parametrized cases actually request different
  target key sizes. Explicit KEM operation or template rejects after `ML_KEM`
  advertisement are reported as xfail evidence; mismatched shared-secret bytes
  remain hard failures.
- **ML-KEM operation and negative-test classification**: generic encapsulation,
  decapsulation, ciphertext-size, and key-derivation smoke paths now share the
  same advertised-operation xfail handling. OpenCryptoki-style
  `CKR_TEMPLATE_INCONSISTENT` from `C_EncapsulateKey` setup is therefore a
  visible partial-capability finding rather than a raw harness failure or a
  skip. Negative ML-KEM probes still require a clean semantic reject: accepting
  `CKA_VALUE` in a decapsulation template becomes xfail evidence, and
  non-specific rejects such as `CKR_GENERAL_ERROR`, `CKR_DEVICE_ERROR`, or
  `CKR_OBJECT_HANDLE_INVALID` are visible xfail findings rather than passes.
- **EC public import/export roundtrip**: generated EC keys can still be a
  valid setup path even when a provider later rejects importing the exported
  public point as a new object. The EC import/export test now reports specific
  public-key import CKR rejects as xfail import-capability evidence, while a
  successful import must still verify the signature with the imported key.
- **Security fuzz and CKR negative-test setup**: AES/RSA setup for mechanism
  parameter fuzzing and encrypt/decrypt CKR negative tests now uses the shared
  setup classification. These tests still exercise bad IVs, non-aligned input,
  wrong mechanism/key combinations, and CKR priority when setup succeeds, but
  advertised key-generation rejects are reported as setup xfail evidence rather
  than hiding the target negative condition behind a raw setup assertion.
- **Property-fuzz setup classification**: Hypothesis-driven `test_fuzz.py`
  now preflights AES/digest/RSA/HMAC/ECDSA mechanisms and reports advertised
  setup or operation rejects as xfail evidence. The current pkcs11-mock rerun
  reports all 11 property-fuzz rows skipped because the needed mechanisms are
  not advertised; this replaces the old hard falsifying examples from missing
  AES, SHA-2, RSA-SHA256, and HMAC support.
- **Destroyed-handle reuse checks**: `security/test_handle_reuse.py` no longer
  catches arbitrary Python exceptions or accepts any non-OK CKR as a destroyed
  handle result. Missing AES/RSA/wrap mechanisms skip before setup, setup keys
  use the shared classifiers, and successful use of a destroyed handle is a hard
  failure. Operation returns are now checked against explicit handle-related
  CKRs. A focused pkcs11-mock rerun in
  `artifacts/_focused/pkcs11-mock-handle-reuse-r2-20260527/` moved the file
  from 1 passed / 5 failed / 1 skipped to 7 skipped.
- **Mechanism-negative setup**: the explicit wrong-key and missing-permission
  mechanism tests now use the same AES/RSA/EC setup guards. TPM-style
  `CKR_FUNCTION_NOT_SUPPORTED` during AES setup is reported as setup xfail
  evidence, while accepting an operation with the wrong key type remains a hard
  failure.
- **Security parameter-validation crash probes**: the parameter-validation
  file now carries `subprocess_per_test` for pkcs11-check isolated runs. The
  current BouncyHSM weak-RSA-exponent crashes are real provider crash findings;
  the marker keeps future runs on per-test units so one segfault does not hide
  the remaining parameter probes in that file.
- **CVE AES-ECB boundary-length cleanup**: the boundary-length regression now
  aborts an encrypt operation after an expected invalid-length reject before
  trying the next size. Old `CKR_OPERATION_ACTIVE` rows in that test can be
  harness contamination. The same test now fails if a non-zero
  non-block-aligned AES-ECB plaintext is accepted.
- **Padding-oracle decrypt-state cleanup**: RSA and AES padding-oracle probes
  now abort decrypt state after expected invalid-ciphertext rejects before
  sending the next probe. Old `CKR_OPERATION_ACTIVE` rows in these tests can
  be harness contamination. Distinct decrypt outcomes, accepted corrupted
  ciphertext, timing gaps, provider crashes, and subprocess signals remain
  hard security findings.
- **Digest/HMAC single-part termination checks**: BouncyHSM fuzz artifacts
  showed `CKR_OPERATION_ACTIVE` after repeated digest and HMAC single-part
  operations. This is now covered by explicit state-machine tests: after the
  real output call of a two-call `C_Digest` or HMAC `C_Sign`, pkcs11-check
  immediately starts a new operation on the same session and expects `CKR_OK`.
  Returning `CKR_OPERATION_ACTIVE` there remains a provider operation-state
  finding; it is not skipped or hidden by changing the fuzz tests.
- **Crash reporting policy**: provider subprocess crashes must fail with the
  signal preserved, not become `pytest.xfail` or `pytest.skip`. Dual-function
  raw probes, NULL-pointer raw CKR probes, NULL-parameter CKR probes, and
  `C_SessionCancel` crash branches now report hard failures. Static regression
  checks prevent future testcase xfails or skips from being used for actual
  crash or signal findings.
- **Mechanism encryption AEAD KAT sizing**: mechanism KAT encryption now uses
  the same AEAD tag overhead and `CKR_BUFFER_TOO_SMALL` retry path as mechanism
  roundtrip encryption. The older NSS `AES_GCM`/`CHACHA20_POLY1305` KAT
  buffer-size rows are pkcs11-check sizing artifacts and should be refreshed
  before being used as provider evidence.
- **Mechanism encryption RSA-OAEP smoke params and runtime rejects**:
  mechanism-driven RSA-OAEP encryption now uses SHA-1/MGF1-SHA1 compatibility
  parameters, matching the dedicated RSA-OAEP smoke tests, because PKCS#11 does
  not expose OAEP hash sub-capability discovery. Targeted SHA-384/SHA-512 OAEP
  tests remain separate. Valid advertised encrypt paths that still return
  `CKR_ARGUMENTS_BAD` or `CKR_ATTRIBUTE_VALUE_INVALID` are now visible xfail
  evidence rather than raw harness failures. The same classification now covers
  the dedicated SHA-384/SHA-512 rows in `test_rsa_oaep.py`; a focused SoftHSM2
  rerun passes the SHA-1 compatibility rows and leaves the broader hash/MGF
  rows as xfail evidence.
- **CKR RSA-OAEP garbage decrypt params**: `test_rsa_oaep_garbage` previously
  reached `C_DecryptInit(CKM_RSA_PKCS_OAEP)` with no
  `CK_RSA_PKCS_OAEP_PARAMS`, so several artifact rows were pkcs11-check setup
  artifacts rather than provider ciphertext-validation evidence. The test now
  uses SHA-1/MGF1-SHA1 OAEP params. Providers that still reject the advertised
  parameter set are reported as visible xfail runtime findings; providers that
  initialize successfully must exercise `C_Decrypt` on the malformed
  ciphertext.
- **Mechanism multipart AEAD reference sizing**: multipart decrypt roundtrip
  coverage now uses the same AEAD tag overhead and `CKR_BUFFER_TOO_SMALL` retry
  path when building the single-part ciphertext reference. Old multipart AEAD
  buffer-size rows should be treated as pkcs11-check sizing artifacts until the
  provider matrix is refreshed.
- **ACVP ECDH runtime rejects**: valid shared-secret vectors still require a
  matching derived value for a clean pass. When a provider advertises
  `CKM_ECDH1_DERIVE` but rejects the derive operation with generic runtime
  errors such as `CKR_DEVICE_ERROR` or `CKR_GENERAL_ERROR`, pkcs11-check now
  reports visible xfail evidence instead of a raw harness failure.
- **Skip accounting for provider-dependent pruning**: AES-CTS CS1/CS2/CS3
  variant selection now keeps non-matching variant nodes in the collected test
  universe as counted skips instead of deselecting them. Runner-level
  `REQUIRED_MECHANISMS` file short-circuits now synthesize skipped counts from
  the collected nodeids, so a missing mechanism does not silently shrink the
  reported total. Dynamic mechanism-driven tests remain provider-selected for
  now; the report does not synthesize skips for every unselected mechanism
  parameter.
- **Dual-function and operation-state setup guards**: `test_dual_function.py`
  and same-session `test_operation_state.py` rows now check AES/SHA setup
  mechanisms before launching raw subprocess scripts. This keeps pkcs11-mock's
  missing `AES_KEY_GEN`, `AES_CBC`, or `SHA256` support as counted skips rather
  than unrelated child-process setup failures. A current focused pkcs11-mock
  rerun in `artifacts/_focused/pkcs11-mock-dual-operation-r2-20260527/`
  reports 3 passed, 5 skipped, and 0 failed for the selected dual/state files.
  `C_SetOperationState` returning `CKR_ARGUMENTS_BAD` for a garbage state blob
  is recorded as a non-clean compliance note; state roundtrips, subprocess
  signals, positive child exits, and wrong digest/ciphertext output remain
  failures when the setup applies.
- **TPM2 remaining-gap setup split**: `test_remaining_gaps.py` now uses the
  shared AES setup classifier for template-constraint and AES-CMAC straggler
  rows, and records `CKR_FUNCTION_NOT_SUPPORTED` from legacy
  `C_GetFunctionStatus` / `C_CancelFunction` as a documented non-clean
  compliance note rather than a hard failure. The general function-list
  section permits unsupported API stubs, while the legacy parallel-function
  section still prefers `CKR_FUNCTION_NOT_PARALLEL`.
- **TPM2 subprocess-safety setup split**: cross-process session-object
  isolation now xfails parent `C_CreateObject` setup rejection instead of
  labelling it as a crash. A current focused TPM2 rerun in
  `artifacts/_focused/tpm2-remaining-sign-safety-r2-20260527/` reports
  6 passed, 23 skipped, 8 xfailed, and 1 failed across `test_remaining_gaps.py`,
  `test_sign_recover.py`, and `test_subprocess_safety.py`. The remaining hard
  row is still `test_fork_after_initialize` timing out after 15 seconds.

The arithmetic-overflow clusters for TPM2, SoftHSM2, OpenCryptoki, and
Kryoptic main were rechecked in the current pass. TPM2 is now reclassified to
setup xfail/skip evidence, while SoftHSM2, OpenCryptoki, and Kryoptic main
still show crash/abort or abnormal child-exit findings. Other sampled abort,
signal, and timeout clusters in BouncyHSM, Kryoptic, NSS, OpenCryptoki,
SoftHSM2, and TPM2 were not reclassified in this pass. They are
subprocess-isolated boundary or operation probes and remain failure/crash
evidence unless a later root-cause pass proves that a specific test input is
invalid for PKCS#11.

Other sampled all-fail rows still look provider-side rather than harness-side:
AES-CTS variant detection still fails when a provider advertises `CKM_AES_CTS`
but no CS variant can be probed, and the low-level raw CKR subprocess crash
probes still report process-level failures. The access-level tests still leave
real access-control findings visible, including private objects visible in a
public session, USER creation of `CKA_TRUSTED=True` keys, USER escalation of
`CKA_TRUSTED`, and wrapping a `CKA_WRAP_WITH_TRUSTED` target with an untrusted
wrapping key. Those should remain findings unless a narrower provider
configuration explanation is found.

## Provider-Specific Notes

- SoftHSM2 release has no runner-level crashes, but the security probes still
  show process failures in malformed-boundary calls. A focused current-source
  stock SoftHSM2 rerun of `test_ffi_length_boundary.py` reports five hard
  failures: signal 11 for `C_EncryptInit(CKM_AES_GCM, pIv=NULL, ulIvLen=12)`
  plus positive child exit code 5 for huge `ulDataLen` HMAC/SHA256
  `C_Sign`/`C_Digest` probes. The generated-IV variant removes the GCM null-IV
  crash in older artifacts through a local simulator patch, but that does not
  change the stock SoftHSM2 finding.
- Kryoptic release/main build against official OpenSSL 4.0.0. Their crash
  clusters are concentrated in boundary and NULL-parameter probes. Kryoptic
  FIPS/PQC has materially more crash evidence and is still a custom OpenSSL
  branch target, not an official OpenSSL 4.0.0 result.
- NSS stable and the earlier source-tip artifacts have similar crash shapes.
  Current `test-nss-pqc` now builds from official NSS/NSPR RTM tags, so its
  crash/failure evidence must be refreshed before being described as tagged
  NSS evidence. Existing source-built artifacts remove the stable ML-DSA failure
  cluster, but they do not remove the NULL-pointer, sign-flag, ML-KEM,
  HMAC/general, or security boundary findings. The older ECDH and DSA buckets
  are superseded by the follow-up loader findings above and should not be used
  as NSS provider evidence until the matrix is rerun.
- OpenCryptoki release and master currently resolve to the same commit, and
  their signal findings are the same boundary-probe class.
- TPM2 source is the current upstream headline; the Fedora package row is kept
  only as archived comparison evidence. Both show digest-boundary subprocess
  crashes and fork-after-initialize timeout behavior.
- BouncyHSM slowness should not be attributed to ".NET on Linux" from the
  current evidence. The artifacts prove a specific pathological tail in ACVP
  MCT-style CFB8, CFB128, and OFB multiblock provider calls, plus broad AES-CCM
  and ECDH failures. Runtime choice may be a hypothesis, but the evidence is
  mechanism and operation specific. If the goal is to distinguish "eventually
  passes but slow" from "never completes", rerun these BouncyHSM MCT segments
  with a much larger timeout budget and keep the timeout value in the report.
## Article-Relevant Takeaways

- A crash is a valid pkcs11-check finding. It should not be skipped just
  because the provider is otherwise usable.
- The article should avoid pass-rate ranking. The more defensible framing is
  behavioral coverage: which providers build, which mechanisms are reachable,
  which areas fail, and whether failures are ordinary CKR mismatches, isolated
  subprocess crashes, runner crashes, or build/configuration gaps.
- For BouncyHSM, use "segmented evidence" rather than "full monolithic run".
  The bounded segments are useful, but the stopped full run and timeout tail
  are part of the result.
- For proprietary or internal PKCS#11 providers, the practical message is that
  users can run the same suite locally and keep results private while still
  getting crash-surviving, mechanism-level evidence.

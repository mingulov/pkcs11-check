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
it is a mock baseline rather than a provider conformance result. `qryptotoken`
has no provider test findings because the Docker target fails before producing
a PKCS#11 module.

## Largest Failure Buckets

These are the largest failed test files per target. They are useful for article
wording because they show which areas dominate each provider's failure shape.

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
504 P-384 generic ECDSA tests and skips all 504. The remaining TPM2 generic
Wycheproof failures still need follow-up: AES-GCM, AES-CBC-PAD, and
HMAC-SHA256 are advertised, but provider operations return `CKR_GENERAL_ERROR`.

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
  issue like ECDH or DSA.
- **Kryoptic AES-CTS 405**: failures are mostly `CKR_DEVICE_ERROR` on encrypt
  after `CKM_AES_CTS` is advertised and selected. Kryoptic source maps
  `CKM_AES_CTS` to CTS mode CS1, and pkcs11-check's CTS test already detects
  the module variant before selecting CS1 vectors. No loader mismatch was found
  in this pass.
- **OpenCryptoki AES-XTS 382**: failures are ciphertext/plaintext mismatches,
  split across encrypt and decrypt, not parameter-import failures. OpenCryptoki
  advertises `CKM_AES_XTS` for `CKK_AES_XTS` keys, so this remains a provider
  behavior or provider/test-vector interpretation question rather than an
  obvious skip/configuration issue.
- **TPM2 AES-CFB128 2,144**: all simple encrypt/decrypt vectors plus the small
  multiblock tail fail with `CKR_GENERAL_ERROR`. tpm2-pkcs11 advertises
  `CKM_AES_CFB128` only when the TPM reports `TPM2_ALG_CFB`; the bucket looks
  like an advertised-but-not-operational backend path, not a pkcs11-check
  vector-shape issue.

## Provider-Specific Notes

- SoftHSM2 release has no runner-level crashes, but the security probes still
  show signal 11 in extreme template-count handling. The generated-IV variant
  removes the GCM null-IV crash observed in the release and main artifacts.
- Kryoptic release/main build against official OpenSSL 4.0.0. Their crash
  clusters are concentrated in boundary and NULL-parameter probes. Kryoptic
  FIPS/PQC has materially more crash evidence and is still a custom OpenSSL
  branch target, not an official OpenSSL 4.0.0 result.
- NSS stable and source-tip targets have similar crash shapes. Source-tip
  removes the stable ML-DSA failure cluster, but it does not remove the
  NULL-pointer, sign-flag, ML-KEM, HMAC/general, or security boundary
  findings. The older ECDH and DSA buckets are superseded by the follow-up
  loader findings above and should not be used as NSS provider evidence until
  the matrix is rerun.
- OpenCryptoki release and master currently resolve to the same commit, and
  their signal findings are the same boundary-probe class.
- TPM2 source is the current upstream headline; the Fedora package row is kept
  only as archived comparison evidence. Both show digest-boundary subprocess
  crashes and fork-after-initialize timeout behavior.
- BouncyHSM slowness should not be attributed to ".NET on Linux" from the
  current evidence. The artifacts prove a specific pathological tail in CFB8,
  CFB128, and OFB multiblock provider calls, plus broad AES-CCM and ECDH
  failures. Runtime choice may be a hypothesis, but the evidence is mechanism
  and operation specific.
- qryptotoken should be discussed as a build/configuration state, not as a
  conformance result: the current Docker target fails before module creation.

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

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
that specific curve with a known unsupported-curve/template CKR, because a
provider can reasonably support X25519 without supporting X448.

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
operational.

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

### Follow-Up: ACVP RSA-PSS Parameter Rejections

ACVP RSA still skips key sizes that a provider cannot generate or import, but
RSA-PSS parameter rejection after an advertised PSS mechanism is now xfail
evidence. This keeps mixed hash/MGF or salt-length limitations visible instead
of treating them as missing test capability.

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

ACVP ML-KEM now follows the same split. In the current NSS-main and NSS-PQC
artifacts, the 50-call ML-KEM failure bucket divides into 25 ML-KEM-512
public-key imports returning `CKR_PARAMETER_SET_NOT_SUPPORTED` and 25
ML-KEM-512 key-generation attempts returning `CKR_HOST_MEMORY`. The import
case is a narrower parameter-set capability result and now skips; the
`CKR_HOST_MEMORY` key-generation result remains a real provider finding. ML-KEM
runtime operation rejects after an advertised mechanism are xfail/failure
evidence, not capability skips. Full provider counts still require a matrix
rerun.

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
- **TPM2 HMAC runtime rejects**: tpm2-pkcs11 registers `CKM_SHA*_HMAC`
  mechanisms when the TPM reports `TPM2_ALG_KEYEDHASH` plus the matching hash
  algorithm. The ACVP HMAC failures reach that advertised mechanism path and
  then return `CKR_GENERAL_ERROR`, so they should be visible xfail findings
  rather than capability skips.
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
- **ACVP ML-DSA non-empty context on OpenCryptoki**: the OpenCryptoki artifact
  has a different ML-DSA SigGen shape from Kryoptic. `C_Sign` returns a
  signature, but the signature does not verify with the ACVP public key when the
  vector uses a non-empty ML-DSA context. Zero-context SigGen vectors do not
  show this shape in the same artifact. pkcs11-check passes the context through
  `CK_SIGN_ADDITIONAL_CONTEXT`, matching the PKCS#11 ML-DSA mechanism shape;
  OASIS also defines ML-DSA private-key `CKA_VALUE` as the FIPS 204 `sk`, which
  is the ACVP value imported by the test. This remains a hard provider finding:
  successful signatures must verify, while only explicit runtime CKRs are
  converted into xfail evidence.
- **Wycheproof AES operation rejects**: BouncyHSM CMAC, Kryoptic CCM,
  OpenCryptoki XTS, and NSS KWP vectors reached advertised AES mechanisms but
  returned runtime CKRs such as `CKR_GENERAL_ERROR`,
  `CKR_MECHANISM_PARAM_INVALID`, or `CKR_DATA_LEN_RANGE`. These are now visible
  xfail findings for valid vectors. Successful AES-KWP calls that return the
  wrong wrapped bytes or wrong length remain hard failures.
- **Wycheproof RSA-OAEP parameter/runtime rejects**: valid RSA-OAEP
  ciphertexts in SoftHSM2 and BouncyHSM artifacts reached an advertised
  `CKM_RSA_PKCS_OAEP` path, then rejected the decrypt operation with explicit
  CKRs such as `CKR_ARGUMENTS_BAD` or `CKR_GENERAL_ERROR`. These are now
  visible xfail findings for advertised-but-not-operational parameter support.
  Successful decrypts still have to match the Wycheproof plaintext, and
  accepted invalid ciphertext remains a hard failure.
- **Wycheproof RSA PKCS#1 decrypt runtime rejects**: Kryoptic FIPS/PQC reached
  advertised `CKM_RSA_PKCS` decrypt with valid Wycheproof ciphertexts and
  returned `CKR_DEVICE_ERROR`. Valid-vector runtime rejects are now visible
  xfail evidence, while wrong plaintext and accepted invalid ciphertexts remain
  hard failures.
- **Wycheproof HMAC operation rejects**: valid HMAC vectors in TPM2,
  SoftHSM2, and BouncyHSM artifacts reached advertised HMAC mechanisms but
  failed at key use with explicit CKRs such as `CKR_GENERAL_ERROR`,
  `CKR_KEY_HANDLE_INVALID`, or `CKR_KEY_SIZE_RANGE`. These are now visible
  xfail findings. If an invalid HMAC vector produces the supplied tag, the test
  still fails.
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
- **ACVP AES CFB/OFB simple-mode runners**: TPM2 CFB128 returned
  `CKR_GENERAL_ERROR` for valid encrypt/decrypt vectors. The simple and MCT
  runners now classify explicit generic runtime rejects as xfail while keeping
  wrong ciphertext/plaintext as failures. BouncyHSM CFB128 multiblock timeouts
  are unchanged: timeouts remain failures.
- **SHA3/SHAKE key derivation**: the standalone SHA3/SHAKE KDF tests now match
  OASIS v3.2 sections 6.20.5 and 6.28-6.32. SHA3 derivation is SHA-1-style
  derivation over the base key value, and SHAKE derivation expands the input
  key; neither path uses `CK_KEY_DERIVATION_STRING_DATA`. SHA3 output lengths
  now use the digest size for the selected mechanism, so SHA3-224 no longer
  requests an invalid 32-byte output. Explicit `C_DeriveKey` CKR rejects are
  still reported as xfail advertised-but-not-operational evidence.
- **ACVP EdDSA key verification**: valid EdDSA public-key import rejected with
  explicit CKR values is now xfail evidence for an advertised EDDSA path that
  cannot import usable ACVP public keys. Accepting an invalid EdDSA key remains
  a hard failure because that is the actual negative key-verification result.
- **ACVP EdDSA sign runtime rejects**: keygen and SigGen vectors now distinguish
  setup from use. Once a key is generated or imported, explicit EdDSA sign/use
  CKRs such as `CKR_DEVICE_ERROR` are visible xfail evidence for an advertised
  but non-operational path. Deterministic EdDSA signature mismatches remain
  real failures.
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
  into a buffer-management failure.
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
  remain failures.
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
  required IV parameter.
- **Access-control attribute setup keys**: the separate CKA_PRIVATE,
  CKA_MODIFIABLE, CKA_COPYABLE, and C_CopyObject tests now use AES-128 setup
  keys for neutral fixture objects. Tests where the template attribute itself is
  under test, such as `CKA_MODIFIABLE=False` or `CKA_COPYABLE=False`, still keep
  their specific rejection handling. Copying a non-copyable key remains a hard
  security failure.
- **Key-size and metamorphic setup paths**: AES key-size checks and metamorphic
  invariants now use the shared advertised-keygen setup classification. Missing
  `AES_KEY_GEN` or `RSA_PKCS_KEY_PAIR_GEN` stays a skip, while explicit
  runtime rejection after advertisement is an xfail setup finding. Roundtrip,
  determinism, copy-equivalence, and wrong-output assertions still fail when
  the setup succeeds and the cryptographic invariant is wrong.
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
  signal preserved, not become `pytest.xfail`. Dual-function raw probes and
  `C_SessionCancel` crash branches now report hard failures, and a static
  regression check prevents future testcase xfails from being used for actual
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
  evidence rather than raw harness failures.
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

The sampled abort, signal, and timeout clusters in BouncyHSM, Kryoptic, NSS,
OpenCryptoki, SoftHSM2, and TPM2 were not reclassified in this pass. They are
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
  show signal 11 in extreme template-count handling. The generated-IV variant
  removes the GCM null-IV crash observed in the release and main artifacts.
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
  current evidence. The artifacts prove a specific pathological tail in CFB8,
  CFB128, and OFB multiblock provider calls, plus broad AES-CCM and ECDH
  failures. Runtime choice may be a hypothesis, but the evidence is mechanism
  and operation specific.
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

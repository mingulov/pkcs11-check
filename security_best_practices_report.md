# Security Best Practices Report

Date: 2026-05-04

## Executive Summary

The audit covered dependency advisories, secret exposure, subprocess boundaries,
download/archive handling, weak-hash context, silent exception swallowing, and public
artifact hygiene for the Python CLI and pytest plugin.

No known dependency vulnerabilities were found. The confirmed issues were fixed with
regression coverage.

## Fixed Findings

### S1: Non-HTTPS Download Schemes Were Not Rejected

Impact: A modified source URL could make `fetch-data` read from local or non-HTTPS
schemes instead of the intended network source.

- Fixed in `src/pkcs11_check/cli/fetch_cmd.py`.
- Added URL validation before every `urlopen` call.
- Added regression coverage in `tests/test_data_paths.py`.

### S2: Zip Members Could Escape the Extraction Directory

Impact: A malicious archive entry could write outside the temporary extraction
directory during test-vector fetching.

- Fixed in `src/pkcs11_check/cli/fetch_cmd.py`.
- Added prefix and resolved-path checks for every extracted member.
- Added regression coverage in `tests/test_data_paths.py`.

### S3: OpenSSL Interop Helper Used `shell=True`

Impact: Shell invocation was unnecessary and widened the command execution surface.

- Fixed in `src/pkcs11_check/testcases/test_interop_openssl.py`.
- Commands now use argv lists and explicit stdin input.
- Added hygiene coverage in `tests/test_release_hygiene.py`.

### S4: Silent Broad `except Exception: pass` Patterns

Impact: Silent broad exception swallowing can hide real provider or test framework
defects.

- Replaced confirmed silent broad handlers with direct cleanup calls, specific
  `AssertionError` handling, or explicit mismatch failures.
- Added AST hygiene coverage in `tests/test_release_hygiene.py`.

### S5: SHA-1 Hashlib Uses Lacked Explicit Non-Security Context

Impact: Standards-required SHA-1 digests in tests could be misread as security
hashing.

- Updated SHA-1 calls to pass `usedforsecurity=False`.
- Added hygiene coverage in `tests/test_release_hygiene.py`.

### S6: Legacy Crypto Reference Calls Were Not Scanner-Annotated

Impact: AES-ECB and SHA-1 PKCS#11 compatibility checks were indistinguishable from
unsafe application-crypto usage in static-analysis output.

- Added narrow `nosec` annotations with comments for deliberate CKM_AES_ECB,
  CKM_SHA1_RSA_PKCS, CKM_SHA_1_HMAC, and OAEP SHA-1 reference checks.
- Added hygiene coverage requiring future legacy crypto reference calls to be
  explicitly annotated.

## Reviewed Non-Actionable Scanner Findings

- Bandit flags subprocess usage in `core/collection.py`, `core/file_runner.py`, and
  `core/preflight.py`. These calls use argv lists without shell execution and are
  central to crash isolation.
- Bandit flags `xml.etree.ElementTree` in `core/file_runner.py`; this code writes
  JUnit XML and does not parse untrusted XML.
- Bandit flags the Rich style string `"green"` as a password candidate; it is display
  styling only.
- Secret scanning reports high-entropy cryptographic test vectors and public test
  constants. No credentials or API tokens were identified in reviewed project code.

## Verification

The audit was verified with dependency audit, static security scans, targeted hygiene
tests, linting, type checking, unit tests, product-test collection, SoftHSM2 smoke,
package build, artifact scrub, and wheel install smoke.

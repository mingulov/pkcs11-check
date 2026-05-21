# Mutable Mechanism Parameter Gap Analysis

Date: 2026-05-04

This document records the gap analysis for Approach A: add a focused mutable
mechanism parameter audit track before broader provider-specific extension work.

The audit track covers PKCS#11 mechanisms where the mechanism parameter
structure is not only input. Some fields point to caller-owned buffers or nested
output structures that a provider can update during `C_Encrypt`,
`C_WrapKey`, `C_WrapKeyAuthenticated`, or `C_DeriveKey`.

## Approach A Scope

Approach A keeps four categories separate:

1. Raw packing coverage: ctypes structures, keepalive ownership, writable
   buffers, and `PackedMechanism.buffer_bytes()`.
2. Standard product tests: behavior required or described by the PKCS#11
   standard, gated by interface version and advertised mechanisms.
3. Vendor-profile tests: CloudHSM, Thales, and proxy/loader behaviors
   that are useful in real deployments but not universal PKCS#11 semantics.
4. Simulator coverage: software-only positive targets for workflows that stock
   open-source providers do not expose.

After the first Approach A implementation pass, MP-01 through MP-08 have
targeted raw and product-test coverage. The remaining release gaps are in-band
vendor IV modes, proxy/loader preservation profiles, and broader simulator
coverage.

## Current Baseline

The raw layer already exposes most mutable-output structures:

- `mech_gcm_generated_iv()` for classic `CKM_AES_GCM` provider-generated IV
  writeback.
- `mech_gcm_message_generated_iv()` and
  `mech_ccm_message_generated_nonce()` for v3 message AEAD outputs.
- `mech_gcm_wrap_generated_iv()` and `mech_ccm_wrap_generated_nonce()` for
  v3.2 wrap parameter outputs.
- `mech_ssl3_key_mat()`, `mech_tls12_key_mat()`, and `mech_wtls_key_mat()` for
  nested key-material output structures and IV buffers.

Meta-tests in `tests/test_raw_pack.py` verify that these buffers are writable
and observable after simulated provider writes. This is necessary, but it does
not prove that real providers write the fields during PKCS#11 operations.

## Gap Summary

| ID | Surface | Current state | Gap | Priority |
| --- | --- | --- | --- | --- |
| MP-01 | Classic `CKM_AES_GCM` IV writeback | Vendor-marked product tests and SoftHSM simulator exist | In-band output variants remain vendor-profile follow-up work | Done / P2 follow-up |
| MP-02 | `CK_GCM_WRAP_PARAMS.pIv` on `C_WrapKey` | Raw tests plus generated-IV wrap/unwrap product coverage | Positive execution depends on v3.2 AES-GCM wrap support | Done |
| MP-03 | `CK_CCM_WRAP_PARAMS.pNonce` on `C_WrapKey` | Raw tests plus generated-nonce wrap/unwrap product coverage | Positive execution depends on AES-CCM wrap support | Done |
| MP-04 | v3 message AES-CCM generated nonce/MAC | AES-GCM and AES-CCM message output product coverage exists | Positive execution depends on provider message API support | Done |
| MP-05 | `C_WrapKeyAuthenticated` generated IV/tag | Dedicated output recipe plus AES-GCM generated-IV/tag product coverage exists | AES-CCM authenticated-wrap generated output remains deferred | Done / P2 follow-up |
| MP-06 | TLS/SSL/WTLS returned key material | Product tests assert nested handles/IVs and clean returned handles | Positive execution depends on advertised derive mechanisms | Done |
| MP-07 | SP800-108 additional derived keys | Raw writable-handle test plus counter-KDF additional-handle product coverage exists | Invalid-template and provider-specific restriction reporting remain follow-up work | Done / P2 follow-up |
| MP-08 | `CK_PBE_PARAMS.pInitVector` | Public packer exposes caller-owned IV output buffer; raw and product tests exist | Positive execution depends on advertised legacy PBE support | Done |
| MP-09 | CloudHSM/Thales in-band IV output | Documented only | No vendor mechanism registration or tests for prepended/appended IV modes | P2 |
| MP-10 | NVIDIA direct IV retrieval | Documented only | No implementation planned for pkcs11-check | Not planned |
| MP-11 | Proxy/loader parameter preservation | p11-kit limitation documented; pkcs11-proxy context external | No pkcs11-check test profile that detects lost mechanism parameter writeback through a proxy | P2 |
| MP-12 | Simulator breadth | Simulator covers classic AES-GCM encryption only | No simulator for wrap params, CCM message/wrap, TLS nested outputs, PBE IV, or SP800-108 multi-key | P2 |

## Detailed Findings

### MP-01: Classic AES-GCM IV Writeback Is Treated As Core Cross-Verify

Current files:

- `src/pkcs11_check/testcases/test_aead.py`
- `src/pkcs11_check/raw/pack_mechanisms.py`
- `docker/softhsm2/Dockerfile.generated-iv`
- `docker/softhsm2/patches/0001-simulate-aes-gcm-generated-iv.patch`

The strict and AWS-style `CKM_AES_GCM` writeback tests are present and useful.
They exercise the exact class of behavior needed for CloudHSM/Thales-style
generated IV workflows.

The remaining issue is classification. The tests live under the module-level
`crossverify` mark, and call `compliance.note(..., ComplianceLevel.VENDOR)`,
but they are not marked `pytest.mark.vendor`. That makes it harder to select or
exclude vendor behavior from a pure standards run.

Recommended acceptance criteria:

- Add `pytest.mark.vendor` to provider-generated classic AES-GCM tests.
- Keep the existing behavior: skip only when the generated-IV convention is
  rejected as unsupported; fail if the provider accepts the convention but fails
  to write the IV.
- Add a short provider-profile note for "writeback" vs "in-band IV" modes.

Implementation status: the classic strict and AWS generated-IV tests are now
marked `vendor`. In-band output modes remain separate vendor-profile work under
MP-09.

### MP-02: GCM Wrap Generated IV Has No Product Test

Current files:

- `src/pkcs11_check/raw/pack_mechanisms.py`
- `tests/test_raw_pack.py`

`mech_gcm_wrap_generated_iv()` correctly allocates a writable `pIv` buffer for
`CK_GCM_WRAP_PARAMS` and stores it in `PackedMechanism`. Raw tests confirm that
simulated provider writes are visible.

What is missing is an end-to-end `C_WrapKey` workflow:

1. Generate or import a wrapping AES key with `CKA_WRAP` and `CKA_UNWRAP`.
2. Generate or import an extractable target key.
3. Call `C_WrapKey` with `CKM_AES_GCM` and `CK_GCM_WRAP_PARAMS` using
   `ivGenerator = CKG_GENERATE` or `CKG_GENERATE_RANDOM`.
4. Read the returned IV from `PackedMechanism.buffer_bytes("iv")`.
5. Unwrap or decrypt using that IV and verify the original key material.

This is a P0 gap because `C_WrapKey` is one of the user's explicit target
workflows, and the raw layer already has the hard ctypes work.

Recommended acceptance criteria:

- Add a standard product test gated by v3.2 semantics and `CKM_AES_GCM`
  wrap/unwrap support.
- Treat `CKR_MECHANISM_INVALID`, `CKR_MECHANISM_PARAM_INVALID`,
  `CKR_FUNCTION_NOT_SUPPORTED`, and equivalent specific unsupported codes as
  capability absence.
- Fail if the provider accepts the generated-IV wrap parameters but leaves the
  IV buffer zeroed or unusable.

Implementation status: `test_aead_wrap_outputs.py` now covers generated-IV GCM
wrap followed by explicit-IV unwrap. The raw layer also exposes explicit
`mech_gcm_wrap()` for the unwrap side.

### MP-03: CCM Wrap Generated Nonce Has No Product Test

Current files:

- `src/pkcs11_check/raw/pack_mechanisms.py`
- `tests/test_raw_pack.py`

`mech_ccm_wrap_generated_nonce()` exists and is covered at the raw packer
level. There is no product test that calls `C_WrapKey` with
`CK_CCM_WRAP_PARAMS` and then validates the returned nonce.

This should follow the same structure as MP-02, but it is P1 rather than P0
because AES-CCM wrap support is less common in the current provider matrix.

Recommended acceptance criteria:

- Add a standard product test gated by `CKM_AES_CCM` wrap/unwrap support.
- Verify the returned nonce is non-zero or otherwise demonstrably provider
  written.
- Verify unwrap/decrypt succeeds only when the returned nonce is supplied.

Implementation status: `test_aead_wrap_outputs.py` now covers generated-nonce
CCM wrap followed by explicit-nonce unwrap. The raw layer also exposes explicit
`mech_ccm_wrap()` for the unwrap side.

### MP-04: Message AES-CCM Generated Nonce/MAC Is Missing

Current files:

- `src/pkcs11_check/testcases/test_mech_message.py`
- `src/pkcs11_check/raw/pack_mechanisms.py`

There is a product test for `CK_GCM_MESSAGE_PARAMS` generated IV writeback:
`test_message_encrypt_aes_gcm_generated_iv_writeback`. It validates both the IV
and tag by decrypting with Python `cryptography`.

The equivalent `CK_CCM_MESSAGE_PARAMS` test is missing. The raw packer already
exposes the nonce and MAC buffers, so the product test can be added without new
ctypes structure work.

Recommended acceptance criteria:

- Add `C_MessageEncrypt*` AES-CCM generated nonce/MAC coverage.
- Gate on `CKF_MESSAGE_ENCRYPT` for `CKM_AES_CCM` and function availability.
- Verify the returned nonce and MAC using independent AES-CCM decryption.

Implementation status: `test_mech_message.py` now validates generated
AES-CCM nonce and MAC output with independent `cryptography` AES-CCM
decryption.

### MP-05: Authenticated Wrap Does Not Exercise Generated Message Params

Current files:

- `src/pkcs11_check/testcases/test_authenticated_wrap.py`
- `src/pkcs11_check/raw/recipes.py`

Authenticated wrap tests use `mech_gcm_message` parameter structures to convey
the authentication tag via `CK_GCM_MESSAGE_PARAMS.pTag`. They cover basic
wrap/unwrap, tampered tag rejection, tampered ciphertext rejection, AAD
mismatch rejection, and generated-IV writeback for AES-GCM.

Implementation status: `wrap_key_authenticated()` matches the PKCS#11 v3.2
§5.13 signature directly (AAD input, wrapped-key output, tag written into
`mech_param`'s pTag buffer). AES-CCM authenticated wrap remains follow-up work.

### MP-06: TLS/SSL/WTLS Nested Output Structures Are Under-Asserted

Current files:

- `src/pkcs11_check/testcases/test_ssl3.py`
- `src/pkcs11_check/testcases/test_tls12.py`
- `src/pkcs11_check/testcases/test_wtls.py`
- `src/pkcs11_check/raw/pack_mechanisms.py`

The raw packers allocate nested output structures and IV buffers:

- `CK_SSL3_KEY_MAT_OUT.hClientMacSecret`
- `CK_SSL3_KEY_MAT_OUT.hServerMacSecret`
- `CK_SSL3_KEY_MAT_OUT.hClientKey`
- `CK_SSL3_KEY_MAT_OUT.hServerKey`
- `CK_SSL3_KEY_MAT_OUT.pIVClient`
- `CK_SSL3_KEY_MAT_OUT.pIVServer`
- `CK_WTLS_KEY_MAT_OUT.hMacSecret`
- `CK_WTLS_KEY_MAT_OUT.hKey`
- `CK_WTLS_KEY_MAT_OUT.pIV`

The product tests mainly verify that `C_DeriveKey` returns a handle and, in
some cases, that the returned value has the expected length. They do not assert
the nested returned handles or IV buffers.

This creates two risks:

- A provider could ignore the nested output struct and still pass.
- Returned nested handles may not be destroyed, causing session-object leaks on
  providers that do populate them.

Recommended acceptance criteria:

- For key-and-MAC derive tests, assert non-zero nested handles when key/MAC sizes
  request them.
- Read attributes from returned handles where extractability allows it.
- Assert IV buffers change when `ulIVSizeInBits > 0`.
- Destroy every non-zero returned nested handle in `finally`.

Implementation status: SSL3, TLS 1.2, and WTLS key-material tests now assert
returned nested key handles and IV buffer writeback, and clean returned nested
handles in `finally`.

### MP-07: SP800-108 Additional Derived Keys Are Not Covered

Current files:

- `src/pkcs11_check/testcases/test_sp800_108_kdf.py`
- `src/pkcs11_check/raw/types_std.py`
- `tests/data/types_std_reference.py`

The generated ctypes types include `CK_DERIVED_KEY` and the
`ulAdditionalDerivedKeys` / `pAdditionalDerivedKeys` fields. Current product
tests always set `ulAdditionalDerivedKeys = 0` and `pAdditionalDerivedKeys =
None`.

Provider research shows this needs careful reporting. NVIDIA and Entrust
nShield document restrictions to one derived key for SP800-108 counter KDF, so a
simple "must support multiple additional keys" assertion would produce noisy
results on known providers.

Recommended acceptance criteria:

- Add raw packer support for a `CK_DERIVED_KEY` array with caller-owned output
  handles and per-key templates.
- Add meta-tests proving returned handles can be observed after simulated
  provider writes.
- Add product tests that distinguish:
  - supported multi-key derivation,
  - documented provider restriction,
  - unexpected success with invalid templates,
  - unexpected CKR outside specific accepted unsupported codes.
- Record provider restrictions through compliance notes or module-issues
  entries, not silent `pass`.

Implementation status: `tests/test_raw_pack.py` now verifies writable
`CK_DERIVED_KEY.phKey` handle slots, and `test_sp800_108_kdf.py` has a
counter-KDF product test for one additional derived key handle. Invalid-template
coverage and provider-specific restriction notes remain follow-up work.

### MP-08: PBE IV Output Is Covered By Public Packer And Product Tests

Current files:

- `src/pkcs11_check/raw/pack_mechanisms.py`
- `src/pkcs11_check/testcases/test_pbe.py`

The public `mech_pbe()` helper exposes a caller-owned `init_vector` output buffer
by default. Passing `iv_len=None` preserves an intentional `pInitVector = NULL`
shape for legacy or provider-specific tests. Product tests use the public packer
and assert provider writeback after successful key generation where advertised
legacy PBE support is operational.

Recommended acceptance criteria:

- Change the public PBE packer API to offer an explicit caller-owned IV buffer.
- Preserve a way to build legacy/null forms only when a test deliberately needs
  that invalid or provider-specific shape.
- Add raw tests for IV buffer observability.
- Add product assertions for advertised PBE mechanisms where provider behavior
  is operational.

Implementation status: `mech_pbe()` now allocates and exposes a caller-owned
`init_vector` output buffer by default, while `iv_len=None` preserves an
intentional NULL shape for legacy/provider-specific tests. Raw tests verify
buffer observability, and PBE product tests assert provider writeback after
successful key generation.

### MP-09: In-Band IV Vendor Mechanisms Are Documented But Untested

Current references:

- AWS `CKM_CLOUDHSM_AES_GCM`
- Thales `CKM_AES_GCM_OLD`
- Thales legacy GCM configuration that preserves appended-IV behavior

AWS documents `CKM_CLOUDHSM_AES_GCM` as a vendor-defined safer alternative that
prepends the generated IV to ciphertext and wrapped output. Thales documents an
older mode where IV material is appended to output.

pkcs11-check currently documents these behaviors but does not register the
vendor mechanism names, packers, or product tests.

Recommended acceptance criteria:

- Add vendor extension registrations for known AWS/Thales symbolic names and
  numeric IDs when those IDs are available from provider headers.
- Add provider-profile tests that verify the IV is in-band and can be used for
  decrypt/unwrap.
- Keep these tests marked `vendor`; do not mix them into standard conformance
  expectations.

### MP-10: NVIDIA Direct IV Retrieval Is Documented Only

Current references:

- NVIDIA DRIVE OS sample application
- NVIDIA DRIVE OS vendor-extension documentation

NVIDIA documents direct IV retrieval for AES-GCM/AES-CTR encryption through
`C_NVIDIA_EncryptGetIV`, and sample coverage for AES-CBC wrap IV retrieval.
This is not a mechanism parameter writeback path, but it solves the same user
problem: retrieving provider-generated IV material that is required for
decryption or unwrap.

Implementation status: no pkcs11-check support is planned for this vendor
extension. Keep the note as research context only; do not add loader symbols,
tests, or release commitments for NVIDIA-specific functions.

### MP-11: Proxy/Loader Preservation Is A Separate Test Surface

Current references:

- `docs/mechanism-output-parameters.md`
- pkcs11-proxy mutable-parameter preservation notes from local provider research

Mutable mechanism parameters are especially fragile through RPC or loader
layers because pointers have to remain valid across calls and updated bytes have
to be copied back to the original caller buffer. The pkcs11-proxy notes show
that both the `CK_GCM_PARAMS` struct and `pIv` buffer may need session-lifetime
storage for CloudHSM-like providers.

pkcs11-check currently warns that p11-kit should not be treated as
authoritative for GCM parameter mutation, but it does not include a focused
proxy-preservation test profile.

Recommended acceptance criteria:

- Keep direct provider tests as the authoritative behavior source.
- Add a separate interop/proxy profile that can detect lost writeback across a
  proxy.
- Report proxy loss as loader/proxy behavior, not as a provider crypto failure.

### MP-12: Simulator Coverage Is Too Narrow For Approach A

Current simulator:

- `test-softhsm2-generated-iv`

The patched SoftHSM2 simulator gives reproducible positive coverage for classic
AES-GCM generated IV writeback. It does not simulate the other mutable output
surfaces.

Recommended acceptance criteria:

- Keep the existing simulator target separate from stock SoftHSM.
- Extend simulator coverage only for workflows where no stock open-source
  provider gives positive behavior.
- Prefer independent, narrowly-scoped simulator patches per behavior over one
  large patch that changes many mechanisms.

## Implementation Order Recommendation

1. Done: Classify existing classic AES-GCM generated-IV tests as vendor tests.
2. Done: Add `CK_GCM_WRAP_PARAMS` generated-IV product coverage for `C_WrapKey`.
3. Done: Add `CK_CCM_WRAP_PARAMS` and AES-CCM message generated nonce/MAC
   product coverage.
4. Done: Harden authenticated-wrap generated parameter handling without relying
   on `C_WrapKey` sizing.
5. Done: Add TLS/SSL/WTLS nested returned-material assertions and cleanup.
6. Done: Add SP800-108 additional-derived-key raw and product coverage.
7. Done: Normalize PBE IV output handling.
8. P2: Add invalid-template and provider-restriction reporting for SP800-108.
9. P2: Add vendor-profile extensions for CloudHSM/Thales in-band IV.

## Release Readiness Impact

Approach A is no longer blocking for a public baseline release if the release
notes describe it as targeted coverage rather than exhaustive provider
coverage. MP-02 through MP-08 now have first-pass implementation coverage, but
vendor in-band IV APIs, proxy preservation, and simulator breadth remain
follow-up tracks.

The release notes should avoid claiming that pkcs11-check fully covers all
mutable mechanism output parameters until MP-09, MP-11, and MP-12 are
implemented or otherwise resolved.

## References

- OASIS PKCS#11 v3.2 specification:
  https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.html
- AWS CloudHSM mechanism annotations:
  https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html
- Thales ProtectToolkit `CKM_AES_GCM`:
  https://thalesdocs.com/gphsm/ptk/protectserver3/docs/ps_ptk_docs/ptkc_programming/ptkc_mechs/ckm_aes_gcm/index.html
- NVIDIA DRIVE OS sample application:
  https://developer.nvidia.com/docs/drive/drive-os/7.0.3/public/drive-os-linux-sdk/production-deployment/PKCS_11SampleApplication71.html
- NVIDIA DRIVE OS implementation details:
  https://developer.nvidia.com/docs/drive/drive-os/7.0.3/public/drive-os-linux-sdk/production-deployment/PKCS_11ImplementationDetails75.html
- Entrust nShield PKCS#11 mechanisms:
  https://nshielddocs.entrust.com/security-world-docs/api-pkcs11/mechanisms.html

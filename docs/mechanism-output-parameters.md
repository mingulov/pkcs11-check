# Mechanism Output Parameters

Some PKCS#11 mechanism parameter structures contain caller-owned buffers that a
module may update during the operation. These are easy to miss because the
operation result is not only returned through the normal output argument.

See [mutable-mechanism-parameter-gap-analysis.md](mutable-mechanism-parameter-gap-analysis.md)
for the current Approach A gap analysis and implementation priorities.

## Covered Surfaces

- `CK_GCM_PARAMS.pIv` for vendor/provider-generated classic `CKM_AES_GCM` IVs.
- `CK_GCM_MESSAGE_PARAMS.pIv` and `pTag` for v3 message-based AES-GCM.
- `CK_CCM_MESSAGE_PARAMS.pNonce` and `pMAC` for v3 message-based AES-CCM.
- `CK_GCM_WRAP_PARAMS.pIv` and `CK_CCM_WRAP_PARAMS.pNonce` for generated IV/nonce
  key-wrap parameter paths.
- `CK_SSL3_KEY_MAT_OUT`, `CK_TLS12_KEY_MAT_PARAMS`, and
  `CK_WTLS_KEY_MAT_PARAMS` IV output buffers for key-material derivation.
- `CK_DERIVED_KEY.phKey` additional output handles for SP800-108 KDF parameter
  arrays.
- `CK_PBE_PARAMS.pInitVector` for legacy PBE key-generation IV output.

The raw packer API exposes these mutable buffers through
`PackedMechanism.buffer_bytes(name)` so tests can verify what the token wrote
after the call.

## Provider Notes

- AWS CloudHSM SDK 5 documents classic AES-GCM as HSM-generated IV only: the
  application supplies a zeroized `CK_GCM_PARAMS.pIV` buffer and the 12-byte IV
  is written back there. SDK 3 has also documented older prepend-to-ciphertext
  behavior, so both result forms are provider-version sensitive.
- Thales ProtectToolkit 7.1+ documents classic `CKM_AES_GCM` writeback when the
  caller supplies an all-zero IV buffer. Older ProtectToolkit behavior returned
  the IV appended to the operation output.
- Thales Luna documents FIPS-mode generated IV behavior and firmware-version
  differences around whether generated IV material is appended to encrypted
  output or sized from `ulIvBits`.
- SoftHSM2 2.7.0 and current `main` do not implement classic generated-IV
  writeback. The `CKM_AES_GCM` path copies `pIv` using `ulIvLen`; it does not
  use `ulIvBits` as a requested output size and does not generate into `pIv`.
  SoftHSM headers include PKCS#11 v3.x message prototypes, but the exported
  function list remains the classic v2-style list, so stock SoftHSM is not a
  positive provider for `C_MessageEncrypt*` generated-IV tests.
- pkcs11-check includes a separate patched SoftHSM2 Docker simulator target,
  `test-softhsm2-generated-iv`, for positive classic `CKM_AES_GCM` writeback
  coverage. The target is not stock SoftHSM behavior; it applies a local patch
  that generates a 12-byte IV during `C_EncryptInit`, writes it to
  `CK_GCM_PARAMS.pIv`, and keeps decrypt explicit-IV only.
- NSS softoken implements v3 message encryption paths and uses
  `CK_GCM_MESSAGE_PARAMS.ivGenerator` / `CK_CCM_MESSAGE_PARAMS.nonceGenerator`.
  Its classic `CKM_AES_GCM` path requires explicit byte-aligned IV parameters.
- Kryoptic supports message-based AES-GCM/CCM IV and nonce generation in its
  v3.x message paths; classic `CKM_AES_GCM` remains explicit-IV only.
- OpenCryptoki exposes v3 message API symbols, but the current API layer returns
  `CKR_FUNCTION_NOT_SUPPORTED` for those message functions.
- BouncyHSM `main` supports classic `CKM_AES_GCM`, but advertises only classic
  encrypt/decrypt/wrap/unwrap flags for it and all v3 message functions return
  `CKR_FUNCTION_NOT_SUPPORTED`. Its GCM path consumes the supplied IV bytes; it
  does not generate and write an IV back to `CK_GCM_PARAMS.pIv`.
- pkcs11-mock and empty-pkcs11 expose v3.1-shaped function lists for test
  scaffolding, but they are not positive providers for this surface:
  pkcs11-mock does not advertise `CKM_AES_GCM`, and both modules return
  `CKR_FUNCTION_NOT_SUPPORTED` for message functions.
- tpm2-pkcs11 does not currently advertise `CKM_AES_GCM`; its AES mechanisms are
  limited to TPM-supported block modes such as CBC, CFB, ECB, and CTR.
- OpenSC exports v3 message symbols in its PKCS#11 module, but the direct module
  returns `CKR_FUNCTION_NOT_SUPPORTED` for message encryption functions.
- p11-kit is a loader/proxy rather than a crypto provider. Its RPC transport can
  serialize `CK_GCM_PARAMS` input, but current parameter-update plumbing is only
  registered for selected IBM derive mechanisms, not `CKM_AES_GCM`; use a direct
  module load when testing mutable GCM mechanism parameters.
- NVIDIA DRIVE OS PKCS#11 exposes a vendor extension,
  `C_NVIDIA_EncryptGetIV`, for retrieving a generated IV after `CKM_AES_GCM`
  encryption. This is a non-standard direct-access workflow distinct from
  `CK_GCM_PARAMS.pIv` writeback and the v3 message API. pkcs11-check documents
  this for context only; no support for NVIDIA-specific functions is planned.

## Test Strategy

1. Packer-level tests ensure every mutable mechanism-parameter buffer is owned,
   writable, and inspectable in Python.
2. Standard positive product tests cover v3 message AES-GCM/AES-CCM generated
   output, v3.2 generated IV/nonce wrap parameters, authenticated-wrap generated
   GCM output, TLS/SSL/WTLS nested key-material outputs, and SP800-108
   additional derived-key handles, plus PBE IV writeback where a provider
   advertises operational legacy PBE support.
3. Vendor positive product tests cover classic `CKM_AES_GCM` writeback
   conventions used by CloudHSM/Thales-style providers.
4. The patched SoftHSM2 simulator target gives CI/local runs a reproducible
   positive software provider for the classic writeback tests without changing
   the stock SoftHSM2 baseline.
5. Standard software providers that only support explicit classic GCM IVs should
   skip the vendor generated-IV tests when they reject those parameters, but if
   a provider accepts a generated-IV convention and fails to write back the IV,
   the test reports that as a finding.

## References

- OASIS PKCS#11 v3 mechanisms specification:
  https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.pdf
- AWS CloudHSM PKCS#11 mechanism annotations:
  https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html
- Thales ProtectToolkit `CKM_AES_GCM`:
  https://thalesdocs.com/gphsm/ptk/protectserver3/docs/ps_ptk_docs/ptkc_programming/ptkc_mechs/ckm_aes_gcm/index.html
- Thales Luna `CKM_AES_GCM`:
  https://thalesdocs.com/gphsm/luna/7/docs/pci/Content/sdk/mechanisms/CKM_AES_GCM.htm
- SoftHSM2 upstream:
  https://github.com/softhsm/SoftHSMv2
- BouncyHSM upstream:
  https://github.com/harrison314/BouncyHsm
- pkcs11-mock upstream:
  https://github.com/Pkcs11Interop/pkcs11-mock
- tpm2-pkcs11 upstream:
  https://github.com/tpm2-software/tpm2-pkcs11
- OpenSC upstream:
  https://github.com/OpenSC/OpenSC
- p11-kit upstream:
  https://github.com/p11-glue/p11-kit
- NVIDIA DRIVE OS PKCS#11 sample and vendor-extension docs:
  https://developer.nvidia.com/docs/drive/drive-os/7.0.3/public/drive-os-linux-sdk/production-deployment/PKCS_11SampleApplication71.html
  https://developer.nvidia.com/docs/drive/drive-os/7.0.3/public/drive-os-linux-sdk-api-ref/group__nvpkcs11__ext.html

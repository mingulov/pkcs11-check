# Roadmap and Known Limitations

This file tracks public post-v0.1.0 follow-up work. These items are not release
blockers for the first public version; they are known limitations or optional
interop profiles that should be implemented in focused follow-up branches.

- [ ] **CloudHSM/Thales In-Band IV Vendor Profiles**
  - Release status: deferred post-v0.1.0 vendor interop work.
  - Add vendor-marked tests for provider modes that return generated IV material
    inside ciphertext or wrapped-key output instead of writing it through a
    standard mutable mechanism parameter.
  - Scope:
    - AWS CloudHSM `CKM_CLOUDHSM_AES_GCM` style prepended-IV workflows when
      public mechanism IDs are available.
    - Thales legacy/appended-IV AES-GCM workflows where provider behavior can be
      selected and documented.
  - Keep these tests out of standard conformance expectations.

- [ ] **Proxy/Loader Mutable Parameter Preservation Profile**
  - Release status: deferred post-v0.1.0 loader/proxy interop work.
  - Add an interop profile that compares direct provider behavior with behavior
    through loaders/proxies such as `p11-kit` or `pkcs11-proxy`.
  - Goal: detect whether mutable mechanism parameter writeback, especially
    generated IV buffers, survives the loader/proxy layer.
  - Report proxy loss as loader/proxy behavior, not as a provider crypto
    failure.

- [ ] **Broader Mutable-Output Simulator Targets**
  - Release status: deferred post-v0.1.0 simulator expansion.
  - Extend simulator coverage only for mutable-output workflows where no stock
    open-source provider gives positive behavior.
  - Candidate surfaces:
    - GCM/CCM wrap generated IV/nonce.
    - AES-CCM message generated nonce/MAC.
    - TLS/SSL/WTLS nested output handles and IVs.
    - SP800-108 additional derived keys.
  - Prefer separate narrow simulator targets over one broad provider patch.

- [ ] **SO Login Support for CKA_TRUSTED Certificate Import**
  - Release status: known v0.1.0 limitation, deferred to a focused SO-login
    feature branch.
  - SO login is not covered and is needed for importing trusted certificates (`CKA_TRUSTED=True`).
  - Current workaround: Import without `CKA_TRUSTED`, which results in weaker trust chain validation.
  - Requires:
    - CLI flag `--p11-so-pin` and env `P11TEST_SO_PIN`.
    - Bootstrap helper to login/logout as SO.
    - Logic in X.509 conftest to switch to SO session for trusted cert creation.
    - Safety: Mark tests as `@destructive` due to lockout risk.

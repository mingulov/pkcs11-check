# TODO

- [ ] **SO Login Support for CKA_TRUSTED Certificate Import**
  - SO login is not covered and is needed for importing trusted certificates (`CKA_TRUSTED=True`).
  - Current workaround: Import without `CKA_TRUSTED`, which results in weaker trust chain validation.
  - Requires:
    - CLI flag `--p11-so-pin` and env `P11TEST_SO_PIN`.
    - Bootstrap helper to login/logout as SO.
    - Logic in X.509 conftest to switch to SO session for trusted cert creation.
    - Safety: Mark tests as `@destructive` due to lockout risk.

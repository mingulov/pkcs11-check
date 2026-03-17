# p11test

CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin.

## Quick Reference

- **Language:** Python 3.11+
- **Package manager:** uv
- **Build backend:** hatchling (src/ layout)
- **CLI framework:** typer + rich
- **Config:** pydantic-settings (TOML + CLI + env)
- **Testing:** pytest (meta-tests in `tests/`, product test cases in `src/p11test/testcases/`)
- **Linting:** ruff
- **Type checking:** mypy --strict
- **PKCS#11 binding:** python-pkcs11 fork (git submodule at `python-pkcs11/`)

## Commands

```bash
uv run p11test version              # check CLI works
uv run p11test test --module /path/to.so --pin 1234  # run PKCS#11 tests
uv run p11test info --module /path/to.so             # show module info
uv run p11test list                 # list test categories
uv run pytest tests/                # run meta-tests (p11test's own tests)
uv run ruff check src/ tests/       # lint
uv run ruff format src/ tests/      # format
uv run mypy src/                    # type check

# Docker multi-module testing
docker compose -f docker/docker-compose.test.yml run test-softhsm2
docker compose -f docker/docker-compose.test.yml run test-kryoptic
docker compose -f docker/docker-compose.test.yml run test-nss
docker compose -f docker/docker-compose.test.yml run test-kryoptic-main

# Local SoftHSM2 testing
bash scripts/setup-softhsm.sh
SOFTHSM2_CONF=/tmp/p11test-softhsm2.conf uv run pytest src/p11test/testcases/ \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234 -v
```

## Architecture

### Two test directories
- `src/p11test/testcases/` — the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` — META-TESTS: tests for p11test's own code (config parsing, markers, CLI)

### Core modules
- `core/loader.py` — PKCS#11 module loading with v2.40/v3.0/v3.1/v3.2 interface negotiation
- `core/isolation.py` — subprocess-based test execution for segfault survival
- `core/logging.py` — rich logging with trace mode
- `config.py` — four-layer config: CLI > env > TOML > defaults
- `plugin.py` — pytest11 entry point, registers markers, fixtures, collection hooks
- `markers.py` — marker definitions with version-skip logic
- `compliance.py` — compliance note system (NOT_RECOMMENDED, DEPRECATED tracking)
- `fixtures.py` — p11_session, p11_module, p11_config, p11_interface_version
- `cli/app.py` — typer app, routes to test/info/list/version subcommands
- `testcases/conftest.py` — shared helpers: mech_name(), import_aes_key(), has_mechanism(), extract_ec_point()

### Test categories
- Core: interface, slot, object, mechanism, encrypt, sign, digest, errors
- Cross-verification: AES-ECB/GCM, RSA PKCS/PSS/OAEP, ECDSA P-256/384/521, EdDSA, HMAC, digest
- NIST KAT: SHA-1/224/256/384/512, AES-ECB from SP 800-38A
- Wycheproof edge-case vectors (see docs/test-coverage.md for details):
  ECDSA (P-224/256/384/521 × SHA/SHA-3), RSA PKCS#1/PSS/OAEP,
  ECDH (P-224/256/384/521), DSA, AES (GCM/CBC/CMAC/CCM/KW/KWP/XTS/GMAC),
  HMAC (SHA/SHA-3/SHA-512 truncated), Ed25519/Ed448, ChaCha20-Poly1305,
  X25519/X448, HKDF — mechanism availability checked at runtime
- PQC (PKCS#11 v3.2): ML-KEM encapsulate/decapsulate, ML-DSA sign/verify, SLH-DSA sign/verify
- Key management: import, export, copy, wrap/unwrap, derive, KEM
- Security: API attacks, padding oracle, ECDSA nonce quality, RNG statistics (Shannon entropy, runs test)
- Standards: buffer boundaries, access control, session lifecycle, token flags, CKO_PROFILE
- Stress: 1000-cycle operations, multi-session, resource safety
- Fuzz: hypothesis property tests for AES, RSA, SHA, HMAC, ECDSA roundtrips

### Docker test matrix (12 targets)
Versioned releases:
- `test-softhsm2` — SoftHSM2 2.7.0 (v2.40, OpenSSL)
- `test-kryoptic` — Kryoptic v1.5.0 (v3.2, Rust)
- `test-nss` — NSS 3.120.1 (v3.0, Fedora 43)
- `test-nss-pqc` — NSS 3.121.0 (v3.2 PQC, Rawhide)
- `test-opencryptoki` — OpenCryptoki 3.25.0 (v3.0, IBM)

Development branches:
- `test-softhsm2-main` — SoftHSM2 main branch
- `test-kryoptic-main` — Kryoptic main branch
- `test-kryoptic-fips` — Kryoptic FIPS + simo5/openssl kryoptic_ossl40

Additional:
- `test-tpm2` — tpm2-pkcs11 + swtpm
- `test-bouncyhsm` — BouncyHSM (.NET/BouncyCastle)
- `test-pkcs11-mock` — pkcs11-mock (v3.1 stub)
- `test-qryptotoken` — qryptotoken (Rust PQC)

### Key design decisions
- python-pkcs11 fork as git submodule (`python-pkcs11/`) with v3.0/3.1/3.2 interface negotiation, PQC mechanisms (ML-KEM, ML-DSA, SLH-DSA), parameter structs (CCM, ChaCha20-Poly1305, HKDF), and 50+ new mechanism/key type enums
- Test cases are native pytest tests with custom fixtures (p11_session, p11_module)
- Tests auto-skip when interface version doesn't support them (@pytest.mark.requires_v30)
- Wycheproof vectors use `xfail` for module limitations (not hard failures)
- Mechanism availability checked at runtime via `slot.get_mechanisms()` — tests skip cleanly
- Compliance notes track NOT_RECOMMENDED/DEPRECATED behavior
- `mech_name()` helper handles both Mechanism enum and raw int (SoftHSM2 2.7.0+ compat)

## Conventions

- Type annotations on all public functions (mypy strict)
- `ruff` for formatting and linting — no other formatters
- Imports sorted by ruff (isort-compatible)
- Line length: 100
- Test files prefixed with `test_`
- Use `rich.console` for all CLI output (no bare print)
- Config values: snake_case in TOML/Python, kebab-case for CLI flags
- PIN values are never logged, printed, or included in error messages

## Design Specs

- `docs/superpowers/specs/2026-03-16-p11test-design.md` — Phase 1 architecture
- `docs/superpowers/specs/2026-03-16-comprehensive-testing-design.md` — Full testing spec (~2,400 tests)
- `docs/superpowers/specs/2026-03-16-standards-addendum.md` — OASIS standards conformance
- `docs/test-coverage.md` — Current test coverage summary and mechanism matrix
- `docs/python-pkcs11-fork.md` — Fork changes and upstream PR plan

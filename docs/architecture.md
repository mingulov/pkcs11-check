# Architecture

## Two test directories

- `src/pkcs11_check/testcases/` — the PRODUCT: PKCS#11 tests run against hardware/software modules
- `tests/` — META-TESTS: tests for pkcs11-check's own code (config parsing, markers, CLI)

## Test vector data (`data/`)

- `data/sources.toml` — tracked manifest: pinned commits, SHA-256 checksums, include filters
- `data/.gitignore` — tracked, ignores extracted directories
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` — gitignored, fetched by `scripts/fetch-data.sh`
- Own test data (mechanism_vectors, KAT JSONs) stays in `src/pkcs11_check/testcases/data/` (tracked)
- Override data location with `PKCS11_CHECK_DATA_DIR` env var

## Core modules

- `core/loader.py` — PKCS#11 module loading with v2.40/v3.0/v3.1/v3.2 interface negotiation
- `core/file_runner.py` — main isolated runner for `auto|file|test`, with resume, adaptive promotion, and aggregated reports
- `core/preflight.py` — collection-safe capability probe written through a helper subprocess manifest
- `core/collection.py` — pytest item metadata collection for marker-aware isolation planning
- `core/isolation.py` — lower-level `spawn` helper retained for focused tests and future integration
- `config.py` — four-layer config: CLI > env > TOML > defaults
- `plugin.py` — pytest11 entry point, registers markers, fixtures, collection hooks
- `fixtures.py` — p11_raw_session / p11_session (both yield RawSession), p11_module, p11_config, p11_interface_version
- `testcases/conftest.py` — shared helpers: get_pin_bytes(), extract_ec_point()
- `testcases/ckr/` — CKR error coverage tests (102 tests, 21 files). Use `--ckr-strict` for exact spec compliance

## Raw PKCS#11 access (`pkcs11_check.raw`)

Pure Python ctypes binding — no C compilation. All 68 v2.40 functions + v3.0 message-based + v3.2 KEM functions. Returns raw CK_RV integers.

```python
from pkcs11_check.raw.api import RawPKCS11
raw = RawPKCS11.from_lib("/path/to/module.so")
rv = raw.C_GetTokenInfo(slot_id, byref(token_info))
```

Use in subprocess for NULL/segfault tests (`subprocess.run([sys.executable, "-c", script])`).

## Local builds (`local-builds/`)

- `providers/<name>.sh` — one file per token with `build()` and `setup()` functions
- `build.sh` — dispatcher: `bash local-builds/build.sh kryoptic [branch]`
- `test.sh` — dispatcher: `bash local-builds/test.sh kryoptic [pytest-args]`
- `reset.sh` — reset token data: `bash local-builds/reset.sh kryoptic`

## Test categories

Core: interface, slot, object, mechanism, encrypt, sign, digest, errors
Cross-verification: AES-ECB/GCM, RSA PKCS/PSS/OAEP, ECDSA, EdDSA, HMAC, digest
NIST KAT: SHA family, AES-ECB from SP 800-38A
Wycheproof: ECDSA, RSA, ECDH, DSA, AES, HMAC, EdDSA, ChaCha20, X25519/X448, HKDF
PQC (v3.2): ML-KEM, ML-DSA, SLH-DSA
Key management: import, export, copy, wrap/unwrap, derive, KEM
Security: attribute fuzz, Tookan vectors, handle reuse, padding oracle, ECDSA nonce, RNG stats
CVE regression: 29 tests across NSS, SoftHSM2, TPM2, OpenCryptoki, BouncyHSM, Kryoptic
CKR spec compliance: exact return code verification per PKCS#11 standard
Interop: OpenSSL pkcs11-provider, p11-kit proxy
Stress: 1000-cycle ops, threading, resource exhaustion, DB concurrent writes
Fuzz: Hypothesis property tests, attribute template fuzzer

## Docker test matrix (12 targets)

- `test-softhsm2` / `test-softhsm2-main` — SoftHSM2 2.7.0 / main
- `test-kryoptic` / `test-kryoptic-main` / `test-kryoptic-fips` — Kryoptic v1.5.0 / main / FIPS
- `test-nss` / `test-nss-pqc` — NSS 3.120.1 / 3.121.0 PQC
- `test-opencryptoki` — OpenCryptoki 3.26.0
- `test-tpm2` — tpm2-pkcs11 + swtpm
- `test-bouncyhsm` — BouncyHSM 2.0.1
- `test-pkcs11-mock` — pkcs11-mock v3.1 stub
- `test-qryptotoken` — qryptotoken Rust PQC

## Key design decisions

- `pkcs11_check.raw` is the sole PKCS#11 access layer: pure ctypes, v2.40-v3.2 interface negotiation, PQC mechanisms, generated type/metadata from vendored PKCS#11 headers
- `pkcs11-check test` defaults to `--isolation auto`; explicit `--isolation none` is the unsafe fast path
- `p11_session` fixture does explicit `login()` / `logout()` per test to avoid `UserAlreadyLoggedIn` cascading
- Tests auto-skip when interface version doesn't support them (@pytest.mark.requires_v30)
- Mechanism availability checked at runtime via `rs.has_mechanism(name)` on `RawSession`
- PQC tests always provide `CKA_PARAMETER_SET` (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s defaults)
- PIN tests marked `@destructive` to prevent token lockout (OpenCryptoki, TPM)

## Writing new tests

### Template

```python
"""CKM_EXAMPLE tests — short description."""
from __future__ import annotations
from typing import Any
import pytest
from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.recipes import gen_aes_key, encrypt_single, destroy_quietly
from pkcs11_check.raw.types_std import CKM_AES_CTR, CKR_OK

pytestmark = [pytest.mark.encrypt]

class TestExample:
    def test_roundtrip(self, p11_raw_session: RawSession) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_CTR, b"test data here!")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
```

### Key fixtures

- `p11_raw_session` — primary: yields `RawSession` with login/logout per test. Fields: `rs.raw`, `rs.sh`, `rs.slot_id`, `rs.has_mechanism(name)`, `rs.mechanisms`
- `p11_session` — legacy alias, also yields `RawSession`
- `p11_module` — loaded PKCS#11 module (session-scoped)
- `p11_config` — merged config (session-scoped)
- `p11_interface_version` — negotiated version string

### Patterns

Always check mechanism availability:
```python
if not rs.has_mechanism("MECHANISM_NAME"):
    pytest.skip("CKM_MECHANISM_NAME not supported")
```

Always destroy objects in `finally`:
```python
key = gen_aes_key(rs.raw, rs.sh, 256)
try:
    # test logic
finally:
    destroy_quietly(rs.raw, rs.sh, key)
```

Compliance notes for above-spec behavior:
```python
from pkcs11_check.compliance import ComplianceLevel, note
note("Module does X above spec Y", ComplianceLevel.VENDOR)
```

## PKCS#11 Specification

OASIS spec in Markdown: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`
Key files: `rsa.md`, `aes.md`, `elliptic_curves.md`, `ml_dsa.md`, `slh-dsa.md`, `session_mgmt_functions.md`, `function_return_values.md`

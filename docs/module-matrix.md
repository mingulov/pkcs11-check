# Module Test Matrix

Test results from local builds and Docker runs. Updated 2026-03-18.

## Local Build Results

| Module | Version | Interface | Passed | Failed | Skipped | xfail | Notes |
|--------|---------|-----------|--------|--------|---------|-------|-------|
| **SoftHSM2** | 2.7.0 | v2.40 | 22,615 | **0** | 6,294 | 658 | Perfect. Primary v2.40 target |
| **SoftHSM2 main** | dev | v2.40 | 22,615 | **0** | 6,294 | 658 | Identical to 2.7.0 |
| **Kryoptic** | 1.5.0+PQC | v3.2 | 21,533 | **0** | 7,657 | 377 | PQC enabled. Primary v3.2 target |
| **Kryoptic main** | dev+PQC | v3.2 | 21,531 | **0** | 7,657 | 379 | Similar to v1.5.0 |
| **pkcs11-mock** | 2.0.0 | v3.1 | 26 | 2 | — | — | Mock stub. Constant RNG, limited ops |
| **qryptotoken** | 0.4.1 | — | 20 | 46 | — | — | Experimental PQC (QUBIP) |
| **tpm2-pkcs11** | 1.9.0 | v2.40 | 33 | 61 | 4 | — | Hardware TPM. 26 mechanisms only |
| **BouncyHSM** | 2.0.1 | v3.2 | — | — | — | — | Segfault on v3.2 attr query (fork bug) |
| **OpenCryptoki** | 3.26.0 | v3.0 | — | — | — | — | Docker only (needs pkcsslotd) |

## Docker Results (latest run)

| Module | Version | Interface | Passed | Failed | Skipped | xfail | Notes |
|--------|---------|-----------|--------|--------|---------|-------|-------|
| **SoftHSM2** | 2.7.0 | v2.40 | 22,622 | **0** | 6,287 | 658 | — |
| **Kryoptic** | 1.5.0 | v3.2 | 21,503 | **0** | 7,687 | 377 | No PQC features in Docker |
| **NSS** | 3.120.1 | v3.0 | 20,730 | 356 | 8,147 | 334 | 296 DSA + 60 module limits |
| **OpenCryptoki** | 3.25 | v3.0 | 468 | 24 | 312 | 1 | +28K errors from PIN lockout |

## Mechanism Support Matrix

| Mechanism | SoftHSM2 | Kryoptic | TPM2 | pkcs11-mock | qryptotoken |
|-----------|----------|----------|------|-------------|-------------|
| AES-ECB | ✓ | ✓ | ✓ | ✓ | ✗ |
| AES-CBC | ✓ | ✓ | ✓ | ✗ | ✗ |
| AES-GCM | ✓ (2.7.0) | ✓ | ✗ | ✗ | ✗ |
| RSA-PKCS | ✓ | ✓ | ✓ | ✓ | ✗ |
| RSA-OAEP | ✓ | ✓ | ✓ | ✗ | ✗ |
| RSA-PSS | ✓ | ✓ | ✗ | ✗ | ✗ |
| ECDSA | ✓ | ✓ | ✓ (P-256) | ✗ | ✓ |
| EdDSA | ✓ | ✓ | ✗ | ✗ | ✓ |
| DH | ✓ | ✓ | ✗ | ✗ | ✗ |
| ECDH | ✓ | ✓ | ✗ | ✗ | ✗ |
| HMAC | ✓ | ✓ | ✓ (SHA-256) | ✗ | ✗ |
| ML-KEM | ✗ | ✓ | ✗ | ✗ | ✗ |
| ML-DSA | ✗ | ✓ | ✗ | ✗ | ✓ |
| SLH-DSA | ✗ | ✓ | ✗ | ✗ | ✗ |

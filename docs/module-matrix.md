# Module Test Matrix

Test results from local builds and Docker runs. Updated 2026-03-28.

## Local Build Results (Post Phase A-H)

| Module | Version | Interface | Passed | Failed | Skipped | xfail | Notes |
|--------|---------|-----------|--------|--------|---------|-------|-------|
| **SoftHSM2** | 2.7.0 | v2.40 | 58,066 | 114 | 15,517 | 1,169 | Primary v2.40 target. Failures: 18 Wycheproof ECDSA + 25 ACVP security + CKR raw ctypes + x509 pre-existing |
| **Kryoptic** | 1.5.0+PQC | v3.2 | 38,193 | 306 | 35,691 | 676 | PQC enabled. Failures: 173 ML-DSA sign seed + 15 ACVP SLH-DSA + CKR raw ctypes + x509 |
| **NSS-PQC** | 3.121.0 | v3.0 | 35,327 | 296 | 31,984 | 645 | Phases 1-11 complete. Failures: 296 Wycheproof DSA (known NSS key-import limitation). 645 xfails verified: ChaCha20-Poly1305 (256), HKDF (232), AES-KWP (77), IKE stubs (16), security bugs (13), spec deviations (32), misc (19). |

## Pre-Phase Baseline (March 18, for comparison)

| Module | Version | Interface | Passed | Failed | Skipped | xfail |
|--------|---------|-----------|--------|--------|---------|-------|
| SoftHSM2 | 2.7.0 | v2.40 | 22,615 | 0 | 6,294 | 658 |
| Kryoptic | 1.5.0+PQC | v3.2 | 21,533 | 0 | 7,657 | 377 |

## Growth Summary

| Metric | March 18 | March 21 | Change |
|--------|----------|----------|--------|
| Test files | 101 | 194 | +93 files |
| Total tests (SoftHSM2) | ~29K | ~75K | +46K tests |
| Mechanism families tested | ~30 | ~60+ | +30 families |
| Object types tested | 6/12 | 12/12 | +6 types |
| API functions tested | ~45/68 | ~57/68 | +12 functions |

## Docker Results (2026-03-28, post mechanism-driven tests)

| Module | Version | Interface | Passed | Failed | Skipped | xfail | Error | Total | Mech Tests |
|--------|---------|-----------|--------|--------|---------|-------|-------|-------|------------|
| **SoftHSM2-main** | master | v2.40 | 44,358 | 13,214 | 11,429 | 11 | 1 | 69,013 | 160 flags, 29 encrypt, 24 digest, 108 sign |
| **Kryoptic-main** | main | v3.2 | 28,518 | 11,631 | 29,542 | 38 | 0 | 69,729 | 326 flags, 33 encrypt, 44 digest, 240 sign |
| **NSS-PQC** | 3.121.0 | v3.0 | 35,840 | 1,010 | 32,624 | 78 | 4 | 69,556 | 276 flags, 65 encrypt, 4 digest, 202 sign |
| **OpenCryptoki** | 3.25 | v3.0 | — | — | — | — | — | — | Needs re-run |
| **tpm2-pkcs11** | 1.9.0 | v2.40 | — | — | — | — | — | — | Untested |
| **BouncyHSM** | 2.0.1 | v3.2 | — | — | — | — | — | — | Untested |
| **pkcs11-mock** | 2.0.0 | v3.1 | Pre-phase | Mock stub |
| **qryptotoken** | 0.4.1 | — | Pre-phase | Experimental PQC |

## Mechanism Support Matrix

| Mechanism | SoftHSM2 | Kryoptic | NSS-PQC | Notes |
|-----------|----------|----------|---------|-------|
| AES-ECB/CBC/GCM/CCM/CTR/CTS/XTS | Y | Y | partial | AES-CCM/XTS/CFB/OFB absent in NSS |
| AES-CMAC/GMAC/MAC | Y | Y | partial | AES-GMAC absent in NSS |
| AES-KEY-WRAP/KWP | Y | Y | partial | KWP: RFC 5649 non-conformant in NSS |
| RSA-PKCS/OAEP/PSS | Y | Y | Y | All hash variants |
| RSA-X.509 (raw) | Y | Y | Y | Phase C addition |
| ECDSA (SHA1/224/256/384/512/SHA3) | Y | Y | partial | NSS: P-256/384/521 only; no SHA-3 |
| EdDSA (Ed25519/Ed448) | Y | Y | partial | NSS keygen ok; params deviation (xfail) |
| ECDH (standard + cofactor) | Y | Y | partial | NSS: NIST curves only; no X448 import |
| DH (PKCS + X9.42) | Y | Y | N | NSS DH not advertised |
| DSA (SHA1/224/256/384/512/SHA3) | Y | Y | partial | NSS: keygen ok; extern key verify fails |
| HMAC (SHA-1/2/3 family) | Y | Y | partial | NSS: SHA-1/2 ok; SHA-3 advertised but no RSA |
| SHA-1/2/3 digests | Y | Y | Y | |
| HKDF | Y | Y | partial | NSS: correct length; wrong values (xfail) |
| SP800-108 KDF | N | Y | partial | NSS: counter ok; feedback/pipeline stub |
| ML-KEM (512/768/1024) | N | Y | partial | NSS-PQC: ML-KEM-768/1024 only |
| ML-DSA (44/65/87) | N | Y | N | Not in NSS 3.121.0 |
| SLH-DSA | N | Y | N | Not in NSS 3.121.0 |
| HASH_ML_DSA/HASH_SLH_DSA | N | Y | N | Phase D addition |
| HSS/XMSS/XMSS-MT | N | skip | N | Stateful sigs |
| DES/3DES | Y | N | N | Legacy, Phase E |
| Camellia | N | N | N | Phase E |
| GOST | N | N | N | Phase E |
| TLS 1.2 / SSL3 | N | N | N | Phase F |
| ChaCha20-Poly1305 | Y | Y | partial | NSS: non-standard param format (xfail) |
| IKE derive | Y | Y | partial | NSS: advertised but not operational (xfail) |
| BLAKE2 | N | N | N | Phase G |

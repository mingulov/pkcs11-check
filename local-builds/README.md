# Local Builds — Soft Token R&D

Local builds of PKCS#11 soft tokens for fast development and debugging.
Much faster than Docker rebuilds for iterative testing.

## Quick Start

```bash
# Build OpenSSL first (optional — for custom OpenSSL dependency)
bash local-builds/build.sh openssl

# Build a specific token
bash local-builds/build.sh kryoptic
bash local-builds/build.sh softhsm2

# Build with custom branch
bash local-builds/build-kryoptic.sh main          # latest dev
bash local-builds/build-softhsm2.sh master         # latest dev
bash local-builds/build-opencryptoki.sh v3.26.0     # specific version

# Build with custom OpenSSL
export OPENSSL_DIR=$(pwd)/local-builds/openssl/install
bash local-builds/build-softhsm2.sh

# Run tests
bash local-builds/test.sh kryoptic
bash local-builds/test.sh softhsm2-local
bash local-builds/test.sh kryoptic -k test_encrypt -v
```

## Available Tokens

| Token | Script | Language | Notes |
|-------|--------|----------|-------|
| **OpenSSL** | `build-openssl.sh` | C | Dependency for others. Default: 3.5.0 |
| **Kryoptic** | `build-kryoptic.sh` | Rust | v3.2, PQC support. Default: v1.5.0 |
| **SoftHSM2** | `build-softhsm2.sh` | C++ | v2.40. Default: 2.7.0. Supports OPENSSL_DIR |
| **OpenCryptoki** | `build-opencryptoki.sh` | C | v3.0, needs pkcsslotd. Default: v3.26.0 |
| **tpm2-pkcs11** | `build-tpm2-pkcs11.sh` | C | Needs swtpm + tpm2-abrmd |
| **pkcs11-mock** | `build-pkcs11-mock.sh` | C | v3.1 stub, minimal |
| **qryptotoken** | `build-qryptotoken.sh` | Rust | Experimental PQC (QUBIP) |
| **BouncyHSM** | `build-bouncyhsm.sh` | .NET | Needs dotnet SDK, TCP-based |

## Directory Layout

```
local-builds/
├── build.sh                # dispatcher — build any target
├── build-openssl.sh        # OpenSSL (dependency)
├── build-kryoptic.sh       # Kryoptic (Rust)
├── build-softhsm2.sh       # SoftHSM2 (C++)
├── build-opencryptoki.sh   # OpenCryptoki (C)
├── build-tpm2-pkcs11.sh    # tpm2-pkcs11 (C)
├── build-pkcs11-mock.sh    # pkcs11-mock (C)
├── build-qryptotoken.sh    # qryptotoken (Rust)
├── build-bouncyhsm.sh      # BouncyHSM (.NET)
├── test.sh                 # run p11test against any local build
├── openssl/                # OpenSSL source + install (gitignored)
├── kryoptic/               # Kryoptic source + lib (gitignored)
├── softhsm2/               # SoftHSM2 source + lib + install (gitignored)
├── ...                     # other tokens (gitignored)
└── tokens/                 # token data directories (gitignored)
```

## Custom OpenSSL

Build OpenSSL first, then use `OPENSSL_DIR` when building tokens:

```bash
bash local-builds/build-openssl.sh openssl-3.5.0
export OPENSSL_DIR=$(pwd)/local-builds/openssl/install

bash local-builds/build-softhsm2.sh       # links against custom OpenSSL
bash local-builds/build-opencryptoki.sh    # links against custom OpenSSL
```

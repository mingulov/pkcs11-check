# Local Builds — Soft Token R&D

Local builds of PKCS#11 soft tokens for fast development and debugging.
Each provider has a single file in `providers/` with `build()` and `setup()`.

## Quick Start

```bash
# Build OpenSSL (dependency for Kryoptic)
bash local-builds/build.sh openssl

# Build a token
bash local-builds/build.sh kryoptic
bash local-builds/build.sh softhsm2

# Run tests
bash local-builds/test.sh kryoptic
bash local-builds/test.sh softhsm2
bash local-builds/test.sh kryoptic -k test_encrypt -v
```

## Providers

Each file in `providers/` defines `build()` and `setup()` for one token:

| Provider | File | Language | Version | Notes |
|----------|------|----------|---------|-------|
| **OpenSSL** | `openssl.sh` | C | 4.0.0 | Build dependency, not a PKCS#11 provider |
| **Kryoptic** | `kryoptic.sh` | Rust | v1.5.0 | v3.2, PQC, auto-detects local OpenSSL |
| **SoftHSM2** | `softhsm2.sh` | C++ | 2.7.0 | v2.40, supports OPENSSL_DIR |
| **OpenCryptoki** | `opencryptoki.sh` | C | v3.27.0 | v3.0, needs pkcsslotd daemon |
| **tpm2-pkcs11** | `tpm2-pkcs11.sh` | C | 1.10.0 | Uses hardware TPM or swtpm |
| **pkcs11-mock** | `pkcs11-mock.sh` | C | v2.0.0 | v3.1 stub, single file |
| **qryptotoken** | `qryptotoken.sh` | Rust | v0.4.1 | Experimental PQC (QUBIP) |
| **BouncyHSM** | `bouncyhsm.sh` | .NET | v2.1.0 | Needs dotnet SDK 10.0, TCP server |

## Custom OpenSSL

```bash
bash local-builds/build.sh openssl
export OPENSSL_DIR=$PWD/local-builds/openssl/install
bash local-builds/build.sh softhsm2
bash local-builds/build.sh kryoptic  # auto-detects local OpenSSL
```

## Branch Switching

```bash
bash local-builds/build.sh kryoptic main     # latest dev
bash local-builds/build.sh softhsm2 master   # latest dev
bash local-builds/build.sh opencryptoki v3.27.0
```

## Directory Layout

```
local-builds/
├── build.sh          # dispatcher → providers/<name>.sh build()
├── test.sh           # dispatcher → providers/<name>.sh setup()
├── providers/        # one file per token: build() + setup()
│   ├── openssl.sh
│   ├── kryoptic.sh
│   ├── softhsm2.sh
│   ├── opencryptoki.sh
│   ├── tpm2-pkcs11.sh
│   ├── pkcs11-mock.sh
│   ├── qryptotoken.sh
│   └── bouncyhsm.sh
├── <token>/src/      # cloned source (gitignored)
├── <token>/lib/      # built .so files (gitignored)
└── tokens/           # token data dirs (gitignored)
```

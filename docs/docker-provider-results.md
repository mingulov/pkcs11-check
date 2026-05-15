# Docker Provider Validation Snapshot

This document records the Docker provider matrix evidence used for the v0.1.0
public release notes. It is release evidence, not a live dashboard.

## Snapshot Metadata

| Field | Value |
|-------|-------|
| Report generated | 2026-05-05 |
| pkcs11-check source state | dev working tree committed with this release-baseline update |
| Full-matrix artifact source | `artifacts/` |
| Full-matrix artifact date | 2026-05-04 to 2026-05-05 |
| Matrix command | `bash docker/test-all.sh --all --rebuild` |
| qryptotoken follow-up command | `bash docker/test-all.sh qryptotoken --rebuild` |
| Runner mode | per-file subprocess isolation |
| Artifact files used | `results.json`, `quality.json`, `state.json`, `console.log`, `build-status.json` |

The old `artifacts2/` directory has been removed. The statistics below come
from the refreshed `artifacts/` run. Failures, errors, and crashes are provider
findings unless explicitly identified as framework or harness bugs elsewhere;
they are not skipped or suppressed in the release evidence.

`qryptotoken` currently does not produce pytest results because upstream
`v0.4.1` fails to compile in the Fedora 44 Docker image with current
Rust/bindgen/clang. The Docker target now records this as
`artifacts/qryptotoken/build-status.json` instead of failing before any artifact
can be created.

## Source Inputs

| Docker target | Provider | Source | Selector | Resolved revision or package |
|---------------|----------|--------|----------|------------------------------|
| `softhsm2` | SoftHSM2 | `https://github.com/softhsm/SoftHSMv2.git` | `2.7.0` | `13e6e86b83748fef74046dbf0c91f664b7acc1c3` |
| `softhsm2-generated-iv` | SoftHSM2 generated-IV simulator | `https://github.com/softhsm/SoftHSMv2.git` plus local simulator patch | `2.7.0` | `13e6e86b83748fef74046dbf0c91f664b7acc1c3` |
| `softhsm2-main` | SoftHSM2 | `https://github.com/softhsm/SoftHSMv2.git` | `main` | `c274be21c08a0db21023aaa3028bb47985ac2417` |
| `kryoptic` | Kryoptic | `https://github.com/latchset/kryoptic.git` | `v1.5.0` | `f3a4ead8baa7568cf99d6dcb6e260b16d69cf010` |
| `kryoptic-main` | Kryoptic | `https://github.com/latchset/kryoptic.git` | default branch (`main`) | `f18e60d92a895cca551798644da544baf929668f` |
| `kryoptic-fips` | Kryoptic | `https://github.com/latchset/kryoptic.git` | default branch (`main`) | `f18e60d92a895cca551798644da544baf929668f` |
| `kryoptic-fips` | OpenSSL FIPS source input | `https://github.com/simo5/openssl.git` | `kryoptic_ossl40` | `2d0c89dff0e3a41ad8a83bd6389fedfff8279c7b` |
| `nss` | NSS softoken | Fedora 44 RPM | package | `nss-3.122.1-1.fc44`, `nss-softokn-3.122.1-1.fc44`, `nspr-4.38.2-9.fc44` |
| `nss-pqc` | NSS softoken | `https://hg.mozilla.org/projects/nss` | `tip` | `d281b0fc9954e4f711e4e1ec2a97c3dbdb78fe35` |
| `nss-pqc` | NSPR | `https://hg.mozilla.org/projects/nspr` | `tip` | `a9bf2eed0b558c3d0a9a0354f40d6f83a6730567` |
| `nss-main` | NSS softoken | `https://hg.mozilla.org/projects/nss` | `tip` | `d281b0fc9954e4f711e4e1ec2a97c3dbdb78fe35` |
| `nss-main` | NSPR | `https://hg.mozilla.org/projects/nspr` | `tip` | `a9bf2eed0b558c3d0a9a0354f40d6f83a6730567` |
| `opencryptoki` | OpenCryptoki SWToken | Fedora 44 RPM | package | `opencryptoki-3.26.0-2.fc44`, `opencryptoki-swtok-3.26.0-2.fc44` |
| `opencryptoki-master` | OpenCryptoki | `https://github.com/opencryptoki/opencryptoki.git` | `master` | `ba2550b01fbfd768b29eee959bd52f936022893e` |
| `bouncyhsm` | BouncyHSM | `https://github.com/harrison314/BouncyHsm.git` | `v2.0.1` | `9c37b66f70a6e1bba11e48f1e3c8e0ad964cf47e` |
| `tpm2` | tpm2-pkcs11 | Fedora 44 RPM | package | `tpm2-pkcs11-1.9.1-7.fc44`, `swtpm-0.10.1-3.fc44`, `tpm2-abrmd-3.0.0-9.fc44` |
| `pkcs11-mock` | pkcs11-mock | `https://github.com/Pkcs11Interop/pkcs11-mock.git` | default branch | `ac5f15adb92e15926825fa93e78a1995db1a32f8` |
| `qryptotoken` | qryptotoken | `https://github.com/QUBIP/qryptotoken.git` | `v0.4.1` | `24fae88227d6d04331fb599327db83c24d5ae955` |

Supporting source inputs resolved from the current Docker definitions:

| Component | Source | Selector | Resolved revision |
|-----------|--------|----------|-------------------|
| OpenSSL | `https://github.com/openssl/openssl.git` | `openssl-3.6.1` | `c9a9e5b10105ad850b6e4d1122c645c67767c341` |
| OpenSSL | `https://github.com/openssl/openssl.git` | `openssl-4.0.0-beta1` | `470ad1757ee81b9a92ae02c26e6a6076b3027bd6` |

## Full Matrix Test Results

| Docker target | Provider | Passed | Failed | Skipped | Xfailed | Errors | Crashed | Total |
|---------------|----------|-------:|-------:|--------:|--------:|-------:|--------:|------:|
| `softhsm2` | SoftHSM2 2.7.0 | 59,974 | 2,609 | 18,846 | 41 | 0 | 0 | 81,470 |
| `softhsm2-generated-iv` | SoftHSM2 generated-IV simulator | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| `softhsm2-main` | SoftHSM2 main | 61,329 | 2,701 | 18,163 | 41 | 0 | 0 | 82,234 |
| `kryoptic` | Kryoptic v1.5.0 | 67,254 | 2,846 | 32,356 | 68 | 0 | 0 | 102,524 |
| `kryoptic-main` | Kryoptic main | 67,264 | 2,838 | 32,354 | 68 | 0 | 0 | 102,524 |
| `kryoptic-fips` | Kryoptic FIPS main | 53,199 | 4,732 | 28,553 | 70 | 0 | 12 | 86,566 |
| `nss` | NSS stable | 48,294 | 2,660 | 33,903 | 101 | 0 | 0 | 84,958 |
| `nss-pqc` | NSS PQC source | 47,452 | 2,017 | 34,679 | 101 | 0 | 1 | 84,250 |
| `nss-main` | NSS main | 47,452 | 2,017 | 34,679 | 101 | 0 | 1 | 84,250 |
| `opencryptoki` | OpenCryptoki 3.26 | 69,287 | 2,403 | 15,726 | 55 | 0 | 0 | 87,471 |
| `opencryptoki-master` | OpenCryptoki master | 78,355 | 2,594 | 7,638 | 54 | 0 | 0 | 88,641 |
| `bouncyhsm` | BouncyHSM v2.0.1 | 66,794 | 22,309 | 9,914 | 58 | 0 | 3 | 99,078 |
| `tpm2` | tpm2-pkcs11 | 8,360 | 5,065 | 49,447 | 6 | 851 | 0 | 63,729 |
| `pkcs11-mock` | pkcs11-mock | 2,541 | 3,543 | 26,439 | 9 | 0 | 0 | 32,532 |
| **Result subtotal** | 14 pytest-producing targets | **677,557** | **58,334** | **342,697** | **773** | **851** | **17** | **1,080,229** |

`qryptotoken` is part of the Docker matrix but is not included in the subtotal
because no PKCS#11 module was built and no pytest run occurred.

| Docker target | Status | Artifact | Detail |
|---------------|--------|----------|--------|
| `qryptotoken` | build failed before module creation | `artifacts/qryptotoken/build-status.json` | upstream `v0.4.1` cargo build failed with exit code 101 |

## Coverage And Quality Summary

| Docker target | Units | Test records | Selection scenarios | Mechanisms available | Mechanisms invoked |
|---------------|------:|-------------:|--------------------:|---------------------:|-------------------:|
| `softhsm2` | 238 | 81,470 | 5 | 80 | 78 |
| `softhsm2-generated-iv` | 1 | 2 | 0 | 80 | 1 |
| `softhsm2-main` | 238 | 82,234 | 5 | 82 | 86 |
| `kryoptic` | 239 | 102,524 | 5 | 168 | 170 |
| `kryoptic-main` | 239 | 102,524 | 5 | 168 | 170 |
| `kryoptic-fips` | 239 | 86,566 | 5 | 151 | 149 |
| `nss` | 238 | 84,958 | 5 | 136 | 144 |
| `nss-pqc` | 238 | 84,250 | 5 | 140 | 142 |
| `nss-main` | 238 | 84,250 | 5 | 140 | 142 |
| `opencryptoki` | 238 | 87,471 | 5 | 147 | 147 |
| `opencryptoki-master` | 238 | 88,641 | 5 | 169 | 167 |
| `bouncyhsm` | 238 | 99,079 | 5 | 213 | 197 |
| `tpm2` | 238 | 63,729 | 5 | 34 | 37 |
| `pkcs11-mock` | 238 | 32,532 | 5 | 9 | 30 |

`mechanisms_invoked` can exceed `mechanisms_available` when a provider exposes
mechanism aliases, extension IDs, or selected tests exercise mechanisms outside
the provider-advertised baseline.

## Execution Notes

- `softhsm2-generated-iv` is a focused supplemental target for the locally
  patched generated-IV simulator. It intentionally ran only
  `src/pkcs11_check/testcases/test_aead.py` generated-IV coverage.
- `kryoptic-fips`, `nss-pqc`, `nss-main`, and `bouncyhsm` produced crash
  findings in isolated subprocesses; the matrix continued and recorded those
  crashes in `results.json`.
- `tpm2` produced pytest error records but no unit-level harness errors or
  timeouts. A Docker wrapper hang caused by `tpm2-abrmd` inheriting the artifact
  logging pipe was fixed after this run.
- `qryptotoken` remains a tracked target, but current upstream `v0.4.1` is a
  build-unavailable provider for this baseline.

# PKCS#11 implementations exercised

pkcs11-check runs against *any* PKCS#11 module you point it at. This page lists
the open-source implementations it is regularly exercised against, with upstream
links. It is evidence of breadth, not a compatibility guarantee or an
endorsement; behavior is observed, not certified.

Exact versions are intentionally omitted: they move over time, and pkcs11-check
is not pinned to any of them. For the precise build used in a given run, see that
run's own evidence.

Several of the C/C++ implementations are additionally exercised under a separate
*AddressSanitizer + UBSan* build, so memory-safety findings surface as crashes
under instrumentation. Those are marked *ASAN* below.

## Software HSMs and tokens

| Implementation | Language | Upstream |
|---|---|---|
| SoftHSM2 *(ASAN)* | C/C++ | [softhsm/SoftHSMv2](https://github.com/softhsm/SoftHSMv2) |
| Kryoptic | Rust | [latchset/kryoptic](https://github.com/latchset/kryoptic) |
| NSS softoken *(ASAN)* | C | [mozilla/nss](https://github.com/mozilla/nss) |
| OpenCryptoki *(ASAN)* | C | [opencryptoki/opencryptoki](https://github.com/opencryptoki/opencryptoki) |
| wolfPKCS11 *(ASAN)* | C | [wolfSSL/wolfPKCS11](https://github.com/wolfSSL/wolfPKCS11) |
| corePKCS11 | C | [FreeRTOS/corePKCS11](https://github.com/FreeRTOS/corePKCS11) |
| FreeHSM (C) *(ASAN)* | C | [afchine1337/freehsm-c](https://github.com/afchine1337/freehsm-c) |
| BouncyHSM | C# | [harrison314/BouncyHsm](https://github.com/harrison314/BouncyHsm) |
| Craton HSM (core) | - | [craton-co/craton-hsm-core](https://github.com/craton-co/craton-hsm-core) |

## TPM-backed

| Implementation | Language | Upstream |
|---|---|---|
| tpm2-pkcs11 | C | [tpm2-software/tpm2-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) |
| wolfPKCS11 (wolfTPM backend) | C | [wolfSSL/wolfPKCS11](https://github.com/wolfSSL/wolfPKCS11) + [wolfSSL/wolfTPM](https://github.com/wolfSSL/wolfTPM) |
| OP-TEE PKCS#11 TA | C (TEE) | [OP-TEE/optee_os](https://github.com/OP-TEE/optee_os) |

## Cloud KMS bridges

| Implementation | Language | Upstream |
|---|---|---|
| Google Cloud KMS PKCS#11 (kmsp11) | C++ | [GoogleCloudPlatform/kms-integrations](https://github.com/GoogleCloudPlatform/kms-integrations) |
| Cosmian KMS | Rust | [cosmian/kms](https://github.com/cosmian/kms) |
| Nitrokey NetHSM | Rust | [Nitrokey/nethsm-pkcs11](https://github.com/Nitrokey/nethsm-pkcs11) |

## Smart cards and simulators

| Implementation | Language | Upstream |
|---|---|---|
| Pico HSM (SmartCard-HSM emulation) | C | [polhenarejos/pico-hsm](https://github.com/polhenarejos/pico-hsm) |
| Cryptech Open HSM | C | [cryptech.is sw/pkcs11](https://git.cryptech.is/sw/pkcs11) |
| IsoApplet on jcardsim | Java | [philipWendland/IsoApplet](https://github.com/philipWendland/IsoApplet) + [ph4r05/jcardsim](https://github.com/ph4r05/jcardsim) |
| PivApplet (PIV smart card) | Java | [arekinath/PivApplet](https://github.com/arekinath/PivApplet) |

## Stubs and harness mocks

These are not real cryptographic providers; they return canned values or
implement only a minimal surface, and are used to exercise pkcs11-check's own
plumbing rather than to find crypto findings.

| Implementation | Language | Upstream |
|---|---|---|
| pkcs11-mock | C | [Pkcs11Interop/pkcs11-mock](https://github.com/Pkcs11Interop/pkcs11-mock) |
| empty-pkcs11 | C | [Pkcs11Interop/empty-pkcs11](https://github.com/Pkcs11Interop/empty-pkcs11) |

# Per-Failure Triage — Executive Summary

**Source:** `docs/findings/per-failure-triage/verdicts.jsonl` (effective view, superseded records removed)
**Date:** 2026-06-13
**Scope:** 7 providers × artifacts_base data (no fresh docker). See parent plan `docs/superpowers/plans/2026-06-13-per-failure-triage.md`.

## Headline counts

- **2 CRITICAL** findings
- **381 HIGH** findings (of which **148** routed USER_ESCALATION)
- **3039** effective verdict records (superseded ones dropped)

## Per-provider table

| Provider | Total | PROVIDER_BUG | KNOWN_ISSUE | SOFT_TOKEN_CAVEAT | HARNESS_BUG | UNKNOWN | CRITICAL | HIGH |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| [wolfpkcs11-master](wolfpkcs11-master.md) | 514 | 251 | 111 | 36 | 0 | 116 | 0 | 52 |
| [opencryptoki-master](opencryptoki-master.md) | 544 | 412 | 5 | 43 | 0 | 83 | 0 | 178 |
| [corepkcs11-main](corepkcs11-main.md) | 170 | 53 | 24 | 19 | 14 | 60 | 0 | 9 |
| [kryoptic-main](kryoptic-main.md) | 807 | 181 | 526 | 65 | 0 | 35 | 1 | 58 |
| [nss-main](nss-main.md) | 488 | 260 | 117 | 54 | 0 | 57 | 0 | 62 |
| [softhsm2-main](softhsm2-main.md) | 185 | 78 | 29 | 35 | 0 | 42 | 0 | 8 |
| [tpm2](tpm2.md) | 331 | 194 | 45 | 18 | 2 | 72 | 1 | 14 |

## Top-priority findings across all providers

| Severity | Provider | Test file | Direction | Routing | Signature |
|---|---|---|---|---|---|
| **CRITICAL** | kryoptic-main | `test_aes_kdf.py` | OTHER | 📨 PROVIDER_REPORT | `sha1:bbe36dcd8a03c859#ph` |
| **CRITICAL** | tpm2 | `test_sensitivity.py` | OTHER | 📨 PROVIDER_REPORT | `sha1:330d6f7e694f71a9#ph` |
| **HIGH** | kryoptic-main | `test_ckr_raw_buffer.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:8ac8b1be5f5c17a2` |
| **HIGH** | kryoptic-main | `test_errors.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:6d9fb730e7f542c6` |
| **HIGH** | kryoptic-main | `test_errors.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:6a48ba1d79747bc5` |
| **HIGH** | kryoptic-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:b2ed1595109a0f66#ph` |
| **HIGH** | kryoptic-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:a300b263485f5a97#ph` |
| **HIGH** | kryoptic-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:1f48de11c63e0623#ph` |
| **HIGH** | kryoptic-main | `test_set_attribute.py` | ACCEPT_INVALID | 📨 PROVIDER_REPORT | `sha1:7de735f304368f99#ph` |
| **HIGH** | kryoptic-main | `test_set_attribute.py` | ACCEPT_INVALID | 📨 PROVIDER_REPORT | `sha1:33f58e21cebe13cf#ph` |
| **HIGH** | kryoptic-main | `test_set_attribute.py` | ACCEPT_INVALID | 📨 PROVIDER_REPORT | `sha1:3084d1d72871f1c4#ph` |
| **HIGH** | kryoptic-main | `test_ckr_object.py` | ACCEPT_INVALID | 📨 PROVIDER_REPORT | `sha1:dc4ef445fa0d38fd#ph` |
| **HIGH** | kryoptic-main | `test_sp800_108_kdf.py` | WRONG_OUTPUT | 🔍 MANUAL_REVIEW | `sha1:425ead980697b227#ph` |
| **HIGH** | kryoptic-main | `test_sp800_108_kdf.py` | WRONG_OUTPUT | 🔍 MANUAL_REVIEW | `sha1:a2194647ac713ec4#ph` |
| **HIGH** | kryoptic-main | `test_misc_kdf.py` | WRONG_OUTPUT | 📨 PROVIDER_REPORT | `sha1:1ffad442544cdfd3#ph` |
| **HIGH** | kryoptic-main | `test_misc_kdf.py` | WRONG_OUTPUT | 📨 PROVIDER_REPORT | `sha1:7615c2e7aa87d32e#ph` |
| **HIGH** | kryoptic-main | `test_tls12.py` | WRONG_OUTPUT | 🔍 MANUAL_REVIEW | `sha1:f98e714feabb1580#ph` |
| **HIGH** | kryoptic-main | `test_ckr_decrypt.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:06d6e9e0d43eec23#ph` |
| **HIGH** | kryoptic-main | `test_mech_message.py` | OTHER | 📨 PROVIDER_REPORT | `sha1:7bed6bf851c2019f#ph` |
| **HIGH** | kryoptic-main | `test_access_levels.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:c406a8eaf0c54026#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:0694006e303c2696#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:c8b3a59e5156f0b0#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:d1d7a1ce3771bd1a#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:2b8fd0ae8d585cfd#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:7f83ae8d23f73e01#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:dedf25e2a49baf74#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:7bcb31816002f619#ph` |
| **HIGH** | kryoptic-main | `test_operation_termination.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:f56d2a08ace19b07#ph` |
| **HIGH** | nss-main | `-` | CRASH |  PROVIDER_REPORT(nss-main) | `crash:nss-main:src/pkcs1` |
| **HIGH** | nss-main | `-` | CRASH |  PROVIDER_REPORT(nss-main) | `crash:nss-main:src/pkcs1` |
| **HIGH** | nss-main | `-` | CRASH |  PROVIDER_REPORT(nss-main) | `crash:nss-main:src/pkcs1` |
| **HIGH** | nss-main | `test_ckr_raw_buffer.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:096be681354cac5e` |
| **HIGH** | nss-main | `test_ckr_raw_buffer.py` | CLEAN_ERROR | 📨 PROVIDER_REPORT | `sha1:9f97b3353fe18f25` |
| **HIGH** | nss-main | `test_ckr_raw_buffer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:bff27217ca8b8e04#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:aeb975f7959bac7d#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:09accbd00fa92e1c#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:fb91deb9ca82d1bd#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:98e9667a95ba6d49#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:864ecb6dceced501#ph` |
| **HIGH** | nss-main | `test_ffi_null_pointer.py` | CRASH | 📨 PROVIDER_REPORT | `sha1:5da3e8b4d83cb77d#ph` |

*…and 210 more CRITICAL/HIGH findings in per-provider reports.*

## Cross-cutting themes (universal patterns)

See `_universal.md` for full analysis. Themes with multi-provider impact:

| Theme | Worst severity | Providers affected |
|---|---|---|
| Wrong-output / crypto-correctness | CRITICAL | 4 — kryoptic, nss, softhsm2, wolfpkcs11 |
| Advertised-but-not-operational mechanism | HIGH | 7 — corepkcs11, kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11 |
| CBC-PKCS5 padding oracle (Vaudenay) | HIGH | 6 — kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11 |
| Op-termination lifecycle | HIGH | 6 — kryoptic, nss, opencryptoki, softhsm2, tpm2, wolfpkcs11 |
| Trust-boundary attribute escalation | HIGH | 4 — corepkcs11, kryoptic, nss, wolfpkcs11 |
| NULL-pointer SIGSEGV family | HIGH | 1 — nss |
| Wrap/unwrap policy bypass | HIGH | 1 — nss |
| Buffer-size protocol deviation | MEDIUM | 5 — corepkcs11, kryoptic, nss, opencryptoki, wolfpkcs11 |
| Wrong CKR for invalid signatures | MEDIUM | 1 — wolfpkcs11 |

## Per-provider reports

- [wolfpkcs11-master](wolfpkcs11-master.md)
- [opencryptoki-master](opencryptoki-master.md)
- [corepkcs11-main](corepkcs11-main.md)
- [kryoptic-main](kryoptic-main.md)
- [nss-main](nss-main.md)
- [softhsm2-main](softhsm2-main.md)
- [tpm2](tpm2.md)

## Methodology and notes

- Records appended idempotently to `verdicts.jsonl`; superseded records filtered out here.
- `UNKNOWN` records are not classified; they appear in a trailing section per provider for follow-up.
- Per user direction (m0213-m0214), classification extension stopped on 2026-06-13; remaining UNKNOWNs will be classified by a different (in-tool) workflow.

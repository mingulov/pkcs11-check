# Test Universe Snapshot

This snapshot describes the product tests under `src/pkcs11_check/testcases/`.
It does not include pkcs11-check's own meta-tests under `tests/`.

The counts were verified on 2026-05-25 with pytest collection metadata. They
are collected test items before provider-specific runtime skips, xfails,
failures, crashes, timeouts, or marker filters.

## Headline Counts

| Count | Meaning |
| --- | ---: |
| Raw generated pytest nodes | 109,608 |
| Collection-time deselected AES-CTS variant nodes | 7,499 |
| Active baseline collection without a CTS variant | 102,109 |
| Single-provider maximum with AES-CTS CS1 | 104,744 |
| Single-provider maximum with AES-CTS CS2 | 104,495 |
| Single-provider maximum with AES-CTS CS3 | 104,587 |

For an article or release report, the safest short phrasing is:

> pkcs11-check currently has about 105k provider-facing product tests. The raw
> generated collection is 109,608 pytest nodes, but a single provider can only
> select one AES-CTS variant, so the exact fully capable provider maximum is
> 104,744 tests with the largest CTS variant.

## Group Breakdown

This table is the active baseline collection before adding one provider-selected
AES-CTS variant.

| Group | Collected tests |
| --- | ---: |
| Wycheproof ECDSA vectors | 28,915 |
| ACVP AES vectors before CTS add-on | 25,599 |
| Wycheproof other vectors | 23,986 |
| Wycheproof ECDH vectors | 13,128 |
| ACVP non-AES vectors | 5,309 |
| General conformance / interop tests | 2,266 |
| CCTV vectors | 1,365 |
| Stress tests | 1,046 |
| Security regression tests | 274 |
| Raw CKR/API negative tests | 178 |
| Fuzz tests | 43 |
| **Active baseline total** | **102,109** |

## AES-CTS Variant Add-On

PKCS#11 exposes `CKM_AES_CTS` without naming the CS1, CS2, or CS3 variant.
pkcs11-check probes the provider at collection time and keeps only the matching
variant vectors. The three variant families must not be summed into a
single-provider pass target.

| CTS variant selected by provider | Additional CTS tests | ACVP AES group total | Single-provider total |
| --- | ---: | ---: | ---: |
| CS1 | 2,635 | 28,234 | 104,744 |
| CS2 | 2,386 | 27,985 | 104,495 |
| CS3 | 2,478 | 28,077 | 104,587 |
| Raw generated nodes before CTS deselection | 7,499 | 33,098 | 109,608 |

# Test Universe Snapshot

This snapshot describes the product tests under `src/pkcs11_check/testcases/`.
It does not include pkcs11-check's own meta-tests under `tests/`.

> *Point-in-time snapshot.* These counts are from late May 2026 (around the
> v0.1.1 release) and are already out of date: the suite grows and is
> reclassified with every release, so the exact figures below are illustrative,
> not current. Treat them as orders of magnitude (">100k product tests"), not
> exact totals. For the live count, run pytest collection (`--collect-only`)
> over `src/pkcs11_check/testcases/`.

The counts were verified on 2026-05-25 with pytest collection metadata. They
are collected test items before provider-specific runtime skips, xfails,
failures, crashes, timeouts, or marker filters.

> **Status (2026-05-28):** suite size is ~stable at **~109k** collected product-test nodes
> (the classification fixes reframe vectors but barely change the count). Large counts (>1000)
> are rounded to ~Xk to avoid churn; a minor refresh accompanies the FP-8 rerun.

## Headline Counts

| Count | Meaning |
| --- | ---: |
| Raw reportable pytest nodes, including all AES-CTS variants | 109,608 |
| AES-CTS variant nodes in the raw collection | 7,499 |
| Provider-executable baseline before adding one CTS variant | 102,109 |
| Largest executable clean-pass target with AES-CTS CS1 | 104,744 |
| Executable clean-pass target with AES-CTS CS2 | 104,495 |
| Executable clean-pass target with AES-CTS CS3 | 104,587 |

For an article or release report, the safest short phrasing is:

> pkcs11-check currently has >100k provider-executable product tests. The
> raw reportable collection is 109,608 pytest nodes, including all AES-CTS
> variants, but a single provider can only execute one CTS variant as a clean
> pass target. The largest fully capable executable target is 104,744 tests with
> CS1; the remaining CTS variants should be counted as not-applicable skips, not
> as missing tests.

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
pkcs11-check probes the provider at collection time and marks non-matching
variant vectors as skipped. The three variant families remain visible in the
reported test universe, but they must not be summed into a single-provider
clean-pass target.

| CTS variant selected by provider | Additional CTS tests | ACVP AES group total | Single-provider total |
| --- | ---: | ---: | ---: |
| CS1 | 2,635 | 28,234 | 104,744 |
| CS2 | 2,386 | 27,985 | 104,495 |
| CS3 | 2,478 | 28,077 | 104,587 |
| Raw reportable nodes before CTS skip marking | 7,499 | 33,098 | 109,608 |

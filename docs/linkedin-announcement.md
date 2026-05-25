# LinkedIn Announcement Draft

This is a short public-facing announcement draft for pkcs11-check. It is meant
for LinkedIn or a similar project announcement post, not as a technical provider
scorecard.

## Suggested Post

pkcs11-check is now public.

It is an open source PKCS#11 test suite for checking real modules: software
tokens, HSMs, smart cards, vendor modules, and internal or proprietary
providers.

The goal is simple: make PKCS#11 behavior easier to test, reproduce, and
discuss.

Current scope:

- about 105k provider-facing product tests for a fully capable provider
- vectors from Wycheproof, NIST ACVP, CCTV, and x509-limbo
- hand-written conformance, CKR/API negative, CVE regression, security, fuzz,
  and stress tests
- PKCS#11 v2.40 through v3.2 interface negotiation, including PQC mechanisms
- file-level subprocess isolation so one provider crash does not stop the whole
  run

The current Docker validation snapshot covers SoftHSM2, Kryoptic, NSS,
OpenCryptoki, TPM2, BouncyHSM, pkcs11-mock, and qryptotoken. Results vary, and
that is the point: pkcs11-check is intended to expose actual provider behavior,
including crashes, wrong CKR return codes, unsupported mechanisms, timeouts, and
build or configuration gaps.

If you maintain a PKCS#11 provider, including one that is not open source, you
can run pkcs11-check locally against your own module and keep the results
private. If you publish results, they become useful interoperability evidence
for the wider PKCS#11 ecosystem.

Project:
https://github.com/mingulov/pkcs11-check

Documentation:
https://github.com/mingulov/pkcs11-check/tree/main/docs

The tool is still young, but it is already useful for finding real
implementation bugs and comparing behavior across providers. Feedback and
additional provider results are welcome.

## Compact Numbers

These are the safest current numbers to mention in the announcement or in a
follow-up comment.

| Item | Current value |
| --- | ---: |
| Raw generated pytest nodes | 109,608 |
| Active baseline before provider-selected AES-CTS variant | 102,109 |
| Largest single-provider collection | 104,744 |
| Vector-derived active baseline tests | 98,302 |
| General/security/stress/negative/fuzz active baseline tests | 3,807 |

For exact group breakdowns and AES-CTS variant handling, use
[test-universe.md](test-universe.md). For current provider build sources and
matrix results, use [docker-provider-results.md](docker-provider-results.md).

## Tone Notes

- Say "provider-facing product tests" instead of implying every generated node
  can be selected by one provider.
- Say "validation snapshot" instead of "benchmark"; the goal is behavioral
  evidence, not performance ranking.
- Say that failures and crashes are retained as findings. Do not imply that a
  clean pass rate is the only useful result.
- Mention proprietary/internal modules explicitly: users can run the tool
  locally without publishing their provider or results.

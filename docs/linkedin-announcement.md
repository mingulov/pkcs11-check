# LinkedIn Announcement Draft

This is a short public-facing announcement draft for pkcs11-check. It is meant
for LinkedIn or a similar project announcement post, not as a technical provider
scorecard.

## Suggested Post

pkcs11-check is now public.

It is an open source PKCS#11 test suite for checking real modules: software
tokens, HSMs, smart cards, vendor modules, and internal or proprietary
providers.

The goal is simple: make PKCS#11 behavior easier to test, reproduce, compare,
and discuss.

Current scope:

- about 105k provider-facing product tests for a fully capable provider
- vectors from Wycheproof, NIST ACVP, CCTV, and x509-limbo
- hand-written conformance, CKR/API negative, CVE regression, security, fuzz,
  and stress tests
- PKCS#11 v2.40 through v3.2 interface negotiation, including PQC mechanisms
- file-level subprocess isolation so one provider crash does not stop the whole
  run

For the current validation snapshot I tested several software PKCS#11 providers
and simulators: SoftHSM2, Kryoptic, NSS softoken, OpenCryptoki, tpm2-pkcs11,
plus long-tail/mock targets such as BouncyHSM, pkcs11-mock, and qryptotoken.

The useful part is not just pass/fail counts. pkcs11-check keeps crashes, wrong
CKR return codes, unsupported mechanisms, timeouts, and build/configuration
problems visible instead of hiding them. That makes the results useful for
maintainers and for users comparing provider behavior.

If you maintain a PKCS#11 provider, including one that is not open source, you
can run pkcs11-check locally against your own module and keep the results
private. If you publish results, they become useful interoperability evidence.

Project:
https://github.com/mingulov/pkcs11-check

Current provider snapshot:
https://github.com/mingulov/pkcs11-check/blob/main/docs/docker-provider-results.md

The tool is still young, but it is already useful for finding implementation
bugs and comparing behavior across providers. Feedback and additional provider
results are welcome.

## Optional First Comment

The provider snapshot includes exact source refs, build policy, OpenSSL version
selection, total/pass/fail/skip/crash counts, and notes for providers that are
build-only or segmented.

Crash and timeout classification:
https://github.com/mingulov/pkcs11-check/blob/main/docs/provider-crash-failure-findings.md

Test-suite size and group breakdown:
https://github.com/mingulov/pkcs11-check/blob/main/docs/test-universe.md

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
- Do not foreground BouncyHSM. It is useful as a long-tail simulator example,
  but the article should center the tool and the broader provider method.
- Mention proprietary/internal modules explicitly: users can run the tool
  locally without publishing their provider or results.
- If the provider result pages are not on `main` yet, use a branch or commit
  URL for the LinkedIn post and replace it with the `main` URL after merge.

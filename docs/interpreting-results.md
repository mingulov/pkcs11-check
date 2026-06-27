# Interpreting results — why xfail and skip counts are large

A run collects ~110k+ items per module. Most are **skipped** (mechanism not advertised) and most **xfail** is `not_operational`. A high xfail count is **not** a pile of crypto deviations.

## `not_operational` is mostly a capability gap, amplified by vector count

The dominant `not_operational` pattern is an advertised **mechanism** (e.g. `CKM_ECDSA`, `CKM_ECDH`, `CKM_RSA_PKCS`) exercised with an **unsupported curve or key size** (brainpoolP224r1, Montgomery, RSA-1024). PKCS#11 has no per-curve capability flag, so the harness can only discover this by trying; a clean rejection of an unsupported curve is conformant, but it is recorded as a deviation and multiplied by the entire wycheproof/ACVP vector file — so one capability gap becomes thousands of `not_operational` xfails (the same curve produced the identical ~12k count across unrelated modules).

**Read the reasoned buckets, not the raw xfail total:** `honest_deviation`, `nonspec_reject`, in-range `not_operational`, and the `fail` list (`accepted_invalid`, `self_contradiction`, `wrong_result`, `crash`). Those are the findings.

## `crash_limited` and incomplete coverage

When a module crashes repeatedly in one file, the runner abandons that file's remaining tests after `--max-crashes-per-file` (default 10) and records them as `crash_limited` (a skipped-class outcome counted in `total`). `summary.incomplete` is then true and the report shows an INCOMPLETE COVERAGE banner. These tests' true outcome is unknown — re-run to probe them.

**Resume caveat:** a resumed run does not re-attempt `crash_limited` units (they are in `_RESUME_COMPLETE_STATUSES`); a fresh run is required to re-probe them.

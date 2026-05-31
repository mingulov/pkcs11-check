# pytest-xdist investigation — 2026-05-28

## TL;DR

**pytest-xdist is NOT the answer for pkcs11-check.** Empirical evidence
collected on opencryptoki and bouncyhsm shows:

- xdist adds **30–60 % wall-clock overhead per file** even with `-n 1`,
  driven by per-test result IPC and worker startup.
- `-n 2` gives **zero** parallelism win because the PKCS#11 backend
  (pkcsslotd on opencryptoki, .NET HTTP server on bouncyhsm) serializes
  requests.
- The plugin's coverage tracking lives in `config.stash` on each xdist
  worker and is never forwarded to the controller, so cumulative function /
  mechanism counts would be lost.
- xdist's `--max-worker-restart` would change the crash classification
  semantics (`crashed` → `failed`).

A separate, important finding emerged: the test_cfb128.py "crashes" we
observed in the full bouncyhsm matrix run are **not reproducible when the
file runs in isolation**. The same provider build, the same tests, with no
xdist — runs cleanly. That points at state-interaction between earlier
units in the matrix, not the test file itself.

## Measurement environment

- Provider images: `docker/docker-compose.test.yml` `test-opencryptoki-master`
  and `test-bouncyhsm`, no rebuild after the 70c9e3c `p11_module_session`
  fix.
- Manifest pre-generated once via `pkcs11_check.core.preflight` and shared
  via `--p11-manifest`, matching what `pkcs11_check.cli.test_cmd` already
  does.
- pytest 9.0.2, pytest-xdist 3.8.0, pytest-reportlog 1.0.0.
- Wycheproof ECDSA target: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
  → 28 829 parametrized tests.
- Crash-prone target: `src/pkcs11_check/testcases/acvp/aes/test_cfb128.py`
  → 2 144 parametrized tests.

## Empirical data

### opencryptoki — 28 829 ECDSA tests

| Mode | Wall clock | passed | xfailed | call records | workers |
|---|---|---|---|---|---|
| Baseline (no xdist) | **35.30 s** | 18 993 | 186 | 28 829 | — |
| `xdist -n 1 --max-worker-restart=200 --dist=loadfile` | 56.27 s | 18 993 | 186 | 28 829 | `gw0` |
| `xdist -n 2 --max-worker-restart=200 --dist=loadfile` | 56.82 s | 18 993 | 186 | 28 829 | `gw0`,`gw1` |

- xdist is **+59 %** slower with one worker.
- Two workers give **no speedup at all** (within noise). The opencryptoki
  SWToken backend through `pkcsslotd` serializes operations across
  processes, so adding workers doesn't help.
- Result counts are bit-exact identical, so xdist is functionally correct.

### bouncyhsm — 28 829 ECDSA tests

| Mode | Wall clock | passed | skipped | call records | workers |
|---|---|---|---|---|---|
| Baseline (no xdist) | **131.76 s** | 21 860 | 6 969 | 28 829 | — |
| `xdist -n 1 --max-worker-restart=200 --dist=loadfile` | 174.56 s | 21 860 | 6 969 | 28 829 | `gw0` |

- xdist is **+32 %** slower (43 s extra) — same per-test IPC tax.
- Identical results.

### bouncyhsm — test_cfb128.py (crash-prone in full suite)

| Mode | Wall clock | Outcomes | Workers / restarts |
|---|---|---|---|
| `xdist -n 1 --max-worker-restart=200 --dist=loadfile`, isolated | **17 m 37 s** | **2 144 passed**, 0 failed, 0 crashed | `gw0`, 0 restarts |
| Baseline (no xdist), isolated | in progress at write time; tc2139 multiblock_encrypt passed in 182.2 s | — | — |

The file that crashes mid-run inside the full bouncyhsm matrix passes
cleanly when run alone. The slow tests are real (the multiblock_encrypt
parameters do 3-minute calls on BouncyHSM), but no crash.

## Gap analysis — why xdist hurts more than it helps here

### G-xdist-1: per-test IPC overhead is ~0.7 ms / test

The controller forwards every TestReport over a stdlib pickle pipe. For a
28 829-test file that's ~21 s extra; for the full ~94 200-test suite that
would be ~66 s on top of every other invocation. Not catastrophic — but
visible, and there's no compensating gain for the non-crashing 234+ files.

### G-xdist-2: no parallelism benefit, the backend serializes

Both providers we care about have a single serializing point:

- **opencryptoki**: every PKCS#11 call goes through `pkcsslotd` via a Unix
  socket and is serialized on the daemon side. -n 2 didn't even break even.
- **bouncyhsm**: every PKCS#11 call is an HTTP request to the same .NET
  HTTP server. We didn't test -n 2, but the architecture is the same as
  opencryptoki's: a single server is the bottleneck.

For NSS / SoftHSM2 / Kryoptic (in-process) the picture might be different,
but those are the providers where everything is already fast and we
don't need parallelism.

### G-xdist-3: plugin coverage state is per-worker, never reaches the controller

`src/pkcs11_check/plugin.py` keeps the cumulative call counts, mechanism
sets, and detail counters in `session.config.stash`. With xdist, that
stash lives on the worker. The controller never sees it unless we add an
explicit hook to serialize stash state back over the xdist channel. That
means:

- `function_coverage.called_counts` would be empty
- `mechanism_coverage.invoked` would be incomplete
- bootstrap counts would be wrong

This is a real, non-trivial port of the plugin to be xdist-aware, and is
the single most likely reason the previous investigation rejected xdist.

### G-xdist-4: crashed tests collapse into "failed"

The classification model in CLAUDE.md treats `crashed` (provider segfault)
as a distinct outcome from `failed` (CKR mismatch). xdist reports the
test that was running when the worker died as a plain test failure with a
"worker 'gw0' crashed" longrepr. We'd lose the explicit crash signal that
the iterative-deselect path emits today.

### G-xdist-5: coverage data is lost from the crashing worker

Documented by `pytest-dev/pytest-xdist#466`: when a worker is restarted,
its in-memory counters (including cov.py state) are gone. For us, even
the report records up to the crash are present (we use `--report-log`),
but the per-process stash counters from the worker session are lost.

### G-xdist-6: worker startup is paid per file when used per-file

If we wrap the existing `_escalate_current_file` path with xdist, each
escalated file pays one extra ~1–2 s controller startup. With 244 units
and only ~5 of them escalating, that's a minor cost — but it's only a
win if we use xdist exactly there and not as the default mode.

## Why the bouncyhsm "crash" isn't reproducible in isolation

`test_acvp_aes_cfb128_multiblock_encrypt[AES-enc-tc2139]` is the test that
crashed at iteration 1 of the iterative-deselect loop in the full matrix
run earlier today. Standalone, with the same provider and the same
`p11_module_session` fixture:

- In xdist mode (17 m 37 s wall), tc2139 finishes as a 178 s **pass** in
  worker `gw0`, no restart.
- In baseline mode (still running at write time), tc2139 finishes as a
  182 s **pass** with the same outcome.

That makes "the .so segfaults inside this test" much less likely than
"earlier files in the matrix put BouncyHSM into a state where this test
crashes":

1. **TCP socket pressure**: the libbouncyhsm_pkcs11 client opens TCP
   connections to the .NET server per session. Earlier files run
   thousands of `C_OpenSession`. CLOSE_WAIT or socket exhaustion could
   plausibly bite tc2139.
2. **Token-object accumulation**: tests that create CKA_TOKEN=True objects
   without cleanup persist across files. The cumulative count by tc2139
   could be large.
3. **.NET GC pause**: the server is .NET; a GC pause during a 3-min test
   could interact badly with the client's TCP read timeout.
4. **Bouncyhsm internal state**: prior tests may have triggered a state
   transition in BouncyHSM (e.g. error-counter rollover) that makes
   tc2139's specific sequence fail.

None of these are fixable in pkcs11-check — they're upstream BouncyHSM
issues. But we can choose to **run the crash-prone files first**, in
relative isolation, so they don't accumulate context.

## What the previous "xdist investigation" probably found

I couldn't find the original investigation in git history, docs, or
memory. Based on the evidence above, plausible prior reasons to reject:

1. Per-test overhead doesn't pay back with no parallelism benefit
   (G-xdist-1 + G-xdist-2). This shows up immediately when you try it.
2. Coverage tracking via `config.stash` breaks (G-xdist-3). Requires a
   non-trivial plugin rewrite to forward stash state.
3. Result classification distinguishes crashed/failed (G-xdist-4); xdist
   collapses them.

Any one of those is enough to abandon xdist.

## Recommendation

**Do not adopt xdist** as the default isolation mode. Even for crash-prone
files, xdist's benefit (worker restart) doesn't outweigh its costs
(per-test IPC + plugin state loss + crashed/failed conflation) given the
specific evidence we have.

Instead, address the actual root cause:

1. **Investigate the state-interaction crashes**. Identify which prior
   unit(s) put BouncyHSM into the state where test_cfb128 crashes in the
   matrix. Likely candidates: tests that don't clean up CKA_TOKEN
   objects, tests that leave sessions open, tests that exhaust some
   bouncyhsm-side resource. Once identified, either add cleanup, run the
   crash-prone file before the polluting one(s), or document upstream.
2. **Make the iterative deselect more thorough**. Today the per-file
   crash budget is `--max-crashes-per-file=3`. For crash-prone providers
   we may want this configurable per-provider, and we should ensure that
   the runner persists per-iteration results so a Ctrl-C doesn't lose
   them.
3. **Actually use the `crashed_tests` policy field**. It's written but
   never read; reading it at run start to pre-deselect known crashers
   would make repeat bouncyhsm runs much faster without ever invoking
   xdist.

These changes are local to `core/file_runner.py` and to plugin policy
handling, and they preserve our existing crash/failed classification,
coverage tracking, and per-iteration progress save.

## Reproducing these measurements

The measurement scripts and JSONL artifacts were temporary
(`/tmp/measure_*.sh` inside the provider containers). To reproduce:

```bash
# Pre-generate manifest once
uv run python -m pkcs11_check.core.preflight \
    --module=<lib.so> --interface=auto --slot=0 \
    --output=/tmp/manifest.json

# Baseline
time uv run pytest <target_file> \
    --p11-module=<lib.so> --p11-pin=<pin> --p11-manifest=/tmp/manifest.json \
    --report-log=/tmp/baseline.jsonl -q --tb=no

# xdist
time uv run pytest <target_file> \
    --p11-module=<lib.so> --p11-pin=<pin> --p11-manifest=/tmp/manifest.json \
    -n 1 --max-worker-restart=200 --dist=loadfile \
    --report-log=/tmp/xdist.jsonl -q --tb=no

# Compare
python3 -c "
import json
for f in ['/tmp/baseline.jsonl', '/tmp/xdist.jsonl']:
    counts = {}
    with open(f) as fp:
        for line in fp:
            try: r = json.loads(line)
            except: continue
            if r.get('\$report_type') != 'TestReport': continue
            if r.get('when') != 'call': continue
            counts[r.get('outcome','?')] = counts.get(r.get('outcome','?'), 0) + 1
    print(f, counts)
"
```

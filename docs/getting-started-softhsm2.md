# Getting started with SoftHSM2

A complete, copy-pasteable walkthrough: install `pkcs11-check`, create a SoftHSM2
config and token from scratch, run the suite, and read the results. SoftHSM2 is a
pure-software PKCS#11 provider, so it needs no hardware and is the easiest way to
try the tool.

Everything below is self-contained in a single working directory (`./pk-demo`);
nothing touches your system configuration.

## 1. Install

```bash
# Option A: isolated tool install (recommended)
uv tool install pkcs11-check          # or: pipx install pkcs11-check

# Option B: a throwaway venv
python -m venv venv && . venv/bin/activate
pip install pkcs11-check
```

Install SoftHSM2 from your distro if you don't have it:

```bash
sudo apt-get install -y softhsm2        # Debian/Ubuntu
# the module is then at /usr/lib/softhsm/libsofthsm2.so  (or /usr/lib/<arch>/...)
```

## 2. Create a SoftHSM2 config and token

SoftHSM2 is told where to keep its tokens by the `SOFTHSM2_CONF` environment
variable, which points at a config file. Keep both inside the demo directory:

```bash
mkdir -p ./pk-demo/tokens
cat > ./pk-demo/softhsm2.conf <<'EOF'
directories.tokendir = ./pk-demo/tokens
objectstore.backend = file
log.level = ERROR
EOF

# point SoftHSM2 at it (use an ABSOLUTE path so it works from any directory)
export SOFTHSM2_CONF="$PWD/pk-demo/softhsm2.conf"
# tokendir must also be absolute for SoftHSM2 — rewrite it now that we know $PWD:
sed -i "s#= ./pk-demo/tokens#= $PWD/pk-demo/tokens#" ./pk-demo/softhsm2.conf

# initialise one token (label + user PIN 1234 + SO/admin PIN 5678)
softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678
```

`SOFTHSM2_CONF` must be exported in **every** shell where you run `pkcs11-check`
— if it isn't set, SoftHSM2 falls back to its system config and won't see your
token.

## 3. Check the setup

`doctor` verifies the module loads and the slot/PIN/token are usable, and tells
you the exact next step for anything that fails:

```bash
pkcs11-check doctor --module /usr/lib/softhsm/libsofthsm2.so --slot 0 --pin 1234
```

Note: `--slot` is a **0-based index** into the token-present slots, *not* the
provider's internal slot ID. A freshly initialised SoftHSM2 token is index `0`.
Run `pkcs11-check info --module <lib>` to list them.

## 4. Run and see results

Start small — a quick functional run prints a summary to the console:

```bash
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 \
    --match "test_encrypt or test_sign or test_digest"
```

To **save** a machine-readable report, add `--output json --output-file`; the
files land in the directory of the path you give:

```bash
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 \
    --match "test_encrypt or test_sign or test_digest" \
    --output json --output-file ./pk-demo/reports/results.json

# read the results
cat ./pk-demo/reports/results.json            # consolidated summary (counts, env)
head ./pk-demo/reports/report.jsonl           # one JSON record per test
```

`./pk-demo/reports/` then contains `results.json` (summary), `report.jsonl`
(per-test records), `coverage.json` (mechanism coverage) and `quality.json`
(per-outcome classification). The `generated report log file: /tmp/…jsonl` lines
printed during a run are *internal* temporaries the runner aggregates and deletes
— the files above are the real output.

## 5. Run the full suite

Drop the `--match` filter to run everything (downloads ~800 MB of test vectors
once; without them the vector-driven suites are skipped and the rest still runs):

```bash
pkcs11-check fetch-data all
pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 \
    --output json --output-file ./pk-demo/reports/results.json
```

## 6. Run it in Docker (optional)

Prefer a container? [docker-examples.md](docker-examples.md) has a self-contained
SoftHSM2 image you can build and run in one shot, plus an example that compares two
SoftHSM2 versions (2.6.1 vs 2.7.0) with `pkcs11-check compare-results` and
`compare-coverage`.

## Troubleshooting

- **`CKR_TOKEN_NOT_RECOGNIZED` / no slots** — `SOFTHSM2_CONF` is not exported, or
  points at the wrong file, or the token was never initialised. Re-check step 2
  and confirm with `pkcs11-check info --module <lib>`.
- **`subprocess_per_test file was not expanded to per-test units`** on a *full*
  run from an installed package — a pytest `rootdir` edge case. **Fixed in 0.1.6.**
  On 0.1.4 / 0.1.5, work around it with `--isolation file`:
  ```bash
  pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --pin 1234 --slot 0 \
      --isolation file --output json --output-file ./pk-demo/reports/results.json
  ```
- **Anything else** — run `pkcs11-check doctor` first; it diagnoses the module,
  slot, PIN, token, and vector data and prints the next step.

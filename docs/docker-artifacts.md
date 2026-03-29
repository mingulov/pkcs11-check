# Docker Test Runner Contract

`pkcs11-check` now uses a shared Docker runner contract across provider images.

## Goals

- standardize how Docker test images execute the suite
- write combined logs and machine-readable reports to a host-mounted directory
- keep provider-specific bootstrap logic separate from the test runner
- reduce duplicated `uv run pkcs11-check test ...` command lines across Dockerfiles

## Shared Scripts

- [docker/run-with-artifacts.sh](/home/user/src/m/pkcs11-check/docker/run-with-artifacts.sh)
  - wraps an arbitrary command
  - if `PKCS11_CHECK_ARTIFACT_DIR` is set, it writes combined stdout/stderr to `console.log`
- [docker/run-pkcs11-check.sh](/home/user/src/m/pkcs11-check/docker/run-pkcs11-check.sh)
  - translates environment variables into a `pkcs11-check test` invocation
  - writes `results.json`, `coverage.json`, `quality.json`, `state.json`, and `policy.json` when `PKCS11_CHECK_ARTIFACT_DIR` is set
  - writes `report.jsonl` as the first-class machine-readable test log when machine-readable output is enabled

## Artifact Layout

Each Compose test service mounts host `artifacts/` into container `/artifacts`.

Per-service output goes to:

- `artifacts/<service>/console.log`
- `artifacts/<service>/report.jsonl`
- `artifacts/<service>/results.json`
- `artifacts/<service>/coverage.json`
- `artifacts/<service>/quality.json`
- `artifacts/<service>/state.json`
- `artifacts/<service>/policy.json`

Example:

```bash
docker compose -f docker/docker-compose.test.yml run --build --rm test-opencryptoki
tail -n 200 artifacts/opencryptoki/console.log
uv run pkcs11-check state artifacts/opencryptoki/state.json
```

Single wrapper for all providers:

```bash
bash docker/test.sh opencryptoki
bash docker/test.sh softhsm2 --match test_interface
bash docker/test.sh nss --timeout 30 -- src/pkcs11_check/testcases/test_interface.py
```

## Why Not One Common Base Image

The Docker matrix mixes incompatible runtime families:

- Debian slim Python images
- Fedora system-package images
- .NET SDK/runtime images
- provider-specific native dependencies and daemons

A single common image would either:

- force one distro across all providers, or
- add a large amount of cross-provider baggage into every image

So the current standardization point is the runner layer, not the OS base layer.

## Current Pattern

Simple providers:

- bootstrap token/module in the Dockerfile
- set `PKCS11_CHECK_*` env vars
- call `docker/run-with-artifacts.sh` + `docker/run-pkcs11-check.sh`

Complex providers:

- keep provider bootstrap in a small provider script
- after bootstrap, call `docker/run-pkcs11-check.sh`
- wrap the whole script with `docker/run-with-artifacts.sh`

Examples:

- [docker/opencryptoki/run-opencryptoki.sh](/home/user/src/m/pkcs11-check/docker/opencryptoki/run-opencryptoki.sh)
- [docker/bouncyhsm/run-bouncyhsm.sh](/home/user/src/m/pkcs11-check/docker/bouncyhsm/run-bouncyhsm.sh)
- [docker/tpm2-pkcs11/run-tpm2.sh](/home/user/src/m/pkcs11-check/docker/tpm2-pkcs11/run-tpm2.sh)

## Passing Custom Runner Parameters

Use [docker/test.sh](/home/user/src/m/pkcs11-check/docker/test.sh) on the host.

- arguments before `--` are passed as extra `pkcs11-check test` options
- arguments after `--` are treated as explicit pytest targets/nodeids

The wrapper serializes them into:

- `PKCS11_CHECK_EXTRA_ARGS`
- `PKCS11_CHECK_TARGETS`

The shared in-container runner then applies them uniformly for every Docker provider.

## Future Extension

If image dedup becomes worth the complexity, the next sane step is not one universal base image. It is two or three family-specific base images:

- Debian/Ubuntu Python test base
- Fedora Python test base
- .NET-assisted provider base

That can be added later without changing the current artifact/report contract.

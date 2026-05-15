# Third-Party License Attribution

`pkcs11-check` is licensed under MIT OR Apache-2.0 (see `LICENSE-MIT` and
`LICENSE-APACHE`). This file lists third-party content that pkcs11-check
either bundles in its source distribution or downloads at runtime via
`pkcs11-check fetch-data`, together with each component's license terms.

The fetch CLI displays the same per-source license information before each
download. The list below mirrors the structured fields in
`src/pkcs11_check/testcases/data/sources.toml`; a regression test enforces
that the two stay in sync.

## Bundled in the source distribution

### `latchset/pkcs11-headers` — Public Domain

The PKCS#11 v3.2 C header `pkcs11.h` lives in the source tree at
`third_party/pkcs11-headers/3.2/pkcs11.h` and ships in the sdist. It is the
dev-time input to `scripts/generate_raw_standard.py`, which produces the
ctypes binding modules (e.g. `pkcs11_check/raw/types_std.py`) that
pkcs11-check ships in the wheel — the wheel itself does not contain a
literal copy of the header.

The header originates from the `public-domain/3.2/` subtree of
[`latchset/pkcs11-headers`](https://github.com/latchset/pkcs11-headers) at
commit
[`c5e61990c5621a9b955fc208644fe8145ac0a75d`](https://github.com/latchset/pkcs11-headers/tree/c5e61990c5621a9b955fc208644fe8145ac0a75d).
The file itself opens with `/* This file is in the Public Domain */`, and
the upstream repo records `public-domain/` as its public-domain subtree
(separate from an `unlicensed/` subtree that pkcs11-check does not use).

See also `third_party/pkcs11-headers/3.2/README.md` in the source tree.

## Downloaded at runtime by `pkcs11-check fetch-data`

These archives are not bundled in the wheel. When you run `fetch-data`, each
upstream archive is extracted under `data/<name>/<repo>-<sha>/...`, and the
files referenced below land on disk alongside the test vectors.

### `C2SP/wycheproof` — Apache-2.0

[`C2SP/wycheproof`](https://github.com/C2SP/wycheproof) at commit
[`6d9d6de30f02e229dfc160323722c3ddac866181`](https://github.com/C2SP/wycheproof/tree/6d9d6de30f02e229dfc160323722c3ddac866181).

License:
[`LICENSE`](https://github.com/C2SP/wycheproof/blob/6d9d6de30f02e229dfc160323722c3ddac866181/LICENSE)
— Apache License, Version 2.0.

After fetch the file lands at
`data/wycheproof/wycheproof-6d9d6de.../LICENSE`.

### `C2SP/CCTV` — mixed (BSD-3-Clause and BSD-1-Clause)

[`C2SP/CCTV`](https://github.com/C2SP/CCTV) at commit
[`67c1397af2a57f935cc96ee112b446c051cdb68a`](https://github.com/C2SP/CCTV/tree/67c1397af2a57f935cc96ee112b446c051cdb68a).

The CCTV repository does **not** carry a single top-level `LICENSE` file.
pkcs11-check uses six subdirectories from this archive (`ed25519/`,
`ML-DSA/`, `ML-KEM/`, `RFC6979/`, `jq255/`, `keygen/`):

| Subdirectory | License | Record |
|---|---|---|
| `ed25519/` | BSD-3-Clause | [`ed25519/LICENSE`](https://github.com/C2SP/CCTV/blob/67c1397af2a57f935cc96ee112b446c051cdb68a/ed25519/LICENSE) (Google LLC / Filippo Valsorda) |
| `ML-DSA/`, `ML-KEM/`, `RFC6979/`, `jq255/`, `keygen/` | BSD 1-Clause (C2SP umbrella, see below) | no per-subdir LICENSE file at the pinned commit |

C2SP's central spec repository
[`C2SP/C2SP`](https://github.com/C2SP/C2SP) states in its README:

> All C2SP specifications are licensed under CC BY 4.0. All code and data
> in this repository is licensed under the BSD 1-Clause License.

The literal scope is `C2SP/C2SP`. We apply that statement to the unlicensed
subdirectories of `C2SP/CCTV` as the most honest reading of upstream intent
since the same maintainers operate both repositories. The BSD-1-Clause text
itself lives at
[`.github/LICENSE-BSD-1-CLAUSE`](https://github.com/C2SP/C2SP/blob/main/.github/LICENSE-BSD-1-CLAUSE)
in `C2SP/C2SP`.

After fetch, `ed25519/LICENSE` lands at
`data/cctv/CCTV-67c1397.../ed25519/LICENSE`.

### `usnistgov/ACVP-Server` — NIST Public Domain

[`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server) at
commit
[`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`](https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0).

The ACVP-Server repository carries **no** dedicated `LICENSE` file. License
terms are embedded in
[`README.md`](https://github.com/usnistgov/ACVP-Server/blob/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/README.md):

> NIST-developed software is provided by NIST as a public service. You may
> use, copy, and distribute copies of the software in any medium, provided
> that you keep intact this entire notice. […] The software developed by
> NIST employees is not subject to copyright protection within the United
> States.

SPDX has no standard identifier for this NIST wording; we use
`LicenseRef-NIST-PD` for machine-readable purposes.

After fetch the README lands at `data/acvp/ACVP-Server-15c0f3d.../README.md`.

### `C2SP/x509-limbo` — Apache-2.0

[`C2SP/x509-limbo`](https://github.com/C2SP/x509-limbo) at commit
[`086b0da8b83d78ed0f491d6df6672b2673406500`](https://github.com/C2SP/x509-limbo/tree/086b0da8b83d78ed0f491d6df6672b2673406500).

License:
[`LICENSE`](https://github.com/C2SP/x509-limbo/blob/086b0da8b83d78ed0f491d6df6672b2673406500/LICENSE)
— Apache License, Version 2.0.

After fetch the file lands at
`data/x509-limbo/x509-limbo-086b0da.../LICENSE`.

## Notes

- No upstream `NOTICE` files exist at any of the pinned commits, so
  Apache-2.0 §4(d) does not impose a propagation requirement on pkcs11-check.
- Python runtime dependencies (typer, rich, pydantic, pytest, etc.) are
  not listed here. Their licenses are recorded in each package's `dist-info`
  metadata installed alongside pkcs11-check.
- To audit attribution drift, run `pytest tests/test_release_hygiene.py`
  and `pkcs11-check fetch-data --status`.

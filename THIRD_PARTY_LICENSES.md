# Third-Party License Attribution

`pkcs11-check` is licensed under MIT OR Apache-2.0 (see `LICENSE-MIT` and
`LICENSE-APACHE`). This file lists third-party content that pkcs11-check
either bundles in its source distribution or downloads at runtime via
`pkcs11-check fetch-data`, together with each component's license terms.

The fetch CLI displays the same per-source license information before each
download. The list below mirrors the structured fields in
`src/pkcs11_check/testcases/data/sources.toml`, which records the exact pinned
commit for each fetched source; a regression test enforces that the two stay
in sync. Exact commit hashes are intentionally not repeated in this file, since
the fetched data is updated over time and the pin lives in `sources.toml`.

## Generated from a public-domain header

### `latchset/pkcs11-headers` - Public Domain

The PKCS#11 v3.2 C header `pkcs11.h` lives in the source repository at
`third_party/pkcs11-headers/3.2/pkcs11.h`. It is the dev-time input to
`scripts/generate_raw_standard.py`, which produces the ctypes binding modules
(e.g. `pkcs11_check/raw/types_std.py`) that pkcs11-check ships in the wheel.
The header itself is *not* shipped in the installable package (it is excluded
from both the wheel and the sdist); only the generated bindings are
distributed, and the header is public domain.

The header originates from the `public-domain/3.2/` subtree of
[`latchset/pkcs11-headers`](https://github.com/latchset/pkcs11-headers); the
exact source commit is recorded in `third_party/pkcs11-headers/3.2/README.md`.
The file itself opens with `/* This file is in the Public Domain */`, and
the upstream repo records `public-domain/` as its public-domain subtree
(separate from an `unlicensed/` subtree that pkcs11-check does not use).

See also `third_party/pkcs11-headers/3.2/README.md` in the source tree.

## Project-authored overlay (MIT OR Apache-2.0, same as pkcs11-check)

`third_party/pkcs11-overlay/` holds project-authored generator inputs that
`scripts/generate_raw_standard.py` parses after the public-domain header above
(overlay entries win on name collision):

- `mu_additions.h`: the ML-DSA ExternalMu mechanism pair
  (`CKM_ML_DSA_EXTERNAL_MU_GEN = 0x403B`, `CKM_ML_DSA_EXTERNAL_MU = 0x403C`)
  and the `CK_MU_GEN_PARAMS` struct, re-typed from the OASIS PKCS 11 TC
  identifier allocation for the v3.3 working draft (issue #58). A
  pre-ratification v3.2 draft carried these mechanisms at `0x1E`/`0x22`;
  the ratified v3.2 OASIS Standard dropped them and the TC re-allocated
  them at `0x403B`/`0x403C`.
- `latchset_3_2_fixes.h`: the `CK_X9_42_MQV_DERIVE_PARAMS` struct with its
  pointer fields spelled as in the ratified OASIS v3.2 text
  (`pOtherInfo`/`pPublicData`/`pPublicData2`; latchset omits the `p`).

No OASIS-copyrighted text is copied: mechanism names, code points, and field
names are API facts. Full provenance is recorded in
`third_party/pkcs11-overlay/README.md`.

## Downloaded at runtime by `pkcs11-check fetch-data`

These archives are not bundled in the wheel. When you run `fetch-data`, each
upstream archive is extracted under `data/<name>/<repo>-<sha>/...`, and the
files referenced below land on disk alongside the test vectors.

### `C2SP/wycheproof` - Apache-2.0

[`C2SP/wycheproof`](https://github.com/C2SP/wycheproof) (pinned commit in
`sources.toml`).

License:
[`LICENSE`](https://github.com/C2SP/wycheproof/blob/HEAD/LICENSE)
- Apache License, Version 2.0.

After fetch the file lands at
`data/wycheproof/wycheproof-<commit>/LICENSE`.

### `C2SP/CCTV` - mixed (BSD-3-Clause and BSD-1-Clause)

[`C2SP/CCTV`](https://github.com/C2SP/CCTV) (pinned commit in `sources.toml`).

The CCTV repository does **not** carry a single top-level `LICENSE` file.
pkcs11-check uses six subdirectories from this archive (`ed25519/`,
`ML-DSA/`, `ML-KEM/`, `RFC6979/`, `jq255/`, `keygen/`):

| Subdirectory | License | Record |
|---|---|---|
| `ed25519/` | BSD-3-Clause | [`ed25519/LICENSE`](https://github.com/C2SP/CCTV/blob/HEAD/ed25519/LICENSE) (Google LLC / Filippo Valsorda) |
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
`data/cctv/CCTV-<commit>/ed25519/LICENSE`.

### `usnistgov/ACVP-Server` - NIST Public Domain

[`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server) (pinned
commit in `sources.toml`).

The ACVP-Server repository carries **no** dedicated `LICENSE` file. License
terms are embedded in
[`README.md`](https://github.com/usnistgov/ACVP-Server/blob/HEAD/README.md):

> NIST-developed software is provided by NIST as a public service. You may
> use, copy, and distribute copies of the software in any medium, provided
> that you keep intact this entire notice. […] The software developed by
> NIST employees is not subject to copyright protection within the United
> States.

SPDX has no standard identifier for this NIST wording; we use
`LicenseRef-NIST-PD` for machine-readable purposes.

After fetch the README lands at `data/acvp/ACVP-Server-<commit>/README.md`.

### `C2SP/x509-limbo` - Apache-2.0

[`C2SP/x509-limbo`](https://github.com/C2SP/x509-limbo) (pinned commit in
`sources.toml`).

License:
[`LICENSE`](https://github.com/C2SP/x509-limbo/blob/HEAD/LICENSE)
- Apache License, Version 2.0.

After fetch the file lands at
`data/x509-limbo/x509-limbo-<commit>/LICENSE`.

## Notes

- Container-based interoperability runs use real third-party PKCS#11
  providers (see `docs/docker-examples.md`). Those provider projects,
  base images, distro packages, and their dependencies are governed by their
  own upstream license terms; they are not bundled into pkcs11-check's Python
  package, source-generated bindings, or application code.
- No upstream `NOTICE` files exist at any of the pinned commits, so
  Apache-2.0 §4(d) does not impose a propagation requirement on pkcs11-check.
- Python runtime dependencies (typer, rich, pydantic, pytest, etc.) are
  not listed here. Their licenses are recorded in each package's `dist-info`
  metadata installed alongside pkcs11-check.
- To audit attribution drift, run `pytest tests/test_release_hygiene.py`
  and `pkcs11-check fetch-data --status`.

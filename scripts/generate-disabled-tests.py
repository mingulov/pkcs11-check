#!/usr/bin/env python3
"""Generate disabled-test candidates from artifact directories."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pkcs11_check.core.test_selection import collect_disabled_candidates


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact-dir",
        action="append",
        dest="artifact_dirs",
        required=True,
        help="Artifact directory containing report.jsonl and optional results.json",
    )
    parser.add_argument(
        "--outcome",
        default="failed,error,crashed,timeout",
        help="Comma-separated outcome classes to include",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output file for exact nodeids",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    artifact_dirs = [Path(value) for value in args.artifact_dirs]
    outcomes = {part.strip() for part in args.outcome.split(",") if part.strip()}
    candidates, manual_review = collect_disabled_candidates(artifact_dirs, outcomes=outcomes)
    output = "".join(f"{nodeid}\n" for nodeid in candidates)

    if args.output is not None:
        args.output.write_text(output)
    else:
        sys.stdout.write(output)

    for line in manual_review:
        print(line, file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

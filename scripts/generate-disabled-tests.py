#!/usr/bin/env python3
"""Generate disabled-test candidates from artifact directories."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from pkcs11_check.core.test_selection import (
    collect_disabled_candidate_review_records,
)


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
    parser.add_argument(
        "--review-output",
        type=Path,
        default=None,
        help="Optional JSON output file for machine-readable review metadata",
    )
    return parser.parse_args()


def _default_review_output_path(output_path: Path) -> Path:
    if output_path.suffix:
        return output_path.with_suffix(f"{output_path.suffix}.review.json")
    return output_path.with_name(f"{output_path.name}.review.json")


def main() -> int:
    args = _parse_args()
    artifact_dirs = [Path(value) for value in args.artifact_dirs]
    outcomes = {part.strip() for part in args.outcome.split(",") if part.strip()}
    review_records, manual_review = collect_disabled_candidate_review_records(
        artifact_dirs,
        outcomes=outcomes,
    )
    candidates = sorted({record.nodeid for record in review_records})
    output = "".join(f"{nodeid}\n" for nodeid in candidates)

    if args.output is not None:
        args.output.write_text(output)
    else:
        sys.stdout.write(output)

    review_output = args.review_output
    if review_output is None and args.output is not None:
        review_output = _default_review_output_path(args.output)
    if review_output is not None:
        review_payload = {
            "schema_version": "1",
            "artifact_dirs": [str(path) for path in artifact_dirs],
            "outcomes": sorted(outcomes),
            "candidates": candidates,
            "records": [asdict(record) for record in review_records],
            "manual_review": manual_review,
        }
        review_output.write_text(json.dumps(review_payload, indent=2) + "\n")

    for line in manual_review:
        print(line, file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

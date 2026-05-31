#!/usr/bin/env python3
"""Print a one-line summary delta between two pkcs11-check results.json
files. Informational only -- always exits 0. Regression detection is
``scripts/compare-results.py``'s job.

Usage:
    uv run python scripts/recheck-summary.py <target> <baseline.json> <current.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_FIELDS_ALWAYS = ("passed", "failed", "xfailed", "skipped")
_FIELDS_CONDITIONAL = ("crashed", "xpassed", "error", "timeout")


def _load_summary(path: Path) -> dict[str, int]:
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"WARN: could not parse {path}: {e}", file=sys.stderr)
        return {}
    summary = data.get("summary")
    if not isinstance(summary, dict):
        print(f"WARN: no summary block in {path}", file=sys.stderr)
        return {}
    return summary


def _fmt_delta(b: dict[str, int], c: dict[str, int], k: str) -> str:
    bv = int(b.get(k, 0))
    cv = int(c.get(k, 0))
    return f"{k} {cv - bv:+d}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 0  # informational tool, no error exit
    _, target, baseline_path, current_path = argv
    base = _load_summary(Path(baseline_path))
    curr = _load_summary(Path(current_path))
    if not base or not curr:
        return 0
    parts = [_fmt_delta(base, curr, k) for k in _FIELDS_ALWAYS]
    for k in _FIELDS_CONDITIONAL:
        if int(base.get(k, 0)) or int(curr.get(k, 0)):
            parts.append(_fmt_delta(base, curr, k))
    total_b = int(base.get("total", 0))
    total_c = int(curr.get("total", 0))
    parts.append(f"total {total_c - total_b:+d}")
    print(f"{target}: " + ", ".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

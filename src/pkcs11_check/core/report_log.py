"""Shared reader for pytest-reportlog JSONL report logs.

A run produces ``report.jsonl`` (the raw pytest-reportlog stream). The run, report, and
merge layers all need to walk it: iterate the JSON-object records, map a pytest outcome to
the unified outcome vocabulary, and pull values out of a record's ``user_properties`` list.
These are defined once here so the parsing rules cannot drift between consumers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def iter_report_log_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parseable JSON-object records from a JSONL report log, line by line.

    Blank/whitespace-only lines, lines that are not valid JSON, and JSON values that are not
    objects are skipped. A missing/unreadable file yields nothing (never raises) so callers
    can treat an absent log as "no records".
    """
    try:
        fh = path.open(encoding="utf-8")
    except OSError:
        return
    with fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def map_report_outcome(raw_outcome: str, wasxfail: object) -> str:
    """Map a raw pytest-reportlog outcome to the unified outcome value.

    ``passed`` + wasxfail -> ``xpassed``; ``skipped`` + wasxfail -> ``xfailed``; a strict-xfail
    ``failed`` stays ``failed`` regardless of wasxfail. Everything else passes through.
    """
    if raw_outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if raw_outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return raw_outcome


def user_property(record: dict[str, Any], key: str) -> Any:
    """Return the value of the first ``(key, value)`` pair in ``record.user_properties``."""
    for pair in record.get("user_properties", []) or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == key:
            return pair[1]
    return None


def user_property_names(record: dict[str, Any]) -> set[str]:
    """Return the set of property names present in ``record.user_properties``."""
    names: set[str] = set()
    for prop in record.get("user_properties") or []:
        if isinstance(prop, (list, tuple)) and prop:
            names.add(str(prop[0]))
    return names

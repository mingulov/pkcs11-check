"""Shared reader for pytest-reportlog JSONL report logs.

A run produces ``report.jsonl`` (the raw pytest-reportlog stream). The run, report, and
merge layers all need to walk it: iterate the JSON-object records, map a pytest outcome to
the unified outcome vocabulary, and pull values out of a record's ``user_properties`` list.
These are defined once here so the parsing rules cannot drift between consumers.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pkcs11_check.core.crash_codes import CTYPES_ACCESS_VIOLATION


@dataclass
class SessionCompletionTracker:
    """Validate pytest report-log session bookends as records are streamed."""

    starts: int = 0
    finishes: int = 0
    _active: bool = False
    _invalid: bool = False
    _exitstatuses: list[int] | None = None

    def observe(self, record: Mapping[str, Any]) -> None:
        report_type = record.get("$report_type")
        if not isinstance(report_type, str) or not report_type:
            self._invalid = True
            return
        if report_type == "SessionStart":
            self.starts += 1
            if self._active:
                self._invalid = True
            self._active = True
            return
        if report_type == "TestReport":
            if (
                not self._active
                or not isinstance(record.get("nodeid"), str)
                or not record["nodeid"]
                or record.get("when") not in {"setup", "call", "teardown"}
                or record.get("outcome") not in {"passed", "failed", "skipped"}
            ):
                self._invalid = True
            return
        if report_type == "CollectReport":
            if (
                not self._active
                or not isinstance(record.get("nodeid"), str)
                or record.get("outcome") not in {"passed", "failed", "skipped"}
            ):
                self._invalid = True
            return
        if report_type != "SessionFinish":
            return

        self.finishes += 1
        if not self._active:
            self._invalid = True
        self._active = False
        exitstatus = record.get("exitstatus")
        if type(exitstatus) is not int:
            self._invalid = True
            return
        if self._exitstatuses is None:
            self._exitstatuses = []
        self._exitstatuses.append(exitstatus)

    def invalidate(self) -> None:
        """Mark the streamed session incomplete after malformed report input."""
        self._invalid = True

    @property
    def complete(self) -> bool:
        """Whether all observed sessions have exactly one valid finish."""
        return self.starts > 0 and not self._active and not self._invalid

    @property
    def single_exitstatus(self) -> int | None:
        """Return one session's exit status only for one valid session pair."""
        if not self.complete or self.starts != 1 or self.finishes != 1:
            return None
        return self._exitstatuses[0] if self._exitstatuses else None


def iter_report_log_records(
    path: Path, *, on_invalid: Callable[[], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Yield parseable JSON-object records from a JSONL report log, line by line.

    Blank/whitespace-only lines, lines that are not valid JSON, and JSON values that are not
    objects are skipped. A missing/unreadable file yields nothing (never raises) so callers
    can treat an absent log as "no records".
    """
    try:
        fh = path.open(encoding="utf-8")
    except OSError:
        if on_invalid is not None:
            on_invalid()
        return
    with fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                if on_invalid is not None:
                    on_invalid()
                continue
            if isinstance(obj, dict):
                yield obj
            elif on_invalid is not None:
                on_invalid()


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


def map_report_record_outcome(record: Mapping[str, Any]) -> str:
    """Map one report record, including a direct caught ctypes SEH failure."""
    raw_outcome = str(record.get("outcome", "passed"))
    if record.get("$report_type", "TestReport") == "TestReport" and raw_outcome == "failed":
        classifications = user_property(dict(record), "pkcs11_classification")
        if isinstance(classifications, list) and any(
            isinstance(classification, Mapping)
            and classification.get("reason") == "crash"
            and isinstance(detail := classification.get("detail"), Mapping)
            and detail.get("windows_status") == CTYPES_ACCESS_VIOLATION
            for classification in classifications
        ):
            return "crashed"
    return map_report_outcome(raw_outcome, record.get("wasxfail"))


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

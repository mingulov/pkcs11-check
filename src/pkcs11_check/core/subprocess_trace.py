"""The child-subprocess RV-trace wire protocol: the ``P11_RV_TRACE_JSON:`` marker parser and
parent-side accumulation of the most recent trace.

This is infrastructure (a subprocess wire-protocol parser), so it lives in ``core`` and is
imported downward by both ``core`` (merge/plugin) and ``testcases`` -- never the reverse.
"""

from __future__ import annotations

import json
import re
from typing import Any

RV_TRACE_MARKER = "P11_RV_TRACE_JSON:"
RV_TRACE_STDOUT_RE = re.compile(rf"(?:^|\b){re.escape(RV_TRACE_MARKER)}(.+)$", re.MULTILINE)

_subprocess_rv_traces: list[list[dict[str, Any]]] = []


def extract_subprocess_rv_trace(text: str) -> list[dict[str, Any]]:
    """Return the last valid RV trace marker from ``text``."""
    trace: list[dict[str, Any]] = []
    for match in RV_TRACE_STDOUT_RE.finditer(text):
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            trace = [entry for entry in value if isinstance(entry, dict)]
    return trace


def record_subprocess_rv_trace(*streams: str) -> None:
    """Remember the most recent child-process RV trace visible in output streams."""
    for stream in streams:
        trace = extract_subprocess_rv_trace(stream)
        if trace:
            _subprocess_rv_traces.append(trace)


def drain_subprocess_rv_trace() -> list[dict[str, Any]]:
    """Return and clear the most recent remembered child-process RV trace."""
    if not _subprocess_rv_traces:
        return []
    trace = _subprocess_rv_traces[-1]
    _subprocess_rv_traces.clear()
    return trace

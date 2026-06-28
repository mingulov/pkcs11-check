"""Pure text-reduction helpers for rendering findings compactly.

The renderer applies these so the markdown report stays scannable: long hex/byte
blobs are truncated, multi-line summaries collapse to their first line, long CKR
want-lists are capped, dashes are normalized to ASCII, and process-crash
summaries are reduced to the crash descriptor plus the crashing C_* call. Full
detail always remains in the per-provider .jsonl.

Every function here is side-effect free and depends only on the stdlib, so the
helpers can be unit-tested in isolation and reused anywhere in the renderer.
"""

from __future__ import annotations

import json
import re

_HEX_RUN = re.compile(r"[0-9a-fA-F]{65,}")
_RV_TRACE_RE = re.compile(r"P11_RV_TRACE_JSON:(.+)$", re.MULTILINE)
_TEARDOWN_FNS = frozenset({"C_Finalize", "C_CloseSession", "C_CloseAllSessions", "C_Logout"})
# em dash (U+2014) and en dash (U+2013), built from code points to keep this
# source ASCII; matched together with any surrounding whitespace.
_DASH_RE = re.compile(rf"\s*[{chr(0x2014)}{chr(0x2013)}]\s*")


def truncate_hex(text: str, limit: int = 64) -> str:
    """Replace every hex run longer than ``limit`` chars with a prefix + byte count.

    A run of N hex digits encodes N // 2 bytes; the marker reports that count so the
    reader knows the size without the full blob.
    """

    def _shorten(match: re.Match[str]) -> str:
        run = match.group(0)
        return f"{run[:limit]}...({len(run) // 2} bytes)"

    return _HEX_RUN.sub(_shorten, text)


def collapse_multiline(text: str) -> str:
    """Keep the first line of a multi-line string, noting how many were dropped."""
    lines = text.split("\n")
    if len(lines) <= 1:
        return text
    extra = len(lines) - 1
    plural = "s" if extra != 1 else ""
    return f"{lines[0]} (+{extra} more line{plural})"


def truncate_ckr_list(ckrs: list[str], keep: int = 3) -> str:
    """Render a CKR list as the first ``keep`` names plus a ``(+N)`` overflow marker."""
    if len(ckrs) <= keep:
        return ", ".join(ckrs)
    return ", ".join(ckrs[:keep]) + f" (+{len(ckrs) - keep})"


def normalize_dashes(text: str) -> str:
    """Replace em/en dashes (and any surrounding spaces) with ' - '; reports are ASCII-only."""
    return _DASH_RE.sub(" - ", text)


def sanitize_line(text: str) -> str:
    """Apply the generic per-line reductions used on every rendered finding line.

    Order matters: collapse multi-line text first (drops bulk such as a crash's
    stdout/stderr tail), then truncate any long hex left on the kept line, then
    normalize dashes.
    """
    return normalize_dashes(truncate_hex(collapse_multiline(text)))


def _crashing_call(text: str) -> str | None:
    """Return the last operational C_* call from an embedded RV trace, or None.

    Uses the last valid trace marker; walks back past clean teardown calls so the
    reported call is where the module actually died on a signal crash.
    """
    trace: list[dict[str, object]] = []
    for match in _RV_TRACE_RE.finditer(text):
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            trace = [entry for entry in value if isinstance(entry, dict)]
    for entry in reversed(trace):
        fn = entry.get("fn")
        if isinstance(fn, str) and fn not in _TEARDOWN_FNS:
            return fn
    return None


def summarize_crash(summary: str) -> str:
    """Reduce a crash summary to its descriptor line plus the crashing C_* call.

    The descriptor (first line) names the operation and the signal/exit code; the
    raw stdout/stderr dump (which can embed hundreds of KB of RV-trace JSON) is
    dropped. When the descriptor does not already name the crashing call, the last
    operational call from the embedded RV trace is appended as ``[died in C_X]``.
    """
    head = summary.partition("\n")[0].strip()
    call = _crashing_call(summary)
    if call and call not in head:
        return f"{head} [died in {call}]"
    return head

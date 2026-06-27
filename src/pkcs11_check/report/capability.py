# pkcs11_check/report/capability.py
"""Per-provider capability audit: in-range advertised-but-not-operational findings.

The actionable signal is the contradiction candidates -- not_operational records
whose detail.capability_verdict == "IN_RANGE" (the module advertised the exact
size/mechanism then refused it). The genuine-absence denominator (mechanisms not
advertised at all) is the coverage meta-check's job and is referenced, not recomputed.
"""

from __future__ import annotations

from typing import Any


def capability_audit(groups: list[dict[str, Any]]) -> dict[str, int]:
    """Summarise not_operational records and the in-range contradiction subset."""
    total = 0
    claimed = 0
    for g in groups:
        if g.get("reason") != "not_operational":
            continue
        n = int(g.get("count", 0))
        total += n
        detail = g.get("detail") or {}
        if isinstance(detail, dict) and detail.get("capability_verdict") == "IN_RANGE":
            claimed += n
    return {"not_operational_total": total, "claimed_refused": claimed}


def render_capability_section(audit: dict[str, int]) -> str:
    """Render the capability-audit markdown section for a provider page."""
    total = audit["not_operational_total"]
    claimed = audit["claimed_refused"]
    lines = [
        "## capability audit",
        "",
        f"- advertised-but-not-operational (xfail) records: **{total}**",
        f"- of which **claimed→refused** (in-range, contradiction candidates to investigate): "
        f"**{claimed}**",
        "",
        "_Genuine-absence (mechanism not advertised) counts come from the coverage "
        "meta-check, not this summary._",
    ]
    return "\n".join(lines) + "\n"

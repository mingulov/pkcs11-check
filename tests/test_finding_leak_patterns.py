"""Lint: forbid finding-hiding patterns in testcases (regression guard).

Each flagged line must be either fixed (route the outcome through the
classification helpers) or annotated with an inline `# audit-ok: <reason>`
for a genuinely-lenient positive-op / capability / lifecycle site.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
_ASSERT_RV_IN_CKR_OK = re.compile(r"assert\s+rv\s+in\s*\(")
_OR_RV_NE_ZERO = re.compile(r"\bor\s+rv\s*!=\s*0\b")


def _flag(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    hits: list[str] = []
    for i, line in enumerate(lines):
        if "# audit-ok:" in line:
            continue
        stripped = line.strip()
        # bare `except AssertionError:` whose next non-blank line is `pass`
        if stripped == "except AssertionError:":
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() == "pass" and "# audit-ok:" not in lines[j]:
                hits.append(f"{path}:{i + 1}: `except AssertionError: pass` swallows a finding")
            continue
        if _OR_RV_NE_ZERO.search(line):
            hits.append(f"{path}:{i + 1}: `or rv != 0` catch-all")
        # `assert rv in (… CKR_OK …)` possibly spanning the next line
        if _ASSERT_RV_IN_CKR_OK.search(line):
            window = line + (lines[i + 1] if i + 1 < len(lines) else "")
            if "CKR_OK" in window:
                hits.append(f"{path}:{i + 1}: `assert rv in (CKR_OK, …)` catch-all")
    return hits


def test_no_finding_leak_patterns() -> None:
    hits: list[str] = []
    for path in sorted(_ROOT.rglob("test_*.py")):
        hits.extend(_flag(path))
    # also scan non-test_ helper modules that build child scripts
    for extra in ("_subprocess_preamble.py",):
        p = _ROOT / extra
        if p.exists():
            hits.extend(_flag(p))
    assert not hits, (
        "Finding-hiding patterns found. Fix (route through the classifier) or "
        "annotate the line with `# audit-ok: <reason>` if it is a genuinely-lenient "
        "positive-op/capability/lifecycle site:\n" + "\n".join(hits)
    )

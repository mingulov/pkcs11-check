"""Lint: forbid finding-hiding patterns in testcases (regression guard).

Each flagged line must be either fixed (route the outcome through the
classification helpers) or annotated with an inline `# audit-ok: <reason>`
for a genuinely-lenient positive-op / capability / lifecycle site.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
_ASSERT_RV_IN_CKR_OK_SINGLE = re.compile(r"assert\s+rv\s+in\s*\(")
_ASSERT_OPEN = re.compile(r"^\s*assert\s*\(\s*(?:#.*)?$")
_OR_RV_NE_ZERO = re.compile(r"\bor\s+rv\s*!=\s*0\b")
_TUPLE_EXCEPT_ASSERTION = re.compile(r"^\s*except\s*\(")


def _swallow_pass(lines: list[str], i: int) -> bool:
    """True if the ``except`` at line ``i`` swallows with a bare ``pass``.

    Skips blank AND comment-only lines between the ``except`` and its body (so a
    ``# comment`` cannot be used to evade detection), and treats a ``# audit-ok:``
    on any line from the ``except`` through the ``pass`` (inclusive) as an exemption.
    """
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith("#")):
        j += 1
    if j >= len(lines) or lines[j].strip() != "pass":
        return False
    return not any("# audit-ok:" in lines[k] for k in range(i, j + 1))


def _flag(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    hits: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "# audit-ok:" in line:
            i += 1
            continue
        stripped = line.strip()

        # ── bare `except AssertionError:` whose next code line is `pass` ──
        if stripped == "except AssertionError:":
            if _swallow_pass(lines, i):
                hits.append(f"{path}:{i + 1}: `except AssertionError: pass` swallows a finding")
            i += 1
            continue

        # ── tuple-form `except (…AssertionError…):` whose next code line is bare `pass` ──
        # Only the swallow-with-pass form is a leak; `as exc:` and non-pass bodies are fine.
        if (
            _TUPLE_EXCEPT_ASSERTION.match(line)
            and "AssertionError" in line
            and " as " not in line
            and line.rstrip().endswith(":")
        ):
            if _swallow_pass(lines, i):
                hits.append(
                    f"{path}:{i + 1}: tuple-form `except (…AssertionError…): pass`"
                    " swallows a finding"
                )
            i += 1
            continue

        if _OR_RV_NE_ZERO.search(line):
            hits.append(f"{path}:{i + 1}: `or rv != 0` catch-all")

        # ── single-line `assert rv in (… CKR_OK …)` possibly spanning the next line ──
        if _ASSERT_RV_IN_CKR_OK_SINGLE.search(line):
            window = line + (lines[i + 1] if i + 1 < len(lines) else "")
            if "CKR_OK" in window:
                hits.append(f"{path}:{i + 1}: `assert rv in (CKR_OK, …)` catch-all")
            i += 1
            continue

        # ── multi-line `assert (` / `rv` / `in (` / `CKR_OK` evasion ──
        # Catches the shape: assert (\n    rv\n    in (\n        CKR_OK,\n    ...
        # A `# audit-ok:` on ANY line of the logical assert (within the scan window) exempts it.
        if _ASSERT_OPEN.match(line):
            # Next non-blank must be `rv` (the return-value variable)
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and re.match(r"^\s*rv\b", lines[j]):
                window_size = min(8, len(lines) - i)
                window = "\n".join(lines[i : i + window_size])
                if re.search(r"\bin\s*\(", window) and "CKR_OK" in window:
                    if not any("# audit-ok:" in lines[i + k] for k in range(window_size)):
                        hits.append(
                            f"{path}:{i + 1}: multi-line `assert (rv in (CKR_OK, …))` catch-all"
                        )

        i += 1
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

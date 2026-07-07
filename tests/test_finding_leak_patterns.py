"""Lint: forbid finding-hiding patterns in testcases (regression guard).

Each flagged line must be either fixed (route the outcome through the
classification helpers) or annotated with an inline `# audit-ok: <reason>`
for a genuinely-lenient positive-op / capability / lifecycle site.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
_ASSERT_RV_IN_CKR_OK_SINGLE = re.compile(r"assert\s+rv\s+in\s*\(")
_ASSERT_OPEN = re.compile(r"^\s*assert\s*\(\s*(?:#.*)?$")
_OR_RV_NE_ZERO = re.compile(r"\bor\s+rv\s*!=\s*0\b")
_TUPLE_EXCEPT_ASSERTION = re.compile(r"^\s*except\s*\(")


_SWALLOW_BODY = re.compile(r"^(?:pass|continue|break|return\b.*)$")


def _swallow_pass(lines: list[str], i: int) -> bool:
    """True if the ``except`` at line ``i`` swallows the caught exception.

    A swallow is a handler whose first statement merely discards the exception: ``pass``,
    ``continue``, ``break``, or ``return`` (all silently drop a caught AssertionError /
    CkrAssertionError, which is how the classifier carries a finding). Skips blank AND
    comment-only lines between the ``except`` and its body, and strips any trailing
    ``# comment`` on the body line before matching, so a comment cannot be used to evade
    detection (``pass  # reason`` is still a swallow). A ``# audit-ok:`` on any line from the
    ``except`` through the body line (inclusive) is the sanctioned exemption.
    """
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith("#")):
        j += 1
    if j >= len(lines):
        return False
    if not _SWALLOW_BODY.match(lines[j].split("#", 1)[0].strip()):
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

        # ── bare `except AssertionError:` / `except CkrAssertionError:` swallow ──
        # CkrAssertionError is an AssertionError subclass, so it carries findings too.
        if stripped in ("except AssertionError:", "except CkrAssertionError:"):
            if _swallow_pass(lines, i):
                hits.append(f"{path}:{i + 1}: `{stripped} <swallow>` swallows a finding")
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
                    f"{path}:{i + 1}: tuple-form `except (…AssertionError…): <swallow>`"
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


def test_guard_flags_commented_pass_swallow() -> None:
    """A trailing comment on `pass` must NOT let a swallow evade the guard."""
    lines = ["    except AssertionError:", "        pass  # looks harmless"]
    assert _swallow_pass(lines, 0) is True


def test_guard_respects_audit_ok_on_swallow() -> None:
    """An audit-ok annotation on the swallow line still exempts it."""
    lines = ["    except AssertionError:", "        pass  # audit-ok: capability gap"]
    assert _swallow_pass(lines, 0) is False


def test_guard_ignores_real_handler_body() -> None:
    """A handler that does real work (not a bare discard) is not a swallow."""
    assert _swallow_pass(["    except AssertionError:", "        raise"], 0) is False
    assert _swallow_pass(["    except AssertionError as e:", "        xfail_as(e)"], 0) is False


def test_guard_flags_return_continue_break_swallow() -> None:
    """return/continue/break discard a caught finding-carrying exception just like pass."""
    assert _swallow_pass(["    except AssertionError:", "        return None"], 0) is True
    assert _swallow_pass(["    except AssertionError:", "        continue"], 0) is True
    assert _swallow_pass(["    except AssertionError:", "        break"], 0) is True
    # audit-ok still exempts, and a real body is still not a swallow
    exempt = ["    except AssertionError:", "        return x  # audit-ok: x"]
    assert _swallow_pass(exempt, 0) is False
    assert _swallow_pass(["    except AssertionError:", "        returned = 1"], 0) is False


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


# --- D2: named-tuple CKR_OK acceptance on negative ops (blind spot of the regex above) ---
# The `assert rv in (CKR_OK, ...)` checks above only see a *literal* tuple. Accepting CKR_OK
# via a named tuple/set -- `assert rv in _ACCEPT` where `_ACCEPT = (..., CKR_OK)` -- is invisible
# to them. This AST check resolves module-level names so a CKR_OK acceptance can't hide behind a
# name. A genuinely-sanctioned CKR_OK (e.g. a v3.0 NULL-mech cancel) is annotated `# audit-ok:`.


def _named_ckr_ok_membership_hits(source: str, path: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    ok_names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Tuple, ast.List, ast.Set)):
            elems = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            if "CKR_OK" in elems:
                ok_names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    if not ok_names:
        return []
    hits: list[str] = []
    for nd in ast.walk(tree):
        test = getattr(nd, "test", None)
        if not (isinstance(nd, (ast.Assert, ast.If)) and isinstance(test, ast.Compare)):
            continue
        if not (test.ops and isinstance(test.ops[0], ast.In) and test.comparators):
            continue
        target = test.comparators[0]
        if isinstance(target, ast.Name) and target.id in ok_names:
            line_text = lines[nd.lineno - 1] if nd.lineno - 1 < len(lines) else ""
            if "# audit-ok:" not in line_text:
                hits.append(f"{path}:{nd.lineno} (in {target.id})")
    return hits


def test_guard_flags_named_ckr_ok_membership() -> None:
    src = "_ACCEPT = (CKR_ARGUMENTS_BAD, CKR_OK)\ndef probe(rv):\n    assert rv in _ACCEPT\n"
    assert _named_ckr_ok_membership_hits(src, "x.py") == ["x.py:3 (in _ACCEPT)"]


def test_guard_named_ckr_ok_respects_audit_ok() -> None:
    src = "_ACCEPT = (CKR_OK,)\ndef p(rv):\n    assert rv in _ACCEPT  # audit-ok: v3.0 cancel\n"
    assert _named_ckr_ok_membership_hits(src, "x.py") == []


def test_guard_named_ckr_ok_ignores_error_only_tuples() -> None:
    src = "_E = (CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED)\ndef p(rv):\n    assert rv in _E\n"
    assert _named_ckr_ok_membership_hits(src, "x.py") == []


def test_no_named_ckr_ok_membership_acceptance() -> None:
    hits: list[str] = []
    for path in sorted(_ROOT.rglob("*.py")):
        rel = path.relative_to(_ROOT.parent.parent.parent)
        hits.extend(_named_ckr_ok_membership_hits(path.read_text(), str(rel)))
    assert not hits, (
        "CKR_OK accepted on a negative op via a named tuple/set. Route through the classifier "
        "or annotate the assertion `# audit-ok: <spec reason>` if the CKR_OK is sanctioned:\n  "
        + "\n  ".join(hits)
    )

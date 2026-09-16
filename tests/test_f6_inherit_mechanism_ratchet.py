"""F6 zero-tolerance guard for mechanism-free ``attr_or_record`` readbacks.

``record_as()`` resolves ``mechanism`` as ``if mechanism is None and inherit_mechanism:
mechanism = _active_mechanism``. A ``C_GetAttributeValue`` readback that omits
``inherit_mechanism=False`` therefore stamps whatever mechanism the calling test last made
active onto a record that has nothing to do with it -- and because ``wrap_context_for()``
memoises per session handle, *which* mechanism gets stamped depends on test ordering and
``-k`` selection. That non-determinism was the release-blocking F6 defect.

Every mechanism-free readback must pass ``inherit_mechanism=False`` at its source. This
is a zero-tolerance guard: an unguarded site would silently stamp a stale mechanism onto
an unrelated readback, and must fail this test until it is fixed.
"""

from __future__ import annotations

import ast
import collections
import pathlib

TESTCASES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
EXPECTED_ATTR_OR_RECORD_SITES = 377


def _unguarded_sites() -> tuple[dict[str, list[int]], int]:
    """Return unguarded sites and the total number of ``attr_or_record`` calls seen.

    Name matching resolves ``as``-aliases per file (``from ... import
    attr_or_record as _attr_or_record``): an aliased call is the same readback
    and must carry the flag too. A scanner that only matched the literal name
    let exactly one such site escape (conftest ``ec_public_key_binding_defect``).
    """
    found: dict[str, list[int]] = collections.defaultdict(list)
    seen_sites = 0
    for path in sorted(TESTCASES_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {"attr_or_record"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "attr_or_record":
                        names.add(alias.asname or alias.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name not in names:
                continue
            seen_sites += 1
            guarded = any(
                keyword.arg == "inherit_mechanism"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
            if not guarded:
                found[str(path.relative_to(TESTCASES_ROOT))].append(node.lineno)
    return dict(found), seen_sites


def test_no_mechanism_inheriting_attribute_reads() -> None:
    """Every ``attr_or_record`` site must pass ``inherit_mechanism=False``."""
    assert TESTCASES_ROOT.is_dir(), f"Testcase source root is missing: {TESTCASES_ROOT}"
    actual, seen_sites = _unguarded_sites()
    assert seen_sites > 0, "Scanner saw no attr_or_record calls; F6 guard would be vacuous"
    assert seen_sites == EXPECTED_ATTR_OR_RECORD_SITES, (
        f"Scanner saw {seen_sites} attr_or_record calls; expected {EXPECTED_ATTR_OR_RECORD_SITES}"
    )
    violations = []
    for name, lines in sorted(actual.items()):
        violations.append(
            f"  {name}: {len(lines)} unguarded sites "
            f"(lines {', '.join(str(line) for line in lines)})"
        )
    assert not violations, (
        "attr_or_record call site(s) omit inherit_mechanism=False, so a readback can "
        "inherit the caller's active mechanism and be attributed non-deterministically:\n"
        + "\n".join(violations)
        + "\n\nPass inherit_mechanism=False at every mechanism-free readback."
    )

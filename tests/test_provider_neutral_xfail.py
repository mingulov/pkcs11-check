"""Meta-test: ``pytest.xfail`` messages in product test cases must be provider-neutral.

Regression guard for audit finding H-CLASS-1 (provider names in xfail output).
The classification model treats ``xfail`` as the universal, provider-GENERAL
"noted deviation, investigate later" bucket: it must never name a specific
provider. A module name in an xfail reason leaks provider identity into the
pytest report and re-introduces per-provider gating.

Only the string passed to ``pytest.xfail()`` is scanned (Constant or the literal
parts of an f-string). Provider names in source COMMENTS, docstrings, or CVE
class names are fine -- they never reach the report -- and are not scanned.
"""

from __future__ import annotations

import ast
import pathlib

_REPO = pathlib.Path(__file__).resolve().parent.parent
_TESTCASES = _REPO / "src" / "pkcs11_check" / "testcases"

# Known PKCS#11 provider / module identifiers that must not appear in xfail output.
_PROVIDER_NAMES = (
    "softhsm",
    "kryoptic",
    "tpm2",
    "bouncyhsm",
    "opencryptoki",
    "nitrokey",
    "yubikey",
    "utimaco",
    "safenet",
    "cloudhsm",
    "softoken",
    "nss",
)


def _literal_text(node: ast.AST) -> str | None:
    """Static string content of a str Constant or the literal parts of an f-string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        ]
        return "".join(parts)
    return None


def _xfail_violations(path: pathlib.Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_xfail = (isinstance(func, ast.Attribute) and func.attr == "xfail") or (
            isinstance(func, ast.Name) and func.id == "xfail"
        )
        if not is_xfail or not node.args:
            continue
        text = _literal_text(node.args[0])
        if text is None:
            continue
        low = text.lower()
        if any(name in low for name in _PROVIDER_NAMES):
            out.append((node.lineno, text))
    return out


def test_no_provider_names_in_xfail_messages() -> None:
    violations: list[str] = []
    for path in sorted(_TESTCASES.rglob("*.py")):
        for lineno, text in _xfail_violations(path):
            rel = path.relative_to(_REPO)
            violations.append(f"{rel}:{lineno}: {text!r}")
    assert not violations, (
        "pytest.xfail messages must be provider-neutral (audit H-CLASS-1); "
        "move the provider name to a code comment:\n  " + "\n  ".join(violations)
    )

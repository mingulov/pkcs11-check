"""Release-readiness hygiene checks for public artifacts and masking patterns."""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "CHANGELOG.md",
    *sorted((REPO_ROOT / "docs").glob("*.md")),
]
SOURCE_DIRS = [REPO_ROOT / "src", REPO_ROOT / "tests"]


def _python_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRS:
        files.extend(sorted(directory.rglob("*.py")))
    return files


def test_public_docs_do_not_reference_workstation_paths_or_agent_plans() -> None:
    banned = ("/home/user", "/home/", "ScheduleWakeup", "/loop", "docs/superpowers/")
    offenders: list[str] = []
    for path in PUBLIC_DOCS:
        text = path.read_text()
        for token in banned:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)} contains {token!r}")
    assert offenders == []


def test_no_exact_exception_pass_swallows() -> None:
    offenders: list[str] = []
    for path in _python_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            stripped = line.strip()
            if stripped == "except Exception: pass" or stripped.startswith(
                "except Exception: pass "
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}")
    assert offenders == []


def test_pqc_xfails_explain_module_or_spec_context() -> None:
    generic = {
        "ML-DSA sign failed",
        "ML-DSA produced identical signatures (deterministic mode?)",
        "SLH-DSA key generation failed",
        "SLH-DSA sign failed",
    }
    offenders: list[str] = []
    path = REPO_ROOT / "src/pkcs11_check/testcases/test_pqc_sign.py"
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "xfail" or getattr(node.func.value, "id", None) != "pytest":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        reason = node.args[0].value
        if isinstance(reason, str) and reason in generic:
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {reason}")
    assert offenders == []

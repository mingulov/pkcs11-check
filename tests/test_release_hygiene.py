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
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
                continue
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert offenders == []


def test_source_subprocess_calls_do_not_use_shell_true() -> None:
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"run", "Popen", "call", "check_call", "check_output"}:
                continue
            if getattr(node.func.value, "id", None) != "subprocess":
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert offenders == []


def test_sha1_calls_declare_non_security_use() -> None:
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "sha1" or getattr(node.func.value, "id", None) != "hashlib":
                continue
            has_context = any(
                keyword.arg == "usedforsecurity"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
            if not has_context:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert offenders == []


def test_legacy_crypto_reference_calls_are_explicitly_annotated() -> None:
    offenders: list[str] = []
    for path in _python_files():
        source_lines = path.read_text().splitlines()
        tree = ast.parse("\n".join(source_lines))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            module_name = getattr(node.func.value, "id", None)
            if module_name == "hashes" and node.func.attr == "SHA1":
                expected = "# nosec B303"
            elif module_name == "modes" and node.func.attr == "ECB":
                expected = "# nosec B305"
            else:
                continue
            if expected not in source_lines[node.lineno - 1]:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
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

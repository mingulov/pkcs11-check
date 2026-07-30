"""Release-readiness hygiene checks for public artifacts and masking patterns."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "CHANGELOG.md",
    *sorted((REPO_ROOT / "docs").glob("*.md")),
]
SOURCE_DIRS = [REPO_ROOT / "src", REPO_ROOT / "tests"]
SOURCES_TOML = REPO_ROOT / "src/pkcs11_check/testcases/data/sources.toml"
THIRD_PARTY_LICENSES_MD = REPO_ROOT / "THIRD_PARTY_LICENSES.md"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"


def _python_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRS:
        files.extend(sorted(directory.rglob("*.py")))
    return files


def test_public_docs_do_not_reference_workstation_paths_or_agent_plans() -> None:
    banned = ("/home/user", "/home/", "ScheduleWakeup", "/loop", "superpowers/")
    offenders: list[str] = []
    for path in PUBLIC_DOCS:
        text = path.read_text(encoding="utf-8")
        for token in banned:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)} contains {token!r}")
    assert offenders == []


def test_no_exact_exception_pass_swallows() -> None:
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
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
        tree = ast.parse(path.read_text(encoding="utf-8"))
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
        tree = ast.parse(path.read_text(encoding="utf-8"))
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
        source_lines = path.read_text(encoding="utf-8").splitlines()
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


def test_third_party_sources_carry_license_metadata() -> None:
    """Every source in sources.toml must declare `license` and `license_files`."""
    with open(SOURCES_TOML, "rb") as f:
        sources = tomllib.load(f)
    offenders: list[str] = []
    for name, entry in sources.items():
        license_id = entry.get("license")
        if not isinstance(license_id, str) or not license_id:
            offenders.append(f"{name}: missing or empty `license`")
        license_files = entry.get("license_files")
        if not isinstance(license_files, list):
            offenders.append(f"{name}: missing `license_files` list")
            continue
        for path in license_files:
            if not isinstance(path, str) or not path:
                offenders.append(f"{name}: invalid license_files entry {path!r}")
                continue
            if path.startswith("/") or ".." in path.split("/"):
                offenders.append(f"{name}: license_files path must be repo-relative, got {path!r}")
        repo = entry.get("repo")
        commit = entry.get("commit")
        if isinstance(repo, str) and isinstance(commit, str):
            for path in license_files:
                if not isinstance(path, str):
                    continue
                url = f"https://github.com/{repo}/blob/{commit}/{path}"
                parsed = urlsplit(url)
                if parsed.scheme != "https" or not parsed.netloc or not parsed.path:
                    offenders.append(f"{name}: constructed URL is malformed: {url}")
    assert offenders == []


def test_third_party_licenses_md_lists_every_source() -> None:
    """THIRD_PARTY_LICENSES.md must mention every fetched source plus pkcs11-headers."""
    assert THIRD_PARTY_LICENSES_MD.is_file(), "THIRD_PARTY_LICENSES.md missing"
    text = THIRD_PARTY_LICENSES_MD.read_text(encoding="utf-8")
    assert text.strip(), "THIRD_PARTY_LICENSES.md is empty"
    with open(SOURCES_TOML, "rb") as f:
        sources = tomllib.load(f)
    missing: list[str] = []
    for name, entry in sources.items():
        repo = entry.get("repo")
        if isinstance(repo, str) and repo not in text:
            missing.append(f"source `{name}` (repo {repo}) not mentioned")
    if "pkcs11-headers" not in text:
        missing.append("pkcs11-headers not mentioned")
    assert missing == []


def test_pyproject_lists_third_party_licenses_in_license_files() -> None:
    """pyproject.toml must include THIRD_PARTY_LICENSES.md in [project].license-files."""
    with open(PYPROJECT_TOML, "rb") as f:
        config = tomllib.load(f)
    license_files = config.get("project", {}).get("license-files")
    assert isinstance(license_files, list), "[project].license-files must be a list"
    assert "THIRD_PARTY_LICENSES.md" in license_files


def test_bundled_pkcs11_header_declares_public_domain() -> None:
    """The bundled PKCS#11 header must carry its public-domain declaration intact."""
    header = REPO_ROOT / "third_party/pkcs11-headers/3.2/pkcs11.h"
    assert header.is_file(), f"missing {header}"
    first_line = header.open(encoding="utf-8").readline().strip()
    assert first_line == "/* This file is in the Public Domain */", (
        f"unexpected first line of pkcs11.h: {first_line!r}"
    )


def test_pqc_xfails_explain_module_or_spec_context() -> None:
    generic = {
        "ML-DSA sign failed",
        "ML-DSA produced identical signatures (deterministic mode?)",
        "SLH-DSA key generation failed",
        "SLH-DSA sign failed",
    }
    offenders: list[str] = []
    path = REPO_ROOT / "src/pkcs11_check/testcases/test_pqc_sign.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
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

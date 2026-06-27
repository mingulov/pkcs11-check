"""Self-contained and vendor-neutral CI guard.

Verifies that the framework ships no references to relocated workspace docs,
workspace/CI-infrastructure artefacts, typographic dashes, provider names
inside reference= kwargs, or provider-named test classes.

These rules also serve as a final integration check that Phases 2-6 of the
public-readiness branch are complete.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Directories and files scanned by the various rules.
SRC_DIR = REPO_ROOT / "src"
TESTS_DIR = REPO_ROOT / "tests"
DOCS_DIR = REPO_ROOT / "docs"
TESTCASES_DIR = SRC_DIR / "pkcs11_check" / "testcases"


def _git_ls_files(*patterns: str) -> list[Path]:
    """Return tracked files matching the given git-ls-files patterns."""
    cmd = ["git", "ls-files", *patterns]
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    return [REPO_ROOT / p for p in result.stdout.splitlines() if p]


def _files_under(*roots: Path, suffix: str = ".py") -> list[Path]:
    """Return all files with the given suffix recursively under the given roots."""
    found: list[Path] = []
    for root in roots:
        if root.is_dir():
            found.extend(sorted(root.rglob(f"*{suffix}")))
        elif root.is_file() and root.suffix == suffix:
            found.append(root)
    return found


def _tracked_files_under(*prefixes: str) -> list[Path]:
    """Return git-tracked files under the given repo-relative path prefixes."""
    result = subprocess.run(
        ["git", "ls-files", *prefixes],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [REPO_ROOT / p for p in result.stdout.splitlines() if p]


# The guard file itself necessarily names the forbidden tokens; exclude it from
# all content scans so it does not flag itself.
_THIS_FILE_REL = Path("tests") / "test_self_contained.py"


def test_no_relocated_doc_refs() -> None:
    """No reference to relocated doc files in src/, tests/, or docs/.

    Forbidden: module-issues.md, cve-regression.md, capability-gating-design,
    destructive-token-isolation.md, and the path docs/findings/.
    rv-trace-design.md is NOT forbidden (stays in framework docs).
    Plain --module-issues flag / PKCS11_CHECK_MODULE_ISSUES env /
    _resolve_module_issues_text function names are not flagged (no .md suffix).
    """
    # Build forbidden tokens from parts so this source file does not self-flag.
    _md = ".md"
    forbidden = (
        "module-issues" + _md,
        "cve-regression" + _md,
        "capability-gating-design",
        "destructive-token-isolation" + _md,
        "docs/findings/",
    )
    offenders: list[str] = []
    for path in _tracked_files_under("src", "tests", "docs"):
        if path.relative_to(REPO_ROOT) == _THIS_FILE_REL:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for token in forbidden:
            if token in text:
                for lineno, line in enumerate(text.splitlines(), 1):
                    if token in line:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{lineno}: contains {token!r}"
                        )
    assert offenders == [], "Relocated doc references found:\n" + "\n".join(offenders)


def test_no_workspace_or_infra_refs() -> None:
    """No workspace/CI-infra references in docs/*.md (excl. docker-examples.md),
    README.md, CLAUDE.md, or src/.
    """
    banned = (
        "pkcs11-check-ws",
        "development workspace",
        "the workspace",
        "local-builds",
        "docker/test_pool",
        "docker compose",
        "docker-compose",
        "test-softhsm2",
        "test-kryoptic",
        "test-nss",
        "test-opencryptoki",
        "test-bouncyhsm",
        "test-wolfpkcs11",
        "test-tpm2",
        "test-corepkcs11",
        "test-pkcs11-mock",
        "test-optee",
    )
    # Build file list: docs/*.md excluding docker-examples.md, plus README.md, CLAUDE.md, src/
    paths_to_check: list[Path] = []
    for md in sorted(DOCS_DIR.glob("*.md")):
        if md.name != "docker-examples.md":
            paths_to_check.append(md)
    paths_to_check.append(REPO_ROOT / "README.md")
    paths_to_check.append(REPO_ROOT / "CLAUDE.md")
    paths_to_check.extend(_files_under(SRC_DIR))

    offenders: list[str] = []
    for path in paths_to_check:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for token in banned:
            if token in text:
                for lineno, line in enumerate(text.splitlines(), 1):
                    if token in line:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{lineno}: contains {token!r}"
                        )
    assert offenders == [], "Workspace/infra references found:\n" + "\n".join(offenders)


def test_no_em_dash_in_markdown() -> None:
    """No em-dash (U+2014) or en-dash (U+2013) in any tracked *.md outside tests/fixtures/."""
    offenders: list[str] = []
    fixtures_rel = str(Path("tests") / "fixtures")
    for path in _git_ls_files("*.md"):
        rel = str(path.relative_to(REPO_ROOT))
        if rel.startswith(fixtures_rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if "—" in line or "–" in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: em/en-dash found")
    assert offenders == [], "Em/en-dash in markdown:\n" + "\n".join(offenders)


_PROVIDER_NAMES_RE = re.compile(
    r"SoftHSM|NSS|Kryoptic|OpenCryptoki|wolfPKCS|wolfpkcs|TPM2|tpm2|BouncyHSM"
)

# Match reference= "..." (double or single quoted value)
_REFERENCE_KW_RE = re.compile(r'\breference\s*=\s*["\']([^"\']*)["\']')


def test_no_provider_in_reference_kwargs() -> None:
    """No reference="..." string in testcases/ contains a provider name.

    Scope: reference= keyword arguments only - plain comments/docstrings that
    legitimately name providers are out of scope for this rule.
    """
    offenders: list[str] = []
    for path in _files_under(TESTCASES_DIR):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _REFERENCE_KW_RE.finditer(line):
                value = m.group(1)
                if _PROVIDER_NAMES_RE.search(value):
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: "
                        f"provider name in reference={value!r}"
                    )
    assert offenders == [], "Provider names in reference= kwargs:\n" + "\n".join(offenders)


_CLASS_TEST_RE = re.compile(r"^class (Test\w*)\b", re.MULTILINE)
_PROVIDER_CLASS_RE = re.compile(r"SoftHSM|NSS|Kryoptic|OpenCryptoki|wolf|TPM2|BouncyHSM")


def test_no_provider_in_test_class_names() -> None:
    """No class Test... under testcases/ has a provider name in its class name."""
    offenders: list[str] = []
    for path in _files_under(TESTCASES_DIR):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _CLASS_TEST_RE.finditer(text):
            class_name = m.group(1)
            if _PROVIDER_CLASS_RE.search(class_name):
                lineno = text[: m.start()].count("\n") + 1
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{lineno}: provider name in class {class_name!r}"
                )
    assert offenders == [], "Provider-named test classes:\n" + "\n".join(offenders)

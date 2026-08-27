"""Release-state checks: the one place that knows what a correct version looks like.

Called two ways:

* ``tests/test_release_hygiene.py`` runs :func:`verify` with ``requested=None`` on every push,
  so version drift fails in normal CI rather than once per release.
* The manual publishing workflows run this module as a script with ``--version X.Y.Z``
  before they upload artifacts, tag a release, or create a GitHub Release.

Standard library only, deliberately: the workflow runs this with the runner's ``python3``
before any ``uv sync``, so a third-party import would break the release.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
CHANGELOG_HEADING_RE = re.compile(r"^## \[(?P<version>[^\]]+)\] - (?P<date>\S+)\s*$")


@dataclass(frozen=True)
class Problem:
    """One reason the repository is not in a releasable state."""

    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.location}: {self.message}"


def read_package_version(repo_root: Path) -> str | None:
    """Return ``__version__`` from the package ``__init__``, or None if absent.

    Parsed with ``ast`` rather than imported: the workflow runs this before the package is
    necessarily installed, and importing would drag in the whole module tree.
    """
    init_path = repo_root / "src" / "pkcs11_check" / "__init__.py"
    tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "__version__"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return node.value.value
    return None


def changelog_entries(repo_root: Path) -> list[tuple[str, str]]:
    """Return ``[(version, date), ...]`` for every ``## [X.Y.Z] - DATE`` heading, in file order."""
    text = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = CHANGELOG_HEADING_RE.match(line)
        if match is not None:
            entries.append((match["version"], match["date"]))
    return entries


def extract_notes(repo_root: Path, version: str) -> str:
    """Return the CHANGELOG body for ``version``, without its own heading.

    Raises ``LookupError`` when the section is absent: a release must never go out with empty
    notes just because the changelog was forgotten.
    """
    lines = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()

    start: int | None = None
    for index, line in enumerate(lines):
        match = CHANGELOG_HEADING_RE.match(line)
        if match is not None and match["version"] == version:
            start = index + 1
            break
    if start is None:
        raise LookupError(f"CHANGELOG.md has no '## [{version}] - DATE' section")

    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break
    return "\n".join(lines[start:end]).strip() + "\n"


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _check_pyproject_is_dynamic(repo_root: Path) -> list[Problem]:
    """The version must come from the package, never be duplicated in pyproject."""
    with (repo_root / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    project = config.get("project", {})
    problems: list[Problem] = []
    if "version" in project:
        problems.append(
            Problem(
                "pyproject.toml",
                "[project].version is set; the version must come only from "
                "src/pkcs11_check/__init__.py via [tool.hatch.version]",
            )
        )
    if "version" not in project.get("dynamic", []):
        problems.append(Problem("pyproject.toml", '[project].dynamic must contain "version"'))
    return problems


def _check_changelog_headings(repo_root: Path) -> list[Problem]:
    """Flag any ``## [...]`` heading that does not match ``## [X.Y.Z] - YYYY-MM-DD``.

    ``changelog_entries`` and ``extract_notes`` both key off ``CHANGELOG_HEADING_RE``, so a
    dateless heading like ``## [Unreleased]`` is invisible to them: it is silently skipped by
    the entries scan, and ``extract_notes`` still stops at it, truncating the release notes it
    extracts for the entry above. Catch it explicitly instead of letting it disappear.
    """
    problems: list[Problem] = []
    for line in (repo_root / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("## [") and CHANGELOG_HEADING_RE.match(line) is None:
            problems.append(
                Problem(
                    "CHANGELOG.md",
                    f"heading {line!r} is malformed; every changelog heading must be "
                    "'## [X.Y.Z] - YYYY-MM-DD'",
                )
            )
    return problems


def _check_changelog(repo_root: Path, version: str) -> list[Problem]:
    problems = _check_changelog_headings(repo_root)

    entries = changelog_entries(repo_root)
    if not entries:
        return [*problems, Problem("CHANGELOG.md", "no '## [X.Y.Z] - DATE' heading found")]

    top_version, top_date = entries[0]
    if top_version != version:
        problems.append(
            Problem(
                "CHANGELOG.md",
                f"first entry is {top_version!r} but the package declares {version!r}",
            )
        )
    try:
        dt.date.fromisoformat(top_date)
    except ValueError:
        problems.append(Problem("CHANGELOG.md", f"entry date {top_date!r} is not an ISO date"))

    if len(entries) > 1:
        previous = entries[1][0]
        top_is_numeric = VERSION_RE.match(top_version) is not None
        previous_is_numeric = VERSION_RE.match(previous) is not None
        if not top_is_numeric:
            problems.append(
                Problem("CHANGELOG.md", f"entry {top_version!r} is not a numeric version")
            )
        elif not previous_is_numeric:
            problems.append(
                Problem("CHANGELOG.md", f"previous entry {previous!r} is not a numeric version")
            )
        elif _version_tuple(top_version) <= _version_tuple(previous):
            problems.append(
                Problem(
                    "CHANGELOG.md",
                    f"version {top_version} is not greater than the previous entry {previous}",
                )
            )
    return problems


def verify(repo_root: Path, requested: str | None = None) -> list[Problem]:
    """Return every reason the repository is not releasable, empty list when it is.

    With ``requested=None`` this checks self-consistency only, which is what the per-push
    meta-test needs. With a version string it also checks the repository declares that version.
    """
    package_version = read_package_version(repo_root)
    if package_version is None:
        return [Problem("src/pkcs11_check/__init__.py", "no __version__ assignment found")]
    if VERSION_RE.match(package_version) is None:
        return [
            Problem(
                "src/pkcs11_check/__init__.py",
                f"__version__ {package_version!r} is not X.Y.Z",
            )
        ]

    problems = _check_pyproject_is_dynamic(repo_root)
    problems.extend(_check_changelog(repo_root, package_version))

    if requested is not None:
        normalized = requested[1:] if requested.startswith("v") else requested
        if normalized != package_version:
            problems.append(
                Problem(
                    "input",
                    f"requested version {requested!r} but the package declares {package_version!r}",
                )
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    """Verify the release state, optionally writing the release notes. 0 = OK, 1 = problems."""
    parser = argparse.ArgumentParser(description="Check the repository is releasable.")
    parser.add_argument("--version", help="version being released, e.g. 0.1.9 or v0.1.9")
    parser.add_argument("--notes-out", type=Path, help="write the CHANGELOG section to this path")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args(argv)

    if args.notes_out is not None and args.version is None:
        print("::error::--notes-out requires --version", file=sys.stderr)
        return 1

    problems = verify(args.repo_root, args.version)
    for problem in problems:
        print(f"::error::{problem}", file=sys.stderr)
    if problems:
        return 1

    if args.notes_out is not None and args.version is not None:
        version = args.version[1:] if args.version.startswith("v") else args.version
        args.notes_out.write_text(extract_notes(args.repo_root, version), encoding="utf-8")

    print(f"release check OK: {read_package_version(args.repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

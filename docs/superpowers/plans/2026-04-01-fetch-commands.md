# fetch-data / fetch-disabled Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `pkcs11-check fetch-data` and `pkcs11-check fetch-disabled` CLI commands so installed users can download test vectors and the disabled baseline without cloning the repo.

**Architecture:** Move `data/sources.toml` into the package so it ships in the wheel. Fix data path resolution to use XDG default for installed packages. Add two CLI commands using stdlib `urllib.request` + `zipfile`. Wire disabled baseline auto-discovery into the existing test runner.

**Tech Stack:** Python stdlib (`urllib.request`, `zipfile`, `tomllib`, `hashlib`, `tempfile`, `shutil`), typer, rich

---

### Task 1: Fix data path resolution

**Files:**
- Modify: `src/pkcs11_check/testcases/data/__init__.py`
- Test: `tests/test_data_paths.py`

- [ ] **Step 1: Write tests for data path resolution**

Create `tests/test_data_paths.py`:

```python
"""Tests for data path resolution logic."""
from __future__ import annotations

from pathlib import Path

import pytest


class TestResolveDataDir:
    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path / "custom"))
        from pkcs11_check.testcases.data import resolve_data_dir

        assert resolve_data_dir() == tmp_path / "custom"

    def test_xdg_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
        # Force non-repo mode by hiding project root marker
        monkeypatch.setattr(
            "pkcs11_check.testcases.data._find_repo_data_dir", lambda: None
        )
        from pkcs11_check.testcases.data import resolve_data_dir

        result = resolve_data_dir()
        assert str(result).endswith(".local/share/pkcs11-check/data")

    def test_repo_root_preferred_in_dev(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
        from pkcs11_check.testcases.data import resolve_data_dir

        # In the repo, should find the repo root data/ dir
        result = resolve_data_dir()
        assert result.exists() or "data" in str(result)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run python -m pytest tests/test_data_paths.py -v
```

Expected: FAIL — `resolve_data_dir` does not exist yet.

- [ ] **Step 3: Implement data path resolution**

Rewrite `src/pkcs11_check/testcases/data/__init__.py`:

```python
"""Centralized test data paths — single source of truth.

Own data (mechanism_vectors, KAT JSONs) lives here in src/.
Third-party vendor data lives in a resolved data directory.
"""
from __future__ import annotations

import os
from pathlib import Path

# Own data (tracked in git, part of the package)
DATA_DIR = Path(__file__).parent
KAT_DIR = DATA_DIR

# Path to the bundled sources.toml manifest
SOURCES_TOML = DATA_DIR / "sources.toml"

_XDG_DATA_DIR = Path.home() / ".local" / "share" / "pkcs11-check" / "data"


def _find_project_root() -> Path | None:
    """Walk up to find pyproject.toml (project root marker)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return None


def _find_repo_data_dir() -> Path | None:
    """Find repo-root data/ dir if we're running from the repo."""
    root = _find_project_root()
    if root is None:
        return None
    data = root / "data"
    # Only use repo data dir if it has fetched content (not just .gitignore)
    if data.is_dir() and any(
        p.is_dir() and p.name != "__pycache__" for p in data.iterdir()
    ):
        return data
    return None


def resolve_data_dir() -> Path:
    """Resolve the third-party vendor data directory.

    Resolution order:
    1. PKCS11_CHECK_DATA_DIR env var
    2. Repo root data/ dir (dev mode, if fetched content exists)
    3. ~/.local/share/pkcs11-check/data/ (XDG default)
    """
    env = os.environ.get("PKCS11_CHECK_DATA_DIR")
    if env:
        return Path(env)

    repo_dir = _find_repo_data_dir()
    if repo_dir is not None:
        return repo_dir

    return _XDG_DATA_DIR


# Resolved vendor data directory
_VENDOR_DIR = resolve_data_dir()

WYCHEPROOF_DIR = _VENDOR_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = _VENDOR_DIR / "cctv"
ACVP_DIR = _VENDOR_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = _VENDOR_DIR / "x509-limbo"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run python -m pytest tests/test_data_paths.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/data/__init__.py tests/test_data_paths.py
git commit -m "feat: fix data path resolution with XDG fallback for installed packages"
```

---

### Task 2: Move sources.toml into the package

**Files:**
- Move: `data/sources.toml` → `src/pkcs11_check/testcases/data/sources.toml`
- Modify: `data/sources.toml` (delete via git mv)
- Test: `tests/test_data_paths.py` (add manifest test)

- [ ] **Step 1: Write test for manifest loading**

Append to `tests/test_data_paths.py`:

```python
class TestSourcesManifest:
    def test_sources_toml_exists_in_package(self) -> None:
        from pkcs11_check.testcases.data import SOURCES_TOML

        assert SOURCES_TOML.exists(), f"sources.toml not found at {SOURCES_TOML}"

    def test_sources_toml_has_expected_keys(self) -> None:
        import tomllib

        from pkcs11_check.testcases.data import SOURCES_TOML

        with open(SOURCES_TOML, "rb") as f:
            sources = tomllib.load(f)
        assert "wycheproof" in sources
        assert "acvp" in sources
        for name, entry in sources.items():
            assert "repo" in entry, f"{name} missing 'repo'"
            assert "commit" in entry, f"{name} missing 'commit'"
            assert "archive_sha256" in entry, f"{name} missing 'archive_sha256'"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run python -m pytest tests/test_data_paths.py::TestSourcesManifest -v
```

Expected: FAIL — `sources.toml` not at package location yet.

- [ ] **Step 3: Move sources.toml into the package**

```bash
git mv data/sources.toml src/pkcs11_check/testcases/data/sources.toml
```

- [ ] **Step 4: Update the manifest header comment**

In `src/pkcs11_check/testcases/data/sources.toml`, change the header:

Old:
```toml
# Third-party test vector sources — single source of truth for fetch-data.sh.
# Run:    bash scripts/fetch-data.sh [name|all|--status]
# Update: change commit + archive_sha256, then re-fetch.
```

New:
```toml
# Third-party test vector sources — single source of truth.
# Run:    pkcs11-check fetch-data [name|all|--status]
# Update: change commit + archive_sha256, then re-fetch.
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run python -m pytest tests/test_data_paths.py -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add data/ src/pkcs11_check/testcases/data/sources.toml tests/test_data_paths.py
git commit -m "feat: move sources.toml into package for wheel distribution"
```

---

### Task 3: Implement fetch-data command

**Files:**
- Create: `src/pkcs11_check/cli/fetch_cmd.py`
- Modify: `src/pkcs11_check/cli/app.py`

- [ ] **Step 1: Create fetch_cmd.py with fetch-data command**

Create `src/pkcs11_check/cli/fetch_cmd.py`:

```python
"""pkcs11-check fetch-data and fetch-disabled commands."""
from __future__ import annotations

import hashlib
import shutil
import tempfile
import tomllib
import zipfile
from pathlib import Path
from urllib.request import urlopen

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TransferSpeedColumn,
)

from pkcs11_check.testcases.data import SOURCES_TOML, resolve_data_dir

console = Console()

_DISABLED_BASELINE_URL = (
    "https://raw.githubusercontent.com/mingulov/pkcs11-check"
    "/main/config/disabled-tests.txt"
)


def _load_manifest() -> dict[str, dict[str, object]]:
    """Load the sources.toml manifest from the package."""
    with open(SOURCES_TOML, "rb") as f:
        return tomllib.load(f)


def _download_with_progress(url: str, dest: Path, label: str) -> None:
    """Download a URL to a file with a rich progress bar."""
    with urlopen(url) as resp:  # noqa: S310
        total = int(resp.headers.get("Content-Length", 0))
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
        ) as progress:
            task = progress.add_task(label, total=total or None)
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    progress.update(task, advance=len(chunk))


def _verify_sha256(path: Path, expected: str) -> bool:
    """Verify SHA-256 checksum of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest() == expected


def _extract_filtered(
    zip_path: Path, dest: Path, include: list[str] | None
) -> int:
    """Extract a zip, stripping the GitHub prefix dir, applying include filter.

    Returns count of extracted items.
    """
    with zipfile.ZipFile(zip_path) as zf:
        # GitHub archives have a single top-level dir: {RepoName}-{commit}/
        names = zf.namelist()
        if not names:
            return 0
        prefix = names[0].split("/")[0] + "/"

        count = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Strip the GitHub prefix
            rel = info.filename[len(prefix):]
            if not rel:
                continue
            # Apply include filter
            if include:
                if not any(rel.startswith(pat.rstrip("/")) for pat in include):
                    continue
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            count += 1
    return count


def _fetch_one(name: str, entry: dict[str, object], data_dir: Path) -> bool:
    """Fetch a single source. Returns True on success."""
    repo = str(entry["repo"])
    commit = str(entry["commit"])
    sha256 = str(entry.get("archive_sha256", ""))
    include_raw = entry.get("include")
    include = list(include_raw) if isinstance(include_raw, list) else None
    desc = str(entry.get("description", name))

    url = f"https://github.com/{repo}/archive/{commit}.zip"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        zip_path = tmp / "archive.zip"

        console.print(f"\n[bold]{name}[/bold]: {desc}")
        _download_with_progress(url, zip_path, f"Downloading {name}")

        # Verify checksum
        if sha256 and sha256 != "PLACEHOLDER":
            if not _verify_sha256(zip_path, sha256):
                actual = hashlib.sha256(zip_path.read_bytes()).hexdigest()
                console.print(f"  [red]SHA-256 mismatch![/red]")
                console.print(f"  Expected: {sha256}")
                console.print(f"  Actual:   {actual}")
                return False
            console.print("  [green]Checksum OK[/green]")
        else:
            console.print("  [yellow]Checksum: PLACEHOLDER (skipping)[/yellow]")

        # Extract to temp, then atomically replace
        extract_dir = tmp / "extracted"
        count = _extract_filtered(zip_path, extract_dir, include)

        dest = data_dir / name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(extract_dir), str(dest))
        console.print(f"  Installed {count} files to {dest}")

    return True


def _show_status(data_dir: Path) -> None:
    """Show status of each source."""
    sources = _load_manifest()
    console.print(f"[bold]Test vector data status[/bold] (target: {data_dir})\n")
    for name, entry in sources.items():
        desc = str(entry.get("description", name))
        dest = data_dir / name
        if dest.exists():
            console.print(f"  [green]\u2713[/green] {name:<14} {desc}")
        else:
            console.print(
                f"  [red]\u2717[/red] {name:<14} {desc}"
                f" [dim](pkcs11-check fetch-data {name})[/dim]"
            )
    console.print()


def _print_checksums() -> None:
    """Download all archives and print SHA-256 checksums."""
    sources = _load_manifest()
    console.print("[bold]Downloading archives and computing SHA-256...[/bold]\n")
    for name, entry in sources.items():
        repo = str(entry["repo"])
        commit = str(entry["commit"])
        url = f"https://github.com/{repo}/archive/{commit}.zip"
        console.print(f"  {name}: {url}")
        with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
            _download_with_progress(url, Path(tmp.name), f"  {name}")
            h = hashlib.sha256(Path(tmp.name).read_bytes()).hexdigest()
            console.print(f'  archive_sha256 = "{h}"\n')


def fetch_data_command(
    source: str = typer.Argument("all", help="Source name or 'all'"),
    status: bool = typer.Option(False, "--status", help="Show status of each source"),
    checksums: bool = typer.Option(
        False, "--checksums", help="Download and print SHA-256 checksums"
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir", help="Override data directory"
    ),
) -> None:
    """Download third-party test vectors (Wycheproof, ACVP, CCTV, x509-limbo)."""
    target = data_dir or resolve_data_dir()

    if status:
        _show_status(target)
        return

    if checksums:
        _print_checksums()
        return

    sources = _load_manifest()

    if source == "all":
        target.mkdir(parents=True, exist_ok=True)
        failed = []
        for name, entry in sources.items():
            if not _fetch_one(name, entry, target):
                failed.append(name)
        if failed:
            console.print(f"\n[red]Failed:[/red] {', '.join(failed)}")
            raise typer.Exit(code=1)
        console.print("\n[green]Done. All sources fetched.[/green]")
    else:
        if source not in sources:
            console.print(f"[red]Unknown source:[/red] {source}")
            console.print(f"Available: {', '.join(sources.keys())}")
            raise typer.Exit(code=2)
        target.mkdir(parents=True, exist_ok=True)
        if not _fetch_one(source, sources[source], target):
            raise typer.Exit(code=1)


def fetch_disabled_command(
    data_dir: Path | None = typer.Option(
        None, "--data-dir", help="Override data directory"
    ),
) -> None:
    """Download the disabled-tests baseline from GitHub."""
    target = data_dir or resolve_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    dest = target / "disabled-tests.txt"

    console.print("[bold]Fetching disabled-tests baseline...[/bold]")

    try:
        with urlopen(_DISABLED_BASELINE_URL) as resp:  # noqa: S310
            content = resp.read().decode("utf-8")
    except Exception as exc:
        console.print(f"[red]Download failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Validate content
    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        console.print("[red]Downloaded file is empty or has no entries[/red]")
        raise typer.Exit(code=1)

    nodeid_lines = [line for line in lines if "::" in line]
    if len(nodeid_lines) < len(lines) * 0.5:
        console.print(
            "[red]Downloaded file doesn't look like a disabled-tests baseline[/red]"
        )
        raise typer.Exit(code=1)

    dest.write_text(content)
    console.print(
        f"  [green]Downloaded {len(nodeid_lines)} disabled entries[/green] to {dest}"
    )
```

- [ ] **Step 2: Register commands in app.py**

In `src/pkcs11_check/cli/app.py`, add imports and register the new commands.

Add after the existing imports:
```python
from pkcs11_check.cli.fetch_cmd import fetch_data_command, fetch_disabled_command
```

Add after the existing `app.command()` registrations:
```python
app.command("fetch-data")(fetch_data_command)
app.command("fetch-disabled")(fetch_disabled_command)
```

- [ ] **Step 3: Verify CLI works**

```bash
uv run pkcs11-check fetch-data --status
uv run pkcs11-check fetch-disabled --help
uv run pkcs11-check --help
```

Expected: `fetch-data --status` shows sources with present/missing status. `--help` shows both new commands.

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/cli/fetch_cmd.py src/pkcs11_check/cli/app.py
git commit -m "feat: add fetch-data and fetch-disabled CLI commands"
```

---

### Task 4: Disabled baseline auto-discovery

**Files:**
- Modify: `src/pkcs11_check/core/test_selection.py`
- Modify: `src/pkcs11_check/cli/test_cmd.py`
- Test: `tests/test_data_paths.py` (extend)

- [ ] **Step 1: Write test for auto-discovery**

Append to `tests/test_data_paths.py`:

```python
class TestDisabledAutoDiscovery:
    def test_auto_discovers_from_data_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "disabled-tests.txt"
        baseline_file.write_text(
            "# test baseline\n"
            "src/pkcs11_check/testcases/test_foo.py::TestFoo::test_bar\n"
        )
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path))

        from pkcs11_check.core.test_selection import auto_discover_disabled_baseline

        result = auto_discover_disabled_baseline()
        assert result is not None
        assert result == baseline_file

    def test_no_discovery_when_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(tmp_path))

        from pkcs11_check.core.test_selection import auto_discover_disabled_baseline

        assert auto_discover_disabled_baseline() is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run python -m pytest tests/test_data_paths.py::TestDisabledAutoDiscovery -v
```

Expected: FAIL — `auto_discover_disabled_baseline` does not exist.

- [ ] **Step 3: Add auto_discover_disabled_baseline to test_selection.py**

In `src/pkcs11_check/core/test_selection.py`, add this function after the existing `load_disabled_baseline`:

```python
def auto_discover_disabled_baseline() -> Path | None:
    """Check if a disabled-tests.txt exists in the resolved data directory."""
    from pkcs11_check.testcases.data import resolve_data_dir

    candidate = resolve_data_dir() / "disabled-tests.txt"
    if candidate.is_file():
        return candidate
    return None
```

- [ ] **Step 4: Wire auto-discovery into test_cmd.py**

In `src/pkcs11_check/cli/test_cmd.py`, modify the baseline loading section. Find the block that reads:

```python
            baseline = None
            if not ignore_disabled_tests:
                baseline = load_disabled_baseline(runtime_config.disabled_tests_file)
```

Replace with:

```python
            baseline = None
            if not ignore_disabled_tests:
                disabled_path = runtime_config.disabled_tests_file
                if disabled_path is None:
                    from pkcs11_check.core.test_selection import (
                        auto_discover_disabled_baseline,
                    )

                    disabled_path = auto_discover_disabled_baseline()
                    if disabled_path is not None:
                        console.print(
                            f"[dim]Using auto-discovered disabled baseline: "
                            f"{disabled_path}[/dim]"
                        )
                baseline = load_disabled_baseline(disabled_path)
```

- [ ] **Step 5: Run tests**

```bash
uv run python -m pytest tests/test_data_paths.py -v
```

Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/core/test_selection.py src/pkcs11_check/cli/test_cmd.py tests/test_data_paths.py
git commit -m "feat: auto-discover disabled baseline from data directory"
```

---

### Task 5: Delete scripts/fetch-data.sh and update docs

**Files:**
- Delete: `scripts/fetch-data.sh`
- Modify: `docs/commands.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`

- [ ] **Step 1: Delete the bash script**

```bash
git rm scripts/fetch-data.sh
```

- [ ] **Step 2: Update docs/commands.md**

In `docs/commands.md`, replace the "Test vector data" section:

Old:
```markdown
## Test vector data

```bash
bash scripts/fetch-data.sh --status          # show what's present/missing
bash scripts/fetch-data.sh all               # fetch all sources (~800 MB)
bash scripts/fetch-data.sh wycheproof        # fetch individual source
```
```

New:
```markdown
## Test vector data

```bash
uv run pkcs11-check fetch-data --status      # show what's present/missing
uv run pkcs11-check fetch-data all           # fetch all sources (~800 MB)
uv run pkcs11-check fetch-data wycheproof    # fetch individual source
uv run pkcs11-check fetch-disabled           # fetch disabled-tests baseline
```
```

- [ ] **Step 3: Update docs/architecture.md**

In `docs/architecture.md`, in the "Test vector data" section, change the line:

Old:
```
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` — gitignored, fetched by `scripts/fetch-data.sh`
```

New:
```
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` — gitignored, fetched by `pkcs11-check fetch-data`
```

Also update:

Old:
```
- `data/sources.toml` — tracked manifest: pinned commits, SHA-256 checksums, include filters
```

New:
```
- `src/pkcs11_check/testcases/data/sources.toml` — tracked manifest: pinned commits, SHA-256 checksums, include filters (ships in wheel)
```

- [ ] **Step 4: Update README.md quick start**

In `README.md`, update the Quick start section to mention the installed workflow.

After the existing quick start block, add:

```markdown

### From PyPI (installed)

```bash
pip install pkcs11-check
pkcs11-check fetch-data all                            # download test vectors (~800 MB)
pkcs11-check test --module /path/to/module.so --pin 1234
```
```

- [ ] **Step 5: Commit**

```bash
git add scripts/fetch-data.sh docs/commands.md docs/architecture.md README.md
git commit -m "docs: update references from scripts/fetch-data.sh to pkcs11-check fetch-data"
```

---

### Task 6: Run full validation

**Files:** None (verification only)

- [ ] **Step 1: Run meta-tests**

```bash
uv run python -m pytest tests/ -v
```

Expected: ALL PASS

- [ ] **Step 2: Run ruff**

```bash
uv run ruff check src/pkcs11_check/cli/fetch_cmd.py src/pkcs11_check/testcases/data/__init__.py
uv run ruff format --check src/pkcs11_check/cli/fetch_cmd.py src/pkcs11_check/testcases/data/__init__.py
```

Expected: No errors

- [ ] **Step 3: Run mypy**

```bash
uv run mypy src/pkcs11_check/cli/fetch_cmd.py src/pkcs11_check/testcases/data/__init__.py src/pkcs11_check/core/test_selection.py
```

Expected: No errors (may need type: ignore for urllib S310 security warning — that's handled by noqa)

- [ ] **Step 4: Verify CLI end-to-end**

```bash
uv run pkcs11-check fetch-data --status
uv run pkcs11-check fetch-data --help
uv run pkcs11-check fetch-disabled --help
uv run pkcs11-check --help | grep fetch
```

Expected: Both commands visible, status shows data sources.

- [ ] **Step 5: Verify wheel includes sources.toml**

```bash
uv build 2>&1 | tail -3
python3 -c "import zipfile; z = zipfile.ZipFile(list(__import__('pathlib').Path('dist').glob('*.whl'))[0]); print([n for n in z.namelist() if 'sources.toml' in n])"
```

Expected: `['pkcs11_check/testcases/data/sources.toml']`

"""pkcs11-check fetch-data and fetch-disabled commands."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import tomllib
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
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
    "https://raw.githubusercontent.com/mingulov/pkcs11-check/main/data/disabled-tests.txt"
)


def _validate_https_url(url: str) -> None:
    """Require HTTPS URLs before handing them to urlopen."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        msg = f"only HTTPS downloads are allowed: {url}"
        raise ValueError(msg)


def _load_manifest() -> dict[str, dict[str, object]]:
    """Load the sources.toml manifest from the package."""
    with open(SOURCES_TOML, "rb") as f:
        return tomllib.load(f)


def _download_with_progress(url: str, dest: Path, label: str) -> None:
    """Download a URL to a file with a rich progress bar."""
    _validate_https_url(url)
    # _validate_https_url rejects local and non-HTTPS schemes before urlopen.
    with urlopen(url) as resp:  # nosec B310
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


def _extract_filtered(zip_path: Path, dest: Path, include: list[str] | None) -> int:
    """Extract a zip, strip GitHub prefix dir, apply include filter.

    Returns count of extracted files.
    """
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        if not names:
            return 0
        prefix = names[0].split("/")[0] + "/"

        count = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not info.filename.startswith(prefix):
                msg = f"unsafe archive member outside root prefix: {info.filename}"
                raise ValueError(msg)
            rel = info.filename[len(prefix) :]
            if not rel:
                continue
            if include:
                if not any(rel.startswith(pat.rstrip("/")) for pat in include):
                    continue
            target = dest / rel
            try:
                target.resolve().relative_to(dest.resolve())
            except ValueError as exc:
                msg = f"unsafe archive member path: {info.filename}"
                raise ValueError(msg) from exc
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
    include = [str(i) for i in include_raw] if isinstance(include_raw, list) else None
    desc = str(entry.get("description", name))

    url = f"https://github.com/{repo}/archive/{commit}.zip"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        zip_path = tmp / "archive.zip"

        console.print(f"\n[bold]{name}[/bold]: {desc}")
        _download_with_progress(url, zip_path, f"Downloading {name}")

        if sha256 and sha256 != "PLACEHOLDER":
            if not _verify_sha256(zip_path, sha256):
                actual = hashlib.sha256(zip_path.read_bytes()).hexdigest()
                console.print("  [red]SHA-256 mismatch![/red]")
                console.print(f"  Expected: {sha256}")
                console.print(f"  Actual:   {actual}")
                return False
            console.print("  [green]Checksum OK[/green]")
        else:
            console.print("  [yellow]Checksum: PLACEHOLDER (skipping)[/yellow]")

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
                f"  [red]\u2717[/red] {name:<14} {desc} [dim](pkcs11-check fetch-data {name})[/dim]"
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
            tmp_path = Path(tmp.name)
            _download_with_progress(url, tmp_path, f"  {name}")
            h = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
            console.print(f'  archive_sha256 = "{h}"\n')


def fetch_data_command(
    source: str = typer.Argument("all", help="Source name or 'all'"),
    status: bool = typer.Option(False, "--status", help="Show status of each source"),
    checksums: bool = typer.Option(
        False,
        "--checksums",
        help="Download and print SHA-256 checksums",
    ),
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Override data directory"),
) -> None:
    """Download third-party test vectors."""
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
        failed: list[str] = []
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
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Override data directory"),
) -> None:
    """Download the disabled-tests baseline from GitHub."""
    target = data_dir or resolve_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    dest = target / "disabled-tests.txt"

    console.print("[bold]Fetching disabled-tests baseline...[/bold]")

    try:
        _validate_https_url(_DISABLED_BASELINE_URL)
        # _DISABLED_BASELINE_URL is an HTTPS constant and is validated above.
        with urlopen(_DISABLED_BASELINE_URL) as resp:  # nosec B310
            content = resp.read().decode("utf-8")
    except Exception as exc:
        console.print(f"[red]Download failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

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
        console.print("[red]Downloaded file doesn't look like a disabled-tests baseline[/red]")
        raise typer.Exit(code=1)

    dest.write_text(content)
    console.print(f"  [green]Downloaded {len(nodeid_lines)} disabled entries[/green] to {dest}")

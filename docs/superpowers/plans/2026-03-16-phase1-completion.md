# Phase 1 Completion Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete all Phase 1 MVP functionality: working `pkcs11-check test` and `info` commands, pytest markers, mechanism filtering, output formats, logging, and expanded test coverage (~50-80 PKCS#11 tests).

**Architecture:** Wire CLI `test` command to invoke pytest programmatically against `src/pkcs11-check/testcases/`. Add rich info display via python-pkcs11 introspection. Register custom markers in the plugin. Add JSON/JUnit output via pytest's built-in reporters. Auto-skip tests based on mechanism availability.

**Tech Stack:** pytest (programmatic invocation), python-pkcs11, typer, rich (tables, panels), Python logging

**Spec:** `docs/superpowers/specs/2026-03-16-pkcs11-check-design.md`

---

## File Structure

### Files to modify
- `src/pkcs11-check/cli/test_cmd.py` — wire to run pytest programmatically
- `src/pkcs11-check/cli/info_cmd.py` — implement module info display
- `src/pkcs11-check/plugin.py` — register markers, add mechanism skip logic
- `src/pkcs11-check/testcases/conftest.py` — add skip-unsupported fixture, marker defs

### Files to create
- `src/pkcs11-check/markers.py` — marker definitions and version-check logic
- `src/pkcs11-check/core/logging.py` — logging setup with rich handler and trace mode
- `src/pkcs11-check/testcases/test_object.py` — object/key/attribute tests
- `src/pkcs11-check/testcases/test_mechanism.py` — mechanism enumeration + edge cases
- `src/pkcs11-check/testcases/test_digest.py` — digest, HMAC, wrap/unwrap tests
- `src/pkcs11-check/testcases/test_errors.py` — error handling and edge cases
- `tests/test_markers.py` — tests for marker skip logic
- `tests/test_info_cmd.py` — tests for info command output

---

## Chunk 1: pytest Markers & Mechanism Filtering

### Task 1: Create marker definitions

**Files:**
- Create: `src/pkcs11-check/markers.py`
- Test: `tests/test_markers.py`

- [ ] **Step 1: Write failing tests for marker logic**

```python
# tests/test_markers.py
"""Tests for pytest marker definitions and version-check logic."""
from __future__ import annotations

import pytest
from pkcs11_check.markers import should_skip_for_version, MARKER_DEFINITIONS


class TestVersionSkipLogic:
    def test_v30_test_skipped_on_v240(self) -> None:
        assert should_skip_for_version("requires_v30", "2.40") is True

    def test_v30_test_runs_on_v30(self) -> None:
        assert should_skip_for_version("requires_v30", "3.0") is False

    def test_v30_test_runs_on_v32(self) -> None:
        assert should_skip_for_version("requires_v30", "3.2") is False

    def test_v32_test_skipped_on_v30(self) -> None:
        assert should_skip_for_version("requires_v32", "3.0") is True

    def test_v32_test_runs_on_v32(self) -> None:
        assert should_skip_for_version("requires_v32", "3.2") is False

    def test_unknown_marker_never_skips(self) -> None:
        assert should_skip_for_version("unknown", "2.40") is False


class TestMarkerDefinitions:
    def test_all_markers_defined(self) -> None:
        names = [m.name for m in MARKER_DEFINITIONS]
        assert "requires_v30" in names
        assert "requires_v32" in names
        assert "destructive" in names
        assert "pqc" in names
        assert "slow" in names
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_markers.py -v`

- [ ] **Step 3: Implement markers.py**

```python
# src/pkcs11-check/markers.py
"""pytest marker definitions for pkcs11-check."""
from __future__ import annotations

from dataclasses import dataclass

# Version ordering for comparison
_VERSION_ORDER = {"2.40": 0, "3.0": 1, "3.2": 2}

# Minimum version required by each marker
_MARKER_MIN_VERSION: dict[str, str] = {
    "requires_v30": "3.0",
    "requires_v32": "3.2",
}


@dataclass(frozen=True)
class MarkerDef:
    name: str
    description: str


MARKER_DEFINITIONS: list[MarkerDef] = [
    MarkerDef("requires_v30", "Test requires PKCS#11 v3.0 or later"),
    MarkerDef("requires_v32", "Test requires PKCS#11 v3.2 or later"),
    MarkerDef("destructive", "Test modifies token state (requires --p11-destructive)"),
    MarkerDef("pqc", "Post-quantum cryptography test"),
    MarkerDef("slow", "Long-running test"),
]


def should_skip_for_version(marker_name: str, interface_version: str) -> bool:
    """Return True if a test with this marker should be skipped for the given version."""
    min_version = _MARKER_MIN_VERSION.get(marker_name)
    if min_version is None:
        return False
    return _VERSION_ORDER.get(interface_version, 0) < _VERSION_ORDER[min_version]
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_markers.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11-check/markers.py tests/test_markers.py
git commit -m "feat: add pytest marker definitions and version-skip logic"
```

### Task 2: Register markers and auto-skip in plugin

**Files:**
- Modify: `src/pkcs11-check/plugin.py`
- Modify: `src/pkcs11-check/testcases/conftest.py`

- [ ] **Step 1: Update plugin.py to register markers and implement skip hooks**

Add to `plugin.py`:
- `pytest_configure` hook to register all markers from `MARKER_DEFINITIONS`
- `pytest_collection_modifyitems` hook that checks `requires_v30`/`requires_v32` markers
  against the detected interface version and adds `pytest.mark.skip` with reason
- Also skip `@destructive` tests unless `--p11-destructive` is set

- [ ] **Step 2: Update testcases/conftest.py**

Remove the existing `pytest_collection_modifyitems` (it just skipped all tests when no module) — that logic moves to plugin.py.

- [ ] **Step 3: Run existing tests to verify nothing breaks**

Run: `uv run pytest tests/ -v`

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11-check/plugin.py src/pkcs11-check/testcases/conftest.py
git commit -m "feat: register markers and auto-skip by version/destructive flag"
```

---

## Chunk 2: Wire `pkcs11-check test` Command

### Task 3: Implement test command via programmatic pytest

**Files:**
- Modify: `src/pkcs11-check/cli/test_cmd.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write test for `pkcs11-check test` invoking pytest**

Add to `tests/test_cli.py`:

```python
class TestTestCommandExecution:
    def test_test_runs_and_returns_results(self, tmp_path: Path) -> None:
        """When module exists, test command invokes pytest and returns exit code."""
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        result = runner.invoke(app, [
            "test", "--module", str(fake_so),
        ])
        # Will fail because fake.so isn't a real module, but should attempt to run
        assert result.exit_code in (1, 3)  # test failure or module error

    def test_test_output_json(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        result = runner.invoke(app, [
            "test", "--module", str(fake_so), "--output", "json",
        ])
        assert result.exit_code in (1, 3)
```

- [ ] **Step 2: Implement test_cmd.py**

Replace the stub with pytest programmatic invocation:

```python
"""pkcs11-check test command — run PKCS#11 test suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import typer
from rich.console import Console

console = Console(stderr=True)

# Path to testcases directory (relative to package)
_TESTCASES_DIR = str(Path(__file__).parent.parent / "testcases")


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(1, "--sessions", "-s", help="Concurrent sessions"),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable destructive tests"),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json, junit"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Verbose output"),
) -> None:
    """Run the PKCS#11 test suite against a module."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    # Build pytest args
    args: list[str] = [_TESTCASES_DIR]
    args.extend(["--p11-module", str(module)])
    args.extend(["--p11-interface", interface])

    if destructive:
        args.append("--p11-destructive")

    if category:
        # Map category names to test file patterns
        for cat in category.split(","):
            args.extend(["-k", cat.strip()])

    if match:
        args.extend(["-k", match])

    if verbose:
        args.append("-v")
    else:
        args.append("-q")

    # Output format
    if output == "json":
        args.extend(["--tb=no", "-q"])
    elif output == "junit":
        args.extend(["--junit-xml=pkcs11-check-results.xml"])

    # Run pytest programmatically
    exit_code = pytest.main(args)
    raise typer.Exit(code=exit_code)
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_cli.py -v`

- [ ] **Step 4: Manual verification with SoftHSM2**

```bash
bash scripts/setup-softhsm.sh
export SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf
uv run pkcs11-check test --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin 1234
```

Expected: runs all testcases, shows results.

Note: `--p11-pin` needs to be passed through. Add `pin` option to test_command and pass
as env var `P11TEST_PIN` before invoking pytest, since pytest.main() runs in-process.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11-check/cli/test_cmd.py tests/test_cli.py
git commit -m "feat: wire pkcs11-check test command to run pytest programmatically"
```

---

## Chunk 3: Implement `pkcs11-check info`

### Task 4: Implement info command

**Files:**
- Modify: `src/pkcs11-check/cli/info_cmd.py`
- Create: `tests/test_info_cmd.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_info_cmd.py
"""Tests for pkcs11-check info command."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner
from pkcs11_check.cli.app import app

runner = CliRunner()


class TestInfoCommand:
    def test_info_nonexistent_module(self) -> None:
        result = runner.invoke(app, ["info", "--module", "/nonexistent.so"])
        assert result.exit_code == 3

    def test_info_shows_module_path(self, tmp_path: Path) -> None:
        fake_so = tmp_path / "module.so"
        fake_so.touch()
        mock_lib = MagicMock()
        mock_lib.manufacturer_id = "Test Manufacturer"
        mock_lib.library_description = "Test Library"
        mock_lib.library_version = (2, 40)
        mock_lib.get_slots.return_value = []
        with patch("pkcs11_check.cli.info_cmd.load_module") as mock_load:
            mock_module = MagicMock()
            mock_module.lib = mock_lib
            mock_module.path = fake_so
            mock_module.interface_version = "2.40"
            mock_module.get_slots.return_value = []
            mock_load.return_value = mock_module
            result = runner.invoke(app, ["info", "--module", str(fake_so)])
        assert result.exit_code == 0
```

- [ ] **Step 2: Implement info_cmd.py**

Use `load_module` to load, then `rich.table.Table` to display:
- Library info (manufacturer, description, version)
- Interface version negotiated
- Slots with token info
- Mechanisms per slot (with key size ranges)

```python
"""pkcs11-check info command — show module information."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pkcs11_check.core.loader import load_module

console = Console()


def info_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    slot: int = typer.Option(0, "--slot", "-s", help="Slot index"),
) -> None:
    """Show PKCS#11 module information: version, slots, mechanisms."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    try:
        p11 = load_module(module, interface=interface)
    except Exception as exc:
        console.print(f"[red]Error loading module:[/red] {exc}")
        raise typer.Exit(code=3)

    # Library info
    console.print(f"[bold]Module:[/bold] {p11.path}")
    console.print(f"[bold]Interface:[/bold] v{p11.interface_version}")

    lib = p11.lib
    if hasattr(lib, "manufacturer_id"):
        console.print(f"[bold]Manufacturer:[/bold] {lib.manufacturer_id}")
    if hasattr(lib, "library_description"):
        console.print(f"[bold]Description:[/bold] {lib.library_description}")

    # Slots
    slots = p11.get_slots(token_present=True)
    console.print(f"\n[bold]Slots with tokens:[/bold] {len(slots)}")

    for i, s in enumerate(slots):
        token = s.get_token()
        console.print(f"\n  [bold]Slot {i}:[/bold] {token.label}")
        if hasattr(token, "manufacturer_id"):
            console.print(f"    Manufacturer: {token.manufacturer_id}")
        if hasattr(token, "model"):
            console.print(f"    Model: {token.model}")

        # Mechanisms
        mechanisms = s.get_mechanisms()
        table = Table(title=f"Mechanisms ({len(mechanisms)})")
        table.add_column("Mechanism", style="cyan")
        table.add_column("Key Size", justify="right")
        for mech in sorted(mechanisms, key=lambda m: m.name):
            info = s.get_mechanism_info(mech)
            key_range = f"{info.min_key_length}-{info.max_key_length}" if info else ""
            table.add_row(mech.name, key_range)
        console.print(table)
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_info_cmd.py -v`

- [ ] **Step 4: Manual verification**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pkcs11-check info \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11-check/cli/info_cmd.py tests/test_info_cmd.py
git commit -m "feat: implement pkcs11-check info command with rich table output"
```

---

## Chunk 4: Logging with Trace Mode

### Task 5: Add logging infrastructure

**Files:**
- Create: `src/pkcs11-check/core/logging.py`
- Modify: `src/pkcs11-check/cli/app.py` (add --log-level and --trace global options)

- [ ] **Step 1: Create logging.py**

```python
# src/pkcs11-check/core/logging.py
"""Logging setup for pkcs11-check."""
from __future__ import annotations

import logging
from rich.logging import RichHandler


def setup_logging(level: str = "INFO", trace: bool = False) -> None:
    """Configure logging with rich handler.

    If trace=True, sets level to DEBUG and enables PKCS#11 call tracing.
    """
    effective_level = "DEBUG" if trace else level.upper()
    logging.basicConfig(
        level=effective_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        force=True,
    )
    # Quiet noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
```

- [ ] **Step 2: Add global options to app.py callback**

Update the `callback()` in `app.py` to accept `--log-level` and `--trace`:

```python
@app.callback()
def callback(
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
    trace: bool = typer.Option(False, "--trace", help="Trace PKCS#11 calls"),
) -> None:
    """CLI-first PKCS#11 test suite."""
    from pkcs11_check.core.logging import setup_logging
    setup_logging(level=log_level, trace=trace)
```

- [ ] **Step 3: Run all tests to verify**

Run: `uv run pytest tests/ -v`

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11-check/core/logging.py src/pkcs11-check/cli/app.py
git commit -m "feat: add logging infrastructure with rich handler and trace mode"
```

---

## Chunk 5: Expanded Test Cases

Add test_object, test_mechanism, test_digest, test_errors to reach ~50+ PKCS#11 tests.

### Task 6: test_object.py — Object and key attribute tests

**Files:**
- Create: `src/pkcs11-check/testcases/test_object.py`

- [ ] **Step 1: Write test_object.py**

Tests for:
- Create session object with attributes
- Read object attributes back
- Find objects by template
- Destroy session objects
- Copy object
- Object size query

```python
# src/pkcs11-check/testcases/test_object.py
"""Tests for PKCS#11 object and key attribute management."""
from __future__ import annotations

from typing import Any

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_session: Any) -> None:
        """Create a named AES key and retrieve it by label."""
        key = p11_session.generate_key(
            KeyType.AES, 256,
            label="test-key-object",
            template={Attribute.EXTRACTABLE: False},
        )
        assert key is not None
        assert key.label == "test-key-object"

    def test_find_objects_by_label(self, p11_session: Any) -> None:
        """Find objects matching a label template."""
        p11_session.generate_key(KeyType.AES, 256, label="findme-obj")
        found = list(p11_session.get_objects({
            Attribute.LABEL: "findme-obj",
        }))
        assert len(found) >= 1

    def test_key_attributes_readable(self, p11_session: Any) -> None:
        """Key attributes (type, class, size) are readable."""
        key = p11_session.generate_key(KeyType.AES, 256, label="attr-test")
        assert key.key_type == KeyType.AES
        assert key.object_class == ObjectClass.SECRET_KEY

    def test_destroy_session_object(self, p11_session: Any) -> None:
        """Destroying a session object removes it from the session."""
        key = p11_session.generate_key(KeyType.AES, 128, label="destroy-me")
        key.destroy()
        found = list(p11_session.get_objects({Attribute.LABEL: "destroy-me"}))
        assert len(found) == 0


class TestKeyPairAttributes:
    def test_rsa_keypair_attributes(self, p11_session: Any) -> None:
        """RSA key pair has correct public/private attributes."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert pub.object_class == ObjectClass.PUBLIC_KEY
        assert priv.object_class == ObjectClass.PRIVATE_KEY
        assert pub.key_type == KeyType.RSA
        assert priv.key_type == KeyType.RSA

    def test_rsa_modulus_readable(self, p11_session: Any) -> None:
        """RSA public key modulus is readable."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == 256  # 2048 bits = 256 bytes
```

- [ ] **Step 2: Run against SoftHSM2**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_object.py \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --p11-pin=1234 -v
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11-check/testcases/test_object.py
git commit -m "feat: add object and key attribute test cases"
```

### Task 7: test_mechanism.py — Mechanism discovery edge cases

**Files:**
- Create: `src/pkcs11-check/testcases/test_mechanism.py`

- [ ] **Step 1: Write test_mechanism.py**

```python
# src/pkcs11-check/testcases/test_mechanism.py
"""Tests for PKCS#11 mechanism discovery and info retrieval."""
from __future__ import annotations

from typing import Any

import pkcs11
from pkcs11 import Mechanism


class TestMechanismInfo:
    def test_mechanism_info_has_key_size(self, p11_module: Any) -> None:
        """Mechanism info reports min/max key sizes."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        assert len(mechanisms) > 0
        # Pick any mechanism and check info
        for mech in mechanisms:
            info = slot.get_mechanism_info(mech)
            assert info.min_key_length >= 0
            assert info.max_key_length >= info.min_key_length
            break

    def test_all_mechanisms_have_info(self, p11_module: Any) -> None:
        """Every reported mechanism should return valid info."""
        slot = p11_module.get_slots(token_present=True)[0]
        for mech in slot.get_mechanisms():
            info = slot.get_mechanism_info(mech)
            assert info is not None

    def test_aes_key_sizes(self, p11_module: Any) -> None:
        """AES mechanism reports correct key size range."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        aes_cbc = [m for m in mechanisms if m == Mechanism.AES_CBC]
        if not aes_cbc:
            import pytest
            pytest.skip("AES_CBC not supported")
        info = slot.get_mechanism_info(aes_cbc[0])
        assert info.min_key_length <= 128
        assert info.max_key_length >= 256

    def test_rsa_key_sizes(self, p11_module: Any) -> None:
        """RSA mechanism reports reasonable key size range."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        rsa_pkcs = [m for m in mechanisms if m == Mechanism.RSA_PKCS]
        if not rsa_pkcs:
            import pytest
            pytest.skip("RSA_PKCS not supported")
        info = slot.get_mechanism_info(rsa_pkcs[0])
        assert info.min_key_length <= 2048
        assert info.max_key_length >= 2048


class TestMechanismCount:
    def test_has_symmetric_mechanisms(self, p11_module: Any) -> None:
        """Module supports at least one symmetric cipher."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        symmetric = [m for m in mechanisms if "AES" in m.name or "DES" in m.name]
        assert len(symmetric) > 0

    def test_has_hash_mechanisms(self, p11_module: Any) -> None:
        """Module supports at least one hash mechanism."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        hashes = [m for m in mechanisms if "SHA" in m.name]
        assert len(hashes) > 0
```

- [ ] **Step 2: Run against SoftHSM2 and commit**

```bash
git add src/pkcs11-check/testcases/test_mechanism.py
git commit -m "feat: add mechanism discovery and info test cases"
```

### Task 8: test_digest.py — Digest, HMAC, Wrap/Unwrap

**Files:**
- Create: `src/pkcs11-check/testcases/test_digest.py`

- [ ] **Step 1: Write test_digest.py**

```python
# src/pkcs11-check/testcases/test_digest.py
"""Tests for PKCS#11 digest, HMAC, and key wrap/unwrap operations."""
from __future__ import annotations

from typing import Any

import pkcs11
from pkcs11 import KeyType, Mechanism


class TestDigest:
    def test_sha256_digest(self, p11_session: Any) -> None:
        """SHA-256 digest produces 32-byte output."""
        data = b"test data for hashing"
        digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert len(digest) == 32

    def test_sha256_deterministic(self, p11_session: Any) -> None:
        """Same input produces same SHA-256 digest."""
        data = b"deterministic test"
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2

    def test_sha256_different_input_different_digest(self, p11_session: Any) -> None:
        """Different inputs produce different digests."""
        d1 = p11_session.digest(b"input one", mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(b"input two", mechanism=Mechanism.SHA256)
        assert d1 != d2

    def test_sha512_digest(self, p11_session: Any) -> None:
        """SHA-512 digest produces 64-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA512)
        assert len(digest) == 64

    def test_sha1_digest(self, p11_session: Any) -> None:
        """SHA-1 digest produces 20-byte output."""
        digest = p11_session.digest(b"test data", mechanism=Mechanism.SHA_1)
        assert len(digest) == 20


class TestKeyWrap:
    def test_aes_wrap_unwrap_roundtrip(self, p11_session: Any) -> None:
        """Wrap and unwrap a key, verify it still works."""
        # Generate a wrapping key
        wrap_key = p11_session.generate_key(
            KeyType.AES, 256,
            capabilities=pkcs11.MechanismFlag.WRAP | pkcs11.MechanismFlag.UNWRAP,
            template={pkcs11.Attribute.WRAP: True, pkcs11.Attribute.UNWRAP: True},
        )
        # Generate a key to be wrapped
        target_key = p11_session.generate_key(
            KeyType.AES, 128,
            template={pkcs11.Attribute.EXTRACTABLE: True},
        )
        # Wrap
        wrapped = wrap_key.wrap_key(target_key)
        assert len(wrapped) > 0

        # Unwrap
        unwrapped = wrap_key.unwrap_key(
            pkcs11.ObjectClass.SECRET_KEY, pkcs11.KeyType.AES, wrapped
        )
        assert unwrapped is not None
```

- [ ] **Step 2: Run and commit**

```bash
git add src/pkcs11-check/testcases/test_digest.py
git commit -m "feat: add digest, hash, and key wrap/unwrap test cases"
```

### Task 9: test_errors.py — Error handling and edge cases

**Files:**
- Create: `src/pkcs11-check/testcases/test_errors.py`

- [ ] **Step 1: Write test_errors.py**

```python
# src/pkcs11-check/testcases/test_errors.py
"""Tests for PKCS#11 error handling and edge cases."""
from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism


class TestInvalidOperations:
    def test_encrypt_with_wrong_key_type(self, p11_session: Any) -> None:
        """Encrypting with a signing key should fail."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            # Try to encrypt with private key (should be public key for RSA)
            priv.encrypt(b"test data")

    def test_invalid_mechanism_param(self, p11_session: Any) -> None:
        """Using wrong mechanism parameters should raise."""
        key = p11_session.generate_key(KeyType.AES, 256)
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            # AES-CBC needs 16-byte IV, provide 8 bytes
            key.encrypt(b"0123456789abcdef", mechanism_param=b"short")

    def test_generate_key_invalid_size(self, p11_session: Any) -> None:
        """Requesting unsupported key size should fail."""
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            p11_session.generate_key(KeyType.AES, 13)  # 13-bit AES doesn't exist


class TestEmptyInputs:
    def test_digest_empty_data(self, p11_session: Any) -> None:
        """Digest of empty data should produce valid hash."""
        digest = p11_session.digest(b"", mechanism=Mechanism.SHA256)
        assert len(digest) == 32
        # SHA-256 of empty string is a well-known value
        assert digest.hex().startswith("e3b0c44298fc")

    def test_encrypt_empty_block(self, p11_session: Any) -> None:
        """Encrypting empty data — behavior depends on mechanism."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        # Empty plaintext with CBC — should either work or raise
        try:
            ct = key.encrypt(b"", mechanism_param=iv)
            assert isinstance(ct, bytes)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Also acceptable


class TestSessionEdgeCases:
    def test_multiple_concurrent_operations(self, p11_session: Any) -> None:
        """Generate multiple keys in sequence without issues."""
        keys = []
        for i in range(10):
            key = p11_session.generate_key(KeyType.AES, 256, label=f"bulk-{i}")
            keys.append(key)
        assert len(keys) == 10

    def test_large_random_generation(self, p11_session: Any) -> None:
        """Generate a large random buffer."""
        # 8192 bits = 1024 bytes
        data = p11_session.generate_random(8192)
        assert len(data) == 1024
```

- [ ] **Step 2: Run and commit**

```bash
git add src/pkcs11-check/testcases/test_errors.py
git commit -m "feat: add error handling and edge case test cases"
```

---

## Chunk 6: Skip-Unsupported & Output Formats

### Task 10: Implement --skip-unsupported mechanism filtering

**Files:**
- Modify: `src/pkcs11-check/testcases/conftest.py`
- Modify: `src/pkcs11-check/plugin.py`

- [ ] **Step 1: Add mechanism-based skip fixture**

In `testcases/conftest.py`, add a fixture that queries the module's mechanisms and marks
tests as skipped if they require a mechanism the module doesn't support.

Create a `p11_mechanisms` session-scoped fixture that returns a set of available
mechanism names. Test cases can then use:

```python
@pytest.fixture(autouse=True)
def _skip_unsupported_mechanisms(
    request: pytest.FixtureRequest,
    p11_module: Any,
    p11_config: P11TestConfig,
) -> None:
    """Auto-skip tests that need mechanisms the module doesn't support."""
    if not p11_config.skip_unsupported:
        return
    marker = request.node.get_closest_marker("needs_mechanism")
    if marker is None:
        return
    needed = marker.args[0]
    slot = p11_module.get_slots(token_present=True)[0]
    available = {m.name for m in slot.get_mechanisms()}
    if needed not in available:
        pytest.skip(f"Mechanism {needed} not supported by module")
```

Then add `--p11-skip-unsupported` option to plugin.py.

- [ ] **Step 2: Commit**

```bash
git commit -m "feat: add mechanism-based auto-skip for unsupported operations"
```

### Task 11: Add JUnit XML output support to CLI

**Files:**
- Modify: `src/pkcs11-check/cli/test_cmd.py`

The JUnit XML output is already built into pytest (`--junit-xml=FILE`).
The test_cmd already passes `--junit-xml` when `--output junit` is specified.
Just needs a `--output-file` option for the path:

```python
output_file: str | None = typer.Option(None, "--output-file", help="Output file path")
```

When `output == "junit"`:
```python
args.extend(["--junit-xml", output_file or "pkcs11-check-results.xml"])
```

- [ ] **Step 1: Add output-file option and verify**
- [ ] **Step 2: Commit**

```bash
git commit -m "feat: add JUnit XML and JSON output support to CLI"
```

---

## Chunk 7: Final Quality Pass

### Task 12: Full quality verification

- [ ] **Step 1: Run ruff**

```bash
uv run ruff check src/ tests/ --fix
uv run ruff format src/ tests/
```

- [ ] **Step 2: Run mypy**

```bash
uv run mypy src/
```

- [ ] **Step 3: Run full meta-test suite**

```bash
uv run pytest tests/ -v
```

- [ ] **Step 4: Run full testcases against SoftHSM2**

```bash
bash scripts/setup-softhsm.sh
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf \
  uv run pytest src/pkcs11-check/testcases/ \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --p11-pin=1234 -v
```

Expected: 50+ PKCS#11 tests passing.

- [ ] **Step 5: Run `pkcs11-check test` CLI end-to-end**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf \
  uv run pkcs11-check test \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

- [ ] **Step 6: Run `pkcs11-check info` CLI**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf \
  uv run pkcs11-check info \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

- [ ] **Step 7: Docker test**

```bash
docker compose -f docker/docker-compose.test.yml build test-softhsm2
docker compose -f docker/docker-compose.test.yml run --rm test-softhsm2
```

- [ ] **Step 8: Commit and update CLAUDE.md if needed**

```bash
git add -A
git commit -m "chore: Phase 1 completion — quality pass and verification"
```

# Operator-Supplied Vendor-Mechanism Mapping — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator point pkcs11-check at a TOML file that names a token's vendor-defined mechanisms and optionally asserts each one implements a standard mechanism's API, so the suite recognizes them and runs the standard conformance rules against them — with zero provider-specific data baked into the source tree.

**Architecture:** A new self-contained loader (`core/vendor_map.py`) parses+validates the operator TOML into `dict[int, VendorMechSpec]`. The map rides on `CapabilityManifest` (serialization-safe, like the existing `functions` field) so subprocess-isolated runners see it. Four surgical integration points consume it: a name overlay (coverage/`has_mechanism`), and `MechanismCatalog.from_manifest` which — for an entry with `test_as` — builds a `MechEntry` keyed by the **vendor id** with the referenced standard's `MechConfig` (keygen mech overridden), so the untouched `select_for_scenario` engine routes it into the existing conformance scenarios. Absent map ⇒ byte-identical to today.

**Tech Stack:** Python 3.13, `tomllib` (stdlib), pydantic-settings, pytest, frozen dataclasses, `dataclasses.replace`. uv + ruff + `mypy src/`.

**Spec:** `docs/superpowers/specs/2026-06-09-vendor-mechanism-mapping-design.md`.

**Pre-reqs / conventions:** Always prefix tools with `uv run`. mypy gate is `uv run mypy src/` (NOT on test files). ruff line length 100. Each marker/schema string is provider-general — no provider names in `src/`.

---

## File Structure

- **Create `src/pkcs11_check/core/vendor_map.py`** — the loader + `VendorMechSpec` dataclass + validation. One responsibility: TOML → validated `dict[int, VendorMechSpec]`. Knows only the standard CKM name table; no PKCS#11 or provider specifics.
- **Modify `src/pkcs11_check/core/preflight.py`** — add `vendor_map` field to `CapabilityManifest` (serialized form) + populate in `probe_capabilities` is NOT where it comes from (it's operator config, not probed) — populated by the plugin, see Task 4.
- **Modify `src/pkcs11_check/plugin.py`** — resolve the map path (CLI/env/config) and attach it to the manifest in `_ensure_manifest`; add `--p11-vendor-map` option; feed vendor names into the coverage overlay in `pytest_sessionfinish`.
- **Modify `src/pkcs11_check/fixtures.py`** — `RawSession.mechanisms` includes declared vendor names when a map is present.
- **Modify `src/pkcs11_check/testcases/mechanism_catalog.py`** — `from_manifest` keeps vendor ids covered by the map and attaches a borrowed config for `test_as` entries.
- **Create `docs/vendor-map.sample.toml`** — a sample IBM map (documentation only; the only place a provider name appears, and it's a sample, not loaded by default).
- **Modify `docs/architecture.md`, `docs/commands.md`** — document the feature + flag.
- **Tests:** `tests/test_vendor_map.py` (loader), additions to `tests/test_mechanism_catalog.py` (or new `tests/test_vendor_catalog.py`), `tests/test_plugin.py` (manifest attach), `tests/test_release_hygiene.py` (generality lock).

---

# PHASE 1 — Vendor-map loader (self-contained, no integration)

### Task 1: `VendorMechSpec` + `load_vendor_map` with validation

**Files:**
- Create: `src/pkcs11_check/core/vendor_map.py`
- Test: `tests/test_vendor_map.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_vendor_map.py`:

```python
"""Tests for the operator-supplied vendor-mechanism map loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core.vendor_map import VendorMechSpec, VendorMapError, load_vendor_map


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "vendor.toml"
    p.write_text(text)
    return p


def test_load_minimal_named_only(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [mechanism.0x80010037]
        name = "CKM_IBM_KYBER"
        vendor = "IBM"
        """,
    )
    spec_map = load_vendor_map(path)
    assert set(spec_map) == {0x80010037}
    spec = spec_map[0x80010037]
    assert isinstance(spec, VendorMechSpec)
    assert spec.mech_id == 0x80010037
    assert spec.name == "CKM_IBM_KYBER"
    assert spec.vendor == "IBM"
    assert spec.test_as is None  # named-only
    assert spec.keygen_id is None


def test_load_full_test_as_entry(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [mechanism.0x80010035]
        name = "CKM_IBM_DILITHIUM"
        vendor = "IBM"
        spec = "IBM EP11 Dilithium r2/r3"
        resembles = "CKM_ML_DSA"
        test_as = "CKM_ML_DSA"
        keygen_id = 0x80010025
        notes = "round-2/3"
        """,
    )
    spec = load_vendor_map(path)[0x80010035]
    assert spec.test_as == "CKM_ML_DSA"
    assert spec.keygen_id == 0x80010025
    assert spec.resembles == "CKM_ML_DSA"


def test_reject_missing_required_name(tmp_path: Path) -> None:
    path = _write(tmp_path, "[mechanism.0x80010037]\nvendor = \"IBM\"\n")
    with pytest.raises(VendorMapError, match="name"):
        load_vendor_map(path)


def test_reject_non_hex_id(tmp_path: Path) -> None:
    path = _write(tmp_path, '[mechanism.not_hex]\nname = "X"\nvendor = "V"\n')
    with pytest.raises(VendorMapError, match="hex"):
        load_vendor_map(path)


def test_reject_unknown_test_as_target(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [mechanism.0x80010035]
        name = "CKM_IBM_DILITHIUM"
        vendor = "IBM"
        test_as = "CKM_NOT_A_REAL_MECHANISM"
        """,
    )
    with pytest.raises(VendorMapError, match="test_as"):
        load_vendor_map(path)


def test_reject_vendor_id_below_vendor_defined(tmp_path: Path) -> None:
    # 0x00000001 == CKM_RSA_PKCS, NOT a vendor id; must be rejected.
    path = _write(tmp_path, '[mechanism.0x00000001]\nname = "X"\nvendor = "V"\n')
    with pytest.raises(VendorMapError, match="vendor"):
        load_vendor_map(path)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(VendorMapError, match="not found"):
        load_vendor_map(tmp_path / "nope.toml")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_vendor_map.py -q`
Expected: FAIL — `ModuleNotFoundError: pkcs11_check.core.vendor_map`.

- [ ] **Step 3: Implement the loader**

Create `src/pkcs11_check/core/vendor_map.py`:

```python
"""Operator-supplied vendor-mechanism map loader.

pkcs11-check ships NO provider data. This module turns an operator-supplied TOML
file into a validated ``dict[int, VendorMechSpec]``. It knows only the standard CKM
name table — no provider specifics live here or anywhere in the source tree.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pkcs11_check.raw.api import ckm_id_for_name
from pkcs11_check.raw.types_std import CKM_VENDOR_DEFINED


class VendorMapError(ValueError):
    """Raised on any malformed or inconsistent vendor-map entry."""


@dataclass(frozen=True)
class VendorMechSpec:
    """One operator declaration for a vendor-defined mechanism id."""

    mech_id: int
    name: str
    vendor: str
    spec: str | None = None
    resembles: str | None = None
    test_as: str | None = None
    keygen_id: int | None = None
    key_param_sets: tuple[str, ...] = field(default_factory=tuple)
    notes: str | None = None


_REQUIRED = ("name", "vendor")
_STR_KEYS = ("name", "vendor", "spec", "resembles", "test_as", "notes")


def _parse_id(raw: str) -> int:
    text = raw.strip()
    try:
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 0)
    except ValueError as exc:
        raise VendorMapError(f"mechanism key {raw!r} is not a hex id") from exc
    return value


def _validate_standard_name(value: str, *, field_name: str) -> None:
    if ckm_id_for_name(value) is None:
        raise VendorMapError(f"{field_name} {value!r} is not a known standard CKM mechanism")


def load_vendor_map(path: Path) -> dict[int, VendorMechSpec]:
    """Parse + validate an operator vendor-map TOML. Raise VendorMapError on any problem."""
    if not Path(path).is_file():
        raise VendorMapError(f"vendor map not found: {path}")
    data = tomllib.loads(Path(path).read_text())
    mechanisms: dict[str, Any] = data.get("mechanism", {})
    if not isinstance(mechanisms, dict):
        raise VendorMapError("[mechanism] table malformed")

    result: dict[int, VendorMechSpec] = {}
    for raw_id, entry in mechanisms.items():
        if not isinstance(entry, dict):
            raise VendorMapError(f"[mechanism.{raw_id}] must be a table")
        mech_id = _parse_id(raw_id)
        if mech_id < int(CKM_VENDOR_DEFINED):
            raise VendorMapError(
                f"[mechanism.{raw_id}] id 0x{mech_id:08x} is below CKM_VENDOR_DEFINED "
                f"(0x{int(CKM_VENDOR_DEFINED):08x}); only vendor mechanisms may be mapped"
            )
        for key in _REQUIRED:
            if not entry.get(key):
                raise VendorMapError(f"[mechanism.{raw_id}] missing required key {key!r}")
        for key in _STR_KEYS:
            if key in entry and not isinstance(entry[key], str):
                raise VendorMapError(f"[mechanism.{raw_id}].{key} must be a string")
        for ref in ("test_as", "resembles"):
            if entry.get(ref):
                _validate_standard_name(entry[ref], field_name=f"[mechanism.{raw_id}].{ref}")
        keygen_id = entry.get("keygen_id")
        if keygen_id is not None and not isinstance(keygen_id, int):
            raise VendorMapError(f"[mechanism.{raw_id}].keygen_id must be an integer")
        param_sets = entry.get("key_param_sets", [])
        if not isinstance(param_sets, list) or not all(isinstance(p, str) for p in param_sets):
            raise VendorMapError(f"[mechanism.{raw_id}].key_param_sets must be a list of strings")
        result[mech_id] = VendorMechSpec(
            mech_id=mech_id,
            name=entry["name"],
            vendor=entry["vendor"],
            spec=entry.get("spec"),
            resembles=entry.get("resembles"),
            test_as=entry.get("test_as"),
            keygen_id=keygen_id,
            key_param_sets=tuple(param_sets),
            notes=entry.get("notes"),
        )
    return result
```

- [ ] **Step 4: Add the `ckm_id_for_name` helper if missing**

`load_vendor_map` needs to validate that `test_as`/`resembles` name a real standard mechanism. Confirm whether `src/pkcs11_check/raw/api.py` already exposes a name→id lookup (the exploration found `_CKM_BY_VALUE` for id→obj and `ckm_name` for id→str). If there is **no** public name→id function, add this to `raw/api.py` next to `ckm_name`:

```python
def ckm_id_for_name(name: str) -> int | None:
    """Return the integer id for a standard CKM_* name (prefix-optional), or None."""
    candidates = (name, name if name.startswith("CKM_") else f"CKM_{name}")
    for cand in candidates:
        obj = getattr(_ts_module, cand, None)  # _ts_module = imported types_std
        if isinstance(obj, int):
            return int(obj)
    return None
```

Confirm the exact name of the already-imported `types_std` module object in `api.py` (the exploration referenced `_build_constant_lookups` iterating `dir(types_std)`); reuse that import rather than re-importing.

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/test_vendor_map.py -q`
Expected: PASS (7 tests).

- [ ] **Step 6: Lint + type-check**

Run: `uv run ruff check src/pkcs11_check/core/vendor_map.py tests/test_vendor_map.py && uv run mypy src/`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/core/vendor_map.py tests/test_vendor_map.py src/pkcs11_check/raw/api.py
git commit -m "feat(vendor-map): operator vendor-mechanism TOML loader + validation"
```

---

# PHASE 2 — Manifest carries the map

### Task 2: Add `vendor_map` field to `CapabilityManifest`

**Files:**
- Modify: `src/pkcs11_check/core/preflight.py`
- Test: `tests/test_preflight.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_preflight.py`:

```python
def test_manifest_vendor_map_roundtrip_and_default(tmp_path: "Path") -> None:
    """vendor_map round-trips through save/load; legacy manifests default to {}."""
    import json
    from pathlib import Path

    from pkcs11_check.core.preflight import CapabilityManifest, load_manifest, save_manifest

    m = CapabilityManifest(
        status="ok",
        module_path="/tmp/m.so",
        requested_interface="auto",
        interface_version="3.2",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_DSA"],
        functions=["C_Sign"],
        vendor_map={"0x80010035": {"name": "CKM_IBM_DILITHIUM", "test_as": "CKM_ML_DSA"}},
    )
    path = tmp_path / "m.json"
    save_manifest(path, m)
    assert load_manifest(path).vendor_map["0x80010035"]["test_as"] == "CKM_ML_DSA"

    legacy = {
        "status": "ok", "module_path": "/tmp/m.so", "requested_interface": "auto",
        "interface_version": "2.40", "slot_index": 0, "slot_count": 1, "mechanisms": [],
    }
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy))
    assert load_manifest(legacy_path).vendor_map == {}
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_preflight.py::test_manifest_vendor_map_roundtrip_and_default -q`
Expected: FAIL — `TypeError: unexpected keyword argument 'vendor_map'`.

- [ ] **Step 3: Add the field**

In `src/pkcs11_check/core/preflight.py`, add to the `CapabilityManifest` dataclass after `functions` (all are default fields):

```python
    functions: list[str] = field(default_factory=list)
    vendor_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    error: str | None = None
    mechanism_info: dict[str, dict[str, Any]] = field(default_factory=dict)
```

The serialized form is the raw TOML-derived dict (string keys), so it is JSON-safe and `asdict`/`load_manifest(**raw)` round-trips. `probe_capabilities` does NOT set it (it is operator config, not probed) — it is populated by the plugin in Task 4.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_preflight.py -q && uv run mypy src/pkcs11_check/core/preflight.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/core/preflight.py tests/test_preflight.py
git commit -m "feat(preflight): carry operator vendor_map on CapabilityManifest"
```

### Task 3: CLI option + config resolution

**Files:**
- Modify: `src/pkcs11_check/plugin.py` (add `--p11-vendor-map` option), and the CLI command module that builds the manifest invocation (`src/pkcs11_check/cli/test_cmd.py` — confirm exact path) + pydantic-settings config (`src/pkcs11_check/config.py` or equivalent — confirm).
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Register the pytest option**

In `plugin.py::pytest_addoption`, add alongside `--p11-manifest`:

```python
    group.addoption(
        "--p11-vendor-map",
        dest="p11_vendor_map",
        default=None,
        help="Path to an operator TOML mapping vendor mechanism ids to names/test rules",
    )
```

- [ ] **Step 2: Resolution helper (TDD)**

Add to `tests/test_plugin.py`:

```python
def test_resolve_vendor_map_path_prefers_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import pkcs11_check.plugin as plugin_mod

    monkeypatch.delenv("P11TEST_VENDOR_MAP", raising=False)
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_vendor_map": "/cli/vendor.toml"}.get(
            name, default
        )
    )
    assert plugin_mod._resolve_vendor_map_path(config) == "/cli/vendor.toml"


def test_resolve_vendor_map_path_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import pkcs11_check.plugin as plugin_mod

    monkeypatch.setenv("P11TEST_VENDOR_MAP", "/env/vendor.toml")
    config = SimpleNamespace(getoption=lambda name, default=None: default)
    assert plugin_mod._resolve_vendor_map_path(config) == "/env/vendor.toml"


def test_resolve_vendor_map_path_none(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import pkcs11_check.plugin as plugin_mod

    monkeypatch.delenv("P11TEST_VENDOR_MAP", raising=False)
    config = SimpleNamespace(getoption=lambda name, default=None: default)
    assert plugin_mod._resolve_vendor_map_path(config) is None
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/test_plugin.py -k resolve_vendor_map -q`
Expected: FAIL — `_resolve_vendor_map_path` undefined.

- [ ] **Step 4: Implement the resolver**

In `plugin.py`:

```python
def _resolve_vendor_map_path(config: Any) -> str | None:
    """CLI flag > env P11TEST_VENDOR_MAP > None. (TOML-config key handled by CLI layer.)"""
    cli = config.getoption("p11_vendor_map", default=None)
    if cli:
        return str(cli)
    env = os.environ.get("P11TEST_VENDOR_MAP")
    return env or None
```

- [ ] **Step 5: Run to verify pass + lint/type**

Run: `uv run pytest tests/test_plugin.py -k resolve_vendor_map -q && uv run mypy src/pkcs11_check/plugin.py && uv run ruff check src/pkcs11_check/plugin.py`
Expected: PASS / clean.

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/plugin.py tests/test_plugin.py
git commit -m "feat(plugin): --p11-vendor-map option + path resolution"
```

### Task 4: Attach the loaded map to the manifest in `_ensure_manifest`

**Files:**
- Modify: `src/pkcs11_check/plugin.py` (`_ensure_manifest`)
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Write the failing test**

```python
def test_ensure_manifest_attaches_vendor_map(
    tmp_path: "Path", monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path
    from types import SimpleNamespace

    import pkcs11_check.plugin as plugin_mod
    from pkcs11_check.core.preflight import CapabilityManifest

    vendor = tmp_path / "vendor.toml"
    vendor.write_text('[mechanism.0x80010035]\nname = "CKM_IBM_DILITHIUM"\nvendor = "IBM"\n')
    module = tmp_path / "m.so"
    module.touch()

    def fake_preflight(module_, *, interface, slot, timeout, output_path):  # noqa: ANN001
        del timeout, output_path
        return CapabilityManifest(
            status="ok", module_path=str(module_), requested_interface=interface,
            interface_version="3.2", slot_index=slot, slot_count=1, mechanisms=[],
        )

    monkeypatch.setattr(plugin_mod, "run_preflight_subprocess", fake_preflight)
    monkeypatch.delenv("P11TEST_VENDOR_MAP", raising=False)
    options = {
        "p11_module": str(module), "p11_manifest": None, "p11_interface": None,
        "p11_slot": None, "p11_vendor_map": str(vendor),
    }
    stash = pytest.Stash()
    stash[plugin_mod._MANIFEST_KEY] = None
    config = SimpleNamespace(
        stash=stash, getoption=lambda name, default=None: options.get(name, default)
    )

    manifest = plugin_mod._ensure_manifest(config)
    assert manifest is not None
    assert manifest.vendor_map["0x80010035"]["name"] == "CKM_IBM_DILITHIUM"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_plugin.py::test_ensure_manifest_attaches_vendor_map -q`
Expected: FAIL — `vendor_map` is `{}`.

- [ ] **Step 3: Implement**

In `_ensure_manifest`, after the manifest is obtained and before caching it in the stash, attach the map. Use `dataclasses.replace` (manifest is frozen):

```python
    vendor_path = _resolve_vendor_map_path(config)
    if vendor_path:
        from dataclasses import replace

        from pkcs11_check.core.vendor_map import VendorMapError, load_vendor_map

        try:
            spec_map = load_vendor_map(Path(vendor_path))
        except VendorMapError as exc:
            pytest.exit(f"Invalid --p11-vendor-map: {exc}", returncode=2)
        manifest = replace(
            manifest,
            vendor_map={
                f"0x{mid:08x}": {
                    "name": s.name, "vendor": s.vendor, "spec": s.spec,
                    "resembles": s.resembles, "test_as": s.test_as,
                    "keygen_id": s.keygen_id, "key_param_sets": list(s.key_param_sets),
                    "notes": s.notes,
                }
                for mid, s in spec_map.items()
            },
        )
```

Apply this to BOTH manifest sources (the `--p11-manifest` precomputed path and the freshly-probed path) so a precomputed manifest still gets the operator map. Place the attach logic just before `config.stash[_MANIFEST_KEY] = manifest`.

- [ ] **Step 4: Run + lint/type**

Run: `uv run pytest tests/test_plugin.py -k vendor_map -q && uv run mypy src/pkcs11_check/plugin.py && uv run ruff check src/pkcs11_check/plugin.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/plugin.py tests/test_plugin.py
git commit -m "feat(plugin): load + attach operator vendor map to manifest (fail-fast on invalid)"
```

---

# PHASE 3 — Catalog integration (recognize + route into conformance)

### Task 5: `MechanismCatalog.from_manifest` keeps mapped vendor ids + borrows config

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_catalog.py`
- Test: `tests/test_vendor_catalog.py` (new)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_vendor_catalog.py`:

```python
"""Vendor-mechanism entries in the MechanismCatalog (operator-map driven)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog


def _manifest(mech_info: dict[str, Any], vendor_map: dict[str, Any]) -> Any:
    return SimpleNamespace(mechanism_info=mech_info, vendor_map=vendor_map)


def test_named_only_vendor_entry_present_without_config() -> None:
    manifest = _manifest(
        {"0x80010037": {"flags": 0, "min_key_size": 800, "max_key_size": 1568}},
        {"0x80010037": {"name": "CKM_IBM_KYBER", "vendor": "IBM", "test_as": None,
                        "keygen_id": None, "key_param_sets": []}},
    )
    catalog = MechanismCatalog.from_manifest(manifest)
    entry = catalog.entry_for_id(0x80010037)
    assert entry is not None
    assert entry.mech_name == "CKM_IBM_KYBER"
    assert entry.config is None  # named-only → never selected for a scenario


def test_test_as_vendor_entry_borrows_standard_config_with_keygen_override() -> None:
    from pkcs11_check.raw.types_std import CKM_ML_DSA

    manifest = _manifest(
        {"0x80010035": {"flags": 0, "min_key_size": 1312, "max_key_size": 2592}},
        {"0x80010035": {"name": "CKM_IBM_DILITHIUM", "vendor": "IBM",
                        "test_as": "CKM_ML_DSA", "keygen_id": 0x80010025,
                        "key_param_sets": []}},
    )
    catalog = MechanismCatalog.from_manifest(manifest)
    entry = catalog.entry_for_id(0x80010035)
    assert entry is not None
    assert entry.mech_id == 0x80010035  # tested against the VENDOR id, not CKM_ML_DSA
    assert entry.config is not None  # borrowed from CKM_ML_DSA's MechConfig
    assert entry.config.keygen_mech == 0x80010025  # overridden to the vendor keygen id
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_vendor_catalog.py -q`
Expected: FAIL — vendor ids dropped (`entry_for_id` None) and/or `entry_for_id` undefined.

- [ ] **Step 3: Implement**

In `mechanism_catalog.py`:

(a) Add an accessor if missing:

```python
    def entry_for_id(self, mech_id: int) -> MechEntry | None:
        return self._entries.get(mech_id)
```

(b) In `from_manifest`, after the standard loop that builds `entries` from `name_to_id`, add a vendor pass that consumes `manifest.vendor_map`:

```python
        from dataclasses import replace

        from pkcs11_check.mechanism_registry import MECHANISM_REGISTRY
        from pkcs11_check.raw.api import ckm_id_for_name

        vendor_map = getattr(manifest, "vendor_map", {}) or {}
        for hex_id, decl in vendor_map.items():
            mech_id = int(hex_id, 16)
            info = mech_info.get(hex_id, {})  # mechanism_info is keyed by the hex string
            config = None
            test_as = decl.get("test_as")
            if test_as:
                std_id = ckm_id_for_name(test_as)
                base = MECHANISM_REGISTRY.get(std_id) if std_id is not None else None
                if base is not None:
                    overrides: dict[str, Any] = {}
                    if decl.get("keygen_id") is not None:
                        overrides["keygen_mech"] = int(decl["keygen_id"])
                    config = replace(base, **overrides) if overrides else base
            entries[mech_id] = MechEntry(
                mech_id=mech_id,
                mech_name=decl.get("name", hex_id),
                flags=info.get("flags", 0),
                min_key_size=info.get("min_key_size", 0),
                max_key_size=info.get("max_key_size", 0),
                config=config,
            )
```

Notes for the implementer: confirm the exact key form of `manifest.mechanism_info` for vendor ids — the exploration found `preflight._mechanism_name` returns the hex string `"0x80010035"`, so `mech_info` is keyed by that hex string and the lookup above matches. Confirm `MechConfig` exposes `keygen_mech` (the exploration confirmed `keygen_mech: int | None`); if `key_param_sets` overrides are needed, map them onto the registry's param-set field name (confirm its exact name in `mechanism_registry/__init__.py`).

- [ ] **Step 4: Run + lint/type**

Run: `uv run pytest tests/test_vendor_catalog.py -q && uv run mypy src/pkcs11_check/testcases/mechanism_catalog.py && uv run ruff check src/pkcs11_check/testcases/mechanism_catalog.py tests/test_vendor_catalog.py`
Expected: PASS / clean.

- [ ] **Step 5: Confirm existing catalog tests still pass**

Run: `uv run pytest tests/test_mechanism_catalog.py tests/test_plugin.py -q`
Expected: PASS (the vendor pass only runs when `manifest.vendor_map` is non-empty, so existing behavior is unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/mechanism_catalog.py tests/test_vendor_catalog.py
git commit -m "feat(catalog): include operator-mapped vendor mechanisms; borrow standard config for test_as"
```

---

# PHASE 4 — Naming overlay (has_mechanism + coverage)

### Task 6: `has_mechanism` sees declared vendor names

**Files:**
- Modify: `src/pkcs11_check/fixtures.py` (`RawSession.mechanisms`)
- Test: `tests/test_fixtures_vendor_names.py` (new) — or extend an existing fixtures test

- [ ] **Step 1: Write the failing test**

Create `tests/test_fixtures_vendor_names.py`:

```python
"""RawSession.has_mechanism recognizes operator-declared vendor names."""

from __future__ import annotations

from pkcs11_check.fixtures import vendor_names_from_map


def test_vendor_names_both_forms() -> None:
    names = vendor_names_from_map({"0x80010035": {"name": "CKM_IBM_DILITHIUM"}})
    assert "CKM_IBM_DILITHIUM" in names
    assert "IBM_DILITHIUM" in names  # short form too
```

(The `RawSession.mechanisms` wiring is exercised end-to-end by the matrix run in Task 9; here we unit-test the pure helper that produces the extra names so the logic is locked without a live token.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_fixtures_vendor_names.py -q`
Expected: FAIL — `vendor_names_from_map` undefined.

- [ ] **Step 3: Implement**

In `fixtures.py`, add a pure helper and call it where `RawSession.mechanisms` builds its name set:

```python
def vendor_names_from_map(vendor_map: dict[str, dict[str, object]]) -> set[str]:
    """Declared vendor mechanism names (both CKM_-prefixed and short forms)."""
    names: set[str] = set()
    for decl in vendor_map.values():
        name = decl.get("name")
        if isinstance(name, str) and name:
            names.add(name)
            if name.startswith("CKM_"):
                names.add(name[4:])
    return names
```

Then, in the `RawSession.mechanisms` builder, after expanding the standard names, union in the vendor names when the session has access to the manifest's `vendor_map`. The `RawSession` already receives its mechanism set from the catalog/preflight; thread the manifest's `vendor_map` to it (the simplest wiring: the fixture that builds `RawSession` reads `_ensure_manifest(config).vendor_map` and passes it in). Confirm the exact `RawSession` construction site in `fixtures.py` and add `names |= vendor_names_from_map(vendor_map)`.

- [ ] **Step 4: Run + lint/type**

Run: `uv run pytest tests/test_fixtures_vendor_names.py -q && uv run mypy src/pkcs11_check/fixtures.py && uv run ruff check src/pkcs11_check/fixtures.py tests/test_fixtures_vendor_names.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/fixtures.py tests/test_fixtures_vendor_names.py
git commit -m "feat(fixtures): has_mechanism recognizes operator-declared vendor names"
```

### Task 7: Coverage reporting buckets vendor mechanisms by name

**Files:**
- Modify: `src/pkcs11_check/plugin.py` (`pytest_sessionfinish` coverage block)
- Test: `tests/test_plugin.py`

- [ ] **Step 1: Write the failing test**

Add a `pytest_sessionfinish` coverage test mirroring the existing `test_sessionfinish_emits_selection_report` shape, with a manifest carrying a `vendor_map`, asserting the emitted `CoverageReport`'s `mechanism_coverage` contains a `vendor` section listing `named+tested` / `named_only` ids by their declared name. (Reuse the `_FakeReportLogPlugin` already in `tests/test_plugin.py`.)

```python
def test_coverage_report_includes_vendor_section() -> None:
    # Build a config.stash like test_sessionfinish_emits_selection_report, plus a
    # manifest with vendor_map {"0x80010035": {name: CKM_IBM_DILITHIUM, test_as: CKM_ML_DSA},
    # "0x80010037": {name: CKM_IBM_KYBER, test_as: None}}. Run pytest_sessionfinish and assert
    # the CoverageReport's mechanism_coverage["vendor"] == {"named_tested": ["CKM_IBM_DILITHIUM"],
    # "named_only": ["CKM_IBM_KYBER"]}.
    ...
```

Fill in the body following the existing `test_sessionfinish_emits_selection_report` exactly (same stash keys, `_FakeReportLogPlugin`, `_RAW_INSTANCE` fake), adding `_MANIFEST_KEY` with the vendor_map manifest.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_plugin.py -k vendor_section -q`
Expected: FAIL — no `vendor` key in `mechanism_coverage`.

- [ ] **Step 3: Implement**

In `pytest_sessionfinish`, where `coverage_data["mechanism_coverage"]` is assembled, add a `vendor` sub-dict derived from `manifest.vendor_map`: ids with `test_as` set → `named_tested` (sorted declared names); without → `named_only`. Annotate each tested name with its `test_as` standard in an `as` map for the report.

- [ ] **Step 4: Run + lint/type**

Run: `uv run pytest tests/test_plugin.py -k vendor -q && uv run mypy src/pkcs11_check/plugin.py && uv run ruff check src/pkcs11_check/plugin.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/plugin.py tests/test_plugin.py
git commit -m "feat(coverage): report vendor mechanisms by declared name (tested/named-only)"
```

---

# PHASE 5 — Generality lock + docs

### Task 8: Generality meta-test + sample + docs

**Files:**
- Modify: `tests/test_release_hygiene.py`
- Create: `docs/vendor-map.sample.toml`
- Modify: `docs/architecture.md`, `docs/commands.md`

- [ ] **Step 1: Generality lock test**

Add to `tests/test_release_hygiene.py`:

```python
def test_no_vendor_mechanism_data_in_source() -> None:
    """pkcs11-check stays provider-general: the source tree ships the vendor-map LOADER
    but no concrete vendor-mechanism DATA. Provider names/ids belong only in operator
    configs and the docs sample."""
    import re

    src = REPO_ROOT / "src"
    # A vendor-id literal (0x8000xxxx+) paired with a provider mechanism name is the smell.
    offenders: list[str] = []
    for path in sorted(src.rglob("*.py")):
        text = path.read_text()
        if re.search(r"CKM_IBM_|CKM_UTIMACO_|CKM_NSS_(?!.*alias)", text):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == [], f"vendor mechanism data must live in operator configs: {offenders}"
```

(Refine the regex against the real tree — the intent is: no hard-coded vendor mechanism *registry data*. The loader module and tests reference `CKM_IBM_DILITHIUM` only as example strings in tests, so scope this to `src/pkcs11_check/**` excluding test files, and to registry-style definitions, not docstrings. Confirm it passes on the implemented tree before committing.)

- [ ] **Step 2: Create the sample**

Create `docs/vendor-map.sample.toml` with the two-entry IBM example from the spec (Dilithium with `test_as`, Kyber named-only), prefaced by a comment block explaining it is a *sample operator config*, not loaded by default, and that the operator asserts the API-equivalence at their own risk.

- [ ] **Step 3: Docs**

In `docs/commands.md`, document `--p11-vendor-map <file>` / `P11TEST_VENDOR_MAP`. In `docs/architecture.md`, add a short "Vendor-mechanism mapping (operator-supplied, opt-in)" subsection describing the loader → manifest → catalog flow and the provider-agnostic guarantee. Do NOT reference `docs/superpowers/` in these public docs (release-hygiene test forbids it).

- [ ] **Step 4: Run + commit**

Run: `uv run pytest tests/test_release_hygiene.py -q`
Expected: PASS.

```bash
git add tests/test_release_hygiene.py docs/vendor-map.sample.toml docs/architecture.md docs/commands.md
git commit -m "feat(vendor-map): generality lock + sample operator config + docs"
```

### Task 9: Matrix validation (deliberate, opt-in)

- [ ] **Step 1:** Run the PQC suite against opencryptoki-master **with** `docs/vendor-map.sample.toml` (IBM Dilithium `test_as=CKM_ML_DSA`, keygen 0x80010025) and confirm: the IBM mechanisms are **named** in coverage (not hex); the Dilithium entry **runs** the ML-DSA sign/verify scenario against id `0x80010035`; results classify per the standard model (pass/xfail/fail) — surfacing any real IBM-vs-FIPS deviation as a finding, never hidden. Command shape:
  `bash docker/test.sh opencryptoki-master --vendor-map docs/vendor-map.sample.toml -- <pqc files>` (wire `--vendor-map` through `docker/test.sh` → `PKCS11_CHECK_EXTRA_ARGS`, or set `P11TEST_VENDOR_MAP` in the container env).
- [ ] **Step 2:** Confirm the run **without** the map is byte-identical to the pre-feature behavior (IBM ids stay hex, untested).
- [ ] **Step 3:** Record observations in `docs/module-issues.md` (any IBM Dilithium/Kyber conformance deviations under the ML-DSA/ML-KEM rules). Do not re-gate to hide them.

---

## Self-Review

- **Spec coverage:** loader+validation (Task 1), manifest carriage (Task 2), CLI/env/config resolution (Task 3), fail-fast attach (Task 4), catalog inclusion + borrowed config + keygen override (Task 5), `has_mechanism` naming (Task 6), coverage buckets (Task 7), generality lock + sample + docs (Task 8), matrix validation (Task 9). Every spec section maps to a task.
- **Provider-agnostic guarantee:** enforced by Task 8's meta-test; the only provider name in-repo is the `docs/` sample.
- **Type consistency:** `VendorMechSpec` fields (Task 1) match the manifest serialized dict keys (Task 4) and the catalog reader (Task 5); `ckm_id_for_name` is defined in Task 1 (api.py) and reused in Task 5; `keygen_mech` override name confirmed against `MechConfig` in Task 5.
- **Open confirmations for the implementer (flagged inline, not placeholders):** exact `types_std` import object name in `api.py` (Task 1/4); the CLI command/config module paths (Task 3); the `MechConfig` param-set field name if `key_param_sets` overrides are wired (Task 5); the `RawSession` construction site for the vendor-name union (Task 6). Each is a "confirm the existing symbol" note, with the surrounding code fully specified.

## Notes / deferred (per spec "out of scope")

- Keygen-as-own-entry normalization (option b) — not implemented; `keygen_id` inline only.
- Full independent per-entry `MechConfig` in TOML — not implemented; reuse-by-reference + `keygen_mech`/param-set overrides only.
- No auto-detection of vendor mechanisms — explicit operator assertion only.

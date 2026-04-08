"""Collection-time CTS variant deselection.

When AES-CTS tests are collected, this conftest probes the module once
to detect the CS variant (CS1/CS2/CS3) and deselects non-matching tests
*before* they execute.  This avoids the overhead of individually skipping
thousands of parameterized tests at ~50ms each.

If detection fails (module errors on CTS encrypt), all CS variant tests
are deselected -- test_cts_detect.py will catch this as a failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Deselect CTS tests for non-matching CS variants at collection time."""
    # Classify CTS variant test items
    cts_variant_items: dict[str, list[pytest.Item]] = {}
    for item in items:
        nodeid = item.nodeid
        if "test_cts.py" not in nodeid:
            continue
        for v in ("1", "2", "3"):
            if f"_cs{v}_" in nodeid:
                cts_variant_items.setdefault(v, []).append(item)
                break

    if not cts_variant_items:
        return

    variant = _probe_cts_variant(config)

    # Collect items to deselect
    to_deselect: list[pytest.Item] = []
    if variant is None:
        # Detection failed: deselect all CS variant tests.
        # test_cts_detect.py (no "_cs{N}_" in its nodeid) will still run and FAIL.
        for vitems in cts_variant_items.values():
            to_deselect.extend(vitems)
    else:
        for v, vitems in cts_variant_items.items():
            if v != variant:
                to_deselect.extend(vitems)

    if to_deselect:
        deselected_ids = {id(item) for item in to_deselect}
        items[:] = [item for item in items if id(item) not in deselected_ids]
        config.hook.pytest_deselected(items=to_deselect)


def _probe_cts_variant(config: pytest.Config) -> str | None:
    """Detect CTS variant using a lightweight PKCS#11 probe.

    Returns "1", "2", "3", or None if detection fails.
    """
    module_path = config.getoption("p11_module", default=None)
    if module_path is None:
        return None

    try:
        return _detect_variant_via_pkcs11(config)
    except Exception:  # noqa: BLE001
        return None


class _MinimalSession:
    """Lightweight adapter for base_cts._detect_cts_variant."""

    __slots__ = ("raw", "sh", "_mechs")

    def __init__(self, raw: Any, sh: int, mechanism_names: frozenset[str]) -> None:
        self.raw = raw
        self.sh = sh
        self._mechs = mechanism_names

    def has_mechanism(self, name: str) -> bool:
        return name in self._mechs or f"CKM_{name}" in self._mechs


def _detect_variant_via_pkcs11(config: pytest.Config) -> str | None:
    """Load module, open session, detect CTS variant, clean up."""
    from pkcs11_check.core.loader import load_module
    from pkcs11_check.raw.bootstrap import (
        close_session_quietly,
        get_slot_ids,
        login_user,
        logout_quietly,
    )
    from pkcs11_check.raw.bootstrap import open_session as raw_open_session
    from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
    from pkcs11_check.raw.recipes import get_mechanism_list
    from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER
    from pkcs11_check.testcases.acvp.aes.base_cts import _detect_cts_variant

    module_path = config.getoption("p11_module")
    interface = config.getoption("p11_interface", default="auto")
    slot_opt = config.getoption("p11_slot", default=None)
    pin = config.getoption("p11_pin", default=None)

    p11 = load_module(Path(module_path), interface=interface)
    raw = p11.raw
    slots = get_slot_ids(raw)
    slot_idx = slot_opt if slot_opt is not None else 0
    slot_id = slots[slot_idx] if slot_idx < len(slots) else slots[0]

    # Build mechanism name set
    mechs = get_mechanism_list(raw, slot_id)
    names: set[str] = set()
    for m in mechs:
        mname = MECHANISM_NAMES.get(m, "")
        if mname:
            names.add(mname)
            if mname.startswith("CKM_"):
                names.add(mname[4:])

    if "AES_CTS" not in names:
        return None  # No CTS support; file-skip should handle this

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    sh = raw_open_session(raw, slot_id, flags)
    logged_in = False
    try:
        if pin is not None:
            login_user(raw, sh, CKU_USER, pin.encode("utf-8"))
            logged_in = True

        rs = _MinimalSession(raw, sh, frozenset(names))
        return _detect_cts_variant(rs)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
        close_session_quietly(raw, sh)

"""Collection-time CTS variant skip marking.

When AES-CTS tests are collected, this conftest probes the module once
to detect the CS variant (CS1/CS2/CS3) and marks non-matching tests as
skipped before they execute.  This keeps the full vector universe visible in
reported totals without paying per-test provider setup costs.

If detection fails (module errors on CTS encrypt), CS variant tests are
collection-skipped only when the detection sentinel is part of the selected
run; an exact standalone vector selection keeps its own runtime guard so the
failure evidence is not lost.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.testcases.acvp.aes.base_cts import (
    CtsDetectionResult as _CtsDetectionResult,
)
from pkcs11_check.testcases.acvp.aes.base_cts import (
    CtsDetectionStatus as _CtsDetectionStatus,
)

_DISABLE_COLLECTION_PROBES_ENV = "PKCS11_CHECK_DISABLE_COLLECTION_PROBES"


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark CTS tests for non-matching CS variants as counted skips."""
    if os.environ.get(_DISABLE_COLLECTION_PROBES_ENV):
        return
    if getattr(getattr(config, "option", None), "collectonly", False):
        return

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

    detection = _probe_cts_variant(config)

    if detection.status is not _CtsDetectionStatus.DETECTED:
        # A standalone exact selection may contain only a vector node.  Do not
        # turn that selected test into a collection-time skip: its normal
        # ``skip_unless_cts_variant`` guard must run and retain the
        # detection-failure classification.  The sentinel is skipped only when
        # it is actually part of this selection; never assume pytest selected a
        # sibling test or add one to the run.
        sentinel_selected = any(
            item.nodeid.rsplit("::", maxsplit=1)[-1] == "test_cts_variant_detected"
            for item in items
        )
        if sentinel_selected:
            # Detection failed: skip all CS variant tests.  The selected
            # sentinel remains the sole reporter.
            reason = _detection_skip_reason(detection)
            for vitems in cts_variant_items.values():
                for item in vitems:
                    item.add_marker(pytest.mark.skip(reason=reason))
        else:
            # An exact/targeted selection may contain only vector nodes.  Keep
            # one deterministic node runnable so its runtime guard emits the
            # detection result, and count the rest as skips.
            all_variant_items = [
                item for v in ("1", "2", "3") for item in cts_variant_items.get(v, [])
            ]
            for item in all_variant_items[1:]:
                item.add_marker(
                    pytest.mark.skip(
                        reason="CKM_AES_CTS detection reporter is retained by the selected CTS item"
                    )
                )
        return

    variant = detection.variant
    assert variant is not None
    for v, vitems in cts_variant_items.items():
        if v == variant:
            continue
        for item in vitems:
            item.add_marker(
                pytest.mark.skip(reason=f"Module implements CS{variant}, skipping CS{v} vectors")
            )


def _detection_skip_reason(detection: _CtsDetectionResult) -> str:
    """Explain collection skips while leaving the selected detector reporter runnable."""
    if detection.status is _CtsDetectionStatus.ABSENT:
        return "CKM_AES_CTS not supported by module"
    if detection.status is _CtsDetectionStatus.SETUP_UNAVAILABLE:
        reason = detection.detail.get("reason")
        if isinstance(reason, str) and reason:
            return reason
        return "C_CreateObject capability unavailable for CKM_AES_CTS detection"
    return (
        "CKM_AES_CTS variant detection failed; the selected CTS reporter records "
        "the provider finding"
    )


def _probe_cts_variant(config: pytest.Config) -> _CtsDetectionResult:
    """Detect CTS variant using a lightweight PKCS#11 probe.

    Returns the structured detection result; absent CTS is represented by
    ``CtsDetectionStatus.ABSENT`` and setup capability gaps by
    ``CtsDetectionStatus.SETUP_UNAVAILABLE``.
    """
    module_path = config.getoption("p11_module", default=None)
    if module_path is None:
        return _CtsDetectionResult(_CtsDetectionStatus.ABSENT)

    try:
        return _detect_variant_via_pkcs11(config)
    except pytest.skip.Exception as exc:
        # A missing setup capability (for example C_CreateObject) is still a
        # genuine skip, but it is distinct from an absent mechanism. Catch
        # only pytest's explicit skip signal; ordinary Python/ctypes
        # exceptions must remain visible to the collection gate.
        return _CtsDetectionResult(
            _CtsDetectionStatus.SETUP_UNAVAILABLE,
            detail={"reason": str(exc)},
        )


class _MinimalSession:
    """Lightweight adapter for base_cts._detect_cts_variant."""

    __slots__ = ("raw", "sh", "_mechs")

    def __init__(self, raw: Any, sh: int, mechanism_names: frozenset[str]) -> None:
        self.raw = raw
        self.sh = sh
        self._mechs = mechanism_names

    def has_mechanism(self, name: str) -> bool:
        return name in self._mechs or f"CKM_{name}" in self._mechs


def _detect_variant_via_pkcs11(config: pytest.Config) -> _CtsDetectionResult:
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
    from pkcs11_check.raw.recipes import get_mechanism_info, get_mechanism_list
    from pkcs11_check.raw.types_std import (
        CKF_DECRYPT,
        CKF_ENCRYPT,
        CKF_RW_SESSION,
        CKF_SERIAL_SESSION,
        CKM_AES_CTS,
        CKU_USER,
    )
    from pkcs11_check.testcases.acvp.aes.base_cts import get_cts_detection

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
        return _CtsDetectionResult(_CtsDetectionStatus.ABSENT)

    # Metadata is the capability boundary.  Do not open a session or touch
    # key/crypto operations when the advertised CTS mechanism does not claim
    # both directions required by this test file.
    info = get_mechanism_info(raw, slot_id, CKM_AES_CTS)
    required_flags = int(CKF_ENCRYPT) | int(CKF_DECRYPT)
    if int(info["flags"]) & required_flags != required_flags:
        return _CtsDetectionResult(
            _CtsDetectionStatus.SETUP_UNAVAILABLE,
            detail={
                "reason": "CKM_AES_CTS does not advertise CKF_ENCRYPT|CKF_DECRYPT",
                "stage": "metadata",
                "operation": "C_GetMechanismInfo",
                "key_bits": None,
                "case": None,
                "ckr": None,
            },
        )

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    sh = raw_open_session(raw, slot_id, flags)
    logged_in = False
    try:
        if pin is not None:
            login_user(raw, sh, CKU_USER, pin.encode("utf-8"))
            logged_in = True

        rs = _MinimalSession(raw, sh, frozenset(names))
        # Use the structured process cache so the selected sentinel/vector
        # runtime guard reuses this collection result instead of touching the
        # provider a second time.
        return get_cts_detection(rs)
    finally:
        if logged_in:
            logout_quietly(raw, sh)
        close_session_quietly(raw, sh)

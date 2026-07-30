"""Unit tests for slot-index resolution shared by the fixtures and the probe harness.

``config.slot`` (``--slot``) is a slot *index* into the present-token slot list, not a raw
slot ID. Both the session fixtures (fixtures.py) and the probe harness (session.probe_main)
must resolve it the same way -- a past divergence (the probe using the index as a raw ID) made
the whole security/boundary probe suite crash with CKR_SLOT_ID_INVALID on dynamic-slot modules.
"""

from __future__ import annotations

from pkcs11_check.raw.bootstrap import resolve_slot_id


def test_index_maps_to_the_slot_id_at_that_position() -> None:
    # Dynamic slot IDs where index != id -- the case that used to break.
    assert resolve_slot_id([0x3F8A, 0x1C2D, 0x77E0], 0) == 0x3F8A
    assert resolve_slot_id([0x3F8A, 0x1C2D, 0x77E0], 1) == 0x1C2D
    assert resolve_slot_id([0x3F8A, 0x1C2D, 0x77E0], 2) == 0x77E0


def test_none_index_means_first_slot() -> None:
    assert resolve_slot_id([500, 600], None) == 500


def test_out_of_range_index_falls_back_to_first_slot() -> None:
    # Mirrors fixtures.py: slots[idx] if idx < len(slots) else slots[0].
    assert resolve_slot_id([500, 600], 9) == 500


def test_single_slot_any_index_resolves_to_it() -> None:
    assert resolve_slot_id([42], 0) == 42
    assert resolve_slot_id([42], 1) == 42


def test_negative_index_clamps_to_first_slot_not_python_negative_indexing() -> None:
    # A negative config.slot must NOT silently select the last slot (Python's slots[-1]); it is
    # out of range, so it clamps to the first present-token slot like any other out-of-range idx.
    assert resolve_slot_id([500, 600, 700], -1) == 500
    assert resolve_slot_id([500, 600, 700], -99) == 500


def test_empty_slot_list_raises_a_clear_error_not_indexerror() -> None:
    import pytest

    with pytest.raises(ValueError, match="present-token slot"):
        resolve_slot_id([], 0)


def _calls_resolve_slot_id(module_path) -> bool:
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(module_path).read_text(encoding="utf-8"))
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "resolve_slot_id"
        for n in ast.walk(tree)
    )


def test_fixture_and_probe_harness_share_the_slot_resolver() -> None:
    # The bug was a divergence: the session fixtures resolved config.slot as an index while the
    # probe harness used it as a raw id, so probes crashed with CKR_SLOT_ID_INVALID on
    # dynamic-slot modules. Guard the DRY invariant -- BOTH must route through resolve_slot_id
    # -- so a probe can never again pass the raw index to C_OpenSession.
    import pkcs11_check.fixtures as fx
    import pkcs11_check.testcases._probes.session as probe

    assert _calls_resolve_slot_id(fx.__file__), (
        "pkcs11_check.fixtures must resolve config.slot via resolve_slot_id"
    )
    assert _calls_resolve_slot_id(probe.__file__), (
        "the probe harness (session.probe_main) must resolve config.slot via resolve_slot_id, "
        "not pass the raw index to C_OpenSession"
    )

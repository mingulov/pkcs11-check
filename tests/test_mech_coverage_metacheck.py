"""Meta-test: the coverage check notes advertised-but-unregistered mechanisms."""

from __future__ import annotations

import pytest

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.types_std import CKF_DECRYPT, CKF_SIGN
from pkcs11_check.testcases import test_mech_coverage as cov
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog, MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig


def _notes_spy(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, ComplianceLevel, str, str]]:
    """Capture (description, level, test_id, reference) tuples from compliance.note calls."""
    captured: list[tuple[str, ComplianceLevel, str, str]] = []

    def fake_note(
        description: str,
        level: ComplianceLevel,
        reference: str = "",
        *,
        test_id: str = "",
    ) -> None:
        captured.append((description, level, test_id, reference))

    monkeypatch.setattr(cov.compliance, "note", fake_note)
    return captured


def _make_unregistered_catalog(
    mech_id: int = 0x00001081,
    mech_name: str = "CKM_AES_ECB",
    *,
    flags: int | None = None,
) -> MechanismCatalog:
    """Return a catalog with one unregistered (config=None) entry."""
    actual_flags = flags if flags is not None else int(CKF_SIGN)
    return MechanismCatalog(
        {
            mech_id: MechEntry(
                mech_id=mech_id,
                mech_name=mech_name,
                flags=actual_flags,
                min_key_size=0,
                max_key_size=0,
                config=None,
            )
        }
    )


def test_unregistered_entries_produce_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    """One unregistered mechanism must produce exactly one per-mechanism note + one summary note."""
    captured = _notes_spy(monkeypatch)
    catalog = _make_unregistered_catalog()
    cov._note_registry_blind_spots(catalog)
    # One per-mechanism note + one summary note
    assert len(captured) == 2
    descriptions = [d for d, _l, _t, _r in captured]
    assert any("CKM_AES_ECB" in d for d in descriptions)
    assert any("no registry config" in d for d in descriptions)
    assert any("1 advertised mechanism" in d for d in descriptions)
    level_vals = [lv for _d, lv, _t, _r in captured]
    assert all(lv is ComplianceLevel.STANDARD for lv in level_vals)


def test_registered_entries_produce_no_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mechanism with a registry config must NOT produce any note."""
    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x00001087: MechEntry(
                mech_id=0x00001087,
                mech_name="CKM_AES_GCM",
                flags=int(CKF_DECRYPT),
                min_key_size=16,
                max_key_size=32,
                config=MechConfig(),
            )
        }
    )
    cov._note_registry_blind_spots(catalog)
    assert captured == []


def test_multiple_unregistered_produce_one_note_each(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x00001081: MechEntry(
                mech_id=0x00001081,
                mech_name="CKM_AES_ECB",
                flags=int(CKF_SIGN),
                min_key_size=0,
                max_key_size=0,
                config=None,
            ),
            0x00001087: MechEntry(
                mech_id=0x00001087,
                mech_name="CKM_AES_GCM",
                flags=int(CKF_DECRYPT),
                min_key_size=0,
                max_key_size=0,
                config=None,
            ),
        }
    )
    cov._note_registry_blind_spots(catalog)
    # 2 per-mechanism notes + 1 summary note
    assert len(captured) == 3
    descriptions = [d for d, _l, _t, _r in captured]
    assert any("CKM_AES_ECB" in d for d in descriptions)
    assert any("CKM_AES_GCM" in d for d in descriptions)
    assert any("2 advertised mechanisms" in d for d in descriptions)


def test_note_contains_hex_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Note must include the mechanism's hex ID."""
    captured = _notes_spy(monkeypatch)
    catalog = _make_unregistered_catalog(mech_id=0x00001081, mech_name="CKM_AES_ECB")
    cov._note_registry_blind_spots(catalog)
    descriptions = [d for d, _l, _t, _r in captured]
    assert any("0x00001081" in d for d in descriptions)


def test_harness_blind_spot_not_module_deviation_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """Note must state this is a harness blind spot, not a module deviation."""
    captured = _notes_spy(monkeypatch)
    catalog = _make_unregistered_catalog()
    cov._note_registry_blind_spots(catalog)
    per_mech = [d for d, _l, _t, _r in captured if "no registry config" in d]
    assert per_mech, "expected at least one per-mechanism note"
    assert any("harness blind spot" in d for d in per_mech)
    assert any("not a module deviation" in d for d in per_mech)


def test_note_reference_is_gap_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-mechanism blind-spot notes must carry the gap-analysis reference."""
    captured = _notes_spy(monkeypatch)
    catalog = _make_unregistered_catalog()
    cov._note_registry_blind_spots(catalog)
    per_mech = [(d, r) for d, _l, _t, r in captured if "no registry config" in d]
    assert per_mech, "expected at least one per-mechanism note"
    for _desc, ref in per_mech:
        assert ref == "docs/findings/advertised-not-operational-gap-analysis.md Q2"


def test_note_test_id_is_enclosing_test_qualname(monkeypatch: pytest.MonkeyPatch) -> None:
    """compliance.note must be called with test_id = the enclosing test's qualname.

    _note_registry_blind_spots is a helper; the compliance note must attribute to
    the test that calls it, not to the helper itself (Fix 1 from code review).
    """
    captured = _notes_spy(monkeypatch)
    catalog = _make_unregistered_catalog()
    cov._note_registry_blind_spots(catalog)
    per_mech = [(d, t) for d, _l, t, _r in captured if "no registry config" in d]
    assert per_mech, "expected at least one per-mechanism note"
    for _desc, test_id in per_mech:
        # Must NOT attribute to the helper
        assert test_id != "_note_registry_blind_spots", (
            f"test_id must not be the helper name; got {test_id!r}"
        )
        # Must attribute to the enclosing test (this function's qualname)
        assert test_id == "test_note_test_id_is_enclosing_test_qualname", (
            f"Expected enclosing test qualname, got {test_id!r}"
        )

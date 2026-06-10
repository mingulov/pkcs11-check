"""Meta-test: the coverage check notes advertised-but-unregistered mechanisms."""

from __future__ import annotations

import pytest

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.testcases import test_mech_coverage as cov
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog, MechEntry


def _notes_spy(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, ComplianceLevel, str]]:
    """Capture (description, level, test_id) tuples from compliance.note calls."""
    captured: list[tuple[str, ComplianceLevel, str]] = []

    def fake_note(
        description: str,
        level: ComplianceLevel,
        reference: str = "",
        *,
        test_id: str = "",
    ) -> None:
        captured.append((description, level, test_id))

    monkeypatch.setattr(cov.compliance, "note", fake_note)
    return captured


def test_unregistered_entries_produce_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x80000001: MechEntry(
                mech_id=0x80000001,
                mech_name="CKM_VENDOR_THING",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            )
        }
    )
    cov._note_registry_blind_spots(catalog)
    assert len(captured) == 1
    description, level, _test_id = captured[0]
    assert "CKM_VENDOR_THING" in description
    assert "no registry config" in description
    assert level is ComplianceLevel.STANDARD


def test_registered_entries_produce_no_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mechanism with a registry config must NOT produce any note."""
    from pkcs11_check.testcases.mechanism_registry import MechConfig

    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x00000001: MechEntry(
                mech_id=0x00000001,
                mech_name="CKM_RSA_PKCS",
                flags=0x200,
                min_key_size=512,
                max_key_size=4096,
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
            0x80000001: MechEntry(
                mech_id=0x80000001,
                mech_name="CKM_VENDOR_A",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            ),
            0x80000002: MechEntry(
                mech_id=0x80000002,
                mech_name="CKM_VENDOR_B",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            ),
        }
    )
    count = cov._note_registry_blind_spots(catalog)
    assert count == 2
    assert len(captured) == 2
    names = {d for d, _l, _t in captured}
    assert any("CKM_VENDOR_A" in n for n in names)
    assert any("CKM_VENDOR_B" in n for n in names)


def test_note_contains_hex_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Note must include the mechanism's hex ID."""
    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x80000001: MechEntry(
                mech_id=0x80000001,
                mech_name="CKM_VENDOR_THING",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            )
        }
    )
    cov._note_registry_blind_spots(catalog)
    description, _level, _test_id = captured[0]
    assert "0x80000001" in description


def test_harness_blind_spot_not_module_deviation_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """Note must state this is a harness blind spot, not a module deviation."""
    captured = _notes_spy(monkeypatch)
    catalog = MechanismCatalog(
        {
            0x80000001: MechEntry(
                mech_id=0x80000001,
                mech_name="CKM_VENDOR_THING",
                flags=0x800,
                min_key_size=0,
                max_key_size=0,
                config=None,
            )
        }
    )
    cov._note_registry_blind_spots(catalog)
    description, _level, _test_id = captured[0]
    assert "harness blind spot" in description
    assert "not a module deviation" in description

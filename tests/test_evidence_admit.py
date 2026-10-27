"""Admission predicates + obligation inventory (Task E2)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from pkcs11_check.core.evidence.admit import (
    EMPTY_SHARD_SHA256,
    PredeclaredRoster,
    ShardExpectation,
    admit_lane,
    row_blob,
    shard_digest,
)
from pkcs11_check.core.evidence.obligations import (
    ObligationInventory,
    compile_obligations,
)
from pkcs11_check.core.evidence.schema import (
    LEDGER_SCHEMA_VERSION,
    LedgerHeader,
    LedgerRow,
    Outcome,
    zero_counters,
)


def _row(
    node_id: str = "tests/a.py::t",
    phase: str = "call",
    attempt: int = 1,
    attempts_total: int = 1,
    shard_id: str = "s0",
    outcome: Outcome = Outcome.PASSED,
) -> LedgerRow:
    return LedgerRow(
        node_id=node_id,
        phase=phase,
        attempt=attempt,
        attempts_total=attempts_total,
        shard_id=shard_id,
        outcome=outcome,
        duration_ms=1,
        reason="",
        class_reason="",
        category="",
        ckr_expected="",
        ckr_actual="",
        mechanism="",
        stimulus_rev="",
        oracle_rev="",
        reach="",
        effect="",
        cleanup="",
        termination="",
        flags=[],
    )


def _header(rows: list[LedgerRow]) -> LedgerHeader:
    counters = zero_counters()
    for row in rows:
        counters[row.outcome.value] += 1
    return LedgerHeader(
        schema_v=LEDGER_SCHEMA_VERSION,
        lane="soft",
        lane_os="linux",
        lane_arch="x86_64",
        framework_sha="f" * 40,
        p11lab_sha="p" * 40,
        image_digest="img",
        corpus_hash="c",
        disabled_hash="d",
        planned_collection_hash="p",
        planned_count=len(rows),
        raw_stream_bytes=0,
        raw_stream_sha256="r",
        malformed_lines=0,
        counters=counters,
        created_by="test",
    )


def _roster(rows: list[LedgerRow]) -> PredeclaredRoster:
    groups: dict[str, list[LedgerRow]] = {}
    for row in rows:
        groups.setdefault(row.shard_id, []).append(row)
    return PredeclaredRoster(
        lane="soft",
        shards={
            shard_id: ShardExpectation(records=len(members), sha256=shard_digest(members))
            for shard_id, members in groups.items()
        },
    )


def _clean_lane() -> tuple[LedgerHeader, list[LedgerRow], PredeclaredRoster, ObligationInventory]:
    rows = [
        _row("tests/a.py::t1", shard_id="s0"),
        _row("tests/a.py::t2", shard_id="s0"),
        _row("tests/b.py::t3", shard_id="s1", outcome=Outcome.FAILED),
    ]
    return _header(rows), rows, _roster(rows), ObligationInventory(members=frozenset())


def _failed_with(verdict_failures: list[str], predicate: str) -> bool:
    return any(predicate in failure for failure in verdict_failures)


def test_predicate_roster_complete() -> None:
    header, rows, roster, obligations = _clean_lane()
    verdict = admit_lane(header, rows, roster, obligations)
    assert verdict.admitted
    assert verdict.failures == []
    assert verdict.warnings == []

    # Pinned canonicalization edges: empty shard hashes b"", blobs deterministic.
    assert shard_digest([]) == hashlib.sha256(b"").hexdigest()
    assert row_blob(rows[0]) == row_blob(replace(rows[0]))

    # Missing shard: s1 declared but absent (diagnostic names it).
    s0_rows = [row for row in rows if row.shard_id == "s0"]
    verdict = admit_lane(_header(s0_rows), s0_rows, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")
    assert "s1" in " ".join(verdict.failures)

    # Count mismatch: records wrong, digest right.
    expected = roster.shards["s0"]
    bad_shards = dict(roster.shards)
    bad_shards["s0"] = ShardExpectation(records=expected.records + 5, sha256=expected.sha256)
    verdict = admit_lane(header, rows, replace(roster, shards=bad_shards), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")

    # Digest mismatch: records right, sha wrong.
    bad_shards["s0"] = ShardExpectation(records=expected.records, sha256="0" * 64)
    verdict = admit_lane(header, rows, replace(roster, shards=bad_shards), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")

    # Extra shard: rows carry sx the roster never declared.
    extra = [*rows, _row("tests/c.py::t4", shard_id="sx")]
    verdict = admit_lane(_header(extra), extra, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")


def test_predicate_zero_malformed() -> None:
    header, rows, roster, obligations = _clean_lane()
    verdict = admit_lane(replace(header, malformed_lines=1), rows, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "zero_malformed")


def test_predicate_typed_fields() -> None:
    header, rows, roster, obligations = _clean_lane()

    missing_outcome = [replace(rows[0], outcome=None), *rows[1:]]  # type: ignore[arg-type]
    verdict = admit_lane(header, missing_outcome, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "typed_fields")

    mistyped_attempt = [replace(rows[0], attempt="1"), *rows[1:]]  # type: ignore[arg-type]
    verdict = admit_lane(header, mistyped_attempt, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "typed_fields")

    empty_node = [replace(rows[0], node_id=""), *rows[1:]]
    verdict = admit_lane(header, empty_node, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "typed_fields")


def test_predicate_session_framing() -> None:
    header, rows, roster, obligations = _clean_lane()
    bad_counters = dict(header.counters)
    bad_counters["passed"] += 1
    verdict = admit_lane(replace(header, counters=bad_counters), rows, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "session_framing")


def test_predicate_occurrence_preserved() -> None:
    attempts = [_row("tests/a.py::t", attempt=i, attempts_total=3) for i in (1, 2, 3)]
    rows = [*attempts, _row("tests/b.py::t2")]
    obligations = ObligationInventory(members=frozenset())
    verdict = admit_lane(_header(rows), rows, _roster(rows), obligations)
    assert verdict.admitted

    short = [row for row in rows if row.attempt != 3]
    verdict = admit_lane(_header(short), short, _roster(short), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "occurrence_preserved")


def test_predicate_observability_complete() -> None:
    header, rows, roster, obligations = _clean_lane()
    bad_counters = dict(header.counters)
    bad_counters["incomplete"] = 1
    verdict = admit_lane(replace(header, counters=bad_counters), rows, roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "observability_complete")


def test_predicate_provenance_present() -> None:
    header, rows, roster, obligations = _clean_lane()
    verdict = admit_lane(replace(header, framework_sha=""), rows, roster, obligations)
    assert not verdict.admitted
    joined = " ".join(verdict.failures)
    assert "provenance_present" in joined
    assert "framework_sha" in joined


def test_obligation_unselected_surfaces() -> None:
    header, rows, roster, _ = _clean_lane()
    # R32: the selected member must be a present row node_id (it is); "b"
    # stays catalog-only so it surfaces as an unselected_obligation warning.
    inventory = compile_obligations({"tests/a.py::t1": {}, "b": {}}, {"cases": ["tests/a.py::t1"]})
    verdict = admit_lane(header, rows, roster, inventory)
    assert verdict.admitted
    assert any("unselected_obligation" in w and "b" in w for w in verdict.warnings)


def test_obligation_membership() -> None:
    inventory = compile_obligations({"a": {}, "b": {}}, {"cases": ["a"]})
    assert "a" in inventory
    assert "b" not in inventory
    assert inventory.members == frozenset({"a"})
    assert inventory.unselected == frozenset({"b"})
    with pytest.raises(ValueError):
        compile_obligations({"a": {}}, {"cases": ["a", "zzz"]})
    with pytest.raises(ValueError):
        compile_obligations({"a": {}}, {})


def test_roster_rejects_zero_records_at_construction() -> None:
    """R19: a roster shard declaring records=0 is rejected when built."""
    with pytest.raises(ValueError):
        ShardExpectation(records=0, sha256=EMPTY_SHARD_SHA256)
    with pytest.raises(ValueError):
        ShardExpectation(records=-1, sha256=EMPTY_SHARD_SHA256)
    # Control: records >= 1 still builds.
    ShardExpectation(records=1, sha256=EMPTY_SHARD_SHA256)


def test_roster_complete_absent_shard_always_fails() -> None:
    """R19: every roster shard must be present in rows -- no unless-clause."""
    obligations = ObligationInventory(members=frozenset())
    roster = PredeclaredRoster(
        lane="soft",
        shards={"never_arrived": ShardExpectation(records=1, sha256="0" * 64)},
    )
    # Reviewer probe shape: empty rows + absent shard must fail, not admit.
    verdict = admit_lane(_header([]), [], roster, obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")

    # Absent shard alongside otherwise-clean rows must also fail.
    header, rows, clean_roster, _ = _clean_lane()
    shards = dict(clean_roster.shards)
    shards["ghost"] = ShardExpectation(records=2, sha256="1" * 64)
    verdict = admit_lane(header, rows, replace(clean_roster, shards=shards), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "roster_complete")


def test_loader_missing_incomplete_key_fails_closed(tmp_path: Path) -> None:
    """R20: end-to-end -- header counters without `incomplete` fail at load."""
    from pkcs11_check.core.evidence import load_ledger

    header, rows, _, _ = _clean_lane()
    ledger = tmp_path / "ledger.jsonl"
    header_record = header.to_record()
    del header_record["counters"]["incomplete"]
    ledger.write_text(
        "\n".join(
            [
                json.dumps(header_record, sort_keys=True),
                *(json.dumps(row.to_record(), sort_keys=True) for row in rows),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="incomplete"):
        load_ledger(ledger)


def test_loader_full_header_loads_and_admits(tmp_path: Path) -> None:
    """R20 control: a complete header loads and the lane admits."""
    from pkcs11_check.core.evidence import load_ledger

    header, rows, _, obligations = _clean_lane()
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(
        "\n".join(
            [
                json.dumps(header.to_record(), sort_keys=True),
                *(json.dumps(row.to_record(), sort_keys=True) for row in rows),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    loaded_header, loaded_rows = load_ledger(ledger)
    verdict = admit_lane(loaded_header, loaded_rows, _roster(loaded_rows), obligations)
    assert verdict.admitted
    assert verdict.failures == []


def test_shard_digest_golden_fixture() -> None:
    """Independent golden pin of the P11Lab-reused canonicalization.

    Canonical bytes are handwritten below; the digest literal was computed
    with shell ``sha256sum`` over those exact bytes (no trailing newline),
    independently of ``shard_digest``.
    """
    blob_low = b'{"attempt":1,"outcome":"passed"}'
    blob_high = b'{"attempt":2,"outcome":"failed"}'
    row_low = {"outcome": "passed", "attempt": 1}
    row_high = {"outcome": "failed", "attempt": 2}
    assert row_blob(row_low) == blob_low
    assert row_blob(row_high) == blob_high
    # Rows passed in reverse byte order: sorting + b"\\n" join are pinned too.
    assert (
        shard_digest([row_high, row_low])
        == "7fe9e7768bcd63c10328e3d9daf94a351bd4de8cc3566e65609a3e3f40f5edf5"
    )


def test_occurrence_preserved_duplicate_attempts() -> None:
    """Attempts [1, 1, 2] with attempts_total=3 fail occurrence_preserved."""
    rows = [_row("tests/a.py::t", attempt=attempt, attempts_total=3) for attempt in (1, 1, 2)]
    obligations = ObligationInventory(members=frozenset())
    verdict = admit_lane(_header(rows), rows, _roster(rows), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "occurrence_preserved")


def test_occurrence_preserved_off_by_one_attempts() -> None:
    """Attempts [2, 3, 4] with attempts_total=3 fail occurrence_preserved."""
    rows = [_row("tests/a.py::t", attempt=attempt, attempts_total=3) for attempt in (2, 3, 4)]
    obligations = ObligationInventory(members=frozenset())
    verdict = admit_lane(_header(rows), rows, _roster(rows), obligations)
    assert not verdict.admitted
    assert _failed_with(verdict.failures, "occurrence_preserved")


# --- final fix round F2: FF2 obligations_executed (8th predicate, R32) -----------


def test_obligations_executed_absent_member_fails_naming_case() -> None:
    """R32: a profile-selected case with no rows fails admission (fail closed)."""
    header, rows, roster, _ = _clean_lane()
    present = [row.node_id for row in rows]
    inventory = ObligationInventory(members=frozenset([*present, "tests/new.py::ghost"]))
    verdict = admit_lane(header, rows, roster, inventory)
    assert not verdict.admitted
    assert (
        "obligations_executed: selected case 'tests/new.py::ghost' has no rows" in verdict.failures
    )


def test_obligations_executed_all_present_passes() -> None:
    """R32 control: every selected case present as a row node_id admits."""
    header, rows, roster, _ = _clean_lane()
    inventory = ObligationInventory(members=frozenset(row.node_id for row in rows))
    verdict = admit_lane(header, rows, roster, inventory)
    assert verdict.admitted

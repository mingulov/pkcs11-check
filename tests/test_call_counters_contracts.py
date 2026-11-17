"""Task-1 contracts: rc1 characterization pins + forward-RED shape tests (plan v8).

Three suites in one file:

- Schema unit tests pin ``core/counters_schema.py`` (predicates, key-set
  validators, identity-key constructors, uuid allocators, five-bucket
  serializers, receipt union, precedence, completeness). GREEN once the
  foundation lands; the module has zero production callers until Tasks 2-5.
- Characterization tests pin rc1 extraction totals/flags on legacy shapes
  with literal fixtures (no schema dependency, so they prove the foundation
  changed no behavior). GREEN immediately; they MUST stay green through
  Tasks 2-5. They assert totals/flags/process rows/round keys only -- never
  the ``by_bucket`` subtree, which Task 2 reshapes to ``by_module`` -- plus
  golden blocks extended to per-process totals and attribution
  (``total_calls``; ``worker_uuid``/``round``/``shard`` tags absent on
  legacy rows).
- Forward-RED tests (``strict=False`` xfail, one class per owning task)
  assert end-state behavior for new shapes through frozen surfaces only
  (JSONL records through the extractor, plugin builders, the results
  block). Each is RED now (verify with ``--runxfail``) and goes GREEN in
  its owning task without rewriting:

  - Task 2: module-first folding, legacy-to-``""`` normalization,
    conditional module tags, ``worker_uuid`` on records and rows.
  - Task 3: sidecar-partial folding, lost records naming dead processes,
    receipt union without double count, registry-issued identity
    acceptance, ``CounterPersistenceError``.
  - Task 4: preflight-synth folding with role rows, error notes never
    replacing evidence.
  - Task 5: isolation stamps on entries and fallback rows, uniform-5
    emission, C2b suppression only on source association.

  Behavioral machinery without a frozen surface (fencing, sweep, seal,
  K-bound, interruption matrix) is covered by the owning task's own
  Step-1 RED tests, not here.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check._plugin_counters as plugin_counters
from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl
from pkcs11_check.core.call_counters import CALL_COUNTERS_PROPERTY, ISOLATION_ENV
from pkcs11_check.core.merge import merge_shard_dirs

_R1 = "20261115T120000000000Z-p100-a1b2c3d4"
_R2 = "20261115T130000000000Z-p200-e5f6a7b8"

_UUID_A = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
_UUID_B = "00112233445566778899aabbccddeeff"


def _fn_block(calls: int, *, rv: int = 0, name: str = "CKR_OK") -> dict[str, Any]:
    return {"calls": calls, "by_rv": {str(rv): {"name": name, "count": calls}}}


def _legacy_block(
    total: int, *, bucket: str = "test", fn: str = "C_Sign", rv: int = 0
) -> dict[str, Any]:
    return {
        "total_calls": total,
        "buckets": {bucket: {"calls": total, "by_fn": {fn: _fn_block(total, rv=rv)}}},
    }


def _module_block(module_buckets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_module: dict[str, Any] = {}
    total = 0
    for module, buckets in module_buckets.items():
        calls = sum(block["calls"] for block in buckets.values())
        by_module[module] = {"calls": calls, "buckets": buckets}
        total += calls
    return {"total_calls": total, "by_module": by_module}


def _session_record(
    pid: int,
    block: dict[str, Any] | None = None,
    total: int = 10,
    *,
    isolation: str = "file",
    probes_lost: int = 0,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersReport",
        "pid": pid,
        "isolation": isolation,
        "probes_lost": probes_lost,
    }
    record.update(_legacy_block(total) if block is None else block)
    if extra:
        record.update(extra)
    return record


def _test_entry(
    pid: int,
    block: dict[str, Any] | None = None,
    total: int = 6,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"pid": pid}
    entry.update(_legacy_block(total) if block is None else block)
    if extra:
        entry.update(extra)
    return entry


def _test_report(
    nodeid: str, when: str, entry: dict[str, Any] | None, *, outcome: str = "passed"
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "$report_type": "TestReport",
        "nodeid": nodeid,
        "when": when,
        "outcome": outcome,
        "duration": 0.1,
        "user_properties": [],
    }
    if entry is not None:
        report["user_properties"] = [[CALL_COUNTERS_PROPERTY, entry]]
    return report


def _marker(target: str, attempt: int) -> dict[str, Any]:
    return {"$report_type": "IsolatedUnitReport", "target": target, "attempt": attempt}


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def _stable_view(block: dict[str, Any]) -> dict[str, Any]:
    """The Task-2-stable projection of a results block (golden comparison).

    Drops the counter trees (``by_bucket`` today, ``by_module`` from Task 2)
    at the top level and in every per-round block; everything else --
    totals, flags, process rows, round keys -- must stay identical through
    Tasks 2-5.
    """
    view = {key: value for key, value in block.items() if key not in {"by_bucket", "by_module"}}
    view["by_round"] = {
        run: {k: v for k, v in payload.items() if k not in {"by_bucket", "by_module"}}
        for run, payload in block["by_round"].items()
    }
    return view


def _find_future(candidates: list[tuple[str, str]], owner: str) -> Any:
    """Import the first existing ``(module, attr)`` candidate or fail RED.

    ADAPTABLE probe: the owning task keeps the normative assertions and
    adjusts this candidate list to its implementation if the name lands
    elsewhere than guessed here.
    """
    for module_name, attr in candidates:
        try:
            return getattr(importlib.import_module(module_name), attr)
        except (ImportError, AttributeError):
            continue
    names = ", ".join(f"{module}.{attr}" for module, attr in candidates)
    pytest.fail(f"none of {names} implemented yet ({owner})")


# --------------------------------------------------------------------------
# Schema unit tests (Task 1 foundation)
# --------------------------------------------------------------------------


class TestSchemaConstants:
    def test_buckets_five_exact(self) -> None:
        assert schema.BUCKETS_5 == (
            "test",
            "setup_teardown",
            "session_provisioning",
            "module_init",
            "preflight",
        )
        assert schema.BUCKETS_RC1 == schema.BUCKETS_5[:4]
        assert call_counters.BUCKETS == schema.BUCKETS_RC1

    def test_end_states_exact(self) -> None:
        assert schema.END_STATES == frozenset(
            {"crashed", "timeout", "killed", "unknown", "unresolved", "conflict"}
        )

    def test_roles_and_module_sentinel(self) -> None:
        assert schema.PROCESS_ROLES == ("unit", "retry", "confirmation", "preflight")
        assert schema.DEFAULT_ROLE == "unit"
        assert schema.UNKNOWN_MODULE == ""

    def test_wire_names(self) -> None:
        assert schema.SESSION_REPORT_TYPE == "CallCountersReport"
        assert schema.TEST_ENTRY_PROPERTY == "pkcs11_call_counters"
        assert schema.PARTIAL_REPORT_TYPE == "CallCountersPartial"
        assert schema.LOST_REPORT_TYPE == "CallCountersLost"
        assert schema.REGISTRY_DIRNAME == "registrations"
        assert schema.PROBE_STATUSES == frozenset({"folded", "lost"})


class TestShapePredicates:
    def test_module_first_accepts_sparse_and_full(self) -> None:
        sparse = _module_block({"modA": _legacy_block(6)["buckets"]})
        assert schema.is_module_first_block(sparse) is True
        full = _module_block(
            {
                "modA": _legacy_block(6, bucket="test")["buckets"],
                "modB": _legacy_block(4, bucket="setup_teardown", fn="C_Login")["buckets"],
            }
        )
        assert full["total_calls"] == 10
        assert schema.is_module_first_block(full) is True
        assert schema.is_module_first_block({"total_calls": 0, "by_module": {}}) is True

    def test_module_first_rejects_mixed_and_broken(self) -> None:
        good = _module_block({"modA": _legacy_block(6)["buckets"]})
        both = dict(good)
        both["buckets"] = {}
        assert schema.is_module_first_block(both) is False
        assert schema.is_module_first_block({"total_calls": 6}) is False
        wrong_total = json.loads(json.dumps(good))
        wrong_total["total_calls"] = 99
        assert schema.is_module_first_block(wrong_total) is False
        assert schema.is_module_first_block({"total_calls": 0, "by_module": {"m": {}}}) is False
        assert schema.is_module_first_block(None) is False
        assert schema.is_module_first_block([]) is False

    def test_module_first_rejects_inner_violations(self) -> None:
        bad_bucket = _module_block({"m": {"nope": {"calls": 1, "by_fn": {}}}})
        assert schema.is_module_first_block(bad_bucket) is False
        mismatch = _module_block({"m": _legacy_block(6)["buckets"]})
        mismatch["by_module"]["m"]["calls"] = 99
        assert schema.is_module_first_block(mismatch) is False
        hex_rv = _module_block({"m": _legacy_block(6)["buckets"]})
        fn_block = hex_rv["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Sign"]
        fn_block["by_rv"] = {"0x0": {"name": "CKR_OK", "count": 6}}
        assert schema.is_module_first_block(hex_rv) is False
        exceeds = _module_block({"m": _legacy_block(6)["buckets"]})
        fn_block = exceeds["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Sign"]
        fn_block["by_rv"]["0"]["count"] = 99
        assert schema.is_module_first_block(exceeds) is False

    def test_legacy_accepts_sparse_rc1(self) -> None:
        assert schema.is_legacy_buckets_block(_legacy_block(10)) is True
        assert schema.is_legacy_buckets_block({"total_calls": 0, "buckets": {}}) is True
        assert schema.is_legacy_buckets_block(_module_block({"m": {}})) is False

    def test_legacy_rejects_preflight_and_violations(self) -> None:
        preflight_first = _legacy_block(4, bucket="preflight")
        assert schema.is_legacy_buckets_block(preflight_first) is False
        assert schema.is_module_first_block(preflight_first) is False
        unknown = _legacy_block(4)
        unknown["buckets"] = {"nope": {"calls": 4, "by_fn": {}}}
        assert schema.is_legacy_buckets_block(unknown) is False
        mismatch = _legacy_block(4)
        mismatch["total_calls"] = 99
        assert schema.is_legacy_buckets_block(mismatch) is False
        boolean = _legacy_block(4)
        boolean["total_calls"] = True  # type: ignore[dict-item]
        assert schema.is_legacy_buckets_block(boolean) is False

    def test_session_record_accepts_both_shapes_and_optionals(self) -> None:
        assert schema.is_session_record(_session_record(100, total=10)) is True
        module_first = _session_record(
            100,
            _module_block({"modA": _legacy_block(6)["buckets"]}),
            extra={
                "run_id": _R1,
                "worker_uuid": _UUID_A,
                "role": "retry",
                "receipts": [{"worker_uuid": _UUID_A, "probe_seq": 0}],
            },
        )
        assert schema.is_session_record(module_first) is True

    def test_session_record_rejects(self) -> None:
        missing_lost = _session_record(100, total=10)
        del missing_lost["probes_lost"]
        assert schema.is_session_record(missing_lost) is False
        bad_pid = _session_record(True, total=10)  # type: ignore[arg-type]
        assert schema.is_session_record(bad_pid) is False
        unknown_key = _session_record(100, total=10, extra={"pin": "nope"})
        assert schema.is_session_record(unknown_key) is False
        bad_receipts = _session_record(100, total=10, extra={"receipts": [{"nope": 1}]})
        assert schema.is_session_record(bad_receipts) is False
        bad_role = _session_record(100, total=10, extra={"role": "janitor"})
        assert schema.is_session_record(bad_role) is False
        bad_uuid = _session_record(100, total=10, extra={"worker_uuid": "xyz"})
        assert schema.is_session_record(bad_uuid) is False
        empty_run = _session_record(100, total=10, extra={"run_id": ""})
        assert schema.is_session_record(empty_run) is False

    def test_test_entry_accepts_and_rejects(self) -> None:
        assert schema.is_test_entry(_test_entry(100, total=6)) is True
        stamped = _test_entry(
            100,
            _module_block({"m": _legacy_block(6)["buckets"]}),
            extra={"run_id": _R1, "worker_uuid": _UUID_A, "isolation": "file", "receipts": []},
        )
        assert schema.is_test_entry(stamped) is True
        assert schema.is_test_entry({"total_calls": 6, "buckets": {}}) is False
        unknown_key = _test_entry(100, total=6, extra={"password": "x"})
        assert schema.is_test_entry(unknown_key) is False

    def _partial(self, **overrides: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "$report_type": "CallCountersPartial",
            "worker_uuid": _UUID_A,
            "truncated": True,
            "run_id": _R1,
            "unit": "a.py",
            "attempt": 0,
            "pid": 100,
            "receipts": [{"worker_uuid": _UUID_A, "probe_seq": 1}],
        }
        record.update(_module_block({"m": _legacy_block(5)["buckets"]}))
        record.update(overrides)
        return record

    def test_sidecar_partial_accepts_and_rejects(self) -> None:
        assert schema.is_sidecar_partial(self._partial()) is True
        minimal = self._partial()
        for key in ("run_id", "unit", "attempt", "pid", "receipts"):
            del minimal[key]
        assert schema.is_sidecar_partial(minimal) is True
        assert schema.is_sidecar_partial(self._partial(truncated=False)) is False
        no_uuid = self._partial()
        del no_uuid["worker_uuid"]
        assert schema.is_sidecar_partial(no_uuid) is False
        bad_counts = self._partial(total_calls=99)
        assert schema.is_sidecar_partial(bad_counts) is False
        assert schema.is_sidecar_partial(self._partial(params={})) is False
        # I3: dead-preflight partials carry their attribution (role +
        # isolation); the role is fail-closed, isolation str-validated.
        attributed = self._partial(role="preflight", isolation="none")
        assert schema.is_sidecar_partial(attributed) is True
        assert schema.is_sidecar_partial(self._partial(role="janitor")) is False
        assert schema.is_sidecar_partial(self._partial(role=None)) is False
        assert schema.is_sidecar_partial(self._partial(isolation=5)) is False

    def test_preflight_synth_accepts_only_preflight_content(self) -> None:
        sparse = _session_record(
            100,
            _module_block({"m": _legacy_block(85, bucket="preflight")["buckets"]}),
            extra={"role": "preflight"},
        )
        assert schema.is_preflight_synth_record(sparse) is True
        uniform = _session_record(
            100,
            {
                "total_calls": 85,
                "by_module": {
                    "m": {
                        "calls": 85,
                        "buckets": {
                            **{b: {"calls": 0, "by_fn": {}} for b in schema.BUCKETS_RC1},
                            "preflight": _legacy_block(85, bucket="preflight")["buckets"][
                                "preflight"
                            ],
                        },
                    }
                },
            },
            extra={"role": "preflight"},
        )
        assert schema.is_preflight_synth_record(uniform) is True
        assert schema.is_session_record(uniform) is True

    def test_preflight_synth_rejects(self) -> None:
        no_role = _session_record(
            100, _module_block({"m": _legacy_block(85, bucket="preflight")["buckets"]})
        )
        assert schema.is_preflight_synth_record(no_role) is False
        mixed = _session_record(
            100,
            _module_block(
                {
                    "m": {
                        "test": {"calls": 1, "by_fn": {"C_X": _fn_block(1)}},
                        "preflight": _legacy_block(85, bucket="preflight")["buckets"]["preflight"],
                    }
                }
            ),
            extra={"role": "preflight"},
        )
        assert schema.is_preflight_synth_record(mixed) is False
        legacy = _session_record(100, total=10, extra={"role": "preflight"})
        assert schema.is_preflight_synth_record(legacy) is False

    def _lost(self, **overrides: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "$report_type": "CallCountersLost",
            "end_state": "crashed",
            "scope_index": 1,
            "worker_uuid": _UUID_A,
            "pid": 100,
            "run_id": _R1,
            "unit": "a.py",
            "attempt": 0,
            "origin_shard": "",
        }
        record.update(overrides)
        return record

    def test_lost_record_accepts_and_rejects(self) -> None:
        assert schema.is_lost_record(self._lost()) is True
        uuid_only = self._lost()
        del uuid_only["pid"]
        assert schema.is_lost_record(uuid_only) is True
        pid_only = self._lost()
        del pid_only["worker_uuid"]
        assert schema.is_lost_record(pid_only) is True
        anonymous = self._lost()
        del anonymous["worker_uuid"]
        del anonymous["pid"]
        assert schema.is_lost_record(anonymous) is False
        assert schema.is_lost_record(self._lost(end_state="vaporized")) is False
        assert schema.is_lost_record(self._lost(scope_index=-1)) is False
        assert schema.is_lost_record(self._lost(scope_index=True)) is False
        assert schema.is_lost_record(self._lost(total_calls=0)) is False
        assert schema.is_lost_record(self._lost(buckets={})) is False
        assert schema.is_lost_record(self._lost(by_module={})) is False
        assert schema.is_lost_record(self._lost(probes_lost=0)) is False

    def _registry(self, **overrides: Any) -> dict[str, Any]:
        content: dict[str, Any] = {
            "worker_uuid": _UUID_A,
            "run_id": _R1,
            "unit": "a.py",
            "attempt": 0,
            "pid": 100,
            "role": "unit",
            "timestamp": 1799999999.5,
            "sidecar": "counters/a1b2c3d4.json",
            "birth_token": 123456,
            "isolation": "file",
        }
        content.update(overrides)
        return content

    def test_registry_content_accepts_and_rejects(self) -> None:
        assert schema.is_registry_content(self._registry()) is True
        for key in (
            "worker_uuid",
            "run_id",
            "unit",
            "attempt",
            "pid",
            "role",
            "timestamp",
            "sidecar",
            "birth_token",
            "isolation",
        ):
            missing = self._registry()
            del missing[key]
            assert schema.is_registry_content(missing) is False, key
        assert schema.is_registry_content(self._registry(role="janitor")) is False
        assert schema.is_registry_content(self._registry(birth_token=True)) is False
        assert schema.is_registry_content(self._registry(birth_token=-1)) is False
        assert schema.is_registry_content(self._registry(timestamp=False)) is False
        assert schema.is_registry_content(self._registry(sidecar="")) is False
        assert schema.is_registry_content(self._registry(unit="")) is False
        assert schema.is_registry_content(self._registry(isolation="")) is False
        assert schema.is_registry_content(self._registry(isolation=None)) is False
        assert schema.is_registry_content(self._registry(extra_key=1)) is False

    def test_process_row_accepts_legacy_and_full(self) -> None:
        legacy = {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
        assert schema.is_process_row(legacy) is True
        full = {
            **legacy,
            "worker_uuid": _UUID_A,
            "module": "modA",
            "role": "preflight",
            "truncated": True,
            "end_state": "timeout",
            "round": _R1,
            "shard": "shard0",
        }
        assert schema.is_process_row(full) is True

    def test_process_row_rejects(self) -> None:
        base = {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
        missing = dict(base)
        del missing["complete"]
        assert schema.is_process_row(missing) is False
        assert schema.is_process_row({**base, "complete": 1}) is False
        assert schema.is_process_row({**base, "worker_uuid": "xyz"}) is False
        assert schema.is_process_row({**base, "end_state": "vaporized"}) is False
        assert schema.is_process_row({**base, "round": ""}) is False
        assert schema.is_process_row({**base, "mystery": 1}) is False

    def test_scalar_predicates(self) -> None:
        assert schema.is_worker_uuid(_UUID_A) is True
        assert schema.is_worker_uuid(_UUID_A.upper()) is False
        assert schema.is_worker_uuid("a1b2c3d4") is False
        assert schema.is_worker_uuid(None) is False
        assert schema.is_birth_token(123456) is True
        assert schema.is_birth_token(0) is True
        assert schema.is_birth_token(True) is False
        assert schema.is_birth_token(-1) is False
        assert schema.is_birth_token("123") is False
        assert schema.is_scope_index(0) is True
        assert schema.is_scope_index(False) is False
        assert schema.is_probe_seq(7) is True
        assert schema.is_probe_seq(-1) is False
        assert schema.is_bucket_name("preflight") is True
        assert schema.is_bucket_name("nope") is False
        assert schema.is_role("retry") is True
        assert schema.is_role("janitor") is False
        assert schema.is_end_state("conflict") is True
        assert schema.is_end_state("vaporized") is False

    def test_receipt_and_probe_detail_predicates(self) -> None:
        receipt = {"worker_uuid": _UUID_A, "probe_seq": 2}
        assert schema.is_receipt(receipt) is True
        assert schema.is_receipt({**receipt, "extra": 0}) is False
        assert schema.is_receipt({"worker_uuid": _UUID_A}) is False
        assert schema.is_receipt({"worker_uuid": "xyz", "probe_seq": 0}) is False
        detail = {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "folded"}
        assert schema.is_probe_detail(detail) is True
        assert schema.is_probe_detail({**detail, "status": "maybe"}) is False
        assert schema.is_probe_detail({"worker_uuid": _UUID_A, "probe_seq": 2}) is False

    def test_secret_free_accepts_counter_shapes(self) -> None:
        block = _module_block({"m": {"test": {"calls": 1, "by_fn": {"C_SetPIN": _fn_block(1)}}}})
        assert schema.is_secret_free(block) is True
        assert schema.is_secret_free(_session_record(100, total=10)) is True
        assert schema.is_secret_free(self._registry()) is True
        assert schema.find_secret_keys(block) == ()

    def test_secret_free_rejects_credentials(self) -> None:
        assert schema.is_secret_free({"pin": "1234"}) is False
        assert schema.is_secret_free({"PIN": "1234"}) is False
        assert schema.is_secret_free({"password": "x"}) is False
        assert schema.is_secret_free({"credentials": []}) is False
        assert schema.is_secret_free({"params": {}}) is False
        assert schema.is_secret_free({"CKA_VALUE": "x"}) is False
        assert schema.is_secret_free({"cka_label": "x"}) is False
        nested = {"buckets": {"test": {"key_bytes": "AA=="}}}
        assert schema.is_secret_free(nested) is False
        assert schema.find_secret_keys(nested) == ("buckets.test.key_bytes",)


class TestKeyValidators:
    def test_violations_empty_on_valid(self) -> None:
        assert (
            schema.key_violations(
                {"a": 1},
                allowed=frozenset({"a", "b"}),
                required=frozenset({"a"}),
            )
            == ()
        )

    def test_violations_report_missing_and_unknown_sorted(self) -> None:
        assert schema.key_violations(
            {"z": 1, "a": 1},
            allowed=frozenset({"a"}),
            required=frozenset({"a", "b", "c"}),
        ) == ("missing:b", "missing:c", "unknown:z")

    def test_violations_reject_non_dict(self) -> None:
        assert schema.key_violations([], allowed=frozenset(), required=frozenset()) == (
            "not-a-dict",
        )


class TestIdentityConstructors:
    def test_sidecar_identity(self) -> None:
        assert schema.sidecar_identity(_R1, "a.py", 0, _UUID_A) == (_R1, "a.py", 0, _UUID_A)
        with pytest.raises(ValueError, match="unit"):
            schema.sidecar_identity(_R1, "", 0, _UUID_A)
        with pytest.raises(ValueError, match="attempt"):
            schema.sidecar_identity(_R1, "a.py", -1, _UUID_A)
        with pytest.raises(ValueError, match="worker_uuid"):
            schema.sidecar_identity(_R1, "a.py", 0, "xyz")

    def test_receipt_key(self) -> None:
        assert schema.receipt_key(_UUID_A, 3) == (_UUID_A, 3)
        with pytest.raises(ValueError, match="probe_seq"):
            schema.receipt_key(_UUID_A, -1)

    def test_session_authority_key(self) -> None:
        assert schema.session_authority_key(_UUID_A) == _UUID_A
        with pytest.raises(ValueError, match="worker_uuid"):
            schema.session_authority_key("xyz")

    def test_test_supersede_key(self) -> None:
        assert schema.test_supersede_key(_UUID_A, "a.py::t1") == (_UUID_A, "a.py::t1")
        with pytest.raises(ValueError, match="nodeid"):
            schema.test_supersede_key(_UUID_A, "")

    def test_source_association(self) -> None:
        assert schema.source_association("", "a.py", 0, _UUID_A) == ("", "a.py", 0, _UUID_A)
        assert schema.source_association("s", "a.py", 1) == ("s", "a.py", 1, None)
        with pytest.raises(ValueError, match="unit"):
            schema.source_association("", "", 0)
        with pytest.raises(ValueError, match="worker_uuid"):
            schema.source_association("", "a.py", 0, "xyz")

    def test_scope_and_merge_keys(self) -> None:
        assert schema.scope_key(1, "a.py", 0) == (1, "a.py", 0)
        with pytest.raises(ValueError, match="scope"):
            schema.scope_key(-1, "a.py", 0)
        assert schema.merge_key("shard0", _R1, _UUID_A) == ("shard0", _R1, _UUID_A)
        with pytest.raises(ValueError, match="shard"):
            schema.merge_key("", _R1, _UUID_A)

    def test_registry_filename_round_trip(self) -> None:
        assert schema.registry_filename(_UUID_A) == f"{_UUID_A}.json"
        assert schema.parse_registry_filename(f"{_UUID_A}.json") == _UUID_A
        assert schema.parse_registry_filename("torn.json") is None
        assert schema.parse_registry_filename(f"{_UUID_A}.tmp") is None
        with pytest.raises(ValueError, match="worker_uuid"):
            schema.registry_filename("xyz")


class TestAllocators:
    def test_mint_formats(self) -> None:
        worker_uuid = schema.mint_worker_uuid()
        assert len(worker_uuid) == 32
        assert all(char in "0123456789abcdef" for char in worker_uuid)
        assert schema.is_worker_uuid(worker_uuid) is True
        nonce = schema.mint_filename_nonce()
        assert len(nonce) == 8
        assert all(char in "0123456789abcdef" for char in nonce)

    def test_mints_unique_and_side_effect_free(self, tmp_path: Path) -> None:
        before = set(tmp_path.iterdir())
        seen = {schema.mint_worker_uuid() for _ in range(25)}
        seen_nonces = {schema.mint_filename_nonce() for _ in range(25)}
        assert len(seen) == 25
        assert len(seen_nonces) == 25
        assert set(tmp_path.iterdir()) == before


class TestSerializers:
    def test_empty_shapes_carry_five_keys(self) -> None:
        buckets = schema.empty_buckets_five()
        assert set(buckets) == set(schema.BUCKETS_5)
        assert all(block == {"calls": 0, "by_fn": {}} for block in buckets.values())
        block = schema.empty_block_five()
        assert block == {"total_calls": 0, "buckets": buckets}
        assert schema.is_uniform_five(buckets) is True
        assert schema.is_uniform_five({"test": {"calls": 0, "by_fn": {}}}) is False

    def test_serialize_counts_five_exact(self) -> None:
        block = schema.serialize_counts_five(
            {
                ("test", "C_Login", 0): 2,
                ("test", "C_Login", 49): 1,
                ("test", "C_Sign", None): 3,
                ("module_init", "C_Initialize", 0): 1,
            },
            resolve_name=lambda rv: "CKR_OK" if rv == 0 else f"0x{rv:X}",
        )
        assert block["total_calls"] == 7
        assert set(block["buckets"]) == set(schema.BUCKETS_5)
        login = block["buckets"]["test"]["by_fn"]["C_Login"]
        assert login["calls"] == 3
        assert login["by_rv"]["0"] == {"name": "CKR_OK", "count": 2}
        assert login["by_rv"]["49"] == {"name": "0x31", "count": 1}
        assert block["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"] == {}
        assert block["buckets"]["preflight"] == {"calls": 0, "by_fn": {}}

    def test_serialize_counts_skips_nonpositive_and_rejects_bad(self) -> None:
        block = schema.serialize_counts_five(
            {("test", "C_Login", 0): 0, ("test", "C_Login", 1): -2},
            resolve_name=lambda rv: "n",
        )
        assert block["total_calls"] == 0
        with pytest.raises(ValueError, match="bucket"):
            schema.serialize_counts_five({("nope", "C_Login", 0): 1}, resolve_name=lambda rv: "n")
        with pytest.raises(ValueError, match="rv"):
            schema.serialize_counts_five({("test", "C_Login", -1): 1}, resolve_name=lambda rv: "n")
        with pytest.raises(ValueError, match="fn"):
            schema.serialize_counts_five({("test", "", 0): 1}, resolve_name=lambda rv: "n")

    def test_ensure_five_buckets_expands_without_aliasing(self) -> None:
        sparse = _legacy_block(4)["buckets"]
        uniform = schema.ensure_five_buckets(sparse)
        assert set(uniform) == set(schema.BUCKETS_5)
        assert uniform["test"]["calls"] == 4
        uniform["test"]["calls"] = 99
        assert sparse["test"]["calls"] == 4

    def test_normalize_legacy_to_unknown_module(self) -> None:
        legacy = _legacy_block(10)
        module_first = schema.normalize_legacy_to_module_first(legacy)
        assert module_first == {
            "total_calls": 10,
            "by_module": {"": {"calls": 10, "buckets": legacy["buckets"]}},
        }
        assert schema.is_module_first_block(module_first) is True
        module_first["by_module"][""]["calls"] = 99
        assert legacy["total_calls"] == 10
        assert schema.normalize_legacy_to_module_first({"total_calls": 1}) is None
        assert schema.normalize_legacy_to_module_first(_legacy_block(1, bucket="nope")) is None

    def test_wrap_and_canonicalize_module_first(self) -> None:
        wrapped = schema.wrap_module_first(
            {
                "modB": _legacy_block(4, bucket="test", fn="C_Zed")["buckets"],
                "modA": _legacy_block(6, bucket="test", fn="C_Login")["buckets"],
            }
        )
        assert wrapped["total_calls"] == 10
        canonical = schema.canonicalize_module_first(wrapped)
        assert list(canonical["by_module"]) == ["modA", "modB"]
        assert list(wrapped["by_module"]) == ["modB", "modA"]
        assert schema.is_module_first_block(canonical) is True
        with pytest.raises(ValueError, match="module-first"):
            schema.canonicalize_module_first(_legacy_block(1))
        with pytest.raises(ValueError, match="module"):
            schema.wrap_module_first({"m": {"test": {"calls": "x"}}})  # type: ignore[dict-item]

    def test_merge_module_first_sums_with_deterministic_names(self) -> None:
        first = _module_block({"m": _legacy_block(2)["buckets"]})
        hex_leaf = _module_block({"m": _legacy_block(3)["buckets"]})
        fn_block = hex_leaf["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Sign"]
        fn_block["by_rv"] = {"0": {"name": "0x0", "count": 3}}
        merged_ab = schema.merge_module_first(
            json.loads(json.dumps(first)), json.loads(json.dumps(hex_leaf))
        )
        merged_ba = schema.merge_module_first(
            json.loads(json.dumps(hex_leaf)), json.loads(json.dumps(first))
        )
        assert merged_ab == merged_ba
        assert merged_ab["total_calls"] == 5
        leaf = merged_ab["by_module"]["m"]["buckets"]["test"]["by_fn"]["C_Sign"]["by_rv"]["0"]
        assert leaf == {"name": "CKR_OK", "count": 5}
        with pytest.raises(ValueError, match="module-first"):
            schema.merge_module_first({"total_calls": 0}, first)  # type: ignore[arg-type]

    def test_union_receipts_dedupes_sorts_and_skips_garbage(self) -> None:
        union = schema.union_receipts(
            [
                {"worker_uuid": _UUID_B, "probe_seq": 1},
                {"worker_uuid": _UUID_A, "probe_seq": 2},
                {"bogus": True},
            ],
            [{"worker_uuid": _UUID_A, "probe_seq": 2}, {"worker_uuid": _UUID_A, "probe_seq": 0}],
        )
        assert union == [
            {"worker_uuid": _UUID_B, "probe_seq": 1},
            {"worker_uuid": _UUID_A, "probe_seq": 0},
            {"worker_uuid": _UUID_A, "probe_seq": 2},
        ]


class TestPrecedenceAndCompleteness:
    def test_precedence_ranks(self) -> None:
        assert schema.contribution_rank("authoritative") == 2
        assert schema.contribution_rank("partial") == 1
        assert schema.contribution_rank("absent") == 0
        assert schema.stronger_contribution("partial", "authoritative") == "authoritative"
        assert schema.stronger_contribution("absent", "partial") == "partial"
        assert schema.stronger_contribution("partial", "partial") == "partial"
        with pytest.raises(ValueError, match="contribution"):
            schema.contribution_rank("rumor")

    def test_effective_group_completeness(self) -> None:
        assert schema.effective_group_complete(True) is True
        assert schema.effective_group_complete(False) is False
        assert schema.effective_group_complete(True, probes_lost=1) is False
        assert schema.effective_group_complete(True, effective_losses=1) is False
        assert schema.effective_group_complete(True, conflicts=1) is False

    def test_all_complete_ands_rounds(self) -> None:
        assert schema.all_complete([True, True]) is True
        assert schema.all_complete([True, False]) is False

    def test_canonicalize_process_row_omits_default_role(self) -> None:
        row = {"pid": 1, "isolation": "file", "total_calls": 1, "complete": True, "role": "unit"}
        assert schema.canonicalize_process_row(row) == {
            "pid": 1,
            "isolation": "file",
            "total_calls": 1,
            "complete": True,
        }
        assert row["role"] == "unit"
        kept = schema.canonicalize_process_row({**row, "role": "retry"})
        assert kept["role"] == "retry"


# --------------------------------------------------------------------------
# Characterization: rc1 extraction totals/flags (GREEN now, GREEN through Tasks 2-5)
# --------------------------------------------------------------------------


class TestCharacterizationRc1:
    def test_session_preferred_over_same_pid_entries(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _test_report("a.py::t1", "teardown", _test_entry(100, total=4)),
                _test_report("a.py::t2", "teardown", _test_entry(100, total=2)),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True
        assert payload["probes_lost"] == 0

    def test_crash_fallback_sums_and_marks_incomplete(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _test_report("a.py::t1", "teardown", _test_entry(100, total=4)),
                _test_report("a.py::t2", "teardown", _test_entry(100, total=2)),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 6
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "unknown", "total_calls": 6, "complete": False}
        ]

    def test_probes_lost_and_retries(self, tmp_path: Path) -> None:
        lost = _write_jsonl(
            tmp_path / "lost.jsonl",
            [
                {"$report_type": "SessionStart"},
                _session_record(100, total=10, probes_lost=1),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(lost)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["probes_lost"] == 1
        assert payload["complete"] is False
        retried = _write_jsonl(
            tmp_path / "retried.jsonl",
            [_marker("a.py", 0), _session_record(100, total=10), _session_record(101, total=7)],
        )
        payload = extract_call_counters_from_jsonl(retried)
        assert payload is not None
        assert payload["total_calls"] == 17
        assert payload["complete"] is True

    def test_c2_and_c2b_emit_unattributed_segments(self, tmp_path: Path) -> None:
        first_test = _write_jsonl(
            tmp_path / "c2.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "setup", None),
            ],
        )
        payload = extract_call_counters_from_jsonl(first_test)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False
        assert payload["by_process"] == []
        assert payload["by_round"] == {}
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]
        first_setup = _write_jsonl(
            tmp_path / "c2b.jsonl", [{"$report_type": "SessionStart"}, _marker("a.py", 0)]
        )
        payload = extract_call_counters_from_jsonl(first_setup)
        assert payload is not None
        assert payload["complete"] is False
        assert payload["total_calls"] == 0

    def test_static_skip_and_old_artifacts_yield_none(self, tmp_path: Path) -> None:
        skip_marker = _marker("a.py", 0)
        skip_marker["reason"] = "missing-provider-capability"
        skip_marker["skipped"] = 3
        skipped = _write_jsonl(
            tmp_path / "skip.jsonl", [{"$report_type": "SessionStart"}, skip_marker]
        )
        assert extract_call_counters_from_jsonl(skipped) is None
        old = _write_jsonl(
            tmp_path / "old.jsonl",
            [
                {"$report_type": "SessionStart"},
                _test_report("a.py::t1", "call", None),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        assert extract_call_counters_from_jsonl(old) is None
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        assert extract_call_counters_from_jsonl(empty) is None

    def test_fail_closed_skips_violating_records(self, tmp_path: Path) -> None:
        unknown_bucket = _session_record(
            100, {"total_calls": 4, "buckets": {"nope": {"calls": 4, "by_fn": {}}}}
        )
        total_mismatch = _session_record(100, total=5)
        total_mismatch["total_calls"] = 99
        bad_props = _test_report("a.py::t9", "teardown", None)
        bad_props["user_properties"] = 1
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [unknown_bucket, total_mismatch, bad_props, _session_record(200, total=7)],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 7
        assert payload["complete"] is True
        assert [row["pid"] for row in payload["by_process"]] == [200]

    def test_rounds_split_with_global_rollup(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10, extra={"run_id": _R1}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(100, total=5, extra={"run_id": _R2}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 15
        assert payload["complete"] is True
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True, "round": _R1},
            {"pid": 100, "isolation": "file", "total_calls": 5, "complete": True, "round": _R2},
        ]
        assert sorted(payload["by_round"]) == [_R1, _R2]
        assert payload["by_round"][_R1]["total_calls"] == 10
        assert payload["by_round"][_R2]["total_calls"] == 5
        assert payload["by_round"][_R1]["by_process"] == [
            {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
        ]

    def test_implicit_round_for_unseeded_records(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert list(payload["by_round"]) == [""]
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
        ]

    def test_legacy_sparse_parses_identical_to_padded(self, tmp_path: Path) -> None:
        """Task-5 no-regression pin: uniform-5 emission must not change legacy parsing."""
        sparse = _write_jsonl(tmp_path / "sparse.jsonl", [_session_record(100, total=10)])
        padded_record = _session_record(100, total=10)
        padded_record["buckets"] = {
            **{bucket: {"calls": 0, "by_fn": {}} for bucket in ("setup_teardown",)},
            **padded_record["buckets"],
        }
        padded = _write_jsonl(tmp_path / "padded.jsonl", [padded_record])
        sparse_payload = extract_call_counters_from_jsonl(sparse)
        padded_payload = extract_call_counters_from_jsonl(padded)
        assert sparse_payload is not None and padded_payload is not None
        assert sparse_payload["total_calls"] == padded_payload["total_calls"] == 10
        assert sparse_payload["complete"] == padded_payload["complete"] is True

    def test_bare_pytest_rows_stay_unknown(self, tmp_path: Path) -> None:
        """Task-5 pin: rows without any stamped isolation stay ``unknown``."""
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _test_report("a.py::t1", "teardown", _test_entry(100, total=6)),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["by_process"] == [
            {"pid": 100, "isolation": "unknown", "total_calls": 6, "complete": False}
        ]

    def test_legacy_rows_carry_no_new_keys(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", _test_entry(100, total=4)),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["by_process"] != []
        for row in payload["by_process"]:
            assert set(row) == {"pid", "isolation", "total_calls", "complete"}
        assert "lost_processes" not in payload
        assert "probes_detail" not in payload
        for payload_round in payload["by_round"].values():
            assert "lost_processes" not in payload_round
            assert "probes_detail" not in payload_round


class TestGoldenBlocks:
    """Golden blocks: exact totals/flags/rows/rounds (counter trees excluded, Task-2-volatile)."""

    def test_golden_single_session(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        row = {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
        assert _stable_view(payload) == {
            "complete": True,
            "total_calls": 10,
            "probes_lost": 0,
            "by_process": [row],
            "by_round": {
                "": {
                    "complete": True,
                    "total_calls": 10,
                    "probes_lost": 0,
                    "by_process": [row],
                }
            },
        }

    def test_golden_crash_fallback(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _test_report("b.py::t1", "teardown", _test_entry(200, total=5)),
                _test_report("b.py::t1", "teardown", _test_entry(200, total=3)),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        row = {"pid": 200, "isolation": "unknown", "total_calls": 8, "complete": False}
        assert _stable_view(payload) == {
            "complete": False,
            "total_calls": 8,
            "probes_lost": 0,
            "by_process": [row],
            "by_round": {
                "": {
                    "complete": False,
                    "total_calls": 8,
                    "probes_lost": 0,
                    "by_process": [row],
                }
            },
        }

    def test_golden_two_rounds(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10, extra={"run_id": _R1}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(100, total=5, extra={"run_id": _R2}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert _stable_view(payload) == {
            "complete": True,
            "total_calls": 15,
            "probes_lost": 0,
            "by_process": [
                {
                    "pid": 100,
                    "isolation": "file",
                    "total_calls": 10,
                    "complete": True,
                    "round": _R1,
                },
                {
                    "pid": 100,
                    "isolation": "file",
                    "total_calls": 5,
                    "complete": True,
                    "round": _R2,
                },
            ],
            "by_round": {
                _R1: {
                    "complete": True,
                    "total_calls": 10,
                    "probes_lost": 0,
                    "by_process": [
                        {"pid": 100, "isolation": "file", "total_calls": 10, "complete": True}
                    ],
                },
                _R2: {
                    "complete": True,
                    "total_calls": 5,
                    "probes_lost": 0,
                    "by_process": [
                        {"pid": 100, "isolation": "file", "total_calls": 5, "complete": True}
                    ],
                },
            },
        }

    def test_golden_merge_two_shards(self, tmp_path: Path) -> None:
        for shard, target, pid, total in (
            ("shard0", "a.py", 100, 10),
            ("shard1", "b.py", 200, 5),
        ):
            shard_dir = tmp_path / shard
            shard_dir.mkdir()
            (shard_dir / "results.json").write_text(
                json.dumps(
                    {
                        "tool": "pkcs11-check",
                        "kind": "test-run",
                        "summary": {"passed": 1, "failed": 0},
                        "units": [{"target": target, "status": "passed"}],
                    }
                ),
                encoding="utf-8",
            )
            _write_jsonl(
                shard_dir / "report.jsonl",
                [
                    {"$report_type": "SessionStart"},
                    _marker(target, 0),
                    _session_record(pid, total=total, isolation="none"),
                    {"$report_type": "SessionFinish", "exitstatus": 0},
                ],
            )
        merged_ab = merge_shard_dirs(
            [tmp_path / "shard0", tmp_path / "shard1"], tmp_path / "merged_ab"
        )
        merged_ba = merge_shard_dirs(
            [tmp_path / "shard1", tmp_path / "shard0"], tmp_path / "merged_ba"
        )
        assert merged_ab["call_counters"] == merged_ba["call_counters"]
        assert json.dumps(merged_ab["call_counters"]) == json.dumps(merged_ba["call_counters"])
        assert _stable_view(merged_ab["call_counters"]) == {
            "complete": True,
            "total_calls": 15,
            "probes_lost": 0,
            "by_process": [
                {
                    "pid": 100,
                    "isolation": "none",
                    "total_calls": 10,
                    "complete": True,
                    "shard": "shard0",
                },
                {
                    "pid": 200,
                    "isolation": "none",
                    "total_calls": 5,
                    "complete": True,
                    "shard": "shard1",
                },
            ],
            "by_round": {
                "shard0/": {
                    "complete": True,
                    "total_calls": 10,
                    "probes_lost": 0,
                    "by_process": [
                        {"pid": 100, "isolation": "none", "total_calls": 10, "complete": True}
                    ],
                },
                "shard1/": {
                    "complete": True,
                    "total_calls": 5,
                    "probes_lost": 0,
                    "by_process": [
                        {"pid": 200, "isolation": "none", "total_calls": 5, "complete": True}
                    ],
                },
            },
        }


# --------------------------------------------------------------------------
# Forward-RED: Task 2 module identity (each goes GREEN in Task 2)
# --------------------------------------------------------------------------


@pytest.mark.xfail(reason="rc2-Task-2: module-first records not emitted or folded", strict=False)
class TestForwardTask2ModuleFirst:
    def test_module_first_session_folds_exactly(self, tmp_path: Path) -> None:
        block = _module_block(
            {
                "modA": _legacy_block(6, bucket="test")["buckets"],
                "modB": _legacy_block(6, bucket="test", fn="C_Login")["buckets"],
            }
        )
        assert schema.is_module_first_block(block) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, block, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 12
        assert payload["complete"] is True
        assert payload["by_module"]["by_module"]["modA"]["calls"] == 6
        assert payload["by_module"]["by_module"]["modB"]["calls"] == 6

    def test_legacy_normalizes_to_unknown_module(self, tmp_path: Path) -> None:
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["by_module"]["by_module"][""]["calls"] == 10
        assert "by_bucket" not in payload

    def test_module_tags_conditional(self, tmp_path: Path) -> None:
        multi = _module_block(
            {
                "modA": _legacy_block(6, bucket="test")["buckets"],
                "modB": _legacy_block(4, bucket="test", fn="C_Login")["buckets"],
            }
        )
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, multi, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        by_module_tag = sorted(row.get("module") for row in payload["by_process"])
        assert by_module_tag == ["modA", "modB"]
        solo = _write_jsonl(
            tmp_path / "solo.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("b.py", 0),
                _session_record(200, total=7),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(solo)
        assert payload is not None
        assert all("module" not in row for row in payload["by_process"])

    def test_worker_uuid_on_records_and_rows(self, tmp_path: Path) -> None:
        record = plugin_counters.build_session_record()
        assert schema.is_worker_uuid(record["worker_uuid"]) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _session_record(100, total=10, extra={"worker_uuid": _UUID_A}),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 10,
                "complete": True,
                "worker_uuid": _UUID_A,
            }
        ]


# --------------------------------------------------------------------------
# Forward-RED: Task 3 durability (each goes GREEN in Task 3)
# --------------------------------------------------------------------------


def _partial_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersPartial",
        "worker_uuid": _UUID_A,
        "truncated": True,
        "run_id": _R1,
        "unit": "a.py",
        "attempt": 0,
        "pid": 100,
    }
    record.update(_module_block({"m": _legacy_block(5)["buckets"]}))
    record.update(overrides)
    return record


def _lost_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "$report_type": "CallCountersLost",
        "end_state": "crashed",
        "scope_index": 1,
        "worker_uuid": _UUID_A,
        "pid": 100,
        "run_id": _R1,
        "unit": "a.py",
        "attempt": 0,
        "origin_shard": "",
    }
    record.update(overrides)
    return record


class TestForwardTask3Durability:
    """Task-3 durability, now wired (was forward-RED; pinned green by Task 3)."""

    def test_partial_counts_fold_truncated(self, tmp_path: Path) -> None:
        assert schema.is_sidecar_partial(_partial_record()) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _partial_record()],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 5
        assert payload["complete"] is False
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "unknown",
                "total_calls": 5,
                "complete": False,
                "worker_uuid": _UUID_A,
                "truncated": True,
            }
        ]
        assert list(payload["by_round"]) == [_R1]

    def test_lost_record_names_dead_process(self, tmp_path: Path) -> None:
        assert schema.is_lost_record(_lost_record()) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _lost_record()],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False
        assert payload["lost_processes"] == [
            {
                "worker_uuid": _UUID_A,
                "pid": 100,
                "end_state": "crashed",
                "scope_index": 1,
                "run_id": _R1,
                "unit": "a.py",
                "attempt": 0,
            }
        ]
        assert payload["by_round"][_R1]["lost_processes"] == payload["lost_processes"]

    def test_receipts_union_without_double_count(self, tmp_path: Path) -> None:
        session = _session_record(
            100,
            _module_block({"m": _legacy_block(10)["buckets"]}),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _R1,
                "receipts": [
                    {"worker_uuid": _UUID_A, "probe_seq": 1},
                    {"worker_uuid": _UUID_A, "probe_seq": 2},
                ],
            },
        )
        entry = _test_entry(
            100,
            _module_block({"m": _legacy_block(4)["buckets"]}),
            extra={
                "worker_uuid": _UUID_A,
                "run_id": _R1,
                "receipts": [
                    {"worker_uuid": _UUID_A, "probe_seq": 2},
                    {"worker_uuid": _UUID_A, "probe_seq": 3},
                ],
            },
        )
        assert schema.is_session_record(session) is True
        assert schema.is_test_entry(entry) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
                session,
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 10
        assert payload["complete"] is True
        assert payload["probes_detail"] == [
            {"worker_uuid": _UUID_A, "probe_seq": 1, "status": "folded"},
            {"worker_uuid": _UUID_A, "probe_seq": 2, "status": "folded"},
            {"worker_uuid": _UUID_A, "probe_seq": 3, "status": "folded"},
        ]

    def test_registry_identity_accepted_malformed_rejected(self, tmp_path: Path) -> None:
        """Registry-issued identities fold end to end; malformed ones fail closed.

        Full registry behavior (torn files, sweep, seal, fencing) is covered
        by Task 3's own Step-1 RED tests; this pins the JSONL-anchored half.
        """
        issued = _lost_record()
        assert schema.is_worker_uuid(issued["worker_uuid"]) is True
        malformed = _lost_record(worker_uuid="not-a-uuid")
        del malformed["pid"]
        assert schema.is_lost_record(malformed) is False
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                issued,
                malformed,
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]

    def test_counter_persistence_error_exists(self) -> None:
        error = _find_future(
            [
                ("pkcs11_check.core.call_counters", "CounterPersistenceError"),
                ("pkcs11_check.core.counters_schema", "CounterPersistenceError"),
                ("pkcs11_check.core.preflight", "CounterPersistenceError"),
            ],
            owner="Task 3 (routing in Task 4)",
        )
        assert issubclass(error, Exception)


# --------------------------------------------------------------------------
# Forward-RED: Task 4 preflight counting (each goes GREEN in Task 4)
# --------------------------------------------------------------------------


def _preflight_synth(**overrides: Any) -> dict[str, Any]:
    record = _session_record(
        300,
        _module_block({"m": _legacy_block(85, bucket="preflight")["buckets"]}),
        isolation="none",
        extra={"role": "preflight", "run_id": _R1, "worker_uuid": _UUID_B},
    )
    record.update(overrides)
    return record


class TestForwardTask4Preflight:
    """Pinned green by Task 4 (preflight synth folding + role rows)."""

    def test_preflight_synth_folds_with_role_row(self, tmp_path: Path) -> None:
        assert schema.is_preflight_synth_record(_preflight_synth()) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _preflight_synth(),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True
        assert payload["by_process"] == [
            {
                "pid": 300,
                "isolation": "none",
                "total_calls": 85,
                "complete": True,
                "worker_uuid": _UUID_B,
                "role": "preflight",
            }
        ]

    def test_error_note_never_replaces_evidence(self, tmp_path: Path) -> None:
        note = {
            "$report_type": "PreflightNote",
            "status": "error",
            "reason": "census-crashed",
            "run_id": _R1,
        }
        bare = _write_jsonl(
            tmp_path / "bare.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), note],
        )
        payload = extract_call_counters_from_jsonl(bare)
        assert payload is not None
        assert payload["total_calls"] == 0
        assert payload["complete"] is False
        assert payload["by_round"] == {}
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]
        retained = _write_jsonl(
            tmp_path / "retained.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                note,
                _preflight_synth(),
                {"$report_type": "SessionFinish", "exitstatus": 0},
            ],
        )
        payload = extract_call_counters_from_jsonl(retained)
        assert payload is not None
        assert payload["total_calls"] == 85
        assert payload["complete"] is True


# --------------------------------------------------------------------------
# Forward-RED: Task 5 structure (each goes GREEN in Task 5)
# --------------------------------------------------------------------------


def _hook_item() -> Any:
    from pkcs11_check._plugin_state import _is_testcase_item

    item: Any = SimpleNamespace(
        path=Path("/repo/src/pkcs11_check/testcases/test_x.py"),
        nodeid="src/pkcs11_check/testcases/test_x.py::test_y",
        stash=pytest.Stash(),
        config=SimpleNamespace(
            getoption=lambda name, default=None: {"p11_module": "/tmp/fake.so"}.get(name, default)
        ),
    )
    assert _is_testcase_item(item)
    return item


def _drive_hook(hook: Any, item: Any, *args: Any, calls: tuple[str, ...] = ()) -> None:
    gen = hook(item, *args)
    next(gen)
    for fn in calls:
        call_counters.record_call(fn)
        call_counters.record_return(fn, 0)
    try:
        gen.send(None)
    except StopIteration:
        return


class TestForwardTask5Structure:
    @pytest.fixture(autouse=True)
    def _clean_counters(self) -> Any:
        call_counters.reset_for_tests()
        yield
        call_counters.reset_for_tests()

    def test_entries_carry_stamped_isolation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ISOLATION_ENV, "file")
        item = _hook_item()
        _drive_hook(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
        _drive_hook(plugin_counters.pytest_runtest_call, item, calls=("C_BodyCall",))
        _drive_hook(plugin_counters.pytest_runtest_teardown, item, None)
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert entry["total_calls"] == 2
        assert entry["isolation"] == "file"
        assert schema.is_test_entry(entry) is True

    def test_fallback_rows_inherit_stamped_isolation(self, tmp_path: Path) -> None:
        entry = _test_entry(100, total=6, extra={"isolation": "file", "run_id": _R1})
        assert schema.is_test_entry(entry) is True
        jsonl = _write_jsonl(
            tmp_path / "report.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _test_report("a.py::t1", "teardown", entry),
            ],
        )
        payload = extract_call_counters_from_jsonl(jsonl)
        assert payload is not None
        assert payload["total_calls"] == 6
        assert payload["by_process"] == [
            {
                "pid": 100,
                "isolation": "file",
                "total_calls": 6,
                "complete": False,
            }
        ]

    def test_emitted_blocks_uniform_five(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ISOLATION_ENV, "file")
        with call_counters.counted_bucket("test"):
            call_counters.record_direct_call("C_Login", 0)
        record = plugin_counters.build_session_record()
        assert schema.is_session_record(record) is True
        for module_block in record["by_module"].values():
            assert set(module_block["buckets"]) == set(schema.BUCKETS_5)
        item = _hook_item()
        _drive_hook(plugin_counters.pytest_runtest_setup, item, calls=("C_SetupCall",))
        _drive_hook(plugin_counters.pytest_runtest_teardown, item, None)
        entry = item.stash[plugin_counters._ENTRY_KEY]
        assert schema.is_test_entry(entry) is True
        for module_block in entry["by_module"].values():
            assert set(module_block["buckets"]) == set(schema.BUCKETS_5)

    def test_c2b_suppressed_only_on_association(self, tmp_path: Path) -> None:
        matched = _write_jsonl(
            tmp_path / "matched.jsonl",
            [{"$report_type": "SessionStart"}, _marker("a.py", 0), _lost_record()],
        )
        payload = extract_call_counters_from_jsonl(matched)
        assert payload is not None
        assert payload["complete"] is False
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]
        assert list(payload["by_round"]) == [_R1]
        decoy = _write_jsonl(
            tmp_path / "decoy.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(unit="other.py", worker_uuid=_UUID_B),
            ],
        )
        payload = extract_call_counters_from_jsonl(decoy)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        assert payload["unattributed_segments"] == [
            {"scope_index": 1, "unit": "a.py", "attempt": 0}
        ]
        prepended = _write_jsonl(
            tmp_path / "prepended.jsonl",
            [_lost_record(), {"$report_type": "SessionStart"}, _marker("a.py", 0)],
        )
        payload = extract_call_counters_from_jsonl(prepended)
        assert payload is not None
        assert list(payload["by_round"]) == [_R1]
        repeated = _write_jsonl(
            tmp_path / "repeated.jsonl",
            [
                {"$report_type": "SessionStart"},
                _marker("a.py", 0),
                _lost_record(),
                _lost_record(),
            ],
        )
        payload = extract_call_counters_from_jsonl(repeated)
        assert payload is not None
        assert [entry["worker_uuid"] for entry in payload["lost_processes"]] == [_UUID_A]

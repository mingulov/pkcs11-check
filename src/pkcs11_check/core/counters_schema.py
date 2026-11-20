"""Frozen counter-evidence contracts for the rc2 counter gaps (Task 1).

Pure foundation: shape predicates, key-set validators, identity-key
constructors, identity allocators, five-bucket serializers, receipt union,
precedence ranks, and completeness combinators. Stdlib only (no imports
from ``pkcs11_check``, so this module cannot create import cycles) and no
I/O -- allocators use ``uuid.uuid4`` randomness only, never the filesystem
or network. ZERO production callers until Tasks 2-5 wire it (verified by
grep, not by test).

Normative companion: ``docs/call-counters-design.md`` ("Normative
contracts (rc2)" section). Later tasks consume this module verbatim; the
forward-RED tests in ``tests/test_call_counters_contracts.py`` prove each
new shape is not yet wired. Parsing rules shared by every predicate:

- Sparse parses, uniform emits: any subset of buckets/keys is accepted.
- Fail-closed: unknown keys, mistyped scalars (bools rejected everywhere
  an int is required), inexact totals, and unknown enum members reject the
  whole value. Predicates never raise.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable, Iterable, Mapping
from typing import Any, TypeGuard

BUCKETS_5: tuple[str, ...] = (
    "test",
    "setup_teardown",
    "session_provisioning",
    "module_init",
    "preflight",
)
BUCKETS_RC1: tuple[str, ...] = BUCKETS_5[:4]
END_STATES: frozenset[str] = frozenset(
    {"crashed", "timeout", "killed", "unknown", "unresolved", "conflict"}
)
PROCESS_ROLES: tuple[str, ...] = ("unit", "retry", "confirmation", "preflight")
DEFAULT_ROLE = "unit"
UNKNOWN_MODULE = ""
SESSION_REPORT_TYPE = "CallCountersReport"
TEST_ENTRY_PROPERTY = "pkcs11_call_counters"
PARTIAL_REPORT_TYPE = "CallCountersPartial"
LOST_REPORT_TYPE = "CallCountersLost"
REGISTRY_DIRNAME = "registrations"
REGISTRY_SUFFIX = ".json"
PROBE_STATUSES: frozenset[str] = frozenset({"folded", "lost"})
CONTRIBUTION_PRECEDENCE: dict[str, int] = {"authoritative": 2, "partial": 1, "absent": 0}

SESSION_REQUIRED_KEYS = frozenset({"$report_type", "pid", "probes_lost", "total_calls"})
SESSION_OPTIONAL_KEYS = frozenset(
    {
        "buckets",
        "by_module",
        "isolation",
        "run_id",
        "worker_uuid",
        "role",
        "receipts",
        "persistence_pending",
        "lost_keys",
    }
)
SESSION_ALLOWED_KEYS = SESSION_REQUIRED_KEYS | SESSION_OPTIONAL_KEYS
ENTRY_REQUIRED_KEYS = frozenset({"pid", "total_calls"})
ENTRY_OPTIONAL_KEYS = frozenset(
    {"buckets", "by_module", "run_id", "worker_uuid", "isolation", "receipts", "consumed_probes"}
)
ENTRY_ALLOWED_KEYS = ENTRY_REQUIRED_KEYS | ENTRY_OPTIONAL_KEYS
PARTIAL_REQUIRED_KEYS = frozenset({"$report_type", "worker_uuid", "truncated", "total_calls"})
PARTIAL_OPTIONAL_KEYS = frozenset(
    {
        "buckets",
        "by_module",
        "run_id",
        "unit",
        "attempt",
        "pid",
        "receipts",
        "role",
        "isolation",
        "probes_lost",
        "lost_keys",
        "recovered_keys",
        "orphan_keys",
        "in_flight",
    }
)
PARTIAL_ALLOWED_KEYS = PARTIAL_REQUIRED_KEYS | PARTIAL_OPTIONAL_KEYS
LOST_REQUIRED_KEYS = frozenset({"$report_type", "end_state", "scope_index"})
LOST_OPTIONAL_KEYS = frozenset(
    {"worker_uuid", "pid", "run_id", "unit", "attempt", "origin_shard", "role", "isolation"}
)
LOST_ALLOWED_KEYS = LOST_REQUIRED_KEYS | LOST_OPTIONAL_KEYS
LOST_FORBIDDEN_KEYS = frozenset(
    {"total_calls", "buckets", "by_module", "probes_lost", "truncated", "receipts"}
)
REGISTRY_REQUIRED_KEYS = frozenset(
    {
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
    }
)
REGISTRY_ALLOWED_KEYS = frozenset(REGISTRY_REQUIRED_KEYS)
ROW_REQUIRED_KEYS = frozenset({"pid", "total_calls", "isolation", "complete"})
ROW_OPTIONAL_KEYS = frozenset(
    {
        "worker_uuid",
        "module",
        "role",
        "truncated",
        "end_state",
        "round",
        "shard",
        "persistence_pending",
        "probes_lost",
    }
)
ROW_ALLOWED_KEYS = ROW_REQUIRED_KEYS | ROW_OPTIONAL_KEYS
RECEIPT_KEYS = frozenset({"worker_uuid", "probe_seq"})
PROBE_DETAIL_KEYS = frozenset({"worker_uuid", "probe_seq", "status"})
LOST_KEY_KEYS = frozenset({"parent_uuid", "probe_seq"})

_SECRET_EXACT_KEYS = frozenset(
    {
        "pin",
        "user_pin",
        "so_pin",
        "new_pin",
        "old_pin",
        "puk",
        "password",
        "passwd",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "params",
        "parameters",
        "key_bytes",
        "plaintext",
        "ciphertext",
        "cka_value",
        "key_material",
        "private_key",
    }
)


def _is_nonneg_int(value: object) -> bool:
    """Whether ``value`` is a non-negative int (bools rejected)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_nonneg_number(value: object) -> bool:
    """Whether ``value`` is a non-negative int/float timestamp (bools rejected)."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float)) and value >= 0


def _is_decimal_rv_key(value: object) -> bool:
    """Whether ``value`` is the canonical decimal rendering of a CK_RV."""
    if not isinstance(value, str):
        return False
    try:
        rv = int(value)
    except ValueError:
        return False
    return rv >= 0 and str(rv) == value


def _buckets_valid(buckets: object, *, allowed: frozenset[str]) -> bool:
    """Whether ``buckets`` satisfies the serialized-buckets contract.

    Mirrors the rc1 extractor rules: known bucket names only, non-negative
    int scalars (bools rejected), non-empty function names, decimal RV keys,
    ``bucket.calls`` exactly the sum of its functions, and ``sum(by_rv)``
    never above the function calls (crash windows make it smaller).
    """
    if not isinstance(buckets, dict):
        return False
    for bucket_name, block in buckets.items():
        if (
            not isinstance(bucket_name, str)
            or bucket_name not in allowed
            or not isinstance(block, dict)
        ):
            return False
        bucket_calls = block.get("calls")
        if not _is_nonneg_int(bucket_calls):
            return False
        assert isinstance(bucket_calls, int)
        by_fn = block.get("by_fn")
        if not isinstance(by_fn, dict):
            return False
        fn_total = 0
        for fn, fn_block in by_fn.items():
            if not isinstance(fn, str) or not fn or not isinstance(fn_block, dict):
                return False
            fn_calls = fn_block.get("calls")
            if not _is_nonneg_int(fn_calls):
                return False
            assert isinstance(fn_calls, int)
            by_rv = fn_block.get("by_rv")
            if not isinstance(by_rv, dict):
                return False
            rv_total = 0
            for rv_key, rv_block in by_rv.items():
                if not _is_decimal_rv_key(rv_key) or not isinstance(rv_block, dict):
                    return False
                if not isinstance(rv_block.get("name"), str):
                    return False
                count = rv_block.get("count")
                if not _is_nonneg_int(count):
                    return False
                assert isinstance(count, int)
                rv_total += count
            if rv_total > fn_calls:
                return False
            fn_total += fn_calls
        if fn_total != bucket_calls:
            return False
    return True


def _buckets_calls_total(buckets: Mapping[str, Any]) -> int:
    """Sum ``calls`` over validated buckets (shape proven by the caller)."""
    return sum(block["calls"] for block in buckets.values())


def is_module_first_block(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a module-first counter block.

    Shape: ``{total_calls, by_module{mod: {calls, buckets}}}`` with exact
    totals at both levels and inner buckets drawn from the five (sparse
    accepted). Legacy ``buckets``-first blocks are rejected here (see
    :func:`is_legacy_buckets_block` and :func:`normalize_legacy_to_module_first`).
    """
    if not isinstance(value, dict):
        return False
    if set(value) != {"total_calls", "by_module"}:
        return False
    total = value["total_calls"]
    if not _is_nonneg_int(total):
        return False
    by_module = value["by_module"]
    if not isinstance(by_module, dict):
        return False
    module_total = 0
    for module, block in by_module.items():
        if not isinstance(module, str) or not isinstance(block, dict):
            return False
        if set(block) != {"calls", "buckets"}:
            return False
        calls = block["calls"]
        buckets = block["buckets"]
        if not _is_nonneg_int(calls):
            return False
        if not _buckets_valid(buckets, allowed=frozenset(BUCKETS_5)):
            return False
        if calls != _buckets_calls_total(buckets):
            return False
        module_total += calls
    return bool(module_total == total)


def is_legacy_buckets_block(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is an rc1 buckets-first counter block.

    Buckets-first blocks carrying ``preflight`` are malformed (that bucket
    only exists module-first): rejected here and by
    :func:`is_module_first_block` alike, never guessed.
    """
    if not isinstance(value, dict):
        return False
    if set(value) != {"total_calls", "buckets"}:
        return False
    total = value["total_calls"]
    buckets = value["buckets"]
    if not _is_nonneg_int(total):
        return False
    if not _buckets_valid(buckets, allowed=frozenset(BUCKETS_RC1)):
        return False
    return bool(total == _buckets_calls_total(buckets))


def is_worker_uuid(value: object) -> bool:
    """Whether ``value`` is a minted worker identity (32 lowercase hex chars)."""
    return (
        isinstance(value, str)
        and len(value) == 32
        and all(char in "0123456789abcdef" for char in value)
    )


def is_birth_token(value: object) -> bool:
    """Whether ``value`` is an OS process-birth id (non-negative int).

    Linux ``/proc/<pid>/stat`` starttime, Windows process creation time, or
    the macOS equivalent; anything else (including ``None``) means the birth
    is unverifiable and fencing must report unresolved without signaling.
    """
    return _is_nonneg_int(value)


def is_scope_index(value: object) -> bool:
    """Whether ``value`` is an assembly-assigned scope index."""
    return _is_nonneg_int(value)


def is_probe_seq(value: object) -> bool:
    """Whether ``value`` is a folded-probe sequence number."""
    return _is_nonneg_int(value)


def is_bucket_name(value: object) -> bool:
    """Whether ``value`` is one of the five bucket strings."""
    return isinstance(value, str) and value in BUCKETS_5


def is_role(value: object) -> bool:
    """Whether ``value`` is a process role (observation vocabulary)."""
    return isinstance(value, str) and value in PROCESS_ROLES


def is_end_state(value: object) -> bool:
    """Whether ``value`` is a loss end state."""
    return isinstance(value, str) and value in END_STATES


def is_uniform_five(buckets: object) -> bool:
    """Whether ``buckets`` carries exactly the five bucket keys (Task-5 emission)."""
    return isinstance(buckets, dict) and set(buckets) == set(BUCKETS_5)


def is_receipt(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a folded-probe receipt ``{worker_uuid, probe_seq}``."""
    if not isinstance(value, dict):
        return False
    if set(value) != RECEIPT_KEYS:
        return False
    return is_worker_uuid(value["worker_uuid"]) and is_probe_seq(value["probe_seq"])


def is_lost_key(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a lost-probe key ``{parent_uuid, probe_seq}``.

    The parent is the probe launcher (accounting owner); the seq is the
    parent-assigned probe number. Same seq vocabulary as receipts, but the
    uuid names the observation's parent, never the child.
    """
    if not isinstance(value, dict):
        return False
    if set(value) != LOST_KEY_KEYS:
        return False
    return is_worker_uuid(value["parent_uuid"]) and is_probe_seq(value["probe_seq"])


def is_probe_detail(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a per-probe results entry ``{worker_uuid, probe_seq, status}``."""
    if not isinstance(value, dict):
        return False
    if set(value) != PROBE_DETAIL_KEYS:
        return False
    return (
        is_worker_uuid(value["worker_uuid"])
        and is_probe_seq(value["probe_seq"])
        and isinstance(value["status"], str)
        and value["status"] in PROBE_STATUSES
    )


def _receipts_valid(value: object) -> bool:
    """Whether ``value`` is a list of receipts (empty accepted)."""
    return isinstance(value, list) and all(is_receipt(entry) for entry in value)


def _counters_match_total(record: dict[str, Any]) -> bool:
    """Whether the record carries exactly one valid counters shape matching its total."""
    has_buckets = "buckets" in record
    has_modules = "by_module" in record
    if has_buckets == has_modules:
        return False
    total = record["total_calls"]
    if has_buckets:
        buckets = record["buckets"]
        return _buckets_valid(buckets, allowed=frozenset(BUCKETS_RC1)) and (
            total == _buckets_calls_total(buckets)
        )
    return is_module_first_block({"total_calls": total, "by_module": record["by_module"]})


def _run_id_valid(value: object) -> bool:
    """Whether an explicitly present ``run_id`` is well-formed (absent means implicit)."""
    return isinstance(value, str) and bool(value)


def is_session_record(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a session ``CallCountersReport`` record (either counters shape)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=SESSION_ALLOWED_KEYS, required=SESSION_REQUIRED_KEYS):
        return False
    if value["$report_type"] != SESSION_REPORT_TYPE:
        return False
    if not _is_nonneg_int(value["pid"]):
        return False
    if not _is_nonneg_int(value["probes_lost"]):
        return False
    if not _is_nonneg_int(value["total_calls"]):
        return False
    if not _counters_match_total(value):
        return False
    isolation = value.get("isolation")
    if isolation is not None and not isinstance(isolation, str):
        return False
    if "run_id" in value and not _run_id_valid(value["run_id"]):
        return False
    if "worker_uuid" in value and not is_worker_uuid(value["worker_uuid"]):
        return False
    if "role" in value and not is_role(value["role"]):
        return False
    return "receipts" not in value or _receipts_valid(value["receipts"])


def is_test_entry(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a per-test ``pkcs11_call_counters`` entry (either shape)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=ENTRY_ALLOWED_KEYS, required=ENTRY_REQUIRED_KEYS):
        return False
    if not _is_nonneg_int(value["pid"]):
        return False
    if not _is_nonneg_int(value["total_calls"]):
        return False
    if not _counters_match_total(value):
        return False
    isolation = value.get("isolation")
    if isolation is not None and not isinstance(isolation, str):
        return False
    if "run_id" in value and not _run_id_valid(value["run_id"]):
        return False
    if "worker_uuid" in value and not is_worker_uuid(value["worker_uuid"]):
        return False
    if "receipts" in value and not _receipts_valid(value["receipts"]):
        return False
    return "consumed_probes" not in value or _receipts_valid(value["consumed_probes"])


def is_sidecar_partial(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a gap-only sidecar-partial record (always truncated)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=PARTIAL_ALLOWED_KEYS, required=PARTIAL_REQUIRED_KEYS):
        return False
    if value["$report_type"] != PARTIAL_REPORT_TYPE:
        return False
    if not is_worker_uuid(value["worker_uuid"]):
        return False
    if value["truncated"] is not True:
        return False
    if not _is_nonneg_int(value["total_calls"]):
        return False
    if not _counters_match_total(value):
        return False
    if "run_id" in value and not _run_id_valid(value["run_id"]):
        return False
    if "unit" in value and not (isinstance(value["unit"], str) and value["unit"]):
        return False
    if "attempt" in value and not _is_nonneg_int(value["attempt"]):
        return False
    if "pid" in value and not _is_nonneg_int(value["pid"]):
        return False
    if "role" in value and not is_role(value["role"]):
        return False
    isolation = value.get("isolation")
    if isolation is not None and not isinstance(isolation, str):
        return False
    if "receipts" in value and not _receipts_valid(value["receipts"]):
        return False
    return "in_flight" not in value or _in_flight_valid(value["in_flight"])


def _in_flight_valid(value: object) -> bool:
    """Whether ``value`` is a valid named in-flight row list (#88)."""
    if not isinstance(value, list):
        return False
    for row in value:
        if not isinstance(row, dict):
            return False
        if set(row) != {"module", "bucket", "fn", "count"}:
            return False
        if not row["module"] or not isinstance(row["module"], str):
            return False
        if not row["bucket"] or not isinstance(row["bucket"], str):
            return False
        if not row["fn"] or not isinstance(row["fn"], str):
            return False
        count = row["count"]
        if not _is_nonneg_int(count) or count == 0:
            return False
    return True


def is_preflight_synth_record(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a preflight-synth record (role-tagged, preflight-only content).

    Synth records are session-shaped with ``role == "preflight"`` and
    module-first counters; every non-``preflight`` bucket must be absent or
    zero-call (Task-5 uniform emission writes the zero buckets explicitly).
    """
    if not is_session_record(value):
        return False
    if value.get("role") != "preflight":
        return False
    by_module = value.get("by_module")
    if not isinstance(by_module, dict):
        return False
    for block in by_module.values():
        buckets = block["buckets"]
        for bucket_name, bucket in buckets.items():
            if bucket_name != "preflight" and bucket["calls"] != 0:
                return False
    return True


def is_lost_record(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is an identity-bearing lost record (never carries counts)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=LOST_ALLOWED_KEYS, required=LOST_REQUIRED_KEYS):
        return False
    if value["$report_type"] != LOST_REPORT_TYPE:
        return False
    if not is_end_state(value["end_state"]):
        return False
    if not is_scope_index(value["scope_index"]):
        return False
    has_uuid = "worker_uuid" in value
    has_pid = "pid" in value
    if not (has_uuid or has_pid):
        return False
    if has_uuid and not is_worker_uuid(value["worker_uuid"]):
        return False
    if has_pid and not _is_nonneg_int(value["pid"]):
        return False
    if "run_id" in value and not _run_id_valid(value["run_id"]):
        return False
    if "unit" in value and not (isinstance(value["unit"], str) and value["unit"]):
        return False
    if "attempt" in value and not _is_nonneg_int(value["attempt"]):
        return False
    if "role" in value and not is_role(value["role"]):
        return False
    isolation = value.get("isolation")
    if isolation is not None and not isinstance(isolation, str):
        return False
    return "origin_shard" not in value or isinstance(value["origin_shard"], str)


def is_registry_content(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a registry file's self-describing content (R4-I5)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=REGISTRY_ALLOWED_KEYS, required=REGISTRY_REQUIRED_KEYS):
        return False
    return (
        is_worker_uuid(value["worker_uuid"])
        and isinstance(value["run_id"], str)
        and isinstance(value["unit"], str)
        and bool(value["unit"])
        and _is_nonneg_int(value["attempt"])
        and _is_nonneg_int(value["pid"])
        and is_role(value["role"])
        and _is_nonneg_number(value["timestamp"])
        and isinstance(value["sidecar"], str)
        and bool(value["sidecar"])
        and is_birth_token(value["birth_token"])
        and isinstance(value["isolation"], str)
        and bool(value["isolation"])
    )


def is_process_row(value: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``value`` is a ``by_process`` row (legacy 4-key rows accepted)."""
    if not isinstance(value, dict):
        return False
    if key_violations(value, allowed=ROW_ALLOWED_KEYS, required=ROW_REQUIRED_KEYS):
        return False
    if not _is_nonneg_int(value["pid"]):
        return False
    if not _is_nonneg_int(value["total_calls"]):
        return False
    if not isinstance(value["isolation"], str):
        return False
    if not isinstance(value["complete"], bool):
        return False
    if "worker_uuid" in value and not is_worker_uuid(value["worker_uuid"]):
        return False
    if "module" in value and not isinstance(value["module"], str):
        return False
    if "role" in value and not is_role(value["role"]):
        return False
    if "truncated" in value and not isinstance(value["truncated"], bool):
        return False
    if "end_state" in value and not is_end_state(value["end_state"]):
        return False
    if "round" in value and not (isinstance(value["round"], str) and value["round"]):
        return False
    if "shard" in value and not (isinstance(value["shard"], str) and bool(value["shard"])):
        return False
    return "probes_lost" not in value or _is_nonneg_int(value["probes_lost"])


def key_violations(
    value: object, *, allowed: frozenset[str], required: frozenset[str]
) -> tuple[str, ...]:
    """Describe a value's key-set violations (empty when valid).

    Returns ``("not-a-dict",)`` for non-dicts, else sorted ``missing:<key>``
    entries followed by sorted ``unknown:<key>`` entries.
    """
    if not isinstance(value, dict):
        return ("not-a-dict",)
    keys = set(value)
    missing = sorted(f"missing:{key}" for key in required if key not in keys)
    unknown = sorted(f"unknown:{key}" for key in keys if key not in allowed)
    return tuple(missing + unknown)


def find_secret_keys(value: object) -> tuple[str, ...]:
    """Return dotted paths of credential-shaped dict keys under ``value``.

    Exact case-insensitive matches against the banned key set plus the
    ``cka_`` prefix; function names such as ``C_SetPIN`` never match (exact,
    not substring). Counters carry identity only, so any hit is a bug.
    """
    found: list[str] = []

    def _walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if isinstance(key, str):
                    lowered = key.lower()
                    if lowered in _SECRET_EXACT_KEYS or lowered.startswith("cka_"):
                        found.append(child_path)
                _walk(child, child_path)
        elif isinstance(node, (list, tuple)):
            for index, child in enumerate(node):
                _walk(child, f"{path}[{index}]" if path else f"[{index}]")

    _walk(value, "")
    return tuple(sorted(found))


def is_secret_free(value: object) -> bool:
    """Whether ``value`` carries no credential-shaped keys (see :func:`find_secret_keys`)."""
    return not find_secret_keys(value)


def _require_text(name: str, value: object, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def _require_nonneg_int(name: str, value: object) -> int:
    if not _is_nonneg_int(value):
        raise ValueError(f"invalid {name}: {value!r}")
    assert isinstance(value, int)
    return value


def _require_uuid(name: str, value: object) -> str:
    if not is_worker_uuid(value):
        raise ValueError(f"invalid {name}: {value!r}")
    assert isinstance(value, str)
    return value


def sidecar_identity(
    run_id: str, unit: str, attempt: int, worker_uuid: str
) -> tuple[str, str, int, str]:
    """Build a sidecar/registry identity key (filename nonce added by Task 3)."""
    return (
        _require_text("run_id", run_id, allow_empty=True),
        _require_text("unit", unit, allow_empty=False),
        _require_nonneg_int("attempt", attempt),
        _require_uuid("worker_uuid", worker_uuid),
    )


def receipt_key(worker_uuid: str, probe_seq: int) -> tuple[str, int]:
    """Build a folded-probe receipt key."""
    return (
        _require_uuid("worker_uuid", worker_uuid),
        _require_nonneg_int("probe_seq", probe_seq),
    )


def session_authority_key(worker_uuid: str) -> str:
    """Build a session-authority key (the producer uuid itself, validated)."""
    return _require_uuid("worker_uuid", worker_uuid)


def test_supersede_key(worker_uuid: str, nodeid: str) -> tuple[str, str]:
    """Build a per-test supersede key (entry uuid plus enclosing report nodeid)."""
    return (
        _require_uuid("worker_uuid", worker_uuid),
        _require_text("nodeid", nodeid, allow_empty=False),
    )


def source_association(
    origin_shard: str, unit: str, attempt: int, worker_uuid: str | None = None
) -> tuple[str, str, int, str | None]:
    """Build an immutable source-execution association for cross-scope matching.

    The C2b match key: assembly re-derives output scopes and matches staged
    evidence via this association, never by bare scope tuples across
    scopes/rounds. ``origin_shard`` is ``""`` for direct (unmerged) streams.
    """
    uuid_part = None if worker_uuid is None else _require_uuid("worker_uuid", worker_uuid)
    return (
        _require_text("origin_shard", origin_shard, allow_empty=True),
        _require_text("unit", unit, allow_empty=False),
        _require_nonneg_int("attempt", attempt),
        uuid_part,
    )


def scope_key(scope: int, target: str, attempt: int) -> tuple[int, str, int]:
    """Build a within-stream scope key ``(scope, target, attempt)``."""
    return (
        _require_nonneg_int("scope", scope),
        _require_text("target", target, allow_empty=False),
        _require_nonneg_int("attempt", attempt),
    )


def merge_key(shard: str, run_id: str, worker_uuid: str) -> tuple[str, str, str]:
    """Build a merge identity key (merge adds the shard to the association)."""
    return (
        _require_text("shard", shard, allow_empty=False),
        _require_text("run_id", run_id, allow_empty=True),
        _require_uuid("worker_uuid", worker_uuid),
    )


def registry_filename(worker_uuid: str) -> str:
    """Return the registry filename for a worker (``<worker_uuid>.json``)."""
    return f"{_require_uuid('worker_uuid', worker_uuid)}{REGISTRY_SUFFIX}"


def parse_registry_filename(name: str) -> str | None:
    """Return the worker uuid bound by a registry filename, else None (torn/absent)."""
    if not name.endswith(REGISTRY_SUFFIX):
        return None
    stem = name[: -len(REGISTRY_SUFFIX)]
    return stem if is_worker_uuid(stem) else None


def mint_worker_uuid() -> str:
    """Mint a producer identity (uuid4 hex; randomness only, no I/O)."""
    return uuid.uuid4().hex


def mint_filename_nonce() -> str:
    """Mint a sidecar filename nonce (8 hex chars; randomness only, no I/O)."""
    return uuid.uuid4().hex[:8]


def empty_buckets_five() -> dict[str, Any]:
    """Return zero buckets with all five keys (Task-5 uniform emission shape)."""
    return {name: {"calls": 0, "by_fn": {}} for name in BUCKETS_5}


def empty_block_five() -> dict[str, Any]:
    """Return a zero buckets-first block with all five keys."""
    return {"total_calls": 0, "buckets": empty_buckets_five()}


def serialize_counts_five(
    counts: Mapping[tuple[str, str, int | None], int],
    *,
    resolve_name: Callable[[int], str],
) -> dict[str, Any]:
    """Serialize flat ``(bucket, fn, rv-or-None)`` counts with all five keys.

    Buckets, functions, and RV names follow the serialized contract; the
    five bucket keys are always present while functions/RVs stay sparse.
    Non-positive counts are skipped (mirroring the rc1 serializer); an
    unknown bucket, empty function name, or negative/bool RV raises
    ``ValueError``.
    """
    buckets: dict[str, dict[str, Any]] = empty_buckets_five()
    total = 0
    names: dict[int, str] = {}
    for (bucket, fn, rv), count in counts.items():
        if bucket not in BUCKETS_5:
            raise ValueError(f"unknown bucket: {bucket!r}")
        if not isinstance(fn, str) or not fn:
            raise ValueError(f"invalid fn: {fn!r}")
        if rv is not None and not _is_nonneg_int(rv):
            raise ValueError(f"invalid rv: {rv!r}")
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError(f"invalid count: {count!r}")
        if count <= 0:
            continue
        block = buckets[bucket]
        by_fn: dict[str, Any] = block["by_fn"]
        target = by_fn.get(fn)
        if target is None:
            target = {"calls": 0, "by_rv": {}}
            by_fn[fn] = target
        target["calls"] += count
        block["calls"] += count
        total += count
        if rv is not None:
            if rv not in names:
                names[rv] = resolve_name(rv)
            by_rv: dict[str, Any] = target["by_rv"]
            leaf = by_rv.get(str(rv))
            if leaf is None:
                by_rv[str(rv)] = {"name": names[rv], "count": count}
            else:
                leaf["count"] += count
    return {"total_calls": total, "buckets": buckets}


def ensure_five_buckets(buckets: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``buckets`` expanded to all five keys (never aliases)."""
    uniform = copy.deepcopy(dict(buckets))
    for name in BUCKETS_5:
        uniform.setdefault(name, {"calls": 0, "by_fn": {}})
    return uniform


def normalize_legacy_to_module_first(legacy: object) -> dict[str, Any] | None:
    """Normalize a legacy buckets-first block under the ``""`` module, else None.

    Inner buckets keep their sparse shape (uniform expansion is Task-5
    emission); the result never aliases the input.
    """
    if not is_legacy_buckets_block(legacy):
        return None
    total = legacy["total_calls"]
    return {
        "total_calls": total,
        "by_module": {"": {"calls": total, "buckets": copy.deepcopy(legacy["buckets"])}},
    }


def wrap_module_first(modules: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Wrap per-module buckets dicts into a module-first block (totals computed).

    Mechanical only: bucket ``calls`` scalars must be well-formed or
    ``ValueError`` is raised; use :func:`is_module_first_block` to fully
    validate the result.
    """
    by_module: dict[str, Any] = {}
    total = 0
    for module, buckets in modules.items():
        if not isinstance(module, str):
            raise ValueError(f"invalid module id: {module!r}")
        if not isinstance(buckets, Mapping):
            raise ValueError(f"invalid buckets for module {module!r}")
        copied = copy.deepcopy(dict(buckets))
        calls = 0
        for bucket_name, block in copied.items():
            if not isinstance(block, Mapping):
                raise ValueError(f"invalid block for module {module!r} bucket {bucket_name!r}")
            block_calls = block.get("calls")
            if not _is_nonneg_int(block_calls):
                raise ValueError(f"invalid calls for module {module!r} bucket {bucket_name!r}")
            assert isinstance(block_calls, int)
            calls += block_calls
        by_module[module] = {"calls": calls, "buckets": copied}
        total += calls
    return {"total_calls": total, "by_module": by_module}


def canonicalize_module_first(block: Mapping[str, Any]) -> dict[str, Any]:
    """Return a key-sorted copy of a module-first block (input never mutated).

    Modules, buckets, functions, and RV keys sort ascending (RV keys as
    strings, mirroring the rc1 canonicalizer), so plain ``json.dumps``
    output is byte-identical across input orders.
    """
    if not is_module_first_block(block):
        raise ValueError("not a module-first block")
    canonical: dict[str, Any] = {"total_calls": block["total_calls"], "by_module": {}}
    for module in sorted(block["by_module"]):
        source = block["by_module"][module]
        buckets: dict[str, Any] = {}
        for bucket_name in sorted(source["buckets"]):
            bucket = source["buckets"][bucket_name]
            by_fn: dict[str, Any] = {}
            for fn in sorted(bucket["by_fn"]):
                fn_block = bucket["by_fn"][fn]
                by_rv = {rv: dict(fn_block["by_rv"][rv]) for rv in sorted(fn_block["by_rv"])}
                by_fn[fn] = {"calls": fn_block["calls"], "by_rv": by_rv}
            buckets[bucket_name] = {"calls": bucket["calls"], "by_fn": by_fn}
        canonical["by_module"][module] = {"calls": source["calls"], "buckets": buckets}
    return canonical


def _is_hex_rv_name(name: str) -> bool:
    """Whether ``name`` is a hex fallback rather than a symbolic RV name."""
    return name.startswith("0x") or name.startswith("0X")


def _resolve_rv_name(first: str, second: str) -> str:
    """Deterministically resolve conflicting observed RV leaf names.

    Prefers the symbolic (non-hex) name; ties resolve to the
    lexicographically smallest, so both merge orders yield the identical leaf.
    """
    first_hex = _is_hex_rv_name(first)
    second_hex = _is_hex_rv_name(second)
    if first_hex != second_hex:
        return second if first_hex else first
    return min(first, second)


def merge_module_first(target: dict[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Add ``incoming`` module-first counts into ``target`` in place (both validated).

    Mirrors the rc1 serialized merge one level down: missing modules,
    buckets, functions, or RVs are created (leaves copied, never aliased)
    and conflicting RV leaf names resolve deterministically.
    """
    if not is_module_first_block(target) or not is_module_first_block(incoming):
        raise ValueError("merge requires module-first blocks")
    target["total_calls"] += incoming["total_calls"]
    target_modules = target["by_module"]
    for module, module_block in incoming["by_module"].items():
        target_module = target_modules.get(module)
        if target_module is None:
            target_modules[module] = copy.deepcopy(dict(module_block))
            continue
        target_module["calls"] += module_block["calls"]
        target_buckets = target_module["buckets"]
        for bucket_name, bucket in module_block["buckets"].items():
            target_bucket = target_buckets.get(bucket_name)
            if target_bucket is None:
                target_buckets[bucket_name] = copy.deepcopy(dict(bucket))
                continue
            target_bucket["calls"] += bucket["calls"]
            target_by_fn = target_bucket["by_fn"]
            for fn, fn_block in bucket["by_fn"].items():
                target_fn = target_by_fn.get(fn)
                if target_fn is None:
                    target_by_fn[fn] = copy.deepcopy(dict(fn_block))
                    continue
                target_fn["calls"] += fn_block["calls"]
                target_by_rv = target_fn["by_rv"]
                for rv_key, rv_block in fn_block["by_rv"].items():
                    existing = target_by_rv.get(rv_key)
                    if existing is None:
                        target_by_rv[rv_key] = {
                            "name": rv_block["name"],
                            "count": rv_block["count"],
                        }
                    else:
                        existing["count"] += rv_block["count"]
                        existing["name"] = _resolve_rv_name(existing["name"], rv_block["name"])
    return target


def union_receipts(*receipt_lists: Iterable[object]) -> list[dict[str, str | int]]:
    """Union receipt lists into sorted deduped ``{worker_uuid, probe_seq}`` dicts.

    Superseding records union superseded receipts (recursive to
    grandchildren); invalid entries are skipped without raising, mirroring
    the garbage-tolerant ingest path.
    """
    seen: dict[tuple[str, int], dict[str, str | int]] = {}
    for receipts in receipt_lists:
        try:
            iterator = iter(receipts)
        except TypeError:
            continue
        for receipt in iterator:
            if not is_receipt(receipt):
                continue
            key = (receipt["worker_uuid"], receipt["probe_seq"])
            seen.setdefault(key, {"worker_uuid": key[0], "probe_seq": key[1]})
    return [seen[key] for key in sorted(seen)]


def contribution_rank(kind: str) -> int:
    """Return the staging precedence rank (authoritative > partial > absent)."""
    try:
        return CONTRIBUTION_PRECEDENCE[kind]
    except KeyError:
        raise ValueError(f"unknown contribution kind: {kind!r}") from None


def stronger_contribution(first: str, second: str) -> str:
    """Return the stronger contribution kind (ties return the kind).

    Terminal conflicts between distinct sources sharing one identity are
    detected at the identity level by Task-3 staging (surfacing ``conflict``),
    not by this kind-level comparison.
    """
    if contribution_rank(second) > contribution_rank(first):
        return second
    return first


def effective_group_complete(
    has_authoritative: bool,
    *,
    probes_lost: int = 0,
    effective_losses: int = 0,
    conflicts: int = 0,
) -> bool:
    """Whether a reconciled group is complete (superseded evidence excluded by the caller).

    A group with only partial evidence passes ``has_authoritative=False``;
    any unresolved loss, conflict, lost probe, or fallback-only evidence
    keeps it incomplete.
    """
    for name, count in (
        ("probes_lost", probes_lost),
        ("effective_losses", effective_losses),
        ("conflicts", conflicts),
    ):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"invalid {name}: {count!r}")
    return bool(has_authoritative) and probes_lost == 0 and effective_losses == 0 and conflicts == 0


def all_complete(flags: Iterable[bool]) -> bool:
    """AND a set of completeness flags (rounds AND groups; global ANDs rounds)."""
    return all(flags)


def canonicalize_process_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a process row with default tags omitted (``role: unit``)."""
    if not is_process_row(row):
        raise ValueError("not a process row")
    canonical = dict(row)
    if canonical.get("role") == DEFAULT_ROLE:
        del canonical["role"]
    return canonical


__all__ = [
    "BUCKETS_5",
    "BUCKETS_RC1",
    "CONTRIBUTION_PRECEDENCE",
    "DEFAULT_ROLE",
    "END_STATES",
    "ENTRY_ALLOWED_KEYS",
    "ENTRY_OPTIONAL_KEYS",
    "ENTRY_REQUIRED_KEYS",
    "LOST_ALLOWED_KEYS",
    "LOST_FORBIDDEN_KEYS",
    "LOST_KEY_KEYS",
    "LOST_OPTIONAL_KEYS",
    "LOST_REPORT_TYPE",
    "LOST_REQUIRED_KEYS",
    "PARTIAL_ALLOWED_KEYS",
    "PARTIAL_OPTIONAL_KEYS",
    "PARTIAL_REPORT_TYPE",
    "PARTIAL_REQUIRED_KEYS",
    "PROBE_DETAIL_KEYS",
    "PROBE_STATUSES",
    "PROCESS_ROLES",
    "RECEIPT_KEYS",
    "REGISTRY_ALLOWED_KEYS",
    "REGISTRY_DIRNAME",
    "REGISTRY_REQUIRED_KEYS",
    "REGISTRY_SUFFIX",
    "ROW_ALLOWED_KEYS",
    "ROW_OPTIONAL_KEYS",
    "ROW_REQUIRED_KEYS",
    "SESSION_ALLOWED_KEYS",
    "SESSION_OPTIONAL_KEYS",
    "SESSION_REPORT_TYPE",
    "SESSION_REQUIRED_KEYS",
    "TEST_ENTRY_PROPERTY",
    "UNKNOWN_MODULE",
    "all_complete",
    "canonicalize_module_first",
    "canonicalize_process_row",
    "contribution_rank",
    "effective_group_complete",
    "empty_block_five",
    "empty_buckets_five",
    "ensure_five_buckets",
    "find_secret_keys",
    "is_birth_token",
    "is_bucket_name",
    "is_end_state",
    "is_legacy_buckets_block",
    "is_lost_key",
    "is_lost_record",
    "is_module_first_block",
    "is_preflight_synth_record",
    "is_probe_detail",
    "is_probe_seq",
    "is_process_row",
    "is_receipt",
    "is_registry_content",
    "is_role",
    "is_scope_index",
    "is_secret_free",
    "is_session_record",
    "is_sidecar_partial",
    "is_test_entry",
    "is_uniform_five",
    "is_worker_uuid",
    "key_violations",
    "merge_key",
    "merge_module_first",
    "mint_filename_nonce",
    "mint_worker_uuid",
    "normalize_legacy_to_module_first",
    "parse_registry_filename",
    "receipt_key",
    "registry_filename",
    "scope_key",
    "serialize_counts_five",
    "session_authority_key",
    "sidecar_identity",
    "source_association",
    "stronger_contribution",
    "test_supersede_key",
    "union_receipts",
    "wrap_module_first",
]

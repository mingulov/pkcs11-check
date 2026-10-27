#!/usr/bin/env python3
"""Verify a CI provider-round receipt against the pinned lock file.

Usage: ``verify_round_receipt.py <receipt.json> --lock <lock.json>
--expect-fw <sha>``. Exit 0 = receipt valid; 1 = receipt INVALID (every
failure names the exact field on stderr, one ``error: <field>: <message>``
line per violation — fail-loud batch, not first-only); 2 = usage/infra
(missing files, unparseable JSON, malformed LOCK, bad args, empty
``--expect-fw``). ``--expect-fw`` is an opaque non-empty string: compared
by exact match only, never parsed as hex.

Standard library only, deliberately: like ``release_check.py``, this runs
in CI glue where third-party imports may be unavailable.

Receipt schema (PINNED cross-repo contract; p11lab implements the
producer side)::

    {
      "receipt_contract_v": 1,
      "tier": "pr-smoke",
      "framework_sha": "<40-hex>",
      "p11lab_sha": "<40-hex>",
      "baseline_fw_sha": "<40-hex>",
      "evaluator_sha": "<40-hex>",
      "policy_hash": "<64-hex>", "profile_hash": "<64-hex>",
      "catalog_hash": "<64-hex>", "corpus_hash": "<64-hex>",
      "disabled_hash": "<64-hex>",
      "handoff_identity": "<non-empty str>",
      "runtime_identity": "<non-empty str>",
      "bundle_identity": "<64-hex, recomputed, see below>",
      "wheel_hashes": {"name": "<64-hex>", "...": "..."},
      "lanes": {"lane-name": {"verdict": "pass|fail", "admitted": true,
                              "evidence_digest": "<64-hex>"}},
      "run_id": "<non-empty str>", "attempt": 1, "job_ids": {}
    }

SHA fields are exact-match strings (no hex validation — opaque pins,
``"PENDING-P11LAB"``-style values are legal during bring-up; equality is
what matters). ``*_hash`` + ``evidence_digest`` + ``bundle_identity`` +
wheel values MUST match ``^[0-9a-f]{64}$``. ``attempt`` is int >= 1.
``job_ids`` must be an object (contents opaque). ``lanes`` must be a
non-empty object (rule 5).

Bundle binding (PINNED): ``bundle_identity`` MUST equal the sha256 hex
over the concatenation, sorted by lane name, of
``lane + "\\0" + evidence_digest + "\\0"`` (UTF-8) for every lane in
``receipt.lanes``. ``compute_bundle_identity({})`` is the sha256 of
``b""`` by construction, but an empty lanes object never reaches
recomputation: it fails the non-empty-closure check (rule 5) first.

Evidence-digest producer contract (PINNED cross-repo; p11lab implements
the producer side): each lane's ``evidence_digest`` is DEFINED AS the
sha256 hex of the EXACT ``ledger.jsonl`` artifact bytes as uploaded --
byte-for-byte, no canonicalization, no re-serialization. Recomputation
enforcement (download the ledger, hash it, compare) is E5 release-job
wiring; this verifier stays artifact-I/O-free by design (it checks the
digest SHAPE and bundle binding, never the ledger bytes).

Lock schema (PINNED; this file lives at
``.github/provider-round.lock.json``)::

    {"receipt_contract_v": 1, "p11lab_ref": "...", "evaluator_fw_ref": "...",
     "baseline_fw_sha": "...",
     "tiers": {"pr-smoke": {"lanes": [...], "quorum": {...}, "budgets": {...}},
               "nightly": {...}, "release": {...}}}

Tier objects carry a non-empty ``lanes`` list of non-empty UTF-8-encodable strings plus
``quorum``/``budgets`` objects (presence-checked only — shapes and
thresholds are TBD-E5). Staged
Windows/macOS lanes (``win-softhsm2``, ``win-bouncyhsm``,
``mac-softhsm2``) are NOT in the initial lock; they land as staged
additions in E5.

Verification rules (normative):
1. ``receipt_contract_v`` == lock ``receipt_contract_v``.
2. ``framework_sha`` == ``--expect-fw``.
3. ``p11lab_sha`` == lock ``p11lab_ref``; ``evaluator_sha`` == lock
   ``evaluator_fw_ref``; ``baseline_fw_sha`` == lock ``baseline_fw_sha``
   ("stale baseline" = rule 3c).
4. ``tier`` is one of the lock tiers; the tier object has a non-empty
   ``lanes`` list of non-empty strings plus ``quorum``/``budgets``
   objects. The lock is OUR file, so a malformed lock (bad JSON or bad
   schema) is a config error -> exit 2.
5. Closed lane roster: receipt ``lanes`` is a non-empty object whose keys
   == tier lanes EXACTLY — a missing lane fails AND an unexpected lane
   fails (never generated-from-found).
6. Per lane: ``verdict`` in {pass, fail}; ``admitted`` is a bool;
   ``evidence_digest`` is 64-hex; ``verdict == "pass"`` with
   ``admitted == false`` fails (unadmitted lane marked pass).
7. Bundle recomputation matches ``bundle_identity`` (skipped without
   cascading noise when any lane name is UTF-8-unencodable or any
   digest is not 64-hex — rules 5/6 already report those).
8. Well-formedness: all ``*_hash`` 64-hex; identities non-empty;
   ``wheel_hashes`` a non-empty object of 64-hex values;
   ``run_id``/``attempt``/``job_ids`` typed as above.

OUT OF SCOPE (owned elsewhere, do not add here): baseline AGE /
merge-base freshness (needs git/GitHub, E5 side); wheel-hash equality
vs built assets (E5 release-job wiring passes expected hashes);
quorum/budget ENFORCEMENT (E5 fills shapes + thresholds); two-receipt
replay comparison (base+candidate identical inputs).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2

RECEIPT_CONTRACT_V = 1

HEX64_RE = re.compile(r"[0-9a-f]{64}")

HASH_FIELDS = ("policy_hash", "profile_hash", "catalog_hash", "corpus_hash", "disabled_hash")
IDENTITY_FIELDS = ("handoff_identity", "runtime_identity")
LOCK_REF_FIELDS = ("p11lab_ref", "evaluator_fw_ref", "baseline_fw_sha")


def compute_bundle_identity(digests: Mapping[str, str]) -> str:
    """Return the pinned bundle binding over lane -> evidence_digest pairs."""
    payload = "".join(f"{lane}\0{digests[lane]}\0" for lane in sorted(digests))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and HEX64_RE.fullmatch(value) is not None


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _missing(field: str) -> str:
    return f"{field}: missing required field"


def validate_lock(data: Any) -> list[str]:
    """Return config errors (each naming the lock field); [] when usable."""
    if not isinstance(data, dict):
        return ["lock: top level must be an object"]
    errors: list[str] = []
    version = data.get("receipt_contract_v")
    if version is None:
        errors.append(_missing("receipt_contract_v"))
    elif not _is_plain_int(version):
        errors.append("receipt_contract_v: must be an integer")
    for field in LOCK_REF_FIELDS:
        ref = data.get(field)
        if ref is None:
            errors.append(_missing(field))
        elif not isinstance(ref, str) or not ref:
            errors.append(f"{field}: must be a non-empty string")
    tiers = data.get("tiers")
    if tiers is None:
        errors.append(_missing("tiers"))
    elif not isinstance(tiers, dict):
        errors.append("tiers: must be an object")
    else:
        for tier in sorted(tiers):
            errors.extend(_validate_lock_tier(tier, tiers[tier]))
    return errors


def _validate_lock_tier(tier: object, spec: Any) -> list[str]:
    prefix = f"tiers.{tier}"
    if not isinstance(spec, dict):
        return [f"{prefix}: must be an object"]
    errors: list[str] = []
    lanes = spec.get("lanes")
    if lanes is None:
        errors.append(_missing(f"{prefix}.lanes"))
    elif (
        not isinstance(lanes, list)
        or not lanes
        or any(not isinstance(name, str) or not name for name in lanes)
    ):
        errors.append(f"{prefix}.lanes: must be a non-empty list of non-empty strings")
    elif not _is_utf8_encodable("".join(lanes)):
        # R30: an unencodable lock lane matching an unencodable receipt
        # lane would pass the roster (rule 5) and lane entries (rule 6)
        # while the bundle check (rule 7) skips -> exit 0 on a bogus
        # bundle. Reject it here as malformed lock schema (exit 2).
        errors.append(f"{prefix}.lanes: lane names must be UTF-8-encodable")
    for field in ("quorum", "budgets"):
        shape = spec.get(field)
        if shape is None:
            errors.append(_missing(f"{prefix}.{field}"))
        elif not isinstance(shape, dict):
            errors.append(f"{prefix}.{field}: must be an object")
    return errors


def validate_receipt(receipt: Any, lock: dict[str, Any], expect_fw: str) -> list[str]:
    """Return receipt failures (each naming the receipt field); [] when valid."""
    if not isinstance(receipt, dict):
        return ["receipt: top level must be an object"]
    failures: list[str] = []
    failures.extend(_check_contract_version(receipt, lock))
    failures.extend(_check_exact_string(receipt, "framework_sha", expect_fw))
    failures.extend(_check_exact_string(receipt, "p11lab_sha", lock["p11lab_ref"]))
    failures.extend(_check_exact_string(receipt, "evaluator_sha", lock["evaluator_fw_ref"]))
    failures.extend(_check_exact_string(receipt, "baseline_fw_sha", lock["baseline_fw_sha"]))
    tier = _check_tier(receipt, lock)
    failures.extend(tier.failures)
    lanes = receipt.get("lanes")
    if lanes is None:
        failures.append(_missing("lanes"))
    elif not isinstance(lanes, dict) or not lanes:
        failures.append("lanes: must be a non-empty object")
    elif tier.name is not None:
        failures.extend(_check_roster(tier.name, lanes, lock))
        failures.extend(_check_lane_entries(lanes))
        failures.extend(_check_bundle(receipt, lanes))
    else:
        failures.extend(_check_lane_entries(lanes))
        failures.extend(_check_bundle(receipt, lanes))
    failures.extend(_check_well_formedness(receipt))
    return failures


def _check_contract_version(receipt: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    version = receipt.get("receipt_contract_v")
    if version is None:
        return [_missing("receipt_contract_v")]
    if not _is_plain_int(version):
        return ["receipt_contract_v: must be an integer"]
    if version != lock["receipt_contract_v"]:
        return [f"receipt_contract_v: expected {lock['receipt_contract_v']!r}, got {version!r}"]
    return []


def _check_exact_string(receipt: dict[str, Any], field: str, expected: str) -> list[str]:
    value = receipt.get(field)
    if value is None:
        return [_missing(field)]
    if not isinstance(value, str):
        return [f"{field}: must be a string"]
    if value != expected:
        return [f"{field}: expected {expected!r}, got {value!r}"]
    return []


class _TierResult:
    def __init__(self, name: str | None, failures: list[str]) -> None:
        self.name = name
        self.failures = failures


def _check_tier(receipt: dict[str, Any], lock: dict[str, Any]) -> _TierResult:
    tier = receipt.get("tier")
    if tier is None:
        return _TierResult(None, [_missing("tier")])
    if not isinstance(tier, str):
        return _TierResult(None, ["tier: must be a string"])
    if tier not in lock["tiers"]:
        return _TierResult(None, [f"tier: unknown tier {tier!r}"])
    return _TierResult(tier, [])


def _check_roster(tier: str, lanes: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    expected = set(lock["tiers"][tier]["lanes"])
    found = set(lanes)
    failures = [
        f"lanes.{name}: missing required lane for tier {tier!r}"
        for name in sorted(expected - found)
    ]
    failures.extend(
        f"lanes.{name}: unexpected lane for tier {tier!r}" for name in sorted(found - expected)
    )
    return failures


def _check_lane_entries(lanes: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for name in sorted(lanes):
        prefix = f"lanes.{name}"
        entry = lanes[name]
        if not isinstance(entry, dict):
            failures.append(f"{prefix}: must be an object")
            continue
        verdict = entry.get("verdict")
        if verdict is None:
            failures.append(_missing(f"{prefix}.verdict"))
        elif verdict not in ("pass", "fail"):
            failures.append(f"{prefix}.verdict: must be 'pass' or 'fail', got {verdict!r}")
        admitted = entry.get("admitted")
        if admitted is None:
            failures.append(_missing(f"{prefix}.admitted"))
        elif not isinstance(admitted, bool):
            failures.append(f"{prefix}.admitted: must be a boolean")
        digest = entry.get("evidence_digest")
        if digest is None:
            failures.append(_missing(f"{prefix}.evidence_digest"))
        elif not _is_hex64(digest):
            failures.append(f"{prefix}.evidence_digest: must be 64 lowercase hex")
        if verdict == "pass" and admitted is False:
            failures.append(f"{prefix}.admitted: lane marked pass but admitted is false")
    return failures


def _is_utf8_encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _check_bundle(receipt: dict[str, Any], lanes: dict[str, Any]) -> list[str]:
    bundle = receipt.get("bundle_identity")
    if not isinstance(bundle, str):
        return []
    digests: dict[str, str] = {}
    for name, entry in lanes.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("evidence_digest"), str):
            return []
        digests[name] = entry["evidence_digest"]
    # No-cascade rule (R29): recomputation is only meaningful over fully
    # valid inputs. Rules 5/6 already emit diagnostics for unexpected lanes
    # and non-hex digests, so skip here when any lane name is
    # UTF-8-unencodable (e.g. a lone surrogate) or any digest is not 64-hex
    # (a 64-hex digest is ASCII by construction, hence encodable) — instead
    # of crashing on .encode("utf-8") or piling on a spurious mismatch.
    for name, digest in digests.items():
        if not _is_utf8_encodable(name) or not _is_hex64(digest):
            return []
    if bundle != compute_bundle_identity(digests):
        return ["bundle_identity: does not match recomputed lane binding"]
    return []


def _check_well_formedness(receipt: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    bundle = receipt.get("bundle_identity")
    if bundle is None:
        failures.append(_missing("bundle_identity"))
    elif not _is_hex64(bundle):
        failures.append("bundle_identity: must be 64 lowercase hex")
    for field in HASH_FIELDS:
        value = receipt.get(field)
        if value is None:
            failures.append(_missing(field))
        elif not _is_hex64(value):
            failures.append(f"{field}: must be 64 lowercase hex")
    for field in IDENTITY_FIELDS:
        value = receipt.get(field)
        if value is None:
            failures.append(_missing(field))
        elif not isinstance(value, str) or not value:
            failures.append(f"{field}: must be a non-empty string")
    failures.extend(_check_wheel_hashes(receipt.get("wheel_hashes")))
    run_id = receipt.get("run_id")
    if run_id is None:
        failures.append(_missing("run_id"))
    elif not isinstance(run_id, str) or not run_id:
        failures.append("run_id: must be a non-empty string")
    attempt = receipt.get("attempt")
    if attempt is None:
        failures.append(_missing("attempt"))
    elif not _is_plain_int(attempt) or attempt < 1:
        failures.append("attempt: must be an integer >= 1")
    job_ids = receipt.get("job_ids")
    if job_ids is None:
        failures.append(_missing("job_ids"))
    elif not isinstance(job_ids, dict):
        failures.append("job_ids: must be an object")
    return failures


def _check_wheel_hashes(wheels: Any) -> list[str]:
    if wheels is None:
        return [_missing("wheel_hashes")]
    if not isinstance(wheels, dict):
        return ["wheel_hashes: must be an object"]
    if not wheels:
        return ["wheel_hashes: must be a non-empty object"]
    return [
        f"wheel_hashes.{name}: must be 64 lowercase hex"
        for name in sorted(str(name) for name in wheels)
        if not _is_hex64(wheels[name])
    ]


def _read_json_file(path: Path, kind: str) -> tuple[Any, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text), None
    except OSError as exc:
        return None, f"cannot read {kind} file {path}: {exc.strerror or exc}"
    except RecursionError:
        # Parser blew the call stack on hostile nesting: keep the handler
        # trivial and RecursionError-safe — static message plus the class
        # name only, never str(exc)/repr of attacker-controlled input.
        return None, (
            f"{kind} file {path} is not valid JSON: "
            "RecursionError (input nesting exceeds parser limits)"
        )
    except (UnicodeDecodeError, ValueError) as exc:
        # UnicodeDecodeError: file is not valid UTF-8. ValueError: parser
        # failures beyond JSONDecodeError, e.g. the 4300-digit int string
        # conversion limit (JSONDecodeError subclasses ValueError, so it is
        # covered here too).
        return None, f"{kind} file {path} is not valid JSON: {exc}"


def main(argv: list[str] | None = None) -> int:
    """Verify the receipt against the lock. 0 = valid, 1 = invalid, 2 = usage/infra."""
    parser = argparse.ArgumentParser(description="Verify a CI provider-round receipt.")
    parser.add_argument("receipt", type=Path, help="path to the round receipt JSON")
    parser.add_argument("--lock", type=Path, required=True, help="path to provider-round.lock.json")
    parser.add_argument(
        "--expect-fw", required=True, help="expected framework SHA (opaque exact match)"
    )
    args = parser.parse_args(argv)

    if not args.expect_fw:
        print("error: --expect-fw must be a non-empty string", file=sys.stderr)
        return EXIT_USAGE

    receipt, problem = _read_json_file(args.receipt, "receipt")
    if problem is not None:
        print(f"error: {problem}", file=sys.stderr)
        return EXIT_USAGE
    lock, problem = _read_json_file(args.lock, "lock")
    if problem is not None:
        print(f"error: {problem}", file=sys.stderr)
        return EXIT_USAGE

    lock_errors = validate_lock(lock)
    for error in lock_errors:
        print(f"error: {error}", file=sys.stderr)
    if lock_errors:
        return EXIT_USAGE

    failures = validate_receipt(receipt, lock, args.expect_fw)
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    if failures:
        return EXIT_INVALID
    print("round receipt OK")
    return EXIT_VALID


if __name__ == "__main__":
    raise SystemExit(main())

"""Pure PKCS#1 v1.5 implicit-rejection observation/assessment model (QF4).

Shared by the structured Bleichenbacher node
(``security/test_padding_oracle.py``) and the fixed-garbage node
(``test_errors.py``). Pure: no pytest, no PKCS#11 calls, no randomness, no
classification emission, no cleanup. Callers collect attempt evidence,
observe each sample, assess the complete collection, and only then emit.

Contract summary:

- Only exact output equality to a known would-be payload witnesses plaintext
  exposure. A separator-less encoding has no would-be payload, so zero,
  empty, variable, or stable output alone never proves exposure or safety.
- A CKR_OK final length above the real capacity or the ``CKM_RSA_PKCS``
  ``k-11`` mechanism maximum (OASIS PKCS#11 v3.2, Table 39) is malformed
  output, not exposure.
- ``synthetic_consistent`` needs an independently correct valid control,
  zero rejected invalid attempts, a stable accepted witness repeat,
  non-constant output across enough accepted distinct ciphertexts in both
  original categories, complete output/length evidence on every accepted
  attempt, no zero/empty accepted output, and no category-correlated status
  distinction. Anything short of that is ``unresolved`` unless a hard
  finding fired.
- ``clean`` needs a non-empty collection with zero accepted invalid attempts
  plus a correct valid control; an empty collection is incomplete evidence.
- A first-attempt category-RV difference is a proved crypto oracle only with
  bounded repeated category-correlated status evidence (past the two
  earliest-collected samples of each category, some status occurs at least
  twice in one category and never in the other). A startup transient or an
  unrepeated flake stays visible unresolved/posture evidence.
- Neither posture outcome is a security certificate: timing and
  side-channel safety are outside this model.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_OK

#: Short-PS witness padding length: ``PS < 8`` is invalid per PKCS#1 v1.5.
V15_PS7_LEN = 7
#: Minimum valid PKCS#1 v1.5 padding-string length.
V15_MIN_PS_LEN = 8
#: ``CKM_RSA_PKCS`` plaintext maximum is ``k - 11`` (OASIS Table 39).
V15_PLAINTEXT_OVERHEAD = 11
#: Earliest-collected first-attempt samples per category excluded from the
#: persistence analysis (ranked by collection sequence, not supplied order).
V15_STARTUP_WINDOW_ITERS = 2
#: Minimum accepted distinct ciphertexts (with non-constant outputs) per
#: original category for a synthetic-consistent assessment.
V15_MIN_ACCEPTS_PER_CATEGORY = 2
#: Outputs at or below this length are retained as exact hex in evidence.
V15_OUTPUT_FULL_HEX_MAX = 256
#: Prefix retained for longer outputs (plus a sha256 digest).
V15_OUTPUT_PREFIX_BYTES = 64

#: Sample categories understood by :func:`observe_v15_sample`.
V15_CATEGORIES = ("cat1", "cat2", "witness", "garbage")


@dataclass(frozen=True)
class V15Attempt:
    """Retained evidence of one semantic decrypt attempt.

    ``rv`` is the exact terminal CK_RV; ``phase`` names where it was produced
    (``"init"``, ``"query"``, or ``"output"``). ``output`` holds exact bytes
    only on CKR_OK (else None); a NULL size query is never output evidence.
    """

    rv: int
    phase: str = "output"
    init_rv: int | None = None
    query_rv: int | None = None
    query_estimate: int | None = None
    output_rv: int | None = None
    reported_len: int | None = None
    capacity: int | None = None
    output: bytes | None = None

    @property
    def accepted(self) -> bool:
        return int(self.rv) == int(CKR_OK)


@dataclass(frozen=True)
class V15SampleObservation:
    """Per-sample evidence: inputs, both attempts, and derived relations.

    ``seq`` is the collection-order sequence number assigned by the caller at
    collection time. Startup-window membership is anchored to it, so the
    assessment verdict is order-independent; serialization keeps the supplied
    order. ``seq`` values must be unique within one assessed collection:
    :func:`assess_v15_samples` rejects tied sequences instead of ranking
    them by supplied order (which would keep the verdict order-dependent).
    """

    sample_id: str
    category: str
    historical: bool
    encoded: bytes | None
    ciphertext: bytes
    first: V15Attempt
    repeated: V15Attempt | None
    would_be_plaintext: bytes | None
    modulus_len: int
    seq: int = 0

    @property
    def any_accepted(self) -> bool:
        return self.first.accepted or (self.repeated is not None and self.repeated.accepted)

    def _is_witness_output(self, attempt: V15Attempt) -> bool:
        return (
            self.would_be_plaintext is not None
            and attempt.accepted
            and attempt.output is not None
            and attempt.output == self.would_be_plaintext
        )

    @property
    def witness(self) -> bool:
        """True only for exact output equality to the known would-be payload."""
        if self._is_witness_output(self.first):
            return True
        return self.repeated is not None and self._is_witness_output(self.repeated)

    @property
    def witness_attempt(self) -> str | None:
        if self._is_witness_output(self.first):
            return "first"
        if self.repeated is not None and self._is_witness_output(self.repeated):
            return "repeat"
        return None

    def _is_overlong(self, attempt: V15Attempt) -> bool:
        if not attempt.accepted or attempt.reported_len is None:
            return False
        if attempt.capacity is not None and attempt.reported_len > attempt.capacity:
            return True
        return attempt.reported_len > self.modulus_len - V15_PLAINTEXT_OVERHEAD

    @property
    def overlong_attempts(self) -> tuple[str, ...]:
        """Attempt labels with a CKR_OK length violation (capacity / k-11)."""
        labels: list[str] = []
        if self._is_overlong(self.first):
            labels.append("first")
        if self.repeated is not None and self._is_overlong(self.repeated):
            labels.append("repeat")
        return tuple(labels)

    @property
    def stable(self) -> bool | None:
        """Same RV, exact length, and exact bytes across first/repeat.

        None when no repeat ran. Stability alone proves neither exposure nor
        implicit rejection; it is one input to the cross-sample assessment.
        """
        if self.repeated is None:
            return None
        return (
            int(self.repeated.rv) == int(self.first.rv)
            and self.repeated.reported_len == self.first.reported_len
            and self.repeated.output == self.first.output
        )


def observe_v15_sample(
    *,
    sample_id: str,
    category: str,
    historical: bool,
    encoded: bytes | None,
    ciphertext: bytes,
    first: V15Attempt,
    repeated: V15Attempt | None = None,
    would_be_plaintext: bytes | None = None,
    modulus_len: int,
    seq: int = 0,
) -> V15SampleObservation:
    """Build one sample observation, retaining bypass/length/stability relations."""
    if category not in V15_CATEGORIES:
        raise ValueError(f"unknown v1.5 sample category: {category!r}")
    return V15SampleObservation(
        sample_id=sample_id,
        category=category,
        historical=historical,
        encoded=encoded,
        ciphertext=ciphertext,
        first=first,
        repeated=repeated,
        would_be_plaintext=would_be_plaintext,
        modulus_len=modulus_len,
        seq=seq,
    )


@dataclass(frozen=True)
class V15ValidControl:
    """The independently constructed valid ciphertext and its attempt."""

    encoded: bytes
    ciphertext: bytes
    expected_plaintext: bytes
    attempt: V15Attempt

    @property
    def status(self) -> str:
        """``"correct"``, ``"wrong_output"``, or ``"rejected"``."""
        if not self.attempt.accepted:
            return "rejected"
        if self.attempt.output == self.expected_plaintext:
            return "correct"
        return "wrong_output"


@dataclass(frozen=True)
class V15Oracle:
    """Category-status assessment over first-attempt RVs.

    ``status`` is ``"none"`` (equal first-attempt sets), ``"persistent"``
    (bounded repeated category-correlated status evidence), or
    ``"transient"`` (sets differ only within the startup window or through
    unrepeated statuses: visible unresolved evidence, not a proved oracle).
    """

    status: str
    cat1: tuple[str, ...]
    cat2: tuple[str, ...]
    cat1_post_window: tuple[str, ...]
    cat2_post_window: tuple[str, ...]
    window_iters: int
    correlated: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class V15Assessment:
    """Cross-sample assessment over a complete collection.

    ``posture`` is ``"clean"`` (a non-empty uniform correct rejection plus a
    correct valid control), ``"synthetic_consistent"`` (all synthetic gates
    hold), or ``"unresolved"`` (everything else, including every hard-finding
    case and every incomplete collection).
    """

    observations: tuple[V15SampleObservation, ...]
    valid_control: V15ValidControl | None
    witnesses: tuple[V15SampleObservation, ...]
    overlong: tuple[V15SampleObservation, ...]
    oracle: V15Oracle
    valid_status: str
    posture: str
    gates: dict[str, bool]


def _assess_oracle(cat1: list[V15SampleObservation], cat2: list[V15SampleObservation]) -> V15Oracle:
    """Assess the first-attempt category-status distinction, if any.

    Startup-window membership follows collection sequence (``seq``), so the
    verdict is order-independent; only the window ranking uses ``seq``.
    Callers must supply unique ``seq`` values (enforced by
    :func:`assess_v15_samples`); the stable sort below only preserves
    determinism and must never resolve a ``seq`` tie.
    """
    ranked1 = sorted(cat1, key=lambda obs: obs.seq)
    ranked2 = sorted(cat2, key=lambda obs: obs.seq)
    post1 = [obs.first.rv for obs in ranked1[V15_STARTUP_WINDOW_ITERS:]]
    post2 = [obs.first.rv for obs in ranked2[V15_STARTUP_WINDOW_ITERS:]]
    full1 = [obs.first.rv for obs in cat1]
    full2 = [obs.first.rv for obs in cat2]
    correlated: list[tuple[str, str]] = []
    for rv in sorted(set(post1) | set(post2)):
        in_cat1 = post1.count(rv)
        in_cat2 = post2.count(rv)
        if in_cat1 >= 2 and in_cat2 == 0:
            correlated.append((ckr_name(int(rv)), "cat1"))
        if in_cat2 >= 2 and in_cat1 == 0:
            correlated.append((ckr_name(int(rv)), "cat2"))
    if set(full1) == set(full2):
        status = "none"
    elif correlated:
        status = "persistent"
    else:
        status = "transient"
    return V15Oracle(
        status=status,
        cat1=tuple(sorted({ckr_name(int(rv)) for rv in full1})),
        cat2=tuple(sorted({ckr_name(int(rv)) for rv in full2})),
        cat1_post_window=tuple(sorted({ckr_name(int(rv)) for rv in post1})),
        cat2_post_window=tuple(sorted({ckr_name(int(rv)) for rv in post2})),
        window_iters=V15_STARTUP_WINDOW_ITERS,
        correlated=tuple(correlated),
    )


def _category_variation(observations: list[V15SampleObservation]) -> bool:
    """At least two accepted distinct ciphertexts with non-constant outputs."""
    distinct_inputs: set[bytes] = set()
    distinct_outputs: set[bytes] = set()
    for obs in observations:
        if not obs.first.accepted or obs.first.output is None:
            continue
        distinct_inputs.add(obs.ciphertext)
        distinct_outputs.add(obs.first.output)
    return (
        len(distinct_inputs) >= V15_MIN_ACCEPTS_PER_CATEGORY
        and len(distinct_outputs) >= V15_MIN_ACCEPTS_PER_CATEGORY
    )


def _accepted_attempts_complete(observations: tuple[V15SampleObservation, ...]) -> bool:
    """Every accepted attempt carries its output bytes and reported length."""
    attempts: list[V15Attempt] = []
    for obs in observations:
        attempts.append(obs.first)
        if obs.repeated is not None:
            attempts.append(obs.repeated)
    return all(
        not attempt.accepted or (attempt.output is not None and attempt.reported_len is not None)
        for attempt in attempts
    )


def _accepted_outputs_nonzero(observations: tuple[V15SampleObservation, ...]) -> bool:
    """No accepted output is empty or all-zero (explicitly non-proving)."""
    for obs in observations:
        for attempt in (obs.first, obs.repeated):
            if attempt is None or not attempt.accepted or attempt.output is None:
                continue
            if len(attempt.output) == 0 or all(byte == 0 for byte in attempt.output):
                return False
    return True


def _synthetic_gates(
    observations: tuple[V15SampleObservation, ...],
    cat1: list[V15SampleObservation],
    cat2: list[V15SampleObservation],
) -> dict[str, bool]:
    """Per-gate breakdown of the synthetic-consistent posture (all must hold)."""
    no_rejects = all(obs.first.accepted for obs in observations) and all(
        obs.repeated is None or obs.repeated.accepted for obs in observations
    )
    witness_stable = any(
        obs.category == "witness"
        and obs.first.accepted
        and obs.repeated is not None
        and obs.repeated.accepted
        and obs.stable is True
        for obs in observations
    )
    return {
        "no_rejects": no_rejects,
        "witness_accepted_stable": witness_stable,
        "cat1_variation": _category_variation(cat1),
        "cat2_variation": _category_variation(cat2),
        "complete_evidence": _accepted_attempts_complete(observations),
        "nonzero_outputs": _accepted_outputs_nonzero(observations),
    }


def assess_v15_samples(
    observations: Sequence[V15SampleObservation],
    valid_control: V15ValidControl | None,
    *,
    modulus_len: int,
) -> V15Assessment:
    """Assess a complete collection: witnesses, oracle, control, posture.

    Order-independent for the verdict (startup-window membership follows
    collection sequence); input order is preserved in the retained
    observations for serialized evidence. Fails closed: any hard evidence, a
    non-correct valid control, or any status distinction forces
    ``"unresolved"``; ``"synthetic_consistent"`` additionally needs every
    synthetic gate, and ``"clean"`` needs a non-empty collection with zero
    accepted invalid attempts. Collections with tied ``seq`` values are
    rejected: ranking ties by supplied order would keep the verdict
    order-dependent, so ambiguity fails closed instead of assessing.
    """
    collected = tuple(observations)
    for obs in collected:
        if obs.modulus_len != modulus_len:
            raise ValueError(
                f"mixed modulus lengths in one assessment: {obs.modulus_len} != {modulus_len}"
            )
    seen: set[int] = set()
    dupes: set[int] = set()
    for obs in collected:
        if obs.seq in seen:
            dupes.add(obs.seq)
        seen.add(obs.seq)
    if dupes:
        raise ValueError(
            "ambiguous collection sequence numbers in one assessment: "
            f"duplicate seq {sorted(dupes)}; startup-window membership "
            "needs unique seqs"
        )
    witnesses = tuple(obs for obs in collected if obs.witness)
    overlong = tuple(obs for obs in collected if obs.overlong_attempts)
    cat1 = [obs for obs in collected if obs.category == "cat1"]
    cat2 = [obs for obs in collected if obs.category == "cat2"]
    oracle = _assess_oracle(cat1, cat2)
    valid_status = "missing" if valid_control is None else valid_control.status
    gates = _synthetic_gates(collected, cat1, cat2)
    hard = bool(witnesses or overlong) or valid_status == "wrong_output"
    hard = hard or oracle.status == "persistent"
    if hard:
        posture = "unresolved"
    elif valid_status != "correct" or oracle.status != "none":
        posture = "unresolved"
    elif collected and not any(obs.any_accepted for obs in collected):
        posture = "clean"
    elif all(gates.values()):
        posture = "synthetic_consistent"
    else:
        posture = "unresolved"
    return V15Assessment(
        observations=collected,
        valid_control=valid_control,
        witnesses=witnesses,
        overlong=overlong,
        oracle=oracle,
        valid_status=valid_status,
        posture=posture,
        gates=gates,
    )


def output_evidence(
    output: bytes | None, *, reported_len: int | None, capacity: int | None
) -> dict[str, Any]:
    """Bounded JSON-safe summary of one attempt's output bytes."""
    if output is None:
        return {"present": False, "reported_len": reported_len, "capacity": capacity}
    detail: dict[str, Any] = {
        "present": True,
        "len": len(output),
        "reported_len": reported_len,
        "capacity": capacity,
        "sha256": sha256(output).hexdigest(),
    }
    if len(output) <= V15_OUTPUT_FULL_HEX_MAX:
        detail["hex"] = output.hex()
    else:
        detail["prefix_hex"] = output[:V15_OUTPUT_PREFIX_BYTES].hex()
    return detail


def attempt_evidence(attempt: V15Attempt) -> dict[str, Any]:
    """JSON-safe phase-specific evidence of one attempt."""
    return {
        "rv": ckr_name(int(attempt.rv)),
        "rv_value": int(attempt.rv),
        "phase": attempt.phase,
        "init_rv": None if attempt.init_rv is None else ckr_name(int(attempt.init_rv)),
        "query_rv": None if attempt.query_rv is None else ckr_name(int(attempt.query_rv)),
        "query_estimate": attempt.query_estimate,
        "output_rv": None if attempt.output_rv is None else ckr_name(int(attempt.output_rv)),
        "reported_len": attempt.reported_len,
        "capacity": attempt.capacity,
        "output": output_evidence(
            attempt.output,
            reported_len=attempt.reported_len,
            capacity=attempt.capacity,
        ),
    }


def sample_evidence(obs: V15SampleObservation) -> dict[str, Any]:
    """JSON-safe replayable evidence of one sample observation."""
    return {
        "sample_id": obs.sample_id,
        "seq": obs.seq,
        "category": obs.category,
        "historical": obs.historical,
        "encoded_hex": None if obs.encoded is None else obs.encoded.hex(),
        "ciphertext_hex": obs.ciphertext.hex(),
        "would_be_known": obs.would_be_plaintext is not None,
        "would_be_len": None if obs.would_be_plaintext is None else len(obs.would_be_plaintext),
        "would_be_hex": None if obs.would_be_plaintext is None else obs.would_be_plaintext.hex(),
        "first": attempt_evidence(obs.first),
        "repeated": None if obs.repeated is None else attempt_evidence(obs.repeated),
        "witness": obs.witness,
        "witness_attempt": obs.witness_attempt,
        "overlong_attempts": list(obs.overlong_attempts),
        "stable": obs.stable,
    }


def control_evidence(valid: V15ValidControl) -> dict[str, Any]:
    """JSON-safe evidence of the independent valid control."""
    return {
        "sample_id": "valid-control",
        "encoded_hex": valid.encoded.hex(),
        "ciphertext_hex": valid.ciphertext.hex(),
        "expected_hex": valid.expected_plaintext.hex(),
        "expected_len": len(valid.expected_plaintext),
        "attempt": attempt_evidence(valid.attempt),
        "status": valid.status,
    }


def assessment_evidence(
    assessment: V15Assessment,
    *,
    modulus_len: int,
    public_exponent: int,
    modulus: int,
) -> dict[str, Any]:
    """JSON-safe replayable evidence of a complete assessment."""
    oracle = assessment.oracle
    return {
        "k": modulus_len,
        "e": public_exponent,
        "n_hex": modulus.to_bytes(modulus_len, "big").hex(),
        "repeat_policy": "witness-only-unconditional",
        "semantic_decrypts": sum(
            1 + (1 if obs.repeated is not None else 0) for obs in assessment.observations
        )
        + (1 if assessment.valid_control is not None else 0),
        "oracle": {
            "status": oracle.status,
            "cat1": list(oracle.cat1),
            "cat2": list(oracle.cat2),
            "cat1_post_window": list(oracle.cat1_post_window),
            "cat2_post_window": list(oracle.cat2_post_window),
            "window_iters": oracle.window_iters,
            "correlated": [{"rv": rv, "category": category} for rv, category in oracle.correlated],
        },
        "valid": assessment.valid_status,
        "posture": assessment.posture,
        "gates": dict(assessment.gates),
        "witnesses": [obs.sample_id for obs in assessment.witnesses],
        "overlong": [obs.sample_id for obs in assessment.overlong],
        "samples": [sample_evidence(obs) for obs in assessment.observations],
        "valid_control": None
        if assessment.valid_control is None
        else control_evidence(assessment.valid_control),
    }


__all__ = [
    "V15_MIN_ACCEPTS_PER_CATEGORY",
    "V15_MIN_PS_LEN",
    "V15_OUTPUT_FULL_HEX_MAX",
    "V15_OUTPUT_PREFIX_BYTES",
    "V15_PLAINTEXT_OVERHEAD",
    "V15_PS7_LEN",
    "V15_STARTUP_WINDOW_ITERS",
    "V15_CATEGORIES",
    "V15Assessment",
    "V15Attempt",
    "V15Oracle",
    "V15SampleObservation",
    "V15ValidControl",
    "assess_v15_samples",
    "assessment_evidence",
    "attempt_evidence",
    "control_evidence",
    "observe_v15_sample",
    "output_evidence",
    "sample_evidence",
]

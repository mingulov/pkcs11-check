"""Crashing-daemon recovery policy (roadmap #2 / GH issue #5).

External-first, liveness-gated recovery for a daemon-backed PKCS#11 provider whose daemon crashes
mid-suite. The framework does NOT restart the service (that is the operator's / supervisor's job);
it detects the death via a fresh-subprocess liveness probe, records the crash finding, waits (or
invokes an opt-in no-shell command) for the daemon to return, supersedes the cascade of false
failures, and resumes or aborts honestly.

This module is the POLICY, deliberately isolated from the runner loop and unit-testable via
injected ``probe``/``recover`` callables. See the spec
``docs/superpowers/specs/2026-07-16-crashing-daemon-recovery-design.md`` (rev. 3) and the plan
``docs/superpowers/plans/2026-07-17-crashing-daemon-recovery.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

RecoveryMode = Literal["off", "wait", "cmd"]


@dataclass(frozen=True)
class RecoveryConfig:
    """Immutable recovery policy configuration (built from CLI/env/TOML; see to_recovery_config)."""

    mode: RecoveryMode
    recover_cmd: list[str] | None
    wait_s: float
    max_attempts: int
    max_total: int
    hint_rvs: frozenset[str]
    consecutive_threshold: int
    quarantine_after: int
    cmd_timeout_s: float
    probe_timeout_s: float


class RecoveryOutcome(Enum):
    """What the runner should do with the current unit after an assessment."""

    CONTINUE = "continue"
    RECOVERED_RETRY = "recovered_retry"
    QUARANTINE = "quarantine"
    ABORT = "abort"


@dataclass
class RecoveryAssessment:
    """The controller's verdict for one unit: outcome + any units to re-queue + records to emit."""

    outcome: RecoveryOutcome
    requeue_units: list[str] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)


class RecoveryController:
    """Stateful across the run: current failure streak, per-unit recovery counts, total recoveries.

    ``assess`` is called once per completed unit. ``probe`` returns True iff the provider is live;
    ``recover`` performs one recovery cycle (wait-only in ``wait`` mode, or run the command then
    wait in ``cmd`` mode) and returns whether it ran without error. Inert when ``config.mode`` is
    ``"off"``: ``assess`` returns CONTINUE without ever probing.
    """

    def __init__(
        self,
        config: RecoveryConfig,
        *,
        probe: Callable[[], bool],
        recover: Callable[[], bool],
    ) -> None:
        self._config = config
        self._probe = probe
        self._recover = recover
        self._streak: list[str] = []
        self._recover_counts: dict[str, int] = {}
        self._total = 0

    def assess(
        self, unit: str, unit_status: str, unit_hint_rvs: frozenset[str]
    ) -> RecoveryAssessment:
        """Assess one completed unit and decide the recovery action (see module docstring)."""
        if self._config.mode == "off":
            return RecoveryAssessment(RecoveryOutcome.CONTINUE)
        # Suspicion + confirmation logic lands in Task 3.
        return RecoveryAssessment(RecoveryOutcome.CONTINUE)

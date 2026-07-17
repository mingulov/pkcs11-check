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

import shlex
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core.preflight import run_preflight_subprocess

RecoveryMode = Literal["off", "wait", "cmd"]

# Unit outcomes that count as a failure for streak/suspicion purposes. A "passed" unit proves
# the provider is live and breaks the streak; anything else neutral (skips) is left untouched.
_FAILURE_STATUSES = frozenset({"failed", "crashed", "error", "timeout"})


def probe_provider_liveness(module: Path, *, interface: str, slot: int, timeout: int) -> bool:
    """Return True iff the provider is reachable, via a fresh-subprocess liveness probe.

    Wraps ``run_preflight_subprocess`` (C_Initialize + C_GetSlotList/mechanism enumeration in an
    isolated subprocess) and returns True iff its manifest status is ``"ok"``. Any exception (a
    module that cannot even be loaded) is treated as dead. Running in a subprocess is deliberate:
    a probe against a crashing provider must not take the runner down with it.

    NOTE: this is reachability-only. The spec's optional crypto-liveness step (a capability-gated
    ``C_GenerateRandom`` to catch a "reachable but crypto-dead" daemon) is deferred: doing it
    in-process would add a crypto crash surface to the recovery probe itself, and doing it in the
    subprocess is a separate preflight change. The residual (a daemon whose RPC front-end answers
    but whose crypto backend died) records real per-op results verbatim -- recorded, never hidden.
    """
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            output_path = Path(fh.name)
        manifest = run_preflight_subprocess(
            module,
            interface=interface,
            slot=slot,
            timeout=timeout,
            output_path=output_path,
        )
    except (OSError, ValueError):
        return False
    finally:
        try:
            output_path.unlink()
        except (OSError, NameError, UnboundLocalError):
            pass
    return getattr(manifest, "status", None) == "ok"


def run_recover_cmd(argv: list[str], *, timeout: float) -> bool:
    """Run the operator recovery command as an argv list, NEVER via a shell.

    ``shell=False`` and no metacharacter interpretation, so provider-controlled output can never
    inject. Returns True iff the command exits 0. Any failure to launch, non-zero exit, or timeout
    returns False (the caller counts it as a failed recovery attempt).
    """
    try:
        completed = subprocess.run(argv, shell=False, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


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


def build_recovery_config(
    *,
    mode: str = "off",
    recover_cmd: str | None = None,
    wait_s: float = 5.0,
    max_attempts: int = 12,
    max_total: int = 20,
    hint_rv: str = "CKR_DEVICE_REMOVED",
    consecutive_threshold: int = 3,
    quarantine_after: int = 2,
    cmd_timeout_s: float = 30.0,
    probe_timeout_s: float = 30.0,
) -> RecoveryConfig:
    """Build a RecoveryConfig from raw CLI/env values (defaults sized for a real supervisor).

    ``recover_cmd`` is tokenized with ``shlex.split`` (tokenize only, never shell-executed).
    Providing ``--recover-cmd`` with ``mode`` left ``"off"`` implies ``"cmd"``; ``mode == "cmd"``
    without a command is a configuration error. ``wait_s`` * ``max_attempts`` (~60s by default)
    is how long ``wait`` mode waits for the external supervisor before aborting -- it must exceed
    the supervisor's worst-case restart+backoff window.
    """
    cmd_list = shlex.split(recover_cmd) if recover_cmd else None
    effective_mode: RecoveryMode
    if mode == "off" and cmd_list:
        effective_mode = "cmd"  # --recover-cmd alone implies cmd
    elif mode in ("off", "wait", "cmd"):
        effective_mode = mode  # type: ignore[assignment]
    else:
        raise ValueError(f"invalid recover-mode {mode!r} (expected off|wait|cmd)")
    if effective_mode == "cmd" and not cmd_list:
        raise ValueError("recover-mode 'cmd' requires --recover-cmd")
    hint_rvs = frozenset(h.strip() for h in hint_rv.split(",") if h.strip())
    return RecoveryConfig(
        mode=effective_mode,
        recover_cmd=cmd_list,
        wait_s=wait_s,
        max_attempts=max_attempts,
        max_total=max_total,
        hint_rvs=hint_rvs,
        consecutive_threshold=consecutive_threshold,
        quarantine_after=quarantine_after,
        cmd_timeout_s=cmd_timeout_s,
        probe_timeout_s=probe_timeout_s,
    )


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

    def _event_record(self, trigger_unit: str) -> dict[str, Any]:
        """The immutable synthetic finding emitted on each confirmed daemon death.

        Standalone record (its own synthetic identity) carrying the streak as candidate causes.
        Never written over a unit's records, so it always survives the re-queue.
        """
        return {
            "reason": "crash",
            "kind": "lifecycle",
            "label": "provider became unreachable (liveness probe failed)",
            "trigger_unit": trigger_unit,
            "streak": list(self._streak),
        }

    def assess(
        self, unit: str, unit_status: str, unit_hint_rvs: frozenset[str]
    ) -> RecoveryAssessment:
        """Assess one completed unit and decide the recovery action (see module docstring).

        Two-stage, liveness-gated: a cheap suspicion hint decides WHEN to run the fresh-subprocess
        probe; only a failing probe (provider actually unreachable) ever recovers. A passing probe
        records the unit's result normally and resets the consecutive-failure counter.
        """
        cfg = self._config
        if cfg.mode == "off":
            return RecoveryAssessment(RecoveryOutcome.CONTINUE)

        if unit_status not in _FAILURE_STATUSES:
            if unit_status == "passed":
                self._streak.clear()  # a real pass proves liveness; break the streak
            return RecoveryAssessment(RecoveryOutcome.CONTINUE)

        # A failing / crashing unit: extend the streak, then decide whether to probe.
        self._streak.append(unit)
        suspicious = (
            bool(unit_hint_rvs & cfg.hint_rvs)
            or len(self._streak) >= cfg.consecutive_threshold
            or unit_status == "crashed"
        )
        if not suspicious:
            return RecoveryAssessment(RecoveryOutcome.CONTINUE)

        if self._probe():
            # Provider is alive: the failures are real (never masked); reset the counter so a
            # legitimately-failing provider does not re-probe on every subsequent failure.
            self._streak.clear()
            return RecoveryAssessment(RecoveryOutcome.CONTINUE)

        # Provider is down. Record the immutable crash finding FIRST, then recover.
        event = self._event_record(unit)
        self._total += 1
        if self._total > cfg.max_total:
            return RecoveryAssessment(RecoveryOutcome.ABORT, records=[event])

        recovered = False
        for _ in range(cfg.max_attempts):
            self._recover()
            if self._probe():
                recovered = True
                break
        if not recovered:
            return RecoveryAssessment(RecoveryOutcome.ABORT, records=[event])

        self._recover_counts[unit] = self._recover_counts.get(unit, 0) + 1
        if self._recover_counts[unit] >= cfg.quarantine_after:
            # This unit reproducibly kills the daemon -> confirmed finding + quarantine.
            return RecoveryAssessment(RecoveryOutcome.QUARANTINE, records=[event])

        requeue = list(self._streak)
        self._streak.clear()
        return RecoveryAssessment(
            RecoveryOutcome.RECOVERED_RETRY, requeue_units=requeue, records=[event]
        )

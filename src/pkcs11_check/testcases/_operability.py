"""Effect-based mechanism operability probe (triage H2).

KAT runners used to xfail "advertised but not operational" mechanisms via
narrow per-CKR allowlists ({MECHANISM_INVALID, MECHANISM_PARAM_INVALID}); any
other clean error on a positive-op vector hard-failed, so a module returning
e.g. CKR_GENERAL_ERROR for a wholly non-operational mechanism produced
thousands of misleading failures (bouncyhsm AES-CCM), while widening the list
blindly could mask real breaks.

This module classifies by EFFECT instead: run ONE canonical known-answer
operation per (mechanism, direction) per process and reuse the verdict:

- ``OPERATIONAL``     canonical OK + correct output. The mechanism works;
                      vector failures stay findings. Only spec-legal
                      parameter-shape rejects remain xfail material.
- ``NOT_OPERATIONAL`` canonical clean CKR error, regardless of which code.
                      Advertised but not operational -> vector clean errors
                      xfail. No provider identity, no CKR allowlist.
- ``WRONG_OUTPUT``    canonical OK but WRONG output: a crypto break. Never
                      masks anything; vector errors stay findings.
- ``INCONCLUSIVE``    the canonical op could not be staged (key import or
                      parameter packing failed). No mechanism evidence (the
                      import path may be broken, see triage H6) -> fall back
                      to the legacy param-shape rules.

Non-CKR exceptions from the probe or the vector are harness bugs and always
propagate. See docs/findings/issues-triage.md (H2) and the classification
model's positive-op row.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import NoReturn

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


class Operability(Enum):
    OPERATIONAL = "operational"
    NOT_OPERATIONAL = "not-operational"
    WRONG_OUTPUT = "wrong-output"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class OperabilityResult:
    status: Operability
    detail: str


# Request-shape rejects that are xfail material even when the mechanism is
# operational: the module cleanly refused THIS request shape (e.g. kryoptic
# rejects 7-byte CCM nonces; corePKCS11-style impls use ARGUMENTS_BAD for
# input-shape constraints) -- a recorded deviation, not a crypto failure.
# Data-verdict and generic-failure codes stay OUT: on an operational mechanism
# those are findings (meta-test pinned).
PARAM_SHAPE_REJECTS: tuple[int, ...] = (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_CACHE: dict[str, OperabilityResult] = {}


def probe_operability(key: str, probe: Callable[[], OperabilityResult]) -> OperabilityResult:
    """Run ``probe`` once per ``key`` per process and cache the verdict.

    ``key`` should name the mechanism, the relevant parameter class and the
    direction, e.g. ``"AES_CCM:encrypt"`` or ``"RSA_OAEP:sha512_224:decrypt"``.
    """
    if key not in _CACHE:
        _CACHE[key] = probe()
    return _CACHE[key]


def reset_operability_cache() -> None:
    """Test hook: forget cached probe verdicts."""
    _CACHE.clear()


def classify_kat_clean_error(
    exc: AssertionError,
    *,
    result: OperabilityResult,
    label: str,
) -> NoReturn:
    """Classify a clean CKR raised by a positive KAT vector operation.

    Call from the runner's ``except AssertionError`` with the canonical-probe
    verdict for the same (mechanism, direction). Either xfails (recorded
    deviation) or re-raises ``exc`` (the finding stands).
    """
    if not isinstance(exc, CkrAssertionError):
        # Not a module return code -- a harness/ctypes bug must never be
        # classified as "not operational".
        raise exc
    if result.status is Operability.NOT_OPERATIONAL:
        pytest.xfail(f"{label}: advertised but not operational ({result.detail}); vector: {exc}")
    if result.status is not Operability.WRONG_OUTPUT and exc.rv in PARAM_SHAPE_REJECTS:
        # OPERATIONAL: the mechanism works, this parameter shape was cleanly
        # refused. INCONCLUSIVE: no effect evidence either way -- keep the
        # legacy param-shape classification rather than inventing findings.
        pytest.xfail(f"{label}: this parameter shape rejected ({result.detail}); vector: {exc}")
    raise exc

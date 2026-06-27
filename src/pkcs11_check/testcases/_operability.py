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
propagate. See the classification model's positive-op row.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import NoReturn

from pkcs11_check.classification import xfail_as
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


# Request-shape rejects that remain xfail material when the probe is
# INCONCLUSIVE (no effect evidence; e.g. the import path is broken, see H6):
# the module cleanly refused THIS request shape (kryoptic rejects 7-byte CCM
# nonces; corePKCS11-style impls use ARGUMENTS_BAD for input-shape
# constraints). Data-verdict and generic-failure codes stay OUT (meta-test
# pinned): with no canonical evidence, blanket-xfailing those would have
# hidden the H6 mass-import failure. With an OPERATIONAL canonical, ANY clean
# CKR is the model's honest-deviation xfail and this set is not consulted.
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


def not_operational_reason(probe_key: str, detail: str) -> str:
    """Canonical advertised-but-not-operational wording, shared across suites.

    One wording per (mechanism, operation) probe key lets report readers group
    the claim-layer signal with its corroborating per-vector xfails.
    """
    return f"{probe_key}: advertised but not operational ({detail})"


def xfail_vacuous_reject(result: OperabilityResult, *, label: str) -> None:
    """Downgrade a negative-op "rejection" on a NOT_OPERATIONAL mechanism.

    The module refuses everything, so the invalid input was never evaluated;
    counting the rejection as pass asserts conformance that was never tested
    (gap-analysis leak 1). Returns normally for every other verdict --
    OPERATIONAL rejections are genuine passes and INCONCLUSIVE (staging
    failure, no mechanism evidence) keeps legacy rules.
    """
    if result.status is Operability.NOT_OPERATIONAL:
        from pkcs11_check.classification import classify

        classify(
            "not_operational",
            label=label,
            summary=(
                f"{label}: vacuous reject -- mechanism not operational "
                f"({result.detail}); input never evaluated"
            ),
        )


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
        xfail_as(
            "not_operational",
            label=label,
            actual=exc.rv,
            summary=f"{not_operational_reason(label, result.detail)}; vector: {exc}",
        )
    if result.status is Operability.OPERATIONAL:
        # Classification model, positive-op row: a clean error is an honest
        # deviation (the module refused; it produced no wrong crypto) -> xfail,
        # whatever the code. Only wrong output / crash / self-contradiction
        # fail; decrypt-side false-rejects of VALID data are verdict errors and
        # are handled by the runners before reaching here.
        xfail_as(
            "honest_deviation",
            label=label,
            actual=exc.rv,
            summary=(
                f"{label}: mechanism operational but this request cleanly rejected "
                f"({result.detail}); vector: {exc}"
            ),
        )
    if result.status is Operability.INCONCLUSIVE and exc.rv in PARAM_SHAPE_REJECTS:
        # No effect evidence either way (canonical staging failed -- e.g. a
        # broken import path, triage H6). Keep the narrow legacy param-shape
        # classification; blanket-xfailing here would have hidden H6.
        xfail_as(
            "nonspec_reject",
            label=label,
            actual=exc.rv,
            summary=f"{label}: this parameter shape rejected ({result.detail}); vector: {exc}",
        )
    # INCONCLUSIVE with a non-shape code, or canonical WRONG_OUTPUT: surface it.
    raise exc

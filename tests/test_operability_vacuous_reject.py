"""Meta-tests: shared not-operational reason + vacuous-reject downgrade helper.

A negative-op vector "rejected" by a mechanism whose canonical probe says
NOT_OPERATIONAL was never evaluated -- recording it as pass asserts conformance
that was not tested. xfail_vacuous_reject downgrades exactly that case; all
other probe verdicts leave the legacy pass untouched.
"""

from __future__ import annotations

import pytest

from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    not_operational_reason,
    xfail_vacuous_reject,
)


def test_not_operational_reason_wording() -> None:
    """Canonical wording matches the existing classify_kat_clean_error message."""
    assert (
        not_operational_reason("AES_CCM:decrypt", "canonical rejected")
        == "AES_CCM:decrypt: advertised but not operational (canonical rejected)"
    )


def test_vacuous_reject_not_operational_xfails() -> None:
    result = OperabilityResult(Operability.NOT_OPERATIONAL, "canonical CCM decrypt rejected")
    with pytest.raises(pytest.xfail.Exception, match="vacuous reject"):
        xfail_vacuous_reject(result, label="tc42: AES_CCM decrypt")


@pytest.mark.parametrize(
    "status",
    [Operability.OPERATIONAL, Operability.INCONCLUSIVE, Operability.WRONG_OUTPUT],
)
def test_vacuous_reject_other_verdicts_return(status: Operability) -> None:
    """OPERATIONAL/INCONCLUSIVE/WRONG_OUTPUT: rejection of invalid input stays a pass."""
    xfail_vacuous_reject(OperabilityResult(status, "detail"), label="tc42: AES_CCM decrypt")

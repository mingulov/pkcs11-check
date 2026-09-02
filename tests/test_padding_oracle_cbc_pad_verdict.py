"""The AES-CBC-PAD sweep must reach a verdict that does not depend on luck.

``test_cbc_pad_all_last_block_positions`` corrupts each byte of the last ciphertext
block over 20 random key+IV trials and inspects the resulting outcomes. Its verdict used
to be "more than one distinct outcome => CRITICAL padding-oracle finding", which is a
coin flip:

* corrupting the LAST ciphertext block randomises that whole block's plaintext, and for a
  32-byte plaintext that block is pure padding, so valid PKCS#7 padding requires the
  final byte to land on 0x01 (or 0x0202, ...) -- about 1/256 per probe, NOT the 6/256 the
  original docstring assumed;
* over 320 probes P(no probe ever lands on valid padding) = (1 - 1/256)^320 ~= 29%.

So ~29% of runs saw one outcome and passed, ~71% saw two and raised a CRITICAL. Measured
across three full pool rounds the fail count moved 10 -> 17 -> 14 with the verdict
flipping in BOTH directions on the same provider across five commits (craton-hsm
pass->fail->pass, softhsm2-main-asan fail->pass->fail).

Worse than the flakiness: a two-outcome result is what EVERY conforming CBC-PAD
implementation produces. The mode leaks the Vaudenay channel by construction and the
mitigation is application-level (AES-GCM / encrypt-then-MAC), as that test's own
docstring states. Reporting it as a `fail` accused the majority of conforming providers,
which is the specific false-accusation the classification model exists to prevent.

What IS a real defect is a module that validates no padding at all -- returning CKR_OK
with garbage plaintext for every corruption. That verdict is stable (it does not depend on
any lucky probe) and stays a finding.
"""

from __future__ import annotations

from pkcs11_check.testcases.security.test_padding_oracle import (
    CBC_PAD_FINDING_VERDICTS,
    cbc_pad_verdict,
)

_REJECT = "CKR_ENCRYPTED_DATA_INVALID"
_LEAK = "CKR_OK_DIFFERENT"
_PROBES = 320


def test_uniform_rejection_is_the_mitigated_case() -> None:
    assert cbc_pad_verdict([_REJECT] * _PROBES) == "uniform_reject"


def test_mixed_outcomes_are_the_inherent_mode_channel() -> None:
    outcomes = [_REJECT] * (_PROBES - 7) + [_LEAK] * 7
    assert cbc_pad_verdict(outcomes) == "inherent_channel"


def test_multiple_reject_codes_are_characterization_not_an_oracle() -> None:
    outcomes = [_REJECT] * 200 + ["CKR_DATA_INVALID"] * 120
    verdict = cbc_pad_verdict(outcomes)
    assert verdict == "reject_code_variance"
    assert verdict not in CBC_PAD_FINDING_VERDICTS


def test_accepting_every_corruption_is_unchecked_malleability() -> None:
    assert cbc_pad_verdict([_LEAK] * _PROBES) == "unchecked_malleability"


def test_all_ok_outcomes_with_any_changed_plaintext_remain_a_finding() -> None:
    outcomes = ["CKR_OK_MATCH"] + [_LEAK] * (_PROBES - 1)
    assert cbc_pad_verdict(outcomes) == "accepted_corruption_match"


def test_matching_plaintext_is_a_finding_even_when_every_corruption_matches() -> None:
    assert cbc_pad_verdict(["CKR_OK_MATCH"] * _PROBES) == "accepted_corruption_match"


def test_matching_plaintext_is_a_finding_when_mixed_with_rejections() -> None:
    outcomes = [_REJECT] * (_PROBES - 1) + ["CKR_OK_MATCH"]
    assert cbc_pad_verdict(outcomes) == "accepted_corruption_match"


def test_matching_plaintext_takes_precedence_over_other_successes() -> None:
    outcomes = [_REJECT] + ["CKR_OK_MATCH"] + [_LEAK] * (_PROBES - 2)
    assert cbc_pad_verdict(outcomes) == "accepted_corruption_match"


def test_verdict_never_flips_on_a_conforming_module_because_of_luck() -> None:
    """The anti-flakiness invariant.

    These two outcome sets differ ONLY by whether a ~1/256 event happened to occur. A
    conforming module produces either one depending on the random keys of the run, so
    neither may be a finding -- otherwise the same module fails one round and passes the
    next, which is exactly what the three pool rounds recorded.
    """
    unlucky = [_REJECT] * _PROBES
    lucky = [_REJECT] * (_PROBES - 1) + [_LEAK]

    assert cbc_pad_verdict(unlucky) not in CBC_PAD_FINDING_VERDICTS
    assert cbc_pad_verdict(lucky) not in CBC_PAD_FINDING_VERDICTS


def test_unchecked_malleability_remains_a_finding() -> None:
    """Reclassifying the inherent channel must not blunt the real defect."""
    assert cbc_pad_verdict([_LEAK] * _PROBES) in CBC_PAD_FINDING_VERDICTS


def test_single_unexpected_ckr_is_not_silently_treated_as_mitigation() -> None:
    """A module answering with one NON-rejection code is not the mitigated case.

    Uniform CKR_OK_MATCH would mean corruption did not change the plaintext at all,
    which cannot happen for AES-CBC and would indicate the probe never landed.
    """
    assert cbc_pad_verdict(["CKR_OK_MATCH"] * _PROBES) == "accepted_corruption_match"

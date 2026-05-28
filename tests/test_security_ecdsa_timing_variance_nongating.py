"""Regression test for CR-6: ECDSA timing-variance heuristic must be
informational (xfail), not a hard fail.

CV-based timing-leak detection over 100 ECDSA P-256 signatures is
environment-sensitive: OS scheduling jitter alone can push CV past 1.0
on shared CI runners or under load, producing false positives for a
"timing leak". Real Minerva-class attacks (CVE-2019-13627,
CVE-2023-6135) need thousands of signatures plus a bimodal-distribution
statistical analysis -- a single CV>=1.0 over 100 ops is a *flag for
further investigation*, not proof of a leak.

Per the project classification model + the catalog F entry, this is
PKCS11-CHECK: make non-gating / informational. The test should record
the high-variance event (so it is not hidden) and ``xfail``, leaving a
real leak to surface either via the dedicated multi-signature Minerva
suites or via a manual rerun.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases.security import test_cve_regression as tcr


class _ScriptedPerfCounter:
    """time.perf_counter() stub producing a scripted (start,stop) pair stream.

    Given an iterable of *elapsed* durations, returns 0, d0, d0, d0+d1, ... so
    a ``stop - start`` call sees exactly the next scripted elapsed value.
    """

    def __init__(self, elapsed: list[float]) -> None:
        self._stream = iter(_pair_stream(elapsed))

    def __call__(self) -> float:
        return next(self._stream)


def _pair_stream(elapsed: list[float]) -> list[float]:
    out: list[float] = []
    t = 0.0
    for d in elapsed:
        out.append(t)
        t += d
        out.append(t)
        # leave t at the stop value so the next start picks up from here
    return out


def _stub_session(monkeypatch: Any) -> SimpleNamespace:
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(tcr, "gen_ec_keypair", lambda *_a, **_kw: (10, 11))
    monkeypatch.setattr(tcr, "sign_single", lambda *_a, **_kw: b"sig")
    monkeypatch.setattr(tcr, "destroy_quietly", lambda *_a, **_kw: None)
    return rs


def test_ecdsa_timing_variance_low_cv_passes(monkeypatch: Any) -> None:
    rs = _stub_session(monkeypatch)
    # 100 near-constant samples -> CV ~ 0
    monkeypatch.setattr("time.perf_counter", _ScriptedPerfCounter([1e-4] * 100))
    tcr.TestECDSATimingBasic().test_ecdsa_timing_variance(rs)


def test_ecdsa_timing_variance_high_cv_is_xfail_not_fail(monkeypatch: Any) -> None:
    """High CV must be classified as xfail (informational), not a hard fail.

    A 90/10 bimodal between ~1us and ~1ms gives CV ~ 3 -- the kind of
    extreme bimodality a noisy CI scheduler can spuriously produce. The
    heuristic must not hard-fail on it.
    """
    rs = _stub_session(monkeypatch)
    elapsed = [1e-6] * 90 + [1e-3] * 10
    monkeypatch.setattr("time.perf_counter", _ScriptedPerfCounter(elapsed))
    with pytest.raises(pytest.xfail.Exception):
        tcr.TestECDSATimingBasic().test_ecdsa_timing_variance(rs)

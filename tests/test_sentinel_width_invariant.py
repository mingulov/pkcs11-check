"""G2: sentinel-distinctness invariant over both CK_ULONG widths.

Pure-arithmetic companion to the static guards (platform-assumption design
2026-10-25, section 5.2). Two halves:

(a) The production accept-sentinel predicate -- imported from
    ``raw.recipes``, never re-implemented here -- accepts exactly
    ``{sentinel(host_width), sentinel(32)}``. On a 4-byte ``CK_ULONG``
    host that set collapses to the 32-bit spelling alone, so the 64-bit
    spelling is rejected there (a 4-byte field can never carry it).
    If this file copied the predicate, the copy would keep passing
    while production drifted; it must not.
(b) Bridge to the static layer: for every width literal pinned in the
    S4 census, the predicate's verdict matches membership in that
    accepted set, and every file binding BOTH spellings (a
    distinguishing consumer) passes S1, i.e. each of its premises is
    gated, accept-both, or audit-annotated. S4 and the predicate's
    consumer set drifting apart fails here on every host width.

``host_width`` is ``sizeof(c_ulong) * 8`` in normal runs. Under the
sentinel-value sim (``PKCS11_CHECK_SIM_LLP64=1``) it is 32: the sim
collapses the constant to the 32-bit spelling but leaves ``sizeof``
at the real host width, so a sizeof-derived expectation would test
the sim's deliberate falsification rather than the predicate. The sim
is the only mode that overrides sizeof, and the windows-contracts job
does not set it -- real LLP64 expectations there stay sizeof-derived.

Value-level only: this varies Python ints, never a ctypes field width. It
proves nothing about ILP32/big-endian layouts or provider behaviour.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

from pkcs11_check.raw.recipes import _is_unavailable_length
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CK_UNAVAILABLE_INFORMATION_32,
)
from tests.test_platform_width_guard import (
    _S4_CENSUS,
    s1_offenders_in_source,
    s4_bindings_in_source,
)

_ROOT = Path(__file__).resolve().parents[1]
_WIDTHS = (32, 64)


def _sentinel(width: int) -> int:
    return (1 << width) - 1


def _sim_active() -> bool:
    return os.environ.get("PKCS11_CHECK_SIM_LLP64") == "1"


def _host_width() -> int:
    """Effective ``CK_ULONG`` width: sizeof-derived, 32 under the sim."""
    if _sim_active():
        return 32
    return ctypes.sizeof(ctypes.c_ulong) * 8


def _accepted() -> set[int]:
    return {_sentinel(_host_width()), _sentinel(32)}


def test_predicate_accepted_set_is_host_width_relative() -> None:
    accepted = _accepted()
    for width in _WIDTHS:
        value = _sentinel(width)
        assert _is_unavailable_length(value) == (value in accepted), width


def test_predicate_rejects_non_sentinels() -> None:
    for width in _WIDTHS:
        for value in (0, 1, _sentinel(32) - 1, _sentinel(width) - 1, 1 << 32, 1 << 63):
            assert not _is_unavailable_length(value), (width, value)


def test_host_constants_match_width_arithmetic() -> None:
    # Width branch inlined (not via _host_width) so the split stays
    # visible in this body: 4-byte CK_ULONG, or the sim's collapsed
    # constant on a wider host, both make the effective width 32.
    if ctypes.sizeof(ctypes.c_ulong) == 4 or _sim_active():
        host_width = 32
    else:
        host_width = ctypes.sizeof(ctypes.c_ulong) * 8
    assert int(CK_UNAVAILABLE_INFORMATION) == _sentinel(host_width)
    assert int(CK_UNAVAILABLE_INFORMATION_32) == _sentinel(32)
    # The two spellings collapse exactly at effective width 32 -- the
    # premise S1 gates and the sentinel-value sim reproduces.
    if host_width == 32:
        assert int(CK_UNAVAILABLE_INFORMATION) == int(CK_UNAVAILABLE_INFORMATION_32)
    else:
        assert int(CK_UNAVAILABLE_INFORMATION) != int(CK_UNAVAILABLE_INFORMATION_32)


def test_s4_census_values_match_predicate_and_distinguishers_gated() -> None:
    accepted = _accepted()
    censused: dict[str, set[str]] = {}
    for rel, name in _S4_CENSUS:
        censused.setdefault(rel, set()).add(name)

    both_spellings: set[str] = set()
    for rel, names in sorted(censused.items()):
        source = (_ROOT / rel).read_text(encoding="utf-8")
        bindings = s4_bindings_in_source(source)
        assert names <= set(bindings), f"{rel}: S4 pin names not bound: {names - set(bindings)}"
        for name in names:
            value = bindings[name]
            assert _is_unavailable_length(value) == (value in accepted), f"{rel}:{name}"
        if set(bindings.values()) >= {_sentinel(32), _sentinel(64)}:
            both_spellings.add(rel)
            offenders = s1_offenders_in_source(source, rel)
            assert offenders == [], (
                f"{rel} binds both sentinel spellings but has ungated "
                f"distinctness premises: {offenders}"
            )

    # Pin the distingisher set itself: a new both-spellings file must be
    # adjudicated here (gated per S1) rather than appearing silently.
    assert both_spellings == {
        "tests/test_llp64_sim_census.py",
        "tests/test_platform_width_guard.py",
        "tests/test_protected_component_contract.py",
        "tests/test_security_64bit_value_gating.py",
    }

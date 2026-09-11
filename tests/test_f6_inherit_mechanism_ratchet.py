"""F6 ratchet: the set of ``attr_or_record`` sites that can inherit a mechanism may not grow.

``record_as()`` resolves ``mechanism`` as ``if mechanism is None and inherit_mechanism:
mechanism = _active_mechanism``. A ``C_GetAttributeValue`` readback that omits
``inherit_mechanism=False`` therefore stamps whatever mechanism the calling test last made
active onto a record that has nothing to do with it -- and because ``wrap_context_for()``
memoises per session handle, *which* mechanism gets stamped depends on test ordering and
``-k`` selection. That non-determinism was the release-blocking F6 defect.

Most sites emit ``mechanism=None`` today only because ``clear()`` runs at teardown and few
files call ``set_mechanism()``. Nothing enforces that: the 103 sites below are one
``set_mechanism()`` call away, in any of their files, from silently stamping a stale
mechanism onto an unrelated readback. Nothing would fail if that happened, which is why
this guard exists -- the invariant is currently upheld by circumstance, not by a rule.

This is a ratchet, not a zero-tolerance rule -- 103 sites are unconverted at v0.2.0 and
converting them is v0.2.1 work. It fails when a *new* unguarded site appears, so the
backlog can only shrink. When you fix sites, lower the baseline in the same commit; the
failure message tells you the number to write.
"""

from __future__ import annotations

import ast
import collections
import pathlib

TESTCASES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"

# Per-file count of ``attr_or_record`` calls that do NOT pass ``inherit_mechanism=False``,
# as of v0.2.0. Per-file rather than a single total so that fixing one file cannot silently
# pay for a new unguarded site in another.
BASELINE: dict[str, int] = {
    "test_access_control.py": 23,
    "test_hkdf_extended.py": 9,
    "test_keymgmt.py": 8,
    "test_remaining_gaps.py": 7,
    "test_attribute_defaults.py": 6,
    "test_domain_params.py": 6,
    "test_data_objects.py": 5,
    "test_hw_features.py": 5,
    "test_ecdh_extended.py": 4,
    "test_validation_objects.py": 4,
    "test_access_levels.py": 3,
    "test_generic_secret.py": 3,
    "test_ec_curves.py": 2,
    "test_large_objects.py": 2,
    "test_sensitivity.py": 2,
    "test_trust_objects.py": 2,
    "test_attribute_enforcement.py": 1,
    "test_attribute_invariants.py": 1,
    "test_des.py": 1,
    "test_key_flags.py": 1,
    "test_mech_attribute.py": 1,
    "test_mech_keygen.py": 1,
    "test_mech_message.py": 1,
    "test_mech_negative.py": 1,
    "test_misc_kdf.py": 1,
    "test_set_attribute.py": 1,
    "test_sp800_108_kdf.py": 1,
    "test_x942_dh.py": 1,
}


def _unguarded_sites() -> dict[str, list[int]]:
    """Return ``{relative path: [line numbers]}`` for sites that can inherit a mechanism."""
    found: dict[str, list[int]] = collections.defaultdict(list)
    for path in sorted(TESTCASES_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name != "attr_or_record":
                continue
            guarded = any(
                keyword.arg == "inherit_mechanism"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
            if not guarded:
                found[str(path.relative_to(TESTCASES_ROOT))].append(node.lineno)
    return dict(found)


def test_no_new_mechanism_inheriting_attribute_reads() -> None:
    """A new ``attr_or_record`` site must pass ``inherit_mechanism=False``."""
    actual = _unguarded_sites()
    regressions = []
    for name, lines in sorted(actual.items()):
        allowed = BASELINE.get(name, 0)
        if len(lines) > allowed:
            regressions.append(
                f"  {name}: {len(lines)} unguarded sites, baseline {allowed} "
                f"(lines {', '.join(str(line) for line in lines)})"
            )
    assert not regressions, (
        "New attr_or_record call site(s) omit inherit_mechanism=False, so a readback can "
        "inherit the caller's active mechanism and be attributed non-deterministically:\n"
        + "\n".join(regressions)
        + "\n\nPass inherit_mechanism=False at the new site. Do not raise the baseline."
    )


def test_baseline_has_no_stale_entries() -> None:
    """Lower the baseline when sites are fixed, so the ratchet keeps tightening."""
    actual = _unguarded_sites()
    stale = []
    for name, allowed in sorted(BASELINE.items()):
        count = len(actual.get(name, []))
        if count < allowed:
            stale.append(f"  {name}: baseline {allowed}, actually {count}")
    assert not stale, (
        "The ratchet baseline is looser than the tree. Lower these entries (delete the "
        "entry entirely when it reaches 0):\n" + "\n".join(stale)
    )


def test_the_backlog_is_accounted_for() -> None:
    """Every unguarded site lives in a file the baseline names."""
    actual = _unguarded_sites()
    unlisted = sorted(set(actual) - set(BASELINE))
    assert not unlisted, (
        "Unguarded attr_or_record sites in files the baseline does not name: "
        f"{unlisted}. A new file may not introduce mechanism-inheriting readbacks."
    )

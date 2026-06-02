"""Gate semantic-conformance suites off pkcs11-mock (catalog EX-2).

pkcs11-mock is a *harness* mock that returns canned values
("Hello world!"), non-random RNG, fixed labels, and does not really
store objects. Running KAT / ACVP / Wycheproof / security-attack /
crossverify / interop suites against it produces ~1,353 noise rows that
do not describe real provider behavior and drown out signal from other
targets.

This module supplies the small predicates the pytest plugin uses at
collection time to skip those rows on a pkcs11-mock target. Smoke,
diagnostic, and bare tests (no marker, or marker outside the
conformance set) still run -- the mock continues to exercise the
harness's own collection + capability path.
"""

from __future__ import annotations

from collections.abc import Iterable

# Markers whose tests are not meaningful on a canned-value mock. A test
# that carries ANY of these markers is skipped on pkcs11-mock unless the
# user explicitly opts back in (see --p11-allow-mock-conformance in the
# pytest plugin).
#
# Rationale per marker:
#   - kat / acvp / cctv / wycheproof: known-answer vector suites; the mock
#     does not produce the right answers (it returns canned bytes).
#   - security: attack-vector probes need real crypto to detect leaks.
#   - interop / crossverify: compare module output against another impl;
#     mock output is nonsense for the comparison.
#   - padding_oracle / nonce_quality / timing: side-channel / quality
#     heuristics need real crypto execution.
#   - regressions: CVE-class regression tests need real semantics.
#   - fuzz / metamorphic: rely on real round-trip semantics.
_MOCK_INCOMPATIBLE_MARKERS: frozenset[str] = frozenset(
    {
        "acvp",
        "cctv",
        "crossverify",
        "fuzz",
        "interop",
        "kat",
        "metamorphic",
        "nonce_quality",
        "padding_oracle",
        "regressions",
        "security",
        "timing",
        "wycheproof",
    }
)


def is_pkcs11_mock_path(module_path: str | None) -> bool:
    """Return True if ``module_path`` looks like the pkcs11-mock library.

    Matches the patterns ``pkcs11-mock`` and ``pkcs11_mock`` anywhere in
    the path, case-insensitively. ``None`` returns False.
    """
    if module_path is None:
        return False
    lowered = module_path.lower()
    return "pkcs11-mock" in lowered or "pkcs11_mock" in lowered


def is_pkcs11_mock_target(
    module_path: str | None,
    backend_module_path: str | None = None,
) -> bool:
    """Return True when either the loaded module or proxied backend is pkcs11-mock."""
    return is_pkcs11_mock_path(module_path) or is_pkcs11_mock_path(backend_module_path)


def should_skip_on_mock(item_markers: Iterable[str]) -> bool:
    """Return True if a test carrying ``item_markers`` should skip on mock.

    The test is skipped iff at least one marker is in
    ``_MOCK_INCOMPATIBLE_MARKERS``.
    """
    return any(m in _MOCK_INCOMPATIBLE_MARKERS for m in item_markers)

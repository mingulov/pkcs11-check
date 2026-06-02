"""Regression test for EX-2: gate semantic-conformance suites off
pkcs11-mock.

pkcs11-mock is a *harness* mock -- it returns canned values
("Hello world!"), non-random RNG, fixed labels, and does not really
store objects. Running KAT, ACVP, Wycheproof, security-attack, and
similar conformance suites against it is meaningless and dominates the
overall failure inventory (~1,353 rows) without describing real
provider behavior.

The plugin must therefore detect a pkcs11-mock module path and skip
tests carrying any marker from ``_MOCK_INCOMPATIBLE_MARKERS``, while
keeping smoke/diagnostic tests live (so the mock still exercises the
harness's own collection + capability path).
"""

from __future__ import annotations

from pkcs11_check.testcases._mock_gating import (
    _MOCK_INCOMPATIBLE_MARKERS,
    is_pkcs11_mock_path,
    is_pkcs11_mock_target,
    should_skip_on_mock,
)


def test_is_pkcs11_mock_path_matches_known_filenames() -> None:
    assert is_pkcs11_mock_path("/usr/lib/pkcs11/pkcs11-mock.so")
    assert is_pkcs11_mock_path("/opt/pkcs11_mock/libpkcs11_mock.so")
    assert is_pkcs11_mock_path("PKCS11-MOCK.DLL")
    assert not is_pkcs11_mock_path("/usr/lib/softhsm/libsofthsm2.so")
    assert not is_pkcs11_mock_path("/usr/lib/pkcs11/opencryptoki.so")
    assert not is_pkcs11_mock_path(None)


def test_is_pkcs11_mock_target_checks_backend_module_path_for_proxy_shim() -> None:
    assert is_pkcs11_mock_target(
        "/opt/proxy/bin/libpkcs11_proxy_ng_shim.so",
        "/usr/lib64/libpkcs11-mock.so",
    )
    assert not is_pkcs11_mock_target(
        "/opt/proxy/bin/libpkcs11_proxy_ng_shim.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
    )


def test_should_skip_on_mock_for_conformance_markers() -> None:
    for marker in _MOCK_INCOMPATIBLE_MARKERS:
        assert should_skip_on_mock({marker}), marker


def test_should_skip_on_mock_keeps_smoke_diagnostic() -> None:
    assert not should_skip_on_mock({"smoke"})
    assert not should_skip_on_mock({"compliance", "smoke"})
    assert not should_skip_on_mock(set())


def test_should_skip_on_mock_skips_when_any_incompatible_marker_present() -> None:
    # Multi-marker test: a single conformance marker pulls the test out.
    assert should_skip_on_mock({"smoke", "kat"})
    assert should_skip_on_mock({"compliance", "wycheproof"})


def test_mock_incompatible_markers_includes_core_conformance_suites() -> None:
    """The set must include the conformance-bearing suites called out in catalog EX-2."""
    expected = {"kat", "acvp", "cctv", "wycheproof", "security", "interop", "crossverify"}
    assert expected.issubset(_MOCK_INCOMPATIBLE_MARKERS)

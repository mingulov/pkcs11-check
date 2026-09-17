"""Regression tests for AES-CTS variant collection accounting."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.core.test_selection import compute_batch_id, compute_collection_sha256
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKF_ENCRYPT, CKM_AES_CTS, CKR_USER_NOT_LOGGED_IN
from pkcs11_check.testcases.acvp.aes import base_cts
from pkcs11_check.testcases.acvp.aes import conftest as cts_conftest

pytest_plugins = ["pytester"]


class _FakeHook:
    def __init__(self) -> None:
        self.deselected: list[object] = []

    def pytest_deselected(self, *, items: list[object]) -> None:
        self.deselected.extend(items)


class _FakeConfig:
    def __init__(self, *, collectonly: bool = False) -> None:
        self.hook = _FakeHook()
        self.option = SimpleNamespace(collectonly=collectonly)


class _FakeItem:
    def __init__(self, nodeid: str) -> None:
        self.nodeid = nodeid
        self.markers: list[Any] = []

    def add_marker(self, marker: Any) -> None:
        self.markers.append(marker)


class _ProbeConfig:
    def getoption(self, name: str, default: Any = None) -> Any:
        if name == "p11_module":
            return "provider.so"
        return default


def _skip_reasons(item: _FakeItem) -> list[str]:
    reasons: list[str] = []
    for marker in item.markers:
        if getattr(marker, "name", None) == "skip":
            reasons.append(str(marker.kwargs.get("reason", "")))
    return reasons


def test_cts_variant_pruning_keeps_nonmatching_nodes_as_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cts_conftest,
        "_probe_cts_variant",
        lambda _config: base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.DETECTED,
            variant="1",
        ),
    )
    config = _FakeConfig()
    cs1 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs1_encrypt[CBC-CS1-AES-enc-tc1]"
    )
    cs2 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs2_encrypt[CBC-CS2-AES-enc-tc1]"
    )
    items: list[Any] = [cs1, cs2]

    cts_conftest.pytest_collection_modifyitems(config, items)

    assert items == [cs1, cs2]
    assert config.hook.deselected == []
    assert _skip_reasons(cs1) == []
    assert _skip_reasons(cs2) == ["Module implements CS1, skipping CS2 vectors"]


def test_cts_detection_failure_keeps_variant_nodes_as_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cts_conftest,
        "_probe_cts_variant",
        lambda _config: base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.NOT_OPERATIONAL,
        ),
    )
    config = _FakeConfig()
    detect = _FakeItem("src/pkcs11_check/testcases/acvp/aes/test_cts.py::test_cts_variant_detected")
    cs1 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs1_decrypt[CBC-CS1-AES-dec-tc1]"
    )
    cs3 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs3_decrypt[CBC-CS3-AES-dec-tc1]"
    )
    items: list[Any] = [detect, cs1, cs3]

    cts_conftest.pytest_collection_modifyitems(config, items)

    assert items == [detect, cs1, cs3]
    assert config.hook.deselected == []
    assert _skip_reasons(detect) == []
    assert _skip_reasons(cs1) == [
        "CKM_AES_CTS variant detection failed; the selected CTS reporter records "
        "the provider finding"
    ]
    assert _skip_reasons(cs3) == [
        "CKM_AES_CTS variant detection failed; the selected CTS reporter records "
        "the provider finding"
    ]


def test_cts_setup_error_keeps_variant_nodes_as_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An off-contract detection CKR skips variants but keeps the reporter runnable."""
    canned = base_cts.CtsDetectionResult(
        base_cts.CtsDetectionStatus.SETUP_ERROR,
        error_rv=int(CKR_USER_NOT_LOGGED_IN),
        detail={
            "attempts": [
                {
                    "stage": "setup",
                    "operation": "C_CreateObject",
                    "case": None,
                    "ckr": int(CKR_USER_NOT_LOGGED_IN),
                    "key_bits": 256,
                }
            ]
        },
    )
    monkeypatch.setattr(
        cts_conftest,
        "_probe_cts_variant",
        lambda _config: canned,
    )
    config = _FakeConfig()
    detect = _FakeItem("src/pkcs11_check/testcases/acvp/aes/test_cts.py::test_cts_variant_detected")
    cs1 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs1_decrypt[CBC-CS1-AES-dec-tc1]"
    )
    items: list[Any] = [detect, cs1]

    cts_conftest.pytest_collection_modifyitems(config, items)

    assert items == [detect, cs1]
    assert _skip_reasons(detect) == []
    assert _skip_reasons(cs1) == [
        "CKM_AES_CTS variant detection failed with CKR_USER_NOT_LOGGED_IN; "
        "the selected CTS reporter records the provider finding"
    ]


def test_standalone_cts_selection_keeps_detection_guard_runnable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the selected sentinel, a CTS vector must retain its own guard evidence."""
    monkeypatch.setattr(
        cts_conftest,
        "_probe_cts_variant",
        lambda _config: base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.NOT_OPERATIONAL,
        ),
    )
    config = _FakeConfig()
    cs1 = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs1_encrypt[CBC-CS1-AES-enc-tc1]"
    )

    cts_conftest.pytest_collection_modifyitems(config, [cs1])

    assert _skip_reasons(cs1) == []


def test_failed_detection_keeps_one_targeted_reporter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Targeted selections retain one deterministic runnable CTS reporter."""
    monkeypatch.setattr(
        cts_conftest,
        "_probe_cts_variant",
        lambda _config: base_cts.CtsDetectionResult(
            base_cts.CtsDetectionStatus.WRONG_RESULT,
            key_bits=128,
            detail={"output": {"aligned": {}, "unaligned": {}}},
        ),
    )
    config = _FakeConfig()
    items = [
        _FakeItem(
            "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
            f"test_acvp_aes_cbc_cs{variant}_encrypt[CBC-CS{variant}-tc1]"
        )
        for variant in (1, 2, 3)
    ]

    cts_conftest.pytest_collection_modifyitems(config, items)

    assert _skip_reasons(items[0]) == []
    assert _skip_reasons(items[1]) == [
        "CKM_AES_CTS detection reporter is retained by the selected CTS item"
    ]
    assert _skip_reasons(items[2]) == [
        "CKM_AES_CTS detection reporter is retained by the selected CTS item"
    ]


def test_cts_collection_hook_is_trylast() -> None:
    """Core exact-selection validation must run before the provider-touching CTS hook."""
    impl = getattr(cts_conftest.pytest_collection_modifyitems, "pytest_impl", {})
    assert impl.get("trylast") is True


def test_cts_collection_hook_does_not_probe_collect_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collect-only metadata discovery must never touch the provider."""

    def probe_should_not_run(_config: Any) -> base_cts.CtsDetectionResult:
        pytest.fail("CTS provider probe ran during --collect-only")

    monkeypatch.setattr(cts_conftest, "_probe_cts_variant", probe_should_not_run)
    config = _FakeConfig(collectonly=True)
    item = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts.py::"
        "test_acvp_aes_cbc_cs1_encrypt[CBC-CS1-AES-enc-tc1]"
    )

    cts_conftest.pytest_collection_modifyitems(config, [item])

    assert _skip_reasons(item) == []


def test_collection_probe_propagates_python_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Python/ctypes probe failure must not become provider undetected evidence."""

    def explode(_config: Any) -> base_cts.CtsDetectionResult:
        raise RuntimeError("probe implementation bug")

    monkeypatch.setattr(cts_conftest, "_detect_variant_via_pkcs11", explode)

    with pytest.raises(RuntimeError, match="probe implementation bug"):
        cts_conftest._probe_cts_variant(_ProbeConfig())


def test_collection_probe_preserves_explicit_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit missing-capability skip remains a skip, not a hard collection error."""

    def no_create_object(_config: Any) -> base_cts.CtsDetectionResult:
        raise pytest.skip.Exception("Module does not implement C_CreateObject")

    monkeypatch.setattr(cts_conftest, "_detect_variant_via_pkcs11", no_create_object)

    try:
        result = cts_conftest._probe_cts_variant(_ProbeConfig())
    except pytest.skip.Exception as exc:
        pytest.fail(f"explicit capability skip escaped collection probe: {exc}")
    assert result.status is base_cts.CtsDetectionStatus.SETUP_UNAVAILABLE


def test_collection_probe_skips_cleanly_when_module_exposes_no_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty slot list must skip collection, not IndexError (whole-file INTERNALERROR)."""
    from pkcs11_check.core import loader
    from pkcs11_check.raw import bootstrap

    raw = object()
    monkeypatch.setattr(
        loader, "load_module", lambda *_args, **_kwargs: SimpleNamespace(raw=raw)
    )
    monkeypatch.setattr(bootstrap, "get_slot_ids", lambda _raw: [])

    try:
        result = cts_conftest._probe_cts_variant(_ProbeConfig())
    except IndexError as exc:
        pytest.fail(f"empty slot list crashed collection: {exc}")
    assert result.status is base_cts.CtsDetectionStatus.SETUP_UNAVAILABLE
    assert "slot" in result.detail["reason"].lower()


def test_collection_probe_contains_unlisted_detector_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CKR answer from detection setup must not crash collection.

    Login, session, mechanism-list, and import failures surface as
    CkrAssertionError: provider answers, not harness bugs. Only non-CKR
    exceptions (true harness bugs) may propagate to the collection gate.
    """

    def login_refused(_config: Any) -> base_cts.CtsDetectionResult:
        raise CkrAssertionError("login refusal", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(cts_conftest, "_detect_variant_via_pkcs11", login_refused)

    try:
        result = cts_conftest._probe_cts_variant(_ProbeConfig())
    except CkrAssertionError as exc:
        pytest.fail(f"provider CKR escaped the collection probe: {exc}")
    assert result.status is base_cts.CtsDetectionStatus.SETUP_ERROR
    assert result.error_rv == int(CKR_USER_NOT_LOGGED_IN)
    with pytest.raises(CkrAssertionError) as excinfo:
        base_cts.report_cts_detection(result)
    assert excinfo.value.rv == int(CKR_USER_NOT_LOGGED_IN)
    assert "login refusal" in str(excinfo.value)
    assert "CKR_USER_NOT_LOGGED_IN" in str(excinfo.value)


def test_collection_probe_checks_cts_flags_before_provider_session_or_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CTS operation flags must stop collection before any provider touch."""
    from pkcs11_check.core import loader
    from pkcs11_check.raw import bootstrap, recipes

    calls: list[str] = []
    raw = object()

    monkeypatch.setattr(loader, "load_module", lambda *_args, **_kwargs: SimpleNamespace(raw=raw))
    monkeypatch.setattr(bootstrap, "get_slot_ids", lambda _raw: [42])
    monkeypatch.setattr(recipes, "get_mechanism_list", lambda *_args: [CKM_AES_CTS])
    monkeypatch.setattr(
        recipes,
        "get_mechanism_info",
        lambda *_args: {"flags": int(CKF_ENCRYPT)},
    )
    monkeypatch.setattr(
        bootstrap,
        "open_session",
        lambda *_args, **_kwargs: calls.append("session") or pytest.fail("session opened"),
    )
    monkeypatch.setattr(
        base_cts,
        "_import_aes_key",
        lambda *_args, **_kwargs: calls.append("import") or pytest.fail("key imported"),
    )
    monkeypatch.setattr(
        base_cts,
        "encrypt_single",
        lambda *_args, **_kwargs: calls.append("encrypt") or pytest.fail("encrypted"),
    )

    result = cts_conftest._detect_variant_via_pkcs11(_ProbeConfig())

    assert result.status is base_cts.CtsDetectionStatus.SETUP_UNAVAILABLE
    assert "CKF_ENCRYPT|CKF_DECRYPT" in str(result.detail["reason"])
    assert cts_conftest._detection_skip_reason(result) == result.detail["reason"]
    assert calls == []


def _selection_manifest(
    *,
    source: str,
    all_nodeids: list[str],
    selected_nodeids: list[str],
    source_collection_sha256: str | None = None,
) -> dict[str, object]:
    collection_sha = source_collection_sha256 or compute_collection_sha256(all_nodeids)
    return {
        "schema": 1,
        "plan_id": "a" * 64,
        "batch_id": compute_batch_id(
            source=source,
            source_collection_count=len(all_nodeids),
            source_collection_sha256=collection_sha,
            nodeids=selected_nodeids,
        ),
        "source": source,
        "source_collection_count": len(all_nodeids),
        "source_collection_sha256": collection_sha,
        "nodeids": selected_nodeids,
    }


def _make_cts_pytester_project(pytester: pytest.Pytester) -> tuple[str, list[str]]:
    """Create a tiny testcase tree while delegating the real CTS hook."""
    source = "acvp/aes/test_cts.py"
    nodeids = [
        f"{source}::test_acvp_aes_cbc_cs1_encrypt",
        f"{source}::test_acvp_aes_cbc_cs2_encrypt",
    ]
    test_file = pytester.path / "testcases" / "acvp" / "aes" / "test_cts.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        """
from pathlib import Path


def test_acvp_aes_cbc_cs1_encrypt():
    (Path(__file__).parents[3] / "executed-case").write_text("cs1", encoding="utf-8")


def test_acvp_aes_cbc_cs2_encrypt():
    (Path(__file__).parents[3] / "executed-case").write_text("cs2", encoding="utf-8")
""",
        encoding="utf-8",
    )
    pytester.makeconftest(
        """
from pathlib import Path

import pkcs11_check.core.test_selection as selection
import pkcs11_check.plugin as core_plugin
from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest
from pkcs11_check.testcases.acvp.aes.base_cts import (
    CtsDetectionResult,
    CtsDetectionStatus,
)

testcases_root = Path(__file__).parent / "testcases"
selection.get_testcases_root = lambda: testcases_root
core_plugin.get_testcases_root = lambda: testcases_root

real_cts_hook = aes_conftest.pytest_collection_modifyitems


def _probe(_config):
    (Path(__file__).parent / "cts-probe-called").write_text("called", encoding="utf-8")
    return CtsDetectionResult(CtsDetectionStatus.ABSENT)


aes_conftest._probe_cts_variant = _probe


def pytest_collection_modifyitems(config, items):
    (Path(__file__).parent / "cts-items-before-probe").write_text(
        str(len(items)), encoding="utf-8"
    )
    real_cts_hook(config, items)


pytest_collection_modifyitems.pytest_impl = real_cts_hook.pytest_impl
"""
    )
    return source, nodeids


@pytest.mark.parametrize(
    ("kind", "expected_error"),
    [
        ("stale", "source_collection_sha256 mismatch"),
        ("tampered", "selected nodeids missing"),
        ("foreign", "mixed source in nodeid"),
    ],
)
def test_invalid_selection_manifest_blocks_cts_probe(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    expected_error: str,
) -> None:
    """Core manifest validation must fail before the provider-touching CTS hook."""
    source, all_nodeids = _make_cts_pytester_project(pytester)
    selected = [all_nodeids[0]]
    if kind == "tampered":
        selected = [f"{source}::test_acvp_aes_cbc_cs9_encrypt"]
    elif kind == "foreign":
        selected = ["other/test_cts.py::test_acvp_aes_cbc_cs1_encrypt"]
    collection_sha = "0" * 64 if kind == "stale" else None
    manifest = pytester.path / "selection.json"
    manifest.write_text(
        json.dumps(
            _selection_manifest(
                source=source,
                all_nodeids=all_nodeids,
                selected_nodeids=selected,
                source_collection_sha256=collection_sha,
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PKCS11_CHECK_SELECTION_MANIFEST", str(manifest))

    result = pytester.runpytest_subprocess("--p11-module", str(Path(__file__)), "-q")

    assert result.ret != 0
    result.stderr.fnmatch_lines([f"*{expected_error}*"])
    assert not (pytester.path / "cts-probe-called").exists()
    assert not (pytester.path / "cts-items-before-probe").exists()


def test_valid_exact_selection_is_pruned_before_cts_probe(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid exact batch reaches CTS only after core pruning to one item."""
    source, all_nodeids = _make_cts_pytester_project(pytester)
    manifest = pytester.path / "selection.json"
    manifest.write_text(
        json.dumps(
            _selection_manifest(
                source=source,
                all_nodeids=all_nodeids,
                selected_nodeids=[all_nodeids[0]],
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PKCS11_CHECK_SELECTION_MANIFEST", str(manifest))

    result = pytester.runpytest_subprocess("--p11-module", str(Path(__file__)), "-q")

    result.assert_outcomes(passed=1)
    assert (pytester.path / "cts-items-before-probe").read_text(encoding="utf-8") == "1"
    assert (pytester.path / "cts-probe-called").read_text(encoding="utf-8") == "called"
    assert (pytester.path / "executed-case").read_text(encoding="utf-8") == "cs1"


def test_default_isolated_cts_file_has_one_detection_reporter(
    pytester: pytest.Pytester,
) -> None:
    """A file-isolated CTS run reports detection once and skips vector siblings."""
    test_file = pytester.path / "testcases" / "acvp" / "aes" / "test_cts.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        """
from pkcs11_check.testcases.acvp.aes.base_cts import (
    CtsDetectionResult,
    CtsDetectionStatus,
    report_cts_detection,
)


def test_cts_variant_detected():
    report_cts_detection(CtsDetectionResult(CtsDetectionStatus.NOT_OPERATIONAL, error_rv=6))


def test_acvp_aes_cbc_cs1_encrypt():
    pass


def test_acvp_aes_cbc_cs2_encrypt():
    pass
""",
        encoding="utf-8",
    )
    pytester.makeconftest(
        """
from pkcs11_check.testcases.acvp.aes import conftest as aes_conftest
from pkcs11_check.testcases.acvp.aes.base_cts import (
    CtsDetectionResult,
    CtsDetectionStatus,
)

real_cts_hook = aes_conftest.pytest_collection_modifyitems
aes_conftest._probe_cts_variant = lambda _config: CtsDetectionResult(
    CtsDetectionStatus.NOT_OPERATIONAL,
)
pytest_collection_modifyitems = real_cts_hook
"""
    )

    result = pytester.runpytest_subprocess(
        "--p11-module",
        str(Path(__file__)),
        "--report-log",
        "report.jsonl",
        "-q",
    )

    result.assert_outcomes(xfailed=1, skipped=2)
    report_lines = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    classified_reports = [
        entry
        for entry in report_lines
        if any(
            property_name == "pkcs11_classification"
            for property_name, _value in entry.get("user_properties", [])
        )
    ]
    assert len(classified_reports) == 1

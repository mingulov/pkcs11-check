"""Tests for pytest plugin registration and fixtures."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.core.preflight import CapabilityManifest
from pkcs11_check.fixtures import p11_config
from pkcs11_check.raw.types_std import (
    CKM_AES_CBC,
    CKM_AES_GCM,
    CKM_EC_KEY_PAIR_GEN,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import mechanism_selection as selection
from pkcs11_check.testcases.mechanism_catalog import MechEntry


class TestPluginRegistration:
    def test_plugin_is_registered(self, pytestconfig: pytest.Config) -> None:
        """Verify pkcs11-check plugin is loaded."""
        plugin = pytestconfig.pluginmanager.get_plugin("pkcs11-check")
        assert plugin is not None

    def test_p11_module_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_module", default="MISSING")
        assert val != "MISSING"

    def test_p11_interface_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_interface", default="MISSING")
        assert val != "MISSING"

    def test_p11_slot_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_slot", default="MISSING")
        assert val != "MISSING"

    def test_p11_destructive_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_destructive", default="MISSING")
        assert val != "MISSING"

    def test_p11_manifest_option_exists(self, pytestconfig: pytest.Config) -> None:
        val = pytestconfig.getoption("p11_manifest", default="MISSING")
        assert val != "MISSING"


def test_p11_config_uses_env_pin_when_cli_pin_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("P11TEST_PIN", "secret123")

    options = {
        "p11_module": str(tmp_path / "module.so"),
        "p11_interface": "auto",
        "p11_slot": 0,
        "p11_pin": None,
        "p11_destructive": False,
    }

    def getoption(name: str, default: object | None = None) -> object | None:
        return options.get(name, default)

    request = SimpleNamespace(config=SimpleNamespace(getoption=getoption))

    config = p11_config.__wrapped__(request)

    assert config.pin is not None
    assert config.pin.get_secret_value() == "secret123"


def test_ensure_manifest_defaults_unset_interface_and_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_path = tmp_path / "module.so"
    module_path.touch()
    options = {
        "p11_module": str(module_path),
        "p11_manifest": None,
        "p11_interface": None,
        "p11_slot": None,
    }
    calls: list[tuple[str, int]] = []

    def getoption(name: str, default: object | None = None) -> object | None:
        return options.get(name, default)

    def fake_preflight(
        module: Path,
        *,
        interface: str,
        slot: int,
        timeout: int,
        output_path: Path,
    ) -> CapabilityManifest:
        del timeout, output_path
        calls.append((interface, slot))
        return CapabilityManifest(
            status="ok",
            module_path=str(module),
            requested_interface=interface,
            interface_version="2.40",
            slot_index=slot,
            slot_count=1,
            mechanisms=[],
        )

    monkeypatch.setattr(plugin_mod, "run_preflight_subprocess", fake_preflight)
    stash = pytest.Stash()
    stash[plugin_mod._MANIFEST_KEY] = None
    config = SimpleNamespace(stash=stash, getoption=getoption)

    manifest = plugin_mod._ensure_manifest(config)

    assert calls == [("auto", 0)]
    assert manifest is not None
    assert manifest.requested_interface == "auto"
    assert manifest.slot_index == 0


class _FakeItem:
    def __init__(self, path: Path, markers: dict[str, object]) -> None:
        self.path = path
        self.fspath = path
        self.nodeid = f"{path}::test_case"
        self._markers = markers
        self.added: list[object] = []

    def get_closest_marker(self, name: str) -> object | None:
        return self._markers.get(name)

    def iter_markers(self) -> list[object]:
        return list(self._markers.values())

    def add_marker(self, marker: object) -> None:
        self.added.append(marker)


class _FakeCatalog:
    def __init__(self, entries: list[MechEntry]) -> None:
        self._entries = entries

    def all_entries(self) -> list[MechEntry]:
        return list(self._entries)

    def filter_registered(self, flag: int) -> list[MechEntry]:
        raise AssertionError("legacy flag routing should not be used")


class _FakeMetafunc:
    def __init__(self, config: object, fixturenames: list[str]) -> None:
        self.config = config
        self.fixturenames = fixturenames
        self.calls: list[dict[str, object]] = []

    def parametrize(
        self,
        argnames: str,
        argvalues: list[object],
        ids: list[str],
        indirect: bool = False,
    ) -> None:
        self.calls.append(
            {
                "argnames": argnames,
                "argvalues": argvalues,
                "ids": ids,
                "indirect": indirect,
            }
        )


class _FakeReportLogPlugin:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def _write_json_data(self, payload: dict[str, object]) -> None:
        self.records.append(payload)


class _FakeHook:
    def __init__(self) -> None:
        self.deselected: list[object] = []

    def pytest_deselected(self, *, items: list[object]) -> None:
        self.deselected.extend(items)


def _fake_entry(name: str, *, flags: int = 0, config: object | None = object()) -> MechEntry:
    return MechEntry(
        mech_id=1,
        mech_name=name,
        flags=flags,
        min_key_size=0,
        max_key_size=0,
        config=config,  # type: ignore[arg-type]
    )


def test_pytest_generate_tests_maps_fixture_to_selection_scenario(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    entries = [
        _fake_entry("CKM_WRAP_OK"),
        _fake_entry("CKM_WRAP_REJECT"),
    ]

    def fake_select(entry: MechEntry, scenario: str) -> selection.SelectionDecision:
        calls.append((entry.mech_name, scenario))
        if entry.mech_name == "CKM_WRAP_OK":
            return selection.SelectionDecision(scenario=scenario, selected=True)
        return selection.SelectionDecision(
            scenario=scenario,
            selected=False,
            reasons=(
                selection.SelectionReason(
                    code="missing_flags",
                    field="flags",
                    expected=("CKF_WRAP", "CKF_UNWRAP"),
                    actual=("CKF_WRAP",),
                    missing=("CKF_UNWRAP",),
                ),
            ),
        )

    monkeypatch.setattr(plugin_mod, "select_for_scenario", fake_select)
    monkeypatch.setattr(
        plugin_mod,
        "_ensure_mechanism_catalog",
        lambda config: _FakeCatalog(entries),
    )
    metafunc = _FakeMetafunc(
        config=SimpleNamespace(stash={}),
        fixturenames=["mech_wrap_entry"],
    )

    plugin_mod.pytest_generate_tests(metafunc)

    assert calls == [
        ("CKM_WRAP_OK", selection.WRAP_ROUNDTRIP),
        ("CKM_WRAP_REJECT", selection.WRAP_ROUNDTRIP),
    ]
    assert metafunc.calls[0]["argnames"] == "mech_wrap_entry"
    assert metafunc.calls[0]["ids"] == ["CKM_WRAP_OK"]


def test_pytest_generate_tests_records_multipart_encrypt_selection_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _fake_entry("CKM_ENCRYPT_OK"),
        _fake_entry("CKM_ENCRYPT_REJECT"),
    ]

    def fake_select(entry: MechEntry, scenario: str) -> selection.SelectionDecision:
        if entry.mech_name == "CKM_ENCRYPT_OK":
            return selection.SelectionDecision(scenario=scenario, selected=True)
        return selection.SelectionDecision(
            scenario=scenario,
            selected=False,
            reasons=(
                selection.SelectionReason(
                    code="unsupported_multi_part",
                    field="multi_part_supported",
                    expected=True,
                    actual=False,
                ),
            ),
        )

    monkeypatch.setattr(plugin_mod, "select_for_scenario", fake_select)
    monkeypatch.setattr(
        plugin_mod,
        "_ensure_mechanism_catalog",
        lambda config: _FakeCatalog(entries),
    )
    config = SimpleNamespace(stash={})
    metafunc = _FakeMetafunc(config=config, fixturenames=["mech_multipart_encrypt_entry"])

    plugin_mod.pytest_generate_tests(metafunc)

    telemetry_key = getattr(plugin_mod, "_SELECTION_TELEMETRY_KEY", None)
    assert telemetry_key is not None
    telemetry = config.stash.get(telemetry_key)
    assert telemetry is not None
    assert telemetry["multipart_encrypt_roundtrip"]["selected_mechanisms"] == {"CKM_ENCRYPT_OK"}
    assert telemetry["multipart_encrypt_roundtrip"]["rejected_mechanisms"] == {"CKM_ENCRYPT_REJECT"}
    assert telemetry["multipart_encrypt_roundtrip"]["rejected_reason_counts"] == Counter(
        {"unsupported_multi_part": 1}
    )


def test_pytest_generate_tests_records_multipart_sign_selection_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _fake_entry("CKM_SIGN_OK"),
        _fake_entry("CKM_SIGN_REJECT"),
    ]

    def fake_select(entry: MechEntry, scenario: str) -> selection.SelectionDecision:
        if entry.mech_name == "CKM_SIGN_OK":
            return selection.SelectionDecision(scenario=scenario, selected=True)
        return selection.SelectionDecision(
            scenario=scenario,
            selected=False,
            reasons=(
                selection.SelectionReason(
                    code="unsupported_multi_part",
                    field="multi_part_supported",
                    expected=True,
                    actual=False,
                ),
            ),
        )

    monkeypatch.setattr(plugin_mod, "select_for_scenario", fake_select)
    monkeypatch.setattr(
        plugin_mod,
        "_ensure_mechanism_catalog",
        lambda config: _FakeCatalog(entries),
    )
    config = SimpleNamespace(stash={})
    metafunc = _FakeMetafunc(config=config, fixturenames=["mech_multipart_sign_entry"])

    plugin_mod.pytest_generate_tests(metafunc)

    telemetry_key = getattr(plugin_mod, "_SELECTION_TELEMETRY_KEY", None)
    assert telemetry_key is not None
    telemetry = config.stash.get(telemetry_key)
    assert telemetry is not None
    assert telemetry["multipart_sign_verify_roundtrip"]["selected_mechanisms"] == {"CKM_SIGN_OK"}
    assert telemetry["multipart_sign_verify_roundtrip"]["rejected_mechanisms"] == {
        "CKM_SIGN_REJECT"
    }
    assert telemetry["multipart_sign_verify_roundtrip"]["rejected_reason_counts"] == Counter(
        {"unsupported_multi_part": 1}
    )


def test_pytest_generate_tests_caches_selection_aggregation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    entries = [
        _fake_entry("CKM_SIGN_OK"),
        _fake_entry("CKM_SIGN_REJECT"),
    ]

    def fake_select(entry: MechEntry, scenario: str) -> selection.SelectionDecision:
        calls.append(entry.mech_name)
        if entry.mech_name == "CKM_SIGN_OK":
            return selection.SelectionDecision(scenario=scenario, selected=True)
        return selection.SelectionDecision(
            scenario=scenario,
            selected=False,
            reasons=(
                selection.SelectionReason(
                    code="missing_flags",
                    field="flags",
                    expected=("CKF_SIGN", "CKF_VERIFY"),
                    actual=("CKF_SIGN",),
                    missing=("CKF_VERIFY",),
                ),
            ),
        )

    monkeypatch.setattr(plugin_mod, "select_for_scenario", fake_select)
    monkeypatch.setattr(
        plugin_mod,
        "_ensure_mechanism_catalog",
        lambda config: _FakeCatalog(entries),
    )
    config = SimpleNamespace(stash={})
    metafunc = _FakeMetafunc(config=config, fixturenames=["mech_sign_entry"])

    plugin_mod.pytest_generate_tests(metafunc)
    telemetry_key = getattr(plugin_mod, "_SELECTION_TELEMETRY_KEY", None)
    assert telemetry_key is not None
    telemetry = config.stash[telemetry_key]
    first_snapshot = {
        scenario: {
            "selected_mechanisms": set(data["selected_mechanisms"]),
            "rejected_mechanisms": set(data["rejected_mechanisms"]),
            "rejected_reason_counts": Counter(data["rejected_reason_counts"]),
        }
        for scenario, data in telemetry.items()
    }

    plugin_mod.pytest_generate_tests(metafunc)

    assert calls == ["CKM_SIGN_OK", "CKM_SIGN_REJECT"]
    assert telemetry["sign_verify_roundtrip"]["selected_mechanisms"] == {"CKM_SIGN_OK"}
    assert telemetry["sign_verify_roundtrip"]["rejected_mechanisms"] == {"CKM_SIGN_REJECT"}
    assert telemetry["sign_verify_roundtrip"]["rejected_reason_counts"] == Counter(
        {"missing_flags": 1}
    )
    assert {
        scenario: {
            "selected_mechanisms": set(data["selected_mechanisms"]),
            "rejected_mechanisms": set(data["rejected_mechanisms"]),
            "rejected_reason_counts": Counter(data["rejected_reason_counts"]),
        }
        for scenario, data in telemetry.items()
    } == first_snapshot
    assert len(metafunc.calls) == 2
    assert metafunc.calls[0]["ids"] == metafunc.calls[1]["ids"] == ["CKM_SIGN_OK"]


def test_sessionfinish_emits_selection_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_log = _FakeReportLogPlugin()
    config = SimpleNamespace(
        stash={
            plugin_mod._CUMULATIVE_FUNCTIONS: set(),
            plugin_mod._RAW_INSTANCE: SimpleNamespace(
                available_function_names=lambda: set(),
                call_log={},
                used_mechanisms=set(),
                mechanism_counts={},
                mechanism_rv_counts={},
            ),
            plugin_mod._CUMULATIVE_MECHANISMS: set(),
            plugin_mod._CUMULATIVE_USED_MECHANISMS: set(),
            plugin_mod._CUMULATIVE_MECHANISM_DETAILS: set(),
            plugin_mod._CUMULATIVE_FUNCTION_COUNTS: {},
            plugin_mod._CUMULATIVE_MECHANISM_COUNTS: {},
            plugin_mod._CUMULATIVE_DETAIL_COUNTS: {},
            plugin_mod._BOOTSTRAP_FUNCTION_COUNTS: {},
        },
        getoption=lambda name, default=None: {"p11_module": "/tmp/module.so"}.get(name, default),
        _report_log_plugin=report_log,
    )
    telemetry_key = getattr(plugin_mod, "_SELECTION_TELEMETRY_KEY", None)
    assert telemetry_key is not None
    config.stash[telemetry_key] = {
        "encrypt_roundtrip": {
            "selected_mechanisms": {"CKM_ENCRYPT_OK"},
            "rejected_mechanisms": {"CKM_ENCRYPT_REJECT"},
            "rejected_reason_counts": Counter({"unsupported_multi_part": 1}),
        }
    }
    session = SimpleNamespace(config=config)

    plugin_mod.pytest_sessionfinish(session, 0)

    selection_reports = [
        record for record in report_log.records if record.get("$report_type") == "SelectionReport"
    ]
    assert selection_reports
    assert selection_reports[0]["selection_coverage"]["encrypt_roundtrip"][
        "selected_mechanisms"
    ] == ["CKM_ENCRYPT_OK"]


def test_sessionfinish_emits_mechanism_state_coverage() -> None:
    report_log = _FakeReportLogPlugin()
    config = SimpleNamespace(
        stash={
            plugin_mod._CUMULATIVE_FUNCTIONS: set(),
            plugin_mod._RAW_INSTANCE: SimpleNamespace(
                available_function_names=lambda: set(),
                call_log={},
                used_mechanisms={int(CKM_AES_CBC), int(CKM_AES_GCM)},
                mechanism_counts={int(CKM_AES_CBC): 1, int(CKM_AES_GCM): 2},
                mechanism_rv_counts={
                    int(CKM_AES_CBC): {int(CKR_OK): 1},
                    int(CKM_AES_GCM): {int(CKR_MECHANISM_INVALID): 2},
                },
            ),
            plugin_mod._CUMULATIVE_MECHANISMS: {"CKM_AES_CBC", "CKM_AES_GCM"},
            plugin_mod._CUMULATIVE_USED_MECHANISMS: {int(CKM_AES_CBC), int(CKM_AES_GCM)},
            plugin_mod._CUMULATIVE_MECHANISM_DETAILS: set(),
            plugin_mod._CUMULATIVE_FUNCTION_COUNTS: {},
            plugin_mod._CUMULATIVE_MECHANISM_COUNTS: {
                int(CKM_AES_CBC): 1,
                int(CKM_AES_GCM): 2,
            },
            plugin_mod._CUMULATIVE_DETAIL_COUNTS: {},
            plugin_mod._BOOTSTRAP_FUNCTION_COUNTS: {},
            plugin_mod._SELECTION_TELEMETRY_KEY: {
                "encrypt_roundtrip": {
                    "selected_mechanisms": {"CKM_AES_CBC"},
                    "rejected_mechanisms": {"CKM_AES_GCM"},
                    "rejected_reason_counts": Counter({"missing_flags": 1}),
                }
            },
        },
        getoption=lambda name, default=None: {"p11_module": "/tmp/module.so"}.get(name, default),
        _report_log_plugin=report_log,
    )
    session = SimpleNamespace(config=config)

    plugin_mod.pytest_sessionfinish(session, 0)

    coverage_reports = [
        record for record in report_log.records if record.get("$report_type") == "CoverageReport"
    ]
    assert coverage_reports
    mechanism_coverage = coverage_reports[0]["mechanism_coverage"]
    assert mechanism_coverage["advertised_names"] == ["CKM_AES_CBC", "CKM_AES_GCM"]
    assert mechanism_coverage["selected_names"] == ["CKM_AES_CBC"]
    assert mechanism_coverage["selection_rejected_names"] == ["CKM_AES_GCM"]
    assert mechanism_coverage["attempted_names"] == ["CKM_AES_CBC", "CKM_AES_GCM"]
    assert mechanism_coverage["accepted_names"] == ["CKM_AES_CBC"]
    assert mechanism_coverage["rejected_cleanly_names"] == ["CKM_AES_GCM"]
    assert mechanism_coverage["crashed_names"] == []
    assert mechanism_coverage["timeout_names"] == []


def test_sessionfinish_mechanism_states_prefer_advertised_alias() -> None:
    report_log = _FakeReportLogPlugin()
    config = SimpleNamespace(
        stash={
            plugin_mod._CUMULATIVE_FUNCTIONS: set(),
            plugin_mod._RAW_INSTANCE: SimpleNamespace(
                available_function_names=lambda: set(),
                call_log={},
                used_mechanisms={int(CKM_EC_KEY_PAIR_GEN)},
                mechanism_counts={int(CKM_EC_KEY_PAIR_GEN): 1},
                mechanism_rv_counts={int(CKM_EC_KEY_PAIR_GEN): {int(CKR_OK): 1}},
            ),
            plugin_mod._CUMULATIVE_MECHANISMS: {"CKM_EC_KEY_PAIR_GEN"},
            plugin_mod._CUMULATIVE_USED_MECHANISMS: {int(CKM_EC_KEY_PAIR_GEN)},
            plugin_mod._CUMULATIVE_MECHANISM_DETAILS: set(),
            plugin_mod._CUMULATIVE_FUNCTION_COUNTS: {},
            plugin_mod._CUMULATIVE_MECHANISM_COUNTS: {int(CKM_EC_KEY_PAIR_GEN): 1},
            plugin_mod._CUMULATIVE_DETAIL_COUNTS: {},
            plugin_mod._BOOTSTRAP_FUNCTION_COUNTS: {},
            plugin_mod._SELECTION_TELEMETRY_KEY: {},
        },
        getoption=lambda name, default=None: {"p11_module": "/tmp/module.so"}.get(name, default),
        _report_log_plugin=report_log,
    )
    session = SimpleNamespace(config=config)

    plugin_mod.pytest_sessionfinish(session, 0)

    coverage_report = next(
        record for record in report_log.records if record.get("$report_type") == "CoverageReport"
    )
    mechanism_coverage = coverage_report["mechanism_coverage"]
    assert mechanism_coverage["attempted_names"] == ["CKM_EC_KEY_PAIR_GEN"]
    assert mechanism_coverage["accepted_names"] == ["CKM_EC_KEY_PAIR_GEN"]
    assert "CKM_ECDSA_KEY_PAIR_GEN" not in mechanism_coverage["attempted_names"]
    assert "CKM_ECDSA_KEY_PAIR_GEN" not in mechanism_coverage["accepted_names"]


def test_collection_modifyitems_applies_only_static_skips() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {
            "destructive": SimpleNamespace(args=()),
            "requires_v32": SimpleNamespace(args=()),
        },
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {
            "p11_module": "/tmp/module.so",
            "p11_destructive": False,
            "p11_thread_safe": False,
        }.get(name, default)
    )

    plugin_mod.pytest_collection_modifyitems(config, [item])

    reasons = [getattr(marker, "kwargs", {}).get("reason") for marker in item.added]
    assert "Destructive test (use --p11-destructive to enable)" in reasons
    assert not any(reason and "Requires v" in reason for reason in reasons)


def test_collection_modifyitems_gates_mock_conformance_behind_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = _FakeItem(
        Path("/tmp/testcases/acvp/test_demo.py"),
        {"acvp": SimpleNamespace(name="acvp", args=())},
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {
            "p11_module": "/opt/proxy/bin/libpkcs11_proxy_ng_shim.so",
            "p11_destructive": False,
            "p11_thread_safe": False,
            "p11_allow_mock_conformance": False,
        }.get(name, default)
    )
    monkeypatch.setenv("PKCS11_CHECK_BACKEND_MODULE", "/usr/lib64/libpkcs11-mock.so")

    plugin_mod.pytest_collection_modifyitems(config, [item])

    reasons = [getattr(marker, "kwargs", {}).get("reason") for marker in item.added]
    assert any(reason and "pkcs11-mock returns canned values" in reason for reason in reasons)


def test_collection_modifyitems_ignores_comments_in_deselect_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deselect_file = tmp_path / "disabled.txt"
    deselect_file.write_text(
        "\n".join(
            [
                "# disabled tests",
                "",
                f"{tmp_path / 'testcases' / 'test_a.py'}::test_case",
                "# keep this comment",
            ]
        )
    )
    item_a = _FakeItem(tmp_path / "testcases" / "test_a.py", {})
    item_b = _FakeItem(tmp_path / "testcases" / "test_b.py", {})
    hook = _FakeHook()
    config = SimpleNamespace(
        hook=hook,
        getoption=lambda name, default=None: {
            "p11_module": "/tmp/module.so",
            "p11_destructive": False,
            "p11_thread_safe": False,
        }.get(name, default),
    )
    monkeypatch.setenv("PKCS11_CHECK_DESELECT_FILE", str(deselect_file))

    plugin_mod.pytest_collection_modifyitems(config, [item_a, item_b])

    assert hook.deselected == [item_a]


def test_collection_modifyitems_ignores_missing_deselect_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = _FakeItem(tmp_path / "testcases" / "test_a.py", {})
    hook = _FakeHook()
    config = SimpleNamespace(
        hook=hook,
        getoption=lambda name, default=None: {
            "p11_module": "/tmp/module.so",
            "p11_destructive": False,
            "p11_thread_safe": False,
        }.get(name, default),
    )
    monkeypatch.setenv("PKCS11_CHECK_DESELECT_FILE", str(tmp_path / "missing.txt"))

    plugin_mod.pytest_collection_modifyitems(config, [item])

    assert hook.deselected == []


def test_runtime_skip_reason_uses_manifest() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {
            "needs_mechanism": SimpleNamespace(args=("CKM_AES_ECB",)),
        },
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="3.0",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_RSA_PKCS"],
    )

    reason = plugin_mod._runtime_skip_reason(item, config, manifest)

    assert reason == "Mechanism CKM_AES_ECB not supported by module"


def _manifest_with(functions: list[str], *, version: str = "2.40") -> CapabilityManifest:
    return CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version=version,
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_DSA"],
        functions=functions,
    )


def test_needs_function_skips_when_function_absent() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = _manifest_with(["C_Sign", "C_Verify"])  # no C_EncapsulateKey

    reason = plugin_mod._runtime_skip_reason(item, config, manifest)

    assert reason == "Function C_EncapsulateKey not present in module"


def test_needs_function_runs_when_function_present() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = _manifest_with(["C_EncapsulateKey", "C_DecapsulateKey"], version="3.2")

    assert plugin_mod._runtime_skip_reason(item, config, manifest) is None


def test_needs_function_registered_as_dynamic_marker() -> None:
    item = _FakeItem(
        Path("/tmp/testcases/test_demo.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    assert plugin_mod._has_dynamic_markers(item) is True


def test_mldsa_runs_but_mlkem_encaps_skips_on_v240_module() -> None:
    """A v2.40 module advertising CKM_ML_DSA but lacking C_EncapsulateKey:
    ML-DSA (mechanism-gated, no version/function marker) runs; ML-KEM encaps
    (needs_function) skips. Locks the silent-skip regression."""
    config = SimpleNamespace(
        getoption=lambda name, default=None: {"p11_skip_unsupported": True}.get(name, default)
    )
    manifest = CapabilityManifest(
        status="ok",
        module_path="/tmp/module.so",
        requested_interface="auto",
        interface_version="2.40",
        slot_index=0,
        slot_count=1,
        mechanisms=["CKM_ML_DSA", "CKM_ML_DSA_KEY_PAIR_GEN"],
        functions=["C_Sign", "C_Verify", "C_GenerateKeyPair"],  # no C_EncapsulateKey
    )

    # ML-DSA test post-migration carries NO version/function marker (mechanism-gated in-test)
    mldsa_item = _FakeItem(Path("/tmp/testcases/test_mldsa.py"), {})
    assert plugin_mod._runtime_skip_reason(mldsa_item, config, manifest) is None

    # ML-KEM encaps test carries needs_function
    mlkem_item = _FakeItem(
        Path("/tmp/testcases/test_kem.py"),
        {"needs_function": SimpleNamespace(args=("C_EncapsulateKey",))},
    )
    assert (
        plugin_mod._runtime_skip_reason(mlkem_item, config, manifest)
        == "Function C_EncapsulateKey not present in module"
    )

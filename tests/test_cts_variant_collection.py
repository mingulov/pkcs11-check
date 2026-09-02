"""Regression tests for AES-CTS variant collection accounting."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.aes import conftest as cts_conftest


class _FakeHook:
    def __init__(self) -> None:
        self.deselected: list[object] = []

    def pytest_deselected(self, *, items: list[object]) -> None:
        self.deselected.extend(items)


class _FakeConfig:
    def __init__(self) -> None:
        self.hook = _FakeHook()


class _FakeItem:
    def __init__(self, nodeid: str) -> None:
        self.nodeid = nodeid
        self.markers: list[Any] = []

    def add_marker(self, marker: Any) -> None:
        self.markers.append(marker)


def _skip_reasons(item: _FakeItem) -> list[str]:
    reasons: list[str] = []
    for marker in item.markers:
        if getattr(marker, "name", None) == "skip":
            reasons.append(str(marker.kwargs.get("reason", "")))
    return reasons


def test_cts_variant_pruning_keeps_nonmatching_nodes_as_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cts_conftest, "_probe_cts_variant", lambda _config: "1")
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
    monkeypatch.setattr(cts_conftest, "_probe_cts_variant", lambda _config: None)
    config = _FakeConfig()
    detect = _FakeItem(
        "src/pkcs11_check/testcases/acvp/aes/test_cts_detect.py::test_cts_variant_detected"
    )
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
        "CKM_AES_CTS variant detection failed; test_cts_detect reports the provider finding"
    ]
    assert _skip_reasons(cs3) == [
        "CKM_AES_CTS variant detection failed; test_cts_detect reports the provider finding"
    ]

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.testcases._probes.params import (
    PinInParamsError,
    ProbeParams,
)


def test_load_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "params.json"
    p.write_text(
        json.dumps(
            {
                "module_path": "/lib/softhsm2.so",
                "slot_id": 0,
                "slot_label": "pkcs11-check",
                "interface": None,
                "extra": {"length": 0x7FFFFFFFFFFFFFFF, "mech": "CKM_AES_GCM"},
            }
        )
    )
    params = ProbeParams.load(str(p))
    assert params.module_path == "/lib/softhsm2.so"
    assert params.slot_id == 0
    assert params.slot_label == "pkcs11-check"
    assert params.extra["length"] == 0x7FFFFFFFFFFFFFFF
    assert params.extra["mech"] == "CKM_AES_GCM"


def test_dump_rejects_pin() -> None:
    with pytest.raises(PinInParamsError):
        ProbeParams.dump({"module_path": "/lib/x.so", "pin": "1234"})


def test_load_rejects_pin(tmp_path: Path) -> None:
    p = tmp_path / "params.json"
    p.write_text(json.dumps({"module_path": "/lib/x.so", "user_pin": "1234"}))
    with pytest.raises(PinInParamsError):
        ProbeParams.load(str(p))


def test_load_rejects_non_object(tmp_path: Path) -> None:
    p = tmp_path / "params.json"
    p.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ValueError):
        ProbeParams.load(str(p))

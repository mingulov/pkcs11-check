"""Tests for per-mechanism call-counter attribution (#87 item 1, 0.3.2 Unit C)."""

from __future__ import annotations

import ctypes
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.core import call_counters
from pkcs11_check.core import counters_schema as schema
from pkcs11_check.raw.api import RawPKCS11
from tests.test_call_counters_module import _function_list_buffer

AES_CBC = 0x1082
AES_CBC_HEX = "0x00001082"
RSA_PKCS = 0x00000001
RSA_PKCS_HEX = "0x00000001"


@pytest.fixture(autouse=True)
def _clean_counters() -> Iterator[None]:
    call_counters.reset_for_tests()
    yield
    call_counters.reset_for_tests()


def _fn_block(snap: dict[str, Any], fn: str, module: str = "") -> dict[str, Any]:
    return snap["by_module"][module]["buckets"]["test"]["by_fn"][fn]


def test_record_call_with_mech_emits_by_mechanism() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_EncryptInit", mech=AES_CBC)
        call_counters.record_return("C_EncryptInit", 0, mech=AES_CBC)
    snap = call_counters.serialize_current()
    assert snap["total_calls"] == 1
    fn_block = _fn_block(snap, "C_EncryptInit")
    assert fn_block["calls"] == 1
    mech = fn_block["by_mechanism"][AES_CBC_HEX]
    assert mech["calls"] == 1
    assert mech["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}
    assert schema.is_module_first_block(snap) is True


def test_mech_refusal_matrix_per_mechanism() -> None:
    from pkcs11_check.raw.rv import ckr_name

    mech_invalid = 0x70
    param_invalid = 0x71
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_SignInit", mech=RSA_PKCS)
        call_counters.record_return("C_SignInit", mech_invalid, mech=RSA_PKCS)
        call_counters.record_call("C_SignInit", mech=AES_CBC)
        call_counters.record_return("C_SignInit", param_invalid, mech=AES_CBC)
    fn_block = _fn_block(call_counters.serialize_current(), "C_SignInit")
    rsa = fn_block["by_mechanism"][RSA_PKCS_HEX]
    assert rsa["by_rv"][str(mech_invalid)] == {
        "name": ckr_name(mech_invalid),
        "count": 1,
    }
    aes = fn_block["by_mechanism"][AES_CBC_HEX]
    assert aes["by_rv"][str(param_invalid)]["count"] == 1
    assert fn_block["calls"] == 2


def test_mech_none_means_unattributed_subset() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_SignInit", mech=RSA_PKCS)
        call_counters.record_return("C_SignInit", 0, mech=RSA_PKCS)
        call_counters.record_call("C_SignInit")
        call_counters.record_return("C_SignInit", 0)
    fn_block = _fn_block(call_counters.serialize_current(), "C_SignInit")
    assert fn_block["calls"] == 2
    assert set(fn_block["by_mechanism"]) == {RSA_PKCS_HEX}
    assert fn_block["by_mechanism"][RSA_PKCS_HEX]["calls"] == 1


@pytest.mark.parametrize("bad", [True, False, "0x1082", -1, 1.5])
def test_mech_rejects_bad_values(bad: Any) -> None:
    with pytest.raises(ValueError, match="mech"):
        call_counters.record_call("C_SignInit", mech=bad)
    with pytest.raises(ValueError, match="mech"):
        call_counters.record_return("C_SignInit", 0, mech=bad)


def test_schema_accepts_valid_by_mechanism_and_rejects_malformed() -> None:
    good = {
        "total_calls": 1,
        "by_module": {
            "": {
                "calls": 1,
                "buckets": {
                    "test": {
                        "calls": 1,
                        "by_fn": {
                            "C_SignInit": {
                                "calls": 1,
                                "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                "by_mechanism": {
                                    AES_CBC_HEX: {
                                        "name": "CKM_AES_CBC",
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
    }
    assert schema.is_module_first_block(good) is True

    import copy

    bad_hex = copy.deepcopy(good)
    bad_hex["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"] = {
        "AES_CBC": {"name": "CKM_AES_CBC", "calls": 1, "by_rv": {}}
    }
    assert schema.is_module_first_block(bad_hex) is False

    over_sum = copy.deepcopy(good)
    over_sum["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"][
        AES_CBC_HEX
    ]["calls"] = 2
    assert schema.is_module_first_block(over_sum) is False

    bad_entry = copy.deepcopy(good)
    bad_entry["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"][
        AES_CBC_HEX
    ] = {"calls": 1}
    assert schema.is_module_first_block(bad_entry) is False

    # Old artifacts without the key stay valid (compatible placement).
    legacy = copy.deepcopy(good)
    del legacy["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"]
    assert schema.is_module_first_block(legacy) is True


def test_merge_unions_by_mechanism_deterministically() -> None:
    left = {
        "total_calls": 1,
        "by_module": {
            "": {
                "calls": 1,
                "buckets": {
                    "test": {
                        "calls": 1,
                        "by_fn": {
                            "C_SignInit": {
                                "calls": 1,
                                "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                "by_mechanism": {
                                    RSA_PKCS_HEX: {
                                        "name": "CKM_RSA_PKCS",
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
    }
    right = {
        "total_calls": 1,
        "by_module": {
            "": {
                "calls": 1,
                "buckets": {
                    "test": {
                        "calls": 1,
                        "by_fn": {
                            "C_SignInit": {
                                "calls": 1,
                                "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                "by_mechanism": {
                                    RSA_PKCS_HEX: {
                                        "name": RSA_PKCS_HEX,
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
    }
    merged = schema.merge_module_first(left, right)
    mech = merged["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"][
        RSA_PKCS_HEX
    ]
    assert mech["calls"] == 2
    assert mech["by_rv"]["0"]["count"] == 2
    # Deterministic symbolic-preferred names, both merge orders.
    assert mech["name"] == "CKM_RSA_PKCS"
    assert schema.is_module_first_block(merged) is True


def test_canonicalize_carries_by_mechanism_sorted() -> None:
    block = {
        "total_calls": 2,
        "by_module": {
            "": {
                "calls": 2,
                "buckets": {
                    "test": {
                        "calls": 2,
                        "by_fn": {
                            "C_SignInit": {
                                "calls": 2,
                                "by_rv": {"0": {"name": "CKR_OK", "count": 2}},
                                "by_mechanism": {
                                    RSA_PKCS_HEX: {
                                        "name": "CKM_RSA_PKCS",
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                    },
                                    AES_CBC_HEX: {
                                        "name": "CKM_AES_CBC",
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                    },
                                },
                            }
                        },
                    }
                },
            }
        },
    }
    canon = schema.canonicalize_module_first(block)
    keys = list(canon["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"])
    assert keys == sorted(keys)
    assert set(keys) == {RSA_PKCS_HEX, AES_CBC_HEX}


def test_flatten_ingest_roundtrip_preserves_mech() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_SignInit", mech=RSA_PKCS)
        call_counters.record_return("C_SignInit", 0, mech=RSA_PKCS)
    flat = call_counters.flatten_current()
    call_counters.reset_for_tests()
    # Ingest drops bucket attribution (the parent applies its own bucket).
    with call_counters.counted_bucket("test"):
        assert call_counters.ingest_child_evidence(flat) is True
    snap = call_counters.serialize_current()
    mech = snap["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"][
        RSA_PKCS_HEX
    ]
    assert mech["calls"] == 1
    assert mech["by_rv"]["0"]["count"] == 1


def test_snapshot_diff_carries_mech() -> None:
    before = call_counters.take_snapshot()
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_SignInit", mech=RSA_PKCS)
        call_counters.record_return("C_SignInit", 0, mech=RSA_PKCS)
    delta = call_counters.diff_snapshots(before, call_counters.take_snapshot())
    mech = delta["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"]["by_mechanism"][
        RSA_PKCS_HEX
    ]
    assert mech["calls"] == 1


def test_emitted_block_is_secret_free_and_param_free() -> None:
    with call_counters.counted_bucket("test"):
        call_counters.record_call("C_EncryptInit", mech=AES_CBC)
        call_counters.record_return("C_EncryptInit", 0, mech=AES_CBC)
    snap = call_counters.serialize_current()
    assert schema.is_secret_free(snap) is True
    text = json.dumps(snap)
    assert "param" not in text.lower()


def test_choke_point_passes_mech_from_struct() -> None:
    buf = _function_list_buffer(2, 40)
    raw = RawPKCS11(funclist_ptr=ctypes.addressof(buf))
    raw._funcs["C_SignInit"] = lambda *args: 0
    mechanism_arg = SimpleNamespace(_obj=SimpleNamespace(mechanism=RSA_PKCS))
    with call_counters.counted_bucket("test"):
        raw._call("C_SignInit", 1, mechanism_arg)
    fn_block = _fn_block(call_counters.serialize_current(), "C_SignInit")
    assert fn_block["by_mechanism"][RSA_PKCS_HEX]["calls"] == 1


def test_choke_point_unreadable_mech_stays_unattributed() -> None:
    buf = _function_list_buffer(2, 40)
    raw = RawPKCS11(funclist_ptr=ctypes.addressof(buf))
    raw._funcs["C_SignInit"] = lambda *args: 0
    with call_counters.counted_bucket("test"):
        raw._call("C_SignInit", 1, object())
    fn_block = _fn_block(call_counters.serialize_current(), "C_SignInit")
    assert fn_block["calls"] == 1
    assert "by_mechanism" not in fn_block


def test_extractor_folds_by_mechanism_into_output(tmp_path: Path) -> None:
    """End to end: a session record's by_mechanism reaches the extract."""
    from pkcs11_check.core._jsonl_extract import extract_call_counters_from_jsonl

    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text(
        "\n".join(
            [
                json.dumps({"$report_type": "SessionStart"}),
                json.dumps(
                    {
                        "$report_type": "CallCountersReport",
                        "pid": 100,
                        "isolation": "file",
                        "probes_lost": 0,
                        "total_calls": 1,
                        "buckets": {
                            "test": {
                                "calls": 1,
                                "by_fn": {
                                    "C_SignInit": {
                                        "calls": 1,
                                        "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                        "by_mechanism": {
                                            RSA_PKCS_HEX: {
                                                "name": "CKM_RSA_PKCS",
                                                "calls": 1,
                                                "by_rv": {"0": {"name": "CKR_OK", "count": 1}},
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    payload = extract_call_counters_from_jsonl(jsonl)
    assert payload is not None
    mech = payload["by_module"]["by_module"][""]["buckets"]["test"]["by_fn"]["C_SignInit"][
        "by_mechanism"
    ][RSA_PKCS_HEX]
    assert mech["calls"] == 1
    assert mech["by_rv"]["0"] == {"name": "CKR_OK", "count": 1}

"""Meta-tests: every valid nonempty GCM IV length is representable (1..2^32-1).

Clean rejection of a valid short, ordinary, long, or 257-byte IV is XFAIL,
never PASS/SKIP. Correct plaintext is PASS; successful wrong plaintext is
FAIL. Empty-IV negative vectors remain negative and unchanged. Exact
regressions pin tc68-valid (8-byte IV) and tc260-valid (20-byte IV) by tcId --
never via a helper that could select an ordinary 12-byte vector.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.data import WYCHEPROOF_DIR
from pkcs11_check.testcases.wycheproof import test_wycheproof as wy
from tests.test_wycheproof_generic_guards import _STUB_CFG


def _exact_vector(tc_id: int) -> dict[str, Any]:
    if not (WYCHEPROOF_DIR / "aes_gcm_test.json").exists():
        pytest.skip("Wycheproof vectors not present")
    vec = next(v for v in wy._load_aes_gcm_vectors() if v["tcId"] == tc_id)
    assert vec["result"] == "valid", tc_id
    return vec


def test_tc68_is_valid_8byte_iv() -> None:
    vec = _exact_vector(68)
    assert len(bytes.fromhex(vec["iv"])) == 8


def test_tc260_is_valid_20byte_iv() -> None:
    vec = _exact_vector(260)
    assert len(bytes.fromhex(vec["iv"])) == 20


def _run_exact(
    monkeypatch: pytest.MonkeyPatch, tc_id: int, operation: Any, *, iv_override: bytes | None = None
) -> None:
    vec = dict(_exact_vector(tc_id))
    if iv_override is not None:
        vec["iv"] = iv_override.hex()
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(wy, "provision_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(wy, "decrypt_single", operation)
    monkeypatch.setattr(wy, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(wy, "generate_random", lambda *_a, **_k: b"")
    wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, vec)


def _reject(rv: int) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError(f"Unexpected CK_RV 0x{rv:08x}", rv)

    return _raise


@pytest.mark.parametrize("tc_id", [68, 260])
def test_exact_valid_iv_correct_plaintext_passes(
    monkeypatch: pytest.MonkeyPatch, tc_id: int
) -> None:
    vec = _exact_vector(tc_id)
    _run_exact(monkeypatch, tc_id, lambda *_a, **_k: bytes.fromhex(vec["msg"]))


@pytest.mark.parametrize("tc_id", [68, 260])
def test_exact_valid_iv_param_reject_is_xfail_never_pass(
    monkeypatch: pytest.MonkeyPatch, tc_id: int
) -> None:
    """CKR_MECHANISM_PARAM_INVALID on a valid short/long IV is XFAIL, never PASS."""
    with pytest.raises(pytest.xfail.Exception):
        _run_exact(monkeypatch, tc_id, _reject(int(CKR_MECHANISM_PARAM_INVALID)))


@pytest.mark.parametrize("tc_id", [68, 260])
def test_exact_valid_iv_generic_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch, tc_id: int
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_exact(monkeypatch, tc_id, _reject(int(CKR_GENERAL_ERROR)))


@pytest.mark.parametrize("tc_id", [68, 260])
def test_exact_valid_iv_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, tc_id: int
) -> None:
    with pytest.raises(Failed, match="undefined CK_RV"):
        _run_exact(monkeypatch, tc_id, _reject(0x7FFFFFFF))


@pytest.mark.parametrize("tc_id", [68, 260])
def test_exact_valid_iv_wrong_plaintext_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, tc_id: int
) -> None:
    with pytest.raises(Failed, match="does not match known answer"):
        _run_exact(monkeypatch, tc_id, lambda *_a, **_k: b"\xff")


def test_257byte_valid_iv_param_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 257-byte IV is >16 bytes yet valid; its clean refusal is XFAIL."""
    with pytest.raises(pytest.xfail.Exception):
        _run_exact(
            monkeypatch,
            260,
            _reject(int(CKR_MECHANISM_PARAM_INVALID)),
            iv_override=bytes(257),
        )


# --- stale provider-verdict language must be gone from owned paths ----------


def _owned_text() -> dict[str, str]:
    root = Path(wy.__file__).resolve().parents[4]
    paths = [
        "src/pkcs11_check/testcases/wycheproof/test_wycheproof.py",
        "src/pkcs11_check/testcases/security/test_parameter_validation.py",
        "src/pkcs11_check/compliance.py",
    ]
    return {p: (root / p).read_text(encoding="utf-8") for p in paths}


@pytest.mark.parametrize(
    "phrase",
    [
        "_GCM_OPTIONAL_IV_REJECT_CKRS",
        "optional IV length",
        "non-96-bit IV support is optional",
        "(not 96-bit)",
        "GCM with 16-byte IV",
        "recommends 96-bit IVs",
        "96 bits is the recommended interoperable length",
    ],
)
def test_no_stale_gcm_iv_optionality_language(phrase: str) -> None:
    for path, text in _owned_text().items():
        assert phrase not in text, f"{phrase!r} still present in {path}"

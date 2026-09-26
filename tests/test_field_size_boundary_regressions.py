"""Regression / structural meta-tests for test_field_size_boundary.py (WS2 Phase 3).

After the _probes migration each test drives the probe via a monkeypatched
``run_probe`` and asserts that:
  (a) the parent calls ``run_probe("field_size", ...)`` with the correct ``which``
      dispatch key and the right truncation-revealing constant in the params,
  (b) a SETUP_XFAIL child stdout xfails the probe before the parent parses TARGET_RV,
  (c) the C_FindObjects cap probe treats CKR_OK as benign (allow_ok=True),
  (d) AES setup preflight runs before the child is spawned,
  (e) the field_size probe module backs the oversized HKDF length with the shared
      demand-zero honeypot (not a raw inline mmap).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_MEMORY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes import field_size as field_size_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases.security import test_field_size_boundary
from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8

# An undefined CK_RV: neither standard nor vendor-defined (vendor range starts
# at 0x80000000). A provider returning it violates the return-value contract.
_UNDEFINED_CKR = 0x777
_VENDOR_CKR = 0x80000001


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _raised_record(excinfo: pytest.ExceptionInfo[Any]) -> C.Classification:
    rec: C.Classification | None = getattr(excinfo.value, "_pkcs11_check_classification", None)
    assert rec is not None, "classified outcome must carry its record"
    return rec


def _expect_pass(desc: str, func: Callable[[], None]) -> None:
    """Run a product node that must PASS; an xfail outcome fails this test.

    A raw ``pytest.xfail`` raised by the node would otherwise mark this
    meta-test itself xfailed, hiding the oracle defect in the tally.
    """
    try:
        func()
    except pytest.xfail.Exception as exc:
        pytest.fail(f"{desc}: expected PASS, got xfail: {exc}")


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _RawSession:
    raw = object()
    sh = object()

    def has_mechanism(self, _name: str) -> bool:
        return True


def _setup_xfail_probe(
    calls: list[tuple[str, dict[str, object]]],
    stdout: str,
) -> object:
    """Return a run_probe stub that records its call and returns a SETUP_XFAIL result."""

    def _stub(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout=stdout, stderr="")

    return _stub


# ---------------------------------------------------------------------------
# 1. CKA_MODULUS_BITS oversized value
# ---------------------------------------------------------------------------


def test_rsa_modulus_bits_calls_run_probe_with_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA modulus-bits probe must call run_probe with the truncation-revealing value."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestRsaModulusBitsOversizedValue().test_rsa_modulus_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "rsa_modulus_bits"
    assert params.get("modulus_bits") == test_field_size_boundary._MODULUS_BITS_TRUNC


# ---------------------------------------------------------------------------
# 2. CKA_PRIME_BITS oversized value
# ---------------------------------------------------------------------------


def test_dh_prime_bits_calls_run_probe_with_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DH prime-bits probe must call run_probe with the truncation-revealing value."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:DH keygen not operational: CKR_FUNCTION_NOT_SUPPORTED\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestPrimeBitsOversizedValue().test_dh_prime_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "dh_prime_bits"
    assert params.get("prime_bits") == test_field_size_boundary._PRIME_BITS_TRUNC


def test_dsa_prime_bits_calls_run_probe_with_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DSA prime-bits probe must call run_probe with the truncation-revealing value."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:DSA keygen not operational: CKR_FUNCTION_NOT_SUPPORTED\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestPrimeBitsOversizedValue().test_dsa_prime_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "dsa_prime_bits"
    assert params.get("prime_bits") == test_field_size_boundary._PRIME_BITS_TRUNC


# ---------------------------------------------------------------------------
# 3. CKA_VALUE_LEN truncation-revealing in C_GenerateKey
# ---------------------------------------------------------------------------


def test_aes_value_len_calls_run_probe_with_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES keygen value-len probe must use an oversized length with low32 == 16."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(test_field_size_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "aes_value_len"
    # The probe must use an oversized length whose low 32 bits are 16 bytes (a
    # valid AES key size), not 8: a 32-bit-truncating provider then reads a
    # *valid* size and may succeed, which is the truncation-revealing premise.
    assert params.get("value_len") == (1 << 32) + 16
    value_len = params.get("value_len")
    assert isinstance(value_len, int) and value_len & 0xFFFFFFFF == 16


def test_aes_keygen_value_len_truncation_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES value-len truncation probe must preflight before spawning child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_field_size_boundary,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_field_size_boundary, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation(
            _RawSession(),
            cfg,
        )


# ---------------------------------------------------------------------------
# 4. C_FindObjects ulMaxObjectCount — crash-survival + allow_ok
# ---------------------------------------------------------------------------


def test_find_objects_count_calls_run_probe_with_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_FindObjects count probe must call run_probe with TRUNCATION_LOW8."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:C_FindObjectsInit rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
        ),
    )

    # assert_subprocess_no_crash xfails when SETUP_XFAIL is in stdout.
    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "find_objects_count"
    assert params.get("max_count") == TRUNCATION_LOW8


def test_find_objects_count_probe_allows_ok_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_FindObjects count probe must treat CKR_OK as benign (allow_ok=True).

    ulMaxObjectCount is a cap — returning ≤ MAX handles is always spec-legal.
    CKR_OK must NOT trigger accepted_invalid.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _stub(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        # Simulate C_FindObjects succeeding with count 0 (no objects found).
        stdout = "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n"
        return ProbeResult(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(test_field_size_boundary, "run_probe", _stub)

    # Must NOT raise (CKR_OK is spec-legal for a cap field).
    test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
        _RawSession(),
        cfg,
    )


def test_find_objects_count_probe_fails_on_guard_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A handle-buffer guard overwrite must fail (buffer overrun is the real finding)."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _stub(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        # Simulate C_FindObjects writing past the declared handle capacity.
        stdout = "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:3\nFINAL_RV:0x00000000\n"
        return ProbeResult(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(test_field_size_boundary, "run_probe", _stub)

    with pytest.raises(pytest.fail.Exception):
        test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
            _RawSession(),
            cfg,
        )


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen truncation (honeypot-backed behavioral comparison)
# ---------------------------------------------------------------------------


def test_hkdf_salt_len_calls_run_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF salt-len probe must call run_probe with the oversized length."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_salt_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "hkdf_salt_len"
    assert params.get("oversize_len") == test_field_size_boundary._OVERSIZE_LEN


def test_hkdf_info_len_calls_run_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF info-len probe must call run_probe with the oversized length."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(
            calls,
            "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n",
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_info_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "field_size"
    assert params.get("which") == "hkdf_info_len"
    assert params.get("oversize_len") == test_field_size_boundary._OVERSIZE_LEN


def test_hkdf_probe_uses_demand_zero_honeypot_not_raw_mmap() -> None:
    """The HKDF sub-probe must back the oversized length with the shared demand-zero honeypot.

    The full-length salt/info buffer must come from ``demand_zero_buffer`` (MAP_PRIVATE|
    MAP_ANONYMOUS, sized far past the 32-bit boundary) so no read beyond the mapping occurs.
    A raw inline ``mmap.mmap(...)`` would re-implement the honeypot instead of reusing the
    one guarded implementation, so it must not appear in the probe module.
    """
    src = inspect.getsource(field_size_probe)
    assert "demand_zero_buffer" in src, "HKDF probe must use the shared demand-zero honeypot"
    assert "CKF_HKDF_SALT_DATA" in src, "salt sub-probe must point to a real (non-NULL) salt"
    assert "PROBE_RV:" in src and "TRUNCATED:" in src, "behavioral comparison protocol required"
    assert "mmap.mmap(" not in src, "probe must reuse the shared honeypot, not raw inline mmap"


# ---------------------------------------------------------------------------
# Operation-family CKR oracle tables (symbolic, operation-specific)
# ---------------------------------------------------------------------------

# RSA modulus, DH/DSA domain parameters, AES value length: PASS only the
# canonical triple. CKR_KEY_SIZE_RANGE (defined for an already-supplied key,
# not this generation premise) and every other defined/vendor clean rejection
# are adverse XFAIL; CKR_OK and undefined CKRs are FAIL.
_KEY_SIZE_ORACLE_ROWS: tuple[tuple[int, str, str | None], ...] = (
    (int(CKR_ATTRIBUTE_VALUE_INVALID), "pass", None),
    (int(CKR_TEMPLATE_INCONSISTENT), "pass", None),
    (int(CKR_ARGUMENTS_BAD), "pass", None),
    (int(CKR_KEY_SIZE_RANGE), "xfail", "nonspec_reject"),
    (int(CKR_FUNCTION_NOT_SUPPORTED), "xfail", "nonspec_reject"),
    (_VENDOR_CKR, "xfail", "nonspec_reject"),
    (int(CKR_OK), "fail", "accepted_invalid"),
    (_UNDEFINED_CKR, "fail", "self_contradiction"),
)


def _oracle_id(value: object) -> str:
    if isinstance(value, int):
        return f"{value:#x}"
    return str(value)


def _run_key_size_node(
    monkeypatch: pytest.MonkeyPatch,
    node: Callable[[Any, Any], None],
    stdout: str,
    *,
    is_rsa: bool = False,
    is_aes: bool = False,
) -> None:
    """Run an RSA/DH/DSA/AES product node against canned child stdout."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    if is_rsa:
        monkeypatch.setattr(
            test_field_size_boundary, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2)
        )
        monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    if is_aes:
        monkeypatch.setattr(test_field_size_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
        monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(test_field_size_boundary, "run_probe", _setup_xfail_probe(calls, stdout))
    node(_RawSession(), cfg)


def _check_oracle_row(
    monkeypatch: pytest.MonkeyPatch,
    node: Callable[[Any, Any], None],
    rv: int,
    outcome: str,
    reason: str | None,
    *,
    is_rsa: bool = False,
    is_aes: bool = False,
) -> None:
    stdout = f"TARGET_RV:{rv:#010x}\n"
    if outcome == "pass":
        _expect_pass(
            f"TARGET_RV:{rv:#x}",
            lambda: _run_key_size_node(monkeypatch, node, stdout, is_rsa=is_rsa, is_aes=is_aes),
        )
        return
    with pytest.raises(
        pytest.xfail.Exception if outcome == "xfail" else pytest.fail.Exception
    ) as excinfo:
        _run_key_size_node(monkeypatch, node, stdout, is_rsa=is_rsa, is_aes=is_aes)
    assert _raised_record(excinfo).reason == reason


@pytest.mark.parametrize(("rv", "outcome", "reason"), _KEY_SIZE_ORACLE_ROWS, ids=_oracle_id)
def test_rsa_modulus_bits_oracle(
    monkeypatch: pytest.MonkeyPatch, rv: int, outcome: str, reason: str | None
) -> None:
    """RSA modulus-bits rejects classify per the canonical symbolic triple."""
    _check_oracle_row(
        monkeypatch,
        test_field_size_boundary.TestRsaModulusBitsOversizedValue().test_rsa_modulus_bits_oversized_value,
        rv,
        outcome,
        reason,
        is_rsa=True,
    )


@pytest.mark.parametrize("node_id", ["dh", "dsa"], ids=["dh", "dsa"])
@pytest.mark.parametrize(("rv", "outcome", "reason"), _KEY_SIZE_ORACLE_ROWS, ids=_oracle_id)
def test_prime_bits_oracle(
    monkeypatch: pytest.MonkeyPatch, node_id: str, rv: int, outcome: str, reason: str | None
) -> None:
    """DH/DSA parameter rejects classify per the canonical symbolic triple."""
    cls = test_field_size_boundary.TestPrimeBitsOversizedValue()
    node = (
        cls.test_dh_prime_bits_oversized_value
        if node_id == "dh"
        else cls.test_dsa_prime_bits_oversized_value
    )
    _check_oracle_row(monkeypatch, node, rv, outcome, reason)


@pytest.mark.parametrize(
    ("rv", "outcome", "reason"),
    [row for row in _KEY_SIZE_ORACLE_ROWS if row[0] != int(CKR_OK)],
    ids=_oracle_id,
)
def test_aes_value_len_reject_oracle(
    monkeypatch: pytest.MonkeyPatch, rv: int, outcome: str, reason: str | None
) -> None:
    """AES value-len rejects classify per the canonical symbolic triple."""
    _check_oracle_row(
        monkeypatch,
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation,
        rv,
        outcome,
        reason,
        is_aes=True,
    )


# ---------------------------------------------------------------------------
# DH/DSA parameter-generation premises (valid CKA_PRIME_BITS operation)
# ---------------------------------------------------------------------------


class _KeypairOnlySession(_RawSession):
    """Advertises key-pair generation but no domain-parameter generation."""

    def has_mechanism(self, name: str) -> bool:
        return name in ("DH_PKCS_KEY_PAIR_GEN", "DSA_KEY_PAIR_GEN")


class _ParamGenOnlySession(_RawSession):
    """Advertises domain-parameter generation but no key-pair generation."""

    def has_mechanism(self, name: str) -> bool:
        return name in ("DH_PKCS_PARAMETER_GEN", "DSA_PARAMETER_GEN")


@pytest.mark.parametrize("node_id", ["dh", "dsa"], ids=["dh", "dsa"])
def test_prime_bits_nodes_gate_on_parameter_gen(
    monkeypatch: pytest.MonkeyPatch, node_id: str
) -> None:
    """DH/DSA nodes test C_GenerateKey parameter generation, not key-pair gen.

    CKA_PRIME_BITS applies to CKM_DH_PKCS_PARAMETER_GEN /
    CKM_DSA_PARAMETER_GEN. A provider advertising only key-pair generation must
    skip; parameter-gen-only advertisement must reach the probe.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    cls = test_field_size_boundary.TestPrimeBitsOversizedValue()
    node = (
        cls.test_dh_prime_bits_oversized_value
        if node_id == "dh"
        else cls.test_dsa_prime_bits_oversized_value
    )

    with pytest.raises(pytest.skip.Exception):
        node(_KeypairOnlySession(), cfg)

    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe(calls, f"TARGET_RV:{int(CKR_ARGUMENTS_BAD):#010x}\n"),
    )
    node(_ParamGenOnlySession(), cfg)
    assert len(calls) == 1 and calls[0][0] == "field_size"


# ---------------------------------------------------------------------------
# AES CKR_OK attribute evidence (truncation vs ignored/defaulted)
# ---------------------------------------------------------------------------


def _run_aes_ok(monkeypatch: pytest.MonkeyPatch, stdout: str) -> C.Classification:
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    monkeypatch.setattr(test_field_size_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(
        test_field_size_boundary,
        "run_probe",
        _setup_xfail_probe([], stdout),
    )
    with pytest.raises(pytest.fail.Exception) as excinfo:
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation(
            _RawSession(), cfg
        )
    return _raised_record(excinfo)


def test_aes_ok_with_16_readback_proves_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OK + CKA_VALUE_LEN readback 16 is proven truncation (low32 == 16)."""
    rec = _run_aes_ok(monkeypatch, f"TARGET_RV:{int(CKR_OK):#010x}\nVALUE_LEN:16\n")
    assert rec.reason == "accepted_invalid"
    assert "truncat" in rec.summary.lower()
    assert "16" in rec.summary


def test_aes_ok_without_readback_is_acceptance_not_proven_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK without exact readback must not claim proven truncation."""
    rec = _run_aes_ok(monkeypatch, f"TARGET_RV:{int(CKR_OK):#010x}\n")
    assert rec.reason == "accepted_invalid"
    assert "truncat" not in rec.summary.lower()


@pytest.mark.parametrize("value_len", ["8", "32", "unavailable", "bogus"])
def test_aes_ok_with_non16_readback_is_acceptance_not_proven_truncation(
    monkeypatch: pytest.MonkeyPatch, value_len: str
) -> None:
    """CKR_OK + readback != 16 (or unavailable) is invalid-value acceptance."""
    rec = _run_aes_ok(monkeypatch, f"TARGET_RV:{int(CKR_OK):#010x}\nVALUE_LEN:{value_len}\n")
    assert rec.reason == "accepted_invalid"
    assert "truncat" not in rec.summary.lower()


# ---------------------------------------------------------------------------
# FindObjects honest-capacity protocol (4 mandatory markers)
# ---------------------------------------------------------------------------


def _run_find_objects(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    monkeypatch.setattr(test_field_size_boundary, "run_probe", _setup_xfail_probe([], stdout))
    test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
        _RawSession(), cfg
    )


def _find_stdout(
    *,
    target: int = int(CKR_OK),
    count: str = "0",
    guard: str = "0",
    final: int = int(CKR_OK),
) -> str:
    return (
        f"TARGET_RV:{target:#010x}\nCOUNT_OUT:{count}\n"
        f"GUARD_OVERWRITE:{guard}\nFINAL_RV:{final:#010x}\n"
    )


@pytest.mark.parametrize("count", [9, 10, 11, 12])
def test_find_objects_midrange_count_without_overwrite_passes(
    monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    """9-12 returned handles with an intact guard are honest-capacity PASS."""
    _expect_pass(
        f"COUNT_OUT:{count}",
        lambda: _run_find_objects(monkeypatch, _find_stdout(count=str(count))),
    )


@pytest.mark.parametrize("rv", [int(CKR_HOST_MEMORY), int(CKR_DEVICE_MEMORY)])
def test_find_objects_resource_refusal_passes(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    """CKR_HOST_MEMORY / CKR_DEVICE_MEMORY are legitimate resource-refusal PASS."""
    _expect_pass(
        f"TARGET_RV:{rv:#x}",
        lambda: _run_find_objects(monkeypatch, _find_stdout(target=rv)),
    )


@pytest.mark.parametrize(
    "rv", [int(CKR_GENERAL_ERROR), int(CKR_FUNCTION_NOT_SUPPORTED), _VENDOR_CKR]
)
def test_find_objects_other_clean_target_refusal_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    """Other clean target refusals are adverse XFAIL, not PASS."""
    with pytest.raises(pytest.xfail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(target=rv))
    assert _raised_record(excinfo).reason == "nonspec_reject"


def test_find_objects_undefined_target_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """An undefined target CKR is FAIL, never XFAIL."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(target=_UNDEFINED_CKR))
    assert _raised_record(excinfo).reason == "self_contradiction"


def test_find_objects_guard_corruption_is_memory_safety_not_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard corruption is memory-safety FAIL evidence, not kind="crypto"."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(guard="2"))
    rec = _raised_record(excinfo)
    assert rec.reason == "self_contradiction"
    assert rec.kind == "metadata"
    assert rec.kind != "crypto"


def test_find_objects_count_overflow_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """count > declared capacity is FAIL even with CKR_OK."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(count=str(TRUNCATION_LOW8 + 1)))
    assert _raised_record(excinfo).reason == "self_contradiction"


@pytest.mark.parametrize(
    "rv", [int(CKR_GENERAL_ERROR), int(CKR_FUNCTION_NOT_SUPPORTED), _VENDOR_CKR]
)
def test_find_objects_clean_final_refusal_xfails(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    """A clean Final refusal after CKR_OK target is adverse XFAIL."""
    with pytest.raises(pytest.xfail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(final=rv))
    assert _raised_record(excinfo).reason == "nonspec_reject"


def test_find_objects_undefined_final_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """An undefined Final CKR is FAIL, never XFAIL."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_find_objects(monkeypatch, _find_stdout(final=_UNDEFINED_CKR))
    assert _raised_record(excinfo).reason == "self_contradiction"


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param("COUNT_OUT:0\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n", id="missing-target"),
        pytest.param(
            "TARGET_RV:0x00000000\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="missing-count",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nFINAL_RV:0x00000000\n", id="missing-guard"
        ),
        pytest.param("TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\n", id="missing-final"),
        pytest.param(
            "TARGET_RV:0x00000000\nTARGET_RV:0x00000000\nCOUNT_OUT:0\n"
            "GUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="duplicate-target",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nCOUNT_OUT:0\n"
            "GUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="duplicate-count",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\n"
            "GUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="duplicate-guard",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\n"
            "FINAL_RV:0x00000000\nFINAL_RV:0x00000000\n",
            id="duplicate-final",
        ),
        pytest.param(
            "TARGET_RV:bogus\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="malformed-target",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:many\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="malformed-count",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:many\nFINAL_RV:0x00000000\n",
            id="malformed-guard",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\nFINAL_RV:bogus\n",
            id="malformed-final",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:-1\nGUARD_OVERWRITE:0\nFINAL_RV:0x00000000\n",
            id="negative-count",
        ),
        pytest.param(
            "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:-1\nFINAL_RV:0x00000000\n",
            id="negative-guard",
        ),
    ],
)
def test_find_objects_marker_protocol_incomplete_fails(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    """Missing/duplicate/malformed FindObjects markers are probe_incomplete FAIL."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_find_objects(monkeypatch, stdout)
    assert _raised_record(excinfo).reason == "probe_incomplete"


# ---------------------------------------------------------------------------
# HKDF completion protocol (exactly-one PROBE_RV + terminal TRUNCATED)
# ---------------------------------------------------------------------------

_HKDF_NODES = ("salt", "info")


def _run_hkdf_node(monkeypatch: pytest.MonkeyPatch, node_id: str, stdout: str) -> None:
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    monkeypatch.setattr(test_field_size_boundary, "run_probe", _setup_xfail_probe([], stdout))
    cls = test_field_size_boundary.TestHkdfParamLengthTruncation()
    node = (
        cls.test_hkdf_salt_len_truncation
        if node_id == "salt"
        else cls.test_hkdf_info_len_truncation
    )
    node(_RawSession(), cfg)


@pytest.mark.parametrize("node_id", _HKDF_NODES)
@pytest.mark.parametrize("rv", [int(CKR_MECHANISM_PARAM_INVALID), int(CKR_ARGUMENTS_BAD)])
def test_hkdf_canonical_reject_passes(
    monkeypatch: pytest.MonkeyPatch, node_id: str, rv: int
) -> None:
    """HKDF canonical rejects (MECHANISM_PARAM_INVALID, ARGUMENTS_BAD) PASS."""
    _expect_pass(
        f"PROBE_RV:{rv:#x}",
        lambda: _run_hkdf_node(monkeypatch, node_id, f"PROBE_RV:{rv:#010x}\n"),
    )


@pytest.mark.parametrize("node_id", _HKDF_NODES)
@pytest.mark.parametrize(
    "rv",
    [
        int(CKR_DATA_LEN_RANGE),
        int(CKR_KEY_SIZE_RANGE),
        int(CKR_FUNCTION_NOT_SUPPORTED),
        _VENDOR_CKR,
    ],
)
def test_hkdf_other_clean_reject_xfails(
    monkeypatch: pytest.MonkeyPatch, node_id: str, rv: int
) -> None:
    """Other clean HKDF rejects (incl. CKR_DATA_LEN_RANGE) are adverse XFAIL."""
    with pytest.raises(pytest.xfail.Exception) as excinfo:
        _run_hkdf_node(monkeypatch, node_id, f"PROBE_RV:{rv:#010x}\n")
    assert _raised_record(excinfo).reason == "nonspec_reject"


@pytest.mark.parametrize("node_id", _HKDF_NODES)
def test_hkdf_undefined_reject_fails(monkeypatch: pytest.MonkeyPatch, node_id: str) -> None:
    """An undefined HKDF probe CKR is FAIL, never XFAIL."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_hkdf_node(monkeypatch, node_id, f"PROBE_RV:{_UNDEFINED_CKR:#010x}\n")
    assert _raised_record(excinfo).reason == "self_contradiction"


@pytest.mark.parametrize("node_id", _HKDF_NODES)
def test_hkdf_ok_with_truncated_zero_passes(monkeypatch: pytest.MonkeyPatch, node_id: str) -> None:
    """CKR_OK + complete TRUNCATED:0 is the honored-length PASS."""
    _expect_pass(
        "TRUNCATED:0",
        lambda: _run_hkdf_node(
            monkeypatch, node_id, f"PROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:0\n"
        ),
    )


@pytest.mark.parametrize("node_id", _HKDF_NODES)
def test_hkdf_ok_with_truncated_one_fails(monkeypatch: pytest.MonkeyPatch, node_id: str) -> None:
    """CKR_OK + TRUNCATED:1 is proven truncation (wrong_result, crypto)."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_hkdf_node(monkeypatch, node_id, f"PROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:1\n")
    rec = _raised_record(excinfo)
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"


@pytest.mark.parametrize("node_id", _HKDF_NODES)
@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param(f"PROBE_RV:{int(CKR_OK):#010x}\n", id="missing-truncated"),
        pytest.param(
            f"PROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:0\nTRUNCATED:0\n",
            id="duplicate-truncated",
        ),
        pytest.param(f"PROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:yes\n", id="malformed-truncated"),
        pytest.param(f"PROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:2\n", id="out-of-domain-truncated"),
        pytest.param("", id="missing-probe-rv"),
        pytest.param(
            f"PROBE_RV:{int(CKR_OK):#010x}\nPROBE_RV:{int(CKR_OK):#010x}\nTRUNCATED:0\n",
            id="duplicate-probe-rv",
        ),
        pytest.param("PROBE_RV:bogus\n", id="malformed-probe-rv"),
    ],
)
def test_hkdf_terminal_evidence_incomplete_fails(
    monkeypatch: pytest.MonkeyPatch, node_id: str, stdout: str
) -> None:
    """Missing/duplicate/malformed/out-of-domain HKDF evidence is probe_incomplete."""
    with pytest.raises(pytest.fail.Exception) as excinfo:
        _run_hkdf_node(monkeypatch, node_id, stdout)
    assert _raised_record(excinfo).reason == "probe_incomplete"

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
from types import SimpleNamespace

import pytest

from pkcs11_check.testcases._probes import field_size as field_size_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases.security import test_field_size_boundary
from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8


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
    """AES keygen value-len probe must call run_probe with TRUNCATION_LOW8."""
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
    # The probe must use the truncation-revealing value (not a normal 16/32/etc.).
    assert params.get("value_len") == TRUNCATION_LOW8


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
        stdout = "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\n"
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
        # Simulate C_FindObjects writing past the 8-slot handle buffer.
        stdout = "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:3\n"
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

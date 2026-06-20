"""Regression / structural meta-tests for test_field_size_boundary.py (WS2 Phase 3).

Each test drives the probe with a monkeypatched run_with_coverage, asserts that:
  (a) the generated child script carries the SETUP_XFAIL protocol,
  (b) references the right op name and/or field name,
  (c) carries the TARGET_RV print (so the parent can classify),
  (d) compiles as valid Python (structural soundness gate).

Tests return a SETUP_XFAIL stdout so assert_subprocess_no_crash xfails the
probe before _parse_prefixed_int runs (avoiding the TARGET_RV missing assertion).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases.security import test_field_size_boundary


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _RawSession:
    raw = object()
    sh = object()

    def has_mechanism(self, _name: str) -> bool:
        return True


# ---------------------------------------------------------------------------
# 1. CKA_MODULUS_BITS oversized value
# ---------------------------------------------------------------------------


def test_rsa_modulus_bits_oversize_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA modulus-bits oversize child script must mark keypair setup rejects."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(
        test_field_size_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestRsaModulusBitsOversizedValue().test_rsa_modulus_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_RSA_PKCS_KEY_PAIR_GEN" in script
    assert "CKA_MODULUS_BITS" in script
    assert "TARGET_RV:" in script
    compile(script, "<rsa-modulus-bits-oversize-child>", "exec")


def test_rsa_modulus_bits_oversize_child_uses_truncation_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA modulus-bits probe must use the truncation-revealing constant."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(
        test_field_size_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestRsaModulusBitsOversizedValue().test_rsa_modulus_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    # The truncation value (1<<32)+2048 must appear in the child script.
    assert str(test_field_size_boundary._MODULUS_BITS_TRUNC) in scripts[0]


# ---------------------------------------------------------------------------
# 2. CKA_PRIME_BITS oversized value
# ---------------------------------------------------------------------------


def test_dh_prime_bits_oversize_child_script_compiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DH prime-bits oversize child script must be syntactically valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:DH keygen not operational: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestPrimeBitsOversizedValue().test_dh_prime_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_DH_PKCS_KEY_PAIR_GEN" in script
    assert "CKA_PRIME_BITS" in script
    assert "TARGET_RV:" in script
    assert str(test_field_size_boundary._PRIME_BITS_TRUNC) in script
    compile(script, "<dh-prime-bits-oversize-child>", "exec")


def test_dsa_prime_bits_oversize_child_script_compiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DSA prime-bits oversize child script must be syntactically valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:DSA keygen not operational: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestPrimeBitsOversizedValue().test_dsa_prime_bits_oversized_value(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_DSA_KEY_PAIR_GEN" in script
    assert "CKA_PRIME_BITS" in script
    assert "TARGET_RV:" in script
    assert str(test_field_size_boundary._PRIME_BITS_TRUNC) in script
    compile(script, "<dsa-prime-bits-oversize-child>", "exec")


# ---------------------------------------------------------------------------
# 3. CKA_VALUE_LEN truncation-revealing in C_GenerateKey
# ---------------------------------------------------------------------------


def test_aes_keygen_value_len_truncation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES keygen value-len truncation probe must mark setup rejects in child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(test_field_size_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_field_size_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_AES_KEY_GEN" in script
    assert "CKA_VALUE_LEN" in script
    assert "TARGET_RV:" in script
    # The child must use the truncation-revealing value (not a normal 16/32/etc.).
    from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8

    assert str(TRUNCATION_LOW8) in script
    compile(script, "<aes-keygen-value-len-truncation-child>", "exec")


def test_aes_keygen_value_len_truncation_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES value-len truncation probe must preflight before spawning child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_field_size_boundary,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_field_size_boundary.TestGenerateKeyValueLenTruncation().test_aes_keygen_value_len_truncation(
            _RawSession(),
            cfg,
        )


# ---------------------------------------------------------------------------
# 4. C_FindObjects ulMaxObjectCount — crash-survival + allow_ok
# ---------------------------------------------------------------------------


def test_find_objects_count_truncation_child_script_compiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_FindObjects count probe child script must be syntactically valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        # Simulate C_FindObjectsInit rejecting; assert_subprocess_no_crash converts
        # SETUP_XFAIL lines to xfail, so we wrap the call in pytest.raises.
        return 0, "SETUP_XFAIL:C_FindObjectsInit rejected: CKR_FUNCTION_NOT_SUPPORTED\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    # assert_subprocess_no_crash xfails when SETUP_XFAIL is in stdout.
    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "C_FindObjects" in script
    assert "C_FindObjectsInit" in script
    # The truncation-revealing count must appear.
    from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8

    assert str(TRUNCATION_LOW8) in script
    # Guard-byte detection must be present (this is a crash/overrun probe).
    assert "GUARD_OVERWRITE:" in script
    assert "guard" in script.lower()
    compile(script, "<find-objects-count-truncation-child>", "exec")


def test_find_objects_count_probe_allows_ok_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_FindObjects count probe must treat CKR_OK as benign (allow_ok=True).

    ulMaxObjectCount is a cap — returning ≤ MAX handles is always spec-legal.
    CKR_OK must NOT trigger accepted_invalid.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        # Simulate C_FindObjects succeeding with count 0 (no objects found).
        stdout = "TARGET_RV:0x00000000\nCOUNT_OUT:0\nGUARD_OVERWRITE:0\n"
        return 0, stdout, ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    # Must NOT raise (CKR_OK is spec-legal for a cap field).
    test_field_size_boundary.TestFindObjectsCountTruncation().test_find_objects_oversized_count_survives(
        _RawSession(),
        cfg,
    )


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen truncation
# ---------------------------------------------------------------------------


def test_hkdf_salt_len_truncation_child_script_compiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF salt-len truncation child script must be syntactically valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        # SETUP_XFAIL causes assert_subprocess_no_crash to raise xfail.
        return 0, "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_salt_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_HKDF_DERIVE" in script
    assert "ulSaltLen" in script or "CKF_HKDF_SALT_DATA" in script
    assert "TARGET_RV:" in script
    from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8

    assert str(TRUNCATION_LOW8) in script
    compile(script, "<hkdf-salt-len-truncation-child>", "exec")


def test_hkdf_info_len_truncation_child_script_compiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF info-len truncation child script must be syntactically valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        # SETUP_XFAIL causes assert_subprocess_no_crash to raise xfail.
        return 0, "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_info_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    assert "CKM_HKDF_DERIVE" in script
    assert "ulInfoLen" in script
    assert "TARGET_RV:" in script
    from pkcs11_check.testcases.security._boundary_values import TRUNCATION_LOW8

    assert str(TRUNCATION_LOW8) in script
    compile(script, "<hkdf-info-len-truncation-child>", "exec")


def test_hkdf_salt_len_probe_uses_real_nonnull_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF salt-len truncation probe must have a NON-NULL real salt buffer.

    This distinguishes it from the existing test_hkdf_null_salt which tests
    the NULL-pointer case. The truncation probe is only meaningful with a real
    buffer (buffer-coupled: real buffer ≥ low32 so a truncating provider reads
    real data and succeeds).
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_salt_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    # A real buffer must be allocated (ctypes array, not None).
    assert "salt_buf" in script
    # pSalt must be set to the real buffer (not None).
    assert "pSalt = None" not in script


def test_hkdf_info_len_probe_uses_real_nonnull_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HKDF info-len truncation probe must have a NON-NULL real info buffer."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "SETUP_XFAIL:HKDF base key import not operational 0x00000054\n", ""

    monkeypatch.setattr(test_field_size_boundary, "run_with_coverage", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_field_size_boundary.TestHkdfParamLengthTruncation().test_hkdf_info_len_truncation(
            _RawSession(),
            cfg,
        )

    assert len(scripts) == 1
    script = scripts[0]
    # A real buffer must be allocated.
    assert "info_buf" in script
    # pInfo must be set to the real buffer (not None).
    assert "pInfo = None" not in script

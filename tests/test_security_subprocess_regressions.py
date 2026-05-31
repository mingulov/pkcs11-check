"""Regression tests for crash-survival subprocess wrappers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases.security import (
    test_api_boundary,
    test_arithmetic_overflow,
    test_error_path_rsa,
    test_ffi_length_boundary,
    test_ffi_null_pointer,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash
from pkcs11_check.testcases.security.test_error_path_kwp import (
    _APIS,
    _CORRUPTION_CODE,
    _DECRYPT_CODE,
    _MECHANISMS,
    _build_script,
)


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _RawSession:
    raw = object()
    sh = object()

    def has_mechanism(self, _name: str) -> bool:
        return True


def test_assert_subprocess_no_crash_rejects_positive_exit() -> None:
    """A child Python error is not a valid no-crash pass."""
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_subprocess_no_crash(
            1,
            "",
            "SyntaxError: expected 'except' or 'finally' block",
            context="generated child script",
        )


def test_assert_subprocess_no_crash_converts_setup_marker_to_xfail() -> None:
    """A controlled child setup rejection is an xfail, not a silent pass."""
    with pytest.raises(pytest.xfail.Exception, match="AES key generation rejected"):
        assert_subprocess_no_crash(
            0,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED",
            "",
            context="generated child script",
        )


@pytest.mark.parametrize("corruption", ["aiv", "padding", "length", "truncate"])
@pytest.mark.parametrize(
    "api",
    [pytest.param(param.values[0], id=str(param.id)) for param in _APIS],
)
@pytest.mark.parametrize(
    "ckm_name",
    [pytest.param(param.values[1], id=str(param.id)) for param in _MECHANISMS],
)
def test_kwp_error_path_generated_script_compiles(
    ckm_name: str,
    api: str,
    corruption: str,
) -> None:
    """The generated AES-KWP crash-regression child script is valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    script = _build_script(
        cfg,
        ckm_name=ckm_name,
        corruption_code=_CORRUPTION_CODE.format(corruption=corruption),
        api=api,
    )

    compile(script, "<kwp-error-path-child>", "exec")


def test_kwp_decrypt_child_uses_minimal_guarded_output_buffer() -> None:
    """The decrypt crash path must expose output-buffer overwrites."""
    assert "minimal_len = max(0, len(corrupted) - 8)" in _DECRYPT_CODE
    assert 'guard_sentinel = b"PKCS11CHK"' in _DECRYPT_CODE
    assert "wrote past the minimal output buffer" in _DECRYPT_CODE


@pytest.mark.parametrize(
    "bad_ct_code,body",
    [
        pytest.param(
            "import os\nbad_ct = os.urandom(mod_len)\n",
            test_error_path_rsa._PKCS_DECRYPT_BODY,
            id="pkcs-random",
        ),
        pytest.param(
            "import os\nbad_ct = os.urandom(mod_len // 2)\n",
            test_error_path_rsa._PKCS_DECRYPT_BODY,
            id="pkcs-truncated",
        ),
        pytest.param(
            "import os\nbad_ct = os.urandom(mod_len + 16)\n",
            test_error_path_rsa._PKCS_DECRYPT_BODY,
            id="pkcs-extended",
        ),
        pytest.param(
            "import os\nbad_ct = os.urandom(mod_len)\n",
            test_error_path_rsa._OAEP_DECRYPT_BODY,
            id="oaep-random",
        ),
        pytest.param(
            "bad_ct = b'\\xff' * mod_len\n",
            test_error_path_rsa._OAEP_DECRYPT_BODY,
            id="oaep-all-ff",
        ),
    ],
)
def test_rsa_error_path_generated_script_compiles(bad_ct_code: str, body: str) -> None:
    """RSA crash-regression child scripts should be syntactically valid."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    script = test_error_path_rsa._build_decrypt_script(
        cfg,
        bad_ct_code=bad_ct_code,
        body=body,
    )

    compile(script, "<rsa-error-path-child>", "exec")


def test_rsa_decrypt_probe_xfails_setup_before_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA decrypt crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> tuple[int, int]:
        pytest.xfail("RSA setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(test_error_path_rsa, "gen_rsa_keypair_or_xfail", _xfail_setup)
    monkeypatch.setattr(test_error_path_rsa, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="RSA setup unavailable"):
        test_error_path_rsa.TestRsaPkcsDecryptErrorPaths().test_rsa_pkcs_decrypt_random_ciphertext(
            _RawSession(),
            cfg,
        )


def test_rsa_verify_probe_xfails_setup_before_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA verify crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> tuple[int, int]:
        pytest.xfail("RSA setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(test_error_path_rsa, "gen_rsa_keypair_or_xfail", _xfail_setup)
    monkeypatch.setattr(test_error_path_rsa, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="RSA setup unavailable"):
        test_error_path_rsa.TestRsaVerifyCorruptedSignature().test_rsa_verify_corrupted_signature(
            _RawSession(),
            cfg,
        )


def test_zero_length_aes_cbc_child_script_compiles(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-CBC zero-length crash probe must generate valid Python."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _compile_child(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        compile(script, "<api-boundary-zero-length-child>", "exec")
        return 0, "", ""

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", lambda *_a, **_kw: 1)
    monkeypatch.setattr(test_api_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_api_boundary, "run_with_coverage", _compile_child)

    test_api_boundary.TestZeroLengthData().test_zero_length_data(
        _RawSession(),
        cfg,
        "encrypt",
        "AES_CBC",
        "CKM_AES_CBC",
    )


def test_zero_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-length AES crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", _xfail_setup, raising=False)
    monkeypatch.setattr(test_api_boundary, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_api_boundary.TestZeroLengthData().test_zero_length_data(
            _RawSession(),
            cfg,
            "encrypt",
            "AES_ECB",
            "CKM_AES_ECB",
        )


def test_arithmetic_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic AES crash probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_arithmetic_overflow, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
            _RawSession(),
            cfg,
            0x80000000,
            "C_Encrypt",
            "C_EncryptInit",
        )


def test_arithmetic_aes_child_script_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic AES child scripts should classify setup rejects inside the child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(test_arithmetic_overflow, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_with_coverage", _capture)

    test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
        _RawSession(),
        cfg,
        0x80000000,
        "C_Encrypt",
        "C_EncryptInit",
    )

    assert len(scripts) == 1
    assert "SETUP_XFAIL:" in scripts[0]
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in scripts[0]


def test_arithmetic_pss_child_script_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic RSA-PSS child scripts should classify keypair setup rejects."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_with_coverage", _capture)

    test_arithmetic_overflow.TestPssSaltLengthOverflow().test_pss_salt_length_overflow(
        _RawSession(),
        cfg,
        0xFFFFFFFF,
    )

    assert len(scripts) == 1
    assert "SETUP_XFAIL:" in scripts[0]
    assert "KEYPAIR_RUNTIME_REJECT_RVS" in scripts[0]


def test_ffi_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length AES crash probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
            _RawSession(),
            cfg,
            0x8000000000000000,
        )


def test_ffi_length_aes_child_script_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length child scripts should classify setup rejects inside the child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_with_coverage", _capture)

    test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
        _RawSession(),
        cfg,
        0x8000000000000000,
    )

    assert len(scripts) == 1
    assert "SETUP_XFAIL:" in scripts[0]
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in scripts[0]


def test_ffi_length_keypair_child_scripts_mark_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EC/RSA FFI child scripts should not expose setup keygen as probe failures."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_ec_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (3, 4),
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_with_coverage", _capture)

    test_ffi_length_boundary.TestMechanismNullInnerParams().test_ecdh_null_public_data(
        _RawSession(),
        cfg,
    )
    test_ffi_length_boundary.TestMechanismNullInnerParams().test_oaep_null_source_data(
        _RawSession(),
        cfg,
    )

    assert len(scripts) == 2
    assert all("SETUP_XFAIL:" in script for script in scripts)
    assert all("KEYPAIR_RUNTIME_REJECT_RVS" in script for script in scripts)


def test_ffi_length_eddsa_child_script_uses_edwards_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ed25519 crash probes must use CKM_EC_EDWARDS_KEY_PAIR_GEN setup."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_ec_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_edwards_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_with_coverage", _capture)

    test_ffi_length_boundary.TestEddsaNullContext().test_eddsa_null_context_data(
        _RawSession(),
        cfg,
    )

    assert len(scripts) == 1
    assert "CKM_EC_EDWARDS_KEY_PAIR_GEN" in scripts[0]
    assert "gen_keypair" in scripts[0]
    assert "gen_ec_keypair" not in scripts[0]


def test_ffi_null_update_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL-pointer AES update probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullDataUpdate().test_null_data_update(
            _RawSession(),
            cfg,
            "encrypt",
            "C_EncryptInit",
            "C_EncryptUpdate",
            "AES_CBC",
        )


def test_ffi_null_final_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL-output final probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullOutputFinal().test_null_output_final(
            _RawSession(),
            cfg,
            "encrypt",
            "C_EncryptFinal",
            "AES_CBC",
        )


def test_ffi_null_oneshot_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL one-shot AES probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullDataOneShot().test_null_data_oneshot(
            _RawSession(),
            cfg,
            "encrypt",
            "C_Encrypt",
            "AES_ECB",
        )


def test_ffi_null_unwrap_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL wrapped-data probes should preflight unwrap-key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullWrapUnwrap().test_unwrap_key_null_wrapped_data(
            _RawSession(),
            cfg,
        )


def test_ffi_null_kem_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL KEM ciphertext probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> tuple[int, str, str]:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullKemApi().test_decapsulate_key_null_ciphertext(
            _RawSession(),
            cfg,
        )


def test_ffi_null_pin_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN child scripts should pass valid pins as CK_UTF8CHAR_PTR."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _capture)

    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_old_pin(cfg)
    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_new_pin(cfg)

    assert len(scripts) == 2
    assert all("CK_UTF8CHAR_PTR" in script for script in scripts)
    assert all(
        "ctypes.cast(ctypes.pointer(pin_buf), CK_UTF8CHAR_PTR)" in script for script in scripts
    )


def test_ffi_null_init_token_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_InitToken child scripts should pass valid buffers as CK_UTF8CHAR_PTR."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    scripts: list[str] = []

    def _capture(script: str, *_args: object, **_kwargs: object) -> tuple[int, str, str]:
        scripts.append(script)
        return 0, "", ""

    monkeypatch.setattr(test_ffi_null_pointer, "run_with_coverage", _capture)

    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_pin(cfg)
    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_label(cfg)

    assert len(scripts) == 2
    assert all("CK_UTF8CHAR_PTR" in script for script in scripts)
    assert "ctypes.cast(ctypes.pointer(label_buf), CK_UTF8CHAR_PTR)" in scripts[0]
    assert "ctypes.cast(ctypes.pointer(pin_buf), CK_UTF8CHAR_PTR)" in scripts[1]

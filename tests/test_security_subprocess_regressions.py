"""Regression tests for crash-survival subprocess wrappers."""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from pkcs11_check.testcases._probes import ffi_length as ffi_length_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases.security import (
    test_api_boundary,
    test_arithmetic_overflow,
    test_error_path_rsa,
    test_ffi_length_boundary,
    test_ffi_null_pointer,
    test_output_length_truncation,
    test_recover_length_boundary,
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


def test_zero_length_aes_cbc_probe_calls_run_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-CBC zero-length crash probe must invoke run_probe with correct params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", lambda *_a, **_kw: 1)
    monkeypatch.setattr(test_api_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_api_boundary, "run_probe", _stub_probe)

    test_api_boundary.TestZeroLengthData().test_zero_length_data(
        _RawSession(),
        cfg,
        "encrypt",
        "AES_CBC",
        "CKM_AES_CBC",
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "api_boundary"
    assert params.get("which") == "zero_length_aes"
    assert params.get("operation") == "encrypt"
    assert params.get("mech_name") == "CKM_AES_CBC"


def test_zero_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-length AES crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", _xfail_setup, raising=False)
    monkeypatch.setattr(test_api_boundary, "run_probe", _child_should_not_run)

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

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
            _RawSession(),
            cfg,
            0x80000000,
            "C_Encrypt",
            "C_EncryptInit",
        )


def test_arithmetic_aes_probe_calls_run_probe_with_correct_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic AES data-length probe must call run_probe with correct probe name and params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_arithmetic_overflow, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _stub_probe)

    test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
        _RawSession(),
        cfg,
        0x80000000,
        "C_Encrypt",
        "C_EncryptInit",
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "arithmetic_overflow"
    assert params.get("which") == "data_length_overflow"
    assert params.get("func") == "C_Encrypt"
    assert params.get("init_func") == "C_EncryptInit"
    assert params.get("data_len") == 0x80000000


def test_arithmetic_pss_probe_calls_run_probe_with_correct_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic RSA-PSS probe must call run_probe with correct probe name and params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _stub_probe)

    test_arithmetic_overflow.TestPssSaltLengthOverflow().test_pss_salt_length_overflow(
        _RawSession(),
        cfg,
        0xFFFFFFFF,
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "arithmetic_overflow"
    assert params.get("which") == "pss_salt_length_overflow"
    assert params.get("salt_len") == 0xFFFFFFFF


def test_ffi_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length AES crash probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
            _RawSession(),
            cfg,
            0x8000000000000000,
        )


def test_ffi_length_aes_child_script_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length AES probe must classify a child setup reject (SETUP_XFAIL) as xfail.

    The AES-keygen setup-reject logic now lives in the ``_probes/ffi_length.py`` child
    (``AES_KEYGEN_RUNTIME_REJECT_RVS`` -> ``_setup_reject_or_raise``); when the child emits
    ``SETUP_XFAIL`` the parent classifies it via ``_classify_unhonorable_length_outcome``
    into an xfail rather than a silent pass.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
            _RawSession(),
            cfg,
            0x8000000000000000,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_isize"
    # The setup-reject logic must live in the probe child, keyed on AES_KEYGEN_RUNTIME_REJECT_RVS.
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in inspect.getsource(ffi_length_probe)


def test_ffi_length_keypair_child_scripts_mark_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EC/RSA FFI probes must classify a child setup reject (SETUP_XFAIL) as xfail.

    The keypair-keygen setup-reject logic now lives in the ``_probes/ffi_length.py`` child
    (``KEYPAIR_RUNTIME_REJECT_RVS`` -> ``_setup_reject_or_raise``); when the child emits
    ``SETUP_XFAIL`` the parent classifies it (via ``assert_subprocess_no_crash``) into an
    xfail rather than exposing setup keygen as a probe failure.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

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
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestMechanismNullInnerParams().test_ecdh_null_public_data(
            _RawSession(),
            cfg,
        )
    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestMechanismNullInnerParams().test_oaep_null_source_data(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {
        "ecdh_null_public_data",
        "oaep_null_source_data",
    }
    # The setup-reject logic must live in the probe child, keyed on KEYPAIR_RUNTIME_REJECT_RVS.
    assert "KEYPAIR_RUNTIME_REJECT_RVS" in inspect.getsource(ffi_length_probe)


def test_ffi_length_eddsa_child_script_uses_edwards_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ed25519 crash probes must use CKM_EC_EDWARDS_KEY_PAIR_GEN setup (in the probe child)."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:EC_EDWARDS keygen rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_edwards_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestEddsaNullContext().test_eddsa_null_context_data(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "eddsa_null_context_data"
    # The EdDSA keygen (Edwards) must live in the probe child, not via gen_ec_keypair.
    eddsa_src = inspect.getsource(ffi_length_probe._run_eddsa_null_context_data)
    assert "CKM_EC_EDWARDS_KEY_PAIR_GEN" in eddsa_src
    assert "gen_keypair" in eddsa_src
    assert "gen_ec_keypair" not in eddsa_src


def test_ffi_null_update_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL-pointer AES update probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

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
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

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
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

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
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullWrapUnwrap().test_unwrap_key_null_wrapped_data(
            _RawSession(),
            cfg,
        )


def test_ffi_null_kem_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL KEM ciphertext probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullKemApi().test_decapsulate_key_null_ciphertext(
            _RawSession(),
            cfg,
        )


def test_ffi_null_pin_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN child probes must dispatch with the correct which keys."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _capture)

    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_old_pin(cfg)
    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_new_pin(cfg)

    assert len(calls) == 2
    assert all(probe == "ffi_null_pointer" for probe, _ in calls)
    which_values = {params.get("which") for _, params in calls}
    assert which_values == {"set_pin_null_old_pin", "set_pin_null_new_pin"}


def test_ffi_null_init_token_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_InitToken child probes must dispatch with the correct which keys."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _capture)

    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_pin(cfg)
    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_label(cfg)

    assert len(calls) == 2
    assert all(probe == "ffi_null_pointer" for probe, _ in calls)
    which_values = {params.get("which") for _, params in calls}
    assert which_values == {"init_token_null_pin", "init_token_null_label"}


# ---------------------------------------------------------------------------
# Wave 1: FFI length-boundary probe extensions regression tests.
# Each asserts that the generated child script (a) marks setup rejects inside
# the child and (b) references the right reject-CKR set name. _capture returns
# a SETUP_XFAIL stdout so assert_subprocess_no_crash xfails the probe before
# _parse_prefixed_int runs (these probe classes classify the target rv, unlike
# the legacy TestIsizeMaxDataLength which stops at the no-crash assertion).
# ---------------------------------------------------------------------------


def test_ffi_length_oaep_source_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA-OAEP source-data length probe must classify setup rejects in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (3, 4),
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestRsaOaepSourceDataLengthBoundary().test_rsa_oaep_source_data_length_boundary(  # noqa: E501
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"rsa_oaep_source_data_length"}
    assert "KEYPAIR_RUNTIME_REJECT_RVS" in inspect.getsource(
        ffi_length_probe._run_rsa_oaep_source_data_length
    )


def test_ffi_length_gcm_iv_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestGcmIvLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestGcmIvLengthBoundary().test_gcm_iv_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"gcm_iv_length"}
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in inspect.getsource(ffi_length_probe._run_gcm_iv_length)


def test_ffi_length_gcm_tag_bits_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestGcmTagBitsLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestGcmTagBitsLengthBoundary().test_gcm_tag_bits_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"gcm_tag_bits_length"}
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in inspect.getsource(
        ffi_length_probe._run_gcm_tag_bits_length
    )


def test_ffi_length_ccm_nonce_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestCcmNonceLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestCcmNonceLengthBoundary().test_ccm_nonce_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"ccm_nonce_length"}
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in inspect.getsource(
        ffi_length_probe._run_ccm_nonce_length
    )


def test_ffi_length_ccm_mac_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestCcmMacLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestCcmMacLengthBoundary().test_ccm_mac_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"ccm_mac_length"}
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in inspect.getsource(
        ffi_length_probe._run_ccm_mac_length
    )


def test_ffi_length_eddsa_context_child_uses_edwards_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EdDSA context-length probe must use CKM_EC_EDWARDS_KEY_PAIR_GEN setup in the child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:EC_EDWARDS keygen rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_edwards_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestEddsaContextLengthBoundary().test_eddsa_context_length_boundary(  # noqa: E501
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"eddsa_context_length"}
    eddsa_src = inspect.getsource(ffi_length_probe._run_eddsa_context_length)
    assert "CKM_EC_EDWARDS_KEY_PAIR_GEN" in eddsa_src
    assert "gen_keypair" in eddsa_src
    assert "gen_ec_keypair" not in eddsa_src
    assert "KEYPAIR_RUNTIME_REJECT_RVS" in eddsa_src


# ---------------------------------------------------------------------------
# Wave 4: TestUpdateOutputGuard + TestContinueAfterNullOutputQuery regressions
# ---------------------------------------------------------------------------


def test_ffi_length_encrypt_update_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestUpdateOutputGuard().test_encrypt_update_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_update_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_update_guard)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_EncryptUpdate" in guard_src


def test_ffi_length_encrypt_final_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptFinal probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_encrypt_final_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_final_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_final_continuation)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_EncryptFinal" in guard_src


# ---------------------------------------------------------------------------
# Phase 6 (I6): TestRecoverInputLengthBoundary + TestRecoverOutputLengthBoundary
# ---------------------------------------------------------------------------


def test_recover_input_length_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_SignRecover input-length probe must classify setup rejects in child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        _xfail_stdout = (
            "SETUP_XFAIL:RSA recover keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        )
        return ProbeResult(returncode=0, stdout=_xfail_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_recover_length_boundary.TestRecoverInputLengthBoundary().test_sign_recover_huge_data_len_does_not_crash(
            _RawSession(),
            cfg,
            0x7FFFFFFFFFFFFFFF,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "recover_length"
    assert params.get("which") == "sign_huge_data_len"
    assert params.get("data_len") == 0x7FFFFFFFFFFFFFFF


def test_recover_output_length_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_VerifyRecover output-length probe must classify setup rejects in child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        _xfail_stdout = (
            "SETUP_XFAIL:RSA recover keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        )
        return ProbeResult(returncode=0, stdout=_xfail_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_recover_length_boundary.TestRecoverOutputLengthBoundary().test_verify_recover_inflated_pul_data_len_does_not_crash(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "recover_length"
    assert params.get("which") == "verify_inflated_out_len"


# ---------------------------------------------------------------------------
# Phase 6 (I7): decrypt-update guard + continuation uncovered methods
# ---------------------------------------------------------------------------


def test_ffi_length_decrypt_update_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestUpdateOutputGuard().test_decrypt_update_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_update_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_update_guard)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_DecryptUpdate" in guard_src


def test_ffi_length_encrypt_update_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_encrypt_update_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_update_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_update_continuation)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_EncryptUpdate" in guard_src


def test_ffi_length_decrypt_update_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_decrypt_update_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_update_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_update_continuation)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_DecryptUpdate" in guard_src


def test_ffi_length_decrypt_final_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptFinal probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_decrypt_final_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_final_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_final_continuation)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_DecryptFinal" in guard_src


# ---------------------------------------------------------------------------
# Phase 2 (F1/M1): every Category-A FFI length probe must parse + classify its
# child rv, and no dead SETUP_XFAIL classify block may remain.
# ---------------------------------------------------------------------------

_F1_CATEGORY_A = [
    "test_encrypt_isize_boundary",
    "test_decrypt_isize_boundary",
    "test_sign_isize_boundary",
    "test_verify_isize_data_len",
    "test_digest_isize_boundary",
    "test_update_isize_data_len",
    "test_verify_isize_sig_len",
    "test_gcm_null_iv",
    "test_ecdh_null_public_data",
    "test_oaep_null_source_data",
    "test_hkdf_null_salt",
    "test_hkdf_null_info",
    "test_eddsa_null_context_data",
    "test_ccm_null_nonce",
    "test_concat_base_data_null",
    "test_tls_kdf_null_label",
    "test_sp800_108_null_data_params",
]


def test_f1_category_a_methods_parse_and_classify_target_rv() -> None:
    """Every Category-A FFI length probe must parse + classify its child rv.

    Migrated methods delegate the child ``TARGET_RV`` emission to the ``_probes/ffi_length.py``
    module via ``run_probe``; not-yet-migrated methods still build an inline child script.
    Either way the parent must classify the returned rv, and the child protocol string must
    exist (inline in the parent body, or via a ``run_probe`` call backed by the probe module).
    """
    src = inspect.getsource(test_ffi_length_boundary)
    probe_src = inspect.getsource(ffi_length_probe)
    for name in _F1_CATEGORY_A:
        idx = src.index(f"def {name}(")
        end = src.index("\n    def ", idx + 1) if "\n    def " in src[idx + 1 :] else len(src)
        body = src[idx:end]
        emits_rv = "TARGET_RV:" in body or "run_probe(" in body
        assert emits_rv, f"{name}: child must print TARGET_RV: (inline or via run_probe)"
        classifies = (
            "classify_negative_rv(" in body or "_classify_unhonorable_length_outcome(" in body
        )
        assert classifies, f"{name}: parent must classify the rv"
    assert "TARGET_RV:" in probe_src, "_probes/ffi_length.py must emit the TARGET_RV protocol"


def test_no_dead_setup_xfail_classify_blocks() -> None:
    """No probe may keep an unreachable `if \"SETUP_XFAIL:\" in stdout: classify(...)`."""
    src = inspect.getsource(test_ffi_length_boundary)
    assert 'if "SETUP_XFAIL:" in stdout:' not in src


def test_isize_boundary_lengths_includes_truncation_ids() -> None:
    """_ISIZE_BOUNDARY_LENGTHS must carry the un-honorable isize-boundary param ids.

    Only un-honorable lengths (values that cannot be the size of any real buffer) are
    sound for small-buffer reject probes: no addressable buffer that large can exist, so
    rejection is the only valid module response.  Honorable ~4 GB truncation-revealing
    values (trunc_low0, trunc_low8) were removed because a conformant 64-bit module
    would try to honor them, over-reading the small buffer and causing caller-induced UB.
    """
    ids = [p.id for p in test_ffi_length_boundary._ISIZE_BOUNDARY_LENGTHS]
    assert "isize_max" in ids, "un-honorable isize_max param must be present"
    assert "isize_max_plus_1" in ids, "un-honorable isize_max_plus_1 param must be present"
    assert "trunc_low0" not in ids, "honorable trunc_low0 must not be in small-buffer reject probes"
    assert "trunc_low8" not in ids, "honorable trunc_low8 must not be in small-buffer reject probes"


# ---------------------------------------------------------------------------
# WS2 Phase 2 (Family B): demand-zero output-write truncation oracle for
# C_Encrypt / C_Decrypt.  Each meta-test drives the probe via a monkeypatched
# run_probe, asserts the correct probe name and dispatch key, and confirms that
# setup rejects xfail before the child is spawned.
# ---------------------------------------------------------------------------

_OUTPUT_TRUNCATION_PROBES = [
    pytest.param(
        "TestEncryptOutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_ctr_encrypt",
        id="encrypt",
    ),
    pytest.param(
        "TestDecryptOutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_ctr_decrypt",
        id="decrypt",
    ),
]


@pytest.mark.parametrize("cls_name,method_name,which", _OUTPUT_TRUNCATION_PROBES)
def test_output_truncation_child_marks_setup_reject_and_carries_oracle(
    monkeypatch: pytest.MonkeyPatch,
    cls_name: str,
    method_name: str,
    which: str,
) -> None:
    """C_Encrypt/C_Decrypt output-truncation probe must invoke run_probe with correct params.

    Returns a SETUP_XFAIL stdout so the probe xfails before the parent parses TARGET_RV.
    The probe name must be ``"output_length"`` and the ``which`` key must select the
    correct cipher direction (aes_ctr_encrypt or aes_ctr_decrypt).
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_output_length_truncation, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_output_length_truncation, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_output_length_truncation, "run_probe", _stub_probe)

    cls = getattr(test_output_length_truncation, cls_name)
    method = getattr(cls(), method_name)
    with pytest.raises(pytest.xfail.Exception):
        method(_RawSession(), cfg)

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "output_length"
    assert params.get("which") == which
    assert params.get("module_path") == "/tmp/fake-pkcs11.so"


@pytest.mark.parametrize("cls_name,method_name,which", _OUTPUT_TRUNCATION_PROBES)
def test_output_truncation_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
    cls_name: str,
    method_name: str,
    which: str,
) -> None:
    """Output-truncation probes must preflight keygen setup before spawning a child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_output_length_truncation,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_output_length_truncation, "run_probe", _child_should_not_run)

    cls = getattr(test_output_length_truncation, cls_name)
    method = getattr(cls(), method_name)
    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        method(_RawSession(), cfg)


def test_output_truncation_oracle_polarity_is_underfill_means_fail() -> None:
    """The output oracle must keep underfill=>accepted_invalid, honored=>note polarity.

    Guards against a future edit silently inverting the demand-zero oracle (which
    would either false-fail compliant providers or hide real truncation).  The
    shared classifier routes UNDERFILL through classify_negative_rv (the
    accepted_invalid path on CKR_OK) and a non-zero probe through compliance.note.
    """
    src = inspect.getsource(test_output_length_truncation._classify_oracle)
    assert "classify_negative_rv(" in src, "underfill path must classify (accepted_invalid on OK)"
    assert "silent under-fill" in src, "underfill label must describe the truncation finding"
    assert "note(" in src, "honored (non-zero probe) path must record a compliance note, not fail"


def test_output_truncation_skips_wrapkey_and_generatekey() -> None:
    """C_WrapKey / C_GenerateKey must NOT get a demand-zero output probe.

    Their written length is governed by the key object, not a caller input length
    the caller can inflate, so the output oracle cannot prove truncation and would
    only false-fail compliant providers.  The module must document this and expose
    no such probe (the only oracle ops are C_Encrypt / C_Decrypt).
    """
    src = inspect.getsource(test_output_length_truncation)
    # No WrapKey/GenerateKey op is driven through the oracle.
    assert "C_WrapKey" not in src or "NOT a Family-B target" in src
    assert "raw.C_WrapKey(" not in src, "C_WrapKey must not be probed by the output oracle"
    assert "raw.C_GenerateKey(" not in src, "C_GenerateKey must not be probed by the output oracle"
    # The rationale for the skip is documented in the module.
    assert "NOT a Family-B target" in src
    assert "does NOT satisfy it" in src
    assert "C_GenerateKey" in src


# ---------------------------------------------------------------------------
# WS4 Phase 1: TestSingleShotOutputGuard regressions
# ---------------------------------------------------------------------------


def test_ffi_length_encrypt_single_shot_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_Encrypt probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestSingleShotOutputGuard().test_encrypt_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_single_shot_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_single_shot_guard)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_Encrypt" in guard_src
    assert "GUARD_OVERWRITE" in inspect.getsource(ffi_length_probe._run_encrypt_single_shot_guard)


def test_ffi_length_decrypt_single_shot_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_Decrypt probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestSingleShotOutputGuard().test_decrypt_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_single_shot_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_single_shot_guard)
    assert "AES_KEYGEN_RUNTIME_REJECT_RVS" in guard_src
    assert "C_Decrypt" in guard_src
    assert "GUARD_OVERWRITE" in inspect.getsource(ffi_length_probe._run_decrypt_single_shot_guard)


def test_run_with_coverage_hang_classifies_not_unclassified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subprocess hang (module did not return) must classify as a crash-class
    finding, never escape as an unclassified TimeoutExpired leak.

    Regression for the kryoptic CKA_VALUE_LEN=(1<<32)+8 hang found by the
    softhsm2/kryoptic pool validation: the module tried to allocate ~4 GiB and
    hung, and run_with_coverage's TimeoutExpired previously leaked unclassified.
    """
    import subprocess as _sp

    from pkcs11_check.testcases._subprocess_preamble import (
        SUBPROCESS_TIMEOUT_MARKER,
        SUBPROCESS_TIMEOUT_RC,
        run_with_coverage,
    )
    from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

    def _raise_timeout(*_a: object, **_k: object) -> object:
        raise _sp.TimeoutExpired(cmd="x", timeout=10, output="partial", stderr="")

    monkeypatch.setattr(_sp, "run", _raise_timeout)
    rc, _out, err = run_with_coverage("print('unused')", timeout=10)
    assert rc == SUBPROCESS_TIMEOUT_RC
    assert SUBPROCESS_TIMEOUT_MARKER in err
    # The parent must turn the hang into a recorded (crash-class) finding.
    with pytest.raises(pytest.fail.Exception):
        assert_subprocess_completed(rc, _out, err, context="probe hang regression")

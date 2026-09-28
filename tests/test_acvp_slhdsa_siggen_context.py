"""Pins for SLH-DSA sigGen context handling (NULL-matrix row).

The SLH-DSA sigGen loader must carry each vector's ``context`` bytes, take
every external-pure vector (both context shapes stay covered as a
consequence), and skip preHash groups (their messages pair with a per-test
hashAlg for the hash-sign mechanisms -- not pre-hashed digests -- so they
are not pure ``CKM_SLH_DSA`` inputs) as well as internal groups
(Sign_internal calling convention, not externally verifiable). The
sigGen test must pass non-empty context via ``mech_sign_context``
(CK_SIGN_ADDITIONAL_CONTEXT), keeping NULL params for pure vectors -- exact
sigVer parity (same conditional shape, same helper) -- and must verify each
produced signature under the intended context (must pass) and a mutated
context (must fail), so a provider that ignores context is caught. A vector
without a projection pk must recover it via CKA_PUBLIC_KEY_INFO readback or
xfail with the explicit oracle-unavailable record -- never a silent
sign-only pass.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import get_records
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_SIGN_ADDITIONAL_CONTEXT,
    CKA_PUBLIC_KEY_INFO,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases.acvp import test_acvp_slhdsa
from tests._skip_assert import assert_xfails


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SLH_DSA",
        has_mechanism_flag=lambda _m, _f: True,
    )


def _fake_siggen_vectors() -> list[dict[str, Any]]:
    """Synthetic ``load_acvp_vectors`` rows: mixed shapes plus preHash and
    internal groups. Mirrors the real corpus: internal groups carry no
    ``preHash`` key at all."""
    vectors = []
    # Mixed set: two non-empty rows, then an empty-context row.
    group = {
        "parameterSet": "SLH-DSA-SHA2-128f",
        "signatureInterface": "external",
        "preHash": "pure",
    }
    for context, tc_id in (("aa55", 101), ("bb66", 102), ("", 103)):
        vectors.append(
            {
                "input": {
                    "tcId": tc_id,
                    "sk": "aa" * 64,
                    "message": "bb" * 16,
                    "context": context,
                },
                "group": group,
            }
        )
    # Uniform set: every row carries a non-empty context.
    group = {
        "parameterSet": "SLH-DSA-SHA2-128s",
        "signatureInterface": "external",
        "preHash": "pure",
    }
    for tc_id in (201, 202):
        vectors.append(
            {
                "input": {
                    "tcId": tc_id,
                    "sk": "aa" * 64,
                    "message": "bb" * 16,
                    "context": "cc77",
                },
                "group": group,
            }
        )
    # PreHash group first in file order: must be skipped outright.
    vectors.append(
        {
            "input": {
                "tcId": 301,
                "sk": "aa" * 64,
                "message": "bb" * 16,
                "context": "dd88",
            },
            "group": {
                "parameterSet": "SLH-DSA-SHA2-192f",
                "signatureInterface": "external",
                "preHash": "preHash",
            },
        }
    )
    vectors.append(
        {
            "input": {
                "tcId": 302,
                "sk": "aa" * 64,
                "message": "bb" * 16,
            },
            "group": {
                "parameterSet": "SLH-DSA-SHA2-192f",
                "signatureInterface": "external",
                "preHash": "pure",
            },
        }
    )
    # Internal group: Sign_internal calling convention, not externally
    # verifiable -- must be skipped outright (no preHash key, like the corpus).
    for tc_id in (401, 402):
        vectors.append(
            {
                "input": {
                    "tcId": tc_id,
                    "sk": "aa" * 64,
                    "message": "bb" * 16,
                    "context": "ee99",
                },
                "group": {
                    "parameterSet": "SLH-DSA-SHA2-192s",
                    "signatureInterface": "internal",
                },
            }
        )
    return vectors


def test_siggen_loader_carries_context_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loader pins context bytes per vector; sigVer parity (``ctx_bytes`` shape)."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc101"]["context"] == bytes.fromhex("aa55")
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc103"]["context"] == b""


def test_siggen_loader_takes_all_external_pure_vectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No per-set sampling: every external-pure vector loads, so both context
    shapes (NULL and explicit parameters) stay covered for every set."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert "sigGen-SLH-DSA-SHA2-128f-tc101" in loaded
    assert "sigGen-SLH-DSA-SHA2-128f-tc102" in loaded
    assert "sigGen-SLH-DSA-SHA2-128f-tc103" in loaded
    assert "sigGen-SLH-DSA-SHA2-128s-tc201" in loaded
    assert "sigGen-SLH-DSA-SHA2-128s-tc202" in loaded
    contexts_128f = {
        loaded[f"sigGen-SLH-DSA-SHA2-128f-tc{tc}"]["context"] for tc in (101, 102, 103)
    }
    assert contexts_128f == {bytes.fromhex("aa55"), bytes.fromhex("bb66"), b""}


def test_siggen_loader_skips_pre_hash_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """PreHash groups are skipped: their messages pair with a per-test hashAlg
    for the hash-sign mechanisms (not pre-hashed digests), so they are not
    pure CKM_SLH_DSA inputs."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert "sigGen-SLH-DSA-SHA2-192f-tc301" not in loaded
    assert "sigGen-SLH-DSA-SHA2-192f-tc302" in loaded
    assert loaded["sigGen-SLH-DSA-SHA2-192f-tc302"]["context"] == b""


def test_siggen_loader_skips_internal_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Internal groups are skipped: the Sign_internal calling convention is
    not externally verifiable, so routing them through pure CKM_SLH_DSA
    would fail mathematically-valid vectors (false provider failures)."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert "sigGen-SLH-DSA-SHA2-192s-tc401" not in loaded
    assert "sigGen-SLH-DSA-SHA2-192s-tc402" not in loaded
    assert "sigGen-SLH-DSA-SHA2-128f-tc101" in loaded


def test_siggen_loader_carries_pk_for_sign_then_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loader attaches the internalProjection public key per tcId so the
    sigGen test can verify each produced signature."""
    monkeypatch.setattr(
        test_acvp_slhdsa, "load_acvp_vectors", lambda _algorithm: _fake_siggen_vectors()
    )
    monkeypatch.setattr(
        test_acvp_slhdsa,
        "_load_siggen_pk_by_tcid",
        lambda: {101: b"public-101", 102: b"public-102"},
    )
    loaded = dict(test_acvp_slhdsa._load_siggen_vectors())
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc101"]["pk"] == b"public-101"
    assert loaded["sigGen-SLH-DSA-SHA2-128f-tc102"]["pk"] == b"public-102"
    assert "pk" not in loaded["sigGen-SLH-DSA-SHA2-128f-tc103"]


def _siggen_vec(context: Any, pk: bytes | None = None) -> dict[str, Any]:
    vec: dict[str, Any] = {
        "param_set": 1,
        "param_name": "SLH-DSA-SHA2-128f",
        "sk": b"secret",
        "msg": b"message",
        "tc_id": 1,
    }
    if context is not ...:
        vec["context"] = context
    if pk is not None:
        vec["pk"] = pk
    return vec


def _run_siggen(monkeypatch: pytest.MonkeyPatch, vec: dict[str, Any]) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    verify_results = [True, False]

    def _capture(*_args: Any, **_kwargs: Any) -> bytes:
        captured.update(_kwargs)
        return b"fake-signature"

    def _verify(*_args: Any, **_kwargs: Any) -> bool:
        return verify_results.pop(0)

    # Sign-side pins need a projection pk: pk-less vectors now exercise the
    # CKA_PUBLIC_KEY_INFO recovery path (covered by the oracle tests below).
    vec = {"pk": b"public", **vec}
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _capture)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _verify)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)
    test_acvp_slhdsa.test_slhdsa_siggen(_session(), "sigGen-pin-tc1", vec)
    return captured


def _packed_context(mech_param: PackedMechanism) -> bytes:
    params = mech_param.params
    assert isinstance(params, CK_SIGN_ADDITIONAL_CONTEXT)
    assert params.pContext is not None
    return ctypes.string_at(params.pContext, params.ulContextLen)


def test_siggen_nonempty_context_selects_mech_sign_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-empty context packs via mech_sign_context; sigVer parity (same helper)."""
    captured = _run_siggen(monkeypatch, _siggen_vec(b"\xaa\x55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == b"\xaa\x55"


def test_siggen_hex_str_context_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hex-str context normalizes to bytes; sigVer parity (same conditional shape)."""
    captured = _run_siggen(monkeypatch, _siggen_vec("aa55"))
    mech_param = captured.get("mech_param")
    assert isinstance(mech_param, PackedMechanism)
    assert _packed_context(mech_param) == bytes.fromhex("aa55")


@pytest.mark.parametrize("context", [b"", ...], ids=["empty-bytes", "missing-key"])
def test_siggen_pure_vector_keeps_null_params(
    monkeypatch: pytest.MonkeyPatch, context: Any
) -> None:
    """Empty/missing context keeps NULL params; sigVer parity (``if context`` guard)."""
    captured = _run_siggen(monkeypatch, _siggen_vec(context))
    assert captured.get("mech_param") is None


def _run_siggen_with_verify(
    monkeypatch: pytest.MonkeyPatch, vec: dict[str, Any], verify_results: list[bool]
) -> dict[str, Any]:
    """Run sigGen with stubbed sign/verify; records both call streams."""
    calls: dict[str, Any] = {"sign": [], "verify": []}
    results = list(verify_results)

    def _sign(*_args: Any, **_kwargs: Any) -> bytes:
        calls["sign"].append(_kwargs)
        return b"fake-signature"

    def _verify(*_args: Any, **_kwargs: Any) -> bool:
        calls["verify"].append(_kwargs)
        return results.pop(0)

    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _sign)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _verify)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)
    test_acvp_slhdsa.test_slhdsa_siggen(_session(), "sigGen-pin-tc1", vec)
    return calls


def test_siggen_verifies_produced_signature_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Produced signature verifies under the intended context, then fails
    under a mutated context; the signing context is passed through."""
    calls = _run_siggen_with_verify(
        monkeypatch, _siggen_vec(b"\xaa\x55", pk=b"public"), [True, False]
    )
    assert len(calls["sign"]) == 1
    assert len(calls["verify"]) == 2
    assert _packed_context(calls["sign"][0]["mech_param"]) == b"\xaa\x55"
    assert _packed_context(calls["verify"][0]["mech_param"]) == b"\xaa\x55"
    assert _packed_context(calls["verify"][1]["mech_param"]) != b"\xaa\x55"


def test_siggen_empty_context_mutated_check_uses_explicit_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty-context vectors sign/verify with NULL params, but the mutated
    check must use explicit (non-empty) context params to be meaningful."""
    calls = _run_siggen_with_verify(monkeypatch, _siggen_vec(b"", pk=b"public"), [True, False])
    assert len(calls["verify"]) == 2
    assert calls["verify"][0].get("mech_param") is None
    mutated_param = calls["verify"][1].get("mech_param")
    assert isinstance(mutated_param, PackedMechanism)
    assert _packed_context(mutated_param) != b""


def test_siggen_ignored_context_signature_is_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fault injection: a provider that accepts the produced signature under
    ANY context (context ignored) must fail, not pass silently."""
    from _pytest.outcomes import Failed

    with pytest.raises(Failed):
        _run_siggen_with_verify(monkeypatch, _siggen_vec(b"\xaa\x55", pk=b"public"), [True, True])


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _spki_der(public_key: bytes) -> bytes:
    """Minimal SubjectPublicKeyInfo DER wrapping raw public-key bytes (fake OID)."""
    alg_id = b"\x30\x03\x06\x01\x2a"
    bit_string = b"\x00" + public_key
    body = alg_id + b"\x03" + _der_len(len(bit_string)) + bit_string
    return b"\x30" + _der_len(len(body)) + body


def _run_siggen_no_projection_pk(
    monkeypatch: pytest.MonkeyPatch,
    vec: dict[str, Any],
    *,
    spki: bytes | None = None,
    read_error: Exception | None = None,
) -> dict[str, Any]:
    """Run sigGen on a projection-pk-less vec: one-byte signer, stubbed readback."""
    calls: dict[str, Any] = {"sign": [], "verify": [], "public_imports": []}
    results = [True, False]

    def _sign(*_args: Any, **_kwargs: Any) -> bytes:
        calls["sign"].append(_kwargs)
        return b"\x01"

    def _verify(*_args: Any, **_kwargs: Any) -> bool:
        calls["verify"].append(_kwargs)
        return results.pop(0)

    def _read_attributes(*_args: Any, **_kwargs: Any) -> dict[Any, Any]:
        if read_error is not None:
            raise read_error
        if spki is None:
            return {}
        return {CKA_PUBLIC_KEY_INFO: spki}

    def _import_public(*_args: Any, **kwargs: Any) -> int:
        calls["public_imports"].append(kwargs)
        return 2

    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_acvp_slhdsa, "import_pqc_public_key", _import_public)
    monkeypatch.setattr(test_acvp_slhdsa, "sign_single", _sign)
    monkeypatch.setattr(test_acvp_slhdsa, "verify_single", _verify)
    # raising=False: pre-fix the module has no read_attributes import and the
    # stub is simply never consulted (the silent sign-only pass under test).
    monkeypatch.setattr(test_acvp_slhdsa, "read_attributes", _read_attributes, raising=False)
    monkeypatch.setattr(test_acvp_slhdsa, "destroy_quietly", lambda *_args: None)
    test_acvp_slhdsa.test_slhdsa_siggen(_session(), "sigGen-pin-tc1", vec)
    return calls


def test_siggen_missing_pk_without_readback_xfails_oracle_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing projection pk + no CKA_PUBLIC_KEY_INFO readback must xfail with
    the explicit oracle-unavailable record -- never a silent sign-only pass."""
    vec = _siggen_vec(b"\xaa\x55")  # no pk: missing internalProjection entry
    xfailed = assert_xfails(
        _run_siggen_no_projection_pk, monkeypatch, vec, match="oracle unavailable"
    )
    assert "sigGen-pin-tc1" in str(xfailed)


def test_siggen_missing_pk_readback_rejection_xfails_oracle_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected C_GetAttributeValue readback is also recovery-impossible:
    xfail with the oracle record, not a pass."""
    vec = _siggen_vec(b"\xaa\x55")
    err = CkrAssertionError("C_GetAttributeValue: Unexpected CK_RV", int(CKR_FUNCTION_FAILED))
    assert_xfails(
        _run_siggen_no_projection_pk,
        monkeypatch,
        vec,
        read_error=err,
        match="oracle unavailable",
    )


def test_siggen_missing_pk_readback_recovery_runs_verify_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recoverable CKA_PUBLIC_KEY_INFO readback imports the recovered pk and
    runs the SAME intended/mutated verify-compare as a projection pk."""
    recovered = bytes(range(32))  # realistic 128f public-key length
    vec = _siggen_vec(b"\xaa\x55")
    calls = _run_siggen_no_projection_pk(monkeypatch, vec, spki=_spki_der(recovered))
    assert calls["public_imports"][0]["value"] == recovered
    assert len(calls["verify"]) == 2
    assert _packed_context(calls["verify"][0]["mech_param"]) == b"\xaa\x55"
    assert _packed_context(calls["verify"][1]["mech_param"]) != b"\xaa\x55"


def test_siggen_missing_pk_unparseable_readback_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nonempty but unparseable CKA_PUBLIC_KEY_INFO bytes fail wrong_result.

    Intentional change from the earlier oracle-unavailable xfail: a CKR_OK
    read that delivers present-but-malformed bytes is provider-malformed
    metadata, not unavailability -- the require_* idiom (present-malformed
    fails, only missing xfails). Swallowing it as oracle-unavailable would
    hide provider bugs behind a not-operational record.
    """
    vec = _siggen_vec(b"\xaa\x55")
    with pytest.raises(Failed) as exc_info:
        _run_siggen_no_projection_pk(monkeypatch, vec, spki=b"\x30\x03oops")
    assert not isinstance(exc_info.value, XFailed)
    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None


def test_siggen_recovered_pk_wrong_length_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recovered key whose length mismatches the parameter set fails
    wrong_result -- it must never reach import, where a CKR_KEY_SIZE_RANGE
    reject would decay into a not-operational XFAIL hiding malformed
    readback. (128f expects a 32-byte public key.)"""
    vec = _siggen_vec(b"\xaa\x55")
    with pytest.raises(Failed) as exc_info:
        _run_siggen_no_projection_pk(monkeypatch, vec, spki=_spki_der(b"\x01"))
    assert not isinstance(exc_info.value, XFailed)
    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None


def test_siggen_malformed_oid_readback_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SPKI whose OID encoding is malformed fails wrong_result end to end,
    even with an otherwise valid key payload."""
    vec = _siggen_vec(b"\xaa\x55")
    spki = _spki_der_with_alg(b"\x30\x02\x06\x00", bytes(range(32)))
    with pytest.raises(Failed) as exc_info:
        _run_siggen_no_projection_pk(monkeypatch, vec, spki=spki)
    assert not isinstance(exc_info.value, XFailed)
    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"


def test_siggen_missing_pk_empty_payload_readback_fails_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonempty SPKI whose BIT STRING carries no key bytes is malformed,
    not unavailable: an SLH-DSA public key cannot be empty."""
    vec = _siggen_vec(b"\xaa\x55")
    with pytest.raises(Failed) as exc_info:
        _run_siggen_no_projection_pk(monkeypatch, vec, spki=_spki_der(b""))
    assert not isinstance(exc_info.value, XFailed)
    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"


def test_siggen_missing_pk_empty_readback_xfails_oracle_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty CKA_PUBLIC_KEY_INFO bytes carry no key: still recovery-impossible,
    xfail with the oracle record -- only NONEMPTY unparseable bytes fail."""
    vec = _siggen_vec(b"\xaa\x55")
    assert_xfails(
        _run_siggen_no_projection_pk,
        monkeypatch,
        vec,
        spki=b"",
        match="oracle unavailable",
    )


def test_siggen_missing_pk_readback_undefined_ckr_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fault injection: an UNDEFINED CK_RV (neither standard nor
    vendor-defined) from the readback must propagate, never be absorbed as
    oracle-unavailable."""
    vec = _siggen_vec(b"\xaa\x55")
    err = CkrAssertionError("C_GetAttributeValue: Unexpected CK_RV", 0x12345678)
    try:
        _run_siggen_no_projection_pk(monkeypatch, vec, read_error=err)
    except CkrAssertionError as exc:
        assert exc.rv == 0x12345678
        return
    except XFailed as exc:
        pytest.fail(f"undefined CK_RV was absorbed as oracle-unavailable: {exc}")
    pytest.fail("undefined CK_RV read error was swallowed entirely")


def test_siggen_missing_pk_readback_vendor_ckr_xfails_oracle_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vendor-defined CK_RV refusal is still a defined refusal: xfail with
    the oracle record, like CKR_FUNCTION_FAILED."""
    vec = _siggen_vec(b"\xaa\x55")
    err = CkrAssertionError("C_GetAttributeValue: Unexpected CK_RV", 0x80000001)
    assert_xfails(
        _run_siggen_no_projection_pk,
        monkeypatch,
        vec,
        read_error=err,
        match="oracle unavailable",
    )


@pytest.mark.parametrize("public_key", [b"public", bytes(range(256))])
def test_spki_extractor_returns_bit_string_contents(public_key: bytes) -> None:
    """The SPKI extractor returns the BIT STRING contents (short + long form)."""
    assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der(public_key)) == public_key


def test_spki_extractor_rejects_garbage() -> None:
    """The SPKI extractor returns None when the DER cannot be parsed at all."""
    assert test_acvp_slhdsa._spki_public_key_bytes(b"not-der") is None
    assert test_acvp_slhdsa._spki_public_key_bytes(b"\x30\x03oops") is None
    assert test_acvp_slhdsa._spki_public_key_bytes(b"") is None
    truncated = _spki_der(b"public")[:-3]
    assert test_acvp_slhdsa._spki_public_key_bytes(truncated) is None


def _spki_der_with_alg(alg_id: bytes, public_key: bytes) -> bytes:
    """SPKI DER with an explicit AlgorithmIdentifier body (fake key material)."""
    bit_string = b"\x00" + public_key
    body = alg_id + b"\x03" + _der_len(len(bit_string)) + bit_string
    return b"\x30" + _der_len(len(body)) + body


def test_spki_extractor_requires_oid_in_algorithm_identifier() -> None:
    """The AlgorithmIdentifier must structurally carry an OBJECT IDENTIFIER:
    an empty sequence or a NULL-only body is malformed even when followed
    by a valid key."""
    key = bytes(range(32))
    assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der(key)) == key
    assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der_with_alg(b"\x30\x00", key)) is None
    assert (
        test_acvp_slhdsa._spki_public_key_bytes(_spki_der_with_alg(b"\x30\x02\x05\x00", key))
        is None
    )


def test_spki_extractor_rejects_malformed_oid_contents() -> None:
    """OID encodings must be well-formed base-128: nonempty, terminated,
    minimal. Unfamiliar but well-formed OIDs still parse (value not pinned)."""
    key = bytes(range(32))
    assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der(key)) == key
    for bad_oid in (b"\x06\x00", b"\x06\x01\x80", b"\x06\x02\x80\x2a"):
        alg = b"\x30" + _der_len(len(bad_oid)) + bad_oid
        assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der_with_alg(alg, key)) is None


def test_spki_extractor_rejects_trailing_algorithm_bytes() -> None:
    """After the OID, the AlgorithmIdentifier may carry at most one
    well-formed parameters element (e.g. NULL); trailing garbage fails."""
    key = bytes(range(32))
    with_null = _spki_der_with_alg(b"\x30\x05\x06\x01\x2a\x05\x00", key)
    assert test_acvp_slhdsa._spki_public_key_bytes(with_null) == key
    trailing = _spki_der_with_alg(b"\x30\x04\x06\x01\x2a\xff", key)
    assert test_acvp_slhdsa._spki_public_key_bytes(trailing) is None


def test_spki_extractor_rejects_nonminimal_lengths() -> None:
    """DER lengths must be minimal: no long form below 128, no leading zero
    octets in long form."""
    good = _spki_der(bytes(range(32)))
    assert good[1] == len(good) - 2  # short-form outer length below 128
    long_for_short = b"\x30\x81" + good[1:2] + good[2:]
    assert test_acvp_slhdsa._spki_public_key_bytes(long_for_short) is None
    head, sep, tail = good.partition(b"\x03\x21")
    assert sep  # BIT STRING header for the 33-byte key field
    widened = head + b"\x03\x81\x21" + tail
    widened = b"\x30" + bytes([widened[1] + 1]) + widened[2:]
    assert test_acvp_slhdsa._spki_public_key_bytes(widened) is None


def test_spki_extractor_rejects_length_mismatch_and_empty_payload() -> None:
    """The extractor validates the full encoding: outer length must match the
    input exactly (no truncation, no trailing bytes) and the key payload must
    be nonempty -- an SLH-DSA public key cannot be empty."""
    good = _spki_der(b"public")
    assert test_acvp_slhdsa._spki_public_key_bytes(good + b"\x00") is None
    oversized = b"\x30\x7f" + good[2:]
    assert test_acvp_slhdsa._spki_public_key_bytes(oversized) is None
    assert test_acvp_slhdsa._spki_public_key_bytes(_spki_der(b"")) is None

"""QF4 structured RSA implicit rejection (#37 and #49.2).

The structured PKCS#1 v1.5 node must separate per-sample evidence from the
cross-sample assessment: only exact output equality to a known would-be
payload witnesses plaintext exposure; behavior consistent with deterministic
implicit rejection is a visible posture xfail (never a security certificate);
anything short of either stays a visible unresolved xfail. A constant-output
invalid decoder must remain unresolved even with a correct valid control.

These tests drive the ACTUAL production structured method through a stateful
PKCS#11 fake (real Init/query/output phases with ctypes buffers), never the
assessor alone. Witness/control ciphertexts below are derived from an
independent test-local reading of the fixed spec shapes (``00 02 || PS7 ||
00 || payload`` and a valid ``00 02 || PS>=8 || 00 || M`` block); the
correspondence test pins them byte-identical to the production builders, so a
production-construction drift fails loudly instead of silently re-keying the
scripted provider behaviors.
"""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification, compliance
from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.testcases.security import test_padding_oracle as tpo

_K = 256
_N = 2**2048 - 159
_E = 65537
_BOUNDARY = 1 << (8 * (_K - 1))

# Independent spec shapes (see module docstring). Production builders must
# produce byte-identical blocks; test_builder correspondence pins that.
_PS7 = bytes(range(1, 8))
_WITNESS_PAYLOAD = bytes((i * 37 + 11) % 256 for i in range(_K - 10))
_WITNESS_ENCODED = b"\x00\x02" + _PS7 + b"\x00" + _WITNESS_PAYLOAD
_CONTROL_MESSAGE = b"QF4-v15-valid-control-plaintext"
_CONTROL_PS = bytes(((i * 53 + 7) % 255) + 1 for i in range(_K - 3 - len(_CONTROL_MESSAGE)))
_CONTROL_ENCODED = b"\x00\x02" + _CONTROL_PS + b"\x00" + _CONTROL_MESSAGE

assert len(_WITNESS_ENCODED) == _K
assert len(_WITNESS_PAYLOAD) == _K - 10
assert len(_CONTROL_ENCODED) == _K
assert len(_CONTROL_PS) >= 8


def _spec_cat1(index: int) -> bytes:
    """Deterministic ``00 02``-prefixed separator-less encoding (test oracle)."""
    body = bytes(((index + j) % 255) + 1 for j in range(_K - 2))
    return b"\x00\x02" + body


def _spec_cat2(index: int) -> bytes:
    """Deterministic non-``00 02`` encoding with top byte nonzero (test oracle)."""
    return (_BOUNDARY + 7 + index).to_bytes(_K, "big")


def _ct(encoded: bytes) -> bytes:
    """The test's independent public transformation ``c = m^e mod n``."""
    return pow(int.from_bytes(encoded, "big"), _E, _N).to_bytes(_K, "big")


def _prefix_ciphertexts() -> list[bytes]:
    cts: list[bytes] = []
    for i in range(50):
        cts.append(_ct(_spec_cat1(i)))
        cts.append(_ct(_spec_cat2(i)))
    return cts


_WITNESS_CT = _ct(_WITNESS_ENCODED)
_CONTROL_CT = _ct(_CONTROL_ENCODED)


# --- Scripted provider behaviors: ("reject", phase, rv) / ("output", ...) ---
_Behavior = tuple[Any, ...]


def _reject(phase: str, rv: int) -> _Behavior:
    assert phase in ("init", "query", "output")
    return ("reject", phase, int(rv))


def _output(out: bytes, *, reported: int | None = None, estimate: int | None = None) -> _Behavior:
    return ("output", bytes(out), reported, estimate)


def _raise(exc: BaseException, phase: str = "output") -> _Behavior:
    assert phase in ("init", "query", "output")
    return ("raise", exc, phase)


_DecryptMap = dict[bytes, _Behavior] | Callable[[bytes, int], _Behavior]


class _V15FakeRaw:
    """Stateful PKCS#11 fake with real Init/query/output phases (ctypes buffers).

    ``decrypt`` maps each queried ciphertext to a behavior (dict, fail-loud on
    an unscripted ciphertext) or resolves it by ``(ciphertext, query_index)``.
    Init behavior is global (``init_rv``) or per-init (``init_script``).
    ``destroy_script`` pops one entry per ``C_DestroyObject`` (None = CKR_OK).
    """

    def __init__(
        self,
        decrypt: _DecryptMap,
        *,
        init_rv: int | BaseException = int(CKR_OK),
        init_script: list[int | BaseException] | None = None,
        destroy_script: list[BaseException | None] | None = None,
    ) -> None:
        self._decrypt = decrypt
        self._init_rv = init_rv
        self._init_script = list(init_script or [])
        self._destroy_script = list(destroy_script or [])
        self.init_count = 0
        self.query_ciphertexts: list[bytes] = []
        self.output_ciphertexts: list[bytes] = []
        self.abort_count = 0
        self.cancel_count = 0
        self.destroyed: list[int] = []
        self._pending: tuple[bytes, _Behavior] | None = None

    def _resolve(self, ct: bytes) -> _Behavior:
        decrypt = self._decrypt
        if isinstance(decrypt, dict):
            if ct not in decrypt:
                raise AssertionError(f"unscripted ciphertext {ct.hex()[:32]}...")
            return decrypt[ct]
        return decrypt(ct, len(self.query_ciphertexts))

    def C_DecryptInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        self.init_count += 1
        if self._init_script:
            outcome: int | BaseException = self._init_script.pop(0)
        else:
            outcome = self._init_rv
        if isinstance(outcome, BaseException):
            raise outcome
        return int(outcome)

    def C_Decrypt(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out_buf: Any, out_len: Any
    ) -> int:
        ct = bytes(in_buf[:in_len])
        if out_buf is None:
            behavior = self._resolve(ct)
            self._pending = (ct, behavior)
            self.query_ciphertexts.append(ct)
            kind = behavior[0]
            if kind == "reject" and behavior[1] == "query":
                return int(behavior[2])
            if kind == "raise" and behavior[2] == "query":
                raise behavior[1]
            if kind == "output":
                estimate = behavior[3]
                out_len._obj.value = len(behavior[1]) if estimate is None else estimate
                return int(CKR_OK)
            if kind == "reject" and behavior[1] == "output":
                out_len._obj.value = 32
                return int(CKR_OK)
            if kind == "raise" and behavior[2] == "output":
                out_len._obj.value = 32
                return int(CKR_OK)
            raise AssertionError(f"bad query behavior {behavior!r} (init phase uses init_script)")
        pending = self._pending
        assert pending is not None and pending[0] == ct, "output call without size query"
        self.output_ciphertexts.append(ct)
        behavior = pending[1]
        kind = behavior[0]
        if kind == "reject":
            assert behavior[1] == "output", f"query already rejected {behavior!r}"
            return int(behavior[2])
        if kind == "raise":
            raise behavior[1]
        assert kind == "output", f"bad output behavior {kind!r}"
        out, reported, _estimate = behavior[1], behavior[2], behavior[3]
        rep = len(out) if reported is None else reported
        cap = len(out_buf)
        for i in range(min(len(out), cap)):
            out_buf[i] = out[i]
        out_len._obj.value = rep
        return int(CKR_OK)

    def C_DecryptFinal(self, *_args: Any) -> int:  # noqa: N802
        self.abort_count += 1
        return int(CKR_OK)

    def C_SessionCancel(self, *_args: Any) -> int:  # noqa: N802
        self.cancel_count += 1
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(handle)
        if self._destroy_script:
            fault = self._destroy_script.pop(0)
            if fault is not None:
                raise fault
        return int(CKR_OK)


def _run_structured(
    monkeypatch: pytest.MonkeyPatch, raw: _V15FakeRaw, *, n: int = _N, e: int = _E, k: int = _K
) -> None:
    """Drive the actual production structured node with deterministic samplers."""
    monkeypatch.setattr(tpo, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        tpo,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_MODULUS: n.to_bytes(k, "big"),
            CKA_PUBLIC_EXPONENT: e.to_bytes(3, "big"),
        },
    )
    cat1 = iter(_spec_cat1(i) for i in range(50))
    cat2 = iter(_spec_cat2(i) for i in range(50))
    monkeypatch.setattr(tpo, "_sample_bleichenbacher_cat1", lambda _n, _k: next(cat1))
    monkeypatch.setattr(tpo, "_sample_bleichenbacher_cat2", lambda _n, _k: next(cat2))
    classification.clear()
    compliance.clear_notes()
    tpo.TestRSAPaddingOracle().test_pkcs1v15_bleichenbacher_structured_oracle(
        SimpleNamespace(raw=raw, sh=1)
    )


def _full_sequence() -> list[bytes]:
    return _prefix_ciphertexts() + [_WITNESS_CT, _WITNESS_CT, _CONTROL_CT]


def _records() -> list[Any]:
    return classification.get_records()


# --- False-positive fix: an early CKR_OK completes the bounded collection ---


def test_first_ok_completes_all_categories_repeats_and_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first CKR_OK neither fails as bypass nor truncates later evidence.

    Pre-fix this reports ``accepted_invalid`` and stops after one decrypt; the
    single separator-less accept must instead complete all 103 operations and
    surface as visible unresolved evidence (one sample cannot prove exposure
    or rejection behavior).
    """
    first_ct = _prefix_ciphertexts()[0]
    first_out = sha256(b"first-ok" + first_ct).digest()
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(first_out)
            if ct == first_ct
            else (
                _output(_CONTROL_MESSAGE)
                if ct == _CONTROL_CT
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert raw.query_ciphertexts == _full_sequence()
    reasons = [r.reason for r in _records()]
    assert reasons == ["honest_deviation"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["assessment"] == "unresolved"


def test_healthy_rejection_passes_with_exact_103_call_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uniform rejection plus a correct valid control passes with zero records.

    Pins the unchanged 100-attempt alternating prefix (sampler order and the
    public ``c = m^e mod n`` transform), the appended witness, its exact
    repeat, and the valid control: exactly 103 semantic decrypts. Every
    rejection also aborts its operation (state-cleanup parity).
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        )
    )
    try:
        _run_structured(monkeypatch, raw)
    except (pytest.skip.Exception, pytest.xfail.Exception) as exc:
        pytest.fail(f"healthy rejection must pass, got {exc!r}")
    assert raw.init_count == 103
    assert raw.query_ciphertexts == _full_sequence()
    assert raw.output_ciphertexts == raw.query_ciphertexts
    assert raw.abort_count == 102  # every rejection aborted; the control accepts
    assert raw.cancel_count == 102  # recipe-parity cancel on each failed output
    assert _records() == []
    assert raw.destroyed == [11, 12]


# --- Posture: synthetic-consistent vs unresolved ---


def _synthetic_output(ct: bytes) -> bytes:
    """Deterministic ciphertext-derived output (implicit-rejection shape)."""
    return sha256(b"implicit-rejection" + ct).digest()[:32]


def test_synthetic_outputs_yield_posture_not_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stable per-input, cross-input-varying outputs plus an exact valid control.

    This is the OpenSSL-style deterministic implicit-rejection shape: it must
    xfail as named posture evidence, explicitly not a pass and not a security
    certificate (timing/side-channel safety is unassessed).
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE) if ct == _CONTROL_CT else _output(_synthetic_output(ct))
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="implicit rejection"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == ["honest_deviation"]
    record = _records()[0]
    assert record.detail is not None
    assert record.detail["assessment"] == "synthetic_consistent"
    assert "not a security certificate" in record.summary


def test_constant_output_stays_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """One output for every invalid ciphertext proves nothing, even valid-OK.

    A constant-output invalid decoder is indistinguishable from a broken
    decoder by bounded functional evidence; the correct valid control must not
    promote it to synthetic-consistent.
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: _output(_CONTROL_MESSAGE) if ct == _CONTROL_CT else _output(b"C" * 32)
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == ["honest_deviation"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["assessment"] == "unresolved"


def test_zero_output_stays_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """All-zero CKR_OK output is not a bypass witness (no separator, no payload)."""
    raw = _V15FakeRaw(
        lambda ct, _qi: _output(_CONTROL_MESSAGE) if ct == _CONTROL_CT else _output(bytes(32))
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["honest_deviation"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["assessment"] == "unresolved"


def test_unstable_witness_repeat_stays_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepted outputs without same-input stability cannot be synthetic."""
    repeat_out = sha256(b"unstable-repeat").digest()[:32]
    raw = _V15FakeRaw(
        lambda ct, qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(repeat_out)
                if ct == _WITNESS_CT and qi == 101
                else _output(_synthetic_output(ct))
            )
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.query_ciphertexts[100] == raw.query_ciphertexts[101] == _WITNESS_CT
    assert [r.reason for r in _records()] == ["honest_deviation"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["assessment"] == "unresolved"


# --- Hard findings: exposure and malformed lengths ---


def test_ps7_witness_leak_is_accepted_invalid_and_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact known-suffix output is a witnessed bypass; collection continues.

    The seeded naive-unpad shape returns the exact 246-byte would-be payload
    (``k-10``, one byte above the ``k-11`` mechanism maximum): both the
    exposure and the independent overlength finding are retained, exposure
    primary, and the later repeat/control still run (nonterminal retention).
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(Failed, match="bypass"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert raw.query_ciphertexts == _full_sequence()
    reasons = [r.reason for r in _records()]
    # The posture carrier preserves the completed corpus alongside the fails.
    assert reasons == ["accepted_invalid", "wrong_result", "honest_deviation"]
    exposure = _records()[0]
    assert exposure.kind == "crypto"
    assert exposure.detail is not None
    assert exposure.detail["sample_id"] == "witness"
    assert "this sample only" in exposure.summary


def test_overlong_old_sample_is_wrong_result_and_collection_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK above ``k-11`` without a known payload is malformed, not exposure."""
    long_ct = _prefix_ciphertexts()[5]
    long_out = bytes((i * 13 + 5) % 256 for i in range(246))
    assert long_out != _WITNESS_PAYLOAD
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(long_out)
                if ct == long_ct
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(Failed, match="malformed|length"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    # The posture carrier preserves the completed corpus alongside the fail.
    assert [r.reason for r in _records()] == ["wrong_result", "honest_deviation"]


def test_overreported_length_fails_closed_without_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CKR_OK length beyond capacity stops collection; no posture is invented."""
    bad_ct = _prefix_ciphertexts()[3]
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(b"Z" * 8, reported=300, estimate=8)
            if ct == bad_ct
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        )
    )
    with pytest.raises(Failed, match="malformed|length|capacity"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 4
    assert [r.reason for r in _records()] == ["wrong_result"]
    detail = _records()[0].detail
    assert detail is not None
    assert detail["reported"] == 300
    assert detail["capacity"] == 8


# --- Valid control ---


def test_valid_control_wrong_plaintext_is_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An independently valid ciphertext decrypting wrongly is broken decoding."""
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(b"WRONG-" + bytes(26))
            if ct == _CONTROL_CT
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        )
    )
    with pytest.raises(Failed, match="valid"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    # The posture carrier preserves the completed corpus alongside the fail.
    assert [r.reason for r in _records()] == ["wrong_result", "honest_deviation"]


def test_valid_control_clean_refusal_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected valid control voids the premise; the assessment is unresolved."""
    raw = _V15FakeRaw(lambda ct, _qi: _reject("output", CKR_ENCRYPTED_DATA_INVALID))
    with pytest.raises(pytest.xfail.Exception, match="not operational|unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == ["not_operational"]
    detail = _records()[0].detail
    assert detail is not None
    assert detail["rv"] == "CKR_ENCRYPTED_DATA_INVALID"
    assert detail["phase"] == "output"


# --- Category oracle: persistent correlation vs startup transient ---


def test_persistent_category_correlation_still_fails_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repeated category-correlated status distinction stays a crypto oracle."""
    cat1_cts = set(_prefix_ciphertexts()[0::2])
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _reject("output", CKR_ENCRYPTED_DATA_INVALID)
                if ct in cat1_cts
                else _reject("output", CKR_DATA_INVALID)
            )
        )
    )
    with pytest.raises(Failed, match="Bleichenbacher"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["oracle"]
    detail = _records()[0].detail
    assert detail is not None
    assert detail["oracle"]["status"] == "persistent"


def test_transient_status_diversity_is_unresolved_not_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A startup-transient status blip is not a proved category oracle.

    Only the first cat-1 sample rejects distinctly; the distinction vanishes
    outside the bounded startup window, so it stays visible unresolved
    evidence instead of failing as a Bleichenbacher oracle.
    """
    transient_ct = _prefix_ciphertexts()[0]
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _reject("output", CKR_DEVICE_ERROR)
                if ct == transient_ct
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved|transient"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == ["honest_deviation"]
    record = _records()[0]
    assert record.detail is not None
    assert record.detail["assessment"] == "unresolved"
    assert record.detail["oracle"]["status"] == "transient"


def test_unrepeated_mid_run_flake_is_unresolved_not_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single mid-run odd status is unrepeated evidence, not an oracle."""
    flake_ct = _prefix_ciphertexts()[60]
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _reject("output", CKR_DEVICE_ERROR)
                if ct == flake_ct
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["honest_deviation"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["oracle"]["status"] == "transient"


# --- Phase-specific refusal evidence ---


def test_init_phase_refusal_carries_phase_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Init-phase rejects retain their phase and still abort each operation."""
    raw = _V15FakeRaw(
        lambda ct, _qi: _reject("output", CKR_ENCRYPTED_DATA_INVALID),
        init_script=[int(CKR_DEVICE_ERROR)] * 103,
    )
    with pytest.raises(pytest.xfail.Exception, match="not operational|unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert raw.query_ciphertexts == []
    assert raw.abort_count == 103
    assert raw.cancel_count == 0  # init failures never reach cancel (recipe parity)
    assert [r.reason for r in _records()] == ["not_operational"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["phase"] == "init"


def test_query_phase_refusal_carries_phase_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Query-phase rejects never reach the output call; the phase is retained."""
    raw = _V15FakeRaw(lambda ct, _qi: _reject("query", CKR_DATA_INVALID))
    with pytest.raises(pytest.xfail.Exception, match="not operational|unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert len(raw.query_ciphertexts) == 103
    assert raw.output_ciphertexts == []
    assert raw.abort_count == 103
    assert raw.cancel_count == 103
    assert [r.reason for r in _records()] == ["not_operational"]
    assert _records()[0].detail is not None
    assert _records()[0].detail["phase"] == "query"


def test_tiny_modulus_premise_check_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A modulus too small for the valid control voids the premise upfront."""
    n_small = 2**255 - 19  # 255 bits -> k = 32 < 40
    assert (n_small.bit_length() + 7) // 8 == 32
    raw = _V15FakeRaw(lambda ct, _qi: _reject("output", CKR_ENCRYPTED_DATA_INVALID))
    with pytest.raises(pytest.xfail.Exception, match="too small"):
        _run_structured(monkeypatch, raw, n=n_small, e=_E, k=32)
    assert raw.init_count == 0
    assert [r.reason for r in _records()] == ["not_operational"]
    assert raw.destroyed == [11, 12]


def test_driver_tolerates_buffer_too_small_size_query() -> None:
    """A BUFFER_TOO_SMALL size query proceeds to the output call (recipe parity)."""
    calls: list[str] = []
    out = b"ok-bytes"

    class _BTSRaw:
        def C_DecryptInit(self, *_args: Any) -> int:  # noqa: N802
            calls.append("init")
            return int(CKR_OK)

        def C_Decrypt(  # noqa: N802
            self, _sh: int, _in_buf: Any, _in_len: int, out_buf: Any, out_len: Any
        ) -> int:
            if out_buf is None:
                calls.append("query")
                out_len._obj.value = len(out)
                return int(CKR_BUFFER_TOO_SMALL)
            calls.append("output")
            for i, byte in enumerate(out):
                out_buf[i] = byte
            out_len._obj.value = len(out)
            return int(CKR_OK)

        def C_SessionCancel(self, *_args: Any) -> int:  # noqa: N802
            calls.append("cancel")
            return int(CKR_OK)

    attempt = tpo._v15_decrypt_attempt(_BTSRaw(), 1, 2, b"C" * 256)
    assert attempt.accepted
    assert attempt.output == out
    assert attempt.query_rv == int(CKR_BUFFER_TOO_SMALL)
    assert attempt.reported_len == len(out)
    assert attempt.capacity == len(out)
    assert calls == ["init", "query", "output"]


def test_driver_recovers_from_stale_operation_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale ACTIVE init cancels and retries once (init-or-recover parity)."""
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        ),
        init_script=[int(CKR_OPERATION_ACTIVE)] + [int(CKR_OK)] * 103,
    )
    try:
        _run_structured(monkeypatch, raw)
    except (pytest.skip.Exception, pytest.xfail.Exception) as exc:
        pytest.fail(f"recovered collection must pass, got {exc!r}")
    assert raw.init_count == 104  # one cancel-and-retry on the first attempt
    assert raw.cancel_count == 102 + 1
    assert len(raw.query_ciphertexts) == 103
    assert _records() == []


# --- Incomplete collection and cleanup faults ---


def test_raw_fault_mid_collection_propagates_without_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raw fault stops collection loudly; no posture finding is invented."""
    fault_ct = _prefix_ciphertexts()[10]
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _raise(RuntimeError("provider transport boom"))
            if ct == fault_ct
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        )
    )
    with pytest.raises(RuntimeError, match="provider transport boom"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 11
    assert _records() == []
    assert raw.destroyed == [11, 12]


def test_exposure_survives_later_raw_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A witnessed exposure is retained before the later control call faults."""
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _raise(RuntimeError("control transport boom"))
            if ct == _CONTROL_CT
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(RuntimeError, match="control transport boom"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["accepted_invalid", "wrong_result"]
    assert raw.destroyed == [11, 12]


def test_exposure_survives_cleanup_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A teardown fault neither replaces the exposure nor skips the second key."""
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        ),
        destroy_script=[RuntimeError("teardown boom"), None],
    )
    with pytest.raises(Failed, match="bypass"):
        _run_structured(monkeypatch, raw)
    # The posture carrier preserves the completed corpus alongside the fails.
    assert [r.reason for r in _records()] == [
        "accepted_invalid",
        "wrong_result",
        "honest_deviation",
    ]
    assert raw.destroyed == [11, 12]
    notes = compliance.get_notes()
    assert any("teardown" in note.description for note in notes)


def test_first_destroy_fault_still_attempts_second_and_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no primary finding, both destroys run and the fault stays loud."""
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        ),
        destroy_script=[RuntimeError("first-key teardown boom"), None],
    )
    with pytest.raises(RuntimeError, match="first-key teardown boom"):
        _run_structured(monkeypatch, raw)
    assert raw.destroyed == [11, 12]
    notes = compliance.get_notes()
    assert any("teardown" in note.description for note in notes)


# --- Production-builder predicates and test-oracle correspondence ---


def test_ps7_witness_builder_matches_spec_predicates() -> None:
    """The production witness is invalid-by-construction with a known suffix."""
    encoded, would_be = tpo._build_v15_ps7_witness(_K)
    assert len(encoded) == _K
    assert encoded[0] == 0x00 and encoded[1] == 0x02
    ps = encoded[2:9]
    assert len(ps) == 7 and all(b != 0 for b in ps)
    assert encoded[9] == 0x00
    assert would_be == encoded[10:]
    assert len(would_be) == _K - 10  # one byte above the k-11 mechanism maximum
    assert int.from_bytes(encoded, "big") < _N
    assert encoded == _WITNESS_ENCODED
    assert would_be == _WITNESS_PAYLOAD


def test_valid_control_builder_matches_spec_predicates() -> None:
    """The production control is a valid block with an exact expected plaintext."""
    encoded, expected = tpo._build_v15_valid_control(_K)
    assert len(encoded) == _K
    assert encoded[0] == 0x00 and encoded[1] == 0x02
    sep = encoded.index(b"\x00", 2)
    ps = encoded[2:sep]
    assert len(ps) >= 8 and all(b != 0 for b in ps)
    assert expected == encoded[sep + 1 :]
    assert len(expected) < _K - 11
    assert int.from_bytes(encoded, "big") < _N
    assert encoded == _CONTROL_ENCODED
    assert expected == _CONTROL_MESSAGE


# --- Pure observation/assessment truth table (supplements the method tests) ---


def test_observe_v15_sample_truth_table() -> None:
    """Witness/overlong/stability semantics of the shared observation model."""
    from pkcs11_check.testcases._rsa_rejection import V15Attempt, observe_v15_sample

    def ok(out: bytes, reported: int | None = None, cap: int = 256) -> V15Attempt:
        return V15Attempt(
            rv=int(CKR_OK),
            phase="output",
            output_rv=int(CKR_OK),
            reported_len=len(out) if reported is None else reported,
            capacity=cap,
            output=out,
        )

    rej = V15Attempt(rv=int(CKR_ENCRYPTED_DATA_INVALID), phase="output")

    payload = b"P" * 246
    witness = observe_v15_sample(
        sample_id="witness",
        category="witness",
        historical=False,
        encoded=b"\x00\x02" + b"\x01" * 7 + b"\x00" + payload,
        ciphertext=b"C" * 256,
        first=ok(payload),
        repeated=ok(payload),
        would_be_plaintext=payload,
        modulus_len=256,
    )
    assert witness.witness is True
    assert witness.witness_attempt == "first"
    assert witness.overlong_attempts == ("first", "repeat")  # 246 > k-11 = 245
    assert witness.stable is True

    separator_less = observe_v15_sample(
        sample_id="cat1-00",
        category="cat1",
        historical=True,
        encoded=b"\x00\x02" + b"\x09" * 254,
        ciphertext=b"D" * 256,
        first=ok(bytes(32)),
        repeated=ok(bytes(32)),
        would_be_plaintext=None,
        modulus_len=256,
    )
    assert separator_less.witness is False
    assert separator_less.overlong_attempts == ()
    assert separator_less.stable is True

    unstable = observe_v15_sample(
        sample_id="cat2-00",
        category="cat2",
        historical=True,
        encoded=None,
        ciphertext=b"E" * 256,
        first=ok(b"A" * 32),
        repeated=ok(b"B" * 32),
        would_be_plaintext=None,
        modulus_len=256,
    )
    assert unstable.witness is False
    assert unstable.stable is False

    unrepeated = observe_v15_sample(
        sample_id="cat1-01",
        category="cat1",
        historical=True,
        encoded=None,
        ciphertext=b"F" * 256,
        first=ok(b"G" * 32),
        repeated=None,
        would_be_plaintext=None,
        modulus_len=256,
    )
    assert unrepeated.stable is None

    over_capacity = observe_v15_sample(
        sample_id="garbage",
        category="garbage",
        historical=True,
        encoded=None,
        ciphertext=bytes(256),
        first=ok(b"H" * 8, reported=300, cap=256),
        repeated=None,
        would_be_plaintext=None,
        modulus_len=256,
    )
    assert over_capacity.witness is False
    assert over_capacity.overlong_attempts == ("first",)

    rejected = observe_v15_sample(
        sample_id="cat1-02",
        category="cat1",
        historical=True,
        encoded=None,
        ciphertext=b"I" * 256,
        first=rej,
        repeated=None,
        would_be_plaintext=None,
        modulus_len=256,
    )
    assert rejected.witness is False
    assert rejected.overlong_attempts == ()
    assert rejected.stable is None

    repeat_only = observe_v15_sample(
        sample_id="witness",
        category="witness",
        historical=False,
        encoded=None,
        ciphertext=b"J" * 256,
        first=rej,
        repeated=ok(payload),
        would_be_plaintext=payload,
        modulus_len=256,
    )
    assert repeat_only.witness is True
    assert repeat_only.witness_attempt == "repeat"
    assert repeat_only.overlong_attempts == ("repeat",)
    assert repeat_only.stable is False


def _attempt_for(rv: int, out: bytes | None = None) -> Any:
    from pkcs11_check.testcases._rsa_rejection import V15Attempt

    if out is None:
        return V15Attempt(rv=int(rv), phase="output")
    return V15Attempt(
        rv=int(CKR_OK),
        phase="output",
        output_rv=int(CKR_OK),
        reported_len=len(out),
        capacity=256,
        output=out,
    )


def _obs_for(
    sample_id: str,
    category: str,
    ciphertext: bytes,
    first: Any,
    *,
    repeated: Any | None = None,
    would_be: bytes | None = None,
    seq: int = 0,
) -> Any:
    from pkcs11_check.testcases._rsa_rejection import observe_v15_sample

    return observe_v15_sample(
        sample_id=sample_id,
        category=category,
        historical=category in ("cat1", "cat2"),
        encoded=None,
        ciphertext=ciphertext,
        first=first,
        repeated=repeated,
        would_be_plaintext=would_be,
        modulus_len=256,
        seq=seq,
    )


def test_assess_oracle_requires_repeated_category_correlation() -> None:
    """Sets differing only transiently (or once) are not a proved oracle."""
    from pkcs11_check.testcases._rsa_rejection import assess_v15_samples

    edi = int(CKR_ENCRYPTED_DATA_INVALID)
    odd = int(CKR_DEVICE_ERROR)

    def run(cat1_rvs: list[int], cat2_rvs: list[int]) -> Any:
        # Unique seqs in supplied order (production shape: cat1 2i, cat2 2i+1),
        # so the seq ranking matches the listed order in every case below.
        obs = [
            _obs_for(f"cat1-{i:02d}", "cat1", bytes([i]) * 256, _attempt_for(rv), seq=2 * i)
            for i, rv in enumerate(cat1_rvs)
        ]
        obs += [
            _obs_for(
                f"cat2-{i:02d}",
                "cat2",
                bytes([100 + i]) * 256,
                _attempt_for(rv),
                seq=2 * i + 1,
            )
            for i, rv in enumerate(cat2_rvs)
        ]
        return assess_v15_samples(obs, None, modulus_len=256)

    # Uniform rejection: no signal at all.
    assert run([edi] * 50, [edi] * 50).oracle.status == "none"
    # Persistent alternating distinction: proved oracle.
    assert run([edi] * 50, [int(CKR_DATA_INVALID)] * 50).oracle.status == "persistent"
    # Startup blip confined to the first sample: transient.
    assert run([odd] + [edi] * 49, [edi] * 50).oracle.status == "transient"
    # Single mid-run flake: unrepeated, transient.
    assert run([edi] * 30 + [odd] + [edi] * 19, [edi] * 50).oracle.status == "transient"
    # Repeated mid-run correlation (twice, same category): persistent.
    mid = [edi] * 50
    mid[10] = mid[20] = odd
    assert run(mid, [edi] * 50).oracle.status == "persistent"


# --- Fix round 1: zero-output / completeness guards (finding 2) ---


def test_zero_buffers_of_differing_lengths_stay_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All-zero outputs alternating 16/32 bytes satisfy variation but prove nothing.

    Each category accepts 50 distinct ciphertexts with two distinct all-zero
    outputs (category variation holds), the witness repeat is stable, and the
    valid control is exact — yet zero output is explicitly non-proving, so the
    collection must stay unresolved instead of synthetic-consistent.
    """

    def _behavior(ct: bytes, qi: int) -> _Behavior:
        if ct == _CONTROL_CT:
            return _output(_CONTROL_MESSAGE)
        if ct == _WITNESS_CT:
            return _output(bytes(32))
        # Prefix queries arrive in collection order: alternate the zero width
        # on the per-category ordinal so EACH category sees both widths.
        width = 16 if (qi // 2) % 2 == 0 else 32
        return _output(bytes(width))

    raw = _V15FakeRaw(_behavior)
    with pytest.raises(pytest.xfail.Exception, match="unresolved"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == ["honest_deviation"]
    record = _records()[0]
    assert record.detail is not None
    assert record.detail["assessment"] == "unresolved"
    assert record.detail["gates"]["nonzero_outputs"] is False


def test_empty_collection_with_correct_control_is_unresolved() -> None:
    """Zero samples plus a correct control is incomplete evidence, not clean."""
    from pkcs11_check.testcases._rsa_rejection import (
        V15Attempt,
        V15ValidControl,
        assess_v15_samples,
    )

    valid = V15ValidControl(
        encoded=b"\x00\x02" + b"\x01" * 8 + b"\x00" + b"M",
        ciphertext=b"C" * 256,
        expected_plaintext=b"M",
        attempt=V15Attempt(
            rv=int(CKR_OK),
            phase="output",
            output_rv=int(CKR_OK),
            reported_len=1,
            capacity=32,
            output=b"M",
        ),
    )
    assert valid.status == "correct"
    assessment = assess_v15_samples((), valid, modulus_len=256)
    assert assessment.oracle.status == "none"
    assert assessment.posture == "unresolved"


def test_incomplete_accepted_output_evidence_stays_unresolved() -> None:
    """An accepted attempt without output bytes fails the completeness gate.

    The collection is otherwise fully synthetic-shaped (distinct per-category
    outputs, stable accepted witness, correct control); the single missing
    output keeps it visibly unresolved.
    """
    from pkcs11_check.testcases._rsa_rejection import (
        V15Attempt,
        V15ValidControl,
        assess_v15_samples,
    )

    def _acc(out: bytes) -> V15Attempt:
        return V15Attempt(
            rv=int(CKR_OK),
            phase="output",
            output_rv=int(CKR_OK),
            reported_len=len(out),
            capacity=256,
            output=out,
        )

    missing = V15Attempt(
        rv=int(CKR_OK),
        phase="output",
        output_rv=int(CKR_OK),
        reported_len=32,
        capacity=256,
        output=None,
    )
    obs = [
        _obs_for("cat1-00", "cat1", b"A" * 256, _acc(b"A1" * 16), seq=0),
        _obs_for("cat1-01", "cat1", b"B" * 256, _acc(b"B1" * 16), seq=1),
        _obs_for("cat1-02", "cat1", b"C" * 256, missing, seq=2),
        _obs_for("cat2-00", "cat2", b"D" * 256, _acc(b"D1" * 16), seq=3),
        _obs_for("cat2-01", "cat2", b"E" * 256, _acc(b"E1" * 16), seq=4),
        _obs_for(
            "witness",
            "witness",
            b"F" * 256,
            _acc(b"W" * 32),
            repeated=_acc(b"W" * 32),
            would_be=b"P" * 246,
            seq=5,
        ),
    ]
    valid = V15ValidControl(
        encoded=b"V",
        ciphertext=b"G" * 256,
        expected_plaintext=b"M",
        attempt=_acc(b"M"),
    )
    assessment = assess_v15_samples(obs, valid, modulus_len=256)
    assert assessment.oracle.status == "none"
    assert assessment.gates["complete_evidence"] is False
    assert assessment.posture == "unresolved"


# --- Fix round 1: serialized operation accounting (finding 3) ---


def test_serialized_semantic_decrypt_count_covers_repeat_and_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Serialized evidence counts 103 semantic decrypts, not 101 + 1.

    The 101 sample observations hold 102 first/repeat attempts (the witness
    observation contains two semantic decrypts) plus the valid control.
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE) if ct == _CONTROL_CT else _output(_synthetic_output(ct))
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="implicit rejection"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    record = _records()[0]
    assert record.detail is not None
    assert record.detail["semantic_decrypts"] == 103
    assert len(record.detail["samples"]) == 101
    assert record.detail["valid_control"] is not None


# --- Fix round 1: order-independent assessment (finding 6) ---


def test_assessment_verdict_is_stable_under_permutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup-window membership follows collection sequence, not input order.

    Two odd rejects sit at the collection start (cat1-00, cat1-01): a startup
    transient in true order. Reversing the production-collected observations
    must not promote it to a persistent oracle, while serialization keeps the
    supplied order.
    """
    from pkcs11_check.testcases._rsa_rejection import assess_v15_samples

    prefix = _prefix_ciphertexts()
    odd_cts = {prefix[0], prefix[2]}  # cat1-00 and cat1-01 in collection order
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _reject("output", CKR_DEVICE_ERROR)
                if ct in odd_cts
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    real_assess = tpo.assess_v15_samples
    captured: dict[str, Any] = {}

    def _spy(observations: Any, valid_control: Any, *, modulus_len: int) -> Any:
        captured["obs"] = list(observations)
        captured["valid"] = valid_control
        return real_assess(observations, valid_control, modulus_len=modulus_len)

    monkeypatch.setattr(tpo, "assess_v15_samples", _spy)
    with pytest.raises(pytest.xfail.Exception, match="unresolved|transient"):
        _run_structured(monkeypatch, raw)
    assert len(captured["obs"]) == 101

    original = assess_v15_samples(captured["obs"], captured["valid"], modulus_len=256)
    permuted = assess_v15_samples(
        list(reversed(captured["obs"])), captured["valid"], modulus_len=256
    )
    assert original.oracle.status == "transient"
    assert permuted.oracle.status == original.oracle.status
    assert permuted.posture == original.posture
    assert permuted.gates == original.gates
    assert [o.sample_id for o in permuted.observations] == [
        o.sample_id for o in reversed(captured["obs"])
    ]


# --- Fix round 1: first-attempt retention before the risky repeat (finding 1) ---


def test_witness_exposure_survives_repeat_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A witnessed first attempt is retained before the risky exact repeat."""
    raw = _V15FakeRaw(
        lambda ct, qi: (
            _raise(RuntimeError("witness repeat boom"))
            if ct == _WITNESS_CT and qi == 101
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT
                else (
                    _output(_CONTROL_MESSAGE)
                    if ct == _CONTROL_CT
                    else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
                )
            )
        )
    )
    with pytest.raises(RuntimeError, match="witness repeat boom"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["accepted_invalid", "wrong_result"]
    assert raw.destroyed == [11, 12]


# --- Fix round 1: overrun phase evidence (finding 4) ---


def test_overrun_record_carries_phase_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """An over-capacity CKR_OK retains its Init/query/output RVs and estimate."""
    bad_ct = _prefix_ciphertexts()[7]
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(b"Z" * 8, reported=300, estimate=8)
            if ct == bad_ct
            else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
        )
    )
    with pytest.raises(Failed, match="malformed|length|capacity"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == ["wrong_result"]
    detail = _records()[0].detail
    assert detail is not None
    assert detail["reported"] == 300
    assert detail["capacity"] == 8
    attempt = detail["attempt_evidence"]
    assert attempt["rv"] == "CKR_OK"
    assert attempt["phase"] == "output"
    assert attempt["init_rv"] == "CKR_OK"
    assert attempt["query_rv"] == "CKR_OK"
    assert attempt["query_estimate"] == 8
    assert attempt["output_rv"] == "CKR_OK"
    assert attempt["reported_len"] == 300
    assert attempt["capacity"] == 8
    assert attempt["output"]["present"] is False


# --- Fix round 1: completed corpus preserved alongside hard findings (finding 5) ---


def test_completed_hard_finding_run_preserves_assessment_corpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed exposure run keeps the 100-sample corpus and valid control.

    The witness records alone cannot replay the assessment; the posture
    carrier preserves every sample, the successful control, and the 103-op
    count independently of the fail terminal.
    """
    raw = _V15FakeRaw(
        lambda ct, _qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT
                else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
            )
        )
    )
    with pytest.raises(Failed, match="bypass"):
        _run_structured(monkeypatch, raw)
    assert [r.reason for r in _records()] == [
        "accepted_invalid",
        "wrong_result",
        "honest_deviation",
    ]
    carrier = _records()[2]
    assert carrier.detail is not None
    assert carrier.detail["assessment"] == "unresolved"
    assert carrier.detail["semantic_decrypts"] == 103
    samples = carrier.detail["samples"]
    assert [s["ciphertext_hex"] for s in samples] == [
        c.hex() for c in _prefix_ciphertexts() + [_WITNESS_CT]
    ]
    assert [s["seq"] for s in samples] == list(range(101))
    control = carrier.detail["valid_control"]
    assert control is not None
    assert control["ciphertext_hex"] == _CONTROL_CT.hex()
    assert control["status"] == "correct"
    assert carrier.detail["oracle"]["status"] == "none"


# --- Fix round 2: ambiguous collection sequences fail closed (item 1) ---


def test_duplicate_collection_sequences_fail_closed() -> None:
    """Tied seqs cannot silently rank by supplied order.

    Round-1 ties fell back to supplied order, so the permutation
    counterexample stayed valid for permitted inputs. Ambiguous collections
    now fail closed identically in both orders instead of returning an
    order-dependent verdict.
    """
    from pkcs11_check.testcases._rsa_rejection import assess_v15_samples

    first = _obs_for("cat1-00", "cat1", b"A" * 256, _attempt_for(int(CKR_DEVICE_ERROR)))
    second = _obs_for("cat2-00", "cat2", b"B" * 256, _attempt_for(int(CKR_ENCRYPTED_DATA_INVALID)))
    assert first.seq == second.seq == 0
    with pytest.raises(ValueError, match="ambiguous.*sequence"):
        assess_v15_samples([first, second], None, modulus_len=256)
    with pytest.raises(ValueError, match="ambiguous.*sequence"):
        assess_v15_samples([second, first], None, modulus_len=256)


# --- Fix round 2: repeat-discovered exposure stays terminal-primary (item 3) ---


def test_repeat_discovered_exposure_stays_terminal_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery order is kept but witnessed exposure wins the terminal.

    The witness first attempt returns unrelated 246-byte output (overlong,
    retained first) while only the repeat exposes the exact known suffix.
    Records stay in discovery order, but the terminal outcome is the
    exposure, not the length finding.
    """
    unrelated = _WITNESS_PAYLOAD[:-1] + bytes([(_WITNESS_PAYLOAD[-1] + 1) % 256])
    assert len(unrelated) == 246
    assert unrelated != _WITNESS_PAYLOAD
    raw = _V15FakeRaw(
        lambda ct, qi: (
            _output(_CONTROL_MESSAGE)
            if ct == _CONTROL_CT
            else (
                _output(_WITNESS_PAYLOAD)
                if ct == _WITNESS_CT and qi == 101
                else (
                    _output(unrelated)
                    if ct == _WITNESS_CT
                    else _reject("output", CKR_ENCRYPTED_DATA_INVALID)
                )
            )
        )
    )
    with pytest.raises(Failed, match="bypass"):
        _run_structured(monkeypatch, raw)
    assert raw.init_count == 103
    assert [r.reason for r in _records()] == [
        "wrong_result",
        "accepted_invalid",
        "honest_deviation",
    ]

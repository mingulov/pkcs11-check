"""Contract tests for generic HashML-DSA and HashSLH-DSA inputs (QF1/#51)."""

from __future__ import annotations

import ctypes
import hashlib
import inspect
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check import classification, compliance
from pkcs11_check import fixtures as p11_fixtures
from pkcs11_check.raw import bootstrap
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.pack_mechanisms import mech_hash_sign_context
from pkcs11_check.raw.recipes import sign_single, verify_single
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_HASH_SIGN_ADDITIONAL_CONTEXT,
    CK_ULONG,
    CKF_SIGN,
    CKF_VERIFY,
    CKH_HEDGE_PREFERRED,
    CKM_HASH_ML_DSA,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_SLH_DSA,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_SHA3_256,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases import mechanism_helpers, test_mech_sign
from pkcs11_check.testcases import test_hash_ml_dsa as ml
from pkcs11_check.testcases import test_hash_pqc_generic_contract as contract
from pkcs11_check.testcases import test_hash_slh_dsa as slh
from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog, MechEntry
from pkcs11_check.testcases.mechanism_helpers import build_test_params
from pkcs11_check.testcases.mechanism_registry import ParamRecipe, get_config
from pkcs11_check.testcases.mechanism_selection import MULTIPART_SIGN_VERIFY_ROUNDTRIP

_ORIGINAL_WRONG_LENGTH_ROWS = (
    ("ML-DSA", "SHA-256", CKM_SHA256),
    ("ML-DSA", "SHA-384", CKM_SHA384),
    ("ML-DSA", "SHA-512", CKM_SHA512),
    ("ML-DSA", "SHA3-256", CKM_SHA3_256),
    ("SLH-DSA", "SHA-256", CKM_SHA256),
)


def _recording_session(*mechanisms: str) -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in mechanisms,
    )


def _param_hash(param: PackedMechanism) -> int:
    assert isinstance(param.params, CK_HASH_SIGN_ADDITIONAL_CONTEXT)
    return int(param.params.hash)


def test_hash_sign_context_recipe_packs_real_parameter() -> None:
    param = build_test_params(
        CKM_HASH_ML_DSA,
        ParamRecipe("hash_sign_context", {"hash_mech": "CKM_SHA256"}),
    )

    assert isinstance(param, PackedMechanism)
    assert int(param.ck.mechanism) == int(CKM_HASH_ML_DSA)
    assert int(param.ck.ulParameterLen) == ctypes.sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)
    assert param.params is not None
    assert int(param.params.hedgeVariant) == int(CKH_HEDGE_PREFERRED)
    assert param.params.pContext is None
    assert int(param.params.ulContextLen) == 0
    assert _param_hash(param) == int(CKM_SHA256)


@pytest.mark.parametrize(
    ("family", "generic", "suffix", "keygen"),
    [
        ("ml", CKM_HASH_ML_DSA, CKM_HASH_ML_DSA_SHA256, CKM_ML_DSA_KEY_PAIR_GEN),
        ("slh", CKM_HASH_SLH_DSA, CKM_HASH_SLH_DSA_SHA256, CKM_SLH_DSA_KEY_PAIR_GEN),
    ],
)
def test_generic_registry_is_prehashed_and_single_part(
    family: str, generic: int, suffix: int, keygen: int
) -> None:
    config = get_config(generic)
    assert config is not None, family
    assert config.input_constraint == "prehash"
    assert config.multi_part_supported is False
    assert config.param_required is True
    assert config.param_recipe.style == "hash_sign_context"
    assert config.param_recipe.defaults == {"hash_mech": "CKM_SHA256"}

    suffix_config = get_config(suffix)
    assert suffix_config is not None
    assert suffix_config.multi_part_supported is True
    assert suffix_config.keygen_mech == keygen

    flags = int(CKF_SIGN) | int(CKF_VERIFY)
    keygen_flags = 0x00000002
    manifest = SimpleNamespace(
        mechanism_info={
            "CKM_HASH_ML_DSA" if family == "ml" else "CKM_HASH_SLH_DSA": {
                "flags": flags,
                "min_key_size": 0,
                "max_key_size": 0,
            },
            "CKM_HASH_ML_DSA_SHA256" if family == "ml" else "CKM_HASH_SLH_DSA_SHA256": {
                "flags": flags,
                "min_key_size": 0,
                "max_key_size": 0,
            },
            "CKM_ML_DSA_KEY_PAIR_GEN" if family == "ml" else "CKM_SLH_DSA_KEY_PAIR_GEN": {
                "flags": keygen_flags,
                "min_key_size": 0,
                "max_key_size": 0,
            },
        }
    )
    catalog = MechanismCatalog.from_manifest(manifest)
    multipart = catalog.filter_for_scenario(MULTIPART_SIGN_VERIFY_ROUNDTRIP)
    assert generic not in {entry.mech_id for entry in multipart}
    assert suffix in {entry.mech_id for entry in multipart}
    assert catalog.get(suffix) is not None
    assert catalog.filter_for_scenario("sign_verify_roundtrip")


@pytest.mark.parametrize(
    ("module", "method", "hash_name", "hash_mech", "message"),
    [
        (ml.TestHashMLDSAGeneric, "test_sign_verify_roundtrip", "SHA-256", CKM_SHA256, ml._MESSAGE),
        (ml.TestHashMLDSAGeneric, "test_sign_verify_roundtrip", "SHA-384", CKM_SHA384, ml._MESSAGE),
        (ml.TestHashMLDSAGeneric, "test_sign_verify_roundtrip", "SHA-512", CKM_SHA512, ml._MESSAGE),
        (
            ml.TestHashMLDSAGeneric,
            "test_sign_verify_roundtrip",
            "SHA3-256",
            CKM_SHA3_256,
            ml._MESSAGE,
        ),
    ],
)
def test_ml_generic_method_passes_exact_digest_and_parameter(
    monkeypatch: pytest.MonkeyPatch,
    module: type[Any],
    method: str,
    hash_name: str,
    hash_mech: int,
    message: bytes,
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(ml, "_generate_ml_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(ml, "destroy_quietly", lambda *_args: None)

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        seen["sign_data"] = args[4]
        seen["sign_param"] = kwargs["mech_param"]
        return b"signature"

    def _verify(*args: Any, **kwargs: Any) -> bool:
        seen["verify_data"] = args[4]
        seen["verify_param"] = kwargs["mech_param"]
        return True

    monkeypatch.setattr(ml, "sign_single", _sign)
    monkeypatch.setattr(ml, "verify_single", _verify)
    rs = _recording_session("HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN")
    _must_complete(lambda: getattr(module(), method)(rs, hash_name, hash_mech))

    expected = {
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
    }[hash_name](message).digest()
    assert seen["sign_data"] == expected
    assert seen["verify_data"] == expected
    assert len(seen["sign_data"]) in {32, 48, 64}
    assert _param_hash(seen["sign_param"]) == int(hash_mech)
    assert seen["verify_param"] is seen["sign_param"]


@pytest.mark.parametrize(
    ("hash_name", "hash_mech"),
    [
        ("SHA-256", CKM_SHA256),
        ("SHA-384", CKM_SHA384),
        ("SHA-512", CKM_SHA512),
        ("SHA3-256", CKM_SHA3_256),
    ],
)
def test_slh_generic_method_passes_exact_digest_and_parameter(
    monkeypatch: pytest.MonkeyPatch, hash_name: str, hash_mech: int
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(slh, "_generate_slh_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(slh, "destroy_quietly", lambda *_args: None)

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        seen["sign_data"] = args[4]
        seen["sign_param"] = kwargs["mech_param"]
        return b"signature"

    def _verify(*args: Any, **kwargs: Any) -> bool:
        seen["verify_data"] = args[4]
        seen["verify_param"] = kwargs["mech_param"]
        return True

    monkeypatch.setattr(slh, "sign_single", _sign)
    monkeypatch.setattr(slh, "verify_single", _verify)
    rs = _recording_session("HASH_SLH_DSA", "SLH_DSA_KEY_PAIR_GEN")
    if hash_name == "SHA-256":
        _must_complete(lambda: slh.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(rs))
    else:
        _must_complete(
            lambda: slh.TestHashSLHDSAGeneric().test_sign_verify_roundtrip_for_hash(
                rs, hash_name, hash_mech
            )
        )

    expected = {
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
    }[hash_name](slh._MESSAGE).digest()
    assert seen["sign_data"] == expected
    assert seen["verify_data"] == expected
    assert _param_hash(seen["sign_param"]) == int(hash_mech)
    assert seen["verify_param"] is seen["sign_param"]


def test_generic_methods_require_only_actual_keygen_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bytes] = []
    monkeypatch.setattr(ml, "_generate_ml_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(ml, "destroy_quietly", lambda *_args: None)

    def _sign(*args: Any, **_kwargs: Any) -> bytes:
        seen.append(args[4])
        return b"sig"

    monkeypatch.setattr(ml, "sign_single", _sign)
    monkeypatch.setattr(ml, "verify_single", lambda *_args, **_kwargs: True)

    rs = _recording_session("HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN")
    _must_complete(
        lambda: ml.TestHashMLDSAGeneric().test_sign_verify_roundtrip(rs, "SHA-256", CKM_SHA256)
    )
    assert seen == [hashlib.sha256(ml._MESSAGE).digest()]


def test_legacy_acceptance_seed_is_not_a_silent_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed malformed Sign must be reported by the real legacy node."""
    fake_raw = SimpleNamespace(enable_rv_trace=lambda: None, rv_trace=[])
    fake_rs = SimpleNamespace(
        raw=fake_raw,
        sh=1,
        has_mechanism=lambda name: name in {"HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN"},
    )
    family = next(item for item in contract._FAMILIES if item.label == "ML-DSA")
    family = replace(family, keygen=lambda _rs: (10, 11))
    monkeypatch.setattr(contract, "_cleanup", lambda *_args: None)
    monkeypatch.setattr(
        contract,
        "run_legacy_null_parameter_sequence",
        lambda *_args: {
            "payload": b"hello pkcs11 sign test" * 2,
            "signature": b"accepted-signature",
            "verify": True,
            "events": [{"phase": "C_Sign", "effect": "completed", "verified": True}],
        },
    )
    with pytest.raises(pytest.fail.Exception, match="accepted NULL parameters"):
        contract.test_legacy_registry_null_parameter_chain(fake_rs, family, "roundtrip-44")


def test_new_raw_only_contract_module_is_present() -> None:
    """Option B owns the stateful probes in one raw-only product module."""
    from pkcs11_check.testcases import test_hash_pqc_generic_contract as contract

    assert {family.label for family in contract._FAMILIES} == {"ML-DSA", "SLH-DSA"}


@pytest.mark.parametrize(
    ("family", "hash_name", "hash_mech"),
    [
        ("ml", "SHA-256", CKM_SHA256),
        ("ml", "SHA-384", CKM_SHA384),
        ("ml", "SHA-512", CKM_SHA512),
        ("ml", "SHA3-256", CKM_SHA3_256),
        ("slh", "SHA-256", CKM_SHA256),
        ("slh", "SHA-384", CKM_SHA384),
        ("slh", "SHA-512", CKM_SHA512),
        ("slh", "SHA3-256", CKM_SHA3_256),
    ],
)
def test_generic_hash_pqc_passes_digest_matching_parameter(
    monkeypatch: pytest.MonkeyPatch, family: str, hash_name: str, hash_mech: int
) -> None:
    """Both production families pass PH(M), not M, with the selected hash."""
    module = ml if family == "ml" else slh
    seen: dict[str, Any] = {}
    if family == "ml":
        monkeypatch.setattr(module, "_generate_ml_dsa_keypair", lambda _rs: (10, 11))
        rs = _recording_session("HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN")
        method = module.TestHashMLDSAGeneric().test_sign_verify_roundtrip
        generic_name = "HASH_ML_DSA"
    else:
        monkeypatch.setattr(module, "_generate_slh_dsa_keypair", lambda _rs: (10, 11))
        rs = _recording_session("HASH_SLH_DSA", "SLH_DSA_KEY_PAIR_GEN")
        generic_name = "HASH_SLH_DSA"

    monkeypatch.setattr(module, "destroy_quietly", lambda *_args: None)

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        seen["sign_data"] = args[4]
        seen["sign_param"] = kwargs["mech_param"]
        return b"signature"

    def _verify(*args: Any, **kwargs: Any) -> bool:
        seen["verify_data"] = args[4]
        seen["verify_param"] = kwargs["mech_param"]
        return True

    monkeypatch.setattr(module, "sign_single", _sign)
    monkeypatch.setattr(module, "verify_single", _verify)
    expected_hash = {
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
    }[hash_name]
    if family == "ml":
        _must_complete(lambda: method(rs, hash_name, hash_mech))
    elif hash_name == "SHA-256":
        _must_complete(lambda: module.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(rs))
    else:
        _must_complete(
            lambda: module.TestHashSLHDSAGeneric().test_sign_verify_roundtrip_for_hash(
                rs, hash_name, hash_mech
            )
        )
    expected = expected_hash(module._MESSAGE).digest()
    assert seen["sign_data"] == expected
    assert seen["verify_data"] == expected
    assert len(expected) == {"SHA-256": 32, "SHA-384": 48, "SHA-512": 64, "SHA3-256": 32}[hash_name]
    assert _param_hash(seen["sign_param"]) == int(hash_mech)
    assert seen["verify_param"] is seen["sign_param"]
    assert generic_name


def test_generic_hash_pqc_registry_has_real_params_and_no_multipart() -> None:
    """The real registry recipes and selector exclude only generic multipart."""
    for family, generic, suffix in (
        ("ml", CKM_HASH_ML_DSA, CKM_HASH_ML_DSA_SHA256),
        ("slh", CKM_HASH_SLH_DSA, CKM_HASH_SLH_DSA_SHA256),
    ):
        config = get_config(generic)
        assert config is not None, family
        packed = build_test_params(generic, config.param_recipe)
        assert isinstance(packed, PackedMechanism)
        assert packed.ck.ulParameterLen == ctypes.sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)
        assert config.param_required is True
        assert config.multi_part_supported is False
        suffix_config = get_config(suffix)
        assert suffix_config is not None and suffix_config.multi_part_supported is True


def test_hash_pqc_does_not_require_unrelated_pure_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual positive methods reach Sign with only generic + keygen advertised."""
    seen: list[bytes] = []
    monkeypatch.setattr(ml, "_generate_ml_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(slh, "_generate_slh_dsa_keypair", lambda _rs: (10, 11))
    monkeypatch.setattr(ml, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(slh, "destroy_quietly", lambda *_args: None)

    def _sign(*args: Any, **_kwargs: Any) -> bytes:
        seen.append(args[4])
        return b"sig"

    monkeypatch.setattr(ml, "sign_single", _sign)
    monkeypatch.setattr(slh, "sign_single", _sign)
    monkeypatch.setattr(ml, "verify_single", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(slh, "verify_single", lambda *_args, **_kwargs: True)
    _must_complete(
        lambda: ml.TestHashMLDSAGeneric().test_sign_verify_roundtrip(
            _recording_session("HASH_ML_DSA", "ML_DSA_KEY_PAIR_GEN"), "SHA-256", CKM_SHA256
        )
    )
    _must_complete(
        lambda: slh.TestHashSLHDSAGeneric().test_sign_verify_roundtrip(
            _recording_session("HASH_SLH_DSA", "SLH_DSA_KEY_PAIR_GEN")
        )
    )
    assert seen == [hashlib.sha256(ml._MESSAGE).digest(), hashlib.sha256(slh._MESSAGE).digest()]


class _RegistryContractFake:
    """Stateful fake used through the real generic registry roundtrip method."""

    def __init__(self) -> None:
        self.active = False
        self.calls: list[tuple[bytes, PackedMechanism | None]] = []

    def sign(self, data: bytes, param: PackedMechanism | None) -> bytes:
        self.calls.append((data, param))
        if param is None:
            raise CkrAssertionError("NULL parameter", int(CKR_MECHANISM_INVALID))
        if len(data) != 32:
            raise CkrAssertionError("wrong prehash length", int(CKR_FUNCTION_NOT_SUPPORTED))
        self.active = True
        return b"signature"

    def verify(self, data: bytes, signature: bytes, param: PackedMechanism | None) -> bool:
        assert self.active
        assert signature == b"signature"
        assert param is not None
        assert len(data) == 32
        self.active = False
        return True


@pytest.mark.parametrize("mech", [CKM_HASH_ML_DSA, CKM_HASH_SLH_DSA])
def test_actual_registry_roundtrip_rejects_null_and_wrong_length(
    monkeypatch: pytest.MonkeyPatch, mech: int
) -> None:
    """Invoke production TestMechSignRoundtrip with a stateful parameter fake."""
    fake = _RegistryContractFake()
    rs: Any = SimpleNamespace(raw=object(), sh=1)
    entry = MechEntry(
        mech_id=int(mech),
        mech_name="CKM_HASH_ML_DSA" if mech == CKM_HASH_ML_DSA else "CKM_HASH_SLH_DSA",
        flags=int(CKF_SIGN) | int(CKF_VERIFY),
        min_key_size=0,
        max_key_size=0,
        config=get_config(mech),
    )
    assert entry.config is not None
    monkeypatch.setattr(test_mech_sign, "generate_key_for_sign", lambda *_args: (10, None))
    monkeypatch.setattr(test_mech_sign, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_mech_sign,
        "sign_single",
        lambda _raw, _sh, _key, _mech, data, *, mech_param=None: fake.sign(data, mech_param),
    )
    monkeypatch.setattr(
        test_mech_sign,
        "verify_single",
        lambda _raw, _sh, _key, _mech, data, signature, *, mech_param=None: fake.verify(
            data, signature, mech_param
        ),
    )
    _must_complete(lambda: test_mech_sign.TestMechSignRoundtrip().test_roundtrip(rs, entry))
    assert len(fake.calls) == 1
    assert len(fake.calls[0][0]) == 32
    assert fake.calls[0][1] is not None
    with pytest.raises(CkrAssertionError):
        fake.sign(b"x" * 32, None)
    with pytest.raises(CkrAssertionError):
        fake.sign(b"x", fake.calls[0][1])


def test_option_b_raw_contract_metadata_and_probe_shapes() -> None:
    path = Path(contract.__file__ or "")
    source = path.read_text(encoding="utf-8")
    assert "p11_raw_session" in source
    assert "p11_module_session" not in source
    expected = {
        "test_legacy_registry_null_parameter_chain",
        "test_generic_valid_parameter_rejects_multipart",
        "test_wrong_length_sign_rejects_original_message",
        "test_changed_input_verify_does_not_verify",
        "test_generic_and_hash_suffix_cross_verify",
    }
    for name in expected:
        member = getattr(contract, name)
        assert "p11_raw_session" in inspect.signature(member).parameters
    assert set(contract._CHAINS) == {
        "roundtrip-44",
        "tamper-25",
        "multipart-136",
        "streaming-96",
    }
    actual_rows = [
        (family.label, hash_name, hash_mech)
        for family, hash_name, hash_mech in contract._WRONG_LENGTH_CASES
    ]
    assert len(actual_rows) == 5
    assert set(actual_rows) == set(_ORIGINAL_WRONG_LENGTH_ROWS)


def test_raw_fixture_generator_owns_distinct_open_and_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The option-B contract relies on fixture lifecycle, not source text alone."""
    opened: list[int] = []
    logged_out: list[int] = []
    closed: list[int] = []
    consumed: list[bool] = []

    def _open(_module: Any, _config: Any) -> tuple[Any, int, int, bool]:
        handle = 100 + len(opened)
        opened.append(handle)
        raw = SimpleNamespace(
            call_log={},
            reset_call_log=lambda: None,
            reset_used_mechanisms=lambda: None,
        )
        return raw, handle, 1, True

    monkeypatch.setattr(p11_fixtures, "_open_or_reinit", _open)
    monkeypatch.setattr(bootstrap, "logout_quietly", lambda _raw, sh: logged_out.append(sh))
    monkeypatch.setattr(bootstrap, "close_session_quietly", lambda _raw, sh: closed.append(sh))

    def _consume() -> bool:
        consumed.append(True)
        return False

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.consume_session_reopen_request",
        _consume,
    )
    fixture = p11_fixtures.p11_raw_session._fixture_function
    handles: list[int] = []
    for _ in range(2):
        generator = fixture(object(), SimpleNamespace(rv_trace=False))
        session = next(generator)
        handles.append(session.sh)
        with pytest.raises(StopIteration):
            next(generator)
    assert handles == [100, 101]
    assert opened == handles
    assert logged_out == handles
    assert closed == handles
    assert len(consumed) == 2


class _StatefulProbeFake:
    """In-memory raw seam that preserves operation state and exact phase/RV."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.rv_trace: list[dict[str, Any]] = []
        self.destroyed: list[int] = []
        self.signed = False

    def enable_rv_trace(self) -> None:
        self.rv_trace.clear()

    def _raise(self, fn: str, rv: int) -> None:
        self.rv_trace.append({"fn": fn, "rv": rv, "rv_name": str(rv)})
        raise CkrAssertionError(f"{fn}: {rv}", rv)

    def sign_single(self, data: bytes, param: PackedMechanism | None) -> bytes:
        if self.mode == "raw_exception":
            raise ValueError("raw fake failure")
        if self.mode == "null_reject" and param is None:
            self._raise("C_SignInit", int(CKR_MECHANISM_PARAM_INVALID))
        if self.mode == "wrong_length_reject":
            self._raise("C_Sign", int(CKR_DATA_LEN_RANGE))
        if self.mode in {"changed_verify_true", "wrong_length_accept"}:
            self.rv_trace.extend(
                {"fn": fn, "rv": int(CKR_OK), "rv_name": "CKR_OK"}
                for fn in ("C_SignInit", "C_Sign", "C_Sign")
            )
        self.signed = True
        return b"signature"

    def sign_multipart(self, chunks: list[bytes], param: PackedMechanism | None) -> bytes:
        if self.mode == "streaming_late_refusal":
            self._raise("C_SignFinal", int(CKR_FUNCTION_NOT_SUPPORTED))
        if self.mode == "multipart_init_refusal":
            self._raise("C_SignInit", int(CKR_MECHANISM_INVALID))
        if self.mode == "multipart_update_refusal":
            self._raise("C_SignUpdate", int(CKR_FUNCTION_NOT_SUPPORTED))
        if self.mode == "multipart_vendor_refusal":
            self._raise("C_SignUpdate", 0x80000001)
        if self.mode == "multipart_undefined_refusal":
            self._raise("C_SignUpdate", 0x1234)
        self.signed = True
        return b"signature"

    def verify_single(self, data: bytes, signature: bytes, param: PackedMechanism | None) -> bool:
        if self.mode == "wrong_length_accept":
            self.rv_trace.extend(
                [
                    {"fn": "C_VerifyInit", "rv": int(CKR_OK), "rv_name": "CKR_OK"},
                    {
                        "fn": "C_Verify",
                        "rv": int(CKR_SIGNATURE_INVALID),
                        "rv_name": "CKR_SIGNATURE_INVALID",
                    },
                ]
            )
            return False
        if self.mode == "changed_verify_true":
            self.rv_trace.extend(
                {"fn": fn, "rv": int(CKR_OK), "rv_name": "CKR_OK"}
                for fn in ("C_VerifyInit", "C_Verify")
            )
            return True
        return False if data else True

    def verify_multipart(
        self, chunks: list[bytes], signature: bytes, param: PackedMechanism | None
    ) -> bool:
        return True

    def destroy(self, handle: int) -> None:
        self.destroyed.append(handle)


def _stateful_session(fake: Any) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=1,
        has_mechanism=lambda _name: True,
    )


def _patch_stateful_contract(
    monkeypatch: pytest.MonkeyPatch, fake: _StatefulProbeFake
) -> contract._Family:
    family = next(item for item in contract._FAMILIES if item.label == "ML-DSA")
    monkeypatch.setattr(
        contract,
        "sign_single",
        lambda _r, _s, _k, _m, data, *, mech_param=None: fake.sign_single(data, mech_param),
    )
    monkeypatch.setattr(
        contract,
        "verify_single",
        lambda _r, _s, _k, _m, data, sig, *, mech_param=None: fake.verify_single(
            data, sig, mech_param
        ),
    )
    monkeypatch.setattr(
        contract,
        "sign_multipart",
        lambda _r, _s, _k, _m, chunks, *, mech_param=None: fake.sign_multipart(chunks, mech_param),
    )
    monkeypatch.setattr(contract, "destroy_quietly", lambda _r, _s, handle: fake.destroy(handle))
    monkeypatch.setattr(
        mechanism_helpers,
        "sign_single",
        lambda _r, _s, _k, _m, data, *, mech_param=None: fake.sign_single(data, mech_param),
    )
    monkeypatch.setattr(
        mechanism_helpers,
        "verify_single",
        lambda _r, _s, _k, _m, data, sig, *, mech_param=None: fake.verify_single(
            data, sig, mech_param
        ),
    )
    monkeypatch.setattr(
        mechanism_helpers,
        "sign_multipart",
        lambda _r, _s, _k, _m, chunks, *, mech_param=None: fake.sign_multipart(chunks, mech_param),
    )
    monkeypatch.setattr(
        mechanism_helpers,
        "verify_multipart",
        lambda _r, _s, _k, _m, chunks, sig, *, mech_param=None: fake.verify_multipart(
            chunks, sig, mech_param
        ),
    )
    return family


def test_stateful_legacy_null_rejection_acceptance_and_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = next(item for item in contract._FAMILIES if item.label == "ML-DSA")
    for mode, expected_reason in (
        ("null_reject", None),
        ("null_accept", "accepted_invalid"),
        ("streaming_late_refusal", "accepted_invalid"),
    ):
        fake = _StatefulProbeFake(mode)
        _patch_stateful_contract(monkeypatch, fake)
        actual_family = replace(family, keygen=lambda _rs: (10, 11))
        rs = _stateful_session(fake)
        classification.clear()
        if mode == "streaming_late_refusal":
            chain = "streaming-96"
        else:
            chain = "roundtrip-44"
        if expected_reason is None:
            _must_complete(
                lambda: contract.test_legacy_registry_null_parameter_chain(rs, actual_family, chain)
            )
        else:
            with pytest.raises(pytest.fail.Exception):
                contract.test_legacy_registry_null_parameter_chain(rs, actual_family, chain)
            records = classification.get_records()
            assert records and records[-1].reason == expected_reason
        assert fake.destroyed == [10, 11]


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_length_accept",
        "changed_verify_true",
        "multipart_success",
        "multipart_init_refusal",
        "multipart_update_refusal",
        "multipart_vendor_refusal",
        "multipart_undefined_refusal",
    ],
)
def test_stateful_seed_controls_make_actual_nodes_loud(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    fake = _StatefulProbeFake(mode)
    family = _patch_stateful_contract(monkeypatch, fake)
    family = replace(family, keygen=lambda _rs: (10, 11))
    rs = _stateful_session(fake)
    classification.clear()
    if mode == "wrong_length_accept":

        def call() -> None:
            contract.test_wrong_length_sign_rejects_original_message(
                rs, family, "SHA-256", CKM_SHA256
            )
    elif mode == "changed_verify_true":

        def call() -> None:
            contract.test_changed_input_verify_does_not_verify(rs, family)
    else:

        def call() -> None:
            contract.test_generic_valid_parameter_rejects_multipart(rs, family)

    if mode == "multipart_update_refusal":
        _must_complete(call)
        assert not classification.get_records()
    elif mode == "multipart_init_refusal" or mode == "multipart_vendor_refusal":
        with pytest.raises(pytest.xfail.Exception):
            call()
        assert classification.get_records()
    elif mode == "multipart_undefined_refusal":
        with pytest.raises(pytest.fail.Exception):
            call()
        assert classification.get_records()[-1].reason == "self_contradiction"
    else:
        with pytest.raises(pytest.fail.Exception):
            call()
        assert classification.get_records()
        if mode == "wrong_length_accept":
            rec = classification.get_records()[0]
            assert rec.reason == "accepted_invalid" and rec.kind is None
            assert rec.operation == "C_Sign"
            assert rec.expected_ckr == ["CKR_DATA_LEN_RANGE"]
            assert rec.actual_ckr == "CKR_OK"
            assert [entry["fn"] for entry in fake.rv_trace] == [
                "C_SignInit",
                "C_Sign",
                "C_Sign",
                "C_VerifyInit",
                "C_Verify",
            ]
        if mode == "changed_verify_true":
            assert classification.get_records()[-1].reason == "wrong_result"
    assert fake.destroyed == [10, 11]


@pytest.mark.parametrize(
    ("family_label", "hash_name", "hash_mech"),
    _ORIGINAL_WRONG_LENGTH_ROWS,
)
def test_stateful_wrong_length_controls_cover_all_original_rows(
    family_label: str,
    hash_name: str,
    hash_mech: int,
) -> None:
    """Every preserved ML/SLH wrong-length row reaches the real production node."""
    fake = _RawPqcFake()
    family = next(item for item in contract._FAMILIES if item.label == family_label)
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_wrong_length_sign_rejects_original_message(
            _stateful_session(fake), _raw_family(family), hash_name, hash_mech
        )
    )
    assert not classification.get_records()
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_Sign",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert fake.calls[1]["rv"] == int(CKR_DATA_LEN_RANGE)
    assert len(compliance.get_notes()) == 1


def test_stateful_raw_exception_is_not_relabelled(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _StatefulProbeFake("raw_exception")
    family = _patch_stateful_contract(monkeypatch, fake)
    family = replace(family, keygen=lambda _rs: (10, 11))
    with pytest.raises(ValueError, match="raw fake failure"):
        contract.test_wrong_length_sign_rejects_original_message(
            _stateful_session(fake), family, "SHA-256", CKM_SHA256
        )
    assert fake.destroyed == [10, 11]


class _RawPqcFake:
    """Stateful PKCS#11 call seam for the unchanged raw sign/verify recipes."""

    def __init__(
        self,
        *,
        null_parameters: str = "reject",
        refuse: tuple[str, int, int] | None = None,
        destroy_rv: int = int(CKR_OK),
        malformed_sign: bool = False,
        accept_wrong_length: bool = False,
        verify_exception: bool = False,
    ) -> None:
        self.null_parameters = null_parameters
        self.refuse = refuse  # function, ordinal invocation, exact CK_RV
        self.destroy_rv = destroy_rv
        self.malformed_sign = malformed_sign
        self.accept_wrong_length = accept_wrong_length
        self.verify_exception = verify_exception
        self.rv_trace: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self._counts: dict[str, int] = {}
        self._active: tuple[str, int, int | None] | None = None
        self._data = b""
        self._signature = b""

    def enable_rv_trace(self) -> None:
        self.rv_trace.clear()

    def _event(self, fn: str, rv: int, **extra: Any) -> int:
        ordinal = self._counts.get(fn, 0) + 1
        self._counts[fn] = ordinal
        event = {"fn": fn, "rv": rv, "rv_name": ckr_name(rv), "ordinal": ordinal, **extra}
        self.calls.append(event)
        self.rv_trace.append(event)
        return rv

    def _refusal(self, fn: str) -> int | None:
        ordinal = self._counts.get(fn, 0) + 1
        if self.refuse is not None and self.refuse[:2] == (fn, ordinal):
            return self.refuse[2]
        return None

    @staticmethod
    def _bytes(ptr: Any, length: int) -> bytes:
        return ctypes.string_at(ptr, length) if length else b""

    @staticmethod
    def _mechanism(ptr: Any) -> tuple[int, int, int | None]:
        ck = ptr._obj
        mechanism = int(ck.mechanism)
        length = int(ck.ulParameterLen)
        if not length:
            return mechanism, length, None
        param = ctypes.cast(ck.pParameter, ctypes.POINTER(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
        return mechanism, length, int(param.contents.hash)

    @staticmethod
    def _semantic(mechanism: int, payload: bytes) -> bytes:
        if mechanism in {int(CKM_HASH_ML_DSA), int(CKM_HASH_SLH_DSA)}:
            return payload
        return hashlib.sha256(payload).digest()

    def C_SignInit(self, _sh: int, mech: Any, _key: int) -> int:  # noqa: N802
        mechanism, parameter_len, hash_mech = self._mechanism(mech)
        rv = self._refusal("C_SignInit")
        if rv is None and parameter_len == 0 and self.null_parameters == "reject":
            rv = int(CKR_MECHANISM_PARAM_INVALID)
        if rv is None:
            rv = int(CKR_OK)
        if rv == int(CKR_OK):
            self._active = ("sign", mechanism, hash_mech)
            self._data = b""
        return self._event(
            "C_SignInit",
            rv,
            mechanism=mechanism,
            parameter_len=parameter_len,
            parameter_address=mech._obj.pParameter,
            parameter_bytes=self._bytes(mech._obj.pParameter, parameter_len),
            hash=hash_mech,
            key=_key,
        )

    def C_Sign(self, _sh: int, data: Any, data_len: int, out: Any, out_len: Any) -> int:  # noqa: N802
        assert self._active is not None and self._active[0] == "sign"
        payload = self._bytes(data, data_len)
        mechanism, hash_mech = self._active[1:]
        rv = self._refusal("C_Sign")
        if rv is None and hash_mech is not None and data_len != 32 and not self.accept_wrong_length:
            rv = int(CKR_DATA_LEN_RANGE)
        if rv is None:
            rv = int(CKR_OK)
        if rv == int(CKR_OK):
            prefix = b"G" if mechanism in {int(CKM_HASH_ML_DSA), int(CKM_HASH_SLH_DSA)} else b"S"
            signature = b"G" if self.malformed_sign else prefix + self._semantic(mechanism, payload)
            ctypes.cast(out_len, ctypes.POINTER(CK_ULONG)).contents.value = len(signature)
            if out is not None:
                ctypes.memmove(out, signature, len(signature))
                self._active = None
        return self._event("C_Sign", rv, data=payload, output_query=out is None)

    def C_VerifyInit(self, _sh: int, mech: Any, _key: int) -> int:  # noqa: N802
        mechanism, parameter_len, hash_mech = self._mechanism(mech)
        rv = self._refusal("C_VerifyInit")
        if rv is None and parameter_len == 0 and self.null_parameters == "reject":
            rv = int(CKR_MECHANISM_PARAM_INVALID)
        if rv is None:
            rv = int(CKR_OK)
        if rv == int(CKR_OK):
            self._active = ("verify", mechanism, hash_mech)
            self._data = b""
        return self._event(
            "C_VerifyInit",
            rv,
            mechanism=mechanism,
            parameter_len=parameter_len,
            parameter_address=mech._obj.pParameter,
            parameter_bytes=self._bytes(mech._obj.pParameter, parameter_len),
            hash=hash_mech,
            key=_key,
        )

    def C_Verify(  # noqa: N802
        self, _sh: int, data: Any, data_len: int, signature: Any, signature_len: int
    ) -> int:
        assert self._active is not None and self._active[0] == "verify"
        payload = self._bytes(data, data_len)
        signed = self._bytes(signature, signature_len)
        if self.verify_exception:
            self.calls.append({"fn": "C_Verify", "rv": None, "data": payload, "signature": signed})
            raise ValueError("raw fake Verify failure")
        rv = self._refusal("C_Verify")
        if rv is None:
            if self.malformed_sign and len(signed) == 1:
                rv = int(CKR_SIGNATURE_LEN_RANGE)
            else:
                rv = (
                    int(CKR_OK)
                    if signed[:1] in {b"G", b"S"}
                    and signed[1:] == self._semantic(self._active[1], payload)
                    else int(CKR_SIGNATURE_INVALID)
                )
        self._active = None
        return self._event("C_Verify", rv, data=payload, signature=signed)

    def C_SignUpdate(self, _sh: int, data: Any, data_len: int) -> int:  # noqa: N802
        assert self._active is not None and self._active[0] == "sign"
        payload = self._bytes(data, data_len)
        rv = self._refusal("C_SignUpdate") or int(CKR_OK)
        if rv == int(CKR_OK):
            self._data += payload
        return self._event("C_SignUpdate", rv, data=payload)

    def C_SignFinal(self, _sh: int, out: Any, out_len: Any) -> int:  # noqa: N802
        assert self._active is not None and self._active[0] == "sign"
        rv = self._refusal("C_SignFinal") or int(CKR_OK)
        if rv == int(CKR_OK):
            signature = b"G" + self._semantic(self._active[1], self._data)
            ctypes.cast(out_len, ctypes.POINTER(CK_ULONG)).contents.value = len(signature)
            if out is not None:
                ctypes.memmove(out, signature, len(signature))
                self._active = None
        return self._event("C_SignFinal", rv, output_query=out is None)

    def C_VerifyUpdate(self, _sh: int, data: Any, data_len: int) -> int:  # noqa: N802
        assert self._active is not None and self._active[0] == "verify"
        payload = self._bytes(data, data_len)
        self._data += payload
        return self._event("C_VerifyUpdate", int(CKR_OK), data=payload)

    def C_VerifyFinal(self, _sh: int, signature: Any, signature_len: int) -> int:  # noqa: N802
        assert self._active is not None and self._active[0] == "verify"
        signed = self._bytes(signature, signature_len)
        rv = (
            int(CKR_OK)
            if signed == b"G" + self._semantic(self._active[1], self._data)
            else int(CKR_SIGNATURE_INVALID)
        )
        self._active = None
        return self._event("C_VerifyFinal", rv, signature=signed)

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        return self._event("C_DestroyObject", self.destroy_rv, handle=handle)


def _must_complete(call: Any) -> None:
    """Turn an unexpected production skip or xfail into a failed meta control."""
    try:
        call()
    except (pytest.skip.Exception, pytest.xfail.Exception) as exc:
        pytest.fail(f"healthy production call did not complete: {exc}")


@pytest.mark.parametrize("outcome", [pytest.skip, pytest.xfail], ids=["skip", "xfail"])
def test_healthy_method_control_fails_on_unexpected_noncompletion(outcome: Any) -> None:
    with pytest.raises(pytest.fail.Exception, match="healthy production call did not complete"):
        _must_complete(lambda: outcome("injected noncompletion"))


def _raw_family(family: contract._Family) -> contract._Family:
    return replace(family, keygen=lambda _rs: (10, 11))


@pytest.mark.parametrize(("family_label", "hash_name", "hash_mech"), _ORIGINAL_WRONG_LENGTH_ROWS)
@pytest.mark.parametrize(
    "outcome",
    [
        "verify_true",
        "verify_false",
        "verify_length_false",
        "init_refusal",
        "verify_refusal",
        "raw_exception",
    ],
)
def test_wrong_length_accepted_sign_preserves_conditional_raw_verify_and_primary_failure(
    family_label: str, hash_name: str, hash_mech: int, outcome: str
) -> None:
    """Dropping the original conditional Verify must fail every retained raw/hash row."""
    family = next(item for item in contract._FAMILIES if item.label == family_label)
    expected_message, expected_mechanism, expected_length = {
        "ML-DSA": (
            b"HashML-DSA pre-hash signature test message 2026",
            CKM_HASH_ML_DSA,
            47,
        ),
        "SLH-DSA": (
            b"HashSLH-DSA pre-hash signature test message 2026",
            CKM_HASH_SLH_DSA,
            48,
        ),
    }[family_label]
    refusal = {
        "verify_false": ("C_Verify", 1, int(CKR_SIGNATURE_INVALID)),
        "verify_length_false": ("C_Verify", 1, int(CKR_SIGNATURE_LEN_RANGE)),
        "init_refusal": ("C_VerifyInit", 1, int(CKR_FUNCTION_NOT_SUPPORTED)),
        "verify_refusal": ("C_Verify", 1, int(CKR_FUNCTION_NOT_SUPPORTED)),
    }.get(outcome)
    fake = _RawPqcFake(
        accept_wrong_length=True,
        refuse=refusal,
        verify_exception=outcome == "raw_exception",
    )
    classification.clear()
    compliance.clear_notes()
    with pytest.raises(pytest.fail.Exception) as failure:
        _must_complete(
            lambda: contract.test_wrong_length_sign_rejects_original_message(
                _stateful_session(fake), _raw_family(family), hash_name, hash_mech
            )
        )
    records = classification.get_records()
    assert len(records) == 1
    rec = records[0]
    assert getattr(failure.value, "_pkcs11_check_classification", None) is rec
    assert rec.reason == "accepted_invalid" and rec.outcome == "fail" and rec.kind is None
    assert rec.operation == "C_Sign" and rec.mechanism == f"CKM_{family.generic_name}"
    assert rec.expected_ckr == ["CKR_DATA_LEN_RANGE"] and rec.actual_ckr == "CKR_OK"
    expected_phases = ["C_SignInit", "C_Sign", "C_Sign", "C_VerifyInit"]
    if outcome != "init_refusal":
        expected_phases.append("C_Verify")
    assert [event["fn"] for event in fake.calls] == [
        *expected_phases,
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    expected_last_rv = {
        "verify_true": int(CKR_OK),
        "verify_false": int(CKR_SIGNATURE_INVALID),
        "verify_length_false": int(CKR_SIGNATURE_LEN_RANGE),
        "init_refusal": int(CKR_FUNCTION_NOT_SUPPORTED),
        "verify_refusal": int(CKR_FUNCTION_NOT_SUPPORTED),
        "raw_exception": None,
    }[outcome]
    assert [event["rv"] for event in fake.calls] == [
        *([int(CKR_OK)] * (len(expected_phases) - 1)),
        expected_last_rv,
        int(CKR_OK),
        int(CKR_OK),
    ]
    sign_calls = [event for event in fake.calls if event["fn"] == "C_Sign"]
    assert [event["data"] for event in sign_calls] == [expected_message, expected_message]
    assert [len(event["data"]) for event in sign_calls] == [expected_length, expected_length]
    assert [event["output_query"] for event in sign_calls] == [True, False]
    init_calls = [event for event in fake.calls if event["fn"] in {"C_SignInit", "C_VerifyInit"}]
    assert [event["mechanism"] for event in init_calls] == [expected_mechanism] * 2
    assert [event["hash"] for event in init_calls] == [hash_mech] * 2
    assert [event["key"] for event in init_calls] == [11, 10]
    assert [event["parameter_len"] for event in init_calls] == [
        ctypes.sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)
    ] * 2
    assert init_calls[0]["parameter_address"] == init_calls[1]["parameter_address"]
    assert init_calls[0]["parameter_address"] is not None
    assert init_calls[0]["parameter_bytes"] == init_calls[1]["parameter_bytes"]
    param = CK_HASH_SIGN_ADDITIONAL_CONTEXT.from_buffer_copy(init_calls[0]["parameter_bytes"])
    assert int(param.hash) == hash_mech and int(param.hedgeVariant) == int(CKH_HEDGE_PREFERRED)
    assert param.pContext is None and int(param.ulContextLen) == 0
    expected_signature = b"G" + expected_message
    verify_calls = [event for event in fake.calls if event["fn"] == "C_Verify"]
    if outcome == "init_refusal":
        assert not verify_calls
    else:
        assert len(verify_calls) == 1
        assert verify_calls[0]["data"] == expected_message
        assert len(verify_calls[0]["data"]) == expected_length
        assert verify_calls[0]["signature"] == expected_signature
    assert rec.detail is not None
    assert rec.detail["payload_hex"] == expected_message.hex()
    assert rec.detail["payload_len"] == expected_length
    assert rec.detail["verify_payload_hex"] == expected_message.hex()
    assert rec.detail["verify_payload_len"] == expected_length
    assert rec.detail["signature_len"] == len(expected_signature)
    observation = rec.detail["conditional_verify"]
    expected_status, expected_phase, expected_verified, expected_effect, expected_target = {
        "verify_true": ("returned", "C_Verify", True, "verification_accepted", True),
        "verify_false": ("returned", "C_Verify", False, "verification_rejected", True),
        "verify_length_false": ("returned", "C_Verify", False, "verification_rejected", True),
        "init_refusal": ("refused", "C_VerifyInit", "unreached", "refused_before_verify", False),
        "verify_refusal": ("refused", "C_Verify", "not_returned", "refused", True),
        "raw_exception": ("raw_exception", None, "not_returned", "unknown", "unconfirmed"),
    }[outcome]
    assert observation["status"] == expected_status
    assert observation["phase"] == expected_phase
    assert observation["verified"] == expected_verified
    assert observation["effect"] == expected_effect
    assert observation["target_reached"] == expected_target
    assert observation["rv"] == expected_last_rv
    assert observation["rv_name"] == (
        None if expected_last_rv is None else ckr_name(expected_last_rv)
    )
    if outcome == "raw_exception":
        assert observation["exception_type"] == "ValueError"
        assert observation["exception_message"] == "raw fake Verify failure"
        assert rec.detail["unreached_phases"] == "indeterminate after raw exception"
        assert rec.detail["unobserved_phases"] == ["C_Verify"]
    else:
        assert rec.detail["unreached_phases"] == (["C_Verify"] if outcome == "init_refusal" else [])
    expected_returned = expected_phases[:-1] if outcome == "raw_exception" else expected_phases
    assert [event["phase"] for event in rec.detail["reached_phases"]] == expected_returned
    assert [event["rv"] for event in rec.detail["reached_phases"]] == (
        [int(CKR_OK)] * len(expected_returned)
        if outcome == "raw_exception"
        else [*([int(CKR_OK)] * (len(expected_phases) - 1)), expected_last_rv]
    )
    assert [event["handle"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [10, 11]
    assert rec.detail["cleanup"] == {
        "public": "best_effort_call_returned_unconfirmed",
        "private": "best_effort_call_returned_unconfirmed",
    }
    assert not compliance.get_notes()


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_real_recipe_bidirectional_cross_verification(
    family: contract._Family,
) -> None:
    """Each production direction uses PH(M)/M, one key, and a real raw recipe."""
    fake = _RawPqcFake(null_parameters="accept")
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_generic_and_hash_suffix_cross_verify(
            _stateful_session(fake), _raw_family(family)
        )
    )
    assert not classification.get_records()
    phases = [event["fn"] for event in fake.calls]
    assert phases == [
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert [event["rv"] for event in fake.calls] == [int(CKR_OK)] * len(phases)
    assert [event["data"] for event in fake.calls if event["fn"] == "C_Sign"] == [
        hashlib.sha256(family.message).digest(),
        hashlib.sha256(family.message).digest(),
        family.message,
        family.message,
    ]
    assert [event["data"] for event in fake.calls if event["fn"] == "C_Verify"] == [
        family.message,
        hashlib.sha256(family.message).digest(),
    ]
    cross_signatures = [event["signature"] for event in fake.calls if event["fn"] == "C_Verify"]
    assert cross_signatures[0][:1] == b"G" and cross_signatures[1][:1] == b"S"
    assert cross_signatures[0] != cross_signatures[1]
    init = [event for event in fake.calls if event["fn"].endswith("Init")]
    assert [(event["mechanism"], event["hash"]) for event in init] == [
        (int(family.generic_mech), int(CKM_SHA256)),
        (int(family.suffix_mech), None),
        (int(family.suffix_mech), None),
        (int(family.generic_mech), int(CKM_SHA256)),
    ]
    assert [event["handle"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [10, 11]
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert "generic_to_suffix" in notes[0].description
    assert "suffix_to_generic" in notes[0].description
    assert "unconfirmed" in notes[0].description


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_same_width_different_digest_remains_legal_caller_input(
    family: contract._Family,
) -> None:
    """The selected SHA-256 width, not equality to PH(M), is the provider input rule."""
    fake = _RawPqcFake(null_parameters="accept")
    alternate = hashlib.sha256(family.message + b" alternative").digest()
    original = hashlib.sha256(family.message).digest()
    param = mech_hash_sign_context(family.generic_mech, hash_mech=CKM_SHA256)
    raw = cast(RawPKCS11, fake)
    signature = sign_single(raw, 1, 11, family.generic_mech, alternate, mech_param=param)
    assert verify_single(raw, 1, 10, family.generic_mech, alternate, signature, mech_param=param)
    assert not verify_single(raw, 1, 10, family.generic_mech, original, signature, mech_param=param)
    assert len(alternate) == len(original) == 32 and alternate != original
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_Sign"] == [
        int(CKR_OK),
        int(CKR_OK),
    ]


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_wrong_length_init_refusal_cannot_count_as_sign_rejection(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(refuse=("C_SignInit", 1, int(CKR_DATA_LEN_RANGE)))
    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        contract.test_wrong_length_sign_rejects_original_message(
            _stateful_session(fake), _raw_family(family), "SHA-256", CKM_SHA256
        )
    rec = classification.get_records()[-1]
    assert rec.operation == "C_SignInit"
    assert rec.actual_ckr == "CKR_DATA_LEN_RANGE"
    assert rec.detail is not None and rec.detail["reached_phase"] == "C_SignInit"
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_DestroyObject",
        "C_DestroyObject",
    ]


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_canonical_sign_refusal_and_cleanup_evidence(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(destroy_rv=int(CKR_GENERAL_ERROR))
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_wrong_length_sign_rejects_original_message(
            _stateful_session(fake), _raw_family(family), "SHA-256", CKM_SHA256
        )
    )
    assert not classification.get_records()
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_Sign"] == [
        int(CKR_DATA_LEN_RANGE)
    ]
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [
        int(CKR_GENERAL_ERROR),
        int(CKR_GENERAL_ERROR),
    ]
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert "phase=C_Sign" in notes[0].description
    assert "public_destroyed': True" not in notes[0].description
    assert "private_destroyed': True" not in notes[0].description
    assert "unconfirmed" in notes[0].description


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_legacy_canonical_init_lists_unreached_phases_after_cleanup(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake()
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_legacy_registry_null_parameter_chain(
            _stateful_session(fake), _raw_family(family), "roundtrip-44"
        )
    )
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert "C_SignInit" in notes[0].description
    assert "C_Sign" in notes[0].description
    assert "C_VerifyInit" in notes[0].description
    assert "C_Verify" in notes[0].description
    assert "unreached" in notes[0].description
    assert "unconfirmed" in notes[0].description
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_DestroyObject",
        "C_DestroyObject",
    ]


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize("chain", contract._CHAINS)
def test_all_legacy_init_refusals_leave_conditional_calls_unreached(
    family: contract._Family, chain: str
) -> None:
    fake = _RawPqcFake()
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_legacy_registry_null_parameter_chain(
            _stateful_session(fake), _raw_family(family), chain
        )
    )
    assert not classification.get_records()
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert "unreached_phases" in notes[0].description
    assert "C_Sign" in notes[0].description
    assert "C_Verify" in notes[0].description
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_DestroyObject",
        "C_DestroyObject",
    ]


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize("chain", contract._CHAINS)
def test_real_recipe_legacy_sequences_preserve_both_families(
    family: contract._Family, chain: str
) -> None:
    fake = _RawPqcFake(null_parameters="accept")
    classification.clear()
    with pytest.raises(pytest.fail.Exception):
        contract.test_legacy_registry_null_parameter_chain(
            _stateful_session(fake), _raw_family(family), chain
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "accepted_invalid"
    assert rec.detail is not None
    assert rec.detail["completed_events"][0]["effect"] == "completed"
    assert rec.detail["completed_events"][0]["rv"] == int(CKR_OK)
    expected_phases = {
        "roundtrip-44": [
            "C_SignInit",
            "C_Sign",
            "C_Sign",
            "C_VerifyInit",
            "C_Verify",
        ],
        "tamper-25": [
            "C_SignInit",
            "C_Sign",
            "C_Sign",
            "C_VerifyInit",
            "C_Verify",
        ],
        "multipart-136": [
            "C_SignInit",
            *("C_SignUpdate",) * 4,
            "C_SignFinal",
            "C_SignFinal",
            "C_VerifyInit",
            *("C_VerifyUpdate",) * 4,
            "C_VerifyFinal",
        ],
        "streaming-96": [
            "C_SignInit",
            "C_Sign",
            "C_Sign",
            "C_SignInit",
            *("C_SignUpdate",) * 3,
            "C_SignFinal",
            "C_SignFinal",
            "C_VerifyInit",
            "C_VerifyUpdate",
            "C_VerifyFinal",
            "C_VerifyInit",
            *("C_VerifyUpdate",) * 3,
            "C_VerifyFinal",
        ],
    }[chain]
    assert [event["fn"] for event in fake.calls] == [
        *expected_phases,
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    expected_rvs = [int(CKR_OK)] * len(expected_phases)
    if chain == "tamper-25":
        expected_rvs[-1] = int(CKR_SIGNATURE_INVALID)
    assert [event["rv"] for event in fake.calls] == [*expected_rvs, int(CKR_OK), int(CKR_OK)]
    assert [(event["phase"], event["effect"]) for event in rec.detail["completed_events"]] == {
        "roundtrip-44": [("C_Sign", "completed"), ("C_Verify", "completed")],
        "tamper-25": [("C_Sign", "completed"), ("C_Verify", "completed")],
        "multipart-136": [("C_SignFinal", "completed"), ("C_VerifyFinal", "completed")],
        "streaming-96": [
            ("C_Sign", "completed"),
            ("C_SignFinal", "completed"),
            ("C_VerifyFinal", "completed"),
            ("C_VerifyFinal", "completed"),
        ],
    }[chain]
    verified_effects = [
        event["verified"] for event in rec.detail["completed_events"] if "verified" in event
    ]
    assert (
        verified_effects
        == {
            "roundtrip-44": [True],
            "tamper-25": [False],
            "multipart-136": [True],
            "streaming-96": [True, True],
        }[chain]
    )
    assert [event["rv"] for event in rec.detail["completed_events"]] == {
        "roundtrip-44": [int(CKR_OK), int(CKR_OK)],
        "tamper-25": [int(CKR_OK), int(CKR_SIGNATURE_INVALID)],
        "multipart-136": [int(CKR_OK), int(CKR_OK)],
        "streaming-96": [int(CKR_OK)] * 4,
    }[chain]
    assert [event["handle"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [10, 11]
    expected_sign_payload = {
        "roundtrip-44": b"hello pkcs11 sign test" * 2,
        "tamper-25": b"original data for signing",
        "multipart-136": b"multipart signing test input data " * 4,
        "streaming-96": b"multipart sign equivalence test " * 3,
    }[chain]
    supplied = b"".join(
        event["data"]
        for event in fake.calls
        if event["fn"] in {"C_Sign", "C_SignUpdate"}
        and (event["fn"] != "C_Sign" or not event["output_query"])
    )
    if chain == "streaming-96":
        assert supplied == expected_sign_payload * 2
    else:
        assert supplied == expected_sign_payload
    if chain == "tamper-25":
        verify = [event for event in fake.calls if event["fn"] == "C_Verify"]
        assert len(verify) == 1 and verify[0]["data"] == b"tampered data XXXXXXXXXXX"
    elif chain == "multipart-136":
        assert [event["fn"] for event in fake.calls if event["fn"] == "C_SignUpdate"] == [
            "C_SignUpdate"
        ] * 4
        assert [event["fn"] for event in fake.calls if event["fn"] == "C_VerifyUpdate"] == [
            "C_VerifyUpdate"
        ] * 4
    elif chain == "streaming-96":
        assert len([event for event in fake.calls if event["fn"] == "C_VerifyFinal"]) == 2


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_valid_multipart_note_follows_cleanup(family: contract._Family) -> None:
    fake = _RawPqcFake(refuse=("C_SignUpdate", 1, int(CKR_FUNCTION_NOT_SUPPORTED)))
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_generic_valid_parameter_rejects_multipart(
            _stateful_session(fake), _raw_family(family)
        )
    )
    assert not classification.get_records()
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_SignUpdate",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    notes = compliance.get_notes()
    assert len(notes) == 1 and "C_SignUpdate" in notes[0].description
    assert "unconfirmed" in notes[0].description


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize(
    ("fn", "ordinal", "mechanism_side"),
    [
        ("C_SignInit", 1, "generic"),
        ("C_VerifyInit", 1, "suffix"),
        ("C_SignInit", 2, "suffix"),
        ("C_VerifyInit", 2, "generic"),
    ],
)
def test_cross_positive_refusal_names_actual_phase_and_mechanism(
    family: contract._Family, fn: str, ordinal: int, mechanism_side: str
) -> None:
    fake = _RawPqcFake(
        null_parameters="accept", refuse=(fn, ordinal, int(CKR_FUNCTION_NOT_SUPPORTED))
    )
    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        contract.test_generic_and_hash_suffix_cross_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.operation == fn
    expected_mech = family.generic_name if mechanism_side == "generic" else family.suffix_name
    assert rec.mechanism == f"CKM_{expected_mech}"
    assert rec.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert rec.detail is not None and rec.detail["reached_phase"] == fn
    assert [event["fn"] for event in fake.calls[-2:]] == ["C_DestroyObject"] * 2


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize("direction", ["generic_to_suffix", "suffix_to_generic"])
def test_cross_wrong_verification_fails_at_the_actual_direction(
    family: contract._Family, direction: str
) -> None:
    ordinal = 1 if direction == "generic_to_suffix" else 2
    fake = _RawPqcFake(
        null_parameters="accept", refuse=("C_Verify", ordinal, int(CKR_SIGNATURE_INVALID))
    )
    classification.clear()
    with pytest.raises(pytest.fail.Exception):
        contract.test_generic_and_hash_suffix_cross_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "wrong_result" and rec.kind == "crypto"
    expected_mech = family.suffix_name if ordinal == 1 else family.generic_name
    assert rec.mechanism == f"CKM_{expected_mech}"
    assert rec.operation == "C_Verify"
    assert rec.detail is not None
    assert rec.detail[direction] is False
    if ordinal == 1:
        assert rec.detail["suffix_to_generic"] == "unreached"
    else:
        assert rec.detail["generic_to_suffix"] is True
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_Verify"][-1] == int(
        CKR_SIGNATURE_INVALID
    )
    assert [event["fn"] for event in fake.calls[-2:]] == ["C_DestroyObject"] * 2


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_changed_input_sign_refusal_is_not_called_verify(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(refuse=("C_SignInit", 1, int(CKR_FUNCTION_NOT_SUPPORTED)))
    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.operation == "C_SignInit"
    assert rec.detail is not None and rec.detail["reached_phase"] == "C_SignInit"
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_DestroyObject",
        "C_DestroyObject",
    ]


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_changed_input_reaches_verify_with_exact_effect_and_cleanup(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake()
    classification.clear()
    compliance.clear_notes()
    _must_complete(
        lambda: contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    )
    assert not classification.get_records()
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_VerifyInit",
        "C_Verify",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert [event["rv"] for event in fake.calls] == [
        *([int(CKR_OK)] * 6),
        int(CKR_SIGNATURE_INVALID),
        int(CKR_OK),
        int(CKR_OK),
    ]
    verify_calls = [event for event in fake.calls if event["fn"] == "C_Verify"]
    assert [event["data"] for event in verify_calls] == [
        hashlib.sha256(family.message).digest(),
        family.message,
    ]
    assert verify_calls[0]["signature"] == verify_calls[1]["signature"]
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert "phase=C_Verify" in notes[0].description
    assert "CKR_SIGNATURE_INVALID" in notes[0].description
    assert "original_verified': True" in notes[0].description
    assert "changed_verified': False" in notes[0].description
    assert "unreached_phases': []" in notes[0].description
    assert "unconfirmed" in notes[0].description


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_changed_input_malformed_signature_stops_before_target(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(malformed_sign=True)
    classification.clear()
    compliance.clear_notes()
    with pytest.raises(pytest.fail.Exception):
        contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "wrong_result" and rec.kind == "crypto"
    assert rec.operation == "C_Verify"
    assert rec.detail is not None
    assert rec.detail["original_verified"] is False
    assert rec.detail["original_verify_rv"] == "CKR_SIGNATURE_LEN_RANGE"
    assert rec.detail["signature_len"] == 1
    assert rec.detail["changed_input_target_reached"] is False
    assert rec.detail["unreached_phases"] == ["C_VerifyInit", "C_Verify"]
    assert rec.detail["cleanup"] == {
        "public": "best_effort_call_returned_unconfirmed",
        "private": "best_effort_call_returned_unconfirmed",
    }
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert [event["rv"] for event in fake.calls] == [
        *([int(CKR_OK)] * 4),
        int(CKR_SIGNATURE_LEN_RANGE),
        int(CKR_OK),
        int(CKR_OK),
    ]
    assert [event["data"] for event in fake.calls if event["fn"] == "C_Verify"] == [
        hashlib.sha256(family.message).digest()
    ]
    assert [event["signature"] for event in fake.calls if event["fn"] == "C_Verify"] == [b"G"]
    assert not compliance.get_notes()


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_changed_input_length_range_after_valid_signature_is_deviation(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(refuse=("C_Verify", 2, int(CKR_SIGNATURE_LEN_RANGE)))
    classification.clear()
    compliance.clear_notes()
    with pytest.raises(pytest.xfail.Exception):
        contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "honest_deviation" and rec.outcome == "xfail"
    assert rec.operation == "C_Verify"
    assert rec.expected_ckr == ["CKR_SIGNATURE_INVALID"]
    assert rec.actual_ckr == "CKR_SIGNATURE_LEN_RANGE"
    assert rec.detail is not None
    assert rec.detail["original_verified"] is True
    assert rec.detail["changed_verified"] is False
    assert rec.detail["changed_input_target_reached"] is True
    assert rec.detail["unreached_phases"] == []
    assert rec.detail["cleanup"] == {
        "public": "best_effort_call_returned_unconfirmed",
        "private": "best_effort_call_returned_unconfirmed",
    }
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_VerifyInit",
        "C_Verify",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert [event["rv"] for event in fake.calls] == [
        *([int(CKR_OK)] * 6),
        int(CKR_SIGNATURE_LEN_RANGE),
        int(CKR_OK),
        int(CKR_OK),
    ]
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_Verify"] == [
        int(CKR_OK),
        int(CKR_SIGNATURE_LEN_RANGE),
    ]
    verify_calls = [event for event in fake.calls if event["fn"] == "C_Verify"]
    assert [event["data"] for event in verify_calls] == [
        hashlib.sha256(family.message).digest(),
        family.message,
    ]
    assert verify_calls[0]["signature"] == verify_calls[1]["signature"]
    assert [event["handle"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [10, 11]
    assert not compliance.get_notes()


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_changed_input_verification_success_after_valid_control_is_failure(
    family: contract._Family,
) -> None:
    fake = _RawPqcFake(refuse=("C_Verify", 2, int(CKR_OK)))
    classification.clear()
    compliance.clear_notes()
    with pytest.raises(pytest.fail.Exception):
        contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "wrong_result" and rec.kind == "crypto"
    assert rec.operation == "C_Verify"
    assert rec.detail is not None
    assert rec.detail["original_verified"] is True
    assert rec.detail["changed_verified"] is True
    assert rec.detail["changed_input_target_reached"] is True
    assert rec.detail["unreached_phases"] == []
    assert rec.detail["cleanup"] == {
        "public": "best_effort_call_returned_unconfirmed",
        "private": "best_effort_call_returned_unconfirmed",
    }
    assert [event["fn"] for event in fake.calls] == [
        "C_SignInit",
        "C_Sign",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_VerifyInit",
        "C_Verify",
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    assert [event["rv"] for event in fake.calls] == [int(CKR_OK)] * 9
    assert [event["rv"] for event in fake.calls if event["fn"] == "C_Verify"] == [
        int(CKR_OK),
        int(CKR_OK),
    ]
    verify_calls = [event for event in fake.calls if event["fn"] == "C_Verify"]
    assert [event["data"] for event in verify_calls] == [
        hashlib.sha256(family.message).digest(),
        family.message,
    ]
    assert verify_calls[0]["signature"] == verify_calls[1]["signature"]
    assert [event["handle"] for event in fake.calls if event["fn"] == "C_DestroyObject"] == [10, 11]
    assert not compliance.get_notes()


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
@pytest.mark.parametrize("verify_init_ordinal", [1, 2], ids=["control", "changed"])
def test_changed_input_typed_verify_init_refusal_keeps_target_reach_exact(
    family: contract._Family, verify_init_ordinal: int
) -> None:
    fake = _RawPqcFake(
        refuse=("C_VerifyInit", verify_init_ordinal, int(CKR_FUNCTION_NOT_SUPPORTED))
    )
    classification.clear()
    compliance.clear_notes()
    with pytest.raises(pytest.xfail.Exception):
        contract.test_changed_input_verify_does_not_verify(
            _stateful_session(fake), _raw_family(family)
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.operation == "C_VerifyInit"
    assert rec.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert rec.detail is not None
    assert rec.detail["reached_phase"] == "C_VerifyInit"
    assert rec.detail["changed_input_target_reached"] is False
    if verify_init_ordinal == 1:
        assert rec.detail["original_verified"] == "unreached"
    else:
        assert rec.detail["original_verified"] is True
    assert rec.detail["unreached_phases"] == (
        ["C_Verify", "C_VerifyInit", "C_Verify"] if verify_init_ordinal == 1 else ["C_Verify"]
    )
    expected_phases = ["C_SignInit", "C_Sign", "C_Sign", "C_VerifyInit"]
    if verify_init_ordinal == 2:
        expected_phases.extend(["C_Verify", "C_VerifyInit"])
    assert [event["fn"] for event in fake.calls] == [
        *expected_phases,
        "C_DestroyObject",
        "C_DestroyObject",
    ]
    expected_rvs = [int(CKR_OK)] * len(expected_phases)
    expected_rvs[-1] = int(CKR_FUNCTION_NOT_SUPPORTED)
    assert [event["rv"] for event in fake.calls] == [*expected_rvs, int(CKR_OK), int(CKR_OK)]
    assert rec.detail["cleanup"] == {
        "public": "best_effort_call_returned_unconfirmed",
        "private": "best_effort_call_returned_unconfirmed",
    }
    assert not compliance.get_notes()


@pytest.mark.parametrize("family", contract._FAMILIES, ids=lambda family: family.label)
def test_missing_sign_trace_cannot_create_canonical_pass(family: contract._Family) -> None:
    class NoSignTrace(_RawPqcFake):
        def _event(self, fn: str, rv: int, **extra: Any) -> int:
            result = super()._event(fn, rv, **extra)
            if fn == "C_Sign":
                self.rv_trace.pop()
            return result

    fake = NoSignTrace()
    classification.clear()
    with pytest.raises(pytest.fail.Exception):
        contract.test_wrong_length_sign_rejects_original_message(
            _stateful_session(fake), _raw_family(family), "SHA-256", CKM_SHA256
        )
    rec = classification.get_records()[-1]
    assert rec.reason == "self_contradiction" and rec.kind == "metadata"

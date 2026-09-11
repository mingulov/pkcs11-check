"""Runtime regression tests for the F7 CKR/ACVP attribute-presence migration (slice 10).

Covers `ckr/test_ckr_object.py`, `ckr/test_ckr_keygen.py`, `ckr/test_ckr_codes.py`,
`ckr/test_ckr_spec_compliance.py`, `acvp/test_acvp_mlkem.py`, and `acvp/test_acvp_ecdh.py`:
every migrated call site in those files now routes a provider-backed `read_attributes()`
result through `attr_or_record()` instead of a bare subscript/`.get()`.

These tests prove, per migrated site:
- an omitted attribute produces a structured record (reason, `operation ==
  "C_GetAttributeValue"`, `mechanism is None`, exact spec_ref) instead of a KeyError crash
  or a silently fabricated `None`/`[]`/default value;
- the omission disables only the dependent oracle -- independent work already done in the
  same test is not discarded, a genuinely wrong sibling attribute still surfaces, and
  handles are still destroyed;
- a present-but-wrong value is unaffected by the migration and still fails/xfails hard;
- no CKR is invented for a plain omission.

`acvp/test_acvp_rsa_keygen.py` is the one exception in this slice: a generated RSA public
key's CKA_MODULUS_BITS/CKA_MODULUS/CKA_PUBLIC_EXPONENT are self-generated output with no
independent evidence elsewhere, so their omission after a successful readback is itself a
self-contradiction, not missing evidence -- `_require_rsa_keygen_attribute` fails hard
immediately instead of deferring to `attr_or_record`. See the RSA-keygen tests below.

Adequacy is mutation-checked: for each site, the guard is masked back to the pre-migration
bare access and the corresponding test is confirmed to fail (see slice report).
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Generator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_CLASS, CKR_OK
from pkcs11_check.testcases.acvp import acvp_loader as _acvp_loader
from pkcs11_check.testcases.acvp import test_acvp_ecdh as ecdh_case
from pkcs11_check.testcases.ckr import test_ckr_codes as ckr_codes_case
from pkcs11_check.testcases.ckr import test_ckr_keygen as ckr_keygen_case
from pkcs11_check.testcases.ckr import test_ckr_object as ckr_object_case
from pkcs11_check.testcases.ckr import test_ckr_spec_compliance as ckr_spec_case

_ACVP_ROOT = Path(__file__).parent.parent / "src" / "pkcs11_check" / "testcases" / "acvp"


def _load_isolated_under_forced_acvp_available(shim_name: str, real_path: Path) -> ModuleType:
    """Execute an ACVP-gated test module under a private module name, forcing
    ``ACVP_AVAILABLE`` True only for this execution, without ever touching
    ``sys.modules`` under the module's real dotted name.

    ``test_acvp_mlkem.py`` and ``test_acvp_rsa_keygen.py`` call
    ``pytest.skip(allow_module_level=True)`` at import time when ACVP vector data has not
    been fetched (true in this environment). These regressions are white-box unit tests
    driven by synthetic `vec` dicts and monkeypatched recipes -- they never read real
    vector files -- so the data gate must be bypassed to reach the module's code.

    Loading under a private name (instead of ``from pkcs11_check.testcases.acvp import
    test_acvp_mlkem``) is deliberate: a plain import would cache the module in
    ``sys.modules`` under its real dotted name in its *bypassed* (never-skipped) state.
    Several other tests/*.py files (e.g. test_keygen_key_size_conformance.py,
    test_advertised_runtime_classification.py) import these same modules directly and
    rely on the real ``pytest.skip(allow_module_level=True)`` firing when ACVP data is
    absent; a shared cache entry would silently suppress that skip for whichever of those
    files pytest collects afterward in the same process (this broke
    tests/test_no_data_skip_guard.py, which runs all vector-referencing tests/*.py files
    together in one subprocess). Loading under a private name means nothing else ever
    observes this bypassed module, and a later real import of the canonical dotted name
    (by any other file, in any order) still gets a fresh, correctly-gated execution.
    """
    original = _acvp_loader.ACVP_AVAILABLE
    _acvp_loader.ACVP_AVAILABLE = True
    try:
        spec = importlib.util.spec_from_file_location(shim_name, real_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # exec_module() may consult sys.modules for its own name (e.g. dataclass /
        # pytest internals); register under the private shim name only, then drop it
        # once loaded -- the canonical dotted name is never touched.
        sys.modules[shim_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            del sys.modules[shim_name]
        return module
    finally:
        _acvp_loader.ACVP_AVAILABLE = original


mlkem_case = _load_isolated_under_forced_acvp_available(
    "_f7_ckr_acvp_shim_test_acvp_mlkem", _ACVP_ROOT / "test_acvp_mlkem.py"
)
rsa_keygen_case = _load_isolated_under_forced_acvp_available(
    "_f7_ckr_acvp_shim_test_acvp_rsa_keygen", _ACVP_ROOT / "test_acvp_rsa_keygen.py"
)

_SPEC_REF = "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session(*, mechanisms: set[str] | None = None, raw: Any = None, **extra: Any) -> Any:
    mechs = mechanisms or set()
    return SimpleNamespace(
        raw=raw if raw is not None else object(),
        sh=1,
        has_mechanism=lambda name: name in mechs,
        has_mechanism_flag=lambda *_a, **_k: False,
        **extra,
    )


def _assert_readback_record(
    record: C.Classification, *, reason: str, kind: str = "metadata"
) -> None:
    assert record.reason == reason
    # ``kind`` is asserted because ``record_as()`` derives outcome and severity from
    # ``(reason, kind)`` together -- leaving it unchecked lets a severity regression
    # through even while ``reason`` still matches.
    assert record.kind == kind
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == _SPEC_REF


# ---------------------------------------------------------------------------
# ckr/test_ckr_object.py -- CKA_ALLOWED_MECHANISMS empty-array enforcement
# readback (guards a dependent C_EncryptInit/C_Encrypt policy probe).
# ---------------------------------------------------------------------------


class _FakeRawCreateEncrypt:
    """Minimal raw stub for C_CreateObject + C_EncryptInit/C_Encrypt."""

    def __init__(self, *, handle_value: int = 100) -> None:
        self.handle_value = handle_value
        self.encrypt_init_calls = 0
        self.encrypt_calls = 0

    def C_CreateObject(  # noqa: N802
        self, _sh: int, _tmpl_ptr: Any, _count: int, handle_ref: Any
    ) -> int:
        handle_ref._obj.value = self.handle_value
        return CKR_OK

    def C_EncryptInit(self, _sh: int, _mech_ptr: Any, _handle: int) -> int:  # noqa: N802
        self.encrypt_init_calls += 1
        return CKR_OK

    def C_Encrypt(  # noqa: N802
        self, _sh: int, _data: Any, _data_len: int, _out: Any, _out_len: Any
    ) -> int:
        self.encrypt_calls += 1
        return CKR_OK


def test_allowed_mechanisms_missing_readback_still_enforces_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: ``rv == CKR_OK`` from the earlier C_CreateObject
    already proves the module accepted the empty CKA_ALLOWED_MECHANISMS template
    at creation, so a missing readback must not disable the enforcement oracle --
    ``classify_policy_enforcement`` still runs as claimed=True (mutation:
    restoring the pre-fix ``claimed = allowed_mechanisms == []`` sentinel-compare
    derivation -- ``None == []`` is False -- silently disables the oracle
    instead)."""
    raw = _FakeRawCreateEncrypt()
    rs = _session(mechanisms={"AES_ECB"}, raw=raw)
    destroyed: list[int] = []
    enforcement_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(ckr_object_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        ckr_object_case,
        "classify_policy_enforcement",
        lambda **kw: enforcement_calls.append(kw),
    )
    monkeypatch.setattr(
        ckr_object_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ckr_object_case.TestCreateObjectErrors().test_allowed_mechanisms_empty_null_pointer_enforced(rs)

    assert enforcement_calls == [
        {
            "claimed": True,
            "violated": True,
            "label": "CKA_ALLOWED_MECHANISMS empty-array enforcement for C_EncryptInit/C_Encrypt",
        }
    ]
    assert destroyed == [100]

    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# ---------------------------------------------------------------------------
# ckr/test_ckr_object.py, ckr/test_ckr_codes.py, ckr/test_ckr_spec_compliance.py --
# CKA_SENSITIVE readback on a CKA_SENSITIVE=True key (guards the claimed/violated
# policy-enforcement compare). The identical pattern is migrated in all three files.
# ---------------------------------------------------------------------------


def test_ckr_object_sensitive_value_missing_readback_still_enforces_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: gen_aes_key_or_xfail() raises/xfails unless the
    module accepted CKA_SENSITIVE=True, so a missing readback must not disable
    the enforcement oracle -- claimed stays True and a readable CKA_VALUE still
    reaches classify_policy_enforcement as a proven violation (mutation:
    restoring the pre-fix ``claimed = sensitive_readback is True`` derivation on
    MISSING_ATTRIBUTE silently disables the oracle instead)."""
    from pkcs11_check.raw.types_std import CKA_VALUE

    rs = _session()
    destroyed: list[int] = []
    enforcement_calls: list[dict[str, Any]] = []

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict[Any, Any]:
        return {CKA_VALUE: b"\x00" * 32} if CKA_VALUE in attrs else {}

    monkeypatch.setattr(ckr_object_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 201)
    monkeypatch.setattr(ckr_object_case, "read_attributes", _read)
    monkeypatch.setattr(
        ckr_object_case,
        "classify_policy_enforcement",
        lambda **kw: enforcement_calls.append(kw),
    )
    monkeypatch.setattr(
        ckr_object_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ckr_object_case.TestGetAttributeErrors().test_sensitive_value(rs)

    assert enforcement_calls == [
        {
            "claimed": True,
            "violated": True,
            "label": "read CKA_VALUE on a CKA_SENSITIVE=True key "
            "(PKCS#11 v3.2 requires CKR_ATTRIBUTE_SENSITIVE)",
        }
    ]
    assert destroyed == [201]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational", kind="policy")


def test_ckr_codes_attribute_sensitive_missing_readback_still_enforces_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: same shape as the ckr_object.py sensitive-value
    site -- a missing readback must not disable the enforcement oracle."""
    from pkcs11_check.raw.types_std import CKA_VALUE

    rs = _session()
    destroyed: list[int] = []
    enforcement_calls: list[dict[str, Any]] = []

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict[Any, Any]:
        return {CKA_VALUE: b"\x00" * 32} if CKA_VALUE in attrs else {}

    monkeypatch.setattr(ckr_codes_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 202)
    monkeypatch.setattr(ckr_codes_case, "read_attributes", _read)
    monkeypatch.setattr(
        ckr_codes_case,
        "classify_policy_enforcement",
        lambda **kw: enforcement_calls.append(kw),
    )
    monkeypatch.setattr(
        ckr_codes_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ckr_codes_case.TestCKRAttributeErrors().test_ckr_attribute_sensitive(rs)

    assert enforcement_calls == [
        {
            "claimed": True,
            "violated": True,
            "label": "read CKA_VALUE on a CKA_SENSITIVE=True key "
            "(PKCS#11 v3.2 requires CKR_ATTRIBUTE_SENSITIVE)",
        }
    ]
    assert destroyed == [202]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational", kind="policy")


def test_ckr_spec_compliance_sensitive_value_missing_readback_still_enforces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: same shape as the ckr_object.py sensitive-value
    site -- a missing readback must not disable the enforcement oracle."""
    from pkcs11_check.raw.types_std import CKA_VALUE

    rs = _session()
    destroyed: list[int] = []
    enforcement_calls: list[dict[str, Any]] = []

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict[Any, Any]:
        return {CKA_VALUE: b"\x00" * 32} if CKA_VALUE in attrs else {}

    monkeypatch.setattr(ckr_spec_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 203)
    monkeypatch.setattr(ckr_spec_case, "read_attributes", _read)
    monkeypatch.setattr(
        ckr_spec_case,
        "classify_policy_enforcement",
        lambda **kw: enforcement_calls.append(kw),
    )
    monkeypatch.setattr(
        ckr_spec_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ckr_spec_case.TestCKRAttributeCompliance().test_sensitive_value_returns_attribute_sensitive(rs)

    assert enforcement_calls == [
        {
            "claimed": True,
            "violated": True,
            "label": "read CKA_VALUE on a CKA_SENSITIVE=True key "
            "(PKCS#11 v3.2 requires CKR_ATTRIBUTE_SENSITIVE)",
        }
    ]
    assert destroyed == [203]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational", kind="policy")


# ---------------------------------------------------------------------------
# ckr/test_ckr_object.py -- read-only CKA_CLASS readback after a claimed-success
# C_SetAttributeValue (guards the self_contradiction-vs-honest_deviation split).
# ---------------------------------------------------------------------------


class _FakeRawSetAttr:
    def __init__(self, *, set_rv: int = CKR_OK) -> None:
        self.set_rv = set_rv

    def C_SetAttributeValue(  # noqa: N802
        self, _sh: int, _handle: int, _tmpl_ptr: Any, _count: int
    ) -> int:
        return self.set_rv


def test_set_readonly_class_missing_readback_claims_neither_verdict_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing post-write CKA_CLASS readback cannot tell a no-op apart from a real
    write, so the site must claim neither `self_contradiction` (fail) nor
    `honest_deviation` (xfail) -- both would be inventing a verdict from an omission."""
    raw = _FakeRawSetAttr()
    rs = _session(raw=raw)
    destroyed: list[int] = []

    monkeypatch.setattr(ckr_object_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(ckr_object_case, "create_object", lambda *_a, **_k: 301)
    monkeypatch.setattr(ckr_object_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        ckr_object_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    # Must return normally: neither pytest.fail (self_contradiction) nor pytest.xfail
    # (honest_deviation) may fire from a plain omission.
    ckr_object_case.TestSetAttributeErrors().test_set_readonly_class(rs)

    assert destroyed == [301]
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_set_readonly_class_actual_writethrough_still_fails_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unaffected by F7: a present CKA_CLASS proving the read-only write actually took
    effect must still raise the hard self_contradiction failure."""
    from pkcs11_check.raw.types_std import CKO_SECRET_KEY

    raw = _FakeRawSetAttr()
    rs = _session(raw=raw)

    monkeypatch.setattr(ckr_object_case, "skip_unless_create_object_supported", lambda _rs: None)
    monkeypatch.setattr(ckr_object_case, "create_object", lambda *_a, **_k: 302)
    monkeypatch.setattr(
        ckr_object_case, "read_attributes", lambda *_a, **_k: {CKA_CLASS: CKO_SECRET_KEY}
    )
    monkeypatch.setattr(ckr_object_case, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="self-contradiction"):
        ckr_object_case.TestSetAttributeErrors().test_set_readonly_class(rs)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"


# ---------------------------------------------------------------------------
# ckr/test_ckr_keygen.py -- generated-key CKA_CLASS/CKA_KEY_TYPE readback after
# C_GenerateKey(NULL, 0) (two independent guards in the same test).
# ---------------------------------------------------------------------------


class _FakeRawGenerateKey:
    def __init__(self, *, handle_value: int = 401) -> None:
        self.handle_value = handle_value

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech_ptr: Any, _tmpl_ptr: Any, _count: int, key_ref: Any
    ) -> int:
        key_ref._obj.value = self.handle_value
        return CKR_OK


def test_generate_key_null_template_missing_class_and_key_type_records_both_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both the CKA_CLASS and CKA_KEY_TYPE readbacks are independent guards: each
    missing attribute records its own evidence and skips only its own assert_correct,
    and the generated key handle is still destroyed."""
    raw = _FakeRawGenerateKey()
    rs = _session(mechanisms={"DES_KEY_GEN"}, raw=raw)
    destroyed: list[int] = []

    monkeypatch.setattr(ckr_keygen_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        ckr_keygen_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ckr_keygen_case.TestGenerateKeyErrors().test_fixed_length_generate_key_accepts_null_empty_template(
        rs
    )

    assert destroyed == [401]
    records = C.get_records()
    assert len(records) == 2
    for record in records:
        _assert_readback_record(record, reason="not_operational")


def test_generate_key_null_template_missing_class_does_not_hide_wrong_key_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing CKA_CLASS must not suppress an independently-read, genuinely wrong
    CKA_KEY_TYPE: the sibling defect still surfaces as a hard wrong_result failure."""
    from pkcs11_check.raw.types_std import CKA_KEY_TYPE, CKK_RSA

    raw = _FakeRawGenerateKey()
    rs = _session(mechanisms={"DES_KEY_GEN"}, raw=raw)

    monkeypatch.setattr(
        ckr_keygen_case, "read_attributes", lambda *_a, **_k: {CKA_KEY_TYPE: CKK_RSA}
    )
    monkeypatch.setattr(ckr_keygen_case, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="CKA_KEY_TYPE.*output does not match known"):
        ckr_keygen_case.TestGenerateKeyErrors().test_fixed_length_generate_key_accepts_null_empty_template(
            rs
        )

    records = C.get_records()
    # One readback record for the missing CKA_CLASS, then the hard CKA_KEY_TYPE failure.
    assert len(records) == 2
    _assert_readback_record(records[0], reason="not_operational")
    assert records[1].reason == "wrong_result"
    assert "CKA_KEY_TYPE" in records[1].label


# ---------------------------------------------------------------------------
# acvp/test_acvp_mlkem.py -- ML-KEM encapsulate/decapsulate shared-secret
# readback (three independent sites across two test methods).
# ---------------------------------------------------------------------------


def _patch_mlkem_common(monkeypatch: pytest.MonkeyPatch, destroyed: list[int]) -> None:
    monkeypatch.setattr(mlkem_case, "import_pqc_public_key", lambda *_a, **_k: 501)
    monkeypatch.setattr(mlkem_case, "import_pqc_private_key", lambda *_a, **_k: 502)
    monkeypatch.setattr(
        mlkem_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )


def test_mlkem_encapsulate_missing_encap_secret_returns_before_decap_read_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing readback on the *encapsulated* secret disables the compare before the
    decapsulated secret is even read; independent setup work (encap+decap operations
    already performed) is still cleaned up."""
    rs = _session(mechanisms={"ML_KEM"})
    destroyed: list[int] = []
    _patch_mlkem_common(monkeypatch, destroyed)
    monkeypatch.setattr(mlkem_case, "encapsulate_key", lambda *_a, **_k: (503, b"\x00" * 8))
    monkeypatch.setattr(mlkem_case, "decapsulate_key", lambda *_a, **_k: 504)
    monkeypatch.setattr(mlkem_case, "read_attributes", lambda *_a, **_k: {})

    vec = {
        "param_set": "ML-KEM-768",
        "parameter_set": "ML-KEM-768",
        "ek": b"\x01" * 16,
        "dk": b"\x02" * 16,
        "c": b"\x00" * 8,
    }
    mlkem_case.TestMlKemEncapsulate().test_mlkem_encapsulate(rs, "tc-1", vec)

    assert set(destroyed) == {501, 502, 503, 504}
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_mlkem_encapsulate_missing_decap_secret_keeps_encap_evidence_and_skips_only_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The encapsulated secret is present and successfully resolved (independent
    evidence retained); only the decapsulated-side readback is missing, and only the
    equality compare is skipped."""
    from pkcs11_check.raw.types_std import CKA_VALUE

    rs = _session(mechanisms={"ML_KEM"})
    destroyed: list[int] = []
    _patch_mlkem_common(monkeypatch, destroyed)
    monkeypatch.setattr(mlkem_case, "encapsulate_key", lambda *_a, **_k: (505, b"\x00" * 8))
    monkeypatch.setattr(mlkem_case, "decapsulate_key", lambda *_a, **_k: 506)

    def _fake_read_attributes(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        return {CKA_VALUE: b"shared-secret"} if handle == 505 else {}

    monkeypatch.setattr(mlkem_case, "read_attributes", _fake_read_attributes)

    vec = {
        "param_set": "ML-KEM-768",
        "parameter_set": "ML-KEM-768",
        "ek": b"\x01" * 16,
        "dk": b"\x02" * 16,
        "c": b"\x00" * 8,
    }
    mlkem_case.TestMlKemEncapsulate().test_mlkem_encapsulate(rs, "tc-2", vec)

    assert set(destroyed) == {501, 502, 505, 506}
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_mlkem_decapsulate_missing_secret_skips_only_kat_compare_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session(mechanisms={"ML_KEM"})
    destroyed: list[int] = []

    monkeypatch.setattr(mlkem_case, "import_pqc_private_key", lambda *_a, **_k: 507)
    monkeypatch.setattr(mlkem_case, "decapsulate_key", lambda *_a, **_k: 508)
    monkeypatch.setattr(mlkem_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        mlkem_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    vec = {
        "param_set": "ML-KEM-768",
        "parameter_set": "ML-KEM-768",
        "dk": b"\x02" * 16,
        "c": b"\x00" * 8,
        "k": b"\x03" * 32,
    }
    mlkem_case.TestMlKemDecapsulate().test_mlkem_decapsulate(rs, "tc-3", vec)

    assert set(destroyed) == {507, 508}
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# ---------------------------------------------------------------------------
# acvp/test_acvp_ecdh.py -- ECDH derived shared-secret readback (KAT-compare site
# and key-agreement continuation site).
# ---------------------------------------------------------------------------


def test_ecdh_kat_missing_shared_secret_skips_compare_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = _session(mechanisms={"ECDH1_DERIVE"})
    destroyed: list[int] = []

    monkeypatch.setattr(ecdh_case, "provision_ec_private_key", lambda *_a, **_k: 601)
    monkeypatch.setattr(ecdh_case, "import_ec_public_key", lambda *_a, **_k: 602)
    monkeypatch.setattr(ecdh_case, "decode_ec_point", lambda _der: b"\x00" * 8)
    monkeypatch.setattr(ecdh_case, "mech_ecdh", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(ecdh_case, "derive_key", lambda *_a, **_k: 603)
    monkeypatch.setattr(ecdh_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        ecdh_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    vec = {
        "curve": "P-256",
        "private_key": b"\x01" * 32,
        "ec_point_der": b"\x02" * 8,
        "expected_shared": b"\x03" * 32,
    }
    ecdh_case.test_acvp_ecdh_shared_secret(rs, None, "tc-4", vec)

    assert set(destroyed) == {601, 602, 603}
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


def test_ecdh_kat_wrong_shared_secret_still_fails_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unaffected by F7: a present-but-wrong shared secret must still fail hard."""
    rs = _session(mechanisms={"ECDH1_DERIVE"})

    monkeypatch.setattr(ecdh_case, "provision_ec_private_key", lambda *_a, **_k: 604)
    monkeypatch.setattr(ecdh_case, "import_ec_public_key", lambda *_a, **_k: 605)
    monkeypatch.setattr(ecdh_case, "decode_ec_point", lambda _der: b"\x00" * 8)
    monkeypatch.setattr(ecdh_case, "mech_ecdh", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(ecdh_case, "derive_key", lambda *_a, **_k: 606)
    from pkcs11_check.raw.types_std import CKA_VALUE

    monkeypatch.setattr(ecdh_case, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\xff" * 32})
    monkeypatch.setattr(ecdh_case, "destroy_quietly", lambda *_a, **_k: None)

    vec = {
        "curve": "P-256",
        "private_key": b"\x01" * 32,
        "ec_point_der": b"\x02" * 8,
        "expected_shared": b"\x03" * 32,
    }
    with pytest.raises(pytest.fail.Exception, match="output does not match known answer"):
        ecdh_case.test_acvp_ecdh_shared_secret(rs, None, "tc-5", vec)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


def test_ecdh_key_agreement_missing_shared_secret_skips_length_check_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.raw.types_std import CKA_EC_POINT

    rs = _session(mechanisms={"ECDH1_DERIVE"})
    destroyed: list[int] = []

    handles = iter([(701, 702), (703, 704)])
    monkeypatch.setattr("pkcs11_check.raw.recipes.gen_ec_keypair", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(ecdh_case, "parse_provider_ec_point", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(ecdh_case, "select_ecdh_point_form", lambda *_a, **_k: b"\x04" * 8)
    monkeypatch.setattr(ecdh_case, "mech_ecdh", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(ecdh_case, "derive_key", lambda *_a, **_k: 705)

    def _fake_read_attributes(_raw: Any, _sh: int, handle: int, attrs: Any) -> dict[int, Any]:
        if CKA_EC_POINT in attrs:
            return {CKA_EC_POINT: b"\x04" * 65}
        return {}

    monkeypatch.setattr(ecdh_case, "read_attributes", _fake_read_attributes)
    monkeypatch.setattr(
        ecdh_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    ecdh_case.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    assert set(destroyed) == {701, 702, 703, 704, 705}
    records = C.get_records()
    assert len(records) == 1
    _assert_readback_record(records[0], reason="not_operational")


# ---------------------------------------------------------------------------
# acvp/test_acvp_rsa_keygen.py -- generated RSA public-key attribute readback
# (three attributes share one `_require_rsa_keygen_attribute` guard).
# ---------------------------------------------------------------------------


def test_rsa_keygen_missing_modulus_bits_is_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing CKA_MODULUS_BITS after a successful attribute readback is a
    self-contradiction (the module returned CKR_OK on the query yet omitted
    required generated-key metadata), not merely missing evidence -- it fails
    hard immediately and does not defer to sibling attribute checks (a
    genuinely malformed present CKA_PUBLIC_EXPONENT here is never reached,
    since the CKA_MODULUS_BITS omission is already a sufficient, correct
    terminal verdict on its own)."""
    from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_PUBLIC_EXPONENT

    rs = _session(mechanisms={"RSA_PKCS_KEY_PAIR_GEN"})

    monkeypatch.setattr(rsa_keygen_case, "gen_rsa_keypair", lambda *_a, **_k: (801, 802))
    monkeypatch.setattr(rsa_keygen_case, "require_keygen_key_size", lambda *_a, **_k: None)
    monkeypatch.setattr(rsa_keygen_case, "skip_duplicate_pkcs11_input", lambda *_a, **_k: None)
    monkeypatch.setattr(
        rsa_keygen_case,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_MODULUS: b"\x01" * 256,
            CKA_PUBLIC_EXPONENT: (4).to_bytes(1, "big"),
        },
    )
    monkeypatch.setattr(rsa_keygen_case, "destroy_quietly", lambda *_a, **_k: None)

    vec = {"modulo": 2048}
    with pytest.raises(pytest.fail.Exception, match="omitted required CKA_MODULUS_BITS"):
        rsa_keygen_case.TestRsaKeyGen().test_rsa_keygen_attributes(rs, "tc-6", vec)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"
    assert records[0].kind == "metadata"


def test_rsa_keygen_missing_all_three_attributes_fails_hard_on_the_first_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All three generated-key attributes omitted: the first one checked
    (CKA_MODULUS_BITS) fails hard immediately rather than recording three soft
    deviations and passing; cleanup still runs for both handles regardless."""
    rs = _session(mechanisms={"RSA_PKCS_KEY_PAIR_GEN"})
    destroyed: list[int] = []

    monkeypatch.setattr(rsa_keygen_case, "gen_rsa_keypair", lambda *_a, **_k: (803, 804))
    monkeypatch.setattr(rsa_keygen_case, "require_keygen_key_size", lambda *_a, **_k: None)
    monkeypatch.setattr(rsa_keygen_case, "skip_duplicate_pkcs11_input", lambda *_a, **_k: None)
    monkeypatch.setattr(rsa_keygen_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        rsa_keygen_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    vec = {"modulo": 2048}
    with pytest.raises(pytest.fail.Exception, match="omitted required CKA_MODULUS_BITS"):
        rsa_keygen_case.TestRsaKeyGen().test_rsa_keygen_attributes(rs, "tc-7", vec)

    assert set(destroyed) == {803, 804}
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"
    assert records[0].kind == "metadata"

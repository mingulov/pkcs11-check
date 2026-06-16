"""Regression tests for storage-shape negotiation on key-import C_CreateObject.

Storage-oriented PKCS#11 implementations reject the spec-minimal import
template with clean errors: corePKCS11 requires CKA_LABEL on every key object
(CKR_ARGUMENTS_BAD when absent, probed 2026-06-09) and supports only token
objects (CKR_ATTRIBUTE_VALUE_INVALID for CKA_TOKEN=False). The spec makes
CKA_LABEL optional and session objects mandatory, so the canonical template
stays minimal; ``create_object_negotiated`` retries spec-equivalent *storage*
variants (add a unique CKA_LABEL, then CKA_TOKEN=True) only on those clean
storage-shape rejects. Crypto-visible attributes are never changed, no
provider identity is consulted, and non-shape rejects propagate immediately.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VERIFY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases import conftest as tc
from pkcs11_check.testcases._negotiation import negotiate_request


class _Session:
    raw = object()
    sh = 1


@pytest.fixture(autouse=True)
def _fresh_negotiation_cache() -> None:
    tc.reset_import_negotiation_cache()


def _raise(rv: int) -> None:
    raise CkrAssertionError(f"Unexpected CK_RV; rv={rv}", int(rv))


_BASE_TEMPLATE: dict[Any, Any] = {
    CKA_CLASS: 2,
    CKA_KEY_TYPE: 3,
    CKA_TOKEN: False,
    CKA_EC_PARAMS: b"params",
    CKA_EC_POINT: b"point",
    CKA_VERIFY: True,
}


def _storage_oriented_module(calls: list[dict[Any, Any]]) -> Any:
    """Fake create_object behaving like corePKCS11: label required, token-only."""

    def _create_object(_raw: Any, _session: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        if CKA_LABEL not in attrs:
            _raise(CKR_ARGUMENTS_BAD)
        if not attrs.get(CKA_TOKEN, False):
            _raise(CKR_ATTRIBUTE_VALUE_INVALID)
        return 42

    return _create_object


def test_canonical_template_unchanged_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module accepting the minimal template sees exactly that template, once."""
    calls: list[dict[Any, Any]] = []

    def _create_object(_raw: Any, _session: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        return 7

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _create_object)

    handle = tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")

    assert handle == 7
    assert calls == [_BASE_TEMPLATE]


def test_retries_label_then_token_for_storage_oriented_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """corePKCS11 shape: no-label -> ARGUMENTS_BAD, session obj -> ATTRIBUTE_VALUE_INVALID."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    handle = tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")

    assert handle == 42
    assert len(calls) == 3
    # Variant 0: canonical, untouched.
    assert calls[0] == _BASE_TEMPLATE
    # Variant 1: + CKA_LABEL only.
    label = calls[1].get(CKA_LABEL)
    assert isinstance(label, bytes) and 0 < len(label) <= 32
    assert calls[1] == {**_BASE_TEMPLATE, CKA_LABEL: label}
    # Variant 2: same label, CKA_TOKEN=True. Crypto attrs never change.
    assert calls[2] == {**_BASE_TEMPLATE, CKA_LABEL: label, CKA_TOKEN: True}


def test_non_shape_reject_propagates_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-storage-shape CKR (e.g. CKR_DEVICE_ERROR) is a finding, not negotiable."""
    calls = 0

    def _create_object(_raw: Any, _session: int, _attrs: dict[Any, Any]) -> int:
        nonlocal calls
        calls += 1
        _raise(CKR_DEVICE_ERROR)
        return 0

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _create_object)

    with pytest.raises(CkrAssertionError) as ei:
        tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")

    assert ei.value.rv == CKR_DEVICE_ERROR
    assert calls == 1


def test_negotiated_labels_are_unique_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Label-keyed stores must not see two imports collide on one label."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")
    tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")

    labels = {c[CKA_LABEL] for c in calls if CKA_LABEL in c}
    assert len(labels) == 2


def test_caller_supplied_label_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit CKA_LABEL is never replaced; only CKA_TOKEN may be negotiated."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    template = {**_BASE_TEMPLATE, CKA_LABEL: b"caller-label"}
    handle = tc.create_object_negotiated(_Session(), template, purpose="t")

    assert handle == 42
    assert calls == [template, {**template, CKA_TOKEN: True}]


def test_token_true_template_gets_no_token_variant(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKA_TOKEN=True templates only negotiate the label, never duplicate variants."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    template = {**_BASE_TEMPLATE, CKA_TOKEN: True}
    handle = tc.create_object_negotiated(_Session(), template, purpose="t")

    assert handle == 42
    assert len(calls) == 2
    label = calls[1][CKA_LABEL]
    assert calls == [template, {**template, CKA_LABEL: label}]


def test_default_negotiate_request_still_rejects_arguments_bad() -> None:
    """The wider storage-shape reject set is import-site only: the default
    negotiate_request must keep propagating CKR_ARGUMENTS_BAD immediately."""
    calls = 0

    def attempt(_delta: Any) -> int:
        nonlocal calls
        calls += 1
        _raise(CKR_ARGUMENTS_BAD)
        return 0

    with pytest.raises(CkrAssertionError):
        negotiate_request(attempt, [{}, {CKA_LABEL: b"x"}], label="t")

    assert calls == 1


def test_winning_variant_is_cached_per_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """After the first negotiation, the winning storage variant is reused:
    no re-walking rejected variants thousands of times (one C_CreateObject per
    subsequent import instead of three on a storage-oriented module)."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")
    first_round = len(calls)
    tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t")

    assert first_round == 3
    assert len(calls) == first_round + 1  # cached winner: single call
    assert calls[-1].get(CKA_TOKEN) is True and CKA_LABEL in calls[-1]


def test_cached_winner_failure_falls_back_to_full_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the cached winner stops working (clean shape reject), the full
    canonical-first sequence runs again and re-learns."""
    calls: list[dict[Any, Any]] = []
    mode = {"accept": "label+token"}

    def _create_object(_raw: Any, _session: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        if mode["accept"] == "label+token":
            if CKA_LABEL not in attrs:
                _raise(CKR_ARGUMENTS_BAD)
            if not attrs.get(CKA_TOKEN, False):
                _raise(CKR_ATTRIBUTE_VALUE_INVALID)
            return 42
        # Later the module only accepts the canonical minimal template.
        if CKA_LABEL in attrs or attrs.get(CKA_TOKEN, False):
            _raise(CKR_ATTRIBUTE_VALUE_INVALID)
        return 43

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _create_object)

    assert tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t") == 42
    mode["accept"] = "canonical"
    assert tc.create_object_negotiated(_Session(), _BASE_TEMPLATE, purpose="t") == 43


def test_policy_attr_drop_variant_on_attribute_type_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """corePKCS11's HMAC key parser returns CKR_ATTRIBUTE_TYPE_INVALID for
    CKA_SENSITIVE (unknown attribute). A storage variant drops the benign
    policy attrs (CKA_SENSITIVE/CKA_EXTRACTABLE), mirroring the unwrap
    negotiation precedent. Crypto-visible attrs are never dropped."""
    from pkcs11_check.raw.types_std import CKA_SENSITIVE, CKA_SIGN, CKA_VALUE

    calls: list[dict[Any, Any]] = []

    def _create_object(_raw: Any, _session: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        if CKA_LABEL not in attrs:
            _raise(CKR_ARGUMENTS_BAD)
        if not attrs.get(CKA_TOKEN, False):
            _raise(CKR_ATTRIBUTE_VALUE_INVALID)
        if CKA_SENSITIVE in attrs:
            _raise(0x12)  # CKR_ATTRIBUTE_TYPE_INVALID
        return 42

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _create_object)

    template = {**_BASE_TEMPLATE, CKA_SIGN: True, CKA_SENSITIVE: False, CKA_VALUE: b"k" * 32}
    handle = tc.create_object_negotiated(_Session(), template, purpose="t")

    assert handle == 42
    final = calls[-1]
    assert CKA_SENSITIVE not in final
    # Crypto-visible attributes survive every variant.
    assert final[CKA_VALUE] == b"k" * 32 and final[CKA_SIGN] is True


def test_binding_defect_none_when_params_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that honors the requested curve shows no binding defect."""
    from pkcs11_check.raw.types_std import CKA_EC_PARAMS as _P

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.read_attributes",
        lambda _raw, _sh, _h, _types: {int(_P): b"\x06\x05requested"},
    )
    assert tc.ec_public_key_binding_defect(_Session(), 5, b"\x06\x05requested") is None


def test_binding_defect_reports_silent_curve_rebind(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OK create followed by different CKA_EC_PARAMS = silent rebind (corePKCS11)."""
    from pkcs11_check.raw.types_std import CKA_EC_PARAMS as _P

    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.read_attributes",
        lambda _raw, _sh, _h, _types: {int(_P): bytes.fromhex("06082a8648ce3d030107")},
    )
    defect = tc.ec_public_key_binding_defect(_Session(), 5, bytes.fromhex("06052b8104000a"))
    assert defect is not None
    assert "06052b8104000a" in defect and "06082a8648ce3d030107" in defect


def test_binding_defect_reports_incoherent_object(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OK create followed by a readback CKR error = incoherent object (corePKCS11
    returns CKR_OBJECT_HANDLE_INVALID for a foreign-curve key it claimed to import)."""

    def _read(_raw: Any, _sh: int, _h: int, _types: Any) -> dict[int, Any]:
        _raise(0x82)  # CKR_OBJECT_HANDLE_INVALID
        return {}

    monkeypatch.setattr("pkcs11_check.raw.recipes.read_attributes", _read)
    defect = tc.ec_public_key_binding_defect(_Session(), 5, b"\x06\x05requested")
    assert defect is not None and "incoherent" in defect


def test_binding_defect_reports_unavailable_params(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKA_EC_PARAMS unavailable after a CKR_OK create is a binding defect."""
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.read_attributes",
        lambda _raw, _sh, _h, _types: {},
    )
    defect = tc.ec_public_key_binding_defect(_Session(), 5, b"\x06\x05requested")
    assert defect is not None and "unavailable" in defect


def test_ec_import_coherence_defect_is_fail_not_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A claimed-OK-but-unhonored import is a Type-C self-contradiction: the
    dedicated conformance test must FAIL, never xfail/skip."""
    from pkcs11_check.testcases import test_ec_import_coherence as coherence

    class _Rs:
        raw = object()
        sh = 1

        @staticmethod
        def has_mechanism(_name: str) -> bool:
            return True

    monkeypatch.setattr(coherence, "import_ec_public_key_negotiated", lambda *a, **k: 7)
    monkeypatch.setattr(coherence, "ec_public_key_binding_defect", lambda *_a: "silently rebound")
    monkeypatch.setattr(coherence, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(coherence, "skip_unless_create_object_supported", lambda *_a, **_k: None)

    with pytest.raises(pytest.fail.Exception, match="self-contradiction"):
        coherence.test_ec_public_key_import_is_coherent(_Rs(), "secp256k1")


def test_ec_import_coherence_clean_reject_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean curve-unsupported reject at import is a capability skip."""
    from pkcs11_check.raw.types_std import CKR_CURVE_NOT_SUPPORTED
    from pkcs11_check.testcases import test_ec_import_coherence as coherence

    class _Rs:
        raw = object()
        sh = 1

        @staticmethod
        def has_mechanism(_name: str) -> bool:
            return True

    def _reject(*_a: Any, **_k: Any) -> int:
        _raise(CKR_CURVE_NOT_SUPPORTED)
        return 0

    monkeypatch.setattr(coherence, "import_ec_public_key_negotiated", _reject)
    monkeypatch.setattr(coherence, "skip_unless_create_object_supported", lambda *_a, **_k: None)

    with pytest.raises(pytest.skip.Exception, match="cleanly rejects"):
        coherence.test_ec_public_key_import_is_coherent(_Rs(), "secp256k1")


def test_wycheproof_ecdsa_uses_negotiated_import() -> None:
    """Regression guard (triage H6): the Wycheproof ECDSA KAT must import its
    public keys through the negotiating helper. With the raw recipe, storage-
    oriented modules (corePKCS11: CKA_LABEL required, token-only objects) hard-
    failed all 21,906 vectors at C_CreateObject with CKR_ARGUMENTS_BAD before a
    single verify ran."""
    import ast
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[1]
        / "src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    raw_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "import_ec_public_key"
    ]
    assert raw_calls == [], (
        f"test_wycheproof_ecdsa.py uses raw import_ec_public_key at lines {raw_calls}; "
        "use import_ec_public_key_negotiated (conftest) so storage-shape rejects negotiate"
    )


def test_import_secret_key_negotiated_builds_canonical_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The secret-key helper presents the same canonical template as the raw
    recipe (CLASS/KEY_TYPE/VALUE + caller attrs) and negotiates storage shape."""
    from pkcs11_check.raw.types_std import CKA_SIGN, CKA_VALUE, CKO_SECRET_KEY

    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    handle = tc.import_secret_key_negotiated(
        _Session(), 21, b"\x01" * 16, attrs={CKA_SIGN: True, CKA_TOKEN: False}, purpose="t"
    )

    assert handle == 42
    assert calls[0][CKA_CLASS] == CKO_SECRET_KEY
    assert calls[0][CKA_KEY_TYPE] == 21
    assert calls[0][CKA_VALUE] == b"\x01" * 16
    assert calls[0][CKA_SIGN] is True
    assert calls[0][CKA_TOKEN] is False
    assert CKA_LABEL not in calls[0]
    assert calls[2][CKA_TOKEN] is True


def test_acvp_hmac_uses_negotiated_import() -> None:
    """Regression guard: the ACVP HMAC KAT must import keys through the
    negotiating helper (corePKCS11: 148 hard-fails at C_CreateObject without it)."""
    import ast
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases/acvp/test_acvp_hmac.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    raw_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "import_secret_key"
    ]
    assert raw_calls == []


def test_import_ec_public_key_negotiated_builds_canonical_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The EC import helper presents the same canonical template as the raw recipe."""
    calls: list[dict[Any, Any]] = []
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _storage_oriented_module(calls))

    handle = tc.import_ec_public_key_negotiated(
        _Session(),
        ec_params=b"params",
        ec_point=b"point",
        attrs={CKA_VERIFY: True},
        purpose="t",
    )

    assert handle == 42
    # Canonical variant matches raw.recipes.import_ec_public_key's template:
    # class/key_type/token=False/params/point + caller attrs.
    assert calls[0][CKA_TOKEN] is False
    assert calls[0][CKA_EC_PARAMS] == b"params"
    assert calls[0][CKA_EC_POINT] == b"point"
    assert calls[0][CKA_VERIFY] is True
    assert CKA_LABEL not in calls[0]
    assert calls[2][CKA_TOKEN] is True


def test_limbo_portable_label_fits_embedded_stores() -> None:
    """Labels stay within the 32-byte floor (corePKCS11 rejects longer with
    CKR_DATA_LEN_RANGE before parsing the cert), short ids pass through,
    long ids map deterministically and without collision."""
    from pkcs11_check.testcases.x509.test_limbo_import import _portable_label

    assert _portable_label("short-id") == "short-id"
    long_a = "webpki::san::exact-localhost-ip-and-very-long-testcase-name"
    long_b = long_a + "-2"
    assert len(_portable_label(long_a).encode()) <= 32
    assert _portable_label(long_a) == _portable_label(long_a)
    assert _portable_label(long_a) != _portable_label(long_b)


def test_ro_session_object_readonly_reject_is_xfail() -> None:
    """Triage H4: bouncyhsm rejects spec-legal SESSION objects in RO sessions
    with CKR_SESSION_READ_ONLY (defined for token objects) -> recorded
    deviation, not a hard fail. Other codes keep propagating."""
    from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_SESSION_READ_ONLY
    from pkcs11_check.testcases import test_ro_session_restrictions as ro

    exc = CkrAssertionError("Unexpected CK_RV CKR_SESSION_READ_ONLY", int(CKR_SESSION_READ_ONLY))
    with pytest.raises(pytest.xfail.Exception, match="deviation"):
        ro._xfail_if_session_object_rejected_readonly(exc)

    other = CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))
    assert ro._xfail_if_session_object_rejected_readonly(other) is None

"""Runtime classification meta-tests for security/test_api_security policy sites.

:241 wrap-decrypt oracle: the target key is created non-extractable/sensitive
(claimed protected). If the wrap-decrypt oracle yields its key material the
protection is violated -> fail; if the module declines the dangerous
combination or the target was not protected -> xfail/return.

:363 copy extractable-escalation: claimed = original reads CKA_EXTRACTABLE=False;
violated = the copy exposes CKA_VALUE -> fail; not claimed -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
)
from pkcs11_check.testcases.security import test_api_security as tas

_MISSING = object()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


# --- :241 wrap-decrypt oracle ---------------------------------------------


def _run_oracle(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, extracted: bool) -> None:
    monkeypatch.setattr(tas, "_skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "_raw_gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tas, "_gen_api_security_aes_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(tas, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(tas, "decrypt_single", lambda *_a, **_k: b"\x11" * 16 if extracted else b"")
    monkeypatch.setattr(
        tas,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: False} if claimed else {CKA_EXTRACTABLE: True},
    )
    tas.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(_session())


def test_oracle_claimed_extracted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_oracle(monkeypatch, claimed=True, extracted=True)
    assert not isinstance(ei.value, XFailed)


def test_oracle_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_oracle(monkeypatch, claimed=False, extracted=True)


def test_oracle_no_extraction_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_oracle(monkeypatch, claimed=True, extracted=False)


# --- RSA private-exponent posture ----------------------------------------


def _run_private_exponent(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sensitive: object,
    extractable: object,
    readable: bool,
    exponent_value: object = _MISSING,
    read_log: list[list[int]] | None = None,
    note_levels: list[ComplianceLevel] | None = None,
) -> list[str]:
    monkeypatch.setattr(tas, "_gen_api_security_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tas, "destroy_quietly", lambda *_a, **_k: None)
    notes: list[str] = []

    def _note(description: str, *args: object, **_kwargs: object) -> None:
        notes.append(description)
        if note_levels is not None:
            assert args and isinstance(args[0], ComplianceLevel)
            note_levels.append(args[0])

    monkeypatch.setattr(tas, "note", _note)

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, object]:
        if read_log is not None:
            read_log.append(attrs)
        if CKA_PRIVATE_EXPONENT in attrs:
            if exponent_value is not _MISSING:
                return {CKA_PRIVATE_EXPONENT: exponent_value}
            return {CKA_PRIVATE_EXPONENT: b"\x00" * 256} if readable else {}
        policy_attrs: dict[int, object] = {}
        if sensitive is not _MISSING:
            policy_attrs[CKA_SENSITIVE] = sensitive
        if extractable is not _MISSING:
            policy_attrs[CKA_EXTRACTABLE] = extractable
        return policy_attrs

    monkeypatch.setattr(tas, "read_attributes", _read)
    tas.TestSensitiveExtraction().test_private_key_not_extractable(_session())
    return notes


def test_rsa_protected_readable_private_exponent_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BouncyHSM-like protected claims make readable private material a failure."""
    with pytest.raises(Failed) as ei:
        _run_private_exponent(
            monkeypatch,
            sensitive=True,
            extractable=False,
            readable=True,
        )
    assert not isinstance(ei.value, XFailed)


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(True, _MISSING), (_MISSING, False)],
)
def test_rsa_definitive_protection_claim_fails_with_missing_sibling(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    with pytest.raises(Failed, match="RSA private exponent is readable"):
        _run_private_exponent(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
            readable=True,
        )


def test_rsa_sensitive_claim_alone_makes_readable_exponent_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed, match="CKA_SENSITIVE=True.*CKA_EXTRACTABLE=True"):
        _run_private_exponent(
            monkeypatch,
            sensitive=True,
            extractable=True,
            readable=True,
        )


def test_rsa_non_extractable_claim_alone_makes_readable_exponent_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed, match="CKA_SENSITIVE=False.*CKA_EXTRACTABLE=False"):
        _run_private_exponent(
            monkeypatch,
            sensitive=False,
            extractable=False,
            readable=True,
        )


def test_rsa_missing_policy_readback_xfails_after_exponent_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[list[int]] = []
    with pytest.raises(XFailed, match="CKA_SENSITIVE=None.*CKA_EXTRACTABLE=True"):
        _run_private_exponent(
            monkeypatch,
            sensitive=_MISSING,
            extractable=True,
            readable=True,
            read_log=reads,
        )
    assert reads == [[CKA_SENSITIVE, CKA_EXTRACTABLE], [CKA_PRIVATE_EXPONENT]]


def test_rsa_protected_missing_exponent_is_standard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    levels: list[ComplianceLevel] = []
    notes = _run_private_exponent(
        monkeypatch,
        sensitive=True,
        extractable=False,
        readable=False,
        note_levels=levels,
    )
    assert notes and "exposure was not observed" in notes[0]
    assert levels == [ComplianceLevel.STANDARD]


@pytest.mark.parametrize("exponent_value", [b"", "not-bytes"])
def test_rsa_empty_or_malformed_exponent_is_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
    exponent_value: object,
) -> None:
    with pytest.raises(XFailed, match="private exponent readback"):
        _run_private_exponent(
            monkeypatch,
            sensitive=True,
            extractable=False,
            readable=True,
            exponent_value=exponent_value,
        )


def test_rsa_malformed_policy_readback_xfails_with_actual_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(XFailed, match="CKA_SENSITIVE='yes'.*CKA_EXTRACTABLE=True"):
        _run_private_exponent(
            monkeypatch,
            sensitive="yes",
            extractable=True,
            readable=False,
        )


def test_rsa_unprotected_readable_private_exponent_is_posture_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenCryptoki-like unprotected/readable material is a posture observation."""
    notes = _run_private_exponent(
        monkeypatch,
        sensitive=False,
        extractable=True,
        readable=True,
    )
    assert notes and "private exponent is readable" in notes[0]


def test_rsa_unprotected_unreadable_private_exponent_is_hardened_posture_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    levels: list[ComplianceLevel] = []
    notes = _run_private_exponent(
        monkeypatch,
        sensitive=False,
        extractable=True,
        readable=False,
        note_levels=levels,
    )
    assert notes and "exposure was not observed through C_GetAttributeValue" in notes[0]
    assert "hardened" not in notes[0]
    assert levels == [ComplianceLevel.NOT_RECOMMENDED]


# --- :363 copy extractable-escalation -------------------------------------


def _run_copy(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, exposed: bool) -> None:
    monkeypatch.setattr(tas, "_skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "_gen_api_security_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tas, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "copy_object", lambda *_a, **_k: 5)

    def _read(_raw: object, _sh: object, handle: int, attrs: list[int]) -> dict[int, object]:
        if CKA_EXTRACTABLE in attrs:
            return {CKA_EXTRACTABLE: False} if claimed else {CKA_EXTRACTABLE: True}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 16} if exposed else {}
        return {}

    monkeypatch.setattr(tas, "read_attributes", _read)
    tas.TestAttributeLaunderingViaCopy().test_copy_cannot_escalate_extractable(_session())


def test_copy_claimed_exposed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_copy(monkeypatch, claimed=True, exposed=True)
    assert not isinstance(ei.value, XFailed)


def test_copy_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_copy(monkeypatch, claimed=False, exposed=True)


def test_copy_not_exposed_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_copy(monkeypatch, claimed=True, exposed=False)

"""F18 pins: X9.42 fixture validity + zero-CKA_VALUE_LEN accept sets (P11C-004).

Part A — fixture validity. ``X942_GEN`` shipped corrupted (257 bytes, ``> p``,
outside the subgroup) and the Bob peer sat outside the subgroup too; the old
pin (``test_x942_rfc5114_exact_vector_constant_matches_modexp``) only checked
modexp self-consistency, which is why the corruption survived. These pins bind
the implementation constants to RFC 5114 section 2.3 bytes transcribed
independently from the fetched RFC text (not copied from the implementation),
plus recorded sha256 hashes of that text, and assert the full relation chain:
lengths, ``1 < g,y < p``, ``q | p-1``, ``g^q = 1``, ``y^q = 1``,
``y = pow(g, xB, p)``, and trailing-32 secret recompute.

Part B — zero-``CKA_VALUE_LEN`` table pins. Both DH derive probes
(``CKM_X9_42_DH_DERIVE`` RFC 5114, ``CKM_DH_PKCS_DERIVE`` Group 14) must accept
the three independently-enumerated codes below; the pre-existing pins only
exercised ``CKR_KEY_SIZE_RANGE``. Six proof rows (2 methods x 3 codes) drive
the real probe against a fake token answering each code and require a clean
pass with zero classification records; acceptance controls prove the probe
still fails when the module accepts the zero-length derive, and unlisted-code
controls prove non-accepted clean rejects still xfail (negative coverage for
side providers stays wide).
"""

from __future__ import annotations

import hashlib
from collections.abc import Generator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_X9_42_DH1_DERIVE_PARAMS,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKM_DH_PKCS_DERIVE,
    CKM_X9_42_DH_DERIVE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_dh_key_agreement as dh
from pkcs11_check.testcases import test_x942_dh


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


# ---------------------------------------------------------------------------
# Part A — RFC 5114 section 2.3 material, transcribed independently from the
# fetched RFC text (https://www.rfc-editor.org/rfc/rfc5114.txt, retrieved
# 2026-09-27). Must NOT be copied from the implementation constants.
# ---------------------------------------------------------------------------

_RFC5114_P = bytes.fromhex(
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00"
    "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C"
    "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
    "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76"
    "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E"
    "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
    "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103"
    "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597"
)

_RFC5114_G = bytes.fromhex(
    "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125"
    "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62"
    "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
    "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193"
    "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A"
    "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
    "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3"
    "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659"
)

_RFC5114_Q = bytes.fromhex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3")

# Bob's private value for the exact vector: the file's sequential scheme
# continues past the extended blocks (0x21..0x80) with 0x81..0xA0.
_RFC5114_XB = bytes(range(0x81, 0xA1))

# sha256 over the fetched RFC text bytes (p, g, q parsed programmatically).
_RFC5114_SHA256 = {
    "p": "0b7835722cb619827610c2549fdda5587421686c4409a13865e76225522ddcc9",
    "g": "a16f15da21d7d610dad3af0f3ea9f80c7de830d97f8f8392cb29071128ac8a4b",
    "q": "f0db115b384f879f40f2f4dbae5dbd1681afdabdcd1be002dca609e6869aae0f",
}


def test_rfc5114_domain_matches_independent_transcription() -> None:
    """Implementation p/g/q are byte-exact RFC 5114 section 2.3 values."""
    assert len(test_x942_dh.X942_PRIME_2048) == 256
    assert len(test_x942_dh.X942_GEN) == 256
    assert len(test_x942_dh.X942_SUBPRIME) == 32
    assert test_x942_dh.X942_PRIME_2048 == _RFC5114_P
    assert test_x942_dh.X942_GEN == _RFC5114_G
    assert test_x942_dh.X942_SUBPRIME == _RFC5114_Q


def test_rfc5114_transcription_matches_fetched_text_hashes() -> None:
    """The pin's own transcription hashes to the fetched RFC text digests."""
    assert hashlib.sha256(_RFC5114_P).hexdigest() == _RFC5114_SHA256["p"]
    assert hashlib.sha256(_RFC5114_G).hexdigest() == _RFC5114_SHA256["g"]
    assert hashlib.sha256(_RFC5114_Q).hexdigest() == _RFC5114_SHA256["q"]


def test_rfc5114_domain_is_a_prime_order_subgroup() -> None:
    """q | p-1, g^q = 1, and 1 < g < p for the implementation domain."""
    prime = int.from_bytes(test_x942_dh.X942_PRIME_2048, "big")
    generator = int.from_bytes(test_x942_dh.X942_GEN, "big")
    subprime = int.from_bytes(test_x942_dh.X942_SUBPRIME, "big")
    assert 1 < generator < prime
    assert (prime - 1) % subprime == 0
    assert pow(generator, subprime, prime) == 1


def test_rfc5114_bob_private_is_pinned() -> None:
    """Bob's exact-vector private value is pinned and inside [1, q)."""
    subprime = int.from_bytes(test_x942_dh.X942_SUBPRIME, "big")
    assert test_x942_dh._X942_RFC5114_BOB_PRIVATE == _RFC5114_XB
    bob_private = int.from_bytes(test_x942_dh._X942_RFC5114_BOB_PRIVATE, "big")
    assert 1 < bob_private < subprime


def test_rfc5114_bob_public_is_a_genuine_subgroup_power() -> None:
    """y = g^xB with 1 < y < p and y^q = 1 (not mere self-consistency)."""
    prime = int.from_bytes(test_x942_dh.X942_PRIME_2048, "big")
    generator = int.from_bytes(test_x942_dh.X942_GEN, "big")
    subprime = int.from_bytes(test_x942_dh.X942_SUBPRIME, "big")
    bob_private = int.from_bytes(test_x942_dh._X942_RFC5114_BOB_PRIVATE, "big")
    bob_public = int.from_bytes(test_x942_dh._X942_RFC5114_BOB_PUBLIC, "big")
    assert 1 < bob_public < prime
    assert bob_public == pow(generator, bob_private, prime)
    assert pow(bob_public, subprime, prime) == 1


def test_rfc5114_expected_secret_is_the_trailing_32_bytes() -> None:
    """The expected secret recomputes as the trailing 32 bytes of Z."""
    prime = int.from_bytes(test_x942_dh.X942_PRIME_2048, "big")
    alice_private = int.from_bytes(test_x942_dh._X942_RFC5114_ALICE_PRIVATE, "big")
    bob_public = int.from_bytes(test_x942_dh._X942_RFC5114_BOB_PUBLIC, "big")
    full_secret = pow(bob_public, alice_private, prime).to_bytes(
        len(test_x942_dh.X942_PRIME_2048),
        "big",
    )
    assert len(test_x942_dh._X942_RFC5114_EXPECTED_SECRET_32) == 32
    assert full_secret[-32:] == test_x942_dh._X942_RFC5114_EXPECTED_SECRET_32


# ---------------------------------------------------------------------------
# Part B — zero-CKA_VALUE_LEN accept sets, table-driven behavioral pins.
# The accepted codes are enumerated here independently, NOT derived from the
# implementation tuples. Witnesses compare portably via int().
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _VlenCode:
    case_id: str
    code: int  # CKR enum member
    legacy: int  # accepted plain-int numeric for the same code


_VLEN_ACCEPTED: tuple[_VlenCode, ...] = (
    _VlenCode("key-size-range", CKR_KEY_SIZE_RANGE, 0x62),
    _VlenCode("attribute-value-invalid", CKR_ATTRIBUTE_VALUE_INVALID, 0x13),
    _VlenCode("template-inconsistent", CKR_TEMPLATE_INCONSISTENT, 0xD1),
)

# Pre-F18 baseline: the runtime-classification pins only exercised this code.
_VLEN_BASELINE_CODES: frozenset[int] = frozenset({int(CKR_KEY_SIZE_RANGE)})


def _x942_session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "X9_42_DH_DERIVE")


def _dh_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"DH_PKCS_KEY_PAIR_GEN", "DH_PKCS_DERIVE"},
    )


def _run_x942_zero_vlen_probe(
    monkeypatch: pytest.MonkeyPatch, outcome: int | None
) -> list[dict[str, Any]]:
    """Drive the X9.42 zero-VLEN probe; ``outcome`` is the fake-token CKR (None = accept)."""
    seen: list[dict[str, Any]] = []

    def _derive(
        _raw: Any,
        _sh: int,
        _base_key: int,
        mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        assert int(mechanism) == int(CKM_X9_42_DH_DERIVE)
        assert isinstance(mech_param.params, CK_X9_42_DH1_DERIVE_PARAMS)
        params = mech_param.params
        assert params.kdf == CKD_NULL
        assert params.ulPublicDataLen == len(test_x942_dh._X942_RFC5114_BOB_PUBLIC)
        seen.append({"attrs": dict(attrs)})
        if outcome is None:
            return 777
        raise CkrAssertionError(f"Unexpected CK_RV {int(outcome):#x}", int(outcome))

    monkeypatch.setattr(test_x942_dh, "_import_x942_private_key", lambda *_args: 501)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHDerive().test_x942_dh_derive_rfc5114_rejects_zero_value_len(
        _x942_session()
    )
    return seen


def _run_dh_zero_vlen_probe(
    monkeypatch: pytest.MonkeyPatch, outcome: int | None
) -> list[dict[str, Any]]:
    """Drive the Group 14 zero-VLEN probe; ``outcome`` is the fake-token CKR (None = accept)."""
    seen: list[dict[str, Any]] = []

    def _derive(
        _raw: Any,
        _sh: int,
        _private_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        del mech_param
        assert int(mechanism) == int(CKM_DH_PKCS_DERIVE)
        seen.append({"attrs": dict(attrs)})
        if outcome is None:
            return 777
        raise CkrAssertionError(f"Unexpected CK_RV {int(outcome):#x}", int(outcome))

    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)
    monkeypatch.setattr(dh, "derive_key", _derive)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len(
        _dh_session()
    )
    return seen


_VLEN_METHODS = {
    "x942-derive": _run_x942_zero_vlen_probe,
    "dh-pkcs-derive": _run_dh_zero_vlen_probe,
}


def _assert_vlen_table_consistent(case: _VlenCode) -> None:
    assert int(case.code) == int(case.legacy), f"{case.case_id}: pin table inconsistent"


@pytest.mark.parametrize("method_id", sorted(_VLEN_METHODS))
@pytest.mark.parametrize("case", _VLEN_ACCEPTED, ids=[c.case_id for c in _VLEN_ACCEPTED])
def test_zero_value_len_accepts_code(
    monkeypatch: pytest.MonkeyPatch, method_id: str, case: _VlenCode
) -> None:
    """Each accepted code passes its zero-VLEN probe with zero silenced records."""
    _assert_vlen_table_consistent(case)
    try:
        seen = _VLEN_METHODS[method_id](monkeypatch, int(case.code))
    except pytest.xfail.Exception as exc:
        pytest.fail(f"{method_id}/{case.case_id}: probe xfailed instead of passing ({exc})")
    assert len(seen) == 1, f"{method_id}/{case.case_id}: expected 1 derive call, saw {seen}"
    assert seen[0]["attrs"][CKA_VALUE_LEN] == 0, (
        f"{method_id}/{case.case_id}: probe did not send CKA_VALUE_LEN=0"
    )
    assert C.get_records() == [], (
        f"{method_id}/{case.case_id}: accept path emitted records "
        f"{[r.reason for r in C.get_records()]}"
    )


@pytest.mark.parametrize("method_id", sorted(_VLEN_METHODS))
def test_zero_value_len_acceptance_still_fails(
    monkeypatch: pytest.MonkeyPatch, method_id: str
) -> None:
    """A module accepting the zero-length derive still fails the probe (not neutered)."""
    with pytest.raises(AssertionError, match="accepted .* CKA_VALUE_LEN=0"):
        _VLEN_METHODS[method_id](monkeypatch, None)


@pytest.mark.parametrize("method_id", sorted(_VLEN_METHODS))
def test_zero_value_len_unlisted_reject_still_xfails(
    monkeypatch: pytest.MonkeyPatch, method_id: str
) -> None:
    """A clean reject outside the accept set still xfails (coverage stays wide)."""
    with pytest.raises(pytest.xfail.Exception):
        _VLEN_METHODS[method_id](monkeypatch, int(CKR_DEVICE_ERROR))
    assert [record.reason for record in C.get_records()] == ["nonspec_reject"]


def test_vlen_pin_table_covers_haskoki_code_above_baseline() -> None:
    """The pin table extends the KEY_SIZE_RANGE-only baseline with the Haskoki code."""
    for case in _VLEN_ACCEPTED:
        _assert_vlen_table_consistent(case)
    table_codes = frozenset(int(case.code) for case in _VLEN_ACCEPTED)
    assert len(table_codes) == 3, f"expected 3 independently-enumerated codes, saw {table_codes}"
    assert int(CKR_TEMPLATE_INCONSISTENT) in table_codes
    assert table_codes > _VLEN_BASELINE_CODES
    proof_rows = len(_VLEN_METHODS) * len(_VLEN_ACCEPTED)
    assert proof_rows == 6
    assert proof_rows > len(_VLEN_METHODS) * len(_VLEN_BASELINE_CODES)


# ---------------------------------------------------------------------------
# Part C — P11C-007: _x942_derive_aes pins CKA_VALUE_LEN like its PKCS#3 twin.
# Without the pin a module may default the length to the full DH secret width
# and store an unusable oversized "AES" key that fails downstream at C_Encrypt
# instead of at derive time.
# ---------------------------------------------------------------------------


def _capture_x942_derive_attrs(
    monkeypatch: pytest.MonkeyPatch, extra_attrs: dict[int, Any] | None = None
) -> dict[Any, Any]:
    """Drive _x942_derive_aes with a stubbed derive_key; return the template."""
    seen: dict[Any, Any] = {}

    def _derive(
        _raw: Any,
        _sh: int,
        _base_key: int,
        mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        assert int(mechanism) == int(CKM_X9_42_DH_DERIVE)
        seen.update(attrs)
        return 777

    monkeypatch.setattr(test_x942_dh, "derive_key", _derive)
    rs = SimpleNamespace(raw=object(), sh=1)
    test_x942_dh._x942_derive_aes(rs, 5, b"\x02" * 256, extra_attrs=extra_attrs)
    return seen


def test_x942_derive_aes_pins_value_len_16(monkeypatch: pytest.MonkeyPatch) -> None:
    """P11C-007: the derived AES-128 template pins CKA_VALUE_LEN 16."""
    seen = _capture_x942_derive_attrs(monkeypatch)
    assert seen[CKA_VALUE_LEN] == 16


def test_x942_derive_aes_extra_attrs_override_value_len(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P11C-007: explicit extra_attrs still override the pinned length."""
    seen = _capture_x942_derive_attrs(monkeypatch, {CKA_VALUE_LEN: 24})
    assert seen[CKA_VALUE_LEN] == 24

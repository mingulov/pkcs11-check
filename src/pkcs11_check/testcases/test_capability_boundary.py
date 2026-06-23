"""Over-delivery probe (@security): does the module perform operations OUTSIDE
its advertised boundaries?

Provider-general; no provider identity. For an advertised mechanism this
deliberately attempts work outside its CK_MECHANISM_INFO box and asserts a
refusal. Performing a below-min/weak op is a security downgrade (fail); performing
a stronger-than-advertised op is benign over-advertisement (xfail). A clean refusal
is the conformant pass; a crash is the finding.

Runs under the framework's per-file subprocess isolation, so a crash on an
out-of-range input is captured as the finding, not a run-killer.
"""

from __future__ import annotations

from ctypes import byref
from enum import Enum
from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    get_mechanism_info,
    pack_attrs,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_VALUE_LEN,
    CKK_DES3,
    CKM_AES_KEY_GEN,
    CKM_DES3_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)

pytestmark = pytest.mark.security

# RSA moduli are multiples of 8 bits; 512 is the smallest gen_rsa_keypair can
# meaningfully attempt. Returns a size STRICTLY below the module's advertised
# minimum (and >= 512), or None when no valid smaller size exists (so the probe
# is inconclusive and must skip -- never a false pass or false fail).
_RSA_HARD_FLOOR = 512

# RSA hard ceiling: largest modulus we will attempt (avoids excessive keygen time).
_RSA_HARD_CEIL = 16384


def rsa_probe_size_below_min(advertised_min: int) -> int | None:
    """A valid RSA modulus size strictly below ``advertised_min``, or None."""
    if advertised_min == 0 or advertised_min <= _RSA_HARD_FLOOR:
        return None
    candidate = advertised_min - 8  # one RSA step (8 bits) below the floor
    if candidate < _RSA_HARD_FLOOR:
        candidate = _RSA_HARD_FLOOR
    return candidate


def rsa_probe_size_above_max(advertised_max: int) -> int | None:
    """A valid RSA modulus size strictly above ``advertised_max``, or None.

    Steps one RSA granularity unit (8 bits) above the advertised maximum.  Returns
    None when no such size exists within our probe ceiling (to avoid runaway keygen).
    """
    if advertised_max == 0:
        return None
    candidate = advertised_max + 8
    if candidate > _RSA_HARD_CEIL:
        return None
    return candidate


# EC curve field sizes (bits) sorted ascending, with their canonical names.
# Each entry is (field_bits, curve_name) where curve_name is accepted by
# encode_named_curve_parameters.  Field bits == PKCS#11 key-size unit for EC.
_EC_CURVE_SIZES: list[tuple[int, str]] = [
    (160, "secp160r1"),
    (192, "secp192r1"),
    (224, "secp224r1"),
    (256, "secp256r1"),
    (384, "secp384r1"),
    (521, "secp521r1"),
]


def ec_probe_curve_below_min(advertised_min: int) -> tuple[int, str] | None:
    """Return (field_bits, curve_name) strictly below ``advertised_min``, or None.

    Picks the largest known curve whose field size is still strictly below the
    advertised minimum, giving the most plausible probe (closest to the boundary).
    """
    candidates = [(bits, name) for bits, name in _EC_CURVE_SIZES if bits < advertised_min]
    return candidates[-1] if candidates else None


def ec_probe_curve_above_max(advertised_max: int) -> tuple[int, str] | None:
    """Return (field_bits, curve_name) strictly above ``advertised_max``, or None.

    Picks the smallest known curve whose field size is still strictly above the
    advertised maximum, giving the most plausible probe (closest to the boundary).
    """
    candidates = [(bits, name) for bits, name in _EC_CURVE_SIZES if bits > advertised_max]
    return candidates[0] if candidates else None


# AES key sizes (bits) we use for boundary probing.  AES spec defines 128/192/256;
# we probe below the floor with a sub-AES size and above the ceiling with a value
# beyond the AES-256 maximum.
_AES_SIZES_BELOW: list[int] = [64, 96]  # not valid AES sizes; used for below-min probe
_AES_SIZE_ABOVE: int = 512  # above any valid AES key; used for above-max probe


def aes_probe_size_below_min(advertised_min: int) -> int | None:
    """Return an AES key size (bits) strictly below ``advertised_min``, or None."""
    candidates = [s for s in _AES_SIZES_BELOW if s < advertised_min]
    return candidates[-1] if candidates else None


def aes_probe_size_above_max(advertised_max: int) -> int | None:
    """Return an AES key size (bits) strictly above ``advertised_max``, or None."""
    if _AES_SIZE_ABOVE > advertised_max:
        return _AES_SIZE_ABOVE
    return None


# Refusal codes that count as the module ENFORCING its advertised boundary.
_ENFORCED_REFUSAL_RVS: frozenset[int] = frozenset(
    {
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_KEY_SIZE_RANGE,
        CKR_MECHANISM_INVALID,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_TEMPLATE_INCONSISTENT,
    }
)


class BoundaryCase(Enum):
    BELOW_MIN = "below_min"
    ABOVE_MAX = "above_max"
    FLAG_UNSET = "flag_unset"
    UNADVERTISED_MECH = "unadvertised_mech"


def classify_boundary_outcome(
    case: BoundaryCase,
    *,
    performed: bool,
    refusal: CkrAssertionError | None,
    weak: bool,
) -> None:
    """Decide the verdict of one out-of-range attempt.

    ``performed`` True means the module carried out the out-of-range operation.
    ``refusal`` is the CkrAssertionError raised when it refused (else None).
    ``weak`` marks the security-relevant direction (below-min, or a known-weak
    unadvertised mechanism). Returns None (= pass) on an enforced refusal;
    otherwise raises the pytest verdict.

    ``performed`` and ``refusal`` are mutually exclusive: a real caller either
    got handles back (performed) or caught a CkrAssertionError (refusal).
    """
    if not performed:
        rv = getattr(refusal, "rv", None)
        if rv is not None and rv in _ENFORCED_REFUSAL_RVS:
            return None  # enforced its boundary -> conformant pass
        # Refused, but with a non-canonical clean code: recorded deviation.
        xfail_as(
            "nonspec_reject",
            label=f"capability_boundary:{case.value}",
            actual=rv if rv is not None else "unknown",
            summary=f"boundary {case.value}: refused with non-canonical code "
            f"({ckr_name(rv) if rv is not None else 'unknown'})",
        )
    # The module PERFORMED an out-of-range operation.
    if weak:
        fail_as(
            "self_contradiction",
            kind="policy",
            label=f"capability_boundary:{case.value}",
            summary=f"boundary {case.value}: performed a weaker-than-advertised "
            "operation it claims to reject (security downgrade)",
        )
    xfail_as(
        "undeclared_capability",
        kind="metadata",
        label=f"capability_boundary:{case.value}",
        summary=f"boundary {case.value}: performed an operation beyond its "
        "advertised boundary (benign over-advertisement)",
    )


class TestRSAKeySizeBoundary:
    """RSA: attempt key sizes outside the advertised [min,max] (bits)."""

    def test_rsa_below_min_is_refused(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for RSA keygen -- cannot determine floor")
        probe_size = rsa_probe_size_below_min(int(info["min_key_size"]))
        if probe_size is None:
            pytest.skip(
                f"advertised RSA min={info['min_key_size']}: no valid size strictly below it"
            )
        # probe_size is genuinely below the module's OWN advertised minimum -> weak.
        performed = False
        refusal: CkrAssertionError | None = None
        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, probe_size)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN, performed=performed, refusal=refusal, weak=True
        )

    def test_rsa_above_max_is_refused(self, p11_raw_session: Any) -> None:
        """Keygen at one step above the advertised RSA maximum must be refused.

        Success (over-delivery) is benign over-advertisement — xfail, not fail.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for RSA keygen -- cannot determine ceiling")
        probe_size = rsa_probe_size_above_max(int(info["max_key_size"]))
        if probe_size is None:
            pytest.skip(
                f"advertised RSA max={info['max_key_size']}: no valid probe size above it"
                f" within ceiling {_RSA_HARD_CEIL}"
            )
        performed = False
        refusal: CkrAssertionError | None = None
        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, probe_size)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        classify_boundary_outcome(
            BoundaryCase.ABOVE_MAX,
            performed=performed,
            refusal=refusal,
            weak=False,  # above-max over-delivery is benign, not a security downgrade
        )


class TestECKeySizeBoundary:
    """EC: attempt key pairs with curves outside the advertised field-bit range."""

    def _run_ec_probe(
        self,
        p11_raw_session: Any,
        case: BoundaryCase,
        _field_bits: int,
        curve_name: str,
    ) -> None:
        """Attempt EC keygen with ``curve_name`` and classify the outcome."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters(curve_name)
        performed = False
        refusal: CkrAssertionError | None = None
        pub = priv = 0
        try:
            pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        classify_boundary_outcome(
            case,
            performed=performed,
            refusal=refusal,
            weak=(case is BoundaryCase.BELOW_MIN),
        )

    def test_ec_below_min_is_refused(self, p11_raw_session: Any) -> None:
        """EC keygen with a curve whose field size is below the advertised minimum."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_EC_KEY_PAIR_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for EC keygen -- cannot determine floor")
        probe = ec_probe_curve_below_min(int(info["min_key_size"]))
        if probe is None:
            pytest.skip(
                f"advertised EC min={info['min_key_size']} bits: "
                "no known curve with field size strictly below it"
            )
        field_bits, curve_name = probe
        self._run_ec_probe(p11_raw_session, BoundaryCase.BELOW_MIN, field_bits, curve_name)

    def test_ec_above_max_is_refused(self, p11_raw_session: Any) -> None:
        """EC keygen with a curve whose field size is above the advertised maximum."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_EC_KEY_PAIR_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for EC keygen -- cannot determine ceiling")
        probe = ec_probe_curve_above_max(int(info["max_key_size"]))
        if probe is None:
            pytest.skip(
                f"advertised EC max={info['max_key_size']} bits: "
                "no known curve with field size strictly above it"
            )
        field_bits, curve_name = probe
        self._run_ec_probe(p11_raw_session, BoundaryCase.ABOVE_MAX, field_bits, curve_name)


class TestAESKeySizeBoundary:
    """AES: attempt key sizes outside the advertised [min,max] (bits)."""

    def test_aes_below_min_is_refused(self, p11_raw_session: Any) -> None:
        """AES keygen at a size below the advertised minimum must be refused."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for AES keygen -- cannot determine floor")
        # CK_MECHANISM_INFO sizes for AES_KEY_GEN are in bytes in some modules; normalise
        # to bits.  Heuristic: if max_key_size <= 32, assume bytes (32 bytes = 256 bits).
        raw_min = int(info["min_key_size"])
        raw_max = int(info["max_key_size"])
        if raw_max <= 32:  # sizes reported in bytes
            advertised_min_bits = raw_min * 8
        else:
            advertised_min_bits = raw_min
        probe_bits = aes_probe_size_below_min(advertised_min_bits)
        if probe_bits is None:
            pytest.skip(
                f"advertised AES min={advertised_min_bits} bits: "
                "no probe size strictly below it in our candidate list"
            )
        performed = False
        refusal: CkrAssertionError | None = None
        key = 0
        try:
            key = gen_aes_key(rs.raw, rs.sh, probe_bits)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN, performed=performed, refusal=refusal, weak=True
        )

    def test_aes_above_max_is_refused(self, p11_raw_session: Any) -> None:
        """AES keygen at a size above the advertised maximum must be refused."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for AES keygen -- cannot determine ceiling")
        raw_max = int(info["max_key_size"])
        if raw_max <= 32:
            advertised_max_bits = raw_max * 8
        else:
            advertised_max_bits = raw_max
        probe_bits = aes_probe_size_above_max(advertised_max_bits)
        if probe_bits is None:
            pytest.skip(
                f"advertised AES max={advertised_max_bits} bits: no probe size strictly above it"
            )
        performed = False
        refusal: CkrAssertionError | None = None
        key = 0
        try:
            key = gen_aes_key(rs.raw, rs.sh, probe_bits)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
        classify_boundary_outcome(
            BoundaryCase.ABOVE_MAX,
            performed=performed,
            refusal=refusal,
            weak=False,  # above-max over-delivery is benign, not a security downgrade
        )


class TestDES3KeySizeBoundary:
    """DES3: attempt key sizes outside the advertised [min,max] (bits).

    DES3 key size is fixed (112 or 168 effective bits; modules typically report
    min==max).  When the range has no gap below or above, the probe skips.  When
    a genuine gap exists, a refusal is the conformant result.
    """

    def _run_des3_probe(
        self,
        p11_raw_session: Any,
        case: BoundaryCase,
        probe_bits: int,
    ) -> None:
        """Attempt DES3 keygen with ``probe_bits`` and classify the outcome."""
        rs = p11_raw_session
        mech = mech_simple(CKM_DES3_KEY_GEN)
        attrs_dict: dict[Any, Any] = {CKA_ENCRYPT: True, CKA_KEY_TYPE: CKK_DES3}
        packed = [attr_ulong(CKA_VALUE_LEN, probe_bits // 8)]
        packed.extend(pack_attrs(attrs_dict, skip={CKA_VALUE_LEN}))
        tmpl = template(*packed)

        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

        key_h = CK_OBJECT_HANDLE(0)
        performed = False
        refusal: CkrAssertionError | None = None
        try:
            rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
            expect_rv(rv, CKR_OK)
            performed = True
        except CkrAssertionError as exc:
            refusal = exc
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h.value)
        classify_boundary_outcome(
            case,
            performed=performed,
            refusal=refusal,
            weak=(case is BoundaryCase.BELOW_MIN),
        )

    def test_des3_below_min_is_refused(self, p11_raw_session: Any) -> None:
        """DES3 keygen at a key size below the advertised minimum must be refused."""
        rs = p11_raw_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_DES3_KEY_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for DES3 keygen -- cannot determine floor")
        advertised_min = int(info["min_key_size"])
        # DES3 sizes are reported in bytes by most modules (8=64 bits, 24=192 bits).
        if advertised_min <= 32:
            advertised_min_bits = advertised_min * 8
        else:
            advertised_min_bits = advertised_min
        if advertised_min_bits <= 8:
            pytest.skip(f"advertised DES3 min={advertised_min_bits} bits: no probe below it")
        probe_bits = advertised_min_bits - 8
        if probe_bits <= 0 or probe_bits % 8 != 0:
            pytest.skip(f"advertised DES3 min={advertised_min_bits} bits: no valid probe below it")
        self._run_des3_probe(p11_raw_session, BoundaryCase.BELOW_MIN, probe_bits)

    def test_des3_above_max_is_refused(self, p11_raw_session: Any) -> None:
        """DES3 keygen at a key size above the advertised maximum must be refused."""
        rs = p11_raw_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("CKM_DES3_KEY_GEN not advertised")
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_DES3_KEY_GEN)
        except CkrAssertionError:
            pytest.skip("C_GetMechanismInfo failed for DES3 keygen -- cannot determine ceiling")
        advertised_max = int(info["max_key_size"])
        if advertised_max <= 32:
            advertised_max_bits = advertised_max * 8
        else:
            advertised_max_bits = advertised_max
        probe_bits = advertised_max_bits + 8
        self._run_des3_probe(p11_raw_session, BoundaryCase.ABOVE_MAX, probe_bits)

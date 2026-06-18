"""RSA-PSS (mechanism, hash, mgf, salt-len) combo operability probe.

A self-roundtrip probe used by both the Wycheproof and ACVP RSA-PSS verify
suites to gate the vacuous-reject downgrade: when a PSS combo is
NOT_OPERATIONAL, an invalid-vector "reject" never evaluated the signature
(advertised-but-not-operational, classification model: xfail, not pass).

Lives in the shared ``testcases/_*.py`` namespace so both suites can import it
without cross-suite coupling. The probe is staging-safe: keypair generation
refusal is INCONCLUSIVE (no PSS evidence either way), so the vacuous-reject
downgrade never fires without combo evidence.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.pack import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKA_VERIFY
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    probe_operability,
)

# Canned message for the operational probe -- arbitrary content.
_PSS_PROBE_MESSAGE = b"pkcs11-check PSS combo operational probe"


def pss_combo_operability(
    rs: Any, mechanism: int, hash_mech: int, mgf: int, salt_len: int
) -> OperabilityResult:
    """Self-roundtrip probe for a (mech, hash, mgf, sLen) PSS combo.

    Keypair generation is staging (plain RSA keygen, no PSS involved) -- its
    refusal is INCONCLUSIVE, not mechanism evidence (so the vacuous-reject
    downgrade never fires without combo evidence). A canonical PSS sign/verify
    refusal (CkrAssertionError) or verify-False IS combo evidence ->
    NOT_OPERATIONAL; a verifying self-roundtrip -> OPERATIONAL. Cached per combo
    via probe_operability.

    Module errors surface as CkrAssertionError (gen_rsa_keypair / sign_single /
    verify_single all route through expect_rv); a plain AssertionError is a
    harness bug and propagates uncached. ``mech_pss`` packing errors are
    harness-side (ctypes) and likewise propagate.
    """

    def probe() -> OperabilityResult:
        pub = priv = 0
        try:
            try:
                pub, priv = gen_rsa_keypair(
                    rs.raw,
                    rs.sh,
                    2048,
                    private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                    public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"RSA-2048 keypair staging failed: {exc}"
                )
            pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=salt_len)
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, mechanism, _PSS_PROBE_MESSAGE, mech_param=pss_param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS sign rejected: {exc}"
                )
            try:
                ok = verify_single(
                    rs.raw, rs.sh, pub, mechanism, _PSS_PROBE_MESSAGE, sig, mech_param=pss_param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical PSS verify rejected: {exc}"
                )
            if not ok:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, "own PSS signature verifies False"
                )
            return OperabilityResult(Operability.OPERATIONAL, "self-roundtrip OK")
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)

    return probe_operability(
        f"RSA_PSS:{mechanism:#x}:{hash_mech:#x}:{mgf:#x}:{salt_len}:sign-verify", probe
    )

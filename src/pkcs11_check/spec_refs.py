"""Central PKCS#11 v3.2 spec-reference table. Never fabricate a paragraph: when no precise
section is known, return the stable coarse form (version + function/mechanism)."""

from __future__ import annotations

_VERSION = "PKCS#11 v3.2"

# (function, mechanism) -> precise section. ONLY add entries you can confirm against the local
# v3.2 mirror at /home/user/src/m/other/pkcs11/. Leaving this small is fine — the coarse
# fallback covers everything else. DO NOT invent section numbers.
_PRECISE: dict[tuple[str | None, str | None], str] = {}


def lookup(function: str | None, mechanism: str | None, expected: object = None) -> str:
    """Return a stable, non-fabricated PKCS#11 v3.2 spec reference string.

    Returns a precise section entry from ``_PRECISE`` when available; otherwise returns
    a coarse ``"PKCS#11 v3.2 · <function> · <mechanism>"`` form that is still truthful
    and stable.  Returns ``""`` when neither ``function`` nor ``mechanism`` is given.
    """
    if (function, mechanism) in _PRECISE:
        return _PRECISE[(function, mechanism)]
    if function and mechanism:
        return f"{_VERSION} · {function} · {mechanism}"
    if function:
        return f"{_VERSION} · {function}"
    if mechanism:
        return f"{_VERSION} · {mechanism}"
    return ""

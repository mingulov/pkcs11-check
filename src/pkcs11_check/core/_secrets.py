"""Central secret-handling policy: values that must never appear in output.

Argv side (this module): :data:`SECRET_ARGV_FLAGS` names the pytest flags
whose values are secrets, and :func:`redact_secret_args` replaces those values
with ``<redacted>``. Every renderer of pytest args — diagnostics, fingerprints,
logs — must pass args through it. Env side: ``_REDACTED_ENV_KEYS`` in
``_run_state`` (fingerprint snapshots, diagnostics).

Leaf module by design (no framework imports): renderers anywhere in the
package can use it without import cycles.
"""

from __future__ import annotations

from collections.abc import Sequence

#: pytest flags whose values are secrets (framework- or user-supplied).
SECRET_ARGV_FLAGS = frozenset({"--p11-pin", "--p11-so-pin", "--p11-wrap-key-value"})


def redact_secret_args(args: Sequence[str]) -> list[str]:
    """Replace secret flag values with ``<redacted>``, preserving arg shape.

    Both ``--flag value`` and ``--flag=value`` forms are handled; a trailing
    bare secret flag (no value) is kept as-is. Token count and order are
    preserved so redacted command lines stay structurally reproducible.
    """
    redacted: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        flag, eq, _value = arg.partition("=")
        if eq and flag in SECRET_ARGV_FLAGS:
            redacted.append(f"{flag}=<redacted>")
            continue
        redacted.append(arg)
        if arg in SECRET_ARGV_FLAGS:
            redact_next = True
    return redacted
